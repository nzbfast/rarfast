//! The wide verify (`read::wide`): a STORED member split across volumes,
//! checked (`Disposition::Verify`, the `t` command) or written (`p`, `x`),
//! is read and hashed on several threads, and says and writes exactly what
//! the ordinary loop says and writes.
//!
//! The shape is the posting one scaled down: one incompressible stored
//! member over several volumes, each fragment above the wide floor of
//! 16 MiB. Every case runs the member twice, at a width of one (the
//! ordinary loop, `read::wide::plan` refuses a width under two) and at a
//! width of four, and asserts the wide arm really did go wide before it
//! compares anything, so a comparison of two ordinary reads cannot pass
//! for one of a wide read.

use std::sync::Arc;

use rarkit::{
    extract, Disposition, MemberInfo, MemberOutcome, MemberSpec, Payload, Progress, RangeSource,
    ReadOptions, Result, Sink, WriteOptions, Writer,
};

/// Incompressible, deterministic bytes.
fn noise(n: usize) -> Vec<u8> {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// One stored member of `len` bytes in volumes of about `per` bytes, by
/// this crate's own writer.
fn stored_set(len: usize, per: u64) -> Vec<Vec<u8>> {
    let data = noise(len);
    let mut writer = Writer::new(WriteOptions {
        volume_size: Some(per),
        ..WriteOptions::default()
    })
    .expect("options");
    writer
        .add(MemberSpec {
            name: b"post.bin",
            payload: Payload::Bytes(&data),
            mtime: None,
            attributes: 0,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut out: Vec<Vec<u8>> = Vec::new();
    writer.finish_volumes(&mut out).expect("finish");
    assert!(out.len() >= 3, "a set of {} volumes", out.len());
    out
}

/// Every member's outcome, checked only.
#[derive(Default)]
struct Verdicts {
    outcomes: Vec<(Vec<u8>, MemberOutcome)>,
    written: bool,
    /// Each written member's bytes, in archive order.
    bytes: Vec<Vec<u8>>,
}

impl Sink for Verdicts {
    type Out = Vec<u8>;

    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        Ok(if self.written {
            Disposition::Write(Vec::new())
        } else {
            Disposition::Verify
        })
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        if let Some(bytes) = out {
            self.bytes.push(bytes);
        }
        self.outcomes.push((member.name.to_vec(), *outcome));
        Ok(())
    }
}

/// The drop-behind reports, which must stay monotone per volume.
#[derive(Default)]
struct Trail {
    released: Vec<(u32, u64)>,
    done: Vec<u32>,
}

impl Progress for Trail {
    fn released(&mut self, volume: u32, offset: u64) -> Result<()> {
        if let Some(&(v, last)) = self.released.iter().rev().find(|(v, _)| *v == volume) {
            assert!(offset >= last, "released went backwards on volume {v}");
        }
        self.released.push((volume, offset));
        Ok(())
    }

    fn volume_done(&mut self, volume: u32) -> Result<()> {
        self.done.push(volume);
        Ok(())
    }
}

/// What one read of the set says: the outcomes, or the error's kind,
/// member and volume; with how many ranges went wide and the volumes
/// finished.
#[derive(Debug, PartialEq)]
struct Said {
    outcomes: std::result::Result<Vec<(Vec<u8>, MemberOutcome)>, String>,
    done: Vec<u32>,
    /// A digest of every written byte, in order, so a failure does not
    /// print 72 MiB.
    written: Vec<(usize, u32)>,
}

fn read(volumes: &[Vec<u8>], workers: usize, written: bool) -> (Said, u64) {
    // A written member reads as `p` does: its writer is not a file.
    read_hinted(volumes, workers, written, written.then_some(false))
}

fn read_hinted(
    volumes: &[Vec<u8>],
    workers: usize,
    written: bool,
    sink_is_file: Option<bool>,
) -> (Said, u64) {
    let sources: Vec<Arc<dyn RangeSource>> = volumes
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect();
    let options = ReadOptions::default()
        .with_workers(Some(workers))
        .with_sink_is_file(sink_is_file);
    let mut sink = Verdicts {
        written,
        ..Verdicts::default()
    };
    let mut trail = Trail::default();
    rarkit::probe::reset_wide_verifies();
    let outcome = extract(sources, &options, &mut sink, &mut trail);
    let wide = rarkit::probe::wide_verifies();
    let outcomes = match outcome {
        Ok(_) => Ok(sink.outcomes),
        Err(e) => Err(format!(
            "{:?} member {:?} volume {:?}",
            e.kind(),
            e.member().map(<[u8]>::to_vec),
            e.volume()
        )),
    };
    let written = sink
        .bytes
        .iter()
        .map(|b| (b.len(), rarkit::checksum::crc32(b)))
        .collect();
    (
        Said {
            outcomes,
            done: trail.done,
            written,
        },
        wide,
    )
}

const LEN: usize = 72 << 20;
const PER: u64 = 20 << 20;

#[test]
fn a_whole_set_says_ok_wide_and_narrow() {
    let set = stored_set(LEN, PER);
    let (narrow, n) = read(&set, 1, false);
    let (wide, w) = read(&set, 4, false);
    assert_eq!(n, 0, "a width of one never goes wide");
    assert!(w >= 3, "only {w} ranges went wide");
    assert_eq!(wide, narrow);
    let outcomes = wide.outcomes.expect("a whole set reads");
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].1.checksum_ok, Some(true));
    assert_eq!(outcomes[0].1.bytes, LEN as u64);
}

#[test]
fn a_flipped_byte_in_a_middle_volume_fails_the_member_both_ways() {
    let mut set = stored_set(LEN, PER);
    let middle = set.len() / 2;
    let at = set[middle].len() / 2;
    set[middle][at] ^= 0x01;
    let (narrow, _) = read(&set, 1, false);
    let (wide, w) = read(&set, 4, false);
    assert!(w >= 1, "nothing went wide");
    assert_eq!(wide, narrow);
    let outcomes = wide
        .outcomes
        .expect("a bad byte is a verdict, not an error");
    assert_eq!(outcomes[0].1.checksum_ok, Some(false));
}

#[test]
fn a_cut_middle_volume_ends_the_same_way_both_ways() {
    let mut set = stored_set(LEN, PER);
    let middle = set.len() / 2;
    let keep = set[middle].len() / 3;
    set[middle].truncate(keep);
    let (narrow, _) = read(&set, 1, false);
    let (wide, w) = read(&set, 4, false);
    assert!(w >= 1, "nothing went wide");
    assert_eq!(wide, narrow);
}

/// `p` and `x`: the member's bytes reach its writer from the walking
/// thread in piece order, the same bytes as the ordinary loop writes and
/// the bytes that were stored.
#[test]
fn a_written_member_goes_wide_and_writes_the_same_bytes() {
    let set = stored_set(LEN, PER);
    let (narrow, n) = read(&set, 1, true);
    let (wide, w) = read(&set, 4, true);
    assert_eq!(n, 0, "a width of one never goes wide");
    assert!(w >= 3, "only {w} ranges went wide");
    assert_eq!(wide, narrow);
    let outcomes = wide.outcomes.expect("a whole set reads");
    assert_eq!(outcomes[0].1.checksum_ok, Some(true));
    let data = noise(LEN);
    assert_eq!(
        wide.written,
        vec![(LEN, rarkit::checksum::crc32(&data))],
        "the written bytes are the stored ones"
    );
}

/// A written member cut short writes the same prefix both ways before
/// the same error.
#[test]
fn a_written_member_over_a_cut_volume_writes_the_same_prefix() {
    let mut set = stored_set(LEN, PER);
    let middle = set.len() / 2;
    let keep = set[middle].len() / 3;
    set[middle].truncate(keep);
    let (narrow, _) = read(&set, 1, true);
    let (wide, w) = read(&set, 4, true);
    assert!(w >= 1, "nothing went wide");
    assert_eq!(wide, narrow);
}

/// `x`: a writer that is a file, or one the caller says nothing about,
/// keeps the seam and never takes the wide read (decided 28
/// Sep 2026), and writes the same bytes.
#[test]
fn a_written_member_to_a_file_or_an_unsaid_writer_never_goes_wide() {
    let set = stored_set(LEN, PER);
    let (reference, _) = read(&set, 1, true);
    for hint in [None, Some(true)] {
        let (said, w) = read_hinted(&set, 4, true, hint);
        assert_eq!(w, 0, "sink_is_file {hint:?} went wide");
        assert_eq!(said, reference, "sink_is_file {hint:?}");
    }
}
