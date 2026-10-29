//! A stored member under BLAKE2sp read at a width of one, four, six and
//! the default: every width says the digest is right and hands over the
//! member's own bytes, and a flipped byte is refused at every width.
//!
//! Four and six are the widths whose leaf team runs two leaves a share in
//! one stream (`many::leaf_pair_run`, 16 Oct 2026); one is the lane kernel
//! on the calling thread and the default is the team of eight. On a box
//! with fewer than eight cores every width takes the lane kernel, and the
//! test still holds the digest to the member there.
//!
//! The pool widths are named by `ReadOptions::with_workers`; the member is
//! 24 MiB and no whole number of the digest's 512-byte groups, so the team
//! is earned and the tail is a partial group. Memory: the archive and one
//! copy of the member at a time, about 75 MiB.

use std::sync::{Arc, Mutex};

use rarkit::{
    extract, ChecksumKind, Disposition, MemberInfo, MemberOutcome, MemberSpec, Payload, Progress,
    RangeSource, ReadOptions, Result, WriteMethod, WriteOptions, Writer,
};

const LEN: usize = (24 << 20) + 301;

/// Incompressible, deterministic bytes.
fn noise(seed: u64, n: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// One member, stored under BLAKE2sp, by this crate's own writer.
fn archive(member: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new(WriteOptions {
        method: WriteMethod::Stored,
        checksum: ChecksumKind::Blake2sp,
        ..WriteOptions::default()
    })
    .expect("options");
    writer
        .add(MemberSpec {
            name: b"Full.mkv",
            payload: Payload::Bytes(member),
            mtime: None,
            attributes: 0,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    out
}

/// What one read said: the digest's verdict, the bytes the member
/// reported, and the bytes handed to the writer (`None` for a test).
#[derive(Debug, PartialEq)]
struct Said {
    error: bool,
    verdict: Option<bool>,
    bytes: u64,
    written: Option<Vec<u8>>,
}

#[derive(Clone, Default)]
struct Kept(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Kept {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// `archive` read by the walk at `width` (`None` is the default), tested
/// (`write` false) or written to a writer.
fn read(archive: &[u8], width: Option<usize>, write: bool) -> Said {
    struct One {
        write: bool,
        kept: Kept,
        closes: Vec<(Option<bool>, u64)>,
    }
    impl rarkit::Sink for One {
        type Out = Kept;
        fn open(&mut self, _: &MemberInfo<'_>) -> Result<Disposition<Kept>> {
            Ok(if self.write {
                Disposition::Write(self.kept.clone())
            } else {
                Disposition::Verify
            })
        }
        fn close(
            &mut self,
            _: &MemberInfo<'_>,
            _: Option<Kept>,
            outcome: &MemberOutcome,
        ) -> Result<()> {
            self.closes.push((outcome.checksum_ok, outcome.bytes));
            Ok(())
        }
    }
    struct Quiet;
    impl Progress for Quiet {}
    let mut sink = One {
        write,
        kept: Kept::default(),
        closes: Vec::new(),
    };
    let sources = vec![Arc::new(archive.to_vec()) as Arc<dyn RangeSource>];
    let options = ReadOptions::default().with_workers(width);
    let error = extract(sources, &options, &mut sink, &mut Quiet).is_err();
    assert_eq!(sink.closes.len(), 1, "width {width:?}: one member closed");
    let (verdict, bytes) = sink.closes[0];
    let written = write.then(|| std::mem::take(&mut *sink.kept.0.lock().unwrap()));
    Said {
        error,
        verdict,
        bytes,
        written,
    }
}

const WIDTHS: [Option<usize>; 4] = [Some(1), Some(4), Some(6), None];

#[test]
fn every_width_proves_and_hands_over_the_member() {
    let member = noise(5, LEN);
    let archive = archive(&member);
    for width in WIDTHS {
        for write in [false, true] {
            let said = read(&archive, width, write);
            assert!(!said.error, "width {width:?}, write {write}: an error");
            assert_eq!(said.verdict, Some(true), "width {width:?}, write {write}");
            assert_eq!(said.bytes, LEN as u64, "width {width:?}, write {write}");
            if write {
                assert!(
                    said.written.as_deref() == Some(&member[..]),
                    "width {width:?}: the bytes written"
                );
            }
        }
    }
}

#[test]
fn a_flipped_byte_is_refused_at_every_width() {
    let member = noise(6, LEN);
    let good = archive(&member);
    let len = good.len();
    for at in [len / 50, len / 2, len - 600] {
        let mut bad = good.clone();
        bad[at] ^= 0x40;
        for width in WIDTHS {
            let said = read(&bad, width, false);
            assert_eq!(said.verdict, Some(false), "at {at}, width {width:?}");
        }
    }
}
