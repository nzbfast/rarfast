//! Fragments abreast (`read::across`): a STORED member posted in volumes
//! smaller than the wide read's floor of 16 MiB, checked
//! (`Disposition::Verify`, the `t` command) or written to a stream (`p`),
//! is read and hashed by one team of readers kept across its volume files,
//! and says and writes exactly what the read in order says and writes.
//!
//! The shape is the commonest posting one scaled down: one incompressible
//! stored member over many volumes, every fragment under the floor. Every
//! case reads the set twice at one width, the knob off (each fragment in
//! order on the member's thread, the path before) and on, and asserts the
//! second really did run abreast before it compares anything, so a
//! comparison of two reads in order cannot pass for one of a read abreast.

use std::sync::Arc;

use rarkit::{
    extract, Disposition, MemberInfo, MemberOutcome, MemberSpec, Password, Payload, Progress,
    RangeSource, ReadOptions, Result, Sink, WriteFormat, WriteOptions, Writer,
};

/// Incompressible, deterministic bytes.
fn noise(seed: u64, n: usize) -> Vec<u8> {
    let mut x: u64 = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// Stored members of `lens` bytes in volumes of about `per` bytes, by this
/// crate's own writer, and their bytes.
fn stored_set_with(
    lens: &[usize],
    per: u64,
    options: WriteOptions,
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let truth: Vec<Vec<u8>> = lens
        .iter()
        .enumerate()
        .map(|(at, len)| noise(7 + at as u64, *len))
        .collect();
    let mut writer = Writer::new(WriteOptions {
        volume_size: Some(per),
        ..options
    })
    .expect("options");
    let names: Vec<String> = (0..lens.len())
        .map(|at| format!("E{:02}.mkv", at + 1))
        .collect();
    for (name, data) in names.iter().zip(&truth) {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(data),
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out: Vec<Vec<u8>> = Vec::new();
    writer.finish_volumes(&mut out).expect("finish");
    (out, truth)
}

fn stored_set(lens: &[usize], per: u64) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    stored_set_with(lens, per, WriteOptions::default())
}

/// Every member's outcome, and its bytes where it is written.
#[derive(Default)]
struct Verdicts {
    outcomes: Vec<(Vec<u8>, MemberOutcome)>,
    written: bool,
    bytes: Vec<Vec<u8>>,
    mismatches: Vec<(Vec<u8>, u32)>,
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

    fn fragment_mismatch(&mut self, member: &MemberInfo<'_>, volume: u32) -> Result<()> {
        self.mismatches.push((member.name.to_vec(), volume));
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
/// member, volume and offset; the volumes finished; each written member's
/// length and CRC32; and the fragments reported as mismatched.
#[derive(Debug, PartialEq)]
struct Said {
    outcomes: std::result::Result<Vec<(Vec<u8>, MemberOutcome)>, String>,
    done: Vec<u32>,
    written: Vec<(usize, u32)>,
    mismatches: Vec<(Vec<u8>, u32)>,
}

/// How a set is read: the width, whether its members are written (as `p`
/// writes them: the writer is said not to be a file), and a password.
#[derive(Clone, Copy)]
struct How {
    workers: usize,
    written: bool,
    password: Option<&'static str>,
}

const CHECKED: How = How {
    workers: 4,
    written: false,
    password: None,
};
const WRITTEN: How = How {
    workers: 4,
    written: true,
    password: None,
};

/// One read with the knob `abreast`: what it said, how many runs went
/// abreast and how many ranges went wide.
fn read(volumes: &[Vec<u8>], how: How, abreast: bool) -> (Said, u64, u64) {
    let sources: Vec<Arc<dyn RangeSource>> = volumes
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect();
    let options = ReadOptions::default()
        .with_workers(Some(how.workers))
        .with_sink_is_file(how.written.then_some(false))
        .with_password(how.password.map(Password::from));
    let mut sink = Verdicts {
        written: how.written,
        ..Verdicts::default()
    };
    let mut trail = Trail::default();
    rarkit::probe::set_fragments_abreast(Some(abreast));
    rarkit::probe::reset_fragments_abreast_runs();
    rarkit::probe::reset_wide_verifies();
    let outcome = extract(sources, &options, &mut sink, &mut trail);
    let runs = rarkit::probe::fragments_abreast_runs();
    let wide = rarkit::probe::wide_verifies();
    rarkit::probe::set_fragments_abreast(None);
    let outcomes = match outcome {
        Ok(_) => Ok(sink.outcomes),
        Err(e) => Err(format!(
            "{:?} member {:?} volume {:?} offset {:?}",
            e.kind(),
            e.member().map(<[u8]>::to_vec),
            e.volume(),
            e.offset()
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
            mismatches: sink.mismatches,
        },
        runs,
        wide,
    )
}

/// Both reads of a set, the second asserted to have run abreast, and held
/// equal; the read abreast is answered.
fn both(volumes: &[Vec<u8>], how: How) -> Said {
    let (in_order, none, _) = read(volumes, how, false);
    let (abreast, runs, _) = read(volumes, how, true);
    assert_eq!(none, 0, "the knob off never reads abreast");
    assert!(runs >= 1, "nothing was read abreast");
    assert_eq!(abreast, in_order);
    abreast
}

/// One member of 40 MiB in volumes of 3 MiB: fourteen fragments, each
/// under the floor.
const LEN: usize = 40 << 20;
const PER: u64 = 3 << 20;

#[test]
fn a_whole_set_says_ok_abreast_and_in_order() {
    let (set, _) = stored_set(&[LEN], PER);
    assert!(set.len() >= 13, "a set of {} volumes", set.len());
    let said = both(&set, CHECKED);
    let outcomes = said.outcomes.expect("a whole set reads");
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].1.checksum_ok, Some(true));
    assert_eq!(outcomes[0].1.bytes, LEN as u64);
    assert_eq!(outcomes[0].1.fragment_mismatches, 0);
    assert_eq!(said.done, (0..set.len() as u32).collect::<Vec<_>>());
}

/// `p`: the member's bytes reach its writer from the member's own thread
/// in order, the bytes that were stored.
#[test]
fn a_written_member_writes_the_same_bytes_abreast() {
    let (set, truth) = stored_set(&[LEN], PER);
    let said = both(&set, WRITTEN);
    assert_eq!(
        said.written,
        vec![(LEN, rarkit::checksum::crc32(&truth[0]))],
        "the written bytes are the stored ones"
    );
    assert_eq!(
        said.outcomes.expect("a whole set reads")[0].1.checksum_ok,
        Some(true)
    );
}

/// A set of many members: several members, each over several small volumes, each its
/// own run, sharing volumes at their ends.
#[test]
fn several_members_each_read_abreast() {
    let lens = [20 << 20, (17 << 20) + 5, 33 << 20];
    let (set, truth) = stored_set(&lens, PER);
    let (_, runs, _) = read(&set, CHECKED, true);
    assert!(runs >= 3, "only {runs} runs for three members");
    let said = both(&set, WRITTEN);
    let want: Vec<(usize, u32)> = truth
        .iter()
        .map(|b| (b.len(), rarkit::checksum::crc32(b)))
        .collect();
    assert_eq!(said.written, want);
    for (_, outcome) in said.outcomes.expect("a whole set reads") {
        assert_eq!(outcome.checksum_ok, Some(true));
    }
}

/// A wrong byte in a middle volume fails the member and names that
/// volume's fragment, both ways.
#[test]
fn a_flipped_byte_in_a_middle_volume_says_the_same_both_ways() {
    let (mut set, _) = stored_set(&[LEN], PER);
    let middle = set.len() / 2;
    let at = set[middle].len() / 2;
    set[middle][at] ^= 0x01;
    for how in [CHECKED, WRITTEN] {
        let said = both(&set, how);
        let outcomes = said
            .outcomes
            .expect("a bad byte is a verdict, not an error");
        assert_eq!(outcomes[0].1.checksum_ok, Some(false));
        assert_eq!(outcomes[0].1.fragment_mismatches, 1);
        assert_eq!(said.mismatches.len(), 1);
        assert_eq!(said.mismatches[0].1, middle as u32);
    }
}

/// A middle volume cut short ends the read with the same error, naming the
/// same volume and offset, and a written member has the same prefix
/// written first: every byte in front of the cut, though pieces behind it
/// were being read when it was found.
#[test]
fn a_cut_middle_volume_ends_the_same_way_both_ways() {
    let (mut set, _) = stored_set(&[LEN], PER);
    let middle = set.len() / 2;
    let keep = set[middle].len() / 3;
    set[middle].truncate(keep);
    for how in [CHECKED, WRITTEN] {
        let said = both(&set, how);
        let error = said.outcomes.expect_err("a cut volume is an error");
        assert!(
            error.contains("Truncated") && error.contains(&format!("volume Some({middle})")),
            "{error}"
        );
    }
}

/// A set whose last volumes are missing ends the same way both ways: the
/// crossing that finds no volume is the walk's own error, given only once
/// every byte in front of it is joined.
#[test]
fn a_set_missing_its_last_volumes_ends_the_same_way_both_ways() {
    let (mut set, _) = stored_set(&[LEN], PER);
    let kept = set.len() - 4;
    set.truncate(kept);
    for how in [CHECKED, WRITTEN] {
        let said = both(&set, how);
        let error = said.outcomes.expect_err("a short set is an error");
        assert!(error.contains("Truncated"), "{error}");
    }
}

/// A width of one has no plan to spread over, so a stated `-mt1` reads on
/// one thread whatever the knob says.
#[test]
fn a_width_of_one_never_reads_abreast() {
    let (set, _) = stored_set(&[LEN], PER);
    let one = How {
        workers: 1,
        ..CHECKED
    };
    let (in_order, _, _) = read(&set, one, false);
    let (still, runs, wide) = read(&set, one, true);
    assert_eq!(runs, 0, "a width of one went abreast");
    assert_eq!(wide, 0, "a width of one went wide");
    assert_eq!(still, in_order);
}

/// A member under the wide read's floor is not one the wide read takes,
/// and is read as it always was.
#[test]
fn a_member_under_the_floor_never_reads_abreast() {
    let (set, _) = stored_set(&[(15 << 20) + 9], PER);
    let (in_order, _, _) = read(&set, CHECKED, false);
    let (still, runs, _) = read(&set, CHECKED, true);
    assert_eq!(runs, 0);
    assert_eq!(still, in_order);
}

/// Fragments under the floor and at it in one member: a short member in
/// front leaves the long one a first fragment under the floor, its next
/// ones are whole volumes of 20 MiB, and its last is short again. The run
/// abreast takes the short ones and stands aside for the wide read.
#[test]
fn fragments_under_and_over_the_floor_in_one_member() {
    let lens = [12 << 20, 70 << 20];
    let (set, truth) = stored_set(&lens, 20 << 20);
    let (said, runs, wide) = read(&set, WRITTEN, true);
    assert!(runs >= 1, "nothing was read abreast");
    assert!(wide >= 2, "only {wide} ranges went wide");
    let (in_order, _, _) = read(&set, WRITTEN, false);
    assert_eq!(said, in_order);
    let want: Vec<(usize, u32)> = truth
        .iter()
        .map(|b| (b.len(), rarkit::checksum::crc32(b)))
        .collect();
    assert_eq!(said.written, want);
}

/// A written member whose writer is a file, or one the caller says
/// nothing about (`x`), keeps the path it has: never abreast.
#[test]
fn a_member_written_to_a_file_never_reads_abreast() {
    let (set, _) = stored_set(&[LEN], PER);
    for hint in [None, Some(true)] {
        let sources: Vec<Arc<dyn RangeSource>> = set
            .iter()
            .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
            .collect();
        let options = ReadOptions::default()
            .with_workers(Some(4))
            .with_sink_is_file(hint);
        let mut sink = Verdicts {
            written: true,
            ..Verdicts::default()
        };
        rarkit::probe::set_fragments_abreast(Some(true));
        rarkit::probe::reset_fragments_abreast_runs();
        extract(sources, &options, &mut sink, &mut ()).expect("the set reads");
        let runs = rarkit::probe::fragments_abreast_runs();
        rarkit::probe::set_fragments_abreast(None);
        assert_eq!(runs, 0, "sink_is_file {hint:?} went abreast");
        assert_eq!(sink.bytes[0].len(), LEN);
    }
}

/// An encrypted member keeps the path it has (its chain crosses fragment
/// ends: a second step), clear headers or encrypted, and reads the same
/// whatever the knob says.
#[test]
fn an_encrypted_member_never_reads_abreast() {
    for headers in [false, true] {
        let (set, truth) = stored_set_with(
            &[LEN],
            PER,
            WriteOptions {
                password: Some(Password::from("abreast")),
                encrypt_headers: headers,
                ..WriteOptions::default()
            },
        );
        let how = How {
            password: Some("abreast"),
            ..WRITTEN
        };
        let (in_order, _, _) = read(&set, how, false);
        let (still, runs, _) = read(&set, how, true);
        assert_eq!(runs, 0, "an encrypted member went abreast");
        assert_eq!(still, in_order);
        assert_eq!(
            still.written,
            vec![(LEN, rarkit::checksum::crc32(&truth[0]))]
        );
    }
}

/// A RAR 4 set: the same walk and the same two checksums of a split
/// member (spec F 3.5.6), read abreast and in order alike.
#[test]
fn a_rar4_set_reads_the_same_both_ways() {
    let (set, truth) = stored_set_with(
        &[LEN],
        PER,
        WriteOptions {
            format: WriteFormat::Rar4(rarkit::Rar4Version::V29),
            filters: rarkit::FilterPolicy::Off,
            ..WriteOptions::default()
        },
    );
    let said = both(&set, WRITTEN);
    assert_eq!(
        said.written,
        vec![(LEN, rarkit::checksum::crc32(&truth[0]))]
    );
    assert_eq!(
        said.outcomes.expect("a whole set reads")[0].1.checksum_ok,
        Some(true)
    );
    let mut bad = set.clone();
    let middle = bad.len() / 2;
    let at = bad[middle].len() / 2;
    bad[middle][at] ^= 0x80;
    let said = both(&bad, CHECKED);
    assert_eq!(
        said.outcomes.expect("a verdict")[0].1.checksum_ok,
        Some(false)
    );
}

/// Volumes far smaller than a piece: every fragment is one short piece,
/// many volumes are crossed inside one window, and the bound on volumes
/// open ahead is what paces the run.
#[test]
fn tiny_volumes_read_the_same_both_ways() {
    let (set, truth) = stored_set(&[(17 << 20) + 3], 70_000);
    assert!(set.len() > 200, "a set of {} volumes", set.len());
    let said = both(&set, WRITTEN);
    assert_eq!(
        said.written,
        vec![(truth[0].len(), rarkit::checksum::crc32(&truth[0]))]
    );
    let (_, _, bound) = rarkit::probe::open_ahead();
    let (peak, _, _) = rarkit::probe::open_ahead();
    assert!(
        peak <= bound,
        "{peak} volumes open ahead over a bound of {bound}"
    );
}

/// A host that will start no thread, or only a few, reads the same bytes
/// with the readers it has: none at all is the read in order, a piece at
/// a time, on the member's own thread.
#[test]
fn a_host_out_of_threads_reads_the_same_with_the_readers_it_has() {
    let (set, _) = stored_set(&[LEN], PER);
    for how in [CHECKED, WRITTEN] {
        let (in_order, _, _) = read(&set, how, false);
        for allowed in [0usize, 1, 3] {
            rarkit::probe::allow_spawns(Some(allowed));
            let (said, runs, _) = read(&set, how, true);
            rarkit::probe::allow_spawns(None);
            assert!(runs >= 1, "nothing was read abreast");
            assert_eq!(said, in_order, "{allowed} threads allowed");
        }
    }
}

/// A host that lets go of a volume the moment it is told it may (spec F
/// 3.7.3): `released(volume, offset)` frees every byte below `offset`, and
/// `volume_done` the whole volume. A read of freed bytes fails, and is
/// counted, so nothing can pass by luck.
mod hostile {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;

    use rarkit::{Progress, RangeSource, Result};

    #[derive(Default)]
    pub struct Freed {
        pub below: Vec<AtomicU64>,
        pub done: Vec<AtomicBool>,
        /// Reads that asked for a freed byte.
        pub late: AtomicU64,
    }

    impl Freed {
        pub fn of(volumes: usize) -> Arc<Freed> {
            Arc::new(Freed {
                below: (0..volumes).map(|_| AtomicU64::new(0)).collect(),
                done: (0..volumes).map(|_| AtomicBool::new(false)).collect(),
                late: AtomicU64::new(0),
            })
        }
    }

    pub struct Volume {
        pub data: Vec<u8>,
        pub index: usize,
        pub freed: Arc<Freed>,
    }

    impl RangeSource for Volume {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            let start = (offset as usize).min(self.data.len());
            let n = buf.len().min(self.data.len() - start);
            if n > 0
                && (self.freed.done[self.index].load(Ordering::SeqCst)
                    || offset < self.freed.below[self.index].load(Ordering::SeqCst))
            {
                self.freed.late.fetch_add(1, Ordering::SeqCst);
                return Err(std::io::Error::other(
                    "a byte the host was told it may free",
                ));
            }
            buf[..n].copy_from_slice(&self.data[start..start + n]);
            Ok(n)
        }
        fn available(&self) -> u64 {
            self.data.len() as u64
        }
        fn len(&self) -> Option<u64> {
            Some(self.data.len() as u64)
        }
    }

    pub struct Frees(pub Arc<Freed>);

    impl Progress for Frees {
        fn released(&mut self, volume: u32, offset: u64) -> Result<()> {
            let below = &self.0.below[volume as usize];
            assert!(
                offset >= below.load(Ordering::SeqCst),
                "released went backwards on volume {volume}"
            );
            below.store(offset, Ordering::SeqCst);
            Ok(())
        }

        fn volume_done(&mut self, volume: u32) -> Result<()> {
            self.0.done[volume as usize].store(true, Ordering::SeqCst);
            Ok(())
        }
    }
}

/// One read of `set` on the hostile host: how many reads asked for a freed
/// byte, what the read said, and whether every volume was let go at last.
fn read_hostile(set: &[Vec<u8>], how: How, form: Option<u8>) -> (u64, Said, bool) {
    use std::sync::atomic::Ordering;
    let freed = hostile::Freed::of(set.len());
    let sources: Vec<Arc<dyn RangeSource>> = set
        .iter()
        .enumerate()
        .map(|(index, data)| {
            Arc::new(hostile::Volume {
                data: data.clone(),
                index,
                freed: Arc::clone(&freed),
            }) as Arc<dyn RangeSource>
        })
        .collect();
    let options = ReadOptions::default()
        .with_workers(Some(how.workers))
        .with_sink_is_file(how.written.then_some(false))
        .with_password(how.password.map(Password::from));
    let mut sink = Verdicts {
        written: how.written,
        ..Verdicts::default()
    };
    match form {
        Some(0) => rarkit::probe::set_fragments_abreast(Some(false)),
        Some(1) => rarkit::probe::set_fragments_abreast(Some(true)),
        Some(_) => rarkit::probe::set_fragments_abreast_joined(),
        None => rarkit::probe::set_fragments_abreast(None),
    }
    let outcome = extract(
        sources,
        &options,
        &mut sink,
        &mut hostile::Frees(Arc::clone(&freed)),
    );
    rarkit::probe::set_fragments_abreast(None);
    let outcomes = match outcome {
        Ok(_) => Ok(sink.outcomes),
        Err(e) => Err(format!(
            "{:?} member {:?} volume {:?} offset {:?}",
            e.kind(),
            e.member().map(<[u8]>::to_vec),
            e.volume(),
            e.offset()
        )),
    };
    let written = sink
        .bytes
        .iter()
        .map(|b| (b.len(), rarkit::checksum::crc32(b)))
        .collect();
    let all_done = freed.done.iter().all(|d| d.load(Ordering::SeqCst));
    (
        freed.late.load(Ordering::SeqCst),
        Said {
            outcomes,
            done: (0..set.len() as u32).collect(),
            written,
            mismatches: sink.mismatches,
        },
        all_done,
    )
}

/// Drop-behind keeps its plain promise (spec F 3.7.3) in every form: on a
/// host that frees a volume's bytes the moment `released` or `volume_done`
/// says it may, the member reads whole and right, no read ever asks for a
/// freed byte, and every volume is let go by the end. Read abreast, the
/// walk crosses to the next volume while this one's pieces are still being
/// read, so this one's news is told at its last join, not at the crossing.
#[test]
fn a_host_that_frees_what_is_released_reads_whole_in_every_form() {
    for (lens, per) in [
        (&[LEN][..], PER),
        (&[20 << 20, 33 << 20][..], PER),
        (&[LEN][..], 300_000),
    ] {
        let (set, truth) = stored_set(lens, per);
        let want: Vec<(usize, u32)> = truth
            .iter()
            .map(|b| (b.len(), rarkit::checksum::crc32(b)))
            .collect();
        for how in [CHECKED, WRITTEN] {
            for form in [0u8, 1, 2] {
                let (late, said, all_done) = read_hostile(&set, how, Some(form));
                assert_eq!(late, 0, "form {form}: reads of freed bytes");
                let outcomes = said.outcomes.unwrap_or_else(|e| panic!("form {form}: {e}"));
                assert!(outcomes.iter().all(|o| o.1.checksum_ok == Some(true)));
                if how.written {
                    assert_eq!(said.written, want, "form {form}");
                }
                assert!(all_done, "form {form}: a volume was never let go");
            }
        }
    }
}

/// The same promise on the paths this lever does not touch, with the knob
/// off: `extract` of split members it hands to workers or to the seam (a
/// stored member written to a file, compressed members checked and
/// written), on the hostile host. A count, held at zero.
#[test]
fn the_paths_before_never_read_a_freed_byte_either() {
    let stored = stored_set(&[LEN, 20 << 20, (18 << 20) + 1], PER).0;
    let texts: Vec<Vec<u8>> = (0..6)
        .map(|m| rarkit_testdata::chatter((40 + m) as u64, (3 << 20) + m as usize))
        .collect();
    let mut writer = Writer::new(WriteOptions {
        volume_size: Some(400_000),
        method: rarkit::WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
        ..WriteOptions::default()
    })
    .expect("options");
    let names: Vec<String> = (0..texts.len()).map(|m| format!("T{m}.txt")).collect();
    for (name, data) in names.iter().zip(&texts) {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(data),
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut packed: Vec<Vec<u8>> = Vec::new();
    writer.finish_volumes(&mut packed).expect("finish");
    assert!(
        packed.len() >= 4,
        "a compressed set of {} volumes",
        packed.len()
    );
    for (what, set) in [("stored", &stored), ("compressed", &packed)] {
        for workers in [1usize, 4, 8] {
            for written in [false, true] {
                let freed = hostile::Freed::of(set.len());
                let sources: Vec<Arc<dyn RangeSource>> = set
                    .iter()
                    .enumerate()
                    .map(|(index, data)| {
                        Arc::new(hostile::Volume {
                            data: data.clone(),
                            index,
                            freed: Arc::clone(&freed),
                        }) as Arc<dyn RangeSource>
                    })
                    .collect();
                let options = ReadOptions::default().with_workers(Some(workers));
                let mut sink = Verdicts {
                    written,
                    ..Verdicts::default()
                };
                rarkit::probe::set_fragments_abreast(Some(false));
                let outcome = extract(
                    sources,
                    &options,
                    &mut sink,
                    &mut hostile::Frees(Arc::clone(&freed)),
                );
                rarkit::probe::set_fragments_abreast(None);
                let late = freed.late.load(std::sync::atomic::Ordering::SeqCst);
                assert_eq!(
                    late, 0,
                    "{what}, {workers} workers, written {written}: reads of freed bytes ({outcome:?})"
                );
                outcome.unwrap_or_else(|e| panic!("{what}, {workers} workers: {e:?}"));
                assert!(sink.outcomes.iter().all(|o| o.1.checksum_ok == Some(true)));
            }
        }
    }
}

/// A provider that notes, each time it is asked for a volume, how many of
/// the member's bytes its writer has been given so far.
struct Asked {
    volumes: Vec<Arc<dyn RangeSource>>,
    delivered: Arc<std::sync::atomic::AtomicU64>,
    at_each_ask: Arc<std::sync::Mutex<Vec<u64>>>,
}

impl rarkit::Volumes for Asked {
    fn volume(&mut self, index: u32) -> Result<Option<Arc<dyn RangeSource>>> {
        self.at_each_ask
            .lock()
            .unwrap()
            .push(self.delivered.load(std::sync::atomic::Ordering::SeqCst));
        Ok(self.volumes.get(index as usize).cloned())
    }
}

struct Counting(Arc<std::sync::atomic::AtomicU64>);

impl std::io::Write for Counting {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0
            .fetch_add(data.len() as u64, std::sync::atomic::Ordering::SeqCst);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct ToCounter(Arc<std::sync::atomic::AtomicU64>, Vec<Option<bool>>);

impl Sink for ToCounter {
    type Out = Counting;
    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Counting>> {
        Ok(Disposition::Write(Counting(Arc::clone(&self.0))))
    }
    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        _out: Option<Counting>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.1.push(outcome.checksum_ok);
        Ok(())
    }
}

/// How many member bytes had been delivered each time the provider was
/// asked for a volume, how many runs went abreast, and how many volumes
/// were asked for ahead of their join; the knob as shipped unless `off`.
fn asks(set: &[Vec<u8>], present: bool, off: bool) -> (Vec<u64>, u64, u64) {
    let delivered = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let at_each_ask = Arc::new(std::sync::Mutex::new(Vec::new()));
    let provider = Asked {
        volumes: set
            .iter()
            .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
            .collect(),
        delivered: Arc::clone(&delivered),
        at_each_ask: Arc::clone(&at_each_ask),
    };
    let options = ReadOptions::default()
        .with_workers(Some(4))
        .with_sink_is_file(Some(false))
        .with_volumes_present(present);
    let mut sink = ToCounter(delivered, Vec::new());
    rarkit::probe::set_fragments_abreast(off.then_some(false));
    rarkit::probe::reset_fragments_abreast_runs();
    extract(provider, &options, &mut sink, &mut ()).expect("the set reads");
    let runs = rarkit::probe::fragments_abreast_runs();
    let ahead = rarkit::probe::crossed_ahead();
    rarkit::probe::set_fragments_abreast(None);
    assert_eq!(sink.1, vec![Some(true)]);
    let asks = at_each_ask.lock().unwrap().clone();
    (asks, runs, ahead)
}

/// SPEC-API 5.3: a caller that says nothing is asked for volume `k + 1`
/// only after every member byte of volume `k` has been delivered, read
/// abreast or not, so a provider that blocks until a volume arrives never
/// holds back bytes it already gave; a caller that says its volumes are
/// all present is asked earlier, inside the read-ahead.
#[test]
fn a_caller_that_says_nothing_is_asked_for_the_next_volume_only_after_this_one() {
    let (set, _) = stored_set(&[LEN], PER);
    let (in_order, none, _) = asks(&set, false, true);
    assert_eq!(none, 0);
    assert_eq!(in_order.len(), set.len(), "each volume asked for once");

    let (unsaid, runs, ahead) = asks(&set, false, false);
    assert!(runs >= 1, "the shipped read of an unsaid caller is abreast");
    assert_eq!(ahead, 0, "an unsaid caller was asked for a volume ahead");
    assert_eq!(
        unsaid, in_order,
        "delivered at each ask, as the read in order"
    );

    let (present, runs, ahead) = asks(&set, true, false);
    assert!(runs >= 1);
    assert!(
        ahead >= 1,
        "a caller with every volume present was never asked ahead"
    );
    assert_eq!(present.len(), in_order.len());
    assert!(
        present.iter().zip(&in_order).all(|(now, then)| now <= then)
            && present.iter().zip(&in_order).any(|(now, then)| now < then),
        "asked ahead, never later"
    );
}

/// A member checked by BLAKE2sp keeps the path it has, whichever way the
/// wide read of such a member is switched: its digest is one ordered
/// stream, which a join of CRC32s does not feed. (Found by the Linux gate,
/// 2 Oct 2026: with the BLAKE2sp wide read on, the run abreast took such a
/// member and its record was called bad.)
#[test]
fn a_blake2sp_member_never_reads_abreast() {
    let (set, truth) = stored_set_with(
        &[LEN, (25 << 20) + 13],
        PER,
        WriteOptions {
            checksum: rarkit::ChecksumKind::Blake2sp,
            ..WriteOptions::default()
        },
    );
    let want: Vec<(usize, u32)> = truth
        .iter()
        .map(|b| (b.len(), rarkit::checksum::crc32(b)))
        .collect();
    for wide in [false, true] {
        rarkit::probe::set_b2sp_wide(Some(wide));
        for how in [CHECKED, WRITTEN] {
            let (in_order, _, _) = read(&set, how, false);
            let (still, runs, _) = read(&set, how, true);
            assert_eq!(runs, 0, "a BLAKE2sp member went abreast (wide {wide})");
            assert_eq!(still, in_order, "wide {wide}");
            let outcomes = still.outcomes.expect("the set reads");
            assert!(
                outcomes.iter().all(|o| o.1.checksum_ok == Some(true)),
                "wide {wide}: a good BLAKE2sp record was called bad"
            );
            if how.written {
                assert_eq!(still.written, want, "wide {wide}");
            }
        }
        rarkit::probe::set_b2sp_wide(None);
    }
}

/// A read-ahead too small for two of this system's full pieces: on macOS
/// (two readers of 128 KiB, where the plan asks for 1 MiB first) a kept
/// team gains nothing and the member reads as it did; everywhere else the
/// smallest piece is the full one and the run goes abreast. Either way the
/// same bytes and verdict. A named limit is never read slower inside it.
#[test]
fn a_budget_under_two_full_pieces_reads_abreast_only_where_it_pays() {
    let (set, truth) = stored_set(&[LEN], PER);
    let read_small = |abreast: bool| {
        let sources: Vec<Arc<dyn RangeSource>> = set
            .iter()
            .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
            .collect();
        let mut options = ReadOptions::default()
            .with_workers(Some(4))
            .with_sink_is_file(Some(false))
            .with_volumes_present(true);
        options.memory.read_ahead = 256 * 1024;
        let mut sink = Verdicts {
            written: true,
            ..Verdicts::default()
        };
        rarkit::probe::set_fragments_abreast(abreast.then_some(true).or(Some(false)));
        rarkit::probe::reset_fragments_abreast_runs();
        extract(sources, &options, &mut sink, &mut ()).expect("the set reads");
        let runs = rarkit::probe::fragments_abreast_runs();
        rarkit::probe::set_fragments_abreast(None);
        assert_eq!(sink.outcomes[0].1.checksum_ok, Some(true));
        (
            runs,
            sink.bytes[0].len(),
            rarkit::checksum::crc32(&sink.bytes[0]),
        )
    };
    let (none, len, crc) = read_small(false);
    assert_eq!(none, 0);
    assert_eq!((len, crc), (LEN, rarkit::checksum::crc32(&truth[0])));
    let (runs, len, crc) = read_small(true);
    assert_eq!((len, crc), (LEN, rarkit::checksum::crc32(&truth[0])));
    if cfg!(target_os = "macos") {
        assert_eq!(runs, 0, "two readers of 128 KiB went abreast on macOS");
    } else {
        assert!(runs >= 1, "nothing was read abreast");
    }
}
