//! A member the sink SKIPPED, in a SOLID chain, split across volumes, whose
//! decode ends in a decode FAULT part way: what the sink hears.
//!
//! A skipped member of a solid chain is still decoded, because the members
//! behind it are packed against its bytes. When that decode ends in a
//! decoder's verdict with fragments of the member still ahead, the walk
//! passes over them (`read/extract.rs`, `land`), as it does for a member
//! the sink took (`tests/split_member_decode_fault_one_close.rs`). This
//! file holds what a sink sees of it, the same from every reader:
//!
//! - the skipped member is offered ONCE (the `open` it answers `Skip` to)
//!   and never closed, and never offered again as its own continuation;
//! - every member the sink took is opened once and closed once;
//! - the fault is the error the operation returns, naming the member;
//! - the members BEHIND the fault are each closed with their own
//!   checksum's verdict. In this set every one of them comes out whole
//!   and good from every reader, although each carries the solid flag
//!   and the member in front of it lost two thirds of its bytes. That is
//!   what this set gives and it is pinned as observed: WHY (where the
//!   writer's solid runs begin here, what the decoder holds after a
//!   fault) was not established for this test, and it is no claim about
//!   a chain whose members reach back into lost bytes.
//!
//! The same set read with NOTHING skipped is held beside it: the damaged
//! member is then closed once, failed, with the bytes it had.
//!
//! The set is written here and is the same bytes every run: eight members
//! of 3 MiB and a bit, SOLID, level 3 with a NAMED 2 MiB dictionary, in
//! volumes of 5 MiB and a bit, clear headers, no password. The damage is
//! 4,096 bytes inverted 504,800 bytes before the end of volume 0, inside
//! the leading fragment of `E01.mkv`, which crosses into volume 1: its
//! decode ends `Corrupt(Rar5(BlockHeaderChecksum))` after 2,097,152 bytes.
//! The damage has to cover a block header for the fault to land, and the
//! test asserts that it does. It sat 1,030,000 bytes back (a fault after
//! 1,048,576 bytes) until 14 Oct 2026, when level 3's thin scan moved this
//! set's bytes and with them its block headers: re-aimed then
//! (FROM-STUDIO 389 C) at the one offset of a scan in 4 KiB steps from
//! 300,000 to 2,600,000 bytes back where the fault landed.
//!
//! ONE test, because the rule that picks the split jobs is a process wide
//! probe. Pools of 1 and of 8 threads; the set is 21 MiB and is held once
//! a read, so the test needs under 200 MiB.
#![cfg(feature = "test-support")]

use std::sync::{Arc, Mutex};

use rarkit::{
    extract, extract_parallel, probe, Disposition, MemberInfo, MemberOutcome, MemberSpec,
    ParallelSink, Payload, Progress, RangeSource, ReadOptions, Result, WriteMethod, WriteOptions,
    Writer,
};

const MEMBER_LEN: usize = (3 << 20) + 333;
const PER: u64 = (5 << 20) + 7;

fn member(i: usize) -> Vec<u8> {
    let mut x = (29 + i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..MEMBER_LEN)
        .map(|n| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            if (n >> 12) & 1 == 0 {
                (x >> 24) as u8
            } else {
                b"the quick brown fox "[(x % 20) as usize]
            }
        })
        .collect()
}

fn many() -> Vec<Vec<u8>> {
    let mut writer = Writer::new(WriteOptions {
        volume_size: Some(PER),
        method: WriteMethod::Compressed {
            level: 3,
            dictionary: Some(2 << 20),
        },
        solid: true,
        ..WriteOptions::default()
    })
    .expect("options");
    let parts: Vec<Vec<u8>> = (0..8).map(member).collect();
    let names: Vec<String> = (0..8).map(|i| format!("E0{i}.mkv")).collect();
    for (data, name) in parts.iter().zip(&names) {
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
    out
}

/// Hears every `open` and `close`, and skips the member named.
struct Sink {
    heard: Mutex<Vec<String>>,
    skip: &'static str,
}

impl Sink {
    fn skipping(skip: &'static str) -> Sink {
        Sink {
            heard: Mutex::default(),
            skip,
        }
    }
}

impl ParallelSink for Sink {
    type Out = Vec<u8>;
    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        self.heard
            .lock()
            .unwrap()
            .push(format!("open {}", member.name_lossy()));
        if member.name_lossy() == self.skip {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Vec::new()))
    }
    fn close(
        &self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.heard.lock().unwrap().push(format!(
            "close {} out={:?} ok={:?} bytes={}",
            member.name_lossy(),
            out.map(|o| o.len()),
            outcome.checksum_ok,
            outcome.bytes
        ));
        Ok(())
    }
}

struct Seq<'a>(&'a Sink);
impl rarkit::Sink for Seq<'_> {
    type Out = Vec<u8>;
    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        self.0.open(member)
    }
    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.0.close(member, out, outcome)
    }
}
struct Quiet;
impl Progress for Quiet {}

fn sources(volumes: &[Vec<u8>]) -> Vec<Arc<dyn RangeSource>> {
    volumes
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect()
}

/// What one read said: every `open` and `close` of the sink, in the order
/// it heard them, and the error the read ended with.
fn said(outcome: Option<rarkit::Error>, sink: Sink) -> (Vec<String>, Option<String>) {
    let error = outcome.map(|e| {
        format!(
            "{:?} member {:?}",
            e.kind(),
            e.member().map(|m| String::from_utf8_lossy(m).into_owned())
        )
    });
    (sink.heard.into_inner().unwrap(), error)
}

#[test]
fn a_skipped_solid_member_that_ends_in_a_decode_fault_is_offered_once_and_never_closed() {
    let mut set = many();
    assert_eq!(set.len(), 5, "a set of five volumes");
    let at = set[0].len() - 504_800;
    for byte in &mut set[0][at..at + 4096] {
        *byte ^= 0xff;
    }

    for skip in ["E01.mkv", ""] {
        let sequential = |workers: usize| {
            let sink = Sink::skipping(skip);
            let options = ReadOptions::default().with_workers(Some(workers));
            let outcome = extract(sources(&set), &options, &mut Seq(&sink), &mut Quiet);
            said(outcome.err(), sink)
        };
        let parallel = |all: bool| {
            let sink = Sink::skipping(skip);
            let options = ReadOptions::default()
                .with_workers(Some(8))
                .with_sink_is_file(Some(true));
            probe::set_split_jobs_all(Some(all));
            let outcome = extract_parallel(sources(&set), &options, &sink, 8);
            probe::set_split_jobs_all(None);
            said(outcome.err(), sink)
        };
        let reads = [
            ("extract, 1 worker", sequential(1)),
            ("extract, 8 workers", sequential(8)),
            ("extract_parallel, stored split jobs only", parallel(false)),
            ("extract_parallel, every split member a job", parallel(true)),
        ];

        for (reader, (heard, error)) in &reads {
            let what = format!("{reader}, skipping {skip:?}");
            assert_eq!(
                error.as_deref(),
                Some("Corrupt(Rar5(BlockHeaderChecksum)) member Some(\"E01.mkv\")"),
                "{what}"
            );
            for i in 0..8 {
                let name = format!("E0{i}.mkv");
                let of = |verb: &str| -> Vec<&String> {
                    heard
                        .iter()
                        .filter(|line| line.starts_with(&format!("{verb} {name}")))
                        .collect()
                };
                assert_eq!(
                    of("open").len(),
                    1,
                    "{what}: {name} offered once: {heard:?}"
                );
                let closes = of("close");
                if name == skip {
                    assert!(closes.is_empty(), "{what}: {name} is not closed: {heard:?}");
                    continue;
                }
                assert_eq!(closes.len(), 1, "{what}: {name} closed once: {heard:?}");
                let want = if i == 1 {
                    // The damaged member, taken: failed, with the bytes
                    // it had.
                    format!("close {name} out=Some(2097152) ok=Some(false) bytes=2097152")
                } else {
                    // Before the fault and behind it: whole, and good by
                    // its own checksum.
                    format!("close {name} out=Some({MEMBER_LEN}) ok=Some(true) bytes={MEMBER_LEN}")
                };
                assert_eq!(closes[0], &want, "{what}");
            }
            let closes = if skip.is_empty() { 8 } else { 7 };
            assert_eq!(heard.len(), 8 + closes, "{what}: {heard:?}");
        }
    }
}
