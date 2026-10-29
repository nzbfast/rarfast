//! A COMPRESSED member split across volumes whose decode ends in a decode
//! FAULT part way is opened ONCE and closed ONCE, whichever reader joins
//! it.
//!
//! A decoder's verdict on one member's bytes is that member's: it is
//! closed failed, with the bytes it had, and extraction goes on (spec F
//! 8). Until 9 Oct 2026 a reader that joined such a member in the walk
//! itself, the sequential `extract` and `extract_parallel` without split
//! jobs, left the walk standing inside the member: its next block was the
//! member's own CONTINUATION header in the next volume, which it took for
//! a member, so the sink was asked to OPEN the same member a second time
//! and was handed a second, empty close. A sink that opens a file by name
//! truncated the partial output it had just been given. `extract_parallel`
//! with every split member a job, which holds the member's fragment list,
//! never did.
//!
//! The set is written here and is the same bytes every run: eight members
//! of 3 MiB and a bit at level 3 with a NAMED 2 MiB dictionary, in volumes
//! of 5 MiB and a bit, clear headers, no password (a password draws a
//! fresh salt a run, and the same damage then lands on other bytes). The
//! damage is 131,072 bytes inverted from 1,488,416 bytes before the end
//! of volume 0, inside the leading fragment of `E01.mkv`: its decode ends
//! early, after the bytes the constant `KEPT` below pins (see `DAMAGE`
//! for why it is no longer a fault that ends it). It sat 1,500,000 bytes
//! back until 14 Oct 2026, when level 3's thin scan moved this set's bytes
//! and the 1,024 byte damage of then no longer landed there: re-aimed then
//! (FROM-STUDIO 389 C) at the nearest offset of a scan in 8 KiB steps from
//! 1,300,000 to 1,700,000 bytes back where the same decode ends after the
//! same bytes.
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

/// How many bytes of the leading fragment are inverted: enough to cover
/// block headers and not only symbols.
///
/// Until 11 Oct 2026 this test inverted 1,024 bytes, and the member's
/// decode ended `Corrupt(Rar5(DistanceOutOfRange))` after 1,048,576
/// bytes: a garbled match reached before the stream. Under the amended rule
/// (SPEC-H2 3.7) such a match gives zero bytes and is no fault, so that
/// damage no longer stops a decode. With this much inverted the member's
/// decode still ends EARLY, at the same 1,048,576 bytes, and it ends with
/// nothing said: the read returns no error and the member is closed
/// failed with what it had. That is what the readers below are held to,
/// each of them, and it leaves the member in the state the defect needed:
/// stopped inside its leading fragment with continuation fragments still
/// ahead in the next volume.
const DAMAGE: usize = 128 * 1024;

/// How many bytes the damaged member had delivered when its decode ended.
const KEPT: usize = 1 << 20;

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

#[derive(Default)]
struct Sink(Mutex<Vec<String>>);

impl ParallelSink for Sink {
    type Out = Vec<u8>;
    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        self.0
            .lock()
            .unwrap()
            .push(format!("open {}", member.name_lossy()));
        Ok(Disposition::Write(Vec::new()))
    }
    fn close(
        &self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.0.lock().unwrap().push(format!(
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
    (sink.0.into_inner().unwrap(), error)
}

#[test]
fn a_split_member_whose_decode_ends_early_is_opened_once_and_closed_once() {
    let mut set = many();
    assert_eq!(set.len(), 5, "a set of five volumes");
    let at = set[0].len() - 1_488_416;
    for byte in &mut set[0][at..at + DAMAGE] {
        *byte ^= 0xff;
    }

    let sequential = |workers: usize| {
        let sink = Sink::default();
        let options = ReadOptions::default().with_workers(Some(workers));
        let outcome = extract(sources(&set), &options, &mut Seq(&sink), &mut Quiet);
        let report = outcome.as_ref().ok().copied();
        (said(outcome.err(), sink), report)
    };
    let parallel = |all: bool| {
        let sink = Sink::default();
        let options = ReadOptions::default()
            .with_workers(Some(8))
            .with_sink_is_file(Some(true));
        probe::set_split_jobs_all(Some(all));
        let outcome = extract_parallel(sources(&set), &options, &sink, 8);
        probe::set_split_jobs_all(None);
        let report = outcome.as_ref().ok().copied();
        (said(outcome.err(), sink), report)
    };
    let reads = [
        ("extract, 1 worker", sequential(1)),
        ("extract, 8 workers", sequential(8)),
        ("extract_parallel, stored split jobs only", parallel(false)),
        ("extract_parallel, every split member a job", parallel(true)),
    ];

    for (reader, ((heard, error), report)) in &reads {
        assert_eq!(error.as_deref(), None, "{reader}: nothing is said");
        // WHAT A CALLER WHO IGNORES `close` STILL READS (spec F section 8,
        // its second point): the report counts the failure. A read that
        // returns no error for a member that stopped short must not read
        // as success from its report either, and the short count has to be
        // visible in it: seven whole members and the damaged one's 1 MiB.
        let report = report.expect("a read that returns no error returns its report");
        assert_eq!(
            report.checksum_failures, 1,
            "{reader}: the member that stopped short is counted as failed: {report:?}"
        );
        assert_eq!(report.members, 8, "{reader}: {report:?}");
        assert_eq!(
            report.bytes,
            (7 * MEMBER_LEN + KEPT) as u64,
            "{reader}: the bytes that reached the sink, the short member's {KEPT} among them: {report:?}"
        );
        assert_eq!(report.damaged_headers, 0, "{reader}: {report:?}");
        for i in 0..8 {
            let name = format!("E0{i}.mkv");
            let of = |what: &str| -> Vec<&String> {
                heard
                    .iter()
                    .filter(|line| line.starts_with(&format!("{what} {name}")))
                    .collect()
            };
            assert_eq!(
                of("open").len(),
                1,
                "{reader}: {name} is opened once: {heard:?}"
            );
            let closes = of("close");
            assert_eq!(
                closes.len(),
                1,
                "{reader}: {name} is closed once: {heard:?}"
            );
            let want = if i == 1 {
                // The damaged member: failed, with the bytes it had.
                format!("close {name} out=Some({KEPT}) ok=Some(false) bytes={KEPT}")
            } else {
                format!("close {name} out=Some({MEMBER_LEN}) ok=Some(true) bytes={MEMBER_LEN}")
            };
            assert_eq!(closes[0], &want, "{reader}");
        }
        assert_eq!(heard.len(), 16, "{reader}: {heard:?}");
    }
}
