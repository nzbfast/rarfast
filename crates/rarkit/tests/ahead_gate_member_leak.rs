//! A member waiting for a lane unit does not open the look-ahead's gate
//! to the workers held at it.
//!
//! The shape that showed it (10 Oct 2026): a set of many members, each a
//! STORED member that does not pack, each behind a small coded member,
//! read by `extract` in order at a read width of 3, 4 and 5 into a writer
//! slower than the read. A stored member's worker took the ceiling's lanes
//! for the whole of its bytes and was held at the gate with them; the
//! next member then waited for a unit, and for as long as it waited every
//! held worker was let go (`read::lanes`), so the member at the gate, and
//! at times the one behind it, was read whole into the look-ahead.
//!
//! The fault is a race between that wait and the writer, so one round
//! proves nothing: every width runs [`ROUNDS`] rounds and every round is
//! held to the bound. Counted on an 18 core aarch64 laptop under load:
//! before the mend, three runs of this test, 108 rounds, 41 of them over
//! the bound (every width in every run, so the test failed three times of
//! three), holding 45 to 99 MiB, a member or two; after it, ten runs,
//! none of 360 rounds over, holding 10 to 20 MiB.
//!
//! What is read is the engine's own account, the most the look-ahead ever
//! held decoded and not yet delivered (`probe::peak_seq_ahead_held`).
//! Nothing timed is asserted: the writer sleeps a millisecond a write so
//! that the read outruns it on any machine, and a slower machine changes
//! how long a round takes and not what the look-ahead may hold.
//!
//! Read widths of 3, 4 and 5, stated below, on a host of any width (a
//! width is a ceiling: two, three and four workers beside the walk), and
//! the default width as well on a host of under 18 threads, where the
//! gate holds at it (a width of 0 in the failure's list). The
//! default memory policy. About 200 MiB: the archive, 192 MiB of it bytes
//! that do not pack, built once and read from memory; nothing is kept of
//! what is written.

#![cfg(feature = "parallel")]

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use rarkit::{
    extract, Disposition, HostOs, MemberInfo, MemberOutcome, MemberSpec, Payload, RangeSource,
    ReadOptions, Result, Sink, WriteFormat, WriteMethod, WriteOptions, Writer,
};

const MIB: u64 = 1 << 20;

/// One big member: over the 16 MiB from which a stored member is read on
/// lanes, and far over the bound, so a member let through the gate cannot
/// be mistaken for anything else.
const MEMBER_LEN: usize = 48 << 20;

/// The big members, each behind its small member.
const MEMBER_COUNT: usize = 4;

/// The gate's window for these reads.
const WINDOW: u64 = MIB;

/// The most the look-ahead may hold: the window, and the floor every slot
/// may hold whatever the window (four chunks of a mebibyte; a width of 5
/// opens eight slots at most, and the archive has eight members), and in
/// each worker's hands a chunk and the one grant of lanes it may finish
/// when a member waits (a mebibyte at this window). 41 MiB, under one
/// big member.
const BOUND: u64 = WINDOW + 8 * 4 * MIB + 4 * MIB + 4 * MIB;

/// Rounds a width. Before the mend about four rounds in ten missed, and
/// no width went twelve rounds without a miss.
const ROUNDS: usize = 12;

/// Bytes that do not pack, the same on every run.
fn noise(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (state >> 16) as u8
        })
        .collect()
}

/// A small member that packs: four hundred bytes of one line.
fn note(i: usize) -> Vec<u8> {
    format!("element {i}\n").repeat(40).into_bytes()
}

/// One RAR 5 archive, not solid, written at `-m3`: for each big member its
/// note and then its bytes, which the writer stores, as `rar` does with
/// bytes that do not pack.
fn archive() -> Vec<u8> {
    // Every body first: the writer borrows them until it finishes.
    let members: Vec<(String, Vec<u8>)> = (0..MEMBER_COUNT)
        .flat_map(|i| {
            [
                (format!("ep{i}/info.nfo"), note(i)),
                (
                    format!("ep{i}/element.bin"),
                    noise(MEMBER_LEN, 2 * i as u32 + 3),
                ),
            ]
        })
        .collect();
    let mut writer = Writer::new(WriteOptions {
        format: WriteFormat::Rar5,
        order: rarkit::MemberOrder::AsAdded,
        method: WriteMethod::Compressed {
            level: 3,
            dictionary: Some(1 << 20),
        },
        host_os: HostOs::Unix,
        ..WriteOptions::default()
    })
    .expect("the writer takes these options");
    for (name, body) in &members {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(body),
                mtime: None,
                attributes: 0o100644,
                host_os: HostOs::Unix,
                is_directory: false,
            })
            .expect("the writer takes the member");
    }
    let mut out = std::io::Cursor::new(Vec::new());
    writer
        .finish_seek(&mut out)
        .expect("the archive is written");
    out.into_inner()
}

/// The archive, read from memory.
struct Held(Vec<u8>);

impl RangeSource for Held {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let at = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(self.0.len());
        let take = buf.len().min(self.0.len() - at);
        buf[..take].copy_from_slice(&self.0[at..at + take]);
        Ok(take)
    }

    fn available(&self) -> u64 {
        self.0.len() as u64
    }

    fn len(&self) -> Option<u64> {
        Some(self.0.len() as u64)
    }
}

/// A writer slower than any read: a millisecond a write, the bytes
/// counted and dropped.
struct Slow(u64);

impl Write for Slow {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        std::thread::sleep(Duration::from_millis(1));
        self.0 += data.len() as u64;
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Every member written to a slow writer; its length and verdict kept.
#[derive(Default)]
struct ManySink {
    members: Vec<(u64, Option<bool>)>,
}

impl Sink for ManySink {
    type Out = Slow;

    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Slow>> {
        Ok(Disposition::Write(Slow(0)))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Slow>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.members
            .push((out.map_or(0, |slow| slow.0), outcome.checksum_ok));
        Ok(())
    }
}

/// At a read width of 3, 4 and 5, round after round, the look-ahead holds
/// no more than its window, a floor a slot and a chunk a worker: never a
/// big member.
#[test]
fn a_waiting_member_does_not_let_a_held_member_through_the_gate() {
    let bytes = archive();
    assert!(
        bytes.len() > MEMBER_COUNT * MEMBER_LEN,
        "the big members were packed, not stored: {} bytes",
        bytes.len()
    );
    let volumes = vec![Arc::new(Held(bytes)) as Arc<dyn RangeSource>];
    rarkit::probe::set_seq_ahead(Some(true));
    rarkit::probe::set_seq_ahead_hold(Some(WINDOW));
    let mut over = Vec::new();
    // The DEFAULT width too, where it is one the gate holds at (under 18
    // threads): there the fault showed on a 16 thread box with no width
    // stated. On a wider host the default width has no gate, by design,
    // and the stated widths are the whole of the test. Zero is how the
    // default is written in the list below.
    let host = std::thread::available_parallelism().map_or(1, |n| n.get());
    let mut widths = vec![3usize, 4, 5];
    if host < 18 {
        widths.push(0);
    }
    let tried = widths.len() * ROUNDS;
    for width in widths {
        let opts = ReadOptions::default().with_workers((width > 0).then_some(width));
        for round in 0..ROUNDS {
            rarkit::probe::reset_seq_ahead_peak();
            let mut sink = ManySink::default();
            let report = extract(volumes.clone(), &opts, &mut sink, &mut ()).expect("extract");
            assert_eq!(report.members, 2 * MEMBER_COUNT as u64);
            for (index, (len, ok)) in sink.members.iter().enumerate() {
                let want = if index % 2 == 0 {
                    note(index / 2).len()
                } else {
                    MEMBER_LEN
                };
                assert_eq!(*len, want as u64, "member {index} at a width of {width}");
                assert_eq!(*ok, Some(true), "member {index} at a width of {width}");
            }
            let peak = rarkit::probe::peak_seq_ahead_held();
            if peak > BOUND {
                over.push((width, round, peak / MIB));
            }
        }
    }
    rarkit::probe::set_seq_ahead(None);
    rarkit::probe::set_seq_ahead_hold(None);
    assert!(
        over.is_empty(),
        "the look-ahead held more than {} MiB in {} of {} rounds (width, round, MiB held): {over:?}",
        BOUND / MIB,
        over.len(),
        tried
    );
}
