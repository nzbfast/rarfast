//! A worker waiting at the look-ahead's gate does not keep the lane units
//! the walking thread is waiting for.
//!
//! One test, `extract` at a stated width of 2 (the walk and one worker, a
//! ceiling of two lane units) under the default memory policy, over an
//! archive of about 9 MiB built in memory: a member of 24 MiB of text, a
//! directory entry, and 256 KiB of noise, which keeps the first member
//! from being the last of its volume (such a member is the walk's own). The offload floor is lowered
//! to zero and the gate's window set to 1 MiB for the calling thread, so
//! the first member's worker is held at the gate with its slot's four
//! chunks decoded, inside a chunk of its decode, holding its own unit and
//! the one lane the ceiling leaves. It takes that lane because the member
//! is over the 16 MiB from which a member decodes on tape lanes, and
//! because the host has a third hardware thread to offer: on a host of two
//! the worker holds one unit of the two, the walk is admitted beside it,
//! and this test passes with or without what it guards.
//!
//! Nothing is timed: the walking thread WAITS, inside its own source, for
//! the worker to be at the gate before it reads the directory entry's
//! header, so a slow machine changes how long the test takes and not what
//! it reads. The entry is the walk's own to decode (it declares no bytes
//! and members are in flight), and a member the walk decodes takes a lane
//! unit as a worker's does.

#![cfg(feature = "parallel")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::sync::Arc;
use std::thread::ThreadId;
use std::time::{Duration, Instant};

use rarkit::{
    extract, Disposition, HostOs, MemberInfo, MemberOutcome, MemberSpec, Payload, RangeSource,
    ReadOptions, Result, Sink, WriteFormat, WriteMethod, WriteOptions, Writer,
};

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

const LARGE: usize = 24 << 20;
const TAIL: usize = 256 << 10;

/// One RAR 5 archive, not solid: a member of 24 MiB, a directory entry,
/// and 256 KiB of noise.
fn archive() -> Vec<u8> {
    let large = rarkit_testdata::chatter(1, LARGE);
    let tail = noise(TAIL, 3);
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
    let members: [(&str, &[u8], bool); 3] = [
        ("large.txt", &large, false),
        ("dir", &[], true),
        ("tail.bin", &tail, false),
    ];
    for (name, body, is_directory) in members {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(body),
                mtime: None,
                attributes: if is_directory { 0o040755 } else { 0o100644 },
                host_os: HostOs::Unix,
                is_directory,
            })
            .expect("the writer takes the member");
    }
    let mut out = std::io::Cursor::new(Vec::new());
    writer
        .finish_seek(&mut out)
        .expect("the archive is written");
    out.into_inner()
}

/// A source that makes the walking thread wait, at its first read past the
/// large member's packed bytes, until a worker is at the gate.
struct Staged {
    bytes: Vec<u8>,
    walker: ThreadId,
    /// Where the directory entry's header begins, at the least.
    after_large: u64,
    waited: AtomicBool,
    /// Whether a worker was at the gate when the walk went on.
    held: Arc<AtomicBool>,
}

impl RangeSource for Staged {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        if std::thread::current().id() == self.walker
            && offset >= self.after_large
            && !self.waited.swap(true, Ordering::SeqCst)
        {
            let end = Instant::now() + Duration::from_secs(60);
            while Instant::now() < end {
                if rarkit::probe::seq_ahead_live().1 > 0 {
                    self.held.store(true, Ordering::SeqCst);
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        let at = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(self.bytes.len());
        let take = buf.len().min(self.bytes.len() - at);
        buf[..take].copy_from_slice(&self.bytes[at..at + take]);
        Ok(take)
    }

    fn available(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn len(&self) -> Option<u64> {
        Some(self.bytes.len() as u64)
    }
}

/// Every member written, the directory entry too, as `rarfast p` does.
#[derive(Default)]
struct Keep {
    members: Vec<(Vec<u8>, Vec<u8>, Option<bool>)>,
}

impl Sink for Keep {
    type Out = Vec<u8>;

    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.members.push((
            member.name.to_vec(),
            out.unwrap_or_default(),
            outcome.checksum_ok,
        ));
        Ok(())
    }
}

/// With the large member's worker waiting at the gate, the walk reaches a
/// directory entry, which it decodes itself; the extraction ends, and
/// every member's bytes are the bytes that went in.
///
/// What would hang it: the worker waits at the gate for the walk to take
/// delivery, holding its member's unit and the lane of the chunk it is
/// in, which are the whole ceiling; the walk waits for a unit for the
/// entry and so delivers nothing. Neither moves again.
#[test]
fn a_worker_at_the_gate_gives_way_to_a_member_waiting_for_a_lane_unit() {
    let (tx, rx) = channel();
    let held = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&held);
    std::thread::spawn(move || {
        rarkit::probe::set_offload_floor(Some(0));
        rarkit::probe::set_seq_ahead(Some(true));
        rarkit::probe::set_seq_ahead_hold(Some(1 << 20));
        // The members are text, which packs well; held all the same here.
        rarkit::probe::set_seq_ahead_hold_packed(Some(true));
        let bytes = archive();
        // The noise does not pack, so the archive's last 256 KiB are its
        // bytes and the entry's header is just before them: the walk's
        // first read in the last 300 KiB is its read of that header, the
        // large member's own bytes being a worker's to read.
        let after_large = bytes.len() as u64 - (300 << 10);
        let source = Staged {
            bytes,
            walker: std::thread::current().id(),
            after_large,
            waited: AtomicBool::new(false),
            held: seen,
        };
        let opts = ReadOptions::default().with_workers(Some(2));
        let mut sink = Keep::default();
        let report = extract(
            vec![Arc::new(source) as Arc<dyn RangeSource>],
            &opts,
            &mut sink,
            &mut (),
        );
        let _ = tx.send((report.map(|_| ()), sink.members));
    });
    let (report, members) = match rx.recv_timeout(Duration::from_secs(120)) {
        Ok(ended) => ended,
        Err(RecvTimeoutError::Timeout) => panic!(
            "the extraction was still running after 120 s: the walk waits for a lane \
             unit that a worker waiting at the gate holds, and delivers nothing"
        ),
        Err(RecvTimeoutError::Disconnected) => panic!("the extraction's thread ended unreported"),
    };
    report.expect("a good archive extracts");
    assert!(
        held.load(Ordering::SeqCst),
        "no worker was at the gate when the walk went on: the test held nothing"
    );
    let names: Vec<&[u8]> = members.iter().map(|m| m.0.as_slice()).collect();
    assert_eq!(names, [&b"large.txt"[..], b"dir", b"tail.bin"]);
    assert!(
        members[0].1 == rarkit_testdata::chatter(1, LARGE),
        "the large member's bytes"
    );
    assert!(members[1].1.is_empty(), "a directory entry has no bytes");
    assert!(members[2].1 == noise(TAIL, 3), "the last member's bytes");
    assert_eq!(members[0].2, Some(true));
    assert_eq!(members[2].2, Some(true));
}
