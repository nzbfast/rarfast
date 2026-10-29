//! A solid archive's walk on a worker never refuses its own member for the
//! bytes it has queued for the caller, and the queue never takes the
//! operation past a named limit.
//!
//! The solid path (`read::sequential::solid`) queues each member's bytes
//! between the walk and the caller's thread, and those buffers are charged
//! to the operation's meter. A packed member's block buffer is priced
//! against that meter as it grows, under a NAMED limit. Until 27 Oct 2026
//! the queue's buffers stood in that price, so a caller slow enough to let
//! the queue fill made the walk refuse a member it reads under the same
//! limit with nothing queued: `LimitExceeded { resource: BlockBuffer }`,
//! the member closed empty with a failed verdict, where the sequential
//! path delivers it whole. `seq_ahead::the_solid_walk_is_taken_and_its_
//! budget_holds` met it about one run in ten (main at 471661fda, 3 of 30
//! runs alone, `m029.txt` at a 4 MiB limit each time). The caller here
//! stalls at every member's open, so the queue is full whenever a block
//! buffer grows, every run.
//!
//! What the walk does instead is wait for the caller to drain the queue,
//! so the operation's peak stays inside the named limit, which this holds
//! as well: the queue's buffers were held to the queue's own budget alone,
//! and the solid path peaked at 4,686,816 bytes on the meter under a named
//! 4 MiB, where the sequential path peaks at 2,327,520 (27 Oct 2026; with
//! the queue held to the limit, 4,162,528).
//!
//! Width and memory: four workers, a named limit of 4 MiB; the archive is
//! 40 members of 200 to 300 KB of text, about 9 MB unpacked.

use std::sync::Arc;
use std::time::Duration;

use rarkit::{
    extract, Disposition, MemberInfo, MemberOutcome, MemberSpec, Payload, RangeSource, ReadOptions,
    Result, Sink, WriteMethod, WriteOptions, Writer,
};

/// The named limit: the smallest the solid tests of `seq_ahead` read under.
const LIMIT: u64 = 4 << 20;

/// A solid archive this crate writes: `members` compressed members of about
/// `size` bytes each, a 2 MiB window.
fn solid(members: usize, size: usize) -> Vec<u8> {
    let options = WriteOptions {
        solid: true,
        solid_dictionary_2mib: true,
        order: rarkit::MemberOrder::AsAdded,
        method: WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    };
    let list: Vec<(String, Vec<u8>)> = (0..members)
        .map(|k| {
            let len = size + (k * 977) % (size / 2 + 1);
            (
                format!("m{k:03}.txt"),
                rarkit_testdata::chatter_of(k as u64, 1 << 12, len),
            )
        })
        .collect();
    let mut writer = Writer::new(options).expect("options");
    for (name, data) in &list {
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
    let mut one = Vec::new();
    writer.finish_into(&mut one).expect("finish");
    one
}

/// One member as the sink saw it: its name, its bytes, its verdict and its
/// count.
type Seen = (Vec<u8>, Vec<u8>, Option<bool>, u64);

/// Every member, in the order the sink saw them; `stall` waits at each
/// open, as a slow file system's creates do.
struct Kept {
    stall: Duration,
    seen: Vec<Seen>,
}

impl Sink for Kept {
    type Out = Vec<u8>;

    fn open(&mut self, _: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        std::thread::sleep(self.stall);
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.seen.push((
            member.name.to_vec(),
            out.unwrap_or_default(),
            outcome.checksum_ok,
            outcome.bytes,
        ));
        Ok(())
    }
}

fn read(archive: &[u8], solid_ahead: bool, stall: Duration) -> (Kept, Option<String>) {
    let mut opts = ReadOptions::default().with_workers(Some(4));
    opts.memory = rarkit::MemoryPolicy::from_limit(LIMIT);
    opts.sink_is_file = Some(true);
    let mut sink = Kept {
        stall,
        seen: Vec::new(),
    };
    rarkit::probe::set_solid_ahead(Some(solid_ahead));
    let outcome = extract(
        vec![Arc::new(archive.to_vec()) as Arc<dyn RangeSource>],
        &opts,
        &mut sink,
        &mut (),
    );
    rarkit::probe::set_solid_ahead(None);
    (sink, outcome.err().map(|e| format!("{:?}", e.kind())))
}

#[test]
fn a_full_queue_neither_refuses_a_member_nor_passes_the_limit() {
    let archive = solid(40, 200_000);
    let (want, want_error) = read(&archive, false, Duration::ZERO);
    assert_eq!(want_error, None, "the sequential control");
    assert_eq!(want.seen.len(), 40);

    rarkit::probe::reset_solid_ahead_seen();
    rarkit::memory::reset_peak();
    let (have, have_error) = read(&archive, true, Duration::from_millis(15));
    let peak = rarkit::memory::peak();
    let (taken, queued) = rarkit::probe::solid_ahead_seen();
    assert_eq!(taken, 1, "the solid path was not taken");
    assert!(queued > 0, "nothing was queued");

    for (w, h) in want.seen.iter().zip(&have.seen) {
        let name = String::from_utf8_lossy(&w.0);
        assert!(
            w == h,
            "{name}: the solid path gave {} bytes, verdict {:?}, count {}; the sequential path \
             {} bytes, verdict {:?}, count {}",
            h.1.len(),
            h.2,
            h.3,
            w.1.len(),
            w.2,
            w.3
        );
    }
    assert_eq!(have.seen.len(), want.seen.len(), "members delivered");
    assert_eq!(have_error, want_error, "the operation's error");
    assert!(
        peak <= LIMIT,
        "the operation held {peak} bytes under a named limit of {LIMIT}"
    );
}
