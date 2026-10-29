//! As many SLIDING flushes at once as the pool has threads end, and write
//! what each alone writes.
//!
//! A chain level's flush of more than one wave slides
//! (`Engine::chains_sliding`): one pool thread runs the linking pass and
//! the block parses are spawned to the pool. The pass used to SLEEP while
//! it waited for a block unless a pool's worth of parses were queued,
//! which is right for one flush on its pool (another thread takes the
//! parse) and never ends where every pool thread is such a pass: each
//! sleeps on a parse that only a pool thread can run, and none is awake.
//!
//! The way there that a caller of this library has is held here: as many
//! writes at once as their pool has threads, each from a thread of the
//! caller's own at `workers: Some(N)` (a write's pool is shared by every
//! write of that width in the process, `write::width`). Two on a pool of
//! two, under a BOUNDED WAIT, so that a pass asleep for good is a failure
//! with a report and never a hung test run. Two is the count held
//! because it fails every time without the rule: each pass runs its own
//! queued parses newest first and sleeps on its oldest, the one it waits
//! for. Three on a pool of three need all three asleep at one moment,
//! and a run of it without the rule ended.
//!
//! The second way there is the writer's own: a SEGMENT TEAM as wide as
//! its pool (`write::engine`'s `Segments`), each engine's flushes sliding,
//! held at two and at three threads. Its engines are told they share the
//! pool (`Engine::share_pool`), which is the same rule without waiting to
//! see another pass.
//!
//! The pool widths here are this file's own, and the file is a test
//! binary of its own: a pool whose threads sleep for good is lost to
//! every later test that shares it.
use std::io::Cursor;
use std::sync::{mpsc, Arc};
use std::time::Duration;

use rarkit::internals::writers::{segment_rounds, slid_flushes, with_segment_width};
use rarkit::{
    FilterPolicy, MemberSpec, Payload, Rar4Version, WriteFormat, WriteMethod, WriteOptions, Writer,
};

/// A slow pass is not a pass asleep for good: each write here ends in
/// seconds on an idle box, and the wait is long enough for one on a box
/// at many times its cores in load. Short beside a run that never ends.
const WAIT: Duration = Duration::from_secs(900);

/// Text and noise by turns, from a seed: three quarters of every 64 KiB
/// text, the rest noise.
fn member(len: usize, seed: u64) -> Vec<u8> {
    let mut out = rarkit_testdata::chatter(seed, len);
    let noise = rarkit_testdata::scramble(seed, len);
    for (block, fill) in out.chunks_mut(64 << 10).zip(noise.chunks(64 << 10)) {
        let from = block.len() * 3 / 4;
        block[from..].copy_from_slice(&fill[from..]);
    }
    out
}

/// The process's own pool, stated: eight threads, whatever the machine. A
/// write at `workers: Some(N)` takes a pool of N of its own only from a
/// caller whose pool is WIDER than N, and otherwise runs on the caller's;
/// so on a machine of two threads "three engines on a pool of three" was
/// two on a pool of two. Built once, before the first write of either
/// test; this file is a test binary of its own, so the pool is its own.
fn wide_process_pool() {
    static BUILT: std::sync::Once = std::sync::Once::new();
    BUILT.call_once(|| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(8)
            .build_global()
            .expect("the process's pool, built before any write used it");
    });
}

fn options(format: WriteFormat, level: u8, workers: usize) -> WriteOptions {
    WriteOptions {
        format,
        // 2 MiB windows, named: a member's stretches, and whether its
        // flushes slide, follow the dictionary, and the default one is
        // not the same at every level.
        method: WriteMethod::Compressed {
            level,
            dictionary: Some(2 << 20),
        },
        filters: FilterPolicy::Off,
        host_os: rarkit::HostOs::Unix,
        workers: Some(workers),
        ..WriteOptions::default()
    }
}

fn write(options: WriteOptions, data: &[u8]) -> Vec<u8> {
    let mut reader = Cursor::new(data);
    let mut writer = Writer::new(options).expect("options");
    writer
        .add(MemberSpec {
            name: b"m.bin",
            payload: Payload::Reader {
                reader: &mut reader,
                size: data.len() as u64,
                crc32: None,
            },
            mtime: None,
            attributes: 0o644,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut out = Cursor::new(Vec::new());
    writer.finish_seek(&mut out).expect("finish");
    out.into_inner()
}

/// `work` on a thread of its own, its answer through a channel, so the
/// test's thread can give up on it.
fn started<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> mpsc::Receiver<T> {
    let (send, receive) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = send.send(work());
    });
    receive
}

fn ended<T>(what: &str, receive: &mpsc::Receiver<T>) -> T {
    receive.recv_timeout(WAIT).unwrap_or_else(|_| {
        panic!(
            "{what}: not ended after {} s: every pool thread is a sliding pass asleep on a \
             parse no thread is awake to run",
            WAIT.as_secs()
        )
    })
}

const FORMATS: [(&str, WriteFormat); 2] = [
    ("rar5", WriteFormat::Rar5),
    ("rar4v29", WriteFormat::Rar4(Rar4Version::V29)),
];

/// `count` writes at once on a pool of `count`, each of a member of its
/// own, against each written alone.
fn at_once(family: &str, format: WriteFormat, level: u8, count: usize) {
    // 2 MiB windows under the shipped limits: a member of 40 MiB is
    // flushed in runs of windows longer than the chains' one wave, so its
    // flushes slide.
    let what = format!("{family} -m{level}, {count} writes on a pool of {count}");
    let data: Vec<Arc<Vec<u8>>> = (0..count)
        .map(|index| Arc::new(member(40 << 20, 31 + index as u64)))
        .collect();
    let start = |data: &Arc<Vec<u8>>| {
        let data = Arc::clone(data);
        started(move || write(options(format, level, count), &data))
    };
    let alone: Vec<Vec<u8>> = data
        .iter()
        .map(|data| ended(&format!("{what} (one alone)"), &start(data)))
        .collect();
    let slid = slid_flushes();
    let together: Vec<mpsc::Receiver<Vec<u8>>> = data.iter().map(start).collect();
    for (index, receive) in together.iter().enumerate() {
        let archive = ended(&what, receive);
        assert!(
            archive == alone[index],
            "{what}: write {index} beside the others moved a byte"
        );
    }
    assert!(
        slid_flushes() > slid,
        "{what}: no flush slid, so nothing was held here"
    );
}

#[test]
fn two_writes_at_once_on_a_pool_of_two_both_end() {
    wide_process_pool();
    for (family, format) in FORMATS {
        at_once(family, format, 1, 2);
    }
    at_once("rar5", WriteFormat::Rar5, 3, 2);
}

#[test]
fn a_segment_team_as_wide_as_its_pool_ends() {
    wide_process_pool();
    // Three stretches and more at the shipped dictionary, a team of as
    // many engines as the pool has threads.
    let data = Arc::new(member(60 << 20, 33));
    for (family, format) in FORMATS {
        for threads in [2usize, 3] {
            let what = format!("{family} -m1, {threads} engines on a pool of {threads}");
            let one = {
                let data = Arc::clone(&data);
                started(move || with_segment_width(1, || write(options(format, 1, threads), &data)))
            };
            let one = ended(&format!("{what} (one engine)"), &one);
            let team = {
                let data = Arc::clone(&data);
                started(move || {
                    with_segment_width(threads, || {
                        let archive = write(options(format, 1, threads), &data);
                        (archive, segment_rounds())
                    })
                })
            };
            let (archive, (rounds, most)) = ended(&what, &team);
            assert!(
                rounds > 0 && most == threads,
                "{what}: {rounds} rounds of at most {most} engines"
            );
            assert!(archive == one, "{what}: the team moved a byte");
        }
    }
}
