//! A rewrite that carries a recovery record does not hold the archive
//! once the archive is past the working limit (bug sweep of 4 Oct 2026,
//! M-20).
//!
//! The record covers every byte before it, and a rewrite built it from a
//! copy of the whole output kept in memory as it was written: 6 GiB of
//! heap for a 6 GiB archive, on any edit of any archive that already had
//! a record, and an abort where the copy could not grow. Now the copy is
//! kept only for a RAR 5 record and only while the archive is within the
//! working limit, where it buys the wide encode; past the limit, and for
//! a RAR 4 family record at every size, the bytes are fed to the
//! streaming encoder as they are written, and what is held is the record
//! and one shard or sector.
//!
//! The counting allocator is this binary's own, which is why the test
//! lives in a file of its own (as `tests/write_allocation.rs` does).
//!
//! Width and memory: the writes and the rewrites run on a pool of
//! [`POOL`] threads. The limit a copy is held within is stated, at
//! [`LIMIT`], as the limit the archive is opened under (`open_named`); the
//! 12 MiB archive is past it. The control runs under the default process
//! budget's limit, 512 MiB at the least, which the archive is far within.

#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use rarkit::{
    edit, Archive, HostOs, MemberSpec, MemoryPolicy, Payload, RangeSource, Rar4Version,
    ReadOptions, ServiceKind, WriteFormat, WriteMethod, WriteOptions, Writer,
};

const POOL: usize = 2;
/// The most a rewrite here keeps a copy of.
const LIMIT: u64 = 4 << 20;
/// The members' bytes: three times the limit.
const ARCHIVE: usize = 12 << 20;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
        PEAK.fetch_max(live, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if new_size >= layout.size() {
            let grow = new_size - layout.size();
            let live = LIVE.fetch_add(grow, Ordering::Relaxed) + grow;
            PEAK.fetch_max(live, Ordering::Relaxed);
        } else {
            LIVE.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// One count at a time: the allocator's peak is the process's, so two
/// tests counting at once would read each other's heap.
static ONE_COUNT: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The heap `work` added at its highest, over what was live when it began.
fn peak_of<T>(work: impl FnOnce() -> T) -> (T, usize) {
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let out = work();
    (out, PEAK.load(Ordering::Relaxed).saturating_sub(before))
}

fn bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            (state.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8
        })
        .collect()
}

fn archive(format: WriteFormat) -> Vec<u8> {
    let data = bytes(ARCHIVE / 3, 11);
    let mut writer = Writer::new(WriteOptions {
        format,
        method: WriteMethod::Stored,
        filters: rarkit::FilterPolicy::Off,
        order: rarkit::MemberOrder::AsAdded,
        host_os: HostOs::Unix,
        recovery_percent: Some(5),
        ..WriteOptions::default()
    })
    .expect("options");
    for name in [&b"a.bin"[..], b"b.bin", b"c.bin"] {
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(&data),
                mtime: None,
                attributes: 0,
                host_os: HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    out
}

/// An output that keeps a checksum and no bytes, so that what the rewrite
/// holds is not confused with what the test holds.
#[derive(Default)]
struct Summed {
    crc: u32,
    len: u64,
}

impl Write for Summed {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.crc = rarkit::checksum::crc32(bytes) ^ self.crc.rotate_left(1);
        self.len += bytes.len() as u64;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_rewrite_past_the_working_limit_does_not_hold_the_archive() {
    let _one = ONE_COUNT.lock().unwrap_or_else(|e| e.into_inner());
    rayon::ThreadPoolBuilder::new()
        .num_threads(POOL)
        .build()
        .expect("a pool")
        .install(|| {
            for format in [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V40)] {
                let source: Arc<dyn RangeSource> = Arc::new(archive(format));
                let src = Archive::open(source.clone(), &ReadOptions::default()).expect("open");
                // The same archive opened under a named limit it is past.
                let past = open_named(&source, LIMIT);

                // Within the limit: the copy and the wide encode, as ever.
                let mut held = Vec::new();
                edit::lock(&src, &mut held).expect("lock, held");

                // Past it: streamed, and the same archive to the byte.
                let mut streamed = Vec::new();
                edit::lock(&past, &mut streamed).expect("lock, streamed");
                assert!(
                    streamed == held,
                    "{format:?}: the streamed record is not the held one's bytes"
                );
                let after: Arc<dyn RangeSource> = Arc::new(streamed);
                let after = Archive::open(after, &ReadOptions::default()).expect("reopen");
                assert!(after.is_locked());
                assert!(after
                    .services()
                    .any(|svc| svc.kind == ServiceKind::RecoveryRecord));
                drop(after);
                drop(held);

                // And what it holds while it does so: the record, 5 percent
                // of 12 MiB, and its working shards. A third of the archive
                // is several times that and far under the archive.
                let (outcome, peak) = peak_of(|| edit::lock(&past, Summed::default()));
                outcome.expect("lock, counted");
                assert!(
                    peak < ARCHIVE / 3,
                    "{format:?}: the rewrite held {peak} bytes over a {ARCHIVE} byte archive \
                     past a {LIMIT} byte limit"
                );
            }
        });
}

/// The archive opened under a limit the caller NAMED, which is what a
/// rewrite of it keeps its copy within.
fn open_named(source: &Arc<dyn RangeSource>, limit: u64) -> Archive {
    let mut options = ReadOptions::default();
    options.memory = MemoryPolicy {
        working_limit: limit,
        limit_named: true,
        ..MemoryPolicy::default()
    };
    Archive::open(source.clone(), &options).expect("open under a named limit")
}

/// A named limit is a promise, and the rewrite keeps it: an archive
/// opened under [`LIMIT`] and three times its size is not copied into
/// memory for its RAR 5 record. Before this an `Archive` did not keep the
/// policy it was opened with, the rewrite held its copy within the
/// process default's working limit (512 MiB at the least) and this
/// archive was held whole.
///
/// Width and memory: a pool of [`POOL`] threads; the named limit is
/// [`LIMIT`] and the archive is [`ARCHIVE`] bytes of members.
#[test]
fn a_rewrite_keeps_the_limit_the_archive_was_opened_with() {
    let _one = ONE_COUNT.lock().unwrap_or_else(|e| e.into_inner());
    rayon::ThreadPoolBuilder::new()
        .num_threads(POOL)
        .build()
        .expect("a pool")
        .install(|| {
            let source: Arc<dyn RangeSource> = Arc::new(archive(WriteFormat::Rar5));
            let named = open_named(&source, LIMIT);
            let (outcome, peak) = peak_of(|| edit::lock(&named, Summed::default()));
            outcome.expect("lock under a named limit");
            assert!(
                peak < ARCHIVE / 3,
                "the rewrite held {peak} bytes over a {ARCHIVE} byte archive \
                 opened under a named limit of {LIMIT} bytes"
            );

            // A limit the archive is within still buys the copy and the
            // wide encode, and both write the same archive.
            let mut streamed = Vec::new();
            edit::lock(&named, &mut streamed).expect("lock, streamed");
            let roomy = open_named(&source, 4 * ARCHIVE as u64);
            let mut held = Vec::new();
            let (outcome, peak) = peak_of(|| edit::lock(&roomy, &mut held));
            outcome.expect("lock within a named limit");
            assert!(
                peak >= ARCHIVE,
                "a rewrite within its named limit kept no copy: {peak} bytes"
            );
            assert!(streamed == held, "the two rewrites differ");
        });
}

/// One arm of the count, one process: the measurement the streamed arm
/// owes against the held one (the path every rewrite took before there
/// were two). Not a gate; a driver script runs it, a process a row, so
/// that the wall and the peak resident size are the process's own and
/// taken from outside it.
///
/// `RARKIT_M20_FILE` names an archive on disk and `RARKIT_M20_ARM` says
/// what to do with it: `make5` or `make4` writes it (stored members,
/// `RARKIT_M20_MIB` of them in all, a 5 percent record), `held` and
/// `streamed` lock it into a discarding output with the copy kept or
/// not. It runs on the machine's own pool, which is what it measures.
#[test]
#[ignore = "a measurement, not a gate"]
fn count_one_arm_of_the_rewrite() {
    let (Ok(path), Ok(arm)) = (
        std::env::var("RARKIT_M20_FILE"),
        std::env::var("RARKIT_M20_ARM"),
    ) else {
        println!("RARKIT_M20_FILE and RARKIT_M20_ARM are not set: nothing counted");
        return;
    };
    if let Some(family) = arm.strip_prefix("make") {
        let mib: usize = std::env::var("RARKIT_M20_MIB")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1024);
        let format = if family == "4" {
            WriteFormat::Rar4(Rar4Version::V40)
        } else {
            WriteFormat::Rar5
        };
        // Three members, so a RAR 4 member stays under its 4 GiB field.
        let data = bytes((mib << 20) / 3, 11);
        let mut writer = Writer::new(WriteOptions {
            format,
            method: WriteMethod::Stored,
            filters: rarkit::FilterPolicy::Off,
            order: rarkit::MemberOrder::AsAdded,
            host_os: HostOs::Unix,
            recovery_percent: Some(5),
            ..WriteOptions::default()
        })
        .expect("options");
        for name in [&b"a.bin"[..], b"b.bin", b"c.bin"] {
            writer
                .add(MemberSpec {
                    name,
                    payload: Payload::Bytes(&data),
                    mtime: None,
                    attributes: 0,
                    host_os: HostOs::Unix,
                    is_directory: false,
                })
                .expect("add");
        }
        let out = std::io::BufWriter::new(std::fs::File::create(&path).expect("create"));
        writer.finish_into(out).expect("finish");
        return;
    }
    let limit = match arm.as_str() {
        "held" => u64::MAX,
        "streamed" => 0,
        other => panic!("RARKIT_M20_ARM={other}: make5, make4, held or streamed"),
    };
    let source: Arc<dyn RangeSource> = Arc::new(std::fs::File::open(&path).expect("open"));
    let src = open_named(&source, limit);
    let began = std::time::Instant::now();
    let mut out = Summed::default();
    edit::lock(&src, &mut out).expect("lock");
    println!(
        "M20ROW arm={arm} format={:?} bytes={} wall_s={:.4} peak_heap_mib={}",
        src.format(),
        out.len,
        began.elapsed().as_secs_f64(),
        PEAK.load(Ordering::Relaxed) >> 20
    );
}
