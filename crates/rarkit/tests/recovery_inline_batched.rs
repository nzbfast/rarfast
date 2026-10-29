//! The RAR 5 inline repair past its repair limit: rebuilt in batches, in
//! volume order, and never refused for the slices it would hold.
//!
//! The repair kept every rebuilt slice until the volume was written out,
//! once, and refused a repair whose slices did not fit
//! `MemoryPolicy::repair_limit`. It now rebuilds as many slices as the
//! limit holds, in the order they lie in the volume, writes the volume
//! up to the last of them, and goes on from there. A repair within the
//! limit is one batch: the same reads, the same peak and one pass of
//! writing, which the second test pins by count.
//!
//! The tests take turns, because the allocator's high-water mark is the
//! process's. Width and memory: the repair is held to ONE worker
//! (`max_workers: 1`) and the hashing pass runs on a pool of ONE thread
//! the test builds, so no count moves with the machine; the volume is
//! 14 MB with a 20 percent record and is held by the test, outside the
//! measured call. Each repair limit is stated where it is used.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use rarkit::internals::recovery as l;
use rarkit::memory::MemoryPolicy;
use rarkit::{ErrorKind, RangeSource, ReadOptions, Resource, SplitCheck};

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ONE_COUNT: Mutex<()> = Mutex::new(());

struct Tracking;

#[allow(unsafe_code)]
unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
        PEAK.fetch_max(live, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Tracking = Tracking;

/// A writer that keeps a sum and a count of its calls, and no bytes.
#[derive(Default)]
struct Count {
    bytes: u64,
    sum: u64,
    calls: u64,
}

impl std::io::Write for Count {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.calls += 1;
        self.bytes += buf.len() as u64;
        self.sum = buf.iter().fold(self.sum, |sum, &b| {
            sum.wrapping_mul(0x0100_0000_01b3)
                .wrapping_add(u64::from(b))
        });
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The volume, counting what is read of it.
struct Counted {
    volume: Vec<u8>,
    calls: AtomicU64,
    bytes: AtomicU64,
}

impl RangeSource for Counted {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let got = self.volume.read_at(offset, buf)?;
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(got as u64, Ordering::Relaxed);
        Ok(got)
    }
    fn available(&self) -> u64 {
        self.volume.len() as u64
    }
    fn len(&self) -> Option<u64> {
        Some(self.volume.len() as u64)
    }
}

const MIB: usize = 1 << 20;
/// Forty whole slices of group 0 and the smallest stripe beside them, 82
/// rows of 8 KiB: what the repair of forty damaged shards holds in one
/// batch.
const WHOLE: u64 = 40 * 65_536 + 82 * 8_192;
/// One slice and the smallest stripe of a group with TWO damaged shards,
/// six rows of 8 KiB: the least a batch of that repair can be.
const FLOOR: u64 = 65_536 + 6 * 8_192;
/// What is not the repair's working memory: the scan's window and one
/// record, the slice being hashed, the copy block and the tables.
const FIXED: usize = 3 * MIB;

/// The volume whole, and with its first `shards` shards damaged in BOTH
/// groups; its forty rows mend as many as forty.
fn damaged(shards: usize) -> (Vec<u8>, Vec<u8>) {
    let data: Vec<u8> = (0..14_000_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    // Laid out as an archive is: the `RR` service header at `P`, then
    // the data area (spec L 3.5.5 O7: shard 0 is among the damaged, so
    // nothing but the header says the records are this file's).
    let area = l::rr5_encode(&data, 20).unwrap();
    let mut whole = data.clone();
    whole.extend_from_slice(&l::rr5_service_header(area.len() as u64, 20));
    whole.extend_from_slice(&area);
    let (k, m, shard, groups, _, _) = l::rr5_geometry(data.len() as u64, 20).unwrap();
    assert_eq!((k, m, shard, groups), (200, 40, 70_000, 2));
    let mut volume = whole.clone();
    for j in 0..shards {
        volume[j * 70_000 + 100] ^= 0xFF;
        volume[j * 70_000 + 65_536 + 100] ^= 0xFF;
    }
    (whole, volume)
}

fn options(limit: u64) -> ReadOptions {
    ReadOptions::default()
        .with_memory(MemoryPolicy {
            repair_limit: limit,
            max_workers: 1,
            ..MemoryPolicy::from_limit(1 << 30)
        })
        .with_split_check(SplitCheck::Streaming)
}

struct Run {
    result: rarkit::Result<rarkit::rev5::RepairReport>,
    out: Count,
    heap_peak: usize,
    read_calls: u64,
    read_bytes: u64,
}

fn repair(volume: &[u8], limit: u64) -> Run {
    let src = Counted {
        volume: volume.to_vec(),
        calls: AtomicU64::new(0),
        bytes: AtomicU64::new(0),
    };
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .expect("a pool");
    let mut out = Count::default();
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let result = pool.install(|| rarkit::recovery::repair_inline(&src, &options(limit), &mut out));
    let heap_peak = PEAK.load(Ordering::Relaxed) - before;
    Run {
        result,
        out,
        heap_peak,
        read_calls: src.calls.load(Ordering::Relaxed),
        read_bytes: src.bytes.load(Ordering::Relaxed),
    }
}

fn sum_of(bytes: &[u8]) -> (u64, u64) {
    let mut want = Count::default();
    std::io::Write::write_all(&mut want, bytes).unwrap();
    (want.bytes, want.sum)
}

/// A limit that does not hold the rebuilt slices is not a refusal: the
/// volume is mended in batches, and what is held stays within the limit.
#[test]
fn a_repair_past_its_limit_is_mended_in_batches() {
    let _one = ONE_COUNT.lock().unwrap_or_else(|e| e.into_inner());
    // Forty shards under 1 MiB, which holds five slices and the stripe:
    // sixteen batches. Two shards under the floor itself: a slice a batch.
    for (shards, limit) in [(40usize, MIB as u64), (2, FLOOR)] {
        let (whole, volume) = damaged(shards);
        assert!(limit < WHOLE);
        let run = repair(&volume, limit);
        let report = run
            .result
            .unwrap_or_else(|e| panic!("a repair under {limit} bytes was not made: {e}"));
        assert_eq!(
            (run.out.bytes, run.out.sum),
            sum_of(&whole),
            "{limit}: the volume is not mended"
        );
        assert_eq!(report.rebuilt, vec![0]);
        assert!(report.failed.is_empty());
        assert!(
            report.peak_working_memory <= limit,
            "{limit}: the repair's own account is {} bytes",
            report.peak_working_memory
        );
        assert!(
            run.heap_peak <= limit as usize + FIXED,
            "{limit}: peak heap during the repair was {} bytes",
            run.heap_peak
        );
    }
}

/// What is still refused is a limit below ONE slice and the smallest
/// stripe, before a byte is rebuilt or written, naming both figures.
#[test]
fn a_limit_below_one_slice_and_a_stripe_is_refused() {
    let _one = ONE_COUNT.lock().unwrap_or_else(|e| e.into_inner());
    let (_, volume) = damaged(2);
    let run = repair(&volume, FLOOR - 1);
    let error = run.result.unwrap_err();
    assert!(
        matches!(
            error.kind(),
            ErrorKind::LimitExceeded {
                resource: Resource::RepairWork,
                needed: FLOOR,
                limit,
            } if *limit == FLOOR - 1
        ),
        "{error}"
    );
    assert_eq!(run.out.bytes, 0, "nothing is written before the refusal");
}

/// A repair WITHIN its limit is one batch, and does what it did before
/// there were batches: the counts below were taken on the repair as it
/// stood (origin/main at 80eb68b42, 4 Oct 2026) and are pinned, so the
/// reads of the source, the writes of the output and the peak the repair
/// accounts for are the same passes over the same bytes.
#[test]
fn a_repair_within_its_limit_reads_and_writes_what_it_always_did() {
    let _one = ONE_COUNT.lock().unwrap_or_else(|e| e.into_inner());
    let (whole, volume) = damaged(40);
    // limit, reads of the source, bytes read, writes of the output, and
    // the working memory the repair accounts for.
    //
    // Two things were added to those counts on 10 Oct 2026 and nothing
    // else moved: the volume now carries its 26-byte `RR` service header,
    // read once with the bytes around it; and the scan asks whose the
    // records are (spec L 3.5.5 O1 and O6), which is two reads of 8
    // bytes, the header at `P` and the block behind the signature.
    const HEADER: u64 = 26;
    const WHOSE: (u64, u64) = (2, 16);
    let pins: [(u64, u64, u64, u64, u64); 2] = [
        (
            WHOLE,
            2_394 + WHOSE.0,
            61_859_840 + HEADER + WHOSE.1,
            94,
            3_293_184,
        ),
        (
            256 << 20,
            994 + WHOSE.0,
            61_859_840 + HEADER + WHOSE.1,
            94,
            7_995_392,
        ),
    ];
    for (limit, read_calls, read_bytes, write_calls, peak) in pins {
        let run = repair(&volume, limit);
        let report = run.result.unwrap();
        assert_eq!((run.out.bytes, run.out.sum), sum_of(&whole));
        assert_eq!(
            (
                run.read_calls,
                run.read_bytes,
                run.out.calls,
                report.peak_working_memory
            ),
            (read_calls, read_bytes, write_calls, peak),
            "under {limit} bytes"
        );
        assert!(run.heap_peak <= limit as usize + FIXED);
    }
}
