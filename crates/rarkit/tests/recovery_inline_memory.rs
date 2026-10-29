//! Spec L 3.8's memory bound on the RAR 5 inline repair, measured on the
//! heap: "Never hold a whole volume or a whole shard grid", and a stripe
//! chosen "so this fits `MemoryPolicy::repair_limit`".
//!
//! The repair keeps every rebuilt slice of a group whole until the group
//! is checked, and every checked slice of every group until the volume is
//! written out. Both used to sit outside the limit: memory that grew with
//! the damage and, across groups, with the volume. They are charged to it
//! now. A repair that would hold more was refused before it started; it
//! is now made in batches, which `tests/recovery_inline_batched.rs` holds.
//!
//! One test in this binary, because the allocator's high-water mark is
//! the process's. The repair is held to ONE worker (`max_workers: 1`), so
//! the figure does not move with the pool's width; the volume is 14 MB
//! and is held by the test, outside the measured call.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use rarkit::internals::recovery as l;
use rarkit::memory::MemoryPolicy;
use rarkit::{ReadOptions, SplitCheck};

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

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

/// A writer that keeps nothing, so the output is not on the heap either.
struct Count(u64, u64);

impl std::io::Write for Count {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len() as u64;
        self.1 = buf.iter().fold(self.1, |sum, &b| {
            sum.wrapping_mul(0x0100_0000_01b3)
                .wrapping_add(u64::from(b))
        });
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

const MIB: usize = 1 << 20;

#[test]
fn the_rebuilt_slices_are_charged_to_the_repair_limit() {
    let data: Vec<u8> = (0..14_000_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    // Laid out as an archive is: the `RR` service header at `P`, then
    // the data area (spec L 3.5.5 O7: shard 0 is among the damaged, so
    // nothing but the header says the records are this file's).
    let area = l::rr5_encode(&data, 20).unwrap();
    let mut volume = data.clone();
    volume.extend_from_slice(&l::rr5_service_header(area.len() as u64, 20));
    volume.extend_from_slice(&area);
    let (k, m, shard, groups, _, _) = l::rr5_geometry(data.len() as u64, 20).unwrap();
    assert_eq!((k, m, shard, groups), (200, 40, 70_000, 2));

    // The sum the mended volume must have, taken before the damage.
    let mut want = Count(0, 0);
    std::io::Write::write_all(&mut want, &volume).unwrap();

    // Forty shards damaged in BOTH groups: as much as the forty rows mend.
    for j in 0..40usize {
        volume[j * 70_000 + 100] ^= 0xFF;
        volume[j * 70_000 + 65_536 + 100] ^= 0xFF;
    }

    // Forty whole slices of group 0 are 2,621,440 bytes, and the smallest
    // stripe beside them is 82 rows of 8 KiB: 3,293,184 in all. A limit
    // of exactly that runs in one batch, and stays in it.
    const NEEDED: u64 = 40 * 65_536 + 82 * 8_192;
    let options = |limit: u64| {
        ReadOptions::default()
            .with_memory(MemoryPolicy {
                repair_limit: limit,
                max_workers: 1,
                ..MemoryPolicy::from_limit(1 << 30)
            })
            .with_split_check(SplitCheck::Streaming)
    };
    let measured = |limit: u64, out: &mut Count| {
        let before = LIVE.load(Ordering::Relaxed);
        PEAK.store(before, Ordering::Relaxed);
        let result = rarkit::recovery::repair_inline(&volume, &options(limit), out);
        (result, PEAK.load(Ordering::Relaxed) - before)
    };
    // What is not the repair's working memory is fixed and small: the
    // scan's 1 MiB window and one record, the 64 KiB slice being hashed,
    // the 1 MiB copy block, and the tables. None of it grows with the
    // damage.
    const FIXED: usize = 3 * MIB;

    let mut out = Count(0, 0);
    let (result, peak) = measured(NEEDED, &mut out);
    let report = result.unwrap();
    assert_eq!((out.0, out.1), (want.0, want.1), "the volume is mended");
    assert_eq!(report.rebuilt, vec![0]);
    assert!(report.failed.is_empty());
    assert!(
        report.peak_working_memory <= NEEDED,
        "the repair's own account, {} bytes, is past its limit of {NEEDED}",
        report.peak_working_memory
    );
    assert!(
        peak <= NEEDED as usize + FIXED,
        "peak heap during the repair was {peak} bytes for a limit of {NEEDED}"
    );
}
