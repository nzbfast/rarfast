//! The LIVE HEAP of a write under a named budget, counted in bytes by this
//! binary's own allocator (spec G 3.7.3's named-ceiling rule, 1 Oct
//! 2026).
//!
//! `tests/named_ceiling.rs` holds the write's STATED peak inside its
//! limit. This row asks the allocator instead: every byte the process has
//! live while a named budget of 512 MiB is written on a pool of
//! thirty-two, less what the test itself held before the write, is inside
//! the budget's `working_limit`; and the same for a SOLID archive under
//! 512, 256 and 160 MiB, whose default dictionary would be 32 MiB with no
//! budget named.
//!
//! **Why it is not a load flake.** It reads no resident set and no
//! footprint: those are pages, they follow what else the box is doing and
//! what the allocator keeps after a free, and a test of them fails on a
//! busy box. This counts REQUESTED bytes, allocation by allocation, in
//! one process that runs one test (a binary of its own, so no other test
//! allocates beside it). The schedule can move the high-water mark by the
//! buffers in flight, which the admission charges; another process cannot
//! move it at all.

#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Cursor;
use std::sync::atomic::{AtomicUsize, Ordering};

use rarkit::{
    FilterPolicy, MemberSpec, MemoryPolicy, Payload, WriteFormat, WriteMethod, WriteOptions, Writer,
};

/// The system allocator, counting the bytes live and their high-water
/// mark.
struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static MOST: AtomicUsize = AtomicUsize::new(0);

fn took(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
    MOST.fetch_max(live, Ordering::Relaxed);
}

// SAFETY: every call is the system allocator's own, with the layout it was
// given; the counters are beside it and touch no memory it hands out.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let at = unsafe { System.alloc(layout) };
        if !at.is_null() {
            took(layout.size());
        }
        at
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let at = unsafe { System.alloc_zeroed(layout) };
        if !at.is_null() {
            took(layout.size());
        }
        at
    }

    unsafe fn dealloc(&self, at: *mut u8, layout: Layout) {
        unsafe { System.dealloc(at, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, at: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(at, layout, size) };
        if !moved.is_null() {
            if size >= layout.size() {
                took(size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - size, Ordering::Relaxed);
            }
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// The set, every member from a reader as the command line gives them:
/// small members for the small crews, members of a third of a MiB to two
/// for the lane, and three long ones for the writing thread.
fn members() -> Vec<Vec<u8>> {
    let mut rng = rarkit_testdata::Seeded::new(0x4ea9);
    let mut out: Vec<Vec<u8>> = (0..400)
        .map(|at| {
            rarkit_testdata::medley(
                at as u64 + 3,
                (4 << 10) + rng.next_u32() as usize % (60 << 10),
            )
        })
        .collect();
    for at in 0..96 {
        out.push(rarkit_testdata::medley(
            at as u64 + 701,
            (340 << 10) + rng.next_u32() as usize % (1700 << 10),
        ));
    }
    for at in 0..3 {
        out.push(rarkit_testdata::medley(
            at as u64 + 9001,
            (14 << 20) + 131 * at,
        ));
    }
    out
}

/// Writes the set to nowhere under `memory` and answers the write's own
/// stated peak.
fn write(
    members: &[Vec<u8>],
    names: &[Vec<u8>],
    level: u8,
    solid: bool,
    memory: MemoryPolicy,
) -> u64 {
    let mut readers: Vec<Cursor<&[u8]>> =
        members.iter().map(|data| Cursor::new(&data[..])).collect();
    let mut writer = Writer::new(WriteOptions {
        format: WriteFormat::Rar5,
        method: WriteMethod::Compressed {
            level,
            dictionary: None,
        },
        solid,
        filters: FilterPolicy::Detect,
        host_os: rarkit::HostOs::Unix,
        memory,
        workers: Some(32),
        ..WriteOptions::default()
    })
    .expect("options");
    for (at, reader) in readers.iter_mut().enumerate() {
        writer
            .add(MemberSpec {
                name: &names[at],
                payload: Payload::Reader {
                    reader,
                    size: members[at].len() as u64,
                    crc32: None,
                },
                mtime: None,
                attributes: 0o644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let report = writer.finish_into(std::io::sink()).expect("finish");
    assert_eq!(
        report.ceiling_exceeded_by, None,
        "level {level} solid {solid}: the write reported its ceiling passed"
    );
    report.peak_working_memory
}

#[test]
fn the_live_heap_of_a_named_budget_stays_inside_its_working_limit() {
    let members = members();
    let names: Vec<Vec<u8>> = (0..members.len())
        .map(|at| format!("m{at:03}.bin").into_bytes())
        .collect();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(32)
        .build()
        .expect("a pool of thirty-two");
    // The 512 MiB budget, not solid and solid; and a SOLID archive under
    // smaller named budgets. A solid RAR 5 archive's default dictionary
    // is 32 MiB since 10 Oct 2026, and a named budget keeps the 2 MiB
    // one (`write::options::resolve`): these rows are what holds that
    // default inside a limit the caller named.
    let rows = [
        (MemoryPolicy::DEFAULT_LIMIT, false),
        (MemoryPolicy::DEFAULT_LIMIT, true),
        (256 << 20, true),
        (160 << 20, true),
    ];
    for (limit, solid) in rows {
        let memory = MemoryPolicy::for_process(limit, 0);
        assert!(memory.limit_named);
        for level in [1u8, 3, 5] {
            // What the test holds itself is the caller's, not the write's.
            let before = LIVE.load(Ordering::Relaxed);
            MOST.store(before, Ordering::Relaxed);
            let stated = pool.install(|| write(&members, &names, level, solid, memory));
            let heap = MOST.load(Ordering::Relaxed).saturating_sub(before) as u64;
            let what = format!("level {level}, solid {solid}, named {} MiB", limit >> 20);
            eprintln!(
                "{what}: live heap at most {} MiB, stated {} MiB, working limit {} MiB",
                heap >> 20,
                stated >> 20,
                memory.working_limit >> 20
            );
            assert!(
                heap <= memory.working_limit,
                "{what}: the write held {heap} live bytes against a working limit of {}",
                memory.working_limit
            );
            assert!(
                stated <= memory.working_limit,
                "{what}: the write stated {stated} bytes against {}",
                memory.working_limit
            );
        }
    }
}
