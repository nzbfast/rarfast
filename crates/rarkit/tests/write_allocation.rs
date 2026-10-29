//! Spec G 7.3: "No allocation per member beyond the member table, and
//! none per header, per name or per chunk."
//!
//! The bench's `g/create/rar5/m0/20k` leg is the one that
//! MEASURES that rule, and a wall figure on a shared box cannot say
//! whether it holds - it says only that the leg got faster or slower.
//! This test says whether it holds, by counting the allocations a run
//! makes and differencing two runs whose only difference is the number
//! of members. Anything the writer allocates once, whatever its size,
//! cancels in the difference; anything it allocates per member, however
//! cheap, survives it.
//!
//! The counting allocator is this binary's own, which is why the test
//! lives in a file of its own: a global allocator is per binary and this
//! one is not something the rest of the suite should run under.
//! `tests/streaming_memory.rs` measures the READ side the same way and
//! for the same reason.

#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io::{Seek, SeekFrom, Write};

use rarkit::{FilterPolicy, HostOs, MemberSpec, Payload, WriteFormat, WriteOptions, Writer};

// Allocations made on THIS thread while it is armed, and whether it is.
// Thread local because the test harness runs the tests of a binary in
// parallel, and a shared counter would count another test's writer as
// well as this one's: that is how this test first read 24 where it
// should have read 10,009.
thread_local!(static COUNT: Cell<usize> = const { Cell::new(0) });
thread_local!(static ARMED: Cell<bool> = const { Cell::new(false) });

/// One allocation, if this thread is counting. `try_with` because an
/// allocation can happen while a thread's locals are being torn down.
fn tick() {
    let _ = ARMED.try_with(|armed| {
        if armed.get() {
            let _ = COUNT.try_with(|count| count.set(count.get() + 1));
        }
    });
}

struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        tick();
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        tick();
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// A seekable output that keeps nothing: the engine patches a header
/// where it lies, and a `Vec` or a temporary file would put its own
/// growth or its own buffering into the count.
#[derive(Default)]
struct Void {
    at: u64,
    len: u64,
}

impl Write for Void {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.at += data.len() as u64;
        self.len = self.len.max(self.at);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Seek for Void {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        self.at = match to {
            SeekFrom::Start(at) => at,
            SeekFrom::End(delta) => self.len.saturating_add_signed(delta),
            SeekFrom::Current(delta) => self.at.saturating_add_signed(delta),
        };
        Ok(self.at)
    }
}

/// How many allocations `finish_seek` makes for `members` members. The
/// names and the payload are built and the writer is loaded BEFORE the
/// count is armed, so what is counted is the write and not the table.
fn allocations(format: WriteFormat, members: usize) -> usize {
    let payload = vec![0x5Au8; members * 64];
    let names: Vec<Vec<u8>> = (0..members)
        .map(|i| format!("m{i:05}.bin").into_bytes())
        .collect();
    let mut writer = Writer::new(WriteOptions {
        format,
        host_os: HostOs::Unix,
        // The RAR 4 family emits no filter record at all (SPEC-J),
        // so a RAR 4 target refuses the default policy outright.
        filters: FilterPolicy::Off,
        ..WriteOptions::default()
    })
    .expect("spec G options");
    for (index, name) in names.iter().enumerate() {
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(&payload[index * 64..(index + 1) * 64]),
                mtime: None,
                attributes: 0o100644,
                host_os: HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }

    COUNT.with(|count| count.set(0));
    ARMED.with(|armed| armed.set(true));
    let report = writer.finish_seek(Void::default());
    ARMED.with(|armed| armed.set(false));
    report.expect("finish");
    COUNT.with(|count| count.get())
}

/// The rule itself, in both families: doubling the members does not
/// change how many times the run allocates.
///
/// Measured before the header buffers were reused, with
/// this same test: RAR 5 made 10,009 allocations over 1,000 members and
/// 20,009 over 2,000, which is TEN per member, and RAR 4 made 8,005 and
/// 16,005, which is eight. They were the copy of the name, the extra
/// area, the block-specific area, the two framing buffers, the extra
/// records, and under RAR 4 the backslash form of the name as well.
/// A per-member allocation of any size shows up here as at least 1,000,
/// so the assertion is equality and not a tolerance.
#[test]
fn a_run_allocates_nothing_per_member_or_per_header() {
    let mut counts: Vec<(WriteFormat, usize, usize)> = Vec::new();
    for format in [
        WriteFormat::Rar5,
        WriteFormat::Rar4(rarkit::Rar4Version::V29),
    ] {
        // ONE RUN FIRST, NOT COUNTED. What the engine reads once a PROCESS
        // (a bench build's knobs, each read from the environment the first
        // time it is asked) is not a run's, and where a read of the
        // environment allocates it lands on whichever run is first: a
        // hosted Windows runner read 18 allocations over 1,000 members and
        // 17 over 2,000 on 6 Oct 2026, one fewer on the SECOND run, where
        // Linux and macOS read 16 and 16. The difference below is between
        // two runs that are both past it.
        let _ = allocations(format, 8);
        let few = allocations(format, 1_000);
        let many = allocations(format, 2_000);
        println!("{format:?}: 1,000 members -> {few} allocations, 2,000 -> {many}");
        counts.push((format, few, many));
    }
    for (format, few, many) in counts {
        assert_eq!(
            few,
            many,
            "{format:?}: 1,000 members allocated {few} times and 2,000 allocated {many}, \
             so {} allocations are per member (spec G 7.3)",
            many.saturating_sub(few)
        );
    }
}

/// The count does not merely SCALE well, it is small: a run's whole
/// write is a handful of buffers, and a regression that allocated once
/// per volume or once per checksum would pass the test above.
#[test]
fn a_run_allocates_a_handful_of_buffers_in_total() {
    for format in [
        WriteFormat::Rar5,
        WriteFormat::Rar4(rarkit::Rar4Version::V29),
    ] {
        let count = allocations(format, 2_000);
        assert!(
            count < 64,
            "{format:?}: a stored run over 2,000 members made {count} allocations; \
             spec G 7.3 wants the buffers of the run and nothing else"
        );
    }
}
