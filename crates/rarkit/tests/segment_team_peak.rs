//! What the SEGMENT TEAM holds against what the write STATES (spec G
//! 3.7.3).
//!
//! Counted on 2 Oct 2026 on a 96 thread box with no cap, one 4 GiB member
//! at level 3, the team forced to 1, 2, 4, 8, 16 and 24 engines: the
//! process stood above `WriteReport::peak_working_memory` by 27, 70, 122,
//! 208, 345 and 478 MiB, about 20 MiB an engine. Under a cgroup cap of 512
//! MiB that is a process of 485 MiB at a budget of 416, and the kernel
//! kills it.
//!
//! The allocator below is this binary's own (a global allocator is per
//! binary, as in `tests/write_allocation.rs`): it keeps the bytes live on
//! the heap, their high-water mark, and at that mark the sizes of the
//! large blocks then live, so a width's blocks can be told apart from
//! one engine's.

#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{Cursor, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicUsize, Ordering};

use rarkit::internals::writers::with_segment_width;
use rarkit::{FilterPolicy, MemberSpec, Payload, WriteFormat, WriteMethod, WriteOptions, Writer};

/// Blocks of at least this many bytes are remembered one by one.
const LARGE: usize = 256 << 10;
/// How many large blocks can be live at once.
const SLOTS: usize = 4096;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ADDRESS: [AtomicUsize; SLOTS] = [const { AtomicUsize::new(0) }; SLOTS];
static SIZE: [AtomicUsize; SLOTS] = [const { AtomicUsize::new(0) }; SLOTS];
static AT_PEAK: [AtomicUsize; SLOTS] = [const { AtomicUsize::new(0) }; SLOTS];

fn took(address: usize, size: usize) {
    if size >= LARGE {
        for (held, bytes) in ADDRESS.iter().zip(&SIZE) {
            if held
                .compare_exchange(0, address, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                bytes.store(size, Ordering::Release);
                break;
            }
        }
    }
    let live = LIVE.fetch_add(size, Ordering::AcqRel) + size;
    // A new high-water mark by a megabyte and more: remember what is live.
    let peak = PEAK.load(Ordering::Acquire);
    if live > peak + (1 << 20)
        && PEAK
            .compare_exchange(peak, live, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    {
        for ((held, bytes), seen) in ADDRESS.iter().zip(&SIZE).zip(&AT_PEAK) {
            let size = if held.load(Ordering::Acquire) == 0 {
                0
            } else {
                bytes.load(Ordering::Acquire)
            };
            seen.store(size, Ordering::Release);
        }
    }
}

fn gave(address: usize, size: usize) {
    if size >= LARGE {
        for (held, bytes) in ADDRESS.iter().zip(&SIZE) {
            if held.load(Ordering::Acquire) == address {
                bytes.store(0, Ordering::Release);
                held.store(0, Ordering::Release);
                break;
            }
        }
    }
    LIVE.fetch_sub(size, Ordering::AcqRel);
}

struct Tracking;

unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let block = unsafe { System.alloc(layout) };
        if !block.is_null() {
            took(block as usize, layout.size());
        }
        block
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let block = unsafe { System.alloc_zeroed(layout) };
        if !block.is_null() {
            took(block as usize, layout.size());
        }
        block
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        gave(block as usize, layout.size());
        unsafe { System.dealloc(block, layout) }
    }

    unsafe fn realloc(&self, block: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(block, layout, new_size) };
        if !moved.is_null() {
            gave(block as usize, layout.size());
            took(moved as usize, new_size);
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: Tracking = Tracking;

/// A seekable output that keeps nothing, so the archive is not on the
/// heap.
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
            SeekFrom::End(by) => self.len.saturating_add_signed(by),
            SeekFrom::Current(by) => self.at.saturating_add_signed(by),
        };
        Ok(self.at)
    }
}

/// `len` bytes a chain level compresses to a little over half (0.65 at
/// level 1 and 0.60 at level 3 with no filter, measured 11 Oct 2026):
/// bytes laid out like machine code, so every stretch has work and
/// packed bytes.
fn binary(len: usize, seed: u64) -> Vec<u8> {
    rarkit_testdata::machine_like(seed, len)
}

/// One member of `data` at `level` on `threads` threads with the team
/// forced to `width` engines: the stated peak, the heap's rise above
/// where it stood before the write, and the sizes of the large blocks
/// live at that high-water mark that were not live before it.
fn write(data: &[u8], level: u8, threads: usize, width: usize) -> (u64, usize, Vec<usize>) {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .expect("a pool");
    pool.install(|| {
        with_segment_width(width, || {
            let before = LIVE.load(Ordering::Acquire);
            let mut held: Vec<usize> = ADDRESS
                .iter()
                .zip(&SIZE)
                .filter(|(address, _)| address.load(Ordering::Acquire) != 0)
                .map(|(_, size)| size.load(Ordering::Acquire))
                .collect();
            PEAK.store(before, Ordering::Release);
            for seen in &AT_PEAK {
                seen.store(0, Ordering::Release);
            }
            let mut writer = Writer::new(WriteOptions {
                format: WriteFormat::Rar5,
                method: WriteMethod::Compressed {
                    level,
                    dictionary: None,
                },
                filters: FilterPolicy::Detect,
                host_os: rarkit::HostOs::Unix,
                workers: Some(threads),
                ..WriteOptions::default()
            })
            .expect("options");
            let mut reader = Cursor::new(data);
            writer
                .add(MemberSpec {
                    name: b"member.bin",
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
            let mut out = Void::default();
            let report = writer.finish_seek(&mut out).expect("finish_seek");
            let rise = PEAK.load(Ordering::Acquire).saturating_sub(before);
            let mut large: Vec<usize> = AT_PEAK
                .iter()
                .map(|seen| seen.load(Ordering::Acquire))
                .filter(|&size| size != 0)
                .collect();
            // What was live before the write is not the write's.
            held.sort_unstable();
            large.sort_unstable();
            for size in held {
                if let Ok(at) = large.binary_search(&size) {
                    large.remove(at);
                }
            }
            (report.peak_working_memory, rise, large)
        })
    })
}

/// The large blocks as "count x MiB", largest first.
fn census(large: &[usize]) -> String {
    let mut sizes: Vec<(usize, usize)> = Vec::new();
    for &size in large.iter().rev() {
        // To a sixteenth of a MiB: the same structure in every engine.
        let rounded = size >> 16;
        match sizes.last_mut() {
            Some((last, count)) if *last == rounded => *count += 1,
            _ => sizes.push((rounded, 1)),
        }
    }
    sizes
        .iter()
        .map(|(size, count)| format!("{count} x {:.2}", *size as f64 / 16.0))
        .collect::<Vec<_>>()
        .join(", ")
}

#[test]
#[ignore = "a probe, run by hand: prints the heap against the stated peak by team width"]
fn probe_the_heap_against_the_stated_peak_by_team_width() {
    let data = binary(1 << 30, 7);
    for level in [3u8, 1] {
        for width in [1usize, 2, 4, 8] {
            let (stated, rise, large) = write(&data, level, 32, width);
            let in_large: usize = large.iter().sum();
            eprintln!(
                "m{level} {width} engines: stated {} MiB, heap {} MiB ({} in {} large blocks), unstated {} MiB",
                stated >> 20,
                rise >> 20,
                in_large >> 20,
                large.len(),
                (rise as i64 - stated as i64) >> 20,
            );
            eprintln!("    large blocks, MiB: {}", census(&large));
        }
    }
}
