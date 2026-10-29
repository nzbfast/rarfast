//! UNTIMED rate profile of the BLAKE2sp kernel (spec L 3.3 and 7).
//!
//! This is not a gate harness and it has no oracle arm: `two_arm` is the
//! gate and the only thing that may carry a ratio. What this measures is
//! rarkit's hash path against ITSELF and against the arithmetic bound,
//! which is a question one box can answer without a timed run:
//!
//! - the clock, measured rather than assumed, from a dependent add chain
//!   whose latency is one cycle a link on every aarch64 core;
//! - the kernel's rate at a working set that fits L2 and at one that does
//!   not, so a memory effect cannot be read as a kernel effect;
//! - the same at eight workers, for the pool's share;
//! - the per-chunk overhead, as the slope of wall against chunk count at
//!   one fixed total.
//!
//! Every figure is ns per byte and cycles per byte. The arithmetic bound
//! it is read against is printed beside it and derived in the results
//! file, not here.
//!
//! `unsafe` is allowed in this file for the clock probe alone, which is
//! two instructions of inline assembly. Spec L 7's restriction is on the
//! PACKAGE; this is an example binary that no shipped build compiles.
#![allow(unsafe_code)]

use std::time::Instant;

use rarkit::internals::recovery::{blake2sp, Blake2sp};

/// Bytes per BLAKE2s block, and the eight-leaf group spec L 3.3 deals.
const GROUP: usize = 64 * 8;

/// The measured clock in Hz, from a chain of dependent adds.
///
/// Each `add` depends on the one before it, so the chain retires at one
/// link a cycle on any core that can issue an add at all: the elapsed
/// time over the link count IS the cycle time, with no assumption about
/// the part. Reported beside the rates so a throttled or efficiency core
/// shows up as an implausible clock rather than as a slow kernel.
fn clock_hz() -> f64 {
    const LINKS: u64 = 400_000_000;
    let mut x: u64 = 0;
    let started = Instant::now();
    #[cfg(target_arch = "aarch64")]
    {
        let mut left = LINKS / 8;
        while left > 0 {
            // SAFETY: eight adds on one general register, no memory and no
            // flags. The chain is what is being timed.
            unsafe {
                std::arch::asm!(
                    "add {x}, {x}, #1",
                    "add {x}, {x}, #1",
                    "add {x}, {x}, #1",
                    "add {x}, {x}, #1",
                    "add {x}, {x}, #1",
                    "add {x}, {x}, #1",
                    "add {x}, {x}, #1",
                    "add {x}, {x}, #1",
                    x = inout(reg) x,
                    options(nomem, nostack, preserves_flags),
                );
            }
            left -= 1;
        }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        for _ in 0..LINKS {
            x = std::hint::black_box(x).wrapping_add(1);
        }
    }
    let elapsed = started.elapsed().as_secs_f64();
    std::hint::black_box(x);
    LINKS as f64 / elapsed
}

/// The best of `repeats` runs of `body` over `bytes` bytes.
///
/// Best rather than mean: every contaminant on a shared box adds time,
/// so the minimum is the closest reading to the kernel's own rate. This
/// is a profile, not a gate sample, and the spread is printed with it.
fn best(bytes: usize, repeats: usize, mut body: impl FnMut()) -> (f64, f64) {
    let mut low = f64::MAX;
    let mut high: f64 = 0.0;
    for _ in 0..repeats {
        let started = Instant::now();
        body();
        let each = started.elapsed().as_secs_f64() / bytes as f64;
        low = low.min(each);
        high = high.max(each);
    }
    (low, high)
}

fn row(name: &str, ns_per_byte: f64, spread: f64, hz: f64) {
    println!(
        "{name:34} {:7.4} ns/B  {:6.3} cyc/B  {:7.3} GB/s  spread {:5.1}%",
        ns_per_byte * 1e9,
        ns_per_byte * hz,
        1.0 / ns_per_byte / 1e9,
        spread * 100.0,
    );
}

fn main() {
    let hz = clock_hz();
    println!(
        "clock {:.3} GHz, measured from a dependent add chain",
        hz / 1e9
    );
    println!("group {GROUP} bytes, eight leaves of one 64-byte block each\n");

    // Sized so each working set sits where it is meant to: 256 KiB inside
    // this core's L2, 64 MiB outside any cache, and the middle rung to
    // show whether the two ends differ for a memory reason.
    for &(label, size, repeats) in &[
        ("one-shot 256KiB (L2)", 256 * 1024, 400),
        ("one-shot 4MiB", 4 * 1024 * 1024, 60),
        ("one-shot 64MiB (DRAM)", 64 * 1024 * 1024, 8),
    ] {
        let data = vec![0x5au8; size];
        let (low, high) = best(size, repeats, || {
            std::hint::black_box(blake2sp(std::hint::black_box(&data)));
        });
        row(label, low, (high - low) / low, hz);
    }
    println!();

    // The same bytes through the incremental seam at one worker and at
    // eight, fed whole. The gap between this and the one-shot row above
    // is the seam's own, not the kernel's.
    let big = vec![0x5au8; 64 * 1024 * 1024];
    for workers in [1usize, 8] {
        let (low, high) = best(big.len(), 8, || {
            let mut hasher = Blake2sp::with_workers(workers);
            hasher.update(std::hint::black_box(&big));
            std::hint::black_box(hasher.finalize());
        });
        row(
            &format!("64MiB whole, {workers} worker(s)"),
            low,
            (high - low) / low,
            hz,
        );
    }
    println!();

    // Per-chunk overhead: one total, many chunk counts. The slope of
    // wall against chunk count is the per-call cost, and it is what the
    // chunked legs are made of.
    for workers in [1usize, 8] {
        let mut points: Vec<(usize, f64)> = Vec::new();
        for &chunk in &[
            4 * 1024usize,
            64 * 1024,
            256 * 1024,
            1024 * 1024,
            4 * 1024 * 1024,
        ] {
            let (low, high) = best(big.len(), 5, || {
                let mut hasher = Blake2sp::with_workers(workers);
                for piece in big.chunks(chunk) {
                    hasher.update(std::hint::black_box(piece));
                }
                std::hint::black_box(hasher.finalize());
            });
            let calls = big.len().div_ceil(chunk);
            points.push((calls, low * big.len() as f64));
            row(
                &format!("64MiB in {:>7} B chunks, {workers}w", chunk),
                low,
                (high - low) / low,
                hz,
            );
        }
        // Two points far apart give the slope with no fitting: the 4 KiB
        // rung has the most calls and the 4 MiB rung the fewest.
        let (calls_many, wall_many) = points[0];
        let (calls_few, wall_few) = points[points.len() - 1];
        let per_call = (wall_many - wall_few) / (calls_many - calls_few) as f64;
        println!(
            "  per-update-call overhead at {workers}w: {:8.1} ns = {:7.0} cycles \
             ({} calls against {})",
            per_call * 1e9,
            per_call * hz,
            calls_many,
            calls_few,
        );
        println!();
    }
}
