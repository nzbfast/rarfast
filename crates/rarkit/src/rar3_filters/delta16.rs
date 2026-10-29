//! The delta transform at SIXTEEN channels, in one vector pass
//! (SPEC-J section 3.7.1).
//!
//! Sixteen is not an arbitrary width to single out. The filtered block is
//! planar and the original is interleaved, so delta decode at `N`
//! channels is a running sum down each of `N` planes followed by an
//! `N`-wide TRANSPOSE, and at `N` equal to the machine's vector width in
//! bytes both halves are things the machine does in one instruction
//! each: the running sum is four shift-and-add steps over a vector, and
//! the transpose is four stages of interleave. The scalar row form in
//! this package's `transforms` module is the same computation and is what
//! every other width takes, including this one where there is no vector
//! unit; `delta16_matches_rows` holds the two against each other.
//!
//! Sixteen channels is also what the RAR 3 corpus asks for: the
//! `rar3_vm_1m` member of the bench is 32 spans of 32,768
//! bytes at 16 channels, and that transform was 68 percent of that leg's
//! decode.
#![allow(unsafe_code)]

/// Channels this kernel answers, which is the vector width in bytes.
pub(super) const N: usize = 16;

/// Rows taken per vector block, which is also `N`: a block is an `N` by
/// `N` byte square read down the planes and written across the rows.
///
/// Only the kernel names it, and every box in this fleet is aarch64, so
/// the `cfg` is the thing no local gate can fail on: without it this is
/// an unused const on x86-64 and `clippy -D warnings` refuses the build
/// there.
#[cfg(target_arch = "aarch64")]
const BLOCK: usize = N;

/// Whether this build has the kernel at all.
#[cfg(target_arch = "aarch64")]
pub(super) const AVAILABLE: bool = true;
/// See the aarch64 arm. x86-64's own kernel is not written yet; until it exists that
/// target takes the scalar row form, which is correct and slower.
#[cfg(not(target_arch = "aarch64"))]
pub(super) const AVAILABLE: bool = false;

/// Delta decode `src` into `out` at [`N`] channels, `starts` naming where
/// each plane begins in `src`.
///
/// `out.len()` must be `src.len()`, and `starts` must be the plane offsets
/// `transforms::delta_decode` computes, or this writes the wrong bytes;
/// it is `pub(super)` and has one caller for that reason.
///
/// Returns the accumulators and the number of WHOLE rows it wrote, so the
/// caller finishes any rows the block loop could not reach and the last
/// partial row exactly as the scalar form does.
#[cfg(target_arch = "aarch64")]
pub(super) fn rows16(src: &[u8], out: &mut [u8], starts: &[usize; N]) -> ([u8; N], usize) {
    use std::arch::aarch64::*;

    let n = out.len();
    let rows = n / N;
    let blocks = rows / BLOCK;
    let mut acc = [0u8; N];
    // What the unsafe block below reads and writes, checked here so the
    // SAFETY note is a statement about THIS function and not about its
    // caller. The shortest plane holds exactly `rows` bytes (plane `c`
    // holds `ceil((n - c) / N)`, which is `rows` for `c >= n % N`), and
    // the block loop reads `starts[c] + j` for `j + BLOCK <= blocks *
    // BLOCK <= rows`; it writes `out[j * N ..][.. N]` for `j < blocks *
    // BLOCK <= rows`, so the last byte written is below `rows * N <= n`.
    let last_read = blocks * BLOCK;
    for &start in starts.iter() {
        assert!(
            start + last_read <= src.len(),
            "a plane's block reads must lie inside the span"
        );
    }
    assert!(
        blocks * BLOCK * N <= n,
        "a block's writes lie inside the span"
    );
    for blk in 0..blocks {
        let j = blk * BLOCK;
        // SAFETY: NEON is part of the aarch64 baseline this crate builds
        // for, so every intrinsic below is callable; the loads read
        // `starts[c] + j .. + 16` and the stores write
        // `(j + q) * N .. + 16`, both checked in full by the two
        // assertions above, which do not depend on the loop variable
        // beyond `blk < blocks`.
        unsafe {
            let zero = vdupq_n_u8(0);
            let mut plane = [zero; N];
            for (c, slot) in plane.iter_mut().enumerate() {
                // The plane's next sixteen filtered bytes become that
                // plane's running sum: shifting the vector up by 1, 2, 4
                // and 8 lanes and adding leaves lane `i` holding the sum
                // of lanes 0 to `i`.
                let v = vld1q_u8(src.as_ptr().add(starts[c] + j));
                let v = vaddq_u8(v, vextq_u8::<15>(zero, v));
                let v = vaddq_u8(v, vextq_u8::<14>(zero, v));
                let v = vaddq_u8(v, vextq_u8::<12>(zero, v));
                let v = vaddq_u8(v, vextq_u8::<8>(zero, v));
                // The original bytes are the accumulator less the running
                // sum, and the accumulator for the next block is the last
                // of them.
                let r = vsubq_u8(vdupq_n_u8(acc[c]), v);
                acc[c] = vgetq_lane_u8::<15>(r);
                *slot = r;
            }
            // `plane[c]` now holds channel `c`'s next sixteen original
            // bytes, and the output wants row `j + q` to be one byte from
            // each channel: that is the transpose of the 16 by 16 square,
            // which is four stages of interleave at 8, 16, 32 and 64 bits.
            let mut a = [zero; N];
            for k in 0..8 {
                a[2 * k] = vtrn1q_u8(plane[2 * k], plane[2 * k + 1]);
                a[2 * k + 1] = vtrn2q_u8(plane[2 * k], plane[2 * k + 1]);
            }
            let mut b = [zero; N];
            for k in 0..4 {
                for q in 0..2 {
                    let (x, y) = (
                        vreinterpretq_u16_u8(a[4 * k + q]),
                        vreinterpretq_u16_u8(a[4 * k + q + 2]),
                    );
                    b[4 * k + q] = vreinterpretq_u8_u16(vtrn1q_u16(x, y));
                    b[4 * k + q + 2] = vreinterpretq_u8_u16(vtrn2q_u16(x, y));
                }
            }
            let mut c4 = [zero; N];
            for k in 0..2 {
                for q in 0..4 {
                    let (x, y) = (
                        vreinterpretq_u32_u8(b[8 * k + q]),
                        vreinterpretq_u32_u8(b[8 * k + q + 4]),
                    );
                    c4[8 * k + q] = vreinterpretq_u8_u32(vtrn1q_u32(x, y));
                    c4[8 * k + q + 4] = vreinterpretq_u8_u32(vtrn2q_u32(x, y));
                }
            }
            for q in 0..8 {
                let (x, y) = (vreinterpretq_u64_u8(c4[q]), vreinterpretq_u64_u8(c4[q + 8]));
                let lo = vreinterpretq_u8_u64(vtrn1q_u64(x, y));
                let hi = vreinterpretq_u8_u64(vtrn2q_u64(x, y));
                vst1q_u8(out.as_mut_ptr().add((j + q) * N), lo);
                vst1q_u8(out.as_mut_ptr().add((j + q + 8) * N), hi);
            }
        }
    }
    (acc, blocks * BLOCK)
}

/// The stand-in on a target with no kernel: nothing is done and no row is
/// claimed, so the caller's scalar loop writes every row itself.
#[cfg(not(target_arch = "aarch64"))]
pub(super) fn rows16(src: &[u8], out: &mut [u8], starts: &[usize; N]) -> ([u8; N], usize) {
    let _ = (src, out, starts);
    ([0u8; N], 0)
}
