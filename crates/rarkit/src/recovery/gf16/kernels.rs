//! The SIMD half of `dst ^= c * src` over GF(2^16) symbols.
//!
//! One shape, three instruction sets. A symbol's four nibbles each select a
//! 16-entry table of partial products (`c * (n << 4j)`, low and high byte
//! kept apart), so the whole multiply is four table shuffles per output
//! byte and no per-symbol logarithm. The x86-64 kernels and the table
//! builder came with the carry port; the NEON kernel and the dispatch
//! below are this package's.
//!
//! This is the one module of the recovery package that carries `unsafe`
//! (spec L section 7): every block is a SIMD intrinsic call whose safety
//! obligation is the target feature plus the slice bounds computed here.
#![allow(unsafe_code)]

use crate::carry::h_ours::recovery::gf16_fold::FoldTables;

/// Fold as much of `src` into `dst` as a vector kernel can take, and
/// return how many bytes that was. `dst` and `src` are the same length and
/// hold a whole number of symbols.
#[inline]
pub(crate) fn fold(tables: &FoldTables, dst: &mut [u8], src: &[u8]) -> usize {
    #[cfg(target_arch = "aarch64")]
    {
        // NEON is baseline on aarch64, so there is nothing to detect.
        // SAFETY: `neon` is guaranteed by the target architecture, and the
        // kernel reads and writes only inside the length it returns.
        unsafe { fold_neon(&tables.nl, &tables.nh, dst, src) }
    }
    #[cfg(target_arch = "x86_64")]
    {
        use crate::carry::h_ours::recovery::gf16_fold::{fold_avx2, fold_gfni, fold_ssse3};
        if is_x86_feature_detected!("gfni") && is_x86_feature_detected!("avx2") {
            // SAFETY: both features were just detected; the kernel stays
            // inside the bytes it returns.
            return unsafe { fold_gfni(&tables.affine, dst, src) };
        }
        if is_x86_feature_detected!("avx2") {
            // SAFETY: as above, for AVX2.
            return unsafe { fold_avx2(&tables.nl, &tables.nh, dst, src) };
        }
        if is_x86_feature_detected!("ssse3") {
            // SAFETY: as above, for SSSE3.
            return unsafe { fold_ssse3(&tables.nl, &tables.nh, dst, src) };
        }
        0
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        let _ = (tables, dst, src);
        0
    }
}

/// NEON: sixteen symbols per 32-byte chunk.
///
/// `vld2q_u8` de-interleaves the little-endian symbols into a vector of low
/// bytes and one of high bytes, which is exactly the split the nibble
/// tables want, and `vst2q_u8` puts the folded pair back.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn fold_neon(nl: &[[u8; 16]; 4], nh: &[[u8; 16]; 4], dst: &mut [u8], src: &[u8]) -> usize {
    use std::arch::aarch64::*;
    let chunks = src.len().min(dst.len()) / 32;
    if chunks == 0 {
        return 0;
    }
    // SAFETY: NEON is enabled per the target feature; every load and store
    // is inside the first `chunks * 32` bytes of both slices, and `vqtbl1q`
    // indexes a 16-byte table with a nibble.
    unsafe {
        let load = |t: &[u8; 16]| vld1q_u8(t.as_ptr());
        let (low0, low1, low2, low3) = (load(&nl[0]), load(&nl[1]), load(&nl[2]), load(&nl[3]));
        let (high0, high1, high2, high3) = (load(&nh[0]), load(&nh[1]), load(&nh[2]), load(&nh[3]));
        let nib = vdupq_n_u8(0x0f);
        for c in 0..chunks {
            let s = vld2q_u8(src.as_ptr().add(c * 32));
            let n0 = vandq_u8(s.0, nib);
            let n1 = vshrq_n_u8::<4>(s.0);
            let n2 = vandq_u8(s.1, nib);
            let n3 = vshrq_n_u8::<4>(s.1);
            let plo = veorq_u8(
                veorq_u8(vqtbl1q_u8(low0, n0), vqtbl1q_u8(low1, n1)),
                veorq_u8(vqtbl1q_u8(low2, n2), vqtbl1q_u8(low3, n3)),
            );
            let phi = veorq_u8(
                veorq_u8(vqtbl1q_u8(high0, n0), vqtbl1q_u8(high1, n1)),
                veorq_u8(vqtbl1q_u8(high2, n2), vqtbl1q_u8(high3, n3)),
            );
            let at = dst.as_mut_ptr().add(c * 32);
            let d = vld2q_u8(at);
            vst2q_u8(at, uint8x16x2_t(veorq_u8(d.0, plo), veorq_u8(d.1, phi)));
        }
    }
    chunks * 32
}

/// The GFNI kernel against the scalar fold, on hardware that has it.
///
/// The bit matrices `fold_gfni` consumes are checked on every target by
/// `super::affine`, which applies them in scalar code from Intel's own
/// definition of the instruction. What cannot be checked that way is
/// whether the KERNEL feeds them the bytes it means to - the pack, the
/// unpack and the low/high split around the four `gf2p8affineqb`s - so
/// this runs the real instruction where one exists.
#[cfg(all(test, target_arch = "x86_64"))]
mod gfni_tests {
    use crate::carry::h_ours::recovery::gf16_fold::{fold_gfni, FoldTables};
    use crate::recovery::gf16::Coefficient;

    /// Deterministic xorshift64, as the other test files here use.
    fn next(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[test]
    fn gfni_fold_matches_the_scalar_fold() {
        if !(is_x86_feature_detected!("gfni") && is_x86_feature_detected!("avx2")) {
            // Named, not silent: a skip that reads as a pass is how an
            // untested kernel ships. Rosetta on aarch64 macOS lands here,
            // so a Mac proves the matrices and has not run the instruction.
            eprintln!(
                "SKIPPED gfni_fold_matches_the_scalar_fold: no GFNI+AVX2 on this CPU. \
                 Not yet run on GFNI hardware."
            );
            return;
        }
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        // Four whole 64-byte chunks and a 30-byte tail the kernel must not
        // touch, so the returned length is checked as well as the bytes.
        let len = 4 * 64 + 30;
        for c in [0u16, 1, 2, 0xFFFF, 0x8000, 0x100B, 0xBEEF, 0x1234] {
            let src: Vec<u8> = (0..len).map(|_| next(&mut state) as u8).collect();
            let original: Vec<u8> = (0..len).map(|_| next(&mut state) as u8).collect();
            let coefficient = Coefficient::new(c);

            let mut expected = original.clone();
            for i in (0..len - 30).step_by(2) {
                let product = coefficient.apply(u16::from_le_bytes([src[i], src[i + 1]]))
                    ^ u16::from_le_bytes([expected[i], expected[i + 1]]);
                expected[i..i + 2].copy_from_slice(&product.to_le_bytes());
            }

            let mut dst = original.clone();
            let tables = FoldTables::new(c);
            // SAFETY: GFNI and AVX2 were just detected on this branch, and
            // the two slices are the same length.
            let done = unsafe { fold_gfni(&tables.affine, &mut dst, &src) };
            assert_eq!(done, 4 * 64, "c = {c:#06x}: whole chunks folded");
            assert_eq!(dst[..done], expected[..done], "c = {c:#06x}: folded bytes");
            assert_eq!(
                dst[done..],
                original[done..],
                "c = {c:#06x}: tail untouched"
            );
        }
    }
}
