//! Carried from the predecessor's `recovery/gf16_fold.rs` at an earlier revision: items ours from birth
//! per the provenance census (and clean-room outputs, clean by provenance).
//!
//! `fold_simd` and `fold_neon` were left out of the first carry port for one
//! reason, that they carry an `unsafe` block and no package specification
//! named this module yet. They are CARRY at the fork tip on the
//! provenance method: zero donor lines each, and no item of the same name
//! anywhere at the fork point. Specification L's erratum of
//! 18 Sep 2026 names this module and permits `unsafe` inside it, which is
//! why the crate-wide `deny` is lifted here and nowhere else; the x86
//! kernels below, carried first time round, are covered by the same lift.
//!
//! This is the nibble-shuffle form over GF(2^16) reduced by 0x1100B: a
//! word's product is the XOR of its four nibbles' contributions, each one a
//! 16-entry table shuffle (`vqtbl1q_u8` on NEON, `pshufb` on x86; four
//! `gf2p8affineqb` bit-matrix products where GFNI exists), sixteen or
//! thirty-two words per iteration.
#![allow(unsafe_code)]

/// The low- and high-byte nibble tables of one coefficient:
/// `nl[j][n]` / `nh[j][n]` are the low / high byte of `c * (n << 4j)`.
#[derive(Clone, Copy)]
pub(crate) struct FoldTables {
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    pub(crate) nl: [[u8; 16]; 4],
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    pub(crate) nh: [[u8; 16]; 4],
    /// GFNI 8x8 bit-matrices `[ll, hl, lh, hh]`: product low / high byte
    /// from source low / high byte.
    #[cfg(target_arch = "x86_64")]
    pub(crate) affine: [u64; 4],
}
impl FoldTables {
    /// Tables for multiply-by-`c`, from the xtime chain over the field:
    /// `c * x^k` for `k` in 0..16, then every nibble entry as the XOR of
    /// the powers its bits select.
    pub(crate) fn new(c: u16) -> Self {
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        let (nl, nh) = {
            let mut powers = [0u16; 16];
            let mut value = c;
            for slot in powers.iter_mut() {
                *slot = value;
                let carry = value & 0x8000 != 0;
                value <<= 1;
                if carry {
                    value ^= 0x100B;
                }
            }
            let mut nl = [[0u8; 16]; 4];
            let mut nh = [[0u8; 16]; 4];
            for (j, (low, high)) in nl.iter_mut().zip(nh.iter_mut()).enumerate() {
                let mut table = [0u16; 16];
                for bit in 0..4 {
                    let basis = powers[4 * j + bit];
                    for i in 0..(1usize << bit) {
                        table[i | (1 << bit)] = table[i] ^ basis;
                    }
                }
                for n in 0..16 {
                    low[n] = table[n] as u8;
                    high[n] = (table[n] >> 8) as u8;
                }
            }
            (nl, nh)
        };
        // The carry emitted this arm calling a `shared_gf16` helper that
        // the census kept back, so it named nothing in this tree and was
        // the twenty-second error stopping the x86-64 build. The tables
        // are the field's own mathematics, so they are built clean in
        // `recovery::gf16::affine` (spec L 3.4) and this arm just asks.
        #[cfg(target_arch = "x86_64")]
        let affine = crate::recovery::gf16::affine::matrices(c);
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        let _ = c;
        Self {
            #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
            nl,
            #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
            nh,
            #[cfg(target_arch = "x86_64")]
            affine,
        }
    }
}
/// NEON: sixteen words per 32-byte chunk through the nibble tables.
///
/// UNREFERENCED ON ITS OWN TARGET, and kept rather than deleted because
/// that is a defect and not dead weight: this is the aarch64 kernel, it is
/// compiled only on aarch64, and on aarch64 nothing calls it. Spec L
/// section 7 names it as the module the NEON fold lives in, wired behind the
/// checksum package, so either a different entry point is wired or the
/// wiring was lost. Not wired yet: what it should be wired to is the
/// specification's question, not the carried code's.
#[cfg(target_arch = "aarch64")]
#[allow(dead_code)]
pub(crate) unsafe fn fold_neon(
    nl: &[[u8; 16]; 4],
    nh: &[[u8; 16]; 4],
    dst: &mut [u8],
    src: &[u8],
) -> usize {
    use std::arch::aarch64::*;
    let chunks = src.len().min(dst.len()) / 32;
    if chunks == 0 {
        return 0;
    }
    // SAFETY: these intrinsics are unsafe to call only because they need
    // NEON, which is baseline on aarch64 and so has no precondition left for
    // a caller to establish. `chunks` is the floor of the SHORTER slice's
    // length over 32, so every load and store at `c * 32` for `c < chunks`
    // covers 32 bytes inside both slices; `dst` and `src` are separate
    // borrows, so the stores alias nothing that is read here.
    unsafe {
        let (low0, low1, low2, low3) = (
            vld1q_u8(nl[0].as_ptr()),
            vld1q_u8(nl[1].as_ptr()),
            vld1q_u8(nl[2].as_ptr()),
            vld1q_u8(nl[3].as_ptr()),
        );
        let (high0, high1, high2, high3) = (
            vld1q_u8(nh[0].as_ptr()),
            vld1q_u8(nh[1].as_ptr()),
            vld1q_u8(nh[2].as_ptr()),
            vld1q_u8(nh[3].as_ptr()),
        );
        let mask = vdupq_n_u8(0x0f);
        for c in 0..chunks {
            let s = vld2q_u8(src.as_ptr().add(c * 32));
            let n0 = vandq_u8(s.0, mask);
            let n1 = vshrq_n_u8::<4>(s.0);
            let n2 = vandq_u8(s.1, mask);
            let n3 = vshrq_n_u8::<4>(s.1);
            let plo = veorq_u8(
                veorq_u8(vqtbl1q_u8(low0, n0), vqtbl1q_u8(low1, n1)),
                veorq_u8(vqtbl1q_u8(low2, n2), vqtbl1q_u8(low3, n3)),
            );
            let phi = veorq_u8(
                veorq_u8(vqtbl1q_u8(high0, n0), vqtbl1q_u8(high1, n1)),
                veorq_u8(vqtbl1q_u8(high2, n2), vqtbl1q_u8(high3, n3)),
            );
            let dp = dst.as_mut_ptr().add(c * 32);
            let d = vld2q_u8(dp);
            vst2q_u8(dp, uint8x16x2_t(veorq_u8(d.0, plo), veorq_u8(d.1, phi)));
        }
    }
    chunks * 32
}
/// SSSE3: the `pshufb` twin of the NEON path, sixteen words per 32-byte
/// chunk; low and high bytes split with mask and `packus`, the products
/// re-interleaved with `unpack` before the XOR into the destination.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "ssse3")]
pub(crate) unsafe fn fold_ssse3(
    nl: &[[u8; 16]; 4],
    nh: &[[u8; 16]; 4],
    dst: &mut [u8],
    src: &[u8],
) -> usize {
    use std::arch::x86_64::*;
    let chunks = src.len().min(dst.len()) / 32;
    if chunks == 0 {
        return 0;
    }
    // SAFETY: SSSE3 is enabled per the target feature and verified by the
    // caller; every access is inside the first chunks * 32 bytes.
    unsafe {
        let (low0, low1, low2, low3) = (
            _mm_loadu_si128(nl[0].as_ptr() as *const __m128i),
            _mm_loadu_si128(nl[1].as_ptr() as *const __m128i),
            _mm_loadu_si128(nl[2].as_ptr() as *const __m128i),
            _mm_loadu_si128(nl[3].as_ptr() as *const __m128i),
        );
        let (high0, high1, high2, high3) = (
            _mm_loadu_si128(nh[0].as_ptr() as *const __m128i),
            _mm_loadu_si128(nh[1].as_ptr() as *const __m128i),
            _mm_loadu_si128(nh[2].as_ptr() as *const __m128i),
            _mm_loadu_si128(nh[3].as_ptr() as *const __m128i),
        );
        let nib = _mm_set1_epi8(0x0f);
        let lo8 = _mm_set1_epi16(0x00ff);
        for c in 0..chunks {
            let sp = src.as_ptr().add(c * 32) as *const __m128i;
            let v0 = _mm_loadu_si128(sp);
            let v1 = _mm_loadu_si128(sp.add(1));
            let slo = _mm_packus_epi16(_mm_and_si128(v0, lo8), _mm_and_si128(v1, lo8));
            let shi = _mm_packus_epi16(_mm_srli_epi16(v0, 8), _mm_srli_epi16(v1, 8));
            let n0 = _mm_and_si128(slo, nib);
            let n1 = _mm_and_si128(_mm_srli_epi16(slo, 4), nib);
            let n2 = _mm_and_si128(shi, nib);
            let n3 = _mm_and_si128(_mm_srli_epi16(shi, 4), nib);
            let plo = _mm_xor_si128(
                _mm_xor_si128(_mm_shuffle_epi8(low0, n0), _mm_shuffle_epi8(low1, n1)),
                _mm_xor_si128(_mm_shuffle_epi8(low2, n2), _mm_shuffle_epi8(low3, n3)),
            );
            let phi = _mm_xor_si128(
                _mm_xor_si128(_mm_shuffle_epi8(high0, n0), _mm_shuffle_epi8(high1, n1)),
                _mm_xor_si128(_mm_shuffle_epi8(high2, n2), _mm_shuffle_epi8(high3, n3)),
            );
            let dp = dst.as_mut_ptr().add(c * 32) as *mut __m128i;
            let d0 = _mm_loadu_si128(dp);
            let d1 = _mm_loadu_si128(dp.add(1));
            _mm_storeu_si128(dp, _mm_xor_si128(d0, _mm_unpacklo_epi8(plo, phi)));
            _mm_storeu_si128(dp.add(1), _mm_xor_si128(d1, _mm_unpackhi_epi8(plo, phi)));
        }
    }
    chunks * 32
}
/// AVX2: the SSSE3 path widened to thirty-two words per 64-byte chunk;
/// every step is lane-local, so the framing is the 128-bit one twice.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn fold_avx2(
    nl: &[[u8; 16]; 4],
    nh: &[[u8; 16]; 4],
    dst: &mut [u8],
    src: &[u8],
) -> usize {
    use std::arch::x86_64::*;
    let chunks = src.len().min(dst.len()) / 64;
    if chunks == 0 {
        return 0;
    }
    // SAFETY: AVX2 is enabled per the target feature and verified by the
    // caller; every access is inside the first chunks * 64 bytes.
    unsafe {
        let bc = |t: &[u8; 16]| {
            _mm256_broadcastsi128_si256(_mm_loadu_si128(t.as_ptr() as *const __m128i))
        };
        let (low0, low1, low2, low3) = (bc(&nl[0]), bc(&nl[1]), bc(&nl[2]), bc(&nl[3]));
        let (high0, high1, high2, high3) = (bc(&nh[0]), bc(&nh[1]), bc(&nh[2]), bc(&nh[3]));
        let nib = _mm256_set1_epi8(0x0f);
        let lo8 = _mm256_set1_epi16(0x00ff);
        for c in 0..chunks {
            let sp = src.as_ptr().add(c * 64) as *const __m256i;
            let v0 = _mm256_loadu_si256(sp);
            let v1 = _mm256_loadu_si256(sp.add(1));
            let slo = _mm256_packus_epi16(_mm256_and_si256(v0, lo8), _mm256_and_si256(v1, lo8));
            let shi = _mm256_packus_epi16(_mm256_srli_epi16(v0, 8), _mm256_srli_epi16(v1, 8));
            let n0 = _mm256_and_si256(slo, nib);
            let n1 = _mm256_and_si256(_mm256_srli_epi16(slo, 4), nib);
            let n2 = _mm256_and_si256(shi, nib);
            let n3 = _mm256_and_si256(_mm256_srli_epi16(shi, 4), nib);
            let plo = _mm256_xor_si256(
                _mm256_xor_si256(_mm256_shuffle_epi8(low0, n0), _mm256_shuffle_epi8(low1, n1)),
                _mm256_xor_si256(_mm256_shuffle_epi8(low2, n2), _mm256_shuffle_epi8(low3, n3)),
            );
            let phi = _mm256_xor_si256(
                _mm256_xor_si256(
                    _mm256_shuffle_epi8(high0, n0),
                    _mm256_shuffle_epi8(high1, n1),
                ),
                _mm256_xor_si256(
                    _mm256_shuffle_epi8(high2, n2),
                    _mm256_shuffle_epi8(high3, n3),
                ),
            );
            let dp = dst.as_mut_ptr().add(c * 64) as *mut __m256i;
            let d0 = _mm256_loadu_si256(dp);
            let d1 = _mm256_loadu_si256(dp.add(1));
            _mm256_storeu_si256(dp, _mm256_xor_si256(d0, _mm256_unpacklo_epi8(plo, phi)));
            _mm256_storeu_si256(
                dp.add(1),
                _mm256_xor_si256(d1, _mm256_unpackhi_epi8(plo, phi)),
            );
        }
    }
    chunks * 64
}
/// GFNI with AVX2: the eight table shuffles replaced by four
/// `gf2p8affineqb` bit-matrix products, no nibble extraction.
//
// THE WORKSPACE'S DECLARED MSRV (1.87) IS FALSE FOR x86_64 BECAUSE OF
// THIS FUNCTION. `_mm256_gf2p8affine_epi64_epi8` is stable since 1.89,
// and this fold is gated on `target_arch = "x86_64"` alone - no feature
// - so an x86_64 host has not been able to build the crate on 1.87
// since it landed. The lint below is RIGHT; it is waived rather than
// answered because answering it means moving `rust-version`, which is a
// published-crate promise and is the fork owner's call, and because
// clippy gates 27 further `as_chunks` suggestions across the codec on
// that same number - they unlock the moment it moves.
//
// Nothing here saw this until 9 Sep 2026, when the first per-push CI run
// on Linux found it in 33 seconds: the lint only fires on x86 code, and
// every box carrying this fork is aarch64 macOS.
//
// Fix by setting `rust-version = "1.89"` in the workspace manifest,
// deleting this allow, and answering the 27 that follow. Do not fix it
// by widening this cfg or by deleting the fold.
#[allow(clippy::incompatible_msrv)]
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "gfni,avx2")]
pub(crate) unsafe fn fold_gfni(affine: &[u64; 4], dst: &mut [u8], src: &[u8]) -> usize {
    use std::arch::x86_64::*;
    let chunks = src.len().min(dst.len()) / 64;
    if chunks == 0 {
        return 0;
    }
    // SAFETY: GFNI and AVX2 are enabled per the target feature and verified
    // by the caller; every access is inside the first chunks * 64 bytes.
    unsafe {
        let mll = _mm256_set1_epi64x(affine[0] as i64);
        let mhl = _mm256_set1_epi64x(affine[1] as i64);
        let mlh = _mm256_set1_epi64x(affine[2] as i64);
        let mhh = _mm256_set1_epi64x(affine[3] as i64);
        let lo8 = _mm256_set1_epi16(0x00ff);
        for c in 0..chunks {
            let sp = src.as_ptr().add(c * 64) as *const __m256i;
            let v0 = _mm256_loadu_si256(sp);
            let v1 = _mm256_loadu_si256(sp.add(1));
            let slo = _mm256_packus_epi16(_mm256_and_si256(v0, lo8), _mm256_and_si256(v1, lo8));
            let shi = _mm256_packus_epi16(_mm256_srli_epi16(v0, 8), _mm256_srli_epi16(v1, 8));
            let plo = _mm256_xor_si256(
                _mm256_gf2p8affine_epi64_epi8::<0>(slo, mll),
                _mm256_gf2p8affine_epi64_epi8::<0>(shi, mhl),
            );
            let phi = _mm256_xor_si256(
                _mm256_gf2p8affine_epi64_epi8::<0>(slo, mlh),
                _mm256_gf2p8affine_epi64_epi8::<0>(shi, mhh),
            );
            let dp = dst.as_mut_ptr().add(c * 64) as *mut __m256i;
            let d0 = _mm256_loadu_si256(dp);
            let d1 = _mm256_loadu_si256(dp.add(1));
            _mm256_storeu_si256(dp, _mm256_xor_si256(d0, _mm256_unpacklo_epi8(plo, phi)));
            _mm256_storeu_si256(
                dp.add(1),
                _mm256_xor_si256(d1, _mm256_unpackhi_epi8(plo, phi)),
            );
        }
    }
    chunks * 64
}
