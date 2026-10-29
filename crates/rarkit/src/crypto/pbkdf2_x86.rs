//! The RAR 5 PBKDF2 loop through the x86 SHA extensions, with every value
//! the loop carries held in vector registers (24 Sep 2026).
//!
//! The aarch64 module, `pbkdf2_armv8`, says why this exists and why no
//! byte is swapped: the first eight message words of each compression are
//! the previous compression's state words, and the last eight are the
//! constant padding of a 96-byte message.
//!
//! **The layout.** SHA256RNDS2 does two rounds of FIPS 180-4 section 6.2.2
//! on the working state split as ABEF and CDGH (lanes 3 to 0: A, B, E, F
//! and C, D, G, H), with the two words plus round constants in the low
//! half of its third operand; SHA256MSG1 and SHA256MSG2 with one PALIGNR
//! extend the message schedule four words at a time. The keyed states, U
//! and V are held in the ABEF / CDGH layout for the whole run, and a
//! compression's output is put in message order (word 0 in lane 0) by
//! [`words`]: two 64-bit unpacks and two 32-bit shuffles.
//!
//! [`run`] is the one function listing the target features; the parent's
//! dispatch argues the one call into it.

use core::arch::x86_64::{
    __m128i, _mm_add_epi32, _mm_alignr_epi8, _mm_extract_epi32, _mm_set_epi32,
    _mm_sha256msg1_epu32, _mm_sha256msg2_epu32, _mm_sha256rnds2_epu32, _mm_shuffle_epi32,
    _mm_unpackhi_epi64, _mm_unpacklo_epi64, _mm_xor_si128,
};

use super::rar5::SHA256_K;

/// Whether this machine has every extension [`run`] lists.
pub(super) fn available() -> bool {
    std::arch::is_x86_feature_detected!("sha")
        && std::arch::is_x86_feature_detected!("sse2")
        && std::arch::is_x86_feature_detected!("ssse3")
        && std::arch::is_x86_feature_detected!("sse4.1")
}

/// Advance the chain `count` iterations: U = PRF(U), V ^= U each, the PRF
/// being HMAC-SHA256 under the keyed states `inner` and `outer` (the state
/// after the key's inner and outer pad blocks).
///
/// Every input enters by `_mm_set_epi32` and every output leaves by lane
/// extracts; no pointer is formed and no load or store intrinsic is used.
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
pub(super) fn run(
    inner: &[u32; 8],
    outer: &[u32; 8],
    u: &mut [u32; 8],
    v: &mut [u32; 8],
    count: u32,
) {
    let (i_abef, i_cdgh) = split(inner);
    let (o_abef, o_cdgh) = split(outer);
    let (mut u_abef, mut u_cdgh) = split(u);
    let (mut v_abef, mut v_cdgh) = split(v);
    let pad0 = _mm_set_epi32(0, 0, 0, 0x8000_0000_u32 as i32);
    let pad1 = _mm_set_epi32(768, 0, 0, 0);
    for _ in 0..count {
        let (m0, m1) = words(u_abef, u_cdgh);
        let (s_abef, s_cdgh) = compress(i_abef, i_cdgh, [m0, m1, pad0, pad1]);
        let (m0, m1) = words(s_abef, s_cdgh);
        (u_abef, u_cdgh) = compress(o_abef, o_cdgh, [m0, m1, pad0, pad1]);
        v_abef = _mm_xor_si128(v_abef, u_abef);
        v_cdgh = _mm_xor_si128(v_cdgh, u_cdgh);
    }
    join(u_abef, u_cdgh, u);
    join(v_abef, v_cdgh, v);
}

/// One SHA-256 compression of the block `w` (sixteen words, four to a
/// register, word 0 in lane 0) from the state `abef`, `cdgh`.
///
/// Written out quad by quad, as `pbkdf2_armv8`'s is: a loop over the
/// sixteen quads with the schedule in an array was not unrolled there.
#[inline]
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
fn compress(abef: __m128i, cdgh: __m128i, w: [__m128i; 4]) -> (__m128i, __m128i) {
    let (mut x, mut y) = (abef, cdgh);
    let [mut w0, mut w1, mut w2, mut w3] = w;
    // Four rounds on the words `$w` with the round constants from `$k`.
    macro_rules! rounds {
        ($w:expr, $k:expr) => {{
            let k = &SHA256_K[$k..$k + 4];
            let wk = _mm_add_epi32($w, set4(k[0], k[1], k[2], k[3]));
            y = _mm_sha256rnds2_epu32(y, x, wk);
            x = _mm_sha256rnds2_epu32(x, y, _mm_shuffle_epi32::<0x0E>(wk));
        }};
    }
    // The next four schedule words in place of `$a`, the oldest four.
    macro_rules! extend {
        ($a:ident, $b:ident, $c:ident, $d:ident) => {
            $a = _mm_sha256msg2_epu32(
                _mm_add_epi32(_mm_sha256msg1_epu32($a, $b), _mm_alignr_epi8::<4>($d, $c)),
                $d,
            );
        };
    }
    // Sixteen rounds from constant `$k`, extending the schedule.
    macro_rules! sixteen {
        ($k:expr) => {
            rounds!(w0, $k);
            extend!(w0, w1, w2, w3);
            rounds!(w1, $k + 4);
            extend!(w1, w2, w3, w0);
            rounds!(w2, $k + 8);
            extend!(w2, w3, w0, w1);
            rounds!(w3, $k + 12);
            extend!(w3, w0, w1, w2);
        };
    }
    sixteen!(0);
    sixteen!(16);
    sixteen!(32);
    rounds!(w0, 48);
    rounds!(w1, 52);
    rounds!(w2, 56);
    rounds!(w3, 60);
    (_mm_add_epi32(x, abef), _mm_add_epi32(y, cdgh))
}

/// Four words into a register, `a` in lane 0.
#[inline]
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
fn set4(a: u32, b: u32, c: u32, d: u32) -> __m128i {
    _mm_set_epi32(d as i32, c as i32, b as i32, a as i32)
}

/// A state's eight words (A to H) into ABEF and CDGH.
#[inline]
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
fn split(s: &[u32; 8]) -> (__m128i, __m128i) {
    (set4(s[5], s[4], s[1], s[0]), set4(s[7], s[6], s[3], s[2]))
}

/// ABEF and CDGH into a state's eight words.
#[inline]
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
fn join(abef: __m128i, cdgh: __m128i, s: &mut [u32; 8]) {
    let (m0, m1) = words(abef, cdgh);
    for (k, x) in [m0, m1].into_iter().enumerate() {
        s[4 * k] = _mm_extract_epi32::<0>(x) as u32;
        s[4 * k + 1] = _mm_extract_epi32::<1>(x) as u32;
        s[4 * k + 2] = _mm_extract_epi32::<2>(x) as u32;
        s[4 * k + 3] = _mm_extract_epi32::<3>(x) as u32;
    }
}

/// ABEF and CDGH in message order: (A, B, C, D) and (E, F, G, H), the first
/// word in lane 0.
#[inline]
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
fn words(abef: __m128i, cdgh: __m128i) -> (__m128i, __m128i) {
    // unpackhi: lanes (B, A, D, C); unpacklo: (F, E, H, G); 0xB1 swaps
    // each pair of lanes.
    (
        _mm_shuffle_epi32::<0xB1>(_mm_unpackhi_epi64(abef, cdgh)),
        _mm_shuffle_epi32::<0xB1>(_mm_unpacklo_epi64(abef, cdgh)),
    )
}
