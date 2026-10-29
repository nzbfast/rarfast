//! The RAR 5 PBKDF2 loop through the ARMv8 SHA-256 instructions, with every
//! value the loop carries held in vector registers (24 Sep 2026).
//!
//! **Why this exists.** After U_1, an iteration of the derivation is two
//! SHA-256 compressions of one block each under a fixed keyed state (spec K
//! 3.7.1, RFC 2104 and RFC 8018 section 5.2), and through `sha2`'s block
//! function each is a call that loads the state and the block from memory,
//! byte-swaps the block and stores the state back: about 101 instructions
//! and 31 cycles an iteration of 364 and 270 on aarch64
//! (counted 24 Sep 2026 at the hmac and sha2 call boundary).
//! Here the two keyed states, U and V stay in registers for a whole run.
//!
//! **Why no byte is swapped.** The block each compression sees is a 32-byte
//! message after the 64-byte keyed pad: U (for the inner hash) or the
//! inner hash S (for the outer), then the constant padding of a 96-byte
//! message. SHA-256 reads its block as big-endian words and writes its hash
//! as the big-endian bytes of its state words, so the first eight message
//! words ARE the previous compression's state words, and the last eight are
//! constants: `0x8000_0000`, six zeros, and 768, the length in bits.
//!
//! **The instructions.** FIPS 180-4 section 6.2.2 four rounds at a time:
//! SHA256H and SHA256H2 advance the ABCD and EFGH halves of the working
//! state over four words plus round constants, and SHA256SU0 and SHA256SU1
//! extend the message schedule four words at a time. [`run`] is the one
//! function listing `#[target_feature(enable = "sha2")]`; the parent's
//! dispatch argues the one call into it.

use core::arch::aarch64::{
    uint32x4_t, vaddq_u32, vcombine_u32, vcreate_u32, veorq_u32, vgetq_lane_u32, vsha256h2q_u32,
    vsha256hq_u32, vsha256su0q_u32, vsha256su1q_u32,
};

use super::rar5::SHA256_K;

/// Whether this machine has the ARMv8 SHA-256 instructions.
pub(super) fn available() -> bool {
    std::arch::is_aarch64_feature_detected!("sha2")
}

/// Advance the chain `count` iterations: U = PRF(U), V ^= U each, the PRF
/// being HMAC-SHA256 under the keyed states `inner` and `outer` (the state
/// after the key's inner and outer pad blocks).
///
/// Every input enters by [`quad`] and every output leaves by lane
/// extracts; no pointer is formed and no load or store intrinsic is used.
#[target_feature(enable = "sha2")]
pub(super) fn run(
    inner: &[u32; 8],
    outer: &[u32; 8],
    u: &mut [u32; 8],
    v: &mut [u32; 8],
    count: u32,
) {
    let (i0, i1) = (quad(&inner[..4]), quad(&inner[4..]));
    let (o0, o1) = (quad(&outer[..4]), quad(&outer[4..]));
    let (mut u0, mut u1) = (quad(&u[..4]), quad(&u[4..]));
    let (mut v0, mut v1) = (quad(&v[..4]), quad(&v[4..]));
    let pad0 = quad(&[0x8000_0000, 0, 0, 0]);
    let pad1 = quad(&[0, 0, 0, 768]);
    for _ in 0..count {
        let (s0, s1) = compress(i0, i1, [u0, u1, pad0, pad1]);
        (u0, u1) = compress(o0, o1, [s0, s1, pad0, pad1]);
        v0 = veorq_u32(v0, u0);
        v1 = veorq_u32(v1, u1);
    }
    unquad(u0, &mut u[..4]);
    unquad(u1, &mut u[4..]);
    unquad(v0, &mut v[..4]);
    unquad(v1, &mut v[4..]);
}

/// One SHA-256 compression of the block `w` (sixteen words, four to a
/// register, word 0 in lane 0) from the state `abcd`, `efgh`.
///
/// Written out quad by quad: a loop over the sixteen quads with the
/// schedule in an array indexed by `q % 4` was NOT unrolled by the
/// compiler, which kept the schedule on the stack and rebuilt each round
/// constant from two scalar loads, 884 instructions an iteration against
/// the floor's 261 (the first count).
#[inline]
#[target_feature(enable = "sha2")]
fn compress(abcd: uint32x4_t, efgh: uint32x4_t, w: [uint32x4_t; 4]) -> (uint32x4_t, uint32x4_t) {
    let (mut x, mut y) = (abcd, efgh);
    let [mut w0, mut w1, mut w2, mut w3] = w;
    // Four rounds on the words `$w` with the round constants from `$k`.
    macro_rules! rounds {
        ($w:expr, $k:expr) => {{
            let wk = vaddq_u32($w, quad(&SHA256_K[$k..$k + 4]));
            let x0 = x;
            x = vsha256hq_u32(x, y, wk);
            y = vsha256h2q_u32(y, x0, wk);
        }};
    }
    // The next four schedule words in place of `$a`, the oldest four.
    macro_rules! extend {
        ($a:ident, $b:ident, $c:ident, $d:ident) => {
            $a = vsha256su1q_u32(vsha256su0q_u32($a, $b), $c, $d);
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
    (vaddq_u32(x, abcd), vaddq_u32(y, efgh))
}

/// Four words into a register, word 0 in lane 0.
#[inline]
#[target_feature(enable = "sha2")]
fn quad(w: &[u32]) -> uint32x4_t {
    let lo = u64::from(w[0]) | (u64::from(w[1]) << 32);
    let hi = u64::from(w[2]) | (u64::from(w[3]) << 32);
    vcombine_u32(vcreate_u32(lo), vcreate_u32(hi))
}

/// A register's four lanes into four words, lane 0 first.
#[inline]
#[target_feature(enable = "sha2")]
fn unquad(x: uint32x4_t, w: &mut [u32]) {
    w[0] = vgetq_lane_u32::<0>(x);
    w[1] = vgetq_lane_u32::<1>(x);
    w[2] = vgetq_lane_u32::<2>(x);
    w[3] = vgetq_lane_u32::<3>(x);
}
