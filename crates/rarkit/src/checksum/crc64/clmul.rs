//! The CRC-64 register (spec L 3.2, both forms) by carry-less multiply:
//! PMULL on aarch64, PCLMULQDQ on x86-64, and VPCLMULQDQ at 256 or 512
//! bits where the CPU has it. The slice-by-8 table in the parent module is
//! the definition these are held to, bit for bit, and what every other CPU
//! and every short input runs.
//!
//! Why: the recovery record's per-slice CRC-64 is what a `-rr` create
//! pays for (1.5 to 2.4 GB/s a core through the table, against 10 to 16
//! GB/s for the Galois fold beside it), and what repair pays for after the
//! copy. The table does one byte per lookup; a multiply folds sixteen.
//!
//! The mathematics, derived here rather than recalled. The register is
//! reflected: bit `i` of a 64-bit word is the coefficient of `x^(63 - i)`,
//! and the first byte of the message is the highest degree. A 16-byte
//! block loaded little-endian is then a 128-bit value whose low word `A`
//! (the first eight bytes) sits above its high word `B`: the block is
//! `A x^64 + B`. Moving it `D` bits later in the message multiplies it by
//! `x^D`, and modulo `P` that is
//!
//! ```text
//!     A (x^(D+64) mod P)  +  B (x^D mod P)
//! ```
//!
//! each a 64 by 64 bit product and so at most 127 bits: a block again. A
//! carry-less multiply of two reflected words lands its product one bit
//! short of the reflected 128-bit position (bit `n` of the product is the
//! coefficient of `x^(126 - n)`, where a reflected block wants
//! `x^(127 - n)`), which is taken up by using `x^(D+63)` and `x^(D-1)` in
//! place of `x^(D+64)` and `x^D`. So a fold by `D` bits is two multiplies
//! by the constant pair [`keys`] gives and an XOR into the block `D` bits
//! on, and nothing waits on anything but the load.
//!
//! The register joins as the XOR of its eight bytes into the first eight
//! of the message (which is what the table's update does with it too).
//! When the wide loop ends, every lane is folded onto the last one by its
//! own distance, then whole blocks left over are folded in one at a time,
//! and the final block and the under-16-byte tail are finished through the
//! table from a zero register: the block is a message of 16 bytes
//! congruent to everything folded so far.
//!
//! `unsafe`: the crate denies it, and this module lifts the deny for its
//! intrinsics alone. Every block's safety comment names its precondition:
//! the CPU features, established by runtime detection in [`kernel`], and
//! load bounds, held by the length checks in each fold.
#![allow(unsafe_code)]

// The constants and the table are the kernels' alone: on an architecture
// with neither kernel they are compiled only for the key test.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64", test))]
use super::update_table;

/// Below this many bytes the table alone. A fold's setup and its closing
/// reduction cost about a hundred bytes of table time.
pub(super) const FOLD_MIN_BYTES: usize = 256;

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64", test))]
/// ECMA-182 in normal form, `x^64` implied.
const POLY_NORMAL: u64 = super::POLY.reverse_bits();

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64", test))]
/// `x^n mod P`, normal form.
const fn x_pow_mod(n: u32) -> u64 {
    let mut r = 1u64;
    let mut i = 0;
    while i < n {
        let top = r >> 63;
        r <<= 1;
        if top != 0 {
            r ^= POLY_NORMAL;
        }
        i += 1;
    }
    r
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64", test))]
/// The pair folding the low and high word of a block `blocks` blocks (of
/// 128 bits) further on, reflected: `[x^(D+63) mod P, x^(D-1) mod P]` for
/// `D = 128 blocks`.
const fn keys(blocks: u32) -> [u64; 2] {
    let d = 128 * blocks;
    [
        x_pow_mod(d + 63).reverse_bits(),
        x_pow_mod(d - 1).reverse_bits(),
    ]
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64", test))]
/// The widest distance any kernel folds across, in blocks: eight 512-bit
/// lanes.
const MAX_BLOCKS: usize = 32;

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64", test))]
/// `KEYS[n]` folds a block `n` blocks further on; `KEYS[0]` is unused.
static KEYS: [[u64; 2]; MAX_BLOCKS + 1] = {
    let mut t = [[0u64; 2]; MAX_BLOCKS + 1];
    let mut n = 1;
    while n <= MAX_BLOCKS {
        t[n] = keys(n as u32);
        n += 1;
    }
    t
};

/// A kernel: the register after `input`, which must be at least
/// [`FOLD_MIN_BYTES`] long.
pub(super) type Kernel = fn(u64, &[u8]) -> u64;

/// The widest kernel this CPU runs, or `None` for the table.
#[inline]
pub(super) fn kernel() -> Option<Kernel> {
    #[cfg(target_arch = "aarch64")]
    if arm::supported() {
        return Some(arm::update);
    }
    #[cfg(target_arch = "x86_64")]
    {
        if x86::supported_512() {
            return Some(x86::update_512);
        }
        if x86::supported_256() {
            return Some(x86::update_256);
        }
        if x86::supported_128() {
            return Some(x86::update_128);
        }
    }
    None
}

/// Every kernel this CPU runs, narrowest first, each with its name, so a
/// differential test holds every one of them to the table and not only
/// the one [`kernel`] picks.
#[cfg(test)]
pub(super) fn kernels() -> Vec<(&'static str, Kernel)> {
    #[allow(unused_mut)]
    let mut all: Vec<(&'static str, Kernel)> = Vec::new();
    #[cfg(target_arch = "aarch64")]
    if arm::supported() {
        all.push(("pmull", arm::update));
    }
    #[cfg(target_arch = "x86_64")]
    {
        if x86::supported_128() {
            all.push(("pclmulqdq", x86::update_128));
        }
        if x86::supported_256() {
            all.push(("vpclmulqdq-256", x86::update_256));
        }
        if x86::supported_512() {
            all.push(("vpclmulqdq-512", x86::update_512));
        }
    }
    all
}

#[cfg(target_arch = "aarch64")]
mod arm {
    use super::{update_table, FOLD_MIN_BYTES, KEYS};
    use std::arch::aarch64::*;

    /// Eight 128-bit lanes: 128 bytes a pass.
    const LANES: usize = 8;
    const STEP: usize = 16 * LANES;

    pub(super) fn supported() -> bool {
        std::arch::is_aarch64_feature_detected!("pmull")
    }

    pub(super) fn update(register: u64, input: &[u8]) -> u64 {
        assert!(input.len() >= FOLD_MIN_BYTES && FOLD_MIN_BYTES >= STEP);
        // SAFETY: `fold` is unsafe to call only for its target features;
        // this function is reached only through `kernel` or `kernels`,
        // each of which returns it after `supported` detected PMULL
        // (NEON is baseline on aarch64). Its length precondition is the
        // assertion above.
        unsafe { fold(register, input) }
    }

    /// `v.lo * k[0] ^ v.hi * k[1] ^ next`: `v` moved on by `k`'s distance.
    #[inline]
    #[target_feature(enable = "neon,aes")]
    fn step(v: uint64x2_t, k: [u64; 2], next: uint64x2_t) -> uint64x2_t {
        let low = vreinterpretq_u64_p128(vmull_p64(vgetq_lane_u64::<0>(v), k[0]));
        let high = vreinterpretq_u64_p128(vmull_p64(vgetq_lane_u64::<1>(v), k[1]));
        veorq_u64(veorq_u64(low, high), next)
    }

    #[target_feature(enable = "neon,aes")]
    unsafe fn fold(register: u64, input: &[u8]) -> u64 {
        let src = input.as_ptr();
        // SAFETY: every `load(at)` below reads the 16 bytes at `at`, and
        // each `at` is checked against `input.len()` before it is read:
        // the first pass needs `STEP <= input.len()`, which the caller
        // asserted; the wide loop advances only while a whole `STEP`
        // remains, and the block loop only while a whole block remains.
        let load = |at: usize| unsafe { vreinterpretq_u64_u8(vld1q_u8(src.add(at))) };
        let mut lanes = [vdupq_n_u64(0); LANES];
        for (lane, value) in lanes.iter_mut().enumerate() {
            *value = load(16 * lane);
        }
        lanes[0] = veorq_u64(
            lanes[0],
            vcombine_u64(vcreate_u64(register), vcreate_u64(0)),
        );
        let mut at = STEP;
        while input.len() - at >= STEP {
            for (lane, value) in lanes.iter_mut().enumerate() {
                *value = step(*value, KEYS[LANES], load(at + 16 * lane));
            }
            at += STEP;
        }
        let mut acc = lanes[LANES - 1];
        for (lane, value) in lanes[..LANES - 1].iter().enumerate() {
            acc = step(*value, KEYS[LANES - 1 - lane], acc);
        }
        while input.len() - at >= 16 {
            acc = step(acc, KEYS[1], load(at));
            at += 16;
        }
        let mut block = [0u8; 16];
        // SAFETY: `block` is 16 writable bytes.
        unsafe { vst1q_u8(block.as_mut_ptr(), vreinterpretq_u8_u64(acc)) };
        update_table(update_table(0, &block), &input[at..])
    }
}

#[cfg(target_arch = "x86_64")]
mod x86 {
    use super::{update_table, FOLD_MIN_BYTES, KEYS};
    use std::arch::x86_64::*;

    pub(super) fn supported_128() -> bool {
        std::arch::is_x86_feature_detected!("pclmulqdq")
            && std::arch::is_x86_feature_detected!("sse2")
    }

    pub(super) fn supported_256() -> bool {
        supported_128()
            && std::arch::is_x86_feature_detected!("avx2")
            && std::arch::is_x86_feature_detected!("vpclmulqdq")
    }

    pub(super) fn supported_512() -> bool {
        supported_128()
            && std::arch::is_x86_feature_detected!("avx512f")
            && std::arch::is_x86_feature_detected!("vpclmulqdq")
    }

    /// Eight lanes at every width: 128, 256 or 512 bytes a pass.
    const LANES: usize = 8;

    pub(super) fn update_128(register: u64, input: &[u8]) -> u64 {
        assert!(input.len() >= FOLD_MIN_BYTES);
        // SAFETY: reached only through `kernel` or `kernels`, which return
        // it after `supported_128` detected PCLMULQDQ and SSE2, the
        // features `fold_128` enables. The length it needs is asserted
        // above (`fold_128` itself stands aside below one whole pass).
        unsafe { fold_128(register, input) }
    }

    pub(super) fn update_256(register: u64, input: &[u8]) -> u64 {
        assert!(input.len() >= FOLD_MIN_BYTES);
        // SAFETY: as `update_128`, after `supported_256` detected AVX2,
        // VPCLMULQDQ and the 128-bit kernel's features.
        unsafe { fold_256(register, input) }
    }

    pub(super) fn update_512(register: u64, input: &[u8]) -> u64 {
        assert!(input.len() >= FOLD_MIN_BYTES);
        // SAFETY: as `update_128`, after `supported_512` detected
        // AVX-512F, VPCLMULQDQ and the 128-bit kernel's features.
        unsafe { fold_512(register, input) }
    }

    /// A key pair as one block: `k[0]` low, `k[1]` high.
    #[inline]
    #[target_feature(enable = "sse2")]
    fn key128(k: [u64; 2]) -> __m128i {
        _mm_set_epi64x(k[1] as i64, k[0] as i64)
    }

    #[inline]
    #[target_feature(enable = "sse2,pclmulqdq")]
    fn step128(v: __m128i, k: __m128i, next: __m128i) -> __m128i {
        let low = _mm_clmulepi64_si128::<0x00>(v, k);
        let high = _mm_clmulepi64_si128::<0x11>(v, k);
        _mm_xor_si128(_mm_xor_si128(low, high), next)
    }

    /// Fold `blocks` (whole 16-byte blocks, in message order) onto the
    /// last, then fold on every whole block of `rest`, then finish through
    /// the table. `blocks` is the wide loop's lanes stored out.
    #[target_feature(enable = "sse2,pclmulqdq")]
    unsafe fn finish(blocks: &[u8], rest: &[u8]) -> u64 {
        let n = blocks.len() / 16;
        // SAFETY: every load below reads 16 bytes at `16 i` of `blocks`
        // for an `i < n`, or at `16 i` of `rest` for a whole block of it.
        let load = |bytes: &[u8], i: usize| unsafe {
            _mm_loadu_si128(bytes.as_ptr().add(16 * i).cast::<__m128i>())
        };
        let mut acc = load(blocks, n - 1);
        for i in 0..n - 1 {
            acc = step128(load(blocks, i), key128(KEYS[n - 1 - i]), acc);
        }
        let whole = rest.len() / 16;
        let one = key128(KEYS[1]);
        for i in 0..whole {
            acc = step128(acc, one, load(rest, i));
        }
        let mut block = [0u8; 16];
        // SAFETY: `block` is 16 writable bytes.
        unsafe { _mm_storeu_si128(block.as_mut_ptr().cast::<__m128i>(), acc) };
        update_table(update_table(0, &block), &rest[16 * whole..])
    }

    #[target_feature(enable = "sse2,pclmulqdq")]
    unsafe fn fold_128(register: u64, input: &[u8]) -> u64 {
        const STEP: usize = 16 * LANES;
        if input.len() < STEP {
            return update_table(register, input);
        }
        let src = input.as_ptr();
        // SAFETY: each `load(at)` reads 16 bytes at `at` with
        // `at + STEP <= input.len()` for the first pass (checked above)
        // and for every later one (the loop's own condition).
        let load = |at: usize| unsafe { _mm_loadu_si128(src.add(at).cast::<__m128i>()) };
        let mut lanes = [_mm_setzero_si128(); LANES];
        for (lane, value) in lanes.iter_mut().enumerate() {
            *value = load(16 * lane);
        }
        lanes[0] = _mm_xor_si128(lanes[0], _mm_set_epi64x(0, register as i64));
        let k = key128(KEYS[LANES]);
        let mut at = STEP;
        while input.len() - at >= STEP {
            for (lane, value) in lanes.iter_mut().enumerate() {
                *value = step128(*value, k, load(at + 16 * lane));
            }
            at += STEP;
        }
        let mut blocks = [0u8; STEP];
        for (lane, value) in lanes.iter().enumerate() {
            // SAFETY: lane `lane` is stored to bytes `16 lane .. 16 lane
            // + 16` of `blocks`, inside its `STEP` bytes.
            unsafe {
                _mm_storeu_si128(blocks.as_mut_ptr().add(16 * lane).cast::<__m128i>(), *value)
            };
        }
        // SAFETY: `finish` needs the features this function enables.
        unsafe { finish(&blocks, &input[at..]) }
    }

    #[target_feature(enable = "sse2,pclmulqdq,avx2,vpclmulqdq")]
    unsafe fn fold_256(register: u64, input: &[u8]) -> u64 {
        const STEP: usize = 32 * LANES;
        if input.len() < STEP {
            // SAFETY: the narrower kernel's features are a subset of
            // this function's.
            return unsafe { fold_128(register, input) };
        }
        let src = input.as_ptr();
        // SAFETY: each `load(at)` reads 32 bytes at `at` with
        // `at + STEP <= input.len()`, as in `fold_128`.
        let load = |at: usize| unsafe { _mm256_loadu_si256(src.add(at).cast::<__m256i>()) };
        let mut lanes = [_mm256_setzero_si256(); LANES];
        for (lane, value) in lanes.iter_mut().enumerate() {
            *value = load(32 * lane);
        }
        lanes[0] = _mm256_xor_si256(lanes[0], _mm256_set_epi64x(0, 0, 0, register as i64));
        // Each 256-bit lane is two blocks, and each moves on by the whole
        // pass: 2 LANES blocks.
        let [k0, k1] = KEYS[2 * LANES];
        let k = _mm256_set_epi64x(k1 as i64, k0 as i64, k1 as i64, k0 as i64);
        let mut at = STEP;
        while input.len() - at >= STEP {
            for (lane, value) in lanes.iter_mut().enumerate() {
                let low = _mm256_clmulepi64_epi128::<0x00>(*value, k);
                let high = _mm256_clmulepi64_epi128::<0x11>(*value, k);
                *value = _mm256_xor_si256(_mm256_xor_si256(low, high), load(at + 32 * lane));
            }
            at += STEP;
        }
        let mut blocks = [0u8; STEP];
        for (lane, value) in lanes.iter().enumerate() {
            // SAFETY: lane `lane` is stored to bytes `32 lane .. 32 lane
            // + 32` of `blocks`, inside its `STEP` bytes.
            unsafe {
                _mm256_storeu_si256(blocks.as_mut_ptr().add(32 * lane).cast::<__m256i>(), *value)
            };
        }
        // SAFETY: `finish` needs a subset of this function's features.
        unsafe { finish(&blocks, &input[at..]) }
    }

    #[target_feature(enable = "sse2,pclmulqdq,avx512f,vpclmulqdq")]
    unsafe fn fold_512(register: u64, input: &[u8]) -> u64 {
        const STEP: usize = 64 * LANES;
        if input.len() < STEP {
            // SAFETY: the narrower kernel's features are a subset of
            // this function's.
            return unsafe { fold_128(register, input) };
        }
        let src = input.as_ptr();
        // SAFETY: each `load(at)` reads 64 bytes at `at` with
        // `at + STEP <= input.len()`, as in `fold_128`.
        let load = |at: usize| unsafe { _mm512_loadu_si512(src.add(at).cast::<__m512i>()) };
        let mut lanes = [_mm512_setzero_si512(); LANES];
        for (lane, value) in lanes.iter_mut().enumerate() {
            *value = load(64 * lane);
        }
        lanes[0] = _mm512_xor_si512(
            lanes[0],
            _mm512_set_epi64(0, 0, 0, 0, 0, 0, 0, register as i64),
        );
        // Each 512-bit lane is four blocks: 4 LANES blocks a pass.
        let [k0, k1] = KEYS[4 * LANES];
        let (k0, k1) = (k0 as i64, k1 as i64);
        let k = _mm512_set_epi64(k1, k0, k1, k0, k1, k0, k1, k0);
        let mut at = STEP;
        while input.len() - at >= STEP {
            for (lane, value) in lanes.iter_mut().enumerate() {
                let low = _mm512_clmulepi64_epi128::<0x00>(*value, k);
                let high = _mm512_clmulepi64_epi128::<0x11>(*value, k);
                // 0x96 is the three-way XOR's truth table.
                *value = _mm512_ternarylogic_epi64::<0x96>(low, high, load(at + 64 * lane));
            }
            at += STEP;
        }
        let mut blocks = [0u8; STEP];
        for (lane, value) in lanes.iter().enumerate() {
            // SAFETY: lane `lane` is stored to bytes `64 lane .. 64 lane
            // + 64` of `blocks`, inside its `STEP` bytes.
            unsafe {
                _mm512_storeu_si512(blocks.as_mut_ptr().add(64 * lane).cast::<__m512i>(), *value)
            };
        }
        // SAFETY: `finish` needs a subset of this function's features.
        unsafe { finish(&blocks, &input[at..]) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fold by one block, done bit by bit through the table: moving a
    /// block 128 bits on is, for the register, the same as feeding it and
    /// then sixteen zero bytes - so the keys are checked against the
    /// definition rather than trusted.
    #[test]
    fn keys_fold_a_block_as_the_table_does() {
        let block: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(37) ^ 0x5a);
        let lo = u64::from_le_bytes(block[..8].try_into().unwrap());
        let hi = u64::from_le_bytes(block[8..].try_into().unwrap());
        for (blocks, &[k0, k1]) in KEYS.iter().enumerate().skip(1) {
            let product = clmul(lo, k0) ^ clmul(hi, k1);
            let mut folded = [0u8; 16];
            folded.copy_from_slice(&product.to_le_bytes());
            let mut moved = block.to_vec();
            moved.resize(16 * (blocks + 1), 0);
            let mut expect = vec![0u8; 16 * blocks];
            expect.extend_from_slice(&folded);
            assert_eq!(
                update_table(0, &moved),
                update_table(0, &expect),
                "{blocks}"
            );
        }
    }

    /// Software carry-less multiply of two 64-bit words.
    fn clmul(a: u64, b: u64) -> u128 {
        let mut out = 0u128;
        for bit in 0..64 {
            if (b >> bit) & 1 != 0 {
                out ^= u128::from(a) << bit;
            }
        }
        out
    }
}
