//! Carried from the predecessor's `crc32/pmull.rs` at an earlier revision: items ours from birth
//! per the provenance census (and clean-room outputs, clean by provenance).
//!
//! The four kernel items below (`update`, `update_aarch64`, `fold`, `chain`)
//! were left out of the first carry port for one reason, that they carry an
//! `unsafe` block and no package specification named this module yet. They
//! are CARRY at the fork tip on the provenance method: zero donor
//! lines each, and no item of the same name anywhere at the fork point.
//! Specification L's erratum of 18 Sep 2026 names this module and
//! permits `unsafe` inside it, which is why the crate-wide `deny` is lifted
//! here and nowhere else.
//!
//! The method is the fold of Gopal et al., "Fast CRC computation for generic
//! polynomials using PCLMULQDQ instruction" (Intel, 2009), in the bit
//! reflected form: `LANES` independent 128-bit accumulators move `16 * LANES`
//! bytes forward per pass with two carry-less multiplies by a constant and
//! one three-way XOR, so nothing waits on anything but the load. What is
//! left when the loop ends is a message of `16 * LANES` bytes whose CRC from
//! a zero register equals the running one, so the CRC32 instructions finish
//! it and the tail.
//!
//! Only where EOR3 (the SHA3 extension) is present as well as PMULL and the
//! CRC32 instructions: that is every Apple core and the ARMv8.2+ server
//! cores. On an older core with PMULL but no SHA3 the CRC32 instructions
//! were the faster choice, so such a CPU, and every other architecture,
//! keeps `crc32fast`.
#![allow(unsafe_code)]

/// Below this many bytes a plain `crc32d` chain; the fold's setup and its
/// closing pass over the lanes cost more than they save.
#[cfg(target_arch = "aarch64")]
pub(crate) const FOLD4_MIN_BYTES: usize = 256;
/// From here eight lanes; between the two, four.
#[cfg(target_arch = "aarch64")]
pub(crate) const FOLD8_MIN_BYTES: usize = 1024;
/// `[reflect(x^(D+32) mod P) << 1, reflect(x^(D-32) mod P) << 1]` for a fold
/// of `D` = 512 and 1024 bits.
///
/// Off aarch64 the `test` arm of the cfg still compiles them and no
/// kernel is built to read them, so they are dead there and live here.
#[cfg(any(target_arch = "aarch64", test))]
#[allow(dead_code)]
pub(crate) const K_512: [u64; 2] = [0x1_5444_2bd4, 0x1_c6e4_1596];
#[cfg(any(target_arch = "aarch64", test))]
#[allow(dead_code)]
pub(crate) const K_1024: [u64; 2] = [0x1_e88e_f372, 0x1_4a7f_e880];
#[cfg(target_arch = "aarch64")]
pub(crate) fn supported() -> bool {
    std::arch::is_aarch64_feature_detected!("pmull")
        && std::arch::is_aarch64_feature_detected!("crc")
        && std::arch::is_aarch64_feature_detected!("sha3")
}

/// The raw (pre-inverted) register after `input`, or `None` where this CPU
/// has no kernel here and the caller should use crc32fast.
#[inline]
pub(crate) fn update(register: u32, input: &[u8]) -> Option<u32> {
    #[cfg(target_arch = "aarch64")]
    if supported() {
        // SAFETY: `update_aarch64` is unsafe to call only because its target
        // features must be present on the CPU; `supported` established PMULL,
        // CRC32 and SHA3 immediately above by runtime detection.
        return Some(unsafe { update_aarch64(register, input) });
    }
    let _ = (register, input);
    None
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon,aes,crc,sha3")]
unsafe fn update_aarch64(register: u32, input: &[u8]) -> u32 {
    // SAFETY: the callees are unsafe to call only for their target features,
    // which are the ones enabled on this function, so the caller's detect
    // (`supported`, in `update`) covers them; `input` is passed through
    // unchanged and each callee bounds its own reads by its length.
    unsafe {
        if input.len() >= FOLD8_MIN_BYTES {
            fold::<8>(register, input, K_1024)
        } else if input.len() >= FOLD4_MIN_BYTES {
            fold::<4>(register, input, K_512)
        } else {
            chain(register, input)
        }
    }
}

/// The fold over `LANES` lanes with the constants for `16 * LANES * 8` bits.
/// Any length is correct; one shorter than a whole pass goes to [`chain`].
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon,aes,crc,sha3")]
unsafe fn fold<const LANES: usize>(register: u32, input: &[u8], keys: [u64; 2]) -> u32 {
    use std::arch::aarch64::*;
    let step = 16 * LANES;
    if input.len() < step {
        // SAFETY: `chain` is unsafe to call only for the CRC32 feature, which
        // is enabled on this function and was detected by `supported`.
        return unsafe { chain(register, input) };
    }
    let src = input.as_ptr();
    // SAFETY: the NEON, PMULL, CRC32 and SHA3 intrinsics below are unsafe to
    // call only for their target features, which are enabled on this function
    // and were detected by `supported` in `update`. Every load reads the 16
    // bytes at `at + 16 * lane` for a `lane` below LANES and an `at` with
    // `at + step <= input.len()` (the entry above rejects a shorter `input`,
    // and the loop advances `at` only while a whole `step` remains), so each
    // read stays inside `input`.
    unsafe {
        let load = |at: usize| vreinterpretq_u64_u8(vld1q_u8(src.add(at)));
        let high_key =
            vreinterpretq_p64_u64(vcombine_u64(vcreate_u64(keys[0]), vcreate_u64(keys[1])));
        let mut lanes = [vdupq_n_u64(0); LANES];
        for (lane, value) in lanes.iter_mut().enumerate() {
            *value = load(16 * lane);
        }
        // The register joins the stream as the XOR of its first four bytes.
        lanes[0] = veorq_u64(
            lanes[0],
            vcombine_u64(vcreate_u64(u64::from(register)), vcreate_u64(0)),
        );
        let mut at = step;
        while input.len() - at >= step {
            for (lane, value) in lanes.iter_mut().enumerate() {
                let low = vreinterpretq_u64_p128(vmull_p64(vgetq_lane_u64(*value, 0), keys[0]));
                let high =
                    vreinterpretq_u64_p128(vmull_high_p64(vreinterpretq_p64_u64(*value), high_key));
                *value = veor3q_u64(low, high, load(at + 16 * lane));
            }
            at += step;
        }
        // The lanes, read in order, are a message congruent to everything
        // folded so far: its CRC from a zero register is the running one.
        let mut folded = 0;
        for value in lanes {
            folded = __crc32d(folded, vgetq_lane_u64(value, 0));
            folded = __crc32d(folded, vgetq_lane_u64(value, 1));
        }
        chain(folded, &input[at..])
    }
}

/// One `crc32d` per eight bytes, then `crc32b` per byte.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "crc")]
unsafe fn chain(mut register: u32, input: &[u8]) -> u32 {
    use std::arch::aarch64::{__crc32b, __crc32d};
    // SAFETY (the whole body, which an edition 2021 `unsafe fn` makes one
    // unsafe block): `__crc32d` and `__crc32b` are unsafe to call only for
    // the CRC32 feature, which is enabled on this function and was detected
    // by `supported` in `update`. Neither reads memory: the bytes come from
    // safe iteration over `input`.
    let mut words = input.chunks_exact(8);
    for word in &mut words {
        let word = u64::from_le_bytes(word.try_into().expect("an eight-byte chunk"));
        register = __crc32d(register, word);
    }
    for &byte in words.remainder() {
        register = __crc32b(register, byte);
    }
    register
}
