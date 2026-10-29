//! BLAKE2sp's eight leaves in the eight 32-bit lanes of ONE ymm register,
//! on x86-64 with AVX2, and with AVX-512VL's rotates where the CPU has them.
//!
//! The observation is the parent module's: a whole 512-byte group gives
//! every leaf one block at the same counter and none of them its last, so
//! the eight compressions differ only in state and message and the round is
//! the scalar round with every word eight wide. A zmm would hold sixteen
//! lanes, and BLAKE2sp has eight leaves, so 512 bits is not a form here;
//! what AVX-512VL adds at ymm width is a one-instruction rotate (`vprord`)
//! where AVX2 spends three for the rotates by 12 and 7 (two shifts and an
//! OR) and a `vpshufb` for 16 and 8, and a three-way XOR (`vpternlogd`) for
//! folding the working words back into the state. The AVX2 form is kept as
//! the same-width control and as the arm for a CPU without AVX-512.
//!
//! The message enters by an 8x8 dword transpose of each half block (eight
//! leaves' 32 bytes): sixteen loads, thirty-two unpacks and sixteen
//! 128-bit permutes per group, against ten rounds of eight `g`s.
//!
//! Only whole groups come here. Every leaf's final block and the root go
//! through the parent's scalar `compress`, where the per-leaf flags are
//! cheap.
//!
//! **The unsafe code, counted (the terms of 28 Sep 2026:
//! a per-function `#[allow(unsafe_code)]` with a written
//! SAFETY argument beside each, intrinsics on registers and caller-bounded
//! slices only, run-time detection guarding every call, the crate's deny
//! kept everywhere else and no module-scope allow, the differential
//! against the replaced path permanent).** Two `unsafe fn`s exist to carry
//! their `#[target_feature]` lists (`absorb_avx2`, `absorb_avx512`), and
//! [`absorb`] is the ONE safe caller, guarded by the run-time detection of
//! every feature each lists; the `#[inline(always)]` helpers and the
//! rotate methods run only inlined into those two, which is the
//! precondition each of their SAFETY notes states. The instructions are
//! present: [`form`] answers a form only after `is_x86_feature_detected!`
//! found each of its features. The memory is in bounds: every load reads 32
//! bytes at `group + 64 * leaf + 32 * half` for a `leaf` below 8 inside one
//! whole group of `groups`, whose length the caller holds to whole groups;
//! the state loads and stores read and write the caller's `[[[u32; 8]; 4];
//! 2]`, which is 64 words, as eight rows of eight. The crate stays
//! `#![deny(unsafe_code)]` everywhere else.

use std::arch::x86_64::*;

use super::{BLOCK, GROUP, IV, LANES, SIGMA};

/// The forms this module can run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Form {
    /// Eight lanes of one ymm, AVX2 rotates. Detection never picks it
    /// until a count says it beats the control's kernel, so without the knob
    /// nothing constructs it.
    #[cfg_attr(not(feature = "x86-wide-knob"), allow(dead_code))]
    Avx2,
    /// Eight lanes of one ymm, AVX-512VL rotates and three-way XOR.
    Avx512,
}

#[cfg_attr(not(feature = "x86-wide-knob"), allow(dead_code))]
fn avx2_supported() -> bool {
    is_x86_feature_detected!("avx2")
}

fn avx512_supported() -> bool {
    is_x86_feature_detected!("avx2")
        && is_x86_feature_detected!("avx512f")
        && is_x86_feature_detected!("avx512vl")
}

/// The form detection picks: the AVX-512VL form where the CPU has it, and
/// otherwise NONE, so that a CPU with only AVX2 keeps the control's kernel
/// (`blake2s_simd`) until a count says the AVX2 form here beats it.
fn detect() -> Option<Form> {
    if avx512_supported() {
        Some(Form::Avx512)
    } else {
        None
    }
}

/// The form to run, or `None` for the control's kernel: the knob's, where the
/// feature is on and `RARKIT_X86_B2SP` names a form the CPU has; the
/// detected one otherwise.
#[cfg(feature = "x86-wide-knob")]
pub(crate) fn form() -> Option<Form> {
    use std::sync::OnceLock;
    static FORM: OnceLock<Option<Form>> = OnceLock::new();
    *FORM.get_or_init(|| {
        let asked = std::env::var("RARKIT_X86_B2SP").unwrap_or_default();
        match asked.as_str() {
            "crate" => None,
            "avx2" if avx2_supported() => Some(Form::Avx2),
            "avx512" if avx512_supported() => Some(Form::Avx512),
            _ => detect(),
        }
    })
}

/// See the knob arm above.
#[cfg(not(feature = "x86-wide-knob"))]
pub(crate) fn form() -> Option<Form> {
    detect()
}

#[allow(unsafe_code)]
/// Advance all eight leaves through every whole group of `groups` from
/// `counter`, the bytes every leaf has compressed before this call.
///
/// The ONE safe caller of the kernels.
pub(crate) fn absorb(form: Form, halves: &mut [[[u32; 8]; LANES]; 2], groups: &[u8], counter: u64) {
    debug_assert!(groups.len().is_multiple_of(GROUP));
    // SAFETY: each kernel is unsafe to call only because its target
    // features must be present; `form` came from [`form`], which answers
    // `Avx2` only after `avx2_supported` found AVX2 and `Avx512` only after
    // `avx512_supported` found AVX2, AVX-512F and AVX-512VL, by run-time
    // detection. `groups` and `halves` are passed through unchanged and the
    // kernel bounds its reads and writes by their lengths.
    unsafe {
        match form {
            Form::Avx2 => absorb_avx2(halves, groups, counter),
            Form::Avx512 => absorb_avx512(halves, groups, counter),
        }
    }
}

/// The rotates and the three-way XOR, in the two instruction sets.
trait Rot {
    unsafe fn ror16(x: __m256i) -> __m256i;
    unsafe fn ror12(x: __m256i) -> __m256i;
    unsafe fn ror8(x: __m256i) -> __m256i;
    unsafe fn ror7(x: __m256i) -> __m256i;
    unsafe fn xor3(a: __m256i, b: __m256i, c: __m256i) -> __m256i;
}

struct Avx2Rot;
struct Avx512Rot;

/// The byte permutations `ror16` and `ror8` are on a little-endian `u32`,
/// one 128-bit half of the table shown; `vpshufb` permutes within each
/// 128-bit lane, so the same 16 bytes serve both halves.
const ROR16: [i8; 32] = [
    2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14,
    15, 12, 13,
];
const ROR8: [i8; 32] = [
    1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12, 1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13,
    14, 15, 12,
];

impl Rot for Avx2Rot {
    #[allow(unsafe_code)]
    #[inline(always)]
    unsafe fn ror16(x: __m256i) -> __m256i {
        // SAFETY: AVX2, enabled by the caller's target feature; the table
        // load reads the module's own 32-byte constant.
        unsafe { _mm256_shuffle_epi8(x, _mm256_loadu_si256(ROR16.as_ptr().cast::<__m256i>())) }
    }
    #[allow(unsafe_code)]
    #[inline(always)]
    unsafe fn ror12(x: __m256i) -> __m256i {
        // SAFETY: as above.
        unsafe { _mm256_or_si256(_mm256_srli_epi32::<12>(x), _mm256_slli_epi32::<20>(x)) }
    }
    #[allow(unsafe_code)]
    #[inline(always)]
    unsafe fn ror8(x: __m256i) -> __m256i {
        // SAFETY: as above.
        unsafe { _mm256_shuffle_epi8(x, _mm256_loadu_si256(ROR8.as_ptr().cast::<__m256i>())) }
    }
    #[allow(unsafe_code)]
    #[inline(always)]
    unsafe fn ror7(x: __m256i) -> __m256i {
        // SAFETY: as above.
        unsafe { _mm256_or_si256(_mm256_srli_epi32::<7>(x), _mm256_slli_epi32::<25>(x)) }
    }
    #[allow(unsafe_code)]
    #[inline(always)]
    unsafe fn xor3(a: __m256i, b: __m256i, c: __m256i) -> __m256i {
        // SAFETY: as above.
        unsafe { _mm256_xor_si256(_mm256_xor_si256(a, b), c) }
    }
}

impl Rot for Avx512Rot {
    #[allow(unsafe_code)]
    #[inline(always)]
    unsafe fn ror16(x: __m256i) -> __m256i {
        // SAFETY: AVX-512F and AVX-512VL, enabled by the caller's target
        // feature.
        unsafe { _mm256_ror_epi32::<16>(x) }
    }
    #[allow(unsafe_code)]
    #[inline(always)]
    unsafe fn ror12(x: __m256i) -> __m256i {
        // SAFETY: as above.
        unsafe { _mm256_ror_epi32::<12>(x) }
    }
    #[allow(unsafe_code)]
    #[inline(always)]
    unsafe fn ror8(x: __m256i) -> __m256i {
        // SAFETY: as above.
        unsafe { _mm256_ror_epi32::<8>(x) }
    }
    #[allow(unsafe_code)]
    #[inline(always)]
    unsafe fn ror7(x: __m256i) -> __m256i {
        // SAFETY: as above.
        unsafe { _mm256_ror_epi32::<7>(x) }
    }
    #[allow(unsafe_code)]
    #[inline(always)]
    unsafe fn xor3(a: __m256i, b: __m256i, c: __m256i) -> __m256i {
        // SAFETY: as above; 0x96 is the three-way XOR.
        unsafe { _mm256_ternarylogic_epi32::<0x96>(a, b, c) }
    }
}

#[allow(unsafe_code)]
/// One `g` (RFC 7693 section 3.1) on eight lanes.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
unsafe fn g<R: Rot>(
    v: &mut [__m256i; 16],
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    x: __m256i,
    y: __m256i,
) {
    // SAFETY: AVX2 at least, enabled by the caller's target feature; every
    // index the callers pass is inside `v`.
    unsafe {
        v[a] = _mm256_add_epi32(_mm256_add_epi32(v[a], v[b]), x);
        v[d] = R::ror16(_mm256_xor_si256(v[d], v[a]));
        v[c] = _mm256_add_epi32(v[c], v[d]);
        v[b] = R::ror12(_mm256_xor_si256(v[b], v[c]));
        v[a] = _mm256_add_epi32(_mm256_add_epi32(v[a], v[b]), y);
        v[d] = R::ror8(_mm256_xor_si256(v[d], v[a]));
        v[c] = _mm256_add_epi32(v[c], v[d]);
        v[b] = R::ror7(_mm256_xor_si256(v[b], v[c]));
    }
}

#[allow(unsafe_code)]
/// Eight rows of eight dwords, transposed: `out[i]` lane `l` is `rows[l]`
/// lane `i`.
#[inline(always)]
unsafe fn transpose(rows: [__m256i; 8]) -> [__m256i; 8] {
    // SAFETY: AVX2, enabled by the caller's target feature; registers only.
    unsafe {
        let t0 = _mm256_unpacklo_epi32(rows[0], rows[1]);
        let t1 = _mm256_unpackhi_epi32(rows[0], rows[1]);
        let t2 = _mm256_unpacklo_epi32(rows[2], rows[3]);
        let t3 = _mm256_unpackhi_epi32(rows[2], rows[3]);
        let t4 = _mm256_unpacklo_epi32(rows[4], rows[5]);
        let t5 = _mm256_unpackhi_epi32(rows[4], rows[5]);
        let t6 = _mm256_unpacklo_epi32(rows[6], rows[7]);
        let t7 = _mm256_unpackhi_epi32(rows[6], rows[7]);
        let u0 = _mm256_unpacklo_epi64(t0, t2);
        let u1 = _mm256_unpackhi_epi64(t0, t2);
        let u2 = _mm256_unpacklo_epi64(t1, t3);
        let u3 = _mm256_unpackhi_epi64(t1, t3);
        let u4 = _mm256_unpacklo_epi64(t4, t6);
        let u5 = _mm256_unpackhi_epi64(t4, t6);
        let u6 = _mm256_unpacklo_epi64(t5, t7);
        let u7 = _mm256_unpackhi_epi64(t5, t7);
        [
            _mm256_permute2x128_si256::<0x20>(u0, u4),
            _mm256_permute2x128_si256::<0x20>(u1, u5),
            _mm256_permute2x128_si256::<0x20>(u2, u6),
            _mm256_permute2x128_si256::<0x20>(u3, u7),
            _mm256_permute2x128_si256::<0x31>(u0, u4),
            _mm256_permute2x128_si256::<0x31>(u1, u5),
            _mm256_permute2x128_si256::<0x31>(u2, u6),
            _mm256_permute2x128_si256::<0x31>(u3, u7),
        ]
    }
}

#[allow(unsafe_code)]
/// Eight 32-byte rows at `base + stride * l`, transposed.
#[inline(always)]
unsafe fn gather(base: *const u8, stride: usize) -> [__m256i; 8] {
    // SAFETY: AVX2; the caller holds `base + stride * 7 + 32` inside its
    // buffer.
    unsafe {
        let row = |l: usize| _mm256_loadu_si256(base.add(stride * l).cast::<__m256i>());
        transpose([
            row(0),
            row(1),
            row(2),
            row(3),
            row(4),
            row(5),
            row(6),
            row(7),
        ])
    }
}

#[allow(unsafe_code)]
/// The body both kernels share, inlined into each under its own features.
#[inline(always)]
unsafe fn absorb_body<R: Rot>(halves: &mut [[[u32; 8]; LANES]; 2], groups: &[u8], counter: u64) {
    // SAFETY: AVX2 at least, enabled by the caller's target feature.
    // `halves` is 64 words read and written as eight rows of eight at
    // `states + 32 * l`; every group load is inside one whole group, and
    // `as_chunks` yields only whole groups.
    unsafe {
        let states = halves.as_mut_ptr().cast::<u8>();
        let mut h = gather(states, 32);
        let mut counter = counter;
        let iv: [__m256i; 8] = std::array::from_fn(|i| _mm256_set1_epi32(IV[i] as i32));
        let (whole, _) = groups.as_chunks::<GROUP>();
        for group in whole {
            counter += BLOCK as u64;
            let low = gather(group.as_ptr(), BLOCK);
            let high = gather(group.as_ptr().add(32), BLOCK);
            let m: [__m256i; 16] =
                std::array::from_fn(|i| if i < 8 { low[i] } else { high[i - 8] });
            let mut v: [__m256i; 16] =
                std::array::from_fn(|i| if i < 8 { h[i] } else { iv[i - 8] });
            // Every lane is at the same counter and none is at its last
            // block, so the two flag words stay as they were.
            v[12] = _mm256_xor_si256(v[12], _mm256_set1_epi32(counter as i32));
            v[13] = _mm256_xor_si256(v[13], _mm256_set1_epi32((counter >> 32) as i32));
            macro_rules! round {
                ($r:expr) => {{
                    const S: [usize; 16] = SIGMA[$r];
                    g::<R>(&mut v, 0, 4, 8, 12, m[S[0]], m[S[1]]);
                    g::<R>(&mut v, 1, 5, 9, 13, m[S[2]], m[S[3]]);
                    g::<R>(&mut v, 2, 6, 10, 14, m[S[4]], m[S[5]]);
                    g::<R>(&mut v, 3, 7, 11, 15, m[S[6]], m[S[7]]);
                    g::<R>(&mut v, 0, 5, 10, 15, m[S[8]], m[S[9]]);
                    g::<R>(&mut v, 1, 6, 11, 12, m[S[10]], m[S[11]]);
                    g::<R>(&mut v, 2, 7, 8, 13, m[S[12]], m[S[13]]);
                    g::<R>(&mut v, 3, 4, 9, 14, m[S[14]], m[S[15]]);
                }};
            }
            round!(0);
            round!(1);
            round!(2);
            round!(3);
            round!(4);
            round!(5);
            round!(6);
            round!(7);
            round!(8);
            round!(9);
            for i in 0..8 {
                h[i] = R::xor3(h[i], v[i], v[i + 8]);
            }
        }
        let rows = transpose(h);
        for (l, row) in rows.iter().enumerate() {
            _mm256_storeu_si256(states.add(32 * l).cast::<__m256i>(), *row);
        }
    }
}

#[allow(unsafe_code)]
/// SAFETY (for callers): AVX2 must be present; `groups` whole groups.
#[target_feature(enable = "avx2")]
unsafe fn absorb_avx2(halves: &mut [[[u32; 8]; LANES]; 2], groups: &[u8], counter: u64) {
    // SAFETY: the body's precondition is this function's.
    unsafe { absorb_body::<Avx2Rot>(halves, groups, counter) }
}

#[allow(unsafe_code)]
/// SAFETY (for callers): AVX2, AVX-512F and AVX-512VL must be present;
/// `groups` whole groups.
#[target_feature(enable = "avx2,avx512f,avx512vl")]
unsafe fn absorb_avx512(halves: &mut [[[u32; 8]; LANES]; 2], groups: &[u8], counter: u64) {
    // SAFETY: the body's precondition is this function's.
    unsafe { absorb_body::<Avx512Rot>(halves, groups, counter) }
}

#[cfg(test)]
mod tests {
    use super::super::{compress, initial, BLOCK, GROUP, LANES};
    use super::*;

    /// The scalar form of exactly what the kernel does: leaf `l` takes
    /// block `l` of every group, at the running counter, no flags.
    fn scalar(halves: &mut [[[u32; 8]; LANES]; 2], groups: &[u8], counter: u64) {
        let mut counter = counter;
        for group in groups.as_chunks::<GROUP>().0 {
            counter += BLOCK as u64;
            for leaf in 0..8 {
                let block: &[u8; BLOCK] = group[leaf * BLOCK..(leaf + 1) * BLOCK]
                    .try_into()
                    .expect("one block");
                compress(
                    &mut halves[leaf / LANES][leaf % LANES],
                    block,
                    counter,
                    false,
                    false,
                );
            }
        }
    }

    fn forms() -> Vec<Form> {
        let mut forms = Vec::new();
        if avx2_supported() {
            forms.push(Form::Avx2);
        }
        if avx512_supported() {
            forms.push(Form::Avx512);
        }
        if forms.is_empty() {
            eprintln!("no AVX2 on this CPU: the lane kernels were not run");
        }
        forms
    }

    #[test]
    fn every_form_matches_the_scalar_compression() {
        let mut rng = rarkit_testdata::Seeded::new(0x0123_4567_89AB_CDEF);
        let mut data = vec![0u8; 64 * GROUP];
        for byte in data.iter_mut() {
            *byte = rng.next_u64() as u8;
        }
        for form in forms() {
            for trial in 0..40 {
                let groups = (trial % 9) + 1;
                let counter = if trial % 3 == 0 {
                    0
                } else {
                    (rng.next_u64() >> 20) & !(BLOCK as u64 - 1)
                };
                let start = ((rng.next_u64() as usize) % 8) * GROUP;
                let input = &data[start..start + groups * GROUP];
                let mut want: [[[u32; 8]; LANES]; 2] = std::array::from_fn(|half| {
                    std::array::from_fn(|lane| {
                        let mut h = initial((half * LANES + lane) as u64, 0);
                        for word in h.iter_mut() {
                            *word ^= rng.next_u64() as u32;
                        }
                        h
                    })
                });
                let mut got = want;
                scalar(&mut want, input, counter);
                absorb(form, &mut got, input, counter);
                assert_eq!(got, want, "{form:?} groups {groups} counter {counter}");
            }
        }
    }

    #[test]
    fn a_form_is_a_stream_across_any_group_split() {
        let mut rng = rarkit_testdata::Seeded::new(0x5F69_CA1F_018D_9BFF);
        let mut data = vec![0u8; 40 * GROUP];
        for byte in data.iter_mut() {
            *byte = rng.next_u64() as u8;
        }
        for form in forms() {
            let fresh: [[[u32; 8]; LANES]; 2] = std::array::from_fn(|half| {
                std::array::from_fn(|lane| initial((half * LANES + lane) as u64, 0))
            });
            let mut whole = fresh;
            absorb(form, &mut whole, &data, 0);
            for cut in [1usize, 7, 20, 39] {
                let mut split = fresh;
                absorb(form, &mut split, &data[..cut * GROUP], 0);
                absorb(form, &mut split, &data[cut * GROUP..], (cut * BLOCK) as u64);
                assert_eq!(split, whole, "{form:?} cut {cut}");
            }
        }
    }
}
