//! The x86-64 forms of the RAR 1.3 member checksum (spec F 3.4.3).
//!
//! The block form in the parent module was built on aarch64, which has no
//! 16-bit rotate, so the definition's add-and-rotate chain costs about
//! three cycles a byte there. x86-64 rotates sixteen bits in one
//! instruction, the chain is about two cycles a byte, and the block form's
//! hundred scalar instructions per eight bytes read about four: slower than
//! the definition it replaced (measured on x86-64, 23 Sep
//! 2026). This module holds the forms x86-64 is offered instead:
//!
//! - [`serial`], the definition's own loop;
//! - [`lanes`], sixteen bytes a step in 16-bit lanes, four lanes to a
//!   `u64` (SWAR), in plain integer arithmetic with no `core::arch`;
//! - `sse2`, the same sixteen lanes as `lanes`, eight to an SSE2
//!   register (x86-64 only; `dispatch` argues the one call
//!   into it, the crate's one exemption from its own lint on unchecked
//!   code);
//! - `avx2`, two blocks a step in one AVX2 register (the second
//!   call `dispatch` argues, taken only when runtime detection finds AVX2,
//!   the SSE2 form running otherwise).
//!
//! [`update`] picks one: `avx2` by default, which is the `sse2`
//! form wherever the processor has no AVX2. On a small x86-64 VPS (Zen 4, 23 Sep
//! 2026) `serial` first ran the
//! `f/extract-rar13-big80k-vsnull` round at 1.324x the block form's speed
//! by cycles, and `lanes` at 1.217x; in a second run `sse2` ran it at
//! 1.079x `serial`'s speed by cycles; in a third `avx2` ran it at 1.037x
//! `sse2`'s, each interval wholly above 1.00x, the `f/test-rar15-txt4MiB`
//! control unmoved each time. `RARKIT_SUM16_FORM` (`avx2`, `sse2`,
//! `serial`, `lanes` or `block`) overrides the default for a measuring
//! run, so the forms can be priced against each other inside one
//! binary.
//!
//! # Why the lane form is exact
//!
//! Work modulo `M = 65535`. A 16-bit rotate left by `k` is multiplication
//! by `2^k` modulo `M` for EVERY 16-bit value, 65,535 included (it rotates
//! to itself, and it is 0 modulo `M`). The one operation of the definition
//! that is not arithmetic modulo `M` is the add, when it wraps: a wrap
//! takes away 65,536, which is 1 modulo `M`. Call step `k` CLEAN when
//! `s_k + b_k <= 65534`: then it does not wrap, the rotate's input is not
//! 65,535, and the state after it lies in `0..=65534`, so it EQUALS its
//! residue. Over a run of clean steps
//!
//! ```text
//! s_k = 2^k * s_0 + Q_k   (mod M),   Q_k = SUM over j < k of 2^(k-j) * b_j
//! ```
//!
//! and `Q_k` depends on the data alone. A state below `0xFF00` makes the
//! next step clean, a byte being at most 255.
//!
//! **The lane test.** Given lanes `0..k` clean, lane `k` takes any 16-bit
//! representatives `a` of `2^k * s_0` and `q` of `Q_k` and forms
//! `r = a + q` wrapping in sixteen bits. If `a + q < 65535`, `s_k = r`. If
//! `a + q = 65535`, `s_k = 0`. If `a + q >= 65536`, `s_k = r + 1`, or 0
//! when `r = 65534`. So `s_k >= 0xFF00` forces `r >= 0xFEFF` in every
//! case, and a lane ALARMS when `r >= 0xFEFF`: it never misses, and its
//! only false alarms are `r = 0xFEFF` without a carry and the two
//! representatives of zero. That holds for ANY representatives. The ones
//! built here are narrower, `q` being the exact `Q_k`, never above 64,770,
//! so a carried sum lands on a state of at most 64,770 and the tighter
//! `r >= 0xFF00` would be exact too; the looser bound is kept because it
//! does not lean on that, and costs one false alarm in 65,536 lanes.
//!
//! An alarm costs nothing but speed: the block is run through the
//! definition's own loop, which is exact whatever the state. A block with
//! no alarm is clean in all sixteen steps, and its outgoing state is
//! `s_0 + Q_16` modulo `M` (`2^16` is 1), reduced to `0..=65535` and then
//! 65,535 read as 0, because a clean step cannot produce 65,535.
//!
//! **The lanes.** Each 8-byte half computes `z_k = SUM over j <= k of
//! 2^(k-j) * b_j` as a doubling scan ([`half`] says how). It is exact in
//! sixteen bits (`z_7 <= 255 * 255`), and `Q_k = z_k - b_k`. The second
//! half starts from `s_8 = 2^8 * s_0 + 2 * z_7`, and the block's
//! `Q_16 = 2^9 * z_7 + 2 * z'_7`, `z'_7` being the second half's.
//!
//! **The SSE2 form** computes the same integers in every lane, packed
//! eight to a register: its pairs, scan, data terms, state rotations and
//! alarm are the `lanes` form's, lane for lane, so the argument above is
//! its argument too. Its notes say where the packing differs.
//!
//! **The AVX2 form** runs the SSE2 form's lanes for two consecutive
//! blocks, the second block's incoming state being the first's outgoing
//! one computed on the assumption that the first is clean. That
//! assumption is tested by the first block's own lanes: if they alarm, the
//! second block's answer is discarded unread and the step restarts sixteen
//! bytes on, after the definition's loop has run the first block. If only
//! the second alarms, the first's outgoing state is exact and the second
//! runs the definition's loop from it.

#[cfg(target_arch = "x86_64")]
use std::sync::OnceLock;

/// The environment variable that overrides the form for a run.
#[cfg(target_arch = "x86_64")]
pub(super) const FORM_ENV: &str = "RARKIT_SUM16_FORM";

/// Which form [`update`] runs.
#[cfg(target_arch = "x86_64")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Form {
    /// Sixteen bytes a step in lanes.
    Lanes,
    /// The definition's own loop.
    Serial,
    /// The parent module's 8-byte block form, as aarch64 runs it.
    Block,
    /// Sixteen bytes a step in SSE2 lanes: the default where
    /// the processor has no AVX2.
    Sse2,
    /// Two 16-byte blocks a step in one AVX2 register, where
    /// the processor has AVX2, and `Sse2` where it does not: the
    /// default.
    Avx2,
}

/// The form this process runs, read once.
#[cfg(target_arch = "x86_64")]
pub(super) fn form() -> Form {
    static FORM: OnceLock<Form> = OnceLock::new();
    *FORM.get_or_init(|| match crate::knob::reader_var(FORM_ENV).as_deref() {
        Ok("lanes") => Form::Lanes,
        Ok("block") => Form::Block,
        Ok("serial") => Form::Serial,
        Ok("sse2") => Form::Sse2,
        _ => Form::Avx2,
    })
}

/// Whether this processor has AVX2. The standard library's detection
/// asks the processor once and caches the answer, so this is a load and
/// a test after the first call. A test may hide AVX2 on its own thread,
/// to run the fall-back on a machine that has it; nothing can make this
/// answer yes where the processor says no.
#[cfg(target_arch = "x86_64")]
fn avx2_present() -> bool {
    #[cfg(test)]
    if HIDE_AVX2.with(std::cell::Cell::get) {
        return false;
    }
    std::arch::is_x86_feature_detected!("avx2")
}

#[cfg(all(test, target_arch = "x86_64"))]
thread_local! {
    /// Set by a test to run [`dispatch`] as though the processor had no
    /// AVX2.
    static HIDE_AVX2: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Feed `data` to a checksum standing at `state`, in this process's form.
#[cfg(target_arch = "x86_64")]
pub(super) fn update(state: u16, data: &[u8]) -> u16 {
    dispatch(form(), state, data)
}

/// Feed `data` to a checksum standing at `state`, in `form`.
///
/// The crate denies unchecked code, and this function alone is excused
/// (decided 23 Sep 2026), for the two calls below. On rustc
/// 1.98.0 an SSE2 or AVX2 intrinsic is a safe call only inside a function
/// that itself lists the feature in `#[target_feature]`, however the build
/// is configured, and a call into such a function from one that does not
/// list it is error E0133 outside an unchecked block.
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
pub(super) fn dispatch(form: Form, state: u16, data: &[u8]) -> u16 {
    match form {
        Form::Lanes => lanes(state, data),
        Form::Serial => serial(state, data),
        Form::Block => super::block_form(state, data),
        // SAFETY: the one obligation `avx2` carries is that the CPU has
        // AVX2, and this arm is taken only when `avx2_present` has just
        // answered yes: the standard library's runtime detection, which
        // asks the processor (and the operating system, for the saved
        // register state), and which nothing in this crate can make answer
        // yes on a processor without AVX2. Where it answers no, the arm
        // below runs the SSE2 form instead. `avx2` takes no raw pointer
        // and calls no load or store intrinsic: its bytes enter by
        // `u64::from_le_bytes` and `_mm256_set_epi64x`, and every other
        // intrinsic it calls works on registers alone.
        Form::Avx2 if avx2_present() => unsafe { avx2(state, data) },
        // SAFETY: the one obligation `sse2` carries is that the CPU has
        // SSE2. It is part of the x86-64 baseline ABI: every x86-64
        // processor has it, and every Rust target for this architecture
        // enables it, so it is present wherever this line was compiled
        // and no runtime detection is needed or done. `sse2` takes no raw
        // pointer and calls no load or store intrinsic: its bytes enter
        // by `u64::from_le_bytes` and `_mm_set_epi64x`, and every other
        // intrinsic it calls works on registers alone.
        Form::Sse2 | Form::Avx2 => unsafe { sse2(state, data) },
    }
}

/// The definition's own loop.
pub(super) fn serial(mut state: u16, data: &[u8]) -> u16 {
    for byte in data {
        state = super::step(state, *byte);
    }
    state
}

/// Sixteen bytes a step; the tail, and any block that alarms, by the
/// definition.
pub(super) fn lanes(mut state: u16, data: &[u8]) -> u16 {
    let (blocks, tail) = data.as_chunks::<16>();
    for block in blocks {
        state = match block16(state, block) {
            Some(next) => next,
            None => serial(state, block),
        };
    }
    serial(state, tail)
}

/// Sixteen bytes a step in SSE2, eight 16-bit lanes to a register; the
/// tail, and any block that alarms, by the definition.
///
/// The lanes are the `lanes` form's, packed differently. The block's
/// sixteen bytes are ONE register read as eight u16 lanes, lane `i`
/// holding bytes `2i` and `2i+1`, so lanes 0 to 3 are the first 8-byte
/// half's pairs and lanes 4 to 7 the second's. The pair scan runs across
/// all eight lanes with every shifted term MASKED where it would cross from
/// lane 3 into lane 4, which keeps the halves apart. The sixteen states
/// are then two registers, the even-numbered steps and the odd, each
/// holding four lanes of the first half (rotations of `s_0`) and four of
/// the second (rotations of `s_8`).
///
/// A rotate of `x` left by `k` is `pmullw | pmulhuw` of `x` by `2^k`: the
/// low sixteen bits of the product are `x << k`, the high sixteen are
/// `x >> (16 - k)`, and for `k = 0` the high half is 0.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
fn sse2(mut state: u16, data: &[u8]) -> u16 {
    use core::arch::x86_64::{
        __m128i, _mm_add_epi16, _mm_and_si128, _mm_cmpeq_epi16, _mm_extract_epi16,
        _mm_movemask_epi8, _mm_mulhi_epu16, _mm_mullo_epi16, _mm_or_si128, _mm_set1_epi16,
        _mm_set_epi16, _mm_set_epi64x, _mm_setzero_si128, _mm_slli_epi16, _mm_slli_si128,
        _mm_srli_epi16, _mm_sub_epi16, _mm_subs_epu16,
    };
    // `_mm_set_epi16` names its lanes from 7 down to 0.
    let low_byte = _mm_set1_epi16(0x00FF);
    // A term shifted up one lane must not reach lane 4 (nor lane 0, where
    // the shift brings in zero anyway).
    let keep_one = _mm_set_epi16(-1, -1, -1, 0, -1, -1, -1, 0);
    // A term shifted up two lanes must not reach lanes 4 and 5.
    let keep_two = _mm_set_epi16(-1, -1, 0, 0, -1, -1, 0, 0);
    // 2^k for the even steps `2i` of each half, lane by lane. Opaque to
    // the optimiser on purpose: seeing a constant, LLVM rewrites
    // `pmulhuw` by powers of two as per-lane right shifts, which SSE2
    // does not have, and spells them in about twenty shuffles and shifts
    // where the multiply is one instruction. Read once per call.
    let even_powers = core::hint::black_box(_mm_set_epi16(64, 16, 4, 1, 64, 16, 4, 1));
    // Saturating subtraction of 0xFEFE leaves a lane nonzero exactly when
    // it is at least 0xFEFF: the alarm.
    let alarm_floor = _mm_set1_epi16(0xFEFE_u16.cast_signed());
    let zero = _mm_setzero_si128();

    let (blocks, tail) = data.as_chunks::<16>();
    for block in blocks {
        let (Some(lo), Some(hi)) = (block.first_chunk::<8>(), block.last_chunk::<8>()) else {
            // Unreachable: a 16-byte block has both halves.
            state = serial(state, block);
            continue;
        };
        let bytes: __m128i = _mm_set_epi64x(
            u64::from_le_bytes(*hi).cast_signed(),
            u64::from_le_bytes(*lo).cast_signed(),
        );
        let even = _mm_and_si128(bytes, low_byte);
        let odd = _mm_srli_epi16::<8>(bytes);
        // c_i = 2 * b_2i + b_2i+1.
        let pairs = _mm_add_epi16(_mm_add_epi16(even, even), odd);
        // y_i = SUM over pairs j <= i of its half of 4^(i-j) * c_j: two
        // doubling steps, each term masked at the halves' boundary.
        let step = _mm_and_si128(_mm_slli_si128::<2>(pairs), keep_one);
        let y = _mm_add_epi16(pairs, _mm_slli_epi16::<2>(step));
        let step = _mm_and_si128(_mm_slli_si128::<4>(y), keep_two);
        // Lane i is z_(2i+1) of its half, exact in sixteen bits.
        let y = _mm_add_epi16(y, _mm_slli_epi16::<4>(step));
        // Q_(2i+1) = z_(2i+1) - b_(2i+1); Q_(2i) = 2 * z_(2i-1), 0 at each
        // half's first byte.
        let q_odd = _mm_sub_epi16(y, odd);
        let q_even = _mm_and_si128(_mm_slli_epi16::<1>(_mm_slli_si128::<2>(y)), keep_one);
        // Lanes 3 and 7 are z_7 of each half; `_mm_extract_epi16` returns
        // the lane zero-extended, so the cast keeps it whole.
        let z_lo = _mm_extract_epi16::<3>(y) as u16;
        let z_hi = _mm_extract_epi16::<7>(y) as u16;
        let s8 = add_mod(state.rotate_left(8), z_lo.rotate_left(1));
        let base = _mm_set_epi16(
            s8.cast_signed(),
            s8.cast_signed(),
            s8.cast_signed(),
            s8.cast_signed(),
            state.cast_signed(),
            state.cast_signed(),
            state.cast_signed(),
            state.cast_signed(),
        );
        let a_even = _mm_or_si128(
            _mm_mullo_epi16(base, even_powers),
            _mm_mulhi_epu16(base, even_powers),
        );
        // The odd steps' rotations are the even ones' rotated once more.
        let a_odd = _mm_or_si128(_mm_slli_epi16::<1>(a_even), _mm_srli_epi16::<15>(a_even));
        let r_even = _mm_add_epi16(a_even, q_even);
        let r_odd = _mm_add_epi16(a_odd, q_odd);
        let alarm = _mm_or_si128(
            _mm_subs_epu16(r_even, alarm_floor),
            _mm_subs_epu16(r_odd, alarm_floor),
        );
        if _mm_movemask_epi8(_mm_cmpeq_epi16(alarm, zero)) != 0xFFFF {
            #[cfg(test)]
            SSE2_ALARMS.with(|n| n.set(n.get() + 1));
            state = serial(state, block);
            continue;
        }
        let next = add_mod(state, add_mod(z_lo.rotate_left(9), z_hi.rotate_left(1)));
        // A clean step never produces 65,535: it is the representative of
        // a true 0 (see `block16`).
        state = if next == 0xFFFF { 0 } else { next };
    }
    serial(state, tail)
}

#[cfg(all(test, target_arch = "x86_64"))]
thread_local! {
    /// The blocks this thread's `sse2` sent down the definition's loop, so
    /// a test can tell a kernel that answers from one that always falls
    /// back.
    static SSE2_ALARMS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// How this thread's 32-byte steps ended in `avx2`, by [`Pair`].
    static AVX2_PAIRS: std::cell::Cell<[u64; 3]> = const { std::cell::Cell::new([0; 3]) };
}

/// How an AVX2 32-byte step ended, for the tests' counters.
#[cfg(all(test, target_arch = "x86_64"))]
#[derive(Clone, Copy)]
enum Pair {
    /// Both blocks clean: the step answered.
    Clean = 0,
    /// The first block clean and the second alarmed: the second ran the
    /// definition's loop from the first's outgoing state.
    SecondAlarmed = 1,
    /// The first block alarmed: it ran the definition's loop, and the next
    /// step started sixteen bytes on.
    FirstAlarmed = 2,
}

/// Count one 32-byte step's ending in `counter`.
#[cfg(all(test, target_arch = "x86_64"))]
fn count(counter: &'static std::thread::LocalKey<std::cell::Cell<[u64; 3]>>, how: Pair) {
    counter.with(|c| {
        let mut n = c.get();
        n[how as usize] += 1;
        c.set(n);
    });
}

/// The state after the first block of a pair, and the pair's outgoing
/// state, from the pair's incoming `state` and the four `z_7` values
/// (first block's halves, then the second's). Both are representatives
/// modulo 65,535 that are EXACT when the block they end was clean, a
/// clean step never producing 65,535 (see `block16`).
#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn pair_states(state: u16, z: [u16; 4]) -> [u16; 4] {
    let s8 = add_mod(state.rotate_left(8), z[0].rotate_left(1));
    let mid = add_mod(state, add_mod(z[0].rotate_left(9), z[1].rotate_left(1)));
    let mid = if mid == 0xFFFF { 0 } else { mid };
    let s24 = add_mod(mid.rotate_left(8), z[2].rotate_left(1));
    let next = add_mod(mid, add_mod(z[2].rotate_left(9), z[3].rotate_left(1)));
    let next = if next == 0xFFFF { 0 } else { next };
    [s8, mid, s24, next]
}

/// Two 16-byte blocks a step in one AVX2 register: lanes 0 to
/// 7 are the first block's, packed exactly as `sse2` packs a block,
/// and lanes 8 to 15 the second's. AVX2's byte shift and its 16-bit
/// arithmetic work within each 128-bit half, so the scan and its masks are
/// the SSE2 form's, twice over, and cannot cross from one block to the
/// other. The second block's states are taken from the first's outgoing
/// state, and a step that alarms is settled as the module notes say.
/// The remainder under 32 bytes goes to `sse2`, which AVX2
/// implies.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
fn avx2(mut state: u16, data: &[u8]) -> u16 {
    use core::arch::x86_64::{
        __m256i, _mm256_add_epi16, _mm256_and_si256, _mm256_blend_epi16, _mm256_cmpeq_epi16,
        _mm256_cvtepu16_epi64, _mm256_extract_epi16, _mm256_movemask_epi8, _mm256_or_si256,
        _mm256_set1_epi16, _mm256_set_epi16, _mm256_set_epi64x, _mm256_setzero_si256,
        _mm256_shufflehi_epi16, _mm256_shufflelo_epi16, _mm256_slli_epi16, _mm256_slli_si256,
        _mm256_srli_epi16, _mm256_sub_epi16, _mm256_subs_epu16, _mm_set_epi16,
    };
    let low_byte = _mm256_set1_epi16(0x00FF);
    // `_mm256_set_epi16` names its lanes from 15 down to 0; each 128-bit
    // half carries the SSE2 form's masks.
    let keep_one = _mm256_set_epi16(-1, -1, -1, 0, -1, -1, -1, 0, -1, -1, -1, 0, -1, -1, -1, 0);
    let keep_two = _mm256_set_epi16(-1, -1, 0, 0, -1, -1, 0, 0, -1, -1, 0, 0, -1, -1, 0, 0);
    let alarm_floor = _mm256_set1_epi16(0xFEFE_u16.cast_signed());
    let zero = _mm256_setzero_si256();

    let mut rest = data;
    while let Some((pair, after)) = rest.split_first_chunk::<32>() {
        let (q0, q1, q2, q3) = {
            let (a, b) = pair.split_at(16);
            let (a0, a1) = a.split_at(8);
            let (b0, b1) = b.split_at(8);
            let word = |s: &[u8]| {
                let mut w = [0u8; 8];
                w.copy_from_slice(s);
                u64::from_le_bytes(w).cast_signed()
            };
            (word(a0), word(a1), word(b0), word(b1))
        };
        let bytes: __m256i = _mm256_set_epi64x(q3, q2, q1, q0);
        let even = _mm256_and_si256(bytes, low_byte);
        let odd = _mm256_srli_epi16::<8>(bytes);
        let pairs = _mm256_add_epi16(_mm256_add_epi16(even, even), odd);
        let step = _mm256_and_si256(_mm256_slli_si256::<2>(pairs), keep_one);
        let y = _mm256_add_epi16(pairs, _mm256_slli_epi16::<2>(step));
        let step = _mm256_and_si256(_mm256_slli_si256::<4>(y), keep_two);
        let y = _mm256_add_epi16(y, _mm256_slli_epi16::<4>(step));
        let q_odd = _mm256_sub_epi16(y, odd);
        let q_even = _mm256_and_si256(_mm256_slli_epi16::<1>(_mm256_slli_si256::<2>(y)), keep_one);
        let z = [
            _mm256_extract_epi16::<3>(y) as u16,
            _mm256_extract_epi16::<7>(y) as u16,
            _mm256_extract_epi16::<11>(y) as u16,
            _mm256_extract_epi16::<15>(y) as u16,
        ];
        let [s8, mid, s24, next] = pair_states(state, z);
        // The four halves' incoming states, one to each 64-bit lane, then
        // copied across that lane's four 16-bit lanes by the shuffles'
        // lane-0 selector: lanes 0 to 3 `state`, 4 to 7 `s8`, 8 to 11
        // `mid`, 12 to 15 `s24`. (A scalar broadcast by multiplication
        // compiled to two 64-bit vector multiplies and led LLVM to widen
        // the rotation's `pmulhuw` through a pack and a permute.)
        let four = _mm_set_epi16(
            0,
            0,
            0,
            0,
            s24.cast_signed(),
            mid.cast_signed(),
            s8.cast_signed(),
            state.cast_signed(),
        );
        let base =
            _mm256_shufflehi_epi16::<0>(_mm256_shufflelo_epi16::<0>(_mm256_cvtepu16_epi64(four)));
        // The even steps' rotations, lane `i` of each four by `2i`, with
        // no multiply: rotate every lane by 4 and keep it in lanes 2 and 3
        // of each four (blend mask 0xCC), then rotate that by 2 and keep it
        // in lanes 1 and 3 (0xAA), so the four read 0, 2, 4 and 6. AVX2's
        // blend applies its mask to both 128-bit halves alike. (The SSE2
        // form multiplies by powers of two instead, having no blend; here
        // LLVM spelled that multiply's high half in nine instructions.)
        let by4 = _mm256_or_si256(_mm256_slli_epi16::<4>(base), _mm256_srli_epi16::<12>(base));
        let part = _mm256_blend_epi16::<0xCC>(base, by4);
        let by2 = _mm256_or_si256(_mm256_slli_epi16::<2>(part), _mm256_srli_epi16::<14>(part));
        let a_even = _mm256_blend_epi16::<0xAA>(part, by2);
        let a_odd = _mm256_or_si256(
            _mm256_slli_epi16::<1>(a_even),
            _mm256_srli_epi16::<15>(a_even),
        );
        let alarm = _mm256_or_si256(
            _mm256_subs_epu16(_mm256_add_epi16(a_even, q_even), alarm_floor),
            _mm256_subs_epu16(_mm256_add_epi16(a_odd, q_odd), alarm_floor),
        );
        // Bits 0 to 15 are the first block's lanes, 16 to 31 the second's.
        let clean = _mm256_movemask_epi8(_mm256_cmpeq_epi16(alarm, zero)).cast_unsigned();
        if clean == u32::MAX {
            #[cfg(test)]
            count(&AVX2_PAIRS, Pair::Clean);
            state = next;
            rest = after;
        } else if clean & 0xFFFF == 0xFFFF {
            #[cfg(test)]
            count(&AVX2_PAIRS, Pair::SecondAlarmed);
            state = serial(mid, &pair[16..]);
            rest = after;
        } else {
            #[cfg(test)]
            count(&AVX2_PAIRS, Pair::FirstAlarmed);
            state = serial(state, &pair[..16]);
            rest = &rest[16..];
        }
    }
    sse2(state, rest)
}

/// Each 16-bit lane of a word: the low byte of every lane.
const LANE_LOW_BYTE: u64 = 0x00FF_00FF_00FF_00FF;
/// Each lane's low fifteen bits.
const LANE_LOW15: u64 = 0x7FFF_7FFF_7FFF_7FFF;
/// Each lane's top bit.
const LANE_TOP: u64 = 0x8000_8000_8000_8000;

/// Four 16-bit lanes added, each wrapping on its own.
#[inline(always)]
fn lanes_add(a: u64, b: u64) -> u64 {
    ((a & LANE_LOW15) + (b & LANE_LOW15)) ^ ((a ^ b) & LANE_TOP)
}

/// The top bit of every lane at or above 0xFEFF, and nothing else: the
/// low fifteen bits plus 0x0101 reach bit 15 exactly when they are at
/// least 0x7EFF, and cannot carry out of the lane.
#[inline(always)]
fn lanes_alarm(r: u64) -> u64 {
    r & ((r & LANE_LOW15) + 0x0101_0101_0101_0101) & LANE_TOP
}

/// `x + y` modulo 65,535, as some representative in `0..=65535`.
#[inline(always)]
fn add_mod(x: u16, y: u16) -> u16 {
    let (sum, carry) = x.overflowing_add(y);
    // After a carry the sum is at most 65,534, so this cannot wrap.
    sum + u16::from(carry)
}

/// One 8-byte half, `x` holding its bytes little-endian, from a state
/// represented by `s0`. Returns whether a lane alarmed, and `z_7`.
///
/// The lanes of a `u64` are four, so the half is split into its even
/// bytes (`b_0, b_2, b_4, b_6`) and odd bytes, and the scan runs over the
/// PAIRS `c_i = 2 * b_2i + b_2i+1`: `z_2i+1 = 4 * z_2i-1 + c_i`, two
/// shifted adds. No lane ever carries into the next, because every
/// partial sum is at most its lane's final `z`, and `z_7 <= 65,025`.
#[inline(always)]
fn half(s0: u16, x: u64) -> (bool, u16) {
    let even = x & LANE_LOW_BYTE;
    let odd = (x >> 8) & LANE_LOW_BYTE;
    let c = (even << 1) + odd;
    let y = c + (c << 18);
    // Lane i is z_(2i+1).
    let y = y + (y << 36);
    // Q_(2i+1) = z_(2i+1) - b_(2i+1), and Q_(2i) = 2 * z_(2i-1), lane 0
    // being Q_0 = 0; the lane shifted out of the top is z_7, not wanted.
    let q_odd = y - odd;
    let q_even = y << 17;
    // ROL(s0, k) is bits 16-k to 31-k of s0 written twice.
    let d = u64::from(s0) * 0x0001_0001;
    let a_even = u64::from(s0)
        | ((d << 2) & 0xFFFF_0000)
        | ((d << 20) & 0xFFFF_0000_0000)
        | ((d << 38) & 0xFFFF_0000_0000_0000);
    // And the odd lanes are the even ones rotated once more.
    let a_odd = ((a_even << 1) & 0xFFFE_FFFE_FFFE_FFFE) | ((a_even >> 15) & 0x0001_0001_0001_0001);
    let alarm = lanes_alarm(lanes_add(a_even, q_even)) | lanes_alarm(lanes_add(a_odd, q_odd));
    (alarm != 0, (y >> 48) as u16)
}

/// One 16-byte block from `s0`, or `None` if a lane alarmed.
#[inline(always)]
fn block16(s0: u16, block: &[u8; 16]) -> Option<u16> {
    let (lo, hi) = block.split_at(8);
    let lo = u64::from_le_bytes(lo.try_into().ok()?);
    let hi = u64::from_le_bytes(hi.try_into().ok()?);
    let (alarm_lo, z_lo) = half(s0, lo);
    let s8 = add_mod(s0.rotate_left(8), z_lo.rotate_left(1));
    let (alarm_hi, z_hi) = half(s8, hi);
    if alarm_lo | alarm_hi {
        return None;
    }
    let data = add_mod(z_lo.rotate_left(9), z_hi.rotate_left(1));
    let next = add_mod(s0, data);
    // Unreachable, and kept as a guard: an outgoing 65,535 means a true 0,
    // which needs `s_15 = 0`, and lane 15 then reads 65,535 or 65,534 and
    // alarms, unless the whole block is zeros from a state of 0, which
    // reaches here as 0.
    Some(if next == 0xFFFF { 0 } else { next })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec F 3.4.3 exactly as written, with nothing borrowed from the
    /// forms under test.
    fn by_definition(mut state: u16, data: &[u8]) -> u16 {
        for byte in data {
            state = state.wrapping_add(u16::from(*byte)).rotate_left(1);
        }
        state
    }

    fn noise(rng: &mut rarkit_testdata::Seeded, len: usize) -> Vec<u8> {
        (0..len).map(|_| (rng.next_u64() >> 29) as u8).collect()
    }

    /// The SSE2 form, through the dispatch that production calls.
    #[cfg(target_arch = "x86_64")]
    fn sse2_form(state: u16, data: &[u8]) -> u16 {
        dispatch(Form::Sse2, state, data)
    }

    /// A form of the checksum: incoming state and bytes to outgoing state.
    type FormFn = fn(u16, &[u8]) -> u16;

    /// The AVX2 form, through the dispatch that production calls: the
    /// AVX2 kernel where the processor has AVX2, and the SSE2 form where
    /// it does not ([`the_avx2_form_runs_its_kernel_or_falls_back`] says
    /// which ran).
    #[cfg(target_arch = "x86_64")]
    fn avx2_form(state: u16, data: &[u8]) -> u16 {
        dispatch(Form::Avx2, state, data)
    }

    /// The AVX2 form with AVX2 hidden on this thread: the fall-back.
    #[cfg(target_arch = "x86_64")]
    fn avx2_hidden_form(state: u16, data: &[u8]) -> u16 {
        HIDE_AVX2.with(|h| h.set(true));
        let out = dispatch(Form::Avx2, state, data);
        HIDE_AVX2.with(|h| h.set(false));
        out
    }

    /// Every 16-byte form this target can run, by name: `lanes` always,
    /// and the SSE2 and AVX2 forms where the architecture has them
    /// (x86-64, natively or under Rosetta on an aarch64 Mac).
    fn sixteen_forms() -> Vec<(&'static str, FormFn)> {
        #[allow(unused_mut)] // only x86-64 pushes the other forms
        let mut forms: Vec<(&'static str, FormFn)> = vec![("lanes", lanes)];
        #[cfg(target_arch = "x86_64")]
        forms.extend([
            ("sse2", sse2_form as FormFn),
            ("avx2", avx2_form),
            ("avx2 hidden", avx2_hidden_form),
        ]);
        forms
    }

    /// Spec F 5.3's vectors through every x86 form.
    #[test]
    fn spec_f_5_3_through_both_forms() {
        assert_eq!(serial(0, b"123456789"), 0xC78A);
        let long = b"123456789123456789123456789123456789";
        for (name, form) in sixteen_forms() {
            assert_eq!(form(0, b"123456789"), 0xC78A, "{name}");
            assert_eq!(form(0, b""), 0x0000, "{name}");
            assert_eq!(form(0, long), by_definition(0, long), "{name}");
        }
    }

    /// Every incoming state, through one block of each of several shapes:
    /// the lane test's cases (no carry, a sum of exactly 65,535, a carry
    /// landing on 0xFEFF) are all reached from some state, and a block the
    /// test lets through must land where the definition does.
    #[test]
    fn one_block_from_every_state() {
        let mut rng = rarkit_testdata::Seeded::new(0x9E37_79B9_7F4A_7C15);
        let mut blocks: Vec<[u8; 16]> = vec![[0x00; 16], [0xFF; 16], [0x80; 16], [0x01; 16]];
        blocks.push(core::array::from_fn(|k| (k * 17) as u8));
        blocks.push(core::array::from_fn(|k| 255 - (k * 13) as u8));
        for _ in 0..4 {
            let v = noise(&mut rng, 16);
            blocks.push(core::array::from_fn(|k| v[k]));
        }
        for (name, form) in sixteen_forms() {
            for block in &blocks {
                for state in 0..=u16::MAX {
                    assert_eq!(
                        form(state, block),
                        by_definition(state, block),
                        "{name} state {state:#06x} block {block:02x?}"
                    );
                }
            }
        }
    }

    /// The edge of the alarm band: a state of exactly 0xFF00 followed by
    /// a 255, the one clean-looking step that lands on 65,535. It is set
    /// up at lane 7, whose successor starts the second half, and at lane
    /// 15, whose successor is the block's outgoing state, from every
    /// incoming state.
    #[test]
    fn a_state_of_0xff00_before_a_255() {
        let mut rng = rarkit_testdata::Seeded::new(0x5851_F42D_4C95_7F2D);
        let mut reached = 0u64;
        for _ in 0..24 {
            let v = noise(&mut rng, 16);
            let mut block: [u8; 16] = core::array::from_fn(|k| v[k]);
            block[7] = 0xFF;
            block[15] = 0xFF;
            for state in 0..=u16::MAX {
                for lane in [7usize, 15] {
                    if by_definition(state, &block[..lane]) == 0xFF00 {
                        reached += 1;
                    }
                }
                for (name, form) in sixteen_forms() {
                    assert_eq!(
                        form(state, &block),
                        by_definition(state, &block),
                        "{name} state {state:#06x} block {block:02x?}"
                    );
                }
            }
        }
        // The setup must actually occur, or this test proves nothing.
        assert!(reached >= 24, "{reached}");
    }

    /// A block whose outgoing state is 0, reached from a state that is
    /// not. Lane 15 then holds a representative of zero, 65,535 or
    /// 65,534, and must alarm (the one way it could hand on 65,535 is the
    /// all-zero block from 0, which hands on 0). A state of 0 after a clean
    /// step needs a 0 before it and a last byte of 0, so every block here
    /// ends in 0, and it is run from every incoming state, then followed
    /// by a second block so a wrong 65,535 is carried where it shows.
    #[test]
    fn a_block_that_ends_on_zero() {
        let mut rng = rarkit_testdata::Seeded::new(0x94D0_49BB_1331_11EB);
        let mut reached = 0u64;
        for _ in 0..24 {
            let v = noise(&mut rng, 32);
            let mut blocks: [u8; 32] = core::array::from_fn(|k| v[k]);
            blocks[15] = 0;
            for state in 1..=u16::MAX {
                if by_definition(state, &blocks[..16]) == 0 {
                    reached += 1;
                }
                for (name, form) in sixteen_forms() {
                    assert_eq!(
                        form(state, &blocks[..16]),
                        by_definition(state, &blocks[..16]),
                        "{name} state {state:#06x} block {blocks:02x?}"
                    );
                    assert_eq!(
                        form(state, &blocks),
                        by_definition(state, &blocks),
                        "{name} state {state:#06x} blocks {blocks:02x?}"
                    );
                }
            }
        }
        assert!(reached >= 12, "{reached}");
    }

    /// The block's own fast path, not only `lanes`: whenever it answers,
    /// the answer is the definition's, and it answers for most states.
    #[test]
    fn the_fast_path_answers_and_is_right() {
        let mut rng = rarkit_testdata::Seeded::new(0xD1B5_4A32_D192_ED03);
        let mut answered = 0u64;
        let mut asked = 0u64;
        for _ in 0..64 {
            let v = noise(&mut rng, 16);
            let block: [u8; 16] = core::array::from_fn(|k| v[k]);
            for state in (0..=u16::MAX).step_by(7) {
                asked += 1;
                if let Some(next) = block16(state, &block) {
                    answered += 1;
                    assert_eq!(next, by_definition(state, &block), "state {state:#06x}");
                }
            }
        }
        // About one lane in 256 alarms, sixteen lanes a block.
        assert!(answered * 100 > asked * 85, "{answered} of {asked}");
    }

    /// The SSE2 form's own fast path: it must answer for most states, or
    /// the differentials would pass on a kernel that always falls back to
    /// the definition's loop. It is counted by the blocks sent down that
    /// loop, the answers being checked against the definition as well.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_sse2_fast_path_answers_and_is_right() {
        let mut rng = rarkit_testdata::Seeded::new(0xD1B5_4A32_D192_ED03);
        let mut asked = 0u64;
        let before = SSE2_ALARMS.with(std::cell::Cell::get);
        for _ in 0..64 {
            let v = noise(&mut rng, 16);
            let block: [u8; 16] = core::array::from_fn(|k| v[k]);
            for state in (0..=u16::MAX).step_by(7) {
                asked += 1;
                assert_eq!(
                    sse2_form(state, &block),
                    by_definition(state, &block),
                    "state {state:#06x}"
                );
            }
        }
        let alarmed = SSE2_ALARMS.with(std::cell::Cell::get) - before;
        // About one lane in 256 alarms, sixteen lanes a block.
        assert!(alarmed * 100 < asked * 15, "{alarmed} of {asked}");
        // And it does alarm: the band is reached from some states.
        assert!(alarmed > 0, "{alarmed} of {asked}");
    }

    /// Data that drives the AVX2 kernel down all three of a step's
    /// endings: noise with runs of high bytes, which push the state into
    /// the band where lanes alarm.
    #[cfg(target_arch = "x86_64")]
    fn mixed(rng: &mut rarkit_testdata::Seeded, len: usize) -> Vec<u8> {
        let mut v = noise(rng, len);
        for chunk in v.chunks_mut(48) {
            if rng.index(3) == 0 {
                for b in chunk.iter_mut() {
                    *b |= 0xE0;
                }
            }
        }
        v
    }

    /// Read the AVX2 kernel's step counters around `f`.
    #[cfg(target_arch = "x86_64")]
    fn pairs_during(
        counter: &'static std::thread::LocalKey<std::cell::Cell<[u64; 3]>>,
        f: impl FnOnce(),
    ) -> [u64; 3] {
        let before = counter.with(std::cell::Cell::get);
        f();
        let after = counter.with(std::cell::Cell::get);
        core::array::from_fn(|i| after[i] - before[i])
    }

    /// The AVX2 kernel answers most 32-byte steps, and reaches both alarm
    /// endings, each settled to the definition's answer: a kernel that
    /// always answers, always falls back, or never tells the two blocks
    /// apart fails here. Where the processor has no AVX2 (Rosetta, for
    /// one) there is no kernel to check, and it says so.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_avx2_kernel_takes_every_path_and_is_right() {
        if !avx2_present() {
            println!("avx2 present: false, so the kernel's paths are not checked here");
            return;
        }
        let mut rng = rarkit_testdata::Seeded::new(0x3C6E_F372_FE94_F82B);
        let data = mixed(&mut rng, 1 << 18);
        let mut total = [0u64; 3];
        for start in [0u16, 0x1234, 0xFEFF, 0xFFFF] {
            let n = pairs_during(&AVX2_PAIRS, || {
                assert_eq!(avx2_form(start, &data), by_definition(start, &data));
            });
            for i in 0..3 {
                total[i] += n[i];
            }
        }
        let [clean, second, first] = total;
        assert!(clean > 10 * (second + first), "{total:?}");
        assert!(second > 0 && first > 0, "{total:?}");
    }

    /// The AVX2 form runs its own kernel where the processor has AVX2, and
    /// the SSE2 form where it is hidden, with the same answer both ways.
    /// It prints which, so a run's log shows the kernel itself ran.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_avx2_form_runs_its_kernel_or_falls_back() {
        println!("avx2 present: {}", avx2_present());
        let mut rng = rarkit_testdata::Seeded::new(0xA54F_F53A_5F1D_36F1);
        let data = mixed(&mut rng, 70_000);
        let want = by_definition(7, &data);
        let ran = pairs_during(&AVX2_PAIRS, || assert_eq!(avx2_form(7, &data), want));
        assert_eq!(ran.iter().sum::<u64>() > 0, avx2_present(), "{ran:?}");
        let hidden = pairs_during(&AVX2_PAIRS, || assert_eq!(avx2_hidden_form(7, &data), want));
        assert_eq!(hidden, [0; 3]);
        assert!(!HIDE_AVX2.with(std::cell::Cell::get));
    }

    /// Random lengths from 0 to 1 MiB at every alignment, from awkward
    /// incoming states, every form against the definition, and fed whole
    /// and in random pieces.
    #[test]
    fn random_lengths_every_alignment() {
        const MIB: usize = 1 << 20;
        let mut rng = rarkit_testdata::Seeded::new(0x2545_F491_4F6C_DD1D);
        let data = noise(&mut rng, MIB + 16);
        // High bytes push the state into the band where lanes alarm.
        let high: Vec<u8> = data.iter().map(|b| b | 0xE0).collect();
        let states = [0u16, 1, 0x7FFF, 0xFEFF, 0xFF00, 0xFFFE, 0xFFFF];
        let mut lengths: Vec<usize> = (0..=300).collect();
        lengths.extend((0..4).map(|_| rng.index(MIB + 1)));
        lengths.push(MIB);
        for (n, &len) in lengths.iter().enumerate() {
            for align in 0..16 {
                for source in [&data, &high] {
                    let bytes = &source[align..align + len];
                    let start = states[(n + align) % states.len()];
                    let want = by_definition(start, bytes);
                    assert_eq!(
                        serial(start, bytes),
                        want,
                        "serial, length {len} align {align}"
                    );
                    for (name, form) in sixteen_forms() {
                        assert_eq!(
                            form(start, bytes),
                            want,
                            "{name}, length {len} align {align}"
                        );
                        // In pieces, as a window flush feeds it.
                        let mut state = start;
                        let mut at = 0;
                        while at < len {
                            let take = (1 + rng.index(40_000)).min(len - at);
                            state = form(state, &bytes[at..at + take]);
                            at += take;
                        }
                        assert_eq!(state, want, "{name} pieces, length {len} align {align}");
                    }
                }
            }
        }
    }

    /// A measuring aid, not a check: how often each 16- and 32-byte form
    /// falls back to the definition's loop on the real member of
    /// `rar13/BIG80K.RAR` (the `f/extract-rar13-big80k-vsnull` row's), fed
    /// whole and in 4 KiB pieces, on this thread so the counters see it.
    /// Run by name with `--ignored --nocapture`.
    #[cfg(target_arch = "x86_64")]
    // It reads the fixture corpus through `rarkit-oracle`, which a vendored
    // copy of this crate does not have (`make mirror-check` builds exactly
    // that copy): the same gate `rar3_filters/tests.rs` puts on its oracle
    // tests.
    #[cfg(all(feature = "repo-tests", feature = "oracle-compare"))]
    #[test]
    #[ignore = "a measuring aid, run by name"]
    fn fallback_census_on_big80k() {
        use crate::{Disposition, MemberInfo, MemberOutcome, ReadOptions, Sink};
        struct Keep(Vec<Vec<u8>>);
        impl Sink for Keep {
            type Out = Vec<u8>;
            fn open(&mut self, _: &MemberInfo<'_>) -> crate::Result<Disposition<Vec<u8>>> {
                Ok(Disposition::Write(Vec::new()))
            }
            fn close(
                &mut self,
                _: &MemberInfo<'_>,
                out: Option<Vec<u8>>,
                _: &MemberOutcome,
            ) -> crate::Result<()> {
                self.0.extend(out);
                Ok(())
            }
        }
        let Ok(source) = rarkit_oracle::fixture("rar13/BIG80K.RAR") else {
            println!("the fixture corpus is not in this checkout");
            return;
        };
        let sources: Vec<std::sync::Arc<dyn crate::RangeSource>> =
            vec![std::sync::Arc::new(source)];
        let mut keep = Keep(Vec::new());
        crate::extract(sources, &ReadOptions::default(), &mut keep, &mut ()).expect("extracts");
        let member = keep.0.concat();
        println!(
            "member bytes {}, 16-byte blocks {}",
            member.len(),
            member.len() / 16
        );
        println!("avx2 present: {}", avx2_present());
        for piece in [member.len(), 4096] {
            let feed = |form: FormFn| member.chunks(piece).fold(0u16, form);
            let want = by_definition(0, &member);
            let before = SSE2_ALARMS.with(std::cell::Cell::get);
            assert_eq!(feed(sse2_form), want);
            let sse2 = SSE2_ALARMS.with(std::cell::Cell::get) - before;
            let avx2 = pairs_during(&AVX2_PAIRS, || assert_eq!(feed(avx2_form), want));
            println!(
                "pieces of {piece}: sse2 blocks alarmed {sse2}; avx2 steps \
                 [clean, second alarmed, first alarmed] {avx2:?}"
            );
        }
    }

    /// The form this target actually runs, through `Sum16`.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_x86_update_is_the_definition() {
        let mut rng = rarkit_testdata::Seeded::new(0x0123_4567_89AB_CDEF);
        let data = noise(&mut rng, 70_000);
        let mut sum = crate::read::rar13::Sum16::new();
        sum.update(&data);
        assert_eq!(sum.finish(), by_definition(0, &data));
    }
}
