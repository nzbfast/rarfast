//! The RAR 2.0 multimedia delta predictor (spec D part 1).
//!
//! One model serves both directions: the decoder turns a residual into an
//! output byte, the encoder turns an input byte into the residual that
//! would produce it, and both leave the model in the same state. The model
//! holds up to four channels plus one stream wide quantity, `g`, the first
//! difference of the most recent multimedia sample in ANY channel.
//!
//! Bytes emitted by LZ blocks never enter the model: `y` is the last byte
//! THIS channel's predictor produced, not the last byte of decoder output.

use crate::carry::c_lz::codec::rar20::{AUDIO_ADAPT_PERIOD, AUDIO_WEIGHT_MAX, AUDIO_WEIGHT_MIN};

/// Channels a RAR 2.0 multimedia block can name.
pub(crate) const MAX_CHANNELS: usize = 4;
/// The five weights a channel adapts.
const WEIGHTS: usize = 5;
/// One accumulator for the current weights and two for each weight's two
/// one step candidates.
const ACCUMULATORS: usize = 2 * WEIGHTS + 1;
/// Lanes each of the two accumulator vectors carries: the five weights
/// and three of padding, so that one lane operation is two whole NEON or
/// SSE2 registers. A padding lane's multiplier is zero for ever, so it
/// accumulates a figure [`Channel::adapt`] never reads and nothing has to
/// mask it.
const LANES: usize = 8;

/// The most any of the eleven accumulators can hold, from spec D 1.4.2:
/// `|e| <= 1024` and `|v_j| <= 255`, so a term is at most 1,279, and at
/// most [`AUDIO_ADAPT_PERIOD`] of them land before [`Channel::adapt`]
/// clears. `E0`'s own worst case, 32 * 1024, is smaller.
///
/// This number is the whole reason [`Acc`] may be [`u16`] on x86-64, so
/// it is CHECKED on every accumulate in debug builds rather than left to
/// the spec's word. The release build compiles the check out; `make ci`
/// runs the tests in both.
///
/// It is typed [`Acc`] and not [`u32`] so the comparison needs no
/// conversion on either target. 40,928 fits a `u16` with 24,607 to
/// spare, which is the point being made.
const ACCUMULATOR_MAX: Acc = 32 * (1024 + 255);

/// Lane of [`Channel::mul`] holding spec D 1.2.2's `h1`, the first
/// difference of this channel's previous sample.
const LANE_H1: usize = 0;
/// Lane holding `h2`, the change in first difference at the previous
/// sample.
const LANE_H2: usize = 1;
/// Lane holding `h3`, `h2` one sample further back.
const LANE_H3: usize = 2;
/// Lane holding `h4`, `h2` two samples further back.
const LANE_H4: usize = 3;
/// Lane holding the stream wide `g`, the first difference of the most
/// recent multimedia sample in ANY channel.
const LANE_G: usize = 4;

/// THE LANE WIDTH, and it is PER TARGET.
///
/// Spec D 1.4.2 proves the narrow lane exact and says so in as many
/// words: `|e| <= 1024` and `|v_j| <= 255`, so a term is at most 1,279,
/// and at most 32 of them accumulate before [`Channel::adapt`] clears,
/// so 40,928 is the most any accumulator holds and it fits [`u16`] with
/// no wrap at any point. `E0` reaches 32,768 and fits too, and every one
/// of the multiplier's five live lanes is inside [`i16`]. So the narrow
/// form is not an approximation of the wide one; it is the same integers
/// in half the space, and every vector in section 1.3 holds byte for
/// byte either way.
///
/// It is still not taken everywhere, because HALF THE SPACE IS NOT HALF
/// THE COST ON EVERY TARGET:
///
/// - on x86-64 it is the win. The absolute difference becomes `pmaxsw`
///   of the two subtractions, which is baseline SSE2, the eleven
///   accumulators fit ONE register instead of two, and the per-sample
///   traffic against `minus` and `plus` halves to one aligned `movdqa`
///   load and one store each. `Channel::advance` is 34 instructions a
///   sample against the wide form's 51.
/// - on aarch64 it is a LOSS. The wide form folds abs-and-accumulate into
///   a single `saba.4s`; there is no narrow spelling of that here with
///   the pinned toolchain, and `advance` goes the other way, 40 to 64.
///   This form had measured 0.82x on that
///   target before this work began, and the codegen now says why.
///
/// So x86-64 narrows and EVERY OTHER TARGET keeps the wide form that
/// ships today. Nothing but x86-64 changes at all. The two forms are one
/// body and not two: these aliases are the only difference between them,
/// which is what stops the narrow arm drifting away from the wide one.
#[cfg(target_arch = "x86_64")]
type Lane = i16;
/// The accumulator lane, matching [`Lane`]: it holds `|e - v|` summed.
#[cfg(target_arch = "x86_64")]
type Acc = u16;
/// The wide lane, for every target but x86-64. See [`Lane`].
#[cfg(not(target_arch = "x86_64"))]
type Lane = i32;
/// The wide accumulator lane. See [`Lane`].
#[cfg(not(target_arch = "x86_64"))]
type Acc = u32;

/// One multiplier lane widened for [`Channel::predict`]'s dot product,
/// which is [`i32`] on every target: the products reach 17 * 255 and the
/// sum reaches about 19,400, and doing that arithmetic in the narrow lane
/// would buy nothing - it is five scalar multiplies, not a lane
/// operation. Two spellings because there is nothing to widen on the wide
/// target and `i32::from` on an `i32` is a lint.
#[cfg(target_arch = "x86_64")]
#[inline]
fn wide(lane: Lane) -> i32 {
    i32::from(lane)
}

/// The wide target's widening, which is the identity. See the other.
#[cfg(not(target_arch = "x86_64"))]
#[inline]
fn wide(lane: Lane) -> i32 {
    lane
}

/// The low 8 bits of `value` read as a two's complement signed byte, so the
/// result is in -128..=127 (spec D's `sx`).
#[inline]
fn sx(value: i32) -> i32 {
    value as u8 as i8 as i32
}

/// One channel's state.
///
/// `repr(C, align(16))` and THIS FIELD ORDER, together, are what put every
/// one of the three eight lane arrays on a sixteen byte boundary. Left to
/// itself the layout is the same order by luck but only four byte aligned,
/// and `Channel` is then 132 bytes, so channels 1 to 3 begin off a
/// boundary and EVERY vector access of theirs can straddle a cache line -
/// on a four channel member, which is what the bench leg decodes, that is
/// three channels in four. Pinned this way `Channel` is 144 bytes, a whole
/// number of sixteen byte units, so channel `c` starts aligned for every
/// `c` and no lane operation splits a line.
///
/// The arrays come FIRST for that reason and not for tidiness: the five
/// weights and the four scalars are read one at a time and do not care
/// where they sit, so they go after, in the padding's way rather than in
/// the vectors'.
#[derive(Clone, Copy)]
#[repr(C, align(16))]
struct Channel {
    /// Spec D 1.2.2 step 5's multiplier vector `v`, in the lane order the
    /// eleven accumulators consume it: `h1`, `h2`, `h3` and `h4` in lanes
    /// [`LANE_H1`] to [`LANE_H4`], the stream wide `g` in [`LANE_G`], and
    /// three padding lanes that are zero for ever.
    ///
    /// `g` LIVES HERE, beside this channel's history, although it is a
    /// stream wide quantity [`Model`] holds as well. That is the whole
    /// point of the array: it makes the eight lane multiplier two
    /// contiguous loads. Held apart, `g` reaches the accumulate in a
    /// general register and lanes 5 to 7 are compile time constants, so
    /// both targets assemble the upper half by hand and put those
    /// transfers on the dependency chain into the accumulate - on x86-64
    /// a `movd` / `punpckldq` / `pshufd` run with the lane 4 and lane 5
    /// to 7 terms computed in general registers, on aarch64 a
    /// `mov.s v[i], w` insert in each half. Lanes 0 to 3 were contiguous
    /// already and were the only ones either target loaded as a vector.
    ///
    /// The history shift of step 2 and the `g` of step 6 are therefore
    /// one store of this array, in [`Channel::predict`].
    mul: [Lane; LANES],
    /// Spec D's ODD accumulators, `E(2j+1)`, in lane `j`: the error the
    /// same samples would have had with weight `j` one LOWER.
    ///
    /// The eleven accumulators used to be one array indexed `2j+1` and
    /// `2j+2`, and that STRIDE is why the update never vectorised: the
    /// two halves interleave, so no lane operation covers either. Split
    /// in two they are contiguous, and spec D 1.2.3 says in as many words
    /// that the eleven updates are independent of each other, so the
    /// order they are made in is free.
    minus: [Acc; LANES],
    /// Spec D's EVEN accumulators, `E(2j+2)`, in lane `j`: weight `j` one
    /// HIGHER.
    plus: [Acc; LANES],
    /// The five integer weights, each in [-17, 16].
    weight: [i32; WEIGHTS],
    /// This channel's most recent first difference, as recorded.
    p: i32,
    /// This channel's most recent multimedia output byte.
    y: i32,
    /// Samples this channel has processed; only `n mod 32` is observed.
    n: u32,
    /// Spec D's `E0`: the summed error of the current weights.
    e0: Acc,
}

impl Channel {
    const fn fresh() -> Channel {
        Channel {
            mul: [0; LANES],
            p: 0,
            y: 0,
            n: 0,
            e0: 0,
            minus: [0; LANES],
            plus: [0; LANES],
            weight: [0; WEIGHTS],
        }
    }
}

/// The predictor, shared by both directions.
pub(crate) struct Model {
    channel: [Channel; MAX_CHANNELS],
    /// First difference of the most recent multimedia sample in ANY
    /// channel, in [-128, 127].
    ///
    /// The channel about to take a sample is handed this in
    /// [`Channel::predict`], which parks it in that channel's own
    /// [`Channel::mul`]; this field is where it lives BETWEEN samples,
    /// because the next sample may be on a different channel.
    g: i32,
}

impl Model {
    /// A model with every quantity zero.
    pub(crate) fn fresh() -> Model {
        Model {
            channel: [Channel::fresh(); MAX_CHANNELS],
            g: 0,
        }
    }

    /// HOT PATH. The decoder step: the output byte for `residual` on
    /// `channel`.
    ///
    /// ONE BORROW OF THE CHANNEL serves the whole sample. The two halves
    /// used to take `&mut self` and index the channel array each, so a
    /// sample paid for the index arithmetic twice and the compiler had to
    /// reload the state between them; the halves take `&mut Channel` now
    /// and the index is taken once, here.
    #[inline(always)]
    pub(crate) fn residual_to_byte(&mut self, channel: usize, residual: u8) -> u8 {
        debug_assert!(channel < MAX_CHANNELS);
        let g = self.g;
        // The mask is a no-op on every reachable index - the caller's is
        // below the block's channel count, which is at most
        // `MAX_CHANNELS` - and it is what lets the sample run with no
        // bounds check at all.
        #[allow(clippy::indexing_slicing)] // masked to the array's length
        let state = &mut self.channel[channel & (MAX_CHANNELS - 1)];
        let predicted = state.predict(g);
        // Both sides are already reduced mod 256, so the subtraction is
        // the byte's own wrapping one and needs no `rem_euclid`.
        let byte = (predicted as u8).wrapping_sub(residual);
        self.g = state.advance(residual, byte);
        byte
    }

    /// The encoder step: the residual that [`Model::residual_to_byte`]
    /// would turn back into `byte` on an identical model.
    #[inline]
    // Live in the `cfg(test)` build only: this package's own tests are its
    // one caller.
    #[allow(dead_code)]
    pub(crate) fn byte_to_residual(&mut self, channel: usize, byte: u8) -> u8 {
        debug_assert!(channel < MAX_CHANNELS);
        let g = self.g;
        #[allow(clippy::indexing_slicing)] // masked to the array's length
        let state = &mut self.channel[channel & (MAX_CHANNELS - 1)];
        let predicted = state.predict(g);
        let residual = (predicted as u8).wrapping_sub(byte);
        self.g = state.advance(residual, byte);
        residual
    }
}

impl Channel {
    /// Steps 1 to 3: shift the history, park this sample's `g` beside it
    /// and predict. Leaves [`Channel::mul`] holding exactly the five
    /// multipliers step 5 needs, which is why [`Channel::advance`] takes
    /// no `g` of its own.
    #[inline(always)]
    fn predict(&mut self, g: i32) -> i32 {
        self.n = self.n.wrapping_add(1);
        let p = self.p;
        // Step 2's shift, whose right hand sides are all the values from
        // BEFORE the step: writing it as ONE array assignment is what
        // says so, since every element is evaluated before any is stored.
        //
        // The three padding lanes are rewritten with it rather than left
        // alone, so the upper half is a whole width store that the load
        // in `advance` forwards from. A four byte store of `g` under a
        // sixteen byte load is the case that stalls instead.
        let h1 = self.mul[LANE_H1];
        self.mul = [
            p as Lane,
            (p as Lane) - h1,
            self.mul[LANE_H2],
            self.mul[LANE_H3],
            g as Lane,
            0,
            0,
            0,
        ];
        let sum = 8 * self.y
            + self.weight[0] * wide(self.mul[LANE_H1])
            + self.weight[1] * wide(self.mul[LANE_H2])
            + self.weight[2] * wide(self.mul[LANE_H3])
            + self.weight[3] * wide(self.mul[LANE_H4])
            + self.weight[4] * wide(self.mul[LANE_G]);
        // Arithmetic shift: floor toward minus infinity, then mod 256.
        (sum >> 3) & 0xff
    }

    /// Steps 5 to 7: accumulate, record and adapt. Answers the stream wide
    /// `g` this sample leaves behind.
    #[inline(always)]
    fn advance(&mut self, residual: u8, byte: u8) -> i32 {
        let scaled = (8 * sx(i32::from(residual))) as Lane;
        // Spec D 1.2.2 step 5's `v`, whole, from the channel: lanes 0 to
        // 3 are the post-step-2 history and lane 4 is the pre-step-6 `g`,
        // both put there by `predict`. Lanes 5 to 7 are padding and zero
        // for ever.
        let multiplier = self.mul;
        // THE ELEVEN ACCUMULATORS, as two branch free lane operations over
        // eight lanes each. Two separate loops, not one loop doing both,
        // because each is then exactly one absolute-difference-accumulate
        // over two registers.
        // INDEXED ON PURPOSE, and `needless_range_loop` is allowed here
        // for that reason: the two loops are the point of the split, and
        // written as `iter_mut().zip()` they stop vectorising on aarch64
        // with the pinned toolchain and the leg measures 0.93x of the
        // indexed form. Both forms are the same arithmetic in the same
        // order; only the codegen differs.
        #[allow(clippy::needless_range_loop)] // vectorises, the zip does not
        for lane in 0..LANES {
            let term = scaled.wrapping_sub(multiplier[lane]).unsigned_abs();
            self.minus[lane] = self.minus[lane].wrapping_add(term);
            debug_assert!(self.minus[lane] <= ACCUMULATOR_MAX);
        }
        #[allow(clippy::needless_range_loop)] // vectorises, the zip does not
        for lane in 0..LANES {
            let term = scaled.wrapping_add(multiplier[lane]).unsigned_abs();
            self.plus[lane] = self.plus[lane].wrapping_add(term);
            debug_assert!(self.plus[lane] <= ACCUMULATOR_MAX);
        }
        self.e0 = self.e0.wrapping_add(scaled.unsigned_abs());
        debug_assert!(self.e0 <= ACCUMULATOR_MAX);

        // `y` is a byte and so is `byte`, so `sx` of their difference is
        // the wrapping byte subtraction read signed.
        let recorded = i32::from(byte.wrapping_sub(self.y as u8) as i8);
        self.p = recorded;
        self.y = i32::from(byte);

        if self.n.is_multiple_of(AUDIO_ADAPT_PERIOD) {
            self.adapt();
        }
        recorded
    }

    /// Step 7: keep the single one step weight change that would have done
    /// best over the last 32 samples, or none. Ties go to the lowest index.
    ///
    /// The search is one `min` chain over KEYS, the accumulator in the
    /// high bits and spec D's own index for it in the low four, so the
    /// lowest index wins a tie BY CONSTRUCTION rather than by the sense of
    /// a comparison, and no accumulator costs a data dependent branch
    /// (spec D 1.4.2).
    #[inline(always)]
    fn adapt(&mut self) {
        let mut best = u64::from(self.e0) << 4;
        #[allow(clippy::needless_range_loop)] // reads two arrays at one index
        for weight in 0..WEIGHTS {
            let odd = (u64::from(self.minus[weight]) << 4) | (2 * weight as u64 + 1);
            let even = (u64::from(self.plus[weight]) << 4) | (2 * weight as u64 + 2);
            best = best.min(odd).min(even);
        }
        self.e0 = 0;
        self.minus = [0; LANES];
        self.plus = [0; LANES];

        let index = (best & 0xf) as usize;
        debug_assert!(index < ACCUMULATORS);
        if index == 0 {
            return;
        }
        let weight = (index - 1) / 2;
        if index % 2 == 1 {
            if self.weight[weight] > i32::from(AUDIO_WEIGHT_MIN) {
                self.weight[weight] -= 1;
            }
        } else if self.weight[weight] < i32::from(AUDIO_WEIGHT_MAX) {
            self.weight[weight] += 1;
        }
    }
}

#[cfg(test)]
mod layout {
    use super::{Acc, Channel, Lane, LANES, MAX_CHANNELS, WEIGHTS};
    use core::mem::{align_of, offset_of, size_of};

    /// The alignment on [`Channel`] is a PERFORMANCE claim, so it is
    /// checked rather than asserted in a comment: every one of the three
    /// eight lane arrays has to begin on a sixteen byte boundary, and
    /// `Channel` has to be a whole number of sixteen byte units so that
    /// channel `c` of the array in [`super::Model`] is aligned for every
    /// `c` and not just for `c = 0`.
    #[test]
    fn every_lane_array_is_sixteen_byte_aligned_in_every_channel() {
        assert_eq!(align_of::<Channel>(), 16, "the channel's own alignment");
        assert_eq!(
            size_of::<Channel>() % 16,
            0,
            "a whole number of sixteen byte units, or channels 1 to {} \
             start off a boundary",
            MAX_CHANNELS - 1
        );
        for (name, offset) in [
            ("mul", offset_of!(Channel, mul)),
            ("minus", offset_of!(Channel, minus)),
            ("plus", offset_of!(Channel, plus)),
        ] {
            assert_eq!(offset % 16, 0, "`{name}` begins at offset {offset}");
        }
        // The multiplier's five live lanes and its three padding lanes
        // are one run, which is the other half of the arrangement: the
        // eight lane load is whole registers and not a gather. Sixteen
        // bytes on the narrow target, thirty two on the wide one, and a
        // whole number of registers either way.
        const { assert!(WEIGHTS < LANES) };
        assert_eq!(size_of::<[Lane; LANES]>() % 16, 0, "the multiplier");
        assert_eq!(size_of::<[Acc; LANES]>() % 16, 0, "an accumulator");
    }
}
