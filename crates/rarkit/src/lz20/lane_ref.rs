//! The narrow lane's INSTRUMENT: a plain wide reference for the RAR 2.0
//! multimedia predictor, and a driver that runs the shipped model beside
//! it over the same residuals (spec D part 1, section 1.4.2).
//!
//! `lz20::audio` narrows its lane and accumulator types to `i16` and
//! `u16` under `#[cfg(target_arch = "x86_64")]` and keeps `i32` and `u32`
//! on every other target. Spec D 1.4.2 proves that narrowing exact:
//! `|e| <= 1024` and `|v_j| <= 255`, so a term is at most 1,279 and at
//! most 32 of them land before the channel adapts, so no accumulator
//! passes 40,928 and a `u16` holds it with 24,607 to spare.
//!
//! A proof is not a measurement, and until this module existed the narrow
//! arm had been fuzzed nowhere: every campaign in this repository has run
//! on an aarch64 box, where the narrow arm does not compile at all.
//! The reference below is therefore written from sections 1.2.1 to 1.2.3
//! as they read - a channel's last byte, its last first difference and
//! its last three second differences, eleven sums in one array, every
//! quantity 32 bits wide - and not from the shipped model's shape, which
//! splits the accumulators into two eight lane arrays so that the update
//! vectorises. Two shapes of one
//! function disagree where either is wrong; one shape twice does not.
//!
//! This module is behind its OWN feature and not behind `test-support` or
//! `bench-internals`, both of which the gate bench turns on through
//! the crate's dev dependency on itself. Compiled code reaches a gate
//! binary's code layout whether or not a leg calls it, and this
//! repository has already paid for that lesson twice.

use core::cell::Cell;

use super::audio::{Model, MAX_CHANNELS};

thread_local! {
    /// Multimedia SAMPLES this THREAD has put through the predictor.
    ///
    /// It answers a question an inventory of fuzz targets cannot:
    /// whether a target that COULD reach the predictor ever does.
    /// `fuzz:rar20_member` and `fuzz:rar20_tables` are the only
    /// registered targets whose input can reach it at all, and both have
    /// to get through a block header's multimedia bit and then a code
    /// length table over 256 symbols per channel before one sample
    /// lands. Counting is the only way to say whether a corpus does
    /// that, and a target that never does is fuzzing the predictor in
    /// name alone.
    ///
    /// PER THREAD and not process wide, so a test that reads it is not
    /// racing every other test in the binary for it. The cost is that a
    /// count is only the decoding thread's: read it from the thread that
    /// called the decoder, which is what `decode_member` gives a caller
    /// and what `examples/h3_audio_reach.rs` does.
    ///
    /// Behind this module's own feature, so nothing shipped and no gate
    /// binary carries the increment.
    static SAMPLES: Cell<u64> = const { Cell::new(0) };
}

/// Record one multimedia sample. Called from `lz20`'s multimedia run.
pub(crate) fn count_sample() {
    SAMPLES.with(|n| n.set(n.get().wrapping_add(1)));
}

/// Multimedia samples this thread has counted since [`reset_samples`].
pub(crate) fn samples() -> u64 {
    SAMPLES.with(Cell::get)
}

/// Set this thread's sample count back to zero.
pub(crate) fn reset_samples() {
    SAMPLES.with(|n| n.set(0));
}

/// The most any accumulator may hold before its channel adapts, from
/// spec D 1.4.2: 32 terms of at most `1024 + 255`.
///
/// It is stated here in the WIDE type on every target, so the bound is a
/// figure the reference can exceed and report rather than a figure the
/// narrow arm silently wraps around.
pub(crate) const ACCUMULATOR_BOUND: u32 = 32 * (1024 + 255);

/// Whether this build's shipped model runs the NARROW lane, which is
/// `i16` multipliers and `u16` accumulators.
///
/// The fuzz target records it, so a campaign's report says which arm it
/// swept rather than leaving it to be inferred from the box.
pub(crate) const NARROW_LANE: bool = cfg!(target_arch = "x86_64");

/// A value's low 8 bits as a signed byte: spec D 1.2.1's `sx`.
fn sx(value: i32) -> i32 {
    i32::from(value as u8 as i8)
}

/// What spec D 1.2.1 says one channel is, held as the section writes it:
/// the last byte, the last first difference, the last three second
/// differences and the five weights, with 1.2.3's eleven sums and the
/// place in the run of 32 beside them. Every quantity is 32 bits wide,
/// which 1.4 shows none of them can fill.
#[derive(Clone, Copy)]
struct Voice {
    /// `x[k-1]`.
    byte: i32,
    /// `d[k-1]`.
    slope: i32,
    /// `q[k-1]`, `q[k-2]`, `q[k-3]`.
    bends: [i32; 3],
    /// `a1` to `a5`.
    weights: [i32; 5],
    /// `T0` to `T10` over the samples of the run so far.
    trials: [u32; 11],
    /// Samples into the present run of 32.
    into_run: u32,
}

impl Voice {
    const SILENT: Voice = Voice {
        byte: 0,
        slope: 0,
        bends: [0; 3],
        weights: [0; 5],
        trials: [0; 11],
        into_run: 0,
    };

    /// Spec D 1.2.3 at the end of a run of 32: the least sum, the lowest
    /// index among equals, moves one weight one step or none.
    fn settle_run(&mut self) {
        let mut least = 0;
        for (index, &sum) in self.trials.iter().enumerate() {
            if sum < self.trials[least] {
                least = index;
            }
        }
        if let Some(pair) = least.checked_sub(1) {
            let weight = &mut self.weights[pair / 2];
            *weight = if pair % 2 == 0 {
                (*weight - 1).max(-17)
            } else {
                (*weight + 1).min(16)
            };
        }
        self.trials = [0; 11];
        self.into_run = 0;
    }
}

/// The reference model: spec D part 1 as it reads, one sample at a time,
/// with no lane, no padding and no narrowing anywhere.
struct Reference {
    voices: [Voice; MAX_CHANNELS],
    /// Spec D's `G`: the first difference the sample before this one left,
    /// whichever channel it was on.
    carried: i32,
    /// The largest value any sum of any channel has held.
    peak: u32,
}

impl Reference {
    fn fresh() -> Reference {
        Reference {
            voices: [Voice::SILENT; MAX_CHANNELS],
            carried: 0,
            peak: 0,
        }
    }

    /// One residual of `channel` to its byte: spec D 1.2.2, then 1.2.3's
    /// sums, then the quantities of 1.2.1 moved on by one sample.
    fn sample(&mut self, channel: usize, residual: u8) -> u8 {
        let voice = &mut self.voices[channel % MAX_CHANNELS];
        let multipliers = [
            voice.slope,
            voice.bends[0],
            voice.bends[1],
            voice.bends[2],
            self.carried,
        ];

        // 1.2.2: `A`, then `P = floor(A / 8) mod 256`, then the byte.
        let weighted: i32 = voice
            .weights
            .iter()
            .zip(&multipliers)
            .map(|(weight, multiplier)| weight * multiplier)
            .sum();
        let predicted = (8 * voice.byte + weighted).div_euclid(8).rem_euclid(256);
        let byte = (predicted - i32::from(residual)).rem_euclid(256);

        // 1.2.3: this sample's term of each of the eleven sums.
        let e = 8 * sx(i32::from(residual));
        voice.trials[0] += e.unsigned_abs();
        for (pair, multiplier) in voice.trials[1..]
            .as_chunks_mut::<2>()
            .0
            .iter_mut()
            .zip(&multipliers)
        {
            pair[0] += (e - multiplier).unsigned_abs();
            pair[1] += (e + multiplier).unsigned_abs();
        }
        let highest = voice.trials.iter().copied().max().unwrap_or(0);
        self.peak = self.peak.max(highest);

        // 1.2.1: the differences this sample leaves behind it.
        let slope = sx(byte - voice.byte);
        voice.bends = [slope - voice.slope, voice.bends[0], voice.bends[1]];
        voice.slope = slope;
        voice.byte = byte;
        self.carried = slope;

        voice.into_run += 1;
        if voice.into_run == 32 {
            voice.settle_run();
        }
        byte as u8
    }
}

/// Run the REFERENCE over `residuals`, rotating `channels` channels, and
/// answer the bytes with the largest accumulator any channel held.
///
/// `channels` is clamped into 1 to [`MAX_CHANNELS`], which is the range a
/// RAR 2.0 multimedia block header can name.
pub(crate) fn reference(channels: usize, residuals: &[u8]) -> (Vec<u8>, u32) {
    let count = channels.clamp(1, MAX_CHANNELS);
    let mut model = Reference::fresh();
    let mut channel = 0usize;
    let mut out = Vec::with_capacity(residuals.len());
    for &residual in residuals {
        out.push(model.sample(channel, residual));
        channel += 1;
        if channel == count {
            channel = 0;
        }
    }
    (out, model.peak)
}

/// Run the SHIPPED model over the same residuals and the same rotation:
/// the narrow arm on x86-64, the wide arm everywhere else.
pub(crate) fn shipped(channels: usize, residuals: &[u8]) -> Vec<u8> {
    let count = channels.clamp(1, MAX_CHANNELS);
    let mut model = Model::fresh();
    let mut channel = 0usize;
    let mut out = Vec::with_capacity(residuals.len());
    for &residual in residuals {
        out.push(model.residual_to_byte(channel, residual));
        channel += 1;
        if channel == count {
            channel = 0;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{reference, shipped, ACCUMULATOR_BOUND};
    use crate::checksum::crc32;

    /// The reference is only worth anything if it is RIGHT, so it is held
    /// to the vectors `lz20::tests` already pins, which were computed on
    /// the WIDE form on aarch64 and are quoted there by CRC.
    ///
    /// This is the check that stops a wrong reference reporting a false
    /// crash out of the fuzz target: it reproduces the spec's own answers
    /// before it is allowed to judge the shipped model's.
    #[test]
    fn the_reference_reproduces_the_pinned_wide_form_vectors() {
        let mut x: u64 = 12345;
        let residuals: Vec<u8> = (0..8192)
            .map(|_| {
                x = (1103515245u64.wrapping_mul(x).wrapping_add(12345)) % (1u64 << 31);
                ((x / 65536) % 256) as u8
            })
            .collect();
        assert_eq!(crc32(&residuals), 0x43f5_2e59, "the V7 vector itself");
        let (out, _) = reference(4, &residuals);
        assert_eq!(
            crc32(&out),
            0x78f8_40af,
            "lz20::tests' V7 four channel vector"
        );

        // Vector C2, which holds the weight ceiling at sixteen.
        let ceiling: Vec<u8> = [0x7f, 0x7f, 0x40]
            .iter()
            .cycle()
            .take(2048)
            .copied()
            .collect();
        assert_eq!(
            crc32(&reference(1, &ceiling).0),
            0x63e1_072d,
            "lz20::tests' C2"
        );

        let mut x: u64 = 987_654_321;
        let hot: Vec<u8> = (0..40_000)
            .map(|_| {
                x = (1103515245u64.wrapping_mul(x).wrapping_add(12345)) % (1u64 << 31);
                [0x7e, 0x7f, 0x80, 0x81][((x >> 16) % 4) as usize]
            })
            .collect();
        assert_eq!(crc32(&hot), 0x3155_c76d, "the worst case vector itself");
        let (hot_out, peak) = reference(4, &hot);
        assert_eq!(
            crc32(&hot_out),
            0x2f09_765f,
            "lz20::tests' narrow lane bound vector"
        );
        // The worst case the format allows drives the accumulators to
        // within a whisker of spec D 1.4.2's figure without reaching it,
        // which is what makes it the right vector to carry the bound.
        assert!(
            peak <= ACCUMULATOR_BOUND,
            "the worst case passed spec D 1.4.2's bound: {peak} against {ACCUMULATOR_BOUND}"
        );
        assert!(
            peak > ACCUMULATOR_BOUND / 2,
            "the worst case vector stopped exercising the bound: {peak}"
        );
    }

    /// THE ARMS AGREE, on this box, whichever arm this box compiles.
    ///
    /// On x86-64 the left hand side is the narrow lane and this is the
    /// check the whole lane exists for; on aarch64 it is the wide lane
    /// against a differently shaped wide reference, which is worth
    /// running anyway and is what lets one regression vector be pinned on
    /// both architectures.
    #[test]
    fn the_shipped_model_and_the_reference_agree_at_every_channel_count() {
        let mut x: u64 = 0x1234_5678_9abc_def0;
        let residuals: Vec<u8> = (0..12_000)
            .map(|_| {
                x = x
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                [0x00, 0x01, 0x7e, 0x7f, 0x80, 0x81, 0xfe, 0xff][((x >> 33) % 8) as usize]
            })
            .collect();
        for channels in 1..=4 {
            let (want, peak) = reference(channels, &residuals);
            assert_eq!(
                shipped(channels, &residuals),
                want,
                "the shipped model disagrees with spec D at {channels} channels"
            );
            assert!(
                peak <= ACCUMULATOR_BOUND,
                "{channels} channels reached {peak}"
            );
        }
    }
}
