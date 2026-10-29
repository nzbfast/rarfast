//! Carried from the predecessor's `codec/rar20.rs` at an earlier revision: items ours from birth
//! per the provenance census (and clean-room outputs, clean by provenance).

use crate::carry::h_ours::codec::match_index::MatchIndex;
use std::io::Read;
use std::io::Write;
pub(crate) const LENGTH_SLOTS: usize = 28;
/// Weight bounds of the multimedia predictor. The range is asymmetric: a
/// weight may fall to -17 but never rise above 16.
pub(crate) const AUDIO_WEIGHT_MIN: i16 = -17;
pub(crate) const AUDIO_WEIGHT_MAX: i16 = 16;
/// A channel reconsiders its weights after every this many of its samples.
pub(crate) const AUDIO_ADAPT_PERIOD: u32 = 32;
/// Same width as the RAR 2.9 LUT: covers virtually every real code.
pub(crate) const HUFF20_LUT_BITS: usize = 12;
