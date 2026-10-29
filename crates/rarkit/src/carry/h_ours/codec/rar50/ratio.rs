//! Carried from the predecessor's `codec/rar50/ratio.rs` at an earlier revision: items ours from birth
//! per the provenance census (and clean-room outputs, clean by provenance).
//!
//! UNREFERENCED, AND KEPT ON PURPOSE. Nothing constructs `Policy`. Spec H3's
//! wording: "the adaptive and filtered ratio encoders' grids and
//! policy", carried in part.
//!
//! It is not deleted because SPEC-H3 section 5 names it as carried
//! capability, to be used rather than rewritten, and the encoder work that
//! would use it is not finished: that work either wires this or deletes
//! it. (Pruned carried tree, 19 Sep 2026.)
#![allow(dead_code)]

use crate::carry::c_lz::codec::rar50::*;
/// Each switch can be measured independently. This is a research API.
#[derive(Clone, Copy, Debug, Default)]
pub struct Policy {
    pub short_repeats: bool,
    pub adaptive: bool,
    pub carry: bool,
    pub exhaustive: bool,
    pub fine: bool,
    pub refine: bool,
}

pub(crate) mod adaptive;
pub(crate) mod filtered;
