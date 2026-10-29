//! Carried from the predecessor's `codec/rar50/ratio/adaptive.rs` at an earlier revision: items ours from birth
//! per the provenance census (and clean-room outputs, clean by provenance).
//!
//! UNREFERENCED, AND KEPT ON PURPOSE. Nothing calls `grid_points`. Spec H3's
//! wording: "the adaptive and filtered ratio encoders' grids and
//! policy", carried in part.
//!
//! It is not deleted because SPEC-H3 section 5 names it as carried
//! capability, to be used rather than rewritten, and the encoder work that
//! would use it is not finished: that work either wires this or deletes
//! it. (Pruned carried tree, 19 Sep 2026.)
#![allow(dead_code)]

use crate::carry::h_ours::codec::rar50::ratio::*;
pub(crate) fn grid_points(offsets: &[usize], spacing: usize) -> Vec<usize> {
    let mut points = vec![0];
    let mut next = spacing;
    for (i, &offset) in offsets.iter().enumerate().skip(1) {
        if offset >= next {
            points.push(i);
            next = offset + spacing;
        }
    }
    points.push(offsets.len() - 1);
    points.sort_unstable();
    points.dedup();
    points
}
