//! Carried from the predecessor's `codec/rar50/boundaries.rs` at an earlier revision: items ours from birth
//! per the provenance census (and clean-room outputs, clean by provenance).
//!
//! UNREFERENCED, AND KEPT ON PURPOSE. Nothing calls `boundary_ranges`. Spec H3's
//! wording: "the entropy block boundary search: the coarse and fine
//! grids, the refinement window and passes", carried in its constants.
//!
//! It is not deleted because SPEC-H3 section 5 names it as carried
//! capability, to be used rather than rewritten, and the encoder work that
//! would use it is not finished: that work either wires this or deletes
//! it. (Pruned carried tree, 19 Sep 2026.)
#![allow(dead_code)]

use crate::carry::c_lz::codec::rar50::*;
use std::ops::Range;
/// The grid the shortest path runs on. Finer costs O(n^2) edges for
/// boundaries the refinement pass reaches anyway.
pub(crate) const COARSE_GRID_BYTES: usize = 64 << 10;
/// The grid the refinement pass may move a boundary onto.
pub(crate) const FINE_GRID_BYTES: usize = 4 << 10;
/// No entropy block chosen by the shortest path spans more than this. It
/// bounds the edge count, and it keeps one table set from covering a
/// stretch without limit.
pub(crate) const MAX_ENTROPY_SPAN_BYTES: usize = 512 << 10;
/// How far the refinement pass may move one boundary. Wider costs
/// proportionally more and measured no smaller.
pub(crate) const REFINE_WINDOW_BYTES: usize = 32 << 10;
/// Coordinate descent passes. A third measured no smaller on any corpus.
pub(crate) const REFINE_PASSES: usize = 2;
/// One candidate boundary: the token index it cuts at (a match is never
/// split) and the input byte offset there.
#[derive(Clone, Copy)]
pub(crate) struct Point {
    pub(crate) token: usize,
    pub(crate) byte: usize,
}
pub(crate) fn boundary_ranges(boundaries: &[usize], points: &[Point]) -> Vec<Range<usize>> {
    boundaries
        .windows(2)
        .map(|pair| points[pair[0]].token..points[pair[1]].token)
        .collect()
}
