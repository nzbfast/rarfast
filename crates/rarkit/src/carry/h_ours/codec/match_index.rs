//! Carried from the predecessor's `codec/match_index.rs` at an earlier revision: items ours from birth
//! per the provenance census (and clean-room outputs, clean by provenance).
//!
//! UNREFERENCED, AND KEPT ON PURPOSE. Nothing calls `Bucket`, `MatchIndex`, or
//! its `new`, `insert` and `candidates`. Spec H3's wording: "the hash
//! chain match index: geometry, tags, insertion, candidates, long
//! anchors, reverse seeding".
//!
//! It is not deleted because SPEC-H3 section 5 names it as carried
//! capability, to be used rather than rewritten, and the encoder work that
//! would use it is not finished: that work either wires this or deletes
//! it. (Pruned carried tree, 19 Sep 2026.)
#![allow(dead_code)]

/// Positions under one hash, oldest first; the live ones are the tail.
pub(crate) struct Bucket {
    pub(crate) entries: Vec<usize>,
}
pub(crate) struct MatchIndex {
    pub(crate) buckets: Vec<Bucket>,
    /// The most positions one hash keeps.
    pub(crate) capacity: usize,
}
impl MatchIndex {
    /// An index whose searches measure at most `candidates` positions per
    /// hash, over an input of `span` bytes.
    pub(crate) fn new(buckets: usize, span: usize, candidates: usize) -> Self {
        // Two beyond the candidate limit: the entry a search breaks out on,
        // and the one it may skip without counting.
        let capacity = candidates.saturating_add(2).min(span.max(1));
        Self {
            buckets: (0..buckets)
                .map(|_| Bucket {
                    entries: Vec::new(),
                })
                .collect(),
            capacity,
        }
    }
    /// Records `position`, which must be above every position already in.
    pub(crate) fn insert(&mut self, position: usize, hash: usize) {
        let capacity = self.capacity;
        let entries = &mut self.buckets[hash].entries;
        if entries.len() == 2 * capacity {
            entries.copy_within(capacity.., 0);
            entries.truncate(capacity);
        } else if entries.len() == entries.capacity() {
            // Grow by doubling, but never past the room a list can use: a
            // `push` alone would leave it holding twice that.
            let want = entries
                .capacity()
                .saturating_mul(2)
                .max(4)
                .min(2 * capacity);
            entries.reserve_exact(want - entries.capacity());
        }
        entries.push(position);
    }
    /// The positions under `hash`, newest first.
    pub(crate) fn candidates(&self, hash: usize) -> impl Iterator<Item = usize> + '_ {
        let entries = &self.buckets[hash].entries;
        let live = entries.len().min(self.capacity);
        entries[entries.len() - live..].iter().rev().copied()
    }
}
