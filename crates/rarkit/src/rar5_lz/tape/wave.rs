//! A wave of blocks decoded to tapes on the pool, and the one block's
//! decode it is made of.

use super::*;

/// A pool of tapes, recycled across the blocks of one member so no block
/// allocates (section 4.2 and 7.3 item 3).
#[derive(Default)]
pub(crate) struct TapePool {
    pub(super) spare: Vec<BlockTape>,
}

impl TapePool {
    pub(crate) fn take(&mut self) -> BlockTape {
        self.spare.pop().unwrap_or_default()
    }
    pub(crate) fn give(&mut self, mut tape: BlockTape) {
        tape.resolved = None;
        if tape.worth_recycling() {
            self.spare.push(tape);
        }
    }
    /// The tapes the pool is holding, for the bound of
    /// `the_tapes_in_flight_are_bounded_by_the_lanes`.
    #[cfg(all(test, feature = "parallel"))]
    pub(crate) fn len(&self) -> usize {
        self.spare.len()
    }
}

/// One wave's tapes, each with the table set its block used.
///
/// The buffer is recycled WHOLE: the apply stage hands it back and the
/// next wave decodes into the same tapes, so a wave in the steady state
/// allocates nothing. It is what the two sides of the overlap pass to each
/// other, which is why it has a name.
pub(crate) type Wave = Vec<(BlockTape, Option<Arc<Tables>>)>;

/// Decode one wave of blocks into `wave`, in parallel.
///
/// `wave` arrives holding an earlier wave's tapes. Each is reused unless it
/// has grown past the carried recycling bound, in which case it is dropped
/// for a fresh one; the buffer is then fitted to `range` out of `pool`.
/// Nothing here touches the window, the repeated distances, the last match
/// length or the filter queue: that is section 3.8's property, and it is
/// what lets this run while the wave before it is being applied.
pub(crate) fn decode_wave_into(
    plan: &Plan,
    packed: &[u8],
    algorithm: u8,
    carried: Option<&Arc<Tables>>,
    range: std::ops::Range<usize>,
    pool: &mut TapePool,
    wave: &mut Wave,
) {
    use rayon::prelude::*;
    while wave.len() > range.len() {
        let (tape, _) = wave.pop().expect("the buffer is longer than the range");
        pool.give(tape);
    }
    for (tape, held) in wave.iter_mut() {
        *held = None;
        if !tape.worth_recycling() {
            *tape = BlockTape::default();
        }
    }
    while wave.len() < range.len() {
        wave.push((pool.take(), None));
    }
    // A wave of ONE block cannot use a second thread, and a stage sizes
    // itself to the work it has and never to the pool it finds (API
    // section 8.2): handing one block to `par_iter` would wake the
    // caller's whole pool to watch one thread decode it.
    if wave.len() < 2 {
        for ((tape, held), index) in wave.iter_mut().zip(range) {
            *held = decode_one_dispatch(plan, packed, algorithm, carried, index, tape);
        }
        return;
    }
    // Counts the batches this stage hands to the CALLER'S pool, which the
    // regression test of 19 Sep 2026 reads. Compiled out entirely without
    // `h2-probes`; see `crate::probe`.
    #[cfg(feature = "h2-probes")]
    crate::probe::note_pool_handoff();
    wave.par_iter_mut()
        .zip(range.into_par_iter())
        .for_each(|((tape, held), index)| {
            *held = decode_one_dispatch(plan, packed, algorithm, carried, index, tape);
        });
}

/// Decode block `index` into `tape`, answering the table set it used.
///
/// The whole of what one decoding unit does, so the two drivers of
/// section 3.8 - the wave and the pipeline - cannot drift apart: a block
/// decodes identically whichever of them reaches it, on whichever thread.
pub(crate) fn decode_one(
    plan: &Plan,
    packed: &[u8],
    algorithm: u8,
    carried: Option<&Arc<Tables>>,
    index: usize,
    tape: &mut BlockTape,
) -> Option<Arc<Tables>> {
    // Counts how wide the decode actually ran. Compiled out entirely
    // without `h2-probes`; see `crate::probe`.
    #[cfg(feature = "h2-probes")]
    let _worker = crate::probe::WorkerGuard::enter();
    let group = &plan.groups[plan.group_of[index]];
    match group.get(plan, packed, algorithm, carried) {
        Ok((tables, start)) => {
            // Only the block that CARRIES the set starts past it; the
            // blocks after it in the group start at bit zero.
            let from = if group.first == Some(index) { start } else { 0 };
            tape.far_off = plan.far_off;
            decode_block_tape(&tables, packed, &plan.blocks[index], from, tape);
            Some(tables)
        }
        Err(err) => {
            tape.clear();
            tape.failure = Some(err);
            None
        }
    }
}

/// Block `index`'s table set and the bit its symbols start at, exactly as
/// [`decode_one`] finds them: only the block that CARRIES the set starts
/// past it. For the one-pass decode of a member on one thread
/// (`Rar5Lz::member_one_thread`), which decodes the block with no tape.
pub(crate) fn block_tables(
    plan: &Plan,
    packed: &[u8],
    algorithm: u8,
    carried: Option<&Arc<Tables>>,
    index: usize,
) -> Result<(Arc<Tables>, usize)> {
    let group = &plan.groups[plan.group_of[index]];
    let (tables, start) = group.get(plan, packed, algorithm, carried)?;
    let from = if group.first == Some(index) { start } else { 0 };
    Ok((tables, from))
}

/// What every caller of [`decode_one`] calls: on aarch64 and x86-64 the
/// literal batch's own [`batch::decode_one`], which hands every set its
/// gate refuses to `decode_one` untouched; elsewhere `decode_one` itself
/// (the batch is compiled and tested everywhere, chosen only
/// where it was held; x86-64 was held on 27 Sep 2026 with every function
/// on a 64-byte line, which the unaligned build needed).
/// Always inlined, so it is a name
/// and not a function.
#[inline(always)]
pub(crate) fn decode_one_dispatch(
    plan: &Plan,
    packed: &[u8],
    algorithm: u8,
    carried: Option<&Arc<Tables>>,
    index: usize,
    tape: &mut BlockTape,
) -> Option<Arc<Tables>> {
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    {
        batch::decode_one(plan, packed, algorithm, carried, index, tape)
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        decode_one(plan, packed, algorithm, carried, index, tape)
    }
}
