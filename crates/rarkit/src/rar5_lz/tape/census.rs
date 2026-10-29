//! The tape's censuses: what a block's tape holds, counted for the
//! instruments. Every item is behind an instrument feature; no shipped
//! build has any of it.

use super::*;

/// Decode one block and histogram what the APPLY STAGE would walk: how
/// long its literal runs are, and how long and how far back its matches
/// are. Nothing is applied to a window.
///
/// The counts of [`census_block`] say how MANY operations the one apply
/// thread walks. They do not say which ARM of that loop each operation
/// takes, and on the incompressible member the two answers are different
/// questions: a literal run of 15 bytes and one of 16 go down different
/// paths in `Window::literals`, and a match at a distance of 15 and one
/// at 16 go down different paths in `Window::copy_match`. A lever aimed
/// at one of those arms is worth its measuring time only in proportion to the
/// operations that actually take it, so this counts them.
///
/// The buckets are the thresholds the code itself branches on:
/// `LITERAL_INLINE_MAX`, the ring's `STRIDE` and `STRIDE_MAX`.
// Reached only through the `internals_*` seam, behind
// `h2-instruments` ALONE: under `bench-internals` it was a second and
// third caller of `decode_block_tape` and `LazyDecodeTables::get` in the
// benchmark binary, which kept both out of line in `decode_one`.
#[cfg(feature = "h2-instruments")]
pub(crate) fn shape_block(
    plan: &Plan,
    packed: &[u8],
    algorithm: u8,
    index: usize,
    tape: &mut BlockTape,
    shape: &mut [u64; SHAPE_BUCKETS],
) -> Result<()> {
    use super::output::{STRIDE, STRIDE_MAX};
    use crate::carry::c_lz::codec::rar50::LITERAL_INLINE_MAX;

    let group = &plan.groups[plan.group_of[index]];
    let (tables, start) = group.get(plan, packed, algorithm, None)?;
    let from = if group.first == Some(index) { start } else { 0 };
    let mut at = from;
    loop {
        decode_block_tape(&tables, packed, &plan.blocks[index], at, tape);
        for op in &tape.steps {
            let length = op.length();
            let run = op.prefix();
            if run != 0 {
                shape[SHAPE_LIT_RUNS] += 1;
                shape[SHAPE_LIT_BYTES] += run as u64;
                if run <= LITERAL_INLINE_MAX {
                    shape[SHAPE_LIT_INLINE] += 1;
                } else if run <= 2 * STRIDE_MAX {
                    shape[SHAPE_LIT_MEMCPY_SHORT] += 1;
                } else {
                    shape[SHAPE_LIT_MEMCPY_LONG] += 1;
                }
            }
            match op.kind() {
                tape_kind::LITS => {}
                tape_kind::MATCH => {
                    shape[SHAPE_MATCHES] += 1;
                    shape[SHAPE_MATCH_BYTES] += length as u64;
                    // The fast arm of `Window::copy_match` also wants the
                    // source and the write point clear of the ring's end,
                    // which is a property of WHERE in the ring the member
                    // is and not of the operation; this counts the two
                    // halves that ARE the operation's own.
                    if length <= STRIDE_MAX && (op.distance as usize) >= STRIDE {
                        shape[SHAPE_MATCH_STRIDE] += 1;
                    } else if length > STRIDE_MAX {
                        shape[SHAPE_MATCH_LONG] += 1;
                    } else {
                        shape[SHAPE_MATCH_NEAR] += 1;
                    }
                }
                tape_kind::REP | tape_kind::REP_LAST => shape[SHAPE_REPEATS] += 1,
                _ => shape[SHAPE_FILTERS] += 1,
            }
        }
        match tape.parked_at {
            Some(next) if next > at => at = next,
            _ => break,
        }
    }
    Ok(())
}

/// Slots of the histogram [`shape_block`] fills.
#[cfg(feature = "h2-instruments")]
pub(crate) const SHAPE_BUCKETS: usize = 12;

#[cfg(feature = "h2-instruments")]
pub(crate) const SHAPE_LIT_RUNS: usize = 0;

#[cfg(feature = "h2-instruments")]
pub(crate) const SHAPE_LIT_BYTES: usize = 1;

/// Runs short enough for the inline ladder.
#[cfg(feature = "h2-instruments")]
pub(crate) const SHAPE_LIT_INLINE: usize = 2;

/// Runs that take the `copy_from_slice` libcall, up to two fast matches.
#[cfg(feature = "h2-instruments")]
pub(crate) const SHAPE_LIT_MEMCPY_SHORT: usize = 3;

/// Runs that take it and are long enough for the libcall to pay.
#[cfg(feature = "h2-instruments")]
pub(crate) const SHAPE_LIT_MEMCPY_LONG: usize = 4;

#[cfg(feature = "h2-instruments")]
pub(crate) const SHAPE_MATCHES: usize = 5;

#[cfg(feature = "h2-instruments")]
pub(crate) const SHAPE_MATCH_BYTES: usize = 6;

/// Matches the stride ladder can take.
#[cfg(feature = "h2-instruments")]
pub(crate) const SHAPE_MATCH_STRIDE: usize = 7;

/// Matches too NEAR for a stride: they fall to the byte-wise slow path.
#[cfg(feature = "h2-instruments")]
pub(crate) const SHAPE_MATCH_NEAR: usize = 8;

/// Matches too LONG for the ladder, which fall to it as well.
#[cfg(feature = "h2-instruments")]
pub(crate) const SHAPE_MATCH_LONG: usize = 9;

#[cfg(feature = "h2-instruments")]
pub(crate) const SHAPE_REPEATS: usize = 10;

#[cfg(feature = "h2-instruments")]
pub(crate) const SHAPE_FILTERS: usize = 11;

/// Decode one block and count what it holds, for the census of SPEC-H2
/// section 7.5: operations, literals, fresh matches, repeats and filters.
/// Nothing is applied to a window.
// Reached only through the `internals_*` seam, behind
// `h2-instruments` ALONE: under `bench-internals` it was a second and
// third caller of `decode_block_tape` and `LazyDecodeTables::get` in the
// benchmark binary, which kept both out of line in `decode_one`.
#[cfg(feature = "h2-instruments")]
pub(crate) fn census_block(
    plan: &Plan,
    packed: &[u8],
    algorithm: u8,
    index: usize,
    tape: &mut BlockTape,
) -> Result<(u64, u64, u64, u64, u64)> {
    let group = &plan.groups[plan.group_of[index]];
    let (tables, start) = group.get(plan, packed, algorithm, None)?;
    let from = if group.first == Some(index) { start } else { 0 };
    let mut counts = (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut at = from;
    loop {
        decode_block_tape(&tables, packed, &plan.blocks[index], at, tape);
        for op in &tape.steps {
            counts.0 += 1;
            counts.1 += op.prefix() as u64;
            match op.kind() {
                tape_kind::LITS => {}
                tape_kind::MATCH => counts.2 += 1,
                tape_kind::REP | tape_kind::REP_LAST => counts.3 += 1,
                _ => counts.4 += 1,
            }
        }
        match tape.parked_at {
            Some(next) if next > at => at = next,
            _ => break,
        }
    }
    Ok(counts)
}

/// The length classes of [`match_shape_block`]: 2, 3, 4, 5, 6, 7, 8, then
/// 9 to 16, 17 to 32 and longer.
#[cfg(feature = "h2-instruments")]
pub(crate) const MATCH_SHAPE_LENGTHS: usize = 10;

/// The distance classes of [`match_shape_block`], each up to and
/// including: 256, 4 KiB, 64 KiB, 256 KiB, 2 MiB, 32 MiB, and beyond.
#[cfg(feature = "h2-instruments")]
pub(crate) const MATCH_SHAPE_DISTANCES: usize = 7;

/// What [`match_shape_block`] fills: fresh matches as (count, bytes) by
/// length class and distance class, and repeats (of either kind whose
/// length the operation carries) as (count, bytes) by length class.
#[cfg(feature = "h2-instruments")]
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct MatchShape {
    pub(crate) fresh: [[(u64, u64); MATCH_SHAPE_DISTANCES]; MATCH_SHAPE_LENGTHS],
    pub(crate) repeats: [(u64, u64); MATCH_SHAPE_LENGTHS],
    /// Repeats that take the last match's length, which the operation
    /// does not carry.
    pub(crate) repeat_last: u64,
}

#[cfg(feature = "h2-instruments")]
fn match_shape_length_class(length: usize) -> usize {
    match length {
        0..=8 => length.saturating_sub(2),
        9..=16 => 7,
        17..=32 => 8,
        _ => 9,
    }
}

/// Decode one block and count its matches by length and distance, for the
/// writer's ratio counts: which kind of match one writer codes and
/// another leaves as literals is a property of the two streams. Nothing
/// is applied to a window.
// Behind `h2-instruments` alone, as `census_block` is and for its reason.
#[cfg(feature = "h2-instruments")]
pub(crate) fn match_shape_block(
    plan: &Plan,
    packed: &[u8],
    algorithm: u8,
    index: usize,
    tape: &mut BlockTape,
    shape: &mut MatchShape,
) -> Result<()> {
    let group = &plan.groups[plan.group_of[index]];
    let (tables, start) = group.get(plan, packed, algorithm, None)?;
    let from = if group.first == Some(index) { start } else { 0 };
    let mut at = from;
    loop {
        decode_block_tape(&tables, packed, &plan.blocks[index], at, tape);
        for op in &tape.steps {
            let length = op.length();
            let class = match_shape_length_class(length);
            match op.kind() {
                tape_kind::MATCH => {
                    let far = match op.distance {
                        0..=0x100 => 0,
                        0x101..=0x1000 => 1,
                        0x1001..=0x1_0000 => 2,
                        0x1_0001..=0x4_0000 => 3,
                        0x4_0001..=0x20_0000 => 4,
                        0x20_0001..=0x200_0000 => 5,
                        _ => 6,
                    };
                    shape.fresh[class][far].0 += 1;
                    shape.fresh[class][far].1 += length as u64;
                }
                tape_kind::REP => {
                    shape.repeats[class].0 += 1;
                    shape.repeats[class].1 += length as u64;
                }
                tape_kind::REP_LAST => shape.repeat_last += 1,
                _ => {}
            }
        }
        match tape.parked_at {
            Some(next) if next > at => at = next,
            _ => break,
        }
    }
    Ok(())
}

/// Whether block `index` decodes under a main table of the single-gap
/// shape (`DecodeTable::serial_single_gap`), and its symbol bits from the
/// bit its symbols start at; for `internals_h2::gap_shape_census`. The
/// tables are read, no symbol is decoded.
#[cfg(feature = "h2-instruments")]
pub(crate) fn gap_shape_block(
    plan: &Plan,
    packed: &[u8],
    algorithm: u8,
    index: usize,
) -> Result<(bool, u64)> {
    let group = &plan.groups[plan.group_of[index]];
    let (tables, start) = group.get(plan, packed, algorithm, None)?;
    let from = if group.first == Some(index) { start } else { 0 };
    let bits = plan.blocks[index].bits().saturating_sub(from) as u64;
    Ok((tables.main.serial_single_gap().is_some(), bits))
}

/// Which path each of a block's copies takes through `Window::copy_match`,
/// counted by walking the tape the way the apply stage does: the write
/// point `at` in a ring of `ring_len`, the repeat state, and the fast
/// copy's four conditions (length at most `STRIDE_MAX`, distance at least
/// `STRIDE`, a source that does not wrap behind the ring's start, and the
/// ladder's reach inside the ring). `reach` caps every distance first, as
/// the `NEAR_SOURCE` ceiling arm does, or is `usize::MAX` for the shipped
/// walk. A COUNT, not a timing:
/// the ceiling arm's
/// gain over any prefetch includes every copy it moves from the slow path
/// to the fast one, and no hint can move those.
///
/// `counts`: fast copies, slow for length, slow for a near distance, slow
/// for a WRAPPED source, slow at the ring's end, and the bytes the slow
/// copies moved; then the slow copies and their bytes under the MIRROR
/// layout (the ring `STRIDE_MAX` longer, the tail copied to the head at
/// each lap, no wrap test); then the wrapped copies whose source sits
/// within `STRIDE_MAX` behind the ring's start, which the EDGE form (the
/// ring as it is, the wrap test replaced) leaves slow. Filter records
/// produce nothing and are skipped.
// Behind `copy-census` ALONE, like the other censuses: `bench-internals`
// is on in `two_arm`, and a census compiled into the measured arm moves
// its shape. Nothing enables it but an explicit
// `--features copy-census` on a counting run.
#[cfg(feature = "copy-census")]
#[allow(clippy::too_many_arguments)]
pub(crate) fn copy_path_census_block(
    plan: &Plan,
    packed: &[u8],
    algorithm: u8,
    index: usize,
    tape: &mut BlockTape,
    state: &mut MatchState,
    at: &mut usize,
    stream: &mut u64,
    ring_len: usize,
    reach: usize,
    counts: &mut [u64; 9],
) -> Result<()> {
    use super::output::{STRIDE, STRIDE_MAX};
    // THE MIRROR LAYOUT's write point for the same stream position: a ring
    // `STRIDE_MAX` longer whose write point laps at `ring_len + STRIDE_MAX`
    // back to slot `STRIDE_MAX`, so its fast copy needs no wrap test.
    let mirrored = |stream: u64| -> usize {
        let edge = STRIDE_MAX as u64;
        if stream < edge {
            stream as usize
        } else {
            STRIDE_MAX + ((stream - edge) % ring_len as u64) as usize
        }
    };
    let group = &plan.groups[plan.group_of[index]];
    let (tables, start) = group.get(plan, packed, algorithm, None)?;
    let from = if group.first == Some(index) { start } else { 0 };
    let mut bit = from;
    loop {
        decode_block_tape(&tables, packed, &plan.blocks[index], bit, tape);
        for op in &tape.ops {
            *at = (*at + op.prefix()) % ring_len;
            *stream += op.prefix() as u64;
            let (distance, length) = match op.kind() {
                tape_kind::LITS => continue,
                tape_kind::MATCH => {
                    let distance = op.distance as usize;
                    state.fresh(distance, op.length());
                    (distance, op.length())
                }
                tape_kind::REP => {
                    let distance = state.rotate(op.distance as usize, op.length())?;
                    (distance, op.length())
                }
                tape_kind::REP_LAST => (state.repeats[0], state.last_length),
                _ => continue,
            };
            let distance = distance.min(reach);
            let slot = if length > STRIDE_MAX {
                1
            } else if distance < STRIDE {
                2
            } else if distance > *at {
                3
            } else if *at + STRIDE_MAX >= ring_len {
                4
            } else {
                0
            };
            counts[slot] += 1;
            if slot != 0 {
                counts[5] += length as u64;
            }
            // The mirror layout: the same copy, slow only for length, a
            // near distance, or the write point's room.
            let fast_mirrored = length <= STRIDE_MAX
                && distance >= STRIDE
                && mirrored(*stream) + STRIDE_MAX < ring_len + STRIDE_MAX;
            if !fast_mirrored {
                counts[6] += 1;
                counts[7] += length as u64;
            }
            // The EDGE form: the ring as it is, the wrap test replaced by
            // "not within `STRIDE_MAX` behind the ring's start". What it
            // leaves slow of the wrapped copies.
            if slot == 3 && distance < *at + STRIDE_MAX {
                counts[8] += 1;
            }
            *at = (*at + length) % ring_len;
            *stream += length as u64;
        }
        match tape.parked_at {
            Some(next) if next > bit => bit = next,
            _ => break,
        }
    }
    Ok(())
}

/// Decode one block and count how much of it a LANE could resolve for
/// itself, leaving the one apply thread a staged RUN between the
/// operations it cannot.
///
/// The apply stage is bound by OPERATIONS and it is one thread, so the
/// question this counts is structural rather than micro: a lane that has
/// already produced the first `N` bytes of its own block holds those bytes
/// in its own staging buffer, so a match whose source lies wholly inside
/// them can be resolved THERE, on a lane thread, and written into the
/// staging buffer exactly as a literal is. Only a match reaching back
/// before the block's start needs the window, and the apply thread then
/// walks one staged run between such matches instead of one operation per
/// literal run and per match.
///
/// Three things make the honest count smaller than "distance <= bytes
/// produced so far", and all three are counted here rather than assumed:
///
/// - a HOLE. An operation the lane cannot resolve still produces bytes,
///   and the lane does not know them, so every later source range must
///   clear the end of the last hole. `valid_from` carries that, and the
///   difference between the optimistic and the hole-aware count is a
///   bucket of its own.
/// - a CARRIED REPEAT SLOT. A `REP` names an index into the four repeated
///   distances, resolved against live state at apply, and at a block's
///   start some of those four were set by an earlier block. The lane knows
///   a slot only once an operation of its own has written it, so
///   knowledge is tracked per slot through the same rotation the apply
///   stage performs.
/// - a FILTER. It produces no byte of its own and SPEC-H2 3.6 puts the
///   UNFILTERED bytes in the window, so it is no barrier to a lane's
///   sources; but its span resolves against the bytes the member has
///   produced, so it stays an operation the apply thread visits in order
///   and it closes the run around it.
///
/// Nothing is applied to a window and nothing is timed: a count is a
/// property of the stream and the same on every machine. The block boundaries
/// are the plan's own, which are the boundaries the parallel path actually
/// decodes at, one block to a lane in `decode_one`.
// Reached only through the `internals_*` seam, behind its OWN feature
// `h2-locality-census`: nothing else turns it on, so no bench binary
// compiles it and neither its layout nor its arithmetic can reach a
// measured arm.
#[cfg(feature = "h2-locality-census")]
#[allow(dead_code)]
pub(crate) fn locality_block(
    plan: &Plan,
    packed: &[u8],
    algorithm: u8,
    index: usize,
    tape: &mut BlockTape,
    loc: &mut [u64; LOCALITY_BUCKETS],
) -> Result<()> {
    let group = &plan.groups[plan.group_of[index]];
    let (tables, start) = group.get(plan, packed, algorithm, None)?;
    let from = if group.first == Some(index) { start } else { 0 };
    let mut at = from;
    // The lane's own view of its block, which is the whole of the model.
    let mut staged = 0u64;
    let mut valid_from = 0u64;
    let mut reps: [Option<u64>; 4] = [None; 4];
    let mut last_length: Option<u64> = None;
    let mut run_open = false;
    // THE CEILING, measured beside the achievable figure: the same walk
    // with the HOLES WISHED AWAY, as though a lane held every byte its
    // block had produced whoever produced it. Nothing can implement this,
    // because the bytes an unresolved operation produces are genuinely not
    // the lane's; it is here because it bounds every variant of this
    // direction at once, and a bound that is itself a loss closes the
    // direction rather than closing one model of it.
    let mut opt_run_open = false;
    loop {
        decode_block_tape(&tables, packed, &plan.blocks[index], at, tape);
        for op in &tape.steps {
            loc[LOC_OPS] += 1;
            let kind = op.kind();
            // What this operation copies and from how far back, in the
            // two kinds where the operation itself does not say.
            if op.prefix() != 0 {
                loc[LOC_LIT_RUNS] += 1;
                loc[LOC_BYTES] += op.prefix() as u64;
                staged += op.prefix() as u64;
                run_open = true;
                opt_run_open = true;
            }
            let (length, distance, known) = match kind {
                tape_kind::LITS => continue,
                tape_kind::MATCH => {
                    let distance = op.distance as u64;
                    let length = op.length() as u64;
                    reps = [Some(distance), reps[0], reps[1], reps[2]];
                    last_length = Some(length);
                    (length, Some(distance), true)
                }
                tape_kind::REP => {
                    let k = op.distance as usize;
                    let length = op.length() as u64;
                    let chosen = reps.get(k).copied().flatten();
                    if k < reps.len() {
                        let mut moved = reps;
                        moved[0] = reps[k];
                        moved[1..=k].copy_from_slice(&reps[..k]);
                        reps = moved;
                    }
                    last_length = Some(length);
                    (length, chosen, chosen.is_some())
                }
                tape_kind::REP_LAST => {
                    // Takes the last match's length and the last distance,
                    // and rotates nothing.
                    let length = last_length.unwrap_or(0);
                    (length, reps[0], last_length.is_some() && reps[0].is_some())
                }
                _ => {
                    // A filter. It produces no byte of its own and it
                    // changes none that a match can read: SPEC-H2 3.6 says
                    // the window keeps the UNFILTERED bytes, so a later
                    // match reaching into a filtered span reads what the
                    // LZ decoder wrote there. So it is NOT a barrier to a
                    // lane's sources and `valid_from` does not move. It is
                    // still an operation the apply thread must visit in
                    // archive order, because its span resolves against the
                    // bytes the member has produced, so it closes the run.
                    loc[LOC_FILTERS] += 1;
                    if run_open {
                        loc[LOC_RESIDUAL_RUNS] += 1;
                        run_open = false;
                    }
                    loc[LOC_RESIDUAL_OTHER] += 1;
                    if opt_run_open {
                        loc[LOC_CEIL_RUNS] += 1;
                        opt_run_open = false;
                    }
                    loc[LOC_CEIL_OTHER] += 1;
                    continue;
                }
            };
            let repeat = kind != tape_kind::MATCH;
            if repeat {
                loc[LOC_REPEATS] += 1;
            } else {
                loc[LOC_MATCHES] += 1;
            }
            // The two questions, and they are not the same question: the
            // source may begin inside this block and still sit inside a
            // hole an earlier unresolved operation left.
            let intra = known && distance.is_some_and(|d| d <= staged);
            let in_lane = intra && distance.is_some_and(|d| staged - d >= valid_from);
            match (repeat, known, intra, in_lane) {
                (false, _, true, true) => loc[LOC_MATCH_IN_LANE] += 1,
                (false, _, true, false) => loc[LOC_MATCH_HOLE_BLOCKED] += 1,
                (false, _, false, _) => loc[LOC_MATCH_CROSS] += 1,
                (true, false, _, _) => loc[LOC_REP_UNKNOWN] += 1,
                (true, true, true, true) => loc[LOC_REP_IN_LANE] += 1,
                (true, true, true, false) => loc[LOC_REP_HOLE_BLOCKED] += 1,
                (true, true, false, _) => loc[LOC_REP_CROSS] += 1,
            }
            if !repeat && intra {
                loc[LOC_MATCH_INTRA] += 1;
            }
            if repeat && intra {
                loc[LOC_REP_INTRA] += 1;
            }
            loc[LOC_BYTES] += length;
            // The ceiling's own accounting, on `intra` rather than on
            // `in_lane`: the operation still has to be SEPARATED from the
            // ones around it by a run, and that run is an operation too,
            // which is the arithmetic this whole direction turns on.
            if intra {
                opt_run_open = true;
            } else {
                if opt_run_open {
                    loc[LOC_CEIL_RUNS] += 1;
                    opt_run_open = false;
                }
                loc[LOC_CEIL_OTHER] += 1;
            }
            if in_lane {
                // Resolved on a lane thread and written into the staging
                // buffer, so the apply thread never sees it as an
                // operation: it arrives inside a run.
                loc[LOC_BYTES_IN_LANE] += length;
                staged += length;
                run_open = true;
            } else {
                if run_open {
                    loc[LOC_RESIDUAL_RUNS] += 1;
                    run_open = false;
                }
                loc[LOC_RESIDUAL_OTHER] += 1;
                staged += length;
                // The bytes this operation produced are the apply thread's
                // and the lane does not hold them.
                valid_from = staged;
            }
        }
        match tape.parked_at {
            Some(next) if next > at => {
                loc[LOC_PARKS] += 1;
                at = next;
            }
            _ => break,
        }
    }
    if run_open {
        loc[LOC_RESIDUAL_RUNS] += 1;
    }
    if opt_run_open {
        loc[LOC_CEIL_RUNS] += 1;
    }
    loc[LOC_STAGE_MAX] = loc[LOC_STAGE_MAX].max(staged);
    Ok(())
}

/// One block's share of `internals::rar5::reach`: every tape of it, the
/// far gate asked of each, and every fresh match placed in a distance band
/// (`internals::rar5::REACH_BANDS`). The slots are that function's.
#[cfg(feature = "h2-locality-census")]
pub(crate) fn reach_block(
    plan: &Plan,
    packed: &[u8],
    algorithm: u8,
    index: usize,
    tape: &mut BlockTape,
    out: &mut [u64; 22],
) -> Result<()> {
    let group = &plan.groups[plan.group_of[index]];
    let (tables, start) = group.get(plan, packed, algorithm, None)?;
    let mut at = if group.first == Some(index) { start } else { 0 };
    loop {
        decode_block_tape(&tables, packed, &plan.blocks[index], at, tape);
        out[2] += 1;
        let admitted = far_gate_admits(&tape.steps);
        out[3] += u64::from(admitted);
        for op in &tape.steps {
            out[4] += 1;
            match op.kind() {
                tape_kind::MATCH => {
                    let d = op.distance as usize;
                    let band = crate::internals::rar5::REACH_BANDS
                        .iter()
                        .take_while(|&&edge| d >= edge)
                        .count();
                    out[6 + band] += 1;
                    out[13 + band] += op.length() as u64;
                    if d >= Window::far_distance() {
                        out[if admitted { 20 } else { 21 }] += 1;
                    }
                }
                tape_kind::REP | tape_kind::REP_LAST => out[5] += 1,
                _ => {}
            }
        }
        match tape.parked_at {
            Some(next) if next > at => at = next,
            _ => break,
        }
    }
    Ok(())
}

/// Slots of the count `locality_block` fills.
#[cfg(feature = "h2-locality-census")]
pub(crate) const LOCALITY_BUCKETS: usize = 22;

/// Operations the one apply thread walks today.
#[cfg(feature = "h2-locality-census")]
pub(crate) const LOC_OPS: usize = 0;

#[cfg(feature = "h2-locality-census")]
pub(crate) const LOC_LIT_RUNS: usize = 1;

#[cfg(feature = "h2-locality-census")]
pub(crate) const LOC_MATCHES: usize = 2;

/// Matches whose source lies wholly inside the block's produced bytes.
#[cfg(feature = "h2-locality-census")]
pub(crate) const LOC_MATCH_INTRA: usize = 3;

/// Matches reaching back before the block's start.
#[cfg(feature = "h2-locality-census")]
pub(crate) const LOC_MATCH_CROSS: usize = 4;

/// Matches a lane could resolve for itself, holes accounted for.
#[cfg(feature = "h2-locality-census")]
pub(crate) const LOC_MATCH_IN_LANE: usize = 5;

/// Intra-block matches an earlier hole puts out of the lane's reach.
#[cfg(feature = "h2-locality-census")]
pub(crate) const LOC_MATCH_HOLE_BLOCKED: usize = 6;

#[cfg(feature = "h2-locality-census")]
pub(crate) const LOC_REPEATS: usize = 7;

#[cfg(feature = "h2-locality-census")]
pub(crate) const LOC_REP_INTRA: usize = 8;

#[cfg(feature = "h2-locality-census")]
pub(crate) const LOC_REP_CROSS: usize = 9;

/// Repeats naming a slot an earlier block set, which a lane cannot know.
#[cfg(feature = "h2-locality-census")]
pub(crate) const LOC_REP_UNKNOWN: usize = 10;

#[cfg(feature = "h2-locality-census")]
pub(crate) const LOC_REP_IN_LANE: usize = 11;

#[cfg(feature = "h2-locality-census")]
pub(crate) const LOC_REP_HOLE_BLOCKED: usize = 12;

#[cfg(feature = "h2-locality-census")]
pub(crate) const LOC_FILTERS: usize = 13;

/// Runs of staged bytes the apply thread would copy, one call each.
#[cfg(feature = "h2-locality-census")]
pub(crate) const LOC_RESIDUAL_RUNS: usize = 14;

/// Operations left in archive order for the apply thread to resolve.
#[cfg(feature = "h2-locality-census")]
pub(crate) const LOC_RESIDUAL_OTHER: usize = 15;

/// Bytes the member produces.
#[cfg(feature = "h2-locality-census")]
pub(crate) const LOC_BYTES: usize = 16;

/// Match bytes resolved on a lane thread, off the apply thread entirely.
#[cfg(feature = "h2-locality-census")]
pub(crate) const LOC_BYTES_IN_LANE: usize = 17;

/// The largest single block's staged bytes, which is what a lane's
/// staging buffer would have to hold.
#[cfg(feature = "h2-locality-census")]
pub(crate) const LOC_STAGE_MAX: usize = 18;

#[cfg(feature = "h2-locality-census")]
pub(crate) const LOC_PARKS: usize = 19;

/// The CEILING: staged runs left if every hole were wished away.
#[cfg(feature = "h2-locality-census")]
pub(crate) const LOC_CEIL_RUNS: usize = 20;

/// The CEILING: operations left if every hole were wished away.
#[cfg(feature = "h2-locality-census")]
pub(crate) const LOC_CEIL_OTHER: usize = 21;
