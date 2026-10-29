//! Carried from the predecessor's `codec/address_filters.rs` at an earlier revision: items ours from birth
//! per the provenance census (and clean-room outputs, clean by provenance).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Direction {
    /// Filtered bytes back to the original bytes (the archive reader).
    Decode,
    /// Original bytes to filtered bytes (the archive writer).
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    Encode,
}
/// The ARM branch-with-link transform.
pub(crate) fn arm(data: &mut [u8], file_offset: u32, direction: Direction) {
    match direction {
        Direction::Decode => arm_pass::<false>(data, file_offset),
        Direction::Encode => arm_pass::<true>(data, file_offset),
    }
}
/// The IA-64 branch transform.
pub(crate) fn ia64(data: &mut [u8], file_offset: u32, direction: Direction) {
    match direction {
        Direction::Decode => ia64_pass::<false>(data, file_offset),
        Direction::Encode => ia64_pass::<true>(data, file_offset),
    }
}
// ---------------------------------------------------------------------------
// x86
// ---------------------------------------------------------------------------

/// The absolute-target window: 16 MiB.
pub(crate) const WINDOW: u32 = 1 << 24;
/// Operands are displacements of near calls and jumps. The encoder turns a
/// displacement whose target lands inside the window into that absolute
/// target, which repeats across a binary and compresses better; the decoder
/// turns it back. Seen as signed values, both directions work cyclically on
/// the interval `[-offset, WINDOW)`: decode subtracts `offset`, encode adds
/// it, and anything outside the interval is left alone.
///
/// **THE SPLIT. It scans the block first and converts after**, a window of
/// triggers at a time, rather than walking from one trigger to the next.
/// The two are exactly equivalent because the scan reads only OPCODE bytes
/// and the conversion writes only OPERAND bytes, and the format's rule that
/// the scan resumes five bytes past a trigger means no accepted operand is
/// ever an opcode the scan tests.
///
/// **THIS IS NO LONGER THE SHIPPED BODY.** It shipped from 21 Sep 2026 to
/// 22 Sep 2026 and [`x86_pass_walking`] has it back. It is kept, reachable
/// through `internals::rar5::rar5_x86_pass` arm 1, because the reason it
/// was built is real and the reason it was withdrawn is narrow, and later
/// work should inherit a measured arm rather than a hunch.
///
/// **What it is good at.** Walking trigger to trigger puts the operand
/// load, the mapping and the store on the loop's own chain, because the
/// address of the next word probed depends on the position of the trigger
/// just converted: about 18 cycles a trigger at a trigger every 13 bytes,
/// several times the instructions it issues. Scanning at a fixed stride
/// takes the conversions off that chain, and scanning a whole window ahead
/// of them lets the two phases issue against each other. Over 32 MiB of the
/// bench suite's x86 corpus, type 2, 0.356 ns a byte walking against 0.236
/// scanned and split, **1.51x** (M3 Ultra, 21 Sep 2026).
///
/// **Why it was withdrawn anyway, and it is not that the figure above is
/// wrong.** That figure is taken at 13.33 bytes a trigger, which is what
/// `two_arm.rs`'s `x86_corpus` emits by construction and which is the one
/// regime where the split leads. Over 3,039 filter blocks that reference
/// `rar` framed ITSELF over real x86-64 binaries - 177 MB, the encoder's
/// own detector choosing the regions - the walking body is **17 percent
/// faster, in every trigger-gap band and on both record types**, and the
/// real population's block median trigger gap runs 22 at its tenth
/// percentile to 43 at its ninetieth. The suite's own legs sit below that
/// tenth percentile. The bench record of 22 Sep 2026 has the table,
/// the null control and the two readings of why the crossover the
/// synthetic sweep showed is absent from real data.
///
/// `the_walking_and_the_split_x86_passes_agree` holds the two to the same
/// bytes on every direction and both record types, whichever ships.
#[cfg_attr(not(feature = "bench-internals"), allow(dead_code))]
#[inline(never)]
pub(crate) fn x86_pass<const ENCODE: bool, const JUMP: bool, const RAR5: bool>(
    data: &mut [u8],
    file_offset: u32,
) {
    /// Triggers held between the two phases. A window this size keeps the
    /// buffer in cache and needs no allocation, which the RAR 5 decoder's
    /// "no allocation per block" requirement asks of every path it calls.
    const BATCH: usize = 256;

    // A trigger needs four whole bytes after its opcode, so the last usable
    // position is `len - 5` and `limit` bounds it.
    let Some(limit) = data.len().checked_sub(4) else {
        return;
    };
    let mut found = [0usize; BATCH];
    let mut at = 0usize;
    // The first position the scan may accept: five past the last trigger.
    let mut resume = 0usize;
    // Bytes crossed with no trigger in them. Past `X86_PROBE_BYTES` the
    // block is sparse here and the vector search is the better shape, which
    // is the whole of that constant's argument.
    let mut barren = 0usize;
    // Set when the word scan can go no further and the byte at a time tail
    // takes over.
    let mut tail = false;
    while at < limit && !tail {
        // PHASE 1: scan, reading only opcode bytes.
        let mut count = 0usize;
        while count + 8 <= BATCH {
            if at >= limit {
                break;
            }
            let Some(word) = data.get(at..).and_then(|rest| rest.first_chunk::<8>()) else {
                tail = true;
                break;
            };
            let mut hits = x86_trigger_bits::<JUMP>(u64::from_le_bytes(*word));
            at += 8;
            if hits == 0 {
                barren += 8;
                if barren >= X86_PROBE_BYTES {
                    let Some(rest) = data.get(at..limit) else {
                        break;
                    };
                    let step = if JUMP {
                        memchr::memchr2(0xe8, 0xe9, rest)
                    } else {
                        memchr::memchr(0xe8, rest)
                    };
                    match step {
                        // Back to the scan's stride. The word scan would
                        // find the trigger either way; this only keeps the
                        // two aligned, and no test rests on it.
                        Some(index) => {
                            at += index & !7;
                            barren = 0;
                        }
                        None => {
                            at = limit;
                            break;
                        }
                    }
                }
                continue;
            }
            barren = 0;
            while hits != 0 {
                let position = at - 8 + (hits.trailing_zeros() / 8) as usize;
                hits &= hits - 1;
                if position < resume || position >= limit {
                    continue;
                }
                // The mask never MISSES a trigger byte, but a borrow out of
                // one can set a bit above it, so the byte itself decides.
                if data
                    .get(position)
                    .is_some_and(|&byte| is_x86_trigger::<JUMP>(byte))
                {
                    found[count] = position;
                    count += 1;
                    resume = position + 5;
                }
            }
        }
        // PHASE 2: convert, writing only operand bytes.
        for &position in &found[..count] {
            convert_x86_operand::<ENCODE, RAR5>(data, position, file_offset);
        }
    }
    // Fewer than eight bytes left to look at.
    while at < limit {
        if at >= resume && is_x86_trigger::<JUMP>(data[at]) {
            convert_x86_operand::<ENCODE, RAR5>(data, at, file_offset);
            resume = at + 5;
        }
        at += 1;
    }
}

// ---------------------------------------------------------------------------
// Candidates priced against the SPLIT body. All three keep the shipped
// body's two phases and change ONE thing each, so the probe's arms subtract
// rather than compare whole designs. None of them ships unless the
// subtraction says it wins; they live behind `bench-internals`.
// ---------------------------------------------------------------------------

/// The shipped split body with its trigger window size made a parameter.
///
/// `x86_pass` fixes that window at 256. Nothing measured it: 256 was chosen
/// so the array stays in cache and needs no allocation, both of which hold
/// over a wide range. The window sets how far phase one runs ahead of phase
/// two, so it trades the two phases' ability to issue against each other
/// (which wants it large) against the distance between a byte's scan and its
/// conversion (which wants it small enough to stay in L1).
#[cfg(feature = "bench-internals")]
pub(crate) fn x86_pass_split_batch<
    const ENCODE: bool,
    const JUMP: bool,
    const RAR5: bool,
    const BATCH: usize,
>(
    data: &mut [u8],
    file_offset: u32,
) {
    let Some(limit) = data.len().checked_sub(4) else {
        return;
    };
    let mut found = [0usize; BATCH];
    let mut at = 0usize;
    let mut resume = 0usize;
    let mut barren = 0usize;
    let mut tail = false;
    while at < limit && !tail {
        let mut count = 0usize;
        while count + 8 <= BATCH {
            if at >= limit {
                break;
            }
            let Some(word) = data.get(at..).and_then(|rest| rest.first_chunk::<8>()) else {
                tail = true;
                break;
            };
            let mut hits = x86_trigger_bits::<JUMP>(u64::from_le_bytes(*word));
            at += 8;
            if hits == 0 {
                barren += 8;
                if barren >= X86_PROBE_BYTES {
                    let Some(rest) = data.get(at..limit) else {
                        break;
                    };
                    let step = if JUMP {
                        memchr::memchr2(0xe8, 0xe9, rest)
                    } else {
                        memchr::memchr(0xe8, rest)
                    };
                    match step {
                        Some(index) => {
                            at += index & !7;
                            barren = 0;
                        }
                        None => {
                            at = limit;
                            break;
                        }
                    }
                }
                continue;
            }
            barren = 0;
            while hits != 0 {
                let position = at - 8 + (hits.trailing_zeros() / 8) as usize;
                hits &= hits - 1;
                if position < resume || position >= limit {
                    continue;
                }
                if data
                    .get(position)
                    .is_some_and(|&byte| is_x86_trigger::<JUMP>(byte))
                {
                    found[count] = position;
                    count += 1;
                    resume = position + 5;
                }
            }
        }
        for &position in &found[..count] {
            convert_x86_operand::<ENCODE, RAR5>(data, position, file_offset);
        }
    }
    while at < limit {
        if at >= resume && is_x86_trigger::<JUMP>(data[at]) {
            convert_x86_operand::<ENCODE, RAR5>(data, at, file_offset);
            resume = at + 5;
        }
        at += 1;
    }
}

/// The shipped split body with phase one taking SIXTEEN bytes a step from
/// two independent word loads instead of eight from one.
///
/// The split already broke the walk's dependency chain, so what is left to
/// win in phase one is issue width rather than latency: two loads whose
/// addresses are both induction variables can be in flight together. This
/// is the portable half of that question; `x86_pass_split_neon` is the
/// other half and they answer it differently, so both are priced.
#[cfg(feature = "bench-internals")]
pub(crate) fn x86_pass_split_wide<const ENCODE: bool, const JUMP: bool, const RAR5: bool>(
    data: &mut [u8],
    file_offset: u32,
) {
    const BATCH: usize = 256;
    let Some(limit) = data.len().checked_sub(4) else {
        return;
    };
    let mut found = [0usize; BATCH];
    let mut at = 0usize;
    let mut resume = 0usize;
    let mut barren = 0usize;
    let mut tail = false;
    while at < limit && !tail {
        let mut count = 0usize;
        while count + 16 <= BATCH {
            if at >= limit {
                break;
            }
            let Some(chunk) = data.get(at..).and_then(|rest| rest.first_chunk::<16>()) else {
                tail = true;
                break;
            };
            // Two independent loads, neither waiting on the other's result.
            let (Some(low), Some(high)) = (chunk.first_chunk::<8>(), chunk.last_chunk::<8>())
            else {
                tail = true;
                break;
            };
            let low_hits = x86_trigger_bits::<JUMP>(u64::from_le_bytes(*low));
            let high_hits = x86_trigger_bits::<JUMP>(u64::from_le_bytes(*high));
            at += 16;
            if low_hits == 0 && high_hits == 0 {
                barren += 16;
                if barren >= X86_PROBE_BYTES {
                    let Some(rest) = data.get(at..limit) else {
                        break;
                    };
                    let step = if JUMP {
                        memchr::memchr2(0xe8, 0xe9, rest)
                    } else {
                        memchr::memchr(0xe8, rest)
                    };
                    match step {
                        Some(index) => {
                            at += index & !15;
                            barren = 0;
                        }
                        None => {
                            at = limit;
                            break;
                        }
                    }
                }
                continue;
            }
            barren = 0;
            for (half, mut hits) in [(16usize, low_hits), (8usize, high_hits)] {
                while hits != 0 {
                    let position = at - half + (hits.trailing_zeros() / 8) as usize;
                    hits &= hits - 1;
                    if position < resume || position >= limit {
                        continue;
                    }
                    if data
                        .get(position)
                        .is_some_and(|&byte| is_x86_trigger::<JUMP>(byte))
                    {
                        found[count] = position;
                        count += 1;
                        resume = position + 5;
                    }
                }
            }
        }
        for &position in &found[..count] {
            convert_x86_operand::<ENCODE, RAR5>(data, position, file_offset);
        }
    }
    while at < limit {
        if at >= resume && is_x86_trigger::<JUMP>(data[at]) {
            convert_x86_operand::<ENCODE, RAR5>(data, at, file_offset);
            resume = at + 5;
        }
        at += 1;
    }
}

/// The shipped split body with phase one on a sixteen byte NEON compare.
///
/// The x86-pass work measured a NEON scan that CONVERTED as it went at
/// 0.7703x of the walking form and retired it: a wider vector does nothing
/// for a dependency chain. The same work measured a NEON COLLECT at 1.7627x
/// on a micro. Neither reading transfers to this base, because both were
/// taken against the WALKING body and this body already collects. What is
/// open is whether sixteen bytes a compare beats eight bytes of SWAR once
/// the chain is already gone, which is a question about issue width alone.
#[cfg(all(feature = "bench-internals", target_arch = "aarch64"))]
pub(crate) fn x86_pass_split_neon<const ENCODE: bool, const JUMP: bool, const RAR5: bool>(
    data: &mut [u8],
    file_offset: u32,
) {
    #![allow(unsafe_code)]
    use std::arch::aarch64::{
        vceqq_u8, vdupq_n_u8, vget_lane_u64, vld1q_u8, vorrq_u8, vreinterpret_u64_u8,
        vreinterpretq_u16_u8, vshrn_n_u16,
    };
    const BATCH: usize = 256;
    let Some(limit) = data.len().checked_sub(4) else {
        return;
    };
    let mut found = [0usize; BATCH];
    let mut at = 0usize;
    let mut resume = 0usize;
    let mut tail = false;
    while at < limit && !tail {
        let mut count = 0usize;
        while count + 16 <= BATCH {
            if at + 16 > limit {
                tail = true;
                break;
            }
            // SAFETY: `at + 16 <= limit <= data.len()`, so sixteen bytes are
            // in bounds at `at`.
            let vector = unsafe { vld1q_u8(data.as_ptr().add(at)) };
            // SAFETY: intrinsics over values only, no memory reached.
            let mut bits = unsafe {
                let equal = if JUMP {
                    vceqq_u8(vorrq_u8(vector, vdupq_n_u8(1)), vdupq_n_u8(0xe9))
                } else {
                    vceqq_u8(vector, vdupq_n_u8(0xe8))
                };
                // Four bits a lane, so a lane's index is its nibble's.
                vget_lane_u64(
                    vreinterpret_u64_u8(vshrn_n_u16(vreinterpretq_u16_u8(equal), 4)),
                    0,
                )
            };
            at += 16;
            while bits != 0 {
                let lane = (bits.trailing_zeros() / 4) as usize;
                bits &= !(0xfu64 << (lane * 4));
                let position = at - 16 + lane;
                if position < resume || position >= limit {
                    continue;
                }
                found[count] = position;
                count += 1;
                resume = position + 5;
            }
        }
        for &position in &found[..count] {
            convert_x86_operand::<ENCODE, RAR5>(data, position, file_offset);
        }
    }
    while at < limit {
        if at >= resume && is_x86_trigger::<JUMP>(data[at]) {
            convert_x86_operand::<ENCODE, RAR5>(data, at, file_offset);
            resume = at + 5;
        }
        at += 1;
    }
}

/// The shipped split body with the five byte skip moved OUT of phase one.
///
/// This is the one structural difference between the shipped body and the
/// x86-pass work's retired `collect` prototype, and it is the arm most
/// likely to matter. The shipped phase one carries `resume` in its inner
/// bit loop, so accepting a trigger writes a variable the next acceptance
/// reads: a loop carried dependency, which is the very thing the split
/// existed to remove, left behind in a smaller place. Here phase one
/// records EVERY trigger byte and phase two applies the skip against
/// `next_allowed`, where it costs a compare against a register.
///
/// **It stays correct across a window boundary, which is not obvious and
/// is the reason the retired prototype cannot simply be dropped in.** That
/// prototype scanned the WHOLE block before converting anything, so no
/// byte a conversion wrote was ever scanned. Windowing breaks that: phase
/// two of window `k` writes operand bytes that phase one of window `k + 1`
/// may read, and a written byte can be `0xE8`. It is discarded anyway.
/// Every byte a conversion writes lies in `[p + 1, p + 4]` for an accepted
/// trigger at `p`, and that acceptance sets `next_allowed` to `p + 5`,
/// which is greater than every one of them. So a written byte can be
/// collected but can never be converted, PROVIDED `next_allowed` carries
/// across windows rather than resetting with each one.
#[cfg(feature = "bench-internals")]
pub(crate) fn x86_pass_split_late<
    const ENCODE: bool,
    const JUMP: bool,
    const RAR5: bool,
    const BATCH: usize,
>(
    data: &mut [u8],
    file_offset: u32,
) {
    let Some(limit) = data.len().checked_sub(4) else {
        return;
    };
    let mut found = [0usize; BATCH];
    let mut at = 0usize;
    // Carried ACROSS windows: see the doc comment. Resetting this per
    // window would convert an operand byte the scan had written.
    let mut next_allowed = 0usize;
    let mut barren = 0usize;
    let mut tail = false;
    while at < limit && !tail {
        let mut count = 0usize;
        while count + 8 <= BATCH {
            if at >= limit {
                break;
            }
            let Some(word) = data.get(at..).and_then(|rest| rest.first_chunk::<8>()) else {
                tail = true;
                break;
            };
            let mut hits = x86_trigger_bits::<JUMP>(u64::from_le_bytes(*word));
            at += 8;
            if hits == 0 {
                barren += 8;
                if barren >= X86_PROBE_BYTES {
                    let Some(rest) = data.get(at..limit) else {
                        break;
                    };
                    let step = if JUMP {
                        memchr::memchr2(0xe8, 0xe9, rest)
                    } else {
                        memchr::memchr(0xe8, rest)
                    };
                    match step {
                        Some(index) => {
                            at += index & !7;
                            barren = 0;
                        }
                        None => {
                            at = limit;
                            break;
                        }
                    }
                }
                continue;
            }
            barren = 0;
            // No `resume` here: nothing this loop writes is read by it.
            while hits != 0 {
                let position = at - 8 + (hits.trailing_zeros() / 8) as usize;
                hits &= hits - 1;
                if position >= limit {
                    continue;
                }
                if data
                    .get(position)
                    .is_some_and(|&byte| is_x86_trigger::<JUMP>(byte))
                {
                    found[count] = position;
                    count += 1;
                }
            }
        }
        // PHASE 2, which is where the five byte skip lives now.
        for &position in &found[..count] {
            if position < next_allowed {
                continue;
            }
            convert_x86_operand::<ENCODE, RAR5>(data, position, file_offset);
            next_allowed = position + 5;
        }
    }
    while at < limit {
        if at >= next_allowed && is_x86_trigger::<JUMP>(data[at]) {
            convert_x86_operand::<ENCODE, RAR5>(data, at, file_offset);
            next_allowed = at + 5;
        }
        at += 1;
    }
}

/// Phase one on a SIXTEEN byte NEON compare, with every other property of
/// the shipped body kept: the five byte skip inside the scan, the sparse
/// `memchr` path, the byte at a time tail, and the same
/// [`convert_x86_operand`] for phase two.
///
/// **This is the shippable form of the arm the 22 Sep subtraction found**,
/// and it differs from the prototype that produced that figure in exactly
/// one way: the prototype had no sparse path. On the code corpus, a trigger
/// every 13.33 bytes, that path is never reached, so its absence cost the
/// measurement nothing and would have cost a sparse block everything. The
/// prototype is not what ships; this is.
///
/// **Why sixteen bytes pays here when width has lost three times before.**
/// The x86-pass work measured a NEON scan at 0.7703x and retired width;
/// the filter-drain work's fused attempt was 2x slower than walking and
/// its fixed stride alone only 1.25x. Every one of those measured width
/// against a body whose scan was still on a dependency chain, and width
/// buys nothing against a chain. The split removed the chain. Issue width
/// is what was left, and it is worth about a quarter on type 2 and a third
/// on type 1 (measured 22 Sep 2026).
///
/// **The byte re-check the SWAR path needs is NOT needed here.** That
/// re-check exists because a borrow out of a trigger byte can set bits
/// above it in the SWAR mask. `vceqq_u8` is an exact per lane compare, so
/// a set lane IS a trigger byte and there is nothing to re-check.
/// `the_split_candidates_agree_with_the_shipped_pass` holds this to the
/// SWAR body byte for byte and would fail if that were wrong.
#[cfg(all(feature = "bench-internals", target_arch = "aarch64"))]
#[inline(never)]
pub(crate) fn x86_pass_neon16<const ENCODE: bool, const JUMP: bool, const RAR5: bool>(
    data: &mut [u8],
    file_offset: u32,
) {
    #![allow(unsafe_code)]
    use std::arch::aarch64::{
        vceqq_u8, vdupq_n_u8, vget_lane_u64, vld1q_u8, vorrq_u8, vreinterpret_u64_u8,
        vreinterpretq_u16_u8, vshrn_n_u16,
    };
    const BATCH: usize = 256;
    const STEP: usize = 16;

    let Some(limit) = data.len().checked_sub(4) else {
        return;
    };
    let mut found = [0usize; BATCH];
    let mut at = 0usize;
    let mut resume = 0usize;
    let mut barren = 0usize;
    let mut tail = false;
    while at < limit && !tail {
        // PHASE 1: scan, reading only opcode bytes.
        let mut count = 0usize;
        while count + STEP <= BATCH {
            if at >= limit {
                break;
            }
            if at + STEP > data.len() {
                // Fewer than sixteen bytes left; the tail below takes over.
                tail = true;
                break;
            }
            // SAFETY: `at + STEP <= data.len()`, so sixteen bytes are in
            // bounds at `at`.
            let vector = unsafe { vld1q_u8(data.as_ptr().add(at)) };
            // SAFETY: intrinsics over values only, no memory reached.
            let mut hits = unsafe {
                let equal = if JUMP {
                    // Setting bit 0 everywhere folds 0xE8 onto 0xE9, so one
                    // compare covers both opcodes, as the SWAR path does.
                    vceqq_u8(vorrq_u8(vector, vdupq_n_u8(1)), vdupq_n_u8(0xe9))
                } else {
                    vceqq_u8(vector, vdupq_n_u8(0xe8))
                };
                // Four bits a lane, so lane `i` is nibble `i`.
                vget_lane_u64(
                    vreinterpret_u64_u8(vshrn_n_u16(vreinterpretq_u16_u8(equal), 4)),
                    0,
                )
            };
            at += STEP;
            if hits == 0 {
                barren += STEP;
                if barren >= X86_PROBE_BYTES {
                    // Sparse from here: the vector search crosses a barren
                    // run far faster than the compare does. This is the
                    // path the prototype lacked.
                    let Some(rest) = data.get(at..limit) else {
                        break;
                    };
                    let step = if JUMP {
                        memchr::memchr2(0xe8, 0xe9, rest)
                    } else {
                        memchr::memchr(0xe8, rest)
                    };
                    match step {
                        // Back to the scan's stride, as the SWAR body does.
                        // The compare would find the trigger either way;
                        // this only keeps the two aligned.
                        Some(index) => {
                            at += index & !(STEP - 1);
                            barren = 0;
                        }
                        None => {
                            at = limit;
                            break;
                        }
                    }
                }
                continue;
            }
            barren = 0;
            while hits != 0 {
                let lane = (hits.trailing_zeros() / 4) as usize;
                hits &= !(0xfu64 << (lane * 4));
                let position = at - STEP + lane;
                if position < resume || position >= limit {
                    continue;
                }
                found[count] = position;
                count += 1;
                resume = position + 5;
            }
        }
        // PHASE 2: convert, writing only operand bytes.
        for &position in &found[..count] {
            convert_x86_operand::<ENCODE, RAR5>(data, position, file_offset);
        }
    }
    // Fewer than sixteen bytes left to look at.
    while at < limit {
        if at >= resume && is_x86_trigger::<JUMP>(data[at]) {
            convert_x86_operand::<ENCODE, RAR5>(data, at, file_offset);
            resume = at + 5;
        }
        at += 1;
    }
}

/// Bytes a trigger at or below which the SPLIT is the better body.
///
/// The two passes cross over, and both sides of the crossover are
/// measured rather than argued (22 Sep 2026).
/// The split leads at 13.33 bytes a trigger, which is what this suite's
/// generated legs emit; the walking body leads over real filter blocks,
/// whose byte-weighted block median trigger gap runs 22 at the tenth
/// percentile to 43 at the ninetieth. So the crossover lies between 13
/// and 22 and this sits at the top of that band, where the split's lead
/// has already gone and walking's has not yet arrived: a mis-choice
/// either side of it costs little, and the band is narrow because the
/// real population does not live in it.
///
/// That is the AARCH64 reading, taken on an M1 Mac and on an M3 Mac, and
/// it is left exactly as it was measured.
#[cfg(not(target_arch = "x86_64"))]
pub(crate) const X86_SPLIT_UPTO: usize = 20;

/// Bytes a trigger at or below which the SPLIT is the better body: on
/// x86-64 there is no such density, so this is zero and every block
/// takes the walking form.
///
/// **The two architectures do not disagree about where the crossover
/// sits. They disagree about which body wins at the dense end, so on
/// x86-64 there is no crossover to place** (measured
/// 22 Sep 2026). Sixty cells on a small VPS, two seeds by two density
/// orders by fifteen density points, 15 pairs a cell, both arms selected
/// inside one process: the walking body leads in every one of them, by
/// 15 to 41 percent, from 8 bytes a trigger to 512. At 13, where aarch64
/// gives the split a lead of 1.51x, x86-64 gives walking a lead of 1.21
/// to 1.32x.
///
/// Zero rather than a number inside the aarch64 band because the
/// predicate is `count == 0 || at / count > X86_SPLIT_UPTO` and `at` is
/// never below `count`, so zero makes every block sparse. The block
/// still pays its FIRST BATCH as the split, which is about 3 KiB of a
/// 256 KiB block at the dense end; that residue is measured rather than
/// assumed, in the binary that carries this constant, by pairing the
/// pure walking arm against the adaptive one.
#[cfg(target_arch = "x86_64")]
pub(crate) const X86_SPLIT_UPTO: usize = 0;

/// The x86 address pass that CHOOSES its body per block.
///
/// Neither body wins everywhere. Over real filter blocks framed by
/// reference `rar` over real x86-64 binaries the walking form is 17
/// percent faster than the split; over this suite's generated legs at
/// 13.33 bytes a trigger the split is 1.51x faster. A block is handed to
/// this pass one at a time and its density is a property of the block, so
/// the choice belongs here rather than in a constant.
///
/// **The estimate is not a separate pass over the bytes.** It is the
/// SPLIT'S OWN FIRST SCAN, read for what it already knows. Phase 1 stops
/// after a batch of triggers or at the end of the block, and at that
/// point it has crossed `at` bytes and found `count` of them, which is
/// the density measured over a span the block itself chose: about 3 KiB
/// where triggers are 13 bytes apart and about 16 KiB where they are 64.
/// Nothing is scanned twice and nothing is scanned that would not have
/// been scanned anyway, so a dense block pays NOTHING for the choice and
/// a sparse one pays only the difference between the two bodies over the
/// first batch.
///
/// A block with no trigger in its first scan takes the walking form,
/// whose `next_x86_trigger` has the vector search sparse data wants.
#[inline(never)]
pub(crate) fn x86_pass_adaptive<const ENCODE: bool, const JUMP: bool, const RAR5: bool>(
    data: &mut [u8],
    file_offset: u32,
) {
    const BATCH: usize = 256;

    let Some(limit) = data.len().checked_sub(4) else {
        return;
    };
    let mut found = [0usize; BATCH];
    let mut at = 0usize;
    let mut resume = 0usize;
    let mut barren = 0usize;
    let mut tail = false;
    let mut first_batch = true;

    while at < limit && !tail {
        let mut count = 0usize;
        while count + 8 <= BATCH {
            if at >= limit {
                break;
            }
            let Some(word) = data.get(at..).and_then(|rest| rest.first_chunk::<8>()) else {
                tail = true;
                break;
            };
            let mut hits = x86_trigger_bits::<JUMP>(u64::from_le_bytes(*word));
            at += 8;
            if hits == 0 {
                barren += 8;
                if barren >= X86_PROBE_BYTES {
                    let Some(rest) = data.get(at..limit) else {
                        break;
                    };
                    let step = if JUMP {
                        memchr::memchr2(0xe8, 0xe9, rest)
                    } else {
                        memchr::memchr(0xe8, rest)
                    };
                    match step {
                        Some(index) => {
                            at += index & !7;
                            barren = 0;
                        }
                        None => {
                            at = limit;
                            break;
                        }
                    }
                }
                continue;
            }
            barren = 0;
            while hits != 0 {
                let position = at - 8 + (hits.trailing_zeros() / 8) as usize;
                hits &= hits - 1;
                if position < resume || position >= limit {
                    continue;
                }
                if data
                    .get(position)
                    .is_some_and(|&byte| is_x86_trigger::<JUMP>(byte))
                {
                    found[count] = position;
                    count += 1;
                    resume = position + 5;
                }
            }
        }
        for &position in &found[..count] {
            convert_x86_operand::<ENCODE, RAR5>(data, position, file_offset);
        }

        // THE CHOICE, made once, on what the scan above already measured.
        if first_batch {
            first_batch = false;
            let sparse = count == 0 || at / count > X86_SPLIT_UPTO;
            if sparse && resume < limit {
                // The walking form takes the rest. `resume` is five bytes
                // past the last trigger accepted, which is exactly where
                // the format's rule says a scan may next look, so no
                // operand byte is ever tested.
                visit_x86_operands_from::<JUMP>(data, resume, |position, operand| {
                    let mut offset = file_offset.wrapping_add(position as u32).wrapping_add(1);
                    if RAR5 {
                        offset &= WINDOW - 1;
                    }
                    let value = u32::from_le_bytes(*operand);
                    let mapped = if ENCODE {
                        x86_encode_operand(value, offset)
                    } else {
                        x86_decode_operand(value, offset)
                    };
                    *operand = mapped.to_le_bytes();
                });
                return;
            }
        }
    }
    while at < limit {
        if at >= resume && is_x86_trigger::<JUMP>(data[at]) {
            convert_x86_operand::<ENCODE, RAR5>(data, at, file_offset);
            resume = at + 5;
        }
        at += 1;
    }
}

/// Map the four operand bytes after the opcode at `position`.
#[inline(always)]
fn convert_x86_operand<const ENCODE: bool, const RAR5: bool>(
    data: &mut [u8],
    position: usize,
    file_offset: u32,
) {
    let Some(operand) = data
        .get_mut(position + 1..)
        .and_then(|rest| rest.first_chunk_mut::<4>())
    else {
        return;
    };
    // The operand's own position, one byte past its opcode. Truncating
    // `position` is exact: only its value modulo 2^32 can matter.
    let mut offset = file_offset.wrapping_add(position as u32).wrapping_add(1);
    if RAR5 {
        offset &= WINDOW - 1;
    }
    let value = u32::from_le_bytes(*operand);
    let mapped = if ENCODE {
        x86_encode_operand(value, offset)
    } else {
        x86_decode_operand(value, offset)
    };
    *operand = mapped.to_le_bytes();
}

#[inline(always)]
pub(crate) fn x86_decode_operand(value: u32, offset: u32) -> u32 {
    if value < WINDOW {
        // An absolute target inside the window (top byte zero).
        value.wrapping_sub(offset)
    } else if reaches_back(value, offset) {
        // A target below the start of the member, stored shifted up by one
        // window so it does not collide with the absolute targets.
        value.wrapping_add(WINDOW)
    } else {
        value
    }
}
#[inline(always)]
pub(crate) fn x86_encode_operand(value: u32, offset: u32) -> u32 {
    let absolute = value.wrapping_add(offset);
    let lowered = value.wrapping_sub(WINDOW);
    if absolute < WINDOW {
        absolute
    } else if reaches_back(lowered, offset) {
        lowered
    } else {
        value
    }
}
/// Whether `value` read as a signed displacement lies in `[-offset, 0)`.
///
/// That signed range is the rule while `offset <= 2^31`, which always holds
/// for RAR 5 (whose offset is reduced into the 16 MiB window). A RAR 3
/// operand past 2 GiB into its member has a larger offset, and there the
/// rule is stated on bit 31 instead: the value is negative and adding the
/// offset makes it non-negative.
///
/// The bit-31 statement covers BOTH cases, so this is one expression and not
/// a choice between two. For `value >= 2^31` and `offset <= 2^31` the sum
/// lies in `[2^31, 2^32 + 2^31)`, and it clears bit 31 exactly when it
/// wraps, which is exactly `value >= 2^32 - offset`, which is the signed
/// range. Writing it this way SPARES the RAR 3 arm a test of `offset` per
/// operand that it used to pay and that could never fail in practice: the
/// whole predicate is now three instructions with no branch in it.
#[inline(always)]
pub(crate) fn reaches_back(value: u32, offset: u32) -> bool {
    (value & !value.wrapping_add(offset)) >> 31 == 1
}
/// **THE SHIPPED x86 address pass**: ask for the next trigger, convert it,
/// resume five bytes on.
///
/// It is what this package ran until 21 Sep 2026, when [`x86_pass`]
/// replaced it on a 1.51x reading, and what it runs again from 22 Sep
/// 2026, when that reading turned out to hold at one trigger density and
/// to reverse at every other. Over real filter blocks framed by reference
/// `rar` over real x86-64 binaries it is 17 percent faster than the split,
/// in every trigger-gap band and on both record types; see [`x86_pass`]'s
/// comment (measured 22 Sep 2026).
///
/// The sparseness it needs is in [`next_x86_trigger`], not here: a word at
/// a time for `X86_PROBE_BYTES` and a vector search after that. No
/// equivalence test can catch that path going missing, because a scan
/// without it computes the same bytes and only takes longer, which is why
/// its worth is recorded in a density sweep rather than in a test.
///
/// `internals::rar5::rar5_x86_pass` arm 0 reaches this and arm 1 the
/// split, so a lab can price the two against each other in one binary, and
/// `the_walking_and_the_split_x86_passes_agree` holds them to the same
/// bytes on every direction and both record types.
#[cfg_attr(
    not(any(feature = "bench-internals", feature = "test-support")),
    allow(dead_code)
)]
#[inline(never)]
pub(crate) fn x86_pass_walking<const ENCODE: bool, const JUMP: bool, const RAR5: bool>(
    data: &mut [u8],
    file_offset: u32,
) {
    visit_x86_operands::<JUMP>(data, |position, operand| {
        // The operand's own position, one byte past its opcode. Truncating
        // `position` is exact: only its value modulo 2^32 can matter.
        let mut offset = file_offset.wrapping_add(position as u32).wrapping_add(1);
        if RAR5 {
            offset &= WINDOW - 1;
        }
        let value = u32::from_le_bytes(*operand);
        let mapped = if ENCODE {
            x86_encode_operand(value, offset)
        } else {
            x86_decode_operand(value, offset)
        };
        *operand = mapped.to_le_bytes();
    });
}

/// Calls `visit(position, operand)` for each trigger opcode, left to right,
/// where `operand` is the four bytes after the opcode byte at `position`.
///
/// After a trigger the scan resumes five bytes on, so operand bytes are never
/// tested, and a trigger without four whole bytes after it is ignored. Only
/// opcode bytes are tested and they are never written, so a buffer and its
/// transformed image visit the same positions in either direction.
#[inline(always)]
pub(crate) fn visit_x86_operands<const JUMP: bool>(
    data: &mut [u8],
    visit: impl FnMut(usize, &mut [u8; 4]),
) {
    visit_x86_operands_from::<JUMP>(data, 0, visit);
}

/// [`visit_x86_operands`] from a given position, which is what lets the
/// adaptive body hand the REST of a block to the walking form after the
/// split's first scan has already crossed the start of it.
///
/// `start` must be a position the format's own rule allows the scan to
/// resume at, which is five bytes past the last trigger accepted before
/// it. Anything else would test an operand byte.
#[inline(always)]
pub(crate) fn visit_x86_operands_from<const JUMP: bool>(
    data: &mut [u8],
    from: usize,
    mut visit: impl FnMut(usize, &mut [u8; 4]),
) {
    let mut start = from;
    while let Some(position) = next_x86_trigger::<JUMP>(data, start) {
        if let Some(operand) = data
            .get_mut(position + 1..)
            .and_then(|rest| rest.first_chunk_mut::<4>())
        {
            visit(position, operand);
        }
        start = position + 5;
    }
}
/// How far the word-at-a-time probe runs before the vector search takes
/// over, in bytes.
///
/// Measured on the `C1-tiled` bench corpus (a real executable), 16 Sep 2026:
/// scanning for calls alone, the gap from one trigger to the next is a
/// median of 17 bytes and NEVER under 8, while scanning for calls and jumps
/// half the gaps are under 8. So a probe one word wide resolved every
/// call-and-jump second gap and no call-only gap at all, and in the
/// call-only modes every trigger on that corpus paid a `memchr` call over a
/// ten-byte haystack - a non-inlined call with a vector prologue to cover a
/// distance a word probe crosses in two instructions. That is the whole of
/// the 0.76-0.86x x86-64 regression the 16 Sep round found, and the reason
/// it showed up in the call-only modes and not the call-and-jump ones.
///
/// A 32-byte probe covered 255 of that corpus's 256 call-only gaps, which is
/// what took the width from 8 to 32 and fixed that regression. It is 128 now,
/// for the reasons at the foot of this comment; the argument that used to
/// close this paragraph - that sparse data reaching the vector search after a
/// few more probes is "nothing against the run it is about to cross" - stays
/// RETRACTED. It is not nothing: crossing a sparse run at 128 costs up to 12%,
/// and that cost is measured rather than argued. What changed is not the cost
/// but whether anything on this path ever pays it.
///
/// **32 IS MEASURABLY A BAD WIDTH, ON BOTH ARCHITECTURES** (16 Sep
/// 2026). This comment used to say that
/// wider probes were rejected because they lose on sparse data, citing a
/// sweep over trigger-free runs; that sweep's corpus used a FIXED STRIDE,
/// which pins every `memchr` call at one alignment - and at a DIFFERENT
/// alignment for the 8-byte arm than for every wider one - and is worth a
/// factor of 2.4 to the baseline on its own. Re-drawn with GEOMETRIC gaps of
/// the same mean, on an M3 Ultra and on an x86 part, 32 is the worst or
/// second-worst arm on nearly every readable row of both: 64 or 128 wins for
/// dense and real-binary inputs, 8 or 16 wins past a mean gap of about 256,
/// and 256 is past the crossover everywhere. The retracted sweep and the
/// redraw are both of 16 Sep 2026.
///
/// **The callers of THIS constant have now been measured too, and 32 lost
/// there as well** (16 Sep 2026). They are the
/// filter-application path, which skips five bytes past each trigger and
/// converts as it goes, so its gaps are the chooser's minus four and its
/// per-trigger work is much larger - large enough that the scan might not have
/// been its bottleneck at all, which would have been a finding of its own. It
/// is: the address filter bench's probe-width leg, on four real Windows
/// PEs and on geometric-gap synthetics, puts 64 at 1.02-1.13x of 32 and 128 at
/// 1.05-1.18x on every real-binary row of BOTH architectures, and 32 is never
/// the best arm on any of them.
///
/// **128 rather than 64, and what decided it is the block census the previous
/// paragraph was waiting on** (16 Sep 2026). 128 is the better arm
/// on every real-binary row of both architectures and 64 is the safer one only
/// at the sparse end: past a median trigger gap of about 180 bytes the ordering
/// inverts, where 128's worst row of the sweep is 0.88x against 64's 0.95x. So
/// the question was never which arm is faster, it was whether a block this path
/// is GIVEN can be sparse. It cannot, on the read path any more than the write
/// one. Censused as a DECODE receives them - `examples/x86_block_census.rs`,
/// 102 archives written by real RAR 7.23 over real x86-64 and i386 binaries and
/// over 196 MB of non-code data, 3,150 blocks, 201 MB of filtered bytes, plus a
/// wild RAR 3.x archive of a real Windows application - **98.4% of filtered
/// bytes sit in blocks whose median trigger gap is 64 bytes or less**, the
/// byte-weighted p90 of that median is 38 and its p99 is 83. Not one byte of
/// non-code data was filtered at all: the encoder's own detector never fired on
/// text, PDFs, tarballs or high-entropy data, so the sparse block the maximin
/// reading was protecting against is not in the population.
///
/// **The one way to reach the sparse end is `-mce+`**, RAR's switch for
/// applying the x86 filter to all processed data whatever its detector thinks,
/// which its own manual introduces under "improper use of this switch". Forced
/// that way over the same non-code corpus, 30% of filtered bytes land in blocks
/// past a median gap of 180 and those blocks pay the 0.88x. That cost is
/// accepted deliberately and it is worth naming why: an archive built that way
/// is one where the filter was already a mistake, half of those bytes are in
/// blocks with fewer than two triggers - one long crossing, where the probe
/// width is a rounding error against the vector search - and it buys 3 to 9
/// points on every archive anybody actually makes.
pub(crate) const X86_PROBE_BYTES: usize = 128;
/// The first trigger at or after `start` that has a whole operand after it.
///
/// The crate's ONE x86 trigger scan since 16 Sep 2026. `src/fast.rs` carried a
/// second one - `next_x86_opcode`, taking a runtime `cmp_mask` and an explicit
/// end bound - which went straight to `memchr` on every call with no probe at
/// all; the RAR writer's carried x86 filter scan was its last
/// caller and now calls this, so that file is gone. The two differed only in
/// how they were parameterised: `cmp_mask` was `0xff` or `0xfe` and nothing
/// else, which is `JUMP`, and the end bound was always `data.len() - 4`, which
/// is what this computes. Neither difference was load-bearing, so there is
/// nothing here to re-derive later.
#[inline(always)]
pub(crate) fn next_x86_trigger<const JUMP: bool>(data: &[u8], start: usize) -> Option<usize> {
    let candidates = data.get(start..data.len().saturating_sub(4))?;
    // In code the next opcode is usually close: a word-at-a-time probe over
    // the first `X86_PROBE_BYTES` settles that before paying for a vector
    // search call, which is what sparse data needs instead.
    let mut probed = 0;
    while probed < X86_PROBE_BYTES {
        let rest = candidates.get(probed..)?;
        let Some(word) = rest.first_chunk::<8>() else {
            // Fewer than eight bytes left to look at.
            return rest
                .iter()
                .position(|&byte| is_x86_trigger::<JUMP>(byte))
                .map(|index| start + probed + index);
        };
        let hits = x86_trigger_bits::<JUMP>(u64::from_le_bytes(*word));
        if hits != 0 {
            return Some(start + probed + (hits.trailing_zeros() / 8) as usize);
        }
        probed += 8;
    }
    let rest = candidates.get(probed..)?;
    let found = if JUMP {
        memchr::memchr2(0xe8, 0xe9, rest)
    } else {
        memchr::memchr(0xe8, rest)
    };
    found.map(|index| start + probed + index)
}
#[inline(always)]
pub(crate) fn is_x86_trigger<const JUMP: bool>(byte: u8) -> bool {
    if JUMP {
        byte | 1 == 0xe9
    } else {
        byte == 0xe8
    }
}
/// Bit 7 of byte `i` of the result is set when byte `i` of `word` (little
/// endian) is a trigger. The lowest set bit is exact; a borrow can also set
/// bits above a real hit, but the caller reads only the lowest.
#[inline(always)]
pub(crate) fn x86_trigger_bits<const JUMP: bool>(word: u64) -> u64 {
    const ONES: u64 = 0x0101_0101_0101_0101;
    const HIGHS: u64 = 0x8080_8080_8080_8080;
    // Setting bit 0 everywhere folds 0xE8 onto 0xE9, so one comparison
    // covers both opcodes.
    let (folded, pattern) = if JUMP {
        (word | ONES, 0xe9 * ONES)
    } else {
        (word, 0xe8 * ONES)
    };
    let zero_where_trigger = folded ^ pattern;
    zero_where_trigger.wrapping_sub(ONES) & !zero_where_trigger & HIGHS
}
// ---------------------------------------------------------------------------
// ARM
// ---------------------------------------------------------------------------

/// Words are taken at multiples of four from the start of the block. A word
/// whose top byte is 0xEB (branch with link, condition "always") carries a
/// 24-bit offset counted in words; the encoder adds the word's own index
/// (the file offset in words), the decoder subtracts it. Trailing bytes that
/// do not fill a word are left alone.
#[inline(never)]
pub(crate) fn arm_pass<const ENCODE: bool>(data: &mut [u8], file_offset: u32) {
    // Only the index modulo 2^24 matters, so dividing the offset first and
    // then counting words (with 32-bit wrapping) gives the same field.
    let first_index = file_offset >> 2;
    // `chunks_exact_mut` leaves the trailing bytes out; every chunk it yields
    // is a whole word, so `first_chunk_mut` never misses one.
    for (index, chunk) in data.chunks_exact_mut(4).enumerate() {
        let Some(word) = chunk.first_chunk_mut::<4>() else {
            continue;
        };
        let value = u32::from_le_bytes(*word);
        let target = first_index.wrapping_add(index as u32);
        let shift = if ENCODE {
            target
        } else {
            target.wrapping_neg()
        };
        let moved = (value & 0xff00_0000) | (value.wrapping_add(shift) & 0x00ff_ffff);
        // Every word is written back, rewritten or not, so the loop has no
        // branch for the compiler to keep.
        *word = if value >> 24 == 0xeb { moved } else { value }.to_le_bytes();
    }
}
// ---------------------------------------------------------------------------
// IA-64
// ---------------------------------------------------------------------------

/// The 20-bit immediate field of an instruction slot.
pub(crate) const IA64_FIELD: u32 = 0x000f_ffff;
/// Which of a bundle's three instruction slots may hold a branch, by
/// template (bits 1-4 of the bundle's first byte). Three bits per template,
/// bit `j` for slot `j`, packed so the lookup is a shift and not a branch.
pub(crate) const IA64_BRANCH_SLOTS: u64 = ia64_slots(0x8, 0b100)
    | ia64_slots(0x9, 0b110)
    | ia64_slots(0xb, 0b111)
    | ia64_slots(0xc, 0b100)
    | ia64_slots(0xe, 0b100);
pub(crate) const fn ia64_slots(template: u32, slots: u64) -> u64 {
    slots << (3 * template)
}
/// Bundles are 16 bytes, aligned to the start of the block, and one is
/// processed only when at least six more bytes follow it. In each branch
/// slot whose 4-bit major opcode is 5, the 20-bit immediate is moved by the
/// bundle's index (the file offset in bundles), modulo 2^20.
#[inline(never)]
pub(crate) fn ia64_pass<const ENCODE: bool>(data: &mut [u8], file_offset: u32) {
    // `P + 22 <= n` for `P = 16k` admits exactly `(n - 6) / 16` bundles.
    let count = data.len().saturating_sub(6) / 16;
    let Some(region) = data.get_mut(..count * 16) else {
        return;
    };
    let first_index = file_offset >> 4;
    for (index, chunk) in region.chunks_exact_mut(16).enumerate() {
        let Some(bundle) = chunk.first_chunk_mut::<16>() else {
            continue;
        };
        let target = first_index.wrapping_add(index as u32);
        let shift = if ENCODE {
            target
        } else {
            target.wrapping_neg()
        };
        *bundle = ia64_bundle(u128::from_le_bytes(*bundle), shift).to_le_bytes();
    }
}
/// One bundle, read as a little-endian 128-bit integer.
///
/// Slot `j` starts at byte `2 + 5j` with its fields shifted up by `j + 2`
/// bits inside that byte-aligned word, so its immediate starts at bit
/// `8(2 + 5j) + j + 2 = 18 + 41j` and its major opcode 24 bits above that.
/// No write reaches the template, an opcode, or another slot's field, so
/// the three slots are independent.
#[inline(always)]
pub(crate) fn ia64_bundle(bundle: u128, shift: u32) -> u128 {
    let template = (bundle >> 1) as u32 & 0xf;
    let slots = (IA64_BRANCH_SLOTS >> (3 * template)) as u32;
    let mut out = bundle;
    for slot in 0..3 {
        let field_at = 18 + 41 * slot;
        let opcode = (bundle >> (field_at + 24)) as u32 & 0xf;
        // All ones over the field when this slot is a branch, zero otherwise:
        // chosen by masking rather than a test, so random templates cost the
        // processor no mispredicted branches.
        let branch = (slots >> slot) & u32::from(opcode == 5) & 1;
        let select = 0u32.wrapping_sub(branch) & IA64_FIELD;
        let field = (bundle >> field_at) as u32 & IA64_FIELD;
        let moved = field.wrapping_add(shift) & IA64_FIELD;
        out ^= u128::from((field ^ moved) & select) << field_at;
    }
    out
}
