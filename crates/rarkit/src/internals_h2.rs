//! Spec H2's RAR 5 LZ decoder, for this repository's own benches, fuzz
//! targets and differential tests (feature `bench-internals`).
//!
//! Not API: nothing here is stable, and the container walk below is test
//! scaffolding rather than the read path, which is spec F's.

use crate::memory::MemoryPolicy;
use crate::rar5_lz::block::block_in_hand;
use crate::rar5_lz::container;
use crate::rar5_lz::output::NullSink;
use crate::rar5_lz::tables::{TableScratch, Tables};
use crate::rar5_lz::{bits::BitReader, Rar5Lz, SliceSource};
use crate::Result;

pub use crate::rar5_lz::container::Member;

/// A policy that puts no window ceiling in the way, so a vector archive's
/// declared dictionary is never the thing under test here. Spec F's own
/// default is what a caller gets.
pub fn policy() -> MemoryPolicy {
    MemoryPolicy {
        working_limit: u64::MAX,
        max_window: 1 << 33,
        ..MemoryPolicy::default()
    }
}

/// The file members of a RAR 5 archive held in memory.
pub fn members(archive: &[u8]) -> Vec<Member> {
    container::members(archive)
}

/// Walk one member's block chain with `block_in_hand` alone, decoding no
/// symbol (SPEC-H2 sections 3.1 and 3.2). Answers how many blocks it saw.
pub fn walk_block_chain(packed: &[u8]) -> Result<usize> {
    let mut at = 0usize;
    let mut blocks = 0usize;
    while at < packed.len() {
        let block = block_in_hand(&packed[at..])?;
        blocks += 1;
        at += block.past();
        if block.ends_member() {
            break;
        }
    }
    Ok(blocks)
}

/// A member's blocks as the serial loop's eight bit literal batch sees
/// them: how many blocks, how many decode under a main table the batch
/// admits, and how many of those also hold 4 KiB of packed work after
/// their tables (the call sites' floor). Stops at the first block that
/// does not parse.
pub fn serial_batch_reach(packed: &[u8], algorithm: u8) -> (usize, usize, usize) {
    let mut tables = Tables::default();
    let mut scratch = TableScratch::default();
    let mut have_tables = false;
    let (mut blocks, mut admitted, mut worked) = (0, 0, 0);
    let mut at = 0usize;
    while at < packed.len() {
        let Ok(block) = block_in_hand(&packed[at..]) else {
            break;
        };
        let payload = block.payload(&packed[at..]);
        let mut bits = BitReader::new(payload, block.bits());
        if block.carries_tables() {
            if tables.read(&mut bits, algorithm, &mut scratch).is_err() {
                break;
            }
            have_tables = true;
        }
        blocks += 1;
        if have_tables && tables.main.serial_literal_admitted() {
            admitted += 1;
            if bits.remaining() >= 32768 {
                worked += 1;
            }
        }
        at += block.past();
        if block.ends_member() {
            break;
        }
    }
    (blocks, admitted, worked)
}

/// One block of a member as its header and tables state it, decoding no
/// symbol: the unrar-friendly writer work's count of how two writers lay a
/// member out (SPEC-H2 sections 3.2 and 3.3).
#[derive(Debug, Clone, Default)]
pub struct BlockShape {
    /// Header plus payload bytes.
    pub packed: usize,
    /// The payload's symbol bits after its tables, if it carries any.
    pub symbol_bits: usize,
    pub has_tables: bool,
    pub is_last: bool,
    /// Bits the tables took, zero when the block carries none.
    pub table_bits: usize,
    /// Code length histograms, index 0 counting unused symbols: main,
    /// distance, alignment and length alphabets.
    pub histograms: [[u32; 16]; 4],
}

/// Every block of one member's packed stream, in order. Stops at the
/// first block that does not parse.
pub fn block_shapes(packed: &[u8], algorithm: u8) -> Vec<BlockShape> {
    use crate::rar5_lz::tables::{distance_symbols, ALIGN_SYMBOLS, MAIN_SYMBOLS};
    let mut tables = Tables::default();
    let mut scratch = TableScratch::default();
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < packed.len() {
        let Ok(block) = block_in_hand(&packed[at..]) else {
            break;
        };
        let payload = block.payload(&packed[at..]);
        let mut bits = BitReader::new(payload, block.bits());
        let mut shape = BlockShape {
            packed: block.past(),
            has_tables: block.carries_tables(),
            is_last: block.ends_member(),
            ..BlockShape::default()
        };
        if block.carries_tables() {
            let before = bits.remaining();
            if tables.read(&mut bits, algorithm, &mut scratch).is_err() {
                break;
            }
            shape.table_bits = before - bits.remaining();
            let lengths = scratch.lengths();
            let ends = [
                MAIN_SYMBOLS,
                MAIN_SYMBOLS + distance_symbols(algorithm),
                MAIN_SYMBOLS + distance_symbols(algorithm) + ALIGN_SYMBOLS,
                lengths.len(),
            ];
            let mut start = 0;
            for (alphabet, &end) in ends.iter().enumerate() {
                for &length in &lengths[start..end] {
                    shape.histograms[alphabet][usize::from(length) & 15] += 1;
                }
                start = end;
            }
        }
        shape.symbol_bits = bits.remaining();
        out.push(shape);
        at += block.past();
        if block.ends_member() {
            break;
        }
    }
    out
}

/// What a member's table groups look like, for pricing the per block
/// table cost on archives whose writer puts tables in every small block.
#[derive(Debug, Default, Clone)]
pub struct TableCensus {
    /// Blocks in the chain.
    pub blocks: u64,
    /// Blocks that carry tables, each starting a group.
    pub groups: u64,
    /// Groups whose whole length list equals the previous group's.
    pub same_all: u64,
    /// Groups whose main, distance, align and length lists each equal the
    /// previous group's, one count per alphabet.
    pub same_part: [u64; 4],
    /// Symbols with a nonzero length, summed over groups, per alphabet.
    pub coded: [u64; 4],
    /// Main alphabet codes longer than the primary lookup, summed.
    pub main_long: u64,
    /// Payload bytes, summed over blocks, headers excluded.
    pub payload_bytes: u64,
    /// Bits the table groups take (the code length lists), summed.
    pub table_bits: u64,
}

/// Walk `packed`'s blocks and census their table groups: how many carry
/// tables, and how many of those repeat the previous group's lengths.
/// Stops at the first block that does not parse.
pub fn table_census(packed: &[u8], algorithm: u8) -> TableCensus {
    use crate::rar5_lz::tables::{distance_symbols, ALIGN_SYMBOLS, LUT_ENTRIES, MAIN_SYMBOLS};
    const LUT_BITS: u8 = LUT_ENTRIES.trailing_zeros() as u8;
    let mut tables = Tables::default();
    let mut scratch = TableScratch::default();
    let mut census = TableCensus::default();
    let mut previous: Vec<u8> = Vec::new();
    let distance = distance_symbols(algorithm);
    let bounds = [
        0,
        MAIN_SYMBOLS,
        MAIN_SYMBOLS + distance,
        MAIN_SYMBOLS + distance + ALIGN_SYMBOLS,
    ];
    let mut at = 0usize;
    while at < packed.len() {
        let Ok(block) = block_in_hand(&packed[at..]) else {
            break;
        };
        census.blocks += 1;
        census.payload_bytes += block.payload(&packed[at..]).len() as u64;
        if block.carries_tables() {
            let payload = block.payload(&packed[at..]);
            let mut bits = BitReader::new(payload, block.bits());
            if tables.read(&mut bits, algorithm, &mut scratch).is_err() {
                break;
            }
            census.table_bits += bits.position() as u64;
            let lengths = scratch.lengths();
            census.groups += 1;
            for part in 0..4 {
                let end = bounds.get(part + 1).copied().unwrap_or(lengths.len());
                let span = bounds[part]..end;
                census.coded[part] +=
                    lengths[span.clone()].iter().filter(|&&l| l != 0).count() as u64;
                if previous.len() == lengths.len() && previous[span.clone()] == lengths[span] {
                    census.same_part[part] += 1;
                }
            }
            census.main_long += lengths[..MAIN_SYMBOLS]
                .iter()
                .filter(|&&l| l > LUT_BITS)
                .count() as u64;
            if previous == lengths {
                census.same_all += 1;
            }
            previous.clear();
            previous.extend_from_slice(lengths);
        }
        at += block.past();
        if block.ends_member() {
            break;
        }
    }
    census
}

/// Read the tables of the first block of `packed` (section 3.3).
pub fn read_block_tables(packed: &[u8], algorithm: u8) -> Result<()> {
    let block = block_in_hand(packed)?;
    if !block.carries_tables() {
        return Ok(());
    }
    let mut bits = BitReader::new(block.payload(packed), block.bits());
    let mut tables = Tables::default();
    let mut scratch = TableScratch::default();
    tables.read(&mut bits, algorithm, &mut scratch)
}

/// Decode one non solid member into a buffer.
pub fn decode_member(
    packed: &[u8],
    unpacked: u64,
    window: u64,
    algorithm: u8,
    parallel: bool,
) -> Result<Vec<u8>> {
    let mut lz = Rar5Lz::new(window, &policy())?;
    lz.set_parallel(parallel);
    let mut sink: Vec<u8> = Vec::new();
    let mut source = SliceSource::new(packed);
    lz.member(&mut source, unpacked, algorithm, &mut sink)?;
    Ok(sink)
}

/// [`decode_member`] with the tape path's two scheduling knobs forced:
/// `tape_width`, the lanes one member's decode may spread over, and how
/// many blocks are in one wave.
///
/// Both are SCHEDULING and neither may change a byte (SPEC-H2 section 3.8,
/// consequence 2). A vector archive has too few blocks for the default
/// wave - twice the worker count - to cross a wave boundary at all, so a
/// small `wave_blocks` is the only way a test or a bench leg reaches the
/// overlap of wave N+1's decode with wave N's apply.
#[cfg(feature = "parallel")]
pub fn decode_member_scheduled(
    packed: &[u8],
    unpacked: u64,
    window: u64,
    algorithm: u8,
    tape_width: usize,
    wave_blocks: Option<usize>,
    overlap: bool,
) -> Result<Vec<u8>> {
    let mut lz = scheduled(window, tape_width, wave_blocks, overlap)?;
    let mut sink: Vec<u8> = Vec::new();
    let mut source = SliceSource::new(packed);
    lz.member(&mut source, unpacked, algorithm, &mut sink)?;
    Ok(sink)
}

/// [`decode_member_probe`] with the same two knobs, for the error kind and
/// the output position a damaged member stops at.
#[cfg(feature = "parallel")]
pub fn decode_member_probe_scheduled(
    packed: &[u8],
    unpacked: u64,
    window: u64,
    algorithm: u8,
    tape_width: usize,
    wave_blocks: Option<usize>,
    overlap: bool,
) -> (Vec<u8>, Option<String>) {
    let lz = scheduled(window, tape_width, wave_blocks, overlap);
    member_probe(lz, packed, unpacked, algorithm, true)
}

/// [`decode_member_probe_scheduled`] for a member that carries NO
/// checksum (see [`decode_member_probe_unchecked`]).
#[cfg(feature = "parallel")]
pub fn decode_member_probe_scheduled_unchecked(
    packed: &[u8],
    unpacked: u64,
    window: u64,
    algorithm: u8,
    tape_width: usize,
    wave_blocks: Option<usize>,
    overlap: bool,
) -> (Vec<u8>, Option<String>) {
    let lz = scheduled(window, tape_width, wave_blocks, overlap);
    member_probe(lz, packed, unpacked, algorithm, false)
}

/// One member through a decoder already set up, keeping what it produced
/// before an error. `checked` is whether the member carries a checksum,
/// which a reader knows and these seams must be told (SPEC-H2 3.1: a
/// filter span the stream completes past the declared size is
/// `FilterRange` under a checksum and passes without one).
fn member_probe(
    lz: Result<Rar5Lz>,
    packed: &[u8],
    unpacked: u64,
    algorithm: u8,
    checked: bool,
) -> (Vec<u8>, Option<String>) {
    let mut sink: Vec<u8> = Vec::new();
    let mut lz = match lz {
        Ok(lz) => lz,
        Err(err) => return (sink, Some(format!("{:?}", err.kind()))),
    };
    if !checked {
        lz.next_member_is_unchecked();
    }
    let mut source = SliceSource::new(packed);
    let outcome = lz.member(&mut source, unpacked, algorithm, &mut sink);
    let failure = outcome.err().map(|err| format!("{:?}", err.kind()));
    (sink, failure)
}

/// Every LZ member of an archive under forced scheduling, keeping the
/// solid chain: the `rar5_wave_overlap` bench legs, which price the
/// overlap of wave N+1's decode with wave N's apply against the bulk
/// synchronous driver it replaced, at a fixed tape width.
///
/// `tape_width` reaches `Rar5Lz::set_tape_width` and nothing else; it is
/// not a memory budget and does not touch [`policy`] (API 8.4.2, and see
/// `scheduled` below for what it cost when it did). `usize::MAX` asks for
/// the host's own width, which is what the `_wmax` legs want.
///
/// `overlap` off is that older driver: decode a wave, stop, apply it,
/// start the next. Both are scheduling and the bytes must be the same,
/// which is what the harness's own byte comparison then checks.
#[cfg(feature = "parallel")]
pub fn extract_scheduled(
    archive: &[u8],
    tape_width: usize,
    wave_blocks: Option<usize>,
    overlap: bool,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut lz: Option<Rar5Lz> = None;
    for member in container::members(archive) {
        if member.directory {
            continue;
        }
        if member.method == 0 {
            out.push((
                member.name.clone().into_bytes(),
                member.packed[..member.unpacked as usize].to_vec(),
            ));
            continue;
        }
        if !member.solid || lz.is_none() {
            lz = Some(scheduled(member.window, tape_width, wave_blocks, overlap)?);
        }
        let mut sink: Vec<u8> = Vec::with_capacity(member.unpacked as usize);
        let mut source = SliceSource::new(&member.packed);
        lz.as_mut().expect("a decoder for this member").member(
            &mut source,
            member.unpacked,
            member.algorithm,
            &mut sink,
        )?;
        out.push((member.name.clone().into_bytes(), sink));
    }
    Ok(out)
}

/// [`extract_scheduled`] to a null sink.
#[cfg(feature = "parallel")]
pub fn extract_counting_scheduled(
    archive: &[u8],
    tape_width: usize,
    wave_blocks: Option<usize>,
    overlap: bool,
) -> Result<u64> {
    let mut total = 0u64;
    let mut lz: Option<Rar5Lz> = None;
    for member in container::members(archive) {
        if member.directory || member.method == 0 {
            total += member.unpacked;
            continue;
        }
        if !member.solid || lz.is_none() {
            lz = Some(scheduled(member.window, tape_width, wave_blocks, overlap)?);
        }
        let mut sink = NullSink { bytes: 0 };
        let mut source = SliceSource::new(&member.packed);
        lz.as_mut().expect("a decoder for this member").member(
            &mut source,
            member.unpacked,
            member.algorithm,
            &mut sink,
        )?;
        total += sink.bytes;
    }
    Ok(total)
}

/// One decoder with the tape path on and its scheduling forced.
///
/// `tape_width` is a PARAMETER and not a field of the memory policy, and
/// the distinction is API 8.4.2's rather than this file's: a memory
/// budget is not a thread count, the read width is `ReadOptions::workers`,
/// and an earlier revision took the one off the other. The seams above used to
/// carry their width in a `MemoryPolicy { max_workers, ..policy() }` and
/// hand that to `Rar5Lz::new`, which stopped reading it at that revision, so
/// the argument was INERT: `rar5_wave_overlap_w2`, `_w4`, `_w8`,
/// `rar5_code_wave_overlap_w4`, `rar5_text_64m_m3_w4` and
/// `rar5_code_32m_m3_w4` every one ran at the engine's DEFAULT width
/// whatever its name said. A later revision made this function set the width;
/// carrying it as an argument is what stops the policy looking like a
/// width dial again, which is the shape 8.4 exists to forbid.
///
/// `policy()`'s own fields are left alone, so the no ceiling window
/// budget a vector archive needs is the same at every width. Two canaries
/// hold the property: `the_named_width_is_the_width_that_runs` in
/// `rar5_lz/tests.rs` for `decode_member_probe_scheduled`, and
/// `tests/internals_seam_named_width.rs` for `extract_scheduled`, which
/// is the one the gate rows come through.
#[cfg(feature = "parallel")]
fn scheduled(
    window: u64,
    tape_width: usize,
    wave_blocks: Option<usize>,
    overlap: bool,
) -> Result<Rar5Lz> {
    let mut lz = Rar5Lz::new(window, &policy())?;
    lz.set_parallel(true);
    lz.set_tape_width(tape_width.max(1));
    // A NAMED width, so it meets the lanes as a stated one does.
    lz.set_width_stated(true);
    lz.set_wave_blocks(wave_blocks);
    lz.set_overlap(overlap);
    Ok(lz)
}

/// Decode one non solid member on the piped lanes with the tape unit
/// forced to `unit` packed bytes (`Some(0)`: one block a unit, the
/// per-block form), for the tape unit's differential (SPEC-API 8.2).
#[cfg(feature = "parallel")]
pub fn decode_member_units(
    packed: &[u8],
    unpacked: u64,
    window: u64,
    algorithm: u8,
    tape_width: usize,
    unit: Option<usize>,
) -> Result<Vec<u8>> {
    let mut lz = scheduled(window, tape_width, None, true)?;
    lz.set_tape_unit(unit);
    let mut sink: Vec<u8> = Vec::new();
    let mut source = SliceSource::new(packed);
    lz.member(&mut source, unpacked, algorithm, &mut sink)?;
    Ok(sink)
}

/// How a member's whole chain cuts into tape units at `budget` packed
/// bytes: its block count, its unit count and the most blocks one unit
/// holds. Every block lies in exactly one unit, in order, or this panics.
#[cfg(feature = "parallel")]
pub fn tape_units(packed: &[u8], budget: usize) -> Result<(usize, usize, usize)> {
    tape_units_for_lanes(packed, budget, 1)
}

/// [`tape_units`] for a chunk that may open `lanes` lanes, as the decode
/// cuts it: never fewer units than one block a unit would give those
/// lanes.
#[cfg(feature = "parallel")]
pub fn tape_units_for_lanes(
    packed: &[u8],
    budget: usize,
    lanes: usize,
) -> Result<(usize, usize, usize)> {
    let mut plan = crate::rar5_lz::tape::Plan::default();
    crate::rar5_lz::tape::plan(packed, false, &mut plan)?;
    plan.cut_units_for_lanes(budget, lanes);
    let mut next = 0;
    let mut widest = 0;
    for &(start, end) in &plan.units {
        assert_eq!(start, next, "units must tile the chain in order");
        assert!(end > start, "a unit holds at least one block");
        widest = widest.max(end - start);
        next = end;
    }
    assert_eq!(next, plan.blocks.len(), "units must cover every block");
    Ok((plan.blocks.len(), plan.units.len(), widest))
}

/// Decode one non solid member, keeping what it produced BEFORE an error:
/// section 3.8 requires the two arms to fail with the same kind at the
/// same output position, and a fuzz target can only see that if it sees
/// both halves.
pub fn decode_member_probe(
    packed: &[u8],
    unpacked: u64,
    window: u64,
    algorithm: u8,
    parallel: bool,
) -> (Vec<u8>, Option<String>) {
    member_probe(plain(window, parallel), packed, unpacked, algorithm, true)
}

/// [`decode_member_probe`] for a member that carries NO checksum, neither
/// a CRC32 field nor a hash record: what a harness that frames its
/// members so must say, as the reader says it for an archive's.
pub fn decode_member_probe_unchecked(
    packed: &[u8],
    unpacked: u64,
    window: u64,
    algorithm: u8,
    parallel: bool,
) -> (Vec<u8>, Option<String>) {
    member_probe(plain(window, parallel), packed, unpacked, algorithm, false)
}

/// A decoder under the seam's policy with the tape path forced on or off.
fn plain(window: u64, parallel: bool) -> Result<Rar5Lz> {
    let mut lz = Rar5Lz::new(window, &policy())?;
    lz.set_parallel(parallel);
    Ok(lz)
}

/// Decode a solid chain: every element is one member's packed bytes and its
/// declared size, and they share one stream.
pub fn decode_solid_chain(
    members: &[(&[u8], u64)],
    window: u64,
    algorithm: u8,
    parallel: bool,
) -> Result<Vec<Vec<u8>>> {
    let mut lz = Rar5Lz::new(window, &policy())?;
    lz.set_parallel(parallel);
    let mut out = Vec::new();
    for (packed, unpacked) in members {
        let mut sink: Vec<u8> = Vec::new();
        let mut source = SliceSource::new(packed);
        lz.member(&mut source, *unpacked, algorithm, &mut sink)?;
        out.push(sink);
    }
    Ok(out)
}

/// Decode a solid chain and answer each member's bytes with the outcome,
/// for the differential of section 6.3.
///
/// `parallel` forces the tape path on or off as `decode_solid_chain` does;
/// `ahead` additionally offers each member to the chain's decode-ahead
/// before the member in front of it is decoded, which is the order spec
/// F's read path offers in and the whole of what the lever does.
///
/// The bytes STOP where the chain stopped: a chain that fails at member
/// `n` answers the members before it and the error kind, so the two arms
/// are compared on where they stopped as well as on what they produced.
pub fn decode_solid_chain_probe(
    members: &[(&[u8], u64)],
    window: u64,
    algorithm: u8,
    parallel: bool,
    ahead: bool,
) -> (Vec<Vec<u8>>, Option<String>) {
    chain_probe(members, window, algorithm, parallel, ahead, true)
}

/// [`decode_solid_chain_probe`] for members that carry NO checksum (see
/// [`decode_member_probe_unchecked`]).
pub fn decode_solid_chain_probe_unchecked(
    members: &[(&[u8], u64)],
    window: u64,
    algorithm: u8,
    parallel: bool,
    ahead: bool,
) -> (Vec<Vec<u8>>, Option<String>) {
    chain_probe(members, window, algorithm, parallel, ahead, false)
}

fn chain_probe(
    members: &[(&[u8], u64)],
    window: u64,
    algorithm: u8,
    parallel: bool,
    ahead: bool,
    checked: bool,
) -> (Vec<Vec<u8>>, Option<String>) {
    let mut lz = match plain(window, parallel) {
        Ok(lz) => lz,
        Err(err) => return (Vec::new(), Some(format!("{:?}", err.kind()))),
    };
    let mut out = Vec::new();
    let mut offered = 0usize;
    for (index, (packed, unpacked)) in members.iter().enumerate() {
        if ahead {
            offered = offer_from(&mut lz, members.len(), index, offered, |at| {
                let (next, next_unpacked) = members[at];
                Some((next, next_unpacked, algorithm))
            });
        }
        let mut sink: Vec<u8> = Vec::new();
        let mut source = SliceSource::new(packed);
        if !checked {
            lz.next_member_is_unchecked();
        }
        let outcome = lz.member(&mut source, *unpacked, algorithm, &mut sink);
        out.push(sink);
        if let Err(err) = outcome {
            return (out, Some(format!("{:?}", err.kind())));
        }
    }
    (out, None)
}

/// Every LZ member of a RAR 5 archive, keeping the solid chain: the name
/// and the decoded bytes, in archive order. Stored members are passed
/// through, so a whole archive compares against the oracle's `extract`.
pub fn extract(archive: &[u8], parallel: bool) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    extract_with(archive, Some(parallel))
}

fn extract_with(archive: &[u8], parallel: Option<bool>) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut lz: Option<Rar5Lz> = None;
    let members = container::members(archive);
    // The member after the last one offered to the chain's decode-ahead.
    // This seam knows the whole archive, so it offers straight from it;
    // spec F's read path offers from its own walk.
    let mut offered = 0usize;
    for (index, member) in members.iter().enumerate() {
        if member.directory {
            continue;
        }
        if member.method == 0 {
            // Stored: the container layer's business, but a differential
            // over a whole archive needs the bytes.
            out.push((
                member.name.clone().into_bytes(),
                member.packed[..member.unpacked as usize].to_vec(),
            ));
            continue;
        }
        if !member.solid || lz.is_none() {
            let mut fresh = Rar5Lz::new(member.window, &policy())?;
            if let Some(parallel) = parallel {
                fresh.set_parallel(parallel);
            }
            lz = Some(fresh);
        }
        let decoder = lz.as_mut().expect("a decoder for this member");
        offered = offer_from(decoder, members.len(), index, offered, |at| {
            let next = &members[at];
            (!next.directory && next.method != 0 && next.solid).then_some((
                next.packed.as_slice(),
                next.unpacked,
                next.algorithm,
            ))
        });
        let mut sink: Vec<u8> = Vec::with_capacity(member.unpacked as usize);
        let mut source = SliceSource::new(&member.packed);
        decoder.member(&mut source, member.unpacked, member.algorithm, &mut sink)?;
        out.push((member.name.clone().into_bytes(), sink));
    }
    Ok(out)
}

/// `[ignored, refused]` over `archive`, decoded serially: filter records
/// ignored for being longer than 4 MiB, and kept spans refused as
/// `FilterRange` for being `W = max(D, 256 KiB)` or longer (SPEC-H2 3.6,
/// "Long records"). The decode stops at the first member that fails and
/// answers what it had counted, the refusal included. The oracle fuzz
/// targets ask this only where rarkit and the old engine disagree on a
/// verdict: the old engine fails the first and runs the second, where
/// rarkit follows the reference on the first and fails loudly on the
/// second, so both are a known class and not a finding.
pub fn long_filter_records(archive: &[u8]) -> [u64; 2] {
    let mut total = [0u64; 2];
    let mut lz: Option<Rar5Lz> = None;
    for member in container::members(archive) {
        if member.directory || member.method == 0 {
            continue;
        }
        if !member.solid || lz.is_none() {
            if let Some(done) = lz.take() {
                let counts = done.long_filter_records();
                total = [total[0] + counts[0], total[1] + counts[1]];
            }
            let Ok(mut fresh) = Rar5Lz::new(member.window, &policy()) else {
                break;
            };
            fresh.set_parallel(false);
            lz = Some(fresh);
        }
        let decoder = lz.as_mut().expect("a decoder for this member");
        let mut sink = NullSink { bytes: 0 };
        let mut source = SliceSource::new(&member.packed);
        if decoder
            .member(&mut source, member.unpacked, member.algorithm, &mut sink)
            .is_err()
        {
            break;
        }
    }
    if let Some(done) = lz {
        let counts = done.long_filter_records();
        total = [total[0] + counts[0], total[1] + counts[1]];
    }
    total
}

/// Offer the members of one solid chain that FOLLOW the member at `index`
/// to the decoder's decode-ahead, starting at `offered`, the first member
/// not yet offered, and answering the new value of that.
///
/// `member(at)` answers the member's packed bytes, declared size and
/// algorithm, or `None` where the chain does not continue through it: a
/// directory, a stored member, a member whose solid bit is clear. The
/// loop stops there, and at the first offer the decoder refuses, which is
/// how a memory budget and a full queue reach it.
///
/// **It never skips and never re-offers.** Every seam arm here offered
/// from `index + 1` and restarted one PAST the member a full queue had
/// refused, so that member decoded serially with the decoder's run still
/// open behind it, and the run then carried a table set that member may
/// have replaced: `DistanceOutOfRange` on a 2,000 member reference chain
/// in the `rar5_small_solid_20k_vsnull` arm, 22 Sep 2026, where the
/// shipped read path, whose cursor stays on a refused member, decoded the
/// same chain whole. A member the stage refuses is offered again at the
/// next member's turn, and the stage itself closes the run when a refusal
/// is for ever (`rar5_lz::ahead::Offered`).
fn offer_from<'a>(
    decoder: &mut Rar5Lz,
    count: usize,
    index: usize,
    offered: usize,
    member: impl Fn(usize) -> Option<(&'a [u8], u64, u8)>,
) -> usize {
    let mut at = offered.max(index + 1);
    while at < count {
        let Some((packed, unpacked, algorithm)) = member(at) else {
            break;
        };
        if !decoder.offer_ahead(packed, unpacked, algorithm) {
            break;
        }
        at += 1;
    }
    at
}

/// [`extract`] under the carried worker policy, which is what a caller
/// gets and what the bench legs measure.
pub fn extract_auto(archive: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    extract_with(archive, None)
}

/// [`extract`] to a null sink: the bytes are counted and dropped, which is
/// what the `rar5_small_solid_20k` bench leg measures.
///
/// **It OFFERS the chain's members to the decode-ahead, as the shipped
/// read path does.** It did not until 22 Sep 2026, and that was a
/// bench-arm measurement defect and not a property of the engine: the
/// leg exists to time what ships, `rarkit::extract` offers every member
/// of a solid chain to `rar5_lz::ahead`, and this arm decoded the same
/// chain with the stage never reached. `extract_auto` beside it offered
/// all along. The pre-correction form is kept as
/// [`extract_counting_unoffered`] so the correction can be priced in one
/// binary, and the correction is a correction: a term this arm was paying
/// that the shipped path does not, and never a gain of the engine's.
pub fn extract_counting(archive: &[u8], parallel: Option<bool>) -> Result<u64> {
    extract_counting_with(archive, parallel, true)
}

/// [`extract_counting`] exactly as it was before 22 Sep 2026: the same
/// borrowing walk, the same null sink, and NO member ever offered to the
/// chain's decode-ahead.
///
/// Kept ONLY so the measurement correction can be shown as one, the way
/// [`extract_counting_owning_walk`] keeps the correction before it. It is
/// NOT a leg and must never become one.
pub fn extract_counting_unoffered(archive: &[u8], parallel: Option<bool>) -> Result<u64> {
    extract_counting_with(archive, parallel, false)
}

fn extract_counting_with(archive: &[u8], parallel: Option<bool>, offer: bool) -> Result<u64> {
    let mut total = 0u64;
    let mut lz: Option<Rar5Lz> = None;
    // `member_refs` and not `members`: this arm is the `rar5_small_solid_20k`
    // legs' rarkit arm, and the owning walk copies every member's packed
    // bytes and allocates every member's name INSIDE the timed region, where
    // the old arm it is compared against carries no such term. See
    // `container::MemberRef` for the measurement. Nothing about what is
    // decoded changes: the name is not used here and the packed bytes are
    // the same bytes.
    let members = container::member_refs(archive);
    let mut offered = 0usize;
    for (index, member) in members.iter().enumerate() {
        if member.directory || member.method == 0 {
            total += member.unpacked;
            continue;
        }
        if !member.solid || lz.is_none() {
            let mut fresh = Rar5Lz::new(member.window, &policy())?;
            if let Some(parallel) = parallel {
                fresh.set_parallel(parallel);
            }
            lz = Some(fresh);
        }
        let decoder = lz.as_mut().expect("a decoder for this member");
        if offer {
            offered = offer_from(decoder, members.len(), index, offered, |at| {
                let next = &members[at];
                (!next.directory && next.method != 0 && next.solid).then_some((
                    next.packed,
                    next.unpacked,
                    next.algorithm,
                ))
            });
        }
        let mut sink = NullSink { bytes: 0 };
        let mut source = SliceSource::new(member.packed);
        decoder.member(&mut source, member.unpacked, member.algorithm, &mut sink)?;
        total += sink.bytes;
    }
    Ok(total)
}

/// [`extract_counting`] with the OWNING container walk, kept so the
/// measurement correction of 22 Sep 2026 can be priced in one binary.
///
/// This is exactly what `extract_counting` was before that date: the walk
/// copies every member's packed bytes into a fresh `Vec` and allocates a
/// `String` for every name, inside the region the `rar5_small_solid_20k`
/// legs time, where the old arm they are compared against carries no such
/// term. Nothing decodes differently; the two differ in the walk and in
/// nothing else, which is what makes the pair readable.
///
/// It is NOT a leg and must never become one. It exists so the correction
/// is visible as a correction - a term removed from rarkit's arm that was
/// never a user's to pay - rather than appearing as a gain.
pub fn extract_counting_owning_walk(archive: &[u8], parallel: Option<bool>) -> Result<u64> {
    let mut total = 0u64;
    let mut lz: Option<Rar5Lz> = None;
    for member in container::members(archive) {
        if member.directory || member.method == 0 {
            total += member.unpacked;
            continue;
        }
        if !member.solid || lz.is_none() {
            let mut fresh = Rar5Lz::new(member.window, &policy())?;
            if let Some(parallel) = parallel {
                fresh.set_parallel(parallel);
            }
            lz = Some(fresh);
        }
        let mut sink = NullSink { bytes: 0 };
        let mut source = SliceSource::new(&member.packed);
        lz.as_mut().expect("a decoder for this member").member(
            &mut source,
            member.unpacked,
            member.algorithm,
            &mut sink,
        )?;
        total += sink.bytes;
    }
    Ok(total)
}

/// One RAR 5 x86 address pass over `data`, for the untimed scan lab.
///
/// Choose the filter pass's subtraction arm for every decode that follows
/// (`rar5_lz::filters::arms`): 0 what ships, 1 the transform not run, 2
/// every record dropped. Only the untimed filter profile calls this, and
/// only a build with `h2-filter-arms`, which no gate binary has.
#[cfg(feature = "h2-filter-arms")]
pub fn set_filter_arm(arm: u8) {
    crate::rar5_lz::filters::arms::set(arm);
}

/// THE TRANSFORM OFFLOAD'S FUZZ SEAM (`fuzz:rar5_filter_offload`): one
/// member driven through the drain by `script`, with the filter transforms
/// handed to a pool task and without, which must agree byte for byte. The
/// script's first byte picks the ring (1 or 2 MiB, which take the short
/// ring form and copy out everything they account for, or 4 or 8 MiB),
/// its second whether an overlapping
/// pair of spans is placed, its third whether the decode runs on the only
/// thread of its pool, so no batch is ever started by the pool. Answers
/// the batches handed away, so a caller can see the path was reached.
#[cfg(feature = "parallel")]
pub fn filter_offload_agrees(script: &[u8]) -> u64 {
    use crate::rar5_lz::filters::offload_case;
    let pick = |i: usize| script.get(i).copied().unwrap_or(0);
    let ring = [1u64 << 20, 2 << 20, 4 << 20, 8 << 20][usize::from(pick(0) % 4)];
    let overlap = pick(1) & 1 == 1;
    let (want, sealed_off, _) = offload_case(ring, false, script, overlap);
    assert_eq!(sealed_off, 0, "the synchronous drain hands nothing away");
    let (got, sealed, stolen) = if pick(2) & 1 == 1 {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .expect("a one-thread pool");
        let out = pool.install(|| offload_case(ring, true, script, overlap));
        assert_eq!(out.2, out.1, "a pool with no free thread runs no batch");
        out
    } else {
        offload_case(ring, true, script, overlap)
    };
    let _ = stolen;
    assert!(got == want, "the handed drain moved a byte");
    sealed
}

/// THE DRAIN LAP'S FUZZ SEAM (`fuzz:rar5_drain_lap`): one member out of
/// `script`, driven through the drain at the tape walk's cadence on a rung
/// of the dictionary ladder (the script's first byte), offload on or off
/// (its second), against the same member in a ring that cannot lap; the
/// two must agree byte for byte, errors included, or this panics. The
/// member is three rings long by construction. Answers its length. See
/// `rar5_lz::output::lap` (23 Sep 2026).
pub fn drain_lap_agrees(script: &[u8]) -> usize {
    crate::rar5_lz::output::lap::agrees(script)
}

/// What one RAR 5 filter record does to its span's bytes, in place: `kind`
/// is the record's type field (0 delta, 1 x86 call, 2 x86 call and jump,
/// 3 ARM), `channels` the delta channel count, `start` the span's member
/// relative start (SPEC-H2 3.6). The transform the decoder runs, so a test
/// can say what a hand built member's bytes must be.
pub fn rar5_filter_pass(kind: u8, channels: u8, start: u64, data: &mut [u8]) {
    crate::rar5_lz::filters::transform_for_seam(kind, channels, start, data);
}

/// `arm` 0 is the walking form, 1 the scan-then-convert split, and 2 the
/// ADAPTIVE body that chooses between them per block, which is what
/// ships; `jump` picks record type 2 against type 1. All three are the
/// DECODE direction, which is the only one a read takes.
pub fn rar5_x86_pass(data: &mut [u8], f: u32, jump: bool, arm: u8) {
    use crate::carry::h_ours::codec::address_filters as af;
    match (jump, arm) {
        (false, 0) => af::x86_pass_walking::<false, false, true>(data, f),
        (true, 0) => af::x86_pass_walking::<false, true, true>(data, f),
        (false, 2) => af::x86_pass_split_batch::<false, false, true, 64>(data, f),
        (true, 2) => af::x86_pass_split_batch::<false, true, true, 64>(data, f),
        (false, 3) => af::x86_pass_split_batch::<false, false, true, 1024>(data, f),
        (true, 3) => af::x86_pass_split_batch::<false, true, true, 1024>(data, f),
        (false, 4) => af::x86_pass_split_wide::<false, false, true>(data, f),
        (true, 4) => af::x86_pass_split_wide::<false, true, true>(data, f),
        #[cfg(target_arch = "aarch64")]
        (false, 5) => af::x86_pass_split_neon::<false, false, true>(data, f),
        #[cfg(target_arch = "aarch64")]
        (true, 5) => af::x86_pass_split_neon::<false, true, true>(data, f),
        #[cfg(target_arch = "aarch64")]
        (false, 7) => af::x86_pass_neon16::<false, false, true>(data, f),
        #[cfg(target_arch = "aarch64")]
        (true, 7) => af::x86_pass_neon16::<false, true, true>(data, f),
        (false, 6) => af::x86_pass_split_late::<false, false, true, 256>(data, f),
        (true, 6) => af::x86_pass_split_late::<false, true, true, 256>(data, f),
        (false, _) => af::x86_pass::<false, false, true>(data, f),
        (true, _) => af::x86_pass::<false, true, true>(data, f),
    }
}

/// One x86 filter block exactly as a DECODE receives it.
///
/// `data` is the block's PRE-filter bytes, `f` the member relative start
/// the pass is given, and `jump` picks record type 2 (calls and jumps)
/// against type 1 (calls alone).
///
/// The bytes are recovered rather than intercepted. A decode produces the
/// block's POST-filter bytes, and the ENCODE direction of the same pass
/// inverts the DECODE direction exactly, so applying it to the decoded
/// span gives back the bytes the decode was handed. The caller checks that
/// round trip rather than trusting it.
#[derive(Debug, Clone)]
pub struct X86Block {
    pub data: Vec<u8>,
    pub f: u32,
    pub jump: bool,
}

/// Every x86 filter block of `archive`, as a decode receives them.
///
/// This is the untimed density lab's instrument and nothing else calls it:
/// it decodes each member to memory, so it is sized by the archive rather
/// than by a window. The spans come from the stream's own records, which
/// means the ENCODER'S detector chose them, which is the whole point of
/// running the lab over real binaries archived by reference `rar` instead
/// of over a generator.
pub fn x86_filter_blocks(archive: &[u8]) -> Result<Vec<X86Block>> {
    use crate::carry::h_ours::codec::address_filters as af;

    let mut out: Vec<X86Block> = Vec::new();
    let mut refused = 0usize;
    let mut lz: Option<Rar5Lz> = None;
    for member in container::members(archive) {
        if member.directory || member.method == 0 {
            continue;
        }
        if !member.solid || lz.is_none() {
            let mut fresh = Rar5Lz::new(member.window, &policy())?;
            fresh.set_parallel(false);
            lz = Some(fresh);
        }
        let decoder = lz.as_mut().expect("a decoder for this member");
        decoder.capture_filter_spans();
        let mut sink: Vec<u8> = Vec::with_capacity(member.unpacked as usize);
        let mut source = SliceSource::new(&member.packed);
        decoder.member(&mut source, member.unpacked, member.algorithm, &mut sink)?;
        for &(start, length, slot) in decoder.captured_filter_spans() {
            // Slot 1 is type 1, slot 2 is type 2; the delta and ARM
            // records this lab is not about are slots 0 and 3.
            let jump = match slot {
                1 => false,
                2 => true,
                _ => continue,
            };
            let start = start as usize;
            let end = start + length as usize;
            let Some(decoded) = sink.get(start..end) else {
                continue;
            };
            let f = start as u32;
            let mut data = decoded.to_vec();
            if jump {
                af::x86_pass::<true, true, true>(&mut data, f);
            } else {
                af::x86_pass::<true, false, true>(&mut data, f);
            }
            // THE INVERSE IS CHECKED, NOT ASSUMED. The whole recovery
            // rests on the encode direction undoing the decode exactly,
            // and a lab that measured the wrong bytes would still print a
            // table. Decoding what was just encoded has to give back the
            // bytes the decode produced; a block that fails is dropped
            // rather than timed, and the count says so.
            let mut check = data.clone();
            if jump {
                af::x86_pass::<false, true, true>(&mut check, f);
            } else {
                af::x86_pass::<false, false, true>(&mut check, f);
            }
            if check != decoded {
                refused += 1;
                continue;
            }
            out.push(X86Block { data, f, jump });
        }
    }
    if refused > 0 {
        eprintln!(
            "x86_filter_blocks: {refused} block(s) did not survive the encode-decode \
             round trip and were dropped rather than timed"
        );
    }
    Ok(out)
}

/// What [`crate::rar5_lz`]'s drain path copies for one archive, counted
/// rather than timed (`examples/h2_drain_census.rs`).
#[derive(Debug, Default, Clone, Copy)]
pub struct DrainCensus {
    pub bytes: u64,
    pub drains: u64,
    pub ring_direct: u64,
    pub ring_to_scratch: u64,
    pub ring_to_hold: u64,
    pub hold_to_sink: u64,
    pub hold_to_scratch: u64,
    pub hold_memmove: u64,
    pub spans_fast: u64,
    pub spans_held: u64,
    /// Records of each kind, then their bytes: delta, x86 call, x86 call
    /// and jump, ARM.
    pub kinds: [u64; 4],
    pub kind_bytes: [u64; 4],
}

/// Decode `archive` serially and report what the drain path copied.
pub fn drain_census(archive: &[u8]) -> Result<DrainCensus> {
    let mut out = DrainCensus::default();
    let mut lz: Option<Rar5Lz> = None;
    for member in container::members(archive) {
        if member.directory || member.method == 0 {
            continue;
        }
        if !member.solid || lz.is_none() {
            let mut fresh = Rar5Lz::new(member.window, &policy())?;
            fresh.set_parallel(false);
            lz = Some(fresh);
        }
        let decoder = lz.as_mut().expect("a decoder for this member");
        let mut sink: Vec<u8> = Vec::with_capacity(member.unpacked as usize);
        let mut source = SliceSource::new(&member.packed);
        decoder.member(&mut source, member.unpacked, member.algorithm, &mut sink)?;
        out.bytes += member.unpacked;
        let c = decoder.drain_counts();
        out.drains = c.drains;
        out.ring_direct = c.ring_direct;
        out.ring_to_scratch = c.ring_to_scratch;
        out.ring_to_hold = c.ring_to_hold;
        out.hold_to_sink = c.hold_to_sink;
        out.hold_to_scratch = c.hold_to_scratch;
        out.hold_memmove = c.hold_memmove;
        out.spans_fast = c.spans_fast;
        out.spans_held = c.spans_held;
        let (kinds, kind_bytes) = decoder.filter_kinds();
        out.kinds = kinds;
        out.kind_bytes = kind_bytes;
    }
    Ok(out)
}

/// Every LZ member of `archive` decoded on the TAPE PATH (the parallel
/// arm, forced), with the batches of filter transforms its drain handed
/// to the pool: the member bytes in archive order, then the batch count.
/// A filtered member on any ring hands batches away (the short ring form
/// of 28 Sep 2026 included); one with no record queued hands none.
#[cfg(feature = "parallel")]
pub fn filter_batches_sealed(archive: &[u8]) -> Result<(Vec<Vec<u8>>, u64)> {
    let mut out = Vec::new();
    let mut sealed = 0u64;
    let mut lz: Option<Rar5Lz> = None;
    for member in container::members(archive) {
        if member.directory || member.method == 0 {
            continue;
        }
        if !member.solid || lz.is_none() {
            if let Some(done) = lz.take() {
                sealed += done.filter_batches_sealed();
            }
            let mut fresh = Rar5Lz::new(member.window, &policy())?;
            fresh.set_parallel(true);
            lz = Some(fresh);
        }
        let decoder = lz.as_mut().expect("a decoder for this member");
        let mut sink: Vec<u8> = Vec::with_capacity(member.unpacked as usize);
        let mut source = SliceSource::new(&member.packed);
        decoder.member(&mut source, member.unpacked, member.algorithm, &mut sink)?;
        out.push(sink);
    }
    if let Some(done) = lz {
        sealed += done.filter_batches_sealed();
    }
    Ok((out, sealed))
}

/// One member's filter LAYOUT, for the filter layout work's untimed count
/// (`examples/g_filter_layout_count.rs`): the records a decode queues,
/// in read order, as `(member relative start, length, kind slot)` with
/// slot 0 delta, 1 x86 call, 2 x86 call and jump, 3 ARM; the member's
/// declared window and size; its blocks and table groups; and what the
/// serial drain copied for it.
#[cfg(feature = "parallel")]
#[derive(Debug, Clone)]
pub struct FilterLayout {
    pub window: u64,
    pub unpacked: u64,
    pub spans: Vec<(u64, u32, u8)>,
    pub blocks: u64,
    pub groups: u64,
    pub drain: DrainCensus,
}

/// Every LZ member's [`FilterLayout`], decoded serially to memory.
#[cfg(feature = "parallel")]
pub fn filter_layout(archive: &[u8]) -> Result<Vec<FilterLayout>> {
    use crate::rar5_lz::tape;

    let mut out = Vec::new();
    let mut lz: Option<Rar5Lz> = None;
    for member in container::members(archive) {
        if member.directory || member.method == 0 {
            continue;
        }
        if !member.solid || lz.is_none() {
            let mut fresh = Rar5Lz::new(member.window, &policy())?;
            fresh.set_parallel(false);
            lz = Some(fresh);
        }
        let decoder = lz.as_mut().expect("a decoder for this member");
        decoder.capture_filter_spans();
        let mut sink: Vec<u8> = Vec::with_capacity(member.unpacked as usize);
        let mut source = SliceSource::new(&member.packed);
        decoder.member(&mut source, member.unpacked, member.algorithm, &mut sink)?;
        let mut plan = tape::Plan::default();
        tape::plan(&member.packed, false, &mut plan)?;
        let c = decoder.drain_counts();
        let (kinds, kind_bytes) = decoder.filter_kinds();
        out.push(FilterLayout {
            window: member.window,
            unpacked: member.unpacked,
            spans: decoder.captured_filter_spans().to_vec(),
            blocks: plan.blocks.len() as u64,
            groups: plan.groups.len() as u64,
            drain: DrainCensus {
                bytes: member.unpacked,
                drains: c.drains,
                ring_direct: c.ring_direct,
                ring_to_scratch: c.ring_to_scratch,
                ring_to_hold: c.ring_to_hold,
                hold_to_sink: c.hold_to_sink,
                hold_to_scratch: c.hold_to_scratch,
                hold_memmove: c.hold_memmove,
                spans_fast: c.spans_fast,
                spans_held: c.spans_held,
                kinds,
                kind_bytes,
            },
        });
    }
    Ok(out)
}

/// What one archive's members are made of (SPEC-H2 section 7.5, and H1's
/// section 7.5 which it defers to): the counts a per symbol against per
/// output byte split needs.
#[derive(Debug, Default, Clone, Copy)]
pub struct Census {
    /// Decoded operations: literal runs count as one each.
    pub operations: u64,
    /// Main alphabet symbols: one per literal and one per control.
    pub symbols: u64,
    pub literals: u64,
    pub matches: u64,
    pub repeats: u64,
    pub filters: u64,
    /// Bytes the members produce.
    pub bytes: u64,
}

/// Count what an archive's LZ members decode to, without applying a byte
/// to a window. Only the Huffman side runs, which is what makes the count
/// a property of the stream rather than of the decoder's speed.
/// Behind `h2-instruments`, so no gate binary compiles it.
#[cfg(all(feature = "parallel", feature = "h2-instruments"))]
pub fn census(archive: &[u8]) -> Result<Census> {
    use crate::rar5_lz::tape;

    let mut out = Census::default();
    for member in container::members(archive) {
        if member.directory || member.method == 0 {
            continue;
        }
        out.bytes += member.unpacked;
        let mut plan = tape::Plan::default();
        tape::plan(&member.packed, false, &mut plan)?;
        let mut tape = tape::BlockTape::default();
        for index in 0..plan.blocks.len() {
            let counts =
                tape::census_block(&plan, &member.packed, member.algorithm, index, &mut tape)?;
            out.operations += counts.0;
            out.literals += counts.1;
            out.matches += counts.2;
            out.repeats += counts.3;
            out.filters += counts.4;
        }
    }
    out.symbols = out.literals + out.matches + out.repeats + out.filters;
    Ok(out)
}

/// An archive's matches by length and distance, summed over its LZ
/// members: `fresh[length class][distance class]` and
/// `repeats[length class]` are (count, bytes), and `repeat_last` counts
/// the repeats that reuse the last length. The length classes are 2, 3,
/// 4, 5, 6, 7, 8, 9 to 16, 17 to 32 and longer; the distance classes end
/// at 256, 4 KiB, 64 KiB, 256 KiB, 2 MiB and 32 MiB, and the last is
/// everything beyond. Behind `h2-instruments`.
#[derive(Debug, Default, Clone, Copy)]
pub struct MatchShapeCensus {
    pub fresh: [[(u64, u64); 7]; 10],
    pub repeats: [(u64, u64); 10],
    pub repeat_last: u64,
}

/// See [`MatchShapeCensus`]. Only the Huffman side runs.
#[cfg(all(feature = "parallel", feature = "h2-instruments"))]
pub fn match_shape_census(archive: &[u8]) -> Result<MatchShapeCensus> {
    use crate::rar5_lz::tape;

    let mut shape = tape::MatchShape::default();
    for member in container::members(archive) {
        if member.directory || member.method == 0 {
            continue;
        }
        let mut plan = tape::Plan::default();
        tape::plan(&member.packed, false, &mut plan)?;
        let mut tape = tape::BlockTape::default();
        for index in 0..plan.blocks.len() {
            tape::match_shape_block(
                &plan,
                &member.packed,
                member.algorithm,
                index,
                &mut tape,
                &mut shape,
            )?;
        }
    }
    Ok(MatchShapeCensus {
        fresh: shape.fresh,
        repeats: shape.repeats,
        repeat_last: shape.repeat_last,
    })
}

/// The SINGLE-GAP table shape, censused: how many of an
/// archive's blocks decode under a main table whose 255 literals all have
/// eight bit codes with one byte value omitted and no shorter code
/// (`DecodeTable::serial_single_gap`), and how many of the payload's
/// symbol bits those blocks hold. Behind `h2-instruments`.
#[derive(Debug, Default, Clone, Copy)]
pub struct GapCensus {
    pub blocks: u64,
    pub gap_blocks: u64,
    pub bits: u64,
    pub gap_bits: u64,
}

/// See [`GapCensus`]. The tables are read; no symbol is decoded.
#[cfg(all(feature = "parallel", feature = "h2-instruments"))]
pub fn gap_shape_census(archive: &[u8]) -> Result<GapCensus> {
    use crate::rar5_lz::tape;

    let mut out = GapCensus::default();
    for member in container::members(archive) {
        if member.directory || member.method == 0 {
            continue;
        }
        let mut plan = tape::Plan::default();
        tape::plan(&member.packed, false, &mut plan)?;
        for index in 0..plan.blocks.len() {
            let Ok((gap, bits)) =
                tape::gap_shape_block(&plan, &member.packed, member.algorithm, index)
            else {
                continue;
            };
            out.blocks += 1;
            out.bits += bits;
            if gap {
                out.gap_blocks += 1;
                out.gap_bits += bits;
            }
        }
    }
    Ok(out)
}

/// Which path an archive's copies take through the match copy, shipped
/// and under the `NEAR_SOURCE` ceiling's distance cap:
/// `tape::copy_path_census_block`'s six counts, summed over every LZ
/// member, for `reach` (`usize::MAX` is the shipped walk), then the mirror
/// layout's slow copies and their bytes, the wrapped copies the EDGE form
/// leaves slow, and the mirror layout's laps (each lap mirrors
/// `STRIDE_MAX` bytes). The ring is
/// the one the window would build for the member with no memory budget.
/// Behind `copy-census`, so no measured arm compiles it.
#[cfg(all(feature = "parallel", feature = "copy-census"))]
pub fn copy_path_census(archive: &[u8], reach: usize) -> Result<[u64; 10]> {
    use crate::rar5_lz::output::{Window, STRIDE_MAX};
    use crate::rar5_lz::{tape, MatchState};

    let mut counts = [0u64; 10];
    for member in container::members(archive) {
        if member.directory || member.method == 0 {
            continue;
        }
        let ring_len = Window::new(member.window, u64::MAX)?.ring_bytes();
        let mut plan = tape::Plan::default();
        tape::plan(&member.packed, false, &mut plan)?;
        let mut block = tape::BlockTape::default();
        let mut state = MatchState::default();
        let mut at = 0usize;
        let mut stream = 0u64;
        let mut nine = [0u64; 9];
        for index in 0..plan.blocks.len() {
            tape::copy_path_census_block(
                &plan,
                &member.packed,
                member.algorithm,
                index,
                &mut block,
                &mut state,
                &mut at,
                &mut stream,
                ring_len,
                reach,
                &mut nine,
            )?;
        }
        for (sum, add) in counts.iter_mut().zip(nine) {
            *sum += add;
        }
        // The mirror layout's laps: its first lap is `ring_len +
        // STRIDE_MAX` bytes and every later one `ring_len`, and each lap
        // copies `STRIDE_MAX` bytes from the tail to the head.
        let first = (ring_len + STRIDE_MAX) as u64;
        if stream >= first {
            counts[9] += 1 + (stream - first) / ring_len as u64;
        }
    }
    Ok(counts)
}

/// The SHAPE of one member's chain: how many blocks the apply stage walks
/// and how many table groups sit below them.
///
/// The apply stage hands a group's table set back once it has passed the
/// group (section 4.2), and what that costs depends on both counts, so a
/// design argument about the apply stage needs them measured rather than
/// assumed. Blocks, groups, and the sum over blocks of the group index the
/// release scan starts from, which is the scan's total work for a member.
#[cfg(feature = "parallel")]
pub fn plan_shape(archive: &[u8]) -> Result<(u64, u64, u64)> {
    use crate::rar5_lz::tape;

    let mut blocks = 0u64;
    let mut groups = 0u64;
    let mut scanned = 0u64;
    for member in container::members(archive) {
        if member.directory || member.method == 0 {
            continue;
        }
        let mut plan = tape::Plan::default();
        tape::plan(&member.packed, false, &mut plan)?;
        blocks += plan.blocks.len() as u64;
        groups += plan.groups.len() as u64;
        for index in 0..plan.blocks.len() {
            scanned += plan.group_of[index] as u64;
        }
    }
    Ok((blocks, groups, scanned))
}

/// Which ARM of the apply loop each of a member's operations takes.
///
/// [`census`] says how many operations the one apply thread walks;
/// the timed rows read the wall that follows from it. Neither says which
/// branch an operation takes when it gets there, and the branches are not
/// alike: a literal run past the inline ladder takes a `memmove` libcall,
/// and a match nearer than one stride takes the byte-wise slow path. A
/// lever aimed at one arm is worth its measuring time in proportion to the
/// operations that take it, so this counts them, in the buckets the code
/// itself branches on.
///
/// A count, so it is a property of the stream and the same on every box.
/// Behind `h2-instruments`, so no gate binary compiles it.
#[cfg(all(feature = "parallel", feature = "h2-instruments"))]
pub fn apply_shape(archive: &[u8]) -> Result<[u64; crate::rar5_lz::tape::SHAPE_BUCKETS]> {
    use crate::rar5_lz::tape;

    let mut shape = [0u64; tape::SHAPE_BUCKETS];
    for member in container::members(archive) {
        if member.directory || member.method == 0 {
            continue;
        }
        let mut plan = tape::Plan::default();
        tape::plan(&member.packed, false, &mut plan)?;
        let mut tape = tape::BlockTape::default();
        for index in 0..plan.blocks.len() {
            tape::shape_block(
                &plan,
                &member.packed,
                member.algorithm,
                index,
                &mut tape,
                &mut shape,
            )?;
        }
    }
    Ok(shape)
}

/// The names of [`apply_shape`]'s buckets, in its own order.
pub const APPLY_SHAPE_NAMES: [&str; 12] = [
    "literal runs",
    "literal bytes",
    "runs on the inline ladder",
    "runs taking memmove, <= 128 B",
    "runs taking memmove, > 128 B",
    "matches",
    "match bytes",
    "matches the stride ladder takes",
    "matches too NEAR for a stride",
    "matches too LONG for the ladder",
    "repeats",
    "filters",
];

/// Whether a member's FIRST block carries its own table set, and how many
/// blocks its chain holds, for the census of section 7.5.
///
/// It is the question the chain's decode-ahead turns on: a member whose
/// first block opens no group depends on a group an earlier member of the
/// chain opened, and cannot be decoded from its own packed bytes.
// Reached only through the `internals_*` seam, behind the
// `bench-internals` feature; no shipped build enables it.
pub fn first_block_has_tables(packed: &[u8]) -> Option<(bool, usize)> {
    let first = crate::rar5_lz::block::block_in_hand(packed).ok()?;
    let mut at = 0usize;
    let mut blocks = 0usize;
    while at < packed.len() {
        let Ok(block) = crate::rar5_lz::block::block_in_hand(&packed[at..]) else {
            break;
        };
        blocks += 1;
        at += block.past();
        if block.ends_member() {
            break;
        }
    }
    Some((first.carries_tables(), blocks))
}

/// How much of a member a LANE could resolve for itself, counted rather
/// than assumed.
///
/// [`census`] says how many operations the one apply thread walks and
/// [`apply_shape`] says which arm each takes. Neither says whether an
/// operation has to be on that thread at all. A match whose source lies
/// wholly inside the bytes its own block has already produced can be
/// resolved on the lane that decoded the block, into the lane's staging
/// buffer, exactly as a literal is; only a match reaching back before the
/// block's start needs the shared window, and the apply thread then walks
/// one staged RUN between such matches rather than one operation per
/// literal run and per match.
///
/// The counts are hole-aware and carried-repeat-aware, and they treat a
/// filter as an ordered operation rather than as a source barrier, which
/// is SPEC-H2 3.6's rule that the window keeps the unfiltered bytes; see
/// [`crate::rar5_lz::tape::locality_block`] for what each of those costs
/// and why the honest figure is smaller than "distance <= bytes produced
/// so far". The boundaries are the plan's own, which are the ones the
/// parallel path decodes at.
///
/// A count, so it is a property of the stream and the same on every box.
///
/// Behind `h2-locality-census`, a feature of its own that nothing in this
/// repository turns on but the lab's own invocation: a counter compiled
/// into `two_arm` would move the measured arms' layout and could run
/// inside one of them, which is a price a lab instrument must not make
/// anybody pay.
#[cfg(all(feature = "parallel", feature = "h2-locality-census"))]
pub fn locality(archive: &[u8]) -> Result<[u64; crate::rar5_lz::tape::LOCALITY_BUCKETS]> {
    use crate::rar5_lz::tape;

    let mut loc = [0u64; tape::LOCALITY_BUCKETS];
    for member in container::members(archive) {
        if member.directory || member.method == 0 {
            continue;
        }
        let mut plan = tape::Plan::default();
        tape::plan(&member.packed, false, &mut plan)?;
        let mut tape = tape::BlockTape::default();
        for index in 0..plan.blocks.len() {
            tape::locality_block(
                &plan,
                &member.packed,
                member.algorithm,
                index,
                &mut tape,
                &mut loc,
            )?;
        }
    }
    Ok(loc)
}

/// THE WINDOW'S REACH, counted per fresh match.
///
/// Every block of every member through the plan and the tape decode, as
/// [`locality`] walks them, with the window untouched: how far back each
/// fresh match reaches, in [`REACH_BANDS`], its count and its bytes, and
/// how many of the matches at or past the far-copy prefetch's distance sit
/// in a tape its gate admits (`tape::far_gate_admits`, the walk's own
/// test) and how many in one it refuses. A repeat's distance is a slot the
/// apply stage resolves, so repeats are counted but not placed in a band.
/// A member whose first block carries no tables (a solid member that takes
/// its predecessor's) is counted as skipped. A count, so it is a property
/// of the stream and the same on every box.
///
/// Slots: 0 members walked, 1 skipped, 2 tapes, 3 tapes the gate admits,
/// 4 operations, 5 repeats, then per band the matches (6 to 12) and their
/// bytes (13 to 19), 20 far matches in admitted tapes, 21 in refused ones.
#[cfg(all(feature = "parallel", feature = "h2-locality-census"))]
pub fn reach(archive: &[u8]) -> Result<[u64; 22]> {
    use crate::rar5_lz::tape;

    let mut out = [0u64; 22];
    for member in container::members(archive) {
        if member.directory || member.method == 0 {
            continue;
        }
        let mut plan = tape::Plan::default();
        if tape::plan(&member.packed, false, &mut plan).is_err() {
            out[1] += 1;
            continue;
        }
        out[0] += 1;
        let mut tape = tape::BlockTape::default();
        for index in 0..plan.blocks.len() {
            if tape::reach_block(
                &plan,
                &member.packed,
                member.algorithm,
                index,
                &mut tape,
                &mut out,
            )
            .is_err()
            {
                out[1] += 1;
                break;
            }
        }
    }
    Ok(out)
}

/// The lower edges of [`reach`]'s distance bands after the first, which
/// starts at 1: 64 KiB, 256 KiB (the far prefetch's distance), 1, 4, 8
/// and 16 MiB.
#[cfg(feature = "h2-locality-census")]
pub const REACH_BANDS: [usize; 6] = [64 << 10, 256 << 10, 1 << 20, 4 << 20, 8 << 20, 16 << 20];

/// The names of `locality`'s buckets, in its own order.
#[cfg(feature = "h2-locality-census")]
pub const LOCALITY_NAMES: [&str; 22] = [
    "ops the apply thread walks today",
    "literal runs",
    "matches",
    "matches whose source is inside the block",
    "matches reaching before the block start",
    "matches a lane could resolve itself",
    "matches blocked by an earlier hole",
    "repeats",
    "repeats whose source is inside the block",
    "repeats reaching before the block start",
    "repeats naming a slot an earlier block set",
    "repeats a lane could resolve itself",
    "repeats blocked by an earlier hole",
    "filters, ordered but no source barrier",
    "RESIDUAL: staged runs the apply thread copies",
    "RESIDUAL: operations left on the apply thread",
    "bytes the members produce",
    "bytes resolved on a lane, off the apply thread",
    "largest one block's staged bytes",
    "parks",
    "CEILING: staged runs with every hole wished away",
    "CEILING: operations with every hole wished away",
];

/// THE STAGE PROBE.
///
/// One member's tape path, priced stage by stage by SUBTRACTION rather
/// than by a sampler, for this reason: self time over a
/// dependency-bound loop does not name the marginal instruction, and two
/// H2 changes have already regressed by taking their next step from where a
/// sampled profile said the time sat. So each figure here is a RUN with
/// one stage taken away, not a share of a stack.
///
/// The three below and the shipped path are four separate calls on
/// purpose, so a timed run can put each in its own cell of one round robin
/// and no stage owns a position in the run.
///
/// [`stage_plan`] walks the chain and decodes no symbol.
#[cfg(all(feature = "parallel", feature = "h2-stage-probe"))]
pub fn stage_plan(packed: &[u8], window: u64, tape_width: usize) -> Result<(usize, usize)> {
    let mut lz = scheduled(window, tape_width, None, true)?;
    lz.probe_plan_only(packed)
}

/// The whole shipped tape path with the APPLY STAGE REMOVED: the plan, the
/// lanes, the channel of one, the round robin and the tape recycling all
/// run exactly as they ship, and the apply stage hands each tape straight
/// back. What this leaves is `D/W` plus every scheduling cost the plan
/// carries.
#[cfg(all(feature = "parallel", feature = "h2-stage-probe"))]
pub fn stage_decode_only(
    packed: &[u8],
    unpacked: u64,
    window: u64,
    algorithm: u8,
    tape_width: usize,
    channel_depth: usize,
) -> Result<usize> {
    let mut lz = scheduled(window, tape_width, None, true)?;
    lz.set_probe_channel_depth(channel_depth);
    lz.probe_decode_only(packed, unpacked, algorithm)
}

/// The shipped tape path at one width and one HAND-OFF CHANNEL DEPTH.
///
/// Depth one is what ships. Depth two lets a lane that finished early run
/// one block further ahead, which is the candidate for the 4 to 6 percent
/// of apply-thread samples the 21 Sep apply work measured BLOCKED IN
/// `recv`, and it stays inside API 8.2's `4 * W` tapes (`3 * lanes`
/// alive rather than `2 * lanes`). A DIAL for pricing that candidate by
/// subtraction; nothing outside this feature can move it.
#[cfg(all(feature = "parallel", feature = "h2-stage-probe"))]
pub fn stage_full(
    packed: &[u8],
    unpacked: u64,
    window: u64,
    algorithm: u8,
    tape_width: usize,
    channel_depth: usize,
) -> Result<Vec<u8>> {
    let mut lz = scheduled(window, tape_width, None, true)?;
    lz.set_probe_channel_depth(channel_depth);
    let mut sink: Vec<u8> = Vec::with_capacity(unpacked as usize);
    let mut source = SliceSource::new(packed);
    lz.member(&mut source, unpacked, algorithm, &mut sink)?;
    Ok(sink)
}

/// The APPLY STAGE ALONE: every block decoded into its own tape first and
/// none of that timed, then the apply loop walked with no lane, no channel
/// and no plan walk left to pay for.
///
/// Section 3.8's property is what makes holding a whole member's tapes
/// lawful: a decode touches no window state, no repeated distance and no
/// filter, so pre-decoding every block changes not one applied byte.
///
/// Answers the apply nanoseconds, the bytes produced and a CRC32 over
/// them. The CRC is the guard that matters: an apply floor which turned
/// out to be doing LESS work than the shipped path would be a faster
/// number and a worthless one, so the caller compares this against the
/// shipped path's own CRC and refuses the cell if they differ. That is
/// SPEC-H2 3.8 consequence 2 applied to an instrument rather than to a
/// driver.
#[cfg(all(feature = "parallel", feature = "h2-stage-probe"))]
pub fn stage_apply_floor(
    packed: &[u8],
    unpacked: u64,
    window: u64,
    algorithm: u8,
) -> Result<(u128, u64, u32)> {
    // The width cannot matter here - nothing is spread - and one is what
    // says so at the call site.
    let mut lz = scheduled(window, 1, None, true)?;
    let mut sink: Vec<u8> = Vec::with_capacity(unpacked as usize);
    let ns = lz
        .probe_apply_floor(packed, unpacked, algorithm, &mut sink)?
        .as_nanos();
    let mut crc = crate::checksum::Crc32::new();
    crc.update(&sink);
    Ok((ns, sink.len() as u64, crc.finish()))
}

/// THE LANE SPLIT: one
/// decode lane's work on every block of a member, serially on this thread,
/// timed in two parts, the decode into a tape and the symbol pass's build
/// over it (`Rar5Lz::probe_lane_split`). `mode` 0 reuses the symbols, 1
/// makes them new for every block (pricing their allocation by
/// subtraction), 2 decodes only (a count by difference), 3 builds in
/// the lean form (`Symbols::build_lean`), symbols reused.
///
/// Answers blocks, operations, decode ns, build ns, blocks the build made
/// gatherable, bytes it gathered, prefix operations, the largest symbol
/// buffer in symbols, then the operations' shape (`symbols::probe_census`).
#[cfg(all(feature = "parallel", feature = "h2-stage-probe"))]
pub fn lane_split(packed: &[u8], window: u64, algorithm: u8, mode: u8) -> Result<[u64; 18]> {
    let mut lz = scheduled(window, 1, None, true)?;
    lz.probe_lane_split(packed, algorithm, mode)
}
