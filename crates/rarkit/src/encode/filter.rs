//! The RAR 5 encoder's side of a filter (spec H3 section 6.6).
//!
//! Spec G decides WHICH filter runs over which bytes; this file is what
//! the encoder does once it has been told. Two things, and only two:
//!
//! - the span is transformed in the ENCODE direction before it is
//!   tokenised, in the encoder's own buffer, so the match finder and the
//!   parse see the filtered bytes, and the history a later match reaches
//!   into holds them too, as the decoder's window will (H2 section 3.6:
//!   the window keeps what the LZ decoder wrote, not what the filter
//!   produced);
//! - main symbol 256 and the record's fields are written in H2 section
//!   3.6's form, ahead of the first token of the parse block the span
//!   starts in, with the offset measured from that block's first byte.
//!   Every parse block ends exactly where its tokens end, so what the
//!   decoder has produced when it reads the record is the block's start,
//!   and the offset it adds lands on the span.
//!
//! A plan is a list of spans that are ASCENDING and DISJOINT (adjacent is
//! fine). H2 section 3.6's order rule drops a record whose span starts
//! before the end of the last one kept, so a plan that broke this would
//! write bytes the reader leaves unfiltered.

use super::bits::{BitWriter, Code};
use crate::carry::h_ours::codec::address_filters::{arm_pass, x86_pass_adaptive};

/// The longest span a record may name. H2 section 0 keeps the format's
/// bound and rarkit's reader refuses a longer one as `FilterRange`.
pub(crate) const MAX_SPAN: usize = 0x3_ffff;

/// A record's transform: H2 section 3.6's three bit type, and the channel
/// count a delta carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilterKind {
    /// Type 0, 1 to 32 channels (SPEC-J 3.7.1).
    Delta(u8),
    /// Type 1, x86 near calls (SPEC-C part 1).
    X86Call,
    /// Type 2, x86 near calls and jumps (SPEC-C part 2).
    X86CallJump,
    /// Type 3, ARM branch with link (SPEC-C part 4).
    Arm,
}

/// One span of a plan, relative to the bytes handed to the encoder with
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FilterSpan {
    pub(crate) start: usize,
    pub(crate) len: usize,
    pub(crate) kind: FilterKind,
}

/// A span placed in the engine's buffer: where it starts there, and its
/// member relative start, which is the transforms' `F`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Placed {
    pub(crate) at: usize,
    pub(crate) len: usize,
    pub(crate) kind: FilterKind,
}

/// A record as one parse block writes it: the offset from the block's
/// first byte, the length and the transform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BlockRecord {
    pub(crate) offset: u32,
    pub(crate) len: u32,
    pub(crate) kind: FilterKind,
}

/// Transform `data` in the ENCODE direction, with `f` the member relative
/// offset of its first byte, taken modulo 2^32 as SPEC-C part 0 says.
/// `scratch` holds a copy for the delta, which is not an in place walk.
pub(crate) fn encode_in_place(kind: FilterKind, data: &mut [u8], f: u64, scratch: &mut Vec<u8>) {
    let f = f as u32;
    match kind {
        FilterKind::Delta(channels) => {
            scratch.clear();
            scratch.extend_from_slice(data);
            delta_encode(scratch, data, usize::from(channels));
        }
        FilterKind::X86Call => x86_pass_adaptive::<true, false, true>(data, f),
        FilterKind::X86CallJump => x86_pass_adaptive::<true, true, true>(data, f),
        FilterKind::Arm => arm_pass::<true>(data, f),
    }
}

/// SPEC-J 3.7.1's encode: the channels one after another, each byte the
/// previous original byte of its channel minus this one.
fn delta_encode(original: &[u8], out: &mut [u8], channels: usize) {
    debug_assert_eq!(original.len(), out.len());
    let mut at = 0;
    for channel in 0..channels.min(original.len()) {
        let mut previous = 0u8;
        for &byte in original[channel..].iter().step_by(channels) {
            out[at] = previous.wrapping_sub(byte);
            previous = byte;
            at += 1;
        }
    }
}

/// The records of a parse block over `bytes` (positions in the engine's
/// buffer): every placed span that starts inside it, in order.
pub(crate) fn records_for(
    placed: &[Placed],
    bytes: std::ops::Range<usize>,
    out: &mut Vec<BlockRecord>,
) {
    for span in placed {
        if bytes.contains(&span.at) {
            out.push(BlockRecord {
                offset: (span.at - bytes.start) as u32,
                len: span.len as u32,
                kind: span.kind,
            });
        }
    }
}

/// Write one record after `symbol_256`'s code (H2 section 3.6).
pub(crate) fn write_record(out: &mut BitWriter, symbol_256: Code, record: BlockRecord) {
    out.push_code(symbol_256);
    write_counted(out, record.offset);
    write_counted(out, record.len);
    match record.kind {
        FilterKind::Delta(channels) => {
            out.push(0, 3);
            out.push(u32::from(channels - 1), 5);
        }
        FilterKind::X86Call => out.push(1, 3),
        FilterKind::X86CallJump => out.push(2, 3),
        FilterKind::Arm => out.push(3, 3),
    }
}

/// A counted little endian 32 bit value: 2 bits give `k`, then `k + 1`
/// bytes, least significant first. The narrowest that holds the value.
fn write_counted(out: &mut BitWriter, value: u32) {
    let bytes = (4 - value.leading_zeros() / 8).max(1);
    out.push(bytes - 1, 2);
    for index in 0..bytes {
        out.push((value >> (8 * index)) & 0xff, 8);
    }
}
