//! A block whose bits end inside its own tables, before the member's
//! declared end, is `IncompleteMember` on every arm.
//!
//! Found on 8 Oct 2026 by `fuzz:rar5_member` and `fuzz:rar5_solid_chain`
//! (item FUZZ-08OCT-1): the serial walk answered `Truncated` and the tape
//! path `IncompleteMember` for the same member, since 28 Sep 2026, when a
//! SYMBOL cut by its block's end before the declared end became
//! `IncompleteMember` (SPEC-H2 3.1) and the tape path took a cut table
//! through the same door while the serial walk did not.
//!
//! THE KIND, settled on 8 Oct 2026: `IncompleteMember`, at once, as for a
//! cut symbol. No packed byte is missing, so `Truncated`, a source that
//! ended early, does not describe it. SPEC-H2 does not yet say so in
//! words: its 3.1 names the cut symbol, and a table that does not read
//! only past the declared end. Its sentence for a cut table, in 3.1 or
//! 3.3, is still to be written.
//!
//! Pool width and memory: every decode here runs on the calling thread or
//! on the decoder's own scoped lanes at the default width (no rayon pool
//! is named), the outcome may not depend on that width (SPEC-H2 3.8), and
//! the whole file stays under 16 MiB.

use super::*;
use crate::rar5_lz::vectors::{frame, BitWriter};

const WINDOW: u64 = 1 << 20;

/// `fuzz:rar5_member`'s minimised input, declared 262,144 bytes there.
/// One block: tables carried, NOT flagged last, a ten byte payload whose
/// last byte holds 4 valid bits, all of it in hand; the header is sound
/// (`8b ^ db ^ 0a ^ 00` is `0x5a`). Its 76 bits end inside the twentieth
/// field of the level table.
const MEMBER: [u8; 14] = [
    0x8b, 0xdb, 0x0a, 0x00, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b,
];

/// `fuzz:rar5_solid_chain`'s minimised input as the one member it frames
/// (declared 16 bytes): one block, tables carried, flagged LAST, an EMPTY
/// payload. The header is sound (`e3 ^ b9 ^ 00` is `0x5a`).
const CHAIN_MEMBER: [u8; 3] = [0xe3, 0xb9, 0x00];

#[derive(Clone, Copy, Debug)]
enum Arm {
    Serial,
    #[cfg(feature = "parallel")]
    Tape,
    #[cfg(feature = "parallel")]
    TapeOfTwo,
    #[cfg(feature = "parallel")]
    Ahead,
}

const ARMS: &[Arm] = &[
    Arm::Serial,
    #[cfg(feature = "parallel")]
    Arm::Tape,
    #[cfg(feature = "parallel")]
    Arm::TapeOfTwo,
    #[cfg(feature = "parallel")]
    Arm::Ahead,
];

/// One solid chain on one arm: each member's error kind (`None` for a
/// member that succeeds) and how many bytes it handed over.
fn kinds(chain: &[(&[u8], u64)], arm: Arm) -> Vec<(Option<String>, usize)> {
    let mut lz = Rar5Lz::new(WINDOW, &policy()).expect("window");
    lz.set_parallel(!matches!(arm, Arm::Serial));
    #[cfg(feature = "parallel")]
    if matches!(arm, Arm::TapeOfTwo) {
        lz.set_tape_width(2);
        lz.set_width_stated(true);
    }
    chain
        .iter()
        .map(|&(packed, declared)| {
            #[cfg(feature = "parallel")]
            if matches!(arm, Arm::Ahead) {
                let _ = lz.offer_ahead(packed, declared, 0);
            }
            let mut sink: Vec<u8> = Vec::new();
            let mut source = SliceSource::new(packed);
            let outcome = lz.member(&mut source, declared, 0, &mut sink);
            (
                outcome.err().map(|err| format!("{:?}", err.kind())),
                sink.len(),
            )
        })
        .collect()
}

const SHORT: &str = "Corrupt(Rar5(IncompleteMember))";

fn short() -> (Option<String>, usize) {
    (Some(SHORT.to_string()), 0)
}

#[test]
fn the_member_target_s_input_is_incomplete_on_every_arm() {
    for &arm in ARMS {
        let got = kinds(&[(&MEMBER, 1 << 18)], arm);
        assert_eq!(got, [short()], "{arm:?}");
    }
}

#[test]
fn the_chain_target_s_input_is_incomplete_on_every_arm() {
    for &arm in ARMS {
        let got = kinds(&[(&CHAIN_MEMBER, 16)], arm);
        assert_eq!(got, [short()], "{arm:?}");
    }
}

/// The level table's twenty 4 bit fields, each a length of five, so a
/// level symbol's code is its own number in five bits.
const LEVEL_BITS: usize = 20 * 4;
/// Where each list of lengths starts, in bits of the payload: the main
/// lengths (306), the distance lengths (64), the alignment lengths (16),
/// the length lengths (44), each length one five bit level symbol
/// (SPEC-H2 3.3: one list, in this order).
const MAIN_AT: usize = LEVEL_BITS;
const DISTANCE_AT: usize = MAIN_AT + 306 * 5;
const ALIGN_AT: usize = DISTANCE_AT + 64 * 5;
const LENGTH_AT: usize = ALIGN_AT + 16 * 5;
const TABLE_BITS: usize = LENGTH_AT + 44 * 5;

/// A block that carries tables and holds only the first `bits` bits of
/// them. Every byte the header declares is there.
fn tables_cut_at(bits: usize, last: bool) -> Vec<u8> {
    let mut whole: Vec<(u32, u32)> = vec![(5, 4); 20];
    whole.extend([(9, 5)].repeat(306));
    whole.extend([(6, 5)].repeat(64));
    whole.extend([(5, 5)].repeat(16));
    whole.extend([(6, 5)].repeat(44));
    let mut payload = BitWriter::default();
    let mut written = 0;
    'fields: for (value, width) in whole {
        for step in (0..width).rev() {
            if written == bits {
                break 'fields;
            }
            payload.put((value >> step) & 1, 1);
            written += 1;
        }
    }
    assert_eq!(written, bits, "the cut lies inside the tables");
    frame(&payload, true, last)
}

/// One cut inside each kind of table, none of them on a field's edge, and
/// the whole table set with nothing after it for contrast.
const CUTS: &[(&str, usize)] = &[
    ("the level table", 42),
    ("the main lengths", MAIN_AT + 100 * 5 + 3),
    ("the distance lengths", DISTANCE_AT + 10 * 5 + 2),
    ("the alignment lengths", ALIGN_AT + 3 * 5 + 1),
    ("the length lengths", LENGTH_AT + 20 * 5 + 4),
];

#[test]
fn a_table_cut_by_its_block_s_end_is_incomplete_on_every_arm() {
    for &(table, bits) in CUTS {
        assert!(bits < TABLE_BITS);
        for last in [false, true] {
            let packed = tables_cut_at(bits, last);
            for &arm in ARMS {
                let got = kinds(&[(&packed, 100)], arm);
                assert_eq!(got, [short()], "{table}, last {last}, {arm:?}");
            }
        }
    }
}

/// The same cut in a member that CONTINUES a solid chain: the member
/// before it decodes whole, and the cut one is short all the same.
#[test]
fn a_table_cut_in_a_later_solid_member_is_incomplete_on_every_arm() {
    let text = b"the member in front of the cut one";
    let mut first = BlockBuilder::default();
    first.literals(text);
    let first = first.finish(true, true);
    for &(table, bits) in CUTS {
        let cut = tables_cut_at(bits, true);
        for &arm in ARMS {
            let got = kinds(&[(&first, text.len() as u64), (&cut, 100)], arm);
            assert_eq!(got, [(None, text.len()), short()], "{table}, {arm:?}");
        }
    }
}

/// THE OTHER SIDE OF THE RULE: packed bytes that are MISSING are still
/// `Truncated` (SPEC-H2 3.2.1 and SPEC-API). The same block, its header
/// naming every byte of its tables, with the source ending inside them.
#[test]
fn packed_bytes_that_run_out_inside_the_tables_are_truncated_on_every_arm() {
    let whole = tables_cut_at(TABLE_BITS, true);
    for &(table, bits) in CUTS {
        // The header is four bytes here (a payload of 279 bytes takes a
        // two byte size), then the payload.
        let packed = &whole[..4 + bits / 8];
        for &arm in ARMS {
            let got = kinds(&[(packed, 100)], arm);
            assert_eq!(
                got,
                [(Some("Truncated".to_string()), 0)],
                "{table}, {arm:?}"
            );
        }
    }
}
