//! A filter record whose type field is 4 or above (SPEC-H2 3.6, "A type
//! of 4 or above", restated 9 Oct 2026; found as READER-08OCT-1).
//!
//! The rule: the record is READ as any record is, the two counted values
//! and the three bits of the type with no channel field, and its type is
//! judged only if the length rule and the order rule KEEP it. A kept
//! record of such a type whose span is empty, or starts at or past the
//! member's declared size, fails nothing and the decode goes on with the
//! next symbol of the same block. One whose span is not empty and starts
//! inside the declared output fails the member, `FilterType`, with a
//! checksum or without (the chosen difference: the genuine programs pass
//! a file with the span cut out of it when nothing checks it). A kept
//! record of such a type moves the order rule's floor like any other.
//!
//! Before the rule was restated the record failed the member wherever it
//! was read, and a member the genuine programs pass whole was refused.
//!
//! Pool width and memory: the calling thread, or the decoder's own
//! scoped lanes at the default width; one 1 MiB window, blocks of under
//! 600 bytes.

use super::*;

const WINDOW: u64 = 1 << 20;
const TEXT: &[u8] = b"abcdefghijklmnopqrst";

/// What stands in the block after its first `at` literals.
#[derive(Clone, Copy, Debug)]
struct Shape {
    /// Literals before the record under test.
    at: usize,
    /// The record: offset, length, type.
    record: (u32, u32, u32),
    /// A delta record of one channel read first, at the block's start:
    /// offset and length, or none.
    before: Option<(u32, u32)>,
}

fn member(shape: Shape) -> Vec<u8> {
    let mut block = BlockBuilder::default();
    if let Some((offset, length)) = shape.before {
        block.filter(offset, length, 0, 1);
    }
    block.literals(&TEXT[..shape.at]);
    let (offset, length, kind) = shape.record;
    block.filter(offset, length, kind, 1);
    block.literals(&TEXT[shape.at..]);
    block.finish(true, true)
}

fn decoder(parallel: bool) -> Rar5Lz {
    let mut lz = Rar5Lz::new(WINDOW, &policy()).expect("window");
    lz.set_parallel(parallel);
    lz
}

fn run(
    packed: &[u8],
    declared: u64,
    parallel: bool,
    unchecked: bool,
) -> (Option<Rar5Fault>, Vec<u8>) {
    let mut lz = decoder(parallel);
    if unchecked {
        lz.next_member_is_unchecked();
    }
    let mut sink: Vec<u8> = Vec::new();
    let mut source = SliceSource::new(packed);
    let fault = lz
        .member(&mut source, declared, 0, &mut sink)
        .err()
        .map(fault_of);
    (fault, sink)
}

/// Every arm and both words about a checksum give `want`.
fn everywhere(shape: Shape, declared: u64, want: (Option<Rar5Fault>, &[u8])) {
    let packed = member(shape);
    for parallel in [false, true] {
        for unchecked in [false, true] {
            let got = run(&packed, declared, parallel, unchecked);
            assert_eq!(
                (got.0, &got.1[..]),
                want,
                "{shape:?}, declares {declared}, parallel {parallel}, unchecked {unchecked}"
            );
        }
    }
}

#[test]
fn a_kept_record_of_an_unknown_type_past_the_declared_size_fails_nothing() {
    for kind in 4..8 {
        // The span starts at or past the declared size: at it exactly,
        // and well past it. Every literal after the record is still
        // decoded, so the member's declared bytes are all delivered.
        for (at, offset, declared) in [(7, 0, 7u64), (7, 0, 5), (3, 9, 12), (3, 30, 12)] {
            let shape = Shape {
                at,
                record: (offset, 4, kind),
                before: None,
            };
            everywhere(shape, declared, (None, &TEXT[..declared as usize]));
        }
        // An empty span, wherever it stands.
        let empty = Shape {
            at: 5,
            record: (0, 0, kind),
            before: None,
        };
        everywhere(empty, 20, (None, TEXT));
    }
}

#[test]
fn a_record_of_an_unknown_type_the_rules_do_not_keep_fails_nothing() {
    for kind in 4..8 {
        // Longer than 0x400000: never read, whatever its type and place.
        // This is the shape READER-08OCT-1 met, a record of 0xfdffffff
        // bytes of type 4.
        let long = Shape {
            at: 5,
            record: (0, 0xfdff_ffff, kind),
            before: None,
        };
        everywhere(long, 20, (None, TEXT));
        // Behind the order rule's floor: a delta on `[2, 12)` is read
        // first, and the record on `[5, 9)` starts inside it. The delta
        // runs over its whole span, so the bytes are the delta's.
        let behind = Shape {
            at: 5,
            record: (0, 4, kind),
            before: Some((2, 10)),
        };
        let alone = {
            let mut block = BlockBuilder::default();
            block.filter(2, 10, 0, 1);
            block.literals(TEXT);
            block.finish(true, true)
        };
        let (fault, want) = run(&alone, 20, false, false);
        assert_eq!(fault, None);
        assert_ne!(want, TEXT);
        everywhere(behind, 20, (None, &want));
    }
}

#[test]
fn a_kept_record_of_an_unknown_type_inside_the_declared_output_is_filter_type() {
    for kind in 4..8 {
        // A span of four bytes that starts inside the declared output:
        // wholly inside it, and straddling its end.
        for declared in [20u64, 12, 6] {
            let shape = Shape {
                at: 5,
                record: (0, 4, kind),
                before: None,
            };
            let packed = member(shape);
            for parallel in [false, true] {
                for unchecked in [false, true] {
                    let (fault, bytes) = run(&packed, declared, parallel, unchecked);
                    let case = format!("type {kind}, declares {declared}, parallel {parallel}");
                    assert_eq!(fault, Some(Rar5Fault::FilterType), "{case}");
                    assert!(bytes.len() <= 5, "{case}: nothing of the span is delivered");
                    assert_eq!(bytes, TEXT[..bytes.len()], "{case}");
                }
            }
        }
    }
}

/// A kept record of an unknown type moves the order rule's floor: a
/// delta read after it that starts inside its span is dropped. Here the
/// unknown record's span is past the declared size, so nothing fails,
/// and the delta on `[12, 16)`, inside `[10, 18)`, changes no byte the
/// window holds for a later member; what shows is that the member
/// passes with its bytes as sent.
#[test]
fn a_kept_record_of_an_unknown_type_moves_the_floor() {
    let mut block = BlockBuilder::default();
    block.literals(&TEXT[..2]);
    block.filter(8, 8, 4, 1);
    block.filter(10, 4, 0, 1);
    block.literals(&TEXT[2..]);
    let packed = block.finish(true, true);
    for parallel in [false, true] {
        // Declared as 10: the unknown record's span `[10, 18)` starts at
        // the declared size and fails nothing. The delta on `[12, 16)`
        // is behind the floor it set, so it is dropped: were it kept it
        // would be a completed span past the declared size, which is
        // `FilterRange` for a caller that says nothing of a checksum.
        let (fault, bytes) = run(&packed, 10, parallel, false);
        assert_eq!(
            (fault, &bytes[..]),
            (None, &TEXT[..10]),
            "parallel {parallel}"
        );
    }
}
