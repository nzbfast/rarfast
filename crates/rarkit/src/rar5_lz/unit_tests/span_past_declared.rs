//! A kept filter span that starts at or past its member's declared size,
//! or straddles it, at the decoder (SPEC-H2 3.1, "a kept filter record whose span is not
//! wholly inside the member's declared output", restated 8 Oct 2026).
//!
//! `crates/rarkit/tests/rar5_zero_byte_member_filter_record.rs` holds the
//! same rule through every read path. Here: what the decoder answers to a
//! caller that says nothing about a checksum (the strict answer), that
//! saying "no checksum" holds for ONE member, and that the answer is the
//! same on the serial and the tape arm.
//!
//! Pool width and memory: the calling thread, or the decoder's own scoped
//! lanes at the default width; one 1 MiB window and no input over 400
//! bytes. The rule keeps one number a member and allocates nothing, so a
//! member it now passes costs no more memory than one it refused.

use super::*;

const WINDOW: u64 = 1 << 20;
const TEXT: &[u8] = b"abcdefghij";

/// Five literals, a delta record at offset 0, then literals up to
/// `after`: the span is `[5, 5 + span)` of the member.
fn member(span: u32, after: usize) -> Vec<u8> {
    let mut block = BlockBuilder::default();
    block.literals(&TEXT[..5]);
    block.filter(0, span, 0, 1);
    block.literals(&TEXT[5..after]);
    block.finish(true, true)
}

/// A decoder on one arm, and one member through it: its fault and bytes.
fn decoder(parallel: bool) -> Rar5Lz {
    let mut lz = Rar5Lz::new(WINDOW, &policy()).expect("window");
    lz.set_parallel(parallel);
    lz
}

fn run(lz: &mut Rar5Lz, packed: &[u8], declared: u64) -> (Option<Rar5Fault>, Vec<u8>) {
    let mut sink: Vec<u8> = Vec::new();
    let mut source = SliceSource::new(packed);
    let fault = lz
        .member(&mut source, declared, 0, &mut sink)
        .err()
        .map(fault_of);
    (fault, sink)
}

#[test]
fn a_completed_span_past_the_declared_size_turns_on_the_checksum() {
    let packed = member(4, 10);
    for parallel in [false, true] {
        for declared in [0u64, 3, 5] {
            let want = TEXT[..declared as usize].to_vec();
            // A caller that says nothing gets the strict answer, with the
            // declared bytes and no more.
            let mut lz = decoder(parallel);
            let strict = run(&mut lz, &packed, declared);
            assert_eq!(strict, (Some(Rar5Fault::FilterRange), want.clone()));
            // No checksum: the member passes, and nothing past its
            // declared size is delivered.
            let mut lz = decoder(parallel);
            lz.next_member_is_unchecked();
            assert_eq!(run(&mut lz, &packed, declared), (None, want.clone()));
            // Said once, it held for that member only.
            let again = run(&mut lz, &packed, declared);
            assert_eq!(again, (Some(Rar5Fault::FilterRange), want));
        }
    }
}

#[test]
fn an_unfinished_span_past_the_declared_size_is_dropped() {
    // The span is `[5, 13)` and the stream ends at 7.
    let packed = member(8, 7);
    for parallel in [false, true] {
        for declared in [0u64, 3, 5] {
            let want = TEXT[..declared as usize].to_vec();
            for unchecked in [false, true] {
                let mut lz = decoder(parallel);
                if unchecked {
                    lz.next_member_is_unchecked();
                }
                assert_eq!(run(&mut lz, &packed, declared), (None, want.clone()));
            }
        }
    }
}

/// A span that starts BEFORE the declared size and is not completed
/// leaves the member short: `FilterRange`, checked or not, whether the
/// declared size falls inside the span or past it.
#[test]
fn an_unfinished_span_that_starts_inside_the_declared_output_is_refused() {
    for parallel in [false, true] {
        for declared in [6u64, 7] {
            for unchecked in [false, true] {
                let mut lz = decoder(parallel);
                if unchecked {
                    lz.next_member_is_unchecked();
                }
                let (fault, bytes) = run(&mut lz, &member(8, 7), declared);
                assert_eq!(fault, Some(Rar5Fault::FilterRange), "{declared}");
                assert!(bytes.len() as u64 <= declared);
            }
        }
    }
}

/// A kept span wholly INSIDE the declared output that the stream does
/// not complete, the member's last block ending validly at 7 of a
/// declared 10 or 20 bytes with the span `[5, 9)` open: `FilterRange`
/// (3.6), not `IncompleteMember`, checked or not, on both arms. The name
/// matters: the reader judges an `IncompleteMember` by the member's
/// checksum (spec F 4.2), and the five bytes before the span, which are
/// all that left, must not pass as the member (3.1, "a member never ends
/// short at a filter boundary").
#[test]
fn an_unfinished_span_inside_the_declared_output_is_filter_range_not_incomplete() {
    let packed = member(4, 7);
    for parallel in [false, true] {
        for declared in [10u64, 20] {
            for unchecked in [false, true] {
                let mut lz = decoder(parallel);
                if unchecked {
                    lz.next_member_is_unchecked();
                }
                let (fault, bytes) = run(&mut lz, &packed, declared);
                assert_eq!(fault, Some(Rar5Fault::FilterRange), "{declared}");
                assert_eq!(bytes, &TEXT[..5], "{declared}");
            }
        }
    }
    // With no record the same short end keeps its own name.
    let mut plain = BlockBuilder::default();
    plain.literals(&TEXT[..7]);
    let plain = plain.finish(true, true);
    for parallel in [false, true] {
        let (fault, bytes) = run(&mut decoder(parallel), &plain, 10);
        assert_eq!(fault, Some(Rar5Fault::IncompleteMember));
        assert_eq!(bytes, &TEXT[..7]);
    }
}

/// A completed span that STRADDLES the declared size: `FilterRange` for
/// a caller that says nothing, and with no checksum the member passes
/// with the first declared bytes of its whole output (rule 2).
#[test]
fn a_completed_span_that_straddles_the_declared_size_turns_on_the_checksum() {
    // The span is `[5, 9)` of ten bytes.
    let packed = member(4, 10);
    for parallel in [false, true] {
        let full = run(&mut decoder(parallel), &packed, 10);
        assert_eq!(full.0, None);
        assert_ne!(full.1, TEXT);
        for declared in 6u64..9 {
            let (fault, bytes) = run(&mut decoder(parallel), &packed, declared);
            assert_eq!(fault, Some(Rar5Fault::FilterRange), "{declared}");
            assert!(bytes.len() as u64 <= declared);
            let mut lz = decoder(parallel);
            lz.next_member_is_unchecked();
            let want = full.1[..declared as usize].to_vec();
            assert_eq!(run(&mut lz, &packed, declared), (None, want), "{declared}");
        }
    }
}

/// Bytes no short run compresses to themselves, so a transform run over
/// the wrong bytes shows.
fn noise(count: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    (0..count)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

/// One block of `total` literals with a three channel delta record read
/// after the first 100, spanning `[100, 100 + span)`.
fn long_member(total: usize, span: u32) -> Vec<u8> {
    let text = noise(total);
    let mut block = BlockBuilder::default();
    block.literals(&text[..100]);
    block.filter(0, span, 0, 3);
    block.literals(&text[100..]);
    block.finish(true, true)
}

/// The same rule on a span longer than a drain batch, so that its bytes
/// wait across several drains and the drain has to keep its cadence past
/// the declared size: 600,000 bytes of a 900,000 byte stream, under a
/// 1 MiB window, with the declared size just inside the span, in its
/// middle and one byte short of its end. Memory: the window, the hold of
/// one span and the 900,000 bytes, twice.
#[test]
fn a_long_straddling_span_is_run_whole_across_drains() {
    const SPAN: u32 = 600_000;
    let packed = long_member(900_000, SPAN);
    for parallel in [false, true] {
        let full = run(&mut decoder(parallel), &packed, 900_000);
        assert_eq!(full.0, None, "parallel {parallel}");
        assert_eq!(full.1.len(), 900_000);
        for declared in [101u64, 300_000, 100 + u64::from(SPAN) - 1] {
            let mut lz = decoder(parallel);
            lz.next_member_is_unchecked();
            let (fault, bytes) = run(&mut lz, &packed, declared);
            assert_eq!(fault, None, "parallel {parallel}, {declared}");
            assert_eq!(bytes.len() as u64, declared, "parallel {parallel}");
            assert!(
                bytes == full.1[..declared as usize],
                "parallel {parallel}, {declared}"
            );
            // Under a checksum the same member is refused, and nothing
            // past its declared size is delivered.
            let (fault, bytes) = run(&mut decoder(parallel), &packed, declared);
            assert_eq!(fault, Some(Rar5Fault::FilterRange), "parallel {parallel}");
            assert!(bytes.len() as u64 <= declared);
        }
    }
    // The stream stops 100,000 bytes short of the span's end.
    let short = long_member(600_000, SPAN);
    for parallel in [false, true] {
        let mut lz = decoder(parallel);
        lz.next_member_is_unchecked();
        let (fault, bytes) = run(&mut lz, &short, 300_000);
        assert_eq!(fault, Some(Rar5Fault::FilterRange), "parallel {parallel}");
        assert!(bytes.len() <= 100, "nothing of the span was delivered");
    }
}
