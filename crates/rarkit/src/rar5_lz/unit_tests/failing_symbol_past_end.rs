//! A symbol that FAILS after its member's declared size has been
//! produced (SPEC-H2 3.1, "A symbol that FAILS past the declared end",
//! added 8 Oct 2026; found as FUZZ-08OCT-3).
//!
//! The rule: the member PASSES and every declared byte is delivered; the
//! symbol ends its BLOCK, so the symbols before it stay applied to the
//! window and nothing of it or after it in that block is; the decode goes
//! on with the member's next block; and the set in force is kept. The
//! serial decode and the tape path agree. Before the declared end the
//! same symbol fails the member under its own name, as it always did.
//!
//! A filter record of a type no transform has is NOT one of these since 9
//! Oct 2026: past the declared end it fails nothing and the block goes
//! on (3.6, `unknown_filter_type.rs`).
//!
//! Before this rule was built such a member failed with the symbol's kind
//! on every arm, the serial decode having delivered all of the member
//! first and the tape path none of it.
//!
//! Pool width and memory: the calling thread, or the decoder's own scoped
//! lanes at the default width; one 1 MiB window, blocks of under 600
//! bytes, and for the campaign's input 262,144 bytes of output twice.

use super::*;

const WINDOW: u64 = 1 << 20;
/// The literals a narrow block may spell: twenty symbols at five bits,
/// which leaves twelve five bit patterns with no code.
const NARROW: &[usize] = &[
    b'a' as usize,
    b'b' as usize,
    b'c' as usize,
    b'd' as usize,
    b'e' as usize,
    b'f' as usize,
    b'g' as usize,
    b'h' as usize,
    b'i' as usize,
    b'j' as usize,
    b'k' as usize,
    b'l' as usize,
    b'm' as usize,
    b'n' as usize,
    b'o' as usize,
    b'p' as usize,
    b'q' as usize,
    b'r' as usize,
    b's' as usize,
    b't' as usize,
];

/// The symbol under test, written where a block's seventh literal ends.
#[derive(Clone, Copy, Debug)]
enum Failing {
    /// Five one bits under a main table of twenty five bit codes.
    NoCode,
    /// Symbol 258 in a stream that has set no distance.
    UnsetRepeat,
}

impl Failing {
    fn kind(self) -> Rar5Fault {
        match self {
            Failing::NoCode => Rar5Fault::InvalidCode,
            Failing::UnsetRepeat => Rar5Fault::UninitialisedRepeat,
        }
    }

    fn builder(self) -> BlockBuilder {
        match self {
            Failing::NoCode => BlockBuilder::default().with_main(NARROW, 5),
            Failing::UnsetRepeat => BlockBuilder::default(),
        }
    }

    fn write(self, block: &mut BlockBuilder) {
        match self {
            Failing::NoCode => block.raw(0b11111, 5),
            Failing::UnsetRepeat => block.repeat(0, 0, 0),
        }
    }
}

/// A member of two blocks. The first spells `abcdefg`, then the failing
/// symbol, then `hi`; the second, which is the member's last, carries its
/// own wide tables and spells `XY`.
fn member(failing: Failing) -> Vec<u8> {
    let mut first = failing.builder();
    first.literals(b"abcdefg");
    failing.write(&mut first);
    first.literals(b"hi");
    let mut out = first.finish(true, false);
    let mut second = BlockBuilder::default();
    second.literals(b"XY");
    out.extend(second.finish(true, true));
    out
}

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

/// The last `count` bytes the decoder wrote into its window.
fn window_tail(lz: &Rar5Lz, count: usize) -> Vec<u8> {
    let at = lz.window.at_for_test();
    lz.window.ring_for_test()[at - count..at].to_vec()
}

#[test]
fn a_symbol_that_fails_past_the_declared_end_ends_its_block_and_the_member_passes() {
    for failing in [Failing::NoCode, Failing::UnsetRepeat] {
        let packed = member(failing);
        for parallel in [false, true] {
            // Declared sizes the failing symbol stands past: inside the
            // seven literals before it, and exactly at them.
            for declared in [3u64, 5, 7] {
                let case = format!("{failing:?}, parallel {parallel}, declares {declared}");
                let mut lz = decoder(parallel);
                let got = run(&mut lz, &packed, declared);
                assert_eq!(
                    got,
                    (None, b"abcdefg"[..declared as usize].to_vec()),
                    "{case}"
                );
                // What the member's blocks left in the window: the seven
                // literals before the symbol, nothing after it in its
                // block, and the second block's two.
                assert_eq!(lz.window.produced(), 9, "{case}");
                assert_eq!(window_tail(&lz, 9), b"abcdefgXY", "{case}");
                // The set in force is the second block's, kept: a member
                // that leans on it decodes under it.
                let mut lean = BlockBuilder::default();
                lean.literals(b"next");
                let next = run(&mut lz, &lean.finish(false, true), 4);
                assert_eq!(next, (None, b"next".to_vec()), "{case}");
            }
        }
    }
}

#[test]
fn the_same_symbol_before_the_declared_end_fails_the_member_under_its_own_name() {
    for failing in [Failing::NoCode, Failing::UnsetRepeat] {
        let packed = member(failing);
        for parallel in [false, true] {
            // Declared sizes the seven literals do not reach.
            for declared in [8u64, 9, 11] {
                let case = format!("{failing:?}, parallel {parallel}, declares {declared}");
                let (fault, bytes) = run(&mut decoder(parallel), &packed, declared);
                assert_eq!(fault, Some(failing.kind()), "{case}");
                assert!(bytes.len() <= 7, "{case}");
                assert_eq!(bytes, b"abcdefg"[..bytes.len()], "{case}");
            }
        }
    }
}

/// The member `fuzz:rar5_member` found (FUZZ-08OCT-3; 194 bytes, sha256
/// a1d1b9cee0799c3c..., also the seed
/// `fuzz/seeds/rar5_member/failing-symbol-past-the-declared-end`): a bit
/// pattern with no code after all 262,144 declared bytes. The reference
/// extracts the member whole (unrar 7.23, All OK, exit 0). Both arms pass
/// it with the same 262,144 bytes.
#[test]
fn the_campaign_member_passes_whole_on_both_arms() {
    const MEMBER: [u8; 194] = [
        0xc6, 0x23, 0xbf, 0x77, 0x76, 0x00, 0x77, 0x77, 0x77, 0x00, 0x01, 0x32, 0x77, 0x30, 0x75,
        0x77, 0x77, 0xc6, 0xbf, 0x60, 0x43, 0xce, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x82, 0xff, 0xfa, 0x00, 0x00, 0x00, 0x13, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x88, 0x24,
        0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x77, 0x2c, 0x77,
        0x77, 0x4b, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x0f, 0x00, 0x88, 0x24, 0x12, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x08, 0x02, 0xff, 0xff, 0xff, 0xff,
    ];
    const DECLARED: u64 = 1 << 18;
    let serial = run(&mut decoder(false), &MEMBER, DECLARED);
    let tape = run(&mut decoder(true), &MEMBER, DECLARED);
    assert_eq!(serial.0, None);
    assert_eq!(tape.0, None);
    assert_eq!(serial.1.len() as u64, DECLARED);
    assert!(serial.1 == tape.1, "the two arms disagree on the bytes");
}
