//! SPEC-H2 3.1 as amended on 28 Sep 2026: where a member ends, and the
//! symbols past its declared size.

use super::*;

// ---------------------------------------------------------------------------
// SPEC-H2 3.1 as amended on 28 Sep 2026: a member decodes EVERY symbol of every
// block it owns into the window and the repeat state; its OUTPUT is the first
// `declared` bytes; the next member of a solid stream counts from the
// window's true end.
// ---------------------------------------------------------------------------

mod member_end_surplus {
    use super::super::ladders::{fresh_match_length, length_from_slot, LENGTH_SLOT_EXTRA_BITS};
    use super::super::{Rar5Lz, SliceSource};
    use super::{distance_slot, policy, BlockBuilder};
    use crate::{Corruption, ErrorKind, Rar5Fault};

    /// One operation, written by [`BlockBuilder`] and replayed by [`model`].
    #[derive(Clone, Copy)]
    enum Op {
        Lit(u8),
        /// A fresh match: distance, and the length the stream CODES (the
        /// decoder adds section 3.5's bonus).
        Fresh(usize, usize),
        /// Symbol `258 + k`, and its length.
        Rep(usize, usize),
        /// Symbol 257.
        Last,
        /// A delta record on one channel: offset, length.
        Filter(u32, u32),
        /// Raw bits, which the model does not see: a block's tail that is
        /// no whole symbol.
        Raw(u32, u32),
    }

    /// The table set a block is written under.
    #[derive(Clone, Copy)]
    enum Set {
        /// Every symbol of every alphabet (`BlockBuilder::default`).
        Wide,
        /// A main alphabet of these symbols alone, at five bits: a set no
        /// `Wide` block builds, so a block decoded under the wrong one
        /// cannot come out right by accident.
        Narrow(&'static [usize]),
    }

    struct Block {
        set: Set,
        /// Whether the block CARRIES its set; clear, it uses the one in force.
        tables: bool,
        ops: Vec<Op>,
    }

    struct Member {
        blocks: Vec<Block>,
        declared: u64,
    }

    const WINDOW: u64 = 1 << 17;

    fn length_slot(length: usize) -> (usize, u32) {
        (0..LENGTH_SLOT_EXTRA_BITS.len())
            .find_map(|slot| {
                let base = length_from_slot(slot, 0);
                let span = 1usize << LENGTH_SLOT_EXTRA_BITS[slot];
                (length >= base && length < base + span).then(|| (slot, (length - base) as u32))
            })
            .expect("a length the ladder reaches")
    }

    fn builder(set: Set) -> BlockBuilder {
        match set {
            Set::Wide => BlockBuilder::default(),
            Set::Narrow(symbols) => BlockBuilder::default().with_main(symbols, 5),
        }
    }

    fn packed(member: &Member) -> Vec<u8> {
        let mut out = Vec::new();
        let last = member.blocks.len() - 1;
        for (index, block) in member.blocks.iter().enumerate() {
            let mut b = builder(block.set);
            for &op in &block.ops {
                match op {
                    Op::Lit(byte) => b.literal(byte),
                    Op::Fresh(distance, length) => {
                        let (ls, le) = length_slot(length);
                        let (ds, de) = distance_slot(distance);
                        b.fresh(ls, le, ds, de);
                    }
                    Op::Rep(k, length) => {
                        let (ls, le) = length_slot(length);
                        b.repeat(k, ls, le);
                    }
                    Op::Last => b.repeat_last(),
                    Op::Filter(offset, length) => b.filter(offset, length, 0, 1),
                    Op::Raw(value, width) => b.raw(value, width),
                }
            }
            out.extend_from_slice(&b.finish(block.tables, index == last));
        }
        out
    }

    /// The specified behaviour, written from 3.1 and 3.5 and nothing else:
    /// every operation applied to one stream, byte at a time, a source
    /// before the stream's start or past the window read as zero; each
    /// member's output its first `declared` bytes. Filter records change
    /// no window byte (3.6) and are skipped.
    fn model(members: &[Member]) -> Vec<Vec<u8>> {
        let mut stream: Vec<u8> = Vec::new();
        let mut reps = [0usize; 4];
        let mut last = 0usize;
        let copy = |stream: &mut Vec<u8>, distance: usize, length: usize| {
            for _ in 0..length {
                let byte = if distance as u64 > WINDOW || distance > stream.len() {
                    0
                } else {
                    stream[stream.len() - distance]
                };
                stream.push(byte);
            }
        };
        members
            .iter()
            .map(|member| {
                let start = stream.len();
                for op in member.blocks.iter().flat_map(|b| b.ops.iter()) {
                    match *op {
                        Op::Lit(byte) => stream.push(byte),
                        Op::Fresh(distance, length) => {
                            let length = fresh_match_length(length, distance);
                            reps = [distance, reps[0], reps[1], reps[2]];
                            last = length;
                            copy(&mut stream, distance, length);
                        }
                        Op::Rep(k, length) => {
                            let distance = reps[k];
                            for i in (1..=k).rev() {
                                reps[i] = reps[i - 1];
                            }
                            reps[0] = distance;
                            last = length;
                            copy(&mut stream, distance, length);
                        }
                        Op::Last => {
                            if last != 0 {
                                copy(&mut stream, reps[0], last);
                            }
                        }
                        Op::Filter(..) | Op::Raw(..) => {}
                    }
                }
                stream[start..start + member.declared as usize].to_vec()
            })
            .collect()
    }

    /// The ways a chain decodes: serial, and with `parallel` the tape path,
    /// and the tape path with every later member offered to the chain's
    /// decode-ahead before each member, as the read path offers.
    #[derive(Clone, Copy, Debug)]
    enum Arm {
        Serial,
        #[cfg(feature = "parallel")]
        Tape,
        #[cfg(feature = "parallel")]
        Ahead,
    }

    const ARMS: &[Arm] = &[
        Arm::Serial,
        #[cfg(feature = "parallel")]
        Arm::Tape,
        #[cfg(feature = "parallel")]
        Arm::Ahead,
    ];

    /// Offer the members from `offered` on to the decode-ahead, as far as
    /// it takes them, answering the first not taken.
    #[cfg(feature = "parallel")]
    fn offer(lz: &mut Rar5Lz, packed: &[Vec<u8>], declared: &[u64], mut offered: usize) -> usize {
        while offered < packed.len() && lz.offer_ahead(&packed[offered], declared[offered], 0) {
            offered += 1;
        }
        offered
    }

    /// One solid chain, every member decoded whatever the one before it
    /// answered, as the read path does; each member's outcome and bytes.
    fn run(members: &[Member], arm: Arm) -> Vec<(crate::Result<()>, Vec<u8>)> {
        let packed: Vec<Vec<u8>> = members.iter().map(packed).collect();
        let declared: Vec<u64> = members.iter().map(|m| m.declared).collect();
        run_packed(&packed, &declared, arm)
    }

    /// [`run`] over members' packed bytes as given, which a test may have
    /// damaged.
    fn run_packed(
        packed: &[Vec<u8>],
        declared: &[u64],
        arm: Arm,
    ) -> Vec<(crate::Result<()>, Vec<u8>)> {
        run_packed_at(packed, declared, arm, None)
    }

    /// [`run_packed`] at a stated tape width, `None` for the default.
    fn run_packed_at(
        packed: &[Vec<u8>],
        declared: &[u64],
        arm: Arm,
        width: Option<usize>,
    ) -> Vec<(crate::Result<()>, Vec<u8>)> {
        let mut lz = Rar5Lz::new(WINDOW, &policy()).expect("window");
        if let Some(width) = width {
            lz.set_tape_width(width);
            lz.set_width_stated(true);
        }
        lz.set_parallel(!matches!(arm, Arm::Serial));
        #[cfg(feature = "parallel")]
        let mut offered = 0usize;
        (0..packed.len())
            .map(|index| {
                #[cfg(feature = "parallel")]
                if matches!(arm, Arm::Ahead) {
                    offered = offer(&mut lz, packed, declared, offered.max(index + 1));
                }
                let mut sink: Vec<u8> = Vec::new();
                let mut source = SliceSource::new(&packed[index]);
                let outcome = lz.member(&mut source, declared[index], 0, &mut sink);
                (outcome, sink)
            })
            .collect()
    }

    fn fault(outcome: &crate::Result<()>) -> Option<Rar5Fault> {
        match outcome {
            Ok(()) => None,
            Err(err) => match err.kind() {
                ErrorKind::Corrupt(Corruption::Rar5(fault)) => Some(*fault),
                other => panic!("not a RAR 5 fault: {other:?}"),
            },
        }
    }

    /// Every arm gives the model's bytes, and every member the fault
    /// `faults` names (`None` for a member that succeeds).
    fn check(members: &[Member], faults: &[Option<Rar5Fault>]) {
        let want = model(members);
        for &arm in ARMS {
            let got = run(members, arm);
            for (index, ((outcome, bytes), want_bytes)) in got.iter().zip(&want).enumerate() {
                assert_eq!(fault(outcome), faults[index], "{arm:?}, member {index}");
                if faults[index].is_none() {
                    assert_eq!(bytes, want_bytes, "{arm:?}, member {index}");
                }
            }
        }
    }

    fn lits(text: &[u8]) -> Vec<Op> {
        text.iter().map(|&b| Op::Lit(b)).collect()
    }

    fn one(set: Set, ops: Vec<Op>, declared: u64) -> Member {
        Member {
            blocks: vec![Block {
                set,
                tables: true,
                ops,
            }],
            declared,
        }
    }

    /// The fixture's own shape, `rar50/solid_interior_match_overrun.rar`: a
    /// fresh match crossing the end with half of it left over, and the next
    /// member opening with a match that reads the surplus. Clipped at the
    /// end, the next member reads 20 bytes early and every byte differs.
    #[test]
    fn a_fresh_match_that_crosses_the_end_is_written_whole() {
        let mut a = lits(b"the quick brown fox jumps over the lazy dog, twice. ");
        a.push(Op::Fresh(20, 40));
        let mut b = vec![Op::Fresh(40, 30)];
        b.extend(lits(b"!"));
        check(
            &[one(Set::Wide, a, 52 + 20), one(Set::Wide, b, 31)],
            &[None, None],
        );
        // Crossing by 1 and by the whole match.
        for over in [1usize, 39] {
            let mut a = lits(b"abcdefghijklmnopqrstuvwxyz0123456789");
            a.push(Op::Fresh(9, 40));
            let b = vec![Op::Fresh(30, 25)];
            check(
                &[
                    one(Set::Wide, a, (36 + 40 - over) as u64),
                    one(Set::Wide, b, 25),
                ],
                &[None, None],
            );
        }
    }

    /// A repeat match (258) and the last-length repeat (257) that cross the
    /// end are written whole, rotate the distances and set the last length;
    /// the next member opens with 258 and with 257 under what they left.
    #[test]
    fn a_repeat_and_symbol_257_cross_the_end_and_the_next_member_uses_their_state() {
        let mut a = lits(b"0123456789abcdefghij");
        a.extend([Op::Fresh(7, 5), Op::Fresh(13, 6), Op::Rep(1, 12)]);
        check(
            &[
                one(Set::Wide, a.clone(), 20 + 5 + 6 + 4),
                one(Set::Wide, vec![Op::Rep(0, 9), Op::Last], 18),
            ],
            &[None, None],
        );
        a.push(Op::Last);
        check(
            &[
                one(Set::Wide, a, 20 + 5 + 6 + 12 + 3),
                one(Set::Wide, vec![Op::Last, Op::Rep(1, 4)], 16),
            ],
            &[None, None],
        );
    }

    /// Symbols after the crossing operation in the same block, and a whole
    /// later block past the end carrying a NEW table set, are applied: the
    /// next member's first block, its table bit clear, decodes under that
    /// set, and its first repeat uses the distances that block left.
    #[test]
    fn every_symbol_and_block_past_the_end_is_applied() {
        const NARROW: &[usize] = &[b'p' as usize, b'q' as usize, 257, 258, 262, 263, 264];
        let mut first = lits(b"surplus test, a member with more than it declares");
        first.extend([
            Op::Fresh(11, 8),
            Op::Lit(b'X'),
            Op::Lit(b'Y'),
            Op::Fresh(5, 4),
        ]);
        let a = Member {
            blocks: vec![
                Block {
                    set: Set::Wide,
                    tables: true,
                    ops: first,
                },
                Block {
                    set: Set::Narrow(NARROW),
                    tables: true,
                    ops: vec![Op::Lit(b'p'), Op::Fresh(23, 3), Op::Lit(b'q'), Op::Last],
                },
            ],
            declared: 50 + 3,
        };
        let b = Member {
            blocks: vec![Block {
                set: Set::Narrow(NARROW),
                tables: false,
                ops: vec![Op::Rep(0, 2), Op::Lit(b'q'), Op::Last, Op::Lit(b'p')],
            }],
            declared: 2 + 1 + 2 + 1,
        };
        check(&[a, b], &[None, None]);
    }

    /// A member whose output is complete at a block boundary still decodes
    /// its later blocks (3.1's bullet on non-zero members).
    #[test]
    fn a_member_complete_at_a_block_boundary_decodes_its_later_blocks() {
        const NARROW: &[usize] = &[b'z' as usize, 262, 263];
        let a = Member {
            blocks: vec![
                Block {
                    set: Set::Wide,
                    tables: true,
                    ops: lits(b"exactly thirty two bytes here..."),
                },
                Block {
                    set: Set::Narrow(NARROW),
                    tables: true,
                    ops: vec![Op::Lit(b'z'), Op::Fresh(9, 3), Op::Lit(b'z')],
                },
            ],
            declared: 32,
        };
        let b = Member {
            blocks: vec![Block {
                set: Set::Narrow(NARROW),
                tables: false,
                ops: vec![Op::Fresh(5, 2), Op::Lit(b'z')],
            }],
            declared: 3,
        };
        check(&[a, b], &[None, None]);
    }

    /// A data area that ends with the declared size produced and no block
    /// flagged last: the reference reports the member OK, whether the data
    /// ends there or goes on in zero bytes (SPEC-H2 3.2, the two
    /// `final-not-flagged` probes), and so does every arm here. Until 6
    /// Oct 2026 the tape and decode-ahead arms answered `Truncated` with
    /// nothing produced where the data ended there, and the serial arm
    /// gave the member whole. A member still short of its size when the
    /// chain runs out is `Truncated` on every arm, as before.
    /// Serial, tape and decode-ahead arms at the default width (the
    /// decoder's own scoped lanes; no rayon pool); under 16 MiB of memory.
    #[test]
    fn a_member_whose_final_block_is_not_flagged_last_is_whole() {
        let text = b"every byte of the member, and no last block";
        let mut b = builder(Set::Wide);
        for &byte in text {
            b.literal(byte);
        }
        let ends_there = b.finish(true, false);
        let mut then_zeros = ends_there.clone();
        then_zeros.extend_from_slice(&[0; 16]);
        for (zeros_follow, packed) in [(false, ends_there), (true, then_zeros)] {
            for &arm in ARMS {
                let whole = run_packed(std::slice::from_ref(&packed), &[text.len() as u64], arm);
                let (outcome, bytes) = &whole[0];
                assert!(
                    outcome.is_ok(),
                    "{arm:?}, zeros {zeros_follow}: {outcome:?}"
                );
                assert_eq!(bytes, text, "{arm:?}, zeros {zeros_follow}");
                if zeros_follow {
                    continue;
                }
                // One byte more declared than the chain holds.
                let short =
                    run_packed(std::slice::from_ref(&packed), &[text.len() as u64 + 1], arm);
                let kind = short[0].0.as_ref().map_err(|err| err.kind());
                assert!(
                    matches!(kind, Err(ErrorKind::Truncated)),
                    "{arm:?}: {kind:?}"
                );
            }
        }
    }

    /// The LAST member of a chain may run past its end: not an error.
    #[test]
    fn the_last_member_may_run_past_its_end() {
        let mut a = lits(b"a last member");
        a.push(Op::Fresh(6, 30));
        check(&[one(Set::Wide, a, 20)], &[None]);
    }

    /// A member that declares ZERO bytes decodes every symbol its blocks
    /// carry into the window and the repeat state, with no output, as any
    /// member does past its declared end (SPEC-H2 3.1, the zero byte
    /// paragraph as reconciled on 28 Sep 2026). The blocks genuine rar
    /// writes on such a member carry tables and no symbol; a block that
    /// carries symbols was read for its tables alone until 4 Oct 2026, so
    /// the member after it counted its distances and its repeats from the
    /// window and the state of the member BEFORE the empty one.
    ///
    /// The empty member carries five literals, or a match of ten at
    /// distance three; the member after it has its table bit clear and
    /// opens with symbol 257, or with a fresh match at distance one.
    /// Serial, tape and decode-ahead arms at the default width (the
    /// decoder's own scoped lanes; no rayon pool); under 16 MiB of memory.
    #[test]
    fn a_zero_byte_member_applies_every_symbol_its_blocks_carry() {
        for (carried, last) in [(lits(b"12345"), 5u64), (vec![Op::Fresh(3, 10)], 10)] {
            for (opening, declared) in [
                (vec![Op::Last, Op::Lit(b'.')], last + 1),
                (vec![Op::Fresh(1, 6), Op::Lit(b'.')], 7),
            ] {
                let mut a = lits(b"a member with bytes, then an empty one. ");
                a.push(Op::Fresh(7, 5));
                let c = Member {
                    blocks: vec![Block {
                        set: Set::Wide,
                        tables: false,
                        ops: opening,
                    }],
                    declared,
                };
                check(
                    &[one(Set::Wide, a, 45), one(Set::Wide, carried.clone(), 0), c],
                    &[None, None, None],
                );
            }
        }
    }

    /// A SYMBOL that fails inside a zero byte member's block (SPEC-H2 3.1,
    /// the bullet added on 4 Oct 2026, measured on reference unrar 7.23):
    ///
    /// 1. a kept filter record fails the member `FilterRange`, every other
    ///    symbol of its blocks is applied and the member after it decodes
    ///    as usual;
    /// 2. any other symbol that fails ends its BLOCK: the symbols before
    ///    it stay applied, nothing after it in that block is, the member
    ///    PASSES and its next block is still decoded;
    /// 3. the set in force is KEPT, so the member after it, its table bit
    ///    clear, decodes under the set the zero byte member's block sent.
    ///
    /// Until this the member passed, its later blocks were skipped and the
    /// set was DROPPED (the sweep's L-20, an interim choice where the
    /// section was silent), so the leaning member failed `EmptyTable`.
    ///
    /// Serial, tape and decode-ahead arms at the default width (the
    /// decoder's own scoped lanes; no rayon pool); under 16 MiB of memory.
    #[test]
    fn a_symbol_that_fails_in_a_zero_byte_member_ends_its_block_and_keeps_the_set() {
        // A main alphabet with these symbols alone at five bits: sixteen
        // codes of thirty-two, so five one bits are a pattern with no code.
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
            // The fresh match of four the next member opens its copy with.
            264,
        ];
        let a = || {
            one(
                Set::Wide,
                lits(b"forty-five literals stand before the empty 1."),
                45,
            )
        };
        let narrow = |tables: bool, ops: Vec<Op>| Block {
            set: Set::Narrow(NARROW),
            tables,
            ops,
        };
        let mut failing = lits(b"abcde");
        failing.push(Op::Raw(0b11111, 5));
        failing.extend(lits(b"fghij"));
        let leaning = || Member {
            blocks: vec![narrow(false, lits(b"onmlkj"))],
            declared: 6,
        };

        let mut wrong: Vec<String> = Vec::new();
        // ONE block, its own tables, a bit pattern with no code in it:
        // the member passes, the five literals before the pattern are in
        // the window, and the member after it decodes under that set.
        // TWO blocks: the second is decoded and applied too.
        for second in [false, true] {
            let mut blocks = vec![narrow(true, failing.clone())];
            let mut applied = vec![narrow(true, lits(b"abcde"))];
            if second {
                blocks.push(narrow(false, lits(b"klmnoo")));
                applied.push(narrow(false, lits(b"klmnoo")));
            }
            let b = Member {
                blocks,
                declared: 0,
            };
            // What the next member copies shows what the empty one left.
            let mut c = leaning();
            c.blocks[0].ops.push(Op::Fresh(8, 4));
            c.declared = 10;
            let mut c_model = leaning();
            c_model.blocks[0].ops.push(Op::Fresh(8, 4));
            c_model.declared = 10;
            let want = model(&[
                a(),
                Member {
                    blocks: applied,
                    declared: 0,
                },
                c_model,
            ]);
            let chain = [packed(&a()), packed(&b), packed(&c)];
            for &arm in ARMS {
                let got = run_packed(&chain, &[45, 0, 10], arm);
                for (index, (outcome, bytes)) in got.iter().enumerate() {
                    if outcome.is_err() || bytes != &want[index] {
                        wrong.push(format!(
                            "no code, second block {second}, {arm:?}, member {index}: {outcome:?} {:?}",
                            String::from_utf8_lossy(bytes)
                        ));
                    }
                }
            }
        }

        // A kept filter record: the member fails `FilterRange`, the
        // literals around the record are applied, the set is kept and the
        // member after it passes.
        let mut recorded = lits(b"abcde");
        recorded.push(Op::Filter(0, 4));
        recorded.extend(lits(b"fghij"));
        let b = Member {
            blocks: vec![Block {
                set: Set::Wide,
                tables: true,
                ops: recorded,
            }],
            declared: 0,
        };
        let c = || Member {
            blocks: vec![Block {
                set: Set::Wide,
                tables: false,
                ops: vec![Op::Fresh(8, 6), Op::Lit(b'.')],
            }],
            declared: 7,
        };
        let members = [a(), b, c()];
        let want = model(&members);
        for &arm in ARMS {
            let got = run(&members, arm);
            if fault(&got[1].0) != Some(Rar5Fault::FilterRange) {
                wrong.push(format!(
                    "filter record, {arm:?}, the empty member: {:?}",
                    got[1].0
                ));
            }
            if got[2].0.is_err() || got[2].1 != want[2] {
                wrong.push(format!(
                    "filter record, {arm:?}, the next member: {:?}",
                    got[2].0
                ));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    /// PINNED, SPEC-H2 3.1's point 4 (4 Oct 2026), which leaves the choice
    /// open and asks for whichever is built to be pinned: a repeat whose
    /// distance was never set, in a zero byte member. The reference
    /// writes zero bytes of its length and reads on; rarkit ENDS THE BLOCK
    /// there under point 2, the member passes and the set is kept, so the
    /// member after it sees the literals before the repeat and nothing of
    /// the block after it. One thread or the decoder's own lanes at the
    /// default width; under 16 MiB of memory.
    #[test]
    fn pinned_an_unset_repeat_in_a_zero_byte_member_ends_its_block() {
        let a = || {
            one(
                Set::Wide,
                lits(b"no match yet, so no repeat distance is set..."),
                45,
            )
        };
        let mut ops = lits(b"12345");
        ops.push(Op::Rep(0, 5));
        ops.extend(lits(b"67890"));
        let b = one(Set::Wide, ops, 0);
        let c = || Member {
            blocks: vec![Block {
                set: Set::Wide,
                tables: false,
                ops: vec![Op::Fresh(8, 8), Op::Lit(b'.')],
            }],
            declared: 9,
        };
        let want = model(&[a(), one(Set::Wide, lits(b"12345"), 0), c()]);
        let chain = [packed(&a()), packed(&b), packed(&c())];
        for &arm in ARMS {
            let got = run_packed(&chain, &[45, 0, 9], arm);
            for (index, (outcome, bytes)) in got.iter().enumerate() {
                assert!(outcome.is_ok(), "{arm:?}, member {index}: {outcome:?}");
                assert_eq!(
                    String::from_utf8_lossy(bytes),
                    String::from_utf8_lossy(&want[index]),
                    "{arm:?}, member {index}"
                );
            }
        }
    }

    /// A kept filter span that leaves the member's DECLARED output fails
    /// that member `FilterRange`, whether read before the crossing
    /// operation (straddling the end) or after it (wholly past it); the
    /// member's symbols after it are still applied, so the next member
    /// decodes right (3.1 and 3.6).
    #[test]
    fn a_filter_span_past_the_declared_output_fails_that_member_only() {
        for straddle in [true, false] {
            let mut a = lits(b"a member whose filter record leaves it");
            if straddle {
                // Read at 38, inside the 44 declared bytes, and running to 58.
                a.push(Op::Filter(0, 20));
            }
            a.push(Op::Fresh(12, 14));
            if !straddle {
                a.push(Op::Filter(0, 4));
            }
            a.extend([Op::Lit(b'!'), Op::Fresh(3, 4)]);
            let b = vec![Op::Fresh(9, 12)];
            check(
                &[one(Set::Wide, a, 39 + 5), one(Set::Wide, b, 12)],
                &[Some(Rar5Fault::FilterRange), None],
            );
        }
    }

    /// PAST the declared end a distance before the stream's start, or past
    /// the window, writes zeros and is not an error (3.1);
    /// the next member copies them back. INSIDE the output it
    /// writes zeros and is not an error either (3.7, as amended on 11 Oct
    /// 2026; until then it was `DistanceOutOfRange` there).
    #[test]
    fn a_bad_distance_writes_zeros_past_the_end_and_inside_it() {
        let mut a = lits(b"short stream");
        a.push(Op::Fresh(4, 6));
        a.push(Op::Fresh(5000, 8));
        check(
            &[
                one(Set::Wide, a, 12 + 3),
                one(Set::Wide, vec![Op::Fresh(9, 9), Op::Lit(b'.')], 10),
            ],
            &[None, None],
        );
        let mut inside = lits(b"short stream");
        inside.push(Op::Fresh(5000, 8));
        check(&[one(Set::Wide, inside, 12 + 9)], &[None]);
    }

    /// SPEC-H2 3.1 (measured 28 Sep 2026): past the declared end, a symbol
    /// CUT by its block's end ends the block, applies nothing, and the
    /// member passes (`Rar5Lz::surplus_tail`). The old engine's fixture
    /// `rar50/solid_match_overruns_member.rar` has exactly this tail, 4
    /// bits past a match that crosses the end, and reference unrar passes
    /// it. BEFORE the declared end the same cut leaves the member short:
    /// `IncompleteMember`. A PINNED DIFFERENCE, not tested here because
    /// the format does not define it: the reference completes the cut
    /// symbol with bits from beyond the block, so a solid successor that
    /// reads that symbol's window bytes may decode differently.
    #[test]
    fn pinned_a_partial_symbol_past_the_end_ends_the_block() {
        let mut a = lits(b"a tail that is no symbol");
        a.push(Op::Fresh(7, 9));
        a.push(Op::Raw(0b1010, 4));
        check(
            &[
                one(Set::Wide, a, 24 + 4),
                one(Set::Wide, vec![Op::Fresh(11, 6), Op::Lit(b'.')], 7),
            ],
            &[None, None],
        );
        let mut short = lits(b"a tail that is no symbol");
        short.push(Op::Raw(0b1010, 4));
        for &arm in ARMS {
            let got = run(&[one(Set::Wide, short.clone(), 30)], arm);
            assert_eq!(
                fault(&got[0].0),
                Some(Rar5Fault::IncompleteMember),
                "{arm:?}"
            );
        }
    }

    /// The member of the header tests: a first block that completes the
    /// declared 32 bytes, and a second block, wholly past the end, of four
    /// literals under the same set (header 3 bytes, payload 5).
    fn two_blocks() -> Member {
        Member {
            blocks: vec![
                Block {
                    set: Set::Wide,
                    tables: true,
                    ops: lits(b"complete before its second block"),
                },
                Block {
                    set: Set::Wide,
                    tables: false,
                    ops: lits(b"more"),
                },
            ],
            declared: 32,
        }
    }

    /// A block wholly PAST the declared end whose HEADER fails (its check
    /// byte, or a size that runs past the packed data) is not decoded: the
    /// member passes, and the next member continues from the window as it
    /// stood before that block (SPEC-H2 3.1, 28 Sep
    /// 2026). Before the declared end the same header fails the member.
    #[test]
    fn a_block_past_the_end_whose_header_fails_is_not_applied() {
        let next = one(Set::Wide, vec![Op::Fresh(8, 6), Op::Lit(b'.')], 7);
        // What the next member reads with the second block ABSENT.
        let mut without = two_blocks();
        without.blocks.truncate(1);
        let want = model(&[
            without,
            one(Set::Wide, vec![Op::Fresh(8, 6), Op::Lit(b'.')], 7),
        ]);
        for damage in ["check byte", "size"] {
            let mut first = packed(&two_blocks());
            let second = first.len() - (2 + 1 + 5);
            match damage {
                "check byte" => first[second + 1] ^= 0xff,
                _ => {
                    first[second + 2] = 0xff;
                    first[second + 1] = 0x5a ^ first[second] ^ 0xff;
                }
            }
            let packed_chain = [first.clone(), packed(&next)];
            for &arm in ARMS {
                let got = run_packed(&packed_chain, &[32, 7], arm);
                for (index, (outcome, bytes)) in got.iter().enumerate() {
                    assert!(
                        outcome.is_ok(),
                        "{damage}, {arm:?}, member {index}: {outcome:?}"
                    );
                    assert_eq!(bytes, &want[index], "{damage}, {arm:?}, member {index}");
                }
                // BEFORE the declared end: the member owes the second
                // block's bytes, and the header fails it.
                let got = run_packed(&[first.clone()], &[36], arm);
                assert!(got[0].0.is_err(), "{damage}, {arm:?}: {:?}", got[0].0);
            }
        }
    }

    /// A block wholly PAST the declared end whose TABLES do not read: the
    /// member passes, none of that block applies, its decode ends there
    /// and the set in force is DROPPED, so a next member that leans on the
    /// carried set (its first block's table bit clear) fails `EmptyTable`
    /// and a next member with its own tables decodes as usual (SPEC-H2
    /// 3.1, the bullet of 28 Sep 2026; rarkit failed such a member until
    /// 4 Oct 2026, pinned, and the tape path passed a cut table and kept
    /// the stale set).
    ///
    /// Four ways a table does not read: the code length alphabet all zero,
    /// the same alphabet over-subscribed, the block ending inside its
    /// tables, and a main table read empty with a symbol to decode under
    /// it. Each on the serial walk, the tape walk at a stated width of one
    /// (the walk on one thread) and of four, and through the chain's
    /// decode-ahead. The tape lanes are the decoder's own scoped threads,
    /// at most four here; no rayon pool is used, and memory is under
    /// 16 MiB.
    #[test]
    fn a_block_past_the_end_whose_tables_do_not_read_passes_and_drops_the_set() {
        let lead = || {
            one(
                Set::Wide,
                lits(b"a member before, so the next is offered. "),
                41,
            )
        };
        let whole = || {
            let mut member = two_blocks();
            member.blocks[1].tables = true;
            member
        };
        let first_len = {
            let mut first = two_blocks();
            first.blocks.truncate(1);
            packed(&first).len()
        };
        let header_len = |bytes: &[u8]| 2 + usize::from((bytes[first_len] >> 3) & 3) + 1;
        let mut damaged: Vec<(&str, Vec<u8>)> = Vec::new();
        for (name, nibbles) in [("zero levels", 0x00u8), ("over-subscribed levels", 0x11)] {
            let mut bytes = packed(&whole());
            let payload = first_len + header_len(&bytes);
            for byte in &mut bytes[payload..payload + 10] {
                *byte = nibbles;
            }
            damaged.push((name, bytes));
        }
        {
            // The block ends six bytes into its tables.
            let bytes = packed(&whole());
            let payload = first_len + header_len(&bytes);
            let flags = bytes[first_len] & !0x18;
            let mut cut = bytes[..first_len].to_vec();
            cut.extend_from_slice(&[flags, 0x5a ^ flags ^ 6, 6]);
            cut.extend_from_slice(&bytes[payload..payload + 6]);
            damaged.push(("cut tables", cut));
        }
        {
            // A main table with no symbol, and eight bits to decode under it.
            let mut member = two_blocks();
            member.blocks[1] = Block {
                set: Set::Narrow(&[]),
                tables: true,
                ops: vec![Op::Raw(0x2a, 8)],
            };
            damaged.push(("empty main table", packed(&member)));
        }

        let own = || one(Set::Wide, vec![Op::Fresh(8, 6), Op::Lit(b'.')], 7);
        let leaning = || Member {
            blocks: vec![Block {
                set: Set::Wide,
                tables: false,
                ops: lits(b"leaning"),
            }],
            declared: 7,
        };
        // What the members read with the damaged block ABSENT.
        let mut without = two_blocks();
        without.blocks.truncate(1);
        let want = model(&[lead(), without, own()]);
        let declared = [41u64, 32, 7];

        let mut ways: Vec<(Arm, Option<usize>)> = vec![(Arm::Serial, None)];
        #[cfg(feature = "parallel")]
        ways.extend([
            (Arm::Tape, Some(1)),
            (Arm::Tape, Some(4)),
            (Arm::Ahead, Some(4)),
        ]);
        let mut wrong: Vec<String> = Vec::new();
        for (damage, bytes) in &damaged {
            for &(arm, width) in &ways {
                let at = format!("{damage}, {arm:?} at {width:?}");
                let chain = [packed(&lead()), bytes.clone(), packed(&own())];
                let got = run_packed_at(&chain, &declared, arm, width);
                for (index, (outcome, bytes)) in got.iter().enumerate() {
                    if outcome.is_err() || bytes != &want[index] {
                        wrong.push(format!("{at}, own tables, member {index}: {outcome:?}"));
                    }
                }
                let chain = [packed(&lead()), bytes.clone(), packed(&leaning())];
                let got = run_packed_at(&chain, &declared, arm, width);
                if got[1].0.is_err() || got[1].1 != want[1] {
                    wrong.push(format!("{at}, leaning, member 1: {:?}", got[1].0));
                }
                if !matches!(&got[2].0, Err(err) if matches!(err.kind(),
                    ErrorKind::Corrupt(Corruption::Rar5(Rar5Fault::EmptyTable))))
                {
                    wrong.push(format!("{at}, the leaning member: {:?}", got[2].0));
                }
                // BEFORE the declared end the member owes the block's
                // bytes, and a table that does not read fails it.
                let got = run_packed_at(std::slice::from_ref(bytes), &[36], arm, width);
                if got[0].0.is_ok() {
                    wrong.push(format!("{at}, before the end: passed"));
                }
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }
}
