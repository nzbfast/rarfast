//! The block header and the block chain (SPEC-H2 sections 3.1 and 3.2).
//!
//! A block's extent is known from its header alone, so the chain can be
//! walked and every block located without decoding a single symbol. That is
//! the property the parallel decode rests on (section 3.8) and the one
//! performance requirement that is also a framing rule (section 7.3 item 4).
//!
//! Implemented from `specs/SPEC-H2-rarkit-rar5-lz.md` alone.

use super::fault;
use crate::Result;

/// This block carries its own tables (section 3.2).
pub(crate) const FLAG_TABLES: u8 = 0x80;
/// This is the last block of the member.
pub(crate) const FLAG_LAST: u8 = 0x40;
/// The header's byte wise check must come to this.
pub(crate) const HEADER_CHECK: u8 = 0x5a;

/// What byte 0 of a block header states, and all that it states
/// (section 3.2.1, the class question; rows L1 and L2). The 64 byte values
/// whose width field is 3 have no class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Class {
    /// How many size bytes the header has: 1, 2 or 3.
    width: u8,
    /// How many bits of the payload's last byte are valid: 1 to 8.
    tail_bits: u8,
    /// Tables stand at the front of the payload.
    tables: bool,
    /// No block of the member follows.
    last: bool,
}

impl Class {
    /// The class of one byte 0, or `None` for "no header". A function of
    /// the byte and of nothing else.
    pub(crate) const fn of(lead: u8) -> Option<Class> {
        let width_field = (lead >> 3) & 3;
        if width_field == 3 {
            return None;
        }
        Some(Class {
            width: width_field + 1,
            tail_bits: (lead & 7) + 1,
            tables: lead & FLAG_TABLES != 0,
            last: lead & FLAG_LAST != 0,
        })
    }
}

/// What a header's size bytes state once its seal holds (section 3.2.1,
/// the reach question; rows L4 to L6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Reach {
    /// The payload's first byte.
    first: usize,
    /// The byte after the payload's last, which is the next header's first.
    after: usize,
    /// The bits the payload holds: the decode asks more than once a block.
    bits: usize,
}

/// One located block, held in the two parts section 3.2.1 names: the
/// class and the reach. The reach counts from the byte the search was
/// given as the header's first, unless [`Located::placed_at`] moved it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Located {
    class: Class,
    reach: Reach,
}

impl Located {
    /// Where the next block's header starts.
    #[inline]
    pub(crate) fn past(&self) -> usize {
        self.reach.after
    }

    /// The payload, out of the bytes the reach counts in.
    #[inline]
    pub(crate) fn payload<'a>(&self, packed: &'a [u8]) -> &'a [u8] {
        &packed[self.reach.first..self.reach.after]
    }

    /// The bits the block holds: every bit of each payload byte but the
    /// last, and of the last the `b + 1` the class names. An empty payload
    /// holds none.
    #[inline]
    pub(crate) fn bits(&self) -> usize {
        self.reach.bits
    }

    /// Tables stand at the front of this block's payload.
    #[inline]
    pub(crate) fn carries_tables(&self) -> bool {
        self.class.tables
    }

    /// No block of the member follows this one.
    #[inline]
    pub(crate) fn ends_member(&self) -> bool {
        self.class.last
    }

    /// The same block with its reach counted from `at` bytes earlier,
    /// for a caller that searched at `at` in a longer run of bytes.
    // The tape's alone, which the `parallel` feature carries.
    #[cfg_attr(not(feature = "parallel"), allow(dead_code))]
    #[inline]
    pub(crate) fn placed_at(self, at: usize) -> Located {
        Located {
            class: self.class,
            reach: Reach {
                first: self.reach.first + at,
                after: self.reach.after + at,
                bits: self.reach.bits,
            },
        }
    }
}

/// How many bytes the block at `input[0..]` occupies, read from its header
/// alone and without checking it. A source that delivers a member in pieces
/// fills this much before [`block_in_hand`] runs; a short header answers the
/// header's own ceiling, so the caller asks again.
pub(crate) fn extent_hint(input: &[u8]) -> usize {
    let Some(&flags) = input.first() else {
        return 5;
    };
    let width = usize::from((flags >> 3) & 3) + 1;
    let header_len = 2 + width;
    if width > 3 {
        // The width the format does not have, which `block_in_hand`
        // refuses: there is no payload to ask for, and four size bytes
        // added to the header overflow a 32-bit `usize`.
        return header_len;
    }
    let Some(size_bytes) = input.get(2..header_len) else {
        return header_len;
    };
    let mut size = 0usize;
    for (index, &byte) in size_bytes.iter().enumerate() {
        size |= usize::from(byte) << (8 * index);
    }
    header_len + size
}

/// What a block's header says of its table bit, asked of the block's first
/// bytes alone: `Some(true)` when tables stand at the front of the payload
/// and `Some(false)` when the block reads its symbols with the tables the
/// block before it left (section 3.2, `flags & 0x80`).
///
/// `head` need hold no more than the header, which is [`HEAD_PROBE`] bytes
/// at the most. The answer is `None`, "cannot say", for anything that is
/// not a whole header whose seal holds: a byte 0 with no class, fewer
/// bytes than the header has, or a check relation that fails. Those are
/// [`locate`]'s three faults and it is asked, so the two cannot come to
/// differ; the reach it also forms is a few instructions once a member.
#[cfg(feature = "parallel")]
pub(crate) fn header_says_tables(head: &[u8]) -> Option<bool> {
    let block = locate(head).ok()?;
    Some(block.carries_tables())
}

/// The most bytes [`header_says_tables`] ever looks at: two header bytes and
/// the widest size field the format has.
#[cfg(feature = "parallel")]
pub(crate) const HEAD_PROBE: usize = 5;

/// The block whose header starts at `packed[0]`, by the four questions of
/// section 3.2.1 in their order. No symbol is decoded, and whether
/// `packed` holds the payload is not asked here.
///
/// The faults, in the order a header with more than one answers them:
/// `BlockSizeWidth` when byte 0 has no class, with no other byte looked
/// at; `Truncated` when `packed` ends inside the header; and
/// `BlockHeaderChecksum` when the header's bytes do not combine to
/// [`HEADER_CHECK`].
pub(crate) fn locate(packed: &[u8]) -> Result<Located> {
    // Class: one byte decides it.
    let Some(&lead) = packed.first() else {
        return Err(fault::truncated());
    };
    let Some(class) = Class::of(lead) else {
        return Err(fault::block_size_width());
    };
    // Span: every byte of the header, or nothing can be said of it.
    let span_len = 2 + usize::from(class.width);
    let Some(span) = packed.get(..span_len) else {
        return Err(fault::truncated());
    };
    // Seal: each byte of the span has the same part in it.
    let mut seal = 0u8;
    for &byte in span {
        seal ^= byte;
    }
    if seal != HEADER_CHECK {
        return Err(fault::block_header_checksum());
    }
    // Reach: the size bytes are the low bytes of a little endian word
    // whose missing high bytes are zero, so at most `0xff_ffff`.
    let mut word = [0u8; 4];
    word[..span_len - 2].copy_from_slice(&span[2..]);
    let length = u32::from_le_bytes(word) as usize;
    let bits = if length == 0 {
        0
    } else {
        (length - 1) * 8 + usize::from(class.tail_bits)
    };
    Ok(Located {
        class,
        reach: Reach {
            first: span_len,
            after: span_len + length,
            bits,
        },
    })
}

/// [`locate`], and then the question the decode asks when it comes to
/// need the payload: are all its bytes in `packed`. `Truncated` when they
/// are not, after every fault of the header itself.
pub(crate) fn block_in_hand(packed: &[u8]) -> Result<Located> {
    let block = locate(packed)?;
    if block.reach.after > packed.len() {
        return Err(fault::truncated());
    }
    Ok(block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Corruption, ErrorKind, Rar5Fault};

    fn fault_of(err: crate::Error) -> Rar5Fault {
        match err.kind() {
            ErrorKind::Corrupt(Corruption::Rar5(f)) => *f,
            other => panic!("wanted a RAR 5 fault, got {other:?}"),
        }
    }

    /// A header whose check holds, built the way section 3.2 states.
    pub(crate) fn header(flags: u8, size: usize, width: usize) -> Vec<u8> {
        let flags = (flags & !0x18) | ((width as u8 - 1) << 3);
        let mut acc = HEADER_CHECK ^ flags;
        let mut out = vec![flags, 0];
        for index in 0..width {
            let byte = (size >> (8 * index)) as u8;
            out.push(byte);
            acc ^= byte;
        }
        out[1] = acc;
        out
    }

    #[test]
    fn a_located_block_names_its_payload_and_its_bit_count() {
        let mut input = header(FLAG_TABLES | FLAG_LAST | 2, 4, 1);
        input.extend_from_slice(&[1, 2, 3, 4, 0xff]);
        let block = block_in_hand(&input).unwrap();
        assert_eq!(block.payload(&input), &[1, 2, 3, 4]);
        assert_eq!(block.past(), 7);
        // Three whole bytes plus three valid bits in the fourth.
        assert_eq!(block.bits(), 3 * 8 + 3);
        assert!(block.carries_tables());
        assert!(block.ends_member());
        // Searched for 100 bytes into a longer run, it is the same block
        // 100 bytes on.
        let mut run = vec![0u8; 100];
        run.extend_from_slice(&input);
        let placed = block_in_hand(&run[100..]).unwrap().placed_at(100);
        assert_eq!(placed.payload(&run), &[1, 2, 3, 4]);
        assert_eq!((placed.past(), placed.bits()), (107, 27));
    }

    #[test]
    fn an_empty_payload_holds_no_bits() {
        // Whatever `b` says, 0 or 7 (section 3.2's empty payload probes).
        for b in [0u8, 7] {
            let input = header(b, 0, 1);
            let block = block_in_hand(&input).unwrap();
            assert_eq!(block.bits(), 0);
            assert_eq!((block.payload(&input).len(), block.past()), (0, 3));
        }
    }

    #[test]
    fn the_last_byte_holds_one_to_eight_bits() {
        for b in 0..8u8 {
            let mut input = header(b, 2, 1);
            input.extend_from_slice(&[0, 0]);
            assert_eq!(
                block_in_hand(&input).unwrap().bits(),
                8 + usize::from(b) + 1
            );
        }
    }

    /// Section 3.2 calls a payload above 75,016 bytes "not established"
    /// for the reference; a three byte size names up to 16,777,215. This
    /// pins what the decoder does today: it finds the widest block there
    /// can be, and one of 75,017 bytes. Single threaded; 16 MiB.
    #[test]
    fn a_payload_past_the_largest_probed_is_found_as_today() {
        for size in [75_017usize, 0xff_ffff] {
            let mut input = header(FLAG_LAST | 4, size, 3);
            input.resize(5 + size, 0);
            let block = block_in_hand(&input).unwrap();
            assert_eq!(
                (block.payload(&input).len(), block.past()),
                (size, 5 + size)
            );
            assert_eq!(block.bits(), 8 * (size - 1) + 5);
            input.pop();
            assert!(matches!(
                block_in_hand(&input).unwrap_err().kind(),
                ErrorKind::Truncated
            ));
        }
    }

    /// Section 3.2: no meaning is established for flag bit `0x20`, and
    /// the reference reads a block with it set as without. This pins the
    /// same here: the bit changes the check byte and nothing else.
    #[test]
    fn flag_bit_0x20_changes_nothing_but_the_check() {
        for flags in [0u8, FLAG_TABLES | 3, FLAG_LAST | 7, FLAG_TABLES | FLAG_LAST] {
            let mut plain = header(flags, 9, 1);
            plain.extend_from_slice(&[0; 9]);
            let mut set = header(flags | 0x20, 9, 1);
            set.extend_from_slice(&[0; 9]);
            let (plain, set) = (block_in_hand(&plain).unwrap(), block_in_hand(&set).unwrap());
            assert_eq!(
                (
                    set.past(),
                    set.bits(),
                    set.carries_tables(),
                    set.ends_member()
                ),
                (
                    plain.past(),
                    plain.bits(),
                    plain.carries_tables(),
                    plain.ends_member()
                )
            );
        }
    }

    /// V5-CHK: each of the four checksum bytes flipped one bit at a time.
    #[test]
    fn v5_chk_every_single_bit_flip_in_the_header_is_refused() {
        let mut good = header(FLAG_TABLES, 0x1234, 2);
        good.extend(std::iter::repeat_n(0u8, 0x1234));
        assert!(block_in_hand(&good).is_ok());
        for byte in 0..4 {
            for bit in 0..8 {
                let mut bad = good.clone();
                bad[byte] ^= 1 << bit;
                // A flip inside the size field's own bytes moves the
                // payload length too; the check is what refuses it either
                // way, unless the flip landed in the width field and made
                // the header a different shape.
                let outcome = block_in_hand(&bad);
                match outcome {
                    Err(e) => assert!(matches!(
                        fault_of(e),
                        Rar5Fault::BlockHeaderChecksum | Rar5Fault::BlockSizeWidth
                    )),
                    Ok(_) => panic!("bit {bit} of byte {byte} was not refused"),
                }
            }
        }
    }

    /// `header_says_tables` must answer exactly what `block_in_hand` does,
    /// on five bytes instead of the whole block, or the decode-ahead's
    /// early refusal would refuse a member the stage would have taken.
    ///
    /// It FAILS if the head form stops checking the header's own check
    /// byte: the mutation loop below feeds it headers whose check does not
    /// hold, and a form that only read the flag bit would answer `Some`
    /// for them where `block_in_hand` answers an error.
    #[cfg(feature = "parallel")]
    #[test]
    fn the_head_form_agrees_with_block_in_hand_on_every_sound_header() {
        for &width in &[1usize, 2, 3] {
            for &size in &[0usize, 1, 7, 300, 70_000] {
                if size >= 1 << (8 * width) {
                    continue;
                }
                for &tables in &[true, false] {
                    for &last in &[true, false] {
                        let mut flags = 0u8;
                        if tables {
                            flags |= FLAG_TABLES;
                        }
                        if last {
                            flags |= FLAG_LAST;
                        }
                        let mut input = header(flags, size, width);
                        assert!(input.len() <= HEAD_PROBE, "a header fits the probe");
                        input.extend(std::iter::repeat_n(0u8, size));
                        let located = block_in_hand(&input).expect("a sound header");
                        assert_eq!(
                            header_says_tables(&input[..HEAD_PROBE.min(input.len())]),
                            Some(located.carries_tables()),
                            "width {width}, size {size}"
                        );
                    }
                }
            }
        }
    }

    /// Everything the head form must answer `None` for, because `None` is
    /// "let the stage decide" and a wrong `Some(false)` costs the lever a
    /// member it could have taken.
    #[cfg(feature = "parallel")]
    #[test]
    fn the_head_form_cannot_say_on_bytes_that_are_not_a_sound_header() {
        let good = header(FLAG_TABLES, 0x1234, 2);
        assert_eq!(header_says_tables(&good), Some(true));
        // Too few bytes to reach the size field.
        for short in 0..good.len() {
            assert_eq!(
                header_says_tables(&good[..short]),
                None,
                "{short} bytes is not enough to decide"
            );
        }
        // A check byte that does not hold.
        let mut bad = good.clone();
        bad[1] ^= 0x01;
        assert_eq!(header_says_tables(&bad), None);
        // The width field the format does not have.
        assert_eq!(header_says_tables(&[0x18u8, 0, 0, 0, 0]), None);
    }

    #[test]
    fn a_size_width_field_of_three_is_refused() {
        // Width 3 means the two bit field holds 3, so four size bytes.
        let input = [0x18u8, 0, 0, 0, 0];
        assert_eq!(
            fault_of(block_in_hand(&input).unwrap_err()),
            Rar5Fault::BlockSizeWidth
        );
    }

    /// The size width the format does not have (the two bit field at 3,
    /// four size bytes) is refused by [`block_in_hand`], and the hint that
    /// runs BEFORE it must answer the header alone: there is no payload
    /// to fetch for a block that cannot be one. It answered the header
    /// plus the four size bytes' value.
    ///
    /// TARGET: on a 32-bit `usize` (armv7-unknown-linux-musleabihf) that
    /// sum, `6 + 0xffff_ffff`, overflows: a panic with overflow checks on,
    /// which every test and fuzz build has. On a 64-bit target it fails
    /// before the fix on the value, a 4 GiB ask of the source.
    ///
    /// One thread, no pool; no memory to speak of.
    #[test]
    fn the_hint_for_the_refused_size_width_is_the_header_alone() {
        let input = [0x18u8, 0, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(extent_hint(&input), 6);
        assert_eq!(
            fault_of(block_in_hand(&input).unwrap_err()),
            Rar5Fault::BlockSizeWidth
        );
        // The widest width the format has is unchanged: 5 + 0xff_ffff.
        let widest = [0x10u8, 0, 0xff, 0xff, 0xff];
        assert_eq!(extent_hint(&widest), 5 + 0xff_ffff);
    }

    /// V5-LOCATE (a): the class question over every value of byte 0.
    #[test]
    fn v5_locate_a_every_byte_0_has_its_class_or_none() {
        let mut none = 0;
        for lead in 0..=255u8 {
            let field = (lead >> 3) & 3;
            match Class::of(lead) {
                None => {
                    assert_eq!(field, 3, "byte {lead:#04x}");
                    none += 1;
                }
                Some(class) => {
                    assert_eq!(
                        (class.width, class.tables, class.last, class.tail_bits),
                        (field + 1, lead >= 0x80, lead & 0x40 != 0, lead % 8 + 1),
                        "byte {lead:#04x}"
                    );
                }
            }
        }
        assert_eq!(none, 64);
    }

    /// V5-LOCATE (b), (c), (d): the fault a header with more than one
    /// answers is `BlockSizeWidth` before `Truncated` before
    /// `BlockHeaderChecksum`. The same of [`block_in_hand`], whose own
    /// question comes after all three.
    #[test]
    fn v5_locate_the_fault_order_is_width_then_truncated_then_checksum() {
        let both = |input: &[u8]| {
            let (plain, in_hand) = (locate(input), block_in_hand(input));
            assert_eq!(plain.is_ok(), in_hand.is_ok());
            (plain.unwrap_err(), in_hand.unwrap_err())
        };
        // (b) A width field of 3: alone as the last byte, and followed by
        // bytes that make the relation hold over three and over four
        // size bytes.
        let lead = 0x18u8 | FLAG_TABLES | 5;
        let seal = HEADER_CHECK ^ lead;
        let arms: [&[u8]; 3] = [&[lead], &[lead, seal, 0, 0, 0], &[lead, seal, 0, 0, 0, 0]];
        for arm in arms {
            let (plain, in_hand) = both(arm);
            assert_eq!(fault_of(plain), Rar5Fault::BlockSizeWidth);
            assert_eq!(fault_of(in_hand), Rar5Fault::BlockSizeWidth);
        }
        // (c) `w = 2`, so a header of four bytes, with three there: the
        // three give 0x5a by exclusive or, and then do not.
        let lead = 0x08u8;
        for second in [HEADER_CHECK ^ lead ^ 0x33, 0] {
            let (plain, in_hand) = both(&[lead, second, 0x33]);
            assert!(matches!(plain.kind(), ErrorKind::Truncated));
            assert!(matches!(in_hand.kind(), ErrorKind::Truncated));
        }
        // (d) A whole header whose relation fails and whose size bytes
        // name more bytes than are there.
        let mut bad = header(FLAG_LAST, 0xffff, 2);
        bad[1] ^= 0x04;
        bad.extend_from_slice(&[0; 7]);
        let (plain, in_hand) = both(&bad);
        assert_eq!(fault_of(plain), Rar5Fault::BlockHeaderChecksum);
        assert_eq!(fault_of(in_hand), Rar5Fault::BlockHeaderChecksum);
    }

    /// V5-LOCATE (e): the bit counts, from headers alone. The reach
    /// question does not ask for the payload (section 3.2.1 step 4), so
    /// none is supplied. No allocation beyond a five byte header.
    #[test]
    fn v5_locate_e_bit_counts_from_the_header_alone() {
        for (length, width, b, bits) in [
            (0usize, 1usize, 0u8, 0usize),
            (0, 1, 7, 0),
            (1, 1, 0, 1),
            (1, 1, 7, 8),
            (3, 1, 2, 19),
            (75_016, 3, 7, 600_128),
        ] {
            let input = header(b, length, width);
            let block = locate(&input).unwrap();
            assert_eq!(block.bits(), bits, "length {length}, b {b}");
            assert_eq!(block.past(), 2 + width + length);
        }
    }

    #[test]
    fn a_short_payload_is_truncated() {
        let mut input = header(0, 16, 1);
        input.extend_from_slice(&[0; 15]);
        assert!(matches!(
            block_in_hand(&input).unwrap_err().kind(),
            ErrorKind::Truncated
        ));
        assert!(matches!(
            block_in_hand(&input[..1]).unwrap_err().kind(),
            ErrorKind::Truncated
        ));
    }
}
