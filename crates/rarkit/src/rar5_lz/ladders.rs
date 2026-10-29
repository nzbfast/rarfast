//! The two ladders of SPEC-H2 section 3.5: what a length slot and a
//! distance slot name, with their extra bits.
//!
//! Each slot names a run of values and the runs follow one another, so a
//! slot is known by two numbers: how many extra bits it reads, and how
//! many values the slots before it name between them. Both are worked
//! out here from the section's words, for every slot of both alphabets.
//!
//! Implemented from `specs/SPEC-H2-rarkit-rar5-lz.md` alone.

/// Length slots in the length alphabet (section 3.3: 44 symbols).
pub(crate) const LENGTH_SLOTS: usize = 44;
/// Distance slots of a version 0 member.
pub(crate) const DISTANCE_SLOTS_V0: usize = 64;
/// Distance slots of a version 1 member (RAR 7's wider alphabet is
/// READ, and a distance it names fails on the window rather than early).
pub(crate) const DISTANCE_SLOTS_V1: usize = 80;

/// Extra bits read for each length slot: none below slot 8, otherwise
/// `(s >> 2) - 1`.
pub(crate) const LENGTH_SLOT_EXTRA_BITS: [u8; LENGTH_SLOTS] = build_length_extra_bits();
/// How many extra bits follow length slot `slot`, or `None` where `slot`
/// is not one of the length alphabet's 44 (section 1.3.1, rule R1: the one
/// bound the format gives a length slot is the size of its alphabet, so
/// that is the one thing asked of it, and a caller names `LengthSlot` on
/// `None`). No stream holds such a slot: the length code is built from 44
/// lengths and a fresh match's slot is its main symbol less 262.
#[inline(always)]
pub(crate) fn bits_after_slot(slot: usize) -> Option<u8> {
    LENGTH_SLOT_EXTRA_BITS.get(slot).copied()
}

/// The refusal of a number that is no length slot, which no stream
/// reaches. OUT OF LINE AND COLD ON aarch64, IN PLACE EVERYWHERE ELSE, AND
/// THAT IS MEASURED, NOT AN OVERSIGHT TO UNIFY (9 Oct 2026): built inside
/// the tape decoder's symbol loop, the profile-guided aarch64 build keeps
/// the literal loop's cursor and limits on the stack (9 to 20 percent
/// more instructions on every RAR 5 row); the x86-64 build does not, and
/// pays 2 to 4 percent of its instructions for the cold call. The rule
/// and the answer are section 1.3.1's on both. The same holds of
/// [`refuse_length_slot`] and of `tape::decode::length_slot_stop`.
// The tape readers', which the `parallel` feature carries, and on aarch64
// the serial reader's too (`serial::read_length_slot`), which every build
// carries: so it is compiled wherever one of the two calls it.
#[cfg(any(feature = "parallel", target_arch = "aarch64"))]
#[cfg_attr(target_arch = "aarch64", cold, inline(never))]
#[cfg_attr(not(target_arch = "aarch64"), inline(always))]
pub(crate) fn no_such_length_slot() -> crate::error::Error {
    super::fault::length_slot()
}

/// [`no_such_length_slot`] as a reader's whole answer, so the reader's
/// way out is one call and a return with nothing built in the loop.
// The tape readers' alone, which the `parallel` feature carries.
#[cfg(feature = "parallel")]
#[cfg_attr(target_arch = "aarch64", cold, inline(never))]
#[cfg_attr(not(target_arch = "aarch64"), inline(always))]
pub(crate) fn refuse_length_slot<T>() -> crate::error::Result<T> {
    Err(no_such_length_slot())
}

/// Extra bits contributed by each distance slot: none below slot 4,
/// otherwise `(t - 2) >> 1`. Defined over all 80 slots.
pub(crate) const DISTANCE_SLOT_BITS: [u8; DISTANCE_SLOTS_V1] = build_distance_slot_bits();
/// The length a slot names before its extra bits and before the bonus:
/// the length is this plus the extra bits, `+` and `|` agreeing because
/// the extra bits sit under the base's lowest set bit. The fast region's
/// fresh match reads it (`tape::fresh_match_in_region`, lever 4 of the
/// fresh match), where it takes `length_from_slot`'s branch on slot 8.
// The fast region's alone, which the `parallel` feature carries.
#[cfg_attr(not(feature = "parallel"), allow(dead_code))]
pub(crate) const LENGTH_SLOT_BASE: [u32; LENGTH_SLOTS] = build_length_bases();
/// One less than the first distance each slot names, where a `u32` holds
/// it: the count of distances that every earlier slot names between them
/// (section 3.5: slot 0 begins at 1 and each later slot begins where the
/// one before it ends). A slot's distance is this, its extra bits' value
/// and one more. From slot 64 on the count is past a `u32` and the entry
/// is `u32::MAX`, which nothing reads: the fast region comes here only for
/// a slot of fewer than 30 extra bits (`tape::decode::FAR_SLOT_BITS`).
// The fast region's alone, which the `parallel` feature carries.
#[cfg_attr(not(feature = "parallel"), allow(dead_code))]
pub(crate) const DISTANCE_SLOT_BASE: [u32; DISTANCE_SLOTS_V1] = build_distance_bases();

/// The length ladder's counts of extra bits (section 3.5, and the `rar5`
/// `length` rows of `vectors-H/ladders.tsv`): none for the first eight
/// slots, then the slots in fours that share a count, 1 for the first four
/// and one more for each four after.
const fn build_length_extra_bits() -> [u8; LENGTH_SLOTS] {
    let mut counts = [0u8; LENGTH_SLOTS];
    let mut slot = 8;
    while slot < LENGTH_SLOTS {
        counts[slot] = ((slot - 8) / 4 + 1) as u8;
        slot += 1;
    }
    counts
}

const fn build_distance_slot_bits() -> [u8; DISTANCE_SLOTS_V1] {
    // Section 3.5: none for the first four slots, then the slots in pairs
    // that share a count, 1 for the first pair and one more for each pair
    // after; slots 64 to 79 carry the same rule on.
    let mut counts = [0u8; DISTANCE_SLOTS_V1];
    let mut slot = 4;
    while slot < DISTANCE_SLOTS_V1 {
        counts[slot] = ((slot - 4) / 2 + 1) as u8;
        slot += 1;
    }
    counts
}

// The fast region's alone, which the `parallel` feature carries.
#[cfg_attr(not(feature = "parallel"), allow(dead_code))]
const fn build_distance_bases() -> [u32; DISTANCE_SLOTS_V1] {
    // The runs follow one another: a slot of `n` extra bits names `2^n`
    // distances, so the count before a slot is the sum of the runs of the
    // slots before it. Kept in 64 bits; an entry past a `u32` is left at
    // `u32::MAX`.
    let mut bases = [u32::MAX; DISTANCE_SLOTS_V1];
    let mut before: u64 = 0;
    let mut slot = 0;
    while slot < DISTANCE_SLOTS_V1 && before <= u32::MAX as u64 {
        bases[slot] = before as u32;
        before += 1u64 << DISTANCE_SLOT_BITS[slot];
        slot += 1;
    }
    bases
}

// The fast region's alone, which the `parallel` feature carries.
#[cfg_attr(not(feature = "parallel"), allow(dead_code))]
const fn build_length_bases() -> [u32; LENGTH_SLOTS] {
    // Slot 0 begins at 2 and each later slot begins where the one before
    // it ends, a slot of `n` extra bits naming `2^n` lengths.
    let mut bases = [0u32; LENGTH_SLOTS];
    let mut next: u32 = 2;
    let mut slot = 0;
    while slot < LENGTH_SLOTS {
        bases[slot] = next;
        next += 1 << LENGTH_SLOT_EXTRA_BITS[slot];
        slot += 1;
    }
    bases
}

/// The length a slot and its extra bits name (section 3.5, "A length
/// from a slot"). Slots 0 to 7 read no extra bits and name `slot + 2`.
/// From slot 8 the slots go in fours that share a count of extra bits, 1
/// for the first four and one more for each four after, and every run
/// begins where the one before it ends: the base is 2 more than
/// `4 + slot % 4` shifted up by the count.
#[inline(always)]
pub(crate) fn length_from_slot(slot: usize, extra: u32) -> usize {
    if slot < 8 {
        return slot + 2;
    }
    let count = slot / 4 - 1;
    2 + ((4 + slot % 4) << count) + extra as usize
}

/// The last distance slot whose run this file gives a place: section 3.5
/// establishes what slots 0 to 65 name, and of slots 66 to 79 only how
/// many bits they take.
const LAST_PLACED_SLOT: usize = 65;

/// For each distance slot, how many distances the slots before it name
/// between them, in 64 bits: slot 63's run ends at `2^32` and slot 65's
/// at `2^33`, past a `u32` and, on a 32 bit target, past a pointer. A
/// slot after [`LAST_PLACED_SLOT`] has no entry it could be found by:
/// `u64::MAX`, so that whatever is added to it stays past every window.
const DISTANCES_BEFORE_SLOT: [u64; DISTANCE_SLOTS_V1] = count_distances_before();

const fn count_distances_before() -> [u64; DISTANCE_SLOTS_V1] {
    let mut before = [u64::MAX; DISTANCE_SLOTS_V1];
    let mut named: u64 = 0;
    let mut slot = 0;
    while slot <= LAST_PLACED_SLOT {
        before[slot] = named;
        named += 1u64 << DISTANCE_SLOT_BITS[slot];
        slot += 1;
    }
    before
}

/// The distance a slot and its extra bits name (section 3.5, "A distance
/// from a slot"): the count of distances the slots before it name, the
/// value of its extra bits, and one more, since slot 0 begins at 1.
///
/// The sum is formed in 64 bits, where no slot the section places can
/// overflow it: slot 63's last is `2^32` and slot 65's is `2^33`. A slot
/// the section does not place (66 to 79), and any number past the
/// alphabet, counts from `u64::MAX` and stays there. Where the sum does
/// not fit in a pointer, which on a 32 bit target is slot 63's last, the
/// answer is `usize::MAX`. Both are distances past every window, so the
/// match fails on the window as `DistanceOutOfRange` (section 3.7) and
/// never copies from a wrong place (section 3.5, "Slots 64 to 79").
#[inline(always)]
pub(crate) fn distance_named(slot: usize, extra: u32) -> usize {
    let before = DISTANCES_BEFORE_SLOT.get(slot).copied().unwrap_or(u64::MAX);
    let distance = before.saturating_add(u64::from(extra) + 1);
    usize::try_from(distance).unwrap_or(usize::MAX)
}

/// The value of a distance slot's extra bits where the slot has four or
/// more of them (section 3.5, "The extra bits of a distance"): `plain`,
/// the bits read from the stream first, are every bit above the lowest
/// four, and the lowest four are `alignment`, one symbol of the alignment
/// code.
#[inline(always)]
pub(crate) fn extra_bits_value(plain: u32, alignment: usize) -> u32 {
    plain * 16 + alignment as u32
}

/// Distances past which a fresh match is one byte longer, a byte for
/// each (section 3.5, "The length bonus"). "Past" is strict: a distance
/// of exactly `0x100` gains nothing.
const LONGER_PAST: [usize; 3] = [0x100, 0x2000, 0x4_0000];

/// A fresh match's whole length: `laddered`, which its slot and extra
/// bits named, and a byte more for every entry of [`LONGER_PAST`] its
/// distance lies beyond. A repeated distance match and a last length
/// repeat do not come here: their length is the laddered one.
#[inline(always)]
pub(crate) fn fresh_match_length(laddered: usize, distance: usize) -> usize {
    LONGER_PAST.iter().fold(laddered, |length, &edge| {
        length + usize::from(distance > edge)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every row of `specs/vectors-H/ladders.tsv` tagged `rar5`
    /// (section 5.3).
    #[cfg(feature = "repo-tests")]
    #[test]
    fn ladders_tsv_matches_every_slot() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../specs/vectors-H/ladders.tsv"
        );
        let text = std::fs::read_to_string(path).expect("ladders.tsv");
        let mut lengths = 0;
        let mut distances = 0;
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split('\t').collect();
            if f[0] != "rar5" {
                continue;
            }
            let slot: usize = f[2].parse().unwrap();
            let extra: u8 = f[3].parse().unwrap();
            let base: u64 = f[4].parse().unwrap();
            let first: u64 = f[5].parse().unwrap();
            let last: u64 = f[6].parse().unwrap();
            match f[1] {
                "length" => {
                    lengths += 1;
                    assert_eq!(LENGTH_SLOT_EXTRA_BITS[slot], extra, "length slot {slot}");
                    assert_eq!(u64::from(LENGTH_SLOT_BASE[slot]), base, "base {slot}");
                    assert_eq!(length_from_slot(slot, 0) as u64, first, "first {slot}");
                    let top = (1u64 << extra) - 1;
                    assert_eq!(
                        length_from_slot(slot, top as u32) as u64,
                        last,
                        "last {slot}"
                    );
                }
                "distance" => {
                    distances += 1;
                    assert_eq!(DISTANCE_SLOT_BITS[slot], extra, "distance slot {slot}");
                    let top = (1u64 << extra) - 1;
                    assert_eq!(DISTANCES_BEFORE_SLOT[slot], base - 1, "base {slot}");
                    let named = |extra: u64| distance_named(slot, extra as u32) as u64;
                    // A 64 bit pointer holds every distance of the 64 slots;
                    // a narrower one holds them up to slot 63's last.
                    if last <= usize::MAX as u64 {
                        assert_eq!((named(0), named(top)), (first, last), "slot {slot}");
                    } else {
                        assert_eq!(named(top), usize::MAX as u64, "slot {slot} saturates");
                    }
                }
                other => panic!("unknown alphabet {other}"),
            }
        }
        assert_eq!(lengths, LENGTH_SLOTS);
        assert_eq!(distances, DISTANCE_SLOTS_V0);
    }

    /// Section 5.3: slot 63's last value is 2^32, and slot 43's length
    /// reaches 4,097 (section 3.5).
    #[test]
    fn the_ladders_reach_their_stated_ends() {
        assert_eq!(DISTANCE_SLOT_BITS[63], 30);
        assert_eq!(DISTANCES_BEFORE_SLOT[63] + (1 << 30), 1 << 32);
        assert_eq!(LENGTH_SLOT_EXTRA_BITS[43], 9);
        assert_eq!(length_from_slot(43, (1 << 9) - 1), 4_097);
    }

    /// Section 1.3.1, rule R1: what bounds a length slot is its alphabet,
    /// 0 to 43, and nothing else. Every slot of the 44 has its count of
    /// extra bits, 0 to 9 (section 3.5), and the first number past the
    /// alphabet has none, which the decoders name `LengthSlot`.
    #[test]
    fn a_length_slot_is_bounded_by_its_alphabet_and_nothing_else() {
        // The function's answer for every number from 0 to 44 at once: the
        // table's entry for each slot of the alphabet, then nothing.
        let answered: Vec<Option<u8>> = (0..=LENGTH_SLOTS).map(bits_after_slot).collect();
        let listed: Vec<Option<u8>> = LENGTH_SLOT_EXTRA_BITS
            .iter()
            .map(|&bits| Some(bits))
            .chain([None])
            .collect();
        assert_eq!(answered, listed);
        assert_eq!(answered.len(), LENGTH_SLOTS + 1);
        assert_eq!(answered[43], Some(9));
        assert!(answered.iter().flatten().all(|&bits| bits <= 9));
        assert!(bits_after_slot(usize::MAX).is_none());
    }

    /// The version 1 alphabet carries the count of extra bits on over all
    /// 80 slots, pair by pair (section 3.5, "Slots 64 to 79"): 31 for the
    /// last pair the section places and 32 to 38 after it. No count is
    /// refused.
    #[test]
    fn the_wide_alphabet_carries_the_count_on_to_its_last_slot() {
        assert_eq!(DISTANCE_SLOT_BITS[64], 31);
        assert_eq!(DISTANCE_SLOT_BITS[65], 31);
        assert_eq!(DISTANCE_SLOT_BITS[66], 32);
        assert_eq!(DISTANCE_SLOT_BITS[67], 32);
        assert_eq!(DISTANCE_SLOT_BITS[70], 34);
        assert_eq!(DISTANCE_SLOT_BITS[78], 38);
        assert_eq!(DISTANCE_SLOT_BITS[79], 38);
    }

    /// Section 3.5: a fresh match gains a byte past each of three
    /// distances and none AT one, whatever length its slot named. This is
    /// vector V5-BONUS's arithmetic half.
    #[test]
    fn a_fresh_match_is_longer_past_each_of_three_distances() {
        for laddered in [2usize, 9, 4_097] {
            for (distance, gained) in [
                (1usize, 0usize),
                (0x100, 0),
                (0x101, 1),
                (0x2000, 1),
                (0x2001, 2),
                (0x4_0000, 2),
                (0x4_0001, 3),
                (usize::MAX, 3),
            ] {
                assert_eq!(
                    fresh_match_length(laddered, distance),
                    laddered + gained,
                    "length {laddered} at distance {distance:#x}"
                );
            }
        }
    }

    /// Section 3.5, "The extra bits of a distance": the alignment symbol
    /// is the lowest four bits and the plain bits are all the others.
    #[test]
    fn the_alignment_symbol_is_the_lowest_four_bits() {
        assert_eq!(extra_bits_value(0, 0), 0);
        assert_eq!(extra_bits_value(0, 15), 15);
        assert_eq!(extra_bits_value(1, 0), 16);
        assert_eq!(extra_bits_value(0x7ff_ffff, 15), 0x7fff_ffff);
    }
}
