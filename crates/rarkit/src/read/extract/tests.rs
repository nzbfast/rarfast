//! The extract walk's own unit tests.

use super::*;
use crate::MemoryPolicy;

/// `RARKIT_B2SP_WIDE`'s words, and that it ships ON: a clear stored
/// member under BLAKE2sp is read wide on `t` and `p` unless the knob
/// says not.
#[cfg(feature = "parallel")]
#[test]
fn the_blake_wide_knob_reads_its_words_and_ships_on() {
    assert_eq!(B2SP_WIDE, cfg!(all()), "the shipped default is on");
    assert_eq!(b2sp_wide_of(None), B2SP_WIDE);
    assert_eq!(b2sp_wide_of(Some("maybe")), B2SP_WIDE);
    assert!(b2sp_wide_of(Some("1")) && b2sp_wide_of(Some(" ON ")));
    assert!(!b2sp_wide_of(Some("0")) && !b2sp_wide_of(Some("off")));
}

/// `RARKIT_B2SP_TEAM`'s words, and the allowance each rule gives: the
/// policy's figure as before; under the default process policy the
/// larger of it and the read's width, which never falls under the
/// policy's, and the policy's own under any other; or the read width
/// alone, where a width of one is one thread.
#[test]
fn the_blake_team_rule_reads_its_words_and_gives_each_allowance() {
    assert_eq!(TEAM_RULE, TeamRule::Larger, "the shipped default");
    assert_eq!(team_rule_of(None), TEAM_RULE);
    assert_eq!(team_rule_of(Some("nonsense")), TEAM_RULE);
    assert_eq!(team_rule_of(Some("policy")), TeamRule::Policy);
    assert_eq!(team_rule_of(Some(" Larger ")), TeamRule::Larger);
    assert_eq!(team_rule_of(Some("WIDTH")), TeamRule::Width);
    // (rule, policy, width, the default process policy) -> allowance
    for (rule, policy, width, process, want) in [
        (TeamRule::Policy, 7, 16, true, 7),
        (TeamRule::Policy, 7, 1, true, 7),
        (TeamRule::Larger, 7, 16, true, 16),
        (TeamRule::Larger, 7, 8, true, 8),
        (TeamRule::Larger, 7, 4, true, 7),
        (TeamRule::Larger, 7, 1, true, 7),
        (TeamRule::Larger, 7, 0, true, 7),
        // A library caller's policy, or a named budget: its figure.
        (TeamRule::Larger, 1, 16, false, 1),
        (TeamRule::Larger, 7, 16, false, 7),
        (TeamRule::Width, 7, 16, false, 16),
        (TeamRule::Width, 7, 1, true, 1),
        (TeamRule::Width, 7, 0, false, 1),
    ] {
        assert_eq!(
            team_allowance(rule, policy, width, process),
            want,
            "{rule:?} policy {policy} width {width} process {process}"
        );
    }
}

/// **No 296 byte header travels by value on the per-member path.**
///
/// The three structures a member of a 20,000 member archive moves
/// through are sized here rather than described, because the cost
/// this pins is the MOVE and a move is exactly `size_of` bytes. The
/// figures are the ones measured on 22 Sep 2026: `FileHdr` was 296
/// bytes, `Block` 352 and `Landed` 424, and `Landed` was that big
/// only because it carried an `Option<FileHdr>` which is `None` for
/// every member with one fragment. A knob that returned a 424 byte
/// value by value against one that returned 136 bytes priced the
/// difference at 5.5 ns a member on an Apple M3 Mac before this lever
/// existed.
///
/// The ceilings are deliberately loose: this test is not a claim
/// about a compiler's field ordering, it is a claim that no later
/// change may put a header back into one of these slots by value
/// without the test saying so.
#[test]
fn no_member_header_travels_by_value() {
    use std::mem::size_of;
    // Printed as well as asserted: a later reader of this test
    // wants the figures, and a bound alone does not carry them.
    println!(
        "FileHdr {} Block {} Landed {} MemberInfo {}",
        size_of::<FileHdr>(),
        size_of::<crate::read::block::Block>(),
        size_of::<Landed>(),
        size_of::<MemberInfo<'_>>(),
    );
    assert!(
        size_of::<Landed>() <= 160,
        "Landed is {} bytes; it was 424 while it carried a whole \
         FileHdr by value, and `land` returns one per member",
        size_of::<Landed>()
    );
    // The header itself is NOT shrunk and the test says so rather
    // than leaving a reader to wonder: boxing its 56 byte
    // encryption record was tried and refuted by
    // `tests/allocations.rs`, so `FileHdr` is still what it was.
    assert!(
        size_of::<FileHdr>() <= 320,
        "FileHdr is {} bytes",
        size_of::<FileHdr>()
    );
    // NON-VACUITY: a `Landed` that shrank because its fields were
    // deleted rather than boxed would pass the bound above. The
    // header is still REACHABLE, and it is still the last
    // fragment's (spec F 3.5.6).
    // One pointer, whatever the pointer's width: 8 bytes on a 64-bit
    // target and 4 on a 32-bit one.
    assert_eq!(
        size_of::<Option<Box<FileHdr>>>(),
        size_of::<usize>(),
        "the last fragment's header must still be carried, as a pointer"
    );
    assert!(
        size_of::<FileHdr>() >= 128,
        "a FileHdr of {} bytes has lost fields rather than boxed one",
        size_of::<FileHdr>()
    );
}

/// **The stored copy buffer never escapes the caller's memory budget,
/// and never costs a short member a long buffer.**
///
/// The buffer is the one place the read path chooses its own chunking
/// for a stored member, and it is sized for the hasher rather than for
/// the read (see [`STORED_COPY`]). That makes it working memory a
/// caller has to be able to bound, so the rule is the least of the
/// measured ceiling, `MemoryPolicy::read_ahead` and the member.
///
/// The worst case a caller plans for is BREADTH times this, since spec
/// API 4.4 lets several members decode at once, and the last case below
/// holds that product inside the budget it was derived from.
#[test]
fn the_stored_copy_buffer_stays_inside_the_callers_budget() {
    let big = Some(1 << 30);

    // A short member never takes more than it can use, whatever its
    // checksum record is.
    let default = MemoryPolicy::default();
    for blake in [false, true] {
        assert_eq!(stored_copy_len(blake, Some(0), default.read_ahead), COPY);
        assert_eq!(stored_copy_len(blake, Some(1024), default.read_ahead), COPY);
        assert_eq!(stored_copy_len(blake, None, default.read_ahead), COPY);
    }

    // A CRC32 record takes the REQUEST size, which clears the
    // concurrent worker's window and is nowhere near the hasher's
    // ceiling: the two constants are chosen for different reasons and
    // a later reader must not fold them together.
    assert_eq!(
        stored_copy_len(false, big, default.read_ahead),
        STORED_REQUEST
    );
    // A budget too small for the request gets the buffer it always
    // had, and never less.
    let tight = MemoryPolicy::from_limit(4 << 20);
    assert_eq!(stored_copy_len(false, big, tight.read_ahead), COPY);

    // A member of unknown or huge size takes the ceiling, and the
    // ceiling is the smaller of the measured figure and the budget.
    for limit in [1 << 20, 4 << 20, 64 << 20, 512 << 20, u64::MAX] {
        let policy = MemoryPolicy::from_limit(limit);
        let got = stored_copy_len(true, big, policy.read_ahead) as u64;
        assert!(
            got >= COPY as u64,
            "limit {limit}: {got} is under the buffer every other record gets"
        );
        assert!(
            got <= STORED_COPY as u64,
            "limit {limit}: {got} is over the measured ceiling {STORED_COPY}"
        );
        assert!(
            got <= policy.read_ahead.max(COPY as u64),
            "limit {limit}: {got} is over the caller's read_ahead {}",
            policy.read_ahead
        );

        // Breadth times the buffer, which is what a caller decoding a
        // non-solid set several members at a time actually holds.
        let worst = got.saturating_mul(policy.max_workers as u64);
        assert!(
            worst <= limit / 4,
            "limit {limit}: {} workers of {got} bytes is {worst}, over a \
             quarter of the budget they were both derived from",
            policy.max_workers
        );
    }
}

/// **The overlap's second buffer is NOT read-ahead, and its working
/// memory stays inside the budget it was derived from.**
///
/// Two separate promises, and the reason this test replaced one that
/// asserted the two buffers cost what the serial path's one costs.
/// That was the wrong invariant, taken from `read::seam::ring_plan`
/// where it is the right one: the seam's ring is filled by the
/// source unit and not yet written, so it IS ahead of the delivery
/// point and the seam halves the budget to pay for it. Here a buffer
/// is written to the caller's writer BEFORE it goes to the hasher,
/// so the hasher's buffer is entirely behind the delivered byte and
/// only the one being filled is ahead. Read-ahead is therefore ONE
/// chunk, the serial path's own, and halving it would have fed the
/// hasher half the batch for nothing.
///
/// What the second buffer costs is WORKING memory, which
/// `working_limit` bounds and which this holds to the same quarter
/// of the budget `the_stored_copy_buffer_stays_inside_the_callers_budget`
/// holds the serial path's one buffer to.
#[test]
fn the_overlaps_two_buffers_stay_inside_the_callers_budget() {
    let big = Some(1 << 30);
    let mut overlapped = 0;
    for limit in [1 << 20, 4 << 20, 64 << 20, 512 << 20, u64::MAX] {
        let policy = MemoryPolicy::from_limit(limit);
        let serial = stored_copy_len(true, big, policy.read_ahead);
        let Some(chunk) = overlap_plan(true, true, big, policy.read_ahead, 8) else {
            continue;
        };
        overlapped += 1;

        // The read-ahead promise: ONE chunk ahead of the delivered
        // byte, exactly what the serial path runs ahead by.
        assert_eq!(
            chunk, serial,
            "limit {limit}: the overlap reads ahead by {chunk} where the serial path \
             reads ahead by {serial}"
        );

        // The working-memory promise: breadth times what a member
        // holds, inside the quarter of the budget the serial path's
        // own test uses.
        let held = 2 * chunk as u64;
        let worst = held.saturating_mul(policy.max_workers as u64);
        assert!(
            worst <= limit / 4,
            "limit {limit}: {} workers holding two {chunk} byte buffers is {worst}, \
             over a quarter of the budget they were both derived from",
            policy.max_workers
        );
    }
    assert!(
        overlapped > 0,
        "no budget overlapped at all, so this test proves nothing"
    );
}

/// The four shapes the overlap REFUSES, so it never spends a thread
/// on a member with nothing to hide.
///
/// The pair of conditions that matters is the first: the overlap is
/// worth a thread only where a SERIAL stage sits in front of a WIDE
/// one, which on this path means a cipher in front of BLAKE2sp. An
/// unencrypted member has no serial stage and a CRC32 member no wide
/// one, and `tests/encrypted_overlap.rs` holds the same two shapes
/// end to end through a real extraction.
#[test]
fn the_overlap_refuses_a_member_with_nothing_to_hide() {
    let policy = crate::MemoryPolicy::default();
    let ahead = policy.read_ahead;
    let big = Some(64 << 20);
    assert!(
        overlap_plan(true, true, big, ahead, 8).is_some(),
        "the shape this test is about must overlap"
    );
    assert!(
        overlap_plan(false, true, big, ahead, 8).is_none(),
        "a CRC32 member has no wide stage to hide the cipher behind"
    );
    assert!(
        overlap_plan(true, false, big, ahead, 8).is_none(),
        "an unencrypted member has no serial stage to hide"
    );
    assert!(
        overlap_plan(true, true, big, ahead, 1).is_none(),
        "a width of one has no thread to spend"
    );
    assert!(
        overlap_plan(true, true, None, ahead, 8).is_none(),
        "a member of unknown size is not known to be worth a thread"
    );
}

/// The floor, from both sides: a member with only one chunk in it
/// has no successor to decipher under its hash, and a member under
/// [`OVERLAP_FLOOR`] is not worth a thread whatever its chunking.
#[test]
fn the_overlap_floor_holds_from_both_sides() {
    let policy = crate::MemoryPolicy::default();
    let ahead = policy.read_ahead;
    assert!(
        overlap_plan(true, true, Some(OVERLAP_FLOOR - 1), ahead, 8).is_none(),
        "a member under the floor overlapped"
    );
    // A member of one chunk has no successor to decipher under its
    // hash, so there is nothing to overlap with.
    let chunk = stored_copy_len(true, Some(1 << 30), ahead) as u64;
    assert!(
        overlap_plan(true, true, Some(chunk), ahead, 8).is_none(),
        "a member of exactly one chunk overlapped"
    );
    assert!(
        overlap_plan(true, true, Some(2 * chunk), ahead, 8).is_some(),
        "a member of two chunks did not overlap"
    );
    // A tight budget shrinks the chunk to `COPY` and the floor is
    // then the only thing holding a small member out, which is 8.5's
    // rule that a member too small for a hand-over runs in sequence
    // and is never an error.
    for limit in [1 << 16, 1 << 18, 1 << 20] {
        let tight = MemoryPolicy::from_limit(limit);
        let small = Some(OVERLAP_FLOOR - 1);
        assert!(
            overlap_plan(true, true, small, tight.read_ahead, 8).is_none(),
            "limit {limit}: a member under the floor overlapped"
        );
    }
}

/// A larger budget never yields a smaller buffer, which is the
/// monotonicity `MemoryPolicy::from_limit` promises for every field it
/// derives, carried through to the one thing this module derives from
/// it.
#[test]
fn a_larger_budget_never_gives_a_smaller_stored_buffer() {
    let mut last = 0usize;
    for shift in 20..=34 {
        let policy = MemoryPolicy::from_limit(1u64 << shift);
        let got = stored_copy_len(true, Some(1 << 30), policy.read_ahead);
        assert!(
            got >= last,
            "budget 2^{shift} gave {got} after {last} at the budget below it"
        );
        last = got;
    }
}

/// Whether a member carries a checksum is its HEADER's answer, and stays
/// so while another unit runs the CRC32 for it: the seam's deliver unit
/// and a pool worker's deliverer both take the running CRC32 out of the
/// member for the length of its decode. The decoder is told "no
/// checksum" from this answer (spec H2 3.1: a filter span the stream
/// completes past the declared size passes only then) and a member that
/// ends short is judged by its checksum from it (spec F 4.2); read off
/// the running state, both were wrong for every member decoded behind
/// such a unit.
#[cfg(feature = "parallel")]
#[test]
fn a_member_whose_crc_another_unit_runs_still_carries_its_checksum() {
    let mut file = FileHdr::empty();
    file.checksum = Some(Checksum::Crc32(0x1234_5678));
    let mut member: Member<Vec<u8>> =
        Member::of(Some(Out::Verify), &file, Format::Rar5, None, &mut None, 1);
    assert!(member.carries_a_checksum());
    let crc = member
        .detach_crc()
        .expect("a CRC32 member has one to hand over");
    assert!(member.carries_a_checksum(), "the header still carries it");
    let lent = member.retarget::<()>(Some(Out::Verify));
    assert!(lent.carries_a_checksum(), "and so does the member lent on");
    let mut back = lent.retarget::<Vec<u8>>(Some(Out::Verify));
    back.attach_crc(crc);
    assert!(back.carries_a_checksum());

    // A member whose header carries none says so throughout.
    let bare = FileHdr::empty();
    let mut member: Member<Vec<u8>> =
        Member::of(Some(Out::Verify), &bare, Format::Rar5, None, &mut None, 1);
    assert!(!member.carries_a_checksum());
    assert!(member.detach_crc().is_none());
    assert!(!member.carries_a_checksum());
}
