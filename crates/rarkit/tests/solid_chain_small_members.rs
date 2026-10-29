//! A SMALL MEMBER THAT CARRIES NO TABLE SET IS LEFT TO THE WALKING THREAD,
//! AND THE RUN STAYS OPEN ACROSS IT (SPEC-H2 sections 3.2 and 3.8,
//! `read::ahead::SMALL_MEMBER`).
//!
//! **What the rule is for.** A member handed to the chain's decode-ahead
//! costs the walking thread an offer, a claim and, where the lane had gone
//! idle, a wake; for a member of a few KiB that is more than the decode it
//! moves (measured 2 Oct 2026). So
//! under a stated floor the lookahead does not offer a member that declares
//! fewer bytes than the floor.
//!
//! **What makes the rule lawful, and what these tests hold.** A lane's
//! decode of a member depends on the table set in force at its start and on
//! nothing else (3.8), and a member none of whose blocks carries a set
//! leaves the set in force as it found it (3.2). So the lookahead steps
//! over such a member WITHOUT closing the run, and the member offered after
//! it still joins the run in front of it. A member that carries a set is
//! offered as before, whatever its size, because the run's lane has to read
//! that set.
//!
//! The first test FAILS if a stepped-over member is decoded under the wrong
//! set or its neighbours are: every member's checksum is verified, with the
//! floor on, with it off and with the stage off. The second FAILS if a
//! stepped-over small member closes the run: the larger members between
//! the small ones would then be refused unless they opened a group of their
//! own, and the count of members claimed would fall to the count of heads.

use std::sync::Arc;

use rarkit::{Disposition, MemberInfo, MemberOutcome, RangeSource, ReadOptions, Result, Sink};

#[path = "support/creategate.rs"]
mod creategate;

use creategate::text_corpus;

/// The floor the tests state: above every small member here, below every
/// large one.
const FLOOR: u64 = 8 * 1024;
/// A small member's bytes: the `rar5_small_solid_20k` corpus averages 2,302.
const SMALL: usize = 2_300;
/// A large member's bytes.
const LARGE: usize = 24_000;

/// Decode and check every member, keeping no byte.
#[derive(Default)]
struct Verify {
    members: u64,
    bytes: u64,
}

impl Sink for Verify {
    type Out = Vec<u8>;
    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Verify)
    }
    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        _out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.members += 1;
        self.bytes += outcome.bytes;
        Ok(())
    }
}

/// A solid chain of members of the given sizes, written by reference `rar`,
/// or `None` where it is not on the path.
fn chain(tag: &str, sizes: &[usize]) -> Option<Vec<u8>> {
    // `std::process::id` in the path: two runs of the suite on one box share
    // `temp_dir`.
    let dir =
        std::env::temp_dir().join(format!("rarkit-small-members-{tag}-{}", std::process::id()));
    let files = dir.join("members");
    let archive = dir.join("chain.rar");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&files).ok()?;
    let total: usize = sizes.iter().sum();
    let text = text_corpus(total + 4096);
    let mut from = 0usize;
    for (index, &size) in sizes.iter().enumerate() {
        std::fs::write(files.join(format!("m{index:06}")), &text[from..from + size]).ok()?;
        from += size;
    }
    let ok = std::process::Command::new("rar")
        .current_dir(&files)
        .args(["a", "-ma5", "-m3", "-s", "-ep", "-idq", "-y"])
        .arg(&archive)
        .arg(".")
        .status()
        .is_ok_and(|s| s.success());
    let bytes = if ok {
        std::fs::read(&archive).ok()
    } else {
        None
    };
    let _ = std::fs::remove_dir_all(&dir);
    bytes
}

/// One extraction with every checksum verified, answering how many members
/// the decode-ahead claimed.
fn claims(archive: &[u8], ahead: bool, floor: u64, members: u64, bytes: u64) -> u64 {
    rarkit::probe::set_ahead_off(!ahead);
    rarkit::probe::set_ahead_small(Some(floor));
    rarkit::probe::begin_ahead_claim_scope();
    rarkit::probe::reset_ahead_claims();
    let mut sink = Verify::default();
    let sources: Vec<Arc<dyn RangeSource>> =
        vec![Arc::new(archive.to_vec()) as Arc<dyn RangeSource>];
    let outcome = rarkit::extract(sources, &ReadOptions::default(), &mut sink, &mut ());
    let claimed = rarkit::probe::ahead_claims();
    rarkit::probe::end_ahead_claim_scope();
    rarkit::probe::set_ahead_small(None);
    rarkit::probe::set_ahead_off(false);
    outcome.expect("the solid chain extracts, every checksum verified");
    assert_eq!(sink.members, members, "every member was read");
    assert_eq!(sink.bytes, bytes, "every declared byte");
    claimed
}

/// The members of a chain, and how many of them open a table group of
/// their own, split by whether they declare fewer bytes than the floor.
fn census(archive: &[u8]) -> (u64, u64, u64, u64) {
    let (mut small, mut small_heads, mut large, mut large_heads) = (0u64, 0u64, 0u64, 0u64);
    for member in rarkit::internals::rar5::members(archive) {
        if member.directory || member.method == 0 {
            continue;
        }
        let head = matches!(
            rarkit::internals::rar5::first_block_has_tables(&member.packed),
            Some((true, _))
        );
        if member.unpacked < FLOOR {
            small += 1;
            small_heads += u64::from(head);
        } else {
            large += 1;
            large_heads += u64::from(head);
        }
    }
    (small, small_heads, large, large_heads)
}

/// ONE test, two halves in order: the claim counter is the process's
/// (`probe::ahead_claims`), so two tests of this file running at once would
/// each read the other's claims.
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn a_small_member_stays_with_the_walking_thread_and_the_run_stays_open() {
    a_chain_of_small_members_decodes_on_the_walking_thread_and_verifies();
    a_stepped_over_small_member_does_not_close_the_run();
}

fn a_chain_of_small_members_decodes_on_the_walking_thread_and_verifies() {
    const MEMBERS: usize = 3_000;
    let sizes = vec![SMALL; MEMBERS];
    let Some(archive) = chain("small", &sizes) else {
        eprintln!("    reference `rar` is not on the path; skipped");
        return;
    };
    let (small, heads, large, _) = census(&archive);
    assert_eq!(
        (small, large),
        (MEMBERS as u64, 0),
        "every member is a small LZ member"
    );
    let bytes = (MEMBERS * SMALL) as u64;

    // The three arms extract the same members to the same verified bytes.
    let off = claims(&archive, false, 0, small, bytes);
    let no_floor = claims(&archive, true, 0, small, bytes);
    let floor = claims(&archive, true, FLOOR, small, bytes);
    eprintln!(
        "    {small} small members, {heads} open a group: claimed {off} with the stage off, \
         {no_floor} with no floor, {floor} under a floor of {FLOOR}"
    );
    assert_eq!(off, 0, "the stage ran with the knob off");
    // Under the floor only what the lookahead could not prove table-less is
    // offered: the members that open a group, and the few it meets before
    // its window is open. Half the chain is the bar, so the test is about
    // the mechanism and not an exact count.
    assert!(
        floor <= heads + small / 2,
        "{floor} of {small} small members were handed to a lane under a floor above every one \
         of them, where {heads} open a group of their own"
    );
    if heads * 4 <= small {
        assert!(
            floor < no_floor,
            "the floor took no member back from the stage: {floor} claimed against {no_floor}"
        );
    }
}

fn a_stepped_over_small_member_does_not_close_the_run() {
    // Two small members, then a large one, six hundred times over.
    const GROUPS: usize = 600;
    let mut sizes = Vec::with_capacity(GROUPS * 3);
    for _ in 0..GROUPS {
        sizes.extend_from_slice(&[SMALL, SMALL, LARGE]);
    }
    let Some(archive) = chain("mixed", &sizes) else {
        eprintln!("    reference `rar` is not on the path; skipped");
        return;
    };
    let (small, small_heads, large, large_heads) = census(&archive);
    assert_eq!((small, large), ((GROUPS * 2) as u64, GROUPS as u64));
    let bytes = (GROUPS * (2 * SMALL + LARGE)) as u64;

    let off = claims(&archive, false, 0, small + large, bytes);
    let no_floor = claims(&archive, true, 0, small + large, bytes);
    let floor = claims(&archive, true, FLOOR, small + large, bytes);
    eprintln!(
        "    {small} small members ({small_heads} open a group) and {large} large \
         ({large_heads} open a group): claimed {off} with the stage off, {no_floor} with no \
         floor, {floor} under a floor of {FLOOR}"
    );
    assert_eq!(off, 0, "the stage ran with the knob off");
    // THE CENSUS FIRST, as `solid_chain_head_refusal` has it: if this `rar`
    // opened a group on most of the large members, a run that closed at
    // every small member would still take them, and the count below would
    // prove nothing about the run. That is the writer's choice, so the test
    // steps aside rather than asserting about it.
    if large_heads * 2 > large {
        eprintln!(
            "    this `rar` opened a table group on {large_heads} of {large} large members, \
             so the run across a small member is not exercised; skipped"
        );
        return;
    }
    // THE ASSERTION. A large member with the table bit clear is taken only
    // while a run is open, and between two large members here sit two small
    // ones the lookahead stepped over. Had either closed the run, the large
    // members claimed would be those that open a group and no others.
    let joined = large - large_heads;
    assert!(
        floor >= large_heads + joined * 8 / 10,
        "only {floor} members were decoded ahead under the floor where {large} large members \
         follow small ones and only {large_heads} open a group of their own: a stepped-over \
         small member closed the run"
    );
    // And the small members were not: the floor leaves them to this thread.
    assert!(
        floor <= large + small_heads + small / 10,
        "{floor} members were decoded ahead under the floor, more than the {large} large ones \
         and the {small_heads} small ones that open a group"
    );
}
