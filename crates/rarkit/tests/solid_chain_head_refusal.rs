//! The chain's decode-ahead must REFUSE A MEMBER BEFORE IT READS IT, and
//! must TAKE the members it can (SPEC-H2 sections 3.2 and 3.8).
//!
//! **The defect this pins.** A member the stage refuses used to be refused
//! on its bytes once they were in hand, so its whole packed data was read
//! into the stage's buffer and thrown away. When the refusal was the table
//! rule, on a chain written by reference `rar` at `-m3 -s` with small
//! members, that was nearly every member: 18,666 of 20,000 on the
//! `rar5_small_solid_20k` corpus, measured 22 Sep 2026. Every permanent
//! refusal is decidable from the file header and the first block's HEADER,
//! five bytes, which the cursor already brings back in the same read as the
//! file header.
//!
//! **What changed on 22 Sep 2026, and why the test has two halves.** The
//! table group is now CARRIED across a member boundary (`rar5_lz::ahead`'s
//! runs), so the table rule refuses almost nothing on that chain and the
//! stage takes the members it used to refuse: the second half counts that
//! it does. The first half keeps the refusal's own count by using the one
//! permanent refusal that survives on such a chain, a stated memory budget
//! below one member's charge, which is decided from the header
//! alone exactly as the table rule was.
//!
//! **What makes this a real test rather than a restatement.** It counts the
//! BYTES THE SOURCE WAS ASKED FOR, with the stage on and with it off, and
//! the difference is what the lookahead cost. The first half FAILS when the
//! early refusal is removed, because the difference then grows by the
//! refused members' whole packed data. The second half FAILS if the carry
//! stops taking the members behind a run's head.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use rarkit::{Disposition, MemberInfo, MemberOutcome, RangeSource, ReadOptions, Result, Sink};

#[path = "support/creategate.rs"]
mod creategate;

use creategate::text_corpus;

/// How many members the chain is cut into. Enough that the archive's writer
/// makes the choice this test is about - carrying one table set across most
/// of the boundaries - and small enough to build in a test.
const MEMBERS: usize = 3_000;
/// Each member's bytes. The `rar5_small_solid_20k` corpus averages 2,302.
const EACH: usize = 2_300;

/// A source that counts what it was asked for, and answers from a `Vec`.
struct Counting {
    bytes: Vec<u8>,
    served: AtomicU64,
    calls: AtomicU64,
}

impl RangeSource for Counting {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let at = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(self.bytes.len());
        let take = buf.len().min(self.bytes.len() - at);
        buf[..take].copy_from_slice(&self.bytes[at..at + take]);
        self.served.fetch_add(take as u64, Ordering::Relaxed);
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(take)
    }
    fn available(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn len(&self) -> Option<u64> {
        Some(self.bytes.len() as u64)
    }
}

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

/// Build the chain with reference `rar`, or answer `None`.
fn chain() -> Option<Vec<u8>> {
    // `std::process::id` in the path: two runs of the suite on one box share
    // `temp_dir` and would otherwise delete each other's work between the
    // write and the call to `rar`.
    let dir = std::env::temp_dir().join(format!("rarkit-head-refusal-{}", std::process::id()));
    let files = dir.join("members");
    let archive = dir.join("chain.rar");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&files).ok()?;
    let text = text_corpus(MEMBERS * EACH + 4096);
    for index in 0..MEMBERS {
        let from = index * EACH;
        std::fs::write(files.join(format!("m{index:06}")), &text[from..from + EACH]).ok()?;
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

/// One extraction, answering the bytes the source was asked for and the
/// calls it took.
fn read_cost(archive: &[u8], ahead: bool, options: &ReadOptions) -> (u64, u64, u64) {
    let source = Arc::new(Counting {
        bytes: archive.to_vec(),
        served: AtomicU64::new(0),
        calls: AtomicU64::new(0),
    });
    rarkit::probe::set_ahead_off(!ahead);
    rarkit::probe::reset_ahead_claims();
    let mut sink = Verify::default();
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::clone(&source) as Arc<dyn RangeSource>];
    rarkit::extract(sources, options, &mut sink, &mut ()).expect("the solid chain extracts");
    rarkit::probe::set_ahead_off(false);
    assert_eq!(sink.members, MEMBERS as u64, "every member was read");
    assert_eq!(sink.bytes, (MEMBERS * EACH) as u64, "every declared byte");
    (
        source.served.load(Ordering::Relaxed),
        source.calls.load(Ordering::Relaxed),
        rarkit::probe::ahead_claims(),
    )
}

#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn a_member_the_decode_ahead_refuses_is_never_read_for_it() {
    let Some(archive) = chain() else {
        eprintln!("    reference `rar` is not on the path; skipped");
        return;
    };

    // THE CENSUS FIRST. The second half is about the members whose first
    // block opens NO group, so a corpus whose writer happened to open one
    // per member would let it pass while proving nothing about the carry.
    // That is the archive writer's choice and not this engine's, so it is
    // checked and the test steps aside rather than asserting about it.
    let members = rarkit::internals::rar5::members(&archive);
    let mut lz = 0u64;
    let mut heads = 0u64;
    let mut packed_total = 0u64;
    for member in &members {
        if member.directory || member.method == 0 {
            continue;
        }
        lz += 1;
        packed_total += member.packed.len() as u64;
        if let Some((true, _)) = rarkit::internals::rar5::first_block_has_tables(&member.packed) {
            heads += 1;
        }
    }
    assert_eq!(lz, MEMBERS as u64, "every member is an LZ member");
    if heads * 4 > lz {
        eprintln!(
            "    this `rar` opened a table group on {heads} of {lz} members, so \
             the carry is not exercised; skipped"
        );
        return;
    }

    // FIRST HALF: refused before it is read. A stated budget of 64 KiB
    // gives the stage a ceiling of 1 KiB, under any member's charge, so
    // every member is refused from its declared sizes and none may cost
    // the source a byte beyond the header reads the cursor makes anyway.
    let starved = ReadOptions::default().with_memory(rarkit::MemoryPolicy {
        working_limit: 64 * 1024,
        ..rarkit::MemoryPolicy::default()
    });
    let (off_served, off_calls, off_claims) = read_cost(&archive, false, &starved);
    let (on_served, on_calls, on_claims) = read_cost(&archive, true, &starved);
    assert_eq!(off_claims, 0, "the stage ran with the knob off");
    assert_eq!(
        on_claims, 0,
        "a stage under a 1 KiB ceiling claimed a member"
    );
    let extra = on_served.saturating_sub(off_served);
    eprintln!(
        "    {lz} members, {heads} open a group, packed {packed_total}; under a \
         starved budget the source served {off_served} with the stage off and \
         {on_served} with it on, {extra} more; calls {off_calls} against {on_calls}"
    );
    // THE ASSERTION, and it names the mechanism. The refused members'
    // packed data is what an early refusal keeps from being read; half of
    // it is the bar rather than all of it, so the test is about the
    // mechanism and not about an exact byte count.
    assert!(
        extra < packed_total / 2,
        "the lookahead asked the source for {extra} bytes more than the walk did \
         while refusing every member, which is the refused members' packed data \
         ({packed_total} bytes) being read and thrown away"
    );

    // SECOND HALF: the carry takes the members behind a run's head. With the
    // default budget the only members refused are those between the chain's
    // first member, which is never offered, and the first head after it.
    let (off_served, _, off_claims) = read_cost(&archive, false, &ReadOptions::default());
    let (on_served, _, on_claims) = read_cost(&archive, true, &ReadOptions::default());
    assert_eq!(off_claims, 0, "the stage ran with the knob off");
    let extra = on_served.saturating_sub(off_served);
    eprintln!(
        "    under the default budget: {on_claims} of {lz} claimed, the source \
         served {extra} bytes more with the stage on"
    );
    assert!(
        on_claims * 10 >= lz * 9,
        "only {on_claims} of {lz} members were decoded ahead where {heads} open a \
         group of their own: the table group is not being carried"
    );
    assert!(
        extra >= packed_total / 2,
        "the stage claimed {on_claims} members but the source served only {extra} \
         bytes more, which cannot be the members' packed data"
    );
}
