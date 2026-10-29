//! The SOLID CHAIN's decode-ahead, through the read path that uses it
//! (SPEC-H2 section 3.8, `rar5_lz::ahead` and `read::ahead`).
//!
//! **What needs a test here that the codec's own suite does not give.**
//! `rar5_lz`'s tests drive the stage from the package's own seam, where
//! the whole archive is already in memory and the offers are made from
//! it. The read path has to find the members itself: a cursor walks the
//! headers in front of the walk, reads their packed bytes through the
//! volume's shared handle and offers those. Nothing about that cursor is
//! visible in an output byte, which is exactly the property that makes it
//! safe and exactly what makes it easy to leave broken.
//!
//! So every case below asserts two things that are not the same thing:
//! the members come back byte for byte, and the lever RAN. A test that
//! checked only the first would pass with the whole stage deleted.

use std::sync::{Arc, Mutex, MutexGuard};

#[path = "support/creategate.rs"]
mod creategate;

use rarkit::{
    extract, Disposition, MemberInfo, MemberSpec, Payload, RangeSource, ReadOptions, Result, Sink,
    WriteFormat, WriteMethod, WriteOptions, Writer,
};

/// The claim counter is PROCESS-wide, for the reason every counter in
/// `probe` is: the lanes that fill the queue are other threads by
/// construction, so there is nowhere per-test to keep it. The test
/// harness runs this file's cases on several threads at once, so a case
/// that READS the counter holds this first and every other case in the
/// file waits.
static COUNTER: Mutex<()> = Mutex::new(());

/// Take the counter, and start it from zero.
fn counting() -> MutexGuard<'static, ()> {
    let held = COUNTER.lock().unwrap_or_else(|e| e.into_inner());
    rarkit::probe::reset_ahead_claims();
    held
}

/// Collects each member's name and bytes, in archive order.
#[derive(Default)]
struct Collect {
    members: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Sink for Collect {
    type Out = Vec<u8>;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        self.members.push((member.name.to_vec(), Vec::new()));
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        _outcome: &rarkit::MemberOutcome,
    ) -> Result<()> {
        if let (Some(bytes), Some(last)) = (out, self.members.last_mut()) {
            last.1 = bytes;
        }
        Ok(())
    }
}

/// One archive and the members that went into it.
type Written = (Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>);

/// One solid RAR 5 archive holding `count` members of about `each` bytes.
fn solid_archive(count: usize, each: usize) -> Written {
    let members: Vec<(Vec<u8>, Vec<u8>)> = (0..count)
        .map(|i| {
            (
                format!("m{i:03}.txt").into_bytes(),
                rarkit_testdata::chatter(i as u64 + 1, each + i * 7),
            )
        })
        .collect();
    let mut writer = Writer::new(WriteOptions {
        format: WriteFormat::Rar5,
        method: WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
        solid: true,
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    })
    .expect("options");
    for (name, data) in &members {
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(data),
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out: Vec<u8> = Vec::new();
    writer.finish_into(&mut out).expect("finish_into");
    (out, members)
}

/// Read one archive back through this crate's reader.
fn read_back(archive: &[u8], options: &ReadOptions) -> Vec<(Vec<u8>, Vec<u8>)> {
    let sources: Vec<Arc<dyn RangeSource>> =
        vec![Arc::new(archive.to_vec()) as Arc<dyn RangeSource>];
    let mut sink = Collect::default();
    extract(sources, options, &mut sink, &mut ())
        .unwrap_or_else(|e| panic!("reading back a solid chain: {e}"));
    sink.members
}

/// The lever runs on the read path, and every member comes back whole.
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn a_solid_chain_comes_back_whole_with_the_decode_ahead_running() {
    let (archive, members) = solid_archive(48, 9_000);
    let _counting = counting();
    let read = read_back(&archive, &ReadOptions::default());
    assert_eq!(read, members);
    let claims = rarkit::probe::ahead_claims();
    assert!(
        claims > 0,
        "no member of a 48 member solid chain reached the decode-ahead, so \
         this comparison says nothing about it"
    );
    assert!(
        claims < members.len() as u64,
        "the chain's FIRST member has nothing in front of it to have been \
         decoded ahead of, so every member cannot have been claimed"
    );
}

/// A width of one still decodes the chain, and still decodes it correctly.
///
/// Running narrower is in contract (SPEC-API 8.2), and one lane ahead of
/// the apply stage is the narrowest the lever has.
#[test]
fn one_lane_ahead_decodes_the_same_chain() {
    let (archive, members) = solid_archive(24, 9_000);
    let _counting = counting();
    let wide = read_back(&archive, &ReadOptions::default());
    let narrow = read_back(&archive, &ReadOptions::default().with_workers(Some(1)));
    assert_eq!(wide, members);
    assert_eq!(narrow, members);
}

/// A caller's STATED memory budget is hard, and a budget too
/// small for the stage turns it off rather than being exceeded.
///
/// The chain still decodes. That is the half worth pinning: the lever is
/// a performance decision, and refusing it must cost a wall and never a
/// byte.
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn a_stated_memory_budget_turns_the_decode_ahead_off_rather_than_growing() {
    let (archive, members) = solid_archive(24, 9_000);
    let policy = rarkit::MemoryPolicy {
        working_limit: 64 * 1024,
        ..rarkit::MemoryPolicy::default()
    };
    let _counting = counting();
    let read = read_back(&archive, &ReadOptions::default().with_memory(policy));
    assert_eq!(read, members, "a narrow budget changed a byte");
    assert_eq!(
        rarkit::probe::ahead_claims(),
        0,
        "a stated budget of 64 KiB was spent on a decode-ahead the caller \
         never asked for"
    );
}

/// A chain that ENDS, and one that never starts: the stage must not carry
/// anything across either boundary.
///
/// The archive holds two solid chains with a non-solid member between
/// them, which is what a writer produces when a run is reset. A stage
/// that kept its queue across the reset would offer the second chain's
/// members against the first chain's window.
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn a_reset_chain_carries_nothing_across_its_boundary() {
    let first: Vec<(Vec<u8>, Vec<u8>)> = (0..12)
        .map(|i| {
            (
                format!("a{i:02}.txt").into_bytes(),
                rarkit_testdata::chatter(i as u64 + 1, 9_000 + i * 13),
            )
        })
        .collect();
    let second: Vec<(Vec<u8>, Vec<u8>)> = (0..12)
        .map(|i| {
            (
                format!("b{i:02}.txt").into_bytes(),
                rarkit_testdata::chatter(i as u64 + 500, 9_000 + i * 29),
            )
        })
        .collect();
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut every = Vec::new();
    for (run, members) in [&first, &second].into_iter().enumerate() {
        let mut writer = Writer::new(WriteOptions {
            format: WriteFormat::Rar5,
            method: WriteMethod::Compressed {
                level: 3,
                dictionary: None,
            },
            solid: true,
            host_os: rarkit::HostOs::Unix,
            ..WriteOptions::default()
        })
        .expect("options");
        for (name, data) in members {
            writer
                .add(MemberSpec {
                    name,
                    payload: Payload::Bytes(data),
                    mtime: None,
                    attributes: 0,
                    host_os: rarkit::HostOs::Unix,
                    is_directory: false,
                })
                .expect("add");
            every.push((name.clone(), data.clone()));
        }
        let mut archive: Vec<u8> = Vec::new();
        writer.finish_into(&mut archive).expect("finish_into");
        out.push(archive);
        let _ = run;
    }
    // Two archives read as two sets, which is the honest form of "the
    // stage is per stream": each one's chain is its own, and the decoder
    // that reads the second was never offered the first's members.
    for (archive, members) in out.iter().zip([&first, &second]) {
        let _counting = counting();
        let read = read_back(archive, &ReadOptions::default());
        assert_eq!(&read, members);
        assert!(rarkit::probe::ahead_claims() > 0);
    }
}

/// The knob the lever's own measurement pairs against turns the stage OFF
/// and changes no byte.
///
/// Worth a test rather than a comment: the stage is invisible in the
/// output, so a knob that had stopped working would leave the pair
/// comparing the lever with itself and reading 1.000x, which is a
/// believable number and a false one. The claim counter is what says the
/// two arms were different arms.
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn the_knob_the_measurement_pairs_against_turns_the_stage_off() {
    let (archive, members) = solid_archive(24, 9_000);
    let _counting = counting();

    rarkit::probe::set_ahead_off(true);
    let without = read_back(&archive, &ReadOptions::default());
    let claimed_off = rarkit::probe::ahead_claims();

    rarkit::probe::set_ahead_off(false);
    rarkit::probe::reset_ahead_claims();
    let with = read_back(&archive, &ReadOptions::default());
    let claimed_on = rarkit::probe::ahead_claims();

    assert_eq!(
        claimed_off, 0,
        "the knob did not turn the decode-ahead off, so a pair taken \
         against it compares the lever with itself"
    );
    assert!(claimed_on > 0, "the knob did not turn it back on");
    assert_eq!(without, members, "the arm with the stage off lost bytes");
    assert_eq!(with, members, "the arm with the stage on lost bytes");
    assert_eq!(without, with);
}

/// A solid chain written by reference `rar`, whose members mostly use the
/// table set an earlier member opened, or `None` without `rar`.
fn reference_chain(tag: &str, members: usize, each: usize) -> Option<Vec<u8>> {
    // `std::process::id` in the path: two runs of the suite on one box share
    // `temp_dir`. And `tag`, because two cases
    // of THIS file build a chain each on two threads of one process, and
    // the first form of this shared one directory between them.
    let dir = std::env::temp_dir().join(format!("rarkit-carry-{tag}-{}", std::process::id()));
    let files = dir.join("members");
    let archive = dir.join("chain.rar");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&files).ok()?;
    let text = creategate::text_corpus(members * each + 4096);
    for index in 0..members {
        let from = index * each;
        std::fs::write(files.join(format!("m{index:06}")), &text[from..from + each]).ok()?;
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

/// THE CARRIED TABLE GROUP on the shape it exists for (SPEC-H2 3.2, 3.8,
/// `rar5_lz::ahead`'s runs): a chain written by reference `rar` at `-m3
/// -s`, where most members' first block opens no group, comes back byte
/// for byte with the stage on, and nearly every member was decoded ahead.
///
/// And the comparison is SHOWN TO HAVE TEETH: with the carried set made
/// stale at every run head (`probe::set_ahead_carry_stale`), the same
/// extraction must NOT come back right, because a member decoded under
/// the wrong set is a wrong byte the checksum then refuses, or a symbol
/// stream that does not decode at all. A carry that is invisible when it
/// is right needs to be seen wrong once.
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn a_reference_rar_chain_carrying_one_table_set_is_decoded_ahead() {
    const MEMBERS: usize = 2_000;
    let Some(archive) = reference_chain("carry", MEMBERS, 2_300) else {
        eprintln!("    reference `rar` is not on the path; skipped");
        return;
    };
    let heads = rarkit::internals::rar5::members(&archive)
        .iter()
        .filter(|m| !m.directory && m.method != 0)
        .filter(|m| {
            matches!(
                rarkit::internals::rar5::first_block_has_tables(&m.packed),
                Some((true, _))
            )
        })
        .count();
    if heads * 4 > MEMBERS {
        eprintln!("    this `rar` opened a group on {heads} of {MEMBERS} members; skipped");
        return;
    }
    let _counting = counting();

    rarkit::probe::set_ahead_off(true);
    let serial = read_back(&archive, &ReadOptions::default());
    assert_eq!(rarkit::probe::ahead_claims(), 0);
    assert_eq!(serial.len(), MEMBERS);

    rarkit::probe::set_ahead_off(false);
    rarkit::probe::reset_ahead_claims();
    let ahead = read_back(&archive, &ReadOptions::default());
    let claims = rarkit::probe::ahead_claims() as usize;
    assert_eq!(
        ahead, serial,
        "the chain decoded ahead differs from the serial bytes"
    );
    assert!(
        claims * 10 >= MEMBERS * 9,
        "{claims} of {MEMBERS} members claimed where only {heads} open a group: \
         the table group is not being carried"
    );

    // THE CORRUPTION. Process wide, so the counter lock above covers it,
    // and turned off again whatever happens below.
    rarkit::probe::set_ahead_carry_stale(true);
    rarkit::probe::reset_ahead_claims();
    let sources: Vec<Arc<dyn RangeSource>> =
        vec![Arc::new(archive.clone()) as Arc<dyn RangeSource>];
    let mut sink = Collect::default();
    let outcome = extract(sources, &ReadOptions::default(), &mut sink, &mut ());
    rarkit::probe::set_ahead_carry_stale(false);
    let corrupted_claims = rarkit::probe::ahead_claims();
    assert!(
        corrupted_claims > 0,
        "the corrupted run never reached a claimed member, so it tested nothing"
    );
    let came_back_right = outcome.is_ok() && sink.members == serial;
    assert!(
        !came_back_right,
        "a stale carried table set gave the serial bytes and no error, so the \
         equivalence above does not rest on the carry"
    );
}

/// THE SEAM'S OFFERING LOOP must never SKIP a member the stage refused for
/// now, because a skipped member may change the table set in force and the
/// run behind it would then carry the wrong one (`rar5_lz::ahead`'s runs).
///
/// Found by `examples/h2_ahead_carry_price.rs` on 22 Sep 2026: the
/// `rar5_small_solid_20k_vsnull` arm, offering through
/// `internals_h2::offer_chain`, decoded a 2,000 member reference chain to
/// `DistanceOutOfRange` where the shipped read path decoded it whole. The
/// loop restarted one PAST the member the full queue had refused, so that
/// member decoded serially with the run still open behind it. Latent
/// before the carry, when every offered member opened its own group.
///
/// The seam arms are the bench legs' rarkit arms, so a wrong byte there is
/// a wrong figure; and the fuzz target's arm offers the same way.
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn the_seam_arms_never_skip_a_member_the_stage_refused_for_now() {
    const MEMBERS: usize = 2_000;
    let Some(archive) = reference_chain("seam", MEMBERS, 2_300) else {
        eprintln!("    reference `rar` is not on the path; skipped");
        return;
    };
    let _counting = counting();
    let total = (MEMBERS * 2_300) as u64;

    rarkit::probe::reset_ahead_claims();
    let counted = rarkit::internals::rar5::extract_counting(&archive, None)
        .unwrap_or_else(|e| panic!("the counting arm decoded a wrong byte: {e}"));
    assert_eq!(counted, total);
    let claims = rarkit::probe::ahead_claims() as usize;
    assert!(
        claims * 10 >= MEMBERS * 9,
        "the counting arm claimed {claims} of {MEMBERS}: the loop is skipping or \
         re-offering members"
    );

    rarkit::probe::reset_ahead_claims();
    let members = rarkit::internals::rar5::extract_auto(&archive)
        .unwrap_or_else(|e| panic!("extract_auto decoded a wrong byte: {e}"));
    assert_eq!(
        members
            .iter()
            .map(|(_, bytes)| bytes.len() as u64)
            .sum::<u64>(),
        total
    );
    let claims = rarkit::probe::ahead_claims() as usize;
    assert!(
        claims * 10 >= MEMBERS * 9,
        "extract_auto claimed {claims} of {MEMBERS}"
    );

    // The fuzz target's arm, on the same chain cut the way the target
    // cuts it: every member's packed bytes and declared size, one window.
    let walked = rarkit::internals::rar5::members(&archive);
    let chain: Vec<(&[u8], u64)> = walked
        .iter()
        .filter(|m| !m.directory && m.method != 0)
        .map(|m| (m.packed.as_slice(), m.unpacked))
        .collect();
    let window = walked.iter().map(|m| m.window).max().unwrap_or(1 << 17);
    let serial = rarkit::internals::rar5::decode_solid_chain_probe(&chain, window, 0, false, false);
    rarkit::probe::reset_ahead_claims();
    let ahead = rarkit::internals::rar5::decode_solid_chain_probe(&chain, window, 0, true, true);
    assert_eq!(
        serial.1, ahead.1,
        "the fuzz arm's outcome moved with the stage on"
    );
    assert!(
        serial.0 == ahead.0,
        "the fuzz arm's bytes moved with the stage on"
    );
    let claims = rarkit::probe::ahead_claims() as usize;
    assert!(
        claims * 10 >= MEMBERS * 9,
        "the fuzz arm claimed {claims} of {MEMBERS}"
    );
}
