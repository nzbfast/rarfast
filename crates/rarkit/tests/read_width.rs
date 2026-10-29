//! The read side's width dial, and the memory ceiling it may not move.
//!
//! API section 8.4 split the read's two jobs out of one field: since
//! 20 Sep 2026 `MemoryPolicy::working_limit` bounds BYTES and
//! `ReadOptions::workers` bounds THREADS, where before a thread count was
//! derived from a memory budget as `working_limit / 64 MiB` and held every
//! read on every box at 8. This file is acceptance tests 1, 2, 5 and 6 of
//! 8.4.4. Test 7 is the command line's and lives in
//! `crates/rarkit-cli/src/width_dial.rs`; tests 3 and 4 are GATE legs and
//! are measured rather than asserted.
//!
//! **Why the members are large and this file is slow.** The tape decode
//! has a size floor of 16 MiB of output below which a member takes no lane
//! at all, so a width this can SEE is a width over members of tens of
//! megabytes. `breadth_width.rs` says the same at its own fixture.

#![cfg(all(feature = "parallel", feature = "test-support"))]

use std::io::Write;
use std::sync::{Arc, Mutex, MutexGuard};

use rarkit::{
    extract, extract_parallel, probe, Disposition, ErrorKind, MemberInfo, MemberOutcome,
    MemberSpec, ParallelSink, Payload, RangeSource, ReadOptions, Resource, Result, Sink,
    WriteMethod, WriteOptions, Writer,
};

/// `probe::peak_lanes` is PROCESS-wide and has to be, so every test here
/// takes this: cargo runs a binary's tests on several threads at once and
/// one test's lanes would otherwise land in another's reading.
static COUNTER: Mutex<()> = Mutex::new(());

fn counter() -> MutexGuard<'static, ()> {
    COUNTER.lock().unwrap_or_else(|e| e.into_inner())
}

/// Material an `-m3` archive can hold: about half of it compresses and
/// half does not, so the block chain keeps growing and there are blocks
/// enough to spread over lanes. A single repeated byte gives a chain of
/// one block, which takes no lane whatever the width.
fn body(bytes: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes + 128);
    let mut seed = 0x2026_0920_u64;
    while out.len() < bytes {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        out.extend_from_slice(format!("{:016x} ", seed >> 24).as_bytes());
        out.extend_from_slice(b"the quick brown fox jumps over the lazy dog ");
        for _ in 0..8 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            out.extend_from_slice(&seed.to_le_bytes());
        }
    }
    out.truncate(bytes);
    out
}

/// A non-solid archive of `members` copies of `body`, written with
/// `dictionary` so a test can decide how large a WINDOW each member makes
/// the decoder hold. That is the term 5.2 counts per member in flight and
/// the one a small budget binds on, so a test of the budget sets it
/// deliberately rather than taking the writer's own choice.
fn archive_with(body: &[u8], members: usize, dictionary: Option<u64>) -> Vec<u8> {
    let mut writer = Writer::new(WriteOptions {
        method: WriteMethod::Compressed {
            level: 3,
            dictionary,
        },
        ..WriteOptions::default()
    })
    .expect("options");
    let names: Vec<Vec<u8>> = (0..members)
        .map(|i| format!("m{i}.dat").into_bytes())
        .collect();
    for name in &names {
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(body),
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    out
}

/// The same, at the writer's own choice of dictionary.
fn archive(body: &[u8], members: usize) -> Vec<u8> {
    archive_with(body, members, None)
}

fn sources(bytes: &[u8]) -> Vec<Arc<dyn RangeSource>> {
    vec![Arc::new(bytes.to_vec()) as Arc<dyn RangeSource>]
}

/// A writer that keeps a rolling checksum and a length, so two runs are
/// compared byte for byte without either holding a gigabyte.
struct Counted {
    len: u64,
    hash: crc32fast::Hasher,
}

impl Counted {
    fn new() -> Counted {
        Counted {
            len: 0,
            hash: crc32fast::Hasher::new(),
        }
    }
    fn digest(self) -> u64 {
        (self.len << 32) ^ u64::from(self.hash.finalize())
    }
}

impl Write for Counted {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.len += data.len() as u64;
        self.hash.update(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Verifies every member and keeps a digest of each: the bytes are not the
/// point here and holding them would dwarf what is being measured.
#[derive(Default)]
struct Digests {
    got: Mutex<Vec<(Vec<u8>, u64)>>,
}

impl ParallelSink for Digests {
    type Out = Counted;

    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Counted>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Counted::new()))
    }

    fn close(
        &self,
        member: &MemberInfo<'_>,
        out: Option<Counted>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        assert_ne!(
            outcome.checksum_ok,
            Some(false),
            "checksum failed for a member this test wrote itself"
        );
        if let Some(out) = out {
            self.got
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((member.name.to_vec(), out.digest()));
        }
        Ok(())
    }
}

/// The same, for the SEQUENTIAL entry point, which takes `&mut self`.
#[derive(Default)]
struct SerialDigests {
    got: Vec<(Vec<u8>, u64)>,
}

impl Sink for SerialDigests {
    type Out = Counted;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Counted>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Counted::new()))
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Counted>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        assert_ne!(outcome.checksum_ok, Some(false), "checksum failed");
        if let Some(out) = out {
            self.got.push((member.name.to_vec(), out.digest()));
        }
        Ok(())
    }
}

/// What one run answered: every member's digest in archive order, the peak
/// the operation itself reports, and the lanes it spread over.
struct Run {
    digests: Vec<(Vec<u8>, u64)>,
    peak: u64,
    lanes: usize,
    members: usize,
}

fn wide(bytes: &[u8], opts: &ReadOptions, breadth: usize) -> Run {
    let sink = Digests::default();
    probe::reset_peak_lanes();
    probe::reset_peak_members();
    let report = extract_parallel(sources(bytes), opts, &sink, breadth).expect("parallel");
    Run {
        digests: sink.got.into_inner().unwrap_or_else(|e| e.into_inner()),
        peak: report.peak_working_memory,
        lanes: probe::peak_lanes(),
        members: probe::peak_members(),
    }
}

fn serial(bytes: &[u8], opts: &ReadOptions) -> Run {
    let mut sink = SerialDigests::default();
    probe::reset_peak_lanes();
    probe::reset_peak_members();
    let report = extract(sources(bytes), opts, &mut sink, &mut ()).expect("sequential");
    Run {
        digests: sink.got,
        peak: report.peak_working_memory,
        lanes: probe::peak_lanes(),
        members: probe::peak_members(),
    }
}

/// The window the members of `bytes` declare, read from the archive rather
/// than assumed: the budget a test wants is a multiple of THIS, and the
/// writer's own choice of dictionary is not this file's to pin.
fn window_of(bytes: &[u8]) -> u64 {
    let archive =
        rarkit::Archive::open(sources(bytes).remove(0), &ReadOptions::default()).expect("open");
    archive
        .members()
        .filter_map(|m| match m.method {
            rarkit::Method::Compressed { dictionary, .. } => Some(dictionary),
            rarkit::Method::Stored => None,
        })
        .max()
        .expect("a compressed member")
}

// -------------------------------------------------------------------------
// 8.4.4 test 1: the memory ceiling still binds when a user sets a small one
// -------------------------------------------------------------------------

/// A budget too small for the members a wide read would put in flight,
/// and `ReadOptions::workers` set WIDE: the operation completes, its
/// output is byte-identical to the sequential form, its peak never passes
/// `working_limit`, and running narrower is reported as no error at all
/// (8.4.1, and 8.4.2's precedence rule).
///
/// **The fixture is a large window over a modest member**, which is what
/// makes this test about the thing 8.4.1 names. The term the budget counts
/// per member in flight is its WINDOW (5.2), and since SPEC-API
/// 8.1's 26 Sep 2026 erratum a RAR 5 member's window is its REACH,
/// `min(declared dictionary, unpacked size)`, and not the declared
/// dictionary. Four 24 MiB members each declaring a larger dictionary
/// therefore each hold a 24 MiB window, plus the decoder's other terms
/// (its packed buffer and read window), against a budget sized off the
/// declared dictionary. The peak must stay inside the budget whatever the
/// dial says, and no more members may be in flight than the budget holds
/// at their reach.
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn a_small_budget_binds_however_wide_the_dial_is_set() {
    let _guard = counter();
    let bytes = archive_with(&body(24 << 20), 4, Some(32 << 20));
    // Read back rather than assumed: the writer narrows a dictionary to
    // what the member can use, and the budget below is sized off whatever
    // it settled on.
    let window = window_of(&bytes);
    assert!(
        window >= 16 << 20,
        "a window of {window} does not dominate the decoder's other terms, \
         so a budget sized off it would bind on something else"
    );

    // Sized off the DECLARED dictionary: room for two of those, and since
    // that erratum the members hold less, their reach.
    let limit = window * 5 / 2;
    let opts = ReadOptions::default()
        .with_memory(rarkit::MemoryPolicy::from_limit(limit))
        .with_workers(Some(32));
    assert!(
        opts.memory.max_window >= window,
        "a member at this window is refused rather than narrowed at a \
         budget of {limit}, which is a different test (8.3)"
    );

    let want = serial(&bytes, &opts);
    let have = wide(&bytes, &opts, 32);
    println!(
        "SMALL BUDGET limit={limit} sequential peak={} wide peak={} members={} lanes={}",
        want.peak, have.peak, have.members, have.lanes
    );
    assert_eq!(
        have.digests, want.digests,
        "a wide read on a small budget delivered different bytes"
    );
    assert_eq!(have.digests.len(), 4, "every member came back");
    assert!(
        have.peak <= opts.memory.working_limit,
        "a wide read held {} of working memory against a budget of {}",
        have.peak,
        opts.memory.working_limit
    );
    // And the BUDGET is what narrowed it: the dial asked for 32, and a
    // member costs at least its reach, so no more than the budget over the
    // reach may be in flight.
    let reach = window.min(24 << 20);
    let fits = limit / reach;
    assert!(
        (have.members as u64) <= fits,
        "a budget of {limit} holds {fits} windows of {reach} (the reach) and \
         the dial asked for 32; {} members were in flight",
        have.members
    );
}

// -------------------------------------------------------------------------
// 8.4.4 test 2: a wide dial does not raise the peak on any shape
// -------------------------------------------------------------------------

/// The peak is FLAT in the width at a fixed breadth, at the default budget.
///
/// The binding memory term is one window per MEMBER in flight (5.2,
/// 8.4.1), so a width that does not raise the members in flight must not
/// raise the peak. The breadth is held at two and the width walks the
/// ladder of 8.4.3: what moves is threads, and threads are not bytes.
///
/// The ladder starts at two because the effective breadth is
/// `min(request, width)` (8.4.2): a width of ONE is a breadth of one as
/// well, so it moves the members in flight and belongs to the other
/// direction, which is asserted separately below - narrower never costs
/// more memory.
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn a_wide_dial_never_raises_the_peak() {
    let _guard = counter();
    let bytes = archive(&body(24 << 20), 4);
    let budget = rarkit::MemoryPolicy::default();

    let mut first: Option<(u64, usize)> = None;
    for width in [2usize, 4, 6, 8, 12, 16, 24, 32] {
        let opts = ReadOptions::default().with_workers(Some(width));
        let have = wide(&bytes, &opts, 2);
        println!(
            "WIDTH {width} breadth 2: peak={} members={} lanes={}",
            have.peak, have.members, have.lanes
        );
        assert!(
            have.peak <= budget.working_limit,
            "a width of {width} held {} against the default budget of {}",
            have.peak,
            budget.working_limit
        );
        match first {
            None => first = Some((have.peak, have.members)),
            Some((peak, members)) => {
                assert_eq!(
                    have.members, members,
                    "a width of {width} changed the members in flight, so the \
                     peak below is not a reading about the width"
                );
                assert_eq!(
                    have.peak, peak,
                    "a width of {width} moved the peak from {peak} to {}, and \
                     the width is not a memory figure (8.4.1)",
                    have.peak
                );
            }
        }
    }

    // The other direction: a width of one narrows the breadth with it, and
    // a narrower read never holds MORE.
    let one = ReadOptions::default().with_workers(Some(1));
    let narrow = wide(&bytes, &one, 2);
    let (peak, _) = first.expect("the ladder ran");
    assert!(
        narrow.peak <= peak,
        "a width of one held {} where a wider read held {peak}",
        narrow.peak
    );
}

// -------------------------------------------------------------------------
// 8.4.4 test 5: the dial reaches the stages it claims to
// -------------------------------------------------------------------------

/// Two widths, two peak LANE counts, and the test FAILS if they agree.
///
/// On the model of `tests/encoder_width.rs`, which exists because a width
/// dial that reached nothing kept its byte-identical-output test passing.
/// The bytes are asserted identical at every width in the same breath,
/// which is promise 2.6 on the read side.
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn the_dial_moves_the_lanes_and_never_the_bytes() {
    let _guard = counter();
    let bytes = archive(&body(24 << 20), 4);

    // A breadth of two, so the widths above it have somewhere to go: the
    // effective breadth is `min(request, width)` and what is left of the
    // width is spent on lanes inside the members (8.3), so a ladder run at
    // a breadth equal to the width would spend every unit on breadth and
    // open no lane at all.
    let mut seen: Vec<(usize, usize)> = Vec::new();
    let mut want: Option<Vec<(Vec<u8>, u64)>> = None;
    for width in [2usize, 4, 8, 16] {
        let opts = ReadOptions::default().with_workers(Some(width));
        let have = wide(&bytes, &opts, 2);
        seen.push((width, have.lanes));
        assert!(
            have.lanes <= width,
            "a width of {width} ran {} lanes, over its own ceiling",
            have.lanes
        );
        match &want {
            None => want = Some(have.digests),
            Some(want) => assert_eq!(
                &have.digests, want,
                "a width of {width} delivered different bytes"
            ),
        }
    }
    println!("LANES BY WIDTH {seen:?}");
    // THE MACHINE THIS STATES: widths of 2 to 16 BY NAME at a breadth of
    // two, the default memory policy, four members of 24 MiB. A stated
    // width meets the machine's lanes, the hardware threads less one for
    // the apply stage, and a member is spread only from two lanes: so the
    // ladder can move only on three hardware threads or more. The engine
    // is asked (`probe::tape_host_lanes`). A hosted Windows runner of two
    // threads gives one lane and read `[(2, 0), (4, 0), (8, 0), (16, 0)]`
    // on 6 Oct 2026: every member on its own worker's thread alone, which
    // is what is pinned there, beside the bytes held above at every width.
    let host = rarkit::probe::tape_host_lanes(true);
    if host < 2 {
        assert!(
            seen.iter().all(|&(_, lanes)| lanes == 0),
            "this machine gives a stated width {host} lane(s), under the two a spread \
             needs, and yet lane threads were alive: {seen:?}"
        );
        eprintln!(
            "the ladder is NOT READ: this machine gives a stated width {host} lane(s) and \
             a spread needs two (three hardware threads); the bytes were one answer at \
             every width"
        );
        return;
    }
    let widest = seen.last().expect("the ladder is not empty").1;
    let narrowest = seen.first().expect("the ladder is not empty").1;
    assert!(
        widest > narrowest,
        "every width on the ladder spread over the same lanes ({seen:?}), \
         so `ReadOptions::workers` reaches nothing"
    );
}

// -------------------------------------------------------------------------
// 8.4.4 test 6: `Some(0)` is the named refusal and `Some(1)` runs
// -------------------------------------------------------------------------

/// A width of zero is `LimitExceeded { resource: Workers }` on BOTH entry
/// points, and a width of one is accepted and runs.
///
/// A width of one is not the same thing as a strictly serial decode, which
/// 8.3 says is reachable only by building without `parallel`; it is a
/// width, and the members still walk through the same paths.
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn a_width_of_zero_is_refused_by_name_and_a_width_of_one_runs() {
    let _guard = counter();
    // Small: neither the refusal nor the run at a width of one needs a
    // member the tape path would take.
    let bytes = archive(&body(64 << 10), 2);
    let refused = ReadOptions::default().with_workers(Some(0));

    let mut sink = SerialDigests::default();
    let err = extract(sources(&bytes), &refused, &mut sink, &mut ())
        .expect_err("a width of zero is refused");
    assert!(
        matches!(
            err.kind(),
            ErrorKind::LimitExceeded {
                resource: Resource::Workers,
                ..
            }
        ),
        "the sequential path refused a width of zero as {:?}",
        err.kind()
    );

    let sink = Digests::default();
    let err = extract_parallel(sources(&bytes), &refused, &sink, 4)
        .expect_err("a width of zero is refused");
    assert!(
        matches!(
            err.kind(),
            ErrorKind::LimitExceeded {
                resource: Resource::Workers,
                ..
            }
        ),
        "the concurrent path refused a width of zero as {:?}",
        err.kind()
    );

    let one = ReadOptions::default().with_workers(Some(1));
    let want = serial(&bytes, &one);
    assert_eq!(want.digests.len(), 2, "a width of one extracted nothing");
    let have = wide(&bytes, &one, 4);
    assert_eq!(
        have.digests, want.digests,
        "a width of one delivered different bytes through the two paths"
    );
}

// -------------------------------------------------------------------------
// 8.4.4 test 5, on the shape the breadth cannot help: ONE member
// -------------------------------------------------------------------------

/// One member, and the dial reaches its tape lanes in BOTH directions up
/// to the engine's measured ceiling.
///
/// The 8.4.3 ladder gained up to 3.311x at a width of 32 on the many
/// member shapes and was FLAT on `one-big-many-small` and `solid-vol`,
/// and the carried per member ceiling (`MT_MAX_WORKERS`) was the obvious
/// suspect: a member decoding alone could not spread past eight lanes
/// whatever the dial, the pool or the budget said.
///
/// **It was not the cause, and that is measured rather than argued.** The
/// ceiling was lifted entirely and the ladder re-run on an M3 Mac at
/// an earlier revision with the base gated at both ends: the wall was flat
/// from 8 lanes to 31 on both single member legs while peak RSS and CPU
/// rose monotonically with the width. A one member shape is flat in the
/// width because the tape decode's APPLY stage is serial (section 3.8),
/// so the lanes saturate against it; the many member shapes gain through
/// BREADTH, which `read::lanes` shares. The ceiling stayed at 8, now as a
/// MEASURED constant (API 8.4.3), and `MT_MAX_WORKERS`'s own comment
/// carries the table.
///
/// So what this test pins is what the dial must still DO on one member:
/// narrow it below the ceiling, never exceed it, and never change a byte.
/// It runs the SEQUENTIAL entry point over a single member, so there is
/// no lane budget and no breadth: what the width does here, it does
/// inside one member and nowhere else.
///
/// `probe::peak_lanes` is a high-water mark over threads that are alive
/// at once, and which lanes overlap depends on scheduling, so the growth
/// is read as the MAX over three runs ("the dial can REACH this width")
/// while the ceiling is asserted on EVERY individual run ("it never
/// exceeds"). One run of each would pass vacuously on a busy box.
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn one_member_lanes_follow_the_dial_up_to_the_measured_ceiling() {
    let _guard = counter();
    let cores = std::thread::available_parallelism().map_or(1, |c| c.get());
    // Large enough that the chain holds far more blocks than the widest
    // rung, which is what a lane can be spent on at all: `lanes` is minned
    // against `plan.blocks.len()` and a short chain reads as a narrow
    // width for a reason that is not the ceiling (rar5_lz.rs, "THE STAGE
    // SIZES ITSELF TO THE WORK").
    let bytes = archive(&body(48 << 20), 1);

    let mut seen: Vec<(usize, usize)> = Vec::new();
    let mut want: Option<Vec<(Vec<u8>, u64)>> = None;
    for width in [2usize, 4, 8, 32] {
        let opts = ReadOptions::default().with_workers(Some(width));
        let mut most = 0usize;
        for _ in 0..3 {
            let have = serial(&bytes, &opts);
            // EVERY run, not the aggregate: a ceiling is a statement about
            // each run, and a max over runs would hide one that broke it.
            assert!(
                have.lanes <= width,
                "a width of {width} ran {} lanes on one member, over its \
                 own ceiling",
                have.lanes
            );
            assert!(
                have.peak <= ReadOptions::default().memory.working_limit,
                "a width of {width} held {} against the default budget",
                have.peak
            );
            most = most.max(have.lanes);
            match &want {
                None => want = Some(have.digests),
                Some(want) => assert_eq!(
                    &have.digests, want,
                    "a width of {width} delivered different bytes from one \
                     member"
                ),
            }
        }
        seen.push((width, most));
    }
    println!("ONE MEMBER LANES BY WIDTH (max of 3) {seen:?} on {cores} cores");

    // A box that cannot run five threads at once has nothing to show: the
    // host's own count is a ceiling this deliberately keeps.
    if cores > 5 {
        let (_, at_two) = seen[0];
        let (_, at_four) = seen[1];
        assert!(
            at_four > at_two,
            "one member ran {seen:?} on {cores} cores: a width of 4 bought \
             no lane over a width of 2, so the dial reaches nothing inside \
             one member"
        );
    }

    // And the ceiling BINDS: a width far above it does not buy lanes past
    // it. This is the other half of the measurement, and it is what makes
    // the constant a ceiling rather than a suggestion.
    let (_, at_eight) = seen[2];
    let (_, at_thirty_two) = seen[3];
    assert!(
        at_thirty_two <= at_eight.max(8),
        "a width of 32 ran {at_thirty_two} lanes on one member against \
         {at_eight} at a width of 8, so the engine's measured ceiling is \
         not binding"
    );
}
