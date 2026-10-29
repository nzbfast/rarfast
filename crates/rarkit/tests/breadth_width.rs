//! BREADTH TIMES WIDTH, against the one ceiling both of them spend.
//!
//! API section 8.2's table gives the row for 8.3 as "at most `max_workers`
//! decode units over all members together", and 8.3 itself says the
//! product of the members decoded at once and the width inside each of
//! them stays at or below that ceiling. SINCE 8.4.2 (20 Sep 2026) the
//! ceiling those units are spent against is `ReadOptions::workers`, the
//! read side's own width dial, and not the memory policy: a memory
//! budget is not a thread count. The property this file asserts is
//! unchanged - the PRODUCT is what is bounded - and only the field it
//! sets has moved. Two pieces of work landed a few
//! hours apart on 20 Sep 2026 and each honoured the ceiling alone: the
//! tape pipeline takes up to `max_workers` lanes inside ONE member, and
//! the concurrent driver dispatches up to `max_workers` members at once.
//! Together they multiplied, because a dispatched member is decoded by a
//! worker holding the operation's FULL policy.
//!
//! Nothing in an output byte shows it, so it is counted here rather than
//! timed, the same way `thread_width.rs` counts the width inside one
//! member. It bites only above the tape path's size floor (16 MiB of
//! output), which is why the members here are large and the file is slow.

#![cfg(all(feature = "parallel", feature = "test-support"))]

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use rarkit::{
    extract_parallel, probe, Disposition, MemberInfo, MemberOutcome, MemberSpec, ParallelSink,
    Payload, RangeSource, ReadOptions, Result, WriteMethod, WriteOptions, Writer,
};

/// `probe::peak_workers` is PROCESS-wide and has to be, so every test in
/// this file takes this: cargo runs a binary's tests on several threads at
/// once and one test's lanes would otherwise land in another's reading.
/// `thread_width.rs` says the same at its own counter.
static COUNTER: Mutex<()> = Mutex::new(());

fn counter() -> MutexGuard<'static, ()> {
    COUNTER.lock().unwrap_or_else(|e| e.into_inner())
}

/// A member comfortably past the tape path's 16 MiB output floor, in
/// material an `-m3` archive could hold: about half of it compresses and
/// half does not.
///
/// A single repeated byte gives a block chain too short to spread over
/// lanes, and a chain of one block takes no lane at all, so the point of
/// the fixture is that it keeps producing new blocks.
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

/// A non-solid archive of one LARGE member followed by `rest` smaller
/// ones, which is the shape a shrinking grant has to survive: the first
/// member is dispatched into an empty pool, takes the whole ceiling, and
/// its neighbours arrive while it still holds it.
fn archive_lopsided(big: &[u8], small: &[u8], rest: usize) -> Vec<u8> {
    let mut writer = Writer::new(WriteOptions {
        method: WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
        ..WriteOptions::default()
    })
    .expect("options");
    let names: Vec<Vec<u8>> = std::iter::once(b"big.dat".to_vec())
        .chain((0..rest).map(|i| format!("m{i}.dat").into_bytes()))
        .collect();
    for (i, name) in names.iter().enumerate() {
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(if i == 0 { big } else { small }),
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

/// A non-solid archive of `members` copies of `body`.
fn archive(body: &[u8], members: usize) -> Vec<u8> {
    let mut writer = Writer::new(WriteOptions {
        method: WriteMethod::Compressed {
            level: 3,
            dictionary: None,
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

/// Verifies every member and keeps nothing: the bytes are not the point
/// here and holding eight of them would dwarf what is being measured.
struct Blackhole {
    closed: Mutex<Vec<Vec<u8>>>,
    /// Each member's name with a checksum of its bytes, in ARCHIVE order
    /// (`close` order is archive order, spec F 3.7.6), so two runs can be
    /// compared without either holding a gigabyte.
    digests: Mutex<Vec<(Vec<u8>, u64)>>,
}

/// A writer that keeps a rolling checksum and a length, so the sink can
/// compare two runs byte for byte without holding either run's bytes.
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
    /// The length and the checksum as one comparable number.
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

impl ParallelSink for Blackhole {
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
        self.closed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(member.name.to_vec());
        if let Some(out) = out {
            self.digests
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((member.name.to_vec(), out.digest()));
        }
        Ok(())
    }
}

/// Every member's name and the CRC32 of its bytes, in archive order.
fn digest_of(bytes: &[u8], ceiling: usize, breadth: usize) -> Vec<(Vec<u8>, u64)> {
    let opts = ReadOptions::default().with_workers(Some(ceiling));
    let sink = Blackhole {
        closed: Mutex::new(Vec::new()),
        digests: Mutex::new(Vec::new()),
    };
    let sources = vec![Arc::new(bytes.to_vec()) as Arc<dyn RangeSource>];
    extract_parallel(sources, &opts, &sink, breadth).expect("parallel");
    sink.digests.into_inner().unwrap_or_else(|e| e.into_inner())
}

/// What one `extract_parallel` at this breadth and this ceiling spread
/// itself over: blocks decoding at once, tape lanes ALIVE at once, and
/// the members it closed.
fn peak_over(bytes: &[u8], ceiling: usize, breadth: usize) -> (usize, usize, usize) {
    let opts = ReadOptions::default().with_workers(Some(ceiling));
    let sink = Blackhole {
        closed: Mutex::new(Vec::new()),
        digests: Mutex::new(Vec::new()),
    };
    let sources = vec![Arc::new(bytes.to_vec()) as Arc<dyn RangeSource>];
    probe::reset_peak_workers();
    probe::reset_peak_lanes();
    extract_parallel(sources, &opts, &sink, breadth).expect("parallel");
    let workers = probe::peak_workers();
    let lanes = probe::peak_lanes();
    let closed = sink.closed.lock().unwrap_or_else(|e| e.into_inner()).len();
    (workers, lanes, closed)
}

/// THE CEILING, over members and over the width inside each of them.
///
/// Failed at an earlier revision: eight 24 MiB members at breadth 8 and a ceiling of
/// 8 put each member on its own worker with the operation's full policy,
/// so each opened its own lanes and the decode ran far past eight blocks
/// at once. What the ceiling allows is the read's WIDTH in units over all
/// members TOGETHER, so that is what is asserted.
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn breadth_times_width_stays_inside_the_ceiling() {
    let _guard = counter();
    let body = body(24 << 20);
    let bytes = archive(&body, 8);

    let mut over = Vec::new();
    for ceiling in [2usize, 4, 8, 16, 32] {
        let (workers, lanes, closed) = peak_over(&bytes, ceiling, 8);
        assert_eq!(closed, 8, "every member closed at a ceiling of {ceiling}");
        // `peak_workers`, NOT a block count. The name `peak_blocks`
        // was on this column until 21 Sep 2026 and it cost the arm 6
        // work its hypothesis; see `probe::note_chunk_plan`.
        println!("CEILING workers={ceiling} breadth=8 peak_workers={workers} peak_lanes={lanes}");
        if lanes > ceiling {
            over.push((ceiling, workers, lanes));
        }
    }
    assert!(
        over.is_empty(),
        "API 8.2's row for 8.3 allows at most the read's width in decode \
         units over all members together; these (workers, blocks at once, \
         lanes alive) rows exceeded it: {over:?}"
    );
}

/// And the ceiling is still SPENT: an arrangement that went serial would
/// also pass the test above and would not be a fix.
///
/// What is asserted is the BLOCKS decoding at once, not the lanes. At a
/// breadth of 8 and a ceiling of 8 the conforming division gives every
/// member a width of one, so it opens no lane at all and spends the whole
/// ceiling on breadth - which is what 8.3's starting default asks for.
/// Counting lanes here would assert the arrangement rather than the
/// property.
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn the_ceiling_is_spent_and_not_merely_respected() {
    let _guard = counter();
    let body = body(24 << 20);
    let bytes = archive(&body, 8);

    let (blocks, lanes, closed) = peak_over(&bytes, 8, 8);
    assert_eq!(closed, 8, "every member closed");
    assert!(
        blocks > 1,
        "a breadth of 8 at a ceiling of 8 ran {blocks} blocks at once over \
         {lanes} lanes, so nothing is decoding in parallel at all"
    );
}

/// FEWER MEMBERS THAN THE POOL HAS SLOTS, which is where the arrangement
/// costs something and where the cost is the caller's to avoid.
///
/// The ceiling is divided by the POOL'S width, not by the members that
/// turn out to exist, because a grant is fixed for a member's life: one
/// made while the pool was quiet is still outstanding when the pool
/// fills, and dividing by the members in flight was measured at 16 lanes
/// on a ceiling of 8. So a caller that asks for a breadth of 8 on a
/// two-member archive gets two members at a width of one and leaves six
/// units of its own ceiling unspent.
///
/// That is a real cost and it is measured: two 256 MiB members at a
/// ceiling of 8 ran 0.86 s at a breadth of 8 against 0.35 s at a breadth
/// of 2, on an M3 Mac. A caller that sizes its breadth to the archive
/// pays nothing. What is asserted here is the part that is the ENGINE'S
/// promise - that the ceiling holds either way - and not the part that
/// is the caller's choice.
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn few_members_in_a_wide_pool_still_hold_the_ceiling() {
    let _guard = counter();
    let body = body(24 << 20);
    let bytes = archive(&body, 2);

    for breadth in [2usize, 8, 32] {
        for ceiling in [4usize, 8, 32] {
            let (blocks, lanes, closed) = peak_over(&bytes, ceiling, breadth);
            assert_eq!(closed, 2, "both members closed at breadth {breadth}");
            assert!(
                lanes <= ceiling,
                "two members at a breadth of {breadth} and a ceiling of \
                 {ceiling} ran {lanes} lanes over {blocks} blocks, \
                 where the ceiling allows {ceiling}"
            );
        }
    }
}

/// THE SHRINKING GRANT, sampled THROUGHOUT a run and not at the peak of
/// a steady state.
///
/// `probe::peak_lanes` is a high-water mark over the whole call, not a
/// snapshot, so a breach at any instant is caught wherever it happens.
/// The shape is what makes the sample worth taking: one 96 MiB member
/// goes out into an empty pool and takes the whole ceiling, and eight
/// more arrive while it still holds it. An arrangement that granted the
/// ceiling and kept it would read far over here, which is exactly what
/// dividing by the members in flight did (16 lanes on a ceiling of 8).
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn a_wide_grant_narrows_as_its_neighbours_arrive() {
    let _guard = counter();
    let big = body(96 << 20);
    let small = body(24 << 20);
    let bytes = archive_lopsided(&big, &small, 8);

    for ceiling in [2usize, 4, 8, 16, 32] {
        for breadth in [4usize, 8, 16] {
            let (blocks, lanes, closed) = peak_over(&bytes, ceiling, breadth);
            assert_eq!(closed, 9, "every member closed at a ceiling of {ceiling}");
            assert!(
                lanes <= ceiling,
                "one large member took the ceiling and eight arrived while \
                 it held it: at a width of {ceiling} and breadth \
                 {breadth} the decode ran {lanes} lanes over {blocks} \
                 blocks, where the ceiling allows {ceiling}"
            );
        }
    }
}

/// NOTHING STARVES AND NOTHING DEADLOCKS: a member that can get no lanes
/// still decodes, at a width of one, on its own thread.
///
/// The reservation's floor is what makes this true, and it costs nothing
/// to honour: below two lanes the tape path is not entered at all, so a
/// member at width one adds no thread to reserve for. The property no
/// output byte shows is that EVERY member closes however the budget was
/// divided, at a breadth far past the ceiling.
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn a_member_that_gets_no_lanes_still_decodes() {
    let _guard = counter();
    let big = body(96 << 20);
    let small = body(24 << 20);
    let bytes = archive_lopsided(&big, &small, 8);

    // A ceiling of one leaves nothing to grant at any breadth.
    for breadth in [1usize, 8, 32] {
        let (_, lanes, closed) = peak_over(&bytes, 1, breadth);
        assert_eq!(closed, 9, "every member closed at a ceiling of one");
        assert_eq!(
            lanes, 0,
            "a ceiling of one grants no lane, so none should be open"
        );
    }
}

/// And the bytes do not depend on the breadth or on the ceiling.
///
/// The property the whole arrangement rests on: how the ceiling is
/// divided is a performance choice and may never be an output one
/// (promise 2.6's determinism, on the read side). `thread_width.rs` pins
/// the same thing for the width inside ONE member; this pins it across
/// the division between members.
#[test]
fn extracted_bytes_do_not_depend_on_how_the_ceiling_is_divided() {
    let _guard = counter();
    let body = body(24 << 20);
    let bytes = archive(&body, 4);

    let mut first: Option<Vec<(Vec<u8>, u64)>> = None;
    for ceiling in [1usize, 2, 8, 32] {
        for breadth in [1usize, 4, 16] {
            let got = digest_of(&bytes, ceiling, breadth);
            match &first {
                None => first = Some(got),
                Some(want) => assert_eq!(
                    &got, want,
                    "a width of {ceiling} at breadth {breadth} \
                     delivered different bytes"
                ),
            }
        }
    }
}

/// THE ZERO-LANE FLOOR, pinned on the cell it was found on.
///
/// Four members at a read width of SIX. The fair share is the floor of
/// six divided by four, which is one, and a member at one lane never
/// enters the tape path at all: `Rar5Lz::member_planned` tests `overlap
/// && lanes > 1` and nothing else, which is what
/// `read::lanes::MIN_USEFUL_LANES` records. So before this was fixed the
/// product API 8.3 bounds bought breadth and NOTHING ELSE, and two of
/// the six units were spent by nobody at all. Found at `-mt6` on an 18
/// core box over four 20 MiB `-m1` members.
///
/// The rule this pins is not "every member gets two lanes", which no
/// ceiling can promise. It is: **the ceiling is SPENT.** A member below
/// the useful lane count is in contract (8.2: a stage that runs
/// narrower, or never threads, is in contract) exactly when there is
/// nothing left over to give it, and is a defect when there is.
///
/// **Why 24 MiB and not the 20 the finding used.** A member below the
/// tape path's 16 MiB output floor takes no lane whatever the division
/// does, and one only just past it has a block chain too short to spread
/// over lanes, so a smaller fixture passes this VACUOUSLY: it would
/// report zero lanes for a reason that has nothing to do with the
/// division. 24 MiB is the smallest member that opens lanes at all here,
/// and the width-8 row below is the control that says so.
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn the_remainder_of_the_width_is_spent_and_not_floored_away() {
    let _guard = counter();
    let body = body(24 << 20);
    let bytes = archive(&body, 4);

    // THE CONTROL, first: at a width of 8 the share divides exactly, two
    // lanes each, and the fixture demonstrably opens lanes. If this row
    // reports zero the test below is vacuous and the fixture is at
    // fault rather than the division.
    let (_, control, closed) = peak_over(&bytes, 8, 4);
    assert_eq!(closed, 4, "every member closed at a width of 8");
    // THE MACHINE THIS STATES: widths of 8, 6 and 4 BY NAME over a breadth
    // of four, the default memory policy, four members of 24 MiB. A
    // stated width meets the machine's lanes, the hardware threads less
    // one for the apply stage, and a member is spread only from two
    // lanes: three hardware threads or more. The engine is asked
    // (`probe::tape_host_lanes`). A hosted Windows runner of two threads
    // gives one lane and read "0 lanes" at the control on 6 Oct 2026:
    // there every member decodes on its own worker's thread alone, which
    // is pinned, and the division has no lane to give anybody.
    let host = rarkit::probe::tape_host_lanes(true);
    if host < 2 {
        assert_eq!(
            control, 0,
            "this machine gives a stated width {host} lane(s), under the two a spread \
             needs, and yet {control} lane threads were alive at a width of 8"
        );
        let (_, lanes, closed) = peak_over(&bytes, 6, 4);
        assert_eq!(closed, 4, "every member closed at a width of 6");
        assert_eq!(lanes, 0, "{lanes} lane threads alive at a width of 6");
        eprintln!(
            "the division is NOT READ: this machine gives a stated width {host} lane(s) \
             and a spread needs two (three hardware threads); all four members closed \
             at widths of 8 and 6 with no lane alive"
        );
        return;
    }
    assert!(
        control >= 2,
        "the fixture opens no lanes even at a width of 8, so this test \
         cannot say anything about the division: {control} lanes"
    );

    // THE CELL. Six over four floors to one; the remainder is two.
    //
    // THE MINIMUM OVER SEVERAL RUNS, and the repetition is not
    // belt-and-braces. A grant is taken when a member reaches its first
    // chunk, so `live` at that instant depends on how the members were
    // scheduled: on a contended box one member can take its grant while
    // only one or two others are live and get a share the steady state
    // would not have given it. Measured 20 Sep 2026 on a laptop at load
    // 60: the same cell read 0, 0, 0, 0, 0, 0, 0, 0 lanes quiet and 5
    // under contention. A single run can therefore pass this VACUOUSLY
    // against the floored share; the minimum cannot, because the
    // steady-state grant is the floor of what any run reports.
    //
    // THE CEILING IS ASSERTED ON EVERY RUN and the floor on the
    // aggregate, which is not a symmetry that can be tidied away. "It
    // never exceeds the width" is a property of each run and an
    // aggregate can hide a single breach; "it reached a useful width" is
    // a property of the steady state and a single run can flatter it.
    // Put the other way round and the test is weaker at both ends. The
    // MT_MAX_WORKERS work arrived at the same split from the opposite
    // direction, wanting the MAX over runs for its can-the-dial-reach
    // assertion, and the two readings agree.
    let lanes = (0..3)
        .map(|_| peak_over(&bytes, 6, 4))
        .inspect(|(_, lanes, closed)| {
            assert_eq!(*closed, 4, "every member closed at a width of 6");
            assert!(*lanes <= 6, "{lanes} lanes alive against a width of 6");
        })
        .map(|(_, lanes, _)| lanes)
        .min()
        .expect("three runs");
    assert!(
        lanes >= 2,
        "a width of 6 over 4 members left the remainder unspent: {lanes} \
         lanes alive at the narrowest of three runs, so no member reached \
         the tape path while two of the six units went to nobody \
         (API 8.3, read::lanes::MIN_USEFUL_LANES)"
    );
    // AND THE HONEST NON-CASE: at a width of four over four members the
    // share divides exactly to one and there is no remainder to spend.
    // Zero lanes there is the breadth-first default spending the whole
    // ceiling, not the defect above, so nothing is asserted about lanes.
    let (_, _, closed) = peak_over(&bytes, 4, 4);
    assert_eq!(closed, 4, "every member closed at a width of 4");
}

/// And spending the remainder changes no byte, on the very cell that
/// changed (promise 2.6's determinism on the read side).
#[test]
fn spending_the_remainder_changes_no_byte() {
    let _guard = counter();
    let body = body(24 << 20);
    let bytes = archive(&body, 4);

    // THREE WIDTHS, one of each KIND, rather than a ladder: 4 divides
    // exactly with no remainder, 6 has a remainder of two and is the
    // cell that changed, and 12 divides exactly with lanes to spare.
    // A fourth width of the same kind as one of these adds a minute of
    // debug-speed decode to `make ci` for everyone and tests
    // nothing new.
    let want = digest_of(&bytes, 8, 4);
    for width in [4usize, 6, 12] {
        assert_eq!(
            digest_of(&bytes, width, 4),
            want,
            "a width of {width} over 4 members delivered different bytes"
        );
    }
}

// ---------------------------------------------------------------------
// THE LATE NARROWING: `probe::BREADTH_ARM_LATE_NARROW`, arm 8
// ---------------------------------------------------------------------

/// How many members were in flight at once, at this arm and threshold.
///
/// **The offload floor is dropped to zero and the members are small on
/// purpose.** What the late narrowing decides is the BREADTH, which is
/// the pool's own count and has nothing to do with the tape path: a
/// member above the breadth is never dispatched, whatever it would have
/// done inside its worker. The tests above need 24 MiB members because
/// they read LANES, and lanes need the tape path's output floor; these
/// read members, and paying that floor twelve times over would put
/// minutes of debug decode into `make ci` for everyone and
/// assert nothing extra.
///
/// The arm and the threshold are PROCESS-wide, so this puts both back
/// where it found them; every caller holds `counter()` besides.
fn flight_at(bytes: &[u8], ceiling: usize, breadth: usize, after: usize, members: usize) -> usize {
    let (peak, _) = flight_held(bytes, ceiling, breadth, after, members, 0);
    peak
}

/// [`flight_at`], with every member HELD in flight until `hold` members
/// are decoding at once, and whether the hold had to give up.
///
/// **Why the reach is read this way.** Unheld, a member of these twelve
/// can finish before the walk has offered the pool its neighbour, so
/// `probe::peak_members` on one run reads what the SCHEDULER allowed as
/// much as what the pool admitted; on a loaded 8-core x86-64 box on 27
/// Sep 2026 the open end of the family read only 4 in three runs, and the
/// thresholds 0 / 4 / 1000 read 4 / 3 / 6. The pool itself counts a member
/// as decoding until its worker answers (`Pool::decoding`), so a member
/// whose writer has not returned is one the pool must hold a slot for:
/// held, the members in flight are exactly the ones the pool ADMITTED, and
/// the only way to reach `hold` is for the pool to admit that many. The
/// writes block on the worker, never on the walk, so the walk keeps
/// offering members for as long as the pool will take them.
///
/// `HOLD_LIMIT` is a backstop for a pool that will NOT admit `hold`
/// members, which is a real failure of the rule, not a slow run: it gives
/// the members back so the call returns and the caller's assertion can
/// say so. A run that meets the hold never touches the clock.
fn flight_held(
    bytes: &[u8],
    ceiling: usize,
    breadth: usize,
    after: usize,
    members: usize,
    hold: usize,
) -> (usize, bool) {
    let opts = ReadOptions::default().with_workers(Some(ceiling));
    let gate = Arc::new(Gate {
        target: hold,
        open: AtomicBool::new(hold <= 1),
        gave_up: AtomicBool::new(false),
    });
    let sink = Holding {
        closed: Mutex::new(Vec::new()),
        gate: gate.clone(),
    };
    let sources = vec![Arc::new(bytes.to_vec()) as Arc<dyn RangeSource>];
    probe::set_offload_floor(Some(0));
    probe::set_narrow_after(after);
    probe::set_breadth_arm(probe::BREADTH_ARM_LATE_NARROW);
    probe::reset_peak_members();
    let report = extract_parallel(sources, &opts, &sink, breadth);
    probe::set_breadth_arm(probe::BREADTH_ARM_SPILL);
    probe::set_narrow_after(probe::NARROW_AFTER_DEFAULT);
    probe::set_offload_floor(None);
    report.expect("parallel");
    let peak = probe::peak_members();
    assert_eq!(
        sink.closed.lock().unwrap_or_else(|e| e.into_inner()).len(),
        members,
        "every member closed at a threshold of {after}"
    );
    (peak, gate.gave_up.load(Ordering::SeqCst))
}

/// How long a held member waits for its neighbours before the hold is
/// given up. Only a pool that refuses to admit `hold` members ever waits
/// this long.
const HOLD_LIMIT: Duration = Duration::from_secs(120);

/// The hold [`flight_held`] puts on every member's first write.
struct Gate {
    target: usize,
    open: AtomicBool,
    gave_up: AtomicBool,
}

impl Gate {
    /// Wait until `target` members are decoding at once (the probe's own
    /// count, the one the reach is read from), or until [`HOLD_LIMIT`].
    fn pass(&self) {
        let until = Instant::now() + HOLD_LIMIT;
        while !self.open.load(Ordering::SeqCst) {
            if probe::peak_members() >= self.target {
                self.open.store(true, Ordering::SeqCst);
                break;
            }
            if Instant::now() >= until {
                self.gave_up.store(true, Ordering::SeqCst);
                self.open.store(true, Ordering::SeqCst);
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// [`Blackhole`] for [`flight_held`]: the same verification, a writer
/// that passes the gate before its first byte.
struct Holding {
    closed: Mutex<Vec<Vec<u8>>>,
    gate: Arc<Gate>,
}

/// A member's writer that holds the member in flight at its first write.
struct Held {
    gate: Arc<Gate>,
    passed: bool,
}

impl Write for Held {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if !self.passed {
            self.gate.pass();
            self.passed = true;
        }
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl ParallelSink for Holding {
    type Out = Held;

    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Held>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Held {
            gate: self.gate.clone(),
            passed: false,
        }))
    }

    fn close(
        &self,
        member: &MemberInfo<'_>,
        _out: Option<Held>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        assert_ne!(
            outcome.checksum_ok,
            Some(false),
            "checksum failed for a member this test wrote itself"
        );
        self.closed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(member.name.to_vec());
        Ok(())
    }
}

/// A fixture the pool will take every member of: twelve members, each
/// too small to be worth a worker until the floor is dropped.
fn many_small() -> Vec<u8> {
    archive(&body(256 << 10), 12)
}

/// THE RULE THE LATE NARROWING FOLLOWS, stated as the code states it.
///
/// **The pool is sized before the walk has read one header**, so it
/// cannot know whether it has the archive narrowing pays on:
/// narrowing was measured at 1.279x on
/// eight members and 0.929x on four, both reproduced in two timed runs.
/// What the pool does learn, one member at a time, is how many the walk
/// has offered it, so the narrowing is deferred until that count passes
/// a threshold. The rule is two bounds and not one figure:
///
/// - the breadth never exceeds what the caller asked for;
/// - once more than `after` members have been dispatched it never
///   exceeds the narrowed breadth (`read::lanes::useful_breadth`);
/// - and the threshold is a FAMILY whose two ends are the two
///   arrangements it has to beat: zero is `probe::BREADTH_ARM_NARROW`
///   and a threshold past the member count is
///   `probe::BREADTH_ARM_SPILL`, which is what ships.
///
/// **Every bound is asserted on EVERY run, and only the "can it reach"
/// reading is an aggregate.** `probe::peak_members` on one run is not
/// deterministic - a run that closed a member early reads low without
/// the bound having moved - but it is the reading the pool controls
/// outright in the other direction, because a member above the breadth
/// is never dispatched at all. So the ceiling holds run by run and the
/// reach is a maximum over runs, which is the split
/// `the_remainder_of_the_width_is_spent_and_not_floored_away` arrived at
/// from the other side.
#[test]
fn the_breadth_narrows_only_after_the_walk_has_shown_it_enough_members() {
    let _guard = counter();
    let bytes = many_small();
    // A ceiling of 8 at a breadth of 8 floors the fair share to one, so
    // this is a cell where narrowing is a lever at all. The narrowed
    // breadth is `read::lanes::useful_breadth(8, 8)`, which is four.
    const CEILING: usize = 8;
    const NARROWED: usize = CEILING / 2;

    let mut wide = 0;
    for _ in 0..3 {
        let narrow = flight_at(&bytes, CEILING, CEILING, 0, 12);
        assert!(
            narrow <= NARROWED,
            "a threshold of zero narrows from the first member, so at \
             most {NARROWED} may ever be in flight: {narrow} were"
        );
        assert!(narrow >= 1, "nothing was dispatched at all");
        let open = flight_at(&bytes, CEILING, CEILING, 1000, 12);
        assert!(
            open <= CEILING,
            "a threshold past the member count narrows nothing, and the \
             caller's breadth is still the bound: {open} members against \
             a breadth of {CEILING}"
        );
        wide = wide.max(open);
    }

    // AND THE NARROWING HAS TO BITE. A rule that quietly did nothing
    // would satisfy every bound above, so the open end must REACH a
    // breadth the narrowed end is not allowed. Read with every member
    // HELD until the caller's whole breadth is in flight (`flight_held`):
    // unheld, a member can close before its neighbour is dispatched, and
    // the widest of three runs read 4 on a loaded box.
    let (held, gave_up) = flight_held(&bytes, CEILING, CEILING, 1000, 12, CEILING);
    assert!(
        held <= CEILING,
        "a threshold past the member count narrows nothing, and the \
         caller's breadth is still the bound: {held} members against a \
         breadth of {CEILING}"
    );
    wide = wide.max(held);
    assert!(
        wide > NARROWED,
        "a threshold past the member count should leave the breadth \
         alone, but with every member held until {CEILING} were in flight \
         the pool admitted only {wide} (hold given up: {gave_up}), so this \
         test cannot tell the family's two ends apart"
    );
}

/// The threshold moves the breadth MONOTONICALLY, which is what makes a
/// sweep of it a sweep rather than a scatter.
///
/// The smallest threshold's reach is the MAXIMUM over three unheld runs,
/// which can only read at or under what the pool admitted. Each larger
/// threshold is then run with its members HELD until that many are in
/// flight (`flight_held`), so it reaches the smaller one's reading unless
/// its pool refuses to admit that many, which is exactly the failure this
/// asserts against. Unheld, the larger threshold's reach was a sample too,
/// and on a loaded box on 27 Sep 2026 the thresholds 0 / 4 / 1000 read
/// 4 / 3 / 6 with no rule having moved.
#[test]
fn a_larger_threshold_never_narrows_sooner() {
    let _guard = counter();
    let bytes = many_small();

    let first = (0..3)
        .map(|_| flight_at(&bytes, 8, 8, 0, 12))
        .max()
        .expect("three runs");
    let mut seen: Vec<(usize, usize, bool)> = vec![(0, first, false)];
    for after in [4usize, 1000] {
        let floor = seen.last().expect("the first reading").1;
        let (reach, gave_up) = flight_held(&bytes, 8, 8, after, 12, floor);
        seen.push((after, reach, gave_up));
    }
    for pair in seen.windows(2) {
        let (lo, lo_reach, _) = pair[0];
        let (hi, hi_reach, gave_up) = pair[1];
        assert!(
            hi_reach >= lo_reach,
            "a threshold of {hi} reached {hi_reach} members where {lo} \
             reached {lo_reach} (held until {lo_reach}, hold given up: \
             {gave_up}), so the family is not ordered: {seen:?}"
        );
    }
}

/// And narrowing late changes no byte, whatever the threshold.
///
/// Promise 2.6's determinism on the read side, the same property
/// `extracted_bytes_do_not_depend_on_how_the_ceiling_is_divided` pins
/// for the division: how many members are in flight is a performance
/// choice and may never be an output one.
#[test]
fn narrowing_late_changes_no_byte() {
    let _guard = counter();
    let bytes = many_small();

    let want = digest_of(&bytes, 8, 8);
    for after in [0usize, 3, 1000] {
        let sink = Blackhole {
            closed: Mutex::new(Vec::new()),
            digests: Mutex::new(Vec::new()),
        };
        let opts = ReadOptions::default().with_workers(Some(8));
        let sources = vec![Arc::new(bytes.to_vec()) as Arc<dyn RangeSource>];
        probe::set_offload_floor(Some(0));
        probe::set_narrow_after(after);
        probe::set_breadth_arm(probe::BREADTH_ARM_LATE_NARROW);
        let report = extract_parallel(sources, &opts, &sink, 8);
        probe::set_breadth_arm(probe::BREADTH_ARM_SPILL);
        probe::set_narrow_after(probe::NARROW_AFTER_DEFAULT);
        probe::set_offload_floor(None);
        report.expect("parallel");
        let got = sink.digests.into_inner().unwrap_or_else(|e| e.into_inner());
        assert_eq!(
            got, want,
            "narrowing after {after} members delivered different bytes"
        );
    }
}
