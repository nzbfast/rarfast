//! `extract_parallel`: the same bytes as `extract`, `close` in archive
//! order, and several members open for writing at once.
//!
//! SPEC-API 4.4 and spec F 3.7.6. The property the pipeline exists for -
//! that the caller holds more than one output open - is one no output byte
//! can show, so the sink here counts its own open writers.

#![cfg(feature = "parallel")]

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rarkit::{
    extract, extract_parallel, Disposition, ErrorKind, MemberInfo, MemberOutcome, ParallelSink,
    RangeSource, ReadOptions, Result, Sink,
};

mod support {
    pub mod rar5build;
}

fn legacy(name: &str) -> Vec<u8> {
    let path = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/legacy/archives"
    ))
    .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn sources(bytes: Vec<u8>) -> Vec<Arc<dyn RangeSource>> {
    vec![Arc::new(bytes) as Arc<dyn RangeSource>]
}

/// What one member looked like to a sink.
type Got = (Vec<u8>, Vec<u8>, Option<bool>);

/// The sequential control.
#[derive(Default)]
struct Plain {
    got: Vec<Got>,
}

impl Sink for Plain {
    type Out = Vec<u8>;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.got.push((
            member.name.to_vec(),
            out.unwrap_or_default(),
            outcome.checksum_ok,
        ));
        Ok(())
    }
}

/// A writer that counts how many of its kind are alive at once and, for the
/// first member, takes its time so the walk can get ahead of it.
struct Slow {
    bytes: Vec<u8>,
    live: Arc<AtomicUsize>,
    delay: Option<Duration>,
}

impl Write for Slow {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if let Some(delay) = self.delay.take() {
            std::thread::sleep(delay);
        }
        self.bytes.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for Slow {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The parallel sink: `&self` everywhere, so the engine may call it for the
/// next member while the one before it is still being written.
struct Counting {
    got: Mutex<Vec<Got>>,
    opened: AtomicUsize,
    live: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
    delay: Duration,
}

impl Counting {
    fn new(delay: Duration) -> Counting {
        Counting {
            got: Mutex::new(Vec::new()),
            opened: AtomicUsize::new(0),
            live: Arc::new(AtomicUsize::new(0)),
            peak: Arc::new(AtomicUsize::new(0)),
            delay,
        }
    }
}

impl ParallelSink for Counting {
    type Out = Slow;

    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Slow>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        let live = self.live.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(live, Ordering::SeqCst);
        let first = self.opened.fetch_add(1, Ordering::SeqCst) == 0;
        Ok(Disposition::Write(Slow {
            bytes: Vec::new(),
            live: Arc::clone(&self.live),
            delay: first.then_some(self.delay),
        }))
    }

    fn close(
        &self,
        member: &MemberInfo<'_>,
        out: Option<Slow>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        let bytes = out.map(|w| w.bytes.clone()).unwrap_or_default();
        self.got.lock().expect("the sink's own lock").push((
            member.name.to_vec(),
            bytes,
            outcome.checksum_ok,
        ));
        Ok(())
    }
}

/// The pipeline delivers what the sequential walk does, member for member,
/// byte for byte, in archive order.
#[test]
fn the_parallel_walk_gives_the_sequential_walk_s_answer() {
    // Every fixture in this repository is below the engine's offload
    // floor, which is measured and production sized, so a test that
    // wants the concurrent path driven at all has to lower it. It is a
    // thread-local, so this reaches this test's own run and no other's.
    rarkit::probe::set_offload_floor(Some(0));
    for name in [
        "r420_m5.rar",
        "d250_m3.rar",
        "r420_solid.rar",
        "d140_m0.rar",
    ] {
        let bytes = legacy(name);
        let mut plain = Plain::default();
        extract(
            sources(bytes.clone()),
            &ReadOptions::default(),
            &mut plain,
            &mut (),
        )
        .unwrap_or_else(|e| panic!("{name}: sequential: {e}"));

        let sink = Counting::new(Duration::from_millis(0));
        let report = extract_parallel(sources(bytes), &ReadOptions::default(), &sink, 4)
            .unwrap_or_else(|e| panic!("{name}: parallel: {e}"));
        let got = sink.got.into_inner().expect("the sink's own lock");
        assert_eq!(
            got.len(),
            plain.got.len(),
            "{name}: the two walks closed different numbers of members"
        );
        for (want, have) in plain.got.iter().zip(&got) {
            assert_eq!(want.0, have.0, "{name}: close order");
            assert_eq!(want.1, have.1, "{name}: the member's bytes");
            assert_eq!(want.2, have.2, "{name}: the member's verdict");
        }
        assert_eq!(
            report.members as usize,
            plain.got.len().max(report.members as usize)
        );
    }
}

/// The property the pipeline exists for: the caller has more than one
/// output open at once. A writer that takes its time on the first member is
/// what makes it observable; with instant writers the engine is free to
/// close each member before opening the next, and does.
///
/// **The bound is TWICE the breadth since 22 Sep 2026**, and
/// the reason is measured: a worker whose answer has arrived takes the
/// next member while its own member waits to close in archive order, and
/// on an archive of small members of uneven size that took
/// `f/extract-par-src4k-m3` from a flight window the workers sat idle
/// behind to one they fill (small compressed
/// members, 22 Sep 2026). The members DECODING at once are still at most
/// the breadth; `tests/outputs_over_breadth.rs` holds that half, in a
/// binary of its own because the probe that counts it is process-wide.
#[test]
fn several_members_are_open_for_writing_at_once() {
    // Every fixture in this repository is below the engine's offload
    // floor, which is measured and production sized, so a test that
    // wants the concurrent path driven at all has to lower it. It is a
    // thread-local, so this reaches this test's own run and no other's.
    rarkit::probe::set_offload_floor(Some(0));
    // The DEFAULT, stated rather than assumed, so a process that carries
    // the outputs knob in its environment still tests what ships.
    rarkit::probe::set_outputs_over_breadth(Some(2));
    let bytes = legacy("r420_m5.rar");
    let sink = Counting::new(Duration::from_millis(400));
    extract_parallel(sources(bytes), &ReadOptions::default(), &sink, 4).expect("parallel");
    rarkit::probe::set_outputs_over_breadth(None);
    let peak = sink.peak.load(Ordering::SeqCst);
    assert!(
        peak >= 2,
        "the caller never held two outputs open at once (peak {peak}), so the \
         walk waited for each writer before opening the next"
    );
    assert!(
        peak <= 8,
        "the caller held {peak} outputs open at once, above twice the four \
         workers it was given"
    );
}

/// At an outputs factor of ONE the pool is the one that shipped before
/// that change: a worker is held until its member closes, so the caller
/// never holds more outputs open than the breadth.
#[test]
fn at_an_outputs_factor_of_one_the_open_outputs_stay_at_the_breadth() {
    rarkit::probe::set_offload_floor(Some(0));
    rarkit::probe::set_outputs_over_breadth(Some(1));
    let bytes = legacy("r420_m5.rar");
    let sink = Counting::new(Duration::from_millis(400));
    extract_parallel(sources(bytes), &ReadOptions::default(), &sink, 4).expect("parallel");
    rarkit::probe::set_outputs_over_breadth(None);
    let peak = sink.peak.load(Ordering::SeqCst);
    assert!(
        peak >= 2,
        "the caller never held two outputs open at once (peak {peak})"
    );
    assert!(
        peak <= 4,
        "the caller held {peak} outputs open at once, above the four workers it \
         was given, at a factor of one"
    );
}

/// The outputs factor at two (`RARKIT_OUTPUTS_OVER_BREADTH`, the default
/// since 22 Sep 2026): a worker whose answer has arrived is freed while an
/// earlier member is still waiting to close, so the caller holds MORE
/// outputs open than the breadth, and never more than twice it.
///
/// The slow first writer is what makes it observable: its worker is busy
/// writing for 400 ms while the other three answer, and in the shipped
/// pool those three would sit held until the first member closed.
#[test]
fn with_the_outputs_knob_at_two_the_open_outputs_rise_above_the_breadth_and_stop_at_twice_it() {
    rarkit::probe::set_offload_floor(Some(0));
    rarkit::probe::set_outputs_over_breadth(Some(2));
    let bytes = legacy("r420_m5.rar");
    let sink = Counting::new(Duration::from_millis(400));
    // The read's width stated: without a workers figure it is the pool's
    // own, and on a pool of two a breadth of four is held to two, where
    // twice the breadth is the four this test asks to see passed.
    let four_wide = ReadOptions::default().with_workers(Some(4));
    extract_parallel(sources(bytes), &four_wide, &sink, 4).expect("parallel");
    rarkit::probe::set_outputs_over_breadth(None);
    let peak = sink.peak.load(Ordering::SeqCst);
    let members = sink.got.lock().expect("the sink's own lock").len();
    assert!(
        members > 4,
        "the fixture has {members} members, too few for the bound to be visible"
    );
    assert!(
        peak > 4,
        "the caller never held more than the breadth open (peak {peak}), so no \
         answered worker was freed early and the knob did nothing"
    );
    assert!(
        peak <= 8,
        "the caller held {peak} outputs open at once, above twice the four \
         workers it was given"
    );
}

/// The outputs knob changes WHEN a worker is freed and nothing a caller
/// is handed: the same members, bytes, verdicts and archive order as the
/// sequential walk, with a slow first writer so answers really do arrive
/// out of order.
#[test]
fn with_the_outputs_knob_at_two_the_parallel_walk_still_gives_the_sequential_answer() {
    rarkit::probe::set_offload_floor(Some(0));
    rarkit::probe::set_outputs_over_breadth(Some(2));
    for name in [
        "r420_m5.rar",
        "d250_m3.rar",
        "r420_solid.rar",
        "d140_m0.rar",
    ] {
        let bytes = legacy(name);
        let mut plain = Plain::default();
        extract(
            sources(bytes.clone()),
            &ReadOptions::default(),
            &mut plain,
            &mut (),
        )
        .unwrap_or_else(|e| panic!("{name}: sequential: {e}"));
        for width in [1, 2, 4] {
            let sink = Counting::new(Duration::from_millis(30));
            extract_parallel(
                sources(bytes.clone()),
                &ReadOptions::default(),
                &sink,
                width,
            )
            .unwrap_or_else(|e| panic!("{name}: parallel at {width}: {e}"));
            let got = sink.got.into_inner().expect("the sink's own lock");
            assert_eq!(
                got.len(),
                plain.got.len(),
                "{name} at {width}: member count"
            );
            for (want, have) in plain.got.iter().zip(&got) {
                assert_eq!(want.0, have.0, "{name} at {width}: close order");
                assert_eq!(want.1, have.1, "{name} at {width}: the member's bytes");
                assert_eq!(want.2, have.2, "{name} at {width}: the member's verdict");
            }
        }
    }
    rarkit::probe::set_outputs_over_breadth(None);
}

/// The worker count is the lesser of the BREADTH the caller asked for and
/// the read's own WIDTH, which is `ReadOptions::workers` since API 8.4.2
/// (20 Sep 2026) and was `MemoryPolicy::max_workers` before it. The
/// buffers in flight stay inside the working limit either way: that is
/// the BUDGET's doing and `the_working_limit_bounds_the_windows_in_flight`
/// is where it is asserted, on a budget rather than on a thread count.
/// The OUTPUTS open are at most twice that worker count.
#[test]
fn the_width_caps_the_writers_in_flight() {
    // Every fixture in this repository is below the engine's offload
    // floor, which is measured and production sized, so a test that
    // wants the concurrent path driven at all has to lower it. It is a
    // thread-local, so this reaches this test's own run and no other's.
    rarkit::probe::set_offload_floor(Some(0));
    let bytes = legacy("r420_m5.rar");
    let opts = ReadOptions::default().with_workers(Some(1));
    let sink = Counting::new(Duration::from_millis(200));
    extract_parallel(sources(bytes), &opts, &sink, 8).expect("parallel");
    let peak = sink.peak.load(Ordering::SeqCst);
    // Twice the width since 22 Sep 2026: one member decoding, and at most
    // one more waiting to close with its answer in hand.
    assert!(
        peak <= 2,
        "the read's width allowed one worker and the caller held {peak} \
         outputs open, above twice that"
    );
}

/// Nothing is attempted with no workers.
#[test]
fn no_workers_is_a_named_limit() {
    let bytes = legacy("r420_m5.rar");
    let sink = Counting::new(Duration::ZERO);
    let err = extract_parallel(sources(bytes), &ReadOptions::default(), &sink, 0)
        .expect_err("zero workers");
    assert!(
        matches!(err.kind(), ErrorKind::LimitExceeded { .. }),
        "{err}"
    );
}

/// A sink that refuses ends the run as the CALLER's error, with the value
/// recoverable, and leaves no worker holding a writer.
#[test]
fn a_sink_that_refuses_ends_the_run_as_caller() {
    // Every fixture in this repository is below the engine's offload
    // floor, which is measured and production sized, so a test that
    // wants the concurrent path driven at all has to lower it. It is a
    // thread-local, so this reaches this test's own run and no other's.
    rarkit::probe::set_offload_floor(Some(0));
    /// Refuses the second member it is asked to close.
    struct Refuses {
        seen: AtomicUsize,
    }

    impl ParallelSink for Refuses {
        type Out = Vec<u8>;

        fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
            if member.is_directory {
                return Ok(Disposition::Skip);
            }
            Ok(Disposition::Write(Vec::new()))
        }

        fn close(
            &self,
            _member: &MemberInfo<'_>,
            _out: Option<Vec<u8>>,
            _outcome: &MemberOutcome,
        ) -> Result<()> {
            if self.seen.fetch_add(1, Ordering::SeqCst) == 1 {
                return Err(rarkit::Error::caller(std::io::Error::other("no thanks")));
            }
            Ok(())
        }
    }

    let bytes = legacy("r420_m5.rar");
    let sink = Refuses {
        seen: AtomicUsize::new(0),
    };
    let err = extract_parallel(sources(bytes), &ReadOptions::default(), &sink, 4)
        .expect_err("the sink refused");
    assert!(
        matches!(err.kind(), ErrorKind::Caller),
        "a caller's own error comes back as Caller: {err}"
    );
    assert!(
        err.into_caller_error().is_ok(),
        "the caller's value is recoverable"
    );
}

// ---------------------------------------------------------------------------
// Concurrent member decode (19 Sep 2026)
// ---------------------------------------------------------------------------
//
// SPEC-API 4.4 and spec F 3.7.6. What no output byte shows, and what these
// tests are therefore for: the members decode on several threads, `close`
// is still in archive order, a damaged member is reported through its own
// `close` with the members around it delivered, and the windows in flight
// stay inside the policy's budget.

fn vectors(name: &str) -> Vec<u8> {
    let path = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../specs/vectors-F/archives"
    ))
    .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The widths every equivalence below is checked at: one (which still
/// offloads, onto one worker), the interesting small ones, and one above
/// the number of members in any of these archives.
const WIDTHS: [usize; 5] = [1, 2, 3, 4, 8];

/// What one member looked like, whichever driver produced it.
type Seen = (Vec<u8>, Vec<u8>, Option<bool>);

/// What one extraction produced, member by member, plus its report.
struct Run {
    seen: Vec<Seen>,
    members: u64,
    bytes: u64,
    checksum_failures: u64,
    error: Option<String>,
}

/// A sink that writes, or one that only verifies: `Disposition::Verify` is
/// the `t` command, it decodes and checks without writing, and it must go
/// wide exactly as extraction does.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum How {
    Write,
    Verify,
}

/// The sequential control.
struct Serial {
    how: How,
    seen: Vec<Seen>,
}

impl Sink for Serial {
    type Out = Vec<u8>;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(match self.how {
            How::Write => Disposition::Write(Vec::new()),
            How::Verify => Disposition::Verify,
        })
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.seen.push((
            member.name.to_vec(),
            out.unwrap_or_default(),
            outcome.checksum_ok,
        ));
        Ok(())
    }
}

/// The same sink on `&self`, for the concurrent driver.
struct Wide {
    how: How,
    seen: Mutex<Vec<Seen>>,
}

impl ParallelSink for Wide {
    type Out = Vec<u8>;

    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(match self.how {
            How::Write => Disposition::Write(Vec::new()),
            How::Verify => Disposition::Verify,
        })
    }

    fn close(
        &self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.seen.lock().expect("the sink's own lock").push((
            member.name.to_vec(),
            out.unwrap_or_default(),
            outcome.checksum_ok,
        ));
        Ok(())
    }
}

fn serial(volumes: Vec<Arc<dyn RangeSource>>, opts: &ReadOptions, how: How) -> Run {
    let mut sink = Serial {
        how,
        seen: Vec::new(),
    };
    let outcome = extract(volumes, opts, &mut sink, &mut ());
    finish(sink.seen, outcome)
}

fn wide(volumes: Vec<Arc<dyn RangeSource>>, opts: &ReadOptions, how: How, workers: usize) -> Run {
    let sink = Wide {
        how,
        seen: Mutex::new(Vec::new()),
    };
    let outcome = extract_parallel(volumes, opts, &sink, workers);
    let seen = sink.seen.into_inner().expect("the sink's own lock");
    finish(seen, outcome)
}

fn finish(seen: Vec<Seen>, outcome: Result<rarkit::ExtractReport>) -> Run {
    match outcome {
        Ok(report) => Run {
            seen,
            members: report.members,
            bytes: report.bytes,
            checksum_failures: report.checksum_failures,
            error: None,
        },
        Err(e) => Run {
            seen,
            members: 0,
            bytes: 0,
            checksum_failures: 0,
            error: Some(kind_of(&e)),
        },
    }
}

/// The error kind, as a string, so two runs can be compared on it.
///
/// The CONTEXT a kind carries - the volume, the offset - differs between
/// the two drivers by design, because they meet a member at different
/// points of the walk; nothing here asserts on that.
fn kind_of(e: &rarkit::Error) -> String {
    format!("{:?}", e.kind())
}

/// Every member, in order, with the same bytes and the same verdict, and
/// the same report.
fn same(label: &str, want: &Run, have: &Run) {
    assert_eq!(
        want.seen.len(),
        have.seen.len(),
        "{label}: the two drivers closed different numbers of members\n  \
         sequential {:?}\n  concurrent {:?}",
        want.seen.iter().map(|m| &m.0).collect::<Vec<_>>(),
        have.seen.iter().map(|m| &m.0).collect::<Vec<_>>()
    );
    for (at, (a, b)) in want.seen.iter().zip(&have.seen).enumerate() {
        assert_eq!(a.0, b.0, "{label}: member {at} closed out of archive order");
        assert_eq!(a.1, b.1, "{label}: member {at} produced different bytes");
        assert_eq!(a.2, b.2, "{label}: member {at} got a different verdict");
    }
    assert_eq!(want.members, have.members, "{label}: report.members");
    assert_eq!(want.bytes, have.bytes, "{label}: report.bytes");
    assert_eq!(
        want.checksum_failures, have.checksum_failures,
        "{label}: report.checksum_failures"
    );
    assert_eq!(want.error, have.error, "{label}: the operation's own error");
}

/// The archives every equivalence runs over, each for a path it is the only
/// one that reaches.
fn corpus() -> Vec<(&'static str, Vec<Arc<dyn RangeSource>>)> {
    let one = |bytes: Vec<u8>| vec![Arc::new(bytes) as Arc<dyn RangeSource>];
    vec![
        // RAR 5, the offloading shapes.
        ("f01_stored.rar", one(vectors("f01_stored.rar"))),
        ("f03_m3.rar", one(vectors("f03_m3.rar"))),
        ("f05_blake.rar", one(vectors("f05_blake.rar"))),
        // RAR 5 with twelve entries, which is where the width is really
        // exercised: nine members, one of them empty, three directories.
        ("r550_m3.rar", one(legacy("r550_m3.rar"))),
        ("r550_m0.rar", one(legacy("r550_m0.rar"))),
        ("r550_md.rar", one(legacy("r550_md.rar"))),
        ("f02_dirs.rar", one(vectors("f02_dirs.rar"))),
        // A solid set, which stays on the walking thread whole.
        ("f04_solid.rar", one(vectors("f04_solid.rar"))),
        ("r420_solid.rar", one(legacy("r420_solid.rar"))),
        ("d250_sol.rar", one(legacy("d250_sol.rar"))),
        // The RAR 4 family and the two oldest containers.
        ("r420_m5.rar", one(legacy("r420_m5.rar"))),
        ("d250_m3.rar", one(legacy("d250_m3.rar"))),
        ("d155_m3.rar", one(legacy("d155_m3.rar"))),
        ("d140_m0.rar", one(legacy("d140_m0.rar"))),
        // A volume set: every member of it is split or follows one, so the
        // whole of it stays sequential and must still agree.
        (
            "f11_svol",
            vec![
                Arc::new(vectors("f11_svol.part1.rar")) as Arc<dyn RangeSource>,
                Arc::new(vectors("f11_svol.part2.rar")),
                Arc::new(vectors("f11_svol.part3.rar")),
                Arc::new(vectors("f11_svol.part4.rar")),
            ],
        ),
        (
            "f12_cvol",
            vec![
                Arc::new(vectors("f12_cvol.part1.rar")) as Arc<dyn RangeSource>,
                Arc::new(vectors("f12_cvol.part2.rar")),
                Arc::new(vectors("f12_cvol.part3.rar")),
                Arc::new(vectors("f12_cvol.part4.rar")),
            ],
        ),
        // A member no decoder claims, and a damaged one: both are reported
        // by name, and both cross this path.
        ("f15_bad_data_crc.rar", one(vectors("f15_bad_data_crc.rar"))),
        ("f13_truncated.rar", one(vectors("f13_truncated.rar"))),
    ]
}

/// The whole of SPEC-API 4.4's promise: byte for byte, member for member,
/// verdict for verdict, at every width, for extraction AND for `t`.
#[test]
fn every_width_gives_the_sequential_answer() {
    let opts = ReadOptions::default();
    // BOTH floors. At zero every member of these fixtures goes to a
    // worker, which is the path this driver exists for; at the engine's
    // own figure every one of them stays on the walking thread, which is
    // the path a real archive of small members takes. The answer has to be
    // the same, and the two are different code.
    for floor in [Some(0), None] {
        rarkit::probe::set_offload_floor(floor);
        let where_ = match floor {
            Some(0) => "workers",
            _ => "the walking thread",
        };
        for (name, volumes) in corpus() {
            for how in [How::Write, How::Verify] {
                let want = serial(volumes.clone(), &opts, how);
                for workers in WIDTHS {
                    let have = wide(volumes.clone(), &opts, how, workers);
                    same(
                        &format!("{name} {how:?} x{workers} on {where_}"),
                        &want,
                        &have,
                    );
                }
            }
        }
    }
    rarkit::probe::set_offload_floor(None);
}

/// The offload floor: a member too small to pay for a worker is decoded on
/// the WALKING thread, and the engine's own figure is what decides.
///
/// It is measured (`read::extract::OFFLOAD_FLOOR` says what by), and no
/// output byte shows it, so what is asserted is the counter that does:
/// `probe::decoded_members` counts on the thread that ran the decode, and
/// a member a worker decoded is not counted on the walking thread.
#[test]
fn a_member_too_small_for_a_worker_decodes_on_the_walking_thread() {
    let volumes = sources(legacy("r550_m0.rar"));
    // The engine's own floor. Every member of this fixture is well under
    // it, so the walking thread should decode all of them.
    rarkit::probe::set_offload_floor(None);
    rarkit::probe::reset();
    let sink = Wide {
        how: How::Write,
        seen: Mutex::new(Vec::new()),
    };
    let report =
        extract_parallel(volumes.clone(), &ReadOptions::default(), &sink, 8).expect("parallel");
    let here = rarkit::probe::decoded_members();
    assert!(
        here >= report.members - 3,
        "the walking thread decoded {here} of {} members below the offload          floor; a member the floor keeps at home must not reach a worker",
        report.members
    );

    // With the floor at zero the same archive goes to the workers, and the
    // walking thread decodes none of it.
    rarkit::probe::set_offload_floor(Some(0));
    rarkit::probe::reset();
    let sink = Wide {
        how: How::Write,
        seen: Mutex::new(Vec::new()),
    };
    extract_parallel(volumes, &ReadOptions::default(), &sink, 8).expect("parallel");
    let here = rarkit::probe::decoded_members();
    // A member declaring NO bytes is never handed over whatever the floor
    // is: it produces nothing, so a worker for it is a handoff for no
    // decode. This fixture holds exactly one (`EMPTY.DAT`).
    let empty = rarkit::Archive::open(
        Arc::new(legacy("r550_m0.rar")) as Arc<dyn RangeSource>,
        &ReadOptions::default(),
    )
    .expect("open")
    .members()
    .filter(|m| !m.is_directory && m.unpacked_size == Some(0))
    .count() as u64;
    assert_eq!(
        here, empty,
        "the walking thread decoded {here} members with the floor at zero, \
         against {empty} that declare no bytes"
    );
    rarkit::probe::set_offload_floor(None);
}

/// The offload floor asks how LONG a member takes, so it asks its METHOD.
///
/// A member of 64 KiB sits between the two floors: above the 16 KiB a
/// COMPRESSED member has to clear (`read::extract::OFFLOAD_FLOOR_
/// COMPRESSED`) and below the 256 KiB a STORED one has to
/// (`OFFLOAD_FLOOR`). The same 64 KiB therefore goes to a worker when it
/// is compressed and stays on the walking thread when it is stored, and
/// that is the whole of the distinction this pins: one archive shape, one
/// size, one width, and only the method changed.
///
/// No output byte shows any of it - `every_width_gives_the_sequential_
/// answer` is what says the bytes do not move - so what is asserted is
/// `probe::decoded_members`, which counts on the thread that ran the
/// decode and so counts a dispatched member nowhere.
#[test]
fn the_floor_a_member_clears_is_the_floor_for_its_method() {
    use rarkit::internals::rar20;
    use support::rar5build::{archive, Member};

    // 64 KiB, compressible enough that the encoder has real work to do:
    // between the two floors whichever way the member is stored.
    const SIZE: usize = 64 * 1024;
    let mut body = Vec::with_capacity(SIZE);
    while body.len() < SIZE {
        let at = body.len();
        body.extend_from_slice(format!("member body at {at} of {SIZE}\n").as_bytes());
    }
    body.truncate(SIZE);
    let packed = rar20::rar5_encode(&body, 3, 128 * 1024);
    let compressed = archive(&[Member {
        name: "C.BIN",
        unpacked: &body,
        packed: &packed,
        dictionary_exponent: 0,
        method: 3,
        solid: false,
    }]);
    let stored = archive(&[Member {
        name: "S.BIN",
        unpacked: &body,
        packed: &body,
        dictionary_exponent: 0,
        method: 0,
        solid: false,
    }]);

    // The ENGINE's own floors, which is the point: a probe figure would
    // replace both and assert nothing about either.
    rarkit::probe::set_offload_floor(None);
    for (what, bytes, on_the_walk) in [("compressed", compressed, 0u64), ("stored", stored, 1u64)] {
        rarkit::probe::reset();
        let sink = Wide {
            how: How::Write,
            seen: Mutex::new(Vec::new()),
        };
        let report = extract_parallel(sources(bytes), &ReadOptions::default(), &sink, 8)
            .expect("the member extracts");
        assert_eq!(report.members, 1, "{what}: one member");
        assert_eq!(report.checksum_failures, 0, "{what}: the member checks out");
        assert_eq!(
            sink.seen.lock().expect("the sink's own lock")[0].1,
            body,
            "{what}: the bytes are the member's"
        );
        assert_eq!(
            rarkit::probe::decoded_members(),
            on_the_walk,
            "{what}: {} members were decoded on the walking thread, wanted {on_the_walk}",
            rarkit::probe::decoded_members()
        );
    }
}

/// Spec F section 8, and the defect of its 8.1 item 3: a damaged member in
/// a non-solid archive loses neither itself nor the members around it. It
/// is reported through its OWN `close` with its own verdict, the members
/// after it are extracted, and the report counts the failure.
#[test]
fn a_damaged_member_keeps_its_neighbours() {
    // Every fixture in this repository is below the engine's offload
    // floor, which is measured and production sized, so a test that
    // wants the concurrent path driven at all has to lower it. It is a
    // thread-local, so this reaches this test's own run and no other's.
    rarkit::probe::set_offload_floor(Some(0));
    let opts = ReadOptions::default();
    for name in ["r550_m3.rar", "r550_m0.rar", "r550_md.rar", "r420_m5.rar"] {
        let clean = legacy(name);
        let archive = rarkit::Archive::open(Arc::new(clean.clone()) as Arc<dyn RangeSource>, &opts)
            .unwrap_or_else(|e| panic!("{name}: open: {e}"));
        let targets: Vec<(Vec<u8>, std::ops::Range<u64>)> = archive
            .members()
            // A member of a handful of packed bytes is not worth damaging:
            // the byte flipped may be one the decoder never reads, and the
            // test would be asserting nothing.
            .filter(|m| !m.is_directory && m.data.end - m.data.start >= 64)
            .map(|m| (m.name.to_vec(), m.data.clone()))
            .collect();
        drop(archive);
        assert!(
            targets.len() >= 2,
            "{name}: this test needs a multi-member archive"
        );
        // Every member the clean archive closes must still be closed when
        // one of them is damaged: that is the defect this rule removes.
        let intact = serial(
            vec![Arc::new(clean.clone()) as Arc<dyn RangeSource>],
            &opts,
            How::Write,
        );
        for (which, (damaged_name, data)) in targets.iter().enumerate() {
            let mut bytes = clean.clone();
            let at = (data.start + (data.end - data.start) / 2) as usize;
            bytes[at] ^= 0xff;
            let volumes = vec![Arc::new(bytes) as Arc<dyn RangeSource>];
            let want = serial(volumes.clone(), &opts, How::Write);
            assert!(
                want.error.is_some() || want.checksum_failures >= 1,
                "{name}: damaging member {which} changed nothing"
            );
            assert_eq!(
                want.seen.len(),
                intact.seen.len(),
                "{name}: sequential lost a member when {} was damaged",
                String::from_utf8_lossy(damaged_name)
            );
            for workers in WIDTHS {
                let have = wide(volumes.clone(), &opts, How::Write, workers);
                same(
                    &format!(
                        "{name} damaged {} x{workers}",
                        String::from_utf8_lossy(damaged_name)
                    ),
                    &want,
                    &have,
                );
            }
        }
    }
}

/// The error the run reports is the FIRST failing member in archive order,
/// whatever order the workers finished in.
#[test]
fn the_first_failure_in_archive_order_is_the_one_reported() {
    // Every fixture in this repository is below the engine's offload
    // floor, which is measured and production sized, so a test that
    // wants the concurrent path driven at all has to lower it. It is a
    // thread-local, so this reaches this test's own run and no other's.
    rarkit::probe::set_offload_floor(Some(0));
    let opts = ReadOptions::default();
    let clean = legacy("r550_m0.rar");
    let archive = rarkit::Archive::open(Arc::new(clean.clone()) as Arc<dyn RangeSource>, &opts)
        .expect("open");
    let targets: Vec<std::ops::Range<u64>> = archive
        .members()
        .filter(|m| !m.is_directory && m.data.end > m.data.start)
        .map(|m| m.data.clone())
        .collect();
    drop(archive);
    assert!(targets.len() >= 2, "this test needs two members");
    // Damage them ALL, so every worker has something to report and the one
    // that is reported can only be right by order.
    let mut bytes = clean;
    for data in &targets {
        let at = (data.start + (data.end - data.start) / 2) as usize;
        bytes[at] ^= 0xff;
    }
    let volumes = vec![Arc::new(bytes) as Arc<dyn RangeSource>];
    let want = serial(volumes.clone(), &opts, How::Write);
    assert_eq!(
        want.checksum_failures as usize,
        targets.len(),
        "damaging every member should fail every member"
    );
    for workers in WIDTHS {
        let have = wide(volumes.clone(), &opts, How::Write, workers);
        same(&format!("all damaged x{workers}"), &want, &have);
    }
}

/// The property the concurrent path exists for, and the one no output byte
/// can show: two members are inside their DECODE at the same moment.
///
/// A member's decode writes into the caller's writer on the worker that is
/// decoding it, so a writer that holds still while it counts its fellows is
/// standing inside two decodes at once when it sees two.
#[test]
fn two_members_decode_at_once() {
    // Every fixture in this repository is below the engine's offload
    // floor, which is measured and production sized, so a test that
    // wants the concurrent path driven at all has to lower it. It is a
    // thread-local, so this reaches this test's own run and no other's.
    rarkit::probe::set_offload_floor(Some(0));
    /// Counts how many writers are inside `write` together.
    struct Together {
        live: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
        bytes: Vec<u8>,
    }

    impl Write for Together {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            let live = self.live.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(live, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(20));
            self.bytes.extend_from_slice(data);
            self.live.fetch_sub(1, Ordering::SeqCst);
            Ok(data.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct Watch {
        live: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
    }

    impl ParallelSink for Watch {
        type Out = Together;

        fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Together>> {
            if member.is_directory {
                return Ok(Disposition::Skip);
            }
            Ok(Disposition::Write(Together {
                live: Arc::clone(&self.live),
                peak: Arc::clone(&self.peak),
                bytes: Vec::new(),
            }))
        }
    }

    let sink = Watch {
        live: Arc::new(AtomicUsize::new(0)),
        peak: Arc::new(AtomicUsize::new(0)),
    };
    extract_parallel(
        sources(legacy("r550_m0.rar")),
        &ReadOptions::default(),
        &sink,
        4,
    )
    .expect("parallel");
    let peak = sink.peak.load(Ordering::SeqCst);
    assert!(
        peak >= 2,
        "no two members were inside their decode at once (peak {peak}): the \
         members are being decoded one after another"
    );
}

/// `Disposition::Verify` - the `t` command - goes wide too. It writes
/// nothing, so the only thing that can show it went wide is the time, and
/// the only thing that can show it stayed correct is the verdict; this
/// asserts the second and leaves the first to the bench.
#[test]
fn verify_goes_wide_and_keeps_its_verdicts() {
    // Every fixture in this repository is below the engine's offload
    // floor, which is measured and production sized, so a test that
    // wants the concurrent path driven at all has to lower it. It is a
    // thread-local, so this reaches this test's own run and no other's.
    rarkit::probe::set_offload_floor(Some(0));
    let opts = ReadOptions::default();
    let volumes = sources(legacy("r550_m3.rar"));
    let want = serial(volumes.clone(), &opts, How::Verify);
    assert!(
        want.seen.iter().any(|m| m.2 == Some(true)),
        "the control verified nothing"
    );
    for workers in WIDTHS {
        let have = wide(volumes.clone(), &opts, How::Verify, workers);
        same(&format!("verify x{workers}"), &want, &have);
        assert!(
            have.seen.iter().all(|m| m.1.is_empty()),
            "verify wrote bytes"
        );
    }
}

/// SPEC-API 5.2, as corrected on 19 Sep 2026, and 8.3: the parallel
/// working memory is ONE WINDOW PER MEMBER IN FLIGHT plus the sequential
/// figure's other terms, and the engine reduces the members in flight so
/// the total stays inside `working_limit`. A member whose window does not
/// fit beside the others WAITS rather than overshooting.
///
/// The figure compared against is the SEQUENTIAL peak at the same policy
/// times the worker count. That is an UPPER bound on what 5.2 now allows
/// and not a restatement of it - the corrected text multiplies only the
/// window term - so a build that held a second window per member would
/// still be inside this. What makes the assertion worth making is the
/// other direction: an absolute number would be a restatement of the
/// fixture's dictionary size and would say nothing about going wide.
#[test]
fn the_working_limit_bounds_the_windows_in_flight() {
    // Every fixture in this repository is below the engine's offload
    // floor, which is measured and production sized, so a test that
    // wants the concurrent path driven at all has to lower it. It is a
    // thread-local, so this reaches this test's own run and no other's.
    rarkit::probe::set_offload_floor(Some(0));
    let bytes = legacy("r550_m3.rar");
    // The lowest rung is 2 MiB: this fixture's one-member floor is about
    // 1.25 MiB, and a named budget under it is refused before any member,
    // which is not what this test is about.
    for limit in [2u64 << 20, 8 << 20, 64 << 20, 512 << 20] {
        // Only the BUDGET is moved here; the width is the caller's, through
        // `ReadOptions::workers` (8.4.2), so the two can be told apart.
        // That is the whole point of the split: this test moves the bytes
        // and holds the threads still.
        let opts = ReadOptions::default()
            .with_memory(rarkit::MemoryPolicy::from_limit(limit))
            .with_workers(Some(8));
        let want = serial(sources(bytes.clone()), &opts, How::Write);
        let sink = Wide {
            how: How::Write,
            seen: Mutex::new(Vec::new()),
        };
        let report = extract_parallel(sources(bytes.clone()), &opts, &sink, 8).expect("parallel");
        let have = Run {
            seen: sink.seen.into_inner().expect("the sink's own lock"),
            members: report.members,
            bytes: report.bytes,
            checksum_failures: report.checksum_failures,
            error: None,
        };
        same(&format!("budget {limit}"), &want, &have);
        let ceiling = sequential_peak(&bytes, &opts).saturating_mul(8);
        assert!(
            report.peak_working_memory <= ceiling,
            "a budget of {limit} bytes over 8 workers held {} of working \
             memory, above the sequential figure times the worker count \
             ({ceiling})",
            report.peak_working_memory
        );
    }
}

/// The peak one sequential extraction of `bytes` reports under `opts`.
fn sequential_peak(bytes: &[u8], opts: &ReadOptions) -> u64 {
    let mut sink = Serial {
        how: How::Write,
        seen: Vec::new(),
    };
    extract(sources(bytes.to_vec()), opts, &mut sink, &mut ())
        .expect("the control extraction")
        .peak_working_memory
}

/// The width the engine uses is the CALLER's, through the policy, and never
/// the machine's: nothing in the engine reads the core count.
///
/// SPEC-API 8.2 and 8.3 (added 19 Sep 2026), with 8.4.2's field (20 Sep
/// 2026): the read's width is a ceiling on the units of work one stage may
/// have in flight, it is spent on BREADTH before width, and a member never
/// holds two windows. This test is that ceiling, asserted from outside:
/// with `ReadOptions::workers` at n the caller never holds more than
/// TWICE n outputs open at once (22 Sep 2026: the members
/// DECODING stay at most n, and an answered member may wait to close
/// beside them), whatever breadth it asked for. It was
/// `MemoryPolicy::max_workers` until 8.4.2 took the read's threads off the
/// memory policy; what the policy still bounds is BYTES, which
/// `the_working_limit_bounds_the_windows_in_flight` above asserts.
#[test]
fn the_policy_caps_the_members_in_flight() {
    // Every fixture in this repository is below the engine's offload
    // floor, which is measured and production sized, so a test that
    // wants the concurrent path driven at all has to lower it. It is a
    // thread-local, so this reaches this test's own run and no other's.
    rarkit::probe::set_offload_floor(Some(0));
    let bytes = legacy("r550_m0.rar");
    for allowed in [1usize, 2, 3] {
        let opts = ReadOptions::default().with_workers(Some(allowed));
        let sink = Counting::new(Duration::from_millis(60));
        extract_parallel(sources(bytes.clone()), &opts, &sink, 64).expect("parallel");
        let peak = sink.peak.load(Ordering::SeqCst);
        assert!(
            peak <= 2 * allowed,
            "the read's width allowed {allowed} workers and the caller held {peak} \
             outputs open at once, above twice that"
        );
    }
}

/// A cancel flag stops the concurrent path as it stops the sequential one,
/// and the error is `Cancelled` and not a decoder's verdict.
#[test]
fn a_cancel_flag_stops_the_workers() {
    let flag = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let opts = ReadOptions::default().with_cancel(Some(Arc::clone(&flag)));
    let sink = Wide {
        how: How::Write,
        seen: Mutex::new(Vec::new()),
    };
    let err = extract_parallel(sources(vectors("f03_m3.rar")), &opts, &sink, 4)
        .expect_err("the flag was set before the walk began");
    assert!(matches!(err.kind(), ErrorKind::Cancelled), "{err}");
}

// ---------------------------------------------------------------------------
// A refusal reaches a worker's decode (20 Sep 2026)
// ---------------------------------------------------------------------------

/// `DATA.BIN` of `D140_M5.RAR` with its declared unpacked size replaced and
/// its "continues from the previous volume" flag set.
///
/// The two edits together are what put the member on the path this test is
/// for. Spec F 3.4.2 gives the RAR 1.3/1.4 file entry as twenty-one bytes
/// then the name, with the unpacked size at offset 4 and the flags at
/// offset 17, and 3.4.4 gives flag 0x01 as "the member continues from the
/// previous volume". A split member is one the concurrent driver never
/// dispatches (it cannot know the later fragments), so the WALK decodes it
/// and only its writes go to a worker - which is exactly the arrangement
/// where a refusal had nowhere to go.
///
/// The declared size is the fuzzer's own trick, from the seed
/// `fuzz/seeds/f_extract_parallel/par-sink-refusal-ignored-2.6gb`, which
/// reached 2,634,043,104 bytes by damaging this field. This test asks for
/// far less, because it has to run in a debug build: at the engine's
/// measured 270 to 290 MB/s a decode that ignores the refusal still costs
/// hundreds of milliseconds here, and a debug build costs it many times
/// over.
///
/// **This helper no longer drives the test below, and it is kept only for
/// what it still proves** (`an_inflated_declared_size_no_longer_buys_a_long_decode`).
/// SPEC-A 6.1 as decided on 20 Sep 2026 ends a RAR 1.5 member
/// when its PACKED input is exhausted, so inflating a declared size buys
/// no decode time at all any more: this construction now stops at about
/// `DATA.BIN`'s true 20,192 bytes whatever it declares.
/// `TEXT.TXT` of `fixtures/large-rar15/archives/l15_txt.rar` with its
/// "continues from the previous volume" flag set, and nothing else touched.
///
/// The member is 4,194,304 bytes from 1,557,122 PACKED, so its length is
/// the archive's own and survives SPEC-A 6.1's bound. The flag
/// is what puts it on the piped path: a split member is one the concurrent
/// driver never dispatches, so the walk decodes it and only its writes go
/// to a worker, which is the arrangement this test is for.
///
/// Spec F 3.4.2's RAR 4 file entry: a seven byte marker, then blocks of
/// `crc(2) type(1) flags(2) size(2)`, with an `add_size(4)` after the
/// header when flag 0x8000 is set. Every offset is asserted rather than
/// assumed, so replacing the fixture fails loudly.
fn large_member_refused() -> Vec<u8> {
    let path = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/large-rar15/archives/l15_txt.rar"
    ));
    let mut bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    assert_eq!(
        &bytes[..7],
        b"Rar!\x1a\x07\x00",
        "l15_txt.rar is not a RAR 4 archive"
    );
    let mut at = 7usize;
    loop {
        assert!(at + 7 <= bytes.len(), "l15_txt.rar has no file entry");
        let kind = bytes[at + 2];
        let flags = u16::from_le_bytes([bytes[at + 3], bytes[at + 4]]);
        let size = usize::from(u16::from_le_bytes([bytes[at + 5], bytes[at + 6]]));
        let add = if flags & 0x8000 != 0 {
            u32::from_le_bytes(bytes[at + 7..at + 11].try_into().expect("four bytes")) as usize
        } else {
            0
        };
        if kind == 0x74 {
            let packed = u32::from_le_bytes(bytes[at + 7..at + 11].try_into().expect("four bytes"));
            let unpacked =
                u32::from_le_bytes(bytes[at + 11..at + 15].try_into().expect("four bytes"));
            assert_eq!(packed, 1_557_122, "l15_txt.rar's packed size moved");
            assert_eq!(unpacked, 4_194_304, "l15_txt.rar's unpacked size moved");
            // The low byte of the block flags, where 0x01 is "continues
            // from the previous volume".
            bytes[at + 3] |= 0x01;
            // This vector's file header carries a CRC over itself (spec F
            // 3.4.2: the low sixteen bits of CRC32 over the header from
            // its type byte to its end), so the edit has to be re-sealed
            // or the walk refuses the header before reaching the decode.
            // `D140_M5.RAR`, the vector this test used before, is an older
            // layout that does not, which is why nothing here was needed.
            let sealed = header_crc16(&bytes[at + 2..at + size]);
            bytes[at..at + 2].copy_from_slice(&sealed.to_le_bytes());
            return bytes;
        }
        at += size + add;
    }
}

/// The low sixteen bits of CRC32 over a block header, which is what spec
/// F 3.4.2's `crc` field holds.
fn header_crc16(header: &[u8]) -> u16 {
    let mut crc = 0xffff_ffffu32;
    for byte in header {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let take = crc & 1 != 0;
            crc >>= 1;
            if take {
                crc ^= 0xedb8_8320;
            }
        }
    }
    (!crc) as u16
}

fn declared_but_refused(declared: u32) -> Vec<u8> {
    let mut bytes = vectors("D140_M5.RAR");
    // The archive header's own size field says where the first entry is
    // (3.4.1), and each entry names the start of the next one (3.4.2).
    let mut at = usize::from(u16::from_le_bytes([bytes[4], bytes[5]]));
    loop {
        let packed = u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"));
        let header = usize::from(u16::from_le_bytes([bytes[at + 10], bytes[at + 11]]));
        let name_len = usize::from(bytes[at + 19]);
        if &bytes[at + 21..at + 21 + name_len] == b"DATA.BIN" {
            bytes[at + 4..at + 8].copy_from_slice(&declared.to_le_bytes());
            bytes[at + 17] |= 0x01;
            return bytes;
        }
        at += header + packed as usize;
        assert!(at + 21 <= bytes.len(), "DATA.BIN is in this vector");
    }
}

/// A writer that refuses once one member has handed it `ceiling` bytes, and
/// counts what it was offered so the two drivers can be compared on it.
struct Ceiling {
    given: u64,
    ceiling: u64,
    offered: Arc<AtomicUsize>,
}

impl Write for Ceiling {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.offered.fetch_add(data.len(), Ordering::Relaxed);
        self.given += data.len() as u64;
        if self.given > self.ceiling {
            return Err(std::io::Error::other("past this test's ceiling"));
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Ceilings {
    ceiling: u64,
    offered: Arc<AtomicUsize>,
}

impl Ceilings {
    fn writer(&self) -> Ceiling {
        Ceiling {
            given: 0,
            ceiling: self.ceiling,
            offered: Arc::clone(&self.offered),
        }
    }
}

impl Sink for Ceilings {
    type Out = Ceiling;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Ceiling>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(self.writer()))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        _out: Option<Ceiling>,
        _outcome: &MemberOutcome,
    ) -> Result<()> {
        Ok(())
    }
}

impl ParallelSink for Ceilings {
    type Out = Ceiling;

    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Ceiling>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(self.writer()))
    }

    fn close(
        &self,
        _member: &MemberInfo<'_>,
        _out: Option<Ceiling>,
        _outcome: &MemberOutcome,
    ) -> Result<()> {
        Ok(())
    }
}

/// A caller's writer refusing stops the decode of a PIPED member about as
/// promptly as it stops the walking thread's own.
///
/// Spec F 3.7.6 makes the caller what stops an extraction. It held on the
/// sequential path and did not hold here: the worker writing a piped
/// member's bytes recorded the refusal and went on draining, so the walk
/// decoded every byte the header declared before anyone heard about it.
/// Measured 20 Sep 2026 on the 2.6 GB seed above, aarch64 release: 0.20 ms
/// sequentially against 7.3 SECONDS at width 4, at a ceiling of zero where
/// the very first write was refused.
///
/// The budget is the sequential arm's OWN wall on the same bytes, times
/// twenty, floored at a quarter of a second so that a fast machine does
/// not measure the floor. That is a loose bound deliberately - this is not
/// a bench and it runs on a shared box - and the defect is about three
/// orders of magnitude, so nothing in between is at stake.
///
/// # The vehicle changed on 20 Sep 2026, and the test is weaker for it
///
/// This test used to inflate `DATA.BIN`'s DECLARED size to 512 MiB over
/// 12,309 packed bytes, so an ignoring worker decoded 512 MiB and a
/// hearing one decoded a chunk. SPEC-A 6.1 ends a
/// RAR 1.5 member when its packed input is exhausted, which removes that
/// amplification entirely: the same construction now produces about 20,192
/// bytes and the writer never reaches its ceiling at all.
///
/// So the vehicle is now a GENUINE large member - `l15_txt.rar`'s
/// `TEXT.TXT`, 4,194,304 bytes from 1,557,122 packed, written by RAR 1.55
/// for DOS - whose length the rule does not touch, because its packed
/// input really does hold those bytes. What is lost is the MARGIN: the
/// ignoring decode is now about 15 ms rather than 1.7 s, which the
/// quarter-second floor below swallows, so the wall assertion no longer
/// discriminates on a fast box and only the two `ErrorKind::Caller`
/// assertions and the equal-bytes assertion carry weight.
///
/// **Still open for this test** (the concurrent refusal fix): either a vehicle whose packed input is large enough
/// to restore the margin under the bound, or a direct assertion on the
/// worker's refusal handshake instead of a wall. The decoder
/// change the rule required did not redesign this test beyond keeping it
/// honest.
#[test]
fn a_refused_write_stops_a_piped_member_s_decode() {
    rarkit::probe::set_offload_floor(Some(0));
    // 4 MiB of genuine member, 64 KiB allowed. A decode that ignores the
    // refusal produces the whole 4 MiB; one that hears it produces about a
    // chunk.
    let bytes = large_member_refused();
    let ceiling = 64 << 10;

    let offered = Arc::new(AtomicUsize::new(0));
    let mut serial = Ceilings {
        ceiling,
        offered: Arc::clone(&offered),
    };
    let started = std::time::Instant::now();
    let want = extract(
        sources(bytes.clone()),
        &ReadOptions::default(),
        &mut serial,
        &mut (),
    )
    .expect_err("the writer refused");
    let sequentially = started.elapsed();
    let offered_sequentially = offered.load(Ordering::Relaxed);

    let wide = Ceilings {
        ceiling,
        offered: Arc::new(AtomicUsize::new(0)),
    };
    let started = std::time::Instant::now();
    let have = extract_parallel(sources(bytes), &ReadOptions::default(), &wide, 4)
        .expect_err("the writer refused");
    let widely = started.elapsed();

    assert!(
        matches!(want.kind(), ErrorKind::Caller),
        "the sequential arm ends in the caller's error: {want}"
    );
    assert!(
        matches!(have.kind(), ErrorKind::Caller),
        "the concurrent arm ends in the caller's error: {have}"
    );
    // The refused member's bytes stop at the same place either way: the
    // writer is offered one chunk past its ceiling and then nothing.
    assert_eq!(
        offered_sequentially,
        wide.offered.load(Ordering::Relaxed),
        "the two arms offered the writer different numbers of bytes"
    );
    let budget = (sequentially * 20).max(Duration::from_millis(250));
    assert!(
        widely <= budget,
        "a refusal took {widely:?} to stop the concurrent decode, against \
         {sequentially:?} sequentially and a budget of {budget:?}: the \
         worker is decoding the whole declared member before it answers"
    );
}

/// SPEC-A 6.1 on BOTH drivers: inflating a declared
/// unpacked size buys no decode at all, because the packed input is what
/// ends a RAR 1.5 member.
///
/// This is the construction the test above used to ride on, kept because
/// it now proves the opposite thing and proves it on the concurrent path,
/// which SPEC-A 6.1's acceptance tests do not mention and which has its
/// own decode loop's worth of ways to get this wrong. A 512 MiB declared
/// member that really decoded to 512 MiB would take about 1.7 s here; the
/// budget is deliberately far looser than that, so this fails on the
/// BEHAVIOUR and not on a shared box's timing.
#[test]
fn an_inflated_declared_size_no_longer_buys_a_long_decode() {
    rarkit::probe::set_offload_floor(Some(0));
    let bytes = declared_but_refused(512 << 20);
    // Far above the member's true 20,192 bytes and far below its declared
    // 512 MiB, so the writer is never refused and the report is the
    // engine's own verdict.
    let ceiling = 1 << 20;

    for parallel in [false, true] {
        let offered = Arc::new(AtomicUsize::new(0));
        let mut sink = Ceilings {
            ceiling,
            offered: Arc::clone(&offered),
        };
        let started = std::time::Instant::now();
        let report = if parallel {
            extract_parallel(sources(bytes.clone()), &ReadOptions::default(), &sink, 4)
        } else {
            extract(
                sources(bytes.clone()),
                &ReadOptions::default(),
                &mut sink,
                &mut (),
            )
        }
        .unwrap_or_else(|e| panic!("parallel {parallel}: {e}"));
        let took = started.elapsed();

        assert!(
            report.bytes < 1 << 20,
            "parallel {parallel}: {} bytes from a member declaring 512 MiB \
             over 12,309 packed ones: SPEC-A 6.1 ends it at the packed input",
            report.bytes
        );
        assert_eq!(
            report.checksum_failures, 1,
            "parallel {parallel}: the short member's checksum is what reports \
             the shortfall (SPEC-A 6.1, SPEC-F 2.5), and it is not an error"
        );
        assert!(
            took < Duration::from_secs(5),
            "parallel {parallel}: {took:?} for a member the packed input ends \
             in milliseconds"
        );
    }
}

/// A source that hands its bytes over in small pieces, so the engine's
/// short-read loops are exercised rather than assumed.
struct Dribble(Vec<u8>, usize);

impl RangeSource for Dribble {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let want = buf.len().min(self.1);
        RangeSource::read_at(&self.0, offset, &mut buf[..want])
    }
    fn available(&self) -> u64 {
        self.0.len() as u64
    }
    fn len(&self) -> Option<u64> {
        Some(self.0.len() as u64)
    }
}

/// **A dispatched STORED member reads straight into the caller's buffer
/// once the request outgrows the worker's window, and that bypass is
/// invisible in the bytes.**
///
/// `read::concurrent::RangeRead` serves small requests out of a 64 KiB
/// staging window, which is what a decoder wants, and hands a larger one
/// over directly, which is what a stored member wants: the member is
/// otherwise copied twice and walked in 64 KiB steps whatever it asked
/// for. Both paths are live in one build and the SIZE of the request
/// chooses between them, so the member sizes here straddle that window
/// deliberately - under it, on it, one byte past it, and far past it -
/// and each is checked against the SEQUENTIAL engine's answer for the
/// same archive, which takes neither path.
///
/// **And against a source that answers SHORT.** The bypass asks for the
/// whole of the member's remainder in one call, so a source free to
/// return less is what says the caller's loop still ends on the right
/// byte and that a partial answer is never read as the end of the member.
/// Three dribble widths are used, one of them a single byte, so a request
/// far larger than the window is satisfied in hundreds of thousands of
/// pieces.
///
/// Both dispositions are run: `Write` is the extract path and `Verify` is
/// the test path, which writes nothing and is where the double copy was
/// most of the wall.
#[test]
fn a_dispatched_stored_member_crosses_the_workers_window_intact() {
    use support::rar5build::{archive, Member};

    // `read::concurrent::READ_BUF`, which this test may not reach for.
    const WINDOW: usize = 64 * 1024;

    for size in [1usize, WINDOW - 1, WINDOW, WINDOW + 1, 3 * WINDOW, 1 << 20] {
        let mut body = Vec::with_capacity(size);
        while body.len() < size {
            let at = body.len();
            body.extend_from_slice(format!("stored body at {at} of {size}\n").as_bytes());
        }
        body.truncate(size);
        let bytes = archive(&[Member {
            name: "S.BIN",
            unpacked: &body,
            packed: &body,
            dictionary_exponent: 0,
            method: 0,
            solid: false,
        }]);

        for how in [How::Write, How::Verify] {
            let want = serial(sources(bytes.clone()), &ReadOptions::default(), how);
            assert_eq!(
                want.seen.len(),
                1,
                "size {size}: the archive holds one member and the control saw {}",
                want.seen.len()
            );
            assert_eq!(
                want.seen[0].2,
                Some(true),
                "size {size} {how:?}: the CONTROL's own checksum verdict"
            );

            for piece in [0usize, 1, 7, 4096] {
                let src: Vec<Arc<dyn RangeSource>> = if piece == 0 {
                    sources(bytes.clone())
                } else {
                    vec![Arc::new(Dribble(bytes.clone(), piece)) as Arc<dyn RangeSource>]
                };
                let got = wide(src, &ReadOptions::default(), how, 4);
                assert_eq!(
                    got.seen,
                    want.seen,
                    "size {size} {how:?}, source answering {} bytes at a time: \
                     the dispatched member's bytes, name and checksum verdict \
                     must be the sequential engine's exactly",
                    if piece == 0 { usize::MAX } else { piece }
                );
                assert_eq!(
                    got.bytes, want.bytes,
                    "size {size} {how:?}, piece {piece}: the reported byte count"
                );
            }
        }
    }
}

/// A worker sweeping its task channel for its next member, instead of
/// parking on it at once, changes nothing a caller sees.
///
/// `read::concurrent::TASK_SPIN_US` is a WAIT and not a decision: the same
/// tasks arrive at the same worker in the same order whether it swept for
/// them or slept for them, and a closed channel still ends the worker. So
/// the test is an equality over everything a caller can observe - the
/// members, their bytes, their verdicts and their order - taken at a sweep
/// of zero, which is what the engine did before this existed, and at one
/// long enough that every dispatch of this archive lands inside it.
///
/// It is not a timing test and asserts nothing about the wall. What made
/// the sweep worth having was measured; what makes it SAFE is
/// here.
#[test]
fn a_worker_sweeping_for_its_next_member_changes_nothing_a_caller_sees() {
    use rarkit::internals::rar20;
    use support::rar5build::{archive, Member};

    // Above the compressed offload floor, so every one of them is
    // dispatched and every dispatch crosses the channel this is about.
    const SIZE: usize = 32 * 1024;
    let names = ["A.BIN", "B.BIN", "C.BIN", "D.BIN", "E.BIN"];
    let mut bodies = Vec::new();
    for (n, name) in names.iter().enumerate() {
        let mut body = Vec::with_capacity(SIZE);
        while body.len() < SIZE {
            let at = body.len();
            body.extend_from_slice(format!("{name} body at {at} of {SIZE} in {n}\n").as_bytes());
        }
        body.truncate(SIZE);
        bodies.push(body);
    }
    let packed: Vec<Vec<u8>> = bodies
        .iter()
        .map(|b| rar20::rar5_encode(b, 3, 128 * 1024))
        .collect();
    let members: Vec<Member<'_>> = names
        .iter()
        .enumerate()
        .map(|(n, name)| Member {
            name,
            unpacked: &bodies[n],
            packed: &packed[n],
            dictionary_exponent: 0,
            method: 3,
            solid: false,
        })
        .collect();
    let bytes = archive(&members);

    // The ENGINE's own floors: a probe figure would replace both and this
    // archive would be dispatched for a different reason than the one the
    // test is about.
    rarkit::probe::set_offload_floor(None);
    let mut answers = Vec::new();
    for sweep in [0u64, 5_000] {
        rarkit::probe::set_task_spin(Some(sweep));
        let sink = Wide {
            how: How::Write,
            seen: Mutex::new(Vec::new()),
        };
        let report = extract_parallel(sources(bytes.clone()), &ReadOptions::default(), &sink, 4)
            .expect("the archive extracts at any sweep");
        let seen = sink.seen.into_inner().expect("the sink's own lock");
        assert_eq!(
            seen.len(),
            names.len(),
            "sweep {sweep}: every member closed"
        );
        assert_eq!(report.checksum_failures, 0, "sweep {sweep}: all check out");
        for (n, name) in names.iter().enumerate() {
            assert_eq!(seen[n].0, name.as_bytes(), "sweep {sweep}: archive order");
            assert_eq!(seen[n].1, bodies[n], "sweep {sweep}: {name}'s own bytes");
        }
        answers.push((seen, report.members, report.bytes));
    }
    rarkit::probe::set_task_spin(None);
    assert_eq!(
        answers[0].0, answers[1].0,
        "the two sweeps saw the same members, bytes and verdicts in the same order"
    );
    assert_eq!(
        (answers[0].1, answers[0].2),
        (answers[1].1, answers[1].2),
        "and the same report"
    );
}

// ---------------------------------------------------------------------------
// Small member batches (RARKIT_SMALL_BATCH, 26 Sep 2026)
// ---------------------------------------------------------------------------

/// The batch shapes every batch test runs over, as `(members, cap bytes)`:
/// one at a time (the FLOOR1 screen), the arms' shapes, one far wider than
/// any fixture, and a cap so small no member fits it, which sends each
/// member to a worker by itself and never as a batch.
const BATCHES: [(usize, u64); 6] = [
    (1, 64 << 10),
    (2, 64 << 10),
    (4, 256 << 10),
    (8, 64 << 10),
    (64, 1 << 20),
    (4, 1),
];

/// With batches on and the engine's OWN floors, every small compressed
/// member goes to a worker in a batch, and the answer is the sequential
/// one: order, bytes, verdicts, report and error, for `x` and `t`.
#[test]
fn small_member_batches_give_the_sequential_answer() {
    let opts = ReadOptions::default();
    rarkit::probe::set_offload_floor(None);
    // The member team at its default, uncapped, and squeezed
    // to one worker, which makes the most of its waits.
    for team in [None, Some(0), Some(1)] {
        rarkit::probe::set_small_team(team);
        for batch in BATCHES {
            rarkit::probe::set_small_batch(Some(batch));
            for (name, volumes) in corpus() {
                for how in [How::Write, How::Verify] {
                    let want = serial(volumes.clone(), &opts, how);
                    for workers in WIDTHS {
                        let have = wide(volumes.clone(), &opts, how, workers);
                        same(
                            &format!("{name} {how:?} x{workers} batch {batch:?} team {team:?}"),
                            &want,
                            &have,
                        );
                    }
                }
            }
        }
    }
    rarkit::probe::set_small_team(None);
    rarkit::probe::set_small_batch(None);
}

/// The DEFAULT shape, whatever this architecture ships (pairs
/// for `x` and `t` on aarch64; on x86-64 pairs for `t` everywhere and for
/// `x` on Linux only, its member team at most half the
/// hardware threads; none elsewhere), gives the sequential answer for `x`
/// and `t`. This is the test that runs each target's shipped shape.
#[test]
fn the_default_small_batch_gives_the_sequential_answer() {
    if std::env::var_os("RARKIT_SMALL_BATCH").is_some() {
        return;
    }
    let opts = ReadOptions::default();
    rarkit::probe::set_offload_floor(None);
    rarkit::probe::set_small_team(None);
    rarkit::probe::set_small_batch(None);
    for (name, volumes) in corpus() {
        for how in [How::Write, How::Verify] {
            let want = serial(volumes.clone(), &opts, how);
            for workers in WIDTHS {
                let have = wide(volumes.clone(), &opts, how, workers);
                same(&format!("{name} {how:?} x{workers} default"), &want, &have);
            }
        }
    }
}

/// Every member damaged: the error and verdicts reported are the
/// sequential path's, the earliest in archive order first, whichever batch
/// and worker finished first; and one damaged member keeps its neighbours.
#[test]
fn small_member_batches_report_the_first_failure_first() {
    rarkit::probe::set_offload_floor(None);
    let opts = ReadOptions::default();
    for name in ["r550_m3.rar", "r420_m5.rar", "d250_m3.rar"] {
        let clean = legacy(name);
        let archive = rarkit::Archive::open(Arc::new(clean.clone()) as Arc<dyn RangeSource>, &opts)
            .expect("open");
        let targets: Vec<std::ops::Range<u64>> = archive
            .members()
            .filter(|m| !m.is_directory && m.data.end - m.data.start >= 64)
            .map(|m| m.data.clone())
            .collect();
        drop(archive);
        assert!(targets.len() >= 2, "{name}: this test needs two members");
        let mut all = clean.clone();
        for data in &targets {
            all[(data.start + (data.end - data.start) / 2) as usize] ^= 0xff;
        }
        let mut one = clean.clone();
        let data = &targets[targets.len() / 2];
        one[(data.start + (data.end - data.start) / 2) as usize] ^= 0xff;
        for (what, bytes) in [("all damaged", all), ("one damaged", one)] {
            let volumes = vec![Arc::new(bytes) as Arc<dyn RangeSource>];
            let want = serial(volumes.clone(), &opts, How::Write);
            for batch in BATCHES {
                rarkit::probe::set_small_batch(Some(batch));
                for workers in WIDTHS {
                    let have = wide(volumes.clone(), &opts, How::Write, workers);
                    same(
                        &format!("{name} {what} x{workers} batch {batch:?}"),
                        &want,
                        &have,
                    );
                }
            }
        }
    }
    rarkit::probe::set_small_batch(None);
}

/// The outputs bound holds with batches on: a batch's members each hold an output,
/// and the caller never holds more than twice the breadth open at once.
#[test]
fn small_member_batches_keep_the_outputs_bound() {
    rarkit::probe::set_offload_floor(None);
    rarkit::probe::set_outputs_over_breadth(Some(2));
    for batch in BATCHES {
        rarkit::probe::set_small_batch(Some(batch));
        for (name, workers) in [
            ("r420_m5.rar", 4usize),
            ("r550_m3.rar", 2),
            ("r550_m3.rar", 1),
        ] {
            let sink = Counting::new(Duration::from_millis(100));
            extract_parallel(
                sources(legacy(name)),
                &ReadOptions::default(),
                &sink,
                workers,
            )
            .expect("parallel");
            let peak = sink.peak.load(Ordering::SeqCst);
            assert!(
                peak <= 2 * workers,
                "{name} batch {batch:?}: the caller held {peak} outputs open at \
                 once, above twice the {workers} workers it was given"
            );
        }
    }
    rarkit::probe::set_small_batch(None);
    rarkit::probe::set_outputs_over_breadth(None);
}

/// A cancel flag stops a batched run as it stops the rest.
#[test]
fn small_member_batches_stop_on_the_cancel_flag() {
    rarkit::probe::set_offload_floor(None);
    rarkit::probe::set_small_batch(Some((8, 64 << 10)));
    let flag = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let opts = ReadOptions::default().with_cancel(Some(Arc::clone(&flag)));
    let sink = Wide {
        how: How::Write,
        seen: Mutex::new(Vec::new()),
    };
    let err = extract_parallel(sources(legacy("r550_m3.rar")), &opts, &sink, 4)
        .expect_err("the flag was set before the walk began");
    rarkit::probe::set_small_batch(None);
    assert!(matches!(err.kind(), ErrorKind::Cancelled), "{err}");
}

/// The working limit binds a batched run as it binds one member at a time.
#[test]
fn small_member_batches_stay_inside_the_working_limit() {
    rarkit::probe::set_offload_floor(None);
    let bytes = legacy("r550_m3.rar");
    for batch in BATCHES {
        rarkit::probe::set_small_batch(Some(batch));
        // 2 MiB at the bottom: under this fixture's one-member floor (about
        // 1.25 MiB) a named budget is refused up front.
        for limit in [2u64 << 20, 8 << 20, 512 << 20] {
            let opts = ReadOptions::default()
                .with_memory(rarkit::MemoryPolicy::from_limit(limit))
                .with_workers(Some(8));
            let want = serial(sources(bytes.clone()), &opts, How::Write);
            let have = wide(sources(bytes.clone()), &opts, How::Write, 8);
            same(&format!("budget {limit} batch {batch:?}"), &want, &have);
            let sink = Wide {
                how: How::Write,
                seen: Mutex::new(Vec::new()),
            };
            let report =
                extract_parallel(sources(bytes.clone()), &opts, &sink, 8).expect("parallel");
            let ceiling = sequential_peak(&bytes, &opts).saturating_mul(8);
            assert!(
                report.peak_working_memory <= ceiling,
                "batch {batch:?} budget {limit}: {} of working memory, above \
                 {ceiling}",
                report.peak_working_memory
            );
        }
    }
    rarkit::probe::set_small_batch(None);
}
