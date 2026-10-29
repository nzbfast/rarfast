//! The sequential entry point DECODING AHEAD (`read::sequential`), held to
//! the sequential contract of SPEC-API 4.4 from outside.
//!
//! The strongest statement a test can make of "the contract is kept at the
//! interface" is that a caller cannot tell the difference: every call the
//! sink receives, in order, with its arguments, the bytes written, the
//! verdicts, the report and the operation's error are the SAME with the
//! look-ahead on as with it off. That is `every_call_the_sink_sees_is_the_
//! sequential_path_s`, over every fixture class the parallel tests use, at
//! several widths, byte ceilings, dispositions and early stops. The rest
//! hold what the trace cannot show: the bound, that the look-ahead was
//! actually used (non-vacuity), drop-behind, and the bytes against the
//! parallel path and the old engine.

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rarkit::{
    extract, extract_parallel, Disposition, MemberInfo, MemberOutcome, MemberSpec, ParallelSink,
    Payload, Progress, RangeSource, ReadOptions, Result, Sink, WriteMethod, WriteOptions, Writer,
};

fn file(dir: &str, name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(dir)
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn legacy(name: &str) -> Vec<u8> {
    file("fixtures/legacy/archives", name)
}

fn vectors(name: &str) -> Vec<u8> {
    file("specs/vectors-F/archives", name)
}

fn one(bytes: Vec<u8>) -> Vec<Arc<dyn RangeSource>> {
    vec![Arc::new(bytes) as Arc<dyn RangeSource>]
}

fn set(volumes: Vec<Vec<u8>>) -> Vec<Arc<dyn RangeSource>> {
    volumes
        .into_iter()
        .map(|v| Arc::new(v) as Arc<dyn RangeSource>)
        .collect()
}

/// An archive this crate writes: `members` compressed members of about
/// `size` bytes, a directory and an empty member among them, as ONE
/// archive or as a volume set of `volume` bytes a volume.
fn written(members: usize, size: usize, volume: Option<u64>) -> Vec<Vec<u8>> {
    written_with(members, size, volume, false)
}

/// [`written`], SOLID when asked: every member continues the window the one
/// before it left.
fn written_with(members: usize, size: usize, volume: Option<u64>, solid: bool) -> Vec<Vec<u8>> {
    let options = WriteOptions {
        solid,
        // The solid default dictionary (10 Oct 2026) is not this file's
        // subject: its archives keep the 2 MiB window they were written
        // for. `solid_default_dictionary` holds the default.
        solid_dictionary_2mib: true,
        // Ordering is not what this test is about: keep the add order.
        order: rarkit::MemberOrder::AsAdded,
        method: WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
        volume_file_size: volume,
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    };
    let mut list: Vec<(String, Vec<u8>, bool)> = Vec::new();
    for k in 0..members {
        if k == members / 3 {
            list.push((format!("d{k}"), Vec::new(), true));
            list.push((format!("d{k}/empty"), Vec::new(), false));
        }
        let len = size + (k * 977) % (size / 2 + 1);
        list.push((
            format!("m{k:03}.txt"),
            // Text of 4,096 words, which packs to about half, so that
            // the first member's packed bytes run past the archive's
            // first 8 KiB, where the read rows below look.
            rarkit_testdata::chatter_of(k as u64, 1 << 12, len),
            false,
        ));
    }
    let mut writer = Writer::new(options).expect("options");
    for (name, data, dir) in &list {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(data),
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: *dir,
            })
            .expect("add");
    }
    if volume.is_none() {
        let mut one = Vec::new();
        writer.finish_into(&mut one).expect("finish");
        return vec![one];
    }
    let mut out: Vec<Vec<u8>> = Vec::new();
    writer.finish_volumes(&mut out).expect("finish");
    out
}

/// An archive of compressed members of exactly these sizes, in order, no
/// directory among them.
fn written_sizes(sizes: &[usize]) -> Vec<Vec<u8>> {
    let options = WriteOptions {
        method: WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    };
    let list: Vec<(String, Vec<u8>)> = sizes
        .iter()
        .enumerate()
        .map(|(k, &len)| {
            (
                format!("s{k:03}.txt"),
                rarkit_testdata::chatter((1000 + k as u32) as u64, len),
            )
        })
        .collect();
    let mut writer = Writer::new(options).expect("options");
    for (name, data) in &list {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(data),
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut one = Vec::new();
    writer.finish_into(&mut one).expect("finish");
    vec![one]
}

/// Every archive the trace comparison runs over.
fn corpus() -> Vec<(&'static str, Vec<Arc<dyn RangeSource>>)> {
    vec![
        ("f01_stored.rar", one(vectors("f01_stored.rar"))),
        ("f03_m3.rar", one(vectors("f03_m3.rar"))),
        ("f05_blake.rar", one(vectors("f05_blake.rar"))),
        ("r550_m3.rar", one(legacy("r550_m3.rar"))),
        ("r550_m0.rar", one(legacy("r550_m0.rar"))),
        ("r550_md.rar", one(legacy("r550_md.rar"))),
        ("f02_dirs.rar", one(vectors("f02_dirs.rar"))),
        ("f04_solid.rar", one(vectors("f04_solid.rar"))),
        ("r420_solid.rar", one(legacy("r420_solid.rar"))),
        ("d250_sol.rar", one(legacy("d250_sol.rar"))),
        ("r420_m5.rar", one(legacy("r420_m5.rar"))),
        ("d250_m3.rar", one(legacy("d250_m3.rar"))),
        ("d155_m3.rar", one(legacy("d155_m3.rar"))),
        ("d140_m0.rar", one(legacy("d140_m0.rar"))),
        (
            "f11_svol",
            set(vec![
                vectors("f11_svol.part1.rar"),
                vectors("f11_svol.part2.rar"),
                vectors("f11_svol.part3.rar"),
                vectors("f11_svol.part4.rar"),
            ]),
        ),
        (
            "f12_cvol",
            set(vec![
                vectors("f12_cvol.part1.rar"),
                vectors("f12_cvol.part2.rar"),
                vectors("f12_cvol.part3.rar"),
                vectors("f12_cvol.part4.rar"),
            ]),
        ),
        ("f15_bad_data_crc.rar", one(vectors("f15_bad_data_crc.rar"))),
        ("f13_truncated.rar", one(vectors("f13_truncated.rar"))),
        ("written_24", set(written(24, 24_000, None))),
        ("written_vols", set(written(24, 24_000, Some(120_000)))),
    ]
}

// ---------------------------------------------------------------------------
// The recording sink
// ---------------------------------------------------------------------------

/// One call a sink received.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Call {
    Open(Vec<u8>, String),
    /// `close`: the name, the bytes the writer received (or `None` when
    /// `close` was handed no writer), the verdict and the byte count.
    Close(Vec<u8>, Option<Vec<u8>>, Option<bool>, u64),
}

/// What a sink does with each member, by its index among the `open`s.
#[derive(Clone, Copy, Debug)]
struct Plan {
    /// Every `k`th member is skipped (0: none).
    skip_every: usize,
    /// Every `k`th member is verified rather than written (0: none).
    verify_every: usize,
    /// The `open` at this index returns an error.
    fail_open: Option<usize>,
    /// The writer of the member at this index refuses its first write.
    fail_write: Option<usize>,
    /// The `close` at this index returns an error.
    fail_close: Option<usize>,
}

const PLAIN: Plan = Plan {
    skip_every: 0,
    verify_every: 0,
    fail_open: None,
    fail_write: None,
    fail_close: None,
};

struct Out {
    bytes: Vec<u8>,
    refuse: bool,
}

impl Write for Out {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.refuse {
            return Err(std::io::Error::other("this writer refuses"));
        }
        self.bytes.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Trace {
    plan: Plan,
    opens: usize,
    closes: usize,
    calls: Vec<Call>,
}

impl Sink for Trace {
    type Out = Out;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Out>> {
        let at = self.opens;
        self.opens += 1;
        let hit = |every: usize| every > 0 && at % every == every - 1;
        let (d, label) = if member.is_directory || hit(self.plan.skip_every) {
            (Disposition::Skip, "skip")
        } else if hit(self.plan.verify_every) {
            (Disposition::Verify, "verify")
        } else {
            (
                Disposition::Write(Out {
                    bytes: Vec::new(),
                    refuse: self.plan.fail_write == Some(at),
                }),
                "write",
            )
        };
        self.calls
            .push(Call::Open(member.name.to_vec(), label.into()));
        if self.plan.fail_open == Some(at) {
            return Err(rarkit::Error::caller(std::io::Error::other("open refused")));
        }
        Ok(d)
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Out>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        let at = self.closes;
        self.closes += 1;
        self.calls.push(Call::Close(
            member.name.to_vec(),
            out.map(|o| o.bytes),
            outcome.checksum_ok,
            outcome.bytes,
        ));
        if self.plan.fail_close == Some(at) {
            return Err(rarkit::Error::caller(std::io::Error::other(
                "close refused",
            )));
        }
        Ok(())
    }
}

/// Everything a caller can see of one extraction.
#[derive(Debug, PartialEq, Eq)]
struct Seen {
    calls: Vec<Call>,
    report: Option<(u64, u64, u64)>,
    error: Option<String>,
}

fn run(
    volumes: &[Arc<dyn RangeSource>],
    opts: &ReadOptions,
    plan: Plan,
    ahead: bool,
    ceiling: Option<u64>,
) -> Seen {
    rarkit::probe::set_seq_ahead(Some(ahead));
    rarkit::probe::set_seq_ahead_bytes(ceiling);
    let mut sink = Trace {
        plan,
        opens: 0,
        closes: 0,
        calls: Vec::new(),
    };
    let outcome = extract(volumes.to_vec(), opts, &mut sink, &mut ());
    rarkit::probe::set_seq_ahead(None);
    rarkit::probe::set_seq_ahead_bytes(None);
    let (report, error) = match outcome {
        Ok(r) => (Some((r.members, r.bytes, r.checksum_failures)), None),
        Err(e) => (None, Some(format!("{:?}", e.kind()))),
    };
    Seen {
        calls: sink.calls,
        report,
        error,
    }
}

fn same(label: &str, want: &Seen, have: &Seen) {
    for (at, (a, b)) in want.calls.iter().zip(&have.calls).enumerate() {
        assert_eq!(a, b, "{label}: call {at} differs");
    }
    assert_eq!(
        want.calls.len(),
        have.calls.len(),
        "{label}: a different number of calls\n  sequential {:?}\n  ahead {:?}",
        want.calls.len(),
        have.calls.len()
    );
    assert_eq!(want.report, have.report, "{label}: the report");
    assert_eq!(want.error, have.error, "{label}: the operation's error");
}

fn widths() -> Vec<ReadOptions> {
    [2usize, 3, 8]
        .into_iter()
        .map(|w| ReadOptions::default().with_workers(Some(w)))
        .collect()
}

// ---------------------------------------------------------------------------
// The contract
// ---------------------------------------------------------------------------

/// SPEC-API 4.4, whole: the look-ahead changes nothing a sink can see.
#[test]
fn every_call_the_sink_sees_is_the_sequential_path_s() {
    let plans = [
        PLAIN,
        Plan {
            skip_every: 3,
            ..PLAIN
        },
        Plan {
            verify_every: 2,
            ..PLAIN
        },
    ];
    // Both floors: at zero every independent member goes to a worker; at
    // the engine's own figure these fixtures' members are mostly walked
    // into the look-ahead instead, or not taken at all.
    for floor in [Some(0), None] {
        rarkit::probe::set_offload_floor(floor);
        for (name, volumes) in corpus() {
            for opts in widths() {
                for plan in plans {
                    let want = run(&volumes, &opts, plan, false, None);
                    for ceiling in [None, Some(0), Some(64 * 1024), Some(1)] {
                        let have = run(&volumes, &opts, plan, true, ceiling);
                        same(
                            &format!(
                                "{name} width {:?} {plan:?} ceiling {ceiling:?} floor {floor:?}",
                                opts.workers
                            ),
                            &want,
                            &have,
                        );
                    }
                }
            }
        }
    }
    rarkit::probe::set_offload_floor(None);
}

/// THE TWO PHASES of one walk: members that cannot go ahead run under the
/// sequential path's own driver, and the walk hands the rest of the archive
/// to the look-ahead at the first member that can, held unopened. What the
/// sink sees is the sequential path's whatever the member the walk hands
/// off at, including a failure there and after it; the look-ahead is used
/// after the hand-off, never built for an archive with no such member, and
/// never used for a caller that skipped a member before it.
#[test]
fn the_walk_hands_off_at_the_first_member_that_can_go_ahead() {
    rarkit::probe::set_offload_floor(None);
    // Small members staying on the walk, as they did before they could go
    // ahead: `small_members_go_ahead_and_the_sink_cannot_tell` holds the
    // other arm.
    rarkit::probe::set_seq_small(Some(false));
    // 30 compressed members under the engine's floor, then 12 over it.
    let mut sizes = vec![2_000usize; 30];
    sizes.extend(std::iter::repeat_n(40_000usize, 12));
    let mixed = set(written_sizes(&sizes));
    let small = set(written_sizes(&[2_000usize; 40]));
    let plans = [
        PLAIN,
        Plan {
            verify_every: 4,
            ..PLAIN
        },
        Plan {
            fail_open: Some(30),
            ..PLAIN
        },
        Plan {
            fail_close: Some(29),
            ..PLAIN
        },
        Plan {
            fail_write: Some(33),
            ..PLAIN
        },
    ];
    for opts in widths() {
        for plan in plans {
            let want = run(&mixed, &opts, plan, false, None);
            let have = run(&mixed, &opts, plan, true, None);
            same(
                &format!("mixed width {:?} {plan:?}", opts.workers),
                &want,
                &have,
            );
        }
        rarkit::probe::reset_seq_ahead_peak();
        let want = run(&mixed, &opts, PLAIN, false, None);
        rarkit::probe::reset_seq_ahead_peak();
        let have = run(&mixed, &opts, PLAIN, true, None);
        same("mixed, plain", &want, &have);
        let taken = rarkit::probe::seq_ahead_taken();
        assert!(
            taken >= 6,
            "width {:?}: only {taken} members went ahead after the hand-off",
            opts.workers
        );
        rarkit::probe::reset_seq_ahead_peak();
        let want = run(&small, &opts, PLAIN, false, None);
        let have = run(&small, &opts, PLAIN, true, None);
        same("small", &want, &have);
        assert_eq!(
            rarkit::probe::seq_ahead_taken(),
            0,
            "no member of the small archive can go ahead"
        );
        let selecting = Plan {
            skip_every: 7,
            ..PLAIN
        };
        rarkit::probe::reset_seq_ahead_peak();
        let want = run(&mixed, &opts, selecting, false, None);
        let have = run(&mixed, &opts, selecting, true, None);
        same("mixed, selecting", &want, &have);
        assert_eq!(
            rarkit::probe::seq_ahead_taken(),
            0,
            "a caller that skipped a member before the hand-off is selecting"
        );
    }
    rarkit::probe::set_seq_small(None);
}

/// SMALL COMPRESSED MEMBERS GO AHEAD (`RARKIT_SEQ_SMALL`): a member under
/// the offload floor goes to a worker, one a task, where it used to be
/// decoded on the walking thread alone, and the sink cannot tell: every
/// call, byte, verdict, report and error is the sequential path's, for a
/// plain, verifying, selecting and failing caller, at every width. They
/// are taken (the test is not vacuous), and with the knob off none of an
/// archive of small members is.
#[test]
fn small_members_go_ahead_and_the_sink_cannot_tell() {
    rarkit::probe::set_offload_floor(None);
    let small = set(written_sizes(&[2_000usize; 40]));
    // Small, then large, then small again: the hand-off at the first
    // member, and small members behind large ones in flight.
    let mut sizes = vec![2_000usize; 30];
    sizes.extend(std::iter::repeat_n(40_000usize, 12));
    sizes.extend(std::iter::repeat_n(1_000usize, 10));
    let mixed = set(written_sizes(&sizes));
    let plans = [
        PLAIN,
        Plan {
            verify_every: 3,
            ..PLAIN
        },
        Plan {
            skip_every: 7,
            ..PLAIN
        },
        Plan {
            fail_open: Some(5),
            ..PLAIN
        },
        Plan {
            fail_close: Some(12),
            ..PLAIN
        },
        Plan {
            fail_write: Some(20),
            ..PLAIN
        },
    ];
    for opts in widths() {
        for (name, volumes, members) in [("small", &small, 40u64), ("mixed", &mixed, 52)] {
            rarkit::probe::set_seq_small(Some(true));
            for plan in plans {
                let want = run(volumes, &opts, plan, false, None);
                let have = run(volumes, &opts, plan, true, None);
                same(
                    &format!("{name} width {:?} {plan:?}", opts.workers),
                    &want,
                    &have,
                );
            }
            rarkit::probe::reset_seq_ahead_peak();
            let _ = run(volumes, &opts, PLAIN, true, None);
            assert_eq!(
                rarkit::probe::seq_ahead_taken(),
                members,
                "{name} width {:?}: every member went ahead",
                opts.workers
            );
            rarkit::probe::set_seq_small(Some(false));
            rarkit::probe::reset_seq_ahead_peak();
            let _ = run(volumes, &opts, PLAIN, true, None);
            if name == "small" {
                assert_eq!(
                    rarkit::probe::seq_ahead_taken(),
                    0,
                    "with the knob off no small member goes ahead"
                );
            }
        }
    }
    rarkit::probe::set_seq_small(None);
}

/// A caller that stops the run - from `open`, from its writer, from
/// `close` - stops it at the same member, with the same calls before it
/// and the same error, as on the sequential path.
#[test]
fn a_caller_that_stops_early_stops_it_at_the_same_member() {
    rarkit::probe::set_offload_floor(Some(0));
    let archives = [
        ("r550_m3.rar", one(legacy("r550_m3.rar"))),
        ("written_24", set(written(24, 24_000, None))),
        ("written_vols", set(written(24, 24_000, Some(120_000)))),
    ];
    for (name, volumes) in archives {
        for at in [0usize, 1, 4, 11] {
            for plan in [
                Plan {
                    fail_open: Some(at),
                    ..PLAIN
                },
                Plan {
                    fail_write: Some(at),
                    ..PLAIN
                },
                Plan {
                    fail_close: Some(at),
                    ..PLAIN
                },
            ] {
                for opts in widths() {
                    let want = run(&volumes, &opts, plan, false, None);
                    let have = run(&volumes, &opts, plan, true, None);
                    same(
                        &format!("{name} {plan:?} width {:?}", opts.workers),
                        &want,
                        &have,
                    );
                }
            }
        }
    }
    rarkit::probe::set_offload_floor(None);
}

/// A damaged member in the middle of the stream: its neighbours are
/// delivered, it is reported through its own `close`, and the operation's
/// error is the sequential path's.
#[test]
fn a_damaged_member_mid_stream_keeps_its_neighbours() {
    rarkit::probe::set_offload_floor(Some(0));
    let mut volumes = written(24, 24_000, None).remove(0);
    // Damage the packed bytes of a member in the middle, well inside the
    // archive and away from any header: a byte flipped every 97 bytes over
    // a window in the second half.
    let from = volumes.len() / 2;
    for k in (from..from + 4_000).step_by(97) {
        volumes[k] ^= 0x5a;
    }
    let volumes = one(volumes);
    let opts = ReadOptions::default().with_workers(Some(4));
    let want = run(&volumes, &opts, PLAIN, false, None);
    let have = run(&volumes, &opts, PLAIN, true, None);
    same("damaged", &want, &have);
    let failed = want
        .calls
        .iter()
        .filter(|c| matches!(c, Call::Close(_, _, Some(false), _)))
        .count();
    let passed = want
        .calls
        .iter()
        .filter(|c| matches!(c, Call::Close(_, _, Some(true), _)))
        .count();
    assert!(
        failed >= 1,
        "the damage reached no member: the test is vacuous"
    );
    assert!(
        passed >= 2,
        "the damage took every member: nothing was delivered around it"
    );
    rarkit::probe::set_offload_floor(None);
}

/// A solid archive has no independent member, so nothing goes ahead and the
/// path is the one it always was.
#[test]
fn a_solid_chain_takes_nothing_ahead() {
    rarkit::probe::set_offload_floor(Some(0));
    for name in ["r420_solid.rar", "d250_sol.rar"] {
        let volumes = one(legacy(name));
        let opts = ReadOptions::default().with_workers(Some(4));
        rarkit::probe::reset_seq_ahead_peak();
        let want = run(&volumes, &opts, PLAIN, false, None);
        let have = run(&volumes, &opts, PLAIN, true, None);
        same(name, &want, &have);
        assert_eq!(
            rarkit::probe::seq_ahead_taken(),
            0,
            "{name}: a solid member went ahead"
        );
    }
    let volumes = one(vectors("f04_solid.rar"));
    let opts = ReadOptions::default().with_workers(Some(4));
    rarkit::probe::reset_seq_ahead_peak();
    same(
        "f04_solid.rar",
        &run(&volumes, &opts, PLAIN, false, None),
        &run(&volumes, &opts, PLAIN, true, None),
    );
    assert_eq!(
        rarkit::probe::seq_ahead_taken(),
        0,
        "f04: a solid member went ahead"
    );
    rarkit::probe::set_offload_floor(None);
}

// ---------------------------------------------------------------------------
// The bound
// ---------------------------------------------------------------------------

/// The look-ahead never holds more than twice the breadth in members, nor
/// more declared bytes than its ceiling, and it is USED: a bound nothing
/// ever reached would pass this vacuously.
#[test]
fn the_look_ahead_never_holds_more_than_its_bound() {
    rarkit::probe::set_offload_floor(Some(0));
    let volumes = set(written(40, 24_000, None));
    for width in [2usize, 3, 4] {
        for ceiling in [100_000u64, 250_000, 0] {
            let opts = ReadOptions::default().with_workers(Some(width));
            rarkit::probe::reset_seq_ahead_peak();
            let want = run(&volumes, &opts, PLAIN, false, None);
            let have = run(&volumes, &opts, PLAIN, true, Some(ceiling));
            same(&format!("width {width} ceiling {ceiling}"), &want, &have);
            let members = rarkit::probe::peak_seq_ahead_members();
            let bytes = rarkit::probe::peak_seq_ahead_bytes();
            let taken = rarkit::probe::seq_ahead_taken();
            assert!(
                taken >= 20,
                "width {width}: only {taken} members went ahead"
            );
            assert!(
                members <= 2 * width,
                "width {width}: {members} members in the look-ahead at once"
            );
            if ceiling > 0 {
                assert!(
                    bytes <= ceiling,
                    "width {width}: {bytes} bytes in a look-ahead of {ceiling}"
                );
            }
            // Non-vacuous: the look-ahead held more than one member at a
            // time, and at the tight ceiling it was the BYTES that bound.
            assert!(members >= 2, "width {width}: the look-ahead never held two");
            if ceiling == 100_000 {
                assert!(
                    bytes > ceiling / 2,
                    "width {width}: the byte ceiling was never approached ({bytes})"
                );
            }
        }
    }
    rarkit::probe::set_offload_floor(None);
}

/// A sink whose writer does not take the FIRST member's first bytes until
/// the look-ahead has run as far ahead of it as it is going to: until a
/// worker waits at the gate, or the look-ahead holds `until` bytes. A
/// later member is taken as it comes: the archive's later members are
/// smaller than `until`, and behind the first no worker is left to wait.
struct Waiting {
    until: u64,
    /// What the look-ahead held, and the workers waiting, when each
    /// member's first bytes were taken: the first member's after a wait of
    /// two minutes at most, which fails the test if it runs out.
    seen: Vec<(u64, usize)>,
    got: Vec<(Vec<u8>, Option<bool>, u64)>,
}

struct WaitingOut {
    /// The figure this member's first bytes wait for, or none.
    until: Option<u64>,
    seen: Option<(u64, usize)>,
    bytes: Vec<u8>,
}

impl Write for WaitingOut {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.seen.is_none() {
            let end = std::time::Instant::now() + std::time::Duration::from_secs(120);
            let live = loop {
                let live = rarkit::probe::seq_ahead_live();
                let Some(until) = self.until else {
                    break live;
                };
                if live.1 > 0 || live.0 >= until {
                    break live;
                }
                // A wait that runs out is a failure and never a pass: six
                // of them were twelve minutes of a green test.
                assert!(
                    std::time::Instant::now() <= end,
                    "after two minutes the look-ahead holds {} bytes of {until} and no worker waits",
                    live.0
                );
                std::thread::sleep(std::time::Duration::from_millis(2));
            };
            self.seen = Some(live);
        }
        self.bytes.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Sink for Waiting {
    type Out = WaitingOut;

    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<WaitingOut>> {
        Ok(Disposition::Write(WaitingOut {
            // Members open in order, each after the one before it closed.
            until: self.seen.is_empty().then_some(self.until),
            seen: None,
            bytes: Vec::new(),
        }))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<WaitingOut>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        let out = out.expect("a written member closes with its writer");
        self.seen.push(out.seen.unwrap_or((0, 0)));
        self.got
            .push((out.bytes, outcome.checksum_ok, outcome.bytes));
        Ok(())
    }
}

/// The workers decode no further ahead of the caller's writer than the
/// gate's window and a floor a slot, where without the gate the member in
/// front of a writer that does not take it is decoded whole into memory.
///
/// Nothing here is timed: the writer WAITS for the look-ahead to stop
/// (a worker at the gate) or to pass a figure, so a slow or loaded
/// machine changes how long the test takes and not what it reads.
///
/// Assumes read widths of 3 and of 18 (stated below; at 18 no more than
/// two worker threads ever start, one a member that goes ahead), and the
/// default memory policy, whose working limit is far above the 15 MiB the
/// archive unpacks to: with the gate off, only the writer bounds what is
/// held.
#[test]
fn the_workers_wait_for_the_writer() {
    const MIB: u64 = 1 << 20;
    rarkit::probe::set_offload_floor(Some(0));
    // A member that streams from the front of the look-ahead, and two
    // behind it that keep it from being the last of its volume (a megabyte
    // of text packs to more than the tail a last member may have).
    let volumes = set(written_sizes(&[14 << 20, 1 << 20, 4096]));
    let narrow = ReadOptions::default().with_workers(Some(3));
    let run = |opts: &ReadOptions, hold: u64, until: u64| {
        rarkit::probe::set_seq_ahead(Some(true));
        rarkit::probe::set_seq_ahead_hold(Some(hold));
        rarkit::probe::set_seq_ahead_hold_packed(Some(true));
        rarkit::probe::reset_seq_ahead_peak();
        let mut sink = Waiting {
            until,
            seen: Vec::new(),
            got: Vec::new(),
        };
        let report = extract(volumes.to_vec(), opts, &mut sink, &mut ()).expect("extract");
        rarkit::probe::set_seq_ahead(None);
        rarkit::probe::set_seq_ahead_hold(None);
        rarkit::probe::set_seq_ahead_hold_packed(None);
        assert_eq!(report.members, 3);
        assert!(rarkit::probe::seq_ahead_taken() >= 1, "nothing went ahead");
        (sink.got, sink.seen, rarkit::probe::peak_seq_ahead_held())
    };
    // No gate, and a writer that takes nothing until 12 MiB are held: the
    // worker decodes the member in front of it that far, unasked.
    let (want, seen, loose) = run(&narrow, 0, 12 * MIB);
    assert!(want.iter().all(|m| m.1 == Some(true)));
    assert_eq!(seen[0].1, 0, "a worker waited with no gate");
    assert!(
        seen[0].0 >= 12 * MIB && loose >= 12 * MIB,
        "with no gate the look-ahead held {} bytes, {loose} at most",
        seen[0].0
    );
    // The gate at 2 MiB, and the same writer: the worker stops and waits.
    // What is held of the first member is the window or the slot's four
    // chunks, whichever is more, and the chunk the worker and the walk
    // may each push past it: 6 MiB, and a quiet machine reads exactly
    // that. The two members behind it are each under a slot's floor, so
    // no gate holds their workers, and whatever of them is decoded before
    // the writer moves is held on top: under load 6 MiB and the last
    // member's 4096 bytes were read 3 times in 600 (9 Oct 2026).
    let small = (1 << 20) + 4096;
    let (gated, seen, held) = run(&narrow, 2 * MIB, 12 * MIB);
    assert_eq!(gated, want, "the gate changed what the sink was given");
    assert_eq!(seen[0].1, 1, "no worker waited at the gate");
    assert!(
        seen[0].0 <= 6 * MIB + small && held <= 6 * MIB + small,
        "under a 2 MiB window the look-ahead held {} bytes, {held} at most",
        seen[0].0
    );
    // At a width with cores to decode a second member beside the first,
    // the look-ahead is as it was: nothing is held back, whatever the
    // window. (Two workers at most ever start: one a member that goes
    // ahead.)
    let wide = ReadOptions::default().with_workers(Some(18));
    let (free, seen, loose) = run(&wide, 2 * MIB, 12 * MIB);
    assert_eq!(free, want, "the width changed what the sink was given");
    assert_eq!(seen[0].1, 0, "a worker waited at a width of 18");
    assert!(
        seen[0].0 >= 12 * MIB && loose >= 12 * MIB,
        "at a width of 18 the look-ahead held {} bytes, {loose} at most",
        seen[0].0
    );
    rarkit::probe::set_offload_floor(None);
}

/// A caller's memory budget binds the look-ahead: the report's working
/// memory stays inside it where the sequential path's does.
#[test]
fn the_working_limit_binds_the_look_ahead() {
    rarkit::probe::set_offload_floor(Some(0));
    let volumes = set(written(40, 24_000, None));
    let mut opts = ReadOptions::default().with_workers(Some(4));
    // 8 MiB: under the one-member floor a named budget leaves the look-ahead only the
    // members whose windows fit above the walk's own floor, and at 2 MiB
    // no worker's 1 MiB floor ring does, so nothing would go ahead.
    opts.memory = rarkit::MemoryPolicy::from_limit(8 << 20);
    rarkit::probe::reset_seq_ahead_peak();
    let want = run(&volumes, &opts, PLAIN, false, None);
    let have = run(&volumes, &opts, PLAIN, true, None);
    same("limit 8 MiB", &want, &have);
    assert!(rarkit::probe::seq_ahead_taken() > 0, "nothing went ahead");
    assert!(
        rarkit::probe::peak_seq_ahead_bytes() <= 8 << 20,
        "the look-ahead passed the caller's budget"
    );
    rarkit::probe::set_offload_floor(None);
}

// ---------------------------------------------------------------------------
// Drop-behind and volume order
// ---------------------------------------------------------------------------

/// One event, stamped from one clock shared by the sources and the
/// observer, so the order of reads against releases is a fact.
#[derive(Debug, Clone)]
enum Event {
    Read(u32, u64),
    Released(u32, u64),
    Done(u32),
    Asked(u32),
}

struct Log(Mutex<Vec<(u64, Event)>>, AtomicU64);

impl Log {
    fn note(&self, e: Event) {
        let t = self.1.fetch_add(1, Ordering::SeqCst);
        self.0.lock().unwrap().push((t, e));
    }
}

struct Watched {
    bytes: Vec<u8>,
    volume: u32,
    log: Arc<Log>,
}

impl RangeSource for Watched {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        self.log.note(Event::Read(self.volume, offset));
        self.bytes.read_at(offset, buf)
    }
    fn available(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn len(&self) -> Option<u64> {
        Some(self.bytes.len() as u64)
    }
}

struct Observer(Arc<Log>);

impl Progress for Observer {
    fn released(&mut self, volume: u32, offset: u64) -> Result<()> {
        self.0.note(Event::Released(volume, offset));
        Ok(())
    }
    fn volume_done(&mut self, volume: u32) -> Result<()> {
        self.0.note(Event::Done(volume));
        Ok(())
    }
}

/// SPEC-API 4.4's drop-behind and 5.3's volume order, with workers reading
/// behind the walk: no byte is read below an offset already released, no
/// volume is read after its `volume_done`, and volume `k + 1` is asked for
/// only after the last read of volume `k`.
#[test]
fn drop_behind_holds_with_workers_reading_behind_the_walk() {
    rarkit::probe::set_offload_floor(Some(0));
    rarkit::probe::set_seq_ahead(Some(true));
    let raw = written(30, 24_000, Some(40_000));
    assert!(raw.len() >= 3, "the set has {} volumes", raw.len());
    let log = Arc::new(Log(Mutex::new(Vec::new()), AtomicU64::new(0)));
    let sources: Vec<Arc<dyn RangeSource>> = raw
        .iter()
        .enumerate()
        .map(|(i, b)| {
            Arc::new(Watched {
                bytes: b.clone(),
                volume: i as u32,
                log: Arc::clone(&log),
            }) as Arc<dyn RangeSource>
        })
        .collect();
    let mut provider = {
        let log = Arc::clone(&log);
        move |index: u32| -> Result<Option<Arc<dyn RangeSource>>> {
            log.note(Event::Asked(index));
            Ok(sources.get(index as usize).cloned())
        }
    };
    let mut sink = Trace {
        plan: PLAIN,
        opens: 0,
        closes: 0,
        calls: Vec::new(),
    };
    rarkit::probe::reset_seq_ahead_peak();
    let opts = ReadOptions::default().with_workers(Some(4));
    extract(
        &mut provider,
        &opts,
        &mut sink,
        &mut Observer(Arc::clone(&log)),
    )
    .expect("the set extracts");
    rarkit::probe::set_seq_ahead(None);
    rarkit::probe::set_offload_floor(None);
    assert!(
        rarkit::probe::seq_ahead_taken() >= 10,
        "the look-ahead was not used"
    );

    let mut events = log.0.lock().unwrap().clone();
    events.sort_by_key(|e| e.0);
    let mut released: std::collections::HashMap<u32, u64> = Default::default();
    let mut done: std::collections::HashSet<u32> = Default::default();
    let mut asked: std::collections::HashSet<u32> = Default::default();
    for (t, e) in &events {
        match *e {
            Event::Read(v, at) => {
                assert!(
                    !done.contains(&v),
                    "t{t}: volume {v} read after its volume_done"
                );
                assert!(
                    !asked.contains(&(v + 1)),
                    "t{t}: volume {v} read after volume {} was asked for",
                    v + 1
                );
                let floor = released.get(&v).copied().unwrap_or(0);
                assert!(
                    at >= floor,
                    "t{t}: volume {v} read at {at}, below its released {floor}"
                );
            }
            Event::Released(v, at) => {
                let before = released.insert(v, at).unwrap_or(0);
                assert!(at > before, "t{t}: released went {before} to {at} on {v}");
            }
            Event::Done(v) => {
                done.insert(v);
            }
            Event::Asked(v) => {
                asked.insert(v);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The bytes, against the parallel path and the old engine
// ---------------------------------------------------------------------------

struct Wide(Mutex<Vec<(Vec<u8>, Vec<u8>)>>);

impl ParallelSink for Wide {
    type Out = Vec<u8>;
    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Vec::new()))
    }
    fn close(&self, m: &MemberInfo<'_>, out: Option<Vec<u8>>, _: &MemberOutcome) -> Result<()> {
        if let Some(out) = out {
            self.0.lock().unwrap().push((m.name.to_vec(), out));
        }
        Ok(())
    }
}

#[test]
fn the_bytes_are_the_parallel_path_s_and_the_old_engine_s() {
    rarkit::probe::set_offload_floor(Some(0));
    let classes: Vec<(&str, Vec<Vec<u8>>)> = vec![
        ("r550_m3.rar", vec![legacy("r550_m3.rar")]),
        ("r550_m0.rar", vec![legacy("r550_m0.rar")]),
        ("r550_md.rar", vec![legacy("r550_md.rar")]),
        ("r420_m5.rar", vec![legacy("r420_m5.rar")]),
        ("d250_m3.rar", vec![legacy("d250_m3.rar")]),
        ("d155_m3.rar", vec![legacy("d155_m3.rar")]),
        ("f05_blake.rar", vec![vectors("f05_blake.rar")]),
        ("written_24", written(24, 24_000, None)),
        ("written_vols", written(24, 24_000, Some(120_000))),
    ];
    for (name, raw) in classes {
        let volumes = set(raw.clone());
        let opts = ReadOptions::default().with_workers(Some(4));
        let ahead = run(&volumes, &opts, PLAIN, true, None);
        assert!(ahead.error.is_none(), "{name}: {:?}", ahead.error);
        let got: Vec<(Vec<u8>, Vec<u8>)> = ahead
            .calls
            .iter()
            .filter_map(|c| match c {
                Call::Close(n, Some(b), _, _) => Some((n.clone(), b.clone())),
                _ => None,
            })
            .collect();
        let wide = Wide(Mutex::new(Vec::new()));
        extract_parallel(volumes.clone(), &opts, &wide, 4).expect("parallel");
        assert_eq!(
            got,
            wide.0.into_inner().unwrap(),
            "{name}: against the parallel path"
        );
        #[cfg(feature = "oracle-compare")]
        {
            let borrowed: Vec<&[u8]> = raw.iter().map(Vec::as_slice).collect();
            let old: Vec<(Vec<u8>, Vec<u8>)> = rarkit_oracle::extract(&borrowed, None)
                .unwrap_or_else(|e| panic!("{name}: the oracle: {e}"))
                .into_iter()
                .filter(|m| !m.is_directory)
                // rarkit forward-slashes every name (SPEC-API `MemberInfo::name`);
                // the old engine hands some formats' separators back as stored.
                .map(|m| {
                    let name = m
                        .name
                        .iter()
                        .map(|&c| if c == b'\\' { b'/' } else { c })
                        .collect();
                    (name, m.data)
                })
                .collect();
            assert_eq!(
                got.len(),
                old.len(),
                "{name}: member count against the old engine"
            );
            for ((n, b), (on, ob)) in got.iter().zip(&old) {
                assert_eq!(n, on, "{name}: member order against the old engine");
                assert!(
                    b == ob,
                    "{name}: {} differs from the old engine",
                    String::from_utf8_lossy(n)
                );
            }
        }
    }
    rarkit::probe::set_offload_floor(None);
}

// ---------------------------------------------------------------------------
// The solid path: the walk on a worker, the caller's thread delivering
// ---------------------------------------------------------------------------

fn run_solid(
    volumes: &[Arc<dyn RangeSource>],
    opts: &ReadOptions,
    plan: Plan,
    solid_ahead: bool,
) -> Seen {
    rarkit::probe::set_solid_ahead(Some(solid_ahead));
    let seen = run(volumes, &file_sink(opts), plan, true, None);
    rarkit::probe::set_solid_ahead(None);
    seen
}

/// The options with the caller's writer declared a FILE: the solid path is
/// taken only for such a caller (`ReadOptions::sink_is_file`).
fn file_sink(opts: &ReadOptions) -> ReadOptions {
    let mut opts = opts.clone();
    opts.sink_is_file = Some(true);
    opts
}

fn solid_corpus() -> Vec<(&'static str, Vec<Arc<dyn RangeSource>>)> {
    vec![
        ("f04_solid.rar", one(vectors("f04_solid.rar"))),
        ("r420_solid.rar", one(legacy("r420_solid.rar"))),
        ("d250_sol.rar", one(legacy("d250_sol.rar"))),
        ("d155_sol.rar", one(legacy("d155_sol.rar"))),
        ("d140_sol.rar", one(legacy("d140_sol.rar"))),
        ("r393_solid.rar", one(legacy("r393_solid.rar"))),
        ("r550_solid.rar", one(legacy("r550_solid.rar"))),
        ("written_solid", set(written_with(30, 40_000, None, true))),
        (
            "written_solid_vols",
            set(written_with(30, 40_000, Some(60_000), true)),
        ),
        // A NON-solid archive under the knob: the peek says no, and the
        // decode-ahead path runs exactly as before.
        ("r550_m3.rar", one(legacy("r550_m3.rar"))),
    ]
}

/// SPEC-API 4.4, whole, on a solid archive: with the walk on a worker, the
/// sink sees exactly the calls, bytes, verdicts, report and error the
/// sequential path gives it.
#[test]
fn a_solid_archive_walked_on_a_worker_gives_the_sequential_answer() {
    let plans = [
        PLAIN,
        Plan {
            skip_every: 3,
            ..PLAIN
        },
        Plan {
            verify_every: 2,
            ..PLAIN
        },
        Plan {
            fail_open: Some(4),
            ..PLAIN
        },
        Plan {
            fail_write: Some(5),
            ..PLAIN
        },
        Plan {
            fail_close: Some(6),
            ..PLAIN
        },
    ];
    for (name, volumes) in solid_corpus() {
        for opts in widths() {
            for plan in plans {
                // The control is the sequential path with NOTHING ahead,
                // told the same about its writer.
                let want = run(&volumes, &file_sink(&opts), plan, false, None);
                let have = run_solid(&volumes, &opts, plan, true);
                same(
                    &format!("{name} width {:?} {plan:?}", opts.workers),
                    &want,
                    &have,
                );
            }
        }
    }
}

/// The path is TAKEN for a solid archive and not for any other, and the
/// buffers between the two threads stay inside its budget: a quarter of
/// the caller's working limit, at most 128 MiB, never less than two chunks.
#[test]
fn the_solid_walk_is_taken_and_its_budget_holds() {
    let volumes = set(written_with(40, 200_000, None, true));
    for limit in [4u64 << 20, 64 << 20] {
        let mut opts = ReadOptions::default().with_workers(Some(4));
        opts.memory = rarkit::MemoryPolicy::from_limit(limit);
        rarkit::probe::reset_solid_ahead_seen();
        let want = run(&volumes, &file_sink(&opts), PLAIN, false, None);
        let have = run_solid(&volumes, &opts, PLAIN, true);
        same(&format!("limit {limit}"), &want, &have);
        let (taken, peak) = rarkit::probe::solid_ahead_seen();
        assert_eq!(taken, 1, "limit {limit}: the solid path was not taken");
        let cap = solid_queue_cap(limit);
        assert!(peak > 0, "limit {limit}: nothing passed through the budget");
        assert!(
            peak <= cap,
            "limit {limit}: {peak} bytes in a budget of {cap}"
        );
    }
    // An in-memory writer (no `sink_is_file`) never takes the path, solid
    // or not.
    rarkit::probe::reset_solid_ahead_seen();
    rarkit::probe::set_solid_ahead(Some(true));
    let _ = run(
        &volumes,
        &ReadOptions::default().with_workers(Some(4)),
        PLAIN,
        true,
        None,
    );
    rarkit::probe::set_solid_ahead(None);
    assert_eq!(
        rarkit::probe::solid_ahead_seen().0,
        0,
        "an in-memory writer went down the solid path"
    );
    let plain = one(legacy("r550_m3.rar"));
    rarkit::probe::reset_solid_ahead_seen();
    let _ = run_solid(
        &plain,
        &ReadOptions::default().with_workers(Some(4)),
        PLAIN,
        true,
    );
    assert_eq!(
        rarkit::probe::solid_ahead_seen().0,
        0,
        "a non-solid archive went down the solid path"
    );
}

/// The solid path's queue budget for an engine working limit of `limit`
/// (`read::sequential::solid_queue_cap`).
fn solid_queue_cap(limit: u64) -> u64 {
    (limit / 4).clamp(2 << 20, 128 << 20)
}

/// A sink that is SLOW to start: its first `open` waits, so the walk runs
/// ahead of the caller's thread and fills the queue between them, as a
/// real file system's creates and closes make it do.
struct Slow {
    stall: bool,
    bytes: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Sink for Slow {
    type Out = Vec<u8>;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        if std::mem::take(&mut self.stall) {
            std::thread::sleep(std::time::Duration::from_millis(2000));
        }
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        _: &MemberOutcome,
    ) -> Result<()> {
        if let Some(out) = out {
            self.bytes.push((member.name.to_vec(), out));
        }
        Ok(())
    }
}

/// THE QUEUE IS CHARGED BY CAPACITY. A chain of SMALL
/// members behind a slow caller: the walk queues member after member, and
/// what it holds is the capacity of the buffers they are queued in, not the
/// few bytes each carries. It was charged by the bytes, each queued member
/// holding a whole 1 MiB chunk, so `rarfast x` of 8,568 system binaries
/// held 786 MiB of footprint; and a chunk taken at every member's end was
/// dropped with its charge never given back.
///
/// Held here: the pool's capacity alive stays within the budget and the
/// two buffers either side of it, the queue actually fills (non-vacuity),
/// every buffer comes back by the end, and the bytes are the sequential
/// path's.
#[test]
fn the_solid_queue_is_charged_by_capacity() {
    // 300 members of 30 to 45 KB: 32 and 64 KiB buffers, about 14 MiB of
    // them in all, against a queue budget of 4 MiB.
    let volumes = set(written_with(300, 30_000, None, true));
    let limit = 16u64 << 20;
    let cap = solid_queue_cap(limit);
    let mut opts = file_sink(&ReadOptions::default().with_workers(Some(4)));
    opts.memory = rarkit::MemoryPolicy::from_limit(limit);

    let mut want = Slow {
        stall: false,
        bytes: Vec::new(),
    };
    rarkit::probe::set_solid_ahead(Some(false));
    extract(volumes.clone(), &opts, &mut want, &mut ()).expect("the sequential path");
    rarkit::probe::reset_solid_ahead_seen();
    rarkit::probe::set_solid_ahead(Some(true));
    let mut have = Slow {
        stall: true,
        bytes: Vec::new(),
    };
    let outcome = extract(volumes, &opts, &mut have, &mut ());
    rarkit::probe::set_solid_ahead(None);
    outcome.expect("the solid path");
    assert!(
        want.bytes == have.bytes,
        "the bytes differ from the sequential path's"
    );

    let (taken, budget_peak) = rarkit::probe::solid_ahead_seen();
    let (alive, out_at_end) = rarkit::probe::solid_pool_seen();
    assert_eq!(taken, 1, "the solid path was not taken");
    assert!(
        budget_peak <= cap,
        "the queue held {budget_peak} bytes of capacity in a budget of {cap}"
    );
    assert!(
        budget_peak > cap / 2,
        "the queue reached only {budget_peak} of {cap}: the test is vacuous"
    );
    assert!(
        alive <= cap + (2 << 20),
        "the pool held {alive} bytes alive against a budget of {cap}"
    );
    assert_eq!(out_at_end, 0, "buffers still charged after the extraction");
}

/// A damaged member in the middle of a solid chain: the members before it
/// are delivered, and what follows is the sequential path's, call for call.
#[test]
fn a_damaged_solid_chain_fails_where_the_sequential_path_fails() {
    let mut bytes = written_with(30, 40_000, None, true).remove(0);
    let from = bytes.len() / 2;
    for k in (from..from + 2_000).step_by(97) {
        bytes[k] ^= 0x5a;
    }
    let volumes = one(bytes);
    let opts = ReadOptions::default().with_workers(Some(4));
    let want = run(&volumes, &file_sink(&opts), PLAIN, false, None);
    let have = run_solid(&volumes, &opts, PLAIN, true);
    same("damaged solid", &want, &have);
    assert!(
        want.calls
            .iter()
            .any(|c| matches!(c, Call::Close(_, _, Some(true), _))),
        "nothing was delivered before the damage: the test is vacuous"
    );
}

/// A source that records every range read from it.
struct Ranges {
    bytes: Vec<u8>,
    reads: Mutex<Vec<(u64, u64)>>,
}

impl RangeSource for Ranges {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.bytes.read_at(offset, buf)?;
        self.reads.lock().unwrap().push((offset, offset + n as u64));
        Ok(n)
    }
    fn available(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn len(&self) -> Option<u64> {
        Some(self.bytes.len() as u64)
    }
}

/// SPEC-API promise 5 on the solid path. The peek at volume 0's main
/// header reads nothing the walk reads again: no range at the front of the
/// archive is read twice (the sequential path's own detect and header reads
/// overlap there, and the peek's kept bytes serve both). And the solid path
/// reads no more of the source than the sequential path does, within 2
/// percent: the chain's look-ahead reads ahead of the walk on BOTH paths,
/// which is the sequential path's own and not this change's.
#[test]
fn the_solid_path_reads_no_more_than_the_sequential_path() {
    for (name, raw) in [
        (
            "written_solid",
            written_with(30, 40_000, None, true).remove(0),
        ),
        ("r420_solid.rar", legacy("r420_solid.rar")),
    ] {
        let mut totals = Vec::new();
        for on in [false, true] {
            let src = Arc::new(Ranges {
                bytes: raw.clone(),
                reads: Mutex::new(Vec::new()),
            });
            rarkit::probe::reset_solid_ahead_seen();
            let seen = run_solid(
                &[Arc::clone(&src) as Arc<dyn RangeSource>],
                &ReadOptions::default().with_workers(Some(4)),
                PLAIN,
                on,
            );
            assert!(seen.error.is_none(), "{name}: {:?}", seen.error);
            assert_eq!(
                rarkit::probe::solid_ahead_seen().0,
                u64::from(on),
                "{name}: the path taken"
            );
            let mut reads = src.reads.lock().unwrap().clone();
            reads.sort();
            if on {
                for pair in reads.windows(2) {
                    assert!(
                        pair[1].0 >= pair[0].1 || pair[1].0 >= 8192,
                        "{name}: the front of the archive read twice: {:?} then {:?}",
                        pair[0],
                        pair[1]
                    );
                }
            }
            totals.push(reads.iter().map(|r| r.1 - r.0).sum::<u64>());
        }
        assert!(
            totals[1] * 100 <= totals[0] * 102,
            "{name}: the solid path read {} bytes against the sequential path's {}",
            totals[1],
            totals[0]
        );
    }
}

/// The caller's `Progress` and `Sink` writing one log, so a test can see
/// which the caller heard first.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Heard {
    Output(u64),
    Released,
    Close(Vec<u8>, u64),
}

struct Logged(Arc<Mutex<Vec<Heard>>>);

impl Progress for Logged {
    fn released(&mut self, _volume: u32, _offset: u64) -> Result<()> {
        self.0.lock().unwrap().push(Heard::Released);
        Ok(())
    }

    fn output(&mut self, total: u64) -> Result<()> {
        self.0.lock().unwrap().push(Heard::Output(total));
        Ok(())
    }
}

struct Collect {
    log: Arc<Mutex<Vec<Heard>>>,
    got: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Sink for Collect {
    type Out = Vec<u8>;

    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        assert_eq!(outcome.checksum_ok, Some(true), "a member's checksum");
        self.log
            .lock()
            .unwrap()
            .push(Heard::Close(member.name.to_vec(), outcome.bytes));
        self.got
            .push((member.name.to_vec(), out.unwrap_or_default()));
        Ok(())
    }
}

/// A solid member whose walk makes MORE PROGRESS NOTES THAN THE QUEUE TO
/// THE CALLER'S THREAD HOLDS, and the extraction still finishes.
///
/// The walk ticks `Progress::output` once per MiB of a member's bytes. The
/// caller's thread used to read the queue those notes went into only
/// between members, so inside one long enough to fill it both threads slept
/// for ever: `rarfast x` on a solid `-m3 -md16m` set of four 1 GiB members
/// stopped 8 MiB short of the first member's end with the queue at its
/// 1024 (found 27 Sep 2026, reproduced on
/// an M3 Mac). Here the queue holds TWO notes and each member makes about
/// eight, the same geometry at a size a test affords; a watchdog turns a
/// stall into a failure rather than a hung run.
#[test]
fn a_solid_member_longer_than_the_progress_queue_does_not_stall() {
    const MIB: usize = 1 << 20;
    let sizes = [8 * MIB + 12_345, 8 * MIB + 777, 3_000];
    let options = WriteOptions {
        solid: true,
        // The solid default dictionary (10 Oct 2026) is not this file's
        // subject: its archives keep the 2 MiB window they were written
        // for. `solid_default_dictionary` holds the default.
        solid_dictionary_2mib: true,
        method: WriteMethod::Compressed {
            level: 1,
            dictionary: None,
        },
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    };
    let members: Vec<(String, Vec<u8>)> = sizes
        .iter()
        .enumerate()
        .map(|(k, &len)| {
            (
                format!("long{k}.bin"),
                rarkit_testdata::chatter((77 + k as u32) as u64, len),
            )
        })
        .collect();
    let mut writer = Writer::new(options).expect("options");
    for (name, data) in &members {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(data),
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut archive = Vec::new();
    writer.finish_into(&mut archive).expect("finish");
    let volumes = one(archive);

    let (done_tx, done) = std::sync::mpsc::channel();
    // The probes are per thread, so the extraction sets them on its own.
    std::thread::spawn(move || {
        rarkit::probe::set_solid_ahead(Some(true));
        rarkit::probe::set_solid_queue_depth(Some(2));
        rarkit::probe::reset_solid_ahead_seen();
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut sink = Collect {
            log: Arc::clone(&log),
            got: Vec::new(),
        };
        let mut progress = Logged(Arc::clone(&log));
        let opts = file_sink(&ReadOptions::default().with_workers(Some(4)));
        let outcome = extract(volumes, &opts, &mut sink, &mut progress)
            .map(|r| (r.members, r.bytes, r.checksum_failures));
        let taken = rarkit::probe::solid_ahead_seen().0;
        rarkit::probe::set_solid_queue_depth(None);
        rarkit::probe::set_solid_ahead(None);
        let heard = log.lock().unwrap().clone();
        let _ = done_tx.send((outcome, taken, sink.got, heard));
    });
    let (outcome, taken, got, heard) = done
        .recv_timeout(std::time::Duration::from_secs(120))
        .expect("the solid extraction STALLED: nothing for 120 s");

    let total: u64 = sizes.iter().map(|&n| n as u64).sum();
    assert_eq!(outcome.expect("the extraction"), (3, total, 0));
    assert_eq!(
        taken, 1,
        "the solid path was not taken: the test is vacuous"
    );
    assert_eq!(got.len(), members.len());
    for ((name, data), (got_name, got_data)) in members.iter().zip(&got) {
        assert_eq!(name.as_bytes(), &got_name[..]);
        assert!(data == got_data, "{name}: the bytes differ");
    }
    let outputs: Vec<u64> = heard
        .iter()
        .filter_map(|h| match h {
            Heard::Output(t) => Some(*t),
            _ => None,
        })
        .collect();
    assert!(
        outputs.len() > 2 * 2,
        "only {} output notes: the queue was never outrun",
        outputs.len()
    );
    assert!(
        outputs.windows(2).all(|w| w[0] < w[1]),
        "output totals out of order: {outputs:?}"
    );
    // Heard WHILE the member was being delivered, not in a burst after it.
    let first_close = heard
        .iter()
        .position(|h| matches!(h, Heard::Close(..)))
        .expect("a close");
    let before = heard[..first_close]
        .iter()
        .filter(|h| matches!(h, Heard::Output(_)))
        .count();
    assert!(
        before >= 4,
        "{before} output notes before the first member closed: {heard:?}"
    );
}
