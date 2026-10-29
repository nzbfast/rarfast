//! What the SEGMENT TEAM and the large-member lane's REACH hold, at the
//! floor: the process default of a machine whose budget is the 512 MiB
//! every machine's default is at least (`MemoryPolicy::process_default`
//! on under 2 GiB of memory, built here from its own terms, since the
//! test runs on whatever the box has).
//!
//! Both spend memory for wall where no ceiling was named, and both are
//! admitted against the policy's `working_limit` (spec G 3.7.3's default
//! mode): the segment team as many engines as the limit affords beside
//! what the run holds, the lane the reach that costs least. Held here:
//! the writer's STATED peak (`WriteReport::peak_working_memory`) stays
//! inside the working limit with each of them on, the engines and crews
//! admitted are stated, and the archive is the one written with neither.
//! The process's own figure (peak RSS, the footprint on macOS) is taken
//! on the boxes (1 Oct 2026).
//!
//! And both with a PASSWORD, data only and headers too: under a seeded
//! entropy the archive is the one-engine archive byte for byte, it reads
//! back through rarkit under the password, and reference `unrar` (where
//! the box has one) tests it and extracts the same bytes.
use std::io::Cursor;
use std::sync::Arc;

use rarkit::internals::writers::{
    reset_segment_rounds, segment_rounds, team_large, with_lane_reach, with_segment_width,
    with_team_cores,
};
use rarkit::{
    extract, Disposition, Entropy, FilterPolicy, MemberInfo, MemberOutcome, MemberSpec,
    MemoryPolicy, Password, Payload, RangeSource, ReadOptions, Sink, WriteFormat, WriteMethod,
    WriteOptions, WriteReport, Writer,
};

/// Text with a quarter of noise in every 64 KiB, so a member packs to
/// about half.
fn member(len: usize, seed: u64) -> Vec<u8> {
    let mut out = rarkit_testdata::chatter(seed, len);
    let noise = rarkit_testdata::scramble(seed, len);
    for (block, fill) in out.chunks_mut(64 << 10).zip(noise.chunks(64 << 10)) {
        let from = block.len() * 3 / 4;
        block[from..].copy_from_slice(&fill[from..]);
    }
    out
}

/// The process default at the floor: `process_default`'s policy with the
/// working limit a machine of under 2 GiB gets, which is the 512 MiB
/// budget less the process's own headroom. An allowance, not a named
/// ceiling, as the default is.
fn floor() -> MemoryPolicy {
    let mut policy = MemoryPolicy::process_default(0);
    policy.working_limit = MemoryPolicy::for_process(MemoryPolicy::DEFAULT_LIMIT, 0).working_limit;
    assert!(!policy.limit_named, "the default names no ceiling");
    policy
}

fn options(level: u8, password: Option<&str>) -> WriteOptions {
    WriteOptions {
        format: WriteFormat::Rar5,
        method: WriteMethod::Compressed {
            level,
            dictionary: None,
        },
        filters: FilterPolicy::Detect,
        host_os: rarkit::HostOs::Unix,
        order: rarkit::MemberOrder::AsAdded,
        workers: Some(8),
        password: password.map(Password::new),
        memory: floor(),
        // Seeded, so an encrypted archive is the same bytes on every run
        // and at every width.
        entropy: Entropy::Seeded([9; 32]),
        ..WriteOptions::default()
    }
}

/// Every member through a reader to an output that can seek.
fn write(options: WriteOptions, members: &[&[u8]]) -> (Vec<u8>, WriteReport) {
    reset_segment_rounds();
    let names: Vec<String> = (0..members.len()).map(|i| format!("m{i}.bin")).collect();
    let mut readers: Vec<Cursor<&[u8]>> = members.iter().map(|m| Cursor::new(*m)).collect();
    let mut writer = Writer::new(options).expect("options");
    for ((name, reader), data) in names.iter().zip(readers.iter_mut()).zip(members) {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Reader {
                    reader,
                    size: <[u8]>::len(data) as u64,
                    crc32: None,
                },
                mtime: None,
                attributes: 0o644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = Cursor::new(Vec::new());
    let report = writer.finish_seek(&mut out).expect("finish");
    (out.into_inner(), report)
}

#[derive(Default)]
struct Collect(Vec<Vec<u8>>);

impl Sink for Collect {
    type Out = Vec<u8>;

    fn open(&mut self, _member: &MemberInfo<'_>) -> rarkit::Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> rarkit::Result<()> {
        assert_eq!(
            outcome.checksum_ok,
            Some(true),
            "a member failed its checksum"
        );
        self.0.push(out.unwrap_or_default());
        Ok(())
    }
}

fn reads_back(what: &str, archive: &[u8], members: &[&[u8]], password: Option<&str>) {
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(archive.to_vec())];
    let mut sink = Collect::default();
    let options = ReadOptions::default().with_password(password.map(Password::new));
    extract(sources, &options, &mut sink, &mut ()).unwrap_or_else(|e| panic!("{what}: {e}"));
    assert!(
        sink.0.iter().map(Vec::as_slice).eq(members.iter().copied()),
        "{what}: the archive reads back as its members"
    );
}

const MIB: u64 = 1 << 20;

/// The width of the pool the tests here run on. The writer fits its team
/// and its lane to the pool it is called from (the pool's width, held to
/// the encoder's), so a test that left the pool to the machine asserted
/// the machine: the lane has at most one crew fewer than the pool is wide,
/// and under three threads there is no lane at all. Nine is the fewest
/// that gives a crew to each of the eight members
/// `one_batch_of_the_reach_is_stated_once` writes, and no wider than that:
/// what the pool holds is real memory on the machine that runs this. The
/// segment team's test states pools of its own ([`TEAM_POOLS`]).
const POOL: usize = 9;

/// `work` on a thread of a pool of [`POOL`] threads, whatever the machine.
/// The hooks a body sets and the lane it reads back are the calling
/// thread's, so a body runs whole on that one thread; and a fresh pool is
/// a thread of its own, for a write whose lane must not be the one before
/// it.
fn pooled<T: Send>(work: impl FnOnce() -> T + Send) -> T {
    pooled_at(POOL, work)
}

/// [`pooled`] on a pool of `width` threads.
fn pooled_at<T: Send>(width: usize, work: impl FnOnce() -> T + Send) -> T {
    rayon::ThreadPoolBuilder::new()
        .num_threads(width)
        .build()
        .expect("a pool")
        .install(work)
}

/// The pools the segment team's test runs on, each stated and none the
/// machine's own. Eight workers are named on every one (`options`), so the
/// team is fitted to eight threads throughout and what moves with the pool
/// is what the run's own engine is reserved, whose parses in flight are
/// the pool's wave. Sixteen is the width this test was red on while it
/// read the machine's pool (a Linux host of 16 threads, 7 Oct 2026), and
/// the others stand either side of it.
///
/// No pool under eight: the test names 64 cores (below), and a pool of
/// four or six threads on 64 cores is a state no shipped build reaches,
/// since the rule by cores reads the pool's own width and gives a pool
/// under sixteen no team at any level (`segment_engines`). Counted in that
/// state on the same host: at level 1 three engines stated 488 to 492 MiB
/// of 480 on a pool of six, which is the run's own engine, reserved from
/// level 3 only. That is the engine's to settle and is not held here.
///
/// Memory: one member of 120 MiB and its archives are held beside a
/// writer that states at most the 480 MiB working limit, on six pools one
/// after another, and what one pool's threads held is not all given back
/// before the next: the process of this test alone stood at 1,055 MiB
/// resident on the Linux host and at a footprint of 2,047 MiB on macOS
/// (an Apple M5 Max of 18 threads).
const TEAM_POOLS: [usize; 6] = [8, 12, 16, 18, 24, 32];

#[test]
fn the_segment_team_at_the_floor_stays_inside_the_working_limit() {
    // One member of several stretches (18 MiB, then 16 MiB each at the
    // shipped dictionary): the pool would run eight engines, and the 512
    // MiB floor says how many of them there are, and at level 3 whether
    // there is a team at all.
    let data = member(120 << 20, 41);
    // The one engine's archive at each level on the first pool: every
    // pool's archive is that one, so the width chose no byte.
    let mut first: [Option<Vec<u8>>; 2] = [None, None];
    for pool in TEAM_POOLS {
        let archives = pooled_at(pool, || {
            the_segment_team_at_the_floor_stays_inside_the_working_limit_on_the_pool(&data)
        });
        for (slot, archive) in first.iter_mut().zip(archives) {
            match slot {
                Some(kept) => assert!(
                    *kept == archive,
                    "a pool of {pool} threads moved a byte of the one engine's archive"
                ),
                None => *slot = Some(archive),
            }
        }
    }
}

/// The body of the test above on the pool it is called from; the one
/// engine's archive at level 1 and at level 3.
fn the_segment_team_at_the_floor_stays_inside_the_working_limit_on_the_pool(
    data: &[u8],
) -> [Vec<u8>; 2] {
    let limit = floor().working_limit;
    let pool = rayon::current_num_threads();
    [1u8, 3].map(|level| {
        let what = format!("-m{level}, one 120 MiB member at the floor, a pool of {pool} threads");
        let (one, alone) = with_segment_width(1, || write(options(level, None), &[data]));
        // Many cores named, so the rule by cores leaves the width to the
        // pool and the memory, which is what is held here.
        let (archive, report) = with_team_cores(64, || write(options(level, None), &[data]));
        let (rounds, engines) = segment_rounds();
        assert!(
            report.peak_working_memory <= limit,
            "{what}: {engines} engines stated {} MiB of a working limit of {} MiB",
            report.peak_working_memory / MIB,
            limit / MIB
        );
        // Level 1 keeps every engine the limit affords, and the floor
        // affords a team there. From level 3 the limit must also hold the
        // run's own engine, and at levels 2 and 3 a team it affords fewer
        // than three engines (two from an 8 MiB window) is the one
        // engine's walk (spec G 3.7.3), since two engines lose to one.
        // This member at level 3, counted on a 96 thread box (2 Oct 2026,
        // the floor's row): the four engines the parent admitted stood at
        // a process of 580 to 591 MiB and were killed 5 of 5 under a 512
        // MiB cgroup cap; the walk lives at 337 MiB and is 1.03x of them.
        //
        // WHETHER THERE IS A TEAM AT LEVEL 3 IS NOT ONE ANSWER, and this
        // test read it as one while it ran on the machine's own pool: "no
        // team from eight threads". That was the row of the systems it was
        // counted on. What the limit affords is what is left of the
        // team's ceiling beside the run's own engine. On macOS the ceiling
        // is the working limit less the 128 MiB that system holds beside
        // the writer, 352 MiB at the floor, which affords two engines on
        // every pool here: no team. Elsewhere the ceiling is the limit
        // whole, and it affords the third engine: counted on a Linux host
        // of 16 threads (x86-64, 7 Oct 2026) on pools of 8 to 32, three
        // engines stating 282 to 292 MiB of 480, in a process of 348 to
        // 359 MiB that lived 17 of 17 under a 512 MiB cgroup cap (and was
        // killed 2 of 2 under one of 200 MiB). On 96 threads the run's own
        // engine is reserved more and two are afforded again.
        //
        // So what is held at level 3 is the rule and not a system's row:
        // no team, or a team of no fewer than three engines. The working
        // limit and the bytes are held on every pool.
        let teamed = level == 1;
        assert!(
            if teamed {
                rounds > 0 && (2..=8).contains(&engines)
            } else {
                rounds == 0 || (3..=8).contains(&engines)
            },
            "{what}: {rounds} rounds of at most {engines} engines (one engine stated {} MiB, \
             the team {} MiB, of {} MiB)",
            alone.peak_working_memory / MIB,
            report.peak_working_memory / MIB,
            limit / MIB
        );
        assert!(archive == one, "{what}: the team moved a byte");
        println!(
            "{what}: {engines} engines admitted, stated peak {} MiB against {} MiB for one engine, \
             working limit {} MiB",
            report.peak_working_memory / MIB,
            alone.peak_working_memory / MIB,
            limit / MIB
        );
        one
    })
}

#[test]
fn the_lanes_reach_at_the_floor_stays_inside_the_working_limit() {
    pooled(the_lanes_reach_at_the_floor_stays_inside_the_working_limit_on_the_pool);
}

fn the_lanes_reach_at_the_floor_stays_inside_the_working_limit_on_the_pool() {
    // Sixteen members of 5 to 9 MiB between small ones: each is past one
    // window, so without the reach the writing thread encodes them one at
    // a time.
    let limit = floor().working_limit;
    let mut set: Vec<Vec<u8>> = Vec::new();
    for i in 0..16u64 {
        set.push(member(60_000 + i as usize * 5_003, 50 + i));
        set.push(member((5 << 20) + i as usize * (256 << 10), 70 + i));
    }
    let members: Vec<&[u8]> = set.iter().map(Vec::as_slice).collect();
    for level in [1u8, 3] {
        let what = format!("-m{level}, sixteen members of 5 to 9 MiB at the floor");
        let (none, without) = with_segment_width(1, || {
            with_lane_reach(0, || write(options(level, None), &members))
        });
        let (archive, report) = with_team_cores(64, || {
            with_segment_width(1, || write(options(level, None), &members))
        });
        let (crews, reach) = team_large();
        assert!(
            report.peak_working_memory <= limit,
            "{what}: {crews} large crews reaching {} MiB stated {} MiB of a working limit of {} MiB",
            reach / MIB,
            report.peak_working_memory / MIB,
            limit / MIB
        );
        assert!(archive == none, "{what}: the reach moved a byte");
        println!(
            "{what}: {crews} large crews admitted at a reach of {} MiB, stated peak {} MiB against \
             {} MiB without the reach, working limit {} MiB",
            reach / MIB,
            report.peak_working_memory / MIB,
            without.peak_working_memory / MIB,
            limit / MIB
        );
    }
}

/// The process default of a machine whose budget is `budget` bytes: the
/// working limit `process_default` gives it, an allowance and not a named
/// ceiling.
fn budget_of(budget: u64) -> MemoryPolicy {
    let mut policy = MemoryPolicy::process_default(0);
    policy.working_limit = MemoryPolicy::for_process(budget, 0).working_limit;
    assert!(!policy.limit_named, "the default names no ceiling");
    policy
}

#[test]
fn the_lanes_reach_stays_inside_budgets_of_one_two_and_four_gib() {
    pooled(the_lanes_reach_stays_inside_budgets_of_one_two_and_four_gib_on_the_pool);
}

fn the_lanes_reach_stays_inside_budgets_of_one_two_and_four_gib_on_the_pool() {
    // The floor is not the only budget the lane must fit: where memory
    // affords MORE crews a batch is larger, and what the writer states of
    // a round must still count each buffer once. Until 1 Oct 2026 the
    // round's sum stated the batch's pulled buffer and the batch written
    // in the round twice each, which the floor's small batches hid: on a
    // 4 GiB set of binaries under a 2 GiB budget the writer stated 2,191
    // MiB of a working limit of 1,991 while it held 1,820
    // (`one_batch_of_the_reach_is_stated_once` is the row that fails on
    // that sum; these read the limit at each budget).
    //
    // Twenty-four members of 22 to 25 MiB (two bodies cut at different
    // lengths) on a pool of 32: a crew's five buffers of its largest
    // member are most of what it is charged, so the crews are bound by
    // memory, a batch holds a member for each, and what they hold is
    // close under the limit.
    let bodies: Vec<Vec<u8>> = (0..2u64).map(|i| member(25 << 20, 90 + i)).collect();
    let members: Vec<&[u8]> = (0..24usize)
        .map(|i| &bodies[i % 2][..(22 << 20) + (i % 12) * (256 << 10)])
        .collect();
    let rows: [(u64, u8); 3] = [(1 << 30, 1), (2 << 30, 1), (4 << 30, 1)];
    for (budget, level) in rows {
        let policy = budget_of(budget);
        let limit = policy.working_limit;
        let what = format!(
            "-m{level}, twenty-four members of 22 to 25 MiB under a budget of {} GiB",
            budget >> 30
        );
        let (_, report) = with_team_cores(64, || {
            with_segment_width(1, || {
                write(
                    WriteOptions {
                        method: WriteMethod::Compressed {
                            level,
                            dictionary: Some(256 << 10),
                        },
                        workers: Some(32),
                        memory: policy,
                        ..options(level, None)
                    },
                    &members,
                )
            })
        });
        let (crews, reach) = team_large();
        assert!(crews >= 2, "{what}: {crews} large crews");
        println!(
            "{what}: {crews} large crews admitted at a reach of {} MiB, stated peak {} MiB, \
             working limit {} MiB",
            reach / MIB,
            report.peak_working_memory / MIB,
            limit / MIB
        );
        assert!(
            report.peak_working_memory <= limit,
            "{what}: {crews} large crews reaching {} MiB stated {} MiB of a working limit of {} MiB",
            reach / MIB,
            report.peak_working_memory / MIB,
            limit / MIB
        );
    }
}

#[test]
fn one_batch_of_the_reach_is_stated_once() {
    pooled(one_batch_of_the_reach_is_stated_once_on_the_pool);
}

fn one_batch_of_the_reach_is_stated_once_on_the_pool() {
    // Eight members of 24 MiB under a budget that affords a crew each:
    // ONE batch, so what the team holds of it is its pulled input and its
    // packed buffers, each the input's length and a little, and the crews.
    // The sum that stated the pulled buffer twice read a whole input
    // higher.
    let bodies: Vec<Vec<u8>> = (0..2u64).map(|i| member(24 << 20, 60 + i)).collect();
    let members: Vec<&[u8]> = (0..8usize).map(|i| bodies[i % 2].as_slice()).collect();
    let input: u64 = members.iter().map(|m| <[u8]>::len(m) as u64).sum();
    let wide = || WriteOptions {
        method: WriteMethod::Compressed {
            level: 1,
            dictionary: Some(256 << 10),
        },
        workers: Some(32),
        memory: budget_of(4 << 30),
        ..options(1, None)
    };
    let (none, without) = with_segment_width(1, || with_lane_reach(0, || write(wide(), &members)));
    let (archive, report) =
        with_team_cores(64, || with_segment_width(1, || write(wide(), &members)));
    let (crews, reach) = team_large();
    println!(
        "one batch of {} MiB: {crews} large crews at a reach of {} MiB stated {} MiB, {} MiB \
         without the reach",
        input / MIB,
        reach / MIB,
        report.peak_working_memory / MIB,
        without.peak_working_memory / MIB
    );
    assert_eq!(crews, 8, "a crew for each member of the one batch");
    assert!(archive == none, "the reach moved a byte");
    // The pulled input, the packed buffers and the crews' structures,
    // none of them more than the input's length, beside what the write
    // states with no reach: 566 MiB of the 611 allowed, and 759 where the
    // pulled buffer was stated twice.
    let most = without.peak_working_memory + 3 * input;
    assert!(
        report.peak_working_memory <= most,
        "one batch of {} MiB stated {} MiB, more than its input, its packed buffers and its \
         crews ({} MiB): a buffer is stated twice",
        input / MIB,
        report.peak_working_memory / MIB,
        most / MIB
    );
}

/// Twelve members of 2 to 7.5 MiB between small ones: each is past one
/// window of the shipped 2 MiB dictionary and inside the 8 MiB an 8-core
/// pool reaches.
fn narrow_reach_set() -> Vec<Vec<u8>> {
    let mut set: Vec<Vec<u8>> = Vec::new();
    for i in 0..12u64 {
        set.push(member(60_000 + i as usize * 5_003, 150 + i));
        set.push(member(
            (2 << 20) + 8_192 + i as usize * (512 << 10),
            170 + i,
        ));
    }
    set
}

#[test]
fn the_narrow_pools_reach_stays_inside_the_floor_and_three_budgets() {
    pooled(the_narrow_pools_reach_stays_inside_the_floor_and_three_budgets_on_the_pool);
}

fn the_narrow_pools_reach_stays_inside_the_floor_and_three_budgets_on_the_pool() {
    // The reach of a pool of 8 to 15 cores at levels 2 and 3 (8 MiB on
    // every architecture): a large crew is charged its
    // structures and five buffers of its largest member, and what the
    // writer states stays inside the working limit at the 512 MiB floor
    // and at budgets of 1, 2 and 4 GiB, with the archive no reach writes.
    // Eight cores named, eight workers, the writer's own rule.
    let set = narrow_reach_set();
    let members: Vec<&[u8]> = set.iter().map(Vec::as_slice).collect();
    let policies: [(&str, MemoryPolicy); 4] = [
        ("the 512 MiB floor", floor()),
        ("a budget of 1 GiB", budget_of(1 << 30)),
        ("a budget of 2 GiB", budget_of(2 << 30)),
        ("a budget of 4 GiB", budget_of(4 << 30)),
    ];
    for level in [2u8, 3] {
        let (none, _) = with_segment_width(1, || {
            with_lane_reach(0, || write(options(level, None), &members))
        });
        for (name, policy) in policies {
            let limit = policy.working_limit;
            let what = format!("-m{level}, twelve members of 2 to 7.5 MiB on 8 cores at {name}");
            let with = |reach: Option<u64>| {
                let options = WriteOptions {
                    memory: policy,
                    ..options(level, None)
                };
                pooled(|| {
                    with_team_cores(8, || {
                        with_segment_width(1, || match reach {
                            Some(bytes) => {
                                with_lane_reach(bytes, || (write(options, &members), (0, 0)))
                            }
                            None => {
                                let out = write(options, &members);
                                (out, team_large())
                            }
                        })
                    })
                })
            };
            let ((_, without), _) = with(Some(0));
            let ((archive, report), (crews, reach)) = with(None);
            println!(
                "{what}: {crews} large crews admitted at a reach of {} MiB, stated peak {} MiB \
                 against {} MiB without the reach, working limit {} MiB",
                reach / MIB,
                report.peak_working_memory / MIB,
                without.peak_working_memory / MIB,
                limit / MIB
            );
            assert!(
                report.peak_working_memory <= limit,
                "{what}: {crews} large crews reaching {} MiB stated {} MiB of a working limit of {} MiB",
                reach / MIB,
                report.peak_working_memory / MIB,
                limit / MIB
            );
            assert!(archive == none, "{what}: the reach moved a byte");
            if policy.working_limit >= 3 << 30 {
                assert!(
                    crews > 0 && reach == 8 << 20,
                    "{what}: {crews} large crews reaching {reach}"
                );
            }
        }
    }
}

#[test]
fn an_encrypted_member_on_a_narrow_pool_is_the_archive_no_reach_writes() {
    pooled(an_encrypted_member_on_a_narrow_pool_is_the_archive_no_reach_writes_on_the_pool);
}

fn an_encrypted_member_on_a_narrow_pool_is_the_archive_no_reach_writes_on_the_pool() {
    // The narrow pool's reach with a password, data only and headers too,
    // at level 3 under a seeded entropy: the archive no reach writes,
    // read back by rarkit and by reference `unrar`.
    let unrar = have_unrar();
    let set = narrow_reach_set();
    let members: Vec<&[u8]> = set.iter().map(Vec::as_slice).collect();
    for headers in [false, true] {
        let sealed = || WriteOptions {
            encrypt_headers: headers,
            memory: budget_of(4 << 30),
            ..options(3, Some("narrow"))
        };
        let what = format!("the narrow reach {}", if headers { "-hp" } else { "-p" });
        let (none, _) = with_segment_width(1, || with_lane_reach(0, || write(sealed(), &members)));
        let (archive, _) =
            with_team_cores(8, || with_segment_width(1, || write(sealed(), &members)));
        let (crews, reach) = team_large();
        assert!(
            crews > 0 && reach == 8 << 20,
            "{what}: {crews} large crews reaching {reach}"
        );
        assert!(archive == none, "{what}: the reach moved a byte");
        reads_back(&what, &archive, &members, Some("narrow"));
        if unrar {
            unrar_reads(&what, &archive, &members, "narrow");
        }
    }
    if !unrar {
        println!("no reference unrar on this box: its read-back was skipped");
    }
}

/// Whether reference `unrar` is on this box's path.
fn have_unrar() -> bool {
    std::process::Command::new("unrar")
        .arg("-?")
        .output()
        .is_ok_and(|run| !run.stdout.is_empty())
}

/// Reference `unrar` tests `archive` under `password` and extracts
/// `members` from it byte for byte. It reports a checksum error on stderr
/// and may still exit 0, so both streams are read.
fn unrar_reads(what: &str, archive: &[u8], members: &[&[u8]], password: &str) {
    let dir = std::env::temp_dir().join(format!(
        "rarkit-team-{}-{}",
        what.replace([' ', ','], "-"),
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a work directory");
    std::fs::write(dir.join("test.rar"), archive).expect("the archive");
    for verb in ["t", "x"] {
        let run = std::process::Command::new("unrar")
            .args([verb, &format!("-p{password}"), "-y", "test.rar"])
            .current_dir(&dir)
            .output()
            .expect("unrar runs");
        let stdout = String::from_utf8_lossy(&run.stdout);
        let stderr = String::from_utf8_lossy(&run.stderr);
        assert!(
            run.status.success() && stderr.trim().is_empty() && stdout.contains("All OK"),
            "{what}: unrar {verb} refused the archive\n{stdout}\n{stderr}"
        );
    }
    for (index, data) in members.iter().enumerate() {
        let out = std::fs::read(dir.join(format!("m{index}.bin"))).expect("an extracted member");
        assert!(
            out == *data,
            "{what}: unrar extracted other bytes for member {index}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_encrypted_member_is_the_one_engines_archive_and_reads_back() {
    pooled(an_encrypted_member_is_the_one_engines_archive_and_reads_back_on_the_pool);
}

fn an_encrypted_member_is_the_one_engines_archive_and_reads_back_on_the_pool() {
    // SPEC-G 3.7.3's condition on both forms: with a password, data only
    // (`-p`) and headers too (`-hp`), under a seeded entropy the archive
    // is the one-engine archive, rarkit reads it back, and reference
    // `unrar` tests it and extracts the payload's bytes.
    let unrar = have_unrar();
    let big = member(60 << 20, 42);
    let set: Vec<Vec<u8>> = (0..6u64)
        .map(|i| member((3 << 20) + i as usize * (512 << 10), 90 + i))
        .collect();
    let members: Vec<&[u8]> = set.iter().map(Vec::as_slice).collect();
    for headers in [false, true] {
        let sealed = |password: &str| WriteOptions {
            encrypt_headers: headers,
            ..options(1, Some(password))
        };
        let how = if headers { "-hp" } else { "-p" };

        // The segment team.
        let what = format!("the team {how}");
        let (one, _) = with_segment_width(1, || write(sealed("segment"), &[&big]));
        let (archive, _) = with_team_cores(64, || write(sealed("segment"), &[&big]));
        let (rounds, engines) = segment_rounds();
        assert!(
            rounds > 0 && engines >= 2,
            "{what}: {rounds} rounds of at most {engines} engines"
        );
        assert!(archive == one, "{what}: the team moved a byte");
        reads_back(&what, &archive, &[&big], Some("segment"));
        if unrar {
            unrar_reads(&what, &archive, &[&big], "segment");
        }

        // The lane's reach.
        let what = format!("the lane {how}");
        let (none, _) =
            with_segment_width(1, || with_lane_reach(0, || write(sealed("lane"), &members)));
        let (archive, _) = with_segment_width(1, || {
            with_lane_reach(16 << 20, || write(sealed("lane"), &members))
        });
        let (crews, reach) = team_large();
        assert!(
            crews > 0 && reach == 16 << 20,
            "{what}: {crews} large crews reaching {reach}"
        );
        assert!(archive == none, "{what}: the reach moved a byte");
        reads_back(&what, &archive, &members, Some("lane"));
        if unrar {
            unrar_reads(&what, &archive, &members, "lane");
        }
    }
    if !unrar {
        println!("no reference unrar on this box: its read-back was skipped");
    }
}
