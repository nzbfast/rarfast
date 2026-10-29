//! Crosses the four ways of dividing `max_workers` between the members
//! decoded at once and the tape lanes inside each of them.
//!
//! API 8.3 names "breadth first" a STARTING DEFAULT, "to be confirmed or
//! overturned by measurement per shape, not a rule", and the memory budget is
//! a hard ceiling with the lowest wall winning inside
//! it. So the arrangement is a measured choice and this is what measures
//! it. the breadth driver script drives it: one process per cell, so
//! `/usr/bin/time -l` gives a peak RSS that is this configuration's and
//! not the largest child a driver ever reaped.
//!
//! Not a gate leg. It times ONE engine against itself under four
//! arrangements, where `two_arm.rs` times the engine against the old one;
//! there is no ratio here and none is implied.

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use rarkit::{
    extract_parallel, memory, probe, Disposition, MemberInfo, MemberOutcome, MemberSpec,
    MemoryPolicy, ParallelSink, Payload, RangeSource, ReadOptions, Result, WriteMethod,
    WriteOptions, Writer,
};

/// The shapes measured, each named on the command line.
///
/// `(name, member size, how many)`, plus the tail of small members that
/// only `one-big-many-small` has. The large sizes are all past the tape
/// path's 16 MiB output floor, because below it a member takes no lane at
/// all and the question does not arise; `many-small` is the shape that
/// shows what the division costs when it buys nothing.
fn shape(name: &str) -> (usize, usize, usize, usize) {
    match name {
        // Eight 16 MiB members: the headline `f/extract-par-8x16-m3` leg.
        "eight-16" => (16 << 20, 8, 0, 0),
        // Two 256 MiB members: breadth 2, where dividing by the pool's
        // width would starve both and dividing by the flight does not.
        "two-256" => (256 << 20, 2, 0, 0),
        // One large member beside many small: the small ones are below
        // the offload floor and stay on the walking thread, so the large
        // one should keep every lane.
        "one-big-many-small" => (256 << 20, 1, 64 << 10, 2000),
        // Sixteen 64 MiB members: more members than the ceiling at every
        // width measured, so the breadth itself is the binding term.
        "sixteen-64" => (64 << 20, 16, 0, 0),
        // FOUR 20 MiB members, the shape the zero-lane floor was found
        // on. Four members at a ceiling of six is the cell where the fair
        // share FLOORS to one: no member reaches the tape path and two
        // units of the ceiling are spent by nobody. 20 MiB is deliberately
        // just past the 16 MiB output floor and short of the 24 MiB that
        // opens lanes comfortably, because that is where it was reported.
        "four-20" => (20 << 20, 4, 0, 0),
        // The same shape one size up, so a cell that DOES open lanes sits
        // beside the one that cannot and the floor is read as a floor
        // rather than as the shape being too small to thread.
        "four-24" => (24 << 20, 4, 0, 0),
        other => parsed(other).unwrap_or_else(|| panic!("unknown shape {other}")),
    }
}

/// A shape written out rather than named: `n<count>x<MiB>-m<level>`.
///
/// **The named shapes above confound three things at once**, and the
/// first breadth-by-width table was read off them: its
/// four-member cells are 24 MiB `-m1` and its eight-member cells are 16
/// MiB `-m3`, so "narrowing wins on eight members and loses on four"
/// could equally be "narrowing wins at `-m3` and loses at `-m1`" or "wins
/// at 16 MiB and loses at 24". Nothing in that run separates them.
/// This spelling lets ONE of the three move at a time, which is what a
/// rule the engine can act on has to be built from.
fn parsed(name: &str) -> Option<(usize, usize, usize, usize)> {
    let (mib, count, _, _) = parsed_spec(name)?;
    Some((mib << 20, count, 0, 0))
}

/// `n<count>x<MiB>-m<level>`, with an optional `-t<material>` after it.
///
/// Answers `(MiB, count, level, material)`. ONE function parses the
/// whole spelling, because the two that used to do it separately could
/// disagree: the level reader took everything after the last `-m` and
/// fell back to 3 when it would not parse, so appending any suffix at
/// all would have built an `-m1` shape at level 3 and said nothing.
/// A spelling this harness cannot read is a panic at `shape`, never a
/// quiet default.
fn parsed_spec(name: &str) -> Option<(usize, usize, u8, u8)> {
    let rest = name.strip_prefix('n')?;
    let (count, rest) = rest.split_once('x')?;
    let (mib, rest) = rest.split_once("-m")?;
    let (level, material) = match rest.split_once("-t") {
        Some((level, material)) => (level, material.parse().ok()?),
        None => (rest, 0),
    };
    Some((
        mib.parse().ok()?,
        count.parse().ok()?,
        level.parse().ok()?,
        material,
    ))
}

/// The pack level of a spelled-out shape, `None` for a named one.
fn parsed_level(name: &str) -> Option<u8> {
    parsed_spec(name).map(|(_, _, level, _)| level)
}

/// The material a spelled-out shape is built from, 0 for a named one.
///
/// **A ROBUSTNESS DIAL, and it exists because of one measurement.** The
/// chunk block count (`probe::note_chunk_plan`) separates `-m1` from
/// `-m3` sharply on material 0: about 48 blocks a chunk against about
/// 26, at packed sizes within one percent. A rule keyed on that would
/// be keyed on a property of THIS GENERATOR unless the separation also
/// holds on material that compresses differently, and this repository
/// has no large RAR 5 fixture to check it against. So the generator
/// takes a dial and the separation is measured across it.
fn material(name: &str) -> u8 {
    parsed_spec(name).map_or(0, |(_, _, _, material)| material)
}

/// The pack level a shape is built at.
///
/// The floor was found on `-m1` members, and the level is not incidental
/// to it: a level 1 member decodes fast enough that the per-chunk
/// arithmetic is a larger share of its wall than it is at level 3, so a
/// division that spends the ceiling badly shows up sooner. The `-m3`
/// shapes are kept at 3 so the cells stay comparable with the earlier
/// cross this table is read beside.
fn level(name: &str) -> u8 {
    if let Some(level) = parsed_level(name) {
        return level;
    }
    match name {
        "four-20" | "four-24" => 1,
        _ => 3,
    }
}

/// `len` bytes of text of material `material`, from `seed`.
///
/// The dial is the vocabulary the text is written in: 160 words at 0 and
/// four times as many for each step up, so a higher material repeats
/// itself farther back and packs less. The materials are this file's
/// own; a table made before 11 Oct 2026 was made on other text.
fn body_of(len: usize, seed: u64, material: u8) -> Vec<u8> {
    let words = 160usize << (2 * u32::from(material.min(6)));
    rarkit_testdata::chatter_of(seed, words, len)
}

fn build(name: &str, path: &std::path::Path) {
    let (big, bigs, small, smalls) = shape(name);
    // The names and the bodies outlive the writer, which borrows both for
    // as long as it is open.
    let material = material(name);
    let big_body = body_of(big, 1, material);
    let small_body = if smalls > 0 {
        body_of(small, 2, material)
    } else {
        Vec::new()
    };
    let names: Vec<Vec<u8>> = (0..bigs)
        .map(|i| format!("big{i}.dat").into_bytes())
        .chain((0..smalls).map(|i| format!("small{i}.dat").into_bytes()))
        .collect();

    let mut writer = Writer::new(WriteOptions {
        method: WriteMethod::Compressed {
            level: level(name),
            dictionary: None,
        },
        ..WriteOptions::default()
    })
    .expect("options");
    for (i, name) in names.iter().enumerate() {
        let payload = if i < bigs { &big_body } else { &small_body };
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(payload),
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = std::fs::File::create(path).expect("create");
    writer.finish_into(&mut out).expect("finish");
    out.flush().expect("flush");
}

/// Verifies and counts, and keeps no bytes: the shapes here run to a
/// gigabyte and holding their output would measure the harness.
struct Blackhole {
    bytes: AtomicU64,
    verify: bool,
}

struct Counted(u64);

impl Write for Counted {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0 += data.len() as u64;
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
        // `RARKIT_BL_VERIFY=1`: the member goes nowhere, as `rarfast t`
        // sends it, so a census row reads the path `t` runs.
        if self.verify {
            return Ok(Disposition::Verify);
        }
        Ok(Disposition::Write(Counted(0)))
    }

    fn close(
        &self,
        _member: &MemberInfo<'_>,
        out: Option<Counted>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        assert_ne!(
            outcome.checksum_ok,
            Some(false),
            "a member this harness wrote failed its checksum"
        );
        self.bytes
            .fetch_add(out.map_or(0, |c| c.0), Ordering::Relaxed);
        Ok(())
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 4 && args[1] == "build" {
        build(&args[2], std::path::Path::new(&args[3]));
        return;
    }
    if args.len() < 6 {
        eprintln!(
            "usage: breadth_lanes build <shape> <path>\n       \
             breadth_lanes run <path> <max_workers> <breadth> <arm> [narrow-after]"
        );
        std::process::exit(2);
    }
    let path = std::path::Path::new(&args[2]);
    let max_workers: usize = args[3].parse().expect("max_workers");
    let breadth: usize = args[4].parse().expect("breadth");
    let arm: u8 = args[5].parse().expect("arm");

    // 255 means LEAVE THE DEFAULT ALONE, which is the only way to read
    // what a build actually ships. `rarkit-oracle` depends on `rarkit`
    // with `test-support`, so cargo's feature unification turns that
    // feature on for any build in a directory that also builds the
    // oracle, and a cell that passes an explicit arm is then measuring
    // the arm rather than the default. This cost 20 minutes on 20 Sep
    // 2026: three runs of a supposedly feature-free build all reported
    // the floored share, because the harness was asking for it.
    if arm != 255 {
        probe::set_breadth_arm(arm);
    }
    // Arm 8's threshold, as an optional seventh word. The arm is a
    // FAMILY of arrangements rather than one, so the cell has to name
    // which member of it is being priced; the arms either side of it are
    // the family's own two ends (`probe::BREADTH_ARM_LATE_NARROW`).
    if let Some(after) = args.get(6).and_then(|a| a.parse::<usize>().ok()) {
        probe::set_narrow_after(after);
    }
    // THE WIDTH IS `ReadOptions::workers` AND HAS BEEN SINCE 8.4.2. This
    // harness set `MemoryPolicy::max_workers` alone when it was written,
    // which was the width dial then and is a MEMORY field now (8.4.1), so
    // between the split landing and this line every cell here ran at
    // whatever `read_width()` fell through to, which is the rayon pool's
    // count and not the number on the command line. The policy is still
    // set beside it, because the budget is a term the ceiling is lowered
    // by (8.4.2's precedence rule) and a cell that moved it silently
    // would not be measuring the width either.
    // `RARKIT_BL_LIMIT_MIB`: the working limit, for a row that asks
    // whether the memory budget is what holds members back.
    let mut memory = MemoryPolicy {
        max_workers,
        ..Default::default()
    };
    if let Some(mib) = std::env::var("RARKIT_BL_LIMIT_MIB")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        memory.working_limit = mib << 20;
    }
    // `RARKIT_BL_WAITING`: `ReadOptions::waiting_outputs`, a number of
    // writers, for a census row of a writing sink.
    let waiting = std::env::var("RARKIT_BL_WAITING")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok());
    let opts = ReadOptions::default()
        .with_workers(Some(max_workers))
        .with_memory(memory)
        .with_waiting_outputs(waiting);
    let file = std::fs::File::open(path).expect("open");
    let sources = vec![Arc::new(file) as Arc<dyn RangeSource>];
    let sink = Blackhole {
        bytes: AtomicU64::new(0),
        verify: std::env::var("RARKIT_BL_VERIFY").is_ok_and(|v| v.trim() == "1"),
    };

    memory::reset_peak();
    probe::reset_peak_lanes();
    probe::reset_peak_members();
    probe::reset_peak_workers();
    probe::reset_chunk_plans();
    #[cfg(feature = "wait-census")]
    let census = census::Sampler::start();
    let started = Instant::now();
    let report = extract_parallel(sources, &opts, &sink, breadth).expect("extract_parallel");
    let wall = started.elapsed().as_secs_f64();
    #[cfg(feature = "wait-census")]
    census.finish(wall);

    let blocks = probe::chunk_blocks();
    let groups = probe::chunk_groups();

    // One line of `key=value`, so the driver parses it without a format.
    //
    // `peak_workers` IS NAMED `peak_workers` HERE. It used to be printed
    // under the heading `peak_blocks`, and that one wrong word cost the
    // arm 6 work its hypothesis: reading a ceiling-capped worker count
    // as a block count, it recorded 8 on every cell and wrote up the
    // chain length as measured and flat when it had never been measured
    // at all. That was corrected. The real block columns are below.
    println!(
        "RESULT wall={wall:.4} members={} bytes={} \
         peak_lanes={} peak_members={} peak_workers={} peak_working={} \
         engine_peak={} limit={} narrow_after={} \
         chunks={} chunk_blocks_total={} chunk_blocks_peak={} \
         chunk_blocks_least={} chunk_blocks_median={} chunk_blocks_p90={} \
         chunk_groups_median={} chunk_series_dropped={}",
        report.members,
        sink.bytes.load(Ordering::Relaxed),
        probe::peak_lanes(),
        probe::peak_members(),
        probe::peak_workers(),
        report.peak_working_memory,
        memory::peak(),
        opts.memory.working_limit,
        args.get(6).map_or(-1i64, |a| a.parse().unwrap_or(-1)),
        probe::chunks_planned(),
        probe::chunk_blocks_total(),
        probe::peak_chunk_blocks(),
        probe::least_chunk_blocks(),
        quantile(&blocks, 0.5),
        quantile(&blocks, 0.9),
        quantile(&groups, 0.5),
        probe::chunk_plans_dropped(),
    );

    // THE SERIES, and the summary above is not a substitute for it. The
    // chunk block count is a DISTRIBUTION over chunks rather than a
    // number, and a mean or a median over it can sit flat while the
    // shape that decides the question moves, so a recording run takes
    // the whole series and decides afterwards what to key on. Off by
    // default because a 256 MiB member plans hundreds of chunks and a
    // timing cell has no use for them.
    if std::env::var_os("RARKIT_CHUNK_SERIES").is_some() && !blocks.is_empty() {
        let spell = |xs: &[u32]| xs.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
        println!("CHUNKBLOCKS {}", spell(&blocks));
        println!("CHUNKGROUPS {}", spell(&groups));
    }
}

/// The `q` quantile of `xs`, by nearest rank, or 0 for an empty series.
///
/// Nearest rank rather than an interpolating definition because a block
/// count is a count: a median of 6.5 blocks is not a thing a chunk can
/// hold, and a reader comparing two fixtures wants the figure one of
/// them actually had.
fn quantile(xs: &[u32], q: f64) -> u32 {
    if xs.is_empty() {
        return 0;
    }
    let mut sorted = xs.to_vec();
    sorted.sort_unstable();
    let rank = ((q * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1]
}

/// The wait census's sampler (feature `wait-census`).
///
/// One thread polls `probe::census`'s gauges about every 200 microseconds
/// while the extraction runs. It prints each site's MEAN (threads inside
/// it, averaged over the run), its entries and its summed seconds, and
/// the share of the run spent at each count of big members in flight and
/// of threads at work. A census, never a timed row: the sites cost a
/// clock read each.
#[cfg(feature = "wait-census")]
mod census {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread::JoinHandle;

    use rarkit::probe::census as c;

    const BUCKETS: usize = 130;

    pub struct Seen {
        samples: u64,
        sums: [i64; c::SITES],
        big: [u64; BUCKETS],
        working: [u64; BUCKETS],
    }

    pub struct Sampler {
        stop: Arc<AtomicBool>,
        thread: JoinHandle<Seen>,
    }

    /// The sites whose threads are on a core rather than parked.
    const WORKING: [usize; 6] = [
        c::FILL,
        c::PLAN,
        c::SPAWN,
        c::APPLY_BUSY,
        c::LANE_DECODE,
        c::ONE_THREAD,
    ];

    impl Sampler {
        pub fn start() -> Sampler {
            c::reset();
            let stop = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&stop);
            let thread = std::thread::spawn(move || {
                let mut seen = Seen {
                    samples: 0,
                    sums: [0; c::SITES],
                    big: [0; BUCKETS],
                    working: [0; BUCKETS],
                };
                while !flag.load(Ordering::Relaxed) {
                    let now = c::now();
                    seen.samples += 1;
                    for (sum, v) in seen.sums.iter_mut().zip(now.iter()) {
                        *sum += *v;
                    }
                    let at = |v: i64| (v.max(0) as usize).min(BUCKETS - 1);
                    seen.big[at(now[c::BIG_MEMBERS])] += 1;
                    seen.working[at(WORKING.iter().map(|&s| now[s]).sum())] += 1;
                    std::thread::sleep(std::time::Duration::from_micros(200));
                }
                seen
            });
            Sampler { stop, thread }
        }

        pub fn finish(self, wall: f64) {
            self.stop.store(true, Ordering::Relaxed);
            let seen = self.thread.join().expect("the sampler");
            let totals = c::totals();
            let n = seen.samples.max(1) as f64;
            println!("CENSUS samples={} wall={wall:.4}", seen.samples);
            for (site, (enters, nanos)) in totals.iter().enumerate() {
                println!(
                    "CENSUS site={} mean={:.3} enters={} secs={:.4}",
                    c::NAMES[site],
                    seen.sums[site] as f64 / n,
                    enters,
                    *nanos as f64 / 1e9,
                );
            }
            for (name, hist) in [("big_members", &seen.big), ("working", &seen.working)] {
                let spelled: Vec<String> = hist
                    .iter()
                    .enumerate()
                    .filter(|(_, &count)| count > 0)
                    .map(|(v, &count)| format!("{v}:{:.3}", count as f64 / n))
                    .collect();
                println!("CENSUS hist={name} {}", spelled.join(" "));
            }
        }
    }
}
