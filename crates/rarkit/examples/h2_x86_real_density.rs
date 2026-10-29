//! The x86 address pass, walking against the shipped split, over the
//! blocks a REAL archive of REAL x86-64 binaries frames.
//!
//! The x86-collect sweep (`examples/h2_x86_density_sweep.rs`, on
//! `impl/h2-x86-pass-collect`) found that the shipped split loses to the
//! walking body it replaced at every geometric mean trigger gap of 32 and
//! above, on SYNTHETIC blocks. Whether real archives sit in that band was
//! an inference across two statistics on two corpora, and this is the
//! measurement that replaces it.
//!
//! Three things make it a different instrument rather than the same one
//! with new numbers:
//!
//! - the blocks are chosen by the ENCODER'S OWN DETECTOR. Reference `rar`
//!   writes the archive at `-ma5 -m3` over real x86-64 object code, and
//!   whatever it decides to frame as an x86 filter record is what this
//!   times. A generator cannot produce that population, because the thing
//!   under test is partly which regions get filtered at all.
//! - the gap DISTRIBUTION is reported, not a mean. The synthetic sweep
//!   had one parameter per cell; a real corpus has a spread, and the
//!   spread is the finding.
//! - the WALKING column is kept, which is the one arm with no stake in this
//!   argument.
//!
//! Untimed: it reports SAME-BINARY ratios between arms, measured on one
//! box in one process with the arms interleaved. No absolute here travels.
//!
//! Implemented from `specs/SPEC-H2-rarkit-rar5-lz.md` alone.

use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use rarkit::internals::rar5::{x86_filter_blocks, X86Block};

/// The arms. `Null` is the control: it reads every byte of every block and
/// writes nothing, so no change to either pass can move it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arm {
    Null,
    Walking,
    Split,
}

impl Arm {
    fn name(self) -> &'static str {
        match self {
            Arm::Null => "null control",
            Arm::Walking => "walking",
            Arm::Split => "split (shipped)",
        }
    }
}

const ARMS: [Arm; 3] = [Arm::Null, Arm::Walking, Arm::Split];

fn run_arm(arm: Arm, data: &mut [u8], f: u32, jump: bool) {
    match arm {
        Arm::Null => {
            let mut sum = 0u64;
            for &byte in data.iter() {
                sum = sum.wrapping_add(u64::from(byte));
            }
            black_box(sum);
        }
        Arm::Walking => rarkit::internals::rar5::rar5_x86_pass(data, f, jump, 0),
        Arm::Split => rarkit::internals::rar5::rar5_x86_pass(data, f, jump, 1),
    }
}

// ---------------------------------------------------------------------------
// The corpus
// ---------------------------------------------------------------------------

/// Real x86-64 object code from the pinned toolchain's own
/// `x86_64-apple-darwin` standard library.
///
/// An rlib is an `ar` archive of real compiled objects, which is what a
/// person actually puts in a RAR archive, and a build box carries the target
/// already because `make cross` gates on it. Nothing here is generated.
fn rlib_sources() -> Vec<PathBuf> {
    let Ok(sysroot) = Command::new("rustc").arg("--print").arg("sysroot").output() else {
        return Vec::new();
    };
    let root = String::from_utf8_lossy(&sysroot.stdout).trim().to_string();
    let dir = Path::new(&root)
        .join("lib")
        .join("rustlib")
        .join("x86_64-apple-darwin")
        .join("lib");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "rlib"))
        .collect();
    out.sort();
    out
}

/// The x86_64 slices of every universal executable on the box, cut out
/// with `lipo`.
///
/// The second source, and a different KIND of real code: linked
/// executables written by several compilers over many years, rather than
/// one toolchain's static libraries. The directories are walked rather
/// than listed by name so the corpus is whatever the box actually has, and
/// a binary with no x86_64 slice is skipped without comment: on an Apple
/// Silicon Mac plenty are arm64 only, and that is a property of the box,
/// not a failure of the lab.
fn lipo_slices(scratch: &Path, want: usize) -> Vec<PathBuf> {
    const ROOTS: [&str; 4] = ["/usr/bin", "/usr/sbin", "/bin", "/usr/libexec"];
    let mut out = Vec::new();
    let mut index = 0usize;
    for root in ROOTS {
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        let mut paths: Vec<PathBuf> = entries
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| path.is_file())
            .collect();
        paths.sort();
        for candidate in paths {
            if out.len() >= want {
                return out;
            }
            let target = scratch.join(format!("slice{index:04}.x86_64"));
            index += 1;
            // A kept scratch already holds the slices an earlier run
            // cut, and `lipo` over a whole `/usr/bin` is minutes.
            if std::fs::metadata(&target).is_ok_and(|meta| meta.len() > 64 * 1024) {
                out.push(target);
                continue;
            }
            let output = Command::new("lipo")
                .arg("-thin")
                .arg("x86_64")
                .arg(&candidate)
                .arg("-output")
                .arg(&target)
                .output();
            let kept = matches!(output, Ok(ref output) if output.status.success())
                && std::fs::metadata(&target).is_ok_and(|meta| meta.len() > 64 * 1024);
            if kept {
                out.push(target);
            } else {
                let _ = std::fs::remove_file(&target);
            }
        }
    }
    out
}

/// Write the archive with reference `rar` at `-ma5 -m3`, its own detector
/// choosing which regions become filter blocks.
fn write_archive(scratch: &Path, files: &[PathBuf], reuse: bool) -> Option<Vec<u8>> {
    let archive = scratch.join("real-x86.rar");
    // A KEPT scratch is the point: building the corpus is minutes and the
    // sweep is seconds, so two runs that must be independent of each
    // other in their TIMING should still share one corpus, or they are
    // comparing two draws as well as two orders.
    if reuse {
        if let Ok(bytes) = std::fs::read(&archive) {
            if !bytes.is_empty() {
                println!("ARCHIVE: reused from the kept scratch.");
                return Some(bytes);
            }
        }
    }
    let _ = std::fs::remove_file(&archive);
    let mut command = Command::new("rar");
    command
        .arg("a")
        .arg("-ma5")
        .arg("-m3")
        .arg("-ep")
        .arg("-inul")
        .arg("-y")
        .arg(&archive);
    for file in files {
        command.arg(file);
    }
    let status = command.status().ok()?;
    if !status.success() {
        eprintln!("reference rar refused the corpus: {status}");
        return None;
    }
    std::fs::read(&archive).ok()
}

// ---------------------------------------------------------------------------
// The gap distribution
// ---------------------------------------------------------------------------

/// Trigger positions under the format's own rule: a trigger is an opcode
/// byte with four whole bytes after it, and the scan resumes five bytes
/// past one, so operand bytes are never tested.
fn trigger_gaps(data: &[u8], jump: bool) -> Vec<usize> {
    let Some(limit) = data.len().checked_sub(4) else {
        return Vec::new();
    };
    let mut gaps = Vec::new();
    let mut at = 0usize;
    let mut previous: Option<usize> = None;
    while at < limit {
        let byte = data[at];
        let hit = if jump { byte | 1 == 0xe9 } else { byte == 0xe8 };
        if hit {
            if let Some(previous) = previous {
                gaps.push(at - previous);
            }
            previous = Some(at);
            at += 5;
        } else {
            at += 1;
        }
    }
    gaps
}

fn median(values: &mut [f64]) -> f64 {
    if values.is_empty() {
        return f64::NAN;
    }
    values.sort_by(|a, b| a.partial_cmp(b).expect("no NaN in a timing sample"));
    let middle = values.len() / 2;
    if values.len().is_multiple_of(2) {
        (values[middle - 1] + values[middle]) / 2.0
    } else {
        values[middle]
    }
}

fn median_absolute_deviation(values: &[f64]) -> f64 {
    let mut copy: Vec<f64> = values.to_vec();
    let centre = median(&mut copy);
    if centre == 0.0 || centre.is_nan() {
        return f64::NAN;
    }
    let mut spread: Vec<f64> = values.iter().map(|value| (value - centre).abs()).collect();
    median(&mut spread) / centre * 100.0
}

/// The byte-weighted percentile of a per-block statistic: each block's
/// value carries its own length, which is the weighting the block census
/// in `X86_PROBE_BYTES`'s comment uses and the one this table must be
/// comparable with.
fn byte_weighted_percentile(pairs: &mut [(f64, u64)], percentile: f64) -> f64 {
    if pairs.is_empty() {
        return f64::NAN;
    }
    pairs.sort_by(|a, b| a.0.partial_cmp(&b.0).expect("no NaN in a block median"));
    let total: u64 = pairs.iter().map(|pair| pair.1).sum();
    let want = (total as f64) * percentile;
    let mut seen = 0u64;
    for &(value, weight) in pairs.iter() {
        seen += weight;
        if (seen as f64) >= want {
            return value;
        }
    }
    pairs[pairs.len() - 1].0
}

/// Reports the corpus and returns each block's MEDIAN trigger gap, in
/// block order, which is what the sweep bands on.
fn report_distribution(blocks: &[X86Block]) -> Vec<f64> {
    let mut per_block: Vec<(f64, u64)> = Vec::new();
    // `per_block` is SORTED in place by the percentile helper below, so the
    // sweep's banding takes this copy, which stays in block order.
    let mut medians: Vec<f64> = Vec::new();
    let mut all_gaps: Vec<f64> = Vec::new();
    let mut type1 = 0usize;
    let mut type2 = 0usize;
    let mut bytes_type1 = 0u64;
    let mut bytes_type2 = 0u64;
    for block in blocks {
        if block.jump {
            type2 += 1;
            bytes_type2 += block.data.len() as u64;
        } else {
            type1 += 1;
            bytes_type1 += block.data.len() as u64;
        }
        let gaps = trigger_gaps(&block.data, block.jump);
        if gaps.is_empty() {
            // A block with fewer than two triggers has no gap to report.
            // It is one long crossing and the sparse path is the whole of
            // what runs on it; it is counted in the band table below by
            // its length rather than dropped.
            per_block.push((f64::INFINITY, block.data.len() as u64));
            medians.push(f64::INFINITY);
            continue;
        }
        let mut values: Vec<f64> = gaps.iter().map(|&gap| gap as f64).collect();
        all_gaps.extend(values.iter().copied());
        let block_median = median(&mut values);
        per_block.push((block_median, block.data.len() as u64));
        medians.push(block_median);
    }

    let bytes: u64 = blocks.iter().map(|block| block.data.len() as u64).sum();
    println!();
    println!("THE CORPUS, as the encoder's own detector framed it");
    println!("  x86 filter blocks         {}", blocks.len());
    println!("    type 1, calls alone     {type1} blocks, {bytes_type1} bytes");
    println!("    type 2, calls and jumps {type2} blocks, {bytes_type2} bytes");
    println!("  filtered bytes            {bytes}");
    println!(
        "  triggers                  {}",
        all_gaps.len() + blocks.len()
    );

    println!();
    println!("THE GAP DISTRIBUTION, byte weighted over each block's MEDIAN gap");
    for percentile in [0.10, 0.25, 0.50, 0.75, 0.90, 0.99] {
        let value = byte_weighted_percentile(&mut per_block, percentile);
        println!("  p{:<3.0}  {value:>10.1}", percentile * 100.0);
    }

    println!();
    println!("THE BAND TABLE: share of filtered BYTES by the block's median gap");
    let bands: [(f64, f64); 6] = [
        (0.0, 16.0),
        (16.0, 32.0),
        (32.0, 64.0),
        (64.0, 128.0),
        (128.0, 256.0),
        (256.0, f64::INFINITY),
    ];
    for (low, high) in bands {
        let share: u64 = per_block
            .iter()
            .filter(|(value, _)| *value >= low && *value < high)
            .map(|(_, weight)| weight)
            .sum();
        let label = if high.is_infinite() {
            format!("{low:.0} and up")
        } else {
            format!("{low:.0} to {high:.0}")
        };
        println!(
            "  {label:<14} {share:>12} bytes  {:>6.2}%",
            if bytes == 0 {
                0.0
            } else {
                share as f64 / bytes as f64 * 100.0
            }
        );
    }
    let sparse: u64 = per_block
        .iter()
        .filter(|(value, _)| value.is_infinite())
        .map(|(_, weight)| weight)
        .sum();
    if sparse > 0 {
        println!("  (of which {sparse} bytes sit in blocks with fewer than two triggers)");
    }
    medians
}

// ---------------------------------------------------------------------------
// The sweep
// ---------------------------------------------------------------------------

/// The groups a block's time is summed into. One pass over the corpus
/// fills every one of them, so the bands and the two record types are not
/// separate runs that could drift apart from each other.
const GROUPS: usize = 9;
const GROUP_NAMES: [&str; GROUPS] = [
    "ALL",
    "median gap 0 to 16",
    "median gap 16 to 32",
    "median gap 32 to 64",
    "median gap 64 to 128",
    "median gap 128 and up",
    "fewer than two triggers",
    "type 1, calls alone",
    "type 2, calls and jumps",
];

/// Which groups a block counts towards: always `ALL`, its gap band, and
/// its record type.
fn groups_of(block_median: f64, jump: bool) -> [usize; 3] {
    let band = if block_median.is_infinite() {
        6
    } else if block_median < 16.0 {
        1
    } else if block_median < 32.0 {
        2
    } else if block_median < 64.0 {
        3
    } else if block_median < 128.0 {
        4
    } else {
        5
    };
    [0, band, if jump { 8 } else { 7 }]
}

/// One arm over every block once, timed, with the restore left out of the
/// clock, summed into each block's groups.
///
/// `work` holds the pristine bytes back before each block, because a
/// decode pass is not idempotent and a second run over its own output
/// would be measuring different data. The restore is the same memory
/// traffic for every arm, and it is outside the clock, so it cannot
/// prefer one.
fn time_arm(
    arm: Arm,
    blocks: &[X86Block],
    bands: &[[usize; 3]],
    work: &mut Vec<u8>,
) -> [u64; GROUPS] {
    let mut totals = [0u64; GROUPS];
    for (block, groups) in blocks.iter().zip(bands) {
        work.clear();
        work.extend_from_slice(&block.data);
        let started = Instant::now();
        run_arm(arm, work.as_mut_slice(), block.f, block.jump);
        let elapsed = started.elapsed().as_nanos() as u64;
        black_box(work.as_slice());
        for &group in groups {
            totals[group] += elapsed;
        }
    }
    totals
}

/// Every arm computes the same bytes, and this is checked before anything
/// is timed. It is the one thing the density question does NOT rest on and
/// the one thing a timing sweep would hide if it were false.
fn byte_check(blocks: &[X86Block]) -> bool {
    for block in blocks {
        let mut walked = block.data.clone();
        let mut split = block.data.clone();
        run_arm(Arm::Walking, &mut walked, block.f, block.jump);
        run_arm(Arm::Split, &mut split, block.f, block.jump);
        if walked != split {
            return false;
        }
    }
    true
}

fn main() {
    let mut rounds = 15usize;
    let mut reverse = false;
    let mut rebuild = false;
    let mut want_slices = 400usize;
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--pairs" | "--rounds" => {
                rounds = arguments
                    .next()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(rounds);
            }
            // The arm ORDER is controlled for the reason the x86-collect
            // sweep controls its density order: an order that never
            // changes makes position and the clock move together, and
            // reversing it SHOWS that they do not rather than asserting it.
            "--reverse" => reverse = true,
            "--rebuild" => rebuild = true,
            "--slices" => {
                want_slices = arguments
                    .next()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or(want_slices);
            }
            other => {
                eprintln!("unknown argument {other}");
                std::process::exit(2);
            }
        }
    }

    let scratch = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join("h2-x86-real-density");
    std::fs::create_dir_all(&scratch).expect("a scratch directory");

    let mut files = rlib_sources();
    let rlibs = files.len();
    let slices = lipo_slices(&scratch, want_slices);
    let sliced = slices.len();
    files.extend(slices);
    println!("SOURCES: {rlibs} x86_64-apple-darwin rlibs, {sliced} lipo x86_64 slices");
    if files.is_empty() {
        eprintln!(
            "REFUSED: no real x86-64 material on this box. The pinned toolchain's \
             x86_64-apple-darwin target and `lipo` are both absent, so there is \
             nothing real to archive and a generator is what this lab exists to avoid."
        );
        std::process::exit(1);
    }

    let Some(archive) = write_archive(&scratch, &files, !rebuild) else {
        eprintln!("REFUSED: reference rar did not write the archive.");
        std::process::exit(1);
    };
    println!("ARCHIVE: {} bytes, -ma5 -m3", archive.len());

    let blocks = match x86_filter_blocks(&archive) {
        Ok(blocks) => blocks,
        Err(error) => {
            eprintln!("REFUSED: rarkit could not read the archive back: {error:?}");
            std::process::exit(1);
        }
    };
    if blocks.is_empty() {
        eprintln!(
            "REFUSED: reference rar framed NO x86 filter record over this corpus. \
             That is a finding about the detector rather than about the passes, \
             and it is reported rather than worked around."
        );
        std::process::exit(1);
    }

    let filtered: u64 = blocks.iter().map(|block| block.data.len() as u64).sum();
    // A FLOOR on the corpus, not on the sample count. At 4 MB of filtered
    // bytes a round is about a millisecond, and a millisecond cell on a
    // shared box is measuring the scheduler: the first run of this lab
    // read its own null control moving 1.19 percent at that size. The
    // floor is stated here rather than in a script so that no invocation
    // can quote a table taken under it.
    const FILTERED_FLOOR: u64 = 32 << 20;
    if filtered < FILTERED_FLOOR {
        eprintln!(
            "REFUSED: only {filtered} filtered bytes, under the {FILTERED_FLOOR} floor. \
             A round this short measures the scheduler. Widen the corpus with \
             --slices, or pass --rebuild if a kept scratch is holding a narrower one."
        );
        std::process::exit(1);
    }

    let medians = report_distribution(&blocks);

    if !byte_check(&blocks) {
        eprintln!("REFUSED: the walking and the split passes disagree on a real block.");
        std::process::exit(1);
    }
    println!();
    println!("BYTE CHECK: walking and split agree on every block.");

    let bands: Vec<[usize; 3]> = blocks
        .iter()
        .zip(&medians)
        .map(|(block, &block_median)| groups_of(block_median, block.jump))
        .collect();
    let mut group_bytes = [0u64; GROUPS];
    let mut group_blocks = [0usize; GROUPS];
    for (block, groups) in blocks.iter().zip(&bands) {
        for &group in groups {
            group_bytes[group] += block.data.len() as u64;
            group_blocks[group] += 1;
        }
    }

    let widest = blocks
        .iter()
        .map(|block| block.data.len())
        .max()
        .unwrap_or(0);
    let mut work: Vec<u8> = Vec::with_capacity(widest);

    // Interleaved round robin: one round runs every arm once over the
    // whole corpus, so a drift inside the sweep moves every arm together
    // rather than the arm that happens to be scheduled while it lasts.
    let mut order: Vec<usize> = (0..ARMS.len()).collect();
    if reverse {
        order.reverse();
    }
    let mut samples: Vec<Vec<[u64; GROUPS]>> = vec![Vec::new(); ARMS.len()];
    for _ in 0..rounds {
        for &index in &order {
            let totals = time_arm(ARMS[index], &blocks, &bands, &mut work);
            samples[index].push(totals);
        }
    }

    let group_samples = |arm: usize, group: usize| -> Vec<f64> {
        samples[arm]
            .iter()
            .map(|totals| totals[group] as f64)
            .collect()
    };

    // THE NULL CONTROL, first half against second half. An arm that reads
    // every byte and writes none cannot be moved by either pass, so if it
    // moved, the box did, and no ratio in the tables below is a reading.
    let null = group_samples(0, 0);
    let half = null.len() / 2;
    let mut first: Vec<f64> = null[..half].to_vec();
    let mut last: Vec<f64> = null[half..].to_vec();
    let first_median = median(&mut first);
    let last_median = median(&mut last);
    let drift = (last_median - first_median) / first_median * 100.0;
    println!();
    println!(
        "NULL CONTROL: first half {:.3} ms, last half {:.3} ms, {drift:+.2}%",
        first_median / 1e6,
        last_median / 1e6
    );
    if drift.abs() > 1.0 {
        eprintln!(
            "REFUSED: the null control moved {drift:+.2} percent across the sweep, \
             past the 1 percent this table is allowed. The box moved; nothing here \
             is a reading."
        );
        std::process::exit(1);
    }

    println!();
    println!("THE TABLE, over the WHOLE corpus.");
    println!("Column is SPLIT over arm, so above 1.00 is FASTER than the shipped split.");
    println!();
    println!("| arm | median ms | MAD % | split/arm |");
    println!("|---|---|---|---|");
    let mut whole_split = group_samples(2, 0);
    let whole_split_median = median(&mut whole_split);
    for (index, &arm) in ARMS.iter().enumerate() {
        let mut values = group_samples(index, 0);
        let mad = median_absolute_deviation(&values);
        let arm_median = median(&mut values);
        let ratio = if arm == Arm::Null {
            "control".to_string()
        } else {
            format!("{:.3}", whole_split_median / arm_median)
        };
        println!(
            "| {} | {:.3} | {mad:.2} | {ratio} |",
            arm.name(),
            arm_median / 1e6
        );
    }

    // THE BAND TABLE, which is what a density-adaptive dispatch needs: not
    // whether the split loses overall, but WHERE it crosses over on real
    // blocks. A band with no bytes in it prints nothing rather than a
    // ratio of two zeros.
    println!();
    println!("THE BANDS, and the two record types. Column is SPLIT over WALKING.");
    println!();
    println!("| group | blocks | bytes | walking ms | split ms | split/walking | MAD walking | MAD split |");
    println!("|---|---|---|---|---|---|---|---|");
    for group in 0..GROUPS {
        if group_bytes[group] == 0 {
            continue;
        }
        let mut walking = group_samples(1, group);
        let mut split = group_samples(2, group);
        let walking_mad = median_absolute_deviation(&walking);
        let split_mad = median_absolute_deviation(&split);
        let walking_median = median(&mut walking);
        let split_median = median(&mut split);
        println!(
            "| {} | {} | {} | {:.4} | {:.4} | {:.3} | {walking_mad:.2} | {split_mad:.2} |",
            GROUP_NAMES[group],
            group_blocks[group],
            group_bytes[group],
            walking_median / 1e6,
            split_median / 1e6,
            split_median / walking_median
        );
    }

    println!();
    println!(
        "rounds {rounds}, arm order {}, one process, arms interleaved, untimed box, \
         same-binary ratios only.",
        if reverse { "REVERSED" } else { "forward" }
    );
}
