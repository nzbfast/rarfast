//! What the 128 KiB dictionary costs the RAR 5 decode, separated from what
//! its STREAM costs.
//!
//! `rar5_text_64m_m5_md128k` reads 0.513x to 0.517x, the worst RAR 5
//! decode ratio in the tree, against `md256m` at 0.939x on the SAME
//! material at the same level. Two explanations fit that equally well and
//! a single pair of legs cannot tell them apart:
//!
//! 1. the small dictionary makes the ENCODER emit more, shorter
//!    operations, and the apply stage is bound by operations (the 21 Sep
//!    apply lane), so the leg is slower because there is more of it;
//! 2. the small RING itself is dearer per operation - it wraps constantly,
//!    a match's source crosses the end, the fast copy's guard fails.
//!
//! A LADDER over the dictionary with everything else held fixed separates
//! them, because it moves both causes together and prints each one's
//! coordinate: the census says how many operations a rung has, and the
//! clock says what one operation cost there. If nanoseconds PER OPERATION
//! are flat across the ladder, the ring is not the cost and explanation 1
//! is the whole of it; if they rise as the dictionary falls, explanation 2
//! is real and this prints its size.
//!
//! Nothing here is a gate figure and nothing here times the old engine:
//! the oracle arm is never sampled, profiled or instrumented, only timed,
//! and this lab does not call it at all. Walls are absolute and do not
//! travel between boxes; the per-operation column is the one to read.
//!
//! It builds its rungs beside the bench's own corpora in
//! `target/bench-h2`, from the SAME `text.dat` the `md128k` and `md256m`
//! legs use, so run `cargo bench -p rarkit --bench two_arm` once first.
//!
//! Usage: `h2_md_ladder [--reps N] [--rungs 128k,1m,...] [--serial]`.
//!
//! Implemented from `specs/SPEC-H2-rarkit-rar5-lz.md` alone; no other RAR
//! implementation and no copy of the predecessor was opened.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

/// This process's CPU seconds and peak RSS in bytes.
///
/// `RUSAGE_SELF`, never `RUSAGE_CHILDREN`, which
/// reports the largest child ever reaped and once printed an archive
/// builder's resident set on every row of a table.
#[cfg(unix)]
#[allow(unsafe_code)]
fn usage() -> (f64, f64) {
    let mut ru = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: getrusage fills the struct it is given; RUSAGE_SELF is valid
    // and the struct is zeroed, so a short write leaves no uninitialised
    // field readable.
    let ok = unsafe { libc::getrusage(libc::RUSAGE_SELF, ru.as_mut_ptr()) } == 0;
    if !ok {
        return (0.0, 0.0);
    }
    // SAFETY: the call above succeeded, so the struct is initialised.
    let ru = unsafe { ru.assume_init() };
    let secs = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 * 1e-6;
    (secs(ru.ru_utime) + secs(ru.ru_stime), ru.ru_maxrss as f64)
}

#[cfg(not(unix))]
fn usage() -> (f64, f64) {
    (0.0, 0.0)
}

/// Build one rung's archive beside the bench's corpora if it is not there.
///
/// The arguments are the bench's own (`-ma5 -ep -idq -y -m5`) with the
/// dictionary moved, so a rung differs from the `md128k` and `md256m` legs
/// in the dictionary and in nothing else.
fn rung(dir: &Path, md: &str) -> Option<PathBuf> {
    let archive = dir.join(format!("ladder_text_64m_m5_md{md}.rar"));
    if archive.exists() {
        return Some(archive);
    }
    if !dir.join("text.dat").exists() {
        return None;
    }
    let ok = Command::new("rar")
        .current_dir(dir)
        .args(["a", "-ma5", "-ep", "-idq", "-y", "-m5"])
        .arg(format!("-md{md}"))
        .arg(&archive)
        .arg("text.dat")
        .status()
        .is_ok_and(|s| s.success());
    if !ok {
        let _ = std::fs::remove_file(&archive);
        return None;
    }
    Some(archive)
}

/// The rungs' archives, built once and reused by every mode.
fn archive_for(dir: &Path, md: &str) -> Option<Vec<u8>> {
    let path = rung(dir, md)?;
    let bytes = std::fs::read(path).ok()?;
    if bytes.is_empty() {
        None
    } else {
        Some(bytes)
    }
}

/// THE WIDTH LADDER, which is what says whether a rung is APPLY bound.
///
/// The tape path decodes blocks on `width` lanes and applies them on one
/// thread in archive order (SPEC-H2 3.8). If the apply stage is the bound,
/// wall stops falling as soon as the lanes can keep it fed and every
/// further lane buys nothing but CPU; if the lanes are the bound, wall
/// keeps falling. The width at which it flattens is the number of lanes a
/// rung actually needs, and the wall it flattens AT is what the apply
/// stage costs with the decode taken out of the way.
fn width_ladder(archive: &[u8], ops: u64, reps: usize) {
    println!(
        "{:>6} {:>9} {:>9} {:>8} {:>8} {:>10}",
        "width", "wall ms", "ns/op", "cpu s", "cpu/wall", "vs width 1"
    );
    let mut one = f64::NAN;
    for width in [1usize, 2, 3, 4, 6, 8, 12, 16] {
        let _ = rarkit::internals::rar5::extract_counting_scheduled(archive, width, None, true);
        let (cpu0, _) = usage();
        let mut best = f64::INFINITY;
        let start = Instant::now();
        for _ in 0..reps {
            let at = Instant::now();
            rarkit::internals::rar5::extract_counting_scheduled(archive, width, None, true)
                .expect("rarkit decodes at every width");
            best = best.min(at.elapsed().as_secs_f64());
        }
        let span = start.elapsed().as_secs_f64() / reps as f64;
        let (cpu1, _) = usage();
        let cpu = (cpu1 - cpu0) / reps as f64;
        if width == 1 {
            one = best;
        }
        println!(
            "{:>6} {:>9.2} {:>9.2} {:>8.4} {:>8.2} {:>10.3}",
            width,
            best * 1e3,
            best * 1e9 / ops.max(1) as f64,
            cpu,
            cpu / span,
            one / best
        );
    }
}

/// THE RING PROBE, which prices the wrap and nothing else.
///
/// The fast match copy in `Window::copy_match` requires `distance <= at`,
/// which is exactly "the source does not wrap the ring's end". On a 128
/// KiB dictionary the ring is 128 KiB plus the spill margin and a distance
/// may be nearly the whole of it, so that guard fails for a large share of
/// matches and each failure falls to the cold path. On a 256 MiB
/// dictionary the write point is almost always further into the ring than
/// any distance the encoder chose, so it essentially never fails.
///
/// This decodes ONE rung's member with the window INFLATED: the stream,
/// its operations and its distances are untouched, and the only thing that
/// changes is how much ring sits behind the write point. So the difference
/// between the rows is the cost of the wrap, isolated from the operation
/// count, from the cache behaviour of the encoder's choices and from
/// everything else.
///
/// It is a MEASURING probe and not a shipped path: an inflated window also
/// inflates the distance a decoder would accept, so it would admit a
/// member this corpus does not contain. The byte count is asserted on
/// every row, which is what says the decode did the same work.
fn ring_probe(archive: &[u8], expect: u64, reps: usize) {
    let members = rarkit::internals::rar5::members(archive);
    let Some(member) = members.into_iter().find(|m| !m.directory && m.method != 0) else {
        eprintln!("no LZ member in this rung");
        return;
    };
    println!(
        "# declared window {} KiB, {} unpacked bytes; the STREAM is identical on every row",
        member.window / 1024,
        member.unpacked
    );
    println!(
        "{:>12} {:>9} {:>9} {:>8} {:>8}",
        "ring KiB", "wall ms", "vs declared", "cpu s", "cpu/wall"
    );
    let mut declared = f64::NAN;
    for factor in [1u64, 2, 4, 8, 32, 128, 512] {
        let window = member.window * factor;
        // A ring larger than this says nothing more and costs the box its
        // memory; the control rung's declared window is already 256 MiB.
        if factor > 1 && window > (1 << 30) {
            continue;
        }
        let _ = rarkit::internals::rar5::decode_member_scheduled(
            &member.packed,
            member.unpacked,
            window,
            member.algorithm,
            4,
            None,
            true,
        );
        let (cpu0, _) = usage();
        let mut best = f64::INFINITY;
        let start = Instant::now();
        for _ in 0..reps {
            let at = Instant::now();
            let out = rarkit::internals::rar5::decode_member_scheduled(
                &member.packed,
                member.unpacked,
                window,
                member.algorithm,
                4,
                None,
                true,
            )
            .expect("rarkit decodes the probe row");
            assert_eq!(
                out.len() as u64,
                expect,
                "ring {window} decoded a different size"
            );
            best = best.min(at.elapsed().as_secs_f64());
        }
        let span = start.elapsed().as_secs_f64() / reps as f64;
        let (cpu1, _) = usage();
        let cpu = (cpu1 - cpu0) / reps as f64;
        if factor == 1 {
            declared = best;
        }
        println!(
            "{:>12} {:>9.2} {:>11.3} {:>8.4} {:>8.2}",
            window / 1024,
            best * 1e3,
            declared / best,
            cpu,
            cpu / span
        );
    }
}

/// THE ONE REGRESSION [`RING_FLOOR`] CAN CAUSE, priced rather than argued.
///
/// A window is allocated per STREAM, and a non solid member starts a fresh
/// stream (SPEC-H2 3.7). Reference `rar` gives a small file a small
/// dictionary, so before the floor every one of those members allocated a
/// 128 KiB ring and after it every one allocates a megabyte. An archive of
/// many small non solid members is therefore where the floor could cost
/// something, and no bench leg covers that shape: `rar5_small_solid_20k`
/// is SOLID, so its twenty thousand members share one decoder and one
/// window, and the churn never happens there.
///
/// Which way it falls is not obvious and that is exactly why it is
/// measured. `vec![0u8; n]` asks for ZEROED memory: at a megabyte that is
/// a fresh anonymous mapping the kernel already guarantees is zero and
/// nothing is memset, while at 128 KiB it can come back from the
/// allocator's freelist and be memset in user space. So the larger ring
/// may be the cheaper allocation.
fn many_small_probe(dir: &Path, count: usize, reps: usize) {
    let archive = dir.join(format!("ladder_manysmall_{count}.rar"));
    if !archive.exists() {
        let files = dir.join(format!("manysmall{count}"));
        if std::fs::create_dir_all(&files).is_err() {
            eprintln!("could not make the member directory");
            return;
        }
        let mut state: u64 = 0x2026_0921;
        for index in 0..count {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let size = 512 + (state >> 33) as usize % 3_584;
            let body: Vec<u8> = (0..size).map(|i| (i * 7 + index) as u8).collect();
            let _ = std::fs::write(files.join(format!("m{index:05}.dat")), &body);
        }
        // NO `-s`: these members must be NON SOLID, which is the whole
        // point. Each one then starts a fresh stream and allocates its own
        // window.
        let ok = Command::new("rar")
            .current_dir(dir)
            .args(["a", "-ma5", "-ep", "-idq", "-y", "-m3"])
            .arg(&archive)
            .arg(format!("manysmall{count}"))
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            let _ = std::fs::remove_file(&archive);
            eprintln!("reference `rar` could not build the many small archive");
            return;
        }
    }
    let bytes = std::fs::read(&archive).unwrap_or_default();
    if bytes.is_empty() {
        eprintln!("the many small archive is empty");
        return;
    }
    let members = rarkit::internals::rar5::members(&bytes);
    let lz_members = members
        .iter()
        .filter(|m| !m.directory && m.method != 0)
        .count();
    let solid = members.iter().filter(|m| m.solid).count();
    let windows: Vec<u64> = {
        let mut seen: Vec<u64> = members
            .iter()
            .filter(|m| !m.directory && m.method != 0)
            .map(|m| m.window)
            .collect();
        seen.sort_unstable();
        seen.dedup();
        seen
    };
    println!(
        "# {} members, {lz_members} of them LZ, {solid} solid; declared windows {:?} bytes",
        members.len(),
        windows
    );
    let _ = rarkit::internals::rar5::extract_counting(&bytes, None);
    let (cpu0, _) = usage();
    let mut best = f64::INFINITY;
    let start = Instant::now();
    for _ in 0..reps {
        let at = Instant::now();
        rarkit::internals::rar5::extract_counting(&bytes, None)
            .expect("rarkit decodes the many small archive");
        best = best.min(at.elapsed().as_secs_f64());
    }
    let span = start.elapsed().as_secs_f64() / reps as f64;
    let (cpu1, rss) = usage();
    println!(
        "{:>10} {:>9} {:>12} {:>8} {:>8} {:>8}",
        "members", "wall ms", "us/member", "cpu s", "cpu/wall", "RSS MiB"
    );
    println!(
        "{:>10} {:>9.2} {:>12.2} {:>8.4} {:>8.2} {:>8.1}",
        lz_members,
        best * 1e3,
        best * 1e6 / lz_members.max(1) as f64,
        (cpu1 - cpu0) / reps as f64,
        (cpu1 - cpu0) / reps as f64 / span,
        rss / (1 << 20) as f64
    );
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let value = |flag: &str| -> Option<String> {
        args.iter()
            .find_map(|a| a.strip_prefix(flag).map(str::to_owned))
    };
    let reps: usize = value("--reps=").and_then(|v| v.parse().ok()).unwrap_or(5);
    let rungs: Vec<String> = value("--rungs=")
        .unwrap_or_else(|| "128k,256k,512k,1m,4m,16m,64m,256m".to_owned())
        .split(',')
        .map(str::to_owned)
        .collect();
    let serial = args.iter().any(|a| a == "--serial");

    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/bench-h2");
    let _ = std::fs::create_dir_all(&dir);

    // MANY SMALL MODE: the shape where a per-stream window is allocated
    // over and over, which is the one place a larger ring could cost.
    if args.iter().any(|a| a == "--manysmall") {
        let count: usize = value("--members=")
            .and_then(|v| v.parse().ok())
            .unwrap_or(20_000);
        many_small_probe(&dir, count, reps);
        return;
    }

    if !dir.join("text.dat").exists() {
        eprintln!(
            "no {}: run `cargo bench -p rarkit --bench two_arm -- rar5_text` once to cache it",
            dir.join("text.dat").display()
        );
        std::process::exit(2);
    }

    // SAMPLE MODE: decode one rung in a loop so an external sampler has a
    // steady process to read. Only rarkit runs in this process; the oracle
    // is never called here, in this mode or any other.
    if let Some(md) = value("--sample=") {
        let seconds: f64 = value("--seconds=")
            .and_then(|v| v.parse().ok())
            .unwrap_or(20.0);
        let Some(archive) = archive_for(&dir, &md) else {
            eprintln!("rung {md} could not be built");
            std::process::exit(2);
        };
        let parallel = if serial { Some(false) } else { None };
        println!(
            "sampling rung md{md} for {seconds} s, pid {}",
            std::process::id()
        );
        let start = Instant::now();
        let mut passes = 0u64;
        while start.elapsed().as_secs_f64() < seconds {
            rarkit::internals::rar5::extract_counting(&archive, parallel)
                .expect("rarkit decodes the sampled rung");
            passes += 1;
        }
        println!("{passes} passes in {:.1} s", start.elapsed().as_secs_f64());
        return;
    }

    // RING MODE: the same stream through rings of several sizes.
    if let Some(md) = value("--ring=") {
        let Some(archive) = archive_for(&dir, &md) else {
            eprintln!("rung {md} could not be built");
            std::process::exit(2);
        };
        let census = rarkit::internals::rar5::census(&archive).expect("census");
        println!(
            "# ring probe, rung md{md}, {} operations",
            census.operations
        );
        ring_probe(&archive, census.bytes, reps);
        return;
    }

    // WIDTH MODE: the lane ladder on one rung.
    if let Some(md) = value("--width=") {
        let Some(archive) = archive_for(&dir, &md) else {
            eprintln!("rung {md} could not be built");
            std::process::exit(2);
        };
        let census = rarkit::internals::rar5::census(&archive).expect("census");
        println!(
            "# width ladder, rung md{md}, {} operations",
            census.operations
        );
        width_ladder(&archive, census.operations, reps);
        return;
    }

    let parallel = if serial { Some(false) } else { None };
    println!(
        "# rarkit arm only, {} decode, {reps} reps, best wall per rung; the oracle is NOT called",
        if serial { "SERIAL" } else { "parallel" }
    );
    println!(
        "{:>6} {:>12} {:>7} {:>9} {:>10} {:>9} {:>9} {:>9} {:>8} {:>8} {:>8}",
        "md",
        "ops",
        "blocks",
        "matches",
        "lit runs",
        "bytes/op",
        "wall ms",
        "ns/op",
        "cpu s",
        "cpu/wall",
        "RSS MiB"
    );
    for md in &rungs {
        let Some(path) = rung(&dir, md) else {
            println!("{md:>6} could not be built by reference `rar`");
            continue;
        };
        let archive = std::fs::read(&path).unwrap_or_default();
        if archive.is_empty() {
            println!("{md:>6} empty archive");
            continue;
        }
        let census = match rarkit::internals::rar5::census(&archive) {
            Ok(c) => c,
            Err(err) => {
                println!("{md:>6} census failed: {err}");
                continue;
            }
        };
        let blocks = rarkit::internals::rar5::plan_shape(&archive)
            .map(|(b, _, _)| b)
            .unwrap_or(0);
        let runs = census
            .operations
            .saturating_sub(census.matches + census.repeats + census.filters);

        // Warm once, then take the BEST of `reps`: this lab is untimed and
        // runs on a box somebody is using, so the minimum is the least
        // contaminated statistic available here. It is a profile, not a
        // gate figure, and is never quoted as one.
        let _ = rarkit::internals::rar5::extract_counting(&archive, parallel);
        let (cpu0, _) = usage();
        let mut best = f64::INFINITY;
        let start = Instant::now();
        for _ in 0..reps {
            let at = Instant::now();
            let bytes = rarkit::internals::rar5::extract_counting(&archive, parallel)
                .expect("rarkit decodes its own ladder rung");
            assert_eq!(bytes, census.bytes, "rung {md} decoded a different size");
            best = best.min(at.elapsed().as_secs_f64());
        }
        let span = start.elapsed().as_secs_f64();
        let (cpu1, rss) = usage();
        let cpu = (cpu1 - cpu0) / reps as f64;
        println!(
            "{:>6} {:>12} {:>7} {:>9} {:>10} {:>9.1} {:>9.2} {:>9.2} {:>8.4} {:>8.2} {:>8.1}",
            md,
            census.operations,
            blocks,
            census.matches,
            runs,
            census.bytes as f64 / census.operations.max(1) as f64,
            best * 1e3,
            best * 1e9 / census.operations.max(1) as f64,
            cpu,
            cpu / (span / reps as f64),
            rss / (1 << 20) as f64
        );
    }
}
