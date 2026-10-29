//! The store sampler's count: where one
//! of spec G 3.8.3's 64 KiB samples spends its time.
//!
//!     g_store_sample_probe census <path>...
//!     g_store_sample_probe stage <mask|whole|fresh> <rounds> [--most N] <path>...
//!
//! `census` walks the paths and, for every file of at least 1 MiB, runs
//! the rule's vote as the writer runs it for bytes in memory (the whole
//! file's sixteen samples, stopped at the sample that settles it) and
//! prints one line a file: its size, the misses allowed, the samples
//! packed, the misses, the verdict and each packed sample's length.
//!
//!     g_store_sample_probe check <stride> <path>...
//!     g_store_sample_probe vote <file>...
//!     g_store_sample_probe vote-whole <file>...
//!
//! `check` packs every window of up to 64 KiB at each multiple of
//! `stride` of every file both ways, the rule's packed sample and the
//! length alone (stage mask 256), and fails on the first lengths that
//! differ.
//!
//!     g_store_sample_probe vote-all <file>...
//!
//! `vote` prints the vote as the writer takes it for a READER payload,
//! which is what `rarfast` hands it for every file: over the file's
//! first 32 MiB, with the misses its whole size allows. `vote-whole` takes
//! the same vote over the WHOLE file, reading each sample where it lies:
//! what a payload that can seek would allow. `vote-all` reads all sixteen
//! of the whole file's samples and prints the verdict by the miss count
//! alone and with a floor on what the samples taken pack to together.
//!
//! `stage` gathers the samples a census would pack (at most `--most` of
//! them, spread over the files) and runs one arm over all of them,
//! `rounds` times: a mask of `internals::writers::StoreSampleStages`'
//! stages, `whole` (the rule's packed sampler, kept between samples),
//! `fresh` (one built per sample) or `counted` (the rule's default since
//! 1 Oct 2026: the length counted, the sample not packed). One JSON line: the samples, the
//! rounds, the arm's check sum, wall, and on macOS the instructions and
//! cycles of the rounds alone (elsewhere zero: `perf stat` the process and
//! take the arm `0` away, which gathers the samples and runs no round).

use rarkit::internals::writers::{
    store_most_misses, store_probe_whole, store_sample_starts, StoreSampleStages,
};
use std::path::{Path, PathBuf};
use std::time::Instant;

const LEAST_MEMBER_BYTES: u64 = 1 << 20;

fn walk(path: &Path, out: &mut Vec<PathBuf>) {
    if path.is_dir() {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(path)
            .expect("the directory reads")
            .map(|entry| entry.expect("an entry").path())
            .collect();
        entries.sort();
        for entry in entries {
            walk(&entry, out);
        }
    } else if path.is_file() {
        out.push(path.to_path_buf());
    }
}

/// The process's retired instructions and cycles so far, every thread.
#[cfg(target_os = "macos")]
fn instructions_and_cycles() -> (u64, u64) {
    let mut info = std::mem::MaybeUninit::<libc::rusage_info_v4>::zeroed();
    // SAFETY: proc_pid_rusage writes one rusage_info_v4 for flavor
    // RUSAGE_INFO_V4 into a buffer of exactly that type.
    #[allow(unsafe_code)]
    let info = unsafe {
        let rc = libc::proc_pid_rusage(
            libc::getpid(),
            libc::RUSAGE_INFO_V4,
            info.as_mut_ptr() as *mut libc::rusage_info_t,
        );
        if rc != 0 {
            return (0, 0);
        }
        info.assume_init()
    };
    (info.ri_instructions, info.ri_cycles)
}

#[cfg(not(target_os = "macos"))]
fn instructions_and_cycles() -> (u64, u64) {
    (0, 0)
}

/// The vote over `data`, as `write::store::samples_say_store` takes it:
/// the samples packed in order until the one that settles it.
fn vote(data: &[u8]) -> (usize, Vec<u64>, bool) {
    let most = store_most_misses(data.len() as u64);
    let (starts, len) = store_sample_starts(data.len());
    let mut packed = Vec::new();
    let mut misses = 0;
    for start in starts {
        let sample = &data[start..start + len];
        let size = store_probe_whole(&[sample], false, true);
        packed.push(size);
        if size * 1000 < len as u64 * 995 {
            misses += 1;
        }
        if misses > most {
            return (most, packed, false);
        }
    }
    (most, packed, true)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = args.first().map(String::as_str).unwrap_or("");
    match mode {
        "census" => {
            let mut files = Vec::new();
            for path in &args[1..] {
                walk(Path::new(path), &mut files);
            }
            let (mut members, mut sampled, mut samples, mut stored) = (0u64, 0u64, 0u64, 0u64);
            for file in &files {
                members += 1;
                let size = std::fs::metadata(file).expect("metadata").len();
                if size < LEAST_MEMBER_BYTES {
                    continue;
                }
                let data = std::fs::read(file).expect("the file reads");
                let (most, packed, stores) = vote(&data);
                sampled += 1;
                samples += packed.len() as u64;
                stored += u64::from(stores);
                let misses = packed.iter().filter(|&&p| p * 1000 < 65_536 * 995).count();
                let lengths: Vec<String> = packed.iter().map(u64::to_string).collect();
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    size,
                    most,
                    packed.len(),
                    misses,
                    if stores { "store" } else { "pack" },
                    lengths.join(","),
                    file.display()
                );
            }
            eprintln!(
                "census: {members} files, {sampled} sampled, {samples} samples, {stored} stored"
            );
        }
        "stage" => {
            let arm = args[1].as_str();
            let rounds: usize = args[2].parse().expect("rounds");
            let mut rest = &args[3..];
            let mut most = usize::MAX;
            if rest.first().map(String::as_str) == Some("--most") {
                most = rest[1].parse().expect("--most N");
                rest = &rest[2..];
            }
            let mut files = Vec::new();
            for path in rest {
                walk(Path::new(path), &mut files);
            }
            let mut held: Vec<Vec<u8>> = Vec::new();
            for file in &files {
                let size = std::fs::metadata(file).expect("metadata").len();
                if size < LEAST_MEMBER_BYTES {
                    continue;
                }
                let data = std::fs::read(file).expect("the file reads");
                let (_, packed, _) = vote(&data);
                let (starts, len) = store_sample_starts(data.len());
                for &start in starts.iter().take(packed.len()) {
                    held.push(data[start..start + len].to_vec());
                }
            }
            if held.len() > most {
                let step = held.len() / most;
                held = held.into_iter().step_by(step).take(most).collect();
            }
            let samples: Vec<&[u8]> = held.iter().map(Vec::as_slice).collect();
            if arm == "0" {
                // Everything but the rounds: what `perf stat` over a whole
                // process takes away from every other arm.
                println!("{{\"arm\":\"0\",\"samples\":{}}}", samples.len());
                return;
            }
            let mut stages = StoreSampleStages::new(65_536);
            let (i0, c0) = instructions_and_cycles();
            let started = Instant::now();
            let mut sum = 0u64;
            for _ in 0..rounds {
                sum = match arm {
                    "whole" => store_probe_whole(&samples, false, true),
                    "fresh" => store_probe_whole(&samples, true, true),
                    "counted" => store_probe_whole(&samples, false, false),
                    mask => {
                        let mask: u32 = mask.parse().expect("a stage mask");
                        samples.iter().map(|s| stages.run(s, mask)).sum()
                    }
                };
            }
            let wall = started.elapsed();
            let (i1, c1) = instructions_and_cycles();
            let runs = (samples.len() * rounds).max(1) as f64;
            println!(
                "{{\"arm\":\"{arm}\",\"samples\":{},\"rounds\":{rounds},\"sum\":{sum},\"ns_per_sample\":{:.0},\"instr_per_sample\":{:.0},\"cycles_per_sample\":{:.0}}}",
                samples.len(),
                wall.as_nanos() as f64 / runs,
                (i1 - i0) as f64 / runs,
                (c1 - c0) as f64 / runs,
            );
        }
        "vote" | "vote-whole" => {
            // The vote as the WRITER takes it for a READER payload, which
            // is what `rarfast` hands it for every file: the span is the
            // member's first 32 MiB, the misses allowed are the declared
            // size's. `vote-whole` takes the span as the WHOLE member and
            // reads each sample where it lies (a payload that can seek).
            // One line a sample taken, then the verdict.
            use std::io::{Read, Seek, SeekFrom};
            const PREFIX: u64 = 32 << 20;
            for path in &args[1..] {
                let size = std::fs::metadata(path).expect("metadata").len();
                let span = if mode == "vote" {
                    size.min(PREFIX)
                } else {
                    size
                };
                let span = usize::try_from(span).expect("a span");
                let mut file = std::fs::File::open(path).expect("the file opens");
                let most = store_most_misses(size);
                let (starts, len) = store_sample_starts(span);
                println!("{path}: {size} bytes, span {span}, {most} misses allowed");
                let mut sample = vec![0u8; len];
                let (mut misses, mut taken) = (0, 0);
                let mut verdict = "STORE";
                for (k, start) in starts.iter().enumerate() {
                    file.seek(SeekFrom::Start(*start as u64)).expect("seek");
                    file.read_exact(&mut sample).expect("the sample reads");
                    let packed = store_probe_whole(&[&sample], false, false);
                    let miss = packed * 1000 < len as u64 * 995;
                    misses += usize::from(miss);
                    taken += 1;
                    println!(
                        "  sample {k:2} at {start:>12} packs to {packed:>6} of {len} ({:.1}%){}",
                        packed as f64 * 100.0 / len as f64,
                        if miss { "  compresses" } else { "" }
                    );
                    if misses > most {
                        verdict = "COMPRESS";
                        break;
                    }
                }
                println!("  verdict {verdict}: {misses} of the {taken} samples taken compress");
            }
        }
        "vote-all" => {
            // The whole-member vote's COUNT:
            // all sixteen samples of the whole file, none skipped, and the
            // verdict three ways. (B) the rule's miss count alone: compress
            // at the sample whose miss passes it. (A) at a floor: compress
            // at the first sample where the misses have passed the count
            // AND the samples taken so far pack together to under the
            // floor; stored where no sample is that. One tab separated
            // line a file: path, size, misses allowed, misses of sixteen,
            // the sixteen together in permille, then `verdict@samples
            // taken` for (B), (A) at 985 and (A) at 990, then each packed
            // length.
            use std::io::{Read, Seek, SeekFrom};
            for path in &args[1..] {
                let size = std::fs::metadata(path).expect("metadata").len();
                let span = usize::try_from(size).expect("a span");
                let mut file = std::fs::File::open(path).expect("the file opens");
                let most = store_most_misses(size);
                let (starts, len) = store_sample_starts(span);
                let mut sample = vec![0u8; len];
                let mut packed = Vec::new();
                for start in &starts {
                    file.seek(SeekFrom::Start(*start as u64)).expect("seek");
                    file.read_exact(&mut sample).expect("the sample reads");
                    packed.push(store_probe_whole(&[&sample], false, false));
                }
                let miss = |p: u64| p * 1000 < len as u64 * 995;
                let under = |floor: u64| {
                    let (mut misses, mut sum) = (0usize, 0u64);
                    for (k, &p) in packed.iter().enumerate() {
                        misses += usize::from(miss(p));
                        sum += p;
                        if misses > most && sum * 1000 < floor * (len * (k + 1)) as u64 {
                            return format!("COMPRESS@{}", k + 1);
                        }
                    }
                    format!("STORE@{}", packed.len())
                };
                let misses = packed.iter().filter(|&&p| miss(p)).count();
                let together =
                    packed.iter().sum::<u64>() * 1000 / (len * packed.len()).max(1) as u64;
                let lengths: Vec<String> = packed.iter().map(u64::to_string).collect();
                println!(
                    "{path}\t{size}\t{most}\t{misses}\t{together}\t{}\t{}\t{}\t{}",
                    // A floor no sum reaches is the miss count alone.
                    under(u64::MAX / (len as u64 * 64)),
                    under(985),
                    under(990),
                    lengths.join("\t")
                );
            }
        }
        "check" => {
            // Every window of up to 64 KiB at each multiple of <stride> of
            // every file: the length-only sampler against the packed one.
            let stride: usize = args[1].parse().expect("stride");
            let mut files = Vec::new();
            for path in &args[2..] {
                walk(Path::new(path), &mut files);
            }
            let mut stages = StoreSampleStages::new(65_536);
            let (mut windows, mut differ, mut full, mut bytes) = (0u64, 0u64, 0u64, 0u64);
            let (mut under, mut near) = (0u64, 0u64);
            for file in &files {
                let data = std::fs::read(file).expect("the file reads");
                let mut at = 0;
                while at < data.len() {
                    let sample = &data[at..(at + 65_536).min(data.len())];
                    let old = store_probe_whole(&[sample], false, true);
                    let new = stages.run(sample, 256);
                    windows += 1;
                    bytes += sample.len() as u64;
                    if new == 0 {
                        full += 1;
                    } else if new != old {
                        differ += 1;
                        if differ <= 20 {
                            println!(
                                "DIFFER\t{}\t{}\t{}\t{}\t{}",
                                file.display(),
                                at,
                                sample.len(),
                                old,
                                new
                            );
                        }
                    }
                    if old * 1000 < sample.len() as u64 * 995 {
                        under += 1;
                    }
                    // Within a quarter percent of the bar, either side.
                    let bar = sample.len() as u64 * 995;
                    if (old * 1000).abs_diff(bar) * 400 < bar {
                        near += 1;
                    }
                    at += stride;
                }
            }
            println!(
                "check: {} files, {windows} windows, {bytes} bytes, {differ} differ, {full} left to the packed sampler, {under} under the bar, {near} within 0.25% of it",
                files.len()
            );
            if differ != 0 {
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("usage: g_store_sample_probe census <path>... | stage <arm> <rounds> [--most N] <path>...");
            std::process::exit(2);
        }
    }
}
