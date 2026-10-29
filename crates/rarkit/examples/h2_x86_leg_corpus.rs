//! Does a writer's x86 detector still FIRE on sparse code, and at what
//! density does it stop?
//!
//! The harness has no sparse x86 filter leg, which is how a density
//! dependent result stayed invisible to three timed runs. Adding one
//! is not a matter of turning a knob: a leg is only a filter leg if the
//! WRITER frames filter records over its corpus, and the writer decides
//! that with a detector nobody here may open. So the density a leg can be
//! built at is measured before any leg is written, and this is the
//! measurement.
//!
//! For each target mean trigger gap it builds a corpus, writes it with
//! reference `rar` at `-ma5 -m3`, reads it back with rarkit, and reports
//! what the writer actually framed: how many x86 records of each type,
//! over how many bytes, and what trigger gap those framed blocks really
//! carry.
//!
//! The RAR 3 half of the question is asked in `two_arm.rs` instead, by
//! the spec J leg's own builder, because counting a RAR 3 filter record
//! needs the chain walker that only the bench binary compiles in.
//!
//! A row where a writer framed NOTHING is the useful half of the output:
//! it says a leg cannot be built at that density through that writer, and
//! it says so before a leg rests on it.
//!
//! Untimed. Nothing here is a timing measurement at all.
//!
//! Implemented from `specs/SPEC-H2-rarkit-rar5-lz.md` alone.

use std::path::PathBuf;
use std::process::Command;

use rarkit::internals::rar5::x86_filter_blocks;

/// 32 MiB, the size every x86 filter leg in the harness already uses.
const MIB32: usize = 32 << 20;

/// x86-64 shaped filler that carries no trigger byte of either kind.
///
/// These are the three shapes `two_arm.rs`'s `x86_corpus` and the spec J
/// pair's `j_code_corpus` both use, so a corpus built here differs from
/// the harness's dense one in its trigger SPACING and in nothing else.
/// None of them contains an `0xE8` or an `0xE9`, which is what lets the
/// generator cut one short to land a gap exactly.
const SHAPES: [&[u8]; 3] = [
    &[0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10],
    &[0x48, 0x8B, 0x45, 0xF8, 0x48, 0x85, 0xC0, 0x74, 0x0A],
    &[0x48, 0x83, 0xC4, 0x10, 0x5D, 0xC3, 0x90, 0x90],
];

/// `len` bytes of x86-shaped code with triggers a mean of `mean_gap`
/// bytes apart.
///
/// `calls_only` leaves the jump opcode out, which is what a type 1 record
/// is framed over.
fn sparse_code(len: usize, mean_gap: f64, seed: u64, calls_only: bool) -> Vec<u8> {
    let mut draw = rarkit_testdata::Seeded::new(seed);
    let mut out: Vec<u8> = Vec::with_capacity(len + 64);
    let mut call_next = true;
    while out.len() < len {
        // A gap drawn evenly from nothing to twice the mean.
        let mut wanted = draw.index((2.0 * mean_gap) as usize + 1);
        while wanted > 0 && out.len() < len {
            let shape = SHAPES[(draw.next_u64() % 3) as usize];
            let take = shape.len().min(wanted);
            out.extend_from_slice(&shape[..take]);
            wanted -= take;
        }
        if out.len() >= len {
            break;
        }
        let target = ((draw.next_u64() % 64) as i64 * 0x40 - out.len() as i64) as i32;
        let opcode = if calls_only || call_next { 0xE8 } else { 0xE9 };
        call_next = !call_next;
        out.push(opcode);
        out.extend_from_slice(&target.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// The corpus's OWN trigger gaps, before any writer sees it, under the
/// format's rule that the scan resumes five bytes past a trigger.
fn measured_gaps(data: &[u8], jump: bool) -> (usize, f64, f64) {
    let Some(limit) = data.len().checked_sub(4) else {
        return (0, f64::NAN, f64::NAN);
    };
    let mut gaps: Vec<f64> = Vec::new();
    let mut at = 0usize;
    let mut previous: Option<usize> = None;
    while at < limit {
        let byte = data[at];
        let hit = if jump { byte | 1 == 0xe9 } else { byte == 0xe8 };
        if hit {
            if let Some(previous) = previous {
                gaps.push((at - previous) as f64);
            }
            previous = Some(at);
            at += 5;
        } else {
            at += 1;
        }
    }
    let count = gaps.len() + usize::from(previous.is_some());
    if gaps.is_empty() {
        return (count, f64::NAN, f64::NAN);
    }
    let mean = gaps.iter().sum::<f64>() / gaps.len() as f64;
    gaps.sort_by(|a, b| a.partial_cmp(b).expect("a finite gap"));
    (count, gaps[gaps.len() / 2], mean)
}

/// What a writer actually framed, read back through rarkit.
#[derive(Default)]
struct Framed {
    blocks: usize,
    type1: usize,
    type2: usize,
    bytes: u64,
    median_gap: f64,
}

fn framed_facts(archive: &[u8]) -> Option<Framed> {
    let blocks = x86_filter_blocks(archive).ok()?;
    let mut out = Framed {
        blocks: blocks.len(),
        ..Framed::default()
    };
    let mut medians: Vec<f64> = Vec::new();
    for block in &blocks {
        if block.jump {
            out.type2 += 1;
        } else {
            out.type1 += 1;
        }
        out.bytes += block.data.len() as u64;
        let (_, median, _) = measured_gaps(&block.data, block.jump);
        if median.is_finite() {
            medians.push(median);
        }
    }
    medians.sort_by(|a, b| a.partial_cmp(b).expect("a finite median"));
    out.median_gap = medians
        .get(medians.len() / 2)
        .copied()
        .unwrap_or(f64::INFINITY);
    Some(out)
}

fn scratch_dir() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join("h2-x86-leg-corpus");
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    dir
}

/// Reference `rar` at `-ma5 -m3`: the writer every RAR 5 filter leg in
/// the harness already goes through.
fn rar5_archive(tag: &str, data: &[u8]) -> Option<Vec<u8>> {
    let dir = scratch_dir();
    let member = dir.join(format!("{tag}.dat"));
    let archive = dir.join(format!("{tag}.rar"));
    std::fs::write(&member, data).ok()?;
    let _ = std::fs::remove_file(&archive);
    let status = Command::new("rar")
        .arg("a")
        .arg("-ma5")
        .arg("-m3")
        .arg("-ep")
        .arg("-inul")
        .arg("-y")
        .arg(&archive)
        .arg(&member)
        .status()
        .ok()?;
    let _ = std::fs::remove_file(&member);
    if !status.success() {
        return None;
    }
    std::fs::read(&archive).ok()
}

/// The pinned toolchain's own `x86_64-apple-darwin` rlibs, concatenated
/// in sorted name order and cut to `len`.
///
/// The one REAL x86-64 corpus that is the same on every fleet box: the
/// toolchain is pinned, the target is the one `make cross` already gates
/// on, and the file list and its order are fixed. `/usr/bin` is real too
/// and differs from box to box, so it can be a LAB corpus and never a
/// leg.
fn rlib_corpus(len: usize) -> Vec<u8> {
    let Ok(sysroot) = Command::new("rustc").arg("--print").arg("sysroot").output() else {
        return Vec::new();
    };
    let root = String::from_utf8_lossy(&sysroot.stdout).trim().to_string();
    let dir = std::path::Path::new(&root)
        .join("lib")
        .join("rustlib")
        .join("x86_64-apple-darwin")
        .join("lib");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "rlib"))
        .collect();
    paths.sort();
    let mut out: Vec<u8> = Vec::with_capacity(len);
    // Repeated if the target's own libraries do not reach `len`, so the
    // leg is a fixed size whatever the toolchain ships.
    while out.len() < len && !paths.is_empty() {
        for path in &paths {
            if out.len() >= len {
                break;
            }
            if let Ok(bytes) = std::fs::read(path) {
                out.extend_from_slice(&bytes);
            }
        }
    }
    out.truncate(len);
    out
}

/// The toolchain's x86_64 rlibs archived as SEPARATE MEMBERS, which is
/// how a real software archive holds them.
fn rar5_multimember(tag: &str, files: &[PathBuf]) -> Option<Vec<u8>> {
    let dir = scratch_dir();
    let archive = dir.join(format!("{tag}.rar"));
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
    if !command.status().ok()?.success() {
        return None;
    }
    std::fs::read(&archive).ok()
}

/// The rlib PATHS, sorted, which is the leg's fixed file list.
fn rlib_paths() -> Vec<PathBuf> {
    let Ok(sysroot) = Command::new("rustc").arg("--print").arg("sysroot").output() else {
        return Vec::new();
    };
    let root = String::from_utf8_lossy(&sysroot.stdout).trim().to_string();
    let dir = std::path::Path::new(&root)
        .join("lib")
        .join("rustlib")
        .join("x86_64-apple-darwin")
        .join("lib");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "rlib"))
        .collect();
    paths.sort();
    paths
}

fn main() {
    let gaps: [f64; 6] = [13.0, 26.0, 40.0, 64.0, 128.0, 256.0];
    let seed = 0x2209_2026u64;

    println!("THE CORPUS AS GENERATED, before any writer sees it");
    println!();
    println!("| target mean gap | triggers | measured median | measured mean |");
    println!("|---|---|---|---|");
    for gap in gaps {
        let data = sparse_code(MIB32, gap, seed, false);
        let (count, median, mean) = measured_gaps(&data, true);
        println!("| {gap:.0} | {count} | {median:.1} | {mean:.1} |");
    }

    println!();
    println!("WHAT REFERENCE `rar -ma5 -m3` FRAMED, read back with rarkit");
    println!();
    println!("| target mean gap | archive bytes | x86 blocks | type 1 | type 2 | filtered bytes | median gap of a framed block |");
    println!("|---|---|---|---|---|---|---|");
    for gap in gaps {
        let data = sparse_code(MIB32, gap, seed, false);
        let tag = format!("rar5_gap{gap:.0}");
        let Some(archive) = rar5_archive(&tag, &data) else {
            println!("| {gap:.0} | reference rar refused the corpus | | | | | |");
            continue;
        };
        let size = archive.len();
        match framed_facts(&archive) {
            Some(facts) => println!(
                "| {gap:.0} | {size} | {} | {} | {} | {} | {:.1} |",
                facts.blocks, facts.type1, facts.type2, facts.bytes, facts.median_gap
            ),
            None => println!("| {gap:.0} | {size} | rarkit could not read it back | | | | |"),
        }
    }

    println!();
    println!("WHAT THE WRITER FRAMES OVER REAL CODE: the pinned toolchain's x86_64 rlibs");
    println!();
    let real = rlib_corpus(MIB32);
    if real.len() < MIB32 {
        println!(
            "  no x86_64-apple-darwin rlibs on this box ({} bytes gathered), so a real \
             type 1 leg cannot be built here.",
            real.len()
        );
    } else {
        match rar5_archive("rar5_rlibs", &real) {
            Some(archive) => {
                let size = archive.len();
                match framed_facts(&archive) {
                    Some(facts) => println!(
                        "  archive {size} bytes, {} blocks, {} type 1, {} type 2, {} filtered \
                         bytes, median gap of a framed block {:.1}",
                        facts.blocks, facts.type1, facts.type2, facts.bytes, facts.median_gap
                    ),
                    None => println!("  rarkit could not read the archive back"),
                }
            }
            None => println!("  reference rar refused the corpus"),
        }
    }

    println!();
    println!("CALLS ONLY (no 0xE9 anywhere): does the writer frame a TYPE 1 record?");
    println!();
    println!("| target mean gap | archive bytes | x86 blocks | type 1 | type 2 | filtered bytes | median gap of a framed block |");
    println!("|---|---|---|---|---|---|---|");
    for gap in gaps {
        let data = sparse_code(MIB32, gap, seed, true);
        let tag = format!("rar5_calls_gap{gap:.0}");
        let Some(archive) = rar5_archive(&tag, &data) else {
            println!("| {gap:.0} | reference rar refused the corpus | | | | | |");
            continue;
        };
        let size = archive.len();
        match framed_facts(&archive) {
            Some(facts) => println!(
                "| {gap:.0} | {size} | {} | {} | {} | {} | {:.1} |",
                facts.blocks, facts.type1, facts.type2, facts.bytes, facts.median_gap
            ),
            None => println!("| {gap:.0} | {size} | rarkit could not read it back | | | | |"),
        }
    }

    println!();
    println!("THE SAME RLIBS AS SEPARATE MEMBERS, which is how a real archive holds them");
    println!();
    let paths = rlib_paths();
    let raw: u64 = paths
        .iter()
        .filter_map(|path| std::fs::metadata(path).ok().map(|meta| meta.len()))
        .sum();
    println!(
        "  {} rlibs, {raw} bytes of real x86-64 material",
        paths.len()
    );
    if paths.is_empty() {
        println!("  no x86_64-apple-darwin rlibs on this box.");
    } else {
        match rar5_multimember("rar5_rlibs_members", &paths) {
            Some(archive) => {
                let size = archive.len();
                match framed_facts(&archive) {
                    Some(facts) => println!(
                        "  archive {size} bytes, {} blocks, {} type 1, {} type 2, {} filtered \
                         bytes, median gap of a framed block {:.1}",
                        facts.blocks, facts.type1, facts.type2, facts.bytes, facts.median_gap
                    ),
                    None => println!("  rarkit could not read the archive back"),
                }
            }
            None => println!("  reference rar refused the corpus"),
        }
    }

    println!();
    println!("PROBE DONE");
}
