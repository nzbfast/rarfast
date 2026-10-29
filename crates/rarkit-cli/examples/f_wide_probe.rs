//! The one-member RAR 5 extract path, alone in a process, priced by
//! SUBTRACTION.
//!
//! `two_arm` runs rarkit and the old engine in ONE process, so sampling
//! that process samples the old engine too. This binary lives in
//! `rarkit-cli`, whose only rarkit dependency is the library itself, so
//! nothing of any other implementation is linked into it and a
//! symbol-keyed profile of it can only name rarkit's own code.
//!
//! The corpus is of the gate's sizes and written by the same reference
//! `rar` at the same switches as `f/extract-m3-text64` and
//! `f/extract-seq-8x16-m3`, but it is NOT the gate's bytes: the text is
//! the shared test text (`rarkit_testdata::chatter`), where the gate
//! bench keeps a maker of its own. A figure from here is this probe's
//! own and is not to be set beside a gate leg's.
//!
//!     f_wide_probe <dir> <subject> <arm> [rounds] [width]
//!
//! `subject` is `text64` (one 64 MiB member, `-ma5 -m3`), `text64m5`
//! (the same at `-m5`), `eight16` (eight 16 MiB members, `-ma5 -m3`) or
//! `text<N>` (one member of N MiB, `-ma5 -m3`, the floor ladder's rungs).
//! The arms, each the whole of `rarkit::extract` on the calling thread
//! with the volumes held in memory, exactly as the gate's rarkit arm holds
//! them:
//!
//! - `crc`: the gate leg's sink, a writer that folds every byte into a
//!   CRC32 and keeps none (`FWriter` in two_arm.rs);
//! - `verify`: `Disposition::Verify`, no writer at all, which is the
//!   `f/test-*-vsverify` shape and subtracts the sink's fold;
//! - `null`: a writer that discards, which subtracts the fold but keeps
//!   the `write_all` call;
//! - `seam-crc`, `seam-null`, `seam-verify`: the same with the seam of
//!   spec F 3.7.7 forced ON through `probe::set_seam_floor(Some(0))`;
//! - `off-crc`, `off-null`, `off-verify`: the same with the seam forced
//!   OFF, the path before the seam engaged on members with a decoder, and
//!   the BEFORE arm of a before-and-after in ONE binary;
//! - `rawcrc`: one CRC32 pass over the 64 MiB corpus in memory, the cost
//!   of ONE checksum pass on this box;
//! - `rawcopy`: one memcpy of the corpus, the cost of a ring's copy.
//!
//! `width` sets `ReadOptions::workers`; unset is the gate's `None`.
//!
//! Every round prints nothing; the end prints one `RESULT` line with the
//! median and minimum wall per round, and the pipeline split counters of
//! the LAST round (`probe::pipeline_split`, `probe::walk_stalls`,
//! `probe::peak_lanes`, `probe::peak_seam`), which say whether the apply
//! stage waited on its lanes or the lanes on it. It is NOT a bench: it
//! has one arm and reports no ratio. CPU seconds and peak RSS come from
//! `/usr/bin/time -l` around it.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;

const MIB: usize = 1 << 20;

fn find_rar() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            let cand = Path::new(dir).join("rar");
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    let home = std::env::var("HOME").unwrap_or_default();
    for cand in [
        format!("{home}/bin/rar"),
        "/opt/homebrew/bin/rar".to_string(),
        "/usr/local/bin/rar".to_string(),
    ] {
        if Path::new(&cand).is_file() {
            return Some(PathBuf::from(cand));
        }
    }
    None
}

/// The subject's corpus on disk, and its reference archive, built once.
fn subject(dir: &Path, name: &str) -> (PathBuf, PathBuf) {
    std::fs::create_dir_all(dir).expect("scratch dir");
    // Never indexed: the marker goes in before the first file.
    let _ = std::fs::write(dir.join(".metadata_never_index"), b"");
    let (corpus, archive, switches): (PathBuf, PathBuf, &[&str]) = match name {
        "text64" => (
            dir.join("text64.bin"),
            dir.join("f_m3t.rar"),
            &["-ma5", "-m3"],
        ),
        "text64m5" => (
            dir.join("text64.bin"),
            dir.join("f_m5t.rar"),
            &["-ma5", "-m5"],
        ),
        "eight16" => (
            dir.join("eight16"),
            dir.join("f_p8m3.rar"),
            &["-ma5", "-m3"],
        ),
        // `text<N>`: one member of N MiB of the same text, `-ma5 -m3`, for
        // the floor ladder.
        other => match other
            .strip_prefix("text")
            .and_then(|n| n.parse::<usize>().ok())
        {
            Some(mib) => (
                dir.join(format!("text{mib}.bin")),
                dir.join(format!("f_m3t{mib}.rar")),
                &["-ma5", "-m3"],
            ),
            None => panic!("unknown subject {other}"),
        },
    };
    if !corpus.exists() {
        if name == "eight16" {
            std::fs::create_dir_all(&corpus).expect("eight16 dir");
            let each = 16 * MIB;
            let text = rarkit_testdata::chatter(0x0816, 8 * each);
            for i in 0..8usize {
                std::fs::write(
                    corpus.join(format!("e{i}.txt")),
                    &text[i * each..(i + 1) * each],
                )
                .expect("member file");
            }
        } else {
            let mib = name
                .trim_end_matches("m5")
                .strip_prefix("text")
                .and_then(|n| n.parse::<usize>().ok())
                .unwrap_or(64);
            std::fs::write(&corpus, rarkit_testdata::chatter(0x0817, mib * MIB))
                .expect("the text corpus");
        }
    }
    if !archive.exists() {
        let rar = find_rar()
            .expect("a reference rar on PATH, ~/bin, /opt/homebrew/bin or /usr/local/bin");
        let status = Command::new(rar)
            .current_dir(dir)
            .args(["a", "-idq", "-y", "-r"])
            .args(switches)
            .arg(archive.file_name().unwrap())
            .arg(corpus.file_name().unwrap())
            .status()
            .expect("rar runs");
        assert!(status.success(), "reference rar failed");
    }
    (corpus, archive)
}

/// `FWriter` of two_arm.rs: the gate leg's writer.
struct CrcWriter(rarkit::checksum::Crc32);

impl std::io::Write for CrcWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Either the gate's writer, a discarding one, or none at all.
enum Mode {
    Crc,
    Null,
    Verify,
}

struct Probe {
    mode: Mode,
    crc: rarkit::checksum::Crc32,
    members: u64,
    bytes: u64,
}

enum Out {
    Crc(CrcWriter),
    Null(std::io::Sink),
}

impl std::io::Write for Out {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Out::Crc(w) => w.write(buf),
            Out::Null(w) => w.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl rarkit::Sink for Probe {
    type Out = Out;

    fn open(
        &mut self,
        member: &rarkit::MemberInfo<'_>,
    ) -> rarkit::Result<rarkit::Disposition<Out>> {
        if member.is_directory {
            return Ok(rarkit::Disposition::Skip);
        }
        self.members += 1;
        Ok(match self.mode {
            Mode::Crc => {
                rarkit::Disposition::Write(Out::Crc(CrcWriter(rarkit::checksum::Crc32::new())))
            }
            Mode::Null => rarkit::Disposition::Write(Out::Null(std::io::sink())),
            Mode::Verify => rarkit::Disposition::Verify,
        })
    }

    fn close(
        &mut self,
        _member: &rarkit::MemberInfo<'_>,
        out: Option<Out>,
        outcome: &rarkit::MemberOutcome,
    ) -> rarkit::Result<()> {
        self.bytes += outcome.bytes;
        if let Some(Out::Crc(w)) = out {
            self.crc.update(&w.0.finish().to_le_bytes());
        }
        Ok(())
    }
}

fn median(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 3 {
        eprintln!("usage: f_wide_probe <dir> <subject> <arm> [rounds] [width]");
        std::process::exit(2);
    }
    let dir = PathBuf::from(&args[0]);
    let subject_name = args[1].as_str();
    let arm = args[2].as_str();
    let rounds: usize = args.get(3).and_then(|n| n.parse().ok()).unwrap_or(50);
    let width: Option<usize> = args.get(4).and_then(|n| n.parse().ok());

    let (corpus, archive) = subject(&dir, subject_name);
    let bytes = std::fs::read(&archive).expect("the archive is readable");
    eprintln!(
        "subject {subject_name}: archive {} bytes at {}",
        bytes.len(),
        archive.display()
    );

    let mut walls: Vec<f64> = Vec::with_capacity(rounds);

    // The two RAW arms price one pass of the two things the seam trades.
    if arm == "rawcrc" || arm == "rawcopy" {
        let plain = if corpus.is_dir() {
            rarkit_testdata::chatter(0x0818, 64 * MIB)
        } else {
            std::fs::read(&corpus).expect("corpus")
        };
        let mut dst: Vec<u8> = vec![0u8; plain.len()];
        let mut fold = 0u32;
        for _ in 0..rounds {
            let started = Instant::now();
            if arm == "rawcrc" {
                let mut c = rarkit::checksum::Crc32::new();
                c.update(&plain);
                fold ^= c.finish();
            } else {
                dst.copy_from_slice(&plain);
                fold ^= u32::from(dst[plain.len() / 2]);
            }
            walls.push(started.elapsed().as_secs_f64() * 1e3);
        }
        std::hint::black_box(fold);
        let min = walls.iter().cloned().fold(f64::MAX, f64::min);
        println!(
            "RESULT subject={subject_name} arm={arm} width=- rounds={rounds} bytes={} median_ms={:.3} min_ms={:.3}",
            plain.len(),
            median(&mut walls),
            min
        );
        return;
    }

    // `crc`, `null`, `verify`: the engine's own answer on whether the
    // member is overlapped (the shipped floors). `seam-*`: the seam forced
    // ON. `off-*`: the seam forced OFF, which is the path before the seam
    // engaged on members with a decoder, and the BEFORE arm of any
    // before-and-after in one binary.
    let (mode, seam) = match arm {
        "crc" => (Mode::Crc, None),
        "null" => (Mode::Null, None),
        "verify" => (Mode::Verify, None),
        "seam-crc" => (Mode::Crc, Some(0)),
        "seam-null" => (Mode::Null, Some(0)),
        "seam-verify" => (Mode::Verify, Some(0)),
        "off-crc" => (Mode::Crc, Some(u64::MAX)),
        "off-null" => (Mode::Null, Some(u64::MAX)),
        "off-verify" => (Mode::Verify, Some(u64::MAX)),
        other => panic!("unknown arm {other}"),
    };
    rarkit::probe::set_seam_floor(seam);
    let sources: Vec<Arc<dyn rarkit::RangeSource>> = vec![Arc::new(bytes)];
    let mut options = rarkit::ReadOptions::default();
    options.workers = width;

    let mut fold = 0u32;
    let mut report = rarkit::ExtractReport::default();
    let mut split = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let mut stalls = (0u64, 0u64);
    let mut lanes = 0usize;
    let mut seam_units = 0usize;
    for _ in 0..rounds {
        rarkit::probe::reset_pipeline_split();
        rarkit::probe::reset_walk_stalls();
        rarkit::probe::reset_peak_lanes();
        rarkit::probe::reset_peak_seam();
        let mut sink = Probe {
            mode: match mode {
                Mode::Crc => Mode::Crc,
                Mode::Null => Mode::Null,
                Mode::Verify => Mode::Verify,
            },
            crc: rarkit::checksum::Crc32::new(),
            members: 0,
            bytes: 0,
        };
        let started = Instant::now();
        report = rarkit::extract(sources.clone(), &options, &mut sink, &mut ())
            .expect("the corpus extracts");
        walls.push(started.elapsed().as_secs_f64() * 1e3);
        fold ^= sink.crc.finish();
        split = rarkit::probe::pipeline_split();
        stalls = rarkit::probe::walk_stalls();
        lanes = rarkit::probe::peak_lanes();
        seam_units = rarkit::probe::peak_seam();
        std::hint::black_box((sink.members, sink.bytes));
    }
    std::hint::black_box(fold);
    let min = walls.iter().cloned().fold(f64::MAX, f64::min);
    let med = median(&mut walls);
    let (apply_waits, apply_wait_ns, apply_busy_ns, lane_waits, lane_wait_ns, lane_decode_ns) =
        split;
    println!(
        "RESULT subject={subject_name} arm={arm} width={} rounds={rounds} members={} bytes={} bad={} median_ms={med:.3} min_ms={min:.3} \
         apply_waits={apply_waits} apply_wait_ms={:.3} apply_busy_ms={:.3} lane_waits={lane_waits} lane_wait_ms={:.3} lane_decode_ms={:.3} \
         walk_stalls={} walk_stall_ms={:.3} peak_lanes={lanes} peak_seam={seam_units} peak_working={}",
        width.map_or("none".to_string(), |w| w.to_string()),
        report.members,
        report.bytes,
        report.checksum_failures,
        apply_wait_ns as f64 / 1e6,
        apply_busy_ns as f64 / 1e6,
        lane_wait_ns as f64 / 1e6,
        lane_decode_ns as f64 / 1e6,
        stalls.0,
        stalls.1 as f64 / 1e6,
        report.peak_working_memory,
    );
}
