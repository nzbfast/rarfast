//! The eight-member VERIFY and BLAKE2sp rows, alone in a process, priced by
//! SUBTRACTION.
//!
//! `two_arm` runs rarkit and the old engine in ONE process, so sampling it
//! samples the old engine too. This binary lives in `rarkit-cli`, whose only
//! rarkit dependency is the library itself, so a symbol-keyed profile of it
//! can only name rarkit's own code. It builds only with the `f8x16-probe`
//! feature, which no gate binary and no `make ci` target turns on.
//!
//!     f_8x16_probe <dir> <subject> <arm> [rounds] [breadth]
//!
//! Subjects, each of the gate's sizes at the gate's own switches. The
//! text is the shared test text (`rarkit_testdata::chatter`) and NOT the
//! gate's bytes, as in `f_wide_probe`; the pseudo-random member's maker
//! is the one in `crates/rarkit/tests/support/creategate.rs`:
//!
//! - `eight16`: eight 16 MiB text members, `-ma5 -m3` (`p8m3`);
//! - `eight16htb`: the same with `-htb`, a BLAKE2sp per member (`p8htb`);
//! - `onestoredblake`: one 64 MiB pseudo-random member, `-ma5 -m0 -htb`
//!   (`1sb`).
//!
//! Arms over an archive:
//!
//! - `seq-verify`: `rarkit::extract`, `Disposition::Verify`, the
//!   `f/test-8x16-m3-vsverify` rarkit arm;
//! - `seq-crc`: `rarkit::extract` into the gate's CRC32-folding writer, the
//!   `f/test-one-stored-blake` rarkit arm's shape;
//! - `wide-crc`: `rarkit::extract_parallel` at `breadth` (default 8) into
//!   the gate's writer, the `f/extract-par-8x16-*` rarkit arm;
//! - `wide-verify`: the same with `Disposition::Verify`.
//!
//! Raw arms, no archive read at all, over the subject's own plain bytes:
//!
//! - `rawcrc`: one CRC32 pass over every member, one thread;
//! - `rawblake`: one BLAKE2sp per member, one member after another;
//! - `rawblake-par`: one BLAKE2sp per member, every member on its OWN
//!   thread at once, which is the shape eight members decoded at once put
//!   their checksums in.
//!
//! Environment: `F8_TEAM` overrides every BLAKE2sp hasher's worker
//! allowance (`rarkit::checksum::probe_blake_team`), `F8_WORKERS` sets
//! `ReadOptions::workers`, `F8_CHUNK` feeds the raw BLAKE2sp arms through
//! the streaming hasher in pieces of that many bytes (unset: one shot).
//!
//! One `RESULT` line at the end: the median and minimum wall per round,
//! and for the sequential arms the pipeline split counters of the LAST
//! round. CPU seconds and peak RSS come from `/usr/bin/time -l` around it.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

const MIB: usize = 1 << 20;

/// Copied from `crates/rarkit/tests/support/creategate.rs`.
fn pseudo_random(len: usize) -> Vec<u8> {
    (0..len as u64)
        .map(|i| {
            let mut v = i.wrapping_mul(0xA24B_AED4_963E_E407).wrapping_add(1);
            v ^= v >> 31;
            v = v.wrapping_mul(0x9FB2_1C65_1E98_DF25);
            (v >> 40) as u8
        })
        .collect()
}

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
    [
        format!("{home}/bin/rar"),
        "/opt/homebrew/bin/rar".to_string(),
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|p| p.is_file())
}

/// The subject's plain members, and its reference archive, built once.
fn subject(dir: &Path, name: &str) -> (Vec<Vec<u8>>, PathBuf) {
    std::fs::create_dir_all(dir).expect("scratch dir");
    let _ = std::fs::write(dir.join(".metadata_never_index"), b"");
    let eight = || {
        let each = 16 * MIB;
        let text = rarkit_testdata::chatter(0x0816, 8 * each);
        (0..8)
            .map(|i| text[i * each..(i + 1) * each].to_vec())
            .collect::<Vec<_>>()
    };
    let (members, corpus, archive, switches): (Vec<Vec<u8>>, PathBuf, PathBuf, &[&str]) = match name
    {
        "eight16" => (
            eight(),
            dir.join("eight16"),
            dir.join("f_p8m3.rar"),
            &["-ma5", "-m3"],
        ),
        "eight16htb" => (
            eight(),
            dir.join("eight16"),
            dir.join("f_p8htb.rar"),
            &["-ma5", "-m3", "-htb"],
        ),
        "onestoredblake" => (
            vec![pseudo_random(64 * MIB)],
            dir.join("data64.bin"),
            dir.join("f_1sb.rar"),
            &["-ma5", "-m0", "-htb"],
        ),
        other => panic!("unknown subject {other}"),
    };
    if !corpus.exists() {
        if members.len() == 8 {
            std::fs::create_dir_all(&corpus).expect("eight16 dir");
            for (i, m) in members.iter().enumerate() {
                std::fs::write(corpus.join(format!("e{i}.txt")), m).expect("member file");
            }
        } else {
            std::fs::write(&corpus, &members[0]).expect("the corpus");
        }
    }
    if !archive.exists() {
        let rar = find_rar().expect("a reference rar on PATH or in ~/bin");
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
    (members, archive)
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

/// The sequential sink: the gate's writer, or `Verify`.
struct Seq {
    verify: bool,
    fold: rarkit::checksum::Crc32,
    bytes: u64,
}

impl rarkit::Sink for Seq {
    type Out = CrcWriter;

    fn open(
        &mut self,
        member: &rarkit::MemberInfo<'_>,
    ) -> rarkit::Result<rarkit::Disposition<CrcWriter>> {
        if member.is_directory {
            return Ok(rarkit::Disposition::Skip);
        }
        Ok(if self.verify {
            rarkit::Disposition::Verify
        } else {
            rarkit::Disposition::Write(CrcWriter(rarkit::checksum::Crc32::new()))
        })
    }

    fn close(
        &mut self,
        _member: &rarkit::MemberInfo<'_>,
        out: Option<CrcWriter>,
        outcome: &rarkit::MemberOutcome,
    ) -> rarkit::Result<()> {
        assert_ne!(
            outcome.checksum_ok,
            Some(false),
            "a member failed its check"
        );
        self.bytes += outcome.bytes;
        if let Some(w) = out {
            self.fold.update(&w.0.finish().to_le_bytes());
        }
        Ok(())
    }
}

/// The concurrent sink, the same two shapes.
struct Wide {
    verify: bool,
    fold: Mutex<rarkit::checksum::Crc32>,
    bytes: AtomicU64,
}

impl rarkit::ParallelSink for Wide {
    type Out = CrcWriter;

    fn open(
        &self,
        member: &rarkit::MemberInfo<'_>,
    ) -> rarkit::Result<rarkit::Disposition<CrcWriter>> {
        if member.is_directory {
            return Ok(rarkit::Disposition::Skip);
        }
        Ok(if self.verify {
            rarkit::Disposition::Verify
        } else {
            rarkit::Disposition::Write(CrcWriter(rarkit::checksum::Crc32::new()))
        })
    }

    fn close(
        &self,
        _member: &rarkit::MemberInfo<'_>,
        out: Option<CrcWriter>,
        outcome: &rarkit::MemberOutcome,
    ) -> rarkit::Result<()> {
        assert_ne!(
            outcome.checksum_ok,
            Some(false),
            "a member failed its check"
        );
        self.bytes.fetch_add(outcome.bytes, Ordering::SeqCst);
        if let Some(w) = out {
            self.fold
                .lock()
                .expect("own lock")
                .update(&w.0.finish().to_le_bytes());
        }
        Ok(())
    }
}

fn median(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn env_usize(key: &str) -> Option<usize> {
    std::env::var(key).ok().and_then(|v| v.parse().ok())
}

fn blake(data: &[u8], workers: usize, chunk: Option<usize>) -> [u8; 32] {
    match chunk {
        Some(c) => rarkit::checksum::probe_blake2sp_chunked(data, workers, c),
        None => rarkit::checksum::probe_blake2sp(data, workers),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 3 {
        eprintln!("usage: f_8x16_probe <dir> <subject> <arm> [rounds] [breadth]");
        std::process::exit(2);
    }
    let dir = PathBuf::from(&args[0]);
    let subject_name = args[1].as_str();
    let arm = args[2].as_str();
    let rounds: usize = args.get(3).and_then(|n| n.parse().ok()).unwrap_or(50);
    let breadth: usize = args.get(4).and_then(|n| n.parse().ok()).unwrap_or(8);
    let team = env_usize("F8_TEAM");
    let workers = env_usize("F8_WORKERS");
    let chunk = env_usize("F8_CHUNK");
    rarkit::checksum::probe_blake_team(team);

    let (members, archive) = subject(&dir, subject_name);
    let mut walls: Vec<f64> = Vec::with_capacity(rounds);
    let label = format!(
        "subject={subject_name} arm={arm} rounds={rounds} breadth={breadth} team={} workers={} chunk={}",
        team.map_or("-".into(), |n| n.to_string()),
        workers.map_or("-".into(), |n| n.to_string()),
        chunk.map_or("-".into(), |n| n.to_string()),
    );

    if arm.starts_with("raw") {
        // The allowance a raw BLAKE2sp gets is the team override when one
        // is set, else 8, the read path's default ceiling.
        let allowance = team.unwrap_or(8);
        let mut fold = 0u8;
        for _ in 0..rounds {
            let started = Instant::now();
            match arm {
                "rawcrc" => {
                    for m in &members {
                        fold ^= rarkit::checksum::crc32(m) as u8;
                    }
                }
                "rawblake" => {
                    for m in &members {
                        fold ^= blake(m, allowance, chunk)[0];
                    }
                }
                "rawblake-par" => {
                    let digests: Vec<[u8; 32]> = std::thread::scope(|s| {
                        let hands: Vec<_> = members
                            .iter()
                            .map(|m| s.spawn(move || blake(m, allowance, chunk)))
                            .collect();
                        hands.into_iter().map(|h| h.join().unwrap()).collect()
                    });
                    for d in digests {
                        fold ^= d[0];
                    }
                }
                other => panic!("unknown arm {other}"),
            }
            walls.push(started.elapsed().as_secs_f64() * 1e3);
        }
        std::hint::black_box(fold);
        let min = walls.iter().cloned().fold(f64::MAX, f64::min);
        println!(
            "RESULT {label} bytes={} median_ms={:.3} min_ms={min:.3}",
            members.iter().map(Vec::len).sum::<usize>(),
            median(&mut walls)
        );
        return;
    }

    let bytes = std::fs::read(&archive).expect("the archive is readable");
    let sources: Vec<Arc<dyn rarkit::RangeSource>> = vec![Arc::new(bytes)];
    let options = rarkit::ReadOptions::default().with_workers(workers);
    let verify = arm.ends_with("verify");
    let mut out_bytes = 0u64;
    let mut split = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let mut lanes = 0usize;
    for _ in 0..rounds {
        rarkit::probe::reset_pipeline_split();
        rarkit::probe::reset_peak_lanes();
        let started = Instant::now();
        match arm {
            "seq-verify" | "seq-crc" => {
                let mut sink = Seq {
                    verify,
                    fold: rarkit::checksum::Crc32::new(),
                    bytes: 0,
                };
                rarkit::extract(sources.clone(), &options, &mut sink, &mut ())
                    .expect("the corpus extracts");
                out_bytes = sink.bytes;
                std::hint::black_box(sink.fold.finish());
            }
            "wide-verify" | "wide-crc" => {
                let sink = Wide {
                    verify,
                    fold: Mutex::new(rarkit::checksum::Crc32::new()),
                    bytes: AtomicU64::new(0),
                };
                rarkit::extract_parallel(sources.clone(), &options, &sink, breadth)
                    .expect("the corpus extracts");
                out_bytes = sink.bytes.load(Ordering::SeqCst);
                std::hint::black_box(sink.fold.lock().expect("own lock").finish());
            }
            other => panic!("unknown arm {other}"),
        }
        walls.push(started.elapsed().as_secs_f64() * 1e3);
        split = rarkit::probe::pipeline_split();
        lanes = rarkit::probe::peak_lanes();
    }
    let min = walls.iter().cloned().fold(f64::MAX, f64::min);
    let med = median(&mut walls);
    let (apply_waits, apply_wait_ns, apply_busy_ns, lane_waits, lane_wait_ns, lane_decode_ns) =
        split;
    println!(
        "RESULT {label} bytes={out_bytes} median_ms={med:.3} min_ms={min:.3} \
         apply_waits={apply_waits} apply_wait_ms={:.3} apply_busy_ms={:.3} lane_waits={lane_waits} \
         lane_wait_ms={:.3} lane_decode_ms={:.3} peak_lanes={lanes}",
        apply_wait_ns as f64 / 1e6,
        apply_busy_ns as f64 / 1e6,
        lane_wait_ns as f64 / 1e6,
        lane_decode_ns as f64 / 1e6,
    );
}
