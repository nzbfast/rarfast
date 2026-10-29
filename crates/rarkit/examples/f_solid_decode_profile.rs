//! UNTIMED profile of the SOLID TEST's walking thread.
//!
//! `rarkit-cli t` of a solid text set runs `rarkit::extract` with every
//! member at `Disposition::Verify`, and on the c6 shape (2 GiB of
//! `rivals_corpus.py` text at `-m3 -s`) it reads 1.14 threads against the
//! reference unrar's 1.87. This asks where the walking thread's time goes,
//! member by member, by the member's declared size, because the solid
//! chain's decode-ahead (`rar5_lz::ahead`) takes only members up to
//! `AHEAD_MEMBER_MAX` (1 MiB) and the in-member tape path only members of
//! `MT_MIN_OUTPUT` (16 MiB) or more; the band between gets neither.
//!
//! For each member it records the wall between the sink's `open` and its
//! `close`, which is that member's decode, apply and CRC on the walking
//! thread, and the gap from one `close` to the next `open`, which is the
//! headers, the lookahead's reads and its offers. Cells, interleaved and
//! rotated every round:
//!
//! - `default`: the shipped read, `ReadOptions::default()`;
//! - `ahead_off`: the same with the chain's decode-ahead refused
//!   (`probe::set_ahead_off`), which prices what it buys today;
//!
//! (A third cell, the chain's decode-ahead WIDE, was decided
//! on 23 Sep 2026 and removed with the code behind it.)
//!
//! plus a CRC32 pricing over a buffer of the same bytes, the one stage of
//! `t` a decoder change does not touch.
//!
//! Usage: `cargo run --release -p rarkit --features test-support --example
//! f_solid_decode_profile -- ARCHIVE [rounds]`. Json lines go to
//! `target/gate/solid-decode-profile-<stamp>.jsonl`.

use std::io::Write as _;
use std::sync::Arc;
use std::time::Instant;

const MIB: u64 = 1 << 20;

/// The bands, by declared size, and why each edge is where it is.
const BANDS: [(&str, u64, u64); 4] = [
    // the chain decode-ahead's reach, `AHEAD_MEMBER_MAX`
    ("le1m", 0, MIB),
    ("1m_4m", MIB + 1, 4 * MIB),
    // below the tape path's floor, `MT_MIN_OUTPUT`
    ("4m_16m", 4 * MIB + 1, 16 * MIB - 1),
    ("ge16m", 16 * MIB, u64::MAX),
];

#[cfg(unix)]
fn cpu_seconds() -> f64 {
    let mut ru = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: getrusage fills the struct it is given; RUSAGE_SELF is valid.
    #[allow(unsafe_code)]
    let ru = unsafe {
        libc::getrusage(libc::RUSAGE_SELF, ru.as_mut_ptr());
        ru.assume_init()
    };
    let t = |val: libc::timeval| val.tv_sec as f64 + val.tv_usec as f64 * 1e-6;
    t(ru.ru_utime) + t(ru.ru_stime)
}

#[cfg(not(unix))]
fn cpu_seconds() -> f64 {
    f64::NAN
}

#[derive(Default, Clone)]
struct Band {
    members: u64,
    bytes: u64,
    seconds: f64,
}

#[derive(Default)]
struct Timed {
    bands: [Band; 4],
    opened: Option<Instant>,
    last_close: Option<Instant>,
    start: Option<Instant>,
    gap: f64,
    before_first: f64,
    failed: u64,
}

fn band_of(size: u64) -> usize {
    BANDS
        .iter()
        .position(|(_, lo, hi)| size >= *lo && size <= *hi)
        .unwrap_or(3)
}

impl rarkit::Sink for Timed {
    type Out = std::io::Sink;

    fn open(
        &mut self,
        member: &rarkit::MemberInfo<'_>,
    ) -> rarkit::Result<rarkit::Disposition<std::io::Sink>> {
        if member.is_directory {
            return Ok(rarkit::Disposition::Skip);
        }
        let now = Instant::now();
        match self.last_close {
            Some(t) => self.gap += (now - t).as_secs_f64(),
            None => {
                if let Some(s) = self.start {
                    self.before_first += (now - s).as_secs_f64();
                }
            }
        }
        self.opened = Some(now);
        Ok(rarkit::Disposition::Verify)
    }

    fn close(
        &mut self,
        member: &rarkit::MemberInfo<'_>,
        _out: Option<std::io::Sink>,
        outcome: &rarkit::MemberOutcome,
    ) -> rarkit::Result<()> {
        let now = Instant::now();
        if let Some(t) = self.opened.take() {
            let size = member.unpacked_size.unwrap_or(0);
            let b = &mut self.bands[band_of(size)];
            b.members += 1;
            b.bytes += size;
            b.seconds += (now - t).as_secs_f64();
        }
        if outcome.checksum_ok == Some(false) {
            self.failed += 1;
        }
        self.last_close = Some(now);
        Ok(())
    }
}

struct Cell {
    name: &'static str,
    walls: Vec<f64>,
    cpus: Vec<f64>,
    last: Timed,
    claims: u64,
    stalls: u64,
    lanes: u64,
}

fn once(path: &str, ahead_off: bool) -> (f64, f64, Timed, u64, u64, u64) {
    let file = std::fs::File::open(path).expect("the archive opens");
    let sources: Vec<Arc<dyn rarkit::RangeSource>> = vec![Arc::new(file)];
    let options = rarkit::ReadOptions::default();
    rarkit::probe::set_ahead_off(ahead_off);
    rarkit::probe::reset_ahead_claims();
    let mut sink = Timed::default();
    let c0 = cpu_seconds();
    let t0 = Instant::now();
    sink.start = Some(t0);
    rarkit::extract(sources, &options, &mut sink, &mut ()).expect("the archive tests");
    let wall = t0.elapsed().as_secs_f64();
    let cpu = cpu_seconds() - c0;
    rarkit::probe::set_ahead_off(false);
    (
        wall,
        cpu,
        sink,
        rarkit::probe::ahead_claims(),
        rarkit::probe::ahead_stalls(),
        rarkit::probe::ahead_peak_lanes(),
    )
}

fn median(v: &[f64]) -> f64 {
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = s.len();
    if n == 0 {
        return f64::NAN;
    }
    if n % 2 == 1 {
        s[n / 2]
    } else {
        (s[n / 2 - 1] + s[n / 2]) / 2.0
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args
        .get(1)
        .expect("usage: f_solid_decode_profile ARCHIVE [rounds]");
    let rounds: usize = args.get(2).and_then(|r| r.parse().ok()).unwrap_or(5);
    std::fs::create_dir_all("target/gate").ok();
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let jpath = format!("target/gate/solid-decode-profile-{stamp}.jsonl");
    let mut jl = std::fs::File::create(&jpath).expect("jsonl opens");
    println!("jsonl {jpath}");
    println!(
        "cores {} archive {} bytes",
        std::thread::available_parallelism().map_or(0, |n| n.get()),
        std::fs::metadata(path).map_or(0, |m| m.len())
    );

    let mut cells = [
        Cell {
            name: "default",
            walls: vec![],
            cpus: vec![],
            last: Timed::default(),
            claims: 0,
            stalls: 0,
            lanes: 0,
        },
        Cell {
            name: "ahead_off",
            walls: vec![],
            cpus: vec![],
            last: Timed::default(),
            claims: 0,
            stalls: 0,
            lanes: 0,
        },
    ];
    // one warm-up of each, untimed, so the page cache holds the archive
    for off in [false, true] {
        let _ = once(path, off);
    }
    for r in 0..rounds {
        // rotated every round and reversed every other one
        let mut order = vec![0usize, 1];
        order.rotate_left(r % 2);
        if r % 2 == 1 {
            order.reverse();
        }
        for i in order {
            let (wall, cpu, timed, claims, stalls, lanes) = once(path, i == 1);
            let c = &mut cells[i];
            let bands: Vec<String> = timed
                .bands
                .iter()
                .zip(BANDS.iter())
                .map(|(b, (n, _, _))| {
                    format!(
                        "\"{n}\":{{\"members\":{},\"bytes\":{},\"s\":{:.6}}}",
                        b.members, b.bytes, b.seconds
                    )
                })
                .collect();
            writeln!(
                jl,
                "{{\"cell\":\"{}\",\"round\":{r},\"wall\":{wall:.6},\"cpu\":{cpu:.6},\"gap\":{:.6},\"before_first\":{:.6},\"claims\":{claims},\"stalls\":{stalls},\"lanes\":{lanes},\"failed\":{},{}}}",
                c.name,
                timed.gap,
                timed.before_first,
                timed.failed,
                bands.join(",")
            )
            .ok();
            println!(
                "round {r} {:10} wall {wall:.3} s cpu {cpu:.3} s threads {:.2} claims {claims} stalls {stalls} lanes {lanes} crc_failed {}",
                c.name,
                cpu / wall,
                timed.failed
            );
            assert_eq!(timed.failed, 0, "a member failed its checksum");
            c.walls.push(wall);
            c.cpus.push(cpu);
            c.last = timed;
            c.claims = claims;
            c.stalls = stalls;
            c.lanes = lanes;
        }
    }

    println!();
    println!("| cell | median wall s | median CPU s | threads | claims | stalls | peak lanes |");
    println!("|---|---:|---:|---:|---:|---:|---:|");
    for c in &cells {
        let w = median(&c.walls);
        let cpu = median(&c.cpus);
        println!(
            "| {} | {w:.3} | {cpu:.3} | {:.2} | {} | {} | {} |",
            c.name,
            cpu / w,
            c.claims,
            c.stalls,
            c.lanes
        );
    }
    println!();
    println!("walking thread, last round of each cell, open to close by band:");
    println!("| cell | band | members | MiB | seconds | share of wall | MB/s |");
    println!("|---|---|---:|---:|---:|---:|---:|");
    for c in &cells {
        let w = *c.walls.last().unwrap_or(&f64::NAN);
        for (b, (n, _, _)) in c.last.bands.iter().zip(BANDS.iter()) {
            println!(
                "| {} | {n} | {} | {:.1} | {:.3} | {:.1}% | {:.0} |",
                c.name,
                b.members,
                b.bytes as f64 / MIB as f64,
                b.seconds,
                100.0 * b.seconds / w,
                b.bytes as f64 / 1e6 / b.seconds
            );
        }
        println!(
            "| {} | gaps (close to next open) | | | {:.3} | {:.1}% | |",
            c.name,
            c.last.gap,
            100.0 * c.last.gap / w
        );
        println!(
            "| {} | before the first open | | | {:.3} | {:.1}% | |",
            c.name,
            c.last.before_first,
            100.0 * c.last.before_first / w
        );
    }

    // THE CRC, priced alone: CRC32 over 2 GiB of bytes in 1 MiB updates.
    let buf: Vec<u8> = (0..(64 * MIB) as usize)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let mut crcs = vec![];
    for _ in 0..3 {
        let t0 = Instant::now();
        let mut crc = rarkit::checksum::Crc32::new();
        for _ in 0..32 {
            for chunk in buf.chunks(MIB as usize) {
                crc.update(chunk);
            }
        }
        std::hint::black_box(crc.finish());
        crcs.push(t0.elapsed().as_secs_f64());
    }
    println!();
    println!(
        "crc32 over 2 GiB in 1 MiB updates: {:.3} s median of 3",
        median(&crcs)
    );
    writeln!(jl, "{{\"crc32_2gib_s\":{:.6}}}", median(&crcs)).ok();
    println!("PROFILE OK");
}
