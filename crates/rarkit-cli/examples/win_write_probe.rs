//! The WRITE PATH of `rarfast x`, alone, by phase: a measuring probe for the
//! c6 corpus's extract (`x`) rows on Windows.
//!
//! It walks a source tree (the c6 corpus as extracted), and for each file
//! writes a copy under the output directory in the shape `rarfast x`'s
//! member writer uses (`TimedFile` in `src/dialect/unrar/extract.rs`):
//! parents made, `create_new`, 1 MiB write calls (the engine's solid
//! delivery chunk), the length reserved ahead in 8 MiB steps, the mtime set
//! on the open handle, then the handle closed. Every phase is timed on its
//! own, so the wall of the write path splits into create, reserve, write,
//! mtime and close by count. The source bytes are read BEFORE the clock
//! starts for each file and are not charged.
//!
//! ARMS change one thing each against `rarkit`:
//!
//! | arm | what differs |
//! |---|---|
//! | `rarkit` | nothing: the landed shape |
//! | `plain` | no reservation |
//! | `full` | the length set ONCE, to the file's size, before the first write |
//! | `nomtime` | no mtime set |
//! | `closer<N>` | the mtime set and the handle closed on N closer threads |
//!
//! Any arm may carry OPEN OPTIONS after a `+`, Windows only (std's
//! `OpenOptionsExt`, no unsafe), several joined by `+`: `share0` (no
//! sharing while open), `shareR` (read sharing only; std's default is read,
//! write and delete), `seq` (`FILE_FLAG_SEQUENTIAL_SCAN`), `wt`
//! (`FILE_FLAG_WRITE_THROUGH`), `nci` (created `NOT_CONTENT_INDEXED`).
//! For example `rarkit+share0`.
//!
//! It is not an extractor and must not be used as one.
//!
//!     win_write_probe <source-tree> <out-dir> <arm>
//!
//! One line of `key=value` pairs on stdout, seconds to the microsecond.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime};

const CHUNK: usize = 1 << 20;
const RESERVE_STEP: u64 = 8 << 20;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Arm {
    Rarkit,
    Plain,
    Full,
    NoMtime,
    Closer(usize),
}

/// Windows open options an arm asks for after its `+`.
#[derive(Default, Clone, Copy)]
struct Open {
    share: Option<u32>,
    flags: u32,
    attributes: u32,
}

fn parse_open(mods: &[&str]) -> Option<Open> {
    let mut o = Open::default();
    for m in mods {
        match *m {
            "share0" => o.share = Some(0),
            "shareR" => o.share = Some(0x1),
            "seq" => o.flags |= 0x0800_0000,
            "wt" => o.flags |= 0x8000_0000,
            "nci" => o.attributes |= 0x2000,
            _ => return None,
        }
    }
    Some(o)
}

#[cfg(windows)]
fn apply_open(options: &mut OpenOptions, o: Open) {
    use std::os::windows::fs::OpenOptionsExt;
    if let Some(share) = o.share {
        options.share_mode(share);
    }
    if o.flags != 0 {
        options.custom_flags(o.flags);
    }
    if o.attributes != 0 {
        options.attributes(o.attributes);
    }
}

#[cfg(not(windows))]
fn apply_open(_options: &mut OpenOptions, _o: Open) {}

fn parse_arm(s: &str) -> Option<Arm> {
    Some(match s {
        "rarkit" => Arm::Rarkit,
        "plain" => Arm::Plain,
        "full" => Arm::Full,
        "nomtime" => Arm::NoMtime,
        _ => Arm::Closer(s.strip_prefix("closer")?.parse().ok().filter(|n| *n > 0)?),
    })
}

fn walk(root: &Path, rel: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root.join(rel)) else {
        return;
    };
    let mut names: Vec<_> = entries.filter_map(|e| e.ok()).collect();
    names.sort_by_key(|e| e.file_name());
    for e in names {
        let r = rel.join(e.file_name());
        match e.file_type() {
            Ok(t) if t.is_dir() => walk(root, &r, out),
            Ok(t) if t.is_file() => out.push(r),
            _ => {}
        }
    }
}

#[derive(Default)]
struct Phases {
    create: Duration,
    reserve: Duration,
    write: Duration,
    mtime: Duration,
    close: Duration,
    handoff: Duration,
    reserves: u64,
    writes: u64,
    bytes: u64,
}

/// What a closer thread finishes: the mtime, then the close.
fn finish(file: File, mtime: Option<SystemTime>) -> (Duration, Duration) {
    let t = Instant::now();
    if let Some(m) = mtime {
        let _ = file.set_modified(m);
    }
    let mt = t.elapsed();
    let t = Instant::now();
    drop(file);
    (mt, t.elapsed())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: win_write_probe <source-tree> <out-dir> <arm>");
        std::process::exit(2);
    }
    let src = PathBuf::from(&args[1]);
    let dst = PathBuf::from(&args[2]);
    let mut parts = args[3].split('+');
    let arm = parts.next().and_then(parse_arm);
    let open = parse_open(&parts.collect::<Vec<_>>());
    let (Some(arm), Some(open)) = (arm, open) else {
        eprintln!("unknown arm {}", args[3]);
        std::process::exit(2);
    };
    let mut files = Vec::new();
    walk(&src, Path::new(""), &mut files);
    let mtime = Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000));

    // Closer threads, each summing its own mtime and close time.
    let (tx, rx) = mpsc::sync_channel::<(File, Option<SystemTime>)>(256);
    let rx = std::sync::Arc::new(std::sync::Mutex::new(rx));
    let mut closers = Vec::new();
    if let Arm::Closer(n) = arm {
        for _ in 0..n {
            let rx = std::sync::Arc::clone(&rx);
            closers.push(std::thread::spawn(move || {
                let mut sum = (Duration::ZERO, Duration::ZERO);
                loop {
                    let job = rx.lock().map(|r| r.recv());
                    let Ok(Ok((file, m))) = job else { break };
                    let (a, b) = finish(file, m);
                    sum.0 += a;
                    sum.1 += b;
                }
                sum
            }));
        }
    }

    let mut p = Phases::default();
    let mut buf = Vec::new();
    let mut made = std::collections::HashSet::new();
    let wall = Instant::now();
    let mut excluded = Duration::ZERO;
    for rel in &files {
        let t = Instant::now();
        buf.clear();
        if File::open(src.join(rel))
            .and_then(|mut f| f.read_to_end(&mut buf))
            .is_err()
        {
            eprintln!("cannot read {}", rel.display());
            std::process::exit(1);
        }
        excluded += t.elapsed();

        let target = dst.join(rel);
        let t = Instant::now();
        if let Some(parent) = target.parent() {
            if made.insert(parent.to_path_buf()) {
                let _ = fs::create_dir_all(parent);
            }
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        apply_open(&mut options, open);
        let mut file = match options.open(&target) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("cannot create {}: {e}", target.display());
                std::process::exit(1);
            }
        };
        p.create += t.elapsed();

        let size = buf.len() as u64;
        let mut written = 0u64;
        let mut reserved = 0u64;
        if arm == Arm::Full && size > 0 {
            let t = Instant::now();
            let _ = file.set_len(size);
            p.reserve += t.elapsed();
            p.reserves += 1;
        }
        for piece in buf.chunks(CHUNK) {
            let want = written + piece.len() as u64;
            if matches!(arm, Arm::Rarkit | Arm::NoMtime | Arm::Closer(_))
                && want > reserved
                && want < size
            {
                let to = size.min(written + RESERVE_STEP).max(want);
                let t = Instant::now();
                if file.set_len(to).is_ok() {
                    reserved = to;
                }
                p.reserve += t.elapsed();
                p.reserves += 1;
            }
            let t = Instant::now();
            if let Err(e) = file.write_all(piece) {
                eprintln!("write failed {}: {e}", target.display());
                std::process::exit(1);
            }
            p.write += t.elapsed();
            p.writes += 1;
            written = want;
        }
        p.bytes += written;
        let m = if arm == Arm::NoMtime { None } else { mtime };
        if let Arm::Closer(_) = arm {
            let t = Instant::now();
            let _ = tx.send((file, m));
            p.handoff += t.elapsed();
        } else {
            let (a, b) = finish(file, m);
            p.mtime += a;
            p.close += b;
        }
    }
    drop(tx);
    let t = Instant::now();
    for c in closers {
        if let Ok((a, b)) = c.join() {
            p.mtime += a;
            p.close += b;
        }
    }
    let join = t.elapsed();
    let total = wall.elapsed().saturating_sub(excluded);
    println!(
        "arm={} files={} bytes={} wall={:.6} create={:.6} reserve={:.6} reserves={} write={:.6} writes={} mtime={:.6} close={:.6} handoff={:.6} join={:.6} read_excluded={:.6}",
        args[3],
        files.len(),
        p.bytes,
        total.as_secs_f64(),
        p.create.as_secs_f64(),
        p.reserve.as_secs_f64(),
        p.reserves,
        p.write.as_secs_f64(),
        p.writes,
        p.mtime.as_secs_f64(),
        p.close.as_secs_f64(),
        p.handoff.as_secs_f64(),
        join.as_secs_f64(),
        excluded.as_secs_f64(),
    );
}
