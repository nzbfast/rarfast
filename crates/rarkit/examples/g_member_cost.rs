//! The per-member create cost probe: every file
//! under a directory written as its own member of ONE non-solid RAR 5
//! archive through the public `Writer`, as the create rivals round's
//! rarkit arm writes it, `--repeat` times over, so a sampler attached
//! after start-up sees only the write. One JSON line per write on stdout:
//! its wall, the process's retired instructions and cycles over the write
//! alone (`proc_pid_rusage`, macOS; zero elsewhere, where `perf stat` over
//! the whole process is the caller's), and the archive's size and CRC32
//! so arms can be compared by bytes.
//!
//!     g_member_cost <dir> <level> [--repeat N] [--threads N] [--reader]
//!         [--out FILE]
//!
//! `--threads N` sets `WriteOptions::workers` and wants
//! `RAYON_NUM_THREADS=N` in the environment, as `create_rivals` does.
//! `--out FILE` writes the last archive to FILE.

use rarkit::{HostOs, MemberSpec, Payload, Timestamp, WriteMethod, WriteOptions, Writer};
use std::path::{Path, PathBuf};
use std::time::Instant;

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("the directory reads") {
        let path = entry.expect("an entry").path();
        if path.is_dir() {
            walk(&path, out);
        } else if path.is_file() {
            out.push(path);
        }
    }
}

/// A `/` separated name, the bytes, the whole-second mtime, the mode.
type Member = (Vec<u8>, Vec<u8>, i64, u32);

fn tree(root: &Path) -> Vec<Member> {
    let mut paths = Vec::new();
    walk(root, &mut paths);
    let mut members: Vec<Member> = paths
        .into_iter()
        .map(|p| {
            let name = p
                .strip_prefix(root)
                .expect("under root")
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/")
                .into_bytes();
            let data = std::fs::read(&p).expect("the file reads");
            let meta = std::fs::metadata(&p).expect("metadata");
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs() as i64);
            (name, data, mtime, mode(&meta))
        })
        .collect();
    members.sort_by(|x, y| x.0.cmp(&y.0));
    members
}

#[cfg(unix)]
fn mode(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode()
}

#[cfg(not(unix))]
fn mode(_meta: &std::fs::Metadata) -> u32 {
    0o100644
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

fn write(members: &[Member], level: u8, threads: Option<usize>, reader: bool) -> Vec<u8> {
    let options = WriteOptions {
        method: WriteMethod::Compressed {
            level,
            dictionary: None,
        },
        workers: threads,
        ..WriteOptions::default()
    };
    let mut writer = Writer::new(options).expect("options");
    let mut cursors: Vec<std::io::Cursor<&[u8]>> = members
        .iter()
        .map(|m| std::io::Cursor::new(m.1.as_slice()))
        .collect();
    for ((name, data, mtime, mode), cursor) in members.iter().zip(cursors.iter_mut()) {
        let payload = if reader {
            Payload::Reader {
                reader: cursor,
                size: data.len() as u64,
                crc32: None,
            }
        } else {
            Payload::Bytes(data)
        };
        writer
            .add(MemberSpec {
                name,
                payload,
                mtime: Some(Timestamp {
                    unix_seconds: *mtime,
                    nanos: 0,
                }),
                attributes: *mode,
                host_os: HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    out
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!(
            "usage: g_member_cost <dir> <level> [--repeat N] [--threads N] [--reader] [--out FILE]"
        );
        std::process::exit(2);
    }
    let dir = PathBuf::from(&args[0]);
    let level: u8 = args[1].parse().expect("level");
    let mut repeat = 1usize;
    let mut threads = None;
    let mut reader = false;
    let mut out = None;
    let mut it = args[2..].iter();
    while let Some(k) = it.next() {
        match k.as_str() {
            "--repeat" => repeat = it.next().expect("N").parse().expect("N"),
            "--threads" => threads = Some(it.next().expect("N").parse().expect("N")),
            "--reader" => reader = true,
            "--out" => out = Some(PathBuf::from(it.next().expect("FILE"))),
            _ => panic!("unknown argument {k}"),
        }
    }
    let members = tree(&dir);
    let input: usize = members.iter().map(|m| m.1.len()).sum();
    let mut last = Vec::new();
    for r in 0..repeat {
        let (i0, c0) = instructions_and_cycles();
        let t = Instant::now();
        last = write(&members, level, threads, reader);
        let wall = t.elapsed().as_secs_f64();
        let (i1, c1) = instructions_and_cycles();
        println!(
            "{{\"repeat\":{r},\"members\":{},\"input_bytes\":{input},\"wall_s\":{wall:.4},\
             \"instructions\":{},\"cycles\":{},\"archive_bytes\":{},\"crc32\":\"{:08x}\"}}",
            members.len(),
            i1.wrapping_sub(i0),
            c1.wrapping_sub(c0),
            last.len(),
            rarkit::checksum::crc32(&last)
        );
    }
    if let Some(path) = out {
        std::fs::write(path, &last).expect("the archive writes");
    }
}
