//! `io_ceiling`: the raw I/O and memory CEILINGS under the big-media extract
//! row, so every rarkit figure on that row can be written as a fraction of
//! what the box can do at all.
//!
//! It is a measuring probe and not an extractor. Each cell moves `size`
//! bytes the way one part of `rarfast x`, `t` or `p` moves them, with the
//! rest of the pipeline absent, and prints the rate:
//!
//! | cell | what it measures |
//! |---|---|
//! | `memcpy` | a user-space copy, T threads |
//! | `crc32` | rarkit's own CRC32 over a warm buffer, T threads |
//! | `write_cached` | `pwrite` of 4 MiB into a preallocated file through the page cache, T threads on one handle, then the flush timed apart: the process wall and the DATA ON DISK wall |
//! | `write_direct` | the same past the cache (`O_DIRECT`, `F_NOCACHE`, `FILE_FLAG_NO_BUFFERING`) at queue depth Q (Q threads, ONE handle, 4 MiB blocks interleaved) |
//! | `write_handles` | `write_direct` with a handle PER THREAD to the one file (a synchronous NT handle serialises its own writes; this says what the disk takes when they are not) |
//! | `read_warm` | `pread` of a page-cached file into 4 KiB-aligned buffers, T threads, in 256 KiB (rarkit's piece) and 4 MiB calls |
//! | `read_cold` | the same after the cache is dropped (root), cached and direct, at queue depth Q |
//! | `pipe` | `write` into a pipe read by `cat`, 64 KiB and 1 MiB calls, and with the pipe grown to 1 MiB where the OS allows |
//!
//!     io_ceiling <dir> [size_mib] [cells] [threads] [qd]
//!
//! `cells` is a comma list of the names above or `all` (default);
//! `threads` and `qd` are comma lists (defaults `1,2,4,8,16` and `1,2,4,8,16`).
//! One `key=value` line per cell on stdout; CPU seconds are the process's
//! (`getrusage`) delta over the cell on Unix, absent on Windows. The file
//! is removed at the end.
//!
//! Safe Rust but for three thin calls with no safe wrapper in std: `fcntl`
//! (macOS `F_NOCACHE`, Linux `F_SETPIPE_SZ`) and `getrusage`, each behind
//! its own `#[allow(unsafe_code)]` with its argument written beside it.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

const PAGE: usize = 4096;
/// The direct write's block, 4 MiB unless `IO_CEILING_BLOCK_MIB` says
/// otherwise (the seam's stored slab is 1 MiB at the default budget).
fn block() -> usize {
    std::env::var("IO_CEILING_BLOCK_MIB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&m| (1..=64).contains(&m))
        .unwrap_or(4)
        << 20
}
const PIECE: usize = 256 << 10;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dir = PathBuf::from(
        args.first()
            .expect("io_ceiling <dir> [size_mib] [cells] [threads] [qd]"),
    );
    let size_mib: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(12288);
    let size = size_mib << 20;
    let cells: Vec<String> = args
        .get(2)
        .map(|s| s.split(',').map(str::to_string).collect())
        .unwrap_or_else(|| vec!["all".to_string()]);
    let threads = list(args.get(3), &[1, 2, 4, 8, 16]);
    let qds = list(args.get(4), &[1, 2, 4, 8, 16]);
    let want = |name: &str| cells.iter().any(|c| c == "all" || c == name);

    println!(
        "io_ceiling os={} arch={} dir={} size_mib={} cpus={}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        dir.display(),
        size_mib,
        std::thread::available_parallelism().map_or(0, |n| n.get())
    );

    if want("memcpy") {
        for &t in &threads {
            memcpy_cell(t);
        }
    }
    if want("crc32") {
        for &t in &threads {
            crc32_cell(t);
        }
    }

    let path = dir.join(format!("io_ceiling.{}.bin", std::process::id()));
    let mut on_disk = false;
    if want("write_cached") {
        for &t in &threads {
            write_cell(&path, size, t, Direct::No);
            on_disk = true;
        }
    }
    if want("write_direct") {
        for &q in &qds {
            write_cell(&path, size, q, Direct::One);
            on_disk = true;
        }
    }
    if want("write_handles") {
        for &q in &qds {
            write_cell(&path, size, q, Direct::PerThread);
            on_disk = true;
        }
    }
    if want("read_warm") || want("read_cold") {
        if !on_disk {
            // Something to read: one cached write, unreported.
            write_file(&path, size, 1, Direct::No);
        }
        if want("read_warm") {
            // A pass that puts the whole file in the cache, whatever wrote it.
            read_file(&path, size, 4, block(), false);
            for &t in &threads {
                read_cell(&path, size, t, PIECE, false, "warm");
                read_cell(&path, size, t, block(), false, "warm");
            }
        }
        if want("read_cold") {
            for &q in &qds {
                let state = drop_caches();
                read_cell(&path, size, q, 1 << 20, false, state);
                let state = drop_caches();
                read_cell(&path, size, q, block(), true, state);
            }
        }
    }
    let _ = std::fs::remove_file(&path);

    if want("pipe") {
        let bytes = size.min(4 << 30);
        pipe_cell(bytes, 64 << 10, false);
        pipe_cell(bytes, 1 << 20, false);
        pipe_cell(bytes, 1 << 20, true);
    }
}

fn list(arg: Option<&String>, default: &[usize]) -> Vec<usize> {
    arg.map(|s| s.split(',').filter_map(|n| n.parse().ok()).collect())
        .unwrap_or_else(|| default.to_vec())
}

/// A buffer of `len` bytes starting on a page boundary, its store beside it.
fn aligned(len: usize) -> (Vec<u8>, usize) {
    let store = vec![0u8; len + PAGE];
    let at = store.as_ptr().align_offset(PAGE);
    (store, at)
}

fn fill(buf: &mut [u8], seed: usize) {
    // Not compressible by a filesystem, not zero: a cheap LCG byte stream.
    let mut x = (seed as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    for chunk in buf.chunks_mut(8) {
        x = x
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let b = x.to_le_bytes();
        chunk.copy_from_slice(&b[..chunk.len()]);
    }
}

struct Clock {
    started: Instant,
    ru: (f64, f64),
}

impl Clock {
    fn start() -> Clock {
        Clock {
            started: Instant::now(),
            ru: rusage(),
        }
    }
    /// Wall, user and sys seconds since the start.
    fn read(&self) -> (f64, f64, f64) {
        let (u, s) = rusage();
        (
            self.started.elapsed().as_secs_f64(),
            u - self.ru.0,
            s - self.ru.1,
        )
    }
}

fn gbps(bytes: u64, secs: f64) -> f64 {
    if secs > 0.0 {
        bytes as f64 / secs / 1e9
    } else {
        0.0
    }
}

fn memcpy_cell(threads: usize) {
    let per = 256usize << 20;
    let reps = 8u64;
    let clock = Clock::start();
    std::thread::scope(|s| {
        for i in 0..threads {
            s.spawn(move || {
                let (mut src, sa) = aligned(per);
                fill(&mut src[sa..sa + per], i);
                let (mut dst, da) = aligned(per);
                for _ in 0..reps {
                    dst[da..da + per].copy_from_slice(&src[sa..sa + per]);
                    std::hint::black_box(&dst);
                }
            });
        }
    });
    let (w, u, sy) = clock.read();
    let bytes = per as u64 * reps * threads as u64;
    println!(
        "cell=memcpy threads={threads} bytes={bytes} wall_s={w:.3} GBps={:.2} user_s={u:.2} sys_s={sy:.2}",
        gbps(bytes, w)
    );
}

fn crc32_cell(threads: usize) {
    let per = 256usize << 20;
    let reps = 8u64;
    let clock = Clock::start();
    std::thread::scope(|s| {
        for i in 0..threads {
            s.spawn(move || {
                let (mut src, sa) = aligned(per);
                fill(&mut src[sa..sa + per], i);
                let mut acc = 0u32;
                for _ in 0..reps {
                    acc ^= rarkit::checksum::crc32(&src[sa..sa + per]);
                }
                std::hint::black_box(acc);
            });
        }
    });
    let (w, u, sy) = clock.read();
    let bytes = per as u64 * reps * threads as u64;
    println!(
        "cell=crc32 threads={threads} bytes={bytes} wall_s={w:.3} GBps={:.2} user_s={u:.2} sys_s={sy:.2}",
        gbps(bytes, w)
    );
}

/// `pwrite` on the platform's own call: no shared cursor between threads.
fn pwrite(file: &File, buf: &[u8], off: u64) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.write_all_at(buf, off)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut done = 0;
        while done < buf.len() {
            let n = file.seek_write(&buf[done..], off + done as u64)?;
            if n == 0 {
                return Err(std::io::Error::other("short write"));
            }
            done += n;
        }
        Ok(())
    }
}

fn pread(file: &File, buf: &mut [u8], off: u64) -> std::io::Result<usize> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.read_at(buf, off)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        file.seek_read(buf, off)
    }
}

/// How a direct write is spread over threads.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Direct {
    /// Cached.
    No,
    /// One direct handle shared by every thread.
    One,
    /// A direct handle per thread.
    PerThread,
}

/// The platform's "past the cache" open, or `None` where there is none:
/// for reading, or for writing (`create` makes and truncates the file).
fn open_direct(path: &Path, write: bool, create: bool) -> Option<File> {
    let mut o = OpenOptions::new();
    o.read(true);
    if write {
        o.write(true);
    }
    if create {
        o.create(true).truncate(true);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_DIRECT, asm-generic (x86-64 and aarch64 alike): 0o40000.
        o.custom_flags(0x4000);
        o.open(path).ok()
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        let f = o.open(path).ok()?;
        // F_NOCACHE = 48: reads and writes bypass the unified buffer cache.
        (fcntl(f.as_raw_fd(), 48, 1) >= 0).then_some(f)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_NO_BUFFERING.
        o.custom_flags(0x2000_0000);
        o.open(path).ok()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        None
    }
}

/// Write `size` bytes to `path` on `threads` threads through one handle,
/// each block of 4 MiB going to thread `block % threads`, into a file whose
/// length is set first (as `rarfast x` reserves). Returns the process wall
/// and the flush wall, or `None` where the direct open is refused.
fn write_file(path: &Path, size: u64, threads: usize, how: Direct) -> Option<(f64, f64, f64, f64)> {
    let _ = std::fs::remove_file(path);
    let direct = how != Direct::No;
    let file = if direct {
        open_direct(path, true, true)?
    } else {
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .ok()?
    };
    file.set_len(size).ok()?;
    // A handle per thread, opened before the clock starts.
    let mut own: Vec<Option<File>> = Vec::with_capacity(threads);
    for _ in 0..threads {
        own.push(if how == Direct::PerThread {
            Some(open_direct(path, true, false)?)
        } else {
            None
        });
    }
    let blocks = size.div_ceil(block() as u64);
    let failed = std::sync::atomic::AtomicBool::new(false);
    let clock = Clock::start();
    std::thread::scope(|s| {
        for (t, mine) in own.iter().enumerate() {
            let file = mine.as_ref().unwrap_or(&file);
            let failed = &failed;
            s.spawn(move || {
                let (mut store, at) = aligned(block());
                fill(&mut store[at..at + block()], t + 1);
                let mut b = t as u64;
                while b < blocks {
                    let off = b * block() as u64;
                    let n = (size - off).min(block() as u64) as usize;
                    // A direct write is whole sectors: the tail is padded
                    // inside the reserved length, as the extractor pads.
                    let n = if direct { n.div_ceil(PAGE) * PAGE } else { n };
                    if pwrite(file, &store[at..at + n], off).is_err() {
                        failed.store(true, std::sync::atomic::Ordering::Relaxed);
                        return;
                    }
                    b += threads as u64;
                }
            });
        }
    });
    let (w, u, sy) = clock.read();
    if failed.load(std::sync::atomic::Ordering::Relaxed) {
        return None;
    }
    let flush = Instant::now();
    file.sync_all().ok()?;
    let f = flush.elapsed().as_secs_f64();
    let _ = file.set_len(size);
    Some((w, f, u, sy))
}

fn write_cell(path: &Path, size: u64, threads: usize, how: Direct) {
    let cell = match how {
        Direct::No => "write_cached",
        Direct::One => "write_direct",
        Direct::PerThread => "write_handles",
    };
    match write_file(path, size, threads, how) {
        Some((w, f, u, sy)) => println!(
            "cell={cell} threads={threads} bytes={size} wall_s={w:.3} GBps={:.2} flush_s={f:.3} ondisk_s={:.3} ondisk_GBps={:.2} user_s={u:.2} sys_s={sy:.2}",
            gbps(size, w),
            w + f,
            gbps(size, w + f)
        ),
        None => println!("cell={cell} threads={threads} bytes={size} unsupported=1"),
    }
}

/// Read `size` bytes of `path` on `threads` threads in `call`-byte pieces,
/// each thread its own contiguous range, or `None` where the direct open
/// is refused.
fn read_file(
    path: &Path,
    size: u64,
    threads: usize,
    call: usize,
    direct: bool,
) -> Option<(f64, f64, f64)> {
    let file = if direct {
        open_direct(path, false, false)?
    } else {
        File::open(path).ok()?
    };
    let per = size.div_ceil(threads as u64).div_ceil(PAGE as u64) * PAGE as u64;
    let failed = std::sync::atomic::AtomicBool::new(false);
    let clock = Clock::start();
    std::thread::scope(|s| {
        for t in 0..threads {
            let file = &file;
            let failed = &failed;
            s.spawn(move || {
                let (mut store, at) = aligned(call);
                let start = per * t as u64;
                let end = (start + per).min(size);
                let mut off = start;
                let mut sum = 0u64;
                while off < end {
                    let n = ((end - off) as usize).min(call);
                    let n = if direct { n.div_ceil(PAGE) * PAGE } else { n };
                    match pread(file, &mut store[at..at + n], off) {
                        Ok(0) | Err(_) => {
                            failed.store(true, std::sync::atomic::Ordering::Relaxed);
                            return;
                        }
                        Ok(got) => {
                            sum = sum.wrapping_add(u64::from(store[at]));
                            off += got as u64;
                        }
                    }
                }
                std::hint::black_box(sum);
            });
        }
    });
    let (w, u, sy) = clock.read();
    (!failed.load(std::sync::atomic::Ordering::Relaxed)).then_some((w, u, sy))
}

fn read_cell(path: &Path, size: u64, threads: usize, call: usize, direct: bool, state: &str) {
    let cell = if direct { "read_direct" } else { "read_cached" };
    match read_file(path, size, threads, call, direct) {
        Some((w, u, sy)) => println!(
            "cell={cell} cache={state} threads={threads} call_kib={} bytes={size} wall_s={w:.3} GBps={:.2} user_s={u:.2} sys_s={sy:.2}",
            call >> 10,
            gbps(size, w)
        ),
        None => println!("cell={cell} cache={state} threads={threads} call_kib={} unsupported=1", call >> 10),
    }
}

/// Drop the page cache where the box allows it, saying which it was.
fn drop_caches() -> &'static str {
    let _ = Command::new("sync").status();
    #[cfg(target_os = "linux")]
    {
        if std::fs::write("/proc/sys/vm/drop_caches", "3\n").is_ok() {
            return "cold";
        }
    }
    #[cfg(target_os = "macos")]
    {
        if Command::new("purge").status().is_ok_and(|s| s.success()) {
            return "cold";
        }
    }
    "WARM"
}

fn pipe_cell(bytes: u64, call: usize, grow: bool) {
    let Ok(mut child) = Command::new("cat")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
    else {
        println!("cell=pipe call_kib={} unsupported=1", call >> 10);
        return;
    };
    let mut stdin = child.stdin.take().expect("piped");
    let grown = if grow { grow_pipe(&stdin) } else { 0 };
    if grow && grown == 0 {
        println!("cell=pipe call_kib={} grown=0 unsupported=1", call >> 10);
        drop(stdin);
        let _ = child.wait();
        return;
    }
    let (mut store, at) = aligned(call);
    fill(&mut store[at..at + call], 7);
    let clock = Clock::start();
    let mut left = bytes;
    while left > 0 {
        let n = left.min(call as u64) as usize;
        if stdin.write_all(&store[at..at + n]).is_err() {
            break;
        }
        left -= n as u64;
    }
    drop(stdin);
    let _ = child.wait();
    let (w, u, sy) = clock.read();
    println!(
        "cell=pipe call_kib={} pipe_grown_to={grown} bytes={bytes} wall_s={w:.3} GBps={:.2} user_s={u:.2} sys_s={sy:.2}",
        call >> 10,
        gbps(bytes, w)
    );
}

/// Grow the pipe to 1 MiB where the OS has such a call; the size it took.
#[cfg(target_os = "linux")]
fn grow_pipe(stdin: &std::process::ChildStdin) -> i32 {
    use std::os::fd::AsRawFd;
    // F_SETPIPE_SZ = 1031.
    let r = fcntl(stdin.as_raw_fd(), 1031, 1 << 20);
    r.max(0)
}

#[cfg(not(target_os = "linux"))]
fn grow_pipe(_stdin: &std::process::ChildStdin) -> i32 {
    0
}

/// `fcntl(fd, cmd, arg)` with one integer argument.
#[cfg(unix)]
#[allow(unsafe_code)]
fn fcntl(fd: i32, cmd: i32, arg: i32) -> i32 {
    // SAFETY: `fcntl` is a plain system call taking an open descriptor and
    // two integers; the descriptor is one this process holds open for the
    // length of the call (the caller's `File` or `ChildStdin` borrow), and
    // neither command used here (`F_NOCACHE`, `F_SETPIPE_SZ`) reads or
    // writes any memory of ours.
    unsafe { libc::fcntl(fd, cmd, arg) }
}

/// The process's user and system CPU seconds so far.
#[cfg(unix)]
#[allow(unsafe_code)]
fn rusage() -> (f64, f64) {
    let mut ru = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: `getrusage` writes exactly one `rusage` into the pointer it is
    // given, which is a valid, writable, correctly sized location for the
    // length of the call; it is read only after the call reports success.
    let ok = unsafe { libc::getrusage(libc::RUSAGE_SELF, ru.as_mut_ptr()) } == 0;
    if !ok {
        return (0.0, 0.0);
    }
    // SAFETY: the call succeeded, so the struct is initialised.
    let ru = unsafe { ru.assume_init() };
    let secs = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
    (secs(ru.ru_utime), secs(ru.ru_stime))
}

#[cfg(not(unix))]
fn rusage() -> (f64, f64) {
    (0.0, 0.0)
}
