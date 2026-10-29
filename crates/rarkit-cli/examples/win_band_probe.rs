//! Does a kernel COPY between a user buffer and the file cache slow down
//! when `(dst - src) mod 4096` falls in a narrow band? A measuring probe for
//! the Windows extract write path, after this finding: on Zen
//! 4 Linux a `pread` or `write` copy runs about 4x slower when that distance
//! is 1 to 15 bytes. Here the same question is put to NT's cached
//! `WriteFile` (user buffer into the cache manager) and `ReadFile` (the
//! reverse), and, as lever 2's first figure, to an unbuffered write.
//!
//! Each cell writes (or reads back) `size` bytes in 4 MiB calls from a
//! buffer whose ADDRESS is 4 KiB aligned plus `a`, at file offsets starting
//! at `o`, so the copy's distance is `(o - a) mod 4096`. The write is timed
//! without a flush (a cached write returns when the copy is done); the read
//! reads a file the write just left in the cache, twice, and times the
//! second. The unbuffered arm needs `a` and `o` both 0 and whole sectors,
//! which the probe gives it.
//!
//! Safe Rust only: the alignment comes from slicing a larger allocation at
//! the right address, and the Windows flag from std's `OpenOptionsExt`.
//! It is not an extractor and must not be used as one.
//!
//!     win_band_probe <dir> <size MiB> <reps> [write|read|nobuf]...
//!
//! One `key=value` line per cell on stdout.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::Instant;

const CALL: usize = 4 << 20;
const PAGE: usize = 4096;

/// The copy distances tried, as `(o, a)`: file offset and address offset
/// within a page. The distance is `(o - a) mod 4096`.
const CELLS: [(usize, usize); 8] = [
    (0, 0),
    (1, 0),
    (8, 0),
    (15, 0),
    (16, 0),
    (64, 0),
    (0, PAGE - 8),
    (8, 16),
];

/// A slice of `len` bytes whose address is `a` past a page boundary.
fn aligned(store: &mut [u8], a: usize, len: usize) -> &mut [u8] {
    let base = store.as_ptr() as usize;
    let skip = (PAGE - base % PAGE) % PAGE + a;
    &mut store[skip..skip + len]
}

fn write_cell(path: &Path, size: usize, o: usize, a: usize, unbuffered: bool) -> f64 {
    let mut store = vec![0u8; CALL + 2 * PAGE];
    let buf = aligned(&mut store, a, CALL);
    for (i, b) in buf.iter_mut().enumerate() {
        *b = (i * 131 + 7) as u8;
    }
    let _ = fs::remove_file(path);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(windows)]
    if unbuffered {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_NO_BUFFERING: whole sectors from sector aligned memory.
        options.custom_flags(0x2000_0000);
    }
    #[cfg(not(windows))]
    let _ = unbuffered;
    let mut file = options.open(path).expect("create");
    file.seek(SeekFrom::Start(o as u64)).expect("seek");
    let started = Instant::now();
    let mut left = size;
    while left > 0 {
        let n = left.min(CALL);
        file.write_all(&buf[..n]).expect("write");
        left -= n;
    }
    let secs = started.elapsed().as_secs_f64();
    drop(file);
    secs
}

fn read_cell(path: &Path, size: usize, o: usize, a: usize) -> f64 {
    let mut store = vec![0u8; CALL + 2 * PAGE];
    let buf = aligned(&mut store, a, CALL);
    let mut secs = 0.0;
    for _ in 0..2 {
        let mut file = File::open(path).expect("open");
        file.seek(SeekFrom::Start(o as u64)).expect("seek");
        let started = Instant::now();
        let mut left = size;
        while left > 0 {
            let n = left.min(CALL);
            file.read_exact(&mut buf[..n]).expect("read");
            left -= n;
        }
        secs = started.elapsed().as_secs_f64();
    }
    secs
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: win_band_probe <dir> <size MiB> <reps> [write|read|nobuf]...";
    let dir = Path::new(args.first().expect(usage));
    let size = args
        .get(1)
        .and_then(|s| s.parse::<usize>().ok())
        .expect(usage)
        << 20;
    let reps: usize = args.get(2).and_then(|s| s.parse().ok()).expect(usage);
    let modes: Vec<&str> = if args.len() > 3 {
        args[3..].iter().map(String::as_str).collect()
    } else {
        vec!["write", "read"]
    };
    fs::create_dir_all(dir).expect("dir");
    let path = dir.join("band.bin");
    for rep in 0..reps {
        for mode in &modes {
            let cells: Vec<(usize, usize)> = if *mode == "nobuf" {
                vec![(0, 0)]
            } else {
                CELLS.to_vec()
            };
            // Rotate the cells each rep, so no distance always runs first.
            let k = rep % cells.len();
            for &(o, a) in cells[k..].iter().chain(&cells[..k]) {
                let secs = match *mode {
                    "write" => write_cell(&path, size, o, a, false),
                    "nobuf" => write_cell(&path, size, o, a, true),
                    "read" => {
                        write_cell(&path, size + o, 0, 0, false);
                        read_cell(&path, size, o, a)
                    }
                    other => panic!("unknown mode {other}: {usage}"),
                };
                let distance = (o + PAGE - a) % PAGE;
                println!(
                    "rep={rep} mode={mode} o={o} a={a} distance={distance} secs={secs:.6} gbps={:.3}",
                    size as f64 / secs / 1e9
                );
            }
        }
    }
    let _ = fs::remove_file(&path);
}
