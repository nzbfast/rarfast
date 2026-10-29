//! The READ side of a stored member on Windows, by arrangement: a measuring
//! probe for the Windows stored `t` and `p` read path.
//!
//! rarfast's stored `t` and `p` read a big member with the WIDE reader
//! (`rarkit::read::wide`): several workers each read a piece of the member
//! by offset from the volume's one shared source and hash it. On Unix a
//! file source reads with `pread`, and concurrent `pread`s on one
//! descriptor run in parallel. On Windows it reads with
//! `FileExt::seek_read` on a handle opened for synchronous I/O (std's
//! default), and the I/O manager SERIALISES the requests on such a handle,
//! so the workers may be reading one at a time. This probe measures that
//! against the alternatives, reading a big file (an archive of the disk
//! ladder's) the way the wide reader does:
//!
//! | mode | what |
//! |---|---|
//! | `seq` | one thread, sequential `read`, the piece size |
//! | `shared:N` | N threads, pieces handed out in order, one `File` shared |
//! | `own:N` | N threads, each with its own `File` opened by path |
//!
//! Each may carry open flags after a `+` (Windows, std's safe
//! `OpenOptionsExt::custom_flags`): `seq` (`FILE_FLAG_SEQUENTIAL_SCAN`),
//! `nobuf` (`FILE_FLAG_NO_BUFFERING`: the probe then reads from 4 KiB
//! aligned buffers, and the piece is a whole number of sectors). Every
//! byte read is folded into a checksum the probe prints, so no read is
//! optimised away and two arms can be seen to read the same bytes; the fold
//! is far cheaper than a CRC32 and is not the hash cost.
//!
//! Each cell reads the file whole, twice, and prints both passes: the first
//! is as the cache left it, the second warm. It is not an extractor.
//!
//!     win_read_probe <file> <piece KiB> <mode>[+flag...]...
//!
//! One `key=value` line per pass on stdout.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

const SECTOR: usize = 4096;

#[derive(Clone, Copy, Default)]
struct Flags {
    seq: bool,
    nobuf: bool,
}

fn open(path: &Path, flags: Flags) -> File {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        let mut bits = 0u32;
        if flags.seq {
            bits |= 0x0800_0000;
        }
        if flags.nobuf {
            bits |= 0x2000_0000;
        }
        if bits != 0 {
            options.custom_flags(bits);
        }
    }
    #[cfg(not(windows))]
    let _ = flags;
    options.open(path).expect("open")
}

/// A read by offset, as rarkit's file source does it on each platform.
fn read_at(file: &File, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
    #[cfg(unix)]
    {
        std::os::unix::fs::FileExt::read_at(file, buf, offset)
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::FileExt::seek_read(file, buf, offset)
    }
}

/// A buffer of `len` bytes starting on a sector boundary.
fn aligned(store: &mut [u8], len: usize) -> &mut [u8] {
    let skip = (SECTOR - store.as_ptr() as usize % SECTOR) % SECTOR;
    &mut store[skip..skip + len]
}

fn fold(bytes: &[u8]) -> u64 {
    bytes
        .chunks(8)
        .map(|c| {
            c.iter()
                .fold(0u64, |a, &b| a.wrapping_mul(31).wrapping_add(u64::from(b)))
        })
        .fold(0u64, u64::wrapping_add)
}

/// Read `piece`-sized pieces of `[0, len)` at the offsets `next` hands
/// out, from `file`, until none is left; the whole of each piece, as the
/// wide reader asks for it.
fn drain(file: &File, len: u64, piece: usize, next: &AtomicU64, sum: &AtomicU64) {
    let mut store = vec![0u8; piece + SECTOR];
    let buf = aligned(&mut store, piece);
    loop {
        let at = next.fetch_add(piece as u64, Ordering::Relaxed);
        if at >= len {
            return;
        }
        let want = (len - at).min(piece as u64) as usize;
        // An unbuffered read takes whole sectors: read the whole piece
        // (past the end is a short read) and fold what is the file's.
        let ask = want.div_ceil(SECTOR) * SECTOR;
        let mut got = 0usize;
        while got < want {
            let n = read_at(file, at + got as u64, &mut buf[got..ask.max(got + 1)]).expect("read");
            if n == 0 {
                break;
            }
            got += n;
        }
        sum.fetch_add(fold(&buf[..want.min(got)]), Ordering::Relaxed);
    }
}

fn pass(path: &Path, len: u64, piece: usize, mode: &str, flags: Flags) -> (f64, u64) {
    let sum = Arc::new(AtomicU64::new(0));
    let started = Instant::now();
    if mode == "seq" {
        let mut file = open(path, flags);
        let mut store = vec![0u8; piece + SECTOR];
        let buf = aligned(&mut store, piece);
        loop {
            let n = file.read(buf).expect("read");
            if n == 0 {
                break;
            }
            sum.fetch_add(fold(&buf[..n]), Ordering::Relaxed);
        }
    } else {
        let (kind, n) = mode
            .split_once(':')
            .expect("mode is seq, shared:N or own:N");
        let n: usize = n.parse().expect("thread count");
        let next = Arc::new(AtomicU64::new(0));
        let shared = Arc::new(open(path, flags));
        std::thread::scope(|scope| {
            for _ in 0..n {
                let (next, sum, shared) =
                    (Arc::clone(&next), Arc::clone(&sum), Arc::clone(&shared));
                let own = kind == "own";
                scope.spawn(move || {
                    if own {
                        let file = open(path, flags);
                        drain(&file, len, piece, &next, &sum);
                    } else {
                        drain(&shared, len, piece, &next, &sum);
                    }
                });
            }
        });
    }
    (started.elapsed().as_secs_f64(), sum.load(Ordering::Relaxed))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: win_read_probe <file> <piece KiB> <mode>[+flag...]...";
    let path = Path::new(args.first().expect(usage));
    let piece = args
        .get(1)
        .and_then(|s| s.parse::<usize>().ok())
        .expect(usage)
        << 10;
    assert!(
        piece.is_multiple_of(SECTOR),
        "the piece must be whole sectors"
    );
    let len = std::fs::metadata(path).expect("the file").len();
    for spec in &args[2..] {
        let mut parts = spec.split('+');
        let mode = parts.next().expect(usage);
        let mut flags = Flags::default();
        for f in parts {
            match f {
                "seq" => flags.seq = true,
                "nobuf" => flags.nobuf = true,
                other => panic!("unknown flag {other}: {usage}"),
            }
        }
        for which in ["first", "warm"] {
            let (secs, sum) = pass(path, len, piece, mode, flags);
            println!(
                "arm={spec} pass={which} piece_kib={} secs={secs:.4} gbps={:.3} sum={sum:016x}",
                piece >> 10,
                len as f64 / secs / 1e9
            );
        }
    }
}
