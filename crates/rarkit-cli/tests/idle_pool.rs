//! THE IDLE POOL (FROM-STUDIO 518 C, part (1)): one clear stored member
//! under a CRC32, larger than the lone small member's 4 MiB, is read on the
//! serial pool (the walking thread its whole pool, no worker made) at the
//! read width it had before, and every other class keeps the pool it had.
//!
//! Each row asserts the POOL's width (`rarfast pool:`), the READ's width
//! (`rarfast read:`), for a lone member the driver (`rarfast drive:`,
//! the walk, so no create ahead helper is armed) and the bytes, for `x`, `e`, `t` and `p`. Both lines
//! are said under `RARFAST_POOL_SAY=1`, which only an `h2-probes` build
//! says. The read width a row must keep is read from the same command over
//! two stored members, which keeps its pool: the width the engine resolved
//! from that pool is the width the idle pool's read states.
//!
//! Every run is its own process (the pool is per process) under a
//! watchdog: a child still running after [`LIMIT`] is killed and the test
//! FAILS, so a job stranded on the serial pool is a failure and never a
//! stall. Any box width; about 120 MiB of disk in the temporary directory
//! and as much memory at most for the largest member's bytes.

#![cfg(feature = "h2-probes")]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const LIMIT: Duration = Duration::from_secs(120);

const MIB: usize = 1 << 20;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-idle-pool-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// What one run said and wrote.
struct Ran {
    /// The `rarfast pool:` line, or empty where the run built no pool.
    pool: String,
    /// The width the `rarfast read:` line says.
    read: usize,
    /// The driver the `rarfast drive:` line says: `walk` or `pool`.
    drive: String,
    stdout: Vec<u8>,
}

/// Run rarfast in `dir` with the pool lines on, killing it and failing if
/// it outlives [`LIMIT`]; the run must exit 0.
fn run(dir: &Path, args: &[&str]) -> Ran {
    let mut child = Command::new(rarfast())
        .current_dir(dir)
        .args(args)
        .env("RARFAST_POOL_SAY", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let out = std::thread::spawn(move || {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut stdout, &mut buf).unwrap();
        buf
    });
    let err = std::thread::spawn(move || {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut stderr, &mut buf).unwrap();
        buf
    });
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() > LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("rarfast {args:?} still running after {LIMIT:?}: a job waits on the pool");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let stdout = out.join().unwrap();
    let stderr = String::from_utf8(err.join().unwrap()).unwrap();
    assert!(status.success(), "rarfast {args:?}: {status}\n{stderr}");
    let pool = stderr
        .lines()
        .filter(|line| line.starts_with("rarfast pool:"))
        .collect::<Vec<_>>()
        .join("\n");
    let reads: Vec<usize> = stderr
        .lines()
        .filter_map(|line| line.strip_prefix("rarfast read: width "))
        .map(|width| width.trim().parse().unwrap())
        .collect();
    assert_eq!(reads.len(), 1, "rarfast {args:?}: {stderr}");
    let drives: Vec<&str> = stderr
        .lines()
        .filter_map(|line| line.strip_prefix("rarfast drive: "))
        .collect();
    assert_eq!(drives.len(), 1, "rarfast {args:?}: {stderr}");
    Ran {
        pool,
        read: reads[0],
        drive: drives[0].to_owned(),
        stdout,
    }
}

/// Deterministic bytes: incompressible, or text a coder packs.
fn bytes(len: usize, seed: u64, text: bool) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let byte = (state >> 56) as u8;
            if text {
                b"the quick brown fox jumps over a lazy dog\n"[usize::from(byte) % 42]
            } else {
                byte
            }
        })
        .collect()
}

/// One class: an archive made by `create` from `files`, and what its pool
/// and read must be.
struct Class {
    tag: &'static str,
    /// `(name, size, text)`.
    files: &'static [(&'static str, usize, bool)],
    create: &'static [&'static str],
    /// Switches every read of it takes (a password, a width).
    read: &'static [&'static str],
    want: Want,
}

#[derive(Clone, Copy)]
enum Want {
    /// The idle pool: serial, at the control's read width.
    Idle,
    /// Today's lone small member: serial, at a read width of one.
    SmallSerial,
    /// The pool it had: as wide as the control's, and the read with it.
    Kept,
    /// A stated `-mt2`: a pool of two (at most the box), the read with it.
    Stated2,
}

const CLASSES: &[Class] = &[
    // (1) The idle pool: one clear stored member under a CRC32, past the
    // small member's bound and past the seam's 32 MiB (Linux and macOS).
    Class {
        tag: "stored5m",
        files: &[("member.bin", 5 * MIB, false)],
        create: &["-m0"],
        read: &[],
        want: Want::Idle,
    },
    Class {
        tag: "stored33m",
        files: &[("member.bin", 33 * MIB, false)],
        create: &["-m0"],
        read: &[],
        want: Want::Idle,
    },
    // Today's rule, unchanged: a lone member of 4 MiB or less.
    Class {
        tag: "stored1m",
        files: &[("member.bin", MIB, false)],
        create: &["-m0"],
        read: &[],
        want: Want::SmallSerial,
    },
    // (2) BLAKE2sp keeps today's width until its count is home.
    Class {
        tag: "blake2sp",
        files: &[("member.bin", 5 * MIB, false)],
        create: &["-m0", "-htb"],
        read: &[],
        want: Want::Kept,
    },
    // (3) A stated width, many members, a solid set, a coded member; and
    // an encrypted one, which (1) does not take.
    Class {
        tag: "mt2",
        files: &[("member.bin", 5 * MIB, false)],
        create: &["-m0"],
        read: &["-mt2"],
        want: Want::Stated2,
    },
    Class {
        tag: "two",
        files: &[("a.bin", 5 * MIB, false), ("b.bin", 5 * MIB, false)],
        create: &["-m0"],
        read: &[],
        want: Want::Kept,
    },
    Class {
        tag: "solid",
        files: &[("a.txt", 5 * MIB, true), ("b.txt", 5 * MIB, true)],
        create: &["-m3", "-s"],
        read: &[],
        want: Want::Kept,
    },
    Class {
        tag: "coded",
        files: &[("member.txt", 5 * MIB, true)],
        create: &["-m3"],
        read: &[],
        want: Want::Kept,
    },
    Class {
        tag: "encrypted",
        files: &[("member.bin", 5 * MIB, false)],
        create: &["-m0", "-pidle"],
        read: &["-pidle"],
        want: Want::Kept,
    },
];

/// The four commands, as `(command, the output directory, writes files)`.
const COMMANDS: [(&str, &str, bool); 4] = [
    ("x", "out-x/", true),
    ("e", "out-e/", true),
    ("t", "", false),
    ("p", "", false),
];

/// Make `class`'s archive in `dir`, and return its files' bytes.
fn make(dir: &Path, class: &Class) -> Vec<(&'static str, Vec<u8>)> {
    let src = dir.join("src");
    std::fs::create_dir_all(&src).unwrap();
    let mut made = Vec::new();
    for (i, &(name, size, text)) in class.files.iter().enumerate() {
        let data = bytes(size, 0x2026_1017 + i as u64, text);
        std::fs::write(src.join(name), &data).unwrap();
        made.push((name, data));
    }
    let mut args = vec!["a", "-idq", "-y"];
    args.extend_from_slice(class.create);
    args.push("../arc.rar");
    args.extend(class.files.iter().map(|f| f.0));
    let out = Command::new(rarfast())
        .args(&args)
        .current_dir(&src)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}: {}",
        class.tag,
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::remove_dir_all(&src).unwrap();
    made
}

/// The pool and read widths of `command` over two stored members, which
/// keep their pool: the widths every kept class must show, and the read
/// width the idle pool must state.
fn control(command: &str, dest: &str) -> (usize, usize) {
    let dir = work(&format!("control-{command}"));
    make(
        &dir,
        &Class {
            tag: "control",
            files: &[("a.bin", 5 * MIB, false), ("b.bin", 5 * MIB, false)],
            create: &["-m0"],
            read: &[],
            want: Want::Kept,
        },
    );
    let mut args = vec![command, "-idq", "-o+", "arc.rar"];
    if !dest.is_empty() {
        args.push(dest);
    }
    let ran = run(&dir, &args);
    let pool: usize = ran
        .pool
        .rsplit(' ')
        .next()
        .and_then(|width| width.parse().ok())
        .unwrap_or_else(|| panic!("control {command}: {:?}", ran.pool));
    assert!(
        ran.pool.contains("serial false built true"),
        "control {command}: {:?}",
        ran.pool
    );
    let _ = std::fs::remove_dir_all(&dir);
    (pool, ran.read)
}

#[test]
fn the_idle_pool_takes_a_lone_clear_stored_member_and_nothing_else() {
    let cores = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    for &(command, dest, writes) in &COMMANDS {
        let (wide_pool, wide_read) = control(command, dest);
        // With no `-mt<n>` the engine reads as wide as the pool.
        assert_eq!(wide_pool, wide_read, "control {command}");
        for class in CLASSES {
            let dir = work(&format!("{}-{command}", class.tag));
            let files = make(&dir, class);
            let mut args = vec![command, "-idq", "-o+"];
            if command == "p" {
                args.push("-inul");
            }
            args.extend_from_slice(class.read);
            args.push("arc.rar");
            if !dest.is_empty() {
                args.push(dest);
            }
            let ran = run(&dir, &args);
            let at = format!("{} {command}", class.tag);
            let (pool, read) = match class.want {
                Want::Idle => (
                    "rarfast pool: asked 1 serial true built true width 1".to_owned(),
                    wide_read,
                ),
                Want::SmallSerial => (
                    "rarfast pool: asked 1 serial true built true width 1".to_owned(),
                    1,
                ),
                Want::Kept => (
                    format!(
                        "rarfast pool: asked {wide_pool} serial false built true width {wide_pool}"
                    ),
                    wide_read,
                ),
                Want::Stated2 => {
                    let two = 2.min(cores);
                    (
                        format!("rarfast pool: asked {two} serial false built true width {two}"),
                        two,
                    )
                }
            };
            assert_eq!(ran.pool, pool, "{at}: the pool");
            assert_eq!(ran.read, read, "{at}: the read width");
            // THE GUARD (FROM-STUDIO 518 C's precondition): a lone member
            // on the serial pool is driven by the walk, never by the
            // member pool, the one driver that arms create ahead's
            // `rayon::spawn`ed helpers, which a serial pool would never
            // run and `Ahead::stop` would wait for. A change that let one
            // arm here fails this line, or the watchdog, never hangs.
            if matches!(class.want, Want::Idle | Want::SmallSerial) {
                assert_eq!(ran.drive, "walk", "{at}: the driver");
            }
            // The bytes: each file for `x` and `e`, the files end to end in
            // archive order for `p`; `t` exited 0, its CRC checked.
            if writes {
                for (name, data) in &files {
                    let got = std::fs::read(dir.join(dest).join(name)).unwrap();
                    assert!(got == *data, "{at}: {name}'s bytes");
                }
            } else if command == "p" {
                let whole: Vec<u8> = files.iter().flat_map(|(_, d)| d.iter().copied()).collect();
                assert!(ran.stdout == whole, "{at}: the printed bytes");
            }
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}
