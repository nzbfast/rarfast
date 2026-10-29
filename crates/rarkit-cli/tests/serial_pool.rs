//! A read proven serial builds no worker (`workers::configure_serial`):
//! the walking thread is the whole pool. Work handed to that pool from a
//! thread that is NOT the walking thread would wait for a worker that
//! never runs, so every shape such a read can take must finish.
//!
//! The rayon entry points on the read path, and why none can wait here:
//!
//! - `read::pool_width` and the RAR 5 decoder's default width ask the
//!   pool's width only; they hand it no job.
//! - the tape decode's `par_iter` runs for members of 16 MiB and more,
//!   and the plan here holds one member under 4 MiB.
//! - BLAKE2sp's `rayon::join` runs only with more than one worker.
//! - the RAR 5 filter batch is `rayon::spawn`ed, and the thread that
//!   collects it runs it itself when no worker has started it.
//! - the CBC two-lane split and the cipher overlap use `std::thread`, not
//!   the pool.
//!
//! Each row below is one of those shapes, run as its own process (the
//! pool is per process) under a watchdog: a child still running after
//! [`LIMIT`] is killed and the test FAILS, so a hang is a failure and
//! never a stall.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const LIMIT: Duration = Duration::from_secs(60);

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-serial-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run rarfast in `dir`, killing it and failing if it outlives [`LIMIT`].
/// Returns the exit code and standard output.
fn run(dir: &Path, args: &[&str]) -> (Option<i32>, Vec<u8>) {
    let mut child = Command::new(rarfast())
        .current_dir(dir)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut stdout, &mut buf).unwrap();
        buf
    });
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return (status.code(), reader.join().unwrap());
        }
        if start.elapsed() > LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("rarfast {args:?} still running after {LIMIT:?}: the serial pool hung");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Deterministic bytes: text-like when `text`, else an x86-like stream
/// dense in E8 opcodes, which the writer's x86 filter takes.
fn bytes(len: usize, text: bool) -> Vec<u8> {
    let mut x: u32 = 0x1234_5678;
    (0..len)
        .map(|i| {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            if text {
                b"the quick brown fox jumps over a lazy dog\n"[(x >> 24) as usize % 42]
            } else if i % 5 == 0 {
                0xE8
            } else {
                (x >> 24) as u8
            }
        })
        .collect()
}

struct Case {
    tag: &'static str,
    name: &'static str,
    len: usize,
    text: bool,
    create: &'static [&'static str],
}

const CASES: [Case; 4] = [
    Case {
        tag: "m3-p",
        name: "a.txt",
        len: 1 << 20,
        text: true,
        create: &["-m3", "-pserial"],
    },
    Case {
        tag: "m3-hp",
        name: "a.txt",
        len: 1 << 20,
        text: true,
        create: &["-m3", "-hpserial"],
    },
    Case {
        tag: "m0-p-under-4m",
        name: "a.bin",
        len: (4 << 20) - 1,
        text: false,
        create: &["-m0", "-pserial"],
    },
    Case {
        tag: "x86-p",
        name: "prog.exe",
        len: 3 << 20,
        text: false,
        create: &["-m3", "-pserial"],
    },
];

#[test]
fn every_serial_shape_finishes_and_keeps_its_bytes() {
    for case in &CASES {
        let dir = work(case.tag);
        let data = bytes(case.len, case.text);
        std::fs::write(dir.join(case.name), &data).unwrap();
        let mut args = vec!["a", "-y", "-idq"];
        args.extend_from_slice(case.create);
        args.extend_from_slice(&["arc.rar", case.name]);
        assert_eq!(run(&dir, &args).0, Some(0), "{}: create", case.tag);
        std::fs::remove_file(dir.join(case.name)).unwrap();

        assert_eq!(
            run(&dir, &["t", "-pserial", "arc.rar"]).0,
            Some(0),
            "{}: t",
            case.tag
        );

        let (code, out) = run(&dir, &["p", "-inul", "-pserial", "arc.rar"]);
        assert_eq!(code, Some(0), "{}: p", case.tag);
        assert!(out == data, "{}: p bytes", case.tag);

        for (cmd, sub) in [("x", "out-x"), ("e", "out-e")] {
            let dest = format!("{sub}/");
            assert_eq!(
                run(&dir, &[cmd, "-o+", "-pserial", "arc.rar", &dest]).0,
                Some(0),
                "{}: {cmd}",
                case.tag
            );
            let got = std::fs::read(dir.join(sub).join(case.name)).unwrap();
            assert!(got == data, "{}: {cmd} bytes", case.tag);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
