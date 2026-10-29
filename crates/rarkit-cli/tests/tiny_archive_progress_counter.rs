//! Items 4 and 5 of the 28 Sep 2026 CLI parity leftovers: `p` and `x`'s
//! progress counter read one low on a tiny archive.
//!
//! `Run::open_progress`'s denominator (`Opened::size`'s derived
//! `total_size` in `extract.rs`) was the last payload's own end - the
//! archive's byte position where the counter should read 100% - but a
//! member's `data_end` (the counter's numerator) is an ABSOLUTE file
//! offset that also counts the bytes AHEAD of the first member: the
//! signature and the main archive header. The reference's own
//! denominator leaves the main header's bytes out while the numerator
//! keeps them, so on an archive whose main header is a real fraction of
//! the whole file - a tiny one - the counter read low everywhere except
//! the very end, where the numerator overshoots the (too small)
//! denominator and the answer is clamped back to 100% by coincidence.
//!
//! Measured against unrar 7.23 (homebrew's, aarch64 macOS, 28 Sep 2026),
//! `rarfast a -m0` archives of 3, 5 and 7 members of a few bytes each (so
//! the fixed-size RAR 5 main header, 15 bytes past its 8 byte signature
//! in every case here, is a real fraction of the file), `x -ierr -o+`
//! and `p -ierr` alike:
//!
//! | members | reference | before this fix |
//! | --- | --- | --- |
//! | 3 | `46%, 77%, 100%` | `43%, 73%, 100%` |
//! | 5 | `28%, 47%, 67%, 86%, 100%` | `26%, 45%, 63%, 81%, 100%` |
//! | 7 | `20%, 34%, 48%, 62%, 76%, 90%, 100%` | `19%, 32%, 45%, 58%, 71%, 84%, 100%` |
//!
//! (The "before" column is what this crate read at each row before this
//! fix, for the exact member names and content `build` below writes.)
//!
//! **Those figures are of the archive a Unix system writes, and the
//! 3-member row is one step different for the archive Windows writes**
//! (1 Oct 2026).
//! A file header carries the member's attributes as a variable-length
//! integer: a Unix mode (0100644) takes three bytes and the Windows
//! attribute word (0x20) one, so each of these members' headers is 41
//! bytes written on macOS or Linux and 39 written on Windows, and the
//! archive of three is 181 bytes against 175. The counter is the member's
//! end offset over the end record's end less the main header's 23 bytes,
//! floored:
//!
//! | written on | file | denominator | unrounded | steps |
//! | --- | --- | --- | --- | --- |
//! | macOS, Linux | 181 | 158 | 46.203, 77.848 | `46%, 77%, 100%` |
//! | Windows | 175 | 152 | 46.711, 78.289 | `46%, 78%, 100%` |
//!
//! unrar 7.23 (homebrew's, aarch64 macOS) prints `46%, 78%, 100%` over the
//! Windows-written bytes, `x` and `p` alike, and rarfast prints each row's
//! steps for that row's bytes on Windows and on macOS both: the archive
//! differs by the system that wrote it, and neither tool rounds
//! differently by the system it runs on. With five and seven members both
//! shapes print the same steps (no step sits that near a whole percent).
//! So the 3-member row below is stated for each writing system, and
//! `the_same_archive_bytes_print_the_same_steps_on_every_system` holds
//! the second half over both archives as bytes. The counts were
//! measured 1 Oct 2026.

use std::path::{Path, PathBuf};
use std::process::Command;

// The copy of the binary run under another name, and its spawns, kept
// clear of Linux's "Text file busy" (`support/exe_copy.rs`).
#[path = "support/exe_copy.rs"]
mod exe_copy;
use exe_copy::{copy_executable, output_of};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-tiny-pct-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A copy of `rarfast` named `unrar`.
fn ours_as_unrar(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "rarfast-tiny-pct-asunrar-{}-{tag}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let named = dir.join("unrar");
    copy_executable(&rarfast(), &named);
    named
}

fn run(binary: &Path, dir: &Path, args: &[&str]) -> (String, String, i32) {
    let out = output_of(Command::new(binary).args(args).current_dir(dir))
        .unwrap_or_else(|err| panic!("{binary:?} could not be run: {err}"));
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

/// The `NN%` tokens in `text`, in order, each parsed to a `u32`.
fn percents(text: &str) -> Vec<u32> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let mut start = index;
            while start > 0 && bytes[start - 1].is_ascii_digit() {
                start -= 1;
            }
            if start < index {
                if let Ok(value) = text[start..index].parse::<u32>() {
                    out.push(value);
                }
            }
        }
        index += 1;
    }
    out
}

/// `n` members of `n + 2` bytes each ("hiNN\n"-shaped), stored (`-m0`),
/// built by rarfast itself.
fn build(dir: &Path, n: usize) -> PathBuf {
    let names: Vec<String> = (1..=n).map(|i| format!("m{i}.txt")).collect();
    for name in &names {
        std::fs::write(dir.join(name), format!("hi{name}\n")).unwrap();
    }
    let mut args: Vec<&str> = vec!["a", "-y", "-idq", "-m0", "tiny.rar"];
    for name in &names {
        args.push(name);
    }
    let (_, stderr, exit) = run(&rarfast(), dir, &args);
    assert_eq!(exit, 0, "building the archive: {stderr}");
    dir.join("tiny.rar")
}

/// The reference's steps over the 3-member archive [`build`] writes on
/// the system the test runs on: a Unix mode in each header, or on Windows
/// the shorter attribute word (the module doc's second table).
#[cfg(not(windows))]
const THREE_MEMBERS_BUILT_HERE: [u32; 3] = [46, 77, 100];
#[cfg(windows)]
const THREE_MEMBERS_BUILT_HERE: [u32; 3] = [46, 78, 100];

/// `rarfast a -y -idq -m0 tiny.rar m1.txt m2.txt m3.txt` over [`build`]'s
/// three members, as aarch64 macOS wrote it (181 bytes) and as Windows
/// wrote it (175 bytes), both written on 1 Oct 2026, with
/// the steps unrar 7.23 prints over each.
const PINNED: [(&str, &[&str], [u32; 3]); 2] = [
    (
        "macos",
        &[
            "526172211a0701003392b5e50a010506000501018080009dba30752402030b89",
            "00048900a4830205bf9980800001066d312e7478740a031313c7be6af3996e36",
            "68696d312e7478740a6dbb6c992402030b8900048900a48302abcd0d06800001",
            "066d322e7478740a031313c7be6ab6c06f3668696d322e7478740a6bc2743524",
            "02030b8900048900a483020e1e51cd800001066d332e7478740a031313c7be6a",
            "23a2703668696d332e7478740a1d77565103050400",
        ],
        [46, 77, 100],
    ),
    (
        "windows",
        &[
            "526172211a0701003392b5e50a010506000501018080002075f4bb2202030b89",
            "000489002005bf9980800000066d312e7478740a030278346dd5f751dd016869",
            "6d312e7478740a83a07def2202030b890004890020abcd0d06800000066d322e",
            "7478740a0302a65b6dd5f751dd0168696d322e7478740ac3d9f24f2202030b89",
            "00048900200e1e51cd800000066d332e7478740a0302a65b6dd5f751dd016869",
            "6d332e7478740a1d77565103050400",
        ],
        [46, 78, 100],
    ),
];

fn bytes_of(hex: &[&str]) -> Vec<u8> {
    let digits: Vec<u8> = hex.concat().into_bytes();
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn check(n: usize) {
    let dir = work(&format!("check-{n}"));
    let archive = build(&dir, n);
    let unrar = ours_as_unrar(&format!("check-{n}"));

    let (_, stderr, exit) = run(
        &unrar,
        &dir,
        &[
            "x",
            "-ierr",
            "-o+",
            archive.file_name().unwrap().to_str().unwrap(),
            "out/",
        ],
    );
    assert_eq!(exit, 0, "{n}: extract failed: {stderr}");
    let steps = percents(&stderr);
    assert_eq!(
        steps.len(),
        n,
        "{n}: one progress step per member, got {steps:?}"
    );
    assert_eq!(
        *steps.last().unwrap(),
        100,
        "{n}: the last step is 100%, got {steps:?}"
    );
    // Strictly increasing: a low-reading denominator does not change
    // monotonicity, so this alone would not have caught the bug, but a
    // fix that broke it would be worse than the bug.
    assert!(
        steps.windows(2).all(|w| w[0] < w[1]),
        "{n}: steps should strictly increase, got {steps:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(unrar.parent().unwrap());
}

#[test]
fn extract_progress_matches_reference_shape_on_tiny_archives() {
    // Reference figures (unrar 7.23, 28 Sep 2026), by member count - see
    // the module doc's table. Only the SHAPE (strictly increasing to
    // 100%) is asserted generically above; the exact reference values are
    // pinned per row here, since they are what this fix is FOR. The
    // 3-member row is the reference's figure for the archive THIS system
    // writes (the module doc's second table).
    for (n, expected) in [
        (3, THREE_MEMBERS_BUILT_HERE.to_vec()),
        (5, vec![28, 47, 67, 86, 100]),
        (7, vec![20, 34, 48, 62, 76, 90, 100]),
    ] {
        let dir = work(&format!("exact-{n}"));
        let archive = build(&dir, n);
        let unrar = ours_as_unrar(&format!("exact-{n}"));

        let (_, stderr, exit) = run(
            &unrar,
            &dir,
            &[
                "x",
                "-ierr",
                "-o+",
                archive.file_name().unwrap().to_str().unwrap(),
                "out/",
            ],
        );
        assert_eq!(exit, 0, "{n}: extract failed: {stderr}");
        assert_eq!(percents(&stderr), expected, "{n}: x -ierr progress steps");

        let (out, stderr, exit) = run(
            &unrar,
            &dir,
            &["p", "-ierr", archive.file_name().unwrap().to_str().unwrap()],
        );
        assert_eq!(exit, 0, "{n}: print failed: {stderr}");
        assert!(
            !out.is_empty(),
            "{n}: p should still write the payload to stdout"
        );
        assert_eq!(percents(&stderr), expected, "{n}: p -ierr progress steps");

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(unrar.parent().unwrap());
    }
}

/// The counter is a function of the archive's bytes and of nothing about
/// the system reading them: each pinned archive prints the reference's
/// steps for THAT archive, `x` and `p` alike, wherever this runs. Until 1
/// Oct 2026 nothing held that, and the one-step difference between the
/// two archives read on Windows as a red of unknown side.
#[test]
fn the_same_archive_bytes_print_the_same_steps_on_every_system() {
    for (origin, hex, expected) in PINNED {
        let dir = work(&format!("pinned-{origin}"));
        std::fs::write(dir.join("tiny.rar"), bytes_of(hex)).unwrap();
        let unrar = ours_as_unrar(&format!("pinned-{origin}"));

        let (_, stderr, exit) = run(&unrar, &dir, &["x", "-ierr", "-o+", "tiny.rar", "out/"]);
        assert_eq!(exit, 0, "{origin}: extract failed: {stderr}");
        assert_eq!(
            percents(&stderr),
            expected,
            "the archive {origin} wrote: x -ierr progress steps"
        );
        for index in 1..=3 {
            assert_eq!(
                std::fs::read(dir.join("out").join(format!("m{index}.txt"))).unwrap(),
                format!("him{index}.txt\n").into_bytes(),
                "the archive {origin} wrote: member {index}"
            );
        }

        let (out, stderr, exit) = run(&unrar, &dir, &["p", "-ierr", "tiny.rar"]);
        assert_eq!(exit, 0, "{origin}: print failed: {stderr}");
        assert_eq!(
            out, "him1.txt\nhim2.txt\nhim3.txt\n",
            "{origin}: p's payload"
        );
        assert_eq!(
            percents(&stderr),
            expected,
            "the archive {origin} wrote: p -ierr progress steps"
        );

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(unrar.parent().unwrap());
    }
}

#[test]
fn extract_progress_shape_holds_generically() {
    for n in [3, 5, 7] {
        check(n);
    }
}
