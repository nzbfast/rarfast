//! What the many-small extraction forms must not move.
//!
//! Each form of the N2W2A funnel (borrowed directory keys, pooled output
//! paths, the borrowed glob, the typed writer, the moved plan and the
//! rest) is a change to HOW the walk does its bookkeeping, never to what
//! it does. These rows pin what it does, on the code as it stood before
//! any of them (an earlier revision), so a form that changes an answer fails
//! here rather than in a hold:
//!
//! - **Masks over names holding a literal `*` or `?`.** The matcher tries
//!   character equality before the star, so a name's own `*` can be
//!   consumed as a literal where the mask meant a wildcard: `*` does not
//!   select `*abc`, and `a*` does not select `a*b`. Surprising, and pinned
//!   as it is; round 4's simple fast path changed exactly this.
//! - **What `x` leaves on disk**: every file's bytes and modification
//!   time, under normal output and under `-idq`, over nested directories.
//! - **The order members are reported in**, which is archive order.
//! - **A member split across volumes**, whose continuation lines are the
//!   one place the finish path reads more than one fragment. The set ends
//!   on the split member. The other layout, a next volume that opens with
//!   a new member after a split member ended exactly at a volume's end, is
//!   the volume chain's own case, pinned in `tests/multivolume_sets.rs`.
//!
//! Fixtures are written by this crate's own `rar` dialect, so nothing is
//! needed on PATH.

use std::path::{Path, PathBuf};
use std::process::Command;

// The copy of the binary run under another name, and its spawns, kept
// clear of Linux's "Text file busy" (`support/exe_copy.rs`).
#[path = "support/exe_copy.rs"]
mod exe_copy;
use exe_copy::{copy_executable, output_of, tool_named};
use std::time::{Duration, SystemTime};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// An empty directory of one test's own, made afresh under the system's
/// temporary directory; `tag` tells the tests of this file apart.
fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-msguards-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A copy of `rarfast` named `unrar`, which is how the binary picks that
/// dialect.
fn as_unrar(tag: &str) -> PathBuf {
    let dir = work(&format!("bin-{tag}"));
    let named = tool_named(&dir, "unrar");
    copy_executable(&rarfast(), &named);
    named
}

struct Ran {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run(binary: &Path, dir: &Path, args: &[&str]) -> Ran {
    let out = output_of(
        Command::new(binary)
            .args(args)
            .current_dir(dir)
            .env("TZ", "UTC"),
    )
    .unwrap_or_else(|err| panic!("{binary:?} could not be run: {err}"));
    Ran {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// The names a `t` reported testing, in the order it reported them.
#[cfg(unix)]
fn tested(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|line| line.strip_prefix("Testing     "))
        .map(|rest| shown_name(rest).to_owned())
        .collect()
}

/// A progress line's name: what comes before the padding and the counter,
/// whose four backspaces lead it.
fn shown_name(rest: &str) -> &str {
    rest.split('\u{8}').next().unwrap_or(rest).trim_end()
}

/// Names that hold a mask's own characters, which the matcher's branch
/// order decides. Each is chosen so that, read as a mask at archive time, it names itself
/// and nothing else here. Unix only by their nature, and so is everything
/// that uses them: Windows has no file name that holds a `*` or a `?`.
#[cfg(unix)]
const WILD_NAMES: [&str; 6] = ["*abc", "a*b", "?q", "x?y", "plain.txt", "ab.txt"];

#[cfg(unix)]
fn wild_archive(dir: &Path) {
    for name in WILD_NAMES {
        std::fs::write(dir.join(name), name.as_bytes()).unwrap();
    }
    let mut args = vec!["a", "-y", "-idq", "-m0", "wild.rar"];
    args.extend(WILD_NAMES);
    let made = run(&rarfast(), dir, &args);
    assert_eq!(made.code, Some(0), "setup create failed: {}", made.stderr);
    for name in WILD_NAMES {
        std::fs::remove_file(dir.join(name)).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn masks_over_names_with_a_literal_star_or_question_mark_select_as_the_reference_does() {
    let dir = work("wild");
    wild_archive(&dir);
    let unrar = as_unrar("wild");
    let all = run(&unrar, &dir, &["t", "wild.rar"]);
    assert_eq!(all.code, Some(0), "{}", all.stderr);
    let mut stored = tested(&all.stdout);
    stored.sort();
    let mut expected: Vec<String> = WILD_NAMES.iter().map(|n| (*n).to_owned()).collect();
    expected.sort();
    assert_eq!(stored, expected, "the archive does not hold the six names");
    for (mask, selects) in [
        // MEASURED against unrar 7.23 on macOS (arm64), 4 Oct 2026, over
        // an archive rar 7.23 made of these six names: the mask's `*` is
        // a wildcard whatever the name holds at that point, so `*`
        // reaches `*abc`, and `a*` and `?*` reach `a*b`. Until then the
        // name's own `*` was taken as equal first and spent the mask's
        // (the rows read `*` without `*abc`, `a*` and `?*` without `a*b`).
        ("*", WILD_NAMES.to_vec()),
        ("a*", vec!["a*b", "ab.txt"]),
        ("*b", vec!["a*b"]),
        ("?*", WILD_NAMES.to_vec()),
        ("a?b", vec!["a*b"]),
        ("*q", vec!["?q"]),
        ("x?y", vec!["x?y"]),
        ("*.txt", vec!["plain.txt", "ab.txt"]),
        ("*abc", vec!["*abc"]),
    ] {
        let ran = run(&unrar, &dir, &["t", "wild.rar", mask]);
        let mut got = tested(&ran.stdout);
        got.sort();
        let mut want: Vec<String> = selects.iter().map(|n| (*n).to_owned()).collect();
        want.sort();
        assert_eq!(got, want, "mask {mask:?}: {}{}", ran.stdout, ran.stderr);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A name of the tree as a listing or a progress line shows it: with the
/// system's separator, which is what the reference's builds print.
fn listed(name: &str) -> String {
    name.replace('/', std::path::MAIN_SEPARATOR_STR)
}

/// A small tree: nested directories, a file at the root, members of a few
/// sizes, each with its own modification time.
fn tree(dir: &Path) -> Vec<(String, Vec<u8>, SystemTime)> {
    let mut made = Vec::new();
    for (i, name) in [
        "top.txt",
        "d1/a.bin",
        "d1/b.bin",
        "d1/d2/c.txt",
        "d1/d2/d3/deep.txt",
        "e1/x.txt",
        "e1/y.txt",
    ]
    .iter()
    .enumerate()
    {
        let path = dir.join("src").join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let bytes: Vec<u8> = (0..(37 * (i + 1) * (i + 1)))
            .map(|k| (k * 7 + i) as u8)
            .collect();
        std::fs::write(&path, &bytes).unwrap();
        let when = SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_000 + 86_400 * i as u64);
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(when)
            .unwrap();
        made.push(((*name).to_owned(), bytes, when));
    }
    made
}

#[test]
fn extraction_leaves_the_same_bytes_and_times_under_normal_and_quiet_output() {
    let dir = work("tree");
    let files = tree(&dir);
    let made = run(
        &rarfast(),
        &dir.join("src"),
        &["a", "-y", "-idq", "-r", "-m3", "../tree.rar", "*"],
    );
    assert_eq!(made.code, Some(0), "setup create failed: {}", made.stderr);
    let unrar = as_unrar("tree");
    for quiet in [false, true] {
        // The destination is typed with the system's separator, and a
        // progress line then shows it as typed, before the member's name.
        let dest = listed(if quiet { "q/" } else { "n/" });
        let dest = dest.as_str();
        let out = dir.join(dest);
        let mut args = vec!["x", "-y"];
        if quiet {
            args.push("-idq");
        }
        args.extend(["tree.rar", dest]);
        let ran = run(&unrar, &dir, &args);
        assert_eq!(ran.code, Some(0), "{}{}", ran.stdout, ran.stderr);
        assert!(ran.stderr.is_empty(), "{}", ran.stderr);
        if quiet {
            assert!(ran.stdout.is_empty(), "-idq printed: {}", ran.stdout);
        } else {
            assert!(ran.stdout.ends_with("All OK\n"), "{}", ran.stdout);
            // Every file named once, in archive order, which is the order
            // the listing gives.
            let listing = run(&unrar, &dir, &["lb", "tree.rar"]);
            let order: Vec<&str> = listing
                .stdout
                .lines()
                .filter(|name| files.iter().any(|(f, _, _)| listed(f) == *name))
                .collect();
            let shown: Vec<&str> = ran
                .stdout
                .lines()
                .filter_map(|line| line.strip_prefix("Extracting  "))
                .map(shown_name)
                .map(|shown| shown.strip_prefix(dest).unwrap_or(shown))
                .collect();
            assert_eq!(shown, order, "{}", ran.stdout);
            for dir_line in ["d1", "d1/d2", "d1/d2/d3", "e1"] {
                let creating = format!("Creating    {dest}{}", listed(dir_line));
                assert_eq!(
                    ran.stdout
                        .lines()
                        .filter_map(|line| line.strip_prefix(creating.as_str()))
                        .filter(|rest| rest.trim_start() == "OK")
                        .count(),
                    1,
                    "{dir_line} not announced once: {}",
                    ran.stdout
                );
            }
        }
        for (name, bytes, when) in &files {
            let path = out.join(name);
            assert_eq!(&std::fs::read(&path).unwrap(), bytes, "{name}");
            let mtime = std::fs::metadata(&path).unwrap().modified().unwrap();
            assert_eq!(mtime, *when, "{name}");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_split_member_reports_each_volume_and_extracts_whole() {
    let dir = work("split");
    let payload: Vec<u8> = {
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        (0..300_000)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state.to_le_bytes()[5]
            })
            .collect()
    };
    std::fs::write(dir.join("big.bin"), &payload).unwrap();
    std::fs::write(dir.join("small.txt"), b"after the split\n").unwrap();
    let made = run(
        &rarfast(),
        &dir,
        &[
            "a",
            "-y",
            "-idq",
            "-m0",
            "-v100000b",
            "set.rar",
            "small.txt",
            "big.bin",
        ],
    );
    assert_eq!(made.code, Some(0), "setup create failed: {}", made.stderr);
    std::fs::remove_file(dir.join("big.bin")).unwrap();
    std::fs::remove_file(dir.join("small.txt")).unwrap();
    let first = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".rar"))
        .min()
        .unwrap();
    let unrar = as_unrar("split");
    let t = run(&unrar, &dir, &["t", &first]);
    assert_eq!(t.code, Some(0), "{}{}", t.stdout, t.stderr);
    // One banner per volume, and continuation lines naming the member.
    assert!(
        t.stdout.matches("Testing archive ").count() >= 4,
        "{}",
        t.stdout
    );
    assert!(t.stdout.contains("...         big.bin"), "{}", t.stdout);
    assert!(t.stdout.ends_with("All OK\n"), "{}", t.stdout);
    let x = run(&unrar, &dir, &["x", "-y", "-idq", &first, "out/"]);
    assert_eq!(x.code, Some(0), "{}{}", x.stdout, x.stderr);
    assert_eq!(std::fs::read(dir.join("out/big.bin")).unwrap(), payload);
    assert_eq!(
        std::fs::read(dir.join("out/small.txt")).unwrap(),
        b"after the split\n"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
