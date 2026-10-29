//! Two properties a `t` or `x` over a volume set must hold, and the
//! failures around them that must not move.
//!
//! Both were defects in the shipped CLI, reproduced with rar 7.23 on
//! an M3 Mac (25 Sep 2026):
//!
//! - A set whose HEADERS are encrypted (`-hp`) was walked as two volumes.
//!   The chain was discovered by reading each next volume without the
//!   password, so volume two's headers did not parse and the chain ended
//!   there: a valid 43-volume set failed with `Unexpected end of archive`
//!   and left a short payload behind.
//! - A set of more volumes than the process has descriptors could not be
//!   read at all, because every volume was opened before the walk began: a
//!   valid 430-volume set failed under macOS's default soft limit of 256.
//!
//! The rows marked `FAILS BEFORE THE FIX` below fail on the code as it
//! stood at an earlier revision. The rest pin the failures that were already right
//! (a wrong password, a missing volume, a damaged one) so the fix cannot
//! move them.
//!
//! **Fixtures.** A PLAIN set is written by this crate's own `rar` dialect,
//! which is rarkit's writer, so those rows need nothing on PATH. An
//! ENCRYPTED set is written by the reference `rar` (7.23), and
//! each encrypted row says it was skipped where no `rar` is on PATH. Not by
//! rarkit's writer, because on 25 Sep 2026 its encrypted volume sets were
//! found to be wrong themselves: reference `unrar t` reports a packed data
//! checksum error in every volume of one, and rarkit's reader fails its
//! member. That writer defect was fixed later; the encrypted rows
//! stay on the reference's sets, which test the reader against a writer
//! that is not rarkit's own.
//!
//! **Why the budget is lowered in a child.** As in `tests/descriptors.rs`:
//! the workspace forbids `unsafe`, so the soft limit is lowered by a shell's
//! `ulimit -n` before it `exec`s the binary, which leaves this process and
//! its neighbouring tests untouched.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The password every encrypted row writes its set with and reads it with.
const PASSWORD: &str = "multivolume-test";

/// The payload's size: enough to span many volumes at [`VOLUME`].
const PAYLOAD: usize = 3 << 20;

/// The volume size, in bytes: 3 MiB over 64 kB is 49 volumes.
const VOLUME: &str = "64000b";

/// The descriptor budget the many-volume rows read under, well under the
/// volume count so that holding every volume at once cannot finish.
const BUDGET: usize = 24;

/// The budgets a row that reads both ways reads under: none, and on Unix
/// the small one as well.
fn budgets() -> Vec<Option<usize>> {
    if cfg!(unix) {
        vec![None, Some(BUDGET)]
    } else {
        vec![None]
    }
}

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// An empty directory of one test's own, made afresh under the system's
/// temporary directory; `tag` tells the tests of this file apart.
fn work(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("rarfast-multivolume-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Bytes a stored member cannot shrink, the same on every run.
fn payload() -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    (0..PAYLOAD)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[3]
        })
        .collect()
}

/// One exit code and the two streams.
struct Ran {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Runs `binary` in `dir`, with the soft descriptor limit lowered to
/// `budget` for that process alone when one is given. Off Unix there is
/// no such limit to lower and no shell to lower it in: the binary is run
/// as it is, and the rows that give a budget are Unix only.
#[cfg(not(unix))]
fn run(binary: &Path, dir: &Path, budget: Option<usize>, args: &[&str]) -> Ran {
    assert!(budget.is_none(), "a descriptor budget is a Unix row");
    let out = Command::new(binary)
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|err| panic!("{} could not be run: {err}", binary.display()));
    Ran {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Runs `binary` in `dir`, with the soft descriptor limit lowered to
/// `budget` for that process alone when one is given.
#[cfg(unix)]
fn run(binary: &Path, dir: &Path, budget: Option<usize>, args: &[&str]) -> Ran {
    let words = std::iter::once(binary.to_string_lossy().into_owned())
        .chain(args.iter().map(|arg| (*arg).to_owned()))
        .map(|word| shell_word(&word))
        .collect::<Vec<_>>()
        .join(" ");
    let line = match budget {
        Some(budget) => format!("ulimit -n {budget} && exec {words}"),
        None => format!("exec {words}"),
    };
    let out = Command::new("/bin/sh")
        .arg("-c")
        .arg(&line)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|err| panic!("the shell could not be run: {err}"));
    Ran {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// One argument, quoted so a path with a space in it survives the shell.
#[cfg(unix)]
fn shell_word(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// The set's volumes in order, which the writer's zero padding makes the
/// same as their names' order.
fn volumes(dir: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rar"))
        .collect();
    found.sort();
    found
}

/// Writes `payload.bin` into `dir` and a stored RAR 5 volume set of it,
/// with `extra` switches, through `writer`. Answers the set's volumes.
fn write_set(writer: &Path, dir: &Path, extra: &[&str]) -> Vec<PathBuf> {
    std::fs::write(dir.join("payload.bin"), payload()).unwrap();
    let volume = format!("-v{VOLUME}");
    let mut args = vec!["a", "-ma5", "-m0", "-y", "-idq", volume.as_str()];
    args.extend_from_slice(extra);
    args.extend_from_slice(&["set.rar", "payload.bin"]);
    let made = run(writer, dir, None, &args);
    assert_eq!(
        made.code,
        Some(0),
        "the set was not written: {}",
        made.stderr
    );
    std::fs::remove_file(dir.join("payload.bin")).unwrap();
    let found = volumes(dir);
    assert!(
        found.len() > 2 * BUDGET,
        "the set has {} volumes, too few for the budget to bite",
        found.len()
    );
    found
}

/// Asserts that rarfast reads the set starting at `first` back whole under
/// `budget`: `t` exits 0 and says `All OK`, then `x` exits 0 and leaves
/// the payload's own bytes in `out/`.
fn reads_back_whole(dir: &Path, first: &Path, budget: Option<usize>, password: Option<&str>) {
    let first = first.to_string_lossy().into_owned();
    let switch = password.map(|p| format!("-p{p}"));
    let mut test = vec!["t", "-y"];
    let mut extract = vec!["x", "-y"];
    if let Some(switch) = &switch {
        test.push(switch);
        extract.push(switch);
    }
    test.push(&first);
    extract.extend_from_slice(&[&first, "out/"]);

    let tested = run(&rarfast(), dir, budget, &test);
    assert_eq!(
        tested.code,
        Some(0),
        "`t` failed\nstdout:\n{}\nstderr:\n{}",
        tested.stdout,
        tested.stderr
    );
    assert!(
        tested.stdout.contains("All OK"),
        "`t` said:\n{}",
        tested.stdout
    );

    let _ = std::fs::remove_dir_all(dir.join("out"));
    let extracted = run(&rarfast(), dir, budget, &extract);
    assert_eq!(
        extracted.code,
        Some(0),
        "`x` failed\nstdout:\n{}\nstderr:\n{}",
        extracted.stdout,
        extracted.stderr
    );
    let got = std::fs::read(dir.join("out/payload.bin")).expect("`x` left no payload");
    assert_eq!(got.len(), PAYLOAD, "`x` left a payload of the wrong length");
    assert!(got == payload(), "`x` left a payload whose bytes differ");
}

/// FAILS BEFORE THE FIX: a header-encrypted set reads whole. This is the
/// report's P3 row in small: 3 MiB in 49 volumes rather than 4 GiB in 43.
#[test]
fn a_header_encrypted_set_reads_back_whole() {
    let hp = format!("-hp{PASSWORD}");
    let Some(writer) = writer_for("hp", &[&hp]) else {
        return;
    };
    let dir = work("hp");
    let set = write_set(&writer, &dir, &[&hp]);
    reads_back_whole(&dir, &set[0], None, Some(PASSWORD));
    let _ = std::fs::remove_dir_all(&dir);
}

/// FAILS BEFORE THE FIX: a plain set of more volumes than the process has
/// descriptors reads whole. Unix only by its nature, as every row with a
/// budget is: the budget is `ulimit -n`.
#[cfg(unix)]
#[test]
fn a_set_outlasts_a_small_descriptor_budget() {
    let dir = work("budget");
    let set = write_set(&rarfast(), &dir, &[]);
    reads_back_whole(&dir, &set[0], Some(BUDGET), None);
    let _ = std::fs::remove_dir_all(&dir);
}

/// FAILS BEFORE THE FIX: both at once, a header-encrypted set under the
/// small budget.
#[cfg(unix)]
#[test]
fn a_header_encrypted_set_outlasts_a_small_descriptor_budget() {
    let hp = format!("-hp{PASSWORD}");
    let Some(writer) = writer_for("hp-budget", &[&hp]) else {
        return;
    };
    let dir = work("hp-budget");
    let set = write_set(&writer, &dir, &[&hp]);
    reads_back_whole(&dir, &set[0], Some(BUDGET), Some(PASSWORD));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A set whose data only is encrypted (`-p`), under the small budget: the
/// discovery reads its headers without a key, and must still.
#[cfg(unix)]
#[test]
fn a_data_encrypted_set_outlasts_a_small_descriptor_budget() {
    let p = format!("-p{PASSWORD}");
    let Some(writer) = writer_for("p-budget", &[&p]) else {
        return;
    };
    let dir = work("p-budget");
    let set = write_set(&writer, &dir, &[&p]);
    reads_back_whole(&dir, &set[0], Some(BUDGET), Some(PASSWORD));
    let _ = std::fs::remove_dir_all(&dir);
}

/// The reference `rar`, where one is on PATH.
fn reference() -> Option<PathBuf> {
    let output = Command::new("which").arg("rar").output().ok()?;
    let path = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (output.status.success() && !path.is_empty()).then(|| PathBuf::from(path))
}

/// The writer for a set with `extra` switches: the reference for an
/// encrypted one (see the module's head), rarkit's own otherwise. `None`
/// is an encrypted row with no reference to write its set, which the row
/// reports as skipped.
fn writer_for(row: &str, extra: &[&str]) -> Option<PathBuf> {
    if !extra
        .iter()
        .any(|switch| switch.starts_with("-p") || switch.starts_with("-hp"))
    {
        return Some(rarfast());
    }
    let found = reference();
    if found.is_none() {
        eprintln!("skipped {row}: no `rar` on PATH to write an encrypted set");
    }
    found
}

/// A wrong password on a header-encrypted set is refused at the first
/// volume, with the reference's words and code, and writes nothing.
#[test]
fn a_wrong_password_is_refused_as_before() {
    let hp = format!("-hp{PASSWORD}");
    let Some(writer) = writer_for("wrong", &[&hp]) else {
        return;
    };
    let dir = work("wrong");
    let set = write_set(&writer, &dir, &[&hp]);
    let first = set[0].to_string_lossy().into_owned();
    for command in ["t", "x"] {
        let ran = run(
            &rarfast(),
            &dir,
            None,
            &[command, "-y", "-pwrong", &first, "out/"],
        );
        assert_eq!(ran.code, Some(11), "`{command}` answered {:?}", ran.code);
        assert!(
            ran.stderr.contains("Incorrect password"),
            "`{command}` said:\n{}",
            ran.stderr
        );
        assert!(!dir.join("out/payload.bin").exists());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A volume missing from the middle of the set is named, and the member
/// that needed it fails, for a plain set and for a header-encrypted one
/// alike, with or without the small budget. Exit 6 and both lines are what
/// the plain set answered unbudgeted before the fix.
#[test]
fn a_missing_volume_is_named_as_before() {
    for (tag, extra) in [
        ("missing-plain", None),
        ("missing-hp", Some(format!("-hp{PASSWORD}"))),
    ] {
        let extras: Vec<&str> = extra.iter().map(String::as_str).collect();
        let Some(writer) = writer_for(tag, &extras) else {
            continue;
        };
        let dir = work(tag);
        let set = write_set(&writer, &dir, &extras);
        let gone = &set[set.len() / 2];
        std::fs::remove_file(gone).unwrap();
        let first = set[0].to_string_lossy().into_owned();
        let switch = format!("-p{PASSWORD}");
        let name = gone.to_string_lossy();
        for budget in budgets() {
            let ran = run(&rarfast(), &dir, budget, &["t", "-y", &switch, &first]);
            assert_eq!(
                ran.code,
                Some(6),
                "{tag} {budget:?}: `t` answered {:?}\n{}",
                ran.code,
                ran.stderr
            );
            assert!(
                ran.stderr.contains(&format!("Cannot find volume {name}\n"))
                    && ran.stderr.contains("payload.bin")
                    && ran.stderr.contains("- checksum error"),
                "{tag} {budget:?}: `t` said:\n{}",
                ran.stderr
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// A volume damaged in its payload fails the member, and the walk still
/// reaches the end of the set rather than stopping short of it, with or
/// without the small budget. A plain member fails its checksum (exit 3),
/// and so does an ENCRYPTED one whose password check record passed: until
/// 29 Sep 2026 this row pinned exit 11, `Incorrect password`, which was
/// a defect. Reference `unrar` 7.23 on this very shape (a `-hp` set of 50
/// volumes of 64000 bytes, one byte of the middle volume flipped) says
/// `payload.bin - checksum error` and exits 3
/// (`tests/encrypted_damage.rs` has the rest).
#[test]
fn a_damaged_volume_fails_its_checksum_as_before() {
    for (tag, extra, code, words) in [
        ("damaged-plain", None, 3, "- checksum error"),
        (
            "damaged-hp",
            Some(format!("-hp{PASSWORD}")),
            3,
            "- checksum error",
        ),
    ] {
        let extras: Vec<&str> = extra.iter().map(String::as_str).collect();
        let Some(writer) = writer_for(tag, &extras) else {
            continue;
        };
        let dir = work(tag);
        let set = write_set(&writer, &dir, &extras);
        let hit = &set[set.len() / 2];
        let mut bytes = std::fs::read(hit).unwrap();
        let at = bytes.len() / 2;
        bytes[at] ^= 0x01;
        std::fs::write(hit, bytes).unwrap();
        let first = set[0].to_string_lossy().into_owned();
        let switch = format!("-p{PASSWORD}");
        for budget in budgets() {
            let ran = run(&rarfast(), &dir, budget, &["t", "-y", &switch, &first]);
            assert_eq!(
                ran.code,
                Some(code),
                "{tag} {budget:?}: `t` answered {:?}\n{}",
                ran.code,
                ran.stderr
            );
            assert!(
                ran.stderr.contains(words),
                "{tag} {budget:?}: `t` said:\n{}",
                ran.stderr
            );
            assert!(
                !ran.stderr.contains("Unexpected end of archive"),
                "{tag} {budget:?}: the walk stopped short:\n{}",
                ran.stderr
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Bytes a stored member cannot shrink, `len` of them.
fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x2545_f491_4f6c_dd1d_u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[3]
        })
        .collect()
}

/// FAILS BEFORE THE FIX: a split member that ENDS exactly at a volume's
/// end, with the next volume starting a NEW member, is followed into that
/// volume. rarkit's own writer makes this layout: 300,000 stored bytes at
/// `-v100000b` fill three volumes, and the 16-byte member after them sits
/// alone in the fourth. The chain used to go on only while a member was
/// split open, so it stopped at volume three with `Unexpected end of
/// archive`, exit 1, and the last member was never read. What says a
/// volume is not the last is its end record (SPEC-F 3.5.5), and that bit
/// is set on the third volume here (SPEC-G 3.10.3).
#[test]
fn a_member_ending_on_a_volume_boundary_does_not_end_the_set() {
    let dir = work("end-aligned");
    let big = noise(300_000);
    let small = b"sixteen bytes!!\n";
    std::fs::write(dir.join("big.bin"), &big).unwrap();
    std::fs::write(dir.join("small.txt"), small).unwrap();
    let made = run(
        &rarfast(),
        &dir,
        None,
        &[
            "a",
            "-y",
            "-idq",
            "-m0",
            "-v100000b",
            "set.rar",
            "big.bin",
            "small.txt",
        ],
    );
    assert_eq!(
        made.code,
        Some(0),
        "the set was not written: {}",
        made.stderr
    );
    std::fs::remove_file(dir.join("big.bin")).unwrap();
    std::fs::remove_file(dir.join("small.txt")).unwrap();
    let set = volumes(&dir);
    assert_eq!(set.len(), 4, "the writer's layout moved: {set:?}");

    // The layout this row is about: the last volume holds the small member
    // alone, and it starts there rather than continuing big.bin.
    let last = run(&rarfast(), &dir, None, &["lt", &set[3].to_string_lossy()]);
    assert_eq!(
        last.code,
        Some(0),
        "`lt` on the last volume: {}",
        last.stderr
    );
    assert!(
        last.stdout.contains("small.txt") && !last.stdout.contains("big.bin"),
        "the last volume is not small.txt alone:\n{}",
        last.stdout
    );

    let first = set[0].to_string_lossy().into_owned();
    let tested = run(&rarfast(), &dir, None, &["t", "-y", &first]);
    assert_eq!(
        tested.code,
        Some(0),
        "`t` failed\nstdout:\n{}\nstderr:\n{}",
        tested.stdout,
        tested.stderr
    );
    for volume in &set {
        assert!(
            tested.stdout.contains(&*volume.to_string_lossy()),
            "`t` did not reach {}:\n{}",
            volume.display(),
            tested.stdout
        );
    }
    assert!(
        tested.stdout.contains("small.txt") && tested.stdout.contains("All OK"),
        "`t` said:\n{}",
        tested.stdout
    );

    let extracted = run(&rarfast(), &dir, None, &["x", "-y", &first, "out/"]);
    assert_eq!(
        extracted.code,
        Some(0),
        "`x` failed\nstdout:\n{}\nstderr:\n{}",
        extracted.stdout,
        extracted.stderr
    );
    assert!(std::fs::read(dir.join("out/big.bin")).unwrap() == big);
    assert_eq!(std::fs::read(dir.join("out/small.txt")).unwrap(), small);

    // A listing reads the volume it is given, and each one answers; a
    // split member is listed once, in the volume where it starts.
    for (volume, member) in set.iter().zip(["big.bin", "", "", "small.txt"]) {
        let listed = run(&rarfast(), &dir, None, &["lb", &volume.to_string_lossy()]);
        assert_eq!(
            listed.code,
            Some(0),
            "`lb` {}: {}",
            volume.display(),
            listed.stderr
        );
        assert_eq!(listed.stdout.trim(), member, "`lb` {}", volume.display());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A lone volume whose end record says none follows is the whole set, and
/// a plain split member still carries the walk on: the one-volume-set
/// and the split rows around the end-aligned one.
#[test]
fn a_truly_last_volume_ends_the_set_and_a_split_member_does_not() {
    let dir = work("last-and-split");
    std::fs::write(dir.join("one.bin"), noise(1000)).unwrap();
    std::fs::write(dir.join("two.bin"), noise(250_000)).unwrap();
    // One volume only: the size bound is never reached.
    let made = run(
        &rarfast(),
        &dir,
        None,
        &["a", "-y", "-idq", "-m0", "-v100000b", "lone.rar", "one.bin"],
    );
    assert_eq!(made.code, Some(0), "{}", made.stderr);
    // A member cut inside volume two and ended inside volume three.
    let made = run(
        &rarfast(),
        &dir,
        None,
        &[
            "a",
            "-y",
            "-idq",
            "-m0",
            "-v100000b",
            "split.rar",
            "two.bin",
        ],
    );
    assert_eq!(made.code, Some(0), "{}", made.stderr);
    let names: Vec<String> = volumes(&dir)
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert!(names.contains(&"lone.part1.rar".to_owned()), "{names:?}");
    assert!(!names.contains(&"lone.part2.rar".to_owned()), "{names:?}");
    assert!(names.contains(&"split.part3.rar".to_owned()), "{names:?}");
    assert!(!names.contains(&"split.part4.rar".to_owned()), "{names:?}");
    for first in ["lone.part1.rar", "split.part1.rar"] {
        let tested = run(&rarfast(), &dir, None, &["t", "-y", first]);
        assert_eq!(
            tested.code,
            Some(0),
            "`t` {first}\nstdout:\n{}\nstderr:\n{}",
            tested.stdout,
            tested.stderr
        );
        assert!(tested.stdout.contains("All OK"), "{}", tested.stdout);
        assert!(
            !tested.stderr.contains("Cannot find volume"),
            "{}",
            tested.stderr
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
