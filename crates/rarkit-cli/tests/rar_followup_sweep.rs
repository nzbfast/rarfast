//! Smaller faults of the rar dialect, each found beside a bug sweep's
//! own items on 4 Oct 2026 and each pinned to what `rar` 7.23 does,
//! MEASURED that day on macOS over the same files.
//!
//! Width and memory: every archive here is a few hundred bytes to a few
//! hundred kilobytes and every rarfast call states `-mt1`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-followup-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::canonicalize(&dir).unwrap()
}

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(rarfast())
        .current_dir(dir)
        .arg(args[0])
        .arg("-mt1")
        .args(&args[1..])
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn ok(dir: &Path, args: &[&str]) -> Output {
    let output = run(dir, args);
    assert!(
        output.status.success(),
        "rarfast {args:?}: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn names(dir: &Path, archive: &str) -> Vec<String> {
    let output = ok(dir, &["lb", archive]);
    // A listing prints the host's separator, a backslash on Windows; the
    // names compared here are the stored ones, which have a forward one.
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| {
            if cfg!(windows) {
                line.replace('\\', "/")
            } else {
                line.to_owned()
            }
        })
        .collect()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// `zab`, `zcd` and `keep.txt` on disk, and `l.rar` holding the three.
fn three(tag: &str) -> PathBuf {
    let dir = work(tag);
    for name in ["zab", "zcd", "keep.txt"] {
        std::fs::write(dir.join(name), format!("{name}\n")).unwrap();
    }
    ok(&dir, &["a", "-idq", "l.rar", "zab", "zcd", "keep.txt"]);
    dir
}

/// A list file that cannot be read stops EVERY command, not only a
/// create. Measured for `d`, `rn`, `lb`, `t` and `x`, the list given as
/// an argument, as `-n@` and as `-x@`: `Program aborted` on stdout,
/// `Cannot open nolist` and the reason on stderr, exit 6, and the
/// archive as it was. (The list here has no extension, so that no line
/// of this file reads as an address.) Read as an empty list, `d -x@nolist arc zab`
/// would exclude nothing, and `x -n@nolist` would extract everything.
#[test]
fn a_list_file_that_cannot_be_read_stops_the_editing_and_reading_commands() {
    let dir = three("unread-list");
    let before = std::fs::read(dir.join("l.rar")).unwrap();
    let cases: [&[&str]; 8] = [
        &["d", "l.rar", "@nolist"],
        &["d", "-n@nolist", "l.rar", "zab"],
        &["d", "-x@nolist", "l.rar", "zab"],
        &["rn", "l.rar", "@nolist"],
        &["lb", "l.rar", "@nolist"],
        &["lb", "-n@nolist", "l.rar"],
        &["t", "l.rar", "@nolist"],
        &["x", "-o+", "-n@nolist", "l.rar", "out/"],
    ];
    for args in cases {
        let output = run(&dir, args);
        let (said, warned) = (text(&output.stdout), text(&output.stderr));
        assert_eq!(output.status.code(), Some(6), "{args:?}: {said}{warned}");
        assert_eq!(said, "\nProgram aborted\n", "{args:?}");
        assert!(warned.contains("Cannot open nolist"), "{args:?}: {warned}");
        assert_eq!(
            std::fs::read(dir.join("l.rar")).unwrap(),
            before,
            "{args:?}"
        );
        assert!(!dir.join("out").exists(), "{args:?} extracted");
    }
    assert_eq!(names(&dir, "l.rar"), ["zab", "zcd", "keep.txt"]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `-t` and a tail the reference does not know is `Unknown option`, exit
/// 7, with nothing written. Measured over every letter on a create: `a`,
/// `b`, `n`, `o` (the time filters), `c`, `k`, `l`, `s` and `v` are
/// read, the other seventeen and a digit are refused. Until 4 Oct 2026
/// every one was accepted.
#[test]
fn a_create_refuses_t_and_a_tail_the_reference_does_not_know() {
    let dir = three("t-tail");
    for letter in "defghijmpqrtuwxyz1".chars() {
        let switch = format!("-t{letter}");
        let output = run(&dir, &["a", &switch, "new.rar", "zab"]);
        let said = text(&output.stdout);
        assert_eq!(output.status.code(), Some(7), "{switch}: {said}");
        assert!(said.contains("ERROR: Unknown option"), "{switch}: {said}");
        assert!(!dir.join("new.rar").exists(), "{switch} wrote an archive");
    }
    // The tails it reads still pass, the two a create acts on among them.
    // (`-ts` alone is read and, since 8 Oct 2026, declined by name: the
    // reference stores creation and access times for it, which this
    // creator does not; `tests/create_switches_never_silent.rs`. `-tsm`
    // asks only for the modification time, which is stored in any case.)
    for switch in ["-tc", "-tv", "-tsm", "-tk", "-tl", "-t"] {
        let _ = std::fs::remove_file(dir.join("new.rar"));
        ok(&dir, &["a", "-idq", switch, "new.rar", "zab"]);
        assert_eq!(names(&dir, "new.rar"), ["zab"], "{switch}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A `-t` after a create that cannot OPEN what was written exits 6, as
/// any open failure does. Measured with the archive made unreadable by
/// the run's own umask (`umask 0777; rar a -t u.rar zab`): `No files to
/// extract` on stdout, `Cannot open u.rar` and `Permission denied` on
/// stderr, exit 6. rarfast said the same and exited 10.
#[cfg(unix)]
#[test]
fn a_test_after_a_create_that_cannot_open_the_archive_exits_6() {
    let dir = three("t-open");
    // The owner of every file reads it whatever its mode: nothing to see.
    let id = Command::new("id").arg("-u").output().unwrap();
    if text(&id.stdout).trim() == "0" {
        return;
    }
    let line = format!(
        "umask 0777; exec '{}' a -mt1 -t u.rar zab",
        rarfast().display()
    );
    let output = Command::new("sh")
        .current_dir(&dir)
        .args(["-c", &line])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let (said, warned) = (text(&output.stdout), text(&output.stderr));
    assert_eq!(output.status.code(), Some(6), "{said}{warned}");
    assert!(said.contains("No files to extract"), "{said}");
    assert!(warned.contains("Cannot open u.rar"), "{warned}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Bytes no compressor shrinks, the same on every run.
fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 32) as u8
        })
        .collect()
}

/// A create with `-k` says `Locking archive`, once for each file it
/// locks. Measured: one archive reads `...  OK \nLocking archive\nDone`;
/// with `-t` the line stands between the last member and the test's
/// banner, one newline each side; a volume set has one after each
/// volume's lines, the next volume's `Creating archive` following a
/// blank line. rarfast locked and said nothing.
#[test]
fn a_create_with_k_says_locking_archive_for_each_file_it_locks() {
    let dir = three("k-line");
    let output = ok(&dir, &["a", "-k", "k.rar", "keep.txt"]);
    let said = text(&output.stdout);
    assert!(said.ends_with("  OK \nLocking archive\nDone\n"), "{said:?}");

    let output = ok(&dir, &["a", "-k", "-t", "k2.rar", "keep.txt"]);
    let said = text(&output.stdout);
    assert!(
        said.contains("  OK \nLocking archive\nTesting archive k2.rar\n"),
        "{said:?}"
    );

    std::fs::write(dir.join("big.bin"), noise(300_000)).unwrap();
    let output = ok(&dir, &["a", "-k", "-m0", "-v100k", "kv.rar", "big.bin"]);
    let said = text(&output.stdout);
    let volumes = std::fs::read_dir(&dir)
        .unwrap()
        .filter(|entry| {
            let name = entry.as_ref().unwrap().file_name();
            name.to_string_lossy().starts_with("kv.part")
        })
        .count();
    assert!(volumes >= 3, "{volumes}");
    assert_eq!(
        said.matches("Locking archive\n").count(),
        volumes,
        "{said:?}"
    );
    assert!(
        said.contains("\nLocking archive\n\nCreating archive kv.part2.rar\n\n"),
        "{said:?}"
    );
    assert!(said.ends_with("  OK \nLocking archive\nDone\n"), "{said:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Each `Cannot delete` stands on its own line of stderr. Measured, `rar
/// m m.rar ro/a.txt ro/b.txt nosuch.txt` with `ro` not writable: stderr
/// is a blank line, `Cannot open nosuch.txt` and its reason, then each
/// `Cannot delete` and its reason, the last line unended. rarfast began
/// its first `Cannot delete` on the end of the complaint before it.
#[cfg(unix)]
#[test]
fn each_cannot_delete_stands_on_its_own_line() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = work("cannot-delete");
    let id = Command::new("id").arg("-u").output().unwrap();
    if text(&id.stdout).trim() == "0" {
        return;
    }
    std::fs::create_dir_all(dir.join("ro")).unwrap();
    std::fs::write(dir.join("ro/a.txt"), "a\n").unwrap();
    std::fs::write(dir.join("ro/b.txt"), "b\n").unwrap();
    std::fs::set_permissions(dir.join("ro"), std::fs::Permissions::from_mode(0o555)).unwrap();
    let output = run(&dir, &["m", "m.rar", "ro/a.txt", "ro/b.txt", "nosuch.txt"]);
    std::fs::set_permissions(dir.join("ro"), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(output.status.code(), Some(10));
    assert_eq!(
        text(&output.stderr),
        "\nCannot open nosuch.txt\nNo such file or directory\
         \nCannot delete ro/b.txt\nPermission denied\
         \nCannot delete ro/a.txt\nPermission denied"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A file chosen twice under ONE spelling is stored once, at its LAST
/// mention, whether a mask or a name chose it; two spellings of one file
/// are two members. Every row is the reference's, measured, but for the
/// order INSIDE a mask, which there is the directory's and here is by
/// name. rarfast stored `z* zab` twice and `./zab z*` once, the reverse
/// on both counts, and kept a file named twice at its first mention.
#[test]
fn a_file_chosen_twice_under_one_spelling_is_stored_once_at_its_last_mention() {
    let dir = work("twice");
    std::fs::create_dir_all(dir.join("a")).unwrap();
    for name in ["zab", "zcd", "zef", "b.txt", "c.txt", "a/one.txt"] {
        std::fs::write(dir.join(name), format!("{name}\n")).unwrap();
    }
    let rows: [(&[&str], &[&str]); 9] = [
        (&["z*", "zab"], &["zcd", "zef", "zab"]),
        (&["zab", "z*"], &["zab", "zcd", "zef"]),
        (&["zcd", "z*"], &["zab", "zcd", "zef"]),
        (&["z*", "z*"], &["zab", "zcd", "zef"]),
        (&["zef", "z*", "zab"], &["zcd", "zef", "zab"]),
        (&["zab", "zcd", "zab"], &["zcd", "zab"]),
        (
            &["a/one.txt", "b.txt", "a/one.txt", "c.txt", "b.txt"],
            &["a/one.txt", "c.txt", "b.txt"],
        ),
        // Two spellings of one file: both stored, as the reference does.
        (&["./zab", "z*"], &["zab", "zab", "zcd", "zef"]),
        (&["z*", "./zab"], &["zab", "zcd", "zef", "zab"]),
    ];
    for (masks, stored) in rows {
        let _ = std::fs::remove_file(dir.join("c.rar"));
        let mut args = vec!["a", "-idq", "c.rar"];
        args.extend_from_slice(masks);
        ok(&dir, &args);
        assert_eq!(names(&dir, "c.rar"), stored, "{masks:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// On Windows a source is printed with backslashes however it was typed.
/// Measured against Rar.exe 7.x on Windows 11: `m m.rar data/b.txt`
/// prints `Adding    data\\b.txt` and `Deleting data\\b.txt`. The stored
/// name keeps its forward separator.
#[cfg(windows)]
#[test]
fn on_windows_a_source_is_printed_with_backslashes() {
    let dir = work("separators");
    std::fs::create_dir_all(dir.join("data")).unwrap();
    std::fs::write(dir.join("data/b.txt"), "b\n").unwrap();
    let output = ok(&dir, &["m", "m.rar", "data/b.txt"]);
    let said = text(&output.stdout);
    assert!(said.contains("Adding    data\\b.txt "), "{said}");
    assert!(said.contains("Deleting data\\b.txt "), "{said}");
    assert_eq!(names(&dir, "m.rar"), ["data/b.txt"]);
    let _ = std::fs::remove_dir_all(&dir);
}
