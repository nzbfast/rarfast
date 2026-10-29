//! The creating commands (`a`, `m`) on the cases a bug sweep of 4 Oct
//! 2026 found them wrong on.
//!
//! Every reference figure below was MEASURED on 4 Oct 2026 against `rar`
//! 7.23 on macOS:
//!
//! - **the size letters are two alphabets.** The first volume of a stored
//!   6 MB member: `-v100k` 102,400 bytes and `-v100K` 100,000; `-v2m`
//!   2,097,152 and `-v2M` 2,000,000; a bare `-v100` 100,000, so a `-v`
//!   with no letter counts THOUSANDS of bytes, and a letter that is no
//!   unit (`-v100x`) reads as none; `b` and `B` are both bytes. (`g`, `G`,
//!   `t` and `T` were measured through `-sl` and `-sm` over sparse files:
//!   2^30 and 10^9, 2^40 and 10^12. A bare `-sl` or `-sm` counts BYTES.)
//! - **symbolic links.** With no switch the reference follows them, and
//!   it has no loop detection of its own: a directory holding two links
//!   to itself does not finish there either. rarfast must finish. `-ol`
//!   stores a link as a link and `m -ol` then removes the link and never
//!   what it points at; rarfast does not build `-ol`, so it refuses it by
//!   name before anything is written or deleted.
//! - **`-dr`** asks for the sources to go to the Recycle Bin. rarfast has
//!   no such deletion, so the switch is refused by name before anything
//!   is written or deleted, rather than deleting for good (`m`) or not at
//!   all (`a`).
//!
//! Width and memory: every rarfast call states `-mt1`, and the largest
//! source is 6 MB, stored.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
#[cfg(unix)]
use std::time::{Duration, Instant};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn work(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("rarfast-createsweep-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::canonicalize(&dir).unwrap()
}

fn command(dir: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(rarfast());
    command
        .current_dir(dir)
        .arg(args[0])
        .arg("-mt1")
        .args(&args[1..])
        .stdin(Stdio::null());
    command
}

fn run(dir: &Path, args: &[&str]) -> Output {
    command(dir, args).output().unwrap()
}

fn names(dir: &Path, archive: &str) -> Vec<String> {
    let output = run(dir, &["lb", archive]);
    assert!(output.status.success(), "lb {archive}");
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

/// A run that must END: the child is killed at `limit` and `None` comes
/// back, where a run that finished gives its output.
#[cfg(unix)]
fn run_within(dir: &Path, args: &[&str], limit: Duration) -> Option<Output> {
    let mut child = command(dir, args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let started = Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            return Some(child.wait_with_output().unwrap());
        }
        if started.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Stores 6,000,000 bytes of noise under `-v<spelling>` and answers the
/// length of the lowest `out.part` file, or `None` where no such file
/// was written.
fn written_volume_len(spelling: &str) -> Option<u64> {
    let dir = work(&format!("v{spelling}"));
    std::fs::write(dir.join("data.bin"), noise(6_000_000)).unwrap();
    let switch = format!("-v{spelling}");
    let output = run(&dir, &["a", "-idq", "-m0", &switch, "out.rar", "data.bin"]);
    assert!(
        output.status.success(),
        "{switch}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let first = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("out.part"))
        .min();
    let length = first.map(|name| std::fs::metadata(dir.join(name)).unwrap().len());
    let _ = std::fs::remove_dir_all(&dir);
    length
}

#[test]
fn the_volume_size_letters_are_binary_in_lower_case_and_decimal_in_upper() {
    for (spelling, measured) in [
        ("100k", Some(102_400)),
        ("100K", Some(100_000)),
        ("2m", Some(2_097_152)),
        ("2M", Some(2_000_000)),
        ("100000b", Some(100_000)),
        ("100000B", Some(100_000)),
        // No letter, and a letter that is no unit: thousands of bytes.
        ("100", Some(100_000)),
        ("100x", Some(100_000)),
        // 7,000 thousands is more than the member: one file, whole.
        ("7000", None),
    ] {
        let first = written_volume_len(spelling);
        match measured {
            Some(_) => assert_eq!(first, measured, "-v{spelling}"),
            // What the letters selected is a volume of 7,000,000 bytes,
            // which the 6,000,000 byte member and its headers fit: the
            // one file is longer than the member and no longer than the
            // volume. Its exact length is not this test's: it is the
            // headers', and a file's attributes are a field of varying
            // length (a unix mode takes three bytes, the Windows
            // attributes of a plain file one), so a figure taken on one
            // system is two bytes off on the other. (The reference
            // names that file `out.rar` and rarfast `out.part1.rar`,
            // which is not this test's subject either.)
            None => assert!(
                first.is_some_and(|whole| whole > 6_000_000 && whole <= 7_000_000),
                "-v{spelling}: {first:?}"
            ),
        }
    }
}

#[cfg(unix)]
#[test]
fn a_directory_that_links_to_itself_twice_is_walked_to_an_end() {
    let dir = work("loops");
    std::fs::create_dir_all(dir.join("d")).unwrap();
    std::fs::write(dir.join("d/f.txt"), "f\n").unwrap();
    std::os::unix::fs::symlink(".", dir.join("d/x")).unwrap();
    std::os::unix::fs::symlink(".", dir.join("d/y")).unwrap();
    let ended = run_within(
        &dir,
        &["a", "-idq", "arc.rar", "d"],
        Duration::from_secs(20),
    );
    let ended = ended.expect("the walk did not end in 20 s");
    assert!(ended.status.success());
    // Each link is stored as the directory it reads as and not entered,
    // being the directory the walk is already inside; the one file is
    // there once.
    assert_eq!(names(&dir, "arc.rar"), ["d/f.txt", "d/x", "d/y", "d"]);
    // A link to a directory the walk is NOT inside is still followed.
    std::fs::create_dir_all(dir.join("other")).unwrap();
    std::fs::write(
        dir.join("other/o.txt"),
        "o
",
    )
    .unwrap();
    std::os::unix::fs::symlink("../other", dir.join("d/z")).unwrap();
    let output = run(&dir, &["a", "-idq", "arc2.rar", "d"]);
    assert!(output.status.success());
    assert_eq!(
        names(&dir, "arc2.rar"),
        ["d/f.txt", "d/x", "d/y", "d/z/o.txt", "d/z", "d"]
    );
    // A wildcard under `-r` ends too.
    let ended = run_within(
        &dir,
        &["a", "-idq", "-r", "arc3.rar", "d/*.txt"],
        Duration::from_secs(20),
    );
    assert!(ended.is_some(), "the wildcard walk did not end in 20 s");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn a_move_given_ol_fails_naming_it_and_deletes_nothing() {
    for switch in ["-ol", "-ola", "-ol-"] {
        let dir = work(&format!("ol{}", switch.len()));
        std::fs::create_dir_all(dir.join("d")).unwrap();
        std::fs::create_dir_all(dir.join("outside")).unwrap();
        std::fs::write(dir.join("d/f.txt"), "f\n").unwrap();
        std::fs::write(dir.join("outside/o.txt"), "o\n").unwrap();
        std::os::unix::fs::symlink("../outside", dir.join("d/link")).unwrap();
        let output = run(&dir, &["m", "-idq", switch, "arc.rar", "d"]);
        let warned = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(!output.status.success(), "{switch} was accepted");
        assert!(warned.contains("`-ol"), "{switch}: {warned}");
        assert_eq!(std::fs::read(dir.join("outside/o.txt")).unwrap(), b"o\n");
        assert_eq!(std::fs::read(dir.join("d/f.txt")).unwrap(), b"f\n");
        assert!(!dir.join("arc.rar").exists(), "{switch} wrote an archive");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn a_create_given_dr_fails_naming_it_and_leaves_source_and_archive_alone() {
    for word in ["m", "a"] {
        let dir = work(&format!("dr-{word}"));
        std::fs::write(dir.join("a.txt"), "a\n").unwrap();
        let output = run(&dir, &[word, "-idq", "-dr", "arc.rar", "a.txt"]);
        let warned = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(!output.status.success(), "{word} -dr was accepted");
        assert!(warned.contains("`-dr`"), "{word}: {warned}");
        assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), b"a\n");
        assert!(!dir.join("arc.rar").exists(), "{word} -dr wrote an archive");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The run is held between its selection and its write by a comment file
/// that is a FIFO: the creator reads its `-z` file after it has chosen
/// the sources and created the archive, so it waits there until this
/// test, having written into the file that was empty, hands it a comment.
#[cfg(unix)]
#[test]
fn a_file_that_was_empty_when_chosen_is_not_moved_away_with_what_it_then_held() {
    let dir = work("grew");
    std::fs::create_dir_all(dir.join("logs")).unwrap();
    std::fs::write(dir.join("logs/app.log"), "").unwrap();
    std::fs::write(dir.join("logs/old.log"), "old\n").unwrap();
    let made = Command::new("mkfifo")
        .arg(dir.join("comment"))
        .status()
        .unwrap();
    assert!(made.success());

    let mut child = command(&dir, &["m", "-idq", "-zcomment", "arc.rar", "logs"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // The archive exists once the sources are chosen.
    let started = Instant::now();
    while !dir.join("arc.rar").exists() {
        assert!(started.elapsed() < Duration::from_secs(20), "no archive");
        assert!(child.try_wait().unwrap().is_none(), "the run ended early");
        std::thread::sleep(Duration::from_millis(10));
    }
    std::fs::write(dir.join("logs/app.log"), "written after the walk\n").unwrap();
    // Opening the FIFO for writing waits for the creator to open it.
    std::fs::write(dir.join("comment"), "a comment\n").unwrap();
    let status = child.wait().unwrap();

    // Either the file is still there with its bytes, and the run says it
    // kept it, or the archive holds them. What must never be: the file
    // gone and the archive holding an empty member in its place.
    let on_disk = std::fs::read(dir.join("logs/app.log")).ok();
    if on_disk.as_deref() == Some(b"written after the walk\n".as_slice()) {
        assert_eq!(status.code(), Some(1), "the file was kept with no word");
        // What the run did archive is gone, and nothing else is.
        assert!(!dir.join("logs/old.log").exists());
    } else {
        assert!(status.success(), "the file is gone and the run failed");
        let printed = run(&dir, &["p", "-idq", "arc.rar", "logs/app.log"]);
        assert_eq!(
            String::from_utf8_lossy(&printed.stdout),
            "written after the walk\n",
            "logs/app.log was deleted holding bytes the archive does not have"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The reference stores `C:\data\f.txt` as `data/f.txt`.
#[cfg(windows)]
#[test]
fn a_source_typed_with_its_drive_letter_is_stored_without_it() {
    let dir = work("drive");
    std::fs::write(dir.join("f.txt"), "f\n").unwrap();
    let typed = dir.join("f.txt");
    let typed = typed.to_string_lossy();
    // `\\?\C:\...` as canonicalize gives it, cut back to `C:\...`.
    let typed = typed.trim_start_matches(r"\\?\");
    assert_eq!(typed.as_bytes()[1], b':', "{typed}");
    let output = run(&dir, &["a", "-idq", "arc.rar", typed]);
    assert!(output.status.success());
    let expected = typed[2..].trim_start_matches('\\').replace('\\', "/");
    assert_eq!(names(&dir, "arc.rar"), [expected]);
    let _ = std::fs::remove_dir_all(&dir);
}
