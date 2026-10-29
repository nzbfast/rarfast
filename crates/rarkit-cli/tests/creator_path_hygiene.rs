//! What `a` stores for sources typed with an absolute path or with
//! parent steps, how it treats symbolic links among its sources, and a
//! plain tree's round trip through `a` and `x`, on macOS and Linux.
//!
//! - No stored name is absolute or climbs out: a leading `/` goes and so
//!   does everything up to and including the last `..`, each name as
//!   `rar` 7.23 stores it (measured on macOS, 28 Oct 2026, with `rar a`
//!   and `unrar lb` over the same forms).
//! - The walk FOLLOWS a symbolic link, to a file or to a directory, and
//!   stores what it leads to under the link's name, as `rar` 7.23 does
//!   without `-ol` (measured the same day), even where the link leads
//!   outside the sources named (SPEC-CLI 8.2). `-ol`, `-ola` and `-ol-`,
//!   which would store the link itself or leave it out, are refused by
//!   name rather than read as nothing.
//! - A file whose own name holds a backslash `..` step (a name a
//!   Windows extractor reads as a climb) is never stored, where `rar`
//!   7.23 stores it as it is. Today that refusal stops the whole run: no
//!   archive is written, which loses nothing and keeps every source,
//!   under `m` too, and the message says that the archive was not
//!   written, which file stopped it and why. Finishing the run without
//!   that member instead is left for a later release. Both names in that
//!   message are printed as any name is (SPEC-CLI section 10): on a
//!   terminal a control character is its stand-in `<U+XXXX>`, through a
//!   pipe it is its own byte (T5), and ESC is `'\033'` on both (T4).
//!
//! Every source is a few bytes long and every run is one process.

#![cfg(unix)]

use std::io::Read;
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-hygiene-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn rarfast(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rarfast"))
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap()
}

/// The stored names of `archive`, one a line, as `lb` lists them.
fn names(dir: &Path, archive: &str) -> Vec<String> {
    let listed = rarfast(dir, &["lb", archive]);
    assert!(listed.status.success(), "lb {archive}: {listed:?}");
    String::from_utf8(listed.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// `w/src` with a file, a subdirectory, a link to a file outside it and
/// a link to a directory outside it; `w/outside` holding the secret;
/// `w/run`, where every command runs.
fn tree(dir: &Path) -> PathBuf {
    let w = dir.join("w");
    std::fs::create_dir_all(w.join("src/sub")).unwrap();
    std::fs::create_dir_all(w.join("outside")).unwrap();
    std::fs::create_dir_all(w.join("run")).unwrap();
    std::fs::write(w.join("src/a.txt"), b"a\n").unwrap();
    std::fs::write(w.join("src/sub/b.txt"), b"b\n").unwrap();
    std::fs::write(w.join("outside/secret.txt"), b"secret\n").unwrap();
    std::os::unix::fs::symlink("../outside/secret.txt", w.join("src/flink")).unwrap();
    std::os::unix::fs::symlink("../outside", w.join("src/dlink")).unwrap();
    w
}

#[test]
fn no_stored_name_is_absolute_or_climbs_out() {
    let dir = work("names");
    let w = tree(&dir);
    let run = w.join("run");
    let absolute = w.join("src/a.txt");
    let absolute = absolute.to_str().unwrap();
    let mut wrong = Vec::new();
    for (tag, args, stored) in [
        (
            "abs",
            vec![absolute],
            vec![absolute.trim_start_matches('/')],
        ),
        ("up", vec!["../src/a.txt"], vec!["src/a.txt"]),
        ("mid", vec!["../src/../src/a.txt"], vec!["src/a.txt"]),
        ("ep2", vec!["-ep2", "../src/a.txt"], vec!["src/a.txt"]),
        // A `dir/` mask with no `-r` takes that directory's files only.
        ("ep1", vec!["-ep1", "../src/"], vec!["a.txt", "flink"]),
    ] {
        let archive = format!("{tag}.rar");
        let mut full = vec!["a", "-idq", archive.as_str()];
        full.extend(&args);
        let made = rarfast(&run, &full);
        if !made.status.success() {
            wrong.push(format!("{tag}: {made:?}"));
            continue;
        }
        let mut got = names(&run, &archive);
        let mut want: Vec<String> = stored.iter().map(|s| (*s).to_owned()).collect();
        got.sort();
        want.sort();
        if got != want {
            wrong.push(format!("{tag}: stored {got:?}, want {want:?}"));
        }
        for name in &got {
            if name.starts_with('/') || name.split('/').any(|part| part == "..") {
                wrong.push(format!("{tag}: {name:?} is absolute or climbs out"));
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn a_link_is_followed_and_its_target_stored_under_the_links_name() {
    let dir = work("links");
    let w = tree(&dir);
    let run = w.join("run");
    let made = rarfast(&run, &["a", "-idq", "tree.rar", "../src"]);
    assert!(made.status.success(), "{made:?}");
    let mut got = names(&run, "tree.rar");
    got.sort();
    assert_eq!(
        got,
        [
            "src",
            "src/a.txt",
            "src/dlink",
            "src/dlink/secret.txt",
            "src/flink",
            "src/sub",
            "src/sub/b.txt"
        ]
    );
    let out = run.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let taken = rarfast(&run, &["x", "-idq", "tree.rar", "out/"]);
    assert!(taken.status.success(), "{taken:?}");
    for path in ["src/flink", "src/dlink/secret.txt"] {
        let meta = std::fs::symlink_metadata(out.join(path)).unwrap();
        assert!(meta.is_file(), "{path} is not a plain file");
        assert_eq!(
            std::fs::read(out.join(path)).unwrap(),
            b"secret\n",
            "{path}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_switch_that_would_store_or_skip_links_is_refused_by_name() {
    let dir = work("ol");
    let w = tree(&dir);
    let run = w.join("run");
    for switch in ["-ol", "-ola", "-ol-"] {
        let archive = format!("ol{}.rar", switch.len());
        let refused = rarfast(&run, &["a", switch, archive.as_str(), "../src"]);
        let said = String::from_utf8_lossy(&refused.stderr);
        assert!(!refused.status.success(), "{switch}: {refused:?}");
        assert!(said.contains(switch), "{switch} not named: {said}");
        assert!(!run.join(&archive).exists(), "{switch} wrote {archive}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_plain_tree_comes_back_as_it_went_in() {
    let dir = work("round");
    let src = dir.join("src");
    let files: [(&str, &[u8]); 5] = [
        ("top.txt", b"top\n"),
        ("d/one.bin", &[0, 1, 2, 255]),
        ("d/e/two.txt", b"two\n"),
        ("d/e/sp ace.txt", b"space\n"),
        ("u/n\u{e9}e.txt", b"accent\n"),
    ];
    for (name, bytes) in files {
        let path = src.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
    }
    std::fs::create_dir_all(src.join("empty")).unwrap();
    let made = rarfast(&dir, &["a", "-idq", "round.rar", "src"]);
    assert!(made.status.success(), "{made:?}");
    let out = dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let taken = rarfast(&dir, &["x", "-idq", "round.rar", "out/"]);
    assert!(taken.status.success(), "{taken:?}");
    for (name, bytes) in files {
        assert_eq!(
            std::fs::read(out.join("src").join(name)).unwrap(),
            bytes,
            "{name}"
        );
    }
    assert!(out.join("src/empty").is_dir());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_backslash_climb_in_a_disk_name_is_never_stored() {
    let dir = work("backslash");
    let bs = dir.join("bs");
    std::fs::create_dir_all(&bs).unwrap();
    std::fs::write(bs.join("plain.txt"), b"plain\n").unwrap();
    let hostile = "x\\..\\..\\evil.txt";
    std::fs::write(bs.join(hostile), b"bs\n").unwrap();
    for command in ["a", "m"] {
        let archive = format!("{command}.rar");
        let run = rarfast(&dir, &[command, "-idq", archive.as_str(), "bs"]);
        let said = String::from_utf8_lossy(&run.stderr);
        assert!(!run.status.success(), "{command}: {run:?}");
        assert!(said.contains(hostile), "{command}: not named: {said}");
        // The message says what happened: the archive, not only that
        // one file, was not written, and why that file stopped it.
        let whole = format!("{archive} was not written");
        assert!(
            said.contains(&whole),
            "{command}: {whole:?} not said: {said}"
        );
        assert!(said.contains("`..` step"), "{command}: no reason: {said}");
        assert!(!said.contains("was not added"), "{command}: {said}");
        // Nothing was written that could hold the name, and every
        // source is where it was.
        assert!(!dir.join(&archive).exists(), "{command} wrote {archive}");
        assert_eq!(std::fs::read(bs.join("plain.txt")).unwrap(), b"plain\n");
        assert_eq!(std::fs::read(bs.join(hostile)).unwrap(), b"bs\n");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A pseudo terminal with output processing off: the end the reader
/// keeps, and the end the tool writes to.
#[allow(unsafe_code)]
fn terminal() -> (std::fs::File, OwnedFd) {
    let (mut reader, mut writer) = (0, 0);
    // SAFETY: openpty fills the two descriptors or fails; the three
    // null pointers ask for no name and the default settings.
    let made = unsafe {
        libc::openpty(
            &mut reader,
            &mut writer,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(made, 0, "openpty: {}", std::io::Error::last_os_error());
    // SAFETY: `writer` is the open terminal end just made; the settings
    // are read into a zeroed struct, made raw, and written back.
    unsafe {
        let mut settings: libc::termios = std::mem::zeroed();
        assert_eq!(libc::tcgetattr(writer, &mut settings), 0);
        libc::cfmakeraw(&mut settings);
        assert_eq!(libc::tcsetattr(writer, libc::TCSANOW, &settings), 0);
    }
    // SAFETY: both descriptors are open and owned by nothing else.
    unsafe {
        (
            std::fs::File::from_raw_fd(reader),
            OwnedFd::from_raw_fd(writer),
        )
    }
}

/// What `rarfast <args>` in `dir` writes to stderr, a terminal or a
/// pipe; stdout goes nowhere.
fn stderr_of(dir: &Path, args: &[&str], on_terminal: bool) -> Vec<u8> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rarfast"));
    command
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    if !on_terminal {
        return command.output().unwrap().stderr;
    }
    let (mut reader, writer) = terminal();
    command.stderr(Stdio::from(writer));
    let mut child = command.spawn().unwrap();
    // The command still holds the tool's end of the terminal; it must
    // close here or the reader never sees the end.
    drop(command);
    let drained = std::thread::spawn(move || {
        let mut all = Vec::new();
        let mut piece = [0_u8; 4096];
        // A terminal's reader ends with an error on Linux and with no
        // bytes on macOS.
        while let Ok(n @ 1..) = reader.read(&mut piece) {
            all.extend_from_slice(&piece[..n]);
        }
        all
    });
    child.wait().unwrap();
    drained.join().unwrap()
}

#[test]
fn a_refused_name_in_the_message_writes_no_byte_a_terminal_acts_on() {
    let dir = work("refused-controls");
    let bs = dir.join("bs");
    std::fs::create_dir_all(&bs).unwrap();
    let hostile = "x\\..\\e\u{1b}[2Ky\r\u{7}z.txt";
    std::fs::write(bs.join(hostile), b"bs\n").unwrap();
    let args = ["a", "-idq", "a.rar", "bs"];
    let said = stderr_of(&dir, &args, true);
    let text = String::from_utf8_lossy(&said);
    let acting: Vec<u8> = said
        .iter()
        .copied()
        .filter(|&b| (b < 0x20 && b != b'\n') || b == 0x7F)
        .collect();
    assert!(acting.is_empty(), "acting bytes {acting:?} in {text:?}");
    // Both names, the one on disk and the one it would be stored under.
    let shown = "x\\..\\e'\\033'[2Ky<U+000D><U+0007>z.txt";
    assert_eq!(text.matches(shown).count(), 2, "{text:?}");
    assert!(text.contains("a.rar was not written"), "{text:?}");
    // Through a pipe a control character is its own byte; ESC is not.
    let piped = String::from_utf8_lossy(&stderr_of(&dir, &args, false)).into_owned();
    let raw = "x\\..\\e'\\033'[2Ky\r\u{7}z.txt";
    assert_eq!(piped.matches(raw).count(), 2, "{piped:?}");
    assert!(!piped.contains('\u{1b}'), "{piped:?}");
    assert!(!dir.join("a.rar").exists());
    let _ = std::fs::remove_dir_all(&dir);
}
