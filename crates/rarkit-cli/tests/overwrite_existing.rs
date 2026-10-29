//! `x` and `e` over outputs that are ALREADY THERE, as reference unrar 7.23
//! leaves them and says so.
//!
//! MEASURED against unrar 7.23 on macOS (arm64) and x86-64 Linux, 2 Oct 2026:
//!
//! - the default rule (`-o`, or no switch) ASKS about each file that is
//!   there, on stderr, and reads the answer from standard input: `Y`, `N`,
//!   `A`, `E`, `R` and `Q`. Until that day rarfast kept every such file,
//!   read no answer and closed with `All OK`, exit 0;
//! - a run that wrote NOTHING, each file kept or not creatable, closes with
//!   `No files to extract`, exit 10 (or 9 with the creates' complaints),
//!   never `All OK`;
//! - `Q` is `Program aborted`, exit 255; an answer that cannot be read (the
//!   input ended) is `Read error in the file stdin`, `Program aborted`,
//!   exit 12;
//! - a file that cannot be created is `Cannot create <path>` and the
//!   system's reason, with no progress line.
//!
//! Every archive here is made by rarfast itself, from this system's files.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// Stands watch over the directory one row of this file works in. The
/// row holds it beside the directory's path and never uses it; when it
/// is let go, at the row's end or because an assertion failed, everything
/// in the directory is made writable again and the directory is deleted.
struct DirWatch(PathBuf);

impl Drop for DirWatch {
    fn drop(&mut self) {
        open_up(&self.0);
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Every file and directory under `dir` made writable again.
fn open_up(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        set_writable(&path, &meta);
        if meta.is_dir() {
            open_up(&path);
        }
    }
}

#[cfg(unix)]
fn set_writable(path: &Path, meta: &std::fs::Metadata) {
    use std::os::unix::fs::PermissionsExt;
    let bits = if meta.is_dir() { 0o755 } else { 0o644 };
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits));
}

#[cfg(not(unix))]
fn set_writable(path: &Path, meta: &std::fs::Metadata) {
    // Read-only, hidden and system all go, a file at a time: `attrib`
    // changes no hidden or system file it is not told to.
    if cfg!(windows) && !meta.is_dir() {
        let _ = Command::new("attrib")
            .args(["-r", "-h", "-s"])
            .arg(path)
            .output();
    }
    let mut permissions = meta.permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    permissions.set_readonly(false);
    let _ = std::fs::set_permissions(path, permissions);
}

fn work(tag: &str) -> (PathBuf, DirWatch) {
    let dir = std::env::temp_dir().join(format!("rarfast-over-there-{}-{tag}", std::process::id()));
    if dir.exists() {
        open_up(&dir);
        std::fs::remove_dir_all(&dir).unwrap();
    }
    std::fs::create_dir_all(&dir).unwrap();
    (dir.clone(), DirWatch(dir))
}

const A: &[u8] = b"alpha alpha alpha\n";
const B: &[u8] = b"beta\n";
const C: &[u8] = b"gamma\n";
const OTHER: &[u8] = b"other bytes";

/// The reason line under `Read error in the file stdin` where the input
/// simply ended.
#[cfg(not(windows))]
const ENDED: &str = "Inappropriate ioctl for device";
#[cfg(windows)]
const ENDED: &str = "The pipe has been ended.";

/// `arc.rar` in `root`, of `a.txt` and `b.txt`, and with `with_dir` of
/// `sub/c.txt` and its directory too, made by `rarfast a` with `switches`.
fn archive(root: &Path, with_dir: bool, switches: &[&str]) -> PathBuf {
    let src = root.join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("a.txt"), A).unwrap();
    std::fs::write(src.join("b.txt"), B).unwrap();
    std::fs::write(src.join("sub").join("c.txt"), C).unwrap();
    let arc = root.join("arc.rar");
    let mut command = Command::new(rarfast());
    command
        .current_dir(&src)
        .args(["a", "-idq", "-y", "-m3", "-r"])
        .args(switches)
        .arg(&arc)
        .args(["a.txt", "b.txt"]);
    if with_dir {
        command.arg("sub");
    }
    let made = command.output().unwrap();
    assert!(made.status.success(), "the archive: {made:?}");
    arc
}

/// What a run is given on its standard input.
enum Feed<'a> {
    Bytes(&'a [u8]),
    Null,
}

/// `rarfast <args> <arc> out/` run in `root`, so that every path it prints
/// is relative and the same on every system but for its separator.
fn run(root: &Path, arc: &Path, args: &[&str], feed: Feed<'_>) -> Output {
    let mut command = Command::new(rarfast());
    command
        .current_dir(root)
        .args(args)
        .arg(arc.file_name().expect("an archive in the root"))
        .arg(format!("out{}", std::path::MAIN_SEPARATOR))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    match feed {
        Feed::Null => {
            command.stdin(Stdio::null());
            command.output().unwrap()
        }
        Feed::Bytes(bytes) => {
            command.stdin(Stdio::piped());
            let mut child = command.spawn().unwrap();
            // The run may stop reading before the last answer: not an error.
            let _ = child.stdin.take().unwrap().write_all(bytes);
            child.wait_with_output().unwrap()
        }
    }
}

/// The destination as a first extraction leaves it, each file then holding
/// other bytes: `out/a.txt`, `out/b.txt` and, with `with_dir`,
/// `out/sub/c.txt`.
fn there(root: &Path, arc: &Path, more: &[&str]) {
    let out = root.join("out");
    if out.exists() {
        open_up(&out);
        std::fs::remove_dir_all(&out).unwrap();
    }
    let mut args = vec!["x", "-idq", "-o+"];
    args.extend_from_slice(more);
    let first = run(root, arc, &args, Feed::Null);
    assert!(first.status.success(), "the first extraction: {first:?}");
    for name in ["a.txt", "b.txt", "sub/c.txt"] {
        let path = out.join(name);
        if path.exists() {
            std::fs::write(&path, OTHER).unwrap();
        }
    }
}

fn read(root: &Path, name: &str) -> Vec<u8> {
    std::fs::read(root.join("out").join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).replace('\x08', "")
}

/// `out/<name>` as the run prints it on this system.
fn shown(name: &str) -> String {
    format!("out/{name}").replace('/', std::path::MAIN_SEPARATOR_STR)
}

/// `stderr` with each `modified on <time>` cut to `modified on T`: the time
/// is the local one, which a test does not compute.
fn untimed(stderr: &[u8]) -> String {
    let said = String::from_utf8_lossy(stderr).into_owned();
    let mut out = String::new();
    let mut rest = said.as_str();
    while let Some(at) = rest.find("modified on ") {
        let stamp = at + "modified on ".len();
        out.push_str(&rest[..stamp]);
        let time = &rest[stamp..stamp + 16];
        let bytes = time.as_bytes();
        assert!(
            bytes[4] == b'-' && bytes[7] == b'-' && bytes[10] == b' ' && bytes[13] == b':',
            "a time reads YYYY-MM-DD HH:MM, not {time:?}"
        );
        out.push('T');
        rest = &rest[stamp + 16..];
    }
    out.push_str(rest);
    out
}

fn question(name: &str, there: usize, new: usize) -> String {
    format!(
        "\nWould you like to replace the existing file {}\n{there:>6} bytes, modified on T\nwith \
         a new one\n{new:>6} bytes, modified on T\n\n[Y]es, [N]o, [A]ll, n[E]ver, [R]ename, [Q]uit ",
        shown(name)
    )
}

#[test]
fn the_default_rule_asks_on_stderr_and_a_answers_for_every_file() {
    let (root, _watch) = work("a");
    let arc = archive(&root, true, &[]);
    for (form, answer) in [
        (&["x"][..], &b"A\n"[..]),
        (&["x", "-o"], b"A\n"),
        (&["x"], b"a\n"),
        (&["x"], b"All\n"),
        (&["x"], b"A"),
        (&["x"], b"A\r\n"),
        (&["e"], b"A\n"),
    ] {
        let row = format!("{form:?} answered {:?}", String::from_utf8_lossy(answer));
        there(&root, &arc, &[]);
        let done = run(&root, &arc, form, Feed::Bytes(answer));
        assert_eq!(done.status.code(), Some(0), "{row}: {done:?}");
        assert_eq!(read(&root, "a.txt"), A, "{row}");
        assert_eq!(read(&root, "b.txt"), B, "{row}");
        if form[0] == "x" {
            assert_eq!(read(&root, "sub/c.txt"), C, "{row}");
        }
        // Asked once, about the first file, apart from the messages.
        assert_eq!(
            untimed(&done.stderr),
            format!("\n{}", question("a.txt", OTHER.len(), A.len())),
            "{row}"
        );
        assert!(
            text(&done.stdout).ends_with("OK \nAll OK\n"),
            "{row}: {done:?}"
        );
    }
}

#[test]
fn y_and_n_answer_for_one_file_each() {
    let (root, _watch) = work("yn");
    let arc = archive(&root, true, &[]);
    there(&root, &arc, &[]);
    let done = run(&root, &arc, &["x"], Feed::Bytes(b"Y\nN\ny\n"));
    assert_eq!(done.status.code(), Some(0), "{done:?}");
    assert_eq!(read(&root, "a.txt"), A);
    assert_eq!(read(&root, "b.txt"), OTHER);
    assert_eq!(read(&root, "sub/c.txt"), C);
    assert_eq!(
        untimed(&done.stderr),
        format!(
            "\n{}\n{}\n{}",
            question("a.txt", OTHER.len(), A.len()),
            question("b.txt", OTHER.len(), B.len()),
            question("sub/c.txt", OTHER.len(), C.len())
        )
    );
    let said = text(&done.stdout);
    assert!(
        said.contains(&format!("Extracting  {}", shown("a.txt"))),
        "{said}"
    );
    assert!(
        !said.contains(&shown("b.txt")),
        "a kept file has no line: {said}"
    );
    assert!(said.ends_with("All OK\n"), "{said}");
}

/// The row this file exists for: `All OK`, exit 0, over files that were
/// not written.
#[test]
fn an_extract_that_writes_nothing_never_says_all_ok() {
    let (root, _watch) = work("nothing");
    let arc = archive(&root, false, &[]);
    for (form, feed, code, closing) in [
        (
            &["x"][..],
            Some(&b"N\nN\n"[..]),
            10,
            "No files to extract\n",
        ),
        (&["x"], Some(b"E\n"), 10, "No files to extract\n"),
        (&["x"], Some(b"n\nE\n"), 10, "No files to extract\n"),
        (&["x"], Some(b"Q\n"), 255, "Program aborted\n"),
        (&["x"], Some(b"N\nQ\n"), 255, "Program aborted\n"),
        (&["x"], Some(b""), 12, "Program aborted\n"),
        (&["x"], Some(b"N\n"), 12, "Program aborted\n"),
        (&["x"], None, 12, "Program aborted\n"),
        (&["x", "-o"], None, 12, "Program aborted\n"),
        (&["e"], Some(b"N\nN\n"), 10, "No files to extract\n"),
        (&["x", "-o-"], None, 10, "No files to extract\n"),
        (&["x", "-o-", "-y"], None, 10, "No files to extract\n"),
        (&["e", "-o-"], None, 10, "No files to extract\n"),
    ] {
        let row = format!("{form:?} fed {:?}", feed.map(String::from_utf8_lossy));
        there(&root, &arc, &[]);
        let done = run(&root, &arc, form, feed.map_or(Feed::Null, Feed::Bytes));
        assert_eq!(read(&root, "a.txt"), OTHER, "{row}");
        assert_eq!(read(&root, "b.txt"), OTHER, "{row}");
        let said = text(&done.stdout);
        assert!(!said.contains("All OK"), "{row}: {said}");
        assert_eq!(done.status.code(), Some(code), "{row}: {done:?}");
        assert!(said.ends_with(closing), "{row}: {said:?}");
        // The same with the messages dropped: the exit still says so.
        there(&root, &arc, &[]);
        let mut quiet = form.to_vec();
        quiet.push("-idq");
        let done = run(&root, &arc, &quiet, feed.map_or(Feed::Null, Feed::Bytes));
        assert_eq!(done.status.code(), Some(code), "{row} -idq: {done:?}");
        assert!(done.stdout.is_empty(), "{row} -idq: {done:?}");
        assert_eq!(read(&root, "a.txt"), OTHER, "{row} -idq");
    }
}

#[test]
fn the_exact_bytes_of_the_closes() {
    let (root, _watch) = work("bytes");
    let arc = archive(&root, false, &[]);
    let banner = "\nExtracting from arc.rar\n\n";
    let first = question("a.txt", OTHER.len(), A.len());
    let second = question("b.txt", OTHER.len(), B.len());
    // (switches, answers, stdout, stderr), apart and on one stream.
    let rows: [(&[&str], &[u8], String, String); 8] = [
        (
            &["x"],
            b"N\nN\n",
            format!("{banner}No files to extract\n"),
            format!("\n{first}\n{second}"),
        ),
        (
            &["x"],
            b"Q\n",
            format!("{banner}Program aborted\n"),
            format!("\n{first}"),
        ),
        (
            &["x"],
            b"",
            format!("{banner}\nProgram aborted\n"),
            format!("\n{first}Read error in the file stdin\n{ENDED}"),
        ),
        (
            &["x"],
            b"what\n\nN\nN\n",
            format!("{banner}No files to extract\n"),
            format!(
                "\n{first}\n[Y]es, [N]o, [A]ll, n[E]ver, [R]ename, [Q]uit \n[Y]es, [N]o, [A]ll, \
                 n[E]ver, [R]ename, [Q]uit \n{second}"
            ),
        ),
        (
            &["x", "-ierr"],
            b"N\nN\n",
            String::new(),
            format!("{banner}{first}\n{second}\nNo files to extract\n"),
        ),
        (
            &["x", "-ierr"],
            b"Q\n",
            String::new(),
            format!("{banner}{first}\nProgram aborted\n"),
        ),
        (
            &["x", "-ierr"],
            b"",
            String::new(),
            format!("{banner}{first}\nRead error in the file stdin\n{ENDED}\nProgram aborted\n"),
        ),
        // `-idq` keeps the question and leaves stderr unended after a stop.
        (&["x", "-idq"], b"Q\n", String::new(), format!("\n{first}")),
    ];
    for (form, answers, stdout, stderr) in rows {
        let row = format!("{form:?} fed {:?}", String::from_utf8_lossy(answers));
        there(&root, &arc, &[]);
        let done = run(&root, &arc, form, Feed::Bytes(answers));
        assert_eq!(String::from_utf8_lossy(&done.stdout), stdout, "{row}");
        assert_eq!(untimed(&done.stderr), stderr, "{row}");
    }
    // `-inul` says nothing and still reads the answer.
    there(&root, &arc, &[]);
    let done = run(&root, &arc, &["x", "-inul"], Feed::Bytes(b"A\n"));
    assert_eq!(done.status.code(), Some(0), "{done:?}");
    assert!(done.stdout.is_empty() && done.stderr.is_empty(), "{done:?}");
    assert_eq!(read(&root, "a.txt"), A);
}

#[test]
fn one_file_written_or_a_directory_entry_is_all_ok() {
    // A directory member is processed whatever is done with the files.
    let (root, _watch) = work("dir");
    let arc = archive(&root, true, &[]);
    for (form, feed) in [
        (&["x", "-o-"][..], None),
        (&["x"], Some(&b"N\nN\nN\n"[..])),
        (&["x"], Some(b"E\n")),
    ] {
        there(&root, &arc, &[]);
        let done = run(&root, &arc, form, feed.map_or(Feed::Null, Feed::Bytes));
        assert_eq!(done.status.code(), Some(0), "{form:?}: {done:?}");
        assert!(
            text(&done.stdout).ends_with("All OK\n"),
            "{form:?}: {done:?}"
        );
        assert_eq!(read(&root, "a.txt"), OTHER, "{form:?}");
    }
    // So is one file that was not there.
    let (root, _watch) = work("one-missing");
    let arc = archive(&root, false, &[]);
    for (form, feed) in [(&["x", "-o-"][..], None), (&["x"], Some(&b"N\n"[..]))] {
        there(&root, &arc, &[]);
        std::fs::remove_file(root.join("out").join("b.txt")).unwrap();
        let done = run(&root, &arc, form, feed.map_or(Feed::Null, Feed::Bytes));
        assert_eq!(done.status.code(), Some(0), "{form:?}: {done:?}");
        assert!(
            text(&done.stdout).ends_with("All OK\n"),
            "{form:?}: {done:?}"
        );
        assert_eq!(read(&root, "a.txt"), OTHER, "{form:?}");
        assert_eq!(read(&root, "b.txt"), B, "{form:?}");
    }
}

#[test]
fn q_stops_at_once_and_keeps_what_was_written_before_it() {
    let (root, _watch) = work("q");
    let arc = archive(&root, true, &[]);
    there(&root, &arc, &[]);
    let done = run(&root, &arc, &["x"], Feed::Bytes(b"Y\nQ\nA\n"));
    assert_eq!(done.status.code(), Some(255), "{done:?}");
    assert_eq!(read(&root, "a.txt"), A);
    assert_eq!(read(&root, "b.txt"), OTHER);
    assert_eq!(read(&root, "sub/c.txt"), OTHER);
    assert!(
        text(&done.stdout).ends_with("OK \nProgram aborted\n"),
        "{done:?}"
    );
    // An input that ends after an answer stops there too.
    there(&root, &arc, &[]);
    let done = run(&root, &arc, &["x"], Feed::Bytes(b"Y\n"));
    assert_eq!(done.status.code(), Some(12), "{done:?}");
    assert_eq!(read(&root, "a.txt"), A);
    assert_eq!(read(&root, "b.txt"), OTHER);
    assert!(
        text(&done.stdout).ends_with("OK \n\nProgram aborted\n"),
        "{done:?}"
    );
    assert!(
        String::from_utf8_lossy(&done.stderr)
            .ends_with(&format!("[Q]uit Read error in the file stdin\n{ENDED}")),
        "{done:?}"
    );
}

#[test]
fn e_keeps_every_later_file_and_asks_no_more() {
    let (root, _watch) = work("e");
    let arc = archive(&root, true, &[]);
    there(&root, &arc, &[]);
    let done = run(&root, &arc, &["x"], Feed::Bytes(b"Y\nE\n"));
    assert_eq!(done.status.code(), Some(0), "{done:?}");
    assert_eq!(read(&root, "a.txt"), A);
    assert_eq!(read(&root, "b.txt"), OTHER);
    assert_eq!(read(&root, "sub/c.txt"), OTHER);
    assert_eq!(untimed(&done.stderr).matches("Would you like").count(), 2);
}

#[test]
fn r_writes_under_the_path_typed_and_asks_again_where_that_is_taken() {
    let (root, _watch) = work("r");
    let arc = archive(&root, false, &[]);
    there(&root, &arc, &[]);
    let typed = shown("renamed.txt");
    let done = run(
        &root,
        &arc,
        &["x"],
        Feed::Bytes(format!("R\n{typed}\nN\n").as_bytes()),
    );
    assert_eq!(done.status.code(), Some(0), "{done:?}");
    assert_eq!(read(&root, "a.txt"), OTHER);
    assert_eq!(read(&root, "renamed.txt"), A);
    assert_eq!(read(&root, "b.txt"), OTHER);
    let said = text(&done.stdout);
    assert!(
        said.contains(&format!("Enter new name: \nExtracting  {typed}")),
        "{said:?}"
    );
    // A typed path that is taken is asked about in its turn, with the
    // member's size, and `A` then answers for the rest.
    there(&root, &arc, &[]);
    let taken = shown("b.txt");
    let done = run(
        &root,
        &arc,
        &["x"],
        Feed::Bytes(format!("R\n{taken}\nA\n").as_bytes()),
    );
    assert_eq!(done.status.code(), Some(0), "{done:?}");
    assert_eq!(read(&root, "a.txt"), OTHER);
    assert_eq!(read(&root, "b.txt"), B);
    assert_eq!(
        untimed(&done.stderr),
        format!(
            "\n{}\n{}",
            question("a.txt", OTHER.len(), A.len()),
            question("b.txt", OTHER.len(), A.len())
        )
    );
    // A bare name goes beside the file it stands in for.
    there(&root, &arc, &[]);
    let done = run(&root, &arc, &["x"], Feed::Bytes(b"R\nbare.txt\nN\n"));
    assert_eq!(done.status.code(), Some(0), "{done:?}");
    assert_eq!(read(&root, "bare.txt"), A);
    assert!(!root.join("bare.txt").exists());
    assert!(
        text(&done.stdout).contains(&format!(
            "Enter new name: \nExtracting  {}",
            shown("bare.txt")
        )),
        "{done:?}"
    );
    // No name to read: the run stops as at any answer it cannot read.
    there(&root, &arc, &[]);
    let done = run(&root, &arc, &["x"], Feed::Bytes(b"R\n"));
    assert_eq!(done.status.code(), Some(12), "{done:?}");
    assert_eq!(read(&root, "a.txt"), OTHER);
    assert!(
        text(&done.stdout).ends_with("Enter new name: \n\nProgram aborted\n"),
        "{done:?}"
    );
}

#[test]
fn o_plus_and_y_ask_nothing_and_read_nothing() {
    let (root, _watch) = work("oplus");
    let arc = archive(&root, true, &[]);
    for form in [
        &["x", "-o+"][..],
        &["x", "-y"],
        &["e", "-o+"],
        &["x", "-o", "-y"],
    ] {
        there(&root, &arc, &[]);
        let done = run(&root, &arc, form, Feed::Null);
        assert_eq!(done.status.code(), Some(0), "{form:?}: {done:?}");
        assert!(done.stderr.is_empty(), "{form:?}: {done:?}");
        assert_eq!(read(&root, "a.txt"), A, "{form:?}");
        assert_eq!(read(&root, "b.txt"), B, "{form:?}");
    }
    // Nothing in the way: the default rule asks nothing either.
    let out = root.join("out");
    std::fs::remove_dir_all(&out).unwrap();
    let done = run(&root, &arc, &["x"], Feed::Null);
    assert_eq!(done.status.code(), Some(0), "{done:?}");
    assert!(done.stderr.is_empty(), "{done:?}");
    assert_eq!(read(&root, "sub/c.txt"), C);
}

/// `-or`: the first free `name(N).ext`, the last of the overwrite switches
/// on the line the rule, and `-y` no part of it.
#[test]
fn or_writes_under_the_first_free_numbered_name() {
    let (root, _watch) = work("or");
    let arc = archive(&root, true, &[]);
    for form in [
        &["x", "-or"][..],
        &["x", "-or", "-y"],
        &["x", "-o+", "-or"],
        &["x", "-o-", "-or"],
    ] {
        there(&root, &arc, &[]);
        let done = run(&root, &arc, form, Feed::Null);
        assert_eq!(done.status.code(), Some(0), "{form:?}: {done:?}");
        assert!(done.stderr.is_empty(), "{form:?}: {done:?}");
        for (kept, new, bytes) in [
            ("a.txt", "a(1).txt", A),
            ("b.txt", "b(1).txt", B),
            ("sub/c.txt", "sub/c(1).txt", C),
        ] {
            assert_eq!(read(&root, kept), OTHER, "{form:?}: {kept}");
            assert_eq!(read(&root, new), bytes, "{form:?}: {new}");
        }
        let said = text(&done.stdout);
        assert!(
            said.contains(&format!("Extracting  {} ", shown("sub/c(1).txt"))),
            "{form:?}: {said:?}"
        );
        assert!(said.ends_with("OK \nAll OK\n"), "{form:?}: {said:?}");
        // Again: the next number, the first that is free.
        std::fs::remove_file(root.join("out").join("a(1).txt")).unwrap();
        std::fs::write(root.join("out").join("a(2).txt"), OTHER).unwrap();
        let done = run(&root, &arc, form, Feed::Null);
        assert_eq!(done.status.code(), Some(0), "{form:?}: {done:?}");
        assert_eq!(read(&root, "a(1).txt"), A, "{form:?}");
        assert_eq!(read(&root, "a(2).txt"), OTHER, "{form:?}");
        assert_eq!(read(&root, "b(2).txt"), B, "{form:?}");
    }
    // A later `-o+` or `-o-` is the rule in its place.
    there(&root, &arc, &[]);
    let done = run(&root, &arc, &["x", "-or", "-o+"], Feed::Null);
    assert_eq!(done.status.code(), Some(0), "{done:?}");
    assert_eq!(read(&root, "a.txt"), A);
    assert!(!root.join("out").join("a(1).txt").exists());
    there(&root, &arc, &[]);
    let done = run(&root, &arc, &["x", "-or", "-o-"], Feed::Null);
    assert_eq!(done.status.code(), Some(0), "{done:?}");
    assert_eq!(read(&root, "a.txt"), OTHER);
    assert!(!root.join("out").join("a(1).txt").exists());
}

/// Where the number goes: before the last dot of the name, a leading dot
/// included, and at the end of a name with none.
#[test]
fn or_numbers_before_the_last_dot_of_the_name() {
    let (root, _watch) = work("or-names");
    let src = root.join("src");
    std::fs::create_dir_all(src.join("sub.d")).unwrap();
    let names = [
        ("noext", "noext(1)"),
        ("a.tar.gz", "a.tar(1).gz"),
        (".hidden", "(1).hidden"),
        ("sub.d/plain", "sub.d/plain(1)"),
        ("x.txt", "x(2).txt"),
        ("x(1).txt", "x(1)(1).txt"),
    ];
    for (name, _) in names {
        std::fs::write(src.join(name), name.as_bytes()).unwrap();
    }
    let arc = root.join("arc.rar");
    let made = Command::new(rarfast())
        .current_dir(&src)
        .args(["a", "-idq", "-y", "-m3", "-r"])
        .arg(&arc)
        .args(["noext", "a.tar.gz", ".hidden", "sub.d", "x.txt", "x(1).txt"])
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
    let first = run(&root, &arc, &["x", "-idq"], Feed::Null);
    assert!(first.status.success(), "{first:?}");
    let done = run(&root, &arc, &["x", "-or", "-idq"], Feed::Null);
    assert_eq!(done.status.code(), Some(0), "{done:?}");
    for (name, new) in names {
        assert_eq!(read(&root, new), name.as_bytes(), "{new}");
    }
}

/// The shapes: stored, a solid archive, a volume set, a password, enciphered
/// headers, each asked about and answered as a plain archive is.
#[test]
fn every_shape_asks_and_answers_alike() {
    for (tag, make, pass) in [
        ("stored", &["-m0"][..], &[][..]),
        ("solid", &["-s"], &[]),
        ("volumes", &["-v1k", "-m0"], &[]),
        ("password", &["-psecret"], &["-psecret"][..]),
        ("headers", &["-hpsecret"], &["-psecret"]),
    ] {
        let (root, _watch) = work(tag);
        let mut arc = archive(&root, false, make);
        if !arc.exists() {
            arc = root.join("arc.part1.rar");
        }
        assert!(arc.exists(), "{tag}: no archive");
        let with = |form: &[&'static str]| -> Vec<&'static str> {
            let mut all = form.to_vec();
            all.extend_from_slice(pass);
            all
        };
        there(&root, &arc, pass);
        let done = run(&root, &arc, &with(&["x"]), Feed::Bytes(b"A\n"));
        assert_eq!(done.status.code(), Some(0), "{tag} A: {done:?}");
        assert_eq!(read(&root, "a.txt"), A, "{tag}");
        assert_eq!(read(&root, "b.txt"), B, "{tag}");
        assert_eq!(
            untimed(&done.stderr),
            format!("\n{}", question("a.txt", OTHER.len(), A.len())),
            "{tag}"
        );

        there(&root, &arc, pass);
        let done = run(&root, &arc, &with(&["x"]), Feed::Bytes(b"N\nY\n"));
        assert_eq!(done.status.code(), Some(0), "{tag} N Y: {done:?}");
        assert_eq!(read(&root, "a.txt"), OTHER, "{tag}");
        assert_eq!(read(&root, "b.txt"), B, "{tag}");

        for (form, feed, code) in [
            (&["x"][..], Some(&b"N\nN\n"[..]), 10),
            (&["x", "-o-"], None, 10),
            (&["x"], Some(b"Q\n"), 255),
            (&["x"], Some(b""), 12),
        ] {
            there(&root, &arc, pass);
            let done = run(
                &root,
                &arc,
                &with(form),
                feed.map_or(Feed::Null, Feed::Bytes),
            );
            let row = format!("{tag} {form:?} fed {:?}", feed.map(String::from_utf8_lossy));
            assert_eq!(done.status.code(), Some(code), "{row}: {done:?}");
            assert!(!text(&done.stdout).contains("All OK"), "{row}: {done:?}");
            assert_eq!(read(&root, "a.txt"), OTHER, "{row}");
            assert_eq!(read(&root, "b.txt"), OTHER, "{row}");
        }
    }
}

/// A solid archive decodes a member it does not write, and says so.
#[test]
fn a_solid_archive_names_each_file_it_keeps() {
    let (root, _watch) = work("solid-skip");
    let arc = archive(&root, false, &["-s"]);
    there(&root, &arc, &[]);
    let done = run(&root, &arc, &["x"], Feed::Bytes(b"N\nY\n"));
    assert_eq!(done.status.code(), Some(0), "{done:?}");
    let said = String::from_utf8_lossy(&done.stdout).into_owned();
    let line = said
        .lines()
        .find(|line| line.starts_with("Skipping    a.txt "))
        .unwrap_or_else(|| panic!("no Skipping line: {said:?}"));
    assert!(line.ends_with("%\x08\x08\x08\x08\x08     "), "{line:?}");
    assert!(
        said.contains(&format!("Extracting  {}", shown("b.txt"))),
        "{said:?}"
    );
    assert_eq!(read(&root, "a.txt"), OTHER);
    assert_eq!(read(&root, "b.txt"), B);
}

/// `p` writes to standard output: nothing on disk is in its way.
#[test]
fn p_asks_nothing() {
    let (root, _watch) = work("p");
    let arc = archive(&root, false, &[]);
    there(&root, &arc, &[]);
    let done = Command::new(rarfast())
        .current_dir(&*root)
        .args(["p", "-inul"])
        .arg(arc.file_name().unwrap())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(done.status.code(), Some(0), "{done:?}");
    assert_eq!(done.stdout, [A, B].concat());
    assert_eq!(read(&root, "a.txt"), OTHER);
}

/// A path that is a DIRECTORY: `Cannot create` with the system's reason and
/// the reference's third line, exit 9, the directory left as it was.
///
/// The member's line IS opened now, and closes with no `OK` (10 Oct 2026):
/// nothing looks at a taken name before the member is written beside it
/// (the look was counted in the wall of every replaced file), so the
/// directory is found by the rename that would have given the member its
/// name. The reference refuses before any line; the complaint, the count
/// and the exit are its own still.
#[test]
fn a_directory_in_the_way_is_cannot_create_with_the_reason() {
    let (root, _watch) = work("dirway");
    let arc = archive(&root, false, &[]);
    for form in [&["x", "-o+"][..], &["x", "-y"]] {
        let out = root.join("out");
        if out.exists() {
            std::fs::remove_dir_all(&out).unwrap();
        }
        std::fs::create_dir_all(out.join("a.txt")).unwrap();
        let done = run(&root, &arc, form, Feed::Null);
        assert_eq!(done.status.code(), Some(9), "{form:?}: {done:?}");
        let complaint = String::from_utf8_lossy(&done.stderr).into_owned();
        let lines: Vec<&str> = complaint.lines().collect();
        assert_eq!(lines.len(), 4, "{form:?}: {complaint:?}");
        assert_eq!(lines[0], "", "{form:?}");
        assert_eq!(
            lines[1],
            format!("Cannot create {}", shown("a.txt")),
            "{form:?}"
        );
        assert!(
            !lines[2].is_empty() && !lines[2].contains("os error"),
            "{complaint:?}"
        );
        assert_eq!(
            lines[3], "Directory with such name already exists",
            "{form:?}"
        );
        let said = text(&done.stdout);
        assert!(said.ends_with("Total errors: 1\n"), "{said:?}");
        assert_eq!(
            said.matches("OK").count(),
            1,
            "only the other member: {said:?}"
        );
        let left: Vec<_> = std::fs::read_dir(&out)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(left.len(), 2, "a name was left beside: {left:?}");
        assert_eq!(read(&root, "b.txt"), B, "{form:?}");
        assert!(out.join("a.txt").is_dir(), "{form:?}");
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Whether a mode refuses this user at all: root is refused by none.
    fn modes_refuse_this_user(scratch: &Path) -> bool {
        let probe = scratch.join("mode-probe");
        std::fs::write(&probe, b"").unwrap();
        chmod(&probe, 0o444);
        let refused = std::fs::OpenOptions::new()
            .write(true)
            .open(&probe)
            .is_err();
        chmod(&probe, 0o644);
        std::fs::remove_file(&probe).unwrap();
        refused
    }

    /// A read-only file is asked about like any other, and `A` writes over
    /// it in place, as `-o+` does (`tests/overwrite_read_only.rs`).
    #[test]
    fn a_read_only_file_is_asked_about_and_written_over() {
        let (root, _watch) = work("ro-ask");
        let arc = archive(&root, false, &[]);
        there(&root, &arc, &[]);
        for name in ["a.txt", "b.txt"] {
            chmod(&root.join("out").join(name), 0o444);
        }
        let done = run(&root, &arc, &["x"], Feed::Bytes(b"A\n"));
        assert_eq!(done.status.code(), Some(0), "{done:?}");
        assert_eq!(read(&root, "a.txt"), A);
        assert_eq!(read(&root, "b.txt"), B);
    }

    /// `Q` after a member that could not be created: the run exits as that
    /// failure ranks, 9, not 255 (measured over files with the immutable
    /// flag; here the first file is missing from a directory that may not
    /// be written and the second is there).
    #[test]
    fn q_after_a_create_that_failed_exits_as_the_failure() {
        let (root, _watch) = work("q-after-9");
        if !modes_refuse_this_user(&root) {
            eprintln!("no mode refuses this user (root): skipped");
            return;
        }
        let arc = archive(&root, false, &[]);
        there(&root, &arc, &[]);
        let out = root.join("out");
        std::fs::remove_file(out.join("a.txt")).unwrap();
        chmod(&out, 0o555);
        let done = run(&root, &arc, &["x"], Feed::Bytes(b"Q\n"));
        chmod(&out, 0o755);
        assert_eq!(done.status.code(), Some(9), "{done:?}");
        assert_eq!(
            untimed(&done.stderr),
            format!(
                "\nCannot create out/a.txt\nPermission denied\n{}",
                question("b.txt", OTHER.len(), B.len())
            )
        );
        assert_eq!(
            String::from_utf8_lossy(&done.stdout),
            "\nExtracting from arc.rar\n\nProgram aborted\n"
        );
        assert_eq!(read(&root, "b.txt"), OTHER);
    }

    /// Files that cannot be created, every one: the complaints, `No files
    /// to extract` in place of `Total errors`, exit 9.
    #[test]
    fn nothing_creatable_is_no_files_to_extract_exit_9() {
        let (root, _watch) = work("no-create");
        if !modes_refuse_this_user(&root) {
            eprintln!("no mode refuses this user (root): skipped");
            return;
        }
        let arc = archive(&root, false, &[]);
        let out = root.join("out");
        std::fs::create_dir_all(&out).unwrap();
        chmod(&out, 0o555);
        for (form, stdout, stderr) in [
            (
                &["x", "-o+"][..],
                "\nExtracting from arc.rar\n\nNo files to extract\n",
                "\nCannot create out/a.txt\nPermission denied\nCannot create \
                 out/b.txt\nPermission denied",
            ),
            (
                &["x", "-o+", "-ierr"],
                "",
                "\nExtracting from arc.rar\n\nCannot create out/a.txt\nPermission denied\nCannot \
                 create out/b.txt\nPermission denied\nNo files to extract\n",
            ),
            (
                &["x", "-o+", "-idq"],
                "",
                "\nCannot create out/a.txt\nPermission denied\nCannot create \
                 out/b.txt\nPermission denied\n",
            ),
        ] {
            let done = run(&root, &arc, form, Feed::Null);
            assert_eq!(done.status.code(), Some(9), "{form:?}: {done:?}");
            assert_eq!(String::from_utf8_lossy(&done.stdout), stdout, "{form:?}");
            assert_eq!(String::from_utf8_lossy(&done.stderr), stderr, "{form:?}");
        }
        chmod(&out, 0o755);
    }
}

/// The Windows rows (UnRAR 7.23 x64, 2 Oct 2026): an output that
/// is there with the read-only, hidden or system attribute is written over
/// in place and left WITHOUT it, where rarfast until then answered `cannot
/// create`, exit 9, over a read-only file and left a hidden or system file
/// its attribute.
#[cfg(windows)]
mod windows {
    use super::*;
    use rarkit::{HostOs, MemberOrder, MemberSpec, Payload, WriteOptions, Writer};
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

    const NOT_CONTENT_INDEXED: u32 = 0x2000;

    /// `attrib <switches> <path>`.
    fn attrib(path: &Path, switches: &[&str]) {
        let done = Command::new("attrib")
            .args(switches)
            .arg(path)
            .output()
            .unwrap();
        assert!(done.status.success(), "attrib {switches:?}: {done:?}");
    }

    fn word(path: &Path) -> u32 {
        std::fs::metadata(path)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
            .file_attributes()
    }

    /// Read-only, hidden and system, as bits 1, 2 and 4.
    fn marks(path: &Path) -> u32 {
        word(path) & 0x07
    }

    #[test]
    fn a_read_only_hidden_or_system_file_is_written_over_and_loses_the_attribute() {
        let (root, _watch) = work("win-marks");
        let arc = archive(&root, false, &[]);
        // `-a` first: a file whose word is the mark ALONE, with no archive
        // attribute beside it (`0x01`), is the one the first form of the
        // opener's remedy left read-only.
        for (state, bits) in [
            (&["+r"][..], 0x01),
            (&["-a", "+r"], 0x01),
            (&["+h"], 0x02),
            (&["+s"], 0x04),
            (&["+r", "+h", "+s"], 0x07),
            (&["-a", "+r", "+h", "+s"], 0x07),
        ] {
            for (form, feed) in [
                (&["x", "-o+"][..], None),
                (&["x", "-y"], None),
                (&["x"], Some(&b"A\n"[..])),
                (&["e", "-o+"], None),
            ] {
                let row = format!("{state:?} {form:?}");
                there(&root, &arc, &[]);
                let out = root.join("out");
                for name in ["a.txt", "b.txt"] {
                    attrib(&out.join(name), state);
                    assert_eq!(marks(&out.join(name)), bits, "{row}: the state");
                }
                let done = run(&root, &arc, form, feed.map_or(Feed::Null, Feed::Bytes));
                assert_eq!(done.status.code(), Some(0), "{row}: {done:?}");
                for (name, bytes) in [("a.txt", A), ("b.txt", B)] {
                    assert_eq!(marks(&out.join(name)), 0, "{row}: {name} kept an attribute");
                    assert_eq!(read(&root, name), bytes, "{row}: {name}");
                }
                assert!(
                    text(&done.stdout).ends_with("OK \nAll OK\n"),
                    "{row}: {done:?}"
                );
            }
            // `t` touches nothing, and neither does a kept file.
            there(&root, &arc, &[]);
            let file = root.join("out").join("a.txt");
            attrib(&file, state);
            for form in [&["t"][..], &["x", "-o-"]] {
                let _ = run(&root, &arc, form, Feed::Null);
                assert_eq!(marks(&file), bits, "{state:?} {form:?}");
            }
        }
    }

    /// An archive of members that carry attributes of their own.
    fn marked_archive(path: &Path) {
        let options = WriteOptions {
            order: MemberOrder::AsAdded,
            ..WriteOptions::default()
        };
        let mut writer = Writer::new(options).unwrap();
        let members: [(&str, u32, HostOs, &[u8]); 5] = [
            ("ro.txt", 0x21, HostOs::Windows, b"read-only"),
            ("hid.txt", 0x22, HostOs::Windows, b"hidden"),
            ("sys.txt", 0x24, HostOs::Windows, b"system"),
            ("plain.txt", 0x20, HostOs::Windows, b"plain"),
            ("unix-0444.txt", 0o100_444, HostOs::Unix, b"a unix member"),
        ];
        for (name, attributes, host_os, bytes) in members {
            writer
                .add(MemberSpec {
                    name: name.as_bytes(),
                    payload: Payload::Bytes(bytes),
                    mtime: None,
                    attributes,
                    host_os,
                    is_directory: false,
                })
                .unwrap();
        }
        let mut out = Vec::new();
        writer.finish_into(&mut out).unwrap();
        std::fs::write(path, out).unwrap();
    }

    /// A member ends with its own stored attributes, fresh or written over
    /// whatever was there; a Unix member's `0444` is not read-only here.
    #[test]
    fn a_member_ends_with_its_stored_attributes() {
        let (root, _watch) = work("win-stored");
        let arc = root.join("arc.rar");
        marked_archive(&arc);
        let out = root.join("out");
        let expect = [
            ("ro.txt", 0x01),
            ("hid.txt", 0x02),
            ("sys.txt", 0x04),
            ("plain.txt", 0x00),
            ("unix-0444.txt", 0x00),
        ];
        let fresh = run(&root, &arc, &["x"], Feed::Null);
        assert_eq!(fresh.status.code(), Some(0), "{fresh:?}");
        for (name, bits) in expect {
            assert_eq!(marks(&out.join(name)), bits, "fresh: {name}");
        }
        // Again over them as they now stand, and over all three marks.
        for state in [&[][..], &["+r", "+h", "+s"]] {
            for (name, _) in expect {
                if !state.is_empty() {
                    attrib(&out.join(name), &["-r", "-h", "-s"]);
                    attrib(&out.join(name), state);
                }
            }
            let again = run(&root, &arc, &["x", "-o+"], Feed::Null);
            assert_eq!(again.status.code(), Some(0), "{state:?}: {again:?}");
            for (name, bits) in expect {
                assert_eq!(marks(&out.join(name)), bits, "{state:?}: {name}");
            }
            assert_eq!(read(&root, "ro.txt"), b"read-only", "{state:?}");
        }
    }

    /// THE ONE DIFFERENCE, pinned: the reference sets every file's word, so
    /// a fresh plain file loses a mark its directory gives it; here it
    /// keeps it, and the many-file extract makes no call for it. A file
    /// that was there is set, as the reference sets it.
    #[test]
    fn a_fresh_plain_file_keeps_what_its_directory_gives_it() {
        let (root, _watch) = work("win-inherit");
        let arc = root.join("arc.rar");
        marked_archive(&arc);
        let out = root.join("out");
        std::fs::create_dir_all(&out).unwrap();
        attrib(&out, &["+i"]);
        let fresh = run(&root, &arc, &["x"], Feed::Null);
        assert_eq!(fresh.status.code(), Some(0), "{fresh:?}");
        let plain = out.join("plain.txt");
        if word(&plain) & NOT_CONTENT_INDEXED == 0 {
            eprintln!("this volume gives a new file no such mark: skipped");
            return;
        }
        // Written over, it ends with the member's own word.
        let again = run(&root, &arc, &["x", "-o+"], Feed::Null);
        assert_eq!(again.status.code(), Some(0), "{again:?}");
        assert_eq!(word(&plain) & NOT_CONTENT_INDEXED, 0, "{:#x}", word(&plain));
        assert_eq!(marks(&plain), 0);
    }

    /// A file another process holds open cannot be replaced: `Cannot
    /// create`, the system's own reason, exit 9, and the file is as it
    /// was.
    ///
    /// SPEC-CLI 9.4 W7 (10 Oct 2026): the member is written beside the
    /// file and takes its name by a rename when it is whole, so the
    /// system's refusal now comes from that rename, AFTER the member was
    /// decoded (its line is open, and closes with no `OK`), and its reason
    /// is the rename's, `Access is denied.`. Until then the file itself
    /// was opened to be written over, and the refusal came before any
    /// line, with the sharing reason (os error 32) and `No files to
    /// extract`. No name of the program's own is left beside it.
    #[test]
    fn a_file_held_open_elsewhere_is_cannot_create_with_the_systems_reason() {
        let (root, _watch) = work("win-held");
        let arc = archive(&root, false, &[]);
        there(&root, &arc, &[]);
        let out = root.join("out");
        let before = {
            let mut names: Vec<_> = std::fs::read_dir(&out)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            names.sort();
            names
        };
        let held: Vec<std::fs::File> = ["a.txt", "b.txt"]
            .iter()
            .map(|name| {
                std::fs::OpenOptions::new()
                    .read(true)
                    .share_mode(0)
                    .open(out.join(name))
                    .unwrap()
            })
            .collect();
        let reason = std::io::Error::from_raw_os_error(5).to_string();
        let reason = reason.split(" (os error").next().unwrap().to_owned();
        let done = run(&root, &arc, &["x", "-o+"], Feed::Null);
        drop(held);
        assert_eq!(done.status.code(), Some(9), "{done:?}");
        assert_eq!(
            String::from_utf8_lossy(&done.stderr).trim_end(),
            format!(
                "\nCannot create {}\n{reason}\nCannot create {}\n{reason}",
                shown("a.txt"),
                shown("b.txt")
            )
        );
        let stdout = String::from_utf8_lossy(&done.stdout);
        assert!(!stdout.contains("OK"), "{stdout}");
        assert!(stdout.contains("Total errors: 2"), "{stdout}");
        let mut after: Vec<_> = std::fs::read_dir(&out)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        after.sort();
        assert_eq!(after, before, "a name was left beside the held files");
        assert_eq!(read(&root, "a.txt"), OTHER);
    }
}
