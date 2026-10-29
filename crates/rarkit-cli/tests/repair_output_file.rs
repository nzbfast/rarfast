//! The file `rarfast r` writes: its mode, a read-only archive, and what
//! stood at its name before (spec L 3.9, F4, F5, F7 and F8).
//!
//! The archive is only read. So an archive of mode 0444, and one in a
//! directory of mode 0555 when the tool is started somewhere it may
//! write, is mended like any other, exit 0, as the reference mends it.
//! Before this, the output was given the archive's mode while it was
//! still being written, and a read-only archive ended `Cannot create
//! fixed.<name>`, exit 9.
//!
//! THE MODE IS A CHOSEN DIFFERENCE (decided 10 Oct 2026). The
//! reference's output has what the caller's umask gives a new file,
//! 0644 under 022, whatever the archive's mode: so the repair of an
//! archive only its owner may read is readable by everyone. Here A
//! REPAIRED ARCHIVE KEEPS THE NAMED ARCHIVE'S OWN MODE, under any umask:
//! 0600 stays 0600 and 0444 ends 0444. The output is made writable by
//! its owner alone beside its name, written, given the archive's mode,
//! and then renamed.
//!
//! Where this tool is safer than the reference by decision besides
//! (3.9's five things): the output is written beside its name and
//! renamed when it is whole, so a file that stood at the name stands,
//! untouched, until then, and the new one has the archive's mode as any
//! output has (the reference writes over it in place and leaves it mode
//! 0700); and
//! nothing is written through a link, whether it points at a file or at
//! nothing (the reference writes through a link that points at nothing
//! and changes the mode of a file a link points at).
//!
//! The place (F2), pinned as the reference has it: a last argument that
//! ends in `/` names a directory, and one that is not there is made; a
//! last argument with no `/` that names nothing there is no place.
//!
//! `-or` (F7): a file at the output's name is left as it is and the
//! output is written under the next free numbered name, as the
//! reference writes it (measured 10 Oct 2026, rar 7.23 for macOS, the
//! fourteen arms of the test below).
//!
//! The bases are rar 7.23's own, kept in `tests/repair-remaining-arms/`.
//! Unix only by its nature: modes, an umask and links. Each run is one
//! `rarfast` process on the machine's own pool; 16,262 bytes at most.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// One member of 6,000 bytes under a record of 150 percent.
const RECORD: &[u8] = include_bytes!("repair-remaining-arms/inner150.rar");
/// Two members and no record.
const PLAIN: &[u8] = include_bytes!("repair-remaining-arms/plain.rar");
/// Where `RECORD`'s own `RR` header begins: its protected length.
const PROTECTED: usize = 6_148;

struct Work(PathBuf);

impl Work {
    fn new(tag: &str) -> Work {
        let dir =
            std::env::temp_dir().join(format!("rarfast-outfile-{}-{tag}", std::process::id()));
        Work::release(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Work(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// Gives back the write bits a test took, then removes the tree.
    fn release(dir: &Path) {
        for sub in [
            dir.to_path_buf(),
            dir.join("ro"),
            dir.join("start"),
            dir.join("shut"),
        ] {
            if sub.is_dir() {
                let _ = std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755));
            }
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        Work::release(&self.0);
    }
}

fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// `RECORD` with 40 bytes of its member changed.
fn damaged() -> Vec<u8> {
    let mut bytes = RECORD.to_vec();
    for byte in &mut bytes[1_074..1_114] {
        *byte ^= 0x5a;
    }
    bytes
}

struct Ran {
    code: i32,
    stdout: String,
    stderr: String,
}

/// `rarfast <args>` started in `dir` under `umask`, nothing on standard
/// input.
fn run(dir: &Path, umask: &str, args: &[&str]) -> Ran {
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("umask {umask}; exec \"$0\" \"$@\""))
        .arg(env!("CARGO_BIN_EXE_rarfast"))
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    Ran {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn assert_mended(path: &Path, what: &str) {
    let fixed = std::fs::read(path).unwrap();
    assert!(
        fixed.len() >= PROTECTED && fixed[..PROTECTED] == RECORD[..PROTECTED],
        "{what}: not the named archive"
    );
}

/// The output's mode is the archive's and never the umask's (the chosen
/// difference from F4), and a read-only archive is mended; the
/// archive's bytes and mode are what they were.
#[test]
fn the_outputs_mode_is_the_archives_whatever_the_umask() {
    for (umask, archive_mode) in [
        ("022", 0o444),
        ("077", 0o444),
        ("027", 0o600),
        ("002", 0o640),
        ("000", 0o600),
        ("022", 0o755),
        ("022", 0o400),
        ("077", 0o644),
    ] {
        let want = archive_mode;
        let work = Work::new(&format!("mode-{umask}-{archive_mode:o}"));
        let archive = work.path("damaged.rar");
        std::fs::write(&archive, damaged()).unwrap();
        set_mode(&archive, archive_mode);
        let ran = run(&work.0, umask, &["r", "-y", "damaged.rar"]);
        let what = format!(
            "umask {umask}, archive {archive_mode:o}: {}{}",
            ran.stdout, ran.stderr
        );
        assert_eq!(ran.code, 0, "{what}");
        assert_mended(&work.path("fixed.damaged.rar"), &what);
        assert_eq!(mode(&work.path("fixed.damaged.rar")), want, "{what}");
        assert_eq!(mode(&archive), archive_mode, "{what}");
        assert!(std::fs::read(&archive).unwrap() == damaged(), "{what}");
    }
}

/// The twin with no record: `rebuilt.` has the archive's mode too.
#[test]
fn a_rebuilt_files_mode_is_the_archives_too() {
    let work = Work::new("rebuilt");
    let archive = work.path("plain.rar");
    std::fs::write(&archive, PLAIN).unwrap();
    set_mode(&archive, 0o444);
    let ran = run(&work.0, "027", &["r", "-y", "plain.rar"]);
    assert_eq!(ran.code, 0, "{}{}", ran.stdout, ran.stderr);
    assert_eq!(mode(&work.path("rebuilt.plain.rar")), 0o444);
    assert_eq!(mode(&archive), 0o444);
}

/// F4: an archive in a directory of mode 0555 is mended when the tool is
/// started somewhere it may write; the output is made where it was
/// started (F2).
#[test]
fn an_archive_in_a_read_only_directory_is_mended_from_elsewhere() {
    let work = Work::new("rodir");
    std::fs::create_dir(work.path("ro")).unwrap();
    std::fs::create_dir(work.path("start")).unwrap();
    std::fs::write(work.path("ro/damaged.rar"), damaged()).unwrap();
    set_mode(&work.path("ro/damaged.rar"), 0o444);
    set_mode(&work.path("ro"), 0o555);
    let ran = run(
        &work.path("start"),
        "022",
        &["r", "-y", "../ro/damaged.rar"],
    );
    let what = format!("{}{}", ran.stdout, ran.stderr);
    assert_eq!(ran.code, 0, "{what}");
    assert_mended(&work.path("start/fixed.damaged.rar"), &what);
    assert_eq!(mode(&work.path("start/fixed.damaged.rar")), 0o444, "{what}");
    assert_eq!(
        std::fs::read_dir(work.path("ro")).unwrap().count(),
        1,
        "nothing is made beside the archive"
    );
}

/// F5: started in a directory of mode 0555, the output cannot be made:
/// exit 9, the tool says so, nothing is written. (Not asked of a user
/// the directory's mode does not hold, the superuser.)
#[test]
fn where_the_output_cannot_be_made_the_exit_is_9_and_nothing_is_written() {
    let work = Work::new("nowrite");
    std::fs::create_dir(work.path("start")).unwrap();
    std::fs::write(work.path("start/damaged.rar"), damaged()).unwrap();
    set_mode(&work.path("start"), 0o555);
    if std::fs::write(work.path("start/probe"), b"").is_ok() {
        return;
    }
    let ran = run(&work.path("start"), "022", &["r", "-y", "damaged.rar"]);
    let what = format!("{}{}", ran.stdout, ran.stderr);
    assert_eq!(ran.code, 9, "{what}");
    assert!(
        ran.stderr.contains("Cannot create fixed.damaged.rar"),
        "{what}"
    );
    assert_eq!(
        std::fs::read_dir(work.path("start")).unwrap().count(),
        1,
        "{what}"
    );
}

/// A file that stood at the output's name, under `-y`: it is not written
/// over in place. A second name for it keeps the old bytes, and the new
/// output has the archive's mode, whatever the old file's was.
#[test]
fn a_file_at_the_outputs_name_is_replaced_whole_with_the_archives_mode() {
    let work = Work::new("over");
    std::fs::write(work.path("damaged.rar"), damaged()).unwrap();
    set_mode(&work.path("damaged.rar"), 0o640);
    std::fs::write(work.path("fixed.damaged.rar"), b"old\n").unwrap();
    set_mode(&work.path("fixed.damaged.rar"), 0o600);
    std::fs::hard_link(work.path("fixed.damaged.rar"), work.path("second-name")).unwrap();
    let ran = run(&work.0, "022", &["r", "-y", "damaged.rar"]);
    let what = format!("{}{}", ran.stdout, ran.stderr);
    assert_eq!(ran.code, 0, "{what}");
    assert_mended(&work.path("fixed.damaged.rar"), &what);
    assert_eq!(mode(&work.path("fixed.damaged.rar")), 0o640, "{what}");
    assert_eq!(std::fs::read(work.path("second-name")).unwrap(), b"old\n");
    assert_eq!(mode(&work.path("second-name")), 0o600, "{what}");
}

/// A symbolic link at the output's name, under `-y`: nothing is written
/// through it. Pointing at a file, that file keeps its bytes AND its
/// mode; pointing at nothing, nothing appears where it points. The
/// output is an ordinary file under the name in both.
#[test]
fn nothing_is_written_through_a_link_at_the_outputs_name() {
    for dangling in [false, true] {
        let work = Work::new(if dangling { "link-none" } else { "link-file" });
        std::fs::write(work.path("damaged.rar"), damaged()).unwrap();
        set_mode(&work.path("damaged.rar"), 0o600);
        if !dangling {
            std::fs::write(work.path("elsewhere"), b"mine\n").unwrap();
            set_mode(&work.path("elsewhere"), 0o640);
        }
        std::os::unix::fs::symlink("elsewhere", work.path("fixed.damaged.rar")).unwrap();
        let ran = run(&work.0, "022", &["r", "-y", "damaged.rar"]);
        let what = format!("dangling {dangling}: {}{}", ran.stdout, ran.stderr);
        assert_eq!(ran.code, 0, "{what}");
        let made = std::fs::symlink_metadata(work.path("fixed.damaged.rar")).unwrap();
        assert!(made.file_type().is_file(), "{what}");
        assert_mended(&work.path("fixed.damaged.rar"), &what);
        assert_eq!(mode(&work.path("fixed.damaged.rar")), 0o600, "{what}");
        if dangling {
            assert!(!work.path("elsewhere").exists(), "{what}");
        } else {
            assert_eq!(std::fs::read(work.path("elsewhere")).unwrap(), b"mine\n");
            assert_eq!(mode(&work.path("elsewhere")), 0o640, "{what}");
        }
    }
}

/// F2: a last argument ending in `/` names a directory, and one that is
/// not there is MADE (mode 0755 under umask 022), one missing level or
/// two, beside where the tool was started or by a path from the root;
/// the output is written in it, exit 0, and nothing where the tool was
/// started.
#[test]
fn a_directory_named_with_a_slash_that_is_not_there_is_made() {
    for form in ["one", "two", "root"] {
        let work = Work::new(&format!("made-{form}"));
        std::fs::write(work.path("damaged.rar"), damaged()).unwrap();
        let (given, made) = match form {
            "one" => ("nodir/".to_owned(), work.path("nodir")),
            "two" => ("up/nodir/".to_owned(), work.path("up/nodir")),
            _ => (
                format!("{}/", work.path("nodir").display()),
                work.path("nodir"),
            ),
        };
        let ran = run(&work.0, "022", &["r", "-y", "damaged.rar", &given]);
        let what = format!("{form}: {}{}", ran.stdout, ran.stderr);
        assert_eq!(ran.code, 0, "{what}");
        assert!(made.is_dir(), "{what}");
        assert_eq!(mode(&made), 0o755, "{what}");
        assert_mended(&made.join("fixed.damaged.rar"), &what);
        assert!(!work.path("fixed.damaged.rar").exists(), "{what}");
    }
}

/// F2: a last argument with NO `/` at its end that names nothing there
/// is not a place: the output goes where the tool was started, as if it
/// had not been given, exit 0, and no directory is made. One that names
/// a directory that IS there is that directory, slash or none.
#[test]
fn a_slashless_name_is_a_place_only_when_it_is_there() {
    let work = Work::new("slashless");
    std::fs::write(work.path("damaged.rar"), damaged()).unwrap();
    let ran = run(&work.0, "022", &["r", "-y", "damaged.rar", "nodir"]);
    let what = format!("{}{}", ran.stdout, ran.stderr);
    assert_eq!(ran.code, 0, "{what}");
    assert!(!work.path("nodir").exists(), "{what}");
    assert_mended(&work.path("fixed.damaged.rar"), &what);

    std::fs::create_dir(work.path("there")).unwrap();
    let ran = run(&work.0, "022", &["r", "-y", "damaged.rar", "there"]);
    let what = format!("{}{}", ran.stdout, ran.stderr);
    assert_eq!(ran.code, 0, "{what}");
    assert_mended(&work.path("there/fixed.damaged.rar"), &what);
}

/// F2: where the missing directory cannot be made (it would stand in a
/// directory of mode 0555): exit 9, nothing written. (Not asked of the
/// superuser.)
#[test]
fn a_directory_that_cannot_be_made_is_exit_9_and_nothing_written() {
    let work = Work::new("unmade");
    std::fs::write(work.path("damaged.rar"), damaged()).unwrap();
    std::fs::create_dir(work.path("shut")).unwrap();
    set_mode(&work.path("shut"), 0o555);
    if std::fs::write(work.path("shut/probe"), b"").is_ok() {
        return;
    }
    let ran = run(&work.0, "022", &["r", "-y", "damaged.rar", "shut/nodir/"]);
    let what = format!("{}{}", ran.stdout, ran.stderr);
    assert_eq!(ran.code, 9, "{what}");
    assert!(!work.path("shut/nodir").exists(), "{what}");
    assert!(!work.path("fixed.damaged.rar").exists(), "{what}");
    assert_eq!(
        std::fs::read_dir(work.path("shut")).unwrap().count(),
        0,
        "{what}"
    );
}

/// One arm of `-or`: the archive's name, the names taken before the run,
/// the switches, and the one new name the run leaves, or none.
type OrRow = (
    &'static str,
    &'static [&'static str],
    &'static [&'static str],
    Option<&'static str>,
);

/// F7, `-or`: with a file at the output's name, the output goes under
/// the next free numbered name and that file is untouched, exit 0. The
/// number stands in brackets before the LAST dot of the output's whole
/// name (`fixed.a(1).rar`; `fixed(1).noext` for an archive with no
/// extension; `fixed.noext(1).` for a name that ends in a dot); it is
/// the least from 1 whose name is free; a name already numbered is
/// numbered again; `-y` beside `-or`, in either order, changes nothing;
/// a later `-o-` takes its place and nothing is written; and with
/// nothing at the name `-or` changes nothing.
#[test]
fn under_or_a_taken_name_gives_the_next_free_numbered_name() {
    let rows: [OrRow; 13] = [
        ("a.rar", &["fixed.a.rar"], &["-or"], Some("fixed.a(1).rar")),
        (
            "a.rar",
            &["fixed.a.rar", "fixed.a(1).rar"],
            &["-or"],
            Some("fixed.a(2).rar"),
        ),
        (
            "a.rar",
            &["fixed.a.rar", "fixed.a(2).rar"],
            &["-or"],
            Some("fixed.a(1).rar"),
        ),
        ("a.rar", &[], &["-or"], Some("fixed.a.rar")),
        ("noext", &["fixed.noext"], &["-or"], Some("fixed(1).noext")),
        (
            "noext.",
            &["fixed.noext."],
            &["-or"],
            Some("fixed.noext(1)."),
        ),
        (
            ".hidden.rar",
            &["fixed..hidden.rar"],
            &["-or"],
            Some("fixed..hidden(1).rar"),
        ),
        (
            "a.part1.rar",
            &["fixed.a.part1.rar"],
            &["-or"],
            Some("fixed.a.part1(1).rar"),
        ),
        (
            "a(1).rar",
            &["fixed.a(1).rar"],
            &["-or"],
            Some("fixed.a(1)(1).rar"),
        ),
        (
            "a.rar",
            &["fixed.a.rar"],
            &["-y", "-or"],
            Some("fixed.a(1).rar"),
        ),
        (
            "a.rar",
            &["fixed.a.rar"],
            &["-or", "-y"],
            Some("fixed.a(1).rar"),
        ),
        ("a.rar", &["fixed.a.rar"], &["-or", "-o-"], None),
        (
            "a.rar",
            &["fixed.a.rar"],
            &["-o-", "-or"],
            Some("fixed.a(1).rar"),
        ),
    ];
    for (index, (archive, taken, switches, new)) in rows.iter().enumerate() {
        let work = Work::new(&format!("or-{index}"));
        std::fs::write(work.path(archive), damaged()).unwrap();
        for name in *taken {
            std::fs::write(work.path(name), b"old\n").unwrap();
        }
        let mut args = vec!["r"];
        args.extend_from_slice(switches);
        args.push(archive);
        let ran = run(&work.0, "022", &args);
        let what = format!(
            "row {index}, {archive} {switches:?}: {}{}",
            ran.stdout, ran.stderr
        );
        assert_eq!(ran.code, 0, "{what}");
        for name in *taken {
            assert_eq!(std::fs::read(work.path(name)).unwrap(), b"old\n", "{what}");
        }
        let mut made: Vec<String> = std::fs::read_dir(&work.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name != archive && !taken.contains(&name.as_str()))
            .collect();
        made.sort();
        match new {
            Some(name) => {
                assert_eq!(made, [*name], "{what}");
                assert_mended(&work.path(name), &what);
            }
            None => assert_eq!(made, [""; 0], "{what}"),
        }
    }
}

/// The same for a rebuild: `rebuilt.p(1).rar` beside an untouched
/// `rebuilt.p.rar`.
#[test]
fn under_or_a_rebuilt_file_is_numbered_the_same_way() {
    let work = Work::new("or-rebuilt");
    std::fs::write(work.path("p.rar"), PLAIN).unwrap();
    std::fs::write(work.path("rebuilt.p.rar"), b"old\n").unwrap();
    let ran = run(&work.0, "022", &["r", "-or", "p.rar"]);
    let what = format!("{}{}", ran.stdout, ran.stderr);
    assert_eq!(ran.code, 0, "{what}");
    assert_eq!(std::fs::read(work.path("rebuilt.p.rar")).unwrap(), b"old\n");
    let rebuilt = std::fs::read(work.path("rebuilt.p(1).rar")).unwrap();
    assert!(
        PLAIN.starts_with(&rebuilt) && rebuilt.len() + 8 >= PLAIN.len(),
        "{what}"
    );
}
