//! Divergences the reference-writer differential sweep found (27 Sep
//! 2026), each minimised to an archive of a few hundred bytes that
//! reference `rar` 7.23 wrote. `tests/refsweep/make.sh` regenerates them
//! and `tests/refsweep/SHA256SUMS` pins the committed bytes.
//!
//! Every test here states what reference `unrar` 7.23 does with the same
//! archive. Each `#[ignore]`d one FAILS on the rarfast the sweep measured
//! (an earlier revision) and stays ignored until the fix
//! lands and removes the attribute. The one live test holds rarfast to
//! the input bytes where unrar 7.23 itself is wrong. Run the ignored ones
//! with:
//!
//!     cargo test -p rarkit-cli --test refsweep_regressions -- --ignored

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/refsweep")
        .join(name)
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-refsweep-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `rarfast <cmd> -y -idq <width> <archive> [dest/]`, as unrar.
fn run(cmd: &str, width: &str, archive: &Path, dest: Option<&Path>) -> std::process::Output {
    let mut c = Command::new(rarfast());
    c.args([cmd, "-y", "-idq", width]).arg(archive);
    if let Some(d) = dest {
        c.arg(format!("{}/", d.display()));
    }
    c.output().unwrap()
}

/// A name as a progress line shows it: with the system's separator.
fn shown(name: &str) -> String {
    name.replace('/', std::path::MAIN_SEPARATOR_STR)
}

/// Both read paths: the sequential one and the concurrent one.
const WIDTHS: [&str; 2] = ["-mt1", "-mt4"];

/// `x` restores the Unix mode a Unix-host member carries. unrar 7.23 gives
/// `x.sh` 0755, `r.txt` 0600 and `g.txt` 0640; rarfast gave all three
/// 0644, which drops the executable bit and makes the 0600 and 0640
/// files readable by every user. Live since the fix landed. Unix only by
/// its nature: a Unix mode is what it reads back.
#[cfg(unix)]
#[test]
fn extract_restores_unix_modes() {
    for width in WIDTHS {
        let out = work(&format!("modes{width}"));
        let done = run("x", width, &fixture("modes.rar"), Some(&out));
        assert!(done.status.success(), "{done:?}");
        for (name, mode) in [("x.sh", 0o755), ("r.txt", 0o600), ("g.txt", 0o640)] {
            let got = std::fs::metadata(out.join("src").join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                got, mode,
                "{name} at {width}: {got:o} where unrar gives {mode:o}"
            );
        }
        let _ = std::fs::remove_dir_all(&out);
    }
}

/// A file copy (`rar -oi`): `b.txt` is stored as a reference to `a.txt`
/// and must come out with `a.txt`'s 85,890 bytes. rarfast wrote it EMPTY
/// and exited 0 from both `t` and `x`: silent data loss.
#[test]
fn file_copy_member_carries_its_targets_bytes() {
    for width in WIDTHS {
        let out = work(&format!("copy{width}"));
        let done = run("x", width, &fixture("filecopy.rar"), Some(&out));
        assert!(done.status.success(), "{done:?}");
        let a = std::fs::read(out.join("src/a.txt")).unwrap();
        let b = std::fs::read(out.join("src/b.txt")).unwrap();
        assert_eq!(a.len(), 85_890);
        assert_eq!(b.len(), a.len(), "b.txt at {width}");
        assert!(a == b, "b.txt at {width} differs from a.txt");
        let _ = std::fs::remove_dir_all(&out);
    }
}

/// `rar -ol -oh`: three symbolic links and a hard link. unrar 7.23 makes
/// `rel -> t.txt`, `dirl -> ../src` and `dang -> nowhere` as links, and
/// `t.txt` a second name of `hard.txt` holding `target-data`. rarfast
/// wrote all four as EMPTY regular files and exited 0, so `t.txt`'s
/// bytes were lost. Unix only by its nature: Windows makes a symbolic
/// link only for a user with that privilege.
#[cfg(unix)]
#[test]
fn link_members_come_out_as_links() {
    for width in WIDTHS {
        let out = work(&format!("links{width}"));
        let done = run("x", width, &fixture("links.rar"), Some(&out));
        assert!(done.status.success(), "{done:?}");
        let src = out.join("src");
        for (name, target) in [("rel", "t.txt"), ("dirl", "../src"), ("dang", "nowhere")] {
            let meta = std::fs::symlink_metadata(src.join(name)).unwrap();
            assert!(
                meta.file_type().is_symlink(),
                "{name} at {width} is not a link"
            );
            assert_eq!(
                std::fs::read_link(src.join(name)).unwrap(),
                Path::new(target)
            );
        }
        for name in ["hard.txt", "t.txt"] {
            assert_eq!(
                std::fs::read(src.join(name)).unwrap(),
                b"target-data\n",
                "{name} at {width}"
            );
        }
        let _ = std::fs::remove_dir_all(&out);
    }
}

/// The 16th member of a `-m1` solid stream is EMPTY. unrar 7.23 tests
/// all 20 members OK. rarfast failed every member after the empty one:
/// the defect the 27 Sep solid fix covers, where the writer gives an
/// empty member a block that carries a new table set. That fix's tests
/// hold `-m3`; this one holds `-m1`, which the sweep also found failing
/// over `/usr/include`. Live since that fix landed.
#[test]
fn solid_stream_with_an_empty_sixteenth_member_at_m1() {
    for width in WIDTHS {
        let done = run("t", width, &fixture("solid-empty16-m1.rar"), None);
        assert!(done.status.success(), "t at {width}: {done:?}");
        let out = work(&format!("empty16{width}"));
        let done = run("x", width, &fixture("solid-empty16-m1.rar"), Some(&out));
        assert!(done.status.success(), "x at {width}: {done:?}");
        assert_eq!(
            std::fs::metadata(out.join("src/f015.txt")).unwrap().len(),
            0
        );
        assert!(std::fs::metadata(out.join("src/f019.txt")).unwrap().len() > 0);
        let _ = std::fs::remove_dir_all(&out);
    }
}

/// A 512 MiB dictionary: `rar -md1g` over 300,000,000 zero bytes, 12,350
/// bytes of archive. unrar 7.23 tests and extracts it. rarfast refused
/// the member ("Window wanted 536870912 bytes and the policy allows
/// 268435456") because the default `MemoryPolicy` caps `max_window` at
/// `working_limit / 2`, printed `OK` beside the refusal, exited 2, and
/// left a zero-byte `zeros` carrying the archived time. The fix is a
/// policy decision (SPEC-API 8.1 on the default budget against a drop-in's
/// promise), not a decoder change.
#[test]
#[ignore = "the default memory policy refuses a dictionary above 256 MiB"]
fn a_512_mib_dictionary_is_read_as_unrar_reads_it() {
    for width in WIDTHS {
        let done = run("t", width, &fixture("dict512m.rar"), None);
        assert!(done.status.success(), "t at {width}: {done:?}");
        let out = work(&format!("dict{width}"));
        let done = run("x", width, &fixture("dict512m.rar"), Some(&out));
        assert!(done.status.success(), "x at {width}: {done:?}");
        let zeros = std::fs::read(out.join("src/zeros")).unwrap();
        assert_eq!(zeros.len(), 300_000_000);
        assert!(zeros.iter().all(|&b| b == 0));
        let _ = std::fs::remove_dir_all(&out);
    }
}

/// A name wider than the listing column. unrar 7.23 still separates it
/// from what follows: five spaces before a file's progress figure and two
/// before a directory's `OK`, in `t` and `x` alike. rarfast wrote them
/// flush, so `...dddOK` reached anything that parses the output. (The
/// banner rarfast omits and the progress figure are documented choices
/// in this crate's README and are not held here.) A progress line shows
/// a name with the system's separator, so the expected lines are put in
/// that form ([`shown`]).
#[test]
fn a_name_wider_than_the_column_keeps_its_separator() {
    let dir = format!("src/{}", "d".repeat(70));
    let out = work("longname");
    // The reference's own prefixes: the verb padded to twelve columns.
    for (cmd, file_verb, dir_verb, prefix) in [
        ("t", "Testing     ", "Testing     ", String::new()),
        (
            "x",
            "Extracting  ",
            "Creating    ",
            format!("{}{}", out.display(), std::path::MAIN_SEPARATOR),
        ),
    ] {
        let mut c = Command::new(rarfast());
        c.args([cmd, "-y", "-mt1"]).arg(fixture("longname.rar"));
        if cmd == "x" {
            // Typed with the system's separator, which is how the line
            // then shows it.
            c.arg(format!("{}{}", out.display(), std::path::MAIN_SEPARATOR));
        }
        let done = c.output().unwrap();
        assert!(done.status.success(), "{done:?}");
        let text = String::from_utf8_lossy(&done.stdout).replace('\u{8}', "");
        let file = format!("{file_verb}{}     ", shown(&format!("{prefix}{dir}/f")));
        assert!(
            text.lines().any(|l| l.starts_with(&file)),
            "{cmd}: no line starts {file:?} in {text}"
        );
        let dir_line = format!("{dir_verb}{}  OK", shown(&format!("{prefix}{dir}")));
        assert!(
            text.lines().any(|l| l == dir_line),
            "{cmd}: no line {dir_line:?} in {text}"
        );
    }
    let _ = std::fs::remove_dir_all(&out);
}

/// Unix names holding control characters and a backslash, all legal
/// there. unrar 7.23 writes each byte for byte. rarfast wrote the name it
/// DISPLAYS: control characters as Rust escapes (`tab\tthere` became the
/// ten characters `tab\\tthere`, `bel\x07x` became `bel\\u{7}x`) and
/// the backslash as a separator, so `bs\x` became a directory `bs` holding
/// `x`. Escaping belongs to what reaches the terminal, not to the file
/// system (the display rule in `dialect/unrar/mod.rs` says as much).
/// Fixed by `disk_name`; `tests/verbatim_names.rs` covers every byte.
/// Unix only by its nature: no Windows file name holds these characters.
#[cfg(unix)]
#[test]
fn unix_names_with_control_characters_are_written_verbatim() {
    let mut want: Vec<String> = [
        "tab\tthere",
        "nl\nx",
        "cr\rx",
        "esc\u{1b}x",
        "bs\\x",
        "del\u{7f}x",
        "bel\u{7}x",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    want.sort();
    for width in WIDTHS {
        let out = work(&format!("ctl{width}"));
        let done = run("x", width, &fixture("ctlnames.rar"), Some(&out));
        assert!(done.status.success(), "{done:?}");
        let mut got: Vec<String> = std::fs::read_dir(out.join("src"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        got.sort();
        assert_eq!(got, want, "at {width}");
        for name in &want {
            assert_eq!(
                std::fs::read(out.join("src").join(name)).unwrap(),
                name.as_bytes(),
                "{name:?} at {width}"
            );
        }
        let _ = std::fs::remove_dir_all(&out);
    }
}

/// A RAR 4 member written by a genuine rar 4.20 with the true-colour
/// filter forced (`-mcC+`) over 65,537 bytes of a ten-letter pattern.
/// rarfast reads it right, and so does unrar 4.20 from the writer's own
/// package; REFERENCE unrar 7.23 reports a checksum error on it (exit 3).
/// This is the one place the sweep found the reference wrong, and the
/// test is live, not ignored: it holds rarfast to the bytes that went in,
/// so nobody "fixes" rarfast toward unrar 7.23's answer.
#[test]
fn rar4_true_colour_member_keeps_its_bytes() {
    let want: Vec<u8> = b"abcdefghij".iter().copied().cycle().take(65_537).collect();
    for width in WIDTHS {
        let done = run("t", width, &fixture("r4-rgb.rar"), None);
        assert!(done.status.success(), "t at {width}: {done:?}");
        let out = work(&format!("rgb{width}"));
        let done = run("x", width, &fixture("r4-rgb.rar"), Some(&out));
        assert!(done.status.success(), "x at {width}: {done:?}");
        assert!(
            std::fs::read(out.join("src/p65537")).unwrap() == want,
            "at {width}"
        );
        let _ = std::fs::remove_dir_all(&out);
    }
}
