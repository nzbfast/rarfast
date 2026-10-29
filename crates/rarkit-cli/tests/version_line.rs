//! `--version`: one line on stdout, exit 0, under every name the binary
//! is called by (its own, `rar`, `unrar`), and nothing on stderr.
//!
//! The dialect is chosen by `argv[0]`, so each name is a real copy of the
//! binary under that name, which is how a user installs it and the one
//! way that works on every system.

use std::path::PathBuf;
use std::process::Command;

// The copies of the binary run under other names, and their spawns, kept
// clear of Linux's "Text file busy" (`support/exe_copy.rs`).
#[path = "support/exe_copy.rs"]
mod exe_copy;
use exe_copy::{copy_executable, output_of, rarfast};

fn named_copy(dir: &std::path::Path, name: &str) -> PathBuf {
    let named = dir.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    copy_executable(&rarfast(), &named);
    named
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-version-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The commit field this build must print: the test crate is compiled in
/// the same cargo run as the binary, so it sees the same variable.
fn expected_commit() -> &'static str {
    match option_env!("RARFAST_BUILD_COMMIT") {
        Some(sha) if !sha.is_empty() => sha.get(..12).unwrap_or(sha),
        _ => "unknown",
    }
}

#[test]
fn version_is_one_stdout_line_under_every_name() {
    let dir = work("names");
    let expected = format!(
        "rarfast {} ({}, {} {})\n",
        env!("CARGO_PKG_VERSION"),
        expected_commit(),
        std::env::consts::ARCH,
        std::env::consts::OS
    );
    for name in ["rarfast", "rar", "unrar", "winrar"] {
        let out = output_of(Command::new(named_copy(&dir, name)).arg("--version")).unwrap();
        assert_eq!(out.status.code(), Some(0), "{name} --version exit");
        assert!(out.stderr.is_empty(), "{name} --version wrote to stderr");
        let stdout = String::from_utf8(out.stdout).unwrap();
        // Windows' println! writes a bare newline too.
        assert_eq!(stdout, expected, "{name} --version");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_line_has_the_released_shape() {
    // Independent of how the fields are built above: the number, a commit
    // of at most 12 characters or the word `unknown`, an arch and a system.
    let out = output_of(Command::new(rarfast()).arg("--version")).unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    let line = stdout.strip_suffix('\n').expect("one terminated line");
    assert!(!line.contains('\n') && !line.contains('\r'));
    let rest = line
        .strip_prefix("rarfast 0.9.0 (")
        .expect("name and number");
    let inner = rest.strip_suffix(')').expect("closing bracket");
    let (commit, target) = inner.split_once(", ").expect("commit, target");
    assert!(
        commit == "unknown"
            || (commit.len() <= 12 && commit.bytes().all(|b| b.is_ascii_hexdigit())),
        "commit field {commit:?}"
    );
    let (arch, os) = target.split_once(' ').expect("arch os");
    assert!(!arch.is_empty() && !os.is_empty() && !os.contains(' '));
}

#[test]
fn the_dialect_switches_keep_their_meaning() {
    // `-v` is not the version under any name: it stays a usage screen (or
    // whatever the dialect answers), never the one-line answer above.
    let dir = work("switches");
    for name in ["rarfast", "rar", "unrar"] {
        // One copy per name: macOS kills a signed binary that was written
        // over in place after it had run.
        let named = named_copy(&dir, name);
        for switch in ["-v", "-V"] {
            let out = output_of(Command::new(&named).arg(switch)).unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
            assert!(
                !stdout.starts_with("rarfast 0.9.0"),
                "{name} {switch} printed the version line"
            );
            assert!(stdout.contains("Usage:") || stdout.contains("Unknown option"));
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
