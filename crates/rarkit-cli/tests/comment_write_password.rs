//! `cw` reads the comment of an archive whose headers are encrypted, given
//! the password (bug sweep of 8 Oct 2026, item 07, its `cw` half).
//!
//! Measured on 8 Oct 2026 with `rar` 7.23 (macOS, aarch64) over the
//! archive this file builds, which rarfast writes (`a -hpabc -z<file>`):
//! `cw -pabc arc.rar out.txt` and `cw -hpabc arc.rar out.txt` exit 0 and
//! write the comment; `cw -pwrong` says `Incorrect password for arc.rar`
//! and writes nothing.
//!
//! Before this `cw` opened the archive with no password whatever the
//! line said, so the right one was answered `Incorrect password`, exit
//! 10.
//!
//! Width and memory: every rarfast call states `-mt1`; the archive is a
//! few hundred bytes.

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

struct Work(PathBuf);

impl Work {
    fn new(tag: &str) -> Work {
        let dir = std::env::temp_dir().join(format!("rarfast-cwpw-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("f.txt"), "a file\n").unwrap();
        std::fs::write(dir.join("note.txt"), "a note\n").unwrap();
        let work = Work(dir);
        let made = work.run(&["a", "-idq", "-hpabc", "-znote.txt", "arc.rar", "f.txt"]);
        assert!(made.status.success(), "rarfast a -hpabc");
        work
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(PathBuf::from(env!("CARGO_BIN_EXE_rarfast")))
            .current_dir(&self.0)
            .arg(args[0])
            .arg("-mt1")
            .args(&args[1..])
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn cw_reads_the_comment_behind_encrypted_headers_with_the_password() {
    for switch in ["-pabc", "-hpabc"] {
        let work = Work::new("right");
        let output = work.run(&["cw", switch, "-idq", "arc.rar", "out.txt"]);
        assert_eq!(
            output.status.code(),
            Some(0),
            "cw {switch}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let written = std::fs::read_to_string(work.0.join("out.txt")).expect("the comment file");
        assert_eq!(written.trim_end(), "a note", "cw {switch}");
    }
}

#[test]
fn cw_with_the_wrong_password_says_so_and_writes_nothing() {
    let work = Work::new("wrong");
    let output = work.run(&["cw", "-pwrong", "-idq", "arc.rar", "out.txt"]);
    assert_ne!(output.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Incorrect password for arc.rar"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!work.0.join("out.txt").exists());
}
