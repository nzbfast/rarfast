//! Security brief 7: member names that look like options or shell input.
//!
//! An archive whose members are named like switches (a leading dash and
//! text, a lone dash, a double dash, the very switches the command line
//! takes) and with shell metacharacters is listed, tested and extracted
//! by `l`, `v`, `lb`, `t`, `x` and `e`, under both dialects (the binary
//! as it is, and a copy named `unrar`). THE RULE pinned: a name is data.
//! Every run succeeds, `x` writes exactly the stored tree and `e` its base
//! names, `lb` prints each name as stored, nothing else appears anywhere
//! under the test's own root (a shell that ran `touch pwned` would leave a
//! file named `pwned`), and no option takes effect: `-x*` excludes nothing,
//! `-p` asks for no password (stdin is closed), `--help` prints no help.
//!
//! No code in rarkit-cli or rarkit starts a process (checked by reading
//! the tree on 28 Oct 2026: no `std::process::Command`, exec, spawn or
//! shell call outside the tests), so a member name has no way to a shell;
//! this test pins the observable half.
//!
//! On Windows a character Win32 refuses in a name lands as `_` (as in
//! `windows_hostile_path_forms.rs`); elsewhere every name lands as stored.
//! The archive is RAR 5 from a Unix host, every member stored.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[path = "../../rarkit/tests/redirection/rewrite.rs"]
mod rewrite;

#[path = "support/hostile_windows_rows.rs"]
#[allow(dead_code)]
mod rows;

/// The member names: switches, the switches this tool takes, and shell
/// input. Two that would land on one name on Windows are kept apart.
const NAMES: &[&str] = &[
    "-",
    "--",
    "-o+",
    "-p",
    "-ppassword",
    "-x*",
    "-idq",
    "--help",
    "-ad1",
    "-y",
    "-dh.txt",
    "-d/-f.txt",
    "--x/--y.txt",
    "$(touch pwned)",
    "`touch pwned`",
    ";touch pwned",
    "a|touch pwned",
    "a&&touch pwned",
    "a&touch pwned",
    "$HOME",
    "${IFS}x",
    "%PATH%",
    "*a",
    "?b",
    "[ab]",
    "a b",
    "'q'",
    "\"dq\"",
    "~",
    "!x",
    ">gt",
    "<lt",
    "@list",
    "a;b",
    "#c",
    "^d",
    "+e",
];

/// A name as it lands on this system.
fn landed(name: &str) -> String {
    if cfg!(windows) {
        name.chars()
            .map(|c| match c {
                '?' | '*' | '<' | '>' | '"' | '|' => '_',
                c => c,
            })
            .collect()
    } else {
        name.to_owned()
    }
}

/// A root of this test's own, removed when dropped.
struct Root(PathBuf);

impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Every file under `dir`, by its path relative to `base` with `/`.
fn files(base: &Path, dir: &Path, out: &mut BTreeSet<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files(base, &path, out);
        } else {
            out.insert(
                path.strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
}

#[test]
fn option_and_shell_shaped_member_names_are_data() {
    let root = std::env::temp_dir().join(format!("rarfast-optnames-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("bin")).unwrap();
    let _root = Root(root.clone());
    let unrar = root
        .join("bin")
        .join(if cfg!(windows) { "unrar.exe" } else { "unrar" });
    std::fs::copy(env!("CARGO_BIN_EXE_rarfast"), &unrar).unwrap();
    let members: Vec<rows::Member> = NAMES
        .iter()
        .map(|name| rows::file(name, &format!("body of {name}\n")))
        .collect();
    let archive = rows::archive(&members);

    let want_x: BTreeSet<String> = NAMES.iter().map(|n| landed(n)).collect();
    let want_e: BTreeSet<String> = NAMES
        .iter()
        .map(|n| landed(n.rsplit('/').next().unwrap()))
        .collect();
    let want_lb: Vec<String> = NAMES.iter().map(|n| (*n).to_owned()).collect();

    let mut failures = Vec::new();
    let arms = [
        ("rarfast", PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))),
        ("unrar", unrar),
    ];
    for (arm, exe) in &arms {
        for command in ["l", "v", "lb", "t", "x", "e"] {
            let work = root.join(arm).join(command);
            std::fs::create_dir_all(&work).unwrap();
            std::fs::write(work.join("arc.rar"), &archive).unwrap();
            let mut args = vec![command];
            if matches!(command, "x" | "e") {
                args.extend(["-o+", "-y", "arc.rar", "out/"]);
                std::fs::create_dir_all(work.join("out")).unwrap();
            } else {
                args.push("arc.rar");
            }
            let done = Command::new(exe)
                .args(&args)
                .current_dir(&work)
                .stdin(Stdio::null())
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&done.stdout).into_owned();
            let said = format!("{stdout}{}", String::from_utf8_lossy(&done.stderr));
            let row = format!("{arm} {command}");
            if done.status.code() != Some(0) {
                failures.push(format!("{row}: exit {:?}:\n{said}", done.status.code()));
            }
            let mut beside: BTreeSet<String> = std::fs::read_dir(&work)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            beside.remove("arc.rar");
            beside.remove("out");
            if !beside.is_empty() {
                failures.push(format!("{row}: written beside the archive: {beside:?}"));
            }
            if matches!(command, "x" | "e") {
                let mut got = BTreeSet::new();
                let out = work.join("out");
                files(&out, &out, &mut got);
                let want = if command == "x" { &want_x } else { &want_e };
                if &got != want {
                    failures.push(format!(
                        "{row}: wrote {:?}, not {:?}:\n{said}",
                        got.difference(want).collect::<Vec<_>>(),
                        want.difference(&got).collect::<Vec<_>>()
                    ));
                }
                for name in NAMES {
                    let path = out.join(landed(name));
                    let body = format!("body of {name}\n");
                    if command == "x" && std::fs::read(&path).ok() != Some(body.into_bytes()) {
                        failures.push(format!("{row}: {name} does not hold its own bytes"));
                    }
                }
            }
            if command == "lb" {
                let got: Vec<String> = stdout.lines().map(|line| line.replace('\\', "/")).collect();
                if got != want_lb {
                    failures.push(format!("{row}: listed {got:?}"));
                }
            }
            if matches!(command, "l" | "v") {
                for name in NAMES {
                    let shown = name.rsplit('/').next().unwrap();
                    if !stdout.contains(shown) {
                        failures.push(format!("{row}: {name} is not listed:\n{said}"));
                    }
                }
            }
        }
    }
    // Nothing a shell or an option could have made, anywhere under the root.
    let mut everything = BTreeSet::new();
    files(&root, &root, &mut everything);
    for path in &everything {
        let leaf = path.rsplit('/').next().unwrap();
        if leaf == "pwned" || leaf.starts_with("pwned") {
            failures.push(format!("a file {path} was made"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}
