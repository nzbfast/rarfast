//! Encrypted members made ahead of the walk (`extract::ahead`, FROM-STUDIO
//! 391 A): only a member with a password check record is, and a wrong or
//! missing password then leaves no file, as the walk alone leaves none.
//!
//! The archives are written by rarkit's own writer from a pinned seed (its
//! RAR 5 members carry check records), 160 small members in four
//! directories, enough that the helpers are armed (they start at 64
//! members). Each test assumes a pool of at least two threads, which the
//! default width gives on every runner here (2 to 4 threads), and a few
//! MiB of memory.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const RIGHT: &str = "secret";

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-encahead-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Member `i`'s name and bytes, the same every run.
fn member(i: usize) -> (String, Vec<u8>) {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64 ^ i as u64;
    let len = 200 + (i * 37) % 3000;
    let body = (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            b"abcdefgh \n"[(state % 10) as usize]
        })
        .collect();
    (format!("d{}/f{:03}.txt", i % 4, i), body)
}

const MEMBERS: usize = 160;

/// A RAR 5 archive of [`MEMBERS`] members at `-m3`, under [`RIGHT`], its
/// headers enciphered too where `headers` is set.
fn archive(dir: &Path, headers: bool) -> PathBuf {
    use rarkit::{Entropy, HostOs, MemberSpec, Password, Payload, WriteFormat, WriteMethod};
    let mut writer = rarkit::Writer::new(rarkit::WriteOptions {
        format: WriteFormat::Rar5,
        method: WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
        password: Some(Password::from(RIGHT)),
        encrypt_headers: headers,
        entropy: Entropy::Seeded([3; 32]),
        host_os: HostOs::Unix,
        ..rarkit::WriteOptions::default()
    })
    .expect("options");
    let members: Vec<(String, Vec<u8>)> = (0..MEMBERS).map(member).collect();
    for (name, body) in &members {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(body),
                mtime: None,
                // A regular file, rw-r--r--: 0 would extract as mode 000.
                attributes: 0o100_644,
                host_os: HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    // The four directories as members of their own, after their files,
    // where rar 7.23 puts them under `-r`: their `Creating` lines are said
    // whatever the files' passwords.
    let dirs: Vec<String> = (0..4).map(|d| format!("d{d}")).collect();
    for name in &dirs {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(&[]),
                mtime: None,
                attributes: 0o040_755,
                host_os: HostOs::Unix,
                is_directory: true,
            })
            .expect("add a directory");
    }
    let mut bytes = Vec::new();
    writer.finish_into(&mut bytes).expect("written");
    let path = dir.join(if headers { "hp.rar" } else { "p.rar" });
    std::fs::write(&path, bytes).unwrap();
    path
}

/// `x` of `arc` into a fresh `out`, standard input closed (a password
/// prompt reads end of input), with `password` as `-p<password>` if given.
fn extract(dir: &Path, arc: &Path, password: Option<&str>) -> (Option<i32>, PathBuf) {
    let out = dir.join("out");
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).unwrap();
    let mut command = Command::new(rarfast());
    command.current_dir(dir).arg("x").arg("-idq").arg("-o+");
    if let Some(password) = password {
        command.arg(format!("-p{password}"));
    }
    let status = command
        .arg(arc)
        .arg(format!("{}/", out.display()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    (status.code(), out)
}

/// Every regular file under `root`, by its path relative to it.
fn files(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                stack.push(entry.path());
            } else {
                found.push(entry.path().strip_prefix(root).unwrap().to_path_buf());
            }
        }
    }
    found.sort();
    found
}

#[test]
fn the_right_password_writes_every_member() {
    let dir = work("right");
    for headers in [false, true] {
        let arc = archive(&dir, headers);
        let (code, out) = extract(&dir, &arc, Some(RIGHT));
        assert_eq!(code, Some(0), "headers {headers}");
        assert_eq!(files(&out).len(), MEMBERS, "headers {headers}");
        for i in 0..MEMBERS {
            let (name, body) = member(i);
            let got = std::fs::read(out.join(&name))
                .unwrap_or_else(|err| panic!("{name}: {err}; made {:?}", &files(&out)[..4]));
            assert_eq!(got, body, "{name}");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_wrong_password_leaves_no_file() {
    let dir = work("wrong");
    for headers in [false, true] {
        let arc = archive(&dir, headers);
        let (code, out) = extract(&dir, &arc, Some("wrong"));
        assert_ne!(code, Some(0), "headers {headers}");
        assert_eq!(files(&out), Vec::<PathBuf>::new(), "headers {headers}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_missing_password_leaves_no_file() {
    let dir = work("missing");
    for headers in [false, true] {
        let arc = archive(&dir, headers);
        let (code, out) = extract(&dir, &arc, None);
        assert_ne!(code, Some(0), "headers {headers}");
        assert_eq!(files(&out), Vec::<PathBuf>::new(), "headers {headers}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// `x` of `arc` into a fresh `out` under `-p<password>`, with `extra`
/// switches: the exit, standard output and error, and every directory and
/// file left under `out`.
fn extract_said(
    dir: &Path,
    arc: &Path,
    password: &str,
    extra: &[&str],
) -> (Option<i32>, String, String, Vec<PathBuf>) {
    let out = dir.join("out");
    let _ = std::fs::remove_dir_all(&out);
    let said = Command::new(rarfast())
        .current_dir(dir)
        .arg("x")
        .arg("-o+")
        .args(extra)
        .arg(format!("-p{password}"))
        .arg(arc.file_name().unwrap())
        .arg("out/")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let mut left = Vec::new();
    if out.exists() {
        let mut stack = vec![out.clone()];
        while let Some(at) = stack.pop() {
            for entry in std::fs::read_dir(&at).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    stack.push(entry.path());
                }
                left.push(entry.path().strip_prefix(&out).unwrap().to_path_buf());
            }
        }
    }
    left.sort();
    let _ = std::fs::remove_dir_all(&out);
    (
        said.status.code(),
        String::from_utf8_lossy(&said.stdout).into_owned(),
        String::from_utf8_lossy(&said.stderr).into_owned(),
        left,
    )
}

/// A wrong password under `-p` (headers in the clear, so it is not known
/// at the open and the helpers are armed): the run says and leaves what
/// the walk alone says and leaves, which is the run at `-mt1`, where no
/// helper starts. A file made ahead in a directory the refused member's
/// `open` made kept that directory from being removed, and its `Creating`
/// line was then never said (FROM-STUDIO 391 A, 14 Oct 2026). Ten runs,
/// since how far the helpers get before the refusal varies.
#[test]
fn a_wrong_password_says_what_the_walk_alone_says() {
    let dir = work("said");
    let arc = archive(&dir, false);
    let alone = extract_said(&dir, &arc, "wrong", &["-mt1"]);
    assert_ne!(alone.0, Some(0));
    assert!(alone.1.contains("Creating"), "{}", alone.1);
    for run in 0..10 {
        let said = extract_said(&dir, &arc, "wrong", &[]);
        assert_eq!(said, alone, "run {run}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
