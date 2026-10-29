//! A drive-relative member name (`C:x`) extracted for real on Windows
//! stays inside the destination (`src/safepath.rs` rule 1).
//!
//! Win32 reads `C:x` as `x` in drive C's CURRENT directory, not as a name
//! under whatever it is joined onto, so a name pushed onto the destination
//! as the host's `Path` reads it would leave the tree. The unit tests in
//! `src/safepath.rs` pin the mapping on every host; this runs the shipped
//! binary on NTFS, from a current folder that is NOT the destination, and
//! looks in all three places a member could land: the destination, the
//! current folder, and where Win32 resolves the stored name.
//!
//! The fixture is built here in code: Windows cannot create a file named
//! `C:x` to archive from the disk.
//!
//! Windows only: elsewhere `C:x` is an ordinary name. One extraction at a
//! time, each a child process on the default thread pool; a few KiB of
//! memory.
#![cfg(windows)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use rarkit::{MemberSpec, Payload, WriteOptions, Writer};

/// `rarfast` as cargo built it, or, for a test binary copied to another
/// machine, the `rarfast.exe` one directory above it, as cargo lays the
/// two out.
fn rarfast() -> PathBuf {
    let built = PathBuf::from(env!("CARGO_BIN_EXE_rarfast"));
    if built.exists() {
        return built;
    }
    let exe = std::env::current_exe().unwrap();
    exe.parent().unwrap().parent().unwrap().join("rarfast.exe")
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-drive-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A copy of `rarfast` named `unrar.exe`, the whole of how the binary
/// picks that dialect.
fn ours_as_unrar(dir: &Path) -> PathBuf {
    let named = dir.join("unrar.exe");
    std::fs::copy(rarfast(), &named).unwrap();
    named
}

/// The drive letter of `dir`, which is the drive whose current directory
/// IS the extraction's current folder.
fn drive_of(dir: &Path) -> char {
    let text = dir.to_str().unwrap();
    let letter = text.chars().next().unwrap();
    assert!(
        letter.is_ascii_alphabetic() && text[1..].starts_with(':'),
        "work folder {text:?} has no drive letter"
    );
    letter
}

/// The stored names (with `L` the work folder's own drive, C and Z the
/// others a hostile archive would name) and what each is written as under
/// `out` by `x`. Each stored `\` is a separator to Win32.
fn members(letter: char) -> Vec<(String, String)> {
    let pid = std::process::id();
    [
        ("L:rkdr-a{pid}.txt", "L_rkdr-a{pid}.txt"),
        ("C:rkdr-b{pid}.txt", "C_rkdr-b{pid}.txt"),
        ("z:rkdr-c{pid}.txt", "z_rkdr-c{pid}.txt"),
        ("L:rkdr-sub{pid}/inner.txt", "L_rkdr-sub{pid}/inner.txt"),
        ("keep/L:rkdr-d{pid}.txt", "keep/L_rkdr-d{pid}.txt"),
        ("L:..\\rkdr-e{pid}.txt", "L_._/rkdr-e{pid}.txt"),
        ("C:.\\rkdr-f{pid}.txt", "C__/rkdr-f{pid}.txt"),
    ]
    .into_iter()
    .map(|(stored, written)| {
        let fill = |s: &str| {
            s.replace("{pid}", &pid.to_string())
                .replace('L', &letter.to_string())
        };
        (fill(stored), fill(written))
    })
    .collect()
}

fn build_archive(path: &Path, names: &[(String, String)]) {
    let mut writer = Writer::new(WriteOptions::default()).expect("options");
    for (stored, _) in names {
        writer
            .add(MemberSpec {
                name: stored.as_bytes(),
                payload: Payload::Bytes(stored.as_bytes()),
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    std::fs::write(path, out).unwrap();
}

/// Every file under `root`, by its path relative to `root` with `/`.
fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut found = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let relative = path.strip_prefix(root).unwrap();
                let key = relative.to_string_lossy().replace('\\', "/");
                found.insert(key, std::fs::read(&path).unwrap());
            }
        }
    }
    found
}

/// Where Win32 itself puts each stored name that opens with a drive: the
/// place a member that escaped would be. None may exist before or after.
fn resolved_elsewhere(names: &[(String, String)]) -> Vec<PathBuf> {
    names
        .iter()
        .filter(|(stored, _)| stored.as_bytes().get(1) == Some(&b':'))
        .filter_map(|(stored, _)| std::path::absolute(stored.replace('/', "\\")).ok())
        .collect()
}

fn extract(command: &str, flat_names: bool) {
    let dir = work(command);
    let letter = drive_of(&dir);
    let names = members(letter);
    let elsewhere = resolved_elsewhere(&names);
    for path in &elsewhere {
        assert!(!path.exists(), "{} exists before the run", path.display());
    }
    let unrar = ours_as_unrar(&dir);
    build_archive(&dir.join("arc.rar"), &names);
    let out = Command::new(&unrar)
        .args([command, "-y", "arc.rar", "out\\"])
        .current_dir(&dir)
        .output()
        .unwrap();
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let escaped: Vec<_> = elsewhere.iter().filter(|path| path.exists()).collect();
    for path in &escaped {
        let _ = std::fs::remove_file(path);
    }
    assert!(
        escaped.is_empty(),
        "written outside the destination: {escaped:?}\n{said}"
    );

    let mut beside: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    beside.sort();
    assert_eq!(beside, ["arc.rar", "out", "unrar.exe"], "{said}");

    let expected: BTreeMap<String, Vec<u8>> = names
        .iter()
        .map(|(stored, written)| {
            let key = if flat_names {
                written.rsplit('/').next().unwrap().to_owned()
            } else {
                written.clone()
            };
            (key, stored.as_bytes().to_vec())
        })
        .collect();
    assert_eq!(tree(&dir.join("out")), expected, "{said}");
    assert!(
        out.status.success(),
        "extract exited {:?}\n{said}",
        out.status
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_drive_relative_name_stays_inside_the_destination_under_x() {
    extract("x", false);
}

#[test]
fn a_drive_relative_name_stays_inside_the_destination_under_e() {
    extract("e", true);
}
