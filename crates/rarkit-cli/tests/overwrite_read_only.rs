//! `x -o+` over a tree that is ALREADY THERE with read-only files and
//! directories in it, as reference unrar 7.23 and rar 7.23 leave it.
//!
//! MEASURED (x86-64 Linux, 1 Oct 2026, an ordinary user, umask 022):
//!
//! - a file that is there with mode `0444`, in a directory of mode `0755`
//!   or `0555`, is overwritten IN PLACE (the same inode), exit 0, and ends
//!   with the member's stored mode;
//! - a file MISSING from a `0555` directory is `Cannot create`, exit 9: the
//!   reference opens no directory up, and neither does this;
//! - a file its owner may not even read (`0000`) the reference overwrites
//!   too. Here it is REFUSED, exit 9, the bytes on disk untouched: the one
//!   difference, kept on purpose (`safepath::add_owner_write` says why).
//!
//! Until 1 Oct 2026 the first row was `cannot create`, exit 9, with the old
//! bytes left on disk.
//!
//! **CHANGED BY RULE, 10 Oct 2026 (SPEC-CLI section 9.4).** rarfast no longer
//! writes a file that is there in place. W7: the member is written BESIDE
//! it and takes the name by one rename when it is whole, so the old file
//! survives a failed member; W6: what is owed of a replace is a regular
//! file with the member's bytes, bits and time, whatever the old file's
//! bits were, and "no row pins the file number". So here:
//!
//! - a `0444` file in a directory that may be written to is replaced, and
//!   ends with the member's stored mode; whether its inode is the old one
//!   is not asserted;
//! - a `0000` file is replaced too, as the reference replaces it (O9): the
//!   difference above is gone, since nothing opens the old file any more;
//! - a file that is there in a `0555` directory is written IN PLACE, as
//!   the reference writes it (O9, `taken-in-no-write-directory`): no file
//!   can be made beside it, and an extraction that worked must not start
//!   failing. It is the one case where a failed member would not leave
//!   the old file, and the run says so once
//!   (`tests/output_path_section9.rs` holds that row).
//!
//! **The umask is STATED**: every run is `sh -c 'umask 022; exec ...'`. No
//! expectation here depends on it (a file that was there takes its Unix
//! member's stored mode exactly), and a second pass runs at 077 to hold
//! that.

// Unix only by its nature: every row is about a Unix mode and the umask.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use rarkit::{HostOs, MemberOrder, MemberSpec, Payload, WriteOptions, Writer};

#[path = "support/exe_copy.rs"]
mod exe_copy;
use exe_copy::{output_of, rarfast};

const FILE: u32 = 0o100_000;
const DIR: u32 = 0o040_000;

/// Stands watch over the directory one row of this file works in. The
/// row holds it beside the directory's path and never uses it; when it
/// is let go, at the row's end or because an assertion failed, the
/// directory is made writable again and deleted. A FAILED row matters
/// most here: what it leaves is directories with no write permission,
/// and those defeat a plain `rm -rf` of the build's temporary files.
struct DirWatch(PathBuf);

impl Drop for DirWatch {
    fn drop(&mut self) {
        clean(&self.0);
    }
}

fn work(tag: &str) -> (PathBuf, DirWatch) {
    let dir = std::env::temp_dir().join(format!("rarfast-over-ro-{}-{tag}", std::process::id()));
    clean(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    (dir.clone(), DirWatch(dir))
}

/// Removes a tree this test made, opening up what it closed first.
fn clean(dir: &Path) {
    if !dir.exists() {
        return;
    }
    let _ = Command::new("chmod")
        .arg("-R")
        .arg("u+rwx")
        .arg(dir)
        .status();
    let _ = std::fs::remove_dir_all(dir);
}

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .permissions()
        .mode()
        & 0o7777
}

/// Whether a mode refuses this user at all: root is refused by none, and
/// the rows that expect a refusal are then passed over.
fn modes_refuse_this_user(scratch: &Path) -> bool {
    let probe = scratch.join("mode-probe");
    std::fs::write(&probe, b"").unwrap();
    chmod(&probe, 0o444);
    let refused = std::fs::OpenOptions::new()
        .write(true)
        .open(&probe)
        .is_err();
    std::fs::remove_file(&probe).unwrap();
    refused
}

/// The archive: a read-only file in a read-only directory, a writable file
/// in another read-only directory, and a read-only file at the top; the
/// directories after their contents, the order rar 7.23 writes.
fn archive(path: &Path) {
    let options = WriteOptions {
        order: MemberOrder::AsAdded,
        ..WriteOptions::default()
    };
    let mut writer = Writer::new(options).unwrap();
    let members: [(&str, u32, bool, &[u8]); 6] = [
        (
            "t/rod/rofile",
            FILE | 0o444,
            false,
            b"read-only in read-only",
        ),
        ("t/ro1/a.txt", FILE | 0o644, false, b"writable in read-only"),
        ("t/top-ro", FILE | 0o444, false, b"read-only at the top"),
        ("t/rod", DIR | 0o555, true, b""),
        ("t/ro1", DIR | 0o555, true, b""),
        ("t", DIR | 0o755, true, b""),
    ];
    for (name, attributes, is_directory, bytes) in members {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(bytes),
                mtime: None,
                attributes,
                host_os: HostOs::Unix,
                is_directory,
            })
            .unwrap();
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).unwrap();
    std::fs::write(path, out).unwrap();
}

fn extract(archive: &Path, out: &Path, umask: &str, switches: &[&str]) -> Output {
    std::fs::create_dir_all(out).unwrap();
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg(format!("umask {umask}; exec \"$0\" \"$@\""))
        .arg(rarfast())
        .args(["x", "-idq"])
        .args(switches)
        .arg(archive)
        .arg(format!("{}/", out.display()));
    output_of(&mut command).unwrap()
}

/// Other bytes in the file at `path`, which is then left with `bits`; its
/// directory is opened for the write and put back.
fn plant(path: &Path, bits: u32) {
    let dir = path.parent().unwrap();
    let dir_bits = mode(dir);
    chmod(dir, 0o755);
    chmod(path, 0o644);
    std::fs::write(path, b"other bytes").unwrap();
    chmod(path, bits);
    chmod(dir, dir_bits);
}

#[test]
fn a_read_only_file_already_there_is_replaced() {
    let (root, _watch) = work("in-place");
    if !modes_refuse_this_user(&root) {
        eprintln!("no mode refuses this user (root): skipped");
        return;
    }
    let arc = root.join("arc.rar");
    archive(&arc);
    for umask in ["022", "077"] {
        for width in ["-mt1", "-mt4"] {
            let row = format!("umask {umask}, {width}");
            let out = root.join("out");
            let first = extract(&arc, &out, umask, &[width]);
            assert!(first.status.success(), "{row}: {first:?}");
            let tree = out.join("t");
            let files = [
                ("rod/rofile", 0o444, &b"read-only in read-only"[..]),
                ("ro1/a.txt", 0o644, &b"writable in read-only"[..]),
                ("top-ro", 0o444, &b"read-only at the top"[..]),
            ];
            // Each left with the mode its member stored, holding other bytes.
            for (name, bits, _) in files {
                plant(&tree.join(name), bits);
            }
            let again = extract(&arc, &out, umask, &["-o+", width]);
            assert!(
                again.status.success(),
                "{row}: exit {:?}\n{}",
                again.status.code(),
                String::from_utf8_lossy(&again.stderr)
            );
            for (name, bits, bytes) in files {
                let path = tree.join(name);
                assert_eq!(std::fs::read(&path).unwrap(), bytes, "{row}: {name}");
                assert_eq!(mode(&path), bits, "{row}: {name}'s mode");
            }
            for dir in ["rod", "ro1"] {
                assert_eq!(mode(&tree.join(dir)), 0o555, "{row}: {dir}");
            }
            clean(&out);
        }
    }
}

#[test]
fn a_file_missing_from_a_read_only_directory_is_refused_as_the_reference_refuses_it() {
    let (root, _watch) = work("missing");
    if !modes_refuse_this_user(&root) {
        eprintln!("no mode refuses this user (root): skipped");
        return;
    }
    let arc = root.join("arc.rar");
    archive(&arc);
    for width in ["-mt1", "-mt4"] {
        let out = root.join("out");
        let first = extract(&arc, &out, "022", &[width]);
        assert!(first.status.success(), "{width}: {first:?}");
        let dir = out.join("t/rod");
        chmod(&dir, 0o755);
        std::fs::remove_file(dir.join("rofile")).unwrap();
        chmod(&dir, 0o555);
        let again = extract(&arc, &out, "022", &["-o+", width]);
        assert_eq!(again.status.code(), Some(9), "{width}: {again:?}");
        assert!(!dir.join("rofile").exists(), "{width}");
        assert_eq!(mode(&dir), 0o555, "{width}: the directory was opened up");
        // The members that could be written were.
        assert_eq!(
            std::fs::read(out.join("t/top-ro")).unwrap(),
            b"read-only at the top",
            "{width}"
        );
        clean(&out);
    }
}

/// A file with no bit at all for its owner is replaced like any other
/// (SPEC-CLI 9.4 W6, O9), and ends with the member's stored mode.
#[test]
fn a_file_its_owner_may_not_read_is_replaced() {
    let (root, _watch) = work("mode-000");
    if !modes_refuse_this_user(&root) {
        eprintln!("no mode refuses this user (root): skipped");
        return;
    }
    let arc = root.join("arc.rar");
    archive(&arc);
    for width in ["-mt1", "-mt4"] {
        let out = root.join("out");
        let first = extract(&arc, &out, "022", &[width]);
        assert!(first.status.success(), "{width}: {first:?}");
        let file = out.join("t/top-ro");
        plant(&file, 0o000);
        let again = extract(&arc, &out, "022", &["-o+", width]);
        assert!(again.status.success(), "{width}: {again:?}");
        assert_eq!(mode(&file), 0o444, "{width}");
        assert_eq!(
            std::fs::read(&file).unwrap(),
            b"read-only at the top",
            "{width}"
        );
        // Every other member was overwritten.
        assert_eq!(
            std::fs::read(out.join("t/rod/rofile")).unwrap(),
            b"read-only in read-only",
            "{width}"
        );
        clean(&out);
    }
}
