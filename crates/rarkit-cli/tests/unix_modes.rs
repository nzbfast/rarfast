//! Extracted members carry their archived MODE, as reference unrar 7.23
//! leaves it (measured 27 Sep 2026; the rule is in
//! `src/dialect/unrar/mode.rs`).
//!
//! Before 27 Sep 2026 `x` never applied a member's stored mode: every
//! file came out `0666` less the umask, so a 0755 member lost its execute
//! bits and a 0600 or 0640 one became readable by everyone. Found by the
//! reference-rar differential sweep on every cell of both architectures.
//! Both paths are held here, `-mt1` (sequential) and `-mt4` (concurrent).

// Unix only by its nature: every row is about a Unix mode or a link on disk.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, SystemTime};

use rarkit::{HostOs, MemberSpec, Payload, WriteOptions, Writer};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-modes-{}-{tag}", std::process::id()));
    clean(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Removes a tree this test made, opening up any directory it closed.
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

/// The permission bits of `path` itself, never through a link.
fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .permissions()
        .mode()
        & 0o7777
}

fn mtime(path: &Path) -> SystemTime {
    std::fs::symlink_metadata(path).unwrap().modified().unwrap()
}

/// This process's umask, which the children inherit: what `mkdir` with
/// `0777` leaves, read back.
fn umask(scratch: &Path) -> u32 {
    let probe = scratch.join("umask-probe");
    std::fs::create_dir(&probe).unwrap();
    let made = mode(&probe);
    std::fs::remove_dir(&probe).unwrap();
    0o777 & !made
}

fn extract(archive: &Path, out: &Path, switches: &[&str]) -> Output {
    std::fs::create_dir_all(out).unwrap();
    Command::new(rarfast())
        .arg("x")
        .args(["-y", "-idq"])
        .args(switches)
        .arg(archive)
        .arg(format!("{}/", out.display()))
        .output()
        .unwrap()
}

/// One member for [`archive`]: name, host, attribute word, whether it is
/// a directory, and its bytes.
type Spec<'a> = (&'a str, HostOs, u32, bool, &'a [u8]);

/// A RAR 5 archive of exactly `members`, in this order, through rarkit's
/// own writer: the host and attribute word are whatever the row says,
/// which is how a Windows-host member or a directory stored BEFORE its
/// contents is made on a Unix box.
fn archive(path: &Path, members: &[Spec<'_>]) {
    let mut writer = Writer::new(WriteOptions::default()).unwrap();
    for (name, host_os, attributes, is_directory, bytes) in members {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(bytes),
                mtime: None,
                attributes: *attributes,
                host_os: *host_os,
                is_directory: *is_directory,
            })
            .unwrap();
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).unwrap();
    std::fs::write(path, out).unwrap();
}

/// Files and directories of the usual kinds, written by `rarfast a`
/// from a real tree (a Unix host, the modes as `stat` gave them), with
/// their times, and extracted on both paths: every mode is the stored one
/// exactly, whatever the umask (less the set user bit, for any run but
/// the superuser's), and every time survives the mode change.
#[test]
fn unix_modes_and_times_survive_both_paths() {
    let root = work("unix");
    let tree = root.join("tree");
    let files: [(&str, u32); 8] = [
        ("f755", 0o755),
        ("f700", 0o700),
        ("f644", 0o644),
        ("f600", 0o600),
        ("f640", 0o640),
        ("f444", 0o444),
        ("f4755", 0o4755),
        ("d700/in600", 0o600),
    ];
    let dirs: [(&str, u32); 4] = [
        ("d700", 0o700),
        ("d555", 0o555),
        ("d750", 0o750),
        ("d750/deep711", 0o711),
    ];
    for (dir, _) in dirs {
        std::fs::create_dir_all(tree.join(dir)).unwrap();
    }
    std::fs::write(tree.join("d555/in"), b"inside a read-only directory").unwrap();
    std::fs::write(tree.join("d750/deep711/in"), b"two deep").unwrap();
    let stamp = |n: u64| SystemTime::UNIX_EPOCH + Duration::new(1_500_000_000 + n, 123_456_700);
    for (n, (file, bits)) in files.iter().enumerate() {
        let path = tree.join(file);
        std::fs::write(&path, file.as_bytes()).unwrap();
        chmod(&path, *bits);
        let handle = std::fs::File::open(&path).unwrap();
        handle.set_modified(stamp(n as u64)).unwrap();
    }
    // Deepest first, once their contents are in place.
    for (n, (dir, bits)) in dirs.iter().enumerate().rev() {
        let path = tree.join(dir);
        std::fs::File::open(&path)
            .unwrap()
            .set_modified(stamp(100 + n as u64))
            .unwrap();
        chmod(&path, *bits);
    }
    let made = Command::new(rarfast())
        .current_dir(&root)
        .args(["a", "-r", "-idq", "arc.rar", "tree"])
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
    let id = Command::new("id").arg("-u").output().unwrap();
    let superuser = String::from_utf8_lossy(&id.stdout).trim() == "0";
    for threads in ["-mt1", "-mt4"] {
        let out = root.join(format!("out{threads}"));
        let done = extract(&root.join("arc.rar"), &out, &[threads]);
        assert!(done.status.success(), "{done:?}");
        for (n, (file, bits)) in files.iter().enumerate() {
            let path = out.join("tree").join(file);
            // SPEC-CLI 9.4 W3: the set user bit is the superuser's alone;
            // any other run leaves the nine bits (and says so once).
            let want = if superuser { *bits } else { *bits & 0o777 };
            assert_eq!(mode(&path), want, "{file} after x {threads}");
            assert_eq!(
                mtime(&path),
                stamp(n as u64),
                "{file}'s time after x {threads}"
            );
        }
        for (n, (dir, bits)) in dirs.iter().enumerate() {
            let path = out.join("tree").join(dir);
            assert_eq!(mode(&path), *bits, "{dir} after x {threads}");
            assert_eq!(
                mtime(&path),
                stamp(100 + n as u64),
                "{dir}'s time after x {threads}"
            );
        }
        assert_eq!(
            std::fs::read(out.join("tree/d555/in")).unwrap(),
            b"inside a read-only directory"
        );
    }
    clean(&root);
}

/// The members a genuine Unix writer does not make, measured off the
/// reference with their headers rewritten: DOS attributes from a Windows
/// host, a directory stored BEFORE its contents, and a symbolic link's
/// mode word on a member this dialect writes as a file. And `-ai`.
#[test]
fn foreign_hosts_links_and_ignore_attributes() {
    let root = work("foreign");
    let umask = umask(&root);
    let path = root.join("foreign.rar");
    archive(
        &path,
        &[
            ("w/plain", HostOs::Windows, 0x20, false, b"archive bit"),
            ("w/ro", HostOs::Windows, 0x21, false, b"read-only"),
            ("w/hidden", HostOs::Windows, 0x26, false, b"hidden, system"),
            ("w/dir", HostOs::Windows, 0x11, true, b""),
            // Ahead of its contents: the reference fails `u/first/inner`
            // with `Cannot create` for anyone but root. Here it is whole.
            ("u/first", HostOs::Unix, 0o040_555, true, b""),
            ("u/first/inner", HostOs::Unix, 0o100_600, false, b"inner"),
            ("u/exec", HostOs::Unix, 0o100_755, false, b"#!/bin/sh\n"),
            ("u/link", HostOs::Unix, 0o120_777, false, b"exec"),
        ],
    );
    for threads in ["-mt1", "-mt4"] {
        let out = root.join(format!("out{threads}"));
        let done = extract(&path, &out, &[threads]);
        assert!(done.status.success(), "{done:?}");
        let at = |name: &str| mode(&out.join(name));
        assert_eq!(at("w/plain"), 0o666 & !umask, "{threads}");
        assert_eq!(at("w/ro"), 0o444 & !umask, "{threads}");
        assert_eq!(at("w/hidden"), 0o666 & !umask, "{threads}");
        assert_eq!(at("w/dir"), 0o777 & !umask, "{threads}");
        // What `mkdir(0555)` gives: less the umask.
        assert_eq!(at("u/first"), 0o555 & !umask, "{threads}");
        assert_eq!(at("u/first/inner"), 0o600, "{threads}");
        assert_eq!(std::fs::read(out.join("u/first/inner")).unwrap(), b"inner");
        assert_eq!(at("u/exec"), 0o755, "{threads}");
        // Never the link's 0777 on a plain file.
        assert_eq!(at("u/link"), 0o666 & !umask, "{threads}");
        assert!(std::fs::symlink_metadata(out.join("u/link"))
            .unwrap()
            .is_file());
    }
    let out = root.join("out-ai");
    let done = extract(&path, &out, &["-ai"]);
    assert!(done.status.success(), "{done:?}");
    for file in ["w/plain", "w/ro", "u/first/inner", "u/exec", "u/link"] {
        assert_eq!(mode(&out.join(file)), 0o666 & !umask, "{file} under -ai");
    }
    for dir in ["w/dir", "u/first"] {
        assert_eq!(mode(&out.join(dir)), 0o777 & !umask, "{dir} under -ai");
    }
    clean(&root);
}

/// An overwritten file is replaced once the member is whole (SPEC-CLI 9.4
/// W7; whether its inode is the old one is not owed, W6) and takes the
/// member's mode as a file that was there does: the stored one for
/// a Unix member, the host default less the umask for a Windows one, and
/// under `-ai` the reference's 0700.
#[test]
fn an_overwritten_file_takes_the_member_s_mode() {
    let root = work("overwrite");
    let umask = umask(&root);
    let path = root.join("over.rar");
    archive(
        &path,
        &[
            ("unix", HostOs::Unix, 0o100_600, false, b"unix member"),
            ("win", HostOs::Windows, 0x20, false, b"windows member"),
            ("dir", HostOs::Unix, 0o040_700, true, b""),
        ],
    );
    let out = root.join("out");
    std::fs::create_dir_all(out.join("dir")).unwrap();
    chmod(&out.join("dir"), 0o755);
    for (name, bits) in [("unix", 0o4755), ("win", 0o700)] {
        std::fs::write(out.join(name), b"old").unwrap();
        chmod(&out.join(name), bits);
    }
    let done = extract(&path, &out, &["-o+"]);
    assert!(done.status.success(), "{done:?}");
    assert_eq!(std::fs::read(out.join("unix")).unwrap(), b"unix member");
    assert_eq!(mode(&out.join("unix")), 0o600);
    assert_eq!(mode(&out.join("win")), 0o666 & !umask);
    // A directory that was there takes its stored mode exactly.
    assert_eq!(mode(&out.join("dir")), 0o700);
    let done = extract(&path, &out, &["-o+", "-ai"]);
    assert!(done.status.success(), "{done:?}");
    assert_eq!(mode(&out.join("unix")), 0o700);
    assert_eq!(mode(&out.join("win")), 0o700);
    // `-ai` leaves an existing directory alone.
    chmod(&out.join("dir"), 0o711);
    let done = extract(&path, &out, &["-o+", "-ai"]);
    assert!(done.status.success(), "{done:?}");
    assert_eq!(mode(&out.join("dir")), 0o711);
    // `-o-` leaves a file it skips alone, and still sets the directory.
    chmod(&out.join("unix"), 0o644);
    let done = extract(&path, &out, &["-o-"]);
    assert!(done.status.success(), "{done:?}");
    assert_eq!(mode(&out.join("unix")), 0o644);
    assert_eq!(mode(&out.join("dir")), 0o700);
    clean(&root);
}

/// A symbolic link already on the disk where a member lands is never
/// followed to set a mode: not for a file member, not for a directory one.
#[test]
fn a_link_on_the_disk_is_never_chmodded_through() {
    let root = work("links");
    let secret = root.join("secret");
    std::fs::write(&secret, b"not the archive's").unwrap();
    chmod(&secret, 0o600);
    let outside = root.join("outside");
    std::fs::create_dir(&outside).unwrap();
    chmod(&outside, 0o700);
    let path = root.join("links.rar");
    archive(
        &path,
        &[
            ("f", HostOs::Unix, 0o100_777, false, b"payload"),
            ("d", HostOs::Unix, 0o040_777, true, b""),
        ],
    );
    let out = root.join("out");
    std::fs::create_dir_all(&out).unwrap();
    std::os::unix::fs::symlink(&secret, out.join("f")).unwrap();
    std::os::unix::fs::symlink(&outside, out.join("d")).unwrap();
    for threads in ["-mt1", "-mt4"] {
        // Each member replaces the LINK at its path, never what it points
        // at (spec F 3.8.2 and 3.8.3, as the reference does): `f` becomes a
        // regular file and `d` a real directory, and neither the secret
        // nor the outside directory is touched.
        let _ = extract(&path, &out, &["-o+", threads]);
        assert_eq!(mode(&secret), 0o600, "{threads}");
        assert_eq!(std::fs::read(&secret).unwrap(), b"not the archive's");
        assert_eq!(mode(&outside), 0o700, "{threads}");
        let d = std::fs::symlink_metadata(out.join("d")).unwrap();
        assert!(d.is_dir() && !d.file_type().is_symlink(), "{threads}");
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0, "{threads}");
    }
    clean(&root);
}
