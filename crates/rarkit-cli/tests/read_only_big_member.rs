//! `x` of a BIG member whose stored mode has no write bit for its owner,
//! on a device the write gate finds slow.
//!
//! **The fault this holds (found 1 Oct 2026, x86-64 Linux, an EBS disk).**
//! A member of 64 MiB or more is created past the OS cache with its stored
//! mode (`unbuffered`). Where the gate finds the device slow the writer
//! falls back to cached writing, and to do that it opens the file a second
//! time BY NAME. A file created `0444` refuses that open to its own owner,
//! so the extract of a tree holding one read-only binary ended `Write error
//! in the file ... Permission denied`, exit 5, with every later member
//! unwritten, where reference unrar 7.23 and rar 7.23 extract it whole.
//! Counted with `strace`: the create returned a handle, the second `openat`
//! (`O_WRONLY`) returned `EACCES`, twice. Read-only DIRECTORIES were never
//! the cause: their modes go on after the walk (`dialect::unrar::mode`),
//! and the rows here hold that beside the member's.
//!
//! **Why a knob build.** Whether the writer falls back is the device's
//! speed, which a test cannot choose; `RARFAST_DIRECT=slow` (feature
//! `reserve-knob`) makes the gate's probe find the device slow at its first
//! direct write, so the fall back happens on every box. `make ci` runs
//! this file through the knob test runner. By hand:
//!
//! ```text
//! cargo test -p rarkit-cli --features reserve-knob --test read_only_big_member
//! ```
//!
//! **Where it fails without the fix.** On Linux (x86-64 and aarch64), as
//! any user but root, in a directory that takes a direct open. macOS opens
//! no member past the cache, so there these rows only hold the modes; the
//! unit test beside the writer (`unbuffered`'s
//! `a_member_created_read_only_falls_back_and_keeps_its_mode`) fails
//! without the fix on both systems.
//!
//! **The umask is STATED, not inherited**: every extract runs under `sh -c
//! 'umask <value>; exec ...'`, at 022 and at 077. A Unix-host member's mode
//! is its stored mode exactly under either (the rule is the reference's,
//! measured in `mode.rs`), and a new directory's is its stored mode less
//! the umask.
#![cfg(all(unix, feature = "reserve-knob"))]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use rarkit::{
    FilterPolicy, HostOs, MemberOrder, MemberSpec, Password, Payload, Rar4Version, WriteFormat,
    WriteMethod, WriteOptions, Writer,
};

#[path = "support/exe_copy.rs"]
mod exe_copy;
use exe_copy::{output_of, rarfast};

/// One byte over a whole number of sectors past the least size written
/// past the cache (`unbuffered::LEAST`, 64 MiB), so the member has a tail.
const BIG: usize = (64 << 20) + 4097;

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

/// A scratch directory on the build's own disk: the system's temporary
/// directory is a tmpfs on some Linux boxes, and a tmpfs takes no direct
/// open, which would leave the fault's path untaken.
fn work(tag: &str) -> (PathBuf, DirWatch) {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("read-only-big-{}-{tag}", std::process::id()));
    clean(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    (dir.clone(), DirWatch(dir))
}

/// Removes a tree this test made, opening up what it closed first: its
/// directories and files are read-only by design.
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

fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .permissions()
        .mode()
        & 0o7777
}

/// Noise, so nothing about the bytes lines up with a sector.
fn noise(len: usize) -> Vec<u8> {
    (0..len as u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect()
}

/// The archive's form: every row is one of these.
#[derive(Clone, Copy, Debug)]
enum Shape {
    /// RAR 5, stored, clear.
    Plain,
    /// RAR 4 (3.0), stored.
    Rar4,
    /// RAR 5 with the members encrypted (`-p`).
    Encrypted,
    /// RAR 5 with the headers encrypted too (`-hp`).
    HeadersEncrypted,
    /// RAR 5, solid, compressed at level 1.
    Solid,
}

const PASSWORD: &str = "secret";

/// An archive of `shape`, members in exactly this order: a read-only
/// directory BEFORE its contents and one nested in it, a file under them,
/// a read-only file whose read-only directory comes AFTER it (the order
/// rar 7.23 writes), and the big member with the mode `big_mode`.
fn archive(path: &Path, big: &[u8], big_mode: u32, shape: Shape) {
    let mut options = WriteOptions {
        order: MemberOrder::AsAdded,
        host_os: HostOs::Unix,
        ..WriteOptions::default()
    };
    match shape {
        Shape::Plain => {}
        Shape::Rar4 => {
            options.format = WriteFormat::Rar4(Rar4Version::V30);
            // The RAR 4 family writes no filter record.
            options.filters = FilterPolicy::Off;
        }
        Shape::Encrypted => options.password = Some(Password::from(PASSWORD)),
        Shape::HeadersEncrypted => {
            options.password = Some(Password::from(PASSWORD));
            options.encrypt_headers = true;
        }
        Shape::Solid => {
            options.solid = true;
            options.method = WriteMethod::Compressed {
                level: 1,
                dictionary: None,
            };
        }
    }
    let mut writer = Writer::new(options).unwrap();
    let members: [(&str, u32, bool, &[u8]); 6] = [
        ("t/ro1", DIR | 0o555, true, b""),
        ("t/ro1/ro2", DIR | 0o555, true, b""),
        ("t/ro1/ro2/leaf.txt", FILE | 0o644, false, b"two deep"),
        (
            "t/rod/rofile",
            FILE | 0o444,
            false,
            b"read-only in read-only",
        ),
        ("t/big.bin", FILE | big_mode, false, big),
        ("t/rod", DIR | 0o555, true, b""),
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

/// `rarfast x` of `archive` into `out` under the stated `umask`, the gate
/// forced slow.
fn extract(archive: &Path, out: &Path, umask: &str, width: Option<&str>, shape: Shape) -> Output {
    std::fs::create_dir_all(out).unwrap();
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg(format!("umask {umask}; exec \"$0\" \"$@\""))
        .arg(rarfast())
        .args(["x", "-y", "-idq"]);
    if let Some(width) = width {
        command.arg(width);
    }
    if matches!(shape, Shape::Encrypted | Shape::HeadersEncrypted) {
        command.arg(format!("-p{PASSWORD}"));
    }
    command
        .arg(archive)
        .arg(format!("{}/", out.display()))
        .env("RARFAST_DIRECT", "slow");
    output_of(&mut command).unwrap()
}

/// Every row: the big member's stored mode, the umask the extract runs
/// under, the width and the archive's shape. One big member a run, because the first fall back
/// is remembered for the device and a second big member would be created
/// cached, never reaching the second open.
#[test]
fn a_big_read_only_member_extracts_on_a_slow_device() {
    let (root, _watch) = work("rows");
    let big = noise(BIG);
    let rows: [(u32, &str, Option<&str>, Shape); 11] = [
        (0o444, "022", Some("-mt1"), Shape::Plain),
        (0o444, "022", None, Shape::Plain),
        (0o444, "077", None, Shape::Plain),
        (0o555, "022", None, Shape::Plain),
        (0o400, "077", Some("-mt1"), Shape::Plain),
        (0o000, "022", Some("-mt1"), Shape::Plain),
        (0o444, "022", None, Shape::Rar4),
        (0o444, "022", None, Shape::Encrypted),
        (0o444, "022", None, Shape::HeadersEncrypted),
        (0o444, "022", Some("-mt1"), Shape::Solid),
        (0o444, "022", None, Shape::Solid),
    ];
    let mut reached = 0;
    for (n, (stored, umask, width, shape)) in rows.into_iter().enumerate() {
        let row = format!("mode {stored:o}, umask {umask}, width {width:?}, {shape:?}");
        let arc = root.join(format!("big-{n}.rar"));
        archive(&arc, &big, stored, shape);
        let out = root.join(format!("out-{n}"));
        let done = extract(&arc, &out, umask, width, shape);
        let stderr = String::from_utf8_lossy(&done.stderr);
        assert!(
            done.status.success(),
            "{row}: exit {:?}\n{stderr}",
            done.status.code()
        );
        assert!(!stderr.contains("Write error"), "{row}:\n{stderr}");
        // The knob build says when the gate shut: the fall back was taken.
        if stderr.contains("rarfast gate: Slow") {
            reached += 1;
        }
        let tree = out.join("t");
        let file = tree.join("big.bin");
        assert_eq!(mode(&file), stored, "{row}: the big member's mode");
        assert_eq!(
            std::fs::metadata(&file).unwrap().len(),
            BIG as u64,
            "{row}: the big member's length"
        );
        // Read back through a mode that lets this user read it.
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(std::fs::read(&file).unwrap() == big, "{row}: bytes");
        // The directories. One met BEFORE its contents is new at its own
        // member and gets what `mkdir` gives its stored mode, less the
        // umask; one met AFTER them was made as a parent and takes its
        // stored mode exactly (`mode.rs`, measured off the reference).
        let masked = 0o555 & !u32::from_str_radix(umask, 8).unwrap();
        for dir in ["ro1", "ro1/ro2"] {
            assert_eq!(mode(&tree.join(dir)), masked, "{row}: {dir}");
        }
        assert_eq!(mode(&tree.join("rod")), 0o555, "{row}: rod");
        assert_eq!(mode(&tree.join("rod/rofile")), 0o444, "{row}: rofile");
        assert_eq!(
            std::fs::read(tree.join("ro1/ro2/leaf.txt")).unwrap(),
            b"two deep",
            "{row}"
        );
        assert_eq!(
            std::fs::read(tree.join("rod/rofile")).unwrap(),
            b"read-only in read-only",
            "{row}"
        );
        clean(&out);
        let _ = std::fs::remove_file(&arc);
    }
    // `x -o+` over the big member ALREADY THERE and read-only, holding
    // other bytes: overwritten in place, as the reference does it (the rule
    // and its measurement are `safepath`'s), through the direct open too.
    let arc = root.join("over.rar");
    archive(&arc, &big, 0o444, Shape::Plain);
    for width in [Some("-mt1"), None] {
        let out = root.join("out-over");
        let first = extract(&arc, &out, "022", width, Shape::Plain);
        assert!(first.status.success(), "{first:?}");
        let file = out.join("t/big.bin");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(&file, b"other bytes").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o444)).unwrap();
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("umask 022; exec \"$0\" \"$@\"")
            .arg(rarfast())
            .args(["x", "-idq", "-o+"]);
        if let Some(width) = width {
            command.arg(width);
        }
        command
            .arg(&arc)
            .arg(format!("{}/", out.display()))
            .env("RARFAST_DIRECT", "slow");
        let again = output_of(&mut command).unwrap();
        let stderr = String::from_utf8_lossy(&again.stderr);
        assert!(
            again.status.success(),
            "-o+ over a read-only big member, width {width:?}: exit {:?}\n{stderr}",
            again.status.code()
        );
        assert_eq!(mode(&file), 0o444, "-o+, width {width:?}: the mode");
        assert!(
            std::fs::read(&file).unwrap() == big,
            "-o+, width {width:?}: bytes"
        );
        clean(&out);
    }
    if cfg!(target_os = "linux") && reached == 0 {
        eprintln!(
            "no member was opened past the cache under {}: the rows hold, the fall back was not reached",
            root.display()
        );
    }
}
