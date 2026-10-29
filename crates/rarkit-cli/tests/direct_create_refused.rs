//! A big member extracted to a filesystem that CREATES the file and then
//! refuses its direct open.
//!
//! A member of 64 MiB or more is created past the cache, `O_DIRECT` with
//! create and exclusive, and where that open is refused it is created
//! cached, silently. Linux can refuse the open AFTER it has made the
//! file: tmpfs on a kernel before 6.6 (Ubuntu 22.04's 5.15, Debian 12's
//! 6.1) answers `EINVAL` and leaves an empty file. The cached create then
//! found a file THIS run had just made and took it for one that was
//! already there:
//!
//! - `-o-`: the member was skipped as kept, a 0 byte file left, exit 0;
//! - the default rule with no terminal: a question about a file that was
//!   never there, and the run aborted;
//! - `-or`: an empty `big.bin`, an empty `big(1).bin`, and so on.
//!
//! Linux on x86-64 and arm64 only, where the open flag exists, and only
//! where the directory shows the fault to a probe of its own (the test
//! SAYS so and passes where it does not: tmpfs on a kernel from 6.6 on
//! takes the direct open). The directory is `/dev/shm`, or the one
//! `RARFAST_TEST_REFUSING_DIR` names: ramfs refuses the direct open after
//! the create on newer kernels too, and a box with such a mount can name
//! it.
//!
//! Each run states `-mt1`. One compressed member of 64 MiB of zeros: about
//! 130 MiB held while the archive is built, 64 MiB of the temporary
//! directory for it, and 64 MiB of `/dev/shm` at a time.
// Linux only by its nature: the open flag and the memory file system that
// refuses it are Linux's.
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use rarkit::{HostOs, MemberSpec, Payload, WriteMethod, WriteOptions, Writer};

const SIZE: usize = 64 << 20;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// Whether a direct exclusive create in `dir` is refused and leaves the
/// file it made.
fn creates_then_refuses(dir: &Path) -> bool {
    let probe = dir.join("probe");
    let opened = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_DIRECT)
        .open(&probe);
    let left = std::fs::symlink_metadata(&probe).is_ok();
    let _ = std::fs::remove_file(&probe);
    opened.is_err() && left
}

fn names(dir: &Path) -> Vec<(String, u64)> {
    let mut found: Vec<(String, u64)> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().to_string_lossy().into_owned(),
                entry.metadata().unwrap().len(),
            )
        })
        .collect();
    found.sort();
    found
}

#[test]
fn a_direct_create_that_leaves_its_file_is_not_a_file_already_there() {
    let named = std::env::var_os("RARFAST_TEST_REFUSING_DIR");
    let shm = named.as_deref().map_or(Path::new("/dev/shm"), Path::new);
    if !shm.is_dir() {
        eprintln!("no {} here: skipped", shm.display());
        return;
    }
    let out = shm.join(format!("rarfast-direct-create-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).unwrap();
    if !creates_then_refuses(&out) {
        let _ = std::fs::remove_dir_all(&out);
        eprintln!(
            "{} takes a direct create here (tmpfs on a kernel from 6.6 on does): skipped",
            shm.display()
        );
        return;
    }

    // The archive on another device than the output, so the member is not
    // kept cached for sharing its source's device.
    let home = std::env::temp_dir().join(format!("rarfast-direct-create-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    let archive = home.join("a.rar");
    {
        let body = vec![0_u8; SIZE];
        // COMPRESSED, so the member is written direct on Linux: a stored
        // member that fits inside the working limit is written cached
        // there (`unbuffered::stored_cached_up_to`), and would not reach
        // the direct create at all.
        let mut writer = Writer::new(WriteOptions {
            method: WriteMethod::Compressed {
                level: 1,
                dictionary: None,
            },
            ..WriteOptions::default()
        })
        .expect("options");
        writer
            .add(MemberSpec {
                name: b"big.bin",
                payload: Payload::Bytes(&body),
                mtime: None,
                attributes: 0o100_644,
                host_os: HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
        let mut bytes = Vec::new();
        writer.finish_into(&mut bytes).expect("finish");
        std::fs::write(&archive, bytes).unwrap();
    }

    // One rule alone where `RARFAST_TEST_RULE` names it (a box that may
    // hold little in the directory runs `-o-` first, which on the fault
    // writes nothing).
    let one = std::env::var("RARFAST_TEST_RULE").ok();
    let rules: Vec<Vec<&str>> = match one.as_deref() {
        Some("default") => vec![vec![]],
        Some(rule) => vec![vec![rule]],
        None => vec![vec!["-o-"], vec![], vec!["-or"], vec!["-o+"]],
    };
    for rule in &rules {
        let _ = std::fs::remove_dir_all(&out);
        std::fs::create_dir_all(&out).unwrap();
        let done = Command::new(rarfast())
            .args(["x", "-mt1", "-idq"])
            .args(rule)
            .arg(&archive)
            .arg(format!("{}/", out.display()))
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(done.status.code(), Some(0), "{rule:?}: {done:?}");
        assert_eq!(
            names(&out),
            [("big.bin".to_owned(), SIZE as u64)],
            "{rule:?}: {done:?}"
        );
    }
    let _ = std::fs::remove_dir_all(&out);
    let _ = std::fs::remove_dir_all(&home);
}
