//! `p`'s payload is the same bytes whatever standard output is.
//!
//! Three levers decide how `p` writes by what its standard output is
//! (`dialect/unrar/extract/payload.rs`): a solid set into a pipe or a
//! regular file states the file cost class and takes the engine's solid
//! path (`RARFAST_P_SINK_FILE`), a pipe is widened on Linux
//! (`RARFAST_P_PIPE`), and the payload goes straight to a duplicate of the
//! descriptor rather than through the line writer (`RARFAST_P_RAW`). Each
//! knob at `0` restores the old rule. Every arm here, into a pipe, a
//! regular file, a regular file opened for APPEND after bytes already in
//! it (the duplicate shares the offset and the `O_APPEND`) and `/dev/null`,
//! must print what the old rules print into a pipe, byte for byte. On
//! Windows the null device is `NUL` ([`NULL_DEVICE`]).
//!
//! A shipped `rarfast` reads no environment word; the read path's exist only
//! under the feature `reader-knobs`, which this test builds with:
//!
//! ```text
//! cargo test -p rarkit-cli --features reader-knobs --test print_payload_targets
//! ```
#![cfg(feature = "reader-knobs")]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const KNOBS: [&str; 3] = ["RARFAST_P_SINK_FILE", "RARFAST_P_PIPE", "RARFAST_P_RAW"];

/// The arms: every lever on, each alone off, and all off (the old rules).
const ARMS: [&[&str]; 5] = [
    &[],
    &["RARFAST_P_SINK_FILE"],
    &["RARFAST_P_PIPE"],
    &["RARFAST_P_RAW"],
    &KNOBS,
];

/// The system's null device.
const NULL_DEVICE: &str = if cfg!(windows) { "NUL" } else { "/dev/null" };

fn vector(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../specs/vectors-J/archives")
        .join(name)
}

fn command(archive: &Path, off: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rarfast"));
    command.args(["p", "-inul"]).arg(archive);
    for knob in KNOBS {
        command.env_remove(knob);
    }
    for knob in off {
        command.env(knob, "0");
    }
    command.stderr(Stdio::null());
    command
}

fn into_pipe(archive: &Path, off: &[&str]) -> Vec<u8> {
    let out = command(archive, off).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "p into a pipe, off {off:?}");
    out.stdout
}

fn into_file(archive: &Path, off: &[&str], path: &Path, prefix: Option<&[u8]>) -> Vec<u8> {
    let file = match prefix {
        None => std::fs::File::create(path).unwrap(),
        Some(prefix) => {
            std::fs::write(path, prefix).unwrap();
            std::fs::OpenOptions::new().append(true).open(path).unwrap()
        }
    };
    let status = command(archive, off).stdout(file).status().unwrap();
    assert_eq!(status.code(), Some(0), "p into a file, off {off:?}");
    std::fs::read(path).unwrap()
}

#[test]
fn every_arm_prints_the_same_bytes_into_every_target() {
    let dir = std::env::temp_dir().join(format!("rarfast-print-targets-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("out.bin");
    for name in ["r420_mixed_solid.rar", "r420_mixed_nonsolid.rar"] {
        let archive = vector(name);
        let old = into_pipe(&archive, &KNOBS);
        assert!(!old.is_empty(), "{name}: the old rules printed nothing");
        for off in ARMS {
            assert!(into_pipe(&archive, off) == old, "{name}, off {off:?}: pipe");
            assert!(
                into_file(&archive, off, &file, None) == old,
                "{name}, off {off:?}: file"
            );
            let prefix = b"already here\n";
            let appended = into_file(&archive, off, &file, Some(prefix));
            assert!(
                appended.starts_with(prefix) && appended[prefix.len()..] == old[..],
                "{name}, off {off:?}: appended file"
            );
            let null = std::fs::OpenOptions::new()
                .write(true)
                .open(NULL_DEVICE)
                .unwrap();
            let status = command(&archive, off).stdout(null).status().unwrap();
            assert_eq!(status.code(), Some(0), "{name}, off {off:?}: {NULL_DEVICE}");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
