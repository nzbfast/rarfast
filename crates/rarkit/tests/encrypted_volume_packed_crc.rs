//! **RAR 5 encrypted volume sets: the packed-data checksum of a fragment
//! that is not the member's last** (spec K 3.7.6, spec G 3.10.2).
//!
//! Spec K 3.7.6, observed on `rar` 7.23: the NON-final fragments of a
//! split encrypted member carry encryption flags 0x0001 (check, no MAC)
//! and their checksum field is the plain CRC32 of that fragment's
//! CIPHERTEXT; the final fragment carries 0x0003 and the whole member's
//! MAC-converted checksum.
//!
//! The writer used to put the MAC-converted checksum of the fragment's
//! PLAINTEXT there, under a record with the MAC flag set. Reference
//! `unrar` 7.23 `t` then printed "packed data checksum error" for every
//! volume of a `-p` or `-hp` set, and rarkit's own reader, which judges
//! the field over the bytes it takes from the volume, failed the member.
//! Plain sets were never affected: with no cipher the two byte sequences
//! are one.
//!
//! Every test here is on the RAR 5 family. The RAR 4 family's reading is
//! spec G 3.10.2's open question and is not touched.

#![cfg(feature = "test-support")]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use rarkit::{
    ChecksumKind, Disposition, HostOs, MemberInfo, MemberOutcome, MemberSpec, Password, Payload,
    RangeSource, ReadOptions, Result, Sink, WriteMethod, WriteOptions, Writer,
};

const SECRET: &str = "crc-over-ciphertext";

/// `-v64000b`, the cap the defect was reproduced on.
const VOLUME_CAP: u64 = 64_000;

/// About 200 KB: a text-like run a compressor shrinks, then noise it
/// cannot, so that the `-m3` arm still spans several volumes.
fn body() -> Vec<u8> {
    let mut out = Vec::with_capacity(200_000);
    let line = b"the packed checksum of a leading fragment is over its ciphertext\n";
    while out.len() < 40_000 {
        out.extend_from_slice(line);
    }
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    while out.len() < 200_000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.push((state >> 24) as u8);
    }
    out
}

#[derive(Clone, Copy, Debug)]
struct Arm {
    label: &'static str,
    compressed: bool,
    headers: bool,
}

const ARMS: [Arm; 4] = [
    Arm {
        label: "m0-p",
        compressed: false,
        headers: false,
    },
    Arm {
        label: "m0-hp",
        compressed: false,
        headers: true,
    },
    Arm {
        label: "m3-p",
        compressed: true,
        headers: false,
    },
    Arm {
        label: "m3-hp",
        compressed: true,
        headers: true,
    },
];

fn options(arm: Arm, password: bool, volumes: bool) -> WriteOptions {
    WriteOptions {
        method: if arm.compressed {
            WriteMethod::Compressed {
                level: 3,
                dictionary: None,
            }
        } else {
            WriteMethod::Stored
        },
        checksum: ChecksumKind::Crc32,
        password: password.then(|| Password::from(SECRET)),
        encrypt_headers: password && arm.headers,
        volume_file_size: volumes.then_some(VOLUME_CAP),
        ..WriteOptions::default()
    }
}

fn written(arm: Arm, password: bool, volumes: bool, payload: &[u8]) -> Vec<Vec<u8>> {
    let mut writer = Writer::new(options(arm, password, volumes)).expect("options");
    writer
        .add(MemberSpec {
            name: b"member.bin",
            payload: Payload::Bytes(payload),
            mtime: None,
            attributes: 0o100_644,
            host_os: HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    if !volumes {
        let mut one = Vec::new();
        writer.finish_into(&mut one).expect("finish_into");
        return vec![one];
    }
    let mut out: Vec<Vec<u8>> = Vec::new();
    writer.finish_volumes(&mut out).expect("finish_volumes");
    out
}

#[derive(Default)]
struct Seen {
    members: Vec<(Vec<u8>, Option<bool>)>,
}

struct Out(Arc<Mutex<Seen>>);

impl Write for Out {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let mut held = lock(&self.0);
        let last = held.members.len() - 1;
        held.members[last].0.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Keep(Arc<Mutex<Seen>>);

impl Sink for Keep {
    type Out = Out;
    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Out>> {
        lock(&self.0).members.push((Vec::new(), None));
        Ok(Disposition::Write(Out(Arc::clone(&self.0))))
    }
    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        _out: Option<Out>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        let mut held = lock(&self.0);
        let last = held.members.len() - 1;
        held.members[last].1 = outcome.checksum_ok;
        Ok(())
    }
}

fn lock<T>(held: &Arc<Mutex<T>>) -> std::sync::MutexGuard<'_, T> {
    held.lock().unwrap_or_else(|e| e.into_inner())
}

/// rarkit's own reader over a set: the one member's bytes and verdict.
fn read_back(volumes: &[Vec<u8>], password: bool) -> (Vec<u8>, Option<bool>) {
    let sources: Vec<Arc<dyn RangeSource>> = volumes
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect();
    let held = Arc::new(Mutex::new(Seen::default()));
    let mut sink = Keep(Arc::clone(&held));
    let options = ReadOptions::default().with_password(password.then(|| Password::from(SECRET)));
    rarkit::extract(sources, &options, &mut sink, &mut ()).expect("the extraction succeeds");
    drop(sink);
    let mut seen = Arc::try_unwrap(held)
        .unwrap_or_else(|_| panic!("the sink outlived the extraction"))
        .into_inner()
        .unwrap_or_else(|e| e.into_inner());
    assert_eq!(seen.members.len(), 1, "one member is delivered");
    seen.members.remove(0)
}

/// rarkit's writer, rarkit's reader: every encrypted arm reads back its
/// exact bytes with a TRUE verdict, over a set of several volumes.
#[test]
fn rarkit_reads_its_own_encrypted_volume_sets_with_a_true_verdict() {
    let payload = body();
    for arm in ARMS {
        let set = written(arm, true, true, &payload);
        assert!(set.len() > 2, "{}: the member is not split", arm.label);
        let (bytes, verdict) = read_back(&set, true);
        assert!(bytes == payload, "{}: wrong bytes", arm.label);
        assert_eq!(
            verdict,
            Some(true),
            "{}: an encrypted split member fails its own packed-data checksum \
             (spec K 3.7.6)",
            arm.label
        );
    }
}

/// What must not move: plain volume sets and single-volume encrypted
/// archives, each read back right with a true verdict.
#[test]
fn plain_sets_and_single_volume_encrypted_archives_are_unchanged() {
    let payload = body();
    for arm in ARMS {
        let plain = written(arm, false, true, &payload);
        assert!(plain.len() > 2, "{}: plain set not split", arm.label);
        assert_eq!(
            read_back(&plain, false),
            (payload.clone(), Some(true)),
            "{}: plain volume set",
            arm.label
        );
        let single = written(arm, true, false, &payload);
        assert_eq!(single.len(), 1, "{}: one volume", arm.label);
        assert_eq!(
            read_back(&single, true),
            (payload.clone(), Some(true)),
            "{}: single-volume encrypted archive",
            arm.label
        );
    }
}

/// A reference binary: a path named in the environment, then `PATH`,
/// then two usual install places. Skipped, saying so, where
/// none answers.
fn reference(name: &str, env: &str) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(path) = std::env::var_os(env) {
        candidates.push(PathBuf::from(path));
    }
    candidates.push(PathBuf::from(name));
    if let Some(home) = std::env::var_os("HOME") {
        candidates.push(Path::new(&home).join("bin").join(name));
    }
    candidates.push(Path::new("/opt/homebrew/bin").join(name));
    candidates
        .into_iter()
        .find(|path| Command::new(path).output().is_ok())
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarkit-enc-vol-crc-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// Reference `unrar` 7.23 `t` over each encrypted arm of rarkit's writer:
/// exit 0 AND no checksum complaint anywhere in its output. The exit code
/// alone does not see this defect, since `unrar` reported every volume's
/// packed-data checksum error and still exited 0. Then `x`, byte exact.
#[test]
fn reference_unrar_tests_rarkit_encrypted_volume_sets_clean() {
    let Some(unrar) = reference("unrar", "RARKIT_REF_UNRAR") else {
        eprintln!("SKIPPED the reference arm: no unrar on PATH, in ~/bin or /opt/homebrew/bin");
        return;
    };
    let payload = body();
    for arm in ARMS {
        let set = written(arm, true, true, &payload);
        let dir = scratch(arm.label);
        let total = set.len() as u32;
        for (index, volume) in set.iter().enumerate() {
            let name = rarkit::volume_file_name("set", index as u32, total, Default::default());
            std::fs::write(dir.join(name), volume).expect("write volume");
        }
        let first = dir.join(rarkit::volume_file_name(
            "set",
            0,
            total,
            Default::default(),
        ));
        let out = Command::new(&unrar)
            .arg("t")
            .arg(format!("-p{SECRET}"))
            .arg(&first)
            .output()
            .expect("unrar t");
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            out.status.success() && !said.to_lowercase().contains("checksum error"),
            "{}: reference unrar t did not pass the set ({:?}):\n{said}",
            arm.label,
            out.status.code()
        );
        let into = dir.join("x");
        std::fs::create_dir_all(&into).expect("x dir");
        let out = Command::new(&unrar)
            .arg("x")
            .arg("-y")
            .arg(format!("-p{SECRET}"))
            .arg(&first)
            .arg(format!("{}/", into.display()))
            .output()
            .expect("unrar x");
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            out.status.success(),
            "{}: unrar x failed ({:?}):\n{said}",
            arm.label,
            out.status.code()
        );
        let got = std::fs::read(into.join("member.bin")).unwrap_or_else(|e| {
            panic!(
                "{}: no extracted member ({e}); unrar x said:\n{said}",
                arm.label
            )
        });
        assert!(
            got == payload,
            "{}: unrar x extracted wrong bytes",
            arm.label
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The READER against a set reference `rar` wrote: rarkit's packed-data
/// check over the ciphertext must accept genuine encrypted volume sets,
/// with exact bytes and a true verdict, on every arm.
#[test]
fn rarkit_reads_reference_encrypted_volume_sets_with_a_true_verdict() {
    let Some(rar) = reference("rar", "RARKIT_REF_RAR") else {
        eprintln!("SKIPPED the reference arm: no rar on PATH, in ~/bin or /opt/homebrew/bin");
        return;
    };
    let payload = body();
    for arm in ARMS {
        let dir = scratch(&format!("ref-{}", arm.label));
        std::fs::write(dir.join("member.bin"), &payload).expect("input");
        let out = Command::new(&rar)
            .current_dir(&dir)
            .arg("a")
            .arg("-idq")
            .arg("-ma5")
            .arg(if arm.compressed { "-m3" } else { "-m0" })
            .arg(format!("-v{VOLUME_CAP}b"))
            .arg(if arm.headers {
                format!("-hp{SECRET}")
            } else {
                format!("-p{SECRET}")
            })
            .arg("set.rar")
            .arg("member.bin")
            .output()
            .expect("rar a");
        assert!(
            out.status.success(),
            "{}: reference rar a failed",
            arm.label
        );
        let mut names: Vec<PathBuf> = std::fs::read_dir(&dir)
            .expect("scratch listing")
            .map(|entry| entry.expect("entry").path())
            .filter(|path| {
                path.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("set.part") && n.ends_with(".rar"))
            })
            .collect();
        names.sort();
        assert!(names.len() > 2, "{}: reference set not split", arm.label);
        let set: Vec<Vec<u8>> = names
            .iter()
            .map(|path| std::fs::read(path).expect("volume"))
            .collect();
        let (bytes, verdict) = read_back(&set, true);
        assert!(
            bytes == payload,
            "{}: wrong bytes from a reference set",
            arm.label
        );
        assert_eq!(
            verdict,
            Some(true),
            "{}: rarkit's reader fails a reference-written encrypted volume set",
            arm.label
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
