//! **Was a pinned difference, found by `fuzz:read_seam` on 22 Sep 2026;
//! SETTLED for RAR 5 by spec K 3.7.6 and fixed in the writer.**
//!
//! A RAR 5 member that is ENCRYPTED, split across volumes and carries a
//! CRC32 record used to read back with the right bytes and a verdict of
//! `checksum_ok == Some(false)`, from an archive rarkit itself wrote: the
//! writer put the MAC-converted CRC32 of each leading fragment's
//! PLAINTEXT in the field that `read/walk.rs::next_fragment` judges over
//! the CIPHERTEXT it takes from the volume.
//!
//! Spec K 3.7.6 says what `rar` 7.23 writes there: the plain CRC32 of the
//! fragment's ciphertext, under a record with the check flag only, and
//! the whole member's MAC-converted checksum on the last fragment. The
//! reader was right; the writer now does that, and this file asserts the
//! verdict is TRUE. `encrypted_volume_packed_crc.rs` holds the reference
//! arms for `-p` and `-hp`, stored and compressed.
//!
//! **It has nothing to do with the seam of spec F 3.7.7**, and this file
//! still says so: the verdict is identical with the seam engaged and with
//! it forced off.

#![cfg(feature = "test-support")]

use std::io::Write;
use std::process::Command;
use std::sync::{Arc, Mutex};

use rarkit::{
    probe, ChecksumKind, Disposition, HostOs, MemberInfo, MemberOutcome, MemberSpec, Password,
    Payload, RangeSource, ReadOptions, Result, Sink, WriteMethod, WriteOptions, Writer,
};

const SECRET: &str = "seam";

/// The vector, as `fuzz/seeds/read_seam/encrypted-split-crc32` builds it:
/// two stored members of 84 KiB over a 64 KiB volume cap, so each member
/// is split and each leading fragment carries a checksum field.
const MEMBER: usize = 86_016;
const VOLUME_CAP: u64 = 64 << 10;

fn body() -> Vec<u8> {
    (0..MEMBER).map(|i| (i % 251) as u8).collect()
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

/// The archive of the vector, as its volumes.
fn volumes(checksum: ChecksumKind) -> Vec<Vec<u8>> {
    let payload = body();
    let mut writer = Writer::new(WriteOptions {
        method: WriteMethod::Stored,
        checksum,
        password: Some(Password::from(SECRET)),
        volume_file_size: Some(VOLUME_CAP),
        ..WriteOptions::default()
    })
    .expect("options");
    for name in ["m0.dat", "m1.dat"] {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(&payload),
                mtime: None,
                attributes: 0,
                host_os: HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out: Vec<Vec<u8>> = Vec::new();
    writer.finish_volumes(&mut out).expect("finish_volumes");
    assert!(out.len() > 2, "the vector is not a split member");
    out
}

/// One extraction: every member's bytes and verdict.
fn read_back(volumes: &[Vec<u8>], hint: Option<bool>) -> Seen {
    let sources: Vec<Arc<dyn RangeSource>> = volumes
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect();
    let held = Arc::new(Mutex::new(Seen::default()));
    let mut sink = Keep(Arc::clone(&held));
    let options = ReadOptions::default()
        .with_password(Some(Password::from(SECRET)))
        .with_workers(Some(2))
        .with_sink_is_file(hint);
    rarkit::extract(sources, &options, &mut sink, &mut ()).expect("the extraction itself succeeds");
    drop(sink);
    Arc::try_unwrap(held)
        .unwrap_or_else(|_| panic!("the sink outlived the extraction"))
        .into_inner()
        .unwrap_or_else(|e| e.into_inner())
}

/// The settled reading, and that it is not the seam's.
#[test]
fn an_encrypted_split_crc32_member_reads_back_right_and_verdicts_true() {
    let payload = body();
    let set = volumes(ChecksumKind::Crc32);

    // With the seam engaged by the caller's hint, and with it forced off
    // at a floor no member reaches. The verdict is the same either way.
    probe::set_seam_floor(None);
    let overlapped = read_back(&set, Some(true));
    probe::set_seam_floor(Some(u64::MAX));
    let sequential = read_back(&set, None);
    probe::set_seam_floor(None);

    for (arm, seen) in [("overlapped", &overlapped), ("sequential", &sequential)] {
        assert_eq!(seen.members.len(), 2, "{arm}: both members are delivered");
        for (index, (bytes, verdict)) in seen.members.iter().enumerate() {
            assert!(
                bytes == &payload,
                "{arm}, member {index}: the bytes are not the ones that were written"
            );
            assert_eq!(
                *verdict,
                Some(true),
                "{arm}, member {index}: an encrypted split CRC32 member verdicts \
                 {verdict:?}, against spec K 3.7.6"
            );
        }
    }

    // The BLAKE2sp twin of the same shape carries no CRC32 field, so no
    // fragment checksum is judged and the verdict is true. It is here
    // because it is what localises the difference to that field.
    let blake = read_back(&volumes(ChecksumKind::Blake2sp), Some(true));
    for (index, (bytes, verdict)) in blake.members.iter().enumerate() {
        assert!(bytes == &payload, "blake2sp, member {index}: wrong bytes");
        assert_eq!(
            *verdict,
            Some(true),
            "blake2sp, member {index}: the twin that carries no CRC32 field now \
             fails too, so the difference is wider than this file says"
        );
    }
}

/// The reference takes what rarkit wrote. Its exit code alone is weak
/// evidence (it exits 0 while printing a packed-data checksum error), so
/// the stronger reference arms are in `encrypted_volume_packed_crc.rs`.
#[test]
fn the_reference_accepts_the_vector_this_file_pins() {
    let Ok(_) = Command::new("unrar").output() else {
        eprintln!("SKIPPED the reference arm: unrar is not on PATH");
        return;
    };
    let set = volumes(ChecksumKind::Crc32);
    let dir = std::env::temp_dir().join(format!("rarkit-split-crc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let total = set.len() as u32;
    for (index, volume) in set.iter().enumerate() {
        let name = rarkit::volume_file_name("pin", index as u32, total, Default::default());
        std::fs::write(dir.join(name), volume).expect("write volume");
    }
    let first = dir.join(rarkit::volume_file_name(
        "pin",
        0,
        total,
        Default::default(),
    ));
    let out = Command::new("unrar")
        .arg("t")
        .arg("-inul")
        .arg(format!("-p{SECRET}"))
        .arg(&first)
        .output()
        .expect("unrar t");
    assert!(
        out.status.success(),
        "reference unrar REFUSED the vector, so the difference is rarkit's writer's \
         and not a reading of a silent section: {:?}\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}
