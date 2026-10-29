//! The member CRC32 of a CLEAR, STORED, SPLIT RAR 5 member, whatever
//! arrangement computes it.
//!
//! Spec F 3.5.6 has every fragment header but the last carry the CRC32 of
//! that fragment's packed bytes, and the last carry the member's. For a
//! clear stored member the packed bytes ARE the member, so a reader may
//! hash each byte once and give the member's checksum the fragments' CRCs
//! (`Crc32::append`) instead of a second pass. These tests were written
//! before that change and hold on the reader before it; each pins one way
//! the sharing could go wrong:
//!
//! - an all-ones leading-fragment field means NO checksum (walk.rs,
//!   `NO_FRAGMENT_CRC`), never an expected CRC, and the member CRC still
//!   covers that fragment's bytes;
//! - the last fragment's field is the member's, judged over every byte;
//! - a declared size that ends INSIDE a fragment clips the member CRC to
//!   the accepted prefix while the fragment check still covers the whole
//!   fragment;
//! - a truncated or missing volume ends the operation on the normal path,
//!   and equal CRCs never stand in for completion;
//! - a writer that fails ends the member with the writer's error and the
//!   bytes before it delivered;
//! - encrypted and BLAKE2sp twins are unchanged.

#![cfg(feature = "test-support")]

use std::io::Write;
use std::sync::{Arc, Mutex};

use rarkit::checksum::crc32;
use rarkit::{
    probe, ChecksumKind, Disposition, HostOs, MemberInfo, MemberOutcome, MemberSpec, Password,
    Payload, RangeSource, ReadOptions, Result, Sink, WriteMethod, WriteOptions, Writer,
};

/// A member over several volumes: 300,000 bytes at a 64 KiB cap is five
/// fragments, the last short.
const MEMBER: usize = 300_000;
const VOLUME_CAP: u64 = 64 << 10;

fn body(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761).max(1);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

fn volumes(members: &[Vec<u8>], checksum: ChecksumKind, password: Option<&str>) -> Vec<Vec<u8>> {
    let mut writer = Writer::new(WriteOptions {
        method: WriteMethod::Stored,
        checksum,
        password: password.map(Password::from),
        volume_file_size: Some(VOLUME_CAP),
        ..WriteOptions::default()
    })
    .expect("options");
    let names: Vec<String> = (0..members.len()).map(|i| format!("m{i}.bin")).collect();
    for (name, payload) in names.iter().zip(members) {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(payload),
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

// ---- a minimal RAR 5 block walker, for patching the vector's headers ----

fn vint(bytes: &[u8], at: &mut usize) -> u64 {
    let mut value = 0u64;
    let mut shift = 0;
    loop {
        let b = bytes[*at];
        *at += 1;
        value |= u64::from(b & 0x7F) << shift;
        if b & 0x80 == 0 {
            return value;
        }
        shift += 7;
    }
}

/// One file header of a volume: where its header CRC, its unpacked-size
/// field and its data CRC field sit, and its packed data range.
struct FileHead {
    start: usize,
    body: std::ops::Range<usize>,
    unpacked: Option<std::ops::Range<usize>>,
    data_crc: Option<usize>,
    data: std::ops::Range<usize>,
}

fn file_heads(volume: &[u8]) -> Vec<FileHead> {
    let mut heads = Vec::new();
    let mut at = 8;
    while at + 4 < volume.len() {
        let start = at;
        let mut p = at + 4;
        let size = vint(volume, &mut p) as usize;
        let body = start + 4..p + size;
        let kind = vint(volume, &mut p);
        let flags = vint(volume, &mut p);
        if flags & 1 != 0 {
            vint(volume, &mut p);
        }
        let data_size = if flags & 2 != 0 {
            vint(volume, &mut p) as usize
        } else {
            0
        };
        let data = body.end..body.end + data_size;
        if kind == 2 {
            let file_flags = vint(volume, &mut p);
            let u0 = p;
            vint(volume, &mut p);
            let unpacked = (file_flags & 8 == 0).then_some(u0..p);
            vint(volume, &mut p);
            if file_flags & 2 != 0 {
                p += 4;
            }
            let data_crc = (file_flags & 4 != 0).then_some(p);
            heads.push(FileHead {
                start,
                body: body.clone(),
                unpacked,
                data_crc,
                data: data.clone(),
            });
        }
        if kind == 5 {
            break;
        }
        at = data.end;
    }
    heads
}

fn reseal(volume: &mut [u8], head: &FileHead) {
    let crc = crc32(&volume[head.body.clone()]);
    volume[head.start..head.start + 4].copy_from_slice(&crc.to_le_bytes());
}

/// Rewrite a vint field in place with a value of the same encoded length.
fn put_vint(volume: &mut [u8], field: std::ops::Range<usize>, mut value: u64) {
    let len = field.len();
    for (i, slot) in volume[field].iter_mut().enumerate() {
        let more = if i + 1 < len { 0x80 } else { 0 };
        *slot = (value & 0x7F) as u8 | more;
        value >>= 7;
    }
    assert_eq!(value, 0, "the new value does not fit the old field");
}

// ---- reading back --------------------------------------------------------

#[derive(Default)]
struct Seen {
    members: Vec<(Vec<u8>, Option<bool>, u64)>,
}

struct Out {
    seen: Arc<Mutex<Seen>>,
    fail_after: Option<usize>,
}

impl Write for Out {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let mut held = lock(&self.seen);
        let last = held.members.len() - 1;
        let bytes = &mut held.members[last].0;
        if let Some(limit) = self.fail_after {
            if bytes.len() + data.len() > limit {
                return Err(std::io::Error::other("the writer refuses"));
            }
        }
        bytes.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Keep {
    seen: Arc<Mutex<Seen>>,
    verify: bool,
    fail_after: Option<usize>,
}

impl Sink for Keep {
    type Out = Out;
    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Out>> {
        lock(&self.seen).members.push((Vec::new(), None, 0));
        Ok(if self.verify {
            Disposition::Verify
        } else {
            Disposition::Write(Out {
                seen: Arc::clone(&self.seen),
                fail_after: self.fail_after,
            })
        })
    }
    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        _out: Option<Out>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        let mut held = lock(&self.seen);
        let last = held.members.len() - 1;
        held.members[last].1 = outcome.checksum_ok;
        held.members[last].2 = outcome.bytes;
        Ok(())
    }
}

fn lock<T>(held: &Arc<Mutex<T>>) -> std::sync::MutexGuard<'_, T> {
    held.lock().unwrap_or_else(|e| e.into_inner())
}

/// One operation over `set`: its result and every member's bytes, verdict
/// and byte count.
fn read_back(
    set: &[Vec<u8>],
    verify: bool,
    hint: Option<bool>,
    password: Option<&str>,
    fail_after: Option<usize>,
) -> (Result<()>, Seen) {
    let sources: Vec<Arc<dyn RangeSource>> = set
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let mut sink = Keep {
        seen: Arc::clone(&seen),
        verify,
        fail_after,
    };
    let options = ReadOptions::default()
        .with_password(password.map(Password::from))
        .with_workers(Some(2))
        .with_sink_is_file(hint);
    let outcome = rarkit::extract(sources, &options, &mut sink, &mut ()).map(|_| ());
    drop(sink);
    let seen = Arc::try_unwrap(seen)
        .unwrap_or_else(|_| panic!("the sink outlived the extraction"))
        .into_inner()
        .unwrap_or_else(|e| e.into_inner());
    (outcome, seen)
}

/// Every arrangement a stored member can be read in: verified, written in
/// sequence, and written through the seam (the caller's hint, the floor
/// lowered so a small member takes it).
fn every_arm(set: &[Vec<u8>], password: Option<&str>) -> Vec<(&'static str, Result<()>, Seen)> {
    let mut arms = Vec::new();
    probe::set_seam_floor(Some(u64::MAX));
    let (r, s) = read_back(set, true, None, password, None);
    arms.push(("verify", r, s));
    let (r, s) = read_back(set, false, None, password, None);
    arms.push(("write", r, s));
    probe::set_seam_floor(Some(0));
    let (r, s) = read_back(set, false, Some(true), password, None);
    arms.push(("write-seam", r, s));
    probe::set_seam_floor(None);
    arms
}

/// The fragments of a ONE-member set, as (volume, head index) pairs.
fn fragments_of_first(set: &[Vec<u8>]) -> Vec<(usize, usize)> {
    (0..set.len())
        .filter(|&v| !file_heads(&set[v]).is_empty())
        .map(|v| (v, 0))
        .collect()
}

// ---- the tests -------------------------------------------------------------

#[test]
fn a_clear_split_stored_member_verifies_true_on_every_arm() {
    let members = vec![
        body(MEMBER, 1),
        body(1, 2),
        body(VOLUME_CAP as usize * 2, 3),
    ];
    let set = volumes(&members, ChecksumKind::Crc32, None);
    for (arm, outcome, seen) in every_arm(&set, None) {
        outcome.unwrap_or_else(|e| panic!("{arm}: {e:?}"));
        assert_eq!(seen.members.len(), members.len(), "{arm}");
        for (i, (bytes, verdict, count)) in seen.members.iter().enumerate() {
            assert_eq!(*verdict, Some(true), "{arm} member {i}");
            assert_eq!(*count, members[i].len() as u64, "{arm} member {i}");
            if arm != "verify" {
                assert!(bytes == &members[i], "{arm} member {i}: bytes");
            }
        }
    }
}

#[test]
fn a_damaged_byte_in_any_fragment_fails_the_member() {
    let members = vec![body(MEMBER, 4)];
    let clean = volumes(&members, ChecksumKind::Crc32, None);
    let frags = fragments_of_first(&clean);
    assert!(frags.len() >= 3, "the vector has a middle fragment");
    for &(v, h) in &frags {
        let mut set = clean.clone();
        let head = &file_heads(&set[v])[h];
        let at = head.data.start + head.data.len() / 2;
        set[v][at] ^= 0x40;
        for (arm, outcome, seen) in every_arm(&set, None) {
            outcome.unwrap_or_else(|e| panic!("{arm} volume {v}: {e:?}"));
            assert_eq!(
                seen.members[0].1,
                Some(false),
                "{arm}: damage in volume {v}"
            );
        }
    }
}

/// All ones in a leading fragment's field is NO checksum: a clean member
/// still verifies, and damage inside that fragment is still caught, by the
/// member's own CRC, which must therefore have covered those bytes.
#[test]
fn the_all_ones_fragment_field_is_no_checksum_and_the_member_crc_still_covers_it() {
    let members = vec![body(MEMBER, 5)];
    let clean = volumes(&members, ChecksumKind::Crc32, None);
    let (v, h) = fragments_of_first(&clean)[1];
    let mut sentinel = clean.clone();
    let head = &file_heads(&sentinel[v])[h];
    let at = head
        .data_crc
        .expect("a leading fragment carries a data CRC");
    sentinel[v][at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    reseal(&mut sentinel[v], head);
    for (arm, outcome, seen) in every_arm(&sentinel, None) {
        outcome.unwrap_or_else(|e| panic!("{arm}: {e:?}"));
        assert_eq!(
            seen.members[0].1,
            Some(true),
            "{arm}: all ones is no checksum"
        );
    }
    let mut damaged = sentinel.clone();
    let head = &file_heads(&damaged[v])[h];
    let mid = head.data.start + head.data.len() / 2;
    damaged[v][mid] ^= 0x01;
    for (arm, outcome, seen) in every_arm(&damaged, None) {
        outcome.unwrap_or_else(|e| panic!("{arm}: {e:?}"));
        assert_eq!(
            seen.members[0].1,
            Some(false),
            "{arm}: the member CRC missed the damage"
        );
    }
}

/// The last fragment's field is the MEMBER's checksum over every byte:
/// replacing it with the last fragment's own packed CRC must fail.
#[test]
fn the_last_fragment_field_is_the_members_checksum() {
    let members = vec![body(MEMBER, 6)];
    let mut set = volumes(&members, ChecksumKind::Crc32, None);
    let &(v, h) = fragments_of_first(&set).last().expect("fragments");
    let head = &file_heads(&set[v])[h];
    let own = crc32(&set[v][head.data.clone()]);
    let at = head
        .data_crc
        .expect("the last fragment carries the member CRC");
    assert_eq!(
        u32::from_le_bytes(set[v][at..at + 4].try_into().unwrap()),
        crc32(&members[0]),
        "the vector's last field is the member's CRC"
    );
    set[v][at..at + 4].copy_from_slice(&own.to_le_bytes());
    reseal(&mut set[v], head);
    for (arm, outcome, seen) in every_arm(&set, None) {
        outcome.unwrap_or_else(|e| panic!("{arm}: {e:?}"));
        assert_eq!(seen.members[0].1, Some(false), "{arm}");
    }
}

/// A declared size that ends inside the SECOND fragment: the member's
/// output and CRC stop there, while every leading fragment's packed CRC
/// still covers its whole fragment. With the member field rewritten to the
/// prefix's CRC the member verifies; left alone it fails.
#[test]
fn a_declared_size_ending_inside_a_leading_fragment_clips_the_member_crc() {
    let members = vec![body(MEMBER, 7)];
    let clean = volumes(&members, ChecksumKind::Crc32, None);
    let frags = fragments_of_first(&clean);
    let first_len = file_heads(&clean[frags[0].0])[frags[0].1].data.len();
    let second_len = file_heads(&clean[frags[1].0])[frags[1].1].data.len();
    let declared = first_len + second_len / 2 + 3;
    let patch = |with_prefix_crc: bool| {
        let mut set = clean.clone();
        for &(v, h) in &frags {
            let head = &file_heads(&set[v])[h];
            put_vint(
                &mut set[v],
                head.unpacked.clone().expect("a size"),
                declared as u64,
            );
            if with_prefix_crc && (v, h) == *frags.last().unwrap() {
                let at = head.data_crc.expect("member CRC");
                set[v][at..at + 4].copy_from_slice(&crc32(&members[0][..declared]).to_le_bytes());
            }
            reseal(&mut set[v], head);
        }
        set
    };
    for (arm, outcome, seen) in every_arm(&patch(true), None) {
        outcome.unwrap_or_else(|e| panic!("{arm}: {e:?}"));
        let (bytes, verdict, count) = &seen.members[0];
        assert_eq!(
            *count, declared as u64,
            "{arm}: output stops at the declared size"
        );
        assert_eq!(*verdict, Some(true), "{arm}: the prefix CRC verifies");
        if arm != "verify" {
            assert!(bytes[..] == members[0][..declared], "{arm}: bytes");
        }
    }
    for (arm, outcome, seen) in every_arm(&patch(false), None) {
        outcome.unwrap_or_else(|e| panic!("{arm}: {e:?}"));
        assert_eq!(
            seen.members[0].1,
            Some(false),
            "{arm}: the whole member's CRC is not the prefix's"
        );
    }
}

/// A volume cut short, or one missing, ends the operation with an error on
/// the normal path and never with a member reported good.
#[test]
fn a_truncated_or_missing_volume_is_never_a_good_member() {
    let members = vec![body(MEMBER, 8)];
    let clean = volumes(&members, ChecksumKind::Crc32, None);
    let (v, h) = fragments_of_first(&clean)[1];
    let mut cut = clean.clone();
    let end = file_heads(&cut[v])[h].data.start + 100;
    cut[v].truncate(end);
    let mut missing = clean.clone();
    missing.remove(v);
    for (name, set) in [("truncated", cut), ("missing", missing)] {
        for (arm, outcome, seen) in every_arm(&set, None) {
            assert!(outcome.is_err(), "{name} {arm}: the operation succeeded");
            assert!(
                seen.members.iter().all(|m| m.1 != Some(true)),
                "{name} {arm}: a member was reported good"
            );
        }
    }
}

/// A writer that refuses mid-member: the writer's error ends the
/// operation and the bytes before it were delivered in order.
#[test]
fn a_failing_writer_keeps_its_error_and_its_partial_output() {
    let members = vec![body(MEMBER, 9)];
    let set = volumes(&members, ChecksumKind::Crc32, None);
    let limit = 150_000;
    for hint in [None, Some(true)] {
        probe::set_seam_floor(if hint.is_some() {
            Some(0)
        } else {
            Some(u64::MAX)
        });
        let (outcome, seen) = read_back(&set, false, hint, None, Some(limit));
        probe::set_seam_floor(None);
        assert!(outcome.is_err(), "hint {hint:?}: the refusal was swallowed");
        let bytes = &seen.members[0].0;
        assert!(bytes.len() <= limit, "hint {hint:?}");
        assert!(
            bytes[..] == members[0][..bytes.len()],
            "hint {hint:?}: partial output out of order"
        );
        assert_ne!(seen.members[0].1, Some(true), "hint {hint:?}");
    }
}

/// The twins the sharing must leave alone: a BLAKE2sp member verifies, and
/// an encrypted CRC32 member, whose fragment fields cover the CIPHERTEXT
/// (spec K 3.7.6, `encrypted_split_fragment_crc.rs`), verifies with the
/// right bytes while sharing nothing: its member CRC is the plaintext's.
#[test]
fn blake2sp_and_encrypted_twins_are_unchanged() {
    let members = vec![body(MEMBER, 10)];
    let blake = volumes(&members, ChecksumKind::Blake2sp, None);
    for (arm, outcome, seen) in every_arm(&blake, None) {
        outcome.unwrap_or_else(|e| panic!("blake {arm}: {e:?}"));
        assert_eq!(seen.members[0].1, Some(true), "blake {arm}");
    }
    let secret = "share";
    let sealed = volumes(&members, ChecksumKind::Crc32, Some(secret));
    for (arm, outcome, seen) in every_arm(&sealed, Some(secret)) {
        outcome.unwrap_or_else(|e| panic!("encrypted {arm}: {e:?}"));
        assert_eq!(seen.members[0].1, Some(true), "encrypted {arm}");
        if arm != "verify" {
            assert!(seen.members[0].0 == members[0], "encrypted {arm}: bytes");
        }
    }
}
