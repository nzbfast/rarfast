//! Spec L 3.5.5, "Whose records they are" (rules O1 to O5 and O1b): a
//! RAR 5 inline recovery record is applied to the named file only when
//! it is that file's OWN.
//!
//! A named archive that stores another archive holds that archive's
//! records as bytes of a member, whole and valid, and a scan for records
//! by their marker meets them. Such a set describes a file that begins
//! further on; holding its slice table against the named file from byte
//! 0 rebuilds the inner archive over the outer one.
//!
//! What is pinned here, on archives rarkit's own writer makes:
//!
//! - O1, O2, O3: an outer archive with a 1 percent record that stores an
//!   inner archive with a 150 percent record, and with a 20 percent one,
//!   its signature damaged so the header path is stopped: the repair
//!   gives back the OUTER archive byte for byte (before the rule the
//!   first gave the inner archive and called it mended, and the second
//!   failed with the outer's whole record unused);
//! - O4: the same outer archive with no record of its own is `NoRecord`,
//!   never the inner archive;
//! - O1: the outer's `RR` header failing its own check is still that
//!   header while its size and type say where it ends;
//! - O1b: with that header's size wrong, its type changed or its bytes
//!   zero, the set is own by shard 0, the file's first bytes, and the
//!   archive is mended; the carried set is refused all the same, also
//!   where the inner payload is one byte repeated and most of the
//!   carried set's shards fit from byte 0;
//! - O1c: such a header AND damage in shard 0 (a signature bit): the
//!   set is own by its distance, its data area starting no more than 40
//!   bytes behind the offset it names, and the archive is mended as the
//!   reference mends it; a carried set starts further off and is
//!   refused;
//! - O5: what a sound main header says, and that a damaged one says
//!   nothing of a record;
//! - O7: a data area with no header at all is no way of its own: it is
//!   own by shard 0 or by its distance, which is 0, and behind other
//!   bytes it is neither.
//!
//! The reference's answers on 178 arms of this shape are
//! `specs/vectors-L/own-records/`; its probe runs `rarfast r` against
//! them.
//!
//! Threads and memory: every call runs under a policy of at most 4
//! workers and a 16 MiB repair limit; the largest file is about 1.1 MiB.

use std::sync::Arc;

use rarkit::memory::MemoryPolicy;
use rarkit::{
    Archive, BlockKind, ErrorKind, MemberSpec, Payload, RangeSource, ReadOptions, RecoveryFailure,
    ServiceKind, WriteFormat, WriteOptions, Writer,
};

fn options() -> ReadOptions {
    ReadOptions::default().with_memory(MemoryPolicy {
        repair_limit: 16 << 20,
        max_workers: 4,
        ..MemoryPolicy::from_limit(64 << 20)
    })
}

/// Bytes from a fixed sequence: the same on every run, and holding no
/// record marker.
fn noise(len: usize, seed: u32) -> Vec<u8> {
    let bytes = rarkit_testdata::scramble(u64::from(seed), len);
    assert!(!bytes.windows(4).any(|w| w == b"{RB}"));
    bytes
}

/// A stored RAR 5 archive of `members`, with a record of `percent`.
fn archive(members: &[(&[u8], &[u8])], percent: Option<u32>) -> Vec<u8> {
    let mut writer = Writer::new(WriteOptions {
        format: WriteFormat::Rar5,
        recovery_percent: percent,
        ..WriteOptions::default()
    })
    .unwrap();
    for (name, data) in members {
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(data),
                mtime: None,
                attributes: 0o100644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .unwrap();
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).unwrap();
    out
}

/// The outer archive: `inner.rar` (a stored archive of one member with a
/// record of `inner` percent) and a small member, under a record of
/// `outer` percent.
fn nested(inner: u32, outer: Option<u32>) -> (Vec<u8>, Vec<u8>) {
    nested_over(&noise(200_000, 0x6f77_6e01), inner, outer)
}

/// [`nested`] over a given inner payload.
fn nested_over(payload: &[u8], inner: u32, outer: Option<u32>) -> (Vec<u8>, Vec<u8>) {
    let small = noise(20_000, 0x6f77_6e02);
    let inner = archive(&[(b"payload.bin", payload)], Some(inner));
    let outer = archive(&[(b"inner.rar", &inner), (b"small.bin", &small)], outer);
    (inner, outer)
}

/// The archive with one bit of its signature changed: the header path
/// reads nothing, so the record is looked for by its marker.
fn signature_damaged(good: &[u8]) -> Vec<u8> {
    let mut damaged = good.to_vec();
    damaged[3] ^= 1;
    damaged
}

fn repaired(damaged: &[u8]) -> rarkit::Result<Vec<u8>> {
    let mut out = Vec::new();
    rarkit::recovery::repair_inline(&damaged.to_vec(), &options(), &mut out)?;
    Ok(out)
}

/// Where the archive's own `RR` service header starts.
fn rr_header(good: &[u8]) -> usize {
    let opened = Archive::open(
        Arc::new(good.to_vec()) as Arc<dyn RangeSource>,
        &ReadOptions::default(),
    )
    .unwrap();
    let block = opened
        .blocks()
        .find(|block| block.kind == BlockKind::Service(ServiceKind::RecoveryRecord))
        .expect("the archive's own record");
    block.range.start as usize
}

fn no_record(error: &rarkit::Error) -> bool {
    matches!(error.kind(), ErrorKind::Recovery(RecoveryFailure::NoRecord))
}

#[test]
fn an_inner_record_of_150_percent_is_not_applied_to_the_outer_archive() {
    let (inner, outer) = nested(150, Some(1));
    let out = repaired(&signature_damaged(&outer)).expect("the outer's own record repairs it");
    assert!(
        out.len() != inner.len() && !out.starts_with(&inner[..4096]),
        "the repair wrote the INNER archive"
    );
    assert!(out == outer, "the outer archive, byte for byte");
}

#[test]
fn an_inner_record_of_20_percent_does_not_hide_the_outer_archives_own() {
    let (_, outer) = nested(20, Some(1));
    let out = repaired(&signature_damaged(&outer)).expect("the outer's own record repairs it");
    assert!(out == outer, "the outer archive, byte for byte");

    // And every slice the check judges is one of the outer's own 200.
    let check = rarkit::recovery::check_inline(&signature_damaged(&outer), &options()).unwrap();
    assert_eq!(check.protected, rr_header(&outer) as u64);
    assert_eq!((check.shards, check.rows), (200, 2));
    let damaged: Vec<&Vec<u16>> = check.groups.iter().map(|group| &group.damaged).collect();
    assert_eq!(damaged, [&vec![0u16]], "the signature's slice alone");
}

#[test]
fn an_outer_archive_with_no_record_of_its_own_is_never_repaired_from_an_inner_one() {
    for percent in [150, 20] {
        let (_, outer) = nested(percent, None);
        let damaged = signature_damaged(&outer);
        let error = repaired(&damaged).expect_err("there is no record of the outer archive");
        assert!(no_record(&error), "{percent}: {error}");
        let error = rarkit::recovery::check_inline(&damaged, &options()).unwrap_err();
        assert!(no_record(&error), "{percent}: {error}");
        let error = rarkit::recovery::scan_inline(&damaged).unwrap_err();
        assert!(no_record(&error), "{percent}: {error}");
    }
}

#[test]
fn control_an_archive_with_no_inner_archive_repairs_as_before() {
    let payload = noise(200_000, 0x6f77_6e01);
    let small = noise(20_000, 0x6f77_6e02);
    let good = archive(
        &[(b"payload.bin", &payload), (b"small.bin", &small)],
        Some(1),
    );
    assert!(repaired(&signature_damaged(&good)).unwrap() == good);
    let mut damaged = signature_damaged(&good);
    damaged[100_000] ^= 0xff;
    assert!(repaired(&damaged).unwrap() == good);
}

/// The `RR` header is not protected by the record it leads, and the
/// reference repairs past one that fails its check (3.5.5). A changed
/// CRC field leaves the header's size and type saying where it ends, so
/// the record behind it is still the archive's own.
#[test]
fn an_own_record_behind_an_rr_header_failing_its_check_is_still_own() {
    let (_, outer) = nested(150, Some(1));
    let at = rr_header(&outer);
    let mut damaged = signature_damaged(&outer);
    damaged[at] ^= 0x10;
    let out = repaired(&damaged).expect("the outer's own record repairs it");
    // The protected bytes come back; the header after them is not the
    // record's to mend (3.8).
    assert!(out[..at] == outer[..at]);
    assert_eq!(out[at], outer[at] ^ 0x10);
    assert!(out[at + 1..] == outer[at + 1..]);
}

/// The three ways the probe unmakes the outer's `RR` header, at `at`:
/// its size field wrong, its type no service header's, every byte zero.
fn unmade_headers(outer: &[u8], at: usize) -> Vec<(&'static str, Vec<u8>)> {
    let end = outer[at..]
        .windows(4)
        .position(|w| w == b"{RB}")
        .expect("the record area")
        + at;
    let mut size = outer.to_vec();
    size[at + 4] += 1;
    let mut kind = outer.to_vec();
    kind[at + 5] = 9;
    let mut zero = outer.to_vec();
    zero[at..end].fill(0);
    vec![("size", size), ("type", kind), ("zero", zero)]
}

/// O1b: the header at `P` gone, the set is own by shard 0, and damage
/// anywhere else is mended from it; the carried set, ten times the rows,
/// is refused.
#[test]
fn an_own_record_whose_header_is_gone_is_own_by_shard_0() {
    let (_, outer) = nested(150, Some(1));
    let at = rr_header(&outer);
    for (what, mut damaged) in unmade_headers(&outer, at) {
        // One slice, past shard 0 and inside the stored inner archive.
        damaged[100_000] ^= 0xff;
        let out = repaired(&damaged).unwrap_or_else(|e| panic!("{what}: {e}"));
        assert!(out[..at] == outer[..at], "{what}: the protected bytes");
        let check = rarkit::recovery::check_inline(&damaged, &options()).unwrap();
        assert_eq!((check.shards, check.rows), (200, 2), "{what}");
    }
}

/// The same where the inner payload is one byte repeated, so that most
/// of the carried set's shards fit the outer file counted from byte 0:
/// shard 0 does not, and a count of fitting shards is never asked.
#[test]
fn a_carried_set_over_a_repeated_byte_is_refused_by_shard_0() {
    let (inner, outer) = nested_over(&vec![b'A'; 200_000], 150, Some(1));
    let at = rr_header(&outer);
    for (what, mut damaged) in unmade_headers(&outer, at) {
        damaged[at - 10_000] ^= 0xff;
        let out = repaired(&damaged).unwrap_or_else(|e| panic!("{what}: {e}"));
        assert!(!out.starts_with(&inner[..64]), "{what}: the INNER archive");
        assert!(out[..at] == outer[..at], "{what}: the protected bytes");
    }
    // And with no own record at all there is nothing to repair from.
    let (_, bare_outer) = nested_over(&vec![b'A'; 200_000], 150, None);
    let error = repaired(&signature_damaged(&bare_outer)).expect_err("no own record");
    assert!(no_record(&error), "{error}");
}

/// O1c: the header at `P` gone AND shard 0 damaged. Neither the header
/// nor the file's first bytes then say whose the set is; its distance
/// does. The own set's data area starts where its header ended, no more
/// than 40 bytes behind `P`, and the archive is mended, as the
/// reference mends it. The carried set starts further from its own `P`
/// by the stored archive's offset and is refused, also over a payload
/// of one byte repeated, where most of its shards fit from byte 0.
#[test]
fn a_gone_header_and_a_damaged_shard_0_are_own_by_distance() {
    for payload in [noise(200_000, 0x6f77_6e03), vec![b'A'; 200_000]] {
        let (inner, outer) = nested_over(&payload, 150, Some(1));
        let at = rr_header(&outer);
        for (what, damaged) in unmade_headers(&outer, at) {
            let mut damaged = signature_damaged(&damaged);
            damaged[at - 10_000] ^= 0xff;
            let out = repaired(&damaged).unwrap_or_else(|e| panic!("{what}: {e}"));
            assert!(!out.starts_with(&inner[..64]), "{what}: the INNER archive");
            assert!(out[..at] == outer[..at], "{what}: the protected bytes");
            let check = rarkit::recovery::check_inline(&damaged, &options()).unwrap();
            assert_eq!((check.shards, check.rows), (200, 2), "{what}");
        }
    }
}

/// O5: only a SOUND main header answers for a record; one that fails
/// its check says the volume is damaged there and nothing of a record,
/// and where none stands after a signature at byte 0 nothing is said.
#[test]
fn a_sound_main_header_says_whether_there_is_a_record() {
    use rarkit::recovery::MainHeaderRecord as Says;

    let says = |bytes: &[u8]| rarkit::recovery::main_header_record(&bytes.to_vec());
    let payload = noise(20_000, 0x6f77_6e02);
    let with = archive(&[(b"small.bin", &payload)], Some(3));
    let without = archive(&[(b"small.bin", &payload)], None);
    assert_eq!(says(&with), Says::Present);
    assert_eq!(says(&without), Says::Absent);
    for good in [&with, &without] {
        assert_eq!(says(&signature_damaged(good)), Says::NoMainHeader);
        // One bit of the main header's flags, and one of its CRC field.
        for at in [14, 9] {
            let mut main = good.to_vec();
            main[at] ^= 0x40;
            assert_eq!(says(&main), Says::Corrupt, "byte {at}");
        }
        // Cut inside the main header.
        assert_eq!(says(&good[..10]), Says::Corrupt);
        // The block's type made the archive encryption header's (O6):
        // no main header stands in the clear there.
        let mut enciphered = good.to_vec();
        enciphered[13] = 4;
        assert_eq!(says(&enciphered), Says::NoMainHeader);
    }
    assert_eq!(says(b""), Says::NoMainHeader);
    assert_eq!(
        says(b"Rar!\x1a\x07\x00 a RAR 4 archive"),
        Says::NoMainHeader
    );
}

/// O7: a data area with no header before it (the encoder's area laid
/// straight after the bytes it protects) is no way of its own. With
/// shard 0 whole it is own by shard 0 and mends damage elsewhere; with
/// shard 0 damaged it is own by its distance, which is 0 (O1c), and
/// shard 0 is mended; and behind 5,000 other bytes it is the record of
/// a file that begins there, own by neither.
#[test]
fn a_bare_record_is_own_by_shard_0_or_by_distance() {
    let data = noise(120_000, 0x0bad_5eed);
    let mut whole = data.clone();
    whole.extend(rarkit::internals::recovery::rr5_encode(&data, 150).unwrap());
    let mut damaged = whole.clone();
    damaged[60_000] ^= 1;
    assert!(repaired(&damaged).unwrap() == whole);

    let mut first = whole.clone();
    first[3] ^= 1;
    assert!(repaired(&first).unwrap() == whole);

    let mut behind = noise(5_000, 0x0000_7777);
    behind.extend(&whole);
    let error = repaired(&behind).expect_err("the record is of a file that begins further on");
    assert!(no_record(&error), "{error}");
}
