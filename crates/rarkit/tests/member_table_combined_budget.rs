//! D3: the open holds the member table and the names together to ONE
//! budget, `MemoryPolicy::max_member_table` (spec F 4.2: "counted as bytes
//! of table plus names"; both rows refuse with
//! `LimitExceeded { resource: MemberTable }`).
//!
//! Two RAR 5 archives are made here with the same number of members and
//! nothing else between them but the names: short in one, long in the
//! other. Under one combined budget the smallest limit that opens the
//! long one is the short one's plus exactly the extra name bytes. A walk
//! that checks the table and the names each against the whole limit on
//! its own needs only the larger of the two, and a table and names
//! together can then hold close to twice the limit.

use std::sync::Arc;

use rarkit::{Archive, ErrorKind, RangeSource, ReadOptions, Resource};

const MEMBERS: usize = 2_000;
const SHORT: usize = 7;
const LONG: usize = 40;

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn vint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let low = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}

/// A RAR 5 block: its CRC32, its size and the header bytes after it.
fn block(fields: &[u8], out: &mut Vec<u8>) {
    let mut sized = Vec::new();
    vint(fields.len() as u64, &mut sized);
    sized.extend_from_slice(fields);
    out.extend_from_slice(&crc32(&sized).to_le_bytes());
    out.extend_from_slice(&sized);
}

/// `MEMBERS` empty stored files, each name `width` bytes long.
fn archive(width: usize) -> Vec<u8> {
    archive_of(MEMBERS, width)
}

/// `count` empty stored files, each name `width` bytes long.
fn archive_of(count: usize, width: usize) -> Vec<u8> {
    let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
    // Main header: type 1, no header flags, no archive flags.
    block(&[1, 0, 0], &mut out);
    for at in 0..count {
        let name = format!("{at:0width$}");
        // File header: type 2, no header flags, no file flags, unpacked
        // size 0, attributes 0, stored, host 0, then the name.
        let mut fields = vec![2, 0, 0, 0, 0, 0, 0];
        vint(name.len() as u64, &mut fields);
        fields.extend_from_slice(name.as_bytes());
        block(&fields, &mut out);
    }
    // End of archive: type 5, no header flags, no end flags.
    block(&[5, 0, 0], &mut out);
    out
}

fn open(bytes: &[u8], limit: u64) -> rarkit::Result<Archive> {
    let mut opts = ReadOptions::default();
    opts.memory.max_member_table = limit;
    Archive::open(Arc::new(bytes.to_vec()) as Arc<dyn RangeSource>, &opts)
}

/// The smallest limit that opens `bytes`; every refusal on the way must
/// be the member table's.
fn smallest(bytes: &[u8]) -> u64 {
    let (mut refused, mut opened) = (0u64, 1u64 << 30);
    assert_eq!(open(bytes, opened).unwrap().members().count(), MEMBERS);
    while opened - refused > 1 {
        let mid = refused + (opened - refused) / 2;
        match open(bytes, mid) {
            Ok(_) => opened = mid,
            Err(err) => {
                assert!(
                    matches!(
                        err.kind(),
                        ErrorKind::LimitExceeded {
                            resource: Resource::MemberTable,
                            ..
                        }
                    ),
                    "at {mid}: {err}"
                );
                refused = mid;
            }
        }
    }
    opened
}

/// D3b: a name that alone does not fit is refused with what the table
/// and names would have needed, which is more than the limit; 899cfe976
/// reported the names held before it, here 0.
#[test]
fn a_refused_name_reports_what_it_needed() {
    let limit = 1_000;
    let err = match open(&archive_of(1, 2_000), limit) {
        Ok(_) => panic!("a 2,000 byte name opened under {limit}"),
        Err(err) => err,
    };
    match err.kind() {
        ErrorKind::LimitExceeded {
            resource: Resource::MemberTable,
            needed,
            limit: allowed,
        } => {
            assert_eq!(*allowed, limit);
            assert!(*needed > limit, "needed {needed}, limit {limit}: {err}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn table_and_names_share_one_budget() {
    let short = smallest(&archive(SHORT));
    let long = smallest(&archive(LONG));
    let extra = (MEMBERS * (LONG - SHORT)) as u64;
    assert_eq!(
        long,
        short + extra,
        "{MEMBERS} members open under {short} bytes with {SHORT} byte names; \
         with {LONG} byte names the names are {extra} bytes more, so one \
         budget for table plus names needs {}, and the open took {long}",
        short + extra
    );
}
