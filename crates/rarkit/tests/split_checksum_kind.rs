//! A split member is never called good by a checksum kind the reader did
//! not run (spec F 3.5.6: the member is judged by the LAST fragment
//! header's checksum).
//!
//! The reader chooses what to run from the FIRST fragment's header: a
//! CRC32 for a CRC32 field or for a bare split header, a BLAKE2sp state
//! for a BLAKE2sp record. When the last header then names the OTHER kind
//! nothing was computed that it could be compared with, and the member
//! fails its checksum whatever its bytes. Before the mend a BLAKE2sp last
//! header behind a first that armed CRC32 gave no verdict, which the tool
//! prints as OK, and a CRC32 last header behind a first that armed
//! BLAKE2sp was compared with a register nothing had fed, which finishes
//! as 0: right bytes failed, and a stored CRC32 of 0 passed anything.
//!
//! `split_checksum_kind/set.part{1,2}.rar` are GENUINE: rar 7.23 for
//! macOS, `rar a -m0 -v1000b -htb -qo-` of 1,500 random bytes, a BLAKE2sp
//! record in both headers. Each arm rewrites ONE file header of the set
//! (the hash record taken out, a CRC32 field put in, the header's size and
//! CRC32 redone) and leaves every other byte alone. No genuine writer is
//! known to make these.
//!
//! WHAT THE REFERENCE DOES (rar 7.23 and unrar 7.23, aarch64 macOS, 10 Oct
//! 2026, the same shapes built from a 300,000 byte member): first CRC32
//! with last BLAKE2sp, and first BLAKE2sp with last CRC32 (the true one or
//! 0), are "checksum error", exit 3, on right bytes: followed here. First
//! BARE with last BLAKE2sp is "All OK", exit 0, WITH A PAYLOAD BYTE
//! FLIPPED: the reference judges by the first header's kind and with none
//! it judges nothing. A DIFFERENCE PINNED, NOT COPIED: that member fails
//! here, right bytes included, because nothing vouches for them.
//!
//! A LAST HEADER WITH NO CHECKSUM behind a first that named one (10 Oct
//! 2026): the reader ran the first header's kind and the last header gives
//! it nothing to meet. The reference prints ` ?` where it prints OK,
//! then "All OK", exit 0, the payload byte flipped or not. Here the
//! member had no verdict, which the tool prints as OK. A CHOSEN
//! STRICTNESS: it fails, right bytes included. A member NEITHER of whose
//! headers names a checksum is the ordinary member without one and keeps
//! no verdict.
//!
//! Every read runs through `extract` at one worker and at four, verified
//! and written; the set is 1,691 bytes and the reads hold the stored
//! path's ordinary working memory, nothing sized by the test.

use std::sync::Arc;

use rarkit::{
    extract, Disposition, MemberInfo, MemberOutcome, RangeSource, ReadOptions, Result, Sink,
};

const PART1: &[u8] = include_bytes!("split_checksum_kind/set.part1.rar");
const PART2: &[u8] = include_bytes!("split_checksum_kind/set.part2.rar");

/// The CRC32 of the member's 1,500 bytes.
const WHOLE_CRC: u32 = 0xf02d_6a6b;

// ---- rewriting one RAR 5 file header -------------------------------------

fn vint(bytes: &[u8], at: &mut usize) -> u64 {
    let mut value = 0u64;
    let mut shift = 0;
    loop {
        let b = bytes[*at];
        *at += 1;
        value |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return value;
        }
        shift += 7;
    }
}

fn put_vint(out: &mut Vec<u8>, mut value: u64) {
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

/// The volume's one file header, taken apart: where the block starts,
/// where its header ends (its data begins), and the header's pieces.
struct Head {
    start: usize,
    end: usize,
    flags: u64,
    data_size: u64,
    /// File flags to the end of the name.
    fields: Vec<u8>,
    /// The extra area's records, each whole (size, type, body).
    records: Vec<(u64, Vec<u8>)>,
}

fn head_of(volume: &[u8]) -> Head {
    let mut at = 8;
    loop {
        let start = at;
        let mut p = at + 4;
        let size = vint(volume, &mut p) as usize;
        let end = p + size;
        let kind = vint(volume, &mut p);
        let flags = vint(volume, &mut p);
        let extra = if flags & 1 != 0 {
            vint(volume, &mut p) as usize
        } else {
            0
        };
        let data_size = if flags & 2 != 0 {
            vint(volume, &mut p)
        } else {
            0
        };
        if kind != 2 {
            at = end + data_size as usize;
            continue;
        }
        let fields = volume[p..end - extra].to_vec();
        let mut records = Vec::new();
        let mut r = end - extra;
        while r < end {
            let from = r;
            let len = vint(volume, &mut r) as usize;
            let mut t = r;
            let record = vint(volume, &mut t);
            records.push((record, volume[from..r + len].to_vec()));
            r += len;
        }
        return Head {
            start,
            end,
            flags,
            data_size,
            fields,
            records,
        };
    }
}

/// `volume` with its file header rewritten: the BLAKE2sp record (extra
/// record type 2) taken out when `strip`, and a CRC32 field put in when
/// `crc` is given.
fn reshape(volume: &[u8], strip: bool, crc: Option<u32>) -> Vec<u8> {
    let head = head_of(volume);
    let mut fields = head.fields.clone();
    if let Some(crc) = crc {
        let file_flags = fields[0];
        assert_eq!(file_flags & 0x86, 0, "no time field, no CRC32, one byte");
        fields[0] = file_flags | 0x04;
        let mut p = 1;
        vint(&fields, &mut p); // unpacked size
        vint(&fields, &mut p); // attributes
        fields.splice(p..p, crc.to_le_bytes());
    }
    let extra: Vec<u8> = head
        .records
        .iter()
        .filter(|(record, _)| !(strip && *record == 2))
        .flat_map(|(_, bytes)| bytes.iter().copied())
        .collect();
    let flags = if extra.is_empty() {
        head.flags & !1
    } else {
        head.flags | 1
    };
    let mut rest = Vec::new();
    put_vint(&mut rest, 2);
    put_vint(&mut rest, flags);
    if !extra.is_empty() {
        put_vint(&mut rest, extra.len() as u64);
    }
    put_vint(&mut rest, head.data_size);
    rest.extend_from_slice(&fields);
    rest.extend_from_slice(&extra);
    let mut body = Vec::new();
    put_vint(&mut body, rest.len() as u64);
    body.extend_from_slice(&rest);
    let mut out = volume[..head.start].to_vec();
    out.extend_from_slice(&crc32fast::hash(&body).to_le_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(&volume[head.end..]);
    out
}

/// The packed bytes of the volume's fragment.
fn data_of(volume: &[u8]) -> &[u8] {
    let head = head_of(volume);
    &volume[head.end..head.end + head.data_size as usize]
}

/// `volume` with one bit of its fragment's middle byte inverted.
fn flipped(volume: &[u8]) -> Vec<u8> {
    let head = head_of(volume);
    let mut out = volume.to_vec();
    out[head.end + head.data_size as usize / 2] ^= 0x01;
    out
}

// ---- reading back ----------------------------------------------------------

struct Keep {
    verify: bool,
    members: Vec<(Option<bool>, Vec<u8>)>,
}

impl Sink for Keep {
    type Out = Vec<u8>;

    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        Ok(if self.verify {
            Disposition::Verify
        } else {
            Disposition::Write(Vec::new())
        })
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.members
            .push((outcome.checksum_ok, out.unwrap_or_default()));
        Ok(())
    }
}

/// The member's verdict in every arrangement, which must all agree; a
/// written member's bytes are checked to be the ones the set holds.
fn verdict_of(first: &[u8], last: &[u8], arm: &str) -> Option<bool> {
    let mut held = data_of(first).to_vec();
    held.extend_from_slice(data_of(last));
    let mut verdicts = Vec::new();
    for workers in [1, 4] {
        for verify in [true, false] {
            let sources: Vec<Arc<dyn RangeSource>> =
                vec![Arc::new(first.to_vec()), Arc::new(last.to_vec())];
            let mut sink = Keep {
                verify,
                members: Vec::new(),
            };
            let options = ReadOptions::default().with_workers(Some(workers));
            // A member's failure is its own `close`.
            let _ = extract(sources, &options, &mut sink, &mut ());
            let at = format!("{arm}, {workers} workers, verify {verify}");
            assert_eq!(sink.members.len(), 1, "{at}");
            if !verify {
                assert_eq!(sink.members[0].1, held, "{at}");
            }
            verdicts.push((sink.members[0].0, at));
        }
    }
    let first_verdict = verdicts[0].0;
    for (verdict, at) in &verdicts {
        assert_eq!(*verdict, first_verdict, "{arm}: {at} parts from the rest");
    }
    first_verdict
}

// ---- the arms ---------------------------------------------------------------

#[test]
fn the_genuine_set_is_judged_by_its_blake2sp() {
    assert_eq!(
        crc32fast::hash(&[data_of(PART1), data_of(PART2)].concat()),
        WHOLE_CRC
    );
    assert_eq!(verdict_of(PART1, PART2, "genuine"), Some(true));
    assert_eq!(
        verdict_of(PART1, &flipped(PART2), "genuine, a byte flipped"),
        Some(false)
    );
}

/// The first header armed CRC32 (its own field, or none at all)
/// and the last names BLAKE2sp: no BLAKE2sp was run, so the member fails.
#[test]
fn a_blake2sp_last_header_behind_a_first_that_armed_crc32_fails() {
    let with_crc = reshape(PART1, true, Some(crc32fast::hash(data_of(PART1))));
    assert_eq!(
        verdict_of(&with_crc, PART2, "first CRC32, last BLAKE2sp"),
        Some(false)
    );
    assert_eq!(
        verdict_of(
            &with_crc,
            &flipped(PART2),
            "first CRC32, last BLAKE2sp, a byte flipped"
        ),
        Some(false)
    );
    // The reference calls both of these OK (the module's note).
    let bare = reshape(PART1, true, None);
    assert_eq!(
        verdict_of(&bare, PART2, "first bare, last BLAKE2sp"),
        Some(false)
    );
    assert_eq!(
        verdict_of(
            &bare,
            &flipped(PART2),
            "first bare, last BLAKE2sp, a byte flipped"
        ),
        Some(false)
    );
}

/// The first header armed BLAKE2sp and the last names CRC32: no
/// CRC32 was run, so the member fails, whether the field holds the true
/// value or the 0 an unfed register finishes as.
#[test]
fn a_crc32_last_header_behind_a_first_that_armed_blake2sp_fails() {
    let truthful = reshape(PART2, true, Some(WHOLE_CRC));
    assert_eq!(
        verdict_of(PART1, &truthful, "first BLAKE2sp, last CRC32"),
        Some(false)
    );
    let zero = reshape(PART2, true, Some(0));
    assert_eq!(
        verdict_of(PART1, &zero, "first BLAKE2sp, last CRC32 of 0"),
        Some(false)
    );
    assert_eq!(
        verdict_of(
            PART1,
            &flipped(&zero),
            "first BLAKE2sp, last CRC32 of 0, a byte flipped"
        ),
        Some(false)
    );
}

/// The control: a bare first header arms CRC32, and a CRC32 last header
/// is then judged by it, as before.
#[test]
fn a_crc32_last_header_behind_a_bare_first_is_judged() {
    let bare = reshape(PART1, true, None);
    let last = reshape(PART2, true, Some(WHOLE_CRC));
    assert_eq!(
        verdict_of(&bare, &last, "first bare, last CRC32"),
        Some(true)
    );
    assert_eq!(
        verdict_of(
            &bare,
            &flipped(&last),
            "first bare, last CRC32, a byte flipped"
        ),
        Some(false)
    );
}

/// The first header named a kind, which was run, and the last names
/// none: nothing vouches for the bytes, and the member fails.
#[test]
fn a_last_header_with_no_checksum_behind_a_first_that_named_one_fails() {
    let bare_last = reshape(PART2, true, None);
    assert_eq!(
        verdict_of(PART1, &bare_last, "first BLAKE2sp, last none"),
        Some(false)
    );
    assert_eq!(
        verdict_of(
            PART1,
            &flipped(&bare_last),
            "first BLAKE2sp, last none, a byte flipped"
        ),
        Some(false)
    );
    let with_crc = reshape(PART1, true, Some(crc32fast::hash(data_of(PART1))));
    assert_eq!(
        verdict_of(&with_crc, &bare_last, "first CRC32, last none"),
        Some(false)
    );
    assert_eq!(
        verdict_of(
            &with_crc,
            &flipped(&bare_last),
            "first CRC32, last none, a byte flipped"
        ),
        Some(false)
    );
}

/// The control: neither header names a checksum. The member is the
/// ordinary one without a checksum and has no verdict, as before.
#[test]
fn a_member_with_no_checksum_in_either_header_keeps_no_verdict() {
    let bare_first = reshape(PART1, true, None);
    let bare_last = reshape(PART2, true, None);
    assert_eq!(
        verdict_of(&bare_first, &bare_last, "first none, last none"),
        None
    );
}
