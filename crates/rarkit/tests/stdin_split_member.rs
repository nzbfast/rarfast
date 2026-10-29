//! A member added from standard input and split across volumes is read
//! (spec F 3.5.4 J5, the join check as restated on 10 Oct 2026).
//!
//! Genuine rar does not know such a member's length when it writes the
//! first volume: every fragment header but the last carries the RAR 5
//! unknown size flag (file flag 0x0008), and the LAST header alone carries
//! the member's size and its checksum. The join check compared the sizes
//! of the two headers whether or not both declared one, so the last
//! fragment was refused as `Corrupt(VolumeSet)` and every such set failed,
//! where the reference reads it.
//!
//! The sets are the specification's own, `specs/vectors-F/stdin-split`:
//! 12 written by genuine rar 7.23 for macOS from standard input
//! (`-sia.bin`, a member of 60,000 bytes: stored and compressed, in two,
//! three and four volumes, with `-htb`, `-p`, `-hp`, `-rr5`, `-s`, `-qo+`
//! and `-qo-`) and 3 controls of the same bytes added as a file. The size
//! arms below rewrite ONE file header of a set (a size field or the
//! unknown size flag, the header's size and CRC32 redone) and leave every
//! other byte alone. They are made on the two sets written with `-qo-`:
//! every other set carries a quick open record, whose copy of a header
//! the reference may read in the header's place. This reader takes the
//! header from the volume itself, and one compressed arm on a set that
//! has the record is kept to show it.
//!
//! WHAT THE REFERENCE DOES with the size arms (the specification's
//! `outcomes-7.23-macos-arm64.tsv`, the `si-noqo` and `file-noqo` rows):
//! the LAST header's size takes no part in its verdict (one less or one
//! more is still OK with the 60,000 true bytes), nor does a field under
//! the flag; a FIRST header that declares a size bounds the member (the
//! flag cleared and 59,999 written is 59,999 bytes and "checksum error").
//! CHOSEN, NOT COPIED: where the last header declares a size the bytes
//! delivered must equal it (fewer or more is a failed member), and two
//! headers that both declare a size must agree (the set is refused), as
//! the section requires.
//!
//! A MEMBER THAT IS NOT SPLIT. Genuine `rar a -si` with no `-v` goes back
//! and writes the true size: `stdin_split_member/one-volume-m3.rar` is one
//! (rar 7.23 for macOS, `-m3 -qo- -sinote.txt`, 3,504 bytes of text), its
//! flag clear, an ordinary member before the mend and after. With the
//! flag set on it by hand, which no genuine writer was seen to do, the
//! reference still tests it OK and writes the true bytes (rar and unrar
//! 7.23, 10 Oct 2026); the reader refused it `Corrupt(Header)` before any
//! decode. Since the same day it is read as the reference reads it,
//! decoded to the end of its packed stream and judged by its checksum.
//! Its one header declares no size, so no size is compared at its close.
//! The specification's own eight archives of that kind,
//! `specs/vectors-F/unsplit-unknown-size` (stored and compressed, as
//! written and with the flag set over a size field of 60,000, of 0 and of
//! 59,999, all written with `-qo-`), are read here too.
//!
//! Every read runs through `extract` at one worker and at four, verified
//! and written; the sets are under 70 KiB and the reads hold the
//! decoder's ordinary working memory for a 128 KiB to 1 MiB dictionary,
//! nothing sized by the test.

use std::path::PathBuf;
use std::sync::Arc;

use rarkit::{
    extract, Disposition, MemberInfo, MemberOutcome, Password, RangeSource, ReadOptions, Result,
    Sink,
};

fn vector(name: &str) -> Vec<u8> {
    let mut path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "..", ".."].iter().collect();
    path.extend(["specs", "vectors-F", "stdin-split"]);
    path.extend(name.split('/'));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The volumes of one kept set, in order.
fn set(name: &str, volumes: usize) -> Vec<Vec<u8>> {
    (1..=volumes)
        .map(|n| vector(&format!("{name}.part{n}.rar")))
        .collect()
}

/// Each kept set, how many volumes it has, and its password.
const SETS: [(&str, usize, Option<&str>); 15] = [
    ("si-m0-2", 2, None),
    ("si-m0-4", 4, None),
    ("si-m3-2", 2, None),
    ("si-m3-4", 4, None),
    ("si-m5-3", 3, None),
    ("si-htb", 2, None),
    ("si-p", 2, Some("pw")),
    ("si-hp", 2, Some("pw")),
    ("si-rr", 2, None),
    ("si-solid", 2, None),
    ("si-qo", 2, None),
    ("si-noqo", 2, None),
    ("file-m0-2", 2, None),
    ("file-noqo", 2, None),
    ("file-m3-2", 2, None),
];

// ---- reading back ----------------------------------------------------------

struct Keep {
    verify: bool,
    members: Vec<(String, Option<bool>, Vec<u8>)>,
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
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.members.push((
            String::from_utf8_lossy(member.name).into_owned(),
            outcome.checksum_ok,
            out.unwrap_or_default(),
        ));
        Ok(())
    }
}

/// What one read answered: how the operation ended, and `a.bin`'s verdict
/// and bytes (empty when verified).
#[derive(Debug, PartialEq, Eq)]
struct Seen {
    ended: Option<String>,
    a_bin: Option<(Option<bool>, Vec<u8>)>,
    others_good: bool,
}

fn read(volumes: &[Vec<u8>], password: Option<&str>, workers: usize, verify: bool) -> Seen {
    let sources: Vec<Arc<dyn RangeSource>> = volumes
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect();
    let mut sink = Keep {
        verify,
        members: Vec::new(),
    };
    let options = ReadOptions::default()
        .with_password(password.map(Password::from))
        .with_workers(Some(workers));
    let ended = extract(sources, &options, &mut sink, &mut ())
        .err()
        .map(|e| format!("{:?}", e.kind()));
    let others_good = sink
        .members
        .iter()
        .filter(|(name, _, _)| name != "a.bin")
        .all(|(_, ok, _)| *ok == Some(true));
    let a_bin = sink
        .members
        .into_iter()
        .find(|(name, _, _)| name == "a.bin")
        .map(|(_, ok, bytes)| (ok, bytes));
    Seen {
        ended,
        a_bin,
        others_good,
    }
}

/// One answer for the four arrangements, which must agree: how the
/// operation ended and `a.bin`'s verdict. A written member's bytes are
/// returned from the one-worker written read.
fn judged(
    volumes: &[Vec<u8>],
    password: Option<&str>,
    arm: &str,
) -> (Option<String>, Option<bool>, Vec<u8>) {
    let mut answers = Vec::new();
    let mut bytes = Vec::new();
    for workers in [1, 4] {
        for verify in [true, false] {
            let seen = read(volumes, password, workers, verify);
            let at = format!("{arm}, {workers} workers, verify {verify}");
            assert!(seen.others_good, "{at}: another member failed");
            let verdict = seen.a_bin.as_ref().and_then(|(ok, _)| *ok);
            if !verify && workers == 1 {
                bytes = seen.a_bin.map(|(_, b)| b).unwrap_or_default();
            }
            answers.push((seen.ended, verdict, at));
        }
    }
    let (ended, verdict, _) = answers[0].clone();
    for (e, v, at) in &answers {
        assert_eq!(
            (e, v),
            (&ended, &verdict),
            "{arm}: {at} parts from the rest"
        );
    }
    (ended, verdict, bytes)
}

// ---- rewriting one RAR 5 file header ----------------------------------------

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

/// The first file header (type 2) of a volume that is not encrypted at
/// the header level: where the block starts, where its header ends, where
/// its data ends, and the header's bytes from its type field on, cut at
/// the file flags and after the unpacked size.
struct Head {
    start: usize,
    end: usize,
    data_end: usize,
    /// Type, header flags, extra size and data size.
    lead: Vec<u8>,
    file_flags: u64,
    unpacked: u64,
    /// Attributes to the end of the header.
    tail: Vec<u8>,
}

fn head_of(volume: &[u8]) -> Head {
    let mut at = 8;
    loop {
        let start = at;
        let mut p = at + 4;
        let size = vint(volume, &mut p) as usize;
        let body = p;
        let end = p + size;
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
        if kind != 2 {
            at = end + data_size;
            continue;
        }
        let lead = volume[body..p].to_vec();
        let file_flags = vint(volume, &mut p);
        let unpacked = vint(volume, &mut p);
        return Head {
            start,
            end,
            data_end: end + data_size,
            lead,
            file_flags,
            unpacked,
            tail: volume[p..end].to_vec(),
        };
    }
}

/// `volume` with its file header's flags and unpacked size field set.
fn resized(volume: &[u8], file_flags: u64, unpacked: u64) -> Vec<u8> {
    let head = head_of(volume);
    let mut rest = head.lead.clone();
    put_vint(&mut rest, file_flags);
    put_vint(&mut rest, unpacked);
    rest.extend_from_slice(&head.tail);
    let mut body = Vec::new();
    put_vint(&mut body, rest.len() as u64);
    body.extend_from_slice(&rest);
    let mut out = volume[..head.start].to_vec();
    out.extend_from_slice(&crc32fast::hash(&body).to_le_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(&volume[head.end..]);
    out
}

/// `volume` with one bit of its fragment's middle byte inverted.
fn flipped(volume: &[u8]) -> Vec<u8> {
    let head = head_of(volume);
    let mut out = volume.to_vec();
    out[(head.end + head.data_end) / 2] ^= 0x01;
    out
}

const UNKNOWN_SIZE: u64 = 0x0008;

// ---- the arms ---------------------------------------------------------------

/// Every kept set reads whole: the member is good by the last header's
/// checksum and its 60,000 bytes are the ones fed to rar.
#[test]
fn every_genuine_set_reads_whole() {
    let fed = vector("in/a.bin");
    assert_eq!(fed.len(), 60_000);
    for (name, volumes, password) in SETS {
        let (ended, verdict, bytes) = judged(&set(name, volumes), password, name);
        assert_eq!(ended, None, "{name}");
        assert_eq!(verdict, Some(true), "{name}");
        assert!(bytes == fed, "{name}: the bytes delivered");
    }
}

/// The shape itself, read from the kept sets: the unknown size flag on
/// every leading header that can be read without a password, and a clear
/// flag with the true size on the last.
#[test]
fn the_leading_headers_declare_no_size_and_the_last_one_does() {
    for (name, volumes, _) in SETS {
        if name == "si-hp" || name == "si-solid" {
            continue;
        }
        let from_stdin = name.starts_with("si-");
        let vols = set(name, volumes);
        for (n, volume) in vols.iter().enumerate() {
            let head = head_of(volume);
            let last = n + 1 == vols.len();
            let flagged = head.file_flags & UNKNOWN_SIZE != 0;
            assert_eq!(flagged, from_stdin && !last, "{name} volume {n}");
            if !flagged {
                assert_eq!(head.unpacked, 60_000, "{name} volume {n}");
            }
        }
    }
}

/// The last header's checksum judges the whole member: one data bit
/// changed in the first volume or in the last fails it.
#[test]
fn a_changed_bit_fails_the_member() {
    for (name, volumes) in [("si-m0-2", 2), ("si-m0-4", 4), ("si-htb", 2)] {
        let whole = set(name, volumes);
        let mut first = whole.clone();
        first[0] = flipped(&first[0]);
        let (ended, verdict, _) = judged(&first, None, &format!("{name}, first volume"));
        assert_eq!((ended, verdict), (None, Some(false)), "{name}, first");
        let mut last = whole.clone();
        last[volumes - 1] = flipped(&last[volumes - 1]);
        let (ended, verdict, _) = judged(&last, None, &format!("{name}, last volume"));
        assert_eq!((ended, verdict), (None, Some(false)), "{name}, last");
    }
}

/// The member's size is the last header's: bytes delivered that are more
/// or fewer than it declares are a failed member, stored and compressed.
/// The reference calls all four OK (the module's note).
#[test]
fn the_last_headers_size_is_the_members() {
    for name in ["si-noqo", "si-m3-2"] {
        for declared in [59_999, 60_001] {
            let mut vols = set(name, 2);
            assert_eq!(head_of(&vols[1]).file_flags & UNKNOWN_SIZE, 0);
            vols[1] = resized(&vols[1], head_of(&vols[1]).file_flags, declared);
            let arm = format!("{name}, last header declares {declared}");
            let (ended, verdict, _) = judged(&vols, None, &arm);
            assert_eq!((ended, verdict), (None, Some(false)), "{arm}");
        }
    }
}

/// A flagged header declares no size, whatever its size field holds.
#[test]
fn a_size_field_under_the_flag_is_not_a_size() {
    let fed = vector("in/a.bin");
    let mut vols = set("si-noqo", 2);
    let flags = head_of(&vols[0]).file_flags;
    assert_ne!(flags & UNKNOWN_SIZE, 0);
    vols[0] = resized(&vols[0], flags, 59_999);
    let (ended, verdict, bytes) = judged(&vols, None, "field 59,999 under the flag");
    assert_eq!((ended, verdict), (None, Some(true)));
    assert!(bytes == fed);
}

/// Two headers that BOTH declare a size must still agree: the first
/// header's flag cleared and its field made the true size joins, and made
/// another size is the mismatched set it always was. The reference joins
/// both (the module's note).
#[test]
fn two_declared_sizes_must_still_agree() {
    let fed = vector("in/a.bin");
    let mut vols = set("si-noqo", 2);
    let flags = head_of(&vols[0]).file_flags & !UNKNOWN_SIZE;
    vols[0] = resized(&vols[0], flags, 60_000);
    let (ended, verdict, bytes) = judged(&vols, None, "first header declares 60,000");
    assert_eq!((ended, verdict), (None, Some(true)));
    assert!(bytes == fed);

    vols[0] = resized(&vols[0], flags, 59_999);
    let (ended, _, _) = judged(&vols, None, "first header declares 59,999");
    assert_eq!(ended.as_deref(), Some("Corrupt(VolumeSet)"));

    let mut control = set("file-noqo", 2);
    control[1] = resized(&control[1], head_of(&control[1]).file_flags, 59_999);
    let (ended, _, _) = judged(&control, None, "the control, last header declares 59,999");
    assert_eq!(ended.as_deref(), Some("Corrupt(VolumeSet)"));
}

// ---- a member that is not split ---------------------------------------------

const ONE_VOLUME: &[u8] = include_bytes!("stdin_split_member/one-volume-m3.rar");

/// The CRC32 of the 3,504 bytes fed to rar for `ONE_VOLUME`.
const NOTE_CRC: u32 = 0x0f11_82be;

/// The one member of a single archive, in the four arrangements, which
/// must agree: how the operation ended, its verdict, and the bytes of the
/// one-worker written read.
fn one_member(archive: &[u8], arm: &str) -> (Option<String>, Option<bool>, Vec<u8>) {
    let mut answers = Vec::new();
    let mut bytes = Vec::new();
    for workers in [1, 4] {
        for verify in [true, false] {
            let source: Arc<dyn RangeSource> = Arc::new(archive.to_vec());
            let mut sink = Keep {
                verify,
                members: Vec::new(),
            };
            let options = ReadOptions::default().with_workers(Some(workers));
            let ended = extract(vec![source], &options, &mut sink, &mut ())
                .err()
                .map(|e| format!("{:?}", e.kind()));
            let at = format!("{arm}, {workers} workers, verify {verify}");
            assert_eq!(sink.members.len(), 1, "{at}");
            let (_, verdict, out) = sink.members.remove(0);
            if !verify && workers == 1 {
                bytes = out;
            }
            answers.push((ended, verdict, at));
        }
    }
    let (ended, verdict, _) = answers[0].clone();
    for (e, v, at) in &answers {
        assert_eq!(
            (e, v),
            (&ended, &verdict),
            "{arm}: {at} parts from the rest"
        );
    }
    (ended, verdict, bytes)
}

/// What genuine rar writes from standard input into ONE volume: the true
/// size and no flag. It reads as any member does.
#[test]
fn a_genuine_one_volume_member_from_standard_input_reads() {
    let head = head_of(ONE_VOLUME);
    assert_eq!(head.file_flags & UNKNOWN_SIZE, 0, "the flag is clear");
    assert_eq!(head.unpacked, 3504);
    let (ended, verdict, bytes) = one_member(ONE_VOLUME, "genuine");
    assert_eq!((ended, verdict), (None, Some(true)));
    assert_eq!(bytes.len(), 3504);
    assert_eq!(crc32fast::hash(&bytes), NOTE_CRC);
}

/// The same member with the unknown size flag set by hand: compressed,
/// not split, and of no declared size. It is decoded to the end of its
/// packed stream and judged by its checksum, as the reference reads it;
/// with one packed bit changed it fails.
#[test]
fn a_compressed_member_of_unknown_size_that_is_not_split_reads() {
    let head = head_of(ONE_VOLUME);
    let flagged = resized(ONE_VOLUME, head.file_flags | UNKNOWN_SIZE, head.unpacked);
    assert_ne!(head_of(&flagged).file_flags & UNKNOWN_SIZE, 0);
    let (ended, verdict, bytes) = one_member(&flagged, "the flag set");
    assert_eq!((ended, verdict), (None, Some(true)));
    assert_eq!(bytes.len(), 3504);
    assert_eq!(crc32fast::hash(&bytes), NOTE_CRC);

    let (_, verdict, _) = one_member(&flipped(&flagged), "the flag set, a bit changed");
    assert_eq!(verdict, Some(false));
}

/// The specification's eight archives of an unsplit member (3.2.6): two
/// as genuine rar wrote them from standard input, and each with the flag
/// set over a size field of the true size, of 0 and of 59,999. Every one
/// reads whole, since a field under the flag is not a size; with one data
/// bit changed every one fails.
#[test]
fn the_kept_unsplit_archives_read_whatever_stands_under_the_flag() {
    let kept = |name: &str| {
        let mut path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "..", ".."].iter().collect();
        path.extend(["specs", "vectors-F", "unsplit-unknown-size"]);
        path.extend(name.split('/'));
        std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    };
    let fed = kept("in/a.bin");
    assert_eq!(fed.len(), 60_000);
    for method in ["si-m0", "si-m3"] {
        for (arm, flagged) in [
            ("", false),
            (".flag", true),
            (".flag-zero", true),
            (".flag-less", true),
        ] {
            let name = format!("{method}{arm}.rar");
            let archive = kept(&name);
            assert_eq!(
                head_of(&archive).file_flags & UNKNOWN_SIZE != 0,
                flagged,
                "{name}"
            );
            let (ended, verdict, bytes) = one_member(&archive, &name);
            assert_eq!((ended, verdict), (None, Some(true)), "{name}");
            assert!(bytes == fed, "{name}: the bytes delivered");
            let (_, verdict, _) = one_member(&flipped(&archive), &format!("{name}, a bit changed"));
            assert_eq!(verdict, Some(false), "{name}, a bit changed");
        }
    }
}
