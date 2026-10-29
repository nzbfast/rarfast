//! A member added from standard input and split across volumes, in the
//! OLDER container (the RAR 4 form), is read.
//!
//! `stdin_split_member_rar4/` holds two sets written by genuine rar for
//! x86-64 Linux, versions 5.50 and 6.24, with `-ma4 -m0 -v1000b -si`: one
//! stored member, `stream.bin`, of 1,500 random bytes, in two volumes of
//! 1,000 and 680 bytes. (rar 7.23 writes no archive of the older
//! container, so the RAR 5 sets of `tests/stdin_split_member.rs` have no
//! twin made by it.)
//!
//! WHAT THE REFERENCE DOES (unrar 7.23, aarch64 macOS, 11 Oct 2026), the
//! same for both sets: `t` marks the member OK, "All OK", exit 0; `x`
//! exits 0 and `p` prints 1,500 bytes whose SHA-256 is the one below. Its
//! technical listing shows `Size: ?` and a `Pack-CRC32` for the member in
//! the first volume, and `Size: 1500` with `CRC32: 03601626` in the last.
//!
//! THE RULE (spec F 3.5.4 J6): a file header of the older container
//! declares NO size when its unpacked size is all ones: with the flag
//! that brings the two high halves (0x0100), the low field and the high
//! field both `FFFFFFFF`, which is what these writers wrote in the
//! leading header; without that flag, the low field `FFFFFFFF`. Every
//! other value is a declared size. A header that declares none is joined
//! to the next fragment whatever that one declares; the member's size and
//! checksum are the last header's, and the bytes delivered are judged
//! against that size at the close.
//!
//! The arms below rewrite ONE file header of the rar 6.24 set (a size
//! field, or the flag with its two fields, the header's CRC redone) and
//! leave every other byte alone; the older container has no quick open
//! record. WHERE THE READER PARTS FROM THE REFERENCE, by the section's own
//! rules and not by accident (the specification's
//! `vectors-F/stdin-split-ma4` tables hold the reference's answers): two
//! headers that both declare a size must agree, so a first header that
//! declares 1,499, a high half of 1 over low all ones, or one of the two
//! values the reference lists as negative is a refused set here (the
//! reference cuts the member at 1,499, reads the second, and fails the
//! last two as a checksum error with no byte written); and the last
//! header's size is judged, so 1,499 or 1,501 there is a failed member
//! here (the reference calls both OK). ONE DECLARED SIZE IS READ AS THE
//! REFERENCE READS IT: low all ones over a high half of 0, the size
//! 4,294,967,295, in a leading header.
//!
//! MORE THAN TWO VOLUMES, AND A COMPRESSED MEMBER (sets of the same bench
//! samples, added 11 Oct 2026, each read by unrar 7.23 with the bytes that
//! were fed to rar): `rar-5.50-stored-3vol` (2,500 random bytes, `-m0
//! -v1000b`), whose MIDDLE volume's header declares no size either;
//! `rar-5.50-m3-text-v60k` and `rar-6.24-m5-text-v60k` (1,000,000 bytes of
//! text, `-m3` and `-m5`, `-v60k`, three volumes, unpack version 29): a
//! COMPRESSED member, decoded to the end mark of its stream with no size
//! to stop at. Before the mend each ended `Corrupt(VolumeSet)` (the tool:
//! exit 2 on all three, measured). And two that are NOT split,
//! `rar-5.50-unsplit-stored` and `rar-6.24-unsplit-m3-text`: there the
//! writer went back and wrote the true size, an ordinary member, read
//! before the mend and after.
//!
//! Every read runs through `extract` at one worker and at four, verified
//! and written; the largest set is 170 KiB and its reads hold the unpack
//! version 29 decoder's ordinary working memory for a 4 MiB dictionary,
//! nothing sized by the test.

use std::sync::Arc;

use rarkit::{
    extract, Disposition, MemberInfo, MemberOutcome, RangeSource, ReadOptions, Result, Sink,
};
use sha2::{Digest, Sha256};

const RAR_550: [&[u8]; 2] = [
    include_bytes!("stdin_split_member_rar4/rar-5.50.part1.rar"),
    include_bytes!("stdin_split_member_rar4/rar-5.50.part2.rar"),
];
const RAR_624: [&[u8]; 2] = [
    include_bytes!("stdin_split_member_rar4/rar-6.24.part1.rar"),
    include_bytes!("stdin_split_member_rar4/rar-6.24.part2.rar"),
];

/// The SHA-256 of the 1,500 bytes `unrar p` prints for either set.
const MEMBER_SHA256: &str = "001552d34f0475edb2b194b6308e72bbb5ce31e7a2bef43c872091c7d19dcc59";

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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The set read in the four arrangements: each ends without an error,
/// delivers the one member `stream.bin` as good, and a written read
/// delivers the bytes the reference prints.
fn reads_as_the_reference_reads_it(set: &[&[u8]], writer: &str, size: usize, sha256: &str) {
    for workers in [1, 4] {
        for verify in [true, false] {
            let sources: Vec<Arc<dyn RangeSource>> = set
                .iter()
                .map(|v| Arc::new(v.to_vec()) as Arc<dyn RangeSource>)
                .collect();
            let mut sink = Keep {
                verify,
                members: Vec::new(),
            };
            let options = ReadOptions::default().with_workers(Some(workers));
            let ended = extract(sources, &options, &mut sink, &mut ())
                .err()
                .map(|e| format!("{:?}", e.kind()));
            let at = format!("{writer}, {workers} workers, verify {verify}");
            assert_eq!(ended, None, "{at}");
            assert_eq!(sink.members.len(), 1, "{at}");
            let (name, verdict, bytes) = &sink.members[0];
            assert_eq!(name, "stream.bin", "{at}");
            assert_eq!(*verdict, Some(true), "{at}");
            if !verify {
                assert_eq!(bytes.len(), size, "{at}");
                assert_eq!(hex(&Sha256::digest(bytes)), sha256, "{at}");
            }
        }
    }
}

/// How one read of a set ended, the member's verdict, and its bytes when
/// written: the four arrangements, which must agree.
fn judged(set: &[Vec<u8>], arm: &str) -> (Option<String>, Option<bool>, Vec<u8>) {
    let mut answers = Vec::new();
    let mut bytes = Vec::new();
    for workers in [1, 4] {
        for verify in [true, false] {
            let sources: Vec<Arc<dyn RangeSource>> = set
                .iter()
                .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
                .collect();
            let mut sink = Keep {
                verify,
                members: Vec::new(),
            };
            let options = ReadOptions::default().with_workers(Some(workers));
            let ended = extract(sources, &options, &mut sink, &mut ())
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

// ---- rewriting one file header of the older container -----------------------

/// The flag that brings the two high size halves.
const HIGH_HALVES: u16 = 0x0100;

/// Where the volume's file block (type 0x74) starts, and its header's
/// size. A block is CRC16, type, flags, size; a file block's data follows
/// its header.
fn file_block(volume: &[u8]) -> (usize, usize) {
    assert_eq!(&volume[..7], b"Rar!\x1a\x07\x00", "the older signature");
    let mut at = 7;
    loop {
        let size = usize::from(u16::from_le_bytes([volume[at + 5], volume[at + 6]]));
        if volume[at + 2] == 0x74 {
            return (at, size);
        }
        at += size;
    }
}

fn flags_of(volume: &[u8]) -> u16 {
    let (at, _) = file_block(volume);
    u16::from_le_bytes([volume[at + 3], volume[at + 4]])
}

/// The header's CRC16, the low half of the CRC32 of the header from its
/// type byte on, made right again.
fn reseal(volume: &mut [u8]) {
    let (at, size) = file_block(volume);
    let crc = crc32fast::hash(&volume[at + 2..at + size]) as u16;
    volume[at..at + 2].copy_from_slice(&crc.to_le_bytes());
}

/// `volume` with its file header's unpacked size made `low` and `high`,
/// the high halves being present.
fn sized(volume: &[u8], low: u32, high: u32) -> Vec<u8> {
    let mut out = volume.to_vec();
    assert_ne!(flags_of(&out) & HIGH_HALVES, 0, "the high halves are there");
    let (at, _) = file_block(&out);
    out[at + 11..at + 15].copy_from_slice(&low.to_le_bytes());
    out[at + 36..at + 40].copy_from_slice(&high.to_le_bytes());
    reseal(&mut out);
    out
}

/// `volume` with the flag cleared and the two high halves taken out of
/// its file header, and its low unpacked size made `low`.
fn without_high_halves(volume: &[u8], low: u32) -> Vec<u8> {
    let (at, size) = file_block(volume);
    let mut out = volume[..at + 32].to_vec();
    out.extend_from_slice(&volume[at + 40..]);
    let flags = flags_of(volume) & !HIGH_HALVES;
    out[at + 3..at + 5].copy_from_slice(&flags.to_le_bytes());
    out[at + 5..at + 7].copy_from_slice(&((size - 8) as u16).to_le_bytes());
    out[at + 11..at + 15].copy_from_slice(&low.to_le_bytes());
    reseal(&mut out);
    out
}

/// `volume` with one bit of its fragment's middle byte inverted.
fn flipped(volume: &[u8]) -> Vec<u8> {
    let (at, size) = file_block(volume);
    let packed = u32::from_le_bytes(volume[at + 7..at + 11].try_into().unwrap()) as usize;
    let mut out = volume.to_vec();
    out[at + size + packed / 2] ^= 0x01;
    out
}

fn rar_624() -> Vec<Vec<u8>> {
    RAR_624.iter().map(|v| v.to_vec()).collect()
}

const GOOD: (Option<String>, Option<bool>) = (None, Some(true));
const FAILED: (Option<String>, Option<bool>) = (None, Some(false));

/// The set is refused as mismatched in every arrangement: the operation
/// ends `Corrupt(VolumeSet)` and no member is closed as good.
fn refused(set: &[Vec<u8>], arm: &str) {
    for workers in [1, 4] {
        for verify in [true, false] {
            let sources: Vec<Arc<dyn RangeSource>> = set
                .iter()
                .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
                .collect();
            let mut sink = Keep {
                verify,
                members: Vec::new(),
            };
            let options = ReadOptions::default().with_workers(Some(workers));
            let ended = extract(sources, &options, &mut sink, &mut ())
                .err()
                .map(|e| format!("{:?}", e.kind()));
            let at = format!("{arm}, {workers} workers, verify {verify}");
            assert_eq!(ended.as_deref(), Some("Corrupt(VolumeSet)"), "{at}");
            assert!(
                sink.members.iter().all(|(_, ok, _)| *ok != Some(true)),
                "{at}: a member of a refused set closed as good"
            );
        }
    }
}

// ---- the arms ---------------------------------------------------------------

/// The shape as the two writers left it: all ones in both halves of the
/// leading header's size under the flag, and the true size in the last.
#[test]
fn the_leading_header_holds_all_ones_and_the_last_the_size() {
    for set in [RAR_550, RAR_624] {
        for (n, want) in [(0usize, (u32::MAX, u32::MAX)), (1, (1500, 0))] {
            let volume = set[n];
            let (at, _) = file_block(volume);
            assert_ne!(flags_of(volume) & HIGH_HALVES, 0);
            let low = u32::from_le_bytes(volume[at + 11..at + 15].try_into().unwrap());
            let high = u32::from_le_bytes(volume[at + 36..at + 40].try_into().unwrap());
            assert_eq!((low, high), want, "volume {n}");
        }
    }
}

/// The last header's CRC32 judges the whole member: one data bit changed
/// in either volume fails it.
#[test]
fn a_changed_bit_fails_the_member() {
    for n in [0, 1] {
        let mut set = rar_624();
        set[n] = flipped(&set[n]);
        let (ended, verdict, _) = judged(&set, &format!("a bit changed in volume {n}"));
        assert_eq!((ended, verdict), FAILED, "volume {n}");
    }
}

/// Without the flag, a low field of all ones declares no size either.
#[test]
fn all_ones_in_the_low_field_alone_declares_no_size() {
    let mut set = rar_624();
    set[0] = without_high_halves(&set[0], u32::MAX);
    assert_eq!(flags_of(&set[0]) & HIGH_HALVES, 0);
    let (ended, verdict, bytes) = judged(&set, "no high halves, low all ones");
    assert_eq!((ended, verdict), GOOD);
    assert_eq!(hex(&Sha256::digest(&bytes)), MEMBER_SHA256);
}

/// Low all ones over a high half of 0 is a size, 4,294,967,295, and the
/// set is READ, as the reference reads it (since 11 Oct 2026): a leading
/// header of the older container whose LOW field is all ones is joined
/// to the next fragment whatever stands in its high half's place, and
/// the member is judged by the last header's size and CRC32. The stored
/// set and the compressed one alike.
#[test]
fn low_all_ones_over_a_high_half_of_zero_reads() {
    let mut set = rar_624();
    set[0] = sized(&set[0], u32::MAX, 0);
    let (ended, verdict, bytes) = judged(&set, "stored, low all ones, high 0");
    assert_eq!((ended, verdict), GOOD);
    assert_eq!(hex(&Sha256::digest(&bytes)), MEMBER_SHA256);

    let mut set: Vec<Vec<u8>> = PACKED_M3.iter().map(|v| v.to_vec()).collect();
    set[0] = sized(&set[0], u32::MAX, 0);
    set[1] = sized(&set[1], u32::MAX, 0);
    let (ended, verdict, bytes) = judged(&set, "-m3, low all ones, high 0, both leading headers");
    assert_eq!((ended, verdict), GOOD);
    assert_eq!(hex(&Sha256::digest(&bytes)), TEXT_1M);
}

/// Every other value of the two fields IS a size that a later header
/// must agree with: a high half of 1 over low all ones, the two values
/// the reference lists as negative, and 1,499.
#[test]
fn any_other_value_is_a_declared_size() {
    for (low, high, arm) in [
        (u32::MAX, 1, "low all ones, high 1"),
        (0, u32::MAX, "low 0, high all ones"),
        (u32::MAX - 1, u32::MAX, "low FFFFFFFE, high all ones"),
        (1499, 0, "the first header declares 1,499"),
    ] {
        let mut set = rar_624();
        set[0] = sized(&set[0], low, high);
        refused(&set, arm);
    }
    let mut set = rar_624();
    set[0] = without_high_halves(&set[0], 1499);
    refused(&set, "no high halves, low 1,499");

    let mut set = rar_624();
    set[0] = sized(&set[0], 1500, 0);
    let (ended, verdict, bytes) = judged(&set, "the first header declares 1,500");
    assert_eq!((ended, verdict), GOOD);
    assert_eq!(hex(&Sha256::digest(&bytes)), MEMBER_SHA256);
}

/// The member's size is the last header's: bytes delivered that are more
/// or fewer than it declares are a failed member. A last header that
/// declares none either leaves a member of no declared size, judged by
/// its checksum alone.
#[test]
fn the_last_headers_size_is_the_members() {
    for declared in [1499, 1501] {
        let mut set = rar_624();
        set[1] = sized(&set[1], declared, 0);
        let arm = format!("the last header declares {declared}");
        let (ended, verdict, _) = judged(&set, &arm);
        assert_eq!((ended, verdict), FAILED, "{arm}");
    }
    let mut set = rar_624();
    set[1] = sized(&set[1], u32::MAX, u32::MAX);
    let (ended, verdict, bytes) = judged(&set, "the last header declares none");
    assert_eq!((ended, verdict), GOOD);
    assert_eq!(hex(&Sha256::digest(&bytes)), MEMBER_SHA256);
}

#[test]
fn a_set_written_by_rar_5_50_reads() {
    reads_as_the_reference_reads_it(&RAR_550, "rar 5.50", 1500, MEMBER_SHA256);
}

#[test]
fn a_set_written_by_rar_6_24_reads() {
    reads_as_the_reference_reads_it(&RAR_624, "rar 6.24", 1500, MEMBER_SHA256);
}

// ---- more volumes, a compressed member, and members that are not split ------

const STORED_3: [&[u8]; 3] = [
    include_bytes!("stdin_split_member_rar4/rar-5.50-stored-3vol.part1.rar"),
    include_bytes!("stdin_split_member_rar4/rar-5.50-stored-3vol.part2.rar"),
    include_bytes!("stdin_split_member_rar4/rar-5.50-stored-3vol.part3.rar"),
];
const PACKED_M3: [&[u8]; 3] = [
    include_bytes!("stdin_split_member_rar4/rar-5.50-m3-text-v60k.part1.rar"),
    include_bytes!("stdin_split_member_rar4/rar-5.50-m3-text-v60k.part2.rar"),
    include_bytes!("stdin_split_member_rar4/rar-5.50-m3-text-v60k.part3.rar"),
];
const PACKED_M5: [&[u8]; 3] = [
    include_bytes!("stdin_split_member_rar4/rar-6.24-m5-text-v60k.part1.rar"),
    include_bytes!("stdin_split_member_rar4/rar-6.24-m5-text-v60k.part2.rar"),
    include_bytes!("stdin_split_member_rar4/rar-6.24-m5-text-v60k.part3.rar"),
];
const UNSPLIT_STORED: &[u8] = include_bytes!("stdin_split_member_rar4/rar-5.50-unsplit-stored.rar");
const UNSPLIT_M3: &[u8] = include_bytes!("stdin_split_member_rar4/rar-6.24-unsplit-m3-text.rar");

/// The SHA-256 of what was fed to rar for each: 2,500 random bytes,
/// 1,000,000 bytes of text, and 100,000 bytes of text.
const RAND_2500: &str = "10802f14985532f918380d02107fe8b61663fb3b38e9d8218255aaaa62fec510";
const TEXT_1M: &str = "2a428021d6c12a8afb832ebd3fb3ed58790712a6a79e89f239cfe3598721e111";
const TEXT_100K: &str = "5afcb7be030f029c1bdd8ea697a9c380b483ec707fa8ee823cb66d66532843e7";

/// The unpacked size a volume's file header holds, as (low, high), and
/// its unpack version and method bytes.
fn header_facts(volume: &[u8]) -> ((u32, u32), u8, u8) {
    let (at, _) = file_block(volume);
    assert_ne!(flags_of(volume) & HIGH_HALVES, 0);
    let low = u32::from_le_bytes(volume[at + 11..at + 15].try_into().unwrap());
    let high = u32::from_le_bytes(volume[at + 36..at + 40].try_into().unwrap());
    ((low, high), volume[at + 24], volume[at + 25])
}

/// Every leading header of a three-volume set declares no size, the
/// middle one too, and the last has the member's.
fn three_volume_shape(set: &[&[u8]; 3], size: u32, version: u8, method: u8) {
    for (n, volume) in set.iter().enumerate() {
        let (halves, v, m) = header_facts(volume);
        let want = if n < 2 {
            (u32::MAX, u32::MAX)
        } else {
            (size, 0)
        };
        assert_eq!(halves, want, "volume {n}");
        assert_eq!((v, m), (version, method), "volume {n}");
    }
}

#[test]
fn a_stored_member_in_three_volumes_reads() {
    three_volume_shape(&STORED_3, 2500, 20, 0x30);
    reads_as_the_reference_reads_it(&STORED_3, "rar 5.50, stored, 3 volumes", 2500, RAND_2500);
}

#[test]
fn a_compressed_member_in_three_volumes_reads() {
    three_volume_shape(&PACKED_M3, 1_000_000, 29, 0x33);
    reads_as_the_reference_reads_it(&PACKED_M3, "rar 5.50, -m3, 3 volumes", 1_000_000, TEXT_1M);
    three_volume_shape(&PACKED_M5, 1_000_000, 29, 0x35);
    reads_as_the_reference_reads_it(&PACKED_M5, "rar 6.24, -m5, 3 volumes", 1_000_000, TEXT_1M);
}

/// A compressed member of no size is still judged: one packed bit changed
/// in its middle volume fails it.
#[test]
fn a_changed_bit_fails_the_compressed_member() {
    let mut set: Vec<Vec<u8>> = PACKED_M3.iter().map(|v| v.to_vec()).collect();
    set[1] = flipped(&set[1]);
    let (_, verdict, _) = judged(&set, "-m3, a bit changed in the middle volume");
    assert_eq!(verdict, Some(false));
}

/// Not split: the writer wrote the true size, and the member is an
/// ordinary one, read before the mend and after.
#[test]
fn a_member_from_standard_input_that_is_not_split_reads() {
    assert_eq!(header_facts(UNSPLIT_STORED).0, (1500, 0));
    reads_as_the_reference_reads_it(
        &[UNSPLIT_STORED],
        "rar 5.50, not split, stored",
        1500,
        MEMBER_SHA256,
    );
    assert_eq!(header_facts(UNSPLIT_M3).0, (100_000, 0));
    reads_as_the_reference_reads_it(
        &[UNSPLIT_M3],
        "rar 6.24, not split, -m3",
        100_000,
        TEXT_100K,
    );
}
