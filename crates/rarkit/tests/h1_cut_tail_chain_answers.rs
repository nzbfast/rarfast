//! Every member rarkit calls GOOD in a solid chain behind a cut member is
//! one the genuine programs wrote with its true bytes: the 249 arms of
//! `specs/vectors-H/h1-cut-tail-chain` (SPEC-H1 3.8, "A cut member and
//! the members after it").
//!
//! The arms are not kept, so each is made here the way the answers'
//! README says: from a tracked genuine archive
//! (`fixtures/legacy/archives`), one compressed member loses the last n
//! bytes of its packed data, its packed size field is lowered by n and
//! its header's checksum redone. `cases.tsv` holds each arm's SHA-256 and
//! every arm made here is held to it, so the test reads the very archives
//! the answers were taken from.
//!
//! The answers (rar 7.23 and unrar 7.23, the same on every arm) give one
//! mark a file member in archive order: `=` true bytes written, `<` a
//! true prefix, `!` other bytes, `.` no file. The rule held here, one
//! way only: a member whose checksum rarkit reports good carries its true
//! bytes, and the answers mark it `=`. A member the answers mark `=` and
//! rarkit does not call good is not this test's business.
//!
//! One CHOSEN DIFFERENCE is named in [`CHOSEN`] (bug sweep item 58,
//! SPEC-H1 3.8, first seen on `IA64.BIN`): a member behind a cut member
//! that rarkit passes by its own checksum with its true bytes where the
//! genuine programs write other bytes. Its 32 rows are pinned; any other
//! disagreement, and any row that stops differing, fails with its arm.
//!
//! Read at the default width and at one worker, under the default memory
//! policy; no archive is over 68 KiB.

use std::collections::BTreeSet;
use std::sync::Arc;

use rarkit::{extract, Disposition, MemberInfo, MemberOutcome, RangeSource, ReadOptions, Sink};
use sha2::{Digest, Sha256};

fn file(dir: &str, name: &str) -> Vec<u8> {
    let path = format!("{}/../../{dir}/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn answers(name: &str) -> String {
    String::from_utf8(file("specs/vectors-H/h1-cut-tail-chain", name)).expect("text")
}

/// The arms where rarkit calls a member good and the answers do not, as
/// (archive, the member cut, bytes cut, the member called good): 32 over
/// 25 arms, every one a member BEHIND the cut member that rarkit delivers
/// with its true bytes under its own checksum where the genuine programs
/// wrote other bytes (a true prefix, once). All 32 are the chosen
/// difference of item 58 (9 Oct 2026): the reference is not copied into
/// wrong bytes. The set is pinned whole, so a row gained or lost fails.
const CHOSEN: &[(&str, &str, usize, &str)] = &[
    ("r393_solid", "DATA.BIN", 2, "TABLE.BIN"),
    ("r393_solid", "DATA.BIN", 3, "TABLE.BIN"),
    ("r393_solid", "TABLE.BIN", 1, "AUDIO.RAW"),
    ("r393_solid", "TABLE.BIN", 2, "AUDIO.RAW"),
    ("r393_solid", "TABLE.BIN", 3, "AUDIO.RAW"),
    ("r393_solid", "TABLE.BIN", 4, "AUDIO.RAW"),
    ("r393_solid", "TABLE.BIN", 6, "AUDIO.RAW"),
    ("r393_solid", "TABLE.BIN", 8, "AUDIO.RAW"),
    ("r393_solid", "TABLE.BIN", 16, "AUDIO.RAW"),
    ("r420_f_mixed", "DELTA.BIN", 2, "X86.BIN"),
    ("r420_f_mixed", "DELTA.BIN", 250, "IA64.BIN"),
    ("r420_f_mixed", "DELTA.BIN", 1000, "IA64.BIN"),
    ("r420_f_mixed", "IA64.BIN", 2, "X86.BIN"),
    ("r420_f_mixed", "IMAGE.BMP", 8, "PCM.RAW"),
    ("r420_f_mixed", "IMAGE.BMP", 8, "RGB.RAW"),
    ("r420_f_mixed", "IMAGE.BMP", 8, "SOUND.WAV"),
    ("r420_f_mixed", "PCM.RAW", 1, "SOUND.WAV"),
    ("r420_f_mixed", "RGB.RAW", 1, "SOUND.WAV"),
    ("r420_f_mixed", "RGB.RAW", 2, "SOUND.WAV"),
    ("r420_solid", "BIG.TXT", 1, "HELLO.TXT"),
    ("r420_solid", "BIG.TXT", 1, "SUB/NESTED/DEEP.TXT"),
    ("r420_solid", "BIG.TXT", 1, "SUB/SIB.TXT"),
    ("r420_solid", "BIG.TXT", 2, "HELLO.TXT"),
    ("r420_solid", "BIG.TXT", 2, "SUB/NESTED/DEEP.TXT"),
    ("r420_solid", "BIG.TXT", 2, "SUB/SIB.TXT"),
    ("r420_solid", "DATA.BIN", 2, "TABLE.BIN"),
    ("r420_solid", "DATA.BIN", 3, "TABLE.BIN"),
    ("r420_solid", "HELLO.TXT", 1, "SUB/SIB.TXT"),
    ("r420_solid", "HELLO.TXT", 2, "SUB/SIB.TXT"),
    ("r420_solid", "ONE.DAT", 1, "AUDIO.RAW"),
    ("r420_solid", "SUB\\NESTED\\DEEP.TXT", 1, "HELLO.TXT"),
    ("r420_solid", "SUB\\NESTED\\DEEP.TXT", 1, "SUB/SIB.TXT"),
];

fn crc32(bytes: &[u8]) -> u32 {
    !bytes.iter().fold(!0u32, |mut crc, &byte| {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (crc & 1).wrapping_neg());
        }
        crc
    })
}

fn le16(bytes: &[u8], at: usize) -> usize {
    usize::from(u16::from_le_bytes([bytes[at], bytes[at + 1]]))
}

fn le32(bytes: &[u8], at: usize) -> usize {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes")) as usize
}

/// `archive`, of the RAR 1.5 to 4.x container, with the last `n` bytes
/// taken out of the packed data of the file member named `member`, its
/// packed size lowered by `n` and its header's checksum redone (SPEC-F
/// 3.3.1 and 3.3.5). `None` when the member is stored or packs to `n`
/// bytes or fewer: the probe makes no such arm.
fn cut(archive: &[u8], member: &[u8], n: usize) -> Option<Vec<u8>> {
    let mut at = 7;
    while at < archive.len() {
        let kind = archive[at + 2];
        let flags = le16(archive, at + 3);
        let size = le16(archive, at + 5);
        let more = if kind == 0x74 || flags & 0x8000 != 0 {
            le32(archive, at + 7)
        } else {
            0
        };
        if kind == 0x74 {
            let name_at = at + 32 + if flags & 0x0100 != 0 { 8 } else { 0 };
            let name = &archive[name_at..name_at + le16(archive, at + 26)];
            // A name with a Unicode form keeps its plain form in front of
            // a zero byte.
            let plain = name.split(|&b| b == 0).next().expect("a name");
            if plain == member {
                let stored = archive[at + 25] == 0x30;
                if stored || more <= n {
                    return None;
                }
                let mut out = archive[..at + size + more - n].to_vec();
                out.extend_from_slice(&archive[at + size + more..]);
                out[at + 7..at + 11].copy_from_slice(&((more - n) as u32).to_le_bytes());
                let sum = crc32(&out[at + 2..at + size]) as u16;
                out[at..at + 2].copy_from_slice(&sum.to_le_bytes());
                return Some(out);
            }
        }
        at += size + more;
    }
    panic!("no member {}", String::from_utf8_lossy(member));
}

/// One file member as the sink was told of it at its close.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Came {
    name: String,
    data: Vec<u8>,
    good: bool,
}

#[derive(Default)]
struct Keep(Vec<Came>);

impl Sink for Keep {
    type Out = Vec<u8>;

    fn open(&mut self, member: &MemberInfo<'_>) -> rarkit::Result<Disposition<Vec<u8>>> {
        Ok(if member.is_directory {
            Disposition::Skip
        } else {
            Disposition::Write(Vec::new())
        })
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> rarkit::Result<()> {
        if !member.is_directory {
            self.0.push(Came {
                name: member.name_lossy().into_owned(),
                data: out.unwrap_or_default(),
                good: outcome.checksum_ok == Some(true),
            });
        }
        Ok(())
    }
}

/// The file members of `bytes` as far as the read went, in order. The
/// read's own error is not this test's business.
fn read(bytes: &[u8], workers: Option<usize>) -> Vec<Came> {
    let source: Vec<Arc<dyn RangeSource>> = vec![Arc::new(bytes.to_vec())];
    let mut sink = Keep::default();
    let _ = extract(
        source,
        &ReadOptions::default().with_workers(workers),
        &mut sink,
        &mut (),
    );
    sink.0
}

#[test]
fn a_member_rarkit_calls_good_behind_a_cut_member_is_good_in_the_answers() {
    let unrar = answers("outcomes-unrar-7.23-macos-arm64.tsv");
    let rar = answers("outcomes-rar-7.23-macos-arm64.tsv");
    let cases = answers("cases.tsv");
    let sha_of = |name: &str| -> &str {
        cases
            .lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix('\t'))
            .unwrap_or_else(|| panic!("{name} is not in cases.tsv"))
    };

    let mut arms = 0;
    let mut differences = BTreeSet::new();
    for (line, other) in unrar.lines().zip(rar.lines()).skip(1) {
        let cells: Vec<&str> = line.split('\t').collect();
        assert_eq!(
            cells[1..],
            other.split('\t').collect::<Vec<_>>()[1..],
            "rar and unrar answer alike"
        );
        let (archive, member, marks) = (cells[1], cells[2], cells[6]);
        let n: usize = cells[3].parse().expect("the bytes cut");
        let arm = format!("{archive}, {member} cut by {n}");
        arms += 1;

        let sound = file("fixtures/legacy/archives", &format!("{archive}.rar"));
        let truth = read(&sound, Some(1));
        assert!(truth.iter().all(|m| m.good), "{archive}.rar is sound");
        let made = cut(&sound, member.as_bytes(), n).unwrap_or_else(|| panic!("{arm}: no arm"));
        let kept = format!("{archive}.{}.cut-{n}.rar", member.replace('\\', "_"));
        let sha: String = Sha256::digest(&made)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(sha, sha_of(&kept), "{arm}: not the arm the answers saw");

        // One mark a file member, the cut member's in brackets.
        let marks: Vec<char> = marks.chars().filter(|c| !"[]".contains(*c)).collect();
        assert_eq!(marks.len(), truth.len(), "{arm}: a mark a file member");
        for workers in [None, Some(1)] {
            for came in read(&made, workers) {
                let index = truth
                    .iter()
                    .position(|m| m.name == came.name)
                    .unwrap_or_else(|| panic!("{arm}: a member {} came", came.name));
                if !came.good {
                    continue;
                }
                // What rarkit calls good is the member's true bytes, on
                // every arm and with no exception.
                assert_eq!(
                    came.data, truth[index].data,
                    "{arm}, workers {workers:?}: {} is called good with other bytes",
                    came.name
                );
                if marks[index] != '=' {
                    differences.insert((
                        archive.to_owned(),
                        member.to_owned(),
                        n,
                        came.name.clone(),
                        marks[index],
                    ));
                }
            }
        }
    }
    assert_eq!(arms, 249, "the arms of the answers");

    let chosen: BTreeSet<_> = CHOSEN
        .iter()
        .map(|&(archive, member, n, good)| {
            (archive.to_owned(), member.to_owned(), n, good.to_owned())
        })
        .collect();
    let found: BTreeSet<_> = differences
        .iter()
        .map(|(archive, member, n, good, _)| (archive.clone(), member.clone(), *n, good.clone()))
        .collect();
    // 32 pairs in 25 arms: 9 of r393_solid, 8 of r420_f_mixed and 8 of
    // r420_solid.
    let differing: BTreeSet<_> = found.iter().map(|(a, m, n, _)| (a, m, n)).collect();
    assert_eq!((found.len(), differing.len()), (32, 25), "pairs and arms");
    assert_eq!(
        found, chosen,
        "members rarkit calls good that the answers do not mark `=` (with the mark): {differences:#?}"
    );
}
