//! A RAR 3/4 solid member that DECLARES FEWER BYTES than its packed data
//! produces, zero included, is decoded to the end of its packed data, and
//! the members after it decode from the state its whole stream left
//! (SPEC-F 3.6.3 item 4, SPEC-H1 3.8 B9, SPEC-I 3.3 "Member end", SPEC-J
//! 3.8; SWEEP2-08OCT-14).
//!
//! Each input is built here from a tracked genuine archive: one member's
//! unpacked size and checksum fields rewritten and its header checksum
//! redone, nothing else touched. What reference unrar 7.23 does with them
//! is the specification's (`vectors-H/h1-declared-short-probe.py`): every
//! member after the altered one comes out right; the altered member is
//! judged by its checksum against its declared bytes, and fails where a
//! filter's span completes past the declared size.
//!
//! Every read here runs at the engine's default pool width and at one
//! worker; the archives are under 100 KiB and the reads hold the decoder's
//! ordinary working memory, nothing sized by the test.

use std::sync::Arc;

use rarkit::{Disposition, MemberInfo, MemberOutcome, RangeSource, ReadOptions, Result, Sink};

/// One member as a read reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    name: String,
    checksum_ok: Option<bool>,
    bytes: Vec<u8>,
}

/// Keeps what each wanted member delivered, and its verdict.
struct Keep {
    only: Option<Vec<&'static str>>,
    seen: Vec<Seen>,
}

impl Sink for Keep {
    type Out = Vec<u8>;
    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        let name = String::from_utf8_lossy(member.name).into_owned();
        let wanted = self
            .only
            .as_ref()
            .is_none_or(|only| only.contains(&name.as_str()));
        if member.is_directory || !wanted {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Vec::new()))
    }
    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.seen.push(Seen {
            name: String::from_utf8_lossy(member.name).into_owned(),
            checksum_ok: outcome.checksum_ok,
            bytes: out.unwrap_or_default(),
        });
        Ok(())
    }
}

fn read(bytes: &[u8], only: Option<&[&'static str]>, options: &ReadOptions) -> Vec<Seen> {
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(bytes.to_vec())];
    let mut sink = Keep {
        only: only.map(<[&str]>::to_vec),
        seen: Vec::new(),
    };
    // A member's failure is its own `close`; the operation's end is not
    // what these tests judge.
    let _ = rarkit::extract(sources, options, &mut sink, &mut ());
    sink.seen
}

/// Every read path: the decode-ahead on and off, at the engine's default
/// width and at one worker.
fn every_path(bytes: &[u8], only: Option<&[&'static str]>) -> Vec<(String, Vec<Seen>)> {
    let mut out = Vec::new();
    for ahead in [true, false] {
        for workers in [None, Some(1)] {
            rarkit::probe::set_ahead_off(!ahead);
            let got = read(bytes, only, &ReadOptions::default().with_workers(workers));
            rarkit::probe::set_ahead_off(false);
            out.push((format!("ahead {ahead}, workers {workers:?}"), got));
        }
    }
    out
}

fn legacy(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/legacy/archives")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

/// `src`, a RAR 3/4 archive, with member `name` declared as `size` bytes
/// with checksum field `crc`: offsets 11 and 16 of its file header
/// rewritten and the header's CRC16 redone.
fn declare(src: &[u8], name: &[u8], size: u32, crc: u32) -> Vec<u8> {
    let u16_at = |p: usize| u16::from_le_bytes([src[p], src[p + 1]]) as usize;
    let u32_at = |p: usize| u32::from_le_bytes(src[p..p + 4].try_into().unwrap()) as usize;
    let mut out = src.to_vec();
    let mut p = src
        .windows(7)
        .position(|w| w == b"Rar!\x1a\x07\x00")
        .expect("a RAR 4 marker");
    while p + 7 <= src.len() {
        let (kind, flags, head) = (src[p + 2], u16_at(p + 3), u16_at(p + 5));
        let data = if kind == 0x74 || flags & 0x8000 != 0 {
            u32_at(p + 7)
        } else {
            0
        };
        if kind == 0x74 {
            let name_len = u16_at(p + 26);
            if &src[p + 32..p + 32 + name_len] == name {
                out[p + 11..p + 15].copy_from_slice(&size.to_le_bytes());
                out[p + 16..p + 20].copy_from_slice(&crc.to_le_bytes());
                let sum = (crc32fast::hash(&out[p + 2..p + head]) & 0xffff) as u16;
                out[p..p + 2].copy_from_slice(&sum.to_le_bytes());
                return out;
            }
        }
        p += head + data;
    }
    panic!("no member {}", String::from_utf8_lossy(name));
}

/// The archive as written: every member's true bytes, by name.
fn truth(src: &[u8]) -> Vec<Seen> {
    let seen = read(src, None, &ReadOptions::default().with_workers(Some(1)));
    assert!(seen.len() >= 5, "the tracked archive reads whole");
    for member in &seen {
        assert_eq!(member.checksum_ok, Some(true), "{} as written", member.name);
    }
    seen
}

/// Every member but `altered` is delivered with its true bytes and passes;
/// `altered` delivers exactly `declared` and has the verdict `verdict`.
fn chain_kept(
    label: &str,
    bytes: &[u8],
    truth: &[Seen],
    altered: &str,
    declared: &[u8],
    verdict: bool,
) {
    for (path, seen) in every_path(bytes, None) {
        assert_eq!(seen.len(), truth.len(), "{label}: {path}: members reported");
        for (got, want) in seen.iter().zip(truth) {
            assert_eq!(got.name, want.name, "{label}: {path}");
            if got.name == altered {
                assert_eq!(
                    got.checksum_ok,
                    Some(verdict),
                    "{label}: {path}: the altered {altered}"
                );
                assert_eq!(got.bytes, declared, "{label}: {path}: {altered}'s bytes");
            } else {
                assert_eq!(
                    got.checksum_ok,
                    Some(true),
                    "{label}: {path}: {} after the altered member",
                    got.name
                );
                assert!(got.bytes == want.bytes, "{label}: {path}: {}", got.name);
            }
        }
    }
}

/// `r420_solid.rar`'s `AUDIO.RAW`, an LZ member whose audio filter spans
/// cover its first 35,840 bytes, declared as 0 bytes with checksum 0. The
/// reference fails that member alone (its filtered spans complete past the
/// declared size) and writes the four after it; SPEC-J 3.8 makes the
/// failure the member's own verdict and keeps the decode going.
#[test]
fn rar3_lz_member_declared_zero_fails_alone_and_hands_the_chain_on() {
    let src = legacy("r420_solid.rar");
    let truth = truth(&src);
    let bytes = declare(&src, b"AUDIO.RAW", 0, 0);
    chain_kept(
        "r420_solid AUDIO.RAW as 0",
        &bytes,
        &truth,
        "AUDIO.RAW",
        b"",
        false,
    );
}

/// The same archive, with only two members AFTER the altered one wanted:
/// the altered member is decoded for the chain and both come out right
/// (the reference: exit 0, All OK).
#[test]
fn rar3_lz_members_after_a_skipped_declared_zero_member_are_right() {
    let src = legacy("r420_solid.rar");
    let truth = truth(&src);
    let bytes = declare(&src, b"AUDIO.RAW", 0, 0);
    let only: &[&'static str] = &["HELLO.TXT", "SUB/SIB.TXT"];
    for (path, seen) in every_path(&bytes, Some(only)) {
        let names: Vec<&str> = seen.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, only, "{path}: the two wanted members are reported");
        for got in &seen {
            let want = truth.iter().find(|m| m.name == got.name).expect("a name");
            assert_eq!(got.checksum_ok, Some(true), "{path}: {}", got.name);
            assert!(got.bytes == want.bytes, "{path}: {}", got.name);
        }
    }
}

/// An LZ member with no filter span past the declared size, declared as
/// half its bytes with the checksum of that half: it passes on them and
/// the chain goes on (SPEC-H1 3.8 B9).
#[test]
fn rar3_lz_member_declared_half_passes_on_its_declared_bytes() {
    let src = legacy("r420_solid.rar");
    let truth = truth(&src);
    let whole = &truth
        .iter()
        .find(|m| m.name == "BIG.TXT")
        .expect("BIG.TXT")
        .bytes;
    let half = &whole[..whole.len() / 2];
    let bytes = declare(&src, b"BIG.TXT", half.len() as u32, crc32fast::hash(half));
    chain_kept(
        "r420_solid BIG.TXT as half",
        &bytes,
        &truth,
        "BIG.TXT",
        half,
        true,
    );
}

/// `r393_solid.rar`'s PPM member `BIG.TXT` declared as 0 bytes with
/// checksum 0: the reference tests All OK, exit 0. The PPM decode goes on
/// past the declared size to the member's end pair (SPEC-I 3.3).
#[test]
fn rar3_ppm_member_declared_zero_passes_and_hands_the_chain_on() {
    let src = legacy("r393_solid.rar");
    let truth = truth(&src);
    let bytes = declare(&src, b"BIG.TXT", 0, 0);
    chain_kept(
        "r393_solid BIG.TXT as 0",
        &bytes,
        &truth,
        "BIG.TXT",
        b"",
        true,
    );
}

/// The same PPM member declared as half its bytes with their checksum: a
/// copy or a literal past the declared size is applied whole to the window
/// and is no member's output (SPEC-I 3.3, "A copy past the declared
/// size").
#[test]
fn rar3_ppm_member_declared_half_passes_on_its_declared_bytes() {
    let src = legacy("r393_solid.rar");
    let truth = truth(&src);
    let whole = &truth
        .iter()
        .find(|m| m.name == "BIG.TXT")
        .expect("BIG.TXT")
        .bytes;
    let half = &whole[..whole.len() / 2];
    let bytes = declare(&src, b"BIG.TXT", half.len() as u32, crc32fast::hash(half));
    chain_kept(
        "r393_solid BIG.TXT as half",
        &bytes,
        &truth,
        "BIG.TXT",
        half,
        true,
    );
}

// ------------------------------------------------ a failed member's queue

/// `src` with the last `cut` packed bytes of member `name` removed: the
/// header's packed size lowered and its CRC16 redone, nothing else
/// touched.
fn cut_packed(src: &[u8], name: &[u8], cut: usize) -> Vec<u8> {
    let u16_at = |p: usize| u16::from_le_bytes([src[p], src[p + 1]]) as usize;
    let u32_at = |p: usize| u32::from_le_bytes(src[p..p + 4].try_into().unwrap()) as usize;
    let mut p = src
        .windows(7)
        .position(|w| w == b"Rar!\x1a\x07\x00")
        .expect("a RAR 4 marker");
    while p + 7 <= src.len() {
        let (kind, flags, head) = (src[p + 2], u16_at(p + 3), u16_at(p + 5));
        let data = if kind == 0x74 || flags & 0x8000 != 0 {
            u32_at(p + 7)
        } else {
            0
        };
        if kind == 0x74 && &src[p + 32..p + 32 + u16_at(p + 26)] == name {
            assert!(cut < data, "the member holds more than the cut");
            let mut header = src[p..p + head].to_vec();
            header[7..11].copy_from_slice(&((data - cut) as u32).to_le_bytes());
            let sum = (crc32fast::hash(&header[2..]) & 0xffff) as u16;
            header[0..2].copy_from_slice(&sum.to_le_bytes());
            let mut out = src[..p].to_vec();
            out.extend_from_slice(&header);
            out.extend_from_slice(&src[p + head..p + head + data - cut]);
            out.extend_from_slice(&src[p + head + data..]);
            return out;
        }
        p += head + data;
    }
    panic!("no member {}", String::from_utf8_lossy(name));
}

/// A member of a RAR 3 solid chain that fails with a filter still waiting
/// leaves nothing waiting (SPEC-J 3.8, "A member that ends with filters
/// waiting"; SWEEP2-08OCT-58).
///
/// `r420_f_mixed.rar`, where all seven members carry filter records, with
/// the last 250 packed bytes of `DELTA.BIN` removed. The reference fails
/// it and the two members after it, which copy from what was lost, and
/// writes `IMAGE.BMP`, `PCM.RAW`, `RGB.RAW` and `SOUND.WAV` whole and
/// right, each through filters of its own. A reader that kept the cut
/// member's waiting filter refused every later member's records, held
/// delivery at the stale span, and put `DELTA.BIN`'s bytes at the head of
/// `SOUND.WAV`'s output.
#[test]
fn rar3_a_failed_members_waiting_filter_is_dropped_with_it() {
    let src = legacy("r420_f_mixed.rar");
    let truth = truth(&src);
    let bytes = cut_packed(&src, b"DELTA.BIN", 250);
    // The two after the cut member lean on what it lost in the
    // reference's reading. rarkit decodes no symbol from bits the cut
    // member does not hold (SPEC-H1 3.8, B7), so here they may come out
    // right: each is judged by its own checksum, and one that passes has
    // its true bytes.
    let leaning = ["IA64.BIN", "X86.BIN"];
    for (path, seen) in every_path(&bytes, None) {
        assert_eq!(seen.len(), truth.len(), "{path}: members reported");
        for (got, want) in seen.iter().zip(&truth) {
            assert_eq!(got.name, want.name, "{path}");
            if got.name == "DELTA.BIN" {
                assert_eq!(got.checksum_ok, Some(false), "{path}: the cut member");
                // What it did deliver is its own, and no more than it has.
                assert!(
                    got.bytes.len() < want.bytes.len()
                        && got.bytes[..] == want.bytes[..got.bytes.len()],
                    "{path}: DELTA.BIN delivers a prefix of its own bytes"
                );
            } else if leaning.contains(&got.name.as_str()) {
                assert_eq!(
                    got.checksum_ok == Some(true),
                    got.bytes == want.bytes,
                    "{path}: {} is good exactly when its bytes are its own",
                    got.name
                );
            } else {
                assert_eq!(got.checksum_ok, Some(true), "{path}: {}", got.name);
                assert!(got.bytes == want.bytes, "{path}: {}", got.name);
            }
        }
    }
}
