//! A member that ends short of its declared size inside a VOLUME of a set
//! (SPEC-F 4.2, "A member that ends short", rule 6, 9 Oct 2026).
//!
//! In a single archive a short member whose checksum matches the bytes
//! produced is good (rule 1). In an archive that carries the main
//! header's volume flag it is never good, whatever its checksum says: a
//! header's checksum there can be a fragment's, and nothing at the
//! member tells the two apart. That is a chosen difference: the genuine
//! programs write the short file and say All OK in both shapes below.
//!
//! The two shapes, each a hand-built RAR 5 set of stored members:
//!
//! - a FIRST FRAGMENT THAT DOES NOT SAY IT CONTINUES: the member's first
//!   46 bytes in the first volume under a header with "continues in the
//!   next volume" cleared and the CRC32 of those 46 bytes, the other 74
//!   in the second volume under a sound continuing header;
//! - a member DECLARED TOO LONG inside a set, nothing continuing it: the
//!   same 46 bytes whole, under a header that declares 120 and carries
//!   their CRC32.
//!
//! And the control: the second shape with the volume flag off is a single
//! archive, and the member is good with its 46 bytes.
//!
//! Read at the default width, at one worker and by `extract_parallel` at
//! two; every archive is under 400 bytes.

use std::sync::{Arc, Mutex};

use rarkit::{
    extract, extract_parallel, Disposition, MemberInfo, MemberOutcome, ParallelSink, RangeSource,
    ReadOptions, Sink,
};

fn vint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// A block: its checksum, its size and its body.
fn header(body: &[u8]) -> Vec<u8> {
    let mut sized = Vec::new();
    vint(&mut sized, body.len() as u64);
    sized.extend_from_slice(body);
    let mut out = rarkit::checksum::crc32(&sized).to_le_bytes().to_vec();
    out.extend_from_slice(&sized);
    out
}

const SPLIT_BEFORE: u64 = 0x0008;
const SPLIT_AFTER: u64 = 0x0010;

/// A stored file member: its header flags beyond "a data area follows",
/// its name, the size it declares, the CRC32 its header carries, and the
/// bytes in its data area.
struct Stored<'a> {
    flags: u64,
    name: &'a str,
    declares: u64,
    crc: u32,
    data: &'a [u8],
}

/// One volume: whether its main header carries the volume flag, its
/// number in the set, its members, and whether its end says another
/// volume follows.
fn volume(flagged: bool, number: u64, members: &[Stored<'_>], more: bool) -> Vec<u8> {
    let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
    let mut main = Vec::new();
    vint(&mut main, 1); // the main archive header
    vint(&mut main, 0);
    // Archive flags: 0x0001 a volume, 0x0002 a volume number follows.
    let numbered = flagged && number > 0;
    vint(&mut main, u64::from(flagged) | (u64::from(numbered) << 1));
    if numbered {
        vint(&mut main, number);
    }
    out.extend(header(&main));
    for member in members {
        let mut body = Vec::new();
        vint(&mut body, 2); // a file header
        vint(&mut body, 0x0002 | member.flags);
        vint(&mut body, member.data.len() as u64);
        vint(&mut body, 0x0004); // file flags: a CRC32 follows
        vint(&mut body, member.declares);
        vint(&mut body, 0); // attributes
        body.extend_from_slice(&member.crc.to_le_bytes());
        vint(&mut body, 0); // compression: stored
        vint(&mut body, 0); // host
        vint(&mut body, member.name.len() as u64);
        body.extend_from_slice(member.name.as_bytes());
        out.extend(header(&body));
        out.extend_from_slice(member.data);
    }
    let mut end = Vec::new();
    vint(&mut end, 5);
    vint(&mut end, 0);
    vint(&mut end, u64::from(more));
    out.extend(header(&end));
    out
}

/// 120 bytes no two of which repeat a pattern.
fn text() -> Vec<u8> {
    (0..120u32).map(|i| (i * 7 + 13) as u8).collect()
}

const HEAD: usize = 46;

/// One member as it closed: its name, its bytes and its verdict.
type Came = (String, Vec<u8>, Option<bool>);

#[derive(Default)]
struct Keep(Mutex<Vec<Came>>);

impl Keep {
    fn closed(&self, member: &MemberInfo<'_>, out: Option<Vec<u8>>, outcome: &MemberOutcome) {
        self.0.lock().expect("lock").push((
            member.name_lossy().into_owned(),
            out.unwrap_or_default(),
            outcome.checksum_ok,
        ));
    }
}

impl Sink for Keep {
    type Out = Vec<u8>;

    fn open(&mut self, _: &MemberInfo<'_>) -> rarkit::Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> rarkit::Result<()> {
        self.closed(member, out, outcome);
        Ok(())
    }
}

impl ParallelSink for Keep {
    type Out = Vec<u8>;

    fn open(&self, _: &MemberInfo<'_>) -> rarkit::Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> rarkit::Result<()> {
        self.closed(member, out, outcome);
        Ok(())
    }
}

/// Every read path over one set, labelled: the closes and whether the
/// operation ended in an error.
fn every_path(volumes: &[Vec<u8>]) -> Vec<(String, Vec<Came>, bool)> {
    let sources = || -> Vec<Arc<dyn RangeSource>> {
        volumes
            .iter()
            .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
            .collect()
    };
    let mut reads = Vec::new();
    for workers in [None, Some(1)] {
        let mut keep = Keep::default();
        let options = ReadOptions::default().with_workers(workers);
        let failed = extract(sources(), &options, &mut keep, &mut ()).is_err();
        let came = keep.0.into_inner().expect("lock");
        reads.push((format!("workers {workers:?}"), came, failed));
    }
    let keep = Keep::default();
    let failed = extract_parallel(sources(), &ReadOptions::default(), &keep, 2).is_err();
    let came = keep.0.into_inner().expect("lock");
    reads.push(("extract_parallel, 2 wide".to_owned(), came, failed));
    reads
}

/// No close of `name` is good: the member is never reported whole or
/// short-and-good.
fn never_good(volumes: &[Vec<u8>], name: &str, case: &str) {
    for (path, came, _) in every_path(volumes) {
        let of_name: Vec<&Came> = came.iter().filter(|(n, _, _)| n == name).collect();
        assert!(!of_name.is_empty(), "{case}, {path}: {name} never closed");
        for (_, bytes, verdict) in of_name {
            assert_ne!(
                *verdict,
                Some(true),
                "{case}, {path}: {name} is called good with {} bytes of its declared 120",
                bytes.len()
            );
        }
    }
}

#[test]
fn a_first_fragment_that_does_not_say_it_continues_is_never_good() {
    let text = text();
    let first = volume(
        true,
        0,
        &[Stored {
            // "Continues in the next volume" CLEARED.
            flags: 0,
            name: "m.bin",
            declares: 120,
            crc: rarkit::checksum::crc32(&text[..HEAD]),
            data: &text[..HEAD],
        }],
        true,
    );
    let second = volume(
        true,
        1,
        &[Stored {
            flags: SPLIT_BEFORE,
            name: "m.bin",
            declares: 120,
            crc: rarkit::checksum::crc32(&text),
            data: &text[HEAD..],
        }],
        false,
    );
    never_good(&[first.clone(), second], "m.bin", "two volumes");
    // The same with the second volume's end of the story untold: the
    // first volume alone, its end still saying another follows.
    never_good(&[first], "m.bin", "the first volume alone");
}

#[test]
fn a_member_declared_too_long_inside_a_set_is_never_good() {
    let text = text();
    let long = |flagged: bool| {
        volume(
            flagged,
            0,
            &[
                Stored {
                    flags: 0,
                    name: "m.bin",
                    declares: 120,
                    crc: rarkit::checksum::crc32(&text[..HEAD]),
                    data: &text[..HEAD],
                },
                Stored {
                    flags: 0,
                    name: "after.bin",
                    declares: 74,
                    crc: rarkit::checksum::crc32(&text[HEAD..]),
                    data: &text[HEAD..],
                },
            ],
            false,
        )
    };
    never_good(&[long(true)], "m.bin", "a volume of a set");
    // The member after it is whole all the same.
    for (path, came, _) in every_path(&[long(true)]) {
        let after = came.iter().find(|(n, _, _)| n == "after.bin");
        assert_eq!(
            after.map(|(_, bytes, ok)| (&bytes[..], *ok)),
            Some((&text[HEAD..], Some(true))),
            "{path}"
        );
    }
    // THE CONTROL: with the volume flag off this is a single archive, and
    // rule 1 stands: the member is good with the 46 bytes its checksum
    // vouches for.
    for (path, came, failed) in every_path(&[long(false)]) {
        assert!(!failed, "{path}");
        let short = came.iter().find(|(n, _, _)| n == "m.bin");
        assert_eq!(
            short.map(|(_, bytes, ok)| (&bytes[..], *ok)),
            Some((&text[..HEAD], Some(true))),
            "{path}"
        );
    }
}

/// A member that continues by its own header, across two volumes, is
/// untouched by the rule: whole and good.
#[test]
fn a_sound_split_member_is_whole() {
    let text = text();
    let first = volume(
        true,
        0,
        &[Stored {
            flags: SPLIT_AFTER,
            name: "m.bin",
            declares: 120,
            crc: rarkit::checksum::crc32(&text[..HEAD]),
            data: &text[..HEAD],
        }],
        true,
    );
    let second = volume(
        true,
        1,
        &[Stored {
            flags: SPLIT_BEFORE,
            name: "m.bin",
            declares: 120,
            crc: rarkit::checksum::crc32(&text),
            data: &text[HEAD..],
        }],
        false,
    );
    for (path, came, failed) in every_path(&[first.clone(), second.clone()]) {
        assert!(!failed, "{path}");
        assert_eq!(
            came,
            [("m.bin".to_owned(), text.clone(), Some(true))],
            "{path}"
        );
    }
}
