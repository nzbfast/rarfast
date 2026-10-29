//! What the writer admits at the default policy is a WIDTH and nothing
//! else: the worker
//! team held to the policy's own `working_limit` with every term it holds
//! charged, and the lead's staged flush narrowed where the lead alone would
//! not fit (`Run::choose_lead_depth`), write the archive the parent wrote,
//! to the byte, at every width.
//!
//! **The control** is the parent's archives, pinned by digest in [`PINNED`]:
//! the same rows run at the parent tree with `RARKIT_PIN_PRINT=1` print
//! the table this file carries (the parent is the store
//! rule's land over fast level 1's, which this work is built on, and whose
//! rows are an earlier revision's; the rows moved three times
//! on the way, with the backward extension's land (level 3), the lazy tree parse's
//! (levels 4 and 5) and fast level 1's (level 1), byte changes of their
//! own). Within a row every pool width
//! must also write the same bytes as the others.
//!
//! **What the rows reach.** A non-solid set of small members (the team's),
//! one member held whole as a slice (one region) and one read from a
//! reader three windows long (the lead's staged windows), at levels 1 to 5
//! and both formats, on pools of 1, 3, 8 and 32 threads, under two
//! policies: the default, and a working limit the caller did NOT name that
//! is small enough to narrow both the team and the lead's staging, which
//! the rows check it did.
//!
//! **Pinned again on 11 Oct 2026, over new test data.** The members here
//! are made by the shared test data makers now, so every digest below
//! was taken again, from that day's build, whose engine was byte for byte
//! the one that passed the pins before them. They record the same
//! behaviour on new data and guard it from here on; they no longer prove
//! equality with the older build this header names.

use std::io::Cursor;
use std::sync::Arc;

use rarkit::{
    extract, Disposition, FilterPolicy, MemberInfo, MemberOutcome, MemberSpec, MemoryPolicy,
    Payload, RangeSource, ReadOptions, Sink, WriteFormat, WriteMethod, WriteOptions, Writer,
};
use sha2::{Digest, Sha256};

use rarkit::internals::writers::{
    forget_widest_flush, reset_team_prepared, team_prepared, widest_flush,
};

/// The parent's digests: (format, level, policy) to the first 16 hex
/// digits of the archive's SHA-256. Printed by the parent tree. The eight
/// level 4 and level 5 rows were re-taken, by the same print, at
/// SPEC-H3 8.1's ladder land of 1 Oct 2026: level 4's
/// default plan went to the chains at 64 links and level 5's lazy tree
/// plan took the backward extension;
/// the twelve rows of levels 1 to 3 are the parent's.
///
/// The four level 5 rows were re-taken once more that day, by the same
/// print, at the land of LEVEL 5 BY CLASS (SPEC-H3 8.1): these
/// members read under the cut-off or are a solid run, so level 5 writes
/// them over the chains at 80 links, 72 in a solid run; every other row
/// was printed beside them and had not moved.
///
/// The eight RAR 5 rows of levels 2 to 5 were re-taken, by the same
/// print, on 8 Oct 2026, when the filter detector's estimate was written
/// to SPEC-G 3.8.2's rule: detection sends other filters over these
/// members, so the archives are other bytes (0.69 to 0.72 per cent
/// larger on this generated set). Level 1 judges nothing and the RAR 4
/// rows carry no filter; they were printed beside and had not moved.
const PINNED: &[(&str, u8, &str, &str)] = &[
    ("rar5", 1, "default", "5e3d8b289ed82527"),
    ("rar5", 1, "tight", "5e3d8b289ed82527"),
    ("rar5", 2, "default", "6ce2de9ec4b21732"),
    ("rar5", 2, "tight", "6ce2de9ec4b21732"),
    ("rar5", 3, "default", "0fb504c28287ba26"),
    ("rar5", 3, "tight", "0fb504c28287ba26"),
    ("rar5", 4, "default", "e6acc3d4389016f1"),
    ("rar5", 4, "tight", "e6acc3d4389016f1"),
    ("rar5", 5, "default", "9d31861cae5a7057"),
    ("rar5", 5, "tight", "9d31861cae5a7057"),
    ("rar4", 1, "default", "1cdabac144fa110a"),
    ("rar4", 1, "tight", "1cdabac144fa110a"),
    ("rar4", 2, "default", "ba40ad3aed79e675"),
    ("rar4", 2, "tight", "ba40ad3aed79e675"),
    ("rar4", 3, "default", "3beea58272939355"),
    ("rar4", 3, "tight", "3beea58272939355"),
    ("rar4", 4, "default", "3a978b9dbece20a0"),
    ("rar4", 4, "tight", "3a978b9dbece20a0"),
    ("rar4", 5, "default", "1137ec31ba6da209"),
    ("rar4", 5, "tight", "1137ec31ba6da209"),
];

/// The set: `SMALL` members of 8 to 136 KiB, one slice of 1.5 MiB, one
/// reader of three windows and a little more.
const SMALL: usize = 48;
const DICTIONARY: u64 = 1 << 20;

fn members() -> Vec<Vec<u8>> {
    let mut rng = rarkit_testdata::Seeded::new(0x5eed);
    let mut out: Vec<Vec<u8>> = (0..SMALL)
        .map(|at| {
            rarkit_testdata::medley(
                at as u64 + 7,
                (8 << 10) + rng.next_u32() as usize % (128 << 10),
            )
        })
        .collect();
    out.push(rarkit_testdata::medley(101, 3 << 19));
    out.push(rarkit_testdata::medley(202, (3 << 20) + 4_099));
    out
}

fn options(format: WriteFormat, level: u8, workers: usize, memory: MemoryPolicy) -> WriteOptions {
    WriteOptions {
        format,
        method: WriteMethod::Compressed {
            level,
            dictionary: Some(DICTIONARY),
        },
        // The RAR 4 family refuses a filter request (SPEC-J).
        filters: if matches!(format, WriteFormat::Rar4(_)) {
            FilterPolicy::Off
        } else {
            FilterPolicy::Detect
        },
        host_os: rarkit::HostOs::Unix,
        memory,
        workers: Some(workers),
        ..WriteOptions::default()
    }
}

fn write(options: WriteOptions, members: &[Vec<u8>]) -> Vec<u8> {
    let mut writer = Writer::new(options).expect("options");
    let names: Vec<Vec<u8>> = (0..members.len())
        .map(|at| format!("m{at:03}.bin").into_bytes())
        .collect();
    let last = members.len() - 1;
    let mut reader = Cursor::new(&members[last][..]);
    for (at, data) in members[..last].iter().enumerate() {
        writer
            .add(MemberSpec {
                name: &names[at],
                payload: Payload::Bytes(data),
                mtime: None,
                attributes: 0o644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    writer
        .add(MemberSpec {
            name: &names[last],
            payload: Payload::Reader {
                reader: &mut reader,
                size: members[last].len() as u64,
                crc32: None,
            },
            mtime: None,
            attributes: 0o644,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    out
}

#[derive(Default)]
struct Collect(Vec<u8>);

impl Sink for Collect {
    type Out = Vec<u8>;

    fn open(&mut self, _member: &MemberInfo<'_>) -> rarkit::Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> rarkit::Result<()> {
        assert_eq!(
            outcome.checksum_ok,
            Some(true),
            "a member failed its checksum"
        );
        self.0.extend_from_slice(&out.unwrap_or_default());
        Ok(())
    }
}

fn reads_back(archive: &[u8], members: &[Vec<u8>], what: &str) {
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(archive.to_vec())];
    let mut sink = Collect::default();
    extract(sources, &ReadOptions::default(), &mut sink, &mut ())
        .unwrap_or_else(|e| panic!("{what}: rarkit could not read it back: {e}"));
    assert!(
        sink.0 == members.concat(),
        "{what}: the members came back different"
    );
}

fn sha16(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A limit the caller did not name, small enough that the team narrows
/// and the lead stages fewer windows.
fn tight() -> MemoryPolicy {
    MemoryPolicy {
        working_limit: 48 << 20,
        limit_named: false,
        ..MemoryPolicy::default()
    }
}

#[test]
fn admission_at_the_default_moves_no_byte() {
    let members = members();
    let print = std::env::var_os("RARKIT_PIN_PRINT").is_some();
    let formats = [
        ("rar5", WriteFormat::Rar5),
        ("rar4", WriteFormat::Rar4(rarkit::Rar4Version::V29)),
    ];
    let policies = [("default", MemoryPolicy::default()), ("tight", tight())];
    let mut missing = Vec::new();
    // Per format and level: the default's and the tight policy's team width
    // and widest staged flush at 32 workers.
    let mut narrowed = Vec::new();
    for (format_name, format) in formats {
        for level in 1..=5u8 {
            for (policy_name, policy) in &policies {
                let what = format!("{format_name} m{level} {policy_name}");
                let mut first: Option<String> = None;
                let mut crews = Vec::new();
                let mut flushes = Vec::new();
                for workers in [1usize, 3, 8, 32] {
                    forget_widest_flush();
                    reset_team_prepared();
                    let archive = write(options(format, level, workers, *policy), &members);
                    crews.push(team_prepared());
                    flushes.push(widest_flush());
                    let sha = sha16(&archive);
                    match &first {
                        None => {
                            reads_back(&archive, &members, &what);
                            first = Some(sha);
                        }
                        Some(first) => assert_eq!(
                            &sha, first,
                            "{what}: {workers} workers wrote other bytes than one"
                        ),
                    }
                }
                let sha = first.expect("a width ran");
                if print {
                    println!("    (\"{format_name}\", {level}, \"{policy_name}\", \"{sha}\"),");
                    continue;
                }
                match PINNED
                    .iter()
                    .find(|row| row.0 == format_name && row.1 == level && row.2 == *policy_name)
                {
                    Some(row) => assert_eq!(sha, row.3, "{what}: not the parent's archive"),
                    None => missing.push(what.clone()),
                }
                eprintln!(
                    "{what}: team-encoded members {crews:?}, widest staged flush {flushes:?}"
                );
                narrowed.push((format_name, level, *policy_name, crews[3], flushes[3]));
            }
        }
    }
    if print {
        return;
    }
    assert!(
        missing.is_empty(),
        "rows with no pinned digest: {missing:?}"
    );
    // The tight rows are the point: somewhere the limit must have narrowed
    // the team or the lead's staging, or these rows proved nothing.
    let pairs: Vec<_> = narrowed
        .chunks(2)
        .filter(|pair| pair[1].3 < pair[0].3 || pair[1].4 < pair[0].4)
        .map(|pair| (pair[0].0, pair[0].1))
        .collect();
    assert!(
        !pairs.is_empty(),
        "the tight limit narrowed nothing: {narrowed:?}"
    );
}

/// SPEC-API 8.4.1, acceptance test 6 (and SPEC-G 3.5's
/// held-member rule under it): the default `working_limit` scales with
/// physical memory, but whether a member is held or streamed does NOT
/// follow it. The threshold is the floor's figure, `DEFAULT_LIMIT` less the
/// process's overhead, so the same set writes the same bytes, with the same
/// member streamed, on a machine of 4 GiB and one of 384 GiB.
///
/// The machine is injected as its policy: `process_default`'s shape, a
/// quarter of each memory as `working_limit` over the same
/// `process_overhead`. The overhead is chosen so the floor's figure is 24
/// MiB, which a 2 MiB member's held-whole sum (about 18 MiB with its
/// finder) fits and a 6 MiB member's (about 50, its packed bytes counted
/// twice) does not.
#[test]
fn the_held_member_threshold_does_not_follow_the_machine() {
    use rarkit::internals::writers::{reset_streamed_members, streamed_members};
    let overhead = MemoryPolicy::DEFAULT_LIMIT - (24 << 20);
    let machine = |physical: u64| MemoryPolicy {
        working_limit: physical / 4 - overhead,
        process_overhead: overhead,
        limit_named: false,
        ..MemoryPolicy::default()
    };
    // Noise with a little text, so neither member is stored by the store
    // rule nor packs to nothing.
    let small = rarkit_testdata::medley(303, 2 << 20);
    let large = rarkit_testdata::medley(404, 6 << 20);
    let write = |memory: MemoryPolicy| {
        reset_streamed_members();
        let mut readers = [Cursor::new(&small[..]), Cursor::new(&large[..])];
        let mut writer = Writer::new(options(WriteFormat::Rar5, 3, 4, memory)).expect("options");
        for (name, (reader, len)) in [&b"small.bin"[..], &b"large.bin"[..]].into_iter().zip(
            readers
                .iter_mut()
                .zip([small.len() as u64, large.len() as u64]),
        ) {
            writer
                .add(MemberSpec {
                    name,
                    payload: Payload::Reader {
                        reader,
                        size: len,
                        crc32: None,
                    },
                    mtime: None,
                    attributes: 0o644,
                    host_os: rarkit::HostOs::Unix,
                    is_directory: false,
                })
                .expect("add");
        }
        // An output that can patch, so a member over the threshold streams.
        let mut out = Cursor::new(Vec::new());
        writer.finish_seek(&mut out).expect("finish_seek");
        (out.into_inner(), streamed_members())
    };
    let (laptop, laptop_streamed) = write(machine(4 << 30));
    let (server, server_streamed) = write(machine(384 << 30));
    assert!(
        laptop == server,
        "the archive follows the machine's memory: {} and {}",
        sha16(&laptop),
        sha16(&server)
    );
    assert_eq!(
        (laptop_streamed, server_streamed),
        (1, 1),
        "the 6 MiB member streams and the 2 MiB one is held, on both machines"
    );
}
