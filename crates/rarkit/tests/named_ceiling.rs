//! A NAMED memory ceiling of 512 MiB and more admits what the default
//! admits (spec G 3.7.3, "A NAMED ceiling admits what the default admits"
//! and "FROM 512 MiB UP, and not below", 1 Oct 2026).
//!
//! **What the rows say.**
//!
//! - AT 512 MiB of budget (`from_limit(DEFAULT_LIMIT)`, and a
//!   `for_process` policy whose budget is the same) the archive is the
//!   DEFAULT policy's, byte for byte, at every pool width; the worker team
//!   is the default's (`tests/team_create.rs` has the row where that is
//!   wider than `max_workers`); a member a window at a time runs the
//!   default's history slack and its flushes are staged. One form stays
//!   off: the large-member lane's reach past a window, under any named
//!   ceiling.
//! - ONE BYTE UNDER (`from_limit(DEFAULT_LIMIT - 1)`) the path is the one
//!   before the rule: the team is held to `max_workers`, a flush is one
//!   window, the slack is the shipped one, and the archive is the PARENT's
//!   named archive, pinned by digest in [`PINNED`] (the same rows run at
//!   the parent tree with `RARKIT_PIN_PRINT=1` print the table).
//! - At every budget the write's stated peak is inside `working_limit`
//!   and `ceiling_exceeded_by` is `None`. That is the engine's own figure
//!   and reads nothing of the process, so no other process's load moves
//!   it; `tests/named_ceiling_heap.rs` counts the live heap beside it.
//! - A SOLID run and a VOLUME SET under a budget of 512 MiB and 2 GiB are
//!   the default's archives too.
//! - A member STREAMED under a named ceiling reserves its packed size
//!   field a fragment at a time, as the default's streamed member does
//!   (spec G 3.5): the two archives are the same bytes.
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
    Payload, RangeSource, ReadOptions, Sink, WriteFormat, WriteMethod, WriteOptions, WriteReport,
    Writer,
};
use sha2::{Digest, Sha256};

use rarkit::internals::writers::{
    forget_widest_flush, last_streamed_slack, reset_streamed_members, streamed_members, team_crews,
    team_large, widest_flush, with_stream_above,
};

/// The parent's digests of the archive written one byte under 512 MiB:
/// (format, level) to the first 16 hex digits of its SHA-256. The parent
/// is an earlier revision; levels 4 and 5 moved on the way with another
/// change's land (the ladder fix, a byte change of its own: at that revision
/// they read `18d73516...`, `9501722f...`, `345be810...` and
/// `9438e57d...`, on the parent and on this tree alike). The two level
/// 5 rows were re-taken, by the same print, at the land of LEVEL 5 BY
/// CLASS (SPEC-H3 8.1): these
/// members read under the cut-off, so level 5 writes them over the
/// chains at 80 links; the eight rows of levels 1 to 4 were printed
/// beside them and had not moved.
///
/// The four RAR 5 rows of levels 2 to 5 were re-taken, by the same
/// print, on 8 Oct 2026, when the filter detector's estimate was written
/// to SPEC-G 3.8.2's rule: detection sends other filters over these
/// members (0.44 to 0.47 per cent larger on this generated set). Level 1
/// and the RAR 4 rows were printed beside and had not moved.
const PINNED: &[(&str, u8, &str)] = &[
    ("rar5", 1, "b27acb4239d0e3d2"),
    ("rar5", 2, "769ce86c9861ecc8"),
    ("rar5", 3, "9fd13c862ff1e61e"),
    ("rar5", 4, "88fcf20721a0731d"),
    ("rar5", 5, "ed0899f4535f7c3b"),
    ("rar4", 1, "d3f72a1069069b0e"),
    ("rar4", 2, "c60286cb9cc79939"),
    ("rar4", 3, "dd4b4d1364bdf630"),
    ("rar4", 4, "5f8fbd8f04016be5"),
    ("rar4", 5, "e96ed9037ac898f8"),
];

/// The shipped default dictionary, which is where a windowed member's
/// slack is the streamed one.
const DICTIONARY: u64 = 2 << 20;

/// The set: `SMALL` members of 4 to 24 KiB for the team, `MIDDLE` readers
/// of 300 KiB to 1.3 MiB for the lane, and one reader of 21 MiB, long
/// enough that its history slides at either slack.
const SMALL: usize = 160;
const MIDDLE: usize = 12;

fn members() -> Vec<Vec<u8>> {
    let mut rng = rarkit_testdata::Seeded::new(0xce11);
    let mut out: Vec<Vec<u8>> = (0..SMALL)
        .map(|at| {
            rarkit_testdata::medley(
                at as u64 + 11,
                (4 << 10) + rng.next_u32() as usize % (20 << 10),
            )
        })
        .collect();
    for at in 0..MIDDLE {
        out.push(rarkit_testdata::medley(
            at as u64 + 501,
            (300 << 10) + rng.next_u32() as usize % (1 << 20),
        ));
    }
    out.push(rarkit_testdata::medley(909, (21 << 20) + 4_099));
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

/// Writes the set: the small members as bytes in memory, the rest from
/// readers, which is what makes them a window at a time.
fn write(options: WriteOptions, members: &[Vec<u8>]) -> (Vec<u8>, WriteReport) {
    let mut writer = Writer::new(options).expect("options");
    let names: Vec<Vec<u8>> = (0..members.len())
        .map(|at| format!("m{at:03}.bin").into_bytes())
        .collect();
    let mut readers: Vec<Cursor<&[u8]>> = members[SMALL..]
        .iter()
        .map(|data| Cursor::new(&data[..]))
        .collect();
    for (at, data) in members[..SMALL].iter().enumerate() {
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
    for (at, reader) in readers.iter_mut().enumerate() {
        writer
            .add(MemberSpec {
                name: &names[SMALL + at],
                payload: Payload::Reader {
                    reader,
                    size: members[SMALL + at].len() as u64,
                    crc32: None,
                },
                mtime: None,
                attributes: 0o644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = Vec::new();
    let report = writer.finish_into(&mut out).expect("finish");
    (out, report)
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

/// What one write on a pool of `threads` showed: the archive, the report,
/// the team's crews, the widest staged flush and the slack the windowed
/// members ran at.
struct Seen {
    archive: Vec<u8>,
    report: WriteReport,
    crews: usize,
    /// The largest member the large-member lane took, or zero.
    reach: u64,
    flush: usize,
    slack: usize,
}

fn on_pool(threads: usize, options: WriteOptions, members: &[Vec<u8>]) -> Seen {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .expect("a pool");
    pool.install(|| {
        forget_widest_flush();
        let (archive, report) = write(options, members);
        Seen {
            archive,
            report,
            crews: team_crews(),
            reach: team_large().1,
            flush: widest_flush(),
            slack: last_streamed_slack(),
        }
    })
}

/// The stated peak is inside the limit the policy carries, and nothing
/// was reported over it.
fn inside(seen: &Seen, memory: &MemoryPolicy, what: &str) {
    assert!(
        seen.report.peak_working_memory <= memory.working_limit,
        "{what}: the write stated {} bytes against a limit of {}",
        seen.report.peak_working_memory,
        memory.working_limit
    );
    assert_eq!(
        seen.report.ceiling_exceeded_by, None,
        "{what}: the write reported its ceiling passed"
    );
}

#[test]
fn a_named_ceiling_steps_to_the_defaults_admission_at_512_mib() {
    let members = members();
    let print = std::env::var_os("RARKIT_PIN_PRINT").is_some();
    let formats = [
        ("rar5", WriteFormat::Rar5),
        ("rar4", WriteFormat::Rar4(rarkit::Rar4Version::V29)),
    ];
    const THREADS: usize = 12;
    let floor = MemoryPolicy::DEFAULT_LIMIT;
    let at = MemoryPolicy::from_limit(floor);
    let process = MemoryPolicy::for_process(floor, 24 << 20);
    let under = MemoryPolicy::from_limit(floor - 1);
    let mut missing = Vec::new();
    for (format_name, format) in formats {
        for level in 1..=5u8 {
            let what = format!("{format_name} m{level}");
            let named =
                |memory| on_pool(THREADS, options(format, level, THREADS, memory), &members);

            // One byte under: the path before the rule, and its archive.
            let below = named(under);
            inside(&below, &under, &format!("{what} under 512 MiB"));
            assert!(
                (2..=under.max_workers).contains(&below.crews),
                "{what}: under 512 MiB the team keeps max_workers ({} crews)",
                below.crews
            );
            assert!(
                below.flush <= 1,
                "{what}: under 512 MiB a flush is one window ({} staged)",
                below.flush
            );
            assert_eq!(
                below.slack, 4,
                "{what}: under 512 MiB the slack is the shipped one"
            );
            let sha = sha16(&below.archive);
            if print {
                println!("    (\"{format_name}\", {level}, \"{sha}\"),");
                continue;
            }
            reads_back(&below.archive, &members, &what);
            match PINNED
                .iter()
                .find(|row| row.0 == format_name && row.1 == level)
            {
                Some(row) => assert_eq!(
                    sha, row.2,
                    "{what}: under 512 MiB the archive is not the parent's named archive"
                ),
                None => missing.push(what.clone()),
            }

            // At 512 MiB, as an engine figure and as a process budget: the
            // default's admission and the default's archive.
            let default = named(MemoryPolicy::default());
            for (name, memory) in [("from_limit", at), ("for_process", process)] {
                let seen = named(memory);
                let what = format!("{what} at 512 MiB ({name})");
                inside(&seen, &memory, &what);
                assert!(
                    seen.archive == default.archive,
                    "{what}: not the default's archive ({} against {})",
                    sha16(&seen.archive),
                    sha16(&default.archive)
                );
                assert_eq!(
                    seen.slack, default.slack,
                    "{what}: the windowed members' slack is the default's"
                );
                // The chains stage their windows; the tree's flush is the
                // default's whatever it is.
                assert_eq!(
                    seen.flush, default.flush,
                    "{what}: a flush stages what the default's does"
                );
                // The lane's reach past a window is the one form a named
                // ceiling leaves off; where the default did not take it,
                // the team is the default's, crew for crew.
                assert!(
                    seen.reach <= DICTIONARY,
                    "{what}: the lane reached past a window ({} bytes)",
                    seen.reach
                );
                if name == "from_limit" && default.reach <= DICTIONARY {
                    assert_eq!(
                        seen.crews, default.crews,
                        "{what}: the team is the default's"
                    );
                }
            }
            eprintln!(
                "{what}: under: {} crews, slack {}; default: {} crews, flush {}, slack {}",
                below.crews, below.slack, default.crews, default.flush, default.slack
            );
        }
    }
    assert!(
        print || missing.is_empty(),
        "rows with no pinned digest: {missing:?}"
    );
}

#[test]
fn a_named_budget_holds_the_stated_peak_inside_it_at_every_width() {
    // 512 MiB, 1 GiB and 2 GiB as process budgets, levels 1, 3 and 5, on
    // pools of 1, 3, 8 and 32: the write's own peak is inside the working
    // limit the budget leaves, nothing is reported over, and the archive is
    // the same bytes at every width and budget (it is the default's).
    let members = members();
    for level in [1u8, 3, 5] {
        let mut first: Option<Vec<u8>> = None;
        for budget in [512u64 << 20, 1 << 30, 2 << 30] {
            let memory = MemoryPolicy::for_process(budget, 16 << 20);
            for threads in [1usize, 3, 8, 32] {
                let what = format!("m{level}, {} MiB, {threads} threads", budget >> 20);
                let seen = on_pool(
                    threads,
                    options(WriteFormat::Rar5, level, threads, memory),
                    &members,
                );
                inside(&seen, &memory, &what);
                match &first {
                    None => first = Some(seen.archive),
                    Some(first) => assert!(
                        &seen.archive == first,
                        "{what}: the budget or the width moved a byte"
                    ),
                }
            }
        }
    }
}

/// Writes the set as [`write`] does, into a volume set where the options
/// name a volume size and into one archive where they do not: the volumes
/// (or the one archive), and the report.
fn write_set(options: WriteOptions, members: &[Vec<u8>]) -> (Vec<Vec<u8>>, WriteReport) {
    let set = options.volume_size.is_some();
    let mut writer = Writer::new(options).expect("options");
    let names: Vec<Vec<u8>> = (0..members.len())
        .map(|at| format!("m{at:03}.bin").into_bytes())
        .collect();
    let mut readers: Vec<Cursor<&[u8]>> = members[SMALL..]
        .iter()
        .map(|data| Cursor::new(&data[..]))
        .collect();
    for (at, data) in members[..SMALL].iter().enumerate() {
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
    for (at, reader) in readers.iter_mut().enumerate() {
        writer
            .add(MemberSpec {
                name: &names[SMALL + at],
                payload: Payload::Reader {
                    reader,
                    size: members[SMALL + at].len() as u64,
                    crc32: None,
                },
                mtime: None,
                attributes: 0o644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    if !set {
        let mut out = Vec::new();
        let report = writer.finish_into(&mut out).expect("finish");
        return (vec![out], report);
    }
    let mut volumes: Vec<Vec<u8>> = Vec::new();
    let report = writer.finish_volumes(&mut volumes).expect("finish_volumes");
    (volumes, report)
}

#[test]
fn a_solid_run_and_a_volume_set_under_a_budget_are_the_defaults_archives() {
    // The timed rows and the step test are non-solid single archives. A
    // SOLID run and a VOLUME SET under a named budget of 512 MiB and 2 GiB
    // write the default policy's archive too, at levels 1, 3 and 5, with
    // the stated peak inside the working limit and nothing reported over.
    let members = members();
    const THREADS: usize = 12;
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(THREADS)
        .build()
        .expect("a pool");
    let shapes: [(&str, bool, Option<u64>); 2] =
        [("solid", true, None), ("volume set", false, Some(3 << 20))];
    for (shape, solid, volume_size) in shapes {
        for level in [1u8, 3, 5] {
            let with = |memory: MemoryPolicy| {
                pool.install(|| {
                    write_set(
                        WriteOptions {
                            solid,
                            volume_size,
                            ..options(WriteFormat::Rar5, level, THREADS, memory)
                        },
                        &members,
                    )
                })
            };
            let (default, _) = with(MemoryPolicy::default());
            if volume_size.is_some() {
                assert!(
                    default.len() > 2,
                    "{shape} m{level}: the set is one of several volumes ({})",
                    default.len()
                );
            }
            for budget in [512u64 << 20, 2 << 30] {
                let memory = MemoryPolicy::for_process(budget, 16 << 20);
                let what = format!("{shape} m{level} under {} MiB", budget >> 20);
                let (named, report) = with(memory);
                assert!(
                    report.peak_working_memory <= memory.working_limit,
                    "{what}: the write stated {} bytes against a limit of {}",
                    report.peak_working_memory,
                    memory.working_limit
                );
                assert_eq!(
                    report.ceiling_exceeded_by, None,
                    "{what}: the write reported its ceiling passed"
                );
                assert_eq!(
                    named.len(),
                    default.len(),
                    "{what}: not the default's volumes"
                );
                for (at, (a, b)) in named.iter().zip(&default).enumerate() {
                    assert!(
                        a == b,
                        "{what}: volume {at} is not the default's ({} against {})",
                        sha16(a),
                        sha16(b)
                    );
                }
            }
        }
    }
}

#[test]
fn a_member_streamed_under_a_named_ceiling_reserves_a_fragment_at_a_time() {
    // Spec G 3.5 (1 Oct 2026): a
    // case (b) member, of a NON-SOLID volume set, streamed under a named
    // ceiling takes the PER-FRAGMENT width of its packed size field, as
    // the default's streamed member does. The default is made to stream
    // the same member by the test's threshold; a 1 MiB dictionary keeps
    // the slack the shipped one on both sides, so the two archives are the
    // same packed stream and can differ only in that field.
    let member = rarkit_testdata::medley(1234, (6 << 20) + 77);
    let set = |memory: MemoryPolicy| {
        reset_streamed_members();
        let mut reader = Cursor::new(&member[..]);
        let mut writer = Writer::new(WriteOptions {
            method: WriteMethod::Compressed {
                level: 1,
                dictionary: Some(1 << 20),
            },
            volume_size: Some(400 << 10),
            host_os: rarkit::HostOs::Unix,
            memory,
            workers: Some(4),
            ..WriteOptions::default()
        })
        .expect("options");
        writer
            .add(MemberSpec {
                name: b"long.bin",
                payload: Payload::Reader {
                    reader: &mut reader,
                    size: member.len() as u64,
                    crc32: None,
                },
                mtime: None,
                attributes: 0o644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
        // `Vec<Vec<u8>>` can patch, so a member over the threshold streams.
        let mut volumes: Vec<Vec<u8>> = Vec::new();
        writer.finish_volumes(&mut volumes).expect("finish_volumes");
        (volumes, streamed_members())
    };
    // A ceiling the member's held-whole sum passes: it streams.
    let ceiling = 24u64 << 20;
    let (named, named_streamed) = set(MemoryPolicy::from_limit(ceiling));
    let (default, default_streamed) = with_stream_above(ceiling, || set(MemoryPolicy::default()));
    assert_eq!(
        (named_streamed, default_streamed),
        (1, 1),
        "both arms stream the member"
    );
    assert!(
        named.len() > 3,
        "the member is cut over several volumes ({})",
        named.len()
    );
    assert_eq!(
        named.len(),
        default.len(),
        "the two sets have the same volumes"
    );
    for (at, (a, b)) in named.iter().zip(&default).enumerate() {
        assert!(
            a == b,
            "volume {at}: the named set's fragment header is not the default's ({} and {} bytes)",
            a.len(),
            b.len()
        );
    }
}
