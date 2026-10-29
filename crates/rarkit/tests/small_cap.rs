//! The DEFAULT policy under a memory limit below the 512 MiB floor that
//! nobody named: what an environment's cap (a cgroup limit, a finite
//! address space) leaves `MemoryPolicy::process_default` (SPEC-API 8.1
//! term 2; spec G 3.7.3).
//!
//! **What the rows say.**
//!
//! - Under such a limit the writer takes the default's own admission where
//!   its plan fits, and otherwise the small named path's byte-neutral
//!   dials: one window a flush, the lead's hold and parses, a team sized
//!   from what a crew holds. A solid run and a storing level choose
//!   nothing and run as they did.
//! - NO TOKEN MOVES at any cap, level or rung: the history slack is the
//!   default's whatever the cap. The archive is the uncapped default's,
//!   byte for byte, RAR 5 and the RAR 4 family, solid and not, held and
//!   streamed, with a password under a seeded entropy; EXCEPT the packed
//!   size field of a member the cap forces to stream, which spec G 3.5
//!   names (1 or 2 bytes a member or fragment, every data byte the same):
//!   pinned by a member built to trigger it, and seen in the volume set's
//!   rows at level 1.
//! - Where a plan fits, the write's stated peak is inside the limit; where
//!   none does, a hold is taken (one window at the tree's levels where
//!   the cap certainly admits it, else the one that holds least), never
//!   the default's unheld run.
//! - Where the policy carries an environment's cap and what the lead
//!   certainly holds cannot fit it, the write is refused before its first
//!   byte, with nothing written.
//! - At a budget of 512 MiB and above nothing here runs: no rung is
//!   chosen and the run is the default's.
//!
//! The policies are built as `process_default` builds them under a cgroup
//! cap, from the cap's figure, so the rows run on a box with no cap; the
//! process's own peak under a real `MemoryMax` is counted from the boxes
//! (1 Oct 2026).

use std::io::Cursor;
use std::sync::Arc;

use rarkit::{
    extract, Disposition, Entropy, ErrorKind, FilterPolicy, MemberInfo, MemberOutcome, MemberSpec,
    MemoryPolicy, Password, Payload, RangeSource, ReadOptions, Resource, Sink, WriteFormat,
    WriteMethod, WriteOptions, WriteReport, Writer,
};

use rarkit::internals::writers::{
    forget_rung, forget_widest_flush, last_chosen_hold, last_rung, last_streamed_slack, team_crews,
    widest_flush,
};

const MIB: u64 = 1 << 20;

/// The shipped default dictionary, where a windowed member's slack is the
/// streamed one.
const DICTIONARY: u64 = 2 << 20;

/// The set: `SMALL` members of 4 to 24 KiB for the team, `MIDDLE` readers
/// of 300 KiB to 1.3 MiB, and one reader of 21 MiB, long enough that its
/// history slides at the default's slack.
const SMALL: usize = 120;
const MIDDLE: usize = 8;

fn members() -> Vec<Vec<u8>> {
    let mut rng = rarkit_testdata::Seeded::new(0x5ca9);
    let mut out: Vec<Vec<u8>> = (0..SMALL)
        .map(|at| {
            rarkit_testdata::medley(
                at as u64 + 31,
                (4 << 10) + rng.next_u64() as usize % (20 << 10),
            )
        })
        .collect();
    for at in 0..MIDDLE {
        out.push(rarkit_testdata::medley(
            at as u64 + 701,
            (300 << 10) + rng.next_u64() as usize % (1 << 20),
        ));
    }
    out.push(rarkit_testdata::medley(919, (21 << 20) + 4_099));
    out
}

/// What `MemoryPolicy::process_default` derives under a cgroup limit of
/// `cap` bytes with `resident` bytes held by the caller: the budget is the
/// larger of three quarters of the cap and the cap less 96 MiB, the
/// working limit that budget less the process's overhead, every other
/// field the default's, and the limit NOT named.
fn capped(cap: u64, resident: u64) -> MemoryPolicy {
    let budget = (cap / 4 * 3).max(cap.saturating_sub(96 * MIB));
    let process = MemoryPolicy::for_process(budget, resident);
    MemoryPolicy {
        working_limit: process.working_limit,
        process_overhead: process.process_overhead,
        environment_cap: cap,
        ..MemoryPolicy::default()
    }
}

/// What the command line holds beside the writer at twelve threads.
const RESIDENT: u64 = 12 * MIB;

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

/// How the archive leaves the writer.
#[derive(Clone, Copy, PartialEq)]
enum Out {
    /// An output that cannot be patched: a long member is held whole.
    Held,
    /// A seekable output: a long member the limit cannot hold is streamed.
    Seek,
    /// A volume set of 3 MiB volumes.
    Volumes,
}

/// Writes the set: the small members as bytes in memory, the rest from
/// readers, which is what makes them a window at a time.
/// A write's volumes and report, or its error with how many bytes had
/// reached the output.
type Written = Result<(Vec<Vec<u8>>, WriteReport), (rarkit::Error, usize)>;

fn write(options: WriteOptions, members: &[Vec<u8>], out: Out) -> Written {
    let mut writer = Writer::new(options).expect("options");
    let names: Vec<Vec<u8>> = (0..members.len())
        .map(|at| format!("m{at:03}.bin").into_bytes())
        .collect();
    // A set of at most `SMALL` members is all readers.
    let small = if members.len() > SMALL { SMALL } else { 0 };
    let mut readers: Vec<Cursor<&[u8]>> = members[small..]
        .iter()
        .map(|data| Cursor::new(&data[..]))
        .collect();
    for (at, data) in members[..small].iter().enumerate() {
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
                name: &names[small + at],
                payload: Payload::Reader {
                    reader,
                    size: members[small + at].len() as u64,
                    crc32: None,
                },
                mtime: None,
                attributes: 0o644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    // A refusal comes back with how many bytes had reached the output.
    match out {
        Out::Held => {
            let mut bytes = Vec::new();
            match writer.finish_into(&mut bytes) {
                Ok(report) => Ok((vec![bytes], report)),
                Err(error) => Err((error, bytes.len())),
            }
        }
        Out::Seek => {
            let mut bytes = Cursor::new(Vec::new());
            match writer.finish_seek(&mut bytes) {
                Ok(report) => Ok((vec![bytes.into_inner()], report)),
                Err(error) => Err((error, bytes.into_inner().len())),
            }
        }
        Out::Volumes => {
            let mut volumes: Vec<Vec<u8>> = Vec::new();
            match writer.finish_volumes(&mut volumes) {
                Ok(report) => Ok((volumes, report)),
                Err(error) => Err((error, volumes.iter().map(Vec::len).sum())),
            }
        }
    }
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

fn reads_back(archive: &[Vec<u8>], members: &[Vec<u8>], password: Option<&str>, what: &str) {
    let sources: Vec<Arc<dyn RangeSource>> = archive
        .iter()
        .map(|volume| Arc::new(volume.clone()) as Arc<dyn RangeSource>)
        .collect();
    let options = ReadOptions::default().with_password(password.map(Password::new));
    let mut sink = Collect::default();
    extract(sources, &options, &mut sink, &mut ())
        .unwrap_or_else(|e| panic!("{what}: rarkit could not read it back: {e}"));
    assert!(
        sink.0 == members.concat(),
        "{what}: the members came back different"
    );
}

/// What one write on a pool of `threads` showed.
struct Seen {
    archive: Vec<Vec<u8>>,
    report: WriteReport,
    /// The rung chosen: `None` where no small unnamed limit applied.
    rung: Option<bool>,
    hold: Option<Option<usize>>,
    crews: usize,
    flush: usize,
    slack: usize,
}

/// One write on a pool of `threads`: what it showed, or `None` where it
/// was REFUSED before its first byte because no plan fits the
/// environment's cap, which is checked here: the named error, the cap as
/// its limit, more needed than the cap, and nothing written.
fn try_on_pool(
    threads: usize,
    options: WriteOptions,
    members: &[Vec<u8>],
    out: Out,
) -> Option<Seen> {
    let cap = options.memory.environment_cap;
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .expect("a pool");
    pool.install(|| {
        forget_widest_flush();
        forget_rung();
        match write(options, members, out) {
            Ok((archive, report)) => Some(Seen {
                archive,
                report,
                rung: last_rung(),
                hold: last_chosen_hold(),
                crews: team_crews(),
                flush: widest_flush(),
                slack: last_streamed_slack(),
            }),
            Err((error, written)) => {
                match error.kind() {
                    ErrorKind::LimitExceeded {
                        resource: Resource::WorkingMemory,
                        needed,
                        limit,
                    } => {
                        assert!(cap > 0, "a write with no environment cap was refused");
                        assert_eq!(*limit, cap, "the refusal names another limit");
                        assert!(*needed > cap, "refused though {needed} fits {cap}");
                        eprintln!(
                            "REFUSED under {} MiB: needs {} MiB",
                            cap >> 20,
                            needed >> 20
                        );
                    }
                    other => panic!("the write failed otherwise: {other:?}"),
                }
                assert_eq!(written, 0, "a refused write left bytes behind");
                None
            }
        }
    })
}

fn on_pool(threads: usize, options: WriteOptions, members: &[Vec<u8>], out: Out) -> Seen {
    try_on_pool(threads, options, members, out).expect("the write was refused")
}

const THREADS: usize = 12;

/// One capped write against the uncapped default's: the same bytes, the
/// default's slack, the stated peak inside the limit where the rung's
/// plan fits, and where the narrow rung ran, its dials.
fn check(what: &str, seen: &Seen, default: &Seen, memory: &MemoryPolicy) {
    assert!(
        seen.archive == default.archive,
        "{what}: the archive is not the uncapped default's"
    );
    assert_eq!(
        seen.report.ceiling_exceeded_by, None,
        "{what}: an unnamed limit is not a ceiling the caller chose"
    );
    let rung = seen
        .rung
        .unwrap_or_else(|| panic!("{what}: no rung was chosen under a small unnamed limit"));
    if rung {
        assert!(
            seen.flush <= 1,
            "{what}: the narrow rung staged {} windows a flush",
            seen.flush
        );
        assert_eq!(
            seen.slack, default.slack,
            "{what}: the narrow rung moved the history slack"
        );
        let held = seen.hold.flatten().is_some();
        assert!(
            seen.report.peak_working_memory <= memory.working_limit || held || seen.crews >= 2,
            "{what}: the narrow rung stated {} bytes over a limit of {} with no hold and no team",
            seen.report.peak_working_memory,
            memory.working_limit
        );
    } else if seen.report.peak_working_memory > memory.working_limit {
        eprintln!(
            "OVER {what}: the default's admission was taken and stated {} MiB against a limit of {} MiB",
            seen.report.peak_working_memory >> 20,
            memory.working_limit >> 20
        );
    }
}

#[test]
fn a_capped_default_writes_the_uncapped_archive_at_every_level_and_cap() {
    let members = members();
    let formats = [
        ("rar5", WriteFormat::Rar5, &[1u8, 2, 3, 4, 5][..]),
        (
            "rar4",
            WriteFormat::Rar4(rarkit::Rar4Version::V29),
            &[1u8, 3, 5][..],
        ),
    ];
    for (format_name, format, levels) in formats {
        for &level in levels {
            let run = |memory, out| {
                on_pool(
                    THREADS,
                    options(format, level, THREADS, memory),
                    &members,
                    out,
                )
            };
            for out in [Out::Held, Out::Seek] {
                let default = run(MemoryPolicy::default(), out);
                assert_eq!(default.rung, None, "the uncapped default chose a rung");
                let kind = if out == Out::Held { "held" } else { "seekable" };
                reads_back(
                    &default.archive,
                    &members,
                    None,
                    &format!("{format_name} m{level} {kind} uncapped"),
                );
                for cap in [96u64, 128, 192, 256, 384, 512] {
                    let memory = capped(cap * MIB, RESIDENT);
                    let what = format!("{format_name} m{level} {kind} under {cap} MiB");
                    let Some(seen) = try_on_pool(
                        THREADS,
                        options(format, level, THREADS, memory),
                        &members,
                        out,
                    ) else {
                        // No plan fits the cap: refused before a byte, and
                        // only under the two smallest caps.
                        assert!(cap <= 128, "{what}: refused");
                        eprintln!("{what}: REFUSED");
                        continue;
                    };
                    check(&what, &seen, &default, &memory);
                    eprintln!(
                        "{what}: limit {} MiB, stated {} MiB, rung {:?}, hold {:?}, {} crews, flush {}",
                        memory.working_limit >> 20,
                        seen.report.peak_working_memory >> 20,
                        seen.rung,
                        seen.hold,
                        seen.crews,
                        seen.flush
                    );
                }
            }
        }
    }
}

#[test]
fn a_budget_of_512_mib_and_above_is_the_defaults_run() {
    // A cgroup limit of 608 MiB leaves a budget of exactly 512 MiB, and one
    // of 1 GiB leaves 928 MiB: no rung is chosen, and the archive, the
    // flush and the slack are the default's. The team is the default's
    // wherever the default's own team fits the smaller limit.
    let members = members();
    for level in [1u8, 3, 5] {
        let run = |memory| {
            on_pool(
                THREADS,
                options(WriteFormat::Rar5, level, THREADS, memory),
                &members,
                Out::Seek,
            )
        };
        let default = run(MemoryPolicy::default());
        for cap in [608u64, 1024] {
            let memory = capped(cap * MIB, RESIDENT);
            assert!(
                memory.working_limit + memory.process_overhead >= MemoryPolicy::DEFAULT_LIMIT,
                "a {cap} MiB cap leaves a budget under the floor"
            );
            let seen = run(memory);
            let what = format!("m{level} under {cap} MiB");
            assert_eq!(
                seen.rung, None,
                "{what}: a rung was chosen at the floor's budget"
            );
            assert!(
                seen.archive == default.archive,
                "{what}: not the default's archive"
            );
            assert_eq!(seen.flush, default.flush, "{what}: the flush moved");
            assert_eq!(seen.slack, default.slack, "{what}: the slack moved");
            assert_eq!(seen.hold, default.hold, "{what}: a hold was chosen");
        }
    }
}

#[test]
fn a_solid_run_and_a_volume_set_under_a_cap_are_the_uncapped_archives() {
    let members = members();
    let shapes: [(&str, bool, Out); 2] = [
        ("solid", true, Out::Seek),
        ("volume set", false, Out::Volumes),
    ];
    for (shape, solid, out) in shapes {
        for level in [1u8, 3, 5] {
            let run = |memory| {
                let mut options = options(WriteFormat::Rar5, level, THREADS, memory);
                options.solid = solid;
                if out == Out::Volumes {
                    options.volume_size = Some(3 << 20);
                }
                try_on_pool(THREADS, options, &members, out)
            };
            let default = run(MemoryPolicy::default()).expect("the uncapped write");
            reads_back(
                &default.archive,
                &members,
                None,
                &format!("{shape} m{level} uncapped"),
            );
            for cap in [96u64, 192, 384] {
                let memory = capped(cap * MIB, RESIDENT);
                let what = format!("{shape} m{level} under {cap} MiB");
                let Some(seen) = run(memory) else {
                    assert!(cap <= 128, "{what}: refused");
                    eprintln!("{what}: REFUSED");
                    continue;
                };
                if seen.archive != default.archive {
                    // Spec G 3.5's one exception: the long member, which
                    // the cap forces to stream, reserves its packed size
                    // field in each fragment's header. Nothing else may
                    // differ: the same volumes, a byte or two a fragment,
                    // and the members read back the same.
                    assert!(!solid, "{what}: the archive is not the uncapped default's");
                    let total = |set: &[Vec<u8>]| set.iter().map(Vec::len).sum::<usize>();
                    let (capped_bytes, default_bytes) =
                        (total(&seen.archive), total(&default.archive));
                    eprintln!(
                        "{what}: {} volumes of {capped_bytes} bytes against {} of {default_bytes}",
                        seen.archive.len(),
                        default.archive.len()
                    );
                    assert!(
                        capped_bytes >= default_bytes
                            && capped_bytes - default_bytes <= 2 * seen.archive.len(),
                        "{what}: more than the packed size fields moved"
                    );
                    reads_back(&seen.archive, &members, None, &what);
                }
                assert_eq!(seen.report.ceiling_exceeded_by, None, "{what}");
                if solid {
                    // A solid run chooses no rung: the default's path at
                    // every limit, as on main (its own sum is not done yet).
                    assert_eq!(seen.rung, None, "{what}: a solid run chose a rung");
                    assert_eq!(seen.hold, default.hold, "{what}: a solid run took a hold");
                }
                eprintln!(
                    "{what}: limit {} MiB, stated {} MiB (uncapped {} MiB), rung {:?}, hold {:?}",
                    memory.working_limit >> 20,
                    seen.report.peak_working_memory >> 20,
                    default.report.peak_working_memory >> 20,
                    seen.rung,
                    seen.hold
                );
            }
        }
    }
}

#[test]
fn a_password_under_a_cap_is_the_uncapped_archive_under_the_same_entropy() {
    // `-p` and `-hp`: with the entropy seeded, the capped archive is the
    // uncapped one byte for byte, and it reads back.
    let members = members();
    for headers in [false, true] {
        for level in [1u8, 5] {
            let run = |memory| {
                let mut options = options(WriteFormat::Rar5, level, THREADS, memory);
                options.password = Some(Password::new("a small cap"));
                options.encrypt_headers = headers;
                options.entropy = Entropy::Seeded([7; 32]);
                try_on_pool(THREADS, options, &members, Out::Seek)
            };
            let default = run(MemoryPolicy::default()).expect("the uncapped write");
            for cap in [96u64, 256] {
                let memory = capped(cap * MIB, RESIDENT);
                let what = format!("headers {headers} m{level} under {cap} MiB");
                let Some(seen) = run(memory) else {
                    assert!(cap <= 128, "{what}: refused");
                    eprintln!("{what}: REFUSED");
                    continue;
                };
                assert!(
                    seen.archive == default.archive,
                    "{what}: the encrypted archive is not the uncapped one"
                );
                reads_back(&seen.archive, &members, Some("a small cap"), &what);
            }
        }
    }
}

#[test]
fn a_stored_run_under_a_cap_chooses_nothing() {
    // A storing level has no encoder to admit: no rung, the same archive.
    let members = members();
    let run = |memory| {
        let options = WriteOptions {
            method: WriteMethod::Stored,
            host_os: rarkit::HostOs::Unix,
            memory,
            workers: Some(THREADS),
            ..WriteOptions::default()
        };
        on_pool(THREADS, options, &members, Out::Seek)
    };
    let default = run(MemoryPolicy::default());
    for cap in [96u64, 256] {
        let seen = run(capped(cap * MIB, RESIDENT));
        assert_eq!(seen.rung, None, "a stored run chose a rung under {cap} MiB");
        assert!(
            seen.archive == default.archive,
            "the stored archive moved under {cap} MiB"
        );
    }
}

#[test]
fn a_cap_no_plan_fits_refuses_before_the_first_byte() {
    // Under a cap of 32 MiB no plan of a compressing level fits: the write
    // is refused as `LimitExceeded { WorkingMemory }` with the cap as its
    // limit and nothing written, on every kind of output (`try_on_pool`
    // checks each). The same policy with NO environment cap (a library
    // caller's own small allowance) is not refused: it runs its narrowest
    // plan, as a job the reference would do is never failed on a policy of
    // rarkit's. And a storing level under the cap is written.
    let members = members();
    let tiny = capped(32 * MIB, 0);
    for level in [1u8, 3, 5] {
        for out in [Out::Held, Out::Seek, Out::Volumes] {
            let mut options = options(WriteFormat::Rar5, level, THREADS, tiny);
            if out == Out::Volumes {
                options.volume_size = Some(3 << 20);
            }
            assert!(
                try_on_pool(THREADS, options, &members, out).is_none(),
                "m{level}: a create under a 32 MiB cap was not refused"
            );
        }
        let allowance = MemoryPolicy {
            environment_cap: 0,
            ..tiny
        };
        let seen = on_pool(
            THREADS,
            options(WriteFormat::Rar5, level, THREADS, allowance),
            &members,
            Out::Seek,
        );
        assert_eq!(seen.rung, Some(true), "m{level}: the allowance took a rung");
    }
    let stored = WriteOptions {
        method: WriteMethod::Stored,
        host_os: rarkit::HostOs::Unix,
        memory: tiny,
        workers: Some(THREADS),
        ..WriteOptions::default()
    };
    on_pool(THREADS, stored, &members, Out::Seek);
}

#[test]
fn a_member_the_cap_forces_to_stream_moves_only_its_packed_size_field() {
    // Spec G 3.5: the default holds a member whose held-whole write fits
    // the floor's working limit and streams it otherwise, and an
    // environment's cap below the floor lowers that limit: "a box that
    // cannot hold the member must stream it, and such a cap is then the
    // ONE thing besides the options that can move those packed size field
    // bytes". A streamed member's field is reserved; where its packed size
    // needs fewer bytes than its unpacked size, the reserved field is 1 or
    // 2 bytes wider than the held member's.
    //
    // One 40 MiB member of a repeated phrase: held by the uncapped default
    // (its packed size, a few hundred KiB, takes a 3 byte field), streamed
    // under a 192 MiB cap (the field reserved for its 40 MiB). The archive
    // grows by that field's bytes and by NOTHING else: every byte after
    // the member's header is the uncapped archive's.
    use rarkit::internals::writers::{reset_streamed_members, streamed_members};
    let member: Vec<u8> = b"a member the cap forces to stream, word for word. "
        .iter()
        .copied()
        .cycle()
        .take(40 << 20)
        .collect();
    let one = |memory: MemoryPolicy| {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(THREADS)
            .build()
            .expect("a pool");
        pool.install(|| {
            reset_streamed_members();
            let mut writer =
                Writer::new(options(WriteFormat::Rar5, 3, THREADS, memory)).expect("options");
            let mut reader = Cursor::new(&member[..]);
            writer
                .add(MemberSpec {
                    name: b"long.txt",
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
            let mut bytes = Cursor::new(Vec::new());
            writer.finish_seek(&mut bytes).expect("finish_seek");
            (bytes.into_inner(), streamed_members())
        })
    };
    let (held, held_streamed) = one(MemoryPolicy::default());
    let (streamed, cap_streamed) = one(capped(192 * MIB, RESIDENT));
    assert_eq!(held_streamed, 0, "the uncapped default streamed the member");
    assert_eq!(cap_streamed, 1, "the cap did not stream the member");
    let wider = streamed.len() - held.len();
    assert!(
        (1..=2).contains(&wider),
        "the streamed archive is {wider} bytes longer than the held one"
    );
    // Everything after the member's header: the packed bytes and the end
    // of the archive, identical.
    let tail = held.len() - 256;
    assert!(
        held[held.len() - tail..] == streamed[streamed.len() - tail..],
        "bytes other than the packed size field moved"
    );
    for archive in [&held, &streamed] {
        let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(archive.clone())];
        let mut sink = Collect::default();
        extract(sources, &ReadOptions::default(), &mut sink, &mut ()).expect("reads back");
        assert!(sink.0 == member, "the member came back different");
    }
}

#[test]
fn where_no_hold_fits_the_tree_takes_one_window_the_cap_admits() {
    // Spec G 3.7.3: where no hold fits a small limit nobody named, at the
    // tree's levels with no worker team, the lead holds ONE WINDOW where
    // the environment's cap certainly admits it, and otherwise the hold
    // that holds least. One 40 MiB member at level 5 under a working
    // limit of 28 MiB: with a 96 MiB cap on the policy the hold is one
    // window; with the same limit and NO cap (a library caller who lowered
    // `working_limit`) it is the least, a narrower one. Neither moves a
    // byte: the two archives are one.
    let member: Vec<u8> = rarkit_testdata::medley(77, 40 << 20);
    let one = |memory: MemoryPolicy| {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(THREADS)
            .build()
            .expect("a pool");
        pool.install(|| {
            forget_rung();
            let mut writer =
                Writer::new(options(WriteFormat::Rar5, 5, THREADS, memory)).expect("options");
            let mut reader = Cursor::new(&member[..]);
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
            let mut bytes = Cursor::new(Vec::new());
            writer.finish_seek(&mut bytes).expect("finish_seek");
            (
                bytes.into_inner(),
                last_rung(),
                last_chosen_hold().flatten(),
            )
        })
    };
    let under_cap = capped(96 * MIB, RESIDENT);
    let no_cap = MemoryPolicy {
        environment_cap: 0,
        ..under_cap
    };
    let (capped_bytes, capped_rung, capped_hold) = one(under_cap);
    let (bare_bytes, bare_rung, bare_hold) = one(no_cap);
    assert_eq!(
        capped_rung,
        Some(true),
        "the capped run took no narrow rung"
    );
    assert_eq!(
        bare_rung,
        Some(true),
        "the run with no cap took no narrow rung"
    );
    let (Some(window), Some(least)) = (capped_hold, bare_hold) else {
        panic!("a run held nothing: {capped_hold:?} under the cap, {bare_hold:?} with none");
    };
    assert!(
        window > least,
        "under the cap the hold is {window} bytes, with no cap {least}: not a window over the least"
    );
    assert!(capped_bytes == bare_bytes, "the hold moved a byte");
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(capped_bytes)];
    let mut sink = Collect::default();
    extract(sources, &ReadOptions::default(), &mut sink, &mut ()).expect("reads back");
    assert!(sink.0 == member, "the member came back different");
}

#[test]
fn a_512_mib_cap_admits_level_5_at_a_32_mib_dictionary() {
    // Level 5 picks a member's finder by its class, read from its head:
    // the tree (320 MiB at a 32 MiB dictionary) or the chains (260 MiB).
    // The refusal weighs ONE of them, the larger, with the hints and the
    // carried history: 428 MiB with the process's room, which a 512 MiB
    // cap admits. It weighed both, 688 MiB, and refused under every cap
    // from 512 to 607 MiB a create that completes (counted under real
    // cgroup limits, 3 Oct 2026).
    //
    // One 40 MiB member of each class: admitted on the narrow rung, the
    // uncapped default's bytes, and the stated peak inside the cap. Under
    // a 256 MiB cap, which holds neither finder, the same create is still
    // refused before its first byte (`try_on_pool` checks the error).
    let at_32_mib = |memory: MemoryPolicy| WriteOptions {
        method: WriteMethod::Compressed {
            level: 5,
            dictionary: Some(32 << 20),
        },
        ..options(WriteFormat::Rar5, 5, THREADS, memory)
    };
    let cap = 512 * MIB;
    let under_cap = capped(cap, RESIDENT);
    for (what, member) in [
        ("the chains' class", rarkit_testdata::medley(77, 40 << 20)),
        (
            "the tree's class",
            rarkit_testdata::chatter_of(78, 1 << 15, 40 << 20),
        ),
    ] {
        let members = [member];
        let default = on_pool(
            THREADS,
            at_32_mib(MemoryPolicy::default()),
            &members,
            Out::Seek,
        );
        let seen = try_on_pool(THREADS, at_32_mib(under_cap), &members, Out::Seek)
            .unwrap_or_else(|| panic!("{what}: -m5 -md32m was refused under a 512 MiB cap"));
        assert_eq!(
            seen.rung,
            Some(true),
            "{what}: no narrow rung under the cap"
        );
        assert!(
            seen.archive == default.archive,
            "{what}: the archive is not the uncapped default's"
        );
        assert_eq!(
            seen.slack, default.slack,
            "{what}: the cap moved the history slack"
        );
        eprintln!(
            "{what}: stated {} MiB under a cap of {} MiB, hold {:?}",
            seen.report.peak_working_memory >> 20,
            cap >> 20,
            seen.hold
        );
        assert!(
            seen.report.peak_working_memory <= cap,
            "{what}: the admitted run stated {} bytes over the cap of {cap}",
            seen.report.peak_working_memory
        );
        reads_back(&seen.archive, &members, None, what);
        assert!(
            try_on_pool(
                THREADS,
                at_32_mib(capped(256 * MIB, RESIDENT)),
                &members,
                Out::Seek
            )
            .is_none(),
            "{what}: -m5 -md32m under a 256 MiB cap was not refused"
        );
    }
}

#[test]
fn a_cap_no_plan_fits_holds_the_chains_parses_in_flight() {
    // Where an environment's cap binds and no plan fits the limit under
    // it, the run is admitted past its narrow rung and the chains' wave
    // is held to the widest that leaves a tenth of the cap free
    // (`Run::parses_under_cap`): at a 32 MiB dictionary a held wave does
    // not bound the parses in flight, and on 96 threads levels 3 to 5
    // stood at a 512 MiB cap itself and were killed on a busy box.
    //
    // One 104 MiB member at level 3 and a 32 MiB dictionary, long enough
    // that its history runs to the full slack, on twelve threads, whose
    // unheld wave is twelve parses: under a 480 MiB cap the wave is held
    // (to its least, eight blocks) and the stated peak is under that of
    // the same limit with NO cap on the policy (a library caller's own
    // allowance, whose run is not moved); under 512 MiB the twelve fit
    // and nothing is held. The archive is the uncapped default's in all.
    let at_32_mib = |memory: MemoryPolicy| WriteOptions {
        method: WriteMethod::Compressed {
            level: 3,
            dictionary: Some(32 << 20),
        },
        ..options(WriteFormat::Rar5, 3, THREADS, memory)
    };
    let cap = 480 * MIB;
    let under_cap = capped(cap, RESIDENT);
    let allowance = MemoryPolicy {
        environment_cap: 0,
        ..under_cap
    };
    let members = [rarkit_testdata::medley(79, 104 << 20)];
    let default = on_pool(
        THREADS,
        at_32_mib(MemoryPolicy::default()),
        &members,
        Out::Seek,
    );
    let held = on_pool(THREADS, at_32_mib(under_cap), &members, Out::Seek);
    let unheld = on_pool(THREADS, at_32_mib(allowance), &members, Out::Seek);
    for (what, seen) in [("under the cap", &held), ("the allowance", &unheld)] {
        assert_eq!(seen.rung, Some(true), "{what}: no narrow rung");
        assert!(
            seen.archive == default.archive,
            "{what}: the archive is not the uncapped default's"
        );
    }
    eprintln!(
        "stated {} MiB under the cap, {} MiB with the same limit and no cap",
        held.report.peak_working_memory >> 20,
        unheld.report.peak_working_memory >> 20
    );
    assert!(
        held.report.peak_working_memory < unheld.report.peak_working_memory,
        "the cap held nothing: {} bytes stated against {} with no cap",
        held.report.peak_working_memory,
        unheld.report.peak_working_memory
    );
    assert!(
        held.report.peak_working_memory <= cap / 10 * 9,
        "the held run stated {} bytes, over nine tenths of the cap of {cap}",
        held.report.peak_working_memory
    );
    reads_back(&held.archive, &members, None, "under the cap");
    // Under 512 MiB twelve parses fit nine tenths of the cap and are not
    // held: the run states more than the held one does under 480 MiB.
    let fits = on_pool(
        THREADS,
        at_32_mib(capped(512 * MIB, RESIDENT)),
        &members,
        Out::Seek,
    );
    assert!(
        fits.archive == default.archive,
        "under 512 MiB: the archive is not the uncapped default's"
    );
    assert!(
        fits.report.peak_working_memory > held.report.peak_working_memory,
        "under 512 MiB on twelve threads the wave was held: {} bytes stated against {} held",
        fits.report.peak_working_memory,
        held.report.peak_working_memory
    );
}

/// PROBE (not a gate): what the default's admission plans against what it
/// states at levels 3 and 5 under a 256 MiB cap, by the windows a flush
/// may stage. Run by hand with RARKIT_RUNG_SAY=1.
#[test]
#[ignore = "a probe, run by hand with RARKIT_RUNG_SAY=1"]
fn probe_plan_against_stated_by_staged_depth() {
    let members = members();
    for level in [3u8, 5] {
        for threads in [1usize, 12] {
            for depth in [1usize, 2, 4, 8] {
                let memory = capped(256 * MIB, RESIDENT);
                let pool = rayon::ThreadPoolBuilder::new()
                    .num_threads(threads)
                    .build()
                    .expect("a pool");
                let (report, flush) = pool.install(|| {
                    rarkit::internals::writers::with_window_depth(depth, || {
                        forget_widest_flush();
                        let (_, report) = write(
                            options(WriteFormat::Rar5, level, threads, memory),
                            &members,
                            Out::Seek,
                        )
                        .unwrap_or_else(|(error, _)| panic!("{error}"));
                        (report, widest_flush())
                    })
                });
                eprintln!(
                    "m{level} {threads} threads, depth {depth}: limit {} MiB, stated {} MiB, rung {:?}, flush {flush}",
                    memory.working_limit >> 20,
                    report.peak_working_memory >> 20,
                    last_rung(),
                );
            }
        }
    }
}
