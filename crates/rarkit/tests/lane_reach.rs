//! The LARGE-MEMBER LANE'S REACH (`write::engine`'s `Run::choose_large_lane`):
//! in a non-solid run with no ceiling named, reader members longer than
//! one window and up to the lane's reach are pulled whole and encoded by
//! crews of the worker team, several at once, where the writing thread
//! encoded them one at a time.
//!
//! **What is held here.** That the reach is a WIDTH and never a byte: the
//! same members at the same options are the same archive at every reach,
//! none included, which is the writer before the lane reached past a
//! window (API promise 2.6). Covered: both archive formats; levels 1 to 5
//! (a crew encodes with the held walk's own calls, whatever the finder);
//! a filter plan; members of a window and a bit, of several windows, and
//! one longer than the history runs before it slides; members the store
//! rule's samples store; members in memory beside readers; a member above
//! the reach, which stays the writing thread's; the shipped dictionary
//! with the streamed slack. And that the lane really took the members:
//! the crews and the reach of the walk are read back. And the rule by
//! cores: the long reach on a wide pool, the short one at levels 2 and 3 on
//! a narrow one (8 MiB on x86-64, a MiB a core up to 8 MiB elsewhere), none at levels 4 and 5 or in a volume set of readers.
use std::io::Cursor;
use std::sync::Arc;

use rarkit::internals::writers::{
    team_large, with_lane_reach, with_segment_width, with_team_cores,
};
use rarkit::{
    extract, ChecksumKind, Disposition, FilterPolicy, MemberInfo, MemberOutcome, MemberSpec,
    MemoryPolicy, Payload, RangeSource, Rar4Version, ReadOptions, Sink, VolumeOut, WriteFormat,
    WriteMethod, WriteOptions, Writer,
};

fn options(format: WriteFormat, level: u8, dictionary: Option<u64>) -> WriteOptions {
    WriteOptions {
        format,
        method: WriteMethod::Compressed { level, dictionary },
        // The RAR 4 family refuses a filter request (SPEC-J).
        filters: if matches!(format, WriteFormat::Rar4(_)) {
            FilterPolicy::Off
        } else {
            FilterPolicy::Detect
        },
        host_os: rarkit::HostOs::Unix,
        order: rarkit::MemberOrder::AsAdded,
        workers: Some(4),
        ..WriteOptions::default()
    }
}

/// Each member through a READER (the command line's payload) unless its
/// flag says bytes in memory, to an output that can seek. Answers the
/// archive and the walk's large-member lane: its crews and its reach.
fn write(options: WriteOptions, members: &[(&[u8], bool)]) -> (Vec<u8>, (usize, u64)) {
    let names: Vec<String> = (0..members.len()).map(|i| format!("m{i}.bin")).collect();
    let mut readers: Vec<Cursor<&[u8]>> = members.iter().map(|m| Cursor::new(m.0)).collect();
    let mut writer = Writer::new(options).expect("options");
    for ((name, reader), &(data, in_memory)) in names.iter().zip(readers.iter_mut()).zip(members) {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: if in_memory {
                    Payload::Bytes(data)
                } else {
                    Payload::Reader {
                        reader,
                        // The slice's own length (`RangeSource` has a `len` too).
                        size: <[u8]>::len(data) as u64,
                        crc32: None,
                    }
                },
                mtime: None,
                attributes: 0o644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = Cursor::new(Vec::new());
    writer.finish_seek(&mut out).expect("finish");
    (out.into_inner(), team_large())
}

#[derive(Default)]
struct Collect(Vec<Vec<u8>>);

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
        self.0.push(out.unwrap_or_default());
        Ok(())
    }
}

fn reads_back(what: &str, archive: &[u8], members: &[(&[u8], bool)]) {
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(archive.to_vec())];
    let mut sink = Collect::default();
    extract(sources, &ReadOptions::default(), &mut sink, &mut ())
        .unwrap_or_else(|e| panic!("{what}: {e}"));
    assert!(
        sink.0
            .iter()
            .map(Vec::as_slice)
            .eq(members.iter().map(|m| m.0)),
        "{what}: the archive reads back as its members"
    );
}

const FORMATS: [(&str, WriteFormat); 2] = [
    ("rar5", WriteFormat::Rar5),
    ("rar4v29", WriteFormat::Rar4(Rar4Version::V29)),
];

/// A dictionary of one parse block, so a window is one block and a member
/// of a few MiB is many windows and several slides of its history.
const SMALL: u64 = 256 << 10;

/// Small members the small crews take, readers from a window and a bit to
/// several MiB, two the samples store, two in memory, and one of 5 MiB.
fn set() -> Vec<(Vec<u8>, bool)> {
    let mut set: Vec<(Vec<u8>, bool)> = Vec::new();
    for i in 0..6u64 {
        set.push((
            rarkit_testdata::medley(200 + i, 30_000 + i as usize * 9_973),
            false,
        ));
    }
    set.push((rarkit_testdata::medley(211, (256 << 10) + 1), false));
    set.push((rarkit_testdata::medley(212, 700_001), false));
    set.push((rarkit_testdata::scramble(213, 900_000), false));
    set.push((rarkit_testdata::medley(214, 1_500_000), true));
    set.push((rarkit_testdata::medley(215, (2 << 20) + 77), false));
    for i in 0..4u64 {
        set.push((
            rarkit_testdata::medley(220 + i, 50_000 + i as usize * 7_919),
            false,
        ));
    }
    set.push((rarkit_testdata::medley(216, 3 << 20), false));
    set.push((rarkit_testdata::scramble(217, 2_300_000), false));
    set.push((rarkit_testdata::medley(218, 5 << 20), false));
    set.push((rarkit_testdata::medley(219, 1_100_000), true));
    set.push((rarkit_testdata::medley(230, 400_000), false));
    set
}

#[test]
fn every_reach_writes_the_archive_the_window_lane_writes() {
    let set = set();
    let members: Vec<(&[u8], bool)> = set.iter().map(|m| (m.0.as_slice(), m.1)).collect();
    for (family, format) in FORMATS {
        for level in 1u8..=5 {
            let what = format!("{family} -m{level}");
            // The segment team held to one engine in both arms, so the
            // member above the reach is the one engine's in both.
            let with = |reach: u64| {
                alone(|| {
                    with_segment_width(1, || {
                        with_lane_reach(reach, || {
                            write(options(format, level, Some(SMALL)), &members)
                        })
                    })
                })
            };
            let (none, (_, most)) = with(0);
            assert!(
                most <= SMALL,
                "{what}: no reach, and the lane took members of up to {most}"
            );
            reads_back(&what, &none, &members);
            // Each above the largest member the small crews take at this
            // dictionary (2 MiB); the first two leave members above them.
            for reach in [3u64 << 20, 4 << 20, 64 << 20] {
                let (archive, (crews, most)) = with(reach);
                assert!(
                    crews > 0 && most == reach,
                    "{what}: reach {reach}: {crews} large crews taking up to {most}"
                );
                assert!(archive == none, "{what}: reach {reach} moved a byte");
            }
        }
    }
}

#[test]
fn the_shipped_dictionary_and_the_writers_own_reach_write_the_same_archive() {
    // The default dictionary (4 MiB for a RAR 5 member at level 1, 2 MiB
    // otherwise) and the streamed slack. The writer's own reach, from the
    // pool, its cores (named here: the rule by cores reaches past a window
    // only from so many) and the memory left, against none.
    let set: Vec<Vec<u8>> = vec![
        rarkit_testdata::medley(240, 100_000),
        rarkit_testdata::medley(241, 3 << 20),
        rarkit_testdata::medley(242, (5 << 20) + 4_321),
        rarkit_testdata::scramble(243, 4 << 20),
        rarkit_testdata::medley(244, 9 << 20),
        rarkit_testdata::medley(245, 200_000),
        rarkit_testdata::medley(246, (2 << 20) + 1),
        rarkit_testdata::medley(247, 6 << 20),
        rarkit_testdata::medley(248, 20 << 20),
    ];
    let members: Vec<(&[u8], bool)> = set.iter().map(|m| (m.as_slice(), false)).collect();
    // A roomy default: an allowance of 8 GiB that names no ceiling, as a
    // machine of 32 GiB has. At the 512 MiB floor a reach is taken only
    // where its crews fit, which `tests/team_memory.rs` holds; here the
    // rule by cores is what is under test.
    let roomy = |format: WriteFormat, level: u8| {
        let memory = MemoryPolicy {
            working_limit: 8 << 30,
            ..MemoryPolicy::default()
        };
        assert!(!memory.limit_named);
        WriteOptions {
            memory,
            ..options(format, level, None)
        }
    };
    for (family, format) in FORMATS {
        for level in [1u8, 3] {
            let what = format!("{family} -m{level} shipped dictionary");
            // Level 3's own default is 16 MiB in a non-solid RAR 5 archive
            // since 9 Oct 2026, as level 1's is 4 MiB.
            let window: u64 = match (matches!(format, WriteFormat::Rar5), level) {
                (true, 1) => 4 << 20,
                (true, 3) => 16 << 20,
                _ => 2 << 20,
            };
            let (none, _) = alone(|| {
                with_segment_width(1, || {
                    with_lane_reach(0, || write(roomy(format, level), &members))
                })
            });
            reads_back(&what, &none, &members);
            let (archive, (crews, most)) = alone(|| {
                with_team_cores(64, || {
                    with_segment_width(1, || write(roomy(format, level), &members))
                })
            });
            assert!(
                crews > 0 && most > window,
                "{what}: the writer's own lane: {crews} large crews taking up to {most}"
            );
            assert!(
                archive == none,
                "{what}: the writer's own reach moved a byte"
            );
            // And on few cores the lane stays inside one window.
            let (few, (_, most)) = alone(|| {
                with_team_cores(2, || {
                    with_segment_width(1, || write(roomy(format, level), &members))
                })
            });
            assert!(most <= window, "{what}: two cores reached to {most}");
            assert!(few == none, "{what}: two cores moved a byte");
        }
    }
}

#[test]
fn a_named_ceiling_and_a_solid_run_have_no_reach() {
    // SPEC-G 3.7.3: both forms are off under a named ceiling and in a
    // solid run, whatever the cores. Each write on a thread of its own,
    // since the lane read back is the thread's last team walk's.
    let set: Vec<Vec<u8>> = (0..6u64)
        .map(|i| rarkit_testdata::medley(300 + i, (3 << 20) + i as usize * (512 << 10)))
        .chain((0..6u64).map(|i| rarkit_testdata::medley(310 + i, 40_000 + i as usize * 3_001)))
        .collect();
    let lane = |options: fn() -> WriteOptions| {
        let set = set.clone();
        alone(move || {
            let members: Vec<(&[u8], bool)> = set.iter().map(|m| (m.as_slice(), false)).collect();
            with_team_cores(64, || write(options(), &members)).1
        })
    };
    let (crews, most) = lane(|| options(WriteFormat::Rar5, 1, None));
    assert!(
        crews > 0 && most > 2 << 20,
        "with neither, the lane reaches: {crews} large crews taking up to {most}"
    );
    let (_, most) = lane(|| WriteOptions {
        memory: MemoryPolicy::from_limit(256 << 20),
        ..options(WriteFormat::Rar5, 1, None)
    });
    assert!(most <= 2 << 20, "a named ceiling reached to {most}");
    // A named ceiling of 512 MiB and more admits what the default admits,
    // all but this: the reach stays inside one window (the named-ceiling
    // rule of 1 Oct 2026).
    let (_, most) = lane(|| WriteOptions {
        memory: MemoryPolicy::from_limit(2 << 30),
        ..options(WriteFormat::Rar5, 1, None)
    });
    assert!(most <= 2 << 20, "a named 2 GiB ceiling reached to {most}");
    let (_, most) = lane(|| WriteOptions {
        solid: true,
        ..options(WriteFormat::Rar5, 1, None)
    });
    assert!(most <= 2 << 20, "a solid run reached to {most}");
}

/// The width of the pool every write here runs on. The writer fits its
/// lane to the pool it is called from (the pool's width, held to the
/// encoder's), so a test that left the pool to the machine asserted the
/// machine: on a pool of three threads a reach past one window costs more
/// than the walk without it at `-md4m` and is not taken, and under three
/// the writer takes no lane at all. Eight is the widest any row here asks
/// of the encoder.
const POOL: usize = 8;

/// `work` on a thread of its own, in a pool of [`POOL`] threads whatever
/// the machine: the lane read back is the thread's last team walk's, so a
/// write that runs no team at all must not read the write before it, and
/// the lane the writer fits is the stated pool's.
fn alone<T: Send>(work: impl FnOnce() -> T + Send) -> T {
    rayon::ThreadPoolBuilder::new()
        .num_threads(POOL)
        .build()
        .expect("a pool")
        .install(work)
}

/// A roomy default: an allowance of 8 GiB that names no ceiling.
fn roomy(format: WriteFormat, level: u8, dictionary: Option<u64>) -> WriteOptions {
    let memory = MemoryPolicy {
        working_limit: 8 << 30,
        ..MemoryPolicy::default()
    };
    assert!(!memory.limit_named);
    WriteOptions {
        memory,
        workers: Some(8),
        ..options(format, level, dictionary)
    }
}

/// The narrow pool's reach on `cores` physical cores at levels 2 and 3, as
/// SPEC-G 3.7.3 has it: 8 MiB on x86-64; elsewhere a MiB a core, at most
/// 8 MiB.
fn narrow(cores: usize) -> u64 {
    if cfg!(target_arch = "x86_64") {
        8 << 20
    } else {
        (cores as u64).min(8) << 20
    }
}

/// Five members of 2 to 3.6 MiB (past one window of the shipped 2 MiB
/// dictionary, inside two), six small ones, and one each of 6, 7.5 and 9
/// MiB: inside a reach of 8 MiB but for the last.
fn narrow_set() -> Vec<Vec<u8>> {
    (0..5u64)
        .map(|i| rarkit_testdata::medley(400 + i, (2 << 20) + 4_096 + i as usize * (400 << 10)))
        .chain((0..6u64).map(|i| rarkit_testdata::medley(420 + i, 40_000 + i as usize * 3_001)))
        .chain([
            rarkit_testdata::medley(440, 6 << 20),
            rarkit_testdata::medley(441, (7 << 20) + (512 << 10)),
            rarkit_testdata::medley(442, 9 << 20),
        ])
        .collect()
}

#[test]
fn a_narrow_pool_reaches_its_short_reach_at_levels_two_and_three() {
    // SPEC-G 3.7.3, where each form is on: at levels 2 and 3 a pool of 4
    // to 15 physical cores has a SHORT reach where it had none: 8 MiB on
    // x86-64, and elsewhere a MiB a core up to 8 MiB (four cores 4 MiB,
    // six 6, eight and more 8). From 16 cores the reach is the long one,
    // as it was; under 4 cores there is none. Whatever the architecture
    // and the cores, the archive is the one no reach writes. The writer's
    // own rule in every arm (no reach set), the cores named.
    //
    // The window is NAMED, 2 MiB: the rule is about members past one
    // window, and level 3's own default in a non-solid RAR 5 archive is
    // 16 MiB since 9 Oct 2026, which would put this whole set inside one.
    const WINDOW: u64 = 2 << 20;
    const NARROW: u64 = 8 << 20;
    let set = narrow_set();
    let members: Vec<(&[u8], bool)> = set.iter().map(|m| (m.as_slice(), false)).collect();
    for (family, format) in FORMATS {
        for level in [2u8, 3] {
            let what = format!("{family} -m{level}");
            let (none, _) = alone(|| {
                with_segment_width(1, || {
                    with_lane_reach(0, || write(roomy(format, level, Some(WINDOW)), &members))
                })
            });
            reads_back(&what, &none, &members);
            let on = |cores: usize| {
                alone(|| {
                    with_team_cores(cores, || {
                        with_segment_width(1, || {
                            write(roomy(format, level, Some(WINDOW)), &members)
                        })
                    })
                })
            };
            for cores in [4usize, 6, 8, 15] {
                let reach = narrow(cores);
                let (archive, (crews, most)) = on(cores);
                assert!(
                    crews > 0 && most == reach,
                    "{what}, {cores} cores: {crews} large crews taking up to {most}"
                );
                assert!(
                    archive == none,
                    "{what}, {cores} cores: the reach moved a byte"
                );
            }
            let (archive, (crews, most)) = on(16);
            assert!(
                crews > 0 && most > NARROW,
                "{what}, 16 cores: {crews} large crews taking up to {most}"
            );
            assert!(archive == none, "{what}, 16 cores: the reach moved a byte");
            let (archive, (_, most)) = on(3);
            assert!(most <= WINDOW, "{what}: three cores reached to {most}");
            assert!(archive == none, "{what}, 3 cores: the rule moved a byte");
        }
    }
    // Level 1 is not the narrow rule's: from 4 cores its reach is the
    // long one, past the narrow pool's most.
    let longer: Vec<Vec<u8>> = (0..4u64)
        .map(|i| rarkit_testdata::medley(450 + i, (5 << 20) + i as usize * (1 << 20)))
        .chain((0..6u64).map(|i| rarkit_testdata::medley(460 + i, 40_000 + i as usize * 3_001)))
        .collect();
    let members: Vec<(&[u8], bool)> = longer.iter().map(|m| (m.as_slice(), false)).collect();
    let (_, (crews, most)) = alone(|| {
        with_team_cores(4, || {
            with_segment_width(1, || write(roomy(WriteFormat::Rar5, 1, None), &members))
        })
    });
    assert!(
        crews > 0 && most > NARROW,
        "-m1, 4 cores: {crews} large crews taking up to {most}"
    );
}

#[test]
fn the_narrow_reach_is_bytes_and_not_windows() {
    // The short reach is in bytes, whatever the dictionary: at `-md4m` a
    // member of up to 4 MiB is inside one window and eight cores still
    // reach 8 MiB past it (four cores too on x86-64; elsewhere their 4 MiB
    // is the window and they reach nothing); at `-md8m` every member of up
    // to 8 MiB is inside one window and nothing is reached. The archive is
    // the one no reach writes.
    let set = narrow_set();
    let members: Vec<(&[u8], bool)> = set.iter().map(|m| (m.as_slice(), false)).collect();
    for level in [2u8, 3] {
        let what = format!("-m{level} -md4m");
        let wide = || roomy(WriteFormat::Rar5, level, Some(4 << 20));
        let (none, _) =
            alone(|| with_segment_width(1, || with_lane_reach(0, || write(wide(), &members))));
        for cores in [4usize, 8] {
            let (archive, (crews, most)) = alone(|| {
                with_team_cores(cores, || with_segment_width(1, || write(wide(), &members)))
            });
            if narrow(cores) > 4 << 20 {
                assert!(
                    crews > 0 && most == narrow(cores),
                    "{what}, {cores} cores: {crews} large crews taking up to {most}"
                );
            } else {
                assert!(most <= 4 << 20, "{what}, {cores} cores: reached to {most}");
            }
            assert!(
                archive == none,
                "{what}, {cores} cores: the rule moved a byte"
            );
        }
        let (_, (_, most)) = alone(|| {
            with_team_cores(8, || {
                with_segment_width(1, || {
                    write(roomy(WriteFormat::Rar5, level, Some(8 << 20)), &members)
                })
            })
        });
        assert!(
            most <= 8 << 20,
            "-m{level} -md8m, 8 cores: reached to {most}"
        );
    }
}

#[test]
fn levels_four_and_five_have_no_reach_on_any_pool() {
    // SPEC-G 3.7.3: the lane is off at levels 4 and 5 by the LEVEL,
    // whatever the cores; the narrow pool's reach does not change that.
    let set: Vec<Vec<u8>> = (0..3u64)
        .map(|i| rarkit_testdata::medley(500 + i, (2 << 20) + 4_096 + i as usize * (600 << 10)))
        .chain((0..4u64).map(|i| rarkit_testdata::medley(510 + i, 40_000 + i as usize * 3_001)))
        .collect();
    let members: Vec<(&[u8], bool)> = set.iter().map(|m| (m.as_slice(), false)).collect();
    for level in [4u8, 5] {
        let what = format!("rar5 -m{level}");
        let (none, _) = alone(|| {
            with_segment_width(1, || {
                with_lane_reach(0, || write(roomy(WriteFormat::Rar5, level, None), &members))
            })
        });
        for cores in [4usize, 8, 16, 64] {
            let (archive, (crews, most)) = alone(|| {
                with_team_cores(cores, || {
                    with_segment_width(1, || write(roomy(WriteFormat::Rar5, level, None), &members))
                })
            });
            assert!(
                crews == 0 && most == 0,
                "{what}, {cores} cores: {crews} large crews taking up to {most}"
            );
            assert!(
                archive == none,
                "{what}, {cores} cores: the rule moved a byte"
            );
        }
    }
}

#[test]
fn a_stored_big_member_beside_members_in_the_narrow_reach_is_the_same_archive() {
    // What a default create of a media folder is: one large member the
    // store rule's samples store (never a crew's, never pulled whole)
    // beside compressible members of 2 to 8 MiB and small ones. The lane's
    // split is over the members crews take, so the stored member costs it
    // nothing: the crews take the members in the reach, and the archive is
    // the one no reach writes.
    let mut set = narrow_set();
    set.insert(3, rarkit_testdata::scramble(470, 24 << 20));
    set.push(rarkit_testdata::scramble(471, 3 << 20));
    let members: Vec<(&[u8], bool)> = set.iter().map(|m| (m.as_slice(), false)).collect();
    for level in [2u8, 3] {
        let what = format!("rar5 -m{level}, a stored 24 MiB member in the set");
        let (none, _) = alone(|| {
            with_segment_width(1, || {
                with_lane_reach(0, || write(roomy(WriteFormat::Rar5, level, None), &members))
            })
        });
        reads_back(&what, &none, &members);
        let (archive, (crews, most)) = alone(|| {
            with_team_cores(8, || {
                with_segment_width(1, || write(roomy(WriteFormat::Rar5, level, None), &members))
            })
        });
        assert!(
            crews > 0 && most == 8 << 20,
            "{what}: {crews} large crews taking up to {most}"
        );
        assert!(archive == none, "{what}: the reach moved a byte");
    }
}

#[test]
fn a_blake2sp_create_on_a_narrow_pool_is_the_same_archive() {
    // `-htb`: a crew hashes its own member on its one thread (`PackRule`),
    // where the writing thread's digest of the same member could take a
    // BLAKE2sp team. The digest is the member's either way: the archive is
    // the one no reach writes, and every member's checksum reads back.
    let set = narrow_set();
    let members: Vec<(&[u8], bool)> = set.iter().map(|m| (m.as_slice(), false)).collect();
    let hashed = |level: u8| WriteOptions {
        checksum: ChecksumKind::Blake2sp,
        ..roomy(WriteFormat::Rar5, level, None)
    };
    for level in [2u8, 3] {
        let what = format!("rar5 -m{level} -htb");
        let (none, _) = alone(|| {
            with_segment_width(1, || with_lane_reach(0, || write(hashed(level), &members)))
        });
        reads_back(&what, &none, &members);
        let (archive, (crews, most)) = alone(|| {
            with_team_cores(8, || {
                with_segment_width(1, || write(hashed(level), &members))
            })
        });
        assert!(
            crews > 0 && most == 8 << 20,
            "{what}: {crews} large crews taking up to {most}"
        );
        assert!(archive == none, "{what}: the reach moved a byte");
    }
}

/// Collects a volume set's volumes.
#[derive(Default)]
struct Volumes(Vec<Vec<u8>>);

impl VolumeOut for Volumes {
    type W = Vec<u8>;

    fn volume(&mut self, _index: u32) -> rarkit::Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn finished(&mut self, _index: u32, volume: Vec<u8>) -> rarkit::Result<()> {
        self.0.push(volume);
        Ok(())
    }
}

#[test]
fn a_volume_set_of_readers_has_no_lane_past_a_window() {
    // SPEC-G 3.7.3: a reader is pulled ahead of the writer only outside a
    // volume set, so in one no member past a window is a crew's, on a
    // narrow pool as on a wide one, and the volumes are the ones no reach
    // writes.
    let set = narrow_set();
    let volumes = |cores: usize, reach: Option<u64>| {
        let set = &set;
        alone(move || {
            let names: Vec<String> = (0..set.len()).map(|i| format!("m{i}.bin")).collect();
            let mut readers: Vec<Cursor<&[u8]>> =
                set.iter().map(|m| Cursor::new(m.as_slice())).collect();
            let mut write = || {
                let mut writer = Writer::new(WriteOptions {
                    volume_file_size: Some(1_000_000),
                    // A named 2 MiB window, which this set's large
                    // members are all past (level 3's own default is
                    // 16 MiB since 9 Oct 2026).
                    ..roomy(WriteFormat::Rar5, 3, Some(2 << 20))
                })
                .expect("options");
                for ((name, reader), data) in names.iter().zip(readers.iter_mut()).zip(set) {
                    writer
                        .add(MemberSpec {
                            name: name.as_bytes(),
                            payload: Payload::Reader {
                                reader,
                                size: data.len() as u64,
                                crc32: None,
                            },
                            mtime: None,
                            attributes: 0o644,
                            host_os: rarkit::HostOs::Unix,
                            is_directory: false,
                        })
                        .expect("add");
                }
                let mut out = Volumes::default();
                writer.finish_volumes(&mut out).expect("finish");
                (out.0, team_large())
            };
            with_team_cores(cores, || {
                with_segment_width(1, || match reach {
                    Some(bytes) => with_lane_reach(bytes, &mut write),
                    None => write(),
                })
            })
        })
    };
    let (none, _) = volumes(8, Some(0));
    assert!(none.len() > 2, "the set is {} volumes", none.len());
    for cores in [8usize, 64] {
        let (set, (crews, most)) = volumes(cores, None);
        assert!(
            crews == 0 && most <= 2 << 20,
            "a volume set, {cores} cores: {crews} large crews taking up to {most}"
        );
        assert!(
            set == none,
            "a volume set, {cores} cores: the rule moved a byte"
        );
    }
}

#[test]
fn levels_4_and_5_on_a_pool_wide_enough_for_the_lane_have_no_reach() {
    // Spec G 3.7.3, keyed by LEVEL: level 4 walks level 3's chains since 1
    // Oct 2026 and the large-member lane's reach past one window stays
    // levels 1 to 3's. On 64 cores level 3 reaches (the control), level 4
    // does not, with its tree option on or off. Each write on a thread of
    // its own, since the lane read back is the thread's last team walk's.
    let set: Vec<Vec<u8>> = (0..6u64)
        .map(|i| rarkit_testdata::medley(400 + i, (3 << 20) + i as usize * (512 << 10)))
        .chain((0..6u64).map(|i| rarkit_testdata::medley(410 + i, 40_000 + i as usize * 3_001)))
        .collect();
    let lane = |level: u8, tree: bool| {
        let set = set.clone();
        alone(move || {
            let members: Vec<(&[u8], bool)> = set.iter().map(|m| (m.as_slice(), false)).collect();
            let options = WriteOptions {
                level4_tree: tree,
                ..options(WriteFormat::Rar5, level, None)
            };
            with_team_cores(64, || write(options, &members)).1
        })
    };
    let (crews, most) = lane(3, false);
    assert!(
        crews > 0 && most > 2 << 20,
        "the control: level 3 reaches, {crews} large crews taking up to {most}"
    );
    for tree in [false, true] {
        let (_, most) = lane(4, tree);
        assert!(
            most <= 2 << 20,
            "-m4 (tree option {tree}) reached to {most}"
        );
    }
    // Level 5 by class walks the chains on members such as these and has
    // no reach either.
    let (_, most) = lane(5, false);
    assert!(most <= 2 << 20, "-m5 reached to {most}");
}
