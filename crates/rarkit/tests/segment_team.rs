//! The SEGMENT TEAM (`write::engine`'s `Segments`): a member longer than
//! one stretch of its streamed encode, in a non-solid run with no ceiling
//! named, at a chain level, is encoded by several engines at once, each
//! over the stretch between two slides of the one engine's history.
//!
//! **What is held here.** That the team is a WIDTH and never a byte: the
//! same member at the same options is the same archive at every team
//! width, one included, which is the walk the writer had before the team
//! (API promise 2.6). Both walks that encode a member a window at a time
//! are covered, the HELD one (`Run::compress_streaming`) and the STREAMED
//! one (`Run::write_member_streamed`, reached by lowering the held-member
//! limit); both archive formats; levels 1 to 3; a filter plan whose spans
//! are measured from each window's offset in its member; a member that
//! ends on a window's edge and one that does not; a member beside others
//! that the worker team takes; and the shipped dictionary with the
//! streamed slack. And that the levels and the runs the team does not
//! claim never see it: the tree's levels, a solid run, a caller's ceiling.
use std::io::Cursor;
use std::sync::Arc;

use rarkit::internals::rar5::filter_layout;
use rarkit::internals::writers::{
    reset_segment_rounds, reset_streamed_members, segment_rounds, streamed_members,
    with_segment_width, with_stream_above, with_team_cores, with_window_depth,
};
use rarkit::{
    extract, Disposition, FilterPolicy, MemberInfo, MemberOutcome, MemberSpec, MemoryPolicy,
    Payload, RangeSource, Rar4Version, ReadOptions, Sink, WriteFormat, WriteMethod, WriteOptions,
    Writer,
};

/// The width of the pool every test here runs on. The writer fits its team
/// to the pool it is called from (the pool's width, held to the encoder's),
/// so a test that left the pool to the machine asserted the machine: "a
/// pool of eight workers" was eight only where the machine had eight
/// threads. Eight is the widest any row here asks of the encoder.
const POOL: usize = 8;

/// A test's body on a pool of [`POOL`] threads, whatever the machine. The
/// hooks a body sets and the team it reads back are the calling thread's,
/// so the whole body runs on one thread of that pool.
fn pooled(body: fn()) {
    rayon::ThreadPoolBuilder::new()
        .num_threads(POOL)
        .build()
        .expect("a pool")
        .install(body)
}

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
        workers: Some(4),
        ..WriteOptions::default()
    }
}

/// Every member through a READER, the command line's payload, to an
/// output that can seek. Answers the archive, how many rounds the segment
/// team ran with the most engines of one, and how many members the
/// streamed walk took.
fn write(options: WriteOptions, members: &[&[u8]]) -> (Vec<u8>, (usize, usize), usize) {
    reset_segment_rounds();
    reset_streamed_members();
    let names: Vec<String> = (0..members.len()).map(|i| format!("m{i}.bin")).collect();
    let mut readers: Vec<Cursor<&[u8]>> = members.iter().map(|m| Cursor::new(*m)).collect();
    let mut writer = Writer::new(options).expect("options");
    for ((name, reader), data) in names.iter().zip(readers.iter_mut()).zip(members) {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Reader {
                    reader,
                    // The slice's own length (`RangeSource` has a `len` too).
                    size: <[u8]>::len(data) as u64,
                    crc32: None,
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
    (out.into_inner(), segment_rounds(), streamed_members())
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

fn reads_back(what: &str, archive: &[u8], members: &[&[u8]]) {
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(archive.to_vec())];
    let mut sink = Collect::default();
    extract(sources, &ReadOptions::default(), &mut sink, &mut ())
        .unwrap_or_else(|e| panic!("{what}: {e}"));
    assert!(
        sink.0.iter().map(Vec::as_slice).eq(members.iter().copied()),
        "{what}: the archive reads back as its members"
    );
}

const FORMATS: [(&str, WriteFormat); 2] = [
    ("rar5", WriteFormat::Rar5),
    ("rar4v29", WriteFormat::Rar4(Rar4Version::V29)),
];

/// A dictionary of one parse block, so a window is one block, the history
/// slides every five windows and a member of a few MiB is many stretches.
const SMALL: u64 = 256 << 10;

#[test]
fn every_team_width_writes_the_one_engines_archive() {
    pooled(every_team_width_writes_the_one_engines_archive_on_the_pool);
}

fn every_team_width_writes_the_one_engines_archive_on_the_pool() {
    let edge = rarkit_testdata::medley(21, 6 << 20);
    let ragged = rarkit_testdata::medley(22, (5 << 20) + 12_345);
    for (family, format) in FORMATS {
        for level in 1u8..=3 {
            for (shape, data) in [("edge", &edge), ("ragged", &ragged)] {
                let what = format!("{family} -m{level} {shape}");
                let (one, rounds, _) =
                    with_segment_width(1, || write(options(format, level, Some(SMALL)), &[data]));
                assert_eq!(rounds, (0, 0), "{what}: a width of one ran a round");
                reads_back(&what, &one, &[data]);
                for width in [2usize, 3, 8] {
                    let (archive, (rounds, most), _) = with_segment_width(width, || {
                        write(options(format, level, Some(SMALL)), &[data])
                    });
                    assert!(
                        rounds > 0 && most == width.min(4),
                        "{what}: width {width} ran {rounds} rounds of at most {most} engines"
                    );
                    assert!(archive == one, "{what}: width {width} moved a byte");
                }
            }
        }
    }
}

#[test]
fn the_streamed_walk_takes_the_team_and_writes_the_same_archive() {
    pooled(the_streamed_walk_takes_the_team_and_writes_the_same_archive_on_the_pool);
}

fn the_streamed_walk_takes_the_team_and_writes_the_same_archive_on_the_pool() {
    // The held-member limit lowered so that a member of a few MiB streams
    // as a member of hundreds does at the shipped limit (spec G 3.5).
    let data = rarkit_testdata::medley(23, (7 << 20) + 4_321);
    for (family, format) in FORMATS {
        for level in [1u8, 3] {
            let what = format!("{family} -m{level} streamed");
            let (one, rounds, took) = with_stream_above(4 << 20, || {
                with_segment_width(1, || write(options(format, level, Some(SMALL)), &[&data]))
            });
            assert_eq!(took, 1, "{what}: the member was held");
            assert_eq!(rounds, (0, 0), "{what}");
            reads_back(&what, &one, &[&data]);
            for width in [2usize, 4] {
                let (archive, (rounds, most), took) = with_stream_above(4 << 20, || {
                    with_segment_width(width, || {
                        write(options(format, level, Some(SMALL)), &[&data])
                    })
                });
                assert_eq!(took, 1, "{what}: width {width} held the member");
                assert!(
                    rounds > 0 && most == width,
                    "{what}: width {width}, {rounds} rounds"
                );
                assert!(archive == one, "{what}: width {width} moved a byte");
            }
        }
    }
}

#[test]
fn a_big_member_beside_small_ones_is_the_same_archive_at_any_team_width() {
    pooled(a_big_member_beside_small_ones_is_the_same_archive_at_any_team_width_on_the_pool);
}

fn a_big_member_beside_small_ones_is_the_same_archive_at_any_team_width_on_the_pool() {
    // The worker team takes the small members while the writing thread's
    // big one runs on the segment team; add order kept.
    let small: Vec<Vec<u8>> = (0..12)
        .map(|i| rarkit_testdata::medley(100 + i as u64, 40_000 + i * 7_919))
        .collect();
    let big = rarkit_testdata::medley(24, 5 << 20);
    let mut members: Vec<&[u8]> = small[..6].iter().map(Vec::as_slice).collect();
    members.push(&big);
    members.extend(small[6..].iter().map(Vec::as_slice));
    for (family, format) in FORMATS {
        let with = |width: usize| {
            with_segment_width(width, || {
                write(
                    WriteOptions {
                        order: rarkit::MemberOrder::AsAdded,
                        ..options(format, 1, Some(SMALL))
                    },
                    &members,
                )
            })
        };
        let (one, _, _) = with(1);
        reads_back(family, &one, &members);
        let (archive, (rounds, most), _) = with(4);
        assert!(
            rounds > 0 && most >= 2,
            "{family}: {rounds} rounds, {most} engines"
        );
        assert!(archive == one, "{family}: the team moved a byte");
    }
}

#[test]
fn the_shipped_dictionary_and_the_default_admission_write_the_one_engines_archive() {
    pooled(
        the_shipped_dictionary_and_the_default_admission_write_the_one_engines_archive_on_the_pool,
    );
}

fn the_shipped_dictionary_and_the_default_admission_write_the_one_engines_archive_on_the_pool() {
    // 2 MiB windows and the streamed slack: a stretch is sixteen to
    // eighteen MiB, so this member is three. Width one against the width
    // the writer chooses for itself from the pool, its cores (named here:
    // the rule by cores runs no team on few) and the memory left (the
    // default policy affords more than one engine).
    let data = rarkit_testdata::medley(25, 44 << 20);
    let (one, _, _) =
        with_segment_width(1, || write(options(WriteFormat::Rar5, 1, None), &[&data]));
    let (archive, (rounds, most), _) =
        with_team_cores(64, || write(options(WriteFormat::Rar5, 1, None), &[&data]));
    assert!(
        rounds > 0 && most >= 2,
        "the default policy ran {rounds} rounds of at most {most} engines"
    );
    // And on few cores the writer runs no team at all.
    let (few, (rounds, _), _) =
        with_team_cores(8, || write(options(WriteFormat::Rar5, 1, None), &[&data]));
    assert_eq!(rounds, 0, "eight cores ran the segment team");
    assert!(few == one, "eight cores moved a byte");
    assert!(archive == one, "the writer's own width moved a byte");
    reads_back("default", &archive, &[&data]);
}

#[test]
fn a_filter_on_both_sides_of_every_stretch_edge_is_the_one_engines_archive() {
    pooled(a_filter_on_both_sides_of_every_stretch_edge_is_the_one_engines_archive_on_the_pool);
}

fn a_filter_on_both_sides_of_every_stretch_edge_is_the_one_engines_archive_on_the_pool() {
    // The history an engine keeps across a slide holds FILTERED bytes
    // (the decoder's window holds them too), so an engine resumed at a
    // stretch's start is given the kept windows transformed as the one
    // engine staged them (`Engine::filter_kept`). Held here at the levels
    // that write a filter plan, 2 and 3, on a member that is filtered in
    // EVERY window, so whichever window edges the stretches fall on, the
    // kept dictionary before each and the window after it are filtered.
    //
    // The RAR 4 family writes no filter (the request is refused,
    // SPEC-J); its arm here is the same member at the same levels
    // across the same edges, with nothing transformed.
    let window = SMALL as usize;
    let data = rarkit_testdata::machine_like(27, (6 << 20) + 54_321);
    for (family, format) in FORMATS {
        for level in [2u8, 3] {
            let what = format!("{family} -m{level} filtered");
            let (one, rounds, _) =
                with_segment_width(1, || write(options(format, level, Some(SMALL)), &[&data]));
            assert_eq!(rounds, (0, 0), "{what}");
            reads_back(&what, &one, &[&data]);
            if matches!(format, WriteFormat::Rar5) {
                let layout = filter_layout(&one).expect("the archive decodes");
                let spans = &layout[0].spans;
                for at in (0..data.len()).step_by(window) {
                    let end = (at + window).min(data.len());
                    let filtered: u64 = spans
                        .iter()
                        .filter(|span| span.0 >= at as u64 && span.0 < end as u64)
                        .map(|span| u64::from(span.1))
                        .sum();
                    assert!(
                        filtered * 2 > (end - at) as u64,
                        "{what}: the window at {at} is filtered over {filtered} bytes only, \
                         so an edge here would hold nothing"
                    );
                }
            }
            for width in [2usize, 3, 4] {
                let (archive, (rounds, most), _) = with_segment_width(width, || {
                    write(options(format, level, Some(SMALL)), &[&data])
                });
                assert!(
                    rounds > 0 && most == width,
                    "{what}: width {width} ran {rounds} rounds of at most {most} engines"
                );
                assert!(archive == one, "{what}: width {width} moved a byte");
            }
        }
    }
}

#[test]
fn the_runs_the_team_does_not_claim_never_see_it() {
    pooled(the_runs_the_team_does_not_claim_never_see_it_on_the_pool);
}

fn the_runs_the_team_does_not_claim_never_see_it_on_the_pool() {
    let data = rarkit_testdata::medley(26, 5 << 20);
    // A member that keeps the tree is one engine's: level 5 by its class
    // (SPEC-H3 8.1), level 4 under its tree option.
    let far = far_linked(5 << 20, 33);
    let (_, rounds, _) = with_segment_width(4, || {
        write(options(WriteFormat::Rar5, 5, Some(SMALL)), &[&far])
    });
    assert_eq!(rounds, (0, 0), "-m5: a member that keeps the tree");
    let (_, rounds, _) = with_segment_width(4, || {
        write(
            WriteOptions {
                level4_tree: true,
                ..options(WriteFormat::Rar5, 4, Some(SMALL))
            },
            &[&data],
        )
    });
    assert_eq!(rounds, (0, 0), "-m4 under the tree option");
    let (_, rounds, _) = with_segment_width(4, || {
        write(
            WriteOptions {
                level5_tree: true,
                ..options(WriteFormat::Rar5, 5, Some(SMALL))
            },
            &[&data],
        )
    });
    assert_eq!(rounds, (0, 0), "-m5 under the tree option");
    let (_, rounds, _) = with_segment_width(4, || {
        write(
            WriteOptions {
                solid: true,
                ..options(WriteFormat::Rar5, 1, Some(SMALL))
            },
            &[&data],
        )
    });
    assert_eq!(rounds, (0, 0), "a solid run keeps one engine");
    let (_, rounds, _) = with_segment_width(4, || {
        write(
            WriteOptions {
                memory: MemoryPolicy::from_limit(256 << 20),
                ..options(WriteFormat::Rar5, 1, Some(SMALL))
            },
            &[&data],
        )
    });
    assert_eq!(rounds, (0, 0), "a caller's ceiling keeps one engine");
}

#[test]
fn levels_4_and_5_take_the_team_by_the_rule_on_a_wide_pool() {
    pooled(levels_4_and_5_take_the_team_by_the_rule_on_a_wide_pool_on_the_pool);
}

fn levels_4_and_5_take_the_team_by_the_rule_on_a_wide_pool_on_the_pool() {
    // Spec G 3.7.3: on a pool the rule by cores gives a team (64 physical
    // cores here, said by the test, a pool of four workers, a member of
    // four stretches, which is as many as the pool and as the floor of
    // engines these levels keep), a member that walks the chains at
    // levels 4 and 5 takes it as level 1 does, and its archive is the one
    // engine's.
    let data = rarkit_testdata::medley(27, 5 << 20);
    let wide = |level: u8| WriteOptions {
        workers: Some(4),
        ..options(WriteFormat::Rar5, level, Some(SMALL))
    };
    for level in [1u8, 4, 5] {
        let (by_rule, rounds, _) = with_team_cores(64, || write(wide(level), &[&data]));
        assert!(
            rounds.0 > 0 && rounds.1 > 1,
            "-m{level} takes the team on this pool, rounds {rounds:?}"
        );
        let (one, rounds, _) = with_segment_width(1, || write(wide(level), &[&data]));
        assert_eq!(rounds, (0, 0), "-m{level}: a width of one ran a round");
        assert!(by_rule == one, "-m{level}: the rule's team moved a byte");
        reads_back("on a wide pool", &by_rule, &[&data]);
    }
    // On a pool under the rule's bar the same member is one engine's.
    for level in [4u8, 5] {
        let (_, rounds, _) = with_team_cores(16, || write(wide(level), &[&data]));
        assert_eq!(rounds, (0, 0), "-m{level} on 16 cores");
    }
    // The bar above level 1 is twenty physical cores (an M1 Ultra's): at
    // twenty the member takes the team and writes the one engine's
    // archive, at nineteen it is one engine's.
    for level in [4u8, 5] {
        let (by_rule, rounds, _) = with_team_cores(20, || write(wide(level), &[&data]));
        assert!(
            rounds.0 > 0 && rounds.1 > 1,
            "-m{level} on 20 cores takes the team, rounds {rounds:?}"
        );
        let (one, _, _) = with_segment_width(1, || write(wide(level), &[&data]));
        assert!(
            by_rule == one,
            "-m{level} on 20 cores: the team moved a byte"
        );
        let (_, rounds, _) = with_team_cores(19, || write(wide(level), &[&data]));
        assert_eq!(rounds, (0, 0), "-m{level} on 19 cores");
    }
}

#[test]
fn levels_2_and_3_take_the_team_from_twenty_cores() {
    pooled(levels_2_and_3_take_the_team_from_twenty_cores_on_the_pool);
}

fn levels_2_and_3_take_the_team_from_twenty_cores_on_the_pool() {
    // The rule by cores above level 1 is twenty physical cores (an M1
    // Ultra's): a member of 2 MiB windows (eight parse blocks, the fewest
    // a team of few stretches takes at these levels) and five stretches
    // of the streamed slack, on a pool of four workers, takes the team at
    // twenty and writes the one engine's archive, and is one engine's at
    // nineteen. Said cores, not the machine's, and a named 2 GiB working
    // limit, above the default floor, so that the team's memory rule
    // affords the four engines whatever the machine's memory (at the
    // default floor it affords level 3 two, and refuses the team, which
    // is that rule and not this one); about 72 MiB of input and four
    // engines of a 2 MiB dictionary, about 500 MiB at most.
    let data = rarkit_testdata::medley(29, 72 << 20);
    let at = |level: u8| WriteOptions {
        workers: Some(4),
        memory: MemoryPolicy::from_limit(2 << 30),
        ..options(WriteFormat::Rar5, level, Some(2 << 20))
    };
    for level in [2u8, 3] {
        let (by_rule, rounds, _) = with_team_cores(20, || write(at(level), &[&data]));
        assert!(
            rounds.0 > 0 && rounds.1 > 1,
            "-m{level} on 20 cores takes the team, rounds {rounds:?}"
        );
        let (one, rounds, _) = with_segment_width(1, || write(at(level), &[&data]));
        assert_eq!(rounds, (0, 0), "-m{level}: a width of one ran a round");
        assert!(
            by_rule == one,
            "-m{level} on 20 cores: the team moved a byte"
        );
        let (_, rounds, _) = with_team_cores(19, || write(at(level), &[&data]));
        assert_eq!(rounds, (0, 0), "-m{level} on 19 cores");
        reads_back("from twenty cores", &by_rule, &[&data]);
    }
}

/// A megabyte's worth of far links: 100,000 bytes of noise, repeated. Its
/// head reads far over level 5's cut-off (SPEC-H3 8.1's third vector), so
/// at level 5 it keeps the tree.
fn far_linked(len: usize, seed: u64) -> Vec<u8> {
    let mut rng = rarkit_testdata::Seeded::new(seed);
    let unit: Vec<u8> = (0..100_000).map(|_| rng.next_u32() as u8).collect();
    unit.iter().copied().cycle().take(len).collect()
}

#[test]
fn every_team_width_at_levels_4_and_5_writes_the_one_engines_archive() {
    pooled(every_team_width_at_levels_4_and_5_writes_the_one_engines_archive_on_the_pool);
}

fn every_team_width_at_levels_4_and_5_writes_the_one_engines_archive_on_the_pool() {
    // A member whose effort is the lazy parse over the chains (level 4's
    // plan; at level 5 the member's class) takes the team, held and
    // streamed, and every width's archive is the one engine's: each
    // stretch is walked by the effort the run's own encoder read off the
    // member's head.
    let edge = rarkit_testdata::medley(31, 6 << 20);
    let ragged = rarkit_testdata::medley(32, (5 << 20) + 12_345);
    for (family, format) in FORMATS {
        for level in [4u8, 5] {
            for (shape, data) in [("edge", &edge), ("ragged", &ragged)] {
                let what = format!("{family} -m{level} {shape}");
                let (one, rounds, _) =
                    with_segment_width(1, || write(options(format, level, Some(SMALL)), &[data]));
                assert_eq!(rounds, (0, 0), "{what}: a width of one ran a round");
                reads_back(&what, &one, &[data]);
                for width in [2usize, 3, 8] {
                    let (archive, (rounds, most), _) = with_segment_width(width, || {
                        write(options(format, level, Some(SMALL)), &[data])
                    });
                    assert!(
                        rounds > 0 && most == width.min(4),
                        "{what}: width {width} ran {rounds} rounds of at most {most} engines"
                    );
                    assert!(archive == one, "{what}: width {width} moved a byte");
                }
            }
            let what = format!("{family} -m{level} streamed");
            let (one, rounds, took) = with_stream_above(4 << 20, || {
                with_segment_width(1, || write(options(format, level, Some(SMALL)), &[&ragged]))
            });
            assert_eq!(took, 1, "{what}: the member was held");
            assert_eq!(rounds, (0, 0), "{what}");
            for width in [2usize, 4] {
                let (archive, (rounds, most), took) = with_stream_above(4 << 20, || {
                    with_segment_width(width, || {
                        write(options(format, level, Some(SMALL)), &[&ragged])
                    })
                });
                assert_eq!(took, 1, "{what}: width {width} held the member");
                assert!(
                    rounds > 0 && most == width,
                    "{what}: width {width}, {rounds} rounds"
                );
                assert!(archive == one, "{what}: width {width} moved a byte");
            }
        }
    }
    // A member that keeps the tree, forced: one engine, one archive.
    let far = far_linked(5 << 20, 33);
    let (one, _, _) = with_segment_width(1, || {
        write(options(WriteFormat::Rar5, 5, Some(SMALL)), &[&far])
    });
    let (forced, rounds, _) = with_segment_width(4, || {
        write(options(WriteFormat::Rar5, 5, Some(SMALL)), &[&far])
    });
    assert_eq!(rounds, (0, 0), "-m5: a member that keeps the tree");
    assert!(
        forced == one,
        "-m5: a member that keeps the tree, one archive"
    );
    // And members of unlike classes in one run: the team's engines take
    // each member's own effort, not the one before it.
    let run: [&[u8]; 4] = [&far, &edge, &far, &ragged];
    let (one, _, _) = with_segment_width(1, || {
        write(options(WriteFormat::Rar5, 5, Some(SMALL)), &run)
    });
    let (archive, (rounds, _), _) = with_segment_width(4, || {
        write(options(WriteFormat::Rar5, 5, Some(SMALL)), &run)
    });
    assert!(
        rounds > 0,
        "the chain-class members of the mixed run took the team"
    );
    assert!(
        archive == one,
        "a run of unlike classes: the team moved a byte"
    );
    reads_back("a run of unlike classes", &archive, &run);
}

#[test]
fn a_member_of_fewer_stretches_than_the_engines_takes_the_team_where_its_windows_fill_the_pool() {
    pooled(a_member_of_fewer_stretches_than_the_engines_takes_the_team_where_its_windows_fill_the_pool_on_the_pool);
}

fn a_member_of_fewer_stretches_than_the_engines_takes_the_team_where_its_windows_fill_the_pool_on_the_pool(
) {
    // Spec G 3.7.3, levels 2 and 3 on a pool the rule by cores gives a
    // team (64 physical cores here, said by the test: 24 engines; a pool
    // of eight workers). A member of at least eight stretches takes the
    // team whatever its window, as before. A member of FEWER takes it
    // where its windows are 2 MiB or more, its stretches times the blocks
    // of a window are at least the pool's eight threads, and the team is
    // no smaller than its window asks (four engines at 2 MiB); and is the
    // one engine's where they are not. The archive is the one engine's
    // every time: the team is a width.
    let wide = |level: u8, dictionary: u64| WriteOptions {
        workers: Some(8),
        ..options(WriteFormat::Rar5, level, Some(dictionary))
    };
    for level in [2u8, 3] {
        // 256 KiB windows are one block, and the slack is four of them:
        // a stretch is a MiB. Five MiB is five or six stretches, under
        // eight: a window under 2 MiB, so the one engine's.
        let few = rarkit_testdata::medley(31, 5 << 20);
        let (archive, rounds, _) = with_team_cores(64, || write(wide(level, SMALL), &[&few]));
        assert_eq!(
            rounds,
            (0, 0),
            "-m{level}: six one-block windows on eight threads"
        );
        let (one, _, _) = with_segment_width(1, || write(wide(level, SMALL), &[&few]));
        assert!(archive == one, "-m{level}: the refusal moved a byte");

        // The same windows on a member of twelve stretches: at least as
        // many as the pool, so the team as it always was.
        let many = rarkit_testdata::medley(32, 12 << 20);
        let (archive, (rounds, most), _) =
            with_team_cores(64, || write(wide(level, SMALL), &[&many]));
        assert!(
            rounds > 0 && most > 1,
            "-m{level}: twelve stretches ran {rounds} rounds of at most {most} engines"
        );
        let (one, _, _) = with_segment_width(1, || write(wide(level, SMALL), &[&many]));
        assert!(archive == one, "-m{level}: the team moved a byte");

        // 1 MiB windows are four blocks and a stretch is four MiB:
        // twenty-two MiB is five or six stretches, under eight again, and
        // twenty blocks and more in flight would fill the eight threads,
        // but no row placed the bar under 2 MiB windows: the one engine's.
        let wider = rarkit_testdata::medley(33, 22 << 20);
        let (archive, rounds, _) = with_team_cores(64, || write(wide(level, 1 << 20), &[&wider]));
        assert_eq!(rounds, (0, 0), "-m{level}: 1 MiB windows");
        let (one, _, _) = with_segment_width(1, || write(wide(level, 1 << 20), &[&wider]));
        assert!(
            archive == one,
            "-m{level}: the refusal at 1 MiB moved a byte"
        );
    }
    // 2 MiB windows are eight blocks and a stretch is sixteen MiB after
    // the first, which is a dictionary longer: a member of fifty-two MiB
    // is four stretches, under the pool's eight, its thirty-two blocks
    // fill eight threads, and four engines are what a 2 MiB window asks:
    // the team, where the working limit affords the four.
    let roomy = |dictionary: u64| WriteOptions {
        memory: MemoryPolicy::from_limit(2 << 30),
        ..wide(3, dictionary)
    };
    let four = rarkit_testdata::medley(35, (52 << 20) + 54_321);
    let (archive, (rounds, most), _) = with_team_cores(64, || write(roomy(2 << 20), &[&four]));
    assert!(
        rounds > 0 && most == 4,
        "-m3: four stretches of 2 MiB windows ran {rounds} rounds of at most {most} engines"
    );
    let (one, _, _) = with_segment_width(1, || write(roomy(2 << 20), &[&four]));
    assert!(
        archive == one,
        "-m3: the team at 2 MiB windows moved a byte"
    );
    reads_back("fewer stretches than engines", &archive, &[&four]);
    // The same member under a named 512 MiB limit, which affords fewer
    // engines of 2 MiB windows than four on the machines this was sat on:
    // whatever a machine affords, no team smaller than the window asks is
    // formed, and the archive is the one engine's either way.
    let tight = |dictionary: u64| WriteOptions {
        memory: MemoryPolicy::from_limit(512 << 20),
        ..wide(3, dictionary)
    };
    let (small, (rounds, most), _) = with_team_cores(64, || write(tight(2 << 20), &[&four]));
    assert!(
        rounds == 0 || most >= 4,
        "-m3: a team of {most} engines at 2 MiB windows under a 512 MiB limit"
    );
    assert!(small == one, "-m3: the afforded team's answer moved a byte");
    // Three stretches of the same windows are under the four engines a
    // 2 MiB window asks, whatever the memory: the one engine's.
    let three = rarkit_testdata::medley(36, (36 << 20) + 4_321);
    let (_, rounds, _) = with_team_cores(64, || write(roomy(2 << 20), &[&three]));
    assert_eq!(rounds, (0, 0), "-m3: three stretches of 2 MiB windows");
    // Level 1 never had the refusal: every stretch another engine takes
    // is a gain there, at one-block windows too.
    let few = rarkit_testdata::medley(34, 5 << 20);
    let (_, (rounds, most), _) = with_team_cores(64, || write(wide(1, SMALL), &[&few]));
    assert!(
        rounds > 0 && most > 1,
        "-m1: {rounds} rounds of at most {most} engines"
    );
}

/// A volume provider that can be written back over, so a member takes the
/// streamed walk in a volume set as it does to a seekable archive.
#[derive(Default)]
struct Volumes(Vec<Vec<u8>>);

impl rarkit::VolumeOut for Volumes {
    type W = Vec<u8>;

    fn volume(&mut self, _index: u32) -> rarkit::Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn finished(&mut self, _index: u32, volume: Vec<u8>) -> rarkit::Result<()> {
        self.0.push(volume);
        Ok(())
    }

    fn can_patch(&self) -> bool {
        true
    }

    fn patch(&mut self, volume: &mut Vec<u8>, at: u64, bytes: &[u8]) -> rarkit::Result<()> {
        let at = at as usize;
        volume[at..at + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
}

/// One reader member written as a volume set. Answers the volumes and how
/// many members the streamed walk took.
fn write_volumes(options: WriteOptions, data: &[u8]) -> (Vec<Vec<u8>>, usize) {
    reset_segment_rounds();
    reset_streamed_members();
    let mut reader = Cursor::new(data);
    let mut writer = Writer::new(options).expect("options");
    writer
        .add(MemberSpec {
            name: b"m0.bin",
            payload: Payload::Reader {
                reader: &mut reader,
                size: <[u8]>::len(data) as u64,
                crc32: None,
            },
            mtime: None,
            attributes: 0o644,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut out = Volumes::default();
    writer.finish_volumes(&mut out).expect("finish_volumes");
    (out.0, streamed_members())
}

/// The streamed walk lays a member's header down before the packed size
/// is known and reserves the field's width from a bound. The bound is a
/// function of the member's declared size, the volume's room and the
/// packed bytes already placed, and of nothing the walk has pulled: so
/// the archive is the same whether the header was laid after one window
/// (one engine, a flush of one window), after a whole flush, or after a
/// round of the segment team.
///
/// The member is built to cross a width: its whole bound is over 2^21, a
/// four byte field, and its packed bytes are well under, so a walk that
/// had pulled most of it before the header would have taken three.
/// Before 1 Oct 2026 the bound was the input not yet pulled plus what was
/// pending, and a 512 MiB member at levels 1 to 3 was one byte shorter
/// from a team of 24 engines than from one
/// (counted 1 Oct 2026).
#[test]
fn a_streamed_members_size_field_does_not_follow_what_was_pulled() {
    pooled(a_streamed_members_size_field_does_not_follow_what_was_pulled_on_the_pool);
}

fn a_streamed_members_size_field_does_not_follow_what_was_pulled_on_the_pool() {
    let data = rarkit_testdata::medley(29, (5 << 19) + 1_234);
    for (family, format) in FORMATS {
        for level in [1u8, 3] {
            let what = format!("{family} -m{level}");
            let run = |depth: usize, width: usize| {
                with_stream_above(1 << 20, || {
                    with_window_depth(depth, || {
                        with_segment_width(width, || {
                            write(options(format, level, Some(SMALL)), &[&data])
                        })
                    })
                })
            };
            // One engine, one window a flush: the header is laid with
            // all but a window still to pull.
            let (one, rounds, took) = run(1, 1);
            assert_eq!(took, 1, "{what}: the member was held");
            assert_eq!(rounds, (0, 0), "{what}");
            reads_back(&what, &one, &[&data]);
            for depth in [1usize, 2, 64] {
                for width in [1usize, 2, 4] {
                    let (archive, _, took) = run(depth, width);
                    assert_eq!(took, 1, "{what}: depth {depth} width {width} held it");
                    assert_eq!(
                        archive.len(),
                        one.len(),
                        "{what}: flush depth {depth}, {width} engines: the archive's length"
                    );
                    assert!(
                        archive == one,
                        "{what}: flush depth {depth}, {width} engines moved a byte"
                    );
                }
            }
            // The team really ran where it could: a round of several
            // engines pulls several stretches before the header.
            let (_, (rounds, most), _) = run(64, 4);
            assert!(rounds > 0 && most > 1, "{what}: {rounds} rounds of {most}");
            // A caller's NAMED ceiling streams the member a window a flush
            // on one engine (spec G 3.5 case (c), mode 2), with no test
            // dial: the same archive again.
            let (named, rounds, took) = write(
                WriteOptions {
                    memory: MemoryPolicy::from_limit(1 << 20),
                    ..options(format, level, Some(SMALL))
                },
                &[&data],
            );
            assert_eq!(took, 1, "{what}: a named ceiling held the member");
            assert_eq!(rounds, (0, 0), "{what}: a named ceiling ran a team");
            assert!(named == one, "{what}: a named ceiling moved a byte");
        }
    }
}

/// The same in a VOLUME SET, where every fragment's field is reserved in
/// turn: at a fragment's start the bytes already placed are the volumes'
/// fills, the same at every width and flush depth, so the set is too.
///
/// Built so the member's LAST fragment crosses a width: a volume of 2.2
/// MB takes the head of the packed stream, what is left is under 2^21,
/// and the input one engine has still to pull at that boundary bounds to
/// over it, where a whole flush or a team's round has pulled nearly all
/// of it. On main before the fix the last volume was one byte shorter
/// from four engines at level 1, and at level 3 from ONE engine at a
/// whole flush against one window a flush: the flush depth is the memory
/// policy's, so that byte followed the machine's memory with no team.
#[test]
fn a_streamed_volume_sets_size_fields_do_not_follow_what_was_pulled() {
    pooled(a_streamed_volume_sets_size_fields_do_not_follow_what_was_pulled_on_the_pool);
}

fn a_streamed_volume_sets_size_fields_do_not_follow_what_was_pulled_on_the_pool() {
    let data = rarkit_testdata::medley(31, 8_400_000);
    for (family, format) in FORMATS {
        for level in [1u8, 3] {
            let what = format!("{family} -m{level} in volumes");
            let run = |depth: usize, width: usize| {
                with_stream_above(1 << 20, || {
                    with_window_depth(depth, || {
                        with_segment_width(width, || {
                            write_volumes(
                                WriteOptions {
                                    volume_size: Some(2_200_000),
                                    ..options(format, level, Some(SMALL))
                                },
                                &data,
                            )
                        })
                    })
                })
            };
            let (one, took) = run(1, 1);
            assert_eq!(took, 1, "{what}: the member was held");
            assert!(one.len() > 1, "{what}: one volume");
            for depth in [1usize, 2, 64] {
                for width in [1usize, 2, 4] {
                    let (set, took) = run(depth, width);
                    assert_eq!(took, 1, "{what}: depth {depth} width {width} held it");
                    assert!(
                        set == one,
                        "{what}: flush depth {depth}, {width} engines moved a byte"
                    );
                }
            }
        }
    }
}

/// And SEALED, `-p` and `-hp`: an encrypted last fragment's field carries
/// its padded length, a cipher block more, through the same bound. The
/// entropy is seeded, so two runs of one member draw the same salt and
/// vector and are the same bytes by design (spec G 3.13).
#[test]
fn a_sealed_streamed_members_size_field_does_not_follow_what_was_pulled() {
    pooled(a_sealed_streamed_members_size_field_does_not_follow_what_was_pulled_on_the_pool);
}

fn a_sealed_streamed_members_size_field_does_not_follow_what_was_pulled_on_the_pool() {
    let data = rarkit_testdata::medley(37, (5 << 19) + 1_234);
    for headers in [false, true] {
        for level in [1u8, 3] {
            let what = format!("rar5 -m{level} sealed, headers {headers}");
            let run = |depth: usize, width: usize| {
                with_stream_above(1 << 20, || {
                    with_window_depth(depth, || {
                        with_segment_width(width, || {
                            write(
                                WriteOptions {
                                    password: Some(rarkit::Password::new("segment")),
                                    encrypt_headers: headers,
                                    entropy: rarkit::Entropy::Seeded([9; 32]),
                                    ..options(WriteFormat::Rar5, level, Some(SMALL))
                                },
                                &[&data],
                            )
                        })
                    })
                })
            };
            let (one, _, took) = run(1, 1);
            assert_eq!(took, 1, "{what}: the member was held");
            for depth in [1usize, 2, 64] {
                for width in [1usize, 2, 4] {
                    let (archive, _, took) = run(depth, width);
                    assert_eq!(took, 1, "{what}: depth {depth} width {width} held it");
                    assert!(
                        archive == one,
                        "{what}: flush depth {depth}, {width} engines moved a byte"
                    );
                }
            }
        }
    }
}
