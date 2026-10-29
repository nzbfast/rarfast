//! The solid parse, pipelined across the members of a VOLUME SET
//! (spec G 3.9 and 3.10, spec H3 section 4).
//!
//! **What is being checked, and why it needs checking at all.** A solid
//! run is encoded in BATCHES: a run of members is staged and parsed as
//! one wave, so the blocks of one member are still being parsed on other
//! threads while the finder walks the member after it. That is a width,
//! and a width is a performance knob; the claim this file holds the
//! engine to is that it is ONLY a width. The same members, at the same
//! level, with the same volume cap, give the same archive to the byte at
//! any pipelining depth and at any thread count.
//!
//! A volume set is where that claim is hardest, and it is the shape a
//! poster writes. A volume boundary ENDS a solid run (spec G 3.9), and
//! where the boundary falls is not known until the packed bytes before it
//! are written, so a batch may turn out to span one: its members past the
//! boundary were encoded carrying a history the next volume does not
//! have. The writer discards those and encodes them again from the reset
//! run, and what this file measures is that nothing of that shows in the
//! bytes.
//!
//! **Depth 1 is the control arm.** It stages one member per batch, which
//! is the member-at-a-time walk the engine had before a batch existed, so
//! every row below is a comparison against the previous behaviour rather
//! than against itself.

use std::sync::Arc;

use rarkit::{
    extract, Disposition, MemberInfo, MemberSpec, Payload, RangeSource, ReadOptions, Result, Sink,
    WriteFormat, WriteMethod, WriteOptions, Writer,
};

/// The depths every shape is written at. 1 is a member at a time, 32 is
/// the depth a shipped build uses, and 2 and 4 are the shallow batches
/// that straddle a boundary most often.
const DEPTHS: [usize; 4] = [1, 2, 4, 32];

/// Collects each member's name and bytes, in archive order.
#[derive(Default)]
struct Collect {
    members: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Sink for Collect {
    type Out = Vec<u8>;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        self.members.push((member.name.to_vec(), Vec::new()));
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        _outcome: &rarkit::MemberOutcome,
    ) -> Result<()> {
        if let (Some(bytes), Some(last)) = (out, self.members.last_mut()) {
            last.1 = bytes;
        }
        Ok(())
    }
}

/// Reads a volume set back through this crate's own reader.
fn read_back(volumes: &[Vec<u8>]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let sources: Vec<Arc<dyn RangeSource>> = volumes
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect();
    let mut sink = Collect::default();
    extract(sources, &ReadOptions::default(), &mut sink, &mut ())
        .unwrap_or_else(|e| panic!("reading back what this writer wrote: {e}"));
    sink.members
}

/// The RAR 4 family refuses a filter REQUEST (SPEC-J).
fn filters_for(format: WriteFormat) -> rarkit::FilterPolicy {
    if matches!(format, WriteFormat::Rar4(_)) {
        rarkit::FilterPolicy::Off
    } else {
        rarkit::FilterPolicy::default()
    }
}

/// One shape: a name, and the members it writes.
struct Shape {
    name: &'static str,
    members: Vec<(Vec<u8>, Vec<u8>)>,
}

/// The shapes this file writes, each one a thing that has broken a
/// pipelined writer or could.
fn shapes() -> Vec<Shape> {
    vec![
        Shape {
            name: "plain",
            members: (0..12)
                .map(|i| {
                    (
                        format!("m{i}.txt").into_bytes(),
                        rarkit_testdata::chatter(i as u64 + 1, 4_000 + i * 37),
                    )
                })
                .collect(),
        },
        Shape {
            // A zero-length member in the middle of the chain: it writes
            // a header and no payload, reaches no encoder, and must not
            // break the run around it (spec G 3.9).
            name: "empty-in-chain",
            members: (0..9)
                .map(|i| {
                    let len = if i == 4 { 0 } else { 5_000 + i * 11 };
                    (
                        format!("m{i}.txt").into_bytes(),
                        rarkit_testdata::chatter(i as u64 + 20, len),
                    )
                })
                .collect(),
        },
        Shape {
            // Every member far smaller than one parse block (256 KiB),
            // so a batch is the only thing that makes the wave wide at
            // all.
            name: "tiny",
            members: (0..40)
                .map(|i| {
                    (
                        format!("t{i}.txt").into_bytes(),
                        rarkit_testdata::chatter(i as u64 + 40, 300 + i * 3),
                    )
                })
                .collect(),
        },
        Shape {
            // One member long enough to span three volumes at the caps
            // below, with members either side of it.
            name: "spans-volumes",
            members: vec![
                (b"head.txt".to_vec(), rarkit_testdata::chatter(7, 2_000)),
                (b"long.txt".to_vec(), rarkit_testdata::chatter(8, 400_000)),
                (b"tail.txt".to_vec(), rarkit_testdata::chatter(9, 2_500)),
            ],
        },
    ]
}

/// Writes `members` under `options` at pipelining depth `depth`.
fn volumes_at(depth: usize, options: WriteOptions, members: &[(Vec<u8>, Vec<u8>)]) -> Vec<Vec<u8>> {
    rarkit::internals::writers::with_batch_depth(depth, || {
        let mut writer = Writer::new(options).expect("options");
        for (name, data) in members {
            writer
                .add(MemberSpec {
                    name,
                    payload: Payload::Bytes(data),
                    mtime: None,
                    attributes: 0,
                    host_os: rarkit::HostOs::Unix,
                    is_directory: false,
                })
                .expect("add");
        }
        let mut out: Vec<Vec<u8>> = Vec::new();
        writer.finish_volumes(&mut out).expect("finish_volumes");
        out
    })
}

/// A solid volume set's options at `level`, capped as a whole FILE.
fn solid_options(format: WriteFormat, cap: u64, file_budget: bool) -> WriteOptions {
    WriteOptions {
        format,
        method: WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
        solid: true,
        // Ordering is not what this test is about: keep the add order.
        order: rarkit::MemberOrder::AsAdded,
        filters: filters_for(format),
        volume_size: (!file_budget).then_some(cap),
        volume_file_size: file_budget.then_some(cap),
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    }
}

fn families() -> [(&'static str, WriteFormat); 2] {
    [
        ("rar5", WriteFormat::Rar5),
        ("rar4", WriteFormat::Rar4(rarkit::Rar4Version::V29)),
    ]
}

/// The claim itself: the depth moves no byte of a solid volume set, and
/// every depth's set reads back to the bytes that went in.
#[test]
fn a_solid_volume_set_is_the_same_archive_at_every_depth() {
    for (family, format) in families() {
        for shape in shapes() {
            for file_budget in [false, true] {
                let mut was_a_set = false;
                for cap in [1_024u64, 4_096, 20_000, 100_000] {
                    let control = volumes_at(
                        DEPTHS[0],
                        solid_options(format, cap, file_budget),
                        &shape.members,
                    );
                    // A cap larger than the whole compressed set writes
                    // ONE volume, which is a fine archive and not a set;
                    // the row below requires that some cap made a set.
                    was_a_set |= control.len() > 1;
                    assert_eq!(
                        read_back(&control),
                        shape.members,
                        "{family}/{}: the control arm did not read back at cap {cap}",
                        shape.name
                    );
                    for depth in &DEPTHS[1..] {
                        let theirs = volumes_at(
                            *depth,
                            solid_options(format, cap, file_budget),
                            &shape.members,
                        );
                        assert_eq!(
                            theirs, control,
                            "{family}/{}: depth {depth} moved a byte at cap {cap} \
                             (file budget {file_budget})",
                            shape.name
                        );
                    }
                }
                assert!(
                    was_a_set,
                    "{family}/{}: no cap wrote more than one volume, so nothing here \
                     measured a volume set (file budget {file_budget})",
                    shape.name
                );
            }
        }
    }
}

/// A member that starts EXACTLY at a volume boundary is the shape the
/// `write_volumes` fuzz target found on 19 Sep 2026, and a batch is the
/// one thing that can encode it before knowing it starts one. Rather
/// than solve for a cap that lands there, this sweeps a range of caps
/// wide enough that several of them do.
#[test]
fn a_boundary_that_falls_at_a_member_edge_moves_no_byte() {
    let members: Vec<(Vec<u8>, Vec<u8>)> = (0..10)
        .map(|i| {
            (
                format!("b{i}.txt").into_bytes(),
                rarkit_testdata::chatter(i as u64 + 100, 600 + i * 17),
            )
        })
        .collect();
    for (family, format) in families() {
        for cap in 700u64..820 {
            let control = volumes_at(1, solid_options(format, cap, true), &members);
            let batched = volumes_at(32, solid_options(format, cap, true), &members);
            assert_eq!(
                batched, control,
                "{family}: depth 32 moved a byte at a {cap} byte cap"
            );
            for (index, volume) in control.iter().enumerate() {
                assert!(
                    volume.len() as u64 <= cap,
                    "{family}: volume {index} is {} bytes against a {cap} byte cap",
                    volume.len()
                );
            }
            assert_eq!(
                read_back(&control),
                members,
                "{family}: a {cap} byte capped set did not read back"
            );
        }
    }
}

/// The thread count is not an input to the archive either (SPEC-API 2.6),
/// and a batch is what makes several threads reachable at all here.
#[test]
fn a_solid_volume_set_is_the_same_archive_at_every_thread_count() {
    let shape = &shapes()[0];
    for (family, format) in families() {
        let control = rarkit::internals::rar20::on_threads(1, || {
            volumes_at(32, solid_options(format, 20_000, true), &shape.members)
        });
        for threads in [2usize, 4, 8] {
            let theirs = rarkit::internals::rar20::on_threads(threads, || {
                volumes_at(32, solid_options(format, 20_000, true), &shape.members)
            });
            assert_eq!(
                theirs, control,
                "{family}: {threads} threads moved a byte of a solid volume set"
            );
        }
    }
}

/// **Scope.** The pipeline is a solid VOLUME SET's, and nothing else may
/// move: a single archive and a NON-SOLID set are both written by the
/// same walk and must be untouched by the depth.
#[test]
fn a_single_archive_and_a_non_solid_set_are_untouched_by_the_depth() {
    let shape = &shapes()[0];
    for (family, format) in families() {
        // One archive, solid.
        let mut control = Vec::new();
        for depth in DEPTHS {
            let theirs = rarkit::internals::writers::with_batch_depth(depth, || {
                let mut writer = Writer::new(WriteOptions {
                    format,
                    method: WriteMethod::Compressed {
                        level: 3,
                        dictionary: None,
                    },
                    solid: true,
                    // Ordering is not what this test is about: keep the add order.
                    order: rarkit::MemberOrder::AsAdded,
                    filters: filters_for(format),
                    host_os: rarkit::HostOs::Unix,
                    ..WriteOptions::default()
                })
                .expect("options");
                for (name, data) in &shape.members {
                    writer
                        .add(MemberSpec {
                            name,
                            payload: Payload::Bytes(data),
                            mtime: None,
                            attributes: 0,
                            host_os: rarkit::HostOs::Unix,
                            is_directory: false,
                        })
                        .expect("add");
                }
                let mut out = Vec::new();
                writer.finish_into(&mut out).expect("finish_into");
                out
            });
            if depth == DEPTHS[0] {
                control = theirs;
            } else {
                assert_eq!(
                    theirs, control,
                    "{family}: depth {depth} moved a byte of a SINGLE solid archive"
                );
            }
        }
        // A volume set that is not solid: no run, so no batch.
        let plain = |depth: usize| {
            let mut options = solid_options(format, 20_000, true);
            options.solid = false;
            volumes_at(depth, options, &shape.members)
        };
        let control = plain(DEPTHS[0]);
        for depth in &DEPTHS[1..] {
            assert_eq!(
                plain(*depth),
                control,
                "{family}: depth {depth} moved a byte of a NON-SOLID volume set"
            );
        }
    }
}

/// **What the pipeline costs in bytes, as a test rather than a claim.**
///
/// A batch stages several members' input and holds the PACKED output of
/// the ones the writer has not reached yet, so the question a pipelined
/// writer has to answer is what bounds that. Every term is bounded by the
/// OPTIONS and not by the archive:
///
/// - the encoder's history, which is the dictionary plus its slack;
/// - the encoder's match finder, sized from the dictionary and the plan
///   and counted in the report since 28 Sep 2026: at level 3 the chains'
///   2^20 heads and 16 Mi links (their floor), 68 MiB;
/// - the blocks in flight, which a batch widens rather than adds;
/// - the batch's pending packed output, bounded by `Engine::batch_cap`
///   at 32 parse blocks, which is 8 MiB, and by the volume's remaining
///   room besides;
/// - held headers: NONE. Spec G 3.5's reserved packed size field is
///   written with the true value rather than patched (`Run::packed_reserve`
///   says why it can be), so nothing is held for a correction and
///   `WriteReport::held_volume_bytes` is zero.
///
/// The one term still following the archive is one member's own packed
/// output, which a member too large to batch holds whole; that is
/// `Run::packed`'s open item and it is not closed here.
///
/// The figure below is asserted against a CEILING and printed, so a
/// change that made the pipeline hold more would fail rather than pass
/// quietly with a bigger number.
#[test]
fn what_the_pipeline_holds_is_bounded_by_the_options() {
    /// The chains' 68 MiB, and 64 MiB for everything else: far above what
    /// the other terms come to at these options (about 5 MiB), and far
    /// below anything that follows the archive.
    const CEILING: u64 = (68 << 20) + (64 << 20);

    for (family, format) in families() {
        let members: Vec<(Vec<u8>, Vec<u8>)> = (0..200)
            .map(|i| {
                (
                    format!("p{i:03}.txt").into_bytes(),
                    rarkit_testdata::chatter(i as u64 + 500, 20_000 + i * 13),
                )
            })
            .collect();
        let mut writer = Writer::new(solid_options(format, 100_000, true)).expect("options");
        for (name, data) in &members {
            writer
                .add(MemberSpec {
                    name,
                    payload: Payload::Bytes(data),
                    mtime: None,
                    attributes: 0,
                    host_os: rarkit::HostOs::Unix,
                    is_directory: false,
                })
                .expect("add");
        }
        let mut out: Vec<Vec<u8>> = Vec::new();
        let report = writer.finish_volumes(&mut out).expect("finish_volumes");
        assert!(out.len() > 1, "{family}: not a set");
        eprintln!(
            "{family}: {} members over {} volumes, peak working memory {} bytes, held {} bytes",
            members.len(),
            out.len(),
            report.peak_working_memory,
            report.held_volume_bytes
        );
        assert!(
            report.peak_working_memory <= CEILING,
            "{family}: the pipeline held {} bytes, over the {CEILING} byte ceiling",
            report.peak_working_memory
        );
        assert_eq!(
            report.held_volume_bytes, 0,
            "{family}: bytes were held for a correction, and this writer patches nothing"
        );
    }
}
