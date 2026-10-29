//! The writer's batch of sixty-four parse blocks and the chain levels'
//! SLIDING waves (30 Sep 2026) are widths, and
//! nothing else: every archive here is the archive the writer wrote before
//! them, to the byte.
//!
//! **The control arm** is the writer before that day: a batch of 32 blocks
//! (`encode::drive::BATCH_BLOCKS_MOST` was 32) and waves that end on their
//! slowest block. `with_wave_arms(Some(32), Some(false), ..)` restores
//! both inside this binary. The two levers are also compared one at a
//! time, so a difference names its lever.
//!
//! **What the rows reach.** A span only wraps the chains' cyclic buffer
//! (16 Mi positions at these dictionaries) past 16 MiB, and a flush is cut
//! into waves only then, so the rows are long enough for a streamed member
//! to slide its history at least twice: the first flush after a slide is
//! 64 blocks of an 18 MiB history, a wave of 55 and then 9 under the old
//! arm, one sliding flush under the new. They cover the member read from a
//! reader a window at a time (the command line's path), a member held
//! whole and encoded as one region, a solid set whose batch spans members,
//! levels 1 to 3 on the chains and 5 on the tree (whose flushes the batch
//! widens and which never slides), the RAR 4 family's encoder, and one
//! thread, three, and the pool's width. The content is mostly noise, which
//! samples as not worth searching and parses at the floor, with stretches
//! of words and x86-like calls that the level's own parse takes, so level
//! 3's optimal parse runs on real blocks at a test's cost.
//! `slid_flushes` says the sliding path was taken where it should be.

use std::io::Cursor;
use std::sync::Arc;

use rarkit::{
    extract, Disposition, FilterPolicy, MemberInfo, MemberOutcome, MemberSpec, MemoryPolicy,
    Payload, RangeSource, ReadOptions, Sink, WriteFormat, WriteMethod, WriteOptions, Writer,
};

use rarkit::internals::writers::{slid_flushes, with_wave_arms};

fn options(
    format: WriteFormat,
    level: u8,
    dictionary: u64,
    workers: Option<usize>,
) -> WriteOptions {
    WriteOptions {
        format,
        method: WriteMethod::Compressed {
            level,
            dictionary: Some(dictionary),
        },
        // The RAR 4 family refuses a filter request (SPEC-J).
        filters: if matches!(format, WriteFormat::Rar4(_)) {
            FilterPolicy::Off
        } else {
            FilterPolicy::Detect
        },
        host_os: rarkit::HostOs::Unix,
        memory: MemoryPolicy::default(),
        workers,
        ..WriteOptions::default()
    }
}

/// How a row hands its members to the writer.
#[derive(Clone, Copy)]
enum Shape {
    /// One member through `Payload::Reader`: the windowed walk.
    Reader,
    /// One member as `Payload::Bytes`: held whole, one region.
    Held,
    /// A solid set of members of `usize` bytes each, as `Payload::Bytes`.
    Solid(usize),
}

fn write(options: WriteOptions, shape: Shape, data: &[u8]) -> Vec<u8> {
    let solid = matches!(shape, Shape::Solid(_));
    let mut writer = Writer::new(WriteOptions { solid, ..options }).expect("options");
    let mut reader = Cursor::new(data);
    let names: Vec<Vec<u8>> = match shape {
        Shape::Solid(each) => (0..data.len().div_ceil(each))
            .map(|at| format!("m{at:04}.bin").into_bytes())
            .collect(),
        _ => vec![b"one.bin".to_vec()],
    };
    match shape {
        Shape::Reader => writer
            .add(MemberSpec {
                name: &names[0],
                payload: Payload::Reader {
                    reader: &mut reader,
                    size: data.len() as u64,
                    crc32: None,
                },
                mtime: None,
                attributes: 0o644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add"),
        Shape::Held => writer
            .add(MemberSpec {
                name: &names[0],
                payload: Payload::Bytes(data),
                mtime: None,
                attributes: 0o644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add"),
        Shape::Solid(each) => {
            for (name, chunk) in names.iter().zip(data.chunks(each)) {
                writer
                    .add(MemberSpec {
                        name,
                        payload: Payload::Bytes(chunk),
                        mtime: None,
                        attributes: 0o644,
                        host_os: rarkit::HostOs::Unix,
                        is_directory: false,
                    })
                    .expect("add");
            }
        }
    }
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

/// rarkit's own reader gives the members back, in order.
fn reads_back(archive: &[u8], data: &[u8], what: &str) {
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(archive.to_vec())];
    let mut sink = Collect::default();
    extract(sources, &ReadOptions::default(), &mut sink, &mut ())
        .unwrap_or_else(|e| panic!("{what}: rarkit could not read it back: {e}"));
    assert!(sink.0 == data, "{what}: the members came back different");
}

/// A 64-bit FNV-1a digest, for the failure message.
fn digest(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3)
    })
}

/// A member of 64 KiB stretches: one in `searched` is text or code (a
/// stretch of the shared three-kind member), the rest noise, which no
/// search is made in.
fn corpus(len: usize, seed: u64, searched: u32) -> Vec<u8> {
    let mut out = rarkit_testdata::scramble(seed, len);
    let found = rarkit_testdata::medley(seed, len);
    for (at, (stretch, text)) in out
        .chunks_mut(64 << 10)
        .zip(found.chunks(64 << 10))
        .enumerate()
    {
        if (at as u32).is_multiple_of(searched) {
            stretch.copy_from_slice(text);
        }
    }
    out
}

struct Row {
    what: &'static str,
    format: WriteFormat,
    level: u8,
    dictionary: u64,
    shape: Shape,
    len: usize,
    /// One stretch in this many is searched text or code.
    searched: u32,
    /// The shipped arm must take the sliding waves at least once.
    slides: bool,
}

fn rows() -> Vec<Row> {
    let rar4 = WriteFormat::Rar4(rarkit::Rar4Version::V29);
    let two = 2u64 << 20;
    vec![
        Row {
            what: "rar5 m1 reader",
            format: WriteFormat::Rar5,
            level: 1,
            dictionary: two,
            shape: Shape::Reader,
            len: (34 << 20) + 4_099,
            searched: 2,
            slides: true,
        },
        Row {
            what: "rar5 m2 reader",
            format: WriteFormat::Rar5,
            level: 2,
            dictionary: two,
            shape: Shape::Reader,
            len: (33 << 20) + 17,
            searched: 3,
            slides: true,
        },
        Row {
            what: "rar5 m3 reader",
            format: WriteFormat::Rar5,
            level: 3,
            dictionary: two,
            shape: Shape::Reader,
            len: (34 << 20) + 777,
            searched: 4,
            slides: true,
        },
        // Held whole: one region of 84 blocks, waves of 63 at a 256 KiB
        // dictionary.
        Row {
            what: "rar5 m3 held",
            format: WriteFormat::Rar5,
            level: 3,
            dictionary: 256 << 10,
            shape: Shape::Held,
            len: (21 << 20) + 5,
            searched: 4,
            slides: true,
        },
        // A solid batch across members at 4 MiB: the solid slack is 16
        // MiB, so the batch is 64 blocks where it was 32, and waves of 47.
        Row {
            what: "rar5 m1 solid 4m",
            format: WriteFormat::Rar5,
            level: 1,
            dictionary: 4 << 20,
            shape: Shape::Solid(300_001),
            len: 44 << 20,
            searched: 2,
            slides: true,
        },
        // The tree: the batch widens its flushes; its waves are the tree's
        // own and never slide.
        Row {
            what: "rar5 m5 reader",
            format: WriteFormat::Rar5,
            level: 5,
            dictionary: two,
            shape: Shape::Reader,
            len: (19 << 20) + 3,
            searched: 4,
            slides: false,
        },
        Row {
            what: "rar4 m3 reader",
            format: rar4,
            level: 3,
            dictionary: two,
            shape: Shape::Reader,
            len: (34 << 20) + 1,
            searched: 4,
            slides: true,
        },
    ]
}

/// The arms: (name, batch blocks, waves slide, windows share a buffer).
/// The first is the control.
type Arm = (&'static str, Option<usize>, Option<bool>, Option<bool>);

const ARMS: [Arm; 5] = [
    ("before 30 Sep", Some(32), Some(false), Some(false)),
    ("batch 64 alone", None, Some(false), Some(false)),
    ("sliding alone", Some(32), None, Some(false)),
    ("one buffer alone", Some(32), Some(false), None),
    ("shipped", None, None, None),
];

#[test]
fn every_arm_writes_the_archive_the_writer_wrote_before() {
    for row in rows() {
        let data = corpus(row.len, row.len as u64, row.searched);
        // One thread, three, and the pool's width; every arm at each.
        for workers in [Some(1), Some(3), None] {
            let what = format!("{} at {workers:?} workers", row.what);
            let write_arm = |blocks, slide, merge| {
                with_wave_arms(blocks, slide, merge, || {
                    let before = slid_flushes();
                    let archive = write(
                        options(row.format, row.level, row.dictionary, workers),
                        row.shape,
                        &data,
                    );
                    (archive, slid_flushes() - before)
                })
            };
            let (control, control_slid) = write_arm(ARMS[0].1, ARMS[0].2, ARMS[0].3);
            assert_eq!(control_slid, 0, "{what}: the control arm slid its waves");
            reads_back(&control, &data, &what);
            // Past one thread, every arm; at one, the control and the
            // shipped arm, which is the path a narrow box takes.
            let arms = if workers == Some(1) {
                &ARMS[4..]
            } else {
                &ARMS[1..]
            };
            for &(arm, blocks, slide, merge) in arms {
                let (archive, slid) = write_arm(blocks, slide, merge);
                assert!(
                    archive == control,
                    "{what}, {arm}: a different archive ({} bytes, digest {:016x}, against {} and {:016x})",
                    archive.len(),
                    digest(&archive),
                    control.len(),
                    digest(&control),
                );
                // At a batch of 32 a streamed or solid flush is narrower
                // than one wave and has nothing to slide; a region held
                // whole is cut into waves at any batch.
                let wide = blocks.is_none() || matches!(row.shape, Shape::Held);
                if slide.is_none() && row.slides && wide {
                    assert!(slid > 0, "{what}, {arm}: no flush took the sliding waves");
                }
                if slide == Some(false) {
                    assert_eq!(slid, 0, "{what}, {arm}: a flush slid with sliding off");
                }
            }
        }
    }
}
