//! Since 28 Sep 2026: with NO ceiling named, a member whose held
//! packed bound passes `MemoryPolicy::DEFAULT_LIMIT` is STREAMED wherever
//! the output can patch: a member of a non-solid volume set (spec G 3.5
//! case b) and, new, a member of one archive over an output that can seek
//! (case c). Its packed size field is reserved a FRAGMENT at a time, at the
//! width of the least of the volume's room and a bound on what the member
//! has still to place, and the streamed walk stages its windows and takes
//! the held walk's slack, so a fragment that fills its volume is the held
//! walk's fragment to the byte and only a LAST fragment's field can be a
//! digit wider. An output that cannot patch still holds the member.
//!
//! The threshold is lowered for these rows (`with_stream_above`), so that a
//! member of a few MiB takes the walk a member of hundreds of MiB takes in
//! a shipped build; the rows that keep the shipped threshold say so.

use std::io::{Cursor, Read};
use std::sync::Arc;

use rarkit::internals::writers::{
    reset_streamed_members, streamed_members, with_segment_width, with_stream_above,
};
use rarkit::{
    extract, Disposition, MemberInfo, MemberOutcome, MemberSpec, Payload, RangeSource, ReadOptions,
    Result, Sink, VolumeOut, WriteFormat, WriteMethod, WriteOptions, WriteReport, Writer,
};

const MIB: usize = 1 << 20;

/// Volumes that can patch, or not: the only difference between the two
/// arms of the volume rows.
struct Volumes {
    patches: bool,
    kept: Vec<Vec<u8>>,
}

impl VolumeOut for Volumes {
    type W = Vec<u8>;

    fn volume(&mut self, _index: u32) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn finished(&mut self, _index: u32, volume: Vec<u8>) -> Result<()> {
        self.kept.push(volume);
        Ok(())
    }

    fn can_patch(&self) -> bool {
        self.patches
    }

    fn patch(&mut self, volume: &mut Vec<u8>, at: u64, bytes: &[u8]) -> Result<()> {
        let at = at as usize;
        volume[at..at + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
}

#[derive(Default)]
struct Collect(Vec<Vec<u8>>);

impl Sink for Collect {
    type Out = Vec<u8>;

    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        self.0.push(Vec::new());
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        assert_eq!(
            outcome.checksum_ok,
            Some(true),
            "a member failed its checksum"
        );
        if let (Some(bytes), Some(last)) = (out, self.0.last_mut()) {
            *last = bytes;
        }
        Ok(())
    }
}

fn read_back(volumes: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let sources: Vec<Arc<dyn RangeSource>> = volumes
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect();
    let mut sink = Collect::default();
    extract(sources, &ReadOptions::default(), &mut sink, &mut ())
        .unwrap_or_else(|e| panic!("reading back: {e}"));
    sink.0
}

fn options(format: WriteFormat, volume: Option<u64>) -> WriteOptions {
    WriteOptions {
        format,
        method: WriteMethod::Compressed {
            level: 1,
            dictionary: None,
        },
        volume_size: volume,
        filters: if matches!(format, WriteFormat::Rar4(_)) {
            rarkit::FilterPolicy::Off
        } else {
            rarkit::FilterPolicy::Detect
        },
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    }
}

/// How an archive is finished.
#[derive(Clone, Copy, PartialEq)]
enum Finish {
    /// One archive over an output that can seek: case (c) streams.
    Seek,
    /// One archive over an output that cannot: held.
    Into,
    /// A volume set whose volumes can patch: case (b) streams.
    Patch,
    /// A volume set whose volumes cannot: held.
    Hold,
}

/// One member through a READER, the CLI's payload. Answers the volumes,
/// the report and how many members the streamed walk took.
fn write(options: WriteOptions, finish: Finish, data: &[u8]) -> (Vec<Vec<u8>>, WriteReport, usize) {
    reset_streamed_members();
    let mut reader = Cursor::new(data);
    let mut writer = Writer::new(options).expect("options");
    writer
        .add(MemberSpec {
            name: b"big.bin",
            payload: Payload::Reader {
                reader: &mut reader as &mut (dyn Read + Send),
                size: data.len() as u64,
                crc32: None,
            },
            mtime: None,
            attributes: 0o644,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let (volumes, report) = match finish {
        Finish::Seek => {
            let mut out = Cursor::new(Vec::new());
            let report = writer.finish_seek(&mut out).expect("finish_seek");
            (vec![out.into_inner()], report)
        }
        Finish::Into => {
            let mut out = Vec::new();
            let report = writer.finish_into(&mut out).expect("finish_into");
            (vec![out], report)
        }
        Finish::Patch | Finish::Hold => {
            let mut out = Volumes {
                patches: finish == Finish::Patch,
                kept: Vec::new(),
            };
            let report = writer.finish_volumes(&mut out).expect("finish_volumes");
            (out.kept, report)
        }
    };
    (volumes, report, streamed_members())
}

const FORMATS: [WriteFormat; 2] = [
    WriteFormat::Rar5,
    WriteFormat::Rar4(rarkit::Rar4Version::V29),
];

/// Case (c): one archive over an output that can seek STREAMS a member
/// above the threshold, and over one that cannot HOLDS it; the two are the
/// same archive but for the packed size field's width, at most a digit,
/// and both read back.
#[test]
fn one_archive_streams_over_a_seekable_output_and_holds_otherwise() {
    let data = rarkit_testdata::medley(1, 6 * MIB + 321);
    for format in FORMATS {
        let (streamed, _, took) = with_stream_above(MIB as u64, || {
            write(options(format, None), Finish::Seek, &data)
        });
        let (held, _, held_took) = with_stream_above(MIB as u64, || {
            write(options(format, None), Finish::Into, &data)
        });
        assert_eq!(
            took, 1,
            "{format:?}: a member above the threshold did not stream"
        );
        assert_eq!(
            held_took, 0,
            "{format:?}: an output that cannot seek streamed"
        );
        let (s, h) = (&streamed[0], &held[0]);
        assert!(
            s.len() >= h.len() && s.len() <= h.len() + 1,
            "{format:?}: streamed {} bytes, held {}",
            s.len(),
            h.len()
        );
        if matches!(format, WriteFormat::Rar4(_)) {
            // A fixed-width field: the two archives are the same bytes.
            assert!(
                s == h,
                "{format:?}: the streamed archive differs from the held one"
            );
        }
        assert_eq!(
            read_back(&streamed),
            vec![data.clone()],
            "{format:?}: streamed"
        );
        assert_eq!(read_back(&held), vec![data.clone()], "{format:?}: held");
    }
}

/// Below the threshold nothing changes: the member is held over every
/// output, and the archive is the one the held walk wrote before the
/// rule, to the byte.
#[test]
fn a_member_below_the_threshold_is_held_and_unchanged() {
    let data = rarkit_testdata::medley(2, 6 * MIB);
    for format in FORMATS {
        let (seek, _, took) = with_stream_above(64 * MIB as u64, || {
            write(options(format, None), Finish::Seek, &data)
        });
        let (into, _, _) = with_stream_above(64 * MIB as u64, || {
            write(options(format, None), Finish::Into, &data)
        });
        assert_eq!(took, 0, "{format:?}: a member under the threshold streamed");
        assert!(
            seek == into,
            "{format:?}: the held archive depends on the output"
        );
    }
}

/// Case (b) with no ceiling: a non-solid volume set streams, and every
/// volume but the last is the held set's volume to the byte, because a
/// fragment that fills its volume is laid down at the held walk's own
/// width; the last may be a digit longer.
#[test]
fn a_volume_set_streams_and_differs_from_the_held_set_only_in_its_last_volume() {
    let data = rarkit_testdata::medley(3, 7 * MIB + 99);
    for format in FORMATS {
        for cap in [700_000u64, 2_000_000] {
            let (streamed, _, took) = with_stream_above(MIB as u64, || {
                write(options(format, Some(cap)), Finish::Patch, &data)
            });
            let (held, _, held_took) = with_stream_above(MIB as u64, || {
                write(options(format, Some(cap)), Finish::Hold, &data)
            });
            assert_eq!(took, 1, "{format:?} cap {cap}: the member did not stream");
            assert_eq!(
                held_took, 0,
                "{format:?} cap {cap}: volumes that cannot patch streamed"
            );
            assert_eq!(
                streamed.len(),
                held.len(),
                "{format:?} cap {cap}: volume count"
            );
            let n = streamed.len();
            assert!(n >= 2, "{format:?} cap {cap}: not a set");
            for i in 0..n - 1 {
                assert!(
                    streamed[i] == held[i],
                    "{format:?} cap {cap}: volume {i} of {n} differs from the held set's"
                );
            }
            let (s, h) = (streamed[n - 1].len(), held[n - 1].len());
            assert!(
                s >= h && s <= h + 1,
                "{format:?} cap {cap}: last volume {s} against {h}"
            );
            assert_eq!(
                read_back(&streamed),
                vec![data.clone()],
                "{format:?} cap {cap}"
            );
        }
    }
}

/// Text with a byte of noise in every thirty-two: uniform in how it
/// packs, and far from packing away to nothing, so the held walk's
/// packed bytes really do follow the member. How much noise is a
/// measured choice (11 Oct 2026, thirty runs on a loaded Apple silicon
/// laptop): what the streamed walk holds varies from run to run with the
/// batch in flight, and with one byte in six it moved by 4.1 MB between
/// the two members in one run of twelve, over the 3 MiB the row allows;
/// with one in thirty-two by 1.8 MB at most, while the held walk still
/// grows by 10.5 MB and more where the row asks for over 6 MiB.
fn text(len: usize, seed: u64) -> Vec<u8> {
    let mut out = rarkit_testdata::chatter(seed, len);
    let noise = rarkit_testdata::scramble(seed, len / 32 + 1);
    for (run, &byte) in out.chunks_mut(32).zip(&noise) {
        run[0] = byte;
    }
    out
}

/// What the streamed walk holds does not follow the member, where the held
/// walk's does: the reason for the rule, as a figure.
///
/// Three things are held constant so that what is compared is the WALK:
/// the dictionary is named (the default one is fitted to the member); both
/// members are past the engine's batch cap (32 parse blocks, 8 MiB), below
/// which a member is staged whole; and the data is uniform text, because
/// what is pending is one batch's PACKED bytes, which on a member of mixed
/// stretches varies with the stretches a batch happens to hold (measured:
/// 70.7 MB at 12 MiB rising to 84.2 MB at 192 MiB on this file's mixed
/// member, one batch's packed bytes and never more). The one term left
/// that grows with the member is spec G 3.8.3's reader prefix, pulled to
/// the sample that settles the vote: 3/32 of the first 32 MiB and half a
/// sample, at most 3 MiB, which `SAME` allows.
///
/// ONE TERM OF THE FIGURE FOLLOWS THE SCHEDULER, NOT THE MEMBER, and the
/// row is asserted twice because of it (11 Oct 2026). The encoder keeps a
/// parse scratch for every parse that was ever in flight at once, for the
/// whole run, and how many overlap is the scheduler's doing: at least
/// one, at most the wave, which is the lesser of the wave's sixteen
/// blocks and the pool's threads. Measured on this text on an 18 thread
/// Apple silicon laptop at a load of 50 to 60, 24 rounds: 7 to 11
/// scratches for the 12 MiB member and 11 to 14 for the 48 MiB one, 354,607
/// to 359,658 bytes each on average, and every other term the same from
/// run to run but the pending batch (904,598 to 1,210,049 bytes); so the
/// two peaks differed by -0.68 to +2.44 MB with nothing about the member
/// in it, and 3 MiB between them is not a promise the walk makes at a
/// width above one.
///
/// (a) AT ONE THREAD, the pool built here and one wide: one parse is in
///     flight at a time and ONE scratch exists, reused for every block, so
///     it is as large as any scratch grows (398,292 bytes measured); the
///     figure is the same number run after run, and the two members'
///     peaks are within `SAME`, the prefix's allowance (measured: equal,
///     53,013,557 bytes each).
/// (b) AT ANY WIDTH, the pool this test is run on: a peak is at most the
///     one-thread peak of the SAME member, plus a scratch for each of the
///     wave's other fifteen blocks, plus what a pool wider than one holds
///     besides (1,048,659 bytes measured, the same in every run):
///
///         peak(width) <= peak(1) + (WAVE - 1) * SCRATCH + WIDER
///                      = peak(1) + 15 * 409,600 + 1,572,864
///                      = peak(1) + 7,716,864 bytes
///
///     `SCRATCH` being 400 KiB against the 398,292 of the largest, and
///     `WIDER` a megabyte and a half against the 1,048,659. The pending
///     batch needs no term: the one-thread run already holds the most of
///     it (1,210,049). The most these figures can make at this width is
///     7,023,039 over the one-thread peak (sixteen scratches all at the
///     largest); the most seen was 5,647,683. With (a) that puts the 48
///     MiB member's peak at ANY width under the 12 MiB member's
///     one-thread peak plus `SAME` plus those 7,716,864 bytes: a ceiling
///     with no load and no member size in it.
#[test]
fn what_the_default_streamed_walk_holds_does_not_follow_the_member() {
    const SAME: u64 = 3 << 20;
    /// The blocks of a parse wave, each of which may keep a scratch.
    const WAVE: u64 = 16;
    /// One parse scratch on this text at this level, at its largest and
    /// rounded up.
    const SCRATCH: u64 = 400 << 10;
    /// What a pool wider than one holds besides, rounded up.
    const WIDER: u64 = 3 << 19;
    const REST_OF_THE_WAVE: u64 = (WAVE - 1) * SCRATCH + WIDER;
    let small = text(12 * MIB, 4);
    // One seed: the large member is the small one, carried on.
    let large = text(48 * MIB, 4);
    let peak = |data: &[u8], finish| {
        let options = WriteOptions {
            method: WriteMethod::Compressed {
                level: 1,
                dictionary: Some(1 << 20),
            },
            ..options(WriteFormat::Rar5, None)
        };
        // The SEGMENT TEAM held to one engine (SPEC-G 3.7.3's acceptance
        // test 5): with no ceiling named it runs as many engines as the
        // member has stretches, the pool has cores and the working limit
        // affords, so what the team holds DOES follow the member up to
        // that bound, and `tests/team_memory.rs` holds that bound. What
        // is compared here is the two WALKS.
        with_segment_width(1, || {
            with_stream_above(MIB as u64, || write(options, finish, data))
        })
        .1
        .peak_working_memory
    };
    // The same measurement on a pool of ONE thread, built here.
    let one_thread = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .expect("a pool of one thread");
    let alone = |data: &[u8]| one_thread.install(|| peak(data, Finish::Seek));

    // (a) One thread: the bound as it always was.
    let (alone_small, alone_large) = (alone(&small), alone(&large));
    assert!(
        alone_large <= alone_small + SAME,
        "streamed on one thread: {alone_small} bytes for 12 MiB and {alone_large} for 48 MiB"
    );

    // (b) Any width: the one-thread peak plus the rest of the wave.
    let (streamed_small, streamed_large) = (peak(&small, Finish::Seek), peak(&large, Finish::Seek));
    for (name, wide, one) in [
        ("12 MiB", streamed_small, alone_small),
        ("48 MiB", streamed_large, alone_large),
    ] {
        assert!(
            wide <= one + REST_OF_THE_WAVE,
            "streamed, {name}: {wide} bytes on this pool against {one} on one thread, \
             more than a wave's scratches apart"
        );
    }
    assert!(
        streamed_large <= alone_small + SAME + REST_OF_THE_WAVE,
        "streamed: {streamed_large} bytes for 48 MiB on this pool against {alone_small} \
         for 12 MiB on one thread"
    );

    let (held_small, held_large) = (peak(&small, Finish::Into), peak(&large, Finish::Into));
    assert!(
        held_large > held_small + 2 * SAME,
        "held: {held_small} bytes for 12 MiB and {held_large} for 48 MiB, so this row measures nothing"
    );
    assert!(streamed_large + SAME < held_large);
    assert!(alone_large + SAME < held_large);
    eprintln!(
        "streamed, one thread: {alone_small} and {alone_large}; this pool: {streamed_small} \
         and {streamed_large}; held: {held_small} and {held_large}"
    );
}

/// The shipped threshold is `MemoryPolicy::DEFAULT_LIMIT`: a member whose
/// packed bound is under 512 MiB is held with no ceiling named.
#[test]
fn the_shipped_threshold_holds_a_member_under_it() {
    let data = rarkit_testdata::medley(6, 6 * MIB);
    let (_, _, took) = write(options(WriteFormat::Rar5, None), Finish::Seek, &data);
    assert_eq!(took, 0, "a 6 MiB member streamed at the shipped threshold");
}
