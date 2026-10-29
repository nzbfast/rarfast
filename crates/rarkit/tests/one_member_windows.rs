//! One member from a READER, encoded a window at a time (spec G 3.7.3),
//! with its windows STAGED so that several parse as one wave.
//!
//! **What is being checked.** A reader's member reaches the encoder in
//! windows of the dictionary, and each window used to be its own flush:
//! at the shipped 2 MiB dictionary that is eight parse blocks, a wave that
//! empties before the next window is read, and one 64 MiB member ran about
//! 4.5 wide on 16 cores for it.
//! The writer now stages a member's windows the way a solid set stages its
//! members, and parses the batch as one wave. That is a width, and the
//! claim this file holds the writer to is that it is ONLY a width: the
//! same member, at the same options, is the same archive to the byte at
//! any window depth.
//!
//! **Depth 1 is the control arm.** It flushes a window at a time, which is
//! the walk the writer had before windows were staged, so every row is a
//! comparison against the previous behaviour.
//!
//! The rows cover what could make a batch of windows differ from a window
//! at a time: a dictionary small enough that a window is ONE parse block
//! and the history slides every few windows, a member whose length is not
//! a whole number of windows, a filter plan whose spans are measured from
//! each window's offset in its member, both finders (chains at levels 1
//! and 3, the tree at 5), and the RAR 4 family's own encoder.

use std::io::Cursor;
use std::sync::Arc;

use rarkit::{
    extract, Disposition, FilterPolicy, MemberInfo, MemberOutcome, MemberSpec, MemoryPolicy,
    Payload, RangeSource, ReadOptions, Sink, WriteFormat, WriteMethod, WriteOptions, Writer,
};

use rarkit::internals::writers::{
    forget_widest_flush, last_streamed_slack, widest_flush, with_streamed_slack, with_window_depth,
    SLACK_MULTIPLES, STREAMED_SLACK_LEAST_DICTIONARY,
};

/// The depths every row is written at: a window at a time, two, and the
/// shipped depth, which only `Engine::may_stage` bounds.
const DEPTHS: [usize; 3] = [1, 2, usize::MAX];

fn options(format: WriteFormat, level: u8, dictionary: u64, memory: MemoryPolicy) -> WriteOptions {
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
        memory,
        ..WriteOptions::default()
    }
}

/// One member through `Payload::Reader`, which takes the windowed walk.
fn write(options: WriteOptions, data: &[u8]) -> Vec<u8> {
    let mut reader = Cursor::new(data);
    let mut writer = Writer::new(options).expect("options");
    writer
        .add(MemberSpec {
            name: b"one.bin",
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
            "the member failed its checksum"
        );
        self.0.extend_from_slice(&out.unwrap_or_default());
        Ok(())
    }
}

/// rarkit's own reader gives the member back.
fn reads_back(archive: &[u8], data: &[u8], what: &str) {
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(archive.to_vec())];
    let mut sink = Collect::default();
    extract(sources, &ReadOptions::default(), &mut sink, &mut ())
        .unwrap_or_else(|e| panic!("{what}: rarkit could not read it back: {e}"));
    assert!(sink.0 == data, "{what}: the member came back different");
}

/// Every row: format, level, dictionary, member length.
fn rows() -> Vec<(&'static str, WriteFormat, u8, u64, usize)> {
    let rar4 = WriteFormat::Rar4(rarkit::Rar4Version::V29);
    vec![
        // A window is ONE parse block and the history slides every four.
        (
            "rar5 m1 128k",
            WriteFormat::Rar5,
            1,
            128 << 10,
            (5 << 20) + 12_345,
        ),
        (
            "rar5 m3 256k",
            WriteFormat::Rar5,
            3,
            256 << 10,
            (4 << 20) + 777,
        ),
        // The shipped dictionary: eight blocks a window, a slide at the
        // fifth.
        (
            "rar5 m1 2m",
            WriteFormat::Rar5,
            1,
            2 << 20,
            (13 << 20) + 4_097,
        ),
        (
            "rar5 m5 256k",
            WriteFormat::Rar5,
            5,
            256 << 10,
            (3 << 20) + 99,
        ),
        ("rar4 m3 256k", rar4, 3, 256 << 10, (3 << 20) + 5),
    ]
}

#[test]
fn a_member_is_the_same_archive_at_every_window_depth() {
    for (what, format, level, dictionary, len) in rows() {
        let data = rarkit_testdata::medley(len as u64, len);
        let control = with_window_depth(1, || {
            write(
                options(format, level, dictionary, MemoryPolicy::default()),
                &data,
            )
        });
        reads_back(&control, &data, what);
        for depth in DEPTHS {
            let archive = with_window_depth(depth, || {
                write(
                    options(format, level, dictionary, MemoryPolicy::default()),
                    &data,
                )
            });
            assert!(
                archive == control,
                "{what}: depth {depth} wrote a different archive ({} bytes against {})",
                archive.len(),
                control.len()
            );
        }
    }
}

/// A ceiling one byte under 512 MiB: the largest that keeps the named
/// path of before the named-ceiling rule (`Run::small_ceiling`).
fn small_ceiling() -> MemoryPolicy {
    MemoryPolicy::from_limit(MemoryPolicy::DEFAULT_LIMIT - 1)
}

/// The shipped depth parses several windows in one flush where the
/// caller set no memory ceiling or one of 512 MiB and more (spec G 3.7.3's
/// named-ceiling rule of 1 Oct 2026), and a window at a time under a
/// SMALL ceiling (whose sum counts one window's wave). The small one is
/// compared at the shipped slack, which is what it keeps: an unheld
/// streamed member's wider slack moves its slides, and with them a few
/// bytes (`a_streamed_member_alone_takes_the_wider_slack`).
#[test]
fn a_member_stages_its_windows_unless_the_caller_set_a_small_ceiling() {
    let dictionary = 2u64 << 20;
    let data = rarkit_testdata::medley(7, (13 << 20) + 4_097);
    for (format, level) in [
        (WriteFormat::Rar5, 1),
        (WriteFormat::Rar5, 3),
        (WriteFormat::Rar4(rarkit::Rar4Version::V29), 3),
    ] {
        let what = format!("{format:?} m{level}");
        forget_widest_flush();
        let free = with_streamed_slack(SLACK_MULTIPLES.0, || {
            write(
                options(format, level, dictionary, MemoryPolicy::default()),
                &data,
            )
        });
        assert!(
            widest_flush() >= 4,
            "{what}: the widest flush parsed {} windows, where four fit its batch",
            widest_flush()
        );
        forget_widest_flush();
        let ceiling = write(options(format, level, dictionary, small_ceiling()), &data);
        assert_eq!(
            widest_flush(),
            0,
            "{what}: a run under a small ceiling staged its windows"
        );
        assert!(
            ceiling == free,
            "{what}: the run under a small ceiling wrote a different archive"
        );
        // A budget of 512 MiB and more is the default's run, slack and all.
        forget_widest_flush();
        let unheld = write(
            options(format, level, dictionary, MemoryPolicy::default()),
            &data,
        );
        let default_flush = widest_flush();
        forget_widest_flush();
        let budget = write(
            options(format, level, dictionary, MemoryPolicy::from_limit(1 << 40)),
            &data,
        );
        assert_eq!(
            widest_flush(),
            default_flush,
            "{what}: a budget of 512 MiB and more stages what the default stages"
        );
        assert!(
            budget == unheld,
            "{what}: a budget of 512 MiB and more wrote another archive than the default"
        );
        reads_back(&free, &data, &what);
    }
}

/// A member streamed a window at a time takes the wider slack (spec G
/// 3.7.3; `encode::drive::STREAMED_SLACK_MULTIPLE` says what it buys and
/// moves) only in a NON-SOLID run with no memory ceiling or one of 512
/// MiB and more, at a dictionary of `STREAMED_SLACK_LEAST_DICTIONARY` or
/// more: a solid run, a run under a SMALL ceiling, and a smaller
/// dictionary, whose chains the wider history would have grown, keep the
/// shipped slack their sums were made with.
/// Every arm reads its member back.
#[test]
fn a_streamed_member_alone_takes_the_wider_slack() {
    let (shipped, streamed) = SLACK_MULTIPLES;
    assert!(streamed > shipped, "the streamed slack is the wider one");
    let least = STREAMED_SLACK_LEAST_DICTIONARY as u64;
    // Over a slide at the shipped slack, which a 2 MiB dictionary makes
    // at the fifth window.
    let data = rarkit_testdata::medley(11, (13 << 20) + 31);
    for format in [
        WriteFormat::Rar5,
        WriteFormat::Rar4(rarkit::Rar4Version::V29),
    ] {
        let what = format!("{format:?}");
        let arms = [
            ("non-solid", false, MemoryPolicy::default(), least, streamed),
            ("solid", true, MemoryPolicy::default(), least, shipped),
            ("small ceiling", false, small_ceiling(), least, shipped),
            (
                "budget",
                false,
                MemoryPolicy::from_limit(1 << 40),
                least,
                streamed,
            ),
            (
                "small dictionary",
                false,
                MemoryPolicy::default(),
                least / 8,
                shipped,
            ),
        ];
        for (arm, solid, memory, dictionary, wants) in arms {
            let archive = write(
                WriteOptions {
                    solid,
                    ..options(format, 1, dictionary, memory)
                },
                &data,
            );
            assert_eq!(
                last_streamed_slack(),
                wants,
                "{what} {arm}: the streamed member ran at the wrong slack"
            );
            reads_back(&archive, &data, &format!("{what} {arm}"));
        }
        // The wider slack is the streamed member's alone: at the shipped
        // multiple the unheld run is the run under a small ceiling, byte
        // for byte.
        let shipped_free = with_streamed_slack(shipped, || {
            write(options(format, 1, least, MemoryPolicy::default()), &data)
        });
        let ceiling = write(options(format, 1, least, small_ceiling()), &data);
        assert!(
            shipped_free == ceiling,
            "{what}: at the shipped slack the unheld run is not the held one"
        );
    }
}
