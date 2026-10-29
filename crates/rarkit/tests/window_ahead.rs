//! A member's windows READ AHEAD of its one engine (`write::engine`'s
//! `WindowsAhead`): where no segment team runs (few cores, the tree's
//! levels), the writing thread reads the next windows and takes their
//! checksum while a flush parses the ones staged, where it read, staged
//! and then waited.
//!
//! **What is held here.** That the read-ahead never reaches a byte: the
//! same member at the same options is the same archive read ahead as
//! not, both formats, levels 1, 3 and 5 (the tree's levels keep their
//! walk and are held to that), with CRC32 and BLAKE2sp, sealed
//! and not, held and streamed, in one archive and in a volume set. That
//! the reader is read once and in order. That a reader which fails, or
//! ends short, leaves the bytes and the error the walk left before. And
//! that one thread, a solid run, a caller's ceiling and the tree's levels
//! never see it.
#![cfg(feature = "parallel")]

use std::io::{Cursor, Read};
use std::sync::Arc;

use rarkit::internals::writers::{
    reset_streamed_members, streamed_members, window_ahead_members, with_segment_width,
    with_stream_above, with_window_ahead,
};
use rarkit::{
    extract, ChecksumKind, Disposition, FilterPolicy, MemberInfo, MemberOutcome, MemberSpec,
    MemoryPolicy, Payload, RangeSource, Rar4Version, ReadOptions, Sink, VolumeOut, WriteFormat,
    WriteMethod, WriteOptions, Writer,
};

/// A dictionary of one parse block, so a window is one block, the history
/// slides every five windows and a member of a few MiB is many stretches.
const SMALL: u64 = 256 << 10;

fn options(format: WriteFormat, level: u8) -> WriteOptions {
    WriteOptions {
        format,
        method: WriteMethod::Compressed {
            level,
            dictionary: Some(SMALL),
        },
        // The RAR 4 family refuses a filter request (SPEC-J).
        filters: if matches!(format, WriteFormat::Rar4(_)) {
            FilterPolicy::Off
        } else {
            FilterPolicy::Detect
        },
        host_os: rarkit::HostOs::Unix,
        workers: Some(4),
        entropy: rarkit::Entropy::Seeded([9; 32]),
        ..WriteOptions::default()
    }
}

/// A reader that counts what it is asked for and where, and can fail or
/// end short at a named byte.
struct Watched<'a> {
    data: &'a [u8],
    at: usize,
    /// Fail with an I/O error once this many bytes have been handed out.
    fail_at: Option<usize>,
    /// End (a read of zero) once this many bytes have been handed out.
    end_at: Option<usize>,
    reads: usize,
}

impl<'a> Watched<'a> {
    fn new(data: &'a [u8]) -> Watched<'a> {
        Watched {
            data,
            at: 0,
            fail_at: None,
            end_at: None,
            reads: 0,
        }
    }
}

impl Read for Watched<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.reads += 1;
        let mut most = self.data.len() - self.at;
        if let Some(fail) = self.fail_at {
            if self.at >= fail {
                return Err(std::io::Error::other("the reader failed"));
            }
            most = most.min(fail - self.at);
        }
        if let Some(end) = self.end_at {
            most = most.min(end.saturating_sub(self.at));
        }
        // Short reads, as a pipe gives them.
        let take = most.min(buffer.len()).min(100_003);
        buffer[..take].copy_from_slice(&self.data[self.at..self.at + take]);
        self.at += take;
        Ok(take)
    }
}

/// What one write left: the bytes that reached the output, and its end.
struct Wrote {
    out: Vec<u8>,
    end: Result<u64, String>,
    /// How far each reader was read.
    read_to: Vec<usize>,
    /// How many members were read ahead of their one engine.
    ahead: usize,
}

fn write_with(
    options: WriteOptions,
    members: &[&[u8]],
    spoil: impl Fn(usize, &mut Watched<'_>),
) -> Wrote {
    let before = window_ahead_members();
    let names: Vec<String> = (0..members.len()).map(|i| format!("m{i}.bin")).collect();
    let mut readers: Vec<Watched<'_>> = members.iter().map(|m| Watched::new(m)).collect();
    for (index, reader) in readers.iter_mut().enumerate() {
        spoil(index, reader);
    }
    let mut out = Cursor::new(Vec::new());
    let end = {
        let mut writer = Writer::new(options).expect("options");
        for ((name, reader), data) in names.iter().zip(readers.iter_mut()).zip(members) {
            writer
                .add(MemberSpec {
                    name: name.as_bytes(),
                    payload: Payload::Reader {
                        reader,
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
        writer
            .finish_seek(&mut out)
            .map(|report| report.peak_working_memory)
            .map_err(|error| format!("{error:?}"))
    };
    Wrote {
        out: out.into_inner(),
        end,
        read_to: readers.iter().map(|reader| reader.at).collect(),
        ahead: window_ahead_members() - before,
    }
}

fn write(options: WriteOptions, members: &[&[u8]]) -> Wrote {
    write_with(options, members, |_, _| {})
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

fn reads_back(what: &str, archive: &[u8], members: &[&[u8]], password: Option<&str>) {
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(archive.to_vec())];
    let mut sink = Collect::default();
    let mut options = ReadOptions::default();
    options.password = password.map(rarkit::Password::from);
    extract(sources, &options, &mut sink, &mut ()).unwrap_or_else(|e| panic!("{what}: {e}"));
    assert!(
        sink.0.iter().map(Vec::as_slice).eq(members.iter().copied()),
        "{what}: the archive reads back as its members"
    );
}

const FORMATS: [(&str, WriteFormat); 2] = [
    ("rar5", WriteFormat::Rar5),
    ("rar4v29", WriteFormat::Rar4(Rar4Version::V29)),
];

/// One engine (no segment team), the windows read ahead or not.
fn one_engine<T>(ahead: bool, work: impl FnOnce() -> T) -> T {
    with_segment_width(1, || with_window_ahead(ahead, work))
}

#[test]
fn reading_ahead_writes_the_archive_the_walk_wrote() {
    let edge = rarkit_testdata::medley(51, 6 << 20);
    let ragged = rarkit_testdata::medley(52, (5 << 20) + 12_345);
    for (family, format) in FORMATS {
        for level in [1u8, 3, 5] {
            for (shape, data) in [("edge", &edge), ("ragged", &ragged)] {
                let what = format!("{family} -m{level} {shape}");
                let plain = one_engine(false, || write(options(format, level), &[data]));
                assert_eq!(plain.ahead, 0, "{what}: read ahead with it off");
                reads_back(&what, &plain.out, &[data], None);
                let ahead = one_engine(true, || write(options(format, level), &[data]));
                assert_eq!(ahead.ahead, usize::from(level <= 3), "{what}");
                assert!(ahead.end.is_ok(), "{what}: {:?}", ahead.end);
                assert!(ahead.out == plain.out, "{what}: reading ahead moved a byte");
                assert_eq!(ahead.read_to, vec![data.len()], "{what}: read whole, once");
            }
        }
    }
}

#[test]
fn reading_ahead_with_blake2sp_and_sealed_is_the_same_archive() {
    let data = rarkit_testdata::medley(53, (5 << 20) + 777);
    for (family, format) in FORMATS {
        let rar5 = matches!(format, WriteFormat::Rar5);
        // (what, BLAKE2sp, a password, sealed headers)
        let mut forms = vec![("p", false, true, false), ("hp", false, true, true)];
        if rar5 {
            forms.push(("htb", true, false, false));
            forms.push(("htb hp", true, true, true));
        }
        for (form, blake, sealed, headers) in forms {
            let what = format!("{family} {form}");
            let with = |ahead: bool| {
                one_engine(ahead, || {
                    write(
                        WriteOptions {
                            checksum: if blake {
                                ChecksumKind::Blake2sp
                            } else {
                                ChecksumKind::Crc32
                            },
                            password: sealed.then(|| rarkit::Password::from("Secret")),
                            encrypt_headers: headers,
                            ..options(format, 1)
                        },
                        &[&data],
                    )
                })
            };
            let plain = with(false);
            reads_back(&what, &plain.out, &[&data], sealed.then_some("Secret"));
            let ahead = with(true);
            assert_eq!(ahead.ahead, 1, "{what}: not read ahead");
            assert!(ahead.out == plain.out, "{what}: reading ahead moved a byte");
        }
    }
}

#[test]
fn big_members_among_others_read_ahead_to_the_same_archive() {
    // Small members before and after, which the worker team takes, and two
    // big ones, the second shorter than the first, so the buffer the first
    // left is read over again.
    let small: Vec<Vec<u8>> = (0..12)
        .map(|i| rarkit_testdata::medley(300 + i as u64, 40_000 + i * 7_919))
        .collect();
    let big = rarkit_testdata::medley(54, (6 << 20) + 5);
    let other = rarkit_testdata::medley(55, 3 << 20);
    let mut members: Vec<&[u8]> = small[..6].iter().map(Vec::as_slice).collect();
    members.push(&big);
    members.extend(small[6..].iter().map(Vec::as_slice));
    members.push(&other);
    for (family, format) in FORMATS {
        let with = |ahead: bool| {
            one_engine(ahead, || {
                write(
                    WriteOptions {
                        order: rarkit::MemberOrder::AsAdded,
                        ..options(format, 1)
                    },
                    &members,
                )
            })
        };
        let plain = with(false);
        reads_back(family, &plain.out, &members, None);
        // Whether the writing thread's one engine or a crew of the team's
        // lane takes the big ones is the writer's choice by cores and
        // memory; either way the archive is the same.
        let ahead = with(true);
        assert!(
            ahead.out == plain.out,
            "{family}: reading ahead moved a byte"
        );
        let lengths: Vec<usize> = members.iter().map(|m| <[u8]>::len(m)).collect();
        assert_eq!(ahead.read_to, lengths, "{family}: every reader read whole");
    }
}

#[test]
fn a_failing_reader_leaves_what_the_walk_left() {
    // The reader of the big member fails, or ends short, inside its first
    // window, inside a later window of the first flush, and in later
    // flushes. Members before it are written either way.
    let before = rarkit_testdata::medley(56, 200_000);
    let big = rarkit_testdata::medley(57, (6 << 20) + 4_321);
    let after = rarkit_testdata::medley(58, 150_000);
    let members: [&[u8]; 3] = [&before, &big, &after];
    for (family, format) in FORMATS {
        for at in [
            1usize,
            300_000,
            700_000,
            1_900_000,
            3_300_000,
            big.len() - 1,
        ] {
            for short in [false, true] {
                let what = format!("{family} at {at} short {short}");
                let with = |ahead: bool| {
                    one_engine(ahead, || {
                        write_with(
                            WriteOptions {
                                order: rarkit::MemberOrder::AsAdded,
                                ..options(format, 1)
                            },
                            &members,
                            |index, reader| {
                                if index == 1 {
                                    if short {
                                        reader.end_at = Some(at);
                                    } else {
                                        reader.fail_at = Some(at);
                                    }
                                }
                            },
                        )
                    })
                };
                let plain = with(false);
                let ahead = with(true);
                assert!(plain.end.is_err(), "{what}: the walk did not fail");
                assert_eq!(ahead.end, plain.end, "{what}: another error");
                assert!(ahead.out == plain.out, "{what}: other bytes were left");
                assert_eq!(ahead.read_to[2], 0, "{what}: a reader past the failure");
            }
        }
    }
}

#[test]
fn a_streamed_member_reads_ahead_to_the_same_archive() {
    // The held-member limit lowered so that a member of a few MiB streams
    // as a member of hundreds does at the shipped limit (spec G 3.5).
    let data = rarkit_testdata::medley(59, (7 << 20) + 4_321);
    for (family, format) in FORMATS {
        for (form, level, sealed, headers) in [
            ("-m1", 1u8, false, false),
            ("-m3", 3, false, false),
            ("-m5", 5, false, false),
            ("-m1 -p", 1, true, false),
            ("-m1 -hp", 1, true, true),
        ] {
            let what = format!("{family} {form} streamed");
            let with = |ahead: bool| {
                reset_streamed_members();
                let wrote = with_stream_above(4 << 20, || {
                    one_engine(ahead, || {
                        write(
                            WriteOptions {
                                password: sealed.then(|| rarkit::Password::from("Secret")),
                                encrypt_headers: headers,
                                ..options(format, level)
                            },
                            &[&data],
                        )
                    })
                });
                assert_eq!(streamed_members(), 1, "{what}: the member was held");
                wrote
            };
            let plain = with(false);
            reads_back(&what, &plain.out, &[&data], sealed.then_some("Secret"));
            let ahead = with(true);
            assert_eq!(ahead.ahead, usize::from(level <= 3), "{what}");
            assert!(ahead.out == plain.out, "{what}: reading ahead moved a byte");
        }
    }
}

/// Volumes that can patch, kept in memory; a volume whose write ended in
/// an error is not in it, which is the same either way.
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

    fn can_patch(&self) -> bool {
        true
    }

    fn patch(&mut self, volume: &mut Vec<u8>, at: u64, bytes: &[u8]) -> rarkit::Result<()> {
        let at = at as usize;
        volume[at..at + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
}

/// One member into volumes of `volume` bytes, the reader failing at
/// `fail_at` where one is named. Answers the volumes finished, how the
/// write ended and how many members were read ahead.
fn write_volumes(
    options: WriteOptions,
    data: &[u8],
    fail_at: Option<usize>,
) -> (Vec<Vec<u8>>, Result<(), String>, usize) {
    let before = window_ahead_members();
    let mut reader = Watched::new(data);
    reader.fail_at = fail_at;
    let mut out = Volumes::default();
    let end = {
        let mut writer = Writer::new(options).expect("options");
        writer
            .add(MemberSpec {
                name: b"big.bin",
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
        writer
            .finish_volumes(&mut out)
            .map(|_| ())
            .map_err(|error| format!("{error:?}"))
    };
    (out.0, end, window_ahead_members() - before)
}

#[test]
fn a_member_split_over_volumes_reads_ahead_to_the_same_set() {
    // Volumes of 700,001 bytes put several volume ends inside one flush;
    // with a password the walk looks a cipher block ahead at each end. And
    // a reader that fails part way leaves the volumes the walk finished
    // before, and its error.
    let data = rarkit_testdata::medley(60, (9 << 20) + 12_345);
    for (family, format) in FORMATS {
        for (form, sealed, headers) in
            [("", false, false), ("-p", true, false), ("-hp", true, true)]
        {
            for fail_at in [None, Some(2_500_000usize), Some(6_000_000)] {
                let what = format!("{family} -v700001 {form} failing at {fail_at:?}");
                let with = |ahead: bool| {
                    with_stream_above(1 << 20, || {
                        one_engine(ahead, || {
                            write_volumes(
                                WriteOptions {
                                    volume_size: Some(700_001),
                                    password: sealed.then(|| rarkit::Password::from("Secret")),
                                    encrypt_headers: headers,
                                    ..options(format, 1)
                                },
                                &data,
                                fail_at,
                            )
                        })
                    })
                };
                let (plain, plain_end, _) = with(false);
                let (ahead, ahead_end, read_ahead) = with(true);
                assert_eq!(read_ahead, 1, "{what}: not read ahead");
                assert_eq!(ahead_end.is_err(), fail_at.is_some(), "{what}");
                assert_eq!(ahead_end, plain_end, "{what}: another end");
                assert_eq!(ahead.len(), plain.len(), "{what}: a volume's end moved");
                for (index, (a, b)) in ahead.iter().zip(&plain).enumerate() {
                    assert!(a == b, "{what}: a byte of volume {index} moved");
                }
                if fail_at.is_none() {
                    assert!(ahead.len() >= 3, "{what}: {} volumes", ahead.len());
                }
            }
        }
    }
}

#[test]
fn a_reader_failing_with_windows_staged_ends_in_its_error() {
    // The walk as it was, with neither the read-ahead nor a team: a
    // streamed member of a volume set whose reader fails after the member
    // has crossed a volume, with windows staged in the engine and not yet
    // flushed. Until 2 Oct 2026 the walk then reset the engine with those
    // windows still staged, and a debug build panicked in the engine where
    // a release build returned the reader's error.
    let data = rarkit_testdata::medley(62, (9 << 20) + 12_345);
    for (family, format) in FORMATS {
        for fail_at in [3_000_000usize, 6_000_000, 8_500_000] {
            let what = format!("{family} failing at {fail_at}");
            let (volumes, end, read_ahead) = with_stream_above(1 << 20, || {
                one_engine(false, || {
                    write_volumes(
                        WriteOptions {
                            volume_size: Some(700_001),
                            ..options(format, 1)
                        },
                        &data,
                        Some(fail_at),
                    )
                })
            });
            assert_eq!(read_ahead, 0, "{what}: read ahead with it off");
            let error = end.expect_err("the reader failed");
            assert!(
                error.contains("the reader failed"),
                "{what}: another error: {error}"
            );
            // The member had crossed a volume or more before its reader
            // failed, which is the case that reset the engine.
            assert!(
                fail_at < 6_000_000 || !volumes.is_empty(),
                "{what}: no volume was finished before the failure"
            );
        }
    }
}

#[test]
fn one_thread_a_solid_run_and_a_ceiling_never_read_ahead() {
    let data = rarkit_testdata::medley(61, 5 << 20);
    let base = || options(WriteFormat::Rar5, 1);
    let one_thread = one_engine(true, || {
        write(
            WriteOptions {
                workers: Some(1),
                ..base()
            },
            &[&data],
        )
    });
    assert_eq!(one_thread.ahead, 0, "one thread read ahead");
    let solid = one_engine(true, || {
        write(
            WriteOptions {
                solid: true,
                ..base()
            },
            &[&data],
        )
    });
    assert_eq!(solid.ahead, 0, "a solid run read ahead");
    let ceiling = one_engine(true, || {
        write(
            WriteOptions {
                memory: MemoryPolicy::from_limit(256 << 20),
                ..base()
            },
            &[&data],
        )
    });
    assert_eq!(ceiling.ahead, 0, "a caller's ceiling read ahead");
}
