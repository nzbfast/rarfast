//! The segment team's ROLLING HAND-OFF (`write::engine`'s `Roll`): an
//! engine takes each stretch of a big member as the writing thread has
//! read it and taken its checksum, and that thread goes on to read the
//! next while the engines encode, where a round read every stretch first
//! with the engines idle.
//!
//! **What is held here.** That the hand-off never reaches a byte: the
//! same member at the same options is the same archive rolling as a round
//! at a time, and as one engine's, at every team width, both formats,
//! levels 1 to 3, with CRC32 and BLAKE2sp, sealed and not. That the reader
//! is read once and in order. And that a reader which fails, or ends
//! short, leaves the bytes and the error a round at a time left.
#![cfg(feature = "parallel")]

use std::io::{Cursor, Read};
use std::sync::Arc;

use rarkit::internals::writers::{
    reset_segment_rounds, reset_streamed_members, segment_rolled, segment_rounds, streamed_members,
    with_segment_roll, with_segment_width, with_stream_above,
};
use rarkit::{
    extract, ChecksumKind, Disposition, FilterPolicy, MemberInfo, MemberOutcome, MemberSpec,
    Payload, RangeSource, Rar4Version, ReadOptions, Sink, VolumeOut, WriteFormat, WriteMethod,
    WriteOptions, Writer,
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
    rolled: usize,
}

fn write_with(
    options: WriteOptions,
    members: &[&[u8]],
    spoil: impl Fn(usize, &mut Watched<'_>),
) -> Wrote {
    let before = segment_rolled();
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
        rolled: segment_rolled() - before,
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

#[test]
fn rolling_writes_the_archive_a_round_at_a_time_writes() {
    let edge = rarkit_testdata::medley(31, 6 << 20);
    let ragged = rarkit_testdata::medley(32, (5 << 20) + 12_345);
    for (family, format) in FORMATS {
        for level in 1u8..=3 {
            for (shape, data) in [("edge", &edge), ("ragged", &ragged)] {
                let what = format!("{family} -m{level} {shape}");
                let one = with_segment_width(1, || write(options(format, level), &[data]));
                assert_eq!(one.rolled, 0, "{what}: one engine rolled");
                reads_back(&what, &one.out, &[data], None);
                for width in [2usize, 3, 8] {
                    let rounds = with_segment_roll(false, || {
                        with_segment_width(width, || write(options(format, level), &[data]))
                    });
                    let rolling = with_segment_roll(true, || {
                        with_segment_width(width, || write(options(format, level), &[data]))
                    });
                    assert_eq!(rounds.rolled, 0, "{what}: width {width} rolled with it off");
                    // Level 1 rolls; levels 2 and 3 keep their rounds
                    // (`Run::rolls`), and are the same archive either way.
                    assert_eq!(
                        rolling.rolled,
                        usize::from(level == 1),
                        "{what}: width {width}"
                    );
                    assert!(rolling.end.is_ok(), "{what}: {:?}", rolling.end);
                    assert!(
                        rolling.out == rounds.out,
                        "{what}: width {width}, rolling moved a byte from the rounds"
                    );
                    assert!(
                        rolling.out == one.out,
                        "{what}: width {width}, rolling moved a byte from one engine"
                    );
                    assert_eq!(
                        rolling.read_to,
                        vec![data.len()],
                        "{what}: read whole, once"
                    );
                }
            }
        }
    }
}

#[test]
fn rolling_with_blake2sp_and_sealed_is_the_same_archive() {
    let data = rarkit_testdata::medley(33, (5 << 20) + 777);
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
            let with = |rolls: bool, width: usize| {
                with_segment_roll(rolls, || {
                    with_segment_width(width, || {
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
                })
            };
            let one = with(false, 1);
            reads_back(&what, &one.out, &[&data], sealed.then_some("Secret"));
            let rounds = with(false, 4);
            let rolling = with(true, 4);
            assert_eq!(rolling.rolled, 1, "{what}: did not roll");
            assert!(rolling.out == rounds.out, "{what}: rolling moved a byte");
            assert!(rolling.out == one.out, "{what}: the team moved a byte");
        }
    }
}

#[test]
fn a_big_member_among_others_rolls_to_the_same_archive() {
    // Small members before and after, which the worker team takes while
    // the writing thread's big one runs on the segment team; add order
    // kept.
    let small: Vec<Vec<u8>> = (0..12)
        .map(|i| rarkit_testdata::medley(200 + i as u64, 40_000 + i * 7_919))
        .collect();
    let big = rarkit_testdata::medley(34, 5 << 20);
    let mut members: Vec<&[u8]> = small[..6].iter().map(Vec::as_slice).collect();
    members.push(&big);
    members.extend(small[6..].iter().map(Vec::as_slice));
    for (family, format) in FORMATS {
        let with = |rolls: bool, width: usize| {
            with_segment_roll(rolls, || {
                with_segment_width(width, || {
                    write(
                        WriteOptions {
                            order: rarkit::MemberOrder::AsAdded,
                            ..options(format, 1)
                        },
                        &members,
                    )
                })
            })
        };
        let one = with(false, 1);
        reads_back(family, &one.out, &members, None);
        reset_segment_rounds();
        let rounds = with(false, 4);
        assert!(segment_rounds().0 > 0, "{family}: the team ran no round");
        let rolling = with(true, 4);
        assert_eq!(rolling.rolled, 1, "{family}: the big member rolls");
        assert!(rolling.out == rounds.out, "{family}: rolling moved a byte");
        assert!(rolling.out == one.out, "{family}: the team moved a byte");
        let lengths: Vec<usize> = members.iter().map(|m| <[u8]>::len(m)).collect();
        assert_eq!(
            rolling.read_to, lengths,
            "{family}: every reader read whole"
        );
    }
}

#[test]
fn two_big_members_in_a_row_roll_with_the_engines_the_first_left() {
    // One hand-off ends and the next begins with the engines and the
    // buffers the first left: the second member is the longer, and then
    // the shorter, so a kept buffer is both grown and reused past its
    // stretch.
    let big = rarkit_testdata::medley(39, 5 << 20);
    let bigger = rarkit_testdata::medley(40, (7 << 20) + 99);
    for (family, format) in FORMATS {
        for members in [[&big[..], &bigger[..]], [&bigger[..], &big[..]]] {
            let with = |rolls: bool, width: usize| {
                with_segment_roll(rolls, || {
                    with_segment_width(width, || {
                        write(
                            WriteOptions {
                                order: rarkit::MemberOrder::AsAdded,
                                ..options(format, 1)
                            },
                            &members,
                        )
                    })
                })
            };
            let one = with(false, 1);
            reads_back(family, &one.out, &members, None);
            let rounds = with(false, 3);
            let rolling = with(true, 3);
            assert_eq!(rolling.rolled, 2, "{family}: both members roll");
            assert!(rolling.out == rounds.out, "{family}: rolling moved a byte");
            assert!(rolling.out == one.out, "{family}: the team moved a byte");
        }
    }
}

#[test]
fn a_failing_reader_leaves_what_a_round_at_a_time_left() {
    // The reader of the big member fails, or ends short, at a byte in each
    // part of it: inside the first stretch, inside a later stretch of the
    // first round, and inside later rounds. Members before it are written
    // either way, so the output is not empty.
    let before = rarkit_testdata::medley(36, 200_000);
    let big = rarkit_testdata::medley(37, (6 << 20) + 4_321);
    let after = rarkit_testdata::medley(38, 150_000);
    let members: [&[u8]; 3] = [&before, &big, &after];
    for (family, format) in FORMATS {
        for width in [2usize, 4] {
            for at in [1usize, 700_000, 1_900_000, 3_300_000, big.len() - 1] {
                for short in [false, true] {
                    let what = format!("{family} width {width} at {at} short {short}");
                    let with = |rolls: bool| {
                        with_segment_roll(rolls, || {
                            with_segment_width(width, || {
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
                        })
                    };
                    let rounds = with(false);
                    let rolling = with(true);
                    assert!(rounds.end.is_err(), "{what}: the rounds did not fail");
                    assert_eq!(rolling.end, rounds.end, "{what}: another error");
                    assert!(rolling.out == rounds.out, "{what}: other bytes were left");
                    assert_eq!(rolling.read_to[2], 0, "{what}: a reader past the failure");
                }
            }
        }
    }
}

#[test]
fn a_streamed_member_rolls_to_the_same_archive() {
    // The held-member limit lowered so that a member of a few MiB streams
    // as a member of hundreds does at the shipped limit (spec G 3.5): its
    // packed bytes go to the output as the walk pulls them, a stretch a
    // pull.
    let data = rarkit_testdata::medley(41, (7 << 20) + 4_321);
    for (family, format) in FORMATS {
        for (form, level, sealed, headers) in [
            ("-m1", 1u8, false, false),
            ("-m3", 3, false, false),
            ("-m1 -p", 1, true, false),
            ("-m1 -hp", 1, true, true),
        ] {
            let what = format!("{family} {form} streamed");
            let with = |rolls: bool, width: usize| {
                reset_streamed_members();
                let wrote = with_stream_above(4 << 20, || {
                    with_segment_roll(rolls, || {
                        with_segment_width(width, || {
                            write(
                                WriteOptions {
                                    password: sealed.then(|| rarkit::Password::from("Secret")),
                                    encrypt_headers: headers,
                                    ..options(format, level)
                                },
                                &[&data],
                            )
                        })
                    })
                });
                assert_eq!(streamed_members(), 1, "{what}: the member was held");
                wrote
            };
            let one = with(false, 1);
            reads_back(&what, &one.out, &[&data], sealed.then_some("Secret"));
            for width in [2usize, 4] {
                let rounds = with(false, width);
                let rolling = with(true, width);
                assert_eq!(
                    rolling.rolled,
                    usize::from(level == 1),
                    "{what}: width {width}"
                );
                assert!(
                    rolling.out == rounds.out,
                    "{what}: width {width}, rolling moved a byte"
                );
                assert!(
                    rolling.out == one.out,
                    "{what}: width {width}, the team moved a byte"
                );
            }
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
/// write ended and whether it rolled.
fn write_volumes(
    options: WriteOptions,
    data: &[u8],
    fail_at: Option<usize>,
) -> (Vec<Vec<u8>>, Result<(), String>, usize) {
    let before = segment_rolled();
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
    (out.0, end, segment_rolled() - before)
}

#[test]
fn a_member_split_over_volumes_rolls_to_the_same_set() {
    // Volumes of 700,001 bytes put several volume ends inside one stretch
    // and inside one round's worth; with a password the walk looks a cipher
    // block ahead at each end. And a reader that fails part way leaves the
    // volumes a round at a time finished, and its error.
    let data = rarkit_testdata::medley(42, (9 << 20) + 12_345);
    for (family, format) in FORMATS {
        for (form, sealed, headers) in
            [("", false, false), ("-p", true, false), ("-hp", true, true)]
        {
            for fail_at in [None, Some(2_500_000usize), Some(6_000_000)] {
                let what = format!("{family} -v700001 {form} failing at {fail_at:?}");
                let with = |rolls: bool, width: usize| {
                    with_stream_above(1 << 20, || {
                        with_segment_roll(rolls, || {
                            with_segment_width(width, || {
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
                    })
                };
                for width in [2usize, 4] {
                    let (rounds, rounds_end, _) = with(false, width);
                    let (rolling, rolling_end, rolled) = with(true, width);
                    assert_eq!(rolled, 1, "{what}: width {width} did not roll");
                    assert_eq!(rolling_end.is_err(), fail_at.is_some(), "{what}");
                    assert_eq!(
                        rolling_end, rounds_end,
                        "{what}: width {width}, another end"
                    );
                    assert_eq!(
                        rolling.len(),
                        rounds.len(),
                        "{what}: width {width} moved a volume's end"
                    );
                    for (index, (a, b)) in rolling.iter().zip(&rounds).enumerate() {
                        assert!(
                            a == b,
                            "{what}: width {width} moved a byte of volume {index}"
                        );
                    }
                    if fail_at.is_none() {
                        assert!(rolling.len() >= 3, "{what}: {} volumes", rolling.len());
                    }
                }
            }
        }
    }
}
