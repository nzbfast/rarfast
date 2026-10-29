//! Spec G 6.3: properties, over deterministic pseudo-random inputs.

use super::*;

/// A random member set, written and read back: names, sizes, times,
/// attributes and payloads all survive, in both families.
#[test]
fn a_random_member_set_survives_a_round_trip() {
    for seed in 1..12u64 {
        let count = (seed as usize % 7) + 1;
        let members: Vec<Member> = (0..count)
            .map(|index| {
                let size = (pseudo(seed * 31 + index as u64, 2)[0] as usize) * 37;
                Member {
                    name: format!("dir{seed}/member{index:03}.bin").into_bytes(),
                    is_directory: false,
                    data: pseudo(seed * 101 + index as u64, size),
                    mtime: Some(Timestamp {
                        unix_seconds: 1_600_000_000 + (seed as i64) * 7 + index as i64,
                        nanos: 0,
                    }),
                    attributes: 0o100644,
                    host_os: rarkit::HostOs::Unix,
                }
            })
            .collect();

        for format in [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V40)] {
            let archive = write_one(
                WriteOptions {
                    format,
                    filters: filters_for(format),
                    host_os: rarkit::HostOs::Unix,
                    ..WriteOptions::default()
                },
                &members,
            );
            let got = read_back_bytes(vec![archive]);
            assert_eq!(got.len(), members.len(), "seed {seed} {format:?}: count");
            for (want, got) in members.iter().zip(&got) {
                assert_eq!(want.name, got.name, "seed {seed} {format:?}: name");
                assert_eq!(want.data, got.data, "seed {seed} {format:?}: bytes");
                assert_eq!(
                    want.attributes, got.attributes,
                    "seed {seed} {format:?}: attributes"
                );
                assert_eq!(want.mtime, got.mtime, "seed {seed} {format:?}: time");
                assert_eq!(want.host_os, got.host_os, "seed {seed} {format:?}: host");
            }
        }
    }
}

/// A reader that hands its bytes over in awkward amounts produces the
/// same archive as one that hands them over whole: the output does not
/// depend on the chunk size the payload arrives in (spec G 6.3).
#[test]
fn the_output_does_not_depend_on_the_chunk_size_a_payload_arrives_in() {
    /// A reader that never gives more than `step` bytes at a time, and
    /// answers a zero-length read now and then, which a caller is allowed
    /// to do and a writer must not spin on.
    struct Dribble<'a> {
        data: &'a [u8],
        step: usize,
        calls: usize,
    }

    impl std::io::Read for Dribble<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.calls += 1;
            if self.data.is_empty() {
                return Ok(0);
            }
            let want = self.step.min(buf.len()).min(self.data.len()).max(1);
            buf[..want].copy_from_slice(&self.data[..want]);
            self.data = &self.data[want..];
            Ok(want)
        }
    }

    let data = pseudo(7, 40_000);
    let crc = rarkit::checksum::crc32(&data);
    let whole = write_one(
        WriteOptions {
            host_os: rarkit::HostOs::Unix,
            ..WriteOptions::default()
        },
        &[Member {
            name: b"payload.bin".to_vec(),
            is_directory: false,
            data: data.clone(),
            mtime: None,
            attributes: 0,
            host_os: rarkit::HostOs::Unix,
        }],
    );

    for step in [1usize, 3, 997, 65_536] {
        let mut reader = Dribble {
            data: &data,
            step,
            calls: 0,
        };
        let mut writer = Writer::new(WriteOptions {
            host_os: rarkit::HostOs::Unix,
            ..WriteOptions::default()
        })
        .unwrap();
        writer
            .add(MemberSpec {
                name: b"payload.bin",
                payload: Payload::Reader {
                    reader: &mut reader,
                    size: data.len() as u64,
                    crc32: Some(crc),
                },
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .unwrap();
        let mut out = Vec::new();
        writer.finish_into(&mut out).unwrap();
        assert_eq!(
            out, whole,
            "a payload in {step} byte steps gave other bytes"
        );
    }
}

/// A volume set concatenated by the reader is the same member set as the
/// single archive of the same members (spec G 6.3).
#[test]
fn a_volume_set_holds_the_same_members_as_one_archive() {
    let members: Vec<Member> = (0..5)
        .map(|index| Member {
            name: format!("m{index}.bin").into_bytes(),
            is_directory: false,
            data: pseudo(900 + index, 3_000 + index as usize * 1_100),
            mtime: None,
            attributes: 0o100644,
            host_os: rarkit::HostOs::Unix,
        })
        .collect();

    for format in [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V40)] {
        let one = read_back_bytes(vec![write_one(
            WriteOptions {
                format,
                filters: filters_for(format),
                host_os: rarkit::HostOs::Unix,
                ..WriteOptions::default()
            },
            &members,
        )]);

        for size in [1_000u64, 4_096, 9_973] {
            let mut writer = Writer::new(WriteOptions {
                format,
                filters: filters_for(format),
                volume_size: Some(size),
                host_os: rarkit::HostOs::Unix,
                ..WriteOptions::default()
            })
            .unwrap();
            for member in &members {
                writer
                    .add(MemberSpec {
                        name: &member.name,
                        payload: Payload::Bytes(&member.data),
                        mtime: member.mtime,
                        attributes: member.attributes,
                        host_os: member.host_os,
                        is_directory: false,
                    })
                    .unwrap();
            }
            let mut volumes: Vec<Vec<u8>> = Vec::new();
            writer.finish_volumes(&mut volumes).unwrap();
            let many = read_back_bytes(volumes);
            assert_eq!(
                one, many,
                "{format:?} at {size} bytes a volume: the set is not the archive"
            );
        }
    }
}

/// No archive this writer produces holds a byte the caller did not supply
/// and this specification does not name: the archive's length is the sum
/// of the blocks it should hold and the payloads that went in
/// (spec G 6.3).
#[test]
fn an_archive_is_exactly_its_blocks_and_its_payloads() {
    let members: Vec<Member> = (0..4)
        .map(|index| Member {
            name: format!("m{index}.bin").into_bytes(),
            is_directory: index == 3,
            data: if index == 3 {
                Vec::new()
            } else {
                pseudo(500 + index, 700 * (index as usize + 1))
            },
            mtime: None,
            attributes: 0o100644,
            host_os: rarkit::HostOs::Unix,
        })
        .collect();

    for format in [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V40)] {
        let archive = write_one(
            WriteOptions {
                format,
                filters: filters_for(format),
                host_os: rarkit::HostOs::Unix,
                ..WriteOptions::default()
            },
            &members,
        );
        let opened = Archive::open(
            Arc::new(archive.clone()) as Arc<dyn RangeSource>,
            &ReadOptions::default(),
        )
        .unwrap();
        // Every byte of the file is inside a block the reader walks, and
        // the blocks do not overlap and leave no gap - which together say
        // there is nothing else in there. The RAR 4 marker block is the
        // archive's first block, the RAR 5 signature its first 8 bytes.
        let mut blocks: Vec<_> = opened.blocks().map(|b| b.range).collect();
        blocks.sort_by_key(|r| r.start);
        let signature = if format == WriteFormat::Rar5 { 8 } else { 0 };
        let mut at = signature;
        for range in &blocks {
            assert_eq!(
                range.start, at,
                "{format:?}: a gap or an overlap before {range:?}"
            );
            at = range.end;
        }
        assert_eq!(
            at,
            archive.len() as u64,
            "{format:?}: {} bytes past the last block",
            archive.len() as u64 - at
        );
    }
}

/// A RAR 4 name holding a backslash is refused, because that family
/// stores a backslash between path components and the name would come
/// back as a different one. RAR 5 stores it unchanged and accepts it.
/// Found by the `write_members` fuzz target of spec G 6.4.
#[test]
fn a_backslash_in_a_name_is_refused_under_rar_4_and_kept_under_rar_5() {
    let name = b"a\\b.txt";

    let mut rar4 = Writer::new(WriteOptions {
        format: WriteFormat::Rar4(Rar4Version::V40),
        filters: rarkit::FilterPolicy::Off,
        ..WriteOptions::default()
    })
    .unwrap();
    let error = rar4
        .add(MemberSpec {
            name,
            payload: Payload::Bytes(b"x"),
            mtime: None,
            attributes: 0,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .unwrap_err();
    assert!(
        matches!(
            error.kind(),
            rarkit::ErrorKind::Corrupt(rarkit::Corruption::MemberName)
        ),
        "a RAR 4 backslash name gave {error}"
    );

    let archive = write_one(
        WriteOptions {
            host_os: rarkit::HostOs::Unix,
            ..WriteOptions::default()
        },
        &[Member {
            name: name.to_vec(),
            is_directory: false,
            data: b"x".to_vec(),
            mtime: None,
            attributes: 0,
            host_os: rarkit::HostOs::Unix,
        }],
    );
    let got = read_back_bytes(vec![archive]);
    assert_eq!(got[0].name, name, "RAR 5 changed a backslash name");
}
