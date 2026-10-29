//! Spec G 3.7.2 and 5.5: `finish_seek`, the one-pass entry.

use super::*;

// ---------------------------------------------------------------------
// Spec G 3.7.2 and 5.5: `finish_seek`, the one-pass entry
// ---------------------------------------------------------------------

/// `finish_seek` writes the same archive as `finish_into`, in one pass
/// and holding nothing.
///
/// Byte identity is the point. `finish_into` has to know a slice
/// payload's checksum before it writes the header, so it reads the member
/// twice; `finish_seek` lays a placeholder down, takes the checksum as
/// the bytes pass and goes back over it. Those are two routes to one
/// archive, and if they ever stopped agreeing the cheaper one would be
/// writing something the tested one does not.
#[test]
fn finish_seek_writes_the_same_archive_as_finish_into() {
    let body = compressible(200_000);
    let wanted = vec![
        Member {
            name: b"one.txt".to_vec(),
            is_directory: false,
            data: body.clone(),
            mtime: Some(Timestamp {
                unix_seconds: 1_700_000_000,
                nanos: 0,
            }),
            attributes: 0o100644,
            host_os: rarkit::HostOs::Unix,
        },
        Member {
            name: b"two.bin".to_vec(),
            is_directory: false,
            data: pseudo(9, 40_000),
            mtime: None,
            attributes: 0o100644,
            host_os: rarkit::HostOs::Unix,
        },
    ];

    for format in [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V40)] {
        for method in [
            rarkit::WriteMethod::Stored,
            rarkit::WriteMethod::Compressed {
                level: 3,
                dictionary: None,
            },
        ] {
            let options = || WriteOptions {
                format,
                method,
                filters: filters_for(format),
                host_os: rarkit::HostOs::Unix,
                ..WriteOptions::default()
            };
            let held = write_one(options(), &wanted);

            let mut writer = Writer::new(options()).expect("options");
            for member in &wanted {
                writer
                    .add(MemberSpec {
                        name: &member.name,
                        payload: Payload::Bytes(&member.data),
                        mtime: member.mtime,
                        attributes: member.attributes,
                        host_os: member.host_os,
                        is_directory: false,
                    })
                    .expect("add");
            }
            let mut seekable = std::io::Cursor::new(Vec::new());
            let report = writer.finish_seek(&mut seekable).expect("finish_seek");
            let patched = seekable.into_inner();

            assert_eq!(
                patched, held,
                "{format:?} {method:?}: finish_seek and finish_into disagree"
            );
            assert_eq!(report.held_volume_bytes, 0, "{format:?}: bytes were held");
            assert_eq!(report.bytes, patched.len() as u64);
            assert_eq!(read_back_bytes(vec![patched]), wanted);
        }
    }
}

/// A reader payload with no stated CRC32 holds bytes through
/// `finish_into` and holds none through `finish_seek`.
///
/// This is the figure spec G 3.7.2 names and `WriteReport` reports, and
/// it is the reason the entry exists: the same archive, with the
/// member's bytes never sitting in memory waiting for a correction.
#[test]
fn a_reader_with_no_checksum_holds_nothing_through_finish_seek() {
    let body = pseudo(3, 300_000);

    let mut source = std::io::Cursor::new(body.clone());
    let mut writer = Writer::new(WriteOptions {
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    })
    .expect("options");
    writer
        .add(MemberSpec {
            name: b"streamed.bin",
            payload: Payload::Reader {
                reader: &mut source,
                size: body.len() as u64,
                crc32: None,
            },
            mtime: None,
            attributes: 0o100644,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut plain = Vec::new();
    let held = writer.finish_into(&mut plain).expect("finish_into");
    assert!(
        held.held_volume_bytes >= body.len() as u64,
        "finish_into held {} bytes of a {} byte member",
        held.held_volume_bytes,
        body.len()
    );

    let mut source = std::io::Cursor::new(body.clone());
    let mut writer = Writer::new(WriteOptions {
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    })
    .expect("options");
    writer
        .add(MemberSpec {
            name: b"streamed.bin",
            payload: Payload::Reader {
                reader: &mut source,
                size: body.len() as u64,
                crc32: None,
            },
            mtime: None,
            attributes: 0o100644,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut seekable = std::io::Cursor::new(Vec::new());
    let patched = writer.finish_seek(&mut seekable).expect("finish_seek");
    assert_eq!(patched.held_volume_bytes, 0);
    assert_eq!(seekable.into_inner(), plain);
}

/// The archive starts where the output is POSITIONED, so one may be
/// appended to something else, and the patch goes to the right place.
#[test]
fn finish_seek_starts_where_the_output_is_positioned() {
    let prefix = b"a self extracting stub would sit here".to_vec();
    let body = compressible(80_000);
    let mut out = std::io::Cursor::new(prefix.clone());
    out.set_position(prefix.len() as u64);

    let mut writer = Writer::new(WriteOptions {
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    })
    .expect("options");
    writer
        .add(MemberSpec {
            name: b"after.txt",
            payload: Payload::Bytes(&body),
            mtime: None,
            attributes: 0o100644,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    writer.finish_seek(&mut out).expect("finish_seek");

    let whole = out.into_inner();
    assert_eq!(&whole[..prefix.len()], &prefix[..], "the prefix moved");
    let archive = whole[prefix.len()..].to_vec();
    let back = read_back_bytes(vec![archive]);
    assert_eq!(back.len(), 1);
    assert_eq!(back[0].data, body);
}

/// A volume set is refused by `finish_seek`, as it is by `finish_into`.
#[test]
fn finish_seek_refuses_a_volume_set() {
    let writer = Writer::new(WriteOptions {
        volume_size: Some(1 << 16),
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    })
    .expect("options");
    let error = writer
        .finish_seek(std::io::Cursor::new(Vec::new()))
        .unwrap_err();
    assert!(
        matches!(
            error.kind(),
            rarkit::ErrorKind::Unsupported(rarkit::Unsupported::WriteFeature(_))
        ),
        "finish_seek on a volume set gave {error}"
    );
}
