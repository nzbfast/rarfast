//! Spec G 3.7.2: a payload the writer pulls.

use super::*;

// ---------------------------------------------------------------------
// Spec G 3.7.2: a payload the writer pulls
// ---------------------------------------------------------------------

/// A reader payload is pulled exactly once, and its checksum is patched
/// in when the caller did not state it.
#[test]
fn a_reader_payload_is_written_with_and_without_its_checksum() {
    let data: Vec<u8> = (0..70_000u32).map(|i| (i * 7) as u8).collect();
    let crc = rarkit::checksum::crc32(&data);

    for stated in [Some(crc), None] {
        let mut source = std::io::Cursor::new(data.clone());
        let mut writer = Writer::new(WriteOptions::default()).unwrap();
        writer
            .add(MemberSpec {
                name: b"streamed.bin",
                payload: Payload::Reader {
                    reader: &mut source,
                    size: data.len() as u64,
                    crc32: stated,
                },
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .unwrap();
        let mut out = Vec::new();
        let report = writer.finish_into(&mut out).unwrap();
        if stated.is_some() {
            assert_eq!(
                report.held_volume_bytes, 0,
                "a stated CRC32 should need no hold"
            );
        } else {
            assert!(
                report.held_volume_bytes > 0,
                "an unstated CRC32 has to be patched in"
            );
        }
        let got = read_back_bytes(vec![out]);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].data, data, "the streamed bytes");
    }
}

/// A reader that ends early is `Truncated`; one with more bytes than it
/// declared is `Corrupt(PayloadLength)` (spec G section 4).
#[test]
fn a_reader_that_lies_about_its_length_is_refused() {
    let data = vec![9u8; 1000];

    let mut short = std::io::Cursor::new(data.clone());
    let mut writer = Writer::new(WriteOptions::default()).unwrap();
    writer
        .add(MemberSpec {
            name: b"short.bin",
            payload: Payload::Reader {
                reader: &mut short,
                size: 2000,
                crc32: None,
            },
            mtime: None,
            attributes: 0,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .unwrap();
    let error = writer.finish_into(Vec::new()).unwrap_err();
    assert!(
        matches!(error.kind(), rarkit::ErrorKind::Truncated),
        "a short reader gave {error}"
    );

    let mut long = std::io::Cursor::new(data.clone());
    let mut writer = Writer::new(WriteOptions::default()).unwrap();
    writer
        .add(MemberSpec {
            name: b"long.bin",
            payload: Payload::Reader {
                reader: &mut long,
                size: 500,
                crc32: None,
            },
            mtime: None,
            attributes: 0,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .unwrap();
    let error = writer.finish_into(Vec::new()).unwrap_err();
    assert!(
        matches!(
            error.kind(),
            rarkit::ErrorKind::Corrupt(rarkit::Corruption::PayloadLength)
        ),
        "a long reader gave {error}"
    );
}

/// A payload whose CRC32 the caller stated wrongly is refused: an archive
/// is a promise about its contents (spec G 3.7.2).
#[test]
fn a_wrong_caller_checksum_is_refused() {
    let data = vec![3u8; 300];
    let mut source = std::io::Cursor::new(data.clone());
    let mut writer = Writer::new(WriteOptions::default()).unwrap();
    writer
        .add(MemberSpec {
            name: b"wrong.bin",
            payload: Payload::Reader {
                reader: &mut source,
                size: data.len() as u64,
                crc32: Some(0xdead_beef),
            },
            mtime: None,
            attributes: 0,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .unwrap();
    let error = writer.finish_into(Vec::new()).unwrap_err();
    assert!(
        matches!(
            error.kind(),
            rarkit::ErrorKind::Corrupt(rarkit::Corruption::Checksum)
        ),
        "a wrong checksum gave {error}"
    );
}
