//! Spec G 3.14.9 and section 4: what `Writer::new` and `add` refuse.

use super::*;

// ---------------------------------------------------------------------
// Spec G 3.14.9 and section 4: what `Writer::new` and `add` refuse
// ---------------------------------------------------------------------

/// Every combination spec G 3.14.9 names is refused before a byte.
#[test]
fn every_refusal_arrives_before_the_first_byte() {
    let cases: Vec<(&str, WriteOptions)> = vec![
        (
            "BLAKE2sp under RAR 4",
            WriteOptions {
                format: WriteFormat::Rar4(Rar4Version::V40),
                filters: rarkit::FilterPolicy::Off,
                checksum: ChecksumKind::Blake2sp,
                ..WriteOptions::default()
            },
        ),
        (
            "the reference layout under RAR 4",
            WriteOptions {
                format: WriteFormat::Rar4(Rar4Version::V40),
                filters: rarkit::FilterPolicy::Off,
                layout: Layout::Reference { quick_open: true },
                ..WriteOptions::default()
            },
        ),
        (
            "the reference layout on a volume set",
            WriteOptions {
                layout: Layout::Reference { quick_open: true },
                volume_size: Some(4096),
                ..WriteOptions::default()
            },
        ),
        (
            "a RAR 4 recovery record on a split set",
            WriteOptions {
                format: WriteFormat::Rar4(Rar4Version::V40),
                filters: rarkit::FilterPolicy::Off,
                recovery_percent: Some(5),
                volume_size: Some(4096),
                ..WriteOptions::default()
            },
        ),
        (
            "classic naming under RAR 5",
            WriteOptions {
                volume_naming: VolumeNaming::Classic,
                volume_size: Some(4096),
                ..WriteOptions::default()
            },
        ),
        (
            "a compression level outside 0 to 5",
            WriteOptions {
                method: rarkit::WriteMethod::Compressed {
                    level: 9,
                    dictionary: None,
                },
                ..WriteOptions::default()
            },
        ),
        (
            "a dictionary that is not a power of two multiple of 128 KiB",
            WriteOptions {
                method: rarkit::WriteMethod::Compressed {
                    level: 3,
                    dictionary: Some(300_000),
                },
                ..WriteOptions::default()
            },
        ),
    ];
    for (what, options) in cases {
        let error = Writer::new(options).err().unwrap_or_else(|| {
            panic!("{what}: accepted");
        });
        assert!(
            matches!(
                error.kind(),
                rarkit::ErrorKind::Unsupported(rarkit::Unsupported::WriteFeature(_))
            ),
            "{what}: refused with {error}"
        );
    }
}

/// A name the format cannot store is refused by `add`, before any output.
#[test]
fn a_name_the_format_cannot_store_is_refused_by_add() {
    for name in [&b""[..], b"/absolute", b"with\0nul", b"a/../b"] {
        let mut writer = Writer::new(WriteOptions::default()).unwrap();
        let error = writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(b""),
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
            "{:?}: refused with {error}",
            String::from_utf8_lossy(name)
        );
    }
}

/// An encrypted member cut across volumes: each fragment holds whole
/// cipher blocks, so the chain never carries across a volume boundary,
/// and the set joins back into the member.
#[test]
fn an_encrypted_member_survives_a_volume_cut() {
    let data: Vec<u8> = (0..30_001u32).map(|i| (i.wrapping_mul(31)) as u8).collect();
    for format in [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V40)] {
        let mut writer = Writer::new(WriteOptions {
            format,
            filters: filters_for(format),
            password: Some(rarkit::Password::from("Secret")),
            entropy: rarkit::Entropy::Seeded([11; 32]),
            volume_size: Some(7_000),
            ..WriteOptions::default()
        })
        .unwrap();
        writer
            .add(MemberSpec {
                name: b"split.bin",
                payload: Payload::Bytes(&data),
                mtime: None,
                attributes: 0o100644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .unwrap();
        let mut volumes: Vec<Vec<u8>> = Vec::new();
        writer.finish_volumes(&mut volumes).unwrap();
        assert!(volumes.len() >= 5, "{format:?}: {} volumes", volumes.len());

        let sources: Vec<Arc<dyn RangeSource>> = volumes
            .into_iter()
            .map(|v| Arc::new(v) as Arc<dyn RangeSource>)
            .collect();
        let read = ReadOptions::default().with_password(Some(rarkit::Password::from("Secret")));
        let mut sink = Collect::default();
        let mut progress = NoProgress;
        extract(sources, &read, &mut sink, &mut progress)
            .unwrap_or_else(|e| panic!("{format:?}: reading the encrypted set back: {e}"));
        assert_eq!(sink.members.len(), 1);
        assert_eq!(sink.members[0].data, data, "{format:?}: the joined bytes");
    }
}
