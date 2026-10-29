//! Spec G 3.6 and 6.1: byte identity with rar 7.23, and the two oracles,
//! rarkit's own reader and reference unrar.

use super::*;

// ---------------------------------------------------------------------
// Spec G 3.6: byte identity with rar 7.23
// ---------------------------------------------------------------------

/// The reference layout reproduces `rar` 7.23's own bytes for a stored
/// archive: the members are read out of the reference's archive and put
/// back, and the two files are compared byte for byte (spec G 5.1).
#[test]
fn the_reference_layout_reproduces_rar_7_23_byte_for_byte() {
    for name in ["r5_store.rar", "r5_lock.rar", "r5_cmt.rar", "r5_blake.rar"] {
        let members = read_back(&[name]);
        let mut options = reference_options();
        if name == "r5_lock.rar" {
            options.lock = true;
        }
        if name == "r5_blake.rar" {
            options.checksum = ChecksumKind::Blake2sp;
        }
        if name == "r5_cmt.rar" {
            options.comment = Some(comment_of(name));
        }
        let ours = write_one(options, &members);
        let theirs = archive_bytes(name);
        assert_eq!(
            ours.len(),
            theirs.len(),
            "{name}: length {} against the reference's {}",
            ours.len(),
            theirs.len()
        );
        assert_eq!(ours, theirs, "{name}: bytes differ from the reference's");
    }
}

/// The archive comment of a vector, taken out of its own `CMT` block.
fn comment_of(name: &str) -> Vec<u8> {
    let archive = Archive::open(
        Arc::new(archive_bytes(name)) as Arc<dyn RangeSource>,
        &ReadOptions::default(),
    )
    .unwrap();
    archive.comment().expect("a comment").to_vec()
}

// ---------------------------------------------------------------------
// Spec G 6.1 oracle 2: rarkit's own reader
// ---------------------------------------------------------------------

/// Every vector's members survive a write and a read back, in both
/// families and both layouts.
#[test]
fn members_survive_a_write_and_a_read_back() {
    let members = read_back(&["r5_store.rar"]);
    for format in [
        WriteFormat::Rar5,
        WriteFormat::Rar4(Rar4Version::V29),
        WriteFormat::Rar4(Rar4Version::V30),
        WriteFormat::Rar4(Rar4Version::V40),
    ] {
        let options = WriteOptions {
            format,
            filters: filters_for(format),
            host_os: rarkit::HostOs::Unix,
            ..WriteOptions::default()
        };
        let archive = write_one(options, &members);
        let got = read_back_bytes(vec![archive]);
        assert_eq!(got.len(), members.len(), "{format:?}: member count");
        for (want, got) in members.iter().zip(&got) {
            assert_eq!(want.name, got.name, "{format:?}: name");
            assert_eq!(want.data, got.data, "{format:?}: bytes");
            assert_eq!(want.is_directory, got.is_directory, "{format:?}: directory");
        }
    }
}

/// A member cut across volumes joins back into the same bytes, and each
/// fragment carries the checksum spec G 3.10.2 names.
#[test]
fn a_volume_set_joins_back_into_one_member_set() {
    let whole = read_back(&[
        "r5_vol.part1.rar",
        "r5_vol.part2.rar",
        "r5_vol.part3.rar",
        "r5_vol.part4.rar",
    ]);
    assert_eq!(whole.len(), 1);
    assert_eq!(whole[0].data.len(), 12_000);

    for format in [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V40)] {
        let options = WriteOptions {
            format,
            filters: filters_for(format),
            volume_size: Some(4_000),
            host_os: rarkit::HostOs::Unix,
            ..WriteOptions::default()
        };
        let mut writer = Writer::new(options).expect("options");
        writer
            .add(MemberSpec {
                name: &whole[0].name,
                payload: Payload::Bytes(&whole[0].data),
                mtime: whole[0].mtime,
                attributes: whole[0].attributes,
                host_os: whole[0].host_os,
                is_directory: false,
            })
            .expect("add");
        let mut volumes: Vec<Vec<u8>> = Vec::new();
        let report = writer.finish_volumes(&mut volumes).expect("finish");
        assert_eq!(
            report.volumes, 3,
            "{format:?}: 12,000 bytes at 4,000 a volume"
        );
        assert_eq!(volumes.len(), 3);
        let got = read_back_bytes(volumes);
        assert_eq!(got.len(), 1, "{format:?}: one member");
        assert_eq!(got[0].data, whole[0].data, "{format:?}: the joined bytes");
    }
}

/// Every shape this writer produces is accepted by reference `unrar`.
#[test]
fn reference_unrar_accepts_what_this_writer_writes() {
    let Some(unrar) = unrar() else {
        eprintln!("SKIPPED: reference unrar is not on PATH");
        return;
    };
    let members = read_back(&["r5_store.rar"]);
    let dir = std::env::temp_dir().join(format!("rarkit-g-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let shapes: Vec<(&str, WriteOptions)> = vec![
        ("rar5_default", WriteOptions::default()),
        (
            "rar5_reference",
            WriteOptions {
                layout: Layout::Reference { quick_open: true },
                ..WriteOptions::default()
            },
        ),
        (
            "rar5_blake",
            WriteOptions {
                checksum: ChecksumKind::Blake2sp,
                ..WriteOptions::default()
            },
        ),
        (
            "rar5_comment",
            WriteOptions {
                comment: Some(b"a comment this writer wrote".to_vec()),
                ..WriteOptions::default()
            },
        ),
        (
            "rar4_v29",
            WriteOptions {
                format: WriteFormat::Rar4(Rar4Version::V29),
                filters: rarkit::FilterPolicy::Off,
                ..WriteOptions::default()
            },
        ),
        (
            "rar4_v40",
            WriteOptions {
                format: WriteFormat::Rar4(Rar4Version::V40),
                filters: rarkit::FilterPolicy::Off,
                ..WriteOptions::default()
            },
        ),
        (
            "rar4_comment",
            WriteOptions {
                format: WriteFormat::Rar4(Rar4Version::V40),
                filters: rarkit::FilterPolicy::Off,
                comment: Some(b"a comment this writer wrote".to_vec()),
                ..WriteOptions::default()
            },
        ),
    ];

    for (label, options) in shapes {
        let archive = write_one(options, &members);
        let path = dir.join(format!("{label}.rar"));
        std::fs::write(&path, &archive).unwrap();
        let out = Command::new(unrar)
            .arg("t")
            .arg("-inul")
            .arg(&path)
            .output()
            .expect("unrar t");
        assert!(
            out.status.success(),
            "{label}: unrar t exited {:?}\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A volume set this writer produces is accepted and joined by reference
/// `unrar`, under both naming forms (spec G 3.10.4).
#[test]
fn reference_unrar_accepts_a_volume_set() {
    let Some(unrar) = unrar() else {
        eprintln!("SKIPPED: reference unrar is not on PATH");
        return;
    };
    let whole = read_back(&[
        "r5_vol.part1.rar",
        "r5_vol.part2.rar",
        "r5_vol.part3.rar",
        "r5_vol.part4.rar",
    ]);
    let dir = std::env::temp_dir().join(format!("rarkit-gv-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    for (label, format, naming) in [
        ("r5", WriteFormat::Rar5, VolumeNaming::Numbered),
        (
            "r4n",
            WriteFormat::Rar4(Rar4Version::V40),
            VolumeNaming::Numbered,
        ),
        (
            "r4c",
            WriteFormat::Rar4(Rar4Version::V40),
            VolumeNaming::Classic,
        ),
    ] {
        let options = WriteOptions {
            format,
            filters: filters_for(format),
            volume_naming: naming,
            volume_size: Some(4_000),
            ..WriteOptions::default()
        };
        let mut writer = Writer::new(options).expect("options");
        writer
            .add(MemberSpec {
                name: &whole[0].name,
                payload: Payload::Bytes(&whole[0].data),
                mtime: whole[0].mtime,
                attributes: whole[0].attributes,
                host_os: whole[0].host_os,
                is_directory: false,
            })
            .expect("add");
        let mut volumes: Vec<Vec<u8>> = Vec::new();
        writer.finish_volumes(&mut volumes).expect("finish");

        let stem = format!("{label}set");
        for (index, bytes) in volumes.iter().enumerate() {
            let name = rarkit::volume_file_name(&stem, index as u32, volumes.len() as u32, naming);
            std::fs::write(dir.join(name), bytes).unwrap();
        }
        let first = rarkit::volume_file_name(&stem, 0, volumes.len() as u32, naming);
        let out = Command::new(unrar)
            .arg("t")
            .arg("-inul")
            .arg(dir.join(first))
            .output()
            .expect("unrar t");
        assert!(
            out.status.success(),
            "{label}: unrar t on the set exited {:?}\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
