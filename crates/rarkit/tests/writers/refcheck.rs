//! Spec G 5.1: the same comparison refcheck.py makes, from Rust.

use super::*;

/// Every shape spec G 5.1 lists, built by reference `rar a -m0` here and
/// now and by rarkit's `Layout::Reference`, and compared byte for byte.
///
/// This is `vectors-G/refcheck.py`'s comparison, which found 24 matches
/// and 0 differences, run from Rust against the binary on this box. The
/// sizes are the ones the specification measured: both crossings of the
/// size-field width rule of 3.6.4, both crossings of the locator reserve
/// rule of 3.6.3, the quick-open threshold, and the natural vint
/// crossing.
#[test]
fn every_measured_shape_matches_fresh_reference_output() {
    // A NAMED skip off unix. The comparison is against reference `rar`
    // output for a Unix host: each member carries the input file's unix
    // mode and `HostOs::Unix`, so on any other host both sides would write
    // a different attribute word for reasons that are not this writer's.
    // `cfg!` rather than `#[cfg]` so the body below still type-checks for
    // a Windows dev target, which is how the unix-only call further down
    // went unnoticed.
    if cfg!(not(unix)) {
        eprintln!(
            "SKIPPED every_measured_shape_matches_fresh_reference_output: \
             the measured shapes are reference `rar` output for a Unix host."
        );
        return;
    }
    let Some(rar) = rar() else {
        eprintln!("SKIPPED: reference rar is not on PATH");
        return;
    };
    let dir = std::env::temp_dir().join(format!("rarkit-gref-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // The whole-second time both sides must agree on.
    let when = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
    let stamp = Timestamp {
        unix_seconds: 1_600_000_000,
        nanos: 0,
    };

    let shapes: [(&str, &str, usize); 12] = [
        ("one_small", "s.bin", 10),
        ("one_127", "s.bin", 127),
        ("one_128", "s.bin", 128),
        ("one_4096", "s.bin", 4_096),
        ("one_4097", "s.bin", 4_097),
        ("w7679", "s.bin", 7_679),
        ("w7680", "s.bin", 7_680),
        ("cross_65487", "s.bin", 65_487),
        ("cross_65488", "s.bin", 65_488),
        ("w1048063", "s.bin", 1_048_063),
        ("w1048064", "s.bin", 1_048_064),
        ("mib_step", "s.bin", 1_048_576),
    ];

    let mut wrong = Vec::new();
    for (label, name, size) in shapes {
        let work = dir.join(label);
        std::fs::create_dir_all(&work).unwrap();
        let data = pseudo(size as u64, size);
        let input = work.join(name);
        std::fs::write(&input, &data).unwrap();
        let file = std::fs::File::options().write(true).open(&input).unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(when))
            .unwrap();
        drop(file);

        let archive = work.join("ref.rar");
        let out = Command::new(rar)
            .arg("a")
            .arg("-idq")
            .arg("-ep1")
            .arg("-m0")
            .arg(&archive)
            .arg(name)
            .current_dir(&work)
            .output()
            .expect("rar a");
        assert!(out.status.success(), "{label}: rar a failed");
        let theirs = std::fs::read(&archive).unwrap();

        let attributes = {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                std::fs::metadata(&input).unwrap().mode()
            }
            // Unreachable: the skip at the top of this test returns off
            // unix. Present so the file COMPILES for a Windows dev target.
            #[cfg(not(unix))]
            {
                0u32
            }
        };
        let ours = write_one(
            reference_options(),
            &[Member {
                name: name.as_bytes().to_vec(),
                is_directory: false,
                data: data.clone(),
                mtime: Some(stamp),
                attributes,
                host_os: rarkit::HostOs::Unix,
            }],
        );
        if ours != theirs {
            let at = ours
                .iter()
                .zip(&theirs)
                .position(|(a, b)| a != b)
                .unwrap_or(ours.len().min(theirs.len()));
            wrong.push(format!(
                "{label} ({size} bytes): ours {} bytes, rar {} bytes, first difference at {at}",
                ours.len(),
                theirs.len()
            ));
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        wrong.is_empty(),
        "{} of 12 shapes differ from fresh rar 7.23 output:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// Spec G 3.10.2's checksum rule, checked by PARSING THE ARCHIVES BACK
/// rather than by trusting the writer: every fragment but the last
/// carries its own checksum, and the last carries the whole member's.
///
/// Spec G 8.4 is the defect this closes: a split stored member that
/// carried a fragment checksum everywhere and the whole member's nowhere
/// extracted corrupt bytes and reported success.
#[test]
fn every_fragment_carries_the_checksum_the_specification_names() {
    let data = pseudo(4242, 12_000);
    let whole = rarkit::checksum::crc32(&data);

    for format in [WriteFormat::Rar5, WriteFormat::Rar4(Rar4Version::V40)] {
        let mut writer = Writer::new(WriteOptions {
            format,
            filters: filters_for(format),
            volume_size: Some(4_000),
            host_os: rarkit::HostOs::Unix,
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
        assert_eq!(volumes.len(), 3, "{format:?}: volumes");

        let mut at = 0usize;
        for (index, volume) in volumes.iter().enumerate() {
            let opened = Archive::open(
                Arc::new(volume.clone()) as Arc<dyn RangeSource>,
                &ReadOptions::default(),
            )
            .unwrap();
            let member = opened.members().next().expect("one fragment per volume");
            let len = member.packed_size as usize;
            let last = index + 1 == volumes.len();
            let expected = if last {
                whole
            } else {
                rarkit::checksum::crc32(&data[at..at + len])
            };
            assert_eq!(
                member.checksum,
                Some(rarkit::Checksum::Crc32(expected)),
                "{format:?} fragment {index}: the {} checksum",
                if last { "whole member's" } else { "fragment's" }
            );
            assert_eq!(
                member.split_before,
                index != 0,
                "{format:?} fragment {index}: continued-from flag"
            );
            assert_eq!(
                member.split_after, !last,
                "{format:?} fragment {index}: continues-into flag"
            );
            assert_eq!(
                member.unpacked_size,
                Some(data.len() as u64),
                "{format:?} fragment {index}: the whole member's size"
            );
            at += len;
        }
        assert_eq!(at, data.len(), "{format:?}: the fragments do not add up");
    }
}

/// What `edit` refuses, and why each one cannot be a rewrite (spec G
/// section 1 and 3.3.6). Found by the `edit_roundtrip` fuzz target of
/// section 6.4, which put a RAR 1.3 archive through and got back
/// something that would not reopen.
#[test]
fn edit_refuses_an_archive_it_cannot_rewrite() {
    // A RAR 1.3 archive, whose container is not the one this crate writes.
    let rar13 = std::path::PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../specs/vectors-F/archives"
    ));
    let Ok(entries) = std::fs::read_dir(&rar13) else {
        eprintln!("SKIPPED: vectors-F is not here");
        return;
    };
    let mut refused = 0;
    let mut rewritten = 0;
    for entry in entries.flatten() {
        let Ok(bytes) = std::fs::read(entry.path()) else {
            continue;
        };
        let Ok(opened) = Archive::open(
            Arc::new(bytes.clone()) as Arc<dyn RangeSource>,
            &ReadOptions::default(),
        ) else {
            continue;
        };
        let mut out = Vec::new();
        match rarkit::edit::set_comment(&opened, Some(b"edited"), &mut out) {
            Err(error) => {
                assert!(
                    matches!(
                        error.kind(),
                        rarkit::ErrorKind::Unsupported(rarkit::Unsupported::WriteFeature(_))
                    ),
                    "{:?}: refused with {error}",
                    entry.file_name()
                );
                refused += 1;
            }
            Ok(()) => {
                // Anything it did NOT refuse must reopen.
                Archive::open(
                    Arc::new(out) as Arc<dyn RangeSource>,
                    &ReadOptions::default(),
                )
                .unwrap_or_else(|e| {
                    panic!(
                        "{:?}: a rewrite this crate accepted did not reopen: {e}",
                        entry.file_name()
                    )
                });
                rewritten += 1;
            }
        }
    }
    assert!(
        rewritten > 0,
        "no archive of the corpus was rewritten at all"
    );
    eprintln!("edit: {rewritten} rewritten, {refused} refused");
}

/// Header encryption (spec G 3.3.6): the archive encryption header goes
/// first and in clear, every block after it is encrypted, and reference
/// `unrar -p` reads the archive back.
#[test]
fn encrypted_headers_read_back_in_both_families() {
    let members = read_back(&["r5_store.rar"]);
    let dir = std::env::temp_dir().join(format!("rarkit-ghp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    for (label, format) in [
        ("r5", WriteFormat::Rar5),
        ("r4", WriteFormat::Rar4(Rar4Version::V40)),
    ] {
        let archive = write_one(
            WriteOptions {
                format,
                filters: filters_for(format),
                password: Some(rarkit::Password::from("Secret")),
                encrypt_headers: true,
                entropy: rarkit::Entropy::Seeded([19; 32]),
                ..WriteOptions::default()
            },
            &members,
        );

        // Nothing in the clear says what is in there: the member names do
        // not appear anywhere in the bytes.
        for member in &members {
            assert!(
                !archive
                    .windows(member.name.len())
                    .any(|w| w == member.name.as_slice()),
                "{label}: a member name is readable in an archive with encrypted headers"
            );
        }

        let sources = vec![Arc::new(archive.clone()) as Arc<dyn RangeSource>];
        let read = ReadOptions::default().with_password(Some(rarkit::Password::from("Secret")));
        let mut sink = Collect::default();
        let mut progress = NoProgress;
        extract(sources, &read, &mut sink, &mut progress)
            .unwrap_or_else(|e| panic!("{label}: reading encrypted headers back: {e}"));
        assert_eq!(sink.members.len(), members.len(), "{label}: member count");
        for (want, got) in members.iter().zip(&sink.members) {
            assert_eq!(want.name, got.name, "{label}: name");
            assert_eq!(want.data, got.data, "{label}: bytes");
        }

        if let Some(unrar) = unrar() {
            let path = dir.join(format!("{label}_hpw.rar"));
            std::fs::write(&path, &archive).unwrap();
            let out = Command::new(unrar)
                .arg("t")
                .arg("-inul")
                .arg("-pSecret")
                .arg(&path)
                .output()
                .expect("unrar t");
            assert!(
                out.status.success(),
                "{label}: unrar t -p on encrypted headers exited {:?}\n{}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
