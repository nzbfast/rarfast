//! Spec G 3.10.4 and 3.12: volume naming, and encryption and where it
//! shows.

use super::*;

// ---------------------------------------------------------------------
// Spec G 3.10.4: volume naming
// ---------------------------------------------------------------------

/// The numbered form is zero padded to the width of the LAST volume's
/// number, minimum one digit.
#[test]
fn the_numbered_form_pads_to_the_last_volumes_width() {
    assert_eq!(
        rarkit::volume_file_name("set", 0, 4, VolumeNaming::Numbered),
        "set.part1.rar"
    );
    assert_eq!(
        rarkit::volume_file_name("set", 3, 4, VolumeNaming::Numbered),
        "set.part4.rar"
    );
    assert_eq!(
        rarkit::volume_file_name("set", 0, 11, VolumeNaming::Numbered),
        "set.part01.rar"
    );
    assert_eq!(
        rarkit::volume_file_name("set", 10, 11, VolumeNaming::Numbered),
        "set.part11.rar"
    );
    assert_eq!(
        rarkit::volume_file_name("set", 0, 3, VolumeNaming::Classic),
        "set.rar"
    );
    assert_eq!(
        rarkit::volume_file_name("set", 1, 3, VolumeNaming::Classic),
        "set.r00"
    );
    assert_eq!(
        rarkit::volume_file_name("set", 2, 3, VolumeNaming::Classic),
        "set.r01"
    );
}

// ---------------------------------------------------------------------
// Spec G 3.12: encryption, and where it shows
// ---------------------------------------------------------------------

/// An encrypted member reads back as itself, through rarkit's own reader
/// and through reference `unrar -p`, in both families.
#[test]
fn an_encrypted_member_reads_back_in_both_families() {
    let members = read_back(&["r5_store.rar"]);
    let dir = std::env::temp_dir().join(format!("rarkit-gp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    for (label, format) in [
        ("r5", WriteFormat::Rar5),
        ("r4", WriteFormat::Rar4(Rar4Version::V40)),
    ] {
        let options = WriteOptions {
            format,
            filters: filters_for(format),
            password: Some(rarkit::Password::from("Secret")),
            entropy: rarkit::Entropy::Seeded([7; 32]),
            ..WriteOptions::default()
        };
        let archive = write_one(options, &members);

        let sources = vec![Arc::new(archive.clone()) as Arc<dyn RangeSource>];
        let read = ReadOptions::default().with_password(Some(rarkit::Password::from("Secret")));
        let mut sink = Collect::default();
        let mut progress = NoProgress;
        extract(sources, &read, &mut sink, &mut progress)
            .unwrap_or_else(|e| panic!("{label}: reading an encrypted archive back: {e}"));
        assert_eq!(sink.members.len(), members.len(), "{label}: member count");
        for (want, got) in members.iter().zip(&sink.members) {
            assert_eq!(want.data, got.data, "{label}: the member's bytes");
        }

        if let Some(unrar) = unrar() {
            let path = dir.join(format!("{label}_pw.rar"));
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
                "{label}: unrar t -p exited {:?}\n{}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A seeded entropy source reproduces an encrypted archive byte for byte,
/// which is what postfast's reproducible posts rest on (spec G 3.13).
#[test]
fn a_seeded_source_reproduces_an_encrypted_archive() {
    let members = read_back(&["r5_store.rar"]);
    let build = || {
        write_one(
            WriteOptions {
                password: Some(rarkit::Password::from("Secret")),
                entropy: rarkit::Entropy::Seeded([42; 32]),
                ..WriteOptions::default()
            },
            &members,
        )
    };
    assert_eq!(build(), build(), "two seeded runs differ");
    let other = write_one(
        WriteOptions {
            password: Some(rarkit::Password::from("Secret")),
            entropy: rarkit::Entropy::Seeded([43; 32]),
            ..WriteOptions::default()
        },
        &members,
    );
    assert_ne!(build(), other, "two different seeds gave one archive");
}

/// Reads `archive` with `password` through rarkit's own reader.
fn read_with(archive: Vec<u8>, password: &str) -> rarkit::Result<Vec<Member>> {
    let sources = vec![Arc::new(archive) as Arc<dyn RangeSource>];
    let read = ReadOptions::default().with_password(Some(rarkit::Password::from(password)));
    let mut sink = Collect::default();
    let mut progress = NoProgress;
    extract(sources, &read, &mut sink, &mut progress)?;
    Ok(sink.members)
}

/// Spec K 3.7.1 and spec B 3.2: the first 127 characters of a password
/// are the password. An archive this writer makes with a longer one opens
/// in the reference with that same password, in both families, and what
/// genuine `rar` writes with a longer one opens here with it.
///
/// One thread; the archives are a few hundred bytes.
#[test]
fn a_password_longer_than_127_characters_agrees_with_the_reference() {
    let long: String = (0..200u8).map(|i| char::from(b'a' + i % 26)).collect();
    let first = &long[..127];
    let members = read_back(&["r5_store.rar"]);
    let dir = std::env::temp_dir().join(format!("rarkit-pw127-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    for (label, format) in [
        ("r5", WriteFormat::Rar5),
        ("r4", WriteFormat::Rar4(Rar4Version::V40)),
    ] {
        let options = WriteOptions {
            format,
            filters: filters_for(format),
            password: Some(rarkit::Password::from(long.as_str())),
            entropy: rarkit::Entropy::Seeded([7; 32]),
            ..WriteOptions::default()
        };
        let archive = write_one(options, &members);
        for (what, password) in [("all 200 typed", long.as_str()), ("the first 127", first)] {
            let got = read_with(archive.clone(), password)
                .unwrap_or_else(|e| panic!("{label}, {what}: {e}"));
            assert_eq!(got.len(), members.len(), "{label}, {what}");
            for (want, got) in members.iter().zip(&got) {
                assert_eq!(want.data, got.data, "{label}, {what}");
            }
        }
        if let Some(unrar) = unrar() {
            let path = dir.join(format!("{label}_long.rar"));
            std::fs::write(&path, &archive).unwrap();
            let out = Command::new(unrar)
                .arg("t")
                .arg("-inul")
                .arg(format!("-p{long}"))
                .arg(&path)
                .output()
                .expect("unrar t");
            assert!(
                out.status.success(),
                "{label}: unrar t with the 200 character password exited {:?}",
                out.status.code()
            );
        }
    }

    if let Some(rar) = rar() {
        let file = dir.join("h.txt");
        std::fs::write(&file, b"hello long password\n").unwrap();
        let path = dir.join("genuine_long.rar");
        let out = Command::new(rar)
            .arg("a")
            .arg("-idq")
            .arg("-ep")
            .arg(format!("-p{long}"))
            .arg(&path)
            .arg(&file)
            .output()
            .expect("rar a");
        assert!(out.status.success(), "rar a exited {:?}", out.status.code());
        let archive = std::fs::read(&path).unwrap();
        for (what, password) in [("all 200 typed", long.as_str()), ("the first 127", first)] {
            let got = read_with(archive.clone(), password)
                .unwrap_or_else(|e| panic!("genuine rar's archive, {what}: {e}"));
            assert_eq!(got.len(), 1, "{what}");
            assert_eq!(got[0].data, b"hello long password\n", "{what}");
        }
        let err = read_with(archive, &long[..126]).unwrap_err();
        assert!(
            matches!(err.kind(), rarkit::ErrorKind::WrongPassword),
            "the first 126 characters are another password: {err}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Spec B 3.2: a character outside the basic plane enters the RAR 3 seed
/// as the low 16 bits of its code point, which is what the reference
/// programs for Linux and macOS derive from; this writer writes that, and
/// reads it back. What a Windows build writes is not established, so the
/// specification's stated rule stands for every host.
///
/// One thread; the archives are a few hundred bytes.
#[test]
fn a_rar4_password_outside_the_basic_plane_opens_in_the_reference() {
    let password = "\u{1f511}key";
    let members = read_back(&["r5_store.rar"]);
    let dir = std::env::temp_dir().join(format!("rarkit-astral-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for (label, encrypt_headers) in [("data", false), ("headers", true)] {
        let format = WriteFormat::Rar4(Rar4Version::V40);
        let archive = write_one(
            WriteOptions {
                format,
                filters: filters_for(format),
                password: Some(rarkit::Password::from(password)),
                encrypt_headers,
                entropy: rarkit::Entropy::Seeded([7; 32]),
                ..WriteOptions::default()
            },
            &members,
        );
        let got = read_with(archive.clone(), password).unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(got.len(), members.len(), "{label}");
        for (want, got) in members.iter().zip(&got) {
            assert_eq!(want.data, got.data, "{label}");
        }
        if let Some(unrar) = unrar() {
            let path = dir.join(format!("{label}_astral.rar"));
            std::fs::write(&path, &archive).unwrap();
            let out = Command::new(unrar)
                .arg("t")
                .arg("-inul")
                .arg(format!("-p{password}"))
                .arg(&path)
                .output()
                .expect("unrar t");
            assert!(
                out.status.success(),
                "{label}: unrar t exited {:?}",
                out.status.code()
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
