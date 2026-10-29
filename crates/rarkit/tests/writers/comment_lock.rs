//! Spec G 3.15: editing a comment and the lock flag.

use super::*;

/// One member as a listing shows it: name, unpacked size, packed size
/// and checksum.
type Listed = (Vec<u8>, Option<u64>, u64, Option<rarkit::Checksum>);

/// Every member of an archive as it is LISTED: what an edit that copies
/// members byte for byte must leave exactly as it found it. A compressed
/// member cannot be extracted here until spec H's decoders are wired to
/// the extract path, and the listing is what can be compared for every
/// vector whatever its method.
fn listing(archive: &[u8]) -> Vec<Listed> {
    let opened = Archive::open(
        Arc::new(archive.to_vec()) as Arc<dyn RangeSource>,
        &ReadOptions::default(),
    )
    .unwrap();
    opened
        .members()
        .map(|m| (m.name.to_vec(), m.unpacked_size, m.packed_size, m.checksum))
        .collect()
}

/// Whether reference `unrar` prints an archive comment for `archive`.
fn comment_seen_by_unrar(archive: &[u8]) -> bool {
    let Some(unrar) = unrar() else {
        return true;
    };
    let path = std::env::temp_dir().join(format!("rarkit-gc-{}.rar", std::process::id()));
    std::fs::write(&path, archive).unwrap();
    let out = Command::new(unrar).arg("l").arg(&path).output().unwrap();
    let _ = std::fs::remove_file(&path);
    String::from_utf8_lossy(&out.stdout).contains("an edited comment")
}

// ---------------------------------------------------------------------
// Spec G 3.15: editing a comment and the lock flag
// ---------------------------------------------------------------------

/// `edit::set_comment` and `edit::lock` copy every member through byte
/// for byte and change only what they were asked to change.
#[test]
fn an_edit_changes_the_comment_and_the_lock_and_nothing_else() {
    for name in ["r5_store.rar", "r4_store.rar", "r5_m3.rar", "r4_m3.rar"] {
        let original = archive_bytes(name);
        let before = listing(&original);
        let opened = Archive::open(
            Arc::new(original.clone()) as Arc<dyn RangeSource>,
            &ReadOptions::default(),
        )
        .unwrap();

        let mut with_comment = Vec::new();
        rarkit::edit::set_comment(&opened, Some(b"an edited comment"), &mut with_comment)
            .unwrap_or_else(|e| panic!("{name}: set_comment: {e}"));
        let after = listing(&with_comment);
        assert_eq!(
            before, after,
            "{name}: a member changed under an edit that only touched the comment"
        );
        let reopened = Archive::open(
            Arc::new(with_comment.clone()) as Arc<dyn RangeSource>,
            &ReadOptions::default(),
        )
        .unwrap();
        // BOTH families, which they did not use to be. A STORED RAR 4
        // comment sub block spells its method 0x30 and
        // `read/archive.rs::read_comment` tested that byte against 0, so
        // this crate reported no comment on a RAR 4 archive whose comment
        // reference `unrar l` printed. Package G pinned the wrong answer
        // here and reported the defect; it is fixed, and the pin is the
        // right answer now.
        assert_eq!(
            reopened.comment(),
            Some(&b"an edited comment"[..]),
            "{name}: the comment did not land"
        );
        assert!(
            comment_seen_by_unrar(&with_comment),
            "{name}: reference unrar does not see the comment either"
        );
        assert!(!reopened.is_locked(), "{name}: set_comment locked it");

        let mut locked = Vec::new();
        rarkit::edit::lock(&opened, &mut locked).unwrap_or_else(|e| panic!("{name}: lock: {e}"));
        let relocked = Archive::open(
            Arc::new(locked.clone()) as Arc<dyn RangeSource>,
            &ReadOptions::default(),
        )
        .unwrap();
        assert!(relocked.is_locked(), "{name}: lock did not land");

        if let Some(unrar) = unrar() {
            let dir = std::env::temp_dir().join(format!("rarkit-ge-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            for (label, bytes) in [("cmt", &with_comment), ("lock", &locked)] {
                let path = dir.join(format!("{name}.{label}.rar"));
                std::fs::write(&path, bytes).unwrap();
                let out = Command::new(unrar)
                    .arg("t")
                    .arg("-inul")
                    .arg(&path)
                    .output()
                    .expect("unrar t");
                assert!(
                    out.status.success(),
                    "{name} {label}: unrar t exited {:?}\n{}",
                    out.status.code(),
                    String::from_utf8_lossy(&out.stderr)
                );
            }
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}
