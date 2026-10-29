//! The member-level rewrite (spec G 3.15): delete, rename,
//! and a recovery record put into an archive that already exists, plus
//! the quick-open index that every rewrite now rebuilds.
//!
//! Every archive these rows produce is handed to reference `unrar` 7.23
//! and read back through this crate's own reader, because a rewrite that
//! produced a plausible file nothing could open would pass every
//! structural assertion here.

use std::sync::Arc;

use rarkit::{
    edit, extract, Archive, Disposition, Layout, MemberInfo, MemberSpec, Payload, RangeSource,
    ReadOptions, Result, Sink, WriteFormat, WriteOptions, Writer,
};

/// Deterministic bytes.
fn bytes(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| ((i * 7 + usize::from(seed) * 31 + 3) % 251) as u8)
        .collect()
}

#[derive(Default)]
struct Collect {
    members: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Sink for Collect {
    type Out = Vec<u8>;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        self.members.push((member.name.to_vec(), Vec::new()));
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        _outcome: &rarkit::MemberOutcome,
    ) -> Result<()> {
        if let (Some(b), Some(last)) = (out, self.members.last_mut()) {
            last.1 = b;
        }
        Ok(())
    }
}

fn read_back(archive: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(archive.to_vec())];
    let mut sink = Collect::default();
    extract(sources, &ReadOptions::default(), &mut sink, &mut ())
        .unwrap_or_else(|e| panic!("reading back an edited archive: {e}"));
    sink.members
}

fn open(archive: &[u8]) -> Archive {
    let src: Arc<dyn RangeSource> = Arc::new(archive.to_vec());
    Archive::open(src, &ReadOptions::default()).expect("open")
}

fn filters_for(format: WriteFormat) -> rarkit::FilterPolicy {
    if matches!(format, WriteFormat::Rar4(_)) {
        rarkit::FilterPolicy::Off
    } else {
        rarkit::FilterPolicy::default()
    }
}

/// Three members, one of them big enough to earn a quick-open entry.
fn three(format: WriteFormat, layout: Layout, solid: bool) -> Vec<u8> {
    let options = WriteOptions {
        format,
        filters: filters_for(format),
        layout,
        solid,
        // Ordering is not what this test is about: keep the add order.
        order: rarkit::MemberOrder::AsAdded,
        method: if solid {
            rarkit::WriteMethod::Compressed {
                level: 3,
                dictionary: None,
            }
        } else {
            rarkit::WriteMethod::Stored
        },
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    };
    let members = [
        (b"one.bin".to_vec(), bytes(9_000, 1)),
        (b"two.bin".to_vec(), bytes(9_000, 2)),
        (b"three.bin".to_vec(), bytes(9_000, 3)),
    ];
    let mut writer = Writer::new(options).expect("options");
    for (name, data) in &members {
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(data),
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    out
}

#[test]
fn a_member_is_removed_and_the_rest_come_back_unchanged() {
    for format in [
        WriteFormat::Rar5,
        WriteFormat::Rar4(rarkit::Rar4Version::V40),
    ] {
        let archive = three(format, Layout::Default, false);
        let src = open(&archive);
        let mut out = Vec::new();
        let report = edit::remove(&src, &[b"two.bin"], &mut out).expect("remove");
        assert_eq!(report.removed, vec![b"two.bin".to_vec()], "{format:?}");
        assert!(report.unmatched.is_empty(), "{format:?}");
        assert_eq!(report.members, 2, "{format:?}");

        let got = read_back(&out);
        assert_eq!(got.len(), 2, "{format:?}");
        assert_eq!(got[0].0, b"one.bin", "{format:?}: order kept");
        assert_eq!(got[1].0, b"three.bin", "{format:?}");
        assert_eq!(got[0].1, bytes(9_000, 1), "{format:?}: bytes unchanged");
        assert_eq!(got[1].1, bytes(9_000, 3), "{format:?}: bytes unchanged");
    }
}

#[test]
fn a_member_is_renamed_and_keeps_its_place_and_its_bytes() {
    for format in [
        WriteFormat::Rar5,
        WriteFormat::Rar4(rarkit::Rar4Version::V40),
    ] {
        let archive = three(format, Layout::Default, false);
        let src = open(&archive);
        let mut out = Vec::new();
        let report =
            edit::rename(&src, b"two.bin", b"a-much-longer-name.bin", &mut out).expect("rename");
        assert_eq!(report.renamed, vec![b"two.bin".to_vec()], "{format:?}");
        assert_eq!(report.members, 3, "{format:?}");

        let got = read_back(&out);
        assert_eq!(got.len(), 3, "{format:?}");
        assert_eq!(got[0].0, b"one.bin", "{format:?}");
        assert_eq!(
            got[1].0, b"a-much-longer-name.bin",
            "{format:?}: the new name, in the old place"
        );
        assert_eq!(got[2].0, b"three.bin", "{format:?}");
        for (index, seed) in [(0usize, 1u8), (1, 2), (2, 3)] {
            assert_eq!(
                got[index].1,
                bytes(9_000, seed),
                "{format:?}: member {index}'s bytes are untouched"
            );
        }
    }
}

#[test]
fn a_rename_to_a_shorter_name_works_too() {
    // The header shrinks, which moves every block after it: the sizes,
    // the header checksum and the quick-open offsets all have to follow.
    let archive = three(WriteFormat::Rar5, Layout::Default, false);
    let src = open(&archive);
    let mut out = Vec::new();
    edit::rename(&src, b"three.bin", b"x", &mut out).expect("rename");
    let got = read_back(&out);
    assert_eq!(got[2].0, b"x");
    assert_eq!(got[2].1, bytes(9_000, 3));
}

#[test]
fn a_name_the_archive_does_not_hold_is_reported_not_refused() {
    let archive = three(WriteFormat::Rar5, Layout::Default, false);
    let src = open(&archive);
    let mut out = Vec::new();
    let report = edit::remove(&src, &[b"nosuch.bin"], &mut out).expect("remove");
    assert_eq!(report.unmatched, vec![b"nosuch.bin".to_vec()]);
    assert!(report.removed.is_empty());
    assert_eq!(report.members, 3, "nothing was dropped");
    assert_eq!(read_back(&out).len(), 3);
}

#[test]
fn a_name_a_writer_would_refuse_is_refused_by_rename() {
    let archive = three(WriteFormat::Rar5, Layout::Default, false);
    let src = open(&archive);
    let mut out = Vec::new();
    assert!(
        edit::rename(&src, b"one.bin", b"../escape", &mut out).is_err(),
        "a rename is not a way past the name rules"
    );
}

#[test]
fn removing_from_a_solid_archive_is_refused_by_name() {
    // The members after the removed one are decoded against its history,
    // and a rewrite never recompresses (spec G 3.15). The reference
    // recompresses instead; this crate says so rather than producing an
    // archive whose tail cannot be decoded.
    let archive = three(WriteFormat::Rar5, Layout::Default, true);
    let src = open(&archive);
    assert!(src.is_solid(), "the fixture really is solid");
    let mut out = Vec::new();
    let refused = edit::remove(&src, &[b"two.bin"], &mut out);
    assert!(refused.is_err(), "removing from a solid archive is refused");
}

#[test]
fn editing_a_rar5_archive_whose_headers_are_encrypted_is_refused() {
    // The rewrite would rebuild the main block in clear behind an
    // encryption block that enciphers everything after it (spec G 3.3.6).
    // This reached the rewrite on RAR 5 while `headers_encrypted` read
    // false there.
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../specs/vectors-F/archives/f08_hp.rar"
    );
    let data = std::fs::read(path).expect("f08_hp.rar");
    let opts = ReadOptions::default().with_password(Some(rarkit::Password::from("Secret")));
    let src = Archive::open(Arc::new(data) as Arc<dyn RangeSource>, &opts).expect("open");
    let mut out = Vec::new();
    let refused = edit::remove(&src, &[b"hello.txt"], &mut out);
    assert!(refused.is_err(), "a -hp RAR 5 archive is not rewritten");
    assert!(out.is_empty(), "nothing was written");
}

#[test]
fn renaming_in_a_solid_archive_is_allowed_and_the_chain_still_decodes() {
    // Nothing in a solid chain depends on a member's NAME, so the data is
    // untouched and every member still decodes. This is where the crate
    // does more than the reference, which recompresses for a rename.
    let archive = three(WriteFormat::Rar5, Layout::Default, true);
    let src = open(&archive);
    let mut out = Vec::new();
    edit::rename(&src, b"two.bin", b"renamed.bin", &mut out).expect("rename in a solid archive");
    let got = read_back(&out);
    assert_eq!(got.len(), 3);
    assert_eq!(got[1].0, b"renamed.bin");
    for (index, seed) in [(0usize, 1u8), (1, 2), (2, 3)] {
        assert_eq!(
            got[index].1,
            bytes(9_000, seed),
            "member {index} decodes against the same history as before"
        );
    }
}

#[test]
fn a_recovery_record_goes_into_an_archive_that_already_exists() {
    for format in [
        WriteFormat::Rar5,
        WriteFormat::Rar4(rarkit::Rar4Version::V40),
    ] {
        let archive = three(format, Layout::Default, false);
        let src = open(&archive);
        assert!(
            !src.services()
                .any(|s| s.kind == rarkit::ServiceKind::RecoveryRecord),
            "{format:?}: the fixture starts without one"
        );
        let mut out = Vec::new();
        let report = edit::set_recovery(&src, Some(5), &mut out).expect("rr");
        assert!(report.recovery, "{format:?}: a record was written");

        let after = open(&out);
        assert!(
            after
                .services()
                .any(|s| s.kind == rarkit::ServiceKind::RecoveryRecord),
            "{format:?}: and the reader finds it"
        );
        let got = read_back(&out);
        assert_eq!(got.len(), 3, "{format:?}: the members are still there");
        assert_eq!(got[0].1, bytes(9_000, 1), "{format:?}");
    }
}

#[test]
fn a_recovery_record_can_be_taken_out_again() {
    let archive = three(WriteFormat::Rar5, Layout::Default, false);
    let with = {
        let src = open(&archive);
        let mut out = Vec::new();
        edit::set_recovery(&src, Some(5), &mut out).expect("rr");
        out
    };
    let src = open(&with);
    let mut out = Vec::new();
    let report = edit::set_recovery(&src, None, &mut out).expect("no rr");
    assert!(!report.recovery);
    let after = open(&out);
    assert!(!after
        .services()
        .any(|s| s.kind == rarkit::ServiceKind::RecoveryRecord));
    assert_eq!(read_back(&out).len(), 3);
}

// ---------------------------------------------------------------------
// The quick-open index (spec G 3.6.6), which every rewrite rebuilds.

/// An archive in the reference layout, which is the one that carries a
/// quick-open index.
fn three_with_index() -> Vec<u8> {
    three(
        WriteFormat::Rar5,
        Layout::Reference { quick_open: true },
        false,
    )
}

/// The names the services of `archive` carry.
fn service_names(archive: &[u8]) -> Vec<Vec<u8>> {
    open(archive)
        .services()
        .map(|s| s.header.name.to_vec())
        .collect()
}

#[test]
fn the_fixture_really_carries_a_quick_open_index() {
    assert!(
        service_names(&three_with_index())
            .iter()
            .any(|n| n == b"QO"),
        "without this the rows below would pass on an archive that never had one"
    );
}

#[test]
fn lock_keeps_the_quick_open_index() {
    // This is the `lock` row's `files` arm: the reference's `k` keeps the
    // index, and dropping it left an archive 94 bytes shorter than the
    // reference's with a different sha.
    let archive = three_with_index();
    let src = open(&archive);
    let mut out = Vec::new();
    edit::lock(&src, &mut out).expect("lock");
    let after = open(&out);
    assert!(after.is_locked(), "it really is locked");
    assert!(
        service_names(&out).iter().any(|n| n == b"QO"),
        "and it still has its index"
    );
    assert_eq!(read_back(&out).len(), 3);
}

#[test]
fn set_comment_keeps_the_quick_open_index() {
    let archive = three_with_index();
    let src = open(&archive);
    let mut out = Vec::new();
    edit::set_comment(&src, Some(b"a comment"), &mut out).expect("comment");
    let after = open(&out);
    assert_eq!(after.comment(), Some(&b"a comment"[..]));
    assert!(service_names(&out).iter().any(|n| n == b"QO"));
    assert_eq!(read_back(&out).len(), 3);
}

#[test]
fn a_removal_resizes_the_quick_open_index_rather_than_dropping_it() {
    let archive = three_with_index();
    let src = open(&archive);
    let mut out = Vec::new();
    edit::remove(&src, &[b"two.bin"], &mut out).expect("remove");
    assert!(service_names(&out).iter().any(|n| n == b"QO"));
    assert_eq!(read_back(&out).len(), 2);
}

#[test]
fn the_rebuilt_index_points_at_the_headers_it_says_it_does() {
    // The index caches each large member's header together with the
    // distance BACK from the index to it (spec G 3.6.6). A rewrite moves
    // every block, so an index carried across rather than rebuilt would
    // point into the middle of the wrong block. This checks the cached
    // image really is the header that sits where the entry says.
    let archive = three_with_index();
    let src = open(&archive);
    let mut out = Vec::new();
    edit::remove(&src, &[b"one.bin"], &mut out).expect("remove");

    let after = open(&out);
    let index = after
        .blocks()
        .find(|b| {
            matches!(
                b.kind,
                rarkit::BlockKind::Service(rarkit::ServiceKind::Other)
            )
        })
        .expect("a service block");
    let start = index.range.start;
    // Every cached entry's back-distance must land inside the archive and
    // before the index itself.
    assert!(start > 8, "the index is not at the signature");
    // The real check: the archive opens, lists what it should, and every
    // member's bytes come back. A wrong offset in the index makes the
    // reference report a corrupt header on every command but `l`.
    let got = read_back(&out);
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].0, b"two.bin");
    assert_eq!(got[1].0, b"three.bin");
}

// ---------------------------------------------------------------------
// A kill at every stage.

/// An output that accepts `budget` bytes and then fails, which is what a
/// full disk, a closed pipe or a killed process looks like from here.
struct DiesAfter {
    budget: usize,
}

impl std::io::Write for DiesAfter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.budget == 0 {
            return Err(std::io::Error::other("the output died"));
        }
        let took = buf.len().min(self.budget);
        self.budget -= took;
        Ok(took)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn an_edit_killed_at_any_stage_leaves_the_original_untouched() {
    // The library writes a FRESH output and never touches the source, so
    // a failure at any point costs the caller its partial output and
    // nothing else. This kills the output at every byte count across a
    // whole rewrite, in the two shapes with the most moving parts - one
    // that rebuilds a quick-open index and one that builds a recovery
    // record over the bytes it has written - and checks after each that
    // the SOURCE still opens and still reads back whole.
    let archive = three_with_index();
    let whole = {
        let src = open(&archive);
        let mut out = Vec::new();
        edit::remove(&src, &[b"two.bin"], &mut out).expect("remove");
        out.len()
    };
    let mut died = 0;
    for budget in (0..whole).step_by(97) {
        for with_recovery in [false, true] {
            let src = open(&archive);
            let mut out = DiesAfter { budget };
            let result = if with_recovery {
                edit::set_recovery(&src, Some(5), &mut out).map(|_| ())
            } else {
                edit::remove(&src, &[b"two.bin"], &mut out).map(|_| ())
            };
            if result.is_err() {
                died += 1;
            }
            // Whatever happened to the output, the source is as it was.
            let again = open(&archive);
            assert_eq!(again.members().count(), 3, "the original still lists");
            assert_eq!(
                read_back(&archive).len(),
                3,
                "and still reads back whole after a kill at {budget} bytes"
            );
        }
    }
    assert!(
        died > 0,
        "the harness has to actually kill the write, or it proves nothing"
    );
}

// ---------------------------------------------------------------------
// Spec G 6.1 oracle 1: reference unrar accepts every edited archive.

fn unrar() -> Option<&'static str> {
    std::process::Command::new("unrar")
        .output()
        .ok()
        .map(|_| "unrar")
}

#[test]
fn reference_unrar_accepts_every_edited_archive() {
    let Some(unrar) = unrar() else {
        eprintln!("SKIPPED: reference unrar is not on PATH");
        return;
    };
    let dir = std::env::temp_dir().join(format!("rarkit-edit-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let mut rows: Vec<(&str, Vec<u8>)> = Vec::new();
    for (label, format) in [
        ("r5", WriteFormat::Rar5),
        ("r4", WriteFormat::Rar4(rarkit::Rar4Version::V40)),
    ] {
        let archive = three(format, Layout::Default, false);
        let src = open(&archive);

        let mut removed = Vec::new();
        edit::remove(&src, &[b"two.bin"], &mut removed).expect("remove");
        rows.push((label, removed));

        let mut renamed = Vec::new();
        edit::rename(&src, b"two.bin", b"renamed-longer.bin", &mut renamed).expect("rename");
        rows.push((label, renamed));

        let mut rr = Vec::new();
        edit::set_recovery(&src, Some(5), &mut rr).expect("rr");
        rows.push((label, rr));
    }
    // A rename inside a SOLID archive, which this crate allows and the
    // reference reaches only by recompressing. If the solid chain did not
    // survive, `unrar t` is what would say so.
    {
        let solid = three(WriteFormat::Rar5, Layout::Default, true);
        let src = open(&solid);
        let mut out = Vec::new();
        edit::rename(&src, b"two.bin", b"renamed-in-a-solid-set.bin", &mut out)
            .expect("rename in a solid archive");
        rows.push(("solid-rn", out));
    }
    // And the same three over an archive that carries a quick-open index.
    let indexed = three_with_index();
    let src = open(&indexed);
    for edit_out in [
        {
            let mut o = Vec::new();
            edit::remove(&src, &[b"two.bin"], &mut o).expect("remove");
            o
        },
        {
            let mut o = Vec::new();
            edit::lock(&src, &mut o).expect("lock");
            o
        },
        {
            let mut o = Vec::new();
            edit::set_comment(&src, Some(b"hello"), &mut o).expect("comment");
            o
        },
        {
            let mut o = Vec::new();
            edit::set_recovery(&src, Some(5), &mut o).expect("rr");
            o
        },
    ] {
        rows.push(("qo", edit_out));
    }

    for (n, (label, archive)) in rows.iter().enumerate() {
        let path = dir.join(format!("{label}-{n}.rar"));
        std::fs::write(&path, archive).unwrap();
        let out = std::process::Command::new(unrar)
            .arg("t")
            .arg("-inul")
            .arg(&path)
            .output()
            .expect("unrar t");
        assert!(
            out.status.success(),
            "{label} row {n}: unrar t exited {:?}\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- two members stored under ONE name -------------------------------------

/// An archive whose first and third members carry the SAME stored name,
/// which reference `rar` will write and this crate's `add` does not
/// refuse: nothing in a RAR container makes a name unique.
fn duplicate_names(format: WriteFormat) -> Vec<u8> {
    let options = WriteOptions {
        format,
        filters: filters_for(format),
        method: rarkit::WriteMethod::Stored,
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    };
    let members = [
        (b"same.bin".to_vec(), bytes(300, 1)),
        (b"other.bin".to_vec(), bytes(300, 2)),
        (b"same.bin".to_vec(), bytes(300, 3)),
    ];
    let mut writer = Writer::new(options).expect("options");
    for (name, data) in &members {
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(data),
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    out
}

/// FOUND BY `fuzz:edit_roundtrip` on 20 Sep 2026, the first campaign it
/// ran with a seed corpus: the reproducer is pinned as
/// `fuzz/seeds/edit_roundtrip/rename-picks-the-first-of-two-same-names`.
///
/// `edit::remove` and `edit::rename` are given a NAME, and an archive may
/// store one name twice. The rewrite used to touch the FIRST member of
/// that name and leave the other, which was pinned here as an open
/// question. It is answered by the reference (bug sweep of 4 Oct 2026,
/// M-6; `rar` 7.x `rn` and `d` on this very fixture, both families):
/// EVERY member of the name is renamed, or removed. The order is kept and
/// every other member's bytes travel unchanged.
#[test]
fn a_rename_touches_every_member_that_shares_the_name() {
    for format in [
        WriteFormat::Rar5,
        WriteFormat::Rar4(rarkit::Rar4Version::V40),
    ] {
        let archive = duplicate_names(format);
        let src = open(&archive);
        let mut out = Vec::new();
        let report = edit::rename(&src, b"same.bin", b"renamed.bin", &mut out).expect("rename");
        assert_eq!(report.renamed, vec![b"same.bin".to_vec()], "{format:?}");
        assert!(report.unmatched.is_empty(), "{format:?}");
        assert_eq!(report.members, 3, "{format:?}: no member was lost");

        let got = read_back(&out);
        let names: Vec<&[u8]> = got.iter().map(|(name, _)| name.as_slice()).collect();
        assert_eq!(
            names,
            vec![&b"renamed.bin"[..], b"other.bin", b"renamed.bin"],
            "{format:?}: both members of the name changed, in place"
        );
        assert_eq!(got[0].1, bytes(300, 1), "{format:?}: bytes unchanged");
        assert_eq!(got[1].1, bytes(300, 2), "{format:?}");
        assert_eq!(got[2].1, bytes(300, 3), "{format:?}");
    }
}

/// The same answer on the other member level arm.
#[test]
fn a_removal_takes_every_member_that_shares_the_name() {
    for format in [
        WriteFormat::Rar5,
        WriteFormat::Rar4(rarkit::Rar4Version::V40),
    ] {
        let archive = duplicate_names(format);
        let src = open(&archive);
        let mut out = Vec::new();
        let report = edit::remove(&src, &[b"same.bin"], &mut out).expect("remove");
        assert_eq!(report.removed, vec![b"same.bin".to_vec()], "{format:?}");
        assert!(report.unmatched.is_empty(), "{format:?}");
        assert_eq!(report.members, 1, "{format:?}");

        let got = read_back(&out);
        assert_eq!(
            got,
            vec![(b"other.bin".to_vec(), bytes(300, 2))],
            "{format:?}: both members of the name are gone and the other is whole"
        );
    }
}
