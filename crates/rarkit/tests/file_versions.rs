//! Spec F 3.2.6.4, 3.3.6 and question 15: a member that is an OLDER
//! VERSION of a file (RAR 5 extra record type 4 with a number of 1 or
//! more; the older container's file flag 0x0800) is listed with its
//! version, is not selected by `extract` unless the caller asks for
//! versions, and is then named `name;n`.
//!
//! The archives are the specification's own: `ver.rar` is what rar 7.23
//! wrote for the same file added three times with `-ver`, and the arms are
//! the probe's, each beside the reference's recorded answer.

use std::sync::{Arc, Mutex};

use rarkit::{
    extract, extract_parallel, Archive, Disposition, FileVersion, MemberInfo, MemberOutcome,
    ParallelSink, RangeSource, ReadOptions, Sink,
};

fn evidence(path: &str) -> Vec<u8> {
    let path = format!(
        "{}/../../specs/vectors-F/evidence-06oct/{path}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// One member the sink was shown: its name as an extractor writes it, and
/// its bytes.
type Shown = (String, Vec<u8>);

#[derive(Default)]
struct Keep(Vec<Shown>);

fn shown_name(member: &MemberInfo<'_>) -> String {
    String::from_utf8_lossy(&member.versioned_name()).into_owned()
}

impl Sink for Keep {
    type Out = Vec<u8>;

    fn open(&mut self, _: &MemberInfo<'_>) -> rarkit::Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> rarkit::Result<()> {
        assert_eq!(outcome.checksum_ok, Some(true), "{}", shown_name(member));
        self.0.push((shown_name(member), out.unwrap_or_default()));
        Ok(())
    }
}

#[derive(Default)]
struct KeepParallel(Mutex<Vec<Shown>>);

impl ParallelSink for KeepParallel {
    type Out = Vec<u8>;

    fn open(&self, _: &MemberInfo<'_>) -> rarkit::Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> rarkit::Result<()> {
        assert_eq!(outcome.checksum_ok, Some(true), "{}", shown_name(member));
        let mut seen = self.0.lock().unwrap();
        seen.push((shown_name(member), out.unwrap_or_default()));
        Ok(())
    }
}

/// What both drivers hand a sink, which must be the same, in archive
/// order. The pooled driver runs four workers.
fn extracted(archive: &[u8], versions: bool) -> Vec<Shown> {
    let sources = || vec![Arc::new(archive.to_vec()) as Arc<dyn RangeSource>];
    let opts = ReadOptions::default().with_versions(versions);
    let mut sink = Keep::default();
    extract(sources(), &opts, &mut sink, &mut ()).expect("extract");
    let pooled = KeepParallel::default();
    extract_parallel(sources(), &opts, &pooled, 4).expect("extract_parallel");
    assert_eq!(sink.0, pooled.0.into_inner().unwrap(), "the drivers differ");
    sink.0
}

fn listed(archive: &[u8]) -> Vec<(String, Option<FileVersion>)> {
    let src: Arc<dyn RangeSource> = Arc::new(archive.to_vec());
    let archive = Archive::open(src, &ReadOptions::default()).expect("open");
    archive
        .members()
        .map(|m| (shown_name(&m), m.file_version))
        .collect()
}

fn names(shown: &[Shown]) -> Vec<&str> {
    shown.iter().map(|(name, _)| name.as_str()).collect()
}

/// What genuine rar writes under `-ver`: three headers named `v.txt`,
/// oldest first, the first two carrying versions 1 and 2. By default the
/// one current file is extracted, holding the THIRD content, and nothing
/// else lands on its name.
#[test]
fn a_genuine_versions_archive_extracts_the_current_file_only() {
    let archive = evidence("rar5-genuine/ver.rar");
    assert_eq!(
        listed(&archive),
        [
            ("v.txt;1".to_string(), Some(FileVersion::Numbered(1))),
            ("v.txt;2".to_string(), Some(FileVersion::Numbered(2))),
            ("v.txt".to_string(), None),
        ]
    );
    let current = extracted(&archive, false);
    assert_eq!(names(&current), ["v.txt"]);
    assert!(current[0].1.starts_with(b"version 3"), "{:?}", current[0]);

    let all = extracted(&archive, true);
    assert_eq!(names(&all), ["v.txt;1", "v.txt;2", "v.txt"]);
    for (i, (name, data)) in all.iter().enumerate() {
        let want = format!("version {}", i + 1);
        assert!(data.starts_with(want.as_bytes()), "{name}");
    }
}

/// The probe's RAR 5 arms, each as the reference answered it: a version
/// record passes the member over (`record-version`, and with a current
/// file of the same name, `record-version-same-name`); a number of 0 is
/// no version (`record-version-0`).
#[test]
fn rar5_version_records_follow_the_reference() {
    let arm = evidence("rar5-container/record-version/x.rar");
    assert_eq!(
        listed(&arm),
        [
            ("a.txt".to_string(), None),
            ("b.txt;3".to_string(), Some(FileVersion::Numbered(3))),
            ("c.txt".to_string(), None),
        ]
    );
    assert_eq!(names(&extracted(&arm, false)), ["a.txt", "c.txt"]);
    assert_eq!(names(&extracted(&arm, true)), ["a.txt", "b.txt;3", "c.txt"]);

    let same = evidence("rar5-container/record-version-same-name/x.rar");
    assert_eq!(names(&extracted(&same, false)), ["a.txt", "b.txt", "c.txt"]);
    assert_eq!(
        names(&extracted(&same, true)),
        ["a.txt", "b.txt;1", "b.txt", "c.txt"]
    );

    let zero = evidence("rar5-container/record-version-0/x.rar");
    assert!(listed(&zero).iter().all(|(_, version)| version.is_none()));
    assert_eq!(names(&extracted(&zero, false)), ["a.txt", "b.txt", "c.txt"]);
}

/// The older container: file flag 0x0800 marks the version, and whatever
/// number there is sits in the stored name, so the name is shown as
/// stored (`flag-version`, `flag-version-plain-name`).
#[test]
fn the_older_containers_version_flag_follows_the_reference() {
    for (arm, stored) in [
        ("flag-version", "b.txt;3"),
        ("flag-version-plain-name", "b.txt"),
    ] {
        let archive = evidence(&format!("old-container/{arm}/x.rar"));
        assert_eq!(
            listed(&archive),
            [
                ("a.txt".to_string(), None),
                (stored.to_string(), Some(FileVersion::InName)),
                ("c.txt".to_string(), None),
            ],
            "{arm}"
        );
        assert_eq!(
            names(&extracted(&archive, false)),
            ["a.txt", "c.txt"],
            "{arm}"
        );
        assert_eq!(
            names(&extracted(&archive, true)),
            ["a.txt", stored, "c.txt"],
            "{arm}"
        );
    }
}

/// A SOLID archive of versions (`tests/file_versions/README.md` has its
/// recipe): every member but the first continues the chain, so the two
/// current files decode right only if the four versions before them were
/// decoded, and discarded, on the way. The reference tests two members.
#[test]
fn a_solid_chain_runs_through_the_versions_passed_over() {
    let archive = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/file_versions/solid-ver.rar"
    ))
    .expect("the committed archive");
    let current = extracted(&archive, false);
    assert_eq!(names(&current), ["v.txt", "w.txt"]);
    assert!(current[0].1.starts_with(b"solid version 3 of the file"));
    assert!(current[1].1.starts_with(b"another member another member"));

    let all = extracted(&archive, true);
    assert_eq!(
        names(&all),
        ["v.txt;1", "w.txt;1", "v.txt;2", "w.txt;2", "v.txt", "w.txt"]
    );
    assert!(all[0].1.starts_with(b"solid version 1 of the file"));
    assert!(all[2].1.starts_with(b"solid version 2 of the file"));
    assert_eq!(all[4], current[0]);
    assert_eq!(all[5], current[1]);
}

/// A version record that does not hold its two fields states no
/// version, and the header is read: the member is a current file.
///
/// Until 9 Oct 2026 the header was refused and the archive with it
/// (`Corrupt`, the rule for input no genuine writer produces). Measured
/// that day with unrar 7.23 on the very bytes this test makes: `t` says
/// `OK` for `a.txt`, `b.txt` and `c.txt`, `All OK`, exit 0, and `lb`
/// lists the three names (SWEEP3-08OCT-14 measured the same on a genuine
/// archive). The member's own bytes and checksum are untouched, so it is
/// delivered good.
#[test]
fn a_version_record_without_its_number_states_no_version() {
    let mut archive = evidence("rar5-container/record-version/x.rar");
    // The record is `03 04 00 03`: size 3, type 4, flags 0, version 3.
    // Shorten it to `01 04` and pad the extra area with the two bytes of
    // a size 1 record of an unknown type, then stamp the header again.
    let at = archive
        .windows(4)
        .position(|w| w == [3, 4, 0, 3])
        .expect("the version record");
    archive[at..at + 4].copy_from_slice(&[1, 4, 1, 99]);
    // Walk the blocks to the header that holds the record. Every size in
    // this archive is under 128, so each vint is one byte.
    let mut block = 8;
    let (start, end) = loop {
        let size = archive[block + 4] as usize;
        let end = block + 5 + size;
        if at < end {
            break (block, end);
        }
        let flags = archive[block + 6];
        let after_extra = block + 7 + usize::from(flags & 1);
        let data = if flags & 2 != 0 {
            archive[after_extra] as usize
        } else {
            0
        };
        block = end + data;
    };
    let crc = rarkit::checksum::crc32(&archive[start + 4..end]);
    archive[start..start + 4].copy_from_slice(&crc.to_le_bytes());
    assert_eq!(
        listed(&archive),
        [
            ("a.txt".to_string(), None),
            ("b.txt".to_string(), None),
            ("c.txt".to_string(), None),
        ]
    );
    assert_eq!(
        names(&extracted(&archive, false)),
        ["a.txt", "b.txt", "c.txt"]
    );
}
