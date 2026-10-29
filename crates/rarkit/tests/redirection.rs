//! Redirection members: symbolic links, hard links and file copies (spec
//! F 3.2.6.2, 3.3.12 and 3.8.1; SPEC-API question 21).
//!
//! The archives in `tests/redirection/` were written by reference rar 7.23
//! and by genuine Linux rar 4.2.0 (`make.sh`); the rows no Linux writer
//! produces are rewritten from them here (`redirection/rewrite.rs`). The
//! defect these close was found by the reference-rar differential sweep of
//! 27 Sep 2026: every such member came out as an EMPTY file and `t` and
//! `x` exited 0.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use rarkit::{
    extract, Archive, Checksum, Corruption, Disposition, ErrorKind, MemberInfo, MemberOutcome,
    Password, RangeSource, ReadOptions, RedirectionKind, Result, Sink, Unsupported,
};

#[path = "redirection/rewrite.rs"]
mod rewrite;

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/redirection")).join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn volumes(bytes: &[u8]) -> Vec<Arc<dyn RangeSource>> {
    vec![Arc::new(bytes.to_vec()) as Arc<dyn RangeSource>]
}

/// What `open` saw of one member, and how it closed.
#[derive(Clone, Debug, Default, PartialEq)]
struct Seen {
    name: String,
    kind: Option<RedirectionKind>,
    target: Option<Vec<u8>>,
    dir: bool,
    closed: Option<(Option<bool>, u64)>,
    written: Vec<u8>,
}

fn opened(member: &MemberInfo<'_>) -> Seen {
    Seen {
        name: String::from_utf8_lossy(member.name).into_owned(),
        kind: member.redirection.map(|r| r.kind),
        target: member
            .redirection
            .and_then(|r| r.target.map(<[u8]>::to_vec)),
        dir: member.redirection.is_some_and(|r| r.target_is_directory),
        ..Seen::default()
    }
}

/// A sink that verifies every redirection member (as spec F 3.8.1 asks of
/// one that materialises them) and writes every file to memory, or, with
/// `write_all`, answers `Write` for everything: the sink never taught
/// about links.
#[derive(Default)]
struct Probe {
    write_all: bool,
    seen: Vec<Seen>,
}

impl Sink for Probe {
    type Out = Vec<u8>;
    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        self.seen.push(opened(member));
        // The record first: a Windows-written directory link carries the
        // directory flag too.
        if member.redirection.is_some() && !self.write_all {
            return Ok(Disposition::Verify);
        }
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Vec::new()))
    }
    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        let name = String::from_utf8_lossy(member.name);
        let seen = self
            .seen
            .iter_mut()
            .rev()
            .find(|s| s.name == name)
            .expect("closed after its open");
        seen.closed = Some((outcome.checksum_ok, outcome.bytes));
        seen.written = out.unwrap_or_default();
        Ok(())
    }
}

#[cfg(feature = "parallel")]
#[derive(Default)]
struct WideProbe(Mutex<Probe>);

#[cfg(feature = "parallel")]
impl rarkit::ParallelSink for WideProbe {
    type Out = Vec<u8>;
    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        self.0.lock().unwrap().open(member)
    }
    fn close(
        &self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.0.lock().unwrap().close(member, out, outcome)
    }
}

struct Run {
    seen: Vec<Seen>,
    result: Result<rarkit::ExtractReport>,
}

/// Every entry point a caller can take: the sequential one at width 1 (the
/// walk alone) and at width 4 (the decode-ahead driver), and the parallel
/// one.
fn every_path(bytes: &[u8], password: Option<&str>) -> Vec<(&'static str, Run)> {
    let options = |width| {
        ReadOptions::default()
            .with_workers(Some(width))
            .with_password(password.map(Password::from))
    };
    let mut runs = Vec::new();
    for (label, width) in [("sequential w1", 1), ("sequential w4", 4)] {
        let mut probe = Probe::default();
        let result = extract(volumes(bytes), &options(width), &mut probe, &mut ());
        runs.push((
            label,
            Run {
                seen: probe.seen,
                result,
            },
        ));
    }
    #[cfg(feature = "parallel")]
    {
        let wide = WideProbe::default();
        let result = rarkit::extract_parallel(volumes(bytes), &options(4), &wide, 4);
        let seen = wide.0.into_inner().unwrap().seen;
        runs.push(("parallel", Run { seen, result }));
    }
    runs
}

fn member<'a>(run: &'a Run, name: &str) -> &'a Seen {
    run.seen
        .iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("{name} was never opened: {:?}", run.seen))
}

fn listing(bytes: &[u8]) -> Vec<(String, Option<rarkit::Redirection<'static>>, MemberSummary)> {
    let archive = Archive::open(Arc::new(bytes.to_vec()), &ReadOptions::default()).expect("opens");
    archive
        .members()
        .map(|m| {
            let redirection = m.redirection.map(|r| rarkit::Redirection {
                kind: r.kind,
                target: r.target.map(|t| &*Box::leak(t.to_vec().into_boxed_slice())),
                target_is_directory: r.target_is_directory,
            });
            (
                m.name_lossy().into_owned(),
                redirection,
                MemberSummary {
                    is_directory: m.is_directory,
                    unpacked_size: m.unpacked_size,
                    packed_size: m.packed_size,
                    checksum: m.checksum,
                },
            )
        })
        .collect()
}

#[derive(Debug, PartialEq)]
struct MemberSummary {
    is_directory: bool,
    unpacked_size: Option<u64>,
    packed_size: u64,
    checksum: Option<Checksum>,
}

fn listed<'a>(
    list: &'a [(String, Option<rarkit::Redirection<'static>>, MemberSummary)],
    name: &str,
) -> &'a (String, Option<rarkit::Redirection<'static>>, MemberSummary) {
    list.iter()
        .find(|m| m.0 == name)
        .unwrap_or_else(|| panic!("{name} not listed"))
}

/// Spec F 3.2.6.2's table of header fields around the record, and API 4.3:
/// the kind, the directory flag and the target reach a listing; the other
/// fields mean what the header says.
#[test]
fn a_listing_carries_the_kind_the_flag_and_the_target() {
    let list = listing(&fixture("links5.rar"));
    let rel = listed(&list, "sym_rel");
    let r = rel.1.expect("sym_rel is a redirection");
    assert_eq!(r.kind, RedirectionKind::PosixSymlink);
    assert_eq!(r.target, Some(&b"a.txt"[..]));
    assert!(!r.target_is_directory);
    assert_eq!(
        rel.2,
        MemberSummary {
            is_directory: false,
            unpacked_size: Some(0),
            packed_size: 0,
            checksum: Some(Checksum::Crc32(0)),
        }
    );
    // A link to a directory is flagged, and is not a directory.
    let dir = listed(&list, "sym_dir");
    assert!(dir.1.unwrap().target_is_directory);
    assert!(!dir.2.is_directory);
    assert_eq!(
        listed(&list, "sym_abs").1.unwrap().target,
        Some(&b"/etc/hostname"[..])
    );
    // A hard link declares its TARGET's size, with nothing packed, and
    // the empty string's CRC32.
    let hard = listed(&list, "hard_a");
    assert_eq!(hard.1.unwrap().kind, RedirectionKind::HardLink);
    assert_eq!(hard.1.unwrap().target, Some(&b"a.txt"[..]));
    assert_eq!(hard.2.unpacked_size, Some(10));
    assert_eq!(hard.2.packed_size, 0);
    assert_eq!(hard.2.checksum, Some(Checksum::Crc32(0)));
    assert!(listed(&list, "a.txt").1.is_none());

    let list = listing(&fixture("copies5.rar"));
    let copy = listed(&list, "e/big3");
    assert_eq!(copy.1.unwrap().kind, RedirectionKind::FileCopy);
    // Relative to the ARCHIVE ROOT, not to the directory holding it.
    assert_eq!(copy.1.unwrap().target, Some(&b"big1"[..]));
    assert_eq!(copy.2.unpacked_size, Some(300_000));
    assert!(listed(&list, "big1").1.is_none());
}

/// Spec F 3.3.12: the older family's link is known from its host and mode,
/// and its target is its content, which a listing does not read.
#[test]
fn a_rar4_link_lists_its_kind_and_no_target() {
    let list = listing(&fixture("links4.rar"));
    let rel = listed(&list, "sym_rel");
    let r = rel.1.expect("sym_rel is a link");
    assert_eq!(r.kind, RedirectionKind::PosixSymlink);
    assert_eq!(r.target, None);
    assert!(!r.target_is_directory);
    assert_eq!(rel.2.unpacked_size, Some(5));
    assert!(listed(&list, "sym_dir").1.is_some());
    assert!(listed(&list, "a.txt").1.is_none());
    assert!(listed(&list, "d").1.is_none());
}

/// Spec F 3.8.1 on every entry point: a redirection member reaches `open`
/// WITH its target, is verified as zero bytes against its stored checksum,
/// closes with `bytes: 0`, and adds nothing to the report's bytes.
#[test]
fn every_member_of_every_archive_verifies_and_delivers_nothing() {
    for (archive, password, files) in [
        ("links5.rar", None, 4 + 10),
        ("copies5.rar", None, 300_000 + 6),
        ("solid5.rar", None, 71_582 + 62_163),
        ("blake5.rar", None, 3_000),
        ("crypt5.rar", Some("redir"), 12),
        ("links4.rar", None, 10),
    ] {
        for (label, run) in every_path(&fixture(archive), password) {
            let report = run
                .result
                .as_ref()
                .unwrap_or_else(|e| panic!("{archive} {label}: {e}"));
            assert_eq!(report.bytes, files, "{archive} {label}: bytes");
            assert_eq!(report.checksum_failures, 0, "{archive} {label}");
            for seen in &run.seen {
                if seen.kind.is_none() {
                    continue;
                }
                assert!(
                    seen.target.as_deref().is_some_and(|t| !t.is_empty()),
                    "{archive} {label}: {} opened without its target",
                    seen.name
                );
                assert_eq!(
                    seen.closed,
                    Some((Some(true), 0)),
                    "{archive} {label}: {}",
                    seen.name
                );
            }
        }
    }
}

/// The targets `open` is handed: RAR 5's from the header, the RAR 4
/// family's decoded from the content and checked first (3.3.12).
#[test]
fn open_hands_over_each_target() {
    for (label, run) in every_path(&fixture("links4.rar"), None) {
        for (name, target) in [
            ("sym_rel", "a.txt"),
            ("sym_dir", "d"),
            ("sym_abs", "/etc/hostname"),
            ("sym_up", "../../escape"),
        ] {
            let seen = member(&run, name);
            assert_eq!(
                seen.kind,
                Some(RedirectionKind::PosixSymlink),
                "{label} {name}"
            );
            assert_eq!(
                seen.target.as_deref(),
                Some(target.as_bytes()),
                "{label} {name}"
            );
        }
        assert_eq!(member(&run, "a.txt").written, b"a-content\n", "{label}");
    }
    for (label, run) in every_path(&fixture("solid5.rar"), None) {
        assert_eq!(
            member(&run, "a_link").target.as_deref(),
            Some(&b"f1.txt"[..]),
            "{label}"
        );
        assert_eq!(
            member(&run, "h2.txt").kind,
            Some(RedirectionKind::HardLink),
            "{label}"
        );
        assert_eq!(
            member(&run, "f3.txt").kind,
            Some(RedirectionKind::FileCopy),
            "{label}"
        );
        assert_eq!(
            member(&run, "f3.txt").target.as_deref(),
            Some(&b"f1.txt"[..]),
            "{label}"
        );
    }
}

/// SPEC-API 4.4 and question 21 (b): a sink that answers `Write` for a
/// redirection member gets NOTHING written and the operation fails naming
/// the member. The structural half of the fix: no sink can turn a link
/// into an empty file again.
#[test]
fn a_write_for_a_redirection_member_is_refused_by_name() {
    let bytes = fixture("links5.rar");
    let options = |width| ReadOptions::default().with_workers(Some(width));
    for width in [1, 4] {
        let mut probe = Probe {
            write_all: true,
            ..Probe::default()
        };
        let err = extract(volumes(&bytes), &options(width), &mut probe, &mut ())
            .expect_err("a Write for a link is refused");
        assert!(
            matches!(
                err.kind(),
                ErrorKind::Unsupported(Unsupported::Redirection(RedirectionKind::PosixSymlink))
            ),
            "width {width}: {err}"
        );
        // The first redirection member in archive order.
        assert_eq!(err.member(), Some(&b"junc_rel"[..]), "width {width}");
        assert!(probe
            .seen
            .iter()
            .all(|s| s.kind.is_none() || s.written.is_empty()));
    }
    #[cfg(feature = "parallel")]
    {
        let wide = WideProbe(Mutex::new(Probe {
            write_all: true,
            ..Probe::default()
        }));
        let err = rarkit::extract_parallel(volumes(&bytes), &options(4), &wide, 4)
            .expect_err("a Write for a link is refused");
        assert!(matches!(
            err.kind(),
            ErrorKind::Unsupported(Unsupported::Redirection(_))
        ));
    }
}

/// Spec F 3.2.6.2: with `-p`, a redirection member needs the password as
/// any encrypted member does, although its target is in the clear.
#[test]
fn an_encrypted_redirection_member_needs_the_password() {
    for (label, run) in every_path(&fixture("crypt5.rar"), None) {
        assert!(run.result.is_err(), "{label}");
        for name in ["p_link", "p_hard"] {
            let closed = run
                .seen
                .iter()
                .find(|s| s.name == name)
                .and_then(|s| s.closed);
            assert!(
                closed.is_none_or(|(ok, _)| ok != Some(true)),
                "{label}: {name} verified without a password"
            );
        }
    }
    // And a wrong one fails the check rather than passing it.
    for (label, run) in every_path(&fixture("crypt5.rar"), Some("wrong")) {
        assert!(
            run.result.is_err()
                || run
                    .seen
                    .iter()
                    .all(|s| s.closed.is_none_or(|c| c.0 != Some(true))),
            "{label}"
        );
    }
}

/// The rewritten rows of spec F 3.2.6.2's last table, on every path.
fn rewritten(body: Vec<u8>) -> Vec<u8> {
    rewrite::with_redirect(&fixture("links5.rar"), "sym_rel", body)
}

/// An unknown type, and type 0, are CARRIED, not refused (question 21 (c)):
/// the caller declines them by name (3.8.6).
#[test]
fn an_unknown_type_reaches_open_as_unknown() {
    for (code, kind) in [
        (9, RedirectionKind::Unknown(9)),
        (0, RedirectionKind::Unknown(0)),
    ] {
        let bytes = rewritten(rewrite::redirect(code, 0, b"a.txt"));
        assert_eq!(listed(&listing(&bytes), "sym_rel").1.unwrap().kind, kind);
        for (label, run) in every_path(&bytes, None) {
            assert!(run.result.is_ok(), "{label}: {:?}", run.result.err());
            let seen = member(&run, "sym_rel");
            assert_eq!(seen.kind, Some(kind), "{label}");
            assert_eq!(seen.target.as_deref(), Some(&b"a.txt"[..]), "{label}");
        }
    }
    assert_eq!(
        RedirectionKind::Unknown(9).listing_name(),
        "unknown redirection 9"
    );
    assert_eq!(RedirectionKind::FileCopy.listing_name(), "File reference");
}

/// Records the engine cannot use: `Corrupt(Redirection)` for that member,
/// reported through its own close, and the members around it extracted.
#[test]
fn a_record_the_engine_cannot_use_is_corrupt_for_that_member() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        // A target of length 0, with the old target left behind it.
        ("an empty target", {
            let mut body = rewrite::redirect(1, 0, b"");
            body.extend_from_slice(b"a.txt");
            body
        }),
        // A target length running past the record.
        ("a target past the record", {
            let mut body = rewrite::redirect(1, 0, b"a.txt");
            body[2] = 0x40;
            body
        }),
        ("a NUL in the target", rewrite::redirect(1, 0, b"a\0txt")),
    ];
    for (row, body) in cases {
        let bytes = rewritten(body);
        for (label, run) in every_path(&bytes, None) {
            let err = run.result.as_ref().expect_err(row);
            assert!(
                matches!(err.kind(), ErrorKind::Corrupt(Corruption::Redirection)),
                "{row} {label}: {err}"
            );
            assert_eq!(err.member(), Some(&b"sym_rel"[..]), "{row} {label}");
            assert_eq!(
                member(&run, "sym_rel").closed,
                Some((Some(false), 0)),
                "{row} {label}"
            );
            // The walk went on past it.
            assert_eq!(
                member(&run, "dotslash").closed,
                Some((Some(true), 0)),
                "{row} {label}"
            );
        }
    }
}

/// Spec F 3.8.5: a copy naming ITSELF is refused, never an empty file.
#[test]
fn a_copy_naming_itself_is_corrupt() {
    let bytes = rewrite::with_redirect(
        &fixture("copies5.rar"),
        "big2",
        rewrite::redirect(5, 0, b"big2"),
    );
    for (label, run) in every_path(&bytes, None) {
        let err = run.result.as_ref().expect_err("a self copy");
        assert!(
            matches!(err.kind(), ErrorKind::Corrupt(Corruption::Redirection)),
            "{label}"
        );
        assert_eq!(
            member(&run, "big2").closed,
            Some((Some(false), 0)),
            "{label}"
        );
        assert_eq!(
            member(&run, "e/big3").closed,
            Some((Some(true), 0)),
            "{label}"
        );
    }
}

/// The accepted oddities: bytes after the target are ignored, so are flag
/// bits other than 0x0001, and of two records the LAST decides.
#[test]
fn trailing_bytes_unknown_flags_and_the_last_record_win() {
    let mut body = rewrite::redirect(1, 0, b"a.t");
    body.extend_from_slice(b"xt");
    let run = &every_path(&rewritten(body), None)[0].1;
    assert_eq!(member(run, "sym_rel").target.as_deref(), Some(&b"a.t"[..]));
    assert_eq!(member(run, "sym_rel").closed, Some((Some(true), 0)));

    let run = &every_path(&rewritten(rewrite::redirect(1, 0x06, b"a.txt")), None)[0].1;
    assert!(!member(run, "sym_rel").dir);
    assert_eq!(member(run, "sym_rel").closed, Some((Some(true), 0)));
    let run = &every_path(&rewritten(rewrite::redirect(1, 0x07, b"a.txt")), None)[0].1;
    assert!(member(run, "sym_rel").dir);

    let bytes = rewrite::rewrite(&fixture("links5.rar"), "sym_rel", |mut records| {
        records.push((5, rewrite::redirect(4, 0, b"top.txt")));
        records
    });
    let run = &every_path(&bytes, None)[0].1;
    assert_eq!(member(run, "sym_rel").kind, Some(RedirectionKind::HardLink));
    assert_eq!(
        member(run, "sym_rel").target.as_deref(),
        Some(&b"top.txt"[..])
    );
}

/// A record on a member WITH a data area: the record decides what the
/// member is, the data is skipped unread, and zero bytes against the
/// stored CRC32 of four fail the check (the reference: "checksum error").
#[test]
fn a_record_on_a_data_bearing_member_fails_its_checksum() {
    let bytes = rewrite::rewrite(&fixture("links5.rar"), "top.txt", |mut records| {
        records.push((5, rewrite::redirect(1, 0, b"a.txt")));
        records
    });
    for (label, run) in every_path(&bytes, None) {
        let seen = member(&run, "top.txt");
        assert_eq!(seen.kind, Some(RedirectionKind::PosixSymlink), "{label}");
        assert_eq!(seen.closed, Some((Some(false), 0)), "{label}");
        assert!(seen.written.is_empty(), "{label}");
        assert_eq!(member(&run, "a.txt").written, b"a-content\n", "{label}");
    }
}

/// Types 2 and 3, rewritten by hand (no Windows writer here): carried as
/// stored, the Windows form untouched by the engine (3.8.7 is the
/// extractor's).
#[test]
fn windows_links_and_junctions_are_carried_as_stored() {
    let bytes = rewrite::with_redirect(
        &fixture("links5.rar"),
        "win_abs",
        rewrite::redirect(2, 0, b"C:\\x\\a.txt"),
    );
    let bytes = rewrite::with_redirect(&bytes, "junc_abs", rewrite::redirect(3, 1, b"\\??\\C:\\x"));
    let list = listing(&bytes);
    let win = listed(&list, "win_abs").1.unwrap();
    assert_eq!(win.kind, RedirectionKind::NtSymlink);
    assert_eq!(win.target, Some(&b"C:\\x\\a.txt"[..]));
    let junction = listed(&list, "junc_abs").1.unwrap();
    assert_eq!(junction.kind, RedirectionKind::NtJunction);
    assert!(junction.target_is_directory);
    assert_eq!(junction.kind.listing_name(), "NTFS junction point");
    for (label, run) in every_path(&bytes, None) {
        assert!(run.result.is_ok(), "{label}");
        assert_eq!(
            member(&run, "junc_abs").closed,
            Some((Some(true), 0)),
            "{label}"
        );
    }
}

/// MEASURED on Rar.exe 7.23 for Windows (a Windows desktop, 27 Sep 2026): the
/// genuine writer stores a Windows target with FORWARD slashes (`../a.txt`,
/// `/??/C:/...`), and sets the file header's directory flag on a directory
/// link and a junction. Such a member is still a redirection, reported with
/// the header's own `is_directory`.
#[test]
fn a_windows_written_directory_link_keeps_its_record() {
    let bytes = rewrite::rewrite_with_flags(&fixture("links5.rar"), "junc_rel", 1, |records| {
        records
            .into_iter()
            .map(|(kind, body)| {
                if kind == 5 {
                    (5, rewrite::redirect(3, 1, b"/??/C:/x"))
                } else {
                    (kind, body)
                }
            })
            .collect()
    });
    let list = listing(&bytes);
    let junction = listed(&list, "junc_rel");
    assert!(junction.2.is_directory);
    assert_eq!(junction.1.unwrap().kind, RedirectionKind::NtJunction);
    assert_eq!(junction.1.unwrap().target, Some(&b"/??/C:/x"[..]));
    for (label, run) in every_path(&bytes, None) {
        assert!(run.result.is_ok(), "{label}");
        let seen = member(&run, "junc_rel");
        assert_eq!(seen.kind, Some(RedirectionKind::NtJunction), "{label}");
        assert_eq!(seen.closed, Some((Some(true), 0)), "{label}");
    }
}
