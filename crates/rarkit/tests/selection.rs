//! Walking past members a selection excludes, and reporting every member
//! that failed rather than the first.
//!
//! Spec F 3.6 and 3.7.1: `Disposition::Skip` on a NON-solid member never
//! reads its packed bytes, and a solid member is decoded and discarded
//! because the next member's dictionary is the result. Nothing in an
//! extraction's output can tell those apart, so the assertions here read
//! `rarkit::probe`, which counts the members whose bytes were run through a
//! codec.
//!
//! Spec F section 8: an extraction error is never a silent success, and a
//! failure on one member never cancels the members after it in a non-solid
//! archive. Reference `unrar t` on a three-member encrypted archive with
//! the wrong password names all three and exits 11.

use std::path::PathBuf;
use std::sync::Arc;

use rarkit::{
    extract, Disposition, ErrorKind, MemberInfo, MemberOutcome, Payload, RangeSource, ReadOptions,
    Result, Sink, Writer,
};

fn legacy(name: &str) -> Vec<u8> {
    let path = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/legacy/archives"
    ))
    .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn sources(bytes: Vec<u8>) -> Vec<Arc<dyn RangeSource>> {
    vec![Arc::new(bytes) as Arc<dyn RangeSource>]
}

/// A sink that writes the members whose names `wanted` names and SKIPS
/// every other, which is what a `rarfast x archive one-name` selection is.
struct Selected {
    wanted: Vec<Vec<u8>>,
    got: Vec<(Vec<u8>, Vec<u8>)>,
    closed: Vec<(Vec<u8>, Option<bool>)>,
}

impl Selected {
    fn new(wanted: &[&str]) -> Selected {
        Selected {
            wanted: wanted.iter().map(|n| n.as_bytes().to_vec()).collect(),
            got: Vec::new(),
            closed: Vec::new(),
        }
    }

    /// Every member, which is the control the selection is compared to.
    fn all() -> Selected {
        Selected {
            wanted: Vec::new(),
            got: Vec::new(),
            closed: Vec::new(),
        }
    }

    fn takes(&self, member: &MemberInfo<'_>) -> bool {
        !member.is_directory
            && (self.wanted.is_empty() || self.wanted.iter().any(|n| n == member.name))
    }
}

impl Sink for Selected {
    type Out = Vec<u8>;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        if self.takes(member) {
            Ok(Disposition::Write(Vec::new()))
        } else {
            Ok(Disposition::Skip)
        }
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.closed
            .push((member.name.to_vec(), outcome.checksum_ok));
        if let Some(bytes) = out {
            self.got.push((member.name.to_vec(), bytes));
        }
        Ok(())
    }
}

/// Spec F 3.6 and 3.7.1: a non-solid member a sink skips is never decoded
/// and its packed bytes are never read.
///
/// `r420_m5.rar` is genuine rar 4.2.0 output: four compressed members at
/// unpack version 29 and two directory entries, not solid. Selecting one of
/// the four must run one decode, not four.
#[test]
fn no_decoder_runs_for_a_skipped_non_solid_member() {
    let archive = legacy("r420_m5.rar");

    let mut all = Selected::all();
    rarkit::probe::reset();
    extract(
        sources(archive.clone()),
        &ReadOptions::default(),
        &mut all,
        &mut (),
    )
    .expect("the whole archive");
    let whole = rarkit::probe::decoded_members();
    assert!(
        all.got.len() >= 4,
        "the control extracted {} members",
        all.got.len()
    );

    let mut one = Selected::new(&["DATA.BIN"]);
    rarkit::probe::reset();
    let report =
        extract(sources(archive), &ReadOptions::default(), &mut one, &mut ()).expect("one member");
    let selected = rarkit::probe::decoded_members();

    assert_eq!(one.got.len(), 1, "one member was written");
    assert_eq!(
        selected, 1,
        "selecting one member of a non-solid archive decoded {selected} members, \
         where the whole archive costs {whole}"
    );
    assert!(whole > selected, "the control decoded {whole}");
    let wanted = all
        .got
        .iter()
        .find(|(name, _)| name == b"DATA.BIN")
        .expect("the control has it");
    assert_eq!(
        one.got[0].1, wanted.1,
        "the selected member's bytes are the ones a whole extraction gives"
    );
    // Only the member opened with `Write` is closed (SPEC-API 4.4: `close`
    // is for a member opened with `Write` or `Verify`; until 30 Sep 2026
    // every skipped member was closed too). The REPORT still counts every
    // member, so a caller that ignores `close` cannot read "everything is
    // fine" from a run in which nothing was written (spec F section 8).
    assert_eq!(one.closed.len(), 1, "closed: {} members", one.closed.len());
    assert!(report.members >= all.got.len() as u64, "{}", report.members);
}

/// Spec F 3.6: skipping is NOT free in a solid archive. A skipped solid
/// member is still decoded, because the next member's dictionary is the
/// result, and the selected member's bytes come out right.
///
/// `r420_solid.rar` is genuine rar 4.2.0 output with the archive solid flag
/// and the per-member bit on every member after the first.
#[test]
fn a_solid_chain_is_decoded_so_the_selected_member_is_right() {
    let archive = legacy("r420_solid.rar");

    let mut all = Selected::all();
    extract(
        sources(archive.clone()),
        &ReadOptions::default(),
        &mut all,
        &mut (),
    )
    .expect("the whole archive");
    let last = all.got.last().expect("members").clone();
    let name = String::from_utf8_lossy(&last.0).into_owned();

    let mut one = Selected::new(&[name.as_str()]);
    rarkit::probe::reset();
    extract(sources(archive), &ReadOptions::default(), &mut one, &mut ()).expect("one member");
    let decoded = rarkit::probe::decoded_members();

    assert_eq!(one.got.len(), 1, "one member was written");
    assert_eq!(
        one.got[0].1, last.1,
        "{name}: the selected member's bytes are the ones a whole extraction gives"
    );
    assert!(
        decoded > 1,
        "the chain in front of {name} was not decoded ({decoded} members), so the \
         bytes above can only have been right by accident"
    );
    assert_eq!(
        one.closed
            .iter()
            .find(|(n, _)| *n == last.0)
            .map(|(_, ok)| *ok),
        Some(Some(true)),
        "{name}: the selected member passed its own checksum"
    );
}

/// Spec F section 8 and API 4.4: a wrong password is one member's failure,
/// not the operation's. Every member is reported through its own `close`
/// before extraction moves on, which is what lets a caller name all of them
/// the way reference `unrar t` does (three `Incorrect password` lines and
/// exit 11 on a three-member archive).
#[test]
fn a_wrong_password_reports_every_member_not_the_first() {
    let names: [&[u8]; 3] = [b"one.txt", b"two.txt", b"three.txt"];
    let mut writer = Writer::new(rarkit::WriteOptions {
        password: Some(rarkit::Password::from("Secret")),
        entropy: rarkit::Entropy::Seeded([9; 32]),
        ..rarkit::WriteOptions::default()
    })
    .expect("options");
    let bodies: Vec<Vec<u8>> = (0..3).map(|i| vec![b'a' + i as u8; 4096]).collect();
    for (name, body) in names.iter().zip(&bodies) {
        writer
            .add(rarkit::MemberSpec {
                name,
                payload: Payload::Bytes(body),
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut archive = Vec::new();
    writer.finish_into(&mut archive).expect("finish");

    // The right password reads all three back.
    let mut good = Selected::all();
    extract(
        sources(archive.clone()),
        &ReadOptions::default().with_password(Some(rarkit::Password::from("Secret"))),
        &mut good,
        &mut (),
    )
    .expect("the right password");
    assert_eq!(good.got.len(), 3);

    let mut bad = Selected::all();
    let outcome = extract(
        sources(archive),
        &ReadOptions::default().with_password(Some(rarkit::Password::from("Wrong"))),
        &mut bad,
        &mut (),
    );
    let err = outcome.expect_err("a wrong password is an error for the run");
    assert!(
        matches!(err.kind(), ErrorKind::WrongPassword),
        "the run's error names the password: {err}"
    );
    assert_eq!(
        bad.closed.len(),
        3,
        "every member was reported through its own close, not just the first: {:?}",
        bad.closed
    );
    for (name, ok) in &bad.closed {
        assert_eq!(
            *ok,
            Some(false),
            "{}: reported as a failure",
            String::from_utf8_lossy(name)
        );
    }
}
