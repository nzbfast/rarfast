//! Spec F 3.2.8: the quick open offset of a RAR 5 main header's locator,
//! where it is counted from and what a reader that reads through damage
//! ([`ReadOptions::read_damaged`]) says of one that is wrong.
//!
//! The archives are the ones the section's probe kept under
//! `specs/vectors-F/locator-offset/`: four bases a genuine rar 7.23 wrote
//! with a quick open record (clear headers and `-hpSecret`, one file and a
//! set of five volumes) and, beside each, arms that hold every file of the
//! base with ONE of them changed. Each arm here is named with what rule 2
//! says of it:
//!
//! - the offset is counted from the first byte of the main header AS
//!   STORED, which behind header encryption is the first byte of the IV
//!   in front of it, so every base and every control is a whole read;
//! - case a, a block the walk read begins at the offset: nothing is said,
//!   whatever kind of block it is;
//! - case b, the offset is at or past the end of the volume's bytes:
//!   `Truncated`;
//! - case c, the offset is inside the volume's bytes and no block begins
//!   there: `Corrupt` at the main header's offset, raised after the walk.
//!
//! In every one of them the four members are delivered whole and right:
//! the offset is judged after the walk and never costs a member.
//!
//! One thread throughout (the sequential driver at its default width);
//! every file is under 5 KiB and held in memory, so no test needs more
//! than a few MiB.

use std::sync::Arc;

use rarkit::{
    extract, Archive, Disposition, ErrorKind, MemberInfo, MemberOutcome, Password, RangeSource,
    ReadOptions, Sink,
};

const DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../specs/vectors-F/locator-offset"
);

const NAMES: [&str; 4] = ["a.txt", "b.txt", "c.txt", "d.txt"];

/// A base: its name, the files of it in volume order, whether its headers
/// are encrypted, and the offset of its main header as stored.
struct Base {
    name: &'static str,
    files: &'static [&'static str],
    keyed: bool,
    main_at: u64,
}

const BASES: [Base; 4] = [
    Base {
        name: "plain",
        files: &["plain.rar"],
        keyed: false,
        main_at: 8,
    },
    Base {
        name: "hp",
        files: &["hp.rar"],
        keyed: true,
        main_at: 46,
    },
    Base {
        name: "vol",
        files: &[
            "vol.part1.rar",
            "vol.part2.rar",
            "vol.part3.rar",
            "vol.part4.rar",
            "vol.part5.rar",
        ],
        keyed: false,
        main_at: 8,
    },
    Base {
        name: "hpvol",
        files: &[
            "hpvol.part1.rar",
            "hpvol.part2.rar",
            "hpvol.part3.rar",
            "hpvol.part4.rar",
            "hpvol.part5.rar",
        ],
        keyed: true,
        main_at: 46,
    },
];

fn read(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// The files of one arm of a base, in volume order; `None` is the base
/// itself.
fn files(base: &Base, arm: Option<&str>) -> Vec<Vec<u8>> {
    base.files
        .iter()
        .map(|file| match arm {
            Some(arm) => read(&format!("{DIR}/{}.arm.{arm}/{file}", base.name)),
            None => read(&format!("{DIR}/{file}")),
        })
        .collect()
}

fn options(base: &Base) -> ReadOptions {
    ReadOptions::default()
        .with_read_damaged(true)
        .with_password(base.keyed.then(|| Password::from("Secret")))
}

/// (name, bytes, checksum verdict) of every member closed.
type Members = Vec<(String, Vec<u8>, Option<bool>)>;

#[derive(Default)]
struct Keep(Members);

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
        self.0.push((
            member.name_lossy().into_owned(),
            out.unwrap_or_default(),
            outcome.checksum_ok,
        ));
        Ok(())
    }
}

/// What a whole read of the base delivers: the four members.
fn whole(base: &Base) -> Members {
    let mut sink = Keep::default();
    extract(
        sources(&files(base, None)),
        &options(base),
        &mut sink,
        &mut (),
    )
    .unwrap_or_else(|e| panic!("{}: the base did not read whole: {e:?}", base.name));
    let names: Vec<&str> = sink.0.iter().map(|m| m.0.as_str()).collect();
    assert_eq!(names, NAMES, "{}", base.name);
    for member in &sink.0 {
        assert_eq!(member.2, Some(true), "{}: {}", base.name, member.0);
    }
    sink.0
}

fn sources(files: &[Vec<u8>]) -> Vec<Arc<dyn RangeSource>> {
    files
        .iter()
        .map(|bytes| Arc::new(bytes.clone()) as Arc<dyn RangeSource>)
        .collect()
}

/// Extract an arm: how the run ended and what it delivered.
fn run(base: &Base, arm: &str) -> (rarkit::Result<()>, Members) {
    let mut sink = Keep::default();
    let ended = extract(
        sources(&files(base, Some(arm))),
        &options(base),
        &mut sink,
        &mut (),
    )
    .map(|_| ());
    (ended, sink.0)
}

/// The offset lands on the `QO` header in every base file, counted from
/// the main header as stored: behind `-hp` that is the IV in front of the
/// main header (3.2.8, "Where the offset is counted from behind header
/// encryption"). Each base, and each control of its arms, is a whole read
/// and is never reported.
#[test]
fn every_base_and_control_is_a_whole_read() {
    for base in &BASES {
        let members = whole(base);
        for arm in [
            "control",
            "offset-same",
            "trailing-zeros-control",
            // Zero is "none", in however many bytes it is written.
            "offset-0-long-form",
            // The quick open record is whole; only the end header is gone.
            "cut-at-end-header",
        ] {
            let (ended, got) = run(base, arm);
            assert!(ended.is_ok(), "{}.{arm}: {ended:?}", base.name);
            assert_eq!(got, members, "{}.{arm}", base.name);
        }
        for file in 0..base.files.len() {
            let bytes = &files(base, None)[file];
            let archive = Archive::open(Arc::new(bytes.clone()), &options(base))
                .unwrap_or_else(|e| panic!("{}: file {file}: {e:?}", base.name));
            assert!(archive.tail().is_none(), "{}: file {file}", base.name);
        }
    }
}

/// Rule 2 case a: a block the walk read begins exactly at the offset, and
/// it is a sound header of another kind (the second file header, the end
/// header). The hint is ignored and nothing is said.
#[test]
fn an_offset_on_another_sound_header_is_ignored() {
    for base in &BASES {
        let members = whole(base);
        for arm in ["offset-on-file-header", "offset-on-end-header"] {
            let (ended, got) = run(base, arm);
            assert!(ended.is_ok(), "{}.{arm}: {ended:?}", base.name);
            assert_eq!(got, members, "{}.{arm}", base.name);
        }
    }
}

/// Rule 2 case b: the offset is at or past the end of the volume's bytes.
/// The volume has lost its tail: `Truncated`, with every member the walk
/// found delivered, also where the walk read an end header.
#[test]
fn an_offset_at_or_past_the_end_of_the_volume_is_truncated() {
    for base in &BASES {
        let members = whole(base);
        let mut arms = vec!["offset-at-file-end", "offset-past-file-end"];
        if base.files.len() > 1 {
            arms.push("second-volume-offset-past-file-end");
        }
        for arm in arms {
            let (ended, got) = run(base, arm);
            let err = ended.expect_err(&format!("{}.{arm}", base.name));
            assert!(
                matches!(err.kind(), ErrorKind::Truncated),
                "{}.{arm}: {err:?}",
                base.name
            );
            assert_eq!(got, members, "{}.{arm}", base.name);
        }
    }
}

/// Rule 2 case c: the offset is inside the volume's bytes and no block the
/// walk read begins there. The locator is wrong, not the tail: `Corrupt`
/// naming the main header's offset in the volume whose locator it is,
/// raised after the walk, so that every member is delivered. Behind
/// header encryption too, where the reference may write none.
#[test]
fn an_offset_inside_the_volume_on_no_block_is_corrupt_after_the_walk() {
    for base in &BASES {
        let members = whole(base);
        let mut arms = vec![
            ("offset-plus-1", 0),
            ("offset-minus-1", 0),
            ("offset-1", 0),
            ("offset-in-file-header", 0),
            ("offset-in-member-data", 0),
            ("offset-in-qo-data", 0),
            ("offset-in-trailing-zeros", 0),
        ];
        if base.files.len() > 1 {
            arms.push(("second-volume-offset-plus-1", 1));
            arms.push(("second-volume-offset-in-member-data", 1));
        }
        for (arm, volume) in arms {
            let (ended, got) = run(base, arm);
            let err = ended.expect_err(&format!("{}.{arm}", base.name));
            assert!(
                matches!(err.kind(), ErrorKind::Corrupt(_)),
                "{}.{arm}: {err:?}",
                base.name
            );
            assert_eq!(err.offset(), Some(base.main_at), "{}.{arm}", base.name);
            assert_eq!(err.volume(), Some(volume), "{}.{arm}", base.name);
            assert_eq!(got, members, "{}.{arm}", base.name);

            // A listing of the volume says the same, and with
            // `tolerant_tail` keeps every member header it read.
            let bytes = files(base, Some(arm)).swap_remove(volume as usize);
            let source: Arc<dyn RangeSource> = Arc::new(bytes);
            let err = Archive::open(Arc::clone(&source), &options(base))
                .err()
                .unwrap_or_else(|| panic!("{}.{arm}: the volume opened", base.name));
            assert!(
                matches!(err.kind(), ErrorKind::Corrupt(_)),
                "{}.{arm}: {err:?}",
                base.name
            );
            assert_eq!(err.offset(), Some(base.main_at), "{}.{arm}", base.name);
            let whole = Archive::open(
                Arc::new(files(base, None).swap_remove(volume as usize)),
                &options(base),
            )
            .expect("the base volume");
            let kept = Archive::open(source, &options(base).with_tolerant_tail(true))
                .unwrap_or_else(|e| panic!("{}.{arm}: {e:?}", base.name));
            assert_eq!(
                kept.members().count(),
                whole.members().count(),
                "{}.{arm}",
                base.name
            );
            let tail = kept.tail().expect("the reason the open is not whole");
            assert!(
                matches!(tail.kind(), ErrorKind::Corrupt(_)),
                "{}.{arm}: {tail:?}",
                base.name
            );
        }
    }
}

/// A walk that did not reach the volume's end judges nothing, and a cut
/// that takes the quick open header with it is case b: the archive cut
/// where its second file header would begin delivers the one member it
/// holds and is `Truncated`.
#[test]
fn a_cut_before_the_quick_open_header_is_truncated() {
    for base in &BASES {
        let members = whole(base);
        let (ended, got) = run(base, "cut-at-second-file-header");
        let err = ended.expect_err(base.name);
        assert!(
            matches!(err.kind(), ErrorKind::Truncated),
            "{}: {err:?}",
            base.name
        );
        assert_eq!(got, members[..1], "{}", base.name);
    }
}

/// The file ends where the `QO` header would begin, so the offset is the
/// first byte past the volume's end: case b. Behind `-hp` this is where
/// the base of the count shows: counted from the first byte after the
/// signature, where the encryption header stands, the offset would fall 38
/// bytes short of the cut, inside the last member's data, and say nothing
/// of a lost tail. In a set the cut volume ends behind a member that
/// continues: the walk goes on to the next volume, every member is
/// delivered, and the run is `Truncated` in the volume that was cut.
#[test]
fn a_cut_where_the_quick_open_header_would_begin_is_truncated() {
    for base in &BASES {
        let members = whole(base);
        let (ended, got) = run(base, "cut-at-qo");
        let err = ended.expect_err(base.name);
        assert!(
            matches!(err.kind(), ErrorKind::Truncated),
            "{}: {err:?}",
            base.name
        );
        assert_eq!(err.volume(), Some(0), "{}", base.name);
        assert_eq!(got, members, "{}", base.name);
    }
}
