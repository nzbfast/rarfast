//! A RAR 5 member whose password check value refuses the password,
//! inside a solid chain and out of one, on the specification's own
//! archives (SPEC-K 3.7.3, "A refused member inside a solid chain", added
//! 8 Oct 2026; bug sweep item SWEEP2-08OCT-17).
//!
//! `specs/vectors-K/check-value-in-chain` holds two genuine archives of
//! six members written with one password, solid and not, and arms with
//! the check values of some members altered and their sums made to fit,
//! beside the answers of rar 7.23 and unrar 7.23. The rule, under the
//! right password:
//!
//! - a refused member delivers no byte and is reported `WrongPassword`,
//!   `MemberOutcome::password_refused` true;
//! - in a solid chain it is still deciphered under the derived key and
//!   decoded, its output discarded, so every later member whose own check
//!   passes comes out with its true bytes: after one refused member,
//!   after four in a row, and when the refused member starts the chain;
//! - a refused member that was not asked for and is decoded on the way
//!   to one that was is reported all the same; one standing after the
//!   last member read costs nothing;
//! - a check record whose own sum does not fit is no check at all.
//!
//! Before the rule was added a refused member was closed undecoded and
//! every later member of its chain failed its checksum.
//!
//! Read at the default width and at one worker, and by `extract_parallel`
//! at two for whole extractions. Every archive is under 4 KiB and its
//! members come to 24,000 bytes; the key derivation is the archives' own
//! (2^15 rounds), once a salt.

use std::sync::{Arc, Mutex};

use rarkit::{
    extract, extract_parallel, Disposition, MemberInfo, MemberOutcome, ParallelSink, Password,
    RangeSource, ReadOptions, Sink,
};

fn vector(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/../../specs/vectors-K/check-value-in-chain/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// One member the sink was told of at its close.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Came {
    name: String,
    data: Option<Vec<u8>>,
    checksum_ok: Option<bool>,
    password_refused: bool,
    bytes: u64,
}

/// Keeps the members named in `only`, or every member when it is empty.
#[derive(Default)]
struct Keep {
    only: Vec<String>,
    came: Mutex<Vec<Came>>,
}

impl Keep {
    fn wants(&self, member: &MemberInfo<'_>) -> Disposition<Vec<u8>> {
        let name = member.name_lossy();
        if self.only.is_empty() || self.only.iter().any(|want| *want == name) {
            Disposition::Write(Vec::new())
        } else {
            Disposition::Skip
        }
    }

    fn closed(&self, member: &MemberInfo<'_>, out: Option<Vec<u8>>, outcome: &MemberOutcome) {
        self.came.lock().expect("lock").push(Came {
            name: member.name_lossy().into_owned(),
            data: out,
            checksum_ok: outcome.checksum_ok,
            password_refused: outcome.password_refused,
            bytes: outcome.bytes,
        });
    }

    fn sorted(self) -> Vec<Came> {
        let mut came = self.came.into_inner().expect("lock");
        came.sort_by(|a, b| a.name.cmp(&b.name));
        came
    }
}

impl Sink for Keep {
    type Out = Vec<u8>;

    fn open(&mut self, member: &MemberInfo<'_>) -> rarkit::Result<Disposition<Vec<u8>>> {
        Ok(self.wants(member))
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> rarkit::Result<()> {
        self.closed(member, out, outcome);
        Ok(())
    }
}

impl ParallelSink for Keep {
    type Out = Vec<u8>;

    fn open(&self, member: &MemberInfo<'_>) -> rarkit::Result<Disposition<Vec<u8>>> {
        Ok(self.wants(member))
    }

    fn close(
        &self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> rarkit::Result<()> {
        self.closed(member, out, outcome);
        Ok(())
    }
}

/// What one read came to: the members closed, by name, and the error
/// the operation ended in, as its kind prints and the member it names.
type Read = (Vec<Came>, Option<String>, Option<String>);

const WRONG: &str = "WrongPassword";
const REQUIRED: &str = "PasswordRequired";

fn options(password: Option<&str>, workers: Option<usize>) -> ReadOptions {
    ReadOptions::default()
        .with_password(password.map(Password::from))
        .with_workers(workers)
}

/// Every read path over one archive, labelled. `extract_parallel` is
/// asked only for a whole extraction.
fn every_path(bytes: &[u8], password: Option<&str>, only: &[&str]) -> Vec<(String, Read)> {
    let source = || -> Vec<Arc<dyn RangeSource>> { vec![Arc::new(bytes.to_vec())] };
    let keep = || Keep {
        only: only.iter().map(|name| (*name).to_owned()).collect(),
        came: Mutex::default(),
    };
    let mut reads = Vec::new();
    for workers in [None, Some(1)] {
        let mut sink = keep();
        let end = extract(source(), &options(password, workers), &mut sink, &mut ());
        let (kind, named) = ended(end);
        reads.push((format!("workers {workers:?}"), (sink.sorted(), kind, named)));
    }
    if only.is_empty() {
        let sink = keep();
        let end = extract_parallel(source(), &options(password, None), &sink, 2);
        let (kind, named) = ended(end);
        reads.push((
            "extract_parallel, 2 wide".to_owned(),
            (sink.sorted(), kind, named),
        ));
    }
    reads
}

/// An operation's end: its error's kind, as it prints, and the member the
/// error names.
fn ended(end: rarkit::Result<rarkit::ExtractReport>) -> (Option<String>, Option<String>) {
    match end {
        Ok(_) => (None, None),
        Err(e) => (
            Some(format!("{:?}", e.kind())),
            e.member()
                .map(|name| String::from_utf8_lossy(name).into_owned()),
        ),
    }
}

/// The member numbers a cell of the answers lists as written with their
/// true bytes (`-` for none; no row here writes other bytes).
fn written(cell: &str) -> Vec<usize> {
    if cell == "-" {
        return Vec::new();
    }
    cell.split(' ')
        .map(|n| n.parse().expect("a member number"))
        .collect()
}

/// The members an archive's name says were refused.
fn refused_of(archive: &str) -> Vec<usize> {
    match archive.split_once(".refuse-") {
        Some((_, rest)) => rest
            .trim_end_matches(".rar")
            .split('-')
            .map(|n| n.parse().expect("a member number"))
            .collect(),
        None => Vec::new(),
    }
}

fn name_of(member: usize) -> String {
    format!("f{member}.txt")
}

#[test]
fn a_refused_member_is_withheld_and_the_chain_after_it_is_right() {
    let truth: Vec<Vec<u8>> = {
        let (came, end, _) = every_path(&vector("solid.rar"), Some("PASS"), &[])
            .remove(0)
            .1;
        assert_eq!(end, None);
        assert_eq!(came.len(), 6);
        came.into_iter()
            .map(|member| member.data.expect("written"))
            .collect()
    };
    let answers = String::from_utf8(vector("outcomes-unrar-7.23-macos-arm64.tsv")).expect("text");
    let mut rows = 0;
    for line in answers.lines().skip(1) {
        let cells: Vec<&str> = line.split('\t').collect();
        let (archive, password) = (cells[1], cells[2]);
        if password != "PASS" {
            continue;
        }
        rows += 1;
        let bytes = vector(archive);
        let refused = refused_of(archive);
        // The whole archive, then f3.txt and f5.txt alone: the exit code
        // and the members the reference wrote with their true bytes.
        for (only, exit, wrote) in [
            (&[][..], cells[4], written(cells[5])),
            (&["f3.txt", "f5.txt"][..], cells[6], written(cells[7])),
        ] {
            for (path, (came, end, named)) in every_path(&bytes, Some(password), only) {
                let case = format!("{archive}, only {only:?}, {path}");
                // Exit 11 is `WrongPassword`, and the error names a
                // member that WAS refused, asked for or not, never
                // another; exit 0 is no error.
                match exit {
                    "0" => assert_eq!(end, None, "{case}"),
                    "11" => {
                        assert_eq!(end.as_deref(), Some(WRONG), "{case}");
                        let named = named.expect("the error names a member");
                        assert!(
                            refused.iter().any(|&n| name_of(n) == named),
                            "{case}: the error names {named}"
                        );
                    }
                    other => panic!("{case}: an exit of {other}"),
                }
                let good: Vec<usize> = (0..6)
                    .filter(|&n| {
                        came.iter().any(|member| {
                            member.name == name_of(n)
                                && member.checksum_ok == Some(true)
                                && member.data.as_ref() == Some(&truth[n])
                        })
                    })
                    .collect();
                assert_eq!(good, wrote, "{case}: the members written right");
                // Every member closed is one of the two kinds: written
                // right, or refused with nothing delivered.
                for member in &came {
                    let n = (0..6)
                        .find(|&n| member.name == name_of(n))
                        .expect("a member");
                    if wrote.contains(&n) {
                        assert!(!member.password_refused, "{case}: {}", member.name);
                    } else {
                        assert!(refused.contains(&n), "{case}: {} failed", member.name);
                        assert!(member.password_refused, "{case}: {}", member.name);
                        assert_eq!(member.checksum_ok, Some(false), "{case}");
                        assert_eq!(member.bytes, 0, "{case}: {}", member.name);
                        assert!(member.data.is_none(), "{case}: {}", member.name);
                    }
                }
            }
        }
    }
    assert_eq!(rows, 12, "the rows under the right password");
}

/// Under a wrong password, or none, every member is refused and nothing
/// is written, solid or not, as the reference answers.
#[test]
fn a_wrong_password_or_none_writes_nothing() {
    for archive in ["solid.rar", "separate.rar", "solid.refuse-2.rar"] {
        for password in [Some("WRONG"), None] {
            for (path, (came, end, _)) in every_path(&vector(archive), password, &[]) {
                let case = format!("{archive}, password {password:?}, {path}");
                assert!(
                    matches!(end.as_deref(), Some(WRONG | REQUIRED)),
                    "{case}: {end:?}"
                );
                for member in &came {
                    assert_ne!(member.checksum_ok, Some(true), "{case}: {}", member.name);
                    assert!(member.data.is_none(), "{case}: {}", member.name);
                    assert_eq!(member.bytes, 0, "{case}: {}", member.name);
                }
            }
        }
    }
}
