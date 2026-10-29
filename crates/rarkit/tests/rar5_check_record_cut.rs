//! A RAR 5 FILE header whose encryption record still FLAGS a password
//! check value (flag 0x0001) while the value's twelve bytes are gone, all
//! of them or some: the check record is damaged, so it is ABSENT (SPEC-K
//! 3.7.3 step 1). The member is not refused for it. It is deciphered with
//! the password given and judged by its own data checksum, as a member
//! that carries no check record is.
//!
//! Every input is made here from the specification's own genuine
//! archives, `specs/vectors-K/check-value-in-chain/separate.rar` and
//! `solid.rar` (six members, one password, rar 7.23): the test drops the
//! tail of the check value from a member's record and redoes the record's
//! size, the extra area's size, the header's size and the header's
//! checksum, so the header is sound and only the record is short.
//!
//! What the reference does, measured with unrar 7.23 on a Mac (arm64) on
//! 9 Oct 2026 over these same edits, `x` into an empty directory:
//!
//! | The edit | right password | wrong password |
//! |---|---|---|
//! | member 2's value dropped whole, or cut to 5 or to 11 bytes | all six written right, exit 0 | nothing written, exit 11 (the other members' check values refuse it) |
//! | every member's value dropped whole | all six written right, exit 0 | nothing written, exit 3 (checksum errors) |
//!
//! and the same for the solid archive as for the other.
//!
//! Before, the short record was `Corrupt` and its member was refused
//! under the right password.
//!
//! Read at the default width and at one worker, and by `extract_parallel`
//! at two. Every archive is under 4 KiB and its members come to 24,000
//! bytes; the key derivation is the archives' own (2^15 rounds), once a
//! salt.

use std::sync::{Arc, Mutex};

use rarkit::{
    extract, extract_parallel, Archive, Disposition, MemberInfo, MemberOutcome, ParallelSink,
    Password, RangeSource, ReadOptions, Sink,
};

const MEMBERS: usize = 6;
/// The length of a check record: the value's eight bytes and its sum's
/// four.
const CHECK: usize = 12;

fn vector(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/../../specs/vectors-K/check-value-in-chain/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn name_of(member: usize) -> String {
    format!("f{member}.txt")
}

/// A RAR 5 vint at `at`, which moves past it.
fn vint(bytes: &[u8], at: &mut usize) -> u64 {
    let mut value = 0;
    for shift in (0..).step_by(7) {
        let byte = bytes[*at];
        *at += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
    }
    value
}

fn put_vint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(value as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn crc32(bytes: &[u8]) -> u32 {
    !bytes.iter().fold(!0u32, |mut crc, &byte| {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (crc & 1).wrapping_neg());
        }
        crc
    })
}

/// `archive` with the check record of each FILE header numbered in
/// `which` cut to its first `keep` bytes, the flag that announces it
/// left set, and every size and the header checksum redone.
fn cut(archive: &[u8], which: &[usize], keep: usize) -> Vec<u8> {
    let mut out = archive[..8].to_vec();
    let (mut at, mut file, mut edits) = (8, 0, 0);
    while at < archive.len() {
        at += 4;
        let size = vint(archive, &mut at) as usize;
        let head = &archive[at..at + size];
        at += size;
        let mut p = 0;
        let kind = vint(head, &mut p);
        let flags = vint(head, &mut p);
        let extra = if flags & 1 != 0 {
            vint(head, &mut p) as usize
        } else {
            0
        };
        let data = if flags & 2 != 0 {
            vint(head, &mut p) as usize
        } else {
            0
        };
        let fields = &head[p..head.len() - extra];
        let mut records = head[head.len() - extra..].to_vec();
        if kind == 2 {
            if which.contains(&file) {
                let old = std::mem::take(&mut records);
                let mut q = 0;
                while q < old.len() {
                    let len = vint(&old, &mut q) as usize;
                    let mut record = &old[q..q + len];
                    q += len;
                    // Type 1, version 0, a flags byte with the check bit,
                    // the count, the salt, the IV and the check record.
                    if record[0] == 1 {
                        assert_eq!(record[1], 0, "the record's version");
                        assert_eq!(record[2] & 1, 1, "the check flag");
                        assert_eq!(record.len(), 4 + 16 + 16 + CHECK);
                        record = &record[..record.len() - CHECK + keep];
                        edits += 1;
                    }
                    put_vint(&mut records, record.len() as u64);
                    records.extend_from_slice(record);
                }
            }
            file += 1;
        }
        let mut body = Vec::new();
        put_vint(&mut body, kind);
        put_vint(&mut body, flags);
        if flags & 1 != 0 {
            put_vint(&mut body, records.len() as u64);
        }
        if flags & 2 != 0 {
            put_vint(&mut body, data as u64);
        }
        body.extend_from_slice(fields);
        body.extend_from_slice(&records);
        let mut sized = Vec::new();
        put_vint(&mut sized, body.len() as u64);
        sized.extend_from_slice(&body);
        out.extend_from_slice(&crc32(&sized).to_le_bytes());
        out.extend_from_slice(&sized);
        out.extend_from_slice(&archive[at..at + data]);
        at += data;
    }
    assert_eq!(file, MEMBERS, "the FILE headers walked");
    assert_eq!(edits, which.len(), "the records cut");
    out
}

/// One member the sink was told of at its close.
#[derive(Debug, Clone)]
struct Came {
    name: String,
    data: Option<Vec<u8>>,
    checksum_ok: Option<bool>,
    password_refused: bool,
}

#[derive(Default)]
struct Keep {
    came: Mutex<Vec<Came>>,
}

impl Keep {
    fn closed(&self, member: &MemberInfo<'_>, out: Option<Vec<u8>>, outcome: &MemberOutcome) {
        self.came.lock().expect("lock").push(Came {
            name: member.name_lossy().into_owned(),
            data: out,
            checksum_ok: outcome.checksum_ok,
            password_refused: outcome.password_refused,
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

    fn open(&mut self, _: &MemberInfo<'_>) -> rarkit::Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
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

    fn open(&self, _: &MemberInfo<'_>) -> rarkit::Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
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

fn options(password: &str, workers: Option<usize>) -> ReadOptions {
    ReadOptions::default()
        .with_password(Some(Password::from(password)))
        .with_workers(workers)
}

/// Every read path over one archive, labelled: the members closed, by
/// name, and the kind of the error the read ended in, as it prints.
fn every_path(bytes: &[u8], password: &str) -> Vec<(String, Vec<Came>, Option<String>)> {
    let source = || -> Vec<Arc<dyn RangeSource>> { vec![Arc::new(bytes.to_vec())] };
    let kind =
        |end: rarkit::Result<rarkit::ExtractReport>| end.err().map(|e| format!("{:?}", e.kind()));
    let mut reads = Vec::new();
    for workers in [None, Some(1)] {
        let mut sink = Keep::default();
        let end = extract(source(), &options(password, workers), &mut sink, &mut ());
        reads.push((format!("workers {workers:?}"), sink.sorted(), kind(end)));
    }
    let sink = Keep::default();
    let end = extract_parallel(source(), &options(password, None), &sink, 2);
    reads.push((
        "extract_parallel, 2 wide".to_owned(),
        sink.sorted(),
        kind(end),
    ));
    reads
}

/// The six members' true bytes, from the archive as rar wrote it.
fn truth(archive: &str) -> Vec<Vec<u8>> {
    let (_, came, end) = every_path(&vector(archive), "PASS").remove(0);
    assert_eq!(end, None);
    assert_eq!(came.len(), MEMBERS);
    came.into_iter()
        .map(|member| member.data.expect("written"))
        .collect()
}

/// The edits: the members whose record is cut, and the bytes of the check
/// record left in each.
const EDITS: [(&[usize], usize); 4] = [(&[2], 0), (&[2], 5), (&[2], 11), (&[0, 1, 2, 3, 4, 5], 0)];

/// The listing: a cut record's member is listed as encrypted with no
/// check, and every member is still there.
#[test]
fn a_member_whose_check_record_is_cut_is_listed_with_no_check() {
    for archive in ["separate.rar", "solid.rar"] {
        for (which, keep) in EDITS {
            let case = format!("{archive}, members {which:?} cut to {keep}");
            let bytes = cut(&vector(archive), which, keep);
            let opened = Archive::open(Arc::new(bytes), &options("PASS", Some(1)))
                .unwrap_or_else(|e| panic!("{case}: {e}"));
            assert!(opened.tail().is_none(), "{case}: {:?}", opened.tail());
            assert!(opened.damaged_headers().is_empty(), "{case}");
            let listed: Vec<(String, bool, bool)> = opened
                .members()
                .map(|m| (m.name_lossy().into_owned(), m.encrypted, m.password_checked))
                .collect();
            let want: Vec<(String, bool, bool)> = (0..MEMBERS)
                .map(|n| (name_of(n), true, !which.contains(&n)))
                .collect();
            assert_eq!(listed, want, "{case}");
        }
    }
}

/// Under the right password every member comes out with its true bytes
/// and a good checksum, the cut ones too, and the read ends in no error.
#[test]
fn a_member_whose_check_record_is_cut_is_read_by_its_checksum() {
    for archive in ["separate.rar", "solid.rar"] {
        let truth = truth(archive);
        for (which, keep) in EDITS {
            let bytes = cut(&vector(archive), which, keep);
            for (path, came, end) in every_path(&bytes, "PASS") {
                let case = format!("{archive}, members {which:?} cut to {keep}, {path}");
                assert_eq!(end, None, "{case}");
                assert_eq!(came.len(), MEMBERS, "{case}");
                for (n, member) in came.iter().enumerate() {
                    assert_eq!(member.name, name_of(n), "{case}");
                    assert_eq!(member.checksum_ok, Some(true), "{case}: {}", member.name);
                    assert!(!member.password_refused, "{case}: {}", member.name);
                    assert_eq!(
                        member.data.as_ref(),
                        Some(&truth[n]),
                        "{case}: {}",
                        member.name
                    );
                }
            }
        }
    }
}

/// Under a WRONG password a member whose check record is cut is never
/// called good: it fails by its data checksum, and it is not called
/// refused by a check either, for no check judged it. A member that kept
/// its check record is refused by it as before.
#[test]
fn a_wrong_password_on_a_cut_check_record_fails_by_the_checksum() {
    for archive in ["separate.rar", "solid.rar"] {
        let truth = truth(archive);
        for (which, keep) in EDITS {
            let bytes = cut(&vector(archive), which, keep);
            for (path, came, end) in every_path(&bytes, "WRONG") {
                let case = format!("{archive}, members {which:?} cut to {keep}, {path}");
                assert!(end.is_some(), "{case}: a wrong password ended in no error");
                if which.len() == MEMBERS {
                    // No check record is left to say "wrong password".
                    assert_ne!(end.as_deref(), Some("WrongPassword"), "{case}");
                    assert_eq!(came.len(), MEMBERS, "{case}");
                }
                for member in &came {
                    let n = (0..MEMBERS)
                        .find(|&n| member.name == name_of(n))
                        .expect("a member");
                    assert_ne!(member.checksum_ok, Some(true), "{case}: {}", member.name);
                    assert_ne!(
                        member.data.as_ref(),
                        Some(&truth[n]),
                        "{case}: {}",
                        member.name
                    );
                    if which.contains(&n) {
                        assert!(!member.password_refused, "{case}: {}", member.name);
                        assert_eq!(member.checksum_ok, Some(false), "{case}: {}", member.name);
                    } else {
                        assert!(member.password_refused, "{case}: {}", member.name);
                        assert!(member.data.is_none(), "{case}: {}", member.name);
                    }
                }
            }
        }
    }
}
