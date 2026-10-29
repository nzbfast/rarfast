//! A sink that SKIPS members of an ENCRYPTED SOLID archive still gets the
//! members it wants, whole and checked.
//!
//! Spec F 3.6 and 3.7.1: a member of a solid archive that the sink skips
//! is decoded and discarded, because the member after it continues from
//! its window. The member that STARTS a chain carries its solid bit clear,
//! and when it is encrypted its packed bytes are ciphertext like every
//! other member's: decoding it for the chain's sake needs its key as much
//! as writing it does.
//!
//! The RAR 5 archives under `tests/encrypted_solid_skip/` are the reference
//! rar 7.23's own (`make.sh` there is how, `SHA256SUMS` which), one with
//! its data encrypted (`-p`) and one with its headers too (`-hp`): four
//! members that share most of their text, the first with its solid bit
//! clear and the three after it set. The reference rar 7.23 writes no
//! RAR 4 family archive, so those are written by this crate, at each of
//! the three versions it writes.
//!
//! Every test here runs the sequential driver at a thread width of 1 and
//! of 4 and the pool at widths of 1, 2 and 4 (2 is the narrowest hosted
//! runner's), under the default memory policy and under a named limit of
//! 64 MiB. Each holds one archive of under 64 KiB and its four members of
//! under 40 KiB in memory, and the archives' dictionary is 1 MiB: no test
//! needs more than a few MiB whatever the width.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use rarkit::{
    extract, extract_parallel, Disposition, FilterPolicy, MemberInfo, MemberOutcome, MemberSpec,
    MemoryPolicy, ParallelSink, Password, Payload, RangeSource, Rar4Version, ReadOptions, Result,
    Session, Sink, WriteFormat, WriteMethod, WriteOptions, Writer,
};

const PASSWORD: &str = "skip the head";

/// The named limit the second memory arm reads under.
const NAMED_LIMIT: u64 = 64 << 20;

const NAMES: [&str; 4] = ["a-head.txt", "b-second.txt", "c-third.txt", "d-last.txt"];

/// The text `make.sh` writes, from the same recurrence.
fn text(seed: u64, lines: usize) -> Vec<u8> {
    let mut state = seed;
    let mut out = Vec::new();
    for n in 0..lines {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        out.extend_from_slice(
            format!(
                "line {:04} of the shared body, word {:05} and word {:05}\n",
                n,
                (state >> 40) % 100_000,
                (state >> 20) % 100_000
            )
            .as_bytes(),
        );
    }
    out
}

/// The four members, in archive order, as `make.sh` builds them.
fn members() -> Vec<(&'static str, Vec<u8>)> {
    let body = text(7, 400);
    let second = [&body[..9000], &text(11, 60), &body[9000..]].concat();
    let third = [&text(13, 40)[..], &body[2000..], &body[..2000]].concat();
    let last = [&body[5000..15000], &text(17, 80), &body[..]].concat();
    vec![
        (NAMES[0], body),
        (NAMES[1], second),
        (NAMES[2], third),
        (NAMES[3], last),
    ]
}

fn genuine(name: &str) -> Vec<u8> {
    let path = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/encrypted_solid_skip"
    ))
    .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// A solid encrypted RAR 4 family archive of the four members, written by
/// this crate.
fn rar4_family(version: Rar4Version, headers: bool) -> Vec<u8> {
    let mut writer = Writer::new(WriteOptions {
        format: WriteFormat::Rar4(version),
        method: WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
        solid: true,
        filters: FilterPolicy::Off,
        password: Some(Password::new(PASSWORD)),
        encrypt_headers: headers,
        workers: Some(1),
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    })
    .expect("options");
    let members = members();
    for (name, data) in &members {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
                payload: Payload::Bytes(data),
                mtime: None,
                attributes: 0o644 << 16,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    out
}

fn sources(bytes: &[u8]) -> Vec<Arc<dyn RangeSource>> {
    vec![Arc::new(bytes.to_vec()) as Arc<dyn RangeSource>]
}

/// One member as its `close` saw it: name, the bytes written, the check's
/// verdict.
type Closed = (Vec<u8>, Option<Vec<u8>>, Option<bool>);

/// A sink that skips the members `skip` names and keeps the rest. One
/// value serves both drivers.
struct Selecting {
    skip: Vec<&'static str>,
    closed: Mutex<Vec<Closed>>,
}

impl Selecting {
    fn skipping(skip: &[&'static str]) -> Selecting {
        Selecting {
            skip: skip.to_vec(),
            closed: Mutex::new(Vec::new()),
        }
    }

    fn disposition(&self, member: &MemberInfo<'_>) -> Disposition<Vec<u8>> {
        if self.skip.iter().any(|n| n.as_bytes() == member.name) {
            Disposition::Skip
        } else {
            Disposition::Write(Vec::new())
        }
    }

    fn record(&self, member: &MemberInfo<'_>, out: Option<Vec<u8>>, outcome: &MemberOutcome) {
        self.closed.lock().expect("the sink's own lock").push((
            member.name.to_vec(),
            out,
            outcome.checksum_ok,
        ));
    }
}

impl Sink for Selecting {
    type Out = Vec<u8>;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        Ok(self.disposition(member))
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.record(member, out, outcome);
        Ok(())
    }
}

impl ParallelSink for Selecting {
    type Out = Vec<u8>;

    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        Ok(self.disposition(member))
    }

    fn close(
        &self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.record(member, out, outcome);
        Ok(())
    }
}

/// The ways a member is opened: which entry point, at what width.
#[derive(Clone, Copy, Debug)]
enum Driver {
    /// `extract`, its thread width named.
    Sequential(usize),
    /// `extract_parallel`, its pool width named.
    Pool(usize),
    /// `Session::extract`, its thread width named.
    SessionSequential(usize),
    /// `Session::extract_parallel`, its pool width named.
    SessionPool(usize),
}

const DRIVERS: [Driver; 8] = [
    Driver::Sequential(1),
    Driver::Sequential(4),
    Driver::Pool(1),
    Driver::Pool(2),
    Driver::Pool(4),
    Driver::SessionSequential(1),
    Driver::SessionSequential(4),
    Driver::SessionPool(2),
];

fn options(width: usize, limit: Option<u64>) -> ReadOptions {
    ReadOptions::default()
        .with_password(Some(Password::new(PASSWORD)))
        .with_workers(Some(width))
        .with_memory(limit.map(MemoryPolicy::from_limit).unwrap_or_default())
}

/// Read `archive` through `driver`, skipping `skip`, and return what the
/// operation answered and what each member's `close` saw.
fn read(
    archive: &[u8],
    driver: Driver,
    limit: Option<u64>,
    skip: &[&'static str],
) -> (Result<()>, Vec<Closed>) {
    let mut sink = Selecting::skipping(skip);
    let answer = match driver {
        Driver::Sequential(width) => {
            extract(sources(archive), &options(width, limit), &mut sink, &mut ())
        }
        Driver::Pool(width) => {
            extract_parallel(sources(archive), &options(width, limit), &sink, width)
        }
        Driver::SessionSequential(width) => {
            Session::new(options(width, limit)).extract(sources(archive), &mut sink, &mut ())
        }
        Driver::SessionPool(width) => {
            Session::new(options(width, limit)).extract_parallel(sources(archive), &sink, width)
        }
    };
    let closed = sink.closed.into_inner().expect("the sink's own lock");
    (answer.map(|_| ()), closed)
}

/// Every driver, both memory arms: the members `skip` leaves are written
/// whole with their check passed, the ones it names are never closed, and
/// the operation succeeds. Returns every arm that differs.
fn faults_of(what: &str, archive: &[u8], skip: &[&'static str]) -> Vec<String> {
    let wanted = members();
    let mut faults = Vec::new();
    for driver in DRIVERS {
        for limit in [None, Some(NAMED_LIMIT)] {
            let (answer, closed) = read(archive, driver, limit, skip);
            let arm = format!("{what}, {driver:?}, limit {limit:?}, skipping {skip:?}");
            if let Err(e) = &answer {
                faults.push(format!("{arm}: the operation answered {e:?}"));
            }
            for (name, bytes) in &wanted {
                let seen = closed.iter().find(|(n, _, _)| n == name.as_bytes());
                if skip.contains(name) {
                    // SPEC-API: `close` is for a member opened with Write
                    // or Verify.
                    if seen.is_some() {
                        faults.push(format!("{arm}: {name} was skipped and was closed"));
                    }
                    continue;
                }
                let Some((_, out, check)) = seen else {
                    faults.push(format!("{arm}: {name} was never closed"));
                    continue;
                };
                if out.as_deref() != Some(&bytes[..]) {
                    faults.push(format!(
                        "{arm}: {name} has {} bytes of {}, or other bytes",
                        out.as_ref().map_or(0, Vec::len),
                        bytes.len()
                    ));
                }
                if *check != Some(true) {
                    faults.push(format!("{arm}: {name}'s check was {check:?}"));
                }
            }
        }
    }
    faults
}

fn skipping_leaves_the_rest_whole(what: &str, archive: &[u8], skip: &[&'static str]) {
    let faults = faults_of(what, archive, skip);
    assert!(faults.is_empty(), "{}", faults.join("\n"));
}

/// [`skipping_leaves_the_rest_whole`] for each of [`SELECTIONS`], every one
/// of them read before any is judged.
fn every_selection_leaves_the_rest_whole(what: &str, archive: &[u8]) -> Vec<String> {
    SELECTIONS
        .iter()
        .flat_map(|skip| faults_of(what, archive, skip))
        .collect()
}

/// Every selection a test here makes: the head alone, a member in the
/// middle, the head and a middle member, all but the last, and the last.
const SELECTIONS: [&[&str]; 6] = [
    &[],
    &["a-head.txt"],
    &["b-second.txt"],
    &["a-head.txt", "c-third.txt"],
    &["a-head.txt", "b-second.txt", "c-third.txt"],
    &["d-last.txt"],
];

/// The fixtures are the archives this file says they are: the members
/// `make.sh` wrote are the members `members()` builds, every one read.
#[test]
fn the_genuine_archives_hold_the_members_this_file_builds() {
    for name in ["rar5_solid_p.rar", "rar5_solid_hp.rar"] {
        skipping_leaves_the_rest_whole(name, &genuine(name), &[]);
    }
}

/// Spec F 3.6: the head of a RAR 5 chain, skipped, is still decoded for
/// the members after it, and it is deciphered first.
#[test]
fn rar5_data_encrypted_solid_with_the_head_skipped() {
    let archive = genuine("rar5_solid_p.rar");
    skipping_leaves_the_rest_whole("rar5 -p", &archive, &["a-head.txt"]);
}

#[test]
fn rar5_header_encrypted_solid_with_the_head_skipped() {
    let archive = genuine("rar5_solid_hp.rar");
    skipping_leaves_the_rest_whole("rar5 -hp", &archive, &["a-head.txt"]);
}

/// A skip anywhere in a RAR 5 chain, and of several members of it.
#[test]
fn rar5_encrypted_solid_with_any_members_skipped() {
    let mut faults = Vec::new();
    for name in ["rar5_solid_p.rar", "rar5_solid_hp.rar"] {
        faults.extend(every_selection_leaves_the_rest_whole(name, &genuine(name)));
    }
    assert!(faults.is_empty(), "{}", faults.join("\n"));
}

/// The same selections over a solid encrypted archive of the RAR 4 family
/// at each version this crate writes, data encrypted and headers too.
#[test]
fn rar4_family_encrypted_solid_with_any_members_skipped() {
    let mut faults = Vec::new();
    for version in [Rar4Version::V29, Rar4Version::V30, Rar4Version::V40] {
        for headers in [false, true] {
            let archive = rar4_family(version, headers);
            let what = format!("rar4 family {version:?}, headers {headers}");
            faults.extend(every_selection_leaves_the_rest_whole(&what, &archive));
        }
    }
    assert!(faults.is_empty(), "{}", faults.join("\n"));
}
