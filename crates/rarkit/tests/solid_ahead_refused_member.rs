//! A member the walk REFUSES on the solid decode-ahead path ends as it
//! does on the sequential path: its own error, its own close, and every
//! member after it still delivered (bug sweep H-5, 4 Oct 2026).
//!
//! **The defect this pins.** The walk refuses a member (a wrong or missing
//! password on an encrypted member, a solid chain whose head is missing)
//! by closing it with no writer, and the writer its `open` was given was
//! dropped after that close. The drop finished the member's slot a SECOND
//! time, as fatal with no error, over the real ending. The delivering
//! thread read the fatal ending, waited for the walk's end and took no
//! later member: the refused member's error was lost and the read
//! returned a clean report of zero members. Where a later member did
//! extract, nobody read its bytes and the walk waited on them for ever.
//!
//! Which ending the delivering thread read was a race between the two
//! threads, so every case here is looped, and every solid read runs on a
//! thread of its own under a bound.
//!
//! WHAT THESE TESTS ASSUME. A STATED read width of 4 (`with_workers`), so
//! nothing depends on the host's cores or on rayon's pool: the solid path
//! starts one walking thread whatever the width, and runs the same on a
//! hosted runner 2, 3 or 4 threads wide. Memory: the default policy for
//! the password case (archives under 1 MiB); the chain cases state a
//! 16 MiB working limit, which puts the solid queue at 4 MiB, and hold a
//! 9 MiB stored member in memory three times over (the archive, and each
//! read's copy of it), about 40 MiB at once.

#![cfg(feature = "parallel")]

use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use rarkit::{
    extract, Disposition, MemberInfo, MemberOutcome, MemberSpec, Password, Payload, RangeSource,
    ReadOptions, Result, Sink, WriteMethod, WriteOptions, Writer,
};

/// The stated read width of every read here.
const WIDTH: usize = 4;

/// How many times each racing case is read.
const LAPS: usize = 200;

/// How long one solid read may take before it is called hung. The largest
/// archive here is 9 MiB of stored bytes.
const BOUND: Duration = Duration::from_secs(120);

const MIB: usize = 1 << 20;

/// One member as the caller saw it: its name, whether its close handed a
/// writer back and with which bytes, its verdict, and whether its outcome
/// said the password was refused.
type Record = (String, Option<Vec<u8>>, Option<bool>, bool);

/// Everything a caller sees of one read: its members and how it ended.
type Seen = (Vec<Record>, String);

#[derive(Default)]
struct Collect {
    got: Vec<Record>,
}

impl Sink for Collect {
    type Out = Vec<u8>;

    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.got.push((
            String::from_utf8_lossy(member.name).into_owned(),
            out,
            outcome.checksum_ok,
            outcome.password_refused,
        ));
        Ok(())
    }
}

/// One read of `archive` on a thread of its own, the solid decode-ahead
/// forced on or off and a stored member's ranges handed or queued, within
/// [`BOUND`]. Answers what the caller saw, and whether the solid path ran.
fn read(archive: &Arc<Vec<u8>>, opts: &ReadOptions, ahead: bool, hands: bool) -> (Seen, bool) {
    let archive = Arc::clone(archive);
    let opts = opts.clone();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        rarkit::probe::set_solid_ahead(Some(ahead));
        rarkit::probe::set_solid_stored_wide(Some(hands));
        rarkit::probe::reset_solid_ahead_seen();
        let mut sink = Collect::default();
        let volumes = vec![archive as Arc<dyn RangeSource>];
        let ended = match extract(volumes, &opts, &mut sink, &mut ()) {
            Ok(r) => format!("ok {} {} {}", r.members, r.bytes, r.checksum_failures),
            Err(e) => format!("err {:?} of {:?}", e.kind(), e.member()),
        };
        let taken = rarkit::probe::solid_ahead_seen().0 > 0;
        rarkit::probe::set_solid_ahead(None);
        rarkit::probe::set_solid_stored_wide(None);
        let _ = tx.send(((sink.got, ended), taken));
    });
    rx.recv_timeout(BOUND).unwrap_or_else(|_| {
        panic!(
            "the solid read HUNG (decode-ahead {ahead}, ranges handed {hands}): \
             no return within {BOUND:?}"
        )
    })
}

/// A file writer's options at the stated width.
fn file_opts() -> ReadOptions {
    let mut opts = ReadOptions::default().with_workers(Some(WIDTH));
    opts.sink_is_file = Some(true);
    opts
}

/// The sequential path's answer, then [`LAPS`] reads on the solid
/// decode-ahead path, each held to it.
fn every_lap_matches(label: &str, archive: Vec<u8>, opts: &ReadOptions, hands: bool) -> Seen {
    let archive = Arc::new(archive);
    let (want, taken) = read(&archive, opts, false, hands);
    assert!(!taken, "{label}: the control read took the solid path");
    for lap in 0..LAPS {
        let (have, taken) = read(&archive, opts, true, hands);
        assert!(taken, "{label}: lap {lap} did not take the solid path");
        assert_eq!(want.1, have.1, "{label}: lap {lap}: how the read ended");
        assert_eq!(
            want.0.len(),
            have.0.len(),
            "{label}: lap {lap}: the members closed"
        );
        for (a, b) in want.0.iter().zip(&have.0) {
            assert_eq!(a.0, b.0, "{label}: lap {lap}: the order of the closes");
            assert_eq!(a.2, b.2, "{label}: lap {lap}: {}'s verdict", a.0);
            assert_eq!(a.3, b.3, "{label}: lap {lap}: {}'s password word", a.0);
            assert!(a.1 == b.1, "{label}: lap {lap}: {}'s writer and bytes", a.0);
        }
    }
    want
}

// ---------------------------------------------------------------------------
// A wrong password
// ---------------------------------------------------------------------------

/// A solid RAR 5 archive this crate writes: member data encrypted under
/// `password`, headers visible.
fn encrypted_solid(members: &[(String, Vec<u8>)], password: &[u8]) -> Vec<u8> {
    let options = WriteOptions {
        solid: true,
        password: Some(Password::new(password.to_vec())),
        encrypt_headers: false,
        order: rarkit::MemberOrder::AsAdded,
        method: WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    };
    let mut writer = Writer::new(options).expect("options");
    for (name, data) in members {
        writer
            .add(MemberSpec {
                name: name.as_bytes(),
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
fn a_wrong_password_on_the_solid_decode_ahead_ends_as_the_sequential_path_does() {
    let members: Vec<(String, Vec<u8>)> = (0..6)
        .map(|k| {
            (
                format!("m{k}.txt"),
                rarkit_testdata::chatter((40 + k as u32) as u64, 30_000 + k * 977),
            )
        })
        .collect();
    let archive = encrypted_solid(&members, b"right");

    // The archive is what it is meant to be: the right password reads it.
    let right = file_opts().with_password(Some(Password::new(b"right".to_vec())));
    let (seen, _) = read(&Arc::new(archive.clone()), &right, true, true);
    assert_eq!(
        seen.0.len(),
        members.len(),
        "the right password: {}",
        seen.1
    );
    for (record, (name, data)) in seen.0.iter().zip(&members) {
        assert_eq!(&record.0, name);
        assert_eq!(record.1.as_deref(), Some(data.as_slice()));
        assert_eq!(record.2, Some(true));
    }

    for (label, password) in [
        ("a wrong password", Some(&b"wrong"[..])),
        ("no password", None),
    ] {
        let opts = file_opts().with_password(password.map(|p| Password::new(p.to_vec())));
        let want = every_lap_matches(label, archive.clone(), &opts, true);
        // And the sequential answer is the one the caller is owed: every
        // member closed as refused, and the read an error.
        assert_eq!(want.0.len(), members.len(), "{label}: {}", want.1);
        assert!(want.1.starts_with("err "), "{label}: {}", want.1);
        for record in &want.0 {
            assert_eq!(record.2, Some(false), "{label}: {}'s verdict", record.0);
            assert!(
                record.1.is_none(),
                "{label}: {} was given a writer",
                record.0
            );
            assert!(record.3, "{label}: {}'s password word", record.0);
        }
    }
}

// ---------------------------------------------------------------------------
// A missing chain head, and members after it that extract
// ---------------------------------------------------------------------------

fn vint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// A RAR 5 block: its CRC32, its size, and `body` from the type field on
/// (spec F 3.2.2).
fn block(body: &[u8]) -> Vec<u8> {
    let mut sized = Vec::with_capacity(body.len() + 8);
    vint(&mut sized, body.len() as u64);
    sized.extend_from_slice(body);
    let mut out = crc32fast::hash(&sized).to_le_bytes().to_vec();
    out.extend_from_slice(&sized);
    out
}

/// A stored member: its name, its bytes, and its solid bit.
type Stored<'a> = (&'a str, &'a [u8], bool);

/// The volume numbered 1 (the SECOND) of a solid RAR 5 set, opened alone,
/// holding `members` stored. A member at its head with the solid bit set
/// continues a chain whose head is in the volume before: the missing head
/// (spec F 3.6). One with the bit clear starts a chain of its own.
fn later_solid_volume(members: &[Stored<'_>]) -> Vec<u8> {
    let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
    let mut main = Vec::new();
    vint(&mut main, 1); // type: main archive header
    vint(&mut main, 0); // header flags
    vint(&mut main, 0x01 | 0x02 | 0x04); // a volume, numbered, solid
    vint(&mut main, 1); // the volume's number
    out.extend_from_slice(&block(&main));
    for (name, data, solid) in members {
        // The slice's own length: `RangeSource::len` is in scope too.
        let size = <[u8]>::len(data) as u64;
        let mut file = Vec::new();
        vint(&mut file, 2); // type: file header
        vint(&mut file, 2); // header flags: a data area follows
        vint(&mut file, size);
        vint(&mut file, 0x04); // file flags: a CRC32 of the bytes
        vint(&mut file, size);
        vint(&mut file, 0); // attributes
        file.extend_from_slice(&crc32fast::hash(data).to_le_bytes());
        vint(&mut file, u64::from(*solid) << 6); // stored, version 0
        vint(&mut file, 1); // host: Unix
        vint(&mut file, name.len() as u64);
        file.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&block(&file));
        out.extend_from_slice(data);
    }
    let mut end = Vec::new();
    vint(&mut end, 5); // type: end of archive
    vint(&mut end, 0); // header flags
    vint(&mut end, 0); // the last volume
    out.extend_from_slice(&block(&end));
    out
}

#[test]
fn a_missing_chain_head_on_the_solid_decode_ahead_ends_as_the_sequential_path_does() {
    let bodies: Vec<Vec<u8>> = (0..5)
        .map(|k| rarkit_testdata::chatter((70 + k as u32) as u64, 20_000 + k * 311))
        .collect();
    let names = ["c0", "c1", "c2", "c3", "c4"];
    let members: Vec<Stored<'_>> = names
        .iter()
        .zip(&bodies)
        .map(|(name, body)| (*name, body.as_slice(), true))
        .collect();
    let archive = later_solid_volume(&members);
    for hands in [true, false] {
        let label = format!("a missing chain head (ranges handed {hands})");
        let want = every_lap_matches(&label, archive.clone(), &file_opts(), hands);
        assert_eq!(want.0.len(), members.len(), "{label}: {}", want.1);
        assert!(
            want.1.starts_with("err Corrupt(Stream)"),
            "{label}: {}",
            want.1
        );
        for record in &want.0 {
            assert_eq!(record.2, Some(false), "{label}: {}'s verdict", record.0);
            assert!(
                record.1.is_none(),
                "{label}: {} was given a writer",
                record.0
            );
        }
    }
}

/// Refused members and, after them, members that extract: on the defect
/// the caller's thread took none of the later members, their bytes had
/// nowhere to go, and the walk waited on them for ever (in the queue's
/// budget, or on a handed range nobody would read). Read under a bound.
#[test]
fn members_that_extract_after_a_refused_one_are_delivered_and_nothing_hangs() {
    let lost = rarkit_testdata::chatter(90, 10_000);
    // Over twice the solid queue (4 MiB at the working limit stated below),
    // so a walk nobody reads from cannot finish it.
    let big = rarkit_testdata::chatter(91, 9 * MIB);
    let small = rarkit_testdata::chatter(92, 5_000);
    let archive = later_solid_volume(&[
        ("lost0", &lost, true),
        ("lost1", &lost, true),
        ("big", &big, false),
        ("small", &small, true),
    ]);
    let mut opts = file_opts();
    opts.memory.working_limit = 16 * MIB as u64;
    for hands in [true, false] {
        let label = format!("a mixed solid volume (ranges handed {hands})");
        let want = every_lap_matches(&label, archive.clone(), &opts, hands);
        assert!(
            want.1.starts_with("err Corrupt(Stream)"),
            "{label}: {}",
            want.1
        );
        let seen: Vec<(&str, Option<bool>, Option<usize>)> = want
            .0
            .iter()
            .map(|r| (r.0.as_str(), r.2, r.1.as_ref().map(Vec::len)))
            .collect();
        assert_eq!(
            seen,
            [
                ("lost0", Some(false), None),
                ("lost1", Some(false), None),
                ("big", Some(true), Some(big.len())),
                ("small", Some(true), Some(small.len())),
            ],
            "{label}"
        );
        assert!(
            want.0[2].1.as_deref() == Some(big.as_slice()),
            "{label}: big's bytes"
        );
    }
}
