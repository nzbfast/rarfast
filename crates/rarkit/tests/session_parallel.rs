//! `Session::extract_parallel` (SPEC-API 4.2, erratum of 25 Sep 2026):
//! `extract_parallel` reading through a session the caller kept, so that a
//! set the session already opened is not keyed a second time.
//!
//! What a test can see of that is everything EXCEPT the saved derivation,
//! which is counted at the key cache on the CLI instead.
//! So these hold the rest of the
//! erratum's sentence: the bytes, the check values, the refusal of a
//! breadth of zero and the wrong-password verdict are the free function's,
//! whether the session has opened the set first or not.

#![cfg(feature = "parallel")]

use std::sync::{Arc, Mutex};

use rarkit::{
    extract_parallel, Archive, Disposition, ErrorKind, MemberInfo, MemberOutcome, MemberSpec,
    ParallelSink, Password, Payload, RangeSource, ReadOptions, Result, Session, WriteFormat,
    WriteMethod, WriteOptions, Writer,
};

const PASSWORD: &[u8] = b"k-hp one session";

/// Four members, non-solid, so that the concurrent walk decodes them on
/// workers rather than on the walking thread.
fn members() -> Vec<(Vec<u8>, Vec<u8>)> {
    (0..4u32)
        .map(|i| {
            let name = format!("m{i}.txt").into_bytes();
            let body = format!("member {i} of a header-encrypted set. ")
                .repeat(3000 + 500 * i as usize)
                .into_bytes();
            (name, body)
        })
        .collect()
}

/// A RAR 5 archive with encrypted headers, written by this crate.
fn archive(wanted: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut writer = Writer::new(WriteOptions {
        format: WriteFormat::Rar5,
        method: WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
        solid: false,
        password: Some(Password::new(PASSWORD)),
        encrypt_headers: true,
        host_os: rarkit::HostOs::Unix,
        ..WriteOptions::default()
    })
    .expect("options");
    for (name, data) in wanted {
        writer
            .add(MemberSpec {
                name,
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

fn options(password: &[u8]) -> ReadOptions {
    ReadOptions::default().with_password(Some(Password::new(password)))
}

/// One member as the sink saw it: name, bytes, check verdict.
type Got = (Vec<u8>, Vec<u8>, Option<bool>);

/// Every member as the sink saw it, in `close` order.
#[derive(Default)]
struct Collect {
    got: Mutex<Vec<Got>>,
}

impl ParallelSink for Collect {
    type Out = Vec<u8>;

    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.got.lock().expect("the sink's own lock").push((
            member.name.to_vec(),
            out.unwrap_or_default(),
            outcome.checksum_ok,
        ));
        Ok(())
    }
}

impl Collect {
    fn into_got(self) -> Vec<Got> {
        self.got.into_inner().expect("the sink's own lock")
    }
}

#[test]
fn a_session_that_opened_the_set_extracts_it_as_the_free_function_does() {
    let wanted = members();
    let bytes = archive(&wanted);

    let free = Collect::default();
    let free_report =
        extract_parallel(sources(&bytes), &options(PASSWORD), &free, 4).expect("free");

    let mut session = Session::new(options(PASSWORD));
    // The set's headers are enciphered: without the password it does not
    // even open, and with it the archive says so.
    assert!(
        Archive::open(Arc::new(bytes.clone()), &ReadOptions::default()).is_err(),
        "the set under test is -hp"
    );
    assert!(
        Archive::open(Arc::new(bytes.clone()), &options(PASSWORD))
            .expect("open with the password")
            .headers_encrypted(),
        "headers_encrypted answers on RAR 5"
    );
    session.open(Arc::new(bytes.clone())).expect("open");
    let kept = Collect::default();
    let kept_report = session
        .extract_parallel(sources(&bytes), &kept, 4)
        .expect("through the session");

    let free = free.into_got();
    let kept = kept.into_got();
    assert_eq!(
        kept, free,
        "the same members, bytes, verdicts and close order"
    );
    assert_eq!(kept_report.members, free_report.members);
    assert_eq!(kept_report.bytes, free_report.bytes);
    assert_eq!(kept_report.checksum_failures, 0);
    let expected: Vec<_> = wanted
        .into_iter()
        .map(|(name, body)| (name, body, Some(true)))
        .collect();
    assert_eq!(kept, expected, "and they are what was written");
}

#[test]
fn a_fresh_session_extracts_as_one_that_opened_first() {
    let bytes = archive(&members());
    let mut fresh = Session::new(options(PASSWORD));
    let first = Collect::default();
    fresh
        .extract_parallel(sources(&bytes), &first, 4)
        .expect("fresh session");
    // The same session again: its keys are warm now, and nothing else is
    // allowed to differ.
    let again = Collect::default();
    fresh
        .extract_parallel(sources(&bytes), &again, 4)
        .expect("warm session");
    assert_eq!(first.into_got(), again.into_got());
}

#[test]
fn a_breadth_of_zero_is_refused_as_the_free_function_refuses_it() {
    let bytes = archive(&members());
    let mut session = Session::new(options(PASSWORD));
    session.open(Arc::new(bytes.clone())).expect("open");
    let err = session
        .extract_parallel(sources(&bytes), &Collect::default(), 0)
        .expect_err("zero workers");
    let free = extract_parallel(sources(&bytes), &options(PASSWORD), &Collect::default(), 0)
        .expect_err("zero workers, free");
    assert!(matches!(
        err.kind(),
        ErrorKind::LimitExceeded {
            resource: rarkit::Resource::Workers,
            ..
        }
    ));
    assert_eq!(format!("{:?}", err.kind()), format!("{:?}", free.kind()));
}

#[test]
fn a_wrong_password_gets_the_free_functions_verdict() {
    let bytes = archive(&members());
    let free = extract_parallel(sources(&bytes), &options(b"wrong"), &Collect::default(), 4)
        .expect_err("wrong password, free");
    let mut session = Session::new(options(b"wrong"));
    let kept = session
        .extract_parallel(sources(&bytes), &Collect::default(), 4)
        .expect_err("wrong password, session");
    assert_eq!(format!("{:?}", kept.kind()), format!("{:?}", free.kind()));
}
