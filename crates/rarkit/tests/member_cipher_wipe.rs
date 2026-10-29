//! NO HANDLE ON A KEY'S SCHEDULES OUTLIVES THE READ THAT ASKED FOR THE KEY
//! (SPEC-K 7, zeroisation on drop).
//!
//! A key's decryption schedules are one value behind a shared handle
//! (`crypto::cbc::Schedule`): the key cache's slot holds it, and a member,
//! the chains of a member read on several threads, and an opened archive's
//! header reader hold others. The schedules are wiped when the LAST handle
//! goes, so the rule rests on where a read drops its last one. The key
//! cache is part of the read's context, which is a local of every free
//! read call and a field of the caller's `Session`: the operation that
//! asked for a key is that call, or the session's life.
//!
//! This pins it from outside, by this crate's own writer and reader and
//! the counted hook (`schedules_made_and_wiped`: every schedule made by
//! the process and every one wiped, on any thread), never by reading freed
//! memory:
//!
//! - after a free `extract` call has returned, checking or writing, at a
//!   width of one and at four (where the member is deciphered in pieces on
//!   other threads), every schedule the call made has been wiped;
//! - a `Session` that reads seventeen archives under seventeen salts
//!   evicts a key from its sixteen slots, and the evicted key's schedules
//!   are wiped at the eviction even though the archive they opened is
//!   still open (an opened archive holds no handle); the schedules alive
//!   are exactly the sixteen cached keys', and once the session is
//!   dropped none is.
//!
//! PINNED ONLY AT THE CRYPTO LEVEL, AND WHY: a MEMBER that is still being
//! deciphered when its key is evicted (it keeps the schedules and they
//! are wiped at its end:
//! `crypto::tests::a_member_that_outlives_the_key_cache_wipes_the_schedules_at_its_own_end`).
//! This crate's writer gives an archive one salt, so no archive this test
//! can make evicts a key under a live member, and nothing else a caller
//! can keep past an eviction (an opened archive, here) holds a handle.
//!
//! ONE TEST, IN A BINARY OF ITS OWN, because the count is the process's:
//! beside any other test that makes a chain it would read that test's
//! schedules too.

#![cfg(all(feature = "test-support", feature = "bench-internals"))]

use std::sync::Arc;

use rarkit::internals::crypto::{schedules_made_and_wiped, CACHE_SLOTS};
use rarkit::{
    extract, probe, Disposition, MemberInfo, MemberOutcome, MemberSpec, Password, Payload,
    Progress, RangeSource, ReadOptions, Result, Session, Sink, WriteOptions, Writer,
};

const SECRET: &str = "wipe-pin";
/// Large enough to be read in pieces at a width of four, and not whole
/// blocks.
const LARGE: usize = (72 << 20) + 5;

/// Incompressible, deterministic bytes: a 64-bit multiply and add
/// generator of this test's own, its top byte taken each step.
fn noise(n: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
    (0..n)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 56) as u8
        })
        .collect()
}

/// One stored member of `len` bytes, encrypted, its headers too where
/// `headers`, by this crate's own writer: one archive, one salt.
fn encrypted(len: usize, headers: bool, seed: u64) -> Vec<u8> {
    let data = noise(len, seed);
    let mut writer = Writer::new(WriteOptions {
        password: Some(Password::from(SECRET)),
        encrypt_headers: headers,
        ..WriteOptions::default()
    })
    .expect("options");
    writer
        .add(MemberSpec {
            name: b"member.bin",
            payload: Payload::Bytes(&data),
            mtime: None,
            attributes: 0,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut one = Vec::new();
    writer.finish_into(&mut one).expect("finish");
    one
}

/// Checks every member, or writes it to memory where `written`.
struct Reads {
    written: bool,
    ok: usize,
    bytes: usize,
}

impl Sink for Reads {
    type Out = Vec<u8>;

    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        Ok(if self.written {
            Disposition::Write(Vec::new())
        } else {
            Disposition::Verify
        })
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        if let Some(out) = out {
            self.bytes += out.len();
        }
        if outcome.checksum_ok == Some(true) && !outcome.password_refused {
            self.ok += 1;
        }
        Ok(())
    }
}

struct Quiet;

impl Progress for Quiet {
    fn released(&mut self, _volume: u32, _offset: u64) -> Result<()> {
        Ok(())
    }

    fn volume_done(&mut self, _volume: u32) -> Result<()> {
        Ok(())
    }
}

fn options(workers: usize) -> ReadOptions {
    ReadOptions::default()
        .with_workers(Some(workers))
        .with_sink_is_file(Some(false))
        .with_password(Some(Password::from(SECRET)))
}

/// Schedules alive now: made and not yet wiped.
fn alive() -> u64 {
    let (made, wiped) = schedules_made_and_wiped();
    made - wiped
}

#[test]
fn every_schedule_a_read_made_is_wiped_when_the_read_has_ended() {
    // The writer enciphers and makes no decryption schedule; whatever the
    // process holds before the first read is none.
    assert_eq!(alive(), 0, "a schedule alive before any read");

    // (a) A free call: the read's context is its local.
    for headers in [false, true] {
        let archive = encrypted(LARGE, headers, 7 + u64::from(headers));
        for workers in [1usize, 4] {
            for written in [false, true] {
                let what = format!("headers {headers}, width {workers}, written {written}");
                let (made_before, _) = schedules_made_and_wiped();
                probe::reset_wide_verifies();
                let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(archive.clone())];
                let mut sink = Reads {
                    written,
                    ok: 0,
                    bytes: 0,
                };
                extract(sources, &options(workers), &mut sink, &mut Quiet)
                    .unwrap_or_else(|e| panic!("{what}: {:?}", e.kind()));
                assert_eq!(sink.ok, 1, "{what}");
                if written {
                    assert_eq!(sink.bytes, LARGE, "{what}");
                } else if workers == 4 {
                    assert!(
                        probe::wide_verifies() >= 1,
                        "{what}: nothing was read in pieces"
                    );
                }
                let (made, _) = schedules_made_and_wiped();
                assert!(
                    made > made_before,
                    "{what}: the read made no schedule, so it pins nothing"
                );
                assert_eq!(
                    alive(),
                    0,
                    "{what}: a schedule outlived the call that asked for its key"
                );
            }
        }
    }

    // (b) A session: the read's context is the session's, and its key
    // cache has CACHE_SLOTS slots. One archive more than that, each under
    // a salt of its own, evicts the first archive's key while that archive
    // is still open.
    let archives: Vec<Vec<u8>> = (0..=CACHE_SLOTS as u64)
        .map(|i| encrypted(4096 + 5, true, 100 + i))
        .collect();
    let (made_before, _) = schedules_made_and_wiped();
    let mut session = Session::new(options(1));
    let first = session
        .open(Arc::new(archives[0].clone()) as Arc<dyn RangeSource>)
        .expect("open the first archive");
    assert_eq!(schedules_made_and_wiped().0 - made_before, 1);
    for archive in &archives[1..] {
        let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(archive.clone())];
        let mut sink = Reads {
            written: false,
            ok: 0,
            bytes: 0,
        };
        session
            .extract(sources, &mut sink, &mut Quiet)
            .expect("a session read");
        assert_eq!(sink.ok, 1);
    }
    // One schedule a salt, none made twice.
    assert_eq!(
        schedules_made_and_wiped().0 - made_before,
        CACHE_SLOTS as u64 + 1
    );
    // The cache holds CACHE_SLOTS keys. The evicted key's schedules were
    // wiped at the eviction: the archive it opened, still open here,
    // holds no handle on them.
    assert_eq!(
        alive(),
        CACHE_SLOTS as u64,
        "the evicted key's schedules outlived the eviction"
    );
    drop(first);
    assert_eq!(alive(), CACHE_SLOTS as u64);
    drop(session);
    assert_eq!(alive(), 0, "a schedule outlived its session");
}
