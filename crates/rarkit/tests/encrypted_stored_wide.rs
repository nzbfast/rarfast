//! The wide read of an ENCRYPTED stored member (SPEC-K 2.1,
//! 3.7.4): a RAR 5 member stored under `-p` or `-hp`, checked (`t`) or
//! written (`p`, `x`), is read, deciphered and hashed on several threads,
//! each piece from the ciphertext block in front of it, and says and
//! writes exactly what the ordinary loop says and writes.
//!
//! Every case reads the set twice, at a width of one (the ordinary loop:
//! `read::wide::plan` refuses a width under two) and at a width of four,
//! and asserts the wide arm really went wide before it compares anything.
//! The volume size is chosen so that fragments are NOT whole cipher
//! blocks (a fragment need not be, SPEC-K 3.7.4), and the member's length
//! is not one either, so its last block is padded (spec F 4.2); the tests
//! that need it assert a block really was finished across a fragment
//! boundary.

#![cfg(feature = "test-support")]

use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use rarkit::{
    extract, probe, Disposition, ErrorKind, MemberInfo, MemberOutcome, MemberSpec, Password,
    Payload, Progress, RangeSource, ReadOptions, Result, Sink, WriteOptions, Writer,
};

const SECRET: &str = "hpwide";
/// Neither whole blocks nor whole pieces: the last block is padded, and
/// the last piece is short.
const LEN: usize = (72 << 20) + 5;
/// Not a multiple of 16, so the fragments are not whole blocks.
const PER: u64 = (20 << 20) + 7;

/// Incompressible, deterministic bytes.
fn noise(n: usize) -> Vec<u8> {
    let mut x: u64 = 0x2929_0929_7f4a_7c15;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// One stored member of `len` bytes, encrypted, its headers too where
/// `headers`, in volumes of `per` bytes (or one archive), by this crate's
/// own writer.
fn encrypted_set(len: usize, per: Option<u64>, headers: bool) -> Vec<Vec<u8>> {
    let data = noise(len);
    let mut writer = Writer::new(WriteOptions {
        volume_size: per,
        password: Some(Password::from(SECRET)),
        encrypt_headers: headers,
        ..WriteOptions::default()
    })
    .expect("options");
    writer
        .add(MemberSpec {
            name: b"Full.mkv",
            payload: Payload::Bytes(&data),
            mtime: None,
            attributes: 0,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    if per.is_none() {
        let mut one = Vec::new();
        writer.finish_into(&mut one).expect("finish");
        return vec![one];
    }
    let mut out: Vec<Vec<u8>> = Vec::new();
    writer.finish_volumes(&mut out).expect("finish");
    assert!(out.len() >= 3, "a set of {} volumes", out.len());
    out
}

/// A writer that refuses after `limit` bytes, as a full disk would.
struct Capped {
    bytes: Vec<u8>,
    limit: Option<usize>,
}

impl Write for Capped {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self
            .limit
            .is_some_and(|l| self.bytes.len() + data.len() > l)
        {
            return Err(std::io::Error::other("full"));
        }
        self.bytes.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct Verdicts {
    outcomes: Vec<(Vec<u8>, MemberOutcome)>,
    written: bool,
    limit: Option<usize>,
    bytes: Vec<Vec<u8>>,
}

impl Sink for Verdicts {
    type Out = Capped;

    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Capped>> {
        Ok(if self.written {
            Disposition::Write(Capped {
                bytes: Vec::new(),
                limit: self.limit,
            })
        } else {
            Disposition::Verify
        })
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Capped>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        if let Some(out) = out {
            self.bytes.push(out.bytes);
        }
        self.outcomes.push((member.name.to_vec(), *outcome));
        Ok(())
    }
}

/// The drop-behind reports, which must stay monotone per volume.
#[derive(Default)]
struct Trail {
    done: Vec<u32>,
    released: Vec<(u32, u64)>,
}

impl Progress for Trail {
    fn released(&mut self, volume: u32, offset: u64) -> Result<()> {
        if let Some(&(v, last)) = self.released.iter().rev().find(|(v, _)| *v == volume) {
            assert!(offset >= last, "released went backwards on volume {v}");
        }
        self.released.push((volume, offset));
        Ok(())
    }

    fn volume_done(&mut self, volume: u32) -> Result<()> {
        self.done.push(volume);
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
struct Said {
    outcomes: std::result::Result<Vec<(Vec<u8>, MemberOutcome)>, String>,
    done: Vec<u32>,
    /// A digest of every written byte, in order.
    written: Vec<(usize, u32)>,
}

/// How one read went: what it said, how many ranges went wide and how
/// many blocks were finished across a fragment boundary.
struct Read {
    said: Said,
    wide: u64,
    joins: u64,
}

#[derive(Clone, Copy)]
struct How {
    workers: usize,
    written: bool,
    sink_is_file: Option<bool>,
    password: &'static str,
    limit: Option<usize>,
    cancel_now: bool,
}

const T: How = How {
    workers: 4,
    written: false,
    sink_is_file: None,
    password: SECRET,
    limit: None,
    cancel_now: false,
};
/// `p`: a writer the caller says is not a file.
const P: How = How {
    written: true,
    sink_is_file: Some(false),
    ..T
};
/// `x`: a writer that is a file.
const X: How = How {
    written: true,
    sink_is_file: Some(true),
    ..T
};

fn read(volumes: &[Vec<u8>], how: How) -> Read {
    let sources: Vec<Arc<dyn RangeSource>> = volumes
        .iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect();
    let cancel = how.cancel_now.then(|| Arc::new(AtomicBool::new(true)));
    let options = ReadOptions::default()
        .with_workers(Some(how.workers))
        .with_sink_is_file(how.sink_is_file)
        .with_password(Some(Password::from(how.password)))
        .with_cancel(cancel);
    let mut sink = Verdicts {
        written: how.written,
        limit: how.limit,
        ..Verdicts::default()
    };
    let mut trail = Trail::default();
    probe::reset_wide_verifies();
    probe::reset_wide_block_joins();
    let outcome = extract(sources, &options, &mut sink, &mut trail);
    let wide = probe::wide_verifies();
    let joins = probe::wide_block_joins();
    let outcomes = match outcome {
        Ok(_) => Ok(sink.outcomes),
        Err(e) => Err(format!(
            "{:?} member {:?} volume {:?}",
            e.kind(),
            e.member().map(<[u8]>::to_vec),
            e.volume()
        )),
    };
    let written = sink
        .bytes
        .iter()
        .map(|b| (b.len(), rarkit::checksum::crc32(b)))
        .collect();
    Read {
        said: Said {
            outcomes,
            done: trail.done,
            written,
        },
        wide,
        joins,
    }
}

/// The same read at a width of one and at four: the wide one went wide,
/// the narrow one did not, and they said the same.
fn both(volumes: &[Vec<u8>], how: How) -> Read {
    let narrow = read(volumes, How { workers: 1, ..how });
    let wide = read(volumes, how);
    assert_eq!(narrow.wide, 0, "a width of one never goes wide");
    assert!(wide.wide >= 1, "nothing went wide");
    assert_eq!(wide.said, narrow.said);
    wide
}

fn whole(read: &Read) {
    let outcomes = read.said.outcomes.as_ref().expect("a whole set reads");
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].1.checksum_ok, Some(true));
    assert_eq!(outcomes[0].1.bytes, LEN as u64);
}

fn stored_bytes(read: &Read) {
    assert_eq!(
        read.said.written,
        vec![(LEN, rarkit::checksum::crc32(&noise(LEN)))],
        "the written bytes are the stored ones"
    );
}

#[test]
fn a_split_p_set_tests_wide_across_unaligned_fragments() {
    let set = encrypted_set(LEN, Some(PER), false);
    let read = both(&set, T);
    whole(&read);
    assert!(read.wide >= 3, "only {} ranges went wide", read.wide);
    assert!(
        read.joins >= 1,
        "no block was finished across a fragment boundary: the set does not test one"
    );
}

#[test]
fn a_split_hp_set_writes_the_stored_bytes_wide_for_p_and_x() {
    let set = encrypted_set(LEN, Some(PER), true);
    for how in [P, X] {
        let read = both(&set, how);
        whole(&read);
        stored_bytes(&read);
        assert!(read.joins >= 1, "no block finished across a boundary");
    }
}

#[test]
fn one_encrypted_archive_goes_wide_for_t_p_and_x() {
    for headers in [false, true] {
        let set = encrypted_set(LEN, None, headers);
        for how in [T, P, X] {
            let read = both(&set, how);
            whole(&read);
            if how.written {
                stored_bytes(&read);
            }
        }
    }
}

/// `x` where the caller says nothing of its writer takes the wide read
/// too, as an encrypted member's serial read is its cipher.
#[test]
fn an_unsaid_writer_goes_wide_for_an_encrypted_member() {
    let set = encrypted_set(LEN, Some(PER), false);
    let read = both(
        &set,
        How {
            sink_is_file: None,
            ..X
        },
    );
    stored_bytes(&read);
}

#[test]
fn a_flipped_ciphertext_byte_fails_the_same_way_both_ways() {
    for headers in [false, true] {
        let mut set = encrypted_set(LEN, Some(PER), headers);
        let middle = set.len() / 2;
        let at = set[middle].len() / 2;
        set[middle][at] ^= 0x01;
        for how in [T, P] {
            let read = both(&set, how);
            if let Ok(outcomes) = &read.said.outcomes {
                assert_eq!(outcomes[0].1.checksum_ok, Some(false));
            }
        }
    }
}

#[test]
fn a_cut_middle_volume_ends_the_same_way_both_ways() {
    let mut set = encrypted_set(LEN, Some(PER), true);
    let middle = set.len() / 2;
    let keep = set[middle].len() / 3;
    set[middle].truncate(keep);
    for how in [T, P] {
        let read = both(&set, how);
        assert!(read.said.outcomes.is_err(), "a cut set is an error");
    }
}

/// A wrong password is refused by the check record before any byte is
/// deciphered (SPEC-K 3.7.3), at `-p` and at `-hp`, whatever the width.
#[test]
fn a_wrong_password_is_refused_the_same_way_at_p_and_hp() {
    for headers in [false, true] {
        let set = encrypted_set(LEN, Some(PER), headers);
        for how in [T, P] {
            let wrong = How {
                password: "not-it",
                ..how
            };
            let narrow = read(
                &set,
                How {
                    workers: 1,
                    ..wrong
                },
            );
            let wide = read(&set, wrong);
            assert_eq!(wide.said, narrow.said);
            assert_eq!(wide.wide, 0, "a wrong password deciphers nothing");
            let said = format!("{:?}", wide.said.outcomes);
            assert!(
                said.contains(&format!("{:?}", ErrorKind::WrongPassword)),
                "headers {headers}: {said}"
            );
        }
    }
}

/// A writer that refuses part way (SPEC-F 3.7.6): the operation ends with
/// the writer's error, the same prefix written both ways, and the wide
/// read's threads joined before `extract` returns.
#[test]
fn a_refusing_writer_stops_the_wide_read_mid_member() {
    let set = encrypted_set(LEN, Some(PER), true);
    let limit = (30 << 20) + 3;
    let how = How {
        limit: Some(limit),
        ..P
    };
    let read = both(&set, how);
    assert!(read.said.outcomes.is_err(), "a refusing writer is an error");
}

/// A cancel already raised stops the member at its first tally both ways.
#[test]
fn a_raised_cancel_stops_both_ways() {
    let set = encrypted_set(LEN, Some(PER), false);
    let how = How {
        cancel_now: true,
        ..T
    };
    let narrow = read(&set, How { workers: 1, ..how });
    let wide = read(&set, how);
    assert_eq!(wide.said, narrow.said);
    let said = format!("{:?}", wide.said.outcomes);
    assert!(said.contains("Cancelled"), "{said}");
}
