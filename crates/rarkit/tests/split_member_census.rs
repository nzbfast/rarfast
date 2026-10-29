//! Where each member of a volume set whose members straddle its
//! boundaries is decoded: on the walking thread, or on a worker.
//!
//! Eight members of 6 MiB and a bit in volumes of 10 MiB and a bit, so
//! most members cross a boundary, four ways: stored, compressed, encrypted
//! stored and encrypted compressed. Through `extract_parallel` with every
//! split member a job (`extract::split_job_kind`), NO member is decoded on
//! the walking thread whatever its method or encryption; with only stored
//! clear split jobs (the rule before 30 Sep 2026), every split compressed
//! or encrypted member was. The shipped default takes the compressed ones
//! and leaves an encrypted stored one to the rule before. Run with
//! `--nocapture` for the table.

#![cfg(feature = "test-support")]

use std::sync::Arc;

use rarkit::{
    extract_parallel, probe, Disposition, MemberInfo, MemberOutcome, MemberSpec, ParallelSink,
    Password, Payload, RangeSource, ReadOptions, Result, WriteMethod, WriteOptions, Writer,
};

const MEMBER_LEN: usize = (6 << 20) + 333;
const PER: u64 = (10 << 20) + 7;

/// Half noise, half text, so a compressed member is worth decoding.
fn member(i: usize) -> Vec<u8> {
    let mut x = (41 + i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..MEMBER_LEN)
        .map(|n| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            if (n >> 12) & 1 == 0 {
                (x >> 24) as u8
            } else {
                b"the quick brown fox "[(x % 20) as usize]
            }
        })
        .collect()
}

fn many(method: WriteMethod, password: Option<&str>) -> Vec<Vec<u8>> {
    let mut writer = Writer::new(WriteOptions {
        volume_size: Some(PER),
        method,
        password: password.map(Password::from),
        ..WriteOptions::default()
    })
    .expect("options");
    let parts: Vec<Vec<u8>> = (0..8).map(member).collect();
    let names: Vec<String> = (0..8).map(|i| format!("E0{i}.mkv")).collect();
    for (data, name) in parts.iter().zip(&names) {
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
    let mut out: Vec<Vec<u8>> = Vec::new();
    writer.finish_volumes(&mut out).expect("finish");
    out
}

struct Null;
impl std::io::Write for Null {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Par;
impl ParallelSink for Par {
    type Out = Null;
    fn open(&self, _: &MemberInfo<'_>) -> Result<Disposition<Null>> {
        Ok(Disposition::Write(Null))
    }
    fn close(&self, _: &MemberInfo<'_>, _: Option<Null>, o: &MemberOutcome) -> Result<()> {
        assert_eq!(o.checksum_ok, Some(true));
        Ok(())
    }
}

fn sources(set: &[Vec<u8>]) -> Vec<Arc<dyn RangeSource>> {
    set.iter()
        .map(|v| Arc::new(v.clone()) as Arc<dyn RangeSource>)
        .collect()
}

/// Members decoded on the walking thread and split jobs taken.
fn count(set: &[Vec<u8>], options: &ReadOptions, all: Option<bool>) -> (u64, u64) {
    probe::set_split_jobs_all(all);
    probe::reset();
    probe::reset_split_jobs_taken();
    extract_parallel(sources(set), options, &Par, 8).expect("a whole set reads");
    let counted = (probe::decoded_members(), probe::split_jobs_taken());
    probe::set_split_jobs_all(None);
    counted
}

#[test]
fn no_member_of_a_split_set_decodes_on_the_walk() {
    let m3 = WriteMethod::Compressed {
        level: 3,
        dictionary: None,
    };
    let shapes: [(&str, WriteMethod, Option<&str>); 4] = [
        ("stored", WriteMethod::Stored, None),
        ("m3", m3, None),
        ("-p stored", WriteMethod::Stored, Some("pw")),
        ("-p m3", m3, Some("pw")),
    ];
    eprintln!("shape | volumes | rule | walk-decoded | split jobs");
    for (label, method, password) in shapes {
        let set = many(method, password);
        let options = ReadOptions::default()
            .with_workers(Some(8))
            .with_sink_is_file(Some(true))
            .with_password(password.map(Password::from));
        let (old_walk, old_jobs) = count(&set, &options, Some(false));
        let (new_walk, new_jobs) = count(&set, &options, Some(true));
        let shipped = count(&set, &options, None);
        eprintln!(
            "{label} | {} | stored only | {old_walk} | {old_jobs}",
            set.len()
        );
        eprintln!("{label} | {} | all | {new_walk} | {new_jobs}", set.len());
        eprintln!(
            "{label} | {} | default | {} | {}",
            set.len(),
            shipped.0,
            shipped.1
        );
        // The default takes every split member but an encrypted STORED
        // one, which keeps the rule before (`extract::SplitJobs::DEFAULT`).
        let encrypted_stored = password.is_some() && matches!(method, WriteMethod::Stored);
        if encrypted_stored {
            assert_eq!(shipped, (old_walk, old_jobs), "{label}: the default");
        } else {
            assert_eq!(shipped, (new_walk, new_jobs), "{label}: the default");
        }
        // Every boundary but possibly one falls inside a member.
        assert!(new_jobs + 2 >= set.len() as u64, "{label}: {new_jobs} jobs");
        assert_eq!(new_walk, 0, "{label}: members decoded on the walk");
        let clear_stored = password.is_none() && matches!(method, WriteMethod::Stored);
        if clear_stored {
            assert_eq!((old_walk, old_jobs), (new_walk, new_jobs), "{label}");
        } else {
            assert_eq!(old_jobs, 0, "{label}");
            assert_eq!(old_walk, new_jobs, "{label}: the split members");
        }
    }
}
