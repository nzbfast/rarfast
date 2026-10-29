//! Small member batches never exceed their member count or their byte cap,
//! and they are actually sent: a batch arm that fell back to one member at
//! a time, or to the walking thread, would pass every equivalence test.
//!
//! In a test binary of its own, with ONE test in it, because the counters
//! it reads (`rarkit::probe::peak_batch`) are process-wide.

#![cfg(all(feature = "parallel", feature = "test-support"))]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use rarkit::{
    extract_parallel, Disposition, MemberInfo, MemberOutcome, ParallelSink, RangeSource,
    ReadOptions, Result,
};

struct Sink(Mutex<Vec<Vec<u8>>>);

impl ParallelSink for Sink {
    type Out = Vec<u8>;
    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Vec::new()))
    }
    fn close(&self, member: &MemberInfo<'_>, _: Option<Vec<u8>>, _: &MemberOutcome) -> Result<()> {
        self.0.lock().expect("lock").push(member.name.to_vec());
        Ok(())
    }
}

fn legacy(name: &str) -> Vec<u8> {
    let path = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/legacy/archives"
    ))
    .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn a_batch_never_holds_more_than_its_members_or_its_cap() {
    rarkit::probe::set_offload_floor(None);
    let bytes = legacy("r550_m3.rar");
    // The read's width stated: without a workers figure it is the pool's
    // own, and a read two wide sends no batch of two members.
    let opts = ReadOptions::default().with_workers(Some(4));
    let members = rarkit::Archive::open(Arc::new(bytes.clone()) as Arc<dyn RangeSource>, &opts)
        .expect("open")
        .members()
        .filter(|m| !m.is_directory && m.unpacked_size.is_some_and(|n| n > 0))
        .count();
    assert!(members >= 4, "this test needs several small members");
    let run = || {
        rarkit::probe::reset_peak_batch();
        let sink = Sink(Mutex::new(Vec::new()));
        extract_parallel(
            vec![Arc::new(bytes.clone()) as Arc<dyn RangeSource>],
            &opts,
            &sink,
            4,
        )
        .expect("parallel");
        rarkit::probe::peak_batch()
    };
    // The DEFAULT, which is per ARCHITECTURE, is pinned in
    // `small_batch_default.rs`, one test per architecture.
    // Off is off: no batch at all.
    rarkit::probe::set_small_batch(Some((0, 0)));
    assert_eq!(run().2, 0, "a batch was sent with batches off");
    for (count, cap) in [
        (2usize, 64u64 << 10),
        (4, 256 << 10),
        (64, 1 << 20),
        (64, 4 << 10),
    ] {
        rarkit::probe::set_small_batch(Some((count, cap)));
        rarkit::probe::reset_peak_batch();
        let sink = Sink(Mutex::new(Vec::new()));
        extract_parallel(
            vec![Arc::new(bytes.clone()) as Arc<dyn RangeSource>],
            &opts,
            &sink,
            4,
        )
        .expect("parallel");
        let (most, most_bytes, sent) = rarkit::probe::peak_batch();
        assert!(sent >= 1, "({count}, {cap}): no batch was ever sent");
        assert!(
            most <= count,
            "({count}, {cap}): a batch held {most} members"
        );
        assert!(
            most_bytes <= cap,
            "({count}, {cap}): a batch held {most_bytes} declared bytes"
        );
        if count >= 2 && cap >= 64 << 10 {
            assert!(most >= 2, "({count}, {cap}): no batch held two members");
        }
    }
    rarkit::probe::set_small_batch(None);
}
