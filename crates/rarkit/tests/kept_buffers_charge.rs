//! What a written stored range keeps for the range after it is CHARGED to
//! the operation while it is kept, is bounded by the read-ahead window,
//! and is gone when the extraction returns.
//!
//! A range that is written to a file reads through buffers of its own (a
//! slab, and the pieces lent to its readers). They are left with the
//! extraction's team at the range's end for the next range to take
//! (`read::team`), because made and freed a range they are faulted in
//! again a range later. So between two ranges the engine holds them, and
//! the counters say so: this test reads `memory::current()` where one
//! member has closed and the next has not begun, which is between ranges,
//! and again after the extraction has returned.
//!
//! THREADS AND MEMORY. The read runs on the test's own rayon pool of
//! exactly [`WIDTH`] threads with `ReadOptions::workers` stated as
//! [`WIDTH`], under `MemoryPolicy::default()`, whose read-ahead window is
//! the bound's unit. ONE test function: the counters are the process's.

#![cfg(feature = "parallel")]

use std::sync::Arc;

use rarkit::{
    extract, memory, Disposition, MemberInfo, MemberOutcome, MemberSpec, MemoryPolicy, Password,
    Payload, RangeSource, ReadOptions, Result, Sink, WriteOptions, Writer,
};

const SECRET: &str = "kept";
const WIDTH: usize = 4;
/// Two members, each several ranges over the wide read's floor of 16 MiB.
const MEMBER: usize = 44 << 20;
/// Not whole blocks.
const PER: u64 = (20 << 20) + 7;

fn noise(n: usize, seed: u64) -> Vec<u8> {
    let mut x: u64 = 0x2929_0929_7f4a_7c15 ^ seed;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

fn encrypted_set() -> Vec<Vec<u8>> {
    let members: Vec<(String, Vec<u8>)> = (0..2)
        .map(|k| (format!("Full.{k}.mkv"), noise(MEMBER, k as u64 + 1)))
        .collect();
    let mut writer = Writer::new(WriteOptions {
        volume_size: Some(PER),
        password: Some(Password::from(SECRET)),
        ..WriteOptions::default()
    })
    .expect("options");
    for (name, data) in &members {
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

/// Writes every member to nowhere, and reads the counters as each closes.
struct Closes {
    held: Vec<u64>,
    outcomes: Vec<MemberOutcome>,
}

impl Sink for Closes {
    type Out = std::io::Sink;

    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<std::io::Sink>> {
        Ok(Disposition::Write(std::io::sink()))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        _out: Option<std::io::Sink>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.held.push(memory::current());
        self.outcomes.push(*outcome);
        Ok(())
    }
}

#[test]
fn what_a_range_keeps_is_charged_bounded_and_gone_at_the_end() {
    let set = encrypted_set();
    assert!(set.len() >= 4, "a set of {} volumes", set.len());
    let policy = MemoryPolicy::default();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(WIDTH)
        .build()
        .expect("a thread pool");
    let before = memory::current();
    let (sink, report) = pool.install(|| {
        let sources: Vec<Arc<dyn RangeSource>> = set
            .into_iter()
            .map(|bytes| Arc::new(bytes) as Arc<dyn RangeSource>)
            .collect();
        let options = ReadOptions::default()
            .with_workers(Some(WIDTH))
            .with_memory(policy)
            .with_sink_is_file(Some(true))
            .with_password(Some(Password::from(SECRET)));
        let mut sink = Closes {
            held: Vec::new(),
            outcomes: Vec::new(),
        };
        let report = extract(sources, &options, &mut sink, &mut ()).expect("the set reads");
        (sink, report)
    });
    let after = memory::current();
    assert_eq!(sink.outcomes.len(), 2);
    for outcome in &sink.outcomes {
        assert_eq!(outcome.checksum_ok, Some(true));
        assert_eq!(outcome.bytes, MEMBER as u64);
    }
    let between = sink.held[0].saturating_sub(before);
    println!(
        "kept between ranges: {between} bytes; the call's peak: {} bytes; read-ahead: {} bytes",
        report.peak_working_memory, policy.read_ahead
    );
    // The slab and the lent pieces are each within the window; four
    // windows is room for both, their page alignment, and a reader's own.
    assert!(
        between <= 4 * policy.read_ahead,
        "{between} bytes are held between two ranges under a read-ahead of {}",
        policy.read_ahead
    );
    assert!(
        between <= report.peak_working_memory,
        "{between} bytes between ranges, over the call's own peak of {}",
        report.peak_working_memory
    );
    assert_eq!(
        after,
        before,
        "the extraction returned holding {} bytes more than it began with",
        after.saturating_sub(before)
    );
}
