//! Per-member admission under a NAMED budget (SPEC-API 8.4.1): an
//! archive of many small members beside one large one reads at the
//! one-member floor and above it with the operation's own peak and the
//! process counters at or under the engine limit, on the sequential path
//! at a width and on `extract_parallel`, and every member's bytes are the
//! default policy's.

use std::sync::{Arc, Mutex};

use rarkit::{
    extract_parallel, Disposition, MemberInfo, MemberSpec, MemoryPolicy, ParallelSink, Payload,
    RangeSource, ReadOptions, Result, Sink, WriteMethod, WriteOptions, Writer,
};

const MIB: u64 = 1 << 20;

fn body(bytes: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes + 64);
    let mut seed = seed;
    while out.len() < bytes {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        out.extend_from_slice(format!("{:016x} ", seed >> 24).as_bytes());
        out.extend_from_slice(b"a member is admitted against its own need ");
        for _ in 0..8 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            out.extend_from_slice(&seed.to_le_bytes());
        }
    }
    out.truncate(bytes);
    out
}

/// One member of 6 MiB and 400 of 2 KiB, compressed, declaring 32 MiB: the
/// one large member sets the floor, and the small ones are what a cap by
/// the largest member's need would have read one or two at a time.
fn archive() -> Vec<u8> {
    let mut writer = Writer::new(WriteOptions {
        method: WriteMethod::Compressed {
            level: 1,
            dictionary: Some(32 * MIB),
        },
        ..WriteOptions::default()
    })
    .expect("options");
    let sizes: Vec<usize> = [6 << 20]
        .into_iter()
        .chain((0..400).map(|_| 2048))
        .collect();
    let bodies: Vec<Vec<u8>> = sizes
        .iter()
        .enumerate()
        .map(|(i, &n)| body(n, 0x2026_0929_00f1 + i as u64))
        .collect();
    let names: Vec<Vec<u8>> = (0..bodies.len())
        .map(|i| format!("m{i:04}.dat").into_bytes())
        .collect();
    for (name, data) in names.iter().zip(&bodies) {
        writer
            .add(MemberSpec {
                name,
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

fn sources(bytes: &[u8]) -> Vec<Arc<dyn RangeSource>> {
    vec![Arc::new(bytes.to_vec()) as Arc<dyn RangeSource>]
}

/// Every member's bytes, by name.
#[derive(Default)]
struct Collect {
    out: Mutex<Vec<(Vec<u8>, Vec<u8>)>>,
}

struct Into {
    name: Vec<u8>,
    bytes: Vec<u8>,
}

impl std::io::Write for Into {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Sink for Collect {
    type Out = Into;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Into>> {
        ParallelSink::open(self, member)
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<Into>,
        _outcome: &rarkit::MemberOutcome,
    ) -> Result<()> {
        ParallelSink::close(self, _member, out, _outcome)
    }
}

impl ParallelSink for Collect {
    type Out = Into;

    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Into>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Into {
            name: member.name.to_vec(),
            bytes: Vec::new(),
        }))
    }

    fn close(
        &self,
        _member: &MemberInfo<'_>,
        out: Option<Into>,
        _outcome: &rarkit::MemberOutcome,
    ) -> Result<()> {
        if let Some(out) = out {
            self.out.lock().unwrap().push((out.name, out.bytes));
        }
        Ok(())
    }
}

type Members = Vec<(Vec<u8>, Vec<u8>)>;
type Run = fn(&[u8], MemoryPolicy) -> Result<(rarkit::ExtractReport, Members)>;

fn sorted(collect: Collect) -> Members {
    let mut v = collect.out.into_inner().unwrap();
    v.sort();
    v
}

fn sequential(bytes: &[u8], policy: MemoryPolicy) -> Result<(rarkit::ExtractReport, Members)> {
    let opts = ReadOptions::default()
        .with_memory(policy)
        .with_workers(Some(8));
    let mut sink = Collect::default();
    let report = rarkit::extract(sources(bytes), &opts, &mut sink, &mut ())?;
    Ok((report, sorted(sink)))
}

fn parallel(bytes: &[u8], policy: MemoryPolicy) -> Result<(rarkit::ExtractReport, Members)> {
    let opts = ReadOptions::default()
        .with_memory(policy)
        .with_workers(Some(8));
    let sink = Collect::default();
    let report = extract_parallel(sources(bytes), &opts, &sink, 8)?;
    Ok((report, sorted(sink)))
}

/// One test, in sequence, because `memory::peak` is the process's and a
/// second test in this binary would charge into it.
#[test]
fn small_members_beside_a_large_one_hold_the_limit_at_the_floor_and_above_it() {
    let bytes = archive();
    let (_, expected) = sequential(&bytes, MemoryPolicy::default()).expect("default");
    assert_eq!(expected.len(), 401);

    let floor = (1..=256u64)
        .map(|m| m * MIB)
        .find(|&limit| sequential(&bytes, MemoryPolicy::from_limit(limit)).is_ok())
        .expect("some budget reads it");

    // At the floor, one MiB above it, and with room for several members:
    // the operation's own peak and the process counters stay under the
    // engine limit on both paths, and the bytes are the default's.
    for limit in [floor, floor + MIB, floor + 16 * MIB] {
        for (path, run) in [
            ("sequential", sequential as Run),
            ("parallel", parallel as Run),
        ] {
            rarkit::memory::reset_peak();
            let (report, got) = run(&bytes, MemoryPolicy::from_limit(limit)).expect(path);
            assert!(
                report.peak_working_memory <= limit,
                "{path} at limit {limit}: the report's peak {} is over it",
                report.peak_working_memory
            );
            let peak = rarkit::memory::peak();
            assert!(
                peak <= limit,
                "{path} at limit {limit}: memory::peak {peak} is over it"
            );
            assert!(
                got == expected,
                "{path} at limit {limit}: bytes differ from the default's"
            );
        }
    }

    // The same in process terms.
    let policy = MemoryPolicy::for_process(floor + MemoryPolicy::PROCESS_HEADROOM, 0);
    for (path, run) in [
        ("sequential", sequential as Run),
        ("parallel", parallel as Run),
    ] {
        rarkit::memory::reset_peak();
        let (report, got) = run(&bytes, policy).expect(path);
        assert!(report.peak_working_memory <= policy.working_limit);
        assert!(rarkit::memory::peak() <= policy.working_limit);
        assert!(got == expected);
    }
}
