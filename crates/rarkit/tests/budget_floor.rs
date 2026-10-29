//! SPEC-API 8.4.1: a NAMED budget below an archive's
//! one-member floor is refused before any member, naming working memory
//! and the minimum; at the floor and above it the read completes inside the
//! budget, `memory::peak` and the operation's own report at or under the
//! engine limit, sequential and concurrent alike.

use std::sync::Arc;

use rarkit::{
    Disposition, ErrorKind, MemberInfo, MemberSpec, MemoryPolicy, Payload, RangeSource,
    ReadOptions, Resource, Result, Sink, WriteMethod, WriteOptions, Writer,
};

const MIB: u64 = 1 << 20;

fn body(bytes: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes + 64);
    let mut seed = seed;
    while out.len() < bytes {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        out.extend_from_slice(format!("{:016x} ", seed >> 24).as_bytes());
        out.extend_from_slice(b"a budget is a ceiling over the whole read ");
        for _ in 0..8 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            out.extend_from_slice(&seed.to_le_bytes());
        }
    }
    out.truncate(bytes);
    out
}

/// Sixteen members of 3 MiB and one of 6 MiB, compressed, declaring 32 MiB:
/// the largest member's window is what the floor turns on.
fn archive() -> Vec<u8> {
    let mut writer = Writer::new(WriteOptions {
        method: WriteMethod::Compressed {
            level: 1,
            dictionary: Some(32 * MIB),
        },
        ..WriteOptions::default()
    })
    .expect("options");
    let sizes: Vec<usize> = (0..16).map(|_| 3 << 20).chain([6 << 20]).collect();
    let bodies: Vec<Vec<u8>> = sizes
        .iter()
        .enumerate()
        .map(|(i, &n)| body(n, 0x2026_0929 + i as u64))
        .collect();
    let names: Vec<Vec<u8>> = (0..bodies.len())
        .map(|i| format!("m{i}.dat").into_bytes())
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

struct Discard;

impl Sink for Discard {
    type Out = std::io::Sink;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<std::io::Sink>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(std::io::sink()))
    }
}

fn read(bytes: &[u8], policy: MemoryPolicy) -> Result<rarkit::ExtractReport> {
    let opts = ReadOptions::default().with_memory(policy);
    rarkit::extract(sources(bytes), &opts, &mut Discard, &mut ())
}

fn minimum(bytes: &[u8], policy: &MemoryPolicy) -> u64 {
    rarkit::Archive::open(sources(bytes).remove(0), &ReadOptions::default())
        .expect("open")
        .minimum_working_memory(policy)
}

#[test]
fn a_named_budget_below_the_floor_is_refused_up_front_and_at_the_floor_it_holds() {
    let bytes = archive();
    // The smallest engine budget the read accepts, in 1 MiB steps.
    let floor = (1..=256u64)
        .map(|m| m * MIB)
        .find(|&limit| read(&bytes, MemoryPolicy::from_limit(limit)).is_ok())
        .expect("some budget reads it");

    // One step under it: refused before any member, naming working memory
    // and the minimum in engine terms.
    let under = MemoryPolicy::from_limit(floor - MIB);
    let err = read(&bytes, under).expect_err("under the floor");
    match err.kind() {
        ErrorKind::LimitExceeded {
            resource: Resource::WorkingMemory,
            needed,
            limit,
        } => {
            assert_eq!(*needed, minimum(&bytes, &under));
            assert_eq!(*limit, floor - MIB);
            assert!(*needed > *limit);
        }
        other => panic!("not a working-memory refusal: {other:?}"),
    }
    assert!(err.member().is_none(), "refused before any member");

    // At the floor and a step above it the read stays inside the budget,
    // by the operation's own report and by the process counters.
    for limit in [floor, floor + MIB] {
        rarkit::memory::reset_peak();
        let report = read(&bytes, MemoryPolicy::from_limit(limit)).expect("at the floor");
        assert!(
            report.peak_working_memory <= limit,
            "limit {limit}: the report's peak {} is over it",
            report.peak_working_memory
        );
    }
}

#[test]
fn a_process_budget_is_refused_and_held_in_its_own_terms() {
    let bytes = archive();
    let floor = (1..=512u64)
        .map(|m| m * MIB)
        .find(|&budget| read(&bytes, MemoryPolicy::for_process(budget, 0)).is_ok())
        .expect("some budget reads it");
    let under = MemoryPolicy::for_process(floor - MIB, 0);
    match read(&bytes, under).expect_err("under the floor").kind() {
        ErrorKind::LimitExceeded {
            resource: Resource::WorkingMemory,
            needed,
            limit,
        } => {
            // Process terms: the headroom is inside both figures.
            assert_eq!(*limit, floor - MIB);
            assert!(*needed >= MemoryPolicy::PROCESS_HEADROOM);
            assert_eq!(*needed, minimum(&bytes, &under));
        }
        other => panic!("not a working-memory refusal: {other:?}"),
    }
    let policy = MemoryPolicy::for_process(floor, 0);
    let report = read(&bytes, policy).expect("at the floor");
    assert!(report.peak_working_memory <= policy.working_limit);
}

#[test]
fn the_default_policy_is_never_refused_for_the_floor() {
    let bytes = archive();
    read(&bytes, MemoryPolicy::default()).expect("the default reads it");
    read(&bytes, MemoryPolicy::process_default(0)).expect("the process default reads it");
}

/// The same shapes through `extract_parallel` at a width the budget cannot
/// hold: under the floor the read is refused before any member is opened,
/// naming working memory; at the floor and a step above it every member is
/// read and the operation's report stays inside the NAMED budget, the
/// breadth capped to the room above the floor. The
/// pool's own admission under a limit the caller did NOT name is pinned in
/// `admission_reuse.rs`.
#[cfg(feature = "parallel")]
#[test]
fn a_named_budget_holds_the_concurrent_read_the_same_way() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Count(AtomicUsize);

    impl rarkit::ParallelSink for Count {
        type Out = std::io::Sink;

        fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<std::io::Sink>> {
            if member.is_directory {
                return Ok(Disposition::Skip);
            }
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(Disposition::Write(std::io::sink()))
        }
    }

    let bytes = archive();
    let files = rarkit::Archive::open(sources(&bytes).remove(0), &ReadOptions::default())
        .expect("open")
        .members()
        .filter(|m| !m.is_directory)
        .count();
    let wide = |limit: u64| {
        let opts = ReadOptions::default()
            .with_workers(Some(8))
            .with_memory(MemoryPolicy::from_limit(limit));
        let sink = Count(AtomicUsize::new(0));
        let got = rarkit::extract_parallel(sources(&bytes), &opts, &sink, 8);
        (got, sink.0.into_inner())
    };
    // The floor as the sequential read finds it, in 1 MiB steps.
    let floor = (1..=256u64)
        .map(|m| m * MIB)
        .find(|&limit| read(&bytes, MemoryPolicy::from_limit(limit)).is_ok())
        .expect("some budget reads it");

    let (under, opened) = wide(floor - MIB);
    let err = under.expect_err("under the floor");
    assert!(
        matches!(
            err.kind(),
            ErrorKind::LimitExceeded {
                resource: Resource::WorkingMemory,
                ..
            }
        ),
        "not a working-memory refusal: {err:?}"
    );
    assert_eq!(opened, 0, "a member was opened before the refusal");

    for limit in [floor, floor + MIB, floor + 8 * MIB] {
        let (done, opened) = wide(limit);
        let report = done.expect("at or above the floor");
        let alone = read(&bytes, MemoryPolicy::from_limit(limit)).expect("in sequence");
        println!(
            "CONCURRENT limit={limit} peak={} sequential peak={}",
            report.peak_working_memory, alone.peak_working_memory
        );
        assert_eq!(opened, files, "limit {limit}: not every member was read");
        assert!(
            report.peak_working_memory <= limit,
            "limit {limit}: the report's peak {} is over it",
            report.peak_working_memory
        );
    }
}

/// One member of `bytes` bytes that packs to almost nothing (one 64 KiB
/// block repeated), declaring a dictionary of its own size: its window is
/// the whole member, and its packed stream is too small to be a term.
fn one_wide_window(bytes: usize) -> (Vec<u8>, Vec<u8>) {
    let block = body(64 << 10, 0x2026_1012);
    let data: Vec<u8> = block.iter().copied().cycle().take(bytes).collect();
    (one_member_of(&data), data)
}

/// One member holding `data`, declaring a dictionary of its own size.
fn one_member_of(data: &[u8]) -> Vec<u8> {
    let bytes = data.len();
    let mut writer = Writer::new(WriteOptions {
        method: WriteMethod::Compressed {
            level: 1,
            dictionary: Some(bytes as u64),
        },
        ..WriteOptions::default()
    })
    .expect("options");
    writer
        .add(MemberSpec {
            name: b"wide.dat",
            payload: Payload::Bytes(data),
            mtime: None,
            attributes: 0,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    out
}

/// A writer that keeps what it is given where the test can read it.
struct Kept(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Kept {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("unpoisoned").extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Keep(Arc<std::sync::Mutex<Vec<u8>>>);

impl Sink for Keep {
    type Out = Kept;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Kept>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Kept(Arc::clone(&self.0))))
    }
}

/// SPEC-API 8.4.1, the account per width: a member whose window is MORE
/// than half a named budget is read where one window and the fixed part
/// fit it, at whatever width the caller asks, the bytes the member's and
/// the meter at or under the limit at every one of them; and it is
/// refused, before any member and naming working memory, only where the
/// window itself does not fit.
#[test]
fn a_window_over_half_a_named_budget_is_read_at_the_width_that_fits() {
    let window = 16 * MIB;
    let (bytes, data) = one_wide_window(window as usize);
    for limit in [window + 4 * MIB, window + 8 * MIB, 2 * window - MIB] {
        for workers in [Some(1), Some(2), Some(4), Some(8), None] {
            let what = format!("limit {limit}, workers {workers:?}");
            let kept = Arc::new(std::sync::Mutex::new(Vec::new()));
            let opts = ReadOptions::default()
                .with_memory(MemoryPolicy::from_limit(limit))
                .with_workers(workers);
            rarkit::memory::reset_peak();
            let report = rarkit::extract(
                sources(&bytes),
                &opts,
                &mut Keep(Arc::clone(&kept)),
                &mut (),
            )
            .unwrap_or_else(|e| panic!("{what}: refused: {e}"));
            println!(
                "ACCOUNT {what}: the report's peak {}",
                report.peak_working_memory
            );
            assert!(
                report.peak_working_memory <= limit,
                "{what}: the report's peak {} is over it",
                report.peak_working_memory
            );
            assert!(
                *kept.lock().expect("unpoisoned") == data,
                "{what}: the bytes are not the member's"
            );
        }
    }

    let under = MemoryPolicy::from_limit(window - 4 * MIB);
    let err = read(&bytes, under).expect_err("a window the budget does not hold");
    match err.kind() {
        ErrorKind::LimitExceeded {
            resource: Resource::WorkingMemory,
            needed,
            limit,
        } => {
            assert_eq!(*needed, minimum(&bytes, &under));
            assert_eq!(*limit, window - 4 * MIB);
            // The account at a width of one: one window and the fixed
            // part, not two windows.
            assert!(
                *needed > window && *needed < window + 4 * MIB,
                "needed {needed} for a window of {window}"
            );
        }
        other => panic!("not a working-memory refusal: {other:?}"),
    }
    assert!(err.member().is_none(), "refused before any member");
}

/// `bytes` with its one member's FIRST BLOCK restated to declare
/// 4,194,303 bytes of payload: a header of three size bytes, its check
/// byte made to hold. No genuine writer makes such a block (ours stops at
/// 120 KiB); a made archive can. The member must pack to more than that,
/// or the block is cut short by the member's own end before any buffer is
/// asked for it.
fn with_a_block_of_four_mebibytes(bytes: &[u8]) -> Vec<u8> {
    let at = rarkit::Archive::open(sources(bytes).remove(0), &ReadOptions::default())
        .expect("open")
        .members()
        .find(|m| !m.is_directory)
        .expect("a member")
        .data
        .start as usize;
    let mut made = bytes.to_vec();
    let flags = (made[at] & !0x18) | (2 << 3);
    made[at] = flags;
    // The check is 0x5a over the flags and the size bytes.
    let size = [0xff, 0xff, 0x3f];
    made[at + 1] = 0x5a ^ flags ^ size[0] ^ size[1] ^ size[2];
    made[at + 2..at + 5].copy_from_slice(&size);
    made
}

/// SPEC-API 8.4.1, the account's item 7: the packed block buffer is not
/// in the up-front account, so a member whose window fits is begun; a
/// block whose packed bytes the budget does not hold beside that window is
/// refused AT THE BLOCK, by name, with what the operation would have held,
/// and the member is named. Under a budget that holds the block the same
/// archive gets as far as its bytes, which are not there.
#[test]
fn a_block_the_budget_does_not_hold_is_refused_at_the_block_by_name() {
    let window = 16 * MIB;
    // Text and noise, which packs to about half: more than the block the
    // header is made to declare.
    let bytes = one_member_of(&body(window as usize, 0x2026_1012));
    assert!(bytes.len() as u64 > 5 * MIB, "the member packs too small");
    let made = with_a_block_of_four_mebibytes(&bytes);
    {
        let cap = window + 4 * MIB;
        for workers in [Some(1), Some(8), None] {
            let what = format!("limit {cap}, workers {workers:?}");
            let opts = ReadOptions::default()
                .with_memory(MemoryPolicy::from_limit(cap))
                .with_workers(workers);
            let err = rarkit::extract(sources(&made), &opts, &mut Discard, &mut ())
                .expect_err("a block of 4 MiB under a budget that leaves under 3");
            match err.kind() {
                ErrorKind::LimitExceeded {
                    resource: Resource::BlockBuffer,
                    needed,
                    limit,
                } => {
                    assert_eq!(*limit, cap, "{what}");
                    assert!(*needed > cap, "{what}: needed {needed}");
                    assert!(
                        *needed <= window + 10 * MIB,
                        "{what}: needed {needed} is more than the window and two blocks"
                    );
                }
                other => panic!("{what}: not a block buffer refusal: {other:?}"),
            }
            assert!(err.member().is_some(), "{what}: the member is not named");
        }
    }

    // Under a budget that holds the block it is read: what a made block
    // then decodes to is not this test's, only that the budget did not
    // refuse it.
    let ample = MemoryPolicy::from_limit(window + 64 * MIB);
    if let Err(err) = read(&made, ample) {
        assert!(
            !matches!(
                err.kind(),
                ErrorKind::LimitExceeded {
                    resource: Resource::BlockBuffer,
                    ..
                }
            ),
            "a budget that holds the block refused it: {err:?}"
        );
    }
}
