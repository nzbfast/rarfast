//! `memory::peak` counts every decode window (SPEC-API section 8, added 27
//! Sep 2026; a stated `-mm` is a hard cap).
//!
//! A member's window is by far its largest buffer and, since that date,
//! the one that may exceed `working_limit`, so a process peak that leaves
//! it out understates the one figure a caller most needs. The acceptance
//! test the section names: decode one member of a known window size with
//! `reset_peak` first, and assert the peak is at least that window. It is
//! asserted here on the sequential path at the default width and at one
//! worker, on the concurrent path, for the RAR 2.0 and RAR 2.9 windows and
//! the PPMd model, and against a stated limit: what the limit admits is
//! counted in full and stays under it, and what it refuses is refused
//! before its window is committed. The RAR 1.5 window is pinned by the
//! unit test `read::extract::tests::the_charge_follows_what_the_decoders_hold`,
//! since a legacy fixture small enough to commit cannot tell a 64 KiB
//! window from the cursor's own read-ahead.
//!
//! The counters are PROCESS-wide, so every test in this binary takes
//! [`counter`]: cargo runs a binary's tests on several threads at once.

use std::sync::{Arc, Mutex, MutexGuard};

use rarkit::{
    extract, memory, Disposition, ErrorKind, MemberInfo, MemberOutcome, MemberSpec, MemoryPolicy,
    Payload, RangeSource, ReadOptions, Resource, Result, Sink, WriteMethod, WriteOptions, Writer,
};

static COUNTER: Mutex<()> = Mutex::new(());

fn counter() -> MutexGuard<'static, ()> {
    COUNTER.lock().unwrap_or_else(|e| e.into_inner())
}

const MIB: u64 = 1 << 20;

/// Material an `-m3` archive compresses by about half, seeded so every box
/// writes the same archive.
fn body(bytes: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes + 128);
    let mut seed = seed;
    while out.len() < bytes {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        out.extend_from_slice(format!("{:016x} ", seed >> 24).as_bytes());
        out.extend_from_slice(b"the window is working memory like any other ");
        for _ in 0..8 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            out.extend_from_slice(&seed.to_le_bytes());
        }
    }
    out.truncate(bytes);
    out
}

/// A RAR 5 archive of `members` distinct bodies of `each` bytes, written
/// with a 32 MiB dictionary, solid or not.
fn archive(members: usize, each: usize, solid: bool) -> Vec<u8> {
    let mut writer = Writer::new(WriteOptions {
        method: WriteMethod::Compressed {
            level: 3,
            dictionary: Some(32 * MIB),
        },
        solid,
        ..WriteOptions::default()
    })
    .expect("options");
    let bodies: Vec<Vec<u8>> = (0..members)
        .map(|i| body(each, 0x2026_0927 + i as u64))
        .collect();
    let names: Vec<Vec<u8>> = (0..members)
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

/// The largest dictionary the archive's compressed members DECLARE, read
/// back rather than assumed: the writer narrows a dictionary to what its
/// input can use.
fn declared(bytes: &[u8]) -> u64 {
    let archive =
        rarkit::Archive::open(sources(bytes).remove(0), &ReadOptions::default()).expect("open");
    archive
        .members()
        .filter_map(|m| match m.method {
            rarkit::Method::Compressed { dictionary, .. } => Some(dictionary),
            rarkit::Method::Stored => None,
        })
        .max()
        .expect("a compressed member")
}

/// Decodes every member to nowhere: the bytes are not the point, and
/// holding them would be the largest thing in the process.
struct Discard;

impl Sink for Discard {
    type Out = std::io::Sink;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<std::io::Sink>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(std::io::sink()))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        _out: Option<std::io::Sink>,
        _outcome: &MemberOutcome,
    ) -> Result<()> {
        Ok(())
    }
}

#[cfg(feature = "parallel")]
impl rarkit::ParallelSink for Discard {
    type Out = std::io::Sink;

    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<std::io::Sink>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(std::io::sink()))
    }

    fn close(
        &self,
        _member: &MemberInfo<'_>,
        _out: Option<std::io::Sink>,
        _outcome: &MemberOutcome,
    ) -> Result<()> {
        Ok(())
    }
}

/// What one extraction did to the process counters: the peak ABOVE what
/// was held when it began, and what was still held after it returned
/// beyond that; beside them what the operation itself reported.
struct Measured {
    rise: u64,
    left: u64,
    report: Result<rarkit::ExtractReport>,
}

fn measure(run: impl FnOnce() -> Result<rarkit::ExtractReport>) -> Measured {
    memory::reset_peak();
    let before = memory::current();
    let report = run();
    Measured {
        rise: memory::peak().saturating_sub(before),
        left: memory::current().saturating_sub(before),
        report,
    }
}

fn sequential(bytes: &[u8], opts: &ReadOptions) -> Measured {
    measure(|| extract(sources(bytes), opts, &mut Discard, &mut ()))
}

/// The run decoded every byte and nothing failed its check, and every
/// window it committed was released by the time it returned.
fn clean(m: &Measured, unpacked: u64) -> rarkit::ExtractReport {
    let report = *m.report.as_ref().expect("extract");
    assert_eq!(report.bytes, unpacked, "every byte decoded");
    assert_eq!(report.checksum_failures, 0, "a member failed its check");
    assert_eq!(
        m.left, 0,
        "the operation returned still charging {} bytes to the process",
        m.left
    );
    report
}

// -------------------------------------------------------------------------
// The acceptance test of SPEC-API 8: the peak is at least the window
// -------------------------------------------------------------------------

/// A SOLID member's window is its declared dictionary (only a member
/// nothing continues is sized by its reach), so the process peak of
/// one extraction is at least that dictionary, at the default width and at
/// one worker (`-mt1`) alike.
#[test]
fn the_process_peak_counts_a_solid_ring_at_every_width() {
    let _guard = counter();
    let bytes = archive(2, 3 << 20, true);
    let window = declared(&bytes);
    assert!(
        window >= 4 * MIB,
        "a {window} byte dictionary does not dominate the cursor and the \
         member table, so a peak above it would prove nothing"
    );
    for (width, opts) in [
        ("default", ReadOptions::default()),
        ("-mt1", ReadOptions::default().with_workers(Some(1))),
    ] {
        let m = sequential(&bytes, &opts);
        let report = clean(&m, 2 * (3 << 20));
        println!(
            "SOLID width={width} window={window} process_rise={} report_peak={}",
            m.rise, report.peak_working_memory
        );
        assert!(
            m.rise >= window,
            "at the {width} width memory::peak rose {} over an operation \
             that committed a {window} byte ring",
            m.rise
        );
        assert!(
            report.peak_working_memory >= window,
            "at the {width} width the operation reported a peak of {} under \
             its own {window} byte ring",
            report.peak_working_memory
        );
    }
}

/// A NON-solid member's window is its reach, `min(dictionary, unpacked)`,
/// and that smaller ring is what the peak counts: on the
/// sequential path at both widths and on the concurrent one.
#[test]
fn the_process_peak_counts_a_member_sized_ring_on_every_path() {
    let _guard = counter();
    let each: u64 = 3 << 20;
    let bytes = archive(2, each as usize, false);
    assert!(
        declared(&bytes) >= each,
        "the writer declared less than a member"
    );
    for (width, opts) in [
        ("default", ReadOptions::default()),
        ("-mt1", ReadOptions::default().with_workers(Some(1))),
    ] {
        let m = sequential(&bytes, &opts);
        clean(&m, 2 * each);
        println!("NON-SOLID sequential width={width} process_rise={}", m.rise);
        assert!(
            m.rise >= each,
            "at the {width} width memory::peak rose {} over members whose \
             rings are at least {each} bytes",
            m.rise
        );
    }
    #[cfg(feature = "parallel")]
    {
        let opts = ReadOptions::default();
        let m = measure(|| rarkit::extract_parallel(sources(&bytes), &opts, &Discard, 2));
        let report = clean(&m, 2 * each);
        println!(
            "NON-SOLID concurrent process_rise={} report_peak={}",
            m.rise, report.peak_working_memory
        );
        assert!(
            m.rise >= each,
            "on the concurrent path memory::peak rose {} over members whose \
             rings are at least {each} bytes",
            m.rise
        );
    }
}

// -------------------------------------------------------------------------
// A stated limit (`-mm`) and the reported peak agree
// -------------------------------------------------------------------------

/// `-mm<size>` reaches a read as `MemoryPolicy::from_limit(size)` (SPEC-API
/// 8.1 term 3). Under a limit that admits the window, the window is counted
/// in full AND the counted peak stays inside the limit, in the process
/// counters and the operation's report alike; under one that does not, the
/// member is refused naming the same window as `needed`, and the refusal
/// comes before the window is committed, so the peak never saw it.
#[test]
fn a_stated_limit_and_the_reported_peak_agree() {
    let _guard = counter();
    let bytes = archive(2, 3 << 20, true);
    let window = declared(&bytes);

    for workers in [None, Some(1)] {
        let limit = 3 * window;
        let opts = ReadOptions::default()
            .with_memory(MemoryPolicy::from_limit(limit))
            .with_workers(workers);
        assert!(opts.memory.max_window >= window);
        let m = sequential(&bytes, &opts);
        let report = clean(&m, 2 * (3 << 20));
        println!(
            "ADMITTED workers={workers:?} limit={limit} window={window} \
             process_rise={} report_peak={}",
            m.rise, report.peak_working_memory
        );
        assert!(m.rise >= window, "the admitted ring was not counted");
        assert!(
            m.rise <= limit,
            "memory::peak rose {} under a stated limit of {limit}",
            m.rise
        );
        assert!(
            report.peak_working_memory <= limit,
            "the operation reported {} under a stated limit of {limit}",
            report.peak_working_memory
        );

        // A limit of the window itself: refused, never tried. The account
        // at a width of one is ONE window and the fixed part (SPEC-API
        // 8.4.1), so a NAMED budget of exactly the window is under the
        // one-member floor and is refused before any member, naming
        // working memory and that account as what the read needs. Until 12
        // Oct 2026 the floor asked for two windows here, and a reader
        // under a stated limit was told it needed twice what it holds.
        let limit = window;
        let opts = ReadOptions::default()
            .with_memory(MemoryPolicy::from_limit(limit))
            .with_workers(workers);
        let m = sequential(&bytes, &opts);
        match m.report.as_ref().map_err(|e| e.kind()) {
            Err(ErrorKind::LimitExceeded {
                resource: Resource::WorkingMemory,
                needed,
                limit: allowed,
            }) => {
                let floor = rarkit::Archive::open(sources(&bytes).remove(0), &opts)
                    .expect("open")
                    .minimum_working_memory(&opts.memory);
                assert_eq!(*needed, floor, "the refusal names the archive's floor");
                assert!(
                    *needed > window && *needed < window + (2 << 20),
                    "the refusal names {needed} for a window of {window}: one \
                     window and the fixed part, not two windows"
                );
                assert_eq!(*allowed, limit);
            }
            other => panic!("a {window} byte window under a limit of {limit}: {other:?}"),
        }
        println!(
            "REFUSED workers={workers:?} limit={limit} process_rise={}",
            m.rise
        );
        assert!(
            m.rise < window / 2,
            "a refused member raised memory::peak by {}: its {window} byte \
             window was committed before the refusal",
            m.rise
        );
        assert_eq!(m.left, 0, "a refused member left bytes charged");
    }
}

// -------------------------------------------------------------------------
// The legacy decoders: RAR 2.0, RAR 2.9 and its PPMd model
// -------------------------------------------------------------------------

fn fixture(path: &str) -> Option<Vec<u8>> {
    let full = format!("{}/../../{path}", env!("CARGO_MANIFEST_DIR"));
    match std::fs::read(&full) {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            eprintln!("{path} is not in this checkout: skipped");
            None
        }
    }
}

/// The unpacked bytes of every file member, which is what a clean
/// extraction delivers.
fn unpacked(bytes: &[u8]) -> u64 {
    let archive =
        rarkit::Archive::open(sources(bytes).remove(0), &ReadOptions::default()).expect("open");
    archive
        .members()
        .filter(|m| !m.is_directory)
        .map(|m| m.unpacked_size.expect("a declared size"))
        .sum()
}

/// Each archive is a few tens of kilobytes, so nothing but a window can
/// raise the peak by a megabyte: the cursor's read-ahead is at most 64 KiB
/// and the member table is a few hundred bytes a member.
#[test]
fn the_process_peak_counts_the_legacy_windows() {
    let _guard = counter();
    // (fixture, the least the decoder commits, what that is)
    let cases: [(&str, u64, &str); 3] = [
        // RAR 2.0 always holds the format maximum (spec H3 3.5).
        ("specs/vectors-H/legacy/D250_M5.RAR", MIB, "RAR 2.0 window"),
        // rar 3.93's default 4 MiB dictionary, the RAR 2.9 maximum.
        (
            "specs/vectors-H/legacy/r393_m5.rar",
            4 * MIB,
            "RAR 2.9 window",
        ),
        // The same window and a text model of at least 1 MiB (spec I).
        (
            "fixtures/legacy/archives/r393_txt.rar",
            5 * MIB,
            "RAR 2.9 window and PPMd model",
        ),
    ];
    for (path, least, what) in cases {
        let Some(bytes) = fixture(path) else { continue };
        assert!(bytes.len() < 128 << 10, "{path} is no longer small");
        let m = sequential(&bytes, &ReadOptions::default());
        clean(&m, unpacked(&bytes));
        println!("LEGACY {path} process_rise={}", m.rise);
        assert!(
            m.rise >= least,
            "{path}: memory::peak rose {} over a {what} of at least {least}",
            m.rise
        );
    }
}
