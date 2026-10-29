//! SPEC-A 6.1: the packed input, not the declared
//! unpacked size, is what ends a RAR 1.5 decode that has no more bits.
//!
//! The two inputs here are `fixtures/rar15-packed-bound/`, found by the
//! second whole-roster fuzz campaign on 20 Sep 2026. Each holds a RAR 1.5
//! member declaring about 4 GiB over a few kilobytes of packed data. They
//! are the acceptance tests of 6.1 driven through the PUBLIC entry points,
//! sequential and concurrent, which is where the amplification was found.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rarkit::{
    extract, extract_parallel, Disposition, MemberInfo, MemberOutcome, MemoryPolicy, ParallelSink,
    RangeSource, ReadOptions, Result, Sink,
};

/// The vector these two inputs damage.
const VECTOR_LEN: usize = 12_917;

/// The vector's password (spec F section 5).
const PASSWORD: &str = "Secret";

/// The two files under `fixtures/rar15-packed-bound/` are `f_extract_any`
/// INPUTS, not archives: the target picks a vector with byte 1 and
/// exclusive-ors bytes 11.. over it from an offset byte 1 also picks. Both
/// of these pick `D140_M5.RAR` at offset 962. The mapping is reproduced
/// here so the tests drive the PUBLIC entry points on the same archive the
/// campaign reached, and every step of it is asserted.
fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/rar15-packed-bound")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn vector() -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../specs/vectors-F/archives/D140_M5.RAR");
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The archive one of those inputs reaches, by the target's own mapping.
fn archive(input: &[u8]) -> Vec<u8> {
    assert!(
        input.len() >= 12,
        "an f_extract_any input is 12 bytes or more"
    );
    let seed = input[1];
    let mut bytes = vector();
    assert_eq!(
        bytes.len(),
        VECTOR_LEN,
        "D140_M5.RAR changed under this test"
    );
    assert_eq!(
        usize::from(seed) % 13,
        9,
        "this input no longer picks D140_M5.RAR"
    );
    assert_eq!(seed & 1, 0, "this input no longer damages its vector");
    let at = usize::from(seed) * 13 % bytes.len();
    for (i, b) in input[11..].iter().enumerate().take(bytes.len() - at) {
        bytes[at + i] ^= b;
    }
    bytes
}

/// The two inputs, with the length each had when the campaign minimised it.
/// The length is asserted so that replacing a fixture fails loudly instead
/// of quietly testing something else: nothing else here can tell, because
/// the archive they build does not list (its headers outrun its bytes) and
/// the declared size cannot be read back through the public API.
fn inputs() -> [(&'static str, Vec<u8>); 2] {
    let pairs = [
        ("minimised", fixture("declared-4gb-minimised.rar"), 11_548),
        ("original", fixture("declared-4gb-original.rar"), 13_802),
    ];
    pairs.map(|(name, bytes, want)| {
        assert_eq!(
            bytes.len(),
            want,
            "{name} is not the byte count the campaign recorded"
        );
        (name, bytes)
    })
}

/// A sink that counts every byte and keeps none, refusing past a ceiling so
/// a regression to an unbounded decode fails the test and not the machine.
/// It also records every member's `checksum_ok`.
#[derive(Default)]
struct Counting {
    ceiling: u64,
    bytes: Arc<AtomicU64>,
    checksums: Arc<std::sync::Mutex<Vec<Option<bool>>>>,
}

struct Tally {
    total: Arc<AtomicU64>,
    ceiling: u64,
}

impl std::io::Write for Tally {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let total = self.total.fetch_add(data.len() as u64, Ordering::Relaxed) + data.len() as u64;
        if total > self.ceiling {
            return Err(std::io::Error::other("past the test's ceiling"));
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Sink for Counting {
    type Out = Tally;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Tally>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Tally {
            total: Arc::clone(&self.bytes),
            ceiling: self.ceiling,
        }))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        _out: Option<Tally>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        if let Ok(mut seen) = self.checksums.lock() {
            seen.push(outcome.checksum_ok);
        }
        Ok(())
    }
}

impl ParallelSink for Counting {
    type Out = Tally;

    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Tally>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Tally {
            total: Arc::clone(&self.bytes),
            ceiling: self.ceiling,
        }))
    }

    fn close(
        &self,
        _member: &MemberInfo<'_>,
        _out: Option<Tally>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        if let Ok(mut seen) = self.checksums.lock() {
            seen.push(outcome.checksum_ok);
        }
        Ok(())
    }
}

/// Print what the archive this input reaches declares, member by member.
fn describe(name: &str, bytes: &[u8]) {
    let source: Arc<dyn RangeSource> = Arc::new(bytes.to_vec());
    match rarkit::Archive::open(source, &options()) {
        Ok(archive) => {
            for m in archive.members() {
                println!(
                    "{name}: member {:?} declared {:?} packed {:?}",
                    m.name, m.unpacked_size, m.packed_size
                );
            }
        }
        Err(e) => println!("{name}: does not list: {e}"),
    }
}

fn options() -> ReadOptions {
    ReadOptions::default()
        // The budget byte of both inputs is 4, so the target gave the
        // engine `1 << 24`.
        .with_memory(MemoryPolicy::from_limit(1 << 24))
        .with_password(Some(rarkit::Password::from(PASSWORD)))
}

struct Ran {
    bytes: u64,
    took: Duration,
    checksums: Vec<Option<bool>>,
}

fn run(bytes: Vec<u8>, ceiling: u64, parallel: bool) -> Ran {
    let source: Arc<dyn RangeSource> = Arc::new(bytes);
    let mut sink = Counting {
        ceiling,
        bytes: Arc::default(),
        checksums: Arc::default(),
    };
    let total = Arc::clone(&sink.bytes);
    let checksums = Arc::clone(&sink.checksums);
    let start = Instant::now();
    let _ = if parallel {
        extract_parallel(vec![source], &options(), &sink, 4)
    } else {
        extract(vec![source], &options(), &mut sink, &mut ())
    };
    let took = start.elapsed();
    let seen = checksums.lock().map(|s| s.clone()).unwrap_or_default();
    Ran {
        bytes: total.load(Ordering::Relaxed),
        took,
        checksums: seen,
    }
}

/// SPEC-A 6.1 acceptance tests 1, 2 and 3, on both fixtures and through
/// BOTH public entry points.
///
/// 1. No panic, no allocation proportional to the declared size, and the
///    output streamed: the ceiling is what would catch an unbounded
///    decode, and the wall is what would catch one proportional to the
///    declared 4 GiB.
/// 2. The shortfall arrives as `checksum_ok == Some(false)` and NOT as an
///    error, on at least one member of each.
/// 3. The output is far below the declared size. No byte count is
///    asserted: the overshoot is unspecified.
#[test]
fn the_fixtures_stop_at_their_packed_input() {
    for (name, input) in inputs() {
        let built = archive(&input);
        for parallel in [false, true] {
            let ran = run(built.clone(), 1 << 20, parallel);
            assert!(
                ran.bytes < 1 << 20,
                "{name} parallel {parallel}: {} bytes from {} packed ones, \
                 for a member declaring about 4 GiB: SPEC-A 6.1 ends the \
                 decode when the packed input is exhausted",
                ran.bytes,
                input.len()
            );
            assert!(
                ran.took < Duration::from_secs(10),
                "{name} parallel {parallel}: {:?} for a decode the packed \
                 input ends in microseconds",
                ran.took
            );
            assert!(
                ran.checksums.contains(&Some(false)),
                "{name} parallel {parallel}: the shortfall is reported as a \
                 member checksum failure (SPEC-A 6.1, SPEC-F 2.5), and these \
                 members reported {:?}",
                ran.checksums
            );
        }
    }
}

/// The two fixtures are `f_extract_any` INPUTS and are also its seeds, so
/// the files under `fixtures/` and the files under `fuzz/seeds/` must be
/// the same bytes.
#[test]
fn the_fixtures_are_the_seeds() {
    for (name, input) in inputs() {
        for target in ["f_extract_any", "f_extract_parallel"] {
            let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("fuzz/seeds")
                .join(target)
                .join(format!("rar15-packed-bound-{name}"));
            let seed = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            assert_eq!(seed, input, "{}: not the fixture's bytes", path.display());
        }
    }
}

/// A plain report, kept for the measurement. Ignored because before the
/// bound it ran for two minutes at four gigabytes; it is milliseconds now.
///
/// `cargo test --release --test rar15_packed_bound -- --ignored --nocapture`
#[test]
#[ignore = "the amplification measurement; see the note above"]
fn report_the_two_fixtures() {
    for (name, bytes) in inputs() {
        let len = bytes.len();
        let built = archive(&bytes);
        describe(name, &built);
        let ran = run(built, u64::MAX, false);
        println!(
            "{name}: {len} input bytes, delivered {} bytes in {:?}, checksums {:?}",
            ran.bytes, ran.took, ran.checksums
        );
    }
}

/// The minimised fixture alone, through the SEQUENTIAL `Archive::extract`:
/// the shape the amplification was measured on (6.1's evidence paragraph).
/// Ignored for the same reason as the report above.
#[test]
#[ignore = "the amplification measurement; see the note above"]
fn report_the_minimised_fixture() {
    let bytes = fixture("declared-4gb-minimised.rar");
    let len = bytes.len();
    let built = archive(&bytes);
    describe("minimised", &built);
    let ran = run(built, u64::MAX, false);
    println!(
        "minimised: {len} input bytes, delivered {} bytes in {:?}, checksums {:?}",
        ran.bytes, ran.took, ran.checksums
    );
}
