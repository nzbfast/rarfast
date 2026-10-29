//! What ends a RAR 1.5 member whose DECLARED UNPACKED SIZE is corrupt: the
//! PACKED INPUT, not the declared size (spec A 6.1).
//!
//! # This file was INVERTED on 20 Sep 2026, and why
//!
//! It used to pin the opposite contract, and it was right to. Spec A once
//! said that the member ends when the output reaches its declared size
//! "whatever that costs in zero bits", so a member declaring 4.27 GB over
//! 12,309 intact packed bytes was decoded to 4.27 GB, at the decoder's
//! ordinary 270 to 290 MB/s and about 2.1 billion steps. Reference `unrar`
//! 7.23 does not do that - it stops `DATA.BIN` at 96% with "checksum
//! error" in 21,666,481 instructions and 2.5 MB peak RSS - and the
//! difference, once measured, was pinned
//! here rather than making rarkit match anything.
//!
//! **That difference was settled on 20 Sep 2026 by adopting
//! the reference's bound.** Spec A 4.11 and section 6's table now say it in
//! their own words: a step that BEGINS with the packed input already
//! exhausted is not taken, and the member ends there, short of its declared
//! size. The outcome is a member CHECKSUM failure - `checksum_ok ==
//! Some(false)`, not an error - so no error variant, no API surface and no
//! `MemoryPolicy` field moved. The overshoot is deliberately not specified:
//! a step that begins with one real bit left may read section 2's zero
//! padding to finish, so the member may pass its true size by part of one
//! step, and nothing here asserts a byte count.
//!
//! So the difference this file pinned is gone, and a NEW one takes its
//! place: rarkit now agrees with the reference and differs from the OLD
//! engine, which followed the earlier contract. Spec A 7.2 carries the
//! named exclusion for exactly this shape, and SPEC-D 3.3.2 and SPEC-H3
//! 9.3 carry it for RAR 2.0. That trade - one differential for the other -
//! was the project owner's to make, and was made.
//!
//! # What is still true from before
//!
//! The 19 Sep 2026 concurrent-member-decode campaign
//! found four inputs on which the RAR 1.5 decoder
//! did not come back. That was never a stuck loop: the work was
//! proportional to the OUTPUT, and the output was the declared size. The
//! 2.00 bytes a step it ran at is not a coincidence either - once the
//! packed bytes were spent, section 2's padding made every bit read 0,
//! all-zero bits decode to short index 0 under either of 4.3's tables, and
//! index 0 is a D6f near match of length exactly 2. The bound removes the
//! whole of that work rather than capping it: 4.11 still forbids an
//! iteration cap, and there is none here.
//!
//! Measured on this file's own construction, aarch64 release, 18-core
//! laptop: the minimised campaign reproducer took 13.045 s and delivered
//! 4,287,955,464 bytes before the bound, and 106 microseconds and 520
//! bytes after it.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rarkit::{
    extract, Disposition, MemberInfo, MemberOutcome, MemoryPolicy, RangeSource, ReadOptions,
    Result, Sink,
};

/// `D140_M5.RAR`, the genuine DOS RAR 1.40 vector of spec F section 5.
fn vector() -> Vec<u8> {
    let path = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../specs/vectors-F/archives/D140_M5.RAR"
    ));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Where `DATA.BIN`'s declared unpacked size sits in that vector, and what
/// the two size fields hold when it is undamaged.
///
/// Asserted rather than assumed: every construction below rewrites four bytes
/// at a fixed offset, so if the vector is ever replaced these tests must fail
/// loudly instead of quietly measuring something else.
const SIZE_AT: usize = 132;
const TRUE_UNPACKED: u32 = 20_192;
const TRUE_PACKED: u32 = 12_309;
const VECTOR_LEN: usize = 12_917;

/// The vector's password (spec F section 5).
const PASSWORD: &str = "Secret";

/// The pristine vector with `DATA.BIN`'s declared unpacked size set to
/// `declared` and NOTHING else touched.
fn declaring(declared: u32) -> Vec<u8> {
    let mut bytes = vector();
    assert_eq!(
        bytes.len(),
        VECTOR_LEN,
        "D140_M5.RAR changed under this test"
    );
    let field = SIZE_AT..SIZE_AT + 4;
    assert_eq!(
        u32::from_le_bytes(bytes[field.clone()].try_into().expect("four bytes")),
        TRUE_UNPACKED,
        "DATA.BIN's declared unpacked size is not at offset {SIZE_AT} any more"
    );
    assert_eq!(
        u32::from_le_bytes(bytes[SIZE_AT - 4..SIZE_AT].try_into().expect("four bytes")),
        TRUE_PACKED,
        "DATA.BIN's declared PACKED size is not at offset {} any more",
        SIZE_AT - 4
    );
    bytes[field].copy_from_slice(&declared.to_le_bytes());
    bytes
}

/// The three seeds the 19 Sep campaign found, as `f_extract_parallel` reads
/// them, with the declared size each one drives `DATA.BIN` to.
///
/// The seed files themselves are in `fuzz/seeds/f_extract_parallel`; these
/// are the same bytes in hex so the test needs no file and the two cannot
/// drift apart unseen (`the_pinned_seed_files_are_these_bytes`).
const SEEDS: [(&str, &str, u64); 3] = [
    (
        "rar15-declared-size-671mb",
        "090000d700d7000300000000000000000000081f0028000133",
        671_109_608,
    ),
    (
        "rar15-declared-size-46mb",
        "0900000000000000000000000000000000000000bd02a40120",
        45_960_928,
    ),
    (
        "rar15-declared-size-4gb",
        "090800000000000000000000000000000000ffff09ff2dff2d",
        4_278_825_247,
    ),
];

fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex pair"))
        .collect()
}

/// `f_extract_parallel`'s own mapping from a seed to an archive: byte 0 picks
/// the vector, bytes 3.. are exclusive-ored over it from an offset byte 0 also
/// picks. All three seeds pick `D140_M5.RAR` and offset 117.
fn damaged(seed: &[u8]) -> Vec<u8> {
    let mut bytes = vector();
    let at = usize::from(seed[0]) * 13 % bytes.len();
    assert_eq!(at, 117, "the seed's damage offset moved");
    for (i, b) in seed[3..].iter().enumerate().take(bytes.len() - at) {
        bytes[at + i] ^= b;
    }
    bytes
}

/// A sink that counts and keeps nothing, and refuses past a ceiling so a
/// regression to UNBOUNDED output fails the test instead of the machine.
///
/// The counter is shared rather than held by the sink because the writer the
/// engine is given outlives the `open` that made it.
#[derive(Default)]
struct Counting {
    ceiling: u64,
    bytes: Arc<AtomicU64>,
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
        _outcome: &MemberOutcome,
    ) -> Result<()> {
        Ok(())
    }
}

fn options() -> ReadOptions {
    ReadOptions::default()
        .with_memory(MemoryPolicy::from_limit(1 << 26))
        .with_password(Some(rarkit::Password::from(PASSWORD)))
}

/// Extract `bytes`, answering how much the sink was handed and how long it
/// took. The ceiling is the sink's, not an iteration cap in the decoder:
/// spec A 4.11 forbids one of those and nothing here adds one.
fn run(bytes: Vec<u8>, ceiling: u64) -> (u64, Duration) {
    let source: Arc<dyn RangeSource> = Arc::new(bytes);
    let mut sink = Counting {
        ceiling,
        bytes: Arc::default(),
    };
    let total = Arc::clone(&sink.bytes);
    let start = Instant::now();
    let _ = extract(vec![source], &options(), &mut sink, &mut ());
    (total.load(Ordering::Relaxed), start.elapsed())
}

/// Extract `bytes` and answer the engine's own report, which is where a
/// member's checksum verdict is counted.
fn report(bytes: Vec<u8>) -> Result<rarkit::ExtractReport> {
    let source: Arc<dyn RangeSource> = Arc::new(bytes);
    let mut sink = Counting {
        ceiling: 1 << 20,
        bytes: Arc::default(),
    };
    extract(vec![source], &options(), &mut sink, &mut ())
}

/// The seed files and the hex above are the same bytes.
#[test]
fn the_pinned_seed_files_are_these_bytes() {
    for (name, hex, _) in SEEDS {
        let path = PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fuzz/seeds/f_extract_parallel"
        ))
        .join(name);
        let on_disk = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(on_disk, unhex(hex), "{name} on disk is not the seed above");
    }
}

/// Each seed reaches `DATA.BIN` with the declared size the campaign recorded,
/// and NONE of the three can be listed.
///
/// Both halves matter. The declared size is read straight out of the header
/// field the damage lands on, which costs nothing and is exact. The listing
/// failing is the other half, and it is the reason `f_extract_parallel` could
/// not bound these by listing them: `Archive::open` answers `Truncated`, so
/// the target's `MOST_OUTPUT` gate never ran and the walk decoded them anyway.
/// The target now caps its SINK instead, which needs no listing; if this
/// assertion ever flips, that cap is still correct but its comment is not.
#[test]
fn each_seed_still_declares_the_size_the_campaign_recorded() {
    for (name, hex, declared) in SEEDS {
        let bytes = damaged(&unhex(hex));
        let field = u32::from_le_bytes(bytes[SIZE_AT..SIZE_AT + 4].try_into().expect("four bytes"));
        assert_eq!(
            u64::from(field),
            declared,
            "{name}: DATA.BIN's declared unpacked size moved"
        );
        let source: Arc<dyn RangeSource> = Arc::new(bytes);
        let listed = rarkit::Archive::open(source, &options());
        assert!(
            listed.is_err(),
            "{name}: this archive now lists, so the note above is stale"
        );
    }
}

/// THE REGRESSION GUARD, inverted. A member declaring far more than its
/// packed input can supply stops at the packed input, not at the declared
/// size.
///
/// This is spec A 6.1's acceptance test 3, which is the one test the
/// decision changed: the number of output bytes is about the member's TRUE
/// size and not its declared one. What is asserted is only that the count
/// is far below the declared size - never a byte count, because the
/// overshoot is unspecified - and that the work no longer tracks the
/// declared size at all.
///
/// A gigabyte and not a mebibyte now, and that is the point: under the old
/// contract this construction could only be run at a mebibyte because a
/// debug build would not finish 4.27 GB. Under the bound the size of the
/// declaration costs nothing whatsoever, so the test asserts that directly
/// by declaring 4,294,967,280 and expecting milliseconds.
#[test]
fn an_inflated_declared_size_stops_at_the_packed_input() {
    // The largest a u32 field can hold, rounded down: the same figure spec
    // A 6.1's observed table used.
    const DECLARED: u32 = 4_294_967_280;
    // The whole vector's six members total 37,212 bytes when undamaged, of
    // which DATA.BIN is 20,192. A ceiling well above that and far below the
    // declared size fails a decode that ignores the bound.
    const CEILING: u64 = 1 << 20;
    let (bytes, took) = run(declaring(DECLARED), CEILING);
    assert!(
        bytes < CEILING,
        "a member declaring {DECLARED} over {TRUE_PACKED} packed bytes \
         delivered {bytes}: spec A 6.1 ends it when the packed input is \
         exhausted"
    );
    // The member is still DECODED, and nearly all of it: what the bound
    // removes is only the part the packed input never supported. Its true
    // size is 20,192 and the archive's other members add 17,020, so a
    // bound that fired early would show up here.
    assert!(
        bytes > 30_000,
        "only {bytes} bytes from an intact 12,309 byte packed extent: the \
         bound fired before the packed input was spent"
    );
    assert!(
        took < Duration::from_secs(10),
        "a member declaring {DECLARED} took {took:?}: the decode is still \
         proportional to the declared size"
    );
}

/// Acceptance test 2 of spec A 6.1: the shortfall arrives as a member
/// CHECKSUM failure and not as an error.
///
/// Held either way by the decision, and it is the half that says no API
/// surface moved. The pristine vector is the control: the same call on
/// undamaged bytes fails no checksum at all.
#[test]
fn the_shortfall_is_a_checksum_failure_and_not_an_error() {
    let short = report(declaring(4_294_967_280))
        .expect("a member short of its declared size is not an error");
    assert_eq!(
        short.checksum_failures, 1,
        "exactly DATA.BIN's checksum fails"
    );
    let pristine = report(vector()).expect("the undamaged vector extracts");
    assert_eq!(
        pristine.checksum_failures, 0,
        "the undamaged vector fails no checksum"
    );
    assert_eq!(
        pristine.members, short.members,
        "the same members are reported either way"
    );
}

/// The undamaged vector is untouched by all of the above.
#[test]
fn the_pristine_vector_still_decodes_to_its_true_size() {
    let (bytes, _) = run(vector(), 1 << 20);
    assert_eq!(
        bytes, 37_212,
        "D140_M5.RAR's six members total 37,212 bytes"
    );
    let (same, _) = run(declaring(TRUE_UNPACKED), 1 << 20);
    assert_eq!(
        same, 37_212,
        "rewriting the field with its own value changed it"
    );
}

/// The three seeds the 19 Sep campaign found, decoded under the bound.
///
/// They declare 671 MB, 45.9 MB and 4.27 GB, which was 18 seconds of
/// release decode and minutes of a debug one; under spec A 6.1 they are
/// milliseconds, so this no longer needs to be ignored. What it pins is
/// that the bound reaches the shapes the campaign actually hit, and not
/// only this file's own controlled construction.
#[test]
fn the_three_seeds_stop_at_their_packed_input() {
    for (name, hex, declared) in SEEDS {
        let (bytes, took) = run(damaged(&unhex(hex)), 1 << 20);
        println!("{name}: declared {declared}, delivered {bytes}, {took:?}");
        assert!(
            bytes < 1 << 20,
            "{name}: {bytes} bytes delivered for a declared {declared}, so \
             the decode still tracks the declared size"
        );
        assert!(
            took < Duration::from_secs(10),
            "{name}: {took:?} for a member the packed input ends at once"
        );
    }
}
