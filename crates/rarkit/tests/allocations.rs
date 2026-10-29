//! API promise 2.4 and spec F 7.3.2: no allocation per header, per member
//! or per name, on the listing path OR the extract path.
//!
//! The crate's own unit test counts the stored RAR 5 and RAR 4 shapes. This
//! one counts the shapes only the writer can build - a BLAKE2sp checksum
//! per member, and an encrypted member per member - because each of those
//! carries per-member state and each is a place the promise can be lost
//! without any output changing.
//!
//! Counted per MEMBER, by the difference between two member counts: a
//! figure for one archive says nothing, since the arena and the table grow
//! geometrically and a run's fixed costs are the bulk of a small archive.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Arc;

use rarkit::{
    extract, ChecksumKind, Disposition, MemberInfo, MemberOutcome, MemberSpec, Payload,
    RangeSource, ReadOptions, Result, Sink, WriteOptions, Writer,
};

thread_local! {
    static ALLOCS: Cell<u64> = const { Cell::new(0) };
    static COUNTING: Cell<bool> = const { Cell::new(false) };
}

struct Counting;

#[allow(unsafe_code)]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.try_with(Cell::get).unwrap_or(false) {
            let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if COUNTING.try_with(Cell::get).unwrap_or(false) {
            let _ = ALLOCS.try_with(|c| c.set(c.get() + 1));
        }
        unsafe { System.realloc(ptr, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Run `body` with the allocations on this thread counted.
fn counted<T>(body: impl FnOnce() -> T) -> (T, u64) {
    ALLOCS.with(|c| c.set(0));
    COUNTING.with(|c| c.set(true));
    let value = body();
    COUNTING.with(|c| c.set(false));
    (value, ALLOCS.with(Cell::get))
}

/// A sink that verifies and keeps nothing, so every allocation counted is
/// the engine's own.
struct Verify;

impl Sink for Verify {
    type Out = Vec<u8>;

    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Verify)
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        _out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        assert_eq!(outcome.checksum_ok, Some(true), "the corpus is sound");
        Ok(())
    }
}

/// `count` stored members of 64 bytes each, written with `options`.
fn archive(count: usize, options: WriteOptions) -> Vec<u8> {
    let mut writer = Writer::new(options).expect("options");
    let names: Vec<Vec<u8>> = (0..count)
        .map(|i| format!("member{i:06}.txt").into_bytes())
        .collect();
    let body = vec![b'x'; 64];
    for name in &names {
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(&body),
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

/// A solid RAR 5 chain of `count` compressed members, each 4 KiB of text
/// of its own: small enough that a chain of a thousand is quick to write,
/// and all of one size, so that what a longer chain costs is its members
/// and nothing else.
fn solid_chain(count: usize) -> Vec<u8> {
    let mut writer = Writer::new(WriteOptions {
        solid: true,
        order: rarkit::MemberOrder::AsAdded,
        method: rarkit::WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
        workers: Some(1),
        ..WriteOptions::default()
    })
    .expect("options");
    let names: Vec<Vec<u8>> = (0..count)
        .map(|i| format!("member{i:06}.txt").into_bytes())
        .collect();
    let bodies: Vec<Vec<u8>> = (0..count)
        .map(|i| rarkit_testdata::chatter(i as u64, 4 << 10))
        .collect();
    for (name, body) in names.iter().zip(&bodies) {
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(body),
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

/// Extract `bytes` and answer how many allocations it took.
fn extract_allocations(bytes: &[u8], read: &ReadOptions) -> (u64, u64) {
    let sources = vec![Arc::new(bytes.to_vec()) as Arc<dyn RangeSource>];
    let (report, allocations) =
        counted(|| extract(sources, read, &mut Verify, &mut ()).expect("the corpus extracts"));
    (report.members, allocations)
}

/// The allocations one more member costs, from two counts far enough apart
/// that the fixed costs cancel.
fn per_member(small: (usize, u64), large: (usize, u64)) -> f64 {
    (large.1 as f64 - small.1 as f64) / (large.0 as f64 - small.0 as f64)
}

const SMALL: usize = 250;
const LARGE: usize = 1_000;

#[test]
fn extracting_crc32_members_allocates_nothing_per_member() {
    let cheap = |n| {
        let bytes = archive(
            n,
            WriteOptions {
                entropy: rarkit::Entropy::Seeded([1; 32]),
                ..WriteOptions::default()
            },
        );
        let (members, allocations) = extract_allocations(&bytes, &ReadOptions::default());
        assert_eq!(members, n as u64);
        (n, allocations)
    };
    let small = cheap(SMALL);
    let large = cheap(LARGE);
    let each = per_member(small, large);
    eprintln!("    CRC32: {small:?} {large:?}, {each:.3} per member");
    assert!(
        each < 0.05,
        "{each:.3} allocations per member: {small:?} {large:?}"
    );
}

/// A BLAKE2sp member carries a hash state, and a state allocated per member
/// is an allocation per member.
#[test]
fn extracting_blake2sp_members_allocates_nothing_per_member() {
    let cheap = |n| {
        let bytes = archive(
            n,
            WriteOptions {
                checksum: ChecksumKind::Blake2sp,
                entropy: rarkit::Entropy::Seeded([2; 32]),
                ..WriteOptions::default()
            },
        );
        let (members, allocations) = extract_allocations(&bytes, &ReadOptions::default());
        assert_eq!(members, n as u64);
        (n, allocations)
    };
    let small = cheap(SMALL);
    let large = cheap(LARGE);
    let each = per_member(small, large);
    eprintln!("    BLAKE2sp: {small:?} {large:?}, {each:.3} per member");
    assert!(
        each < 0.05,
        "{each:.3} allocations per member: {small:?} {large:?}"
    );
}

/// An encrypted member carries a key schedule and the password reaches it
/// through the session. Neither may cost an allocation per member: the key
/// derivation is cached per (salt, password) by spec F 3.7.5, and one
/// archive has one salt.
#[test]
fn extracting_encrypted_members_allocates_nothing_per_member() {
    let cheap = |n| {
        let bytes = archive(
            n,
            WriteOptions {
                password: Some(rarkit::Password::from("Secret")),
                entropy: rarkit::Entropy::Seeded([3; 32]),
                ..WriteOptions::default()
            },
        );
        let read = ReadOptions::default().with_password(Some(rarkit::Password::from("Secret")));
        let (members, allocations) = extract_allocations(&bytes, &read);
        assert_eq!(members, n as u64);
        (n, allocations)
    };
    let small = cheap(SMALL);
    let large = cheap(LARGE);
    let each = per_member(small, large);
    eprintln!("    encrypted: {small:?} {large:?}, {each:.3} per member");
    assert!(
        each < 0.05,
        "{each:.3} allocations per member: {small:?} {large:?}"
    );
}

/// SPEC-H2 section 4.2: the chain's DECODE-AHEAD allocates nothing per
/// member either.
///
/// It is the one stage whose memory grows with the members held AHEAD
/// rather than with the width, so it is the one that could quietly take
/// an allocation per member back: a work item, a packed copy, a tape and
/// a table handle are all per member if they are not pooled.
///
/// They are pooled, and this asserts it TWICE, because one counter alone
/// could not see it.
///
/// **The allocation counter above this file is a thread-local**: it sees
/// the CALLING thread only, and the decode-ahead does its work on lanes
/// of its own, so a stage that allocated a tape per member on a lane
/// would read as perfectly pooled here. That half is still worth
/// asserting, because the claim path and the offering cursor DO run on
/// the calling thread.
///
/// The other half is the stage's own count of what its pools could not
/// answer, which is thread agnostic. Section 4.2's "no allocation per
/// member" means that number is bounded by the QUEUE and does not grow
/// with the chain, so a chain four times longer must not cost four times
/// as many.
///
/// **Why the calling thread's half STATES the width.** The difference of
/// two counts cancels a fixed cost only when the cost is the same in both
/// runs, and a default stage has two that are not, neither of them per
/// member. It GROWS: after its apply stage has waited eight times it opens
/// one more lane, up to the width, and a lane start is about fourteen
/// allocations on the calling thread (the thread, its name and two
/// channels). Whether those waits come inside the 250 member run or the
/// 1,000 member one is scheduling: counted with a backtrace per allocation
/// on 29 Sep 2026, the short run waited 0 or 1 times and the long one 0 to
/// 16, and two grown lanes read 0.059 per member, the failure on record,
/// every other site identical. And its queue is 64 deep, so its pooled
/// packed buffers, which grow to the longest member each has held and
/// never shrink, are still reaching that mark at member 250 (about 15 of
/// the difference, in every run). Both are bounded, by the width and by
/// the queue. A stated width opens every lane at the first offer, never
/// grows, and holds a queue four lanes deep that is warm long before
/// member 250, so what the difference still sees is what grows with the
/// chain, which is the property. Nothing is taken out of the count, and
/// the test checks that both runs held the same lanes. The default,
/// growing stage keeps half two, which a lane start does not reach.
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn a_solid_chain_decode_ahead_allocates_nothing_per_member() {
    let small_chain = solid_chain(SMALL);
    let large_chain = solid_chain(LARGE);
    let count = |bytes: &[u8], n: usize, read: &ReadOptions| {
        rarkit::probe::reset_ahead_claims();
        let (members, allocations) = extract_allocations(bytes, read);
        assert_eq!(members, n as u64);
        (
            (n, allocations),
            rarkit::probe::ahead_claims(),
            rarkit::probe::ahead_allocs(),
            rarkit::probe::ahead_peak_lanes(),
        )
    };

    // Half one: the calling thread, at a stated width of three, which is
    // the lanes a default stage opens with.
    let stated = ReadOptions::default().with_workers(Some(3));
    let (small, small_claims, _, small_lanes) = count(&small_chain, SMALL, &stated);
    let (large, large_claims, _, large_lanes) = count(&large_chain, LARGE, &stated);

    // The stage RAN, or the rest of this test is about nothing.
    assert!(
        small_claims > 0 && large_claims > 0,
        "the decode-ahead never fired on a solid RAR 5 chain, so this test          asserts nothing about it ({small_claims} and {large_claims} claims)"
    );
    assert_eq!(
        small_lanes, large_lanes,
        "a stated width must hold its lanes, or the difference below counts          a lane start"
    );

    let each = per_member(small, large);
    eprintln!(
        "    solid chain: {small:?} {large:?}, {each:.3} per member on the          calling thread at {small_lanes} lanes"
    );
    assert!(
        each < 0.05,
        "{each:.3} allocations per member on a solid chain: {small:?} {large:?}"
    );

    // Half two: every thread, counted by the stage, at the default width.
    // A chain four times longer must not cost four times as much.
    let default = ReadOptions::default();
    let (_, small_claims, small_allocs, _) = count(&small_chain, SMALL, &default);
    let (_, large_claims, large_allocs, _) = count(&large_chain, LARGE, &default);
    assert!(
        small_claims > 0 && large_claims > 0,
        "the default decode-ahead never fired on a solid RAR 5 chain          ({small_claims} and {large_claims} claims)"
    );
    eprintln!(
        "    solid chain, default width: the stage made {small_allocs} and          {large_allocs} fresh, against {small_claims} and {large_claims}          members claimed"
    );
    assert!(
        large_allocs <= small_allocs * 2,
        "the stage made {small_allocs} fresh allocations for {SMALL} members          and {large_allocs} for {LARGE}, so something in it is per member"
    );
}
