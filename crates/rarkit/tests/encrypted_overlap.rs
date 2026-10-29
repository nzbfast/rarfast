//! THE ACCEPTANCE TESTS OF SPEC F 3.7.7: an encrypted stored
//! member's cipher output feeds its hasher AS IT IS PRODUCED.
//!
//! The rule is about an ARRANGEMENT of work, so every test here is the
//! same question in a different shape: **the bytes, the digest and the
//! verdict are identical with the overlap on and off, and the calls the
//! caller's writer sees are the same calls.** A performance change that
//! can alter a checksum is not a performance change, and the two legs
//! the rule names (`f/test-one-stored-encrypted`,
//! `f/extract-one-stored-encrypted`) are BLAKE2sp legs, so a hasher fed
//! one chunk out of order, one chunk twice or one chunk short would
//! still extract the right bytes and quietly fail the digest.
//!
//! **Why the counter is read before anything is compared.** All four of
//! `overlap_plan`'s conditions are satisfiable by accident in a small
//! fixture, and two sequential extractions agree with each other
//! perfectly. So `probe::cipher_overlaps` is asserted FIRST in every
//! test that claims to exercise the overlap: without that, this file
//! would keep passing if the overlap stopped engaging altogether, which
//! is exactly the failure a later change moving `OVERLAP_FLOOR` would
//! introduce.
//!
//! `probe::set_cipher_overlap` is what lets these fixtures be megabytes
//! rather than the gate legs' 64 MiB. SPEC-API 8.5 promises nothing
//! about whether a given member is overlapped, so neither answer is an
//! API fact.

#![cfg(all(feature = "test-support", feature = "parallel"))]

use std::io::Write;
use std::sync::{Arc, Mutex};

use rarkit::{
    probe, ChecksumKind, Disposition, HostOs, MemberInfo, MemberOutcome, MemberSpec, Password,
    Payload, RangeSource, ReadOptions, Result, Sink, WriteMethod, WriteOptions, Writer,
};

const PASSWORD: &str = "overlap";

/// Material no cipher and no hasher can shortcut: a run of one byte
/// would let a dropped chunk still produce the right digest.
fn body(bytes: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes + 64);
    let mut seed = 0x2026_0921_1500_u64;
    while out.len() < bytes {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        out.extend_from_slice(&seed.to_le_bytes());
    }
    out.truncate(bytes);
    out
}

/// One stored, encrypted, BLAKE2sp member of `payload`.
fn archive(payload: &[u8]) -> Vec<u8> {
    let mut writer = Writer::new(WriteOptions {
        method: WriteMethod::Stored,
        checksum: ChecksumKind::Blake2sp,
        password: Some(Password::from(PASSWORD)),
        ..WriteOptions::default()
    })
    .expect("options");
    writer
        .add(MemberSpec {
            name: b"one.dat",
            payload: Payload::Bytes(payload),
            mtime: None,
            attributes: 0,
            host_os: HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    out
}

fn options() -> ReadOptions {
    ReadOptions::default().with_password(Some(Password::from(PASSWORD)))
}

fn sources(archive: &[u8]) -> Vec<Arc<dyn RangeSource>> {
    vec![Arc::new(archive.to_vec()) as Arc<dyn RangeSource>]
}

/// Run the next extraction on this thread with the overlap on, or off.
struct Overlap;

impl Overlap {
    fn on() -> Overlap {
        probe::set_cipher_overlap(Some(true));
        probe::reset_cipher_overlaps();
        Overlap
    }
    fn off() -> Overlap {
        probe::set_cipher_overlap(Some(false));
        probe::reset_cipher_overlaps();
        Overlap
    }
}

impl Drop for Overlap {
    fn drop(&mut self) {
        probe::set_cipher_overlap(None);
    }
}

#[derive(Default)]
struct Keep {
    bytes: Vec<u8>,
    /// The LENGTH of each `write` in call order, which is spec F 3.7.6's
    /// promise about what a refusing writer is offered.
    writes: Vec<usize>,
    verdict: Option<Option<bool>>,
    reported: u64,
}

struct Recorder {
    held: Arc<Mutex<Keep>>,
    /// Refuse once this many bytes have been written, for the
    /// cancellation test.
    ceiling: Option<usize>,
}

impl Write for Recorder {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ceiling) = self.ceiling {
            if held.bytes.len() >= ceiling {
                return Err(std::io::Error::other("the caller's writer refused"));
            }
        }
        held.bytes.extend_from_slice(data);
        held.writes.push(data.len());
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Recording {
    held: Arc<Mutex<Keep>>,
    ceiling: Option<usize>,
}

impl Sink for Recording {
    type Out = Recorder;

    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Recorder>> {
        Ok(Disposition::Write(Recorder {
            held: Arc::clone(&self.held),
            ceiling: self.ceiling,
        }))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        _out: Option<Recorder>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        held.verdict = Some(outcome.checksum_ok);
        held.reported = outcome.bytes;
        Ok(())
    }
}

/// Extract with the overlap as `on` says, and answer what the sink saw,
/// how the call ended, and how many members actually overlapped.
fn run(archive: &[u8], on: bool, ceiling: Option<usize>) -> (Keep, bool, u64) {
    let _arm = if on { Overlap::on() } else { Overlap::off() };
    let held = Arc::new(Mutex::new(Keep::default()));
    let mut sink = Recording {
        held: Arc::clone(&held),
        ceiling,
    };
    let ok = rarkit::extract(sources(archive), &options(), &mut sink, &mut ()).is_ok();
    let overlapped = probe::cipher_overlaps();
    drop(sink);
    let keep = Arc::try_unwrap(held)
        .unwrap_or_else(|_| panic!("the sink outlived the extraction"))
        .into_inner()
        .unwrap_or_else(|e| e.into_inner());
    (keep, ok, overlapped)
}

/// Sizes chosen for the seams the overlap has: several chunks, a size
/// that is not a whole number of chunks, and - the one that matters for
/// an ENCRYPTED stored member - a size that is not a whole number of
/// AES blocks, so the last packed block carries padding the member does
/// not own and `emit` must drop (spec F 4.2). If the overlap hashed what
/// it read instead of what `emit` accepted, only this size would catch
/// it.
const SIZES: &[usize] = &[
    5 << 20,       // several whole chunks
    (5 << 20) + 7, // a short last chunk AND a padded last cipher block
    (4 << 20) + 1, // one byte into a second chunk
    (2 << 20) - 1, // one byte under a single chunk
    1 << 20,       // exactly the floor
];

#[test]
fn the_overlap_and_the_sequence_give_the_same_bytes_digest_and_verdict() {
    for &size in SIZES {
        let payload = body(size);
        let archive = archive(&payload);

        let (with, ok_with, overlapped) = run(&archive, true, None);
        let (without, ok_without, sequential) = run(&archive, false, None);

        assert_eq!(
            overlapped, 1,
            "{size}: the overlapped arm did not overlap, so this test proves nothing"
        );
        assert_eq!(
            sequential, 0,
            "{size}: the sequential arm overlapped, so there is no control"
        );

        assert!(ok_with && ok_without, "{size}: an arm failed to extract");
        assert_eq!(
            with.verdict,
            Some(Some(true)),
            "{size}: the overlapped arm's BLAKE2sp did not match the recorded digest"
        );
        assert_eq!(with.verdict, without.verdict, "{size}: verdicts differ");
        assert_eq!(with.bytes, payload, "{size}: the overlapped arm's bytes");
        assert_eq!(without.bytes, payload, "{size}: the sequential arm's bytes");
        assert_eq!(with.reported, without.reported, "{size}: reported bytes");
        assert_eq!(
            with.reported, size as u64,
            "{size}: the member's padding was reported as output"
        );
    }
}

/// Spec F 3.7.6's promise: a refusing writer is offered exactly what
/// the sequential path offers it, so the overlap may neither coalesce
/// nor enlarge a write. The seam's own history is why this is pinned
/// rather than assumed: its deliver unit once handed a refusing writer
/// 1,049,096 bytes where the sequential path handed it 131,592, which
/// is that promise loosened by the size of a ring.
///
/// Equality, and not merely "no larger", because the overlap's chunk IS
/// the serial path's chunk: the second buffer sits behind the delivery
/// point and is not read-ahead, so nothing had to be halved to pay for
/// it. An earlier arrangement did halve it, and this test asserting
/// only "no larger" is what let that pass unremarked.
#[test]
fn the_overlap_makes_the_same_calls_on_the_callers_writer() {
    let payload = body((5 << 20) + 7);
    let archive = archive(&payload);
    let (with, _, overlapped) = run(&archive, true, None);
    let (without, _, _) = run(&archive, false, None);
    assert_eq!(overlapped, 1, "the overlapped arm did not overlap");
    assert_eq!(
        with.writes, without.writes,
        "the overlap changed the write boundaries the caller sees"
    );
}

/// **A WRONG PLAINTEXT MUST BE CAUGHT.** One flipped ciphertext bit
/// deciphers to a different chunk, and the member's recorded BLAKE2sp no
/// longer matches it. The overlapped arm has to reach the same verdict
/// as the sequential one, which it only does if it hashes every byte the
/// member accepted, once, in order.
#[test]
fn a_flipped_ciphertext_byte_fails_the_digest_in_both_arrangements() {
    let payload = body(5 << 20);
    let good = archive(&payload);
    // Well inside the member's packed bytes, past every header.
    let at = good.len() / 2;
    for bit in [0x01u8, 0x80] {
        let mut damaged = good.clone();
        damaged[at] ^= bit;
        let (with, _, overlapped) = run(&damaged, true, None);
        let (without, _, _) = run(&damaged, false, None);
        assert_eq!(overlapped, 1, "the overlapped arm did not overlap");
        assert_eq!(
            with.verdict,
            Some(Some(false)),
            "bit {bit:#04x}: the overlapped arm passed a damaged member"
        );
        assert_eq!(
            with.verdict, without.verdict,
            "bit {bit:#04x}: the two arrangements disagree about a damaged member"
        );
        assert_eq!(
            with.bytes, without.bytes,
            "bit {bit:#04x}: the two arrangements produced different bytes"
        );
    }
}

/// **EVERY CHUNK MUST REACH THE HASHER, ONCE AND IN ORDER**, which is
/// the failure an overlap makes possible and a sequential loop does
/// not. A member of twenty chunks is damaged one chunk at a time, at
/// the first byte of the chunk, in the middle and at the last byte, and
/// each damaged copy must FAIL in both arrangements. A hasher that
/// dropped a chunk, hashed one twice, or took two out of order would
/// pass some of these and fail others, and would disagree with the
/// sequential arm on exactly the chunks it mishandled.
#[test]
fn damage_in_any_chunk_fails_the_digest_in_both_arrangements() {
    // Twenty chunks. The chunk is driven DOWN with the dial rather than
    // the member being driven up: at the shipping chunk twenty of them
    // is an 80 MiB fixture, and what this test is about is the number of
    // hand-overs and not the size of them.
    let chunk = 256 << 10;
    probe::set_cipher_overlap_chunk(Some(chunk));
    let payload = body(20 * chunk + 3);
    let good = archive(&payload);
    // Where the member's packed bytes begin: the archive is longer than
    // the payload by its headers, and the payload is the tail of it.
    let data_at = good.len() - payload.len().div_ceil(16) * 16;

    let mut failed = 0;
    for chunk_index in 0..20 {
        for offset in [0usize, chunk / 2, chunk - 1] {
            let at = data_at + chunk_index * chunk + offset;
            assert!(at < good.len(), "chunk {chunk_index}: off the end");
            let mut damaged = good.clone();
            damaged[at] ^= 0x01;
            let (with, _, overlapped) = run(&damaged, true, None);
            let (without, _, sequential) = run(&damaged, false, None);
            assert_eq!(
                overlapped, 1,
                "chunk {chunk_index}: the arm did not overlap"
            );
            assert_eq!(sequential, 0, "chunk {chunk_index}: the control overlapped");
            assert_eq!(
                with.verdict,
                Some(Some(false)),
                "chunk {chunk_index} offset {offset}: the overlapped arm passed damaged bytes"
            );
            assert_eq!(
                with.verdict, without.verdict,
                "chunk {chunk_index} offset {offset}: the arrangements disagree"
            );
            assert_eq!(
                with.bytes, without.bytes,
                "chunk {chunk_index} offset {offset}: the arrangements produced different bytes"
            );
            failed += 1;
        }
    }
    probe::set_cipher_overlap_chunk(None);
    assert_eq!(failed, 60, "not every chunk was damaged and checked");
}

/// Cancellation: a refusing writer ends the operation under the overlap
/// exactly as it does without it, and the scope joins rather than
/// leaving the hasher running.
#[test]
fn a_refusing_writer_stops_an_overlapped_member() {
    let payload = body(5 << 20);
    let archive = archive(&payload);
    let (with, ok_with, overlapped) = run(&archive, true, Some(1 << 20));
    let (without, ok_without, _) = run(&archive, false, Some(1 << 20));
    assert_eq!(overlapped, 1, "the overlapped arm did not overlap");
    assert!(!ok_with, "the overlapped arm did not report the refusal");
    assert_eq!(
        ok_with, ok_without,
        "the two arrangements disagree about a refusal"
    );
    assert!(
        with.bytes.len() < payload.len(),
        "the overlapped arm wrote the whole member after a refusal"
    );
    assert!(
        with.bytes.len() <= without.bytes.len(),
        "the overlap wrote MORE after a refusal than the sequence did: {} against {}",
        with.bytes.len(),
        without.bytes.len()
    );
}

/// The engine's OWN answer, with no knob at all, still overlaps the
/// shape the rule is about and still gets the verdict right. Without
/// this the whole file could pass while `overlap_plan` refused every
/// real member.
#[test]
fn the_engine_overlaps_a_large_encrypted_member_with_no_knob_set() {
    // TWO chunks at the engine's own chunk, which at the default budget
    // is the 4 MiB `stored_copy_len` gives: a member of one chunk has no
    // successor to decipher under its hash and is refused on purpose.
    let payload = body(9 << 20);
    let archive = archive(&payload);
    probe::set_cipher_overlap(None);
    probe::reset_cipher_overlaps();
    let held = Arc::new(Mutex::new(Keep::default()));
    let mut sink = Recording {
        held: Arc::clone(&held),
        ceiling: None,
    };
    rarkit::extract(sources(&archive), &options(), &mut sink, &mut ()).expect("extract");
    let overlapped = probe::cipher_overlaps();
    drop(sink);
    let keep = Arc::try_unwrap(held)
        .unwrap_or_else(|_| panic!("the sink outlived the extraction"))
        .into_inner()
        .unwrap_or_else(|e| e.into_inner());
    assert_eq!(
        overlapped, 1,
        "the engine's own answer did not overlap a 5 MiB encrypted BLAKE2sp member"
    );
    assert_eq!(keep.verdict, Some(Some(true)));
    assert_eq!(keep.bytes, payload);
}

/// And the shapes the overlap must REFUSE, so it never spends a thread
/// on a member with nothing to hide: an unencrypted member (no serial
/// stage) and a CRC32 member (no wide stage).
#[test]
fn the_engine_does_not_overlap_a_member_with_nothing_to_hide() {
    for (label, checksum, password) in [
        ("unencrypted blake2sp", ChecksumKind::Blake2sp, None),
        ("encrypted crc32", ChecksumKind::Crc32, Some(PASSWORD)),
    ] {
        // Large enough that only the SHAPE keeps it off the overlapped
        // path, never the floor or the two-chunk rule.
        let payload = body(9 << 20);
        let mut writer = Writer::new(WriteOptions {
            method: WriteMethod::Stored,
            checksum,
            password: password.map(Password::from),
            ..WriteOptions::default()
        })
        .expect("options");
        writer
            .add(MemberSpec {
                name: b"one.dat",
                payload: Payload::Bytes(&payload),
                mtime: None,
                attributes: 0,
                host_os: HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
        let mut bytes = Vec::new();
        writer.finish_into(&mut bytes).expect("finish");

        probe::set_cipher_overlap(None);
        probe::reset_cipher_overlaps();
        let held = Arc::new(Mutex::new(Keep::default()));
        let mut sink = Recording {
            held: Arc::clone(&held),
            ceiling: None,
        };
        let opts = ReadOptions::default().with_password(password.map(Password::from));
        rarkit::extract(sources(&bytes), &opts, &mut sink, &mut ()).expect("extract");
        let overlapped = probe::cipher_overlaps();
        drop(sink);
        let keep = Arc::try_unwrap(held)
            .unwrap_or_else(|_| panic!("the sink outlived the extraction"))
            .into_inner()
            .unwrap_or_else(|e| e.into_inner());
        assert_eq!(
            overlapped, 0,
            "{label}: overlapped a member with no serial cipher in front of a wide hasher"
        );
        assert_eq!(keep.verdict, Some(Some(true)), "{label}");
        assert_eq!(keep.bytes, payload, "{label}");
    }
}

/// **RANDOM SIZES AND RANDOM CHUNKINGS, against the serial arm.**
///
/// The named fuzz targets of SPEC-K 6 exercise `MemberDecryptor` and the
/// hasher IN ISOLATION, and neither reaches `copy_overlapped`: a fuzz
/// input is bytes, and the overlap wants a member over `OVERLAP_FLOOR`
/// with at least two chunks in it, which no libFuzzer corpus will build.
/// So the arrangement's own coverage is here, and the tests above pin
/// five hand-picked sizes at one chunking. This adds the axis those
/// miss: the RELATIONSHIP between the member's length and the chunk,
/// which decides how many hand-overs there are, whether the last one is
/// short, and whether the final cipher block's padding lands on a chunk
/// boundary or inside one.
///
/// Deterministic, not random: a seeded sequence, so a failure is
/// reproducible from the printed case rather than from a re-run that
/// might not hit it. The oracle is the serial arm on the same bytes,
/// which is the strongest one available - it is the code this replaced.
#[test]
fn random_sizes_and_chunkings_agree_with_the_serial_arm() {
    let mut seed = 0x5eed_2026_0921_u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for case in 0..24 {
        // Chunks from a whole group up to a megabyte, and members from
        // under one chunk to a dozen of them, with the last chunk short
        // about as often as not.
        let chunk = 64 << (next() % 5); // 64 KiB .. 1 MiB
        let chunk = chunk << 10;
        let chunks = 1 + (next() % 12) as usize;
        let ragged = (next() % (chunk as u64)) as usize;
        let size = chunks * chunk + if case % 3 == 0 { 0 } else { ragged };
        if size == 0 {
            continue;
        }
        let payload = body(size);
        let archive = archive(&payload);

        probe::set_cipher_overlap_chunk(Some(chunk));
        let (with, ok_with, overlapped) = run(&archive, true, None);
        probe::set_cipher_overlap_chunk(None);
        let (without, ok_without, sequential) = run(&archive, false, None);

        let case = format!("case {case}: size {size}, chunk {chunk}");
        assert_eq!(overlapped, 1, "{case}: the overlapped arm did not overlap");
        assert_eq!(sequential, 0, "{case}: the control overlapped");
        assert!(ok_with && ok_without, "{case}: an arm failed to extract");
        assert_eq!(
            with.verdict,
            Some(Some(true)),
            "{case}: the overlapped arm's digest did not match"
        );
        assert_eq!(with.verdict, without.verdict, "{case}: verdicts differ");
        assert_eq!(with.bytes, payload, "{case}: the overlapped arm's bytes");
        assert_eq!(without.bytes, payload, "{case}: the serial arm's bytes");
        assert_eq!(
            with.reported, without.reported,
            "{case}: reported byte counts differ"
        );
    }
}
