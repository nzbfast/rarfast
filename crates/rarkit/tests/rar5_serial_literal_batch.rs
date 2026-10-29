//! The serial loop's eight bit literal batch on whole members: written by
//! this crate's own RAR 5 writer, so no tool is needed, with enough noise
//! in them that their tables admit the batch, and then damaged and cut
//! short.
//!
//! A member the batch reaches must decode to its bytes, and a damaged or
//! truncated one must stop where the tape path stops, with the same error
//! and the same bytes before it (SPEC-H2 section 3.8). The tape path does
//! not batch, so it is the reference the serial arm is held to here; the
//! lib test `rar5_lz::serial_batch_tests` holds the batch to the scalar
//! loop symbol by symbol. Without the `parallel` feature there is no tape
//! path, and the member is held to its bytes and to not panicking.
//!
//! Implemented from `specs/SPEC-H2-rarkit-rar5-lz.md` alone.

use rarkit::internals::rar5;
use rarkit::{
    FilterPolicy, MemberSpec, Payload, VolumeNaming, WriteFormat, WriteMethod, WriteOptions, Writer,
};

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

/// `len` bytes that are mostly noise, with `copies` repeats of a noise
/// block so the writer finds matches and compresses rather than stores:
/// the noise makes near flat literal tables, which is the table shape the
/// batch admits.
fn body(seed: u64, len: usize, block: usize) -> Vec<u8> {
    let mut state = seed | 1;
    let noise: Vec<u8> = (0..block).map(|_| xorshift(&mut state) as u8).collect();
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        if xorshift(&mut state).is_multiple_of(3) {
            out.extend_from_slice(&noise);
        } else {
            let run = (block / 2).min(len - out.len());
            out.extend((0..run).map(|_| xorshift(&mut state) as u8));
        }
    }
    out.truncate(len);
    out
}

fn archive(data: &[u8], level: u8) -> Vec<u8> {
    let options = WriteOptions {
        format: WriteFormat::Rar5,
        method: WriteMethod::Compressed {
            level,
            dictionary: None,
        },
        solid: false,
        volume_size: None,
        volume_naming: VolumeNaming::Numbered,
        filters: FilterPolicy::Off,
        workers: Some(1),
        ..WriteOptions::default()
    };
    let mut writer = Writer::new(options).expect("representable");
    writer
        .add(MemberSpec {
            name: b"noise.bin",
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

struct Case {
    data: Vec<u8>,
    member: rar5::Member,
}

/// Members the batch reaches: at least one block admitted with the packed
/// work the batch asks for, in a member above its floor.
fn cases() -> Vec<Case> {
    let mut out = Vec::new();
    for (seed, len, block, level) in [
        (1u64, 200_000usize, 24_000usize, 3u8),
        (2, 96 << 10, 20_000, 1),
        (3, 300_000, 40_000, 5),
        (4, 70_000, 16_000, 3),
    ] {
        let data = body(seed, len, block);
        let bytes = archive(&data, level);
        let mut members = rar5::members(&bytes);
        assert_eq!(members.len(), 1);
        let member = members.remove(0);
        assert_ne!(
            member.method, 0,
            "seed {seed}: the writer stored the member"
        );
        let (blocks, admitted, worked) = rar5::serial_batch_reach(&member.packed, member.algorithm);
        assert!(
            worked > 0 && member.unpacked >= 64 << 10,
            "seed {seed}: {blocks} blocks, {admitted} admitted, {worked} with work: \
             the batch is not reached"
        );
        out.push(Case { data, member });
    }
    out
}

fn serial(case: &Case, packed: &[u8]) -> (Vec<u8>, Option<String>) {
    let m = &case.member;
    rar5::decode_member_probe(packed, m.unpacked, m.window, m.algorithm, false)
}

#[test]
fn an_admitted_member_decodes_to_its_bytes() {
    for case in cases() {
        let (bytes, failure) = serial(&case, &case.member.packed);
        assert_eq!(failure, None);
        assert!(bytes == case.data, "the serial arm's bytes differ");
    }
}

/// Every block's worth of the packed stream, one bit flipped at a time at
/// spread positions: the serial arm stops where the tape arm stops.
#[cfg(feature = "parallel")]
#[test]
fn a_damaged_admitted_member_stops_where_the_tape_path_stops() {
    let mut state = 0xda3a_9ed0_u64;
    let mut differed = 0;
    for case in cases() {
        let m = &case.member;
        for _ in 0..160 {
            let mut packed = m.packed.clone();
            let at = (xorshift(&mut state) % packed.len() as u64) as usize;
            packed[at] ^= 1 << (xorshift(&mut state) % 8);
            let got = serial(&case, &packed);
            let want = rar5::decode_member_probe(&packed, m.unpacked, m.window, m.algorithm, true);
            assert_eq!(got.1, want.1, "flip at {at}: the outcome differs");
            assert!(
                got.0 == want.0,
                "flip at {at}: {} against {} bytes",
                got.0.len(),
                want.0.len()
            );
            differed += usize::from(got.0 != case.data || got.1.is_some());
        }
    }
    assert!(differed > 100, "only {differed} flips changed anything");
}

/// The packed stream cut at spread lengths, and at every length in the
/// last few bytes of the first block: the serial arm stops where the tape
/// arm stops.
#[cfg(feature = "parallel")]
#[test]
fn a_truncated_admitted_member_stops_where_the_tape_path_stops() {
    for case in cases() {
        let m = &case.member;
        let len = m.packed.len();
        let mut cuts: Vec<usize> = (0..=64).map(|i| len * i / 64).collect();
        cuts.extend(len.saturating_sub(40)..len);
        cuts.extend((1..200).map(|i| i * 37 % len));
        for cut in cuts {
            let packed = &m.packed[..cut];
            let got = serial(&case, packed);
            let want = rar5::decode_member_probe(packed, m.unpacked, m.window, m.algorithm, true);
            assert_eq!(got.1, want.1, "cut at {cut} of {len}: the outcome differs");
            assert!(got.0 == want.0, "cut at {cut} of {len}: the bytes differ");
            assert!(case.data.starts_with(&got.0), "cut at {cut}: wrong bytes");
        }
    }
}

/// Without the tape path: damage and truncation end in an error or in
/// the member's bytes, and never in a panic.
#[cfg(not(feature = "parallel"))]
#[test]
fn a_damaged_or_truncated_admitted_member_fails_cleanly() {
    let mut state = 0xda3a_9ed0_u64;
    for case in cases() {
        let m = &case.member;
        for _ in 0..160 {
            let mut packed = m.packed.clone();
            let at = (xorshift(&mut state) % packed.len() as u64) as usize;
            packed[at] ^= 1 << (xorshift(&mut state) % 8);
            let _ = serial(&case, &packed);
        }
        for i in 0..=64 {
            let cut = m.packed.len() * i / 64;
            let got = serial(&case, &m.packed[..cut]);
            assert!(case.data.starts_with(&got.0), "cut at {cut}: wrong bytes");
            if cut < m.packed.len() {
                assert!(got.1.is_some(), "cut at {cut}: no error");
            }
        }
    }
}

/// Seeds for the `rar5_member` fuzz target (`fuzz/`), which takes a
/// member's packed bytes and declares 256 KiB: members of noise whose
/// tables the batch admits, at most 60 KiB packed. Written to the
/// directory `RARKIT_SEED_DIR` names, never committed:
///
///     RARKIT_SEED_DIR=target/seed/rar5_member cargo test --release \
///         -p rarkit --test rar5_serial_literal_batch -- --ignored write_member_seeds
#[test]
#[ignore]
fn write_member_seeds() {
    let dir = std::env::var("RARKIT_SEED_DIR").expect("RARKIT_SEED_DIR");
    std::fs::create_dir_all(&dir).unwrap();
    let mut written = 0;
    for seed in 1..=24u64 {
        let len = 20_000 + (seed as usize % 6) * 9_000;
        let data = body(seed, len, 4_000 + (seed as usize % 4) * 2_000);
        let bytes = archive(&data, 1 + (seed % 5) as u8);
        let member = rar5::members(&bytes).remove(0);
        let (_, _, worked) = rar5::serial_batch_reach(&member.packed, member.algorithm);
        if member.method == 0 || worked == 0 || member.packed.len() > 60 << 10 {
            continue;
        }
        std::fs::write(format!("{dir}/batch-{seed:02}"), &member.packed).unwrap();
        written += 1;
    }
    assert!(written >= 12, "only {written} seeds reach the batch");
}
