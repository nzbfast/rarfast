//! An intact member after a damaged one keeps its own verdict (spec F
//! section 8; SPEC-API 4.4: the concurrent driver's answer is the
//! sequential one).
//!
//! FOUND by `crates/rarkit/fuzz:f_extract_batches` on an M3 Mac, 26 Sep
//! 2026, after 8,937 executions: `r393_m3.rar` (RAR 4 format, not solid)
//! with one byte exclusive-ored by 0x50 at offset 22,663, which lands in
//! `BIG.TXT`'s packed data. The fuzz input, five bytes, is [`FUZZ_INPUT`]
//! and is deliberately NOT a committed fuzz seed: a campaign loads its
//! seeds first, so the target would stop on it every run until the fix.
//!
//! Reference `unrar t` (7.23) on those bytes: `BIG.TXT - checksum error`,
//! every other member OK. `extract_parallel` agrees with it. The
//! sequential `extract` ALSO fails `EMPTY.DAT`, the member right after
//! `BIG.TXT`, which declares no bytes and is intact: a false failure,
//! deterministic, and independent of small member batches (every cell of
//! the grid below differed the same way, including a cap that admits no
//! batch). FIXED on `impl/f-sequential-verdict-after-damage`: a member
//! that declares no bytes kept the decoder's stream in a NON-solid archive
//! too, so it decoded its 8 packed bytes on the stream `BIG.TXT` faulted.
//! Spec F section 0 item 12; `zero_byte_after_damage.rs`
//! carries the RAR 5 twin and the rule's own recipe.
//!
//! In a test binary of its own because the batch, team and floor settings
//! it sets are per thread and the counters process-wide, as
//! `small_batch_caps.rs` explains.

#![cfg(all(feature = "parallel", feature = "test-support"))]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use rarkit::{
    extract, extract_parallel, Disposition, MemberInfo, MemberOutcome, MemoryPolicy, ParallelSink,
    RangeSource, ReadOptions, Result, Sink,
};

/// The fuzz input as found: input 5 of the target's list (`r393_m3.rar`),
/// batch shape 7 `(2, 4096)` and team 1, width 3 with the outputs bound at
/// 2, a 1 GiB policy, and 0x50 as the damage.
pub const FUZZ_INPUT: [u8; 5] = [0xad, 0x0f, 0x3a, 0x2e, 0x50];

/// Where the target put the damage for that input: `pick * 131 % len`.
const DAMAGE_AT: usize = FUZZ_INPUT[0] as usize * 131 % 68_942;

/// Reference `unrar t` (7.23) on the damaged bytes, member by member in
/// archive order: `BIG.TXT` fails, every other file member passes.
const REFERENCE: [(&str, bool); 9] = [
    ("AUDIO.RAW", true),
    ("BIG.TXT", false),
    ("EMPTY.DAT", true),
    ("ONE.DAT", true),
    ("SUB/SIB.TXT", true),
    ("SUB/NESTED/DEEP.TXT", true),
    ("TABLE.BIN", true),
    ("HELLO.TXT", true),
    ("DATA.BIN", true),
];

/// Name, verdict, bytes, CRC32 of the bytes.
type Seen = (String, Option<bool>, u64, u32);

#[derive(Default)]
struct Digest {
    crc: rarkit::checksum::Crc32,
}

impl std::io::Write for Digest {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.crc.update(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn seen(member: &MemberInfo<'_>, out: Option<Digest>, outcome: &MemberOutcome) -> Seen {
    (
        String::from_utf8_lossy(member.name).into_owned(),
        outcome.checksum_ok,
        outcome.bytes,
        out.map_or(0, |d| d.crc.finish()),
    )
}

#[derive(Default)]
struct Serial(Vec<Seen>);

impl Sink for Serial {
    type Out = Digest;
    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Digest>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Digest::default()))
    }
    fn close(&mut self, m: &MemberInfo<'_>, out: Option<Digest>, o: &MemberOutcome) -> Result<()> {
        self.0.push(seen(m, out, o));
        Ok(())
    }
}

#[derive(Default)]
struct Wide(Mutex<Vec<Seen>>);

impl ParallelSink for Wide {
    type Out = Digest;
    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Digest>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Digest::default()))
    }
    fn close(&self, m: &MemberInfo<'_>, out: Option<Digest>, o: &MemberOutcome) -> Result<()> {
        self.0.lock().expect("lock").push(seen(m, out, o));
        Ok(())
    }
}

fn damaged() -> Vec<u8> {
    let path = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/legacy/archives/r393_m3.rar"
    ));
    let mut bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    assert_eq!(bytes.len(), 68_942, "the fixture this finding was cut from");
    bytes[DAMAGE_AT] ^= 0x50;
    bytes
}

fn options() -> ReadOptions {
    ReadOptions::default()
        .with_memory(MemoryPolicy::from_limit(1 << 30))
        .with_password(Some(rarkit::Password::from("Secret")))
}

/// One driver's answer: its member list and what it returned.
struct Answer {
    seen: Vec<Seen>,
    result: String,
}

fn sequential(bytes: &[u8]) -> Answer {
    rarkit::probe::set_offload_floor(None);
    let mut serial = Serial::default();
    let result = extract(
        vec![Arc::new(bytes.to_vec()) as Arc<dyn RangeSource>],
        &options(),
        &mut serial,
        &mut (),
    );
    Answer {
        seen: serial.0,
        result: format!("{result:?}"),
    }
}

fn concurrent(bytes: &[u8], batch: (usize, u64), team: usize, width: usize) -> Answer {
    rarkit::probe::set_offload_floor(None);
    rarkit::probe::set_small_batch(Some(batch));
    rarkit::probe::set_small_team(Some(team));
    rarkit::probe::set_outputs_over_breadth(Some(2));
    let wide = Wide::default();
    let result = extract_parallel(
        vec![Arc::new(bytes.to_vec()) as Arc<dyn RangeSource>],
        &options(),
        &wide,
        width,
    );
    rarkit::probe::set_small_batch(None);
    rarkit::probe::set_small_team(None);
    rarkit::probe::set_outputs_over_breadth(None);
    Answer {
        seen: wide.0.into_inner().expect("lock"),
        result: format!("{result:?}"),
    }
}

/// The file members' verdicts against [`REFERENCE`], or what differs.
fn against_reference(answer: &Answer) -> Vec<String> {
    let files: Vec<&Seen> = answer.seen.iter().filter(|s| s.1.is_some()).collect();
    let mut bad = Vec::new();
    if files.len() != REFERENCE.len() {
        bad.push(format!(
            "{} file members closed, the reference has {}",
            files.len(),
            REFERENCE.len()
        ));
    }
    for (have, (name, ok)) in files.iter().zip(REFERENCE) {
        if have.0 != name || have.1 != Some(ok) {
            bad.push(format!(
                "{} {:?}, reference unrar {name} {ok}",
                have.0, have.1
            ));
        }
    }
    bad
}

/// The concurrent driver at the found shape agrees with reference `unrar`.
#[test]
fn the_concurrent_driver_gives_the_reference_verdicts() {
    let answer = concurrent(&damaged(), (2, 4096), 1, 3);
    let bad = against_reference(&answer);
    assert!(
        bad.is_empty(),
        "{}\nreturned {}\n{:#?}",
        bad.join("\n"),
        answer.result,
        answer.seen
    );
}

/// The sequential walk agrees with reference `unrar`, `EMPTY.DAT` included.
#[test]
fn the_sequential_walk_gives_the_reference_verdicts() {
    let answer = sequential(&damaged());
    let bad = against_reference(&answer);
    assert!(
        bad.is_empty(),
        "{}\nreturned {}\n{:#?}",
        bad.join("\n"),
        answer.result,
        answer.seen
    );
}

/// Every batch shape, team and width: the concurrent answer is the
/// sequential one, member for member.
#[test]
fn every_batch_shape_gives_the_sequential_answer() {
    let bytes = damaged();
    let want = sequential(&bytes);
    let mut bad = Vec::new();
    for batch in [
        (1, 64 << 10),
        (2, 4096),
        (2, 64 << 10),
        (4, 256 << 10),
        (64, 1 << 20),
        (4, 1),
    ] {
        for team in [0, 1, 2, 8] {
            for width in [2, 3, 4, 8] {
                let have = concurrent(&bytes, batch, team, width);
                if have.seen != want.seen {
                    bad.push(format!(
                        "batch {batch:?} team {team} width {width}\n  sequential {:?}\n  concurrent {:?}",
                        want.seen, have.seen
                    ));
                }
            }
        }
    }
    assert!(
        bad.is_empty(),
        "{} cell(s) differ; sequential returned {}\n{}",
        bad.len(),
        want.result,
        bad.join("\n")
    );
}
