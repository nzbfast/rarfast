//! A member that declares no bytes, after a damaged one, is reported OK
//! (spec F section 0 item 12, 21 Sep 2026), and only the
//! damaged member fails, in both drivers, in both formats.
//!
//! The defect this pins: the sequential walk let a zero byte member keep
//! the decoder's stream in a NON-solid archive, where there is no chain to
//! keep, so a RAR 4 `EMPTY.DAT` with 8 packed bytes was decoded on the
//! stream the damaged `BIG.TXT` before it had faulted, and failed.
//! `damaged_neighbour_verdict.rs` carries the fuzz find's own input.
//!
//! Reference `unrar t` (7.23), run on the very bytes each case builds:
//! `BIG.TXT - checksum error`, every other member OK, `Total errors: 1`.
//! In `r550_m3.rar` (RAR 5) `EMPTY.DAT` has no packed bytes at all, so
//! that case holds the verdict and not the carried stream; the flag that
//! was wrong feeds the RAR 5 decoder too, and no genuine RAR 5 writer we
//! hold gives an empty member packed bytes.

use std::path::PathBuf;
use std::sync::Arc;

use rarkit::{
    extract, Disposition, MemberInfo, MemberOutcome, RangeSource, ReadOptions, Result, Sink,
};

/// File members in archive order, and whether reference `unrar` passes each.
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

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/legacy/archives")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Damage `BIG.TXT`'s packed data 200 bytes before the next member's name,
/// which in these archives is deep inside it (its data is over 20 KB).
fn damaged_before_empty(name: &str) -> Vec<u8> {
    let mut bytes = fixture(name);
    let at = bytes
        .windows(9)
        .position(|w| w == b"EMPTY.DAT")
        .expect("the fixture has EMPTY.DAT")
        - 200;
    bytes[at] ^= 0x50;
    bytes
}

/// The rule's own recipe: byte 29,567 of `r393_md.rar` (PPMd) flipped.
fn the_rules_recipe() -> Vec<u8> {
    let mut bytes = fixture("r393_md.rar");
    assert_eq!(bytes.len(), 59_135, "the fixture the rule was made on");
    bytes[29_567] ^= 0xA5;
    bytes
}

type Seen = Vec<(String, Option<bool>, u64)>;

#[derive(Default)]
struct Serial(Seen);

impl Sink for Serial {
    type Out = std::io::Sink;
    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<std::io::Sink>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(std::io::sink()))
    }
    fn close(
        &mut self,
        m: &MemberInfo<'_>,
        _: Option<std::io::Sink>,
        o: &MemberOutcome,
    ) -> Result<()> {
        self.0.push((
            String::from_utf8_lossy(m.name).into_owned(),
            o.checksum_ok,
            o.bytes,
        ));
        Ok(())
    }
}

fn sequential(bytes: Vec<u8>) -> Seen {
    let mut sink = Serial::default();
    let _ = extract(
        vec![Arc::new(bytes) as Arc<dyn RangeSource>],
        &ReadOptions::default(),
        &mut sink,
        &mut (),
    );
    sink.0
}

fn assert_reference(what: &str, seen: &Seen) {
    let files: Vec<_> = seen.iter().filter(|s| s.1.is_some()).collect();
    let got: Vec<(&str, bool)> = files
        .iter()
        .map(|s| (s.0.as_str(), s.1 == Some(true)))
        .collect();
    assert_eq!(got, REFERENCE, "{what}: {seen:#?}");
    let empty = files.iter().find(|s| s.0 == "EMPTY.DAT").expect("closed");
    assert_eq!(empty.2, 0, "{what}: EMPTY.DAT is zero bytes long");
}

#[test]
fn rar4_lz_sequential_passes_the_empty_member() {
    assert_reference("r393_m3", &sequential(damaged_before_empty("r393_m3.rar")));
}

#[test]
fn rar4_ppmd_rule_recipe_sequential() {
    assert_reference("r393_md", &sequential(the_rules_recipe()));
}

#[test]
fn rar5_sequential_passes_the_empty_member() {
    assert_reference("r550_m3", &sequential(damaged_before_empty("r550_m3.rar")));
}

#[test]
fn the_undamaged_fixtures_still_pass_every_member() {
    for name in ["r393_m3.rar", "r393_md.rar", "r550_m3.rar"] {
        let seen = sequential(fixture(name));
        assert!(seen.iter().all(|s| s.1 != Some(false)), "{name}: {seen:#?}");
    }
}

#[cfg(feature = "parallel")]
mod concurrent {
    use super::*;
    use rarkit::{extract_parallel, ParallelSink};
    use std::sync::Mutex;

    #[derive(Default)]
    struct Wide(Mutex<Seen>);

    impl ParallelSink for Wide {
        type Out = std::io::Sink;
        fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<std::io::Sink>> {
            if member.is_directory {
                return Ok(Disposition::Skip);
            }
            Ok(Disposition::Write(std::io::sink()))
        }
        fn close(
            &self,
            m: &MemberInfo<'_>,
            _: Option<std::io::Sink>,
            o: &MemberOutcome,
        ) -> Result<()> {
            self.0.lock().expect("lock").push((
                String::from_utf8_lossy(m.name).into_owned(),
                o.checksum_ok,
                o.bytes,
            ));
            Ok(())
        }
    }

    fn wide(bytes: Vec<u8>) -> Seen {
        let sink = Wide::default();
        let _ = extract_parallel(
            vec![Arc::new(bytes) as Arc<dyn RangeSource>],
            &ReadOptions::default(),
            &sink,
            4,
        );
        sink.0.into_inner().expect("lock")
    }

    #[test]
    fn every_case_matches_the_sequential_answer_and_the_reference() {
        for (what, bytes) in [
            ("r393_m3", damaged_before_empty("r393_m3.rar")),
            ("r393_md", the_rules_recipe()),
            ("r550_m3", damaged_before_empty("r550_m3.rar")),
        ] {
            let seen = wide(bytes.clone());
            assert_reference(what, &seen);
            assert_eq!(seen, sequential(bytes), "{what}: the two drivers differ");
        }
    }
}
