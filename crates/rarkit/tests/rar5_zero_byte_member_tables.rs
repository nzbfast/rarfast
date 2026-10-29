//! A ZERO BYTE member of a RAR 5 solid chain can carry a table set, and the
//! member after it decodes under that set (SPEC-H2 section 3.2).
//!
//! **The defect this pins.** Reference `rar` 7.23 at `-m3 -s` gives every
//! fifteenth member of a solid stream a block of its own that carries a
//! table set, EVEN WHEN THE MEMBER IS EMPTY, and the member after it, its
//! first block's table bit clear, decodes under that set. rarkit read no
//! block of a member that declares no bytes, so the older set stayed in
//! force and the next member decoded to the wrong bytes: on a solid RAR 5
//! archive of a Python tree (4,878 members) 239 failed their checksum, the
//! first wrong and the rest copying from it, where reference `unrar t`
//! passed every one (27 Sep 2026). It had been so since the decoder was
//! written.
//!
//! **Two sites, and this test holds both.** The serial decoder
//! (`Rar5Lz::member`) now reads the table sets of a zero byte member's
//! blocks. The chain's decode-ahead cursor (`read::ahead`) stepped over a
//! member it could not offer WITHOUT closing the run when that member
//! declared no bytes, as one that "reads no table"; an offerable one was
//! already closed by the stage's own refusal. The member it cannot offer
//! is the one with its solid bit CLEAR, which the read path still takes as
//! continuing a solid archive's chain (`d250_sol.rar`'s `EMPTY.DAT` shape),
//! so a lane decoded the member behind it under the run's set. It now
//! closes the run at any zero byte member that carries packed bytes. The
//! hand built chain below puts a run head in front of such an empty
//! member, so it fails on either site alone.

use std::sync::Arc;

use rarkit::{Disposition, MemberInfo, MemberOutcome, RangeSource, ReadOptions, Result, Sink};

mod support {
    pub mod rar5build;
}

#[path = "support/creategate.rs"]
mod creategate;

use support::rar5build::{solid_archive, Member};

/// Most significant bit first, like a block's payload (section 3.2).
#[derive(Default)]
struct Bits {
    bytes: Vec<u8>,
    count: usize,
}

impl Bits {
    fn put(&mut self, value: u32, width: u32) {
        for step in (0..width).rev() {
            if self.count.is_multiple_of(8) {
                self.bytes.push(0);
            }
            if (value >> step) & 1 != 0 {
                self.bytes[self.count / 8] |= 1 << (7 - self.count % 8);
            }
            self.count += 1;
        }
    }
}

/// The main alphabet's size, and the other three alphabets' (section 3.3).
const MAIN: usize = 306;
const DISTANCE: usize = 64;
const ALIGN: usize = 16;
const LENGTH: usize = 44;

/// A block's main code lengths: every symbol at nine bits, so a literal's
/// code is its own number, or just `letters` at two bits, so a letter's
/// code is its rank among them.
fn main_lengths(letters: Option<&[u8]>) -> Vec<u8> {
    match letters {
        None => vec![9; MAIN],
        Some(letters) => {
            let mut lengths = vec![0; MAIN];
            for &letter in letters {
                lengths[usize::from(letter)] = 2;
            }
            lengths
        }
    }
}

/// One block: its tables when `main` is given, then `text` as literals
/// under `code`, framed as section 3.2 says, flagged last.
fn block(main: Option<&[u8]>, text: &[u8], code: impl Fn(u8) -> (u32, u32)) -> Vec<u8> {
    let mut payload = Bits::default();
    if let Some(main) = main {
        // The code length alphabet: its twenty lengths, all five bits.
        for _ in 0..20 {
            payload.put(5, 4);
        }
        let rest = [vec![6; DISTANCE], vec![5; ALIGN], vec![6; LENGTH]];
        for list in std::iter::once(main).chain(rest.iter().map(Vec::as_slice)) {
            for &length in list {
                payload.put(u32::from(length), 5);
            }
        }
    }
    for &byte in text {
        let (value, width) = code(byte);
        payload.put(value, width);
    }
    let final_bits = if payload.count == 0 {
        1
    } else {
        payload.count - (payload.bytes.len() - 1) * 8
    };
    // Two size bytes: a block that carries tables is about 280 bytes.
    let size = u16::try_from(payload.bytes.len()).expect("two size bytes hold it");
    let [low, high] = size.to_le_bytes();
    let mut flags = ((final_bits - 1) as u8) & 7;
    flags |= 1 << 3; // a size field of two bytes
    flags |= 0x40; // last
    if main.is_some() {
        flags |= 0x80; // tables
    }
    let mut out = vec![flags, 0x5a ^ flags ^ low ^ high, low, high];
    out.extend_from_slice(&payload.bytes);
    out
}

const LETTERS: &[u8] = b"aipr";

fn nine_bit(byte: u8) -> (u32, u32) {
    (u32::from(byte), 9)
}

fn letter(byte: u8) -> (u32, u32) {
    let rank = LETTERS.iter().position(|&l| l == byte).expect("a letter");
    (rank as u32, 2)
}

/// The chain: a lead member, a run head, the empty member carrying the
/// four letter set with its OWN solid bit clear (so the decode-ahead's
/// cursor cannot offer it), and a member under that set with its table
/// bit clear.
fn hand_built() -> (Vec<u8>, Vec<(&'static str, Vec<u8>)>) {
    let uniform = main_lengths(None);
    let letters = main_lengths(Some(LETTERS));
    let lead = b"the lead member, which the walk decodes itself\n".to_vec();
    let head = b"hello, a run head\n".to_vec();
    let packed = [
        block(Some(&uniform), &lead, nine_bit),
        block(Some(&uniform), &head, nine_bit),
        block(Some(&letters), b"", letter),
        block(None, b"pair", letter),
    ];
    let names = ["lead", "head", "empty", "pair"];
    let bodies = [lead, head, Vec::new(), b"pair".to_vec()];
    let members: Vec<Member<'_>> = (0..4)
        .map(|index| Member {
            name: names[index],
            unpacked: &bodies[index],
            packed: &packed[index],
            dictionary_exponent: 0,
            method: 3,
            solid: index == 1 || index == 3,
        })
        .collect();
    let bytes = solid_archive(&members);
    let want = names.iter().copied().zip(bodies.iter().cloned()).collect();
    (bytes, want)
}

/// Keep every member's bytes and its verdict.
#[derive(Default)]
struct Collect {
    members: Vec<(Vec<u8>, Vec<u8>, Option<bool>)>,
}

impl Sink for Collect {
    type Out = Vec<u8>;
    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Write(Vec::new()))
    }
    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.members.push((
            member.name.to_vec(),
            out.unwrap_or_default(),
            outcome.checksum_ok,
        ));
        Ok(())
    }
}

fn extract(bytes: &[u8], options: &ReadOptions) -> Collect {
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(bytes.to_vec())];
    let mut sink = Collect::default();
    let report = rarkit::extract(sources, options, &mut sink, &mut ())
        .unwrap_or_else(|err| panic!("the chain reads: {err:?}"));
    assert_eq!(report.checksum_failures, 0, "no member fails its checksum");
    sink
}

/// Every path the read side has: the decode-ahead on and off, at the
/// engine's default width and at one worker.
fn every_path(bytes: &[u8], mut check: impl FnMut(&str, Collect)) {
    for ahead in [true, false] {
        for workers in [None, Some(1)] {
            rarkit::probe::set_ahead_off(!ahead);
            let got = extract(bytes, &ReadOptions::default().with_workers(workers));
            rarkit::probe::set_ahead_off(false);
            check(&format!("ahead {ahead}, workers {workers:?}"), got);
        }
    }
}

#[test]
fn a_zero_byte_members_tables_reach_the_member_after_it() {
    let (bytes, want) = hand_built();
    every_path(&bytes, |path, got| {
        assert_eq!(got.members.len(), want.len(), "{path}");
        for ((name, body, verdict), (want_name, want_body)) in got.members.iter().zip(&want) {
            assert_eq!(name.as_slice(), want_name.as_bytes(), "{path}");
            assert_eq!(body, want_body, "{path}: {want_name}");
            assert_eq!(*verdict, Some(true), "{path}: {want_name}");
        }
    });
}

/// The decoder seam agrees, serial and parallel, so the in-crate
/// differential tests read the same shape the read path does.
#[test]
fn the_decoder_seam_reads_the_same_chain() {
    let (bytes, want) = hand_built();
    for parallel in [false, true] {
        let got = rarkit::internals::rar5::extract(&bytes, parallel).expect("the chain decodes");
        let got: Vec<Vec<u8>> = got.into_iter().map(|(_, body)| body).collect();
        let want: Vec<Vec<u8>> = want.iter().map(|(_, body)| body.clone()).collect();
        assert_eq!(got, want, "parallel {parallel}");
    }
}

/// The shape as reference `rar` writes it, when `rar` is on the path, at
/// `-m1`, `-m3` and `-m5`: a text member, then sixteen empty ones, then a
/// short one. The fifteenth member after the first is empty and carries a
/// table set, which is checked rather than assumed, so a `rar` that stops
/// writing the shape skips a method rather than passing it for nothing.
/// (`-m1` was found failing on its own by the reference `rar` sweep, on a
/// tree of 5,404 headers: 2,885 members, 27 Sep 2026.)
#[test]
fn reference_rar_writes_the_shape_and_it_reads_whole() {
    let mut names = vec!["a.py".to_string()];
    let mut bodies = vec![creategate::text_corpus(4096)];
    for index in 1..=16 {
        names.push(format!("e{index:02}.py"));
        bodies.push(Vec::new());
    }
    names.push("z.py".to_string());
    bodies.push(b"\"pair tests\"\n".to_vec());
    for method in ["-m1", "-m3", "-m5"] {
        let Some(bytes) = reference_chain(&names, &bodies, method) else {
            eprintln!("    reference `rar` is not on the path; skipped");
            return;
        };
        let carrying = rarkit::internals::rar5::members(&bytes)
            .iter()
            .filter(|member| member.unpacked == 0 && !member.packed.is_empty())
            .count();
        if carrying == 0 {
            eprintln!("    this `rar` at {method} gave no empty member a block; skipped");
            continue;
        }
        every_path(&bytes, |path, got| {
            assert_eq!(got.members.len(), names.len(), "{method} {path}");
            for ((name, body, verdict), (want_name, want_body)) in
                got.members.iter().zip(names.iter().zip(&bodies))
            {
                assert_eq!(name.as_slice(), want_name.as_bytes(), "{method} {path}");
                assert_eq!(body, want_body, "{method} {path}: {want_name}");
                assert_eq!(*verdict, Some(true), "{method} {path}: {want_name}");
            }
        });
    }
}

/// The members packed by reference `rar` at `-s` and `method`, in the order
/// given, or `None` when `rar` is not on the path.
fn reference_chain(names: &[String], bodies: &[Vec<u8>], method: &str) -> Option<Vec<u8>> {
    // `std::process::id` in the path: two runs of the suite on one box share
    // `temp_dir`.
    let dir = std::env::temp_dir().join(format!(
        "rarkit-zero-byte-tables-{}{method}",
        std::process::id()
    ));
    let files = dir.join("members");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&files).ok()?;
    for (name, body) in names.iter().zip(bodies) {
        std::fs::write(files.join(name), body).ok()?;
    }
    let target = dir.join("chain.rar");
    let made = std::process::Command::new("rar")
        .current_dir(&files)
        .args(["a", "-ma5", method, "-s", "-ep", "-idq", "-y"])
        .arg(&target)
        .args(names)
        .status()
        .is_ok_and(|status| status.success());
    let bytes = made.then(|| std::fs::read(&target).ok()).flatten();
    let _ = std::fs::remove_dir_all(&dir);
    bytes
}
