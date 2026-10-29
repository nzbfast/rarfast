//! A RAR 3 LZ member whose last block ends "a block header follows in this
//! member" and whose packed data then stops, with no header: SPEC-H1 3.7
//! and 3.8 read it as the member done and the next member starting at a
//! header, and rarkit does.
//!
//! **Why this is pinned.** The old engine ends EVERY LZ member it writes
//! this way (symbol 256, then the one bit 1 of `SameMemberNewTables`, then
//! 0 to 7 padding bits and nothing more). On the small9k RAR 4 solid
//! archive the compression rivals round wrote with it (27 Sep 2026, sha256
//! `3ef17f45...`, 9,681 members, 147 of them LZ and 9,499 PPM), rarkit
//! extracts every member to the ORIGINAL input bytes and every stored
//! CRC-32 matches, while reference `unrar` 4.20, 5.50 and 7.23 fail the
//! same 5,090 members. Every one of those is a PPM member, or an LZ member
//! copying from one, that follows such an LZ member in a stream that
//! already holds a PPM model. From the outside, the reference reads the
//! header the block end promised from PAST the member's packed data, and
//! what it finds there leaves its PPM escape byte at something other than
//! 2. Its output for the first failing member is exactly that member's PPM
//! symbol stream with every escape pair written out as literal bytes (`02
//! 04 00 00 44 00` where a match at distance 70 belongs). Genuine rar never
//! writes the shape: its five `SameMemberNewTables` ends at a member end in
//! `vectors-J` are each followed by a real header of 67 to 83 bits in the
//! same member. rarkit's own RAR 2.9 writer ends a member's last block with
//! `NewMemberNewTables`.
//!
//! So rarkit does what the specification says, and the specification's
//! rule here is marked [OLD]. Whether it should stay lenient, or refuse the
//! shape as a reference accident is refused on the RAR 5 side, is an
//! open question, raised on
//! 27 Sep 2026. Until it is decided, this file pins the specification's
//! reading, and when `unrar` is present, the reference's disagreement.
//!
//! **The archive.** Hand built per SPEC-F 3.3 around a hand written LZ
//! member per SPEC-H1 3.2 to 3.7. The two PPM members are one PPM START
//! member's packed bytes (header `0xa7`: order 8, 25 MB, no escape byte),
//! copied verbatim from the small9k archive, where it is member 23, the
//! first that fails. It decodes to 1,725 bytes of the `Inflector` 0.11.4
//! crate's `src/string/deconstantize/mod.rs` (MIT/BSD-2). rarkit has no
//! PPM encoder (SPEC-I question 6), so the member is carried as bytes
//! rather than written here. The same member serves as the stream's first
//! member and as its third: it starts a fresh model and its matches reach
//! only into its own bytes.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use rarkit::{Disposition, MemberInfo, MemberOutcome, RangeSource, ReadOptions, Result, Sink};

/// Member 23 of the small9k archive: 334 packed bytes, a PPM START block.
const PPM_MEMBER: &str = concat!(
    "a718233a59633eaf7dfeae120f8341465cde07ff3b0d8a45751098edab18fd04",
    "9827582b9eb41e947e8bf2c280c631c95f5f4a3c8744899840eca9dd1cc64e03",
    "f55551a722fa1c682d32df76a059501e6772fc53f5f28f8a2d3c78fdb244b487",
    "9c3b4f6d1e87041c048dd1b74d1c8daa6b06edf526ac0ac4d5382cdb7762ebad",
    "ffaf5ea19a705a82cbae32275367a33ac6c2cfcf7f9789ab55ba980520b97a43",
    "5781367ad462bf1e7f39511657ad7de7040d1a82382166933c772377e6e7878e",
    "333cc9fb0b834c29ea33c83954ba14e206bdd5ea68059fa9b4838210753c3cf8",
    "9569cf89af0cdb3147519009bc1797e1a384bd601c6567e663a63f9971ad0e9e",
    "d339478cc8cecc247c558f77c77eab88489c4f247499ac7654da5d7b9431e09c",
    "9278e47cc1dcaf8e57b865e244c628dd10a5ac5095a5bcfb0a24b3bb05d72e0b",
    "250cfe84b05792acdeb490a6815a",
);
/// What that member declares: its unpacked size and CRC-32.
const PPM_SIZE: u32 = 1725;
const PPM_CRC: u32 = 0x0D88_1A55;

/// The archives as built here, so the reference's verdicts recorded below
/// are about exactly these bytes.
const SAME_SHA256: &str = "d15f21bde4b3160fc03c5a0241b5eb386e90e8580ffadcd89668a9c7f1c0c151";
const NEW_SHA256: &str = "f4e1934dce6175ec6fbaf816f5197ce796d2616115cc773301571df4b6002e38";

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

/// Bits out, most significant first (SPEC-H1: bits are read MSB first).
#[derive(Default)]
struct Bits {
    bits: Vec<u8>,
}

impl Bits {
    fn put(&mut self, value: u32, width: u32) {
        for step in (0..width).rev() {
            self.bits.push(((value >> step) & 1) as u8);
        }
    }

    fn bytes(&self) -> Vec<u8> {
        self.bits
            .chunks(8)
            .map(|chunk| {
                chunk
                    .iter()
                    .enumerate()
                    .fold(0u8, |byte, (at, &bit)| byte | (bit << (7 - at)))
            })
            .collect()
    }
}

/// The main symbols this member's table names, all at three bits, so a
/// symbol's code is its rank here (canonical codes, SPEC-D 3.2).
const MAIN: [u16; 8] = [65, 66, 256, 258, 259, 260, 262, 271];

fn main_code(symbol: u16) -> u32 {
    MAIN.iter().position(|&s| s == symbol).expect("named") as u32
}

/// One LZ member: `AB`, then four fresh matches of length 3 at distance
/// 2, so fourteen bytes `ABAB...`, then symbol 256 and the block end
/// field. `same_member` writes the end the old engine writes
/// (`SameMemberNewTables`, 3.7) and stops there; otherwise it writes
/// `NewMemberNewTables`.
fn lz_member(same_member: bool) -> (Vec<u8>, Vec<u8>) {
    let mut out = Bits::default();
    out.put(0, 1); // 3.2: an LZ block
    out.put(0, 1); // keep bit clear: stored lengths start at zero

    // 3.3: the code length alphabet. Symbols 0, 1, 3 and 19 at two bits,
    // so their codes are 00, 01, 10 and 11.
    let mut level = [0u32; 20];
    for symbol in [0, 1, 3, 19] {
        level[symbol] = 2;
    }
    for length in level {
        out.put(length, 4);
    }
    // The 404 lengths: main (299), distance (60), low distance (17),
    // length (28). Main symbols three bits; distance slots 1 and 10, low
    // symbols 0 and 16, length slots 0 and 1, one bit each.
    let mut lengths = [0u32; 404];
    for symbol in MAIN {
        lengths[usize::from(symbol)] = 3;
    }
    for at in [299 + 1, 299 + 10, 359, 359 + 16, 376, 377] {
        lengths[at] = 1;
    }
    for length in lengths {
        let code = match length {
            0 => 0,
            1 => 1,
            _ => 2,
        };
        out.put(code, 2);
    }
    // 3.4 and 3.5: two literals, then four times symbol 271 (length slot
    // 0, so 3) with distance slot 1 (code 0: distance 2).
    out.put(main_code(65), 3);
    out.put(main_code(66), 3);
    for _ in 0..4 {
        out.put(main_code(271), 3);
        out.put(0, 1);
    }
    out.put(main_code(256), 3);
    if same_member {
        out.put(1, 1);
    } else {
        out.put(0, 1);
        out.put(1, 1);
    }
    (out.bytes(), b"ABABABABABABAB".to_vec())
}

/// A RAR 4 block with its size and header checksum filled in (SPEC-F
/// 3.3.1).
fn block(kind: u8, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut header = vec![kind];
    header.extend_from_slice(&flags.to_le_bytes());
    header.extend_from_slice(&((7 + body.len()) as u16).to_le_bytes());
    header.extend_from_slice(body);
    let mut out = (crc32fast::hash(&header) as u16).to_le_bytes().to_vec();
    out.extend_from_slice(&header);
    out
}

struct Member<'a> {
    name: &'a str,
    packed: &'a [u8],
    size: u32,
    crc: u32,
    method: u8,
    solid: bool,
}

/// A solid RAR 4 archive (SPEC-F 3.3.4 to 3.3.6): archive flag 0x0008,
/// each member's own solid bit, a 1 MiB dictionary, unpack version 29.
fn archive(members: &[Member<'_>]) -> Vec<u8> {
    let mut out = b"Rar!\x1a\x07\x00".to_vec();
    out.extend(block(0x73, 0x0008, &[0; 6]));
    for member in members {
        let flags = 0x8000 | 0x0080 | if member.solid { 0x0010 } else { 0 };
        let mut body = Vec::new();
        body.extend_from_slice(&(member.packed.len() as u32).to_le_bytes());
        body.extend_from_slice(&member.size.to_le_bytes());
        body.push(2); // host OS: Win32
        body.extend_from_slice(&member.crc.to_le_bytes());
        body.extend_from_slice(&0x2121_0000u32.to_le_bytes()); // DOS time
        body.push(29);
        body.push(0x30 + member.method);
        body.extend_from_slice(&(member.name.len() as u16).to_le_bytes());
        body.extend_from_slice(&0x20u32.to_le_bytes());
        body.extend_from_slice(member.name.as_bytes());
        out.extend(block(0x74, flags, &body));
        out.extend_from_slice(member.packed);
    }
    out.extend(block(0x7B, 0x4000, &[]));
    out
}

/// PPM member, the LZ member, the PPM member again.
fn built(same_member: bool) -> (Vec<u8>, Vec<u8>) {
    let ppm = unhex(PPM_MEMBER);
    let (lz, lz_bytes) = lz_member(same_member);
    let bytes = archive(&[
        Member {
            name: "p1",
            packed: &ppm,
            size: PPM_SIZE,
            crc: PPM_CRC,
            method: 5,
            solid: false,
        },
        Member {
            name: "lz",
            packed: &lz,
            size: lz_bytes.len() as u32,
            crc: crc32fast::hash(&lz_bytes),
            method: 3,
            solid: true,
        },
        Member {
            name: "p3",
            packed: &ppm,
            size: PPM_SIZE,
            crc: PPM_CRC,
            method: 5,
            solid: true,
        },
    ]);
    (bytes, lz_bytes)
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Default)]
struct Collect {
    members: Vec<(Vec<u8>, Vec<u8>, Option<bool>)>,
}

impl Sink for Collect {
    type Out = Vec<u8>;
    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
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

/// Every read path: the decode-ahead on and off, default width and one
/// worker. Each must give all three members whole.
fn reads_whole(bytes: &[u8], lz_bytes: &[u8]) {
    for ahead in [true, false] {
        for workers in [None, Some(1)] {
            rarkit::probe::set_ahead_off(!ahead);
            let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(bytes.to_vec())];
            let mut sink = Collect::default();
            let options = ReadOptions::default().with_workers(workers);
            let report = rarkit::extract(sources, &options, &mut sink, &mut ());
            rarkit::probe::set_ahead_off(false);
            let path = format!("ahead {ahead}, workers {workers:?}");
            let report = report.unwrap_or_else(|err| panic!("{path}: the chain reads: {err:?}"));
            assert_eq!(report.checksum_failures, 0, "{path}");
            let names: Vec<&[u8]> = sink.members.iter().map(|m| m.0.as_slice()).collect();
            assert_eq!(names, [&b"p1"[..], b"lz", b"p3"], "{path}");
            for (name, body, verdict) in &sink.members {
                let name = String::from_utf8_lossy(name);
                assert_eq!(*verdict, Some(true), "{path}: {name}");
                if name == "lz" {
                    assert_eq!(body, lz_bytes, "{path}");
                } else {
                    assert_eq!(body.len() as u32, PPM_SIZE, "{path}: {name}");
                    assert_eq!(crc32fast::hash(body), PPM_CRC, "{path}: {name}");
                }
            }
        }
    }
}

/// SPEC-H1 3.8: after the block end, `finish_member` finds the member's
/// input run out, "the member is done", and 3.7's `SameMemberNewTables`
/// leaves the next member at a header. SPEC-I 3.1 and 3.2: the escape byte
/// is still 2 when member p3's START block, which sends none, begins.
#[test]
fn a_same_member_block_end_with_no_header_left_reads_whole() {
    let (bytes, lz_bytes) = built(true);
    assert_eq!(sha256(&bytes), SAME_SHA256);
    reads_whole(&bytes, &lz_bytes);
}

/// The control: the same members with the LZ member ending
/// `NewMemberNewTables`, the end genuine rar and rarkit's writer use.
#[test]
fn the_control_ending_new_member_new_tables_reads_whole() {
    let (bytes, lz_bytes) = built(false);
    assert_eq!(sha256(&bytes), NEW_SHA256);
    reads_whole(&bytes, &lz_bytes);
}

fn reference(name: &str, env: &str) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(path) = std::env::var_os(env) {
        candidates.push(PathBuf::from(path));
    }
    candidates.push(PathBuf::from(name));
    if let Some(home) = std::env::var_os("HOME") {
        candidates.push(Path::new(&home).join("bin").join(name));
    }
    candidates.push(Path::new("/opt/homebrew/bin").join(name));
    candidates
        .into_iter()
        .find(|path| Command::new(path).output().is_ok())
}

/// Reference `unrar t` on both archives: its output names the members
/// that fail their checksum. Measured with 7.23 on 27 Sep 2026: the
/// control passes whole and the pinned shape fails `p3` alone. Should a
/// reference ever read the pinned shape whole, this fails, and that is
/// news for the specification question above, not a defect in rarkit.
#[test]
fn reference_unrar_fails_the_third_member_of_the_pinned_shape_only() {
    let Some(unrar) = reference("unrar", "RARKIT_REF_UNRAR") else {
        eprintln!("SKIPPED the reference arm: no unrar on PATH, in ~/bin or /opt/homebrew/bin");
        return;
    };
    let dir = std::env::temp_dir().join(format!("rarkit-same-end-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    for (same_member, want_failed) in [(true, vec!["p3"]), (false, vec![])] {
        let (bytes, _) = built(same_member);
        let path = dir.join(if same_member { "same.rar" } else { "new.rar" });
        std::fs::write(&path, &bytes).expect("write archive");
        let run = Command::new(&unrar)
            .arg("t")
            .arg("-idcdp")
            .arg(&path)
            .output()
            .expect("unrar runs");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );
        let failed: Vec<&str> = text
            .lines()
            .filter_map(|line| line.strip_suffix(" - checksum error"))
            .map(str::trim)
            .collect();
        assert_eq!(
            failed, want_failed,
            "same member end {same_member}:\n{text}"
        );
        assert_eq!(run.status.success(), want_failed.is_empty(), "{text}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
