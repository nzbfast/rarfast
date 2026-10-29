//! `rarfast r`, the repair command, against `rar` 7.23's own answers.
//!
//! Every row below was measured on 30 Sep 2026 by running `rar r` (7.23,
//! macOS, aarch64) and `rarfast r` side by side on byte-identical copies of
//! the archives this file builds: the inputs come from the same generator,
//! the archives are written by rarfast itself (stored, so their geometry
//! does not move with the compressor), and the damage is the same bytes.
//! Each row pins stdout (the banner the harness drops left out, every
//! counter written `[NN]`), the exit code and the files written.
//!
//! Three things differ from the reference, each by design and each pinned
//! by a row that says so:
//!
//! - a group with more damaged slices than recovery rows is REPORTED as
//!   the reference reports it, but its bytes are left as they were. The
//!   reference overwrites every damaged slice of such a group with a solve
//!   that cannot be right (it matches neither the original bytes nor the
//!   damaged ones, measured on two archives), so the file is never worse
//!   here and is otherwise the reference's;
//! - a volume whose headers do not walk and that has no usable record is
//!   rebuilt by the reference from a scan for headers. rarkit does not
//!   rebuild headers by scanning, so that is refused by name, exit 2,
//!   nothing written;
//! - the RAR 4 family's `r` is a different report (512-byte sectors, two
//!   analysis passes, a fixed file even when nothing was wrong) and is
//!   refused by name, exit 2, nothing written.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// An empty directory of one test's own, made afresh under the system's
/// temporary directory; `tag` tells the tests of this file apart.
fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-repair-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Seeded bytes that do not compress. The measurement used a byte-for-byte
/// copy of this generator.
fn noise(seed: u32, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9e37_79b9) | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

/// The inputs: `src/rand.bin` and `src/text.bin` (500,000 bytes between
/// them), or `src/big.bin` (14,000,000, so the record has three groups).
fn inputs(dir: &Path, big: bool) {
    std::fs::create_dir_all(dir.join("src")).unwrap();
    if big {
        std::fs::write(dir.join("src/big.bin"), noise(3, 14_000_000)).unwrap();
    } else {
        std::fs::write(dir.join("src/rand.bin"), noise(1, 300_000)).unwrap();
        std::fs::write(dir.join("src/text.bin"), noise(2, 200_000)).unwrap();
    }
}

fn run(dir: &Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(rarfast())
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        tokens(&String::from_utf8_lossy(&out.stdout)),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Every counter redraw (four backspaces and a right-aligned percentage)
/// written as `[NN]`, which is how the rows spell them.
fn tokens(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find("\u{8}\u{8}\u{8}\u{8}") {
        out.push_str(&rest[..at]);
        let tail = &rest[at + 4..];
        let end = tail.find('%').expect("a counter ends in %");
        out.push('[');
        out.push_str(tail[..end].trim_start());
        out.push(']');
        rest = &tail[end + 1..];
    }
    out.push_str(rest);
    out
}

/// Flips four bytes at `start + j * step` for each `j` below `count`,
/// which is what the measurement did.
fn damage(path: &Path, count: usize, start: usize, step: usize) {
    let mut bytes = std::fs::read(path).unwrap();
    for j in 0..count {
        for byte in &mut bytes[start + j * step..start + j * step + 4] {
            *byte ^= 0x5a;
        }
    }
    std::fs::write(path, bytes).unwrap();
}

/// The archives every row starts from, built once.
struct Built {
    dir: PathBuf,
}

impl Built {
    fn new(tag: &str) -> Built {
        let dir = work(&format!("built-{tag}"));
        let small = dir.join("small");
        let large = dir.join("large");
        inputs(&small, false);
        inputs(&large, true);
        let make = |at: &Path, args: &[&str]| {
            let status = Command::new(rarfast())
                .args(args)
                .current_dir(at)
                .status()
                .unwrap();
            assert!(status.success(), "{args:?}");
        };
        make(&small, &["a", "-idq", "-m0", "-rr3", "../a3.rar", "src/"]);
        make(&small, &["a", "-idq", "-m0", "-rr10", "../a10.rar", "src/"]);
        make(
            &small,
            &["a", "-idq", "-m0", "-rr3", "-v150k", "../v.rar", "src/"],
        );
        make(&small, &["a", "-idq", "-m0", "../n.rar", "src/"]);
        make(&small, &["a", "-idq", "-m0", "-v150k", "../vn.rar", "src/"]);
        make(
            &small,
            &["a", "-idq", "-m0", "-rr3", "-hpsecret", "../hp.rar", "src/"],
        );
        make(&large, &["a", "-idq", "-m0", "-rr3", "../big.rar", "src/"]);
        Built { dir }
    }

    /// A fresh cell directory holding `a.rar`, a copy of `archive`.
    fn cell(&self, tag: &str, archive: &str) -> PathBuf {
        let dir = work(tag);
        std::fs::copy(self.dir.join(archive), dir.join("a.rar")).unwrap();
        dir
    }

    /// A fresh cell directory holding every volume of the set `stem`.
    fn set(&self, tag: &str, stem: &str) -> PathBuf {
        let dir = work(tag);
        for n in 1..=4 {
            let name = format!("{stem}.part{n}.rar");
            std::fs::copy(self.dir.join(&name), dir.join(&name)).unwrap();
        }
        dir
    }

    fn bytes(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.dir.join(name)).unwrap()
    }
}

impl Drop for Built {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

const SEARCH_SMALL: &str =
    "\nSearching for recovery record      [0][100]\nData recovery record found\n";
const ANALYZE_SMALL: &str = "Analyzing file data      [99][100]\n";
const SEARCH_BIG: &str = "\nSearching for recovery record      [0][7][14][21][29][36][43][50][58][65][72][79][87][94][100]\nData recovery record found\n";
const ANALYZE_BIG: &str = "Analyzing file data      [28][57][85][99][100]\n";

/// `Corrupt` lines for the small archive's shards (`G` = 2,502).
fn corrupt(shards: &[u64], verdict: &str) -> String {
    shards
        .iter()
        .map(|j| {
            format!(
                "\nCorrupt 2502 bytes at 00000000 {:08x} - {verdict}     ",
                j * 2502
            )
        })
        .collect()
}

/// The shards `damage(.., 21, 1000, 2600)` lands in: shard 16 is stepped over.
const SHARDS_2600: [u64; 21] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18, 19, 20, 21,
];

#[test]
fn every_measured_cell_answers_as_the_reference_does() {
    let built = Built::new("cells");
    let original = built.bytes("a3.rar");

    // Undamaged: the whole report and no file.
    let dir = built.cell("clean", "a3.rar");
    let (code, stdout, _) = run(&dir, &["r", "a.rar"]);
    assert_eq!(code, 0);
    assert_eq!(
        stdout,
        format!("{SEARCH_SMALL}{ANALYZE_SMALL}Building fixed.a.rar      [0][100]\n0 blocks are recovered, 0 blocks are relocated\nDone\n")
    );
    assert!(!dir.join("fixed.a.rar").exists());

    // One and three damaged slices: mended, and the file is the original.
    for (tag, count, shards) in [("one", 1, &[0u64][..]), ("three", 3, &[0, 1, 3][..])] {
        let dir = built.cell(tag, "a3.rar");
        damage(&dir.join("a.rar"), count, 1000, 4000);
        let (code, stdout, stderr) = run(&dir, &["r", "a.rar"]);
        assert_eq!(code, 0, "{tag}: {stderr}");
        assert_eq!(
            stdout,
            format!(
                "{SEARCH_SMALL}{ANALYZE_SMALL}Building fixed.a.rar      [0]{}[100]\n{count} blocks are recovered, 0 blocks are relocated\nDone\n",
                corrupt(shards, "data recovered")
            ),
            "{tag}"
        );
        assert_eq!(
            std::fs::read(dir.join("fixed.a.rar")).unwrap(),
            original,
            "{tag}"
        );
    }

    // Beyond the record (seven slices, six rows): reported, nothing mended,
    // and the archive rebuilt without asking: the volume up to its end
    // block.
    let dir = built.cell("beyond", "a3.rar");
    damage(&dir.join("a.rar"), 7, 1000, 4000);
    let damaged = std::fs::read(dir.join("a.rar")).unwrap();
    let (code, stdout, _) = run(&dir, &["r", "a.rar"]);
    // Exit 3, not the reference's 0: a repair that did not mend everything
    // it judged damaged never exits 0 (bug sweep of 8 Oct 2026, item 09;
    // `tests/repair_unmended_exit.rs`).
    assert_eq!(code, 3);
    assert_eq!(
        stdout,
        format!(
            "{SEARCH_SMALL}{ANALYZE_SMALL}Building fixed.a.rar      [0]{}[100]\n0 blocks are recovered, 0 blocks are relocated\nReconstructing a.rar\nBuilding rebuilt.a.rar      [0]\nFound  src/rand.bin     [57]\nFound  src/text.bin     [95][99][100]\nDone\n",
            corrupt(&[0, 1, 3, 5, 6, 8, 9], "cannot recover data")
        )
    );
    assert!(!dir.join("fixed.a.rar").exists());
    assert_eq!(
        std::fs::read(dir.join("rebuilt.a.rar")).unwrap(),
        damaged[..damaged.len() - 8]
    );

    // `-rr10`: twenty slices mend, twenty-one do not.
    let dir = built.cell("ten20", "a10.rar");
    damage(&dir.join("a.rar"), 20, 1000, 2600);
    let (code, stdout, _) = run(&dir, &["r", "a.rar"]);
    assert_eq!(code, 0);
    assert_eq!(
        stdout,
        format!(
            "{SEARCH_SMALL}{ANALYZE_SMALL}Building fixed.a.rar      [0]{}[100]\n20 blocks are recovered, 0 blocks are relocated\nDone\n",
            corrupt(&SHARDS_2600[..20], "data recovered")
        )
    );
    assert_eq!(
        std::fs::read(dir.join("fixed.a.rar")).unwrap(),
        built.bytes("a10.rar")
    );
    let dir = built.cell("ten21", "a10.rar");
    damage(&dir.join("a.rar"), 21, 1000, 2600);
    let (code, stdout, _) = run(&dir, &["r", "a.rar"]);
    // Exit 3, as above.
    assert_eq!(code, 3);
    assert_eq!(
        stdout,
        format!(
            "{SEARCH_SMALL}{ANALYZE_SMALL}Building fixed.a.rar      [0]{}[100]\n0 blocks are recovered, 0 blocks are relocated\nReconstructing a.rar\nBuilding rebuilt.a.rar      [0]\nFound  src/rand.bin     [51]\nFound  src/text.bin     [85][99][100]\nDone\n",
            corrupt(&SHARDS_2600, "cannot recover data")
        )
    );

    // An existing `fixed.a.rar`: asked on stderr, no answer on stdin is a
    // read error (12); `-o-` skips to `Done`; `-y` overwrites.
    let dir = built.cell("exist", "a3.rar");
    damage(&dir.join("a.rar"), 1, 1000, 4000);
    std::fs::write(dir.join("fixed.a.rar"), b"old\n").unwrap();
    let (code, stdout, stderr) = run(&dir, &["r", "a.rar"]);
    assert_eq!(code, 12);
    assert_eq!(stdout, format!("{SEARCH_SMALL}\nProgram aborted\n"));
    assert!(
        stderr.contains("Overwrite fixed.a.rar?\n[Y]es, [N]o, [A]ll, n[E]ver, [R]ename, [Q]uit ")
    );
    assert!(stderr.contains("Read error in the file stdin"));
    let (code, stdout, _) = run(&dir, &["r", "-o-", "a.rar"]);
    assert_eq!(
        (code, stdout.as_str()),
        (0, &*format!("{SEARCH_SMALL}Done\n"))
    );
    assert_eq!(std::fs::read(dir.join("fixed.a.rar")).unwrap(), b"old\n");
    let (code, _, _) = run(&dir, &["r", "-y", "a.rar"]);
    assert_eq!(code, 0);
    assert_eq!(std::fs::read(dir.join("fixed.a.rar")).unwrap(), original);

    // A destination that is not there yet is created, with its own line,
    // and the fixed file goes into it.
    let dir = built.cell("dest", "a3.rar");
    damage(&dir.join("a.rar"), 1, 1000, 4000);
    let (code, stdout, _) = run(&dir, &["r", "a.rar", "out/"]);
    assert_eq!(code, 0);
    assert_eq!(
        stdout,
        format!(
            "{SEARCH_SMALL}Creating    out                                                       OK\n{ANALYZE_SMALL}Building out/fixed.a.rar      [0]{}[100]\n1 blocks are recovered, 0 blocks are relocated\nDone\n",
            corrupt(&[0], "data recovered")
        )
    );
    assert_eq!(
        std::fs::read(dir.join("out/fixed.a.rar")).unwrap(),
        original
    );

    // An archive in another directory: the fixed file lands in the
    // CURRENT directory, under the archive's own name.
    let dir = work("elsewhere");
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::copy(built.dir.join("a3.rar"), dir.join("sub/a.rar")).unwrap();
    damage(&dir.join("sub/a.rar"), 1, 1000, 4000);
    let (code, _, _) = run(&dir, &["r", "sub/a.rar"]);
    assert_eq!(code, 0);
    assert_eq!(std::fs::read(dir.join("fixed.a.rar")).unwrap(), original);
    assert!(!dir.join("sub/fixed.a.rar").exists());

    // No record: no search, and the rebuild.
    let dir = built.cell("norec", "n.rar");
    let (code, stdout, _) = run(&dir, &["r", "a.rar"]);
    assert_eq!(code, 0);
    assert_eq!(
        stdout,
        "\nData recovery record not found\nReconstructing a.rar\nBuilding rebuilt.a.rar      [0]\nFound  src/rand.bin     [59]\nFound  src/text.bin     [99][100]\nDone\n"
    );
    let plain = built.bytes("n.rar");
    assert_eq!(
        std::fs::read(dir.join("rebuilt.a.rar")).unwrap(),
        plain[..plain.len() - 8]
    );

    // A volume set: only the named volume, and its end block rewritten as
    // a last volume's.
    let dir = built.set("vol", "v");
    damage(&dir.join("v.part2.rar"), 1, 5000, 1);
    let (code, stdout, _) = run(&dir, &["r", "v.part2.rar"]);
    assert_eq!(code, 0);
    assert_eq!(
        stdout,
        format!("{SEARCH_SMALL}{ANALYZE_SMALL}Building fixed.v.part2.rar      [0]\nCorrupt 1024 bytes at 00000000 00001000 - data recovered     [100]\n1 blocks are recovered, 0 blocks are relocated\nDone\n")
    );
    let volume = built.bytes("v.part2.rar");
    let mut expected = volume[..volume.len() - 8].to_vec();
    expected.extend_from_slice(&[0x1d, 0x77, 0x56, 0x51, 0x03, 0x05, 0x04, 0x00]);
    assert_eq!(
        std::fs::read(dir.join("fixed.v.part2.rar")).unwrap(),
        expected
    );
    for other in [
        "fixed.v.part1.rar",
        "fixed.v.part3.rar",
        "fixed.v.part4.rar",
    ] {
        assert!(!dir.join(other).exists(), "{other}");
    }

    // A volume set with no record: an unpadded volume drops its end block.
    let dir = built.set("voln", "vn");
    let (code, stdout, _) = run(&dir, &["r", "vn.part1.rar"]);
    assert_eq!(code, 0);
    assert_eq!(
        stdout,
        "\nData recovery record not found\nReconstructing vn.part1.rar\nBuilding rebuilt.vn.part1.rar      [0]\nFound  src/rand.bin     [99][100]\nDone\n"
    );
    let first = built.bytes("vn.part1.rar");
    assert_eq!(
        std::fs::read(dir.join("rebuilt.vn.part1.rar")).unwrap(),
        first[..first.len() - 8]
    );

    // Encrypted headers: the record is found by scanning either way; with
    // the password the fixed file is the whole volume, without it only the
    // protected bytes.
    let hp = built.bytes("hp.rar");
    for (tag, args) in [
        ("hp", &["r", "a.rar"][..]),
        ("hpp", &["r", "-psecret", "a.rar"][..]),
    ] {
        let dir = built.cell(tag, "hp.rar");
        damage(&dir.join("a.rar"), 1, 5000, 1);
        let (code, stdout, _) = run(&dir, args);
        assert_eq!(code, 0, "{tag}");
        assert_eq!(
            stdout,
            format!(
                "{SEARCH_SMALL}{ANALYZE_SMALL}Building fixed.a.rar      [0]\nCorrupt 2502 bytes at 00000000 000009c6 - data recovered     [100]\n1 blocks are recovered, 0 blocks are relocated\nDone\n"
            ),
            "{tag}"
        );
        let fixed = std::fs::read(dir.join("fixed.a.rar")).unwrap();
        if tag == "hpp" {
            assert_eq!(fixed, hp);
        } else {
            assert!(fixed.len() < hp.len() && hp.starts_with(&fixed), "{tag}");
        }
    }

    // Three groups: the lines come group by group between the counter's
    // per-group ticks.
    let dir = built.cell("big", "big.rar");
    damage(&dir.join("a.rar"), 3, 100_000, 300_000);
    let (code, stdout, _) = run(&dir, &["r", "a.rar"]);
    assert_eq!(code, 0);
    assert_eq!(
        stdout,
        format!("{SEARCH_BIG}{ANALYZE_BIG}Building fixed.a.rar      [0]\nCorrupt 65536 bytes at 00000000 00011172 - data recovered     \nCorrupt 65536 bytes at 00000000 0005573a - data recovered     [93]\nCorrupt 4466 bytes at 00000000 000a9d02 - data recovered     [100]\n3 blocks are recovered, 0 blocks are relocated\nDone\n")
    );
    assert_eq!(
        std::fs::read(dir.join("fixed.a.rar")).unwrap(),
        built.bytes("big.rar")
    );

    // A missing archive: `k`'s answer.
    let dir = work("none");
    let (code, stdout, stderr) = run(&dir, &["r", "nosuch.rar"]);
    assert_eq!((code, stdout.as_str()), (10, "\nDone\n"));
    assert!(stderr.contains("Cannot open nosuch.rar"));
}

#[test]
fn a_partly_recoverable_archive_mends_what_it_can_and_asks_before_rebuilding() {
    let built = Built::new("part");
    let dir = built.cell("part", "big.rar");
    // Seven slices of group 1 (six rows), one of group 0.
    damage(&dir.join("a.rar"), 7, 66_000, 70_002);
    damage(&dir.join("a.rar"), 1, 701_020, 1);
    let damaged = std::fs::read(dir.join("a.rar")).unwrap();
    let (code, stdout, stderr) = run(&dir, &["r", "a.rar"]);
    let lost: String = (0..7u64)
        .map(|j| {
            format!(
                "\nCorrupt 4466 bytes at 00000000 {:08x} - cannot recover data     ",
                j * 70_002 + 65_536
            )
        })
        .collect();
    assert_eq!(code, 12);
    assert_eq!(
        stdout,
        format!("{SEARCH_BIG}{ANALYZE_BIG}Building fixed.a.rar      [0]\nCorrupt 65536 bytes at 00000000 000aae74 - data recovered     [93]{lost}[100]\n1 blocks are recovered, 0 blocks are relocated\n\nProgram aborted\n")
    );
    assert!(stderr.contains("Reconstruct archive structure? [Y]es, [N]o "));

    // The difference from the reference, by design: group 0 is mended and
    // group 1 is left exactly as it was, where the reference writes a
    // solve over it that matches neither.
    let fixed = std::fs::read(dir.join("fixed.a.rar")).unwrap();
    let original = built.bytes("big.rar");
    assert_eq!(fixed.len(), original.len());
    assert_eq!(fixed[701_020..701_024], original[701_020..701_024]);
    for j in 0..7 {
        let at = 66_000 + j * 70_002;
        assert_eq!(fixed[at..at + 4], damaged[at..at + 4], "slice {j}");
    }

    // `-y` answers the question: the rebuild follows, from the damaged
    // archive, not from the fixed one.
    let (code, stdout, _) = run(&dir, &["r", "-y", "a.rar"]);
    // Exit 3, not the reference's 0: a repair that did not mend everything
    // it judged damaged never exits 0 (bug sweep of 8 Oct 2026, item 09;
    // `tests/repair_unmended_exit.rs`).
    assert_eq!(code, 3);
    assert!(stdout.ends_with(
        "1 blocks are recovered, 0 blocks are relocated\nReconstructing a.rar\nBuilding rebuilt.a.rar      [0]\nFound  src/big.bin     [96][99][100]\nDone\n"
    ));
    assert_eq!(
        std::fs::read(dir.join("rebuilt.a.rar")).unwrap(),
        damaged[..damaged.len() - 8]
    );
}

/// CRC-64/XZ, bit by bit: the seal of one record of a RAR 5 recovery
/// record (spec L 3.5.2), which anyone can compute.
fn crc64_xz(bytes: &[u8]) -> u64 {
    let mut crc = u64::MAX;
    for &byte in bytes {
        crc ^= u64::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xC96C_5795_D787_0F42
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Changes four parity bytes of recovery row `row` (group 0) and seals
/// the record again, so its own check holds over parity that is wrong.
fn falsify_row(path: &Path, row: usize) {
    let mut bytes = std::fs::read(path).unwrap();
    let first = bytes
        .windows(4)
        .position(|w| w == b"{RB}")
        .expect("a record");
    let le32 = |b: &[u8], at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) as usize;
    let (len, header) = (le32(&bytes, first + 0x0c), le32(&bytes, first + 0x10));
    let at = first + row * len;
    assert_eq!(
        &bytes[at..at + 4],
        b"{RB}",
        "one group, so rows are a record apart"
    );
    for byte in &mut bytes[at + header + 10..at + header + 14] {
        *byte ^= 0xa5;
    }
    let seal = crc64_xz(&bytes[at + 0x0c..at + len]);
    bytes[at + 4..at + 12].copy_from_slice(&seal.to_le_bytes());
    std::fs::write(path, bytes).unwrap();
}

/// A slice whose rebuild fails its own CRC-64 is not recovered, and the
/// run must not say it was. Measured on 4 Oct 2026 with `rar` 7.23
/// (macOS, aarch64) on byte-identical copies: one damaged slice and a
/// recovery row 0 sealed over wrong parity is `cannot recover data`, `0
/// blocks are recovered`, no fixed file and the rebuild without asking;
/// two damaged slices the same, both lines; the wrong parity in a row the
/// solve does not use (row 5, one slice) is `data recovered` and a fixed
/// file. The archive is 525 KB, the default thread pool and memory.
#[test]
fn a_rebuild_that_fails_its_check_is_not_reported_as_recovered() {
    let built = Built::new("falsified");
    const REBUILT: &str = "Reconstructing a.rar\nBuilding rebuilt.a.rar      [0]\nFound  src/rand.bin     [57]\nFound  src/text.bin     [95][99][100]\nDone\n";
    for (tag, count, shards) in [("one", 1, &[0u64][..]), ("two", 2, &[0, 1][..])] {
        let dir = built.cell(&format!("falsified-{tag}"), "a3.rar");
        damage(&dir.join("a.rar"), count, 1000, 4000);
        falsify_row(&dir.join("a.rar"), 0);
        let damaged = std::fs::read(dir.join("a.rar")).unwrap();
        let (code, stdout, stderr) = run(&dir, &["r", "a.rar"]);
        // Exit 3, not the reference's 0: a repair that did not mend
        // everything it judged damaged never exits 0 (bug sweep of 8 Oct
        // 2026, item 09; `tests/repair_unmended_exit.rs`).
        assert_eq!(code, 3, "{tag}: {stderr}");
        assert_eq!(
            stdout,
            format!(
                "{SEARCH_SMALL}{ANALYZE_SMALL}Building fixed.a.rar      [0]{}[100]\n0 blocks are recovered, 0 blocks are relocated\n{REBUILT}",
                corrupt(shards, "cannot recover data")
            ),
            "{tag}"
        );
        assert!(!dir.join("fixed.a.rar").exists(), "{tag}");
        assert!(!dir.join("fixed.a.rar.rarfast-new").exists(), "{tag}");
        assert_eq!(
            std::fs::read(dir.join("rebuilt.a.rar")).unwrap(),
            damaged[..damaged.len() - 8],
            "{tag}"
        );
    }

    // The wrong parity in a row the solve leaves alone: mended.
    let dir = built.cell("falsified-unused", "a3.rar");
    damage(&dir.join("a.rar"), 1, 1000, 4000);
    falsify_row(&dir.join("a.rar"), 5);
    let (code, stdout, _) = run(&dir, &["r", "a.rar"]);
    assert_eq!(code, 0);
    assert_eq!(
        stdout,
        format!(
            "{SEARCH_SMALL}{ANALYZE_SMALL}Building fixed.a.rar      [0]{}[100]\n1 blocks are recovered, 0 blocks are relocated\nDone\n",
            corrupt(&[0], "data recovered")
        )
    );
    let fixed = std::fs::read(dir.join("fixed.a.rar")).unwrap();
    let original = built.bytes("a3.rar");
    assert_eq!(
        fixed[..500_000],
        original[..500_000],
        "the data is the original's"
    );
}

/// Breaks the seal of every record of `group` (one parity byte each), so
/// no recovery row survives for that group and its slices have no table
/// to be checked against.
fn lose_group(path: &Path, group: u64) {
    let mut bytes = std::fs::read(path).unwrap();
    let le = |b: &[u8], at: usize, n: usize| {
        let mut wide = [0u8; 8];
        wide[..n].copy_from_slice(&b[at..at + n]);
        u64::from_le_bytes(wide) as usize
    };
    let mut at = bytes
        .windows(4)
        .position(|w| w == b"{RB}")
        .expect("a record");
    let mut lost = 0;
    while at + 0x48 <= bytes.len() && &bytes[at..at + 4] == b"{RB}" {
        let (len, header) = (le(&bytes, at + 0x0c, 4), le(&bytes, at + 0x10, 4));
        if le(&bytes, at + 0x16, 8) as u64 == group * 65_536 {
            bytes[at + header + 20] ^= 0xff;
            lost += 1;
        }
        at += len;
    }
    assert_eq!(lost, 6, "-rr3 at k = 200 is six rows");
    std::fs::write(path, bytes).unwrap();
}

/// A group whose recovery records are all lost cannot be judged, and the
/// run must not end `Done`, exit 0, as if it had been. Measured on 4 Oct
/// 2026 with `rar` 7.23 (macOS, aarch64) on byte-identical copies of the
/// 14 MB archive with every group-1 record's seal broken: `Recovery
/// record is corrupt.` on stdout after the count, then the flow of a
/// group that could not mend, and exit 3 where that flow ends `Done`;
/// the same whether a group-1 slice is damaged or not, since nothing can
/// tell. The default thread pool and memory.
#[test]
fn a_group_with_no_record_left_is_reported_and_not_called_done() {
    let built = Built::new("lostgroup");
    const REBUILT: &str = "Reconstructing a.rar\nBuilding rebuilt.a.rar      [0]\nFound  src/big.bin     [96][99][100]\nDone\n";

    // Damage in the unjudged group, and none: the same answer.
    for (tag, hits) in [("damaged", 1), ("clean", 0)] {
        let dir = built.cell(&format!("lostgroup-{tag}"), "big.rar");
        damage(&dir.join("a.rar"), hits, 66_000, 1);
        lose_group(&dir.join("a.rar"), 1);
        let (code, stdout, stderr) = run(&dir, &["r", "a.rar"]);
        assert_eq!(code, 3, "{tag}: {stderr}");
        assert_eq!(
            stdout,
            format!("{SEARCH_BIG}{ANALYZE_BIG}Building fixed.a.rar      [0][93][100]\n0 blocks are recovered, 0 blocks are relocated\nRecovery record is corrupt.\n{REBUILT}"),
            "{tag}"
        );
        assert!(!dir.join("fixed.a.rar").exists(), "{tag}");
    }

    // Group 0 mends beside it: the fixed file, then the question.
    let dir = built.cell("lostgroup-both", "big.rar");
    damage(&dir.join("a.rar"), 1, 66_000, 1);
    damage(&dir.join("a.rar"), 1, 1_000, 1);
    lose_group(&dir.join("a.rar"), 1);
    let report = format!("{SEARCH_BIG}{ANALYZE_BIG}Building fixed.a.rar      [0]\nCorrupt 65536 bytes at 00000000 00000000 - data recovered     [93][100]\n1 blocks are recovered, 0 blocks are relocated\nRecovery record is corrupt.\n");
    let (code, stdout, stderr) = run(&dir, &["r", "a.rar"]);
    assert_eq!(code, 12);
    assert_eq!(stdout, format!("{report}\nProgram aborted\n"));
    assert!(stderr.contains("Reconstruct archive structure? [Y]es, [N]o "));
    let fixed = std::fs::read(dir.join("fixed.a.rar")).unwrap();
    let original = built.bytes("big.rar");
    assert_eq!(
        fixed[1_000..1_004],
        original[1_000..1_004],
        "group 0 mended"
    );
    let (code, stdout, _) = run(&dir, &["r", "-y", "a.rar"]);
    assert_eq!(code, 3);
    assert_eq!(stdout, format!("{report}{REBUILT}"));
}

/// A repair holds its rebuilt slices until they are written, and that is
/// charged to the repair's memory limit with its stripe. A repair whose
/// slices are past the limit is made in BATCHES and mends all the same;
/// it was refused before the engine had batches.
///
/// 14 MB at `-rr20` (forty rows, two groups), forty slices of group 0
/// damaged: 2,621,440 bytes of slices and a stripe of 671,744, which is
/// 3,293,184 in one batch. `-mm2m` gives a repair 1 MiB and `-mm38m` is
/// the largest budget whose share is under the one batch; both mend, as
/// `-mm39m` and no budget at all do. The repair runs on the calling
/// thread here whatever the pool's width (under a MiB of slices per
/// thread to hash, stripes under the team's gate).
#[test]
fn a_repair_past_the_memory_limit_is_made_in_batches() {
    let dir = work("memory");
    inputs(&dir, true);
    let (code, _, stderr) = run(&dir, &["a", "-idq", "-m0", "-rr20", "big.rar", "src/"]);
    assert_eq!(code, 0, "{stderr}");
    let original = std::fs::read(dir.join("big.rar")).unwrap();
    std::fs::copy(dir.join("big.rar"), dir.join("a.rar")).unwrap();
    damage(&dir.join("a.rar"), 40, 100, 70_002);

    for budget in [
        &["r", "-y", "-mm2m", "a.rar"][..],
        &["r", "-y", "-mm38m", "a.rar"][..],
        &["r", "-y", "-mm39m", "a.rar"][..],
        &["r", "-y", "a.rar"][..],
    ] {
        let (code, stdout, stderr) = run(&dir, budget);
        assert_eq!(code, 0, "{budget:?}: {stderr}");
        assert!(
            stdout.ends_with("40 blocks are recovered, 0 blocks are relocated\nDone\n"),
            "{budget:?}: {stdout}"
        );
        assert_eq!(std::fs::read(dir.join("fixed.a.rar")).unwrap(), original);
        std::fs::remove_file(dir.join("fixed.a.rar")).unwrap();
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// What is still refused, by name, with both figures and the `-mm` that
/// lets it run, exit 2, before anything is rebuilt: a limit below ONE
/// slice and the smallest stripe. It is neither `recovered` nor `cannot
/// recover`, and nothing is written.
///
/// 14 MB at `-rr40` (eighty rows), sixty-four slices of group 0 damaged:
/// one slice of 65,536 bytes and a stripe of 130 rows of 8 KiB, 1,130,496
/// in all, which the 1 MiB that `-mm2m` gives a repair does not hold.
/// One process at a time, on the calling thread as above.
#[test]
fn a_repair_limit_under_one_slice_and_a_stripe_stops_with_both_figures() {
    let dir = work("memory-floor");
    inputs(&dir, true);
    let (code, _, stderr) = run(&dir, &["a", "-idq", "-m0", "-rr40", "big.rar", "src/"]);
    assert_eq!(code, 0, "{stderr}");
    let original = std::fs::read(dir.join("big.rar")).unwrap();
    std::fs::copy(dir.join("big.rar"), dir.join("a.rar")).unwrap();
    damage(&dir.join("a.rar"), 64, 100, 70_002);

    let (code, stdout, stderr) = run(&dir, &["r", "-mm2m", "a.rar"]);
    assert_eq!(code, 2, "{stderr}");
    assert!(
        stdout.ends_with("Building fixed.a.rar      [0]\n"),
        "{stdout}"
    );
    assert!(!stdout.contains("Corrupt") && !stdout.contains("recovered"));
    assert_eq!(
        stderr,
        "\nrarfast: a.rar is not repaired: the repair needs 1130496 bytes of working memory \
         and its limit is 1048576. -mm35m or more lets it run.\n"
    );
    assert!(!dir.join("fixed.a.rar").exists());
    assert!(!dir.join("fixed.a.rar.rarfast-new").exists());

    // The budget the refusal names: mended.
    let (code, stdout, stderr) = run(&dir, &["r", "-y", "-mm35m", "a.rar"]);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stdout.ends_with("64 blocks are recovered, 0 blocks are relocated\nDone\n"),
        "{stdout}"
    );
    assert_eq!(std::fs::read(dir.join("fixed.a.rar")).unwrap(), original);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The fixed and the rebuilt volume are each written under a name nothing
/// else holds and then renamed into place. A file somebody left at the
/// old fixed name `<output>.rarfast-new` (a file, or a link to one
/// elsewhere) is neither truncated, written through nor renamed away, and
/// the output carries the archive's own permissions, not the umask's (a
/// chosen difference from the reference, spec L 3.9 F4: a private
/// archive's repair stays private).
/// One process at a time, 525 KB. Unix only by its nature: the
/// permissions are a Unix mode and the link is made with the Unix call.
#[cfg(unix)]
#[test]
fn the_output_is_made_under_a_fresh_name_with_the_archives_mode() {
    use std::os::unix::fs::PermissionsExt;
    let built = Built::new("fresh");
    let original = built.bytes("a3.rar");
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;

    // `fixed.`: one slice mends.
    let dir = built.cell("fresh-fixed", "a3.rar");
    damage(&dir.join("a.rar"), 1, 1000, 4000);
    std::fs::set_permissions(dir.join("a.rar"), std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(dir.join("elsewhere"), b"mine\n").unwrap();
    std::os::unix::fs::symlink("elsewhere", dir.join("fixed.a.rar.rarfast-new")).unwrap();
    let (code, _, stderr) = run(&dir, &["r", "a.rar"]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(std::fs::read(dir.join("fixed.a.rar")).unwrap(), original);
    assert_eq!(mode(&dir.join("fixed.a.rar")), 0o600);
    assert_eq!(std::fs::read(dir.join("elsewhere")).unwrap(), b"mine\n");
    assert!(dir
        .join("fixed.a.rar.rarfast-new")
        .symlink_metadata()
        .unwrap()
        .file_type()
        .is_symlink());

    // `rebuilt.`: more damage than rows, so the rebuild runs.
    let dir = built.cell("fresh-rebuilt", "a3.rar");
    damage(&dir.join("a.rar"), 7, 1000, 4000);
    std::fs::set_permissions(dir.join("a.rar"), std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(dir.join("rebuilt.a.rar.rarfast-new"), b"mine\n").unwrap();
    let damaged = std::fs::read(dir.join("a.rar")).unwrap();
    let (code, _, stderr) = run(&dir, &["r", "a.rar"]);
    // Exit 3: more damage than rows is not mended (item 09 of 8 Oct 2026).
    assert_eq!(code, 3, "{stderr}");
    assert_eq!(
        std::fs::read(dir.join("rebuilt.a.rar")).unwrap(),
        damaged[..damaged.len() - 8]
    );
    assert_eq!(mode(&dir.join("rebuilt.a.rar")), 0o600);
    assert_eq!(
        std::fs::read(dir.join("rebuilt.a.rar.rarfast-new")).unwrap(),
        b"mine\n"
    );

    // Nothing of the run's own is left behind in either cell.
    for cell in ["fresh-fixed", "fresh-rebuilt"] {
        let left: Vec<String> = std::fs::read_dir(work_path(cell))
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".rarfast-new."))
            .collect();
        assert!(left.is_empty(), "{cell}: {left:?}");
    }
}

/// Where [`work`] puts the directory of `tag`, without emptying it.
#[cfg(unix)]
fn work_path(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("rarfast-repair-{}-{tag}", std::process::id()))
}

#[test]
fn a_repaired_archive_passes_t_and_gives_back_the_source_bytes() {
    let built = Built::new("round");
    // One volume, damaged at 1 and 3 slices.
    for count in [1, 3] {
        let dir = built.cell(&format!("round{count}"), "a3.rar");
        damage(&dir.join("a.rar"), count, 1000, 4000);
        assert_eq!(run(&dir, &["r", "a.rar"]).0, 0);
        assert_eq!(run(&dir, &["t", "-idq", "fixed.a.rar"]).0, 0);
        assert_eq!(run(&dir, &["x", "-idq", "fixed.a.rar", "out/"]).0, 0);
        for name in ["rand.bin", "text.bin"] {
            assert_eq!(
                std::fs::read(dir.join("out/src").join(name)).unwrap(),
                std::fs::read(built.dir.join("small/src").join(name)).unwrap(),
                "{name} after {count}"
            );
        }
    }
    // A set: the fixed volume put back in its place.
    let dir = built.set("roundset", "v");
    damage(&dir.join("v.part2.rar"), 1, 5000, 1);
    assert_ne!(run(&dir, &["t", "-idq", "v.part1.rar"]).0, 0);
    assert_eq!(run(&dir, &["r", "v.part2.rar"]).0, 0);
    std::fs::rename(dir.join("fixed.v.part2.rar"), dir.join("v.part2.rar")).unwrap();
    assert_eq!(run(&dir, &["t", "-idq", "v.part1.rar"]).0, 0);
    assert_eq!(run(&dir, &["x", "-idq", "v.part1.rar", "out/"]).0, 0);
    for name in ["rand.bin", "text.bin"] {
        assert_eq!(
            std::fs::read(dir.join("out/src").join(name)).unwrap(),
            std::fs::read(built.dir.join("small/src").join(name)).unwrap(),
            "{name} from the set"
        );
    }
}

#[test]
fn a_repair_rarkit_cannot_do_exits_2_and_leaves_no_output() {
    let built = Built::new("refuse");
    // A member header damaged and no record: the reference scans for
    // headers, which rarkit does not.
    let dir = built.cell("hdr", "n.rar");
    damage(&dir.join("a.rar"), 1, 60, 1);
    let (code, stdout, stderr) = run(&dir, &["r", "a.rar"]);
    assert_eq!(code, 2);
    assert_eq!(
        stdout,
        "\nData recovery record not found\nReconstructing a.rar\n"
    );
    assert!(stderr.contains("rarfast: cannot repair a.rar"));
    assert!(!dir.join("rebuilt.a.rar").exists());

    // The RAR 4 family: a genuine rar 4.20 archive with a record.
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/legacy/archives/r420_rr.rar");
    let dir = work("rar4");
    std::fs::copy(fixture, dir.join("a.rar")).unwrap();
    let (code, _, stderr) = run(&dir, &["r", "a.rar"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("RAR 4 family"));
    assert!(!dir.join("fixed.a.rar").exists());
}
