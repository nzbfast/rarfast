//! `rarfast r` repairs the NAMED archive from its OWN recovery record, or
//! says it has none: it never writes another archive under the fixed
//! name (spec L 3.5.5, "Whose records they are", rules O1 to O5 and O1b;
//! bug sweep of 10 Oct 2026, items 01 and 02).
//!
//! Item 01. An archive that stores another archive holds that archive's
//! recovery record inside a member's data, and a scan for records by
//! their marker meets it. Before the rule, with the header path stopped
//! (one bit of the signature changed), the larger set won whoever it
//! belonged to and was held against the named file from byte 0:
//!
//! - an inner record of 150 percent rebuilt every slice from its own
//!   parity, and `r` wrote `fixed.<name>` holding the INNER archive,
//!   said `Done` and exited 0;
//! - an inner record of 20 percent called every slice `cannot recover
//!   data` and exited 3, the outer archive's whole record unused.
//!
//! The reference (`rar` 7.23, 3.5.5's probe of 178 arms) writes two
//! files there, `fixed1.<name>`, the inner archive, and `fixed2.<name>`,
//! the named archive mended; and with the named archive's own records
//! gone it writes the inner archive alone as `fixed.<name>`, `Done`, exit
//! 0. THAT IS NOT FOLLOWED, a chosen strictness of 3.5.5: the one file
//! written here is the reference's second, under the one name
//! `fixed.<name>`, and where the named archive has no record of its own
//! the answer is `not found`.
//!
//! Also pinned: the `RR` header gone and the set own by shard 0 (O1b);
//! that and one signature bit, where the set is own by its distance
//! from the offset it names (O1c) and is mended as the reference mends
//! it; and
//! the rebuild (spec L 3.8, B1 to B4): it walks from where the NAMED
//! archive begins, past a signature that does not read when a sound
//! main header stands behind it, so the outer's own members are rebuilt
//! and never the stored inner archive's; an archive behind other bytes
//! is rebuilt with one line that gives its offset, unless a block of the
//! enclosing archive stands right behind it (B6), which makes it a
//! stored member and the rebuild the enclosing archive's; and every
//! rebuild says its members' data was copied unchecked.
//!
//! Item 02 and O5. One bit of the MAIN HEADER changed: the tolerant open
//! goes past it and so cannot say whether the archive has a record, and
//! `r` did not search: `Data recovery record not found`, exit 2. The
//! reference says on stderr that the main archive header is corrupt,
//! finds the record, writes `fixed.<name>` byte for byte the original,
//! and exits 3. Here the same, line and exit included (decided 10 Oct
//! 2026: the fixed file is right and the corrupt header was real; in
//! the probe the reference exits 3 in every mended arm that damages the
//! main header and 0 in every other mended arm). The other half of O5: a
//! SOUND main header whose record flag is clear ends the search,
//! although every record is there, as the reference does.
//!
//! Width and memory: each run is one `rarfast` process on the machine's
//! own pool; the largest archive is about 1.1 MiB.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

struct Work(PathBuf);

impl Work {
    fn new(tag: &str) -> Work {
        let dir = std::env::temp_dir().join(format!("rarfast-own-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Work(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// Every file here whose name starts `fixed` or `rebuilt`.
    fn outputs(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("fixed") || name.starts_with("rebuilt"))
            .collect();
        names.sort();
        names
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn noise(len: usize, seed: u64) -> Vec<u8> {
    rarkit_testdata::scramble(seed, len)
}

/// `rarfast a`, stored, of `files` into `archive`, with `switches`.
fn add(dir: &Path, switches: &[&str], archive: &str, files: &[&str]) {
    let status = Command::new(rarfast())
        .args(["a", "-idq", "-m0", "-ep"])
        .args(switches)
        .arg(archive)
        .args(files)
        .current_dir(dir)
        .status()
        .unwrap();
    assert!(status.success(), "rarfast a {archive}");
}

/// `outer.rar` in a fresh directory: `inner.rar` (one stored member under
/// `inner`) and a small member, under `outer`. Returns the inner and the
/// outer archive's bytes.
fn nested(tag: &str, inner: &str, outer: &[&str]) -> (Work, Vec<u8>, Vec<u8>) {
    let work = Work::new(tag);
    std::fs::write(work.path("payload.bin"), noise(200_000, 0x6f77_6e01)).unwrap();
    std::fs::write(work.path("small.bin"), noise(20_000, 0x6f77_6e02)).unwrap();
    add(&work.0, &[inner], "inner.rar", &["payload.bin"]);
    add(&work.0, outer, "outer.rar", &["inner.rar", "small.bin"]);
    let inner = std::fs::read(work.path("inner.rar")).unwrap();
    let outer = std::fs::read(work.path("outer.rar")).unwrap();
    (work, inner, outer)
}

/// `plain.rar` in a fresh directory: two stored members under `switches`.
fn plain(tag: &str, switches: &[&str]) -> (Work, Vec<u8>) {
    let work = Work::new(tag);
    std::fs::write(work.path("payload.bin"), noise(200_000, 0x6f77_6e01)).unwrap();
    std::fs::write(work.path("small.bin"), noise(20_000, 0x6f77_6e02)).unwrap();
    add(
        &work.0,
        switches,
        "plain.rar",
        &["payload.bin", "small.bin"],
    );
    let bytes = std::fs::read(work.path("plain.rar")).unwrap();
    (work, bytes)
}

/// Writes `bytes` with each `(offset, mask)` applied as `damaged.rar`.
fn damage(work: &Work, bytes: &[u8], flips: &[(usize, u8)]) {
    let mut damaged = bytes.to_vec();
    for &(at, mask) in flips {
        damaged[at] ^= mask;
    }
    std::fs::write(work.path("damaged.rar"), damaged).unwrap();
}

/// `rarfast r -y damaged.rar` with nothing on standard input: the exit
/// code and stdout.
fn repair(dir: &Path) -> (i32, String) {
    let (code, stdout, _) = repair_all(dir);
    (code, stdout)
}

/// [`repair`], and stderr.
fn repair_all(dir: &Path) -> (i32, String, String) {
    let out = Command::new(rarfast())
        .args(["r", "-y", "damaged.rar"])
        .current_dir(dir)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// One bit of the 8-byte signature: the header path reads nothing.
const SIGNATURE_BIT: (usize, u8) = (3, 0x01);
/// One bit of the main header's flags, the block after the signature: its
/// CRC32 (bytes 8 to 11), its size (12), its type (13), its flags (14).
const MAIN_HEADER_BIT: (usize, u8) = (14, 0x40);

/// The run mended the named archive: `Done`, exit 0, and `fixed.` is
/// `whole` byte for byte, with nothing else written.
fn assert_repaired(work: &Work, whole: &[u8], blocks: u32) {
    let stderr = assert_repaired_exiting(work, whole, blocks, 0);
    assert!(!stderr.contains("is corrupt"), "{stderr}");
}

/// [`assert_repaired`] with the exit named; returns stderr.
fn assert_repaired_exiting(work: &Work, whole: &[u8], blocks: u32, exit: i32) -> String {
    let (code, stdout, stderr) = repair_all(&work.0);
    assert!(stdout.contains("Data recovery record found\n"), "{stdout}");
    assert!(
        stdout.ends_with(&format!(
            "\n{blocks} blocks are recovered, 0 blocks are relocated\nDone\n"
        )),
        "{stdout}"
    );
    assert_eq!(code, exit, "{stdout}");
    assert_eq!(work.outputs(), ["fixed.damaged.rar"]);
    let fixed = std::fs::read(work.path("fixed.damaged.rar")).unwrap();
    assert!(fixed == whole, "fixed.damaged.rar is not the named archive");
    stderr
}

#[test]
fn an_inner_record_of_150_percent_is_not_written_as_the_named_archive() {
    let (work, inner, outer) = nested("in150", "-rr150", &["-rr1"]);
    damage(&work, &outer, &[SIGNATURE_BIT]);
    assert_repaired(&work, &outer, 1);
    let fixed = std::fs::read(work.path("fixed.damaged.rar")).unwrap();
    assert!(!fixed.starts_with(&inner[..4096]));
}

#[test]
fn an_inner_record_of_20_percent_does_not_hide_the_named_archives_own() {
    let (work, _, outer) = nested("in20", "-rr20", &["-rr1"]);
    damage(&work, &outer, &[SIGNATURE_BIT]);
    assert_repaired(&work, &outer, 1);

    // And with a second slice damaged, inside the stored inner archive.
    damage(&work, &outer, &[SIGNATURE_BIT, (100_000, 0xff)]);
    std::fs::remove_file(work.path("fixed.damaged.rar")).unwrap();
    assert_repaired(&work, &outer, 2);
}

/// What every rebuild says of its output, on stderr.
const UNCHECKED: &str = "holds the members' data copied as it was found; none of it was checked";
/// The line of a rebuild whose archive did not begin at byte 0.
const FOUND_AT: &str = "was found at offset ";

/// `not found`, then the plain rebuild from the headers: `rebuilt.` is
/// `whole` up to its end block, under a whole signature; no `fixed.`
/// file, no slice called recovered, the unchecked line, exit 0. Returns
/// stdout and stderr.
fn assert_rebuilt(work: &Work, whole: &[u8]) -> (String, String) {
    let (code, stdout, stderr) = repair_all(&work.0);
    assert!(
        stdout.contains("Data recovery record not found\n"),
        "{stdout}"
    );
    assert!(
        !stdout.contains("recovered") && !stdout.contains("repaired"),
        "{stdout}"
    );
    assert!(stdout.ends_with("Done\n"), "{stdout}");
    assert!(stderr.contains(UNCHECKED), "{stderr}");
    assert_eq!(code, 0, "{stdout}{stderr}");
    assert_eq!(work.outputs(), ["rebuilt.damaged.rar"]);
    let rebuilt = std::fs::read(work.path("rebuilt.damaged.rar")).unwrap();
    assert!(
        whole.starts_with(&rebuilt) && rebuilt.len() + 8 >= whole.len(),
        "rebuilt.damaged.rar is not the named archive up to its end block"
    );
    (stdout, stderr)
}

/// The named archive has no record of its own (O4): it is said to have
/// none and nothing is repaired from the inner archive's. The rebuild
/// that follows walks the NAMED archive past its damaged signature (B2)
/// and writes its two members; the inner archive stays a member (B3).
#[test]
fn an_archive_with_no_record_of_its_own_is_not_repaired_from_an_inner_one() {
    for (tag, inner) in [("none150", "-rr150"), ("none20", "-rr20")] {
        let (work, _, outer) = nested(tag, inner, &[]);
        damage(&work, &outer, &[SIGNATURE_BIT]);
        let (stdout, stderr) = assert_rebuilt(&work, &outer);
        assert!(stdout.contains("Found  inner.rar"), "{inner}: {stdout}");
        assert!(stdout.contains("Found  small.bin"), "{inner}: {stdout}");
        assert!(!stdout.contains("payload.bin"), "{inner}: {stdout}");
        assert!(!stderr.contains(FOUND_AT), "{inner}: {stderr}");
    }
}

/// The rebuild alone, no record anywhere (`rarfast a -m0 outer.rar
/// inner.rar small.bin`), spec L 3.8.
///
/// One signature bit: before the rule the only archive the open found
/// was the stored inner one, and the run wrote `rebuilt.<name>` as a
/// prefix of the damaged file cut at the INNER archive's end block,
/// `Found  payload.bin`, `Done`, exit 0. Now the walk begins at the
/// sound main header behind the damaged signature and the OUTER's own
/// members are rebuilt, as the reference rebuilds them.
#[test]
fn a_rebuild_walks_the_named_archive_past_a_damaged_signature() {
    let (work, _, outer) = nested("rebuild", "-ep", &[]);
    damage(&work, &outer, &[SIGNATURE_BIT]);
    let (stdout, stderr) = assert_rebuilt(&work, &outer);
    assert!(stdout.contains("Found  inner.rar"), "{stdout}");
    assert!(stdout.contains("Found  small.bin"), "{stdout}");
    assert!(!stdout.contains("payload.bin"), "{stdout}");
    assert!(!stderr.contains(FOUND_AT), "{stderr}");

    // The control: the same archive undamaged, the same file.
    std::fs::remove_file(work.path("rebuilt.damaged.rar")).unwrap();
    damage(&work, &outer, &[]);
    let (stdout, stderr) = assert_rebuilt(&work, &outer);
    assert!(stdout.contains("Found  inner.rar"), "{stdout}");
    assert!(!stderr.contains(FOUND_AT), "{stderr}");

    // A signature bit AND a main header bit: no head of the named
    // archive is left to walk, and nothing is rebuilt from the archive
    // further in. Nothing written, exit 2.
    std::fs::remove_file(work.path("rebuilt.damaged.rar")).unwrap();
    damage(&work, &outer, &[SIGNATURE_BIT, MAIN_HEADER_BIT]);
    let (code, stdout, stderr) = repair_all(&work.0);
    assert!(!stdout.contains("Found  "), "{stdout}");
    assert!(stderr.contains("cannot repair"), "{stderr}");
    assert_eq!(code, 2, "{stdout}");
    assert_eq!(work.outputs(), [""; 0]);
}

/// B4 and its control: 3,001 other bytes in front of the archive are a
/// module. The archive behind them is rebuilt without them, signature
/// bit changed or not, and one line gives the offset it was found at.
#[test]
fn a_rebuild_behind_other_bytes_says_where_the_archive_was_found() {
    let (work, _, outer) = nested("module", "-ep", &[]);
    let module = noise(3_001, 0x0000_4d5a);
    for flips in [&[][..], &[(3_001 + 3, 0x01u8)][..]] {
        let mut file = module.clone();
        file.extend(&outer);
        damage(&work, &file, flips);
        let (stdout, stderr) = assert_rebuilt(&work, &outer);
        assert!(stdout.contains("Found  inner.rar"), "{stdout}");
        assert!(stdout.contains("Found  small.bin"), "{stdout}");
        assert!(
            stderr.contains(&format!("{FOUND_AT}3001 of damaged.rar")),
            "{stderr}"
        );
        std::fs::remove_file(work.path("rebuilt.damaged.rar")).unwrap();
    }
}

/// B6, the same head gone: every byte in front of the stored inner
/// archive zero. The walk from the stored signature ends at the inner
/// archive's end block, and right behind it stands the file header of
/// `small.bin`, a block of the archive that ENCLOSES it. So the rebuild
/// is of the enclosing archive: `small.bin` is written, and the stored
/// archive, whose own file header went with the head, is left out with
/// one line that gives its offset and its length. Its member is never
/// written as if it were the named archive's. (The reference lists the
/// inner archive's member alone.)
#[test]
fn with_the_named_archives_head_gone_the_rebuild_is_of_the_enclosing_archive() {
    let (work, inner, outer) = nested("headgone", "-ep", &[]);
    let at = outer
        .windows(inner.len())
        .position(|w| w == inner)
        .expect("the stored inner archive");
    let mut headless = outer.clone();
    headless[..at].fill(0);
    damage(&work, &headless, &[]);
    let (_, stdout, stderr) = repair_all(&work.0);
    assert!(stdout.contains("Found  small.bin"), "{stdout}");
    assert!(!stdout.contains("payload.bin"), "{stdout}");
    assert!(!stdout.contains("recovered"), "{stdout}");
    let length = inner.len().to_string();
    assert!(
        stderr
            .lines()
            .any(|line| { line.contains(&format!("offset {at}")) && line.contains(&length) }),
        "no line gives offset {at} and length {length}: {stderr}"
    );
    assert!(!stderr.contains(FOUND_AT), "{stderr}");
    assert!(stderr.contains(UNCHECKED), "{stderr}");
    assert_eq!(work.outputs(), ["rebuilt.damaged.rar"]);
    // The member is the true one: the rebuilt archive tests clean and
    // gives `small.bin` back byte for byte.
    std::fs::create_dir(work.path("out")).unwrap();
    let extracted = Command::new(rarfast())
        .args(["x", "-y", "-idq", "rebuilt.damaged.rar", "out/"])
        .current_dir(&work.0)
        .stdin(Stdio::null())
        .status()
        .unwrap();
    assert!(extracted.success(), "x rebuilt.damaged.rar");
    let again = std::fs::read(work.path("out/small.bin")).unwrap();
    assert!(again == noise(20_000, 0x6f77_6e02), "small.bin");
    assert!(!work.path("out/payload.bin").exists());
}

/// The limit that stays (3.8, the known limit): the same file cut where
/// the stored archive ends. Nothing of the outer stands behind it, so
/// it cannot be told from an archive behind other bytes: the rebuilt
/// file holds the INNER archive's member, as the reference's does, and
/// the line with the offset is what tells the user.
#[test]
fn with_the_head_gone_and_nothing_behind_the_rebuild_says_where_it_began() {
    let (work, inner, outer) = nested("headcut", "-ep", &[]);
    let at = outer
        .windows(inner.len())
        .position(|w| w == inner)
        .expect("the stored inner archive");
    let mut headless = outer[..at + inner.len()].to_vec();
    headless[..at].fill(0);
    damage(&work, &headless, &[]);
    let (code, stdout, stderr) = repair_all(&work.0);
    assert!(stdout.contains("Found  payload.bin"), "{stdout}");
    assert!(!stdout.contains("recovered"), "{stdout}");
    assert!(
        stderr.contains(&format!("{FOUND_AT}{at} of damaged.rar")),
        "{stderr}"
    );
    assert!(stderr.contains(UNCHECKED), "{stderr}");
    assert_eq!(code, 0, "{stdout}");
    assert_eq!(work.outputs(), ["rebuilt.damaged.rar"]);
}

/// Where the named archive's own `RR` header starts and where its data
/// area does: the last record in the file is the named archive's, and
/// every record carries its protected length at 0x22, which is the
/// header's offset (spec L 3.5.1, 3.5.2).
fn own_rr_header(archive: &[u8]) -> (usize, usize) {
    let last = archive
        .windows(4)
        .rposition(|w| w == b"{RB}")
        .expect("a record");
    let protected = u64::from_le_bytes(archive[last + 0x22..last + 0x2a].try_into().unwrap());
    let header = protected as usize;
    let area = archive[header..]
        .windows(4)
        .position(|w| w == b"{RB}")
        .unwrap()
        + header;
    assert!(area - header < 128, "an RR header of {}", area - header);
    (header, area)
}

/// O1b: every byte of the named archive's `RR` header zero, and damage
/// past shard 0: the set is own by shard 0 and the archive is mended;
/// the inner archive's 150 percent record is left alone.
#[test]
fn a_record_whose_header_is_gone_still_mends_the_named_archive() {
    let (work, inner, outer) = nested("o1b", "-rr150", &["-rr1"]);
    let (header, area) = own_rr_header(&outer);
    let mut headless = outer.clone();
    headless[header..area].fill(0);
    damage(&work, &headless, &[(100_000, 0xff)]);
    let (code, stdout) = repair(&work.0);
    assert!(stdout.contains("Data recovery record found\n"), "{stdout}");
    assert!(
        stdout.contains("\n1 blocks are recovered, 0 blocks are relocated\n"),
        "{stdout}"
    );
    assert_eq!(code, 0, "{stdout}");
    let fixed = std::fs::read(work.path("fixed.damaged.rar")).unwrap();
    assert!(fixed[..header] == outer[..header], "the protected bytes");
    assert!(!fixed.starts_with(&inner[..4096]));
}

/// O1c: the `RR` header zero AND one signature bit, so neither the
/// header nor shard 0 says whose the set is. Its distance does: the
/// records begin where that header ended, no more than 40 bytes behind
/// the offset they name, and the archive is mended as the reference
/// mends it; the inner archive's record, further from its own, is left
/// alone. (Before O1c this was `not found`.)
#[test]
fn a_gone_header_and_a_signature_bit_are_own_by_distance() {
    let (work, inner, outer) = nested("o1c", "-rr150", &["-rr1"]);
    let (header, area) = own_rr_header(&outer);
    let mut headless = outer.clone();
    headless[header..area].fill(0);
    damage(&work, &headless, &[SIGNATURE_BIT, (100_000, 0xff)]);
    let (code, stdout) = repair(&work.0);
    assert!(stdout.contains("Data recovery record found\n"), "{stdout}");
    assert!(
        stdout.contains("\n2 blocks are recovered, 0 blocks are relocated\n"),
        "{stdout}"
    );
    assert_eq!(code, 0, "{stdout}");
    assert_eq!(work.outputs(), ["fixed.damaged.rar"]);
    let fixed = std::fs::read(work.path("fixed.damaged.rar")).unwrap();
    assert!(fixed[..header] == outer[..header], "the protected bytes");
    assert!(!fixed.starts_with(&inner[..4096]));
}

#[test]
fn control_an_archive_with_no_inner_archive_repairs_as_before() {
    let (work, whole) = plain("control", &["-rr1"]);
    damage(&work, &whole, &[SIGNATURE_BIT]);
    assert_repaired(&work, &whole, 1);
}

/// The file is mended byte for byte; the run says the main header was
/// corrupt and exits 3 for it, as the reference does.
#[test]
fn a_damaged_main_header_is_searched_past_and_repaired() {
    const SAID: &str = "Main archive header is corrupt\n";
    let (work, whole) = plain("main", &["-rr3"]);
    damage(&work, &whole, &[MAIN_HEADER_BIT]);
    let stderr = assert_repaired_exiting(&work, &whole, 1, 3);
    assert!(stderr.contains(SAID), "{stderr}");

    damage(&work, &whole, &[MAIN_HEADER_BIT, (100_000, 0xff)]);
    std::fs::remove_file(work.path("fixed.damaged.rar")).unwrap();
    let stderr = assert_repaired_exiting(&work, &whole, 2, 3);
    assert!(stderr.contains(SAID), "{stderr}");

    // The same inside an outer archive that carries an inner record.
    let (work, _, outer) = nested("mainnested", "-rr150", &["-rr1"]);
    damage(&work, &outer, &[MAIN_HEADER_BIT]);
    let stderr = assert_repaired_exiting(&work, &outer, 1, 3);
    assert!(stderr.contains(SAID), "{stderr}");
}

/// The search that now runs finds nothing where there is nothing: an
/// archive written without `-rr`, its main header damaged, is refused as
/// it was, and nothing is written.
#[test]
fn control_a_damaged_main_header_and_no_record_writes_nothing() {
    let (work, whole) = plain("mainnone", &[]);
    damage(&work, &whole, &[MAIN_HEADER_BIT]);
    let (code, stdout) = repair(&work.0);
    assert!(
        stdout.contains("Data recovery record not found\n"),
        "{stdout}"
    );
    assert_ne!(code, 0, "{stdout}");
    assert_eq!(work.outputs(), [""; 0]);
}

/// An archive written without `-rr` whose headers are whole is still not
/// searched: straight to `not found`, as the reference does.
#[test]
fn control_a_whole_main_header_without_the_flag_is_not_searched() {
    let (work, whole) = plain("noflag", &[]);
    damage(&work, &whole, &[]);
    let (_, stdout) = repair(&work.0);
    assert!(
        !stdout.contains("Searching for recovery record"),
        "{stdout}"
    );
    assert!(
        stdout.contains("Data recovery record not found\n"),
        "{stdout}"
    );
}

/// CRC32 (IEEE), for a header rewritten by hand.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (crc & 1).wrapping_neg());
        }
    }
    !crc
}

/// O5's other half: a main header that is SOUND and says there is no
/// record ends the search, although every record is there. Measured on
/// the reference (3.5.5, the `noflag` arms): `not found`, and it mends
/// nothing.
#[test]
fn a_sound_main_header_with_the_flag_cleared_is_not_searched() {
    let (work, whole) = plain("cleared", &["-rr3"]);
    // The main header: CRC32 at 8, its size at 12 (one byte here), its
    // type at 13, its header flags at 14, an extra size when they say
    // so, then the archive flags.
    let size = usize::from(whole[12]);
    assert!(size < 0x80 && whole[13] == 1, "a short main header");
    let flags = if whole[14] & 0x01 != 0 { 16 } else { 15 };
    assert!(
        whole[15] < 0x80 && whole[flags] & 0x08 != 0,
        "the record flag"
    );
    let mut cleared = whole.clone();
    cleared[flags] &= !0x08;
    let crc = crc32(&cleared[12..13 + size]);
    cleared[8..12].copy_from_slice(&crc.to_le_bytes());
    damage(&work, &cleared, &[(100_000, 0xff)]);
    let (_, stdout) = repair(&work.0);
    assert!(
        !stdout.contains("Searching for recovery record"),
        "{stdout}"
    );
    assert!(
        stdout.contains("Data recovery record not found\n"),
        "{stdout}"
    );
    assert!(!stdout.contains("data recovered"), "{stdout}");
    assert!(!work.path("fixed.damaged.rar").exists());
}
