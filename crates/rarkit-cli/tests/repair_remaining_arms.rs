//! `rarfast r` on three shapes the repair of 10 Oct 2026 left open, as
//! decided the same day: a set of recovery records that is the named
//! archive's own by its distance from the offset it names (spec L 3.5.5
//! O1c); the rebuild of an archive whose head is gone while a later
//! header of its own still stands (3.8 B6); and the exit of a repair
//! under enciphered headers (`-hp`).
//!
//! THE BASES are genuine: seven archives written by reference rar 7.23,
//! kept in `tests/repair-remaining-arms/` with the commands that wrote
//! them. Every damaged input is made from one of them in a scratch
//! directory by the change the test names. The expected rows are what
//! rar 7.23 was MEASURED to do on the same inputs (the probe behind spec
//! L 3.5.5 O6 and 3.8, run again on 10 Oct 2026, macOS arm64), and where
//! the rule departs from the reference the test says so.
//!
//! Own by distance. Eight arms the reference mends were refused: the
//! named archive's `RR` header no longer reads (its type changed under
//! a right checksum, its size field wrong, or every byte zero), one bit
//! of the signature is changed, which is damage in shard 0, and 40
//! bytes of data are changed. Neither the header nor the file's first
//! bytes then say whose the set is. Its distance does: an own set's
//! records begin its `RR` header's length behind the offset they name,
//! at most 40 bytes, and a set carried in a stored archive begins at
//! least 51 behind. So the own set is applied and the carried one, in
//! the two bases that hold one, is left alone, also where the stored
//! payload is one letter and most of the carried set's shards fit.
//!
//! The rebuild. With every byte in front of a stored archive zero, the
//! walk begins at the stored archive's signature and ends at its end of
//! archive block. In a file that IS that archive, nothing stands behind
//! that block. Here a sound file header stands at the very next byte,
//! with no signature in front of it: it is a header of the ENCLOSING
//! archive, and the walked archive is a stored member's data. So the
//! rebuild is of the enclosing archive: its later members that still
//! have headers are written, and the stored archive, whose own file
//! header is gone, is left out with one line that gives its offset and
//! its length. It is never given a made-up name. (The reference lists
//! the INNER archive's member alone and copies the later member's bytes
//! behind the end block, where no reader lists them.)
//!
//! The exits, where the archive is mended (the fixed file's bytes up to
//! the recovery record's header are the true ones in every row):
//!
//! | The archive | right password | `-p-`, or a wrong one |
//! |---|---|---|
//! | data changed | 0 | 11 |
//! | and one bit of the signature | 0 | 0 |
//! | and one bit of the archive encryption header | 3 | 3 |
//! | and the enciphered `RR` header changed or zero | 3 | 11 |
//!
//! With no password switch at all the exit is 0, as the reference's is
//! with standard input at its end.
//!
//! With nothing damaged no file is written and the exit is the same
//! table's (11 for want of the password, 0 with it).
//!
//! Where nothing can be mended the reference writes nothing and exits
//! 10. With the right password this tool writes the plain rebuild, with
//! its line that none of the data was checked: a chosen capability.
//!
//! Width and memory: each run is one `rarfast` process on the machine's
//! own pool; the largest archive is 20,840 bytes.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const PLAIN: &[u8] = include_bytes!("repair-remaining-arms/plain.rar");
const HP150: &[u8] = include_bytes!("repair-remaining-arms/hp150.rar");
const HP20: &[u8] = include_bytes!("repair-remaining-arms/hp20.rar");
const OUTER: &[u8] = include_bytes!("repair-remaining-arms/outer150w.rar");
const OUTER_A: &[u8] = include_bytes!("repair-remaining-arms/outerA150w.rar");
const SINGLE: &[u8] = include_bytes!("repair-remaining-arms/inner150.rar");
const SINGLE_A: &[u8] = include_bytes!("repair-remaining-arms/innerA150.rar");

/// The password the two enciphered bases were written with.
const RIGHT: &str = "-pwalk-own";
const NONE: &str = "-p-";
const WRONG: &str = "-pnot-the-password";

const SIGNATURE: &[u8] = b"Rar!\x1a\x07\x01\x00";
const UNCHECKED: &str = "holds the members' data copied as it was found; none of it was checked";
const FOUND_AT: &str = "was found at offset ";

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

struct Work(PathBuf);

impl Work {
    fn new(tag: &str) -> Work {
        let dir = std::env::temp_dir().join(format!("rarfast-arms-{}-{tag}", std::process::id()));
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

struct Ran {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(dir: &Path, args: &[&str]) -> Ran {
    let out = Command::new(rarfast())
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    Ran {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// `rarfast r -y <switches> damaged.rar` over `bytes`, in a fresh
/// directory.
fn repair(tag: &str, bytes: &[u8], switches: &[&str]) -> (Work, Ran) {
    let work = Work::new(tag);
    std::fs::write(work.path("damaged.rar"), bytes).unwrap();
    let mut args = vec!["r", "-y"];
    args.extend_from_slice(switches);
    args.push("damaged.rar");
    let ran = run(&work.0, &args);
    (work, ran)
}

fn find(bytes: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    bytes[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|at| at + from)
}

// Own by distance.

/// A base with clear headers: where its own `RR` service header begins
/// and ends, and where the probe changes 40 bytes of data (100 bytes
/// into `small.bin` in an outer base, 1,000 into `payload.bin` in a
/// single one). The offsets are pinned, the bases being pinned.
struct Clear {
    base: &'static [u8],
    header: usize,
    area: usize,
    data: usize,
}

const CLEAR_OUTER: (usize, usize, usize) = (17_155, 17_178, 16_480);
const CLEAR_SINGLE: (usize, usize, usize) = (6_148, 6_174, 1_074);

fn clear(base: &'static [u8], (header, area, data): (usize, usize, usize)) -> Clear {
    // The last record in the file is the named archive's: it names the
    // header's offset, and the first record naming it stands at `area`.
    let last = base
        .windows(4)
        .rposition(|w| w == b"{RB}")
        .expect("a record");
    let names = |at: usize| u64::from_le_bytes(base[at + 0x22..at + 0x2a].try_into().unwrap());
    assert_eq!(names(last), header as u64);
    assert_eq!(&base[area..area + 4], b"{RB}");
    assert_eq!(names(area), header as u64);
    assert!(area - header <= 40, "O1c's bound");
    Clear {
        base,
        header,
        area,
        data,
    }
}

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

impl Clear {
    /// The probe's arm `<how>+sig+<data>`.
    fn arm(&self, how: &str) -> Vec<u8> {
        let mut bytes = self.base.to_vec();
        match how {
            // The type made 9, the header's checksum made right again.
            "rrtype" => {
                bytes[self.header + 5] = 9;
                let sum = crc32(&bytes[self.header + 4..self.area]);
                bytes[self.header..self.header + 4].copy_from_slice(&sum.to_le_bytes());
            }
            // The size field raised by 1, the checksum left.
            "rrsize" => bytes[self.header + 4] ^= 1,
            "rrzero" => bytes[self.header..self.area].fill(0),
            other => panic!("no arm {other}"),
        }
        bytes[1] ^= 1;
        for byte in &mut bytes[self.data..self.data + 40] {
            *byte ^= 0x5a;
        }
        bytes
    }

    /// The named archive is mended as the reference mends it: `found`,
    /// one `fixed.` file whose bytes up to the `RR` header are the
    /// base's, exit 0; nothing rebuilt and nothing of a carried set.
    fn assert_mended(&self, tag: &str, how: &str) {
        let (work, ran) = repair(&format!("{tag}-{how}"), &self.arm(how), &[]);
        let what = format!("{tag} {how}: {}{}", ran.stdout, ran.stderr);
        assert!(
            ran.stdout.contains("Data recovery record found\n"),
            "{what}"
        );
        assert!(!ran.stdout.contains("not found"), "{what}");
        assert_eq!(work.outputs(), ["fixed.damaged.rar"], "{what}");
        let fixed = std::fs::read(work.path("fixed.damaged.rar")).unwrap();
        assert!(
            fixed.len() >= self.header && fixed[..self.header] == self.base[..self.header],
            "fixed.damaged.rar is not the named archive: {what}"
        );
        assert_eq!(ran.code, 0, "{what}");
    }
}

/// The six arms on an outer of two sets. The carried set has 10 rows to
/// the own set's 3, and over the one-letter payload 5 of its 7 shards
/// fit the named file from byte 0: it stands 100 bytes from the offset
/// it names and is never applied.
#[test]
fn a_gone_header_and_a_signature_bit_are_own_by_distance_in_an_outer_of_two_sets() {
    for (tag, base) in [("outer", OUTER), ("outer-a", OUTER_A)] {
        let outer = clear(base, CLEAR_OUTER);
        // The carried set: the first record in the file names an offset
        // 100 bytes in front of itself.
        let first = find(base, b"{RB}", 0).unwrap();
        let names = u64::from_le_bytes(base[first + 0x22..first + 0x2a].try_into().unwrap());
        assert_eq!(first as u64 - names, 100);
        for how in ["rrtype", "rrsize", "rrzero"] {
            outer.assert_mended(tag, how);
        }
    }
}

/// The two arms on an archive of one set.
#[test]
fn a_zero_header_and_a_signature_bit_are_own_by_distance_in_an_archive_of_one_set() {
    clear(SINGLE, CLEAR_SINGLE).assert_mended("single", "rrzero");
    clear(SINGLE_A, CLEAR_SINGLE).assert_mended("single-a", "rrzero");
}

// The rebuild.

/// Where the stored inner archive begins in `plain.rar` and where the
/// walk from its signature ends: its end of archive block is the 8 bytes
/// in front of the enclosing archive's next file header, the 44 bytes
/// that name `small.bin`. The offsets are pinned, the base being pinned.
const INNER_AT: usize = 68;
const INNER_END: usize = 6220;

fn headless() -> Vec<u8> {
    assert_eq!(find(PLAIN, SIGNATURE, 1), Some(INNER_AT));
    let name = find(PLAIN, b"small.bin", 0).expect("the later member's header");
    assert!((INNER_END..INNER_END + 44).contains(&name), "{name}");
    let mut bytes = PLAIN.to_vec();
    bytes[..INNER_AT].fill(0);
    bytes
}

/// The member names `rarfast lb` gives for `archive`.
fn members(work: &Work, archive: &str) -> Vec<String> {
    let listed = run(&work.0, &["lb", archive]);
    assert_eq!(listed.code, 0, "lb {archive}: {}", listed.stderr);
    listed.stdout.lines().map(str::to_owned).collect()
}

/// Spec L 3.8, the rule of 10 Oct 2026 beside B4: a
/// sound header right behind the walked archive's end block makes the
/// rebuild one of the ENCLOSING archive.
#[test]
fn a_header_behind_the_end_block_makes_the_rebuild_the_enclosing_archives() {
    let (work, ran) = repair("enclosing", &headless(), &[]);
    assert_eq!(work.outputs(), ["rebuilt.damaged.rar"], "{}", ran.stdout);
    assert_eq!(
        members(&work, "rebuilt.damaged.rar"),
        ["small.bin"],
        "the enclosing archive's later member, and never the stored archive's own"
    );
    assert!(!ran.stdout.contains("payload.bin"), "{}", ran.stdout);
    assert!(!ran.stdout.contains("recovered"), "{}", ran.stdout);
    // One line says the stored archive was left out: where it stands and
    // how long it is. Its wording is the specification's to give.
    let length = (INNER_END - INNER_AT).to_string();
    assert!(
        ran.stderr.lines().any(|line| {
            line.contains(&INNER_AT.to_string())
                && line.contains(&length)
                && line.contains("damaged.rar")
        }),
        "no line gives offset {INNER_AT} and length {length}: {}",
        ran.stderr
    );
    assert!(ran.stderr.contains(UNCHECKED), "{}", ran.stderr);
    assert!(!ran.stderr.contains(FOUND_AT), "{}", ran.stderr);
    // A member of the named archive is known to be missing from the
    // file written, so the exit is not a whole archive's. (The
    // reference exits 0 over the inner archive's member; which exit this
    // rebuild gives is this tool's choice until the specification
    // gives one.)
    assert_eq!(ran.code, 3, "{}{}", ran.stdout, ran.stderr);
    // The member written is the true one.
    for (dir, archive) in [("whole", "plain.rar"), ("again", "rebuilt.damaged.rar")] {
        std::fs::create_dir(work.path(dir)).unwrap();
        if archive == "plain.rar" {
            std::fs::write(work.path(archive), PLAIN).unwrap();
        }
        let out = format!("{dir}/");
        let extracted = run(&work.0, &["x", "-y", "-idq", archive, "small.bin", &out]);
        assert_eq!(extracted.code, 0, "x {archive}: {}", extracted.stderr);
    }
    let whole = std::fs::read(work.path("whole/small.bin")).unwrap();
    let again = std::fs::read(work.path("again/small.bin")).unwrap();
    assert_eq!(whole.len(), 700);
    assert!(whole == again, "small.bin of the rebuilt archive");
}

/// The limit that stays: cut where the stored archive ends, the file IS
/// that archive behind other bytes, and no scan can say otherwise. The
/// rebuild holds the inner archive's member, with the line of B4.
#[test]
fn control_nothing_behind_the_end_block_is_an_archive_behind_other_bytes() {
    let mut bytes = headless();
    bytes.truncate(INNER_END);
    let (work, ran) = repair("cut", &bytes, &[]);
    assert_eq!(ran.code, 0, "{}{}", ran.stdout, ran.stderr);
    assert_eq!(work.outputs(), ["rebuilt.damaged.rar"]);
    assert_eq!(members(&work, "rebuilt.damaged.rar"), ["payload.bin"]);
    assert!(
        ran.stderr
            .contains(&format!("{FOUND_AT}{INNER_AT} of damaged.rar")),
        "{}",
        ran.stderr
    );
    assert!(ran.stderr.contains(UNCHECKED), "{}", ran.stderr);
}

/// The other side of the same fact: an archive behind 3,001 bytes that
/// are not its own ends the file with its end block, and is rebuilt
/// whole, as the reference rebuilds it.
#[test]
fn control_an_archive_behind_a_module_is_rebuilt_with_its_own_members() {
    let mut bytes = vec![0x5a; 3001];
    bytes.extend_from_slice(PLAIN);
    let (work, ran) = repair("stub", &bytes, &[]);
    assert_eq!(ran.code, 0, "{}{}", ran.stdout, ran.stderr);
    assert_eq!(work.outputs(), ["rebuilt.damaged.rar"]);
    assert_eq!(
        members(&work, "rebuilt.damaged.rar"),
        ["inner.rar", "small.bin"]
    );
    assert!(
        ran.stderr
            .contains(&format!("{FOUND_AT}3001 of damaged.rar")),
        "{}",
        ran.stderr
    );
}

// The exits under enciphered headers.

/// What a base's own records say: `protected`, the file offset its `RR`
/// header's bytes begin at (spec L 3.5.2, the field at 0x22); `area`,
/// where the records begin; and the records' whole length, rows times
/// span (0x3c and 0x32). Each base holds one set.
struct Own {
    protected: usize,
    area: usize,
    length: usize,
}

fn own(base: &[u8]) -> Own {
    let area = find(base, b"{RB}", 0).expect("a record");
    let field = |at: usize, len: usize| {
        let mut wide = [0u8; 8];
        wide[..len].copy_from_slice(&base[area + at..area + at + len]);
        u64::from_le_bytes(wide) as usize
    };
    let own = Own {
        protected: field(0x22, 8),
        area,
        length: field(0x3c, 2) * field(0x32, 8),
    };
    assert_eq!(own.area - own.protected, 48, "16 and two blocks (O6)");
    own
}

/// The probe's arms, joined with `+`.
fn arm(base: &[u8], parts: &str) -> Vec<u8> {
    let own = own(base);
    let mut bytes = base.to_vec();
    for part in parts.split('+') {
        match part {
            // 40 bytes at half of the protected length.
            "data" => {
                for byte in &mut bytes[own.protected / 2..own.protected / 2 + 40] {
                    *byte ^= 0x5a;
                }
            }
            // One bit of the signature's second byte.
            "sig" => bytes[1] ^= 1,
            // One bit of the archive encryption header's size field.
            "enchdr" => bytes[12] ^= 1,
            // One bit inside the enciphered `RR` header.
            "rrhdr" => bytes[own.protected + 20] ^= 1,
            // Every byte from the `RR` header's first to the records.
            "rrzero" => bytes[own.protected..own.area].fill(0),
            // Every record.
            "rrgone" => bytes[own.area..own.area + own.length].fill(0),
            other => panic!("no arm {other}"),
        }
    }
    bytes
}

/// The run mended the archive and left with `exit`: one `fixed.` file,
/// whose bytes up to the `RR` header are the base's.
fn assert_mended(base: &[u8], parts: &str, password: &str, exit: i32) {
    let tag = format!("{}{parts}{password}", base.len());
    let (work, ran) = repair(&tag, &arm(base, parts), &[password]);
    let what = format!("{parts} {password}: {}{}", ran.stdout, ran.stderr);
    assert!(
        ran.stdout.contains("Data recovery record found\n"),
        "{what}"
    );
    assert_eq!(work.outputs(), ["fixed.damaged.rar"], "{what}");
    let fixed = std::fs::read(work.path("fixed.damaged.rar")).unwrap();
    let protected = own(base).protected;
    assert!(
        fixed.len() >= protected && fixed[..protected] == base[..protected],
        "fixed.damaged.rar is not the named archive: {what}"
    );
    assert_eq!(ran.code, exit, "{what}");
}

#[test]
fn control_the_right_password_and_changed_data_exit_0() {
    assert_mended(HP150, "data", RIGHT, 0);
    assert_mended(HP20, "data", RIGHT, 0);
}

/// With one bit of the signature changed the reference meets no header
/// to ask a password for: 0 whatever the password.
#[test]
fn control_a_signature_bit_exits_0_whatever_the_password() {
    for password in [RIGHT, NONE, WRONG] {
        assert_mended(HP150, "sig+data", password, 0);
        assert_mended(HP150, "rrzero+sig+data", password, 0);
    }
}

/// Mended without the key, and the exit says the password was wanted:
/// 11, as the reference.
#[test]
fn no_password_mends_and_exits_11() {
    for parts in ["data", "rrhdr+data", "rrzero+data"] {
        assert_mended(HP150, parts, NONE, 11);
    }
    assert_mended(HP20, "data", NONE, 11);
}

/// No password switch at all is not `-p-`: the reference, with standard
/// input at its end, mends, names no password and exits 0. (Measured 10
/// Oct 2026, rar 7.23 for macOS, `r a.rar` and `r -y a.rar`.)
#[test]
fn no_password_switch_at_all_mends_and_exits_0() {
    for parts in ["data", "rrhdr+data"] {
        let (work, ran) = repair("noswitch", &arm(HP150, parts), &[]);
        let what = format!("{parts}: {}{}", ran.stdout, ran.stderr);
        assert_eq!(work.outputs(), ["fixed.damaged.rar"], "{what}");
        let fixed = std::fs::read(work.path("fixed.damaged.rar")).unwrap();
        let protected = own(HP150).protected;
        assert!(fixed[..protected] == HP150[..protected], "{what}");
        assert_eq!(ran.code, 0, "{what}");
    }
}

/// A wrong password is no password. (Measured by hand on 10 Oct 2026,
/// rar 7.23 for macOS; not among the probe's kept answers.)
#[test]
fn a_wrong_password_mends_and_exits_11() {
    for parts in ["data", "rrhdr+data"] {
        assert_mended(HP150, parts, WRONG, 11);
    }
}

/// One bit of the archive encryption header: mended, and 3 for the
/// header, with the password and without.
#[test]
fn a_damaged_encryption_header_mends_and_exits_3() {
    for password in [RIGHT, NONE] {
        assert_mended(HP150, "enchdr+data", password, 3);
    }
}

/// With the right password every enciphered header is read, and one
/// that does not read is damage the record does not mend: 3.
#[test]
fn the_right_password_and_a_damaged_enciphered_header_exit_3() {
    for parts in ["rrhdr+data", "rrzero+data"] {
        assert_mended(HP150, parts, RIGHT, 3);
    }
}

/// Nothing damaged at all: the record is found, no file is written, and
/// the exit is still the reference's: 11 for want of the password, 0
/// with it; and 3 with it when the enciphered `RR` header does not read,
/// which no record mends. (A bit of the signature or of the encryption
/// header is not this case: both lie in the protected bytes, are mended,
/// and a file is written; the tests above hold them.)
#[test]
fn with_nothing_to_mend_the_exit_still_answers_for_the_headers() {
    for (parts, password, exit) in [
        ("", RIGHT, 0),
        ("", NONE, 11),
        ("", WRONG, 11),
        ("rrhdr", RIGHT, 3),
        ("rrhdr", NONE, 11),
    ] {
        let bytes = if parts.is_empty() {
            HP150.to_vec()
        } else {
            arm(HP150, parts)
        };
        let (work, ran) = repair("whole", &bytes, &[password]);
        let what = format!("{parts:?} {password}: {}{}", ran.stdout, ran.stderr);
        assert!(
            ran.stdout.contains("Data recovery record found\n"),
            "{what}"
        );
        assert_eq!(work.outputs(), [""; 0], "{what}");
        assert_eq!(ran.code, exit, "{what}");
    }
}

/// Nothing to mend from: every record zero. The reference writes
/// nothing and exits 10. With the right password this tool writes the
/// plain rebuild and says none of the data was checked; it is named
/// `rebuilt`, and no line says recovered. Without the password nothing
/// is written and the exit is not 0.
#[test]
fn control_no_record_left_is_a_rebuild_with_the_password_and_nothing_without() {
    let bytes = arm(HP150, "rrgone+data");
    let (work, ran) = repair("gone-right", &bytes, &[RIGHT]);
    assert_eq!(work.outputs(), ["rebuilt.damaged.rar"], "{}", ran.stdout);
    assert!(ran.stderr.contains(UNCHECKED), "{}", ran.stderr);
    assert!(!ran.stdout.contains("recovered"), "{}", ran.stdout);
    let (work, ran) = repair("gone-none", &bytes, &[NONE]);
    assert_eq!(work.outputs(), [""; 0], "{}", ran.stdout);
    assert_ne!(ran.code, 0, "{}", ran.stdout);
}

/// Two damaged places and one row: not mendable, nothing written, and
/// never exit 0 (the reference: 10).
#[test]
fn control_more_damage_than_rows_writes_nothing() {
    for password in [RIGHT, NONE] {
        let (work, ran) = repair("rows", &arm(HP20, "sig+data"), &[password]);
        assert_eq!(work.outputs(), [""; 0], "{}", ran.stdout);
        assert_ne!(ran.code, 0, "{}", ran.stdout);
    }
}
