//! Spec L 3.5.1: the protected region of a RAR 5 inline recovery record is
//! the FILE from byte 0 up to the `RR` service header, so bytes that
//! precede the signature (a self-extracting module, or anything else) are
//! protected too and `P` counts them, while the locator stays measured
//! from the byte after the signature.
//!
//! Two arms. The first needs no reference program: it puts 3,001 bytes
//! before the committed genuine `rr5_small.rar` and gives the file a
//! record in the form 3.5.1 states (`P` equal to the `RR` header's file
//! offset, the table over the file's bytes from byte 0). The second makes
//! the archive the section's own probe makes, with reference `rar rr5`,
//! and is skipped, saying so, where no reference answers.
//!
//! Threads and memory: every call here runs under a policy of at most 4
//! workers and a 16 MiB repair limit; the largest file is 46 KiB.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use rarkit::memory::MemoryPolicy;
use rarkit::{Archive, ErrorKind, ReadOptions, SplitCheck, Unsupported};

const SIGNATURE: &[u8; 8] = b"Rar!\x1a\x07\x01\x00";
const STUB: usize = 3_001;
/// `rr5_small.rar`: its `RR` header's offset, which is its `P`.
const SMALL_PROTECTED: usize = 40_218;

fn vector(name: &str) -> Vec<u8> {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../specs/vectors-L");
    std::fs::read(format!("{dir}/{name}")).expect("spec L vector")
}

fn policy() -> MemoryPolicy {
    MemoryPolicy {
        repair_limit: 16 << 20,
        max_workers: 4,
        ..MemoryPolicy::from_limit(64 << 20)
    }
}

fn options(sfx_scan: u64) -> ReadOptions {
    ReadOptions::default()
        .with_password(None)
        .with_memory(policy())
        .with_sfx_scan(sfx_scan)
        .with_split_check(SplitCheck::Streaming)
        .with_tolerant_tail(false)
        .with_cancel(None)
        .with_workers(None)
        .with_sink_is_file(None)
}

/// Bytes that are not an archive and hold no signature: a fixed
/// multiplicative sequence, so the file is the same on every run.
fn stub() -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let bytes: Vec<u8> = (0..STUB)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 56) as u8
        })
        .collect();
    assert!(!bytes.windows(4).any(|w| w == b"Rar!" || w == b"{RB}"));
    bytes
}

fn vint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let low = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(low);
            return out;
        }
        out.push(low | 0x80);
    }
}

/// The `RR` service header as the reference writes it (spec G 3.11):
/// header flags 0x0007, no CRC32 field, unpacked size equal to the data
/// size, one extra record of type 7 holding the percentage.
fn rr_header(data: u64, percent: u8) -> Vec<u8> {
    let mut body = vec![0x03, 0x07, 0x03];
    body.extend(vint(data));
    body.push(0x00);
    body.extend(vint(data));
    body.extend([
        0x00, 0x80, 0x00, 0x01, 0x02, b'R', b'R', 0x02, 0x07, percent,
    ]);
    let mut sized = vint(body.len() as u64);
    sized.extend(body);
    let mut head = rarkit::checksum::crc32(&sized).to_le_bytes().to_vec();
    head.extend(sized);
    head
}

/// The stub, then the genuine archive's protected bytes, then a record
/// over ALL of those bytes at 5 percent, then the genuine end header.
fn stubbed_small() -> Vec<u8> {
    let genuine = vector("rr5_small.rar");
    let mut file = stub();
    file.extend(&genuine[..SMALL_PROTECTED]);
    let record = rarkit::internals::recovery::rr5_encode(&file, 5).expect("a record over the file");
    file.extend(rr_header(record.len() as u64, 5));
    file.extend(record);
    file.extend(&genuine[genuine.len() - 8..]);
    file
}

fn repaired(volume: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    rarkit::recovery::repair_inline(&volume.to_vec(), &options(0), &mut out).expect("a repair");
    out
}

fn flip(volume: &mut [u8], at: usize, len: usize) {
    for byte in &mut volume[at..at + len] {
        *byte ^= 0x77;
    }
}

#[test]
fn the_record_behind_a_stub_counts_the_stub_in_its_protected_length() {
    let file = stubbed_small();
    let check = rarkit::recovery::check_inline(&file, &options(0)).expect("the record is found");
    // P is the `RR` header's FILE offset, not its distance from the
    // signature: 3,001 + 40,218 bytes in 43 shards of 1,006.
    assert_eq!(check.protected, (STUB + SMALL_PROTECTED) as u64);
    assert_eq!((check.shards, check.shard_len), (43, 1_006));
    assert!(check
        .groups
        .iter()
        .all(|g| g.rows == 2 && g.damaged.is_empty()));
    // The locator is still the genuine one, measured from the byte after
    // the signature (40,210), and it still names the `RR` header.
    let sig = STUB + SIGNATURE.len();
    assert_eq!(&file[STUB..sig], SIGNATURE);
    assert_eq!(&file[sig + 40_210 + 18..][..2], b"RR");
}

#[test]
fn damage_in_the_stub_is_mended() {
    let whole = stubbed_small();
    let mut damaged = whole.clone();
    flip(&mut damaged, 100, 30);
    let check = rarkit::recovery::check_inline(&damaged, &options(0)).expect("found");
    assert_eq!(
        check.groups[0].damaged,
        vec![0],
        "shard 0 starts at file byte 0"
    );
    assert_eq!(repaired(&damaged), whole);
}

#[test]
fn damage_in_the_archive_behind_the_stub_is_mended() {
    let whole = stubbed_small();
    let mut damaged = whole.clone();
    // 5,000 bytes past the signature: file byte 8,001, shard 7 from byte 0
    // (it would be shard 4 were the shards cut from the signature).
    flip(&mut damaged, STUB + 5_000, 30);
    let check = rarkit::recovery::check_inline(&damaged, &options(0)).expect("found");
    assert_eq!(check.groups[0].damaged, vec![7]);
    assert_eq!(repaired(&damaged), whole);
    // Two damaged shards, one of them the stub's, are the two rows' limit.
    flip(&mut damaged, 100, 30);
    assert_eq!(repaired(&damaged), whole);
}

/// rarkit's writer never has bytes before the signature: it writes no
/// stub and carries none (spec G section 1), so a record it writes is
/// over the file from byte 0 by construction. Asked to add a record to an
/// archive that sits behind a stub, it refuses by name and writes nothing.
#[test]
fn adding_a_record_behind_a_stub_is_refused_by_name() {
    let genuine = vector("rr5_small.rar");
    let mut file = stub();
    file.extend(&genuine);
    let src = Archive::open(Arc::new(file), &options(1 << 20)).expect("opens behind the stub");
    let mut out = Vec::new();
    let error = rarkit::edit::set_recovery(&src, Some(5), &mut out).expect_err("refused");
    assert!(
        matches!(
            error.kind(),
            ErrorKind::Unsupported(Unsupported::WriteFeature(_))
        ),
        "{error:?}"
    );
    assert!(out.is_empty(), "bytes were written before the refusal");
}

/// A reference binary: a path named in the environment, then `PATH`, then
/// two usual install places.
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

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarkit-rr-stub-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// The section's probe, both ways round: a record reference `rar rr5`
/// adds behind a stub is one rarkit repairs from, stub included; and the
/// file the first arm builds is one reference `rar r` repairs from.
#[test]
fn the_reference_and_rarkit_agree_on_a_record_behind_a_stub() {
    let Some(rar) = reference("rar", "RARKIT_REF_RAR") else {
        eprintln!("skipped: no reference rar");
        return;
    };
    let dir = scratch("agree");
    let run = |args: &[&str]| {
        Command::new(&rar)
            .args(args)
            .current_dir(&dir)
            .output()
            .expect("the reference runs")
    };

    // A genuine archive with no record, a stub put before it, and then the
    // reference asked to add the record.
    std::fs::write(dir.join("hello.txt"), vector("in/hello.txt")).unwrap();
    std::fs::write(dir.join("data.bin"), vector("in/data.bin")).unwrap();
    let made = run(&[
        "a",
        "-ma5",
        "-m0",
        "-idq",
        "plain.rar",
        "hello.txt",
        "data.bin",
    ]);
    assert!(made.status.success(), "{made:?}");
    let mut file = stub();
    file.extend(std::fs::read(dir.join("plain.rar")).unwrap());
    std::fs::write(dir.join("x.rar"), &file).unwrap();
    let added = run(&["rr5", "-idq", "x.rar"]);
    assert!(added.status.success(), "{added:?}");
    let whole = std::fs::read(dir.join("x.rar")).unwrap();

    let check = rarkit::recovery::check_inline(&whole, &options(0)).expect("the genuine record");
    let rr_at = whole
        .windows(4)
        .position(|w| w == b"{RB}")
        .expect("a record")
        - 23;
    assert_eq!(
        check.protected, rr_at as u64,
        "P is the header's file offset"
    );
    assert!(check.groups.iter().all(|g| g.damaged.is_empty()));
    for at in [100, STUB + 5_000] {
        let mut damaged = whole.clone();
        flip(&mut damaged, at, 30);
        assert_eq!(repaired(&damaged), whole, "damage at file byte {at}");
    }

    // The other way: the reference repairs the first arm's file, whose
    // record this crate's encoder computed over the file from byte 0.
    let ours = stubbed_small();
    for at in [100, STUB + 5_000] {
        let mut damaged = ours.clone();
        flip(&mut damaged, at, 30);
        let _ = std::fs::remove_file(dir.join("fixed.y.rar"));
        std::fs::write(dir.join("y.rar"), &damaged).unwrap();
        let mended = run(&["r", "-y", "y.rar"]);
        let fixed = std::fs::read(dir.join("fixed.y.rar"))
            .unwrap_or_else(|_| panic!("no fixed file for damage at {at}: {mended:?}"));
        assert_eq!(
            fixed[..STUB + SMALL_PROTECTED],
            ours[..STUB + SMALL_PROTECTED]
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
