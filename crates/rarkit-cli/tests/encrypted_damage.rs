//! A damaged ENCRYPTED member is damage, not a wrong password, wherever a
//! password check record says the password was right.
//!
//! Found on 29 Sep 2026: one flipped
//! ciphertext byte in a `-p` RAR 5 volume set (data encrypted, headers
//! clear) made `rarfast` say `Incorrect password for <name>` and exit 11,
//! where reference `unrar` 7.23 says `<name> - checksum error` and exits 3.
//! The dialect took every encrypted member's failure for its password.
//!
//! Measured against `unrar` 7.23 that day, `t`, `p` and `x`, one volume
//! and several, the byte in the first and in the last fragment, stored and
//! compressed, its stderr read every time:
//!
//! - RAR 5, the member's check record intact and passed: `<name> -
//!   checksum error`, exit 3; `-kb` keeps the file.
//! - No check record, where nothing can tell a wrong password from damage
//!   (the RAR 1.3 to 4.x family; a RAR 5 record with flag 0x0001 clear):
//!   `Checksum error in the encrypted file <name>. Corrupt file or wrong
//!   password.`, exit 3, for a wrong password too, and where a decoder
//!   rather than the checksum found it; `-kb` keeps the file.
//! - RAR 5, the record FAILED (a wrong password): one `Incorrect password
//!   for <name>` for a one-volume archive, `Total errors: 1`, exit 11, no
//!   file even under `-kb`.
//!
//! Out of this file and not done yet: the reference's `<name> : packed
//! data checksum error in volume <vol>` for a non-final fragment, and its
//! one `Incorrect password` per volume of a set.
//!
//! **Fixtures.** RAR 5 archives are written by rarkit's own writer (which
//! writes check records) from a pinned seed ([`SEED`] says why), so nothing
//! need be on PATH; a record-less form is made from them here. RAR 4
//! archives are spec G's `rar` 4.20 vectors.

use std::path::{Path, PathBuf};
use std::process::Command;

const PASSWORD: &str = "-psecret";
const WRONG: &str = "-pwrong";
const MEMBER: &str = "payload.bin";
const PAYLOAD: usize = 300_000;

const CHECKSUM: &str = "- checksum error";
const ENCRYPTED: &str =
    "Checksum error in the encrypted file payload.bin. Corrupt file or wrong password.";
const INCORRECT: &str = "Incorrect password for payload.bin";

/// The set's last volume, whatever its count.
const LAST: usize = usize::MAX;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-encdamage-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Ran {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run(dir: &Path, args: &[&str]) -> Ran {
    let out = Command::new(rarfast())
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    Ran {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Bytes no compressor shrinks, the same every run.
fn payload() -> Vec<u8> {
    let mut state = 0x2545_f491_4f6c_dd1d_u64;
    (0..PAYLOAD)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[5]
        })
        .collect()
}

/// The entropy every damaged row's archive is written with.
///
/// **Why a seed, and why this one.** These
/// archives used to be written by `rarfast a -p`, which draws a fresh salt
/// and IV every run, so the byte [`flip`] changes garbled DIFFERENT
/// ciphertext every run. On about 2 percent of `-m3` draws the garbled block
/// decodes to a match reaching before the start of the stream, which SPEC-H2
/// 3.7 made `DistanceOutOfRange` inside the declared output until 11 Oct
/// 2026 where unrar 7.23 decodes on, and `x -kb` then kept 0 bytes against
/// the reference's 300,000: 4 of 300 runs of this file failed on main, and
/// 6 of 300 fresh archives reproduced it. The rows here are about CHECKSUM damage, so they
/// are written from a seed under which every damaged `-m3` row's flip is
/// checksum damage alone: `[1; 32]`, the first seed tried. Every row below
/// that asserts `-kb` keeps the whole payload is what checks that, so a
/// change to the writer that moves the flip onto a decoder fault fails a
/// row by name rather than going quiet; pick the next seed that passes and
/// say why here. The draw that was a fault is pinned on purpose, by its own seed, in
/// [`a_damaged_rar5_member_whose_match_reaches_before_the_stream_keeps_everything_under_kb`].
const SEED: [u8; 32] = [1; 32];

/// A RAR 5 `-psecret` archive of [`MEMBER`] written by rarkit from `seed`,
/// as `arc.rar` (one volume) or `arc.partN.rar` (a set of at least three,
/// each volume FILE at most 120,000 bytes, as `rarfast a -v120000b` writes
/// them), at `-m<method>`. Answers the volumes in order.
fn rar5(dir: &Path, method: &str, set: bool, seed: [u8; 32]) -> Vec<PathBuf> {
    rar5_floor(dir, method, set, seed, false)
}

/// [`rar5`], with `WriteOptions::level3_floor_lazy` as given:
/// `true` writes level 3 as it was before the floor scan reached it.
fn rar5_floor(
    dir: &Path,
    method: &str,
    set: bool,
    seed: [u8; 32],
    level3_floor_lazy: bool,
) -> Vec<PathBuf> {
    use rarkit::{Entropy, HostOs, MemberSpec, Password, Payload, WriteFormat, WriteMethod};
    let body = payload();
    let mut writer = rarkit::Writer::new(rarkit::WriteOptions {
        format: WriteFormat::Rar5,
        method: match method {
            "0" => WriteMethod::Stored,
            _ => WriteMethod::Compressed {
                level: method.parse().expect("a method digit"),
                dictionary: None,
            },
        },
        password: Some(Password::from(&PASSWORD[2..])),
        volume_file_size: set.then_some(120_000),
        entropy: Entropy::Seeded(seed),
        host_os: HostOs::Unix,
        level3_floor_lazy,
        ..rarkit::WriteOptions::default()
    })
    .expect("options");
    writer
        .add(MemberSpec {
            name: MEMBER.as_bytes(),
            payload: Payload::Bytes(&body),
            mtime: None,
            attributes: 0,
            host_os: HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut volumes: Vec<Vec<u8>> = Vec::new();
    if set {
        writer.finish_volumes(&mut volumes).expect("written");
    } else {
        let mut one = Vec::new();
        writer.finish_into(&mut one).expect("written");
        volumes.push(one);
    }
    if set {
        assert!(volumes.len() >= 3, "a set of {} volumes", volumes.len());
    } else {
        assert_eq!(volumes.len(), 1);
    }
    volumes
        .iter()
        .enumerate()
        .map(|(i, bytes)| {
            let path = if set {
                dir.join(format!("arc.part{}.rar", i + 1))
            } else {
                dir.join("arc.rar")
            };
            std::fs::write(&path, bytes).unwrap();
            path
        })
        .collect()
}

/// Spec G's `rar` 4.20 archives, copied into `dir` under their own names.
fn rar4(dir: &Path, names: &[&str]) -> Vec<PathBuf> {
    let from = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../specs/vectors-G/archives");
    names
        .iter()
        .map(|name| {
            let to = dir.join(name);
            std::fs::copy(from.join(name), &to).unwrap();
            to
        })
        .collect()
}

/// One byte of `path` changed, `at` a fraction of the way in, which in
/// these archives is inside the member's data.
fn flip(path: &Path, at: f64) {
    let mut bytes = std::fs::read(path).unwrap();
    let i = (bytes.len() as f64 * at) as usize;
    bytes[i] ^= 0x40;
    std::fs::write(path, bytes).unwrap();
}

/// What `x -kb` leaves of the member.
#[derive(Clone, Copy, Debug)]
enum Kept {
    /// A file of this many bytes, as the reference keeps it.
    Bytes(u64),
    /// No file.
    Nothing,
    /// Not pinned: what a wrong key's decoder leaves behind is its own.
    Unpinned,
}

/// `t`, `p`, `x` and `x -kb` over `first` with `password`: each exits
/// `code` and says `says` on stderr and nothing of `never`; `x` leaves no
/// file and `x -kb` leaves what `kept` says.
#[allow(clippy::too_many_arguments)]
fn four_ways(
    dir: &Path,
    first: &Path,
    password: &str,
    member: &str,
    code: i32,
    says: &str,
    never: &[&str],
    kept: Kept,
    what: &str,
) {
    let first = first.to_string_lossy().into_owned();
    for command in [&["t"][..], &["p"], &["x", "-o+"], &["x", "-o+", "-kb"]] {
        let out = dir.join("out");
        let _ = std::fs::remove_dir_all(&out);
        std::fs::create_dir_all(&out).unwrap();
        let mut args: Vec<&str> = command.to_vec();
        args.push(password);
        args.push(&first);
        let out_arg = format!("{}/", out.display());
        if command[0] == "x" {
            args.push(&out_arg);
        }
        let ran = run(dir, &args);
        let label = format!("{what}: `{}`", command.join(" "));
        assert_eq!(
            ran.code,
            Some(code),
            "{label} exit; stderr:\n{}",
            ran.stderr
        );
        assert!(
            ran.stderr.contains(says),
            "{label} did not say {says:?}:\n{}",
            ran.stderr
        );
        // Every byte these rows change is in a member's data: a header
        // hit would be a different row.
        for word in never.iter().chain(&["Corrupt header"]) {
            assert!(
                !ran.stderr.contains(word),
                "{label} said {word:?}:\n{}",
                ran.stderr
            );
        }
        if command[0] == "x" {
            let file = std::fs::metadata(out.join(member)).ok().map(|m| m.len());
            let want = match (command.contains(&"-kb"), kept) {
                (false, _) | (true, Kept::Nothing) => Some(None),
                (true, Kept::Bytes(n)) => Some(Some(n)),
                (true, Kept::Unpinned) => None,
            };
            if let Some(want) = want {
                assert_eq!(file, want, "{label} left {file:?}");
            }
        }
    }
}

#[test]
fn a_damaged_rar5_member_whose_record_passed_is_a_checksum_error() {
    for (method, set, volume, at) in [
        ("0", false, 0, 0.5),
        ("3", false, 0, 0.5),
        ("0", true, 0, 0.5),
        ("0", true, LAST, 0.5),
        ("3", true, 0, 0.5),
        ("3", true, LAST, 0.5),
    ] {
        let dir = work(&format!("r5-{method}-{set}-{volume}"));
        let volumes = rar5(&dir, method, set, SEED);
        let volume = volume.min(volumes.len() - 1);
        let what = format!("-m{method} set={set} damage in volume {}", volume + 1);
        flip(&volumes[volume], at);
        four_ways(
            &dir,
            &volumes[0],
            PASSWORD,
            MEMBER,
            3,
            CHECKSUM,
            &["Incorrect password", "encrypted file"],
            Kept::Bytes(PAYLOAD as u64),
            &what,
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The draw the row above was written to avoid, which since 11 Oct 2026
/// behaves as the reference does.
///
/// Under this seed the same flip, half way into volume 1 of the `-m3` set,
/// garbles a block into a match that reaches before the start of the
/// stream. SPEC-H2 3.7 made that `DistanceOutOfRange` inside the declared
/// output, so rarkit's decode stopped there and `x -kb` kept a file of 0
/// bytes, where reference unrar 7.23 decodes on through the garbled match
/// and keeps all 300,000 (measured on two such draws on 29 Sep 2026). Under
/// the amended rule (SPEC-H2 3.5, note 3.5.1 and 3.7) such a match gives zero
/// bytes and is no fault, the decode goes on and the member's checksum
/// decides: so `x -kb` keeps all 300,000 here too, with the messages and
/// the exit of checksum damage, which already agreed.
///
/// That answers the question this row used to leave open (what `-kb`
/// gets when rarkit's decoder faults inside the output where unrar's
/// decodes on): for this fault there is none any more.
///
/// Seed `[6; 32]` is the first of `[k; 32]` for k in 1 to 255 whose flip
/// lands on such a match (6, 21, 101 and 120 do).
///
/// **Written with `level3_floor_lazy` since 30 Sep 2026.** The
/// floor scan writes this payload's blocks at level 3 as literals, where a
/// flipped bit cannot make a match reach before the stream: counted on the
/// floor scan's own branch, NO seed of the 255 lands there any more. The
/// row pins the DECODER on such a match, which the floor scan does not
/// touch, so it keeps the bytes level 3 wrote before it (the option's
/// promise, spec G 3.8.3) and its draw.
#[test]
fn a_damaged_rar5_member_whose_match_reaches_before_the_stream_keeps_everything_under_kb() {
    let dir = work("r5-fault");
    let volumes = rar5_floor(&dir, "3", true, [6; 32], true);
    flip(&volumes[0], 0.5);
    four_ways(
        &dir,
        &volumes[0],
        PASSWORD,
        MEMBER,
        3,
        CHECKSUM,
        &["Incorrect password", "encrypted file"],
        Kept::Bytes(PAYLOAD as u64),
        "-m3 set=true damage in volume 1, a draw whose match reaches before the stream",
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_wrong_password_on_a_rar5_record_is_said_once_and_writes_nothing() {
    let dir = work("r5-wrong");
    let volumes = rar5(&dir, "3", false, SEED);
    four_ways(
        &dir,
        &volumes[0],
        WRONG,
        MEMBER,
        11,
        INCORRECT,
        &[CHECKSUM, "encrypted file", "malformed"],
        Kept::Nothing,
        "wrong password",
    );
    let ran = run(&dir, &["t", WRONG, &volumes[0].to_string_lossy()]);
    assert_eq!(
        ran.stderr.matches("Incorrect password").count(),
        1,
        "{}",
        ran.stderr
    );
    assert!(ran.stdout.contains("Total errors: 1"), "{}", ran.stdout);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn without_a_check_record_damage_and_a_wrong_password_say_the_same() {
    for (method, set, volume) in [
        ("3", false, 0),
        ("0", true, 0),
        ("0", true, LAST),
        ("3", true, LAST),
    ] {
        let dir = work(&format!("nc-{method}-{set}-{volume}"));
        let volumes = rar5(&dir, method, set, SEED);
        let volume = volume.min(volumes.len() - 1);
        let what = format!("record-less -m{method} set={set} volume {}", volume + 1);
        for v in &volumes {
            let stripped = strip_check_records(&std::fs::read(v).unwrap());
            std::fs::write(v, stripped).unwrap();
        }
        // Still an archive, and still the right password.
        let ran = run(&dir, &["t", PASSWORD, &volumes[0].to_string_lossy()]);
        assert_eq!(ran.code, Some(0), "{what} intact:\n{}", ran.stderr);
        // A wrong password on the intact archive: no record to refuse it.
        four_ways(
            &dir,
            &volumes[0],
            WRONG,
            MEMBER,
            3,
            ENCRYPTED,
            &["Incorrect password", CHECKSUM, "malformed"],
            Kept::Unpinned,
            &format!("{what}, wrong password"),
        );
        flip(&volumes[volume], 0.5);
        four_ways(
            &dir,
            &volumes[0],
            PASSWORD,
            MEMBER,
            3,
            ENCRYPTED,
            &["Incorrect password", CHECKSUM, "malformed"],
            Kept::Bytes(PAYLOAD as u64),
            &format!("{what}, damaged"),
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn a_rar4_member_says_the_encrypted_file_sentence() {
    let dir = work("r4");
    let one = rar4(&dir, &["r4_pw.rar"]);
    flip(&one[0], 0.6);
    let stored = rar4(
        &dir,
        &[
            "r4_pwvol.part1.rar",
            "r4_pwvol.part2.rar",
            "r4_pwvol.part3.rar",
        ],
    );
    let compressed = rar4(
        &dir,
        &[
            "r4_pwvolc.part1.rar",
            "r4_pwvolc.part2.rar",
            "r4_pwvolc.part3.rar",
            "r4_pwvolc.part4.rar",
        ],
    );
    let sentence = |name: &str| {
        format!("Checksum error in the encrypted file {name}. Corrupt file or wrong password.")
    };
    let never = ["Incorrect password", CHECKSUM, "malformed"];
    four_ways(
        &dir,
        &one[0],
        "-pSecret",
        "hello.txt",
        3,
        &sentence("hello.txt"),
        &never,
        Kept::Bytes(300),
        "r4_pw damaged",
    );
    // The compressed set with a wrong password: a decoder finds it, and
    // says the same sentence, not the engine's reason.
    four_ways(
        &dir,
        &compressed[0],
        "-pWrong",
        "split.bin",
        3,
        &sentence("split.bin"),
        &never,
        Kept::Unpinned,
        "r4_pwvolc wrong password",
    );
    flip(&stored[2], 0.5);
    four_ways(
        &dir,
        &stored[0],
        "-pSecret",
        "split.bin",
        3,
        &sentence("split.bin"),
        &never,
        Kept::Bytes(12000),
        "r4_pwvol damaged last",
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------
// A RAR 5 archive without check records (as tests/password_verdicts.rs in
// the rarkit crate, which carries the same function and its reasons)
// ---------------------------------------------------------------------

fn read_vint(b: &[u8], mut i: usize) -> (u64, usize) {
    let (mut value, mut shift) = (0u64, 0);
    loop {
        let byte = b[i];
        i += 1;
        value |= u64::from(byte & 0x7F) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return (value, i);
        }
    }
}

fn write_vint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

fn write_vint_len(mut value: u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    for k in 0..len {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        out.push(if k + 1 < len { byte | 0x80 } else { byte });
    }
    assert_eq!(value, 0, "the new size does not fit the old field");
    out
}

/// Every file and service header's check record removed (spec F 3.2.2,
/// spec K 3.7.1): flag 0x0001 cleared, the 12 bytes dropped, sizes and
/// the header CRC32 re-stamped.
fn strip_check_records(archive: &[u8]) -> Vec<u8> {
    const SIGNATURE: usize = 8;
    let mut out = archive[..SIGNATURE].to_vec();
    let mut i = SIGNATURE;
    let mut stripped = 0;
    while i < archive.len() {
        let (size, body_at) = read_vint(archive, i + 4);
        let mut body = archive[body_at..body_at + size as usize].to_vec();
        let (kind, at) = read_vint(&body, 0);
        let (flags, at) = read_vint(&body, at);
        let (mut extra, mut data) = (0u64, 0u64);
        let mut extra_field = at..at;
        let mut at = at;
        if flags & 1 != 0 {
            let (value, next) = read_vint(&body, at);
            extra_field = at..next;
            extra = value;
            at = next;
        }
        if flags & 2 != 0 {
            data = read_vint(&body, at).0;
        }
        if (kind == 2 || kind == 3) && extra > 0 {
            let start = body.len() - extra as usize;
            let mut records = Vec::new();
            let mut r = start;
            while r < body.len() {
                let (len, rec_at) = read_vint(&body, r);
                let end = rec_at + len as usize;
                let (rec_kind, fields) = read_vint(&body, rec_at);
                if rec_kind == 1 {
                    let (version, a) = read_vint(&body, fields);
                    let (rec_flags, b) = read_vint(&body, a);
                    if rec_flags & 1 != 0 {
                        let kept = &body[b..end - 12];
                        let mut rec = write_vint(1);
                        rec.extend(write_vint(version));
                        rec.extend(write_vint(rec_flags & !1));
                        rec.extend_from_slice(kept);
                        records.extend(write_vint(rec.len() as u64));
                        records.extend(rec);
                        stripped += 1;
                        r = end;
                        continue;
                    }
                }
                records.extend_from_slice(&body[r..end]);
                r = end;
            }
            let mut rebuilt = body[..extra_field.start].to_vec();
            rebuilt.extend(write_vint_len(records.len() as u64, extra_field.len()));
            rebuilt.extend_from_slice(&body[extra_field.end..start]);
            rebuilt.extend(records);
            body = rebuilt;
        }
        let mut header = write_vint(body.len() as u64);
        header.extend_from_slice(&body);
        out.extend_from_slice(&rarkit::checksum::crc32(&header).to_le_bytes());
        out.extend(header);
        let end = body_at + size as usize;
        out.extend_from_slice(&archive[end..end + data as usize]);
        i = end + data as usize;
        if kind == 5 {
            out.extend_from_slice(&archive[i..]);
            break;
        }
    }
    assert!(stripped > 0, "no check record to strip");
    out
}
