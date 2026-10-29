//! A ZERO BYTE member's packed bytes are READ, and the member after it
//! depends on them (SPEC-F 3.6's erratum of 28 Sep 2026, SPEC-H1 3.8 and
//! 4.3, SPEC-H2 3.1).
//!
//! The probe is `specs/vectors-F/zero-byte-member-probe.py`: a genuine
//! solid archive whose zero byte member carries packed bytes, run as written
//! and with those bytes REMOVED (packed size 0) or REPLACED, the header's
//! packed size and checksum rewritten and nothing else touched. A reader
//! that skipped the bytes would pass every variant exactly as it passes the
//! original. Reference unrar 7.23 does not: the zero byte member itself
//! still passes and later members fail their checksums. rarkit must fail
//! where the reference fails, and pass where it passes; these tests pin
//! both, member by member.

use std::sync::Arc;

use rarkit::{Disposition, MemberInfo, MemberOutcome, RangeSource, ReadOptions, Result, Sink};

// ------------------------------------------------------------ reading

/// Every member's name and verdict: `Some(true)` passed its checksum,
/// `Some(false)` failed it, `None` carried none. A read that stopped with an
/// error keeps what it had and names the error.
#[derive(Default)]
struct Verdicts {
    members: Vec<(String, Option<bool>)>,
}

impl Sink for Verdicts {
    type Out = std::io::Sink;
    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<std::io::Sink>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(Disposition::Verify)
    }
    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        _out: Option<std::io::Sink>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.members.push((
            String::from_utf8_lossy(member.name).into_owned(),
            outcome.checksum_ok,
        ));
        Ok(())
    }
}

/// Every member's name and verdict, and the error a read ended with.
type Read = (Vec<(String, Option<bool>)>, Option<String>);

/// The verdicts on one path, and the error the read ended with, if any.
fn verdicts(bytes: &[u8], options: &ReadOptions) -> Read {
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(bytes.to_vec())];
    let mut sink = Verdicts::default();
    let end = rarkit::extract(sources, options, &mut sink, &mut ())
        .err()
        .map(|err| format!("{:?}", err.kind()));
    (sink.members, end)
}

/// Every read path: the decode-ahead on and off, at the engine's default
/// width and at one worker.
fn every_path(bytes: &[u8]) -> Vec<(String, Read)> {
    let mut out = Vec::new();
    for ahead in [true, false] {
        for workers in [None, Some(1)] {
            rarkit::probe::set_ahead_off(!ahead);
            let got = verdicts(bytes, &ReadOptions::default().with_workers(workers));
            rarkit::probe::set_ahead_off(false);
            out.push((format!("ahead {ahead}, workers {workers:?}"), got));
        }
    }
    out
}

/// The members reference `unrar t` fails, or `None` when it is not on the
/// path.
fn unrar_failures(bytes: &[u8], tag: &str) -> Option<Vec<String>> {
    // `std::process::id` in the path: two runs of the suite on one box share
    // `temp_dir`.
    let path = std::env::temp_dir().join(format!(
        "rarkit-zero-byte-packed-{}-{tag}.rar",
        std::process::id()
    ));
    std::fs::write(&path, bytes).ok()?;
    let ran = std::process::Command::new("unrar")
        .arg("t")
        .arg(&path)
        .output();
    let _ = std::fs::remove_file(&path);
    let ran = ran.ok()?;
    let text =
        String::from_utf8_lossy(&ran.stdout).into_owned() + &String::from_utf8_lossy(&ran.stderr);
    let mut failed: Vec<String> = text
        .lines()
        .filter(|line| line.contains(" - checksum error") || line.contains(" - CRC failed"))
        .map(|line| line.split(" - ").next().unwrap_or("").trim().to_string())
        .map(|name| name.rsplit(['/', '\\']).next().unwrap_or("").to_string())
        .collect();
    failed.sort();
    failed.dedup();
    Some(failed)
}

fn legacy(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/legacy/archives")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

// ------------------------------------------------------------ RAR 3

/// `src`, a RAR 1.5 to 4 archive, with member `name`'s packed bytes
/// replaced by `data`: the header's packed size and its CRC16 rewritten,
/// nothing else touched.
fn rar4_replace(src: &[u8], name: &[u8], data: &[u8]) -> Vec<u8> {
    let u16_at = |p: usize| u16::from_le_bytes([src[p], src[p + 1]]) as usize;
    let u32_at = |p: usize| u32::from_le_bytes(src[p..p + 4].try_into().unwrap()) as usize;
    let mut p = src
        .windows(7)
        .position(|w| w == b"Rar!\x1a\x07\x00")
        .expect("a RAR 4 marker");
    while p + 7 <= src.len() {
        let (kind, flags, size) = (src[p + 2], u16_at(p + 3), u16_at(p + 5));
        if kind == 0x74 {
            let packed = u32_at(p + 7);
            let name_len = u16_at(p + 26);
            if &src[p + 32..p + 32 + name_len] == name {
                let mut head = src[p..p + size].to_vec();
                head[7..11].copy_from_slice(&(data.len() as u32).to_le_bytes());
                let crc = (crc32fast::hash(&head[2..]) & 0xffff) as u16;
                head[0..2].copy_from_slice(&crc.to_le_bytes());
                let mut out = src[..p].to_vec();
                out.extend_from_slice(&head);
                out.extend_from_slice(data);
                out.extend_from_slice(&src[p + size + packed..]);
                return out;
            }
            p += size + packed;
        } else {
            p += size
                + if flags & 0x8000 != 0 {
                    u32_at(p + 7)
                } else {
                    0
                };
        }
    }
    panic!("no member {}", String::from_utf8_lossy(name));
}

/// What reference unrar 7.23 was measured to fail on each variant (spec F
/// 3.6's erratum): nothing as written; `ONE.DAT` and `AUDIO.RAW`, and only
/// those, with `EMPTY.DAT`'s two bytes removed or replaced.
const R420_FAILS: &[&str] = &["AUDIO.RAW", "ONE.DAT"];

/// Assert every path's verdicts: the members in `fails` fail their
/// checksum, and every other member that carries one passes it. Where
/// `unrar` is on the path it is asked too, and must still fail exactly
/// `fails`.
fn fails_exactly(label: &str, bytes: &[u8], fails: &[&str]) {
    for (path, (members, _end)) in every_path(bytes) {
        assert!(!members.is_empty(), "{label}: {path}: no member reported");
        for (name, verdict) in &members {
            let leaf = name.rsplit('/').next().unwrap_or(name);
            if fails.contains(&leaf) {
                assert_eq!(*verdict, Some(false), "{label}: {path}: {name} must fail");
            } else if verdict.is_some() {
                assert_eq!(*verdict, Some(true), "{label}: {path}: {name} must pass");
            }
        }
    }
    if let Some(reference) = unrar_failures(bytes, &label.replace(' ', "_")) {
        let mut want: Vec<String> = fails.iter().map(|s| s.to_string()).collect();
        want.sort();
        assert_eq!(
            reference, want,
            "{label}: unrar 7.23 no longer fails what it did"
        );
    } else {
        eprintln!("    unrar is not on the path; {label} checked on rarkit's side only");
    }
}

/// RAR 3: `r420_solid.rar` (rar 4.20), whose `EMPTY.DAT` carries 2 packed
/// bytes, `ff 88`: main symbol 256 with "new member, tables not kept" under
/// the tables `TABLE.BIN` left (spec H1 3.8). With them removed, `ONE.DAT`
/// decodes under `TABLE.BIN`'s tables instead of reading its own; with them
/// replaced, `finish_member` meets a symbol that is not 256 and answers
/// `TrailingData`, which fails the member after it and NOT `EMPTY.DAT`
/// itself, whose outcome is its checksum's against zero bytes.
#[test]
fn rar3_a_zero_byte_members_packed_bytes_are_read() {
    let src = legacy("r420_solid.rar");
    fails_exactly("r420_solid as written", &src, &[]);
    for (label, data) in [
        ("r420_solid EMPTY.DAT removed", &b""[..]),
        ("r420_solid EMPTY.DAT 00 00", &b"\0\0"[..]),
        ("r420_solid EMPTY.DAT 7f 7f", &b"\x7f\x7f"[..]),
    ] {
        fails_exactly(label, &rar4_replace(&src, b"EMPTY.DAT", data), R420_FAILS);
    }
}

// ------------------------------------------------------------ RAR 5

fn read_vint(b: &[u8], mut p: usize) -> (u64, usize) {
    let (mut value, mut shift) = (0u64, 0);
    loop {
        let c = b[p];
        p += 1;
        value |= u64::from(c & 0x7f) << shift;
        shift += 7;
        if c & 0x80 == 0 {
            return (value, p);
        }
    }
}

fn write_vint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let c = (value & 0x7f) as u8;
        value >>= 7;
        out.push(c | if value != 0 { 0x80 } else { 0 });
        if value == 0 {
            return;
        }
    }
}

/// Every file header of a RAR 5 archive: `(header start, header end,
/// data size, name)`.
fn rar5_members(b: &[u8]) -> Vec<(usize, usize, usize, Vec<u8>)> {
    let mut out = Vec::new();
    let mut p = 8;
    while p < b.len() {
        let (size, q) = read_vint(b, p + 4);
        let end = q + size as usize;
        let (kind, r) = read_vint(b, q);
        let (flags, mut r) = read_vint(b, r);
        if flags & 1 != 0 {
            r = read_vint(b, r).1;
        }
        let mut data = 0;
        if flags & 2 != 0 {
            let (d, next) = read_vint(b, r);
            data = d as usize;
            r = next;
        }
        if kind == 5 {
            break;
        }
        if kind == 2 {
            let (file_flags, mut r) = read_vint(b, r);
            r = read_vint(b, r).1; // unpacked size
            r = read_vint(b, r).1; // attributes
            r += if file_flags & 2 != 0 { 4 } else { 0 };
            r += if file_flags & 4 != 0 { 4 } else { 0 };
            r = read_vint(b, r).1; // compression information
            r = read_vint(b, r).1; // host os
            let (name_len, r) = read_vint(b, r);
            out.push((p, end, data, b[r..r + name_len as usize].to_vec()));
        }
        p = end + data;
    }
    out
}

/// `src` with member `name`'s packed bytes replaced by `data`: the data
/// size and the header CRC32 rewritten, nothing else touched.
fn rar5_replace(src: &[u8], name: &[u8], data: &[u8]) -> Vec<u8> {
    let (p, end, size, _) = rar5_members(src)
        .into_iter()
        .find(|m| m.3 == name)
        .expect("the member");
    let q = read_vint(src, p + 4).1;
    let (kind, r) = read_vint(src, q);
    let (flags, mut r) = read_vint(src, r);
    let mut head = Vec::new();
    write_vint(&mut head, kind);
    write_vint(&mut head, flags);
    if flags & 1 != 0 {
        let (extra, next) = read_vint(src, r);
        write_vint(&mut head, extra);
        r = next;
    }
    r = read_vint(src, r).1;
    write_vint(&mut head, data.len() as u64);
    head.extend_from_slice(&src[r..end]);
    let mut sized = Vec::new();
    write_vint(&mut sized, head.len() as u64);
    sized.extend_from_slice(&head);
    let mut out = src[..p].to_vec();
    out.extend_from_slice(&crc32fast::hash(&sized).to_le_bytes());
    out.extend_from_slice(&sized);
    out.extend_from_slice(data);
    out.extend_from_slice(&src[end + size..]);
    out
}

/// The probe's RAR 5 archive, by reference `rar` at `-ma5 -m3 -s`, or
/// `None` when it is not on the path: one 4,096 byte text file, sixteen
/// empty ones and one 13 byte one. rar orders a solid archive by extension,
/// so the sixteen empty `.dat` members are stream indices 0 to 15.
fn probe_archive() -> Option<Vec<u8>> {
    let dir = std::env::temp_dir().join(format!("rarkit-zero-byte-probe-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).ok()?;
    let mut names = vec!["a00.txt".to_string()];
    std::fs::write(dir.join("a00.txt"), rarkit_testdata::chatter(1, 4_096)).ok()?;
    for index in 0..16 {
        let name = format!("e{index:02}.dat");
        std::fs::write(dir.join(&name), b"").ok()?;
        names.push(name);
    }
    std::fs::write(dir.join("z99.txt"), rarkit_testdata::chatter(2, 13)).ok()?;
    names.push("z99.txt".to_string());
    let ran = std::process::Command::new("rar")
        .current_dir(&dir)
        .args(["a", "-ma5", "-m3", "-s", "-ep", "-idq", "-y", "probe.rar"])
        .args(&names)
        .output();
    let archive = match ran {
        Ok(out) if out.status.success() => std::fs::read(dir.join("probe.rar")).ok(),
        _ => None,
    };
    let _ = std::fs::remove_dir_all(&dir);
    archive
}

/// RAR 5: the empty members at stream indices 0 and 15 each carry one table
/// carrying block (spec H2 3.1). With index 15's bytes removed both text
/// members after it fail; with index 0's removed every member passes,
/// because index 15 brings a fresh table set before any member with bytes
/// decodes under index 0's. Skipped when reference `rar` is not on the
/// path, since only it writes the shape; `rar5_zero_byte_member_tables.rs`
/// holds the positive half on a hand built chain.
#[test]
fn rar5_a_zero_byte_members_table_block_is_read() {
    let Some(src) = probe_archive() else {
        eprintln!("    reference `rar` is not on the path; skipped");
        return;
    };
    let order = rar5_members(&src);
    let carriers: Vec<(usize, Vec<u8>)> = order
        .iter()
        .enumerate()
        .filter(|(_, m)| m.3.ends_with(b".dat") && m.2 > 0)
        .map(|(index, m)| (index, m.3.clone()))
        .collect();
    let indices: Vec<usize> = carriers.iter().map(|c| c.0).collect();
    if indices != [0, 15] {
        eprintln!(
            "    this `rar` gave the empty members at {indices:?} a block, not 0 and 15; skipped"
        );
        return;
    }
    let texts: Vec<String> = order[16..]
        .iter()
        .map(|m| String::from_utf8_lossy(&m.3).into_owned())
        .collect();
    assert_eq!(
        texts,
        ["a00.txt", "z99.txt"],
        "both text members follow the empty ones"
    );
    fails_exactly("r5 as written", &src, &[]);
    fails_exactly(
        "r5 index 15 removed",
        &rar5_replace(&src, &carriers[1].1, b""),
        &["a00.txt", "z99.txt"],
    );
    fails_exactly(
        "r5 index 0 removed",
        &rar5_replace(&src, &carriers[0].1, b""),
        &[],
    );
}
