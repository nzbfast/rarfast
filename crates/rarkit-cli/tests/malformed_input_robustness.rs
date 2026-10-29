//! Security brief 4 of 0.9.0: a malformed RAR 4 or RAR 5 archive never
//! makes `t`, `l`, `v` or `x` panic, abort, run without end or write
//! outside the destination.
//!
//! Every input is made here: `rarfast a` writes a sound archive (RAR 5
//! plain and solid, RAR 4 plain) and the test damages one field at a time,
//! its header checksum redone where the damage would otherwise be caught
//! by the checksum alone. The named cases: the archive cut at every byte
//! of every header and at points in the data; a header size of 0, 1, a
//! byte short, a byte over, far over and an eleven byte vint; an unpacked
//! size and a data size of up to 2^64 - 1; the dictionary and method
//! fields at their largest; a name of length 0, a name length far past the
//! header, and a name 3,000 directories deep; an extra area size past the
//! header; members whose packed data is garbage; and file copy members
//! that refer to themselves and to each other.
//!
//! What each run must show: an exit by status, never by signal; never the
//! code 101 or a panic message; an end inside `BOUND`; a message on
//! standard error whenever the exit is not 0, but for the two quiet exits
//! the reference makes too (no archive, nothing to extract); and under
//! `x`, nothing outside the destination directory. A case whose signature
//! is whole and whose main header is cut or damaged must be called damaged,
//! never no archive (see `fault`).
//!
//! What 471661fda did, every case run whole under `rar` 7.23 beside it on
//! a Mac on 27 Oct 2026 (12,216 runs; the reference measured whole, from
//! outside):
//!
//! | The input | `rar` 7.23 | rarfast at 471661fda |
//! |---|---|---|
//! | the signature whole, the main header cut or its size or extra area wrong | `Unexpected end of archive`, `Corrupt header is found` or `Main archive header is corrupt` on standard error, exit 1 or 3, under `t`, `l`, `v` and `x` | `<archive> is not RAR archive` on standard output alone, exit 10 under `t` and `x` and 0 under `l` and `v` |
//! | a RAR 5 first header size near 2^64, under `l` with a password | `Corrupt header is found`, exit 3 | a debug build panics (`attempt to add with overflow`, exit 101) in the first block sniffer; a release build wraps |
//! | every other case | no panic, signal or hang in either, nothing written outside the destination | the same |
//!
//! Spec F 4 asks for a named error on every such input and SPEC-CLI says
//! nothing of the words, so the reference's run whole settles them. Two
//! forms of that first row were met only by the commit after: the cut
//! right behind the signature (the walk read nothing and met no fault) and
//! a RAR 5 main header size of 2^31 (refused at the open), which rarfast
//! still called nothing to extract, exit 0 under `l` and `v`, and no
//! archive. Both now match `rar` 7.23's exit and first line on standard
//! error under every command (`Unexpected end of archive`, exit 1;
//! `Corrupt header is found`, exit 3).
//!
//! Every run is the rar dialect, `-p-` (or `-pkey` for `l-p`) with standard
//! input closed, under the default memory policy; no archive is over
//! 100 KiB.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// A run that has not ended by then counts as one that never ends.
const BOUND: Duration = Duration::from_secs(60);

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-malformed-{}-{tag}", std::process::id()));
    clear(&dir).unwrap();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Removes `dir` and everything below it, holding one directory open at a
/// time. `std::fs::remove_dir_all` keeps a descriptor open for every level
/// it is inside, and `x` of the name-deep cases leaves a tree some 500
/// levels deep: four lanes in each of seven tests, all in one process,
/// went past a 1,024 open file limit. So each directory is first moved up
/// beside `dir`, and no path grows with the depth either.
fn clear(dir: &Path) -> std::io::Result<()> {
    if std::fs::symlink_metadata(dir).is_err() {
        return Ok(());
    }
    let parent = dir.parent().unwrap();
    let base = dir.file_name().unwrap().to_string_lossy().into_owned();
    let mut moved = 0usize;
    let mut pending = vec![dir.to_path_buf()];
    while let Some(at) = pending.pop() {
        let entries = std::fs::read_dir(&at)?.collect::<std::io::Result<Vec<_>>>()?;
        for entry in entries {
            if entry.file_type()?.is_dir() {
                moved += 1;
                let up = parent.join(format!("{base}.clear{moved}"));
                std::fs::rename(entry.path(), &up)?;
                pending.push(up);
            } else {
                std::fs::remove_file(entry.path())?;
            }
        }
        std::fs::remove_dir(&at)?;
    }
    Ok(())
}

/// Text that compresses, from a seed.
fn text(seed: u32, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9e37_79b9) | 1;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        out.extend_from_slice(format!("w{:02} ", state % 90).as_bytes());
    }
    out.truncate(len);
    out
}

/// Bytes that do not compress, from a seed.
fn noise(seed: u32, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x85eb_ca6b) | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state >> 11) as u8
        })
        .collect()
}

const MEMBERS: [&str; 3] = ["a.txt", "b.txt", "c.bin"];

/// `rarfast a` over the three members with `switches`.
fn archive(tag: &str, switches: &[&str]) -> Vec<u8> {
    let dir = work(&format!("make-{tag}"));
    let src = dir.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join(MEMBERS[0]), text(1, 2_000)).unwrap();
    std::fs::write(src.join(MEMBERS[1]), text(2, 6_000)).unwrap();
    std::fs::write(src.join(MEMBERS[2]), noise(3, 1_500)).unwrap();
    let rar = dir.join("a.rar");
    let mut args = vec!["a", "-idq", "-m3"];
    args.extend_from_slice(switches);
    let rar_text = rar.to_str().unwrap().to_owned();
    args.push(&rar_text);
    args.extend_from_slice(&MEMBERS);
    let out = Command::new(rarfast())
        .current_dir(&src)
        .args(&args)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "building the archive: {out:?}");
    let bytes = std::fs::read(&rar).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    bytes
}

fn vint(bytes: &[u8], mut at: usize) -> (u64, usize) {
    let mut value = 0u64;
    let mut shift = 0;
    loop {
        let byte = bytes[at];
        at += 1;
        if shift < 64 {
            value |= u64::from(byte & 0x7f) << shift;
        }
        shift += 7;
        if byte & 0x80 == 0 {
            return (value, at);
        }
    }
}

/// A committed RAR 4 archive (`fixtures/legacy/archives`).
fn fixture(name: &str) -> Vec<u8> {
    let at = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/legacy/archives")
        .join(name);
    std::fs::read(&at).unwrap_or_else(|e| panic!("{}: {e}", at.display()))
}

fn put_vint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

/// One RAR 5 block: where its header and data lie, and its header taken
/// apart.
#[derive(Clone)]
struct Block5 {
    start: usize,
    end: usize,
    data_end: usize,
    kind: u64,
    flags: u64,
    /// The fields behind the data size, up to the extra area.
    fields: Vec<u8>,
    extra: Vec<u8>,
    data_size: Option<u64>,
}

fn blocks5(bytes: &[u8]) -> Vec<Block5> {
    let mut at = 8;
    let mut out = Vec::new();
    while at + 4 < bytes.len() {
        let (size, body) = vint(bytes, at + 4);
        let end = body + size as usize;
        let (kind, next) = vint(bytes, body);
        let (flags, mut next) = vint(bytes, next);
        let mut extra = 0usize;
        if flags & 1 != 0 {
            let (value, after) = vint(bytes, next);
            extra = value as usize;
            next = after;
        }
        let mut data_size = None;
        if flags & 2 != 0 {
            let (value, after) = vint(bytes, next);
            data_size = Some(value);
            next = after;
        }
        out.push(Block5 {
            start: at,
            end,
            data_end: end + data_size.unwrap_or(0) as usize,
            kind,
            flags,
            fields: bytes[next..end - extra].to_vec(),
            extra: bytes[end - extra..end].to_vec(),
            data_size,
        });
        at = end + data_size.unwrap_or(0) as usize;
    }
    out
}

/// A RAR 5 header body (type to the end of the extra area) from its parts;
/// `extra_size` and `data_size` are written as given, raw.
fn body5(
    kind: u64,
    flags: u64,
    extra_size: &[u8],
    data_size: &[u8],
    fields: &[u8],
    extra: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    put_vint(kind, &mut body);
    put_vint(flags, &mut body);
    body.extend_from_slice(extra_size);
    body.extend_from_slice(data_size);
    body.extend_from_slice(fields);
    body.extend_from_slice(extra);
    body
}

fn vint_bytes(value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    put_vint(value, &mut out);
    out
}

/// `bytes` with `block`'s header replaced by `body` (its size and checksum
/// written for it) and its data by `data`.
fn replaced5(bytes: &[u8], block: &Block5, body: &[u8], data: &[u8]) -> Vec<u8> {
    let mut sized = vint_bytes(body.len() as u64);
    sized.extend_from_slice(body);
    let mut out = bytes[..block.start].to_vec();
    out.extend_from_slice(&crc32(&sized).to_le_bytes());
    out.extend_from_slice(&sized);
    out.extend_from_slice(data);
    out.extend_from_slice(&bytes[block.data_end..]);
    out
}

/// `block`'s header written again from its own parts, with `fields`,
/// `extra` and the data given.
fn rebuilt5(bytes: &[u8], block: &Block5, fields: &[u8], extra: &[u8], data: &[u8]) -> Vec<u8> {
    let mut flags = block.flags & !3;
    let mut extra_size = Vec::new();
    if !extra.is_empty() {
        flags |= 1;
        extra_size = vint_bytes(extra.len() as u64);
    }
    let mut data_size = Vec::new();
    if block.data_size.is_some() {
        flags |= 2;
        data_size = vint_bytes(data.len() as u64);
    }
    let body = body5(block.kind, flags, &extra_size, &data_size, fields, extra);
    replaced5(bytes, block, &body, data)
}

/// A RAR 5 file header's fields, taken apart.
#[derive(Clone)]
struct File5 {
    file_flags: u64,
    unpacked: u64,
    attributes: u64,
    mtime: Option<[u8; 4]>,
    crc: Option<[u8; 4]>,
    compression: u64,
    host: u64,
    name_len: u64,
    name: Vec<u8>,
}

fn file5(fields: &[u8]) -> File5 {
    let (file_flags, at) = vint(fields, 0);
    let (unpacked, at) = vint(fields, at);
    let (attributes, mut at) = vint(fields, at);
    let mut mtime = None;
    if file_flags & 2 != 0 {
        mtime = Some(fields[at..at + 4].try_into().unwrap());
        at += 4;
    }
    let mut crc = None;
    if file_flags & 4 != 0 {
        crc = Some(fields[at..at + 4].try_into().unwrap());
        at += 4;
    }
    let (compression, at) = vint(fields, at);
    let (host, at) = vint(fields, at);
    let (name_len, at) = vint(fields, at);
    File5 {
        file_flags,
        unpacked,
        attributes,
        mtime,
        crc,
        compression,
        host,
        name_len,
        name: fields[at..].to_vec(),
    }
}

impl File5 {
    fn fields(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_vint(self.file_flags, &mut out);
        put_vint(self.unpacked, &mut out);
        put_vint(self.attributes, &mut out);
        if let Some(mtime) = self.mtime {
            out.extend_from_slice(&mtime);
        }
        if let Some(crc) = self.crc {
            out.extend_from_slice(&crc);
        }
        put_vint(self.compression, &mut out);
        put_vint(self.host, &mut out);
        put_vint(self.name_len, &mut out);
        out.extend_from_slice(&self.name);
        out
    }
}

/// A file copy redirection record naming `target`.
fn copy_record(target: &[u8]) -> Vec<u8> {
    let mut record = Vec::new();
    put_vint(5, &mut record);
    put_vint(4, &mut record);
    put_vint(0, &mut record);
    put_vint(target.len() as u64, &mut record);
    record.extend_from_slice(target);
    let mut out = vint_bytes(record.len() as u64);
    out.extend_from_slice(&record);
    out
}

/// Every damaged RAR 5 archive made from `bytes`, named.
fn cases5(tag: &str, bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let blocks = blocks5(bytes);
    // File headers, and service headers (a recovery record's among them),
    // which share their layout.
    let files: Vec<&Block5> = blocks
        .iter()
        .filter(|b| b.kind == 2 || b.kind == 3)
        .collect();
    let mut out = Vec::new();

    // Cut at every byte of the signature and of every header, and at
    // points inside each data area.
    let mut cuts: Vec<usize> = (1..8).collect();
    for block in &blocks {
        cuts.extend(block.start..block.end);
        let data = block.data_end - block.end;
        cuts.extend(
            (1..8)
                .map(|k| block.end + data * k / 8)
                .filter(|&at| at > block.end),
        );
    }
    cuts.push(bytes.len() - 1);
    cuts.sort_unstable();
    cuts.dedup();
    for at in cuts {
        out.push((format!("{tag}-cut-{at}"), bytes[..at].to_vec()));
    }

    // A header size not the header's: the checksum taken over what the
    // size claims, where that lies inside the file.
    for (index, block) in blocks.iter().enumerate() {
        let (real, body) = vint(bytes, block.start + 4);
        let claims: [(&str, Vec<u8>); 9] = [
            ("0", vint_bytes(0)),
            ("1", vint_bytes(1)),
            ("2", vint_bytes(2)),
            ("short", vint_bytes(real - 1)),
            ("over", vint_bytes(real + 1)),
            ("far", vint_bytes(real + 4_096)),
            ("2p31", vint_bytes(1 << 31)),
            ("max", vint_bytes(u64::MAX)),
            ("eleven", {
                let mut v = vec![0x80u8; 10];
                v.push(1);
                v
            }),
        ];
        for (name, size) in claims {
            let claimed = vint(&size, 0).0.min(bytes.len() as u64) as usize;
            let mut sized = size.clone();
            let span_end = (body + claimed).min(bytes.len());
            sized.extend_from_slice(&bytes[body..span_end.max(body)]);
            let mut damaged = bytes[..block.start].to_vec();
            damaged.extend_from_slice(&crc32(&sized).to_le_bytes());
            damaged.extend_from_slice(&size);
            damaged.extend_from_slice(&bytes[body..]);
            out.push((format!("{tag}-hsize-{index}-{name}"), damaged));
        }
    }

    // An extra area size and a data size past anything there is.
    for (index, block) in blocks.iter().enumerate() {
        let data = &bytes[block.end..block.data_end];
        for (name, value) in [("over", block.extra.len() as u64 + 200), ("max", u64::MAX)] {
            let body = body5(
                block.kind,
                block.flags | 1,
                &vint_bytes(value),
                &block.data_size.map(vint_bytes).unwrap_or_default(),
                &block.fields,
                &block.extra,
            );
            out.push((
                format!("{tag}-extra-{index}-{name}"),
                replaced5(bytes, block, &body, data),
            ));
        }
        if block.data_size.is_some() {
            for (name, value) in [
                ("double", bytes.len() as u64 * 2),
                ("2p62", 1 << 62),
                ("max", u64::MAX),
            ] {
                let extra_size = if block.flags & 1 != 0 {
                    vint_bytes(block.extra.len() as u64)
                } else {
                    Vec::new()
                };
                let body = body5(
                    block.kind,
                    block.flags,
                    &extra_size,
                    &vint_bytes(value),
                    &block.fields,
                    &block.extra,
                );
                out.push((
                    format!("{tag}-data-{index}-{name}"),
                    replaced5(bytes, block, &body, data),
                ));
            }
        }
    }

    // The file header's own fields at their limits.
    for (index, block) in files.iter().enumerate() {
        let data = bytes[block.end..block.data_end].to_vec();
        let base = file5(&block.fields);
        let mut variants: Vec<(String, File5)> = Vec::new();
        for (name, value) in [
            ("0", 0),
            ("2p40", 1 << 40),
            ("2p62", 1 << 62),
            ("max", u64::MAX),
        ] {
            let mut f = base.clone();
            f.unpacked = value;
            variants.push((format!("unpacked-{name}"), f));
        }
        let mut f = base.clone();
        f.compression |= (0x1f << 10) | (0x1f << 15);
        variants.push(("dictionary-max".to_owned(), f));
        let mut f = base.clone();
        f.compression = (f.compression & !0x3f) | 0x3f;
        variants.push(("version-max".to_owned(), f));
        let mut f = base.clone();
        f.compression |= 7 << 7;
        variants.push(("method-max".to_owned(), f));
        let mut f = base.clone();
        f.compression = u64::MAX;
        variants.push(("compression-max".to_owned(), f));
        let mut f = base.clone();
        f.name_len = 0;
        f.name.clear();
        variants.push(("name-empty".to_owned(), f));
        let mut f = base.clone();
        f.name_len = 1 << 40;
        variants.push(("name-length-far".to_owned(), f));
        let mut f = base.clone();
        f.name = b"d/".repeat(3_000);
        f.name.extend_from_slice(&base.name);
        f.name_len = f.name.len() as u64;
        variants.push(("name-deep".to_owned(), f));
        for (name, f) in variants {
            out.push((
                format!("{tag}-file-{index}-{name}"),
                rebuilt5(bytes, block, &f.fields(), &block.extra, &data),
            ));
        }
        // Packed data that is garbage under a sound header.
        for seed in 1..=6u32 {
            let garbage = noise(seed * 31, data.len());
            out.push((
                format!("{tag}-garbage-{index}-{seed}"),
                rebuilt5(bytes, block, &block.fields, &block.extra, &garbage),
            ));
        }
        for (name, fill) in [("zero", 0u8), ("ones", 0xff)] {
            out.push((
                format!("{tag}-garbage-{index}-{name}"),
                rebuilt5(
                    bytes,
                    block,
                    &block.fields,
                    &block.extra,
                    &vec![fill; data.len()],
                ),
            ));
        }
    }

    // File copies that refer to themselves, and to each other.
    let copy = |bytes: &[u8], which: usize, target: &str| -> Vec<u8> {
        let block = &blocks5(bytes)
            .into_iter()
            .filter(|b| b.kind == 2)
            .collect::<Vec<_>>()[which];
        let mut extra = block.extra.clone();
        extra.extend_from_slice(&copy_record(target.as_bytes()));
        rebuilt5(bytes, block, &block.fields, &extra, &[])
    };
    out.push((format!("{tag}-copy-self"), copy(bytes, 2, MEMBERS[2])));
    let one = copy(bytes, 1, MEMBERS[2]);
    out.push((format!("{tag}-copy-cycle"), copy(&one, 2, MEMBERS[1])));
    out.push((format!("{tag}-copy-missing"), copy(bytes, 2, "nothing.bin")));
    out
}

/// One RAR 4 block: where its header and data lie.
struct Block4 {
    start: usize,
    end: usize,
    data_end: usize,
    kind: u8,
}

fn blocks4(bytes: &[u8]) -> Vec<Block4> {
    let mut at = 7;
    let mut out = Vec::new();
    while at + 7 <= bytes.len() {
        let kind = bytes[at + 2];
        let flags = u16::from_le_bytes([bytes[at + 3], bytes[at + 4]]);
        let size = u16::from_le_bytes([bytes[at + 5], bytes[at + 6]]) as usize;
        let mut data = 0u64;
        if flags & 0x8000 != 0 || kind == 0x74 {
            data = u64::from(u32::from_le_bytes(
                bytes[at + 7..at + 11].try_into().unwrap(),
            ));
            if kind == 0x74 && flags & 0x100 != 0 {
                data |= u64::from(u32::from_le_bytes(
                    bytes[at + 32..at + 36].try_into().unwrap(),
                )) << 32;
            }
        }
        out.push(Block4 {
            start: at,
            end: at + size,
            data_end: at + size + data as usize,
            kind,
        });
        at += size + data as usize;
    }
    out
}

/// `bytes` with `block`'s header from `head` (the bytes behind the
/// checksum, its size field rewritten to fit) and its data from `data`;
/// the checksum redone.
fn replaced4(bytes: &[u8], block: &Block4, mut head: Vec<u8>, data: &[u8]) -> Vec<u8> {
    let size = (head.len() + 2) as u16;
    head[3..5].copy_from_slice(&size.to_le_bytes());
    let crc = (crc32(&head) & 0xffff) as u16;
    let mut out = bytes[..block.start].to_vec();
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&head);
    out.extend_from_slice(data);
    out.extend_from_slice(&bytes[block.data_end..]);
    out
}

/// Every damaged RAR 4 archive made from `bytes`, named.
fn cases4(tag: &str, bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let blocks = blocks4(bytes);
    let mut out = Vec::new();

    let mut cuts: Vec<usize> = (1..7).collect();
    for block in &blocks {
        cuts.extend(block.start..block.end);
        let data = block.data_end - block.end;
        cuts.extend(
            (1..8)
                .map(|k| block.end + data * k / 8)
                .filter(|&at| at > block.end),
        );
    }
    cuts.push(bytes.len() - 1);
    cuts.sort_unstable();
    cuts.dedup();
    for at in cuts {
        out.push((format!("{tag}-cut-{at}"), bytes[..at].to_vec()));
    }

    // A header size not the header's, the checksum over what it claims.
    for (index, block) in blocks.iter().enumerate() {
        let real = block.end - block.start;
        for (name, size) in [
            ("0", 0usize),
            ("1", 1),
            ("6", 6),
            ("7", 7),
            ("20", 20),
            ("short", real - 1),
            ("over", real + 1),
            ("max", 0xffff),
        ] {
            let mut damaged = bytes.to_vec();
            damaged[block.start + 5..block.start + 7].copy_from_slice(&(size as u16).to_le_bytes());
            let span_end = (block.start + size.max(3)).min(bytes.len());
            let crc = (crc32(&damaged[block.start + 2..span_end]) & 0xffff) as u16;
            damaged[block.start..block.start + 2].copy_from_slice(&crc.to_le_bytes());
            out.push((format!("{tag}-hsize-{index}-{name}"), damaged));
        }
    }

    // File blocks, and service blocks (a recovery record's among them),
    // which share their layout.
    for (index, block) in blocks
        .iter()
        .filter(|b| b.kind == 0x74 || b.kind == 0x7a)
        .enumerate()
    {
        let head = bytes[block.start + 2..block.end].to_vec();
        let data = bytes[block.end..block.data_end].to_vec();
        let flags = u16::from_le_bytes([head[1], head[2]]);
        let large = flags & 0x100 != 0;
        let name_at = if large { 38 } else { 30 };
        let name_len = u16::from_le_bytes([head[24], head[25]]) as usize;
        let mut variants: Vec<(&str, Vec<u8>)> = Vec::new();
        // A packed size far past the file, and an unpacked size of the most
        // the fields hold.
        let mut h = head.clone();
        h[5..9].copy_from_slice(&u32::MAX.to_le_bytes());
        variants.push(("packed-max", h));
        let mut h = head.clone();
        h[9..13].copy_from_slice(&u32::MAX.to_le_bytes());
        variants.push(("unpacked-max", h));
        let mut h = head[..30].to_vec();
        h[1..3].copy_from_slice(&(flags | 0x100).to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes());
        h.extend_from_slice(&u32::MAX.to_le_bytes());
        h.extend_from_slice(&head[name_at..]);
        h[9..13].copy_from_slice(&u32::MAX.to_le_bytes());
        variants.push(("unpacked-high-max", h));
        let mut h = head.clone();
        h[23] = 0x40;
        variants.push(("method-unknown", h));
        let mut h = head.clone();
        h[22] = 0xff;
        variants.push(("version-max", h));
        let mut h = head.clone();
        h[1..3].copy_from_slice(&(flags | 0xe0).to_le_bytes());
        variants.push(("dictionary-directory", h));
        let mut h = head.clone();
        h[1..3].copy_from_slice(&(flags | 0xc0).to_le_bytes());
        variants.push(("dictionary-4m", h));
        let mut h = head.clone();
        h[24..26].copy_from_slice(&0u16.to_le_bytes());
        variants.push(("name-length-0", h));
        let mut h = head.clone();
        h[24..26].copy_from_slice(&u16::MAX.to_le_bytes());
        variants.push(("name-length-max", h));
        let mut h = head[..name_at].to_vec();
        let mut deep = b"d\\".repeat(3_000);
        deep.extend_from_slice(&head[name_at..name_at + name_len]);
        h[24..26].copy_from_slice(&(deep.len() as u16).to_le_bytes());
        h.extend_from_slice(&deep);
        h.extend_from_slice(&head[name_at + name_len..]);
        variants.push(("name-deep", h));
        for (name, h) in variants {
            out.push((
                format!("{tag}-file-{index}-{name}"),
                replaced4(bytes, block, h, &data),
            ));
        }
        for seed in 1..=6u32 {
            let garbage = noise(seed * 37, data.len());
            out.push((
                format!("{tag}-garbage-{index}-{seed}"),
                replaced4(bytes, block, head.clone(), &garbage),
            ));
        }
        for (name, fill) in [("zero", 0u8), ("ones", 0xff)] {
            out.push((
                format!("{tag}-garbage-{index}-{name}"),
                replaced4(bytes, block, head.clone(), &vec![fill; data.len()]),
            ));
        }
    }
    out
}

struct Ran {
    command: &'static str,
    code: Option<i32>,
    stdout: String,
    stderr: String,
    took: Duration,
    escaped: Vec<String>,
    /// Under `x`, whether a top level `d` was made in the destination:
    /// the first level of a name-deep case's member.
    made_d: bool,
}

/// `rarfast <command>` over `rar` in `dir`, its output to files, killed
/// at `BOUND`. Under `x` the destination is `dir/out`, and every name in
/// `dir` beside `out`, `a.rar` and the output files is an escape.
fn run(dir: &Path, command: &'static str) -> Ran {
    let out_dir = dir.join("out");
    // `l-p` is `l` with a password, which reads the first block before the
    // engine does.
    let mut args = match command {
        "l-p" => vec!["l".to_owned(), "-pkey".to_owned()],
        _ => vec![command.to_owned(), "-p-".to_owned()],
    };
    if command == "x" {
        std::fs::create_dir_all(&out_dir).unwrap();
        args.push("-y".to_owned());
    }
    args.push("a.rar".to_owned());
    if command == "x" {
        args.push("out/".to_owned());
    }
    let stdout = std::fs::File::create(dir.join("stdout")).unwrap();
    let stderr = std::fs::File::create(dir.join("stderr")).unwrap();
    let started = Instant::now();
    let mut child = Command::new(rarfast())
        .current_dir(dir)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .unwrap();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if started.elapsed() > BOUND {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    let took = started.elapsed();
    let stdout = String::from_utf8_lossy(&std::fs::read(dir.join("stdout")).unwrap()).into_owned();
    let stderr = String::from_utf8_lossy(&std::fs::read(dir.join("stderr")).unwrap()).into_owned();
    let beside: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| !["out", "a.rar", "stdout", "stderr"].contains(&name.as_str()))
        .collect();
    let made_d = command == "x" && out_dir.join("d").is_dir();
    let mut escaped = Vec::new();
    match command {
        "x" => {
            escaped = beside;
            clear(&out_dir).unwrap();
        }
        // `r` writes its rebuilt archive beside the damaged one.
        "r" => {
            for name in beside {
                let _ = std::fs::remove_file(dir.join(name));
            }
        }
        _ => {}
    }
    Ran {
        command,
        code: match status {
            Some(status) => status.code(),
            None => Some(-1),
        },
        stdout,
        stderr,
        took,
        escaped,
        made_d,
    }
}

/// Whether the run called the file no archive, which the reference says
/// on standard output alone (`rar` 7.23 the same: exit 10 under `t` and
/// `x`, 0 under `l` and `v`, standard error empty).
fn not_an_archive(ran: &Ran) -> bool {
    ran.stdout.contains("is not RAR archive")
}

/// What is wrong with one run, or nothing. `damaged` is a case whose
/// signature is whole and whose main header is cut or damaged: `rar`
/// 7.23 calls it `Unexpected end of archive`, `Corrupt header is found`
/// or `Main archive header is corrupt` on standard error, exit 1 or 3,
/// under every command here, and never no archive.
fn fault(ran: &Ran, damaged: bool) -> Option<String> {
    let read_as_sound = not_an_archive(ran) || ran.code == Some(0) || ran.stderr.trim().is_empty();
    if damaged && ran.code.is_some_and(|code| code != 101) && read_as_sound {
        return Some(format!(
            "a damaged main header read as {}, exit {:?}, standard error {:?}",
            if not_an_archive(ran) {
                "no archive"
            } else {
                "sound"
            },
            ran.code,
            ran.stderr.trim()
        ));
    }
    if ran.took > BOUND {
        return Some(format!("ran past {BOUND:?}"));
    }
    let Some(code) = ran.code else {
        return Some("ended by a signal".to_owned());
    };
    if code == 101 || ran.stderr.contains("panicked") {
        return Some(format!("panicked, exit {code}: {}", ran.stderr.trim_end()));
    }
    // An archive with no member to test or extract is `No files to
    // extract`, exit 10, on standard output alone, as at the reference.
    let nothing = code == 10 && ran.stdout.contains("No files to extract");
    if code != 0 && ran.stderr.trim().is_empty() && !not_an_archive(ran) && !nothing {
        return Some(format!("exit {code} with nothing on standard error"));
    }
    if !ran.escaped.is_empty() {
        return Some(format!("wrote outside the destination: {:?}", ran.escaped));
    }
    None
}

/// Windows: `x` of a name-deep case, 3,000 levels and so past 4,096
/// characters, is refused by name, exit 9 `Cannot create` (FROM-STUDIO
/// 1001), as the system's PATH_MAX refuses it on Linux. Writing it cost
/// minutes there (hosted Windows, run 40663527000: 27 such runs past 60
/// s), and an archive of many could hold a run for hours. A case whose
/// deep name falls on a header that is never written as a file
/// (`rar4rr-file-12` and `rar5rr-file-3`: exit 0 on macOS too, where a
/// written one ends at the path limit, exit 9) makes nothing under it,
/// and passes.
fn deep_refused(name: &str, ran: &Ran) -> Option<String> {
    if !cfg!(windows) || ran.command != "x" || !name.ends_with("-name-deep") {
        return None;
    }
    if ran.code == Some(9) && ran.stderr.contains("Cannot create") {
        return None;
    }
    if ran.code == Some(0) && !ran.made_d {
        return None;
    }
    Some(format!(
        "not refused past 4,096 characters: exit {:?}, standard error {:?}",
        ran.code,
        ran.stderr.trim()
    ))
}

/// Every case under each of `commands`, on four threads; every fault, by
/// case and command. With `RARFAST_MALFORMED_DUMP` set, each case's
/// archive is kept there and each run's exit is written to `exits.tsv`,
/// for a side by side with the reference.
fn sweep(
    tag: &str,
    cases: Vec<(String, Vec<u8>)>,
    damaged: &[String],
    commands: &[&'static str],
) -> Vec<String> {
    let dump = std::env::var_os("RARFAST_MALFORMED_DUMP").map(PathBuf::from);
    let root = work(tag);
    let cases = std::sync::Mutex::new(cases.into_iter());
    let faults = std::sync::Mutex::new(Vec::new());
    let rows = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for lane in 0..4 {
            let (root, cases, faults, rows, dump) = (&root, &cases, &faults, &rows, &dump);
            scope.spawn(move || {
                let dir = root.join(format!("lane{lane}"));
                loop {
                    let Some((name, bytes)) = cases.lock().unwrap().next() else {
                        break;
                    };
                    clear(&dir).unwrap();
                    std::fs::create_dir_all(&dir).unwrap();
                    std::fs::write(dir.join("a.rar"), &bytes).unwrap();
                    if let Some(dump) = dump {
                        std::fs::write(dump.join(format!("{name}.rar")), &bytes).unwrap();
                    }
                    for &command in commands {
                        let ran = run(&dir, command);
                        rows.lock().unwrap().push(format!(
                            "{name}\t{}\t{}\t{}",
                            ran.command,
                            ran.code.map_or("signal".to_owned(), |c| c.to_string()),
                            ran.stderr.lines().next().unwrap_or("")
                        ));
                        let why = fault(&ran, damaged.contains(&name))
                            .or_else(|| deep_refused(&name, &ran));
                        if let Some(why) = why {
                            faults
                                .lock()
                                .unwrap()
                                .push(format!("{name} {command}: {why}"));
                        }
                    }
                }
            });
        }
    });
    if let Some(dump) = dump {
        let mut rows = rows.into_inner().unwrap();
        rows.sort();
        std::fs::write(
            dump.join(format!("exits-{tag}.tsv")),
            rows.join("\n") + "\n",
        )
        .unwrap();
    }
    clear(&root).unwrap();
    let mut faults = faults.into_inner().unwrap();
    faults.sort();
    faults
}

const READS: [&str; 5] = ["t", "l", "l-p", "v", "x"];
/// An archive with a recovery record is also repaired.
const READS_AND_REPAIR: [&str; 6] = ["t", "l", "l-p", "v", "x", "r"];

/// The RAR 5 cases whose signature is whole and whose main header is cut
/// or damaged (see [`fault`]), the cut right behind the signature among
/// them (`Unexpected end of archive`, exit 1, at the reference).
fn damaged5(tag: &str, bytes: &[u8]) -> Vec<String> {
    let main = &blocks5(bytes)[0];
    assert_eq!(main.kind, 1, "the main header comes first");
    let mut out: Vec<String> = (main.start..main.end)
        .map(|at| format!("{tag}-cut-{at}"))
        .collect();
    for size in [
        "0", "1", "2", "short", "over", "far", "2p31", "max", "eleven",
    ] {
        out.push(format!("{tag}-hsize-0-{size}"));
    }
    out.push(format!("{tag}-extra-0-over"));
    out.push(format!("{tag}-extra-0-max"));
    out
}

/// The same for the RAR 1.5 to 4.x container.
fn damaged4(tag: &str, bytes: &[u8]) -> Vec<String> {
    let main = &blocks4(bytes)[0];
    assert_eq!(main.kind, 0x73, "the main header comes first");
    let mut out: Vec<String> = (main.start..main.end)
        .map(|at| format!("{tag}-cut-{at}"))
        .collect();
    for size in ["0", "1", "6", "7", "20", "short", "over", "max"] {
        out.push(format!("{tag}-hsize-0-{size}"));
    }
    out
}

fn check(
    tag: &str,
    bytes: Vec<u8>,
    cases: Vec<(String, Vec<u8>)>,
    damaged: &[String],
    commands: &[&'static str],
) {
    let sound = sweep(
        &format!("{tag}-sound"),
        vec![(format!("{tag}-sound"), bytes)],
        &[],
        commands,
    );
    assert!(sound.is_empty(), "the sound archive: {sound:#?}");
    let faults = sweep(tag, cases, damaged, commands);
    assert!(
        faults.is_empty(),
        "{} faults:\n{}",
        faults.len(),
        faults.join("\n")
    );
}

fn check5(tag: &str, bytes: Vec<u8>, commands: &[&'static str]) {
    let cases = cases5(tag, &bytes);
    let damaged = damaged5(tag, &bytes);
    check(tag, bytes, cases, &damaged, commands);
}

fn check4(tag: &str, bytes: Vec<u8>, commands: &[&'static str]) {
    let cases = cases4(tag, &bytes);
    let damaged = damaged4(tag, &bytes);
    check(tag, bytes, cases, &damaged, commands);
}

#[test]
fn rar5_malformed_archives_end_cleanly() {
    check5("rar5", archive("rar5", &["-ma5"]), &READS);
}

#[test]
fn rar5_solid_malformed_archives_end_cleanly() {
    check5("rar5s", archive("rar5s", &["-ma5", "-s"]), &READS);
}

#[test]
fn rar5_recovery_malformed_archives_end_cleanly() {
    check5(
        "rar5rr",
        archive("rar5rr", &["-ma5", "-rr10%"]),
        &READS_AND_REPAIR,
    );
}

/// RAR 2.9 to 4.x: the LZ and PPMd text of `r420_txt.rar`.
#[test]
fn rar4_malformed_archives_end_cleanly() {
    check4("rar4", fixture("r420_txt.rar"), &READS);
}

/// The RAR 3 filter machine's input: `r420_f_delta.rar`.
#[test]
fn rar4_filter_malformed_archives_end_cleanly() {
    check4("rar4f", fixture("r420_f_delta.rar"), &READS);
}

/// A RAR 4 recovery record: `r420_rr.rar`.
#[test]
fn rar4_recovery_malformed_archives_end_cleanly() {
    check4("rar4rr", fixture("r420_rr.rar"), &READS_AND_REPAIR);
}

/// RAR 1.5 and 2.0 methods: `d155_m3.rar` and `d250_m3.rar`.
#[test]
fn rar15_and_rar20_malformed_archives_end_cleanly() {
    for name in ["d155_m3.rar", "d250_m3.rar"] {
        check4(&name[..4], fixture(name), &READS);
    }
}
