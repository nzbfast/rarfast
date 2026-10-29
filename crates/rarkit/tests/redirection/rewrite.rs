//! Rewrites one RAR 5 file header's extra area and recomputes its header
//! checksum, for the rows of spec F 3.2.6.2 that no genuine Linux writer
//! produces (spec F 3.8.9 asks for that tool to be written here).
//!
//! Built from spec F 3.2.1 (the vint), 3.2.2 (block framing, and a header
//! CRC32 over every byte after its own field), 3.2.6 (the file header's
//! fields) and 3.2.10 (extra records) alone. Shared by the engine's tests
//! and the command line's, which include this file by path.

#![allow(dead_code)]

/// CRC32, the IEEE polynomial, bit by bit: a few hundred header bytes a
/// test, so no table.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

pub fn vint_read(buf: &[u8], at: &mut usize) -> u64 {
    let mut value = 0u64;
    let mut shift = 0;
    loop {
        let byte = buf[*at];
        *at += 1;
        value |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            return value;
        }
        shift += 7;
    }
}

pub fn vint(mut value: u64) -> Vec<u8> {
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

/// One extra record: its type and its body.
pub type Record = (u64, Vec<u8>);

/// The records of an extra area, in order.
pub fn records(extra: &[u8]) -> Vec<Record> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < extra.len() {
        let size = vint_read(extra, &mut at) as usize;
        let end = at + size;
        let mut inner = at;
        let kind = vint_read(extra, &mut inner);
        out.push((kind, extra[inner..end].to_vec()));
        at = end;
    }
    out
}

/// An extra area of `records`, each framed by its size and type.
pub fn area(records: &[Record]) -> Vec<u8> {
    let mut out = Vec::new();
    for (kind, body) in records {
        let mut record = vint(*kind);
        record.extend_from_slice(body);
        out.extend(vint(record.len() as u64));
        out.extend(record);
    }
    out
}

/// A redirection record's body (spec F 3.2.6.2).
pub fn redirect(kind: u64, flags: u64, target: &[u8]) -> Vec<u8> {
    let mut body = vint(kind);
    body.extend(vint(flags));
    body.extend(vint(target.len() as u64));
    body.extend_from_slice(target);
    body
}

/// `archive` with the file header named `name` given the extra area
/// `edit` makes of its own, framed and checksummed afresh.
pub fn rewrite(
    archive: &[u8],
    name: &str,
    edit: impl FnOnce(Vec<Record>) -> Vec<Record>,
) -> Vec<u8> {
    rewrite_with_flags(archive, name, 0, edit)
}

/// [`rewrite`], also setting `set_flags` in the file flags word (spec F
/// 3.2.6): 0x0001 is the directory flag, which the Windows writer sets on a
/// directory link and a junction.
pub fn rewrite_with_flags(
    archive: &[u8],
    name: &str,
    set_flags: u64,
    edit: impl FnOnce(Vec<Record>) -> Vec<Record>,
) -> Vec<u8> {
    assert_eq!(&archive[..8], b"Rar!\x1a\x07\x01\x00", "a RAR 5 archive");
    let mut pos = 8;
    loop {
        let mut at = pos + 4;
        let size = vint_read(archive, &mut at) as usize;
        let body_start = at;
        let body_end = body_start + size;
        let body = &archive[body_start..body_end];
        let mut b = 0;
        let kind = vint_read(body, &mut b);
        let flags = vint_read(body, &mut b);
        let extra_size = if flags & 1 != 0 {
            vint_read(body, &mut b) as usize
        } else {
            0
        };
        let data_size = if flags & 2 != 0 {
            vint_read(body, &mut b)
        } else {
            0
        };
        let fields = b;
        assert!(kind != 5, "no file header named {name}");
        if kind == 2 {
            let mut f = fields;
            let fflags = vint_read(body, &mut f);
            vint_read(body, &mut f); // unpacked size
            vint_read(body, &mut f); // attributes
            if fflags & 2 != 0 {
                f += 4;
            }
            if fflags & 4 != 0 {
                f += 4;
            }
            vint_read(body, &mut f); // compression
            vint_read(body, &mut f); // host
            let len = vint_read(body, &mut f) as usize;
            if &body[f..f + len] == name.as_bytes() {
                let rest = &body[fields..size - extra_size];
                let mut r = 0;
                let old_flags = vint_read(rest, &mut r);
                let mut rest_new = vint(old_flags | set_flags);
                rest_new.extend_from_slice(&rest[r..]);
                let rest = rest_new.as_slice();
                let extra = area(&edit(records(&body[size - extra_size..])));
                let mut new = vint(kind);
                new.extend(vint(flags | 1));
                new.extend(vint(extra.len() as u64));
                if flags & 2 != 0 {
                    new.extend(vint(data_size));
                }
                new.extend_from_slice(rest);
                new.extend(extra);
                let mut framed = vint(new.len() as u64);
                framed.extend(new);
                let mut out = archive[..pos].to_vec();
                out.extend(crc32(&framed).to_le_bytes());
                out.extend(framed);
                out.extend_from_slice(&archive[body_end..]);
                return out;
            }
        }
        pos = body_end + data_size as usize;
    }
}

/// `archive` with the redirection record of `name` replaced by `body`.
pub fn with_redirect(archive: &[u8], name: &str, body: Vec<u8>) -> Vec<u8> {
    rewrite(archive, name, |records| {
        assert!(
            records.iter().any(|r| r.0 == 5),
            "{name} carries a redirection record"
        );
        records
            .into_iter()
            .map(|(kind, old)| {
                if kind == 5 {
                    (5, body.clone())
                } else {
                    (kind, old)
                }
            })
            .collect()
    })
}
