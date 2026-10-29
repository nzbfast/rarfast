//! Test and bench support for spec I: the smallest RAR 4 family header walk
//! that finds a compressed member's packed bytes, until spec F's real
//! walker exists. Written from `SPEC-API-rarkit.md` and RARLAB's public
//! `technote.txt` header layout; it handles exactly what the spec I vectors
//! contain (no encryption, no comment, no header-encrypted set).
#![allow(dead_code)]

use std::ops::Range;

/// One file member of one RAR 4 volume.
#[derive(Debug, Clone)]
pub struct Frag4 {
    pub name: Vec<u8>,
    pub unpacked: u64,
    pub crc32: u32,
    /// 0x30 stored to 0x35 best.
    pub method: u8,
    /// The unpack version: 29 for the RAR 2.9 family.
    pub version: u8,
    pub solid: bool,
    pub split_before: bool,
    pub split_after: bool,
    pub data: Range<usize>,
}

const MARK4: &[u8] = b"Rar!\x1a\x07\x00";

fn u16at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Every file member of one RAR 4 volume, in stored order.
pub fn walk4(arc: &[u8]) -> Vec<Frag4> {
    assert_eq!(arc.get(..7), Some(MARK4), "not a RAR 4 archive");
    let mut pos = 7 + usize::from(u16at(arc, 12));
    let mut out = Vec::new();
    while pos + 7 <= arc.len() {
        let size = usize::from(u16at(arc, pos + 5));
        if size < 7 || pos + size > arc.len() {
            break;
        }
        let h = &arc[pos..pos + size];
        let kind = h[2];
        let flags = u16at(h, 3);
        let add = if flags & 0x8000 != 0 {
            u32at(h, 7) as usize
        } else {
            0
        };
        if kind == 0x7B {
            break;
        }
        if kind == 0x74 {
            let mut unpacked = u64::from(u32at(h, 11));
            let crc32 = u32at(h, 16);
            let version = h[24];
            let method = h[25];
            let nlen = usize::from(u16at(h, 26));
            let mut at = 32;
            if flags & 0x0100 != 0 {
                // High halves of the 64-bit sizes.
                unpacked |= u64::from(u32at(h, 36)) << 32;
                at = 40;
            }
            out.push(Frag4 {
                name: h[at..at + nlen].to_vec(),
                unpacked,
                crc32,
                method,
                version,
                solid: flags & 0x0010 != 0,
                split_before: flags & 0x0001 != 0,
                split_after: flags & 0x0002 != 0,
                data: pos + size..pos + size + add,
            });
        }
        pos += size + add;
    }
    out
}
