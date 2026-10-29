//! Test support for spec H1: the smallest RAR 1.5 to 4.x header walk that
//! finds each member's packed span, its declared size, its checksum and
//! the dictionary its header names, and groups members into solid chains.
//! Written from `SPEC-API-rarkit.md` and RARLAB's public `technote.txt`
//! header layout, until spec F's real walker exists. It handles exactly
//! what the spec H, I and J vectors contain: no encryption, no volumes.
#![allow(dead_code)]

use std::ops::Range;

/// One file member of one RAR 4 family archive.
#[derive(Debug, Clone)]
pub struct Member4 {
    pub name: Vec<u8>,
    pub unpacked: u64,
    pub crc32: u32,
    /// 0x30 stored to 0x35 best.
    pub method: u8,
    /// The unpack version: 29 for the codec spec H1 owns.
    pub version: u8,
    pub solid: bool,
    pub is_directory: bool,
    /// The member's data is encrypted (spec K's, not this package's).
    pub encrypted: bool,
    /// The member is split across volumes.
    pub split_before: bool,
    pub split_after: bool,
    /// The declared dictionary: `65,536 << n` for `n` in 0 to 6.
    pub dictionary: u32,
    pub data: Range<usize>,
}

const MARK4: &[u8] = b"Rar!\x1a\x07\x00";

fn u16at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn u32at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// Every file member of one archive, in stored order.
pub fn walk(archive: &[u8]) -> Vec<Member4> {
    // A damaged or truncated archive lists what it still can.
    if archive.get(..7) != Some(MARK4) || archive.len() < 14 {
        return Vec::new();
    }
    let mut at = 7 + usize::from(u16at(archive, 12));
    let mut out = Vec::new();
    while at + 7 <= archive.len() {
        let size = usize::from(u16at(archive, at + 5));
        if size < 7 || at + size > archive.len() {
            break;
        }
        let header = &archive[at..at + size];
        let kind = header[2];
        let flags = u16at(header, 3);
        let extra = if flags & 0x8000 != 0 {
            u32at(header, 7) as usize
        } else {
            0
        };
        if kind == 0x7B {
            break;
        }
        if kind == 0x74 {
            let mut unpacked = u64::from(u32at(header, 11));
            let name_len = usize::from(u16at(header, 26));
            let mut name_at = 32;
            if flags & 0x0100 != 0 {
                unpacked |= u64::from(u32at(header, 36)) << 32;
                name_at = 40;
            }
            let dictionary_bits = (flags >> 5) & 7;
            out.push(Member4 {
                name: header[name_at..name_at + name_len].to_vec(),
                unpacked,
                crc32: u32at(header, 16),
                method: header[25],
                version: header[24],
                solid: flags & 0x0010 != 0,
                encrypted: flags & 0x0004 != 0,
                split_before: flags & 0x0001 != 0,
                split_after: flags & 0x0002 != 0,
                is_directory: dictionary_bits == 7,
                dictionary: 0x1_0000u32 << dictionary_bits.min(6),
                data: at + size..at + size + extra,
            });
        }
        at += size + extra;
    }
    out
}

/// One solid chain, or one non solid member: the members' packed data
/// concatenated the way spec F concatenates it, with each member's span.
#[derive(Debug, Default)]
pub struct Chain {
    pub packed: Vec<u8>,
    pub members: Vec<Member4>,
    pub spans: Vec<Range<usize>>,
    pub dictionary: u32,
}

/// Group an archive's members into streams: a member with the solid flag
/// continues the one before it.
pub fn chains(archive: &[u8]) -> Vec<Chain> {
    let mut out: Vec<Chain> = Vec::new();
    for member in walk(archive) {
        if member.is_directory {
            continue;
        }
        let fresh = !member.solid || out.is_empty();
        if fresh {
            out.push(Chain {
                dictionary: member.dictionary,
                ..Chain::default()
            });
        }
        let chain = out.last_mut().expect("a chain");
        chain.dictionary = chain.dictionary.max(member.dictionary);
        let start = chain.packed.len();
        // A truncated archive's last member may name bytes it does not
        // carry; the decoder sees the short span and says so.
        let data = member.data.start.min(archive.len())..member.data.end.min(archive.len());
        chain.packed.extend_from_slice(&archive[data]);
        chain.spans.push(start..chain.packed.len());
        chain.members.push(member);
    }
    out
}
