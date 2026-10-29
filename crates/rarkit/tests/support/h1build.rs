//! Test support for spec H1's differential case 4: build a RAR 2.9 solid
//! archive around a hand written LZ stream, so the old engine can be asked
//! the same question this package answers.
//!
//! The header layout is RARLAB's public `technote.txt` one, the same
//! fields `rar4lz.rs` reads back. The LZ stream is written from SPEC-H1
//! sections 3.2 to 3.5.
#![allow(dead_code)]

/// Bits out, most significant first.
#[derive(Default)]
pub struct BitWriter {
    pub bytes: Vec<u8>,
    used: u32,
}

impl BitWriter {
    pub fn put(&mut self, value: u32, count: u32) {
        for index in (0..count).rev() {
            if self.used.is_multiple_of(8) {
                self.bytes.push(0);
            }
            let bit = ((value >> index) & 1) as u8;
            let at = self.bytes.len() - 1;
            self.bytes[at] |= bit << (7 - self.used % 8);
            self.used += 1;
        }
    }

    /// Bits written so far.
    pub fn bit_len(&self) -> u32 {
        self.used
    }

    /// End a member's packed span on a byte boundary, as a writer flushes
    /// it, and answer where that span ends.
    pub fn flush(&mut self) -> usize {
        while !self.used.is_multiple_of(8) {
            self.put(0, 1);
        }
        self.bytes.len()
    }
}

/// The alphabets a block names, as code lengths: main (299), distance
/// (60), low distance (17), length (28).
pub struct Tables {
    pub lengths: Vec<u8>,
    pub codes: Vec<(u32, u8)>,
    pub distance: Vec<(u32, u8)>,
}

/// Equal lengths for the symbols named, the smallest width that fits.
fn flat(size: usize, symbols: &[u16]) -> Vec<u8> {
    let mut width = 1u8;
    while (1usize << width) < symbols.len() {
        width += 1;
    }
    let mut lengths = vec![0u8; size];
    for &symbol in symbols {
        lengths[usize::from(symbol)] = width;
    }
    lengths
}

/// Canonical codes: each length's codes assigned in symbol order,
/// shorter lengths first.
fn canonical(lengths: &[u8]) -> Vec<(u32, u8)> {
    let mut codes = vec![(0u32, 0u8); lengths.len()];
    let mut next = 0u32;
    for width in 1..=15u8 {
        for (symbol, &length) in lengths.iter().enumerate() {
            if length == width {
                codes[symbol] = (next, width);
                next += 1;
            }
        }
        next <<= 1;
    }
    codes
}

/// Write an LZ block header and its tables, naming `main` and the
/// distance slots `distances`.
pub fn start_block(out: &mut BitWriter, main: &[u16], distances: &[u16]) -> Tables {
    let main_lengths = flat(299, main);
    let distance_lengths = flat(60, distances);
    let low = flat(17, &[0]);
    let length = flat(28, &[0]);
    out.put(0, 1); // an LZ block
    out.put(0, 1); // the stored code lengths are cleared
    for _ in 0..20 {
        out.put(5, 4); // twenty five-bit level codes
    }
    let mut lengths = Vec::new();
    lengths.extend_from_slice(&main_lengths);
    lengths.extend_from_slice(&distance_lengths);
    lengths.extend_from_slice(&low);
    lengths.extend_from_slice(&length);
    for &value in &lengths {
        out.put(u32::from(value), 5);
    }
    Tables {
        codes: canonical(&main_lengths),
        distance: canonical(&distance_lengths),
        lengths,
    }
}

impl Tables {
    pub fn main(&self, out: &mut BitWriter, symbol: u16) {
        let (code, width) = self.codes[usize::from(symbol)];
        assert!(width > 0, "main symbol {symbol} has no code");
        out.put(code, u32::from(width));
    }

    pub fn distance_slot(&self, out: &mut BitWriter, slot: u16) {
        let (code, width) = self.distance[usize::from(slot)];
        assert!(width > 0, "distance slot {slot} has no code");
        out.put(code, u32::from(width));
    }
}

fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

fn stamp(mut header: Vec<u8>) -> Vec<u8> {
    let size = header.len() as u16;
    header[5..7].copy_from_slice(&size.to_le_bytes());
    let crc = crc32(&header[2..]) as u16;
    header[..2].copy_from_slice(&crc.to_le_bytes());
    header
}

/// One member of the archive to build.
pub struct Member<'a> {
    pub name: &'a str,
    pub packed: &'a [u8],
    pub unpacked: &'a [u8],
    pub solid: bool,
}

/// A RAR 2.9 archive of compressed members, with a 64 KiB dictionary.
pub fn archive(members: &[Member<'_>]) -> Vec<u8> {
    let mut out = b"Rar!\x1a\x07\x00".to_vec();
    let mut main = vec![0, 0, 0x73];
    main.extend_from_slice(&0u16.to_le_bytes());
    main.extend_from_slice(&[0; 2]);
    main.extend_from_slice(&[0; 6]);
    out.extend_from_slice(&stamp(main));
    for member in members {
        // 0x8000 long block, 0x0010 solid, dictionary bits 0 (64 KiB).
        let mut flags: u16 = 0x8000;
        if member.solid {
            flags |= 0x0010;
        }
        let mut header = vec![0, 0, 0x74];
        header.extend_from_slice(&flags.to_le_bytes());
        header.extend_from_slice(&[0; 2]);
        header.extend_from_slice(&(member.packed.len() as u32).to_le_bytes());
        header.extend_from_slice(&(member.unpacked.len() as u32).to_le_bytes());
        header.push(2); // host OS: Win32
        header.extend_from_slice(&crc32(member.unpacked).to_le_bytes());
        header.extend_from_slice(&0x5A21_0000u32.to_le_bytes()); // DOS time
        header.push(29); // unpack version
        header.push(0x35); // best
        header.extend_from_slice(&(member.name.len() as u16).to_le_bytes());
        header.extend_from_slice(&0x20u32.to_le_bytes());
        header.extend_from_slice(member.name.as_bytes());
        out.extend_from_slice(&stamp(header));
        out.extend_from_slice(member.packed);
    }
    out.extend_from_slice(&stamp(vec![0, 0, 0x7B, 0x00, 0x40, 0, 0]));
    out
}
