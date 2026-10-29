//! Test support for spec H3 section 7: the smallest RAR 4 container that
//! can carry one compressed member, so reference `unrar` can be asked
//! whether the RAR 2.9 encoder's bytes are the format.
//!
//! Not a writer: spec G owns the containers. No volume, no encryption, no
//! comment, no recovery. Every archive it makes goes straight to `unrar`
//! and is thrown away.
#![allow(dead_code)]

/// The seven byte mark head.
const MARK: &[u8] = b"Rar!\x1a\x07\x00";

/// Fill in a block's size and its header checksum, which is the low half
/// of the CRC-32 over everything after the checksum itself.
fn stamp(mut header: Vec<u8>) -> Vec<u8> {
    let size = header.len() as u16;
    header[5..7].copy_from_slice(&size.to_le_bytes());
    let checksum = crc32fast::hash(&header[2..]) as u16;
    header[..2].copy_from_slice(&checksum.to_le_bytes());
    header
}

/// One compressed member.
pub struct Member<'a> {
    pub name: &'a str,
    /// The member's original bytes, whose length and CRC-32 the header
    /// declares.
    pub unpacked: &'a [u8],
    /// The packed bytes the encoder produced.
    pub packed: &'a [u8],
    /// The unpack version byte: 29 is spec H1's codec.
    pub version: u8,
    /// The method byte; 0x30 is stored and 0x35 is best.
    pub method: u8,
    /// The dictionary as `65,536 << bits`, in the header's flag bits.
    pub dictionary_bits: u8,
    /// Whether the member continues the previous one's window.
    pub solid: bool,
}

fn file_header(member: &Member<'_>) -> Vec<u8> {
    // 0x8000 marks a long block, whose added size is the data area.
    let mut flags: u16 = 0x8000 | (u16::from(member.dictionary_bits) << 5);
    if member.solid {
        flags |= 0x10;
    }
    let mut header = vec![0, 0, 0x74];
    header.extend_from_slice(&flags.to_le_bytes());
    header.extend_from_slice(&[0; 2]); // size, stamped below
    header.extend_from_slice(&(member.packed.len() as u32).to_le_bytes());
    header.extend_from_slice(&(member.unpacked.len() as u32).to_le_bytes());
    header.push(2); // host os: Win32
    header.extend_from_slice(&crc32fast::hash(member.unpacked).to_le_bytes());
    header.extend_from_slice(&0x5A21_0000u32.to_le_bytes()); // DOS time
    header.push(member.version);
    header.push(member.method);
    header.extend_from_slice(&(member.name.len() as u16).to_le_bytes());
    header.extend_from_slice(&0x20u32.to_le_bytes()); // attributes
    header.extend_from_slice(member.name.as_bytes());
    stamp(header)
}

/// One archive holding `members` in order.
pub fn archive(members: &[Member<'_>]) -> Vec<u8> {
    let mut out = MARK.to_vec();
    let mut main = vec![0, 0, 0x73];
    main.extend_from_slice(&0u16.to_le_bytes());
    main.extend_from_slice(&[0; 2]);
    main.extend_from_slice(&[0; 6]);
    out.extend_from_slice(&stamp(main));
    for member in members {
        out.extend_from_slice(&file_header(member));
        out.extend_from_slice(member.packed);
    }
    out.extend_from_slice(&stamp(vec![0, 0, 0x7B, 0x00, 0x40, 0, 0]));
    out
}
