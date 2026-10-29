//! Test support for spec H3 part B: the smallest RAR 5 container that can
//! carry one compressed member, so that reference `unrar` can be asked
//! whether the encoder's bytes are the format.
//!
//! This is NOT a writer. Spec G owns the containers; this builds one
//! member of one volume, with no volume, no encryption, no comment and no
//! recovery, from the block shapes the crate's own RAR 5 walker in
//! `rarwalk.rs` already reads. Every archive it makes is handed straight
//! to `unrar` and thrown away.
#![allow(dead_code)]

/// The eight byte RAR 5 signature.
const SIGNATURE: &[u8] = b"Rar!\x1a\x07\x01\x00";

/// Append `value` as a RAR 5 variable length integer.
fn vint(out: &mut Vec<u8>, mut value: u64) {
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

/// Wrap `body`, which starts at the block's type field, in its size and
/// its CRC-32. The checksum covers the size field and everything after
/// it, which is what a reader recomputes.
fn block(body: &[u8]) -> Vec<u8> {
    let mut sized = Vec::with_capacity(body.len() + 8);
    vint(&mut sized, body.len() as u64);
    sized.extend_from_slice(body);
    let mut out = crc32fast::hash(&sized).to_le_bytes().to_vec();
    out.extend_from_slice(&sized);
    out
}

/// The main archive header, which says nothing but "an archive", or "a
/// solid archive" when `solid`.
fn main_header(solid: bool) -> Vec<u8> {
    let mut body = Vec::new();
    vint(&mut body, 1); // type: main archive header
    vint(&mut body, 0); // header flags
    vint(&mut body, if solid { 0x04 } else { 0 }); // archive flags
    block(&body)
}

/// The end of archive header.
fn end_header() -> Vec<u8> {
    let mut body = Vec::new();
    vint(&mut body, 5); // type: end of archive
    vint(&mut body, 0); // header flags
    vint(&mut body, 0); // end of archive flags: not a volume
    block(&body)
}

/// What the file header says about the member behind it.
pub struct Member<'a> {
    pub name: &'a str,
    /// The member's original bytes, whose length and CRC-32 the header
    /// declares.
    pub unpacked: &'a [u8],
    /// The packed bytes the encoder produced.
    pub packed: &'a [u8],
    /// The dictionary as `131,072 << exponent`.
    pub dictionary_exponent: u8,
    /// The compression method, 1 to 5; 0 is stored.
    pub method: u8,
    /// Whether the member continues the previous one's window.
    pub solid: bool,
}

fn file_header(member: &Member<'_>) -> Vec<u8> {
    let mut body = Vec::new();
    vint(&mut body, 2); // type: file header
    vint(&mut body, 2); // header flags: a data area follows
    vint(&mut body, member.packed.len() as u64);
    // File flags: bit 2 says a CRC-32 of the unpacked bytes is present.
    vint(&mut body, 0x04);
    vint(&mut body, member.unpacked.len() as u64);
    vint(&mut body, 0); // attributes
    body.extend_from_slice(&crc32fast::hash(member.unpacked).to_le_bytes());
    // Compression information: the algorithm version in the low six bits,
    // the solid bit, the method, and the dictionary exponent.
    let solid = u64::from(member.solid) << 6;
    let compression =
        solid | (u64::from(member.method) << 7) | (u64::from(member.dictionary_exponent) << 10);
    vint(&mut body, compression);
    vint(&mut body, 0); // host os: Windows
    vint(&mut body, member.name.len() as u64);
    body.extend_from_slice(member.name.as_bytes());
    block(&body)
}

/// One archive holding `members` in order.
pub fn archive(members: &[Member<'_>]) -> Vec<u8> {
    archive_with(members, false)
}

/// [`archive`] with the main header's solid flag set, which is what the
/// read path takes as a solid chain (spec F 3.6).
pub fn solid_archive(members: &[Member<'_>]) -> Vec<u8> {
    archive_with(members, true)
}

fn archive_with(members: &[Member<'_>], solid: bool) -> Vec<u8> {
    let mut out = SIGNATURE.to_vec();
    out.extend_from_slice(&main_header(solid));
    for member in members {
        out.extend_from_slice(&file_header(member));
        out.extend_from_slice(member.packed);
    }
    out.extend_from_slice(&end_header());
    out
}
