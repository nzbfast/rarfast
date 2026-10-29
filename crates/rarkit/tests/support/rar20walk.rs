//! Test support for spec H3 part A: just enough of the RAR 1.5 to 4.x
//! container to hand a member's packed bytes to the RAR 2.0 codec, until
//! spec F's real walker exists. It reads no encrypted header, follows no
//! volume and decodes no name.
#![allow(dead_code)]

/// One file member of a RAR 1.5 to 4.x archive.
#[derive(Debug, Clone)]
pub struct Member {
    /// The name exactly as stored.
    pub name: Vec<u8>,
    /// The member's packed data.
    pub packed: Vec<u8>,
    /// The size the header declares.
    pub unpacked: u64,
    /// The header's CRC-32 of the unpacked bytes.
    pub crc: u32,
    /// The unpack version byte: 20 and 26 are spec H3 part A's.
    pub version: u8,
    /// The method byte; 0x30 is stored.
    pub method: u8,
    /// The header's solid bit.
    pub solid: bool,
    /// The dictionary selector from the header flags, so the window is
    /// `65,536 << bits`.
    pub dictionary_bits: u8,
    /// Whether the flags mark a directory rather than a file.
    pub is_dir: bool,
}

impl Member {
    /// Whether the member holds compressed data this package decodes.
    pub fn is_compressed_file(&self) -> bool {
        !self.is_dir && self.method != 0x30 && self.unpacked > 0
    }
}

/// The seven byte mark head every RAR 1.5 to 4.x archive starts with.
const MARK: &[u8] = &[0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00];

/// Walk `archive`, returning every file member with its packed bytes.
pub fn members(archive: &[u8]) -> Vec<Member> {
    assert_eq!(archive.get(..7), Some(MARK), "not a RAR 1.5 to 4.x archive");
    let main_size = usize::from(u16::from_le_bytes([archive[12], archive[13]]));
    let mut at = 7 + main_size;
    let mut out = Vec::new();
    while at + 7 <= archive.len() {
        let kind = archive[at + 2];
        let flags = u16::from_le_bytes([archive[at + 3], archive[at + 4]]);
        let size = usize::from(u16::from_le_bytes([archive[at + 5], archive[at + 6]]));
        if kind == 0x7b || size < 7 {
            break;
        }
        let add = if flags & 0x8000 != 0 {
            u32::from_le_bytes(archive[at + 7..at + 11].try_into().unwrap()) as usize
        } else {
            0
        };
        let data = at + size;
        if kind == 0x74 {
            let name_len = usize::from(u16::from_le_bytes([archive[at + 26], archive[at + 27]]));
            let dictionary_bits = ((flags >> 5) & 7) as u8;
            out.push(Member {
                name: archive[at + 32..at + 32 + name_len].to_vec(),
                packed: archive[data..data + add].to_vec(),
                unpacked: u64::from(u32::from_le_bytes(
                    archive[at + 11..at + 15].try_into().unwrap(),
                )),
                crc: u32::from_le_bytes(archive[at + 16..at + 20].try_into().unwrap()),
                version: archive[at + 24],
                method: archive[at + 25],
                solid: flags & 0x10 != 0,
                dictionary_bits,
                // The dictionary bits are all set on a directory entry.
                // The attribute word is host specific and says nothing
                // here: a unix written member carries mode bits in it.
                is_dir: dictionary_bits == 7,
            });
        }
        at = data + add;
    }
    out
}
