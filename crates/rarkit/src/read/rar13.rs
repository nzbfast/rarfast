//! RAR 1.3 and 1.4 (spec F 3.4). The oldest container this package reads:
//! no block-type dispatch, no header checksum and no end block. An archive
//! is a 7-byte archive header followed by one file entry per member, each
//! entry being a header and its packed bytes, to the end of the file.

use std::ops::Range;

use crate::error::{Corruption, Error, ErrorKind, Result};
use crate::read::block::{CommentCodec, CommentSpan, Fields, FileHdr, Main};
use crate::read::dostime;
use crate::types::{HostOs, Method};

#[cfg(any(target_arch = "x86_64", test))]
mod sum16_x86;

/// The fixed part of a file entry header, before the name.
pub(crate) const FILE_FIXED: usize = 21;
/// The smallest archive header.
pub(crate) const ARCHIVE_FIXED: usize = 7;

/// Archive flags (spec F 3.4.1).
pub(crate) const AF_VOLUME: u8 = 0x01;
pub(crate) const AF_COMMENT: u8 = 0x02;
pub(crate) const AF_LOCK: u8 = 0x04;
pub(crate) const AF_SOLID: u8 = 0x08;

/// File flags (spec F 3.4.4), which agree with the later container's low
/// four bits.
pub(crate) const FF_SPLIT_BEFORE: u8 = 0x01;
pub(crate) const FF_SPLIT_AFTER: u8 = 0x02;
pub(crate) const FF_ENCRYPTED: u8 = 0x04;
pub(crate) const FF_COMMENT: u8 = 0x08;

fn corrupt() -> Error {
    Error::new(ErrorKind::Corrupt(Corruption::Header))
}

/// The member checksum of spec F 3.4.3: not a CRC32 and not the low half of
/// one. A 16-bit running value that starts at zero and, for each byte of
/// the UNPACKED member, adds the byte modulo 2^16 and then rotates the
/// result left by one bit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Sum16(u16);

impl Sum16 {
    /// A checksum over no bytes.
    pub(crate) fn new() -> Sum16 {
        Sum16(0)
    }

    /// Feed `data`.
    ///
    /// x86-64 runs the forms in [`sum16_x86`]; every other target runs
    /// [`block_form`], whose notes say why it is not the definition's own
    /// byte loop and why this function is out of line.
    #[inline(never)]
    pub(crate) fn update(&mut self, data: &[u8]) {
        #[cfg(target_arch = "x86_64")]
        {
            self.0 = sum16_x86::update(self.0, data);
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            self.0 = block_form(self.0, data);
        }
    }

    /// The checksum of everything fed.
    pub(crate) fn finish(self) -> u16 {
        self.0
    }
}

/// Feed `data` to a checksum standing at `state`, eight bytes a block.
///
/// # Why this is not the byte loop the definition is written as
///
/// The definition above is a dependency chain one byte deep: an add
/// and a rotate, each waiting on the byte before it, which measures
/// about three cycles a byte and cannot go faster however the two
/// operations are spelled. On `rar13/BIG80K.RAR` - one 80 KiB member -
/// that chain was 49% of the whole extract leg, decode included, and
/// it is the single largest item of that leg's gap against the old
/// engine. So the chain is BROKEN, by this identity:
///
/// **A rotate left by one is multiplication by two modulo 65,535.**
/// For `x <= 65534`, `ROL(x) = 2x - 65535 * (x >> 15)`, which is
/// `2x mod 65535`; and `ROL(65535) = 65535`. So a run of steps is
/// arithmetic in `Z/65535` and has a closed form:
///
/// ```text
/// s_n = 2^n * ( s_0 + SUM over k < n of 2^-k * b_k )   (mod 65535)
/// ```
///
/// Every term of that sum is independent of every other, so eight of
/// them are one tree of adds instead of eight waiting adds, and
/// `2^-k * b_k mod 65535` is the byte rotated RIGHT by `k` in sixteen
/// bits.
///
/// # The one place the identity does not hold, and what is done about it
///
/// The add of the definition is modulo 2^16, not modulo 65,535. When
/// it wraps it takes away 65,536, and 65,536 is 1 modulo 65,535, so a
/// wrapping step is the modular step MINUS ONE. The closed form is
/// therefore exact only over a run of steps in which no `s_k + b_k`
/// reaches 65,535. Call such a step CLEAN.
///
/// A step is clean whenever `s_k < 65280`, because a byte is at most
/// 255. So each block of eight computes its eight intermediate
/// states, which cost nothing extra, being what the closed form
/// produces on the way, and takes the block only if all eight are below
/// 65,280. Otherwise it takes ONE byte down the definition's own loop,
/// which is exact whatever the state, and tries the block again.
///
/// The test is deliberately CONSERVATIVE in two ways, and both are
/// safe because a false alarm costs one serial byte and a false
/// all-clear would be a wrong checksum: it compares the state against
/// 65,280 rather than against `65535 - b_k`, and it compares the
/// once-folded value rather than the fully reduced one. A value that
/// is not yet fully reduced is either the state itself or the state
/// plus 65,535, and both are at or above 65,280 whenever the state is.
///
/// Lane 0 needs no special case: its `x` is the incoming state
/// unchanged, so a state of 65,535 - the one value the modular form
/// cannot represent, and reachable only out of a step that was already
/// unclean - alarms on itself.
///
/// # Out of line, and that matters more than it looks
///
/// The block form is about a hundred instructions where the byte loop
/// was six, and `emit`'s caller on this path is the RAR 1.5 decode
/// loop's own window flush, so INLINED it lands inside that
/// decoder's member loop. That loop is instruction-delivery bound - the
/// `CPU Counters` template puts about a third of BOTH arms of
/// `f/extract-rar15-doc17` there - and a RAR 1.5 member never runs a
/// single byte of this code, only the RAR 1.3 container having this
/// checksum at all. Inlined it cost that leg 4%, measured against the
/// same build with `#[inline(never)]`, which [`Sum16::update`] carries
/// for every form it runs. One call per 64 KiB flush costs nothing
/// measurable.
#[inline(always)]
fn block_form(state: u16, data: &[u8]) -> u16 {
    let mut state = u32::from(state);
    let mut at = 0usize;
    while let Some(block) = data.get(at..at + 8) {
        let b: [u32; 8] = core::array::from_fn(|k| u32::from(block[k]));
        // b_k * 2^-k mod 65535, which for a byte is a rotate right.
        let w: [u32; 8] = core::array::from_fn(|k| ((b[k] >> k) | (b[k] << (16 - k))) & 0xFFFF);
        // The eight prefixes of `w` as a TREE: depth three, not eight.
        let a01 = w[0] + w[1];
        let a23 = w[2] + w[3];
        let a45 = w[4] + w[5];
        let a67 = w[6] + w[7];
        let a0123 = a01 + a23;
        let a4567 = a45 + a67;
        let prefix = [
            0,
            w[0],
            a01,
            a01 + w[2],
            a0123,
            a0123 + w[4],
            a0123 + a45,
            a0123 + a45 + w[6],
        ];
        // The eight intermediate states, each folded once: every lane
        // depends on the incoming state and on nothing else.
        let folded: [u32; 8] = core::array::from_fn(|k| {
            let x = (state + prefix[k]) << k;
            (x & 0xFFFF) + (x >> 16)
        });
        let m01 = folded[0].max(folded[1]);
        let m23 = folded[2].max(folded[3]);
        let m45 = folded[4].max(folded[5]);
        let m67 = folded[6].max(folded[7]);
        if m01.max(m23).max(m45.max(m67)) >= 0xFF00 {
            state = u32::from(step(state as u16, b[0] as u8));
            at += 1;
            continue;
        }
        // 2^8 * (state + the whole block's weighted sum), reduced.
        let x = (state + a0123 + a4567) << 8;
        let a = (x & 0xFFFF) + (x >> 16);
        let a = (a & 0xFFFF) + (a >> 16);
        // 65,535 and 0 are the same residue; the definition's own
        // value here is 0, because a clean step cannot produce 65,535.
        state = if a == 0xFFFF { 0 } else { a };
        at += 8;
    }
    let mut state = state as u16;
    #[allow(clippy::indexing_slicing)] // `at` never passes the length
    for byte in &data[at..] {
        state = step(state, *byte);
    }
    state
}

/// One step of the checksum exactly as spec F 3.4.3 writes it: add the
/// byte modulo 2^16, then rotate the result left by one bit.
#[inline(always)]
fn step(state: u16, byte: u8) -> u16 {
    state.wrapping_add(u16::from(byte)).rotate_left(1)
}

/// The archive header and what it declares.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ArchiveHeader {
    /// The header's size, counting from the signature.
    pub size: u16,
}

/// Parse the archive header. `head` starts at the signature.
pub(crate) fn parse_archive(head: &[u8], at: u64) -> Result<(ArchiveHeader, Fields)> {
    if head.len() < ARCHIVE_FIXED {
        return Err(corrupt());
    }
    let size = u16::from_le_bytes([head[4], head[5]]);
    if usize::from(size) < ARCHIVE_FIXED {
        return Err(corrupt());
    }
    let flags = head[6];
    // An archive comment fills the header past its first seven bytes: a
    // u16 size of everything that follows it, a u16 unpacked size, then the
    // packed comment bytes, compressed by this generation's codec.
    let comment = if flags & AF_COMMENT != 0 {
        let body = head.get(ARCHIVE_FIXED..usize::from(size));
        body.filter(|b| b.len() >= 4).map(|body| {
            let following = usize::from(u16::from_le_bytes([body[0], body[1]]));
            let unpacked = u64::from(u16::from_le_bytes([body[2], body[3]]));
            let end = (2 + following).min(body.len());
            CommentSpan {
                data: at + (ARCHIVE_FIXED + 4) as u64..at + (ARCHIVE_FIXED + end) as u64,
                unpacked,
                version: 0,
                method: 0,
                // RAR 1.3 records no method byte and its comment is
                // packed by that generation's codec: the reference
                // prints 30 bytes from 32 packed (spec F question 5).
                // So the packed bytes are never the comment, and a
                // comment this package cannot name an algorithm for is
                // `None` rather than the packed bytes handed back as
                // text. Which algorithm it is, is not known yet.
                codec: CommentCodec::Missing,
            }
        })
    } else {
        None
    };
    let main = Main {
        flags: u64::from(flags),
        is_volume: flags & AF_VOLUME != 0,
        volume_number: None,
        solid: flags & AF_SOLID != 0,
        locked: flags & AF_LOCK != 0,
        comment,
        ..Main::default()
    };
    Ok((ArchiveHeader { size }, Fields::Main(main)))
}

/// What [`parse_file`] returns beside the fields.
pub(crate) struct FileParse {
    /// The fields, with an empty name span the caller fills in.
    pub fields: FileHdr,
    /// The stored name bytes within the header.
    pub name: Range<usize>,
    /// The header's own size, which the next entry's position uses.
    pub header_size: u16,
}

/// One file entry header. `head` starts at the entry.
pub(crate) fn parse_file(head: &[u8], at: u64) -> Result<FileParse> {
    if head.len() < FILE_FIXED {
        return Err(corrupt());
    }
    let packed = u64::from(u32::from_le_bytes([head[0], head[1], head[2], head[3]]));
    let unpacked = u64::from(u32::from_le_bytes([head[4], head[5], head[6], head[7]]));
    let sum16 = u16::from_le_bytes([head[8], head[9]]);
    let header_size = u16::from_le_bytes([head[10], head[11]]);
    let dos_time = u32::from_le_bytes([head[12], head[13], head[14], head[15]]);
    let attributes = u32::from(head[16]);
    let flags = head[17];
    let unpack_version = u32::from(head[18]);
    let name_len = usize::from(head[19]);
    let method_code = u32::from(head[20]);

    // The header size counts from offset 0, name included, so it must hold
    // the fixed part and the name.
    let need = FILE_FIXED.checked_add(name_len).ok_or_else(corrupt)?;
    if usize::from(header_size) < need {
        return Err(corrupt());
    }
    let size = usize::from(header_size);
    if size > head.len() {
        return Err(corrupt());
    }
    let name = FILE_FIXED..need;

    // A file comment sits after the name when flag 0x08 is set: a u16
    // length, then that many bytes, stored as plain text.
    let comment = if flags & FF_COMMENT != 0 && size >= need + 2 {
        let len = u64::from(u16::from_le_bytes([head[need], head[need + 1]]));
        let start = at + (need + 2) as u64;
        Some(CommentSpan {
            data: start..start + len,
            unpacked: len,
            version: 0,
            method: 0,
            // A RAR 1.3 FILE comment is plain text after the name, not
            // packed by anything, which is what makes it different from
            // that container's ARCHIVE comment above.
            codec: CommentCodec::Stored,
        })
    } else {
        None
    };

    // There are no dictionary bits in this container, so the DOS directory
    // attribute is the only marking, exactly as in genuine RAR 1.5.
    let is_directory = attributes & 0x10 != 0 && packed == 0 && unpacked == 0;
    // The method is a small integer, not 0x30 plus one: 0 to 5.
    let method = if method_code == 0 {
        Method::Stored
    } else {
        Method::Compressed {
            level: method_code as u8,
            dictionary: 64 * 1024,
        }
    };

    Ok(FileParse {
        fields: FileHdr {
            name: 0..0,
            raw_name: name.start as u32..name.end as u32,
            file_flags: u64::from(flags),
            dict_bits: 0,
            host_raw: 0,
            raw_checksum: u32::from(sum16),
            service: None,
            is_directory,
            unpacked_size: Some(unpacked),
            packed_size: packed,
            split_before: flags & FF_SPLIT_BEFORE != 0,
            split_after: flags & FF_SPLIT_AFTER != 0,
            encrypted: flags & FF_ENCRYPTED != 0,
            solid: false,
            mtime: dostime::from_dos(dos_time),
            header_mtime: dostime::from_dos(dos_time),
            attributes,
            host_os: HostOs::MsDos,
            // `Checksum` has no 16-bit variant, so the value is reported as
            // None and verified internally: a damaged member still fails
            // (spec F 3.4.3; a `Checksum::Sum16` variant is not decided).
            checksum: None,
            method,
            // The container records no dictionary bits, and its one window
            // is 64 KiB. Reference `unrar lt` prints `-m0 -md=64k` for
            // every file member of the genuine `d140_m0.rar` and no `-md=`
            // clause for its directory entries.
            dictionary: (!is_directory).then_some(64 * 1024),
            method_code,
            unpack_version,
            rar4_salt: None,
            crypt: None,
            comment,
            recovery_percent: None,
            redirect: None,
            version: 0,
        },
        name,
        header_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec F 5.3: the checksum of `123456789` is 0xC78A, and of the empty
    /// string 0x0000.
    #[test]
    fn spec_f_5_3_member_checksum() {
        let mut sum = Sum16::new();
        sum.update(b"123456789");
        assert_eq!(sum.finish(), 0xC78A);
        assert_eq!(Sum16::new().finish(), 0x0000);
    }

    /// The block form of [`Sum16::update`] against the definition's own
    /// byte loop, over every length a block boundary can fall on and over
    /// the states the modular identity is least comfortable with: 0,
    /// 65,535 (the residue it cannot represent) and both sides of it.
    #[test]
    fn the_block_form_agrees_with_the_definition_byte_for_byte() {
        fn by_definition(data: &[u8], mut state: u16) -> u16 {
            for byte in data {
                state = state.wrapping_add(u16::from(*byte)).rotate_left(1);
            }
            state
        }
        // A spread that reaches the top of the range often, so the
        // unclean step is exercised rather than merely allowed for.
        let mut data = Vec::new();
        let mut x = 0x2545_F491_4F6C_DD1Du64;
        for _ in 0..4096 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            data.push((x >> 33) as u8);
        }
        for start in [0u16, 1, 0x00FF, 0x7FFF, 0x8000, 0xFF00, 0xFFFE, 0xFFFF] {
            for len in 0..=200usize {
                let mut sum = Sum16(start);
                sum.update(&data[..len]);
                assert_eq!(
                    sum.finish(),
                    by_definition(&data[..len], start),
                    "length {len} from state {start:#06x}"
                );
            }
            let mut sum = Sum16(start);
            sum.update(&data);
            assert_eq!(sum.finish(), by_definition(&data, start));
        }
    }

    /// Every byte value, from every state that can precede an unclean
    /// step, one step at a time: the block form must agree there too.
    #[test]
    fn the_block_form_agrees_across_the_unclean_boundary() {
        for state in 0xFE00u32..=0xFFFF {
            for byte in 0..=255u8 {
                let want = (state as u16).wrapping_add(u16::from(byte)).rotate_left(1);
                let mut sum = Sum16(state as u16);
                sum.update(&[byte]);
                assert_eq!(sum.finish(), want, "state {state:#06x} byte {byte:#04x}");
                // And with the step buried inside a block.
                let mut block = [0u8; 8];
                block[3] = byte;
                let mut whole = Sum16(state as u16);
                whole.update(&block);
                let mut piece = Sum16(state as u16);
                for b in &block {
                    piece.update(&[*b]);
                }
                assert_eq!(whole.finish(), piece.finish());
            }
        }
    }

    #[test]
    fn the_checksum_is_the_same_fed_in_pieces() {
        let data: Vec<u8> = (0..500u32).map(|i| (i * 37) as u8).collect();
        let mut whole = Sum16::new();
        whole.update(&data);
        let mut split = Sum16::new();
        for chunk in data.chunks(7) {
            split.update(chunk);
        }
        assert_eq!(whole.finish(), split.finish());
    }
}
