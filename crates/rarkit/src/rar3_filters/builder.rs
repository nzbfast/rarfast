//! Section 3.9's record layout, as a builder the READER's tests drive.
//!
//! The project's decision of 19 Sep 2026 answers SPEC-J section 0 question 1 with
//! NO, so this crate ships no record writer: the whole module is
//! `cfg(test)`, and what it exists for is to hand the reader of section 3.3
//! records shaped exactly as genuine rar 4.20 shapes them, so the reader
//! can be held to the rows of `specs/vectors-J/genuine-records.tsv`, the
//! genuine archives' own records, without any archive to decompress first.
//!
//! A DEFINITION carries a program's bytes, and this crate holds none. It
//! carries a STAND-IN instead: [`stand_in`] builds a byte string of the
//! right length whose CRC32 is the right one, which is all the reader ever
//! looks at (section 3.4: identification is by length and CRC32, and must
//! not depend on anything else). A stand-in is the same length as the
//! program it stands in for, so a record built here has the same flags
//! byte and the same body length as the genuine record it reproduces.

use super::StandardProgram;
use crate::error::{Error, ErrorKind, Result, Unsupported};

/// The longest span one record covers: 65,536 bytes, the largest genuine
/// rar 4.20 uses (section 3.9).
pub(crate) const MAX_WRITTEN_SPAN: u32 = 65_536;

/// Where a record's bytes go: 8 bits each into an LZ block, or one PPMd
/// symbol each.
pub(crate) trait RecordSink {
    /// Append one byte of the record.
    fn put_byte(&mut self, byte: u8) -> Result<()>;
}

/// A program's parameters as the record states them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Params {
    /// x86 and Itanium: no registers (the reader derives the offset).
    None,
    /// Delta and audio: the channel count, sent as `R0`.
    Channels(u32),
    /// RGB: row width in bytes (`R0 - 3`) and red position (`R1`).
    Rgb {
        /// Bytes per row, a positive multiple of 3.
        width: u32,
        /// The red position.
        red_at: u32,
    },
}

/// Longest body this module builds: selector, start, length, mask, two
/// registers and a 216-byte stand-in come to 240 bytes. Records built
/// field by field through [`BodyBits`] may be longer, up to this bound.
const BODY_CAP: usize = 1024;

/// A record body under construction, most significant bit first.
pub(crate) struct BodyBits {
    buf: [u8; BODY_CAP],
    bits: usize,
}

impl Default for BodyBits {
    fn default() -> Self {
        BodyBits {
            buf: [0; BODY_CAP],
            bits: 0,
        }
    }
}

impl BodyBits {
    /// Append the low `count` bits of `value` (count at most 32).
    pub(crate) fn put(&mut self, value: u32, count: u32) -> Result<()> {
        if self.bits + count as usize > BODY_CAP * 8 {
            return Err(build_error("filter record body over 1024 bytes"));
        }
        for k in (0..count).rev() {
            let bit = (value >> k) & 1;
            if bit != 0 {
                self.buf[self.bits / 8] |= 0x80 >> (self.bits % 8);
            }
            self.bits += 1;
        }
        Ok(())
    }

    /// The shortest plain form of the variable-length integer.
    pub(crate) fn vint(&mut self, value: u32) -> Result<()> {
        match value {
            0..=15 => {
                self.put(0, 2)?;
                self.put(value, 4)
            }
            16..=255 => {
                self.put(1, 2)?;
                self.put(value, 8)
            }
            256..=65_535 => {
                self.put(2, 2)?;
                self.put(value, 16)
            }
            _ => {
                self.put(3, 2)?;
                self.put(value, 32)
            }
        }
    }

    /// The body so far, padded to whole bytes.
    pub(crate) fn body(&self) -> &[u8] {
        &self.buf[..self.bits.div_ceil(8)]
    }

    /// Emit the record: `flags` (whose low three bits are replaced by the
    /// smallest length code that fits), the length prefix, then the body.
    pub(crate) fn emit(&self, flags: u8, out: &mut impl RecordSink) -> Result<()> {
        let body = self.body();
        let len = body.len();
        let high = flags & 0xF8;
        match len {
            1..=6 => out.put_byte(high | (len as u8 - 1))?,
            0 | 7..=262 => {
                // A 0-byte body only fits the two-byte form.
                if len == 0 {
                    out.put_byte(high | 7)?;
                    out.put_byte(0)?;
                    out.put_byte(0)?;
                } else {
                    out.put_byte(high | 6)?;
                    out.put_byte((len - 7) as u8)?;
                }
            }
            _ => {
                out.put_byte(high | 7)?;
                out.put_byte((len >> 8) as u8)?;
                out.put_byte(len as u8)?;
            }
        }
        for &b in body {
            out.put_byte(b)?;
        }
        Ok(())
    }
}

fn build_error(what: &'static str) -> Error {
    Error::new(ErrorKind::Unsupported(Unsupported::WriteFeature(what)))
}

// ---------------------------------------------------------------------------
// Stand-in programs
// ---------------------------------------------------------------------------

/// The CRC32 of section 3.4: ISO 3309 / ITU-T V.42, reflected polynomial
/// 0xEDB88320, initial value and final XOR 0xFFFFFFFF. The byte table and
/// the inverse of its top byte, which is a permutation of 0 to 255.
fn crc_tables() -> ([u32; 256], [u8; 256]) {
    let mut table = [0u32; 256];
    for (i, slot) in table.iter_mut().enumerate() {
        let mut x = i as u32;
        for _ in 0..8 {
            x = if x & 1 != 0 {
                (x >> 1) ^ 0xEDB8_8320
            } else {
                x >> 1
            };
        }
        *slot = x;
    }
    let mut inverse = [0u8; 256];
    let mut seen = [false; 256];
    for (i, &entry) in table.iter().enumerate() {
        let top = (entry >> 24) as usize;
        assert!(!seen[top], "the top byte of the table is a permutation");
        seen[top] = true;
        inverse[top] = i as u8;
    }
    (table, inverse)
}

/// One step of the register: consume `byte`.
fn crc_step(table: &[u32; 256], register: u32, byte: u8) -> u32 {
    (register >> 8) ^ table[((register ^ u32::from(byte)) & 0xFF) as usize]
}

/// A byte string of `len` bytes whose CRC32 is `crc32`: a stand-in for a
/// program with that fingerprint, which is the whole of what a definition
/// tells the reader (section 3.4).
///
/// The first `len - 4` bytes are a fixed arithmetic pattern of this
/// project's choosing; the last four are solved for. The solution is the
/// plain algebra of the reflected CRC: after four more bytes the register
/// holds `T[u0] >> 24 ^ T[u1] >> 16 ^ T[u2] >> 8 ^ T[u3]` and nothing at
/// all of what came before, where `u_k` is the byte XORed into the
/// register's low byte at step `k`. Only `T[u3]` reaches bits 24 to 31,
/// only it and `T[u2]` reach bits 16 to 23, and so on, so the four `u_k`
/// come off the target one byte at a time (the top byte of the table is a
/// permutation, so a byte names its row), and each becomes a message byte
/// on the way forward.
pub(crate) fn stand_in(len: u32, crc32: u32) -> Vec<u8> {
    stand_in_from(len, crc32, None)
}

/// [`stand_in`], with the pattern's first two bytes replaced by `lead`
/// when one is given: a family of strings with one fingerprint, for
/// [`stand_in_program`] to choose among.
fn stand_in_from(len: u32, crc32: u32, lead: Option<u16>) -> Vec<u8> {
    let n = len as usize;
    assert!(n >= 4, "a fingerprint under 4 bytes has no stand-in");
    let (table, inverse) = crc_tables();
    let mut out: Vec<u8> = (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(7))
        .collect();
    if let Some(lead) = lead {
        assert!(n >= 6, "two free bytes before the four solved ones");
        out[..2].copy_from_slice(&lead.to_be_bytes());
    }

    // Peel the four solved bytes off the target register, highest first.
    let mut u = [0u8; 4];
    let mut peeled = crc32 ^ 0xFFFF_FFFF;
    for j in 0..4 {
        let row = inverse[((peeled >> (24 - 8 * j)) & 0xFF) as usize];
        u[3 - j] = row;
        peeled ^= table[row as usize] >> (8 * j);
    }
    assert_eq!(peeled, 0, "four bytes cover every 32-bit register");

    let mut register = out[..n - 4]
        .iter()
        .fold(0xFFFF_FFFFu32, |r, &b| crc_step(&table, r, b));
    for (k, &want) in u.iter().enumerate() {
        let byte = want ^ (register & 0xFF) as u8;
        out[n - 4 + k] = byte;
        register = crc_step(&table, register, byte);
    }
    assert_eq!(register ^ 0xFFFF_FFFF, crc32, "the stand-in's fingerprint");
    out
}

/// A stand-in for `program`: the length and CRC32 its row of the
/// fingerprint table names and a zero XOR of all its bytes, which is the
/// whole of what makes a definition that program (section 3.4), over
/// bytes that are this project's own.
///
/// The CRC32 is solved for; the XOR is searched for, over the strings of
/// that fingerprint that differ in their first two bytes. One in 256 of
/// them has it, so the first is found within a few hundred.
pub(crate) fn stand_in_program(program: StandardProgram) -> Vec<u8> {
    let (len, crc32) = program.fingerprint();
    (0..=u16::MAX)
        .map(|lead| stand_in_from(len, crc32, Some(lead)))
        .find(|made| made.iter().fold(0, |xor, byte| xor ^ byte) == 0)
        .expect("a string of this fingerprint whose bytes XOR to zero")
}

// ---------------------------------------------------------------------------
// The record builder
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct BuiltSlot {
    program: StandardProgram,
    len: u32,
}

/// The slot table of the stream being built.
#[derive(Debug, Default)]
pub(crate) struct RecordBuilder {
    slots: Vec<BuiltSlot>,
    last: u32,
    started: bool,
}

impl RecordBuilder {
    /// A builder for a fresh stream.
    pub(crate) fn new() -> RecordBuilder {
        RecordBuilder::default()
    }

    /// Build one record, at stream position `pos`, for a filter over
    /// `[span_start, span_start + span_len)`, following every rule of
    /// section 3.9.
    pub fn record(
        &mut self,
        program: StandardProgram,
        span_start: u64,
        span_len: u32,
        pos: u64,
        params: Params,
        out: &mut impl RecordSink,
    ) -> Result<()> {
        if span_len > MAX_WRITTEN_SPAN {
            return Err(build_error("RAR 3 filter span over 65,536 bytes"));
        }
        let offset = span_start
            .checked_sub(pos)
            .ok_or_else(|| build_error("RAR 3 filter span before its record"))?;
        let registers: &[u32] = match (program, params) {
            (
                StandardProgram::X86Call | StandardProgram::X86CallJump | StandardProgram::Itanium,
                Params::None,
            ) => &[],
            (StandardProgram::Delta | StandardProgram::Audio, Params::Channels(n)) if n >= 1 => {
                &[n]
            }
            (StandardProgram::Rgb, Params::Rgb { width, red_at })
                if width >= 3 && width % 3 == 0 && width <= u32::MAX - 3 =>
            {
                &[width + 3, red_at]
            }
            _ => return Err(build_error("RAR 3 filter parameters outside their domain")),
        };

        // Which slot, and whether to define it.
        let found = self.slots.iter().position(|s| s.program == program);
        let (slot, defines) = match found {
            Some(p) if self.started => (p as u32, false),
            _ => {
                if self.started && self.slots.len() >= super::SLOTS_AT_MOST {
                    return Err(build_error("more RAR 3 filter slots than a reader admits"));
                }
                (
                    if self.started {
                        self.slots.len() as u32
                    } else {
                        0
                    },
                    true,
                )
            }
        };

        let mut flags = 0u8;
        let mut body = BodyBits::default();
        if !self.started {
            // The first record of a stream resets and defines slot 0.
            flags |= 0x80;
            body.vint(0)?;
        } else if defines || slot != self.last {
            flags |= 0x80;
            body.vint(slot + 1)?;
        }
        let v = if offset >= 258 {
            flags |= 0x40;
            offset - 258
        } else {
            offset
        };
        let v = u32::try_from(v).map_err(|_| build_error("RAR 3 filter span too far ahead"))?;
        body.vint(v)?;
        let recorded = if defines {
            0
        } else {
            self.slots[slot as usize].len
        };
        if span_len != recorded {
            flags |= 0x20;
            body.vint(span_len)?;
        }
        if !registers.is_empty() {
            flags |= 0x10;
            body.put((1 << registers.len()) - 1, 7)?;
            for &r in registers {
                body.vint(r)?;
            }
        }
        if defines {
            let bytes = stand_in_program(program);
            body.vint(bytes.len() as u32)?;
            for &b in &bytes {
                body.put(u32::from(b), 8)?;
            }
        }
        body.emit(flags, out)?;

        if !self.started {
            self.slots.clear();
            self.started = true;
        }
        if defines {
            self.slots.push(BuiltSlot {
                program,
                len: span_len,
            });
        } else {
            self.slots[slot as usize].len = span_len;
        }
        self.last = slot;
        Ok(())
    }
}

impl RecordSink for Vec<u8> {
    fn put_byte(&mut self, byte: u8) -> Result<()> {
        self.push(byte);
        Ok(())
    }
}
