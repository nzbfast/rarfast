//! Encrypted headers (spec K 3.6.3 and 3.7.5), for the header walkers of
//! spec F and the writers of spec G.
//!
//! RAR 4 family: `salt (8) | AES-128-CBC(header, zero-padded to 16)`, a
//! fresh chain from the (password, salt) IV per block. RAR 5:
//! `IV (16) | AES-256-CBC(header, zero-padded to 16)`, a fresh chain from
//! each header's own IV. The data area after a header is not covered.

use aes::cipher::KeyInit;
use aes::{Aes128Dec, Aes128Enc, Aes256Dec, Aes256Enc};
use zeroize::Zeroizing;

use super::cbc::{decrypt_run, encrypt_run};

use super::rar5::read_vint;
use super::{KeyCache, Rar4Key, Rar5Cipher, Rar5Keys};
use crate::error::{Corruption, Error, ErrorKind, Result};
use crate::source::RangeSource;
use crate::types::Password;

/// The RAR 5 header size limit (the technote's 3-byte vint, 2 MiB).
pub const RAR5_MAX_HEADER: u64 = 2 << 20;

fn corrupt() -> Error {
    Error::new(ErrorKind::Corrupt(Corruption::Header))
}

/// A header is padded to a whole number of blocks; anything else is
/// `Corrupt` before a byte is touched.
fn whole_blocks(buf: &[u8]) -> Result<()> {
    if !buf.len().is_multiple_of(16) {
        return Err(corrupt());
    }
    Ok(())
}

// The walk (`HeaderReader::rar4_from`, `rar5_from`) deciphers on the
// schedule the key cache holds (`Rar4Cipher`, `Rar5Cipher`, expanded once
// per derived key) and the writer on the schedule it holds
// (`*_encrypt_header_with`): neither expands a key per header. The
// key-taking functions below expand one per call, for the tests, the
// fuzz targets and the test walker.

/// Decrypt the first ciphertext block of a RAR 4 encrypted header, to
/// learn its size (plaintext bytes 5..7).
// The walk opens a header on the cache's schedule (`HeaderReader`); this
// form serves the tests and the `internals_*` seam.
#[allow(dead_code)]
pub fn rar4_open_header(key: &Rar4Key, first_block: [u8; 16]) -> [u8; 16] {
    let mut block = first_block;
    decrypt_run(&Aes128Dec::new(&key.key.into()), key.iv, &mut block);
    block
}

/// Decrypt a whole padded RAR 4 header in place, one chain from the IV.
// The walk deciphers a header as one chain in `HeaderReader`; this whole-
// header form is reached from the tests and the `internals_*` seam.
#[allow(dead_code)]
pub fn rar4_decrypt_header(key: &Rar4Key, padded: &mut [u8]) -> Result<()> {
    whole_blocks(padded)?;
    decrypt_run(&Aes128Dec::new(&key.key.into()), key.iv, padded);
    Ok(())
}

/// Encrypt a zero-padded RAR 4 header in place, expanding the key's
/// encryption schedule for this one call (tests and tools; the writer
/// holds its schedule and calls [`rar4_encrypt_header_with`]).
// Reached from the tests, the test walker and the `internals_*` seam.
#[allow(dead_code)]
pub fn rar4_encrypt_header(key: &Rar4Key, padded: &mut [u8]) -> Result<()> {
    rar4_encrypt_header_with(&Aes128Enc::new(&key.key.into()), key, padded)
}

/// Encrypt a zero-padded RAR 4 header in place under `enc`, the
/// encryption schedule of `key`, from the key's IV (writer).
pub(crate) fn rar4_encrypt_header_with(
    enc: &Aes128Enc,
    key: &Rar4Key,
    padded: &mut [u8],
) -> Result<()> {
    whole_blocks(padded)?;
    encrypt_run(enc, key.iv, padded);
    Ok(())
}

/// Decrypt the first ciphertext block of a RAR 5 encrypted header.
// The walk opens a header on the cache's schedule (`HeaderReader`); this
// form serves the tests and the `internals_*` seam.
#[allow(dead_code)]
pub fn rar5_open_header(keys: &Rar5Keys, iv: &[u8; 16], first_block: [u8; 16]) -> [u8; 16] {
    let mut block = first_block;
    decrypt_run(&Aes256Dec::new(&keys.key.into()), *iv, &mut block);
    block
}

/// Decrypt a whole padded RAR 5 header in place, one chain from `iv`.
// The walk deciphers a header as one chain in `HeaderReader`; this whole-
// header form is reached from the tests and the `internals_*` seam.
#[allow(dead_code)]
pub fn rar5_decrypt_header(keys: &Rar5Keys, iv: &[u8; 16], padded: &mut [u8]) -> Result<()> {
    whole_blocks(padded)?;
    decrypt_run(&Aes256Dec::new(&keys.key.into()), *iv, padded);
    Ok(())
}

/// Encrypt a zero-padded RAR 5 header in place, expanding the key's
/// encryption schedule for this one call (tests and tools; the writer
/// holds its schedule and calls [`rar5_encrypt_header_with`]).
// Reached from the tests, the test walker and the `internals_*` seam.
#[allow(dead_code)]
pub fn rar5_encrypt_header(keys: &Rar5Keys, iv: &[u8; 16], padded: &mut [u8]) -> Result<()> {
    rar5_encrypt_header_with(&Aes256Enc::new(&keys.key.into()), iv, padded)
}

/// Encrypt a zero-padded RAR 5 header in place under `enc`, the key's
/// encryption schedule, one chain from `iv` (writer).
pub(crate) fn rar5_encrypt_header_with(
    enc: &Aes256Enc,
    iv: &[u8; 16],
    padded: &mut [u8],
) -> Result<()> {
    whole_blocks(padded)?;
    encrypt_run(enc, *iv, padded);
    Ok(())
}

/// Where a RAR 4 encrypted header block sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rar4HeaderSpan {
    /// The header's own size (plaintext bytes 5..7).
    pub size: u16,
    /// The first byte after the padded ciphertext: the data area, if any.
    pub end: u64,
}

/// Where a RAR 5 encrypted header sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rar5HeaderSpan {
    /// `4 + len(size vint) + size`: the plaintext header length.
    pub len: usize,
    /// The first byte after the padded ciphertext.
    pub end: u64,
}

fn round16(n: u64) -> u64 {
    (n + 15) & !15
}

/// Read exactly `buf.len()` bytes at `offset`; a short source is
/// `Truncated`, a source error is `Source`.
fn read_exact_at(src: &dyn RangeSource, mut offset: u64, mut buf: &mut [u8]) -> Result<()> {
    while !buf.is_empty() {
        match src.read_at(offset, buf) {
            Ok(0) => return Err(Error::new(ErrorKind::Truncated)),
            Ok(n) => {
                let n = n.min(buf.len());
                buf = &mut buf[n..];
                offset += n as u64;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(Error::new(ErrorKind::Source(e)).with_offset(offset)),
        }
    }
    Ok(())
}

/// Where an encrypted header's bytes are read from: a source read
/// directly (the tests, the fuzz targets, the test walker), or the walk's
/// own buffered window (`read::cursor`), which serves a header from bytes
/// it already holds where a direct read is two reads of the source per
/// header.
pub(crate) trait HeaderBytes {
    /// Fill `buf` from `at`: a short source is `Truncated`, a source error
    /// is `Source`.
    fn read_exact_at(&mut self, at: u64, buf: &mut [u8]) -> Result<()>;
}

impl HeaderBytes for &dyn RangeSource {
    fn read_exact_at(&mut self, at: u64, buf: &mut [u8]) -> Result<()> {
        read_exact_at(*self, at, buf)
    }
}

/// One header decrypt buffer per walk, reused across headers and zeroed on
/// drop: at most 65,536 bytes (RAR 4) or 2 MiB + 16 (RAR 5).
#[derive(Default)]
pub struct HeaderReader {
    buf: Zeroizing<Vec<u8>>,
    len: usize,
}

impl HeaderReader {
    /// A reader with no buffer yet.
    pub fn new() -> Self {
        HeaderReader::default()
    }

    /// The plaintext of the last header read (its own length, no padding).
    pub fn plain(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Put the first block's PLAINTEXT, already deciphered to learn the
    /// size, at the front, then read the rest of the padded ciphertext
    /// (from `at`) behind it. The caller deciphers `buf[16..padded]`
    /// continuing the chain from the first block's ciphertext, so no
    /// block of a header is deciphered twice.
    fn fill(
        &mut self,
        src: &mut impl HeaderBytes,
        at: u64,
        open: &[u8; 16],
        padded: usize,
    ) -> Result<()> {
        if self.buf.len() < padded {
            // Grow to the largest size seen; the old buffer zeroes on drop.
            self.buf = Zeroizing::new(vec![0u8; padded]);
        }
        self.buf[..16].copy_from_slice(open);
        src.read_exact_at(at, &mut self.buf[16..padded])
    }

    /// Read and decrypt the RAR 4 family encrypted header block at `pos`
    /// (its salt first). Checks the CRC16 on the plaintext: a mismatch is
    /// `HeaderChecksum`, which is also how a wrong password shows (3.6.4).
    // The walk reads through its window (`rar4_from`, `rar5_from`); this
    // direct form serves the tests, the fuzz targets and the test walker.
    #[allow(dead_code)]
    pub fn rar4(
        &mut self,
        mut src: &dyn RangeSource,
        pos: u64,
        password: &Password,
        cache: &mut KeyCache,
    ) -> Result<Rar4HeaderSpan> {
        self.rar4_from(&mut src, pos, password, cache)
    }

    /// [`HeaderReader::rar4`] over any [`HeaderBytes`]. A password with a
    /// character outside the basic plane is tried under both readings of
    /// spec B 3.2, the observed one first.
    pub(crate) fn rar4_from(
        &mut self,
        src: &mut impl HeaderBytes,
        pos: u64,
        password: &Password,
        cache: &mut KeyCache,
    ) -> Result<Rar4HeaderSpan> {
        cache.rar4_either_reading(password, |cache| self.rar4_under(src, pos, password, cache))
    }

    /// One reading of the encrypted header at `pos`, under the key the
    /// cache gives for its salt.
    fn rar4_under(
        &mut self,
        src: &mut impl HeaderBytes,
        pos: u64,
        password: &Password,
        cache: &mut KeyCache,
    ) -> Result<Rar4HeaderSpan> {
        self.len = 0;
        let mut head = [0u8; 24];
        src.read_exact_at(pos, &mut head)?;
        let mut salt = [0u8; 8];
        salt.copy_from_slice(&head[..8]);
        let key = cache.rar4_cipher(password, Some(salt))?;
        let mut first = [0u8; 16];
        first.copy_from_slice(&head[8..]);
        let mut open = first;
        key.run(key.key.iv, &mut open);
        // A first block whose type byte names no RAR 4 block cannot be a
        // header: that is how a wrong password shows, and it is named as
        // the failed header check of 3.6.4 rather than as whatever the
        // garbage size field would imply (too small, or past the end).
        if !(0x72..=0x7B).contains(&open[2]) {
            return Err(Error::new(ErrorKind::HeaderChecksum).with_offset(pos));
        }
        let size = u16::from_le_bytes([open[5], open[6]]);
        if size < 7 {
            return Err(corrupt().with_offset(pos));
        }
        let padded = round16(u64::from(size)) as usize;
        self.fill(src, pos + 24, &open, padded)?;
        key.run(first, &mut self.buf[16..padded]);
        let plain = &self.buf[..usize::from(size)];
        let crc = crc32fast::hash(&plain[2..]) as u16;
        if crc != u16::from_le_bytes([plain[0], plain[1]]) {
            return Err(Error::new(ErrorKind::HeaderChecksum).with_offset(pos));
        }
        self.len = usize::from(size);
        Ok(Rar4HeaderSpan {
            size,
            end: pos + 8 + padded as u64,
        })
    }

    /// Read and decrypt the RAR 5 encrypted header at `pos` (its IV first).
    /// The size is bounded (2 MiB) before any allocation; the CRC32 over
    /// the plaintext is checked (`HeaderChecksum`).
    // The walk reads through its window (`rar4_from`, `rar5_from`); this
    // direct form serves the tests, the fuzz targets and the test walker.
    #[allow(dead_code)]
    pub fn rar5(
        &mut self,
        mut src: &dyn RangeSource,
        pos: u64,
        keys: &Rar5Keys,
    ) -> Result<Rar5HeaderSpan> {
        self.rar5_from(&mut src, pos, &Rar5Cipher::new(keys.clone()))
    }

    /// [`HeaderReader::rar5`] over any [`HeaderBytes`].
    pub(crate) fn rar5_from(
        &mut self,
        src: &mut impl HeaderBytes,
        pos: u64,
        keys: &Rar5Cipher,
    ) -> Result<Rar5HeaderSpan> {
        self.len = 0;
        let mut head = [0u8; 32];
        src.read_exact_at(pos, &mut head)?;
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&head[..16]);
        let mut first = [0u8; 16];
        first.copy_from_slice(&head[16..]);
        let mut open = first;
        keys.run(iv, &mut open);
        let mut at = 4;
        let size = read_vint(&open[..4 + 3], &mut at).ok_or_else(|| corrupt().with_offset(pos))?;
        if size == 0 || size > RAR5_MAX_HEADER {
            return Err(corrupt().with_offset(pos));
        }
        let len = at as u64 + size;
        let padded = round16(len) as usize;
        self.fill(src, pos + 32, &open, padded)?;
        keys.run(first, &mut self.buf[16..padded]);
        let len = len as usize;
        let plain = &self.buf[..len];
        if crc32fast::hash(&plain[4..])
            != u32::from_le_bytes([plain[0], plain[1], plain[2], plain[3]])
        {
            return Err(Error::new(ErrorKind::HeaderChecksum).with_offset(pos));
        }
        self.len = len;
        Ok(Rar5HeaderSpan {
            len,
            end: pos + 16 + padded as u64,
        })
    }
}
