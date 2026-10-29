//! Work package K: crypto (spec K). The member decryptor for every format,
//! the RAR 4 family and RAR 5 key derivations and their per-session cache,
//! header decryption for the header walkers, and the writers' AES-CBC.
//!
//! Primitives are RustCrypto's (`aes`, `cbc`, `sha1`, `sha2`, `hmac`); the
//! glue here is this package's whole cryptographic content. No `unsafe`,
//! except the writers' AES-CBC chain in `armv8` and `x86`, five argued
//! items in each (SPEC-K 2.1).
//! Every key, IV and derived value zeroises on drop, and no `Debug` output
//! or error carries one.

/// `Debug` for types holding key material: the type's name and nothing
/// of its bytes, so no log line or panic message carries a secret.
macro_rules! redacted_debug {
    ($($t:ident),+) => {$(
        impl std::fmt::Debug for $t {
            fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                out.pad(concat!(stringify!($t), "(..)"))
            }
        }
    )+};
}
pub(crate) use redacted_debug;

#[cfg(target_arch = "aarch64")]
mod armv8;
#[cfg(target_arch = "aarch64")]
mod armv8_dec;
pub(crate) mod cbc;
pub(crate) mod header;
mod legacy;
#[cfg(target_arch = "aarch64")]
mod pbkdf2_armv8;
#[cfg(target_arch = "x86_64")]
mod pbkdf2_x86;
mod rar4;
mod rar5;
#[cfg(test)]
mod tests;
#[cfg(target_arch = "x86_64")]
mod x86;
#[cfg(target_arch = "x86_64")]
mod x86_dec;

// The member decryptors' own chain where the machine has the instructions
// for one: the same two entry points on either architecture.
#[cfg(target_arch = "aarch64")]
use armv8_dec as wide_dec;
#[cfg(target_arch = "x86_64")]
use x86_dec as wide_dec;

use aes::cipher::consts::U16;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes::{Aes128Dec, Aes256Dec};

use self::cbc::{CbcDec, CbcEnc};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Corruption, Error, ErrorKind, Result, Unsupported};
use crate::read::Format;
use crate::types::Password;

// Re-exported for spec F's walkers, spec G's writers, the benches and the
// fuzz targets; not every item has a caller in every build yet.
#[allow(unused_imports)]
pub use header::{
    rar4_decrypt_header, rar4_encrypt_header, rar4_open_header, rar5_decrypt_header,
    rar5_encrypt_header, rar5_open_header, HeaderReader, Rar4HeaderSpan, Rar5HeaderSpan,
    RAR5_MAX_HEADER,
};
pub use legacy::{Rar13Stream, Rar15Stream, Rar20Block};
#[allow(unused_imports)]
pub use rar4::{readings_differ, Astral, NonUtf8Password, Rar4Key};
#[allow(unused_imports)]
pub use rar5::{cuts_differ, Cut, Rar5Keys, Rar5Record, FLAG_CHECK, FLAG_MAC, MAX_LOG2};

type Aes128Cbc = CbcDec<Aes128Dec>;
type Aes256Cbc = CbcDec<Aes256Dec>;

/// How many characters of a password enter a key derivation: the RAR 3
/// and RAR 5 formats use the first 127 and no more (spec K 3.7.1, spec B
/// 3.2). The unit is the code point.
pub const PASSWORD_CHARS: usize = 127;

/// The part of a password any cipher uses: up to, and not including, its
/// first zero byte (SPEC-API 4.5, as the genuine programs read one, so an
/// archive opens in both under the same password). Every cipher's setup
/// and both key derivations take their bytes through this, reading and
/// writing alike; what follows the zero byte is not looked at.
pub(crate) fn until_zero_byte(password: &[u8]) -> &[u8] {
    match password.iter().position(|&byte| byte == 0) {
        Some(end) => &password[..end],
        None => password,
    }
}

/// The part of `text` a derivation uses: its first [`PASSWORD_CHARS`]
/// characters.
pub(crate) fn used_text(text: &str) -> &str {
    match text.char_indices().nth(PASSWORD_CHARS) {
        Some((end, _)) => &text[..end],
        None => text,
    }
}

fn corrupt() -> Error {
    Error::new(ErrorKind::Corrupt(Corruption::Stream))
}

/// A RAR 3/4 password that is not UTF-8 on the read side: no archive of
/// the family can have been made with it (2.3).
pub fn rar4_derive_read(
    password: &[u8],
    salt: Option<[u8; 8]>,
    reading: Astral,
) -> Result<Rar4Key> {
    Rar4Key::derive_reading(password, salt, reading)
        .map_err(|_| Error::new(ErrorKind::WrongPassword))
}

/// The writer's check that a RAR 4 family password can be written (2.3):
/// `Writer::new` calls it before any output.
pub fn rar4_check_write_password(password: &Password) -> Result<()> {
    std::str::from_utf8(until_zero_byte(password.as_bytes()))
        .map(|_| ())
        .map_err(|_| {
            Error::new(ErrorKind::Unsupported(Unsupported::WriteFeature(
                "a RAR 4 family password must be UTF-8",
            )))
        })
}

/// The cipher a RAR 1.5 to 4.x encrypted member's unpack version selects
/// (3.2); any other version is `Unsupported`.
// The read path takes `rar4_family_cipher_on` and the key cache's
// schedule; this form serves the tests and the `internals_*` seam.
#[allow(dead_code)]
pub fn rar4_family_cipher(
    unpack_version: u8,
    password: &[u8],
    key: Option<&Rar4Key>,
) -> Result<MemberCipher> {
    let cipher = key.map(|k| Rar4Cipher::new(k.clone()));
    rar4_family_cipher_on(unpack_version, password, cipher.as_ref())
}

/// [`rar4_family_cipher`] on the key cache's schedule for the key.
pub fn rar4_family_cipher_on(
    unpack_version: u8,
    password: &[u8],
    key: Option<&Rar4Cipher>,
) -> Result<MemberCipher> {
    match unpack_version {
        15 => Ok(MemberCipher::V15(Rar15Stream::new(password))),
        20 | 26 => Ok(MemberCipher::V20(Box::new(Rar20Block::new(password)))),
        v if v >= 29 => match key {
            Some(k) => Ok(MemberCipher::aes128_on(k)),
            None => Err(Error::new(ErrorKind::PasswordRequired)),
        },
        v => Err(rar5::unsupported(Format::Rar4Family, u32::from(v))),
    }
}

/// The cipher chosen once per member (3.2).
pub enum MemberCipher {
    /// Not encrypted.
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    None,
    /// RAR 1.3/1.4 stream.
    V13(Rar13Stream),
    /// RAR 1.5 stream.
    V15(Rar15Stream),
    /// RAR 2.0 block cipher.
    V20(Box<Rar20Block>),
    /// RAR 2.9 to 4.x. Unboxed, and on the key cache's schedules
    /// (`aes128_on`, `aes256_on`): no allocation per member for AES.
    Aes128Cbc(Aes128Cbc),
    /// RAR 5.
    Aes256Cbc(Aes256Cbc),
}

impl MemberCipher {
    /// AES-128-CBC from a RAR 4 family key and its IV.
    // The read path takes `aes128_on` and the key cache's schedule; this
    // form serves the tests and the `internals_*` seam.
    #[allow(dead_code)]
    pub fn aes128(key: &Rar4Key) -> Self {
        MemberCipher::Aes128Cbc(CbcDec::new_with_key(
            Aes128Dec::new(&key.key.into()),
            &key.key,
            key.iv,
        ))
    }

    /// AES-128-CBC on the schedules the key cache holds for the member's
    /// key, BORROWED and not copied: members under one salt share one
    /// expansion (spec K 3.6.2), and a member has only its chaining value
    /// to wipe when it ends ([`cbc::Schedule`]).
    pub fn aes128_on(key: &Rar4Cipher) -> Self {
        MemberCipher::Aes128Cbc(CbcDec::new_on(&key.sched, key.key.iv))
    }

    /// AES-256-CBC from RAR 5 keys and the member's IV.
    // The read path takes `aes256_on` and the key cache's schedule; this
    // form serves the tests and the `internals_*` seam.
    #[allow(dead_code)]
    pub fn aes256(keys: &Rar5Keys, iv: &[u8; 16]) -> Self {
        MemberCipher::Aes256Cbc(CbcDec::new_with_key(
            Aes256Dec::new(&keys.key.into()),
            &keys.key,
            *iv,
        ))
    }

    /// AES-256-CBC on the schedules the key cache holds for the member's
    /// keys, the ones the encrypted headers under the same salt decipher
    /// with too (spec K 3.7.4, 3.7.5): BORROWED, neither expanded nor
    /// copied, so a member has only its chaining value to wipe when it
    /// ends ([`cbc::Schedule`]).
    pub fn aes256_on(keys: &Rar5Cipher, iv: &[u8; 16]) -> Self {
        MemberCipher::Aes256Cbc(CbcDec::new_on(&keys.sched, *iv))
    }

    fn is_block(&self) -> bool {
        matches!(
            self,
            MemberCipher::V20(_) | MemberCipher::Aes128Cbc(_) | MemberCipher::Aes256Cbc(_)
        )
    }

    /// The BULK of one buffer, with the AES-CBC ciphers allowed to split
    /// it across two lanes when the caller has a width unit to spend.
    ///
    /// Only the two AES-CBC ciphers take the split. The RAR 2.0 block
    /// cipher is left serial: it is a legacy format whose members are
    /// small, and its mode is not this one. The stream ciphers have no
    /// block structure to divide at all.
    #[inline]
    fn decrypt_bulk(&mut self, buf: &mut [u8], two_lane: bool) {
        if two_lane {
            match self {
                MemberCipher::Aes128Cbc(c) => return c.decrypt_blocks_two_lane(buf),
                MemberCipher::Aes256Cbc(c) => return c.decrypt_blocks_two_lane(buf),
                _ => {}
            }
        }
        self.decrypt(buf);
    }

    /// Decrypt whole blocks (block ciphers) or every byte (streams).
    #[inline]
    fn decrypt(&mut self, buf: &mut [u8]) {
        match self {
            MemberCipher::None => {}
            MemberCipher::V13(c) => c.decrypt(buf),
            MemberCipher::V15(c) => c.apply(buf),
            MemberCipher::V20(c) => c.decrypt_blocks(buf),
            MemberCipher::Aes128Cbc(c) => c.decrypt_blocks(buf),
            MemberCipher::Aes256Cbc(c) => c.decrypt_blocks(buf),
        }
    }
}

/// Turns a member's packed bytes, in arbitrary chunks in volume order, into
/// plaintext in place. HOT PATH: no allocation, no copy of the buffer,
/// whole-buffer cipher calls.
///
/// A block cipher cannot decrypt a partial block. When a chunk ends
/// mid-block the decryptor carries those ciphertext bytes (at most 15) into
/// the next call. There, the block they start straddles the boundary: its
/// first `k` plaintext bytes come back as [`Plain::head`], from the
/// decryptor's own storage, and everything after lies in place at the
/// front of the caller's buffer. So the plaintext of one call is `head`
/// followed by `buf[..body]`, and no byte is ever shifted.
pub struct MemberDecryptor {
    cipher: MemberCipher,
    /// Ciphertext of a partial block.
    carry: [u8; 16],
    carry_len: u8,
    /// Plaintext of the straddling block that precedes the buffer.
    head: [u8; 16],
    /// Whether the bulk run of whole blocks may take a second lane.
    two_lane: bool,
}

/// A member's AES-CBC chain, shared by the threads that decipher its
/// pieces ([`MemberDecryptor::pieces`]): each piece runs from the
/// ciphertext block in front of it and touches no state of the chain.
///
/// It is a second chain on the SAME key schedules, the range's own, behind
/// a shared handle: the threads that decipher pieces are kept across ranges
/// (`read::team`) and so cannot borrow the member's decryptor, which the
/// member's own thread goes on using between ranges. It holds no copy of
/// the schedules ([`cbc::Schedule`]); its chaining value is wiped when the
/// last piece's handle drops.
#[cfg(feature = "parallel")]
#[derive(Clone)]
pub(crate) enum Pieces {
    Aes128(std::sync::Arc<Aes128Cbc>),
    Aes256(std::sync::Arc<Aes256Cbc>),
}

#[cfg(feature = "parallel")]
impl Pieces {
    /// Decrypt the whole blocks of `buf` in place from `chain` and answer
    /// their last ciphertext block ([`cbc::CbcDec::run_from`]).
    pub(crate) fn run_from(&self, chain: [u8; 16], buf: &mut [u8]) -> [u8; 16] {
        match self {
            Pieces::Aes128(c) => c.run_from(chain, buf),
            Pieces::Aes256(c) => c.run_from(chain, buf),
        }
    }
}

/// The plaintext one [`MemberDecryptor::update`] produced: `head`, then
/// the first `body` bytes of the buffer passed in.
pub struct Plain<'a> {
    /// Up to 15 bytes that come before the buffer's bytes.
    pub head: &'a [u8],
    /// How many bytes at the front of the buffer are plaintext.
    pub body: usize,
}

impl MemberDecryptor {
    /// A decryptor for one member.
    pub fn new(cipher: MemberCipher) -> Self {
        MemberDecryptor {
            cipher,
            carry: [0; 16],
            carry_len: 0,
            head: [0; 16],
            two_lane: false,
        }
    }

    /// Decrypt `buf` in place. The plaintext is `head` then `buf[..body]`;
    /// `head.len() + body <= buf.len() + 15` and `body <= buf.len()`.
    #[inline]
    pub fn update(&mut self, buf: &mut [u8]) -> Plain<'_> {
        if !self.cipher.is_block() {
            self.cipher.decrypt(buf);
            return Plain {
                head: &[],
                body: buf.len(),
            };
        }
        let k = usize::from(self.carry_len);
        let len = buf.len();
        let need = if k == 0 { 0 } else { 16 - k };
        if len < need {
            // Still no whole block: carry every byte.
            self.carry[k..k + len].copy_from_slice(buf);
            self.carry_len = (k + len) as u8;
            return Plain { head: &[], body: 0 };
        }
        let whole = (len - need) & !15;
        let tail = len - need - whole;
        // The run of whole blocks after the straddling one, in place. Its
        // CBC chaining value is the straddling block's ciphertext, so the
        // straddling block goes first.
        let head_len = if k > 0 {
            let mut block = [0u8; 16];
            block[..k].copy_from_slice(&self.carry[..k]);
            block[k..].copy_from_slice(&buf[..need]);
            self.cipher.decrypt(&mut block);
            self.head[..k].copy_from_slice(&block[..k]);
            buf[..need].copy_from_slice(&block[k..]);
            block.zeroize();
            k
        } else {
            0
        };
        self.carry[..tail].copy_from_slice(&buf[need + whole..]);
        self.carry_len = tail as u8;
        self.cipher
            .decrypt_bulk(&mut buf[need..need + whole], self.two_lane);
        Plain {
            head: &self.head[..head_len],
            body: need + whole,
        }
    }

    /// Spend a SECOND LANE on the bulk of each buffer, or stop.
    ///
    /// Off by default, so no caller gets a thread it did not ask for.
    /// The one caller that turns it on is
    /// `read::extract::copy_overlapped`, where `overlap_plan` has
    /// already found the width to spend and the member is large enough
    /// to be worth the arrangement; everything else decrypts on the
    /// thread that called it, exactly as before.
    ///
    /// It moves the ARRANGEMENT and never the bytes: see
    /// [`cbc::CbcDec::decrypt_blocks_two_lane`], and the tests that pin
    /// the two forms against each other at every length.
    // The lib's own caller is behind `parallel`, so a build without that
    // feature has none and reaches this only through the `internals_*`
    // seam, from `crypto::tests` and the `k_two_lane_cbc` fuzz target.
    #[allow(dead_code)]
    pub fn set_two_lane(&mut self, on: bool) {
        self.two_lane = on;
    }

    /// Whether the cipher is one of the AES-CBC pair, whose runs may be
    /// deciphered in pieces ([`MemberDecryptor::pieces`]).
    #[cfg(feature = "parallel")]
    pub(crate) fn is_cbc(&self) -> bool {
        matches!(
            self.cipher,
            MemberCipher::Aes128Cbc(_) | MemberCipher::Aes256Cbc(_)
        )
    }

    /// The chain lent to a reader that deciphers the next whole blocks of
    /// the member in pieces on several threads, with the chaining value the
    /// first piece starts from; `None` when the cipher is not AES-CBC or a
    /// partial block is carried, where only [`MemberDecryptor::update`] may
    /// go on. `len` is the run's length, so the chain can be made ready for
    /// runs of it before it is shared. The caller hands back the last
    /// ciphertext block of the bytes it deciphered with
    /// [`MemberDecryptor::resume`].
    #[cfg(feature = "parallel")]
    pub(crate) fn pieces(&mut self, len: usize) -> Option<(Pieces, [u8; 16])> {
        if self.carry_len != 0 {
            return None;
        }
        match &mut self.cipher {
            MemberCipher::Aes128Cbc(c) => {
                c.prepare(len);
                Some((Pieces::Aes128(std::sync::Arc::new(c.share())), c.chain()))
            }
            MemberCipher::Aes256Cbc(c) => {
                c.prepare(len);
                Some((Pieces::Aes256(std::sync::Arc::new(c.share())), c.chain()))
            }
            _ => None,
        }
    }

    /// Carry on after whole blocks [`MemberDecryptor::pieces`] lent the
    /// chain for, from `chain`, their last ciphertext block.
    #[cfg(feature = "parallel")]
    pub(crate) fn resume(&mut self, chain: [u8; 16]) {
        debug_assert_eq!(self.carry_len, 0);
        match &mut self.cipher {
            MemberCipher::Aes128Cbc(c) => c.set_chain(chain),
            MemberCipher::Aes256Cbc(c) => c.set_chain(chain),
            _ => debug_assert!(false, "pieces lends only an AES-CBC chain"),
        }
    }

    /// Ciphertext bytes carried into the next call: exactly the length of
    /// the `head` that call will return when it completes the block. A
    /// caller that keeps plaintext contiguous reserves this much room in
    /// front of the next buffer.
    pub fn pending(&self) -> usize {
        usize::from(self.carry_len)
    }

    /// The next volume's fragment of the SAME member starts: only the RAR
    /// 1.3 keystream restarts (3.3); every other state carries on.
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    pub fn next_fragment(&mut self) {
        if let MemberCipher::V13(c) = &mut self.cipher {
            c.restart();
        }
    }

    /// End of the member's packed bytes: `Corrupt` when a partial block is
    /// left (the total was not a multiple of 16).
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    pub fn finish(self) -> Result<()> {
        if self.carry_len != 0 {
            return Err(corrupt());
        }
        Ok(())
    }
}

impl Drop for MemberDecryptor {
    fn drop(&mut self) {
        self.carry.zeroize();
        self.head.zeroize();
    }
}

/// The chain a writer's cipher drives: the AES instructions directly
/// where the machine has them (the ARMv8 ones through `armv8`,
/// AES-NI through `x86`), and the `aes` crate through [`CbcEnc`]
/// everywhere else, including an x86-64 part without AES-NI. They give
/// the same bytes, which `crypto::tests` holds against the `aes` and
/// `cbc` crates at every key size and tile edge.
enum EncChain<C> {
    Crate(CbcEnc<C>),
    #[cfg(target_arch = "aarch64")]
    Armv8(Box<armv8::Chain>),
    #[cfg(target_arch = "x86_64")]
    X86(Box<x86::Chain>),
}

impl<C: BlockCipherEncrypt<BlockSize = U16>> EncChain<C> {
    /// The instructions' chain when this machine has them, otherwise the
    /// crate's, built by `fallback` only when it is the one used.
    fn new(key: &[u8], iv: [u8; 16], fallback: impl FnOnce() -> C) -> Self {
        #[cfg(target_arch = "aarch64")]
        if let Some(chain) = armv8::Chain::new(key, iv) {
            return EncChain::Armv8(Box::new(chain));
        }
        #[cfg(target_arch = "x86_64")]
        if let Some(chain) = x86::Chain::new(key, iv) {
            return EncChain::X86(Box::new(chain));
        }
        let _ = key;
        EncChain::Crate(CbcEnc::new(fallback(), iv))
    }

    /// Which chain was selected, for the test that pins the choice.
    #[cfg(test)]
    fn kind(&self) -> &'static str {
        match self {
            EncChain::Crate(_) => "crate",
            #[cfg(target_arch = "aarch64")]
            EncChain::Armv8(_) => "armv8",
            #[cfg(target_arch = "x86_64")]
            EncChain::X86(_) => "x86",
        }
    }

    fn blocks(&mut self, buf: &mut [u8]) {
        match self {
            EncChain::Crate(chain) => chain.encrypt_blocks(buf),
            #[cfg(target_arch = "aarch64")]
            EncChain::Armv8(chain) => chain.encrypt_blocks(buf),
            #[cfg(target_arch = "x86_64")]
            EncChain::X86(chain) => chain.encrypt_blocks(buf),
        }
    }

    fn restart(&mut self, iv: [u8; 16]) {
        match self {
            EncChain::Crate(chain) => chain.restart(iv),
            #[cfg(target_arch = "aarch64")]
            EncChain::Armv8(chain) => chain.restart(iv),
            #[cfg(target_arch = "x86_64")]
            EncChain::X86(chain) => chain.restart(iv),
        }
    }

    fn blocks_from(&mut self, src: &[u8], dst: &mut [u8]) {
        match self {
            EncChain::Crate(chain) => chain.encrypt_blocks_from(src, dst),
            #[cfg(target_arch = "aarch64")]
            EncChain::Armv8(chain) => chain.encrypt_blocks_from(src, dst),
            #[cfg(target_arch = "x86_64")]
            EncChain::X86(chain) => chain.encrypt_blocks_from(src, dst),
        }
    }
}

/// AES-128-CBC encryption for the RAR 4 writer, in place.
pub struct Aes128Enc(EncChain<aes::Aes128Enc>);
/// AES-256-CBC encryption for the RAR 5 writer, in place.
pub struct Aes256Enc(EncChain<aes::Aes256Enc>);

impl Aes128Enc {
    /// Start a fresh chain from `iv` under the same expanded key, for a
    /// writer that enciphers many short chains under one key (its
    /// encrypted headers): the key is expanded once, not per chain.
    pub fn restart(&mut self, iv: &[u8; 16]) {
        self.0.restart(*iv);
    }

    /// A chain from the key's own IV.
    pub fn new(key: &Rar4Key) -> Self {
        Aes128Enc(EncChain::new(&key.key, key.iv, || {
            aes::Aes128Enc::new(&key.key.into())
        }))
    }

    /// Encrypt whole blocks; a length that is not a multiple of 16 is
    /// refused and nothing is changed.
    pub fn encrypt(&mut self, buf: &mut [u8]) -> Result<()> {
        if !buf.len().is_multiple_of(16) {
            return Err(corrupt());
        }
        self.0.blocks(buf);
        Ok(())
    }

    /// Encrypt the whole blocks of `src` into `dst`, the chain carried
    /// exactly as [`encrypt`](Self::encrypt) carries it. Lengths that
    /// differ, or that are not a multiple of 16, are refused and nothing
    /// is changed.
    pub fn encrypt_from(&mut self, src: &[u8], dst: &mut [u8]) -> Result<()> {
        if src.len() != dst.len() || !src.len().is_multiple_of(16) {
            return Err(corrupt());
        }
        self.0.blocks_from(src, dst);
        Ok(())
    }
}

impl Aes256Enc {
    /// Start a fresh chain from `iv` under the same expanded key, for a
    /// writer that enciphers many short chains under one key (its
    /// encrypted headers): the key is expanded once, not per chain.
    pub fn restart(&mut self, iv: &[u8; 16]) {
        self.0.restart(*iv);
    }

    /// A chain from `iv` under the RAR 5 key.
    pub fn new(keys: &Rar5Keys, iv: &[u8; 16]) -> Self {
        Aes256Enc(EncChain::new(&keys.key, *iv, || {
            aes::Aes256Enc::new(&keys.key.into())
        }))
    }

    /// Encrypt whole blocks; see [`Aes128Enc::encrypt`].
    pub fn encrypt(&mut self, buf: &mut [u8]) -> Result<()> {
        if !buf.len().is_multiple_of(16) {
            return Err(corrupt());
        }
        self.0.blocks(buf);
        Ok(())
    }

    /// Encrypt the whole blocks of `src` into `dst`, the chain carried
    /// exactly as [`encrypt`](Self::encrypt) carries it. Lengths that
    /// differ, or that are not a multiple of 16, are refused and nothing
    /// is changed.
    pub fn encrypt_from(&mut self, src: &[u8], dst: &mut [u8]) -> Result<()> {
        if src.len() != dst.len() || !src.len().is_multiple_of(16) {
            return Err(corrupt());
        }
        self.0.blocks_from(src, dst);
        Ok(())
    }
}

/// RAR 5 keys as the key cache holds them: the three derived values
/// and the AES-256 DECRYPTION SCHEDULE of the key, expanded once per
/// derivation.
///
/// Every encrypted header of an archive and every member under the same
/// salt deciphers on this one schedule (spec K 3.7.4 and 3.7.5): expanding
/// it per header was two FIPS 197 expansions a header, most of what a
/// 20,000-member `-hp` listing paid (counted 30 Sep
/// 2026). It is a [`cbc::Schedule`] behind a shared handle, made once and
/// never moved: the cache's boxed slot holds the handle, every member
/// under the key borrows through another, and the schedules are zeroised
/// when the last handle goes, which is the slot's own end (spec K 3.8)
/// unless a member is still deciphering on them: the `aes` crate clears
/// its schedule on drop and the wide chain clears its own. A member
/// copied them and wiped its copy until 13 Oct 2026, 1,208 bytes a member
/// on aarch64 (counted). It is NOT inside [`Rar5Keys`], which members carry inline for
/// the MAC: eight bytes more there cost every member of a CLEAR archive
/// about 195 instructions of moves on x86-64 (counted 30 Sep
/// 2026).
///
/// On an x86-64 part with VAES it also holds the key's WIDE chain
/// (`x86_dec`), inverted once: the `aes` crate's per-call path
/// there broadcasts the schedule to 512-bit registers on every call, which
/// a header of a few blocks pays twice, and a member large enough for the
/// wide chain inverted its own. Headers and members decipher on it.
///
/// `Clone` copies the derived values and takes another handle on the same
/// schedules.
#[derive(Clone)]
pub struct Rar5Cipher {
    pub(crate) keys: Rar5Keys,
    pub(crate) sched: std::sync::Arc<cbc::Schedule<Aes256Dec>>,
}

/// The RAR 4 family key as the key cache holds it: the key, its IV and
/// the AES-128 decryption schedule of the key, expanded once (see
/// [`Rar5Cipher`], whose wide chain this holds too).
pub struct Rar4Cipher {
    pub(crate) key: Rar4Key,
    pub(crate) sched: std::sync::Arc<cbc::Schedule<Aes128Dec>>,
}

redacted_debug!(Rar5Cipher, Rar4Cipher);

impl Rar5Cipher {
    /// The keys, and their schedule expanded here.
    pub fn new(keys: Rar5Keys) -> Rar5Cipher {
        let sched = cbc::Schedule::new(Aes256Dec::new(&keys.key.into()), &keys.key);
        Rar5Cipher { keys, sched }
    }

    /// Decipher one run of whole blocks in place from `chain` on the
    /// held schedule (the wide chain where there is one), and answer its
    /// last ciphertext block.
    pub(crate) fn run(&self, chain: [u8; 16], buf: &mut [u8]) -> [u8; 16] {
        self.sched.run(chain, buf)
    }

    /// The derived values.
    pub fn keys(&self) -> &Rar5Keys {
        &self.keys
    }
}

impl Rar4Cipher {
    /// The key, and its schedule expanded here.
    pub fn new(key: Rar4Key) -> Rar4Cipher {
        let sched = cbc::Schedule::new(Aes128Dec::new(&key.key.into()), &key.key);
        Rar4Cipher { key, sched }
    }

    /// See [`Rar5Cipher::run`].
    pub(crate) fn run(&self, chain: [u8; 16], buf: &mut [u8]) -> [u8; 16] {
        self.sched.run(chain, buf)
    }

    /// The key and IV.
    // Reached from the tests and the `internals_*` seam.
    #[allow(dead_code)]
    pub fn key(&self) -> &Rar4Key {
        &self.key
    }
}

// The schedules are cleared when their last handle goes, by the `aes`
// crate's own drop (its `zeroize` feature) and the wide chain's
// (`cbc::Schedule`); these clear the derived bytes beside them.
impl Zeroize for Rar5Cipher {
    fn zeroize(&mut self) {
        self.keys.zeroize();
    }
}

impl Zeroize for Rar4Cipher {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

/// How many keys' decryption schedules ([`cbc::Schedule`]) this process
/// has MADE and how many it has WIPED, on any thread, by the counted hook
/// `cbc::wiped`: equal once every holder of a key has ended. For the test
/// that pins it after whole reads (`tests/member_cipher_wipe.rs`); no
/// shipped build carries the count.
#[cfg(feature = "test-support")]
#[cfg_attr(not(feature = "bench-internals"), allow(dead_code))]
pub fn schedules_made_and_wiped() -> (u64, u64) {
    cbc::wiped::totals()
}

/// Session key cache capacity (3.8).
pub const CACHE_SLOTS: usize = 16;

// Each slot is its own box (`KeyCache::slots`), so the larger variant
// costs no other slot anything.
#[allow(clippy::large_enum_variant)]
#[derive(Zeroize, ZeroizeOnDrop)]
enum Slot {
    Rar4 {
        salt: Option<[u8; 8]>,
        /// Derived under [`Astral::Pair`].
        pairs: bool,
        key: Rar4Cipher,
    },
    Rar5 {
        salt: [u8; 16],
        log2: u8,
        /// Derived under [`Cut::Units`].
        units: bool,
        keys: Rar5Cipher,
    },
}

/// What a session knows of which reading of [`Astral`] its RAR 3 member
/// data was keyed under (spec B 3.2).
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Rar4Reading {
    /// No member has asked yet.
    #[default]
    Unasked,
    /// The password has one reading, or one of its two has verified.
    Known,
    /// The password has two readings and nothing has verified under
    /// either.
    Open,
}

/// One per `Session`: derived keys keyed by (format, salt, exponent), the
/// password being fixed for the session. Fixed slots, each boxed so key
/// bytes never move; least-recently-used replacement; every slot zeroises
/// on eviction and on drop.
#[derive(Default)]
pub struct KeyCache {
    slots: [Option<Box<Slot>>; CACHE_SLOTS],
    used: [u64; CACHE_SLOTS],
    tick: u64,
    /// Derivations run so far (tests assert one per distinct salt).
    derivations: u64,
    cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// The session's RAR 3 keys are derived under [`Astral::Pair`]: set
    /// once an encrypted header has verified under that reading and under
    /// no other (spec B 3.2).
    rar4_pairs: bool,
    /// Whether member data still has that reading to find out.
    rar4_reading: Rar4Reading,
    /// The session's RAR 5 keys are derived under [`Cut::Units`]: set once
    /// a check record has passed under that cut and not under the other
    /// (spec K 3.7.1). It changes nothing for a password with one cut.
    rar5_units: bool,
}

impl KeyCache {
    /// An empty cache; `cancel` is polled by RAR 5 derivations.
    pub fn new(cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>) -> Self {
        KeyCache {
            cancel,
            ..KeyCache::default()
        }
    }

    /// How many derivations this cache has run.
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    pub fn derivations(&self) -> u64 {
        self.derivations
    }

    fn find(&self, hit: impl Fn(&Slot) -> bool) -> Option<usize> {
        self.slots
            .iter()
            .position(|s| s.as_deref().is_some_and(&hit))
    }

    fn touch(&mut self, i: usize) {
        self.tick += 1;
        self.used[i] = self.tick;
    }

    fn victim(&self) -> usize {
        match self.slots.iter().position(Option::is_none) {
            Some(i) => i,
            None => (0..CACHE_SLOTS).min_by_key(|&i| self.used[i]).unwrap_or(0),
        }
    }

    fn store(&mut self, slot: Slot) -> usize {
        let i = self.victim();
        // Dropping the old box zeroises it.
        self.slots[i] = Some(Box::new(slot));
        self.derivations += 1;
        self.touch(i);
        i
    }

    /// The RAR 4 family key and IV for `salt` (3.6.1).
    // The read path asks for the cipher form; this one serves the tests,
    // the fuzz targets and the `internals_*` seam.
    #[allow(dead_code)]
    pub fn rar4(&mut self, password: &Password, salt: Option<[u8; 8]>) -> Result<&Rar4Key> {
        self.rar4_cipher(password, salt).map(|c| &c.key)
    }

    /// [`KeyCache::rar4`] with the key's schedule, which the read path
    /// deciphers on.
    pub fn rar4_cipher(
        &mut self,
        password: &Password,
        salt: Option<[u8; 8]>,
    ) -> Result<&Rar4Cipher> {
        let pairs = self.rar4_pairs;
        let held = self.find(
            |s| matches!(s, Slot::Rar4 { salt: t, pairs: p, .. } if *t == salt && *p == pairs),
        );
        let i = match held {
            Some(i) => {
                self.touch(i);
                i
            }
            None => {
                let reading = if pairs { Astral::Pair } else { Astral::Low16 };
                let key = rar4_derive_read(password.as_bytes(), salt, reading)?;
                self.store(Slot::Rar4 {
                    salt,
                    pairs,
                    key: Rar4Cipher::new(key),
                })
            }
        };
        match self.slots[i].as_deref() {
            Some(Slot::Rar4 { key, .. }) => Ok(key),
            _ => Err(corrupt()),
        }
    }

    /// Run `attempt`, which verifies something deciphered with this
    /// session's RAR 3 key, under the observed reading of a character
    /// outside the basic plane and, when that does not verify and the
    /// password holds such a character, once more under the surrogate
    /// pair reading (spec B 3.2). The reading that verified is the
    /// session's from then on; when neither does, the first failure is the
    /// answer and nothing changes.
    pub(crate) fn rar4_either_reading<T>(
        &mut self,
        password: &Password,
        mut attempt: impl FnMut(&mut KeyCache) -> Result<T>,
    ) -> Result<T> {
        // Bytes deciphered under the wrong key are noise, and noise fails
        // as a bad checksum, a forbidden size or a length past the end.
        let first = match attempt(self) {
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::HeaderChecksum | ErrorKind::Corrupt(_) | ErrorKind::Truncated
                ) =>
            {
                e
            }
            other => return other,
        };
        if self.rar4_pairs || !readings_differ(password.as_bytes()) {
            return Err(first);
        }
        self.rar4_pairs = true;
        let second = attempt(self);
        if second.is_err() {
            self.rar4_pairs = false;
            return Err(first);
        }
        second
    }

    /// Whether RAR 3 member data keyed from `password` has two readings
    /// of which neither has verified yet under this cache (spec B 3.2): the
    /// one question a member's key fetch asks before it may look for the
    /// reading ([`KeyCache::rar4_either_reading`]). False from the first
    /// asking on for a password with no character outside the basic plane.
    pub(crate) fn rar4_reading_open(&mut self, password: &Password) -> bool {
        if self.rar4_reading == Rar4Reading::Unasked {
            self.rar4_reading = if !self.rar4_pairs && readings_differ(password.as_bytes()) {
                Rar4Reading::Open
            } else {
                Rar4Reading::Known
            };
        }
        self.rar4_reading == Rar4Reading::Open
    }

    /// Something has verified under the session's reading, which it now
    /// keeps: no later member looks for it again.
    pub(crate) fn rar4_reading_found(&mut self) {
        self.rar4_reading = Rar4Reading::Known;
    }

    /// The RAR 5 keys for (`salt`, `log2`) (3.7.1).
    // The read path asks for the cipher form; this one serves the tests,
    // the fuzz targets and the `internals_*` seam.
    #[allow(dead_code)]
    pub fn rar5(&mut self, password: &Password, salt: &[u8; 16], log2: u8) -> Result<&Rar5Keys> {
        self.rar5_cipher(password, salt, log2).map(|c| &c.keys)
    }

    /// [`KeyCache::rar5`] with the key's schedule, which the read path
    /// deciphers on.
    pub fn rar5_cipher(
        &mut self,
        password: &Password,
        salt: &[u8; 16],
        log2: u8,
    ) -> Result<&Rar5Cipher> {
        let i = self.rar5_slot(password, salt, log2)?;
        self.rar5_at(i)
    }

    /// [`KeyCache::rar5_cipher`], judged against the check record the
    /// member or the archive carries, when it carries one (3.7.3): a
    /// record the keys do not fit is `WrongPassword`, before any byte is
    /// deciphered.
    ///
    /// A password that the two families of the reference cut differently
    /// ([`cuts_differ`]) is judged under the session's cut and, when the
    /// record does not fit, once more under the other (3.7.1). The cut
    /// that fits is the session's from then on; when neither does, the
    /// answer is the first one and nothing changes. Every other password
    /// has one derivation.
    pub(crate) fn rar5_judged(
        &mut self,
        password: &Password,
        salt: &[u8; 16],
        log2: u8,
        check: Option<&[u8; 12]>,
    ) -> Result<&Rar5Cipher> {
        let first = self.rar5_slot(password, salt, log2)?;
        let Some(check) = check else {
            return self.rar5_at(first);
        };
        let Err(refused) = self.rar5_at(first)?.keys.judge_record(check) else {
            return self.rar5_at(first);
        };
        // A password of 127 bytes or fewer is 127 units or fewer and has
        // one cut: the refusal of every ordinary wrong password is decided
        // by its length alone, before its text is looked at.
        if password.as_bytes().len() <= PASSWORD_CHARS || !cuts_differ(password.as_bytes()) {
            return Err(refused);
        }
        self.rar5_units = !self.rar5_units;
        let second = self.rar5_slot(password, salt, log2);
        let fits = match second {
            Ok(i) => self.rar5_at(i)?.keys.judge_record(check).map(|()| i),
            Err(e) => Err(e),
        };
        match fits {
            Ok(i) => self.rar5_at(i),
            Err(e) => {
                self.rar5_units = !self.rar5_units;
                // A second derivation that was cancelled is the caller's
                // answer; a record that fits neither is the first refusal.
                Err(if matches!(e.kind(), ErrorKind::WrongPassword) {
                    refused
                } else {
                    e
                })
            }
        }
    }

    /// The slot holding the keys for (`salt`, `log2`) under the session's
    /// cut, derived when no slot holds them.
    fn rar5_slot(&mut self, password: &Password, salt: &[u8; 16], log2: u8) -> Result<usize> {
        let units = self.rar5_units;
        let found = self.find(|s| {
            matches!(s, Slot::Rar5 { salt: t, log2: l, units: u, .. }
                if t == salt && *l == log2 && *u == units)
        });
        Ok(match found {
            Some(i) => {
                self.touch(i);
                i
            }
            None => {
                let cut = if units { Cut::Units } else { Cut::Chars };
                let keys = Rar5Cipher::new(Rar5Keys::derive_cut(
                    password.as_bytes(),
                    salt,
                    log2,
                    self.cancel.as_deref(),
                    cut,
                )?);
                self.store(Slot::Rar5 {
                    salt: *salt,
                    log2,
                    units,
                    keys,
                })
            }
        })
    }

    fn rar5_at(&self, i: usize) -> Result<&Rar5Cipher> {
        match self.slots[i].as_deref() {
            Some(Slot::Rar5 { keys, .. }) => Ok(keys),
            _ => Err(corrupt()),
        }
    }
}

impl std::fmt::Debug for KeyCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyCache")
            .field("filled", &self.slots.iter().filter(|s| s.is_some()).count())
            .finish()
    }
}
