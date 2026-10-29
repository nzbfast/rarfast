//! RAR 5: key derivation, the password check record, the checksum MAC and
//! the encryption record (spec K 3.7).

use std::sync::atomic::{AtomicBool, Ordering};

use hmac::{Hmac, KeyInit, Mac};
use sha2::block_api::compress256;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Corruption, Error, ErrorKind, Result, Unsupported};
use crate::read::Format;

type HmacSha256 = Hmac<Sha256>;

super::redacted_debug!(Rar5Keys, Rar5Record);

/// The largest KDF exponent accepted (3.7.1).
pub const MAX_LOG2: u8 = 24;
/// How often, in iterations, the derivation polls its cancel flag.
const CANCEL_POLL: u32 = 1 << 16;

/// The three values one RAR 5 derivation yields.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Rar5Keys {
    pub(crate) key: [u8; 32],
    pub(crate) hash_key: [u8; 32],
    pub(crate) check: [u8; 8],
}

/// `Unsupported` for an encryption parameter this crate cannot use.
pub(crate) fn unsupported(format: Format, code: u32) -> Error {
    Error::new(ErrorKind::Unsupported(Unsupported::Encryption {
        format,
        code,
    }))
}

/// Which rule cuts a password longer than the 127 a derivation uses
/// (spec K 3.7.1). The two families of the reference programs each have
/// one, and both are genuine writers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cut {
    /// The first 127 characters (code points): the programs for Linux and
    /// macOS. This is the form a writer uses.
    Chars,
    /// The first 127 UTF-16 units, a character outside the basic plane
    /// counting as two: the programs for Windows.
    Units,
}

/// The first 127 UTF-16 units of `text`, where it is longer than that and
/// the cut falls between two characters. `None` for a text of 127 units or
/// fewer, which no rule cuts, and for one whose 127th and 128th units are
/// one character's pair: what that reading keys is not established
/// (3.7.1), and such a password stays at its first reading.
fn kept_units(text: &str) -> Option<&str> {
    let mut units = 0;
    for (at, ch) in text.char_indices() {
        if units == super::PASSWORD_CHARS {
            return Some(&text[..at]);
        }
        units += ch.len_utf16();
        if units > super::PASSWORD_CHARS {
            return None;
        }
    }
    None
}

/// Whether the two rules of [`Cut`] key `password` differently: it is
/// longer than 127 UTF-16 units and a character outside the basic plane
/// lies in the part kept (3.7.1). Every other password has one cut.
pub fn cuts_differ(password: &[u8]) -> bool {
    std::str::from_utf8(super::until_zero_byte(password))
        .is_ok_and(|text| kept_units(text).is_some_and(|kept| kept != super::used_text(text)))
}

impl Rar5Keys {
    /// Derive the key, hash key and check value (3.7.1) from the first 127
    /// characters of `password`. `log2` above 24 is `Unsupported` before
    /// any work; a set `cancel` is `Cancelled`.
    pub fn derive(
        password: &[u8],
        salt: &[u8; 16],
        log2: u8,
        cancel: Option<&AtomicBool>,
    ) -> Result<Self> {
        Self::derive_cut(password, salt, log2, cancel, Cut::Chars)
    }

    /// [`Rar5Keys::derive`] with the rule that cuts a long password named:
    /// a reader's second derivation is the one under [`Cut::Units`].
    pub fn derive_cut(
        password: &[u8],
        salt: &[u8; 16],
        log2: u8,
        cancel: Option<&AtomicBool>,
        cut: Cut,
    ) -> Result<Self> {
        if log2 > MAX_LOG2 {
            return Err(unsupported(Format::Rar5, u32::from(log2)));
        }
        // Fuzz builds are not KDF benchmarks (spec K 6).
        #[cfg(fuzzing)]
        let log2 = log2.min(4);
        // SPEC-API 4.5: the password ends at its first zero byte.
        let password = super::until_zero_byte(password);
        // Only the first 127 characters enter (3.7.1). The limit is stated
        // in characters, so bytes that are not UTF-8 are used whole.
        let password = match std::str::from_utf8(password) {
            Ok(text) => match cut {
                Cut::Chars => super::used_text(text).as_bytes(),
                Cut::Units => kept_units(text).unwrap_or(text).as_bytes(),
            },
            Err(_) => password,
        };
        #[cfg(feature = "kdf-census")]
        census(log2);
        #[cfg(feature = "kdf-arms")]
        if !kdf_blocks() {
            return Self::derive_hmac(password, salt, log2, cancel);
        }
        Self::derive_blocks(password, salt, log2, cancel)
    }

    /// The derivation driven one SHA-256 block at a time (see
    /// [`BlockPrf`]): the shipped form.
    pub(crate) fn derive_blocks(
        password: &[u8],
        salt: &[u8; 16],
        log2: u8,
        cancel: Option<&AtomicBool>,
    ) -> Result<Self> {
        let n = 1u32 << log2;
        // Every secret this derivation holds lives in `prf` and is cleared
        // once, when it drops, on every return below.
        let mut prf = BlockPrf::new(password);
        prf.first(salt);
        let mut out = Rar5Keys {
            key: [0; 32],
            hash_key: [0; 32],
            check: [0; 8],
        };
        // V_1 is held; the three runs reach V_N, V_(N+16) and V_(N+32).
        prf.run(1, n, cancel)?;
        put_words(&mut out.key, &prf.v);
        prf.run(n, n + 16, cancel)?;
        put_words(&mut out.hash_key, &prf.v);
        prf.run(n + 16, n + 32, cancel)?;
        let w = &prf.v;
        for j in 0..2 {
            let x = w[j] ^ w[j + 2] ^ w[j + 4] ^ w[j + 6];
            out.check[4 * j..4 * j + 4].copy_from_slice(&x.to_be_bytes());
        }
        Ok(out)
    }

    /// The derivation through the `hmac` crate's `Mac`, one clone and one
    /// finalize an iteration: the form this crate shipped until the block
    /// form was priced, kept for its knob cell and as the block form's
    /// permanent differential.
    #[cfg(any(test, feature = "kdf-arms"))]
    pub(crate) fn derive_hmac(
        password: &[u8],
        salt: &[u8; 16],
        log2: u8,
        cancel: Option<&AtomicBool>,
    ) -> Result<Self> {
        let n = 1u32 << log2;
        let prf = HmacSha256::new_from_slice(password).expect("HMAC takes any key length");
        let mut u = {
            let mut mac = prf.clone();
            mac.update(salt);
            mac.update(&1u32.to_be_bytes());
            mac.finalize().into_bytes()
        };
        let mut v: [u8; 32] = u.into();
        let mut out = Rar5Keys {
            key: [0; 32],
            hash_key: [0; 32],
            check: [0; 8],
        };
        let mut i = 1u32;
        loop {
            if i == n {
                out.key = v;
            } else if i == n + 16 {
                out.hash_key = v;
            } else if i == n + 32 {
                for j in 0..8 {
                    out.check[j] = v[j] ^ v[j + 8] ^ v[j + 16] ^ v[j + 24];
                }
                break;
            }
            if i.is_multiple_of(CANCEL_POLL) && cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                u.as_mut_slice().zeroize();
                v.zeroize();
                return Err(Error::new(ErrorKind::Cancelled));
            }
            let mut mac = prf.clone();
            mac.update(&u);
            u = mac.finalize().into_bytes();
            for (x, y) in v.iter_mut().zip(u.iter()) {
                *x ^= y;
            }
            i += 1;
        }
        u.as_mut_slice().zeroize();
        v.zeroize();
        Ok(out)
    }

    /// Put the check record after `body`, where a writer's encryption
    /// record has it (3.7.2): the eight bytes of the check value, then
    /// the first four of their SHA-256.
    pub fn append_check_record(&self, body: &mut Vec<u8>) {
        body.extend_from_slice(&self.check);
        body.extend_from_slice(&Sha256::digest(self.check)[..4]);
    }

    /// Judge the check record a parsed encryption record holds (3.7.3,
    /// steps 2 and 3): a value other than the derived one is
    /// `WrongPassword`. A record that fails its own checksum never comes
    /// here: [`Rar5Record::parse`] reads it as absent (step 1).
    pub fn judge_record(&self, record: &[u8; 12]) -> Result<()> {
        if !ct_eq(&record[..8], &self.check) {
            return Err(Error::new(ErrorKind::WrongPassword));
        }
        Ok(())
    }

    fn mac(&self) -> HmacSha256 {
        HmacSha256::new_from_slice(&self.hash_key).expect("HMAC takes any key length")
    }

    /// The word a header stores for an encrypted member's 32 bit
    /// checksum under this key set (3.7.6). The plain value's four
    /// bytes, low byte first, go through the MAC; the MAC's bytes are
    /// then folded by exclusive or into one four byte word, each onto
    /// the byte of the word at its own place.
    pub fn stored_word_under_key(&self, plain: u32) -> u32 {
        let mut mac = self.mac();
        mac.update(&plain.to_le_bytes());
        let mut word = [0u8; 4];
        for (place, byte) in mac.finalize().into_bytes().iter().enumerate() {
            word[place % 4] ^= byte;
        }
        u32::from_le_bytes(word)
    }

    /// A BLAKE2sp digest as stored under the MAC flag (3.7.6).
    pub fn mac_digest(&self, digest: &[u8; 32]) -> [u8; 32] {
        let mut mac = self.mac();
        mac.update(digest);
        mac.finalize().into_bytes().into()
    }

    /// The AES-256 key (vectors and tests).
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    /// The MAC key (vectors and tests).
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    pub fn hash_key(&self) -> &[u8; 32] {
        &self.hash_key
    }

    /// The check value (vectors and tests).
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    pub fn check(&self) -> &[u8; 8] {
        &self.check
    }
}

/// A bench knob, `kdf-arms` builds only: `0` or `off` derives through
/// the `hmac` crate's `Mac` ([`Rar5Keys::derive_hmac`]) instead of the
/// block form. Nothing ships reading it.
#[cfg(feature = "kdf-arms")]
pub(crate) const KDF_BLOCKS_ENV: &str = "RARKIT_KDF_BLOCKS";

#[cfg(feature = "kdf-arms")]
fn kdf_blocks() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        !matches!(
            std::env::var(KDF_BLOCKS_ENV)
                .ok()
                .map(|v| v.trim().to_ascii_lowercase())
                .as_deref(),
            Some("0" | "off")
        )
    })
}

/// SHA-256's initial hash value (FIPS 180-4, 5.3.3).
const SHA256_H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// SHA-256's round constants (FIPS 180-4, 4.2.2), for the register
/// kernels of the PBKDF2 loop.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
pub(super) const SHA256_K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

#[cfg(test)]
thread_local! {
    /// Set by a test to run [`BlockPrf::advance`] through `compress256`
    /// on a machine whose processor has the SHA-256 instructions.
    pub(super) static HIDE_KERNEL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// HMAC-SHA256 (RFC 2104) for the PBKDF2 loop, driven one block at a time
/// through `sha2`'s block function, and the chain's U and V beside it.
///
/// **Why.** Every iteration after the first hashes a 32-byte message under
/// the same key, so each of its two hashes is exactly ONE block after the
/// keyed pad: the inner and outer states after the pads are computed once,
/// and an iteration is two calls of the block function on one fixed block
/// whose first 32 bytes change. Through `Mac`, the same iteration also
/// cloned a keyed state with its buffer and counters and ran the generic
/// update and finalize, and the chain carried the value as bytes between
/// them; here it is carried as words and the padding is written once.
/// `k/kdf/rar5-log15` read 0.955x of the old engine on Zen 5 under Windows
/// through `Mac` (23 Sep 2026).
///
/// **Clearing.** The struct holds every secret of one derivation: the
/// keyed pads pass through `block` (no other buffer holds the key), the
/// two keyed states, the inner hash `s`, and U and V. [`Drop`] clears each
/// field once through two out-of-line loops, so the clearing is a few
/// calls and not hundreds of unrolled byte stores, and nothing is cleared
/// per iteration.
struct BlockPrf {
    inner: [u32; 8],
    outer: [u32; 8],
    /// The inner hash of the current iteration.
    s: [u32; 8],
    /// U_i, the latest PRF output.
    u: [u32; 8],
    /// V_i, the XOR of U_1 to U_i.
    v: [u32; 8],
    /// The iteration block: the message in bytes 0 to 31, then the fixed
    /// padding for a 96-byte (pad plus 32) message. Before [`Self::first`]
    /// it holds the keyed pads.
    block: [u8; 64],
}

impl BlockPrf {
    fn new(password: &[u8]) -> Self {
        let mut p = BlockPrf {
            inner: SHA256_H0,
            outer: SHA256_H0,
            s: [0; 8],
            u: [0; 8],
            v: [0; 8],
            block: [0; 64],
        };
        if password.len() > 64 {
            let mut d: [u8; 32] = Sha256::digest(password).into();
            p.block[..32].copy_from_slice(&d);
            wipe(&mut d);
        } else {
            p.block[..password.len()].copy_from_slice(password);
        }
        // K ^ ipad, then K ^ opad in the same bytes.
        p.block.iter_mut().for_each(|b| *b ^= 0x36);
        compress256(&mut p.inner, core::slice::from_ref(&p.block));
        p.block.iter_mut().for_each(|b| *b ^= 0x36 ^ 0x5c);
        compress256(&mut p.outer, core::slice::from_ref(&p.block));
        p
    }

    /// U_1 = PRF(salt || INT(1)), which is also V_1. The message is 20
    /// bytes, so it and its padding fill every byte of the block, and the
    /// pad left there by [`Self::new`] is overwritten.
    fn first(&mut self, salt: &[u8; 16]) {
        self.block[..16].copy_from_slice(salt);
        self.block[16..20].copy_from_slice(&1u32.to_be_bytes());
        pad_block(&mut self.block, 20);
        self.s = self.inner;
        compress256(&mut self.s, core::slice::from_ref(&self.block));
        put_words(&mut self.block, &self.s);
        pad_block(&mut self.block, 32);
        self.u = self.outer;
        compress256(&mut self.u, core::slice::from_ref(&self.block));
        self.v = self.u;
    }

    /// Advance the chain from V_`from` to V_`to`, polling `cancel` at every
    /// `i` that is a multiple of [`CANCEL_POLL`] before U_(i+1).
    fn run(&mut self, from: u32, to: u32, cancel: Option<&AtomicBool>) -> Result<()> {
        let mut i = from;
        while i < to {
            if i.is_multiple_of(CANCEL_POLL) && cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                return Err(Error::new(ErrorKind::Cancelled));
            }
            // Up to the next poll point, or `to`.
            let next = (i / CANCEL_POLL + 1).saturating_mul(CANCEL_POLL).min(to);
            self.advance(next - i);
            i = next;
        }
        Ok(())
    }

    /// `count` iterations of [`Self::next`]: through the processor's
    /// SHA-256 instructions with the chain held in registers where it has
    /// them, through `compress256` otherwise. The kernels
    /// write U and V; the inner hash `s` and the block are left as they
    /// were, and [`Drop`] clears them either way.
    #[allow(unsafe_code)]
    fn advance(&mut self, count: u32) {
        #[cfg(test)]
        if HIDE_KERNEL.with(std::cell::Cell::get) {
            (0..count).for_each(|_| self.next());
            return;
        }
        #[cfg(target_arch = "aarch64")]
        if super::pbkdf2_armv8::available() {
            // SAFETY: the one obligation `run` carries is that the
            // processor has the SHA-256 instructions its
            // `#[target_feature(enable = "sha2")]` lists, and this call is
            // made only when `available()` has just answered yes: the
            // standard library's runtime detection, which asks the
            // operating system and which nothing in this crate can make
            // answer yes on a processor without them. Where it answers no,
            // the loop below runs instead. `run` forms no raw pointer and
            // calls no load or store intrinsic: its words enter by
            // `vcreate_u32` and `vcombine_u32` and leave by lane extracts,
            // through the four references it is given, and every other
            // intrinsic it calls works on registers alone.
            unsafe {
                super::pbkdf2_armv8::run(&self.inner, &self.outer, &mut self.u, &mut self.v, count);
            }
            return;
        }
        #[cfg(target_arch = "x86_64")]
        if super::pbkdf2_x86::available() {
            // SAFETY: the one obligation `run` carries is that the
            // processor has the extensions its `#[target_feature]` lists,
            // `sha`, `sse2`, `ssse3` and `sse4.1`, and this call is made
            // only when `available()` has just found each of the four by
            // the standard library's runtime detection, which asks the
            // processor (and the operating system, for the saved register
            // state) and which nothing in this crate can make answer yes
            // on a processor without them. Where it answers no, the loop
            // below runs instead. `run` forms no raw pointer and calls no
            // load or store intrinsic: its words enter by `_mm_set_epi32`
            // and leave by `_mm_extract_epi32`, through the four
            // references it is given, and every other intrinsic it calls
            // works on registers alone.
            unsafe {
                super::pbkdf2_x86::run(&self.inner, &self.outer, &mut self.u, &mut self.v, count);
            }
            return;
        }
        (0..count).for_each(|_| self.next());
    }

    /// U_(i+1) = PRF(U_i), and V ^= U.
    #[inline]
    fn next(&mut self) {
        put_words(&mut self.block, &self.u);
        self.s = self.inner;
        compress256(&mut self.s, core::slice::from_ref(&self.block));
        put_words(&mut self.block, &self.s);
        self.u = self.outer;
        compress256(&mut self.u, core::slice::from_ref(&self.block));
        for (x, y) in self.v.iter_mut().zip(&self.u) {
            *x ^= y;
        }
    }

    /// Clear every field, once each.
    fn clear(&mut self) {
        for w in [
            &mut self.inner,
            &mut self.outer,
            &mut self.s,
            &mut self.u,
            &mut self.v,
        ] {
            wipe_words(w);
        }
        wipe(&mut self.block);
    }
}

impl Drop for BlockPrf {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Zeroize out of line: one loop, not the stores unrolled at each site.
#[inline(never)]
fn wipe(bytes: &mut [u8]) {
    bytes.zeroize();
}

/// [`wipe`] for words.
#[inline(never)]
fn wipe_words(words: &mut [u32]) {
    words.zeroize();
}

/// SHA-256 padding for a `len`-byte message after one 64-byte pad block:
/// the 0x80 marker, zeros, and the total length in bits.
fn pad_block(block: &mut [u8; 64], len: usize) {
    block[len] = 0x80;
    block[len + 1..56].fill(0);
    block[56..].copy_from_slice(&((64 + len as u64) * 8).to_be_bytes());
}

/// Eight words into the buffer's first 32 bytes, big-endian.
#[inline]
fn put_words<const N: usize>(block: &mut [u8; N], w: &[u32; 8]) {
    for (c, x) in block[..32].as_chunks_mut::<4>().0.iter_mut().zip(w) {
        *c = x.to_be_bytes();
    }
}

/// Equality whose time does not depend on where the inputs differ.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && std::hint::black_box(a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y))) == 0
}

/// What [`Rar5Record::unusable`] keeps in place of a code for a record
/// that did not parse: above every code, which is 32 bits.
const NOT_PARSED: u64 = u64::MAX;

/// Flag of the encryption record: a check record is present.
pub const FLAG_CHECK: u64 = 0x0001;
/// Flag of the file encryption record: checksums are MAC-converted.
pub const FLAG_MAC: u64 = 0x0002;

/// A parsed RAR 5 encryption record: the archive encryption header's body
/// (`iv` absent) or a file record's (technote; spec K 3.7).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Rar5Record {
    pub flags: u64,
    pub log2: u8,
    pub salt: [u8; 16],
    pub iv: Option<[u8; 16]>,
    /// The check record, when one is flagged AND fits its own checksum. A
    /// damaged record says nothing about the password and is absent here
    /// (3.7.3 step 1), so the member's checksum alone judges the member.
    pub check: Option<[u8; 12]>,
}

impl Rar5Record {
    /// Parse the record's bytes exactly: version, flags, exponent, salt,
    /// the IV when `file` is set, and the check record when flagged (kept
    /// only when its own checksum fits). A short record or one with bytes
    /// left over is `Corrupt`; version other than 0 or exponent above 24 is
    /// `Unsupported`.
    pub fn parse(bytes: &[u8], file: bool) -> Result<Self> {
        let corrupt = || Error::new(ErrorKind::Corrupt(Corruption::Header));
        let mut at = 0;
        let version = read_vint(bytes, &mut at).ok_or_else(corrupt)?;
        if version != 0 {
            return Err(unsupported(
                Format::Rar5,
                u32::try_from(version).unwrap_or(u32::MAX),
            ));
        }
        let flags = read_vint(bytes, &mut at).ok_or_else(corrupt)?;
        let log2 = *bytes.get(at).ok_or_else(corrupt)?;
        at += 1;
        if log2 > MAX_LOG2 {
            return Err(unsupported(Format::Rar5, u32::from(log2)));
        }
        let mut take = |n: usize| -> Result<&[u8]> {
            let s = bytes.get(at..at + n).ok_or_else(corrupt)?;
            at += n;
            Ok(s)
        };
        let mut salt = [0u8; 16];
        salt.copy_from_slice(take(16)?);
        let iv = if file {
            let mut iv = [0u8; 16];
            iv.copy_from_slice(take(16)?);
            Some(iv)
        } else {
            None
        };
        let check = if flags & FLAG_CHECK != 0 {
            let mut c = [0u8; 12];
            c.copy_from_slice(take(12)?);
            ct_eq(&Sha256::digest(&c[..8])[..4], &c[8..]).then_some(c)
        } else {
            None
        };
        if at != bytes.len() {
            return Err(corrupt());
        }
        Ok(Rar5Record {
            flags,
            log2,
            salt,
            iv,
            check,
        })
    }

    /// Whether the member's stored checksums are MAC-converted.
    pub fn mac(&self) -> bool {
        self.log2 <= MAX_LOG2 && self.flags & FLAG_MAC != 0
    }

    /// The record of a FILE header whose own bytes [`Rar5Record::parse`]
    /// refused with `refusal`: kept in the header, so that the member is
    /// refused when it is reached and the archive's other members are
    /// read (measured against unrar 7.23, which extracts the others and
    /// exits 2 for a version or an exponent it does not know).
    ///
    /// It holds no salt, no IV and no check record, and is told apart by
    /// an exponent no parsed record has. Nothing is ever keyed from it:
    /// [`Rar5Record::refusal`] is asked first.
    pub(crate) fn unusable(refusal: &Error) -> Self {
        let code = match refusal.kind() {
            ErrorKind::Unsupported(Unsupported::Encryption { code, .. }) => u64::from(*code),
            _ => NOT_PARSED,
        };
        Rar5Record {
            flags: code,
            log2: u8::MAX,
            salt: [0; 16],
            iv: None,
            check: None,
        }
    }

    /// Why this record cannot key its member, when it cannot: the
    /// `Unsupported` its parse answered, or `Corrupt` for a record that
    /// did not parse at all. `None` for every record that parsed.
    pub(crate) fn refusal(&self) -> Option<Error> {
        if self.log2 <= MAX_LOG2 {
            return None;
        }
        Some(match u32::try_from(self.flags) {
            Ok(code) => unsupported(Format::Rar5, code),
            Err(_) => Error::new(ErrorKind::Corrupt(Corruption::Header)),
        })
    }
}

/// A technote vint: 7 bits per byte, low group first, high bit = more.
/// At most 10 bytes; `None` when it runs off the end or overflows.
pub(crate) fn read_vint(bytes: &[u8], at: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let b = *bytes.get(*at)?;
        *at += 1;
        let low = u64::from(b & 0x7F);
        if shift == 63 && low > 1 {
            return None;
        }
        value |= low << shift;
        if b & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

#[cfg(test)]
mod clearing {
    use super::*;

    /// Every field of a used [`BlockPrf`] reads zero after the clearing
    /// its `Drop` runs, for a key under and over SHA-256's 64-byte block:
    /// the struct is the derivation's only holder of the key pads, the
    /// keyed states, the inner hash, U and V, so this is the proof that
    /// each secret byte is cleared once before `derive_blocks` returns.
    #[test]
    fn rar5_kdf_block_prf_clears_every_field() {
        for pw in [&b"Secret"[..], &[0xa5; 100][..]] {
            let mut p = BlockPrf::new(pw);
            p.first(&[7; 16]);
            p.run(1, 5, None).unwrap();
            assert!(p.v.iter().chain(&p.u).any(|&w| w != 0));
            p.clear();
            let words = [p.inner, p.outer, p.s, p.u, p.v];
            assert!(words.iter().flatten().all(|&w| w == 0), "words");
            assert!(p.block.iter().all(|&b| b == 0), "block");
        }
    }

    /// The keyed pads pass through the iteration block and nowhere else:
    /// after `first`, no byte of `K ^ opad` is left in it.
    #[test]
    fn rar5_kdf_first_overwrites_the_pad() {
        let mut p = BlockPrf::new(&[0xff; 64]);
        assert!(p.block.iter().all(|&b| b == 0xff ^ 0x5c));
        p.first(&[0; 16]);
        assert!(p.block.iter().all(|&b| b != 0xff ^ 0x5c));
    }
}

/// The KDF census, `kdf-census` builds only: one stderr line per
/// derivation naming the exponent and the kernel [`BlockPrf::advance`]
/// will take, so a count answers whether the SHA extensions are
/// dispatched and how many derivations a command runs. Nothing ships it.
#[cfg(feature = "kdf-census")]
fn census(log2: u8) {
    #[cfg(target_arch = "x86_64")]
    let kernel = if super::pbkdf2_x86::available() {
        "sha-ni"
    } else {
        "scalar"
    };
    #[cfg(target_arch = "aarch64")]
    let kernel = if super::pbkdf2_armv8::available() {
        "armv8-sha2"
    } else {
        "scalar"
    };
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let kernel = "scalar";
    eprintln!(
        "kdf-census: derive log2={log2} kernel={kernel} thread={:?}",
        std::thread::current().id()
    );
}
