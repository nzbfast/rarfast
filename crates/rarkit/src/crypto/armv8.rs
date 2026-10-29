//! AES-CBC ENCRYPTION driven through the ARMv8 cryptography instructions
//! directly, for the writers (22 Sep 2026; SPEC-K 2.1 as it
//! reads from that date).
//!
//! **Why this exists.** CBC encryption is one dependent chain: block `i`
//! cannot start until block `i - 1` has left the cipher. Through the `aes`
//! crate each block is a call into two non-inlined leaves and a round trip
//! through memory, and those sit ON the chain; a count of 22
//! Sep 2026 measured the same chain
//! with the round keys in registers at 0.55x of the crate's wall, and
//! rarkit owns the chain on those numbers.
//!
//! **What is here and what is not.** The key expansion is FIPS 197 section
//! 5.2, with SubWord taken from the AESE instruction itself (a word
//! repeated across all four columns comes out of ShiftRows unchanged, so
//! column 0 is SubBytes of the word), so no S-box table is carried. A block
//! is FIPS 197 section 5.1's cipher in the ARMv8 spelling: AESE is
//! AddRoundKey then SubBytes and ShiftRows, AESMC is MixColumns, and the
//! last round key is a plain XOR. The mode is CBC exactly as
//! [`super::cbc`] states it. Decryption is `super::armv8_dec`, on this
//! module's key schedule.
//!
//! **What holds it.** `super::tests` holds every key size, at every tile
//! edge, from both entry points, against the `aes` and `cbc` crates block
//! for block, and FIPS 197 appendix C's vectors directly; the writers'
//! own tests hold the archives. The differential against
//! the crate is permanent by design.
//!
//! The round keys live in a zeroised byte array and are loaded into
//! registers once per CALL, not per block.
//!
//! **The unsafe code, counted.** The crate is
//! `#![deny(unsafe_code)]`; this module allows it on FIVE items and no
//! others, each carrying its own `#[allow(unsafe_code)]` and a SAFETY
//! argument: two `unsafe fn`s that exist only to carry
//! `#[target_feature(enable = "aes")]` (`sub_word_aes`, `chain_blocks`),
//! and the three safe functions that call them (`sub_word`,
//! `encrypt_from`, `encrypt_in_place`). The whole argument is two facts.
//! THE INSTRUCTIONS ARE PRESENT: every path into those five runs through a
//! [`Chain`], and [`Chain::new`] is the only constructor of a `Chain`, and
//! it and [`Expanded::checked`] the only two of a key schedule, and each
//! answers `None` unless [`available`] has found the AES extension at run
//! time. THE MEMORY IS IN BOUNDS: the only loads and
//! stores through pointers are 16-byte blocks at `16 * i` for `i` below a
//! count computed from the SHORTER of the two slices' lengths, and the
//! round-key loads read the module's own fixed arrays.

use core::arch::aarch64::{
    uint8x16_t, vaeseq_u8, vaesmcq_u8, vdupq_n_u32, vdupq_n_u8, veorq_u8, vgetq_lane_u32, vld1q_u8,
    vreinterpretq_u32_u8, vreinterpretq_u8_u32, vst1q_u8,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// FIPS 197 section 5.2's round constants, the first byte of `Rcon[i]`.
const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

/// Whether this machine has the ARMv8 AES instructions. Every aarch64
/// macOS machine does; the check is what keeps the path honest elsewhere.
fn available() -> bool {
    std::arch::is_aarch64_feature_detected!("aes")
}

/// An expanded AES-128 or AES-256 key, `rounds + 1` round keys.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct Expanded {
    pub(super) keys: [[u8; 16]; 15],
    pub(super) rounds: usize,
}

impl Expanded {
    /// The schedule of `key` (16 or 32 bytes) for the decrypting twin
    /// (`super::armv8_dec`), or `None` when this machine lacks the AES
    /// extension: the same check [`Chain::new`] makes, so a schedule
    /// exists outside this module only where the instructions do.
    pub(super) fn checked(key: &[u8]) -> Option<Expanded> {
        if !available() {
            return None;
        }
        Some(Expanded::new(key))
    }

    /// FIPS 197 section 5.2 for a 16-byte (10 rounds) or 32-byte
    /// (14 rounds) key. The caller has checked [`available`].
    fn new(key: &[u8]) -> Expanded {
        let nk = key.len() / 4;
        assert!(nk == 4 || nk == 8, "an AES-128 or AES-256 key");
        let rounds = nk + 6;
        let total = 4 * (rounds + 1);
        let mut w = [[0u8; 4]; 60];
        for (slot, word) in w.iter_mut().zip(key.as_chunks::<4>().0) {
            *slot = *word;
        }
        for i in nk..total {
            let mut temp = w[i - 1];
            if i % nk == 0 {
                temp = [temp[1], temp[2], temp[3], temp[0]];
                temp = sub_word(temp);
                temp[0] ^= RCON[i / nk - 1];
            } else if nk > 6 && i % nk == 4 {
                temp = sub_word(temp);
            }
            for b in 0..4 {
                w[i][b] = w[i - nk][b] ^ temp[b];
            }
        }
        let mut keys = [[0u8; 16]; 15];
        for (r, round) in keys.iter_mut().enumerate().take(rounds + 1) {
            for c in 0..4 {
                round[4 * c..4 * c + 4].copy_from_slice(&w[4 * r + c]);
            }
        }
        w.zeroize();
        Expanded { keys, rounds }
    }
}

/// SubWord: the S-box on each byte of a word, through AESE with a zero
/// round key over the word repeated in every column.
#[allow(unsafe_code)]
fn sub_word(word: [u8; 4]) -> [u8; 4] {
    // SAFETY: reached only from `Expanded::new`, which only `Chain::new`
    // and `Expanded::checked` call, after `available()` has found the AES
    // extension; the
    // function reads and writes registers and its own locals only.
    unsafe { sub_word_aes(word) }
}

/// SAFETY (for callers): the AES extension must be present.
#[allow(unsafe_code)]
#[target_feature(enable = "aes")]
unsafe fn sub_word_aes(word: [u8; 4]) -> [u8; 4] {
    let v = vreinterpretq_u8_u32(vdupq_n_u32(u32::from_ne_bytes(word)));
    let s = vaeseq_u8(v, vdupq_n_u8(0));
    vgetq_lane_u32::<0>(vreinterpretq_u32_u8(s)).to_ne_bytes()
}

/// CBC-encrypt the whole blocks of `src` into `dst` from `chain`, and
/// answer the last ciphertext block. The callers in `crypto` have checked
/// the lengths equal and a multiple of 16; the block count is taken from
/// the shorter of the two regardless, so no length can reach past either.
#[allow(unsafe_code)]
fn encrypt_from(keys: &Expanded, chain: [u8; 16], src: &[u8], dst: &mut [u8]) -> [u8; 16] {
    debug_assert_eq!(src.len(), dst.len());
    let blocks = src.len().min(dst.len()) / 16;
    // SAFETY: an `Expanded` exists only inside a `Chain`, and `Chain::new`
    // builds one only after `available()` held, so the AES extension is
    // present. `chain_blocks` loads 16 bytes at `src + 16 * i` and stores
    // 16 at `dst + 16 * i` for `i < blocks`, and `16 * blocks` is at most
    // the length of each slice; `src` and `dst` are distinct borrows.
    unsafe {
        if keys.rounds == 14 {
            chain_blocks::<14>(keys, chain, src.as_ptr(), dst.as_mut_ptr(), blocks)
        } else {
            chain_blocks::<10>(keys, chain, src.as_ptr(), dst.as_mut_ptr(), blocks)
        }
    }
}

/// [`encrypt_from`] over one buffer, in place.
#[allow(unsafe_code)]
fn encrypt_in_place(keys: &Expanded, chain: [u8; 16], buf: &mut [u8]) -> [u8; 16] {
    let blocks = buf.len() / 16;
    let ptr = buf.as_mut_ptr();
    // SAFETY: the extension as in `encrypt_from`; every access is a
    // 16-byte block at `ptr + 16 * i`, `i < buf.len() / 16`, inside `buf`.
    // Source and destination are the same block, and `chain_blocks` loads
    // a block in full before it stores the same 16 bytes.
    unsafe {
        if keys.rounds == 14 {
            chain_blocks::<14>(keys, chain, ptr, ptr, blocks)
        } else {
            chain_blocks::<10>(keys, chain, ptr, ptr, blocks)
        }
    }
}

/// The chain itself. `R` is the round count, so the loop over round keys
/// unrolls and every round key stays in a register for the whole call.
///
/// SAFETY (for callers): the AES extension must be present, and `src`
/// must be readable and `dst` writable for `16 * blocks` bytes each; they
/// may be the same pointer.
#[allow(unsafe_code)]
#[target_feature(enable = "aes")]
unsafe fn chain_blocks<const R: usize>(
    keys: &Expanded,
    chain: [u8; 16],
    src: *const u8,
    dst: *mut u8,
    blocks: usize,
) -> [u8; 16] {
    let mut rk = [vdupq_n_u8(0); 15];
    for (r, slot) in rk.iter_mut().enumerate().take(R + 1) {
        *slot = vld1q_u8(keys.keys[r].as_ptr());
    }
    let mut x: uint8x16_t = vld1q_u8(chain.as_ptr());
    for i in 0..blocks {
        let p = vld1q_u8(src.add(16 * i));
        x = veorq_u8(x, p);
        for key in &rk[..R - 1] {
            x = vaesmcq_u8(vaeseq_u8(x, *key));
        }
        x = vaeseq_u8(x, rk[R - 1]);
        x = veorq_u8(x, rk[R]);
        vst1q_u8(dst.add(16 * i), x);
    }
    let mut out = [0u8; 16];
    vst1q_u8(out.as_mut_ptr(), x);
    for slot in rk.iter_mut() {
        *slot = vdupq_n_u8(0);
    }
    out
}

/// One CBC encryption chain over an [`Expanded`] key: the writers' member
/// and header ciphers when the machine has the instructions.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct Chain {
    keys: Expanded,
    chain: [u8; 16],
}

impl Chain {
    /// A chain from `iv` under `key` (16 or 32 bytes), or `None` when
    /// this machine lacks the AES extension. The ONLY way to a `Chain`
    /// or to its key schedule, and so the guarantee every unsafe site in
    /// this module rests on.
    pub(crate) fn new(key: &[u8], iv: [u8; 16]) -> Option<Chain> {
        if !available() {
            return None;
        }
        Some(Chain {
            keys: Expanded::new(key),
            chain: iv,
        })
    }

    /// Whole blocks, in place.
    pub(crate) fn encrypt_blocks(&mut self, buf: &mut [u8]) {
        self.chain = encrypt_in_place(&self.keys, self.chain, buf);
    }

    /// Start a fresh chain from `iv` under the same expanded key: one
    /// expansion serves every short chain of a key (the writer's
    /// encrypted headers, spec K 3.6.3 and 3.7.5). A field store; no
    /// unsafe code is reached.
    pub(crate) fn restart(&mut self, iv: [u8; 16]) {
        self.chain = iv;
    }

    /// Whole blocks from `src` into `dst`, equal lengths.
    pub(crate) fn encrypt_blocks_from(&mut self, src: &[u8], dst: &mut [u8]) {
        self.chain = encrypt_from(&self.keys, self.chain, src, dst);
    }
}
