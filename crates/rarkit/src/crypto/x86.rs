//! AES-CBC ENCRYPTION driven through the x86-64 AES instructions (AES-NI)
//! directly, for the writers (22 Sep 2026; SPEC-K 2.1 as it
//! reads from that date). The x86-64 half of the aarch64 module
//! `armv8`, in the same shape.
//!
//! **Why this exists.** CBC encryption is one dependent chain: block `i`
//! cannot start until block `i - 1` has left the cipher. Through the `aes`
//! crate each block is a call and a round trip through memory, and those
//! sit ON the chain; rarkit owns the chain with the round
//! keys held in registers for the whole call. The plaintext load and the
//! ciphertext store sit off the chain, so each block costs the latency of
//! its rounds and little else.
//!
//! **What is here and what is not.** The key expansion is FIPS 197 section
//! 5.2, with SubWord taken from the AESENCLAST instruction itself:
//! AESENCLAST is ShiftRows, then SubBytes, then AddRoundKey, and a word
//! repeated across all four columns comes out of ShiftRows unchanged, so
//! with a zero round key column 0 is SubBytes of the word. No S-box table
//! is carried. A block is FIPS 197 section 5.1's cipher in the x86
//! spelling: the first round key is a plain XOR, AESENC is one full middle
//! round (ShiftRows, SubBytes, MixColumns, AddRoundKey), and AESENCLAST the
//! last round without MixColumns. The mode is CBC exactly as
//! [`super::cbc`] states it. Decryption stays in the `aes` crate, as it
//! does beside `armv8`.
//!
//! **What holds it.** `super::tests` holds every key size, at every tile
//! edge, from both entry points, against the `aes` and `cbc` crates block
//! for block, and FIPS 197 appendix C's vectors directly; the writers'
//! own tests hold the archives. The differential against
//! the crate is permanent by design. On an Apple Silicon Mac an `x86_64-apple-darwin`
//! test binary runs this module under Rosetta, which advertises AES.
//!
//! The round keys live in a zeroised byte array and are loaded into
//! registers once per CALL, not per block.
//!
//! **The unsafe code, counted.** The
//! crate is `#![deny(unsafe_code)]`; this module allows it on FIVE items
//! and no others, each carrying its own `#[allow(unsafe_code)]` and a
//! SAFETY argument: two `unsafe fn`s that exist only to carry
//! `#[target_feature(enable = "aes")]` (`sub_word_aes`, `chain_blocks`),
//! and the three safe functions that call them (`sub_word`,
//! `encrypt_from`, `encrypt_in_place`). The whole argument is two facts.
//! THE INSTRUCTIONS ARE PRESENT: every path into those five runs through a
//! [`Chain`], and [`Chain::new`] is the only constructor of a `Chain` or of
//! its key schedule, and answers `None` unless [`available`] has found
//! AES-NI at run time. SSE2, which the unaligned loads and stores need, is
//! part of the x86-64 baseline. THE MEMORY IS IN BOUNDS: the only loads
//! and stores through pointers are 16-byte blocks at `16 * i` for `i` below
//! a count computed from the SHORTER of the two slices' lengths, all of
//! them unaligned forms, and the round-key loads read the module's own
//! fixed arrays.

use core::arch::x86_64::{
    __m128i, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_cvtsi128_si32, _mm_loadu_si128,
    _mm_set1_epi32, _mm_setzero_si128, _mm_storeu_si128, _mm_xor_si128,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// FIPS 197 section 5.2's round constants, the first byte of `Rcon[i]`.
const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

/// Whether this machine has AES-NI. Every x86-64 part this project runs
/// on does; the check is what keeps the path honest on one that does not,
/// where [`Chain::new`] answers `None` and the crate's chain is used.
fn available() -> bool {
    std::arch::is_x86_feature_detected!("aes")
}

/// An expanded AES-128 or AES-256 key, `rounds + 1` round keys.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct Expanded {
    pub(super) keys: [[u8; 16]; 15],
    pub(super) rounds: usize,
}

impl Expanded {
    /// FIPS 197 section 5.2 for a 16-byte (10 rounds) or 32-byte
    /// (14 rounds) key. The caller has checked [`available`].
    pub(super) fn new(key: &[u8]) -> Expanded {
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

/// SubWord: the S-box on each byte of a word, through AESENCLAST with a
/// zero round key over the word repeated in every column.
#[allow(unsafe_code)]
fn sub_word(word: [u8; 4]) -> [u8; 4] {
    // SAFETY: reached only from `Expanded::new`, which only `Chain::new`
    // calls, after `available()` has found AES-NI; the function reads and
    // writes registers and its own locals only.
    unsafe { sub_word_aes(word) }
}

/// SAFETY (for callers): AES-NI must be present.
#[allow(unsafe_code)]
#[target_feature(enable = "aes")]
unsafe fn sub_word_aes(word: [u8; 4]) -> [u8; 4] {
    // The word's bytes in memory order in every column: x86-64 is little
    // endian, so lane 0's low byte is the word's first byte.
    let v = _mm_set1_epi32(i32::from_le_bytes(word));
    let s = _mm_aesenclast_si128(v, _mm_setzero_si128());
    _mm_cvtsi128_si32(s).to_le_bytes()
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
    // builds one only after `available()` held, so AES-NI is present.
    // `chain_blocks` loads 16 bytes at `src + 16 * i` and stores 16 at
    // `dst + 16 * i` for `i < blocks`, unaligned forms both, and
    // `16 * blocks` is at most the length of each slice; `src` and `dst`
    // are distinct borrows.
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
    // SAFETY: AES-NI as in `encrypt_from`; every access is a 16-byte
    // block at `ptr + 16 * i`, `i < buf.len() / 16`, inside `buf`. Source
    // and destination are the same block, and `chain_blocks` loads a block
    // in full before it stores the same 16 bytes.
    unsafe {
        if keys.rounds == 14 {
            chain_blocks::<14>(keys, chain, ptr, ptr, blocks)
        } else {
            chain_blocks::<10>(keys, chain, ptr, ptr, blocks)
        }
    }
}

/// The chain itself. `R` is the round count, so the loop over round keys
/// unrolls and every round key stays in a register for the whole call
/// (fifteen of the sixteen XMM registers at AES-256, the sixteenth the
/// chaining value).
///
/// SAFETY (for callers): AES-NI must be present, and `src` must be
/// readable and `dst` writable for `16 * blocks` bytes each; they may be
/// the same pointer.
#[allow(unsafe_code)]
#[target_feature(enable = "aes")]
unsafe fn chain_blocks<const R: usize>(
    keys: &Expanded,
    chain: [u8; 16],
    src: *const u8,
    dst: *mut u8,
    blocks: usize,
) -> [u8; 16] {
    let mut rk = [_mm_setzero_si128(); 15];
    for (r, slot) in rk.iter_mut().enumerate().take(R + 1) {
        *slot = _mm_loadu_si128(keys.keys[r].as_ptr().cast::<__m128i>());
    }
    let mut x = _mm_loadu_si128(chain.as_ptr().cast::<__m128i>());
    for i in 0..blocks {
        let p = _mm_loadu_si128(src.add(16 * i).cast::<__m128i>());
        // The plaintext meets the first round key before the chain does:
        // `p ^ k0` does not wait on the previous block, so only one XOR
        // sits on the chain ahead of the rounds.
        x = _mm_xor_si128(x, _mm_xor_si128(p, rk[0]));
        for key in &rk[1..R] {
            x = _mm_aesenc_si128(x, *key);
        }
        x = _mm_aesenclast_si128(x, rk[R]);
        _mm_storeu_si128(dst.add(16 * i).cast::<__m128i>(), x);
    }
    let mut out = [0u8; 16];
    _mm_storeu_si128(out.as_mut_ptr().cast::<__m128i>(), x);
    for slot in rk.iter_mut() {
        *slot = _mm_setzero_si128();
    }
    out
}

/// One CBC encryption chain over an [`Expanded`] key: the writers' member
/// and header ciphers when the machine has AES-NI.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct Chain {
    keys: Expanded,
    chain: [u8; 16],
}

impl Chain {
    /// A chain from `iv` under `key` (16 or 32 bytes), or `None` when
    /// this machine lacks AES-NI. The ONLY way to a `Chain` or to its key
    /// schedule, and so the guarantee every unsafe site in this module
    /// rests on.
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
