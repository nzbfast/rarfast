//! AES-CBC DECRYPTION driven through the ARMv8 cryptography instructions
//! directly, for the member decryptors (10 Oct 2026): the decrypting twin
//! of [`super::armv8`], and the aarch64 twin of `x86_dec`, in the same
//! shape. With it decryption leaves the `aes` crate on aarch64 as it left
//! it on x86-64, with the differential against the `aes` and `cbc` crates
//! PERMANENT.
//!
//! **Why this exists.** Through the crate a tile of blocks is a call into
//! a leaf that reloads the round keys from memory, writes the plain blocks
//! to a scratch, and leaves the XOR with the previous ciphertext to a
//! second pass over the tile ([`super::cbc::decrypt_run`]). A count of 10
//! Oct 2026 on a stored member at one thread put that at 63.6 instructions
//! and 10.8 cycles a block, 89 percent of the instructions of the whole
//! test of the member. CBC decryption is parallel by construction, `P[i] =
//! D(C[i]) ^ C[i - 1]`, so `N` blocks can be in the cipher at once with the
//! round keys held in registers for the whole run, and the XOR is one more
//! instruction on the block's way to its store.
//!
//! **What is here.** The round keys are [`super::armv8::Expanded`]'s (FIPS
//! 197 section 5.2), inverted for the equivalent inverse cipher of section
//! 5.3.5 with the AESIMC instruction: `dk[0] = k[R]`, `dk[i] =
//! InvMixColumns(k[R - i])`, `dk[R] = k[0]`. In the ARMv8 spelling AESD is
//! AddRoundKey, then InvShiftRows and InvSubBytes, and AESIMC is
//! InvMixColumns, so a block is `R - 1` AESD and AESIMC pairs, one AESD
//! and a plain XOR with the last key. A pass stores its blocks from the
//! LAST to the first, each XORed with the ciphertext block in front of it
//! read from the buffer just before, so the in-place form reads only
//! ciphertext; the first block of a pass takes the chaining value carried
//! in a register. Blocks short of a whole pass go through the same rounds
//! one at a time.
//!
//! **What holds it.** The tests below hold every pass width against the
//! `aes` and `cbc` crates block for block at every length around each pass
//! edge, both key sizes, random keys and IVs, in place and across split
//! calls, and FIPS 197 appendix C's vectors directly; `super::cbc`'s
//! dispatch tests hold the wired path.
//!
//! **The unsafe code, counted (the terms `x86_dec` states).** Two `unsafe
//! fn`s exist to carry `#[target_feature(enable = "aes")]` (`invert`,
//! `run`), and the two safe callers ([`Chain::new`], [`Chain::decrypt_run`])
//! are guarded: THE INSTRUCTIONS ARE PRESENT because [`Chain::new`] is the
//! only constructor and answers `None` unless [`Expanded::checked`] found
//! the AES extension at run time; THE MEMORY IS IN BOUNDS because every
//! load and store through a pointer is one 16-byte block at `16 * i` for an
//! `i` below `blocks`, and `blocks` is `buf.len() / 16`; the round-key
//! loads read this module's own fixed arrays. The crate stays
//! `#![deny(unsafe_code)]` everywhere else.

use core::arch::aarch64::{
    uint8x16_t, vaesdq_u8, vaesimcq_u8, vdupq_n_u8, veorq_u8, vld1q_u8, vst1q_u8,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::armv8::Expanded;

/// Blocks in the cipher at once on the shipped path. On an Apple core the
/// width hardly matters, a block of a CBC decryption depending on no other
/// block's cipher, so the core overlaps the passes itself (the tests'
/// count, 10 Oct 2026: 1.23 to 1.34 ns a block at every width from 1 to
/// 16, AES-256, against 2.76 through the crate's tile); 8 is the width
/// with the fewest instructions a block in the member row, and one a core
/// with a shorter window still fills its AES units with.
const PASS: usize = 8;

/// One CBC decryption chain's inverted key schedule, `rounds + 1` keys in
/// the order the inverse cipher applies them.
///
/// `Clone` copies a chain [`Chain::new`] already made, so a clone rests on
/// the same detection: the key cache builds ONE per key and every member
/// under that key starts from a copy.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct Chain {
    dk: [[u8; 16]; 15],
    rounds: usize,
}

impl Chain {
    #[allow(unsafe_code)]
    /// The inverted schedule of `key` (16 or 32 bytes), or `None` where
    /// the machine lacks the AES extension: the ONLY constructor, and so
    /// the guarantee every unsafe site here rests on.
    pub(crate) fn new(key: &[u8]) -> Option<Chain> {
        let keys = Expanded::checked(key)?;
        // SAFETY: `Expanded::checked` answered `Some` only after it found
        // the AES extension at run time; `invert` reads and writes the two
        // fixed arrays and registers only.
        let dk = unsafe { invert(&keys) };
        Some(Chain {
            dk,
            rounds: keys.rounds,
        })
    }

    #[allow(unsafe_code)]
    /// Decrypt the whole blocks at the front of `buf` in place from
    /// `chain`, and answer the run's LAST CIPHERTEXT BLOCK (or `chain`
    /// when there was none), which chains into whatever follows.
    pub(crate) fn decrypt_run(&self, chain: [u8; 16], buf: &mut [u8]) -> [u8; 16] {
        let blocks = buf.len() / 16;
        if blocks == 0 {
            return chain;
        }
        let ptr = buf.as_mut_ptr();
        // SAFETY: a `Chain` exists only through `Chain::new`, so the AES
        // extension was detected. Every access `run` makes is one whole
        // 16-byte block at an offset below `16 * blocks <= buf.len()`, and
        // a block's ciphertext is read for the last time before the store
        // that replaces it.
        unsafe {
            if self.rounds == 14 {
                run::<PASS, 14>(&self.dk, chain, ptr, blocks)
            } else {
                run::<PASS, 10>(&self.dk, chain, ptr, blocks)
            }
        }
    }
}

#[allow(unsafe_code)]
/// The equivalent inverse cipher's keys (FIPS 197 section 5.3.5): the
/// encryption schedule reversed, with InvMixColumns (AESIMC) applied to
/// every key but the first and last.
///
/// SAFETY (for callers): the AES extension must be present.
#[target_feature(enable = "aes")]
unsafe fn invert(keys: &Expanded) -> [[u8; 16]; 15] {
    let r = keys.rounds;
    let mut dk = [[0u8; 16]; 15];
    dk[0] = keys.keys[r];
    for (i, slot) in dk.iter_mut().enumerate().take(r).skip(1) {
        let k = vld1q_u8(keys.keys[r - i].as_ptr());
        vst1q_u8(slot.as_mut_ptr(), vaesimcq_u8(k));
    }
    dk[r] = keys.keys[0];
    dk
}

#[allow(unsafe_code)]
/// `N` blocks a pass, then single blocks. `R` is the round count, so the
/// loop over round keys unrolls and every key stays in a register.
///
/// SAFETY (for callers): the AES extension must be present; `buf` must be
/// readable and writable for `16 * blocks` bytes.
#[target_feature(enable = "aes")]
unsafe fn run<const N: usize, const R: usize>(
    dk: &[[u8; 16]; 15],
    chain: [u8; 16],
    buf: *mut u8,
    blocks: usize,
) -> [u8; 16] {
    let mut rk = [vdupq_n_u8(0); 15];
    for (r, slot) in rk.iter_mut().enumerate().take(R + 1) {
        *slot = vld1q_u8(dk[r].as_ptr());
    }
    let mut prev = vld1q_u8(chain.as_ptr());
    let mut done = 0;
    while blocks - done >= N {
        let at = buf.add(16 * done);
        let mut x: [uint8x16_t; N] = std::array::from_fn(|j| vld1q_u8(at.add(16 * j)));
        // The pass's last ciphertext block chains into the next pass, and
        // is kept before its store below replaces it.
        let last = x[N - 1];
        for key in &rk[..R - 1] {
            for v in x.iter_mut() {
                *v = vaesimcq_u8(vaesdq_u8(*v, *key));
            }
        }
        // Descending, so each block reads its predecessor's ciphertext
        // from the buffer before that predecessor becomes plaintext.
        for j in (1..N).rev() {
            let before = vld1q_u8(at.add(16 * (j - 1)));
            let p = veorq_u8(vaesdq_u8(x[j], rk[R - 1]), veorq_u8(rk[R], before));
            vst1q_u8(at.add(16 * j), p);
        }
        let p = veorq_u8(vaesdq_u8(x[0], rk[R - 1]), veorq_u8(rk[R], prev));
        vst1q_u8(at, p);
        prev = last;
        done += N;
    }
    while done < blocks {
        let at = buf.add(16 * done);
        let c = vld1q_u8(at);
        let mut x = c;
        for key in &rk[..R - 1] {
            x = vaesimcq_u8(vaesdq_u8(x, *key));
        }
        let p = veorq_u8(vaesdq_u8(x, rk[R - 1]), veorq_u8(rk[R], prev));
        vst1q_u8(at, p);
        prev = c;
        done += 1;
    }
    let mut out = [0u8; 16];
    vst1q_u8(out.as_mut_ptr(), prev);
    for slot in rk.iter_mut() {
        *slot = vdupq_n_u8(0);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::{BlockModeDecrypt, KeyIvInit};

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn fill(&mut self, buf: &mut [u8]) {
            for byte in buf.iter_mut() {
                *byte = self.next() as u8;
            }
        }
    }

    /// The `cbc` crate over the `aes` crate: the reference.
    fn reference(key: &[u8], iv: [u8; 16], buf: &mut [u8]) {
        if key.len() == 32 {
            cbc::Decryptor::<aes::Aes256>::new_from_slices(key, &iv)
                .expect("a 32-byte key")
                .decrypt_padded::<aes::cipher::block_padding::NoPadding>(buf)
                .expect("whole blocks");
        } else {
            cbc::Decryptor::<aes::Aes128>::new_from_slices(key, &iv)
                .expect("a 16-byte key")
                .decrypt_padded::<aes::cipher::block_padding::NoPadding>(buf)
                .expect("whole blocks");
        }
    }

    /// The pass widths the tests hold: the shipped one and the ones it was
    /// counted against.
    const WIDTHS: [usize; 7] = [1, 4, 6, 8, 10, 12, 16];

    #[allow(unsafe_code)]
    /// One run of `chain`'s schedule at pass width `n`, by hand, so that
    /// every width is under test and not the shipped one alone.
    fn run_at(chain: &Chain, n: usize, iv: [u8; 16], buf: &mut [u8]) -> [u8; 16] {
        let blocks = buf.len() / 16;
        let ptr = buf.as_mut_ptr();
        // SAFETY: `chain` came from `Chain::new`, so the AES extension is
        // present; `blocks` whole blocks lie inside `buf`.
        unsafe {
            match (n, chain.rounds) {
                (1, 14) => run::<1, 14>(&chain.dk, iv, ptr, blocks),
                (1, _) => run::<1, 10>(&chain.dk, iv, ptr, blocks),
                (4, 14) => run::<4, 14>(&chain.dk, iv, ptr, blocks),
                (4, _) => run::<4, 10>(&chain.dk, iv, ptr, blocks),
                (6, 14) => run::<6, 14>(&chain.dk, iv, ptr, blocks),
                (6, _) => run::<6, 10>(&chain.dk, iv, ptr, blocks),
                (8, 14) => run::<8, 14>(&chain.dk, iv, ptr, blocks),
                (8, _) => run::<8, 10>(&chain.dk, iv, ptr, blocks),
                (10, 14) => run::<10, 14>(&chain.dk, iv, ptr, blocks),
                (10, _) => run::<10, 10>(&chain.dk, iv, ptr, blocks),
                (12, 14) => run::<12, 14>(&chain.dk, iv, ptr, blocks),
                (12, _) => run::<12, 10>(&chain.dk, iv, ptr, blocks),
                (16, 14) => run::<16, 14>(&chain.dk, iv, ptr, blocks),
                (_, _) => run::<16, 10>(&chain.dk, iv, ptr, blocks),
            }
        }
    }

    fn chain(key: &[u8]) -> Option<Chain> {
        let chain = Chain::new(key);
        if chain.is_none() {
            eprintln!("no AES extension on this machine: the ARMv8 decrypt chain was not run");
        }
        chain
    }

    #[test]
    fn the_shipped_width_is_one_the_tests_hold() {
        assert!(WIDTHS.contains(&PASS));
    }

    #[test]
    fn fips_197_appendix_c_blocks_decrypt() {
        // FIPS 197 appendix C.1 and C.3: one block under the all-zero IV
        // is the plain inverse cipher.
        let plain: [u8; 16] = std::array::from_fn(|i| (i as u8) * 0x11);
        let cases: [(&[u8], [u8; 16]); 2] = [
            (
                &[
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f,
                ],
                [
                    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70,
                    0xb4, 0xc5, 0x5a,
                ],
            ),
            (
                &[
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                    0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                ],
                [
                    0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b,
                    0x49, 0x60, 0x89,
                ],
            ),
        ];
        for (key, cipher) in cases {
            let Some(chain) = chain(key) else { return };
            let mut block = cipher;
            let last = chain.decrypt_run([0; 16], &mut block);
            assert_eq!(block, plain, "key of {} bytes", key.len());
            assert_eq!(last, cipher);
        }
    }

    #[test]
    fn every_width_matches_the_crates_at_every_length_around_each_pass_edge() {
        let mut rng = Rng(0x1357_9BDF_2468_ACE0);
        for key_len in [32usize, 16] {
            let mut key = vec![0u8; key_len];
            rng.fill(&mut key);
            let mut iv = [0u8; 16];
            rng.fill(&mut iv);
            let mut data = vec![0u8; 16 * 100];
            rng.fill(&mut data);
            let Some(chain) = chain(&key) else { return };
            for blocks in 0..=70 {
                let mut want = data[..16 * blocks].to_vec();
                reference(&key, iv, &mut want);
                let expect_last = if blocks == 0 {
                    iv
                } else {
                    data[16 * blocks - 16..16 * blocks].try_into().unwrap()
                };
                let mut got = data[..16 * blocks].to_vec();
                let last = chain.decrypt_run(iv, &mut got);
                assert_eq!(got, want, "shipped, key {key_len} blocks {blocks}");
                assert_eq!(last, expect_last, "shipped, chain after {blocks}");
                if blocks == 0 {
                    continue;
                }
                for n in WIDTHS {
                    let mut got = data[..16 * blocks].to_vec();
                    let last = run_at(&chain, n, iv, &mut got);
                    assert_eq!(got, want, "width {n} key {key_len} blocks {blocks}");
                    assert_eq!(last, expect_last, "width {n} chain after {blocks}");
                }
            }
        }
    }

    /// Every block count from none to past two passes of the widest
    /// width, in place, at EVERY ALIGNMENT of the buffer's first byte,
    /// both key sizes: the loads and stores are unaligned ones, and this
    /// is what holds that.
    #[test]
    fn every_block_count_at_every_alignment_matches_the_crates() {
        let mut rng = Rng(0x0BAD_5EED_1234_5678);
        const MOST: usize = 40;
        for key_len in [32usize, 16] {
            let mut key = vec![0u8; key_len];
            rng.fill(&mut key);
            let mut iv = [0u8; 16];
            rng.fill(&mut iv);
            let mut data = vec![0u8; 16 * MOST];
            rng.fill(&mut data);
            let Some(chain) = chain(&key) else { return };
            for blocks in 0..=MOST {
                let mut want = data[..16 * blocks].to_vec();
                reference(&key, iv, &mut want);
                for skew in 0..16 {
                    // One allocation, the run starting `skew` bytes into
                    // it, a guard byte either side that must not move.
                    let mut room = vec![0xA5u8; skew + 16 * blocks + 1];
                    room[skew..skew + 16 * blocks].copy_from_slice(&data[..16 * blocks]);
                    let mut plain = room.clone();
                    chain.decrypt_run(iv, &mut plain[skew..skew + 16 * blocks]);
                    assert_eq!(
                        &plain[skew..skew + 16 * blocks],
                        &want[..],
                        "shipped, key {key_len} blocks {blocks} skew {skew}"
                    );
                    assert!(plain[..skew].iter().all(|&b| b == 0xA5));
                    assert_eq!(plain[skew + 16 * blocks], 0xA5);
                    for n in WIDTHS {
                        let mut plain = room.clone();
                        run_at(&chain, n, iv, &mut plain[skew..skew + 16 * blocks]);
                        assert_eq!(
                            &plain[skew..skew + 16 * blocks],
                            &want[..],
                            "width {n} key {key_len} blocks {blocks} skew {skew}"
                        );
                        assert!(plain[..skew].iter().all(|&b| b == 0xA5));
                        assert_eq!(plain[skew + 16 * blocks], 0xA5);
                    }
                }
            }
        }
    }

    #[test]
    fn every_width_is_a_stream_across_any_split() {
        let mut rng = Rng(0xFEDC_BA98_7654_3210);
        let mut key = [0u8; 32];
        rng.fill(&mut key);
        let mut iv = [0u8; 16];
        rng.fill(&mut iv);
        let mut data = vec![0u8; 16 * 300];
        rng.fill(&mut data);
        let mut want = data.clone();
        reference(&key, iv, &mut want);
        let Some(chain) = chain(&key) else { return };
        for n in WIDTHS {
            for cut in [1usize, 7, 8, 9, 12, 16, 33, 64, 200, 299] {
                let mut got = data.clone();
                let (first, second) = got.split_at_mut(16 * cut);
                let carried = run_at(&chain, n, iv, first);
                run_at(&chain, n, carried, second);
                assert_eq!(got, want, "width {n} cut {cut}");
            }
        }
    }

    /// THE WIDTH COUNT: every width and the crate's tile path over one
    /// 1 MiB buffer (resident in the second-level cache, so the figure is
    /// the cipher and not the memory), best of 9 turns of 64 runs each,
    /// one thread, no pool. Ignored: it is a count for a quiet box, run by
    /// name in a release build, and asserts nothing.
    #[test]
    #[ignore = "a count for a quiet box: run by name with --release --nocapture"]
    fn count_every_width_against_the_crates_tile() {
        use aes::cipher::KeyInit;
        let mut rng = Rng(0x2468_ACE0_1357_9BDF);
        let mut data = vec![0u8; 1 << 20];
        rng.fill(&mut data);
        let blocks = (data.len() / 16) as f64;
        let best = |f: &mut dyn FnMut(&mut [u8])| {
            let mut buf = data.clone();
            let mut least = f64::MAX;
            for _ in 0..9 {
                let t = std::time::Instant::now();
                for _ in 0..64 {
                    f(&mut buf);
                }
                least = least.min(t.elapsed().as_secs_f64() / 64.0);
            }
            1e9 * least / blocks
        };
        for key_len in [32usize, 16] {
            let mut key = vec![0u8; key_len];
            rng.fill(&mut key);
            let Some(chain) = chain(&key) else { return };
            let ns = if key_len == 32 {
                let c = aes::Aes256Dec::new_from_slice(&key).unwrap();
                best(&mut |buf| {
                    super::super::cbc::decrypt_run(&c, [0; 16], buf);
                })
            } else {
                let c = aes::Aes128Dec::new_from_slice(&key).unwrap();
                best(&mut |buf| {
                    super::super::cbc::decrypt_run(&c, [0; 16], buf);
                })
            };
            eprintln!("key {key_len} crate tile: {ns:.3} ns a block");
            for n in WIDTHS {
                let ns = best(&mut |buf| {
                    run_at(&chain, n, [0; 16], buf);
                });
                eprintln!("key {key_len} width {n:2}: {ns:.3} ns a block");
            }
        }
    }

    #[test]
    fn a_partial_trailing_block_is_left_alone() {
        let mut rng = Rng(0x0F1E_2D3C_4B5A_6978);
        let mut key = [0u8; 16];
        rng.fill(&mut key);
        let iv = [7u8; 16];
        let mut data = vec![0u8; 16 * 20 + 5];
        rng.fill(&mut data);
        let Some(chain) = chain(&key) else { return };
        let mut got = data.clone();
        chain.decrypt_run(iv, &mut got);
        assert_eq!(&got[16 * 20..], &data[16 * 20..]);
        let mut want = data[..16 * 20].to_vec();
        reference(&key, iv, &mut want);
        assert_eq!(&got[..16 * 20], &want[..]);
    }
}
