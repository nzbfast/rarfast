//! AES-CBC DECRYPTION driven through the x86-64 VAES instructions, 256 or
//! 512 bits wide, for the member decryptors (the third of the
//! wide x86 kernels). It leaves the `aes`
//! crate for DECRYPTION as of 28 Sep
//! 2026: rarkit's OWN AES-CBC chain driving the x86 AES instructions in
//! place of the crate, with the differential against the `aes` and `cbc`
//! crates PERMANENT; SPEC-K 2.1's sentence that decryption stays in the
//! crate has not been corrected yet. The decrypting twin
//! of [`super::x86`], in the same shape.
//!
//! **Why width helps here and not for encryption.** CBC decryption is
//! parallel by construction: `P[i] = D(C[i]) ^ C[i - 1]`, so every block of
//! a run can be in the cipher at once, and a ymm holds two blocks, a zmm
//! four; `N` such registers keep `2 * N` or `4 * N` blocks in flight per
//! pass, the AES units fed on every cycle. Encryption is one dependent
//! chain per stream and a wider register shortens nothing on it: what VAES
//! could do for the writers is two or four MEMBERS at once, which is a
//! writer question and not this module's.
//!
//! **What is here.** The round keys are [`super::x86::Expanded`]'s (FIPS
//! 197 section 5.2), inverted for the equivalent inverse cipher of section
//! 5.3.5 with the AESIMC instruction: `dk[0] = k[R]`, `dk[i] =
//! InvMixColumns(k[R - i])`, `dk[R] = k[0]`, so a block is one XOR, `R - 1`
//! AESDECs and one AESDECLAST. The XOR with the previous ciphertext block
//! is a load one block behind the current one, made before any store of
//! the pass, so the in-place form reads only ciphertext; the first block of
//! a pass takes the chaining value carried in a register. Blocks short of a
//! whole pass go through the same rounds one 128-bit block at a time.
//!
//! **What holds it.** `super::tests` holds every form against the `aes` and
//! `cbc` crates block for block at every length around each pass edge, both
//! key sizes, random keys and IVs, in place and across split calls, and the
//! member and header differentials against reference `rar` are unchanged.
//!
//! **The unsafe code, counted (the terms of 28 Sep 2026:
//! a per-function `#[allow(unsafe_code)]` with a written
//! SAFETY argument beside each, intrinsics on registers and caller-bounded
//! slices only, run-time detection guarding every call, the crate's deny
//! kept everywhere else and no module-scope allow, the differential
//! against the replaced path permanent).**
//! Three `unsafe fn`s exist to carry their `#[target_feature]` lists
//! (`invert`, `run_ymm`, `run_zmm`), and the two safe callers
//! ([`Chain::new`], [`Chain::decrypt_run`]) are guarded: THE INSTRUCTIONS
//! ARE PRESENT because [`Chain::new`] is the only constructor and answers
//! `None` unless [`form`] found AES-NI, VAES and the width's AVX feature at
//! run time; THE MEMORY IS IN BOUNDS because every load and store through a
//! pointer is `W` bytes at `off + W * j` (or one block behind, at `off + W *
//! j - 16` for `j >= 1`) for a `j` below `N` and an `off` with `off + W * N
//! <= 16 * blocks`, then single blocks at `16 * i` for `i < blocks`, and
//! `blocks` is `buf.len() / 16`; the round-key loads read this module's own
//! fixed arrays. The crate stays `#![deny(unsafe_code)]` everywhere else.

use core::arch::x86_64::*;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::x86::Expanded;

/// The forms this module can run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Form {
    /// Four ymm, eight blocks a pass (AES-NI, AVX2, VAES).
    Ymm4,
    /// Four zmm, sixteen blocks a pass (AES-NI, AVX-512F, VAES); a counted
    /// form that detection does not pick, so without the knob nothing
    /// constructs it.
    #[cfg_attr(not(feature = "x86-wide-knob"), allow(dead_code))]
    Zmm4,
    /// Eight zmm, thirty-two blocks a pass: the shipped form where the
    /// CPU has AVX-512F, by the count (28 Sep 2026: 8.29
    /// bytes a cycle against zmm4's 7.48 on Zen 5, the rows equal).
    Zmm8,
}

fn ymm_supported() -> bool {
    is_x86_feature_detected!("aes")
        && is_x86_feature_detected!("avx2")
        && is_x86_feature_detected!("vaes")
}

fn zmm_supported() -> bool {
    is_x86_feature_detected!("aes")
        && is_x86_feature_detected!("avx512f")
        && is_x86_feature_detected!("vaes")
}

/// The widest form this CPU has, or `None` for the crate's chain.
fn detect() -> Option<Form> {
    if zmm_supported() {
        Some(Form::Zmm8)
    } else if ymm_supported() {
        Some(Form::Ymm4)
    } else {
        None
    }
}

/// The form to run: the knob's, where the feature is on and
/// `RARKIT_X86_AES` names a form the CPU has; the detected one otherwise.
#[cfg(feature = "x86-wide-knob")]
pub(crate) fn form() -> Option<Form> {
    use std::sync::OnceLock;
    static FORM: OnceLock<Option<Form>> = OnceLock::new();
    *FORM.get_or_init(|| {
        let asked = std::env::var("RARKIT_X86_AES").unwrap_or_default();
        match asked.as_str() {
            "crate" => None,
            "ymm4" if ymm_supported() => Some(Form::Ymm4),
            "zmm4" if zmm_supported() => Some(Form::Zmm4),
            "zmm8" if zmm_supported() => Some(Form::Zmm8),
            _ => detect(),
        }
    })
}

/// See the knob arm above.
#[cfg(not(feature = "x86-wide-knob"))]
pub(crate) fn form() -> Option<Form> {
    detect()
}

/// One CBC decryption chain's inverted key schedule, `rounds + 1` keys in
/// the order the inverse cipher applies them.
///
/// `Clone` copies a chain [`Chain::new`] already made, form and all, so a
/// clone rests on the same detection: the key cache builds ONE per key and
/// every member under that key starts from a copy (since
/// 30 Sep 2026), instead of inverting the schedule again per member.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct Chain {
    dk: [[u8; 16]; 15],
    rounds: usize,
    #[zeroize(skip)]
    form: Form,
}

impl Chain {
    #[allow(unsafe_code)]
    /// The inverted schedule of `key` (16 or 32 bytes) for this CPU's
    /// form, or `None` where the CPU has none: the ONLY constructor, and so
    /// the guarantee every unsafe site here rests on.
    pub(crate) fn new(key: &[u8]) -> Option<Chain> {
        let form = form()?;
        // `Expanded::new` needs AES-NI, which every form's detection asked
        // for.
        let keys = Expanded::new(key);
        // SAFETY: `form()` answered `Some` only after `ymm_supported` or
        // `zmm_supported` found AES-NI at run time; `invert` reads and
        // writes the two fixed arrays and registers only.
        let dk = unsafe { invert(&keys) };
        Some(Chain {
            dk,
            rounds: keys.rounds,
            form,
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
        // SAFETY: a `Chain` exists only through `Chain::new`, so the form's
        // features were detected. Every access `run_ymm` and `run_zmm` make
        // is a whole 16-byte block, or a run of them, at an offset below
        // `16 * blocks <= buf.len()`, and each pass loads all it reads
        // before it stores.
        unsafe {
            match (self.form, self.rounds) {
                (Form::Ymm4, 14) => run_ymm::<4, 14>(&self.dk, chain, ptr, blocks),
                (Form::Ymm4, _) => run_ymm::<4, 10>(&self.dk, chain, ptr, blocks),
                (Form::Zmm4, 14) => run_zmm::<4, 14>(&self.dk, chain, ptr, blocks),
                (Form::Zmm4, _) => run_zmm::<4, 10>(&self.dk, chain, ptr, blocks),
                (Form::Zmm8, 14) => run_zmm::<8, 14>(&self.dk, chain, ptr, blocks),
                (Form::Zmm8, _) => run_zmm::<8, 10>(&self.dk, chain, ptr, blocks),
            }
        }
    }
}

#[allow(unsafe_code)]
/// The equivalent inverse cipher's keys (FIPS 197 section 5.3.5): the
/// encryption schedule reversed, with InvMixColumns (AESIMC) applied to
/// every key but the first and last.
///
/// SAFETY (for callers): AES-NI must be present.
#[target_feature(enable = "aes")]
unsafe fn invert(keys: &Expanded) -> [[u8; 16]; 15] {
    let r = keys.rounds;
    let mut dk = [[0u8; 16]; 15];
    dk[0] = keys.keys[r];
    for (i, slot) in dk.iter_mut().enumerate().take(r).skip(1) {
        let k = _mm_loadu_si128(keys.keys[r - i].as_ptr().cast::<__m128i>());
        _mm_storeu_si128(slot.as_mut_ptr().cast::<__m128i>(), _mm_aesimc_si128(k));
    }
    dk[r] = keys.keys[0];
    dk
}

#[allow(unsafe_code)]
/// One block's rounds on a 128-bit register.
#[inline(always)]
unsafe fn block_128<const R: usize>(rk: &[__m128i; 15], c: __m128i) -> __m128i {
    // SAFETY: AES-NI, enabled by the caller's target feature; registers.
    unsafe {
        let mut x = _mm_xor_si128(c, rk[0]);
        for key in &rk[1..R] {
            x = _mm_aesdec_si128(x, *key);
        }
        _mm_aesdeclast_si128(x, rk[R])
    }
}

#[allow(unsafe_code)]
/// `N` ymm registers, `2 * N` blocks a pass, then single blocks.
///
/// SAFETY (for callers): AES-NI, AVX2 and VAES must be present; `buf` must
/// be readable and writable for `16 * blocks` bytes.
#[target_feature(enable = "aes,avx2,vaes")]
unsafe fn run_ymm<const N: usize, const R: usize>(
    dk: &[[u8; 16]; 15],
    chain: [u8; 16],
    buf: *mut u8,
    blocks: usize,
) -> [u8; 16] {
    const W: usize = 32;
    let mut rk = [_mm_setzero_si128(); 15];
    for (r, slot) in rk.iter_mut().enumerate().take(R + 1) {
        *slot = _mm_loadu_si128(dk[r].as_ptr().cast::<__m128i>());
    }
    let rky: [__m256i; 15] = std::array::from_fn(|r| _mm256_broadcastsi128_si256(rk[r]));
    let mut prev = _mm_loadu_si128(chain.as_ptr().cast::<__m128i>());
    let step = 2 * N;
    let mut done = 0;
    while blocks - done >= step {
        let off = 16 * done;
        let c: [__m256i; N] =
            std::array::from_fn(|j| _mm256_loadu_si256(buf.add(off + W * j).cast::<__m256i>()));
        let p: [__m256i; N] = std::array::from_fn(|j| {
            if j == 0 {
                _mm256_permute2x128_si256::<0x20>(_mm256_broadcastsi128_si256(prev), c[0])
            } else {
                _mm256_loadu_si256(buf.add(off + W * j - 16).cast::<__m256i>())
            }
        });
        prev = _mm256_extracti128_si256::<1>(c[N - 1]);
        let mut x: [__m256i; N] = std::array::from_fn(|j| _mm256_xor_si256(c[j], rky[0]));
        for key in &rky[1..R] {
            for v in x.iter_mut() {
                *v = _mm256_aesdec_epi128(*v, *key);
            }
        }
        for (j, v) in x.iter_mut().enumerate() {
            *v = _mm256_xor_si256(_mm256_aesdeclast_epi128(*v, rky[R]), p[j]);
            _mm256_storeu_si256(buf.add(off + W * j).cast::<__m256i>(), *v);
        }
        done += step;
    }
    while done < blocks {
        let at = buf.add(16 * done).cast::<__m128i>();
        let c = _mm_loadu_si128(at);
        _mm_storeu_si128(at, _mm_xor_si128(block_128::<R>(&rk, c), prev));
        prev = c;
        done += 1;
    }
    let mut out = [0u8; 16];
    _mm_storeu_si128(out.as_mut_ptr().cast::<__m128i>(), prev);
    for slot in rk.iter_mut() {
        *slot = _mm_setzero_si128();
    }
    out
}

#[allow(unsafe_code)]
/// `N` zmm registers, `4 * N` blocks a pass, then single blocks.
///
/// SAFETY (for callers): AES-NI, AVX-512F and VAES must be present; `buf`
/// must be readable and writable for `16 * blocks` bytes.
#[target_feature(enable = "aes,avx512f,vaes")]
unsafe fn run_zmm<const N: usize, const R: usize>(
    dk: &[[u8; 16]; 15],
    chain: [u8; 16],
    buf: *mut u8,
    blocks: usize,
) -> [u8; 16] {
    const W: usize = 64;
    let mut rk = [_mm_setzero_si128(); 15];
    for (r, slot) in rk.iter_mut().enumerate().take(R + 1) {
        *slot = _mm_loadu_si128(dk[r].as_ptr().cast::<__m128i>());
    }
    let rkz: [__m512i; 15] = std::array::from_fn(|r| _mm512_broadcast_i32x4(rk[r]));
    let mut prev = _mm_loadu_si128(chain.as_ptr().cast::<__m128i>());
    let step = 4 * N;
    let mut done = 0;
    while blocks - done >= step {
        let off = 16 * done;
        let c: [__m512i; N] =
            std::array::from_fn(|j| _mm512_loadu_si512(buf.add(off + W * j).cast::<__m512i>()));
        let p: [__m512i; N] = std::array::from_fn(|j| {
            if j == 0 {
                // The chain in front of the first three blocks: qwords 6 and
                // 7 of the broadcast, then qwords 0 to 5 of `c[0]`.
                _mm512_alignr_epi64::<6>(c[0], _mm512_broadcast_i32x4(prev))
            } else {
                _mm512_loadu_si512(buf.add(off + W * j - 16).cast::<__m512i>())
            }
        });
        prev = _mm512_extracti32x4_epi32::<3>(c[N - 1]);
        let mut x: [__m512i; N] = std::array::from_fn(|j| _mm512_xor_si512(c[j], rkz[0]));
        for key in &rkz[1..R] {
            for v in x.iter_mut() {
                *v = _mm512_aesdec_epi128(*v, *key);
            }
        }
        for (j, v) in x.iter_mut().enumerate() {
            *v = _mm512_xor_si512(_mm512_aesdeclast_epi128(*v, rkz[R]), p[j]);
            _mm512_storeu_si512(buf.add(off + W * j).cast::<__m512i>(), *v);
        }
        done += step;
    }
    while done < blocks {
        let at = buf.add(16 * done).cast::<__m128i>();
        let c = _mm_loadu_si128(at);
        _mm_storeu_si128(at, _mm_xor_si128(block_128::<R>(&rk, c), prev));
        prev = c;
        done += 1;
    }
    let mut out = [0u8; 16];
    _mm_storeu_si128(out.as_mut_ptr().cast::<__m128i>(), prev);
    for slot in rk.iter_mut() {
        *slot = _mm_setzero_si128();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::{BlockModeDecrypt, KeyIvInit};

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

    #[allow(unsafe_code)]
    /// Every form this CPU has, each as a `Chain` built by hand so that
    /// the knob and detection are not what is under test.
    fn chains(key: &[u8]) -> Vec<Chain> {
        let mut forms = Vec::new();
        if ymm_supported() {
            forms.push(Form::Ymm4);
        }
        if zmm_supported() {
            forms.push(Form::Zmm4);
            forms.push(Form::Zmm8);
        }
        if forms.is_empty() {
            eprintln!("no VAES on this CPU: the wide decrypt forms were not run");
        }
        forms
            .into_iter()
            .map(|form| {
                let keys = Expanded::new(key);
                // SAFETY: AES-NI was detected by the form's check above.
                let dk = unsafe { invert(&keys) };
                Chain {
                    dk,
                    rounds: keys.rounds,
                    form,
                }
            })
            .collect()
    }

    #[test]
    fn every_form_matches_the_crates_at_every_length_around_each_pass_edge() {
        let mut rng = rarkit_testdata::Seeded::new(0x1357_9BDF_2468_ACE0);
        for key_len in [32usize, 16] {
            let mut key = vec![0u8; key_len];
            rng.fill(&mut key);
            let mut iv = [0u8; 16];
            rng.fill(&mut iv);
            let mut data = vec![0u8; 16 * 100];
            rng.fill(&mut data);
            for chain in chains(&key) {
                for blocks in 0..=70 {
                    let mut want = data[..16 * blocks].to_vec();
                    reference(&key, iv, &mut want);
                    let mut got = data[..16 * blocks].to_vec();
                    let last = chain.decrypt_run(iv, &mut got);
                    assert_eq!(got, want, "{:?} key {key_len} blocks {blocks}", chain.form);
                    let expect_last = if blocks == 0 {
                        iv
                    } else {
                        data[16 * blocks - 16..16 * blocks].try_into().unwrap()
                    };
                    assert_eq!(last, expect_last, "{:?} chain after {blocks}", chain.form);
                }
            }
        }
    }

    #[test]
    fn every_form_is_a_stream_across_any_split() {
        let mut rng = rarkit_testdata::Seeded::new(0xFEDC_BA98_7654_3210);
        let mut key = [0u8; 32];
        rng.fill(&mut key);
        let mut iv = [0u8; 16];
        rng.fill(&mut iv);
        let mut data = vec![0u8; 16 * 300];
        rng.fill(&mut data);
        let mut want = data.clone();
        reference(&key, iv, &mut want);
        for chain in chains(&key) {
            for cut in [1usize, 7, 8, 9, 16, 33, 64, 200, 299] {
                let mut got = data.clone();
                let (first, second) = got.split_at_mut(16 * cut);
                let carried = chain.decrypt_run(iv, first);
                chain.decrypt_run(carried, second);
                assert_eq!(got, want, "{:?} cut {cut}", chain.form);
            }
        }
    }

    #[test]
    fn a_partial_trailing_block_is_left_alone() {
        let mut rng = rarkit_testdata::Seeded::new(0x0F1E_2D3C_4B5A_6978);
        let mut key = [0u8; 16];
        rng.fill(&mut key);
        let iv = [7u8; 16];
        let mut data = vec![0u8; 16 * 20 + 5];
        rng.fill(&mut data);
        for chain in chains(&key) {
            let mut got = data.clone();
            chain.decrypt_run(iv, &mut got);
            assert_eq!(&got[16 * 20..], &data[16 * 20..], "{:?}", chain.form);
            let mut want = data[..16 * 20].to_vec();
            reference(&key, iv, &mut want);
            assert_eq!(&got[..16 * 20], &want[..], "{:?}", chain.form);
        }
    }
}
