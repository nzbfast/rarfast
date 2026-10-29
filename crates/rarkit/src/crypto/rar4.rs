//! RAR 2.9 / 3.x / 4.x: the key and IV derivation of spec B part 3, and the
//! AES-128-CBC keys built from it (spec K 3.6).

use sha1::{Digest, Sha1};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

super::redacted_debug!(Rar4Key);

/// Iterations of the derivation.
#[cfg(not(fuzzing))]
const ROUNDS: u32 = 0x40000;
/// Fuzz builds are not KDF benchmarks: far fewer rounds, same structure.
#[cfg(fuzzing)]
const ROUNDS: u32 = 0x100;
/// IV bytes are sampled every `ROUNDS / 16` iterations.
const IV_STEP: u32 = ROUNDS / 16;

/// The password was not UTF-8, so no RAR 4 family archive can carry it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonUtf8Password;

/// What a character outside the basic plane (U+10000 and above) becomes in
/// the seed (spec B 3.1 and 3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Astral {
    /// One unit, the low 16 bits of the code point: what the reference
    /// programs for Linux and macOS were observed to derive from.
    Low16,
    /// Two units, the UTF-16 surrogate pair: what an archive encrypted on
    /// Windows may need, which is not established.
    Pair,
}

/// Whether the two readings of [`Astral`] differ for `password`: whether
/// the part of it a derivation uses holds a character outside the basic
/// plane.
pub fn readings_differ(password: &[u8]) -> bool {
    std::str::from_utf8(super::until_zero_byte(password))
        .is_ok_and(|text| super::used_text(text).chars().any(|ch| ch.len_utf16() == 2))
}

/// The AES-128 key and CBC IV for one (password, salt).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Rar4Key {
    pub(crate) key: [u8; 16],
    pub(crate) iv: [u8; 16],
}

impl Rar4Key {
    /// Derive from the password bytes and the optional 8-byte salt (absent
    /// is the no-salt form, not a zero salt), under the reading the
    /// reference programs on Linux and macOS were observed to use
    /// ([`Astral::Low16`]). This is the form a writer uses.
    pub fn derive(password: &[u8], salt: Option<[u8; 8]>) -> Result<Self, NonUtf8Password> {
        Self::derive_reading(password, salt, Astral::Low16)
    }

    /// [`Rar4Key::derive`] under a stated reading of a character outside
    /// the basic plane. The two readings give one key for a password that
    /// holds no such character.
    pub fn derive_reading(
        password: &[u8],
        salt: Option<[u8; 8]>,
        reading: Astral,
    ) -> Result<Self, NonUtf8Password> {
        // SPEC-API 4.5: the password ends at its first zero byte.
        let password = super::until_zero_byte(password);
        let text = std::str::from_utf8(password).map_err(|_| NonUtf8Password)?;
        // Spec B 3.2: a longer password is cut before the seed is formed.
        let text = super::used_text(text);
        // A character is at most two units of two bytes.
        let mut seed = Zeroizing::new(Vec::with_capacity(text.chars().count() * 4 + 8));
        for ch in text.chars() {
            match reading {
                // Truncation is the reading: the code point's low 16 bits.
                Astral::Low16 => seed.extend_from_slice(&(u32::from(ch) as u16).to_le_bytes()),
                Astral::Pair => {
                    for unit in ch.encode_utf16(&mut [0; 2]) {
                        seed.extend_from_slice(&unit.to_le_bytes());
                    }
                }
            }
        }
        if let Some(salt) = salt {
            seed.extend_from_slice(&salt);
        }
        Ok(derive_from_seed(&mut seed))
    }

    /// The key bytes (vectors and tests).
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    pub fn key(&self) -> &[u8; 16] {
        &self.key
    }

    /// The IV bytes (vectors and tests).
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    pub fn iv(&self) -> &[u8; 16] {
        &self.iv
    }
}

/// How much of the SHORT seed's stream is staged before one `update`.
///
/// A six-character password's unit is 23 bytes, so feeding the stream
/// field by field spends two trips through the hasher's own block buffer
/// to carry about a third of a SHA-1 block. Staging whole units and
/// feeding them once leaves one buffered call per kilobyte and lets the
/// hasher take its block loop in bulk. 1 KiB rather than more: the win is
/// flat from here to 64 KiB on both architectures and the smallest buffer
/// that gets it is the one that stays in L1 beside the seed.
const STAGE_BYTES: usize = 1024;

/// Spec B 3.2 over the seed buffer `R`, which it mutates (the long-input
/// rule) and the caller zeroises.
///
/// `Lr >= 64` decides everything here: it is the test that says whether
/// the rewrite fires, and so also whether the seed is CONSTANT across
/// iterations. A constant seed can be staged once and fed in bulk, which
/// is what the short arm below does. A rewritten one cannot, and staging
/// it anyway was MEASURED as a loss: on aarch64 the long leg reads
/// 8.4 ms fed a field at a time against 9.5 ms restaged every iteration,
/// for 1.10x on x86-64, so the two arms are written separately rather
/// than as one loop with a flag.
fn derive_from_seed(seed: &mut [u8]) -> Rar4Key {
    if seed.len() >= 64 {
        derive_rewriting(seed)
    } else {
        derive_staged(seed)
    }
}

/// The short arm, `Lr < 64`: the seed never changes, so its copies are
/// written into the stage once and each iteration touches only its three
/// counter bytes.
fn derive_staged(seed: &[u8]) -> Rar4Key {
    let unit = seed.len() + 3;
    // Whole units only, so a flush never splits one and what is staged is
    // exactly the stream: `R` followed by the low three bytes of `i`.
    let units = (STAGE_BYTES / unit).max(1);
    let mut stage = Zeroizing::new(vec![0u8; units * unit]);
    for slot in stage.chunks_exact_mut(unit) {
        slot[..seed.len()].copy_from_slice(seed);
    }
    let mut sha = Sha1::new();
    let mut iv = [0u8; 16];
    let mut held = 0usize;
    for i in 0..ROUNDS {
        let at = held * unit + seed.len();
        stage[at..at + 3].copy_from_slice(&i.to_le_bytes()[..3]);
        held += 1;
        // An IV byte is sampled from the stream SO FAR, so the stage is
        // flushed at a sample point before the running state is cloned.
        let sample = i.is_multiple_of(IV_STEP);
        if sample || held == units {
            sha.update(&stage[..held * unit]);
            held = 0;
        }
        if sample {
            sample_iv(&sha, &mut iv, i);
        }
    }
    if held > 0 {
        sha.update(&stage[..held * unit]);
    }
    finish(sha, iv)
}

/// The long arm, `Lr >= 64`: the seed is rewritten as it is absorbed, so
/// every iteration feeds the buffer as it stands.
fn derive_rewriting(seed: &mut [u8]) -> Rar4Key {
    let lr = seed.len() as u64;
    let mut sha = Sha1::new();
    let mut iv = [0u8; 16];
    for i in 0..ROUNDS {
        sha.update(&*seed);
        let counter = i.to_le_bytes();
        sha.update(&counter[..3]);
        if i.is_multiple_of(IV_STEP) {
            sample_iv(&sha, &mut iv, i);
        }
        // Whole 64-byte stream blocks strictly after this iteration's
        // first seed byte and inside its seed bytes were just absorbed;
        // rewrite them for later iterations.
        let start = u64::from(i) * (lr + 3);
        let mut c = (start / 64 + 1) * 64;
        while c + 64 <= start + lr {
            let at = (c - start) as usize;
            if let Some(block) = seed.get_mut(at..at + 64) {
                schedule_rewrite(block);
            }
            c += 64;
        }
    }
    finish(sha, iv)
}

/// IV byte `i / M`: the last byte of the digest of the stream so far,
/// taken from a cheap clone of the running state (spec B 3.2).
#[inline]
fn sample_iv(sha: &Sha1, iv: &mut [u8; 16], i: u32) {
    let mut digest = sha.clone().finalize();
    iv[(i / IV_STEP) as usize] = digest[19];
    digest.as_mut_slice().zeroize();
}

/// The key from the finalised state, its four words byte-reversed, and
/// the IV beside it.
fn finish(sha: Sha1, mut iv: [u8; 16]) -> Rar4Key {
    let mut digest = sha.finalize();
    let mut key = [0u8; 16];
    for w in 0..4 {
        for b in 0..4 {
            key[4 * w + b] = digest[4 * w + 3 - b];
        }
    }
    digest.as_mut_slice().zeroize();
    let out = Rar4Key { key, iv };
    key.zeroize();
    iv.zeroize();
    out
}

/// SHA-1's message expansion over a 64-byte block, words 64..80 written
/// back little-endian (spec B 3.2).
///
/// The expansion's taps reach back 16 words at most, so it runs in a
/// sixteen-word ring rather than an 80-word array: the same words, a fifth
/// of the memory traffic and a fifth of the scratch to zeroise, on a path
/// that runs about 1.4 times per derivation iteration for a 40-character
/// password. After the loop `w[j]` holds `W[64 + j]`, which is what goes
/// back into the block.
fn schedule_rewrite(block: &mut [u8]) {
    let mut w = [0u32; 16];
    for (t, word) in block.as_chunks::<4>().0.iter().enumerate() {
        w[t] = u32::from_be_bytes(*word);
    }
    // Rounds 16 to 80 in four groups of sixteen, so every index is a
    // constant of the unrolled body and the ring stays in registers.
    for _ in 0..4 {
        for j in 0..16usize {
            // (t - 3), (t - 8), (t - 14) and (t - 16) modulo 16.
            let x = w[(j + 13) & 15] ^ w[(j + 8) & 15] ^ w[(j + 2) & 15] ^ w[j];
            w[j] = x.rotate_left(1);
        }
    }
    for (j, out) in block.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        out.copy_from_slice(&w[j].to_le_bytes());
    }
    w.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// For seeds under 64 bytes the rewrite never fires, so a plain SHA-1
    /// over the repeated stream must agree (spec B 3.4, boundary case).
    fn plain(seed: &[u8]) -> ([u8; 16], [u8; 16]) {
        let mut stream = Vec::new();
        let mut iv = [0u8; 16];
        for i in 0..ROUNDS {
            stream.extend_from_slice(seed);
            stream.extend_from_slice(&i.to_le_bytes()[..3]);
            if i % IV_STEP == 0 {
                iv[(i / IV_STEP) as usize] = Sha1::digest(&stream)[19];
            }
        }
        let d = Sha1::digest(&stream);
        let mut key = [0u8; 16];
        for w in 0..4 {
            for b in 0..4 {
                key[4 * w + b] = d[4 * w + 3 - b];
            }
        }
        (key, iv)
    }

    /// Spec B 3.4's two drawn rows whose seed is under one block (the
    /// short seed vector, and case 18): the password's units and the salt
    /// are 24 bytes, so the derivation's key and IV are the plain ones.
    #[test]
    fn a_seed_under_one_block_derives_as_plain_sha1_does() {
        let drawn: [(&str, [u8; 8]); 2] = [
            ("FEqY3yKH", [0x26, 0xd6, 0x49, 0xa0, 0x73, 0xae, 0x91, 0x2d]),
            ("gbQftPZR", [0x5b, 0xe8, 0x2b, 0xaf, 0xf3, 0xf7, 0x61, 0x87]),
        ];
        for (password, salt) in drawn {
            let mut seed: Vec<u8> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
            seed.extend_from_slice(&salt);
            assert!(seed.len() < 64, "{password}");
            let got = Rar4Key::derive(password.as_bytes(), Some(salt)).unwrap();
            assert_eq!((got.key, got.iv), plain(&seed), "{password}");
        }
    }

    /// Spec B 3.2, arm `astral`: a character outside the basic plane enters
    /// the seed as the low 16 bits of its code point, one unit. For the
    /// password U+1F511 then `key` the seed begins `11 F5`.
    #[test]
    fn a_character_outside_the_basic_plane_is_its_low_16_bits() {
        let salt = *b"saltsalt";
        let seeded = |units: &[u8]| {
            let mut seed = units.to_vec();
            seed.extend_from_slice(&salt);
            let k = derive_from_seed(&mut seed);
            (k.key, k.iv)
        };
        let low = seeded(&[0x11, 0xf5, b'k', 0, b'e', 0, b'y', 0]);
        let got = Rar4Key::derive("\u{1f511}key".as_bytes(), Some(salt)).unwrap();
        assert_eq!((got.key, got.iv), low);
    }

    /// The surrogate pair reading, which the reference programs at hand
    /// refuse and an archive made on Windows may need, is the other arm;
    /// the two agree wherever the password stays in the basic plane.
    #[test]
    fn the_pair_reading_is_the_surrogate_pair() {
        let salt = *b"saltsalt";
        let mut seed = vec![0x3d, 0xd8, 0x11, 0xdd, b'k', 0, b'e', 0, b'y', 0];
        seed.extend_from_slice(&salt);
        let pair = derive_from_seed(&mut seed);
        let pw = "\u{1f511}key".as_bytes();
        let got = Rar4Key::derive_reading(pw, Some(salt), Astral::Pair).unwrap();
        assert_eq!((got.key, got.iv), (pair.key, pair.iv));
        assert!(readings_differ(pw));

        // Any password whose every character is inside the basic plane:
        // letters and digits, drawn once.
        let plain: &[u8] = b"OCWCg8rKoSl";
        assert!(!readings_differ(plain));
        let a = Rar4Key::derive_reading(plain, Some(salt), Astral::Low16).unwrap();
        let b = Rar4Key::derive_reading(plain, Some(salt), Astral::Pair).unwrap();
        assert_eq!((a.key, a.iv), (b.key, b.iv));
        // A character past the 127th does not enter, so it makes no
        // difference either.
        let tail = format!("{}\u{1f511}", "x".repeat(127));
        assert!(!readings_differ(tail.as_bytes()));
        assert!(!readings_differ(b"\xff\xf0"));
    }
}
