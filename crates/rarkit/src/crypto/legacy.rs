//! The three pre-AES ciphers (spec K 3.3 to 3.5). Obfuscation, not
//! security: nothing here is treated as such. Decrypt only in production;
//! the encrypt directions exist to build test inputs.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::checksum::CRC32_TABLE as T;

/// RAR 1.3/1.4 byte stream (3.3). Keeps the post-setup state so a split
/// member can restart it at each volume's fragment.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Rar13Stream {
    start: [u8; 3],
    k: [u8; 3],
}

impl Rar13Stream {
    /// Key setup from the password bytes, which end at their first zero
    /// byte (SPEC-API 4.5).
    pub fn new(password: &[u8]) -> Self {
        let password = super::until_zero_byte(password);
        let mut k = [0u8; 3];
        for &p in password {
            k[0] = k[0].wrapping_add(p);
            k[1] ^= p;
            k[2] = k[2].wrapping_add(p).rotate_left(1);
        }
        let out = Rar13Stream { start: k, k };
        k.zeroize();
        out
    }

    /// The fixed-key state for the RAR 1.3 archive comment.
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    pub fn comment() -> Self {
        let k = [0, 7, 77];
        Rar13Stream { start: k, k }
    }

    /// Back to the state right after key setup.
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    pub fn restart(&mut self) {
        self.k = self.start;
    }

    /// The state, for the setup vectors.
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    pub fn state(&self) -> [u8; 3] {
        self.k
    }

    /// Decrypt in place.
    pub fn decrypt(&mut self, buf: &mut [u8]) {
        self.apply::<false>(buf);
    }

    /// Encrypt in place (tests and benches build inputs with it).
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    pub fn encrypt(&mut self, buf: &mut [u8]) {
        self.apply::<true>(buf);
    }

    /// The keystream's period. Per byte 3.3 sets `k1 += k2` then
    /// `k0 += k1`, so after `n` bytes `k1` has grown by `n k2` and `k0` by
    /// `n k1 + k2 n(n + 1) / 2`. At `n = 512` both are zero modulo 256
    /// (512 k2 = 0, and 512 * 513 / 2 = 256 * 513), so the state returns
    /// exactly to where it started and the keystream repeats.
    const PERIOD: usize = 512;

    /// One direction over `buf`, advancing the state by its length.
    ///
    /// A buffer worth more than a couple of periods gets its keystream
    /// built once, in the recurrence's own serial chain, and then applied
    /// to the whole buffer as a plain byte add or subtract, which the
    /// backend vectorises. Anything shorter runs the recurrence directly:
    /// the two agree byte for byte, which is what the differential
    /// against `legacy_decrypt` and the bench leg's byte comparison
    /// check.
    fn apply<const ADD: bool>(&mut self, buf: &mut [u8]) {
        if buf.len() < 2 * Self::PERIOD {
            let [mut k0, mut k1, k2] = self.k;
            for c in buf {
                k1 = k1.wrapping_add(k2);
                k0 = k0.wrapping_add(k1);
                *c = if ADD {
                    c.wrapping_add(k0)
                } else {
                    c.wrapping_sub(k0)
                };
            }
            self.k = [k0, k1, k2];
            return;
        }
        let mut keystream = [0u8; Self::PERIOD];
        let [mut k0, mut k1, k2] = self.k;
        for s in keystream.iter_mut() {
            k1 = k1.wrapping_add(k2);
            k0 = k0.wrapping_add(k1);
            *s = k0;
        }
        // The state is back where it started after every whole period, so
        // each chunk of the buffer takes the keystream from its front.
        for chunk in buf.chunks_mut(Self::PERIOD) {
            for (c, &s) in chunk.iter_mut().zip(&keystream) {
                *c = if ADD {
                    c.wrapping_add(s)
                } else {
                    c.wrapping_sub(s)
                };
            }
        }
        keystream.zeroize();
        // Only the last, partial period moves the state.
        let [mut k0, mut k1, k2] = self.k;
        for _ in 0..buf.len() % Self::PERIOD {
            k1 = k1.wrapping_add(k2);
            k0 = k0.wrapping_add(k1);
        }
        self.k = [k0, k1, k2];
    }
}

/// RAR 1.5 byte stream (3.4); the one transform both encrypts and decrypts.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Rar15Stream {
    k: [u16; 4],
}

impl Rar15Stream {
    /// Key setup. The password ends at its first zero byte.
    pub fn new(password: &[u8]) -> Self {
        let end = password
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(password.len());
        let password = &password[..end];
        // The CRC register with no final inversion.
        let mut c = u32::MAX;
        for &p in password {
            c = T[usize::from(c as u8 ^ p)] ^ (c >> 8);
        }
        let mut k = [c as u16, (c >> 16) as u16, 0, 0];
        for &p in password {
            let e = T[usize::from(p)];
            k[2] ^= u16::from(p) ^ e as u16;
            k[3] = k[3]
                .wrapping_add(u16::from(p))
                .wrapping_add((e >> 16) as u16);
        }
        c.zeroize();
        Rar15Stream { k }
    }

    /// The state, for the setup vectors.
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    pub fn state(&self) -> [u16; 4] {
        self.k
    }

    /// Encrypt or decrypt in place.
    ///
    /// # The recurrence, rearranged so the chain is short
    ///
    /// Read row by row as section 3.4's table has it, a byte's `k3` waits
    /// for its `k1`, which waits for the table entry, and the entry's
    /// index is made from `k0`, which the byte before finished last: the
    /// previous byte's `k0`, so the loop is one serial chain and its speed
    /// is the chain's LENGTH: an untimed count put it at 13.6 cycles a
    /// byte at an IPC of 1.28 (22 Sep 2026).
    ///
    /// Rotation distributes over XOR, and `k1` here is `k1_old ^ e_lo`, so
    ///
    /// ```text
    /// k3' = ror(k3, 2) ^ ror(k1_old, 1) ^ ror(e_lo, 1)
    /// ```
    ///
    /// The first two terms come from the PREVIOUS byte's state and are
    /// worked out while this byte's table load is in flight; the third is a
    /// second table, [`E_LO_ROR`], read beside the first. What is left on
    /// the chain after the loads is one subtract and two XORs, where the
    /// literal form had an XOR, two 16-bit rotates (several instructions
    /// each on a machine without a 16-bit rotate) and two more XORs.
    ///
    /// The state after every byte is the literal form's state exactly,
    /// which is what makes a split member and a solid chain unaffected:
    /// `tests::rar15_apply_matches_the_literal_recurrence` runs the two
    /// side by side over every class of state and every buffer split.
    pub fn apply(&mut self, buf: &mut [u8]) {
        let [mut k0, mut k1, mut k2, mut k3] = self.k;
        for b in buf {
            k0 = k0.wrapping_add(0x1234);
            let at = usize::from((k0 >> 1) as u8);
            // Off the chain: the previous byte's `k3` and `k1`.
            let ahead = k3.rotate_right(2) ^ k1.rotate_right(1);
            // A u8 index into two 256-entry tables.
            #[allow(clippy::indexing_slicing)]
            let (e, e_lo_ror) = (T[at], E_LO_ROR[at]);
            k1 ^= e as u16;
            k2 = k2.wrapping_sub((e >> 16) as u16);
            k3 = ahead ^ e_lo_ror;
            k0 ^= k2 ^ k3;
            *b ^= (k0 >> 8) as u8;
        }
        self.k = [k0, k1, k2, k3];
    }

    /// Encrypt or decrypt in place by section 3.4's table as it is
    /// written, one row a statement: what [`Rar15Stream::apply`] is held
    /// to, state for state.
    #[cfg(test)]
    pub(crate) fn apply_literal(&mut self, buf: &mut [u8]) {
        let [mut k0, mut k1, mut k2, mut k3] = self.k;
        for byte in buf {
            let moved = k0.wrapping_add(0x1234);
            // Bits 1 to 8 of the sum pick the entry.
            let entry = T[usize::from((moved >> 1) as u8)];
            k1 ^= entry as u16;
            k2 = k2.wrapping_sub((entry >> 16) as u16);
            k3 = (k3.rotate_right(1) ^ k1).rotate_right(1);
            k0 = moved ^ k2 ^ k3;
            *byte ^= (k0 >> 8) as u8;
        }
        self.k = [k0, k1, k2, k3];
    }

    /// A stream in any state at all, for the side-by-side test.
    #[cfg(test)]
    pub(crate) fn from_state(k: [u16; 4]) -> Self {
        Rar15Stream { k }
    }
}

/// `E_LO_ROR[x]` is the low half of `T[x]` rotated right one bit: the one
/// term of [`Rar15Stream::apply`]'s `k3` update that depends on the byte's
/// own table load.
///
/// Built at compile time the way `T` itself is (spec K 3.1: from `x`,
/// eight times shift right one bit, XOR `0xEDB88320` when the bit shifted
/// out was set), because `T` is a static and a static cannot be read while
/// another is built. `tests::rar15_second_table_is_the_first_rotated` holds
/// the two to each other entry by entry.
static E_LO_ROR: [u16; 256] = e_lo_ror();

const fn e_lo_ror() -> [u16; 256] {
    let mut table = [0u16; 256];
    let mut x = 0;
    while x < 256 {
        let mut c = x as u32;
        let mut bit = 0;
        while bit < 8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xEDB8_8320
            } else {
                c >> 1
            };
            bit += 1;
        }
        table[x] = (c as u16).rotate_right(1);
        x += 1;
    }
    table
}

#[cfg(test)]
pub(crate) fn e_lo_ror_table() -> &'static [u16; 256] {
    &E_LO_ROR
}

/// The RAR 2.0 initial key words (3.5).
const K_INIT: [u32; 4] = [0xD3A3_B879, 0x3F6D_12F7, 0x7515_A235, 0xA4E7_F123];

/// The RAR 2.0 initial substitution table `S0` (3.5), written as one
/// byte string, eight rows of 32.
pub(crate) const S0: [u8; 256] = *b"\
\xd7\x13\x95\x23\x49\xc5\xc0\xcd\xf9\x1c\x10\x77\x30\xdd\x02\x2a\xe8\x01\xb1\xe9\x0e\x58\xdb\x19\xdf\xc3\xf4\x5a\x57\xef\x99\x89\
\xff\xc7\x93\x46\x5c\x42\xf6\x0d\xd8\x28\x3e\x1d\xd9\xe6\x56\x06\x47\x18\xab\xc4\x65\x71\xda\x7b\x5d\x5b\xa3\xb2\xca\x43\x2c\xeb\
\x6b\xfa\x4b\xea\x31\xa7\x7d\xd3\x53\x72\x9d\x90\x20\xc1\x8f\x24\x9e\x7c\xf7\xbb\x59\xd6\x8d\x2f\x79\xe4\x3d\x82\xd5\xc2\xae\xfb\
\x61\x6e\x36\xe5\x73\x39\x98\x5e\x69\xf3\xd4\x37\xd1\xf5\x3f\x0b\xa4\xc8\x1f\x9c\x51\xb0\xe3\x15\x4c\x63\x8b\xbc\x7f\x11\xf8\x33\
\xcf\x78\xbd\xd2\x08\xe2\x29\x48\xb7\xcb\x87\xa5\xa6\x3c\x62\x07\x7a\x26\x9b\xaa\x45\xac\xfc\xee\x27\x86\x3b\x80\xec\x1b\xf0\x50\
\x83\x03\x55\xce\x91\x4f\x9a\x8e\x9f\xdc\xc9\x85\x4a\x40\x14\x81\xe0\xb9\x8a\x67\xad\xb6\x2b\x22\xfe\x52\xc6\x97\xe7\xb4\x3a\x0a\
\x76\x1a\x66\x0c\x32\x84\x16\xbf\x88\x6f\xa2\xb3\x2d\x04\x94\x6c\xa1\x38\x4e\x7e\xf2\xde\x0f\xaf\x92\x17\x21\xf1\xb5\xbe\x4d\xe1\
\x00\x2e\xa9\xba\x44\x5f\xed\x41\x35\xd0\xfd\xa8\x09\x12\x64\x34\x74\xb8\xa0\x60\x6d\x25\x1e\x6a\x8c\x68\x96\x05\xcc\x75\x70\x54";

/// RAR 2.0 128-bit block cipher (3.5). About 4.4 KiB: the member cipher
/// boxes it.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Rar20Block {
    k: [u32; 4],
    s: [u8; 256],
    /// `S[x]` shifted into each byte lane, so `SW` is four loads.
    sw: [[u32; 256]; 4],
}

impl Rar20Block {
    /// Key setup (3.5): the table shuffle the password orders, then the
    /// password itself put through the cipher for what that does to the
    /// key words. An empty password leaves both as the format fixes them.
    pub fn new(password: &[u8]) -> Self {
        // SPEC-API 4.5: the password ends at its first zero byte.
        let password = super::until_zero_byte(password);
        let mut cipher = Rar20Block {
            k: K_INIT,
            s: S0,
            sw: [[0; 256]; 4],
        };
        // 256 passes, and in each one every pair of password bytes in
        // order; a last pair cut short has 0 for its second byte.
        for pass in 0..=255u8 {
            for (m, pair) in password.chunks(2).enumerate() {
                let second = pair.get(1).copied().unwrap_or(0);
                let from = T[usize::from(pair[0].wrapping_sub(pass))] as u8;
                let to = T[usize::from(second.wrapping_add(pass))] as u8;
                // The walk goes up from `from`, round through 0, and
                // stops before `to`; its k-th value, counted from 1,
                // changes places with the entry `2m + k` further on.
                let mut at = from;
                let mut reach = 2 * m + 1;
                while at != to {
                    let other = at.wrapping_add(reach as u8);
                    cipher.s.swap(usize::from(at), usize::from(other));
                    at = at.wrapping_add(1);
                    reach += 1;
                }
            }
        }
        cipher.build_sw();
        // The password, zero padded to whole blocks, is encrypted for
        // the key words it leaves; what comes out is not kept.
        for piece in password.chunks(16) {
            let mut block = [0u8; 16];
            block[..piece.len()].copy_from_slice(piece);
            cipher.encrypt_block(&mut block);
            block.zeroize();
        }
        cipher
    }

    fn build_sw(&mut self) {
        for x in 0..256 {
            let v = u32::from(self.s[x]);
            self.sw[0][x] = v;
            self.sw[1][x] = v << 8;
            self.sw[2][x] = v << 16;
            self.sw[3][x] = v << 24;
        }
    }

    /// Key words and the first 16 table bytes, for the setup vectors.
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    pub fn state(&self) -> ([u32; 4], [u8; 16]) {
        let mut head = [0u8; 16];
        head.copy_from_slice(&self.s[..16]);
        (self.k, head)
    }

    #[inline(always)]
    fn sw(&self, v: u32) -> u32 {
        self.sw[0][usize::from(v as u8)]
            | self.sw[1][usize::from((v >> 8) as u8)]
            | self.sw[2][usize::from((v >> 16) as u8)]
            | self.sw[3][usize::from((v >> 24) as u8)]
    }

    /// One round (3.5) over `[c0, c1, r0, r1]`: the pair in front is the
    /// one this round changes and the pair behind the one it reads. The
    /// two change places on the way out, so the next round, whichever
    /// way the rounds are run, changes the pair this one read.
    #[inline(always)]
    fn round(&self, key: u32, x: [u32; 4]) -> [u32; 4] {
        let [c0, c1, r0, r1] = x;
        let first = c0 ^ self.sw(r0.wrapping_add(r1.rotate_left(11)) ^ key);
        let second = c1 ^ self.sw((r1 ^ r0.rotate_left(17)).wrapping_add(key));
        [r0, r1, first, second]
    }

    /// The key words after a block whose CIPHERTEXT is `ct`: sixteen table
    /// loads, no branches.
    #[inline(always)]
    fn next_keys(mut k: [u32; 4], ct: &[u8; 16]) -> [u32; 4] {
        for g in ct.as_chunks::<4>().0 {
            for w in 0..4 {
                k[w] ^= T[usize::from(g[w])];
            }
        }
        k
    }

    #[inline(always)]
    fn load(k: &[u32; 4], block: &[u8; 16]) -> [u32; 4] {
        let w = |i: usize| u32::from_le_bytes([block[i], block[i + 1], block[i + 2], block[i + 3]]);
        [w(0) ^ k[0], w(4) ^ k[1], w(8) ^ k[2], w(12) ^ k[3]]
    }

    #[inline(always)]
    fn store(k: &[u32; 4], abcd: [u32; 4], block: &mut [u8; 16]) {
        let [a, b, c, d] = abcd;
        block[0..4].copy_from_slice(&(c ^ k[0]).to_le_bytes());
        block[4..8].copy_from_slice(&(d ^ k[1]).to_le_bytes());
        block[8..12].copy_from_slice(&(a ^ k[2]).to_le_bytes());
        block[12..16].copy_from_slice(&(b ^ k[3]).to_le_bytes());
    }

    fn encrypt_block(&mut self, block: &mut [u8; 16]) {
        let k = self.k;
        let mut x = Self::load(&k, block);
        for r in 0..32 {
            x = self.round(k[r & 3], x);
        }
        Self::store(&k, x, block);
        self.k = Self::next_keys(k, block);
    }

    #[inline(always)]
    fn decrypt_block(&mut self, block: &mut [u8; 16]) {
        let k = self.k;
        self.k = Self::next_keys(k, block);
        let mut x = Self::load(&k, block);
        for r in (0..32).rev() {
            x = self.round(k[r & 3], x);
        }
        Self::store(&k, x, block);
    }

    /// Decrypt whole 16-byte blocks in place; a trailing partial block is
    /// left untouched (the member decryptor never passes one).
    ///
    /// Each block's key words depend only on EARLIER ciphertext, which is
    /// all known, so four blocks run their rounds interleaved: four
    /// independent dependency chains hide the table-load latency.
    pub fn decrypt_blocks(&mut self, buf: &mut [u8]) {
        let (blocks, _) = buf.as_chunks_mut::<16>();
        let (quads, rest) = blocks.as_chunks_mut::<4>();
        for q in quads {
            let k0 = self.k;
            let k1 = Self::next_keys(k0, &q[0]);
            let k2 = Self::next_keys(k1, &q[1]);
            let k3 = Self::next_keys(k2, &q[2]);
            self.k = Self::next_keys(k3, &q[3]);
            let ks = [k0, k1, k2, k3];
            let mut x = [
                Self::load(&k0, &q[0]),
                Self::load(&k1, &q[1]),
                Self::load(&k2, &q[2]),
                Self::load(&k3, &q[3]),
            ];
            for r in (0..32).rev() {
                for j in 0..4 {
                    x[j] = self.round(ks[j][r & 3], x[j]);
                }
            }
            for j in 0..4 {
                Self::store(&ks[j], x[j], &mut q[j]);
            }
        }
        for block in rest {
            self.decrypt_block(block);
        }
    }

    /// Encrypt whole 16-byte blocks in place (tests and benches).
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    pub fn encrypt_blocks(&mut self, buf: &mut [u8]) {
        let (blocks, _) = buf.as_chunks_mut::<16>();
        for block in blocks {
            self.encrypt_block(block);
        }
    }
}
