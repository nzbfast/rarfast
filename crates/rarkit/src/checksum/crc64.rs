//! CRC-64 in the two conventions the RAR 5 recovery record uses (spec L
//! 3.2).
//!
//! One polynomial, ECMA-182 `0x42F0E1EBA9EA3693`, processed LSB first from
//! its reflected form `0xC96C5795D7870F42`. The record uses it twice over:
//!
//! - **Form A, CRC-64/XZ** - register all ones, final XOR all ones - is
//!   each record's own checksum.
//! - **Form B, the raw register** - from zero, no final XOR - is what the
//!   per-slice state tables hold, which is why it is incremental here: a
//!   slice's state is carried across the chunk boundaries of a streaming
//!   encode.

mod clmul;

/// The reflected ECMA-182 polynomial.
const POLY: u64 = 0xC96C_5795_D787_0F42;

/// Slice-by-8: table `n` folds a byte that is `n` places further from the
/// register's low end, so eight bytes are consumed per round with no
/// dependency between them.
static TABLE: [[u64; 256]; 8] = build_tables();

const fn build_tables() -> [[u64; 256]; 8] {
    let mut t = [[0u64; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u64;
        let mut bit = 0;
        while bit < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ POLY } else { c >> 1 };
            bit += 1;
        }
        t[0][i] = c;
        i += 1;
    }
    let mut n = 1;
    while n < 8 {
        let mut i = 0;
        while i < 256 {
            let prev = t[n - 1][i];
            t[n][i] = (prev >> 8) ^ t[0][(prev & 0xff) as usize];
            i += 1;
        }
        n += 1;
    }
    t
}

/// The raw register (form B): from zero, no final inversion.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Crc64Register(pub(crate) u64);

impl Crc64Register {
    /// A register over no bytes yet.
    pub(crate) fn new() -> Crc64Register {
        Crc64Register(0)
    }

    /// Feed `data`.
    #[inline]
    pub(crate) fn update(&mut self, data: &[u8]) {
        self.0 = update(self.0, data);
    }

    /// The register as it stands. Chunking never changes it.
    #[inline]
    pub(crate) fn state(&self) -> u64 {
        self.0
    }
}

/// `register` after `data`, LSB first: the carry-less fold where this CPU
/// has one and `data` is long enough to pay for it, the table otherwise.
/// Both answer the same register (the differential test below).
#[inline]
fn update(crc: u64, data: &[u8]) -> u64 {
    if data.len() >= clmul::FOLD_MIN_BYTES {
        if let Some(kernel) = clmul::kernel() {
            return kernel(crc, data);
        }
    }
    update_table(crc, data)
}

/// `register` after `data` through the slice-by-8 table: the definition
/// every fold is held to.
#[inline]
fn update_table(mut crc: u64, data: &[u8]) -> u64 {
    let mut rest = data;
    // Eight at a time while eight remain; the loop body has no carried
    // dependency beyond the single XOR into `crc`.
    while rest.len() >= 8 {
        let (head, tail) = rest.split_at(8);
        let word = u64::from_le_bytes(head.try_into().unwrap()) ^ crc;
        crc = TABLE[7][(word & 0xff) as usize]
            ^ TABLE[6][((word >> 8) & 0xff) as usize]
            ^ TABLE[5][((word >> 16) & 0xff) as usize]
            ^ TABLE[4][((word >> 24) & 0xff) as usize]
            ^ TABLE[3][((word >> 32) & 0xff) as usize]
            ^ TABLE[2][((word >> 40) & 0xff) as usize]
            ^ TABLE[1][((word >> 48) & 0xff) as usize]
            ^ TABLE[0][((word >> 56) & 0xff) as usize];
        rest = tail;
    }
    for &byte in rest {
        crc = (crc >> 8) ^ TABLE[0][((crc ^ byte as u64) & 0xff) as usize];
    }
    crc
}

/// CRC-64/XZ (form A) of `data`.
// Reached only through the `internals_*` seam, behind the
// `bench-internals` feature; no shipped build enables it.
#[allow(dead_code)]
pub(crate) fn crc64_xz(data: &[u8]) -> u64 {
    !update(!0, data)
}

/// The raw register over `data` through the table alone (the bench seam's
/// baseline arm).
#[allow(dead_code)]
pub(crate) fn register_by_table(data: &[u8]) -> u64 {
    update_table(0, data)
}

/// CRC-64/XZ over pieces hashed as if concatenated.
pub(crate) fn crc64_xz_pieces(pieces: &[&[u8]]) -> u64 {
    let mut crc = !0u64;
    for piece in pieces {
        crc = update(crc, piece);
    }
    !crc
}

/// The raw register advanced past a fixed number of zero bytes, as the
/// 64 by 64 matrix over GF(2) it is: feeding a zero byte is linear in the
/// register (`(crc >> 8) ^ TABLE[0][crc & 0xff]`, the table itself linear
/// and zero at zero), so its column `i` is the register `1 << i` advanced
/// the same way, and applying it is 64 conditional XORs.
///
/// What it is for: the raw register is linear in the register and the
/// data together, so `update(r, B) = zeros(r, |B|) ^ update(0, B)`. A
/// checksum over `A || B` where `B` was hashed on its own, from zero, is
/// then finished from `A`'s register without reading `B` again, which is
/// how a recovery record computed in place seals its records
/// (`rr5::encode_in_place`).
pub(crate) struct ZeroShift {
    columns: [u64; 64],
}

impl ZeroShift {
    /// The operator for `n` zero bytes.
    pub(crate) fn new(n: usize) -> ZeroShift {
        const ZEROS: [u8; 4096] = [0; 4096];
        let mut columns = [0u64; 64];
        for (bit, column) in columns.iter_mut().enumerate() {
            let mut crc = 1u64 << bit;
            let mut left = n;
            while left > 0 {
                let take = left.min(ZEROS.len());
                crc = update(crc, &ZEROS[..take]);
                left -= take;
            }
            *column = crc;
        }
        ZeroShift { columns }
    }

    /// `register` advanced past the operator's zero bytes.
    pub(crate) fn apply(&self, register: u64) -> u64 {
        let mut out = 0u64;
        let mut rest = register;
        while rest != 0 {
            out ^= self.columns[rest.trailing_zeros() as usize];
            rest &= rest - 1;
        }
        out
    }
}

/// CRC-64/XZ (form A) of `head || tail` from `head` itself and `tail`'s
/// raw register (form B, from zero), `shift` being the operator for
/// `tail`'s length. Nothing of `tail` is read.
pub(crate) fn crc64_xz_then(head: &[u8], tail_raw: u64, shift: &ZeroShift) -> u64 {
    !(shift.apply(update(!0, head)) ^ tail_raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tail_hashed_alone_finishes_the_whole() {
        let data: Vec<u8> = (0..70_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        for (cut, end) in [(0, 0), (0, 9), (13, 13), (1_672, 67_208), (5, 70_000)] {
            let (head, tail) = data[..end].split_at(cut);
            let mut raw = Crc64Register::new();
            raw.update(tail);
            let shift = ZeroShift::new(tail.len());
            assert_eq!(
                crc64_xz_then(head, raw.state(), &shift),
                crc64_xz_pieces(&[head, tail]),
                "cut {cut} end {end}"
            );
        }
    }

    #[test]
    fn spec_check_values() {
        // Spec L 5.1.
        assert_eq!(crc64_xz(b"123456789"), 0x995D_C9BB_DF19_39FA);
        assert_eq!(crc64_xz(b""), 0);
        assert_eq!(Crc64Register::new().state(), 0);
        // Inputs of this test's own making, each held to the long
        // division below in both forms: one byte, a length that is not a
        // multiple of eight, one table round exactly, a length past the
        // fold's floor, and one past two passes of the widest fold (eight
        // lanes of 64 bytes) with a ragged tail.
        let stream: Vec<u8> = (0..1_543u32)
            .map(|i| (i.wrapping_mul(i).wrapping_add(41 * i) >> 3) as u8 ^ 0xA6)
            .collect();
        for len in [1usize, 8, 11, 301, 1_543] {
            let input = &stream[stream.len() - len..];
            let mut reg = Crc64Register::new();
            reg.update(input);
            assert_eq!(reg.state(), long_division(0, input), "raw, {len} bytes");
            assert_eq!(
                crc64_xz(input),
                !long_division(!0, input),
                "xz, {len} bytes"
            );
        }
    }

    /// Spec L 3.2 from its stated parameters and nothing of this module:
    /// the message as a polynomial over GF(2), highest degree first,
    /// divided by ECMA-182 in normal form one bit at a time. "LSB first"
    /// is carried by reversing each byte on the way in and the remainder
    /// on the way out, so the register here runs the other way round from
    /// every table and fold it checks.
    fn long_division(start: u64, data: &[u8]) -> u64 {
        const ECMA_182: u64 = 0x42F0_E1EB_A9EA_3693;
        let mut remainder = start.reverse_bits();
        for &byte in data {
            remainder ^= u64::from(byte.reverse_bits()) << 56;
            for _ in 0..8 {
                let carry = remainder >> 63 == 1;
                remainder <<= 1;
                if carry {
                    remainder ^= ECMA_182;
                }
            }
        }
        remainder.reverse_bits()
    }

    /// The bit-at-a-time definition, so the tables are checked rather than
    /// trusted.
    fn bitwise(mut crc: u64, data: &[u8]) -> u64 {
        for &byte in data {
            crc ^= byte as u64;
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ POLY
                } else {
                    crc >> 1
                };
            }
        }
        crc
    }

    #[test]
    fn tables_match_the_definition() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
        for len in [0usize, 1, 7, 8, 9, 15, 16, 17, 63, 64, 999, 1000] {
            assert_eq!(update(0, &data[..len]), bitwise(0, &data[..len]), "{len}");
            assert_eq!(crc64_xz(&data[..len]), !bitwise(!0, &data[..len]), "{len}");
        }
    }

    /// Every fold this CPU runs, against the table, bit for bit: every
    /// length up to past two of the widest kernel's passes (so every
    /// length below one fold block, and every tail and lane count, for
    /// each kernel), then random lengths up to past a slice, at every
    /// alignment of the start within 64 bytes, from zero and from random
    /// registers. The empty input and the lengths below the kernels'
    /// floor go through `update`, which must stay on the table for them.
    #[test]
    fn every_fold_matches_the_table() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let data: Vec<u8> = (0..(70_000 + 64)).map(|_| next() as u8).collect();
        let kernels = clmul::kernels();
        eprintln!(
            "folds on this CPU: {:?}",
            kernels.iter().map(|k| k.0).collect::<Vec<_>>()
        );
        let check = |register: u64, input: &[u8]| {
            let want = update_table(register, input);
            assert_eq!(update(register, input), want, "update, len {}", input.len());
            if input.len() >= clmul::FOLD_MIN_BYTES {
                for (name, kernel) in &kernels {
                    assert_eq!(kernel(register, input), want, "{name}, len {}", input.len());
                }
            }
        };
        check(0, &[]);
        check(!0, &[]);
        for len in 0..=1_100 {
            let offset = len % 64;
            check(next(), &data[offset..offset + len]);
            check(0, &data[..len]);
        }
        for _ in 0..3_000 {
            let len = (next() % 70_001) as usize;
            let offset = (next() % 64) as usize;
            check(next(), &data[offset..offset + len]);
        }
        for len in [65_536usize, 65_535, 65_537, 70_000] {
            for offset in 0..64 {
                check(next(), &data[offset..offset + len]);
            }
        }
    }

    #[test]
    fn chunking_does_not_matter() {
        let data: Vec<u8> = (0..4096u32).map(|i| (i * 31 + 5) as u8).collect();
        let whole = Crc64Register::new();
        let mut whole = whole;
        whole.update(&data);
        for step in [1usize, 3, 7, 8, 64, 511, 512, 4095] {
            let mut reg = Crc64Register::new();
            for chunk in data.chunks(step) {
                reg.update(chunk);
            }
            assert_eq!(reg.state(), whole.state(), "step {step}");
        }
        let pieces: Vec<&[u8]> = data.chunks(97).collect();
        assert_eq!(crc64_xz_pieces(&pieces), crc64_xz(&data));
    }
}
