//! Checksums (API spec section 10), and spec L section 3.1 to 3.3.
//!
//! The CRC32 kernel is the `crc32fast` crate, which picks a hardware
//! implementation at run time (PCLMULQDQ on x86-64, the ARMv8 CRC
//! instructions on aarch64) and falls back to a table. This module owns
//! only the glue: the incremental type, the zero-extend and combine
//! operators, the piece-parallel entry, and the two reader helpers.

use std::io::Read;
use std::path::Path;

use crate::carry::wiring;

pub(crate) mod blake2sp;
pub(crate) mod crc64;

/// Bytes per read in [`crc32_reader`] and [`crc32_file`] (API 10: "blocks
/// of at least 1 MiB").
const READ_BLOCK: usize = 1 << 20;

/// The smallest piece [`crc32_pieces`] gives a worker (spec L 3.1).
// Reached only through the `internals_*` seam, behind the
// `bench-internals` feature; no shipped build enables it.
#[allow(dead_code)]
const MIN_PIECE: usize = 1 << 20;

/// The reflected CRC-32 (IEEE 802.3) byte table, `T[x]` of spec K 3.1:
/// start from `x`, eight times shift right one bit, XOR `0xEDB88320` when
/// the bit shifted out was set. Shared by the CRC32 and the legacy ciphers.
pub(crate) static CRC32_TABLE: [u32; 256] = crc32_table();

const fn crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
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
        table[x] = c;
        x += 1;
    }
    table
}

/// The CRC32 of one buffer, for a caller with nothing to resume from.
///
/// Spec L 3.1 pins the answer: the reflected CRC-32 of polynomial
/// `0xEDB88320`, so `123456789` gives `0xCBF43926` and no bytes at all
/// give 0. This is [`Crc32`] driven once and finished, and it reaches the
/// same kernels, so a caller loses nothing by preferring it.
pub fn crc32(data: &[u8]) -> u32 {
    let mut running = Crc32::new();
    running.update(data);
    running.finish()
}

/// A CRC32 register a caller feeds in as many pieces as it likes.
///
/// The state is the finished CRC of everything fed so far, so [`finish`]
/// is free and a hasher can be built from a CRC someone else computed.
///
/// [`finish`]: Crc32::finish
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Crc32 {
    state: u32,
}

impl Crc32 {
    /// A register that has been fed nothing, which spec L 3.1 fixes at 0.
    pub fn new() -> Self {
        Crc32 { state: 0 }
    }

    /// Roll `data` into the register.
    ///
    /// This is the one line of CRC32 that is not `crc32fast`, and spec
    /// L 3.1's erratum of 18 Sep 2026 says why. `crc32fast` is the
    /// implementation the section names and the only one on most boxes;
    /// but its aarch64 path chains the CRC32 instruction eight bytes at a
    /// time, which is bound by latency rather than by the machine, and it
    /// came in at 0.429x of the ceiling section 7 sets. So on aarch64 with
    /// PMULL, the CRC32 instructions and EOR3, the bytes go through an
    /// eight-lane carry-less fold instead, and everywhere else through
    /// `crc32fast` as before.
    ///
    /// The choice is made below this line, not here, and the fold is
    /// NEITHER written nor owned by this package: the erratum has it
    /// carried in whole, so what belongs to CRC32 is the call and the
    /// promise around it. That promise is that the two paths are the same
    /// function - same register out for the same bytes in, at any length,
    /// from any starting register, across any split - which is a
    /// differential test's job to hold and not a caller's to think about.
    pub fn update(&mut self, data: &[u8]) {
        self.state = wiring::crc32_update(self.state, data);
    }

    /// The register as it stands, which spec L 3.1 makes the CRC of
    /// everything fed so far.
    pub fn finish(&self) -> u32 {
        self.state
    }
}

impl Crc32 {
    /// The register after `n` further zero bytes, in `O(log n)`: the
    /// standard GF(2) matrix-squaring method (spec L 3.1).
    // Live in the `cfg(test)` build only: this package's own tests are its
    // one caller.
    #[allow(dead_code)]
    pub(crate) fn update_zeros(&mut self, n: u64) {
        // Feeding zeros is linear on the INTERNAL register, which is the
        // finished CRC with every bit flipped; `shift` is linear on the
        // finished value, so cross into the register and back.
        self.state = shift(self.state ^ !0, n) ^ !0;
    }

    /// The CRC32 of `A || B` from `CRC(A)`, `CRC(B)` and `B`'s length.
    ///
    /// Shipped since the stored split CRC share: `append` below is how a
    /// split stored member's checksum takes the CRC its fragment check
    /// already computed, once per read, which is why `shift` is a table.
    pub(crate) fn combine(a: u32, b: u32, len_b: u64) -> u32 {
        shift(a, len_b) ^ b
    }

    /// Append bytes whose own CRC32, `crc`, someone else computed: the
    /// register then holds the CRC of everything before them and them.
    pub(crate) fn append(&mut self, crc: u32, len: u64) {
        self.state = Self::combine(self.state, crc, len);
    }
}

/// One step of the operator: `crc` advanced past as many zero bytes as
/// `matrix` encodes, as a GF(2) matrix-vector product over the bits.
fn matrix_times(matrix: &[u32; 32], mut vec: u32) -> u32 {
    let mut sum = 0u32;
    let mut i = 0;
    while vec != 0 {
        if vec & 1 != 0 {
            sum ^= matrix[i];
        }
        vec >>= 1;
        i += 1;
    }
    sum
}

#[cfg(test)]
/// `square = matrix * matrix`: the operator for twice as many zero bytes.
fn matrix_square(square: &mut [u32; 32], matrix: &[u32; 32]) {
    for (out, &row) in square.iter_mut().zip(matrix.iter()) {
        *out = matrix_times(matrix, row);
    }
}

/// `matrix_times` for a compile-time table.
const fn const_times(matrix: &[u32; 32], mut vec: u32) -> u32 {
    let mut sum = 0u32;
    let mut i = 0;
    while vec != 0 {
        if vec & 1 != 0 {
            sum ^= matrix[i];
        }
        vec >>= 1;
        i += 1;
    }
    sum
}

/// `matrix * matrix`, for a compile-time table.
const fn const_square(matrix: &[u32; 32]) -> [u32; 32] {
    let mut out = [0u32; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = const_times(matrix, matrix[i]);
        i += 1;
    }
    out
}

/// `POWERS[k]` advances a CRC past `2^k` zero bytes: the byte operator
/// squared `k` times, every power a `u64` length can name. 8 KiB of
/// read-only data built by the compiler, so `shift` applies one matrix
/// per set bit of the length and squares nothing at run time.
const POWERS: [[u32; 32]; 64] = {
    // The one-BIT operator, as in `shift_squaring` below.
    let mut bit = [0u32; 32];
    bit[0] = 0xEDB8_8320;
    let mut i = 1;
    while i < 32 {
        bit[i] = 1u32 << (i - 1);
        i += 1;
    }
    let two = const_square(&bit);
    let four = const_square(&two);
    let mut powers = [[0u32; 32]; 64];
    powers[0] = const_square(&four);
    let mut k = 1;
    while k < 64 {
        powers[k] = const_square(&powers[k - 1]);
        k += 1;
    }
    powers
};

/// `crc` advanced past `n` zero bytes, as the linear operator alone (no
/// initial or final inversion: those cancel in both callers above).
///
/// The powers of one operator commute, so the set bits of `n` may be
/// visited in any order; lowest first is the cheapest to find.
fn shift(crc: u32, n: u64) -> u32 {
    let mut crc = crc;
    let mut n = n;
    while n != 0 && crc != 0 {
        crc = matrix_times(&POWERS[n.trailing_zeros() as usize], crc);
        n &= n - 1;
    }
    crc
}

/// The run-time squaring form the table replaced, kept as the reference
/// the table is tested against.
#[cfg(test)]
fn shift_squaring(crc: u32, n: u64) -> u32 {
    if n == 0 || crc == 0 {
        return if n == 0 { crc } else { 0 };
    }
    // The one-BIT operator: bit 0 of the register shifts out through the
    // polynomial, every other bit shifts down one place.
    let mut odd = [0u32; 32];
    odd[0] = 0xEDB8_8320;
    let mut row = 1u32;
    for slot in odd.iter_mut().skip(1) {
        *slot = row;
        row <<= 1;
    }
    let mut even = [0u32; 32];
    // Two bits, then four: the byte operator is eight bit steps, so two
    // squarings from the bit operator give four bits and the loop below
    // starts at one byte.
    matrix_square(&mut even, &odd);
    matrix_square(&mut odd, &even);

    let mut crc = crc;
    let mut n = n;
    loop {
        // `odd` now advances four bits; squaring it gives one byte.
        matrix_square(&mut even, &odd);
        if n & 1 != 0 {
            crc = matrix_times(&even, crc);
        }
        n >>= 1;
        if n == 0 {
            break;
        }
        matrix_square(&mut odd, &even);
        if n & 1 != 0 {
            crc = matrix_times(&odd, crc);
        }
        n >>= 1;
        if n == 0 {
            break;
        }
    }
    crc
}

/// The CRC32 of `pieces` concatenated, on up to `workers` threads.
///
/// Identical to one pass over the same bytes for every split: each piece
/// group is hashed independently and the results joined with
/// [`Crc32::combine`]. Groups are at least [`MIN_PIECE`] bytes, so a small
/// buffer never pays for a spawn.
// Reached only through the `internals_*` seam, behind the
// `bench-internals` feature; no shipped build enables it.
#[allow(dead_code)]
pub(crate) fn crc32_pieces(pieces: &[&[u8]], workers: usize) -> u32 {
    let total: usize = pieces.iter().map(|p| p.len()).sum();
    let serial = || {
        let mut hasher = crc32fast::Hasher::new();
        for piece in pieces {
            hasher.update(piece);
        }
        hasher.finalize()
    };
    #[cfg(not(feature = "parallel"))]
    {
        let _ = (total, workers);
        serial()
    }
    #[cfg(feature = "parallel")]
    {
        use crate::carry::g_recovery::crc32::PARALLEL_PIECES_MIN_BYTES;
        if workers <= 1 || total < PARALLEL_PIECES_MIN_BYTES || pieces.len() < 2 {
            return serial();
        }
        // Gather whole pieces into at most `workers` groups of at least
        // MIN_PIECE bytes. Splitting a piece would gain nothing: the join
        // is exact wherever the cut falls, and whole pieces keep the group
        // boundaries aligned with the caller's own buffers.
        let target = (total / workers).max(MIN_PIECE);
        let mut groups: Vec<(usize, usize)> = Vec::new();
        let (mut start, mut acc) = (0usize, 0usize);
        for (i, piece) in pieces.iter().enumerate() {
            acc += piece.len();
            if acc >= target && groups.len() + 1 < workers {
                groups.push((start, i + 1));
                start = i + 1;
                acc = 0;
            }
        }
        if start < pieces.len() {
            groups.push((start, pieces.len()));
        }
        if groups.len() < 2 {
            return serial();
        }
        use rayon::prelude::*;
        let parts: Vec<(u32, u64)> = groups
            .par_iter()
            .map(|&(a, b)| {
                let mut hasher = crc32fast::Hasher::new();
                let mut len = 0u64;
                for piece in &pieces[a..b] {
                    hasher.update(piece);
                    len += piece.len() as u64;
                }
                (hasher.finalize(), len)
            })
            .collect();
        parts
            .into_iter()
            .fold(0u32, |acc, (crc, len)| Crc32::combine(acc, crc, len))
    }
}

/// Build every later BLAKE2sp hasher with `workers` as its allowance
/// instead of its caller's, or with the caller's own at `None`.
///
/// A lab dial and
/// nothing else: it moves which threads hash a member, never a digest or a
/// verdict. Behind the `f8x16-probe` feature, which no shipped build and
/// no gate binary enables.
#[cfg(feature = "f8x16-probe")]
pub fn probe_blake_team(workers: Option<usize>) {
    blake2sp::TEAM_OVERRIDE.store(workers.unwrap_or(0), std::sync::atomic::Ordering::Relaxed);
}

/// BLAKE2sp of `data` at an allowance of `workers`, for the same lab and
/// behind the same feature: the raw cost of one member's checksum.
#[cfg(feature = "f8x16-probe")]
pub fn probe_blake2sp(data: &[u8], workers: usize) -> [u8; 32] {
    blake2sp::blake2sp_with_workers(data, workers)
}

/// The same through the STREAMING hasher fed in `chunk` byte pieces, which
/// is how the read path feeds a member's output to it.
#[cfg(feature = "f8x16-probe")]
pub fn probe_blake2sp_chunked(data: &[u8], workers: usize, chunk: usize) -> [u8; 32] {
    let mut hasher = blake2sp::Blake2sp::with_workers(workers);
    for piece in data.chunks(chunk.max(1)) {
        hasher.update(piece);
    }
    hasher.finalize()
}

/// Drain `r` and report how many bytes came out and what they hash to.
///
/// The reader is taken to its end, so this returns on end of stream or on
/// the reader's own error and never part way.
pub fn crc32_reader(r: &mut dyn Read) -> std::io::Result<(u64, u32)> {
    let mut buf = vec![0u8; READ_BLOCK];
    let mut hasher = crc32fast::Hasher::new();
    let mut len = 0u64;
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            return Ok((len, hasher.finalize()));
        }
        hasher.update(&buf[..n]);
        len += n as u64;
    }
}

/// Hash a file the caller names by path, reporting its length with the
/// CRC.
///
/// Section 10 answers open question 4 by making this one of only two
/// places in the crate that opens a path itself; everywhere else takes a
/// source already opened. Reads are positional and at least 1 MiB at a
/// time, as that section requires, so the file is never wholly resident
/// however large it is.
pub fn crc32_file(path: &Path) -> std::io::Result<(u64, u32)> {
    use crate::source::RangeSource;
    let file = std::fs::File::open(path)?;
    let mut buf = vec![0u8; READ_BLOCK];
    let mut hasher = crc32fast::Hasher::new();
    let mut at = 0u64;
    loop {
        let n = RangeSource::read_at(&file, at, &mut buf)?;
        if n == 0 {
            return Ok((at, hasher.finalize()));
        }
        hasher.update(&buf[..n]);
        at += n as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_value_and_empty() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
        assert_eq!(Crc32::new().finish(), 0);
    }

    #[test]
    fn incremental_matches_one_shot_for_every_split() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
        for cut in [0, 1, 3, 64, 255, 256, 999, 1000] {
            let mut h = Crc32::new();
            h.update(&data[..cut]);
            h.update(&data[cut..]);
            assert_eq!(h.finish(), crc32(&data), "cut {cut}");
        }
    }

    #[test]
    fn update_zeros_matches_feeding_zeros() {
        for n in [0u64, 1, 7, 64, 4095, 65536, 1_000_000] {
            for prefix in [&b""[..], &b"123456789"[..]] {
                let mut fast = Crc32::new();
                fast.update(prefix);
                fast.update_zeros(n);
                let mut slow = Crc32::new();
                slow.update(prefix);
                slow.update(&vec![0u8; n as usize]);
                assert_eq!(fast.finish(), slow.finish(), "n {n}");
            }
        }
    }

    /// The table form against the squaring form it replaces, over every
    /// basis register and every power, and a spread of lengths.
    #[test]
    fn the_shift_table_is_the_squaring_operator() {
        for bit in 0..32 {
            for (k, power) in POWERS.iter().enumerate() {
                let crc = 1u32 << bit;
                let n = 1u64 << k;
                assert_eq!(
                    super::const_times(power, crc),
                    shift_squaring(crc, n),
                    "bit {bit} power {k}"
                );
            }
        }
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        for _ in 0..2000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let crc = (x >> 32) as u32;
            for n in [x, x >> 40, x & 0xFFFF, 0, 1, u64::MAX, 1 << 32, 128 << 10] {
                assert_eq!(shift(crc, n), shift_squaring(crc, n), "crc {crc:#x} n {n}");
            }
        }
        assert_eq!(shift(0, 12345), 0);
        assert_eq!(shift(0xDEAD_BEEF, 0), 0xDEAD_BEEF);
    }

    /// `append` joins a prefix's register and a suffix's own CRC.
    #[test]
    fn append_matches_one_pass() {
        let data: Vec<u8> = (0..5000u32).map(|i| (i * 7 + i / 13) as u8).collect();
        for cut in [0, 1, 7, 64, 2500, 4999, 5000] {
            let (a, b) = data.split_at(cut);
            let mut joined = Crc32::new();
            joined.update(a);
            joined.append(crc32(b), b.len() as u64);
            assert_eq!(joined.finish(), crc32(&data), "append at {cut}");
        }
    }

    #[test]
    fn combine_matches_one_pass() {
        let data: Vec<u8> = (0..5000u32).map(|i| (i * 31 + 11) as u8).collect();
        for cut in [0usize, 1, 2, 3, 1023, 1024, 4999, 5000] {
            let joined = Crc32::combine(
                crc32(&data[..cut]),
                crc32(&data[cut..]),
                (data.len() - cut) as u64,
            );
            assert_eq!(joined, crc32(&data), "cut {cut}");
        }
    }

    #[test]
    fn pieces_match_one_pass() {
        let data: Vec<u8> = (0..(5 << 20) as u32)
            .map(|i| (i ^ (i >> 5)) as u8)
            .collect();
        for cuts in [
            vec![0usize, data.len()],
            vec![0, 1, 1 << 20, 3 << 20, data.len()],
            vec![0, 7, 9, 4_000_000, data.len()],
        ] {
            let pieces: Vec<&[u8]> = cuts.windows(2).map(|w| &data[w[0]..w[1]]).collect();
            for workers in [1usize, 2, 4, 16] {
                assert_eq!(crc32_pieces(&pieces, workers), crc32(&data));
            }
        }
    }

    #[test]
    fn reader_and_file_agree() {
        let data: Vec<u8> = (0..3_000_000u32).map(|i| (i * 13) as u8).collect();
        let mut cursor = std::io::Cursor::new(&data);
        assert_eq!(
            crc32_reader(&mut cursor).unwrap(),
            (data.len() as u64, crc32(&data))
        );
        let dir = std::env::temp_dir().join("rarkit-crc32-file-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("data.bin");
        std::fs::write(&path, &data).unwrap();
        assert_eq!(
            crc32_file(&path).unwrap(),
            (data.len() as u64, crc32(&data))
        );
        let _ = std::fs::remove_file(&path);
    }
}
