//! Multiply-by-a-constant over GF(2^16) as GFNI bit matrices (spec L 3.4).
//!
//! Multiplication by a fixed `c` is linear over GF(2): `c * (u ^ v)` is
//! `c * u ^ c * v`, and the field's addition IS exclusive or. In the
//! polynomial basis a symbol is the sum of the basis elements its set bits
//! select, `x^k` being the bit pattern `1 << k`, so multiply-by-`c` is
//! completely described by the sixteen images `c * x^k`: it is the 16x16
//! bit matrix over GF(2) whose column `k` is that image.
//!
//! x86-64's `gf2p8affineqb` applies 8x8 bit matrices to bytes, so that
//! 16x16 matrix crosses as its four 8x8 blocks - source low or high byte,
//! to product low or high byte. A block's columns are the eight images
//! belonging to its source byte, narrowed to the product byte it feeds.
//! The fold XORs the two blocks that reach each output byte, which is the
//! same statement as `c * x == c * (x & 0xff) ^ c * (x & 0xff00)`.
//!
//! THE PACKING ORDER IS INTEL'S, not a choice made here. Intel's
//! definition of the instruction (Intel 64 and IA-32 Architectures
//! Software Developer's Manual, GF2P8AFFINEQB; the same pseudocode appears
//! in the Intel Intrinsics Guide under `_mm256_gf2p8affine_epi64_epi8`)
//! says that with an immediate of zero, output bit `i` of a byte is the
//! parity of the source byte ANDed with BYTE `7 - i` of the matrix qword,
//! and bit `j` within that byte selects source bit `j`. So row `i` of the
//! matrix - the row that produces output bit `i` - is stored in qword byte
//! `7 - i`: row 0 in the most significant byte, row 7 in the least.
//!
//! `super::kernels` never calls this on a target without GFNI; the tests
//! below build the matrices on every target and check them by applying
//! them in plain scalar code, straight from that definition.

use super::REDUCTION;

/// The images of the sixteen basis elements under multiply-by-`c`:
/// `images[k] == c * x^k`, for `k` in 0..16.
///
/// `c * x^0` is `c`, and each step is one multiply by `x`: shift left, and
/// where a bit leaves the top of the symbol, fold the field polynomial's
/// low 16 bits back in. This is the chain `FoldTables::new` already walks
/// for the nibble tables, and it agrees with `field().mul(c, 1 << k)` for
/// every `c` and `k` - which the tests assert rather than assume.
fn basis_images(c: u16) -> [u16; 16] {
    let mut images = [0u16; 16];
    let mut value = c;
    for slot in images.iter_mut() {
        *slot = value;
        let overflowed = value & 0x8000 != 0;
        value <<= 1;
        if overflowed {
            value ^= REDUCTION;
        }
    }
    images
}

/// Pack one 8x8 block into a `gf2p8affineqb` matrix operand.
///
/// `source` is 0 for the block driven by a symbol's low byte and 8 for the
/// one driven by its high byte, so the block's column `j` is the image
/// `images[source + j]`. `shift` picks which byte of that image the block
/// feeds: 0 for the product's low byte, 8 for its high byte. Row `i`
/// collects bit `i` of each column, and goes into qword byte `7 - i` per
/// the instruction's definition above.
fn pack(images: &[u16; 16], source: usize, shift: u32) -> u64 {
    let mut matrix = 0u64;
    for i in 0..8 {
        let mut row = 0u8;
        for j in 0..8 {
            let column = images[source + j];
            row |= (((column >> shift) as u8 >> i) & 1) << j;
        }
        matrix |= (row as u64) << (8 * (7 - i));
    }
    matrix
}

/// The four matrix operands of multiply-by-`c`, in the order `fold_gfni`
/// consumes them: source low byte to product low byte, source high byte to
/// product low byte, then the same two to the product's high byte.
pub(crate) fn matrices(c: u16) -> [u64; 4] {
    let images = basis_images(c);
    [
        pack(&images, 0, 0),
        pack(&images, 8, 0),
        pack(&images, 0, 8),
        pack(&images, 8, 8),
    ]
}

#[cfg(test)]
mod tests {
    use super::super::field;
    use super::*;

    /// One byte through one matrix operand, exactly as Intel defines
    /// `gf2p8affineqb` with an immediate of zero: output bit `i` is the
    /// parity of the source byte ANDed with byte `7 - i` of the qword.
    ///
    /// Written from the definition and nothing else - it is the reference
    /// the packing is checked against, so it may not share code with it.
    fn emulate(matrix: u64, source: u8) -> u8 {
        let mut out = 0u8;
        for i in 0..8 {
            let row = (matrix >> (8 * (7 - i))) as u8;
            let mut parity = 0u8;
            for j in 0..8 {
                parity ^= ((row >> j) & 1) & ((source >> j) & 1);
            }
            out |= parity << i;
        }
        out
    }

    /// The four blocks reassembled into the 16-bit product, the way
    /// `fold_gfni` does it: each output byte is the XOR of the two blocks
    /// that reach it.
    fn apply(matrices: &[u64; 4], x: u16) -> u16 {
        let (low, high) = ((x & 0xff) as u8, (x >> 8) as u8);
        let product_low = emulate(matrices[0], low) ^ emulate(matrices[1], high);
        let product_high = emulate(matrices[2], low) ^ emulate(matrices[3], high);
        (product_high as u16) << 8 | product_low as u16
    }

    /// Deterministic xorshift64, as the other test files here use.
    fn next(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    /// The basis chain is the field multiply. This is the identity the
    /// packing rests on, so it is checked on its own first: if it holds,
    /// `matrices` needs no 384 KiB logarithm table to be built.
    #[test]
    fn basis_images_are_the_field_product() {
        let gf = field();
        let mut state = 0x243F_6A88_85A3_08D3u64;
        let mut constants = vec![0u16, 1, 2, 0xFFFF, 0x8000, 0x100B];
        constants.extend((0..4096).map(|_| next(&mut state) as u16));
        for c in constants {
            let images = basis_images(c);
            for (k, &image) in images.iter().enumerate() {
                assert_eq!(
                    image,
                    gf.mul(c, 1 << k),
                    "c * x^{k} for c = {c:#06x}: chain gave {image:#06x}"
                );
            }
        }
    }

    /// Every basis element, through the packed matrices, against the field.
    ///
    /// Column `j` of the whole map is the image of `1 << j`, so this checks
    /// the matrices column by column: sixteen single-bit inputs per
    /// constant, which pins every one of the 256 bits of the four operands.
    #[test]
    fn packed_matrices_agree_on_every_basis_element() {
        let gf = field();
        let mut state = 0x13198A2E_03707344u64;
        let mut constants = vec![0u16, 1, 2, 0xFFFF];
        constants.extend((0..4096).map(|_| next(&mut state) as u16));
        for c in constants {
            let packed = matrices(c);
            for j in 0..16 {
                let x = 1u16 << j;
                assert_eq!(
                    apply(&packed, x),
                    gf.mul(c, x),
                    "c = {c:#06x}, basis element {x:#06x}"
                );
            }
        }
    }

    /// Whole 16-bit inputs, which is the linearity claim itself: the two
    /// blocks feeding an output byte must XOR to the product's byte for
    /// arbitrary symbols, not only for single-bit ones.
    #[test]
    fn packed_matrices_agree_on_whole_symbols() {
        let gf = field();
        let mut state = 0xA409_3822_299F_31D0u64;
        let mut constants = vec![0u16, 1, 2, 0xFFFF];
        constants.extend((0..2048).map(|_| next(&mut state) as u16));
        for c in constants {
            let packed = matrices(c);
            let mut inputs = vec![0u16, 1, 0xFFFF, 0x8000];
            inputs.extend((0..64).map(|_| next(&mut state) as u16));
            for x in inputs {
                assert_eq!(
                    apply(&packed, x),
                    gf.mul(c, x),
                    "c = {c:#06x} times {x:#06x}"
                );
            }
        }
    }

    /// Multiply by one is the identity map, so its four blocks are the
    /// identity matrix, the identity matrix and two zeroes - a value that
    /// can be read off the packing rule by hand and so catches a
    /// wholesale mis-ordering that the agreement tests above, which use
    /// the same `emulate` on both sides of the low/high split, could not.
    #[test]
    fn multiply_by_one_is_the_documented_identity() {
        // Row i lands in byte 7 - i with bit i set: row 0 is 0x01 in the
        // most significant byte, row 7 is 0x80 in the least.
        let identity = 0x0102_0408_1020_4080u64;
        assert_eq!(matrices(1), [identity, 0, 0, identity]);
        assert_eq!(matrices(0), [0, 0, 0, 0]);
    }
}
