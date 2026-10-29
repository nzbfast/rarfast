//! GF(2^16), the Cauchy code, and the fold kernel (spec L 3.4).
//!
//! The field is spec B part 2's: `x^16 + x^12 + x^3 + x + 1` (`0x1100B`),
//! generator 2, addition XOR. The code is Cauchy: the coefficient of data
//! shard `j` in recovery row `i` of a `k`-shard set is the inverse of
//! `(i + k) XOR j`, which is never zero because `j < k <= i + k`. Every
//! square submatrix of such a matrix is invertible, so any `d` intact rows
//! rebuild any `d` missing shards.
//!
//! `fold(dst, src, c)` - `dst ^= c * src`, symbol by symbol - is the kernel
//! of both encode and repair. It never takes a logarithm per symbol: a
//! coefficient's tables are built once (`Coefficient::new`) and reused for
//! every byte it touches.

use std::sync::OnceLock;

/// The GFNI bit-matrix form of a coefficient. Only `fold_gfni` consumes
/// it, but its own tests build and check it on every target.
#[cfg(any(target_arch = "x86_64", test))]
pub(crate) mod affine;
pub(crate) mod kernels;

/// The field polynomial's low 16 bits: what a bit shifted out of the top of
/// a symbol folds back in as.
pub(crate) const REDUCTION: u16 = 0x100B;
/// Nonzero elements, which is the multiplicative order of the generator.
const ORDER: usize = 65_535;
/// The exponent table's length. `mul` indexes it with the sum of two
/// logarithms, at most `2 * 65534 = 131068`, and `inv` with `65535 - log`,
/// so the period is stored twice over and neither lookup needs a modulo.
const EXP_LEN: usize = 1 << 17;

/// The exponent and logarithm tables of GF(2^16).
pub(crate) struct Gf16 {
    exp: Box<[u16; EXP_LEN]>,
    log: Box<[u16; 65_536]>,
}

impl Gf16 {
    fn build() -> Gf16 {
        let mut exp = vec![0u16; EXP_LEN].into_boxed_slice();
        let mut log = vec![0u16; 65_536].into_boxed_slice();
        let mut value: u16 = 1;
        for i in 0..ORDER {
            exp[i] = value;
            log[value as usize] = i as u16;
            let carry = value & 0x8000 != 0;
            value <<= 1;
            if carry {
                value ^= REDUCTION;
            }
        }
        debug_assert_eq!(value, 1, "the generator's order is the field's");
        for i in ORDER..EXP_LEN {
            exp[i] = exp[i - ORDER];
        }
        Gf16 {
            exp: exp.try_into().expect("exponent table length"),
            log: log.try_into().expect("logarithm table length"),
        }
    }

    /// The field product; zero if either operand is zero.
    #[inline]
    pub(crate) fn mul(&self, x: u16, y: u16) -> u16 {
        if x == 0 || y == 0 {
            return 0;
        }
        self.exp[self.log[x as usize] as usize + self.log[y as usize] as usize]
    }

    /// The multiplicative inverse; `None` for zero.
    #[inline]
    pub(crate) fn inv(&self, x: u16) -> Option<u16> {
        if x == 0 {
            return None;
        }
        Some(self.exp[ORDER - self.log[x as usize] as usize])
    }

    /// `numerator / denominator`; `None` for a zero denominator.
    #[inline]
    // Required surface: spec B 2.1 lists `div` beside `mul` and `inv`.
    // Nothing inside this crate needs it yet.
    #[allow(dead_code)]
    pub(crate) fn div(&self, numerator: u16, denominator: u16) -> Option<u16> {
        self.inv(denominator).map(|i| self.mul(numerator, i))
    }
}

/// The process-wide field. Built once; the tables are 384 KiB in all.
pub(crate) fn field() -> &'static Gf16 {
    static FIELD: OnceLock<Gf16> = OnceLock::new();
    FIELD.get_or_init(Gf16::build)
}

/// The coefficient of data shard `col` in recovery row `row` of a code over
/// `k` data shards: the inverse of `(row + k) XOR col`.
///
/// `row + k` is at most 65,534 because `k + m <= 65,535`, and the XOR is
/// never zero because `col < k <= row + k`.
#[inline]
pub(crate) fn cauchy_cell(k: u16, row: u16, col: u16) -> u16 {
    let element = (row as u32 + k as u32) as u16 ^ col;
    field()
        .inv(element)
        .expect("a Cauchy element is never zero")
}

/// One coefficient's multiply tables: the scalar pair the fold falls back
/// on, and the nibble tables the SIMD kernels shuffle.
///
/// `c * x == lo[x & 0xff] ^ hi[x >> 8]`, because multiplication distributes
/// over XOR and `x = (x & 0xff) ^ ((x >> 8) << 8)`.
#[derive(Clone, Copy)]
pub(crate) struct Coefficient {
    pub(crate) value: u16,
    lo: [u16; 256],
    hi: [u16; 256],
    simd: crate::carry::h_ours::recovery::gf16_fold::FoldTables,
}

impl Coefficient {
    /// Tables for multiply-by-`c`.
    pub(crate) fn new(c: u16) -> Coefficient {
        let gf = field();
        let mut lo = [0u16; 256];
        let mut hi = [0u16; 256];
        for x in 0..256u32 {
            lo[x as usize] = gf.mul(c, x as u16);
            hi[x as usize] = gf.mul(c, (x as u16) << 8);
        }
        Coefficient {
            value: c,
            lo,
            hi,
            simd: crate::carry::h_ours::recovery::gf16_fold::FoldTables::new(c),
        }
    }

    /// `c * x` for one symbol.
    #[inline]
    pub(crate) fn apply(&self, x: u16) -> u16 {
        self.lo[(x & 0xff) as usize] ^ self.hi[(x >> 8) as usize]
    }

    /// `dst ^= c * src`, symbol by symbol, over `min(dst.len(), src.len())`
    /// bytes rounded down to a whole symbol. HOT PATH.
    pub(crate) fn fold(&self, dst: &mut [u8], src: &[u8]) {
        let len = dst.len().min(src.len()) & !1;
        let (dst, src) = (&mut dst[..len], &src[..len]);
        if self.value == 0 {
            return;
        }
        let done = kernels::fold(&self.simd, dst, src);
        // Whatever the kernel left: at most one chunk, and always a whole
        // number of symbols because every kernel's chunk is even.
        let (left, _) = dst[done..].as_chunks_mut::<2>();
        let (right, _) = src[done..].as_chunks::<2>();
        for (d, s) in left.iter_mut().zip(right) {
            let product = self.apply(u16::from_le_bytes(*s)) ^ u16::from_le_bytes(*d);
            *d = product.to_le_bytes();
        }
    }
}

/// Solve `matrix * x = rhs` over the field, in place, by Gaussian
/// elimination. `matrix` is `n` rows of `n` cells; `rhs` is `n` rows of
/// `width` bytes, and holds the solution on return.
///
/// `None` means the system was singular, which a Cauchy submatrix never is
/// - so it is reported as damage rather than trusted.
pub(crate) fn solve(matrix: &mut [Vec<u16>], rhs: &mut [Vec<u8>], width: usize) -> Option<()> {
    let n = matrix.len();
    // A system that is not `n` by `n` over `n` rows of `width` bytes is
    // not one this was asked to solve: it is answered like a singular one.
    if rhs.len() != n
        || matrix.iter().any(|cells| cells.len() != n)
        || rhs.iter().any(|bytes| bytes.len() < width)
    {
        return None;
    }
    let gf = field();
    // Spec L 3.4 S1: the columns in the order they stand, the diagonal
    // cell the divisor each time, no search for a pivot and no exchange
    // of rows. When column `at` is reached every column before it is
    // already a unit column, so the cells left of `at` in row `at` are
    // zero and the work on a row begins at `at`.
    for at in 0..n {
        // A zero here cannot come from a Cauchy system (every leading
        // square part of it is invertible): a fault, answered `None`.
        let unit = gf.inv(matrix[at][at])?;
        if unit != 1 {
            matrix[at][at] = 1;
            for cell in &mut matrix[at][at + 1..] {
                *cell = gf.mul(*cell, unit);
            }
            scale_row(&Coefficient::new(unit), &mut rhs[at][..width]);
        }
        for row in (0..n).filter(|&row| row != at) {
            let factor = matrix[row][at];
            if factor == 0 {
                continue;
            }
            // The divisor's cell is 1 by now, so this row's cell in the
            // column goes to zero without a product.
            let (from, into) = split_matrix(matrix, row, at);
            into[at] = 0;
            for (cell, &above) in into[at + 1..].iter_mut().zip(&from[at + 1..]) {
                *cell ^= gf.mul(factor, above);
            }
            let (into, from) = split_rows(rhs, row, at);
            Coefficient::new(factor).fold(&mut into[..width], &from[..width]);
        }
    }
    Some(())
}

/// `row *= c`, symbol by symbol.
fn scale_row(c: &Coefficient, row: &mut [u8]) {
    let (symbols, _) = row.as_chunks_mut::<2>();
    for symbol in symbols {
        *symbol = c.apply(u16::from_le_bytes(*symbol)).to_le_bytes();
    }
}

/// Two distinct rows of a matrix: the pivot's, read-only, and the one
/// being reduced.
fn split_matrix(rows: &mut [Vec<u16>], target: usize, pivot: usize) -> (&[u16], &mut [u16]) {
    debug_assert_ne!(target, pivot);
    if target < pivot {
        let (left, right) = rows.split_at_mut(pivot);
        (&right[0], &mut left[target])
    } else {
        let (left, right) = rows.split_at_mut(target);
        (&left[pivot], &mut right[0])
    }
}

/// Two distinct rows of `rows`, the first mutable.
fn split_rows(rows: &mut [Vec<u8>], target: usize, source: usize) -> (&mut [u8], &[u8]) {
    debug_assert_ne!(target, source);
    if target < source {
        let (left, right) = rows.split_at_mut(source);
        (&mut left[target], &right[0])
    } else {
        let (left, right) = rows.split_at_mut(target);
        (&mut right[0], &left[source])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec B 2.3, its four cases (drawn or forced, 11 Oct 2026; the
    /// numbers are the probe's). No genuine program shows a product or an
    /// inverse, so no sample value is pinned: each case is the definition
    /// of 2.1 held whole.
    #[test]
    fn field_check_values() {
        let gf = field();

        // Case 2, a cell of the code's matrix, at the drawn k = 16, i = 54,
        // j = 11: C(i, j) is the inverse of (i + k) XOR j.
        let (k, i, j): (u16, u16, u16) = (16, 54, 11);
        let element = (i + k) ^ j;
        let cell = cauchy_cell(k, i, j);
        assert_eq!(Some(cell), gf.inv(element));
        assert_eq!(gf.mul(cell, element), 1);
        assert_eq!(slow_mul(cell, element), 1);

        // Case 9, every inverse: x times its inverse is 1 for every
        // nonzero x, and zero has none.
        assert_eq!(gf.inv(0), None);
        assert_eq!(gf.div(1, 0), None);
        for x in 1..=u16::MAX {
            let inverse = gf.inv(x).expect("a nonzero element has an inverse");
            assert_eq!(gf.mul(x, inverse), 1, "{x:#x}");
            assert_eq!(gf.div(x, x), Some(1), "{x:#x}");
        }

        // Case 11, the overflow: products by 2, the operands rising. Up
        // to 0x7FFF, the last with no overflow, the product is the
        // operand doubled; from 0x8000, the first that overflows, it is
        // the doubling with its seventeenth bit dropped, XOR the low bits
        // of 2.1's polynomial. Two operands are drawn, one on each side.
        let no_overflow = |x: u16| x << 1;
        let overflowed = |x: u16| (x << 1) ^ REDUCTION;
        let products: [(u16, u16); 6] = [
            (0, 0),
            (1, 2),
            (0x15B6, no_overflow(0x15B6)),
            (0x7FFF, 0xFFFE),
            (0x8000, 0x100B),
            (0xF766, overflowed(0xF766)),
        ];
        assert!(products.windows(2).all(|pair| pair[0].0 < pair[1].0));
        for (operand, product) in products {
            assert_eq!(gf.mul(operand, 2), product, "{operand:#x}");
            assert_eq!(gf.mul(2, operand), product, "{operand:#x}");
            assert_eq!(slow_mul(operand, 2), product, "{operand:#x}");
        }
        assert_eq!(no_overflow(0x7FFF), 0xFFFE);
        assert_eq!(overflowed(0x8000), 0x100B);

        // Case 19, the powers of two: 65,535 distinct elements, so 2 is
        // primitive, and the next power is 1 again.
        let mut seen = vec![false; 1 << 16];
        let mut power = 1u16;
        for n in 0..ORDER {
            assert!(!seen[usize::from(power)], "2^{n} repeats");
            seen[usize::from(power)] = true;
            power = gf.mul(power, 2);
        }
        assert_eq!(power, 1);
        assert!(!seen[0]);
    }

    /// The carry-free product reduced by the polynomial, as an independent
    /// check on the log/exp tables.
    fn slow_mul(mut a: u16, mut b: u16) -> u16 {
        let mut product = 0u16;
        for _ in 0..16 {
            if b & 1 != 0 {
                product ^= a;
            }
            b >>= 1;
            let carry = a & 0x8000 != 0;
            a <<= 1;
            if carry {
                a ^= REDUCTION;
            }
        }
        product
    }

    #[test]
    fn tables_match_carry_free_multiplication() {
        let gf = field();
        let mut x: u32 = 0x1234_5678;
        for _ in 0..20_000 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            let (a, b) = ((x >> 16) as u16, x as u16);
            assert_eq!(gf.mul(a, b), slow_mul(a, b), "{a:#x} * {b:#x}");
        }
    }

    #[test]
    fn fold_kernels_match_the_scalar_definition() {
        let mut x: u32 = 0x9E37_79B9;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x
        };
        let src: Vec<u8> = (0..4096).map(|_| next() as u8).collect();
        // Six coefficients drawn, not chosen: the low 16 bits of the first
        // six outputs of the xorshift above (shifts 13, 17, 5 on a `u32`)
        // started from the seed 0x2026_1011. Three have the top bit set and
        // three do not; the test needs no particular value among them.
        for c in [0x6163u16, 0x9043, 0x64c6, 0x1241, 0xe8cf, 0xcbd9] {
            let coefficient = Coefficient::new(c);
            for len in [0usize, 2, 30, 32, 34, 62, 64, 66, 1000, 4096] {
                let mut fast = vec![0u8; len];
                fast.copy_from_slice(&src[..len]);
                let mut slow = fast.clone();
                coefficient.fold(&mut fast, &src[..len]);
                let (left, _) = slow.as_chunks_mut::<2>();
                let (right, _) = src[..len].as_chunks::<2>();
                for (d, s) in left.iter_mut().zip(right) {
                    *d = (coefficient.apply(u16::from_le_bytes(*s)) ^ u16::from_le_bytes(*d))
                        .to_le_bytes();
                }
                assert_eq!(fast, slow, "c {c:#x} len {len}");
            }
        }
    }

    #[test]
    fn fold_is_the_field_product() {
        let coefficient = Coefficient::new(0x1234);
        let src = [0x34u8, 0x12, 0xff, 0xff];
        let mut dst = [0u8; 4];
        coefficient.fold(&mut dst, &src);
        assert_eq!(
            u16::from_le_bytes([dst[0], dst[1]]),
            field().mul(0x1234, 0x1234)
        );
        assert_eq!(
            u16::from_le_bytes([dst[2], dst[3]]),
            field().mul(0x1234, 0xffff)
        );
    }

    #[test]
    fn cauchy_submatrices_invert() {
        // Any 3 rows against any 3 columns of a k = 10 code.
        let k = 10u16;
        let rows = [0u16, 2, 5];
        let columns = [1usize, 4, 9];
        let mut matrix: Vec<Vec<u16>> = rows
            .iter()
            .map(|&r| {
                columns
                    .iter()
                    .map(|&c| cauchy_cell(k, r, c as u16))
                    .collect()
            })
            .collect();
        // Right-hand side: the identity, one symbol wide per column.
        let mut rhs: Vec<Vec<u8>> = (0..3)
            .map(|r| {
                let mut row = vec![0u8; 6];
                row[2 * r..2 * r + 2].copy_from_slice(&1u16.to_le_bytes());
                row
            })
            .collect();
        let original = matrix.clone();
        solve(&mut matrix, &mut rhs, 6).expect("a Cauchy submatrix inverts");
        // original * inverse = identity.
        let gf = field();
        for (i, original_row) in original.iter().enumerate() {
            for j in 0..3 {
                let cell = (0..3).fold(0u16, |acc, t| {
                    let inv = u16::from_le_bytes([rhs[t][2 * j], rhs[t][2 * j + 1]]);
                    acc ^ gf.mul(original_row[t], inv)
                });
                assert_eq!(cell, u16::from(i == j), "cell {i},{j}");
            }
        }
    }
}
