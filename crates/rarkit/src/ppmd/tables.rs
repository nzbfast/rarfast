//! Spec I section 3.11: the constant tables, generated from the rules the
//! specification states beside each one so the shape is checked, not typed.

/// Seeds for the binary-context probability table (spec I 3.5 step 5).
pub(super) const INIT_BIN: [u16; 8] = [
    0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051,
];

/// The escape allowance a binary context's updated probability implies
/// (spec I 3.7 path B step 5).
pub(super) const ESC_AFTER_BINARY: [u8; 16] = [25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2];

/// `bin_class[n - 1]` for a parent of `n` states: 0, 2, 4 or 6.
pub(super) const BIN_CLASS: [u8; 256] = {
    let mut t = [6u8; 256];
    t[0] = 0;
    t[1] = 2;
    let mut i = 2;
    while i <= 10 {
        t[i] = 4;
        i += 1;
    }
    t
};

/// `esc_class[u - 1]` for `u` unmasked states. The first three entries are
/// 0, 1, 2; from index 3 the value `v` runs for `v - 2` indices, which lands
/// value 24 exactly on 234 to 255.
pub(super) const ESC_CLASS: [u8; 256] = {
    let mut t = [0u8; 256];
    t[1] = 1;
    t[2] = 2;
    let (mut i, mut v) = (3usize, 3u8);
    while i < 256 {
        let mut run = v as usize - 2;
        while run > 0 && i < 256 {
            t[i] = v;
            i += 1;
            run -= 1;
        }
        v += 1;
    }
    t
};

/// Units per size class (spec I 3.4.1). 38 classes, steps of 1, 2, 3 then 4.
pub(super) const UNITS_OF: [u8; CLASSES] = [
    1, 2, 3, 4, 6, 8, 10, 12, 15, 18, 21, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76,
    80, 84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124, 128,
];

/// How many size classes there are.
pub(super) const CLASSES: usize = 38;

/// `CLASS_OF[u]` is the smallest class whose blocks hold `u` units, for `u`
/// in 1 to 128. Index 0 is unused.
pub(super) const CLASS_OF: [u8; 129] = {
    let mut t = [0u8; 129];
    let mut u = 1usize;
    while u <= 128 {
        let mut k = 0usize;
        while (UNITS_OF[k] as usize) < u {
            k += 1;
        }
        t[u] = k as u8;
        u += 1;
    }
    t
};

/// 0 for a symbol below 64, 8 for one at or above it (spec I 3.7).
#[inline(always)]
pub(super) fn hb(sym: u8) -> usize {
    usize::from(sym >= 64) * 8
}
