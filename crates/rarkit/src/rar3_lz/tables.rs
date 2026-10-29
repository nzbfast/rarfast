//! The four ladders of SPEC-H1 sections 3.4 and 3.5, checked row by row
//! against `specs/vectors-H/ladders.tsv` by this package's tests.

/// Symbols in the code length alphabet (SPEC-H1 3.3).
pub(crate) const LEVEL_SYMBOLS: usize = 20;
/// Symbols in the main alphabet (3.4).
pub(crate) const MAIN_SYMBOLS: usize = 299;
/// Slots in the distance alphabet (3.5).
pub(crate) const DISTANCE_SYMBOLS: usize = 60;
/// Symbols in the low distance alphabet (3.5).
pub(crate) const LOW_SYMBOLS: usize = 17;
/// Slots in the length alphabet (3.4).
pub(crate) const LENGTH_SYMBOLS: usize = 28;
/// Code lengths one table read produces, in the order main, distance, low
/// distance, length (3.2).
pub(crate) const TABLE_LENGTHS: usize =
    MAIN_SYMBOLS + DISTANCE_SYMBOLS + LOW_SYMBOLS + LENGTH_SYMBOLS;

/// Base of each length slot, before the arm's bonus (3.4).
pub(crate) const LENGTH_BASE: [u16; LENGTH_SYMBOLS] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128,
    160, 192, 224,
];
/// Extra bits of each length slot (3.4).
pub(crate) const LENGTH_EXTRA: [u8; LENGTH_SYMBOLS] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5,
];
/// A fresh match's length is `LENGTH_BASE + FRESH_LENGTH_BONUS + extra`.
pub(crate) const FRESH_LENGTH_BONUS: u32 = 3;
/// A repeated distance match's length is `LENGTH_BASE + REPEAT_LENGTH_BONUS
/// + extra`, and gets no distance bonus.
pub(crate) const REPEAT_LENGTH_BONUS: u32 = 2;

/// Base of each distance slot; the distance is `DISTANCE_BASE + 1 + extra`
/// (3.5).
pub(crate) const DISTANCE_BASE: [u32; DISTANCE_SYMBOLS] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
    2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608,
    262144, 327680, 393216, 458752, 524288, 589824, 655360, 720896, 786432, 851968, 917504, 983040,
    1048576, 1310720, 1572864, 1835008, 2097152, 2359296, 2621440, 2883584, 3145728, 3407872,
    3670016, 3932160,
];
/// Extra bits of each distance slot (3.5).
pub(crate) const DISTANCE_EXTRA: [u8; DISTANCE_SYMBOLS] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18,
];
/// The largest distance the ladder can name, which is also the largest
/// dictionary the RAR 3 family declares (3.5).
pub(crate) const MAX_DISTANCE: u32 = 4 * 1024 * 1024;

/// Base of each short distance slot; the distance is `SHORT_BASE + 1 +
/// extra` and the length is exactly 2 (3.5).
pub(crate) const SHORT_BASE: [u32; 8] = [0, 4, 8, 16, 32, 64, 128, 192];
/// Extra bits of each short distance slot (3.5).
pub(crate) const SHORT_EXTRA: [u8; 8] = [2, 2, 3, 4, 5, 6, 6, 6];

/// A fresh match's length gains one byte at this distance and one more at
/// [`FAR_BONUS_TWO`] (3.5).
pub(crate) const FAR_BONUS_ONE: u32 = 0x2000;
/// The second length bonus boundary (3.5).
pub(crate) const FAR_BONUS_TWO: u32 = 0x40000;

/// The low distance symbol that repeats the remembered low part for the
/// next fifteen far distances (3.5).
pub(crate) const LOW_REPEAT: u16 = 16;
/// How many further distances one [`LOW_REPEAT`] serves.
pub(crate) const LOW_REPEAT_RUN: u32 = 15;
