//! The fixed prefix codes of spec A 4.2 and 4.3, as lookups on the next
//! bits of the stream.
//!
//! Every code of 4.2 is at most 12 bits long and complete, so the next 12
//! bits name exactly one codeword: a lookup of 4,096 entries answers the
//! value and how many bits its codeword took. The short-match index codes
//! of 4.3 are at most 8 bits long and take a lookup of 256.

/// One code of 4.2: for each 12 bit window, `value << 4 | codeword length`.
pub(super) type Wide = [u16; 4096];

/// One column of 4.3: for each 8 bit window, `index << 4 | codeword length`.
pub(super) type Narrow = [u8; 256];

/// One used length of a code, as 4.2.1 holds it: the length in bits and
/// the LAST value that length gives. A length's first value is one more
/// than the row before's last, 0 for the first row.
type Row = (u8, u16);

/// The lookup of one code from its rows (4.2.1), by the canonical rule of
/// 4.2: values in increasing order take codewords in increasing order,
/// and a codeword of `length` bits owns the `2^(12 - length)` windows that
/// start with it. A complete code leaves no window over and none short,
/// which is checked where the table is built.
const fn windows(rows: &[Row]) -> Wide {
    let mut lookup = [0u16; 4096];
    // The first window no codeword owns yet, and the first value with no
    // codeword yet.
    let mut window = 0usize;
    let mut value = 0u16;
    let mut row = 0;
    while row < rows.len() {
        let (length, last) = rows[row];
        let share = 1usize << (12 - length);
        while value <= last {
            let end = window + share;
            while window < end {
                lookup[window] = value << 4 | length as u16;
                window += 1;
            }
            value += 1;
        }
        row += 1;
    }
    assert!(window == lookup.len(), "the rows are not a complete code");
    lookup
}

/// Table 4.2.1's `LENA`.
pub(super) static LENA: Wide = windows(&[
    (2, 1),
    (3, 2),
    (4, 4),
    (5, 6),
    (6, 10),
    (7, 15),
    (8, 19),
    (9, 23),
    (10, 31),
    (12, 255),
]);
/// Table 4.2.1's `LENB`.
pub(super) static LENB: Wide = windows(&[
    (3, 4),
    (4, 6),
    (5, 8),
    (6, 12),
    (7, 17),
    (8, 21),
    (9, 25),
    (10, 33),
    (11, 35),
    (12, 255),
]);
/// The five rank codes of 4.2.1, `RK[n]` being the table's `RKn`.
pub(super) static RK: [Wide; 5] = [
    windows(&[(4, 7), (5, 15), (6, 23), (7, 32), (12, 256)]),
    windows(&[
        (5, 3),
        (6, 43),
        (7, 59),
        (8, 75),
        (9, 79),
        (11, 126),
        (12, 256),
    ]),
    windows(&[(5, 1), (6, 6), (7, 52), (8, 116), (9, 232), (10, 256)]),
    windows(&[(6, 1), (7, 15), (8, 217), (9, 250), (10, 256)]),
    windows(&[(8, 254), (9, 256)]),
];

/// The rank code a literal is read with, by the literal average over 256
/// (4.5). Every boundary of that table is a multiple of 256: 3584, 13824,
/// 24064 and 30208 are 14, 54, 94 and 118 times 256.
static LITERAL_CODE: [&Wide; 256] = {
    let mut pick: [&Wide; 256] = [&RK[0]; 256];
    let mut high = 14;
    while high < 256 {
        pick[high] = match high {
            118.. => &RK[4],
            94.. => &RK[3],
            54.. => &RK[2],
            _ => &RK[1],
        };
        high += 1;
    }
    pick
};

/// The literal code an average selects (4.5). The average never passes
/// 65,280: it is a sum less a 256th of itself, and the sum gains at most
/// 255.
#[inline(always)]
pub(super) fn literal_code(mean: u32) -> &'static Wide {
    LITERAL_CODE[usize::from((mean >> 8) as u8)]
}

/// A column of table 4.3 from its codewords, written as the table writes
/// them; `words[index]` is empty where the index does not exist.
const fn column(words: [&str; 15]) -> Narrow {
    let mut lookup = [0u8; 256];
    let mut index = 0;
    while index < 15 {
        let word = words[index].as_bytes();
        if !word.is_empty() {
            let mut first = 0usize;
            let mut i = 0;
            while i < word.len() {
                first = first << 1 | (word[i] - b'0') as usize;
                i += 1;
            }
            first <<= 8 - word.len();
            let mut slot = 0;
            while slot < 1usize << (8 - word.len()) {
                lookup[first + slot] = (index as u8) << 4 | word.len() as u8;
                slot += 1;
            }
        }
        index += 1;
    }
    lookup
}

/// The four columns of table 4.3, by `[second table][alternate variant]`.
pub(super) static SHORT: [[Narrow; 2]; 2] = [
    [
        column([
            "0", "101", "1101", "1110", "11110", "111110", "1111110", "11111110", "11111111",
            "1100", "1000", "10010", "100110", "100111", "",
        ]),
        column([
            "0", "1010", "1101", "1110", "11110", "111110", "1111110", "11111110", "11111111",
            "1100", "1000", "10010", "100110", "100111", "1011",
        ]),
    ],
    [
        column([
            "00", "010", "011", "101", "1101", "1110", "11110", "111110", "111111", "1100", "1000",
            "10010", "100110", "100111", "",
        ]),
        column([
            "00", "010", "011", "1010", "1101", "1110", "11110", "111110", "111111", "1100",
            "1000", "10010", "100110", "100111", "1011",
        ]),
    ],
];
