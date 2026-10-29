//! Seeded input makers shared by rarkit's tests, examples and fuzz
//! targets.
//!
//! Two needs, one maker each:
//!
//! - [`scramble`]: bytes from a seed that do not compress.
//! - [`chatter`]: text from a seed that does compress.
//!
//! and one made of both, [`medley`], for a member whose stretches differ.
//!
//! Both are pure functions of their arguments: the same seed and length
//! give the same bytes on every system, every width and every run. That
//! is the whole contract a test may pin. [`Seeded`] is the generator
//! under both, public for a test that wants to draw its own numbers.
//!
//! This crate is test equipment. It is a dev-dependency of the engine and
//! of the command line crate and is never linked into either one's
//! shipped build.

#![forbid(unsafe_code)]

/// The step between successive states: the odd 64-bit integer nearest
/// to 2^64 divided by the golden ratio.
const STRIDE: u64 = 0x9E37_79B9_7F4A_7C15;

/// A seeded source of numbers.
///
/// The generator is SplitMix64 (Steele, Lea and Flood, "Fast splittable
/// pseudorandom number generators", OOPSLA 2014; the constants are the
/// ones of Vigna's public domain `splitmix64.c`): a counter that walks
/// by a fixed odd stride, with each output a mixed copy of the counter.
/// Every seed is a good seed, zero included, and the period is 2^64.
/// It is not a cipher and must never be used as one.
#[derive(Clone, Debug)]
pub struct Seeded {
    counter: u64,
}

impl Seeded {
    /// A source that depends on nothing but `seed`.
    pub fn new(seed: u64) -> Self {
        Self { counter: seed }
    }

    /// The next 64 bits.
    pub fn next_u64(&mut self) -> u64 {
        self.counter = self.counter.wrapping_add(STRIDE);
        let mut z = self.counter;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// The next 32 bits: the high half of [`Seeded::next_u64`].
    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// The next byte: the top byte of [`Seeded::next_u64`].
    pub fn next_byte(&mut self) -> u8 {
        (self.next_u64() >> 56) as u8
    }

    /// A number in `0..bound`, or 0 when `bound` is 0.
    ///
    /// The high half of a 64 by 64 bit product. The bias is at most
    /// `bound` parts in 2^64, which no test here can see.
    pub fn below(&mut self, bound: u64) -> u64 {
        ((u128::from(self.next_u64()) * u128::from(bound)) >> 64) as u64
    }

    /// [`Seeded::below`] for an index or a length.
    pub fn index(&mut self, bound: usize) -> usize {
        self.below(bound as u64) as usize
    }

    /// True `per_mille` times in a thousand.
    pub fn chance(&mut self, per_mille: u64) -> bool {
        self.below(1_000) < per_mille
    }

    /// A number in `low..=high`. `low` must not exceed `high`.
    pub fn between(&mut self, low: usize, high: usize) -> usize {
        assert!(low <= high, "between({low}, {high})");
        low + self.index(high - low + 1)
    }

    /// Overwrites `out` with bytes that do not compress: eight per draw,
    /// low byte first, and the low bytes of one more draw for a tail.
    pub fn fill(&mut self, out: &mut [u8]) {
        let (eights, tail) = out.as_chunks_mut::<8>();
        for eight in eights {
            *eight = self.next_u64().to_le_bytes();
        }
        if !tail.is_empty() {
            let last = self.next_u64().to_le_bytes();
            tail.copy_from_slice(&last[..tail.len()]);
        }
    }

    /// The next `len` bytes, as [`Seeded::fill`] writes them.
    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        self.fill(&mut out);
        out
    }
}

/// `len` bytes from `seed` that do not compress.
///
/// Every byte value is equally likely and no byte depends on another in
/// any way a compressor can find, so a packed copy is never smaller than
/// the input.
pub fn scramble(seed: u64, len: usize) -> Vec<u8> {
    Seeded::new(seed).bytes(len)
}

/// How many words [`chatter`] gives a seed's vocabulary.
///
/// Few, and for a reason that is the engine's and not the text's: a
/// level 5 writer reads the head of a member and sorts it into one of
/// two classes by how far back its repeats lie. The tests that just
/// want "text" want the common class, the one whose repeats are near,
/// and with 32 words every word comes round again within a few hundred
/// bytes (measured 11 Oct 2026 with the engine's own reading: 2.6 far
/// links a byte against a cut-off of 7.0, where 160 words read 6.0 and
/// 32,768 words 16.0). A test that wants the other class asks
/// [`chatter_of`] for a large vocabulary and says so.
pub const VOCABULARY: usize = 32;

// The three parts of a syllable. A part may be empty or two letters, so
// that words do not all step in twos and threes: text whose every
// syllable is consonant, vowel, and sometimes one more reads to a
// writer's screens as records three bytes wide, which no written
// language does.
const ONSETS: &[&[u8]] = &[
    b"", b"b", b"c", b"d", b"f", b"g", b"h", b"j", b"k", b"l", b"m", b"n", b"p", b"r", b"s", b"t",
    b"v", b"w", b"z", b"br", b"ch", b"dr", b"fl", b"gr", b"kl", b"pl", b"sh", b"st", b"th", b"tr",
];
const VOWELS: &[&[u8]] = &[
    b"a", b"e", b"i", b"o", b"u", b"a", b"e", b"o", b"ai", b"ea", b"io", b"ou",
];
const CODAS: &[&[u8]] = &[
    b"", b"", b"", b"", b"l", b"m", b"n", b"r", b"s", b"t", b"nd", b"rt", b"st",
];

/// `len` bytes of text from `seed` that compress.
///
/// The text is ASCII: lower case words, a capital at the head of each
/// sentence, spaces, commas, full stops and line feeds. The words are
/// not from any list: each seed makes up its own vocabulary of
/// [`VOCABULARY`] words out of syllables, and then writes sentences
/// from it, reaching for a few of the words often and most of them
/// seldom. A compressor finds short repeats near at hand (the common
/// words) and longer ones far back (a rare word coming round again),
/// and the few dozen byte values in use are far from equally likely.
///
/// Every seed writes in the SAME made up language: the seed chooses the
/// wording and never the words. Two members from two seeds therefore
/// share their vocabulary, as two files of one language do, which is
/// what a solid archive or a carried table set has to gain from; no two
/// seeds share a sentence beyond chance.
pub fn chatter(seed: u64, len: usize) -> Vec<u8> {
    chatter_of(seed, VOCABULARY, len)
}

/// [`chatter`] as a `String`.
pub fn chatter_string(seed: u64, len: usize) -> String {
    String::from_utf8(chatter(seed, len)).expect("chatter writes ASCII")
}

/// [`chatter`] from a vocabulary of `words` words (one at least).
///
/// The vocabulary is the one dial this maker has, and it sets how far
/// back a repeat lies: a few hundred words come round every few hundred
/// bytes, where of many thousand most are met again only megabytes on,
/// the way a dictionary or a word list reads. Whatever the vocabulary,
/// the text is drawn the same way and still compresses.
pub fn chatter_of(seed: u64, words: usize, len: usize) -> Vec<u8> {
    assert!(words > 0, "a vocabulary of no words");
    let words = vocabulary(LANGUAGE, words);
    let mut source = Seeded::new(seed);
    let mut out = Vec::with_capacity(len + 64);
    while out.len() < len {
        paragraph(&mut source, &words, &mut out);
    }
    out.truncate(len);
    out
}

fn syllable(source: &mut Seeded, word: &mut Vec<u8>) {
    for part in [ONSETS, VOWELS, CODAS] {
        word.extend_from_slice(part[source.index(part.len())]);
    }
}

/// The seed of the one language every text here is written in.
pub const LANGUAGE: u64 = 0x6c61_6e67;

/// `count` made up words from `seed`: each lower case ASCII, no two
/// alike, of one to three syllables by turns. [`chatter_of`] writes in the words of
/// [`LANGUAGE`]; a test that builds lines or records of its own, or that
/// wants a second language, asks for them here.
pub fn vocabulary(seed: u64, count: usize) -> Vec<Vec<u8>> {
    words_of(&mut Seeded::new(seed), count)
}

fn words_of(source: &mut Seeded, count: usize) -> Vec<Vec<u8>> {
    let mut taken = std::collections::BTreeSet::new();
    let mut words: Vec<Vec<u8>> = Vec::with_capacity(count);
    while words.len() < count {
        // One, two and three syllables by turns, so that the common
        // words are of every length and the spaces between them keep
        // no beat.
        let syllables = 1 + words.len() % 3;
        let mut word = Vec::with_capacity(syllables * 3);
        for _ in 0..syllables {
            syllable(source, &mut word);
        }
        // A word already in the vocabulary grows until it is a new one.
        while !taken.insert(word.clone()) {
            syllable(source, &mut word);
        }
        words.push(word);
    }
    words
}

/// `len` bytes from `seed` of three kinds by turns: text, bytes laid out
/// like machine code, and noise.
///
/// A member of one kind exercises one path of a writer. This one changes
/// kind every few tens of kilobytes, so that successive stretches of it
/// differ: the text is [`chatter`]'s, the code is [`machine_like`]'s,
/// which is where a filter for such code has something to find, and the
/// noise stretches are short, so that the whole still compresses and no
/// rule that judges a member by samples takes it for incompressible.
///
/// The first stretch is text and the kinds then follow in the order
/// text, code, noise.
pub fn medley(seed: u64, len: usize) -> Vec<u8> {
    let words = vocabulary(LANGUAGE, VOCABULARY);
    let mut source = Seeded::new(seed);
    let mut out = Vec::with_capacity(len + 64);
    while out.len() < len {
        let end = out.len() + source.between(24 << 10, 96 << 10);
        while out.len() < end {
            paragraph(&mut source, &words, &mut out);
        }
        let code = source.between(24 << 10, 96 << 10);
        out.extend_from_slice(&machine_like(source.next_u64(), code));
        let noise = source.between(6 << 10, 18 << 10);
        out.extend_from_slice(&source.bytes(noise));
    }
    out.truncate(len);
    out
}

/// The 2,048 commonest words of this engine's own source, commonest
/// first, one a line: every run of letters of 2 to 14 in the `.rs` files
/// of the engine's crate and of its command line crate, in lower case,
/// counted (11 Oct 2026), ties in alphabetical order, with every proper
/// name left out and the next commonest word taken in its place: the
/// names of formats, programs, systems, processors, libraries, ciphers
/// and checksums, and of people. Nothing else was read to make it, and
/// nothing reads those files again: the list is this file, so the text
/// made from it is the same bytes on every box and at every commit.
/// Two words that name content rather than shape were replaced on
/// 26 Oct 2026 by words of the same length the list did not hold
/// (`lump` and `subset`, at their places), so every line of the text
/// breaks where it did; the pinned digest below moved with them.
const SOURCE_WORDS: &str = include_str!("source_words.txt");

/// `len` bytes of text in real words, from `seed`: whole words in a
/// seeded order from the 2,048 commonest words of this engine's own source,
/// the commoner a word in that source the oftener here, set in lines
/// as ordinary text is wrapped.
///
/// Each line is given a width of its own, drawn from 40 to 100 columns,
/// and takes words, a space between them, for as long as the next one
/// fits; then a line feed. So lines end at no fixed count of words and
/// at no fixed column, and a word is never cut.
///
/// For a member that has to look like written text to a codec: real
/// letter and word statistics, repeats of a word or two at every
/// distance, and no long run copied whole (a text that repeats itself,
/// or runs on in stretches of one source, is one enormous self
/// reference, and a timed leg on it measures a copy and not a codec).
/// The bytes depend on `seed` and `len` and on nothing of the machine or
/// the tree it is built in. A shorter ask is a prefix of a longer one
/// from the same seed.
pub fn source_text(seed: u64, len: usize) -> Vec<u8> {
    let words: Vec<&[u8]> = SOURCE_WORDS.lines().map(str::as_bytes).collect();
    let mut source = Seeded::new(seed);
    let mut out = Vec::with_capacity(len + 64);
    while out.len() < len {
        let width = source.between(40, 100);
        let line = out.len();
        loop {
            let word = words[product_of_two(&mut source, words.len())];
            if out.len() > line {
                if out.len() - line + 1 + word.len() > width {
                    break;
                }
                out.push(b' ');
            }
            out.extend_from_slice(word);
        }
        out.push(b'\n');
    }
    out.truncate(len);
    out
}

/// An index in `0..count`, the product of two even draws scaled back
/// into range: the first tenth of a ranked list takes about a third of
/// all picks and no rank is left out.
fn product_of_two(source: &mut Seeded, count: usize) -> usize {
    source.index(count) * source.index(count) / count
}

/// One paragraph: three to nine sentences and a line feed.
fn paragraph(source: &mut Seeded, words: &[Vec<u8>], out: &mut Vec<u8>) {
    for _ in 0..source.between(3, 9) {
        let length = source.between(4, 15);
        for place in 0..length {
            let word = &words[common_first(source, words.len())];
            let start = out.len();
            out.extend_from_slice(word);
            if place == 0 {
                out[start] = out[start].to_ascii_uppercase();
            }
            if place + 1 == length {
                out.extend_from_slice(b". ");
            } else if source.below(9) == 0 {
                out.extend_from_slice(b", ");
            } else {
                out.push(b' ');
            }
        }
    }
    // The sentence's trailing space becomes the end of the line.
    let last = out.len() - 1;
    out[last] = b'\n';
}

/// An index in `0..count` that favours the low ones: every other pick
/// is from the first quarter, the rest from anywhere. The commonest word
/// of 32 is then one word in thirteen, about what the commonest word of
/// a written language is, and no one word sets a rhythm.
fn common_first(source: &mut Seeded, count: usize) -> usize {
    if source.below(2) == 0 {
        source.index(count.div_ceil(4))
    } else {
        source.index(count)
    }
}

/// How many of the first routines of a [`machine_like`] image are the
/// busy ones, called from everywhere.
const BUSY: usize = 40;

/// How many of the latest routines a call may also reach.
const NEARBY: usize = 256;

/// `len` bytes from `seed` laid out like compiled x86 code, for a test
/// that wants a filter for relative addresses to have work to do.
///
/// Such a filter looks for the opcode of a call or a jump with a 32 bit
/// operand (the byte 0xE8 or 0xE9) and treats the four bytes after it as
/// a little endian distance from the end of the instruction to its
/// target. Calls to one place from many places hold many distances and
/// one address, so turning each distance into an address makes those
/// bytes alike. To give it that, the image is a row of routines, each
/// starting on a 16 byte line: it sets up a frame, runs a few dozen short
/// instructions and returns. One instruction in six is a call to the
/// first byte of a routine laid down before it (or of its own), three
/// times in four one of the 40 earliest and otherwise one of the
/// 256 latest. One routine in eight leaves by a jump to another
/// in place of a return.
///
/// The bytes are well formed instructions one by one and no program: a
/// short conditional jump may land inside an instruction, and nothing
/// here is meant to be run. The first byte of the image is address 0. A
/// shorter ask is a prefix of a longer one from the same seed.
pub fn machine_like(seed: u64, len: usize) -> Vec<u8> {
    let mut image = Image {
        source: Seeded::new(seed),
        bytes: Vec::with_capacity(len + 512),
        busy: Vec::with_capacity(BUSY),
        nearby: Vec::with_capacity(NEARBY),
        laid: 0,
    };
    while image.bytes.len() < len {
        image.routine();
    }
    image.bytes.truncate(len);
    image.bytes
}

/// A [`machine_like`] image as it grows.
struct Image {
    source: Seeded,
    bytes: Vec<u8>,
    /// Where the first [`BUSY`] routines begin.
    busy: Vec<usize>,
    /// Where the latest [`NEARBY`] routines begin, the oldest overwritten.
    nearby: Vec<usize>,
    /// Routines begun so far.
    laid: usize,
}

impl Image {
    fn routine(&mut self) {
        let entry = self.bytes.len();
        if self.busy.len() < BUSY {
            self.busy.push(entry);
        }
        if self.nearby.len() < NEARBY {
            self.nearby.push(entry);
        } else {
            self.nearby[self.laid % NEARBY] = entry;
        }
        self.laid += 1;

        // push rbp; mov rbp, rsp; sub rsp, a frame of 16 to 128 bytes.
        let frame = 16 * self.source.between(1, 8) as u8;
        self.bytes
            .extend_from_slice(&[0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, frame]);
        for _ in 0..self.source.between(4, 36) {
            if self.source.below(6) == 0 {
                self.transfer(0xE8);
            } else {
                self.plain();
            }
        }
        // leave, then a return or a jump to another routine's start.
        self.bytes.push(0xC9);
        if self.source.below(8) == 0 {
            self.transfer(0xE9);
        } else {
            self.bytes.push(0xC3);
        }
        // int3 up to the next 16 byte line, as a linker pads.
        while !self.bytes.len().is_multiple_of(16) {
            self.bytes.push(0xCC);
        }
    }

    /// A call (0xE8) or a jump (0xE9) to where some routine begins.
    fn transfer(&mut self, opcode: u8) {
        let target = if self.source.below(4) != 0 {
            self.busy[self.source.index(self.busy.len())]
        } else {
            self.nearby[self.source.index(self.nearby.len())]
        };
        let after = self.bytes.len() + 5;
        let distance = (target as i64 - after as i64) as i32;
        self.bytes.push(opcode);
        self.bytes.extend_from_slice(&distance.to_le_bytes());
    }

    /// One instruction that goes nowhere, built from the encoding rules:
    /// an opcode, then a ModRM byte whose top two bits say register
    /// (binary 11) or frame slot (binary 01 with base rbp and one byte
    /// of offset).
    fn plain(&mut self) {
        let source = &mut self.source;
        let one = source.below(8) as u8;
        let other = source.below(8) as u8;
        let kind = source.below(10);
        // Two instructions in five of the ModRM kinds are 64 bit wide.
        if (2..9).contains(&kind) && source.below(5) < 2 {
            self.bytes.push(0x48);
        }
        // A slot of the frame: rbp minus 4, 8, and so on to 64.
        let slot = (-4 * source.between(1, 16) as i8) as u8;
        match kind {
            0 => self.bytes.push(0x50 | one),
            1 => self.bytes.push(0x58 | one),
            2 | 3 => self
                .bytes
                .extend_from_slice(&[0x8B, 0xC0 | one << 3 | other]),
            4 | 5 => self.bytes.extend_from_slice(&[0x8B, 0x45 | one << 3, slot]),
            6 => self.bytes.extend_from_slice(&[0x89, 0x45 | one << 3, slot]),
            7 => {
                // add, or, adc, sbb, and, sub, xor or cmp with a small
                // constant: the eight operations of opcode 0x83.
                let small = source.below(32) as u8;
                self.bytes
                    .extend_from_slice(&[0x83, 0xC0 | one << 3 | other, small]);
            }
            8 => self
                .bytes
                .extend_from_slice(&[0x85, 0xC0 | one << 3 | other]),
            _ => {
                // A conditional jump a few bytes on.
                let condition = source.below(16) as u8;
                let hop = source.between(2, 30) as u8;
                self.bytes.extend_from_slice(&[0x70 | condition, hop]);
            }
        }
    }
}

// These tests run on one thread and hold well under 1 MiB.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_generator_is_the_published_one() {
        // The first outputs of splitmix64.c from the seed 1234567.
        let mut source = Seeded::new(1_234_567);
        assert_eq!(source.next_u64(), 6_457_827_717_110_365_317);
        assert_eq!(source.next_u64(), 3_203_168_211_198_807_973);
        assert_eq!(source.next_u64(), 9_817_491_932_198_370_423);
    }

    #[test]
    fn a_seed_fixes_every_byte() {
        for len in [0, 1, 7, 8, 9, 4096, 65_537] {
            assert_eq!(scramble(41, len), scramble(41, len));
            assert_eq!(scramble(41, len).len(), len);
            assert_eq!(chatter(41, len), chatter(41, len));
            assert_eq!(chatter(41, len).len(), len);
        }
        assert_ne!(scramble(41, 64), scramble(42, 64));
        assert_ne!(chatter(41, 64), chatter(42, 64));
    }

    #[test]
    fn a_shorter_ask_is_a_prefix_of_a_longer_one() {
        let long = scramble(7, 1000);
        assert_eq!(scramble(7, 996), long[..996]);
        // A tail is the low bytes of the draw a longer ask spends whole.
        assert_eq!(scramble(7, 13), long[..13]);
        let long = chatter(7, 5000);
        assert_eq!(chatter(7, 1234), long[..1234]);
    }

    #[test]
    fn bounded_draws_stay_in_bounds() {
        let mut source = Seeded::new(0);
        assert_eq!(source.below(0), 0);
        assert_eq!(source.below(1), 0);
        let mut seen = [false; 10];
        for _ in 0..1000 {
            seen[source.index(10)] = true;
            let n = source.between(3, 5);
            assert!((3..=5).contains(&n));
        }
        assert!(seen.iter().all(|&hit| hit));
    }

    /// Bits per byte of the order zero model: 8.0 for bytes no coder
    /// can shorten one at a time.
    fn entropy(data: &[u8]) -> f64 {
        let mut counts = [0usize; 256];
        for &byte in data {
            counts[usize::from(byte)] += 1;
        }
        let total = data.len() as f64;
        counts
            .iter()
            .filter(|&&n| n != 0)
            .map(|&n| {
                let p = n as f64 / total;
                -p * p.log2()
            })
            .sum()
    }

    /// The share of positions whose next four bytes stood somewhere
    /// earlier: what a match finder has to work with.
    fn repeated_fours(data: &[u8]) -> f64 {
        let mut seen = std::collections::HashSet::new();
        let mut repeats = 0usize;
        for four in data.windows(4) {
            if !seen.insert(four) {
                repeats += 1;
            }
        }
        repeats as f64 / (data.len() - 3) as f64
    }

    #[test]
    fn scramble_gives_a_compressor_nothing() {
        let data = scramble(2026, 1 << 18);
        assert!(entropy(&data) > 7.99, "{}", entropy(&data));
        assert!(repeated_fours(&data) < 0.001, "{}", repeated_fours(&data));
    }

    #[test]
    fn chatter_gives_a_compressor_plenty() {
        let data = chatter(2026, 1 << 18);
        assert!(data.is_ascii());
        assert!(entropy(&data) < 4.5, "{}", entropy(&data));
        assert!(repeated_fours(&data) > 0.9, "{}", repeated_fours(&data));
        // Short asks are text too, from the first byte.
        assert!(chatter(3, 1)[0].is_ascii_uppercase());
    }

    #[test]
    fn a_larger_vocabulary_puts_the_repeats_farther_back() {
        let few = chatter_of(5, 64, 1 << 18);
        let many = chatter_of(5, 1 << 14, 1 << 18);
        assert_eq!(chatter_of(5, VOCABULARY, 999), chatter(5, 999));
        assert!(many.is_ascii());
        assert!(repeated_fours(&few) > repeated_fours(&many));
        assert!(entropy(&many) < 4.5, "{}", entropy(&many));
        // More words than one syllable can spell: each is still its own.
        let words = vocabulary(5, 1 << 14);
        let unique: std::collections::BTreeSet<_> = words.iter().collect();
        assert_eq!(unique.len(), 1 << 14);
    }

    #[test]
    fn a_medley_holds_all_three_kinds_and_still_compresses() {
        let data = medley(11, 1 << 20);
        assert_eq!(data.len(), 1 << 20);
        assert_eq!(data, medley(11, 1 << 20));
        assert_eq!(medley(11, 70_001), data[..70_001]);
        assert_ne!(medley(12, 4096), data[..4096]);
        // Text first; calls by the thousand somewhere after it; and
        // bytes no text holds.
        assert!(data[..4096].is_ascii());
        assert!(!data.is_ascii());
        let calls = data.iter().filter(|&&byte| byte == 0xE8).count();
        assert!(calls > 5_000, "{calls} call opcodes");
        // Each megabyte holds some noise and is far from all noise.
        let fours = repeated_fours(&data);
        assert!((0.6..0.97).contains(&fours), "{fours}");
    }

    /// FNV-1a over 64 bits: a digest to pin bytes by, with no dependency.
    fn fnv(data: &[u8]) -> u64 {
        data.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &byte| {
            (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
        })
    }

    #[test]
    fn the_source_words_are_the_list_and_their_text_is_fixed_bytes() {
        let words: Vec<&str> = SOURCE_WORDS.lines().collect();
        assert_eq!(words.len(), 2_048);
        let unique: std::collections::BTreeSet<_> = words.iter().collect();
        assert_eq!(unique.len(), words.len());
        // A checkout that turned the list's line ends would give the same
        // words: the reading drops a carriage return.
        let turned = SOURCE_WORDS.replace('\n', "\r\n");
        assert!(turned.lines().eq(words.iter().copied()));
        for word in &words {
            assert!((2..=14).contains(&word.len()), "{word}");
            assert!(word.bytes().all(|b| b.is_ascii_lowercase()), "{word}");
        }
        // The same megabyte on every box and at every commit, pinned.
        let text = source_text(1, 1 << 20);
        assert_eq!(text.len(), 1 << 20);
        assert!(text.is_ascii());
        assert_eq!(source_text(1, 123_457), text[..123_457]);
        assert_ne!(source_text(2, 4_096), text[..4_096]);
        assert_eq!(
            fnv(&text),
            FNV_OF_THE_FIRST_MEGABYTE,
            "{:#018x}",
            fnv(&text)
        );
        // Text to a compressor: few byte values, far from evenly used.
        assert!(entropy(&text) < 4.5, "{}", entropy(&text));
    }

    /// [`source_text`]`(1, 1 << 20)`, by [`fnv`].
    const FNV_OF_THE_FIRST_MEGABYTE: u64 = 0x79e0_dcff_5b32_6ec6;

    #[test]
    fn two_seeds_write_two_texts_in_one_language() {
        let (one, two) = (chatter_string(1, 20_000), chatter_string(2, 20_000));
        assert_ne!(one, two);
        // Every word of either is a word of the one language (but for
        // the last, which the length may have cut); no shared sentences.
        let ours = vocabulary(LANGUAGE, VOCABULARY);
        for text in [&one, &two] {
            let mut words: Vec<&str> = text
                .split(|c: char| !c.is_ascii_alphabetic())
                .filter(|word| !word.is_empty())
                .collect();
            words.pop();
            assert!(words.len() > 2_000);
            for word in words {
                let lower = word.to_ascii_lowercase().into_bytes();
                assert!(ours.contains(&lower), "{word}");
            }
        }
        assert!(!one.contains(&two[..200]));
        // Another language holds other words.
        let other = vocabulary(LANGUAGE + 1, VOCABULARY);
        let long = |word: &&Vec<u8>| word.len() >= 6;
        assert!(
            other
                .iter()
                .filter(long)
                .filter(|w| ours.contains(w))
                .count()
                <= 2
        );
    }

    /// Every call or jump opcode in `image` whose operand, read as a
    /// distance, lands inside it on a 16 byte line: (place, address).
    fn landings(image: &[u8]) -> Vec<(usize, usize)> {
        let mut found = Vec::new();
        for (place, five) in image.windows(5).enumerate() {
            if five[0] != 0xE8 && five[0] != 0xE9 {
                continue;
            }
            let distance = i32::from_le_bytes([five[1], five[2], five[3], five[4]]);
            let address = place as i64 + 5 + i64::from(distance);
            if (0..image.len() as i64).contains(&address) && address % 16 == 0 {
                found.push((place, address as usize));
            }
        }
        found
    }

    #[test]
    fn machine_like_bytes_call_a_few_places_from_many() {
        let len = 1 << 18;
        let image = machine_like(77, len);
        assert_eq!(image.len(), len);
        assert_eq!(image, machine_like(77, len));
        assert_eq!(machine_like(77, 50_003), image[..50_003]);
        assert_ne!(machine_like(78, 4096), image[..4096]);
        assert!(machine_like(77, 0).is_empty());

        // Plenty of transfers, and each lands where a routine begins:
        // on the frame set up there.
        let found = landings(&image);
        assert!(found.len() > len / 60, "{} transfers", found.len());
        let framed = found
            .iter()
            .filter(|&&(_, address)| image[address..].starts_with(&[0x55, 0x48, 0x89, 0xE5]))
            .count();
        assert!(
            framed * 100 > found.len() * 98,
            "{framed} of {}",
            found.len()
        );

        // What an address filter gains: the distances as written are
        // nearly all different, the addresses they stand for are few.
        let distances: std::collections::BTreeSet<_> = found
            .iter()
            .map(|&(place, _)| &image[place + 1..place + 5])
            .collect();
        let addresses: std::collections::BTreeSet<_> =
            found.iter().map(|&(_, address)| address).collect();
        assert!(
            distances.len() * 10 > found.len() * 8,
            "{}",
            distances.len()
        );
        assert!(addresses.len() * 4 < found.len(), "{}", addresses.len());
        let busiest = found
            .iter()
            .filter(|&&(_, address)| address == found[0].1)
            .count();
        assert!(busiest > found.len() / 100, "{busiest} to one address");
    }
}
