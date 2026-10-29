//! Tests for the shared encoder pieces.

use super::bits::BitWriter;
use super::huffman::{
    canonical, code_lengths, code_lengths_dense, code_lengths_reference, is_complete, MAX_CODE_LEN,
};
use super::lz::{Arm, Repeats, Token};
use super::{cut, rar29, rar5};
// The sibling modules a test names by path: a child module's `super::drive`
// is this module's `drive`, so it is named here once.
use super::{bits, chain, class, drive, filter, lz, sample};
use crate::lz20::bits::{BitSource, SliceBits};
use crate::lz20::table::Table;
#[cfg(feature = "parallel")]
use std::sync::atomic::Ordering;

// The tests, one module a subject.
// The directory is `unit_tests` and not `tests` because a vendored mirror of
// this crate leaves out every directory of that name (`make mirror-check`).
#[path = "unit_tests/carried_tables.rs"]
mod carried_tables;
#[path = "unit_tests/chains.rs"]
mod chains;
#[path = "unit_tests/codes.rs"]
mod codes;
#[path = "unit_tests/levels.rs"]
mod levels;
#[path = "unit_tests/packed_ceiling.rs"]
mod packed_ceiling;
#[path = "unit_tests/paired_search.rs"]
mod paired_search;
#[path = "unit_tests/walk.rs"]
mod walk;

// ---- the low distance run form ---------------------------------------------------

fn far(distance: u32) -> Token {
    Token {
        arm: Arm::Fresh,
        length: 8,
        distance,
    }
}

// ---- the level ladder, and the sample under it ------------------------

/// Bytes with nothing in them to find: the shape the sample exists for.
fn nothing_to_find(len: usize, seed: u64) -> Vec<u8> {
    rarkit_testdata::scramble(seed ^ 0x6e6f_7468, len)
}

/// Bytes no level compresses.
fn incompressible(len: usize, seed: u64) -> Vec<u8> {
    rarkit_testdata::scramble(seed, len)
}

/// Decode a version 0 RAR 5 packed stream with rarkit's own decoder.
fn rar5_decode(packed: &[u8], unpacked: usize, window: u64) -> Vec<u8> {
    let policy = crate::memory::MemoryPolicy {
        working_limit: u64::MAX,
        max_window: 1 << 33,
        ..crate::memory::MemoryPolicy::default()
    };
    let mut lz = crate::rar5_lz::Rar5Lz::new(window, &policy).expect("a window");
    let mut sink: Vec<u8> = Vec::new();
    let mut source = crate::rar5_lz::SliceSource::new(packed);
    lz.member(&mut source, unpacked as u64, 0, &mut sink)
        .expect("decodes");
    sink
}

/// `len` bytes of words from a vocabulary of eight: a level 5 head reads
/// it far under the cut-off (1.0 far link a byte) and a greedy parse of
/// it takes long matches by the thousand (6,429 in a megabyte), measured
/// 11 Oct 2026.
fn few_words(len: usize, seed: u64) -> Vec<u8> {
    rarkit_testdata::chatter_of(seed, 8, len)
}

/// Text that a level 5 head reads far over the cut-off: a vocabulary of
/// 32,768 words, most of them met again only megabytes on.
fn far_linked(len: usize) -> Vec<u8> {
    rarkit_testdata::chatter_of(0x6661_726c, 1 << 15, len)
}

/// Text whose far copies begin with the commonest words: sentences drawn
/// from a pool, each one first seen far back, between runs of `few_words`.
/// A sentence's first four bytes (`the `, `parse`) sit on chains full of
/// near copies, so the far copy is found only a few bytes in: the lost
/// head the backward extension exists for.
fn far_sentences(len: usize, seed: u64) -> Vec<u8> {
    let pool: Vec<Vec<u8>> = (0..400u64)
        .map(|i| {
            let mut sentence = b"the ".to_vec();
            sentence.extend_from_slice(&few_words(40 + (i as usize * 7) % 60, seed ^ (i * 977)));
            sentence.push(b'.');
            sentence
        })
        .collect();
    let mut source = rarkit_testdata::Seeded::new(seed);
    let mut out = Vec::with_capacity(len + 256);
    while out.len() < len {
        out.extend_from_slice(&pool[source.index(pool.len())]);
        out.extend_from_slice(&few_words(source.between(8, 31), source.next_u64()));
    }
    out.truncate(len);
    out
}

/// [`far_linked`] text with one of 256 phrases of 24 letters after every
/// `every` words: it still reads far over level 5's cut-off, and a greedy
/// parse of it takes a long match at nearly every phrase.
fn far_linked_with_phrases(len: usize, every: usize) -> Vec<u8> {
    let words = far_linked(len);
    let phrases: Vec<Vec<u8>> = (0..256u32)
        .map(|phrase| {
            let mut letters = rarkit_testdata::Seeded::new(u64::from(phrase));
            (0..24).map(|_| b'A' + letters.below(26) as u8).collect()
        })
        .collect();
    let mut text = Vec::with_capacity(len + 64);
    let mut pick = rarkit_testdata::Seeded::new(0x7068_7261);
    for (index, word) in words.split(|&byte| byte == b' ').enumerate() {
        if text.len() >= len {
            break;
        }
        text.extend_from_slice(word);
        text.push(b' ');
        if index % every == every - 1 {
            text.extend_from_slice(&phrases[pick.index(phrases.len())]);
            text.push(b' ');
        }
    }
    text.resize(len, b' ');
    text
}
