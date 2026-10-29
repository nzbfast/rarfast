//! Where one set of prefix code tables ends and the next begins (spec H3
//! section 6.2: "block boundaries are chosen for compression, not for
//! convenience").
//!
//! A parse block's token stream is cut into entropy blocks, each written
//! with its own tables, so a stretch of text and the already compressed
//! bytes after it are not priced with one shared code. The cut is a
//! shortest path over a coarse grid of candidate boundaries, each edge
//! costed as the entropy of the symbols it spans plus what its tables cost
//! to send, and then a coordinate descent that moves each boundary on a
//! finer grid. The grids, the span ceiling and the descent's reach are the
//! carried ones.
//!
//! Everything here is integer arithmetic over the token stream alone, so
//! the cut is deterministic and independent of the thread count, which is
//! what section 6.2 requires of it.

use super::lz::{Arm, Format, Token};
use crate::carry::c_lz::codec::rar50::{log2_sixteenths, ENTROPY_BLOCK_MIN_TOKENS, PRICE_SHIFT};
use crate::carry::h_ours::codec::rar50::boundaries::{
    Point, COARSE_GRID_BYTES, FINE_GRID_BYTES, MAX_ENTROPY_SPAN_BYTES, REFINE_PASSES,
    REFINE_WINDOW_BYTES,
};
use std::ops::Range;

/// What a table set is charged before its symbols are counted: the block
/// header and the code length alphabet's own lengths, in bits.
const TABLE_FLAT_BITS: u64 = 5 * 8 + 20 * 4;
/// What each used symbol adds to a table set, in bits. A code length costs
/// about this much through the code length alphabet.
const TABLE_SYMBOL_BITS: u64 = 5;

/// The symbol counts at every fine grid point, as running totals, so any
/// stretch's counts are one subtraction.
struct Running {
    points: Vec<Point>,
    symbols: usize,
    /// `points.len()` rows of `symbols` counts.
    counts: Vec<u32>,
    /// Plain bits written before each point.
    plain: Vec<u64>,
}

impl Running {
    fn new<F: Format + ?Sized>(format: &F, tokens: &[Token]) -> Running {
        let symbols = format.symbols();
        let mut running = Running {
            points: vec![Point { token: 0, byte: 0 }],
            symbols,
            counts: vec![0; symbols],
            plain: vec![0],
        };
        let mut row = vec![0u32; symbols];
        let mut plain = 0u64;
        let mut byte = 0usize;
        let mut next = FINE_GRID_BYTES;
        for (index, &token) in tokens.iter().enumerate() {
            if token.arm == Arm::Literal {
                // Its byte, and no plain bit ([`Format::visit`]'s rule).
                row[token.distance as u8 as usize] += 1;
            } else {
                plain += u64::from(format.visit(token, &mut |symbol| row[symbol] += 1));
            }
            byte += token.length as usize;
            if byte >= next && index + 1 < tokens.len() {
                // A match is never split: the point sits after the token
                // that crossed the grid line.
                running.push(index + 1, byte, &row, plain);
                next = (byte / FINE_GRID_BYTES + 1) * FINE_GRID_BYTES;
            }
        }
        running.push(tokens.len(), byte, &row, plain);
        running
    }

    fn push(&mut self, token: usize, byte: usize, row: &[u32], plain: u64) {
        self.points.push(Point { token, byte });
        self.counts.extend_from_slice(row);
        self.plain.push(plain);
    }

    /// What the stretch from point `from` to point `to` costs as one
    /// entropy block, in bits.
    fn cost<F: Format + ?Sized>(&self, format: &F, from: usize, to: usize) -> u64 {
        let low = &self.counts[from * self.symbols..(from + 1) * self.symbols];
        let high = &self.counts[to * self.symbols..(to + 1) * self.symbols];
        let mut sixteenths = 0u64;
        let mut used = 0u64;
        for range in format.alphabets() {
            let mut total = 0u64;
            let mut weighted = 0u64;
            for symbol in range.clone() {
                let count = u64::from(high[symbol] - low[symbol]);
                if count != 0 {
                    used += 1;
                    total += count;
                    weighted += count * u64::from(log2_sixteenths(count));
                }
            }
            if total != 0 {
                sixteenths += total * u64::from(log2_sixteenths(total)) - weighted;
            }
        }
        (sixteenths >> PRICE_SHIFT)
            + (self.plain[to] - self.plain[from])
            + TABLE_FLAT_BITS
            + TABLE_SYMBOL_BITS * used
    }
}

/// [`cut_counting`] without the counts, for the tests and the bench
/// builds' stage counts.
#[cfg(any(test, feature = "bench-internals"))]
pub(crate) fn cut<F: Format + ?Sized>(format: &F, tokens: &[Token], cuts: &mut Vec<Range<usize>>) {
    let mut counts = Vec::new();
    cut_counting(format, tokens, cuts, &mut counts);
}

/// Cut `tokens` into entropy blocks, `cuts` becoming their token ranges
/// in order, and put the symbol counts of each block it chose into
/// `counts`, a table of [`Format::symbols`] a block in the order of
/// `cuts`, the tokens' alone (no filter record's symbol): what
/// `Emit::emit_counted` takes, so the emitter need not count the tokens a
/// second time. The cut has every one of them already, as the difference
/// of two rows of its running totals. Left EMPTY where a stretch is too
/// short to be cut, which the emitter answers by counting for itself.
// No inline hint: whether it is inlined into its callers is left to the
// compiler's choice. A hint here moved the sizes of functions across a
// profile-guided x86-64 build, put the decode output path's closure out of
// line and cost trained decode rows 2.5 to 3.1 percent of instructions,
// for about one point on a one-thread create of a small tree.
pub(crate) fn cut_counting<F: Format + ?Sized>(
    format: &F,
    tokens: &[Token],
    cuts: &mut Vec<Range<usize>>,
    counts: &mut Vec<u32>,
) {
    cuts.clear();
    counts.clear();
    if tokens.len() <= ENTROPY_BLOCK_MIN_TOKENS {
        cuts.push(0..tokens.len());
        return;
    }
    let running = Running::new(format, tokens);
    let points = &running.points;
    let last = points.len() - 1;

    // The coarse grid: the first fine point at or past each coarse line,
    // and both ends.
    let mut coarse = vec![0usize];
    let mut line = COARSE_GRID_BYTES;
    for (index, point) in points.iter().enumerate().take(last).skip(1) {
        if point.byte >= line {
            coarse.push(index);
            line = (point.byte / COARSE_GRID_BYTES + 1) * COARSE_GRID_BYTES;
        }
    }
    coarse.push(last);

    // The shortest path over the coarse grid. An edge may not span more
    // than the ceiling, unless it holds so few tokens that tables are
    // beside the point: that keeps every node reachable through a long
    // run of long matches.
    let ceiling = format.block_bits_most().unwrap_or(u64::MAX);
    let mut best = vec![u64::MAX; coarse.len()];
    let mut back = vec![0usize; coarse.len()];
    best[0] = 0;
    for to in 1..coarse.len() {
        for from in (0..to).rev() {
            let bytes = points[coarse[to]].byte - points[coarse[from]].byte;
            let held = points[coarse[to]].token - points[coarse[from]].token;
            if bytes > MAX_ENTROPY_SPAN_BYTES && held > ENTROPY_BLOCK_MIN_TOKENS && from + 1 != to {
                break;
            }
            if best[from] == u64::MAX {
                continue;
            }
            let cost = running.cost(format, coarse[from], coarse[to]);
            if cost > ceiling && from + 1 != to {
                continue;
            }
            let through = best[from] + cost;
            if through < best[to] {
                best[to] = through;
                back[to] = from;
            }
        }
    }
    let mut chosen = vec![last];
    let mut node = coarse.len() - 1;
    while node != 0 {
        node = back[node];
        chosen.push(coarse[node]);
    }
    chosen.reverse();

    // Coordinate descent on the fine grid: each interior boundary in turn
    // moves to wherever between its neighbours, within the window, the
    // two blocks it separates cost least.
    let reach = REFINE_WINDOW_BYTES / FINE_GRID_BYTES;
    for _ in 0..REFINE_PASSES {
        let mut moved = false;
        for index in 1..chosen.len() - 1 {
            let (before, here, after) = (chosen[index - 1], chosen[index], chosen[index + 1]);
            let low = here.saturating_sub(reach).max(before + 1);
            let high = (here + reach).min(after - 1);
            let mut least = running.cost(format, before, here) + running.cost(format, here, after);
            for candidate in low..=high {
                if candidate == here {
                    continue;
                }
                let (left, right) = (
                    running.cost(format, before, candidate),
                    running.cost(format, candidate, after),
                );
                // A move may not take either block over the ceiling.
                if (left > ceiling && candidate - before > 1)
                    || (right > ceiling && after - candidate > 1)
                {
                    continue;
                }
                let cost = left + right;
                if cost < least {
                    least = cost;
                    chosen[index] = candidate;
                    moved = true;
                }
            }
        }
        if !moved {
            break;
        }
    }

    cuts.extend(
        chosen
            .windows(2)
            .map(|pair| points[pair[0]].token..points[pair[1]].token),
    );
    let symbols = running.symbols;
    for pair in chosen.windows(2) {
        let low = &running.counts[pair[0] * symbols..(pair[0] + 1) * symbols];
        let high = &running.counts[pair[1] * symbols..(pair[1] + 1) * symbols];
        counts.extend(high.iter().zip(low).map(|(&high, &low)| high - low));
    }
}

/// How many input bytes one entropy block of the BLIND cut spans
/// ([`cut_blind`]): reference `rar` 7.23's `-m1` writes about 70 KiB a
/// block. Counted 30 Sep 2026 on the fast level 1: 128 KiB is level with
/// 64, 32 KiB writes 0.3 percent more.
pub(crate) const BLIND_CUT_BYTES: usize = 64 << 10;

/// Cut `tokens` into entropy blocks of [`BLIND_CUT_BYTES`] input bytes
/// each, pricing nothing: the fast level 1's cut (`lz::fast_parse`).
///
/// A block ends with the token that takes it to that many bytes, so no
/// match is split, and only while more than [`ENTROPY_BLOCK_MIN_TOKENS`]
/// tokens are left for the block after it: a parse block of a few long
/// matches is one entropy block, as [`cut`] makes it. The priced cut's
/// shortest path and descent were 13 percent of the fast level 1's
/// instructions for 0.1 to 0.3 percent of its bytes. The format's ceiling
/// on a block's packed size ([`Format::block_bits_most`]) is not read
/// here: the emitter splits a block that reaches it, as it does a block
/// the priced cut misjudged.
#[cfg(test)]
pub(crate) fn cut_blind(tokens: &[Token], cuts: &mut Vec<Range<usize>>) {
    cuts.clear();
    let mut first = 0usize;
    let mut bytes = 0usize;
    for (index, token) in tokens.iter().enumerate() {
        bytes += token.length as usize;
        if bytes >= BLIND_CUT_BYTES && tokens.len() - (index + 1) > ENTROPY_BLOCK_MIN_TOKENS {
            cuts.push(first..index + 1);
            first = index + 1;
            bytes = 0;
        }
    }
    cuts.push(first..tokens.len());
}
