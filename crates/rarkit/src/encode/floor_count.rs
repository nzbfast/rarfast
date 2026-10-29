//! The floor's lazy parse, COUNTED: what spec G 3.8.3's store rule needs
//! of a sample, which is only how long it packs.
//!
//! [`FloorCount`] is the lazy parse of `lz` at the floor effort over the
//! chains of `chain`, written for that one fixed form and run as a single
//! loop with the chains' pass, giving the symbol counts of the tokens the
//! parse would write and no token. `rar5::SampleLength` turns the counts
//! into the sample's packed length. It is a module of its own because it
//! is a second copy of scoring that lives in `lz` (see [`floor_score`]):
//! the two are held together by `rar5`'s test
//! `the_counted_sample_is_the_packed_sample`.

use super::chain::{bucket, HEAD_BITS};
use super::lz::{
    mean_literal_price, Arm, Format, PriceModel, Repeats, Scored, Token, LAZY_EXACT_LITERALS,
    REPEATS, UNPRICED,
};
use crate::carry::c_lz::codec::rar50::OPTIMAL_SUFFICIENT_LENGTH;
use crate::carry::h_ours::codec::rar50::tree::common_prefix;

/// The longest span [`FloorCount`] takes: a position is held in sixteen
/// bits.
pub(crate) const FLOOR_COUNT_MOST: usize = 1 << 16;

/// The lazy parse at the FLOOR effort over the chains (`Plan::floor`: one
/// link, a 32 byte match ends a search, no backward extension), of one
/// span of at most [`FLOOR_COUNT_MOST`] bytes from no history, giving the
/// SYMBOL COUNTS and the plain bits of the tokens `lz::lazy_parse` would
/// write for it and no token: what spec G 3.8.3's store rule needs of a
/// sample, which is only how long it packs.
///
/// **Why it is the same parse.** The lazy parse asks the chains one thing
/// at this effort: at the position it stands on, the NEWEST earlier
/// position whose first four bytes fall in the same hash bucket, which is
/// a match exactly when those four bytes are the same. It asks at
/// positions in rising order and never twice. So the pass and the parse
/// are run here as one: every position is put in its bucket's head in
/// order, a position the parse stands on reading the head before it
/// writes it, and the positions a match covers written without a read.
/// Everything else is `lz::lazy_parse_as`'s own loop with the extension off,
/// over the same prices, the same model and the same scoring
/// ([`floor_score`] is `lz::best_scored` with the chain's one candidate
/// handed in).
///
/// **Why a run of literals is cheap.** `lz::best_scored` answers nothing at
/// a position where the head offers no match and no held distance repeats
/// the position's first two bytes: every arm it scores needs one or the
/// other. Such a position is a literal, and the loop that finds the next
/// position that is not one does those two tests and nothing else.
///
/// **Why the heads are never emptied.** A head holds a position of the
/// span and nothing else, and is taken as a candidate only where it lies
/// before the position asked at AND begins with the same four bytes. A
/// head no position of this span has written holds anything at all: but
/// if what it holds passed both tests it would be an earlier position of
/// this span in this bucket, which would have written the head. So a
/// stale head is never taken, whatever it holds, and the table is kept
/// from one span to the next with no pass over it.
pub(crate) struct FloorCount {
    /// The newest position under each hash, of whichever span wrote it
    /// last: this span, or any span before it. NEVER EMPTIED, and it need
    /// not be: a head is taken as a candidate only where it lies before
    /// the position asked at and begins with that position's four bytes,
    /// and a position of this span that does both is in this bucket and
    /// came earlier, so it wrote this head itself. What a head holds from
    /// an earlier span therefore either fails a test or is, by value, the
    /// position this span wrote. Two mebibytes, the chains' own 2^20
    /// buckets (`chain::HEAD_BITS`: a narrower table would let a position
    /// hide another the chains keep apart, and move a token).
    heads: Box<[u16; 1 << HEAD_BITS]>,
    model: PriceModel,
    /// The span's symbol counts, the model's regions summed.
    pub(crate) frequency: Vec<u32>,
}

/// The four bytes at `at`, least significant first.
#[inline(always)]
fn word_at(span: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(span[at..at + 4].try_into().unwrap())
}

/// `lz::best_scored` at `at` where the chains' one link gave `candidate`, an
/// earlier position that begins with the same four bytes, or none.
///
/// **A second copy of `lz::best_scored`'s scoring, and it must stay one**:
/// the held distances first, in slot order, then the candidate, each
/// priced and weighed as there. `Links::search` at one link reports a
/// candidate only where its four bytes agree, measures it from the fourth
/// byte on, and never past the dictionary, which a span of
/// [`FLOOR_COUNT_MOST`] cannot reach. `rar5`'s test
/// `the_counted_sample_is_the_packed_sample` fails when the copies part.
#[inline(never)]
fn floor_score<F: Format>(
    format: &F,
    prices: &[u16],
    literal_price: u32,
    span: &[u8],
    repeats: &Repeats,
    at: usize,
    candidate: Option<usize>,
) -> Option<Scored> {
    let room = span.len() - at;
    let mut best: Option<Scored> = None;
    let mut consider = |arm: Arm, distance: u32, length: usize, price: u32| {
        if price >= UNPRICED {
            return;
        }
        let exact = length.min(LAZY_EXACT_LITERALS);
        let literals: i64 = span[at..at + exact]
            .iter()
            .map(|&byte| i64::from(prices[byte as usize]))
            .sum::<i64>()
            + i64::from(literal_price) * (length - exact) as i64;
        let gain = literals - i64::from(price);
        if gain > 0 && best.is_none_or(|b| gain > b.gain) {
            best = Some(Scored {
                arm,
                distance,
                length,
                gain,
            });
        }
    };
    let limit = room.min(format.longest_repeat());
    if limit >= 2 {
        for k in 0..REPEATS {
            let held = repeats.distance[k];
            if held == 0 || repeats.distance[..k].contains(&held) {
                continue;
            }
            let source = at - held as usize;
            if span[source] != span[at] || span[source + 1] != span[at + 1] {
                continue;
            }
            let length = common_prefix(span, source, at, 2, limit);
            let mut price = format.repeat_price(prices, k, length as u32);
            if k == 0 && length == repeats.last_length as usize {
                price = price.min(format.last_price(prices));
            }
            consider(Arm::Repeat(k as u8), held, length, price);
        }
    }
    if let Some(candidate) = candidate {
        let limit = room.min(format.longest());
        let length = common_prefix(span, candidate, at, 4, limit) as u32;
        let distance = (at - candidate) as u32;
        let bonus = format.bonus(distance);
        if repeats.slot_of(distance).is_none() && length >= 2 + bonus {
            let price = format
                .fresh_distance_price(prices, distance)
                .saturating_add(format.fresh_length_price(prices, length - bonus));
            consider(Arm::Fresh, distance, length as usize, price);
        }
    }
    best
}

impl FloorCount {
    pub(crate) fn new(format: &dyn Format) -> FloorCount {
        FloorCount {
            heads: vec![0u16; 1 << HEAD_BITS]
                .into_boxed_slice()
                .try_into()
                .expect("a table of that length"),
            model: PriceModel::new(format),
            frequency: vec![0; format.symbols()],
        }
    }

    /// Parse `span` and leave its symbol counts in `frequency`; the plain
    /// bits its tokens write beside their symbols.
    pub(crate) fn count<F: Format>(&mut self, format: &F, span: &[u8]) -> u64 {
        assert!(span.len() <= FLOOR_COUNT_MOST);
        let FloorCount {
            heads,
            model,
            frequency,
        } = self;
        frequency.fill(0);
        model.open(format);
        let end = span.len();
        // A position with fewer than four bytes after it is in no head,
        // and the chains are not asked at it.
        let keyed = end.saturating_sub(3);
        let mut plain = 0u64;
        let mut repeats = Repeats::default();
        // The held distances, the empty slots left out.
        let mut live = [0usize; REPEATS];
        let mut lives = 0;
        let mut literal_price = mean_literal_price(&model.prices);
        let mut at = 0;
        // The first position not yet in its head.
        let mut next = 0;
        let mut held: Option<Scored> = None;
        while at < end {
            let found = match held.take() {
                Some(found) => Some(found),
                None => {
                    for skipped in next..at.min(keyed) {
                        heads[bucket(word_at(span, skipped))] = skipped as u16;
                    }
                    // The run of literals from here: positions the head
                    // gives no match at and no held distance repeats.
                    let run = at;
                    let mut candidate = None;
                    let literals = &mut model.counts[..256];
                    while at < keyed {
                        let word = word_at(span, at);
                        let head = &mut heads[bucket(word)];
                        let earlier = *head as usize;
                        *head = at as u16;
                        // A stale head lies before `at` about half the
                        // time, which no branch predicts: its four bytes
                        // are read either way (the position's own where it
                        // does not), and the one branch is on the match.
                        let before = earlier < at;
                        let read = if before { earlier } else { at };
                        if before & (word_at(span, read) == word) {
                            candidate = Some(earlier);
                            break;
                        }
                        let pair = word as u16;
                        let mut repeated = false;
                        for &distance in &live[..lives] {
                            let source = at - distance;
                            repeated |=
                                u16::from_le_bytes([span[source], span[source + 1]]) == pair;
                        }
                        if repeated {
                            break;
                        }
                        literals[(word & 0xff) as usize] += 1;
                        at += 1;
                    }
                    model.bytes += at - run;
                    if at == end {
                        break;
                    }
                    next = at + 1;
                    floor_score(
                        format,
                        &model.prices,
                        literal_price,
                        span,
                        &repeats,
                        at,
                        candidate,
                    )
                }
            };
            let Some(found) = found else {
                model.counts[span[at] as usize] += 1;
                model.bytes += 1;
                at += 1;
                continue;
            };
            if found.length < OPTIMAL_SUFFICIENT_LENGTH && at + 1 < end {
                debug_assert_eq!(next, at + 1);
                next = at + 2;
                let mut candidate = None;
                if at + 1 < keyed {
                    let word = word_at(span, at + 1);
                    let head = &mut heads[bucket(word)];
                    let earlier = *head as usize;
                    *head = (at + 1) as u16;
                    if earlier < at + 1 && word_at(span, earlier) == word {
                        candidate = Some(earlier);
                    }
                }
                let ahead = floor_score(
                    format,
                    &model.prices,
                    literal_price,
                    span,
                    &repeats,
                    at + 1,
                    candidate,
                );
                if let Some(ahead) = ahead {
                    if ahead.gain > found.gain + i64::from(literal_price) / 2 {
                        model.counts[span[at] as usize] += 1;
                        model.bytes += 1;
                        at += 1;
                        held = Some(ahead);
                        continue;
                    }
                }
            }
            let arm = if found.arm == Arm::Repeat(0)
                && found.length == repeats.last_length as usize
                && format.last_price(&model.prices)
                    <= format.repeat_price(&model.prices, 0, found.length as u32)
            {
                Arm::Last
            } else {
                found.arm
            };
            let token = Token {
                arm,
                length: found.length as u16,
                distance: found.distance,
            };
            // As `PriceModel::observe` counts it, with its plain bits kept.
            let counts = &mut model.counts;
            plain += u64::from(format.visit(token, &mut |symbol| counts[symbol] += 1));
            model.bytes += found.length;
            repeats = repeats.after(arm, found.distance, found.length as u16);
            lives = 0;
            for &distance in &repeats.distance {
                if distance != 0 {
                    live[lives] = distance as usize;
                    lives += 1;
                }
            }
            at += found.length;
            if model.bytes >= model.threshold {
                // The counts are about to become the prices and reset.
                for (sum, &count) in frequency.iter_mut().zip(&model.counts) {
                    *sum += count;
                }
            }
            if model.settle(format) {
                literal_price = mean_literal_price(&model.prices);
            }
        }
        for (sum, &count) in frequency.iter_mut().zip(&model.counts) {
            *sum += count;
        }
        plain
    }
}
