//! The hash chain match finder: one link per position, written by a pass
//! that only inserts and read by parses that search only where they look.
//!
//! The carried binary tree finder answers every position of the member,
//! because its walk is separate from the parse and cannot know which
//! positions the parse will skip. Measured 18 Sep 2026 on an Apple M3 Mac, on
//! two real corpora, that walk cost about 115 ns per
//! input byte at any descent depth (about 55 once its first loads were
//! warmed ahead), where reference `rar` spends 57 ns on a byte at `-m5`
//! altogether; and a parse skips most positions, since they sit inside
//! the matches it takes. So the split is made in a different place here.
//! INSERTING is separate from the parse, serial and cheap, one store per
//! position: position `p`'s link is the newest earlier position
//! whose first four bytes hash as `p`'s do. SEARCHING is the parse's own
//! business: from `p`'s link it follows the chain back, nearest first, for
//! as many steps as its level allows, and only at the positions it
//! actually considers.
//!
//! ## Why the links are atomic, and why the output cannot depend on timing
//!
//! The inserting pass runs AHEAD of the parses, up to one wave of blocks,
//! on another thread. A link is a pure function of the member's bytes, so
//! it does not matter when it was written, only that it was written before
//! it is read and not overwritten before it is read again. Written before:
//! a block is linked whole before its parse starts. Not overwritten: the
//! links live in a cyclic buffer in which `p` and `p + cyclic` share a
//! slot, the pass is never more than one wave ahead of any parse, and
//! `cyclic` exceeds the reach plus a wave, so the position whose slot is
//! overwritten is already farther back than any search may follow. A search checks a candidate's distance BEFORE
//! loading that candidate's link, so a stale slot is never read. `Relaxed`
//! is therefore all the ordering this needs; the atomics make the sharing
//! well defined, as the carried tree's do, and synchronise nothing.
//!
//! ## The pass, built across the pool
//!
//! One thread linking every position is the width ceiling of levels 1 to
//! 3 on a large member: a level 1 parse costs eight to fifteen times the
//! pass a byte, so past about that many threads the parses wait on it
//! (measured 30 Sep 2026). [`Build`] links a wave's pieces in two steps that give every
//! position the link the pass gives it, so the output cannot move:
//!
//! 1. LINK, a piece at a time, any number at once: each piece is linked
//!    against a head table of its builder's own, which starts empty, so a
//!    position gets the newest earlier position of its bucket INSIDE its
//!    piece. The positions that have none, a bucket's first in the piece,
//!    are its FIRSTS, and are dealt by bucket share.
//! 2. JOIN, a share at a time, each share's pieces in order: a first's
//!    link is the shared head of its bucket, which after every earlier
//!    piece's join is the newest position of that bucket before the
//!    piece, exactly what the pass would have found there; the head then
//!    takes the bucket's last position in the piece.
//!
//! In a piece of 256 KiB about one position in ten is a first on text
//! and one in eight on machine code (measured 30 Sep 2026), so the join
//! is a small part of the pass, and it is dealt across shares that never
//! touch each other's heads.

use crate::carry::h_ours::codec::rar50::tree::empty_slots;
// THE COMPARE of a chain search and of the parse (`encode::lz` takes it
// from here), by architecture, the same in every build of each:
//
// - on x86-64 a CALL (`tree::common_prefix`, never inlined). The loop that
//   follows links wants its function to itself there: counted 1 Oct 2026
//   at one thread, inlining the compare into the searches cost text64
//   1.3 to 4.3 percent more instructions at levels 2 to 4 in the `pinned`
//   build and 4.3 to 10.7 in the plain one;
// - on every other architecture INLINED (`tree::common_prefix_inlined`):
//   on aarch64 that is 0.5 to 2.9 percent fewer instructions at levels 2
//   to 4 on text and machine code, over the plain and `pinned` builds.
//
// Left to `#[inline]` the choice was the inliner's, build by build. No
// byte moves either way (measured 1 Oct 2026).
#[cfg(target_arch = "x86_64")]
pub(crate) use crate::carry::h_ours::codec::rar50::tree::common_prefix;
#[cfg(not(target_arch = "x86_64"))]
pub(crate) use crate::carry::h_ours::codec::rar50::tree::common_prefix_inlined as common_prefix;
use std::ops::Range;
#[cfg(feature = "parallel")]
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::atomic::{AtomicU32, Ordering};
#[cfg(feature = "parallel")]
use std::sync::{Mutex, RwLock};

const HASH_MULTIPLIER: u32 = 0x9E37_79B1;
/// Hash heads: enough that a chain is mostly one four byte word's own
/// positions, small enough to stay in cache while the pass runs.
pub(crate) const HEAD_BITS: u32 = 20;
/// The smallest cyclic buffer, in positions: what lets a small dictionary
/// still run a wide wave.
const CYCLIC_FLOOR: usize = 16 << 20;

/// Whether the links are taken from zeroed pages ([`zeroed_slots`]) or
/// filled on the calling thread, as every target did before 30 Sep 2026.
/// Zeroed on Linux, where it was measured a win on every row (a Zen 4
/// box of 1 to 32 cores, code32, text64, tree5k, small20k and bin4g at
/// levels 1 to 3: 1.00x to 1.14x of the fill);
/// filled elsewhere, since on macOS the fill costs next to nothing (the
/// M5 Ultra read 0.98x to 1.04x, bin4g -m1 at a load of 8 to 18 the low
/// end) and Windows is not measured. A bench knob, `RARKIT_CHAIN_LINKS`
/// (`zero` or `fill`), read once; nothing ships setting it.
fn links_zeroed() -> bool {
    static ZEROED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ZEROED.get_or_init(|| {
        match crate::knob::writer_var("RARKIT_CHAIN_LINKS")
            .ok()
            .as_deref()
        {
            Some("zero") => true,
            Some("fill") => false,
            _ => cfg!(target_os = "linux"),
        }
    })
}

/// A head table, every head empty: zeroed pages nothing has written, and
/// advised before anything does (`crate::pages`), since the inserting pass
/// stores to it wherever a position's hash lands.
#[inline(always)]
fn head_slots() -> Vec<u32> {
    #[cfg(not(target_os = "linux"))]
    let heads = vec![0; 1 << HEAD_BITS];
    #[cfg(target_os = "linux")]
    let heads = {
        let mut heads = vec![0u32; 1 << HEAD_BITS];
        crate::pages::advise_huge_of(&mut heads[..]);
        heads
    };
    heads
}

/// `count` links, every one ending its chain.
fn link_slots(count: usize) -> Vec<AtomicU32> {
    if links_zeroed() {
        zeroed_slots(count)
    } else {
        empty_slots(count)
    }
}

/// `count` zero slots from a zeroed allocation: for a table this size the
/// allocator maps fresh pages and writes none of them, so each page is
/// first touched by whoever first links a position in it (the pass, or a
/// builder of [`Build`]) and not by the thread that asked for the table.
/// Filling the 16 Mi links of the floor one slot at a time on that thread
/// was 40 to 55 ms of wall a process on x86 Linux, with nothing else
/// running (measured 30 Sep 2026).
/// No slot is read before the pass writes it, so the fill could never
/// reach a byte of output either way.
#[allow(unsafe_code)]
pub(crate) fn zeroed_slots(count: usize) -> Vec<AtomicU32> {
    let mut zeros = std::mem::ManuallyDrop::new(vec![0u32; count]);
    // Before any slot is written: a search follows links at random, and
    // 2 MiB pages keep those loads off the page walker (`crate::pages`).
    #[cfg(target_os = "linux")]
    crate::pages::advise_huge_of(&mut zeros[..]);
    // SAFETY: `AtomicU32` has the same size, alignment and bit validity
    // as `u32` (its documentation says so), and zero is a valid value of
    // it; the buffer is handed over whole, with its own length and
    // capacity, and `ManuallyDrop` keeps it from being freed twice.
    unsafe {
        Vec::from_raw_parts(
            zeros.as_mut_ptr().cast::<AtomicU32>(),
            zeros.len(),
            zeros.capacity(),
        )
    }
}

/// THE EMPTY STRIDE: a block the incompressible sample calls empty (not
/// worth searching, `sample::worth`) is linked at every fourth position
/// from its start, the others' chains ended ([`Links::insert_sparse`]),
/// where the level's plan scans such blocks at the floor and its chains
/// are keyed on four bytes (`Engine::link_stride`).
///
/// Such a block's own parse asks the finder only at every sixteenth
/// position, and what a later block finds in it is mostly noise that
/// costs the lazy parse links. Counted 15 Oct 2026 on 1 GiB of a big member at
/// level 3 on an Apple M5 Max (loaded, plain builds, two runs): 3,091
/// of its 4,096 blocks are empty; every position linked took 3.65 and
/// 3.59 s, 34.5 CPU s, for 1,032,538,304 B; every fourth 2.68 and 2.98 s,
/// 24.4 and 24.7 CPU s, for 1,031,387,229 B; every second 2.89 and
/// 3.05 s for 1,031,746,464 B. The sample reads the block's own bytes,
/// so the archive is the same at any width.
pub(crate) const EMPTY_STRIDE: usize = 4;

/// How far apart the floor scan asks: `lz::SCAN_STRIDE`, which the
/// drive holds equal to this.
pub(crate) const EMPTY_ASK_EVERY: usize = 16;

/// Whether a block linked at the empty stride `stride` (a power of two
/// no wider than [`EMPTY_ASK_EVERY`]) links position `at`: every
/// `stride`th position of the span, and every position the floor scan
/// asks at, one in [`EMPTY_ASK_EVERY`], its offset turning through
/// `0..stride` from one to the next (`lz::ScanAsk::Turn`).
///
/// The scan's candidates at a position are read from that position's own
/// link, so a position it asks must be linked; and a duplicate at
/// distance `d` is met where an asked position and the position `d`
/// before it are both linked. The asks' offsets cover every residue
/// modulo `stride` within `stride` asks, so one of them has its source
/// on the grid whatever `d` is. A function of the position alone, so
/// how the span is cut into pieces moves no link.
#[inline(always)]
pub(crate) fn empty_takes(at: usize, stride: usize) -> bool {
    let low = stride - 1;
    at & low == 0 || at & (EMPTY_ASK_EVERY - 1) == (at / EMPTY_ASK_EVERY) & low
}

/// The head a position whose first four bytes are `word` hangs from.
#[inline]
pub(crate) fn bucket(word: u32) -> usize {
    (word.wrapping_mul(HASH_MULTIPLIER) >> (32 - HEAD_BITS)) as usize
}

/// How many of a position's first bytes key its chain at every level but
/// the fast level 1.
pub(crate) const KEY_SHORT: usize = 4;
/// The fast level 1's key (`lz::fast_parse`): six bytes.
///
/// The key is what makes that parse's ONE link enough. Read from reference
/// `rar` 7.23's `-m1` archives, the source of a match is the nearest or
/// the second nearest earlier position that begins with the same six bytes
/// every time, and no fresh match under six bytes is taken on text; a four
/// byte chain's nearest candidate is a four or five byte match most of the
/// time, which a one link parse can only refuse. Counted 30 Sep 2026 on
/// text64 with the same parse: a four byte key wrote 9.2 percent more and
/// retired 38 percent more instructions, five bytes sat between, seven
/// bought 0.7 percent for 6 percent more instructions and eight lost both.
pub(crate) const KEY_WIDE: usize = 6;

const WIDE_MULTIPLIER: u64 = 0x9E37_79B9_7F4A_7C15;

/// The head a position hangs from under the six byte key, given the eight
/// bytes loaded at it, least significant first: the top two are shifted
/// out, so the head is a function of the six alone.
#[inline(always)]
fn bucket_of_word(word: u64) -> usize {
    ((word << (64 - 8 * KEY_WIDE as u32)).wrapping_mul(WIDE_MULTIPLIER) >> (64 - HEAD_BITS))
        as usize
}

/// The head position `at` of `span` hangs from under the six byte key.
/// `at + KEY_WIDE` must lie inside `span`; the load is padded where fewer
/// than eight bytes are left, which cannot reach the head.
#[inline(always)]
fn bucket_wide(span: &[u8], at: usize) -> usize {
    let word = if at + 8 <= span.len() {
        u64::from_le_bytes(span[at..at + 8].try_into().unwrap())
    } else {
        let mut bytes = [0u8; 8];
        bytes[..span.len() - at].copy_from_slice(&span[at..]);
        u64::from_le_bytes(bytes)
    };
    bucket_of_word(word)
}

/// Where a chain search's FAR links begin, in bytes back: a candidate
/// farther back than this is a far link, and a search that was given a
/// far-link budget follows no more of them than the budget
/// ([`Links::set_far_budget`]). 2 MiB, the reach every search has at the default
/// dictionary of levels 2 to 5, so a budgeted search over a longer
/// dictionary walks the chain as that default does and then looks a few
/// links past it. A constant and never a figure of the machine: which
/// candidates a search tests decides bytes.
pub(crate) const FAR_FROM: usize = 2 << 20;

/// A candidate a search found: nearest first, each longer than the last.
#[derive(Clone, Copy, Default)]
pub(crate) struct Found {
    pub(crate) distance: u32,
    pub(crate) length: u32,
}

/// The most candidates one search reports.
pub(crate) const FOUND_MAX: usize = 8;

/// Which positions the lazy parse asks the chains at together
/// ([`Links::search_pair`]). It moves time and never a byte: every list is
/// the one [`Links::search`] gives for its position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pairing {
    /// One position a search, as every parse asked until 1 Oct 2026: the
    /// knob, the tests and the store rule's sample instruments, none of
    /// them in a shipped build.
    #[cfg_attr(not(any(test, feature = "pair-knob")), allow(dead_code))]
    Single,
    /// A position reached with nothing in hand, together with the one
    /// after it, where the position has at least this many bytes of its
    /// span behind it; one position a search before that.
    ///
    /// Two walks taken in turn win where a link followed is a load the
    /// cache does not hold. A position with little behind it has short
    /// chains whose links and bytes are in cache already; its walks have
    /// nothing to wait for, and taking them in turn only makes their
    /// branches harder to predict. Counted 1 Oct 2026 on x86-64 over
    /// 20,000 small members each parsed from no history: paired from
    /// their first byte, level 2 took 1.0 to 2.2 percent MORE cycles;
    /// paired from 16 KiB in, it was level, and a tree of 5,000 larger
    /// members kept most of what the pair gives it.
    From(usize),
}

impl Pairing {
    /// The pairing every plan is built with.
    ///
    /// A build with the `pair-knob` feature reads `RARKIT_CHAIN_PAIR` (`0`
    /// for [`Pairing::Single`]) and `RARKIT_PAIR_FROM` (the bytes behind
    /// a position from which it is paired) once, so that the arms are
    /// counted and timed inside one binary; no shipped build has the
    /// feature.
    pub(crate) fn shipped() -> Pairing {
        #[cfg(feature = "pair-knob")]
        {
            static KNOB: std::sync::OnceLock<Pairing> = std::sync::OnceLock::new();
            *KNOB.get_or_init(|| {
                if std::env::var("RARKIT_CHAIN_PAIR").is_ok_and(|v| v == "0") {
                    return Pairing::Single;
                }
                std::env::var("RARKIT_PAIR_FROM")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .map_or(PAIRING, Pairing::From)
            })
        }
        #[cfg(not(feature = "pair-knob"))]
        PAIRING
    }
}

/// [`Pairing::shipped`] without the knob.
pub(crate) const PAIRING: Pairing = Pairing::From(16 << 10);

/// The paired search's COUNT (feature `pair-census`): how the lazy parse
/// asked the chains, and how many links each kind of walk followed. A lab
/// instrument, a feature of its own under the measured-arm rule: no
/// shipped build and no gate binary turns it on, the counters are shared
/// atomics, and a figure of time from a build with it means nothing.
#[cfg(feature = "pair-census")]
pub(crate) mod census {
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Lists the lazy parse asked for.
    pub(crate) static ASKED: AtomicU64 = AtomicU64::new(0);
    /// Of those, lists already in hand from an earlier pair.
    pub(crate) static IN_HAND: AtomicU64 = AtomicU64::new(0);
    /// Searches of two positions together.
    pub(crate) static PAIRS: AtomicU64 = AtomicU64::new(0);
    /// Searches of one position (every parse's, the floor scan's too).
    pub(crate) static SINGLES: AtomicU64 = AtomicU64::new(0);
    /// Links followed by a single search, by a pair's first walk and by
    /// its second.
    pub(crate) static SINGLE_LINKS: AtomicU64 = AtomicU64::new(0);
    pub(crate) static FIRST_LINKS: AtomicU64 = AtomicU64::new(0);
    pub(crate) static SECOND_LINKS: AtomicU64 = AtomicU64::new(0);
    /// Turns of a pair's loop in which both walks took a step.
    pub(crate) static TOGETHER: AtomicU64 = AtomicU64::new(0);

    #[inline]
    pub(crate) fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }

    /// Every counter by name, for the tool to print as the process ends.
    pub(crate) fn read() -> Vec<(&'static str, u64)> {
        [
            ("asked", &ASKED),
            ("in_hand", &IN_HAND),
            ("pairs", &PAIRS),
            ("singles", &SINGLES),
            ("single_links", &SINGLE_LINKS),
            ("first_links", &FIRST_LINKS),
            ("second_links", &SECOND_LINKS),
            ("together", &TOGETHER),
        ]
        .into_iter()
        .map(|(name, counter)| (name, counter.load(Ordering::Relaxed)))
        .collect()
    }
}

pub(crate) struct Chains {
    /// The newest position under each hash, plus one. Only the inserting
    /// pass touches it, which is why it sits apart from the links: the
    /// pass borrows this mutably while the parses share those.
    pub(crate) heads: Vec<u32>,
    pub(crate) links: Links,
    /// The largest the cyclic buffer gets, in positions.
    ceiling: usize,
    /// Positions [`Chains::wave_bytes`] keeps in hand below the exact
    /// bound: one, as these chains were first built, or none where a
    /// caller's budget holds the wave (`Chains::new`'s `wave`).
    spare: usize,
}

/// Each position's link, which is all a search reads.
pub(crate) struct Links {
    /// Plus one; zero ends a chain.
    slots: Vec<AtomicU32>,
    mask: usize,
    /// The farthest back a search may follow.
    reach: usize,
    /// How many of a position's first bytes key its chain: [`KEY_SHORT`],
    /// or [`KEY_WIDE`] for the fast level 1. Fixed when the chains are
    /// built, so every position of a run is keyed alike.
    key: usize,
    /// Where a search's walk ends unless it has far links to spend: the
    /// reach, or [`FAR_FROM`] under a far-link budget over chains that
    /// reach farther ([`Links::set_far_budget`]).
    near: usize,
    /// How many far links a search may follow past `near`; zero with no
    /// budget, where `near` is the reach and there are none to follow.
    far: u32,
}

impl Chains {
    /// Chains whose searches reach `dictionary` back, over a span of
    /// `span_len` positions, for waves of at most `wave` bytes. The
    /// buffer's ceiling comes from the dictionary and `wave` alone; a
    /// shorter span gets a buffer that simply never wraps. Its size cannot
    /// reach the output: a search's answers are the same in any buffer the
    /// pass is kept from overrunning.
    ///
    /// `wave` is `usize::MAX` unless a caller's memory budget holds the
    /// encoder to fewer blocks in flight (`Engine::hold_wave`). Then the
    /// buffer is the least power of two that still holds the reach and
    /// one such wave, where the floor would otherwise keep sixteen mebi
    /// links: at a 2 MiB dictionary 64 MiB of them, for a windowed member
    /// whose flushes never put more than 2 MiB in flight.
    ///
    /// `key` is [`KEY_SHORT`] or [`KEY_WIDE`]: how many of a position's
    /// first bytes its chain is keyed on. It moves no size here.
    pub(crate) fn new(dictionary: usize, span_len: usize, wave: usize, key: usize) -> Chains {
        debug_assert!(key == KEY_SHORT || key == KEY_WIDE);
        let cyclic = Chains::cyclic_for(dictionary, span_len, wave);
        Chains {
            heads: head_slots(),
            links: Links {
                slots: link_slots(cyclic),
                mask: cyclic - 1,
                reach: dictionary,
                key,
                near: dictionary,
                far: 0,
            },
            ceiling: Chains::ceiling_for(dictionary, wave),
            spare: usize::from(wave == usize::MAX),
        }
    }

    /// The largest the cyclic buffer gets for `dictionary` and `wave`.
    fn ceiling_for(dictionary: usize, wave: usize) -> usize {
        let ceiling = (2 * dictionary).max(CYCLIC_FLOOR).next_power_of_two();
        if wave == usize::MAX {
            return ceiling;
        }
        // The reach and the wave, exactly: held chains keep no position in
        // hand (`Chains::wave_bytes`).
        dictionary
            .saturating_add(wave.max(1))
            .next_power_of_two()
            .min(ceiling)
    }

    /// The cyclic buffer's length, in positions, for [`Chains::new`].
    fn cyclic_for(dictionary: usize, span_len: usize, wave: usize) -> usize {
        Chains::ceiling_for(dictionary, wave).min(span_len.next_power_of_two().max(1 << 16))
    }

    /// How many four-byte slots [`Chains::new`] allocates, heads and
    /// links together.
    pub(crate) fn slots_for(dictionary: usize, span_len: usize, wave: usize) -> usize {
        (1 << HEAD_BITS) + Chains::cyclic_for(dictionary, span_len, wave)
    }

    /// Whether these chains serve a span of `span_len` positions as they
    /// stand: either nothing would wrap, or they are already as large as
    /// the dictionary ever asks for.
    pub(crate) fn holds(&self, span_len: usize) -> bool {
        let cyclic = self.links.mask + 1;
        cyclic >= span_len || cyclic == self.ceiling
    }

    /// The head position `at` of `span` hangs from under the six byte key,
    /// for a test to say which positions share one.
    #[cfg(test)]
    pub(crate) fn heads_bucket_for_tests(&self, span: &[u8], at: usize) -> usize {
        bucket_wide(span, at)
    }

    /// Empty every head that inserting any position of `span` could have
    /// written, and no other: the buckets of its four byte words (its six
    /// byte ones under [`KEY_WIDE`]). After
    /// it the heads are as a fresh run finds them, if every position
    /// inserted since they were last empty lay in `span`'s bytes.
    ///
    /// It is the cheap form of `heads.fill(0)` for a short span, which is
    /// what a non-solid set of small members runs into once per member:
    /// clearing all 2^20 heads for a member of a few KiB was a fifth of
    /// that set's `-m1` time on its own. A head's bucket is a function of
    /// the four bytes at its position and nothing else, so the buckets a
    /// span can reach are the ones its words hash to, wherever in the
    /// span they sat.
    pub(crate) fn forget(&mut self, span: &[u8]) {
        if self.links.key == KEY_WIDE {
            for at in 0..span.len().saturating_sub(KEY_WIDE - 1) {
                self.heads[bucket_wide(span, at)] = 0;
            }
            return;
        }
        for at in 0..span.len().saturating_sub(3) {
            let word = u32::from_le_bytes(span[at..at + 4].try_into().unwrap());
            self.heads[bucket(word)] = 0;
        }
    }

    /// What [`Chains::wave_bytes`] reads for a span of `span_len` bytes on
    /// the chains [`Chains::new`] builds for `dictionary`, `sizing` and
    /// `wave`, before anything is built: for a writer to charge the blocks
    /// such chains parse at once (`Engine::flight_term_over`).
    pub(crate) fn wave_for(
        dictionary: usize,
        sizing: usize,
        wave: usize,
        span_len: usize,
    ) -> usize {
        let cyclic = Chains::cyclic_for(dictionary, sizing, wave);
        if cyclic >= span_len {
            usize::MAX
        } else {
            cyclic - dictionary - usize::from(wave == usize::MAX)
        }
    }

    /// How many bytes of blocks may be in flight at once, from the oldest
    /// block still being parsed to the newest the pass has linked, without
    /// the pass overwriting a link a parse can still follow.
    ///
    /// The exact bound is `cyclic - reach`. A wave starts at `s` and its
    /// pass links up to `s + wave - 1`; a parse in it searches from some
    /// `q >= s` and loads the link of a candidate `c` only once `q - c <=
    /// reach`, so `c >= s - reach`; `c`'s slot is overwritten by `c +
    /// cyclic >= s - reach + cyclic`, which is past `s + wave - 1` exactly
    /// when `wave <= cyclic - reach`. Unheld chains keep one position
    /// under it, as they were first built, so that no default wave moves;
    /// held ones use all of it (`spare`), which at a 2 MiB dictionary is
    /// what lets 4 Mi links parse a 2 MiB window in one wave of eight
    /// blocks rather than seven and one.
    pub(crate) fn wave_bytes(&self, span_len: usize) -> usize {
        let cyclic = self.links.mask + 1;
        if cyclic >= span_len {
            // Nothing wraps, so nothing is ever overwritten.
            usize::MAX
        } else {
            cyclic - self.links.reach - self.spare
        }
    }
}

impl Links {
    pub(crate) fn reach(&self) -> usize {
        self.reach
    }

    /// Put every search over these chains under a FAR-LINK BUDGET, or
    /// under none: with `Some(n)`, a search follows at most `n` candidates
    /// farther back than [`FAR_FROM`], each counted against its depth;
    /// with `None`, every link to the reach alike, as these chains are
    /// built. Chains that reach no farther than `FAR_FROM` have no far
    /// link, and are left as they are built whatever is asked.
    pub(crate) fn set_far_budget(&mut self, budget: Option<u32>) {
        match budget {
            Some(links) if self.reach > FAR_FROM => {
                self.near = FAR_FROM;
                self.far = links;
            }
            _ => {
                self.near = self.reach;
                self.far = 0;
            }
        }
    }

    /// How many links the cyclic buffer holds.
    pub(crate) fn len(&self) -> usize {
        self.slots.len()
    }

    /// How many of a position's first bytes key its chain.
    pub(crate) fn key(&self) -> usize {
        self.key
    }

    /// The head position `at` of `span` hangs from, under this key. `at`
    /// has at least the key's bytes after it.
    #[cfg(feature = "parallel")]
    #[inline(always)]
    fn bucket_at(&self, span: &[u8], at: usize) -> usize {
        if self.key == KEY_SHORT {
            bucket(u32::from_le_bytes(span[at..at + 4].try_into().unwrap()))
        } else {
            bucket_wide(span, at)
        }
    }

    /// Where the positions of a range ending at `end` stop being linked
    /// over `span`, from `start` on: a position with fewer bytes after it
    /// than the key is not linked.
    #[inline]
    fn keyed_end(&self, span: &[u8], start: usize, end: usize) -> usize {
        end.min(span.len().saturating_sub(self.key - 1)).max(start)
    }

    /// Under [`KEY_WIDE`], end the chains of the positions from `keyed`
    /// to `end` that a search may still ask at: the ones with four or five
    /// bytes after them, which no six byte key links. A search reads the
    /// link of the position it stands on before anything else
    /// ([`Links::search`], [`Links::nearest`]), and a slot the pass never
    /// wrote holds whatever an earlier lap of the cyclic buffer, or an
    /// earlier member, left in it.
    fn end_short(&self, span: &[u8], keyed: usize, end: usize) {
        for at in keyed..end.min(span.len().saturating_sub(KEY_SHORT - 1)) {
            self.slots[at & self.mask].store(0, Ordering::Relaxed);
        }
    }

    /// [`Links::insert`] under [`KEY_WIDE`]: one eight byte load, a
    /// shift, a multiply, the head's load and two stores a position.
    fn insert_wide(&self, heads: &mut [u32], span: &[u8], range: Range<usize>) {
        let keyed = self.keyed_end(span, range.start, range.end);
        // Whole words while eight bytes are in hand, the padded load for
        // the two positions after them.
        let whole = keyed.min(span.len().saturating_sub(7)).max(range.start);
        let mut at = range.start;
        // The whole table by its size, where it is the whole table (the
        // pass's own always is): a bucket is under `1 << HEAD_BITS` by its
        // shift, so no index into it is checked. The positions go a run at
        // a time, each run the slots up to the cyclic buffer's wrap, so no
        // slot is masked or checked either. The same loads and stores in
        // the same order: 18 instructions a position became 11.
        if let Ok(heads) = <&mut [u32; 1 << HEAD_BITS]>::try_from(&mut *heads) {
            while at < whole {
                let slot = at & self.mask;
                let run = (whole - at).min(self.slots.len() - slot);
                let links = &self.slots[slot..slot + run];
                let words = span[at..at + run + 7].windows(8);
                for ((link, window), position) in links.iter().zip(words).zip(at as u32 + 1..) {
                    let bucket = bucket_of_word(u64::from_le_bytes(window.try_into().unwrap()));
                    link.store(heads[bucket], Ordering::Relaxed);
                    heads[bucket] = position;
                }
                at += run;
            }
        }
        if whole > at {
            for window in span[at..whole + 7].windows(8) {
                let bucket = bucket_of_word(u64::from_le_bytes(window.try_into().unwrap()));
                self.slots[at & self.mask].store(heads[bucket], Ordering::Relaxed);
                heads[bucket] = at as u32 + 1;
                at += 1;
            }
        }
        for at in whole..keyed {
            let bucket = bucket_wide(span, at);
            self.slots[at & self.mask].store(heads[bucket], Ordering::Relaxed);
            heads[bucket] = at as u32 + 1;
        }
        self.end_short(span, keyed, range.end);
    }

    /// Link every position of `range`, which begins where the last call
    /// ended. A position with fewer than four bytes after it starts no
    /// match and is not linked; under [`KEY_WIDE`], one with fewer than
    /// six is not linked either, and its chain is ended.
    pub(crate) fn insert(&self, heads: &mut [u32], span: &[u8], range: Range<usize>) {
        if self.key == KEY_WIDE {
            return self.insert_wide(heads, span, range);
        }
        let end = range.end.min(span.len().saturating_sub(3));
        let mut at = range.start;
        // As [`Links::insert_wide`] goes: the whole table by its size, so
        // no bucket is checked, and the positions a run at a time up to the
        // cyclic buffer's wrap, so no slot is masked or checked. The same
        // loads and stores in the same order.
        if let Ok(heads) = <&mut [u32; 1 << HEAD_BITS]>::try_from(&mut *heads) {
            while at < end {
                let slot = at & self.mask;
                let run = (end - at).min(self.slots.len() - slot);
                let links = &self.slots[slot..slot + run];
                let words = span[at..at + run + 3].windows(4);
                for ((link, window), position) in links.iter().zip(words).zip(at as u32 + 1..) {
                    let bucket = bucket(u32::from_le_bytes(window.try_into().unwrap()));
                    link.store(heads[bucket], Ordering::Relaxed);
                    heads[bucket] = position;
                }
                at += run;
            }
        }
        for at in at..end {
            let word = u32::from_le_bytes(span[at..at + 4].try_into().unwrap());
            let bucket = bucket(word);
            self.slots[at & self.mask].store(heads[bucket], Ordering::Relaxed);
            heads[bucket] = at as u32 + 1;
        }
    }

    /// [`Links::insert`] for a block the sample calls empty (THE EMPTY
    /// STRIDE, [`EMPTY_STRIDE`]): the positions of `range` that
    /// [`empty_takes`] names are linked, and every other position's chain
    /// is ended. Under [`KEY_SHORT`] only.
    ///
    /// As [`Links::insert`] goes: the whole table by its size, and the
    /// positions a run at a time up to the cyclic buffer's wrap. A run's
    /// chains are all ended first, then only the positions the stride
    /// takes are linked, in order, sixteen positions at a time: the grid
    /// and the turning ask, five hashes of sixteen at the empty stride,
    /// and a position the stride skips is never visited. Every slot ends as
    /// [`Links::insert_sparse_each`] leaves it and the heads take the same
    /// positions in the same order; no parse reads a block's links before
    /// the block is linked whole, so the order of a run's stores is never
    /// seen. Counted 17 Oct 2026 from a profile of a big member at level 3 on an
    /// M1 Ultra: the position at a time form took about 2.5 times what
    /// [`Links::insert`] takes a block, on the one thread the pass runs on.
    pub(crate) fn insert_sparse(
        &self,
        heads: &mut [u32],
        span: &[u8],
        range: Range<usize>,
        stride: usize,
    ) {
        debug_assert_eq!(self.key, KEY_SHORT);
        debug_assert!(stride.is_power_of_two() && stride <= EMPTY_ASK_EVERY);
        let end = range.end.min(span.len().saturating_sub(3));
        let mut at = range.start;
        let low = stride - 1;
        if let Ok(heads) = <&mut [u32; 1 << HEAD_BITS]>::try_from(&mut *heads) {
            while at < end {
                let slot = at & self.mask;
                let run = (end - at).min(self.slots.len() - slot);
                let links = &self.slots[slot..slot + run];
                for link in links {
                    link.store(0, Ordering::Relaxed);
                }
                let mut take = |position: usize| {
                    let word = u32::from_le_bytes(span[position..position + 4].try_into().unwrap());
                    let bucket = bucket(word);
                    links[position - at].store(heads[bucket], Ordering::Relaxed);
                    heads[bucket] = position as u32 + 1;
                };
                let last = at + run;
                let mut window = at & !(EMPTY_ASK_EVERY - 1);
                while window < last {
                    let ask = (window / EMPTY_ASK_EVERY) & low;
                    let mut offset = 0;
                    while offset < EMPTY_ASK_EVERY {
                        let position = window + offset;
                        if position >= at && position < last {
                            take(position);
                        }
                        // The ask lies between the grid's first two
                        // positions where it is off the grid.
                        if offset == 0 && ask != 0 && window + ask >= at && window + ask < last {
                            take(window + ask);
                        }
                        offset += stride;
                    }
                    window += EMPTY_ASK_EVERY;
                }
                at = last;
            }
        }
        self.insert_sparse_each(heads, span, at..end, stride);
    }

    /// [`Links::insert_sparse`] a position at a time, over a table of any
    /// size: what the run form leaves, and the test's measure of it.
    pub(crate) fn insert_sparse_each(
        &self,
        heads: &mut [u32],
        span: &[u8],
        range: Range<usize>,
        stride: usize,
    ) {
        let end = range.end.min(span.len().saturating_sub(3));
        for at in range.start..end {
            if empty_takes(at, stride) {
                let word = u32::from_le_bytes(span[at..at + 4].try_into().unwrap());
                let bucket = bucket(word);
                self.slots[at & self.mask].store(heads[bucket], Ordering::Relaxed);
                heads[bucket] = at as u32 + 1;
            } else {
                self.slots[at & self.mask].store(0, Ordering::Relaxed);
            }
        }
    }

    /// Every slot's link as it stands, for a test to hold two passes'
    /// links equal.
    #[cfg(test)]
    pub(crate) fn slots_for_tests(&self) -> Vec<u32> {
        self.slots
            .iter()
            .map(|slot| slot.load(Ordering::Relaxed))
            .collect()
    }

    /// The nearest earlier position linked under `at`'s key, if it is
    /// within reach, with no byte compared: [`Links::nearest_back`] as a
    /// position, for a test to read a link by. `at` is a position the pass
    /// has linked, or one whose chain it ended.
    #[cfg(test)]
    pub(crate) fn nearest(&self, at: usize) -> Option<usize> {
        let back = self.nearest_back(at);
        (back != 0).then(|| at - back)
    }

    /// How far back the nearest earlier position linked under `at`'s key
    /// lies, zero where there is none within reach, with no byte compared
    /// and no branch taken on the link: all the fast level 1 follows
    /// (`lz::fast_parse`). Whether a bucket is empty, and whether its
    /// newest position is still within reach, turn on the input's bytes,
    /// and a parse that branched on each, at every position it does not
    /// skip, paid for the guesses. `at` is a position the pass has linked,
    /// or one whose chain it ended.
    #[inline(always)]
    pub(crate) fn nearest_back(&self, at: usize) -> usize {
        let link = self.slots[at & self.mask].load(Ordering::Relaxed) as usize;
        // `at - (link - 1)`; an ended chain (zero) and a slot that names
        // no earlier position both land past the reach or are masked.
        let distance = (at + 1).wrapping_sub(link);
        let within = (link != 0) & (distance <= self.reach);
        distance & usize::from(within).wrapping_neg()
    }

    /// The matches at `at` of four bytes or more, at most `limit` long:
    /// nearest first, each strictly longer than the one before. Follows at
    /// most `depth` links and stops early at a match of `enough` bytes.
    /// Returns how many of `found` it filled; past [`FOUND_MAX`] the last
    /// slot holds the longest.
    ///
    /// The walk ends at the first candidate past `near`, which is the
    /// reach unless the chains were given a FAR-LINK BUDGET
    /// ([`Links::set_far_budget`]); with one, the links past it are
    /// [`Links::search_far`]'s, out of line, so that a search with no
    /// budget is the loop it was before there was one.
    ///
    /// **Pinned by architecture, the same in every build of each**, as the
    /// compare above is: a search the inliner may or may not take in is a
    /// parse whose body moves with the build.
    ///
    /// - on x86-64 NEVER inlined, a symbol of its own as
    ///   [`Links::search_pair`] is: the loop that follows links is fastest
    ///   there in a function to itself (inlined into the parse with its
    ///   callers it cost text 1.7 to 4.2 percent more instructions and the
    ///   binary sets 0.8 to 4.4);
    /// - on every other architecture ALWAYS inlined: on aarch64 the call
    ///   is what costs (as a symbol it took small members from 0.963 of
    ///   the parent's instructions to 1.007, and text at level 2 from
    ///   0.975 to 0.995), and the binary sets do not pay for it there
    ///   (0.980 to 0.984 inlined).
    ///
    /// Counted 2 Oct 2026 at one thread and at sixteen.
    #[cfg_attr(target_arch = "x86_64", inline(never))]
    #[cfg_attr(not(target_arch = "x86_64"), inline(always))]
    pub(crate) fn search(
        &self,
        span: &[u8],
        at: usize,
        limit: usize,
        depth: u32,
        enough: usize,
        found: &mut [Found; FOUND_MAX],
    ) -> usize {
        if limit < 4 || at + 4 > span.len() {
            return 0;
        }
        let word = u32::from_le_bytes(span[at..at + 4].try_into().unwrap());
        let mut kept = 0;
        let mut best = 3usize;
        let mut link = self.slots[at & self.mask].load(Ordering::Relaxed);
        #[cfg(feature = "pair-census")]
        census::add(&census::SINGLES, 1);
        for step in 0..depth {
            if link == 0 {
                break;
            }
            let candidate = link as usize - 1;
            let distance = at - candidate;
            if distance > self.near {
                if self.far != 0 {
                    // Eight words of arguments, so that the hand-over is
                    // a jump and this function keeps no frame for it.
                    let walk = u64::from(link) << 32 | u64::from(depth - step);
                    let have = (best as u64) << 32 | kept as u64;
                    // A span is under 4 GiB (a link is a `u32`), so no
                    // match is as long as that, and a limit or an `enough`
                    // past it means what the largest `u32` means.
                    let most = u32::MAX as usize;
                    let ends = (limit.min(most) as u64) << 32 | enough.min(most) as u64;
                    return self.search_far(span, at, ends, walk, have, found);
                }
                break;
            }
            #[cfg(feature = "pair-census")]
            census::add(&census::SINGLE_LINKS, 1);
            // The byte a longer match must have is the cheapest test there
            // is, and it rejects nearly every candidate that cannot win.
            if best < limit
                && span[candidate + best] == span[at + best]
                && u32::from_le_bytes(span[candidate..candidate + 4].try_into().unwrap()) == word
            {
                let length = common_prefix(span, candidate, at, 4, limit);
                if length > best {
                    best = length;
                    let slot = kept.min(FOUND_MAX - 1);
                    found[slot] = Found {
                        distance: distance as u32,
                        length: length as u32,
                    };
                    kept = slot + 1;
                    if length >= enough || length == limit {
                        break;
                    }
                }
            }
            link = self.slots[candidate & self.mask].load(Ordering::Relaxed);
        }
        kept
    }

    /// The FAR links of a search under a budget: [`Links::search`] hands
    /// over at its first candidate farther back than [`FAR_FROM`], with
    /// `left` of its depth unspent and what it has found so far, and this
    /// follows at most the budget's count of them, each tested exactly as
    /// `search` tests a candidate and each counted against the depth. A
    /// chain runs nearest first, so every link from here on is a far one;
    /// the walk ends at the reach as `search`'s does.
    #[cold]
    #[inline(never)]
    fn search_far(
        &self,
        span: &[u8],
        at: usize,
        ends: u64,
        walk: u64,
        have: u64,
        found: &mut [Found; FOUND_MAX],
    ) -> usize {
        // As `search` packed them: the limit and `enough`, the link in
        // hand and the depth unspent, the best length and the count kept.
        let (limit, enough) = ((ends >> 32) as usize, ends as u32 as usize);
        let (mut link, left) = ((walk >> 32) as u32, walk as u32);
        let (mut best, mut kept) = ((have >> 32) as usize, have as u32 as usize);
        let word = u32::from_le_bytes(span[at..at + 4].try_into().unwrap());
        let mut steps = left.min(self.far);
        while steps != 0 {
            if link == 0 {
                break;
            }
            let candidate = link as usize - 1;
            let distance = at - candidate;
            // Tested before the candidate's own link is loaded, as in
            // `search` (the module's notes).
            if distance > self.reach {
                break;
            }
            if best < limit
                && span[candidate + best] == span[at + best]
                && u32::from_le_bytes(span[candidate..candidate + 4].try_into().unwrap()) == word
            {
                let length = common_prefix(span, candidate, at, 4, limit);
                if length > best {
                    best = length;
                    let slot = kept.min(FOUND_MAX - 1);
                    found[slot] = Found {
                        distance: distance as u32,
                        length: length as u32,
                    };
                    kept = slot + 1;
                    if length >= enough || length == limit {
                        break;
                    }
                }
            }
            // The last link the budget covers leads nowhere this walk
            // goes: its candidate's own link, a load from a far slot, is
            // left unread.
            steps -= 1;
            if steps == 0 {
                break;
            }
            link = self.slots[candidate & self.mask].load(Ordering::Relaxed);
        }
        kept
    }

    /// [`Links::search`] at two positions at once, their walks taken a
    /// link at a time in turn: `found[i]` and the count returned for it
    /// are what `search` gives for `at[i]` under `limit[i]`.
    ///
    /// A walk is bound by memory and not by work: each link followed is a
    /// load from a slot the cache most likely does not hold, and the next
    /// link cannot be asked for until that load answers. Two walks share
    /// nothing, so taken in turn the two loads wait together, and the pair
    /// costs little more time than the longer walk alone. Each walk makes
    /// the same loads, the same tests and the same stops in the same order
    /// as `search` does ([`Links::step`] is one turn of `search`'s loop),
    /// and neither reads anything the other wrote, so the answers cannot
    /// differ. A walk reads a slot only where `search` would: its own
    /// position's, which the pass has linked (the caller asks only at
    /// positions of a block being parsed), and a candidate's once that
    /// candidate is within reach.
    #[inline(never)]
    pub(crate) fn search_pair(
        &self,
        span: &[u8],
        at: [usize; 2],
        limit: [usize; 2],
        depth: u32,
        enough: usize,
        found: &mut [[Found; FOUND_MAX]; 2],
    ) -> [usize; 2] {
        #[cfg(test)]
        if span.len() == PROBE_SPAN.load(Ordering::Relaxed) {
            PROBE_PAIRS.fetch_add(1, Ordering::Relaxed);
        }
        let [first_found, second_found] = found;
        // The pair WARM_AHEAD positions on is warmed while this one walks
        // ([`Links::warm`]).
        self.warm(span, at[0] + WARM_AHEAD);
        self.warm(span, at[0] + WARM_AHEAD + 1);
        let mut first = self.walk(span, at[0], limit[0], depth);
        let mut second = self.walk(span, at[1], limit[1], depth);
        while first.left != 0 && second.left != 0 {
            self.step(span, &mut first, enough, first_found);
            self.step(span, &mut second, enough, second_found);
            #[cfg(feature = "pair-census")]
            census::add(&census::TOGETHER, 1);
        }
        while first.left != 0 {
            self.step(span, &mut first, enough, first_found);
        }
        while second.left != 0 {
            self.step(span, &mut second, enough, second_found);
        }
        if self.far != 0 {
            // Under a FAR-LINK BUDGET a walk that ended at the near bound
            // has its far links still to follow, and `search_far` follows
            // them alone, as it does for `search` and packed as `search`
            // packs them (a budget is a link or two, so there is nothing
            // of a far walk to take in turn). By value: neither walk's
            // address leaves this function.
            let most = u32::MAX as usize;
            let enough = enough.min(most) as u64;
            if first.far_left != 0 {
                let links = u64::from(first.link) << 32 | u64::from(first.far_left);
                let have = (first.best as u64) << 32 | first.kept as u64;
                let ends = (first.limit.min(most) as u64) << 32 | enough;
                first.kept = self.search_far(span, first.at, ends, links, have, first_found);
            }
            if second.far_left != 0 {
                let links = u64::from(second.link) << 32 | u64::from(second.far_left);
                let have = (second.best as u64) << 32 | second.kept as u64;
                let ends = (second.limit.min(most) as u64) << 32 | enough;
                second.kept = self.search_far(span, second.at, ends, links, have, second_found);
            }
        }
        #[cfg(feature = "pair-census")]
        {
            census::add(&census::PAIRS, 1);
            census::add(&census::FIRST_LINKS, u64::from(first.followed));
            census::add(&census::SECOND_LINKS, u64::from(second.followed));
        }
        [first.kept, second.kept]
    }

    /// Load what the first step of a walk at `at` will read, where its
    /// first candidate is within reach: that candidate's bytes and its
    /// link. Nothing is kept: the loads are there so the lines are in
    /// cache when the parse comes to `at`, where they are the walk's first
    /// dependent loads. A position the parse skips, or one past the
    /// span, costs a load or two and moves nothing.
    #[inline(always)]
    fn warm(&self, span: &[u8], at: usize) {
        if at + 4 > span.len() {
            return;
        }
        // A position the pass has not linked yet holds whatever an earlier
        // lap or member left in its slot, which may name a LATER position:
        // the distance then wraps past the reach and nothing is loaded.
        let link = self.slots[at & self.mask].load(Ordering::Relaxed) as usize;
        if link == 0 || (at + 1).wrapping_sub(link) > self.near {
            return;
        }
        let candidate = link - 1;
        std::hint::black_box(span[candidate + 3]);
        std::hint::black_box(self.slots[candidate & self.mask].load(Ordering::Relaxed));
    }

    /// A walk at `at` about to follow its first link, or one already
    /// ended where [`Links::search`] answers nothing without looking.
    #[inline(always)]
    fn walk(&self, span: &[u8], at: usize, limit: usize, depth: u32) -> Walk {
        if limit < 4 || at + 4 > span.len() {
            return Walk {
                at,
                limit,
                word: 0,
                link: 0,
                left: 0,
                far_left: 0,
                best: 3,
                kept: 0,
                #[cfg(feature = "pair-census")]
                followed: 0,
            };
        }
        Walk {
            at,
            limit,
            word: u32::from_le_bytes(span[at..at + 4].try_into().unwrap()),
            link: self.slots[at & self.mask].load(Ordering::Relaxed),
            left: depth,
            far_left: 0,
            best: 3,
            kept: 0,
            #[cfg(feature = "pair-census")]
            followed: 0,
        }
    }

    /// One turn of [`Links::search`]'s loop for `walk`, which has links
    /// left to follow.
    #[inline(always)]
    fn step(&self, span: &[u8], walk: &mut Walk, enough: usize, found: &mut [Found; FOUND_MAX]) {
        if walk.link == 0 {
            walk.left = 0;
            return;
        }
        let candidate = walk.link as usize - 1;
        let distance = walk.at - candidate;
        if distance > self.near {
            // As `search` ends: at the near bound, which is the reach
            // unless the chains have a FAR-LINK BUDGET. What the walk had
            // left is kept for `search_pair` to hand to `search_far` once
            // both walks have ended, so this turn makes no call.
            walk.far_left = walk.left;
            walk.left = 0;
            return;
        }
        walk.left -= 1;
        #[cfg(feature = "pair-census")]
        {
            walk.followed += 1;
        }
        if walk.best < walk.limit
            && span[candidate + walk.best] == span[walk.at + walk.best]
            && u32::from_le_bytes(span[candidate..candidate + 4].try_into().unwrap()) == walk.word
        {
            let length = common_prefix(span, candidate, walk.at, 4, walk.limit);
            if length > walk.best {
                walk.best = length;
                let slot = walk.kept.min(FOUND_MAX - 1);
                found[slot] = Found {
                    distance: distance as u32,
                    length: length as u32,
                };
                walk.kept = slot + 1;
                if length >= enough || length == walk.limit {
                    walk.left = 0;
                    return;
                }
            }
        }
        walk.link = self.slots[candidate & self.mask].load(Ordering::Relaxed);
    }
}

/// How many positions ahead of a paired search [`Links::search_pair`]
/// warms the first step of the walks it will take there.
///
/// Sixteen, measured 14 Oct 2026 on an EPYC 4345P (x86-64, eight cores,
/// plain builds, K=3, one thread, a 1 GiB member at level 3, where a
/// quarter of the blocks take the lazy parse and its walks are most of the
/// wall): 12.94 s against 13.15 s without (0.984), and 13.00 s at eight; a
/// prefetch hint in place of the loads read the same 12.96 s. It moves no
/// byte: what a walk reads and in which order is unchanged, and nothing
/// loaded is kept.
const WARM_AHEAD: usize = 16;

/// How many paired searches have run over a span of [`PROBE_SPAN`] bytes:
/// for the one test that sets that length to its own member's to show the
/// member was parsed in pairs at all, on whichever threads the parses ran
/// and whatever the tests beside it are encoding.
#[cfg(test)]
pub(crate) static PROBE_PAIRS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
pub(crate) static PROBE_SPAN: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(usize::MAX);

/// One position's walk in [`Links::search_pair`]: what [`Links::search`]
/// keeps in its locals.
struct Walk {
    at: usize,
    limit: usize,
    /// The position's first four bytes.
    word: u32,
    /// The next candidate, plus one; zero ends the chain.
    link: u32,
    /// How many links the walk may still follow; zero once it has ended.
    left: u32,
    /// What `left` was when the walk ended at the near bound with its
    /// far candidate in `link`, zero for a walk that ended any other way:
    /// the links [`Links::search_far`] may follow under a budget.
    far_left: u32,
    /// The longest match kept so far, three before any.
    best: usize,
    kept: usize,
    /// Links followed, for the count.
    #[cfg(feature = "pair-census")]
    followed: u32,
}

/// The longest [`Piece`], in positions: four parse blocks.
///
/// A longer piece has fewer firsts for its length (on text one position
/// in ten in 256 KiB, one in twelve in 1 MiB), and it is the firsts that
/// the build pays for over the pass: measured 30 Sep 2026 on one thread
/// of an M5 Max, the two steps cost 2.2 to 2.4 times the pass a position
/// at 256 KiB and 2.1 to 2.2 at 1 MiB.
#[cfg(feature = "parallel")]
pub(crate) const PIECE_MOST: usize = 1 << 20;

/// The heads are joined in this many shares, each a contiguous run of
/// buckets that only its own joiner touches.
#[cfg(feature = "parallel")]
const SHARE_BITS: u32 = 4;
#[cfg(feature = "parallel")]
const SHARES: usize = 1 << SHARE_BITS;

/// A stretch of positions [`Build::run`] links: a parse block's, or a
/// stretch of the history nothing parses.
#[cfg(feature = "parallel")]
#[derive(Clone)]
pub(crate) struct Piece {
    /// The span the piece is linked over ends here, as the span
    /// [`Links::insert`] is given does: a member's last three positions
    /// are linked by no piece.
    pub(crate) cut: usize,
    /// At most [`PIECE_MOST`] positions.
    pub(crate) range: Range<usize>,
    /// The parse blocks whose links this piece completes, if any: each
    /// handed to `ready` once this piece and every piece before it are
    /// joined.
    pub(crate) parses: Range<usize>,
    /// 1, or [`EMPTY_STRIDE`] for a piece of empty blocks: the positions
    /// linked are those [`empty_takes`] names, as
    /// [`Links::insert_sparse`] links them.
    pub(crate) stride: usize,
}

/// How many builds, and history pieces in them, any test has run: for a
/// test to show it reached the build at all.
#[cfg(all(test, feature = "parallel"))]
pub(crate) static BUILDS: AtomicUsize = AtomicUsize::new(0);
#[cfg(all(test, feature = "parallel"))]
pub(crate) static HISTORY_PIECES: AtomicUsize = AtomicUsize::new(0);

/// One linked piece's firsts, by share: `starts[s]..starts[s + 1]` of
/// `entries` are share `s`'s, each a first's offset into the piece, in
/// position order. Until its share is joined a first's own link slot
/// holds its bucket's last position in the piece, plus one: nothing reads
/// the slot before the join, which writes the first's link over it.
#[cfg(feature = "parallel")]
#[derive(Default)]
struct Firsts {
    starts: [u32; SHARES + 1],
    entries: Vec<u32>,
}

/// A share's heads and the next piece it joins.
#[cfg(feature = "parallel")]
struct Share<'a> {
    next: usize,
    heads: &'a mut [u32],
}

/// The pass across the pool: see the module's notes. Kept by the engine
/// between waves, and all of it taken the first time it runs, so what it
/// holds is a function of the builder count and never of the input.
#[cfg(feature = "parallel")]
#[derive(Default)]
pub(crate) struct Build {
    /// A head table a builder, all zero between pieces.
    tables: Vec<Mutex<Vec<u32>>>,
    /// The firsts of the pieces linked and not yet joined, a ring.
    firsts: Vec<RwLock<Firsts>>,
}

#[cfg(feature = "parallel")]
impl Build {
    /// How many pieces may be linked ahead of the oldest piece not yet
    /// joined whole, for `builders` builders: each builder's piece and one
    /// more, so a builder can link on while the joins trail.
    fn ring(builders: usize) -> usize {
        builders + 1
    }

    /// The bytes this build holds now: every table whole and every slot
    /// of the ring at a piece's worth of firsts, which is what the first
    /// run takes. Both come from pages nothing writes until a piece does,
    /// so this is the most it can touch rather than what it has.
    pub(crate) fn held_bytes(&self) -> u64 {
        let tables: usize = self
            .tables
            .iter()
            .map(|table| table.lock().unwrap_or_else(|e| e.into_inner()).capacity())
            .sum();
        let firsts: usize = self
            .firsts
            .iter()
            .map(|firsts| {
                firsts
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .entries
                    .capacity()
                    + SHARES
                    + 1
            })
            .sum();
        4 * (tables + firsts) as u64
    }

    /// What [`Build::held_bytes`] reads once a build of `builders`
    /// builders has run.
    pub(crate) fn most_bytes(builders: usize) -> u64 {
        let tables = builders << HEAD_BITS;
        let firsts = Build::ring(builders) * (PIECE_MOST + SHARES + 1);
        4 * (tables + firsts) as u64
    }

    /// Take the tables and the ring for `builders` builders, once.
    fn take(&mut self, builders: usize) {
        while self.tables.len() < builders {
            self.tables.push(Mutex::new(head_slots()));
        }
        while self.firsts.len() < Build::ring(builders) {
            self.firsts.push(RwLock::new(Firsts {
                starts: [0; SHARES + 1],
                entries: Vec::with_capacity(PIECE_MOST),
            }));
        }
    }

    /// Link `pieces`, in order, on `builders` builders of the pool, this
    /// thread one of them, leaving `heads` and `links` as
    /// [`Links::insert`] over each piece in turn leaves them. Each
    /// piece's `parse` is handed to `ready` once its links and every
    /// earlier piece's are final, which may be on any builder's thread.
    ///
    /// Any builder can finish the build alone, so one that never gets a
    /// thread holds nothing up; a builder with nothing left to take
    /// leaves, the last one never. `builders` sizes what the build keeps;
    /// no more builders run than there are pieces.
    pub(crate) fn run<R: Fn(usize) + Sync>(
        &mut self,
        heads: &mut [u32],
        links: &Links,
        span: &[u8],
        pieces: &[Piece],
        builders: usize,
        ready: &R,
    ) {
        debug_assert_eq!(heads.len(), 1 << HEAD_BITS);
        debug_assert!(pieces
            .windows(2)
            .all(|pair| pair[0].range.end <= pair[1].range.start));
        debug_assert!(pieces.iter().all(|piece| piece.range.len() <= PIECE_MOST));
        let count = pieces.len();
        if count == 0 {
            return;
        }
        #[cfg(test)]
        {
            BUILDS.fetch_add(1, Ordering::Relaxed);
            let history = pieces
                .iter()
                .filter(|piece| piece.parses.is_empty())
                .count();
            HISTORY_PIECES.fetch_add(history, Ordering::Relaxed);
        }
        let builders = builders.max(1);
        self.take(builders);
        let ring = Build::ring(builders);
        let tables = &self.tables[..builders];
        let firsts = &self.firsts[..ring];
        let builders = builders.min(count);
        let shares: Vec<Mutex<Share>> = heads
            .chunks_mut(1 << (HEAD_BITS - SHARE_BITS))
            .map(|heads| Mutex::new(Share { next: 0, heads }))
            .collect();
        // Pieces taken to link; linked; joined in how many shares; and
        // how many from the first are joined in every share.
        let taken = AtomicUsize::new(0);
        let linked: Vec<AtomicBool> = (0..count).map(|_| AtomicBool::new(false)).collect();
        let joined: Vec<AtomicUsize> = (0..count).map(|_| AtomicUsize::new(0)).collect();
        let settled = AtomicUsize::new(0);
        let started = AtomicUsize::new(0);
        let active = AtomicUsize::new(0);
        let work = || {
            let id = started.fetch_add(1, Ordering::AcqRel);
            active.fetch_add(1, Ordering::AcqRel);
            let mut idle = 0u32;
            let mut turn = id;
            loop {
                if settled.load(Ordering::Acquire) == count {
                    break;
                }
                // Joins first: they are what frees a parse.
                let mut did = false;
                for step in 0..SHARES {
                    let index = (turn + step) % SHARES;
                    let Ok(mut share) = shares[index].try_lock() else {
                        continue;
                    };
                    while share.next < count && linked[share.next].load(Ordering::Acquire) {
                        let piece = share.next;
                        {
                            let held = firsts[piece % ring]
                                .read()
                                .unwrap_or_else(|e| e.into_inner());
                            join(links, share.heads, index, span, &pieces[piece], &held);
                        }
                        share.next += 1;
                        did = true;
                        if joined[piece].fetch_add(1, Ordering::AcqRel) + 1 == SHARES {
                            // Pieces are joined whole in order: a share
                            // joins piece `k + 1` only after piece `k`.
                            settled.fetch_max(piece + 1, Ordering::AcqRel);
                            pieces[piece].parses.clone().for_each(ready);
                        }
                    }
                }
                turn += 1;
                if did {
                    idle = 0;
                    continue;
                }
                let next = taken.load(Ordering::Acquire);
                if next < count {
                    // The ring slot is free once the piece `ring` before
                    // is joined whole.
                    if next < settled.load(Ordering::Acquire) + ring
                        && taken
                            .compare_exchange(next, next + 1, Ordering::AcqRel, Ordering::Acquire)
                            .is_ok()
                    {
                        let mut table = tables[id].lock().unwrap_or_else(|e| e.into_inner());
                        let mut held = firsts[next % ring]
                            .write()
                            .unwrap_or_else(|e| e.into_inner());
                        link(links, &mut table, span, &pieces[next], &mut held);
                        drop(held);
                        linked[next].store(true, Ordering::Release);
                        idle = 0;
                        continue;
                    }
                } else {
                    // Every piece is taken: what is left is joins, which
                    // the builders still linking go on to.
                    let now = active.load(Ordering::Acquire);
                    if now > 1
                        && active
                            .compare_exchange(now, now - 1, Ordering::AcqRel, Ordering::Acquire)
                            .is_ok()
                    {
                        return;
                    }
                }
                // Waiting on another builder's piece: a parse this build
                // has already freed is better use of the thread than a
                // spin, and any builder left can finish the build.
                idle += 1;
                if idle < 16 {
                    std::hint::spin_loop();
                } else if rayon::yield_now() != Some(rayon::Yield::Executed) {
                    std::thread::yield_now();
                }
            }
            active.fetch_sub(1, Ordering::AcqRel);
        };
        let work = &work;
        rayon::in_place_scope(|scope| {
            for _ in 1..builders {
                scope.spawn(move |_| work());
            }
            work();
        });
    }
}

/// Step 1 for one piece: its links inside itself, its firsts gathered by
/// share with their buckets' last positions in their own slots, and the
/// builder's table left all zero again.
#[cfg(feature = "parallel")]
fn link(links: &Links, table: &mut [u32], span: &[u8], piece: &Piece, firsts: &mut Firsts) {
    let span = &span[..piece.cut];
    let start = piece.range.start;
    let end = links.keyed_end(span, start, piece.range.end);
    let mut counts = [0u32; SHARES];
    let stride = piece.stride;
    let mut take = |at: usize| {
        let bucket = links.bucket_at(span, at);
        let head = table[bucket];
        links.slots[at & links.mask].store(head, Ordering::Relaxed);
        table[bucket] = at as u32 + 1;
        counts[bucket >> (HEAD_BITS - SHARE_BITS)] += u32::from(head == 0);
    };
    if stride == 1 {
        for at in start..end {
            take(at);
        }
    } else {
        for at in start..end {
            // A position the empty stride does not take has its chain
            // ended, and is no first: the loop below reads only the
            // positions linked.
            if empty_takes(at, stride) {
                take(at);
            } else {
                links.slots[at & links.mask].store(0, Ordering::Relaxed);
            }
        }
    }
    let starts = &mut firsts.starts;
    starts[0] = 0;
    for share in 0..SHARES {
        starts[share + 1] = starts[share] + counts[share];
    }
    let mut cursor = [0u32; SHARES];
    cursor.copy_from_slice(&starts[..SHARES]);
    firsts.entries.resize(starts[SHARES] as usize, 0);
    // A first is the one kind of position whose link inside the piece is
    // none. Its bucket's head is emptied here, which empties every head
    // this piece wrote, and what it held goes to the first's slot.
    for at in (start..end).filter(|&at| stride == 1 || empty_takes(at, stride)) {
        let slot = &links.slots[at & links.mask];
        if slot.load(Ordering::Relaxed) == 0 {
            let bucket = links.bucket_at(span, at);
            slot.store(table[bucket], Ordering::Relaxed);
            table[bucket] = 0;
            let share = bucket >> (HEAD_BITS - SHARE_BITS);
            firsts.entries[cursor[share] as usize] = (at - start) as u32;
            cursor[share] += 1;
        }
    }
    if links.key == KEY_WIDE {
        links.end_short(span, end, piece.range.end);
    }
}

/// Step 2 for one share of one linked piece: each first's link is its
/// bucket's head, and the head takes the bucket's last position in the
/// piece, which the first's slot held until now.
#[cfg(feature = "parallel")]
fn join(
    links: &Links,
    heads: &mut [u32],
    share: usize,
    span: &[u8],
    piece: &Piece,
    firsts: &Firsts,
) {
    let span = &span[..piece.cut];
    let start = piece.range.start;
    let base = share << (HEAD_BITS - SHARE_BITS);
    let range = firsts.starts[share] as usize..firsts.starts[share + 1] as usize;
    for &offset in &firsts.entries[range] {
        let at = start + offset as usize;
        let bucket = links.bucket_at(span, at) - base;
        let slot = &links.slots[at & links.mask];
        let last = slot.load(Ordering::Relaxed);
        slot.store(heads[bucket], Ordering::Relaxed);
        heads[bucket] = last;
    }
}
