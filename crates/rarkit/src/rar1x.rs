//! The decoder of RAR 1.3, 1.4 and 1.5 compressed members.
//!
//! The decode code, the tables and the tests of this file and of
//! `rar1x/` were written from `specs/SPEC-A-rar15-codec.md`, the tables
//! from its sections 4.2 and 4.3; no other RAR implementation and no copy
//! of the predecessor was opened.
//!
//! What else its author had seen, so that this says no more than is true.
//! The seam to the callers (what a decoder is given and what it returns)
//! was learned from the callers in `src/read`. Before writing, the author
//! had seen the header comment and the import lines of the driver this
//! module replaced: its first 43 lines and about a dozen single lines, and
//! no function body. After the module was complete, a compiler warning
//! printed six function names of the decoder that driver stood on.
//!
//! Three parts: [`feed`] is the bit stream of section 2, [`codes`] the
//! fixed prefix codes of 4.2 and 4.3, [`ranks`] the adaptive rank table of
//! 4.1. This file holds the state of section 3, the steps of 4.4 to 4.7
//! and the history a match copies from (4.8).
//!
//! What the specification leaves open and this decoder chooses:
//!
//! - bits past the end of the packed bytes read as zero, whatever the
//!   member's size (4.11);
//! - a copy at a distance that names no byte gives zeros however much has
//!   been output since the last full reset (4.8);
//! - the count of literals in a row is kept only as far as 16, the one
//!   value any rule compares it with (3.2, 4.5, 4.7).

mod codes;
mod feed;
mod ranks;
#[cfg(test)]
mod tests;

use crate::error::{Corruption, Error, ErrorKind, Result};
use crate::rar5_lz::output::LzSink;
use crate::rar5_lz::PackedSource;

use codes::{literal_code, LENA, LENB, RK, SHORT};
use feed::{Feed, Hold};
use ranks::Ranks;

/// How far back a copy can reach (4.8): the largest distance any rule
/// gives.
const REACH: u32 = 65_535;

/// The ring the history is kept in: twice the reach and more, so that a
/// copy may write a few places past its end without touching a byte a
/// later copy can read.
const RING: usize = 1 << 17;

/// How many bytes the wide copy moves at a time.
const BLOCK: usize = 8;

/// How many bytes the wide copy always moves, whatever the match's
/// length: two blocks, with no test between them. A match of this length
/// or less (most matches here: their mean is about 7.5 bytes on a text
/// member) is copied with no loop, so no branch turns on its length; a
/// longer one goes on a block at a time. A copy may therefore write up to
/// `FIRST` slots past its end: all of them for a copy of no bytes, which
/// no rule of the decoder makes but the copy itself allows.
const FIRST: usize = 2 * BLOCK;

// What makes that overrun harmless, held at compile time: a slot `i`
// past the write point is `RING - i` back from it, and for every `i` the
// overrun can touch that is further than any distance reaches. A ring
// shrunk to the reach, or a first run widened past the difference, does
// not build.
const _: () = assert!(RING - FIRST > REACH as usize);

/// How many slots past a copy's end the guard below keeps: the first run
/// and one block more.
///
/// It is sized from the widest write the copy can make, not from the
/// ring. A right copy ends at most `FIRST` slots past the copy's end.
/// A wrong copy is a block wider than it should be or one block too many,
/// and either lands inside the block after the first run; so does
/// anything the byte at a time copy could write past its end. So this
/// holds every slot one fault can reach, and a watch any wider would only
/// look at slots that took two faults to touch, at a cost paid on every
/// copy.
#[cfg(debug_assertions)]
const WATCHED: usize = FIRST + BLOCK;

/// The write side guard of this ring: the slots just past where a copy
/// in place ends, kept across the copy. Debug builds only.
///
/// `crate::window_guard` asks of the other rings whether a copy touched
/// a slot a legal distance still names. Asked that here it could never
/// fail, since every slot near the write point lies in the half of the
/// ring no distance names, whatever the copy did. So this asks the
/// question that CAN fail, with the assertion above carrying the rest:
/// did the copy write past the slots it is allowed, which are
/// `FIRST` for the wide copy and none for the copy that goes a byte
/// at a time.
#[cfg(debug_assertions)]
struct Watch {
    /// The slot after the copy's last byte.
    end: usize,
    was: [u8; WATCHED],
}

#[cfg(debug_assertions)]
impl Watch {
    /// Keep the slots from `end` on. Call before the copy.
    fn take(ring: &[u8; RING], end: usize) -> Watch {
        let mut was = [0u8; WATCHED];
        for (index, slot) in was.iter_mut().enumerate() {
            *slot = ring[(end + index) % RING];
        }
        Watch { end, was }
    }

    /// Fail if the copy changed a watched slot past the first `allowed`.
    /// Call after the copy.
    fn held(&self, ring: &[u8; RING], allowed: usize, site: &str) {
        for (index, &was) in self.was.iter().enumerate().skip(allowed) {
            let slot = (self.end + index) % RING;
            assert!(
                ring[slot] == was,
                "{site}: a copy that ends at {} changed slot {slot}, the slot \
                 numbered {index} from its end, and only the first {allowed} \
                 slots there are its to change",
                self.end
            );
        }
    }
}

/// A distance never set (3.1): over 256 and not under either threshold
/// when compared, and outside every distance a copy reads from.
const UNSET: u32 = u32::MAX;

/// The two values of the far-distance threshold (3.2, 4.7 R11).
const NEAR_LINE: u32 = 8193;
const FAR_LINE: u32 = 32512;

/// The decoder: the history and the adaptive state of section 3, kept
/// from one member to the next for a solid chain.
pub(crate) struct Rar1x {
    past: Past,
    model: Box<Model>,
}

impl Rar1x {
    pub(crate) fn new() -> Rar1x {
        Rar1x {
            past: Past::new(),
            model: Box::new(Model::first()),
        }
    }

    /// What the history holds, for the caller's memory account.
    pub(crate) fn window_bytes(&self) -> usize {
        RING
    }

    /// Decode one member of declared size `target` from `source` into
    /// `out`.
    ///
    /// `Ok` with fewer than `target` bytes delivered is a member whose
    /// packed bytes ran out (4.11): the caller's checksum reports it. The
    /// one decode failure is a match that would pass `target` (4.8). A
    /// failure of the source or of the sink is returned as it came.
    pub(crate) fn member<S: PackedSource, O: LzSink>(
        &mut self,
        source: &mut S,
        target: u64,
        solid: bool,
        out: &mut O,
    ) -> Result<()> {
        if !solid {
            *self.model = Model::first();
            self.past.clear();
        }
        self.model.dials.begin_member();
        if target == 0 {
            return Ok(());
        }
        let mut hold = Hold::new();
        let Model { tables, dials } = &mut *self.model;
        let mut pass = Pass {
            feed: Feed::new(source, &mut hold),
            tables,
            dials: *dials,
            pen: self.past.pen(),
            out,
            left: target,
        };
        let ran = pass.steps();
        let settled = pass.pen.settle(pass.out);
        *dials = pass.dials;
        (self.past.at, self.past.lapped) = (pass.pen.at, pass.pen.lapped);
        // The source's own failure is the cause of whatever the zero bits
        // after it decoded to.
        if let Some(fault) = hold.fault {
            return Err(fault);
        }
        ran.and(settled)
    }
}

/// The history of 4.8 as a ring, between members.
struct Past {
    ring: Box<[u8; RING]>,
    /// Where the next byte goes.
    at: u32,
    /// The output since the last full reset has been round the ring.
    lapped: bool,
}

impl Past {
    fn new() -> Past {
        Past {
            ring: vec![0u8; RING]
                .into_boxed_slice()
                .try_into()
                .expect("the ring is RING bytes"),
            at: 0,
            lapped: false,
        }
    }

    /// The empty history of a full reset. What the ring held is never
    /// read again: a copy reads only places written since.
    fn clear(&mut self) {
        self.at = 0;
        self.lapped = false;
    }

    /// The history as one member writes it.
    fn pen(&mut self) -> Pen<'_> {
        Pen {
            ring: &mut self.ring,
            at: self.at,
            sent: self.at,
            lapped: self.lapped,
        }
    }
}

/// The history while a member is decoded: the ring, and the bytes of it
/// not yet delivered. Its three words are meant to stay in registers, so
/// the paths that leave the loop take what they need by value.
struct Pen<'a> {
    ring: &'a mut [u8; RING],
    /// Always under `RING`.
    at: u32,
    /// `ring[sent..at]` is output the sink has not been given.
    sent: u32,
    lapped: bool,
}

/// The block of the ring that starts at `at`.
#[inline(always)]
fn block(ring: &[u8; RING], at: usize) -> [u8; BLOCK] {
    ring[at..at + BLOCK].try_into().expect("a block")
}

/// Write a block into the ring at `at`.
#[inline(always)]
fn put_block(ring: &mut [u8; RING], at: usize, bytes: [u8; BLOCK]) {
    ring[at..at + BLOCK].copy_from_slice(&bytes);
}

/// Hand a run of output to the sink.
#[cold]
#[inline(never)]
fn deliver<O: LzSink>(out: &mut O, bytes: &[u8]) -> Result<()> {
    out.put(bytes)
}

impl Pen<'_> {
    /// Output one byte.
    #[inline(always)]
    fn push<O: LzSink>(&mut self, byte: u8, out: &mut O) -> Result<()> {
        self.ring[self.at as usize % RING] = byte;
        self.at = (self.at + 1) % RING as u32;
        if self.at == 0 {
            // The ring's end was reached: deliver up to it.
            let from = self.sent as usize % RING;
            self.sent = 0;
            self.lapped = true;
            deliver(out, &self.ring[from..])?;
        }
        Ok(())
    }

    /// Deliver what is held, at the member's end.
    #[inline(always)]
    fn settle<O: LzSink>(&mut self, out: &mut O) -> Result<()> {
        let held = self.sent as usize..self.at as usize;
        self.sent = self.at;
        match self.ring.get(held) {
            Some(bytes) if !bytes.is_empty() => out.put(bytes),
            _ => Ok(()),
        }
    }

    /// Output `length` bytes, each the byte `distance` places back; or
    /// `length` zeros when the distance names no byte as the copy begins
    /// (4.8, and section 6's rows for a distance of 0, a distance never
    /// set and a distance over the output so far).
    #[inline(always)]
    fn copy<O: LzSink>(&mut self, distance: u32, length: u32, out: &mut O) -> Result<()> {
        // How far back a byte exists: the output since the last full
        // reset, and no further than a distance can say.
        let reach = if self.lapped {
            REACH
        } else {
            self.at.min(REACH)
        };
        if distance.wrapping_sub(1) >= reach {
            for _ in 0..length {
                self.push(0, out)?;
            }
            return Ok(());
        }
        let to = self.at as usize;
        let from = self.at.wrapping_sub(distance) as usize % RING;
        let length = length as usize;
        if to.max(from) + length + FIRST <= RING {
            // Neither run comes near the ring's end.
            #[cfg(debug_assertions)]
            let watch = Watch::take(self.ring, to + length);
            if distance as usize >= BLOCK {
                // A block at a time, lowest first, so a block reads what
                // the one before wrote when the distance is under two
                // blocks; the first two always, then one more while the
                // match lasts. The copy may run up to `FIRST` places
                // past its end: those places are over REACH back from
                // every byte still to be written before they are written
                // themselves, so no copy reads what is left there.
                let first = block(self.ring, from);
                put_block(self.ring, to, first);
                let second = block(self.ring, from + BLOCK);
                put_block(self.ring, to + BLOCK, second);
                let mut done = FIRST;
                while done < length {
                    self.ring
                        .copy_within(from + done..from + done + BLOCK, to + done);
                    done += BLOCK;
                }
                #[cfg(debug_assertions)]
                watch.held(self.ring, FIRST, "rar1x, the wide copy");
            } else {
                // Lowest byte first, so the copy reads what it has just
                // written.
                for step in 0..length {
                    self.ring[to + step] = self.ring[from + step];
                }
                #[cfg(debug_assertions)]
                watch.held(self.ring, 0, "rar1x, the byte copy");
            }
            self.at = (to + length) as u32;
            return Ok(());
        }
        for _ in 0..length {
            let byte = self.ring[self.at.wrapping_sub(distance) as usize % RING];
            self.push(byte, out)?;
        }
        Ok(())
    }
}

/// The adaptive state of section 3, the history apart.
struct Model {
    tables: Tables,
    dials: Dials,
}

/// The four tables of 3.1.
struct Tables {
    literals: Ranks<161>,
    flag_bytes: Ranks<255>,
    far_parts: Ranks<255>,
    /// The short-match distance list: entry `r` is a distance less one.
    near: [u8; 256],
}

/// The scalars of 3.1. One member's decode works on a copy of them and
/// hands it back when the member ends.
#[derive(Clone, Copy)]
struct Dials {
    /// The four most recent match distances, newest first.
    recent: [u32; 4],
    /// The previous match: distance and length.
    last: (u32, u32),
    literal_mean: u32,
    far_mean: u32,
    short_mean: u32,
    long_mean: u32,
    hits: u32,
    far_line: u32,
    literal_lean: u32,
    long_lean: u32,
    /// Literals in a row, counted no further than 16.
    streak: u32,
    /// The alternate short-code variant is in effect.
    alternate: bool,
    // The three quantities every member starts afresh.
    run_mode: bool,
    repeats: u32,
    /// The flag bits in hand, the next at the top, and how many.
    flags: u8,
    flags_held: u32,
}

impl Model {
    /// The first values of 3.2.
    fn first() -> Model {
        let mut near = [0u8; 256];
        for (entry, value) in near.iter_mut().zip(0u8..=255) {
            *entry = value;
        }
        Model {
            tables: Tables {
                literals: Ranks::flat(|slot| slot),
                flag_bytes: Ranks::flat(|slot| 0u8.wrapping_sub(slot)),
                far_parts: Ranks::graded(|slot| slot),
                near,
            },
            dials: Dials {
                recent: [UNSET; 4],
                last: (UNSET, 0),
                literal_mean: 13568,
                far_mean: 0,
                short_mean: 0,
                long_mean: 0,
                hits: 0,
                far_line: NEAR_LINE,
                literal_lean: 128,
                long_lean: 128,
                streak: 0,
                alternate: false,
                run_mode: false,
                repeats: 0,
                flags: 0,
                flags_held: 0,
            },
        }
    }
}

impl Dials {
    /// The member reset of 3.2.
    fn begin_member(&mut self) {
        self.run_mode = false;
        self.repeats = 0;
        self.flags_held = 0;
    }

    /// A distance becomes the newest of the recent four.
    #[inline(always)]
    fn remember(&mut self, distance: u32) {
        let [a, b, c, _] = self.recent;
        self.recent = [distance, a, b, c];
    }
}

/// One of the two preference counters gains 16; past 255 it falls to 144
/// and the other is halved (rule L and 4.7 R2).
#[inline(always)]
fn lean(gains: &mut u32, other: &mut u32) {
    if *gains < 240 {
        *gains += 16;
    } else {
        // One step in seven or fewer: kept a branch, which predicts,
        // where a select would cost every step.
        std::hint::cold_path();
        *gains = 144;
        *other /= 2;
    }
}

/// A match would carry the member past its declared size (4.8).
#[cold]
#[inline(never)]
fn overrun() -> Error {
    Error::new(ErrorKind::Corrupt(Corruption::Stream))
}

/// What the flag bits of 4.4 select.
enum Step {
    Literal,
    Long,
    Short,
}

/// One member's decode in progress.
struct Pass<'a, S: PackedSource, O: LzSink> {
    feed: Feed<'a, S>,
    tables: &'a mut Tables,
    dials: Dials,
    pen: Pen<'a>,
    out: &'a mut O,
    /// Bytes the member still owes: its declared size less its output.
    left: u64,
}

impl<S: PackedSource, O: LzSink> Pass<'_, S, O> {
    /// The main loop of 4.4, bounded as 4.11 rules: a step is taken while
    /// the member owes bytes and at least one packed bit is left. The
    /// feed is topped up once here, for the whole step: no step reads
    /// more than that refill leaves (`feed::STEP_BITS`).
    #[inline(always)]
    fn steps(&mut self) -> Result<()> {
        while self.left > 0 {
            self.feed.top_up();
            if self.feed.spent() {
                break;
            }
            if self.dials.run_mode {
                self.run_steps()?;
                continue;
            }
            let long_first = self.dials.long_lean > self.dials.literal_lean;
            let step = if self.flag() {
                if long_first {
                    Step::Long
                } else {
                    Step::Literal
                }
            } else if self.flag() {
                if long_first {
                    Step::Literal
                } else {
                    Step::Long
                }
            } else {
                Step::Short
            };
            match step {
                Step::Literal => self.plain_literal()?,
                Step::Long => self.far_match()?,
                Step::Short => self.short_family()?,
            }
        }
        Ok(())
    }

    /// The next flag bit, reading a flag byte when none is in hand (D3).
    #[inline(always)]
    fn flag(&mut self) -> bool {
        if self.dials.flags_held == 0 {
            let value = self.feed.coded(&RK[2]);
            self.dials.flags = match u8::try_from(value) {
                Ok(slot) => self.tables.flag_bytes.take(slot),
                // Value 256: eight zero bits, the table untouched.
                Err(_) => 0,
            };
            self.dials.flags_held = 8;
        }
        let bit = self.dials.flags >= 0x80;
        self.dials.flags <<= 1;
        self.dials.flags_held -= 1;
        bit
    }

    /// Rule L: the literal at `slot`.
    #[inline(always)]
    fn literal(&mut self, slot: u8) -> Result<()> {
        let byte = self.tables.literals.take(slot);
        let sum = self.dials.literal_mean + u32::from(slot);
        self.dials.literal_mean = sum - sum / 256;
        lean(&mut self.dials.literal_lean, &mut self.dials.long_lean);
        self.left -= 1;
        self.pen.push(byte, self.out)
    }

    /// 4.5.1.
    #[inline(always)]
    fn plain_literal(&mut self) -> Result<()> {
        let value = self.feed.coded(literal_code(self.dials.literal_mean));
        if self.dials.streak == 16 {
            self.dials.run_mode = self.dials.flags_held == 0;
        } else {
            self.dials.streak += 1;
        }
        // Value 256 is slot 0.
        self.literal(value as u8)
    }

    /// 4.5.2: run-mode steps, one after another for as long as they are
    /// literals and the loop of 4.4 would take another step. A run of
    /// literals is where this format spends its time on data that does
    /// not compress, so it has a loop of its own.
    #[inline(always)]
    fn run_steps(&mut self) -> Result<()> {
        // The caller has topped the feed up and found a packed bit left.
        // Each literal tops it up again for the next, so the tail after
        // the loop reads from the refill before the last literal code.
        loop {
            let value = self.feed.coded(literal_code(self.dials.literal_mean));
            if value == 0 {
                break;
            }
            self.literal((value - 1) as u8)?;
            if self.left == 0 {
                return Ok(());
            }
            self.feed.top_up();
            if self.feed.spent() {
                return Ok(());
            }
        }
        if self.feed.bit() {
            self.dials.streak = 0;
            self.dials.run_mode = false;
            return Ok(());
        }
        let length = if self.feed.bit() { 4 } else { 3 };
        let high = self.feed.coded(&RK[2]);
        let low = self.feed.field(5);
        self.copy(high * 32 + low, length)
    }

    /// 4.6.
    #[inline(always)]
    fn short_family(&mut self) -> Result<()> {
        self.dials.streak = 0;
        if self.dials.repeats == 2 {
            if self.feed.bit() {
                let (distance, length) = self.dials.last;
                return self.copy(distance, length);
            }
            self.dials.repeats = 0;
        }
        let column =
            &SHORT[usize::from(self.dials.short_mean >= 37)][usize::from(self.dials.alternate)];
        let index = self.feed.index(column);
        let (distance, length) = match index {
            9 => {
                self.dials.repeats += 1;
                self.dials.last
            }
            14 => {
                self.dials.repeats = 0;
                let length = self.feed.coded(&LENB) + 5;
                let distance = 32768 + self.feed.field(15);
                (distance, length)
            }
            10..=13 => {
                self.dials.repeats = 0;
                // Chosen by name and not by a computed place, so that
                // the scalars can stay in registers.
                let [first, second, third, fourth] = self.dials.recent;
                let distance = match index {
                    10 => first,
                    11 => second,
                    12 => third,
                    _ => fourth,
                };
                let code = self.feed.coded(&LENA);
                if index == 10 && code == 255 {
                    self.dials.alternate = !self.dials.alternate;
                    return Ok(());
                }
                let length = code
                    + 2
                    + u32::from(distance > 256)
                    + u32::from(distance >= self.dials.far_line);
                self.dials.remember(distance);
                (distance, length)
            }
            _ => {
                self.dials.repeats = 0;
                let sum = self.dials.short_mean + index;
                self.dials.short_mean = sum - sum / 16;
                // Value 256 is rank 0.
                let rank = usize::from(self.feed.coded(&RK[2]) as u8);
                let entry = self.tables.near[rank];
                if rank > 0 {
                    self.tables.near.swap(rank, rank - 1);
                }
                let distance = u32::from(entry) + 1;
                self.dials.remember(distance);
                (distance, index + 2)
            }
        };
        self.dials.last = (distance, length);
        self.copy(distance, length)
    }

    /// 4.7.
    #[inline(always)]
    fn far_match(&mut self) -> Result<()> {
        let was_long = self.dials.long_mean;
        let code = match was_long {
            122.. => self.feed.coded(&LENB),
            64.. => self.feed.coded(&LENA),
            _ => self.feed.counted(),
        };
        let rank = self.feed.coded(match self.dials.far_mean {
            10496.. => &RK[2],
            1792.. => &RK[1],
            _ => &RK[0],
        });
        let low = self.feed.field(7);

        let dials = &mut self.dials;
        // Value 256 is slot 0, and counts in full toward the average.
        let distance = u32::from(self.tables.far_parts.take(rank as u8)) * 128 + low;
        let line = dials.far_line;
        let length = code + 3 + u32::from(distance >= line) + 8 * u32::from(distance <= 256);

        dials.far_line = if dials.hits > 176 || (dials.literal_mean >= 10752 && was_long < 64) {
            FAR_LINE
        } else {
            NEAR_LINE
        };
        if code != 1 && code != 4 {
            dials.hits = if code == 0 && distance <= line {
                (dials.hits + 1).min(255)
            } else {
                dials.hits.saturating_sub(1)
            };
        }
        let sum = was_long + code;
        dials.long_mean = sum - sum / 32;
        let sum = dials.far_mean + rank;
        dials.far_mean = sum - sum / 256;
        lean(&mut dials.long_lean, &mut dials.literal_lean);
        dials.streak = 0;
        dials.remember(distance);
        dials.last = (distance, length);
        self.copy(distance, length)
    }

    /// A match's bytes, refused whole when they would pass the member's
    /// declared size (4.8).
    #[inline(always)]
    fn copy(&mut self, distance: u32, length: u32) -> Result<()> {
        if u64::from(length) > self.left {
            return Err(overrun());
        }
        self.left -= u64::from(length);
        self.pen.copy(distance, length, self.out)
    }
}
