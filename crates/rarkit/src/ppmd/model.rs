//! Spec I sections 3.5 and 3.7 to 3.10: the model, symbol decoding and the
//! update that follows every symbol.
//!
//! The model is driven only by the sequence of symbols decoded, and every
//! rule here is total over all of them (spec I 3.10), so a hostile stream
//! cannot reach a state ordinary input could not. Where a rule would index
//! or divide through a broken invariant the code checks it and raises
//! [`PpmFault::Inconsistent`]; none of those checks can fire.

use super::arena::{Arena, BASE, STATE, UNIT};
use super::range::RangeDecoder;
use super::tables::{hb, BIN_CLASS, CLASS_OF, ESC_AFTER_BINARY, ESC_CLASS, INIT_BIN};
use super::{fault, PpmFault, StreamBytes};
use crate::{Corruption, ErrorKind, Result};

/// Bytes the binary-probability table holds: 128 rows of 64.
pub(super) const BIN_TABLE: usize = 128 * 64;
/// Entries the escape-estimator table holds: 25 classes of 16.
pub(super) const ESC_TABLE: usize = 25 * 16;
/// The largest frequency a state of a multi-state context keeps.
const FREQ_LIMIT: u32 = 124;
/// The cap on a binary context's frequency.
const BIN_FREQ_CAP: u32 = 128;
/// The most units a state array can span: 256 states, two to a unit.
const UNITS_MAX: usize = 128;
/// Up to this many units, an escape's pick walks the unit sums rather than
/// halving them. Priced on an Apple M3 Mac by subtraction (22 Sep 2026):
/// the walk takes the solid-run vector from 1.018 of the tip's cycles back
/// to 0.992 and leaves the root's 128-unit search as it was.
const WALKED_UNITS: usize = 4;
/// The deepest chain [`Model::successors`] can build: one context per order,
/// plus the state it starts from.
const CHAIN_MAX: usize = 68;
/// A symbol no escape has excluded: every bit set, so that ANDing it onto
/// a frequency keeps the frequency.
const STILL_OPEN: u8 = 0xFF;

/// State 0 of a unit pair (see [`Arena::unit_pair`]).
#[inline(always)]
fn pair_low(w: u64) -> (u8, u32) {
    (w as u8, (w >> 8) as u32 & 0xFF)
}

/// State 1 of a unit pair.
#[inline(always)]
fn pair_high(w: u64) -> (u8, u32) {
    ((w >> 48) as u8, (w >> 56) as u32)
}

/// One escape estimator (spec I 3.5): a running sum, its shift and the
/// countdown to the next widening.
#[derive(Clone, Copy, Default)]
pub(super) struct EscEst {
    sum: u16,
    shift: u8,
    count: u8,
}

/// `P` as a model start leaves it (spec I 3.5 item 5):
/// `P[i][k + 8m] = 16,384 - floor(init_bin[k] / (i + 2))`.
static BIN_START: [u16; BIN_TABLE] = {
    let mut table = [0u16; BIN_TABLE];
    let mut at = 0;
    while at < BIN_TABLE {
        let (row, column) = (at / 64, at % 64);
        table[at] = (16_384 - INIT_BIN[column % 8] as u32 / (row as u32 + 2)) as u16;
        at += 1;
    }
    table
};

/// `Q` as a model start leaves it (spec I 3.5 item 6): class `i` holds
/// sixteen of `(sum = (5i + 10) * 8, shift = 3, count = 4)`.
static ESC_START: [EscEst; ESC_TABLE] = {
    let mut table = [EscEst {
        sum: 0,
        shift: 3,
        count: 4,
    }; ESC_TABLE];
    let mut at = 0;
    while at < ESC_TABLE {
        table[at].sum = (8 * (5 * (at / 16) + 10)) as u16;
        at += 1;
    }
    table
};

/// The PPMd variant H model as RAR 3 drives it.
pub(super) struct Model {
    pub(super) arena: Arena,
    max_order: u32,
    fall: i32,
    run: i32,
    run_init: i32,
    last_hit: u32,
    esc_init: u32,
    high_flag: usize,
    /// The state the last symbol was decoded from.
    found: u32,
    /// The context the next symbol is decoded in.
    cur: u32,
    /// The deepest context of the current position.
    top: u32,
    bin: Box<[u16]>,
    esc: Box<[EscEst]>,
    /// Which symbols the escapes of the symbol being decoded have not yet
    /// excluded: [`STILL_OPEN`] for one that may still be decoded, 0 for
    /// one excluded. An entry is ANDed onto its state's frequency, so an
    /// excluded state adds nothing to a sum and costs no branch. Only an
    /// escape reads it, and the first escape of a symbol sets it all open
    /// before excluding anything, so a symbol decoded without an escape
    /// never touches it (spec I 7.3 item 4).
    open: [u8; 256],
    /// Scratch for one escape step, and one successor chain. `unit_sums`
    /// holds, per unit of the context being decoded in, the frequency of
    /// the unmasked states up to and including that unit. Fixed arrays
    /// inside this struct, never heap: `step` allocates nothing (spec I
    /// 4.2, 7.3 item 3).
    unit_sums: [u32; UNITS_MAX],
    chain: [u32; CHAIN_MAX],
    /// How many times the model has been started, for the vectors'
    /// `model_starts` column.
    pub(super) starts: u64,
    /// The fault this model raised, if it has raised one: see
    /// [`Model::decode`]. Cleared by a model start.
    dead: Option<PpmFault>,
}

impl Model {
    pub(super) fn new() -> Model {
        Model {
            arena: Arena::new(),
            max_order: 0,
            fall: 0,
            run: 0,
            run_init: 0,
            last_hit: 0,
            esc_init: 0,
            high_flag: 0,
            found: 0,
            cur: 0,
            top: 0,
            bin: vec![0u16; BIN_TABLE].into_boxed_slice(),
            esc: vec![EscEst::default(); ESC_TABLE].into_boxed_slice(),
            open: [STILL_OPEN; 256],
            unit_sums: [0u32; UNITS_MAX],
            chain: [0; CHAIN_MAX],
            starts: 0,
            dead: None,
        }
    }

    /// Working memory this model holds on the heap: the arena, `P` and `Q`
    /// (spec I 4.2). The open flags, the unit sums and the chain are fixed
    /// arrays in this struct, which that accounting does not count.
    pub(super) fn held_bytes(&self) -> u64 {
        self.arena.held_bytes() + (BIN_TABLE * 2) as u64 + (ESC_TABLE * 4) as u64
    }

    /// Give the arena room for `size` bytes. Allocates only when the buffer
    /// held is too small.
    pub(super) fn reserve(&mut self, size: u32) {
        self.arena.reserve(size);
    }

    /// Start the model (spec I 3.5). In place: no allocation, no free, and
    /// no arena byte touched beyond the root.
    pub(super) fn start(&mut self, max_order: u32) {
        self.max_order = max_order;
        self.restart();
    }

    /// Spec I 3.5's start values. They are a set and read nothing of one
    /// another, so they are laid down outermost first: the two tables, the
    /// model's own counters, then the arena and the root in it.
    ///
    /// The tables' start values depend on nothing a stream says, so they
    /// are worked out when this crate is compiled and a model start copies
    /// them.
    ///
    /// THE ROOT'S SET-UP IS WRITTEN PLAINLY ON PURPOSE. A form of this
    /// routine that walked the root's symbols as an inclusive range of
    /// bytes and assigned the gap's two ends from locals decoded the same
    /// bytes and retired 1.4 percent more instructions over a 64 MB text
    /// member on x86-64 (counted 7 Oct 2026, a binary a variant); which of
    /// its expressions cost that was not established. This form counts
    /// level with the routine it replaced.
    fn restart(&mut self) {
        self.bin.copy_from_slice(&BIN_START);
        self.esc.copy_from_slice(&ESC_START);
        self.last_hit = 0;
        self.run_init = -(self.max_order.min(12) as i32) - 1;
        self.run = self.run_init;
        self.fall = self.max_order as i32;

        self.arena.restart();
        let array = self.arena.gap_lo;
        self.arena.gap_lo += 128 * UNIT;
        self.arena.gap_hi -= UNIT;
        let root = self.arena.gap_hi;
        for i in 0..256u32 {
            self.arena.write_state(array + i * STATE, i as u8, 1, 0);
        }
        self.arena.set_parent(root, 0);
        self.arena.set_array(root, array);
        self.arena.set_total(root, 257);
        self.arena.set_count(root, 256);
        self.top = root;
        self.cur = root;
        self.found = array;

        self.dead = None;
        self.starts += 1;
    }

    /// Decode one symbol and update the model (spec I 3.7 to 3.9).
    ///
    /// A MODEL THAT HAS FAULTED IS NOT DECODED FROM AGAIN. Spec I 3.10's
    /// invariants hold because the model is driven only by decoded
    /// symbols and every rule is total over them - but a fault can land
    /// half way through 3.9.2's update, and what it leaves is a model no
    /// symbol sequence could have built. A caller that carries on is not
    /// hypothetical: spec F reports the member and opens the next one,
    /// and a SOLID chain shares this model with it. The next decode then
    /// walks a link the invariant says cannot exist. A 1,387 byte fuzz
    /// input found exactly that within three seconds of the `ppm_member`
    /// target learning to continue past a fault, three hours after the
    /// range decoder's own version of this was fixed.
    ///
    /// So the fault is kept and re-raised. A START block header clears it
    /// (3.5 rebuilds the model wholesale), which is what a non solid
    /// member sends; a continuing block on a broken model is refused.
    /// Only this package's own faults poison: `Truncated` and the memory
    /// limit say nothing about the model's state.
    ///
    /// Spec I does not rule on this, and this is the conservative reading
    /// rather than an invented behaviour: the fault the member already
    /// raised is the fault it keeps raising. `fuzz/findings-20sep/` records
    /// the open question.
    pub(super) fn decode(
        &mut self,
        rc: &mut RangeDecoder,
        input: &mut impl StreamBytes,
    ) -> Result<u8> {
        if let Some(dead) = self.dead {
            return Err(fault(dead));
        }
        let out = self.decode_live(rc, input);
        if let Err(e) = &out {
            if let ErrorKind::Corrupt(Corruption::Ppmd(f)) = e.kind() {
                self.dead = Some(*f);
            }
        }
        out
    }

    fn decode_live(&mut self, rc: &mut RangeDecoder, input: &mut impl StreamBytes) -> Result<u8> {
        let hit = if self.arena.count(self.cur) >= 2 {
            self.path_multi(rc, input)?
        } else {
            self.path_binary(rc, input)?
        };
        match hit {
            Some(sym) => {
                self.next_context()?;
                Ok(sym)
            }
            None => {
                let sym = self.escape(rc, input)?;
                self.update()?;
                Ok(sym)
            }
        }
    }

    /// Path A (spec I 3.7): a context with two or more states.
    fn path_multi(
        &mut self,
        rc: &mut RangeDecoder,
        input: &mut impl StreamBytes,
    ) -> Result<Option<u8>> {
        let cur = self.cur;
        let total = self.arena.total(cur);
        let count = self.arena.count(cur);
        let array = self.arena.array(cur);
        let v = rc.count(total)?;

        let (first_sym, first) = self.arena.sym_freq(array);
        if v < first {
            rc.take(0, first, input)?;
            let sym = first_sym;
            self.found = array;
            self.last_hit = u32::from(2 * first > total);
            self.run = self.run.saturating_add(self.last_hit as i32);
            self.arena.set_total(cur, total + 4);
            self.arena.set_freq(array, first + 4);
            if first + 4 > FREQ_LIMIT {
                self.rescale()?;
            }
            return Ok(Some(sym));
        }

        self.last_hit = 0;
        let mut acc = first;
        // Two states share one unit, so one load serves both, and the
        // state's own position is only worked out when it is the hit.
        let mut unit = array;
        let mut pair = self.arena.unit_pair(array);
        let mut index = 1u32;
        while index < count {
            let (state_sym, f) = if index & 1 == 1 {
                pair_high(pair)
            } else {
                unit += UNIT;
                pair = self.arena.unit_pair(unit);
                pair_low(pair)
            };
            acc += f;
            if acc > v {
                rc.take(acc - f, f, input)?;
                let s = array + index * STATE;
                self.arena.set_freq(s, f + 4);
                self.arena.set_total(cur, self.arena.total(cur) + 4);
                self.found = s;
                if f + 4 > self.arena.freq(s - STATE) {
                    self.arena.swap_states(s, s - STATE);
                    self.found = s - STATE;
                    if f + 4 > FREQ_LIMIT {
                        self.rescale()?;
                    }
                }
                return Ok(Some(state_sym));
            }
            index += 1;
        }

        if v >= total {
            return Err(fault(PpmFault::RangeOutOfBounds));
        }
        self.high_flag = hb(self.arena.sym(self.found));
        rc.take(acc, total - acc, input)?;
        // The symbol's first escape: every symbol open, but for this
        // context's own.
        self.open = [STILL_OPEN; 256];
        let mut s = array;
        let mut seen = 0u32;
        while seen + 2 <= count {
            let w = self.arena.unit_pair(s);
            self.open[w as u8 as usize] = 0;
            self.open[(w >> 48) as u8 as usize] = 0;
            s += UNIT;
            seen += 2;
        }
        if seen < count {
            self.open[self.arena.sym(s) as usize] = 0;
        }
        Ok(None)
    }

    /// Path B (spec I 3.7): a context holding one state.
    fn path_binary(
        &mut self,
        rc: &mut RangeDecoder,
        input: &mut impl StreamBytes,
    ) -> Result<Option<u8>> {
        let cur = self.cur;
        let state = Arena::only_state(cur);
        let parent = self.arena.parent(cur);
        if parent == 0 {
            return Err(fault(PpmFault::Inconsistent));
        }
        self.high_flag = hb(self.arena.sym(self.found));
        let freq = self.arena.freq(state);
        if freq == 0 || freq > BIN_FREQ_CAP {
            return Err(fault(PpmFault::Inconsistent));
        }
        let parent_count = self.arena.count(parent);
        if parent_count == 0 || parent_count > 256 {
            return Err(fault(PpmFault::Inconsistent));
        }
        let column = self.last_hit as usize
            + BIN_CLASS[parent_count as usize - 1] as usize
            + self.high_flag
            + 2 * hb(self.arena.sym(state))
            + if self.run < 0 { 32 } else { 0 };
        let at = (freq as usize - 1) * 64 + column;
        let p = u32::from(self.bin[at]);
        let step = (p + 32) / 128;
        if rc.bit(p, input)? {
            let updated = p - step;
            self.bin[at] = updated as u16;
            self.esc_init = u32::from(ESC_AFTER_BINARY[(updated >> 10) as usize]);
            // The symbol's first escape: every symbol open but this one.
            let sym = self.arena.sym(state);
            self.open = [STILL_OPEN; 256];
            self.open[sym as usize] = 0;
            self.last_hit = 0;
            Ok(None)
        } else {
            self.bin[at] = (p + 128 - step) as u16;
            self.found = state;
            if freq < BIN_FREQ_CAP {
                self.arena.set_freq(state, freq + 1);
            }
            self.last_hit = 1;
            self.run = self.run.saturating_add(1);
            Ok(Some(self.arena.sym(state)))
        }
    }

    /// The escape loop (spec I 3.7): climb to a context with symbols this
    /// decode has not excluded, and decode there.
    fn escape(&mut self, rc: &mut RangeDecoder, input: &mut impl StreamBytes) -> Result<u8> {
        loop {
            let masked = self.arena.count(self.cur);
            loop {
                self.fall = self.fall.saturating_add(1);
                let parent = self.arena.parent(self.cur);
                if parent == 0 {
                    return Err(fault(PpmFault::RootEscape));
                }
                self.cur = parent;
                if self.arena.count(self.cur) != masked {
                    break;
                }
            }
            let cur = self.cur;
            let count = self.arena.count(cur);
            let array = self.arena.array(cur);
            if !(2..=256).contains(&count) {
                return Err(fault(PpmFault::Inconsistent));
            }

            // Sum the unmasked frequencies, keeping the sum after each
            // UNIT rather than after each state: a unit holds two states
            // and one load reads both symbols and both frequencies. The
            // symbol is picked below by a binary search over these unit
            // sums and then settled inside its unit, which finds exactly
            // spec I 3.7's "first state whose running sum exceeds v": a
            // unit whose sum exceeds v holds that state, and the unit
            // before it does not. On the binary vector nearly every symbol
            // is decoded this way in the root's 128 units, where a
            // per-state list and a linear search over it were most of the
            // symbol's instructions.
            let pairs = (count / 2) as usize;
            let mut hi = 0u32;
            let mut open = 0u32;
            {
                let bytes = self.arena.unit_bytes(array, pairs);
                let open_of = &self.open;
                let units = bytes
                    .as_chunks::<{ UNIT as usize }>()
                    .0
                    .iter()
                    .zip(self.unit_sums.iter_mut());
                if count == 256 {
                    // The root has no estimator, so it needs no count of
                    // the unmasked states: only their sum.
                    for (unit, sum) in units {
                        let w = u64::from_le_bytes(unit[..8].try_into().unwrap());
                        let (sym, freq) = pair_low(w);
                        let low = freq & u32::from(open_of[sym as usize]);
                        let (sym, freq) = pair_high(w);
                        let high = freq & u32::from(open_of[sym as usize]);
                        hi += low + high;
                        *sum = hi;
                    }
                    open = u32::from(hi != 0);
                } else {
                    for (unit, sum) in units {
                        let w = u64::from_le_bytes(unit[..8].try_into().unwrap());
                        let (sym, freq) = pair_low(w);
                        let low = u32::from(open_of[sym as usize]);
                        let (sym, freq_high) = pair_high(w);
                        let high = u32::from(open_of[sym as usize]);
                        hi += (freq & low) + (freq_high & high);
                        open += (low & 1) + (high & 1);
                        *sum = hi;
                    }
                }
            }
            if count & 1 == 1 {
                let (sym, freq) = self.arena.sym_freq(array + pairs as u32 * UNIT);
                let last = u32::from(self.open[sym as usize]);
                hi += freq & last;
                open += last & 1;
                self.unit_sums[pairs] = hi;
            }
            if open == 0 {
                return Err(fault(PpmFault::Inconsistent));
            }

            let mut est = usize::MAX;
            let extra = if count == 256 {
                1
            } else {
                let parent = self.arena.parent(cur);
                if parent == 0 {
                    return Err(fault(PpmFault::Inconsistent));
                }
                let j = usize::from(open < self.arena.count(parent).saturating_sub(count))
                    + 2 * usize::from(self.arena.total(cur) < 11 * count)
                    + 4 * usize::from(masked > open)
                    + self.high_flag;
                est = ESC_CLASS[open as usize - 1] as usize * 16 + j;
                let e = &mut self.esc[est];
                let r = u32::from(e.sum) >> e.shift;
                e.sum -= r as u16;
                r.max(1)
            };

            let v = rc.count(hi + extra)?;
            if v < hi {
                // The first unit whose sum exceeds `v`: the sums never
                // fall, and the last is `hi`, which does exceed it. A
                // context of a few units is walked, which its branch
                // predicts; a larger one is halved without a branch.
                let units = count.div_ceil(2) as usize;
                let unit = if units <= WALKED_UNITS {
                    let mut unit = 0usize;
                    while unit < units && self.unit_sums[unit] <= v {
                        unit += 1;
                    }
                    unit
                } else {
                    let mut base = 0usize;
                    let mut size = units;
                    while size > 1 {
                        let half = size / 2;
                        let mid = base + half;
                        base = if self.unit_sums[mid] <= v { mid } else { base };
                        size -= half;
                    }
                    base + usize::from(self.unit_sums[base] <= v)
                };
                if unit >= units {
                    return Err(fault(PpmFault::Inconsistent));
                }
                // Inside the unit: its first state if that one is open and
                // already carries the sum past `v`, else its second, which
                // must then be open, since the unit's sum does exceed `v`.
                let before = if unit == 0 {
                    0
                } else {
                    self.unit_sums[unit - 1]
                };
                let first = array + unit as u32 * UNIT;
                let (sym, freq) = self.arena.sym_freq(first);
                let through_first = before + freq;
                let is_first = (self.open[sym as usize] != 0) & (through_first > v);
                let pick = if is_first { first } else { first + STATE };
                let acc = if is_first {
                    through_first
                } else {
                    self.unit_sums[unit]
                };
                let f = self.arena.freq(pick);
                rc.take(acc - f, f, input)?;
                if est != usize::MAX {
                    let e = &mut self.esc[est];
                    if e.shift < 7 {
                        e.count = e.count.saturating_sub(1);
                        if e.count == 0 {
                            e.sum = e.sum.wrapping_mul(2);
                            e.count = 3 << e.shift;
                            e.shift += 1;
                        }
                    }
                }
                let sym = self.arena.sym(pick);
                self.found = pick;
                self.arena.set_freq(pick, f + 4);
                self.arena.set_total(cur, self.arena.total(cur) + 4);
                if f + 4 > FREQ_LIMIT {
                    self.rescale()?;
                }
                self.run = self.run_init;
                return Ok(sym);
            }
            if v >= hi + extra {
                return Err(fault(PpmFault::RangeOutOfBounds));
            }
            rc.take(hi, extra, input)?;
            if est != usize::MAX {
                let e = &mut self.esc[est];
                e.sum = e.sum.wrapping_add((hi + extra) as u16);
            }
            // Every symbol of this context is now excluded. Those excluded
            // already are simply excluded again.
            let mut s = array;
            for _ in 0..count {
                self.open[self.arena.sym(s) as usize] = 0;
                s += STATE;
            }
        }
    }

    /// Spec I 3.9.1: follow the found state's successor, or grow the model.
    fn next_context(&mut self) -> Result<()> {
        let succ = self.arena.succ(self.found);
        if self.fall == 0 && succ > self.arena.text_top {
            if !self.arena.is_context(succ) {
                return Err(fault(PpmFault::Inconsistent));
            }
            self.cur = succ;
            self.top = succ;
            Ok(())
        } else {
            self.update()
        }
    }

    /// Spec I 3.9.2: update the model after a symbol.
    fn update(&mut self) -> Result<()> {
        let fs = self.found;
        let sym = self.arena.sym(fs);
        let fq = self.arena.freq(fs);
        let mut nx = self.arena.succ(fs);
        let cur = self.cur;

        // 1. Reinforce the symbol in the parent.
        let parent = self.arena.parent(cur);
        if fq < 31 && parent != 0 {
            if self.arena.count(parent) == 1 {
                let s = Arena::only_state(parent);
                let f = self.arena.freq(s);
                if f < 32 {
                    self.arena.set_freq(s, f + 1);
                }
            } else {
                let mut s = self.find_state(parent, sym)?;
                let array = self.arena.array(parent);
                if s != array && self.arena.freq(s) >= self.arena.freq(s - STATE) {
                    self.arena.swap_states(s, s - STATE);
                    s -= STATE;
                }
                let f = self.arena.freq(s);
                if f < 115 {
                    self.arena.set_freq(s, f + 2);
                    let t = self.arena.total(parent);
                    self.arena.set_total(parent, t + 2);
                }
            }
        }

        // 2. At full order there is nothing to append.
        if self.fall == 0 {
            match self.successors(true)? {
                Some(c) => {
                    self.cur = c;
                    self.top = c;
                    self.arena.set_succ(fs, c);
                    return Ok(());
                }
                None => {
                    self.restart();
                    return Ok(());
                }
            }
        }

        // 3. Append the symbol to the text region.
        let mut succ = self.arena.push_text(sym);
        if self.arena.text_top >= self.arena.units_floor {
            self.restart();
            return Ok(());
        }

        // 4. Resolve the found state's successor.
        if nx != 0 {
            if nx <= succ {
                match self.successors(false)? {
                    Some(c) => nx = c,
                    None => {
                        self.restart();
                        return Ok(());
                    }
                }
            }
            self.fall -= 1;
            if self.fall == 0 {
                succ = nx;
                if self.top != cur {
                    self.arena.text_top -= 1;
                }
            }
        } else {
            self.arena.set_succ(fs, succ);
            nx = cur;
        }

        // 5, 6. Add the symbol to every context from `top` below `cur`.
        let ns = self.arena.count(cur);
        let s0 = i64::from(self.arena.total(cur)) - i64::from(ns) - (i64::from(fq) - 1);
        let mut c = self.top;
        let mut guard = 0u32;
        while c != cur {
            guard += 1;
            if guard > self.max_order + 2 || c == 0 {
                return Err(fault(PpmFault::Inconsistent));
            }
            let k = self.arena.count(c);
            if k >= 256 {
                return Err(fault(PpmFault::Inconsistent));
            }
            if k >= 2 {
                if k.is_multiple_of(2) {
                    let array = self.arena.array(c);
                    match self.arena.grow(array, k / 2) {
                        Some(moved) => self.arena.set_array(c, moved),
                        None => {
                            self.restart();
                            return Ok(());
                        }
                    }
                }
                let t = self.arena.total(c);
                let add = u32::from(2 * k < ns) + 2 * u32::from(4 * k <= ns && t <= 8 * k);
                self.arena.set_total(c, t + add);
            } else {
                let array = match self.arena.take(0) {
                    Some(a) => a,
                    None => {
                        self.restart();
                        return Ok(());
                    }
                };
                self.arena.move_state(Arena::only_state(c), array);
                self.arena.set_array(c, array);
                let f = self.arena.freq(array);
                let widened = if f < 30 { 2 * f } else { 120 };
                self.arena.set_freq(array, widened);
                self.arena
                    .set_total(c, widened + self.esc_init + u32::from(ns > 3));
            }

            let t = i64::from(self.arena.total(c));
            let weight = 2 * i64::from(fq) * (t + 6);
            let scale = s0 + t;
            let (freq, added) = if weight < 6 * scale {
                (
                    1 + i64::from(weight > scale) + i64::from(weight >= 4 * scale),
                    3,
                )
            } else {
                let f = 4
                    + i64::from(weight >= 9 * scale)
                    + i64::from(weight >= 12 * scale)
                    + i64::from(weight >= 15 * scale);
                (f, f)
            };
            if t + added > 65_535 {
                return Err(fault(PpmFault::Inconsistent));
            }
            self.arena.set_total(c, (t + added) as u32);
            let array = self.arena.array(c);
            self.arena
                .write_state(array + k * STATE, sym, freq as u32, succ);
            self.arena.set_count(c, k + 1);
            c = self.arena.parent(c);
        }

        self.cur = nx;
        self.top = nx;
        Ok(())
    }

    /// Spec I 3.9.3: build the chain of contexts the text that follows
    /// needs. `None` means the arena is exhausted.
    fn successors(&mut self, skip: bool) -> Result<Option<u32>> {
        let up = self.arena.succ(self.found);
        // `up` may equal `text_top`: spec I 3.9.2 step 4 rolls the text
        // region back over the symbol it just appended, which leaves that
        // byte written and the cursor on it.
        if up == 0 || up < BASE || up > self.arena.text_top {
            return Err(fault(PpmFault::Inconsistent));
        }
        let sym = self.arena.sym(self.found);
        let mut chain = 0usize;
        if !skip {
            self.chain[0] = self.found;
            chain = 1;
        }
        let mut c = self.cur;
        loop {
            let parent = self.arena.parent(c);
            if parent == 0 {
                break;
            }
            c = parent;
            let s = if self.arena.count(c) == 1 {
                Arena::only_state(c)
            } else {
                self.find_state(c, sym)?
            };
            let next = self.arena.succ(s);
            if next != up {
                // Spec I 3.9.3 step 2 reads this successor as a context.
                if !self.arena.is_context(next) {
                    return Err(fault(PpmFault::Inconsistent));
                }
                c = next;
                if chain == 0 {
                    return Ok(Some(c));
                }
                break;
            }
            if chain >= CHAIN_MAX {
                return Err(fault(PpmFault::Inconsistent));
            }
            self.chain[chain] = s;
            chain += 1;
        }

        let sym_up = self.arena.u8at(up);
        let succ_up = up + 1;
        let freq = if self.arena.count(c) == 1 {
            self.arena.freq(Arena::only_state(c))
        } else {
            let s = self.find_state(c, sym_up)?;
            let cf = i64::from(self.arena.freq(s)) - 1;
            let s0 = i64::from(self.arena.total(c)) - i64::from(self.arena.count(c)) - cf;
            if s0 <= 0 {
                return Err(fault(PpmFault::Inconsistent));
            }
            if 2 * cf <= s0 {
                1 + u32::from(5 * cf > s0)
            } else {
                (1 + (2 * cf + 3 * s0 - 1) / (2 * s0)) as u32
            }
        };
        if freq == 0 || freq > BIN_FREQ_CAP {
            return Err(fault(PpmFault::Inconsistent));
        }

        for i in (0..chain).rev() {
            let Some(made) = self.arena.take_context() else {
                return Ok(None);
            };
            self.arena.set_count(made, 1);
            self.arena
                .write_state(Arena::only_state(made), sym_up, freq, succ_up);
            self.arena.set_parent(made, c);
            self.arena.set_succ(self.chain[i], made);
            c = made;
        }
        Ok(Some(c))
    }

    /// The state of `c` (which has two or more) whose symbol is `sym`.
    /// Every symbol of a context appears in its parent (spec I 3.10), so
    /// the miss is unreachable.
    #[inline(always)]
    fn find_state(&self, c: u32, sym: u8) -> Result<u32> {
        let count = self.arena.count(c);
        let mut s = self.arena.array(c);
        let mut seen = 0u32;
        while seen + 2 <= count {
            let w = self.arena.unit_pair(s);
            if w as u8 == sym {
                return Ok(s);
            }
            if (w >> 48) as u8 == sym {
                return Ok(s + STATE);
            }
            s += UNIT;
            seen += 2;
        }
        if seen < count && self.arena.sym(s) == sym {
            return Ok(s);
        }
        Err(fault(PpmFault::Inconsistent))
    }

    /// Spec I 3.8: halve a context's frequencies when one passes the limit.
    #[cold]
    fn rescale(&mut self) -> Result<()> {
        let cur = self.cur;
        let count = self.arena.count(cur);
        let array = self.arena.array(cur);
        if !(2..=256).contains(&count)
            || self.found < array
            || self.found >= array + count * STATE
            || !(self.found - array).is_multiple_of(STATE)
        {
            return Err(fault(PpmFault::Inconsistent));
        }

        // 1. The found state to the front, the rest shifted up one place.
        let mut p = self.found;
        while p != array {
            self.arena.swap_states(p, p - STATE);
            p -= STATE;
        }

        // 2, 3. Halve, keeping the states in non-increasing frequency order.
        let mut escapes = i64::from(self.arena.total(cur)) - i64::from(self.arena.freq(array));
        let adder = u32::from(self.fall != 0);
        let first = (self.arena.freq(array) + 4 + adder) / 2;
        self.arena.set_freq(array, first);
        let mut sum = first;
        for j in 1..count {
            let s = array + j * STATE;
            let was = self.arena.freq(s);
            escapes -= i64::from(was);
            let f = (was + adder) / 2;
            self.arena.set_freq(s, f);
            sum += f;
            if f > self.arena.freq(s - STATE) {
                let mut q = s;
                while q > array && self.arena.freq(q - STATE) < f {
                    self.arena.swap_states(q, q - STATE);
                    q -= STATE;
                }
            }
        }
        if escapes < 0 {
            return Err(fault(PpmFault::Inconsistent));
        }

        // 4. Drop the states that reached frequency 0.
        if self.arena.freq(array + (count - 1) * STATE) == 0 {
            let mut zeros = 0u32;
            while zeros < count && self.arena.freq(array + (count - 1 - zeros) * STATE) == 0 {
                zeros += 1;
            }
            escapes += i64::from(zeros);
            let left = count - zeros;
            let was_units = count.div_ceil(2);
            if left == 1 {
                let mut f = self.arena.freq(array);
                loop {
                    f -= f / 2;
                    escapes /= 2;
                    if escapes <= 1 {
                        break;
                    }
                }
                let sym = self.arena.sym(array);
                let succ = self.arena.succ(array);
                self.arena
                    .give(array, CLASS_OF[was_units as usize] as usize);
                self.arena.set_count(cur, 1);
                let state = Arena::only_state(cur);
                self.arena.write_state(state, sym, f, succ);
                self.found = state;
                return Ok(());
            }
            let now_units = left.div_ceil(2);
            if was_units != now_units {
                let moved = self.arena.shrink(array, was_units, now_units);
                self.arena.set_array(cur, moved);
            }
            self.arena.set_count(cur, left);
        }

        // 5.
        let total = i64::from(sum) + escapes - escapes / 2;
        if total > 65_535 {
            return Err(fault(PpmFault::Inconsistent));
        }
        self.arena.set_total(cur, total as u32);
        self.found = self.arena.array(cur);
        Ok(())
    }
}
