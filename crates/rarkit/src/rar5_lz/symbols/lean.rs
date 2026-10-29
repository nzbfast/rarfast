//! THE LEAN LANE BUILD:
//! [`Symbols::build_lean`], the same symbols as [`Symbols::build`] in fewer
//! instructions an operation, and the knob that chooses between them.
//!
//! **A module of its own, on purpose.** Its code in `symbols.rs` itself moved
//! how the SHIPPED WALK (`tape::apply::<Vec<u8>>`, `<NullSink>`) and the
//! serial loop (`decode_block`) compiled with the knob off, read in the
//! linked binary against the control's own (the lane
//! build measurement): `symbols::apply` calls `tape::apply` for a block's
//! prefix, so what shares that file shares those instances' code unit.
//! Implemented from `specs/SPEC-H2-rarkit-rar5-lz.md` and this repository's
//! own measurements alone.

use super::{Slot, Symbols, AT_SPLIT, MAX_GATHER, MIN_GATHER};
use crate::rar5_lz::output::{Window, STRIDE, STRIDE_MAX};
use crate::rar5_lz::tape::{tape_kind, BlockTape};

/// Which lane build runs when no harness has said otherwise: the LEAN form
/// ([`Symbols::build_lean`]) or the first one ([`Symbols::build`]). True
/// on its priced figure (the lane build measurement):
/// the timed measurement on an Apple M3 Mac decides whether it stays true.
pub(crate) const SHIPPED_LEAN: bool = true;

/// The lean form's dial and environment, in atomics: 0 means defer (the
/// dial) or not yet read (the environment), 1 the first form, 2 the lean
/// form, 3 (the environment only) not set.
#[cfg(feature = "test-support")]
static FORM_DIAL: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
#[cfg(feature = "test-support")]
static FORM_ENV: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Force the lean lane build on or off for every thread's next decodes, or
/// defer to the environment and then [`SHIPPED_LEAN`] with `None`. Process
/// wide: both forms make the same bytes, so a test that sets it cannot
/// change another test's answer, only which form made it.
#[cfg(feature = "test-support")]
#[allow(dead_code)]
pub(crate) fn set_form_dial(lean: Option<bool>) {
    let v = match lean {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    };
    FORM_DIAL.store(v, std::sync::atomic::Ordering::Relaxed);
}

/// Whether this thread's decode builds its symbols in the lean form. Read
/// once per chunk on the calling thread and handed to the lanes, as
/// [`super::enabled`] is. With `test-support` the knob
/// `RARKIT_SYMBOL_LANE_FORM` (`lean` or `1` for the lean form, anything
/// else the first, read once a process into an atomic) or the dial
/// ([`set_form_dial`]) overrides [`SHIPPED_LEAN`]; without it the answer is
/// the constant and the other form is compiled out.
pub(crate) fn lean_form() -> bool {
    #[cfg(feature = "test-support")]
    {
        use std::sync::atomic::Ordering;
        match FORM_DIAL.load(Ordering::Relaxed) {
            1 => return false,
            2 => return true,
            _ => {}
        }
        let mut env = FORM_ENV.load(Ordering::Relaxed);
        if env == 0 {
            // Read once: 1 the first form, 2 the lean, 3 not set. Two
            // threads racing here read the same environment and store the
            // same value; only the one that stores it first says so.
            let read = match std::env::var("RARKIT_SYMBOL_LANE_FORM") {
                Ok(v) if matches!(v.trim(), "lean" | "1") => 2,
                Ok(_) => 1,
                Err(_) => 3,
            };
            if FORM_ENV
                .compare_exchange(0, read, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
                && read != 3
            {
                eprintln!(
                    "rarkit symbol lane form: {}",
                    if read == 2 { "lean" } else { "first" }
                );
            }
            env = read;
        }
        match env {
            1 => false,
            2 => true,
            _ => SHIPPED_LEAN,
        }
    }
    #[cfg(not(feature = "test-support"))]
    SHIPPED_LEAN
}

impl Symbols {
    /// [`Symbols::build`]'s LEAN FORM:
    /// the same symbols, the
    /// same split, the same state after the block and the same refusals,
    /// field for field (`tests.rs`, the lane form differential), in fewer
    /// instructions an operation.
    ///
    /// **Why.** Counted on an Apple M3 Mac (the lane
    /// build measurement): the first form retires about 93 instructions an
    /// operation at 4.5 a cycle, so it is instruction bound, and read from
    /// the linked binary about 12 of a common copy's 86 do the copy. The
    /// rest is overhead this form removes:
    ///
    /// - the four repeat slots are four scalars, not an array a variable
    ///   index pins to the stack, so a repeat rotates them in registers
    ///   rather than by a `memmove` call;
    /// - each operation's end is written by INDEX into a buffer sized once
    ///   a block, not pushed through `self` (a length load and store an
    ///   operation), and moved down past the split in the rare block that
    ///   has one;
    /// - a literal run of at most four bytes, most of them, writes four
    ///   symbols rather than a stride of sixteen;
    /// - the copy is inlined (the first form's inliner did so; this body's
    ///   budget did not, and a call a copy cost more than the copy).
    pub(crate) fn build_lean(&mut self, tape: &BlockTape, declared: usize) {
        self.ready = false;
        self.len = 0;
        let ops = &tape.steps[..];
        let n = ops.len();
        if n == 0 {
            self.ends.clear();
            return;
        }
        // THE BOUND, before the walk: every byte a suffix can produce, so the
        // symbol buffer is sized once and the walk runs over a plain slice
        // with no growth check and no call in it (a call inside the loop
        // kept every live value on the stack). A repeat of the last length
        // before the block sets one restarts and adds nothing to a suffix;
        // restarts only ever shrink what the suffix holds.
        let mut bound = 0usize;
        let mut last = 0usize;
        // Selects, not a match: the kind is unpredictable, and a branch on
        // it here would mispredict as often as the walk's own dispatch. A
        // literal run or a copy adds its length, a repeat of the last length
        // the last one set, a filter record (length zero) nothing.
        for op in ops {
            let length = op.length();
            let kind = op.kind();
            bound += op.prefix();
            bound += if kind == tape_kind::REP_LAST {
                last
            } else {
                length
            };
            last = if kind == tape_kind::MATCH || kind == tape_kind::REP {
                length
            } else {
                last
            };
        }
        if bound > MAX_GATHER {
            // The first form refuses such a block or not operation by
            // operation; it answers exactly, and it is rare.
            self.build(tape, declared);
            return;
        }
        // Grown only: the fill is the difference from the last block's size.
        if self.ends.len() < n {
            self.ends.resize(n, 0);
        }
        if self.symbols.len() < bound + STRIDE {
            self.symbols.resize(bound + STRIDE, 0);
        }
        let ends = &mut self.ends[..n];
        let all_literals = &tape.verbatim[..];
        let buf = &mut self.symbols[..bound + STRIDE];
        let mut split = 0usize;
        let (mut s0, mut s1, mut s2, mut s3): (Slot, Slot, Slot, Slot) =
            (AT_SPLIT, AT_SPLIT | 1, AT_SPLIT | 2, AT_SPLIT | 3);
        let mut last_slot: Slot = AT_SPLIT;
        let mut literals = 0usize;
        let mut reach = 0usize;
        let mut longest = 0usize;
        let mut p = 0usize;
        let mut refused = false;
        // The first form's `restart`, on the scalars: what the block has set
        // is now known, and a slot it has not set is the live state's at the
        // new split, in its own position.
        macro_rules! restart {
            ($i:expr) => {{
                split = $i + 1;
                if s0 & AT_SPLIT != 0 {
                    s0 = AT_SPLIT;
                }
                if s1 & AT_SPLIT != 0 {
                    s1 = AT_SPLIT | 1;
                }
                if s2 & AT_SPLIT != 0 {
                    s2 = AT_SPLIT | 2;
                }
                if s3 & AT_SPLIT != 0 {
                    s3 = AT_SPLIT | 3;
                }
                if last_slot & AT_SPLIT != 0 {
                    last_slot = AT_SPLIT;
                }
                p = 0;
                reach = 0;
                longest = 0;
            }};
        }
        for i in 0..n {
            let op = ops[i];
            let length = op.length();
            let kind = op.kind();
            // THE PREFIX, the literal run before the operation (the whole
            // of a `LITS`), empty or not: most runs are a byte or two (1.65
            // on md128k), four symbols for those, a stride at a time for
            // the rest. Four written for an empty one land where the
            // operation's own copy writes next, inside the bound's stride.
            let prefix = op.prefix();
            let from = literals;
            literals += prefix;
            longest = longest.max(prefix);
            if prefix <= 4 {
                for j in 0..4 {
                    buf[p + j] = Window::SYMBOL_LITERAL | u32::from(all_literals[from + j]);
                }
            } else {
                let mut k = 0usize;
                while k < prefix {
                    widen(
                        (&mut buf[p + k..p + k + STRIDE])
                            .try_into()
                            .expect("a stride of symbols"),
                        all_literals[from + k..from + k + STRIDE]
                            .try_into()
                            .expect("a stride of literals"),
                    );
                    k += STRIDE;
                }
            }
            p += prefix;
            let (distance, length) = if kind == tape_kind::LITS {
                ends[i] = p as u32;
                continue;
            } else if kind == tape_kind::MATCH {
                let distance = op.distance as usize;
                s3 = s2;
                s2 = s1;
                s1 = s0;
                s0 = distance;
                last_slot = length;
                (distance, length)
            } else if kind == tape_kind::REP {
                let k = op.distance as usize & 3;
                let chosen = match k {
                    0 => s0,
                    1 => {
                        let c = s1;
                        s1 = s0;
                        c
                    }
                    2 => {
                        let c = s2;
                        s2 = s1;
                        s1 = s0;
                        c
                    }
                    _ => {
                        let c = s3;
                        s3 = s2;
                        s2 = s1;
                        s1 = s0;
                        c
                    }
                };
                s0 = chosen;
                last_slot = length;
                if chosen & AT_SPLIT != 0 {
                    restart!(i);
                    continue;
                }
                (chosen, length)
            } else if kind == tape_kind::REP_LAST {
                if last_slot & AT_SPLIT != 0 || s0 & AT_SPLIT != 0 {
                    restart!(i);
                    continue;
                }
                let length = last_slot;
                if length == 0 {
                    ends[i] = p as u32;
                    continue;
                }
                (s0, length)
            } else {
                restart!(i);
                continue;
            };
            // The walk raises on these; so the whole block goes to it.
            if distance == 0 || distance > declared || distance >= AT_SPLIT {
                refused = true;
                break;
            }
            p = copy_lean(buf, p, distance, length, &mut reach);
            ends[i] = p as u32;
        }
        if refused || split >= n || p < MIN_GATHER {
            return;
        }
        // The ends of the suffix's operations, and only those.
        // Moved down past a split (rare) by a plain loop: no slice range
        // helper, which the shipped walk and the serial loop share.
        if split > 0 {
            for k in 0..n - split {
                self.ends[k] = self.ends[k + split];
            }
        }
        self.ends.truncate(n - split);
        self.finish_prefix(tape, split, p, reach, longest, [s0, s1, s2, s3], last_slot);
    }

    /// The lean form's tail, the first form's own lines: the prefix as a
    /// tape of its own for the shipped walk, and the rest of the block's
    /// bookkeeping.
    #[allow(clippy::too_many_arguments)]
    fn finish_prefix(
        &mut self,
        tape: &BlockTape,
        split: usize,
        p: usize,
        reach: usize,
        longest: usize,
        slots: [Slot; 4],
        last_slot: Slot,
    ) {
        let ops = &tape.steps[..];
        let mut prefix_literals = 0usize;
        let mut prefix_known = 0usize;
        let mut prefix_carried = 0usize;
        let mut last_p: Option<usize> = None;
        for op in &ops[..split] {
            let length = op.length();
            prefix_literals += op.prefix();
            prefix_known += op.prefix();
            match op.kind() {
                tape_kind::LITS => {}
                tape_kind::MATCH | tape_kind::REP => {
                    prefix_known += length;
                    last_p = Some(length);
                }
                tape_kind::REP_LAST => match last_p {
                    Some(l) => prefix_known += l,
                    None => prefix_carried += 1,
                },
                _ => {}
            }
        }
        let prefix = &mut self.prefix;
        prefix.steps.clear();
        prefix.steps.extend_from_slice(&ops[..split]);
        prefix.verbatim.clear();
        prefix
            .verbatim
            .extend_from_slice(&tape.verbatim[..prefix_literals]);
        prefix.verbatim.resize(prefix_literals + STRIDE_MAX, 0);
        prefix.records.clear();
        prefix.records.extend_from_slice(&tape.records);
        prefix.parked_at = None;
        prefix.failure = None;
        self.prefix_known = prefix_known;
        self.prefix_carried = prefix_carried;
        self.len = p;
        self.reach = reach;
        self.longest_literal = longest;
        self.slots = slots;
        self.last = last_slot;
        self.ready = true;
    }
}

/// A stride of literals as literal symbols. A function of its own so the
/// two arrays arrive as arguments, which the compiler knows do not
/// overlap, and it widens them as vectors rather than a byte at a time.
#[inline(always)]
fn widen(out: &mut [u32; STRIDE], bytes: &[u8; STRIDE]) {
    for (slot, &byte) in out.iter_mut().zip(bytes) {
        *slot = Window::SYMBOL_LITERAL | u32::from(byte);
    }
}

/// [`copy`] for the lean form, the same symbols with NO CALL in any path:
/// a long copy at least a stride back moves whole strides (spilling past
/// its end as the common form does), and a near copy, whose source overlaps
/// what it writes, moves a symbol at a time. A variable length copy lowers
/// to a `memmove` call, and one call anywhere in the build's loop kept the
/// loop's values on the stack for every operation (read in the linked
/// binary).
#[inline(always)]
fn copy_lean(
    buf: &mut [u32],
    p: usize,
    distance: usize,
    length: usize,
    reach: &mut usize,
) -> usize {
    const STRIDE_SYMBOLS: usize = 16;
    let end = p + length;
    let back = distance.saturating_sub(p);
    let holes = length.min(back);
    *reach = (*reach).max(back);
    if length <= STRIDE_SYMBOLS && distance >= STRIDE_SYMBOLS {
        let first = back as u32;
        let names: &mut [u32; STRIDE_SYMBOLS] = (&mut buf[p..p + STRIDE_SYMBOLS])
            .try_into()
            .expect("a stride of symbols");
        for (j, slot) in names.iter_mut().enumerate() {
            *slot = first.wrapping_sub(j as u32);
        }
        let q = p + holes;
        let src = q.saturating_sub(distance);
        let stride: [u32; STRIDE_SYMBOLS] = buf[src..src + STRIDE_SYMBOLS]
            .try_into()
            .expect("a stride of symbols");
        buf[q..q + STRIDE_SYMBOLS].copy_from_slice(&stride);
        return end;
    }
    if holes > 0 {
        let first = back as u32;
        let mut k = 0usize;
        while k < holes {
            let out: &mut [u32; STRIDE_SYMBOLS] = (&mut buf[p + k..p + k + STRIDE_SYMBOLS])
                .try_into()
                .expect("a stride of symbols");
            for (j, slot) in out.iter_mut().enumerate() {
                *slot = first.wrapping_sub((k + j) as u32);
            }
            k += STRIDE_SYMBOLS;
        }
    }
    let mut q = p + holes;
    if distance >= STRIDE_SYMBOLS {
        // Each stride reads symbols at least a stride behind it, all
        // written already, and writes past `end` onto symbols not yet
        // written, which the buffer's stride of slack holds.
        while q < end {
            let src = q - distance;
            let stride: [u32; STRIDE_SYMBOLS] = buf[src..src + STRIDE_SYMBOLS]
                .try_into()
                .expect("a stride of symbols");
            buf[q..q + STRIDE_SYMBOLS].copy_from_slice(&stride);
            q += STRIDE_SYMBOLS;
        }
    } else {
        while q < end {
            buf[q] = buf[q - distance];
            q += 1;
        }
    }
    end
}
