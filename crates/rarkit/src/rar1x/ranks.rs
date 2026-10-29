//! The adaptive rank table of spec A 4.1.
//!
//! 256 slots, each a symbol and a weight. Section 4.1 notes that the
//! weights never increase from one slot to the next, so the slots of one
//! weight are a run, and "the lowest-numbered slot whose weight is w" is
//! the number of slots whose weight is over w. That count is kept per
//! weight, which makes a promotion a fixed amount of work: three loads
//! and three stores, a slot's symbol and weight being one word.

/// A rank table whose weights stop at `CEILING`.
pub(super) struct Ranks<const CEILING: u16> {
    /// Each slot: its symbol in the low byte, its weight above it.
    slot: [u16; 256],
    /// `heavier[w]`: how many slots hold a weight over `w`.
    heavier: [u16; 256],
}

impl<const CEILING: u16> Ranks<CEILING> {
    /// A table whose slot `i` holds `symbol(i)` with weight 0 (3.2).
    pub(super) fn flat(symbol: impl Fn(u8) -> u8) -> Self {
        let mut table = Ranks {
            slot: [0; 256],
            heavier: [0; 256],
        };
        for place in 0..=255u8 {
            table.slot[usize::from(place)] = u16::from(symbol(place));
        }
        table
    }

    /// A table whose slot `i` holds `symbol(i)` with the weights a
    /// re-weight gives (3.2's first value of the distance table).
    pub(super) fn graded(symbol: impl Fn(u8) -> u8) -> Self {
        let mut table = Self::flat(symbol);
        table.regrade();
        table
    }

    /// The re-weight of 4.1: slot `p` gets 7 less one for every 32 slots
    /// before it, and keeps its symbol.
    #[cold]
    #[inline(never)]
    fn regrade(&mut self) {
        for (place, slot) in self.slot.iter_mut().enumerate() {
            *slot = *slot & 0xff | (7 - (place / 32) as u16) << 8;
        }
        for (weight, count) in self.heavier.iter_mut().enumerate() {
            *count = 32 * 7u16.saturating_sub(weight as u16);
        }
    }

    /// The symbol slot `place` holds, and the promotion of that slot.
    #[inline(always)]
    pub(super) fn take(&mut self, place: u8) -> u8 {
        let place = usize::from(place);
        if self.slot[place] >> 8 == CEILING {
            self.regrade();
        }
        let held = self.slot[place];
        let weight = usize::from(held >> 8);
        // The first slot of this weight: at or before `place`, so under
        // 256. What it holds has the same weight and takes this place.
        let first = usize::from(self.heavier[weight] as u8);
        self.slot[place] = self.slot[first];
        self.slot[first] = held + 0x100;
        self.heavier[weight] += 1;
        held as u8
    }

    /// The symbol and weight of every slot, for the tests.
    #[cfg(test)]
    pub(super) fn slots(&self) -> Vec<(u8, u8)> {
        self.slot
            .iter()
            .map(|slot| (*slot as u8, (slot >> 8) as u8))
            .collect()
    }
}
