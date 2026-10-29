//! Spec I section 3.4: one arena, carved in 12-byte units, with the exact
//! accounting the format depends on.
//!
//! The arena is a flat byte buffer and every link inside it is a 32-bit
//! byte offset ("position"), 0 meaning none (spec I 7.3 item 1). Position 0
//! is outside the arena because spec I's position 0 is this buffer's
//! [`BASE`]. The arena's end is not marked in the buffer: the one walk
//! that could step onto it, [`Arena::glue`]'s merge, asks where it is.
//!
//! Layouts, chosen so that the first 16 bits of every block in use are
//! non-zero, which is what [`Arena::glue`] needs to tell a free block from
//! one in use (spec I 3.4.4):
//!
//! | block | bytes 0..2 | 2..4 | 4..8 | 8..12 |
//! |---|---|---|---|---|
//! | context, 2+ states | `count` (>= 2) | `total` | states | parent |
//! | context, 1 state | `count` (= 1) | symbol, freq | successor | parent |
//! | free block | 0 | next free | size, in glue | - |
//!
//! A state is 6 bytes: symbol, frequency, successor. A binary context's one
//! state therefore lies at its position plus 2, and every rule that reads a
//! state reads it the same way wherever it lives.

use super::tables::{CLASSES, CLASS_OF, UNITS_OF};

/// Bytes in one unit.
pub(super) const UNIT: u32 = 12;
/// Bytes in one state.
pub(super) const STATE: u32 = 6;
/// Where spec I's position 0 lies in the buffer, so that 0 itself is free
/// to mean "none". Sixteen bytes: any base above 0 would do, and this one
/// makes the buffer of a model of `S` bytes `S + 16` long, which is what
/// this package has always reported holding for one.
pub(super) const BASE: u32 = 16;
/// Marker a merge writes over a block it has swallowed: anything but 0,
/// which means "a free block".
const SWALLOWED: u16 = 0xFFFF;
/// How much of each end the model grows from stays on ordinary pages when
/// the rest of the buffer is asked for on large ones (see
/// [`Arena::ask_large_pages`]): a model that never grows past this at any
/// end touches no large page, and so pays for none.
#[cfg(target_os = "linux")]
const ORDINARY_END: usize = 256 * 1024;
/// The large page the request is cut to: 2 MiB, which is a whole number
/// of base pages at every base page size Linux runs with.
#[cfg(target_os = "linux")]
const LARGE_PAGE: usize = 2 << 20;

/// The model's memory: the text region growing up from [`BASE`], the unit
/// region coming down from the top, and the gap between them.
pub(super) struct Arena {
    mem: Vec<u8>,
    /// The size the header signalled, which the accounting uses even when
    /// the buffer is larger (spec I 4.2).
    size: u32,
    pub(super) text_top: u32,
    pub(super) units_floor: u32,
    pub(super) gap_lo: u32,
    pub(super) gap_hi: u32,
    free: [u32; CLASSES],
    glue_countdown: u32,
}

/// Advise the system that the whole large pages inside `bytes` are wanted
/// as large pages. The outcome is not read: it is advice, and the caller
/// carries on the same either way.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn advise_large(bytes: &mut [u8]) {
    let start = bytes.as_mut_ptr();
    let skip = start.align_offset(LARGE_PAGE);
    if skip >= bytes.len() {
        return;
    }
    let length = (bytes.len() - skip) / LARGE_PAGE * LARGE_PAGE;
    if length == 0 {
        return;
    }
    // SAFETY: `skip + length` is at most `bytes.len()`, so the range named
    // lies inside `bytes`, which the caller holds exclusively; it starts
    // on a large page boundary, which is a base page boundary. The advice
    // changes how the system backs those pages, never their contents nor
    // whether they may be read and written.
    let _ = unsafe {
        libc::madvise(
            start.add(skip).cast::<libc::c_void>(),
            length,
            libc::MADV_HUGEPAGE,
        )
    };
}

impl Arena {
    /// An arena with no memory at all.
    pub(super) fn new() -> Arena {
        Arena {
            mem: Vec::new(),
            size: 0,
            text_top: BASE,
            units_floor: BASE,
            gap_lo: BASE,
            gap_hi: BASE,
            free: [0; CLASSES],
            glue_countdown: 0,
        }
    }

    /// Bytes of buffer held, whatever size is signalled.
    pub(super) fn held_bytes(&self) -> u64 {
        self.mem.capacity() as u64
    }

    /// Make room for a model of `size` bytes, growing the buffer only when
    /// the one held is too small (spec I 4.2: never shrunk).
    pub(super) fn reserve(&mut self, size: u32) {
        let want = (BASE + size) as usize;
        if self.mem.len() < want {
            // Zero-filled: pages the model never touches stay unmapped.
            self.mem = vec![0u8; want];
            #[cfg(target_os = "linux")]
            self.ask_large_pages(size);
        }
        self.size = size;
    }

    /// How many bytes of a model of `size` bytes the unit region takes
    /// (spec I 3.4): the top seven eighths, in whole units.
    #[inline(always)]
    fn unit_region(size: u32) -> u32 {
        84 * (size / 96)
    }

    /// Ask the system to back a fresh buffer with large pages, where it
    /// will. A model of tens of megabytes is read all over at every
    /// symbol, and on ordinary pages each of those reads may also miss the
    /// address translation: on a 64 MB text member, x86-64, that was 26
    /// million misses and 7 percent of the decode's cycles (counted 10 Oct
    /// 2026).
    ///
    /// The model grows from three places: the text up from the bottom, the
    /// state arrays up from the unit region's floor and the contexts down
    /// from the top (spec I 3.4). The first [`ORDINARY_END`] bytes of each
    /// are left as they are, so a small member's model is the pages it was
    /// before. Only advice: the buffer, its length, its contents and what
    /// this arena reports holding are unchanged, and a system that
    /// refuses, or has large pages off, leaves everything as it was.
    #[cfg(target_os = "linux")]
    fn ask_large_pages(&mut self, size: u32) {
        let end = (BASE + size) as usize;
        let floor = end - Self::unit_region(size) as usize;
        let text_from = (BASE as usize + ORDINARY_END).min(floor);
        advise_large(&mut self.mem[text_from..floor]);
        let units_to = end.saturating_sub(ORDINARY_END);
        let units_from = (floor + ORDINARY_END).min(units_to);
        advise_large(&mut self.mem[units_from..units_to]);
    }

    /// The position one past the arena's last byte.
    #[inline(always)]
    fn end(&self) -> u32 {
        BASE + self.size
    }

    /// Reset the regions and the free lists for a model start (spec I 3.4).
    /// Touches no arena byte: nothing reads a byte the model did not write
    /// since the restart.
    pub(super) fn restart(&mut self) {
        let unit_region = Self::unit_region(self.size);
        self.glue_countdown = 0;
        self.free = [0; CLASSES];
        self.gap_hi = self.end();
        self.gap_lo = self.gap_hi - unit_region;
        self.units_floor = self.gap_lo;
        self.text_top = BASE;
    }

    // ---- raw access -------------------------------------------------
    //
    // Every position below comes from this allocator or from a link this
    // model wrote, so it is in range by construction (spec I 3.10: the
    // rules are total over every symbol sequence). The slice bounds are
    // the proof, not a check the stream can fail.

    #[inline(always)]
    pub(super) fn u8at(&self, p: u32) -> u8 {
        self.mem[p as usize]
    }

    #[inline(always)]
    pub(super) fn set_u8(&mut self, p: u32, v: u8) {
        self.mem[p as usize] = v;
    }

    #[inline(always)]
    pub(super) fn u16at(&self, p: u32) -> u16 {
        let b: [u8; 2] = self.mem[p as usize..p as usize + 2].try_into().unwrap();
        u16::from_le_bytes(b)
    }

    #[inline(always)]
    pub(super) fn set_u16(&mut self, p: u32, v: u16) {
        self.mem[p as usize..p as usize + 2].copy_from_slice(&v.to_le_bytes());
    }

    #[inline(always)]
    pub(super) fn u32at(&self, p: u32) -> u32 {
        let b: [u8; 4] = self.mem[p as usize..p as usize + 4].try_into().unwrap();
        u32::from_le_bytes(b)
    }

    #[inline(always)]
    pub(super) fn set_u32(&mut self, p: u32, v: u32) {
        self.mem[p as usize..p as usize + 4].copy_from_slice(&v.to_le_bytes());
    }

    // ---- states -----------------------------------------------------

    #[inline(always)]
    pub(super) fn sym(&self, s: u32) -> u8 {
        self.u8at(s)
    }

    #[inline(always)]
    pub(super) fn freq(&self, s: u32) -> u32 {
        u32::from(self.u8at(s + 1))
    }

    /// The symbols and frequencies of the two states in one unit, in one
    /// load: state 0's at bits 0 to 15 and state 1's at bits 48 to 63.
    /// Every scan of a state array wants those four bytes and nothing else,
    /// and one unit always has eight readable bytes.
    #[inline(always)]
    pub(super) fn unit_pair(&self, p: u32) -> u64 {
        let b: [u8; 8] = self.mem[p as usize..p as usize + 8].try_into().unwrap();
        u64::from_le_bytes(b)
    }

    /// `units` whole units from `p`, as bytes: a scan of a state array
    /// reads them through one slice, so its bounds are proved once and
    /// not at every unit.
    #[inline(always)]
    pub(super) fn unit_bytes(&self, p: u32, units: usize) -> &[u8] {
        &self.mem[p as usize..p as usize + units * UNIT as usize]
    }

    /// A state's symbol and frequency in one load: they are adjacent, and
    /// every scan wants both.
    #[inline(always)]
    pub(super) fn sym_freq(&self, s: u32) -> (u8, u32) {
        let both = self.u16at(s);
        (both as u8, u32::from(both >> 8))
    }

    #[inline(always)]
    pub(super) fn succ(&self, s: u32) -> u32 {
        self.u32at(s + 2)
    }

    #[inline(always)]
    pub(super) fn set_freq(&mut self, s: u32, f: u32) {
        self.set_u8(s + 1, f as u8);
    }

    #[inline(always)]
    pub(super) fn set_succ(&mut self, s: u32, v: u32) {
        self.set_u32(s + 2, v);
    }

    #[inline(always)]
    pub(super) fn write_state(&mut self, s: u32, sym: u8, freq: u32, succ: u32) {
        self.set_u8(s, sym);
        self.set_u8(s + 1, freq as u8);
        self.set_u32(s + 2, succ);
    }

    /// Move one state's six bytes.
    #[inline(always)]
    pub(super) fn move_state(&mut self, from: u32, to: u32) {
        self.mem
            .copy_within(from as usize..from as usize + STATE as usize, to as usize);
    }

    /// Swap two states' six bytes.
    #[inline(always)]
    pub(super) fn swap_states(&mut self, a: u32, b: u32) {
        for i in 0..STATE {
            self.mem.swap((a + i) as usize, (b + i) as usize);
        }
    }

    // ---- contexts ---------------------------------------------------

    #[inline(always)]
    pub(super) fn count(&self, c: u32) -> u32 {
        u32::from(self.u16at(c))
    }

    #[inline(always)]
    pub(super) fn set_count(&mut self, c: u32, n: u32) {
        self.set_u16(c, n as u16);
    }

    #[inline(always)]
    pub(super) fn total(&self, c: u32) -> u32 {
        u32::from(self.u16at(c + 2))
    }

    #[inline(always)]
    pub(super) fn set_total(&mut self, c: u32, t: u32) {
        self.set_u16(c + 2, t as u16);
    }

    #[inline(always)]
    pub(super) fn array(&self, c: u32) -> u32 {
        self.u32at(c + 4)
    }

    #[inline(always)]
    pub(super) fn set_array(&mut self, c: u32, p: u32) {
        self.set_u32(c + 4, p);
    }

    #[inline(always)]
    pub(super) fn parent(&self, c: u32) -> u32 {
        self.u32at(c + 8)
    }

    #[inline(always)]
    pub(super) fn set_parent(&mut self, c: u32, p: u32) {
        self.set_u32(c + 8, p);
    }

    /// Whether `p` can be read as a context: above the text region, which
    /// is spec I 3.9.1's own test for "a context", and far enough below
    /// the top of the buffer for its twelve bytes. A successor is either a
    /// text position or a context, and the two are told apart by that
    /// test; a model that has faulted half way through an update can hold
    /// a link that is neither, and a link that is neither must fault and
    /// not index.
    #[inline(always)]
    pub(super) fn is_context(&self, p: u32) -> bool {
        p > self.text_top && (p as usize) + (UNIT as usize) <= self.mem.len()
    }

    /// Where a one-state context keeps its state.
    #[inline(always)]
    pub(super) fn only_state(c: u32) -> u32 {
        c + 2
    }

    // ---- the text region --------------------------------------------

    /// Append one past symbol. The caller checks the region against
    /// `units_floor` afterwards (spec I 3.9.2 step 3).
    #[inline(always)]
    pub(super) fn push_text(&mut self, sym: u8) -> u32 {
        self.set_u8(self.text_top, sym);
        self.text_top += 1;
        self.text_top
    }

    // ---- the free lists ---------------------------------------------

    #[inline(always)]
    fn pop(&mut self, k: usize) -> Option<u32> {
        let head = self.free[k];
        if head == 0 {
            return None;
        }
        self.free[k] = self.u32at(head + 2);
        Some(head)
    }

    /// Put `block` back on class `k`'s stack (spec I 3.4.2, "give").
    #[inline(always)]
    pub(super) fn give(&mut self, block: u32, k: usize) {
        self.set_u16(block, 0);
        let head = self.free[k];
        self.set_u32(block + 2, head);
        self.free[k] = block;
    }

    /// How many bytes a block of class `k` is.
    #[inline(always)]
    fn bytes_of(k: usize) -> u32 {
        UNIT * u32::from(UNITS_OF[k])
    }

    /// A block of class `k` off the bottom of the gap, if the gap has it.
    #[inline(always)]
    fn off_gap(&mut self, k: usize) -> Option<u32> {
        let bytes = Self::bytes_of(k);
        if self.gap_hi - self.gap_lo < bytes {
            return None;
        }
        let block = self.gap_lo;
        self.gap_lo = block + bytes;
        Some(block)
    }

    /// A block of class `k`, or `None` when the arena is exhausted: from
    /// the class's own stack, else from the gap, else the slow way (spec I
    /// 3.4.2, "take").
    pub(super) fn take(&mut self, k: usize) -> Option<u32> {
        self.pop(k)
            .or_else(|| self.off_gap(k))
            .or_else(|| self.rare(k))
    }

    /// One unit for a context, taken from the top of the gap first.
    pub(super) fn take_context(&mut self) -> Option<u32> {
        if self.gap_hi == self.gap_lo {
            return self.pop(0).or_else(|| self.rare(0));
        }
        self.gap_hi -= UNIT;
        Some(self.gap_hi)
    }

    /// The slow path of [`Arena::take`] (spec I 3.4.2, "rare"): a merge
    /// when one is due, then the smallest larger class that has a block,
    /// cut down to size, then room the text has not reached.
    #[cold]
    fn rare(&mut self, k: usize) -> Option<u32> {
        if self.glue_countdown == 0 {
            self.glue();
            if let Some(block) = self.pop(k) {
                return Some(block);
            }
        }
        if let Some(larger) = (k + 1..CLASSES).find(|&i| self.free[i] != 0) {
            let block = self.pop(larger)?;
            self.split(block, larger, k);
            return Some(block);
        }
        self.glue_countdown -= 1;
        let bytes = Self::bytes_of(k);
        if self.units_floor.saturating_sub(self.text_top) <= bytes {
            return None;
        }
        self.units_floor -= bytes;
        Some(self.units_floor)
    }

    /// Put a run of `units` units at `at` back on the free lists (spec I
    /// 3.4.2's rule for a rest, which 3.4.4 step 4 uses again): whole when
    /// it is a class's size, and otherwise as the largest class that fits
    /// and then the one to three units left after it. The two go to
    /// different classes, so which is pushed first shows nowhere; the piece
    /// at the lower position goes first.
    fn file(&mut self, at: u32, units: u32) {
        let fits = CLASS_OF[units as usize] as usize;
        let whole = u32::from(UNITS_OF[fits]);
        if whole == units {
            self.give(at, fits);
            return;
        }
        let lead = u32::from(UNITS_OF[fits - 1]);
        self.give(at, fits - 1);
        self.give(at + UNIT * lead, CLASS_OF[(units - lead) as usize] as usize);
    }

    /// Keep the first `to`-class worth of `block`, which is of class
    /// `from`, and give the rest back.
    fn split(&mut self, block: u32, from: usize, to: usize) {
        let kept = u32::from(UNITS_OF[to]);
        self.file(block + UNIT * kept, u32::from(UNITS_OF[from]) - kept);
    }

    #[inline(always)]
    fn copy_units(&mut self, from: u32, to: u32, units: u32) {
        let n = (UNIT * units) as usize;
        self.mem
            .copy_within(from as usize..from as usize + n, to as usize);
    }

    /// An array of `units` units that needs one more (spec I 3.4.2). It
    /// stays where it is when the next size is still its class's; else it
    /// moves to a block of the next class and its old block is given back.
    pub(super) fn grow(&mut self, old: u32, units: u32) -> Option<u32> {
        let class = CLASS_OF[units as usize] as usize;
        if CLASS_OF[units as usize + 1] as usize == class {
            return Some(old);
        }
        let roomier = self.take(class + 1)?;
        self.copy_units(old, roomier, units);
        self.give(old, class);
        Some(roomier)
    }

    /// An array of `from` units that now needs only `to` (spec I 3.4.2).
    /// Never fails: with no free block of the smaller class to move into,
    /// the array keeps its place and gives its tail back.
    pub(super) fn shrink(&mut self, old: u32, from: u32, to: u32) -> u32 {
        let was = CLASS_OF[from as usize] as usize;
        let now = CLASS_OF[to as usize] as usize;
        if was == now {
            return old;
        }
        match self.pop(now) {
            Some(smaller) => {
                self.copy_units(old, smaller, to);
                self.give(old, was);
                smaller
            }
            None => {
                self.split(old, was, now);
                old
            }
        }
    }

    /// Merge every physically adjacent pair of free blocks and re-file the
    /// results (spec I 3.4.4). Three walks of one list threaded through the
    /// free blocks themselves: no allocation, and no list node survives its
    /// block being handed out.
    #[cold]
    fn glue(&mut self) {
        // Two places a free block can end at are not blocks at all, and
        // the merge must not read them as one: the arena's end, and the
        // bottom of a gap that still has room in it.
        let end = self.end();
        let gap = if self.gap_lo == self.gap_hi {
            end
        } else {
            self.gap_lo
        };
        // 1. Every free block onto one list, newest at the front, each
        //    carrying its size in units at its sixth byte.
        let mut head = 0u32;
        for (k, &units) in UNITS_OF.iter().enumerate() {
            while let Some(block) = self.pop(k) {
                self.set_u16(block, 0);
                self.set_u16(block + 6, u16::from(units));
                self.set_u32(block + 2, head);
                head = block;
            }
        }
        // 2. Merge upwards. A block a merge swallows is marked not-free,
        //    which both removes it from the list and stops any later
        //    neighbour merging into its middle.
        let mut p = head;
        while p != 0 {
            if self.u16at(p) == 0 {
                loop {
                    let size = u32::from(self.u16at(p + 6));
                    let next = p + UNIT * size;
                    if next == end || next == gap || self.u16at(next) != 0 {
                        break;
                    }
                    let grown = size + u32::from(self.u16at(next + 6));
                    if grown >= 65_536 {
                        break;
                    }
                    self.set_u16(next, SWALLOWED);
                    self.set_u16(p + 6, grown as u16);
                }
            }
            p = self.u32at(p + 2);
        }
        // 3. Drop the swallowed blocks from the list, while the markers
        //    still mean what they say (step 4 writes fresh markers).
        let (mut live, mut tail, mut p) = (0u32, 0u32, head);
        while p != 0 {
            let next = self.u32at(p + 2);
            if self.u16at(p) == 0 {
                if tail == 0 {
                    live = p;
                } else {
                    self.set_u32(tail + 2, p);
                }
                tail = p;
            }
            p = next;
        }
        if tail != 0 {
            self.set_u32(tail + 2, 0);
        }
        // 4. Re-file, largest class first for anything over 128 units.
        let mut p = live;
        while p != 0 {
            let next = self.u32at(p + 2);
            let mut block = p;
            let mut size = u32::from(self.u16at(p + 6));
            while size > 128 {
                self.give(block, CLASSES - 1);
                block += UNIT * 128;
                size -= 128;
            }
            self.file(block, size);
            p = next;
        }
        self.glue_countdown = 255;
    }

    /// Every free block as (position, units), for the arena's own tests.
    #[cfg(test)]
    pub(super) fn free_blocks(&self) -> Vec<(u32, u32)> {
        let mut out = Vec::new();
        for (k, &head) in self.free.iter().enumerate() {
            let mut p = head;
            while p != 0 {
                out.push((p, u32::from(UNITS_OF[k])));
                p = self.u32at(p + 2);
            }
        }
        out
    }

    /// The size the header signalled, for the arena's own tests.
    #[cfg(test)]
    pub(super) fn size(&self) -> u32 {
        self.size
    }

    /// Force the next rare allocation to glue, for the arena's own tests.
    #[cfg(test)]
    pub(super) fn arm_glue(&mut self) {
        self.glue_countdown = 0;
    }
}

#[cfg(test)]
mod reserve_tests {
    use super::{Arena, BASE, UNIT};

    /// One thread; the largest arena here is 32 MiB, read once whole.
    ///
    /// Whatever pages back a fresh buffer (on Linux most of a large one is
    /// asked for on large pages), the arena is what it reports: exactly
    /// the bytes signalled plus the base, all zero, and writable at the
    /// three places a model grows from and at its two ends.
    #[test]
    fn a_reserved_arena_is_whole_and_zero_at_every_size() {
        for mib in [1u32, 2, 3, 4, 32] {
            let size = mib << 20;
            let mut arena = Arena::new();
            arena.reserve(size);
            let want = (BASE + size) as usize;
            assert_eq!(arena.mem.len(), want);
            assert_eq!(arena.held_bytes(), want as u64);
            assert_eq!(arena.size(), size);
            assert!(arena.mem.iter().all(|&byte| byte == 0));
            arena.restart();
            let ends = [
                0,
                BASE,
                arena.units_floor - 1,
                arena.gap_lo,
                arena.gap_hi - UNIT,
                arena.gap_hi - 1,
            ];
            for (i, &p) in ends.iter().enumerate() {
                arena.set_u8(p, i as u8 + 1);
            }
            for (i, &p) in ends.iter().enumerate() {
                assert_eq!(arena.u8at(p), i as u8 + 1);
            }
            // Asking again for no more than is held keeps the buffer.
            let held = arena.mem.as_ptr();
            arena.reserve(size);
            assert_eq!(arena.mem.as_ptr(), held);
            assert_eq!(arena.u8at(BASE), 2);
        }
    }
}
