//! The sliding window the RAR 2.0 codec produces into (spec H3 section 3.5,
//! whose rules are spec H1 section 3.6's).
//!
//! One buffer per stream, allocated once at the format maximum (1 MiB, spec H3 3.5),
//! never grown and never shrunk, and not cleared between members of a solid
//! chain. Bytes are produced into it and drained out by the caller; a match
//! reaches back into what the stream produced earlier, including into an
//! earlier member of the chain.

use crate::error::Rar20Fault;
use crate::{Corruption, Error, ErrorKind, Result};

/// The output side of one stream.
pub(crate) struct Window {
    /// The ring, exactly `capacity` bytes.
    ring: Vec<u8>,
    /// Where the next byte is written, always less than `capacity`.
    write: usize,
    /// Bytes produced since the stream started. Never wraps.
    produced: u64,
    /// Bytes the caller has taken. `produced - drained` is what is still
    /// held for it.
    drained: u64,
}

impl Window {
    /// A window of `capacity` bytes, which spec F has already checked
    /// against the memory policy.
    pub(crate) fn new(capacity: u32) -> Window {
        let capacity = capacity.max(1) as usize;
        Window {
            ring: vec![0; capacity],
            write: 0,
            produced: 0,
            drained: 0,
        }
    }

    /// The size this window was allocated at.
    pub(crate) fn capacity(&self) -> usize {
        self.ring.len()
    }

    /// Bytes produced but not yet taken by the caller.
    pub(crate) fn held_bytes(&self) -> u64 {
        self.produced - self.drained
    }

    /// Room for more bytes before an undrained byte would be overwritten.
    pub(crate) fn room(&self) -> usize {
        self.capacity() - self.held_bytes() as usize
    }

    /// Put one byte.
    #[inline(always)]
    pub(crate) fn put(&mut self, byte: u8) {
        self.ring[self.write] = byte;
        self.write += 1;
        if self.write == self.ring.len() {
            self.write = 0;
        }
        self.produced += 1;
    }

    /// HOT PATH. The run at the write point that a caller producing bytes
    /// one at a time may fill directly, at most `want` long and never
    /// wrapping the ring.
    ///
    /// It is the multimedia block's way in (spec H3 section 3.4), where
    /// every byte comes through the predictor and none comes from the
    /// window: writing them through this slice costs no bounds check and
    /// no wrap test per byte, where [`Window::put`] pays both. The bytes
    /// are NOT produced until [`Window::commit`] says how many were
    /// written, so a caller that stops early - on the block terminator or
    /// on a fault - commits what it filled and no more.
    ///
    /// The write invariant below is kept because the run is EXACT: it ends
    /// at the ring's end at the latest, and `commit` advances the write
    /// point by what was filled, never by the run's length.
    #[inline(always)]
    pub(crate) fn run(&mut self, want: usize) -> &mut [u8] {
        let end = self.ring.len().min(self.write + want);
        #[allow(clippy::indexing_slicing)] // `write < len` and `end <= len`
        &mut self.ring[self.write..end]
    }

    /// Count the first `filled` bytes of the last [`Window::run`] as
    /// produced.
    #[inline(always)]
    pub(crate) fn commit(&mut self, filled: usize) {
        debug_assert!(self.write + filled <= self.ring.len());
        self.write += filled;
        if self.write == self.ring.len() {
            self.write = 0;
        }
        self.produced += filled as u64;
    }

    /// HOT PATH. Copy `length` bytes from `distance` back, which may
    /// overlap the write point: a distance of one fills with the last byte.
    ///
    /// # The write invariant, in this window's own terms
    ///
    /// The ring is EXACTLY `capacity` bytes, the allocation of spec H3
    /// section 3.5 (the format maximum for a stream, whatever the header
    /// declared; a caller may size it otherwise), allocated once and never grown, shrunk or
    /// cleared between members of a solid chain. It carries NO MARGIN, so
    /// the slot `j` ahead of the write point holds the byte the stream
    /// produced `capacity - j` ago, which is precisely the source a match
    /// at distance `capacity - j` names. The range check above admits
    /// every distance up to `capacity`, so once a member has lapped there
    /// is no dead slot anywhere in this ring.
    ///
    /// **A copy owns `[write, write + length)` around the ring and
    /// nothing else.** Nothing outside the codec can widen that: this
    /// package has no filter path of its own, and [`Window::pending`]
    /// lends the drained bytes as `&[u8]`, so the caller reads the ring
    /// and never writes it.
    ///
    /// The mechanism is EXACTNESS. The fast arm below copies `length`
    /// bytes and no more - it is a `copy_within` of exactly the range,
    /// NOT a rounded up block - and the slow arm is one byte at a time.
    /// `crate::window_guard` enforces that on every copy in a test
    /// build; with a margin of zero, every watched slot is reachable once
    /// the member has lapped, so any spill at all fails there.
    #[inline]
    pub(crate) fn copy(&mut self, distance: u32, length: u32) -> Result<()> {
        let capacity = self.ring.len();
        let distance = distance as usize;
        if distance == 0 || distance as u64 > self.produced || distance > capacity {
            return Err(fault(Rar20Fault::DistanceOutOfRange));
        }
        #[cfg(debug_assertions)]
        let watch = crate::window_guard::SpillWatch::take(&self.ring, self.write, length as usize);
        let mut read = if distance <= self.write {
            self.write - distance
        } else {
            capacity + self.write - distance
        };
        let length = length as usize;
        // The fast arm: the source does not overlap the destination, and
        // neither run wraps the ring. Everything else goes byte at a time,
        // which is what the overlapping case means anyway.
        if distance >= length && read + length <= capacity && self.write + length <= capacity {
            self.ring.copy_within(read..read + length, self.write);
            self.write += length;
            if self.write == capacity {
                self.write = 0;
            }
            self.produced += length as u64;
            #[cfg(debug_assertions)]
            watch.check(
                &self.ring,
                self.produced,
                capacity,
                "spec H3 3.5 RAR 2.0 window, block arm",
            );
            return Ok(());
        }
        for _ in 0..length {
            let byte = self.ring[read];
            read += 1;
            if read == capacity {
                read = 0;
            }
            self.put(byte);
        }
        #[cfg(debug_assertions)]
        watch.check(
            &self.ring,
            self.produced,
            capacity,
            "spec H3 3.5 RAR 2.0 window, byte arm",
        );
        Ok(())
    }

    /// The bytes produced and not yet taken, oldest first, as at most two
    /// runs because the ring may wrap.
    pub(crate) fn pending(&self) -> (&[u8], &[u8]) {
        let held = self.held_bytes() as usize;
        let capacity = self.ring.len();
        let start = (self.write + capacity - held) % capacity;
        if start + held <= capacity {
            (&self.ring[start..start + held], &[])
        } else {
            // The held bytes sit at [start, start + held) around the ring,
            // so the wrapped half is what is left after the run to the
            // ring's end: `held - (capacity - start)`, and NOT that plus
            // `start` again. The two are equal only when `start` is zero,
            // which is the branch above, so the old expression was never
            // right here; it asked for a slice longer than the ring the
            // moment a member drained a full window's worth with the write
            // cursor off zero. OBSERVED as a panic, "range end index 79410
            // out of range for slice of length 65536", on the genuine
            // `fixtures/legacy/archives/d250_m1.rar` through the public
            // `extract` (spec H3 part A, `Window::pending`).
            (&self.ring[start..], &self.ring[..held - (capacity - start)])
        }
    }

    /// Mark `count` pending bytes taken.
    pub(crate) fn take(&mut self, count: u64) {
        debug_assert!(count <= self.held_bytes());
        self.drained += count.min(self.held_bytes());
    }
}

fn fault(fault: Rar20Fault) -> Error {
    Error::new(ErrorKind::Corrupt(Corruption::Rar20(fault)))
}
