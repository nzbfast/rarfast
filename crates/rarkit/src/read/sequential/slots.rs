//! The slots a member decoded ahead is held in: the read ahead, the held
//! progress, a slot and its pieces, the spare buffers, and the worker
//! that fills them.

use super::*;

// ---------------------------------------------------------------------------
// Who still reads what: drop-behind held back behind the workers
// ---------------------------------------------------------------------------

/// The byte ranges workers are still reading, by volume.
///
/// A worker registers nothing itself: the driver begins a read when it
/// dispatches a member and the worker ends it the moment its decode stops,
/// so the walk can learn, without asking the driver, that a volume is
/// finished with.
///
/// **`reading` is the count of `live`, kept beside it so the walk can ask
/// "is any worker reading at all?" without the lock.** The walk asks
/// [`Reads::floor`] at every drop-behind report, which is once a member,
/// and on an archive whose members all run on the walking thread no read
/// is ever live: the lock was the whole of the answer and about a third
/// of the look-ahead's cost a member there (`f/test-rar4-20000-vsnull`,
/// 20,000 members of about 200 bytes, read 0.92x against the old arm with
/// the look-ahead on and 1.04x with it off; 23 Sep 2026).
/// Sound because a read BEGINS only on the walking thread, the one that
/// asks: a count of zero read there means every read it began has ended,
/// and the Release of `end` orders the worker's reading before it.
#[derive(Default)]
pub(crate) struct Reads {
    pub(super) live: Mutex<Vec<(u64, u32, u64)>>,
    pub(super) gone: Condvar,
    pub(super) next: AtomicU64,
    pub(super) reading: AtomicUsize,
}

impl Reads {
    pub(super) fn begin(&self, volume: u32, start: u64) -> u64 {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        lock(&self.live).push((id, volume, start));
        self.reading.fetch_add(1, Ordering::Relaxed);
        id
    }

    pub(super) fn end(&self, id: u64) {
        let mut live = lock(&self.live);
        if let Some(at) = live.iter().position(|r| r.0 == id) {
            live.swap_remove(at);
            self.reading.fetch_sub(1, Ordering::Release);
        }
        drop(live);
        self.gone.notify_all();
    }

    /// Whether any worker may still be reading, asked without the lock.
    #[inline(always)]
    pub(super) fn idle(&self) -> bool {
        self.reading.load(Ordering::Acquire) == 0
    }

    /// The lowest offset of `volume` a worker may still read.
    pub(super) fn floor(&self, volume: u32) -> Option<u64> {
        lock(&self.live)
            .iter()
            .filter(|r| r.1 == volume)
            .map(|r| r.2)
            .min()
    }

    /// Wait until no worker reads `volume`.
    pub(super) fn wait_out(&self, volume: u32) {
        if self.idle() {
            return;
        }
        let mut live = lock(&self.live);
        while live.iter().any(|r| r.1 == volume) {
            live = self.gone.wait(live).unwrap_or_else(|p| p.into_inner());
        }
    }
}

/// What the caller's `Progress` asks of the driver at a volume's end.
pub(crate) trait Deliver {
    /// Hand every member in the look-ahead to the caller now.
    fn deliver_all(&self) -> Result<()>;
}

/// The caller's `Progress`, with drop-behind held back behind the workers
/// (only [`extract_ahead`] wraps one; every other extraction reports to
/// the caller's own observer exactly as before).
///
/// `released(v, x)` is forwarded only as far as the lowest offset of `v` a
/// worker may still read, and the rest at the next report once the worker
/// is done. `volume_done(v)` first HANDS OVER the whole look-ahead: every
/// member in it precedes the end of the volume, so the caller receives them
/// now, the member at the front streaming as it decodes, and no worker
/// reads `v` afterwards. The walk calls `volume_done` before it asks the
/// caller for the next volume, which is how SPEC-API 5.3 holds: the engine
/// asks for volume `k + 1` only after the last byte it needs from volume
/// `k`.
///
/// **Delivering here, not waiting here, was measured.** The first build
/// WAITED for the workers at `volume_done`; the caller then could not
/// stream the front member while it decoded, a lone 64 MiB member was
/// buffered whole into fresh pages, and `f/extract-m3-text64` read 0.751x
/// its own wall with the look-ahead off (untimed, an Apple M3 Mac, 9 pairs).
pub(crate) struct Held<'p, P: Progress, X: Deliver> {
    pub(super) inner: &'p mut P,
    pub(super) reads: Arc<Reads>,
    pub(super) ahead: X,
    pub(super) volume: u32,
    pub(super) wanted: u64,
    pub(super) told: u64,
}

impl<'p, P: Progress, X: Deliver> Held<'p, P, X> {
    pub(super) fn new(inner: &'p mut P, reads: Arc<Reads>, ahead: X) -> Held<'p, P, X> {
        Held {
            inner,
            reads,
            ahead,
            volume: 0,
            wanted: 0,
            told: 0,
        }
    }

    #[inline(always)]
    pub(super) fn forward(&mut self) -> Result<()> {
        // No worker reading: nothing to hold back, and no lock to take
        // (see `Reads`).
        let allowed = if self.reads.idle() {
            self.wanted
        } else {
            let floor = self.reads.floor(self.volume).unwrap_or(u64::MAX);
            self.wanted.min(floor)
        };
        if allowed > self.told {
            self.told = allowed;
            self.inner.released(self.volume, allowed)?;
        }
        Ok(())
    }
}

impl<P: Progress, X: Deliver> Progress for Held<'_, P, X> {
    #[inline(always)]
    fn released(&mut self, volume: u32, offset: u64) -> Result<()> {
        if volume != self.volume {
            self.volume = volume;
            self.wanted = 0;
            self.told = 0;
        }
        self.wanted = self.wanted.max(offset);
        self.forward()
    }

    fn volume_done(&mut self, volume: u32) -> Result<()> {
        self.ahead.deliver_all()?;
        self.reads.wait_out(volume);
        if volume == self.volume {
            self.forward()?;
        }
        self.inner.volume_done(volume)
    }

    fn output(&mut self, total: u64) -> Result<()> {
        self.forward()?;
        self.inner.output(total)
    }
}

// ---------------------------------------------------------------------------
// The look-ahead's slots
// ---------------------------------------------------------------------------

pub(super) fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// How one member ended, from whichever unit decoded it.
pub(super) struct Finish {
    pub(super) bytes: u64,
    /// The verdict, when the deliverer runs the member's CRC32
    /// (`Bench::decode_with`); `checksum_ok` is then unset.
    pub(super) verdict: Option<Box<Unfinished>>,
    pub(super) checksum_ok: Option<bool>,
    pub(super) error: Option<Error>,
    /// Whether the error ends the whole operation rather than the member.
    pub(super) fatal: bool,
    /// Whether the member's `close` is handed its writer: every member but
    /// one refused before its decode (`extract::refuse` closes with none).
    pub(super) writer: bool,
    /// The volumes of the leading fragments whose CRC32 field disagreed
    /// (spec F 3.5.6), told to the caller's sink before the member's
    /// `close` once the caller has opened it. Empty, and unallocated, on
    /// every member but such a one.
    pub(super) mismatches: Vec<u32>,
}

#[derive(Default)]
pub(super) struct SlotState {
    pub(super) chunks: VecDeque<Piece>,
    /// The bytes of the chunks queued here and not yet taken.
    pub(super) held: u64,
    pub(super) finish: Option<Finish>,
    /// The caller does not want this member's bytes: stop producing them.
    pub(super) abandoned: bool,
    /// The caller is parked on this slot.
    pub(super) waiting: bool,
    /// No decoder claims the member (the solid path's `Producer`).
    pub(super) refused: bool,
    /// The member's ending has been given (`Slot::finish`): a note made
    /// after it belongs to the queue, not to a slot the caller may have
    /// left (`Slot::note`).
    pub(super) sealed: bool,
}

/// One member's place in the look-ahead: the bytes its decode has produced
/// and not yet handed over, and its ending.
#[derive(Default)]
pub(super) struct Slot {
    pub(super) state: Mutex<SlotState>,
    pub(super) ready: Condvar,
    /// Something was put in the slot since the taker last found it empty.
    /// Written under the lock, read without it: what the taker's sweep
    /// polls, so that it takes the lock only for something to take
    /// ([`Slot::next`]).
    pub(super) stocked: AtomicBool,
}

pub(super) enum Next {
    Chunk(Vec<u8>),
    /// A progress call the walk made while this member was open, in its
    /// place among the member's chunks. Only the solid path makes these
    /// ([`Relay`]); the look-ahead's slots never hold one.
    Note(Note),
    /// A range of a stored member, for this thread to read and deliver
    /// (`read::handed`). Only the solid path makes these ([`ChainOut`]).
    Range(Box<Ranged>),
    Done(Finish),
}

/// What a slot holds, in the order its producer made it.
pub(super) enum Piece {
    Chunk(Vec<u8>),
    Note(Note),
    Range(Box<Ranged>),
}

impl SlotState {
    /// The piece at the head of the slot, out of it.
    #[inline(always)]
    fn take(&mut self) -> Option<Piece> {
        let piece = self.chunks.pop_front()?;
        if let Piece::Chunk(c) = &piece {
            self.held = self.held.saturating_sub(c.len() as u64);
        }
        Some(piece)
    }
}

impl Piece {
    #[inline(always)]
    pub(super) fn next(self) -> Next {
        match self {
            Piece::Chunk(c) => Next::Chunk(c),
            Piece::Note(n) => Next::Note(n),
            Piece::Range(r) => Next::Range(r),
        }
    }
}

/// A stored member's range in its place among the member's chunks: where
/// the bytes are, the member's bytes the walk held unwritten in front of
/// them, and the way back to the walk, which waits to hear of each piece.
pub(super) struct Ranged {
    pub(super) range: handed::Range,
    pub(super) lead: Vec<u8>,
    pub(super) told: std::sync::mpsc::Sender<Told>,
}

/// What the delivering thread tells the walk about a range it was handed.
pub(super) enum Told {
    /// The next piece, delivered.
    Passed(handed::Passed),
    /// The range is over: passed whole, or stopped where and why.
    End(std::result::Result<(), wide::Stop>),
}

/// A call the solid path's walk made on the caller's `Progress`, which only
/// the caller's thread may make (SPEC-API 4.4).
pub(super) enum Note {
    Released(u32, u64),
    VolumeDone(u32),
    Output(u64),
}

impl Note {
    pub(super) fn tell<P: Progress>(self, progress: &mut P) -> Result<()> {
        match self {
            Note::Released(v, x) => progress.released(v, x),
            Note::VolumeDone(v) => progress.volume_done(v),
            Note::Output(total) => progress.output(total),
        }
    }
}

impl Slot {
    pub(super) fn push(&self, buf: Vec<u8>) -> io::Result<()> {
        let mut state = lock(&self.state);
        if state.abandoned {
            return Err(io::Error::other("the member's look-ahead was abandoned"));
        }
        state.held += buf.len() as u64;
        state.chunks.push_back(Piece::Chunk(buf));
        self.stocked.store(true, Ordering::Release);
        if state.waiting {
            self.ready.notify_one();
        }
        Ok(())
    }

    /// Whether the slot holds `most` chunk bytes or fewer, or was
    /// abandoned: what a producer held at the look-ahead's gate ([`Gate`])
    /// is released on.
    pub(super) fn holds_at_most(&self, most: u64) -> bool {
        let state = lock(&self.state);
        state.abandoned || state.held <= most
    }

    /// A range, in its place after the chunks pushed before it; handed
    /// back when the slot takes no more.
    pub(super) fn push_range(&self, ranged: Box<Ranged>) -> std::result::Result<(), Box<Ranged>> {
        let mut state = lock(&self.state);
        if state.abandoned {
            return Err(ranged);
        }
        state.chunks.push_back(Piece::Range(ranged));
        self.stocked.store(true, Ordering::Release);
        if state.waiting {
            self.ready.notify_one();
        }
        Ok(())
    }

    /// The note at the head of the slot, if a note is what is there: what
    /// the walk reported for the pieces of a range the caller's thread is
    /// still delivering, taken without waiting.
    pub(super) fn take_note(&self) -> Option<Note> {
        let mut state = lock(&self.state);
        match state.chunks.front() {
            Some(Piece::Note(_)) => match state.chunks.pop_front() {
                Some(Piece::Note(note)) => Some(note),
                _ => None,
            },
            _ => None,
        }
    }

    /// A progress note, in its place after the chunks pushed before it.
    /// Handed back when the slot takes no more: its ending is given (a walk
    /// that failed inside the member still reports its drop-behind, and the
    /// caller's thread reads that from the queue), or the caller abandoned
    /// it and is draining the queue.
    pub(super) fn note(&self, note: Note) -> Option<Note> {
        let mut state = lock(&self.state);
        if state.abandoned || state.sealed {
            return Some(note);
        }
        state.chunks.push_back(Piece::Note(note));
        self.stocked.store(true, Ordering::Release);
        if state.waiting {
            self.ready.notify_one();
        }
        None
    }

    pub(super) fn finish(&self, finish: Finish) {
        let mut state = lock(&self.state);
        // A member has ONE ending. A producer going away with none of its
        // own gives the fatal one through `fail_unsealed`, which keeps an
        // ending already given; a second `finish` would replace the
        // member's own ending (bug sweep H-5, 4 Oct 2026).
        debug_assert!(!state.sealed, "a slot was given a second ending");
        state.finish = Some(finish);
        state.sealed = true;
        self.stocked.store(true, Ordering::Release);
        if state.waiting {
            self.ready.notify_one();
        }
    }

    /// End a member whose producer is going away WITHOUT giving its ending
    /// (the solid walk unwinding): the caller parked on it wakes to a
    /// fatal ending and waits for the walk's own, as for a member the walk
    /// failed inside. A member already given its ending keeps it.
    pub(super) fn fail_unsealed(&self) {
        let mut state = lock(&self.state);
        if state.sealed {
            return;
        }
        state.finish = Some(Finish {
            bytes: 0,
            verdict: None,
            checksum_ok: None,
            error: None,
            fatal: true,
            writer: false,
            mismatches: Vec::new(),
        });
        state.sealed = true;
        self.stocked.store(true, Ordering::Release);
        if state.waiting {
            self.ready.notify_one();
        }
    }

    /// The next chunk, or the member's ending once every chunk is taken.
    /// Waits for either, spinning `spin` microseconds before parking.
    ///
    /// **The sweep polls a flag and not the lock.** It used to take the
    /// slot's lock on every turn, for a hundred microseconds at a time,
    /// against a producer that takes the same lock to push: sampled on a
    /// member streaming from the front of the look-ahead to memory, a
    /// tenth of the process's samples were this loop and three percent
    /// more the kernel's wait queue under the lock. The producer marks the
    /// slot stocked under the lock; the taker clears the mark under the
    /// lock when it finds nothing, so no mark is lost.
    pub(super) fn next(&self, spin: u64) -> Next {
        let mut sweep = super::super::spin::Spin::new(spin);
        loop {
            if self.stocked.load(Ordering::Acquire) {
                let mut state = lock(&self.state);
                if let Some(c) = state.take() {
                    return c.next();
                }
                if let Some(f) = state.finish.take() {
                    return Next::Done(f);
                }
                self.stocked.store(false, Ordering::Release);
            }
            if sweep.over() {
                let mut state = lock(&self.state);
                loop {
                    if let Some(c) = state.take() {
                        state.waiting = false;
                        return c.next();
                    }
                    if let Some(f) = state.finish.take() {
                        state.waiting = false;
                        return Next::Done(f);
                    }
                    state.waiting = true;
                    state = self.ready.wait(state).unwrap_or_else(|p| p.into_inner());
                }
            }
            std::hint::spin_loop();
        }
    }

    /// Stop the member's producer at its next chunk and hand back what it
    /// had queued. Answers the chunk bytes dropped.
    pub(super) fn abandon<R: Recycle>(&self, spares: &R) -> u64 {
        let mut state = lock(&self.state);
        state.abandoned = true;
        let dropped = std::mem::take(&mut state.held);
        for c in state.chunks.drain(..) {
            match c {
                Piece::Chunk(c) => spares.put(c),
                // Dropping its sender is what tells the walk, which waits
                // on it, that nobody will read the range.
                Piece::Range(r) => spares.put(r.lead),
                Piece::Note(_) => {}
            }
        }
        dropped
    }

    /// Ready for the next member. The previous one's ending has been taken.
    pub(super) fn reset(&self) {
        let mut state = lock(&self.state);
        state.chunks.clear();
        self.stocked.store(false, Ordering::Release);
        state.held = 0;
        state.finish = None;
        state.abandoned = false;
        state.waiting = false;
        state.refused = false;
        state.sealed = false;
    }
}

/// Where a chunk buffer goes back to when its bytes are done with.
pub(super) trait Recycle {
    fn put(&self, buf: Vec<u8>);
}

impl Recycle for Spares {
    fn put(&self, buf: Vec<u8>) {
        Spares::put(self, buf);
    }
}

impl<R: Recycle> Recycle for Arc<R> {
    fn put(&self, buf: Vec<u8>) {
        R::put(self, buf);
    }
}

/// Chunk buffers no slot holds, reused so a warm run allocates nothing per
/// member (API promise 2.4), and the count of every chunk buffer alive.
///
/// The count is what the look-ahead's admission reads and what the
/// process counters are charged with (API section 8, whole-process): a
/// member's DECLARED size is what it will produce, but what is resident is
/// the CAPACITY of the buffers it is produced into, a warm buffer handed to
/// a small member included, and of the buffers kept idle here.
pub(super) struct Spares {
    pub(super) pool: Mutex<Pool>,
    /// The most capacity kept idle here at once.
    pub(super) keep: u64,
}

pub(super) struct Pool {
    pub(super) bufs: Vec<Vec<u8>>,
    /// The capacity of `bufs`.
    pub(super) idle: u64,
    /// The capacity of every buffer taken and not yet put back: in a
    /// slot, in a producer's hands, or on its way to the caller.
    pub(super) out: u64,
    /// `idle + out`, charged to `memory::current`.
    pub(super) charge: crate::memory::Held,
}

impl Pool {
    pub(super) fn recharge(&mut self) {
        let resident = self.idle.saturating_add(self.out);
        self.charge.set(resident);
    }
}

impl Spares {
    pub(super) fn new(keep: u64) -> Spares {
        Spares {
            pool: Mutex::new(Pool {
                bufs: Vec::new(),
                idle: 0,
                out: 0,
                charge: crate::memory::Held::default(),
            }),
            keep,
        }
    }

    /// A buffer that holds `want` bytes without growing: a buffer grown by
    /// doubling from empty holds its old and new allocation at once at
    /// every step, which the untimed dry run read as peak RSS.
    pub(super) fn take(&self, want: usize) -> Vec<u8> {
        let got = {
            let mut pool = lock(&self.pool);
            let got = pool.bufs.pop();
            if let Some(buf) = &got {
                pool.idle = pool.idle.saturating_sub(buf.capacity() as u64);
            }
            got
        };
        let buf = match got {
            Some(mut buf) => {
                if buf.capacity() < want {
                    buf.reserve_exact(want);
                }
                buf
            }
            None => Vec::with_capacity(want),
        };
        let mut pool = lock(&self.pool);
        pool.out = pool.out.saturating_add(buf.capacity() as u64);
        pool.recharge();
        buf
    }

    pub(super) fn put(&self, mut buf: Vec<u8>) {
        buf.clear();
        let mut pool = lock(&self.pool);
        let cap = buf.capacity() as u64;
        pool.out = pool.out.saturating_sub(cap);
        if cap > 0 && pool.idle.saturating_add(cap) <= self.keep {
            pool.idle += cap;
            pool.bufs.push(buf);
        }
        pool.recharge();
    }

    /// Drop idle buffers until at most `left` bytes of them remain.
    pub(super) fn shed(&self, left: u64) {
        let mut pool = lock(&self.pool);
        while pool.idle > left {
            let Some(buf) = pool.bufs.pop() else {
                break;
            };
            pool.idle = pool.idle.saturating_sub(buf.capacity() as u64);
        }
        pool.recharge();
    }

    /// The idle capacity kept here.
    pub(super) fn held(&self) -> u64 {
        lock(&self.pool).idle
    }

    /// The capacity of every chunk buffer alive, idle or out.
    pub(super) fn resident(&self) -> (u64, u64) {
        let pool = lock(&self.pool);
        (pool.idle, pool.out)
    }
}

/// HOW FAR THE WORKERS DECODE AHEAD OF THE CALLER'S WRITER: the bytes the
/// look-ahead holds decoded and not yet delivered, and the window a worker
/// is held at.
///
/// **Why.** A slot takes every chunk its producer makes, so a member at
/// the front of the look-ahead, streaming to a writer slower than its
/// decode, was decoded whole into memory in front of that writer, and the
/// members behind it too, up to the working limit: gibibytes, every chunk
/// of them a fresh buffer, since none had come back to the pool. The
/// writer was never waiting for those bytes, so they bought no wall, and
/// on a machine that one member's decode already fills the members behind
/// the front took its lanes as well.
///
/// **The rule.** A worker with a chunk to hand over waits while the
/// look-ahead holds more than the window AND its own slot holds more than
/// [`GATE_FLOOR`]. The second half is what keeps the caller fed: the
/// member the caller is taking is never held with its slot near empty,
/// whatever the members behind it hold. What is held at most is the
/// window, a floor a slot and a chunk a worker.
///
/// **Only where one member fills the machine** (a read width under
/// [`ABREAST_UNITS`]; `sequential::holds`). There a held worker gives
/// the front member its lanes back, and the gate is worth 1.2 to 1.5
/// times the wall on a set of several large members, to a drive and to
/// memory alike (counted on eight cores). On a wider machine the members
/// behind the front decode on cores the front leaves idle, and the
/// walking thread, which is the narrow place there, takes a member it
/// finds already decoded for a write and nothing else: holding them back
/// cost 6 to 16 percent (counted on forty eight cores, to memory), so
/// there the look-ahead is as it was.
///
/// **The walking thread is never held and never waits on a held worker.**
/// It is the thread that delivers, so its own slots (the small members it
/// decodes into the look-ahead) pass the gate, and wherever it blocks for a
/// worker's answer the gate is lifted for that wait ([`Gate::lift`]): a
/// worker held there would be waiting for a delivery that cannot come.
/// When the operation fails or ends the gate opens for good
/// ([`Gate::open`]).
///
/// **Nor is a worker held while any member waits for a lane unit.** A
/// held worker keeps its member's unit and the lanes of the chunk it is
/// in, and the walking thread takes a unit for every member it decodes
/// itself, a directory entry among them: held workers with the whole
/// ceiling between them and the walk waiting for a unit is a wait nobody
/// ends. So the workers wait in the lane budget's own waiting place
/// (`lanes::Yield`), which lets them go for as long as a member waits
/// there, whichever thread that member is on.
pub(crate) struct Gate {
    /// Chunk bytes pushed into the look-ahead's slots and not yet taken.
    held: AtomicU64,
    /// The most `held` ever read.
    peak: AtomicU64,
    /// The window; zero is no gate.
    window: u64,
    /// Open for good: the operation has ended or failed.
    open: AtomicBool,
    /// The walking thread is blocked on a worker's answer.
    lifted: AtomicUsize,
    /// Where the workers held here wait: the lane budget's place, or one
    /// of this gate's own where the read has no budget.
    place: Arc<crate::read::lanes::Yield>,
}

/// What a slot may always hold, whatever the look-ahead holds: four
/// chunks, the reach of the ring a member decoded on the walking thread
/// streams through at the default policy (`seam::ring_plan`).
pub(super) const GATE_FLOOR: u64 = 4 * CHUNK as u64;

/// The read width from which a second large member decodes abreast of the
/// first on cores the first leaves idle: twice one member's units, its
/// tape lanes (eight at most) and its apply.
pub(super) const ABREAST_UNITS: usize = 2 * (8 + 1);

impl Gate {
    /// A gate at `window` bytes, zero for none, whose workers wait in
    /// `place`.
    pub(super) fn new(window: u64, place: Arc<crate::read::lanes::Yield>) -> Gate {
        Gate {
            held: AtomicU64::new(0),
            peak: AtomicU64::new(0),
            window,
            open: AtomicBool::new(false),
            lifted: AtomicUsize::new(0),
            place,
        }
    }

    /// `bytes` more are queued.
    #[inline(always)]
    pub(super) fn queued(&self, bytes: u64) {
        let now = self.held.fetch_add(bytes, Ordering::SeqCst) + bytes;
        self.peak.fetch_max(now, Ordering::Relaxed);
    }

    /// What is held now, and the workers waiting here.
    #[cfg(feature = "test-support")]
    pub(crate) fn live(&self) -> (u64, usize) {
        (self.held.load(Ordering::SeqCst), self.place.parked())
    }

    /// The most the look-ahead held decoded and not yet delivered.
    #[cfg(feature = "test-support")]
    pub(super) fn peak(&self) -> u64 {
        self.peak.load(Ordering::Relaxed)
    }

    /// `bytes` were taken out of `slot`.
    ///
    /// **The waiters are woken a quarter of a window late.** Woken at
    /// every take, a worker at the gate ran one chunk and waited again, a
    /// wake and a sleep for every megabyte the walking thread delivered
    /// (counted on a big member to an NVMe drive: 2.80 s with the gate against
    /// 2.70 s without). So a take wakes them only once the look-ahead is a
    /// quarter under its window, or the slot taken from is down to its
    /// floor, the one case a waiter passes on whatever is held.
    #[inline(always)]
    pub(super) fn took(&self, bytes: u64, slot: &Slot) {
        let held = self
            .held
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |held| {
                Some(held.saturating_sub(bytes))
            })
            .map_or(0, |before| before.saturating_sub(bytes));
        if self.place.parked() == 0 {
            return;
        }
        if held <= self.window - self.window / 4 || slot.holds_at_most(GATE_FLOOR) {
            self.wake();
        }
    }

    /// `bytes` queued for a slot never reached it, or left it unread.
    pub(super) fn dropped(&self, bytes: u64) {
        let _ = self
            .held
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |held| {
                Some(held.saturating_sub(bytes))
            });
        self.wake();
    }

    /// Wake every worker held here, to look again.
    #[inline(always)]
    pub(super) fn wake(&self) {
        self.place.wake();
    }

    /// Open for good.
    pub(super) fn open(&self) {
        self.open.store(true, Ordering::SeqCst);
        self.wake();
    }

    /// The walking thread is about to block for a worker (`true`), or has
    /// its answer (`false`).
    pub(super) fn lift(&self, on: bool) {
        if on {
            self.lifted.fetch_add(1, Ordering::SeqCst);
            self.wake();
        } else {
            self.lifted.fetch_sub(1, Ordering::SeqCst);
        }
    }

    fn passes(&self, more: u64, slot: &Slot, stop: &AtomicBool) -> bool {
        self.held.load(Ordering::SeqCst).saturating_add(more) <= self.window
            || self.open.load(Ordering::SeqCst)
            || self.lifted.load(Ordering::SeqCst) > 0
            || stop.load(Ordering::Relaxed)
            || slot.holds_at_most(GATE_FLOOR)
    }

    /// Wait until `slot`'s producer may hand over `more` bytes.
    #[inline(always)]
    pub(super) fn hold(&self, more: u64, slot: &Slot, stop: &AtomicBool) {
        if self.window == 0 || self.held.load(Ordering::Relaxed).saturating_add(more) <= self.window
        {
            // Through unasked: its next chunk takes its lanes again.
            crate::read::lanes::Yield::passed();
            return;
        }
        self.hold_slow(more, slot, stop);
    }

    #[cold]
    #[inline(never)]
    fn hold_slow(&self, more: u64, slot: &Slot, stop: &AtomicBool) {
        self.place.park_while(|| !self.passes(more, slot, stop));
    }
}

/// What a member in the look-ahead is decoded INTO, on a worker or on the
/// walking thread: its slot, a chunk at a time.
pub(crate) struct SlotOut {
    pub(super) slot: Arc<Slot>,
    pub(super) spares: Arc<Spares>,
    pub(super) cur: Vec<u8>,
    /// Bytes the member may still produce, by its declared size: what the
    /// next buffer is sized for.
    pub(super) left: u64,
    /// The operation has ended: produce nothing more.
    pub(super) stop: Arc<AtomicBool>,
    /// What the look-ahead holds decoded and not yet delivered.
    pub(super) gate: Arc<Gate>,
    /// A WORKER fills this slot, so it is held at the gate. The walking
    /// thread's own slots never are: it is the thread that delivers.
    pub(super) waits: bool,
}

impl SlotOut {
    pub(super) fn hand_over(&mut self) -> io::Result<()> {
        if self.stop.load(Ordering::Relaxed) {
            return Err(io::Error::other("the extraction has ended"));
        }
        let full = self.cur.len() as u64;
        self.left = self.left.saturating_sub(full);
        if self.waits {
            // Held BEFORE the next buffer is taken, so a producer that
            // waits holds no buffer it is not filling.
            self.gate.hold(full, &self.slot, &self.stop);
        }
        let next = self.spares.take(self.left.min(CHUNK as u64) as usize);
        let full_buf = std::mem::replace(&mut self.cur, next);
        self.gate.queued(full);
        let pushed = self.slot.push(full_buf);
        if pushed.is_err() {
            self.gate.dropped(full);
        }
        pushed
    }

    /// Hand over the last bytes and the member's ending.
    pub(super) fn seal(mut self, finish: Finish) {
        if self.cur.is_empty() {
            self.spares.put(std::mem::take(&mut self.cur));
        } else {
            let last = std::mem::take(&mut self.cur);
            let bytes = last.len() as u64;
            self.gate.queued(bytes);
            if let Err(_abandoned) = self.slot.push(last) {
                // Nobody will read it; the ending still arrives.
                self.gate.dropped(bytes);
            }
        }
        self.slot.finish(finish);
    }
}

impl Drop for SlotOut {
    fn drop(&mut self) {
        // The buffer in hand goes back to the spares it was taken from. A
        // member the walk refuses after its `open` is closed with no
        // writer (`extract::refuse`) and this is dropped unsealed: dropped
        // with its buffer, that buffer stayed counted as taken, and as
        // engine memory, for the rest of the operation. A writer that was
        // sealed, or whose buffer was taken back, holds none.
        if self.cur.capacity() > 0 {
            self.spares.put(std::mem::take(&mut self.cur));
        }
        // Dropped by a panic (a worker's decode unwinding): the member
        // gets the fatal ending, so the thread waiting on its slot wakes
        // and does not wait for ever on a member nobody is decoding. A
        // slot already given its ending keeps it.
        if std::thread::panicking() {
            self.slot.fail_unsealed();
        }
    }
}

impl Write for SlotOut {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let room = CHUNK.saturating_sub(self.cur.len()).max(1);
        let take = data.len().min(room);
        self.cur.extend_from_slice(&data[..take]);
        if self.cur.len() >= CHUNK {
            self.hand_over()?;
        }
        Ok(take)
    }

    fn write_all(&mut self, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            let n = self.write(data)?;
            data = &data[n..];
        }
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// What the WALK writes a member into: the caller's own writer, for a
/// member that runs as it always did, or the member's slot.
///
/// **The slot's writer is BOXED, and the box is the driver's, lent for one
/// member at a time.** The walk moves a member's writer by value several
/// times a member, and every member carries this type, the ones that never
/// go ahead too: with the slot's writer inline (56 bytes) the 20,000 member
/// row paid about 64 instructions a member for moves alone (untimed,
/// an Apple M3 Mac, 23 Sep 2026). A box a member would be an allocation a member,
/// which SPEC-API 2.4 forbids, so [`Inner`] keeps ONE box and lends it: only
/// one member at a time sits between the walk's `open` and the moment its
/// writer is handed on (`offer`, `close`, `here`), and the box comes back
/// empty there.
pub(crate) enum SeqOut<W> {
    Direct(W),
    Ahead(Box<Option<SlotOut>>),
}

/// The slot's writer, out of the box it rides in.
pub(super) fn lent(out: &mut Option<SlotOut>) -> io::Result<&mut SlotOut> {
    out.as_mut()
        .ok_or_else(|| io::Error::other("the member's writer was handed on"))
}

impl<W: Write> Write for SeqOut<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        match self {
            SeqOut::Direct(w) => w.write(data),
            SeqOut::Ahead(s) => lent(s)?.write(data),
        }
    }

    fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            SeqOut::Direct(w) => w.write_all(data),
            SeqOut::Ahead(s) => lent(s)?.write_all(data),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            SeqOut::Direct(w) => w.flush(),
            SeqOut::Ahead(s) => lent(s)?.flush(),
        }
    }
}

// ---------------------------------------------------------------------------
// The workers
// ---------------------------------------------------------------------------

pub(super) struct Task {
    pub(super) job: Job<PoolOut<SlotOut>>,
    pub(super) width: usize,
    pub(super) read: u64,
    /// The member is at the FRONT of the look-ahead: its bytes stream to
    /// the caller as they are decoded, and its CRC32 runs there, beside
    /// the caller's write, as the one-member seam runs it.
    pub(super) crc_on_deliver: bool,
    /// Rebuild a held ring larger than this member reaches at its reach
    /// (`concurrent::Bench::set_exact`).
    pub(super) exact: bool,
}

/// A worker's word that it is free again.
pub(super) struct Answer {
    pub(super) worker: usize,
    pub(super) working: u64,
    pub(super) name: Vec<u8>,
}

pub(super) struct Hand {
    pub(super) tasks: SyncSender<Task>,
    /// The decode window this worker has committed to.
    pub(super) held: u64,
    pub(super) working: u64,
}

/// A look-ahead worker, or `None` when the host will not start its thread
/// (`crate::threads`).
#[allow(clippy::too_many_arguments)]
pub(super) fn spawn<'scope, 'env>(
    scope: &'scope Scope<'scope, 'env>,
    index: usize,
    policy: MemoryPolicy,
    cancel: Option<Arc<AtomicBool>>,
    budget: Option<Arc<crate::read::lanes::LaneBudget>>,
    reads: Arc<Reads>,
    answers: SyncSender<Answer>,
    width_stated: bool,
) -> Option<Hand> {
    let (tasks, rx) = sync_channel::<Task>(1);
    // Read on the walking thread, where a bench's thread-local is set.
    let spin = concurrent::task_spin_us();
    // The operation's meter follows its threads (API 8.4.1, `memory::Meter`).
    let op = crate::memory::op_slot();
    crate::threads::scoped(scope, move || {
        let _op = crate::memory::enter(op);
        // The look-ahead's workers rebuild rings small and release every
        // one (`extract::Shrink::Tight`): its admission counts high-water
        // figures, so only this keeps `p`'s resident bytes down.
        let mut bench = Bench::new(policy, cancel.clone(), budget.clone())
            .with_shrink(extract::Shrink::Tight)
            .with_width_stated(width_stated);
        // The first panic a decode here ended in, kept for the end.
        let mut panicked: Option<Box<dyn std::any::Any + Send>> = None;
        while let Some(task) = concurrent::next_on(&rx, spin) {
            let Task {
                job,
                width,
                read,
                crc_on_deliver,
                exact,
            } = task;
            bench.set_exact(exact);
            // A PANIC in the decode (the caller's source, a decoder) must
            // not leave the walk waiting: it parks on this member's slot,
            // on an answer, or on this read ending, and none of the three
            // would ever come, so the scope never reached the join that
            // raises the panic. Caught here instead: the slot has its
            // fatal ending already (`SlotOut`'s drop, in the unwind), the
            // read is ended and the answer sent, and the worker goes on
            // with a new bench so no task sent to it is left unanswered.
            // The panic itself is raised again when the walk has let go.
            let decoded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                bench.decode_with(job, width, crc_on_deliver)
            }));
            let done: Done<SlotOut> = match decoded {
                Ok(done) => done,
                Err(payload) => {
                    reads.end(read);
                    panicked.get_or_insert(payload);
                    bench = Bench::new(policy, cancel.clone(), budget.clone())
                        .with_shrink(extract::Shrink::Tight)
                        .with_width_stated(width_stated);
                    let gone = answers
                        .send(Answer {
                            worker: index,
                            working: 0,
                            name: Vec::new(),
                        })
                        .is_err();
                    if gone {
                        break;
                    }
                    continue;
                }
            };
            reads.end(read);
            let Done {
                out,
                bytes,
                verdict,
                checksum_ok,
                error,
                fatal,
                name,
                working,
                ..
            } = done;
            if let Some(out) = out {
                out.seal(Finish {
                    bytes,
                    verdict,
                    checksum_ok,
                    error,
                    fatal,
                    writer: true,
                    // A worker here decodes a member that is not split.
                    mismatches: Vec::new(),
                });
            }
            if answers
                .send(Answer {
                    worker: index,
                    working,
                    name,
                })
                .is_err()
            {
                break;
            }
        }
        if let Some(payload) = panicked {
            std::panic::resume_unwind(payload);
        }
    })
    .ok()?;
    Some(Hand {
        tasks,
        held: 0,
        working: 0,
    })
}

// ---------------------------------------------------------------------------
// The driver
// ---------------------------------------------------------------------------

/// A member's `MemberInfo`, owned, for the caller's `open` and `close` at
/// the member's turn.
///
/// A redirection member's target (spec F 3.8.1) is kept in the same buffer
/// after the name, so an owned member still costs one buffer and the
/// caller's `open` sees the target the walk saw.
pub(super) struct Owned {
    pub(super) name: Vec<u8>,
    pub(super) name_len: usize,
    pub(super) info: MemberInfo<'static>,
}

impl Owned {
    pub(super) fn of(info: &MemberInfo<'_>, mut name: Vec<u8>) -> Owned {
        name.clear();
        name.extend_from_slice(info.name);
        let name_len = name.len();
        if let Some(target) = info.redirection.and_then(|r| r.target) {
            name.extend_from_slice(target);
        }
        Owned {
            name,
            name_len,
            info: MemberInfo {
                name: &[],
                is_directory: info.is_directory,
                unpacked_size: info.unpacked_size,
                packed_size: info.packed_size,
                split_before: info.split_before,
                split_after: info.split_after,
                encrypted: info.encrypted,
                password_checked: info.password_checked,
                mtime: info.mtime,
                attributes: info.attributes,
                host_os: info.host_os,
                checksum: info.checksum,
                method: info.method,
                dictionary: info.dictionary,
                solid: info.solid,
                algorithm_version: info.algorithm_version,
                data: info.data.clone(),
                redirection: info
                    .redirection
                    .map(|r| crate::read::Redirection { target: None, ..r }),
                file_version: info.file_version,
            },
        }
    }

    pub(super) fn view(&self) -> MemberInfo<'_> {
        let (name, target) = self.name.split_at(self.name_len);
        MemberInfo {
            name,
            redirection: self.info.redirection.map(|r| crate::read::Redirection {
                target: Some(target),
                ..r
            }),
            ..self.info.clone()
        }
    }
}
