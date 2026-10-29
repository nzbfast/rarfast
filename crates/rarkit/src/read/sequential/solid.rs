//! A solid archive ahead of its sink: the chain decoded on one thread, its
//! output queued in rungs under a budget, and delivery in order.

use super::*;

// ---------------------------------------------------------------------------
// The solid path: the walk on a worker, the caller's thread writing
// ---------------------------------------------------------------------------
//
// A solid archive has no independent member: every member continues the
// window the one before it left (spec F 3.6), so nothing of it goes ahead
// in the driver above and, on the sequential path, each member is decoded
// and then written, in turn, on the caller's thread. The one-member seam
// would overlap the two, but it runs a member on its own thread with no
// chain look-ahead, and on a solid text set that cost more than the
// overlap bought (the solid extract to disk, 23 Sep 2026).
//
// So here the WHOLE WALK moves: one scoped worker runs it, headers, chain
// look-ahead and decode, exactly as the walking thread ran it, and writes
// each member into a slot. The caller's thread only delivers: the caller's
// `open`, the member's bytes as they arrive, its `close`, in archive order,
// one member at a time. The walk's drop-behind news and progress reach the
// caller's `Progress` through the same queue, in the order the walk made
// them. The bytes buffered between the two are bounded (`Budget`). It is
// taken only where the caller has said its writer is a file
// (`ReadOptions::sink_is_file`), which is where the write is worth hiding.
//
// Except a STORED member's bytes, which exist in the volume already: the
// walk queues where they are (`Ranged`, `ChainOut::hand`) and the caller's
// thread reads, hashes and writes them itself, wide and from page-aligned
// pieces (`read::handed`), while the walk waits and accounts for each piece
// as its own read would have. Counted, the queue cost such a member two
// copies of every byte and a serial read (1 Oct
// 2026); `RARKIT_SOLID_STORED_WIDE=0` restores it.

/// Whether a solid archive's walk goes to a worker: `RARKIT_SOLID_AHEAD`,
/// `1` or `on`, `0` or `off`. A RUNTIME knob, so one binary measures both.
pub(crate) const SOLID_AHEAD_ENV: &str = "RARKIT_SOLID_AHEAD";

/// Whether the solid path is on when [`SOLID_AHEAD_ENV`] says nothing: ON,
/// on its timed price (an Apple M3 Mac, 23 Sep 2026: a 2 GiB solid text set
/// extracted to disk by rarkit-cli, 3.97 to 3.48 s, 1.141x, every control
/// unmoved). It engages only for a writer the caller calls a
/// file (`ReadOptions::sink_is_file`).
pub(super) const SOLID_AHEAD_DEFAULT: bool = true;

pub(super) fn solid_env_on() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        match crate::knob::reader_var(SOLID_AHEAD_ENV)
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("1" | "on") => true,
            Some("0" | "off") => false,
            _ => SOLID_AHEAD_DEFAULT,
        }
    })
}

#[cfg(feature = "test-support")]
pub(super) fn solid_engaged() -> bool {
    crate::probe::solid_ahead().unwrap_or_else(solid_env_on)
}

#[cfg(not(feature = "test-support"))]
pub(super) fn solid_engaged() -> bool {
    solid_env_on()
}

/// The caller's volumes, with volume 0 asked for ONCE, ahead of the walk,
/// and handed to the walk when it asks: the engine still asks for each
/// volume at most once (SPEC-API 5.3).
pub(super) struct Peeked<V> {
    pub(super) inner: V,
    pub(super) first: Option<Option<Arc<dyn crate::source::RangeSource>>>,
}

impl<V: Volumes> Peeked<V> {
    pub(super) fn new(inner: V) -> Peeked<V> {
        Peeked { inner, first: None }
    }

    /// Whether volume 0 is a SOLID archive, from its main header.
    ///
    /// Anything short of a plain main header with the solid flag set,
    /// including a header that needs a password to read, answers no and
    /// leaves the archive to the path it would have taken anyway. The
    /// header's bytes are read here and again by the walk, one window of
    /// the volume's start.
    pub(super) fn first_is_solid(&mut self, options: &crate::read::ReadOptions) -> Result<bool> {
        let Some(inner) = self.inner.volume(0)? else {
            self.first = Some(None);
            return Ok(false);
        };
        // Every byte the peek reads is KEPT and served to the walk from
        // here, so the walk's own read of the same header asks the caller
        // for nothing twice (SPEC-API promise 5).
        let kept = Arc::new(Kept {
            inner,
            seen: Mutex::new(Vec::new()),
            keeping: AtomicBool::new(true),
        });
        self.first = Some(Some(
            Arc::clone(&kept) as Arc<dyn crate::source::RangeSource>
        ));
        let answer = Self::solid_flag(Arc::clone(&kept) as _, options);
        kept.keeping.store(false, Ordering::Relaxed);
        Ok(answer)
    }

    pub(super) fn solid_flag(
        src: Arc<dyn crate::source::RangeSource>,
        options: &crate::read::ReadOptions,
    ) -> bool {
        let Ok(found) = crate::read::archive::require_signature(src.as_ref(), options.sfx_scan)
        else {
            return false;
        };
        let mut ctx = ReadCtx::new(crate::read::ReadOptions {
            password: None,
            ..options.clone()
        });
        let mut reader =
            crate::read::reader::BlockReader::shared(src, &mut ctx, found.format, found.start);
        for _ in 0..3 {
            match reader.next() {
                Ok(Some(block)) => {
                    if let crate::read::block::Fields::Main(main) = &block.fields {
                        return main.solid;
                    }
                }
                _ => return false,
            }
        }
        false
    }
}

/// Volume 0 behind the peek: what the peek read is kept, and served to
/// whoever asks for it again, so no byte of the caller's source is read
/// twice. A read that would run into a kept range stops at its start.
pub(super) struct Kept {
    pub(super) inner: Arc<dyn crate::source::RangeSource>,
    pub(super) seen: Mutex<Vec<(u64, Vec<u8>)>>,
    pub(super) keeping: AtomicBool,
}

impl crate::source::RangeSource for Kept {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let want = {
            let seen = lock(&self.seen);
            for (at, bytes) in seen.iter() {
                let end = at + bytes.len() as u64;
                if offset >= *at && offset < end {
                    let from = (offset - at) as usize;
                    let n = buf.len().min(bytes.len() - from);
                    buf[..n].copy_from_slice(&bytes[from..from + n]);
                    return Ok(n);
                }
            }
            let next = seen
                .iter()
                .map(|(at, _)| *at)
                .filter(|at| *at > offset)
                .min()
                .unwrap_or(u64::MAX);
            buf.len()
                .min(usize::try_from(next - offset).unwrap_or(usize::MAX))
        };
        let n = self.inner.read_at(offset, &mut buf[..want])?;
        if n > 0 && self.keeping.load(Ordering::Relaxed) {
            lock(&self.seen).push((offset, buf[..n].to_vec()));
        }
        Ok(n)
    }

    fn available(&self) -> u64 {
        self.inner.available()
    }

    fn len(&self) -> Option<u64> {
        self.inner.len()
    }
}

impl<V: Volumes> Volumes for Peeked<V> {
    fn volume(&mut self, index: u32) -> Result<Option<Arc<dyn crate::source::RangeSource>>> {
        if index == 0 {
            if let Some(first) = self.first.take() {
                return Ok(first);
            }
        }
        self.inner.volume(index)
    }
}

/// The bytes produced and not yet delivered, bounded: the walk waits when
/// the caller's thread is that far behind.
pub(super) struct Budget {
    pub(super) held: Mutex<u64>,
    pub(super) room: Condvar,
    pub(super) cap: u64,
    pub(super) stop: Arc<AtomicBool>,
    /// The engine limit of a NAMED budget, which the queue's buffers are
    /// held under with the rest of the operation ([`Budget::room_for`]).
    pub(super) limit: Option<u64>,
    #[cfg(feature = "test-support")]
    pub(super) peak: AtomicU64,
}

impl Budget {
    /// Take `n` bytes of room, waiting for the caller to deliver. `false`
    /// when the operation has ended and nothing more is wanted.
    pub(super) fn take(&self, n: u64) -> bool {
        let mut held = lock(&self.held);
        while *held > 0 && held.saturating_add(n) > self.cap {
            if self.stop.load(Ordering::Relaxed) {
                return false;
            }
            held = self
                .room
                .wait_timeout(held, Duration::from_millis(50))
                .map(|(g, _)| g)
                .unwrap_or_else(|p| p.into_inner().0);
        }
        *held += n;
        #[cfg(feature = "test-support")]
        self.peak.fetch_max(*held, Ordering::Relaxed);
        !self.stop.load(Ordering::Relaxed)
    }

    pub(super) fn give(&self, n: u64) {
        let mut held = lock(&self.held);
        *held = held.saturating_sub(n);
        drop(held);
        self.room.notify_all();
    }

    /// Wait until the caller's thread has delivered everything queued,
    /// then free the pool's idle buffers: what the walk lends the meter
    /// ([`crate::memory::make_room`]) for a charge that would pass a named
    /// limit. The queue's buffers are charged to the operation, and a
    /// packed block buffer is priced against it; with them in the price a
    /// slow caller made the walk refuse a member the sequential path reads
    /// under the same limit (27 Oct 2026). Every member before the walk's
    /// is sealed, so the caller always drains; `false` when the operation
    /// has ended instead.
    pub(super) fn drain(&self, spares: &Rungs) -> bool {
        let mut held = lock(&self.held);
        while *held > 0 {
            if self.stop.load(Ordering::Relaxed) {
                return false;
            }
            held = self
                .room
                .wait_timeout(held, Duration::from_millis(50))
                .map(|(g, _)| g)
                .unwrap_or_else(|p| p.into_inner().0);
        }
        drop(held);
        spares.shed();
        true
    }

    /// Before the walk takes a buffer of `size` bytes: under a named limit
    /// the operation would pass with a FRESH one, the pool's idle buffers
    /// are freed, and while anything is queued the walk waits for the
    /// caller's thread to deliver it. The queue was held to its own budget
    /// alone, and beside the walk's window it took a solid read to 4.7 MB
    /// under a named 4 MiB, where the sequential path held 2.3 MB (27 Oct
    /// 2026).
    ///
    /// **A pooled buffer of that size needs no room**: [`Rungs::take`]
    /// reuses it at no new charge, so the walk goes on at once, and a wait
    /// ends as soon as the caller gives one back. Priced as fresh, a reused
    /// buffer was freed and the walk waited for the WHOLE queue to drain,
    /// near a tight limit at almost every buffer (93 of 95 waits a run at
    /// `-mm66m` on a one-file solid archive, 27 Oct 2026), which cost a
    /// quarter of the wall on Linux.
    pub(super) fn room_for(&self, size: u64, spares: &Rungs) {
        let Some(limit) = self.limit else {
            return;
        };
        let over = || crate::memory::op_current().saturating_add(size) > limit;
        if !over() {
            return;
        }
        let rung = rung_of(size as usize);
        if spares.has_idle(rung) {
            return;
        }
        spares.shed();
        let mut held = lock(&self.held);
        while *held > 0 && over() && !spares.has_idle(rung) {
            if self.stop.load(Ordering::Relaxed) {
                return;
            }
            held = self
                .room
                .wait_timeout(held, Duration::from_millis(50))
                .map(|(g, _)| g)
                .unwrap_or_else(|p| p.into_inner().0);
        }
    }
}

/// One thing the walk tells the caller's thread, in the walk's own order.
pub(super) enum Item {
    /// A member reached: its `MemberInfo`, and the slot its bytes arrive in.
    Member(Owned, Arc<Slot>),
    /// A progress call made while no member was open.
    Note(Note),
    /// The walk is over.
    End(Result<ExtractReport>),
}

/// How many items the queue between the walk and the caller's thread holds.
pub(super) const QUEUE_DEPTH: usize = 1024;

#[cfg(feature = "test-support")]
pub(super) fn queue_depth() -> usize {
    crate::probe::solid_queue_depth().unwrap_or(QUEUE_DEPTH)
}

#[cfg(not(feature = "test-support"))]
pub(super) fn queue_depth() -> usize {
    QUEUE_DEPTH
}

/// The member the walk has open, between `Producer::open` and its `close`,
/// shared with the [`Relay`] on the same thread.
pub(super) type Open = std::rc::Rc<std::cell::RefCell<Option<Arc<Slot>>>>;

/// The caller's `Progress`, on the walk's worker: every call is queued
/// for the caller's thread, which is the only one that may make it.
///
/// **WHILE A MEMBER IS OPEN A NOTE GOES INTO ITS SLOT, NEVER THE QUEUE.**
/// The caller's thread reads the queue only between members; inside one it
/// waits on that member's slot alone. The walk ticks `output` once per
/// `walk::TICK` of a member's bytes and `released` once per `TICK` of its
/// input, so a member long enough made more notes than the bounded queue
/// holds, the walk parked in `send` with the member unsealed, and the
/// caller parked on a slot nothing would fill again: both threads asleep
/// for ever at 0 percent CPU (found 27 Sep 2026: a
/// solid `-m3 -md16m` set of four 1 GiB members stopped 8 MiB short of the
/// first member's end at every width but `-mt1`). In the slot a note
/// wakes the very wait the caller is in, and keeps its place among the
/// member's chunks. Between members the queue is safe to block on: every
/// member before it is sealed, so the caller always comes back to it.
pub(super) struct Relay {
    pub(super) tx: SyncSender<Item>,
    pub(super) open: Open,
}

impl Relay {
    pub(super) fn tell(&self, note: Note) {
        let note = match self.open.borrow().as_ref() {
            Some(slot) => slot.note(note),
            None => Some(note),
        };
        if let Some(note) = note {
            let _ = self.tx.send(Item::Note(note));
        }
    }
}

impl Progress for Relay {
    fn released(&mut self, volume: u32, offset: u64) -> Result<()> {
        self.tell(Note::Released(volume, offset));
        Ok(())
    }

    fn volume_done(&mut self, volume: u32) -> Result<()> {
        self.tell(Note::VolumeDone(volume));
        Ok(())
    }

    fn output(&mut self, total: u64) -> Result<()> {
        self.tell(Note::Output(total));
        Ok(())
    }
}

/// The smallest buffer [`Rungs`] deals in, as a power of two: 4 KiB.
pub(super) const RUNG_LOW: u32 = 12;

/// How many sizes [`Rungs`] deals in: every power of two from 4 KiB to a
/// whole [`CHUNK`].
pub(super) const RUNGS: usize = (CHUNK.trailing_zeros() - RUNG_LOW + 1) as usize;

/// The rung a buffer of at least `want` bytes comes from.
pub(super) fn rung_of(want: usize) -> usize {
    let bits = want.max(1).next_power_of_two().trailing_zeros();
    (bits.max(RUNG_LOW) - RUNG_LOW).min(RUNGS as u32 - 1) as usize
}

/// The solid path's buffers: every power of two from 4 KiB to a chunk,
/// each size pooled apart, and every buffer alive counted by capacity.
///
/// **Why sizes, and why pooled.** A member's bytes are queued in a buffer
/// sized to what it declared, so a small member holds a small buffer
/// rather than a chunk. Allocated to the byte and freed once delivered,
/// those buffers were made on the walk's thread and freed on the caller's,
/// and macOS malloc kept what they freed: under a stated `-mm256m`, 131 MiB
/// of the zone's 268 MiB resident was free memory it held (M5, 30 Sep
/// 2026). Rounded to a power of two and handed back here, a warm run frees
/// nothing (API promise 2.4) and what is resident is what is counted.
///
/// **The bound.** Idle and out together are kept at or under `keep`: a
/// buffer that comes back when they are over it is freed rather than
/// pooled, and a fresh buffer sheds idle ones of other sizes first, so a
/// chain whose members change size frees only what it no longer needs.
pub(super) struct Rungs {
    pub(super) pool: Mutex<RungPool>,
    pub(super) keep: u64,
}

pub(super) struct RungPool {
    pub(super) idle: [Vec<Vec<u8>>; RUNGS],
    /// The capacity of every idle buffer.
    pub(super) idle_bytes: u64,
    /// The capacity of every buffer handed out and not yet back.
    pub(super) out: u64,
    /// `idle_bytes + out`, charged to `memory::current`.
    pub(super) charge: crate::memory::Held,
    /// The most `idle_bytes + out` has been, for the bound its test reads.
    #[cfg(feature = "test-support")]
    pub(super) peak: u64,
}

impl RungPool {
    pub(super) fn recharge(&mut self) {
        let alive = self.idle_bytes.saturating_add(self.out);
        self.charge.set(alive);
        #[cfg(feature = "test-support")]
        {
            self.peak = self.peak.max(alive);
        }
    }
}

impl Rungs {
    pub(super) fn new(keep: u64) -> Rungs {
        Rungs {
            pool: Mutex::new(RungPool {
                idle: Default::default(),
                idle_bytes: 0,
                out: 0,
                charge: crate::memory::Held::default(),
                #[cfg(feature = "test-support")]
                peak: 0,
            }),
            keep,
        }
    }

    /// The most capacity alive at once, and the capacity handed out now.
    #[cfg(feature = "test-support")]
    pub(super) fn seen(&self) -> (u64, u64) {
        let pool = lock(&self.pool);
        (pool.peak, pool.out)
    }

    /// A buffer of at least `want` bytes, at most a chunk, whose capacity
    /// is a power of two.
    pub(super) fn take(&self, want: usize) -> Vec<u8> {
        let rung = rung_of(want);
        let size = 1usize << (rung as u32 + RUNG_LOW);
        let mut pool = lock(&self.pool);
        let buf = match pool.idle[rung].pop() {
            Some(buf) => {
                pool.idle_bytes = pool.idle_bytes.saturating_sub(size as u64);
                buf
            }
            None => {
                // Room for a fresh one: idle buffers of other sizes go
                // first, the largest first.
                let mut top = RUNGS;
                while pool.idle_bytes + pool.out + size as u64 > self.keep && top > 0 {
                    match pool.idle[top - 1].pop() {
                        Some(shed) => {
                            pool.idle_bytes = pool.idle_bytes.saturating_sub(shed.capacity() as u64)
                        }
                        None => top -= 1,
                    }
                }
                Vec::with_capacity(size)
            }
        };
        pool.out = pool.out.saturating_add(buf.capacity() as u64);
        pool.recharge();
        buf
    }

    /// Whether an idle buffer of rung `rung` is pooled ([`Budget::room_for`]).
    pub(super) fn has_idle(&self, rung: usize) -> bool {
        !lock(&self.pool).idle[rung].is_empty()
    }

    /// Free every idle buffer ([`Budget::drain`]).
    pub(super) fn shed(&self) {
        let mut pool = lock(&self.pool);
        for rung in &mut pool.idle {
            rung.clear();
        }
        pool.idle_bytes = 0;
        pool.recharge();
    }
}

impl Recycle for Rungs {
    fn put(&self, mut buf: Vec<u8>) {
        buf.clear();
        let cap = buf.capacity();
        let mut pool = lock(&self.pool);
        pool.out = pool.out.saturating_sub(cap as u64);
        let rung = rung_of(cap);
        if cap.is_power_of_two()
            && 1usize << (rung as u32 + RUNG_LOW) == cap
            && pool.idle_bytes + pool.out + cap as u64 <= self.keep
        {
            pool.idle_bytes += cap as u64;
            pool.idle[rung].push(buf);
        }
        pool.recharge();
    }
}

/// What the walk writes one member into, on its worker: the member's slot,
/// a chunk at a time, inside the budget.
///
/// **THE BUDGET IS CHARGED BY CAPACITY, and a buffer is taken only when a
/// byte needs it, sized to what the member has left.** Charged by the bytes
/// written, a small member's last buffer passed for its few bytes while it
/// held a whole chunk, and with a thousand such members queued behind the
/// walk `rarfast x` of a solid archive of 8,568 binaries held 786 MiB of
/// footprint against 126 MiB with this path off (M5, 30 Sep 2026). And a buffer taken
/// ahead of need at the member's end was dropped unused, one per member,
/// with its charge never given back.
pub(crate) struct ChainOut {
    pub(super) slot: Arc<Slot>,
    pub(super) spares: Arc<Rungs>,
    pub(super) budget: Arc<Budget>,
    pub(super) cur: Vec<u8>,
    /// The bytes the member may still produce, by its declared size, or
    /// `u64::MAX` where it declares none: what the next buffer is sized for.
    pub(super) left: u64,
    /// Sealed with the member's ending; a member the walk abandons (its
    /// walk failed mid-member) is sealed by `Drop` with no ending of its
    /// own, which tells the caller's thread to wait for the walk's error.
    /// A slot its member's close already sealed keeps that ending.
    pub(super) sealed: bool,
}

impl ChainOut {
    /// Queue the bytes in hand, charged at the capacity of the buffer that
    /// holds them, and leave no buffer in hand.
    pub(super) fn hand_over(&mut self) -> io::Result<()> {
        let full = std::mem::take(&mut self.cur);
        if full.is_empty() {
            self.spares.put(full);
            return Ok(());
        }
        let cap = full.capacity() as u64;
        if !self.budget.take(cap) {
            self.spares.put(full);
            return Err(io::Error::other("the extraction has ended"));
        }
        self.left = self.left.saturating_sub(full.len() as u64);
        self.slot.push(full)
    }

    pub(super) fn seal(mut self, finish: Finish) {
        let _ = self.hand_over();
        self.sealed = true;
        self.slot.finish(finish);
    }
}

/// What a range's walk is told when the caller's thread has gone.
pub(super) fn ended() -> wide::Stop {
    wide::Stop::Accepted(Error::from(io::Error::other("the extraction has ended")))
}

impl ChainOut {
    /// Hand a stored member's range to the caller's thread
    /// (`read::handed`, [`Driver::hand_over`]): queued in the member's slot
    /// behind the chunks already there, with the bytes in hand in front
    /// of it, and waited for here, each piece it delivers told to `passed`
    /// in order. Nothing of the range is charged to the budget: it is
    /// never queued.
    ///
    /// The wait wakes every 50 ms to read the operation's stop flag, as
    /// [`Budget::take`] does, so a caller's thread that left without
    /// reaching the range cannot leave the walk parked.
    pub(super) fn hand(
        out: &mut ChainOut,
        range: handed::Range,
        passed: &mut dyn FnMut(handed::Passed) -> Result<()>,
    ) -> std::result::Result<(), wide::Stop> {
        let lead = std::mem::take(&mut out.cur);
        out.left = out.left.saturating_sub(lead.len() as u64);
        let (told, hear) = std::sync::mpsc::channel::<Told>();
        if let Err(back) = out.slot.push_range(Box::new(Ranged { range, lead, told })) {
            out.spares.put(back.lead);
            return Err(ended());
        }
        loop {
            match hear.recv_timeout(Duration::from_millis(50)) {
                Ok(Told::Passed(piece)) => {
                    out.left = out.left.saturating_sub(piece.len);
                    // An error here drops `hear`, which is what stops the
                    // caller's thread at its next piece.
                    passed(piece).map_err(wide::Stop::Accepted)?;
                }
                Ok(Told::End(outcome)) => return outcome,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if out.budget.stop.load(Ordering::Relaxed) {
                        return Err(ended());
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Err(ended()),
            }
        }
    }
}

impl Drop for ChainOut {
    fn drop(&mut self) {
        self.spares.put(std::mem::take(&mut self.cur));
        // Only a slot with NO ending is given the fatal one. A member the
        // walk refuses is closed with no writer (`Producer::close` seals
        // its slot there) while this writer is still alive, and it is
        // dropped after: finished again here, the slot lost the member's
        // own ending, the caller's thread read a fatal one, dropped the
        // member's error and took no member after it (4 Oct 2026).
        if !self.sealed {
            self.slot.fail_unsealed();
        }
    }
}

impl Write for ChainOut {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        if self.cur.len() == self.cur.capacity() {
            self.hand_over()?;
            // What the member declared it has left, a chunk at most; a
            // member that runs past its declaration takes whole chunks.
            let want = match self.left {
                0 => CHUNK,
                left => left.min(CHUNK as u64) as usize,
            };
            self.budget
                .room_for(1 << (rung_of(want) as u32 + RUNG_LOW), &self.spares);
            self.cur = self.spares.take(want);
        }
        let room = self.cur.capacity() - self.cur.len();
        let take = data.len().min(room);
        self.cur.extend_from_slice(&data[..take]);
        if self.cur.len() == self.cur.capacity() {
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

/// The driver the walk's worker runs: every member into a slot, announced
/// to the caller's thread the moment the walk reaches it.
pub(super) struct Producer {
    pub(super) tx: SyncSender<Item>,
    pub(super) spares: Arc<Rungs>,
    pub(super) budget: Arc<Budget>,
    /// The member between `open` and `close`, and whether no decoder
    /// claims it (`Driver::note_refused`).
    pub(super) current: Open,
    pub(super) refused: bool,
    /// The fragment mismatches of the member between `open` and `close`,
    /// carried to the caller's thread in its [`Finish`].
    pub(super) mismatches: Vec<u32>,
    /// Whether a stored member's ranges are handed to the caller's thread
    /// ([`stored_wide`]).
    pub(super) hands: bool,
}

impl Driver for Producer {
    type Out = ChainOut;

    fn hand_over(&self) -> Option<handed::HandOver<ChainOut>> {
        self.hands
            .then_some(ChainOut::hand as handed::HandOver<ChainOut>)
    }

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<ChainOut>> {
        let slot = Arc::new(Slot::default());
        if self
            .tx
            .send(Item::Member(
                Owned::of(member, Vec::new()),
                Arc::clone(&slot),
            ))
            .is_err()
        {
            return Err(Error::new(ErrorKind::Cancelled));
        }
        *self.current.borrow_mut() = Some(Arc::clone(&slot));
        self.refused = false;
        self.mismatches.clear();
        Ok(Disposition::Write(ChainOut {
            slot,
            spares: Arc::clone(&self.spares),
            budget: Arc::clone(&self.budget),
            cur: Vec::new(),
            left: member.unpacked_size.unwrap_or(u64::MAX),
            sealed: false,
        }))
    }

    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        out: Option<ChainOut>,
        outcome: &MemberOutcome,
        err: Option<Error>,
    ) -> Result<()> {
        let finish = Finish {
            bytes: outcome.bytes,
            verdict: None,
            checksum_ok: outcome.checksum_ok,
            error: err,
            // `refused` rides in `fatal`'s place for a member that is not
            // fatal at all; the deliverer reads it as the refusal it is.
            fatal: false,
            writer: out.is_some(),
            mismatches: std::mem::take(&mut self.mismatches),
        };
        let refused = std::mem::take(&mut self.refused);
        match out {
            Some(o) => {
                if refused {
                    o.slot.mark_refused();
                }
                o.seal(finish);
            }
            None => {
                if let Some(slot) = self.current.borrow_mut().take() {
                    if refused {
                        slot.mark_refused();
                    }
                    slot.finish(finish);
                }
            }
        }
        *self.current.borrow_mut() = None;
        Ok(())
    }

    /// Never reached: `open` gives every member a slot, and the caller's own
    /// `Skip` is answered on its thread (`deliver_all`). Settled as the
    /// slot's close would be, should a later `open` answer one.
    fn skipped(
        &mut self,
        member: &MemberInfo<'_>,
        outcome: &MemberOutcome,
        err: Option<Error>,
    ) -> Result<()> {
        self.close(member, None, outcome, err)
    }

    fn fragment_mismatch(&mut self, _member: &MemberInfo<'_>, volume: u32) -> Result<()> {
        self.mismatches.push(volume);
        Ok(())
    }

    fn note_refused(&mut self) {
        self.refused = true;
    }

    fn closed(&mut self) -> Closed {
        Closed::default()
    }
}

impl Slot {
    /// No decoder claims this member.
    pub(super) fn mark_refused(&self) {
        lock(&self.state).refused = true;
    }

    pub(super) fn was_refused(&self) -> bool {
        lock(&self.state).refused
    }
}

/// The most the solid path's queue may hold, by the capacity of its
/// buffers, when the policy allows more (see [`solid_queue_cap`]).
///
/// Priced timed on an Apple M1 Ultra (20 cores, 30 Sep 2026), `rarfast x`
/// of a solid `-m3` archive of 8,568 binaries in ONE binary through
/// [`SOLID_QUEUE_ENV`]: a 64 MiB queue read 2.27 to 2.29 s against the control's
/// 2.21 to 2.23, a 128 or 256 MiB one 2.21 to 2.24 (both at the limit's
/// quarter, 119 MiB), CPU level throughout. At the default the quarter
/// binds, so this ceiling only matters to a caller whose limit is above
/// 512 MiB.
pub(super) const SOLID_QUEUE_CEILING: u64 = 128 * MIB;

/// A bench knob: `RARKIT_SOLID_QUEUE_MIB=<n>` puts the ceiling at `n` MiB
/// (`0` leaves it where it is), so one binary measures every setting.
pub(crate) const SOLID_QUEUE_ENV: &str = "RARKIT_SOLID_QUEUE_MIB";

pub(super) fn solid_queue_ceiling() -> u64 {
    static CEILING: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *CEILING.get_or_init(|| {
        crate::knob::reader_var(SOLID_QUEUE_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|&n| n > 0)
            .map_or(SOLID_QUEUE_CEILING, |n| n.saturating_mul(MIB))
    })
}

/// The bytes the solid path may queue between the walk and the caller's
/// thread, counted by the CAPACITY of the buffers that hold them: a quarter
/// of the policy's working limit, the rest being the walk's own (its window,
/// the chain's decode-ahead, the reads), and never above
/// [`SOLID_QUEUE_CEILING`]. At least two chunks, so the walk can always hand
/// one over while the caller holds the other.
///
/// It was HALF the limit, 240 MiB at the default, counted by bytes written:
/// with the walk's own share beside it that was never inside the limit
/// (the solid extract to disk, held to the budget). A quarter,
/// by capacity, is 119 MiB at the default, 55 MiB at `-mm256m`.
pub(super) fn solid_queue_cap(policy: &MemoryPolicy) -> u64 {
    (policy.working_limit / 4)
        .min(solid_queue_ceiling())
        .max(2 * CHUNK as u64)
}

/// Whether the solid path hands a stored member's RANGES to the caller's
/// thread (`read::handed`), and how they are read: `RARKIT_SOLID_STORED_WIDE`.
/// `0` or `off` is the arrangement before 1 Oct 2026, every byte through
/// the queue; `1`, `on` or nothing hands them, read as [`handed::Dial`]'s
/// defaults say. The measuring arms, alone or joined by a colon: `seq` (one
/// reader in order), `wide` (the window's pieces at once), and a number of
/// 64 or more (the piece, in KiB), as in `seq:1024`. A RUNTIME knob, so
/// one binary measures every arm.
pub(crate) const SOLID_STORED_WIDE_ENV: &str = "RARKIT_SOLID_STORED_WIDE";

/// Whether ranges are handed when [`SOLID_STORED_WIDE_ENV`] says nothing.
pub(super) const SOLID_STORED_WIDE_DEFAULT: bool = true;

/// What `text` asks for: `None` for the queue, the dial otherwise
/// ([`handed::dial_of`]).
pub(super) fn stored_wide_of(text: Option<&str>) -> Option<handed::Dial> {
    handed::dial_of(
        text,
        SOLID_STORED_WIDE_DEFAULT.then(handed::Dial::default),
        handed::Dial::default(),
    )
}

pub(super) fn stored_wide_env() -> Option<handed::Dial> {
    static WIDE: std::sync::OnceLock<Option<handed::Dial>> = std::sync::OnceLock::new();
    *WIDE.get_or_init(|| {
        stored_wide_of(
            crate::knob::reader_var(SOLID_STORED_WIDE_ENV)
                .ok()
                .as_deref(),
        )
    })
}

#[cfg(feature = "test-support")]
pub(super) fn stored_wide() -> Option<handed::Dial> {
    match crate::probe::solid_stored_wide() {
        Some(false) => None,
        Some(true) => Some(handed::Dial {
            piece: crate::probe::solid_stored_piece(),
            in_order: crate::probe::solid_stored_in_order(),
        }),
        None => stored_wide_env(),
    }
}

#[cfg(not(feature = "test-support"))]
pub(super) fn stored_wide() -> Option<handed::Dial> {
    stored_wide_env()
}

/// What [`extract_solid`] did: the read, or nothing at all because the host
/// would not start the walk's thread, the volumes handed back untouched.
pub(super) enum Solid<V> {
    Ran(Result<ExtractReport>),
    NoThread(V),
}

/// The solid walk's open member, finished with a fatal ending if the walk
/// UNWINDS before giving it one, so the caller parked on its slot wakes.
///
/// A member's `ChainOut` seals its slot when it is dropped, but a member
/// the walk holds no writer for at that moment (between `Producer::open`
/// and its writer reaching the decode, or refused with none) has only this
/// to end it, and a panic there left the caller parked on the slot for
/// ever.
pub(super) struct SealOnUnwind(pub(super) Open);

impl Drop for SealOnUnwind {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }
        if let Some(slot) = self.0.try_borrow_mut().ok().and_then(|mut s| s.take()) {
            slot.fail_unsealed();
        }
    }
}

/// The caller's side of the solid path, UNWINDING (a sink or progress call
/// that panicked on this thread): the walk is told to stop and its queue is
/// drained, so it ends and the scope's join can return and carry the panic
/// on. Without it the walk waited in `Budget::take` or in a full queue's
/// `send` for a caller that had gone, and the scope waited on the walk.
pub(super) struct StopOnUnwind<'a> {
    pub(super) stop: &'a AtomicBool,
    pub(super) budget: &'a Budget,
    pub(super) rx: &'a Receiver<Item>,
    pub(super) spares: &'a Rungs,
}

impl Drop for StopOnUnwind<'_> {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }
        self.stop.store(true, Ordering::Relaxed);
        self.budget.room.notify_all();
        while let Ok(item) = self.rx.recv() {
            if let Item::Member(_, slot) = item {
                slot.abandon(self.spares);
            }
        }
    }
}

/// `extract` over a SOLID archive with the walk on a scoped worker and the
/// caller's thread delivering.
///
/// A panic on EITHER thread reaches the caller as a panic, unchanged, once
/// both threads are finished with (SPEC-API 2.1: a caller's own panic
/// inside a trait method propagates unchanged, and the walk runs the
/// caller's source and volumes). Neither thread is left parked.
pub(super) fn extract_solid<V: Volumes, K: Sink, P: Progress>(
    volumes: V,
    ctx: &mut ReadCtx,
    sink: &mut K,
    progress: &mut P,
) -> Solid<V> {
    let stop = Arc::new(AtomicBool::new(false));
    let cap = solid_queue_cap(&ctx.options.memory);
    let budget = Arc::new(Budget {
        held: Mutex::new(0),
        room: Condvar::new(),
        cap,
        stop: Arc::clone(&stop),
        limit: ctx
            .options
            .memory
            .limit_named
            .then_some(ctx.options.memory.working_limit),
        #[cfg(feature = "test-support")]
        peak: AtomicU64::new(0),
    });
    // What the queue holds, and the buffer in the walk's hands and the one
    // in the caller's: the most the pool keeps alive.
    let spares = Arc::new(Rungs::new(cap.saturating_add(2 * CHUNK as u64)));
    let cancel = ctx.options.cancel.clone();
    // Read here, on the caller's thread, where a test's dial is set.
    let stored = stored_wide();
    let (tx, rx) = sync_channel::<Item>(queue_depth());
    std::thread::scope(|scope| {
        let walker = {
            let budget = Arc::clone(&budget);
            let spares = Arc::clone(&spares);
            let tx = tx.clone();
            // The operation's meter follows its threads (API 8.4.1, `memory::Meter`).
            let op = crate::memory::op_slot();
            let started =
                crate::threads::scoped_with(scope, (volumes, ctx), move |(volumes, ctx)| {
                    let _op = crate::memory::enter(op);
                    let _giver = {
                        let (budget, spares) = (Arc::clone(&budget), Arc::clone(&spares));
                        crate::memory::lend_giver(Box::new(move || budget.drain(&spares)))
                    };
                    let open = Open::default();
                    let _seal = SealOnUnwind(std::rc::Rc::clone(&open));
                    let mut producer = Producer {
                        tx: tx.clone(),
                        spares,
                        budget,
                        current: std::rc::Rc::clone(&open),
                        refused: false,
                        mismatches: Vec::new(),
                        hands: stored.is_some(),
                    };
                    let mut relay = Relay {
                        tx: tx.clone(),
                        open,
                    };
                    let outcome = extract::extract_driven(volumes, ctx, &mut producer, &mut relay);
                    drop(producer);
                    let _ = tx.send(Item::End(outcome));
                });
            match started {
                Ok(walker) => walker,
                // The host would not start the walk's thread: nothing has
                // been read or delivered, and the caller's thread walks.
                Err((volumes, _)) => return Solid::NoThread(volumes),
            }
        };
        drop(tx);
        let unwinding = StopOnUnwind {
            stop: &stop,
            budget: &budget,
            rx: &rx,
            spares: &spares,
        };
        let delivered = deliver_all(
            &rx,
            sink,
            progress,
            &budget,
            &spares,
            cancel.as_deref(),
            stored.unwrap_or_default(),
        );
        drop(unwinding);
        // Whatever happened on this side, the walk is told to stop and its
        // queue is drained, so it can never block on a caller that left.
        if delivered.is_err() {
            stop.store(true, Ordering::Relaxed);
            budget.room.notify_all();
        }
        let mut end = None;
        while let Ok(item) = rx.recv() {
            match item {
                Item::End(r) => end = Some(r),
                Item::Member(_, slot) => {
                    slot.abandon(&spares);
                }
                _ => {}
            }
        }
        let walked = walker.join();
        #[cfg(feature = "test-support")]
        {
            crate::probe::note_solid_ahead(budget.peak.load(Ordering::Relaxed));
            let (peak, out) = spares.seen();
            crate::probe::note_solid_pool(peak, out);
        }
        if let Err(panic) = walked {
            // Both threads are finished with: the walk's panic is the
            // caller's to see, as it would be on the walking thread.
            std::panic::resume_unwind(panic);
        }
        Solid::Ran(solid_report(delivered, end, cap, &budget))
    })
}

/// The solid path's report, from what the caller's thread delivered and
/// the walk's own ending.
pub(super) fn solid_report(
    delivered: Result<Delivered>,
    end: Option<Result<ExtractReport>>,
    cap: u64,
    budget: &Budget,
) -> Result<ExtractReport> {
    let (members, failures, deferred, end_from_loop) = delivered?;
    let report = match end_from_loop.or(end) {
        Some(r) => r?,
        None => {
            return Err(Error::new(ErrorKind::Corrupt(
                crate::error::Corruption::Stream,
            )))
        }
    };
    if let Some(e) = deferred {
        return Err(e);
    }
    Ok(ExtractReport {
        members,
        bytes: report.bytes,
        checksum_failures: failures,
        damaged_headers: report.damaged_headers,
        peak_working_memory: report
            .peak_working_memory
            .saturating_add(cap.min(budget_high_water(budget))),
    })
}

#[cfg(feature = "test-support")]
pub(super) fn budget_high_water(b: &Budget) -> u64 {
    b.peak.load(Ordering::Relaxed)
}

#[cfg(not(feature = "test-support"))]
pub(super) fn budget_high_water(b: &Budget) -> u64 {
    b.cap
}

pub(super) type Delivered = (u64, u64, Option<Error>, Option<Result<ExtractReport>>);

/// The caller's thread: every member in archive order, as the sequential
/// path hands it over, and the walk's progress between them.
pub(super) fn deliver_all<K: Sink, P: Progress>(
    rx: &Receiver<Item>,
    sink: &mut K,
    progress: &mut P,
    budget: &Budget,
    spares: &Rungs,
    cancel: Option<&AtomicBool>,
    dial: handed::Dial,
) -> Result<Delivered> {
    let mut members = 0u64;
    let mut failures = 0u64;
    let mut deferred: Option<Error> = None;
    let spin = concurrent::settle_spin_us();
    // The slab a stored member's ranges are cut on (`read::handed`): one
    // for the operation, and nothing until a range arrives.
    let mut cutter = handed::Cutter::new(dial);
    while let Ok(item) = rx.recv() {
        match item {
            Item::Note(note) => note.tell(progress)?,
            Item::End(r) => return Ok((members, failures, deferred, Some(r))),
            Item::Member(info, slot) => {
                let view = info.view();
                let disposition = sink.open(&view)?;
                let (mut writer, skip) = match disposition {
                    Disposition::Write(w) => (Some(w), false),
                    Disposition::Verify => (None, false),
                    Disposition::Skip => (None, true),
                };
                // The bytes this member's writer has been given straight
                // from chunks, which its first range is cut to meet.
                let mut given = 0u64;
                let finish = loop {
                    match slot.next(spin) {
                        Next::Chunk(buf) => {
                            // Given back as it was charged: by capacity.
                            let n = buf.capacity() as u64;
                            let wrote = match writer.as_mut() {
                                // Behind a range of the same member, its
                                // bytes keep to the range's pieces.
                                Some(w) if cutter.cutting() => cutter.put(w, &buf),
                                Some(w) => {
                                    given += buf.len() as u64;
                                    w.write_all(&buf)
                                }
                                None => Ok(()),
                            };
                            spares.put(buf);
                            budget.give(n);
                            wrote.map_err(Error::from)?;
                            if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                                return Err(Error::new(ErrorKind::Cancelled));
                            }
                        }
                        Next::Note(note) => note.tell(progress)?,
                        Next::Range(ranged) => {
                            let Ranged { range, lead, told } = *ranged;
                            #[cfg(feature = "test-support")]
                            crate::probe::note_solid_stored_range();
                            // The walk has stopped listening: an error of
                            // its own, which its ending of the member
                            // carries. Not this thread's to raise.
                            let mut deaf = false;
                            let outcome = cutter.deliver(
                                &range,
                                &lead,
                                writer.as_mut(),
                                given,
                                None,
                                &mut |piece| {
                                    if told.send(Told::Passed(piece)).is_err() {
                                        deaf = true;
                                        return Err(Error::new(ErrorKind::Cancelled));
                                    }
                                    // What the walk reported for the pieces
                                    // before this one, while it is fresh.
                                    while let Some(note) = slot.take_note() {
                                        note.tell(progress)?;
                                    }
                                    if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                                        return Err(Error::new(ErrorKind::Cancelled));
                                    }
                                    Ok(())
                                },
                            );
                            spares.put(lead);
                            match outcome {
                                Err(wide::Stop::Accepted(_)) if deaf => {}
                                // The caller's own: its writer, its
                                // `Progress` or its cancel flag. It ends
                                // the operation from here, as a chunk's
                                // failed write does, and dropping `told`
                                // is what releases the walk.
                                Err(wide::Stop::Accepted(e)) => return Err(e),
                                other => {
                                    let _ = told.send(Told::End(other.map(|_| ())));
                                }
                            }
                        }
                        Next::Done(f) => break f,
                    }
                };
                // A member cut on the slab has its last, short write here.
                cutter.finish(writer.as_mut()).map_err(Error::from)?;
                if finish.fatal {
                    // The walk failed inside this member, after its `open`,
                    // exactly where the sequential path fails: its error is
                    // the walk's own, and it arrives as the walk's end.
                    loop {
                        match rx.recv() {
                            Ok(Item::End(r)) => return Ok((members, failures, deferred, Some(r))),
                            Ok(Item::Note(note @ (Note::Released(..) | Note::VolumeDone(_)))) => {
                                note.tell(progress)?
                            }
                            // A member AFTER a fatal ending: the walk did
                            // not end there after all. Nobody will read
                            // this member, so its slot takes no more and
                            // the walk is told to stop, as it is when this
                            // thread leaves on an error (`extract_solid`):
                            // left unread, its bytes filled the budget
                            // and both threads waited for ever.
                            Ok(Item::Member(_, unread)) => {
                                unread.abandon(spares);
                                budget.stop.store(true, Ordering::Relaxed);
                                budget.room.notify_all();
                            }
                            Ok(_) => {}
                            Err(_) => return Ok((members, failures, deferred, None)),
                        }
                    }
                }
                let refused = slot.was_refused();
                let Finish {
                    bytes,
                    checksum_ok,
                    error,
                    writer: gives_writer,
                    mismatches,
                    ..
                } = finish;
                members += 1;
                let outcome = if skip {
                    // What the sequential path counts a SKIPPED solid
                    // member as: it is decoded (the chain needs it) but
                    // put nowhere, so it has no verdict unless no decoder
                    // claims it or its decode failed.
                    MemberOutcome {
                        checksum_ok: (refused || error.is_some()).then_some(false),
                        bytes,
                        password_refused: crate::read::password_refused(error.as_ref()),
                        fragment_mismatches: 0,
                    }
                } else {
                    for &volume in &mismatches {
                        sink.fragment_mismatch(&view, volume)?;
                    }
                    MemberOutcome {
                        checksum_ok,
                        bytes,
                        password_refused: crate::read::password_refused(error.as_ref()),
                        fragment_mismatches: u32::try_from(mismatches.len()).unwrap_or(u32::MAX),
                    }
                };
                if outcome.checksum_ok == Some(false) {
                    failures += 1;
                }
                // A skipped member is counted above and its failure kept,
                // and the caller hears nothing more of it (SPEC-API 4.4).
                if !skip {
                    let out = if gives_writer { writer } else { None };
                    sink.close(&view, out, &outcome)?;
                }
                if deferred.is_none() {
                    deferred = error;
                }
            }
        }
    }
    Ok((members, failures, deferred, None))
}

#[cfg(test)]
mod refused_member_ending {
    use super::*;

    /// A member the walk refuses is closed with NO writer while the writer
    /// its `open` was given is still alive, and that writer is dropped
    /// afterwards (`extract::refuse`). The slot keeps the ending its close
    /// gave: read as fatal, the caller's thread lost the member's error
    /// and stopped delivering (bug sweep H-5, 4 Oct 2026).
    ///
    /// One thread, no pool: nothing here assumes a width or a memory limit.
    #[test]
    fn a_writer_dropped_after_its_member_s_close_keeps_the_close_s_ending() {
        let (tx, rx) = sync_channel::<Item>(4);
        let stop = Arc::new(AtomicBool::new(false));
        let mut producer = Producer {
            tx,
            spares: Arc::new(Rungs::new(2 * CHUNK as u64)),
            budget: Arc::new(Budget {
                held: Mutex::new(0),
                room: Condvar::new(),
                cap: 2 * CHUNK as u64,
                stop,
                limit: None,
                #[cfg(feature = "test-support")]
                peak: AtomicU64::new(0),
            }),
            current: Open::default(),
            refused: false,
            mismatches: Vec::new(),
            hands: false,
        };
        let info = MemberInfo {
            name: b"refused",
            is_directory: false,
            unpacked_size: Some(10),
            packed_size: 10,
            split_before: false,
            split_after: false,
            encrypted: true,
            password_checked: true,
            mtime: None,
            attributes: 0,
            host_os: Default::default(),
            checksum: None,
            method: crate::Method::Stored,
            dictionary: None,
            solid: true,
            algorithm_version: 0,
            data: 0..10,
            redirection: None,
            file_version: None,
        };
        let outcome = MemberOutcome {
            checksum_ok: Some(false),
            bytes: 0,
            password_refused: true,
            fragment_mismatches: 0,
        };
        // As `extract::member` holds it across `refuse`.
        let disposition = producer.open(&info).expect("the queue is open");
        producer
            .close(
                &info,
                None,
                &outcome,
                Some(Error::new(ErrorKind::WrongPassword)),
            )
            .expect("close");
        drop(disposition);
        let Ok(Item::Member(_, slot)) = rx.recv() else {
            panic!("the member was not announced");
        };
        let Next::Done(finish) = slot.next(0) else {
            panic!("a refused member queued something before its ending");
        };
        assert!(
            !finish.fatal,
            "the writer's drop replaced the member's ending with a fatal one"
        );
        assert!(
            matches!(
                finish.error.as_ref().map(Error::kind),
                Some(ErrorKind::WrongPassword)
            ),
            "the member's own error was lost"
        );
        assert_eq!(finish.checksum_ok, Some(false));
        assert!(!finish.writer, "a refused member's close hands no writer");
    }

    /// A sink that keeps nothing.
    struct Nowhere;

    impl Sink for Nowhere {
        type Out = Vec<u8>;

        fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
            Ok(Disposition::Write(Vec::new()))
        }

        fn close(
            &mut self,
            _member: &MemberInfo<'_>,
            _out: Option<Vec<u8>>,
            _outcome: &MemberOutcome,
        ) -> Result<()> {
            Ok(())
        }
    }

    fn info(name: &'static [u8], size: u64) -> MemberInfo<'static> {
        MemberInfo {
            name,
            is_directory: false,
            unpacked_size: Some(size),
            packed_size: size,
            split_before: false,
            split_after: false,
            encrypted: false,
            password_checked: false,
            mtime: None,
            attributes: 0,
            host_os: Default::default(),
            checksum: None,
            method: crate::Method::Stored,
            dictionary: None,
            solid: true,
            algorithm_version: 0,
            data: 0..size,
            redirection: None,
            file_version: None,
        }
    }

    /// The caller's thread, waiting for the walk's end after a FATAL
    /// ending, meets a member the walk went on to: it abandons the member
    /// and tells the walk to stop. Left unread, that member's bytes filled
    /// the budget, the walk waited for room nobody would give and this
    /// thread waited for an end the walk would never send.
    ///
    /// Two threads, this one delivering and one standing in for the walk;
    /// a budget of two chunks and six chunks written, 6 MiB at most alive.
    #[test]
    fn a_member_after_a_fatal_ending_is_abandoned_and_the_walk_released() {
        let (tx, rx) = sync_channel::<Item>(8);
        let stop = Arc::new(AtomicBool::new(false));
        let budget = Arc::new(Budget {
            held: Mutex::new(0),
            room: Condvar::new(),
            cap: 2 * CHUNK as u64,
            stop: Arc::clone(&stop),
            limit: None,
            #[cfg(feature = "test-support")]
            peak: AtomicU64::new(0),
        });
        let spares = Arc::new(Rungs::new(4 * CHUNK as u64));
        let (done, heard) = std::sync::mpsc::channel();
        let walk = {
            let (budget, spares) = (Arc::clone(&budget), Arc::clone(&spares));
            std::thread::spawn(move || {
                let mut producer = Producer {
                    tx: tx.clone(),
                    spares,
                    budget,
                    current: Open::default(),
                    refused: false,
                    mismatches: Vec::new(),
                    hands: false,
                };
                // A member whose writer goes with no ending: fatal.
                let first = info(b"first", 10);
                drop(producer.open(&first).expect("the queue is open"));
                // And the walk carries on into a member three times the
                // budget, which is the mistake this guards.
                let size = 6 * CHUNK as u64;
                let second = info(b"second", size);
                let Ok(Disposition::Write(mut out)) = producer.open(&second) else {
                    panic!("the second member was not opened");
                };
                let wrote = out.write_all(&vec![7u8; size as usize]);
                drop(out);
                let _ = done.send(wrote.is_err());
                let _ = tx.send(Item::End(Err(Error::new(ErrorKind::Cancelled))));
            })
        };
        let delivering = std::thread::spawn(move || {
            let delivered = deliver_all(
                &rx,
                &mut Nowhere,
                &mut (),
                &budget,
                &spares,
                None,
                handed::Dial::default(),
            );
            delivered.map(|(members, _, _, end)| (members, end.is_some()))
        });
        let refused = heard
            .recv_timeout(Duration::from_secs(60))
            .expect("the walk is PARKED on a member nobody reads");
        assert!(refused, "the unread member's writer took every byte");
        assert!(
            stop.load(Ordering::Relaxed),
            "the walk was not told to stop"
        );
        walk.join().expect("the walk's thread");
        let (members, ended) = delivering
            .join()
            .expect("the delivering thread")
            .expect("the delivery");
        assert_eq!(members, 0, "no member was closed");
        assert!(ended, "the delivery ended on the walk's own end");
    }
}
