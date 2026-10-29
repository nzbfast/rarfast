//! What crosses between the walking thread and a worker: the task, the
//! answer, the pipe a member's bytes come back through, and the worker
//! thread itself.

use super::*;

// ---------------------------------------------------------------------------
// The walk's writer for a member a worker only WRITES
// ---------------------------------------------------------------------------

/// The way back from a piped member's writing worker to the thread
/// decoding it, for the one thing the worker learns that the decode must
/// act on: the caller's own writer refusing.
///
/// **Why it has to exist.** Spec F 3.7.6 makes the caller what stops an
/// extraction, and on the sequential path the WRITER is one of the things
/// that does it: `extract::emit` calls `write_all` and returns what it
/// answers, so a refused member's decode ends within one chunk. A member
/// whose writes are pipelined onto a worker had no way back at all - the
/// worker recorded the refusal and went on draining until the member
/// ended, so the walk decoded every byte the header declared first. On a
/// `DATA.BIN` declaring 2,634,043,104 bytes that cost about eight seconds
/// at every ceiling, INCLUDING a ceiling of zero where the very first
/// write was refused, against 0.2 ms sequentially
/// (measured; `tests/parallel.rs`
/// `a_refused_write_stops_a_piped_member_s_decode`).
///
/// **Why it carries the error and not just a flag.** The walking thread
/// raises the caller's OWN `io::Error`, so a refused member ends in the
/// same error object the sequential path would have raised for it, not
/// merely in the same kind. The error is moved, never copied, and
/// whichever of the two threads reaches it first is the one that reports
/// it: the walk when the decode is still running, which is the case this
/// exists for, and the worker's own answer when the member had already
/// ended before its last chunk was written.
#[derive(Default)]
pub(super) struct Refusal {
    /// Read once per chunk by the walking thread, so the common case
    /// costs one relaxed-ordered load and no lock.
    pub(super) refused: AtomicBool,
    pub(super) error: Mutex<Option<io::Error>>,
}

impl Refusal {
    /// Record what the caller's writer answered.
    pub(super) fn refuse(&self, e: io::Error) {
        *self.error.lock().unwrap_or_else(|p| p.into_inner()) = Some(e);
        // Stored AFTER the error, and released, so a thread that sees the
        // flag set sees the error beside it.
        self.refused.store(true, Ordering::Release);
    }

    /// Whether the caller's writer has refused.
    pub(super) fn refused(&self) -> bool {
        self.refused.load(Ordering::Acquire)
    }

    /// The caller's error, for whichever thread reports this member.
    ///
    /// It leaves the slot, so the second caller gets the stand-in rather
    /// than a second copy of one error: a member is reported once.
    pub(super) fn take(&self) -> io::Error {
        self.error
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
            .unwrap_or_else(|| io::Error::other("the caller's writer refused this member"))
    }
}

/// The writer the WALK sees for a member it decodes itself: it hands
/// decoded bytes to a worker rather than to the caller's own writer.
pub(crate) struct Handoff {
    pub(super) tx: Option<SyncSender<Vec<u8>>>,
    pub(super) ret: Receiver<Vec<u8>>,
    pub(super) current: Option<Vec<u8>>,
    /// The worker draining it, so `close` knows whose answer to wait for.
    pub(super) worker: usize,
    /// What that worker answers with when the caller's writer refuses.
    pub(super) refusal: Arc<Refusal>,
}

impl Handoff {
    /// The next empty buffer: one the worker has returned, or a new one
    /// when the pool has not filled yet.
    pub(super) fn take(&mut self) -> Vec<u8> {
        match self.ret.recv() {
            Ok(mut buf) => {
                buf.clear();
                buf
            }
            // The worker is gone, which its answer will report; the writes
            // that follow go nowhere and the member's outcome is unchanged.
            Err(_) => Vec::with_capacity(CHUNK),
        }
    }

    pub(super) fn flush_chunk(&mut self) {
        let Some(mut buf) = self.current.take() else {
            return;
        };
        if buf.is_empty() {
            self.current = Some(buf);
            return;
        }
        let Some(tx) = &self.tx else {
            // No worker to hand it to: the bytes go nowhere and the buffer
            // is filled again, so a writer that has lost its worker costs
            // one buffer and not one per chunk.
            buf.clear();
            self.current = Some(buf);
            return;
        };
        if tx.send(buf).is_err() {
            // The worker ended early, which its answer reports. Stop
            // sending rather than meeting the closed channel once a chunk.
            self.tx = None;
            self.current = Some(Vec::new());
            return;
        }
        self.current = Some(self.take());
    }
}

impl Write for Handoff {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        // Asked BEFORE the bytes are taken, so a decode that is already
        // refused produces nothing more. This is the whole of the
        // promptness: the decoder meets the caller's error here, at the
        // next chunk, exactly as it meets it in `emit` on the sequential
        // path.
        if self.refusal.refused() {
            return Err(self.refusal.take());
        }
        if self.current.is_none() {
            self.current = Some(self.take());
        }
        let buf = self.current.as_mut().expect("filled above");
        let room = CHUNK.saturating_sub(buf.len()).max(1);
        let take = data.len().min(room);
        buf.extend_from_slice(&data[..take]);
        if buf.len() >= CHUNK {
            self.flush_chunk();
        }
        Ok(take)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_chunk();
        Ok(())
    }
}

/// What the WALK writes a member's decoded bytes into.
///
/// One type, two futures: a member the pool is about to take whole carries
/// the caller's own writer untouched, because the worker will do the
/// writing; a member the walk decodes itself hands its bytes to a worker
/// through [`Handoff`]. The walk never writes into a `Carried`, and a
/// `Carried` that IS written into - a member the pool offered to take and
/// then did not - writes straight through to the caller, which is correct
/// and merely unpipelined.
pub(crate) enum PoolOut<W> {
    Piped(Handoff),
    Carried(W),
}

impl<W: Write> Write for PoolOut<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        match self {
            PoolOut::Piped(h) => h.write(data),
            PoolOut::Carried(w) => w.write(data),
        }
    }

    fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            PoolOut::Piped(h) => h.write_all(data),
            PoolOut::Carried(w) => w.write_all(data),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            PoolOut::Piped(h) => h.flush(),
            PoolOut::Carried(w) => w.flush(),
        }
    }
}

// ---------------------------------------------------------------------------
// The workers
// ---------------------------------------------------------------------------

/// What a worker is asked to do.
pub(super) enum Task<W> {
    /// Read this member's own byte range, decode it and write it, with
    /// `width` tape lanes at most: the share of `max_workers` the pool
    /// granted this member when it dispatched it (8.3, and `inner_width`).
    Decode {
        job: Box<Job<PoolOut<W>>>,
        width: usize,
        /// Rebuild a held ring larger than this member reaches at its
        /// reach ([`Bench::set_exact`]).
        exact: bool,
    },
    /// Several small members, each decoded as `Decode` would and each
    /// answered on its own, in the order given.
    Batch {
        jobs: Vec<Job<PoolOut<W>>>,
        width: usize,
        exact: bool,
    },
    /// Write the bytes arriving on `chunks` into the caller's writer. The
    /// decode is the walking thread's.
    Pipe {
        out: W,
        chunks: Receiver<Vec<u8>>,
        ret: SyncSender<Vec<u8>>,
        refusal: Arc<Refusal>,
    },
}

/// What a worker answers with.
/// A verdict whose CRC32 the DELIVERER runs ([`Bench::decode_with`]).
pub(crate) struct Unfinished {
    pub(super) member: Member<()>,
    pub(super) file: FileHdr,
}

impl Unfinished {
    /// The member's integrity verdict, with the CRC32 of every byte it
    /// produced, folded in order by whoever delivered them.
    pub(crate) fn finish(mut self, crc: crate::checksum::Crc32) -> Option<bool> {
        self.member.attach_crc(crc);
        extract::verdict(&self.member, &mut None, &self.file, false)
    }
}

pub(crate) struct Done<W> {
    /// The verdict, when its CRC32 was left to the deliverer.
    pub(crate) verdict: Option<Box<Unfinished>>,
    /// The caller's own writer, handed back for its `close`.
    pub(crate) out: Option<W>,
    /// Decoded bytes this member produced, which the report counts.
    pub(crate) bytes: u64,
    /// The member's integrity verdict, for a decode task.
    pub(crate) checksum_ok: Option<bool>,
    /// The error this member met, kept for the report in archive order.
    pub(crate) error: Option<Error>,
    /// Whether that error ends the whole operation rather than one member.
    pub(crate) fatal: bool,
    /// A split member (`extract::Split`) the WALK stopped before its last
    /// fragment: the walk's own error is the operation's, returned right
    /// after the pool settles, so this member neither closes nor reports
    /// one of its own. That is what the walk's own read of it did: the
    /// failure met crossing to the next fragment ended the operation
    /// inside the member, with no `close`.
    pub(crate) yielded: bool,
    /// The name buffer, back for the next job.
    pub(crate) name: Vec<u8>,
    /// A split member's leading fragments whose CRC32 field disagreed
    /// (spec F 3.5.6), by volume, told to the sink before its `close`.
    pub(crate) mismatches: Vec<u32>,
    /// Buffers a pipe task still held, back for the pool.
    pub(crate) spare: Vec<Vec<u8>>,
    /// What this worker's decoders and scratch buffers hold now.
    pub(crate) working: u64,
}

/// Write one member's decoded bytes as the walking thread produces them.
pub(super) fn pipe<W: Write>(
    mut out: W,
    chunks: Receiver<Vec<u8>>,
    ret: SyncSender<Vec<u8>>,
    working: u64,
    refusal: &Refusal,
) -> Done<W> {
    let mut failed = false;
    let mut spare = Vec::new();
    while let Ok(mut buf) = chunks.recv() {
        if !failed {
            if let Err(e) = out.write_all(&buf) {
                failed = true;
                // Told to the decoding thread FIRST, before this loop
                // takes another chunk: it is decoding this member now and
                // the refusal is what stops it (spec F 3.7.6).
                refusal.refuse(e);
            }
        }
        buf.clear();
        // Hand it back while there is room, and keep it otherwise: either
        // way the pool gets it when this answer arrives.
        match ret.try_send(buf) {
            Ok(()) => {}
            Err(std::sync::mpsc::TrySendError::Full(buf))
            | Err(std::sync::mpsc::TrySendError::Disconnected(buf)) => spare.push(buf),
        }
    }
    // A write the CALLER's own writer refused is the caller's error and
    // ends the run, exactly as it does on the sequential path where
    // `write_all` returns it into `emit`. The walking thread raises it
    // instead whenever it was still decoding when the refusal arrived,
    // which is the case this member was piped for; `Refusal::take` is
    // what settles which of the two has it.
    let error = failed.then(|| Error::caller(refusal.take()));
    let fatal = failed;
    Done {
        verdict: None,
        out: Some(out),
        bytes: 0,
        checksum_ok: None,
        error,
        fatal,
        yielded: false,
        name: Vec::new(),
        mismatches: Vec::new(),
        spare,
        working,
    }
}

/// What a worker tells the walk beside its answer.
#[derive(Clone)]
pub(super) struct Notes {
    /// Set when an answer ENDS THE OPERATION, before that answer is sent:
    /// a pool that queues ([`QUEUE_OWN_ENV`]) reads it at every member, so
    /// the walk stops opening members behind a failure it has not yet
    /// reached in the queue.
    pub(super) failed: Arc<AtomicBool>,
    /// The walking thread, unparked after every answer under
    /// [`WAIT_ANY_ENV`]; `None` with the knob off.
    pub(super) walker: Option<std::thread::Thread>,
}

/// One worker thread's whole life.
pub(super) struct Hand<'scope, W> {
    pub(super) tasks: SyncSender<Task<W>>,
    pub(super) answers: Receiver<Done<W>>,
    pub(super) handle: ScopedJoinHandle<'scope, ()>,
    /// The decode window this worker has committed to, which is what the
    /// memory bound of SPEC-API 5.2 is computed over.
    pub(super) held: u64,
    /// What it reported holding when it last answered.
    pub(super) working: u64,
    /// Answers it still owes: one for a decode or a pipe, one per member
    /// for a batch. It is free again only at zero.
    pub(super) owed: usize,
}

/// A worker's next task, WITHOUT parking for it where parking would cost
/// more than the wait ([`TASK_SPIN_US`]).
///
/// Nothing about what a worker does changes here: the same tasks arrive
/// from the same channel in the same order, and `None` is the closed
/// channel exactly as `recv`'s error was. Only the way of waiting is
/// different, and the wait that is removed is the one the sender pays for.
pub(super) fn next_task<W>(tasks: &Receiver<Task<W>>, spin: u64) -> Option<Task<W>> {
    next_on(tasks, spin)
}

/// [`next_task`] for any task type: the sequential driver's workers
/// (`read::sequential`) wait for their tasks the same way.
pub(crate) fn next_on<T>(tasks: &Receiver<T>, spin: u64) -> Option<T> {
    #[cfg(feature = "wait-census")]
    let _census = crate::probe::census::at(crate::probe::census::WORKER_IDLE);
    let mut sweep = super::super::spin::Spin::new(spin);
    if sweep.parks_at_once() {
        return tasks.recv().ok();
    }
    loop {
        match tasks.try_recv() {
            Ok(task) => return Some(task),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => return None,
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
        if sweep.over() {
            // Past the budget, or the box took the core: park.
            return tasks.recv().ok();
        }
        std::hint::spin_loop();
    }
}

/// A worker for one slot, or `None` when the host will not start its
/// thread (`crate::threads`): the pool then runs without that slot.
pub(super) fn spawn<'scope, 'env, W: Write + Send + 'env>(
    scope: &'scope Scope<'scope, 'env>,
    policy: MemoryPolicy,
    cancel: Option<Arc<AtomicBool>>,
    budget: Option<Arc<crate::read::lanes::LaneBudget>>,
    answers_depth: usize,
    width_stated: bool,
    notes: Notes,
) -> Option<Hand<'scope, W>>
where
    'env: 'scope,
{
    let (tasks, task_rx) = sync_channel::<Task<W>>(1);
    // Deep enough for a whole batch, so a worker never waits on the walk
    // to take one member's answer before it decodes the next.
    let (answer_tx, answers) = sync_channel::<Done<W>>(answers_depth.max(1));
    // Read HERE, on the walking thread the pool spawns from, and carried
    // into the worker: the bench seam behind it is a thread-local of the
    // caller's, and a worker cannot see one.
    let spin = task_spin_us();
    // The operation's meter follows its threads (API 8.4.1, `memory::Meter`).
    let op = crate::memory::op_slot();
    let handle = crate::threads::scoped(scope, move || {
        let _op = crate::memory::enter(op);
        let mut decoders = Decoders::default();
        // Under a NAMED budget, and under the whole-process default
        // (`MemoryPolicy::keeps_residency`), a worker gives every dropped
        // ring back (Shrink::Tight), as the walk and the look-ahead do: a
        // ring freed into the allocator's cache is resident memory the
        // budget does not see.
        if policy.keeps_residency() {
            decoders.shrink = extract::Shrink::Tight;
        }
        #[cfg(feature = "parallel")]
        {
            decoders.budget = budget;
        }
        decoders.width_stated = width_stated;
        let mut bench = Bench {
            decoders,
            scratch: Scratch::default(),
            blake: None,
            read_buf: Vec::new(),
            policy,
            cancel,
            charge: crate::memory::Held::default(),
        };
        // An answer told to the walk beyond its channel ([`Notes`]).
        let tell = |done: &Done<W>| {
            if done.fatal {
                notes.failed.store(true, Ordering::Release);
            }
        };
        let wake = || {
            if let Some(walker) = &notes.walker {
                walker.unpark();
            }
        };
        while let Some(task) = next_task(&task_rx, spin) {
            let done = match task {
                Task::Decode { job, width, exact } => {
                    bench.set_exact(exact);
                    bench.decode(*job, width)
                }
                Task::Batch { jobs, width, exact } => {
                    bench.set_exact(exact);
                    let mut gone = false;
                    for job in jobs {
                        if gone {
                            // The walk has gone; the rest are dropped
                            // undecoded, as a closed channel drops a task.
                            continue;
                        }
                        let done = bench.decode(job, width);
                        tell(&done);
                        gone = answer_tx.send(done).is_err();
                        wake();
                    }
                    if gone {
                        break;
                    }
                    continue;
                }
                Task::Pipe {
                    out,
                    chunks,
                    ret,
                    refusal,
                } => pipe(out, chunks, ret, bench.working(), &refusal),
            };
            tell(&done);
            if answer_tx.send(done).is_err() {
                break;
            }
            wake();
        }
    })
    .ok()?;
    Some(Hand {
        tasks,
        answers,
        handle,
        held: 0,
        working: 0,
        owed: 0,
    })
}
