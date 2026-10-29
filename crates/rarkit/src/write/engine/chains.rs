//! The cipher chains: stored members of an encrypted run enciphered AHEAD
//! of the one the writing thread is placing.

use super::*;

impl<'a, 'p, V: VolumeSource, P: Progress> Run<'a, 'p, V, P> {
    // ---- chains ahead ---------------------------------------------------

    /// Whether this run may encipher stored members AHEAD of the one
    /// being written (`cipher_chain`), with how many chains and how much
    /// held ciphertext.
    ///
    /// What it reaches, under `WriteOptions::encrypted_read_ahead` (SPEC-API
    /// 7.1: without it no reader is read ahead): a stored (`-m0`) RAR 5
    /// archive with a password, an output that can be patched, no recovery
    /// record, not solid, not the reference layout; one archive with or
    /// without encrypted headers, and a volume set without them (under
    /// header encryption a volume boundary draws header vectors between
    /// two members' own, spec G 3.13); and at
    /// least two helper threads (the member being written
    /// spends one on its chain and each chain ahead one more, two where a
    /// chain reads on a thread of its own). Everything else is today's
    /// walk, and so is a width of one.
    ///
    /// The held ciphertext is charged to the working limit: the policy's
    /// `working_limit`, less [`CHAINS_BESIDE`] for everything else the
    /// process holds, which under a named `-mm` is the caller's ceiling.
    pub(super) fn choose_chains(&mut self) {
        if !self.options.encrypted_read_ahead {
            return;
        }
        let (chains, cap) = chains_knob();
        if chains == 0
            || !self.options.stored()
            || !matches!(self.key, ArchiveKey::Rar5 { .. })
            || (self.options.volume_set() && self.header_key.is_some())
            || self.options.recovery_percent.is_some()
            || self.options.solid
            || self.options.reference_layout()
            || !self.out.can_patch()
        {
            return;
        }
        let helpers = self.helpers();
        if helpers < 2 {
            return;
        }
        let budget = self
            .options
            .memory
            .working_limit
            .saturating_sub(CHAINS_BESIDE)
            .min(cap.unwrap_or(u64::MAX));
        if budget < CHAINS_LEAST {
            return;
        }
        self.chains_most = chains.min(helpers - 1);
        // A reading thread of its own for each chain where the helpers
        // allow two a chain, the chain of the member being written
        // included.
        self.chains_split = helpers >= 2 * (self.chains_most + 1);
        self.chains_budget = budget;
        self.chain_pool = Some(std::sync::Arc::new(ChainPool::default()));
    }

    /// The member at a time walk with chains ahead: before each member is
    /// written, the next stored encrypted members are given their vectors
    /// and their chains (`Run::start_chains`), which run while this thread
    /// writes. Every chain is stopped and joined on every path out.
    pub(super) fn walk_chains(&mut self) -> Result<()> {
        let pool = std::sync::Arc::clone(self.chain_pool.as_ref().expect("chosen with the chains"));
        std::thread::scope(|scope| {
            // Dropped before the scope joins its threads, on a return and
            // on a panic alike: a parked chain is always woken to end.
            let _stop = StopChains(pool);
            let mut outcome = Ok(());
            for index in 0..self.members.len() {
                outcome = self
                    .start_chains(scope, index)
                    .and_then(|()| self.write_member(index));
                if outcome.is_err() {
                    break;
                }
            }
            self.chains.clear();
            self.chain_now = None;
            self.chain_live = None;
            self.chain_seals.clear();
            outcome
        })
    }

    /// Draws, in today's order, every vector up to member `through`'s own:
    /// a member's, then its header's where headers are encrypted, a member
    /// at a time (spec G 3.13). The last member's header vector is left to
    /// be drawn when its header is written, or by the next call. In one
    /// archive that is not a volume set nothing else draws between two
    /// members, which is why the chains stay out of a volume set under
    /// encrypted headers.
    pub(super) fn draw_chain_vectors(&mut self, through: usize) -> Result<()> {
        while self.chains_drawn <= through {
            let index = self.chains_drawn;
            if let Some(last) = self.chain_seals.back_mut() {
                if last.header_iv.is_none() && self.header_key.is_some() {
                    let mut iv = [0u8; 16];
                    self.draw.fill(&mut iv)?;
                    last.header_iv = Some(iv);
                }
            }
            let crypt = if self.members[index].is_directory {
                None
            } else {
                MemberCrypt::new(&self.key, &mut self.draw)?
            };
            self.chain_seals.push_back(ChainSeal {
                index,
                crypt,
                header_iv: None,
            });
            self.chains_drawn += 1;
        }
        Ok(())
    }

    /// Starts chains for the members after `index`, nearest first, up to
    /// `chains_most` running ahead, and shares the held-bytes budget out
    /// among them (`Run::share_chains`).
    pub(super) fn start_chains<'scope>(
        &mut self,
        scope: &'scope std::thread::Scope<'scope, '_>,
        index: usize,
    ) -> Result<()>
    where
        'a: 'scope,
    {
        let count = self.members.len();
        let mut next = self
            .chains
            .back()
            .map_or(index + 1, |chain| chain.index + 1)
            .max(index + 1);
        let ahead = |chains: &std::collections::VecDeque<ChainEnd>| {
            chains.iter().filter(|chain| chain.index > index).count()
        };
        while next < count && ahead(&self.chains) < self.chains_most {
            let member = &self.members[next];
            let size = member.size;
            let eligible = !member.is_directory
                && size >= READ_AHEAD_FLOOR
                && matches!(member.payload, Payload::Reader { .. });
            if !eligible {
                // A member the chains do not take ends the look ahead for
                // now: it is written by today's path when it is reached.
                break;
            }
            self.draw_chain_vectors(next)?;
            let seal = self
                .chain_seals
                .iter_mut()
                .find(|seal| seal.index == next)
                .expect("drawn just now");
            let crypt = seal.crypt.take().expect("a file member with no cipher");
            seal.crypt = crypt.header_twin();
            let Payload::Reader { crc32, .. } = &self.members[next].payload else {
                unreachable!("checked above")
            };
            let crc32 = *crc32;
            // The chain owns the caller's reader from here; what stands in
            // its place reads as ended, and keeps the declared checksum.
            let stand_in: &'a mut (dyn Read + Send) = Box::leak(Box::new(std::io::empty()));
            let taken = std::mem::replace(
                &mut self.members[next].payload,
                Payload::Reader {
                    reader: stand_in,
                    crc32,
                },
            );
            let Payload::Reader { reader, .. } = taken else {
                unreachable!("checked above")
            };
            // The chain's digest hashes on the chain's own thread: a team
            // of its own would be helpers nobody counted.
            let digest = new_running(self.options.checksum, 1);
            let gate = std::sync::Arc::new(ChainGate::default());
            let (tx, rx) = std::sync::mpsc::channel();
            let pool =
                std::sync::Arc::clone(self.chain_pool.as_ref().expect("chosen with the chains"));
            pool.enrol(&gate);
            let work = ChainWork {
                reader,
                size,
                split: self.chains_split,
                crypt,
                digest,
                gate: std::sync::Arc::clone(&gate),
                pool,
                tx,
                #[cfg(test)]
                census: HELPERS.with(std::sync::Arc::clone),
            };
            scope.spawn(move || cipher_chain(work));
            self.chains.push_back(ChainEnd {
                index: next,
                size,
                rx,
                gate,
            });
            next += 1;
        }
        self.share_chains(index);
        Ok(())
    }

    /// Shares the held-bytes budget out, nearest member first: each chain
    /// ahead may hold its whole member where that fits what is left. The
    /// chain the writing thread takes from (member `index`'s) is given
    /// only what it holds now, which the writer is draining, so the
    /// budget passes to the chains ahead as it is written.
    pub(super) fn share_chains(&mut self, index: usize) {
        let mut left = self.chains_budget;
        let live = self
            .chain_live
            .iter()
            .chain(
                self.chains
                    .front()
                    .filter(|chain| chain.index == index)
                    .map(|chain| &chain.gate),
            )
            .next();
        if let Some(gate) = live {
            // What the writer is draining, and never less than
            // [`CHAIN_LIVE`]: the writer may hold part of a buffer while it
            // waits for the rest of a whole one (`Run::take_chain`), and
            // the chain it waits on must be free to hand the next over.
            let room = gate.held().max(CHAIN_LIVE);
            gate.allow(room);
            left = left.saturating_sub(room);
        }
        for chain in self.chains.iter().filter(|chain| chain.index > index) {
            let want = (padded_len(chain.size) + READ_AHEAD_CHUNK as u64).min(left);
            chain.gate.allow(want);
            left -= want;
        }
    }

    /// What the chains hold now, in bytes TOUCHED: every ciphertext buffer
    /// the pool has made, held or waiting to be filled again, and each
    /// chain's plaintext buffers.
    pub(super) fn chains_held(&self) -> u64 {
        let Some(pool) = self.chain_pool.as_ref() else {
            return 0;
        };
        let plain = if self.chains_split {
            READ_AHEAD_DEPTH * READ_AHEAD_CHUNK
        } else {
            READ_AHEAD_CHUNK
        };
        let running = self.chains.len() + usize::from(self.chain_live.is_some());
        pool.made_bytes() + (running * plain) as u64
    }

    /// Writes one fragment of member `index` from its chain: `room`
    /// plaintext bytes, which are `packed` bytes of ciphertext, in order;
    /// on the member's `last` fragment it returns the plaintext digest the
    /// chain took.
    ///
    /// **A failure the chain met is this member's, raised here, with the
    /// output left as the walk without chains leaves it.** That walk reads
    /// a fragment of [`READ_AHEAD_FLOOR`] and more a [`READ_AHEAD_CHUNK`]
    /// at a time from the fragment's start and writes a buffer only once
    /// it is whole, and a shorter fragment as each read returns; so here a
    /// buffer of the first kind is written only when every byte of it has
    /// come, and of the second as it comes.
    pub(super) fn copy_chain(
        &mut self,
        index: usize,
        room: u64,
        packed: u64,
        fragment: Option<&mut Running>,
        last: bool,
    ) -> Result<Option<Running>> {
        if self.chain_now.is_none() {
            let end = self.chains.pop_front().expect("checked by the caller");
            debug_assert_eq!(end.index, index);
            self.chain_live = Some(std::sync::Arc::clone(&end.gate));
            note_chain_member();
            self.chain_now = Some(ChainTaking {
                plain_left: end.size,
                end,
                queue: std::collections::VecDeque::new(),
                front_at: 0,
                queued: 0,
                failed: None,
            });
        }
        let mut taking = self.chain_now.take().expect("set just above");
        let outcome = self.take_chain(index, &mut taking, room, packed, fragment, last);
        match &outcome {
            Ok(_) if !last => self.chain_now = Some(taking),
            Ok(_) => self.chain_live = None,
            Err(_) => {
                taking.end.gate.stop();
                self.chain_live = None;
            }
        }
        outcome
    }

    /// [`Run::copy_chain`]'s loop.
    pub(super) fn take_chain(
        &mut self,
        index: usize,
        taking: &mut ChainTaking,
        room: u64,
        packed: u64,
        mut fragment: Option<&mut Running>,
        last: bool,
    ) -> Result<Option<Running>> {
        let pool = std::sync::Arc::clone(self.chain_pool.as_ref().expect("chosen with the chains"));
        // Whether the walk without chains would read this fragment ahead,
        // a whole buffer at a time (a chain runs only where there is a
        // helper for that).
        let whole_buffers = room >= READ_AHEAD_FLOOR;
        let mut left = packed;
        let mut since = 0usize;
        while left > 0 {
            let want = if whole_buffers {
                left.min(READ_AHEAD_CHUNK as u64)
            } else {
                1
            };
            while taking.queued < want && taking.failed.is_none() {
                // **The chain this thread waits on is never parked.** In a
                // volume set a fragment's buffers do not line up with the
                // chain's, so the writer can hold part of one, short of
                // the whole buffer it writes, while the chain holds exactly
                // that part and its share allows no more: both would sleep
                // (a Zen 4 rental, 2 Oct 2026: `-m0 -p -v1g -mm512m`, every
                // thread parked). Whatever the share said, the chain may
                // hold one buffer more than the writer has.
                taking
                    .end
                    .gate
                    .at_least(taking.queued + ChainPool::BUFFER as u64);
                match chain_recv(&taking.end, taking.queued, want) {
                    Ok(ChainMsg::Chunk { bytes }) => {
                        taking.queued += bytes.len() as u64;
                        taking.queue.push_back(bytes);
                    }
                    Ok(ChainMsg::Fail(error)) => taking.failed = Some(error),
                    Ok(ChainMsg::Done { .. }) => {
                        unreachable!("a chain ended before its member's bytes")
                    }
                    // The chain ended without an answer, which only a panic
                    // does; the scope's join carries it on.
                    Err(_) => taking.failed = Some(Error::new(ErrorKind::Truncated)),
                }
            }
            if taking.queued < want {
                return Err(taking.failed.take().expect("the queue fell short"));
            }
            let mut write = if whole_buffers {
                want
            } else {
                left.min(taking.queued)
            };
            left -= write;
            while write > 0 {
                let front = taking.queue.front().expect("counted in `queued`");
                let take = write.min((front.len() - taking.front_at) as u64) as usize;
                let bytes = &front[taking.front_at..taking.front_at + take];
                if let Some(fragment) = fragment.as_deref_mut() {
                    fragment.update(bytes);
                }
                let written = self.out.write(bytes);
                taking.front_at += take;
                taking.queued -= take as u64;
                write -= take as u64;
                taking.end.gate.release(take as u64);
                if taking.front_at == front.len() {
                    taking.front_at = 0;
                    if let Some(spent) = taking.queue.pop_front() {
                        // Back for any chain to fill again.
                        pool.give(spent);
                    }
                }
                written?;
                // One report a `COPY_CHUNK` of plaintext, the stored copy's
                // cadence (spec G 3.13); the padded last block is not
                // payload.
                let mut plain = (take as u64).min(taking.plain_left);
                taking.plain_left -= plain;
                while plain > 0 {
                    let piece = plain.min(COPY_CHUNK as u64);
                    self.delivered += piece;
                    self.progress.output(self.delivered)?;
                    plain -= piece;
                }
            }
            since += 1;
            if since.is_multiple_of(8) {
                self.share_chains(index);
            }
            if since.is_multiple_of(64) {
                self.note_peak();
            }
        }
        self.note_peak();
        if !last {
            return Ok(None);
        }
        debug_assert_eq!(taking.queued, 0, "ciphertext past the member");
        if let Some(error) = taking.failed.take() {
            return Err(error);
        }
        match taking.end.rx.recv() {
            Ok(ChainMsg::Done { digest, end }) => {
                end.map_err(|error| error.with_member(self.members[index].name))?;
                Ok(Some(digest))
            }
            Ok(ChainMsg::Fail(error)) => Err(error),
            Ok(ChainMsg::Chunk { .. }) => unreachable!("ciphertext past the member"),
            Err(_) => Err(Error::new(ErrorKind::Truncated)),
        }
    }

    /// The helper threads the chains hold now: one a chain, or two where
    /// each reads on a thread of its own, the chain the writing thread is
    /// taking from included.
    pub(super) fn chain_threads(&self) -> usize {
        let chains = self.chains.len() + usize::from(self.chain_live.is_some());
        chains * if self.chains_split { 2 } else { 1 }
    }
}

/// What a run with chains ahead leaves, of its working limit, for
/// everything else the process holds: the stored copy's own pipeline, the
/// chains' plaintext buffers, the output's staging and the process itself.
/// A named `-mm` of 512 MiB and more is the PROCESS's budget (SPEC-API
/// 8.4.1), so the held ciphertext is fitted under it with this much room.
pub(super) const CHAINS_BESIDE: u64 = 96 << 20;

/// The least held-bytes budget worth a chain ahead.
pub(super) const CHAINS_LEAST: u64 = 32 << 20;

/// What the chain the writing thread takes from may always hold: four
/// buffers, so it is not parked while the writer drains it.
pub(super) const CHAIN_LIVE: u64 = 4 * ChainPool::BUFFER as u64;

/// How many chains run ahead under `WriteOptions::encrypted_read_ahead`
/// where no knob says: three, which filled a 3.4 GB/s drive beside a
/// chain of 1.5 GB/s (a Zen 4 rental, 1 Oct 2026).
pub(super) const CHAINS_AHEAD: usize = 3;

#[cfg(feature = "bench-internals")]
thread_local! {
    pub(super) static CHAINS_SET: std::cell::Cell<Option<(usize, Option<u64>)>> =
        const { std::cell::Cell::new(None) };
    pub(super) static CHAIN_MEMBERS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Runs `work` with `chains` chains ahead and their held bytes capped at
/// `cap` on this thread. This repository's tests only.
#[cfg(feature = "bench-internals")]
pub(crate) fn with_chains_ahead<T>(chains: usize, cap: Option<u64>, work: impl FnOnce() -> T) -> T {
    let was = CHAINS_SET.with(|cell| cell.replace(Some((chains, cap))));
    let result = work();
    CHAINS_SET.with(|cell| cell.set(was));
    result
}

/// How many members this thread has written from a chain that ran ahead,
/// since [`reset_chain_members`]. This repository's tests only.
#[cfg(feature = "bench-internals")]
pub(crate) fn chain_members() -> usize {
    CHAIN_MEMBERS.with(std::cell::Cell::get)
}

/// Starts the count in [`chain_members`] again from zero.
#[cfg(feature = "bench-internals")]
pub(crate) fn reset_chain_members() {
    CHAIN_MEMBERS.with(|count| count.set(0));
}

/// One member written from a chain that ran ahead.
pub(super) fn note_chain_member() {
    #[cfg(feature = "bench-internals")]
    CHAIN_MEMBERS.with(|count| count.set(count.get() + 1));
}

/// How many chains may run ahead, and a cap on the ciphertext they hold
/// between them: a test's setting (`with_chains_ahead`), else
/// [`CHAINS_AHEAD`] and no cap.
pub(super) fn chains_knob() -> (usize, Option<u64>) {
    #[cfg(feature = "bench-internals")]
    if let Some(set) = CHAINS_SET.with(std::cell::Cell::get) {
        return set;
    }
    (CHAINS_AHEAD, None)
}

/// The next thing a member's chain hands the writing thread. In this
/// repository's tests a wait of five seconds is noted with what each side
/// held (`chain_stall`), so a test of a wedge can say where it stood.
pub(super) fn chain_recv(
    end: &ChainEnd,
    queued: u64,
    want: u64,
) -> std::result::Result<ChainMsg, std::sync::mpsc::RecvError> {
    #[cfg(feature = "bench-internals")]
    loop {
        match end.rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(message) => return Ok(message),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err(std::sync::mpsc::RecvError)
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                let (held, allowed) = end.gate.figures();
                *CHAIN_STALL
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(format!(
                    "member {}: the writer has {queued} of the {want} bytes it waits for; \
                     its chain holds {held} and is allowed {allowed}",
                    end.index
                ));
            }
        }
    }
    #[cfg(not(feature = "bench-internals"))]
    {
        let _ = (queued, want);
        end.rx.recv()
    }
}

#[cfg(feature = "bench-internals")]
pub(super) static CHAIN_STALL: Mutex<Option<String>> = Mutex::new(None);

/// What the last five second wait of a writing thread on its chain looked
/// like, on any thread, taken. This repository's tests only.
#[cfg(feature = "bench-internals")]
pub(crate) fn chain_stall() -> Option<String> {
    CHAIN_STALL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
}

/// What was drawn ahead for one member: its cipher (a directory has
/// none; for a member whose chain runs ahead, the twin its headers are
/// built from) and its header's vector where that was drawn too.
pub(super) struct ChainSeal {
    pub(super) index: usize,
    pub(super) crypt: Option<MemberCrypt>,
    pub(super) header_iv: Option<[u8; 16]>,
}

/// The writing thread's end of a chain running ahead.
pub(super) struct ChainEnd {
    pub(super) index: usize,
    pub(super) size: u64,
    pub(super) rx: std::sync::mpsc::Receiver<ChainMsg>,
    pub(super) gate: std::sync::Arc<ChainGate>,
}

/// The chain of the member being written, from its first fragment to its
/// last, and the plaintext bytes not yet reported.
pub(super) struct ChainTaking {
    pub(super) end: ChainEnd,
    /// Ciphertext come from the chain and not yet written, in order, with
    /// how far into the first buffer the writer is and the bytes in all.
    pub(super) queue: std::collections::VecDeque<Vec<u8>>,
    pub(super) front_at: usize,
    pub(super) queued: u64,
    /// The chain's failure, once it has come: raised when the bytes it
    /// produced before it are written or dropped.
    pub(super) failed: Option<Error>,
    pub(super) plain_left: u64,
}

/// What a chain hands the writing thread, in order.
pub(super) enum ChainMsg {
    /// Ciphertext, in whole cipher blocks.
    Chunk { bytes: Vec<u8> },
    /// The member's end: its plaintext digest, and whether the reader
    /// ended where it declared.
    Done { digest: Running, end: Result<()> },
    /// The read or the cipher failed.
    Fail(Error),
}

/// The ciphertext buffers every chain of a run shares: one a
/// [`READ_AHEAD_CHUNK`] of plaintext, made only when none is free, and
/// given back by the writing thread once written. A buffer is taken only
/// after its bytes are allowed (`ChainGate::take`), so what the pool has
/// made is at most the held-bytes budget and a buffer a chain, and that is
/// what the run is charged (`Run::chains_held`).
#[derive(Default)]
pub(super) struct ChainPool {
    pub(super) state: Mutex<(Vec<Vec<u8>>, usize)>,
    /// Every chain's gate, so that all of them can be stopped at once.
    pub(super) gates: Mutex<Vec<std::sync::Arc<ChainGate>>>,
}

/// Stops every chain of a run when dropped.
pub(super) struct StopChains(std::sync::Arc<ChainPool>);

impl Drop for StopChains {
    fn drop(&mut self) {
        self.0.stop_all();
    }
}

impl ChainPool {
    /// One buffer's capacity: a chunk and its padded last block.
    pub(super) const BUFFER: usize = READ_AHEAD_CHUNK + 2 * CIPHER_BLOCK;

    pub(super) fn lock(&self) -> MutexGuard<'_, (Vec<Vec<u8>>, usize)> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(super) fn take(&self) -> Vec<u8> {
        let mut state = self.lock();
        if let Some(buffer) = state.0.pop() {
            return buffer;
        }
        state.1 += 1;
        drop(state);
        Vec::with_capacity(Self::BUFFER)
    }

    pub(super) fn give(&self, buffer: Vec<u8>) {
        self.lock().0.push(buffer);
    }

    pub(super) fn made_bytes(&self) -> u64 {
        (self.lock().1 * Self::BUFFER) as u64
    }

    pub(super) fn enrol(&self, gate: &std::sync::Arc<ChainGate>) {
        self.gates
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(std::sync::Arc::clone(gate));
    }

    pub(super) fn stop_all(&self) {
        let gates = self
            .gates
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for gate in gates.iter() {
            gate.stop();
        }
    }
}

/// How much ciphertext one chain holds and may hold.
#[derive(Default)]
pub(super) struct ChainGate {
    pub(super) state: Mutex<ChainHeld>,
    pub(super) wake: std::sync::Condvar,
}

#[derive(Default)]
pub(super) struct ChainHeld {
    pub(super) held: u64,
    pub(super) allowed: u64,
    pub(super) stopped: bool,
}

impl ChainGate {
    pub(super) fn lock(&self) -> MutexGuard<'_, ChainHeld> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Waits until `bytes` more may be held, or the chain is stopped
    /// (`false`). A chain holding nothing may always hold one buffer, so a
    /// chain the writer is taking from never waits on its allowance.
    pub(super) fn take(&self, bytes: u64) -> bool {
        let mut state = self.lock();
        while !state.stopped && state.held > 0 && state.held + bytes > state.allowed {
            state = self
                .wake
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        if state.stopped {
            return false;
        }
        state.held += bytes;
        true
    }

    pub(super) fn release(&self, bytes: u64) {
        let mut state = self.lock();
        state.held = state.held.saturating_sub(bytes);
        drop(state);
        self.wake.notify_all();
    }

    pub(super) fn allow(&self, bytes: u64) {
        let mut state = self.lock();
        if state.allowed != bytes {
            state.allowed = bytes;
            drop(state);
            self.wake.notify_all();
        }
    }

    /// Raises what may be held to `bytes` where it is less.
    pub(super) fn at_least(&self, bytes: u64) {
        let mut state = self.lock();
        if state.allowed < bytes {
            state.allowed = bytes;
            drop(state);
            self.wake.notify_all();
        }
    }

    pub(super) fn stop(&self) {
        self.lock().stopped = true;
        self.wake.notify_all();
    }

    pub(super) fn held(&self) -> u64 {
        self.lock().held
    }

    /// What is held and what is allowed.
    #[cfg(feature = "bench-internals")]
    pub(super) fn figures(&self) -> (u64, u64) {
        let state = self.lock();
        (state.held, state.allowed)
    }
}

/// What a chain running ahead owns.
pub(super) struct ChainWork<'r> {
    pub(super) reader: &'r mut (dyn Read + Send),
    pub(super) size: u64,
    pub(super) split: bool,
    pub(super) crypt: MemberCrypt,
    pub(super) digest: Running,
    pub(super) gate: std::sync::Arc<ChainGate>,
    pub(super) pool: std::sync::Arc<ChainPool>,
    pub(super) tx: std::sync::mpsc::Sender<ChainMsg>,
    #[cfg(test)]
    pub(super) census: std::sync::Arc<HelperCensus>,
}

/// One member's pipeline ahead of the writer: read, the plaintext digest,
/// the member's ONE serial CBC chain, each buffer of
/// ciphertext handed on in order once the gate lets it be held. The padded
/// last block rides the last buffer. With `split` the reading and the
/// digest run on a thread of their own, as the stored copy's stages do,
/// and the chain's thread only enciphers. Each thread is a
/// helper.
pub(super) fn cipher_chain(work: ChainWork<'_>) {
    use std::sync::mpsc;
    let ChainWork {
        reader,
        size,
        split,
        mut crypt,
        mut digest,
        gate,
        pool,
        tx,
        #[cfg(test)]
        census,
    } = work;
    // The helper count of this thread, for the tests: it ends where the
    // chain's WORK ends, just before its last message, and not where the
    // thread exits. The writing thread starts the next chain as soon as it
    // has that message, while this thread is still freeing its buffers on
    // the way out, so a count held to the thread's last instruction read
    // one helper more than were working (seen on a loaded machine).
    #[cfg(test)]
    let live = Live::enter(&census);
    #[cfg(test)]
    census
        .chains
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    // The reading: fills `plain`, feeds the digest.
    // A read that fails says how many bytes came before it failed: the
    // walk without chains writes those where it reads a short fragment as
    // each read returns, so the writing thread is handed them too.
    let read = |reader: &mut (dyn Read + Send),
                digest: &mut Running,
                plain: &mut [u8],
                left: &mut u64|
     -> std::result::Result<usize, (usize, Error)> {
        let want = (*left).min(plain.len() as u64) as usize;
        let mut filled = 0;
        while filled < want {
            match reader.read(&mut plain[filled..want]) {
                Ok(0) => return Err((filled, Error::new(ErrorKind::Truncated))),
                Ok(read) => filled += read,
                Err(error) => return Err((filled, Error::from(error))),
            }
        }
        digest.update(&plain[..want]);
        *left -= want as u64;
        Ok(want)
    };
    // Whether the reader ended where it declared (spec G 3.7.2), asked
    // here because the writing thread no longer holds the reader.
    let end_of = |reader: &mut (dyn Read + Send)| -> Result<()> {
        let mut over = [0u8; 1];
        match reader.read(&mut over) {
            Ok(0) => Ok(()),
            Ok(_) => Err(Error::new(ErrorKind::Corrupt(Corruption::PayloadLength))),
            Err(error) => Err(Error::from(error)),
        }
    };
    // The enciphering of one plaintext buffer, handed on. `false` ends
    // the chain: stopped, failed, or the writer gone. The bytes are
    // allowed BEFORE their buffer is taken, so the pool never makes more
    // than the budget holds.
    let mut tail = Vec::new();
    let mut seal = |plain: &[u8], last: bool| -> bool {
        if !gate.take((plain.len() + 2 * CIPHER_BLOCK) as u64) {
            return false;
        }
        let mut bytes = pool.take();
        let sealed = crypt.push(plain, &mut bytes).and_then(|()| {
            if last {
                crypt.finish(&mut tail)?;
                bytes.extend_from_slice(&tail);
            }
            Ok(())
        });
        if let Err(error) = sealed {
            let _ = tx.send(ChainMsg::Fail(error));
            return false;
        }
        // What was allowed is what the writer gives back.
        let spare = (plain.len() + 2 * CIPHER_BLOCK - bytes.len()) as u64;
        gate.release(spare);
        tx.send(ChainMsg::Chunk { bytes }).is_ok()
    };
    if !split {
        let mut plain = vec![0u8; READ_AHEAD_CHUNK];
        let mut left = size;
        while left > 0 {
            match read(reader, &mut digest, &mut plain, &mut left) {
                Ok(want) => {
                    if !seal(&plain[..want], left == 0) {
                        return;
                    }
                }
                Err((came, error)) => {
                    if came == 0 || seal(&plain[..came], false) {
                        let _ = tx.send(ChainMsg::Fail(error));
                    }
                    return;
                }
            }
        }
        let end = end_of(reader);
        #[cfg(test)]
        drop(live);
        let _ = tx.send(ChainMsg::Done { digest, end });
        return;
    }
    std::thread::scope(|scope| {
        // A buffer read, its length, and the failure that ended it short.
        type Read = (Vec<u8>, usize, Option<Error>);
        let (full_tx, full_rx) = mpsc::sync_channel::<Read>(READ_AHEAD_DEPTH);
        let (empty_tx, empty_rx) = mpsc::channel::<Vec<u8>>();
        for _ in 0..READ_AHEAD_DEPTH {
            let _ = empty_tx.send(vec![0u8; READ_AHEAD_CHUNK]);
        }
        #[cfg(test)]
        let census = std::sync::Arc::clone(&census);
        let reading = scope.spawn(move || {
            #[cfg(test)]
            let _live = Live::enter(&census);
            let mut left = size;
            while left > 0 {
                let Ok(mut plain) = empty_rx.recv() else {
                    return None;
                };
                match read(reader, &mut digest, &mut plain, &mut left) {
                    Ok(want) => {
                        if full_tx.send((plain, want, None)).is_err() {
                            return None;
                        }
                    }
                    Err((came, error)) => {
                        let _ = full_tx.send((plain, came, Some(error)));
                        return None;
                    }
                }
            }
            let end = end_of(reader);
            Some((digest, end))
        });
        let mut left = size;
        for (plain, came, failed) in full_rx {
            match failed {
                None => {
                    left -= came as u64;
                    let went = seal(&plain[..came], left == 0);
                    let _ = empty_tx.send(plain);
                    if !went {
                        break;
                    }
                }
                Some(error) => {
                    if came == 0 || seal(&plain[..came], false) {
                        let _ = tx.send(ChainMsg::Fail(error));
                    }
                    break;
                }
            }
        }
        drop(empty_tx);
        match reading.join() {
            Ok(Some((digest, end))) => {
                // The reading thread is joined, so its count has ended.
                #[cfg(test)]
                drop(live);
                let _ = tx.send(ChainMsg::Done { digest, end });
            }
            Ok(None) => {}
            Err(caught) => std::panic::resume_unwind(caught),
        }
    });
}
