//! The rolling hand-off of the segment team: an engine takes each stretch
//! as it is read, while the writing thread places what has landed.

use super::*;

/// The segment team's ROLLING HAND-OFF for one member.
///
/// **What was serial.** A round read its stretches and took their
/// checksum on the writing thread, one after the other, with every engine
/// idle, and only then encoded them; and each round zero-filled its
/// buffers before it read into them. Counted 2 Oct 2026 on sixteen cores
/// of a Xeon 8488C, one 4 GiB member at level 1: of a 7.5 s wall the
/// writing thread was the only thread running for 2.8 s, 0.90 of it the
/// read, 0.41 the CRC32, 0.35 the zero fill and 0.22 page faults.
///
/// **What rolls.** The writing thread reads a stretch, takes its checksum
/// and hands it to an engine at once, on the pool, and goes on to read the
/// next while that one is encoded; a stretch's packed bytes go to the
/// member's as soon as every stretch before it has. So the reads and the
/// checksum of all but a member's first stretch run beside the encode.
/// The run's own encoder is one of the engines and runs on the pool like
/// the others, since this thread is reading.
///
/// **Why it moves no byte.** The stretches are the ones the rounds cut
/// (`Engine::streamed_period`, planned for the whole member before the
/// first is read), each is encoded by [`encode_stretch`] from the same
/// kept dictionary, and their packed bytes are appended in order. The
/// payload is read once, in order, by the writing thread, and the checksum
/// taken over it in that order.
///
/// **A failing reader.** A round that could not be read whole left
/// nothing of itself behind. So nothing of a GROUP of stretches (as many
/// as there are engines, a round's worth) leaves here until the group has
/// been read whole, and a reader's error is returned once every group
/// before it has gone out: the bytes and the error a round at a time left.
///
/// **What it holds.** The engines and buffers the rounds hold: an
/// engine's buffers are read into again only once its packed bytes have
/// gone to the member's. A STREAMED member holds one stretch's packed
/// bytes more, the one being placed (`Run::roll_fits_streamed`), and the
/// walk is handed a stretch at a time, where a round handed it as many as
/// there are engines.
#[cfg(feature = "parallel")]
pub(super) struct Roll {
    pub(super) slots: Vec<Slot>,
    /// Every stretch of the member: its length, and how much of the
    /// history a slide keeps after it, which is the next one's dictionary.
    pub(super) plan: Vec<(usize, usize)>,
    /// How many stretches have been read and handed to an engine.
    pub(super) read: usize,
    /// How many stretches' packed bytes have gone to the member's.
    pub(super) emitted: usize,
    /// How many engines are away encoding.
    pub(super) flying: usize,
    /// How far the member has been read.
    pub(super) pulled: u64,
    /// How many of the member's bytes the emitted stretches stand for.
    pub(super) out_at: u64,
    /// The error the reader ended in, returned once every group before
    /// the one it struck has gone out.
    pub(super) failed: Option<Error>,
    pub(super) landing: std::sync::mpsc::Receiver<Landed>,
    pub(super) land: std::sync::mpsc::Sender<Landed>,
    pub(super) window: usize,
    pub(super) depth: usize,
    pub(super) slack: usize,
    /// The member's effort (`Stretch::effort`).
    pub(super) effort: crate::encode::drive::Plan,
    /// What an engine beside the run's own is stated at while it is away
    /// (`Run::segment_charge`'s engine term).
    pub(super) engine_bound: u64,
    /// The pool is lent for as long as an engine may be away.
    pub(super) _lent: width::Lent,
}

/// One engine of the rolling hand-off, with its buffers.
#[cfg(feature = "parallel")]
pub(super) struct Slot {
    /// The engine, or nothing while it is away encoding.
    pub(super) engine: Option<Encoder>,
    /// The kept dictionary and then the stretch; `live` bytes of it are in
    /// use, the rest is what earlier stretches left.
    pub(super) input: Vec<u8>,
    pub(super) out: Vec<u8>,
    pub(super) live: usize,
    /// The stretch it holds, away or encoded and waiting its turn.
    pub(super) stretch: Option<usize>,
    /// Whether that stretch is encoded.
    pub(super) landed: bool,
    /// What the slot is stated at while its engine is away.
    pub(super) away: u64,
}

/// An engine come back from its stretch, with its buffers, and the panic
/// it ended in where it did.
#[cfg(feature = "parallel")]
pub(super) struct Landed {
    pub(super) slot: usize,
    pub(super) engine: Encoder,
    pub(super) input: Vec<u8>,
    pub(super) out: Vec<u8>,
    /// The most windows one flush of the stretch parsed, for the tests'
    /// `widest_flush`, which the flush wrote on the thread it ran on.
    pub(super) widest: usize,
    pub(super) panic: Option<Box<dyn std::any::Any + Send>>,
}

#[cfg(feature = "parallel")]
impl Roll {
    /// What the hand-off holds now: each engine measured where it is
    /// here, and stated at its bound while it is away.
    pub(super) fn held(&self) -> u64 {
        self.slots.iter().fold(0u64, |sum, slot| {
            sum.saturating_add(match &slot.engine {
                Some(engine) => engine
                    .held_bytes()
                    .saturating_add(engine.structure_bytes())
                    .saturating_add(engine.flight_bytes())
                    .saturating_add(slot.live as u64)
                    .saturating_add(slot.out.len() as u64),
                None => slot.away,
            })
        })
    }

    /// How many stretches may go out: those of the groups read whole.
    pub(super) fn may_emit(&self) -> usize {
        if self.read == self.plan.len() {
            self.read
        } else {
            let group = self.slots.len().max(1);
            self.read / group * group
        }
    }

    /// Takes back an engine that has ended its stretch. A panic it ended
    /// in is carried on here, on the writing thread.
    pub(super) fn take_back(&mut self, landed: Landed) {
        let slot = &mut self.slots[landed.slot];
        slot.engine = Some(landed.engine);
        slot.input = landed.input;
        slot.out = landed.out;
        slot.landed = true;
        self.flying -= 1;
        note_flush_width(landed.widest);
        if let Some(panic) = landed.panic {
            std::panic::resume_unwind(panic);
        }
    }
}

#[cfg(feature = "parallel")]
impl Drop for Roll {
    /// No engine is left encoding behind a write that has ended, on the
    /// error and panic paths too.
    fn drop(&mut self) {
        while self.flying > 0 {
            match self.landing.recv() {
                Ok(_) => self.flying -= 1,
                Err(_) => break,
            }
        }
    }
}

/// Whether the segment team hands its stretches over ROLLING ([`Roll`])
/// rather than a round at a time. ON, on the rows
/// measured 1 Oct 2026; the knob below
/// turns it off for a count, and a test sets it for its own thread.
#[cfg(feature = "parallel")]
pub(super) const SEGMENT_ROLLS: bool = true;

/// Under the COUNT-ONLY feature `wave-knob`, `RARKIT_SEGMENT_ROLL=0` turns
/// the rolling hand-off off and `=1` on, read once, so both forms are
/// counted inside one binary. A hand-off and never a byte.
#[cfg(all(feature = "parallel", feature = "wave-knob"))]
pub(super) fn knob_segment_rolls() -> Option<bool> {
    static ROLLS: std::sync::OnceLock<Option<bool>> = std::sync::OnceLock::new();
    *ROLLS.get_or_init(|| match std::env::var("RARKIT_SEGMENT_ROLL").ok()?.trim() {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    })
}

#[cfg(all(feature = "parallel", not(feature = "wave-knob")))]
#[inline(always)]
pub(super) fn knob_segment_rolls() -> Option<bool> {
    None
}

#[cfg(feature = "bench-internals")]
thread_local! {
    pub(super) static SEGMENT_ROLL: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
    pub(super) static SEGMENT_ROLLED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Runs `work` with the segment team's hand-off rolling, or a round at a
/// time, on this thread. This repository's tests only.
#[cfg(feature = "bench-internals")]
pub(crate) fn with_segment_roll<T>(rolls: bool, work: impl FnOnce() -> T) -> T {
    let was = SEGMENT_ROLL.with(|cell| cell.replace(Some(rolls)));
    let result = work();
    SEGMENT_ROLL.with(|cell| cell.set(was));
    result
}

/// How many members this thread's writes have handed over rolling. This
/// repository's tests only.
#[cfg(feature = "bench-internals")]
pub(crate) fn segment_rolled() -> usize {
    SEGMENT_ROLLED.with(std::cell::Cell::get)
}

/// Whether a member the segment team takes is handed over rolling.
#[cfg(feature = "parallel")]
pub(super) fn segment_rolls() -> bool {
    #[cfg(feature = "bench-internals")]
    if let Some(rolls) = SEGMENT_ROLL.with(std::cell::Cell::get) {
        return rolls;
    }
    knob_segment_rolls().unwrap_or(SEGMENT_ROLLS)
}

impl<'a, 'p, V: VolumeSource, P: Progress> Run<'a, 'p, V, P> {
    /// Whether the member about to be encoded by the segment team is
    /// handed over rolling ([`Roll`]): where the form is on, at LEVEL 1,
    /// and where this thread is not one of the pool's own, which could not
    /// wait for an engine without keeping the pool from running it.
    ///
    /// **Level 1 only, by the rows.** That is the level whose reads and
    /// checksum were a quarter to a third of the wall, and where rolling
    /// read 1.5x to 1.8x on 16 and 32 cores. At levels 2 and 3 they were
    /// about a hundredth, and rolling LOST there on 32 cores of a Xeon
    /// 8488C: 0.64x at level 2 and 0.74x at level 3 on one 4 GiB member,
    /// CPU seconds down and wall up, engines standing idle
    /// (measured 1 Oct 2026;
    /// the cause is not established). So levels 2 and 3 keep
    /// their rounds.
    #[cfg(feature = "parallel")]
    pub(super) fn rolls(&self) -> bool {
        self.segments.width >= 2
            && self.options.method == 1
            && segment_rolls()
            && !width::on_own_pool()
    }

    /// Whether a STREAMED member may roll. The stretch the walk is placing
    /// is still pending while the engine it came from, read into again,
    /// writes another: one more stretch's packed bytes than a round at a
    /// time held, at their bound. So it rolls only where that much is left
    /// of the policy's working limit beside what the team is charged
    /// (`Run::segment_width`'s own sum); elsewhere the member is handed
    /// over a round at a time, as it was.
    #[cfg(feature = "parallel")]
    pub(super) fn roll_fits_streamed(&self, window: usize) -> bool {
        let width = self.segments.width as u64;
        let limit = team_ceiling(self.options.memory.working_limit);
        let (lead, each) = self.segment_charge(window);
        let owed = self.team_charged.saturating_sub(self.team_now());
        let room = limit
            .saturating_sub(self.working_now())
            .saturating_sub(owed)
            .saturating_sub(lead)
            .saturating_sub(width.saturating_sub(1).saturating_mul(each));
        room >= self.segment_packed(window)
    }

    /// Starts the rolling hand-off of a member of `want` bytes: its
    /// stretches planned, the run's own encoder and the crews made its
    /// engines.
    #[cfg(feature = "parallel")]
    pub(super) fn roll_start(&mut self, want: u64, window: usize, depth: usize, slack: usize) {
        let width = self.segments.width;
        while self.segments.crews.len() + 1 < width {
            let crew = self.encoder_held(Some(window));
            self.segments.crews.push(crew);
        }
        let (buffers, each) = self.segment_charge(window);
        let mut lead = self
            .encoder
            .take()
            .expect("the encoder was built before the walk");
        let mut plan = Vec::new();
        let (mut at, mut kept) = (0u64, 0usize);
        while at < want {
            let period = lead.streamed_period(window, kept, want - at) as usize;
            kept = lead.kept_by_slide(kept.saturating_add(period));
            plan.push((period, kept));
            at += period as u64;
        }
        let engines = width.min(plan.len()).max(1);
        let effort = lead.member_effort();
        lead.share_pool(engines);
        let Segments {
            crews,
            outs,
            kept,
            idle_inputs,
            ..
        } = &mut self.segments;
        kept.clear();
        let mut slots = Vec::with_capacity(engines);
        let mut lead = Some(lead);
        for _ in 0..engines {
            let mut engine = match lead.take() {
                Some(lead) => lead,
                None => crews.pop().expect("a crew for every engine but the lead"),
            };
            engine.share_pool(engines);
            let mut out = outs.pop().unwrap_or_default();
            out.clear();
            slots.push(Slot {
                engine: Some(engine),
                input: idle_inputs.pop().unwrap_or_default(),
                out,
                live: 0,
                stretch: None,
                landed: false,
                away: 0,
            });
        }
        let (land, landing) = std::sync::mpsc::channel();
        #[cfg(feature = "bench-internals")]
        SEGMENT_ROLLED.with(|cell| cell.set(cell.get() + 1));
        self.segments.roll = Some(Roll {
            slots,
            plan,
            read: 0,
            emitted: 0,
            flying: 0,
            pulled: 0,
            out_at: 0,
            failed: None,
            landing,
            land,
            window,
            depth,
            slack,
            effort,
            engine_bound: each.saturating_sub(buffers),
            _lent: width::lend(),
        });
    }

    /// Ends the rolling hand-off: every engine waited for, the run's own
    /// encoder put back, the crews and the buffers kept for the next
    /// member.
    #[cfg(feature = "parallel")]
    pub(super) fn roll_end(&mut self) {
        let Some(mut roll) = self.segments.roll.take() else {
            return;
        };
        while roll.flying > 0 {
            match roll.landing.recv() {
                Ok(landed) => roll.take_back(landed),
                Err(_) => break,
            }
        }
        for (at, slot) in roll.slots.drain(..).enumerate() {
            let Slot {
                engine,
                input,
                mut out,
                ..
            } = slot;
            if let Some(mut engine) = engine {
                if at == 0 {
                    // Outside the hand-off the run's own is alone.
                    engine.share_pool(0);
                    self.encoder = Some(engine);
                } else {
                    self.segments.crews.push(engine);
                }
            }
            out.clear();
            self.segments.outs.push(out);
            self.segments.idle_inputs.push(input);
        }
        self.segments.kept.clear();
        self.note_peak();
    }

    /// Reads the next stretch of member `index` into the engine at `at`,
    /// takes its checksum and sends the engine off to encode it. A reader
    /// that fails leaves its error in the roll and the engine here.
    #[cfg(feature = "parallel")]
    pub(super) fn roll_feed(&mut self, index: usize, at: usize, digest: &mut Running) {
        let Run {
            members,
            prefix,
            segments,
            ..
        } = self;
        let Segments { roll, kept, .. } = segments;
        let roll = roll.as_mut().expect("a roll in flight");
        let sequence = roll.read;
        let (period, keep) = roll.plan[sequence];
        // A group of stretches is what a round was, and is counted as one.
        let group = roll.slots.len();
        if sequence.is_multiple_of(group) {
            note_segment_round(group.min(roll.plan.len() - sequence));
        }
        let slot = &mut roll.slots[at];
        let held = kept.len();
        let need = held + period;
        // Grown and never cleared: only bytes no stretch has yet been
        // read over are zero-filled.
        if slot.input.len() < need {
            slot.input.resize(need, 0);
        }
        slot.input[..held].copy_from_slice(kept);
        let target = &mut slot.input[held..need];
        let filled = match &mut members[index].payload {
            Payload::Bytes(data) => {
                let from = roll.pulled as usize;
                target.copy_from_slice(&data[from..from + period]);
                Ok(())
            }
            Payload::Reader { reader, .. } => {
                let mut filled = 0;
                let mut outcome = Ok(());
                while filled < period {
                    match prefix.read(index, &mut **reader, &mut target[filled..]) {
                        Ok(0) => {
                            outcome = Err(Error::new(ErrorKind::Truncated));
                            break;
                        }
                        Ok(read) => filled += read,
                        Err(error) => {
                            outcome = Err(Error::from(error));
                            break;
                        }
                    }
                }
                outcome
            }
        };
        if let Err(error) = filled {
            roll.failed = Some(error);
            return;
        }
        digest.update(&slot.input[held..need]);
        let stretch = Stretch {
            kept: held,
            base: roll.pulled,
            last: sequence + 1 == roll.plan.len(),
            effort: Some(roll.effort),
        };
        roll.pulled += period as u64;
        roll.read += 1;
        // What a slide keeps of this stretch's history is the next one's.
        kept.clear();
        kept.extend_from_slice(&slot.input[need - keep..need]);

        let mut engine = slot.engine.take().expect("an idle engine");
        let measured = engine
            .held_bytes()
            .saturating_add(engine.structure_bytes())
            .saturating_add(engine.flight_bytes());
        let bound = if at == 0 { 0 } else { roll.engine_bound };
        slot.away = measured
            .max(bound)
            .saturating_add(need as u64)
            .saturating_add(crate::encode::drive::packed_most(period) as u64);
        slot.live = need;
        slot.stretch = Some(sequence);
        slot.landed = false;
        let input = std::mem::take(&mut slot.input);
        let mut out = std::mem::take(&mut slot.out);
        let (window, depth, slack) = (roll.window, roll.depth, roll.slack);
        let land = roll.land.clone();
        roll.flying += 1;
        width::spawn(move || {
            #[cfg(feature = "bench-internals")]
            let before = WIDEST_FLUSH.with(|cell| cell.replace(0));
            let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                encode_stretch(
                    &mut engine,
                    &input[..need],
                    stretch,
                    window,
                    depth,
                    slack,
                    &mut out,
                );
            }));
            #[cfg(feature = "bench-internals")]
            let widest = WIDEST_FLUSH.with(|cell| cell.replace(before));
            #[cfg(not(feature = "bench-internals"))]
            let widest = 0;
            // The roll outlives every engine away (`Roll::drop`).
            let _ = land.send(Landed {
                slot: at,
                engine,
                input,
                out,
                widest,
                panic: caught.err(),
            });
        });
    }

    /// Carries the rolling hand-off of member `index` on, appending the
    /// packed bytes of its stretches to `sink` in order: to the member's
    /// end, or, where the member is `streamed`, until one more stretch has
    /// gone out, so that the walk places it while the engines go on. A
    /// streamed stretch that finds `sink` empty is handed over whole, its
    /// buffer for the sink's, and nothing is copied.
    #[cfg(feature = "parallel")]
    pub(super) fn roll_on(
        &mut self,
        index: usize,
        digest: &mut Running,
        sink: &mut Vec<u8>,
        streamed: bool,
    ) -> Result<()> {
        let started = self.segments.roll.as_ref().map_or(0, |roll| roll.emitted);
        loop {
            let roll = self.segments.roll.as_mut().expect("a roll in flight");
            // The engines that have ended, without waiting for one.
            let mut landed_any = false;
            while let Ok(landed) = roll.landing.try_recv() {
                roll.take_back(landed);
                landed_any = true;
            }
            // Their packed bytes, in order.
            let mut emitted_any = false;
            while roll.emitted < roll.may_emit() {
                let next = roll.emitted;
                let Some(slot) = roll
                    .slots
                    .iter_mut()
                    .find(|slot| slot.landed && slot.stretch == Some(next))
                else {
                    break;
                };
                emitted_any = true;
                if streamed && sink.is_empty() {
                    std::mem::swap(sink, &mut slot.out);
                } else {
                    sink.extend_from_slice(&slot.out);
                }
                slot.out.clear();
                slot.live = 0;
                slot.stretch = None;
                slot.landed = false;
                roll.out_at += roll.plan[next].0 as u64;
                roll.emitted += 1;
                if streamed {
                    break;
                }
            }
            let (emitted, stretches) = (roll.emitted, roll.plan.len());
            let may_read = roll.failed.is_none() && roll.read < stretches;
            let idle = roll
                .slots
                .iter()
                .position(|slot| slot.engine.is_some() && slot.stretch.is_none());
            let flying = roll.flying;
            // An engine back with its structures built, its input still
            // held and its packed bytes whole is a high point; so is the
            // member's buffer grown by a stretch.
            if emitted_any || landed_any {
                self.note_peak();
            }
            if emitted == stretches {
                return Ok(());
            }
            if streamed && emitted > started {
                return Ok(());
            }
            if let (true, Some(at)) = (may_read, idle) {
                self.roll_feed(index, at, digest);
                continue;
            }
            let roll = self.segments.roll.as_mut().expect("a roll in flight");
            if flying == 0 {
                // Nothing away, nothing to send out and nothing to read:
                // the reader failed, and every group before it has gone.
                return Err(roll
                    .failed
                    .take()
                    .unwrap_or_else(|| refuse("the segment team's hand-off stalled")));
            }
            match roll.landing.recv() {
                Ok(landed) => roll.take_back(landed),
                Err(_) => return Err(refuse("the segment team's engines went away")),
            }
            self.note_peak();
        }
    }
}
