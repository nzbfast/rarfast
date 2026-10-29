//! A worker's bench: its decoders and scratch, and one member's decode on it.

use super::*;

/// One worker's own decoders, buffers and hasher: one set per WORKER, never
/// one per member, which is what SPEC-API 5.2 means by the sequential
/// figure times the worker count.
pub(crate) struct Bench {
    pub(super) decoders: Decoders,
    pub(super) scratch: Scratch,
    pub(super) blake: Option<Box<Blake2sp>>,
    /// This worker's read window over whichever volume it is reading.
    pub(super) read_buf: Vec<u8>,
    pub(super) policy: MemoryPolicy,
    pub(super) cancel: Option<Arc<AtomicBool>>,
    /// The read window above, charged to `memory::current` after every
    /// member: API section 8's counters are whole-process, and a worker's
    /// read buffer is resident as surely as its ring (the decoders charge
    /// their windows and the scratch, `extract::decode`).
    pub(super) charge: crate::memory::Held,
}

impl Bench {
    /// This bench's workers rebuild and release rings under `shrink`
    /// (`extract::Shrink`); the sequential look-ahead's are `Tight`.
    pub(crate) fn with_shrink(mut self, shrink: extract::Shrink) -> Self {
        self.decoders.shrink = shrink;
        self
    }

    /// Whether the caller STATED the width this bench's members decode
    /// at (`extract::Decoders::width_stated`).
    pub(crate) fn with_width_stated(mut self, stated: bool) -> Self {
        self.decoders.width_stated = stated;
        self
    }

    /// The pool's order for the NEXT member: with `exact`, a held ring
    /// larger than the member reaches is rebuilt at its reach
    /// (`extract::Shrink::Exact`); without, the bench's own rule again.
    /// Only a bench under a NAMED budget, whose rule is `Tight`, is ever
    /// ordered, so `Tight` is what the order is lifted back to.
    pub(crate) fn set_exact(&mut self, exact: bool) {
        if exact {
            self.decoders.shrink = extract::Shrink::Exact;
        } else if self.decoders.shrink == extract::Shrink::Exact {
            self.decoders.shrink = extract::Shrink::Tight;
        }
    }

    /// A worker's bench: its own decoders, sharing `budget`'s lanes.
    pub(crate) fn new(
        policy: MemoryPolicy,
        cancel: Option<Arc<AtomicBool>>,
        budget: Option<Arc<crate::read::lanes::LaneBudget>>,
    ) -> Bench {
        let mut decoders = Decoders::default();
        decoders.budget = budget;
        Bench {
            decoders,
            scratch: Scratch::default(),
            blake: None,
            read_buf: Vec::new(),
            policy,
            cancel,
            charge: crate::memory::Held::default(),
        }
    }

    pub(crate) fn working(&self) -> u64 {
        self.decoders
            .window_bytes()
            .saturating_add(self.scratch.held_bytes())
            .saturating_add(self.read_buf.capacity() as u64)
    }

    /// Decode one member from its own byte range, `width` lanes at most.
    ///
    /// `width` is this member's SHARE of the operation's ceiling, which
    /// the pool worked out from the breadth it is running at (8.3). It
    /// reaches the tape decode as the policy's `max_workers`, because that
    /// is the field `tape::workers` mins against; nothing else about the
    /// policy changes, so the window bound and the refusals a member meets
    /// are the ones the sequential path would have given it.
    pub(crate) fn decode<W: Write + Send>(
        &mut self,
        job: Job<PoolOut<W>>,
        width: usize,
    ) -> Done<W> {
        self.decode_with(job, width, false)
    }

    /// [`Bench::decode`], with the member's CRC32 left to whoever DELIVERS
    /// its bytes when `crc_on_deliver`, as the one-member seam does for a
    /// member with a decoder (`seam::checksum_on_deliver`): the fold then
    /// runs beside the caller's write and not on the decode's serial
    /// apply. The verdict comes back unfinished in [`Done::verdict`], for
    /// the deliverer to finish with the CRC32 it ran. Only a member whose
    /// checksum IS a CRC32 is taken this way; any other decodes as before.
    pub(crate) fn decode_with<W: Write + Send>(
        &mut self,
        job: Job<PoolOut<W>>,
        width: usize,
        crc_on_deliver: bool,
    ) -> Done<W> {
        // Counts the BREADTH the same way the lanes count the width;
        // compiled out entirely without `test-support`. See `crate::probe`.
        #[cfg(feature = "test-support")]
        let _member = crate::probe::MemberGuard::enter();
        #[cfg(feature = "wait-census")]
        let _census = crate::probe::census::at(crate::probe::census::DECODE);
        // THE WIDTH IS THE DECODERS', NOT THE POLICY'S (API 8.4.2). It
        // used to be handed over as a policy whose `max_workers` was this
        // member's share, which made a memory field carry a thread count;
        // the policy now travels untouched, so the window bound, the
        // refusals and the BLAKE2sp team this member meets are exactly
        // the ones the sequential path would have given it.
        self.decoders.decode_width = width.max(1);
        let policy = self.policy;
        let Job {
            src,
            data,
            file,
            name,
            format,
            out,
            codec,
            decryptor,
            keys,
            volume: job_volume,
            in_set,
            split,
        } = job;
        // The caller's writer comes out of the carrier the walk put it in;
        // a piped one here would mean the pool offered a member it had
        // already given a worker, which `offloadable` forbids.
        let written = matches!(out, Out::Write(_));
        let out = match out {
            Out::Write(PoolOut::Carried(w)) => Out::Write(w),
            Out::Write(PoolOut::Piped(_)) => {
                unreachable!("a dispatched member carries the caller's own writer")
            }
            Out::Verify => Out::Verify,
        };
        let mut member = Member::of(
            Some(out),
            &file,
            format,
            keys,
            &mut self.blake,
            // The BLAKE2sp leaf team's ceiling is the operation's, not a
            // share of it: API 8.2 bounds each STAGE by `max_workers`, and
            // the team engages only on a batch large enough to be worth it,
            // so a member hashed on a worker asks for no more threads than
            // the same member hashed on the walking thread would. Under
            // `extract::TeamRule`'s other values the width is this
            // worker's share, as its decode's is.
            extract::blake_workers(&self.policy, &self.decoders),
        );
        member.in_set = in_set;
        // A split member's verdict needs its fragments' own, which the
        // deliverer does not see: it is finished here.
        let deferred = crc_on_deliver
            && split.is_none()
            && matches!(file.checksum, Some(crate::types::Checksum::Crc32(_)))
            && member.detach_crc().is_some();
        let (judge, more, split_volume) = match split {
            Some(split) => (
                split.checksum.map(|c| (crate::checksum::Crc32::new(), c)),
                Some(split.more),
                Some(job_volume),
            ),
            None => (None, None, None),
        };
        let wide = match (&codec, decryptor.as_ref()) {
            (extract::Codec::Stored, Some(cipher)) if cipher.is_cbc() => job_wide(),
            (extract::Codec::Stored, None) if job_wide_clear() => job_wide(),
            _ => 0,
        };
        if wide > 0 && job_wide_write() {
            member.wide_write = true;
        }
        // A stored member this worker WRITES to a file is cut here, into
        // aligned pieces at whole offsets, by its own readers
        // (`read::handed`): the worker is the writer's thread and holds
        // the member's key.
        let cut = written
            && wide > 0
            && !member.wide_write
            && crate::read::handed::stored_cut().is_some();
        // An encrypted one only where the cipher's cut is on (macOS).
        let cut = cut && (decryptor.is_none() || crate::read::handed::stored_cut_cipher());
        if cut {
            member.hand_over = Some(crate::read::handed::cut_here::<W>);
            member.hand_cipher = Some(crate::read::handed::cut_cipher_here::<W>);
            member.hand_hashed = Some(crate::read::handed::cut_hashed_here::<W>);
        }
        let (wide, beside_others) = match (written, job_wide_written()) {
            // Never: neither read wide nor cut (Windows, until its rows).
            (true, Written::Never) => (0, false),
            (true, Written::Beside) => (wide, true),
            _ => (wide, false),
        };
        // A clear one's readers are two at most, whatever the width.
        let wide = if cut && decryptor.is_none() {
            wide.min(CUT_LANES)
        } else {
            wide
        };
        let cut_when = if cut {
            stored_cut_when()
        } else {
            extract::CutWhen::Never
        };
        // The joined wide read takes a member that is only verified, one
        // whose writer is no file, and an encrypted one; a clear member
        // written to a file goes wide by the cut alone.
        let uncut = !written || member.wide_write || decryptor.is_some();
        let mut source = RangeRead {
            src,
            at: data.start,
            end: data.end,
            name: &name,
            more,
            judge,
            mismatches: Vec::new(),
            last: None,
            yielded: false,
            volume: split_volume,
            buf: std::mem::take(&mut self.read_buf),
            at_in_buf: 0,
            filled: 0,
            broken: false,
            wide,
            beside_others,
            cut: cut_when,
            uncut,
            held: None,
        };
        let mut tally = Polled {
            cancel: self.cancel.as_deref(),
            since: 0,
        };
        let outcome = extract::decode(
            &mut source,
            &mut member,
            &mut self.blake,
            &mut tally,
            decryptor,
            codec,
            &mut self.decoders,
            &mut self.scratch,
            &policy,
            // A dispatched member never continues a chain: that is what
            // made it dispatchable, and it is also why there is no chain
            // in front of it to decode ahead of.
            false,
            None,
        )
        .and_then(|()| source.drain_split());
        // The buffer goes back whatever happened, so the next member this
        // worker takes reuses it.
        self.read_buf = std::mem::take(&mut source.buf);
        let mismatches = std::mem::take(&mut source.mismatches);
        let bytes = member.written;
        let (checksum_ok, error, fatal, verdict, out) = match outcome {
            // The deliverer finishes it, with the CRC32 it ran.
            Ok(()) if deferred => {
                let out = member.out.take();
                let unfinished = Box::new(Unfinished {
                    member: member.retarget::<()>(Some(Out::Verify)),
                    file: file.clone(),
                });
                (None, None, false, Some(unfinished), out)
            }
            // It was not refused, or it would never have been read. A split
            // member is judged by its LAST header alone (3.5.6); a leading
            // fragment whose field disagreed rides in `mismatches`.
            Ok(()) => (
                extract::verdict(
                    &member,
                    &mut self.blake,
                    source.last.as_deref().unwrap_or(&file),
                    false,
                ),
                None,
                false,
                None,
                member.out.take(),
            ),
            Err(e) => {
                let fatal = source.broken || extract::ends_operation(&e);
                (
                    Some(false),
                    Some(e.with_member(&name)),
                    fatal,
                    None,
                    member.out.take(),
                )
            }
        };
        self.recharge();
        Done {
            out: match out {
                Some(Out::Write(w)) => Some(w),
                _ => None,
            },
            bytes,
            verdict,
            checksum_ok,
            error,
            fatal,
            yielded: source.yielded,
            name,
            mismatches,
            spare: Vec::new(),
            working: self.working(),
        }
    }

    /// Bring the process counters' charge for this bench's read window up
    /// to what it holds (its decoders charge their windows and its scratch
    /// themselves, `extract::decode`).
    pub(super) fn recharge(&mut self) {
        self.charge.set(self.read_buf.capacity() as u64);
    }
}
