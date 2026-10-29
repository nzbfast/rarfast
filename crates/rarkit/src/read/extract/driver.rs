//! What drives an extract: the job a member becomes, what closing one
//! says, the `Driver` every path implements, and the direct one.

use super::*;

/// One member's decode, everything it needs, and nothing that borrows the
/// walk.
///
/// That last clause is the whole point of the shape: a job holds its
/// volume's source by `Arc` and its member's byte range in that volume, so
/// a worker can read and decode it long after the walk has passed it. Spec
/// F 3.5.4 joins a SPLIT member's fragments inside the walk, so a job is
/// never one of those: [`dispatchable`] says which members qualify.
#[cfg(feature = "parallel")]
pub(crate) struct Job<W> {
    pub(crate) src: std::sync::Arc<dyn crate::source::RangeSource>,
    pub(crate) data: std::ops::Range<u64>,
    pub(crate) file: FileHdr,
    pub(crate) name: Vec<u8>,
    pub(crate) format: Format,
    pub(crate) out: Out<W>,
    pub(crate) codec: Codec,
    pub(crate) decryptor: Option<MemberDecryptor>,
    pub(crate) keys: Option<Rar5Keys>,
    /// The volume the member's range is in, counting from zero: what the
    /// sequential driver's drop-behind is held back by (`read::sequential`).
    pub(crate) volume: u32,
    /// The member's archive is a volume of a set (`Walk::in_set`), which
    /// the verdict of a member that ends short turns on.
    pub(crate) in_set: bool,
    /// A member SPLIT across volumes: the rest of its fragments, which the
    /// walk sends as it crosses to them ([`Split`]). `None` for a member
    /// whose whole packed range is `data`.
    pub(crate) split: Option<Split>,
}

/// The rest of a split member, for a worker that reads it whole.
///
/// A member that crosses a volume boundary is joined inside the walk (spec
/// F 3.5.4), which is why it was never dispatched: the walk could not read
/// the next member's header until this one's last fragment was consumed,
/// so every volume boundary of a stored volume set was a member-long
/// barrier with the pool idle behind it. Here the walk still does all of
/// 3.5.4 itself, on its own thread, in order: it crosses into each next
/// volume, checks the continuation header's name, size and method, and
/// only then SENDS the fragment it found. The worker reads the fragments
/// in that order and judges each leading fragment's packed CRC32 (3.5.6)
/// exactly as the walk's own stream would have.
#[cfg(feature = "parallel")]
pub(crate) struct Split {
    /// The first fragment's packed CRC32, which `data` is judged against.
    pub(crate) checksum: Option<u32>,
    pub(crate) more: std::sync::mpsc::Receiver<Next>,
}

/// What the walk sends a split member's worker next.
#[cfg(feature = "parallel")]
pub(crate) enum Next {
    /// The member's next fragment: its volume's source, its packed range,
    /// and the packed CRC32 its header carries where it is to be judged
    /// (every fragment but the last).
    Fragment {
        src: std::sync::Arc<dyn crate::source::RangeSource>,
        data: std::ops::Range<u64>,
        checksum: Option<u32>,
        /// The volume it is in, which the worker's own read errors name as
        /// the walk's would.
        volume: u32,
        /// Its place in the count of fragments forwarded and unread
        /// (`read::forwarded`), which the worker drops when it has read it.
        held: crate::read::forwarded::Held,
    },
    /// No more fragments: the LAST fragment's header, which carries the
    /// member's checksum and says how to compare it (3.5.6, spec K 3.7.4).
    End(Box<FileHdr>),
}

/// What a driver's own closes add to the report.
#[derive(Default)]
pub(crate) struct Closed {
    pub(crate) members: u64,
    /// Bytes produced away from the walking thread, which the walk's own
    /// tally never saw.
    pub(crate) bytes: u64,
    pub(crate) checksum_failures: u64,
    /// Working memory this driver's workers hold.
    pub(crate) working_memory: u64,
    /// The FIRST error in archive order among the members it closed,
    /// raised once every member has had its `close` (spec F section 8).
    pub(crate) deferred: Option<Error>,
    /// Bytes the WALK decoded and counted for members the caller then
    /// skipped, which the sequential path would never have decoded: the
    /// decode-ahead driver's (`read::sequential`), taken off the report.
    pub(crate) walk_bytes_skipped: u64,
}

impl Closed {
    /// A member the caller skipped, counted as a closed one is
    /// ([`Driver::skipped`]).
    pub(crate) fn skip(&mut self, outcome: &MemberOutcome, err: Option<Error>) {
        self.members += 1;
        if outcome.checksum_ok == Some(false) {
            self.checksum_failures += 1;
        }
        if self.deferred.is_none() {
            self.deferred = err;
        }
    }
}

/// Where a member's decode runs, and where its `close` happens.
///
/// The sequential driver ([`Direct`]) decodes every member itself and
/// closes it at the decode site. The concurrent one
/// ([`crate::read::concurrent::Pool`]) hands a non-solid member to a worker
/// and closes it later - but through the SAME queue the members it decoded
/// itself go through, so archive order is structural here and not an
/// argument about which thread finished first.
///
/// **Every close of every member goes through `close`**, which is what
/// carries spec F section 8: the member is counted, its verdict is the
/// caller's, and the error that belongs to it is kept in archive order.
pub(crate) trait Driver {
    type Out: std::io::Write;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Self::Out>>;

    /// Close one member with its own outcome and its own error, counting
    /// it. A driver that has members in flight ahead of this one closes
    /// those first.
    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Self::Out>,
        outcome: &MemberOutcome,
        err: Option<Error>,
    ) -> Result<()>;

    /// Settle one member the caller answered `Skip` at `open`, counting it
    /// as [`Driver::close`] counts a member, with no call to the caller:
    /// `Sink::close` is promised only for a member opened with `Write` or
    /// `Verify` (SPEC-API 4.4), and a skipped one's fragments are judged by
    /// nobody (spec F 3.5.6). What its read met still reaches the report
    /// as it did when such a member was closed: a refusal, or the failed
    /// decode of a solid member the chain needed, is a checksum failure
    /// and its error the operation's deferred one (spec F section 8).
    fn skipped(
        &mut self,
        member: &MemberInfo<'_>,
        outcome: &MemberOutcome,
        err: Option<Error>,
    ) -> Result<()>;

    /// A leading fragment of `member`, in `volume`, disagreed with its
    /// header's packed CRC32 (spec F 3.5.6): called once per such fragment
    /// before the member's `close`. A driver whose caller has already
    /// opened the member passes it straight on; one that opens the
    /// member later carries it to that member's close.
    fn fragment_mismatch(&mut self, member: &MemberInfo<'_>, volume: u32) -> Result<()>;

    /// The archive being walked is solid, or is not.
    ///
    /// A driver that decides anything from it needs it before the first
    /// member, which is where the main header sits.
    fn note_solid(&mut self, solid: bool) {
        let _ = solid;
    }

    /// Whether the walk stops BEFORE this member, its header read and
    /// nothing of it opened, and hands the rest of the archive to the next
    /// driver ([`Walking::phase`]). Only a driver that runs one phase of a
    /// two-phase walk answers yes (`read::sequential`).
    #[inline(always)]
    fn hands_off(
        &self,
        solid_archive: bool,
        file: &FileHdr,
        block: &crate::read::block::Block,
    ) -> bool {
        let _ = (solid_archive, file, block);
        false
    }

    /// Whether this driver may take the job of the member it last
    /// opened. A driver that answers no is never asked to build one, so
    /// the sequential path pays nothing for the existence of the
    /// concurrent one. Asked once a member, after its `open`, so a driver
    /// may answer per member (`read::sequential`).
    #[cfg(feature = "parallel")]
    fn offloads(&self) -> bool {
        false
    }

    /// Whether this driver takes a member SPLIT across volumes as a job
    /// whose fragments the walk sends as it reaches them ([`Split`]).
    /// Only a driver that never waits at a volume's end for the members in
    /// flight may: one that hands its look-ahead over at `volume_done`
    /// (`read::sequential`) would wait there for a member whose next
    /// fragment the walk has not reached.
    #[cfg(feature = "parallel")]
    fn takes_split(&self) -> bool {
        false
    }

    /// Whether this driver also takes a member BELOW the offload floor,
    /// in a batch with its neighbours ([`batchable`]). Only the concurrent
    /// pool with `RARKIT_SMALL_BATCH` set answers yes.
    #[cfg(feature = "parallel")]
    fn batches_small(&self) -> bool {
        false
    }

    /// x86-64 only: whether the small batches also take a
    /// member that is WRITTEN (`x`). The concurrent pool answers yes only
    /// when `RARKIT_SMALL_BATCH` was set by name.
    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    fn batches_written(&self) -> bool {
        false
    }

    /// Whether a member this driver decodes on the WALKING thread may
    /// overlap its own stages with its write (spec F 3.7.7).
    ///
    /// True for the sequential driver, which writes into the caller's own
    /// writer and has nothing else hiding the write. FALSE for the
    /// concurrent one: a member it decodes on the walking thread already
    /// pipes its writes to a worker (`concurrent::Handoff`), which is the
    /// same overlap got the other way round, and a seam on top of it would
    /// spend a second unit of the ceiling to hide a stage that is already
    /// hidden. SPEC-API 8.5 allows a member decoded on a POOL WORKER to
    /// overlap its own stages for one unit as well; that is not done yet and
    /// is not this.
    #[cfg(feature = "parallel")]
    fn overlaps(&self) -> bool {
        false
    }

    /// How this driver's writer takes a stored member's RANGE instead of
    /// its bytes (`read::handed`), or `None` where it cannot: only a
    /// driver whose writer leads to another thread, which can read the
    /// range itself, answers one (`read::sequential`, the solid path).
    #[cfg(feature = "parallel")]
    fn hand_over(&self) -> Option<crate::read::handed::HandOver<Self::Out>> {
        None
    }

    /// The lane budget this driver's members share, if it shares one.
    ///
    /// The sequential driver has one member decoding at a time and needs
    /// none: its width is the whole ceiling by arithmetic rather than by
    /// reservation, which is what 8.2 means by a stage running narrower
    /// being in contract.
    #[cfg(feature = "parallel")]
    fn lane_budget(&self) -> Option<std::sync::Arc<crate::read::lanes::LaneBudget>> {
        None
    }

    /// Offer a member's decode to a worker. Handing the job back leaves it
    /// to the walk, which is what the sequential driver always does.
    #[cfg(feature = "parallel")]
    fn offer(&mut self, job: Job<Self::Out>) -> Result<Option<Job<Self::Out>>> {
        Ok(Some(job))
    }

    /// A name buffer the driver has finished with, so building a job costs
    /// no allocation per member once the run is warm.
    #[cfg(feature = "parallel")]
    fn spare_name(&mut self) -> Vec<u8> {
        Vec::new()
    }

    /// Close everything taken and not yet closed, in archive order.
    fn settle(&mut self) -> Result<()> {
        Ok(())
    }

    /// What this driver's closes add to the report.
    fn closed(&mut self) -> Closed;

    /// The member about to be closed was REFUSED before any decode (no
    /// decoder claims it), which the sequential path counts as a failure
    /// even for a member the sink skipped (`Driver::skipped`). A driver
    /// that closes members later needs to know it; nothing else does.
    fn note_refused(&mut self) {}

    /// Decoded bytes this driver has handed the caller that the walk never
    /// counted, so far: what the caller's `Progress::output` adds to the
    /// walk's own count. Nothing for a driver whose members all reach the
    /// caller through the walk.
    fn delivered(&self) -> u64 {
        0
    }
}

/// The sequential driver: the caller's sink, and nothing between.
pub(crate) struct Direct<'a, K: Sink> {
    pub(super) sink: &'a mut K,
    pub(super) closed: Closed,
}

impl<'a, K: Sink> Direct<'a, K> {
    pub(crate) fn new(sink: &'a mut K) -> Direct<'a, K> {
        Direct {
            sink,
            closed: Closed::default(),
        }
    }
}

impl<K: Sink> Driver for Direct<'_, K> {
    type Out = K::Out;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<K::Out>> {
        self.sink.open(member)
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<K::Out>,
        outcome: &MemberOutcome,
        err: Option<Error>,
    ) -> Result<()> {
        self.closed.members += 1;
        if outcome.checksum_ok == Some(false) {
            self.closed.checksum_failures += 1;
        }
        self.sink.close(member, out, outcome)?;
        if self.closed.deferred.is_none() {
            self.closed.deferred = err;
        }
        Ok(())
    }

    fn skipped(
        &mut self,
        _member: &MemberInfo<'_>,
        outcome: &MemberOutcome,
        err: Option<Error>,
    ) -> Result<()> {
        self.closed.skip(outcome, err);
        Ok(())
    }

    fn fragment_mismatch(&mut self, member: &MemberInfo<'_>, volume: u32) -> Result<()> {
        self.sink.fragment_mismatch(member, volume)
    }

    #[cfg(feature = "parallel")]
    fn overlaps(&self) -> bool {
        true
    }

    fn closed(&mut self) -> Closed {
        std::mem::take(&mut self.closed)
    }
}
