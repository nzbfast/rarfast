//! A stored member taken wide: fragments abreast across volumes, the cut
//! of one member into granted slices, and the wide plan with its
//! decipher and its joined check.

use super::*;

/// `RARKIT_FRAGMENTS_ABREAST`: how a stored member's fragments UNDER the
/// wide read's floor are read ([`Abreast`]). `0` (or `off`) reads each in
/// order on the member's own thread, the path before; `ahead` reads them
/// with one team of readers kept across their volume files, crossing to
/// the next volume while this one's pieces are joined (`read::across`);
/// `joined` keeps the team but joins everything it holds before it
/// crosses; `1` (or `on`) is ahead for a caller that says its volumes are
/// all present and joined for one that does not; anything else, or
/// nothing, is [`FRAGMENTS_ABREAST`]. A RUNTIME knob, so one binary carries
/// every arm.
#[cfg(feature = "parallel")]
pub(crate) const FRAGMENTS_ABREAST_ENV: &str = "RARKIT_FRAGMENTS_ABREAST";

/// How a run of fragments under the wide read's floor is read.
#[cfg(feature = "parallel")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Abreast {
    /// Each fragment in order on the member's own thread.
    Off,
    /// One kept team; every piece joined before the next volume is opened.
    Joined,
    /// One kept team; the next volume opened while pieces are joined.
    Ahead,
    /// [`Self::Ahead`] where the caller has said every volume is already
    /// present (`ReadOptions::volumes_present`), [`Self::Joined`] where it
    /// has not: SPEC-API 5.3 asks for volume `k + 1` only after the last
    /// byte of `k` unless the caller says otherwise.
    Asked,
}

/// ON, on its rows (2 Oct 2026): `t` of
/// a 12.9 GB stored member in 859 volumes of 15 MB read warm in 0.150 s
/// against 0.849 s on an M3 Ultra and 0.272 s against 0.503 s on an 8-core
/// Zen 4, cold in 2.156 s against 2.670 s and 2.058 s against 2.863 s, with
/// larger volumes, one archive, encrypted and BLAKE2sp members, small
/// members and compressed sets unmoved.
#[cfg(feature = "parallel")]
pub(super) const FRAGMENTS_ABREAST: Abreast = Abreast::Asked;

/// [`FRAGMENTS_ABREAST_ENV`]'s value as an answer.
#[cfg(feature = "parallel")]
pub(super) fn fragments_abreast_of(value: Option<&str>) -> Abreast {
    match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        Some("1" | "on") => Abreast::Asked,
        Some("ahead") => Abreast::Ahead,
        Some("joined") => Abreast::Joined,
        Some("0" | "off") => Abreast::Off,
        _ => FRAGMENTS_ABREAST,
    }
}

#[cfg(feature = "parallel")]
pub(super) fn fragments_abreast() -> Abreast {
    #[cfg(feature = "test-support")]
    match crate::probe::fragments_abreast() {
        Some(0) => return Abreast::Off,
        Some(1) => return Abreast::Ahead,
        Some(_) => return Abreast::Joined,
        None => {}
    }
    static ON: std::sync::OnceLock<Abreast> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        fragments_abreast_of(
            crate::knob::reader_var(FRAGMENTS_ABREAST_ENV)
                .ok()
                .as_deref(),
        )
    })
}

#[cfg(all(test, feature = "parallel"))]
mod fragments_abreast_tests {
    use super::{fragments_abreast_of, Abreast, FRAGMENTS_ABREAST};

    /// `RARKIT_FRAGMENTS_ABREAST=0` keeps the path before on every system,
    /// and the shipped answer is on.
    #[test]
    fn the_knob_keeps_the_path_before() {
        assert_eq!(fragments_abreast_of(Some("0")), Abreast::Off);
        assert_eq!(fragments_abreast_of(Some(" Off ")), Abreast::Off);
        assert_eq!(fragments_abreast_of(Some("1")), Abreast::Asked);
        assert_eq!(fragments_abreast_of(Some("ON")), Abreast::Asked);
        assert_eq!(fragments_abreast_of(Some("ahead")), Abreast::Ahead);
        assert_eq!(fragments_abreast_of(Some("joined")), Abreast::Joined);
        assert_eq!(FRAGMENTS_ABREAST, Abreast::Asked);
        assert_eq!(fragments_abreast_of(None), FRAGMENTS_ABREAST);
        assert_eq!(fragments_abreast_of(Some("2")), FRAGMENTS_ABREAST);
    }
}

/// Whether a fragment of `len` bytes under the wide read's floor begins a
/// run read abreast (`read::across`): the knob says so, the reader gives
/// its fragments by handle (the walk's own stream), the member is checked
/// or written to a stream (a file's writer keeps the slice it has always
/// been offered), and the fragment is inside what the member declares
/// (`emit` drops what is over, so that takes the loop that does).
///
/// The member is one the wide read takes already and is clear: the caller
/// holds its plan, so it declares at least `wide::FLOOR` bytes and a width
/// of one never comes here. Its one check must be a CRC32, asked here: the
/// wide read also takes a clear member under BLAKE2sp alone, and that one
/// keeps the path it has.
#[cfg(feature = "parallel")]
pub(super) fn across_takes<R: PackedRead, W>(
    stream: &R,
    member: &Member<W>,
    len: u64,
    plan: crate::read::wide::Plan,
) -> bool {
    fragments_abreast() != Abreast::Off
        && stream.leads()
        // Pieces of the size this system's plan asks for first: under a
        // budget too small for them a kept team gains nothing on macOS
        // (`wide::full_pieces`), and the member reads as it did.
        && crate::read::wide::full_pieces(plan)
        // Joined by its CRC32 alone: a BLAKE2sp record is one ordered
        // stream with no join, and the wide read's own arm feeds it.
        && member.crc_wanted
        && !member.blake
        && member.sum16.is_none()
        && (!matches!(member.out, Some(Out::Write(_))) || member.wide_write)
        && member
            .unpacked_size
            .is_none_or(|n| member.written + len <= n)
}

/// A run of the member's fragments under the wide read's floor, read and
/// hashed by one team kept across their volumes and joined into the member
/// in order (`read::across`): every byte reaches the member's CRC32, its
/// writer and the tally exactly as the read in order gives it, and each
/// fragment's packed CRC32 is judged over the same bytes. `None` where the
/// stream gave nothing to take.
#[cfg(feature = "parallel")]
pub(super) fn copy_across<R: PackedRead, W: std::io::Write, T: Tally>(
    stream: &mut R,
    member: &mut Member<W>,
    tally: &mut T,
    plan: crate::read::wide::Plan,
) -> Result<Option<crate::read::across::Ended>> {
    use crate::read::across::{run, Ended, Next, Stop};
    let floor = crate::read::wide::FLOOR;
    let room = member
        .unpacked_size
        .map(|n| n.saturating_sub(member.written));
    let first = match stream.lead(floor, room, None)? {
        Next::Lead(lead) => lead,
        Next::Over => return Ok(None),
        Next::End => return Ok(Some(Ended::Member)),
    };
    #[cfg(feature = "test-support")]
    crate::probe::note_fragments_abreast();
    // The bytes come home only where there is a writer to give them to.
    let lend = matches!(member.out, Some(Out::Write(_)));
    // Ahead of the join only for a caller that says its volumes are all
    // present (SPEC-API 5.3), or where the knob states the form.
    let ahead = match fragments_abreast() {
        Abreast::Ahead => true,
        Abreast::Asked => member.volumes_present,
        Abreast::Joined | Abreast::Off => false,
    };
    let mut fragments = Leads { stream, floor };
    let outcome = run(
        plan,
        lend,
        first,
        room,
        ahead,
        &mut fragments,
        // In `emit`'s order: the checksum, then the writer, then the count.
        &mut |crc, len, bytes| {
            member.crc.append(crc, len);
            if let (Some(Out::Write(w)), Some(bytes)) = (&mut member.out, bytes) {
                std::io::Write::write_all(w, bytes)?;
            }
            member.written += len;
            tally.output(len as usize)
        },
    );
    // Nothing of the run is in flight now, whatever it read: the news it
    // kept back is told (spec F 3.7.3, on an error path too).
    let told = stream.fragments_ended();
    match outcome {
        Ok(ended) => told.map(|()| Some(ended)),
        Err(Stop::Short { volume, at }) => Err(stream.truncated_in(volume, at)),
        Err(Stop::Source { volume, error }) => Err(stream.broken_in(volume, error)),
        Err(Stop::Other(error)) => Err(error),
    }
}

/// A member's stream as a read abreast uses it (`across::Fragments`).
#[cfg(feature = "parallel")]
pub(super) struct Leads<'s, R: PackedRead> {
    pub(super) stream: &'s mut R,
    pub(super) floor: u64,
}

#[cfg(feature = "parallel")]
impl<R: PackedRead> crate::read::across::Fragments for Leads<'_, R> {
    fn next(
        &mut self,
        held: Option<crate::read::forwarded::Held>,
        room: Option<u64>,
    ) -> Result<crate::read::across::Next> {
        self.stream.lead(self.floor, room, held)
    }

    fn passed(&mut self, volume: u32, upto: u64, len: u64) -> Result<()> {
        self.stream.passed_in(volume, upto, len)
    }

    fn joined(&mut self, volume: u32, mismatch: bool) -> Result<()> {
        if mismatch {
            self.stream.fragment_failed(volume);
        }
        self.stream.fragment_joined(volume)
    }
}

/// How much of a range of `len` bytes is read wide now, at what plan, and
/// under which grant of the pool's lanes; `None` where the lanes on offer
/// are too few and the member reads a buffer on its own thread instead,
/// and asks again.
///
/// The WALK's own stream has no slice (`PackedRead::grant_slice`) and
/// reads the whole range at the width it was given, as it always has. A
/// DISPATCHED member's lanes come out of the pool's budget, a slice at a
/// time, so the ceiling holds beside the members decoding with it
/// (SPEC-API 8.3, `read::lanes`): a member alone is granted the plan
/// whole, and one with neighbours its fair share until they finish. Under
/// the fewest lanes worth it, the pool is spending its width on members
/// already.
#[cfg(feature = "parallel")]
pub(super) fn granted<'b, R: PackedRead>(
    stream: &R,
    budget: Lanes<'b>,
    plan: crate::read::wide::Plan,
    len: u64,
    first: bool,
) -> Option<(
    u64,
    crate::read::wide::Plan,
    Option<crate::read::lanes::LaneGrant<'b>>,
    bool,
)> {
    let Some(slice) = stream.grant_slice() else {
        return Some((len, plan, None, true));
    };
    let alone = budget.is_none_or(|b| b.members() < 2);
    // Whether the member's writer takes this range itself
    // (`Member::hand_over`, where it has one): the last of the tuple.
    let hand = match slice.cut {
        CutWhen::Never => false,
        CutWhen::Alone => alone,
        CutWhen::Always => true,
    };
    if !hand && (!slice.uncut || (slice.beside_others && alone)) {
        return None;
    }
    // A clear member its writer cuts asks, the FIRST time, for no more
    // than its share of the breadth the pool was asked for ([`CutTake`]).
    let ahead = hand && !slice.uncut && first && cut_take() == CutTake::Ahead;
    let want = if ahead {
        let share = budget.map_or(usize::MAX, |b| b.share_of_breadth());
        plan.workers.min(share.max(slice.fewest))
    } else {
        plan.workers
    };
    let grant = budget.map(|b| b.take(want));
    let lanes = grant.as_ref().map_or(plan.workers, |g| g.lanes());
    (lanes >= slice.fewest).then(|| {
        let plan = crate::read::wide::Plan {
            workers: lanes.min(plan.workers),
            ..plan
        };
        // A member longer than one slice asks again anyway: its first ask,
        // the one capped for the members to come, is a short one. And a
        // member that would be cut were it alone asks again sooner, so one
        // that began beside a short neighbour is cut once it has gone.
        let bytes = if ahead && len > slice.bytes {
            slice.bytes.min(FIRST_ASK)
        } else if slice.cut == CutWhen::Alone && !hand {
            slice.bytes.min(ALONE_RETRY)
        } else {
            slice.bytes
        };
        // And no more under one grant than the budget lets a holder sit
        // on: where the member's worker can be held at the look-ahead's
        // gate, a quarter of its window (`LaneBudget::held_at`).
        let bytes = bytes.min(budget.map_or(u64::MAX, |b| b.grant_bytes()));
        (len.min(bytes), plan, grant, hand)
    })
}

/// `RARKIT_CUT_TAKE`: `all` or `ahead`, what a CLEAR stored member its pool
/// worker cuts (`read::handed`) asks the pool's budget for ([`CutTake`]);
/// anything else, or nothing, is [`CUT_TAKE`]. A RUNTIME knob, so one
/// binary carries both.
#[cfg(feature = "parallel")]
pub(crate) const CUT_TAKE_ENV: &str = "RARKIT_CUT_TAKE";

/// What a clear cut member asks the pool's budget for.
#[cfg(feature = "parallel")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CutTake {
    /// The wide plan's whole width at every ask: the fair share of the
    /// members ADMITTED so far. The arrangement before 2 Oct 2026.
    All,
    /// At a member's FIRST ask, no more than the ceiling over the breadth
    /// the pool was asked for (`LaneBudget::share_of_breadth`): the share
    /// of the members that WILL be in flight. A member of one slice or
    /// less asks once and that is its width. A member longer than a slice
    /// (a big member) makes that first ask a short one ([`FIRST_ASK`]) and from
    /// its second takes the fair share of the members in flight, as
    /// before: beside a sample and an nfo that is the whole width.
    Ahead,
}

/// **`Ahead` on Linux, `All` everywhere else** (measured
/// 2 Oct 2026).
///
/// The cause. Under `All` two members that arrive first take half the
/// ceiling each and hold it for [`Slice::bytes`] (1 GiB); a third cannot
/// be admitted until one gives its lanes back, which for a member of
/// 1 GiB or less is when it ends. Counted on a 96-core Zen 5 to tmpfs,
/// four stored 1 GiB members: two began at 0.009 s and two at 0.174 s,
/// 0.36 s in all, where a run that happened to admit all four first took
/// 0.19 s for the same CPU seconds. The readers a member holds beyond its
/// share do not shorten it: its one writer is what it waits on.
///
/// What `Ahead` buys, to memory, against the parent's own binary (K=5,
/// a quiet box): four 1 GiB members 1.69x on 96 x86 cores, 1.85x on 64
/// Arm cores, 1.18x on 8 cores, 1.16x on 4; sixteen 256 MiB members
/// 1.45x, 1.49x, 1.24x and 1.01x. To an NVMe at 3.4 GB/s every arm is the
/// drive's. One large member does not take this path.
///
/// Why not the simpler rules, each counted in the same runs. A flat
/// cap of four lanes costs a big member beside its sample and nfo, read COLD
/// from an NVMe to memory on 8 cores, 0.86x (its readers are what a cold
/// read spreads over); the breadth's share at every ask, 0.93x; the share
/// with the members waiting, sixteen members on 8 cores 0.90x (a member
/// that gives lanes back to ask again has one taken from under it). A
/// first ask of 128 MiB cost that member 0.96x to memory on 4 cores; of
/// 16 MiB, nothing measured (1.00x cold and warm on 8 cores).
///
/// macOS keeps `All`: there a member is cut only while it is alone in the
/// pool ([`CutWhen::Alone`]), no member waits, and the rows had nothing to
/// gain (an M1 Ultra, to disk). Windows writes a clear member wide and
/// never cuts it, so no value reaches it.
#[cfg(all(feature = "parallel", target_os = "linux"))]
pub(super) const CUT_TAKE: CutTake = CutTake::Ahead;

#[cfg(all(feature = "parallel", not(target_os = "linux")))]
pub(super) const CUT_TAKE: CutTake = CutTake::All;

/// [`CUT_TAKE`], or what [`CUT_TAKE_ENV`] says.
#[cfg(feature = "parallel")]
pub(super) fn cut_take() -> CutTake {
    static TAKE: std::sync::OnceLock<CutTake> = std::sync::OnceLock::new();
    *TAKE.get_or_init(|| cut_take_of(crate::knob::reader_var(CUT_TAKE_ENV).ok().as_deref()))
}

#[cfg(feature = "parallel")]
pub(super) fn cut_take_of(value: Option<&str>) -> CutTake {
    match value
        .map(|text| text.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("all") => CutTake::All,
        Some("ahead") => CutTake::Ahead,
        _ => CUT_TAKE,
    }
}

#[cfg(all(test, feature = "parallel"))]
mod cut_take_tests {
    use super::{cut_take_of, CutTake, CUT_TAKE};

    /// The knob keeps the arrangement before on every system, and names
    /// the other; anything else is the system's own default.
    #[test]
    fn the_knob_keeps_the_parents_path_on_every_system() {
        assert_eq!(cut_take_of(Some("all")), CutTake::All);
        assert_eq!(cut_take_of(Some(" All ")), CutTake::All);
        assert_eq!(cut_take_of(Some("ahead")), CutTake::Ahead);
        assert_eq!(cut_take_of(None), CUT_TAKE);
        assert_eq!(cut_take_of(Some("")), CUT_TAKE);
        assert_eq!(cut_take_of(Some("4")), CUT_TAKE);
    }

    /// The default, a system at a time: the share of the breadth on
    /// Linux, the whole width everywhere else.
    #[test]
    fn the_default_is_each_systems_own() {
        let ahead = cfg!(target_os = "linux");
        assert_eq!(CUT_TAKE == CutTake::Ahead, ahead);
        assert_eq!(CUT_TAKE == CutTake::All, !ahead);
    }
}

/// The bytes of a long member's FIRST ask under [`CutTake::Ahead`]: the
/// wide read's own floor, the least it takes at all, so the member has its
/// whole width back after a hundredth of a second.
#[cfg(feature = "parallel")]
pub(super) const FIRST_ASK: u64 = crate::read::wide::FLOOR;

/// The bytes a member read joined, which its worker would cut were it
/// alone ([`CutWhen::Alone`]), reads before it asks again: whole cipher
/// blocks, long enough that starting the wide read's threads again is
/// under a hundredth of it, and a tenth of a second on a fast drive.
#[cfg(feature = "parallel")]
pub(super) const ALONE_RETRY: u64 = 128 << 20;

/// When a pool worker's member is handed to its own writer to be cut
/// (`read::handed`, [`Slice::cut`]).
#[cfg(feature = "parallel")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CutWhen {
    /// Never: the member has no such writer, or the rule is off.
    Never,
    /// Only while no other member is being decoded.
    Alone,
    /// Whenever the lanes allow.
    Always,
}

/// How a pool worker's wide read of a stored member is granted
/// (`PackedRead::grant_slice`).
#[cfg(feature = "parallel")]
#[derive(Clone, Copy)]
pub(crate) struct Slice {
    /// The most bytes of a `Span::Range` to read wide under ONE grant of
    /// the pool's lanes (`read::lanes`), after which the grant goes back
    /// and the rest of the range is asked for again.
    pub(crate) bytes: u64,
    /// The fewest lanes a grant must hold for the wide read to be taken.
    pub(crate) fewest: usize,
    /// Whether the wide read whose pieces are JOINED (not cut) is taken
    /// only while ANOTHER member is being decoded
    /// (`concurrent::Written::Beside`).
    pub(crate) beside_others: bool,
    /// When the range is handed to the member's writer to be cut instead.
    pub(crate) cut: CutWhen,
    /// Whether the joined wide read may take the member at all: not a
    /// clear member that is written, which goes wide only by the cut.
    pub(crate) uncut: bool,
}

/// `RARKIT_B2SP_WIDE`: `1` (or `on`) reads a CLEAR stored member checked
/// by BLAKE2sp wide where it is tested or printed (`t`, `p`), its pieces
/// fed to the hasher in order by the thread that joins them; `0` (or
/// `off`) leaves it on the ordinary loop, one buffer read and then hashed
/// on one thread, the arrangement before 2 Oct 2026; anything else, or
/// nothing, is [`B2SP_WIDE`]. A RUNTIME
/// knob, so one binary carries both arms. It moves which threads read,
/// never a digest.
#[cfg(feature = "parallel")]
pub(crate) const B2SP_WIDE_ENV: &str = "RARKIT_B2SP_WIDE";

/// Whether such a member is read wide where [`B2SP_WIDE_ENV`] says
/// nothing: yes, from 2 Oct 2026, on its rows
/// (tip against the control's own
/// binary, a quiet box). On a Zen 4 the lone big member's `t` was one thread at
/// every width, the hash and the read in sequence: read wide its cold `t`
/// went 5.83 s to 2.46 s (2.62x over unrar) and its `p` 3.02 s to 2.45 s;
/// on an M1 Ultra, on top of the leaf team's rule, `t` 4.19 s to 3.31 s.
/// A member written to a file, an encrypted one, a stated `-mt1` and a
/// CRC32 set do not move. On a RAID 6 of twelve hard disks, where
/// several far-apart readers were feared, a cold big member's `t` went 14.87 s
/// to 10.01 s and with the knob off it tested BEHIND unrar: the hash, not
/// the seek, is the wall of this shape, so no device rule narrows it.
#[cfg(feature = "parallel")]
pub(super) const B2SP_WIDE: bool = true;

/// [`B2SP_WIDE_ENV`]'s value as an answer.
#[cfg(feature = "parallel")]
pub(super) fn b2sp_wide_of(value: Option<&str>) -> bool {
    match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        Some("1" | "on") => true,
        Some("0" | "off") => false,
        _ => B2SP_WIDE,
    }
}

/// Whether a clear stored member checked by BLAKE2sp is read wide: a
/// test's answer, then the environment's, read once.
#[cfg(feature = "parallel")]
pub(super) fn b2sp_wide() -> bool {
    #[cfg(feature = "test-support")]
    if let Some(forced) = crate::probe::b2sp_wide() {
        return forced;
    }
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| b2sp_wide_of(crate::knob::reader_var(B2SP_WIDE_ENV).ok().as_deref()))
}

/// The wide verify's plan for this member, or `None` when it takes the
/// ordinary loop.
///
/// A member whose one check is a CRC32, whose pieces are hashed apart and
/// joined; or, under [`b2sp_wide`], a CLEAR member whose one check is a
/// BLAKE2sp record, whose pieces are READ apart and fed to the hasher in
/// order by the joining thread (the digest is one ordered stream: its
/// eight leaves are dealt by position). A RAR 1.3 checksum is a serial
/// byte loop, an older cipher runs in order, and an encrypted BLAKE2sp
/// member keeps the overlap of [`copy_overlapped`]. A member that goes nowhere (`t`) always
/// may; a WRITTEN one only where [`Member::wide_write`] says its writer is
/// not a file (`p`), and `verify_wide` then writes it from this thread in
/// piece order, or where its writer takes the range itself
/// ([`Member::hand_over`], the solid path's, `read::handed`).
#[cfg(feature = "parallel")]
pub(super) fn wide_plan<R: PackedRead, W>(
    packed: &Packed<R>,
    member: &Member<W>,
    blake: &Option<Box<Blake2sp>>,
    read_ahead: u64,
    width: usize,
) -> Option<crate::read::wide::Plan> {
    // Clear, or AES-CBC, whose pieces decipher apart. The
    // older ciphers run in order.
    let cbc = packed.decryptor.as_ref().is_some_and(|d| d.is_cbc());
    let hashed = member.blake && blake.is_some();
    let crc_only =
        member.crc_wanted && member.sum16.is_none() && !hashed && (!packed.encrypted() || cbc);
    // A clear member under BLAKE2sp alone: tested, or written by this
    // thread in piece order to a writer that is no file. Never handed to
    // a writer to be cut (`read::handed` accounts for a CRC32 only).
    let blake_only = hashed
        && !member.crc_wanted
        && member.sum16.is_none()
        && !packed.encrypted()
        && (!matches!(member.out, Some(Out::Write(_))) || member.wide_write)
        && b2sp_wide();
    // The same member WRITTEN TO A FILE by the pool worker that reads it:
    // cut by that worker as a CRC32 member is, its hasher fed in order off
    // the writing thread (`read::handed::cut_hashed_here`, `b2sp_cut`).
    let blake_cut = hashed
        && !member.crc_wanted
        && member.sum16.is_none()
        && !packed.encrypted()
        && matches!(member.out, Some(Out::Write(_)))
        && !member.wide_write
        && member.hand_hashed.is_some()
        && crate::read::handed::b2sp_cut().is_some();
    if matches!(member.out, Some(Out::Write(_)))
        && !member.wide_write
        && !(cbc && cipher_to_file())
        && member.hand_over.is_none()
        && !blake_cut
    {
        return None;
    }
    if !(crc_only || blake_only || blake_cut)
        || member
            .unpacked_size
            .is_some_and(|n| n < crate::read::wide::FLOOR)
    {
        return None;
    }
    // The hashed plan is the TESTED member's: one written to a file keeps
    // the plan it had (its pieces are also what the writer is handed, and
    // in the pair `x` of a 4 GiB member read 0.969 by minima in pieces of
    // 4 MiB where `t` read 1.344).
    if blake_only {
        crate::read::wide::plan_hashed(width, read_ahead)
    } else {
        crate::read::wide::plan(width, read_ahead)
    }
}

/// Whether [`wide_plan`] will take this member, asked from its HEADER
/// before any stream is open, which is where the seam is chosen. The same
/// conditions: stored, clear or AES-CBC (`opaque` is a cipher the wide
/// read cannot take), a CRC32 record (or, `clear` and under [`b2sp_wide`],
/// a BLAKE2sp one) and no RAR 1.3 checksum, a declared size at the floor,
/// and a width to spread over.
#[cfg(feature = "parallel")]
pub(super) fn wide_takes(
    codec: Option<&Codec>,
    file: &FileHdr,
    format: Format,
    opaque: bool,
    clear: bool,
    width: usize,
    read_ahead: u64,
) -> bool {
    matches!(codec, Some(Codec::Stored))
        && !opaque
        && match file.checksum {
            Some(Checksum::Crc32(_)) => true,
            Some(Checksum::Blake2sp(_)) => clear && b2sp_wide(),
            _ => false,
        }
        && !matches!(format, Format::Rar13)
        && file
            .unpacked_size
            .is_some_and(|n| n >= crate::read::wide::FLOOR)
        && crate::read::wide::plan(width, read_ahead).is_some()
}

/// `len` bytes at `at` of `source`, the rest of the member's current
/// fragment, read and hashed wide and joined into the member in order:
/// each piece reaches the stream (the fragment's packed CRC32 and the
/// drop-behind report), the member's CRC32 and the tally exactly as a
/// serial read of the same bytes would reach them. `plan` is the plan the
/// pool's lanes granted and `whole` the member's own, whose window a range
/// handed to its writer keeps. With a `hasher` (a member under BLAKE2sp,
/// [`b2sp_wide`]) the pieces are only READ wide, and each is fed to it in
/// order as it is joined.
#[cfg(feature = "parallel")]
#[allow(clippy::too_many_arguments)]
pub(super) fn verify_wide<R: PackedRead, W: std::io::Write, T: Tally>(
    stream: &mut R,
    member: &mut Member<W>,
    tally: &mut T,
    source: &std::sync::Arc<dyn crate::source::RangeSource>,
    at: u64,
    len: u64,
    plan: crate::read::wide::Plan,
    whole: crate::read::wide::Plan,
    hand: bool,
    hasher: Option<&mut Blake2sp>,
    hold: Option<&mut crate::read::wide::Hold>,
) -> Result<()> {
    wide_joined(
        stream, member, tally, source, at, len, plan, whole, hand, None, hasher, hold,
    )
    .map(|_| ())
}

/// [`verify_wide`] for an ENCRYPTED stored member: `len`
/// bytes at `at`, whole blocks from a chain with nothing carried, read,
/// deciphered and hashed wide, and joined in order; the member's chain
/// then goes on from their last ciphertext block exactly as if it had
/// deciphered them itself (SPEC-K 2.1, 3.7.4).
#[cfg(feature = "parallel")]
#[allow(clippy::too_many_arguments)]
pub(super) fn decipher_wide<R: PackedRead, W: std::io::Write, T: Tally>(
    packed: &mut Packed<R>,
    member: &mut Member<W>,
    tally: &mut T,
    source: &std::sync::Arc<dyn crate::source::RangeSource>,
    at: u64,
    len: u64,
    plan: crate::read::wide::Plan,
    whole: crate::read::wide::Plan,
    hand: bool,
    hold: Option<&mut crate::read::wide::Hold>,
) -> Result<()> {
    let decryptor = packed.decryptor.as_mut().expect("checked by the caller");
    let Some((pieces, chain)) = decryptor.pieces(plan.piece) else {
        unreachable!("an AES-CBC chain with nothing carried, checked by the caller")
    };
    let cipher = crate::read::wide::Cipher {
        pieces,
        chain,
        packed_crc: packed.stream.packed_crc_wanted(),
        // The joined read; the cut asks for the page itself.
        page_plain: false,
    };
    let last = wide_joined(
        &mut packed.stream,
        member,
        tally,
        source,
        at,
        len,
        plan,
        whole,
        hand,
        Some(cipher),
        None,
        hold,
    )?;
    packed
        .decryptor
        .as_mut()
        .expect("checked by the caller")
        .resume(last);
    Ok(())
}

/// The combiner both wide reads share: each piece reaches the stream (the
/// fragment's packed CRC32 and the drop-behind report), the member's CRC32,
/// its writer and the tally exactly as a serial read of the same bytes
/// would reach them, and the last piece's final ciphertext block is
/// answered.
#[cfg(feature = "parallel")]
#[allow(clippy::too_many_arguments)]
pub(super) fn wide_joined<R: PackedRead, W: std::io::Write, T: Tally>(
    stream: &mut R,
    member: &mut Member<W>,
    tally: &mut T,
    source: &std::sync::Arc<dyn crate::source::RangeSource>,
    at: u64,
    len: u64,
    plan: crate::read::wide::Plan,
    whole: crate::read::wide::Plan,
    hand: bool,
    cipher: Option<crate::read::wide::Cipher>,
    mut hasher: Option<&mut Blake2sp>,
    hold: Option<&mut crate::read::wide::Hold>,
) -> Result<[u8; 16]> {
    use crate::read::wide::{verify_range_held, Stop};
    #[cfg(feature = "test-support")]
    crate::probe::note_wide_verify();
    // A range whose writer takes it whole (`read::handed`): the thread
    // behind the writer reads, hashes and writes it, and each piece it has
    // delivered is accounted for here exactly as the combiner below
    // accounts for one, in order. A cipher's pieces borrow the member's
    // key, which does not leave this thread: only a writer that cuts the
    // range on this thread takes a deciphered one.
    let (hand_over, hand_cipher) = (member.hand_over, member.hand_cipher);
    // A CLEAR member under BLAKE2sp whose writer takes hashed ranges (a
    // pool worker's, `read::handed::cut_hashed_here`): the range is read
    // by one reader in order, the hasher is fed off this thread, and this
    // thread writes. Each piece is accounted for here as below, less the
    // member's CRC32, which it does not carry.
    if hand && cipher.is_none() && !member.wide_write {
        if let (Some(hasher), Some(hand_hashed), Some(dial)) = (
            hasher.as_deref_mut(),
            member.hand_hashed,
            crate::read::handed::b2sp_cut(),
        ) {
            if let Some(Out::Write(w)) = &mut member.out {
                let written = &mut member.written;
                let range = crate::read::handed::Range {
                    source: std::sync::Arc::clone(source),
                    at,
                    len,
                    plan,
                    window: (whole.workers * whole.piece) as u64,
                    before: *written,
                };
                let hashed = crate::read::handed::Hashed {
                    hasher,
                    dial,
                    packed_crc: stream.packed_crc_wanted(),
                };
                let mut passed = |piece: crate::read::handed::Passed| {
                    stream.passed(piece.packed_crc, piece.len)?;
                    *written += piece.len;
                    tally.output(piece.len as usize)
                };
                return match hand_hashed(w, range, hashed, &mut passed) {
                    Ok(()) => Ok([0; 16]),
                    Err(Stop::Short(end)) => Err(stream.truncated_at(end)),
                    Err(Stop::Source(error)) => Err(stream.broken_by(error)),
                    Err(Stop::Accepted(error)) => Err(error),
                };
            }
        }
    }
    // A range under BLAKE2sp that was not cut above is read WIDE (a cut
    // one is counted where it is cut, `probe::note_b2sp_cut`).
    #[cfg(feature = "test-support")]
    if hasher.is_some() {
        crate::probe::note_b2sp_wide();
    }
    // `hand` is the lane grant's word on it (`granted`): a pool worker's
    // member is cut only when its rule says so.
    // Never a member under BLAKE2sp: this hand-over accounts for a CRC32.
    let handed = hand
        && hasher.is_none()
        && match cipher {
            None => hand_over.is_some(),
            Some(_) => hand_cipher.is_some() && !member.wide_write,
        };
    if handed {
        if let Some(Out::Write(w)) = &mut member.out {
            let (crc, written) = (&mut member.crc, &mut member.written);
            let range = crate::read::handed::Range {
                source: std::sync::Arc::clone(source),
                at,
                len,
                plan,
                window: (whole.workers * whole.piece) as u64,
                before: *written,
            };
            let mut passed = |piece: crate::read::handed::Passed| {
                stream.passed(piece.packed_crc, piece.len)?;
                crc.append(piece.crc, piece.len);
                *written += piece.len;
                tally.output(piece.len as usize)
            };
            let outcome = match (cipher, hand_over, hand_cipher) {
                (None, Some(hand), _) => hand(w, range, &mut passed).map(|()| [0; 16]),
                (Some(cipher), _, Some(hand)) => hand(w, range, cipher, &mut passed),
                _ => unreachable!("checked above"),
            };
            return match outcome {
                Ok(last) => Ok(last),
                Err(Stop::Short(end)) => Err(stream.truncated_at(end)),
                Err(Stop::Source(error)) => Err(stream.broken_by(error)),
                Err(Stop::Accepted(error)) => Err(error),
            };
        }
    }
    // The bytes come home only where there is a writer to give them to,
    // or a hasher to feed.
    let lend = matches!(member.out, Some(Out::Write(_))) || hasher.is_some();
    let mut last = cipher.as_ref().map_or([0; 16], |c| c.chain);
    let outcome = verify_range_held(source, at, len, plan, hold, lend, cipher, &mut |piece| {
        stream.passed(piece.packed_crc, piece.len)?;
        member.crc.append(piece.crc, piece.len);
        // In `emit`'s order: the checksum, then the writer, then the count.
        // The BLAKE2sp digest is fed HERE, on the joining thread and in
        // piece order, while the readers read on: one ordered stream.
        if let Some(hasher) = hasher.as_deref_mut() {
            debug_assert!(piece.bytes.is_some(), "a hashed range lends its bytes");
            if let Some(bytes) = piece.bytes {
                hasher.update(bytes);
            }
        }
        if let (Some(Out::Write(w)), Some(bytes)) = (&mut member.out, piece.bytes) {
            std::io::Write::write_all(w, bytes)?;
        }
        member.written += piece.len;
        last = piece.chain;
        tally.output(piece.len as usize)
    });
    match outcome {
        Ok(()) => Ok(last),
        Err(Stop::Short(end)) => Err(stream.truncated_at(end)),
        Err(Stop::Source(error)) => Err(stream.broken_by(error)),
        Err(Stop::Accepted(error)) => Err(error),
    }
}
