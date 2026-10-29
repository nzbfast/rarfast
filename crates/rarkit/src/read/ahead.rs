//! The packed-byte lookahead that feeds a solid chain's decode-ahead.
//!
//! **What it is for.** SPEC-H2 section 3.8 says a block's symbol stream
//! depends only on the tables in force for it, so the members AHEAD of the
//! one being applied can be Huffman decoded while it is applied. The
//! decoder cannot reach them on its own: it is handed one member's packed
//! bytes at a time, and which bytes those are is a question about the
//! CONTAINER, which is this layer's (spec H2 section 1.2 puts the headers,
//! the declared size and the solid flag here).
//!
//! So this is the half of the lever that belongs to the read path: a
//! cursor that walks the headers in front of the walk, reads the packed
//! bytes of the members it finds and OFFERS them. It decides nothing about
//! what is decoded; the decoder refuses whatever it cannot use.
//!
//! **It reads through the volume's shared handle**, the same one a
//! dispatched member's worker reads through (spec F 3.7.6), never through
//! the walk's own reader. The walk's cursor does not move, its drop-behind
//! promise is untouched because every byte read here is AHEAD of the
//! member being decoded, and nothing here is parsed into the walk's arena.
//!
//! **Every refusal is silent and costs nothing but the lever.** A header
//! that does not parse, a checksum that does not match, an encrypted
//! member, a split member, a member that does not continue the chain, a
//! source that runs out: each stops the cursor where it is, and every
//! member from there on decodes on the path it always did.

use std::sync::Arc;

use super::block::FileHdr;
use super::rar5;
use crate::rar5_lz::ahead::Offered;
use crate::rar5_lz::Rar5Lz;
use crate::read::Format;
use crate::source::RangeSource;
use crate::types::Method;

/// The most header bytes one lookahead read asks for.
///
/// A RAR 5 header is its fields plus a name and an extra area, and the
/// walk's own reader bounds it the same way. A header larger than this
/// stops the cursor, which costs the lever and nothing else.
const HEAD_MAX: usize = 64 * 1024;

/// The most bytes one read of the cursor's WINDOW asks for.
///
/// **Why a window.** The cursor used to ask the source three times a
/// member: the header's size field, the header with the first block's
/// head behind it, and the member's packed bytes. On a chain of small
/// members those three reads are most of what the walking thread does for
/// the stage: counted on a 20,000 member chain written by reference `rar`
/// at `-m3 -s` (3.7 KiB a member), 60,000 reads through the shared handle
/// for an 8.6 MB archive, 28 percent of the walking thread's samples
/// (measured 2 Oct 2026). One read
/// of this many bytes at the cursor serves every header and every small
/// member's packed bytes that lie inside it; a member that does not lie
/// inside it is read straight into the stage's buffer, as before.
///
/// Every byte the window holds is AHEAD of the member being decoded, as
/// every byte this cursor read was, and the ask never reaches past what
/// the source can answer without waiting ([`RangeSource::available`])
/// except by the bytes the old exact read asked for too.
///
/// **A REFUSED MEMBER IS STILL NEVER READ FOR THE STAGE.** The window is
/// asked for only while the stage is TAKING members: its reach starts at
/// nothing (three exact reads, as before), opens at [`REACH_FIRST`] when a
/// member is taken, doubles each time it is read through up to this
/// figure, and closes to nothing at the first member the stage refuses for
/// ever or the cursor steps over with packed bytes. So a chain the stage
/// refuses whole (a stated budget under one member's charge)
/// costs the source exactly the header reads it always did
/// (`tests/solid_chain_head_refusal.rs`), and what a window reads past the
/// last member taken is never more than the reach the members taken before
/// it had opened.
const WINDOW: usize = 256 * 1024;

/// The window's reach after the first member the stage takes.
const REACH_FIRST: usize = 4 * 1024;

/// A bench knob: `RARKIT_AHEAD_WINDOW_KIB=<n>` sizes the cursor's window,
/// and `0` takes it away (three exact reads a member, as before), so one
/// binary measures both. Read once.
pub(crate) const WINDOW_ENV: &str = "RARKIT_AHEAD_WINDOW_KIB";

fn window_bytes() -> usize {
    static BYTES: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *BYTES.get_or_init(|| {
        crate::knob::reader_var(WINDOW_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .map_or(WINDOW, |kib| kib.saturating_mul(1024).min(16 << 20))
    })
}

/// A SMALL MEMBER THAT CARRIES NO TABLE SET IS LEFT TO THE WALKING THREAD,
/// AND THE RUN STAYS OPEN ACROSS IT: the declared size under which a member
/// is not offered, where every block it owns has the table bit clear.
///
/// **Why.** A member handed to a lane costs the walking thread an offer, a
/// claim on its content and, where the lane had gone idle, a wake; decoded
/// where it stands it costs its own symbols and nothing else. For a member
/// of a few KiB the hand-over is the larger: counted on a 20,000 member
/// chain written by reference `rar` at `-m3 -s` (3.7 KiB a member), the
/// chain tests at the default width in about three quarters of the stage's
/// own wall with no member offered at all, on a 96 core Zen 5
/// (measured 2 Oct 2026).
///
/// **Why the run survives it.** A lane's decode of a member depends on the
/// table set in force at its start and on nothing else (SPEC-H2 3.8), and
/// a member none of whose blocks carries a set leaves the set in force as
/// it found it (3.2). So the member offered after it joins the run in
/// front of it exactly as if it were not there. The cursor PROVES that
/// before it steps over: it holds the member's whole packed bytes in its
/// window and walks the block headers to the block flagged last (3.1: a
/// member decodes every block it owns to that one). A member it cannot
/// prove it for, because the bytes are not in hand or a header does not
/// read, is offered as before, and one that does carry a set is a run's
/// head or joins one, as before.
///
/// **A small member that carries a set** is the head of a run, and the
/// lane has to read that set if the run holds a member it will take. So
/// the cursor holds such a member back: it is offered, first, when a member
/// that takes the lane's road and opens no set of its own comes up behind
/// it, and it is given up, and the run closed, when the next member that
/// carries a set comes up instead, or the walk reaches it. On a chain of
/// small members alone nothing is offered at all, and on a chain where
/// larger members sit among small ones the larger ones are still decoded
/// ahead under the sets the small ones opened
/// (`tests/solid_chain_small_members.rs`).
///
/// **OFF, and why.** What the rule trades is a wake against a decode, and
/// a wake's price is the BOX's, not the system's or the architecture's
/// (measured 2 Oct 2026): on a 96
/// core Zen 5 server a floor of 16 KiB reads the 20,000 member chain 1.01x
/// to 1.15x of no floor at the default width, and on an 8 core Zen 4
/// under the same system every floor reads UNDER none (0.83x at 16 KiB),
/// as it does on Apple silicon, the lane there keeping up with members of
/// 2 KiB. So the shipped figure is none, and the rule is a knob until a
/// default keyed on the box's width has its rows.
///
/// A bench knob, `RARKIT_AHEAD_SMALL_KIB=<n>`, turns it on at `n` KiB;
/// read once.
const SMALL_MEMBER: u64 = 0;

/// See [`SMALL_MEMBER`].
pub(crate) const SMALL_ENV: &str = "RARKIT_AHEAD_SMALL_KIB";

fn small_member() -> u64 {
    #[cfg(feature = "test-support")]
    if let Some(bytes) = crate::probe::ahead_small() {
        return bytes;
    }
    static BYTES: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *BYTES.get_or_init(|| {
        crate::knob::reader_var(SMALL_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map_or(SMALL_MEMBER, |kib| kib.saturating_mul(1024))
    })
}

/// How far in front of the walk the cursor steps over small members
/// without offering one. An offer is bounded by the stage's queue; a step
/// over is bounded by this, so a chain of small members alone is walked
/// one window in front of the decode and never to its end.
const SMALL_SPAN: u64 = WINDOW as u64;

/// Whether no block of this member carries a table set: `Some(true)` when
/// every block header from the first to the one flagged last reads and has
/// the table bit clear, `Some(false)` when one carries a set, `None` when
/// that cannot be said from these bytes (a header that does not read, or a
/// chain that ends with no block flagged last).
fn carries_no_tables(packed: &[u8]) -> Option<bool> {
    let mut at = 0usize;
    loop {
        let block = crate::rar5_lz::block::block_in_hand(packed.get(at..)?).ok()?;
        if block.carries_tables() {
            return Some(false);
        }
        if block.ends_member() {
            return Some(true);
        }
        at = at.checked_add(block.past())?;
    }
}

/// Where the cursor reads from, for one member's worth of offering.
pub(crate) struct Feed {
    /// The volume being walked, by handle.
    pub(crate) source: Arc<dyn RangeSource>,
    /// The volume's number, so a cursor left in another one is dropped.
    pub(crate) volume: u32,
    /// The end of the member being decoded: the first byte the cursor may
    /// look at, and never below where it already is.
    pub(crate) from: u64,
    /// What the member being decoded declares, where its header says.
    pub(crate) declared: Option<u64>,
}

/// Where one step of the cursor leaves it.
enum Step {
    /// The header after this one begins here.
    Advance(u64),
    /// Stay on this header: the stage will take it later.
    Stay,
    /// The lookahead ends here.
    End,
}

/// The cursor, and the two buffers it reuses.
///
/// Allocated once for the operation and carried across members, so the
/// lookahead adds no allocation per member (spec F 7.3.5).
#[derive(Default)]
pub(crate) struct Lookahead {
    /// The volume `at` is an offset into.
    volume: u32,
    /// The offset of the next header to parse.
    at: u64,
    /// Whether the cursor may still be used in this volume.
    live: bool,
    /// Where the walk ENDED in this volume, if it did: the offset of the
    /// header it could not read or parse, or of the record that ends the
    /// chain. Nothing between the walk and that offset is worth walking
    /// again, so a feed that arrives below it does nothing unless the
    /// source has grown past it.
    ///
    /// Without this a chain whose every member is refused was walked to
    /// its end on EVERY feed, because the walk ended, the cursor restarted
    /// at the next member and walked to the end again: on a 3,000 member
    /// chain under a starved budget that was 9,004,205 source reads for a
    /// 2.5 MB archive, found by `tests/solid_chain_head_refusal.rs` on 22
    /// Sep 2026. A stage that takes nothing must cost one walk, not one
    /// walk per member.
    ended: Option<u64>,
    head: Vec<u8>,
    /// The cursor's window ([`WINDOW`]): `window_len` bytes of the volume
    /// from `window_at`. Empty until the first header is read through it.
    window: Vec<u8>,
    window_at: u64,
    window_len: usize,
    /// How many bytes the next read of the window asks for: nothing until
    /// the stage takes a member, and nothing again once it refuses one
    /// ([`WINDOW`]).
    reach: usize,
    /// A small member that CARRIES a table set, met and not yet offered
    /// ([`SMALL_MEMBER`], "a small member that carries a set"): offered when
    /// a member the stage takes needs its set, given up when the run it
    /// opens ends with no such member or the walk reaches it.
    pending: Option<Pending>,
}

/// A member the cursor is holding back: where its header is, and what an
/// offer of it needs.
#[derive(Clone, Copy)]
struct Pending {
    at: u64,
    data_start: u64,
    len: usize,
    unpacked: u64,
    algorithm: u8,
}

impl Lookahead {
    /// Put the cursor at the end of the member about to be decoded,
    /// answering whether anything between where it was and where it is
    /// now went unoffered.
    ///
    /// Never BACKWARDS: the members already offered are in front of this
    /// one, and offering them again would decode them twice. A cursor that
    /// is BEHIND the member about to be decoded, because it stopped or
    /// because the walk moved to another volume, has members between that
    /// nothing offered, and the decoder's run must not carry a table set
    /// across them (`rar5_lz::ahead`).
    fn arrive(&mut self, feed: &Feed) -> bool {
        if !self.live || self.volume != feed.volume {
            self.volume = feed.volume;
            self.at = feed.from;
            self.live = true;
            self.ended = None;
            // An offset means nothing in a volume it was not taken from,
            // and a stopped cursor may be handed another source.
            self.window_len = 0;
            self.reach = 0;
            self.pending = None;
            return true;
        }
        let gap = feed.from > self.at;
        self.at = self.at.max(feed.from);
        gap
    }

    /// Whether there is anything for this feed to walk: not when the walk
    /// already ended past the cursor and the source has not grown since.
    fn worth_walking(&mut self, feed: &Feed) -> bool {
        match self.ended {
            Some(ended) if self.at <= ended => {
                if feed.source.available() <= ended {
                    return false;
                }
                // The source grew past where the walk ended: what ended
                // it may have been a short read, so walk on from there.
                self.at = self.at.max(ended);
                self.ended = None;
                true
            }
            _ => {
                self.ended = None;
                true
            }
        }
    }

    /// The one reusable buffer, for the operation's reported peak. The
    /// members' packed bytes are never held here: they are read into the
    /// stage's own work item, in place.
    pub(crate) fn held_bytes(&self) -> u64 {
        (self.head.capacity() + self.window.capacity()) as u64
    }

    /// Forget where the cursor is, which a chain that has ended leaves
    /// behind.
    pub(crate) fn stop(&mut self) {
        self.live = false;
        self.ended = None;
        self.pending = None;
    }

    /// Offer the members in front of the walk to `lz`, until the decoder
    /// is full, the chain ends or the headers stop parsing.
    ///
    /// Offering is the whole of what this does. A member the decoder
    /// refuses is STEPPED OVER rather than retried, because the refusal is
    /// a property of that member - too large, or not starting its own
    /// table group when no run is open - and the members behind it may
    /// still be taken, as heads of runs of their own; a decoder that is
    /// FULL stops the cursor where it is, because that refusal is
    /// temporary and the same member is offered again when the queue has
    /// drained.
    pub(crate) fn feed(&mut self, feed: &Feed, lz: &mut Rar5Lz) {
        // NOTHING TO WALK FOR ([`SMALL_MEMBER`]): the member being decoded
        // is small, so its decode is over before a lane could use the time,
        // and nothing is queued or held back that a walk would add to. The
        // cursor stays where it is; when a member at or over the floor
        // comes, the walk it starts finds the cursor behind it and closes
        // the run, as for any member that went by unoffered. So a chain of
        // small members alone costs the stage no header and no read.
        let floor = small_member();
        if floor != 0
            && feed.declared.is_some_and(|declared| declared < floor)
            && self.pending.is_none()
            && !lz.ahead_in_flight()
        {
            return;
        }
        if self.arrive(feed) {
            lz.ahead_break();
        }
        // THE WALK HAS REACHED A MEMBER HELD BACK: it decodes on the walking
        // thread now, it carries a set, and so the run ends with it.
        if self.pending.is_some_and(|held| held.at < feed.from) {
            self.pending = None;
            lz.ahead_break();
        }
        if !self.worth_walking(feed) {
            return;
        }
        while self.live && !lz.ahead_full() {
            match self.step(feed, lz) {
                Step::Advance(next) => self.at = next,
                // The stage refused for now and not for ever: the cursor
                // stays on this member and offers it again next time,
                // so nothing is stepped over and the decoder's run stays
                // open for it.
                Step::Stay => break,
                // The walk ends here, and stays ended for every feed
                // below this point: see `ended`.
                Step::End => {
                    self.ended = Some(self.at);
                    break;
                }
            }
        }
    }

    /// One header: parse it, offer it if it is an eligible member, and
    /// answer where the header after it begins.
    fn step(&mut self, feed: &Feed, lz: &mut Rar5Lz) -> Step {
        match self.step_inner(feed, lz) {
            Some(step) => step,
            None => Step::End,
        }
    }

    /// [`Lookahead::step`] with `?` on every read and parse that ends the
    /// lookahead.
    fn step_inner(&mut self, feed: &Feed, lz: &mut Rar5Lz) -> Option<Step> {
        let (head_len, probed) = self.read_header(feed)?;
        let common = rar5::parse_common(&self.head[..head_len]).ok()?;
        // A header whose own checksum does not match is not a header this
        // cursor may act on. The walk will meet it too and will say so;
        // here it simply ends the lookahead.
        if rar5::header_checksum(&self.head[..head_len]) != common.crc {
            return None;
        }
        let data_start = self.at.checked_add(head_len as u64)?;
        let next = data_start.checked_add(common.data_size)?;
        if common.btype != rar5::TYPE_FILE && common.btype != rar5::TYPE_SERVICE {
            // A main header, an encryption header or an end record: the
            // chain this cursor was following does not continue past it.
            return None;
        }
        let parsed = rar5::parse_file(&self.head[..head_len], &common, data_start).ok()?;
        let file = parsed.fields;
        // A member the walk will refuse for its version (spec F 3.2.6)
        // ends the lookahead: the chain cannot continue past it, and no
        // decoder is built for an algorithm this package does not know.
        // Its header failed to parse until 28 Sep 2026, which ended the
        // lookahead here too.
        if matches!(
            // Only whether a codec exists is asked, and this is a solid
            // chain's lookahead, so the reach is the dictionary's.
            crate::read::extract::codec_of(&file, crate::read::Format::Rar5, true),
            crate::read::extract::Codec::Missing(_)
        ) {
            return None;
        }
        if file.service.is_some() {
            // A service record sits between members and carries none of
            // the chain: step over it.
            return Some(Step::Advance(next));
        }
        if !self.offerable(&file) {
            // Not a member this stage can take, and not a reason to stop:
            // the chain continues through it. But the decoder's RUN does
            // not: a member decoded on the path it always took may leave
            // a different table set in force, so the member after it may
            // not join the run in front of it. A directory, and a member
            // with no packed bytes, read no table and break nothing. A
            // member declaring no bytes but CARRYING packed bytes does
            // break it: reference `rar` 7.23 at `-m3 -s` writes such
            // members with a block that carries a table set, and the
            // member after one decodes under that set (SPEC-H2 3.2,
            // `Rar5Lz::member`).
            if !file.is_directory && (file.unpacked_size != Some(0) || file.packed_size > 0) {
                lz.ahead_break();
            }
            if file.packed_size > 0 {
                // Its packed bytes are not the stage's to read.
                self.reach = 0;
            }
            return Some(Step::Advance(next));
        }
        let unpacked = file.unpacked_size?;
        let algorithm = u8::try_from(file.unpack_version).ok()?;
        let len = usize::try_from(file.packed_size).ok()?;
        // A SMALL MEMBER THAT CARRIES NO TABLE SET stays with the walking
        // thread, and the run stays open across it ([`SMALL_MEMBER`]). Not
        // a refusal: nothing is stepped over that could change the set in
        // force, so the run is not closed and the window is not either.
        if unpacked < small_member() {
            if self.at > feed.from.saturating_add(SMALL_SPAN) {
                // Far enough in front of the walk: wait for it here.
                return Some(Step::Stay);
            }
            // The proof needs the member's whole packed bytes in hand. An
            // open window that ends inside them is read afresh from this
            // header, which the headers behind it will want anyway.
            let whole = head_len.checked_add(len)?;
            if self.windowed(data_start, len).is_none()
                && self.reach != 0
                && whole <= window_bytes()
            {
                self.refill(feed, self.at, whole);
            }
            match self.windowed(data_start, len).map(carries_no_tables) {
                // No set: it stays with the walking thread, and neither the
                // run nor a member held back is touched.
                Some(Some(true)) => return Some(Step::Advance(next)),
                // It carries a set: held back until a member behind it says
                // whether the lane needs that set. Whatever was held back
                // before it opened a run that has now ended with nothing
                // for the lane in it.
                Some(Some(false)) => {
                    if self.pending.take().is_some() {
                        lz.ahead_break();
                    }
                    self.pending = Some(Pending {
                        at: self.at,
                        data_start,
                        len,
                        unpacked,
                        algorithm,
                    });
                    return Some(Step::Advance(next));
                }
                // Cannot say: offered as before.
                _ => {}
            }
        }
        // A MEMBER HELD BACK, and this one may go to a lane: the lane needs
        // the held member's set exactly when this one opens none of its own,
        // which its first block's header says. Offered first, so the queue
        // is in archive order; given up, and the run closed, otherwise.
        if let Some(held) = self.pending.take() {
            let joins = probed
                && len >= Rar5Lz::AHEAD_HEAD_PROBE
                && crate::rar5_lz::block::header_says_tables(
                    &self.head[head_len..head_len + Rar5Lz::AHEAD_HEAD_PROBE],
                ) == Some(false);
            if !joins {
                lz.ahead_break();
            } else {
                match self.offer(
                    feed,
                    lz,
                    held.data_start,
                    held.len,
                    held.unpacked,
                    held.algorithm,
                ) {
                    Offered::Taken => self.taken(),
                    Offered::Later => {
                        // The queue is full: both wait here, in order.
                        self.pending = Some(held);
                        return Some(Step::Stay);
                    }
                    // The offer closed the run itself.
                    Offered::Never => {}
                }
            }
        }
        // REFUSED BEFORE IT IS READ. The stage takes a member only when its
        // first block opens a table group (SPEC-H2 3.2 and 3.8), and that is
        // decidable from the block's HEADER, which `read_header` above
        // brought back in the SAME read as the file header: `probed` says
        // those bytes are in hand. Without this the member's whole packed
        // data is read into the stage's buffer and thrown away when the rule
        // refuses it, and on a chain whose writer carries one table set
        // across most of its boundaries that is nearly every member: 18,666
        // of 20,000 on the `rar5_small_solid_20k` corpus, about 15 MB read
        // for nothing, measured 22 Sep 2026.
        //
        // The test is skipped when the probe is not in hand or the member is
        // shorter than the probe, in which case the five bytes would reach
        // past the member into the header behind it. `ahead_refuses_head` is
        // one direction only and every bound is tested again by the offer,
        // so a skipped test costs the lever nothing.
        if probed && len >= Rar5Lz::AHEAD_HEAD_PROBE {
            let probe = &self.head[head_len..head_len + Rar5Lz::AHEAD_HEAD_PROBE];
            if lz.ahead_refuses_head(probe, unpacked, len) {
                // Stepped over, so the run ends here, and the window with
                // it: a refused member is not read for the stage.
                lz.ahead_break();
                self.reach = 0;
                return Some(Step::Advance(next));
            }
        }
        // STRAIGHT INTO THE STAGE'S OWN BUFFER. A read into a buffer here
        // and a copy out of it into the stage would cost the WALKING
        // THREAD two passes over every member's packed bytes, which is the
        // one thread this whole lever exists to unblock. A member whose
        // packed bytes the window already holds is the exception: they
        // came back in the read that brought its header, and a copy of a
        // small member costs less than a third read for it.
        Some(
            match self.offer(feed, lz, data_start, len, unpacked, algorithm) {
                // A refusal for now: the cursor waits on this member rather
                // than stepping over it, because stepping over it would close
                // the decoder's run for nothing (`rar5_lz::ahead::Offered`).
                Offered::Later => Step::Stay,
                Offered::Taken => {
                    self.taken();
                    Step::Advance(next)
                }
                Offered::Never => {
                    self.reach = 0;
                    Step::Advance(next)
                }
            },
        )
    }

    /// Offer the member whose packed bytes are the `len` at `data_start`:
    /// copied from the window where it holds them, read straight into the
    /// stage's buffer otherwise.
    fn offer(
        &self,
        feed: &Feed,
        lz: &mut Rar5Lz,
        data_start: u64,
        len: usize,
        unpacked: u64,
        algorithm: u8,
    ) -> Offered {
        let source = &feed.source;
        let held = self.windowed(data_start, len);
        lz.offer_ahead_into(unpacked, algorithm, len, |room| match held {
            Some(bytes) => {
                room.copy_from_slice(bytes);
                true
            }
            None => read_exact(source, data_start, room).is_some(),
        })
    }

    /// The stage took a member: the window is open from here ([`WINDOW`]).
    fn taken(&mut self) {
        self.reach = match window_bytes() {
            0 => 0,
            most => self.reach.clamp(REACH_FIRST.min(most), most),
        };
    }

    /// Whether this header names a member the decode-ahead could take.
    ///
    /// Everything here is a statement about what the OFFER would have to
    /// know that this cursor cannot supply, and every one of them is the
    /// same shape: a member whose packed bytes are not, by themselves, the
    /// member's own compressed stream.
    fn offerable(&self, file: &FileHdr) -> bool {
        // The chain IS the window the member before it left (spec F 3.6).
        // A member that does not continue it starts a fresh stream, and
        // nothing behind it belongs to the chain being decoded.
        file.solid
            && !file.is_directory
            // Enciphered packed bytes are spec K's to turn into the
            // stream, and this cursor holds no key.
            && !file.encrypted
            // A split member's later fragments are found by walking to the
            // next volume (spec F 3.5.4), so its packed bytes are not this
            // volume's to hand over.
            && !file.split_before
            && !file.split_after
            && !matches!(file.method, Method::Stored)
            && file.unpacked_size.is_some()
            && file.packed_size > 0
    }

    /// Read the header at the cursor, answering its total length and whether
    /// the FIRST BLOCK HEADER behind it came back too.
    ///
    /// The length is in the header's own size field, so the read is two
    /// steps: enough bytes to hold the field, then the rest.
    ///
    /// **The second step asks for the block header as well**, which costs
    /// nothing because it is the same read: `Rar5Lz::AHEAD_HEAD_PROBE` bytes
    /// past the file header are the first bytes of the member's packed data,
    /// and they decide whether the decode-ahead can take the member at all.
    /// Reading them separately would put an extra read on every member of
    /// every chain, including the chains where none is refused, which is the
    /// shape this whole stage exists not to slow down.
    ///
    /// The longer ask can fail where the shorter would have worked, at the
    /// END of an archive whose last header has fewer than five bytes behind
    /// it, so a failure falls back to the exact header and answers `false`
    /// for the probe. That path costs one extra read and is reached once per
    /// archive at most.
    fn read_header(&mut self, feed: &Feed) -> Option<(usize, bool)> {
        // The CRC field and the widest size vint, which is what the length
        // can be read out of.
        const PROBE: usize = 4 + 10;
        self.fill(feed, self.at, PROBE)?;
        let mut at = 4usize;
        let size = super::vint::read(&self.head, &mut at)?;
        let head_len = usize::try_from((at as u64).checked_add(size)?).ok()?;
        if head_len > HEAD_MAX || head_len < at {
            return None;
        }
        let with_probe = head_len.checked_add(Rar5Lz::AHEAD_HEAD_PROBE)?;
        if with_probe <= HEAD_MAX && self.fill(feed, self.at, with_probe).is_some() {
            return Some((head_len, true));
        }
        self.fill(feed, self.at, head_len)?;
        Some((head_len, false))
    }

    /// Fill `head` with `want` bytes from `at`.
    fn fill(&mut self, feed: &Feed, at: u64, want: usize) -> Option<()> {
        if want > HEAD_MAX {
            return None;
        }
        if self.head.len() < want {
            self.head.resize(want, 0);
        }
        if self.windowed(at, want).is_none() && self.reach != 0 {
            self.refill(feed, at, want);
        }
        if let Some(start) = self.window_offset(at, want) {
            self.head[..want].copy_from_slice(&self.window[start..start + want]);
            return Some(());
        }
        // The window is closed, or the source answered short of `want`:
        // the exact read, which says a short source in its own way.
        read_exact(&feed.source, at, &mut self.head[..want])
    }

    /// Where in the window the `len` bytes at `at` begin, when the window
    /// holds all of them.
    fn window_offset(&self, at: u64, len: usize) -> Option<usize> {
        let start = usize::try_from(at.checked_sub(self.window_at)?).ok()?;
        let end = start.checked_add(len)?;
        (end <= self.window_len).then_some(start)
    }

    /// The `len` bytes at `at`, when the window holds all of them.
    fn windowed(&self, at: u64, len: usize) -> Option<&[u8]> {
        let start = self.window_offset(at, len)?;
        Some(&self.window[start..start + len])
    }

    /// Read the window afresh from `at`: one ask of the source for as much
    /// of the reach as it can answer without waiting and never fewer than
    /// `want`, then more asks only while fewer than `want` came back.
    fn refill(&mut self, feed: &Feed, at: u64, want: usize) {
        let size = self.reach.max(want);
        if self.window.len() < size {
            self.window.resize(size, 0);
        }
        self.window_at = at;
        self.window_len = 0;
        let ready = feed.source.available().saturating_sub(at);
        let ask = usize::try_from(ready)
            .unwrap_or(usize::MAX)
            .min(size)
            .max(want);
        while self.window_len < want {
            let Some(offset) = at.checked_add(self.window_len as u64) else {
                return;
            };
            match feed
                .source
                .read_at(offset, &mut self.window[self.window_len..ask])
            {
                Ok(0) | Err(_) => return,
                Ok(got) => self.window_len += got,
            }
        }
        // An open window that was read through opens further.
        self.reach = (self.reach * 2).min(window_bytes().max(self.reach));
    }
}

/// Read exactly `buf.len()` bytes at `at`, or answer `None`.
///
/// Past the end of a source is `Ok(0)` and not an error (spec F 3.1), and
/// a short read is where the archive ends, which stops the cursor.
fn read_exact(source: &Arc<dyn RangeSource>, at: u64, buf: &mut [u8]) -> Option<()> {
    let mut done = 0usize;
    while done < buf.len() {
        let offset = at.checked_add(done as u64)?;
        match source.read_at(offset, &mut buf[done..]) {
            Ok(0) => return None,
            Ok(got) => done += got,
            Err(_) => return None,
        }
    }
    Some(())
}

/// Whether a member being decoded is one the lookahead should run for.
///
/// The lever is the SOLID CHAIN's, so it runs only where a chain is being
/// decoded, and only in the one container generation SPEC-H2 speaks for.
pub(crate) fn wanted(format: Format, solid_chain: bool, split: bool) -> bool {
    matches!(format, Format::Rar5) && solid_chain && !split
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A struct that answers no bytes, for the cursor's own bookkeeping.
    struct Nothing;

    impl RangeSource for Nothing {
        fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
        fn available(&self) -> u64 {
            0
        }
        fn len(&self) -> Option<u64> {
            Some(0)
        }
    }

    fn feed(volume: u32, from: u64) -> Feed {
        Feed {
            source: Arc::new(Nothing) as Arc<dyn RangeSource>,
            volume,
            from,
            declared: None,
        }
    }

    /// The lever is the SOLID CHAIN's, and only in the one container
    /// generation SPEC-H2 speaks for.
    #[test]
    fn only_a_solid_rar5_chain_of_unsplit_members_is_walked_ahead() {
        assert!(wanted(Format::Rar5, true, false));
        assert!(!wanted(Format::Rar5, false, false), "not a solid archive");
        assert!(!wanted(Format::Rar5, true, true), "a split member");
        for format in [
            Format::Rar4Family,
            Format::Rar20,
            Format::Rar15,
            Format::Rar13,
        ] {
            assert!(!wanted(format, true, false), "{format:?} is not spec H2's");
        }
    }

    /// The cursor never moves BACKWARDS inside one volume.
    ///
    /// The members already offered are in front of the one being decoded,
    /// so a cursor that went back would offer them a second time, and the
    /// second copy would be decoded on a lane and then discarded by the
    /// content key. That is wasted work rather than a wrong byte, which is
    /// exactly the kind of defect no output can show.
    #[test]
    fn the_cursor_never_walks_back_over_what_it_has_offered() {
        let mut cursor = Lookahead::default();
        cursor.arrive(&feed(0, 1_000));
        assert_eq!(cursor.at, 1_000);
        cursor.at = 9_000;
        // A member whose end is BEHIND the cursor leaves it where it is.
        cursor.arrive(&feed(0, 2_000));
        assert_eq!(cursor.at, 9_000, "the cursor walked back");
        // One ahead of it moves it forward.
        cursor.arrive(&feed(0, 12_000));
        assert_eq!(cursor.at, 12_000);
    }

    /// A new VOLUME resets the cursor, because an offset means nothing in
    /// a volume it was not taken from.
    #[test]
    fn a_new_volume_resets_the_cursor_rather_than_carrying_an_offset() {
        let mut cursor = Lookahead::default();
        cursor.arrive(&feed(0, 9_000));
        assert_eq!(cursor.at, 9_000);
        cursor.arrive(&feed(1, 100));
        assert_eq!(cursor.at, 100, "an offset was carried across a volume");
        assert_eq!(cursor.volume, 1);
    }

    /// A chain that has ended leaves nothing behind for the next one.
    #[test]
    fn a_stopped_cursor_starts_again_where_it_is_next_told_to() {
        let mut cursor = Lookahead::default();
        cursor.arrive(&feed(0, 9_000));
        cursor.stop();
        cursor.arrive(&feed(0, 100));
        assert_eq!(cursor.at, 100, "a stopped cursor kept its old offset");
    }

    /// A walk that ENDED is not walked again by the feeds below it: the
    /// cursor remembers where it ended and does nothing until the walk
    /// passes that point or the source grows past it.
    #[test]
    fn an_ended_walk_is_not_walked_again_from_every_member_below_it() {
        let mut cursor = Lookahead::default();
        let feed_0 = feed(0, 1_000);
        cursor.arrive(&feed_0);
        assert!(cursor.worth_walking(&feed_0));
        cursor.at = 9_000;
        cursor.ended = Some(9_000);
        // A feed from below the end, on a source that has not grown.
        let feed_2 = feed(0, 2_000);
        assert!(
            !cursor.arrive(&feed_2),
            "a feed below the cursor is not a gap"
        );
        assert!(
            !cursor.worth_walking(&feed_2),
            "the ended walk was walked again"
        );
        assert_eq!(cursor.ended, Some(9_000));
        // The walk passes the end: worth walking again, from there.
        let feed_12 = feed(0, 12_000);
        assert!(cursor.arrive(&feed_12));
        assert!(cursor.worth_walking(&feed_12));
        assert_eq!(cursor.ended, None);
        assert_eq!(cursor.at, 12_000);
    }

    /// A source of known bytes that counts what it is asked: how many reads,
    /// the furthest byte an ask reached, and, with `most` set, never more
    /// than that many bytes an answer. `ready` is what `available` answers.
    struct Counted {
        bytes: Vec<u8>,
        ready: u64,
        most: usize,
        reads: std::sync::atomic::AtomicUsize,
        furthest: std::sync::atomic::AtomicU64,
    }

    impl Counted {
        fn new(len: usize) -> Counted {
            Counted {
                bytes: (0..len).map(|i| (i * 31 % 251) as u8).collect(),
                ready: len as u64,
                most: usize::MAX,
                reads: std::sync::atomic::AtomicUsize::new(0),
                furthest: std::sync::atomic::AtomicU64::new(0),
            }
        }
        fn reads(&self) -> usize {
            self.reads.load(std::sync::atomic::Ordering::Relaxed)
        }
        fn furthest(&self) -> u64 {
            self.furthest.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    impl RangeSource for Counted {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            use std::sync::atomic::Ordering::Relaxed;
            self.reads.fetch_add(1, Relaxed);
            self.furthest.fetch_max(offset + buf.len() as u64, Relaxed);
            let start = (offset as usize).min(self.bytes.len());
            let got = buf.len().min(self.bytes.len() - start).min(self.most);
            buf[..got].copy_from_slice(&self.bytes[start..start + got]);
            Ok(got)
        }
        fn available(&self) -> u64 {
            self.ready
        }
        fn len(&self) -> Option<u64> {
            Some(self.bytes.len() as u64)
        }
    }

    fn counted_feed(source: &Arc<Counted>, from: u64) -> Feed {
        Feed {
            source: Arc::clone(source) as Arc<dyn RangeSource>,
            volume: 0,
            from,
            declared: None,
        }
    }

    /// ONE read serves every header and every small member inside the
    /// window: the fills behind the first ask the source nothing, and the
    /// bytes are the source's own.
    #[test]
    fn the_window_serves_what_lies_inside_it_from_one_read() {
        let source = Arc::new(Counted::new(WINDOW + 4_000));
        let feed = counted_feed(&source, 100);
        let mut cursor = Lookahead::default();
        cursor.arrive(&feed);
        cursor.reach = WINDOW;
        cursor.fill(&feed, 100, 14).expect("the first fill");
        assert_eq!(source.reads(), 1, "the first fill is one read");
        assert_eq!(&cursor.head[..14], &source.bytes[100..114]);
        // A header, its probe and a member's packed bytes further on.
        cursor.fill(&feed, 100, 300).expect("a longer fill");
        cursor.fill(&feed, 9_000, 77).expect("a later header");
        assert_eq!(&cursor.head[..77], &source.bytes[9_000..9_077]);
        assert_eq!(
            cursor.windowed(20_000, 5_000),
            Some(&source.bytes[20_000..25_000]),
            "a member inside the window is in hand"
        );
        assert_eq!(source.reads(), 1, "the window was read again");
        // The last byte the window holds is in hand, and one past it is not.
        let end = 100 + WINDOW as u64;
        assert!(cursor.windowed(end - 10, 10).is_some());
        assert!(cursor.windowed(end - 10, 11).is_none());
        assert!(cursor.windowed(99, 2).is_none(), "below the window");
        // A fill that reaches past the window reads it afresh from there.
        cursor
            .fill(&feed, end - 4, 14)
            .expect("a fill across the window's end");
        assert_eq!(source.reads(), 2);
        assert_eq!(
            &cursor.head[..14],
            &source.bytes[(end - 4) as usize..(end + 10) as usize]
        );
    }

    /// A source that answers a few bytes a read still fills what was asked,
    /// and the end of the source ends the lookahead as the exact read did.
    #[test]
    fn a_short_answering_source_fills_and_its_end_stops_the_walk() {
        let mut source = Counted::new(1_000);
        source.most = 7;
        let source = Arc::new(source);
        let feed = counted_feed(&source, 0);
        let mut cursor = Lookahead::default();
        cursor.arrive(&feed);
        cursor.reach = WINDOW;
        cursor
            .fill(&feed, 10, 64)
            .expect("sixty four bytes, seven at a time");
        assert_eq!(&cursor.head[..64], &source.bytes[10..74]);
        // Past the end: no bytes, and no loop.
        assert!(cursor.fill(&feed, 990, 14).is_none());
        // The last bytes exactly are still read.
        cursor.fill(&feed, 990, 10).expect("the last ten bytes");
        assert_eq!(&cursor.head[..10], &source.bytes[990..1_000]);
    }

    /// The window's ask never reaches past what the source can answer
    /// without waiting, except by the bytes the exact read asked for too.
    #[test]
    fn the_window_asks_no_further_than_the_source_has_ready() {
        let mut source = Counted::new(WINDOW * 2);
        source.ready = 5_000;
        let source = Arc::new(source);
        let feed = counted_feed(&source, 0);
        let mut cursor = Lookahead::default();
        cursor.arrive(&feed);
        cursor.reach = WINDOW;
        cursor
            .fill(&feed, 1_000, 14)
            .expect("a header inside what is ready");
        assert_eq!(source.furthest(), 5_000, "the ask passed what is ready");
        // Past what is ready the ask is the exact read's and no more.
        cursor
            .fill(&feed, 6_000, 14)
            .expect("a header past what is ready");
        assert_eq!(source.furthest(), 6_014);
    }

    /// A new volume, and a stopped cursor, forget the window: an offset
    /// means nothing in a source it was not read from.
    #[test]
    fn a_new_volume_forgets_the_window() {
        let source = Arc::new(Counted::new(10_000));
        let feed = counted_feed(&source, 0);
        let mut cursor = Lookahead::default();
        cursor.arrive(&feed);
        cursor.reach = WINDOW;
        cursor.fill(&feed, 0, 14).expect("a fill");
        assert!(cursor.windowed(100, 10).is_some());
        let mut next = counted_feed(&source, 0);
        next.volume = 1;
        cursor.arrive(&next);
        assert!(
            cursor.windowed(100, 10).is_none(),
            "the window crossed a volume"
        );
        assert_eq!(cursor.reach, 0, "the reach crossed a volume");
        cursor.reach = WINDOW;
        cursor.fill(&next, 0, 14).expect("a fill");
        cursor.stop();
        cursor.arrive(&next);
        assert!(
            cursor.windowed(100, 10).is_none(),
            "a stopped cursor kept its window"
        );
    }

    /// A CLOSED window asks the source for exactly what the cursor needs,
    /// as before the window existed: nothing is read for a stage that is
    /// taking nothing.
    #[test]
    fn a_closed_window_reads_exactly_what_is_asked() {
        let source = Arc::new(Counted::new(100_000));
        let feed = counted_feed(&source, 0);
        let mut cursor = Lookahead::default();
        cursor.arrive(&feed);
        assert_eq!(cursor.reach, 0, "a new cursor's window is closed");
        cursor.fill(&feed, 1_000, 14).expect("a header");
        assert_eq!(source.furthest(), 1_014);
        cursor.fill(&feed, 1_000, 90).expect("the whole header");
        assert_eq!(source.furthest(), 1_090);
        assert_eq!(source.reads(), 2);
        assert_eq!(&cursor.head[..90], &source.bytes[1_000..1_090]);
        // Open, the same fills are served by one read of the reach.
        cursor.reach = REACH_FIRST;
        cursor.fill(&feed, 2_000, 14).expect("a header");
        cursor.fill(&feed, 2_000, 90).expect("the whole header");
        assert_eq!(source.reads(), 3);
        assert_eq!(source.furthest(), 2_000 + REACH_FIRST as u64);
    }

    /// A block header whose check holds (SPEC-H2 3.2), then its payload.
    fn block(tables: bool, last: bool, payload: &[u8]) -> Vec<u8> {
        use crate::rar5_lz::block::{FLAG_LAST, FLAG_TABLES, HEADER_CHECK};
        let flags = if tables { FLAG_TABLES } else { 0 } | if last { FLAG_LAST } else { 0 };
        let size = payload.len() as u8;
        let mut out = vec![flags, HEADER_CHECK ^ flags ^ size, size];
        out.extend_from_slice(payload);
        out
    }

    /// The proof a member is stepped over on: every block header to the one
    /// flagged last reads and none carries a table set. Anything short of
    /// that is "cannot say", and the member is offered as before.
    #[test]
    fn a_member_is_proved_to_carry_no_tables_from_its_block_headers_alone() {
        let one = block(false, true, &[1, 2, 3]);
        assert_eq!(carries_no_tables(&one), Some(true));
        let head = block(true, true, &[1, 2, 3]);
        assert_eq!(carries_no_tables(&head), Some(false));
        // Three blocks, the table set in the SECOND: the first block's bit
        // alone does not say it.
        let mut later = block(false, false, &[9; 7]);
        later.extend(block(true, false, &[8; 5]));
        later.extend(block(false, true, &[7; 2]));
        assert_eq!(carries_no_tables(&later), Some(false));
        let mut clear = block(false, false, &[9; 7]);
        clear.extend(block(false, false, &[8; 5]));
        clear.extend(block(false, true, &[7; 2]));
        assert_eq!(carries_no_tables(&clear), Some(true));
        // Bytes past the block flagged last are not the member's blocks.
        let mut surplus = clear.clone();
        surplus.extend(block(true, true, &[6; 4]));
        assert_eq!(carries_no_tables(&surplus), Some(true));
        // Cannot say: no block flagged last, a payload cut short, a header
        // whose check fails, no bytes at all.
        let mut open = block(false, false, &[9; 7]);
        open.extend(block(false, false, &[8; 5]));
        assert_eq!(carries_no_tables(&open), None);
        assert_eq!(carries_no_tables(&clear[..clear.len() - 1]), None);
        let mut bad = clear.clone();
        bad[1] ^= 0x10;
        assert_eq!(carries_no_tables(&bad), None);
        assert_eq!(carries_no_tables(&[]), None);
    }

    /// A source that answers nothing stops the cursor rather than looping.
    #[test]
    fn a_source_that_answers_nothing_stops_the_walk() {
        let mut cursor = Lookahead::default();
        let feed = feed(0, 0);
        cursor.arrive(&feed);
        assert!(cursor.read_header(&feed).is_none());
        assert!(read_exact(&feed.source, 0, &mut [0u8; 4]).is_none());
    }
}
