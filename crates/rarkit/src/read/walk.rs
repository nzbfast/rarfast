//! Layer 3 of spec F section 2.3: the crossing of volume boundaries, and
//! the packed byte stream of ONE member.
//!
//! `Walk` owns the volume provider, the reader of the volume being read and
//! the ordering checks a set owes (3.5.3). `MemberStream` is the packed byte
//! stream of one member, continuing across fragments and volumes, and it is
//! what a codec reads: the fragments are ONE stream, the decoder is not
//! restarted, its dictionary is not cleared, and it never learns that a
//! boundary passed (3.5.4).
//!
//! Every decoder in this crate PULLS its packed bytes, so layer 4 cannot
//! drive the walk with a loop of its own while a member is being decoded:
//! the stream drives the walk instead, and hands layer 4 back a walk
//! positioned after the member's last fragment.

use std::cell::RefCell;
#[cfg(feature = "parallel")]
use std::sync::Arc;

use crate::checksum::Crc32;
use crate::error::{Corruption, Error, ErrorKind, Result};
use crate::read::archive;
use crate::read::block::{Block, Fields, FileHdr};
use crate::read::reader::{BlockReader, ReadCtx};
use crate::read::{Format, Progress, SplitCheck};
#[cfg(feature = "parallel")]
use crate::source::RangeSource;
use crate::source::Volumes;
use crate::types::Method;

/// How often `released` is reported and the cancel flag polled, in bytes of
/// source consumed and of output produced (spec F 3.7.3, 3.7.6).
pub(crate) const TICK: u64 = 1 << 20;

/// The progress observer, reachable from both sides of one member at once.
///
/// While a member decodes, the packed side reports `released` and the
/// decoded side reports `output`, and both are alive together: the decoder
/// sits between them. A `RefCell` is what lets one `&mut P` serve both.
/// The two borrows never overlap - an observer cannot call back into the
/// engine, so no call is ever made while the other side holds the cell -
/// and each is one call per mebibyte.
pub(crate) type Gate<'p, P> = RefCell<&'p mut P>;

/// Where the walk's drop-behind news goes.
///
/// The walk reports `released` and `volume_done` as it consumes a volume,
/// and until 20 Sep 2026 it reported them straight into the caller's
/// [`Progress`] through a [`Gate`]. Spec F 3.7.7 puts the READ of one
/// member on a second thread while the caller's writer stays on the
/// walking thread, and `Progress` has no `Send` bound (SPEC-API 8.5), so
/// the walk can no longer assume the thread it is on may call the
/// observer.
///
/// This is the one thing it needs of its surroundings: somewhere to put
/// the news. The sequential path passes the gate and the observer is
/// called where it always was; the seam passes [`Notes`], which records
/// the news in order for the walking thread to relay. Nothing about WHAT
/// is reported, or when, changes with the choice.
pub(crate) trait Notify {
    /// Nothing below `offset` of `volume` will be read again (3.7.3).
    fn released(&self, volume: u32, offset: u64) -> Result<()>;
    /// That volume is finished with entirely.
    fn volume_done(&self, volume: u32) -> Result<()>;
    /// The walk is about to ask the provider for the next volume. Every
    /// `released` and `volume_done` made so far must have reached the
    /// caller's `Progress` by the time this returns, because SPEC-API 5.3
    /// lets the caller drop volume `k` once it is released whole and the
    /// provider is entitled to rely on that when asked for `k + 1` (spec F
    /// 3.7.3). An observer that reports synchronously has nothing to do.
    fn crossing(&self) -> Result<()> {
        Ok(())
    }
}

impl<P: Progress> Notify for Gate<'_, P> {
    fn released(&self, volume: u32, offset: u64) -> Result<()> {
        self.borrow_mut().released(volume, offset)
    }

    fn volume_done(&self, volume: u32) -> Result<()> {
        self.borrow_mut().volume_done(volume)
    }
}

/// One piece of drop-behind news, kept in the order it was made.
#[cfg(feature = "parallel")]
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Note {
    Released(u32, u64),
    VolumeDone(u32),
}

/// The drop-behind news of a member whose read is running on the source
/// unit of spec F 3.7.7, for the walking thread to relay.
///
/// `released` must still be monotone and must still never name an offset
/// the source unit may read below (3.7.3, and acceptance test 7). Both
/// hold for free here, because the FILTERING is the walk's own and
/// unchanged: `Walk::release` only calls this for an offset it has passed
/// and only when it is higher than the last, and this keeps the order.
///
/// **The news reaches the caller before the next volume is asked for.**
/// The source unit crosses volume boundaries itself, inside the member's
/// stream, so it asks the provider for volume `k + 1` on its own thread.
/// The relay used to run only when a full ring buffer reached the walking
/// thread and at the member's end, so the provider was asked for the next
/// volume while the caller had heard only the header release of the one
/// before: a caller dropping volumes as they were released could not
/// supply the set at all (the coverage row
/// `f/onepass-rar4-m3-vol-text64`, 26 Sep 2026, volume 0 released to byte
/// 20 of 694,616). [`Notify::crossing`] now wakes the walking thread with
/// an empty ring buffer, which no hand-over ever sends, and waits until
/// that thread has relayed every note.
#[cfg(feature = "parallel")]
#[derive(Default)]
pub(crate) struct Notes {
    queue: std::sync::Mutex<Vec<Note>>,
    /// The ring's sender, while the source unit runs; `None` after.
    wake: std::sync::Mutex<Option<std::sync::mpsc::SyncSender<crate::read::seam::Slab>>>,
    /// The walking thread's answer to the last wake: `Some(true)` relayed,
    /// `Some(false)` the operation is stopping.
    answer: std::sync::Mutex<Option<bool>>,
    answered: std::sync::Condvar,
}

#[cfg(feature = "parallel")]
impl Notes {
    /// Hand every note made since the last drain to the observer, in
    /// order. A failing observer is the CALLER's error and stops the
    /// operation (spec F 3.7.6).
    pub(crate) fn drain_into<P: Progress>(&self, gate: &Gate<'_, P>) -> Result<()> {
        let taken = {
            let mut held = self.queue.lock().unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut *held)
        };
        for note in taken {
            match note {
                Note::Released(volume, offset) => gate.borrow_mut().released(volume, offset)?,
                Note::VolumeDone(volume) => gate.borrow_mut().volume_done(volume)?,
            }
        }
        Ok(())
    }

    /// Notes whose [`Notify::crossing`] wakes the walking thread through
    /// `wake`, the ring's own channel.
    pub(crate) fn waking(wake: std::sync::mpsc::SyncSender<crate::read::seam::Slab>) -> Notes {
        Notes {
            wake: std::sync::Mutex::new(Some(wake)),
            ..Notes::default()
        }
    }

    /// Drop the ring's sender, so the deliver loop can end.
    pub(crate) fn unhook(&self) {
        drop(self.wake.lock().unwrap_or_else(|e| e.into_inner()).take());
    }

    /// The walking thread's reply to a wake: whether it relayed.
    pub(crate) fn reply(&self, relayed: bool) {
        *self.answer.lock().unwrap_or_else(|e| e.into_inner()) = Some(relayed);
        self.answered.notify_all();
    }

    fn push(&self, note: Note) {
        self.queue
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(note);
    }
}

#[cfg(feature = "parallel")]
impl Notify for Notes {
    fn released(&self, volume: u32, offset: u64) -> Result<()> {
        self.push(Note::Released(volume, offset));
        Ok(())
    }

    fn volume_done(&self, volume: u32) -> Result<()> {
        self.push(Note::VolumeDone(volume));
        Ok(())
    }

    fn crossing(&self) -> Result<()> {
        let wake = self.wake.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let Some(wake) = wake else {
            return Ok(());
        };
        *self.answer.lock().unwrap_or_else(|e| e.into_inner()) = None;
        // The walking thread is gone: the operation is ending, and its own
        // error is the one reported.
        if wake.send(crate::read::seam::Slab::marker()).is_err() {
            return Err(Error::new(ErrorKind::Cancelled));
        }
        drop(wake);
        let mut answer = self.answer.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            match *answer {
                Some(true) => return Ok(()),
                Some(false) => return Err(Error::new(ErrorKind::Cancelled)),
                None => {
                    answer = self
                        .answered
                        .wait(answer)
                        .unwrap_or_else(|e| e.into_inner());
                }
            }
        }
    }
}

fn corrupt() -> Error {
    Error::new(ErrorKind::Corrupt(Corruption::VolumeSet))
}

/// The value a writer that keeps no per-fragment checksum leaves in the
/// field: all ones.
///
/// Spec F 3.5.6 has every fragment header but the last carrying the CRC32
/// of that fragment's PACKED bytes, and the genuine RAR 3.00 sets do.
/// Genuine RAR 1.54 does not: OBSERVED on the corpus's `rar154/random.*`,
/// a 2 MiB member over three volumes, whose two leading headers both hold
/// `0xFFFFFFFF` against packed CRC32s of `0xff19f87f` and `0x3361765c`,
/// and whose last holds the member's own `0x1c9eb697`. Judging the
/// placeholder as a checksum fails every RAR 1.5 volume set whose bytes
/// are perfect. A fragment that carries none is one `SplitCheck::Strict`
/// refuses, exactly as it refuses a header with no checksum field at all.
const NO_FRAGMENT_CRC: u32 = u32::MAX;

/// The unpack version whose writers keep no per-fragment checksum at all
/// (spec F 3.5.6 C3). Only the RAR 1.5 to 4.x container holds it: a RAR 5
/// header's version is 0 or 1 and the RAR 1.3 container's is 2.
const NO_FRAGMENT_CRC_VERSION: u32 = 15;

/// The CRC32 a fragment header carries over its own packed bytes, or
/// `None` when it carries none.
///
/// The CONTAINER decides (spec F 3.5.6 C3 and C4). In RAR 5 every CRC32
/// field is one, all ones and zero included: the reference prints its
/// line for either over packed bytes of another CRC32. In the older
/// container the field is not judged when the member's unpack version is
/// 15, whatever it holds, or when it is all ones at any version; the
/// reference prints nothing for those.
pub(crate) fn fragment_crc32(file: &FileHdr, format: Format) -> Option<u32> {
    let Some(crate::types::Checksum::Crc32(value)) = file.checksum else {
        return None;
    };
    let placeholder = !matches!(format, Format::Rar5)
        && (file.unpack_version == NO_FRAGMENT_CRC_VERSION || value == NO_FRAGMENT_CRC);
    (!placeholder).then_some(value)
}

/// Where the read context is while the walk is between volumes.
enum State<'c> {
    /// A volume is open and the reader holds the context.
    Walking(Box<BlockReader<'static, 'c>>),
    /// No volume is open; the context is here.
    Between(&'c mut ReadCtx),
    /// Only while one is being exchanged for the other.
    Moving,
}

/// The walk of one volume set.
pub(crate) struct Walk<'c, V: Volumes> {
    volumes: V,
    state: State<'c>,
    /// The volume being read.
    pub(crate) volume: u32,
    /// The generation volume 0's signature named.
    pub(crate) format: Format,
    /// Whether the main header of the volume being read said solid.
    pub(crate) solid_archive: bool,
    /// The number the previous volume declared, and the first the current
    /// volume declares (spec F 3.5.3).
    last_number: Option<u32>,
    number_here: Option<u32>,
    /// Volumes passed since `last_number` whose end record was damaged
    /// and so declared none (`ReadOptions::read_damaged`).
    unnumbered: u64,
    /// Headers read although their own checksum failed, in the volumes
    /// already closed (`ReadOptions::read_damaged`).
    unsound_read: u64,
    /// The first later fragment whose own encryption record could not be
    /// used, as the error the operation ends with once every member has
    /// been delivered. `None` on every set no such header sits in.
    pub(crate) fragment_refusal: Option<Error>,
    /// What the walk met while passing over the fragments a member still
    /// had ahead when a decoder's verdict ended it
    /// ([`MemberStream::pass_the_rest`]): the error the operation ends
    /// with once that member has been closed. `None` unless that walk
    /// failed.
    pub(crate) passing_failed: Option<Error>,
    /// What spec F 3.2.8 rule 2 says of the first volume whose locator
    /// names a quick open offset the walk of that volume did not bear
    /// out, as the error the operation ends with once every member has
    /// been delivered (`ReadOptions::read_damaged`). `None` on every set
    /// whose locators are right.
    pub(crate) locator_wrong: Option<Error>,
    /// Whether the main header of the volume being read carries the
    /// volume flag: the archive is a VOLUME of a set, which is what a
    /// member that ends short is judged by (spec F 4.2, rule 6).
    pub(crate) in_set: bool,
    /// This volume's end record said another follows.
    saw_end_with_next: bool,
    /// The volume the walk began in is a single archive or the FIRST
    /// volume of a set by its main header (spec F 3.5.3), so nothing can
    /// precede the first member in it.
    first_volume: bool,
    /// A member header has been delivered, other than a RAR 5
    /// redirection's, which has no stream.
    member_seen: bool,
    /// The member just delivered is the first of the walk, whole, in a
    /// volume known to be the first, so a solid bit on it continues no
    /// chain: it is an
    /// ORPHAN CHAIN START and begins a fresh stream (spec F 3.6). Where
    /// this is false a member with its bit set and no chain behind it is
    /// the genuinely missing head, which stays refused.
    pub(crate) at_set_start: bool,
    /// Drop-behind: the walk will never again read below this offset of the
    /// volume being read.
    released: u64,
    consumed_since_tick: u64,
    /// The largest working set any volume's reader has held, which the
    /// report carries.
    pub(crate) peak_reader_bytes: u64,
    started: bool,
    /// The source of the volume being read, kept by handle so a member's
    /// decode can be handed to a worker that reads that member's own byte
    /// range while the walk moves on (spec F 3.7.6). The walk itself reads
    /// through the reader and never through this.
    current: Option<std::sync::Arc<dyn crate::source::RangeSource>>,
    /// The drop-behind news of volumes whose bytes a read abreast has
    /// taken and not yet joined (`read::across`), kept back until they are.
    #[cfg(feature = "parallel")]
    kept: KeptNews,
}

/// Drop-behind news kept back while a read abreast holds bytes unjoined.
///
/// `released(volume, offset)` promises that nothing below `offset` of that
/// volume is read again, and `volume_done` that the volume is finished
/// with (spec F 3.7.3): a caller may free the volume's bytes on either. A
/// read abreast takes a fragment whole and crosses to the next volume
/// while readers are still reading this one, so what the walk would report
/// at the take and at the crossing is kept here, in order, and told only
/// when the last byte taken from that volume has been joined.
#[cfg(feature = "parallel")]
#[derive(Default)]
struct KeptNews {
    /// The lowest volume with bytes taken and not joined; news of it and
    /// of every later volume is kept.
    from: Option<u32>,
    /// The highest volume a fragment was taken from.
    taken: u32,
    notes: std::collections::VecDeque<Note>,
}

impl<'c, V: Volumes> Walk<'c, V> {
    pub(crate) fn new(volumes: V, ctx: &'c mut ReadCtx) -> Walk<'c, V> {
        Walk {
            volumes,
            state: State::Between(ctx),
            volume: 0,
            format: Format::Rar5,
            solid_archive: false,
            last_number: None,
            number_here: None,
            unnumbered: 0,
            unsound_read: 0,
            fragment_refusal: None,
            passing_failed: None,
            locator_wrong: None,
            in_set: false,
            saw_end_with_next: false,
            first_volume: false,
            member_seen: false,
            at_set_start: false,
            released: 0,
            consumed_since_tick: 0,
            peak_reader_bytes: 0,
            started: false,
            current: None,
            #[cfg(feature = "parallel")]
            kept: KeptNews::default(),
        }
    }

    /// The volume being read, by handle. `None` between volumes.
    ///
    /// A worker that holds one of these keeps that volume alive for as
    /// long as it needs it, which is what makes a concurrent decode safe
    /// against a walk that has already crossed into the next volume.
    ///
    /// And what lets a member be read a second time from its own range,
    /// which the walk's forward-only reader cannot do
    /// (`extract::reading`).
    pub(crate) fn shared_source(&self) -> Option<std::sync::Arc<dyn crate::source::RangeSource>> {
        self.current.clone()
    }

    /// The reader of the volume being read.
    fn reader(&mut self) -> Result<&mut BlockReader<'static, 'c>> {
        match &mut self.state {
            State::Walking(reader) => Ok(reader),
            _ => Err(corrupt().with_volume(self.volume)),
        }
    }

    /// Whether the volume being read has its headers encrypted, each one
    /// having been deciphered and checked with the session's key.
    pub(crate) fn headers_keyed(&self) -> bool {
        match &self.state {
            State::Walking(reader) => reader.headers_keyed(),
            _ => false,
        }
    }

    /// The read context, whether or not a volume is open.
    pub(crate) fn ctx(&mut self) -> &mut ReadCtx {
        match &mut self.state {
            State::Walking(reader) => reader.ctx(),
            State::Between(ctx) => ctx,
            State::Moving => unreachable!("the walk is never left moving"),
        }
    }

    /// The name arena of the volume being read.
    pub(crate) fn arena(&mut self) -> &[u8] {
        match &self.state {
            State::Walking(reader) => reader.arena(),
            _ => &[],
        }
    }

    /// Drop every name the current volume's reader added since `mark`.
    pub(crate) fn arena_reset(&mut self, mark: usize) {
        if let State::Walking(reader) = &mut self.state {
            reader.arena_reset(mark);
        }
    }

    pub(crate) fn arena_mark(&mut self) -> usize {
        match &self.state {
            State::Walking(reader) => reader.arena_mark(),
            _ => 0,
        }
    }

    /// Close the volume being read, keeping the context.
    fn close_volume(&mut self) {
        match std::mem::replace(&mut self.state, State::Moving) {
            State::Walking(reader) => {
                self.peak_reader_bytes = self.peak_reader_bytes.max(reader.working_bytes());
                self.unsound_read += reader.unsound_read();
                self.state = State::Between((*reader).into_ctx());
            }
            other => self.state = other,
        }
    }

    /// Open volume `self.volume`. `Ok(false)` means the provider has no
    /// such volume; what that means is the caller's to say.
    fn open_volume(&mut self) -> Result<bool> {
        self.close_volume();
        let index = self.volume;
        let Some(src) = self.volumes.volume(index)? else {
            return Ok(false);
        };
        let State::Between(ctx) = std::mem::replace(&mut self.state, State::Moving) else {
            unreachable!("the volume was just closed");
        };
        let found = match archive::require_signature(src.as_ref(), ctx.options.sfx_scan) {
            Ok(found) => found,
            Err(e) => {
                self.state = State::Between(ctx);
                return Err(e.with_volume(index));
            }
        };
        if index == 0 {
            self.format = found.format;
        }
        self.current = Some(std::sync::Arc::clone(&src));
        self.state = State::Walking(Box::new(BlockReader::shared(
            src,
            ctx,
            found.format,
            found.start,
        )));
        self.released = 0;
        self.number_here = None;
        self.saw_end_with_next = false;
        Ok(true)
    }

    /// Move to the next volume of the set, which a set that has ended does
    /// not have: that is `Truncated`, because something is still expected.
    fn next_volume<N: Notify>(&mut self, notify: &N) -> Result<()> {
        self.finish_this_volume()?;
        self.finish_volume(notify)?;
        notify.crossing()?;
        self.volume += 1;
        if !self.open_volume()? {
            return Err(Error::new(ErrorKind::Truncated).with_volume(self.volume));
        }
        Ok(())
    }

    /// Walk what is left of the volume being read, which is its trailing
    /// records: the end record above all, because the RAR 1.5 to 4.x
    /// family keeps its volume NUMBER there (3.3.10) and the ordering
    /// check of 3.5.3 has nothing else to go on. A member that ends on a
    /// volume boundary leaves those records unread, and a set whose
    /// members each span several volumes would then skip every number
    /// between the first and the last: OBSERVED as `Corrupt(VolumeSet)` on
    /// volume 25 of a 26-volume RAR 4 set spec G's writer wrote, whose
    /// numbers went 2 then 25 because the volumes between were crossed
    /// inside one member.
    ///
    /// This reads a volume's trailing records only when the walk has
    /// reached them, which is what 3.7.2 forbids doing EARLY and not at
    /// all.
    fn finish_this_volume(&mut self) -> Result<()> {
        if !matches!(self.state, State::Walking(_)) {
            return Ok(());
        }
        loop {
            let volume = self.volume;
            match self.reader()?.next() {
                Ok(Some(block)) => self.note(&block)?,
                Ok(None) => return Ok(()),
                Err(e) => return Err(e.with_volume(volume)),
            }
        }
    }

    /// The end of one volume: release it whole and tell the observer.
    fn finish_volume<N: Notify>(&mut self, notify: &N) -> Result<()> {
        let end = match &mut self.state {
            State::Walking(reader) => reader.source().len(),
            _ => None,
        };
        let end = end.unwrap_or(self.released);
        self.release(notify, end)?;
        // The walk of this volume has run to its end, which is when its
        // locator's quick open offset is judged (spec F 3.2.8 rule 2):
        // kept, so that it costs no member of this volume or a later one.
        if self.locator_wrong.is_none() {
            if let State::Walking(reader) = &self.state {
                self.locator_wrong = reader
                    .locator_verdict()
                    .map(|wrong| wrong.with_volume(self.volume));
            }
        }
        if self.number_here.is_some() {
            self.last_number = self.number_here;
            self.unnumbered = 0;
        } else if matches!(&self.state, State::Walking(reader) if reader.cut_after_split()) {
            // The RAR 1.5 to 4.x family keeps its number in the end
            // record, and this volume's was damaged and not read: the
            // next number met may be one further on for it.
            self.unnumbered += 1;
        }
        let volume = self.volume;
        self.close_volume();
        self.tell_done(notify, volume)
    }

    /// `volume_done`, told now or kept ([`KeptNews`]).
    fn tell_done<N: Notify>(&mut self, notify: &N, volume: u32) -> Result<()> {
        #[cfg(feature = "parallel")]
        if self.kept.from.is_some_and(|from| volume >= from) {
            self.kept.notes.push_back(Note::VolumeDone(volume));
            return Ok(());
        }
        notify.volume_done(volume)
    }

    /// `released`, told now or kept ([`KeptNews`]).
    fn tell_released<N: Notify>(&mut self, notify: &N, volume: u32, offset: u64) -> Result<()> {
        #[cfg(feature = "parallel")]
        if self.kept.from.is_some_and(|from| volume >= from) {
            self.kept.notes.push_back(Note::Released(volume, offset));
            return Ok(());
        }
        notify.released(volume, offset)
    }

    /// A fragment of the volume being read is taken whole by a read
    /// abreast: its news, and every later volume's, is kept from here on.
    #[cfg(feature = "parallel")]
    fn keep_news(&mut self) {
        self.kept.taken = self.volume;
        if self.kept.from.is_none() {
            self.kept.from = Some(self.volume);
        }
    }

    /// The last byte taken from `volume` is joined: tell its kept news, in
    /// order, and keep only what belongs to a later volume that still has
    /// bytes unjoined.
    #[cfg(feature = "parallel")]
    fn joined_news<N: Notify>(&mut self, notify: &N, volume: u32) -> Result<()> {
        self.kept.from = (volume < self.kept.taken).then_some(volume + 1);
        self.tell_kept(notify, Some(volume))
    }

    /// The read abreast is over, whatever it read: nothing of it is in
    /// flight, so every kept note is told (spec F 3.7.3: on an error path
    /// too, before the error is returned).
    #[cfg(feature = "parallel")]
    fn end_kept_news<N: Notify>(&mut self, notify: &N) -> Result<()> {
        self.kept.from = None;
        self.tell_kept(notify, None)
    }

    #[cfg(feature = "parallel")]
    fn tell_kept<N: Notify>(&mut self, notify: &N, through: Option<u32>) -> Result<()> {
        while let Some(note) = self.kept.notes.front() {
            let volume = match note {
                Note::Released(volume, _) | Note::VolumeDone(volume) => *volume,
            };
            if through.is_some_and(|through| volume > through) {
                break;
            }
            match self.kept.notes.pop_front().expect("checked") {
                Note::Released(volume, offset) => notify.released(volume, offset)?,
                Note::VolumeDone(volume) => notify.volume_done(volume)?,
            }
        }
        Ok(())
    }

    /// Report that nothing below `offset` of the volume being read will be
    /// read again (spec F 3.7.3).
    pub(crate) fn release<N: Notify>(&mut self, notify: &N, offset: u64) -> Result<()> {
        if offset > self.released {
            self.released = offset;
            let volume = self.volume;
            self.tell_released(notify, volume, offset)?;
        }
        Ok(())
    }

    fn tick_source<N: Notify>(&mut self, notify: &N, offset: u64, bytes: u64) -> Result<()> {
        self.consumed_since_tick += bytes;
        if self.consumed_since_tick >= TICK {
            self.consumed_since_tick = 0;
            self.release(notify, offset)?;
        }
        Ok(())
    }

    /// How many headers the walk has read although their own checksum
    /// failed, over every volume so far and the one being read.
    pub(crate) fn unsound_read(&self) -> u64 {
        let here = match &self.state {
            State::Walking(reader) => reader.unsound_read(),
            _ => 0,
        };
        self.unsound_read + here
    }

    /// What has been released of the volume being read, for the error path.
    pub(crate) fn released(&self) -> u64 {
        self.released
    }

    /// The next block of the set, crossing volume boundaries where the end
    /// record says another follows. `None` is the clean end of the set.
    /// Fill `into` with the next block; `false` at the end of the set.
    ///
    /// The caller owns the slot, so the 352 byte block is written once
    /// and never moved: returning it by value here and again out of
    /// `BlockReader` compiled to two `memcpy` calls of 0x160 bytes per
    /// block on a path that runs once per member, read off the release
    /// disassembly.
    pub(crate) fn next_block_into<N: Notify>(
        &mut self,
        notify: &N,
        into: &mut Block,
    ) -> Result<bool> {
        if !self.started {
            self.started = true;
            if !self.open_volume()? {
                return Err(Error::new(ErrorKind::NotAnArchive));
            }
        }
        loop {
            let volume = self.volume;
            match self.reader()?.next_into(into) {
                Ok(true) => {}
                Ok(false) => {
                    // A volume whose trailing records are damaged behind
                    // a member that continues has not said so with an end
                    // record; its last member header has
                    // (`ReadOptions::read_damaged`).
                    if self.saw_end_with_next || self.reader()?.cut_after_split() {
                        self.next_volume(notify)?;
                        continue;
                    }
                    self.finish_volume(notify)?;
                    return Ok(false);
                }
                Err(e) => return Err(e.with_volume(volume)),
            }
            self.note(into)?;
            if let Fields::File(file) = &into.fields {
                // A RAR 5 redirection has no stream, so it is not the
                // member a chain could start at (spec F 3.6.1 F6): the
                // member behind leading links is still the set's first.
                // A RAR 4 link's target IS its content and it counts.
                let streamless = file.redirect.is_some_and(|r| !r.in_content);
                if file.service.is_none() && !streamless {
                    self.at_set_start = !self.member_seen
                        && self.volume == 0
                        && !file.split_before
                        && self.first_volume;
                    self.member_seen = true;
                }
            }
            return Ok(true);
        }
    }

    /// The bookkeeping every block of every volume owes, whichever side of
    /// the walk asked for it.
    fn note(&mut self, block: &Block) -> Result<()> {
        match &block.fields {
            Fields::Main(main) => {
                self.solid_archive = main.solid;
                // Which volume is first (spec F 3.5.3): RAR 5's volume flag
                // with no number or number 0, the RAR 4 family's main flag
                // 0x0100. Asked of the volume the walk BEGAN in only: the
                // provider's index 0 is what the caller opened.
                //
                // A RAR 4 volume with 0x0100 CLEAR is not taken for the
                // first. 3.5.3 tells a writer that sets the flag (this is a
                // later volume) from one that never does (this may be the
                // first) by the volume's END block, and 3.7.2 forbids
                // reading that before the members in front of it: when the
                // first member is reached the evidence is not in hand. So
                // the member is refused as a missing head, which is right
                // for every later volume of a rar 3 or later set and wrong
                // only for a DOS RAR 2.50 first volume whose first member
                // carries its solid bit (no genuine writer sets it there;
                // DOS 1.55 has no bit to read, 3.6's erratum). The host
                // byte is never asked: it names the platform, not the
                // writer (3.5.3, 28 Sep 2026).
                self.in_set = main.is_volume;
                if self.volume == 0 {
                    self.first_volume = !main.is_volume
                        || match self.format {
                            Format::Rar5 => main.volume_number.unwrap_or(0) == 0,
                            _ => main.flags & u64::from(crate::read::rar4::MF_FIRST_VOLUME) != 0,
                        };
                }
                // RAR 5's volume number is zero-based and the FIRST volume
                // omits the field, so a RAR 5 set volume with no number
                // field is volume 0 (3.2.5). Without that default a set
                // handed over as part1, part3, part4 passes unremarked.
                //
                // The RAR 1.5 to 4.x main header has no number field at
                // all, and its "first volume" flag 0x0100 cannot stand in
                // for one. Spec F 3.5.3 reads that flag as a claim to be
                // volume 0; OBSERVED on the genuine RAR 3.00 sets
                // `multivol_oldnaming_rar300.*` and
                // `multivol_newnaming_rar300.part0*`, whose EVERY volume
                // carries main flags 0x0101 and 0x0111 respectively, so
                // the flag is set on the continuation volumes too. Reading
                // it as a number refuses every genuine RAR 3 set with
                // `Corrupt(VolumeSet)` on its second volume. The ordering
                // authority for that family is the END block's number
                // field, which those sets leave out (end flags 0x4001 and
                // 0x4000, bit 0x0002 clear), and where it is missing the
                // three join checks of 3.5.4 are what stop a spliced set.
                // An erratum to 3.5.3, not made yet.
                let now = match self.format {
                    Format::Rar5 => main.volume_number.or_else(|| main.is_volume.then_some(0)),
                    _ => None,
                };
                self.check_volume_number(now)
            }
            Fields::End(end) => {
                self.saw_end_with_next = end.next_follows;
                // The RAR 1.5 to 4.x family records the volume number in
                // its END block rather than its main header, so the
                // ordering check of spec F 3.5.3 lands here for that family.
                self.check_volume_number(end.volume_number)
            }
            _ => Ok(()),
        }
    }

    /// A volume whose declared number is lower than the previous volume's,
    /// or more than one higher, is `Corrupt`: the provider is handing over a
    /// different set or a set out of order, and continuing would splice one
    /// member's bytes from two archives (spec F 3.5.3). Only the first
    /// number a volume declares counts.
    fn check_volume_number(&mut self, now: Option<u32>) -> Result<()> {
        let Some(now) = now else { return Ok(()) };
        if self.number_here.is_some() {
            return Ok(());
        }
        if let Some(previous) = self.last_number {
            if now <= previous || u64::from(now) > u64::from(previous) + 1 + self.unnumbered {
                return Err(corrupt().with_volume(self.volume));
            }
        }
        self.number_here = Some(now);
        Ok(())
    }

    /// Read member data through the SAME buffer the headers are read
    /// through, so a byte a header read already fetched is not read again
    /// (spec F 7.3.3).
    fn take_data(&mut self, at: u64, buf: &mut [u8]) -> Result<usize> {
        self.reader()?.take_data(at, buf)
    }

    /// The volume being read, shared, when no byte at `at` is already in
    /// the walk's own buffer: a wide verify may then read `at` onwards
    /// straight from the source without reading any byte twice (spec F
    /// 3.7.2). `None` sends the caller through [`Self::take_data`].
    #[cfg(feature = "parallel")]
    fn wide_source(&mut self, at: u64) -> Result<Option<Arc<dyn RangeSource>>> {
        let reader = self.reader()?;
        if reader.holds(at) {
            return Ok(None);
        }
        Ok(reader.shared_source())
    }
}

/// What a wide verify may take of a member next ([`MemberStream::span`]).
#[cfg(feature = "parallel")]
pub(crate) enum Span {
    /// The unread rest of the fragment being read: `len` bytes at `at` of
    /// `source`, which the caller reads on its own threads and then
    /// reports with [`MemberStream::passed`].
    Range {
        source: Arc<dyn RangeSource>,
        at: u64,
        len: u64,
    },
    /// Take the next bytes through [`MemberStream::read_crc`]: some are in
    /// the walk's buffer already, or the source is a borrowed one.
    Narrow,
    /// The member has ended.
    End,
}

/// The packed byte stream of one member (spec F 2.3).
///
/// **`Send` where the walk and the notifier are** (spec F 3.7.7): the
/// stream borrows the walk and nothing else, so the source unit of the
/// seam may hold one member's stream for the length of that member inside
/// a `std::thread::scope` without the walk itself leaving the walking
/// thread. That is the whole of what this package owes the seam, and it
/// is why the observer reaches the stream through [`Notify`] rather than
/// through a [`Gate`]: `Progress` has no `Send` bound and must not gain
/// one (SPEC-API 8.5).
pub(crate) struct MemberStream<'w, 'c, V: Volumes, N: Notify> {
    walk: &'w mut Walk<'c, V>,
    notify: &'w N,
    /// The unread packed bytes of the fragment being read.
    at: u64,
    end: u64,
    /// The fragment being read says the member continues on the next
    /// volume.
    split_after: bool,
    /// What the next fragment's header must match (spec F 3.5.4).
    name: Vec<u8>,
    unpacked_size: Option<u64>,
    method: Method,
    strict: bool,
    /// The CRC32 of the fragment being read, which every fragment header
    /// but the last carries over its PACKED bytes (spec F 3.5.6).
    fragment_crc: Crc32,
    fragment_checksum: Option<u32>,
    /// The volumes (0 based) of the leading fragments whose packed CRC32
    /// disagreed with their header's field: a per-volume DIAGNOSTIC, never
    /// the member's failure (spec F 3.5.6, 29 Sep 2026). Empty, and so never
    /// allocated, on every member whose fields agree.
    pub(crate) fragment_mismatches: Vec<u32>,
    /// Set when the WALK itself failed: a source that ended, a volume the
    /// provider does not have, a continuation header that does not join.
    /// Those end the operation, where a decoder's verdict on one member's
    /// bytes ends only that member (spec F 8).
    pub(crate) broken: bool,
    /// The header of the fragment being read: the LAST one carries the
    /// member's own checksum (3.5.6).
    ///
    /// The FIRST fragment's header is the caller's own and is BORROWED.
    /// It is the whole of the header for every member that is not split,
    /// which on a many-member archive is every member there is, and
    /// cloning it per member cost a measured 6.1 ns of a 330 ns member on
    /// a laptop (the stored TEST legs). A later fragment's
    /// header is owned, because by the time it is read the walk has moved
    /// past the block that held the first.
    first: &'w FileHdr,
    /// The header of a LATER fragment, once one has replaced the first.
    /// `None` says the member has exactly one fragment.
    pub(crate) later: Option<Box<FileHdr>>,
    /// That fragment's data area and name, for the `close` report.
    pub(crate) data: std::ops::Range<u64>,
    pub(crate) name_span: std::ops::Range<u32>,
}

impl<'w, 'c, V: Volumes, N: Notify> MemberStream<'w, 'c, V, N> {
    /// Open the stream of the member whose first fragment is `block`.
    pub(crate) fn new(
        walk: &'w mut Walk<'c, V>,
        notify: &'w N,
        block: &Block,
        file: &'w FileHdr,
        name: &[u8],
    ) -> MemberStream<'w, 'c, V, N> {
        let strict = matches!(walk.ctx().options.split_check, SplitCheck::Strict);
        let fragment_checksum = fragment_crc32(file, walk.format);
        MemberStream {
            walk,
            notify,
            at: block.data.start,
            end: block.data.end,
            split_after: file.split_after,
            name: if file.split_after {
                name.to_vec()
            } else {
                Vec::new()
            },
            unpacked_size: file.unpacked_size,
            method: file.method,
            strict,
            fragment_crc: Crc32::new(),
            fragment_checksum,
            fragment_mismatches: Vec::new(),
            broken: false,
            first: file,
            later: None,
            data: block.data.clone(),
            name_span: file.name.clone(),
        }
    }

    /// The header of the fragment being read, borrowed from the caller
    /// until a later fragment replaces it.
    #[inline]
    pub(crate) fn file(&self) -> &FileHdr {
        self.later.as_deref().unwrap_or(self.first)
    }

    /// `Strict` refuses a set whose leading fragment headers carry no
    /// checksum field at all, which `Streaming` accepts (spec F question 1).
    pub(crate) fn check_leading_fragment(&self) -> Result<()> {
        // A RAR 5 member hashed with BLAKE2sp carries a hash per fragment
        // rather than a CRC32 (OBSERVED on the corpus's
        // `rar50/encrypted_multivol.part*`, whose three headers hold three
        // different digests), so such a header does carry a checksum even
        // though 3.5.6 names CRC32. Verifying it is not done yet: this package
        // checks the CRC32 form and accepts the other.
        let carries = match self.file().checksum {
            None => false,
            // All ones is a placeholder in the older container alone
            // (3.5.6 C4): in RAR 5 it is a field, and is judged.
            Some(crate::types::Checksum::Crc32(value)) => {
                matches!(self.walk.format, Format::Rar5) || value != NO_FRAGMENT_CRC
            }
            Some(crate::types::Checksum::Blake2sp(_)) => true,
        };
        if self.strict && self.split_after && !carries {
            return Err(corrupt()
                .with_member(&self.name)
                .with_volume(self.walk.volume));
        }
        Ok(())
    }

    /// Whether this fragment's packed CRC32 will be JUDGED, which is the
    /// only reason to compute it.
    ///
    /// Spec F 3.5.6 puts the packed CRC32 in every fragment header but the
    /// last, so it exists to catch a fragment that arrived wrong before the
    /// decoder is fed it. A member that does not continue past this
    /// fragment has no such field to compare against: `next_fragment` below
    /// consumes the running value under exactly this condition, and a
    /// member that is not split never reaches the consuming branch at all.
    ///
    /// Computing it anyway is a whole CRC32 pass over the member's packed
    /// bytes thrown away, which a profile of a 2 GiB stored member on this
    /// box put at 8 of 92 samples of the extract wall, alongside the
    /// member's own checksum in `emit` at 4. The two fields are fixed for
    /// the length of a fragment (set together at `new` and again for each
    /// fragment in `next_fragment`), so the test is a pair of loads once
    /// per read and never changes answer inside one.
    fn fragment_crc_wanted(&self) -> bool {
        self.split_after && self.fragment_checksum.is_some()
    }

    /// The end of one fragment: judge its packed checksum, and open the
    /// next fragment when the member continues. `Ok(false)` is the end of
    /// the member.
    fn next_fragment(&mut self) -> Result<bool> {
        // Every fragment header but the last carries the CRC32 of that
        // fragment's PACKED bytes (spec F 3.5.6).
        if self.split_after {
            if let Some(stored) = self.fragment_checksum {
                if std::mem::replace(&mut self.fragment_crc, Crc32::new()).finish() != stored {
                    // Named by the volume the fragment ends in, which the
                    // walk has not left yet.
                    self.fragment_mismatches.push(self.walk.volume);
                }
            }
        }
        if !self.split_after {
            return Ok(false);
        }
        // The next volume's headers are parsed only now: a reader that
        // walked them earlier would have read to the end of this volume
        // (spec F 3.7.2).
        self.walk.next_volume(self.notify)?;
        loop {
            let volume = self.walk.volume;
            let block = match self.walk.reader()?.next() {
                Ok(Some(block)) => block,
                // A volume with no continuation in it at all: keep asking,
                // exactly as a set whose end record promised another does.
                Ok(None) => {
                    self.walk.next_volume(self.notify)?;
                    continue;
                }
                Err(e) => return Err(e.with_volume(volume)),
            };
            self.walk.note(&block)?;
            let Fields::File(file) = &block.fields else {
                continue;
            };
            if file.service.is_some() {
                continue;
            }
            // The three checks of spec F 3.5.4, before the fragments are
            // joined. Failing any of them is `Corrupt` naming the member,
            // not a silent restart: that is the difference between
            // reporting a mismatched set and writing a file made of two
            // different members' bytes.
            let older = !matches!(self.walk.format, Format::Rar5);
            let arena = self.walk.arena();
            //
            // The sizes are compared only when BOTH headers declare one
            // (3.5.4 J5, 10 Oct 2026). A member genuine rar reads from
            // standard input carries the RAR 5 unknown size flag on every
            // fragment header but the last, which alone has its size:
            // comparing an unknown size with that one refused every such
            // set at its last volume.
            //
            // ONE DECLARED SIZE IS NOT COMPARED EITHER (11 Oct 2026): in
            // the older container, a pending size of 4,294,967,295, the
            // low field all ones over a high half of 0. It is one half
            // short of that container's "no size" (J6), the reference
            // reads such a set, and the member is judged by its last
            // header's size and checksum as any member is.
            let low_all_ones = older && self.unpacked_size == Some(u64::from(u32::MAX));
            let sizes_agree = match (self.unpacked_size, file.unpacked_size) {
                (Some(pending), Some(next)) => pending == next || low_all_ones,
                _ => true,
            };
            let joined = file.split_before
                && arena
                    .get(file.name.start as usize..file.name.end as usize)
                    .is_some_and(|n| n == self.name)
                && sizes_agree
                && file.method == self.method;
            if !joined {
                return Err(corrupt().with_member(&self.name).with_volume(volume));
            }
            // The size a later header must agree with is the last one
            // DECLARED, so a known size is never lost behind an unknown.
            if file.unpacked_size.is_some() {
                self.unpacked_size = file.unpacked_size;
            }
            // A LATER fragment's own encryption record that cannot be
            // used keys nothing (the first fragment's does), so the
            // member is read; the run is still not a success. unrar 7.23
            // extracts the member, says `Unknown encryption method` and
            // exits 2 (SWEEP3-08OCT-06, measured 9 Oct 2026).
            if let Some(refusal) = file.crypt.as_ref().and_then(|record| record.refusal()) {
                let refusal = refusal.with_member(&self.name).with_volume(volume);
                self.walk.fragment_refusal.get_or_insert(refusal);
            }
            self.at = block.data.start;
            self.end = block.data.end;
            self.split_after = file.split_after;
            self.fragment_checksum = fragment_crc32(file, self.walk.format);
            self.data = block.data.clone();
            self.name_span = file.name.clone();
            // One copy per LATER fragment, which a test counts so that a
            // change restoring the per-member copy is caught by more than
            // a wall (spec F 3.5.4, 3.5.6).
            #[cfg(feature = "test-support")]
            crate::probe::note_header_clone();
            self.later = Some(Box::new(file.clone()));
            return Ok(true);
        }
    }

    /// Take the next packed bytes of the member, in order. `Ok(0)` is the
    /// end of the member and nothing else: a fragment that ends on a volume
    /// boundary opens the next one here, and the decoder never learns of it.
    pub(crate) fn read(&mut self, into: &mut [u8]) -> Result<usize> {
        let outcome = self.read_inner(into, false).map(|(got, _)| got);
        if outcome.is_err() {
            self.broken = true;
        }
        outcome
    }

    /// [`Self::read`], and with it the CRC32 of exactly the bytes it
    /// returned when this read had to hash them anyway for a fragment's
    /// packed checksum: the member's own checksum can then take that CRC
    /// instead of a second pass over the same bytes. `None` when nothing
    /// was hashed here (a last fragment, an unsplit member, a fragment
    /// with no checksum to judge).
    ///
    /// The CRC describes bytes DELIVERED: a read that fails after its
    /// hash (the source's tick below) returns the error and no CRC, so no
    /// undelivered byte can reach a member's checksum.
    pub(crate) fn read_crc(&mut self, into: &mut [u8]) -> Result<(usize, Option<u32>)> {
        let outcome = self.read_inner(into, true);
        if outcome.is_err() {
            self.broken = true;
        }
        outcome
    }

    fn read_inner(&mut self, into: &mut [u8], share: bool) -> Result<(usize, Option<u32>)> {
        loop {
            if self.at < self.end {
                // Clamped in `u64` and THEN narrowed. A member fragment
                // may be larger than 4 GiB, so narrowing first truncates
                // on a 32-bit target and the `min` then picks the wrong
                // figure: a remainder of exactly 4 GiB narrows to zero and
                // the branch below reports end of data in the middle of a
                // member. Clamping first is exact, because `into.len()` is
                // a `usize` already.
                let want = (self.end - self.at).min(into.len() as u64) as usize;
                if want == 0 {
                    return Ok((0, None));
                }
                let got = self.walk.take_data(self.at, &mut into[..want])?;
                if got == 0 {
                    return Err(Error::new(ErrorKind::Truncated)
                        .with_member(&self.name)
                        .with_volume(self.walk.volume)
                        .with_offset(self.at));
                }
                let mut shared = None;
                if self.fragment_crc_wanted() {
                    if share {
                        // The read's own CRC from zero, appended to the
                        // fragment's register and handed on, so the
                        // member's checksum appends it too instead of a
                        // second pass over the same bytes.
                        let own = crate::checksum::crc32(&into[..got]);
                        self.fragment_crc.append(own, got as u64);
                        shared = Some(own);
                    } else {
                        self.fragment_crc.update(&into[..got]);
                    }
                }
                self.at += got as u64;
                self.walk.tick_source(self.notify, self.at, got as u64)?;
                return Ok((got, shared));
            }
            if !self.next_fragment()? {
                return Ok((0, None));
            }
        }
    }

    /// Whether the fragment being read says the member continues in the
    /// next volume.
    pub(crate) fn continues(&self) -> bool {
        self.split_after
    }

    /// A decoder's verdict has ended this member with fragments of it
    /// still AHEAD: pass over them unread, so that the walk stands after
    /// the member's LAST fragment and the next block it reads is the next
    /// member's and not this member's own continuation header.
    ///
    /// What the member's `close` reads (the header of the fragment the
    /// decode stopped in, its data area, its name, the fragments whose
    /// field disagreed) is left exactly as the decode left it: the close
    /// is the one a member with no fragment ahead would have had. A walk
    /// that fails here does not break the member: the error is kept in
    /// the walk (`passing_failed`) and ends the operation after the close.
    #[cold]
    pub(crate) fn pass_the_rest(&mut self) {
        let kept = (
            self.later.take(),
            self.data.clone(),
            self.name_span.clone(),
            std::mem::take(&mut self.fragment_mismatches),
        );
        if let Err(failed) = self.skip_inner() {
            self.walk.passing_failed.get_or_insert(failed);
        }
        (
            self.later,
            self.data,
            self.name_span,
            self.fragment_mismatches,
        ) = kept;
    }

    /// Advance past the whole member without reading its packed bytes,
    /// which only a member outside every solid chain may do (spec F 3.6).
    pub(crate) fn skip(&mut self) -> Result<()> {
        let outcome = self.skip_inner();
        if outcome.is_err() {
            self.broken = true;
        }
        outcome
    }

    fn skip_inner(&mut self) -> Result<()> {
        loop {
            let end = self.end;
            self.at = end;
            self.walk.tick_source(self.notify, end, 0)?;
            self.walk.release(self.notify, end)?;
            // A skipped fragment's packed checksum is not computed: the
            // bytes are never read, so there is nothing to judge.
            self.fragment_checksum = None;
            if !self.next_fragment()? {
                return Ok(());
            }
        }
    }

    /// A split member dispatched over its fragment list
    /// (`extract::Split`): cross to each next fragment exactly as
    /// [`Self::read`] would once this one's bytes were read, with every
    /// check of spec F 3.5.4 made here on the walking thread, and send the
    /// worker each fragment as it is found, then the last header. The
    /// bytes are the worker's to read and each leading fragment's packed
    /// CRC32 is the worker's to judge, so none is computed here.
    ///
    /// A crossing that fails (a volume the provider does not have, a
    /// continuation header that does not join) is this walk's error, as it
    /// is when the walk reads the member itself; the worker is told only
    /// that no more fragments come, by the channel closing.
    #[cfg(feature = "parallel")]
    pub(crate) fn forward_fragments(
        &mut self,
        more: &std::sync::mpsc::Sender<crate::read::extract::Next>,
    ) -> Result<()> {
        use crate::read::extract::Next;
        let outcome = (|| loop {
            let end = self.end;
            self.at = end;
            self.walk.tick_source(self.notify, end, 0)?;
            self.walk.release(self.notify, end)?;
            // Judged by the worker over the bytes it reads.
            self.fragment_checksum = None;
            // Before the next volume is opened: the worker may be this many
            // volumes behind and no more (`read::forwarded`).
            let held = crate::read::forwarded::take();
            if !self.next_fragment()? {
                // A worker that has gone takes no answer; its own error is
                // the one its member reports.
                let _ = more.send(Next::End(Box::new(self.file().clone())));
                return Ok(());
            }
            let src = self.walk.shared_source().ok_or_else(|| {
                corrupt()
                    .with_member(&self.name)
                    .with_volume(self.walk.volume)
            })?;
            let checksum = if self.split_after {
                self.fragment_checksum
            } else {
                None
            };
            let _ = more.send(Next::Fragment {
                src,
                data: self.at..self.end,
                checksum,
                volume: self.walk.volume,
                held,
            });
        })();
        if outcome.is_err() {
            self.broken = true;
        }
        outcome
    }

    /// The unread rest of the fragment being read, taken WHOLE for a
    /// caller that reads it on a team of its own kept across fragments
    /// (`read::across`): the pull form of [`Self::forward_fragments`]. A
    /// fragment read to its end is left exactly as [`Self::read`] leaves
    /// it, the next one opened here with every check of spec F 3.5.4, on
    /// the walking thread, `held` being its volume's place among those
    /// opened ahead (`read::forwarded`). The fragment answered is PASSED:
    /// its bytes are the caller's to read, its packed CRC32 the caller's to
    /// judge (the register so far goes with it), and the stream stands at
    /// its end.
    ///
    /// `Over`, with nothing consumed, for a fragment of `floor` bytes or
    /// more (the wide read's own), one larger than `room` (more packed
    /// bytes than the member declares: the ordinary loop drops the excess),
    /// and one whose volume is not held by handle.
    #[cfg(feature = "parallel")]
    pub(crate) fn lead(
        &mut self,
        floor: u64,
        room: Option<u64>,
        held: Option<crate::read::forwarded::Held>,
    ) -> Result<crate::read::across::Next> {
        let outcome = self.lead_inner(floor, room, held);
        if outcome.is_err() {
            self.broken = true;
        }
        outcome
    }

    #[cfg(feature = "parallel")]
    fn lead_inner(
        &mut self,
        floor: u64,
        room: Option<u64>,
        held: Option<crate::read::forwarded::Held>,
    ) -> Result<crate::read::across::Next> {
        use crate::read::across::{Lead, Next};
        loop {
            if self.at < self.end {
                let (from, end) = (self.at, self.end);
                let rest = end - from;
                if rest >= floor || room.is_some_and(|room| rest > room) {
                    return Ok(Next::Over);
                }
                let reader = self.walk.reader()?;
                let Some(source) = reader.shared_source() else {
                    return Ok(Next::Over);
                };
                // What the walk's own window holds of it is taken from
                // there: no byte range is read twice (spec F 3.7.2).
                let in_hand = (reader.held_from(from) as u64).min(rest) as usize;
                let mut head = vec![0u8; in_hand];
                if in_hand > 0 {
                    let got = reader.take_data(from, &mut head)?;
                    head.truncate(got);
                }
                let at = from + head.len() as u64;
                let judge = if self.fragment_crc_wanted() {
                    self.fragment_checksum
                } else {
                    None
                };
                let carried = std::mem::replace(&mut self.fragment_crc, Crc32::new());
                let volume = self.walk.volume;
                // Passed: judged by its taker. Its drop-behind news, and
                // the crossing's after it, is kept until its last byte is
                // joined ([`Self::fragment_joined`]).
                self.at = end;
                self.fragment_checksum = None;
                self.walk.keep_news();
                self.walk.tick_source(self.notify, end, 0)?;
                self.walk.release(self.notify, end)?;
                return Ok(Next::Lead(Lead {
                    source,
                    at,
                    len: end - at,
                    head,
                    carried,
                    judge,
                    volume,
                    held,
                }));
            }
            if !self.next_fragment()? {
                return Ok(Next::End);
            }
        }
    }

    /// The error [`Self::read`] gives for a source that ended at `at` of
    /// `volume` inside the member, for a reader that took the fragment
    /// ahead ([`Self::lead`]) and so cannot ask the walk which volume.
    #[cfg(feature = "parallel")]
    pub(crate) fn truncated_in(&mut self, volume: u32, at: u64) -> Error {
        self.broken = true;
        Error::new(ErrorKind::Truncated)
            .with_member(&self.name)
            .with_volume(volume)
            .with_offset(at)
    }

    /// A leading fragment taken ahead whose packed CRC32 disagreed with
    /// its header's field, named by its volume (spec F 3.5.6).
    #[cfg(feature = "parallel")]
    pub(crate) fn fragment_failed(&mut self, volume: u32) {
        self.fragment_mismatches.push(volume);
    }

    /// `len` more bytes of a fragment taken from `volume` are joined, up to
    /// `upto` of it: nothing below is read again, which is reported once a
    /// mebibyte as [`Self::read`] reports it (spec F 3.7.3).
    #[cfg(feature = "parallel")]
    pub(crate) fn passed_in(&mut self, volume: u32, upto: u64, len: u64) -> Result<()> {
        self.walk.consumed_since_tick += len;
        if self.walk.consumed_since_tick < TICK {
            return Ok(());
        }
        self.walk.consumed_since_tick = 0;
        let outcome = self.notify.released(volume, upto);
        if outcome.is_err() {
            self.broken = true;
        }
        outcome
    }

    /// The last byte of the fragment taken from `volume` is joined: its
    /// kept drop-behind news is told now (spec F 3.7.3).
    #[cfg(feature = "parallel")]
    pub(crate) fn fragment_joined(&mut self, volume: u32) -> Result<()> {
        let outcome = self.walk.joined_news(self.notify, volume);
        if outcome.is_err() {
            self.broken = true;
        }
        outcome
    }

    /// The read abreast has ended: every kept note is told.
    #[cfg(feature = "parallel")]
    pub(crate) fn fragments_ended(&mut self) -> Result<()> {
        let outcome = self.walk.end_kept_news(self.notify);
        if outcome.is_err() {
            self.broken = true;
        }
        outcome
    }

    /// Consume whatever the decoder left, so the walk lands after the
    /// member's last fragment whatever the decoder did with it.
    pub(crate) fn drain(&mut self, buf: &mut [u8]) -> Result<()> {
        while self.read(buf)? != 0 {}
        Ok(())
    }

    /// Where the member's next packed bytes are, for a caller that reads
    /// them on threads of its own (`read::wide`). A fragment that has been
    /// read to its end is judged and the next one opened here, exactly as
    /// [`Self::read`] does it, so the walk crosses a volume boundary on
    /// the walking thread and nowhere else (spec F 3.5.4, 3.7.1).
    #[cfg(feature = "parallel")]
    pub(crate) fn span(&mut self) -> Result<Span> {
        let outcome = self.span_inner();
        if outcome.is_err() {
            self.broken = true;
        }
        outcome
    }

    #[cfg(feature = "parallel")]
    fn span_inner(&mut self) -> Result<Span> {
        loop {
            if self.at < self.end {
                return Ok(match self.walk.wide_source(self.at)? {
                    Some(source) => Span::Range {
                        source,
                        at: self.at,
                        len: self.end - self.at,
                    },
                    None => Span::Narrow,
                });
            }
            if !self.next_fragment()? {
                return Ok(Span::End);
            }
        }
    }

    /// `len` bytes of the member at the stream's position were read and
    /// hashed off the walking thread, and `crc` is their CRC32: account
    /// for them as [`Self::read_crc`] would have, the fragment's packed
    /// checksum and the drop-behind report included (spec F 3.5.6,
    /// 3.7.3).
    #[cfg(feature = "parallel")]
    pub(crate) fn passed(&mut self, crc: u32, len: u64) -> Result<()> {
        debug_assert!(len <= self.end - self.at);
        if self.fragment_crc_wanted() {
            self.fragment_crc.append(crc, len);
        }
        self.at += len;
        let outcome = self.walk.tick_source(self.notify, self.at, len);
        if outcome.is_err() {
            self.broken = true;
        }
        outcome
    }

    /// Whether the CRC32 given to [`Self::passed`] is judged: this
    /// fragment carries a packed checksum and the member goes on after it
    /// (spec F 3.5.6).
    #[cfg(feature = "parallel")]
    pub(crate) fn packed_crc_wanted(&self) -> bool {
        self.fragment_crc_wanted()
    }

    /// The error [`Self::read`] gives for a source that ended at `at`
    /// inside the member, for the wide reader to give the same one.
    #[cfg(feature = "parallel")]
    pub(crate) fn truncated_at(&mut self, at: u64) -> Error {
        self.broken = true;
        Error::new(ErrorKind::Truncated)
            .with_member(&self.name)
            .with_volume(self.walk.volume)
            .with_offset(at)
    }

    /// A source error the wide reader met, which ends the walk as the
    /// same error through [`Self::read`] does.
    #[cfg(feature = "parallel")]
    pub(crate) fn broken_by(&mut self, error: Error) -> Error {
        self.broken = true;
        error
    }
}
