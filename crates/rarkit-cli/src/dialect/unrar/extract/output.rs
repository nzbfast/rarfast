//! An extracted file as it is written: its room reserved ahead, its times
//! set at its close, and the directories finished after.

use super::*;

/// A member's output file, whose modification time is set from the
/// archive on the open handle when it is closed - after the last write, so
/// nothing moves it again, and with no second open of the path. unrar
/// restores it; this dialect used not to (found 18 Sep 2026, every
/// extracted file carried the extraction time). Best effort, as the
/// reference's own restore is: a file system that refuses the time still
/// keeps the member's bytes.
///
/// The member's mode is set the same way and at the same moment, before
/// the time (a mode change moves only the status time, but the order is
/// the one the reference's result implies and costs nothing): see
/// [`mode`] for which bits, and [`mode::FileMode::finish`] for why most
/// files need no second call at all.
pub(super) struct TimedFile {
    pub(super) file: fs::File,
    pub(super) mtime: Option<SystemTime>,
    /// The mode to set at close, or `None` where creating the file already
    /// left it with the member's.
    pub(super) mode: Option<u32>,
    /// The member's declared unpacked size, or 0 where it has none.
    pub(super) declared: u64,
    /// Bytes handed to the file so far.
    pub(super) written: u64,
    /// How far room is RESERVED for the file ([`TimedFile::reserve`]),
    /// where that is ahead of `written`. The file's LENGTH is never moved
    /// by it: it is `written` at every instant.
    pub(super) reserved: u64,
    /// A big member's staging, where its file was opened past the OS cache
    /// ([`unbuffered`]); `None` for every other member, on a target with no
    /// such open, and after a fall back to the cached path.
    pub(super) staged: Option<unbuffered::Staged>,
    /// The member's close has been written through a handle still past the
    /// OS cache ([`TimedFile::flush`]): the file holds the member whole, at
    /// its exact length, and the handle takes no more bytes. Such a handle
    /// cannot be put at the member's end to wait for one (see the flush),
    /// so a write after it is refused here by name and never left to land
    /// wherever the handle's cursor happens to be.
    pub(super) shut: bool,
    /// For a member written BESIDE a taken name: how its file takes the
    /// member's name as it closes, once the run has found the member
    /// whole (`safepath::NameAtClose`). `None` for every other member.
    pub(super) named: Option<crate::safepath::NameAtClose>,
    /// A big member's writeback cursor, where it is written cached with
    /// writeback started behind the cursor ([`writeback`], Linux), and any
    /// cached member's under a cgroup memory cap, where its writes are
    /// paced; `None` for every other member.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    pub(super) behind: Option<writeback::Behind>,
}

/// The largest member that is HELD IN MEMORY when it replaces a file.
///
/// SPEC-CLI 9.4 W7 keeps the file that stood at a member's name through
/// any failure by writing the member beside it and renaming, and that
/// costs a replace dearly: 0.81x of writing in place on Windows and
/// about half on macOS, over 20,000 small files (counted 11 Oct 2026).
/// Its second form, settled the same day: a member no larger than this
/// is kept in memory until its close and the verdict on its bytes, and
/// only a member that is WHOLE AND VERIFIED is then written, in place,
/// over the old file. A bad archive never costs the old file; a write
/// the system refuses part way can, which is what every other RAR tool
/// loses in every failing case. A larger member is written beside and
/// renamed as before.
///
/// 1 MiB: the files whose number makes a replace slow are far under it
/// (the 20,000 of the row are at most 64 KiB).
pub(super) const HOLD_BOUND: u64 = 1 << 20;

/// The most that all held members may DECLARE between them at once:
/// 64 MiB, or an eighth of a named `-mm` where that is less. A member
/// that would take the run past it is not held: it is written beside the
/// old file and renamed, as a large one is. So the hold is a fixed,
/// small part of the working limit (the default limit is never under
/// 512 MiB), however many members the walk has open; a member's line is
/// opened before the one before it has closed, so their number is not
/// the pool's width.
pub(super) const HOLD_TOTAL: u64 = 64 << 20;

/// [`HOLD_TOTAL`] under a named `-mm`.
pub(super) fn hold_total(memory_cap: Option<u64>) -> u64 {
    memory_cap.map_or(HOLD_TOTAL, |named| HOLD_TOTAL.min(named / 8))
}

/// Where a held member's bytes are.
pub(super) enum HeldState {
    /// In memory still.
    Memory(Vec<u8>),
    /// It outgrew [`HOLD_BOUND`] (it declared less than it delivered) and
    /// went to a file, beside the taken name where one could be made:
    /// the run settles it as a member written beside.
    Spilled(Option<PathBuf>),
}

/// How a held member that outgrows its bound makes its file.
pub(super) type Spill = Box<dyn FnOnce() -> std::io::Result<(TimedFile, Option<PathBuf>)> + Send>;

/// The writer of a member held in memory ([`HOLD_BOUND`]).
pub(super) struct HeldWriter {
    pub(super) state: Arc<Mutex<HeldState>>,
    /// The file it went to, once it outgrew the bound.
    pub(super) file: Option<TimedFile>,
    pub(super) spill: Option<Spill>,
}

impl Write for HeldWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write_all(buf)?;
        Ok(buf.len())
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        if let Some(file) = self.file.as_mut() {
            return file.write_all(buf);
        }
        let mut state = sink::lock(&self.state);
        let HeldState::Memory(held) = &mut *state else {
            return Err(after_close());
        };
        if held.len() as u64 + buf.len() as u64 <= HOLD_BOUND {
            held.extend_from_slice(buf);
            return Ok(());
        }
        let Some(spill) = self.spill.take() else {
            return Err(after_close());
        };
        let (mut file, beside) = spill()?;
        let so_far = std::mem::take(held);
        *state = HeldState::Spilled(beside);
        drop(state);
        file.write_all(&so_far)?;
        file.write_all(buf)?;
        self.file = Some(file);
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self.file.as_mut() {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}

/// How far ahead of the write position a member's output file is grown.
///
/// The engine hands a stored member's bytes over in 64 KiB pieces
/// (`read::extract::COPY`), and a file extended 64 KiB at a time costs
/// about a third more wall than the same bytes written into a length the
/// file system already knows: 69 ms against 51 ms for 512 MiB on this
/// laptop's APFS, and 38 ms with the pieces at 128 KiB as well.
///
/// Reserved in STEPS rather than at the declared size in one call, on
/// purpose. A member may declare any size it likes - `fixtures/` holds
/// RAR 1.5 inputs that declare 4 GiB - and a file system that does not
/// store holes would then write the whole declaration before the first
/// byte arrived. What is ever reserved here is what has been written
/// plus one step.
pub(super) const RESERVE_STEP: u64 = 8 << 20;

/// The step [`TimedFile::reserve`] takes in a shipped build: [`RESERVE_STEP`],
/// except on Windows and on Apple systems, where it is 0, the DOUBLING
/// form (room is kept to twice what has been written, at least a step
/// ahead).
///
/// On NTFS every growth is a call, and at 8 MiB steps a 12 GiB
/// stored member made 1,536 of them: a Windows desktop (Ryzen 7 9800X3D, NTFS NVMe)
/// extracted it in 4.90 s against UnRAR.exe 7.23's 3.87 s, and the Windows
/// media work's write probe put the steps at 1.3 to 1.6 s of that. Doubling
/// makes about eleven calls for the same member (3.88 s, level with unrar)
/// and keeps the shipped guard: a member that declares far more than it
/// delivers is never reserved further ahead than it already holds. Growing
/// the file once to its declared size was as fast and gives that guard up;
/// no growth at all lost sintel (counted 29 Sep 2026).
///
/// On APFS the call that keeps room without moving the length
/// (`F_PREALLOCATE`) costs about 80 microseconds more than the
/// set-length it replaced: at 8 MiB steps a 512 MiB stored member read
/// 0.133 s against 0.128 s (0.962x); doubling, 0.126 s (1.020x); no
/// reservation at all, 0.135 s (an Apple silicon Mac Studio, K=7, 11 Oct
/// 2026). So Apple systems double as well. Linux keeps the 8 MiB steps:
/// its large rows are level with them.
#[cfg(not(any(windows, target_vendor = "apple")))]
#[cfg_attr(feature = "reserve-knob", allow(dead_code))]
pub(super) const SHIPPED_STEP: u64 = RESERVE_STEP;

/// See the other [`SHIPPED_STEP`].
#[cfg(any(windows, target_vendor = "apple"))]
#[cfg_attr(feature = "reserve-knob", allow(dead_code))]
pub(super) const SHIPPED_STEP: u64 = 0;

/// The declared size FROM which a member has no room kept for it at all;
/// under it room is kept. A member of no declared size (standard
/// input's) never had any.
///
/// `None` everywhere but on Apple systems: every size has room kept.
/// There it is the size from which the seam takes a member OF EVERY KIND
/// on its size alone ([`route::SEAM_TAKES_ANY_FROM`], a gibibyte), that
/// one name and no number of its own: under it room is kept whichever way
/// the member is written and however many are written at once.
///
/// It was first tied to the size from which the seam takes a clear stored
/// member under a CRC32 ([`route::SEAM_TAKES_FROM`]), which was the same
/// gibibyte when the rows below were sat. When that floor went to 32 MiB
/// the bound went with it, and every member declaring 32 MiB or more lost
/// its room: sixteen stored members of 128 MiB extracted at once read
/// 1.18 times slower at eight threads, 1.51 at sixteen and 1.63 at the
/// default width of an M5 Ultra, on three times the system CPU, where one
/// such member alone read level with room and without (K=7, 13 Oct 2026).
/// So the rows below are what the bound rests on, a member alone either
/// side of a gibibyte, and many members at once are why it does not
/// follow the lower floor. On APFS
/// (an Apple silicon Mac Studio, stored members, the default width, n=15
/// alternating, wall minima against the build before any room was kept,
/// 11 Oct 2026):
///
/// | member  | room kept | no reservation |
/// |---------|-----------|----------------|
/// | 512 MiB | 1.004x    | 0.965x         |
/// | 768 MiB | 1.010x    | 0.955x         |
/// | 896 MiB | 1.012x    | 0.956x         |
/// | 960 MiB | 1.021x    | 0.971x         |
/// | 992 MiB | 1.019x    | 0.963x         |
/// | 1 GiB   | 0.965x    | 1.011x         |
/// | 1.5 GiB | 0.973x    | 1.024x         |
/// | 4 GiB   | 0.940x    | 1.005x         |
///
/// The turn is the build before's own: at a gibibyte it reads the member
/// another way (0.255 s for 992 MiB, 0.184 s for 1 GiB), and a 768 MiB
/// member taken out of an archive of 1.34 GB sits on the small side, so
/// the member's size is the key and not the archive's. A member under a
/// gibibyte that the seam takes for another reason (the lone large one of
/// a set in small volumes) has no row and keeps room.
///
/// THE SIZE ALONE IS NOT THE KEY: at a read width of one the seam takes
/// no member, a member of any size is written by the sequential walk, and
/// room is kept for it ([`no_room_from`]). The shipped pair of 12 Oct 2026
/// (the same Mac Studio, `x -mt1`, K=15, both arms the release recipe's
/// draws) read the size-only rule at 0.909x for a 1 GiB stored member,
/// 0.898x for 2 GiB, 0.906x for 4 GiB and 0.916x for 12 GiB against the
/// build that moved the length, at 1.25 to 1.31 times its instructions,
/// where plain builds of 11 Oct had read the 4 GiB cell at 0.968x.
///
/// By the DECLARED size, which is all that is known when the first piece
/// arrives. Either side of it a run that is killed leaves a file of its
/// bytes and nothing more: room kept does not move the length, and no
/// reservation has nothing to give back.
#[cfg(not(all(target_vendor = "apple", feature = "parallel")))]
#[cfg_attr(feature = "reserve-knob", allow(dead_code))]
pub(super) const RESERVE_UNDER: Option<u64> = None;

/// See the other [`RESERVE_UNDER`].
#[cfg(all(target_vendor = "apple", feature = "parallel"))]
#[cfg_attr(feature = "reserve-knob", allow(dead_code))]
pub(super) const RESERVE_UNDER: Option<u64> = Some(super::route::SEAM_TAKES_ANY_FROM);

/// The read width this run stated to the engine, said once by the walk
/// before a member is written ([`state_read_width`]). Until then, and in a
/// row that builds a [`TimedFile`] by hand, it is unknown and reads as
/// wide.
static READ_WIDTH: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(usize::MAX);

/// States the run's read width, for [`no_room_from`].
pub(super) fn state_read_width(width: usize) {
    READ_WIDTH.store(width, std::sync::atomic::Ordering::Relaxed);
}

/// The declared size from which THIS RUN keeps no room for a member:
/// [`RESERVE_UNDER`] where the seam can take a member at all, which wants
/// a read width of two or more (the engine's seam spends a thread of the
/// width, and a width of one has none to spend); at a width of one, no
/// size. So room is kept wherever the sequential walk writes the member
/// and none only where the seam does.
#[cfg_attr(feature = "reserve-knob", allow(dead_code))]
pub(super) fn no_room_from() -> Option<u64> {
    if READ_WIDTH.load(std::sync::atomic::Ordering::Relaxed) < 2 {
        return None;
    }
    RESERVE_UNDER
}

/// THE RESERVE DIAL, for the Windows extract write path's untimed count:
/// one binary, the
/// reservation chosen by `RARFAST_RESERVE` read once, so the arms differ in
/// nothing else. `off` reserves nothing, `full` grows the file to the
/// member's declared size in one call, `double` to twice what has been
/// written each time, `step:N` in steps of N MiB, and
/// anything else is the shipped [`RESERVE_STEP`]. A feature of its own that
/// no shipped build and no `make ci` target enables.
#[cfg(feature = "reserve-knob")]
pub(super) mod reserve_knob {
    use std::sync::OnceLock;

    /// The step, or `None` for no reservation at all.
    pub(super) fn step() -> Option<u64> {
        static STEP: OnceLock<Option<u64>> = OnceLock::new();
        *STEP.get_or_init(|| {
            let v = std::env::var("RARFAST_RESERVE").unwrap_or_default();
            let step = match v.trim() {
                "off" => None,
                "full" => Some(u64::MAX),
                "double" => Some(0),
                other => Some(
                    other
                        .strip_prefix("step:")
                        .and_then(|n| n.parse::<u64>().ok())
                        .map_or(super::RESERVE_STEP, |mib| mib << 20),
                ),
            };
            eprintln!("rarfast reserve: {step:?}");
            step
        })
    }
}

impl TimedFile {
    /// Grow the file to cover `len` more bytes, in steps, never past what
    /// the member declared. Best effort: a file system that refuses the
    /// call still takes the bytes, one extension at a time.
    pub(super) fn reserve(&mut self, len: usize) {
        let want = self.written.saturating_add(len as u64);
        if want <= self.reserved || self.declared <= want {
            return;
        }
        #[cfg(feature = "reserve-knob")]
        let step = match reserve_knob::step() {
            Some(step) => step,
            None => return,
        };
        #[cfg(not(feature = "reserve-knob"))]
        let step = SHIPPED_STEP;
        // From the size where the seam writes the member (Apple systems
        // only, and only at a read width the seam can use), nothing is
        // asked of the file system. The dial's arms say for themselves.
        #[cfg(not(feature = "reserve-knob"))]
        if no_room_from().is_some_and(|from| self.declared >= from) {
            return;
        }
        // A zero step (Windows' shipped form, and the dial's `double`)
        // grows the file to twice what has been written, so it is never
        // reserved further ahead than it already holds.
        let ahead = if step == 0 {
            self.written.max(RESERVE_STEP)
        } else {
            step
        };
        let to = self
            .declared
            .min(self.written.saturating_add(ahead))
            .max(want);
        if reserve_room(&self.file, self.reserved.max(self.written), to) {
            self.reserved = to;
        } else {
            // A file system that has no such call, or refuses it: no
            // reservation, silently, and no second asking.
            self.declared = 0;
        }
    }
}

/// Reserves room for `file` from `from` up to `to` bytes WITHOUT moving
/// its length: the file system keeps the blocks for it, and the file is
/// still as long as the bytes written. So a run that is killed mid
/// member leaves a file of its bytes and nothing more (until 11 Oct
/// 2026 the length itself was moved ahead and put back at the close,
/// and a killed run left zeros to the next step, which `-kb` kept).
/// `false` where the system has no such call or the file system refuses
/// it.
///
/// THE THREE CALLS, one a system, each wrapped here and nowhere else:
/// Linux `fallocate` with keep-size; macOS `fcntl` `F_PREALLOCATE`,
/// counted from the end of what the file holds; Windows the
/// allocation-size class of `SetFileInformationByHandle`
/// (`safepath::set_allocation_size`).
#[cfg(any(target_os = "linux", target_os = "android"))]
#[allow(unsafe_code)]
fn reserve_room(file: &fs::File, from: u64, to: u64) -> bool {
    use std::os::fd::AsRawFd;
    let (Ok(offset), Ok(len)) = (
        libc::off_t::try_from(from),
        libc::off_t::try_from(to.saturating_sub(from)),
    ) else {
        return false;
    };
    // SAFETY: a plain system call on a descriptor this process holds
    // open for the length of the call (the `&File` borrow); it takes no
    // pointer.
    unsafe { libc::fallocate(file.as_raw_fd(), libc::FALLOC_FL_KEEP_SIZE, offset, len) == 0 }
}

/// See the Linux [`reserve_room`].
#[cfg(target_vendor = "apple")]
#[allow(unsafe_code)]
fn reserve_room(file: &fs::File, from: u64, to: u64) -> bool {
    use std::os::fd::AsRawFd;
    let Ok(length) = libc::off_t::try_from(to.saturating_sub(from)) else {
        return false;
    };
    let mut store = libc::fstore_t {
        fst_flags: libc::F_ALLOCATEALL,
        fst_posmode: libc::F_PEOFPOSMODE,
        fst_offset: 0,
        fst_length: length,
        fst_bytesalloc: 0,
    };
    // SAFETY: a plain system call on a descriptor this process holds
    // open for the length of the call; `store` is a whole `fstore_t`
    // that lives across it, which the call reads and writes.
    unsafe { libc::fcntl(file.as_raw_fd(), libc::F_PREALLOCATE, &raw mut store) != -1 }
}

/// See the Linux [`reserve_room`].
#[cfg(windows)]
fn reserve_room(file: &fs::File, _from: u64, to: u64) -> bool {
    crate::safepath::set_allocation_size(file, to)
}

/// A system with no such call: nothing is reserved.
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    windows
)))]
fn reserve_room(_file: &fs::File, _from: u64, _to: u64) -> bool {
    false
}

impl TimedFile {
    /// The member left direct writing mid-file: where the gate found the
    /// device slow, the rest goes in [`unbuffered::slow_form`], which on
    /// Linux is write-behind from the next step on; and under a cgroup
    /// memory cap the rest is paced, whatever sent it to the cache
    /// (`writeback`).
    pub(super) fn left_direct(&mut self) {
        let left = self
            .staged
            .take()
            .map(|staged| (staged.fell(), staged.slow_form()));
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        if self.behind.is_none() {
            self.behind = writeback::Behind::after_direct(
                self.written,
                left == Some((Some(unbuffered::Fell::Rate), unbuffered::Form::Behind)),
            );
        }
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
        let _ = left;
    }
}

impl Write for TimedFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.reserve(buf.len());
        if let Some(staged) = self.staged.as_mut() {
            if !staged.put(&mut self.file, buf)? {
                self.left_direct();
            }
            self.written += buf.len() as u64;
            return Ok(buf.len());
        }
        if self.shut {
            return Err(after_close());
        }
        let n = self.file.write(buf)?;
        self.written += n as u64;
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        if let Some(behind) = self.behind.as_mut() {
            behind.advance(&self.file, self.written);
        }
        Ok(n)
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.reserve(buf.len());
        if let Some(staged) = self.staged.as_mut() {
            if !staged.put(&mut self.file, buf)? {
                self.left_direct();
            }
            self.written += buf.len() as u64;
            return Ok(());
        }
        if self.shut {
            return Err(after_close());
        }
        self.file.write_all(buf)?;
        self.written += buf.len() as u64;
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        if let Some(behind) = self.behind.as_mut() {
            behind.advance(&self.file, self.written);
        }
        Ok(())
    }

    /// The member's CLOSE asks for this before its verdict
    /// (`Walk::on_close`), and for an unbuffered member it is where the
    /// last staged block is written, padded to a sector, and the file cut
    /// back to the bytes that arrived: a tail that cannot be written is
    /// this call's error, and so a write error like any other. Until 4 Oct
    /// 2026 that write was made in `drop` alone, which can report nothing:
    /// a disk that filled under the tail left a zero tail in a file of the
    /// member's whole length, reported `OK`.
    ///
    /// Once a member: the staging is taken, so a second call is the file's
    /// own flush. For a member written through the cache nothing is added.
    ///
    /// **No seek of the unbuffered handle (8 Oct 2026).** Until then this
    /// call ended by seeking the handle to the member's length, so that a
    /// write after it would land at the member's end. Windows refuses to
    /// put a `FILE_FLAG_NO_BUFFERING` handle anywhere but on a multiple of
    /// the volume's logical sector ("The parameter is incorrect", error
    /// 87), so on a drive of 512 byte sectors every member of 64 MiB or
    /// more whose length is not a multiple of 512 ended in a write error
    /// AFTER its bytes were down and its length was exact, and was removed.
    /// Seen on a Windows 11 PC on two NVMe drives, and traced there call by
    /// call (`examples/win_tail_probe.rs`): the write of whole sectors and
    /// the cut to the exact length succeed at every length, the seek fails
    /// at every length off a multiple of 512, from 6 bytes up.
    ///
    /// Why the hosted Windows gate never met it: a member that has left
    /// direct writing closes through a cached handle, which seeks anywhere
    /// (on that PC the same binary extracted the same member whole once its
    /// gate was forced slow, and failed with the gate forced open). A disk
    /// under the write-rate gate (`unbuffered::GATE_RATE`) sends every big
    /// member that way mid-file; a 300 MB member on a fast drive ends
    /// before the gate can judge it and closes direct. That a hosted
    /// runner's disk is under the gate is inferred from its passing, not
    /// measured there.
    ///
    /// The engine writes nothing after a member's close (`Walk::on_close`
    /// drops the handle next), so the seek bought nothing. Now: a member
    /// that fell back is closed through its cached handle, which the fall
    /// back left at the member's end; one still past the cache is SHUT
    /// ([`TimedFile::shut`]), and a later write is refused by name.
    fn flush(&mut self) -> std::io::Result<()> {
        if let Some(mut staged) = self.staged.take() {
            // Shut first: a close that fails part way leaves a handle whose
            // place nobody knows, and it takes no more bytes either.
            self.shut = true;
            staged.finish(&mut self.file)?;
            self.file.set_len(self.written)?;
            self.shut = staged.fell().is_none();
        }
        self.file.flush()
    }
}

/// The error of a write to a member whose close has already been written
/// past the OS cache ([`TimedFile::shut`]).
pub(super) fn after_close() -> std::io::Error {
    std::io::Error::other("a write after the member's close")
}

impl Drop for TimedFile {
    fn drop(&mut self) {
        // An unbuffered member that was never flushed, which is one that
        // already failed or stopped short (its close flushes every other,
        // and reports what that write says): its last partial block,
        // padded to a sector, and then the file cut back to the bytes that
        // arrived. Best effort, like everything here.
        if let Some(mut staged) = self.staged.take() {
            let _ = staged.finish(&mut self.file);
            let _ = self.file.set_len(self.written);
        }
        // The tail's writeback started too, before the cut back below.
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        if let Some(behind) = self.behind.as_mut() {
            behind.finish(&self.file, self.written);
        }
        // A member that stopped short - a damaged archive, a refused
        // password, a lost volume - gives back the room reserved past
        // its bytes: the file's length is already those bytes, and
        // setting it to itself is how a file system is told to let the
        // rest go. Before the time is set, since this call moves it.
        if self.reserved > self.written {
            let _ = self.file.set_len(self.written);
        }
        // After the last write, so the kernel's clearing of setuid and
        // setgid on a write cannot take them back off.
        if let Some(mode) = self.mode {
            mode::set_on(&self.file, mode);
        }
        if let Some(mtime) = self.mtime {
            let _ = self.file.set_modified(mtime);
        }
        // Last, with its bits and times on: the file gives itself the
        // member's name, where the run armed that and the system can.
        if let Some(named) = self.named.as_ref() {
            named.close_of(&self.file);
        }
    }
}

/// One directory member's mode and time, as the walk leaves them for
/// [`finish_directories`].
pub(super) struct DirFinish {
    pub(super) path: PathBuf,
    pub(super) mode: Option<u32>,
    pub(super) mtime: Option<SystemTime>,
}

/// Sets each extracted directory's mode and modification time from the
/// archive. Called when every member is written, so no later write moves
/// a time and no mode refuses a later child. A directory listed twice
/// keeps its LATER member's, as a later file member would. Best effort,
/// like [`TimedFile`]'s: a directory that cannot be opened or refuses the
/// change keeps what it has.
///
/// Each is an open, a set and a close, about 23 us on an Apple M3 Mac's APFS,
/// which over `small-r.rar`'s 1,722 directories was 4% of the run's wall
/// done serially; many are spread over up to four threads. Order is free
/// while every mode leaves the owner able to search the directory, which
/// is every directory a genuine writer has been seen to store; when one
/// does not (`0o555` is fine, `0o444` is not), children must be finished
/// before their parent, so the directories go deepest first, a level at
/// a time.
pub(super) fn finish_directories(dirs: Vec<DirFinish>) {
    // A directory listed twice keeps its LATER member's: the later entry
    // takes the earlier one's place, whichever of the two it has.
    let mut place: HashMap<PathBuf, usize> = HashMap::with_capacity(dirs.len());
    let mut kept: Vec<(usize, PathBuf, Option<u32>, Option<SystemTime>)> =
        Vec::with_capacity(dirs.len());
    for DirFinish { path, mode, mtime } in dirs {
        let depth = path.components().count();
        match place.get(&path) {
            Some(&at) => kept[at] = (depth, path, mode, mtime),
            None => {
                place.insert(path.clone(), kept.len());
                kept.push((depth, path, mode, mtime));
            }
        }
    }
    if kept.iter().all(|(_, _, mode, _)| owner_may_search(*mode)) {
        return finish_level(&kept);
    }
    // One mode would shut its directory to its owner: everything below a
    // directory is finished before it, the deepest level first.
    kept.sort_by_key(|entry| std::cmp::Reverse(entry.0));
    for level in kept.chunk_by(|a, b| a.0 == b.0) {
        finish_level(level);
    }
}

/// Whether a directory left with `mode` can still be searched by its
/// owner, so that what is below it can be finished after it. Off Unix the
/// word is not permission bits and shuts nothing.
fn owner_may_search(mode: Option<u32>) -> bool {
    if cfg!(unix) {
        mode.is_none_or(|bits| bits & 0o100 != 0)
    } else {
        true
    }
}

/// [`finish_directories`] for directories whose order does not matter.
pub(super) fn finish_level(dirs: &[(usize, PathBuf, Option<u32>, Option<SystemTime>)]) {
    let threads = if dirs.len() < 256 {
        1
    } else {
        std::thread::available_parallelism().map_or(1, |n| n.get().min(4))
    };
    let chunk = dirs.len().div_ceil(threads).max(1);
    std::thread::scope(|scope| {
        for part in dirs.chunks(chunk) {
            scope.spawn(move || {
                part.iter()
                    .for_each(|(_, path, mode, mtime)| finish_one(path, *mode, *mtime))
            });
        }
    });
}

pub(super) fn finish_one(path: &Path, mode: Option<u32>, mtime: Option<SystemTime>) {
    match crate::safepath::open_directory(path) {
        // Never a link (the open refuses one), and inside the tree: what
        // sits at the member's path takes its mode, as the reference's
        // own set by name would give it, with no second look.
        Ok(dir) => {
            if let Some(mode) = mode {
                mode::set_on(&dir, mode);
            }
            if let Some(mtime) = mtime {
                let _ = dir.set_modified(mtime);
            }
        }
        // A directory this user may not read, which the reference still
        // sets by name: the mode first, and then, if it now opens, the time.
        Err(_) => {
            if let Some(mode) = mode {
                if mode::set_on_directory_path(path, mode) {
                    if let (Some(mtime), Ok(dir)) = (mtime, crate::safepath::open_directory(path)) {
                        let _ = dir.set_modified(mtime);
                    }
                }
            }
        }
    }
}

impl Run<'_> {
    /// The time to set on what a member is written as: its archived
    /// time ([`member_mtime`]), or none under `-ts-` and `-tsm-`, which
    /// leave the time of extraction.
    pub(super) fn mtime_to_set(&self, member: &Member) -> Option<SystemTime> {
        if self.opts.leave_mtime {
            None
        } else {
            member_mtime(member)
        }
    }
}

/// A member's archived time as a `SystemTime`, to the precision the
/// archive stored: reference unrar 7.23 restores a RAR 5 TIME record's
/// nanoseconds and a RAR 4 extended time's 100 ns ticks, on files and
/// directories alike, and a DOS time's whole seconds. The fraction counts
/// FORWARD from the second, before 1970 too, as `rarkit::Timestamp` keeps
/// it. What the file system then keeps is its own affair: APFS and ext4
/// hold the nanosecond, NTFS truncates to its 100 ns tick, which is the
/// tick the reference's Windows build writes as well.
///
/// A time stored as a WALL CLOCK (every format before RAR 5) is set as
/// that clock in the box's own zone, as the reference sets it and as the
/// listing prints it ([`time::wall_to_instant`]); until sweep 2 item 38 it
/// was set as that clock in UTC.
pub(super) fn member_mtime(member: &Member) -> Option<SystemTime> {
    let seconds = member.mtime?;
    let seconds = if member.wall_clock {
        time::wall_to_instant(seconds).unwrap_or(seconds)
    } else {
        seconds
    };
    let whole = if seconds >= 0 {
        SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(seconds.unsigned_abs()))
    } else {
        SystemTime::UNIX_EPOCH.checked_sub(Duration::from_secs(seconds.unsigned_abs()))
    }?;
    whole.checked_add(Duration::from_nanos(u64::from(member.mtime_nanos)))
}

/// Sweep H-1 (4 Oct 2026): the tail of a member written past the OS cache.
#[cfg(test)]
mod lost_tail {
    use super::*;

    /// A staged tail that cannot be written is the FLUSH's error, which the
    /// member's close asks for before its verdict (`Walk::on_close`). Until
    /// this change the tail was written in `drop` alone, its error was
    /// discarded there, and the file was then set to the member's whole
    /// length: a zero tail under a member reported `OK`.
    ///
    /// The failure is made of two parts, as a full disk makes it: the
    /// tail's direct write is forced to fail, and the fall back's second
    /// open by name fails because the staging is told a name that is not
    /// there. Nothing here is one system's: it runs on Windows as on Unix,
    /// at depth 0 (the synchronous write every other target ships) and at
    /// depth 1 (the writer thread Windows ships).
    ///
    /// Assumes: no thread pool (this thread, and at depth 1 the output's
    /// one writer thread), under 16 MiB of memory (two staging blocks), any
    /// file system (the handle is a plain cached one; the staging does not
    /// ask which).
    #[test]
    fn a_staged_tail_that_cannot_be_written_fails_the_flush() {
        use unbuffered::Forced;
        let _serial = unbuffered::TEST_SERIAL
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        for depth in [0, 1] {
            unbuffered::forget();
            *unbuffered::TEST_DEPTH.lock().unwrap() = Some(depth);
            *unbuffered::TEST_FORCED.lock().unwrap() = Forced::Tail;
            let path = std::env::temp_dir().join(format!(
                "rarfast-lost-tail-{}-{:?}-{depth}",
                std::process::id(),
                std::thread::current().id()
            ));
            let gone = path.with_extension("gone");
            let _ = fs::remove_file(&path);
            let _ = fs::remove_file(&gone);
            let own = fs::File::create(&path).unwrap();
            let staged = unbuffered::Staged::new(&gone, &own, unbuffered::Member::Stored);
            // Pieces under a sector, so every byte is staged and none is
            // written before the close: 100,000 bytes, all of it tail.
            let piece = [7u8; 1000];
            let mut file = TimedFile {
                file: own,
                mtime: None,
                mode: None,
                declared: 100 * piece.len() as u64,
                written: 0,
                reserved: 0,
                staged: Some(staged),
                shut: false,
                named: None,
                #[cfg(all(target_os = "linux", target_env = "gnu"))]
                behind: None,
            };
            for _ in 0..100 {
                file.write_all(&piece).unwrap();
            }
            let staged_still = file.staged.is_some();
            let flushed = file.flush();
            let again = file.flush();
            drop(file);
            *unbuffered::TEST_FORCED.lock().unwrap() = Forced::None;
            *unbuffered::TEST_DEPTH.lock().unwrap() = None;
            let _ = fs::remove_file(&path);
            assert!(
                staged_still,
                "depth {depth}: the member left its staging before its close"
            );
            assert!(
                flushed.is_err(),
                "depth {depth}: 100,000 staged bytes reached no file and the flush said nothing"
            );
            // Said once: the staging is gone, and what is left is a plain file.
            assert!(again.is_ok(), "depth {depth}: a second flush: {again:?}");
        }
    }
}

/// EXPORT-08OCT-3 (8 Oct 2026): the close of a member still written past
/// the OS cache, at lengths that are not a whole number of sectors.
#[cfg(test)]
mod odd_close {
    use super::*;

    /// A member written past the cache to its END (no fall back) and closed
    /// by its flush, as `Walk::on_close` closes it: the flush succeeds, the
    /// file is the member's exact length while the handle is still open and
    /// after, its bytes are the member's, and a write after the close is
    /// refused and changes nothing.
    ///
    /// Before the fix the flush ended by seeking the unbuffered handle to
    /// the member's length, which Windows refuses off a sector boundary:
    /// every length here that is not a multiple of the volume's logical
    /// sector failed its flush with "The parameter is incorrect" on any
    /// Windows volume, a hosted runner's included. A test build's gate
    /// finds no device slow (`unbuffered::gate_rate` is 0 under test), so
    /// the member stays direct to its close here, which is the route a fast
    /// drive takes in the shipped tool and a hosted runner's slow disk does
    /// not; nothing else is forced. Linux's `O_DIRECT` handle seeks
    /// anywhere and passed before as after.
    ///
    /// Lengths: one byte either side of a block, of a sector and of 512
    /// bytes over a block, a multiple of 512 that is not one of 4,096, a
    /// length under one sector, and whole sectors. At depth 0 (the
    /// synchronous write) and depth 1 (the writer thread Windows ships),
    /// in pieces of 64 KiB and from a sector aligned buffer in one piece.
    ///
    /// Skipped, saying so, on a target with no such open and where neither
    /// the temp dir nor the crate's own dir takes one (a tmpfs).
    ///
    /// Assumes: no thread pool (this thread, and at depth 1 the output's
    /// one writer thread), under 64 MiB of memory (the member twice and
    /// two staging blocks), a file system that takes a direct open.
    #[test]
    fn a_member_still_direct_closes_at_its_exact_length_whatever_its_size() {
        use std::io::Read;
        let _serial = unbuffered::TEST_SERIAL
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if !unbuffered::ABLE {
            eprintln!("no past-the-cache open on this target: skipped");
            return;
        }
        const BLOCK: usize = 4 << 20;
        let lengths = [
            1,
            511,
            513,
            4095,
            4097,
            BLOCK - 1,
            BLOCK + 1,
            BLOCK + 512,
            BLOCK + 513,
            BLOCK + 4096,
            2 * BLOCK + 3 * 4096 + 1234,
            3 * BLOCK,
        ];
        let most = 3 * BLOCK;
        let mut store = vec![0u8; most + 4096];
        let skip = store.as_ptr().align_offset(4096);
        for (i, byte) in store[skip..].iter_mut().enumerate() {
            *byte = ((i as u32).wrapping_mul(2_654_435_761) >> 13) as u8;
        }
        let data = &store[skip..skip + most];
        let dirs = [std::env::temp_dir(), std::env::current_dir().unwrap()];
        let mut failed = Vec::new();
        for depth in [0, 1] {
            *unbuffered::TEST_DEPTH.lock().unwrap() = Some(depth);
            for (len, piece) in lengths
                .into_iter()
                .flat_map(|len| [(len, 64 << 10), (len, most)])
            {
                unbuffered::forget();
                let name = format!(
                    "rarfast-odd-close-{depth}-{len}-{piece}-{}",
                    std::process::id()
                );
                let mut opened = None;
                for dir in &dirs {
                    let path = dir.join(&name);
                    let _ = fs::remove_file(&path);
                    if let Ok(Some(crate::safepath::Created { file, .. })) =
                        crate::safepath::make_member_file_with(
                            &path,
                            crate::safepath::IfOutputExists::Keep,
                            0o666,
                            unbuffered::FLAG,
                        )
                    {
                        if unbuffered::take_direct(&file) {
                            opened = Some((path, file));
                            break;
                        }
                    }
                }
                let Some((path, own)) = opened else {
                    eprintln!("no directory here takes a direct open: skipped");
                    *unbuffered::TEST_DEPTH.lock().unwrap() = None;
                    return;
                };
                let staged = unbuffered::Staged::new(&path, &own, unbuffered::Member::Stored);
                let mut file = TimedFile {
                    file: own,
                    mtime: None,
                    mode: None,
                    declared: len as u64,
                    written: 0,
                    reserved: 0,
                    staged: Some(staged),
                    shut: false,
                    named: None,
                    #[cfg(all(target_os = "linux", target_env = "gnu"))]
                    behind: None,
                };
                for part in data[..len].chunks(piece) {
                    file.write_all(part).unwrap();
                }
                let direct_still = file.staged.is_some();
                let flushed = file.flush();
                let open_len = fs::metadata(&path).map(|m| m.len());
                let late = file.write_all(&[9u8; 4096]);
                let later = file.write(&[9u8; 1]);
                drop(file);
                let mut got = Vec::new();
                fs::File::open(&path)
                    .and_then(|mut f| f.read_to_end(&mut got))
                    .unwrap();
                let _ = fs::remove_file(&path);
                let case = format!("depth {depth}, {len} bytes in pieces of {piece}");
                if !direct_still {
                    failed.push(format!("{case}: left direct writing before its close"));
                }
                if let Err(e) = &flushed {
                    failed.push(format!("{case}: the flush failed: {e}"));
                }
                if open_len.as_ref().ok() != Some(&(len as u64)) {
                    failed.push(format!("{case}: length at the close {open_len:?}"));
                }
                if late.is_ok() || later.is_ok() {
                    failed.push(format!("{case}: a write after the close was taken"));
                }
                if got.len() != len {
                    failed.push(format!("{case}: length after the drop {}", got.len()));
                } else if got != data[..len] {
                    failed.push(format!("{case}: other bytes"));
                }
            }
        }
        *unbuffered::TEST_DEPTH.lock().unwrap() = None;
        assert!(failed.is_empty(), "{}", failed.join("\n"));
    }
}
