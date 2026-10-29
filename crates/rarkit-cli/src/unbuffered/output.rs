//! An archive output: written past the OS cache, or through it with its
//! corrections held to the close.

use super::*;

/// An ARCHIVE's output, for `a`: the one file (a single archive, or one
/// volume of a set) written past the cache where the target and the file
/// system allow, and through it otherwise.
///
/// **What an archive's output needs that a member's does not: writes BEHIND
/// its end.** The writer lays a header down with a placeholder and corrects
/// it where it lies once the bytes after it have passed (spec G 3.7.2,
/// `VolumeOut::patch`), so the output is `Write` and `Seek`, and a write
/// at a position short of the end is a correction of bytes already given.
/// Such a correction is applied where those bytes now are:
///
/// - still STAGED ([`Staged`]'s block, not yet on disk): into the block, so
///   they go down corrected with it, and no I/O at all;
/// - already written past the cache: each sector it touches is read back
///   through the same handle into sector aligned memory, corrected and
///   written again, and the handle is returned to where the next append
///   goes. That is the whole cost of a correction, a sector each way, and a
///   header is corrected at most once.
///
/// Appends go through [`Staged`] as a member's do, the archive's own
/// headers leaving its payload at no particular alignment in the file.
/// [`Output::close`] writes the staged tail and cuts the file back to the
/// bytes given; its error is the caller's, where a member's tail is written
/// on drop.
///
/// **And reads of what it wrote**, which is how the writer computes a
/// recovery record (`-rr`) without keeping a copy of the volume
/// (`VolumeOut::read_back`): bytes still staged are read from the block,
/// and bytes on disk through a sector aligned bounce buffer, whole sectors
/// at a time, the handle then returned to where the next append goes.
///
/// FALLBACK, silent and byte exact, as for a member: an open refused, or a
/// direct write or read-back that fails, leaves the rest of the output to
/// a cached handle at the right place ([`Staged`]'s fall back), and a
/// correction or a read after that is the cached output's ([`Held`]).
///
/// **On macOS a CACHED output holds its corrections and makes them at its
/// close**, by the rule [`HOLDS`] names ([`Held`]; nowhere else): a write
/// behind the end goes to a small list, and the list is written, in the
/// order given, by [`Output::close`], before any read of the output, before
/// a correction made at once, and early where it would pass its bound. The
/// file's bytes once closed are the same.
pub(crate) struct Output {
    pub(super) file: File,
    pub(super) direct: Option<Direct>,
    /// The cached output's own account of itself and the corrections it
    /// holds; `None` while the output is direct, and for a cached output
    /// driven as a plain file: every system but macOS ([`HOLDS`]), and where
    /// something was asked that the account does not model.
    pub(super) held: Option<Held>,
    /// When this output, once cached, holds its corrections ([`holds`],
    /// read once at its creation).
    pub(super) holds: Holds,
}

/// When a cached output holds a correction rather than making it at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Holds {
    /// Never: the plain file, each correction a seek and a write as given.
    Never,
    /// While the member being read is in the page cache ([`input_is_warm`])
    /// and never otherwise: a count arm since the rows chose
    /// [`Holds::WarmOrBound`] over it.
    #[cfg_attr(not(any(test, feature = "reserve-knob")), allow(dead_code))]
    WhenWarm,
    /// While the member being read is warm, OR whatever its residency
    /// where the create's own work is the bound and not the drive: an
    /// encrypted archive ([`create_is_bound`]). macOS's shipped rule
    /// ([`HOLDS`]).
    WarmOrBound,
    /// Always (a count arm, and the tests of the list itself).
    #[cfg_attr(not(any(test, feature = "reserve-knob")), allow(dead_code))]
    Always,
}

/// When a cached output holds its corrections until its close: on macOS
/// while its input is warm, or its create is bound by its cipher
/// ([`Holds::WarmOrBound`]); everywhere else never.
///
/// **What it wins, warm** (the stored set of eight like members, on disk):
/// an M5 Ultra 0.951 s to 0.637 s (1.49x; the default level 1.61x, `-rr3`
/// 1.31x, `-htb` 1.36x), an M1 Ultra 2.568 s to 1.743 s (1.47x, every rep
/// 1.71 to 1.76 s), an M5 Air 4.482 s to 1.565 s (2.86x)
/// (1 Oct 2026).
///
/// **Why not cold.** With memory to spare the form that makes each
/// correction at once gets something for nothing cold: the create reads
/// its input first and writes at the close, and held always LOST cold (the
/// M5 Ultra's plain set of eight 0.85x, 300 members of 8 MiB 0.60x; an M3 Ultra
/// 0.91x to 0.96x; the M1 Ultra 0.84x). Held only while the member being
/// read is warm, a cold create is the other form's own path (0.995x and
/// 0.997x). An ENCRYPTED create held won cold too on both Ultras sat
/// (1.13x and 1.22x): its cipher binds and not the drive. A BLAKE2sp one
/// won cold on one and lost on the other, so it does not count as bound.
///
/// **What it leaves as it was, still to do.** On a Mac with little memory
/// (an M5 Air, 32 GiB, 7 GiB of it compressed already) the cold form SWAPS:
/// 4,408 to 8,136 pages a create of that set, where held swapped
/// nothing and ran 1.23x faster. A rule by the output's share of physical
/// memory was built and failed its confirm (an eighth held the M1 Ultra's
/// cold set of eight at 0.84x where nothing swapped: 64 GiB with memory free):
/// what separates the two machines is their memory STATE, and a rule that
/// reads it has no rows yet.
///
/// **What it does not fix.** On the M3 Ultra an appending cached write of
/// 8.76 GB runs seconds long about one time in eight to eleven, WHOEVER
/// writes it (a one-thread plain copy waited in 6 of 40 runs); the held
/// form appends, so a warm create there meets it (16 long of 174) where
/// the other form meets it more rarely (7 of 115, mostly in its close).
/// By the mean the held form does not lose there and by the median it
/// wins; its worst runs are longer. The cause is that system's and is not
/// known.
///
/// On Linux's cached arm every rule read level with the plain file (0.98x
/// to 1.02x), so nothing is left to do there and nothing is held.
pub(crate) const HOLDS: Holds = if cfg!(target_os = "macos") {
    Holds::WarmOrBound
} else {
    Holds::Never
};

#[cfg(test)]
thread_local! {
    /// A test's own answer to [`holds`], for the thread it runs on: the
    /// held form is tested on every system, and the plain one on macOS.
    pub(crate) static TEST_HOLDS: std::cell::Cell<Option<Holds>> = const { std::cell::Cell::new(None) };
    /// A test's own answer to "is the input warm", for its thread.
    pub(crate) static TEST_WARM: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
    /// A test's own answer to "is the create bound", read with `TEST_WARM`.
    pub(crate) static TEST_BOUND: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// [`HOLDS`]; in a `reserve-knob` build what `RARFAST_HELD` says (`1`
/// always, `0` never, `w` while the input is warm, `x` while it is warm or
/// the create is bound by its cipher, on any system), for a count
/// or a timed run in one binary.
pub(super) fn holds() -> Holds {
    #[cfg(test)]
    if let Some(stated) = TEST_HOLDS.with(std::cell::Cell::get) {
        return stated;
    }
    #[cfg(all(not(test), feature = "reserve-knob"))]
    match std::env::var("RARFAST_HELD").as_deref().map(str::trim) {
        Ok("1") => return Holds::Always,
        Ok("0") => return Holds::Never,
        Ok("w") => return Holds::WhenWarm,
        Ok("x") => return Holds::WarmOrBound,
        _ => {}
    }
    HOLDS
}

/// Whether the member a create is reading now was found in the page cache:
/// set by the command line's source as it opens each member it samples
/// ([`input_is_warm`]), read by the output at each correction. A command
/// line runs one create a process, so a process-wide flag is the whole of
/// it. Cold until a member says otherwise: an input never sampled (members
/// too small to be worth the sample) is written as it always was.
pub(super) static INPUT_WARM: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Whether a create's source should sample its members' residency at all:
/// only where an output holds corrections by it.
pub(crate) fn samples_input() -> bool {
    matches!(holds(), Holds::WhenWarm | Holds::WarmOrBound)
}

/// Whether this create's own work is its bound whatever the drive does: its
/// members are enciphered. Set once by the command line before its first
/// member, read under [`Holds::WarmOrBound`].
pub(super) static CREATE_BOUND: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// States whether the create is bound by a cipher of its own.
pub(crate) fn create_is_bound(bound: bool) {
    CREATE_BOUND.store(bound, std::sync::atomic::Ordering::Relaxed);
}

/// Whether a correction is held under `holds`, the member being read
/// `warm` and the create `bound` by its own work.
pub(super) fn held_by(holds: Holds, warm: bool, bound: bool) -> bool {
    match holds {
        Holds::Never => false,
        Holds::Always => true,
        Holds::WhenWarm => warm,
        Holds::WarmOrBound => warm || bound,
    }
}

/// States whether the member now being read is in the page cache.
pub(crate) fn input_is_warm(warm: bool) {
    INPUT_WARM.store(warm, std::sync::atomic::Ordering::Relaxed);
}

/// Whether a correction given now is held: by the output's rule, what the
/// source last said of its input, and what the command line said of the
/// create ([`held_by`]).
pub(super) fn holding_now(holds: Holds) -> bool {
    #[cfg(test)]
    if let Some(warm) = TEST_WARM.with(std::cell::Cell::get) {
        return held_by(holds, warm, TEST_BOUND.with(std::cell::Cell::get));
    }
    held_by(
        holds,
        INPUT_WARM.load(std::sync::atomic::Ordering::Relaxed),
        CREATE_BOUND.load(std::sync::atomic::Ordering::Relaxed),
    )
}

/// A CACHED output's corrections, held until its close.
///
/// **Why.** A stored member read from a file states no CRC32, so its header
/// goes down with a placeholder and is corrected where it lies once the
/// member's bytes have passed: a write of a few tens of bytes BEHIND the
/// end, once a member. On APFS that backward write stops the kernel writing
/// the cached file back as it grows, and what it would have written as it
/// went is then written at `close`: a 4 GiB archive of eight stored members
/// spent 228 ms in the one `close(2)` of its output after a 155 ms write
/// (6.50 G instructions against 4.32 G for the same bytes as one member,
/// whose single correction comes at its end), and a plain copy with a
/// 64-byte write behind the end per member closed in 0.34 to 0.66 s against
/// 0.000 s with the same writes all made at the end
/// (the close count, 1 Oct 2026). So
/// the corrections are kept here and made at the end, in the order they
/// were given, and the file is only ever appended to until then.
///
/// **What it keeps**: the output's length and the position the writer
/// believes it is at, which a seek within the output only moves here (no
/// system call); where the file really is, so an append or a read seeks
/// only when it must; and the corrections, at most [`HELD_BYTES_MOST`]
/// bytes in [`HELD_SPANS_MOST`] pieces. At either bound the list is written
/// EARLY, in order, and starts again; a single correction of more than a
/// quarter of the byte bound is written at once, after the list. A read of
/// the output (a recovery record's read-back) writes the list first, so no
/// byte is ever read from under a correction not yet made.
///
/// **A failed or abandoned create.** The corrections are in the file only
/// once [`Output::close`] has returned, which is where the engine's
/// `finished` is answered; an output dropped without it (the run failed and
/// removes the file, or the process was killed) holds its members' bytes
/// and their headers as first laid down. So on macOS a create KILLED part
/// way leaves the completed members' data with their headers' checksum
/// fields not yet corrected, where before they were corrected as each
/// member ended; what a reader then makes of such a file is pinned by
/// `a_cached_archive_left_unclosed_reads_as_this` in the create tests. The
/// output of a cancelled or killed run was always the caller's to discard.
///
/// A seek past the end, which the writer never asks for, ends the account:
/// the list is written, the file is put where the writer believes it is, and
/// from there the output is a plain file, as it was before this.
pub(super) struct Held {
    /// Bytes given so far: the end of the output, and of the file.
    pub(super) len: u64,
    /// Where the writer's next write or read goes.
    pub(super) pos: u64,
    /// Where the file's own offset is, or `u64::MAX` when a failed call has
    /// left it unknown.
    pub(super) real: u64,
    /// The corrections held, in the order given: where each goes and how
    /// many of `bytes` it is.
    pub(super) spans: Vec<(u64, usize)>,
    pub(super) bytes: Vec<u8>,
}

/// The most correction bytes a cached output holds before it writes them.
/// A stored member's header correction is a few tens of bytes.
///
/// **Small on purpose** (1 Oct 2026): the bound is
/// charged to every create on every system ([`HELD_MOST`]), so that a named
/// `-mm` leaves the writer the same on every machine, and on the systems
/// that hold nothing that charge buys nothing. With [`HELD_SPANS_MOST`] it comes to 80 KiB, and covers every
/// media shape ranked first (a many-member set is 8 to 24 members); past it the list
/// is written early.
pub(crate) const HELD_BYTES_MOST: usize = 64 << 10;

/// The most corrections held, whatever their size.
pub(crate) const HELD_SPANS_MOST: usize = 1_024;

/// What a cached output's held corrections can come to in memory, for the
/// create's `caller_resident`: the bytes and the list's own entries. It is
/// charged on EVERY system, though only macOS holds ([`HOLDS`]): what the
/// writer is left under a named `-mm` decides bytes, and bytes must not
/// depend on the machine (1 Oct 2026).
pub(crate) const HELD_MOST: u64 =
    (HELD_BYTES_MOST + HELD_SPANS_MOST * std::mem::size_of::<(u64, usize)>()) as u64;

impl Held {
    /// The account of a cached output `len` bytes long, the writer at `pos`
    /// and the file's own offset at `real`, where the output `holds`; `None`
    /// where it is the plain file.
    pub(super) fn at(holds: Holds, len: u64, pos: u64, real: u64) -> Option<Held> {
        (holds != Holds::Never).then(|| Held {
            len,
            pos,
            real,
            spans: Vec::new(),
            bytes: Vec::new(),
        })
    }
}

/// The state of an [`Output`] still written past the cache.
pub(super) struct Direct {
    pub(super) staged: Staged,
    /// Bytes given so far: the end of the output.
    pub(super) len: u64,
    /// Where the next write goes.
    pub(super) pos: u64,
    /// One sector, sector aligned, for a correction's read-back.
    pub(super) sector: Vec<u8>,
    pub(super) sector_at: usize,
    /// A block, sector aligned, for reads of bytes on disk: allocated on
    /// the first such read, which only a recovery record makes. It holds
    /// the WINDOW `bounce_from` to `bounce_from + bounce_len` of the file,
    /// read a block at a time, so a recovery record's many small reads of
    /// one volume cost one disk read a block and not one each.
    pub(super) bounce: Vec<u8>,
    pub(super) bounce_from: u64,
    pub(super) bounce_len: usize,
}

impl Output {
    /// Creates `path` for an output expected to reach about `expected`
    /// bytes: past the cache when that is at least [`LEAST`] and the target,
    /// the file system and the open allow it, and through the cache
    /// otherwise. Either way it is created or truncated, symlinks followed,
    /// as `File::create` does, and opened for READING as well, because the
    /// writer reads a volume back for its recovery record.
    pub(crate) fn create(path: &Path, expected: u64) -> std::io::Result<Output> {
        let holds = holds();
        if form(expected) == Form::Direct && !open_refused() {
            if let Ok(file) = open_direct(path) {
                if take_direct(&file) {
                    let sector = vec![0u8; 2 * SECTOR];
                    let sector_at = sector.as_ptr().align_offset(SECTOR);
                    let mut staged = Staged::at_depth(path, &file, depth_or(OUTPUT_DEPTH), None);
                    staged.readable = true;
                    return Ok(Output {
                        file,
                        held: None,
                        holds,
                        direct: Some(Direct {
                            staged,
                            len: 0,
                            pos: 0,
                            sector,
                            sector_at,
                            bounce: Vec::new(),
                            bounce_from: 0,
                            bounce_len: 0,
                        }),
                    });
                }
            }
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        Ok(Output {
            file,
            direct: None,
            held: Held::at(holds, 0, 0, 0),
            holds,
        })
    }

    /// Whether the output is still being written past the cache.
    #[cfg(test)]
    pub(crate) fn is_direct(&self) -> bool {
        self.direct.is_some()
    }

    /// Writes the staged tail and cuts the file back to the bytes given; a
    /// cached output writes the corrections it holds ([`Held`]). The output
    /// takes no more bytes after this.
    pub(crate) fn close(&mut self) -> std::io::Result<()> {
        let Some(mut direct) = self.direct.take() else {
            self.make_held()?;
            return self.file.flush();
        };
        direct.staged.finish(&mut self.file)?;
        self.file.set_len(direct.len)
    }

    /// Writes every correction a cached output holds, in the order given,
    /// and empties the list. The file's offset is left after the last one;
    /// [`Held::real`] says so, and the next append or read seeks.
    pub(super) fn make_held(&mut self) -> std::io::Result<()> {
        let Some(held) = self.held.as_mut() else {
            return Ok(());
        };
        let mut from = 0;
        for &(at, len) in &held.spans {
            held.real = u64::MAX;
            self.file.seek(SeekFrom::Start(at))?;
            self.file.write_all(&held.bytes[from..from + len])?;
            held.real = at + len as u64;
            from += len;
        }
        held.spans.clear();
        held.bytes.clear();
        Ok(())
    }

    /// How many corrections a cached output holds.
    #[cfg(test)]
    pub(crate) fn held_count(&self) -> usize {
        self.held.as_ref().map_or(0, |held| held.spans.len())
    }

    /// A cached output's write: an append to the file, or a correction
    /// behind the end, which is held.
    pub(super) fn write_cached(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let Some(held) = self.held.as_mut() else {
            return self.file.write(buf);
        };
        if held.pos == held.len {
            if held.real != held.len {
                held.real = u64::MAX;
                self.file.seek(SeekFrom::Start(held.len))?;
                held.real = held.len;
            }
            held.real = u64::MAX;
            let wrote = self.file.write(buf)?;
            held.len += wrote as u64;
            held.pos = held.len;
            held.real = held.len;
            return Ok(wrote);
        }
        // Behind the end: a correction, as far as the end; what lies past
        // it is the next call's, an append.
        let take = buf.len().min((held.len - held.pos) as usize);
        let at = held.pos;
        if take > HELD_BYTES_MOST / 4 || !holding_now(self.holds) {
            // Too large to hold, or given while the input is cold: made at
            // once, after everything given before it.
            self.make_held()?;
            let held = self.held.as_mut().expect("still held");
            held.real = u64::MAX;
            self.file.seek(SeekFrom::Start(at))?;
            self.file.write_all(&buf[..take])?;
            held.real = at + take as u64;
            held.pos = held.real;
            return Ok(take);
        }
        if held.spans.len() == HELD_SPANS_MOST || held.bytes.len() + take > HELD_BYTES_MOST {
            self.make_held()?;
        }
        let held = self.held.as_mut().expect("still held");
        held.spans.push((at, take));
        held.bytes.extend_from_slice(&buf[..take]);
        held.pos += take as u64;
        Ok(take)
    }

    /// A cached output's read: of the file with every correction made.
    pub(super) fn read_cached(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.held.is_none() {
            return std::io::Read::read(&mut self.file, buf);
        }
        self.make_held()?;
        let held = self.held.as_mut().expect("still held");
        if held.real != held.pos {
            held.real = u64::MAX;
            self.file.seek(SeekFrom::Start(held.pos))?;
            held.real = held.pos;
        }
        held.real = u64::MAX;
        let got = std::io::Read::read(&mut self.file, buf)?;
        held.pos += got as u64;
        held.real = held.pos;
        Ok(got)
    }

    /// A cached output's seek: within the output it moves only where the
    /// writer believes it is; past the end it ends the account ([`Held`]).
    pub(super) fn seek_cached(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        let Some(held) = self.held.as_mut() else {
            return self.file.seek(to);
        };
        let target = match to {
            SeekFrom::Start(at) => Some(at),
            SeekFrom::End(delta) => held.len.checked_add_signed(delta),
            SeekFrom::Current(delta) => held.pos.checked_add_signed(delta),
        };
        if let Some(at) = target {
            if at <= held.len {
                held.pos = at;
                return Ok(at);
            }
        }
        let pos = held.pos;
        self.make_held()?;
        self.held = None;
        self.file.seek(SeekFrom::Start(pos))?;
        self.file.seek(to)
    }

    /// Leaves direct writing: everything staged goes to a cached handle
    /// positioned after it, which becomes the output's file.
    pub(super) fn fall_back(&mut self) -> std::io::Result<()> {
        if let Some(mut direct) = self.direct.take() {
            direct.staged.fall_back(&mut self.file, Fell::Failed)?;
        }
        Ok(())
    }

    /// A correction of `bytes` at `at`, short of the end, on a direct
    /// output: into the staging block where they are still staged, and by
    /// an aligned read-modify-write of each sector already on disk.
    pub(super) fn correct(&mut self, at: u64, bytes: &[u8]) -> std::io::Result<()> {
        // Every block in flight lands first: what is below `done` is then
        // on disk, and what is past it still in the block being filled.
        let still = self
            .direct
            .as_mut()
            .expect("a correction on a cached output")
            .staged
            .settle(&mut self.file)?;
        if !still {
            self.direct = None;
            return Err(std::io::Error::other("the output fell back"));
        }
        let direct = self
            .direct
            .as_mut()
            .expect("a correction on a cached output");
        // Whatever the read window holds may be what is corrected.
        direct.bounce_len = 0;
        let staged_from = direct.staged.done;
        for (offset, byte) in (at..).zip(bytes) {
            if offset >= staged_from {
                let into = direct.staged.at + (offset - staged_from) as usize;
                direct.staged.store[into] = *byte;
            }
        }
        let mut sector = at / SECTOR as u64 * SECTOR as u64;
        let end = (at + bytes.len() as u64).min(staged_from);
        while sector < end {
            if forced() == Forced::Patch {
                return Err(std::io::Error::other("forced read-back failure"));
            }
            let buf = &mut direct.sector[direct.sector_at..direct.sector_at + SECTOR];
            self.file.seek(SeekFrom::Start(sector))?;
            std::io::Read::read_exact(&mut self.file, buf)?;
            let from = at.max(sector);
            let to = (at + bytes.len() as u64).min(sector + SECTOR as u64);
            let src = (from - at) as usize..(to - at) as usize;
            let dst = (from - sector) as usize..(to - sector) as usize;
            buf[dst].copy_from_slice(&bytes[src]);
            self.file.seek(SeekFrom::Start(sector))?;
            self.file.write_all(buf)?;
            sector += SECTOR as u64;
        }
        self.file.seek(SeekFrom::Start(staged_from))?;
        Ok(())
    }
}

impl Write for Output {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let Some(direct) = self.direct.as_mut() else {
            return self.write_cached(buf);
        };
        if direct.pos == direct.len {
            let direct_still = direct.staged.put(&mut self.file, buf)?;
            direct.len += buf.len() as u64;
            direct.pos = direct.len;
            if !direct_still {
                // `put` fell back: the cached handle already holds every
                // byte, `buf` included, and is positioned at the end.
                let len = direct.len;
                self.direct = None;
                self.held = Held::at(self.holds, len, len, len);
            }
            return Ok(buf.len());
        }
        // Behind the end: a correction. Its tail past the end is refused
        // rather than guessed at; the writer never asks for one.
        let (at, len) = (direct.pos, direct.len);
        let take = buf.len().min((len - at) as usize);
        if take == 0 {
            return Err(std::io::Error::other("a write past the end of an output"));
        }
        if self.correct(at, &buf[..take]).is_err() {
            self.fall_back()?;
            self.file.seek(SeekFrom::Start(at))?;
            self.file.write_all(&buf[..take])?;
            self.file.seek(SeekFrom::Start(len))?;
            self.held = Held::at(self.holds, len, at + take as u64, len);
            return Ok(take);
        }
        if let Some(direct) = self.direct.as_mut() {
            direct.pos += take as u64;
        }
        Ok(take)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // A direct output's staged tail is written by `close`, once: a
        // flush in the middle would have to pad a sector the next append
        // then writes over.
        match self.direct {
            Some(_) => Ok(()),
            None => self.file.flush(),
        }
    }
}

impl std::io::Read for Output {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let Some(direct) = self.direct.as_mut() else {
            return self.read_cached(buf);
        };
        let at = direct.pos;
        let left = direct.len.saturating_sub(at);
        let want = (buf.len() as u64).min(left) as usize;
        if want == 0 {
            return Ok(0);
        }
        let staged_from = direct.staged.done;
        // Still staged: from the block.
        if at >= staged_from {
            let from = direct.staged.at + (at - staged_from) as usize;
            buf[..want].copy_from_slice(&direct.staged.store[from..from + want]);
            direct.pos += want as u64;
            return Ok(want);
        }
        // On disk, once every block in flight has landed (a fall back meanwhile
        // leaves the cached handle to read from, at `at`).
        if !direct.staged.settle(&mut self.file)? {
            let len = direct.len;
            self.direct = None;
            self.file.seek(SeekFrom::Start(at))?;
            let got = self.file.read(buf)?;
            let after = at + got as u64;
            self.held = Held::at(self.holds, len, after, after);
            return Ok(got);
        }
        let direct = self.direct.as_mut().expect("still direct");
        // On disk: from the read window, refilled a block at a time from
        // the sector at or before `at` (every byte below `staged_from` is
        // on disk in whole sectors, `staged_from` itself a sector
        // boundary).
        if direct.bounce.is_empty() {
            direct.bounce = vec![0u8; BLOCK + SECTOR];
        }
        let skew = direct.bounce.as_ptr().align_offset(SECTOR);
        let window_end = direct.bounce_from + direct.bounce_len as u64;
        if at < direct.bounce_from || at >= window_end {
            let first = at / SECTOR as u64 * SECTOR as u64;
            let span = (staged_from - first).min(BLOCK as u64) as usize;
            direct.bounce_len = 0;
            let bounce = &mut direct.bounce[skew..skew + span];
            self.file.seek(SeekFrom::Start(first))?;
            std::io::Read::read_exact(&mut self.file, bounce)?;
            self.file.seek(SeekFrom::Start(staged_from))?;
            direct.bounce_from = first;
            direct.bounce_len = span;
        }
        let offset = (at - direct.bounce_from) as usize;
        let got = (direct.bounce_len - offset).min(want);
        let from = skew + offset;
        buf[..got].copy_from_slice(&direct.bounce[from..from + got]);
        direct.pos += got as u64;
        Ok(got)
    }
}

impl Seek for Output {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        let Some(direct) = self.direct.as_mut() else {
            return self.seek_cached(to);
        };
        let target = match to {
            SeekFrom::Start(at) => Some(at),
            SeekFrom::End(delta) => direct.len.checked_add_signed(delta),
            SeekFrom::Current(delta) => direct.pos.checked_add_signed(delta),
        };
        match target {
            Some(at) if at <= direct.len => {
                direct.pos = at;
                Ok(at)
            }
            _ => Err(std::io::Error::other("a seek outside an output's bytes")),
        }
    }
}

/// Opens `path` for an archive's output past the cache: read and write
/// (a correction reads its sector back), created or truncated, with
/// [`FLAG`] on the open where the target takes it there.
pub(super) fn open_direct(path: &Path) -> std::io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(true);
    #[cfg(unix)]
    if FLAG != 0 {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(FLAG as i32);
    }
    #[cfg(windows)]
    if FLAG != 0 {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(FLAG);
    }
    options.open(path)
}

/// macOS, the `reserve-knob` count arm only: the handle just
/// opened is taken past the unified buffer cache by `fcntl(F_NOCACHE, 1)`;
/// `false` where the call is refused, and the member is then written
/// cached. Every other target answers `true`, its handle having been
/// opened with [`FLAG`]; on macOS without the knob no form ever asks.
#[cfg(all(target_os = "macos", feature = "reserve-knob"))]
#[allow(unsafe_code)]
pub(crate) fn take_direct(file: &File) -> bool {
    use std::os::fd::AsRawFd;
    extern "C" {
        fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    }
    // F_NOCACHE is 48 on every Darwin.
    const F_NOCACHE: i32 = 48;
    // SAFETY: `fcntl` is a plain system call on a descriptor this process
    // holds open for the length of the call (the `&File` borrow), with one
    // integer argument; `F_NOCACHE` reads or writes no memory of ours.
    unsafe { fcntl(file.as_raw_fd(), F_NOCACHE, 1) == 0 }
}

/// See the macOS [`take_direct`].
#[cfg(not(all(target_os = "macos", feature = "reserve-knob")))]
pub(crate) fn take_direct(_file: &File) -> bool {
    true
}
