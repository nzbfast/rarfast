//! A member's bytes: the file opened on its first read and closed at its
//! last, and what is sampled of it on the way.

use super::*;

/// A member's bytes, opened on first read and CLOSED AT ITS LAST.
///
/// The FIRST read of a payload is what tells the report that this member
/// is the one being processed, and that is the only signal that works for
/// every member: `Progress::output` counts the bytes the writer WROTE,
/// which for a compressed member are its packed bytes, and nothing
/// outside the engine knows how many of those a member will take.
///
/// **The descriptor is the member's, not the run's.** Opening lazily
/// bounds nothing on its own, because a source that has been read is
/// still a source that is OPEN, and the writer borrows every one of them
/// until it finishes. A create of 256 files at macOS's default soft
/// limit therefore added and reported every member, then failed at the
/// close with `Too many open files` and left no archive (measured 19 Sep
/// 2026: 252 files exit 0, 256 files exit 2, 4,000 files under
/// `ulimit -Sn 10240` exit 0 again). Releasing the file at EOF makes the
/// creator hold ONE source descriptor at a time whatever the member
/// count, which `a_create_outlasts_a_small_descriptor_budget` pins.
///
/// EOF is a signal this source is guaranteed to see, and seeing it twice
/// is not a risk: the writer reads a payload through exactly once and
/// never rewinds it (`rarkit::Payload::Reader`), and after the declared
/// size it reads ONE more byte to check the payload is not longer than
/// it claimed (spec G 3.7.2). That probe is the last read a source ever
/// gets, so the descriptor goes on it.
///
/// **A small member is read AHEAD** (`ahead`): its bytes are loaded on
/// the pool before the writer asks, and this source serves them, then
/// the end. The report still hears of the member at the writer's first
/// read of it, and of a failed open at the same place, so the progress
/// lines and their order do not change. In a VOLUME SET the writer may
/// read a member before it has reached it, and the report waits for the
/// writer's own word as well (`Report::writer_takes`).
pub(super) struct Source<'a> {
    pub(super) path: PathBuf,
    pub(super) open: Option<std::fs::File>,
    /// The read-ahead that loads this member, and its place there.
    pub(super) ahead: Option<(Ahead, usize)>,
    /// The bytes the read-ahead loaded, and how many have been served.
    pub(super) held: Option<(Vec<u8>, usize)>,
    /// Whether the file has been read to its end and closed, which is
    /// what keeps a reopen from rewinding a payload the writer has
    /// already taken.
    pub(super) spent: bool,
    /// Whether the file is open for the writer's LOOK at it and not yet
    /// for its read (`Seek`): no progress line is open for it, and its
    /// reads are the file's own.
    pub(super) looking: bool,
    /// Which member this is, in `add` order.
    pub(super) member: usize,
    /// Whether this member's place in the page cache is sampled as it is
    /// opened, for an output that holds its corrections by it
    /// ([`says_whether_warm`]).
    pub(super) sampled: bool,
    /// Whether the file is advised as read in order once it is open
    /// ([`advises_input`]): a member this source reads itself.
    pub(super) advised: bool,
    /// The least length at which this member, found COLD as it is opened,
    /// is read through a window ([`windows_cold_input`]); `None` where the
    /// command or the member takes none.
    pub(super) windowed_from: Option<u64>,
    /// The window this member is being read through, once it is open.
    pub(super) window: Option<Windowed>,
    pub(super) report: Hook<'a>,
}

/// Whether a stored create reads a COLD input member through a read window
/// (`crate::window`: one thread filling two slabs of 128 MiB in file order,
/// the kernel asked 256 MiB ahead), and from what length: **ON for macOS**,
/// from [`WINDOWED_FROM`].
///
/// **What it is for.** A big member is read by one reader in order in
/// requests of 2 MiB while another thread writes the archive to the same
/// drive. Counted on an M1 Ultra's own drive with no engine in it (8 GiB,
/// cold, K=3, 10 Oct 2026): the read alone 1.17 s, the write alone 1.29 s
/// on disk, both at once in that shape 2.93 s, and both at once with the
/// read made in slabs of 128 MiB 2.53 s. The drive does not overlap the
/// two, and what it is given in large requests it serves nearer the sum of
/// the two alone. The ladder: slabs of 32 MiB 2.60 s, 64 MiB 2.57, 128 MiB
/// 2.53, 256 MiB 2.59, 512 MiB 2.83; three slabs 2.53, one 2.87; the
/// kernel asked ahead with the reads left at 2 MiB or 16 MiB 2.92 to 2.98
/// (nothing). The extract side met the same drive the same way
/// (`crate::window`), and the constants are its own.
///
/// **What it did, counted** (the same box, plain builds, K=5, on disk,
/// every process read from a fresh copy 0 percent resident; the reference
/// rar beside it): the 8 GiB member 2.872 s to 2.535 (1.13x; rar 3.054), one
/// member of 2.7 GiB 1.035 s to 0.876 (1.18x; rar 1.051), four members of
/// 2 GiB 2.781 s to 2.688 (1.03x; rar 3.083). Warm, every row where it was
/// (a warm member takes no window), and with the window stated off the tip
/// is the base (2.870 s against 2.872).
///
/// **Why the floor.** A window is one member's: at each member's end the
/// reader has nothing to read until the writer has taken the last slabs
/// and opened the next file. Under 2 GiB a member that costs more than the
/// slabs save: eight members of a gibibyte LOST, 2.713 s to 2.896 (0.94),
/// sixteen of 512 MiB 2.625 to 3.291 and sixty-four of 128 MiB 2.633 to
/// 3.305 (0.80, the floor stated lower by the knob). Slabs handed from one
/// member's window to the next were built and counted and changed nothing
/// (the many-member set 2.901 s against 2.894), so it is not the slabs' pages. No
/// member between one and two gibibytes has a row; the floor is the
/// smallest member with a winning one. A window that reads on ACROSS
/// members, as the archive's does, was not built.
///
/// **Where it is not taken.** A member found warm (the sample every such
/// member already has, [`says_whether_warm`]) is read as it was, and so is
/// every member where the command line states one thread, a memory limit,
/// a level that compresses, a password or volumes: none of those has a row
/// ([`command_takes_window`]); and where any memory cap is stated for the
/// process ([`memory_is_capped`]). **What it costs**: the two slabs for as
/// long as such a member is read (peak 17 MiB to 273 MiB), and a copy more
/// (the big member 2.22 CPU s to 2.93; rar 3.23).
pub(super) const WINDOWS_COLD_INPUT: bool = cfg!(all(target_os = "macos", feature = "parallel"));

/// The smallest member read through a window: 2 GiB, the smallest member
/// with a winning row ([`WINDOWS_COLD_INPUT`]).
pub(super) const WINDOWED_FROM: u64 = 2 << 30;

/// The least member length windowed when found cold, or `None` for no
/// window: [`WINDOWS_COLD_INPUT`] and [`WINDOWED_FROM`]; in a `reserve-knob`
/// build what `RARFAST_CREATE_WINDOW_MIB` says (`0` none, else the floor in
/// mebibytes, on any unix), read once.
pub(super) fn windows_cold_input() -> Option<u64> {
    #[cfg(all(not(test), feature = "reserve-knob"))]
    {
        static SAID: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
        let said = SAID.get_or_init(|| {
            std::env::var("RARFAST_CREATE_WINDOW_MIB")
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
        });
        match said {
            Some(0) => return None,
            Some(mib) => return Some(mib.saturating_mul(1 << 20)),
            None => {}
        }
    }
    WINDOWS_COLD_INPUT.then_some(WINDOWED_FROM)
}

/// Whether this command's members may be windowed at all: a plain stored
/// create at the default width. One thread stated, a memory limit stated,
/// a level that compresses, a password and volumes each have no row, and
/// read as they did.
pub(super) fn command_takes_window(opts: &Options) -> bool {
    opts.level == super::super::args::Level::Store
        && opts.shared.password.is_none()
        && opts.volume_size.is_none()
        && opts.memory_cap.is_none()
        && opts.shared.threads != Some(1)
}

/// Whether a memory cap of any kind is stated for this process: a cgroup
/// limit (`rarkit::memory::container_cap`) or a finite soft `RLIMIT_AS`,
/// `RLIMIT_DATA` or `RLIMIT_RSS`. A window's two slabs are held beside
/// everything the memory policy counts, so under ANY such cap, whatever
/// its size, and under a stated `-mm` ([`command_takes_window`]), a member
/// takes no window and the create holds what it held before there was one.
///
/// The limits are read whether or not the system enforces them (macOS
/// enforces none of the three on a map, and has no cgroup): one stated is
/// a user's word about memory, and the window is not worth going against
/// it. Read once a process.
pub(super) fn memory_is_capped() -> bool {
    static CAPPED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CAPPED
        .get_or_init(|| rarkit::memory::container_cap().is_some() || a_resource_limit_is_finite())
}

/// Whether the soft limit on the address space, the data segment or the
/// resident set is finite.
#[cfg(unix)]
#[allow(unsafe_code)]
fn a_resource_limit_is_finite() -> bool {
    [libc::RLIMIT_AS, libc::RLIMIT_DATA, libc::RLIMIT_RSS]
        .into_iter()
        .any(|resource| {
            let mut limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: `limit` is a live, writable `rlimit`, which is all
            // `getrlimit` writes; it reads nothing of ours.
            let ok = unsafe { libc::getrlimit(resource, &mut limit) } == 0;
            ok && limit_is_finite(limit.rlim_cur, libc::RLIM_INFINITY)
        })
}

/// Nowhere else is there such a limit to read.
#[cfg(not(unix))]
fn a_resource_limit_is_finite() -> bool {
    false
}

/// Whether a soft limit states a bound: anything but the system's word for
/// none.
#[cfg_attr(not(any(unix, test)), allow(dead_code))]
pub(super) fn limit_is_finite<T: PartialEq>(soft: T, infinity: T) -> bool {
    soft != infinity
}

/// Bytes the window served from its slabs: a test's proof that it ran.
#[cfg(all(test, unix))]
impl Windowed {
    pub(super) fn served(&self) -> u64 {
        self.window.counts().0
    }
}

/// A member's file read through a window: where the next read stands, and
/// the file's length as it was opened.
pub(super) struct Windowed {
    #[cfg(unix)]
    window: crate::window::Window,
    #[cfg(unix)]
    at: u64,
    #[cfg(unix)]
    len: u64,
}

impl Windowed {
    /// A window over `file` where it is a regular file of `from` bytes or
    /// more; nothing is read and no thread started until its reads have run
    /// on in order (the window's own probation).
    #[cfg(unix)]
    pub(super) fn over(file: &std::fs::File, from: u64) -> Option<Windowed> {
        Windowed::over_with(file, from, crate::window::SLAB, crate::window::AHEAD)
    }

    /// [`Windowed::over`] with the slab and the distance asked ahead stated.
    #[cfg(unix)]
    pub(super) fn over_with(
        file: &std::fs::File,
        from: u64,
        slab: u64,
        ahead: u64,
    ) -> Option<Windowed> {
        let meta = file.metadata().ok()?;
        if !meta.is_file() || meta.len() < from {
            return None;
        }
        let window = crate::window::Window::asking(file, meta.len(), slab, ahead)?;
        Some(Windowed {
            window,
            at: 0,
            len: meta.len(),
        })
    }

    /// Nowhere else: the window's pass-through read is a positional one.
    #[cfg(not(unix))]
    pub(super) fn over(_file: &std::fs::File, _from: u64) -> Option<Windowed> {
        None
    }

    /// The next bytes of the file in order: out of the window where it
    /// holds them, and from the file at the same offset where it does not
    /// (before a run begins, and past the length the file was opened at,
    /// which is where the writer's one byte past the end is answered).
    #[cfg(unix)]
    pub(super) fn read(
        &mut self,
        file: &std::fs::File,
        buffer: &mut [u8],
    ) -> std::io::Result<usize> {
        use std::os::unix::fs::FileExt;
        let inside = usize::try_from(self.len.saturating_sub(self.at))
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let mut read = self.window.read(self.at, &mut buffer[..inside]);
        if read < inside || inside == 0 {
            let upto = if inside == 0 { buffer.len() } else { inside };
            read += file.read_at(&mut buffer[read..upto], self.at + read as u64)?;
        }
        self.at += read as u64;
        Ok(read)
    }

    #[cfg(not(unix))]
    pub(super) fn read(
        &mut self,
        file: &std::fs::File,
        buffer: &mut [u8],
    ) -> std::io::Result<usize> {
        let mut file = file;
        std::io::Read::read(&mut file, buffer)
    }
}

/// Whether a create advises the kernel that each member it reads itself
/// (one over the small-member read-ahead's 1 MiB) is read in order
/// (`engine::advise_file_sequential`): LEVER (a) of the create cold-input
/// work, **ON for Linux**, the one system the advice exists on here
/// (2 Oct 2026, once its hard-disk row showed no loss).
///
/// **What it is for.** A big member is read by ONE reader in order (the
/// writer's read-ahead stage, or the writing thread at `-mt1` and for a
/// compressed member), through the system's default read-ahead. On Linux
/// the advice doubles that window, and priced with a preload shim on the earlier
/// binary (a Zen 4 rental, two KIOXIA NVMe, read-ahead 256 KiB, K=5,
/// wall to the archive on disk) it took a COLD 12.9 GB stored create on
/// ONE device from 5.683 s to 5.114 s (1.111x; a set of eight 3.900 to
/// 3.498, 1.115x; at `-mt1` 1.143x and 1.136x), was level warm (0.998x to
/// 1.001x) and across two devices (1.000x, 1.002x: the write binds there),
/// level under `-hp` (1.002x: the cipher binds) and 1.029x on one 4 GiB
/// member at `-m3`; no CPU (1 Oct 2026).
/// In a knob build after that: 1.114x and 1.122x on the same two rows, a
/// volume set 1.134x, 300 stored members of 8 MiB 1.202x, 1.01x to 1.06x
/// behind an encoder. On a SATA SSD it read level inside that drive's own
/// two modes. On twelve hard disks in one RAID 6 (a NAS, btrfs, K=5) it
/// WON: the cold big member 21.10 s to 19.57 s (1.08x), a set of many
/// members 15.58 to 14.63
/// (1.07x). No row sat lost. ONE spinning disk alone has no row yet.
///
/// A member of at most 1 MiB is read whole by the read-ahead's loaders and
/// is never advised, so the small-file walk makes no call more.
pub(super) const ADVISES_INPUT: bool = cfg!(target_os = "linux");

/// [`ADVISES_INPUT`]; in a `reserve-knob` build what `RARFAST_CREATE_ADVISE`
/// says (`1` advise, `0` not), read once.
pub(super) fn advises_input() -> bool {
    #[cfg(all(not(test), feature = "reserve-knob"))]
    {
        static SAID: std::sync::OnceLock<Option<bool>> = std::sync::OnceLock::new();
        let said = SAID.get_or_init(|| {
            match std::env::var("RARFAST_CREATE_ADVISE")
                .as_deref()
                .map(str::trim)
            {
                Ok("1") => Some(true),
                Ok("0") => Some(false),
                _ => None,
            }
        });
        if let Some(said) = said {
            return *said;
        }
    }
    ADVISES_INPUT
}

/// The smallest member whose residency is sampled as it is opened whatever
/// came before it: the wide read's floor on the extract side, and far above
/// the small members, whose opens are counted one by one (a sample is an
/// open, a map and sixteen `mincore` calls). A smaller member is sampled
/// only by the bytes since the last sample, and only from [`SMALL_FROM`]
/// ([`SAMPLES_SMALL`], [`sampled_members`]); between two samples an output
/// keeps the form the last one chose.
pub(super) const SAMPLED_FROM: u64 = 16 << 20;

/// Whether members UNDER [`SAMPLED_FROM`] and of [`SMALL_FROM`] or more are
/// sampled too, by the bytes that have passed since the last sample
/// ([`sampled_members`]): ON. It decides something only where a create
/// samples at all (`unbuffered::samples_input`: macOS), and
/// `RARFAST_SAMPLE_SMALL` states it in a `reserve-knob` build.
///
/// **Why.** With the floor alone, an archive none of whose members reaches
/// 16 MiB was never sampled, so on macOS its output kept the form that
/// makes every header correction at once, whatever its input's residency.
/// Measured warm, stored, on disk, 512 members of 8 MiB (4 GiB): an M5
/// laptop 2.13 s with the floor alone against 0.695 s sampled (3.06x; 15.3
/// G instructions against 4.6 G; the reference rar 2.20 s), an M1 Ultra
/// 1.448 s against 0.939 s (1.54x; rar 1.85 s); held, 64, 128 and 256 such
/// members gain 1.24x to 1.38x on the M5 laptop and 1.31x to 1.55x on the M1
/// Ultra. From cold sources the two are one path
/// (2 Oct 2026).
///
/// **What a sample costs**: about 0.4 M instructions, the kernel's among
/// them, so at most that for each 16 MiB of input.
pub(super) const SAMPLES_SMALL: bool = true;

/// [`SAMPLES_SMALL`]; in a `reserve-knob` build what `RARFAST_SAMPLE_SMALL`
/// says (`1` sample them, `0` not), read once.
pub(super) fn samples_small() -> bool {
    #[cfg(all(not(test), feature = "reserve-knob"))]
    {
        static SAID: std::sync::OnceLock<Option<bool>> = std::sync::OnceLock::new();
        let said = SAID.get_or_init(|| {
            match std::env::var("RARFAST_SAMPLE_SMALL")
                .as_deref()
                .map(str::trim)
            {
                Ok("1") => Some(true),
                Ok("0") => Some(false),
                _ => None,
            }
        });
        if let Some(said) = said {
            return *said;
        }
    }
    SAMPLES_SMALL
}

/// The smallest member that [`SAMPLES_SMALL`] samples: 8 MiB.
///
/// **Why a floor under the floor.** A correction made at once costs where
/// it lies far behind the output's end, and the kernel's edge is at a
/// member of 8 MiB: counted on an M5 laptop over about 4 GiB of equal
/// members, warm, the form that holds nothing took 0.683 s and 0.700 s at 5
/// and 6 MiB members (the drive's own figure; holding them is level), 0.838
/// s at 7 MiB (held 1.13x), and 2.06 to 2.21 s at 8, 9, 10 and 12 MiB (held
/// 2.4x to 3.1x). Under it holding is not free either: 2,048 members of 2
/// MiB held read 0.68x on that laptop and 0.73x on an M1 Ultra (the list
/// passes its bound and is written early), and 256 members of 4 MiB ahead
/// of a big member 0.95x on the M1 Ultra. So a member under 8 MiB is never
/// sampled by this rule and never counts toward a sample: an archive of
/// such members is written as it always was.
pub(super) const SMALL_FROM: u64 = 8 << 20;

/// Which members' residency is sampled as each is opened, from the member
/// list alone: `members` gives each member's size and whether the writer
/// reads it from its file itself (not a directory, and not loaded by the
/// read-ahead).
///
/// A member of [`SAMPLED_FROM`] and more is sampled, as it always was. With
/// `small`, a member of [`SMALL_FROM`] and more that the writer reads is
/// sampled too: the FIRST such member, and then each one at which the bytes
/// of such members since the last sample, its own among them, reach
/// [`SAMPLED_FROM`]. So after the first there is never more than one sample
/// for each 16 MiB of input, which is the bound the large members already
/// keep. A member under [`SMALL_FROM`] is never sampled and counts for
/// nothing, and where the members of [`SMALL_FROM`] and more come to under
/// [`SAMPLED_FROM`] in all, nothing is sampled: one small file is added as
/// it always was. The members between two samples keep the form the last
/// sample chose.
///
/// **Why the first.** The output holds a correction only once a sample has
/// said warm, and one correction made at once far behind the end, early in
/// the output, costs the whole archive what holding saves: counted on an M5
/// Max laptop over 1.5 GiB of equal members, warm, with the first member's
/// correction made at once, 2.21 to 2.24 G instructions at 9, 10, 12 and
/// 15 MiB members (what holding nothing costs: 2.17 to 2.21 G) against
/// 1.72 to 1.76 G held from the first (an 8 MiB first member did not show
/// it: 1.83 to 1.86 G against 1.79 G).
pub(super) fn sampled_members(
    members: impl Iterator<Item = (u64, bool)>,
    small: bool,
) -> Vec<bool> {
    let members: Vec<(u64, bool)> = members.collect();
    let counted: u64 = members
        .iter()
        .filter(|&&(size, by_writer)| by_writer && size >= SMALL_FROM)
        .fold(0, |sum, &(size, _)| sum.saturating_add(size));
    let small = small && counted >= SAMPLED_FROM;
    // At the floor already, so the first small member is sampled itself.
    let mut since = SAMPLED_FROM;
    members
        .into_iter()
        .map(|(size, by_writer)| {
            if size >= SAMPLED_FROM {
                since = 0;
                return by_writer;
            }
            if !small || !by_writer || size < SMALL_FROM {
                return false;
            }
            since = since.saturating_add(size);
            if since < SAMPLED_FROM {
                return false;
            }
            since = 0;
            true
        })
        .collect()
}

/// Tells the output whether the member at `path`, about to be read, is in
/// the page cache (`unbuffered::input_is_warm`): warm when at least half
/// of `residency`'s sample is resident, cold when less, and cold too where
/// the kernel will not say, which is the form every create took before.
pub(super) fn says_whether_warm(path: &Path) -> bool {
    let (_, verdict) = crate::residency::of(path);
    let warm = warm(verdict);
    crate::unbuffered::input_is_warm(warm);
    warm
}

/// Whether a sampled member counts as warm: only when the sample says so.
pub(super) fn warm(verdict: crate::residency::Residency) -> bool {
    verdict == crate::residency::Residency::Resident
}

impl Source<'_> {
    /// Tells the report this member is the one being written: its first
    /// read, which is where the writer takes it up.
    pub(super) fn starts(&self) {
        if let Ok(mut report) = self.report.lock() {
            report.source_starts(self.member);
        }
    }
}

/// The writer's LOOK at a member before it reads it (spec G 3.8.3: the
/// store rule's samples, read across a member that can seek): a seek
/// opens the file QUIETLY, the reads that follow are the file's own, and
/// the seek back to the start closes it again. So the report hears
/// nothing of the member until its first real read, a failed open is
/// still named where that read is, and one source descriptor is held at
/// a time as before. A member that was read ahead, is being read or has
/// been read through cannot be looked at, and neither can anything that
/// is not a regular file: the seek fails, and the writer judges such a
/// member from its head as it reads it.
impl std::io::Seek for Source<'_> {
    fn seek(&mut self, to: std::io::SeekFrom) -> std::io::Result<u64> {
        let refused = || std::io::Error::from(std::io::ErrorKind::Unsupported);
        if self.spent || self.ahead.is_some() || self.held.is_some() {
            return Err(refused());
        }
        if self.open.is_some() && !self.looking {
            return Err(refused());
        }
        if self.open.is_none() {
            if to == std::io::SeekFrom::Current(0) {
                // Where it stands, which needs no file: at its start.
                return Ok(0);
            }
            let file = std::fs::File::open(&self.path)?;
            if !file.metadata()?.is_file() {
                return Err(refused());
            }
            self.open = Some(file);
            self.looking = true;
        }
        let at = match self.open.as_mut() {
            Some(file) => file.seek(to)?,
            None => 0,
        };
        if at == 0 {
            // Back at the start: the look is over.
            self.open = None;
            self.looking = false;
        }
        Ok(at)
    }
}

impl std::io::Read for Source<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.looking {
            return match self.open.as_mut() {
                Some(file) => std::io::Read::read(file, buffer),
                None => Ok(0),
            };
        }
        // A zero length buffer reads zero bytes from anything and says
        // nothing about the file's end, so it must not close one.
        if self.spent || buffer.is_empty() {
            return Ok(0);
        }
        if let Some((ahead, place)) = self.ahead.take() {
            match ahead.take(place) {
                Loaded::Bytes(bytes) => {
                    self.held = Some((bytes, 0));
                    self.starts();
                }
                Loaded::OpenFailed(err) => {
                    // As a failed open below: named here, no line opened.
                    if let Ok(mut report) = self.report.lock() {
                        report.source_cannot_open(self.member, &err);
                    }
                    return Err(err);
                }
                Loaded::ReadFailed(err) => {
                    self.starts();
                    self.spent = true;
                    return Err(err);
                }
            }
        }
        if let Some((bytes, served)) = &mut self.held {
            let count = buffer.len().min(bytes.len() - *served);
            buffer[..count].copy_from_slice(&bytes[*served..*served + count]);
            *served += count;
            if count == 0 {
                self.spent = true;
                self.held = None;
            }
            return Ok(count);
        }
        if self.open.is_none() {
            // Before the first byte is read: reading makes it resident.
            let cold = self.sampled && !says_whether_warm(&self.path);
            match std::fs::File::open(&self.path) {
                Ok(file) => {
                    if self.advised {
                        crate::engine::advise_file_sequential(&file);
                    }
                    if let (true, Some(from)) = (cold, self.windowed_from) {
                        self.window = Windowed::over(&file, from);
                    }
                    self.open = Some(file);
                    self.starts();
                }
                Err(err) => {
                    // The member is named HERE, where the failure is, and
                    // no line is opened for it: the report never hears
                    // that this member started, so nothing claims it went
                    // in. Before this the whole run died at the close with
                    // `Permission denied` and no name attached, and the
                    // member had already been filled in as `OK`.
                    if let Ok(mut report) = self.report.lock() {
                        report.source_cannot_open(self.member, &err);
                    }
                    return Err(err);
                }
            }
        }
        // `as_mut` cannot fail: the line above filled it or returned.
        let read = match (self.open.as_mut(), self.window.as_mut()) {
            (Some(file), Some(window)) => window.read(file, buffer)?,
            (Some(file), None) => std::io::Read::read(file, buffer)?,
            (None, _) => 0,
        };
        if read == 0 {
            self.spent = true;
            self.window = None;
            self.open = None;
        }
        Ok(read)
    }
}
