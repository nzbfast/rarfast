//! Which route an extract takes: the pool or the walk, the stored routes,
//! the lone large member and the cold window.

use super::*;

/// Which split members this command sends through the engine's pool as
/// split jobs, beyond a stored clear one: the engine's runtime knob
/// `RARKIT_SPLIT_JOBS` read here too, so one binary carries every arm.
/// `(compressed, compressed written, encrypted stored)`: at the default
/// (`compressed`) a compressed member for `t`, `x` and `e`; `verified` a
/// compressed member for `t` only, which is the arrangement before the
/// written one was taken; `all` an encrypted stored one as well; `stored`
/// none.
#[cfg(feature = "parallel")]
pub(super) fn split_jobs_beyond_stored() -> (bool, bool, bool) {
    static MODE: std::sync::OnceLock<(bool, bool, bool)> = std::sync::OnceLock::new();
    *MODE.get_or_init(|| {
        match crate::knob::reader_var("RARKIT_SPLIT_JOBS")
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("stored") => (false, false, false),
            Some("verified") => (true, false, false),
            Some("all") => (true, true, true),
            _ => (true, true, false),
        }
    })
}

/// What `RARFAST_POOL` asks of the route ([`Run::takes_pool`]).
#[cfg(feature = "parallel")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum PoolKnob {
    /// `0` (or `off`): `t`, `x` and `e` never take the engine's member
    /// pool, so every archive takes the sequential entry at the full
    /// width, as `p` and a split set do.
    Never,
    /// `1` (or `on`): the pool wherever the route before 1 Oct 2026 took
    /// it, the stored rule below switched off.
    Always,
    /// Anything else, or nothing: the shipped choice.
    Rule,
}

/// `RARFAST_POOL`, read once: a RUNTIME knob, so one binary prices the
/// pool against the walk on any archive.
#[cfg(feature = "parallel")]
pub(super) fn pool_knob() -> PoolKnob {
    static KNOB: std::sync::OnceLock<PoolKnob> = std::sync::OnceLock::new();
    *KNOB.get_or_init(|| {
        match crate::knob::reader_var("RARFAST_POOL")
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("0" | "off") => PoolKnob::Never,
            Some("1" | "on") => PoolKnob::Always,
            _ => PoolKnob::Rule,
        }
    })
}

/// Whether an archive of STORED members, clear or encrypted, that is being
/// WRITTEN takes the walk and not the pool ([`Run::stored_written`]): on
/// macOS only, each system on its own rows.
///
/// Linux keeps the pool: there it writes eight outputs past the cache at
/// once and extracted the same set of many members cold in 5.49 s against the walk's
/// 7.69 s (a Zen 4 rental, Ryzen 7 7700, held for the run, 1 Oct 2026). Windows
/// keeps the route before until its own rows are in.
#[cfg(feature = "parallel")]
pub(super) const STORED_WRITTEN_WALKS: bool = cfg!(target_os = "macos");

/// Whether the engine's cut of a stored member is switched off
/// (`RARKIT_STORED_CUT` of `0` or `off`, the engine's own knob, read here
/// too so that one word restores the route this rule replaced).
#[cfg(feature = "parallel")]
pub(super) fn stored_cut_off() -> bool {
    static OFF: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *OFF.get_or_init(|| {
        crate::knob::reader_var("RARKIT_STORED_CUT")
            .is_ok_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "off"))
    })
}

/// [`Run::stored_written`] over the selected members' facts: `(is a
/// directory, method, split)`: every file stored, and either none split
/// or a SPLIT SET, [`SPLIT_SET_MEMBERS`] or more split, where
/// `split_set` says this part walks a split set ([`split_set_takes_pool_on`]).
#[cfg(feature = "parallel")]
pub(super) fn all_stored_written(
    extract: bool,
    split_set: bool,
    members: impl Iterator<Item = (bool, u8, bool)>,
) -> bool {
    if !extract {
        return false;
    }
    let (mut files, mut split_files) = (0usize, 0usize);
    for (is_dir, method, split) in members {
        if is_dir {
            continue;
        }
        if method != 0 {
            return false;
        }
        files += 1;
        split_files += usize::from(split);
    }
    files > 0 && (split_files == 0 || (split_set && split_files >= SPLIT_SET_MEMBERS))
}

/// How many selected stored members must be SPLIT across volumes before a
/// set with split members takes the stored route ([`all_stored_written`]):
/// two, a split set. One split member (a big member in volumes, alone
/// or beside its note) keeps the route before: the pool, where a member
/// alone is cut.
///
/// **What it is for (21 Oct 2026).** A stored split set went to
/// the pool, one member a worker, all at once: ten members of 2 GiB in
/// 100 MiB volumes were ten readers in 128 KiB requests on ten cold
/// files. The released build read it on a base M5 MacBook Air (4
/// performance and 6 efficiency cores, 16 GiB, so the 20 GiB set is never
/// all in memory) in 11.0 s against unrar's 10.1 s. On an M5 Max (18
/// cores; K=5, INDICATIVE at a load of 2 to 10) the walk read the same set
/// cold, from copies proven out of the cache, in 3.98 and 3.89 s against
/// the pool's 4.71 and 5.35 (unrar 5.75 and 5.87), and warm in 1.59 against
/// 1.65 on half the CPU (0.30 + 2.12 s against 0.62 + 5.11). The big
/// member alone read cold 4 percent slower by the walk (0.728 s against 0.698),
/// so it keeps the pool.
#[cfg(feature = "parallel")]
pub(super) const SPLIT_SET_MEMBERS: usize = 2;

/// The fewest cores of a Mac's TOP performance level
/// (`hw.perflevel0.physicalcpu`) at which a split set keeps the
/// pool rather than the stored route ([`split_set_takes_pool_on`]).
///
/// **Why the top level, and why 8 (22 Oct 2026).** The stored route won
/// the split set on the base M5 MacBook Air (its shipped pair: 7.49 s cold
/// after a large write against the released 10.96 and unrar's 10.95) and
/// on an M5 Max (0.777 of the pool cold), but gave back 1.5 percent cold
/// on an M1 Ultra, where sixteen fast cores keep ten readers fed. The
/// count of every level not named Efficiency cannot tell these apart (the
/// M5 Max reads 18, the M1 Ultra 16: the M5 generation names its levels
/// Super and Performance, with no Efficiency level on the Max); the top
/// level alone can: Super 4 on the base M5 MacBook Air, Super 6 on the M5
/// Max, Performance 16 on the M1 Ultra. Those three are the MEASURED
/// parts. Every other part (the Pro, Max and Ultra of M2 to M4, the M5
/// Pro) is UNMEASURED: its side of 8 is a reading of the rule, not a
/// count.
#[cfg(feature = "parallel")]
pub(super) const SPLIT_SET_POOL_FROM_TOP_CORES: usize = 8;

/// Whether a split set keeps the pool on a part whose top
/// performance level has `top_cores` cores: at
/// [`SPLIT_SET_POOL_FROM_TOP_CORES`] or more. `None` (the level cannot be
/// read, or not macOS) keeps the stored route, as before the rule.
#[cfg(feature = "parallel")]
pub(super) fn split_set_takes_pool_on(top_cores: Option<usize>) -> bool {
    top_cores.is_some_and(|cores| cores >= SPLIT_SET_POOL_FROM_TOP_CORES)
}

/// The top performance level's physical cores of the part this runs on
/// (`hw.perflevel0.physicalcpu`), read once; `None` where it cannot be
/// read.
#[cfg(all(feature = "parallel", target_os = "macos"))]
pub(super) fn top_level_cores() -> Option<usize> {
    static TOP: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    *TOP.get_or_init(|| sysctl_count(c"hw.perflevel0.physicalcpu"))
}

/// Off macOS no part is asked: the stored route is macOS's alone
/// ([`STORED_WRITTEN_WALKS`]).
#[cfg(all(feature = "parallel", not(target_os = "macos")))]
pub(super) fn top_level_cores() -> Option<usize> {
    None
}

/// One positive integer `sysctl` by name, `None` where it cannot be read.
#[cfg(all(feature = "parallel", target_os = "macos"))]
#[allow(unsafe_code)]
fn sysctl_count(name: &std::ffi::CStr) -> Option<usize> {
    let mut value: libc::c_int = 0;
    let mut size = std::mem::size_of::<libc::c_int>();
    // SAFETY: the name is NUL terminated, `value` is a live `c_int` and
    // `size` names its size, so the call writes at most that many bytes;
    // no new value is set.
    let ok = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            (&raw mut value).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    (ok == 0 && value > 0)
        .then(|| usize::try_from(value).ok())
        .flatten()
}

/// What [`Run::stored_route`] knows of a run before it asks the cache.
#[cfg(feature = "parallel")]
pub(super) struct StoredAsk {
    /// The rule applies here at all: this system walks stored archives,
    /// and this is `x` or `e` of members all stored, none split or a
    /// split set ([`all_stored_written`]).
    pub(super) stored: bool,
    /// No selected member is encrypted.
    pub(super) clear: bool,
    /// Some volume of the set is solid.
    pub(super) solid: bool,
    /// The engine's cut is switched off ([`stored_cut_off`]).
    pub(super) cut_off: bool,
    pub(super) knob: PoolKnob,
}

/// [`Run::stored_route`]'s answer: whether the archive takes the walk,
/// whether the walk reads deep, and whether the archive is one cold
/// stream. `sample` asks the page cache of the first volume, `None` where
/// the run has no volume name, and is called only where the rule needs
/// the answer.
///
/// **One cold stream** is a cold archive that is not solid, the pool not
/// forced, its members clear OR ENCRYPTED: what the source's window is for
/// ([`cold_window_of`]). **Deep** is the same archive with every member
/// clear, the only one whose read-ahead grows where there is no window: an
/// encrypted member is not the seam's, so the seam's depth buys it
/// nothing, but the bytes it is cut from come off the same cold file in
/// the same order as a clear member's, and the window serves both.
#[cfg(feature = "parallel")]
pub(super) fn stored_route_for(
    ask: &StoredAsk,
    sample: impl FnOnce() -> Option<(Option<f64>, crate::residency::Residency)>,
) -> (bool, bool, bool) {
    if !ask.stored {
        return (false, false, false);
    }
    // The engine's cut switched off (`RARKIT_STORED_CUT=0`) is the
    // arrangement before it, route and all: a clear archive walks at the
    // shipped depth whatever the cache holds, an encrypted one takes the
    // pool, and the cache is not asked.
    if ask.cut_off {
        return (ask.clear, false, false);
    }
    let Some(residency) = sample() else {
        return (true, false, false);
    };
    let stream = !ask.solid && ask.knob != PoolKnob::Always;
    let (walks, cold) = stored_route_of(residency, stream);
    (walks, cold && ask.clear, cold)
}

/// Whether a command the pool could take does take it ([`Run::takes_pool`]):
/// the knob first, then the stored route.
#[cfg(feature = "parallel")]
pub(super) fn takes_pool_of(knob: PoolKnob, stored_walks: bool) -> bool {
    match knob {
        PoolKnob::Never => false,
        PoolKnob::Always => true,
        PoolKnob::Rule => !stored_walks,
    }
}

/// The least size of the ONE large member of a set in SMALL VOLUMES that
/// [`lone_large_stored`] takes: 96 MiB on Linux and macOS, a gibibyte on
/// Windows, each system on its own rows.
///
/// **Linux: where the sign changes.** One member beside a sample of a
/// tenth of it, an `.nfo` and an `.srt`, in 15 MB volumes, the pool's time
/// over the walk's (a Zen 4 rental, K=5, on disk, 2 Oct 2026):
/// 24 MiB 0.91 cold and 0.89 warm, 48 MiB 0.96
/// and 1.00, 96 MiB 1.17 and 1.03, 192 MiB 1.25 and 1.06, 300 MiB 1.28 and
/// 1.06, 700 MiB 1.37 and 1.09, 4 GiB 1.38 and 1.15. A member of a
/// many-member set is 300 MiB to a gibibyte.
///
/// **Windows: a gibibyte**, the size from which the seam reads a member a
/// whole slab at a time. Under it the seam reads in the pool worker's own
/// 128 KiB requests and Windows writes a pool worker's member from a
/// second thread already, so the walk has nothing to add: a member of
/// 350 MiB and of 700 MiB in 15 MiB volumes read level by both routes cold
/// (0.99x and 0.98x, K=7, a Windows desktop), already 1.36x and 1.24x ahead of UnRAR.
///
/// **macOS: as Linux.** The same member shapes on an M1 Ultra (20
/// cores, K=5, the walk with the seam stated against the pool;
/// the cold rows at a load of 7 to 9, so indicative): 300 MiB 1.12x cold
/// and 1.07x warm, 700 MiB 1.10x and 1.09x, 1.1 GiB 1.05x and 1.38x, 96 MiB
/// 1.05x and 1.02x.
#[cfg(feature = "parallel")]
pub(super) const LONE_LARGE_SMALL_FLOOR: u64 = if cfg!(windows) { 1 << 30 } else { 96 << 20 };

/// The size from which the walk's seam takes a clear stored member under
/// a CRC32 on its size alone (rarkit's `read::seam`, its `LENT_FLOOR`,
/// mirrored): 32 MiB, and on Windows a gibibyte, which has no row of its
/// own yet. A member of that kind and that size is written by a second
/// thread while the walk reads.
#[cfg(feature = "parallel")]
pub(super) const SEAM_TAKES_FROM: u64 = if cfg!(windows) { 1 << 30 } else { 32 << 20 };

/// The size from which the walk's seam takes EVERY stored member on its
/// size alone, one under BLAKE2sp too: a gibibyte. A large member under
/// it may not be the seam's by its size, so there the walk states the file
/// cost class, which [`Run::walk`] does for a set [`lone_large_stored`]
/// takes.
#[cfg(feature = "parallel")]
pub(super) const SEAM_TAKES_ANY_FROM: u64 = 1 << 30;
#[cfg(feature = "parallel")]
const _: () = assert!(SEAM_TAKES_FROM <= SEAM_TAKES_ANY_FROM);

/// How many times the bytes of every OTHER selected file the large one
/// must hold ([`lone_large_stored`]): 4, so the rest is a quarter of it at
/// most. The walk extracts the rest one at a time, where the pool hid it
/// behind the large member. A 700 MiB member in 15 MB volumes beside a
/// sample of a quarter of it: the walk 1.20x cold and 1.03x warm; of a
/// half 1.10x and 0.97x; of its own size 0.87x and 0.90x (a 4 GiB member
/// beside a quarter: 1.25x and 1.10x).
#[cfg(feature = "parallel")]
pub(super) const LONE_LARGE_SHARE: u64 = 4;

/// Whether [`lone_large_stored`] takes a large member under BLAKE2sp
/// (`-htb`): on Linux alone, each system on its own rows.
///
/// In 15 MB volumes the walk is 1.15x the pool cold and warm on Linux
/// (a Zen 4 rental, K=3); on Windows it is 0.68x cold and 0.89x warm (a desktop,
/// K=5), where the pool's writer hashes a member as it writes it. macOS has
/// no row and keeps the pool.
#[cfg(feature = "parallel")]
pub(super) const LONE_LARGE_BLAKE2SP: bool = cfg!(target_os = "linux");

/// [`LONE_LARGE_SMALL_FLOOR`]. A count-only knob (feature
/// `read-depth-knob`, never shipped): `RARFAST_LONE_LARGE_KIB` states it,
/// for `tests/lone_large_route.rs`, whose archives are small.
#[cfg(feature = "parallel")]
pub(super) fn lone_large_floor() -> u64 {
    #[cfg(feature = "read-depth-knob")]
    if let Some(kib) = std::env::var("RARFAST_LONE_LARGE_KIB")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|kib| (1..=(1 << 30)).contains(kib))
    {
        return kib << 10;
    }
    LONE_LARGE_SMALL_FLOOR
}

/// What [`lone_large_stored`] is told of the command and the set.
#[cfg(feature = "parallel")]
#[derive(Clone, Copy)]
pub(super) struct LoneAsk {
    /// `x` or `e`.
    pub(super) extract: bool,
    /// The set is in SMALL VOLUMES: several, none larger than the wide
    /// read's floor ([`WIDE_READ_FLOOR`]), so no fragment of a member is
    /// one a pool worker reads wide.
    pub(super) small_volumes: bool,
    /// A large member under BLAKE2sp is taken ([`LONE_LARGE_BLAKE2SP`]).
    pub(super) blake2sp: bool,
    /// The least size of the large member ([`lone_large_floor`]).
    pub(super) floor: u64,
}

/// Whether `x` or `e` of these selected members is of ONE LARGE STORED
/// MEMBER BESIDE SMALL ONES, IN SMALL VOLUMES ([`Run::lone_large`]), and
/// if so that member's size: by each member's facts, `(is a directory,
/// method, encrypted, has a CRC32, size)`, and by the set's volumes, all
/// read from the archive's own headers and files. The set is in small
/// volumes; the largest file is stored, clear and at least `floor` bytes
/// ([`LONE_LARGE_SMALL_FLOOR`]); its checksum is a CRC32 (or the system
/// takes BLAKE2sp, [`LONE_LARGE_BLAKE2SP`]); there is another file beside
/// it; and everything else together is no more than a
/// [`LONE_LARGE_SHARE`]th of it.
///
/// **Such a set takes the walk, on every system.** It is the commonest
/// release there is: a big member beside its sample, its `.nfo`
/// and its subtitles, posted in volumes of 15 MB. Its files are several,
/// so the dialect asked the engine for the member pool, and the pool has
/// nothing to run abreast: one worker takes the large member, and a
/// fragment under the wide read's floor (16 MiB) is read in order by that
/// worker in requests of 128 KiB (the engine's `STORED_REQUEST`, sized for
/// members that share the cache), volume after volume. Walked, the same
/// member is the seam's: read deep by one thread, written by another
/// ([`SEAM_TAKES_ANY_FROM`] says how a member under a gibibyte gets there).
///
/// Counted on Windows (a desktop, Ryzen 7 9800X3D, a WD SN8100, cold, the
/// kernel's own file trace, 2 Oct 2026):
/// a 12.9 GB member in 824 volumes of 15 MB through the pool is ONE
/// reader making 98,276 reads of 128 KiB through the cache, inside those
/// reads 7.64 s of an 8.79 s wall, where UnRAR 7.23 reads 4 MiB at a time
/// and is inside its reads 1.9 s of 5.5. Timed, on disk, the walk over the
/// pool on 15 MB volumes: Windows 1.54x cold and 1.15x warm (UnRAR behind
/// the walk 1.36x cold); Linux 1.45x cold and 1.20x warm on 8 cores and
/// 1.65x warm on 96 threads; macOS 1.06x cold and 1.61x warm (an M1
/// Ultra).
///
/// **Small volumes only.** Where a volume is over the wide read's floor,
/// or the set is one archive, the pool's worker reads the large member's
/// ranges wide and the two routes are near level: on Windows the walk is
/// behind (one archive 0.89x cold and 0.91x warm, 100 MB volumes 0.93x
/// cold, 50 MB volumes behind), on macOS 0.97x cold and 1.09x warm at 50
/// MiB, on Linux 0.98x to 1.06x by the row. Such a set keeps the route it
/// had.
///
/// **Where else it stops.** Two large members or more keep the pool, which
/// runs them abreast (eight of them warm on 96 threads: the walk 0.23x);
/// so does a set of many members, in one archive or in volumes (0.87x to 0.94x). A
/// compressed or an encrypted large member keeps the route it had: its
/// decode or its cipher is the pool's to spread. `t` and `p` write no file
/// and are not asked. A stated `-mt1` walks already, and `RARFAST_POOL`
/// wins over the rule either way.
#[cfg(feature = "parallel")]
pub(super) fn lone_large_stored(
    ask: LoneAsk,
    members: impl Iterator<Item = (bool, u8, bool, bool, u64)>,
) -> Option<u64> {
    if !ask.extract || !ask.small_volumes {
        return None;
    }
    // The largest file, as (size, stored and clear, has a CRC32), and
    // every file's sum.
    let (mut largest, mut total, mut files) = ((0u64, false, false), 0u128, 0usize);
    for (is_dir, method, encrypted, crc32, size) in members {
        if is_dir {
            continue;
        }
        files += 1;
        total += u128::from(size);
        if size > largest.0 {
            largest = (size, method == 0 && !encrypted, crc32);
        }
    }
    let (size, plain, crc32) = largest;
    let rest = total - u128::from(size);
    let taken = files > 1
        && plain
        && size >= ask.floor
        && (crc32 || ask.blake2sp)
        && rest * u128::from(LONE_LARGE_SHARE) <= u128::from(size);
    taken.then_some(size)
}

/// Whether `x` and `e` read ONE STORED MEMBER ALONE, IN MEMORY, wide
/// ([`lone_wide_stored`]) when nothing says otherwise: on macOS, Windows
/// and Linux, each on its own rows ([`lone_wide_ships_on`]).
///
/// **What it is for (release blocker 4).** Such a member is a breadth of
/// one, so it is read by the plain walk whatever the route, and there it
/// was SERIAL: under the seam's floor (32 MiB, the engine's `LENT_FLOOR`)
/// one thread read, checked and wrote it 128 KiB at a time, and above it
/// one reader fed one writer 4 MiB at a time with the writer waiting on
/// it. Counted on an M1 Ultra against the old engine (the stored
/// extraction count, 18 Oct 2026): `x` of a 16 MiB member 0.853 and of a
/// 64 MiB one 0.869, `e` alike, on less CPU than the old engine's; the
/// write was 1.90 ms of the 16 MiB member's 3.76 on its one thread and
/// the read and the check 1.61 beside it, and at 64 MiB the writer
/// spent 3.0 ms between its writes waiting. `t` of the same member reads
/// it wide and was ahead.
///
/// **The form.** The engine's wide read (its `read::wide`) reads the
/// member's pieces on several threads, each piece checked where it was
/// read, and the walking thread writes them in piece order: the read and
/// the check go behind the write, and the writer never waits on one
/// reader. The writer sees the same calls in the same order as it did
/// from the serial loop (the engine's own promise for a written member of
/// that read). It is what `p` to a stream already takes, so the run
/// states that cost class (`ReadOptions::sink_is_file` of `Some(false)`)
/// for this member alone: the field is a cost class the engine never
/// verifies, and on it no byte, no verdict and no order of writes moves.
/// One APFS file takes no faster writes from more threads (an M5 Ultra,
/// 64 MiB in 1 MiB writes: 4.24 ms from one thread, 4.76 from two and
/// 5.10 from four), so one writer fed without a wait is the floor this
/// reaches.
///
/// **In memory only.** A cold archive is read through the source's window
/// in order ([`cold_window_of`]), and wide readers over it lost by far:
/// cold, the 64 MiB member read 15.9 ms by the seam against 26.2 wide and
/// a 512 MiB one 90 ms against 631 (an M5 Ultra, K=7, 18 Oct 2026). So the
/// rule asks the page cache's answer the stored route already took
/// ([`Run::stored_route`]): the whole sample in memory.
///
/// Timed warm on an M5 Ultra (36 cores, K=31 alternating, process wall
/// medians at a load of 4 to 10, so INDICATIVE; 18 Oct 2026), the
/// shipped route against this one: 16 MiB 5.80 ms against 5.01, 32 MiB
/// 7.05 against 6.43, 64 MiB 10.16 against 9.09; 128 MiB 14.70 against
/// 14.13 and 512 MiB 45.09 against 40.94 (K=11, at the shipped depth).
#[cfg(feature = "parallel")]
pub(super) const LONE_WIDE: bool = lone_wide_ships_on(ON_MACOS, cfg!(windows), ON_LINUX);

/// The read-ahead a member [`lone_wide_stored`] takes is read at: 4 MiB,
/// so the wide read's readers are four of 1 MiB (its macOS piece).
///
/// Against the extract's own 8 MiB, which gives eight readers, on the same
/// count: 16 MiB 5.30 ms on 6.37 CPU ms and 13.3 MiB at the peak against
/// 5.01 on 5.10 and 9.2 MiB; 64 MiB 9.45 on 14.86 against 9.09 on 13.15.
/// At 2 MiB (two readers) the 64 MiB member read 10.07: two readers do
/// not keep the writer fed.
#[cfg(feature = "parallel")]
pub(super) const LONE_WIDE_READ_AHEAD: u64 = 4 << 20;

/// The size from which [`lone_wide_stored`] leaves a member to the seam:
/// a gibibyte ([`SEAM_TAKES_ANY_FROM`]), where the seam's reads ask the
/// ring for a whole slab and every write is a slab (no row above 512 MiB
/// was taken for it); on Linux 128 MiB ([`lone_wide_under_on`]).
#[cfg(feature = "parallel")]
pub(super) const LONE_WIDE_UNDER: u64 = lone_wide_under_on(ON_LINUX);

/// What `RARFAST_LONE_WIDE` asks of [`lone_wide_stored`].
#[cfg(feature = "parallel")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LoneWide {
    /// Never.
    Off,
    /// Where the page cache was asked and holds the whole sample: on the
    /// systems whose stored route samples it ([`STORED_WRITTEN_WALKS`]).
    Rule,
    /// COUNT ONLY: on any system, the cache NOT asked, so a system with no
    /// sample of it (off Unix the sample answers Unknown) can price the
    /// rule. The archive must still have no window ([`cold_window_of`]).
    Any,
}

/// `RARFAST_LONE_WIDE`: `1` (or `on`) is the rule where the cache is asked,
/// `0` (or `off`) never, `any` the count arm ([`LoneWide::Any`]); anything
/// else, or nothing, is [`LONE_WIDE`]'s answer. A RUNTIME knob, so one
/// binary carries every arm.
#[cfg(feature = "parallel")]
pub(super) fn lone_wide_knob() -> LoneWide {
    static WORD: std::sync::OnceLock<LoneWide> = std::sync::OnceLock::new();
    *WORD.get_or_init(|| lone_wide_of(crate::knob::reader_var("RARFAST_LONE_WIDE").ok().as_deref()))
}

/// [`lone_wide_knob`]'s reading of the variable's value, in any case and
/// with space around it.
#[cfg(feature = "parallel")]
pub(super) fn lone_wide_of(value: Option<&str>) -> LoneWide {
    match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        Some("1" | "on") => LoneWide::Rule,
        Some("0" | "off") => LoneWide::Off,
        Some("any") => LoneWide::Any,
        _ if LONE_WIDE => LoneWide::Rule,
        _ => LoneWide::Off,
    }
}

/// What [`lone_wide_stored`] is told of the command and the set.
#[cfg(feature = "parallel")]
#[derive(Clone, Copy)]
pub(super) struct LoneWideAsk {
    /// `x` or `e`.
    pub(super) extract: bool,
    /// The rule is on ([`lone_wide_knob`]): `Rule` or `Any`.
    pub(super) on: bool,
    /// The set is one volume, and not solid.
    pub(super) one_plain_volume: bool,
    /// The stored route found the WHOLE sample of the archive in the page
    /// cache ([`stored_route_of`]'s pool answer), and no window reads it.
    pub(super) in_memory: bool,
    /// A width is stated as one thread (`-mt1`), or a memory budget is
    /// stated (`-mm`), which keeps SPEC-API 8.1's own read-ahead.
    pub(super) stated: bool,
}

/// Whether `x` or `e` of these selected members is of ONE STORED MEMBER
/// ALONE, IN MEMORY, that the engine reads wide ([`LONE_WIDE`] says why):
/// by each member's facts, `(is a directory, method, encrypted, has a
/// CRC32, split, size)`, read from the archive's own headers. Exactly one
/// file is selected (directories aside); it is stored, clear, checked by
/// a CRC32 and whole in its volume; it is at least the system's floor
/// ([`LONE_WIDE_FROM`]) and under [`LONE_WIDE_UNDER`]; the set is one
/// volume that is not solid, and in memory; and no `-mt1` and no `-mm` is
/// stated.
#[cfg(feature = "parallel")]
pub(super) fn lone_wide_stored(
    ask: LoneWideAsk,
    members: impl Iterator<Item = (bool, u8, bool, bool, bool, u64)>,
) -> bool {
    if !ask.extract || !ask.on || !ask.one_plain_volume || !ask.in_memory || ask.stated {
        return false;
    }
    let mut files = members.filter(|member| !member.0);
    match (files.next(), files.next()) {
        (Some((_, method, encrypted, crc32, split, size)), None) => {
            method == 0
                && !encrypted
                && crc32
                && !split
                && (LONE_WIDE_FROM..LONE_WIDE_UNDER).contains(&size)
        }
        _ => false,
    }
}

/// How many times the bytes of every OTHER written file must fit in the
/// largest one before a compressed set in volumes is taken abreast
/// ([`written_abreast`]): 2, so the rest is more than half of the largest.
#[cfg(feature = "parallel")]
pub(super) const WRITTEN_ABREAST_SHARE: u64 = 2;

/// Whether written files of these sizes give the pool something to run
/// abreast: the files beside the largest one hold, together, more than a
/// [`WRITTEN_ABREAST_SHARE`]th of it.
///
/// **What it guards.** A compressed member split across volumes is sent to
/// the pool when it is written only where this holds
/// ([`Run::split_dispatched`]). A set of many members is the shape it is
/// for: eight like members decoded and written at once where the walk took
/// them one at a time. A big member or a large binary beside a sample and an `.nfo` is the
/// shape it refuses: the pool gives the one large member a single worker
/// that decodes it and writes it, where the walk decodes it ahead on
/// several threads and writes behind them, so through the pool such a set
/// read about 0.75x. Counted warm on eighteen cores, 8 GiB at `-m3` in
/// 100 MB volumes, the pool over the walk: beside an eighth of its size
/// 0.81x, a quarter 0.90x, a half level, a set of eight 2.2x, a tree of
/// 2,300 files 1.8x to 2.5x.
#[cfg(feature = "parallel")]
pub(super) fn written_abreast(sizes: impl Iterator<Item = u64>) -> bool {
    let (mut largest, mut total) = (0u64, 0u128);
    for size in sizes {
        total += u128::from(size);
        largest = largest.max(size);
    }
    (total - u128::from(largest)) * u128::from(WRITTEN_ABREAST_SHARE) > u128::from(largest)
}

/// Whether `x` or `e` of these selected members is of ONE LARGE COMPRESSED
/// MEMBER BESIDE SMALL ONES ([`Run::lone_packed`]): by each member's facts,
/// `(is a directory, method, size)`, read from the archive's own headers.
/// The largest file is compressed, there is another file beside it, and
/// the files beside it give the pool nothing to run abreast
/// ([`written_abreast`]): together they hold no more than a
/// [`WRITTEN_ABREAST_SHARE`]th of it.
///
/// **Such a set takes the walk, as one archive too.** A big member or a large
/// binary packed beside a sample, an `.nfo` and subtitles has several
/// files, so the dialect asked the engine for the member pool, and the
/// pool has nothing to run abreast: one worker decodes the large member
/// and writes it. Walked, the same member is decoded ahead on several
/// threads and written behind them. The set in volumes keeps the walk by
/// the same share ([`Run::split_dispatched`]); this is the rule for the
/// set that is not split.
///
/// **Where it stops.** A set of many members and a tree keep the pool, which runs their
/// members abreast. A large STORED member is not asked about here
/// ([`lone_large_stored`]). `t` and `p` write no file and are not asked. A
/// stated `-mt1` walks already, and `RARFAST_POOL` wins over the rule
/// either way.
#[cfg(feature = "parallel")]
pub(super) fn lone_large_packed(
    extract: bool,
    members: impl Iterator<Item = (bool, u8, u64)>,
) -> bool {
    if !extract {
        return false;
    }
    // The largest file as (size, compressed), and every file's size.
    let (mut largest, mut sizes) = ((0u64, false), Vec::new());
    for (is_dir, method, size) in members {
        if is_dir {
            continue;
        }
        if size > largest.0 {
            largest = (size, method != 0);
        }
        sizes.push(size);
    }
    sizes.len() > 1 && largest.1 && !written_abreast(sizes.into_iter())
}

/// Whether the walk's driver is the member pool ([`Run::drive`]): never
/// for `p`, a solid set, a set with an undispatched split member or a
/// breadth of one, and otherwise as [`takes_pool_of`] says.
#[cfg(feature = "parallel")]
pub(super) fn pool_drives(
    print: bool,
    solid: bool,
    split: bool,
    breadth: usize,
    takes_pool: bool,
) -> bool {
    !print && !solid && !split && breadth > 1 && takes_pool
}

/// The read-ahead of an extract whose stored route is `deep`: the larger
/// of `shipped` and [`STORED_COLD_READ_AHEAD`], never more than half the
/// policy's working limit, and `shipped` where a memory cap is stated.
#[cfg(feature = "parallel")]
pub(super) fn stored_read_ahead(shipped: u64, deep: bool, capped: bool, working_limit: u64) -> u64 {
    if !deep || capped {
        return shipped;
    }
    shipped.max(stored_cold_read_ahead(shipped).min(working_limit / 2))
}

/// Whether a cold clear stored archive is read through the source's WINDOW
/// (`crate::window`) and not at the seam's deep read-ahead: ON, its rows
/// being in on two Apple boxes (2 Oct 2026: no cold stored shape slower,
/// members under a gibibyte 1.14x to 1.20x).
/// `RARFAST_COLD_WINDOW`
/// of `0` or `off` switches it off, which is the deep route before it: a
/// RUNTIME knob, like `RARFAST_POOL`, so one binary prices the window
/// against the deep route on any archive.
#[cfg(feature = "parallel")]
pub(super) fn cold_window_knob() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        cold_window_on(
            crate::knob::reader_var("RARFAST_COLD_WINDOW")
                .ok()
                .as_deref(),
        )
    })
}

/// [`cold_window_knob`]'s reading of the variable's value: off for `0` or
/// `off`, in any case and with space around it; on for anything else and
/// for no value at all.
#[cfg(feature = "parallel")]
pub(super) fn cold_window_on(value: Option<&str>) -> bool {
    !value.is_some_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "off"))
}

/// Whether the window's reader asks the kernel for the file ahead of its
/// own reads (`crate::window::AHEAD`): ON, its rows being in (2 Oct 2026,
/// K=7, cold `x` of 4 GiB on disk).
/// On an M5 MacBook Air it
/// took a cold stored extract from 0.81 to 0.86 of the drive to 0.95 and
/// over, 1.14x to 1.25x over the window alone on four shapes; on an M1
/// Ultra, already at its drive, it is level. `RARFAST_COLD_WINDOW_ASK` of
/// `0` or `off` switches it off, which is the window before it: a RUNTIME
/// knob, like `RARFAST_COLD_WINDOW`, read as it is.
#[cfg(feature = "parallel")]
pub(super) fn cold_window_ask_knob() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        cold_window_on(
            crate::knob::reader_var("RARFAST_COLD_WINDOW_ASK")
                .ok()
                .as_deref(),
        )
    })
}

/// How far past each slab the window's reader asks the kernel for the
/// file: `crate::window::AHEAD`, or 0 where the request is switched off. A count-only knob (feature `read-depth-knob`, never shipped):
/// `RARFAST_COLD_WINDOW_ADVISE_MIB` states the distance, 0 to 1024, for a
/// ladder.
#[cfg(feature = "parallel")]
pub(super) fn cold_window_ahead(on: bool) -> u64 {
    if !on {
        return 0;
    }
    #[cfg(feature = "read-depth-knob")]
    if let Some(mib) = std::env::var("RARFAST_COLD_WINDOW_ADVISE_MIB")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|mib| (0..=1024).contains(mib))
    {
        return mib << 20;
    }
    crate::window::AHEAD
}

/// The slab the archive's window reads at for this walk, or `None` for no
/// window: only where the knob is `on` (it is, unless switched off), the
/// archive is one cold `stream` (a
/// cold stored archive that is not solid, its members clear or encrypted,
/// written by `x` or `e` on
/// a system whose stored archives walk), the command extracts EVERY file
/// of the set (`whole`), no memory cap is stated and the command may use
/// a second thread.
///
/// **Why only the whole set.** The window reads on in file order, two
/// slabs past whatever the walk last read. A command that picks members
/// out hops over the others, and read-ahead behind a picked member is
/// bytes nobody asked for: one 64 MiB member picked out of sixty-four
/// took 0.49 s through a window against 0.11 s without (an M1 Ultra, K=7,
/// 2 Oct 2026). A selection keeps the
/// deep route it had.
///
/// **Why this and not the seam's depth.** `deep` gives the seam's ring 256
/// MiB, which only a member of a gibibyte or more takes: under that floor
/// a member is read and written by one thread in 128 KiB requests. On an
/// M1 Ultra (K=5, cold `x` on disk, 2 Oct 2026) eight members
/// of 512 MiB to sixty-four of 64 MiB took 1.76 to 1.81 s where four of 1
/// GiB took 1.57 s and the drive's own ceiling, by a raw probe, is 1.52 to
/// 1.55 s at every member count; the window reads the file in that probe's
/// shape.
///
/// **An encrypted archive too.** Its members are cut by one reader in
/// order (the engine's `read::handed`), in requests of a mebibyte under
/// the shipped read-ahead, and a cold drive answers those as it answers a
/// clear member's small requests: counted on a 20 core Apple desktop (4
/// GiB to disk, cold, K=3), a big member and a set of eight under a password
/// extracted in 1.755 to 1.775 s with no window where their clear twins
/// took 1.52 s through one. The window is under the engine and knows no
/// cipher: the reads it serves are the same reads, answered from memory.
///
/// **Its memory is what `deep` held.** The window's slabs together are
/// never more than half the policy's working limit, the bound
/// [`stored_read_ahead`] keeps for the ring they replace; under a limit
/// that leaves a slab less than a mebibyte there is no window. A stated
/// `-mm` keeps SPEC-API 8.1's own derivation and no window, and `-mt1`
/// states one thread, which the window's reader would be a second of.
///
/// A count-only knob (feature `read-depth-knob`, never shipped):
/// `RARFAST_COLD_WINDOW_KIB` sets the slab, for a ladder and for
/// `tests/cold_window.rs`, whose archives are small, and
/// `RARFAST_COLD_WINDOW_ADVISE_MIB` (0 to 1024) how far past each slab the
/// window's reader asks the kernel for the file ([`cold_window_ahead`]).
#[cfg(feature = "parallel")]
pub(super) fn cold_window_of(
    on: bool,
    stream: bool,
    whole: bool,
    capped: bool,
    threads: Option<u64>,
    working_limit: u64,
) -> Option<u64> {
    if !on || !stream || !whole || capped || threads == Some(1) {
        return None;
    }
    #[cfg(feature = "read-depth-knob")]
    if let Some(kib) = std::env::var("RARFAST_COLD_WINDOW_KIB")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|kib| (1..=(1 << 20)).contains(kib))
    {
        return Some(kib << 10);
    }
    let slab = crate::window::SLAB.min(working_limit / 2 / crate::window::SLABS as u64);
    (slab >= 1 << 20).then_some(slab)
}

/// An all-stored extract's route from what the page cache said of its
/// archive ([`Run::stored_route`]): whether it takes the walk, and whether
/// the walk reads deep, which only a `plain` archive (clear, not solid,
/// the pool not forced) may.
#[cfg(feature = "parallel")]
pub(super) fn stored_route_of(
    (fraction, residency): (Option<f64>, crate::residency::Residency),
    plain: bool,
) -> (bool, bool) {
    use crate::residency::Residency;
    match residency {
        // The pool only where the WHOLE sample is in memory
        // ([`STORED_POOL_RESIDENT`]); a verdict stated with no fraction
        // (a count build's knob) is taken at its word.
        Residency::Resident if fraction.is_none_or(|f| f >= STORED_POOL_RESIDENT) => (false, false),
        // Partly in memory: the walk, at the shipped depth.
        Residency::Resident => (true, false),
        Residency::Cold => (true, plain),
        // As before the cache was asked: the walk, at the shipped depth.
        Residency::Unknown => (true, false),
    }
}

/// The sampled fraction of an archive at and above which an all-stored
/// extract takes the pool ([`stored_route_of`]): all of it.
///
/// **Not the sampler's own half.** The two mistakes are not the same
/// size. The walk on an archive that is in memory gives back 2 to 9
/// percent; the pool on one that is half on its device reads the cold
/// half at several offsets at once and lost by half: on the M5 Ultra a
/// clear set of many members with its first 47 percent read (the sample then says
/// exactly one half) extracted in 2.59 s through the pool against 1.21 s
/// by the walk, and with 53 percent read in 2.37 s against 1.15 s
/// (1 Oct 2026). So one sampled page out of memory is
/// enough for the walk.
#[cfg(feature = "parallel")]
pub(super) const STORED_POOL_RESIDENT: f64 = 1.0;

impl Run<'_> {
    /// Whether any member this run will extract spans a volume boundary.
    ///
    /// **A set like that takes the sequential path, and it is the engine's
    /// ceiling that makes it the right answer rather than any property of
    /// volumes.** Spec F 3.5.4 joins a split member's fragments by walking
    /// into the next volume, so the engine cannot dispatch one and decodes
    /// it on the walking thread. In a set where some members are split and
    /// some are not, the walk is therefore doing a full member's decode
    /// ITSELF while the members it dispatched are each running on
    /// `max_workers / breadth` lanes - and the walk's own decode takes the
    /// whole ceiling. The machine is oversubscribed and the walk, which
    /// everything else waits on, is the thing slowed down.
    ///
    /// Measured on the 18 core laptop, nine rounds, a nine-part set of
    /// eight 16 MiB `-m3` members in 16 MB volumes, so about half of them
    /// straddle a boundary:
    ///
    /// | leg | sequential | through the pool | ratio |
    /// |---|---|---|---|
    /// | `t`, default width | 41.3 ms | 52.2 ms | **0.791x** |
    /// | `t`, `-mt4` | 57.0 ms | 90.3 ms | **0.631x** |
    /// | `x`, default width | 52.6 ms | 59.3 ms | **0.887x** |
    ///
    /// A volume set whose members each sit WHOLE inside one volume has
    /// nothing split in it and is not caught by this; it goes wide like
    /// any other non-solid set.
    ///
    /// **A split member that is STORED and clear no longer counts.** The
    /// engine's pool now dispatches one over its fragment list
    /// (`extract::Split`, 29 Sep 2026): the walk only crosses the volume
    /// boundaries and a worker reads and writes the bytes, so nothing is
    /// decoded on the walking thread and the ceiling is spent as for any
    /// other member. That is the many-member shape, a stored `-v4g` set of
    /// big members, which extracted one member at a time at every boundary.
    ///
    /// **Nor does a COMPRESSED one, encrypted or not**: the engine takes it
    /// over its fragment list too, which removes the oversubscription
    /// measured above, because the walk no longer decodes anything
    /// ([`Self::split_dispatched`], which also says which written sets
    /// keep this path).
    ///
    /// **`x` and `e` only, for a stored clear one.** `t` of such a set
    /// keeps the sequential path,
    /// where the wide verify already spreads each member across the width:
    /// through the pool it read 0.280 s
    /// against 0.235 s at `-mt2` on an 8 GiB `-v4g` set (an 18 core laptop,
    /// INDICATIVE), the pool's own `-mt2` cost that a single archive
    /// already pays, for a win only at the default width.
    ///
    /// **Open, and it is the same item as the solid
    /// one:** this is a judgement about how the ENGINE spends its ceiling,
    /// made in a caller because the caller is where it was measured.
    /// Dispatching a compressed split member removed the rest of it for
    /// the set as a whole; a set whose ONLY split members are stored and
    /// clear, read by `t`, is what still takes this path.
    /// Whether a command the pool could take does take it: the knob, and
    /// the one shape the pool is the wrong route for.
    #[cfg(feature = "parallel")]
    pub(super) fn takes_pool(&self) -> bool {
        let walks = self.stored_walks || self.lone_large().is_some() || self.lone_packed();
        // COUNT ONLY (feature `read-depth-knob`): `RARFAST_ROUTE_SAY=1`
        // says on stderr which route the rule gives, which is what
        // `tests/lone_large_route.rs` reads.
        #[cfg(feature = "read-depth-knob")]
        if std::env::var("RARFAST_ROUTE_SAY").is_ok_and(|v| v.trim() == "1") {
            eprintln!(
                "rarfast route: {}; lone large {}; lone packed {}",
                if takes_pool_of(pool_knob(), walks) {
                    "pool"
                } else {
                    "walk"
                },
                self.lone_large().is_some(),
                self.lone_packed()
            );
        }
        takes_pool_of(pool_knob(), walks)
    }

    /// The size of the one large stored member this run extracts beside
    /// small ones, where such a set takes the walk
    /// ([`lone_large_stored`]).
    #[cfg(feature = "parallel")]
    pub(super) fn lone_large(&self) -> Option<u64> {
        let small_volumes = self.volumes.len() > 1
            && self
                .volumes
                .iter()
                .all(|volume| volume.size <= WIDE_READ_FLOOR);
        lone_large_stored(
            LoneAsk {
                extract: matches!(self.mode, Mode::Extract { .. }),
                small_volumes,
                blake2sp: LONE_LARGE_BLAKE2SP,
                floor: lone_large_floor(),
            },
            self.selected.iter().map(|index| {
                let member = &self.plan[*index].member;
                (
                    member.is_dir,
                    member.method,
                    member.encrypted,
                    member.crc32.is_some(),
                    member.size,
                )
            }),
        )
    }

    /// Whether this run extracts one stored member alone, in memory, that
    /// the engine reads wide ([`lone_wide_stored`]). `walks` and `window`
    /// are the stored route's answers ([`Self::stored_route`],
    /// [`cold_window_of`]): an archive whose whole sample is in memory
    /// does not take the walk by that rule, and has no window. `threads`
    /// is the width the walk runs at, stated or set by a rule.
    ///
    /// **macOS asks the cache, and only there may `walks` be read so.** The
    /// stored route samples the archive on the systems that walk stored
    /// archives ([`STORED_WRITTEN_WALKS`]); elsewhere it answers `false`
    /// unasked, so no other system reads it: Windows and Linux take the
    /// rule with no cache term ([`LONE_WIDE_ASKS_CACHE`]).
    #[cfg(feature = "parallel")]
    pub(super) fn lone_wide(&self, walks: bool, window: bool, threads: Option<u64>) -> bool {
        let knob = lone_wide_knob();
        let rule = lone_wide_stored(
            LoneWideAsk {
                extract: matches!(self.mode, Mode::Extract { .. }),
                on: knob != LoneWide::Off,
                one_plain_volume: self.volumes.len() == 1 && !self.volumes[0].solid,
                in_memory: !window
                    && match knob {
                        LoneWide::Any => true,
                        _ => !LONE_WIDE_ASKS_CACHE || (STORED_WRITTEN_WALKS && !walks),
                    },
                stated: threads == Some(1) || self.opts.memory_cap.is_some(),
            },
            self.selected.iter().map(|index| {
                let planned = &self.plan[*index];
                let member = &planned.member;
                let split =
                    planned.fragments.len() > 1 || member.split_before || planned.split_after_last;
                (
                    member.is_dir,
                    member.method,
                    member.encrypted,
                    member.crc32.is_some(),
                    split,
                    member.size,
                )
            }),
        );
        let taken = self.lone_written(rule, window, threads);
        // COUNT ONLY (feature `read-depth-knob`): `RARFAST_LONE_WIDE_SAY=1` says on stderr
        // whether the rule took the run's member, which is what `tests/lone_wide_stored.rs` reads.
        #[cfg(feature = "read-depth-knob")]
        if std::env::var("RARFAST_LONE_WIDE_SAY").is_ok_and(|v| v.trim() == "1") {
            eprintln!(
                "rarfast lone wide: {}",
                if taken { "taken" } else { "not taken" }
            );
        }
        taken
    }

    /// Whether this run extracts one large compressed member beside small
    /// ones, a set that takes the walk ([`lone_large_packed`]).
    #[cfg(feature = "parallel")]
    pub(super) fn lone_packed(&self) -> bool {
        lone_large_packed(
            matches!(self.mode, Mode::Extract { .. }),
            self.selected.iter().map(|index| {
                let member = &self.plan[*index].member;
                (member.is_dir, member.method, member.size)
            }),
        )
    }

    /// Whether this run's stored archive takes the walk, whether the
    /// walk reads it at [`STORED_COLD_READ_AHEAD`], and whether it is one
    /// cold stream, which the source's window reads ([`stored_route_for`]).
    ///
    /// **The walk, unless the archive is in memory** (macOS,
    /// [`STORED_WRITTEN_WALKS`]). What makes the walk right for a stored
    /// archive is a COLD device, which answers one reader in order far
    /// faster than several at once ([`Self::stored_written`]). An archive
    /// already in the page cache has no device to please, and there the
    /// pool is ahead, its members written by as many threads: on the M5
    /// Ultra the clear many-member set extracted WARM in 0.635 s through the pool
    /// against 0.694 s by the walk, the `-hp` one in 0.639 s against 0.653
    /// s (1 Oct 2026). So the page cache is asked, once
    /// (`residency::of`, a sample of sixty-four pages), and an archive
    /// whose WHOLE sample it holds takes the pool
    /// ([`STORED_POOL_RESIDENT`]). One it holds part of, and one it cannot
    /// say of, take the walk, as before it was asked.
    ///
    /// **Deep, when the archive is cold and clear.** The seam hands the
    /// walk's reads to this thread's writes a slab at a time, and at the
    /// 4 MiB slabs of [`EXTRACT_READ_AHEAD`] the two threads wait on each
    /// other about as often as they work: the same box reads a cold
    /// many-member set and writes as many bytes AT ONCE in 1.38 s (a raw probe, no
    /// rarfast in it), where a byte copy takes 1.66 s and the walk took
    /// 1.63 s. Read further ahead the walk reaches it. Only a cold
    /// archive: warm, the deeper slabs lose 2 to 3 percent, and a warm
    /// archive is the pool's. Only a clear one that is not solid: an
    /// encrypted member is not the seam's, so the seam's depth gains it
    /// nothing (it has the source's window instead, below), and
    /// a solid set's walk is another path with its own rows.
    ///
    /// **Since 2 Oct 2026 that depth is the archive source's, not the
    /// seam's** ([`cold_window_of`]): the seam takes only a member of a
    /// gibibyte or more, so a set of smaller like members was read and
    /// written by one thread in small requests, level with unrar. The
    /// source's window reads the file in order across members, and the
    /// walk then runs at the shipped depth. Where there is no window (the
    /// knob off, `-mt1`) the seam's deep read-ahead is as it was. A cold
    /// ENCRYPTED archive has the window too and never the seam's depth: with
    /// no window it is read as it was before it had one.
    #[cfg(feature = "parallel")]
    pub(super) fn stored_route(&self) -> (bool, bool, bool) {
        let ask = StoredAsk {
            stored: STORED_WRITTEN_WALKS && self.stored_written(),
            clear: self
                .selected
                .iter()
                .all(|index| !self.plan[*index].member.encrypted),
            solid: self.volumes.iter().any(|v| v.solid),
            cut_off: stored_cut_off(),
            knob: pool_knob(),
        };
        stored_route_for(&ask, || {
            self.volume_names
                .first()
                .map(|first| crate::residency::of(Path::new(first)))
        })
    }

    /// Whether this is `x` or `e` of members that are ALL stored
    /// (directories aside), clear or encrypted, none of them split, or a
    /// split set ([`SPLIT_SET_MEMBERS`] or more split).
    ///
    /// **On macOS such an archive takes the walk**
    /// ([`STORED_WRITTEN_WALKS`]). In the pool each stored member
    /// is one worker's, which reads it in requests of 128 KiB (the
    /// engine's `STORED_REQUEST`, sized for a copy that stays in cache)
    /// and writes it as it reads: several members in flight then read ONE
    /// file at several offsets in small requests, which a cold device and
    /// the kernel's read-ahead answer far slower than one stream. The walk
    /// takes the members one at a time, each read deep by the seam's
    /// source unit while this thread writes it.
    ///
    /// Timed on an M5 Ultra (36 cores, internal SSD; load 2 to 7, so
    /// INDICATIVE; `x` on disk with `F_FULLFSYNC`; 1 Oct 2026),
    /// a stored set of eight like members, 8.76 GB in one archive:
    /// COLD 3.595 s through the pool and 1.639 s through the walk, where
    /// unrar took 1.659 s and a byte copy 1.659 s; WARM 0.644 s against
    /// 0.682 s (unrar 0.945 s), so the walk gives back 5.9 percent warm,
    /// which waits on the change that overlaps the read with the write.
    /// The big member beside its `.nfo`: warm 1.213 s to 0.936 s (unrar 1.304
    /// s), cold level at the copy's own 2.44 s.
    ///
    /// **An ENCRYPTED stored archive takes the walk too** (1 Oct 2026):
    /// the walk now cuts its own encrypted
    /// member with ONE reader in order and the cipher on lanes behind it
    /// (the engine's `read::handed`), so the cipher is spread without the
    /// pool, and the archive is read as one stream. The same box, the
    /// set of eight under `-hp`: COLD 2.17 s through the pool and 1.64 s through
    /// the walk (7-Zip 2.48 s, a byte copy 1.67 s); WARM 0.639 s against
    /// 0.653 s, a 2 percent give-back that waits, with the clear set's,
    /// on a route chosen by whether the archive is in memory.
    ///
    /// A VERIFIED member (`t`) keeps the pool, where a worker reads a
    /// stored member wide. One split stored member is a split job and is
    /// not asked about here ([`Self::any_selected_is_split`]); a split set
    /// is ([`SPLIT_SET_MEMBERS`]).
    #[cfg(feature = "parallel")]
    pub(super) fn stored_written(&self) -> bool {
        all_stored_written(
            matches!(self.mode, Mode::Extract { .. }),
            !split_set_takes_pool_on(top_level_cores()),
            self.selected.iter().map(|index| {
                let planned = &self.plan[*index];
                let member = &planned.member;
                let split =
                    planned.fragments.len() > 1 || member.split_before || planned.split_after_last;
                (member.is_dir, member.method, split)
            }),
        )
    }

    /// Whether the command extracts every file the set holds (directories
    /// aside): what [`cold_window_of`] asks before it reads the archive
    /// ahead in file order.
    #[cfg(feature = "parallel")]
    pub(super) fn selects_every_file(&self) -> bool {
        let files = self.plan.iter().filter(|p| !p.member.is_dir).count();
        let selected = self
            .selected
            .iter()
            .filter(|index| !self.plan[**index].member.is_dir)
            .count();
        files > 0 && selected == files
    }

    #[cfg(feature = "parallel")]
    pub(super) fn any_selected_is_split(&self) -> bool {
        self.selected.iter().any(|index| {
            let planned = &self.plan[*index];
            let split = planned.fragments.len() > 1
                || planned.member.split_before
                || planned.split_after_last;
            split && !self.split_dispatched(planned)
        })
    }

    /// Whether the engine's pool takes this SPLIT member whole, over its
    /// fragment list (`extract::Split` in rarkit), in a way this command
    /// wants. A member the plan holds is its first fragment joined to the
    /// rest, so no other fragment of it is asked about.
    ///
    /// - **stored and clear**: written (`x`, `e`) only; `t` keeps the
    ///   sequential path's wide verify (above).
    /// - **compressed, encrypted or not** (the engine's `split_job_kind`):
    ///   VERIFIED (`t`) always. Nothing of such a member is decoded on the
    ///   walk, so the set spends its ceiling as any other non-solid set
    ///   does, where on the sequential path each one drained the look-ahead
    ///   and decoded one member at a time: a set of eight at `-m3 -v1g`
    ///   tested 2.33x faster cold and 1.60x warm on eight cores. WRITTEN
    ///   (`x`, `e`) where the set has members to run abreast
    ///   ([`Self::written_abreast`]): the same set as one archive
    ///   already took the pool, and in volumes it decoded one member at a
    ///   time. A set that is one large member beside small ones keeps the
    ///   sequential path, where that member is decoded ahead and written
    ///   behind.
    /// - **stored and encrypted**: not taken, so such a set keeps the
    ///   sequential entry's wide read (cold `x` 0.916x as a split job).
    ///
    /// `RARKIT_SPLIT_JOBS` set to `stored` gives the arrangement before
    /// both, `verified` the one that took a compressed member for `t`
    /// alone, and `all` takes every kind for `x`, `e` and `t`, in the
    /// engine and here alike.
    #[cfg(feature = "parallel")]
    pub(super) fn split_dispatched(&self, planned: &Planned) -> bool {
        let member = &planned.member;
        if member.is_dir || member.split_before {
            return false;
        }
        if member.method == 0 && !member.encrypted {
            return matches!(self.mode, Mode::Extract { .. });
        }
        let (compressed, compressed_written, encrypted_stored) = split_jobs_beyond_stored();
        match self.mode {
            Mode::Test if member.method == 0 => encrypted_stored,
            Mode::Test => compressed,
            Mode::Extract { .. } if member.method == 0 => encrypted_stored,
            Mode::Extract { .. } => compressed_written && self.written_abreast(),
            Mode::Print => false,
        }
    }

    /// Whether the files this run writes give the pool something to run
    /// abreast ([`written_abreast`]), by the sizes their headers state.
    #[cfg(feature = "parallel")]
    pub(super) fn written_abreast(&self) -> bool {
        written_abreast(self.selected.iter().filter_map(|index| {
            let member = &self.plan[*index].member;
            (!member.is_dir).then_some(member.size)
        }))
    }

    /// How many members to ask the engine to keep in flight.
    ///
    /// **This is not simply `max_workers`, and the difference is worth 4.3x on
    /// one leg.** The engine divides its ceiling between the
    /// two things that can claim it (SPEC-API 8.3): the members decoded at
    /// once and the tape lanes INSIDE each of them. A member dispatched into a
    /// pool of `n` workers is granted `max_workers / n` lanes, never fewer
    /// than one. So the breadth a caller asks for is also the divisor of every
    /// member's own width, and asking for the whole ceiling leaves every
    /// member a single lane.
    ///
    /// That costs nothing when there are members enough to use the breadth,
    /// and it is ruinous when there are not. Measured on the 18 core laptop,
    /// nine rounds, one 256 MiB member at `-m3`:
    ///
    /// | breadth asked for | lanes per member | `t` wall |
    /// |---|---|---|
    /// | 8, the whole ceiling | 1 | 333.5 ms |
    /// | 1, this archive's own count | 8 | 81 ms |
    ///
    /// So the request is the number of members this run could actually have in
    /// flight at once, and the engine keeps the rest of the ceiling for their
    /// widths. A member that is a directory, that was not selected, or that is
    /// SPLIT across volumes can never be one of them: the first two are never
    /// dispatched and spec F 3.5.4 keeps the third on the walking thread, so
    /// counting any of them would starve the members that are dispatched.
    ///
    /// The ceiling itself still bounds it, and since API 8.4.2 that ceiling
    /// is `ReadOptions::workers`, the read side's own width dial, which
    /// `engine::read_options_with` sets from `-mt<n>` exactly and leaves at
    /// `None` when there is none. `ReadOptions::read_width` is the engine's
    /// own resolution of it, read here rather than guessed, so the breadth
    /// this asks for and the width the engine spends are one figure. It was
    /// `MemoryPolicy::max_workers` until 20 Sep 2026, which is the eight
    /// 8.4 was written to remove.
    ///
    /// It is deliberately NOT `crate::workers::width`. That figure sizes the
    /// process's rayon POOL, which is a third thing again; see
    /// `crate::workers`.
    #[cfg(feature = "parallel")]
    pub(super) fn breadth(&self, options: &rarkit::ReadOptions) -> usize {
        let dispatchable = self
            .selected
            .iter()
            .filter(|index| {
                let planned = &self.plan[**index];
                let whole = !planned.member.is_dir
                    && !planned.member.split_before
                    && !planned.split_after_last
                    && planned.fragments.len() == 1;
                // A stored split member goes to a worker too; counting only
                // the whole ones held a set in which every member
                // crosses a volume to a breadth of one.
                whole || self.split_dispatched(planned)
            })
            .count();
        dispatchable.clamp(1, options.read_width().max(1))
    }
}

/// THE WINDOWS ARM of [`lone_wide_stored`] (18 Oct 2026), THE LINUX ARM
/// (20 Oct 2026), and the four answers per system the rule is built of.
/// [`LONE_WIDE`] is [`lone_wide_ships_on`] of this build's system,
/// [`LONE_WIDE_FROM`], [`LONE_WIDE_UNDER`] and [`LONE_WIDE_ASKS_CACHE`]
/// the same of theirs.
///
/// **Windows has no sample of the page cache** (`residency` asks `mincore`,
/// which is Unix only, and answers Unknown elsewhere), so there the rule is
/// taken warm or cold with no cache term. The cold window guard stays as
/// it is: Windows arms no window ([`cold_window_of`] wants the stored
/// route's cold stream, which Windows does not ask for).
///
/// Counted on a Windows desktop (Ryzen 7 9800X3D, a WD SN8100, one build
/// with `RARFAST_LONE_WIDE=any` against `0`, K=15, a quiet box; 18 Oct
/// 2026): the wide read never lost. A 16 MiB member read LEVEL warm and
/// cold; from 32 MiB it won warm and cold, and more as the member grew
/// (cold 128 MiB 1.30x, 256 MiB 1.39x); at a gibibyte level, which is the
/// ceiling ([`LONE_WIDE_UNDER`]). The warm loss the pool's count once found
/// for a written member read wide there was not seen.
///
/// **Linux, from 32 MiB to under 128 MiB, with no cache term.** The stored
/// route samples no page cache on Linux (it walks no stored archive by
/// that rule), so the rule is taken with the cold window guard alone, as
/// on Windows. Counted on an AMD EPYC 4345P (8 cores, 16 threads; one
/// build with `RARFAST_LONE_WIDE=any` against `0`, warm, K=45, quiet; 19
/// Oct 2026), the shipped route was BEHIND the old engine at 32 MiB (`x`
/// 0.936, `e` 0.920) and the wide read brought both level (1.077x and
/// 1.049x faster than the route before it); at 64 MiB the two read level;
/// at 16 MiB (0.953, 0.948) and 128 MiB (0.973, 0.969) the wide read was
/// SLOWER, so the floor is 32 MiB ([`lone_wide_from_on`]) and the ceiling
/// 128 MiB ([`lone_wide_under_on`]). A Linux archive read cold was not
/// counted.
#[cfg(feature = "parallel")]
pub(super) const fn lone_wide_ships_on(macos: bool, windows: bool, linux: bool) -> bool {
    macos || windows || linux
}

/// The least size [`lone_wide_stored`] takes on a system: 32 MiB on
/// Windows, where 16 MiB read level, and on Linux, where it read slower
/// ([`lone_wide_ships_on`] has the counts), and the wide read's floor
/// ([`WIDE_READ_FLOOR`]) elsewhere.
#[cfg(feature = "parallel")]
pub(super) const fn lone_wide_from_on(windows: bool, linux: bool) -> u64 {
    if windows || linux {
        32 << 20
    } else {
        WIDE_READ_FLOOR
    }
}

/// Whether the rule asks the page cache on a system: everywhere but
/// Windows, which has no sample of it, and Linux, whose stored route takes
/// none ([`lone_wide_ships_on`]).
#[cfg(feature = "parallel")]
pub(super) const fn lone_wide_asks_cache_on(windows: bool, linux: bool) -> bool {
    !windows && !linux
}

/// The size from which [`lone_wide_stored`] leaves a member to the seam on
/// a system ([`LONE_WIDE_UNDER`]): 128 MiB on Linux, where the wide read
/// was slower at 128 MiB ([`lone_wide_ships_on`] has the count), and
/// [`SEAM_TAKES_ANY_FROM`] elsewhere.
#[cfg(feature = "parallel")]
pub(super) const fn lone_wide_under_on(linux: bool) -> u64 {
    if linux {
        128 << 20
    } else {
        SEAM_TAKES_ANY_FROM
    }
}

/// [`lone_wide_from_on`] of this build's system.
#[cfg(feature = "parallel")]
pub(super) const LONE_WIDE_FROM: u64 = lone_wide_from_on(cfg!(windows), ON_LINUX);

/// [`lone_wide_asks_cache_on`] of this build's system: when it is false the
/// rule's cache term ([`LoneWideAsk::in_memory`]) is the window guard alone.
#[cfg(feature = "parallel")]
pub(super) const LONE_WIDE_ASKS_CACHE: bool = lone_wide_asks_cache_on(cfg!(windows), ON_LINUX);

/// THE WINDOWS LONE WRITE (19 Oct 2026): `x` and `e` of ONE STORED MEMBER
/// ALONE on Windows, from 16 MiB to under 64 MiB, are read by the serial
/// walk and WRITTEN BEHIND it, on a thread of their own, into a file whose
/// end is set to the member's declared size before the first write
/// (`lone_write`). Where it takes the member, the lone wide rule
/// ([`lone_wide_stored`]) does not.
///
/// **What it is for.** A count on a Windows desktop (Ryzen 7 9800X3D, the
/// shipped build of main a9991e459, K=15, 19 Oct 2026) had such a member
/// behind the old engine: `x` and `e` at 16 MiB 0.942 and 0.925, at 32 MiB
/// 0.904 and 0.903. At 16 MiB one thread read, checked and wrote it in
/// turn, and the write was the largest piece, 127 cached writes of 128 KiB
/// in 3.6 ms of a 6.56 ms dispatch; at 32 MiB the wide read took the reads
/// onto 17 threads and the write stayed serial, 7.11 ms of 9.12.
///
/// **The form, from a screen of three arms** (the same desktop, a plain
/// build, the arms in one binary, K=15 and K=11, a quiet box; the shipped
/// route over each arm, above 1 the arm faster): the end of file set ahead
/// alone, 1.008 to 1.030; larger writes (1 or 4 MiB pieces), level or
/// worse; the write on its own thread, 1.049 to 1.073 at 16 MiB and a loss
/// over the wide read at 32 MiB (0.97); the end of file AND the thread,
/// 1.115 (`x`) and 1.098 (`e`) at 16 MiB, and on the serial route at
/// 32 MiB 1.108 and 1.102, where the wide read with the end set gave 1.022
/// and 1.038. So the two arms add, and the serial walk with a writer
/// behind it beats the wide read with a writer in it: the write is the
/// long piece on NTFS, a file growing by every write is what makes it
/// long, and a write that overlaps nothing is the whole of it.
#[cfg(feature = "parallel")]
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) const fn lone_write_ships_on(windows: bool) -> bool {
    windows
}

/// [`lone_write_ships_on`] of this build's system.
#[cfg(feature = "parallel")]
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) const LONE_WRITE: bool = lone_write_ships_on(cfg!(windows));

/// The least size the lone write takes: the wide read's floor
/// ([`WIDE_READ_FLOOR`], 16 MiB), the smallest row it was screened at.
#[cfg(feature = "parallel")]
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) const LONE_WRITE_FROM: u64 = WIDE_READ_FLOOR;

/// The size from which the lone write leaves a member to the routes before
/// it: the least size written past the OS cache (`unbuffered::LEAST`,
/// 64 MiB). There the member's file is not grown by its writes through the
/// cache at all, and the screen read every arm level at 64 MiB (0.988 to
/// 1.006) and the serial walk behind the wide read at 128 MiB (0.934), so
/// from 64 MiB the lone wide rule keeps its rows.
#[cfg(feature = "parallel")]
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) const LONE_WRITE_UNDER: u64 = crate::unbuffered::LEAST;

/// `RARFAST_LONE_WRITE` (a build with `reader-knobs`): `1` (or `on`) takes
/// the lone write on any system, `0` (or `off`) on none; anything else, or
/// nothing, is [`LONE_WRITE`]. And a STATED `RARFAST_LONE_WIDE` is a count
/// of the wide read, so it keeps the member to that rule unless this word
/// is stated too.
#[cfg(feature = "parallel")]
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) fn lone_write_knob() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        lone_write_of(
            crate::knob::reader_var("RARFAST_LONE_WRITE")
                .ok()
                .as_deref(),
            crate::knob::reader_var("RARFAST_LONE_WIDE").is_ok(),
        )
    })
}

/// [`lone_write_knob`]'s reading of its word, and of whether the wide
/// rule's word is stated.
#[cfg(feature = "parallel")]
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) fn lone_write_of(value: Option<&str>, wide_stated: bool) -> bool {
    match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        Some("1" | "on") => true,
        Some("0" | "off") => false,
        _ => LONE_WRITE && !wide_stated,
    }
}

/// Whether `x` or `e` of these selected members is of ONE STORED MEMBER
/// ALONE that the lone write takes ([`lone_write_ships_on`] says why): the
/// shape [`lone_wide_stored`] asks for, by the same facts of each member,
/// with the lone write's own sizes ([`LONE_WRITE_FROM`] to under
/// [`LONE_WRITE_UNDER`]). `ask.on` is [`lone_write_knob`], and `ask.in_memory`
/// is the window guard alone: no system that ships the lone write has a
/// sample of the page cache.
#[cfg(feature = "parallel")]
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) fn lone_written_stored(
    ask: LoneWideAsk,
    members: impl Iterator<Item = (bool, u8, bool, bool, bool, u64)>,
) -> bool {
    if !ask.extract || !ask.on || !ask.one_plain_volume || !ask.in_memory || ask.stated {
        return false;
    }
    let mut files = members.filter(|member| !member.0);
    match (files.next(), files.next()) {
        (Some((_, method, encrypted, crc32, split, size)), None) => {
            method == 0
                && !encrypted
                && crc32
                && !split
                && (LONE_WRITE_FROM..LONE_WRITE_UNDER).contains(&size)
        }
        _ => false,
    }
}

impl Run<'_> {
    /// The lone wide rule's answer as the walk takes it: off Windows, as
    /// it is ([`lone_wide_stored`]).
    #[cfg(all(feature = "parallel", not(windows)))]
    #[inline(always)]
    pub(super) fn lone_written(&self, wide: bool, _window: bool, _threads: Option<u64>) -> bool {
        // COUNT ONLY (feature `read-depth-knob`): the lone write takes
        // nothing here (`tests/lone_write_windows.rs`).
        #[cfg(feature = "read-depth-knob")]
        if std::env::var("RARFAST_LONE_WRITE_SAY").is_ok_and(|v| v.trim() == "1") {
            eprintln!("rarfast lone write: not taken");
        }
        wide
    }

    /// On Windows, whether the lone write takes this run's member
    /// ([`lone_written_stored`]), stated for its writer (`lone_write::state`);
    /// where it does the lone wide rule does not, so the answer is `wide`
    /// and not the lone write.
    #[cfg(all(feature = "parallel", windows))]
    pub(super) fn lone_written(&self, wide: bool, window: bool, threads: Option<u64>) -> bool {
        let lone = lone_written_stored(
            LoneWideAsk {
                extract: matches!(self.mode, Mode::Extract { .. }),
                on: lone_write_knob(),
                one_plain_volume: self.volumes.len() == 1 && !self.volumes[0].solid,
                in_memory: !window,
                stated: threads == Some(1) || self.opts.memory_cap.is_some(),
            },
            self.selected.iter().map(|index| {
                let planned = &self.plan[*index];
                let member = &planned.member;
                let split =
                    planned.fragments.len() > 1 || member.split_before || planned.split_after_last;
                (
                    member.is_dir,
                    member.method,
                    member.encrypted,
                    member.crc32.is_some(),
                    split,
                    member.size,
                )
            }),
        );
        super::lone_write::state(lone);
        // COUNT ONLY (feature `read-depth-knob`): `RARFAST_LONE_WRITE_SAY=1`
        // says whether the lone write took the run's member, which is what
        // `tests/lone_write_windows.rs` reads.
        #[cfg(feature = "read-depth-knob")]
        if std::env::var("RARFAST_LONE_WRITE_SAY").is_ok_and(|v| v.trim() == "1") {
            eprintln!(
                "rarfast lone write: {}",
                if lone { "taken" } else { "not taken" }
            );
        }
        wide && !lone
    }
}

/// How far ahead of the bytes written the lone write sets its file's end
/// ([`lone_write_end`]): the extract's own reserve step (`RESERVE_STEP`,
/// 8 MiB). A run killed mid member leaves at most this much of zeros past
/// its bytes, and never the member's declared length.
///
/// Screened on the Windows desktop the lone write was counted on (a plain
/// build, the step read at run time, K=15, a quiet box, 19 Oct 2026; main
/// over each arm, above 1 faster, at 16 and 32 MiB, `x` and `e`): the end
/// set at the declared length at the first write (the form before this)
/// 1.080 to 1.115; the end never moved, the writer thread alone, 1.067 to
/// 1.087; steps of 1 MiB 1.060 to 1.087, 2 MiB 1.074 to 1.102, 4 MiB 1.061
/// to 1.087, and 8 MiB 1.099 to 1.110, the best of them on every row and
/// level with or ahead of the declared length at once on three of four.
#[cfg(feature = "parallel")]
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) const LONE_WRITE_STEP: u64 = super::output::RESERVE_STEP;

/// The end the lone write's file is given before a write of `len` bytes
/// at `written`, where its end is `end` now and the member declares
/// `declared`: unmoved while the write fits; else a step
/// ([`LONE_WRITE_STEP`]) past the write, but NEVER the declared length
/// itself. The file reaches its declared length only by the member's own
/// last bytes, so a file that stands at that length under the member's name
/// holds them all (the promise: a killed run must never leave a file
/// a downloader would read as complete).
///
/// So the writes inside the end extend nothing, which is what the end set
/// ahead is for, and the last write past `declared - 1` extends the file by
/// its own bytes, once.
#[cfg(feature = "parallel")]
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) const fn lone_write_end(end: u64, written: u64, len: u64, declared: u64) -> u64 {
    let want = written.saturating_add(len);
    if want <= end {
        return end;
    }
    let ahead = want.saturating_add(LONE_WRITE_STEP);
    let most = declared.saturating_sub(1);
    let to = if ahead < most { ahead } else { most };
    if to > end {
        to
    } else {
        end
    }
}

/// Whether this build is for macOS, and for Linux, as the per-system
/// answers of [`lone_wide_stored`] read it (Windows is `cfg!(windows)`).
#[cfg(feature = "parallel")]
const ON_MACOS: bool = cfg!(target_os = "macos");
#[cfg(feature = "parallel")]
const ON_LINUX: bool = cfg!(target_os = "linux");
