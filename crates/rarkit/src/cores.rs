//! How many PHYSICAL cores this process may run on.
//!
//! `std::thread::available_parallelism` counts hardware THREADS: on a box
//! with simultaneous multithreading it counts each core twice, and two
//! threads of one core share its execution units and its first level
//! caches. A stage whose wall is one serial thread (the tape decode's
//! apply, SPEC-H2 3.8) loses when a lane is scheduled beside that thread
//! on the same core, so the tape's DEFAULT width is sized from this count
//! and not from the threads (`rar5_lz::tape::workers`).
//!
//! Asked once a process, and cheap where it is asked: Linux reads one
//! short sysfs file per CPU in the affinity mask, macOS one `sysctl`,
//! Windows one `GetLogicalProcessorInformation`. Anything that cannot be
//! read, and every other target, answers the thread count, which is what
//! every caller used before this existed. Never above the thread count,
//! so a CPU quota (a cgroup's `cpu.max`, which `available_parallelism`
//! reads) still binds, and never below one.

/// The hardware threads this process may run on, at least one.
pub(crate) fn logical() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
}

/// The physical cores this process may run on: [`logical`] with SMT
/// siblings counted once, at least one and never above [`logical`].
pub(crate) fn physical() -> usize {
    static PHYSICAL: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *PHYSICAL.get_or_init(|| {
        let logical = logical();
        read_physical().map_or(logical, |n| n.min(logical)).max(1)
    })
}

/// The CPU time the calling thread has run for, user and system together,
/// where the system keeps such a clock by the thread (Linux and macOS:
/// `CLOCK_THREAD_CPUTIME_ID`); `None` everywhere else, and where the call
/// fails. Beside a wall clock it says whether a thread RAN or WAITED: a
/// thread blocked on a source accrues none.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(unsafe_code)]
pub(crate) fn thread_cpu() -> Option<std::time::Duration> {
    // SAFETY: `timespec` is plain integers, for which all zeroes is a
    // value.
    let mut spent: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: `spent` is a live, writable `timespec`, which is all the
    // call requires; the clock named is this thread's own.
    let ok = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut spent) };
    if ok != 0 {
        return None;
    }
    Some(std::time::Duration::new(
        u64::try_from(spent.tv_sec).ok()?,
        u32::try_from(spent.tv_nsec).ok()?,
    ))
}

/// No such clock is read here: the caller keeps what it had.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn thread_cpu() -> Option<std::time::Duration> {
    None
}

/// macOS only. The cores of every performance level this machine does
/// not name "Efficiency": on Apple silicon its fast cores, with the
/// efficiency cores left out (an M1 Ultra 16 of 20, an M3 Ultra 24 of 32,
/// an M5 Ultra, whose two levels are "Super" and "Performance", all 36).
/// Where a level's name or count cannot be read, the first level alone;
/// where no level can be read at all (an Intel Mac has one kind of core
/// and reports none), `None`, and the caller keeps what it had: an Intel
/// Mac of many cores is a machine with no row behind it either. Never
/// above [`physical`] and at least one.
///
/// The tree walk's cap is sized from this and not from [`physical`]
/// (`encode::drive::tree_walkers_most`): a bin of one chunk waits for the
/// same bin of the chunk before it, so a walker on a slow core holds up
/// the walkers behind it. Timed 1 Oct 2026 (K=5, level 5, the same bytes
/// in every arm, one binary): on an M3 Ultra (24 performance and 8
/// efficiency cores) a solid tree of small files read 1.04x faster at 24
/// walkers than at 12 and 0.97x at 32; an M1 Ultra (16 and 4) had read
/// 1.01x at 16 and 0.96x at 20. On an M5 Ultra (12 and 24, no efficiency
/// level; a desktop in use, K=3, indicative) the same tree read 1.10x at
/// 36 and text64 1.83x, so a second level of fast cores counts
/// (measured 1 Oct 2026). No other system asks
/// at all: a machine with no row behind it keeps the walk it had.
#[cfg(target_os = "macos")]
pub(crate) fn performance() -> Option<usize> {
    static PERFORMANCE: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    *PERFORMANCE.get_or_init(|| read_performance().map(|n| n.min(physical()).max(1)))
}

/// x86-64 Linux only, and only with the pool (the `parallel` feature: its
/// one caller is the pool's). [`physical`], where every core of this
/// machine is of ONE kind; `None` where the kernel names a second kind, and the caller
/// keeps what it had.
///
/// The walk of a member that keeps the tree by its own class is sized
/// from this on x86-64 Linux (`encode::drive::tree_walkers_by_class`),
/// for the reason [`performance`]
/// gives on macOS: a bin of one chunk waits for the same bin of the chunk
/// before it, so a walker on a slow core holds up the walkers behind it,
/// and a machine of two kinds of core has no row behind it. A hybrid
/// Intel part is told by the second event source its kernel registers for
/// the small cores (`/sys/devices/cpu_atom`). A part whose cores differ
/// with nothing in sysfs to say so (some AMD parts mix cores of two
/// sizes) reads as one kind: it has no measured row yet, like the hybrid part.
#[cfg(all(feature = "parallel", target_os = "linux", target_arch = "x86_64"))]
pub(crate) fn alike() -> Option<usize> {
    static ALIKE: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    *ALIKE.get_or_init(|| (!std::path::Path::new("/sys/devices/cpu_atom").exists()).then(physical))
}

/// The distinct cores among `allowed` CPUs, where `siblings(cpu)` is that
/// CPU's sibling list in the kernel's list form ("0,8", "0-1", "3").
/// Two CPUs are one core when their lists name the same first CPU, which
/// the kernel prints in ascending order. `None` when any CPU's list
/// cannot be read or parsed, or when no CPU is allowed: a partial count
/// would be an undercount.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn distinct_cores(
    allowed: impl IntoIterator<Item = usize>,
    mut siblings: impl FnMut(usize) -> Option<String>,
) -> Option<usize> {
    let mut firsts: Vec<usize> = Vec::new();
    for cpu in allowed {
        let list = siblings(cpu)?;
        let first = list
            .trim()
            .split([',', '-'])
            .next()
            .and_then(|n| n.trim().parse::<usize>().ok())?;
        firsts.push(first);
    }
    firsts.sort_unstable();
    firsts.dedup();
    (!firsts.is_empty()).then_some(firsts.len())
}

/// Linux: the CPUs in this thread's affinity mask, grouped by core
/// through `/sys/devices/system/cpu/cpuN/topology/thread_siblings_list`.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn read_physical() -> Option<usize> {
    // SAFETY: `cpu_set_t` is plain bits, for which all zeroes is the
    // empty set.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    // SAFETY: `set` is a live, writable `cpu_set_t` and the size passed is
    // its own, which is all the call requires; pid 0 is this thread.
    let ok =
        unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) };
    if ok != 0 {
        return None;
    }
    let bits = 8 * std::mem::size_of::<libc::cpu_set_t>();
    // SAFETY: `set` is initialised and `cpu` is below its size in bits.
    let allowed = (0..bits).filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, &set) });
    distinct_cores(allowed, |cpu| {
        std::fs::read_to_string(format!(
            "/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list"
        ))
        .ok()
    })
}

/// macOS: `hw.physicalcpu`. Apple silicon has no SMT, so there it equals
/// the thread count; an Intel Mac with Hyper-Threading reads half.
#[cfg(target_os = "macos")]
fn read_physical() -> Option<usize> {
    sysctl_count(c"hw.physicalcpu")
}

/// macOS: `hw.nperflevels` levels, each with a name and its physical
/// cores (`hw.perflevelN.name`, `hw.perflevelN.physicalcpu`), summed by
/// [`fast_cores`]. Absent on an Intel Mac, which has one kind of core.
#[cfg(target_os = "macos")]
fn read_performance() -> Option<usize> {
    let levels = sysctl_count(c"hw.nperflevels")?;
    fast_cores(levels, |level| {
        let name = std::ffi::CString::new(format!("hw.perflevel{level}.name")).ok()?;
        let cores = std::ffi::CString::new(format!("hw.perflevel{level}.physicalcpu")).ok()?;
        Some((sysctl_text(&name)?, sysctl_count(&cores)?))
    })
}

/// The cores of every one of `levels` performance levels whose name is not
/// "Efficiency", where `level(n)` is level `n`'s name and cores. A level
/// that cannot be read makes the answer the first level's cores alone,
/// since a partial sum would count nobody knows what; `None` where the
/// first level itself cannot be read or there is no level.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn fast_cores(
    levels: usize,
    mut level: impl FnMut(usize) -> Option<(String, usize)>,
) -> Option<usize> {
    if levels == 0 {
        return None;
    }
    let (first_name, first) = level(0)?;
    let mut fast = if first_name.eq_ignore_ascii_case("Efficiency") {
        0
    } else {
        first
    };
    for index in 1..levels {
        let Some((name, cores)) = level(index) else {
            return Some(first);
        };
        if !name.eq_ignore_ascii_case("Efficiency") {
            fast += cores;
        }
    }
    Some(if fast == 0 { first } else { fast })
}

/// macOS: one text `sysctl` by name, `None` where the name is unknown or
/// the value is not text of fewer than 64 bytes.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn sysctl_text(name: &std::ffi::CStr) -> Option<String> {
    let mut value = [0u8; 64];
    let mut size = value.len();
    // SAFETY: the name is NUL terminated, `value` is a live buffer and
    // `size` names its length, so the call writes at most that many bytes
    // and leaves in `size` how many it wrote; no new value is set.
    let ok = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            value.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if ok != 0 || size == 0 || size > value.len() {
        return None;
    }
    let text = &value[..size];
    let text = text.split(|&byte| byte == 0).next()?;
    (!text.is_empty())
        .then(|| std::str::from_utf8(text).ok().map(str::to_owned))
        .flatten()
}

/// macOS: one positive integer `sysctl` by name, `None` where the name is
/// unknown or the value is not a positive `int`.
#[cfg(target_os = "macos")]
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

/// Windows: the processor-core entries `GetLogicalProcessorInformation`
/// reports for this process's processor group.
#[cfg(windows)]
#[allow(unsafe_code)]
fn read_physical() -> Option<usize> {
    /// `SYSTEM_LOGICAL_PROCESSOR_INFORMATION`: the mask, the relationship
    /// and a sixteen byte union this reader does not look inside.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Info {
        mask: usize,
        relationship: u32,
        union: [u64; 2],
    }
    /// `RelationProcessorCore`.
    const PROCESSOR_CORE: u32 = 0;
    #[link(name = "kernel32")]
    extern "system" {
        #[allow(non_snake_case)]
        fn GetLogicalProcessorInformation(buffer: *mut Info, length: *mut u32) -> i32;
    }
    let mut length: u32 = 0;
    // SAFETY: a null buffer with a length of zero asks only for the length
    // needed, which the call writes into `length`.
    unsafe { GetLogicalProcessorInformation(std::ptr::null_mut(), &mut length) };
    let entries = usize::try_from(length).ok()? / std::mem::size_of::<Info>();
    if entries == 0 {
        return None;
    }
    let blank = Info {
        mask: 0,
        relationship: u32::MAX,
        union: [0; 2],
    };
    let mut infos = vec![blank; entries];
    let mut length = u32::try_from(entries * std::mem::size_of::<Info>()).ok()?;
    // SAFETY: `infos` holds `length` writable bytes of `Info`, the layout
    // the call writes, and it writes no more than `length` says.
    let ok = unsafe { GetLogicalProcessorInformation(infos.as_mut_ptr(), &mut length) };
    if ok == 0 {
        return None;
    }
    let written = usize::try_from(length).ok()? / std::mem::size_of::<Info>();
    let cores = infos
        .iter()
        .take(written)
        .filter(|info| info.relationship == PROCESSOR_CORE && info.mask != 0)
        .count();
    (cores > 0).then_some(cores)
}

/// Every other target: not read, so the thread count stands.
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn read_physical() -> Option<usize> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smt_siblings_count_once() {
        // Eight cores, two threads each, numbered as Linux numbers an
        // EPYC 4345P: CPU n and CPU n + 8 are one core.
        let list = |cpu: usize| Some(format!("{},{}\n", cpu % 8, cpu % 8 + 8));
        assert_eq!(distinct_cores(0..16, list), Some(8));
        // An affinity mask of one thread per core, and of both threads
        // of four cores.
        assert_eq!(distinct_cores(0..8, list), Some(8));
        assert_eq!(distinct_cores([0, 1, 2, 3, 8, 9, 10, 11], list), Some(4));
    }

    #[test]
    fn range_lists_and_lone_threads() {
        let pairs = |cpu: usize| Some(format!("{}-{}", cpu & !1, cpu | 1));
        assert_eq!(distinct_cores(0..6, pairs), Some(3));
        let lone = |cpu: usize| Some(cpu.to_string());
        assert_eq!(distinct_cores(0..12, lone), Some(12));
    }

    #[test]
    fn an_unreadable_or_empty_answer_is_none() {
        assert_eq!(
            distinct_cores(0..4, |cpu| (cpu != 2).then(|| "0".into())),
            None
        );
        assert_eq!(distinct_cores(0..4, |_| Some("x".into())), None);
        assert_eq!(distinct_cores([], |_| Some("0".into())), None);
    }

    #[test]
    fn physical_is_between_one_and_the_threads() {
        assert!((1..=logical()).contains(&physical()));
    }

    #[cfg(all(feature = "parallel", target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn alike_is_the_cores_or_nothing() {
        // `None` on a machine whose kernel names a second kind of core.
        if let Some(cores) = alike() {
            assert_eq!(cores, physical());
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn performance_is_between_one_and_the_cores() {
        // `None` on a Mac that reports no performance level.
        if let Some(fast) = performance() {
            assert!((1..=physical()).contains(&fast));
        }
    }

    /// A level list as a machine reports it.
    fn levels<'a>(
        list: &'a [(&'a str, usize)],
    ) -> impl FnMut(usize) -> Option<(String, usize)> + 'a {
        |index| {
            list.get(index)
                .map(|&(name, cores)| (name.to_owned(), cores))
        }
    }

    #[test]
    fn every_level_but_the_efficiency_level_counts() {
        // An M3 Ultra, an M1 Ultra, and an M5 Ultra, whose second level is
        // a fast one.
        let m3 = [("Performance", 24), ("Efficiency", 8)];
        assert_eq!(fast_cores(2, levels(&m3)), Some(24));
        let m1 = [("Performance", 16), ("Efficiency", 4)];
        assert_eq!(fast_cores(2, levels(&m1)), Some(16));
        let m5 = [("Super", 12), ("Performance", 24)];
        assert_eq!(fast_cores(2, levels(&m5)), Some(36));
    }

    #[test]
    fn three_levels_count_the_two_that_are_not_efficiency() {
        let three = [("Super", 4), ("Performance", 8), ("Efficiency", 6)];
        assert_eq!(fast_cores(3, levels(&three)), Some(12));
        // Wherever the efficiency level sits, and however it is cased.
        let middle = [("Super", 4), ("efficiency", 6), ("Performance", 8)];
        assert_eq!(fast_cores(3, levels(&middle)), Some(12));
    }

    #[test]
    fn a_level_that_cannot_be_read_leaves_the_first_alone() {
        // The second level's name is missing: the first level's cores.
        let one = [("Super", 12)];
        assert_eq!(fast_cores(2, levels(&one)), Some(12));
        // The first level itself unreadable, or no level: no answer, and
        // the physical cores stand.
        assert_eq!(fast_cores(2, |_| None), None);
        assert_eq!(fast_cores(0, levels(&one)), None);
        // Nothing but efficiency cores is no machine, and is the first.
        let slow = [("Efficiency", 4)];
        assert_eq!(fast_cores(1, levels(&slow)), Some(4));
    }
}
