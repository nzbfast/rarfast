//! The rule: which form a member's output takes, from the archive's
//! residency, the device's verdict and the member's own facts.

use super::*;

/// A failure forced for a test, or the form chosen for a count. `Off` and
/// `Behind` are constructed by the `reserve-knob` measuring build alone,
/// and never by a test, so the shipped build and the test build carry
/// them unconstructed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[allow(dead_code)]
pub(crate) enum Forced {
    /// What ships.
    None,
    /// The unbuffered path is not taken at all.
    Off,
    /// The cached path with writeback behind the cursor (`writeback`).
    Behind,
    /// macOS's `F_NOCACHE` form, a count arm only.
    Nocache,
    /// The unbuffered open is refused.
    Open,
    /// The first direct write of a block (staged or straight) fails.
    Write,
    /// The tail's direct write fails.
    Tail,
    /// Every direct write fails as a full volume's does (`StorageFull`).
    Full,
    /// A write behind the end that must read its sector back fails
    /// (`Output`'s read-modify-write).
    Patch,
    /// Direct with the write-rate gate off: never timed, never falls back
    /// for the device's rate (the measuring arm beside the gated default).
    On,
    /// The gate's probe finds the device slow at the first direct write,
    /// whatever its rate: the fall back mid-file, forced.
    Slow,
}

/// What the run has said of the archive being read ([`note_source`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Source {
    /// The device it lives on, where that can be named.
    pub(super) device: Option<u64>,
    /// Whether it was in the page cache when the run began, where the rule
    /// on facts had it sampled; Unknown otherwise.
    pub(super) residency: Residency,
}

impl Source {
    pub(super) const NONE: Source = Source {
        device: None,
        residency: Residency::Unknown,
    };
}

pub(super) static SOURCE: std::sync::Mutex<Source> = std::sync::Mutex::new(Source::NONE);

/// What the run has noted of its archive.
pub(super) fn source() -> Source {
    *SOURCE.lock().unwrap_or_else(|p| p.into_inner())
}

/// Whether an extract's [`note_source`] should SAMPLE the archive's
/// residency: only under the rule on facts, and only where a member can be
/// written past the cache by an open flag at all. False in every shipped
/// build, so nothing is asked of the kernel there.
pub(crate) fn samples_source() -> bool {
    FLAG != 0 && rule() == Rule::Facts
}

/// Names the device the archive lives on (by its first volume, `volumes[0]`),
/// for [`form_at`]; an extract calls it once per archive before its first
/// member is opened.
///
/// With `sample` (the caller having asked [`samples_source`], and the run
/// holding a big stored member) the archive's residency is sampled here as
/// well, for [`facts_form`]: NOW, before the run's own reads bring the
/// archive into memory (by the time a device's verdict arrives a volume
/// set's first volume has been read whole, and would read as resident
/// whatever it was), and over the WHOLE set ([`whole_residency`]).
pub(crate) fn note_source<P: AsRef<Path>>(volumes: &[P], sample: bool) {
    let Some(first) = volumes.first() else {
        return;
    };
    let residency = if sample && rule() == Rule::Facts {
        let sampled: Vec<(Option<f64>, Residency)> = spread(volumes.len(), SAMPLED_VOLUMES)
            .into_iter()
            .map(|index| crate::residency::of(volumes[index].as_ref()))
            .collect();
        let residency = whole_residency(&sampled);
        #[cfg(all(not(test), feature = "reserve-knob"))]
        eprintln!(
            "rarfast write rule: Facts; archive residency {residency:?} ({} of {} volumes sampled, least {:?})",
            sampled.len(),
            volumes.len(),
            sampled
                .iter()
                .filter_map(|(fraction, _)| *fraction)
                .fold(None, |least: Option<f64>, f| Some(least.map_or(f, |l| l.min(f))))
        );
        residency
    } else {
        Residency::Unknown
    };
    *SOURCE.lock().unwrap_or_else(|p| p.into_inner()) = Source {
        device: device_at(first.as_ref()),
        residency,
    };
}

/// The most volumes of a set whose residency is sampled, sixty-four pages
/// each (`residency`): about twenty system calls a volume, once a run.
pub(super) const SAMPLED_VOLUMES: usize = 32;

/// Which of `count` volumes are sampled when at most `most` may be: all of
/// them, or `most` spread evenly from the first to the last, both included.
pub(super) fn spread(count: usize, most: usize) -> Vec<usize> {
    if count <= most || most < 2 {
        return (0..count.min(most.max(1))).collect();
    }
    (0..most).map(|i| i * (count - 1) / (most - 1)).collect()
}

/// The archive's residency for the rule on facts, from its sampled volumes:
/// RESIDENT only where EVERY sampled page of every sampled volume is in
/// memory; cold where any is not; unknown where nothing could be sampled.
///
/// Not the majority `residency` judges one file by, and not the first volume
/// alone, because the two mistakes do not cost the same here. An archive
/// called resident is written CACHED, and cached while the archive still
/// comes off its device is the slowest form there is: with the first 30
/// percent of a stored set of many members in memory (its first volumes whole, the first
/// volume's sample reading resident) the set landed on a second SATA SSD in
/// 25.4 s cached against 16.4 s by write-behind and 16.0 s direct, and with
/// 70 percent in memory in 19.0 s against 15.8 and 15.5
/// (1 Oct 2026, the partly resident cells). An
/// archive called cold that was in memory is written direct, which costs
/// nothing on disk and only the earlier return of the process.
pub(crate) fn whole_residency(sampled: &[(Option<f64>, Residency)]) -> Residency {
    let mut resident = false;
    for (fraction, verdict) in sampled {
        match (fraction, verdict) {
            (_, Residency::Unknown) => {}
            (Some(fraction), _) if *fraction < 1.0 => return Residency::Cold,
            (_, Residency::Cold) => return Residency::Cold,
            (_, Residency::Resident) => resident = true,
        }
    }
    if resident {
        Residency::Resident
    } else {
        Residency::Unknown
    }
}

/// The form a member of `declared` bytes and of kind `member` takes when it
/// is written into the directory `dir`, by a run whose stated memory cap
/// (`-mm`) is `memory_cap`: [`form`]'s, except that
///
/// - a STORED member that fits inside the run's working limit is cached on
///   Linux ([`stored_cached_up_to`]);
/// - a direct member goes [`slow_for`] where `dir`'s device is remembered
///   SLOW (no direct open just to fall back at the first put);
/// - and [`same_form`] where `dir` is on the device the archive is read
///   from.
pub(crate) fn form_at(declared: u64, dir: &Path, member: Member, memory_cap: Option<u64>) -> Form {
    let form = form(declared);
    if form != Form::Direct || forced() == Forced::On {
        return form;
    }
    // Unless a count build forces a form (`RARFAST_DIRECT`), which keeps
    // the direct rules below reachable for a stored member too.
    if member == Member::Stored
        && forced() == Forced::None
        && declared <= stored_cached_up_to(memory_cap)
    {
        return Form::Cached;
    }
    let device = device_at(dir);
    if device.is_none() {
        return form;
    }
    if remembered(device) == Some(Verdict::Slow) {
        return slow_for(device, Some(member), dir);
    }
    if device == source().device {
        return same_form();
    }
    form
}

/// Whether a STORED member of an extract that fits inside the run's
/// working limit is written through the cache where [`form`] would write
/// it direct: on Linux alone, each system on its own rows (FROM-STUDIO
/// 375 A: the bar is process wall).
///
/// **Linux, by process wall** (a Zen 4 rental, EPYC 4345P, ext4 on NVMe,
/// the archive on the output's own drive, `fstrim` before each `x`, K=3,
/// plain builds, 14 Oct 2026). Direct, a stored member's one writer sat
/// in its 4 MiB writes 1.34 s of a 1.37 s run, at the drive's own rate;
/// the 8 MiB reservation steps were 2.6 ms of it. The same binary with
/// the write cached:
///
/// | row | direct | cached | a `sync` after cached |
/// |---|---|---|---|
/// | 4 GiB, CRC32 | 1.19 to 1.20 s | 0.59 to 0.66 s | 1.20 s |
/// | 4 GiB, BLAKE2sp | 1.19 to 1.21 s | 0.81 to 0.82 s | 1.21 s |
/// | sixteen of 128 MiB | 0.59 to 0.61 s | 0.13 s | 0.60 s |
///
/// Write-behind read level with direct. So cached returns the process in
/// half the wall or less and leaves the bytes in the cache, as a cached
/// writer does; ON DISK it is the slower of the two (direct was first
/// shipped on that measure). A member larger than the working limit keeps
/// the direct form, so one larger than memory is written as before. A
/// coded member keeps [`form`]'s answer: its decode, not the drive, paces
/// it. Windows keeps direct, where its rows are ahead; macOS has no direct
/// form by default ([`FLAG`]).
pub(crate) const STORED_CACHED: bool = cfg!(target_os = "linux");

/// The largest stored member [`form_at`] writes cached
/// ([`STORED_CACHED`]): the run's WORKING LIMIT, which is the larger of
/// 512 MiB and a quarter of physical memory, never above a cgroup or
/// `RLIMIT_AS` cap (`MemoryPolicy::process_default`), and under a stated
/// `-mm` that budget's own (`MemoryPolicy::for_process`, as the read's
/// options derive it). 0 where the rule is off, so no member is.
pub(crate) fn stored_cached_up_to(memory_cap: Option<u64>) -> u64 {
    #[cfg(test)]
    if *TEST_STORED_DIRECT.lock().unwrap_or_else(|p| p.into_inner()) {
        return 0;
    }
    if !STORED_CACHED {
        return 0;
    }
    match memory_cap {
        Some(cap) => rarkit::MemoryPolicy::for_process(cap.max(1 << 17), 0).working_limit,
        None => {
            static LIMIT: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
            *LIMIT.get_or_init(|| rarkit::MemoryPolicy::process_default(0).working_limit)
        }
    }
}

/// Set by a test that reads the direct form's rules for a stored member.
#[cfg(test)]
pub(crate) static TEST_STORED_DIRECT: std::sync::Mutex<bool> = std::sync::Mutex::new(false);

/// Which rule gives a slow device's form.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Rule {
    /// The line alone ([`slow_form`]): what ships.
    Line,
    /// The rule on facts ([`facts_form`]), for a member of an extract.
    Facts,
}

/// The rule every shipped build runs.
pub(super) const RULE: Rule = Rule::Line;

/// [`RULE`]; in a `reserve-knob` build what `RARFAST_WRITE_RULE` says
/// (`facts`, `line`), so one binary times both; in a test, the rule the
/// test set (under `TEST_SERIAL`).
pub(super) fn rule() -> Rule {
    #[cfg(test)]
    {
        TEST_RULE
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .unwrap_or(RULE)
    }
    #[cfg(all(not(test), feature = "reserve-knob"))]
    {
        static SET: std::sync::OnceLock<Rule> = std::sync::OnceLock::new();
        *SET.get_or_init(|| {
            let rule = match std::env::var("RARFAST_WRITE_RULE")
                .unwrap_or_default()
                .trim()
            {
                "facts" => Rule::Facts,
                "line" => Rule::Line,
                _ => RULE,
            };
            eprintln!("rarfast write rule: {rule:?}");
            rule
        })
    }
    #[cfg(all(not(test), not(feature = "reserve-knob")))]
    {
        RULE
    }
}

/// The rule a test runs under, where one sets it (under [`TEST_SERIAL`]).
#[cfg(test)]
pub(crate) static TEST_RULE: std::sync::Mutex<Option<Rule>> = std::sync::Mutex::new(None);

/// How a member's bytes are produced, as far as the rule on facts asks.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Member {
    /// Stored: its bytes come as fast as the archive is read.
    Stored,
    /// Coded, in an archive that is not solid: such members are decoded
    /// several at once, each writing its own output.
    Coded,
    /// Coded, in a SOLID archive: one decoder, one output at a time.
    Solid,
}

/// Write-behind where the target has it (`writeback`: Linux with glibc), and
/// direct where it has not, for [`facts_form`]'s one write-behind row.
pub(super) const BEHIND_OR_DIRECT: Form = if cfg!(all(target_os = "linux", target_env = "gnu")) {
    Form::Behind
} else {
    Form::Direct
};

/// THE RULE ON FACTS: the form a member takes on a device the line found
/// SLOW (a fast device is direct and nothing here is asked).
///
/// - **A CODED member: direct.** The decoder paces the job, and bytes left
///   in the cache leave the device idle until the flusher wakes: on one SATA
///   SSD four big LZ members were on disk 1.36x to 1.43x sooner direct than
///   cached.
/// - **Except a coded member of a SOLID archive written to ANOTHER device:
///   write-behind**, the line's own form there, where the target has it
///   ([`BEHIND_OR_DIRECT`]). One decoder writes one output at a time, and a
///   direct write at depth 0 holds the decoder for its length; left to the
///   cache with writeback started behind the cursor, the device works while
///   the decoder does. Four big LZ members solid, one SATA SSD to another:
///   5.73 s on disk against 6.10 direct cold and 5.92 against 5.98 warm
///   (K=3), and the write-probe work's 5.91 against 6.01 and 5.64 against
///   6.00. On the archive's OWN device it stays direct (7.66 s against
///   10.77 cached, cold).
/// - **A STORED member whose archive is RESIDENT: cached.** Nothing reads
///   the device, direct lands the data only 1.09x to 1.14x sooner than
///   cached and returns the process 3.6x to 13x later (over the
///   ceiling set for it). Resident means the WHOLE archive ([`whole_residency`]); a
///   partly resident one is cold. Unknown reads as Resident, which is every
///   Windows run.
/// - **Stored, the archive COLD, the output on the archive's OWN device:
///   cached.** The kernel lets the read run first and writes the debt back
///   unopposed: direct was 0.89x to 0.97x on disk and twice the process
///   wall.
/// - **Stored, cold, on ANOTHER device: direct**, 1.09x to 1.17x sooner on
///   disk than write-behind and level with it by process.
/// - **Ahead of them all, an output on a PARITY ARRAY: cached**
///   (`device_class::parity`: an md raid4, 5 or 6 in the output device's
///   stack), where a direct write is slower than a cached one whoever
///   reads. Seen on Linux through md alone: a hardware controller's array
///   and a network share are not, and take the rows above.
///
/// (The rows: an i7 rental with two SATA SSDs of about 500 MB/s, K=3,
/// 1 Oct 2026.)
pub(crate) fn facts_form(member: Member, residency: Residency, same: bool, parity: bool) -> Form {
    if parity {
        return Form::Cached;
    }
    match (member, residency) {
        (Member::Coded, _) => Form::Direct,
        (Member::Solid, _) if same => Form::Direct,
        (Member::Solid, _) => BEHIND_OR_DIRECT,
        (Member::Stored, Residency::Resident | Residency::Unknown) => Form::Cached,
        (Member::Stored, Residency::Cold) if same => Form::Cached,
        (Member::Stored, Residency::Cold) => Form::Direct,
    }
}

/// The form an output on `device` takes where the gate finds it SLOW:
/// [`slow_form`] under the line, and for an archive's output (`member` is
/// `None`) under either rule; [`facts_form`] for a member under the rule on
/// facts, `path` being the output's file or its directory.
pub(crate) fn slow_for(device: Option<u64>, member: Option<Member>, path: &Path) -> Form {
    let (Rule::Facts, Some(member)) = (rule(), member) else {
        return slow_form(device);
    };
    let source = source();
    let same = device.is_some() && device == source.device;
    let parity = parity(device, path);
    let form = facts_form(member, source.residency, same, parity);
    #[cfg(all(not(test), feature = "reserve-knob"))]
    eprintln!(
        "rarfast write form: {form:?} (slow device; member {member:?}, archive {:?}, same device {same}, parity {parity})",
        source.residency
    );
    form
}

/// Whether `device`, which `path` is on, is a parity array
/// (`device_class::parity`), asked of sysfs once a device a process; a
/// device that cannot be named is asked each time. A test states it
/// (`TEST_PARITY`).
pub(super) fn parity(device: Option<u64>, path: &Path) -> bool {
    #[cfg(test)]
    {
        let _ = (device, path);
        TEST_PARITY.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        static MEMO: std::sync::Mutex<Vec<(u64, bool)>> = std::sync::Mutex::new(Vec::new());
        let Some(device) = device else {
            return crate::device_class::parity(path);
        };
        let mut memo = MEMO.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((_, parity)) = memo.iter().find(|(d, _)| *d == device) {
            return *parity;
        }
        let parity = crate::device_class::parity(path);
        memo.push((device, parity));
        parity
    }
}

#[cfg(test)]
thread_local! {
    /// Whether a test's output device is a parity array.
    pub(super) static TEST_PARITY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether this process runs under a CGROUP MEMORY CAP that binds the default
/// policy (`MemoryPolicy::environment_cap`, and not a finite `RLIMIT_AS`,
/// which counts no page cache): there an ARCHIVE's output stays direct
/// whatever its device's rate.
///
/// **Why.** A cgroup's limit counts the page cache its processes dirty, and
/// nothing blocks a writer at that limit: an archive written through the cache
/// to a device slower than the encoders fills what the process leaves of the
/// cap with unwritten pages, and the kernel kills the process. Counted 2 Oct 2026:
/// one 4 GiB
/// member on 96 threads to a 135 MB/s volume under `MemoryMax` 512M and 600M,
/// where the gate above finds the device slow and leaves direct writing: the
/// kernel's report at the kill read anon 388 MiB, inside the policy's 504 MiB
/// budget, and 200 MiB of dirty file pages, 4 MiB of them under writeback.
/// Three reps a cell: the shipped form, write-behind and cached were killed
/// 36 times of 36; direct kept lived 9 of 9 at level 1 under both caps and at
/// level 3 under 600M (the level 3 run under 512M dies of its own engines,
/// which is the writer's to fix). Past the cache the process runs at the
/// device's pace, which is the wall such a device allows either way; inside a
/// cap the cache is not there to lend.
///
/// A member's output on an extract is left as it was: its own count is not done yet.
pub(super) fn capped() -> bool {
    #[cfg(test)]
    if let Some(capped) = TEST_CAPPED.with(std::cell::Cell::get) {
        return capped;
    }
    static CAPPED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CAPPED.get_or_init(|| {
        let cap = rarkit::MemoryPolicy::process_default(0).environment_cap;
        cap > 0 && crate::workers::address_space_limit() != Some(cap)
    })
}

#[cfg(test)]
thread_local! {
    /// A test's answer to [`capped`], or `None` for the process's own.
    pub(super) static TEST_CAPPED: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// Where a slow verdict leaves an output's gate: shut, the next put falling
/// back, unless [`slow_for`] keeps it direct, which only the rule on facts
/// does.
pub(super) fn slow_gate(device: Option<u64>, member: Option<Member>, path: &Path) -> Gate {
    if slow_for(device, member, path) == Form::Direct {
        Gate::Open
    } else {
        Gate::Shut
    }
}

/// Where the gate finds `device` SLOW, the form the rest of an output and
/// every later one on it takes.
///
/// - **On another device than the archive's: WRITE-BEHIND on Linux with
///   glibc** (`writeback`). On an i7 rental, x from one Samsung SATA SSD to
///   another (about 500 MB/s; cold, K=3, on disk) the stored many-member set
///   landed in 16.15 s against cached's 28.90, 1.79x, and the 12 GiB member in 29.14
///   against 38.11, 1.31x, for 1.1 s and 5.5 s more process wall: with 64 GB
///   of memory the kernel writes nothing back while the archive is read, and
///   write-behind starts it. On a Zen 4 rental under a 500 MB/s cap, 25.74 s
///   against 27.52.
/// - **On the archive's OWN device: cached**, as before. One
///   drive cannot read and write faster than it does either, and
///   write-behind there only puts the two in each other's way: on
///   the i7 rental, one SATA SSD, the big member was on disk in 61.8 s by
///   write-behind against 55.3 s cached, and the process returned in 61.8 s
///   against 34.3 (the first version shipped write-behind there for a
///   day; found 1 Oct 2026).
/// - Cached elsewhere, where there is no write-behind.
///
/// A `reserve-knob` build takes `RARFAST_SLOW` (`cached`, `behind`) for a
/// device that is not the archive's and `RARFAST_SLOW_SAME` for one that is.
pub(crate) fn slow_form(device: Option<u64>) -> Form {
    let same = device.is_some() && device == source().device;
    if same {
        return knob_form("RARFAST_SLOW_SAME", Form::Cached);
    }
    let shipped = if cfg!(all(target_os = "linux", target_env = "gnu")) {
        Form::Behind
    } else {
        Form::Cached
    };
    knob_form("RARFAST_SLOW", shipped)
}

/// The form a member takes where it is written to the device its archive is
/// read from: DIRECT, the gate deciding as for any other device. A
/// `reserve-knob` build takes `RARFAST_SAME` (`cached`, `behind`, `direct`).
///
/// **A size rule was shipped here for one revision and withdrawn** (the rule:
/// cached below 4 GiB, from Zen 4 rental A's one-drive stored many-member set, COLD,
/// 1.015x cached against 0.984x direct). It forced every S8-shaped member
/// cached on one drive, and warm on a 3.3 GB/s NVMe that cost a many-member set's
/// extract a third (Zen 4 rental B: 3.02 s before, 4.03 s after; the
/// stored-solid extract rows, 1 Oct 2026): one writer at a time gets
/// the whole drive direct, and a cold pool of writers on one box is not the
/// warm case. The rule was a cold figure on one shape.
pub(crate) fn same_form() -> Form {
    knob_form("RARFAST_SAME", Form::Direct)
}

/// `shipped`, or in a `reserve-knob` build the form the variable `name`
/// names, read once for each name.
#[cfg_attr(not(all(not(test), feature = "reserve-knob")), allow(unused_variables))]
pub(super) fn knob_form(name: &'static str, shipped: Form) -> Form {
    #[cfg(all(not(test), feature = "reserve-knob"))]
    {
        type Set = Vec<(&'static str, Option<Form>)>;
        static SET: std::sync::Mutex<Set> = std::sync::Mutex::new(Vec::new());
        let mut set = SET.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((_, form)) = set.iter().find(|(n, _)| *n == name) {
            return form.unwrap_or(shipped);
        }
        let form = match std::env::var(name).unwrap_or_default().trim() {
            "cached" => Some(Form::Cached),
            "behind" => Some(Form::Behind),
            "direct" => Some(Form::Direct),
            _ => None,
        };
        eprintln!("rarfast {name}: {form:?}");
        set.push((name, form));
        form.unwrap_or(shipped)
    }
    #[cfg(not(all(not(test), feature = "reserve-knob")))]
    {
        shipped
    }
}

/// The unbuffered open, refused where a test forces it.
pub(crate) fn open_refused() -> bool {
    forced() == Forced::Open
}

#[cfg(test)]
pub(crate) static TEST_FORCED: std::sync::Mutex<Forced> = std::sync::Mutex::new(Forced::None);

/// Held by every test that sets [`TEST_FORCED`], so that one test's forced
/// failure is never read by another test's writer running beside it.
#[cfg(test)]
pub(crate) static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// What is forced: set by a test, or, in a build with the `reserve-knob`
/// measuring feature, by `RARFAST_DIRECT` (`off`, `behind`, `nocache`, `on`,
/// `slow`, `fail-open`, `fail-write`, `fail-tail`, `fail-full`, `fail-patch`).
/// Nothing, in every shipped build.
pub(super) fn forced() -> Forced {
    #[cfg(test)]
    {
        *TEST_FORCED.lock().unwrap_or_else(|p| p.into_inner())
    }
    #[cfg(all(not(test), feature = "reserve-knob"))]
    {
        static FORCED: std::sync::OnceLock<Forced> = std::sync::OnceLock::new();
        *FORCED.get_or_init(|| {
            let v = std::env::var("RARFAST_DIRECT").unwrap_or_default();
            let forced = match v.trim() {
                "off" => Forced::Off,
                "behind" => Forced::Behind,
                "nocache" => Forced::Nocache,
                "on" => Forced::On,
                "slow" => Forced::Slow,
                "fail-open" => Forced::Open,
                "fail-write" => Forced::Write,
                "fail-tail" => Forced::Tail,
                "fail-full" => Forced::Full,
                "fail-patch" => Forced::Patch,
                _ => Forced::None,
            };
            eprintln!("rarfast direct: {forced:?}");
            forced
        })
    }
    #[cfg(all(not(test), not(feature = "reserve-knob")))]
    {
        Forced::None
    }
}
