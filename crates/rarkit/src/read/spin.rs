//! The read pool's no-park waits, BOUNDED: a sweep that reads the clock
//! once every few polls, and that stops sweeping at once on a box whose
//! run queue is longer than its cores.
//!
//! Every wait in the read pool has the same shape (`read::concurrent`'s
//! worker task wait and the walk's two answer waits, `read::sequential`'s
//! look-ahead waits): poll a channel, and if nothing is there, poll again
//! until a budget of about 100 us is spent, then park. Two things about
//! that shape cost more than the wait they save, and both are measured
//! (30 Sep 2026):
//!
//! - **The clock was read on EVERY poll.** An empty channel poll is a few
//!   loads; `Instant::now` is a call into the vDSO (Linux) or the
//!   commpage (macOS) of several times that. On the 9,681 member set 23 to
//!   47 percent of `t`'s and 41 percent of `x`'s user instructions were
//!   the clock. Here it is read once every [`POLLS_PER_CLOCK`] polls: the
//!   budget is overshot by at most that many polls, well under a
//!   microsecond, and a poll that finds work still returns at once.
//! - **A waiter that is descheduled mid-sweep keeps sweeping when it comes
//!   back**, and on a loaded box every sweeping worker is a thread the
//!   run queue has to find a core for, so the walk, the one thread every
//!   member passes through, waits behind them. That is the 18,478
//!   involuntary switches against 7zz's 994 on an Apple M3 Mac, and the
//!   walk-only arm 3 to 5x faster in wall than the pool on a loaded
//!   x86-64 box. Here a waiter that sees a gap between two of its own
//!   clock reads longer than its whole budget knows it lost its core,
//!   parks at once, and MARKS it: every wait that starts within
//!   [`HOLD_US`] of a mark parks without sweeping. The mark is the load
//!   signal, measured by the waits themselves, on every operating system,
//!   at no cost on a quiet box (no waiter is descheduled, so no mark is
//!   ever made and the sweep is the one that shipped).
//!
//! Nothing a wait returns changes: the same item from the same channel,
//! in the same order. The park is the one each site already had (a
//! channel's `recv`, or the condition variable the producer notifies), so
//! the producer's wake-up is untouched. Only how long a waiter sweeps
//! before it parks is different.
//!
//! **`RARKIT_POOL_WAIT`** ([`POOL_WAIT_ENV`]) sets the form, read once per
//! process, so that one binary can be timed against itself:
//! `legacy` is the form that shipped before (the
//! clock on every poll, no mark, the walk's two sweeps back to back);
//! `every=N` reads the clock every N polls; `hold=US` sets the hold after
//! a mark, `hold=0` turns the mark off. Two more are a bench's dials and
//! no default: `spin=US` sets every wait's budget (0 parks at once), and
//! `report` says each mark on stderr. Items separated by commas; an
//! unreadable item is ignored and leaves its default.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// The environment variable that sets the wait's form (see the module
/// header).
pub(crate) const POOL_WAIT_ENV: &str = "RARKIT_POOL_WAIT";

/// Polls between two clock reads.
///
/// At a few nanoseconds a poll the budget is overshot by well under a
/// microsecond, against a budget of 100; the clock's share of a sweep
/// falls by the same factor.
pub(crate) const POLLS_PER_CLOCK: u32 = 32;

/// How long, in microseconds, every wait parks without sweeping after
/// some waiter found it had been descheduled mid-sweep.
///
/// Several of the scheduler slices a loaded box hands out (a few
/// milliseconds on Linux and macOS alike), so that one mark covers the
/// stretch of load it was made in rather than a sliver of it, and short
/// enough that a box which has gone quiet again is sweeping within a
/// fiftieth of a second.
///
/// **20 ms is TIMED, against 4 ms, both architectures.** One
/// binary, `RARKIT_POOL_WAIT=legacy` as the reference and a byte copy as
/// the null, small9k-r, small20k-r and tree5k, `t`, `p` and `x`, K=9.
/// Quiet, on a Zen 4 rental (EPYC 4345P, 16 threads) and an Apple M5 Air
/// (10 cores), every row of both holds is level with the old loops. Under
/// pure-spin burners on half the cores, 4 ms wins two x86-64 rows (1.10x,
/// 1.16x) and reads one at a 0.960x median inside its null's own spread;
/// 20 ms wins four (1.17x to 1.45x) at 0.55 to 0.67 of the CPU and no row
/// of either architecture has a median under 0.97x. At 4 ms a mark covered
/// too little of a loaded run to matter: 23 to 327 marks a run on
/// an Apple M3 Mac, the sweep resuming between them.
pub(crate) const HOLD_US: u64 = 20_000;

/// A gap between two of a waiter's clock reads shorter than this is never
/// read as a lost core, whatever the budget: a bench's budget of a few
/// microseconds must not mark every wait.
const OVERRUN_FLOOR: Duration = Duration::from_micros(50);

/// The form in force, read once per process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Form {
    /// The form that shipped before: the clock on every poll, no mark, and
    /// the walk's sweep followed by a second sweep on one worker.
    pub(crate) legacy: bool,
    /// Polls between two clock reads, at least 1.
    pub(crate) every: u32,
    /// The hold after a mark, in nanoseconds; 0 makes no mark.
    pub(crate) hold_ns: u64,
    /// Every wait's budget in microseconds, in place of the site's own
    /// (`spin=US`; 0 parks at once). A bench's dial, `None` in the engine.
    pub(crate) spin: Option<u64>,
    /// Say each mark on stderr (`report`). A bench's dial.
    pub(crate) report: bool,
}

impl Form {
    const SHIPPED: Form = Form {
        legacy: false,
        every: POLLS_PER_CLOCK,
        hold_ns: HOLD_US * 1_000,
        spin: None,
        report: false,
    };
}

/// Parse `RARKIT_POOL_WAIT`'s text (see the module header).
pub(crate) fn parse_form(text: &str) -> Form {
    let mut form = Form::SHIPPED;
    for item in text.split(',').map(str::trim) {
        if item.eq_ignore_ascii_case("legacy") {
            form.legacy = true;
        } else if let Some(n) = item.strip_prefix("every=") {
            if let Ok(n) = n.trim().parse::<u32>() {
                form.every = n.max(1);
            }
        } else if let Some(us) = item.strip_prefix("hold=") {
            if let Ok(us) = us.trim().parse::<u64>() {
                form.hold_ns = us.saturating_mul(1_000);
            }
        } else if let Some(us) = item.strip_prefix("spin=") {
            if let Ok(us) = us.trim().parse::<u64>() {
                form.spin = Some(us);
            }
        } else if item.eq_ignore_ascii_case("report") {
            form.report = true;
        }
    }
    if form.legacy {
        form.every = 1;
        form.hold_ns = 0;
    }
    form
}

/// The form in force for this process.
pub(crate) fn form() -> Form {
    static FORM: OnceLock<Form> = OnceLock::new();
    *FORM.get_or_init(|| parse_form(&crate::knob::reader_var(POOL_WAIT_ENV).unwrap_or_default()))
}

/// Whether the walk's answer wait is the one that shipped before: a sweep
/// of every worker, then a second sweep on the oldest one.
pub(crate) fn legacy() -> bool {
    form().legacy
}

/// The instant the marks are counted from.
fn epoch() -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

/// Nanoseconds after [`epoch`] until which every wait parks at once.
static HELD_UNTIL: AtomicU64 = AtomicU64::new(0);

/// Marks made since the process started: a count for a bench to read.
static MARKS: AtomicU64 = AtomicU64::new(0);

fn since_epoch(at: Instant) -> u64 {
    u64::try_from(at.saturating_duration_since(epoch()).as_nanos()).unwrap_or(u64::MAX)
}

fn held(at: Instant) -> bool {
    since_epoch(at) < HELD_UNTIL.load(Ordering::Relaxed)
}

fn mark(at: Instant, hold_ns: u64) {
    HELD_UNTIL.fetch_max(since_epoch(at).saturating_add(hold_ns), Ordering::Relaxed);
    let n = MARKS.fetch_add(1, Ordering::Relaxed) + 1;
    if form().report {
        eprintln!(
            "rarkit pool wait: mark {n} at {} us",
            since_epoch(at) / 1_000
        );
    }
}

/// Marks made so far in this process.
#[cfg(test)]
fn marks() -> u64 {
    MARKS.load(Ordering::Relaxed)
}

/// One wait's sweep: ask [`Spin::over`] after every poll that found
/// nothing, and park once it says so.
///
/// ```text
/// let mut spin = Spin::new(budget_us);
/// loop {
///     if let Some(item) = poll() { return item; }
///     if spin.over() { return park(); }
///     std::hint::spin_loop();
/// }
/// ```
pub(crate) struct Spin {
    until: Instant,
    last: Instant,
    gap: Duration,
    polls: u32,
    every: u32,
    hold_ns: u64,
    /// Park at the first ask: no budget, a hold was in force, or the
    /// sweep is over.
    park: bool,
}

impl Spin {
    /// A sweep of at most `micros` microseconds, in the process's form.
    pub(crate) fn new(micros: u64) -> Spin {
        Spin::with(micros, form())
    }

    /// A sweep of at most `micros` microseconds, in `form`.
    pub(crate) fn with(micros: u64, form: Form) -> Spin {
        let micros = form.spin.unwrap_or(micros);
        let start = Instant::now();
        let budget = Duration::from_micros(micros);
        let park = micros == 0 || (form.hold_ns != 0 && held(start));
        Spin {
            until: start + budget,
            last: start,
            gap: budget.max(OVERRUN_FLOOR),
            polls: 0,
            every: form.every.max(1),
            hold_ns: form.hold_ns,
            park,
        }
    }

    /// Whether this wait parks without sweeping at all.
    pub(crate) fn parks_at_once(&self) -> bool {
        self.park
    }

    /// Whether the sweep is over and the waiter should park now. Called
    /// once after each poll that found nothing.
    #[inline]
    pub(crate) fn over(&mut self) -> bool {
        if self.park {
            return true;
        }
        self.polls += 1;
        if self.polls < self.every {
            return false;
        }
        self.polls = 0;
        let at = Instant::now();
        if self.hold_ns != 0 && at.saturating_duration_since(self.last) > self.gap {
            // Descheduled between two reads: the box has more runnable
            // threads than cores. Stop, and tell every other wait.
            mark(at, self.hold_ns);
            self.park = true;
            return true;
        }
        self.last = at;
        if at >= self.until {
            self.park = true;
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::mpsc::{sync_channel, Receiver};
    use std::sync::Arc;

    /// `next_on`'s shape, over [`Spin::with`] so a test can pick the form.
    fn next(rx: &Receiver<u64>, micros: u64, form: Form) -> Option<u64> {
        let mut spin = Spin::with(micros, form);
        if spin.parks_at_once() {
            return rx.recv().ok();
        }
        loop {
            match rx.try_recv() {
                Ok(v) => return Some(v),
                Err(std::sync::mpsc::TryRecvError::Disconnected) => return None,
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
            if spin.over() {
                return rx.recv().ok();
            }
            std::hint::spin_loop();
        }
    }

    const FORMS: [Form; 3] = [
        Form::SHIPPED,
        Form {
            legacy: true,
            every: 1,
            hold_ns: 0,
            spin: None,
            report: false,
        },
        Form {
            legacy: false,
            every: 1_000_000,
            hold_ns: 0,
            spin: None,
            report: false,
        },
    ];

    #[test]
    fn the_text_sets_the_form() {
        assert_eq!(parse_form(""), Form::SHIPPED);
        assert_eq!(parse_form("nonsense, every=x"), Form::SHIPPED);
        let legacy = parse_form(" legacy ");
        assert!(legacy.legacy);
        assert_eq!(
            (legacy.every, legacy.hold_ns),
            (1, 0),
            "legacy is the old loop"
        );
        let f = parse_form("every=8,hold=250");
        assert_eq!((f.legacy, f.every, f.hold_ns), (false, 8, 250_000));
        assert_eq!(parse_form("every=0").every, 1, "at least one poll a read");
        assert_eq!(parse_form("hold=0").hold_ns, 0);
        assert_eq!(parse_form("spin=0").spin, Some(0));
        assert!(parse_form("report").report);
        assert!(Spin::with(100, parse_form("spin=0")).parks_at_once());
    }

    #[test]
    fn a_sweep_ends_near_its_budget() {
        for form in FORMS {
            let form = Form { hold_ns: 0, ..form };
            if form.every > 1_000 {
                continue;
            }
            let from = Instant::now();
            let mut spin = Spin::with(200, form);
            let mut polls = 0u64;
            while !spin.over() {
                polls += 1;
                std::hint::spin_loop();
            }
            let took = from.elapsed();
            assert!(polls > 0, "{form:?}: it swept");
            assert!(took >= Duration::from_micros(200), "{form:?}: {took:?}");
            // Generous: a shared test box may take the core away.
            assert!(took < Duration::from_millis(500), "{form:?}: {took:?}");
        }
    }

    #[test]
    fn no_budget_parks_at_once() {
        let mut spin = Spin::with(0, Form::SHIPPED);
        assert!(spin.parks_at_once());
        assert!(spin.over());
    }

    /// The name the test below is run by, alone, in a process of its own.
    const ALONE: &str = "RARKIT_TEST_SPIN_ALONE";

    /// A waiter that finds a gap longer than its budget between two of its
    /// own clock reads marks it, and a wait that starts inside the hold
    /// parks without sweeping.
    ///
    /// The hold is the PROCESS's, and so is the count of marks. On a
    /// loaded box other tests of this binary run real pool waits that
    /// mark, and a wait made inside THEIR hold parks at its first ask
    /// without a mark of its own, which is the rule: until 10 Oct 2026
    /// this test then went red at "and marks it" (seen 2 runs in 4 of the
    /// `read::` tests at a load of about 40, never alone). So it runs
    /// this binary again with this one test, where no other wait exists.
    /// The hold is a minute there, so a box slow to run the next line
    /// cannot outlast it.
    ///
    /// One thread, and no memory to speak of.
    #[test]
    fn a_lost_core_marks_and_the_next_wait_parks_at_once() {
        if std::env::var_os(ALONE).is_none() {
            let done = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "read::spin::tests::a_lost_core_marks_and_the_next_wait_parks_at_once",
                    "--exact",
                    "--test-threads=1",
                ])
                .env(ALONE, "1")
                .output()
                .unwrap();
            let said = String::from_utf8_lossy(&done.stdout);
            assert!(done.status.success(), "{done:?}");
            // The child ran the test, and did not pass over a name it
            // did not know.
            assert!(said.contains("1 passed"), "{said}");
            return;
        }
        let form = Form {
            every: 1,
            hold_ns: 60_000_000_000,
            ..Form::SHIPPED
        };
        let before = marks();
        let mut spin = Spin::with(100, form);
        assert!(!spin.parks_at_once(), "no hold is in force yet");
        // Stand in for the scheduler taking the core away mid-sweep.
        std::thread::sleep(Duration::from_millis(5));
        assert!(spin.over(), "a gap longer than the budget ends the sweep");
        assert_eq!(marks(), before + 1, "and marks it");
        assert!(
            Spin::with(100, form).parks_at_once(),
            "a wait inside the hold does not sweep"
        );
        assert!(
            !Spin::with(100, Form { hold_ns: 0, ..form }).parks_at_once(),
            "a form without the mark ignores it"
        );
        // A wait inside a hold parks at its first ask and makes no mark
        // of its own.
        let mut held = Spin::with(100, form);
        assert!(held.over());
        assert_eq!(marks(), before + 1, "a wait inside a hold makes no mark");
    }

    /// A consumer that has parked (its sweep long spent, nothing sent)
    /// wakes on the producer's send, in every form, with and without a
    /// hold in force.
    #[test]
    fn a_starved_consumer_wakes_on_produce() {
        for form in FORMS {
            for micros in [0u64, 100, 5_000] {
                let (tx, rx) = sync_channel::<u64>(1);
                let taker = std::thread::spawn(move || next(&rx, micros, form));
                std::thread::sleep(Duration::from_millis(30));
                tx.send(7).expect("the consumer is waiting");
                assert_eq!(
                    taker.join().expect("no panic"),
                    Some(7),
                    "{form:?} {micros}"
                );
                // And a closed channel ends a parked wait.
                let (tx, rx) = sync_channel::<u64>(1);
                let taker = std::thread::spawn(move || next(&rx, micros, form));
                std::thread::sleep(Duration::from_millis(30));
                drop(tx);
                assert_eq!(taker.join().expect("no panic"), None, "{form:?} {micros}");
            }
        }
    }

    /// Bursts with gaps between them, so the consumer is caught at every
    /// point of its wait (sweeping, just past its budget, parked): every
    /// item arrives, in order, and nothing hangs.
    #[test]
    fn no_lost_wake_up_under_a_burst() {
        const ITEMS: u64 = 60_000;
        for form in FORMS {
            for micros in [0u64, 3, 100] {
                let (tx, rx) = sync_channel::<u64>(1);
                let done = Arc::new(AtomicBool::new(false));
                let seen = done.clone();
                let taker = std::thread::spawn(move || {
                    let mut want = 0u64;
                    while let Some(v) = next(&rx, micros, form) {
                        assert_eq!(v, want, "in order");
                        want += 1;
                    }
                    seen.store(true, Ordering::SeqCst);
                    want
                });
                let mut state = 0x9e37_79b9_7f4a_7c15u64;
                for v in 0..ITEMS {
                    tx.send(v).expect("the consumer lives");
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    match state % 512 {
                        0 => std::thread::sleep(Duration::from_micros(200)),
                        1..=8 => std::thread::yield_now(),
                        9..=40 => {
                            let until = Instant::now() + Duration::from_micros(state % 150);
                            while Instant::now() < until {
                                std::hint::spin_loop();
                            }
                        }
                        _ => {}
                    }
                }
                drop(tx);
                let from = Instant::now();
                while !done.load(Ordering::SeqCst) {
                    assert!(
                        from.elapsed() < Duration::from_secs(60),
                        "{form:?} {micros}: the consumer hung"
                    );
                    std::thread::sleep(Duration::from_millis(1));
                }
                assert_eq!(taker.join().expect("no panic"), ITEMS, "{form:?} {micros}");
            }
        }
    }
}
