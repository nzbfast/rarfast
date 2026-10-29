//! The concurrent pool's queue of members the WALK handled
//! (`RARKIT_QUEUE_OWN`, `probe::set_queue_own`): a directory entry the
//! sink skipped, an empty member, a small one the walk decoded itself.
//!
//! Spec F 3.7.6 promises four things of `extract_parallel`, and the queue
//! may move none of them: every member's bytes are the sequential path's,
//! `close` is called in archive order, a member's failure is its own, and
//! the caller holds at most the promised number of writers open (twice the
//! breadth). What the queue changes is only WHEN the walk goes
//! on: it used to close every member in flight before it closed one of its
//! own, so an archive whose large members sit between directory entries
//! decoded them one at a time.

#![cfg(all(feature = "parallel", feature = "test-support"))]

use std::collections::HashMap;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::ThreadId;
use std::time::Duration;

use rarkit::{
    extract, extract_parallel, Disposition, Error, HostOs, MemberInfo, MemberOutcome, MemberSpec,
    ParallelSink, Payload, RangeSource, ReadOptions, Result, Sink, WriteMethod, WriteOptions,
    Writer,
};

/// Bytes a level 3 encoder half compresses, different for every `salt`.
fn body(bytes: usize, salt: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes + 64);
    let mut seed = 0x2026_1001_u64 ^ salt;
    while out.len() < bytes {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        out.extend_from_slice(b"the walk goes on past its own members ");
        out.extend_from_slice(&seed.to_le_bytes());
    }
    out.truncate(bytes);
    out
}

/// `groups` directories, each holding one member large enough to be
/// dispatched, one EMPTY member and one small member, in that order, so
/// every dispatched member is followed by three the walk handles itself.
fn archive(groups: usize, method: WriteMethod) -> Vec<u8> {
    let mut names = Vec::new();
    let mut bodies = Vec::new();
    for g in 0..groups {
        names.push((format!("d{g}").into_bytes(), true));
        bodies.push(Vec::new());
        names.push((format!("d{g}/large.bin").into_bytes(), false));
        bodies.push(body(96 * 1024 + g * 1000, g as u64));
        names.push((format!("d{g}/empty").into_bytes(), false));
        bodies.push(Vec::new());
        names.push((format!("d{g}/small.txt").into_bytes(), false));
        bodies.push(body(200 + g, 1000 + g as u64));
    }
    let mut writer = Writer::new(WriteOptions {
        method,
        ..WriteOptions::default()
    })
    .expect("options");
    for ((name, is_directory), body) in names.iter().zip(&bodies) {
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(body),
                mtime: None,
                attributes: 0,
                host_os: HostOs::Unix,
                is_directory: *is_directory,
            })
            .expect("add");
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    out
}

fn sources(bytes: &[u8]) -> Vec<Arc<dyn RangeSource>> {
    vec![Arc::new(bytes.to_vec()) as Arc<dyn RangeSource>]
}

/// The dials every test here sets: the walk keeps a member under 4 KiB
/// (no small batches), a worker takes the rest, the queue is `on`, and
/// the walk's wait for a worker is the one that ships beside it (ended by
/// any worker's answer with the queue on, parked on the oldest with it
/// off).
fn dials(on: bool) {
    dials_with(on, on);
}

/// [`dials`], with the wait for a worker named apart from the queue.
fn dials_with(queue: bool, wait_any: bool) {
    rarkit::probe::set_offload_floor(Some(4096));
    rarkit::probe::set_small_batch(Some((0, 0)));
    rarkit::probe::set_outputs_over_breadth(Some(2));
    rarkit::probe::set_queue_own(Some(queue));
    rarkit::probe::set_wait_any(Some(wait_any));
}

fn dials_off() {
    rarkit::probe::set_offload_floor(None);
    rarkit::probe::set_small_batch(None);
    rarkit::probe::set_outputs_over_breadth(None);
    rarkit::probe::set_queue_own(None);
    rarkit::probe::set_wait_any(None);
}

/// What a sink was told, in the order it was told it.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Event {
    Open(Vec<u8>),
    Close(Vec<u8>, Vec<u8>, Option<bool>),
}

/// How a sink answers `open`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Files written, directories skipped: `x` as the CLI runs it.
    Write,
    /// Files written, directories verified, so they are closed too.
    WriteAll,
    /// Nothing written: `t`.
    Verify,
}

fn answer<W>(mode: Mode, member: &MemberInfo<'_>, writer: impl FnOnce() -> W) -> Disposition<W> {
    match mode {
        Mode::Verify => Disposition::Verify,
        Mode::Write if member.is_directory => Disposition::Skip,
        Mode::WriteAll if member.is_directory => Disposition::Verify,
        _ => Disposition::Write(writer()),
    }
}

/// The sequential control.
struct Plain {
    mode: Mode,
    events: Vec<Event>,
}

impl Sink for Plain {
    type Out = Vec<u8>;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        self.events.push(Event::Open(member.name.to_vec()));
        Ok(answer(self.mode, member, Vec::new))
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.events.push(Event::Close(
            member.name.to_vec(),
            out.unwrap_or_default(),
            outcome.checksum_ok,
        ));
        Ok(())
    }
}

/// A writer that counts how many of its kind are alive and, where it is
/// told to, takes its time over its first write.
struct Slow {
    bytes: Vec<u8>,
    live: Arc<AtomicUsize>,
    delay: Option<Duration>,
}

impl Write for Slow {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if let Some(delay) = self.delay.take() {
            std::thread::sleep(delay);
        }
        self.bytes.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for Slow {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The parallel sink: every call logged, the writers alive counted, the
/// first LARGE member's writer slow, and one member's `close` refused
/// where a test names it.
struct Logging {
    mode: Mode,
    events: Mutex<Vec<Event>>,
    live: Arc<AtomicUsize>,
    peak: AtomicUsize,
    slowed: AtomicUsize,
    delay: Duration,
    refuse: Option<&'static [u8]>,
}

impl Logging {
    fn new(mode: Mode, delay: Duration) -> Logging {
        Logging {
            mode,
            events: Mutex::new(Vec::new()),
            live: Arc::new(AtomicUsize::new(0)),
            peak: AtomicUsize::new(0),
            slowed: AtomicUsize::new(0),
            delay,
            refuse: None,
        }
    }

    fn events(&self) -> Vec<Event> {
        self.events.lock().expect("the sink's own lock").clone()
    }
}

impl ParallelSink for Logging {
    type Out = Slow;

    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Slow>> {
        self.events
            .lock()
            .expect("the sink's own lock")
            .push(Event::Open(member.name.to_vec()));
        Ok(answer(self.mode, member, || {
            let live = self.live.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(live, Ordering::SeqCst);
            let slow = member.name.ends_with(b"large.bin")
                && self.slowed.fetch_add(1, Ordering::SeqCst) == 0;
            Slow {
                bytes: Vec::new(),
                live: Arc::clone(&self.live),
                delay: slow.then_some(self.delay),
            }
        }))
    }

    fn close(
        &self,
        member: &MemberInfo<'_>,
        out: Option<Slow>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        let bytes = out.map(|w| w.bytes.clone()).unwrap_or_default();
        self.events
            .lock()
            .expect("the sink's own lock")
            .push(Event::Close(
                member.name.to_vec(),
                bytes,
                outcome.checksum_ok,
            ));
        if self.refuse == Some(member.name) {
            return Err(Error::caller(std::io::Error::other(
                "the caller stops here",
            )));
        }
        Ok(())
    }
}

fn closes(events: &[Event]) -> Vec<Event> {
    events
        .iter()
        .filter(|e| matches!(e, Event::Close(..)))
        .cloned()
        .collect()
}

fn opens(events: &[Event]) -> Vec<Event> {
    events
        .iter()
        .filter(|e| matches!(e, Event::Open(..)))
        .cloned()
        .collect()
}

/// BYTES, VERDICTS AND THE ORDER OF `close` (spec F 3.7.6): the queue on
/// and the queue off both give the sequential walk's answer, member for
/// member, for a compressed archive and a stored one, written, verified,
/// and with the directory entries closed as well as skipped.
#[test]
fn the_queue_gives_the_sequential_walks_closes_in_archive_order() {
    for method in [
        WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
        WriteMethod::Stored,
    ] {
        let bytes = archive(9, method);
        for mode in [Mode::Write, Mode::WriteAll, Mode::Verify] {
            let mut plain = Plain {
                mode,
                events: Vec::new(),
            };
            extract(
                sources(&bytes),
                &ReadOptions::default(),
                &mut plain,
                &mut (),
            )
            .expect("sequential");
            let want = closes(&plain.events);
            assert!(
                want.len() >= 27,
                "the fixture closed {} members",
                want.len()
            );
            for (on, any, breadth) in [
                (false, false, 4),
                (true, false, 4),
                (true, true, 4),
                (false, true, 4),
                // A narrow pool, where the walk waits for a worker at
                // nearly every member.
                (true, true, 2),
                (false, true, 2),
            ] {
                dials_with(on, any);
                let sink = Logging::new(mode, Duration::from_millis(30));
                let report =
                    extract_parallel(sources(&bytes), &ReadOptions::default(), &sink, breadth)
                        .expect("parallel");
                dials_off();
                let events = sink.events();
                assert_eq!(
                    closes(&events),
                    want,
                    "queue {on}, wait any {any}, breadth {breadth}: the closes are not \
                     the sequential walk's, in its order"
                );
                assert_eq!(
                    opens(&events),
                    opens(&plain.events),
                    "queue {on}, wait any {any}, breadth {breadth}: the opens are not \
                     in archive order"
                );
                assert_eq!(report.checksum_failures, 0);
                assert_eq!(sink.live.load(Ordering::SeqCst), 0, "a writer was kept");
            }
        }
    }
}

/// WHAT THE QUEUE IS FOR. The first large member's writer takes its time;
/// the member after it is one the walk handles itself. With the queue off
/// the walk closes the large member before it goes on, so exactly two
/// members have been opened by then (the pool before this lever, pinned);
/// with it on the walk is past the next directory, and the next large
/// member is open, before the first one closes.
#[test]
fn the_walk_goes_on_past_its_own_members_while_a_large_one_decodes() {
    let bytes = archive(
        6,
        WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
    );
    let opened_before_the_first_close = |on: bool| {
        dials(on);
        let sink = Logging::new(Mode::Write, Duration::from_millis(400));
        extract_parallel(sources(&bytes), &ReadOptions::default(), &sink, 4).expect("parallel");
        dials_off();
        let events = sink.events();
        let first_close = events
            .iter()
            .position(|e| matches!(e, Event::Close(..)))
            .expect("a member closed");
        assert_eq!(
            events[first_close],
            closes(&events)[0],
            "the first close is the first member's"
        );
        assert!(
            matches!(&events[first_close], Event::Close(name, ..) if name == b"d0/large.bin"),
            "the first member closed is the first large one"
        );
        opens(&events[..first_close]).len()
    };
    // d0 (skipped), d0/large.bin, d0/empty: the walk stops at the empty
    // member's close until the large one has closed.
    assert_eq!(opened_before_the_first_close(false), 3);
    let on = opened_before_the_first_close(true);
    assert!(
        on >= 6,
        "with the queue on only {on} members were opened before the first large \
         one closed: the walk still waited at a member of its own"
    );
}

/// THE OUTPUTS PROMISE HOLDS UNDER THE QUEUE: a member waiting
/// in the queue with the caller's writer counts against the bound, so the
/// caller never holds more than twice the breadth open, however many small
/// written members the walk gets through behind one slow large one.
#[test]
fn the_queue_never_holds_more_writers_open_than_twice_the_breadth() {
    let bytes = archive(
        30,
        WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
    );
    for breadth in [2usize, 4] {
        dials(true);
        let sink = Logging::new(Mode::Write, Duration::from_millis(400));
        // The read's width stated: without a workers figure it is the
        // pool's own, and on a pool of two a breadth of four is held to
        // two, so the lower bound below could not be met.
        let four_wide = ReadOptions::default().with_workers(Some(4));
        extract_parallel(sources(&bytes), &four_wide, &sink, breadth).expect("parallel");
        dials_off();
        let peak = sink.peak.load(Ordering::SeqCst);
        assert!(
            peak <= 2 * breadth,
            "the caller held {peak} writers open at a breadth of {breadth}"
        );
        assert!(
            peak > breadth,
            "the caller held only {peak} writers open at a breadth of {breadth}: \
             the queue kept nothing waiting behind the slow member"
        );
    }
}

/// A STATED ALLOWANCE LETS FINISHED WRITERS WAIT, AND NO MORE THAN IT
/// (`ReadOptions::waiting_outputs`, SPEC-API section 4, "Outputs open at
/// once"): with `Some(n)` the caller holds more than twice the breadth of
/// writers open behind a slow large member, never more than twice the
/// breadth and `n` together, and the closes are still the sequential
/// walk's in its order. `None` is the test above.
#[test]
fn a_stated_allowance_lets_finished_writers_wait_and_no_more() {
    let bytes = archive(
        30,
        WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
    );
    let mut plain = Plain {
        mode: Mode::Write,
        events: Vec::new(),
    };
    extract(
        sources(&bytes),
        &ReadOptions::default(),
        &mut plain,
        &mut (),
    )
    .expect("sequential");
    for (breadth, n) in [(2usize, 6usize), (4, 20), (4, 0)] {
        dials(true);
        let sink = Logging::new(Mode::Write, Duration::from_millis(400));
        let options = ReadOptions::default().with_waiting_outputs(Some(n));
        extract_parallel(sources(&bytes), &options, &sink, breadth).expect("parallel");
        dials_off();
        let peak = sink.peak.load(Ordering::SeqCst);
        assert!(
            peak <= 2 * breadth + n,
            "the caller held {peak} writers open at a breadth of {breadth} and an \
             allowance of {n}"
        );
        if n > 0 {
            assert!(
                peak > 2 * breadth,
                "the caller held only {peak} writers open at a breadth of {breadth} \
                 and an allowance of {n}: nothing waited under the allowance"
            );
        }
        assert_eq!(closes(&sink.events()), closes(&plain.events));
    }
    // The allowance is the queue's: with the queue off it is not read, and
    // the bound is twice the breadth.
    dials(false);
    let sink = Logging::new(Mode::Write, Duration::from_millis(400));
    let options = ReadOptions::default().with_waiting_outputs(Some(50));
    extract_parallel(sources(&bytes), &options, &sink, 4).expect("parallel");
    dials_off();
    let peak = sink.peak.load(Ordering::SeqCst);
    assert!(peak <= 8, "the queue off held {peak} writers open");
}

/// What the walk can know of one written member, as its caller sees it.
struct Seen {
    /// One a worker decodes (the fixture's `large.bin`), not the walk.
    large: bool,
    /// Its decode is over AND ITS ANSWER IS WITH THE WALK'S QUEUE: the
    /// thread that wrote it has since written a later member (a worker
    /// answers one member before it takes the next), or the walk handled
    /// it itself and has gone on to the next member.
    answered: AtomicBool,
    /// Its writer is dropped, which is after its `close`.
    closed: AtomicBool,
}

/// A writer that tells [`Fronts`] which thread wrote it.
struct Watched {
    bytes: Vec<u8>,
    seen: Arc<Seen>,
    told: bool,
    live: Arc<AtomicUsize>,
    last: Arc<Mutex<HashMap<ThreadId, Arc<Seen>>>>,
}

impl Write for Watched {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if !self.told {
            self.told = true;
            let earlier = self
                .last
                .lock()
                .expect("the sink's own lock")
                .insert(std::thread::current().id(), Arc::clone(&self.seen));
            if let Some(earlier) = earlier {
                earlier.answered.store(true, Ordering::SeqCst);
            }
        }
        self.bytes.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for Watched {
    fn drop(&mut self) {
        self.seen.closed.store(true, Ordering::SeqCst);
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

/// What [`Fronts`] keeps under its one lock.
#[derive(Default)]
struct Order {
    /// Every written member, in the order the walk opened them.
    opened: Vec<Arc<Seen>>,
    /// The oldest of them not yet closed: the front of the walk's queue,
    /// as far as writers go.
    front: usize,
    /// The front, where it was ALREADY ANSWERED when the walk opened the
    /// large member it offered last: the walk closes the ready front at
    /// every member it offers, so this one is closed before the next open
    /// unless the queue kept it.
    ready_at_offer: Option<usize>,
    events: Vec<Event>,
}

/// A sink that reads, at every `open`, whether the writer at the front of
/// the queue is one the queue had no reason to keep.
struct Fronts {
    order: Mutex<Order>,
    live: Arc<AtomicUsize>,
    last: Arc<Mutex<HashMap<ThreadId, Arc<Seen>>>>,
    /// The most writers open at once, whatever the front was doing.
    peak: AtomicUsize,
    /// The most writers open at once BEHIND A FRONT THE QUEUE KEPT.
    kept_peak: AtomicUsize,
}

impl Fronts {
    fn new() -> Fronts {
        Fronts {
            order: Mutex::new(Order::default()),
            live: Arc::new(AtomicUsize::new(0)),
            last: Arc::new(Mutex::new(HashMap::new())),
            peak: AtomicUsize::new(0),
            kept_peak: AtomicUsize::new(0),
        }
    }
}

impl ParallelSink for Fronts {
    type Out = Watched;

    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Watched>> {
        let mut order = self.order.lock().expect("the sink's own lock");
        order.events.push(Event::Open(member.name.to_vec()));
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        // The walk is here, so a member it handled itself is behind it.
        if let Some(before) = order.opened.last().filter(|seen| !seen.large) {
            before.answered.store(true, Ordering::SeqCst);
        }
        while order
            .opened
            .get(order.front)
            .is_some_and(|seen| seen.closed.load(Ordering::SeqCst))
        {
            order.front += 1;
        }
        let large = member.name.ends_with(b"large.bin");
        let seen = Arc::new(Seen {
            large,
            answered: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        });
        let at = order.opened.len();
        order.opened.push(Arc::clone(&seen));
        let live = self.live.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(live, Ordering::SeqCst);
        let front = order.front;
        if order.ready_at_offer == Some(front) {
            self.kept_peak.fetch_max(live, Ordering::SeqCst);
        }
        if large {
            let ready = front < at && order.opened[front].answered.load(Ordering::SeqCst);
            order.ready_at_offer = ready.then_some(front);
        }
        Ok(Disposition::Write(Watched {
            bytes: Vec::new(),
            seen,
            told: false,
            live: Arc::clone(&self.live),
            last: Arc::clone(&self.last),
        }))
    }

    fn close(
        &self,
        member: &MemberInfo<'_>,
        out: Option<Watched>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        let bytes = out.map(|w| w.bytes.clone()).unwrap_or_default();
        self.order
            .lock()
            .expect("the sink's own lock")
            .events
            .push(Event::Close(
                member.name.to_vec(),
                bytes,
                outcome.checksum_ok,
            ));
        Ok(())
    }
}

/// Under an allowance, a finished writer waits only behind a member still
/// decoding: with nothing slow at the front, the ready front is closed as
/// the walk goes (`RARKIT_CLOSE_READY`), and the writers open at once stay
/// far under the allowance. With that knob off the same run holds every
/// one of its 180 writers open until the walk ends (proved by running this
/// test under `RARKIT_CLOSE_READY=0`, where it fails at 180 of 180).
///
/// WHAT IS COUNTED, AND WHY NOT THE PLAIN PEAK. "Nothing at the front is
/// still decoding" is a statement about the scheduler as much as the
/// archive. Where the machine is busy, the worker holding the front member
/// is put aside while the others finish theirs, and every writer they
/// finish waits behind it, inside the allowance and by the rule: on 18
/// hardware threads beside 46 busy processes the plain peak passed 60 in
/// 10 runs of 150 (7 Oct 2026), and of the 381 writers opened above 60 in
/// a census of such runs, 377 were opened while the front member's worker
/// had yet to write it, 4 within 8 microseconds of its write, and none
/// behind a member the walk had handled. A hosted runner of two threads
/// read 85 of 180 at a breadth of four the same way (6 Oct 2026).
/// So the bound of 60 is held over the writers open BEHIND A FRONT THE
/// QUEUE KEPT, which no scheduler can produce: a front member that had
/// answered before the walk offered its last large member ([`Seen`],
/// [`Order::ready_at_offer`]) and is still open at a later `open`. The
/// plain peak is printed beside it.
///
/// THE MACHINE IT STATES: the breadth is stated to the pool and held to
/// the hardware threads the machine has, less one for the walk, and every
/// breadth from one up to that is read: one worker on any machine, four
/// from five threads. The default memory policy; the members are 96 KiB.
#[test]
fn an_allowance_is_not_used_where_nothing_at_the_front_is_still_decoding() {
    let threads = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    let widest = threads.saturating_sub(1).clamp(1, 4);
    println!("{threads} hardware threads: breadths 1 to {widest} are read");
    let bytes = archive(
        60,
        WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
    );
    let mut plain = Plain {
        mode: Mode::Write,
        events: Vec::new(),
    };
    extract(
        sources(&bytes),
        &ReadOptions::default(),
        &mut plain,
        &mut (),
    )
    .expect("sequential");
    for breadth in 1..=widest {
        dials(true);
        let sink = Fronts::new();
        let options = ReadOptions::default().with_waiting_outputs(Some(1000));
        extract_parallel(sources(&bytes), &options, &sink, breadth).expect("parallel");
        dials_off();
        let peak = sink.peak.load(Ordering::SeqCst);
        let kept = sink.kept_peak.load(Ordering::SeqCst);
        println!(
            "breadth {breadth}: at most {peak} of 180 writers open at once, {kept} behind a \
             front the queue kept"
        );
        assert!(
            kept <= 60,
            "the caller held {kept} of 180 writers open at once behind a front member that \
             had answered, with no member slow to decode, at a breadth of {breadth} on \
             {threads} hardware threads"
        );
        let order = sink.order.lock().expect("the sink's own lock");
        // The reading is not an empty one: a worker's every large member
        // but its last is known to have answered.
        let answered = order
            .opened
            .iter()
            .filter(|seen| seen.large && seen.answered.load(Ordering::SeqCst))
            .count();
        assert!(
            answered >= 60 - breadth,
            "only {answered} of 60 large members were seen to answer at a breadth of {breadth}"
        );
        assert_eq!(closes(&order.events), closes(&plain.events));
    }
}

/// A MEMBER THAT GOES NOWHERE HOLDS NO WRITER, so `t` is not held by the
/// outputs bound at all under the queue. There is no writer to slow in
/// `t`, so this reads the walk's reach by count: the most members opened
/// and not yet closed. With the queue off that is at most the flight's
/// bound, twice the breadth, and the walk's own member; with it on the
/// walk reaches further.
#[test]
fn a_verified_member_does_not_count_against_the_outputs_bound() {
    let bytes = archive(
        30,
        WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
    );
    let mut reach = [0usize; 2];
    for on in [false, true] {
        dials(on);
        let sink = Logging::new(Mode::Verify, Duration::ZERO);
        extract_parallel(sources(&bytes), &ReadOptions::default(), &sink, 2).expect("parallel");
        dials_off();
        let events = sink.events();
        let mut open = 0usize;
        for event in &events {
            match event {
                Event::Open(..) => open += 1,
                Event::Close(..) => open -= 1,
            }
            reach[usize::from(on)] = reach[usize::from(on)].max(open);
        }
        assert_eq!(open, 0, "queue {on}: a member was opened and never closed");
    }
    assert!(
        reach[0] <= 2 * 2 + 1,
        "the queue off held {} members open, above its flight bound",
        reach[0]
    );
    assert!(
        reach[1] > reach[0],
        "the queue on reached {} members open against {} off",
        reach[1],
        reach[0]
    );
}

/// A `close` THE CALLER REFUSES ENDS THE RUN AT THAT MEMBER, queue or no
/// queue: the same error comes back, and the closes the caller saw up to
/// and including the refused one are the same ones in the same order.
#[test]
fn a_refused_close_ends_the_run_at_the_same_member_either_way() {
    let bytes = archive(
        8,
        WriteMethod::Compressed {
            level: 3,
            dictionary: None,
        },
    );
    for refused in [&b"d2/empty"[..], b"d3/large.bin", b"d5/small.txt"] {
        let run = |on: bool| {
            dials(on);
            let mut sink = Logging::new(Mode::Write, Duration::from_millis(20));
            sink.refuse = Some(refused);
            let outcome = extract_parallel(sources(&bytes), &ReadOptions::default(), &sink, 4);
            dials_off();
            let closed = closes(&sink.events());
            let at = closed
                .iter()
                .position(|e| matches!(e, Event::Close(name, ..) if name == refused))
                .expect("the refused member was closed");
            (
                outcome.expect_err("the caller's refusal").to_string(),
                closed[..=at].to_vec(),
            )
        };
        assert_eq!(run(true), run(false), "refusing {:?}", refused);
    }
}
