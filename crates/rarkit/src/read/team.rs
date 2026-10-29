//! The helper threads of one extraction, KEPT: a team started as ranges
//! first need its threads and ended when the extraction ends.
//!
//! **What it is for.** The wide read (`read::wide`), the cut range
//! (`read::handed`) and the fragments abreast (`read::across`) each read a
//! range of a stored member on helper threads, and each used to start its
//! threads for the range and end them with it. Two things followed. A
//! range paid a start and an end of every helper it used, which is tens of
//! microseconds a thread: nothing on a big member in one archive, and a
//! measurable share of a big member posted in volumes of 16 to 20 MiB, where a
//! range is read in under half a millisecond. And a thread whose work is
//! over is still a thread until it has left, so the next range's helpers
//! were started beside the last range's: never more than the width at
//! WORK, but for a moment more than the width ALIVE, which is what a host
//! that counts threads (a container's pids limit) counts.
//!
//! **The arrangement.** A range takes [`Seats`] for the helpers it would
//! have started, and hands the team one [`Job`] a helper: the loop that
//! helper's thread ran, which reads the range's pieces until the range has
//! no more and then leaves its thread to the team. Inside a range nothing
//! is different from a thread of the range's own. The team has as
//! many threads as there are seats taken at once and never more: a seat
//! taken where every thread is spoken for starts one, a seat given back
//! starts nothing and ends nothing, and the thread it leaves idle serves
//! the next range, the member's next fragment or the next member's alike.
//! So no thread is started or ended at a range's end, and the threads
//! alive are at most the seats the ranges of this extraction held at
//! once, which are the widths the engine grants them.
//!
//! **Whose it is.** One extraction's (`read::metered`), found through the
//! operation slot every thread of the extraction carries
//! (`memory::op_slot`), and ended there: each thread is told to leave and
//! is waited for by its handle, so nothing of the team outlives the call.
//! It is not a pool of the process (SPEC-API 8.3): it is started by one
//! call, sized by that call's ranges, and gone when the call returns. A
//! range read outside any extraction's slot gets a team of its own for the
//! range, ended and waited for when the range gives its seats back.
//!
//! **What a range keeps.** A range that makes buffers for itself (the cut
//! range's slab and its reader's ring) made them for every range and gave
//! them back, and an allocator that returns freed memory to the system
//! then faults the same pages in again a range later: 12 MiB a range for a
//! big member in 20 MiB volumes, a tenth of the wall of its extraction, or none
//! of it where the allocator happened to keep them (counted on an 8 core
//! Zen 4, 6 Oct 2026). So a range may leave such a thing with the team
//! ([`keep`]) for the extraction's next range to take ([`kept`]). It is
//! dropped with the team, and its charge to the operation's meter is its
//! own for as long as it lives.
//!
//! **A host that will start no thread** (`crate::threads`) leaves a range
//! with the seats it could be given, none at all included, and the range
//! reads narrower or on its own thread, as it always did.

use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crate::read::wide::Aligned;

/// What a thread of the team keeps between jobs: one buffer of its own,
/// for the pieces that bring none. A buffer that stays with its thread
/// stays in that core's cache, and is not made and unmade a range.
#[derive(Default)]
pub(crate) struct Scratch {
    /// The buffer, the bytes it was asked to have in front of its page,
    /// and its charge to the operation's meter.
    own: Option<(usize, Aligned)>,
    held: crate::memory::Held,
}

impl Scratch {
    /// This thread's buffer of `len` bytes whose byte `head` starts a page
    /// ([`Aligned::headed`]): the one it has, where that is its shape, and
    /// a new one otherwise.
    pub(crate) fn buffer(&mut self, len: usize, head: usize) -> &mut Aligned {
        let fits = matches!(&self.own, Some((h, buf)) if *h == head && buf.bytes().len() == len);
        if !fits {
            // The old one is gone before the new one is made.
            self.own = None;
            let buf = Aligned::headed(len - head, head);
            self.held.set(buf.held_bytes());
            self.own = Some((head, buf));
        }
        &mut self.own.as_mut().expect("made above").1
    }
}

/// One helper's work for a range, run on a thread of the team until the
/// range has no more for it.
pub(crate) type Job = Box<dyn FnOnce(&mut Scratch) + Send + 'static>;

/// A job, or the word to leave.
type Message = Option<Job>;

struct State {
    threads: Vec<JoinHandle<()>>,
    /// The seats taken now.
    taken: usize,
}

struct Team {
    /// What ranges left for the ranges after them ([`keep`]).
    kept: Mutex<Vec<Box<dyn std::any::Any + Send>>>,
    jobs: Sender<Message>,
    queue: Arc<Mutex<Receiver<Message>>>,
    state: Mutex<State>,
    /// The operation slot the team's threads charge to.
    op: Option<usize>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Team {
    fn new(op: Option<usize>) -> Arc<Team> {
        let (jobs, queue) = channel::<Message>();
        Arc::new(Team {
            kept: Mutex::new(Vec::new()),
            jobs,
            queue: Arc::new(Mutex::new(queue)),
            state: Mutex::new(State {
                threads: Vec::new(),
                taken: 0,
            }),
            op,
        })
    }

    /// Take up to `want` seats, starting a thread for each one that has
    /// none, and answer how many were had: fewer where the host would
    /// start no more.
    fn take(&self, want: usize) -> usize {
        let mut state = lock(&self.state);
        let mut had = 0;
        while had < want {
            if state.threads.len() <= state.taken {
                let queue = Arc::clone(&self.queue);
                let op = self.op;
                let started = crate::threads::kept(move || {
                    // The operation's meter follows its threads (API 8.4.1,
                    // `memory::Meter`).
                    let _op = crate::memory::enter(op);
                    let mut scratch = Scratch::default();
                    loop {
                        let message = lock(&queue).recv();
                        let Ok(Some(job)) = message else {
                            break;
                        };
                        // A job that panics has told its range so as it
                        // unwound ([`Fell`]); the thread stays, so the team
                        // is the size its seats say.
                        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            job(&mut scratch);
                        }));
                    }
                });
                match started {
                    Some(thread) => state.threads.push(thread),
                    None => break,
                }
            }
            state.taken += 1;
            had += 1;
        }
        had
    }

    fn give_back(&self, seats: usize) {
        let mut state = lock(&self.state);
        state.taken = state.taken.saturating_sub(seats);
    }

    /// Tell every thread to leave and wait for each by its handle. The
    /// jobs still queued are in front of the word and are run first.
    fn end(&self) {
        let threads = std::mem::take(&mut lock(&self.state).threads);
        for _ in &threads {
            let _ = self.jobs.send(None);
        }
        for thread in threads {
            let _ = thread.join();
        }
        lock(&self.kept).clear();
    }
}

/// The most things kept at once: more than the ranges an extraction reads
/// at a time leave, and a bound on what is held if they left more.
const KEPT: usize = 16;

/// The team of the extraction the calling thread works for, if it has one
/// already. A thing is kept only where a range has taken seats, so the
/// team is there to end and to drop what it keeps.
fn team_here() -> Option<Arc<Team>> {
    let slot = crate::memory::op_slot()?;
    let teams = lock(&TEAMS);
    teams
        .iter()
        .find(|(s, _)| *s == slot)
        .map(|(_, team)| Arc::clone(team))
}

/// Leave `thing` for a later range of this extraction ([`kept`]). Outside
/// an extraction, or where enough is kept already, it is dropped here.
pub(crate) fn keep<T: Send + 'static>(thing: T) {
    if let Some(team) = team_here() {
        let mut kept = lock(&team.kept);
        if kept.len() < KEPT {
            kept.push(Box::new(thing));
        }
    }
}

/// Take a `T` an earlier range of this extraction left ([`keep`]), the
/// first `wanted` passes.
pub(crate) fn kept<T: Send + 'static>(wanted: impl Fn(&T) -> bool) -> Option<T> {
    let team = team_here()?;
    let mut kept = lock(&team.kept);
    let at = kept
        .iter()
        .position(|thing| thing.downcast_ref::<T>().is_some_and(&wanted))?;
    kept.swap_remove(at)
        .downcast::<T>()
        .ok()
        .map(|thing| *thing)
}

/// The teams of the extractions running now, by operation slot.
static TEAMS: Mutex<Vec<(usize, Arc<Team>)>> = Mutex::new(Vec::new());

/// Seats on a team for one range's helpers, given back when this drops.
pub(crate) struct Seats {
    team: Arc<Team>,
    seats: usize,
    /// A team made for this range alone, ended with it.
    own: bool,
}

impl Seats {
    /// The seats had: the helpers the range may count on.
    pub(crate) fn count(&self) -> usize {
        self.seats
    }

    /// One more seat, where the host will start the thread for it.
    pub(crate) fn more(&mut self) -> bool {
        let had = self.team.take(1);
        self.seats += had;
        had == 1
    }

    /// Hand the team a job. It is run by whichever thread is free first,
    /// behind the jobs handed before it.
    pub(crate) fn hand(&self, job: Job) {
        // The receiver lives as long as the team does, which is as long
        // as this does.
        let _ = self.team.jobs.send(Some(job));
    }
}

impl Drop for Seats {
    fn drop(&mut self) {
        self.team.give_back(self.seats);
        if self.own {
            self.team.end();
        }
    }
}

/// Take up to `want` seats for a range read on the calling thread's
/// operation: on the extraction's team, started here if this is its first
/// range, or on a team of the range's own where the thread is in no
/// extraction's slot.
pub(crate) fn seats(want: usize) -> Seats {
    let (team, own) = match crate::memory::op_slot() {
        Some(slot) => {
            let mut teams = lock(&TEAMS);
            let team = match teams.iter().find(|(s, _)| *s == slot) {
                Some((_, team)) => Arc::clone(team),
                None => {
                    let team = Team::new(Some(slot));
                    teams.push((slot, Arc::clone(&team)));
                    team
                }
            };
            (team, false)
        }
        None => (Team::new(None), true),
    };
    let seats = team.take(want);
    Seats { team, seats, own }
}

/// Ends an extraction's team when it drops, on every path out of the
/// extraction: made beside the operation's meter (`read::metered`).
pub(crate) struct Ends(Option<usize>);

impl Ends {
    /// For the operation whose slot is `slot`; `None` ends nothing.
    pub(crate) fn of(slot: Option<usize>) -> Ends {
        Ends(slot)
    }
}

impl Drop for Ends {
    fn drop(&mut self) {
        let Some(slot) = self.0 else {
            return;
        };
        let team = {
            let mut teams = lock(&TEAMS);
            teams
                .iter()
                .position(|(s, _)| *s == slot)
                .map(|at| teams.swap_remove(at).1)
        };
        if let Some(team) = team {
            team.end();
        }
    }
}

/// Tells a range that one of its jobs fell (panicked) before it answered:
/// `fell` is sent as the job unwinds, unless [`Fell::answered`] was called
/// first. The range then panics on its own thread, as a scope whose thread
/// panicked did.
pub(crate) struct Fell<T: Send>(Option<(Sender<T>, T)>);

impl<T: Send> Fell<T> {
    pub(crate) fn watch(to: Sender<T>, fell: T) -> Fell<T> {
        Fell(Some((to, fell)))
    }

    /// The job is over: send `answer` in the place of the word that it
    /// fell, and answer whether the range was still there to hear it.
    pub(crate) fn answered(mut self, answer: T) -> bool {
        match self.0.take() {
            Some((to, _)) => to.send(answer).is_ok(),
            None => false,
        }
    }
}

impl<T: Send> Drop for Fell<T> {
    fn drop(&mut self) {
        if let Some((to, fell)) = self.0.take() {
            let _ = to.send(fell);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

    /// A team of the range's own (no operation slot here): seats start
    /// threads only while every thread is spoken for, the same threads
    /// serve every job, and giving the seats back ends and joins them.
    #[test]
    fn a_team_is_as_large_as_its_seats_and_no_larger() {
        let ran = Arc::new(AtomicUsize::new(0));
        let ids = Arc::new(Mutex::new(std::collections::HashSet::new()));
        {
            let mut seats = seats(3);
            assert_eq!(seats.count(), 3);
            assert!(seats.more());
            assert_eq!(seats.count(), 4);
            let (tx, rx) = channel::<()>();
            for _ in 0..64 {
                let (ran, ids, tx) = (Arc::clone(&ran), Arc::clone(&ids), tx.clone());
                seats.hand(Box::new(move |_| {
                    lock(&ids).insert(std::thread::current().id());
                    ran.fetch_add(1, SeqCst);
                    let _ = tx.send(());
                }));
            }
            for _ in 0..64 {
                rx.recv().expect("every job answers");
            }
            assert_eq!(lock(&seats.team.state).threads.len(), 4);
        }
        assert_eq!(ran.load(SeqCst), 64);
        assert!(lock(&ids).len() <= 4);
    }

    /// A job that panics tells its range and leaves the team whole.
    #[test]
    fn a_fallen_job_says_so_and_its_thread_stays() {
        let seats = seats(1);
        let (tx, rx) = channel::<Option<u32>>();
        let watch = Fell::watch(tx.clone(), None);
        seats.hand(Box::new(move |_| {
            let _watch = watch;
            panic!("a job fell (this test's own panic)");
        }));
        assert_eq!(rx.recv().expect("the word arrives"), None);
        let watch = Fell::watch(tx, None);
        seats.hand(Box::new(move |_| {
            watch.answered(Some(7));
        }));
        assert_eq!(rx.recv().expect("the thread is still there"), Some(7));
    }

    /// A thread's buffer is kept while its shape is asked for again.
    #[test]
    fn a_scratch_buffer_is_kept_for_its_shape() {
        let mut scratch = Scratch::default();
        let first = scratch.buffer(8192, 0).bytes().as_ptr();
        assert_eq!(scratch.buffer(8192, 0).bytes().as_ptr(), first);
        assert_eq!(scratch.buffer(8192 + 16, 16).bytes().len(), 8192 + 16);
    }
}
