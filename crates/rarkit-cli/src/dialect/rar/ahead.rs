//! Small members' bytes read AHEAD of the writer, on the process's pool.
//!
//! The writer pulls every reader payload on its own writing thread, in
//! `add` order, and a team batch of up to several hundred small members
//! is pulled whole before the crews start on it. For a create of many
//! small files that is one `open`, two `read`s and a `close` a member, one
//! after another, with the pool idle: 20,000 opens cost 0.8 to 1.3 s on
//! APFS (41 to 65 us each) and about 0.1 s on Linux, the largest cost the
//! command line adds on macOS (counted 30 Sep 2026).
//!
//! Here up to [`LOADERS_MOST`] loader jobs on the process's pool open and
//! read the small members in `add` order, one batch's worth ahead of the
//! writer, so the writer's pull finds the bytes in memory. What a member's
//! [`Source`](super::create) serves is exactly what reading the file would
//! have served, up to one byte past the size the walk recorded, which is
//! as far as the writer ever reads it (spec G 3.7.2's end probe), so the
//! archive's bytes do not change and a file that grew or shrank since the
//! walk fails the same way.
//!
//! Three bounds:
//!
//! - **Threads.** The loaders are jobs on the pool the command line sized
//!   to `-mt` (`workers::configure`), never threads of their own, so
//!   `-mt N` is still at most N helpers beside the writing thread.
//! - **Descriptors.** A loader holds one file open at a time and closes it
//!   before it takes the next, so at most [`LOADERS_MOST`] files are open
//!   here, plus the writer's own (`a_create_outlasts_a_small_descriptor_budget`).
//! - **Memory.** The bytes loaded and not yet taken are at most one team
//!   batch's input, and only members of at most [`MEMBER_MOST`] are read
//!   ahead; a larger member the writer reads itself, a window at a time,
//!   as before.
//!
//! **Nothing waits on a loader that has not started.** A member no loader
//! has claimed yet the writer loads itself, so a pool that runs no job at
//! all (one busy with the crews, or a pool of the calling thread alone)
//! slows the read-ahead down to what it replaced and never stops it.

use std::io::Read as _;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

use super::select::Chosen;

/// The largest member read ahead: a crew's share of a team batch
/// (the engine's `CREW_BATCH_BYTES`). A larger one is the writer's to
/// read, a window at a time, as it always was.
const MEMBER_MOST: u64 = 1 << 20;

/// The least a read-ahead holds, in bytes and in members: one team batch
/// at its floor (the engine's `TEAM_BATCH_BYTES` and `TEAM_BATCH_MOST`).
const HELD_BYTES_LEAST: u64 = 4 << 20;
const HELD_MEMBERS_LEAST: usize = 512;

/// What a team batch adds per crew, which the read-ahead follows so that
/// the next batch is loaded whole while the crews encode this one (the
/// engine's `CREW_BATCH_BYTES` and `CREW_BATCH_MEMBERS`).
const HELD_BYTES_PER_CREW: u64 = 1 << 20;
const HELD_MEMBERS_PER_CREW: usize = 32;

/// The most loader jobs at once, and so the most files they hold open.
///
/// Two, counted with the loaders 1, 2 and 4 in one binary (untimed,
/// shared; an M3 Mac, macOS, 32 cores, K = 5; a Zen 4 rental, Linux, 16
/// threads, K = 3). On macOS two take the wall as far as four do
/// (small20k `-m0` 0.59 s at both, 1.04 without the read-ahead) for less
/// than half the system CPU four add (1.13 s against 1.97; 0.88 without),
/// since the opens contend in the kernel; on Linux one, two and four read
/// alike and cost about the same.
const LOADERS_MOST: usize = 2;

/// What reading a member ahead found.
pub(crate) enum Loaded {
    /// The file's bytes, at most its recorded size plus one.
    Bytes(Vec<u8>),
    /// The file could not be opened: the report names it, as a failed
    /// open on the writing thread did.
    OpenFailed(std::io::Error),
    /// The file opened and a read of it failed.
    ReadFailed(std::io::Error),
}

/// The read-ahead of one create, shared by the members' sources and the
/// loader jobs.
#[derive(Clone)]
pub(crate) struct Ahead(Arc<Inner>);

struct Inner {
    /// The members read ahead, in `add` order: path and recorded size.
    members: Vec<(PathBuf, u64)>,
    held_bytes: u64,
    held_members: usize,
    loaders_most: usize,
    state: Mutex<State>,
    ready: Condvar,
}

struct State {
    slots: Vec<Slot>,
    /// The first member no loader has claimed.
    next: usize,
    /// Bytes and members claimed by a loader and not yet taken.
    bytes: u64,
    members: usize,
    /// Loader jobs running.
    loaders: usize,
    /// Whether the writer is waiting on a member a loader holds, so a
    /// loader wakes it only then: a wake per member was a `futex` call
    /// per member whoever was waiting.
    waiting: bool,
}

// Without the pool no loader runs, so only the writer's arms are reached.
#[cfg_attr(not(feature = "parallel"), allow(dead_code))]
enum Slot {
    Waiting,
    Loading,
    Ready(Loaded),
    Taken,
}

/// The most bytes a read-ahead for a pool `width` wide holds at once
/// ([`Ahead::plan`]'s bound), for the create's `caller_resident`.
pub(crate) fn held_bytes_most(width: usize) -> u64 {
    HELD_BYTES_LEAST.max(HELD_BYTES_PER_CREW.saturating_mul(width.max(1) as u64))
}

impl Ahead {
    /// A read-ahead over `files` for a pool `width` wide, and each file's
    /// place in it (`None` for one that is not read ahead); `None` where
    /// there is nothing to read ahead. `loaders` bounds the loaders below
    /// [`LOADERS_MOST`] (the count's knob; `None` in a shipped build).
    pub(crate) fn plan(
        files: &[Chosen],
        width: usize,
        loaders: Option<usize>,
    ) -> Option<(Self, Vec<Option<usize>>)> {
        let mut members = Vec::new();
        let places = files
            .iter()
            .map(|file| {
                if file.is_dir || file.size == 0 || file.size > MEMBER_MOST {
                    return None;
                }
                members.push((file.disk.clone(), file.size));
                Some(members.len() - 1)
            })
            .collect();
        if members.is_empty() {
            return None;
        }
        let width = width.max(1);
        let slots = members.iter().map(|_| Slot::Waiting).collect();
        let inner = Inner {
            members,
            held_bytes: held_bytes_most(width),
            held_members: HELD_MEMBERS_LEAST.max(HELD_MEMBERS_PER_CREW.saturating_mul(width)),
            loaders_most: width.min(loaders.unwrap_or(LOADERS_MOST)).max(1),
            state: Mutex::new(State {
                slots,
                next: 0,
                bytes: 0,
                members: 0,
                loaders: 0,
                waiting: false,
            }),
            ready: Condvar::new(),
        };
        Some((Self(Arc::new(inner)), places))
    }

    /// Starts the loaders on the process's pool, which must already be
    /// sized: a job spawned before `workers::configure` would build the
    /// pool at the box's width.
    pub(crate) fn start(&self) {
        let spawn = self.0.more_loaders(&mut self.0.lock());
        self.spawn(spawn);
    }

    /// The bytes of the member at `place`, taken once: loaded by a loader
    /// (waiting for one that has started on it), or read here when no
    /// loader has claimed it yet.
    pub(crate) fn take(&self, place: usize) -> Loaded {
        let inner = &self.0;
        let mut state = inner.lock();
        loop {
            match std::mem::replace(&mut state.slots[place], Slot::Taken) {
                Slot::Ready(loaded) => {
                    state.bytes -= inner.members[place].1;
                    state.members -= 1;
                    let spawn = inner.more_loaders(&mut state);
                    drop(state);
                    self.spawn(spawn);
                    return loaded;
                }
                Slot::Loading => {
                    state.slots[place] = Slot::Loading;
                    state.waiting = true;
                    state = inner.ready.wait(state).unwrap_or_else(|e| e.into_inner());
                }
                Slot::Waiting => {
                    // No loader has it: this thread reads it, charged to
                    // nothing, and the loaders go on from the member after.
                    state.next = state.next.max(place + 1);
                    drop(state);
                    let (path, size) = &inner.members[place];
                    return load(path, *size);
                }
                // Taken twice cannot happen (a source takes its bytes on
                // its first read and is spent at their end); an empty
                // member is the answer that reads as a short file.
                Slot::Taken => return Loaded::Bytes(Vec::new()),
            }
        }
    }

    /// Starts `count` loaders on the pool. Without the pool there is no
    /// thread to read ahead on, no loader runs, and the writer reads every
    /// member itself through [`Ahead::take`], as it did before.
    fn spawn(&self, count: usize) {
        #[cfg(feature = "parallel")]
        for _ in 0..count {
            let ahead = self.clone();
            rayon::spawn(move || ahead.0.run_loader());
        }
        #[cfg(not(feature = "parallel"))]
        {
            let mut state = self.0.lock();
            state.loaders = state.loaders.saturating_sub(count);
        }
    }
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether a loader could claim the next member now.
    fn claimable(&self, state: &State) -> bool {
        let Some((_, size)) = self.members.get(state.next) else {
            return false;
        };
        state.members < self.held_members
            && (state.members == 0 || state.bytes.saturating_add(*size) <= self.held_bytes)
    }

    /// How many more loaders to start, counted as running from here.
    ///
    /// Only once what is held has been taken down to HALF the bound: the
    /// loaders then run a half batch each time, rather than one loader
    /// woken for each member the writer takes. Woken per member, the pool
    /// took 62,000 context switches over small20k at `-m0` on Linux (336
    /// without the read-ahead) and 2.32 G instructions against 1.69.
    fn more_loaders(&self, state: &mut State) -> usize {
        let mut count = 0;
        let drained = state.bytes.saturating_mul(2) <= self.held_bytes
            && state.members.saturating_mul(2) <= self.held_members;
        if drained && self.claimable(state) {
            while state.loaders < self.loaders_most {
                state.loaders += 1;
                count += 1;
            }
        }
        count
    }

    /// One loader: claim the next member in `add` order while the held
    /// bytes allow, load it, and stop when nothing is claimable. A later
    /// `take` starts it again.
    #[cfg_attr(not(feature = "parallel"), allow(dead_code))]
    fn run_loader(&self) {
        loop {
            let place = {
                let mut state = self.lock();
                // Past members the writer read itself.
                while state.next < self.members.len()
                    && !matches!(state.slots[state.next], Slot::Waiting)
                {
                    state.next += 1;
                }
                if !self.claimable(&state) {
                    state.loaders -= 1;
                    return;
                }
                let place = state.next;
                state.next += 1;
                state.slots[place] = Slot::Loading;
                state.bytes = state.bytes.saturating_add(self.members[place].1);
                state.members += 1;
                place
            };
            let (path, size) = &self.members[place];
            let loaded = load(path, *size);
            let mut state = self.lock();
            state.slots[place] = Slot::Ready(loaded);
            let wake = std::mem::take(&mut state.waiting);
            drop(state);
            if wake {
                self.ready.notify_all();
            }
        }
    }
}

/// A member's bytes as the writer would read them: up to its recorded
/// size and ONE byte more, which is where the writer's end probe stops.
fn load(path: &std::path::Path, size: u64) -> Loaded {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(err) => return Loaded::OpenFailed(err),
    };
    let most = size.saturating_add(1);
    let mut bytes = Vec::with_capacity(usize::try_from(most).unwrap_or(0));
    match file.take(most).read_to_end(&mut bytes) {
        Ok(_) => Loaded::Bytes(bytes),
        Err(err) => Loaded::ReadFailed(err),
    }
}

#[cfg(test)]
mod tests {
    use super::{Ahead, Loaded, HELD_BYTES_PER_CREW, MEMBER_MOST};
    use crate::dialect::rar::select::Chosen;
    use std::path::{Path, PathBuf};

    fn dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rarfast-ahead-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    fn chosen(path: &Path, size: u64) -> Chosen {
        Chosen {
            shown: path.to_string_lossy().into_owned(),
            disk: path.to_path_buf(),
            stored: path.to_string_lossy().into_owned(),
            is_dir: false,
            size,
            mtime: None,
            attributes: 0,
        }
    }

    fn bytes(loaded: Loaded) -> Vec<u8> {
        match loaded {
            Loaded::Bytes(bytes) => bytes,
            Loaded::OpenFailed(err) | Loaded::ReadFailed(err) => panic!("load failed: {err}"),
        }
    }

    fn body(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 7 + n) as u8).collect()
    }

    #[test]
    fn every_member_is_served_its_bytes_in_order() {
        let dir = dir("order");
        let files: Vec<Chosen> = (0..300)
            .map(|n| {
                let path = dir.join(format!("f{n}"));
                std::fs::write(&path, body(n * 13 + 1)).expect("write");
                chosen(&path, (n * 13 + 1) as u64)
            })
            .collect();
        let (ahead, places) = Ahead::plan(&files, 4, None).expect("a plan");
        ahead.start();
        for (n, place) in places.iter().enumerate() {
            let place = place.expect("every file is small");
            assert_eq!(bytes(ahead.take(place)), body(n * 13 + 1), "member {n}");
        }
        std::fs::remove_dir_all(&dir).expect("clean up");
    }

    #[test]
    fn a_member_is_read_to_one_byte_past_its_recorded_size() {
        // A file that grew since the walk serves one byte more than it
        // declared, which the writer's end probe refuses; one that shrank
        // serves what it has, which the writer reads as truncated. Both as
        // reading the file itself would.
        let dir = dir("size");
        let grew = dir.join("grew");
        let shrank = dir.join("shrank");
        std::fs::write(&grew, body(100)).expect("write");
        std::fs::write(&shrank, body(40)).expect("write");
        let files = [chosen(&grew, 60), chosen(&shrank, 50)];
        let (ahead, places) = Ahead::plan(&files, 2, None).expect("a plan");
        ahead.start();
        assert_eq!(bytes(ahead.take(places[0].unwrap())), body(100)[..61]);
        assert_eq!(bytes(ahead.take(places[1].unwrap())), body(40));
        std::fs::remove_dir_all(&dir).expect("clean up");
    }

    #[test]
    fn a_file_that_will_not_open_says_so_where_it_is_taken() {
        let dir = dir("missing");
        let here = dir.join("here");
        std::fs::write(&here, b"here").expect("write");
        let files = [chosen(&dir.join("gone"), 5), chosen(&here, 4)];
        let (ahead, places) = Ahead::plan(&files, 2, None).expect("a plan");
        ahead.start();
        assert!(matches!(
            ahead.take(places[0].unwrap()),
            Loaded::OpenFailed(err) if err.kind() == std::io::ErrorKind::NotFound
        ));
        assert_eq!(bytes(ahead.take(places[1].unwrap())), b"here");
        std::fs::remove_dir_all(&dir).expect("clean up");
    }

    #[test]
    fn with_no_loader_running_the_taker_reads_each_member_itself() {
        // `start` is never called: no job runs, and nothing waits on one.
        let dir = dir("unstarted");
        let files: Vec<Chosen> = (0..20)
            .map(|n| {
                let path = dir.join(format!("f{n}"));
                std::fs::write(&path, body(n + 3)).expect("write");
                chosen(&path, (n + 3) as u64)
            })
            .collect();
        let (ahead, places) = Ahead::plan(&files, 8, None).expect("a plan");
        for (n, place) in places.iter().enumerate() {
            assert_eq!(bytes(ahead.take(place.unwrap())), body(n + 3));
        }
        std::fs::remove_dir_all(&dir).expect("clean up");
    }

    #[test]
    fn large_members_and_directories_are_not_read_ahead() {
        let mut dir_entry = chosen(Path::new("d"), 0);
        dir_entry.is_dir = true;
        let files = [
            chosen(Path::new("small"), 10),
            chosen(Path::new("empty"), 0),
            dir_entry,
            chosen(Path::new("large"), MEMBER_MOST + 1),
            chosen(Path::new("edge"), MEMBER_MOST),
        ];
        let (_, places) = Ahead::plan(&files, 2, None).expect("a plan");
        assert_eq!(places, [Some(0), None, None, None, Some(1)]);
    }

    #[test]
    fn the_loaders_hold_at_most_one_batch_ahead() {
        // Nothing is taken, so the loaders fill to the bound and stop.
        let dir = dir("bound");
        let size = 64 << 10;
        let files: Vec<Chosen> = (0..200)
            .map(|n| {
                let path = dir.join(format!("f{n}"));
                std::fs::write(&path, body(size)).expect("write");
                chosen(&path, size as u64)
            })
            .collect();
        let width = 8;
        let (ahead, _) = Ahead::plan(&files, width, None).expect("a plan");
        ahead.start();
        let held = || {
            let state = ahead.0.lock();
            (state.bytes, state.loaders)
        };
        let start = std::time::Instant::now();
        while held().1 > 0 && start.elapsed() < std::time::Duration::from_secs(20) {
            std::thread::yield_now();
        }
        let (bytes, loaders) = held();
        assert_eq!(loaders, 0, "the loaders stopped at the bound");
        assert!(bytes <= HELD_BYTES_PER_CREW * width as u64, "{bytes} held");
        assert!(bytes > 0);
        std::fs::remove_dir_all(&dir).expect("clean up");
    }
}
