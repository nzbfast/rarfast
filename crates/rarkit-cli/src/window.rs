//! A COLD archive read IN ORDER, far ahead of the walk, on a thread of the
//! command's own: the read WINDOW of an archive file.
//!
//! **What it is for.** A stored archive that is not in the page cache is
//! extracted on macOS by the walk, one member at a time
//! (`dialect::unrar::extract`, `Run::stored_route`). A member of a gibibyte
//! or more is overlapped by the engine's seam, its reads deep; a member
//! under that floor is read and written by one thread in requests of
//! 128 KiB, and a set of many like members is nothing but such members. Counted
//! on an M1 Ultra (4 GiB to disk, cold, K=5, 2 Oct 2026):
//! eight members of
//! 512 MiB to sixty-four of 64 MiB took 1.76 to 1.81 s, level with unrar
//! and rarpar, where four members of 1 GiB took 1.57 s. No depth of the
//! seam serves every size: with the seam forced on, its 128 MiB slabs made
//! thirty-two members of 128 MiB 0.93 of that (a member is one slab, so
//! nothing overlaps) and 64 MiB slabs gave back 5 percent on the big ones.
//!
//! **What the drive does.** A raw probe of the same box, no engine in it
//! (2 Oct 2026): the cold read alone 0.63 to 0.74 s, the write alone
//! 0.79 s, and both together never under 1.52 s in any arrangement,
//! because the two share the drive. The arrangements at that ceiling are
//! the ones that read in LARGE requests while the write goes on: ONE
//! reader filling two slabs of 128 MiB in file order, whoever consumes
//! them. With its consumer copying out in 128 KiB pieces on one thread
//! into sixty-four files that probe read 1.53 s, and 1.53 s into one.
//!
//! **So the depth lives here, under the engine and across its members.**
//! The archive's source holds [`SLABS`] slabs of [`SLAB`] bytes. A thread
//! fills them in file order from where the walk's reads are seen to run
//! on in order, one read a slab; the walk's own reads, whatever their size
//! and whichever member they belong to, are copied out of the slab that
//! holds them. A slab is given back to the reader when the walk has read
//! past its end.
//! The engine is untouched and runs at its shipped depth: it sees a file
//! whose bytes arrive at the speed of memory.
//!
//! **It is a cache of the file and never the only way to it.** Every read
//! the window cannot serve goes straight to the file: one behind the run
//! (a slab already given back), one from before a run began, any read
//! once the reader has met an error, which the direct read then reports in
//! the caller's own terms. No byte the engine is handed differs from what
//! the file answers at that offset; no verdict moves.
//!
//! **A run begins where reads are seen to go in order, and nowhere else.**
//! Nothing is read ahead until the reads that went to the file have run
//! on from one another for a short stretch (the window's probation, a
//! mebibyte at the shipped slab); the run then begins at their end. A
//! read that skips more than that stretch past where the run has got to
//! ends it, and the next stretch in order begins another. So a walk that
//! hops from header to header over members the command does not extract
//! costs no read it did not ask for, the reader never reads through what
//! the walk skipped, and a command that reads the file's end before its
//! start still gets its run. What a run does read past is its two slabs,
//! which is why the walk asks for a window only when it extracts EVERY
//! member (`cold_window_of`): one member of 64 MiB picked out of a cold
//! set of sixty-four took 0.49 s through a window that read on behind it
//! where it takes 0.11 s without (an M1 Mac, K=7, the selection
//! run).
//!
//! **On by default** on that route, its rows being in on two Apple boxes;
//! `RARFAST_COLD_WINDOW=0` (or `off`) gives the deep route before it.
//!
//! **The reader ASKS THE KERNEL AHEAD of its own reads** (the work
//! of 2 Oct 2026 for the cold stored extract on two newer Apple machines).
//! Before it reads a slab it asks for the slab and [`AHEAD`] bytes of the
//! file past it (`fcntl(F_RDADVISE)`, `engine::read_ahead_range`), each
//! byte of a run once. Counted on an M5 MacBook Air (4 GiB to
//! disk, cold, K=7, 2 Oct 2026):
//! the window alone left a
//! cold stored extract at 0.81 to 0.86 of that drive, the writer in
//! `write` for 99 percent of its samples and the reader in `pread` for 70.
//! What moved it was the size of the request the DRIVE is given, not the
//! bytes this process holds: sixteen slabs of 128 MiB were level with two
//! (1.76 s), two slabs of a gibibyte reached 1.61 s, and two of 128 MiB
//! with the kernel asked 256 MiB ahead 1.46 s, with the peak where it was.
//! On an M1 Ultra, whose cold extract was at its drive already, the
//! request is level (0.98 to 1.01 in three timed runs); a gibibyte ahead
//! lost 6 percent of one row there, which is why the distance is the
//! smaller one. The request holds no memory of the command's (the cache's
//! pages are the kernel's to drop) and changes no byte a read answers.
//! `RARFAST_COLD_WINDOW_ASK=0` (or `off`) is the window without it.
//!
//! **A form it was chosen over**: a reader that first measured itself for
//! three slabs and asked only where it had been reading for half the clock
//! or more (so that a drive whose WRITE is the slow side, where the reader
//! mostly stands waiting, is asked for nothing). On that laptop it gave
//! back a third of the gain (1.15x to 1.17x over main against 1.20x to
//! 1.25x, the slabs read before the verdict), and the one box it was built
//! for, an M3 Ultra whose drive was 98 percent full and slowing by the
//! hour, read 0.96x to 0.98x asked always and 1.006x measured, inside that
//! box's own spread either way.
//!
//! **Its memory and its thread are the command's.** Two slabs are what the
//! deep stored route held before it in the seam's ring
//! (`STORED_COLD_READ_AHEAD`), so the command holds what it held; a stated
//! `-mm` keeps the engine's own derivation and no window, and so does
//! `-mt1`, which states one thread. A slab's pages are touched only as far
//! as the file fills them, so a small archive costs what it holds.
//!
//! Safe Rust and std alone.

use std::collections::VecDeque;
use std::fs::File;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

/// The slabs a window holds: one the reader is filling, one the walk is
/// reading from. A third bought nothing in the probe (1.530 s at two,
/// 1.542 s at three).
pub(crate) const SLABS: usize = 2;

/// A slab's size. The probe's ladder on the M1 Ultra: 32 MiB 1.62 s,
/// 64 MiB 1.57 s, 128 MiB 1.54 s, 256 MiB 1.52 s; 128 MiB is the size the
/// deep route's ring already held, so the command's memory does not move.
/// (Named by the walk's rule, which is the `parallel` build's: a build
/// without threads arms no window.)
#[cfg_attr(not(feature = "parallel"), allow(dead_code))]
pub(crate) const SLAB: u64 = 128 << 20;

/// The slab size archives opened from here on are windowed at, 0 for no
/// window. Process-wide, like `engine::advise_sequential_reads`: a command
/// line runs one command, and the walk sets it before it opens a volume.
static ARMED: AtomicU64 = AtomicU64::new(0);

/// Window every regular archive file opened from here on, at `slab` bytes
/// a slab; 0 opens them plain again.
#[cfg_attr(not(feature = "parallel"), allow(dead_code))]
pub(crate) fn arm(slab: u64) {
    ARMED.store(slab, Ordering::Relaxed);
}

/// How far past the slab it is about to read a window's reader asks the
/// kernel for the file, as shipped: 256 MiB.
///
/// **The ladder** (cold `x` of 4 GiB on disk, K=7, 2 Oct 2026, one member
/// and eight members). On an
/// M5 MacBook Air, against 1.82 s with no request: 1 MiB (the slab alone)
/// 1.52 and 1.64 s, 64 MiB 1.51 and 1.51, 128 MiB 1.62 and 1.53, 256 MiB
/// 1.52 and 1.46, and in the run before it 256 MiB 1.46 and 1.65
/// against a gibibyte's 1.43 and 1.62. On an M1 Ultra 256 MiB read 1.526
/// and 1.569 s against 1.533 and 1.570 with none, and a gibibyte 1.493 and
/// 1.683 against 1.532 and 1.589: the far request costs the eight-member
/// row there what the near one does not.
#[cfg_attr(not(feature = "parallel"), allow(dead_code))]
pub(crate) const AHEAD: u64 = 256 << 20;

/// How far past each slab the reader of a window opened from here on asks
/// the kernel for the file, 0 for no request. Process-wide, as [`ARMED`]
/// is, and set by the walk beside it.
static ARMED_AHEAD: AtomicU64 = AtomicU64::new(0);

/// The readers of windows opened from here on ask the kernel for `ahead`
/// bytes past each slab they read; 0 has them ask for nothing.
#[cfg_attr(not(feature = "parallel"), allow(dead_code))]
pub(crate) fn arm_ahead(ahead: u64) {
    ARMED_AHEAD.store(ahead, Ordering::Relaxed);
}

/// The slab size in force, if a window is asked for.
pub(crate) fn armed() -> Option<u64> {
    match ARMED.load(Ordering::Relaxed) {
        0 => None,
        slab => Some(slab),
    }
}

/// How far reads must run on in order before a run begins at `slab` bytes
/// a slab: an eighth of a slab, at least a page and at most a mebibyte.
/// The floor keeps a header's few reads from starting a run; the ceiling
/// is eight of the engine's 128 KiB requests, or one of the seam's.
fn probation_of(slab: u64) -> u64 {
    (slab / 8).clamp(4096, 1 << 20)
}

/// One filled slab: slab `index` of the run, `len` bytes of it the file's.
struct Held {
    index: u64,
    len: usize,
    buf: Vec<u8>,
}

/// What the walk's reads and the reader thread share.
struct State {
    /// The file offset slab 0 of the run begins at; `None` while there is
    /// no run.
    origin: Option<u64>,
    /// The reads that went to the file and ran on from one another: where
    /// the stretch began, and the byte after its last.
    passing: Option<(u64, u64)>,
    /// Filled slabs, in order.
    held: VecDeque<Held>,
    /// Buffers with nothing in them.
    spare: Vec<Vec<u8>>,
    /// The slab the reader fills next.
    next: u64,
    /// The byte after the last one the run handed out: where the walk
    /// reads next if it goes on in order.
    frontier: u64,
    /// The lowest slab of the run that has not landed yet: a slab below
    /// it that is not held has been given back.
    landing: u64,
    /// Bumped when the run moves, so a slab read for the old run is
    /// dropped when it lands.
    run: u64,
    /// The reader met an error, or could not be started: every read goes
    /// to the file.
    dead: bool,
    /// The window is being dropped.
    stop: bool,
}

struct Shared {
    file: File,
    len: u64,
    slab: u64,
    /// How far reads must run on in order before a run begins.
    probation: u64,
    /// How far past a slab the reader asks the kernel for the file before
    /// it reads the slab; 0 asks for nothing.
    ahead: u64,
    state: Mutex<State>,
    /// A slab landed, or the reader stopped.
    landed: Condvar,
    /// A buffer came back, the run moved, or the window is stopping.
    wanted: Condvar,
    /// Bytes served out of slabs, reads that went to the file in part or
    /// in whole, and bytes the kernel was asked for ahead: what
    /// `RARFAST_COLD_WINDOW_SAY` prints.
    served: AtomicU64,
    passed: AtomicU64,
    asked: AtomicU64,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        // A panic while the lock is held leaves nothing half-written that
        // a later read trusts: the state is taken as it stands.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The window over one archive file. See the module.
pub(crate) struct Window {
    shared: Arc<Shared>,
    reader: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl Window {
    /// A window over `file`, whose length is `len`, or `None` where the
    /// file's handle cannot be shared with a reader thread. Nothing is
    /// read and no thread is started until a run begins.
    pub(crate) fn new(file: &File, len: u64, slab: u64) -> Option<Window> {
        Window::asking(file, len, slab, ARMED_AHEAD.load(Ordering::Relaxed))
    }

    /// [`Window::new`] with the distance its reader asks the kernel ahead
    /// stated, 0 for no request: an archive's window takes the distance the
    /// walk armed, and a create's cold input member states its own
    /// (`dialect::rar::create`, the cold stored create on macOS).
    pub(crate) fn asking(file: &File, len: u64, slab: u64, ahead: u64) -> Option<Window> {
        let slab = slab.max(1);
        usize::try_from(slab).ok()?;
        let file = file.try_clone().ok()?;
        Some(Window {
            shared: Arc::new(Shared {
                file,
                len,
                slab,
                probation: probation_of(slab),
                ahead,
                state: Mutex::new(State {
                    origin: None,
                    passing: None,
                    held: VecDeque::new(),
                    spare: (0..SLABS).map(|_| Vec::new()).collect(),
                    next: 0,
                    frontier: 0,
                    landing: 0,
                    run: 0,
                    dead: false,
                    stop: false,
                }),
                landed: Condvar::new(),
                wanted: Condvar::new(),
                served: AtomicU64::new(0),
                passed: AtomicU64::new(0),
                asked: AtomicU64::new(0),
            }),
            reader: Mutex::new(None),
        })
    }

    /// Fill as much of `buf` as the window holds or will hold of the bytes
    /// at `offset`, and say how many: `buf.len()` unless the window stops
    /// serving part of the way, when the caller reads the rest from the
    /// file (which this call has then noted, so a stretch of such reads in
    /// order begins a run). The caller has cut `buf` to the file's length.
    pub(crate) fn read(&self, offset: u64, buf: &mut [u8]) -> usize {
        let shared = &*self.shared;
        let slab = shared.slab;
        let mut done = 0usize;
        let mut state = shared.lock();
        while done < buf.len() {
            if state.dead {
                break;
            }
            let at = offset + done as u64;
            let Some(origin) = state.origin else {
                break;
            };
            if at < origin {
                break;
            }
            let index = (at - origin) / slab;
            // A skip past where the run has got to (a member the command
            // does not extract, hopped over): the reads have left this
            // run. It ends, and the reader does NOT read through what was
            // skipped; a slab in flight is dropped when it lands.
            if at > state.frontier.saturating_add(shared.probation) {
                end_run(&mut state);
                shared.wanted.notify_all();
                break;
            }
            // The walk has moved on from every slab before this one.
            while state.held.front().is_some_and(|h| h.index < index) {
                let freed = state.held.pop_front().expect("checked above");
                state.spare.push(freed.buf);
                shared.wanted.notify_all();
            }
            let front = state.held.front().map(|held| held.index);
            if front == Some(index) {
                let held = state.held.front().expect("matched above");
                let inside = (at - origin - index * slab) as usize;
                if inside >= held.len {
                    // The file answered short of its length there.
                    break;
                }
                let n = (buf.len() - done).min(held.len - inside);
                buf[done..done + n].copy_from_slice(&held.buf[inside..inside + n]);
                let emptied = inside + n == held.len;
                done += n;
                state.frontier = state.frontier.max(at + n as u64);
                if emptied {
                    let freed = state.held.pop_front().expect("matched above");
                    state.spare.push(freed.buf);
                    shared.wanted.notify_all();
                }
            } else if front.is_some() || index < state.landing {
                // Slabs land in order, so one that is neither held nor
                // still to land was given back: behind the run.
                break;
            } else {
                // Being read, or next: nothing older is held, so the
                // reader has a buffer for it. Wait for it to land.
                state = shared.landed.wait(state).unwrap_or_else(|e| e.into_inner());
            }
        }
        if done == buf.len() {
            state.passing = None;
        } else if !state.dead {
            // The caller reads [from, to) from the file. Where such reads
            // run on from one another for the probation, a run begins at
            // their end: the byte the next read in order asks for.
            let (from, to) = (offset + done as u64, offset + buf.len() as u64);
            let begun = match state.passing {
                Some((begun, next)) if next == from => begun,
                _ => from,
            };
            state.passing = Some((begun, to));
            if to - begun >= shared.probation && to < shared.len {
                end_run(&mut state);
                state.origin = Some(to);
                state.frontier = to;
                state.passing = None;
                if !self.start() {
                    state.dead = true;
                }
                shared.wanted.notify_all();
            }
        }
        drop(state);
        shared.served.fetch_add(done as u64, Ordering::Relaxed);
        if done < buf.len() {
            shared.passed.fetch_add(1, Ordering::Relaxed);
        }
        done
    }

    /// Start the reader thread, once; false where the host will not.
    fn start(&self) -> bool {
        let mut reader = self.reader.lock().unwrap_or_else(|e| e.into_inner());
        if reader.is_some() {
            return true;
        }
        let shared = Arc::clone(&self.shared);
        match std::thread::Builder::new()
            .name("rarfast-window".into())
            .spawn(move || fill(&shared))
        {
            Ok(handle) => {
                *reader = Some(handle);
                true
            }
            Err(_) => false,
        }
    }

    /// Bytes served from slabs, reads handed back to the file in part or
    /// in whole, and bytes the kernel was asked for ahead.
    #[cfg_attr(not(any(test, feature = "read-depth-knob")), allow(dead_code))]
    pub(crate) fn counts(&self) -> (u64, u64, u64) {
        (
            self.shared.served.load(Ordering::Relaxed),
            self.shared.passed.load(Ordering::Relaxed),
            self.shared.asked.load(Ordering::Relaxed),
        )
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        {
            let mut state = self.shared.lock();
            state.stop = true;
        }
        self.shared.wanted.notify_all();
        self.shared.landed.notify_all();
        let handle = self.reader.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(handle) = handle {
            // At most the read in flight: one slab.
            let _ = handle.join();
        }
    }
}

/// End the run: its slabs go back, and a slab being read for it is
/// dropped when it lands.
fn end_run(state: &mut State) {
    state.run += 1;
    state.origin = None;
    state.next = 0;
    state.landing = 0;
    while let Some(freed) = state.held.pop_front() {
        state.spare.push(freed.buf);
    }
}

/// The reader thread: slabs of the run in order, one read each, for as
/// long as there is a run, a buffer to fill and file left to read.
fn fill(shared: &Shared) {
    let slab = shared.slab;
    // The run the kernel was last asked for, and the byte after what it
    // was asked for of it.
    let mut asked: (u64, u64) = (u64::MAX, 0);
    let mut state = shared.lock();
    loop {
        if state.stop {
            return;
        }
        let start = state
            .origin
            .map(|origin| origin.saturating_add(state.next.saturating_mul(slab)));
        let start = match start {
            Some(start) if !state.dead && !state.spare.is_empty() && start < shared.len => start,
            _ => {
                state = shared.wanted.wait(state).unwrap_or_else(|e| e.into_inner());
                continue;
            }
        };
        let mut buf = state.spare.pop().expect("checked above");
        let (index, run) = (state.next, state.run);
        state.next += 1;
        drop(state);

        let want = usize::try_from((shared.len - start).min(slab)).unwrap_or(usize::MAX);
        if shared.ahead > 0 {
            // The slab and the stretch after it, less what this run has
            // asked for already: each byte of the run is asked for once.
            if asked.0 != run {
                asked = (run, start);
            }
            let upto = shared
                .len
                .min((start + want as u64).saturating_add(shared.ahead));
            let from = asked.1.max(start);
            if upto > from {
                crate::engine::read_ahead_range(&shared.file, from, upto - from);
                shared.asked.fetch_add(upto - from, Ordering::Relaxed);
                asked.1 = upto;
            }
        }
        if buf.len() < want {
            // Zeroed pages from the allocator, untouched until the read
            // lands in them: a slab costs what the file puts in it.
            buf = vec![0u8; want];
        }
        let mut got = 0usize;
        let mut failed = false;
        while got < want {
            match rarkit::RangeSource::read_at(
                &shared.file,
                start + got as u64,
                &mut buf[got..want],
            ) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => {
                    failed = true;
                    break;
                }
            }
        }

        state = shared.lock();
        if failed {
            // The walk's own read of these bytes reports it.
            state.dead = true;
            state.spare.push(buf);
        } else if state.run != run {
            state.spare.push(buf);
        } else {
            state.landing = index + 1;
            state.held.push_back(Held {
                index,
                len: got,
                buf,
            });
        }
        shared.landed.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A file of `len` bytes no two aligned runs of which agree, and its
    /// bytes.
    fn fixture(tag: &str, len: usize) -> (std::path::PathBuf, Vec<u8>) {
        let path =
            std::env::temp_dir().join(format!("rarfast-window-{}-{tag}", std::process::id()));
        let mut state = 0x9e37_79b9_7f4a_7c15u64 ^ len as u64;
        let bytes: Vec<u8> = (0..len)
            .map(|_| {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (state >> 56) as u8
            })
            .collect();
        std::fs::File::create(&path)
            .unwrap()
            .write_all(&bytes)
            .unwrap();
        (path, bytes)
    }

    /// A read as the archive's source makes it: the window first, the file
    /// for whatever it did not serve.
    fn read(window: &Window, file: &File, offset: u64, buf: &mut [u8]) {
        let served = window.read(offset, buf);
        let mut got = served;
        while got < buf.len() {
            let n =
                rarkit::RangeSource::read_at(file, offset + got as u64, &mut buf[got..]).unwrap();
            assert!(n > 0, "the file ended inside a read cut to its length");
            got += n;
        }
    }

    #[test]
    fn reads_in_order_are_the_files_bytes_at_every_request_size() {
        let (path, bytes) = fixture("order", 10_500);
        let file = File::open(&path).unwrap();
        for slab in [1u64, 7, 1000, 4096, 10_499, 10_500, 1 << 20] {
            for request in [1usize, 3, 128, 999, 1000, 1001, 4096, 10_500] {
                let window = Window::new(&file, bytes.len() as u64, slab).unwrap();
                let mut at = 0usize;
                while at < bytes.len() {
                    let n = request.min(bytes.len() - at);
                    let mut buf = vec![0u8; n];
                    read(&window, &file, at as u64, &mut buf);
                    assert_eq!(
                        buf,
                        &bytes[at..at + n],
                        "slab {slab} request {request} at {at}"
                    );
                    at += n;
                }
                // All but the probation, which the file answers, and the
                // read it ends in.
                let (served, _, _) = window.counts();
                let least =
                    (bytes.len() as u64).saturating_sub(probation_of(slab) + request as u64);
                assert!(
                    served >= least && served < bytes.len() as u64,
                    "slab {slab} request {request}: served {served}, at least {least}"
                );
            }
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_read_behind_the_run_or_far_ahead_of_it_is_still_the_files_bytes() {
        let (path, bytes) = fixture("jumps", 64_000);
        let file = File::open(&path).unwrap();
        let window = Window::new(&file, bytes.len() as u64, 1000).unwrap();
        // Headers hopped over (no run), a stretch in order that begins a
        // run, a step back, on in order, a skip of many slabs and a new
        // stretch there, a step back again, the tail, the last byte, and
        // the whole file from its first byte last.
        let plan: [(usize, usize); 12] = [
            (0, 300),
            (20_000, 300),
            (5_000, 300),
            (5_300, 4_000),
            (9_300, 2_900),
            (5_100, 50),
            (12_200, 7_000),
            (40_000, 5_500),
            (39_000, 2_000),
            (45_500, 18_500),
            (63_999, 1),
            (0, 64_000),
        ];
        for (at, n) in plan {
            let mut buf = vec![0u8; n];
            read(&window, &file, at as u64, &mut buf);
            assert_eq!(buf, &bytes[at..at + n], "at {at} for {n}");
        }
        let (served, _, _) = window.counts();
        assert!(served > 25_000, "the runs in order were served: {served}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn header_hops_read_nothing_ahead_and_a_stretch_in_order_does() {
        let (path, bytes) = fixture("hops", 400_000);
        let file = File::open(&path).unwrap();
        let window = Window::new(&file, bytes.len() as u64, 32_768).unwrap();
        assert_eq!(probation_of(32_768), 4096);
        // Ten small reads far apart, as a walk over members it skips.
        for hop in 0..10usize {
            let at = hop * 37_000;
            let mut buf = [0u8; 600];
            read(&window, &file, at as u64, &mut buf);
            assert_eq!(buf[..], bytes[at..at + 600]);
        }
        assert!(
            window.reader.lock().unwrap().is_none(),
            "no run, so no reader thread"
        );
        assert_eq!(window.counts().0, 0);
        // Then a member read in order: the run begins after the probation.
        let mut at = 100_000usize;
        while at < 200_000 {
            let mut buf = [0u8; 2048];
            read(&window, &file, at as u64, &mut buf);
            assert_eq!(buf[..], bytes[at..at + 2048]);
            at += 2048;
        }
        let (served, _, _) = window.counts();
        assert!(served >= 100_000 - 4096 - 2048, "{served}");
        // A hop far past the run ends it: nothing is held for the old run.
        let mut buf = [0u8; 600];
        read(&window, &file, 399_000, &mut buf);
        assert_eq!(buf[..], bytes[399_000..399_600]);
        assert!(window.shared.lock().origin.is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_skip_ends_the_run_and_the_reader_does_not_read_through_it() {
        let (path, bytes) = fixture("skip", 400_000);
        let file = File::open(&path).unwrap();
        let slab = 32_768u64;
        let window = Window::new(&file, bytes.len() as u64, slab).unwrap();
        // A member read in order: the run begins and serves.
        let mut at = 0usize;
        while at < 60_000 {
            let mut buf = [0u8; 2048];
            read(&window, &file, at as u64, &mut buf);
            assert_eq!(buf[..], bytes[at..at + 2048]);
            at += 2048;
        }
        let (served, _, _) = window.counts();
        assert!(served > 40_000, "{served}");
        // A hop of one slab and a half: inside what two slabs ahead would
        // reach, and still a skip. The run ends; the hop's bytes are the
        // file's, read from the file; nothing more is served.
        let hop = at + 48_000;
        let mut buf = [0u8; 600];
        read(&window, &file, hop as u64, &mut buf);
        assert_eq!(buf[..], bytes[hop..hop + 600]);
        {
            let state = window.shared.lock();
            assert!(state.origin.is_none(), "the skip ended the run");
            assert!(state.held.is_empty());
        }
        assert_eq!(
            window.counts().0,
            served,
            "the hop was not served from a slab"
        );
        // A step back inside the probation is not a skip: a re-read of a
        // header just behind the run's reads keeps a run going.
        let window = Window::new(&file, bytes.len() as u64, slab).unwrap();
        for at in (100_000..140_000).step_by(2000) {
            let mut buf = [0u8; 2000];
            read(&window, &file, at as u64, &mut buf);
            assert_eq!(buf[..], bytes[at..at + 2000]);
        }
        let mut back = [0u8; 500];
        read(&window, &file, 139_000, &mut back);
        assert_eq!(back[..], bytes[139_000..139_500]);
        let mut on = [0u8; 2000];
        read(&window, &file, 140_000, &mut on);
        assert_eq!(on[..], bytes[140_000..142_000]);
        assert!(window.shared.lock().origin.is_some(), "the run goes on");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn any_order_of_reads_is_the_files_bytes() {
        let (path, bytes) = fixture("any", 200_000);
        let file = File::open(&path).unwrap();
        for slab in [512u64, 4096, 65_536] {
            let window = Window::new(&file, bytes.len() as u64, slab).unwrap();
            let mut state = slab ^ 0x5851_f42d_4c95_7f2d;
            let mut at = 0usize;
            for _ in 0..600 {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                let pick = (state >> 33) as usize;
                // Mostly onward from where the last read ended, as a walk
                // goes; now and then anywhere.
                if pick.is_multiple_of(7) {
                    at = (pick / 7) % bytes.len();
                }
                let n = (1 + (pick / 49) % 9_000).min(bytes.len() - at);
                let mut buf = vec![0u8; n];
                read(&window, &file, at as u64, &mut buf);
                assert_eq!(buf, &bytes[at..at + n], "slab {slab} at {at} for {n}");
                at = (at + n) % bytes.len();
            }
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_window_nobody_reads_to_the_end_stops_when_dropped() {
        let (path, bytes) = fixture("drop", 50_000);
        let file = File::open(&path).unwrap();
        // Never read: no thread. Read into a run and dropped with slabs
        // held and the reader waiting for a buffer.
        drop(Window::new(&file, bytes.len() as u64, 1000).unwrap());
        let window = Window::new(&file, bytes.len() as u64, 1000).unwrap();
        let mut buf = [0u8; 5000];
        read(&window, &file, 0, &mut buf);
        let mut next = [0u8; 10];
        read(&window, &file, 5000, &mut next);
        assert_eq!(buf, bytes[..5000]);
        assert_eq!(next, bytes[5000..5010]);
        assert_eq!(window.counts().0, 10, "the second read came from a slab");
        drop(window);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_file_cut_short_under_the_window_is_read_as_the_file_answers() {
        let (path, bytes) = fixture("short", 30_000);
        let file = File::open(&path).unwrap();
        // The window is told the length the file was opened with; the file
        // is then cut, so a slab lands short.
        let window = Window::new(&file, bytes.len() as u64, 4096).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(10_000)
            .unwrap();
        // A stretch in order begins the run at 4,096; the read after it
        // asks past the cut.
        let mut head = vec![0u8; 4096];
        read(&window, &file, 0, &mut head);
        assert_eq!(head, bytes[..4096]);
        let mut buf = vec![0u8; 12_000];
        let served = window.read(4096, &mut buf);
        assert!(
            served <= 10_000 - 4096,
            "nothing past the cut is served: {served}"
        );
        assert_eq!(buf[..served], bytes[4096..4096 + served]);
        let _ = std::fs::remove_file(&path);
    }

    /// **The request ahead changes no byte and asks for each byte of a
    /// run at most once**: the same reads, at every slab and distance, are
    /// the file's bytes; a reader that asks for nothing counts nothing;
    /// one that asks counts no more than the file from where its run
    /// began, however many slabs the request spans.
    #[test]
    fn the_request_ahead_changes_no_byte_and_asks_for_each_byte_once() {
        let (path, bytes) = fixture("ahead", 70_000);
        let file = File::open(&path).unwrap();
        let len = bytes.len() as u64;
        for slab in [512u64, 4096, 30_000, 1 << 20] {
            for ahead in [0u64, 1, 4096, 10_000, 1 << 30] {
                let window = Window::asking(&file, len, slab, ahead).unwrap();
                let mut at = 0usize;
                while at < bytes.len() {
                    let n = 1000.min(bytes.len() - at);
                    let mut buf = vec![0u8; n];
                    read(&window, &file, at as u64, &mut buf);
                    assert_eq!(buf, &bytes[at..at + n], "slab {slab} ahead {ahead} at {at}");
                    at += n;
                }
                let (served, _, asked) = window.counts();
                if probation_of(slab) >= len {
                    // No stretch in order is long enough for a run here.
                    assert_eq!((served, asked), (0, 0), "slab {slab} ahead {ahead}");
                    continue;
                }
                assert!(served > 0, "slab {slab} ahead {ahead}: a run began");
                if ahead == 0 {
                    assert_eq!(asked, 0, "slab {slab}: nothing is asked for unasked");
                } else {
                    // The run begins after the probation; no byte before
                    // it and none past the file's end is asked for, and
                    // none twice.
                    assert!(
                        asked > 0 && asked <= len - probation_of(slab),
                        "slab {slab} ahead {ahead}: asked for {asked} of {len}"
                    );
                }
            }
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_switch_is_off_until_armed() {
        // The only test that reads or writes the process-wide switch.
        assert_eq!(armed(), None);
        arm(SLAB);
        assert_eq!(armed(), Some(SLAB));
        arm(0);
        assert_eq!(armed(), None);
    }
}
