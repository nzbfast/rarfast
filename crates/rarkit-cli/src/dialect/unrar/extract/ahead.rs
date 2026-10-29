//! CREATE AHEAD and CLOSE BEHIND: a plain member's file made, and closed,
//! off the walking thread (Linux, the pool's walk).
//!
//! **Why (counted 14 Oct 2026 on an 8-core x86-64 Linux box, ext4, `x` of
//! 20,000 small files in 200 directories at `-m3`).** The walking thread
//! makes every file call of such a run: 20,065 creates, 20,000 time sets
//! and 20,004 closes, on CPU for the whole wall, while the decoding
//! workers wait for it. The file system alone made the same 20,000 files'
//! creates in 0.079 s on one thread and 0.026 s on four, so the one thread
//! that makes them is the run's bound.
//!
//! **What moves, and what does not.** Only the system calls move. Every
//! decision stays the walk's, made in archive order as before: the
//! member's line, its directories and their `Creating` lines, the rule
//! for a taken name, and the complaint for a create that fails. A helper
//! makes, for a member the walk has not reached yet, the one exclusive
//! create the walk would make first for it (SPEC-CLI 9.4 W1: same path,
//! same flags, same mode, never through a link). When the walk reaches
//! that member and its own first create would be that very one, it takes
//! the helper's file instead of making the call ([`Ahead::take`]). On any
//! other answer the helper had (the name taken, a refusal) it made
//! nothing, and the walk does exactly what it did before, its own create
//! included. A file made ahead for a member the walk never takes (the run
//! stopped first) is removed when the walk ends, by name, and only while
//! the name is still that file.
//!
//! A helper makes a member's file only under a directory the walk has
//! already made or found real, or one the helper has just made itself
//! inside such a directory (an exclusive `mkdir`, which follows no link):
//! a file is never made through a link. A directory a helper made that
//! the walk never reached is removed when the walk ends, if empty.
//!
//! The close of such a member (its time and mode set on the open handle,
//! then the handle closed) is handed to the same helpers after the
//! member's verdict ([`Ahead::close_later`]); every one is done before
//! the walk returns, so before the directories are finished and before
//! the run says anything of its end.
//!
//! **Where it is armed** ([`Run::arm_ahead`]): `x` and `e` on the pool's
//! walk, on Linux, where no member of the archive is a link or a copy and
//! no rule looks at a name before creating it (`-o-`); for a member that
//! is a plain file, not encrypted (or encrypted with a password check
//! record, below), not split, not of an unknown version,
//! and no larger than a member held in memory ([`output::HOLD_BOUND`]),
//! so its first create is the exclusive one under every other rule. The
//! helpers are tasks on the read's own pool, whose width is the run's.
//!
//! **macOS (APFS), its own arm.** Counted on 14 Oct 2026 on an Apple M1
//! Ultra, the same 20,000 files: the walk's samples were `open` 63 to 67
//! percent, the time set 16 and the close 11, and the file system alone
//! made the files' creates in 0.77 s on one thread, 0.50 on two, 0.58 on
//! four and 1.27 on eight. Creates there scale to two threads and wider
//! COSTS, so the arm starts at most `MACOS_HELPERS` helpers. And the
//! walk's own create of a member a helper did not reach is made through
//! the helpers' book (`Ahead::make_here`, macOS only), the same create call for
//! call, so that file is closed behind too: with closes handed over only
//! for files made ahead, the walk still spent 22 percent of its samples
//! setting times and closing.
//!
//! **An encrypted member WITH a password check record** is made ahead too
//! (FROM-STUDIO 391 A, counted 14 Oct 2026 on an 8-core x86-64 Linux box:
//! `x` of the same 20,000 files under `-p` and `-hp` read as this form off,
//! 0.13 to 0.15 s against 0.10 to 0.12, the walk making every file call).
//! A wrong password for the whole archive is found at the open and its
//! encrypted members are done before the helpers are armed; a member whose
//! own record fails is refused before its first byte, after the walk has
//! made (or taken) its file, which the refusal removes as it always did.
//! So a wrong password leaves what the walk alone would leave.

use super::*;

use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

/// How far ahead of the walk, in plan entries, a member's file may be made,
/// as a multiple of the walk's breadth: TWICE it, the outputs the pool
/// itself holds open at once (`Pool::open`'s bound). So a run that is
/// killed (no handler can run then) leaves no more empty files than it
/// left before the form, where up to that many members are opened ahead
/// of the decode. A window of 128 read no faster on the same box.
const WINDOW_PER_BREADTH: usize = 2;

/// The most helpers a run starts. Four made the count's 20,000 creates
/// three times as fast as one.
const MOST_HELPERS: usize = 4;

/// The fewest members worth starting helpers for.
const FEWEST: usize = 64;

// A lone member is never armed (FROM-STUDIO 518 C): its run may have the
// walking thread for its whole pool, where a spawned helper never runs and
// `Ahead::stop` would wait for it for ever. `Run::drive` says the other two
// guards.
const _: () = assert!(FEWEST > 1);

/// The most helpers a run starts on macOS: APFS creates scale to two
/// threads and get slower past four. Timed as a knob on an Apple M1 Ultra
/// (`x` of 20,000 small files, K=5, plain builds): one helper 1.24 s, two
/// 1.08, three 1.12, four 1.17, against 1.44 with none.
#[cfg(target_os = "macos")]
const MACOS_HELPERS: usize = 2;

/// macOS's window, as a multiple of the walk's breadth: the same as
/// [`WINDOW_PER_BREADTH`], held apart so either can move alone. A window
/// of 128 or 400 entries read no faster on the same box (1.06 and 1.09 s
/// against 1.08).
#[cfg(target_os = "macos")]
const MACOS_WINDOW_PER_BREADTH: usize = 2;

/// The most closes waiting for a helper before the walk closes a member's
/// file itself, so the descriptors held open stay bounded: where no soft
/// descriptor limit binds. Under one, the window and this queue share what
/// [`crate::workers::ahead_descriptors`] allows, the window at most half
/// of it and the queue the rest (FROM-STUDIO 443 C: a constant 256 here
/// alone outgrew macOS's default limit of 256 once the closes lagged).
const MOST_WAITING_CLOSES: usize = 256;

/// How long a helper with nothing it may do sleeps before it looks again,
/// after [`SPINS`] yields.
const NAP: std::time::Duration = std::time::Duration::from_micros(50);

/// How many times a helper held at a directory or at the window yields
/// before it naps.
const SPINS: u32 = 32;

// An item's states.
const OPEN: u8 = 0;
const CLAIMED: u8 = 1;
const MADE: u8 = 2;
const NOT_MADE: u8 = 3;
const TAKEN: u8 = 4;
const USED: u8 = 5;

/// One member a helper may make the file of.
struct Item {
    /// Its plan index.
    index: usize,
    /// Its path, a range of [`Ahead::paths`].
    path: (usize, usize),
    /// The mode it is created with (`mode::file_create`).
    mode: u32,
    /// Its directory, a range of [`Ahead::paths`] (empty: the current
    /// directory, always there).
    dir: (usize, usize),
    /// The plan index whose open makes or finds the directory; `None` for
    /// the current directory.
    dir_after: Option<usize>,
    /// The plan index whose open makes or finds the directory ABOVE it,
    /// where the helper may make the directory itself.
    above_after: Option<usize>,
    state: AtomicU8,
    file: Mutex<Option<fs::File>>,
}

/// The run's helpers and what they share with the walk.
pub(super) struct Ahead {
    /// Every item's path and directory, end to end.
    paths: String,
    items: Vec<Item>,
    /// The item of each plan index, or `u32::MAX`.
    by_index: Vec<u32>,
    /// The next item a helper takes up.
    next: AtomicUsize,
    /// The plan entry after the last one the walk has opened.
    walked: AtomicUsize,
    /// Set when the walk is over: the helpers stop.
    over: AtomicBool,
    /// Helpers still running.
    running: AtomicUsize,
    /// Whether closes are handed to the helpers at all.
    closes_behind: bool,
    /// How far ahead of the walk a file may be made ([`WINDOW_PER_BREADTH`]).
    window: usize,
    /// The most closes waiting for a helper ([`MOST_WAITING_CLOSES`], or
    /// the descriptor limit's share).
    most_closes: usize,
    /// Member files whose close waits for a helper.
    closes: Mutex<Vec<Box<dyn Write + Send>>>,
    /// How many closes were handed over and are not yet done.
    closes_owed: AtomicUsize,
    /// The directories helpers made, by their range in `paths`.
    made_dirs: Mutex<Vec<(usize, usize)>>,
}

/// What the knob asks for (`RARFAST_CREATE_AHEAD`, `reader-knobs` builds
/// only), words joined by commas: `off`, `create` (no close behind),
/// `helpers:<n>`, or `window:<n>` (a window of n entries in place of
/// [`WINDOW_PER_BREADTH`]'s).
struct Asked {
    on: bool,
    closes: bool,
    helpers: Option<usize>,
    window: Option<usize>,
}

fn asked() -> Asked {
    let words = crate::knob::reader_var("RARFAST_CREATE_AHEAD").unwrap_or_default();
    let mut asked = Asked {
        on: true,
        closes: true,
        helpers: None,
        window: None,
    };
    for word in words.split(',').map(str::trim) {
        match word {
            "off" => asked.on = false,
            "create" => asked.closes = false,
            _ => {
                if let Some(n) = word.strip_prefix("helpers:").and_then(|n| n.parse().ok()) {
                    asked.helpers = Some(n).filter(|&n: &usize| n > 0);
                }
                if let Some(n) = word.strip_prefix("window:").and_then(|n| n.parse().ok()) {
                    asked.window = (n > 0).then_some(n);
                }
            }
        }
    }
    asked
}

impl Ahead {
    /// The file made ahead for plan entry `index`, if a helper made it;
    /// otherwise `None`, and no helper will make it from now on. Called by
    /// the walk where its own first create of the member would be made.
    pub(super) fn take(&self, index: usize) -> Option<fs::File> {
        let item = self.item_of(index)?;
        loop {
            match item
                .state
                .compare_exchange(OPEN, TAKEN, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return None,
                // A helper's create is in flight: a few microseconds.
                Err(CLAIMED) => std::thread::yield_now(),
                Err(MADE) => {
                    let file = sink::lock(&item.file).take();
                    item.state.store(USED, Ordering::Release);
                    return file;
                }
                Err(_) => return None,
            }
        }
    }

    /// Whether plan entry `index`'s file is one a helper made and the walk
    /// took: its close may be handed back ([`Ahead::close_later`]).
    pub(super) fn made(&self, index: usize) -> bool {
        self.item_of(index)
            .is_some_and(|item| item.state.load(Ordering::Acquire) == USED)
    }

    /// macOS: the walk's own create of plan entry `index`, made here
    /// where [`Ahead::take`] has just given it the entry (no helper made
    /// it, and none will), so a file made fresh is closed behind as one
    /// made ahead is ([`Ahead::made`]). `None`, and nothing made, where
    /// the create the walk asks for is not the entry's own: another path
    /// (a name chosen at the question) or another mode. Otherwise the
    /// create's own answer, whatever it is: a taken name and a refusal
    /// are the walk's to judge, as they were.
    #[cfg(target_os = "macos")]
    pub(super) fn make_here(
        &self,
        index: usize,
        target: &Path,
        create: u32,
    ) -> Option<std::io::Result<Option<crate::safepath::Created>>> {
        let item = self.item_of(index)?;
        if item.state.load(Ordering::Acquire) != TAKEN
            || item.mode != create
            || Path::new(self.text(item.path)) != target
        {
            return None;
        }
        let made = crate::safepath::make_member_file(
            target,
            crate::safepath::IfOutputExists::Keep,
            create,
        );
        if let Ok(Some(created)) = &made {
            if created.beside.is_none() && !created.in_place {
                item.state.store(USED, Ordering::Release);
            }
        }
        Some(made)
    }

    /// The walk has opened every plan entry before `reached`.
    pub(super) fn walked(&self, reached: usize) {
        self.walked.store(reached, Ordering::Release);
    }

    /// Hands a member's file to the helpers to close, or gives it back
    /// where closes are not handed over or too many already wait.
    pub(super) fn close_later(&self, out: Box<dyn Write + Send>) -> Option<Box<dyn Write + Send>> {
        if !self.closes_behind
            || self.closes_owed.load(Ordering::Relaxed) >= self.most_closes
            || self.running.load(Ordering::Acquire) == 0
        {
            return Some(out);
        }
        self.closes_owed.fetch_add(1, Ordering::AcqRel);
        sink::lock(&self.closes).push(out);
        None
    }

    fn item_of(&self, index: usize) -> Option<&Item> {
        let at = *self.by_index.get(index)?;
        self.items.get(at as usize)
    }

    fn text(&self, range: (usize, usize)) -> &str {
        &self.paths[range.0..range.1]
    }

    /// One helper: makes the files of the items it takes up, in order, as
    /// the walk lets it, and closes what the walk hands back.
    fn help(&self) {
        let mut at = self.next.fetch_add(1, Ordering::AcqRel);
        let mut spins = 0;
        loop {
            self.close_waiting();
            if self.over.load(Ordering::Acquire) {
                break;
            }
            let Some(item) = self.items.get(at) else {
                // Nothing left to make: the pool's thread goes back to the
                // pool (the engine's checksums use it), and the walk closes
                // what it closes from here on itself.
                break;
            };
            let walked = self.walked.load(Ordering::Acquire);
            if item.state.load(Ordering::Acquire) != OPEN || item.index < walked {
                // The walk got there first.
                at = self.next.fetch_add(1, Ordering::AcqRel);
                continue;
            }
            if item.index >= walked + self.window || !self.dir_ready(item, walked) {
                // The walk frees an item every few microseconds: a few yields
                // first, then a nap.
                spins += 1;
                if spins < SPINS {
                    std::thread::yield_now();
                } else {
                    spins = 0;
                    std::thread::park_timeout(NAP);
                }
                continue;
            }
            spins = 0;
            if item
                .state
                .compare_exchange(OPEN, CLAIMED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let made = crate::safepath::make_member_file(
                    Path::new(self.text(item.path)),
                    crate::safepath::IfOutputExists::Keep,
                    item.mode,
                );
                match made {
                    Ok(Some(created)) if created.beside.is_none() && !created.in_place => {
                        *sink::lock(&item.file) = Some(created.file);
                        item.state.store(MADE, Ordering::Release);
                    }
                    _ => item.state.store(NOT_MADE, Ordering::Release),
                }
            }
            at = self.next.fetch_add(1, Ordering::AcqRel);
        }
        self.close_waiting();
        self.running.fetch_sub(1, Ordering::AcqRel);
    }

    /// Whether `item`'s directory may be written into now: the walk has
    /// made or found it, or it has made or found the directory above and
    /// a helper makes this one (or has made it).
    fn dir_ready(&self, item: &Item, walked: usize) -> bool {
        let Some(after) = item.dir_after else {
            return true;
        };
        if after < walked {
            return true;
        }
        if !item.above_after.is_some_and(|above| above < walked) {
            return false;
        }
        let mut made = sink::lock(&self.made_dirs);
        // Halted ([`Ahead::halt`]) or stopped: no directory is made from
        // here on. Read under the lock the halt takes after setting it.
        if self.over.load(Ordering::Acquire) {
            return false;
        }
        if made
            .iter()
            .rev()
            .any(|&range| self.text(range) == self.text(item.dir))
        {
            return true;
        }
        // One exclusive make, which follows no link: what it makes is a
        // real directory of this run's; anything already there is left to
        // the walk to judge.
        if fs::create_dir(self.text(item.dir)).is_ok() {
            made.push(item.dir);
            return true;
        }
        false
    }

    fn close_waiting(&self) {
        loop {
            let Some(out) = sink::lock(&self.closes).pop() else {
                return;
            };
            drop(out);
            self.closes_owed.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

impl Ahead {
    /// The helpers' shared state over `items`, whose paths are ranges of
    /// `paths`, before any helper starts.
    fn new(
        paths: String,
        items: Vec<Item>,
        plan_len: usize,
        closes_behind: bool,
        window: usize,
        most_closes: usize,
    ) -> Ahead {
        let mut by_index = vec![u32::MAX; plan_len];
        for (at, item) in items.iter().enumerate() {
            by_index[item.index] = at as u32;
        }
        Ahead {
            paths,
            items,
            by_index,
            next: AtomicUsize::new(0),
            walked: AtomicUsize::new(0),
            over: AtomicBool::new(false),
            running: AtomicUsize::new(0),
            closes_behind,
            window,
            most_closes,
            closes: Mutex::new(Vec::new()),
            closes_owed: AtomicUsize::new(0),
            made_dirs: Mutex::new(Vec::new()),
        }
    }

    /// Starts `helpers` helpers on the run's pool.
    fn start(self: &Arc<Self>, helpers: usize) {
        self.running.fetch_add(helpers, Ordering::AcqRel);
        for _ in 0..helpers {
            let ahead = Arc::clone(self);
            rayon::spawn(move || ahead.help());
        }
    }

    /// Stops the helpers and waits for them: every close handed to them is
    /// done when this returns, and no helper makes anything after it.
    fn stop(&self) {
        self.over.store(true, Ordering::Release);
        while self.running.load(Ordering::Acquire) > 0 {
            std::thread::yield_now();
        }
        self.close_waiting();
    }

    /// Ends making ahead part way through the walk, without waiting for the
    /// helpers (they may have no thread to run on while the walk holds the
    /// sink): none makes anything from here on, and every file made ahead
    /// and not taken is removed, while its name is still that file. A
    /// create in flight is waited for, a few microseconds. What the walk
    /// has taken stays the walk's; the closes handed over are still done.
    /// `false` where it was already over.
    fn halt(&self) -> bool {
        if self.over.swap(true, Ordering::AcqRel) {
            return false;
        }
        for item in &self.items {
            loop {
                match item.state.compare_exchange(
                    OPEN,
                    NOT_MADE,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Err(CLAIMED) => std::thread::yield_now(),
                    Err(MADE) => {
                        if let Some(file) = sink::lock(&item.file).take() {
                            let path = Path::new(self.text(item.path));
                            if same_file(&file, path) {
                                let _ = fs::remove_file(path);
                            }
                        }
                        item.state.store(NOT_MADE, Ordering::Release);
                        break;
                    }
                    _ => break,
                }
            }
        }
        true
    }

    /// After [`Ahead::stop`]: every file made ahead and never taken
    /// removed, while its name is still that file.
    fn remove_untaken(&self) {
        for item in &self.items {
            if item.state.load(Ordering::Acquire) != MADE {
                continue;
            }
            let Some(file) = sink::lock(&item.file).take() else {
                continue;
            };
            let path = Path::new(self.text(item.path));
            if same_file(&file, path) {
                let _ = fs::remove_file(path);
            }
        }
    }
}

impl Run<'_> {
    /// Starts the helpers for this walk where the run and its members
    /// allow ([`self`]); the pool's walk only, so after the pool is sized.
    pub(super) fn arm_ahead(&mut self, breadth: usize) {
        let asked = asked();
        if !asked.on || !matches!(self.mode, Mode::Extract { .. }) || self.keeps_silently() {
            return;
        }
        // A link or a copy anywhere: their opens and closes read and make
        // names of other members, so nothing is made ahead of them.
        if self.plan.iter().any(|p| p.member.redirect.is_some()) {
            return;
        }
        let width = rayon::current_num_threads();
        let helpers = asked
            .helpers
            .unwrap_or_else(|| (width / 2).clamp(1, MOST_HELPERS));
        // macOS: the same, capped at its own count where none is asked.
        #[cfg(target_os = "macos")]
        let helpers = if asked.helpers.is_some() {
            helpers
        } else {
            helpers.min(MACOS_HELPERS)
        };
        if width < 2 {
            return;
        }
        // The plan index whose open first makes or finds each directory a
        // selected member's path runs through (`ensure_dest`,
        // `ensure_parents`, a directory member's own make), by path.
        let mut first: HashMap<&str, usize> = HashMap::new();
        // A directory member's own path: a file made ahead there would be
        // what its open finds in its way.
        let mut dir_members: HashSet<&str> = HashSet::new();
        // A directory whose first open is its OWN member's: that open makes
        // it with the member's stored mode, so no helper makes it first.
        let mut made_by_member: HashSet<&str> = HashSet::new();
        let dest = dest_base(&self.dest);
        for &index in self.selected.iter() {
            let Some(Target::Pooled(start, end)) = self.target_at.get(index) else {
                continue;
            };
            let path = &self.targets[*start..*end];
            if self.plan[index].member.is_dir {
                dir_members.insert(path);
            }
            let mut level = if self.plan[index].member.is_dir {
                Some(Path::new(path))
            } else {
                Path::new(path).parent()
            };
            while let Some(dir) = level.and_then(Path::to_str).filter(|d| !d.is_empty()) {
                if first.contains_key(dir) {
                    break;
                }
                first.insert(dir, index);
                if self.plan[index].member.is_dir && dir == path {
                    made_by_member.insert(dir);
                }
                if dir == dest {
                    break;
                }
                level = Path::new(dir).parent();
            }
        }
        let mut paths = String::new();
        let mut items = Vec::new();
        for &index in self.selected.iter() {
            let member = &self.plan[index].member;
            // An encrypted member only where it carries a password CHECK
            // RECORD (`password_checked`): a wrong password is then refused
            // before its first byte, by which time today's walk has made
            // its file anyway and removes it (`close_refused_password`,
            // by `wrote`, which a file taken from here is in). Without a
            // record a wrong password is found only at the checksum: out.
            if member.is_dir
                || (member.encrypted && !member.password_checked)
                || member.unknown_version
                || member.split_before
                || member.split_after
                || member.size >= unbuffered::LEAST
                || member.size > output::HOLD_BOUND
                || self.done.contains(index)
            {
                continue;
            }
            let Some(Target::Pooled(start, end)) = self.target_at.get(index) else {
                continue;
            };
            let path = &self.targets[*start..*end];
            if dir_members.contains(path) {
                continue;
            }
            let dir = Path::new(path)
                .parent()
                .and_then(Path::to_str)
                .unwrap_or("");
            let dir_after = (!dir.is_empty()).then(|| first.get(dir).copied()).flatten();
            if !dir.is_empty() && dir_after.is_none() {
                continue;
            }
            let above_after = Path::new(dir)
                .parent()
                .filter(|_| !made_by_member.contains(dir))
                .and_then(Path::to_str)
                .filter(|above| !above.is_empty())
                .and_then(|above| first.get(above).copied());
            let begin = paths.len();
            paths.push_str(path);
            let path_range = (begin, paths.len());
            let dir_range = (begin, begin + dir.len());
            items.push(Item {
                index,
                path: path_range,
                mode: mode::file_create(self.file_mode(member)),
                dir: dir_range,
                dir_after,
                above_after,
                state: AtomicU8::new(OPEN),
                file: Mutex::new(None),
            });
        }
        if items.len() < FEWEST {
            return;
        }
        let window = asked
            .window
            .unwrap_or_else(|| breadth.saturating_mul(WINDOW_PER_BREADTH).max(1));
        #[cfg(target_os = "macos")]
        let window = if asked.window.is_some() {
            window
        } else {
            breadth.saturating_mul(MACOS_WINDOW_PER_BREADTH).max(1)
        };
        // Inside the soft descriptor limit: the window at most half the
        // share, the close queue the rest; not armed where that leaves
        // the window nothing.
        let (window, most_closes) =
            match crate::workers::ahead_descriptors(self.any_selected_is_split()) {
                Some(share) => {
                    let window = window.min(share / 2);
                    (window, MOST_WAITING_CLOSES.min(share - window))
                }
                None => (window, MOST_WAITING_CLOSES),
            };
        if window == 0 {
            return;
        }
        let ahead = Arc::new(Ahead::new(
            paths,
            items,
            self.plan.len(),
            asked.closes,
            window,
            most_closes,
        ));
        ahead.start(helpers);
        self.ahead = Some(ahead);
    }

    /// Ends the helpers when the walk is over: every close handed to them
    /// done, every file made ahead and never taken removed, every
    /// directory a helper made that the walk never reached removed.
    pub(super) fn end_ahead(&mut self) {
        let Some(ahead) = self.ahead.take() else {
            return;
        };
        ahead.stop();
        ahead.remove_untaken();
        self.remove_unreached_dirs(&ahead);
    }

    /// A refused member is about to have the directories its `open` made
    /// removed ([`Run::drop_held`]), which succeeds only where nothing else
    /// has been put in them: a file or a directory made ahead for a member
    /// the walk has not reached would be such a thing, where the walk alone
    /// put nothing, and the directory stayed, unannounced when a later
    /// member came to it (FROM-STUDIO 391 A: 201 `Creating` lines missing
    /// under a wrong `-p`, counted 14 Oct 2026). So making ahead ends here
    /// ([`Ahead::halt`]), its untaken files and the directories the walk
    /// never reached removed, and the rest of the run is the walk's alone.
    pub(super) fn halt_ahead(&self) {
        let Some(ahead) = self.ahead.as_ref() else {
            return;
        };
        if ahead.halt() {
            self.remove_unreached_dirs(ahead);
        }
    }

    /// Every directory a helper made that the walk never reached, removed
    /// where empty.
    fn remove_unreached_dirs(&self, ahead: &Ahead) {
        let mut made = std::mem::take(&mut *sink::lock(&ahead.made_dirs));
        // Deepest first, so a directory is empty when its turn comes.
        made.sort_by_key(|&range| std::cmp::Reverse(range.1 - range.0));
        for range in made {
            let dir = Path::new(ahead.text(range));
            if !self.dirs.made(dir) {
                let _ = fs::remove_dir(dir);
            }
        }
    }

    /// The walk is about to judge a name by looking at it (`-o-`, or `E`
    /// answered): a file made ahead for this member would be found there,
    /// so it is removed first and the walk judges the name as it stood.
    pub(super) fn forget_ahead(&self, index: usize) {
        if let Some(ahead) = self.ahead.as_ref() {
            ahead.forget(index);
        }
    }
}

impl Ahead {
    /// [`Run::forget_ahead`]: the file made ahead for `index`, if any,
    /// removed while its name is still that file, and none made from now on.
    fn forget(&self, index: usize) {
        let Some(file) = self.take(index) else {
            return;
        };
        let Some(item) = self.item_of(index) else {
            return;
        };
        let path = Path::new(self.text(item.path));
        if same_file(&file, path) {
            let _ = fs::remove_file(path);
        }
    }
}

/// Whether `path` names, without following a link, the very file `file`
/// is open on.
fn same_file(file: &fs::File, path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (file.metadata(), fs::symlink_metadata(path)) {
        (Ok(open), Ok(named)) => open.dev() == named.dev() && open.ino() == named.ino(),
        _ => false,
    }
}

/// The helpers against a walk played by the test itself (`ahead`), on
/// Linux. Each test assumes a pool of at least one thread for its helpers
/// beside the test's own thread (the global pool, any width), a few MiB of
/// memory, and a temporary directory that takes regular files, directories
/// and links.
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    /// The tests' window: wide enough that a helper runs well ahead.
    const TEST_WINDOW: usize = 128;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rarfast-ahead-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Items for `files` in plan order, plan index = position, each with
    /// its directory made by the open of `dir_after` and the directory
    /// above it by `above_after`.
    fn items_for(
        files: &[PathBuf],
        dir_after: Option<usize>,
        above_after: Option<usize>,
    ) -> (String, Vec<Item>) {
        let mut paths = String::new();
        let mut items = Vec::new();
        for (index, file) in files.iter().enumerate() {
            let path = file.to_str().unwrap();
            let dir = file.parent().unwrap().to_str().unwrap();
            let begin = paths.len();
            paths.push_str(path);
            items.push(Item {
                index,
                path: (begin, paths.len()),
                mode: 0o644,
                dir: (begin, begin + dir.len()),
                dir_after,
                above_after,
                state: AtomicU8::new(OPEN),
                file: Mutex::new(None),
            });
        }
        (paths, items)
    }

    fn read(path: &Path) -> String {
        let mut text = String::new();
        fs::File::open(path)
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        text
    }

    /// The walk takes every file a helper made ahead and makes the rest
    /// itself; every member's file is there once with its own bytes, and
    /// the closes handed back are all done when the helpers stop.
    #[test]
    fn the_walk_takes_what_was_made_ahead_and_makes_the_rest() {
        let dir = scratch("takes");
        let files: Vec<PathBuf> = (0..600).map(|i| dir.join(format!("f{i}"))).collect();
        let (paths, items) = items_for(&files, None, None);
        let ahead = Arc::new(Ahead::new(
            paths,
            items,
            files.len(),
            true,
            TEST_WINDOW,
            MOST_WAITING_CLOSES,
        ));
        ahead.start(2);
        let mut taken = 0;
        for (index, path) in files.iter().enumerate() {
            if index % 100 == 0 {
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            let mut file = match ahead.take(index) {
                Some(file) => {
                    taken += 1;
                    file
                }
                None => {
                    crate::safepath::make_member_file(
                        path,
                        crate::safepath::IfOutputExists::Keep,
                        0o644,
                    )
                    .unwrap()
                    .expect("a free name")
                    .file
                }
            };
            ahead.walked(index + 1);
            file.write_all(format!("member {index}").as_bytes())
                .unwrap();
            if ahead.made(index) {
                drop(ahead.close_later(Box::new(file)));
            }
        }
        ahead.stop();
        ahead.remove_untaken();
        assert!(taken > 0, "no file was made ahead of the walk");
        for (index, path) in files.iter().enumerate() {
            assert_eq!(read(path), format!("member {index}"), "{}", path.display());
        }
        assert_eq!(fs::read_dir(&dir).unwrap().count(), files.len());
        assert_eq!(ahead.closes_owed.load(Ordering::Acquire), 0);
        let _ = fs::remove_dir_all(&dir);
    }

    /// Helpers that never get to a close (a slow drive, a busy pool): the
    /// queue takes no more than its bound and hands every file past it
    /// back to the walk, which closes it itself. Before FROM-STUDIO 443 C
    /// the bound was 256 under any limit, and a queue that full is every
    /// descriptor macOS's default limit allows.
    #[test]
    fn the_close_queue_takes_no_more_than_its_bound() {
        let ahead = Ahead::new(String::new(), Vec::new(), 0, true, TEST_WINDOW, 8);
        // A helper counted as running that never runs.
        ahead.running.store(1, Ordering::Release);
        let handed_back = (0..40)
            .filter(|_| ahead.close_later(Box::new(Vec::<u8>::new())).is_some())
            .count();
        assert_eq!(ahead.closes_owed.load(Ordering::Acquire), 8);
        assert_eq!(handed_back, 32);
        ahead.running.store(0, Ordering::Release);
        ahead.stop();
        assert_eq!(ahead.closes_owed.load(Ordering::Acquire), 0);
    }

    /// A run that stops part way: the files made ahead for members the
    /// walk never reached are removed, and the ones it wrote stay.
    #[test]
    fn a_file_made_ahead_and_never_taken_is_removed() {
        let dir = scratch("untaken");
        let files: Vec<PathBuf> = (0..100).map(|i| dir.join(format!("f{i}"))).collect();
        let (paths, items) = items_for(&files, None, None);
        let ahead = Arc::new(Ahead::new(
            paths,
            items,
            files.len(),
            false,
            TEST_WINDOW,
            MOST_WAITING_CLOSES,
        ));
        ahead.start(1);
        for (index, path) in files.iter().enumerate().take(10) {
            let file = ahead.take(index).or_else(|| {
                crate::safepath::make_member_file(
                    path,
                    crate::safepath::IfOutputExists::Keep,
                    0o644,
                )
                .unwrap()
                .map(|created| created.file)
            });
            let mut file = file.expect("a free name");
            ahead.walked(index + 1);
            file.write_all(b"written").unwrap();
        }
        // Let the helper run on into the window past the walk.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while ahead.items[40].state.load(Ordering::Acquire) != MADE
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(ahead.items[40].state.load(Ordering::Acquire), MADE);
        ahead.stop();
        ahead.remove_untaken();
        for (index, path) in files.iter().enumerate() {
            assert_eq!(path.exists(), index < 10, "{}", path.display());
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// A name already taken is the walk's to judge: the helper makes
    /// nothing for it and the file there is left as it was.
    #[test]
    fn a_taken_name_is_left_to_the_walk() {
        let dir = scratch("taken");
        let files: Vec<PathBuf> = (0..80).map(|i| dir.join(format!("f{i}"))).collect();
        fs::write(&files[5], b"already here").unwrap();
        let (paths, items) = items_for(&files, None, None);
        let ahead = Arc::new(Ahead::new(
            paths,
            items,
            files.len(),
            false,
            TEST_WINDOW,
            MOST_WAITING_CLOSES,
        ));
        ahead.start(1);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while ahead.items[5].state.load(Ordering::Acquire) == OPEN
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(ahead.take(5).map(|_| ()), None);
        ahead.stop();
        ahead.remove_untaken();
        assert_eq!(read(&files[5]), "already here");
        let _ = fs::remove_dir_all(&dir);
    }

    /// macOS: a member no helper made is made by the walk through the
    /// book, at its own path and mode only, and then counts as made ahead
    /// (its close is handed back); a taken name is answered as the create
    /// answers it and counts as nothing.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_walk_makes_its_own_create_through_the_book() {
        let dir = scratch("here");
        let files: Vec<PathBuf> = (0..3).map(|i| dir.join(format!("f{i}"))).collect();
        fs::write(&files[1], b"already here").unwrap();
        let (paths, items) = items_for(&files, None, None);
        let ahead = Ahead::new(
            paths,
            items,
            files.len(),
            true,
            TEST_WINDOW,
            MOST_WAITING_CLOSES,
        );
        // Not given the entry by `take` yet: nothing is made.
        assert!(ahead.make_here(0, &files[0], 0o644).is_none());
        assert!(ahead.take(0).is_none());
        // Another path or another mode: not the entry's own create.
        assert!(ahead.make_here(0, &dir.join("other"), 0o644).is_none());
        assert!(ahead.make_here(0, &files[0], 0o600).is_none());
        let made = ahead.make_here(0, &files[0], 0o644).unwrap().unwrap();
        assert!(made.is_some());
        assert!(ahead.made(0));
        assert!(ahead.take(1).is_none());
        let taken = ahead.make_here(1, &files[1], 0o644).unwrap().unwrap();
        assert!(taken.is_none());
        assert!(!ahead.made(1));
        assert_eq!(read(&files[1]), "already here");
        assert!(!dir.join("other").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    /// A directory not yet made by the walk is made by a helper only where
    /// that one exclusive make succeeds: a LINK standing at its name is
    /// never written through, and what it leads to stays empty. A
    /// directory the helper did make takes the members' files.
    #[test]
    fn a_helper_makes_no_file_through_a_link() {
        let dir = scratch("link");
        let outside = scratch("link-outside");
        std::os::unix::fs::symlink(&outside, dir.join("sub")).unwrap();
        let through: Vec<PathBuf> = (0..70)
            .map(|i| dir.join("sub").join(format!("f{i}")))
            .collect();
        // Its own directory is made by an open the walk never reaches; the
        // one above it by the first open.
        let (paths, items) = items_for(&through, Some(1_000), Some(0));
        let ahead = Arc::new(Ahead::new(
            paths,
            items,
            2_000,
            false,
            TEST_WINDOW,
            MOST_WAITING_CLOSES,
        ));
        ahead.walked(1);
        ahead.start(1);
        std::thread::sleep(std::time::Duration::from_millis(30));
        ahead.stop();
        assert!(ahead
            .items
            .iter()
            .all(|item| item.state.load(Ordering::Acquire) == OPEN));
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);

        let fresh: Vec<PathBuf> = (0..70)
            .map(|i| dir.join("new").join(format!("f{i}")))
            .collect();
        let (paths, items) = items_for(&fresh, Some(1_000), Some(0));
        let ahead = Arc::new(Ahead::new(
            paths,
            items,
            2_000,
            false,
            TEST_WINDOW,
            MOST_WAITING_CLOSES,
        ));
        ahead.walked(1);
        ahead.start(1);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        // Entry 0 counts as walked (it made the directory above), so a
        // helper starts at entry 1.
        while ahead.items[1].state.load(Ordering::Acquire) != MADE
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        ahead.stop();
        assert_eq!(ahead.items[1].state.load(Ordering::Acquire), MADE);
        assert!(fs::symlink_metadata(dir.join("new")).unwrap().is_dir());
        ahead.remove_untaken();
        assert_eq!(fs::read_dir(dir.join("new")).unwrap().count(), 0);
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside);
    }
}
