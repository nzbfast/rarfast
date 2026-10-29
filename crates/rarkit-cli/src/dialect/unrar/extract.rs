//! `e`, `x`, `t` and `p`: the commands that read member data.
//!
//! Two things here are not obvious from the reference's manual and both
//! came out of the captured tables.
//!
//! **The progress line has two shapes, not one.** A file's line reserves
//! a four-column percentage field and ends `  OK` at column 80; a
//! directory's has no percentage and ends `OK` at column 70. The
//! reference writes the percentage with backspaces so a terminal
//! overwrites it with the `  OK `, and this module emits the same bytes,
//! backspaces included, so a terminal sees what the reference's terminal
//! sees and a pipe records what the reference's pipe records.
//!
//! **The reference does not stop at a bad member.** A checksum failure,
//! a wrong password or a lost volume is counted and the walk continues,
//! which is why `extract-corrupted` still writes `rand.bin` and
//! `sub/nested.txt`. rarkit reports a mismatch through `Sink::close` and
//! carries on, so the walk here is a single pass: the predecessor's
//! restart-with-the-block-dropped machinery met an all-or-nothing engine
//! and is not carried.
//!
//! **Members are written on the walking thread.** The predecessor wrote
//! them concurrently through its own engine's worker entry. rarkit's
//! parallel entry point takes a different trait (`ParallelSink`), and
//! wiring this dialect's ordered output on top of it is left undone rather than
//! guessed at: see the crate README.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use rarkit::Disposition;

use super::args::{Options, Overwrite, TimeFilter};
use super::mode::{self, DirMode, FileMode};
use super::{
    percent, DamagedHeader, Exit, Member, OpenFailure, Opened, Out, Tail, CORRUPT_HEADER,
    UNEXPECTED_END,
};

mod links;
mod payload;

use crate::unbuffered;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use crate::writeback;

/// The hasher of a table keyed by a member's index (or a volume's): one
/// multiply. An index is a small dense number this program made itself, so
/// the standard hasher's keyed rounds guard nothing here, and they were
/// most of what a small file cost at its close: about 1,020 of the 1,284
/// user instructions a file that `x` of 20,000 small files spent over the
/// tree before the output path was written again (counted 12 Oct 2026
/// on a Zen 4 box, plain builds, perf stat and a count by function).
/// The odd multiplier (the golden ratio's, as in multiplicative hashing)
/// carries an index into both the low bits a table takes its slot from
/// and the high bits it tags the slot with.
#[derive(Clone, Copy, Default)]
struct IndexHasher(u64);

impl std::hash::Hasher for IndexHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    /// Not the path a `usize` key takes; kept right for any other key.
    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 = (self.0 ^ u64::from(*byte)).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        }
    }

    fn write_usize(&mut self, index: usize) {
        self.0 = (self.0 ^ index as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }
}

/// A map from a member's index, hashed by [`IndexHasher`].
type ByIndex<V> = HashMap<usize, V, std::hash::BuildHasherDefault<IndexHasher>>;

/// A set of indices, hashed by [`IndexHasher`].
type Indices = HashSet<usize, std::hash::BuildHasherDefault<IndexHasher>>;

// The parts, one module a seam. A part's names are taken whole.
// Armed only where the pool would drive, on Linux.
#[cfg(all(target_os = "linux", feature = "parallel"))]
mod ahead;
// And on macOS, under its own gate and helper count (`ahead`, "macOS").
#[cfg(all(target_os = "macos", feature = "parallel"))]
mod ahead;
mod existing;
mod lines;
pub(crate) mod mask;
mod member;
mod output;
mod read_ahead;
mod rotational;
mod route;
mod select;
mod settle;
mod sink;
mod target;
use target::dest_base;
// Asked only where the pool would drive.
#[cfg(feature = "parallel")]
mod twins;
mod volumes;
mod walk;
use super::progress_line_name;
use super::AttributeForm;
use super::{io_reason, time};
#[allow(unused_imports)]
use existing::*;
#[allow(unused_imports)]
use lines::*;
#[allow(unused_imports)]
use output::*;
#[allow(unused_imports)]
use read_ahead::*;
#[allow(unused_imports)]
use rotational::*;
#[allow(unused_imports)]
use route::*;
#[allow(unused_imports)]
pub(crate) use select::*;
#[allow(unused_imports)]
use sink::*;
#[allow(unused_imports)]
pub(crate) use volumes::*;

/// Column the file progress line pads its name out to, before the
/// percentage field. Measured off the reference: `Extracting  ` is twelve
/// characters, and `out/text.txt` is followed by exactly 49 spaces.
const FILE_NAME_COLUMN: usize = 73;

/// Column the directory line pads to, before its bare `OK`.
const DIR_NAME_COLUMN: usize = 70;

/// Width of the verb field (`Extracting  `, `Creating    `, `Testing     `,
/// and `...         ` for a member continuing from the previous volume).
const VERB_WIDTH: usize = 12;

/// The verb of a member's line in each volume after its first.
const CONTINUED: &str = "...";

/// Column the stderr per-member complaints pad the name out to, as in
/// `text.txt             - checksum error`.
const COMPLAINT_COLUMN: usize = 21;

/// The whole state of one `e`/`x`/`t`/`p` run.
struct Run<'a> {
    /// The real streams, and **nothing outside [`Run::say`] and
    /// [`Run::warn`] may touch them.**
    ///
    /// Named `streams` rather than `out` so that a `self.streams.say(..)`
    /// copied in from anywhere - or left behind by a rewrite - does not
    /// compile. That is not a style rule: it is the one defect a
    /// differential sweep found in this code. A single
    /// `self\n.out\n.warn(..)`, split over three lines and so missed by a
    /// line-by-line rewrite, sent a member's `Incorrect password`
    /// complaint straight to stderr while the rest of that member's
    /// output waited in its slot, and under `-ierr` - where both streams
    /// are one - it surfaced before the archive's own banner. It shows on
    /// no other switch, which is why the matrix that crosses the message
    /// switches with the widths is the one that caught it.
    streams: &'a Out,
    mode: Mode,
    opts: &'a Options,
    dest: String,
    /// Read by [`Run::drive`]'s and [`Run::walk`]'s solid-set checks.
    volumes: Vec<Opened>,
    /// The session the first volume was opened through, whose derived
    /// keys the walk reuses. Taken by [`Run::drive`] for the walk, since
    /// the walk's sink borrows the run.
    session: Option<rarkit::Session>,
    volume_names: Vec<String>,
    plan: Vec<Planned>,
    selected: Selected,
    /// Members that have already been written, so a restart does not
    /// write or announce them a second time.
    done: IndexSet,
    failures: Vec<(usize, Failure)>,
    /// Leading fragments whose packed CRC32 disagreed with their field,
    /// as `(member, volume)`: said at that volume's end, never a failure
    /// (spec F 3.5.6). Empty on every run but a damaged one.
    mismatches: Vec<(usize, usize)>,
    /// What an encrypted member's `open` is saying and making, while it
    /// opens: see [`Run::held`].
    capture: Option<Capture>,
    /// What an encrypted member's `open` said after its volume's banner
    /// (its progress line, a `Creating` line) and the directories it made,
    /// held until the engine has NOT refused its password: said at its
    /// first byte (`p`, [`ReleaseFirst`]) or its close, or dropped with
    /// those directories removed when it is refused. The reference judges
    /// the password before it says or makes anything for the member, where
    /// the engine judges it after the sink's `open` (spec K 3.7.3); measured
    /// against unrar 7.23 on 30 Sep 2026 (`t`, `x`, `p`, one archive and
    /// volume sets), a refused member has no line and no directory.
    held: ByIndex<Held>,
    /// Volumes whose `Extracting from` banner has already been printed.
    announced: Indices,
    /// The volume the command line named, when it is not the set's first
    /// and the walk starts over at the first ([`restart_at_first`]): its
    /// banner is said before the first volume's, which then has no blank
    /// line of its own in front of it.
    named_banner: Option<String>,
    /// Whether a STORED member is selected, which makes the walk say the
    /// banner of every volume it passes on its way to a selected member,
    /// an empty banner where nothing in that volume is selected. Measured
    /// against unrar 7.23 on 30 Sep 2026 over four-part sets of a
    /// 10,000-byte member and a 2,000-byte one starting in the third
    /// volume, each stored or compressed: with the stored
    /// second member selected the reference says `Testing archive` for the
    /// first and second volumes before the third's, whatever the first
    /// member is; with a compressed one selected it says the third's alone.
    announce_passed: bool,
    /// The directories the walk takes as there: those this run made (so
    /// `Creating` is printed once each), those that stood before it, and
    /// the parents last found among them ([`target::KnownDirs`]).
    dirs: target::KnownDirs,
    /// The mode each directory [`Run::ensure_parents`] made was left with,
    /// as the stat that confirms it read it. A directory member landing
    /// on one of these with those same bits sets nothing: on a genuine
    /// writer's archive (directories stored after their contents, every
    /// one 0755 under umask 022) that is every directory, 12,102 of them
    /// over the rivals set's `full/c2`, whose chmod cost the tip 1.2% of
    /// its instructions in the first timed hold (27 Sep 2026).
    made_modes: std::collections::HashMap<PathBuf, u32>,
    /// Each extracted directory member's path, the mode it is to be left
    /// with and its archived time, set by [`finish_directories`] once the
    /// walk is over. Not at creation: every child written afterwards moves
    /// its parent's time again, which is how every directory used to carry
    /// the run's own time (found 26 Sep 2026, 1,722 of 1,722 over
    /// `small-r.rar`), and a mode without the owner's write bit set first
    /// would refuse the children (see [`mode`]).
    dir_finish: Vec<DirFinish>,
    /// Members whose output file THIS run created and opened for writing.
    /// A failed member's file is removed only if it is here, so cleanup
    /// can never reach a file the run did not write: under `t` a
    /// member's target resolves against the current directory, and a
    /// target `-o-` skipped is the caller's own file.
    wrote: Indices,
    /// Members being written BESIDE a name that was taken, and the path
    /// each is written at (SPEC-CLI 9.4 W7): the file takes the member's
    /// name when the member is whole ([`Run::take_name`]) and is removed
    /// on any failure, so what stood at the name survives one.
    beside: ByIndex<PathBuf>,
    /// For each member in [`Run::beside`], how its open file takes the
    /// member's name as it closes (`safepath::NameAtClose`): armed at the
    /// member's close when it is whole, asked by [`Run::take_name`].
    naming: ByIndex<crate::safepath::NameAtClose>,
    /// Small members that replace a file and are HELD IN MEMORY until
    /// their close (`output::HOLD_BOUND`): each one's bytes, the mode
    /// decided for it and the time to set. Written in place by
    /// [`Run::write_held`] when the member is whole and verified.
    held_members: ByIndex<HeldMember>,
    /// What the members in [`Run::held_members`] declare between them,
    /// kept under `output::hold_total`.
    held_declared: u64,
    /// A held member that could not have its name when its close came to
    /// write it (no file could be opened or made there, or the rename was
    /// refused): the system's reason, for [`Run::settle_name`] to report.
    held_refused: ByIndex<std::io::Error>,
    /// A member this run wrote had one of the three bits above the nine
    /// (set user, set group, sticky) left off because the run is not the
    /// superuser's (SPEC-CLI 9.4 W3): said once, when the run ends.
    high_bits_left_off: std::sync::atomic::AtomicBool,
    /// A file that stood at a member's name was written IN PLACE, because
    /// its directory let no file be made beside it
    /// (`safepath::write_in_place`): said once, when the run ends, since
    /// such a file would not have survived a failed member.
    wrote_in_place: bool,
    /// Members whose line is open, waiting for its `  OK`.
    ///
    /// A SET and not a cursor, because the concurrent walk opens a
    /// member's line before the member before it has closed. Ordered, so
    /// that "the line the run stopped on" is the FIRST one in archive
    /// order rather than whichever the container happened to hold first.
    open_lines: BTreeSet<usize>,
    /// Members the engine will never close: a close for a LATER member
    /// passed over them (see [`Walk`]). Their lines are already ended with
    /// no `OK`; the walk error names the first of them and counts it
    /// ([`Run::report_walk_error`]).
    passed_over: BTreeSet<usize>,
    /// Each member's own output, held until the member is settled.
    ///
    /// **This is what keeps archive order.** The engine opens members
    /// ahead of the decode and closes them in archive order, so a line
    /// written the moment it is composed would interleave. Every message
    /// a member produces - its banner, its `Creating` lines, its progress
    /// line, its complaint and its `  OK` - goes into that member's slot,
    /// and a slot reaches the real streams only when every slot ahead of
    /// it has. The bytes are therefore the sequential path's, whatever
    /// order the workers finished in.
    pending: VecDeque<Pending>,
    /// The plan entry after the last one the engine opened ([`Walk`]):
    /// every entry from here on was never opened.
    reached: usize,
    /// Whose slot [`Run::say`] and [`Run::warn`] are writing into.
    /// `None` outside the walk, where a message goes straight out.
    emit_to: Option<usize>,
    /// Whether the last member's line ended in a failure, which has already
    /// ended the line. See [`Run::finish`].
    last_failed: bool,
    /// `-idn`: whether the last banner still owes the blank line it has
    /// with the names shown. A member's counter follows the banner
    /// directly and cancels it; a member refused for its password gets it
    /// first, as it does without `-idn`. Measured against unrar 7.23 on 30
    /// Sep 2026 over a stored `-p` set given the wrong password, `t` and
    /// `x`, plain and `-ierr`.
    banner_gap_owed: bool,
    /// Byte offset of each volume within the set, and the set's total:
    /// the numerator's base and the denominator of the percentage
    /// counter. A volume before the last counts its whole file, the last
    /// its `Opened::counted_end` (see where they are summed).
    volume_offset: Vec<u64>,
    total_size: u64,
    /// The percentage the last progress line drew. A CONTINUATION line
    /// whose percentage has not moved since draws none: measured against
    /// unrar 7.23 on 30 Sep 2026 over rar 7.23's `-v9k` and `-v6k` sets,
    /// where a member's last few hundred bytes in the next volume read
    /// `...         v3.bin` and its padding, then `  OK`, with no counter
    /// (and under `p` the padding alone). A member's first line always
    /// draws it, the same value or not.
    last_pct: Option<u64>,
    /// The largest data end in each volume, which is also the unit that
    /// volume contributes to the denominator: a member that reaches it is
    /// the last thing in that file with a payload, so its line reads 100%
    /// for a single archive and the set's own fraction for a volume.
    /// Measured on the three-part fixture, whose final fragment reads
    /// 100%, and on the equal-member fixtures, where the file length as a
    /// denominator reads one low on every intermediate line.
    volume_last_data: Vec<u64>,
    /// Whether the password on the command line failed the archive's own
    /// check, which the reference reports per member rather than once.
    password_wrong: bool,
    /// Whether anything at all was processed, which decides between
    /// `All OK` and `No files to extract`. A file left as it was because
    /// one of its name was already there, and a file that could not be
    /// created, are NOT processed: MEASURED against unrar 7.23 on macOS and
    /// x86-64 Linux, 2 Oct 2026 (`x -o-`, `x` answered `N` or `E`, and
    /// `x -o+` over files that may not be written, each over an archive of
    /// files only: `No files to extract`, exit 10, or 9 with the creates'
    /// complaints; a directory member, or one file written, and the run
    /// closes with `All OK` or `Total errors` as before).
    touched: bool,
    /// The standing answer to the reference's question about a file that
    /// is already there ([`Run::settle_existing`]).
    asked: Asked,
    /// Why the run stopped at that question, if it did. No member after it
    /// is opened, and [`Run::finish`] closes with `Program aborted`.
    stopped: Option<Stopped>,
    /// Whether the rule is to ask and a selected member's path was taken
    /// before the run: such a run takes the sequential walk, so that each
    /// question follows the lines of the members before it, as the
    /// reference's does. Nothing else leaves the pool for it, and a
    /// destination with nothing in the way pays one `lstat` a member, the
    /// one the open no longer makes.
    may_ask: bool,
    /// What stopped the first volume in hand whose header walk stopped
    /// short of its end, if one did: said once, after the walk.
    tail: Option<Tail>,
    /// The headers read although their checksum failed, every volume's in
    /// order (`Opened::damaged`): said before the walk, two errors each.
    damaged: Vec<DamagedHeader>,
    errors: usize,
    /// Every selected member's validated output path, resolved ONCE and
    /// stored end to end in one string; see [`Run::pool_targets`].
    targets: String,
    /// Symbolic links, hard links and file copies in flight (spec F 3.8):
    /// see `links`.
    links: links::State,
    /// The largest window the walk's memory policy allows
    /// (`MemoryPolicy::max_window`), set as the walk starts: a member
    /// declaring a larger dictionary may be refused for it after its
    /// `open`, so what its `open` says is held until it is not
    /// ([`Run::open_member`]).
    window_ceiling: u64,
    /// The walk's memory policy where the user named BOTH a width and a
    /// memory limit, set as the walk starts: what [`Run::note_width`]
    /// asks how wide the limit lets a member run.
    narrowing: Option<rarkit::MemoryPolicy>,
    /// The narrowest width the memory limit held any member to, below
    /// the width the user named (SPEC-CLI 14).
    narrowest: Option<usize>,
    /// Whether this run's stored archive takes the walk and not the pool
    /// ([`Run::stored_route`]), settled once as the walk starts.
    #[cfg(feature = "parallel")]
    stored_walks: bool,
    /// Where each plan index's path sits in `targets`, by plan index.
    /// Empty outside `x` and `e`, the only modes that write.
    target_at: Vec<Target>,
    /// The helpers that make plain members' files ahead of the pool's
    /// walk and close them behind it, while it runs (`ahead`).
    #[cfg(all(target_os = "linux", feature = "parallel"))]
    ahead: Option<Arc<ahead::Ahead>>,
    #[cfg(all(target_os = "macos", feature = "parallel"))]
    ahead: Option<Arc<ahead::Ahead>>,
}

/// One member held in memory until its close ([`Run::held_members`]).
struct HeldMember {
    /// The size the member declared, counted in [`Run::held_declared`].
    declared: u64,
    state: Arc<Mutex<output::HeldState>>,
    decided: FileMode,
    mtime: Option<SystemTime>,
}

/// One member's resolved output path, as [`Run::pool_targets`] keeps it.
#[derive(Clone)]
enum Target {
    /// Not selected, or not a writing mode: never asked for.
    Unresolved,
    /// The name may not be joined onto the destination.
    Refused,
    /// A byte range of [`Run::targets`].
    Pooled(usize, usize),
    /// A path that is not UTF-8, kept whole: a RAR 1.3 to 4 8-bit name
    /// on a host that writes any bytes (`disk_name`), which the pool of
    /// UTF-8 text cannot hold.
    Owned(PathBuf),
    /// The name as the file system gets it is EMPTY (a NUL or a byte
    /// that is not UTF-8 first): the reference skips such a member
    /// silently, extracting nothing and counting nothing.
    Nameless,
    /// `e` into a named destination, and a FILE whose name without its
    /// path is empty (`d/`): what is left names the destination
    /// directory itself, which the reference says it cannot create.
    DestinationItself,
}

impl Run<'_> {
    /// What this binary holds beside the engine for the run: the per-member
    /// plan and its names (the policy's `caller_resident`).
    fn plan_resident(&self) -> u64 {
        let table = self.plan.capacity() * std::mem::size_of::<Planned>();
        let names: usize = self.plan.iter().map(|p| p.member.name.as_str().len()).sum();
        (table + names) as u64
    }
}

/// A run that DIES mid-walk still prints what it had.
///
/// The buffer that keeps archive order is the one thing in this file that
/// can swallow output, and a process that stops before its walk finishes
/// is exactly when that would matter: the engine can still panic on a
/// damaged member (a divide by zero in the PPMd range decoder, found by
/// the differential sweep of 20 Sep 2026 on `r393_m5` with bytes flipped
/// over it, and reached identically by both walks), and a crash that also
/// ate the last few progress lines would be a worse report of itself.
///
/// So the drain runs from the destructor, which unwinding reaches. On the
/// ordinary path there is nothing left to do: [`Run::walk`] has already
/// drained, and this is a no-op.
impl Drop for Run<'_> {
    fn drop(&mut self) {
        self.drain_all();
    }
}

/// Whether the read is told that each member is written to a FILE, in
/// order (`rarkit::ReadOptions::files_in_order`): `x` and `e`, and no
/// other command.
///
/// It is read only by the engine's in-order walk, which an extract takes
/// where it may have to ask about a file already there, over a solid
/// set, a member split across volumes or at `-mt1`; the pool never reads
/// it. There the engine takes members ahead of the file being written
/// only while the sizes they declare fit 1,024 MiB (less under `-mm`, a
/// cap or a small machine); a member the engine already holds at its own
/// window (one that barely packs, under 18 threads) is left to that. Without it such a run held every member it
/// had decoded ahead, up to the working limit, which on a large machine
/// is gibibytes (11 Oct 2026, six 320 MiB members on machines of 16 and
/// 20 threads: 1,277 to 1,847 MB against 157 to 906 MB with it, the wall
/// 0.99 to 1.17 of what it was). `p` and `t` write no file and state
/// nothing.
fn files_in_order(mode: Mode) -> bool {
    matches!(mode, Mode::Extract { .. })
}

/// THE WAITING ALLOWANCE an extract states to the engine
/// (`rarkit::ReadOptions::waiting_outputs`): how many extracted files may
/// stay open, finished, while they wait their turn to be closed in archive
/// order ([`crate::workers::waiting_outputs`]).
///
/// Only `x` and `e` state one: `t` and `p` open no file. And NOT ONTO A
/// ROTATIONAL DEVICE (`device_class::of` the destination, or the nearest
/// directory above it that exists): there the engine's own bound of twice
/// the breadth stands until a hard-disk row says otherwise,
/// because the allowance lets more large members write abreast while
/// finished files wait behind them, and a disk with one head is the device
/// that pays for writes spread over many files.
fn waiting_outputs(mode: Mode, dest: &str, width: usize) -> Option<usize> {
    if !matches!(mode, Mode::Extract { .. }) {
        return None;
    }
    let dest = if dest.is_empty() { "." } else { dest };
    let mut at = Path::new(dest);
    while !at.exists() {
        match at.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => at = parent,
            _ => {
                at = Path::new(".");
                break;
            }
        }
    }
    if crate::device_class::of(at) == crate::device_class::Class::Rotational {
        return None;
    }
    crate::workers::waiting_outputs(width)
}

/// Runs one of the four data commands.
pub(crate) fn run(
    out: &Out,
    path: &str,
    opts: &Options,
    selection: &Selection,
    mode: Mode,
    extract_path: Option<&str>,
) -> Exit {
    // `p`'s stdout is the payload, so no message may go there.
    let muted;
    let out = if mode == Mode::Print {
        muted = out.beside_payload();
        &muted
    } else {
        out
    };
    // An extract to disk, and any command at one thread, reads its archive
    // in order and so with sequential advice on Linux
    // (`engine::advise_sequential`); `t` and `p` at a wider width do not,
    // their big stored members being read wide.
    if matches!(mode, Mode::Extract { .. }) || opts.threads == Some(1) {
        crate::engine::advise_sequential_reads();
    }
    let password = opts.password.as_deref().map(str::as_bytes);
    // ONE session for the command: the first volume is opened through it
    // and the walk extracts through it, so a set whose headers are
    // encrypted is keyed once and not again after the open. It is made
    // with the walk's own options (`Run::walk`), which depend on nothing
    // but the password, `-mt`, `-mm` and `p`'s cost class, so reusing it changes
    // no option the read sees. One command, one password; never shared
    // beyond it.
    let mut session_options =
        // No plan exists yet: the open is charged the process headroom only.
        crate::engine::read_options_capped(password, opts.threads, opts.memory_cap, 0);
    if mode == Mode::Print {
        session_options = session_options.with_sink_is_file(Some(false));
    }
    // The walk's read-ahead for an extract to disk (`Run::walk`), stated
    // here too: a set whose headers are encrypted is extracted with the
    // options made HERE, and without it such a set read at the engine's
    // default 4 MiB where every other set reads at 8, so its stored members
    // were cut in pieces half the size of the same members under `-p`.
    session_options.memory.read_ahead = session_read_ahead(
        mode,
        opts.memory_cap.is_some(),
        session_options.memory.read_ahead,
    );
    // The width the pool is about to get (`crate::workers::width`), never
    // the engine's `read_width()`: with no `-mt` that asks rayon how wide
    // the global pool is, which BUILDS it at one thread a core before the
    // walk sizes it, so a lone small member's pool of one
    // (`crate::workers::configure_serial`) was never built (FROM-STUDIO
    // 454 B: 18 threads made where `-mt1` makes one, counted 15 Oct 2026).
    let waiting = waiting_outputs(
        mode,
        extract_path.unwrap_or(""),
        session_options
            .workers
            .unwrap_or_else(|| crate::workers::width(None, crate::workers::Work::Read)),
    );
    session_options = session_options.with_waiting_outputs(waiting);
    // As the walk states it (`Run::walk`, [`files_in_order`]).
    session_options = session_options.with_files_in_order(files_in_order(mode));
    let mut session = rarkit::Session::new(session_options);
    let first = match crate::engine::open_in(path, &mut session) {
        Ok(opened) => opened,
        Err(OpenFailure::Missing(text)) => {
            out.refused(&text, Some("No files to extract\n"));
            return Exit::NothingMatched;
        }
        Err(OpenFailure::NotAnArchive(text)) => {
            out.say(&format!("{text}\n"));
            out.say("\nNo files to extract\n");
            return Exit::NothingMatched;
        }
        Err(failure @ OpenFailure::Damaged(tail)) => {
            out.refused(failure.text(), Some("No files to extract\n"));
            return tail.exit();
        }
        // In the words and count of the same refusal met later in the walk.
        Err(OpenFailure::OverBudget(text)) => {
            out.refused(
                &format!("{text}\n"),
                (!opts.hide_done).then_some("Total errors: 1\n"),
            );
            return Exit::Aborted;
        }
        // Headers enciphered under another password (RAR 5 `-hp`): one
        // error, counted as the reference counts it (`Out::refused`).
        Err(OpenFailure::BadPassword(text)) => {
            out.refused(&text, (!opts.hide_done).then_some("Total errors: 1\n"));
            return Exit::WrongPassword;
        }
    };

    // A later volume named: the walk may start over at the set's first.
    let (first, chain, named_banner) = match restart_at_first(path, &first, &mut session, selection)
    {
        Some((opened, chain)) => (opened, chain, Some(path.to_owned())),
        None => {
            let chain = volume_chain(path, &first, &mut session);
            (first, chain, None)
        }
    };
    let first_password_wrong = first.password_wrong;
    let keep_session = first.header_encrypted;
    let Chain {
        names: volume_names,
        later,
        missing,
        not_rar: _,
    } = chain;
    // Kept only where the open derived a header key; elsewhere the walk
    // keys afresh exactly as before, since there is nothing to reuse.
    let session = keep_session.then_some(session);
    let mut volumes = Vec::with_capacity(volume_names.len());
    volumes.push(first);
    volumes.extend(later);

    let dest = extract_path.unwrap_or("").to_owned();
    let mut units = Vec::with_capacity(volumes.len());
    let mut volume_last_data = Vec::with_capacity(volumes.len());
    let main_header_ends: Vec<u64> = volumes.iter().map(|v| v.main_header_size).collect();
    let last_volume = volumes.len().saturating_sub(1);
    for (index, volume) in volumes.iter().enumerate() {
        // Service headers do NOT count here, and the measurement that
        // says so is the `add-then-test` conformance row. A `rar a`
        // archive puts its quick-open block after the last file, so
        // counting it makes the last file stop at 99% - and the
        // reference prints 100% there. Re-measured against rar 7.23 on
        // 4 Sep 2026 over four shapes, one file, two files, three files
        // and a recursed directory: the counter reaches 100% on the last
        // member WITH A PAYLOAD and on nothing else, whatever service
        // blocks follow it. In the recursed shape the last payload is
        // `sub/nested.txt` and the trailing directory entry carries no
        // percentage at all, which is why that row reads 99% and reads
        // the same either way.
        volume_last_data.push(
            volume
                .members
                .iter()
                .filter(|m| !m.is_service)
                .map(|m| m.data_end)
                .max()
                .unwrap_or(0)
                .min(volume.size),
        );
        // The unit a volume contributes to the counter's denominator, and
        // to every later volume's offset. Measured against unrar 7.23 on
        // 18 Sep 2026 over single archives of two to ten members, and on
        // 30 Sep 2026 over volume sets: a volume BEFORE
        // the last counts its whole file, its padding and quick-open index
        // included, and the last counts to its end record less the
        // service blocks behind its last member (`Opened::counted_end`).
        // The first rule is the one the sets needed: counting each volume
        // to its last payload read one high from the second volume on
        // (`r5_vol`: 32, 65, 98 where the reference reads 32, 64, 97).
        // The second is the single archive's: the index and recovery
        // record `rar a` writes after the last member are not counted
        // (dividing by the file length read 24/49/74 on four equal members
        // where the reference reads 25/50/75), and a walk stopped by a
        // damaged header counts the whole file.
        units.push(if index < last_volume {
            volume.size
        } else {
            volume.counted_end
        });
    }
    let tail = volumes.iter().find_map(|volume| volume.tail);
    let damaged: Vec<DamagedHeader> = volumes
        .iter_mut()
        .flat_map(|volume| std::mem::take(&mut volume.damaged))
        .collect();
    // After the summaries above, which are the last readers of the member
    // lists: the plan TAKES the members rather than copying them.
    let mut plan = build_plan(&mut volumes);
    let selected: Vec<usize> = plan
        .iter()
        .enumerate()
        .filter(|(_, planned)| selection.keeps(&planned.member))
        .filter(|(_, planned)| !select::nameless(&planned.member, mode, extract_path.unwrap_or("")))
        .map(|(index, _)| index)
        .collect();
    // A version `-ver<n>` picked by its number goes by its name without
    // the `;n`, on its line and on disk (sweep 2 item 34).
    for &index in &selected {
        if selection.picks_by_number(&plan[index].member) {
            plan[index].member.drop_version_suffix();
        }
    }
    // Only a volume SET has volumes to pass or a later one to start at, so
    // a single archive does not look at the selection a second time.
    let (announce_passed, first_selected) = if volumes.len() > 1 {
        (
            selected
                .iter()
                .any(|&index| !plan[index].member.is_dir && plan[index].member.method == 0),
            selected.first().copied(),
        )
    } else {
        (false, None)
    };
    let selected = Selected::new(selected);
    // The counter counts from the volume the walk STARTS at: the first,
    // when a stored member is selected (the reference then walks every
    // volume, [`Run::announce_passed`]), and otherwise the first selected
    // member's, where the reference begins. Its denominator leaves out
    // that volume's main header, the signature included, though a
    // member's `data_end` (the numerator) is an absolute file offset that
    // still counts it once (`Opened::main_header_size`). Measured against
    // unrar 7.23 on 30 Sep 2026: `b.bin` alone, starting in the third of
    // four compressed volumes, reads ` 91%` there, the third and fourth
    // volumes' share.
    let start = if announce_passed {
        0
    } else {
        first_selected.map_or(0, |index| plan[index].fragments[0].0)
    };
    let mut running = 0_u64;
    let volume_offset: Vec<u64> = units
        .iter()
        .enumerate()
        .map(|(index, unit)| {
            let offset = running;
            if index >= start {
                running += unit;
            }
            offset
        })
        .collect();
    let total_size = running.saturating_sub(main_header_ends.get(start).copied().unwrap_or(0));
    let plan_len = plan.len();
    // Declared before `run`, so it is dropped, and what it holds written,
    // after the walk's last line and before this returns.
    let held = out.held();
    // The device the archive is read from, which a big member written back
    // to it may take another form on (`unbuffered::form_at`): one stat.
    // Under the write rule on facts (a knob, off in every shipped build) a
    // run with a big stored member has its archive's residency sampled
    // there too, over the set's volumes, before anything of it is read.
    if matches!(mode, Mode::Extract { .. }) {
        let sample = unbuffered::samples_source()
            && selected.iter().any(|&index| {
                let member = &plan[index].member;
                !member.is_dir && member.method == 0 && member.size >= unbuffered::LEAST
            });
        unbuffered::note_source(&volume_names, sample);
    }
    let mut run = Run {
        streams: &held,
        mode,
        opts,
        dest,
        volumes,
        volume_names,
        plan,
        selected,
        done: IndexSet::with_bound(plan_len),
        failures: Vec::new(),
        mismatches: Vec::new(),
        capture: None,
        held: ByIndex::default(),
        announced: Indices::default(),
        named_banner,
        announce_passed,
        dirs: target::KnownDirs::default(),
        made_modes: std::collections::HashMap::new(),
        dir_finish: Vec::new(),
        wrote: Indices::default(),
        beside: ByIndex::default(),
        naming: ByIndex::default(),
        held_members: ByIndex::default(),
        held_declared: 0,
        held_refused: ByIndex::default(),
        high_bits_left_off: std::sync::atomic::AtomicBool::new(false),
        wrote_in_place: false,
        open_lines: BTreeSet::new(),
        passed_over: BTreeSet::new(),
        pending: VecDeque::new(),
        reached: 0,
        emit_to: None,
        last_failed: false,
        banner_gap_owed: false,
        password_wrong: first_password_wrong,
        session,
        volume_offset,
        total_size,
        last_pct: None,
        volume_last_data,
        touched: false,
        asked: Asked::Each,
        stopped: None,
        may_ask: false,
        tail,
        damaged,
        errors: 0,
        targets: String::new(),
        target_at: Vec::new(),
        links: links::State::default(),
        window_ceiling: u64::MAX,
        narrowing: None,
        narrowest: None,
        #[cfg(feature = "parallel")]
        stored_walks: false,
        #[cfg(all(target_os = "linux", feature = "parallel"))]
        ahead: None,
        #[cfg(all(target_os = "macos", feature = "parallel"))]
        ahead: None,
    };
    run.execute(password, missing)
}

/// Folds every volume's file headers into the members the ENGINE opens,
/// one entry a member, in the order it opens them.
///
/// The fold is the engine's own join and nothing wider (spec F 3.5.4, as
/// `rarkit`'s walk applies it): a member whose header says the data
/// continues is joined to the FIRST file header of the next volume, and
/// only where that header says "split before" and agrees on name, size
/// and method. Until 8 Oct 2026 a "split before" header was folded into
/// ANY earlier entry of its name, which is not what the engine does, and
/// every header the two disagreed on put the walk's bookkeeping one member
/// out of step: later members were written, and called `OK`, under a
/// neighbour's name (a continuation block written twice, a stray "split
/// before" header in a plain archive, one cleared "split after" bit).
///
/// Three kinds of file header are no member and get no entry:
///
/// - a "split before" header that continues nothing, anywhere but at the
///   very start of the walk. The engine opens it as a member of its own
///   and [`Walk::on_open`] passes it over, as unrar 7.23 does without a
///   word (measured 8 Oct 2026, RAR 5 and the older sets);
/// - a header after one that says the data continues, in the same
///   volume: the engine has left for the next volume and never reads it;
/// - the first header of a volume that fails the join: the engine
///   refuses the member it was reading and reads on past this header.
///
/// The plan is still only the tool's reading. What ties a line and a file
/// to a member is what the engine says it opened ([`Walk::on_open`]), and
/// an entry the walk never opens is refused by name
/// ([`Run::refuse_unopened`]).
///
/// The members are MOVED out of each volume's list, which is left empty:
/// nothing reads a volume's members after the plan is made.
fn build_plan(volumes: &mut [Opened]) -> Vec<Planned> {
    let mut plan: Vec<Planned> = Vec::new();
    // The entry the engine is inside as it enters a volume: its last
    // fragment said the data continues.
    let mut carried: Option<usize> = None;
    let mut walk_begun = false;
    for (index, volume) in volumes.iter_mut().enumerate() {
        // Whether the walk has left this volume for the next.
        let mut left = false;
        // Service headers carry no payload and the engine's extraction
        // never calls back for one.
        for member in std::mem::take(&mut volume.members)
            .into_iter()
            .filter(|m| !m.is_service)
        {
            let first_of_walk = !std::mem::replace(&mut walk_begun, true);
            if left {
                continue;
            }
            if let Some(open) = carried.take() {
                let head = &plan[open].member;
                if member.split_before
                    && member.name.as_str() == head.name.as_str()
                    && member.size == head.size
                    && member.method == head.method
                {
                    plan[open].fragments.push((index, member.data_end));
                    plan[open].split_after_last = member.split_after;
                    if member.split_after {
                        carried = Some(open);
                        left = true;
                    }
                }
                continue;
            }
            // A set read from a later volume opens with the rest of a
            // member whose head is not in hand: that one is an entry, and
            // its failure is said as it always was.
            if member.split_before && !first_of_walk {
                continue;
            }
            if member.split_after {
                carried = Some(plan.len());
                left = true;
            }
            plan.push(Planned {
                fragments: Fragments::One([(index, member.data_end)]),
                split_after_last: member.split_after,
                member,
            });
        }
    }
    plan
}

#[cfg(test)]
mod tests;

// The Windows lone write's writer (`route::lone_write_ships_on`).
#[cfg(all(windows, feature = "parallel"))]
mod lone_write;
