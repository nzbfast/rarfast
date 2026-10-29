//! Which files on disk a creator command puts in the archive, and under
//! what name.
//!
//! Written from `rar` 7.23's observable behaviour on an Apple Silicon Mac. The rules
//! that surprised the first draft, each measured on the conformance
//! payload set:
//!
//! - a mask that NAMES A DIRECTORY is walked whether or not `-r` was
//!   given, and the directory's own entry is stored AFTER its contents
//!   (`rar a arc.rar sub` stores `sub/nested.txt`, then `sub`). Only
//!   `-r-` stops that walk: it stores the entry `sub` alone;
//! - `-r` makes a name search the subdirectories too, so `rar a -r
//!   arc.rar nested.txt` finds `sub/nested.txt`, and beside a
//!   `nested.txt` that is here it takes every other one below;
//! - a WILDCARD takes files only, of its own directory only, unless `-r`
//!   or `-r0` is given; then it takes every file below whose name
//!   matches and the entry, not the contents, of every directory whose
//!   name matches (`tests/create-selection/rar723-recursion.txt`);
//! - `-ep` drops the directory entries entirely, because a bare base name
//!   has no folder left to record;
//! - a mask that matches NOTHING is reported on stderr in the C library's
//!   own words and does not stop the others: `rar a arc.rar text.txt
//!   nosuch.txt rand.bin` writes both files that exist, prints `Cannot
//!   open nosuch.txt` and `No such file or directory`, and exits 10.
//!
//! The progress line shows the path ON DISK, not the name that is stored:
//! `rar a -ep arc.rar sub` prints `Adding    sub/nested.txt` and stores
//! `nested.txt`.
//!
//! A source outside the current directory is named the way the reference
//! names it, measured 30 Sep 2026 over every path switch with and without
//! `-r`: a leading `/` is dropped and so is everything up to and
//! including the LAST `..` component, so `rar a arc.rar /abs/full.mkv`
//! stores `abs/full.mkv`, `../src/d` stores `src/d/...` and
//! `src/d/../full.mkv` stores `full.mkv`. No stored name is ever absolute
//! or climbs out, which is the writer's own rule too; the command line
//! reaches it by stripping, never by asking the writer to relax.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use rarkit::Timestamp;

use super::args::{Options, PathMode, Recurse};
use crate::dialect::unrar::extract::mask::{has_wildcard, lead, wildcard, Screen};

/// One file or directory chosen for the archive.
pub(crate) struct Chosen {
    /// The path on disk, which is what the progress line shows.
    pub(crate) shown: String,
    /// The path to open, which differs from `shown` only in separators.
    pub(crate) disk: PathBuf,
    /// The name to store, as archive bytes.
    pub(crate) stored: String,
    /// Whether this is a directory entry rather than a file.
    pub(crate) is_dir: bool,
    /// The file's length; zero for a directory.
    pub(crate) size: u64,
    /// The modification time to record, when the platform gave one.
    pub(crate) mtime: Option<Timestamp>,
    /// The attributes to record: the file mode on a unix host.
    pub(crate) attributes: u32,
}

/// What a walk of the command line's masks found.
pub(crate) struct Found {
    /// Everything chosen, in the order the reference adds it.
    pub(crate) files: Vec<Chosen>,
    /// The masks that matched nothing, in the reference's own wording,
    /// ready for stderr.
    pub(crate) missing: Vec<String>,
    /// The directories the walk could not read, in the reference's own
    /// wording, ready for stderr. What lies below them is not in `files`.
    pub(crate) unread: Vec<String>,
    /// The files chosen that their owner may not read and that would
    /// not open, in the reference's own wording, ready for stderr. They
    /// are not in `files` ([`owner_cannot_read`]).
    pub(crate) unopened: Vec<String>,
    /// How many paths the masks MATCHED, before any filter dropped one.
    ///
    /// Counted apart from `files` because the two questions are
    /// different, and conflating them cost a conformance row: the
    /// `add-exclude` line is `rar a -xrand.bin arc.rar text.txt
    /// rand.bin`, where `rand.bin` matches a real file and is then
    /// excluded. Reading "nothing was kept" as "nothing was there" would
    /// print `Cannot open rand.bin`, which the reference does not.
    matched: usize,
    /// The path prefix `-ep1` strips from the names the mask now being
    /// walked yields, in the form [`display`] gives paths.
    base: String,
    /// The current directory, as text, when `-ep2` or `-ep3` joins it to
    /// every relative source; read once rather than per file.
    cwd: Option<String>,
    /// The `-x` masks, read once ([`Mask`]).
    exclude: Vec<Mask>,
    /// The `-n` masks. With none, every path is included.
    include: Vec<Mask>,
    /// The current directory, as text, when a mask is an absolute path
    /// and so is compared with each walked path made absolute.
    here: Option<String>,
    /// `-ep`: an exclude mask that is a bare name is compared with the
    /// name alone.
    bare_names: bool,
}

/// One `-x` or `-n` mask of a create.
///
/// It is read by the read commands' own rule, [`Screen`], so that one
/// mask means one thing whether it screens an archive's members or the
/// files a create walks: until 9 Oct 2026 the create kept a matcher of
/// its own beside it. rar 7.23's answers over a tree three levels deep
/// are `tests/create-selection/rar723-exclude-include.txt` (measured 8
/// Oct 2026) and `rar723-one-matcher.txt` (9 Oct 2026, the rows where the
/// two matchers differed), and the screen gives them all:
///
/// - **no wildcard**: that exact path and everything below it. `-xa.txt`
///   takes `a.txt` in the current directory and not `s/a.txt`; `-xs/d`
///   takes the directory `s/d` and its whole contents. Compared as typed:
///   `s//d` and `S/D` are not `s/d`.
/// - **a wildcard in the name, none in the folder** (`*.txt`, `s/d*`):
///   the folder part is a prefix of the path's own folder and the name
///   part is matched against the path's last component.
/// - **a wildcard in the folder** (`*/a.txt`, `s/*/z.txt`): the whole
///   mask against the whole path, a `*` and a `?` standing for a
///   separator too, and a leading `*/` may stand for nothing.
/// - **a directory** is taken by a wildcard mask only when the mask's
///   name part is literal, is `*` or `*.*`, or the mask ends in a
///   separator. `-x*.txt` leaves a directory named `dd.txt` in.
///
/// What a create adds, because its paths are paths on disk and not
/// members' names: the path compared is the path as walked, without a
/// leading `./`; a mask typed with a `/` or a `../` at its front is
/// compared with a path that has the same front (an absolute mask with
/// the walked path made absolute), where the screen alone would drop
/// it; and under `-ep` an exclude mask that is a bare name takes that
/// name at any depth.
///
/// A directory an exclude mask takes is not walked, so nothing below it
/// is archived, and nothing below it is deleted by `-df` or a move.
struct Mask {
    /// The mask as typed, with the archive's separator.
    text: String,
    /// The `/` and `../` parts the mask began with, which a path must
    /// begin with too. A leading `./` is no part of it.
    front: String,
    /// The reference's reading of the mask.
    screen: Screen,
    /// Nothing but its front is left of the mask (`-x/`, `-x./`), which
    /// the screen reads as every file and no directory, wherever it is.
    every_file: bool,
    /// A name alone: no separator and no wildcard.
    plain_name: bool,
}

impl Mask {
    fn new(typed: &str) -> Self {
        let text = separators(typed);
        let dropped = lead(&text);
        Self {
            front: text[..dropped]
                .split_inclusive('/')
                .filter(|part| *part != "./")
                .collect(),
            screen: Screen::new(&text),
            every_file: dropped > 0 && dropped == text.len(),
            plain_name: !text.is_empty() && !text.contains('/') && !has_wildcard(&text),
            text,
        }
    }

    /// Whether the mask is an absolute path.
    fn is_absolute(&self) -> bool {
        self.front.starts_with('/')
    }

    /// Whether the mask takes `path`, a file or a directory. `by_name`
    /// lets a bare name take its name at any depth.
    fn takes(&self, path: &str, is_dir: bool, by_name: bool) -> bool {
        if self.every_file {
            return !is_dir;
        }
        (by_name
            && self.plain_name
            && path
                .rsplit('/')
                .next()
                .is_some_and(|name| name == self.text))
            || path
                .strip_prefix(self.front.as_str())
                .is_some_and(|rest| self.screen.covers(rest, is_dir))
    }
}

impl Found {
    /// Whether any mask of `masks` takes `shown`, a walked path in the
    /// form [`display`] gives it.
    fn any_takes(&self, masks: &[Mask], shown: &str, is_dir: bool, by_name: bool) -> bool {
        // Rule C12 of the command line's specification, section 3: a
        // name is taken when any mask takes it. An absolute mask is put
        // to the path made absolute ([`Mask`]); `here` is known whenever
        // such a mask was typed.
        let rooted = self
            .here
            .as_deref()
            .filter(|_| !shown.starts_with('/'))
            .map(|here| format!("{}/{shown}", here.trim_end_matches('/')));
        masks.iter().any(|mask| {
            let path = match &rooted {
                Some(rooted) if mask.is_absolute() => rooted.as_str(),
                _ => shown,
            };
            mask.takes(path, is_dir, by_name)
        })
    }

    /// Whether a `-x` mask takes the path. A directory it takes is
    /// neither stored nor walked.
    fn excludes(&self, shown: &str, is_dir: bool) -> bool {
        // Measured: under `-ep`, `-xa.txt` takes every `a.txt`, and
        // `-nb.txt` takes no `s/b.txt`.
        !self.exclude.is_empty() && self.any_takes(&self.exclude, shown, is_dir, self.bare_names)
    }

    /// Whether the `-n` masks, if there are any, take the path.
    fn includes(&self, shown: &str, is_dir: bool) -> bool {
        self.include.is_empty() || self.any_takes(&self.include, shown, is_dir, false)
    }
}

/// Walks every mask on the command line.
pub(crate) fn collect(masks: &[String], opts: &Options) -> Found {
    let mut found = Found {
        files: Vec::new(),
        missing: Vec::new(),
        unread: Vec::new(),
        unopened: Vec::new(),
        matched: 0,
        base: String::new(),
        cwd: match opts.path_mode {
            PathMode::FullPath | PathMode::FullPathWithDrive => std::env::current_dir()
                .ok()
                .map(|dir| separators(&dir.to_string_lossy())),
            _ => None,
        },
        exclude: opts.shared.exclude.iter().map(|m| Mask::new(m)).collect(),
        include: opts.shared.include.iter().map(|m| Mask::new(m)).collect(),
        here: None,
        bare_names: opts.path_mode == PathMode::NoPaths,
    };
    if found
        .exclude
        .iter()
        .chain(&found.include)
        .any(Mask::is_absolute)
    {
        found.here = std::env::current_dir()
            .ok()
            .map(|dir| separators(&dir.to_string_lossy()));
    }
    for mask in masks {
        let before = found.matched;
        walk_mask(mask, opts, &mut found);
        if found.matched == before && !has_wildcard(mask) && opts.recurse != Recurse::On {
            // A LITERAL name that matched nothing is an error the
            // reference reports per mask; a wildcard that matches nothing
            // is not, which is why the two are split here. Nor is a name
            // searched for below with `-r` and found nowhere: measured 8
            // Oct 2026, `rar a -r arc s nosuch` says nothing of `nosuch`
            // and exits 0.
            let reason = std::fs::metadata(mask).err().map_or_else(
                || "No such file or directory".to_owned(),
                |err| crate::dialect::unrar::io_reason(&err),
            );
            found.missing.push(format!("Cannot open {mask}\n{reason}"));
        }
    }
    dedupe(&mut found.files);
    if opts.solid && !opts.keep_order && !opts.level.is_store() {
        // A solid archive groups members so that like packs with like:
        // measured, `rar a -m3 -s arc.rar text.txt rand.bin` stores
        // rand.bin first, which is the order an extension sort gives.
        // `-ds` keeps the order found, and so does `-m0`, measured: `rar
        // a -s -m0` stores in the order it scanned, since nothing in a
        // stored archive shares history.
        sort_for_solid(&mut found.files);
    }
    found
}

/// Drops a file chosen twice under ONE spelling, keeping the LAST
/// choice, which is what the reference stores: measured 4 Oct 2026,
/// `a/one.txt b.txt a/one.txt c.txt b.txt` stores `a/one.txt`, `c.txt`,
/// `b.txt`, and `z* zab` stores `zab` after the mask's other files.
///
/// The key is the path as walked, not the stored name, measured against
/// `rar` 7.23: `a a/same.txt` stores `a/same.txt` once, but
/// `a/same.txt ./a/same.txt` stores it twice, and `-ep a/same.txt
/// b/same.txt` stores BOTH files as `same.txt`, exit 0, no warning. An
/// archive may hold two members of one name; dropping the second here
/// lost its data without a word.
///
/// The paths seen go in a hash set, one lookup a file. A list searched
/// from the front made this n squared compares, which on 20,000 files
/// cost as much as the whole walk (0.14 s on Linux, up to 0.6 s on macOS,
/// 30 Sep 2026). A path hashes as it compares,
/// by its components, so what is kept and its order are the list's.
fn dedupe(files: &mut Vec<Chosen>) {
    let keep: Vec<bool> = {
        let mut seen: HashSet<&Path> = HashSet::with_capacity(files.len());
        let mut keep: Vec<bool> = files
            .iter()
            .rev()
            .map(|file| seen.insert(&file.disk))
            .collect();
        keep.reverse();
        keep
    };
    let mut keep = keep.into_iter();
    files.retain(|_| keep.next().unwrap_or(true));
}

/// The order a solid archive stores its members in: the writer's own
/// [`MemberSortKey`](rarkit::MemberSortKey), which is reference `rar`
/// 7.23's, applied HERE rather than inside the writer so that
/// the progress lines, which follow this list, come out in archive order.
/// The writer is then told to keep the order it is given.
fn sort_for_solid(files: &mut [Chosen]) {
    fn key(file: &Chosen) -> rarkit::MemberSortKey<'_> {
        rarkit::MemberSortKey::of(file.stored.as_bytes(), file.size, file.is_dir)
    }
    files.sort_by(|left, right| key(left).cmp(&key(right)));
}

/// Whether a mask names a directory's CONTENTS rather than the directory:
/// `.`, `..`, `dir/`, `dir/.`, `dir/..`. Measured against rar 7.23, such
/// a mask stores no entry for the directory itself, and every name keeps
/// the mask's own spelling as its prefix (`sub/.` stores `sub/./b.txt`,
/// `.` and `./` store `b.txt`). Without `-r` it takes only the files
/// directly inside (`rar a arc.rar sub/` stores `sub/b.txt` and neither
/// `sub/deep` nor anything in it).
fn names_contents(mask: &str) -> bool {
    mask == "."
        || mask == ".."
        || mask.ends_with('/')
        || mask.ends_with("/.")
        || mask.ends_with("/..")
}

/// The prefix `-ep1` strips: the mask's directory part, which for a
/// contents mask is the whole mask (`-ep1 sub/` stores `b.txt`, `-ep1
/// sub/deep` stores `deep/c.txt`).
fn base_of(mask: &str) -> String {
    let dir = if names_contents(mask) {
        let mut whole = mask.to_owned();
        if !whole.ends_with('/') {
            whole.push('/');
        }
        whole
    } else {
        mask.rfind('/')
            .map_or_else(String::new, |at| mask[..=at].to_owned())
    };
    display_text(&dir)
}

/// One mask: a literal path, a directory to walk, or a pattern to match.
fn walk_mask(mask: &str, opts: &Options, found: &mut Found) {
    let path = PathBuf::from(mask);
    found.base = base_of(mask);
    let mut within = Within::default();
    if !has_wildcard(mask) {
        match stat(&path) {
            Ok(meta) if meta.is_dir() => {
                if !names_contents(mask) && found.excludes(&display(&path), true) {
                    // The directory was there; a mask took it, and with
                    // it everything below.
                    found.matched += 1;
                    return;
                }
                if names_contents(mask) {
                    if matches!(opts.recurse, Recurse::Off | Recurse::Never) {
                        walk_files_only(&path, opts, found);
                    } else {
                        within.enter(&meta);
                        walk_directory(&path, opts, found, &mut within);
                    }
                } else if opts.recurse != Recurse::Never {
                    within.enter(&meta);
                    walk_directory(&path, opts, found, &mut within);
                }
                if names_contents(mask) {
                    // The walk matched the directory; it just has no
                    // entry of its own to store.
                    found.matched += 1;
                } else {
                    push(&path, true, Ok(meta), opts, found);
                }
                return;
            }
            // A file that is here, and with `-r` every file of its name
            // below as well, which is the next arm: measured, `rar a -r
            // arc a.txt` stores `a.txt`, `s/a.txt` and `s/d/a.txt`.
            Ok(_) if opts.recurse == Recurse::On => {}
            Ok(meta) => {
                push(&path, false, Ok(meta), opts, found);
                return;
            }
            // Not there under the name as spelled. With `-r` it may still
            // be somewhere below, which is the next arm.
            Err(_) => {}
        }
    }
    let base = path.parent().filter(|p| !p.as_os_str().is_empty());
    let pattern = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let root = base.map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    // `-r` is what sends a mask below the directory it names; without it
    // a name that is not there is simply not there. `-r0` sends only a
    // wildcard below.
    let wild = has_wildcard(&pattern);
    let search = Search {
        // Measured: `s/*.*` takes `s/dx`, a name with no dot in it, which
        // is the matcher's own rule for `*.*`.
        pattern: &pattern,
        wild,
        deep: match opts.recurse {
            Recurse::On => true,
            Recurse::WildcardsOnly => wild,
            Recurse::Off | Recurse::Never => false,
        },
    };
    let from = found.files.len();
    match_under(&root, &search, opts, found, &mut within);
    if base.is_none() {
        // A mask with no directory was walked from `.`, which the mask
        // did not spell: `z*` chose `./zab`. That path is put back as
        // typed, so that the same file chosen by name, `zab`, is seen as
        // the one spelling it is ([`dedupe`]), and `./zab`, typed, as
        // another.
        for file in &mut found.files[from..] {
            if let Ok(typed) = file.disk.strip_prefix(".") {
                file.disk = typed.to_path_buf();
            }
        }
    }
}

/// The directories the walk is inside at this moment, outermost first,
/// each by the identity the file system gives it.
///
/// The walk follows links, so a link that points at a directory it sits
/// under leads back into the walk for ever: `d/x -> .` is `d` again, and
/// two such links doubled the walk at every level until the system's own
/// limit on links in one path, which no run reaches (the reference does
/// not finish that walk either, measured 4 Oct 2026). A directory that is
/// already being walked is therefore not entered a second time. Its own
/// entry is still recorded, and nothing that is there is left out, since
/// everything inside it is being walked under its first name.
///
/// The identity comes from the stat the walk has taken already, so this
/// costs no call. Off a unix host the stat carries none and every
/// directory is entered, as before.
#[derive(Default)]
struct Within(Vec<Option<(u64, u64)>>);

impl Within {
    /// Goes into the directory `meta` describes, unless the walk is
    /// inside it already, and says whether it went.
    fn enter(&mut self, meta: &std::fs::Metadata) -> bool {
        let identity = identity_of(meta);
        if identity.is_some() && self.0.contains(&identity) {
            return false;
        }
        self.0.push(identity);
        true
    }

    /// Comes out of the directory last entered.
    fn leave(&mut self) {
        self.0.pop();
    }
}

#[cfg(unix)]
fn identity_of(meta: &std::fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    Some((meta.dev(), meta.ino()))
}

#[cfg(not(unix))]
fn identity_of(_meta: &std::fs::Metadata) -> Option<(u64, u64)> {
    None
}

/// Walks `entry`, a directory with the stat `meta`, unless the walk is
/// inside it already.
fn walk_below(
    entry: &Path,
    meta: &std::io::Result<std::fs::Metadata>,
    opts: &Options,
    found: &mut Found,
    within: &mut Within,
) {
    let Ok(meta) = meta else { return };
    if found.excludes(&display(entry), true) {
        return;
    }
    if within.enter(meta) {
        walk_directory(entry, opts, found, within);
        within.leave();
    }
}

/// What a mask that is not a path to something looks for below a
/// directory.
struct Search<'a> {
    /// The mask's last component, matched against each entry's name.
    pattern: &'a str,
    /// Whether `pattern` holds a wildcard.
    wild: bool,
    /// Whether the directories below are searched too.
    deep: bool,
}

/// Every entry of `root` the search takes, and, when it is deep, of every
/// directory below it.
///
/// A NAME that turns out to be a directory is walked whole. A WILDCARD
/// that matches a directory takes its entry alone, and only when the
/// search is deep; what the directory holds is matched name by name like
/// everything else below.
fn match_under(
    root: &Path,
    search: &Search<'_>,
    opts: &Options,
    found: &mut Found,
    within: &mut Within,
) {
    let Search {
        pattern,
        wild,
        deep,
    } = *search;
    let (entries, failed) = read_sorted(root);
    // A directory that is NOT THERE is not one that could not be read:
    // measured, `rar a arc.rar nodir/*` says nothing about `nodir`.
    if let Some(err) = failed.filter(|err| err.kind() != std::io::ErrorKind::NotFound) {
        unread(root, &err, found);
    }
    for (entry, meta) in entries {
        let is_dir = is_dir(&meta);
        let name = entry
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        // A name that is searched for is matched as a mask is, so `-r
        // a.txt.` finds every `a.txt` (the matcher's rule for a last
        // dot); a name that is only looked up where it was typed is that
        // name and no other (measured: `rar a arc s/a.txt.` finds
        // nothing, exit 10).
        let matched = if wild || deep {
            wildcard(pattern, &name)
        } else {
            name == pattern
        };
        if matched && !(is_dir && wild) {
            if is_dir {
                walk_below(&entry, &meta, opts, found, within);
            }
            push(&entry, is_dir, meta, opts, found);
            continue;
        }
        if !(deep && is_dir) {
            continue;
        }
        if !found.excludes(&display(&entry), true) {
            if let Ok(below) = &meta {
                if within.enter(below) {
                    match_under(&entry, search, opts, found, within);
                    within.leave();
                }
            }
        }
        if matched {
            push(&entry, true, meta, opts, found);
        }
    }
}

/// Walks a directory the command line named: its files, then the entries
/// of each directory below it, then that directory itself.
fn walk_directory(root: &Path, opts: &Options, found: &mut Found, within: &mut Within) {
    let (entries, failed) = read_sorted(root);
    if let Some(err) = failed {
        unread(root, &err, found);
    }
    for (entry, meta) in entries {
        let is_dir = is_dir(&meta);
        if is_dir {
            walk_below(&entry, &meta, opts, found, within);
        }
        push(&entry, is_dir, meta, opts, found);
    }
}

/// The files directly inside a directory, and nothing below it: a
/// contents mask without `-r`.
fn walk_files_only(root: &Path, opts: &Options, found: &mut Found) {
    let (entries, failed) = read_sorted(root);
    if let Some(err) = failed {
        unread(root, &err, found);
    }
    for (entry, meta) in entries {
        if !is_dir(&meta) {
            push(&entry, false, meta, opts, found);
        }
    }
}

/// A directory's entries, sorted by name, each with its ONE stat.
///
/// The reference walks them in the order the file system hands them back,
/// which on macOS is neither sorted nor stable across file systems. A
/// sort is the one order that does not depend on where the archive was
/// built, and the difference is visible only for a WILDCARD mask: every
/// conformance row that creates names its members, and a named member is
/// added where it was named.
///
/// **A directory that cannot be read is reported, not skipped.** The
/// second half of the answer is the error that stopped the listing, or
/// the first one an entry of it gave; the entries are the ones read
/// before and around it. Until 4 Oct 2026 both were dropped here, so
/// what lay below a directory of mode 000 was missing from the archive
/// with nothing said and exit 0 (see [`unread`]).
///
/// The stat is taken here and carried to [`push`], which records the
/// entry from it. Asking the path whether it is a directory, and then
/// statting it again to record it, made two a file (47,350 `statx` for
/// small20k's 23,669 entries, 30 Sep 2026). It
/// FOLLOWS a link, as both of those did, so a link to a directory is still
/// walked as one; a stat that fails reads as not a directory, as it did,
/// and `push` reports its error.
fn read_sorted(root: &Path) -> (Vec<Walked>, Option<std::io::Error>) {
    let mut failed = None;
    let mut entries: Vec<PathBuf> = match std::fs::read_dir(root) {
        Ok(listing) => listing
            .filter_map(|entry| match entry {
                Ok(entry) => Some(entry.path()),
                Err(err) => {
                    failed.get_or_insert(err);
                    None
                }
            })
            .collect(),
        Err(err) => {
            failed = Some(err);
            Vec::new()
        }
    };
    entries.sort();
    let entries = entries
        .into_iter()
        .map(|entry| {
            let meta = stat(&entry);
            (entry, meta)
        })
        .collect();
    (entries, failed)
}

/// One entry of a walked directory, with its ONE stat.
type Walked = (PathBuf, std::io::Result<std::fs::Metadata>);

/// Records a directory the walk could not read.
///
/// Measured against rar 7.23 on 4 Oct 2026, `proj/secret` at mode 000:
/// `rar a arc.rar proj` complains `Cannot read contents of
/// <cwd>/proj/secret` and `Permission denied`, writes everything it
/// could reach and exits 6. The path is the current directory and then
/// the path AS WALKED, unchanged: `./proj` gives `<cwd>/./proj/secret`
/// and a walk of `.` gives `<cwd>/./secret`. A path that is already
/// absolute is given as it is.
fn unread(root: &Path, err: &std::io::Error, found: &mut Found) {
    let walked = separators(&root.to_string_lossy());
    // `proj/secret/` is reported as `proj/secret`, measured.
    let walked = match walked.trim_end_matches('/') {
        "" => walked.as_str(),
        trimmed => trimmed,
    }
    .to_owned();
    let shown = if root.is_absolute() {
        walked
    } else {
        match std::env::current_dir() {
            Ok(cwd) => format!("{}/{walked}", separators(&cwd.to_string_lossy())),
            Err(_) => walked,
        }
    };
    found.unread.push(format!(
        "Cannot read contents of {shown}\n{}",
        crate::dialect::unrar::io_reason(err)
    ));
}

/// Whether a walked entry is a directory, as `Path::is_dir` answers it: a
/// stat that failed is not one.
fn is_dir(meta: &std::io::Result<std::fs::Metadata>) -> bool {
    meta.as_ref().is_ok_and(std::fs::Metadata::is_dir)
}

/// The one stat the walk takes of a path, following links.
fn stat(path: &Path) -> std::io::Result<std::fs::Metadata> {
    #[cfg(test)]
    stat_count::STATS.with(|count| count.set(count.get() + 1));
    std::fs::metadata(path)
}

/// Records one chosen path, unless a filter on the command line drops it,
/// from the stat the walk took of it.
fn push(
    path: &Path,
    is_dir: bool,
    meta: std::io::Result<std::fs::Metadata>,
    opts: &Options,
    found: &mut Found,
) {
    found.matched += 1;
    let shown = display(path);
    let Some(stored) = stored_name(path, is_dir, opts, found) else {
        return;
    };
    let meta = match meta {
        Ok(meta) => meta,
        Err(err) => {
            found.missing.push(format!(
                "Cannot open {shown}\n{}",
                crate::dialect::unrar::io_reason(&err)
            ));
            return;
        }
    };
    let size = if is_dir { 0 } else { meta.len() };
    if let Some(limit) = opts.size_more {
        // `-sm<size>`: only files LARGER than the limit. A directory
        // carries no size and is not filtered, which is the rule the
        // decoder's own `-sm` was measured to follow.
        if !is_dir && size <= limit {
            return;
        }
    }
    if found.excludes(&shown, is_dir) || !found.includes(&shown, is_dir) {
        return;
    }
    if is_dir && opts.no_empty_dirs {
        // `-ed`: leave out folders. The reference drops the entry and
        // keeps whatever was found inside it.
        return;
    }
    if !is_dir && owner_cannot_read(&meta) {
        if let Err(err) = std::fs::File::open(path) {
            found.unopened.push(format!(
                "Cannot open {shown}\n{}",
                crate::dialect::unrar::io_reason(&err)
            ));
            return;
        }
    }
    found.files.push(Chosen {
        shown,
        disk: path.to_path_buf(),
        stored,
        is_dir,
        size,
        // `-ts-` and `-tsm-` store no modification time.
        mtime: if opts.no_mtime { None } else { mtime_of(&meta) },
        attributes: if opts.default_modes && cfg!(unix) {
            // `-ai`, measured against rar 7.23 on 8 Oct 2026: a file is
            // stored `rw-rw-rw-` and a directory `rwxrwxrwx`, under the
            // type bits of each, whatever the mode on disk.
            if is_dir {
                0o040_777
            } else {
                0o100_666
            }
        } else {
            attributes_of(&meta, is_dir)
        },
    });
}

/// The name to store, or `None` when the path mode leaves nothing to
/// store (`-ep` over a directory, or a directory whose whole name the
/// strip of [`inside`] removes).
fn stored_name(path: &Path, is_dir: bool, opts: &Options, found: &Found) -> Option<String> {
    let relative = display(path);
    let name = match opts.path_mode {
        PathMode::AsGiven => inside(&relative),
        PathMode::NoBaseDir => inside(relative.strip_prefix(&found.base).unwrap_or(&relative)),
        PathMode::NoPaths => {
            if is_dir {
                return None;
            }
            return path.file_name().map(|n| n.to_string_lossy().into_owned());
        }
        // `-ep2` and `-ep3`: the current directory joined to the path AS
        // TYPED, `./` and all (measured: `./full.mkv` from `/w/src` stores
        // `w/src/./full.mkv`), then the same strip, so the leading `/`
        // goes and a `../` climbs away with everything before it. The two
        // are one on a unix host, measured.
        PathMode::FullPath | PathMode::FullPathWithDrive => {
            let typed = separators(&path.to_string_lossy());
            match &found.cwd {
                Some(cwd) if !path.is_absolute() => inside(&format!("{cwd}/{typed}")),
                _ => inside(&typed),
            }
        }
    };
    (!name.is_empty()).then_some(name)
}

/// A name as the reference stores it when the path would reach outside
/// the archive: everything up to and including the LAST `..` component
/// goes, then any leading `/`, then any leading `./` run.
///
/// Measured against `rar` 7.23: `/w/src/full.mkv` stores `w/src/full.mkv`,
/// `../src/full.mkv` and `src/../src/full.mkv` store `src/full.mkv`,
/// `src/d/../full.mkv` stores `full.mkv` (the rest of the path is NOT
/// resolved), and a `./` or `//` inside a name stays as typed.
///
/// On Windows a drive letter goes first, [`past_drive`].
fn inside(name: &str) -> String {
    let name = if cfg!(windows) {
        past_drive(name)
    } else {
        name
    };
    let mut rest = name;
    let mut start = 0;
    for part in name.split('/') {
        let end = start + part.len();
        if part == ".." {
            rest = &name[end..];
        }
        start = end + 1;
    }
    display_text(rest.trim_start_matches('/'))
}

/// A name without the drive letter it was typed with: `C:/data/f.txt` is
/// `/data/f.txt` and `C:dir/f.txt` is `dir/f.txt`.
///
/// Until 4 Oct 2026 a source typed with its drive kept it, and the
/// archive held a member named `C:/data/f.txt`: a name an extractor that
/// honours it writes outside the directory it was told to fill. Only a
/// Windows build calls this ([`inside`]): elsewhere `C:` at the front of
/// a name is two characters of a file's name like any others.
fn past_drive(name: &str) -> &str {
    match name.as_bytes() {
        [letter, b':', ..] if letter.is_ascii_alphabetic() => &name[2..],
        _ => name,
    }
}

/// A path's text with the archive's separator, `/`, for the host's.
///
/// Only Windows has another one. On a unix host a backslash is a
/// character of a file's name like any other and is stored as it is
/// (measured against rar 7.23 on 8 Oct 2026: `n/back\slash.txt` is stored
/// under that name). Until that day it was turned into `/` on every host,
/// so that file became `n/back/slash.txt`, and a name holding `\..\` was
/// then cut as a climb out of the archive and stored outside its own
/// directory.
fn separators(text: &str) -> String {
    if cfg!(windows) {
        text.replace('\\', "/")
    } else {
        text.to_owned()
    }
}

/// A path as the reference prints it and stores it: forward separators on
/// a unix host, and no `./` prefix.
fn display(path: &Path) -> String {
    display_text(&path.to_string_lossy())
}

/// [`display`] over text: any leading `./` run goes, and the separators
/// after it (`.//a` is `a`, measured).
fn display_text(text: &str) -> String {
    let text = separators(text);
    let mut rest = text.as_str();
    while let Some(after) = rest.strip_prefix("./") {
        rest = after.trim_start_matches('/');
    }
    rest.to_owned()
}

/// Whether a file's mode says its owner may not read it, which is the
/// one case the walk asks the system about before the writer does.
///
/// A source that will not open is left out and the rest is archived, as
/// the reference does (measured against rar 7.23 on 8 Oct 2026: `Cannot
/// open s/a.txt`, `Permission denied`, the other members stored, exit
/// 6). Until then the writer met it and the whole create was lost. To
/// find EVERY such file the walk would have to open each one, a system
/// call a member on a path counted in stats; the mode is in the stat it
/// has taken already, so this costs a file that can be read nothing. A
/// file unreadable for another reason (another user's, with no read bit
/// for the rest) is still met by the writer, with the old outcome.
#[cfg(unix)]
fn owner_cannot_read(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    meta.mode() & 0o400 == 0
}

/// Off a unix host a file carries no such bit.
#[cfg(not(unix))]
fn owner_cannot_read(_meta: &std::fs::Metadata) -> bool {
    false
}

/// The modification time to record.
fn mtime_of(meta: &std::fs::Metadata) -> Option<Timestamp> {
    let modified = meta.modified().ok()?;
    let since = modified.duration_since(std::time::UNIX_EPOCH).ok()?;
    Some(Timestamp {
        unix_seconds: since.as_secs() as i64,
        nanos: since.subsec_nanos(),
    })
}

/// The attributes to record: on a unix host the file mode, which is what
/// the reference stores and what its own listing renders back as
/// `-rw-r--r--`.
#[cfg(unix)]
fn attributes_of(meta: &std::fs::Metadata, _is_dir: bool) -> u32 {
    use std::os::unix::fs::MetadataExt;
    meta.mode()
}

/// The Windows arm: the DOS attribute word the platform already keeps.
#[cfg(windows)]
fn attributes_of(meta: &std::fs::Metadata, _is_dir: bool) -> u32 {
    use std::os::windows::fs::MetadataExt;
    meta.file_attributes()
}

/// Neither unix nor Windows: a directory bit and nothing else, which is
/// the least a reader needs to tell the two apart.
#[cfg(not(any(unix, windows)))]
fn attributes_of(_meta: &std::fs::Metadata, is_dir: bool) -> u32 {
    if is_dir {
        0x10
    } else {
        0
    }
}

#[cfg(test)]
mod dedupe_tests {
    use super::{dedupe, inside, past_drive, Chosen};
    use std::path::PathBuf;

    fn chosen(shown: &str, stored: &str) -> Chosen {
        Chosen {
            shown: shown.to_owned(),
            disk: PathBuf::from(shown),
            stored: stored.to_owned(),
            is_dir: false,
            size: 0,
            mtime: None,
            attributes: 0,
        }
    }

    fn shown(files: &[Chosen]) -> Vec<&str> {
        files.iter().map(|file| file.shown.as_str()).collect()
    }

    #[test]
    fn a_drive_letter_is_cut_from_the_front_of_a_name_and_nothing_else_is() {
        for (typed, cut) in [
            ("C:/data/f.txt", "/data/f.txt"),
            ("c:dir/f.txt", "dir/f.txt"),
            ("z:", ""),
            ("data/f.txt", "data/f.txt"),
            ("/C:/f.txt", "/C:/f.txt"),
            ("1:/f.txt", "1:/f.txt"),
            ("dir/C:f.txt", "dir/C:f.txt"),
            (":", ":"),
            ("", ""),
        ] {
            assert_eq!(past_drive(typed), cut, "{typed}");
        }
        // The whole strip is a Windows build's: here a name keeps its
        // first two characters whatever they are.
        if cfg!(windows) {
            assert_eq!(inside("C:/data/f.txt"), "data/f.txt");
            assert_eq!(inside("C:../x/f.txt"), "x/f.txt");
        } else {
            assert_eq!(inside("C:/data/f.txt"), "C:/data/f.txt");
        }
    }

    #[test]
    fn a_path_chosen_twice_is_kept_once_at_its_last_place() {
        let mut files = vec![
            chosen("a/one.txt", "a/one.txt"),
            chosen("b.txt", "b.txt"),
            chosen("a/one.txt", "a/one.txt"),
            chosen("c.txt", "c.txt"),
            chosen("b.txt", "b.txt"),
        ];
        dedupe(&mut files);
        assert_eq!(shown(&files), ["a/one.txt", "c.txt", "b.txt"]);
    }

    #[test]
    fn two_files_stored_under_one_name_are_both_kept() {
        // `-ep a/same.txt b/same.txt`: two files, one stored name, and
        // rar 7.23 stores both.
        let mut files = vec![
            chosen("a/same.txt", "same.txt"),
            chosen("b/same.txt", "same.txt"),
        ];
        dedupe(&mut files);
        assert_eq!(shown(&files), ["a/same.txt", "b/same.txt"]);
    }

    #[test]
    fn names_that_differ_only_in_case_are_both_kept() {
        // As the list compared them: a path's spelling is its own, case
        // and all, whatever the file system under it folds.
        let mut files = vec![
            chosen("A.txt", "A.txt"),
            chosen("a.txt", "a.txt"),
            chosen("dir/Name", "dir/Name"),
            chosen("dir/name", "dir/name"),
            chosen("A.txt", "A.txt"),
        ];
        dedupe(&mut files);
        assert_eq!(shown(&files), ["a.txt", "dir/Name", "dir/name", "A.txt"]);
    }

    #[test]
    fn twenty_thousand_names_keep_their_order() {
        // small20k's size, every name chosen twice by two masks: the
        // first pass is dropped whole and the second keeps its order.
        let first: Vec<String> = (0..20_000).map(|n| format!("d{}/f{n}", n % 97)).collect();
        let mut files: Vec<Chosen> = first
            .iter()
            .chain(first.iter().rev())
            .map(|name| chosen(name, name))
            .collect();
        dedupe(&mut files);
        let second: Vec<&String> = first.iter().rev().collect();
        assert_eq!(shown(&files), second);
    }
}

/// How many stats the walk took on this thread, so a test can pin one
/// stat an entry. The walk runs on the thread that calls [`collect`].
#[cfg(test)]
mod stat_count {
    thread_local! {
        pub(super) static STATS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }
}

#[cfg(test)]
mod stat_tests {
    use super::{collect, stat_count::STATS};
    use crate::dialect::rar::args::{Options, Recurse};
    use std::path::{Path, PathBuf};

    /// A tree of `dirs` directories, each holding `files` files and one
    /// empty directory, under a fresh directory; and how many entries it
    /// holds below its root.
    fn tree(tag: &str, dirs: usize, files: usize) -> (PathBuf, usize) {
        let root = std::env::temp_dir().join(format!("rarfast-stat-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mut entries = 0;
        for d in 0..dirs {
            let dir = root.join(format!("d{d}"));
            std::fs::create_dir_all(dir.join("empty")).expect("mkdir");
            entries += 2;
            for f in 0..files {
                std::fs::write(dir.join(format!("f{f}.txt")), [b'x'; 7]).expect("write");
                entries += 1;
            }
        }
        (root, entries)
    }

    fn stats_of(masks: &[String], opts: &Options) -> (usize, usize) {
        STATS.with(|count| count.set(0));
        let found = collect(masks, opts);
        (STATS.with(std::cell::Cell::get), found.files.len())
    }

    fn text(path: &Path) -> String {
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn a_named_directory_is_walked_with_one_stat_an_entry() {
        let (root, entries) = tree("named", 5, 7);
        let (stats, chosen) = stats_of(&[text(&root)], &Options::default());
        std::fs::remove_dir_all(&root).expect("clean up");
        // Every entry below, and the root the mask names.
        assert_eq!(chosen, entries + 1);
        assert_eq!(stats, entries + 1);
    }

    #[test]
    fn a_recursive_wildcard_stats_each_entry_once() {
        let (root, entries) = tree("wild", 4, 6);
        let opts = Options {
            recurse: Recurse::On,
            ..Options::default()
        };
        let (stats, chosen) = stats_of(&[text(&root.join("*.txt"))], &opts);
        std::fs::remove_dir_all(&root).expect("clean up");
        assert_eq!(chosen, 4 * 6);
        // The wildcard reads every entry below the root, directories and
        // files alike, and asks each one question.
        assert_eq!(stats, entries);
    }

    #[cfg(unix)]
    #[test]
    fn a_link_to_a_directory_is_still_walked_as_one() {
        let (root, entries) = tree("link", 2, 3);
        let target = root.join("d0");
        std::os::unix::fs::symlink(&target, root.join("via")).expect("symlink");
        let (stats, chosen) = stats_of(&[text(&root)], &Options::default());
        std::fs::remove_dir_all(&root).expect("clean up");
        // `via` is walked through: its own entry and d0's four again.
        assert_eq!(chosen, entries + 1 + 1 + 4);
        assert_eq!(stats, chosen);
    }
}
