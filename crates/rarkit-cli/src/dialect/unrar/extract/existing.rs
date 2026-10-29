//! A member whose path is already taken: the question, its answers and
//! the standing one.

use super::*;

impl Run<'_> {
    /// Records which of the paths this run could create already exist, for
    /// [`Run::logically_exists`]. Taken ONCE, before the first pass: a
    /// directory a worker made during a pass that then failed was never
    /// announced, and the restarted walk must still announce it.
    pub(super) fn snapshot_preexisting(&mut self) {
        let mut seen: HashSet<PathBuf> = HashSet::new();
        let trimmed = dest_base(&self.dest);
        if !trimmed.is_empty() {
            seen.insert(PathBuf::from(trimmed));
        }
        // Borrowed, not cloned: this body reads `self` and writes only
        // the local `seen`, so there is no borrow conflict to dodge here
        // and the clone it replaces bought nothing.
        for &index in self.selected.iter() {
            let Some(target) = self.member_target(index) else {
                continue;
            };
            if self.plan[index].member.is_dir {
                seen.insert(target.to_path_buf());
            }
            let mut cursor = target.parent();
            while let Some(dir) = cursor {
                // Probed borrowed first: a directory most members share is
                // already in the set, and its owned key is made only once.
                if dir.as_os_str().is_empty() || seen.contains(dir) {
                    break;
                }
                seen.insert(dir.to_path_buf());
                cursor = dir.parent();
            }
        }
        // A REAL directory, never a link to one: a component that is a link
        // is replaced before anything is created under it (spec F 3.8.3).
        // The destination itself is the caller's to name, link or not.
        //
        // Judged FROM THE DESTINATION OUTWARD: a path is there only if the
        // directory above it is, so nothing below a link is recorded. The
        // system follows every component but the last, and asking each
        // path on its own took `out/link/sub` for a real directory where
        // `out/link` led outside the destination; nothing replaced the
        // link and a member was written through it (10 Oct 2026). A
        // directory is always shorter than what is in it, so the shortest
        // paths are judged first; and a path below one that is not there
        // costs no call at all.
        let mut seen: Vec<PathBuf> = seen.into_iter().collect();
        seen.sort_unstable_by_key(|path| path.as_os_str().len());
        let mut there: HashSet<PathBuf> = HashSet::with_capacity(seen.len());
        for path in seen {
            let real = if path.as_os_str() == trimmed {
                path.exists()
            } else {
                // Every path here but the destination is below it, and
                // its parent is the destination, nothing (no destination
                // was named) or another path of this set.
                path.parent()
                    .is_some_and(|above| above.as_os_str().is_empty() || there.contains(above))
                    && links::is_real_dir(&path)
            };
            if real {
                there.insert(path);
            }
        }
        self.dirs.set_before(there);
    }

    /// Whether a file already there is written over WITHOUT a question:
    /// `-o+`, or the default rule answered for good by `-y` or by `A`.
    pub(super) fn may_overwrite(&self) -> bool {
        match self.opts.overwrite {
            Overwrite::Always => true,
            Overwrite::Never | Overwrite::Rename => false,
            Overwrite::Ask => self.opts.assume_yes || self.asked == Asked::All,
        }
    }

    /// Whether a file already there is kept without a word: `-o-`, or the
    /// default rule once `E` has answered for the rest.
    pub(super) fn keeps_silently(&self) -> bool {
        match self.opts.overwrite {
            Overwrite::Never => true,
            Overwrite::Ask => !self.opts.assume_yes && self.asked == Asked::Never,
            Overwrite::Always | Overwrite::Rename => false,
        }
    }

    /// Whether a file already there is asked about: the default rule (`-o`
    /// or no switch), until `-y`, `A` or `E` has answered for the rest.
    pub(super) fn asks(&self) -> bool {
        self.opts.overwrite == Overwrite::Ask && !self.opts.assume_yes && self.asked == Asked::Each
    }

    /// Whether any selected member's path is taken as the run starts: one
    /// `lstat` a member, up to the first found, and none where the
    /// destination itself is not there. Directories are not asked about.
    pub(super) fn any_target_taken(&self) -> bool {
        let trimmed = dest_base(&self.dest);
        if !trimmed.is_empty() && !self.dirs.was_there(Path::new(trimmed)) {
            return false;
        }
        self.selected.iter().any(|&index| {
            !self.plan[index].member.is_dir
                && self
                    .member_target(index)
                    .is_some_and(|target| fs::symlink_metadata(target).is_ok())
        })
    }

    /// One line of the caller's answer from standard input, without its
    /// line end; `None` once the run is stopped for want of one.
    ///
    /// MEASURED against unrar 7.23 (macOS and x86-64 Linux, 2 Oct 2026): an
    /// input that ends (an empty pipe, the null device, a closed
    /// descriptor, or after earlier answers) is `Read error in the file
    /// stdin`, `Program aborted`, exit 12. On one stream (`-ierr`) the
    /// line the answer was typed on is ended after the read.
    pub(super) fn read_answer(&mut self) -> Option<Vec<u8>> {
        use std::io::BufRead;
        let mut line = Vec::new();
        let got = std::io::stdin().lock().read_until(b'\n', &mut line);
        if self.streams.one_stream() {
            self.streams.warn("\n");
        }
        match got {
            Ok(0) => {
                self.stopped = Some(Stopped::NoAnswer(None));
                None
            }
            Err(err) => {
                self.stopped = Some(Stopped::NoAnswer(Some(super::io_reason(&err))));
                None
            }
            Ok(_) => {
                while matches!(line.last(), Some(b'\n' | b'\r')) {
                    line.pop();
                }
                Some(line)
            }
        }
    }

    /// The reference's question about the file at `path`, which is already
    /// there, asked on stderr and answered on standard input; `shown` is
    /// the path as a progress line would print it, and `rename` whether
    /// `[R]ename` is offered (a file; not a link or a copy).
    ///
    /// MEASURED against unrar 7.23 on macOS and x86-64 Linux, 2 Oct 2026,
    /// plain `x` and
    /// `x -o` with the answers on a pipe:
    ///
    /// - the text is `\nWould you like to replace the existing file
    ///   <path>\n<size> bytes, modified on <time>\nwith a new
    ///   one\n<size> bytes, modified on <time>\n\n` and the choices,
    ///   unended; apart from the messages it opens with one more newline,
    ///   as every complaint does. `-idq` keeps it, `-inul` silences it
    ///   and the answer is still read;
    /// - the answer is the line's first letter, in either case (`All`
    ///   reads as `A`): `Y` this file, `N` not this file, `A` this and
    ///   every later one, `E` none from here on, `R` a new path read
    ///   after `Enter new name: ` on stdout (asked about again if that is
    ///   taken too), `Q` stops: `Program aborted`, exit 255. Anything
    ///   else, an empty line included, prints the choices again;
    /// - before this (and since the first rarfast) the default rule kept
    ///   every file there, read no answer, and closed with `All OK`.
    ///
    /// `-or` asks nothing: the member is written under the first free
    /// `name(N).ext`, N from 1, the number put before the last dot of the
    /// name's last component and at its end where it has none (unrar 7.23,
    /// 2 Oct 2026: `a.tar(1).gz`, `noext(1)`, `(1).hidden`, `x(2).txt`
    /// beside an `x(1).txt` that was there; links and copies alike).
    pub(super) fn settle_existing(
        &mut self,
        index: usize,
        path: &Path,
        shown: &str,
        rename: bool,
    ) -> Standing {
        if self.opts.overwrite == Overwrite::Rename {
            let free = (1u32..)
                .map(|n| (numbered_path(path, n), n))
                .find(|(candidate, _)| fs::symlink_metadata(candidate).is_err());
            return match free {
                Some((path, n)) => Standing::Renamed(path, numbered(shown, n)),
                None => Standing::Keep,
            };
        }
        if !self.asks() {
            return Standing::Keep;
        }
        let member = &self.plan[index].member;
        let found = fs::metadata(path).ok();
        let there = found.as_ref().map_or(0, fs::Metadata::len);
        let since = found
            .and_then(|meta| meta.modified().ok())
            .and_then(|at| at.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| super::time::short(i64::try_from(d.as_secs()).unwrap_or(i64::MAX), false));
        let blank = || " ".repeat(16);
        let stored = member
            .mtime
            .map(|seconds| super::time::short(seconds, member.wall_clock));
        let choices = if rename { CHOICES } else { CHOICES_LINK };
        let apart = if self.streams.one_stream() { "" } else { "\n" };
        // Straight to the stream, never into a member's slot: the caller
        // is waiting to answer it.
        self.streams.warn(&format!(
            "{apart}\nWould you like to replace the existing file {shown}\n{there:>6} bytes, \
             modified on {}\nwith a new one\n{:>6} bytes, modified on {}\n\n{choices}",
            since.unwrap_or_else(blank),
            member.size,
            stored.unwrap_or_else(blank),
        ));
        loop {
            let Some(answer) = self.read_answer() else {
                return Standing::Stop;
            };
            match answer.first().map(u8::to_ascii_uppercase) {
                Some(b'Y') => return Standing::Replace,
                Some(b'N') => return Standing::Keep,
                Some(b'A') => {
                    self.asked = Asked::All;
                    return Standing::Replace;
                }
                Some(b'E') => {
                    self.asked = Asked::Never;
                    return Standing::Keep;
                }
                Some(b'Q') => {
                    self.stopped = Some(Stopped::Quit);
                    return Standing::Stop;
                }
                Some(b'R') if rename => {
                    // With the names hidden (`-idn`) it opens a line of
                    // its own and the counters run on after it; shown, the
                    // typed line is ended on stdout, which on one stream
                    // the read has done already.
                    let hidden = self.opts.hide_names;
                    self.streams.say(if hidden {
                        "\nEnter new name: "
                    } else {
                        "Enter new name: "
                    });
                    self.streams.release();
                    let name = self.read_answer();
                    if !hidden && !self.streams.one_stream() {
                        self.streams.say("\n");
                    }
                    return match name {
                        Some(name) => {
                            // A bare name goes beside the file it stands in
                            // for (`d/renamed.bin`); a path is read as
                            // typed, from the current directory.
                            let typed = String::from_utf8_lossy(&name).into_owned();
                            let (path, shown) = if typed.contains(std::path::is_separator) {
                                (
                                    PathBuf::from(&typed),
                                    super::progress_line_name(typed.as_bytes()),
                                )
                            } else {
                                let beside = shown
                                    .rfind(std::path::is_separator)
                                    .map_or("", |at| &shown[..=at]);
                                (
                                    path.with_file_name(&typed),
                                    format!(
                                        "{beside}{}",
                                        super::progress_line_name(typed.as_bytes())
                                    ),
                                )
                            };
                            Standing::Renamed(path, shown)
                        }
                        None => Standing::Stop,
                    };
                }
                _ => self.streams.warn(&format!("{apart}{choices}")),
            }
        }
    }

    /// A SOLID archive's line for a file it does not write, kept or not
    /// created: `Skipping    <name>`, the archived name, the member's
    /// counter and five spaces where the `OK` would go, because the member
    /// is still decoded for the ones after it (unrar 7.23, 2 Oct 2026:
    /// `x -o-`, `x` answered `N`, and `x -o+` over files that may not be
    /// written, over a solid RAR 5 archive; outside a solid archive such a
    /// member has no line). It is not counted as processed.
    pub(super) fn say_skipping(&mut self, index: usize, volume: usize, data_end: u64) {
        if !self.volumes.iter().any(|v| v.solid) || !self.streams.says() {
            return;
        }
        let name = self.plan[index].member.name.to_string();
        self.open_progress("Skipping", &name, volume, data_end);
        // The five backspaces are there with or without the counter
        // (`-idp`), as measured.
        let end = if self.opts.hide_names { "" } else { "\n" };
        self.say(&format!("\x08\x08\x08\x08\x08     {end}"));
        self.last_failed = false;
    }
}

/// `name` with `(n)` before the last dot of its last component, or at its
/// end where that component has no dot: `-or`'s new name for a member whose
/// own is taken ([`Run::settle_existing`]).
pub(super) fn numbered(name: &str, n: u32) -> String {
    let last = name.rfind(std::path::is_separator).map_or(0, |at| at + 1);
    let at = name[last..].rfind('.').map_or(name.len(), |dot| last + dot);
    format!("{}({n}){}", &name[..at], &name[at..])
}

/// [`numbered`] for a path: its last component renamed, the rest as it is.
pub(super) fn numbered_path(path: &Path, n: u32) -> PathBuf {
    let name = path.file_name().unwrap_or_default();
    #[cfg(unix)]
    let renamed = {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};
        let bytes = name.as_bytes();
        let at = bytes
            .iter()
            .rposition(|&b| b == b'.')
            .unwrap_or(bytes.len());
        let mut out = bytes[..at].to_vec();
        out.extend_from_slice(format!("({n})").as_bytes());
        out.extend_from_slice(&bytes[at..]);
        std::ffi::OsString::from_vec(out)
    };
    #[cfg(not(unix))]
    let renamed = std::ffi::OsString::from(numbered(&name.to_string_lossy(), n));
    path.with_file_name(renamed)
}

/// The standing answer to the question about a file already there: each
/// is asked about, until `A` (all are replaced) or `E` (none is).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Asked {
    Each,
    All,
    Never,
}

/// Why a run stopped at the question: `Q`, or an answer that could not be
/// read (the input ended, or the read failed with this reason).
pub(super) enum Stopped {
    Quit,
    NoAnswer(Option<String>),
}

/// What is done with a member whose path is already taken.
pub(super) enum Standing {
    /// Written over what is there.
    Replace,
    /// Left as it is, silently, and not counted as extracted.
    Keep,
    /// Written under this path, shown as this name: the one typed at
    /// `Enter new name:`, or `-or`'s numbered one.
    Renamed(PathBuf, String),
    /// Nothing more is opened ([`Run::stopped`]).
    Stop,
}

/// The run was stopped at the question about a file already there: what
/// the sequential sink's `open` returns, so that the engine opens no
/// member after it. [`Run::finish`] says why; this text is never printed.
#[derive(Debug)]
pub(super) struct StoppedAtQuestion;

impl std::fmt::Display for StoppedAtQuestion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("stopped at the question about a file already there")
    }
}

impl std::error::Error for StoppedAtQuestion {}

/// The reason line of `Read error in the file stdin` where the input simply
/// ended: see [`Run::finish_stopped`].
#[cfg(not(windows))]
pub(super) const END_OF_ANSWERS: &str = "Inappropriate ioctl for device";

/// Windows: UnRAR 7.23 x64 says the pipe's own end there (os error 109),
/// and nothing for the null device; this says it for both.
#[cfg(windows)]
pub(super) const END_OF_ANSWERS: &str = "The pipe has been ended.";

/// The question's choices, as the reference prints them: a link or a copy
/// is not offered `[R]ename`.
pub(super) const CHOICES: &str = "[Y]es, [N]o, [A]ll, n[E]ver, [R]ename, [Q]uit ";

pub(super) const CHOICES_LINK: &str = "[Y]es, [N]o, [A]ll, n[E]ver, [Q]uit ";
