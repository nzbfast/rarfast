//! Redirection members on `x`, `e` and `t`: symbolic links, hard links and
//! file copies (spec F 3.8, which is normative for this dialect).
//!
//! The engine never hands such a member over as bytes. Its `open` carries
//! the target, the sink answers `Verify`, and the link, hard link or copy is
//! made HERE at the member's `close`, when the engine's verdict is in and
//! every earlier member has closed: closes arrive in archive order on both
//! walks, and a hard link or a copy only ever names an earlier member.
//!
//! What this module owes, each against the reference unrar 7.23 it was
//! measured on (27 Sep 2026, x86-64 Linux):
//!
//! - a symbolic link is created with its target verbatim and never
//!   followed; an UNSAFE one (absolute, a `..` anywhere but a leading run,
//!   or a leading run longer than the output path's own depth) is skipped
//!   with the reference's own words and counted, unless `-ola`; `-ol-`
//!   skips every one silently (3.8.2);
//! - nothing is ever created THROUGH a link: a directory component that is
//!   a link is replaced by a real directory first, `-ola` or not (3.8.3,
//!   question 14 (a)); that half lives in the parent's creation code;
//! - a hard link or a copy is made only from the file THIS run wrote for
//!   an earlier member, never from whatever sits at its path (3.8.4, 3.8.5,
//!   question 14 (b));
//! - a copy whose target this run will not write to its own path (not
//!   selected, or kept by `-o-`) is filled by decoding the target straight
//!   into the copy's output (question 14 (c));
//! - a kind this program cannot make, or does not know, is refused loudly,
//!   by name, and counted (3.8.6).

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use rarkit::{Disposition, Redirection, RedirectionKind};

use super::{
    mode, pad_to, Failure, Mark, Mode, Run, Standing, TimedFile, FILE_NAME_COLUMN, VERB_WIDTH,
};
use crate::dialect::unrar::args::Links;
use crate::dialect::unrar::{disk_name, progress_line_name, text_from_archive, HostOs};

/// What a run holds for its redirection members.
#[derive(Default)]
pub(super) struct State {
    /// Members whose `open` answered `Verify`, waiting for their `close`.
    pending: super::ByIndex<Pending>,
    /// Plan indices by ON-DISK name ([`super::super::Member::disk_name`]),
    /// for a hard link's or a copy's target ([`target_name`]). Built only
    /// when the archive holds one of those.
    by_name: HashMap<Vec<u8>, Vec<usize>>,
    /// Each copy target, and the selected copies that name it in archive
    /// order (`x` and `e` only).
    copies_of: super::ByIndex<Vec<usize>>,
    /// A target being decoded into a copy's output, and that copy.
    feeding: super::ByIndex<usize>,
    /// A copy a target was decoded into, and the target's verdict once it
    /// has closed.
    fed: super::ByIndex<Option<bool>>,
    /// A member `-o-` kept as it was on disk, which a copy may need fed.
    kept: Option<usize>,
}

/// One redirection member between its `open` and its `close`.
struct Pending {
    kind: RedirectionKind,
    target: Vec<u8>,
    dir: bool,
    /// The engine will refuse the record (spec F 3.8.1): its `close` is a
    /// refusal, not a checksum failure.
    fault: bool,
    /// The RAR 4 family's link, whose target is its content (3.3.12).
    in_content: bool,
}

/// An archived name in the form a hard link's or a copy's target spells it:
/// forward slashes, as RAR 5 stores names (3.2.6.2).
fn slashed(name: &str) -> String {
    if cfg!(windows) {
        name.replace('\\', "/")
    } else {
        name.to_owned()
    }
}

/// The on-disk name a hard link's or a copy's stored target names: cut as
/// a RAR 5 member's own name is cut ([`disk_name`]: at a NUL, at the first
/// byte that is not UTF-8), and every `\` read as a separator.
///
/// MEASURED against unrar 7.23 on macOS (an M3 Mac) and Linux
/// (a small x86-64 VPS), 28 Sep 2026, whose target reaches the file it names
/// through its own name conversion: a target `a\xffb` or `a\xfec` links to
/// the file written for `a\xffb` (which is `a`); `tab<TAB>there` to that
/// file; and `bs\x` to `bs/x`, never to a Unix member `bs\x`, whether the
/// link was written on Unix or Windows, and refused where there is no
/// `bs/x`. A `..` read this way is refused by [`Run::earlier_member`].
fn target_name(target: &[u8]) -> Vec<u8> {
    disk_name(target, HostOs::Unix, true)
        .iter()
        .map(|&b| if b == b'\\' { b'/' } else { b })
        .collect()
}

/// Whether a symbolic link's target is SAFE to create at an output path
/// with `depth` directory components (spec F 3.8.2, and 3.8.7 for the
/// Windows forms, judged as stored), on the host this program runs on.
pub(super) fn link_is_safe(kind: RedirectionKind, target: &[u8], depth: usize) -> bool {
    link_is_safe_on(cfg!(windows), kind, target, depth)
}

/// [`link_is_safe`] for a stated host, so that the Windows reading is
/// tested on every host.
///
/// A target is judged in the form the HOST is given. A Windows host is
/// handed every `/` as `\` and every `\` as it stands (`make_symlink`),
/// and reads both as separators and a drive letter as a root, whatever
/// kind the record says it is: a Unix link stored as `..\..\x` or
/// `C:\x` is one name to a Unix host and a way out of the destination to
/// a Windows one.
fn link_is_safe_on(host_windows: bool, kind: RedirectionKind, target: &[u8], depth: usize) -> bool {
    let windows = host_windows
        || matches!(
            kind,
            RedirectionKind::NtSymlink | RedirectionKind::NtJunction
        );
    let separator = |b: u8| b == b'/' || (windows && b == b'\\');
    // Absolute: a leading separator (which covers `\\` and `\??\`), or,
    // for the Windows forms and on a Windows host, a drive letter and a
    // colon.
    if target.first().is_some_and(|&b| separator(b)) {
        return false;
    }
    if windows && target.len() >= 2 && target[0].is_ascii_alphabetic() && target[1] == b':' {
        return false;
    }
    let mut climbs = 0usize;
    let mut descended = false;
    for part in target.split(|&b| separator(b)) {
        match part {
            b"" | b"." => {}
            b".." if descended => return false,
            b".." => climbs += 1,
            _ => descended = true,
        }
    }
    climbs <= depth
}

/// The link content a host is given for a stored target (spec F 3.8.7).
#[cfg(not(windows))]
fn host_form(kind: RedirectionKind, target: &[u8]) -> Vec<u8> {
    let target = match kind {
        // The genuine Windows writer stores `/??/C:/...` with forward
        // slashes (MEASURED, Rar.exe 7.23 on Windows); a hand-rewritten
        // record may carry the `\??\` form. Either prefix goes.
        RedirectionKind::NtJunction => target
            .strip_prefix(b"\\??\\")
            .or_else(|| target.strip_prefix(b"/??/"))
            .unwrap_or(target),
        _ => target,
    };
    match kind {
        RedirectionKind::NtSymlink | RedirectionKind::NtJunction => target
            .iter()
            .map(|&b| if b == b'\\' { b'/' } else { b })
            .collect(),
        _ => target.to_vec(),
    }
}

#[cfg(not(windows))]
fn make_symlink(
    kind: RedirectionKind,
    target: &[u8],
    _dir: bool,
    at: &Path,
) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let content = host_form(kind, target);
    std::os::unix::fs::symlink(std::ffi::OsStr::from_bytes(&content), at)
}

/// Windows: a symbolic link, file or directory by the record's flag; a
/// junction is declined (spec F 3.8.6). What the reference does here, and
/// without the privilege to create links, is not measured yet on a
/// Windows box (question 14).
#[cfg(windows)]
fn make_symlink(kind: RedirectionKind, target: &[u8], dir: bool, at: &Path) -> std::io::Result<()> {
    if kind == RedirectionKind::NtJunction {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "a junction cannot be created on this host",
        ));
    }
    let content = String::from_utf8_lossy(target).replace('/', "\\");
    if dir {
        std::os::windows::fs::symlink_dir(content, at)
    } else {
        std::os::windows::fs::symlink_file(content, at)
    }
}

/// Whether `path` is a directory itself, and not a link to one. Its LAST
/// component only: the system follows every component above it, so a
/// caller that must know nothing above is a link asks from the top down
/// ([`Run::snapshot_preexisting`]).
///
/// "Not a link" is asked outright. A Windows directory link or junction
/// carries the directory attribute; the standard library already answers
/// `is_dir` false for one (a file type is a directory, a file or a link,
/// never two), and this does not lean on that.
pub(super) fn is_real_dir(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink())
}

/// Whether `path` is a symbolic link, whatever it points at.
pub(super) fn is_link(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
}

/// Whether `a` and `b` name one file on disk, judged by the file system's
/// identity of it and never by the path text (spec F 3.8.5): device and
/// inode on Unix; elsewhere the paths the file system resolves them to,
/// which settles case and links. Either missing is not the same.
fn same_file(a: &Path, b: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        match (fs::metadata(a), fs::metadata(b)) {
            (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
            _ => false,
        }
    }
    #[cfg(not(unix))]
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Removes a link at `path`: the link, never what it points at.
pub(super) fn unlink(path: &Path) {
    if fs::remove_file(path).is_err() {
        // A Windows directory link is removed as a directory.
        let _ = fs::remove_dir(path);
    }
}

/// Makes `dir` a real directory, replacing a link that stands in its place
/// (spec F 3.8.3). Best effort, as `create_dir` was: the caller asks
/// [`is_real_dir`] whether it worked.
pub(super) fn real_dir(dir: &Path) {
    if is_link(dir) {
        unlink(dir);
    }
    let _ = fs::create_dir(dir);
}

impl Run<'_> {
    /// Indexes the plan for the hard links and copies it holds. Once per
    /// run, and nothing at all for an archive without them.
    pub(super) fn plan_redirects(&mut self) {
        let named = |kind| matches!(kind, RedirectionKind::HardLink | RedirectionKind::FileCopy);
        if !self
            .plan
            .iter()
            .any(|p| p.member.redirect.as_ref().is_some_and(|r| named(r.kind)))
        {
            return;
        }
        let mut by_name: HashMap<Vec<u8>, Vec<usize>> = HashMap::new();
        for (index, planned) in self.plan.iter().enumerate() {
            if !planned.member.is_dir && !planned.member.is_service {
                by_name
                    .entry(planned.member.disk_name().to_vec())
                    .or_default()
                    .push(index);
            }
        }
        self.links.by_name = by_name;
        if !matches!(self.mode, Mode::Extract { .. }) {
            return;
        }
        for position in 0..self.selected.len() {
            let index = self.selected.at(position);
            let Some(redirect) = &self.plan[index].member.redirect else {
                continue;
            };
            if redirect.kind != RedirectionKind::FileCopy {
                continue;
            }
            let Some(target) = redirect.target.clone() else {
                continue;
            };
            if let Some(source) = self.earlier_member(index, &target) {
                self.links.copies_of.entry(source).or_default().push(index);
            }
        }
    }

    /// The EARLIER member a hard link's or a copy's target names, by its
    /// on-disk name ([`target_name`], spec F 3.8.4): never an absolute
    /// name, never one with a `..` component, never the member itself or
    /// one after it.
    fn earlier_member(&self, index: usize, target: &[u8]) -> Option<usize> {
        let name = target_name(target);
        if name.first() == Some(&b'/') || name.split(|&b| b == b'/').any(|part| part == b"..") {
            return None;
        }
        self.links
            .by_name
            .get(&name)?
            .iter()
            .rev()
            .copied()
            .find(|&earlier| earlier < index)
    }

    /// Whether this run wrote an earlier member's output and kept it.
    fn written_ok(&self, index: usize) -> bool {
        self.wrote.contains(&index) && !self.failures.iter().any(|(i, _)| *i == index)
    }

    /// Decodes a copy's target into the copy's own output, for a target
    /// this run will not write to its own path (spec F 3.8.5, question 14
    /// (c)). `None` when no selected copy is waiting on it, or when the
    /// copy's output may not be written; the copy then settles itself.
    pub(super) fn feed(
        &mut self,
        index: usize,
    ) -> Option<Disposition<Box<dyn std::io::Write + Send>>> {
        let copy = *self.links.copies_of.get(&index)?.iter().find(|&&copy| {
            self.selected.contains(copy)
                && !self.done.contains(copy)
                && !self.links.fed.contains_key(&copy)
        })?;
        let out = self.member_target(copy)?.to_path_buf();
        // Past the Windows cap: the copy is refused at its own turn.
        if Self::too_long(&out).is_some() {
            return None;
        }
        self.ensure_dest();
        // A level still a link: the copy is refused when its own turn
        // comes, by the same walk.
        if !self.ensure_parents(&out) {
            return None;
        }
        if !self.may_overwrite() && fs::symlink_metadata(&out).is_ok() {
            return None;
        }
        // A link at the copy's name is a taken name: replaced when the
        // copy is whole, and not removed before (SPEC-CLI 9.4 W8).
        let policy = if self.may_overwrite() {
            crate::safepath::IfOutputExists::Replace
        } else {
            crate::safepath::IfOutputExists::Keep
        };
        // The copy's OWN mode, from its own header (3.8.5).
        let owner = &self.plan[copy].member;
        let decided = self.file_mode(owner);
        let Ok(Some(crate::safepath::Created {
            file,
            beside,
            in_place,
        })) = crate::safepath::make_member_file(&out, policy, mode::file_create(decided))
        else {
            return None;
        };
        let fresh = beside.is_none() && !in_place;
        let named = beside.as_ref().map(|_| {
            let named = crate::safepath::NameAtClose::new(&out);
            self.naming.insert(copy, named.clone());
            named
        });
        if let Some(beside) = beside {
            self.beside.insert(copy, beside);
        }
        if in_place {
            self.wrote_in_place = true;
        }
        self.note_high_bits(&self.plan[copy].member);
        self.links.feeding.insert(index, copy);
        self.links.fed.insert(copy, None);
        self.wrote.insert(copy);
        Some(Disposition::Write(Box::new(TimedFile {
            file,
            // The copy's OWN time, not its target's (3.8.5).
            mtime: self.mtime_to_set(&self.plan[copy].member),
            mode: mode::file_finish(decided, fresh),
            declared: self.plan[index].member.size,
            written: 0,
            reserved: 0,
            staged: None,
            shut: false,
            named,
            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            behind: crate::writeback::Behind::at_open(false),
        })))
    }

    /// A member the overwrite policy kept as it was, noted while the
    /// target pool is lent out; [`Run::feed_kept`] feeds from it after.
    pub(super) fn note_kept(&mut self, index: usize) {
        self.links.kept = Some(index);
    }

    /// [`Run::feed`] for the member [`Run::note_kept`] noted, if any.
    pub(super) fn feed_kept(&mut self) -> Option<Disposition<Box<dyn std::io::Write + Send>>> {
        let index = self.links.kept.take()?;
        self.feed(index)
    }

    /// A redirection member's progress line, which carries no percentage
    /// (measured: the reference prints none for a link, a hard link, or a
    /// copy under `t`), or the `counter` text given.
    fn open_bare(&mut self, index: usize, verb: &str, name: &str, counter: &str) {
        self.open_lines.insert(index);
        if !self.streams.says() {
            return;
        }
        let names = !self.opts.hide_names;
        let mut text = String::new();
        if !self.opts.hide_percent {
            if names {
                text.push_str(&pad_to(
                    &format!("{verb:VERB_WIDTH$}{name}"),
                    FILE_NAME_COLUMN,
                ));
            }
            text.push_str(counter);
        } else if names {
            text.push_str(&pad_to(
                &format!("{verb:VERB_WIDTH$}{name}"),
                FILE_NAME_COLUMN - 5,
            ));
        }
        self.say(&text);
    }

    /// Ends a line the way the reference ends one whose link or copy it
    /// could not make: five spaces where the `  OK ` would have gone.
    fn close_short(&mut self, index: usize) {
        if self.open_lines.remove(&index) {
            self.last_failed = true;
            self.say("     \n");
        }
    }

    /// Declines a member this program does not make, by name, counted
    /// (spec F 3.8.6).
    fn decline(&mut self, index: usize, verb: &str, shown: &str, reason: &str, failure: Failure) {
        self.open_bare(index, verb, shown, "");
        self.warn(&format!("\n{reason}"));
        self.errors += 1;
        self.failures.push((index, failure));
        self.close_progress(index, false);
        self.done.insert(index);
    }

    /// `open` for a redirection member under `t`, `x` or `e`.
    pub(super) fn begin_redirect(
        &mut self,
        index: usize,
        redirection: Redirection<'_>,
    ) -> Disposition<Box<dyn std::io::Write + Send>> {
        let name = self.plan[index].member.name.to_string();
        let kind = redirection.kind;
        let target = redirection.target.unwrap_or(&[]).to_vec();
        let verb = self.mode.verb();
        // Counted as processed, unless it is kept because its path is
        // taken (below; `Run::touched`).
        let counted = std::mem::replace(&mut self.touched, true);
        let mut shown = match self.mode {
            Mode::Extract { .. } if self.streams.says() => self.member_display_name(index),
            _ => name.clone(),
        };
        if let RedirectionKind::Unknown(code) = kind {
            let reason = format!("{name}: unsupported redirection type {code}");
            self.decline(index, verb, &shown, &reason, Failure::Refused);
            return Disposition::Skip;
        }
        // What the engine will refuse as `Corrupt(Redirection)` (spec F
        // 3.8.1): its `close` says so, and this sink must not read that as
        // a checksum failure.
        let fault = target.is_empty()
            || target.contains(&0)
            || (kind == RedirectionKind::FileCopy
                && slashed(&name).as_bytes() == target.as_slice());
        // The listing has no target for the RAR 4 family's link: its target
        // is its content (3.3.12), and it has a data area, which the
        // reference's line counts.
        let in_content = self.plan[index]
            .member
            .redirect
            .as_ref()
            .is_some_and(|r| r.target.is_none());
        let pending = Pending {
            kind,
            target,
            dir: redirection.target_is_directory,
            fault,
            in_content,
        };
        if self.mode == Mode::Test {
            self.open_bare(index, verb, &shown, "");
            self.links.pending.insert(index, pending);
            return Disposition::Verify;
        }
        let Some(out) = self.member_target(index).map(Path::to_path_buf) else {
            self.refuse_unsafe_name(index);
            return Disposition::Skip;
        };
        let symlink = !matches!(kind, RedirectionKind::HardLink | RedirectionKind::FileCopy);
        if symlink && self.opts.links == Links::Skip {
            // `-ol-`: silently, no line, no count (3.8.2).
            self.done.insert(index);
            return Disposition::Skip;
        }
        // Windows: a path past 4,096 characters is refused by name, as a
        // file's is ([`Run::too_long`]).
        if let Some(err) = Self::too_long(&out) {
            let said = self.member_display_name(index);
            self.refuse_create(index, &out, &said, &err);
            return Disposition::Skip;
        }
        self.ensure_dest();
        if !symlink {
            // A hard link's or a copy's parents are made before its line,
            // as a file's are; a link's after (see `make_link`). A level
            // still a link is never walked (spec F 3.8.3).
            if !self.ensure_parents(&out) {
                self.refuse_through_link(index);
                return Disposition::Skip;
            }
        }
        let fed = self.links.fed.contains_key(&index);
        if !fed && !self.may_overwrite() && fs::symlink_metadata(&out).is_ok() {
            // Kept under `-o-`; asked about under the default rule, as a
            // file is, with no new name on offer.
            let said = self.member_display_name(index);
            match self.settle_existing(index, &out, &said, false) {
                Standing::Replace => {}
                // `-or`: the link or copy is made under the numbered name.
                Standing::Renamed(path, name) => {
                    self.target_at[index] = super::Target::Owned(path);
                    shown = name;
                }
                Standing::Keep | Standing::Stop => {
                    self.touched = counted;
                    self.done.insert(index);
                    return Disposition::Skip;
                }
            }
        }
        if in_content {
            // Measured: `Extracting  o/sym_rel  43%  OK`, the counter of a
            // member with a data area.
            let (volume, data_end) = self.plan[index].fragments[0];
            self.open_progress(verb, &shown, volume, data_end);
            self.open_lines.insert(index);
        } else {
            // A copy made from a file on disk shows the reference's ` 0%`,
            // and one whose target names no earlier member shows none
            // (measured: `bs\x` read as `bs/x` where there is no `bs/x`).
            let counter = if kind == RedirectionKind::FileCopy
                && !fed
                && self.earlier_member(index, &pending.target).is_some()
            {
                "\x08\x08\x08\x08  0%"
            } else {
                ""
            };
            self.open_bare(index, verb, &shown, counter);
        }
        if symlink && !fault && self.opts.links != Links::All {
            // The link's depth under the destination, counted on the
            // separators the HOST splits the on-disk name on, exactly as
            // `target_parts` and `safepath` do: on Unix a `\` is a
            // character of the name, so `a\b\c` is ONE component at depth
            // 0. Counting it as a separator there made that name depth 2
            // and let a target `../../x` out of the destination.
            let depth = {
                let (_, resolved) = self.target_parts(index);
                resolved
                    .split(|&b| b == b'/' || (cfg!(windows) && b == b'\\'))
                    .filter(|part| !part.is_empty() && *part != b".")
                    .count()
                    .saturating_sub(1)
            };
            if !link_is_safe(kind, &pending.target, depth) {
                self.warn(&format!(
                    "\nSkipping the potentially unsafe {name} -> {} link. For archives from a \
                     trustworthy source use -ola to extract it anyway.",
                    text_from_archive(&pending.target)
                ));
                self.errors += 1;
                self.failures.push((index, Failure::UnsafeLink));
                self.close_progress(index, false);
                self.done.insert(index);
                return Disposition::Skip;
            }
        }
        self.links.pending.insert(index, pending);
        Disposition::Verify
    }

    /// The member closing as `index` is whole and verified, and its file
    /// is still open: a file written beside a taken name may take the
    /// name as it closes (`safepath::NameAtClose`). A copy fed from this
    /// member's decode is the file that is open, and is armed in its
    /// place.
    pub(super) fn arm_name(&self, index: usize) {
        let written = self.links.feeding.get(&index).copied().unwrap_or(index);
        if let Some(named) = self.naming.get(&written) {
            named.arm();
        }
    }

    /// `close` for a member this module opened or fed. `false` when the
    /// member is none of its business.
    pub(super) fn close_redirect(&mut self, index: usize, outcome: &rarkit::MemberOutcome) -> bool {
        if let Some(copy) = self.links.feeding.remove(&index) {
            // A copy written beside a taken name takes the name now that
            // its bytes are whole, or broken under `-kb`; otherwise it is
            // removed and what stood at the name stays (SPEC-CLI 9.4 W7).
            let sound = outcome.checksum_ok != Some(false);
            let named = if sound || self.opts.keep_broken {
                self.take_name(copy).is_ok()
            } else {
                self.drop_beside(copy);
                false
            };
            let whole = sound && named;
            self.links.fed.insert(copy, Some(whole));
            return true;
        }
        let Some(pending) = self.links.pending.remove(&index) else {
            return false;
        };
        if pending.fault {
            self.refuse_member(index);
            return true;
        }
        if outcome.checksum_ok == Some(false) {
            self.record_failure(index);
            return true;
        }
        // Not failed: `OK`, or the question mark where the record's own
        // header names no checksum ([`Mark`]).
        let mark = Mark::of(outcome);
        match self.mode {
            Mode::Extract { .. } => self.make(index, &pending, mark),
            _ => self.test_redirect(index, &pending, mark),
        }
        true
    }

    /// `t`: the record checked out. A hard link or a copy whose target is
    /// not an earlier member could not be extracted, so it is reported as
    /// `x` would report it (spec F 3.8.8); nothing is read from disk.
    fn test_redirect(&mut self, index: usize, pending: &Pending, mark: Mark) {
        let named = matches!(
            pending.kind,
            RedirectionKind::HardLink | RedirectionKind::FileCopy
        );
        if named && self.earlier_member(index, &pending.target).is_none() {
            let name = self.plan[index].member.name.to_string();
            self.warn(&format!(
                "\n{name}: {} is not an earlier member of the archive",
                text_from_archive(&pending.target)
            ));
            self.errors += 1;
            self.failures.push((index, Failure::Refused));
            self.close_progress(index, false);
            self.done.insert(index);
            return;
        }
        if pending.in_content {
            // Measured, and odd: `t` ends a RAR 4 family link's line with
            // no `OK` at all, and the run is still "All OK".
            if self.open_lines.remove(&index) && !self.opts.hide_names {
                self.say("\n");
            }
        } else {
            self.finish_marked(index, mark);
        }
        self.done.insert(index);
    }

    /// `x` and `e`: make the link, hard link or copy.
    fn make(&mut self, index: usize, pending: &Pending, mark: Mark) {
        let Some(out) = self.member_target(index).map(Path::to_path_buf) else {
            return;
        };
        let made = match pending.kind {
            RedirectionKind::HardLink => self.make_hard_link(index, pending, &out),
            RedirectionKind::FileCopy => self.make_copy(index, pending, &out),
            _ => self.make_link(index, pending, &out),
        };
        if made {
            self.wrote.insert(index);
            self.finish_marked(index, mark);
            self.done.insert(index);
        }
    }

    /// Creates a symbolic link, its missing parents first, announced the
    /// way the reference announces them: after the link's own line, which
    /// its `OK` then closes on the last `Creating` line.
    fn make_link(&mut self, index: usize, pending: &Pending, out: &Path) -> bool {
        if !self.link_parents(out) {
            self.close_progress(index, false);
            self.refuse_through_link(index);
            return false;
        }
        match fs::symlink_metadata(out) {
            // A later member made this path a directory already (the
            // concurrent walk opens members ahead of this close), which is
            // what the reference ends with too: the link replaced by a real
            // directory (3.8.3).
            Ok(meta) if meta.is_dir() && self.dirs.made(out) => return true,
            Ok(meta) if meta.is_dir() => {}
            // Allowed to go at `open`, which checked the overwrite policy.
            Ok(_) => unlink(out),
            Err(_) => {}
        }
        match make_symlink(pending.kind, &pending.target, pending.dir, out) {
            Ok(()) => true,
            Err(err) => {
                if cfg!(windows) {
                    // MEASURED on UnRAR 7.23 for Windows without the
                    // privilege to create links: these three lines, exit
                    // 9, nothing created in the link's place.
                    let shown = self.member_display_name(index);
                    self.warn(&format!(
                        "\nCannot create symbolic link {shown}\nYou may need to run RAR as \
                         administrator\n{}",
                        crate::dialect::unrar::io_reason(&err)
                    ));
                    self.errors += 1;
                    self.failures.push((index, Failure::Create));
                    self.close_progress(index, false);
                    self.done.insert(index);
                } else {
                    let name = self.plan[index].member.name.to_string();
                    self.cannot_create(index, &name, &err);
                }
                false
            }
        }
    }

    /// The missing parents of a link's output path, made real directories
    /// and announced after its line (measured: `Extracting  o/d/up_in`,
    /// then `Creating    o/d  OK` carrying the link's own `OK`). `false`,
    /// as [`Run::ensure_parents`], where a level is still a link.
    fn link_parents(&mut self, out: &Path) -> bool {
        let mut stack = Vec::new();
        let mut cursor = out.parent();
        while let Some(dir) = cursor {
            if dir.as_os_str().is_empty() || self.logically_exists(dir) {
                break;
            }
            stack.push(dir.to_path_buf());
            cursor = dir.parent();
        }
        if stack.is_empty() {
            return true;
        }
        let base = PathBuf::from(super::dest_base(&self.dest));
        let mut lines = Vec::new();
        let mut walked = true;
        for dir in stack.into_iter().rev() {
            real_dir(&dir);
            if is_link(&dir) {
                walked = false;
                break;
            }
            if is_real_dir(&dir) && self.dirs.make(dir.clone()) {
                let shown = match dir.strip_prefix(&base) {
                    Ok(relative) if !base.as_os_str().is_empty() => {
                        format!("{}{}", self.dest, relative.to_string_lossy())
                    }
                    _ => dir.to_string_lossy().into_owned(),
                };
                lines.push(format!(
                    "{}OK",
                    pad_to(
                        &format!("{:VERB_WIDTH$}{shown}", "Creating"),
                        super::DIR_NAME_COLUMN
                    )
                ));
            }
        }
        if !lines.is_empty() && !self.opts.hide_names {
            self.say(&format!("\n{}", lines.join("\n")));
        }
        walked
    }

    /// A hard link to the file this run wrote for its target (3.8.4).
    fn make_hard_link(&mut self, index: usize, pending: &Pending, out: &Path) -> bool {
        let source = self
            .earlier_member(index, &pending.target)
            .filter(|&t| self.written_ok(t))
            .and_then(|t| self.member_target(t).map(Path::to_path_buf));
        let shown = self.member_display_name(index);
        let Some(source) = source else {
            self.warn(&format!(
                "\nCannot create hard link {shown}\nYou need to unpack the link target first"
            ));
            self.errors += 1;
            self.failures.push((index, Failure::Create));
            self.close_short(index);
            self.done.insert(index);
            return false;
        };
        if fs::symlink_metadata(out).is_ok_and(|m| !m.is_dir()) {
            unlink(out);
        }
        match fs::hard_link(&source, out) {
            Ok(()) => true,
            Err(err) => {
                self.warn(&format!(
                    "\nCannot create hard link {shown}\n{}",
                    crate::dialect::unrar::io_reason(&err)
                ));
                self.errors += 1;
                self.failures.push((index, Failure::Create));
                self.close_short(index);
                self.done.insert(index);
                false
            }
        }
    }

    /// A copy of the bytes this run decoded for its target (3.8.5).
    fn make_copy(&mut self, index: usize, pending: &Pending, out: &Path) -> bool {
        match self.links.fed.remove(&index) {
            Some(Some(true)) => return true,
            // The target it was decoded from failed, so the copy fails
            // with it and is never reported OK.
            Some(_) => {
                self.record_failure(index);
                return false;
            }
            None => {}
        }
        let source = self.earlier_member(index, &pending.target);
        // The target's own output, or, where this run did not write it,
        // an earlier copy of it this run made: the first copy was fed from
        // the target's decode, and every later one is made from that.
        let written = source.and_then(|t| {
            if self.written_ok(t) {
                return Some(t);
            }
            self.links
                .copies_of
                .get(&t)?
                .iter()
                .copied()
                .find(|&copy| copy < index && self.written_ok(copy))
        });
        let from = written.and_then(|t| self.member_target(t).map(Path::to_path_buf));
        let Some(from) = from else {
            let shown = self.member_display_name(index);
            let named = match source {
                Some(t) => self.member_display_name(t),
                // The path the reference tried: `o/bs/x` for `bs\x`.
                None => format!(
                    "{}{}",
                    self.dest,
                    progress_line_name(&target_name(&pending.target))
                ),
            };
            self.warn(&format!(
                "\nCannot open {named}\nNo such file or directory\nCannot copy {named} to \
                 {shown}.\nYou need to unpack the entire archive to create file reference entries."
            ));
            self.errors += 1;
            self.failures.push((index, Failure::CopySource));
            self.close_short(index);
            self.done.insert(index);
            return false;
        };
        if is_link(out) {
            unlink(out);
        }
        // The copy lands on its own source (`e` flattening `d/big1` onto
        // `big1`, or two names of one file on a case-insensitive volume):
        // the bytes there ARE the target's, so nothing is copied, and a
        // copy reading and writing one file would leave it empty.
        let copied = if same_file(&from, out) {
            Ok(())
        } else {
            // Whatever else stands at the name goes first, as for a hard
            // link member: `fs::copy` writes INTO a file it finds there, and
            // until 27 Oct 2026 a file with another name (a hard link) took
            // the copy's bytes and mode under that name too, outside the
            // destination as well. The overwrite policy was settled at the
            // member's open.
            if fs::symlink_metadata(out).is_ok_and(|m| !m.is_dir()) {
                unlink(out);
            }
            fs::copy(&from, out).map(drop)
        };
        match copied {
            Ok(()) => {
                // The copy's OWN mode and time, from its own header (3.8.5):
                // `fs::copy` gave it the target's permissions.
                let owner = &self.plan[index].member;
                let decided = self.file_mode(owner);
                self.note_high_bits(owner);
                if let Ok(file) = fs::OpenOptions::new().write(true).open(out) {
                    if let Some(mode) = mode::file_finish(decided, true) {
                        mode::set_on(&file, mode);
                    }
                    if let Some(mtime) = self.mtime_to_set(owner) {
                        let _ = file.set_modified(mtime);
                    }
                }
                true
            }
            Err(err) => {
                let name = self.plan[index].member.name.to_string();
                self.cannot_create(index, &name, &err);
                false
            }
        }
    }

    /// A create error for one member: named, counted, exit 9 (3.8.7).
    fn cannot_create(&mut self, index: usize, name: &str, err: &std::io::Error) {
        self.errors += 1;
        self.failures.push((index, Failure::Create));
        self.close_progress(index, false);
        self.complain(
            name,
            &format!("- cannot create: {}", crate::dialect::unrar::io_reason(err)),
        );
        self.done.insert(index);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec F 3.8.2's table, row by row, at the depths it gives.
    #[test]
    fn the_safety_rule_matches_the_measured_table() {
        let unix = RedirectionKind::PosixSymlink;
        for (target, depth, safe) in [
            ("a.txt", 0, true),
            ("/etc/hostname", 0, false),
            ("../../escape", 0, false),
            ("..", 0, false),
            ("../top.txt", 1, true),
            ("../../top.txt", 2, true),
            ("../../top.txt", 1, false),
            ("d/../top.txt", 0, false),
            ("d/e/../../../x", 3, false),
            ("./top.txt", 0, true),
            // A backslash is an ordinary byte in a Unix target.
            ("d\\f.txt", 0, true),
        ] {
            assert_eq!(
                link_is_safe(unix, target.as_bytes(), depth),
                safe,
                "{target} at depth {depth}"
            );
        }
    }

    /// Spec F 3.8.7 and question 14 (d): a Windows-form target is judged
    /// AS STORED, where a drive letter or `\??\` makes it absolute.
    #[test]
    fn an_absolute_windows_form_is_unsafe_on_every_host() {
        for kind in [RedirectionKind::NtSymlink, RedirectionKind::NtJunction] {
            for target in ["C:\\x\\a.txt", "\\??\\C:\\x", "\\\\server\\share", "\\x"] {
                assert!(!link_is_safe(kind, target.as_bytes(), 5), "{target}");
            }
            assert!(link_is_safe(kind, b"a.txt", 0));
            assert!(!link_is_safe(kind, b"..\\a.txt", 0));
            assert!(link_is_safe(kind, b"..\\a.txt", 1));
        }
    }

    /// A Windows host reads `\` as a separator and a drive letter as a
    /// root in EVERY link it is given, a Unix-type one included, so a Unix
    /// link stored with backslashes is judged on them there (spec F 3.8.2:
    /// such a link is skipped and counted). On a Unix host the same bytes
    /// are one name, as before.
    #[test]
    fn a_unix_link_is_judged_on_the_separators_its_host_reads() {
        let unix = RedirectionKind::PosixSymlink;
        for (target, depth) in [
            ("..\\..\\..\\Users\\victim", 0),
            ("..\\x", 0),
            ("C:\\Windows\\System32", 5),
            ("C:x", 5),
            ("\\x", 5),
            ("\\\\server\\share", 5),
            ("d\\..\\..\\x", 5),
            ("d/..\\x", 5),
            ("..\\../x", 1),
        ] {
            assert!(
                !link_is_safe_on(true, unix, target.as_bytes(), depth),
                "{target} at depth {depth} on a Windows host"
            );
        }
        for (target, depth) in [("d\\f.txt", 0), ("..\\top.txt", 1), ("a.txt", 0)] {
            assert!(
                link_is_safe_on(true, unix, target.as_bytes(), depth),
                "{target} at depth {depth} on a Windows host"
            );
        }
        // A Unix host is given the bytes as stored: one name each.
        for target in ["..\\..\\x", "C:\\x", "d\\..\\..\\x"] {
            assert!(
                link_is_safe_on(false, unix, target.as_bytes(), 0),
                "{target}"
            );
        }
    }

    /// Spec F 3.8.7's conversions, measured on the reference on Linux.
    #[cfg(not(windows))]
    #[test]
    fn windows_forms_are_converted_for_a_unix_host() {
        assert_eq!(
            host_form(RedirectionKind::NtSymlink, b"C:\\x\\a.txt"),
            b"C:/x/a.txt"
        );
        assert_eq!(
            host_form(RedirectionKind::NtJunction, b"\\??\\C:\\x"),
            b"C:/x"
        );
        assert_eq!(host_form(RedirectionKind::NtJunction, b"d"), b"d");
        assert_eq!(
            host_form(RedirectionKind::PosixSymlink, b"d\\f.txt"),
            b"d\\f.txt"
        );
    }
}
