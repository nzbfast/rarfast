//! Commands that REWRITE an existing archive.
//!
//! Written from `rar` 7.23's observable behaviour. All of them are built
//! on rarkit's `edit` module, which rewrites an archive's head and copies
//! every member it keeps byte for byte, so no member is ever
//! recompressed:
//!
//! - `c` sets or removes the archive comment (`edit::set_comment`);
//! - `k` sets the lock flag (`edit::lock`);
//! - `d` drops the members the masks name (`edit::remove`);
//! - `rn` renames members in place (`edit::rename_many`);
//! - `rr[N]` puts a recovery record into an archive that already exists
//!   (`edit::set_recovery`).
//!
//! `ch` is the same rewrite with no change asked for, which is what the
//! reference's own `ch` is when the switches beside it name nothing the
//! main header carries.
//!
//! **What still refuses by name.** `d` on a SOLID archive: the members
//! after the removed one are decoded against its history, and the
//! reference gets there by recompressing the whole archive, which this
//! rewrite will not do. The engine says so and this prints what it says.

use super::super::unrar::extract::mask::{self, has_wildcard, Screen};
use super::super::unrar::{self, Exit, Out};

/// The `-n` and `-x` masks beside `d` or `rn`, read as the read commands
/// read them ([`Screen`]): a member is acted on only where every `-n`
/// list that was given covers it and no `-x` mask does.
///
/// Measured against rar 7.23, 27 Oct 2026
/// (`tests/edit_honours_x_and_n.rs`): `d -x'*.txt' arc.rar '*'` keeps the
/// text files and deletes the rest, the directories holding them
/// included; `rn -xs arc.rar s Z` renames nothing. Until then both
/// switches were read and never reached either command.
pub(crate) struct Screens {
    include: Vec<Screen>,
    exclude: Vec<Screen>,
}

impl Screens {
    pub(crate) fn new(include: &[String], exclude: &[String]) -> Self {
        Self {
            include: include.iter().map(|m| Screen::new(m)).collect(),
            exclude: exclude.iter().map(|m| Screen::new(m)).collect(),
        }
    }

    /// Whether the member survives `-n` and `-x`.
    fn pass(&self, member: &rarkit::MemberInfo<'_>) -> bool {
        let name = String::from_utf8_lossy(member.name);
        let covers = |screen: &Screen| screen.covers(&name, member.is_directory);
        (self.include.is_empty() || self.include.iter().any(covers))
            && !self.exclude.iter().any(covers)
    }
}

/// `d <archive> <files>`: delete members.
///
/// The reference's own three lines, measured: `Deleting from <archive>`,
/// one `Deleting <name>` per member it drops, and `Done`. A mask that
/// names nothing gets `No files to delete` and exit 10, with the archive
/// left alone.
///
/// A mask that is a directory's name takes every member beneath it too,
/// and a `d` that leaves no member removes the archive file, after its
/// own line (measured, 8 Oct 2026: `Erasing empty archive <archive>`
/// before `Done`, exit 0, and no file after).
pub(crate) fn delete(out: &Out, archive: &str, masks: &[String], screens: &Screens) -> Exit {
    let (chosen, every) = {
        // An archive that does not open ends `d` with `Program aborted`
        // and exit 6, where `rn`, `k`, `c`, `ch` and `rr` say `Done` and
        // exit 10 (measured against rar 7.23, 30 Sep 2026).
        let Ok(opened) = opened(out, archive) else {
            out.abort();
            return Exit::CannotOpen;
        };
        if let Some(exit) = refuse_if_locked(out, &opened) {
            return exit;
        }
        out.say(&format!("\nDeleting from {archive}\n"));
        let chosen = chosen_members(&opened, masks, screens);
        // One volume of a set is never erased here: the rewrite refuses
        // a member-level edit of it by name, and that refusal stands.
        let every = !opened.volume().is_volume && chosen.len() == opened.members().count();
        (chosen, every)
    };
    if chosen.is_empty() {
        out.say("No files to delete\n");
        return Exit::NothingMatched;
    }
    for name in &chosen {
        out.say(&format!("Deleting {}\n", unrar::text_from_archive(name)));
    }
    if every {
        // Nothing is rewritten: an archive of no member is not left
        // behind (it was, 24 bytes of it).
        out.say(&format!("Erasing empty archive {archive}\n"));
        if let Err(err) = std::fs::remove_file(archive) {
            out.complain(&format!(
                "Cannot delete {archive}\n{}",
                unrar::io_reason(&err)
            ));
            return Exit::WriteFailed;
        }
        out.say("Done\n");
        return Exit::Clean;
    }
    let exit = rewrite(out, archive, |source, target| {
        let borrowed: Vec<&[u8]> = chosen.iter().map(Vec::as_slice).collect();
        rarkit::edit::remove(source, &borrowed, target).map(|_| ())
    });
    if exit == Exit::Clean {
        out.say("Done\n");
    }
    exit
}

/// The members of `opened` that `masks` name, in archive order.
///
/// A mask here is read as a read command reads a file argument
/// ([`mask::selects`]), so one rule decides what a mask means whichever
/// command carries it. Measured over 396 masks, 9 Oct 2026
/// (`tests/edit-selection/rar723-d.txt`): a mask with no wildcard is that
/// path and every member BENEATH it (`d arc.rar s/d` drops `s/d/c.txt`
/// and `s/d/e/f.dat` with `s/d`, and leaves `s/dup.bin`; `d arc.rar
/// a.txt` leaves `s/a.txt`); a wildcard name with no path is tried on
/// each member's own name, at any depth; and the dot rules are the
/// matcher's (`*.` is the names with no dot, `a.txt.` is `a.txt`).
///
/// One CHOSEN DIFFERENCE from the reference: the masks `.` and `..`,
/// which a read command takes for every member and with which rar 7.23
/// deletes every member, name nothing here, as a mask that ends in a
/// separator names nothing. A delete that empties an archive is asked
/// for with a wildcard.
fn chosen_members(opened: &rarkit::Archive, masks: &[String], screens: &Screens) -> Vec<Vec<u8>> {
    let masks: Vec<&str> = masks
        .iter()
        .map(String::as_str)
        .filter(|mask| !matches!(*mask, "." | ".."))
        .collect();
    opened
        .members()
        .filter(|member| {
            let name = String::from_utf8_lossy(member.name);
            masks.iter().any(|mask| mask::selects(mask, &name)) && screens.pass(member)
        })
        .map(|member| member.name.to_vec())
        .collect()
}

/// What follows `directory` in `name` when `name` lies beneath it: the
/// separator and the rest. `s/dup.bin` is not beneath `s/d`.
fn beneath<'n>(directory: &[u8], name: &'n [u8]) -> Option<&'n [u8]> {
    if directory.is_empty() {
        return None;
    }
    name.strip_prefix(directory)
        .filter(|rest| rest.first() == Some(&b'/'))
}

/// A mask cut at its last separator: the path, if it has one, and the
/// name part.
fn path_and_name(mask: &str) -> (Option<&str>, &str) {
    match mask.rsplit_once('/') {
        Some((path, name)) => (Some(path), name),
        None => (None, mask),
    }
}

/// Whether a new name is one the reference reads as a PATH and not as a
/// name: it ends in a separator, or its last part is `.` or `..`.
/// Measured, 9 Oct 2026: `rn arc.rar s/d q/` and `rn arc.rar s/d x/.`
/// rename nothing and exit 0. (One that ends in a separator and is the
/// last argument never reaches here: the command line takes it for a
/// path, as the reference does.)
fn new_name_is_a_path(to: &str) -> bool {
    matches!(path_and_name(to).1, "" | "." | "..")
}

/// Whether a new name would put a member outside the archive's own tree:
/// it begins with a separator, or one of its parts is `..`, whichever
/// separator stands beside it.
///
/// A CHOSEN DIFFERENCE from rar 7.23, which writes such a name and exits 0
/// (measured 9 Oct 2026: `rn arc.rar a.txt ../x.txt` stores a member
/// named `../x.txt`, `rn arc.rar s/d /D` stores `/D` and `/D/c.txt`). It
/// is asked of the name as BUILT, since a mask builds one too: `rn
/// arc.rar s/b.txt '../*'` builds `../`. The engine refuses the same
/// names at the rewrite; asking here refuses before the `Renaming` lines,
/// and in words about the name and not about the archive.
fn leaves_the_tree(new: &[u8]) -> bool {
    matches!(new.first(), Some(b'/' | b'\\'))
        || new
            .split(|byte| matches!(byte, b'/' | b'\\'))
            .any(|part| part == b"..")
}

/// The length in bytes of the character `text` starts with.
fn first_width(text: &[u8]) -> usize {
    let width = match text.first() {
        Some(byte) if *byte >= 0xF0 => 4,
        Some(byte) if *byte >= 0xE0 => 3,
        Some(byte) if *byte >= 0xC0 => 2,
        _ => 1,
    };
    width.min(text.len())
}

/// The name the new mask `to` gives the member named `old`.
///
/// The mask is read left to right beside a place in the old name, which
/// starts at its front, and the old name is the WHOLE archived name, path
/// and all:
///
/// - `*` copies the old name from the place up to the first byte equal to
///   the mask's next character, and leaves the place there; a `*` that
///   ends the mask copies all that is left;
/// - `?` copies one character and steps over it;
/// - `/` is written, and the place moves past the old name's next `/`
///   when it has one;
/// - `.` is written, and the place moves past a `.` of the old name: its
///   LAST one where this is the mask's last `.`, its next one otherwise,
///   and to the end where there is none ahead;
/// - any other character is written and the place does not move.
///
/// So `q/*` puts `s/d/c.txt` at `q/d/c.txt`, `*.zz` keeps a path and
/// changes an extension (`s/b.txt` to `s/b.zz`, `a.b.txt` to `a.zz`), and
/// a mask with no wildcard, separator or dot is the new name itself.
///
/// Measured against rar 7.23, 9 Oct 2026: the rule was read off some 150
/// hand made pairs, then held against 3,600 more (400 random masks of
/// `a b x . / * ?` over nine names), every one the reference's answer.
/// `tests/edit-selection/rar723-rn-built.txt` is a tenth of those, and
/// `tests/edit-selection/rar723-rn-names.txt` whole runs.
fn built(to: &str, old: &[u8]) -> Vec<u8> {
    let mask = to.as_bytes();
    let last_dot = mask.iter().rposition(|byte| *byte == b'.');
    let ahead = |place: usize, wanted: u8| {
        old[place..]
            .iter()
            .position(|byte| *byte == wanted)
            .map(|at| place + at)
    };
    let mut new = Vec::with_capacity(old.len() + mask.len());
    let mut place = 0;
    for (index, &wanted) in mask.iter().enumerate() {
        match wanted {
            b'*' => {
                let stop = match mask.get(index + 1) {
                    Some(&next) => ahead(place, next).unwrap_or(old.len()),
                    None => old.len(),
                };
                new.extend_from_slice(&old[place..stop]);
                place = stop;
            }
            b'?' => {
                let width = first_width(&old[place..]);
                new.extend_from_slice(&old[place..place + width]);
                place += width;
            }
            b'/' => {
                new.push(wanted);
                if let Some(at) = ahead(place, b'/') {
                    place = at + 1;
                }
            }
            b'.' => {
                new.push(wanted);
                let dot = if Some(index) == last_dot {
                    old.iter()
                        .rposition(|byte| *byte == b'.')
                        .filter(|at| *at >= place)
                } else {
                    ahead(place, b'.')
                };
                place = dot.map_or(old.len(), |at| at + 1);
            }
            _ => new.push(wanted),
        }
    }
    new
}

/// The name the pair `from`, `to` gives the member `name`, and what its
/// `Renaming` line calls the old one; `None` when the pair does not name
/// it.
///
/// Measured, 8 Oct 2026. With no wildcard in `from`: the member of that
/// name and every member beneath it, the line naming `from` itself for
/// each (`Renaming s/d to s/D2/c.txt`). With one: the members whose own
/// path is the mask's and whose name part the mask's matches (`s/d/*`
/// does not reach `s/d/e/f.dat`, and `*.txt` matches nothing inside
/// `s`), the line naming the member.
///
/// A name is matched by the read commands' matcher ([`mask::wildcard`]),
/// so its dot rules hold here too (9 Oct 2026,
/// `tests/edit-selection/rar723-rn.txt`): `rn arc.rar a.txt. Q9` renames
/// `a.txt`, and `s/*.` names `s/dx` and the directory `s/d`.
///
/// The new name is [`built`] from the member's whole name; for a member
/// beneath a directory named with no wildcard, from the directory's name,
/// with the rest of the member's after it (`rn arc.rar s/d '*.zz'` gives
/// `s/d.zz/c.txt`).
///
/// The last answer is HOW the pair names it ([`Reach`]), which decides
/// between two pairs that both do ([`naming_pair`]).
fn renamed(from: &str, to: &str, name: &[u8]) -> Option<(String, Vec<u8>, Reach)> {
    if !has_wildcard(from) {
        if std::str::from_utf8(name).is_ok_and(|name| mask::wildcard(from, name)) {
            let said = unrar::text_from_archive(name).into_owned();
            return Some((said, built(to, name), Reach::Direct));
        }
        let rest = beneath(from.as_bytes(), name)?;
        return Some((
            from.to_owned(),
            [&built(to, from.as_bytes()), rest].concat(),
            Reach::Beneath,
        ));
    }
    let text = std::str::from_utf8(name).ok()?;
    let (path, base) = path_and_name(text);
    let (mask_path, mask_name) = path_and_name(from);
    if path != mask_path || !mask::wildcard(mask_name, base) {
        return None;
    }
    Some((
        unrar::text_from_archive(name).into_owned(),
        built(to, name),
        Reach::Direct,
    ))
}

/// How a pair's mask names a member.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reach {
    /// By its whole name, or by a wildcard in its own directory.
    Direct,
    /// As a member beneath a directory the mask names whole.
    Beneath,
}

/// The ONE pair that renames the member `name`, as its `Renaming` line's
/// old name and the new name: the first pair that names it directly, and
/// where none does the first that reaches it beneath a directory,
/// whatever the pairs' order (the command line's specification, 11.1,
/// rule B11). Measured on rar 7.23 for macOS, 10 Oct 2026: `rn s t
/// s/a.txt z` and `rn s/a.txt z s t` both end with `z` and `t/b.txt`.
/// Until then the first pair that named a member in either way took it.
fn naming_pair(pairs: &[[String; 2]], name: &[u8]) -> Option<(String, Vec<u8>)> {
    let mut beneath = None;
    for [from, to] in pairs {
        match renamed(from, to, name) {
            Some((said, new, Reach::Direct)) => return Some((said, new)),
            Some((said, new, Reach::Beneath)) if beneath.is_none() => {
                beneath = Some((said, new));
            }
            _ => {}
        }
    }
    beneath
}

/// `rn <archive> <old> <new> [<old> <new> ...]`: rename members.
///
/// The masks are taken in PAIRS, which is what the reference does, and
/// each member a pair renames gets its own `Renaming <old> to <new>` line
/// before the one rewrite that applies them all. The lines come in the
/// archive's order, and a member takes ONE pair ([`naming_pair`] says
/// which; [`renamed`] says which members a pair names).
pub(crate) fn rename(out: &Out, archive: &str, masks: &[String], screens: &Screens) -> Exit {
    let (locked, stored) = match opened(out, archive) {
        Ok(opened) => (
            opened.is_locked(),
            // A member `-n` or `-x` screens out is no pair's to rename.
            opened
                .members()
                .filter(|member| screens.pass(member))
                .map(|member| member.name.to_vec())
                .collect::<Vec<_>>(),
        ),
        Err(exit) => {
            out.say("Done\n");
            return exit;
        }
    };
    out.say(&format!("\nProcessing archive {archive}\n"));
    if locked {
        return locked_and_done(out);
    }
    // An odd trailing mask names no new name, so there is nothing to do
    // with it; the reference takes the pairs it has.
    let pairs = masks.as_chunks::<2>().0;
    // A new name the reference reads as a path renames nothing there, in
    // silence. Here the pair is refused by name before a line is printed
    // or a byte written.
    for [from, to] in pairs {
        if new_name_is_a_path(to) {
            out.complain(&format!(
                "Cannot rename {from} to {to}\nthe new name ends in a separator or a dot \
                 directory, which names a path and no member"
            ));
            out.say("Done\n");
            return Exit::Aborted;
        }
    }
    // One line for each MEMBER a pair renames, which is none for a name
    // the archive does not hold and two for a name two members store
    // (measured 4 Oct 2026; the engine renames every one of them).
    let mut renames: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut lines = String::new();
    for name in &stored {
        let Some((said, new)) = naming_pair(pairs, name) else {
            continue;
        };
        // A new name that would leave the archive's own tree is refused
        // by name before a line is printed or a byte written
        // ([`leaves_the_tree`]).
        if leaves_the_tree(&new) {
            out.complain(&format!(
                "Cannot rename {said} to {}\nthe new name begins with a separator or holds a .. \
                 part, and a member is not given a name outside the archive's own tree",
                unrar::text_from_archive(&new)
            ));
            out.say("Done\n");
            return Exit::Aborted;
        }
        lines.push_str(&format!(
            "Renaming {said} to {}\n",
            unrar::text_from_archive(&new)
        ));
        if !renames.iter().any(|(old, _)| old == name) {
            renames.push((name.clone(), new));
        }
    }
    out.say(&lines);
    // Nothing named: nothing to rewrite, and the archive is left as it
    // lies.
    if renames.is_empty() {
        out.say("Done\n");
        return Exit::Clean;
    }
    let pairs = renames;
    let exit = rewrite(out, archive, |source, target| {
        let borrowed: Vec<(&[u8], &[u8])> = pairs
            .iter()
            .map(|(from, to)| (from.as_slice(), to.as_slice()))
            .collect();
        rarkit::edit::rename_many(source, &borrowed, target).map(|_| ())
    });
    if exit == Exit::Clean {
        out.say("Done\n");
    }
    exit
}

/// `k <archive>`: set the archive's lock flag.
pub(crate) fn lock(out: &Out, archive: &str) -> Exit {
    // The OPEN comes first, and the `Processing archive` line only
    // after it: measured, `rar k nosuch.rar` prints `Done` and nothing
    // else on stdout, with `Cannot open nosuch.rar` on stderr and exit
    // 10. An archive that opens gets three lines, `Processing archive
    // <name>`, `Locking archive` and `Done`.
    let locked = match opened(out, archive) {
        Ok(opened) => opened.is_locked(),
        Err(exit) => {
            out.say("Done\n");
            return exit;
        }
    };
    out.say(&format!("\nProcessing archive {archive}\n"));
    // An archive that is locked already is not locked again: measured,
    // the `Locking archive` line is never reached.
    if locked {
        return locked_and_done(out);
    }
    out.say("Locking archive\n");
    let exit = lock_archive(out, archive);
    if exit == Exit::Clean {
        out.say("Done\n");
    }
    exit
}

/// The lock itself, which `-k` beside a creating command also asks for.
pub(crate) fn lock_archive(out: &Out, archive: &str) -> Exit {
    rewrite(out, archive, |source, target| {
        rarkit::edit::lock(source, target)
    })
}

/// `ch <archive>`: change archive parameters.
///
/// The parameters the reference can change here that rarkit's rewrite
/// carries are the LOCK flag, which `-k` beside the command asks for, and
/// the recovery record, which `-rr[N]` does. With neither switch the
/// command is a rewrite that changes nothing, and the reference's own
/// output for it is two lines.
///
/// `-rr[N]` here is the `rr[N]` command (measured, 8 Oct 2026: the same
/// lines and the same record, on an archive with no record and on one
/// with another), and with `-k` as well the record is made first and
/// `Locking archive` follows its line.
pub(crate) fn change_parameters(
    out: &Out,
    archive: &str,
    lock_after: bool,
    recovery_percent: Option<u64>,
) -> Exit {
    let (locked, has_record) = match opened(out, archive) {
        Ok(opened) => (opened.is_locked(), opened.has_recovery_record()),
        Err(exit) => {
            out.say("Done\n");
            return exit;
        }
    };
    out.say(&format!("\nProcessing archive {archive}\n"));
    if locked {
        return locked_and_done(out);
    }
    let mut exit = match recovery_percent {
        Some(percent) => set_recovery_record(out, archive, percent, has_record),
        None => Exit::Clean,
    };
    if exit == Exit::Clean && lock_after {
        if recovery_percent.is_some_and(|percent| percent > 0) {
            out.say("Locking archive\n");
        }
        exit = lock_archive(out, archive);
    }
    if exit == Exit::Clean {
        out.say("Done\n");
    }
    exit
}

/// `c <archive>`: set the archive comment from `-z<file>`.
///
/// A LOCKED archive is refused before the comment is read, and in this
/// command's own words, which are not `d`'s: measured, `rar c -z<file>` on
/// a locked archive prints `Processing archive <name>` and `Done` on
/// stdout, `ERROR: Locked archive` on stderr and exits 4, whether or not
/// the comment file is there.
pub(crate) fn comment(out: &Out, archive: &str, comment_file: Option<&str>) -> Exit {
    let locked = match opened(out, archive) {
        Ok(opened) => opened.is_locked(),
        Err(exit) => {
            out.say("Done\n");
            return exit;
        }
    };
    out.say(&format!("\nProcessing archive {archive}\n"));
    if locked {
        return locked_and_done(out);
    }
    let text = match comment_file {
        // A `c` with no `-z` reads the comment from standard input, which
        // is what the reference does when it is not on a terminal.
        None | Some("") => {
            let mut buffer = Vec::new();
            if let Err(err) = std::io::Read::read_to_end(&mut std::io::stdin(), &mut buffer) {
                out.complain(&format!("Cannot open stdin\n{}", unrar::io_reason(&err)));
                return Exit::CannotOpen;
            }
            buffer
        }
        Some(path) => {
            // `Reading comment from` goes out BEFORE the read and
            // `Adding a comment to` only after it succeeds: measured on
            // the conformance `comment-add` row, where the file is not
            // there and the reference prints `Processing archive
            // arc.rar`, `Reading comment from plain/comment.txt` and
            // `Done`, with the open failure on stderr and exit 6. It
            // still prints `Done`, having done nothing.
            out.say(&format!("Reading comment from {path}\n"));
            match std::fs::read(path) {
                Ok(bytes) => {
                    out.say(&format!("Adding a comment to {archive}\n"));
                    bytes
                }
                Err(err) => {
                    out.complain(&format!("Cannot open {path}\n{}", unrar::io_reason(&err)));
                    out.say("Done\n");
                    return Exit::CannotOpen;
                }
            }
        }
    };
    let exit = rewrite(out, archive, |source, target| {
        rarkit::edit::set_comment(source, Some(&text), target)
    });
    if exit == Exit::Clean {
        out.say("Done\n");
    }
    exit
}

/// `rr[N] <archive>`: add an inline recovery record.
///
/// **The counter walks in SHARDS, not in bytes.** The reference prints one
/// tick per data shard of the record it is building, which is `k` of
/// SPEC-L 3.5.1 - fifteen ticks for a 15,207 byte archive, measured - and
/// the percentage of tick `i` is `i * 100 / k` rounded down. The engine
/// reports `k` in `rarkit::edit::EditReport::recovery_shards` because nothing outside
/// it knows the protected length the geometry follows from, and the ticks
/// go out once the record is built: they are the same bytes on the same
/// line either way.
pub(crate) fn add_recovery_record(out: &Out, archive: &str, percent: u64) -> Exit {
    let (locked, has_record) = match opened(out, archive) {
        Ok(opened) => (opened.is_locked(), opened.has_recovery_record()),
        Err(exit) => {
            out.say("Done\n");
            return exit;
        }
    };
    out.say(&format!("\nProcessing archive {archive}\n"));
    if locked {
        return locked_and_done(out);
    }
    let exit = set_recovery_record(out, archive, percent, has_record);
    if exit == Exit::Clean {
        out.say("Done\n");
    }
    exit
}

/// The record itself, for `rr[N]` and for `ch -rr[N]`: everything between
/// `Processing archive` and `Done`.
///
/// **A percentage of 0 is NO record.** Measured, 8 Oct 2026: `rr0` and
/// `ch -rr0` print nothing of their own, exit 0, and the archive has no
/// record after, whether or not it had one (0 was taken for 1 before
/// this, so `rr0` wrote a record). An archive with none already is left
/// as it lies.
fn set_recovery_record(out: &Out, archive: &str, percent: u64, has_record: bool) -> Exit {
    if percent == 0 {
        if !has_record {
            return Exit::Clean;
        }
        return rewrite(out, archive, |source, target| {
            rarkit::edit::set_recovery(source, None, target).map(|_| ())
        });
    }
    // The label, then the four column counter field the counter walks
    // back over, then one space before it: measured, the reference writes
    // `Adding the data recovery record` and five spaces before its first
    // backspace.
    out.say("Adding the data recovery record     ");
    let mut shards = 0u32;
    let exit = rewrite(out, archive, |source, target| {
        // The most a record of the archive's family takes: 1,000 for a
        // RAR 5 record (SPEC-L 3.5.1), 100 for the RAR 4 family's.
        let most = if source.format() == rarkit::Format::Rar5 {
            1_000
        } else {
            100
        };
        rarkit::edit::set_recovery(source, Some(percent.clamp(1, most) as u32), target).map(
            |report| {
                shards = report.recovery_shards;
            },
        )
    });
    if exit == Exit::Clean {
        for tick in 1..=shards {
            out.say(&super::lines::counter(
                u64::from(tick) * 100 / u64::from(shards.max(1)),
            ));
        }
        out.say("\n");
    }
    exit
}

/// A LOCKED archive refuses every command that would change it, and the
/// reference's refusal is its own two lines and exit 4.
///
/// Measured as the second step of the conformance `lock` row: after
/// `rar k -y arc.rar`, `rar d -y arc.rar text.txt` prints `Program
/// aborted` on stdout, `ERROR: Locked archive` on stderr and exits 4.
/// An archive that cannot be opened at all is NOT refused here: the
/// command itself answers that, in its own words.
///
/// These are `d`'s words. Every other command here answers with
/// [`locked_and_done`].
fn refuse_if_locked(out: &Out, opened: &rarkit::Archive) -> Option<Exit> {
    if !opened.is_locked() {
        return None;
    }
    out.warn("\nERROR: Locked archive\n");
    out.say("Program aborted\n");
    Some(Exit::SealedArchive)
}

/// The refusal of a locked archive by `rn`, `k`, `ch`, `c` and `rr`, said
/// after the command's `Processing archive` line.
///
/// Measured on 4 Oct 2026, each of the five over a locked archive: stdout
/// is `Processing archive <name>` and `Done`, stderr is `ERROR: Locked
/// archive`, the exit is 4 and the archive is not rewritten. That holds
/// for `k` on an archive that is locked already and for a `ch` that asks
/// for nothing.
fn locked_and_done(out: &Out) -> Exit {
    out.warn("\nERROR: Locked archive\n");
    out.say("Done\n");
    Exit::SealedArchive
}

/// Opens an archive for a command that means to change it, answering an
/// open failure in the reference's own words.
///
/// Measured over `nosuch.rar`: `Cannot open nosuch.rar` and the C
/// library's reason on STDERR, exit 10, and each command's own stdout -
/// which for `k`, `c`, `ch` and `rr` is `Done` and nothing else, the
/// `Processing archive` line never being reached.
fn opened(out: &Out, archive: &str) -> Result<rarkit::Archive, Exit> {
    let mut session = rarkit::Session::new(rarkit::ReadOptions::default());
    match session.open_path(std::path::Path::new(archive)) {
        Ok(opened) => Ok(opened),
        Err(err) => {
            let reason = match err.kind() {
                rarkit::ErrorKind::Source(io) => unrar::io_reason(io),
                _ => format!("{err}"),
            };
            out.complain(&format!("Cannot open {archive}\n{reason}"));
            Err(Exit::NothingMatched)
        }
    }
}

/// One rewrite: open the archive, write the new one beside it, and replace
/// the original only once the new one is complete, so a rewrite that fails
/// leaves the caller's archive exactly as it was.
///
/// The new one is made by [`beside`], under a name nothing else holds,
/// and it carries the permissions the archive had.
fn rewrite<F>(out: &Out, archive: &str, body: F) -> Exit
where
    F: FnOnce(&rarkit::Archive, &mut std::fs::File) -> rarkit::Result<()>,
{
    let source = match opened(out, archive) {
        Ok(source) => source,
        Err(exit) => return exit,
    };
    let (temporary, mut target) = match beside(archive) {
        Ok(made) => made,
        Err(err) => {
            out.complain(&format!(
                "Cannot create {archive}\n{}",
                unrar::io_reason(&err)
            ));
            return Exit::CannotCreate;
        }
    };
    let written = body(&source, &mut target);
    let one_of_a_set = source.volume().is_volume;
    // Both are closed before the name changes hands: the archive's file
    // so that it can be replaced where an open file cannot be, the new
    // one so that all of it is the file's before it is the archive.
    drop(source);
    drop(target);
    if let Err(err) = written {
        // The archive was never written to (spec CLI 11.4); only what
        // this call made is taken away.
        let _ = std::fs::remove_file(&temporary);
        // What the engine will not write it names in a sentence of its
        // own, and that sentence is what is said; any other failure in
        // the engine's words for it.
        let refused = match err.kind() {
            rarkit::ErrorKind::Unsupported(rarkit::Unsupported::WriteFeature(what)) => Some(what),
            _ => None,
        };
        let why = match refused {
            Some(what) => format!("the engine does not write this: {what}"),
            None => err.to_string(),
        };
        out.warn(&format!("\nrarfast: cannot change {archive}: {why}\n"));
        // An edit the engine will not make to one volume of a set ends
        // as the reference ends `d` there, with 4 (measured, rar 7.23:
        // `Cannot modify volume`); every other failure is 2.
        return if refused.is_some() && one_of_a_set {
            Exit::SealedArchive
        } else {
            Exit::Aborted
        };
    }
    // The new archive is whole, so it takes the archive's name in one
    // step, on the archive's own volume: the old one stands until then
    // (rarkit's choice where E9 differs), and a link at the name is replaced, not followed
    // (E7).
    if let Err(err) = std::fs::rename(&temporary, archive) {
        let _ = std::fs::remove_file(&temporary);
        out.complain(&format!(
            "Cannot create {archive}\n{}",
            unrar::io_reason(&err)
        ));
        return Exit::CannotCreate;
    }
    Exit::Clean
}

/// A new, empty file beside `archive` for a rewrite to fill, and its name.
///
/// The file is CREATED, never opened: a name that already exists, whether
/// a file, a link somebody left there or another rewrite's work in
/// progress, is passed over for the next one, so nothing that was there
/// before is written through or truncated and two rewrites of one archive
/// never share a file. It starts out readable by its owner alone and is
/// then given the archive's own permissions, so a rewrite never leaves an
/// archive more widely readable than it found it.
fn beside(archive: &str) -> std::io::Result<(String, std::fs::File)> {
    // How many names are tried before the directory is called full of
    // them; the first is free in the ordinary case.
    const NAMES: u32 = 10_000;
    let mut making = std::fs::OpenOptions::new();
    making.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        making.mode(0o600);
    }
    // The name is the reference's own for its temporary (spec CLI 11.3
    // E1): the process's number, a second number, `.rartemp`. It is made
    // in the ARCHIVE's directory, so the two are on one volume.
    let process = std::process::id();
    for turn in 0..NAMES {
        let name = std::path::Path::new(archive)
            .with_file_name(format!("__rar_{process}.{turn}.rartemp"))
            .to_string_lossy()
            .into_owned();
        let file = match making.open(&name) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        };
        let allowed =
            std::fs::metadata(archive).and_then(|meta| file.set_permissions(meta.permissions()));
        return match allowed {
            Ok(()) => Ok((name, file)),
            Err(err) => {
                // The file is this call's own: no other run was handed it.
                drop(file);
                let _ = std::fs::remove_file(&name);
                Err(err)
            }
        };
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!("no free name for a temporary file beside {archive}"),
    ))
}

#[cfg(test)]
mod tests {
    use super::built;

    /// 360 names rar 7.23 built, one in ten of the 3,600 the rule was held
    /// against (9 Oct 2026): the old name, the new mask and the new name,
    /// a tab between them.
    #[test]
    fn a_new_name_is_built_as_the_reference_builds_it() {
        let table = include_str!("../../../tests/edit-selection/rar723-rn-built.txt");
        let mut rows = 0;
        for row in table.lines() {
            let mut fields = row.split('\t');
            let (old, mask, new) = (
                fields.next().unwrap(),
                fields.next().unwrap(),
                fields.next().unwrap(),
            );
            assert_eq!(
                String::from_utf8_lossy(&built(mask, old.as_bytes())),
                new,
                "{old} under {mask}"
            );
            rows += 1;
        }
        assert_eq!(rows, 360);
    }

    #[test]
    fn a_plain_new_name_is_itself() {
        for plain in ["Q9", "s/D2", "s/d/E9.tar.gz", "a b"] {
            assert_eq!(built(plain, b"s/d/c.txt"), plain.as_bytes());
        }
    }
}
