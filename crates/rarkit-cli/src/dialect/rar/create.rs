//! The creator's WRITE half, on rarkit's writer (work package G).
//!
//! **Written from the reference binary's observable behaviour.** `rar`
//! 7.23 is the specification for this dialect: its output, its exit codes
//! and the archives it produces are what every rule below was measured
//! from, and the project's conformance tables are the pinned capture
//! of that measurement. No other RAR implementation was opened.
//!
//! What this file OWES a caller, in the order the reference does it:
//!
//! 1. the archive name, after `-ag` and the default extension;
//! 2. the files, from `crate::dialect::rar::select`;
//! 3. a REFUSAL BY NAME for anything the command line asked for that this
//!    creator cannot honour end to end. Exiting 0 having written something
//!    different is the worse failure and spec R.2 says so, which is why
//!    the refusals below name the switch and touch nothing;
//! 4. the archive itself, through one [`Writer`];
//! 5. what the switches ask for afterwards: `-k` locks it, `-t` tests it,
//!    and `-df` and `-dw` delete the sources, which a failed lock or test
//!    keeps.
//!
//! **Byte identity, and where it stops.** A STORED archive is the one
//! shape where an encoder has nothing to choose, so this creator asks for
//! rarkit's `Layout::Reference` there and the bytes are the reference's
//! own. A COMPRESSED archive is not: rarkit's encoder makes its own
//! choices, the archive extracts to source-identical bytes and its sha256
//! is its own. The conformance tables record a sha for those rows too, so
//! they diverge; that difference is reported in the crate README rather
//! than worked around here.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use rarkit::{
    ChecksumKind, Layout, MemberOrder, MemberSpec, Password, Payload, Progress, VolumeNaming,
    VolumeOut, WriteFormat, WriteMethod, WriteOptions, Writer,
};

use super::super::unrar::{self, Exit, Out};
use super::ahead::{Ahead, Loaded};
use super::args::{HashType, Options, PathMode};
use super::lines::{self, Ending, Verb};
use super::select::{self, Chosen};

// The parts, one module a seam. A part's names are taken whole.
mod options;
mod report;
mod source;
mod volumes;
use super::ahead;
#[allow(unused_imports)]
use options::*;
#[allow(unused_imports)]
use report::*;
#[allow(unused_imports)]
use source::*;
#[allow(unused_imports)]
use volumes::*;

/// Which creator command asked to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddMode {
    /// `a`: add files to an archive.
    Add,
    /// `m`: add, then delete the originals.
    Move,
    /// `mf`: add files only, then delete them.
    MoveFiles,
    /// `u`: add new files and update older ones.
    Update,
    /// `f`: update files already in the archive.
    Freshen,
}

impl AddMode {
    /// The command word the reference spells this with, for the refusal.
    fn word(self) -> &'static str {
        match self {
            Self::Add => "a",
            Self::Move => "m",
            Self::MoveFiles => "mf",
            Self::Update => "u",
            Self::Freshen => "f",
        }
    }

    /// Whether the command deletes the sources once the archive is
    /// written, as `-df` does for every other command.
    fn deletes_sources(self) -> bool {
        matches!(self, Self::Move | Self::MoveFiles)
    }

    /// Whether the command adds files that are not in the archive yet.
    /// `f` alone does not: it only refreshes what is already there.
    fn adds_new(self) -> bool {
        !matches!(self, Self::Freshen)
    }
}

/// `a`, `m`, `mf`, `u`, `f`.
pub(crate) fn add(
    out: &Out,
    archive: &str,
    masks: &[String],
    opts: &Options,
    mode: AddMode,
) -> Exit {
    let archive = match &opts.generate_name {
        Some(format) => unrar::generated_name(archive, format),
        None => archive.to_owned(),
    };
    let archive = unrar::default_extension(&archive);
    let existing = Path::new(&archive).is_file();

    // The header the reference opens with. Measured: an archive that
    // exists is `Updating archive`, whatever the command word, and one
    // that does not is `Creating archive` - `rar f -y arc.rar` over a
    // name with no file behind it says `Creating archive arc.rar` and
    // then `WARNING: No files`.
    let head = match (existing, opts.solid) {
        (true, _) => "Updating archive",
        (false, true) => "Creating solid archive",
        (false, false) => "Creating archive",
    };
    // The header is said once the archive EXISTS: the reference creates
    // its output before it prints it, so a create that fails prints no
    // header at all (measured against rar 7.23, 30 Sep 2026: `rar a
    // nodir/arc.rar f.txt` answers `Cannot create nodir/arc.rar` and
    // `Program aborted`, exit 9). A run that stops before the create -
    // no files, a refusal - still says it, as the reference does.
    let say_head = || out.say(&format!("\n{head} {archive}\n\n"));

    // A list file that could not be read ends the run before anything
    // else, in the reference's words and with its code (measured against
    // rar 7.23, 4 Oct 2026: `Cannot open keep.lst` and the reason, then
    // `Program aborted`, exit 6, no header and nothing written). Taken
    // as an empty list, a missing `-n@` list selected every file and a
    // move then deleted them all.
    if let Some(text) = &opts.unread_list {
        out.complain(text);
        out.abort();
        return Exit::CannotOpen;
    }

    // A switch this creator cannot honour is refused BEFORE the files
    // are chosen, because some of them decide what a chosen file would
    // even be called: off a unix host `-ep3` has no measured name, so
    // every candidate would drop out of the selection and the run would
    // otherwise report `WARNING: No files` for a reason that has nothing
    // to do with the files.
    if let Some((switch, asks)) = opts.create_declines.first() {
        // The reference's code for a command line it will not run, and
        // nothing has been read, written or deleted.
        say_head();
        out.warn(&format!(
            "rarfast: `{}` does not act on `{switch}`, {asks} - {archive} was not touched.\n",
            mode.word()
        ));
        return Exit::BadCommandLine;
    }
    if let Some(reason) = unsupported_switch(opts) {
        say_head();
        return refuse(out, mode.word(), &archive, &reason);
    }

    let found = select::collect(masks, opts);
    let mut files = found.files;
    if !mode.adds_new() {
        // `f` refreshes only what the archive already holds. With no
        // archive there is nothing to refresh, and with one the names it
        // holds are the filter.
        files = freshen_filter(&archive, files);
    }
    // The reference reads its sources before it creates anything, so a
    // mask that names nothing is reported before the header: on one
    // stream (`-ierr`) `Cannot open nosuch.txt` comes first (measured 30
    // Sep 2026).
    for text in &found.missing {
        out.complain(text);
    }
    // So is a directory the walk could not read, which until 4 Oct 2026
    // was skipped without a word (`select::unread`).
    for text in &found.unread {
        out.complain(text);
    }
    // And so is a file that would not open (`select::owner_cannot_read`).
    // Measured against rar 7.23 on 8 Oct 2026: the rest is archived, the
    // count is said after the last file's line, and the run exits 6; with
    // nothing else to add the count comes before `WARNING: No files`,
    // nothing is written, and the code is still 6.
    for text in &found.unopened {
        out.complain(text);
    }
    let cannot_open = match found.unopened.len() {
        0 => None,
        1 => Some("WARNING: Cannot open 1 file\n".to_owned()),
        count => Some(format!("WARNING: Cannot open {count} files\n")),
    };
    if files.is_empty() {
        say_head();
        if let Some(line) = &cannot_open {
            out.say(line);
            out.say("WARNING: No files\n");
            return Exit::CannotOpen;
        }
        // Measured: `WARNING: No files` on stdout, exit 10, and nothing
        // written - not even an empty archive.
        // The blank line the header already ended with is the one the
        // reference leaves in front of this: measured, `rar f -y arc.rar`
        // over a name with no file behind it prints
        // `Creating archive arc.rar\n\nWARNING: No files\n` and no more.
        out.say("WARNING: No files\n");
        return Exit::NothingMatched;
    }

    if existing {
        // rarkit's API writes a NEW archive and edits an existing one's
        // main header; merging new members into one that already exists
        // is neither, and guessing at it would rewrite the caller's
        // archive with a different member set. Checked AFTER the
        // selection, because an update with nothing selected never
        // reaches the merge: the reference answers `WARNING: No files`
        // and so does this, which is the `update` and `freshen` rows.
        say_head();
        return refuse(
            out,
            mode.word(),
            &archive,
            &format!(
                "adding to an archive that already exists (the reference's `{}` over \
                 an existing archive), which needs an engine-side merge rarkit's write \
                 API does not offer",
                mode.word()
            ),
        );
    }

    if opts.volume_size.is_some() {
        // Since 25 Sep 2026 a volume set is refused, like the
        // plain archive above and before anything is written, over a file
        // already at one of its names. Otherwise the run truncates it and,
        // if the run then fails, removes it.
        if let Some(name) = existing_volume(&archive, opts.old_volume_names) {
            say_head();
            return refuse(
                out,
                mode.word(),
                &archive,
                &format!(
                    "a volume set over {name}, which already exists and would be \
                     overwritten"
                ),
            );
        }
    }

    // The pool is built BEFORE anything is created, so that a system which
    // refuses its threads (an address space limit, a thread limit) is
    // answered in rarfast's own words with no file left behind. Its error
    // was discarded until 1 Oct 2026, and the first use of the pool then
    // panicked over a 0-byte archive (`crate::workers::configure`).
    if let Err(why) = crate::workers::configure(opts.shared.threads, crate::workers::Work::Write) {
        out.complain(&why);
        out.abort();
        return Exit::OutOfMemory;
    }

    // A single archive is created here, before its header; a volume set
    // creates each volume as the writer reaches it (unmeasured when the
    // first of them cannot be created, so it keeps its old order).
    // An encrypted create is bound by its own work (one CBC chain a
    // member), which an output may hold its corrections by
    // (`unbuffered::Holds`). A BLAKE2sp-checksummed one is NOT counted
    // bound: its hash outruns a slower drive (see `unbuffered::HOLDS`).
    crate::unbuffered::create_is_bound(opts.shared.password.is_some());
    let early = if opts.volume_size.is_none() {
        match crate::unbuffered::Output::create(Path::new(&archive), output_expected(&files, opts))
        {
            Ok(file) => Some(file),
            Err(err) => {
                out.complain(&format!(
                    "Cannot create {archive}\n{}",
                    unrar::io_reason(&err)
                ));
                out.abort();
                return Exit::CannotCreate;
            }
        }
    } else {
        None
    };
    say_head();

    let (comment, comment_failed) = read_comment(out, opts, &archive);

    let written = match write_archive(out, &archive, &files, opts, comment, early) {
        Ok(written) => written,
        Err(exit) => return exit,
    };

    if opts.recovery_percent.is_some() {
        out.say(&lines::recovery_record());
    }
    if let Some(line) = &cannot_open {
        out.say(line);
    }

    // A mask that named nothing is an error even when the other masks
    // wrote an archive: measured, `rar a arc.rar text.txt nosuch.txt
    // rand.bin` writes both files that are there, reports the one that
    // is not, and exits 10.
    let mut exit = if found.missing.is_empty() {
        Exit::Clean
    } else {
        Exit::NothingMatched
    };
    if !found.unread.is_empty() {
        // Measured: what could be reached is archived, and the run exits
        // 6. With nothing reached it is `WARNING: No files` and 10, above.
        exit = exit.worse_of(Exit::CannotOpen);
    }
    if cannot_open.is_some() {
        exit = exit.worse_of(Exit::CannotOpen);
    }
    if comment_failed {
        // Measured: a `-z` file that is not there leaves the archive
        // written without a comment, and the run exits 6.
        exit = exit.worse_of(Exit::CannotOpen);
    }
    // The sources go only once the archive is the one that was asked
    // for. Until 4 Oct 2026 they went whatever `-t` and `-k` had just
    // answered, so `m -t` unlinked them after a FAILED test.
    //
    // Measured against rar 7.23 on 4 Oct 2026 (`m -t`, `a -df -t` and
    // `a -dw -t`, the archive damaged while it was being written): a
    // failed test is the last thing the reference does. It exits 3,
    // deletes nothing, prints no `Deleting` line, no `Done` and no word
    // about the deletion it skipped, and `a -t` with no deletion asked
    // for ends the same way. It locks BEFORE it tests, which is the
    // order here. A failed lock could not be produced in the reference;
    // here it keeps the sources too, since keeping a file loses nothing.
    //
    // Both follow the files this run WROTE, not the name it was given:
    // with `-v` there is no `arc.rar`, the set is `arc.part1.rar` and on,
    // and until 4 Oct 2026 the test and the lock opened `arc.rar`, found
    // nothing and failed a create that had succeeded. Measured the same
    // day, `rar a -m0 -v100k -k -t arc.rar big.bin` locks EVERY volume
    // (`rar lt` says `lock` of each) and tests the set from its first.
    //
    // The lock has a line of its own, `Locking archive`, once for each
    // file locked (measured the same day). The earlier volumes' lines
    // went out as each volume ended (`Report::lock_follows`); this is
    // the last file's, or a single archive's. Before a test it takes the
    // newline the last member's line left for the test's banner.
    let mut locked = true;
    if opts.lock_after {
        out.say(if opts.test_after {
            "\nLocking archive"
        } else {
            "Locking archive\n"
        });
        for volume in &written {
            let lock = lock_written(out, &volume.to_string_lossy());
            locked &= lock == Exit::Clean;
            exit = exit.worse_of(lock);
        }
    }
    if opts.test_after {
        let first = written.first().map_or_else(
            || archive.clone(),
            |first| first.to_string_lossy().into_owned(),
        );
        let test = test_written(out, &first, opts);
        exit = exit.worse_of(test);
        if test != Exit::Clean {
            return exit;
        }
    }
    if opts.archive_time_latest {
        exit = exit.worse_of(date_by_newest(out, &written, &files));
    }
    if locked && (opts.delete_after || opts.wipe_after || mode.deletes_sources()) {
        exit = exit.worse_of(delete_once_synced(
            out,
            &written,
            &files,
            opts,
            mode,
            sync_written,
        ));
    }
    out.say("Done\n");
    exit
}

/// The one refusal every unbuilt path in the creator prints.
///
/// It names the COMMAND and what is missing, so a caller reading stderr
/// knows what it is waiting on, and it never touches the archive.
/// [`Exit::Aborted`] rather than [`Exit::BadCommandLine`]: the caller spelled a
/// real command correctly, and a usage error would send them looking for a
/// typo they did not make.
pub(crate) fn unbuilt(out: &Out, word: &str, archive: &str, needs: &str) -> Exit {
    out.warn(&format!(
        "rarfast: `{word}` is not built in this rarkit-cli yet - it needs {needs}. \
         {archive} was not touched.\n"
    ));
    Exit::Aborted
}

/// A command line this creator understands and cannot honour end to end.
fn refuse(out: &Out, word: &str, archive: &str, reason: &str) -> Exit {
    out.warn(&format!(
        "rarfast: `{word}` cannot honour {reason} - {archive} was not touched.\n"
    ));
    Exit::Aborted
}

/// Every SWITCH the command line can carry that this creator would have
/// to honour silently wrong, each named so a caller learns which one
/// stopped it.
///
/// A switch that only costs compression RATIO is not here: `-ms`, which
/// asks for named extensions to be stored rather than packed, comes out
/// compressed instead and extracts to the same bytes. Every switch that
/// would change what lands on disk is either honoured or in this list.
fn unsupported_switch(opts: &Options) -> Option<String> {
    if opts.synchronize {
        return Some("`-as`, which deletes archived members that are not on disk".to_owned());
    }
    // `-ep2` and `-ep3` are honoured on a unix host as the reference
    // honours them there (`select::stored_name`). Elsewhere the drive
    // letter's spelling in a stored name is unmeasured, so they stay
    // refused rather than guessed.
    if cfg!(not(unix))
        && matches!(
            opts.path_mode,
            PathMode::FullPath | PathMode::FullPathWithDrive
        )
    {
        return Some(
            "`-ep2` or `-ep3` off a unix host, whose stored drive spelling is unmeasured"
                .to_owned(),
        );
    }
    if opts.sfx_module.is_some() {
        return Some("`-sfx`, which needs a self-extracting module to graft".to_owned());
    }
    if opts.recovery_volumes.is_some() {
        return Some("`-rv`, which needs rarkit's rev5 WRITER".to_owned());
    }
    // The switches a create read and then ignored until 4 Oct 2026, so
    // that `m -sl1m small.rar *` archived and then deleted every file,
    // the large ones included, and exited 0. Each is named as it was
    // typed; honouring them is later work (`Options::create_refuses`).
    // `-u` is not among them: over no archive it adds every file, as the
    // reference does, and over an existing one `add` refuses already.
    if let Some((switch, asks)) = opts.create_refuses.first() {
        return Some(format!(
            "`{switch}`, {asks} and which this creator does not act on yet"
        ));
    }
    None
}

/// `f`: keep only the chosen files the archive already holds a member for.
fn freshen_filter(archive: &str, files: Vec<Chosen>) -> Vec<Chosen> {
    let Ok(opened) = unrar::open(archive, None) else {
        return Vec::new();
    };
    files
        .into_iter()
        .filter(|file| {
            opened
                .members
                .iter()
                .any(|member| *member.compared_name() == *file.stored)
        })
        .collect()
}

/// `-z[file]`: the archive comment, read from a file or from standard
/// input, with the two lines the reference prints while it does so, and
/// whether the read FAILED.
///
/// `Reading comment from` goes out before the read and `Adding a comment
/// to` only after it succeeds. A comment that cannot be read does not stop
/// the create: measured against rar 7.23 on 30 Sep 2026, `rar a
/// -znosuch.txt arc.rar f.txt` prints `Reading comment from nosuch.txt`,
/// complains `Cannot open nosuch.txt`, adds `f.txt` with no comment and
/// exits 6.
fn read_comment(out: &Out, opts: &Options, archive: &str) -> (Option<Vec<u8>>, bool) {
    let Some(source) = opts.comment_file.as_deref() else {
        return (None, false);
    };
    let shown = if source.is_empty() { "stdin" } else { source };
    out.say(&format!("Reading comment from {shown}\n"));
    let read = if source.is_empty() {
        let mut buffer = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut buffer).map(|_| buffer)
    } else {
        std::fs::read(source)
    };
    match read {
        Ok(bytes) => {
            out.say(&format!("Adding a comment to {archive}\n\n"));
            (Some(bytes), false)
        }
        Err(err) => {
            out.complain(&format!("Cannot open {shown}\n{}", unrar::io_reason(&err)));
            (None, true)
        }
    }
}

/// Writes the archive, printing the reference's progress lines as it goes.
///
/// `early` is the single archive's output, already created by [`add`];
/// a failure before the writer reaches it removes it again.
///
/// Answers every file the run created, in order: the archive, or each
/// volume of the set.
fn write_archive(
    out: &Out,
    archive: &str,
    files: &[Chosen],
    opts: &Options,
    comment: Option<Vec<u8>>,
    early: Option<crate::unbuffered::Output>,
) -> Result<Vec<PathBuf>, Exit> {
    let forget_early = |early: Option<crate::unbuffered::Output>| {
        if early.is_some() {
            drop(early);
            let _ = std::fs::remove_file(archive);
        }
    };
    let report: Hook<'_> = std::sync::Arc::new(std::sync::Mutex::new(Report::new(
        out, opts, files, archive,
    )));

    // Every payload is a file opened on FIRST READ, so a thousand member
    // archive does not need a thousand open descriptors: the writer pulls
    // each payload exactly once, in `add` order, and that first pull is
    // what opens the member's progress line. Declared BEFORE the writer,
    // because the writer borrows them and is dropped first.
    let options = write_options(opts, files, comment);

    // The small members are read ahead on the pool `write_options` has
    // just sized (`ahead`), so the writer's pull of each finds its bytes
    // in memory; the rest it opens itself, as before.
    let ahead = read_ahead(files, opts);
    let sampled = sampled_members(
        files.iter().enumerate().map(|(member, file)| {
            let read_ahead = ahead
                .as_ref()
                .is_some_and(|(_, places)| places[member].is_some());
            (file.size, !file.is_dir && !read_ahead)
        }),
        samples_small(),
    );
    // A cold member of a plain stored create is read through a window
    // (`source::windows_cold_input`); every other form of the command has
    // no row for it and reads as it did, and so does every command under a
    // stated memory cap (`-mm`, a cgroup limit, a finite resource limit).
    let windowed_from =
        windows_cold_input().filter(|_| command_takes_window(opts) && !memory_is_capped());
    let mut sources: Vec<Source<'_>> = files
        .iter()
        .enumerate()
        .map(|(member, file)| Source {
            path: file.disk.clone(),
            open: None,
            ahead: ahead
                .as_ref()
                .and_then(|(ahead, places)| places[member].map(|place| (ahead.clone(), place))),
            held: None,
            sampled: sampled[member] && crate::unbuffered::samples_input(),
            advised: !file.is_dir
                && ahead
                    .as_ref()
                    .is_none_or(|(_, places)| places[member].is_none())
                && file.size > 0
                && advises_input(),
            windowed_from: windowed_from.filter(|from| {
                !file.is_dir
                    && file.size >= *from
                    && ahead
                        .as_ref()
                        .is_none_or(|(_, places)| places[member].is_none())
            }),
            window: None,
            spent: false,
            looking: false,
            member,
            report: std::sync::Arc::clone(&report),
        })
        .collect();
    if let Some((ahead, _)) = &ahead {
        ahead.start();
    }
    let mut writer = match Writer::new(options) {
        Ok(writer) => writer,
        Err(err) => {
            forget_early(early);
            out.warn(&format!("rarfast: {archive} was not written: {err}\n"));
            return Err(Exit::Aborted);
        }
    };

    for (file, source) in files.iter().zip(sources.iter_mut()) {
        let spec = MemberSpec {
            name: file.stored.as_bytes(),
            payload: if file.is_dir || file.size == 0 {
                Payload::Bytes(&[])
            } else {
                // A source that can seek: the writer reads the store
                // rule's samples across a member of 4 GiB and more through
                // it before it reads the member (`Source`'s `Seek`).
                Payload::Seekable {
                    reader: source,
                    size: file.size,
                    crc32: None,
                }
            },
            mtime: file.mtime,
            attributes: file.attributes,
            host_os: host_os(),
            is_directory: file.is_dir,
        };
        if let Err(err) = writer.add(spec) {
            forget_early(early);
            // The run stops here and writes nothing, so the message says
            // so of the ARCHIVE: "was not added" of the one file read as
            // if the rest had been. Both names are printed as any name
            // is (SPEC-CLI section 10): a refused one may hold anything.
            let why = match err.kind() {
                rarkit::ErrorKind::Corrupt(rarkit::Corruption::MemberName) => format!(
                    "the name it would be stored under, {}, is one an archive may not hold \
                     (absolute, a drive, a `..` step behind `/` or `\\`, or a NUL) or this \
                     format cannot carry",
                    unrar::text_from_archive(file.stored.as_bytes())
                ),
                _ => err.to_string(),
            };
            out.warn(&format!(
                "rarfast: {archive} was not written: {} stopped it: {why}\n",
                unrar::text_from_archive(file.shown.as_bytes())
            ));
            return Err(Exit::Aborted);
        }
    }

    let mut hook = Hooked(std::sync::Arc::clone(&report));
    // Every file THIS RUN created, recorded the moment it is created, so a
    // failure removes exactly those and never a name re-derived after the
    // fact: a failed volume create used to remove `archive`, a name a
    // volume set never writes, and leave the volumes it had written.
    let mut created: Vec<PathBuf> = Vec::new();
    let total = output_expected(files, opts);
    let outcome = match opts.volume_size {
        None => {
            let made = match early {
                Some(file) => Ok(file),
                None => crate::unbuffered::Output::create(Path::new(archive), total),
            };
            let mut file = match made {
                Ok(file) => file,
                Err(err) => {
                    out.complain(&format!(
                        "Cannot create {archive}\n{}",
                        unrar::io_reason(&err)
                    ));
                    out.abort();
                    return Err(Exit::CannotCreate);
                }
            };
            created.push(PathBuf::from(archive));
            writer
                .finish_seek_read_with(&mut file, &mut hook)
                .map(|report| trace_write_report(&report))
                .and_then(|()| file.close().map_err(rarkit::Error::from))
        }
        Some(_) => {
            let mut volumes = Volumes {
                stem: volume_stem(archive),
                naming: if opts.old_volume_names {
                    VolumeNaming::Classic
                } else {
                    VolumeNaming::Numbered
                },
                estimate: estimated_volumes(files, opts),
                expected: opts.volume_size.map_or(total, |cap| cap.min(total)),
                created: &mut created,
            };
            writer
                .finish_volumes_with(&mut volumes, &mut hook)
                .map(|report| trace_write_report(&report))
        }
    };
    let mut open_failed = false;
    if let Ok(mut report) = report.lock() {
        report.finish(outcome.is_ok());
        open_failed = report.open_failed();
    }
    match outcome {
        Ok(()) => Ok(created),
        Err(err) => {
            // What was written is left as far as it got and is not a
            // valid archive or volume set, so it goes rather than staying
            // to be mistaken for a finished one. Exiting 0 having written
            // half of one is the failure spec R.2 names. Only the files
            // this run created go; anything else under those names, such
            // as a user's own `arc.rar` beside a set of `arc.partN.rar`,
            // is not ours to remove. (The reference, measured on rar 7.23
            // 25 Sep 2026, leaves its partial volumes behind on exit 9;
            // this deliberately does not.)
            for path in &created {
                let _ = std::fs::remove_file(path);
            }
            if open_failed {
                // The member and the reason are already on stderr, in the
                // reference's own words, and repeating the engine's
                // wrapping of the same `errno` under a second heading
                // would only bury them. Exit 6 is what the reference
                // answers for a source it could not open, where a mask
                // that matched NOTHING is 10.
                out.warn(&format!("\n{archive} was not written\n"));
                return Err(Exit::CannotOpen);
            }
            // A create refuses for memory in two cases, both before a byte
            // and with the reference's code for "not enough memory": under
            // a named `-mm` its encoder cannot fit inside it
            // (`WriteOptions::refuse_over_ceiling`), said as `rv` under
            // `-mm` says it, naming the `-mm` that would do; or no plan
            // fits the cap of the environment it runs in (spec G 3.5, a
            // cgroup limit, a finite address space), said with both
            // figures.
            if let rarkit::ErrorKind::LimitExceeded {
                resource: rarkit::Resource::WorkingMemory,
                needed,
                limit,
            } = err.kind()
            {
                if let Some(cap) = opts.memory_cap {
                    out.warn(&format!(
                        "\n{archive}: the archive is not written: it needs {needed} bytes of \
                         working memory at this level and dictionary, and -mm names {cap}. \
                         -mm{}m or more lets it run.\n",
                        least_mm_that_holds(*needed, files, opts)
                    ));
                    return Err(Exit::OutOfMemory);
                }
                out.warn(&format!(
                    "\n{archive} was not written: the memory limit here is {} MiB and this \
                     archive needs at least {} MiB at this level and dictionary\n",
                    limit >> 20,
                    needed.div_ceil(1 << 20)
                ));
                return Err(Exit::OutOfMemory);
            }
            out.warn(&format!("\n{archive} was not written: {err}\n"));
            Err(Exit::Aborted)
        }
    }
}

/// COUNT KNOB: `RARKIT_WRITE_REPORT=1` (any value but `0`) prints the writer's report on
/// stderr once the archive is written, so a count can set the engine's
/// STATED peak (`WriteReport::peak_working_memory`) beside the process
/// peak `/usr/bin/time` reads. Nothing ships setting it.
const WRITE_REPORT_ENV: &str = "RARKIT_WRITE_REPORT";

fn trace_write_report(report: &rarkit::WriteReport) {
    if crate::knob::writer_var_os(WRITE_REPORT_ENV)
        .is_some_and(|value| !value.is_empty() && value != "0")
    {
        eprintln!(
            "rarkit write report: peak_working_memory {} bytes ({} MiB), bytes {}, volumes {}",
            report.peak_working_memory,
            report.peak_working_memory >> 20,
            report.bytes,
            report.volumes,
        );
    }
}

/// What the archive, or each volume, is expected to reach, which decides
/// whether it is written past the OS cache (`crate::unbuffered::Output`):
/// the input's bytes, which a stored archive is and a compressed one is at
/// most.
///
/// **An archive with a recovery record is written through the cache**, as
/// it always was, and this answers 0 for it: the record is computed from
/// the volume READ BACK, a stripe from each of its shards in turn, and read
/// that way from disk it cost 186 s at `-m0 -rr5%` over 12 GiB on
/// a Zen 4 rental against 8.3 to 9.4 s on disk through the cache (29 Sep
/// 2026, untimed; rar 7.23 14.0 s).
fn output_expected(files: &[Chosen], opts: &Options) -> u64 {
    if opts.recovery_percent.is_some() {
        return 0;
    }
    files.iter().map(|file| file.size).sum()
}

/// The read-ahead for this create (`ahead`), sized to the pool the
/// command line asked for, or `None` where no member is read ahead.
///
/// Under the `ahead-knob` feature, which no shipped build enables,
/// `RARFAST_AHEAD=off` turns it off and `RARFAST_AHEAD=<n>` runs at most n
/// loaders, so the lever can be timed inside one binary against its own
/// shipped setting.
fn read_ahead(files: &[Chosen], opts: &Options) -> Option<(Ahead, Vec<Option<usize>>)> {
    #[allow(unused_mut)]
    let mut loaders = None;
    #[cfg(feature = "ahead-knob")]
    if let Some(knob) = std::env::var_os("RARFAST_AHEAD") {
        if knob == "off" {
            return None;
        }
        loaders = knob.to_str().and_then(|n| n.parse().ok());
    }
    if !cfg!(feature = "parallel") {
        return None;
    }
    Ahead::plan(files, ahead_width(opts), loaders)
}

/// The host this archive records for its members.
fn host_os() -> rarkit::HostOs {
    if cfg!(windows) {
        rarkit::HostOs::Windows
    } else {
        rarkit::HostOs::Unix
    }
}

/// `-t`: test the archive that was just written, in the decoder's own
/// words, which is what the reference prints here too.
///
/// The words are the decoder's and one exit is not: an archive this run
/// has just written and cannot OPEN is an open failure, 6, where the
/// decoder's own `t` of a file it cannot open answers 10 (measured 4 Oct
/// 2026 with the archive made unreadable by the run's umask: `No files
/// to extract`, `Cannot open` and its reason, exit 6). A written archive
/// holds what was added, so the decoder's "nothing to do" here can only
/// be that failure.
fn test_written(out: &Out, archive: &str, opts: &Options) -> Exit {
    let selection = super::super::unrar::extract::Selection::new(&[], &opts.shared);
    let exit = super::super::unrar::extract::run(
        out,
        archive,
        &opts.shared,
        &selection,
        super::super::unrar::extract::Mode::Test,
        None,
    );
    if exit == Exit::NothingMatched {
        Exit::CannotOpen
    } else {
        exit
    }
}

/// `-tl`: give every file the run wrote the time of its newest member.
///
/// Measured against rar 7.23 on 8 Oct 2026: a single archive and each
/// volume of a set carry the newest modification time among the members,
/// directories counted. Done after the lock and the test, which rewrite
/// and read what was written, and before any source is deleted.
fn date_by_newest(out: &Out, written: &[PathBuf], files: &[Chosen]) -> Exit {
    let Some(newest) = files
        .iter()
        .filter_map(|file| file.mtime)
        .max_by_key(|time| (time.unix_seconds, time.nanos))
    else {
        return Exit::Clean;
    };
    let Ok(seconds) = u64::try_from(newest.unix_seconds) else {
        return Exit::Clean;
    };
    let time = std::time::UNIX_EPOCH + std::time::Duration::new(seconds, newest.nanos);
    let mut exit = Exit::Clean;
    for path in written {
        let dated = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .and_then(|file| file.set_modified(time));
        if let Err(err) = dated {
            out.complain(&format!(
                "Cannot set time for {}\n{}",
                path.display(),
                unrar::io_reason(&err)
            ));
            exit = Exit::Cautioned;
        }
    }
    exit
}

/// `-k`: lock the archive once it is written, through rarkit's own
/// rewrite.
fn lock_written(out: &Out, archive: &str) -> Exit {
    super::edit::lock_archive(out, archive)
}

/// The order the reference deletes in: the reverse of the order it added,
/// except that a directory waits until the last of its own members has
/// gone, because `select::collect` stores a directory AFTER its contents
/// and a plain reversal would put it first.
fn deletion_order(files: &[Chosen]) -> Vec<&Chosen> {
    let reversed: Vec<&Chosen> = files.iter().rev().collect();
    // Where each directory's last member sits in the reversed list.
    let mut release: Vec<Vec<usize>> = vec![Vec::new(); reversed.len()];
    let mut placed = vec![false; reversed.len()];
    for (at, dir) in reversed.iter().enumerate().filter(|(_, f)| f.is_dir) {
        let last = reversed
            .iter()
            .rposition(|f| f.disk != dir.disk && f.disk.starts_with(&dir.disk));
        if let Some(last) = last.filter(|last| *last > at) {
            release[last].push(at);
            placed[at] = true;
        }
    }
    let mut order = Vec::with_capacity(reversed.len());
    for (at, file) in reversed.iter().enumerate() {
        if !placed[at] {
            order.push(*file);
        }
        // Inner directories first: the longer path is the deeper one.
        release[at].sort_by_key(|dir| std::cmp::Reverse(reversed[*dir].disk.as_os_str().len()));
        order.extend(release[at].iter().map(|dir| reversed[*dir]));
    }
    order
}

/// What stands between a finished archive and the deletion of its
/// sources: every file the run wrote, the archive or each volume of the
/// set, is forced to the disk first, by `sync`.
///
/// An unlink is a small change the file system records at once, and the
/// archive's bytes may still be in memory when it does: power lost
/// between the two left the sources gone and the archive short or empty.
/// The sync comes after the test and the lock, which read and rewrite
/// what was written, and before the first unlink. A sync that FAILS
/// keeps every source and is a write error.
///
/// It is paid only by a run that deletes (`m`, `mf`, `-df`, `-dw`). rar
/// 7.23 does not sync here (measured 4 Oct 2026 by an interposed
/// libSystem). Counted the same day on a quiet NVMe drive under Linux:
/// nothing for an archive of 64 MiB and more, which is written past the
/// page cache, and 3 to 18 ms under that.
fn delete_once_synced(
    out: &Out,
    written: &[PathBuf],
    files: &[Chosen],
    opts: &Options,
    mode: AddMode,
    sync: impl Fn(&Path) -> std::io::Result<()>,
) -> Exit {
    for path in written {
        if let Err(err) = sync(path) {
            out.warn(&format!(
                "Cannot write {}\n{}\nrarfast: the archive could not be forced to the disk - \
                 no source was deleted.\n",
                path.display(),
                unrar::io_reason(&err)
            ));
            return Exit::WriteFailed;
        }
    }
    delete_sources(out, files, opts, mode)
}

/// Forces one written file to the disk. Opened for writing, which is
/// what a flush of a file's buffers needs on Windows.
fn sync_written(path: &Path) -> std::io::Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)?
        .sync_all()
}

/// `-df`, `-dw`, and the `m`/`mf` commands: delete the sources.
///
/// Measured against `rar` 7.23: it deletes in the reverse of the order it
/// added, a directory only after its members, and counts every entry,
/// directories included, in the percentage. A directory has a line of its
/// own (`Deleting directory <name>`), and one that is not empty says
/// `NOT DELETED` and warns. `mf` moves files only, so a directory it
/// walked into stays and prints nothing, but it still counts.
///
/// **A file stored EMPTY is looked at again before it goes.** A file of
/// no bytes when it was chosen is stored as no bytes without being
/// opened, so one that was written while the archive was being made
/// would be deleted holding bytes the archive does not have. It is kept
/// instead, named on stderr, and the run answers [`Exit::Cautioned`]. (rar
/// 7.23 reads such a file when it reaches it and stores what it then
/// holds, measured 4 Oct 2026 with the run held at its comment; this
/// keeps the file rather than store it, and loses nothing either way.)
/// The look is one stat, taken only of a file that was empty and only by
/// a run that deletes.
///
/// **NOTHING IS TOUCHED THROUGH A LINK** (SPEC-CLI 8.2, K1 to K4). The
/// walk follows links on purpose, so a path that was archived may be a
/// symbolic link, or lie behind a directory that is one, and what it
/// leads to is a file the user did not hand over:
///
/// - a path that is a link is removed as the link it is, by `-dw` too:
///   nothing is written through it and no mode is changed through it;
/// - a path behind a directory link is neither wiped nor deleted, and the
///   directory link itself is removed as a link (left by `mf`, which
///   leaves every directory).
///
/// CHOSEN DIFFERENCES from rar 7.23, measured 10 Oct 2026: its `-dw`
/// leaves a link's target a file of no bytes, all three of its deletes
/// make a read-only target writable, and under `-r` they delete the files
/// behind a directory link. Until that day `-dw` here wrote zeros over the
/// target and removed only the link, and the files behind a directory
/// link went as they do there.
///
/// The archive still holds what the walk stored, a link's target under
/// the link's name, so a run that left such a target in place says so,
/// once ([`LEFT_IN_PLACE`]).
///
/// The cost is one `lstat` of each path deleted, taken here and never by
/// the walk, and paid only by a run that deletes.
///
/// **A delete that fails is not exit 0**: the run answers
/// [`Exit::Cautioned`]. Until 10 Oct 2026 a tree left half deleted still
/// answered 0. ONE CASE stays 0, as the reference answers it (the
/// selection rows pin it, `m -r -x*.txt s`): a directory kept because it
/// is NOT EMPTY, which is what a tree holding paths the run did not
/// archive ends as. A directory that is not empty because a delete in it
/// failed has that delete's answer already.
fn delete_sources(out: &Out, files: &[Chosen], opts: &Options, mode: AddMode) -> Exit {
    let order = deletion_order(files);
    let total = order.len().max(1) as u64;
    let mut exit = Exit::Clean;
    // The directories that are links: what lies behind one is not ours.
    let links: Vec<&Path> = order
        .iter()
        .filter(|file| file.is_dir && is_link(&file.disk))
        .map(|file| file.disk.as_path())
        .collect();
    // And the directory links on the way to a path below the run, however
    // the path was named ([`LinksOnTheWay`]); the ones that are no path of
    // the run are removed as links once the loop is done.
    let mut on_the_way = LinksOnTheWay::new();
    let mut found: Vec<PathBuf> = Vec::new();
    // Whether a file behind a directory link was passed over, and where
    // each file link that was removed led: such a target is "left in
    // place" only if it is still there when the run is over (a target
    // inside the named tree goes as the path it is).
    let mut passed_over = false;
    let mut led_to: Vec<PathBuf> = Vec::new();
    for (done, file) in order.iter().enumerate() {
        if let Some(link) = on_the_way.topmost(&file.disk) {
            passed_over |= !file.is_dir;
            if !found.contains(&link) && !order.iter().any(|entry| entry.disk == link) {
                found.push(link);
            }
            continue;
        }
        if links
            .iter()
            .any(|link| file.disk != *link && file.disk.starts_with(link))
        {
            passed_over |= !file.is_dir;
            continue;
        }
        if file.is_dir && mode == AddMode::MoveFiles {
            continue;
        }
        let link = if file.is_dir {
            links.contains(&file.disk.as_path())
        } else {
            is_link(&file.disk)
        };
        if link && !file.is_dir {
            led_to.extend(std::fs::canonicalize(&file.disk));
        }
        if !file.is_dir
            && !link
            && file.size == 0
            && std::fs::symlink_metadata(&file.disk).is_ok_and(|now| now.len() != 0)
        {
            out.warn(&format!(
                "rarfast: {} was empty when it was archived and holds bytes now - it was \
                 stored empty and is NOT deleted.\n",
                file.shown
            ));
            exit = Exit::Cautioned;
            continue;
        }
        let percent = (done as u64 + 1).saturating_mul(100) / total;
        let removed = if link {
            remove_link(&file.disk, file.is_dir)
        } else if file.is_dir {
            std::fs::remove_dir(&file.disk)
        } else if opts.wipe_after {
            wipe(&file.disk)
        } else {
            std::fs::remove_file(&file.disk)
        };
        let gone = removed.is_ok();
        if file.is_dir {
            out.say(&lines::deleted_directory(&file.shown, percent, gone));
        } else if gone {
            out.say(&lines::deleted(&file.shown, percent));
        }
        if let Err(err) = removed {
            // A complaint like the creator's others, in their layout:
            // each opens its own line whatever was said before it
            // (measured 4 Oct 2026 after a `Cannot open`, whose last
            // line the first of these used to be written onto).
            out.complain(&format!(
                "Cannot delete {}\n{}",
                file.shown,
                unrar::io_reason(&err)
            ));
            if !(file.is_dir && err.kind() == std::io::ErrorKind::DirectoryNotEmpty) {
                exit = Exit::Cautioned;
            }
        }
    }
    // A link found on the way is removed as the link it is (K3), and left
    // by `mf`, which leaves every directory.
    if mode != AddMode::MoveFiles {
        for link in &found {
            let removed = remove_link(link, true);
            let shown = link.display().to_string();
            out.say(&lines::deleted_directory(&shown, 100, removed.is_ok()));
            if let Err(err) = removed {
                out.complain(&format!(
                    "Cannot delete {shown}\n{}",
                    unrar::io_reason(&err)
                ));
                exit = Exit::Cautioned;
            }
        }
    }
    if passed_over || led_to.iter().any(|target| target.exists()) {
        out.warn(LEFT_IN_PLACE);
    }
    exit
}

/// The one line of a run that left a link's target where it was although
/// the archive holds its bytes (SPEC-CLI 8.2, K4). Never printed under
/// `-ol`, where no such bytes are stored: the creator refuses `-ol`
/// before anything is written.
const LEFT_IN_PLACE: &str =
    "rarfast: a symbolic link is removed as a link - what the links of this \
                             run lead to was archived and is left in place, not deleted.\n";

/// Whether `path` itself is a symbolic link: one `lstat`, following
/// nothing. A path that cannot be looked at is not one, and its delete
/// then says why.
fn is_link(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())
}

/// Removes the link at `path` and nothing it leads to. `directory` is
/// whether it leads to one, which is how Windows wants it removed.
fn remove_link(path: &Path, directory: bool) -> std::io::Result<()> {
    if cfg!(windows) && directory {
        std::fs::remove_dir(path)
    } else {
        std::fs::remove_file(path)
    }
}

/// The DIRECTORY LINKS on the way to a path, at or below the folder the
/// run is in: the owner's rule of 27 Oct 2026. However a path was named
/// (`dirlink/`, `dirlink/*`, `dirlink/one.bin`, or met by the walk), a
/// directory above it that is a symbolic link puts it behind that link,
/// and what lies behind a link is archived and never deleted or wiped.
/// Until that day a link named with a trailing slash, a mask through a
/// link and a file named through one were all deleted through it, exit
/// 0, nothing said (a look at `dirlink/` resolves the link, and the link
/// itself was no path of the run).
///
/// A linked folder ABOVE the run (`/tmp` on macOS) is an ordinary part of
/// the user's path and is never looked at: a relative path's directories
/// are all below the run, and an absolute path's are only where they lie
/// lexically inside it. Each directory is looked at once, by one `lstat`.
struct LinksOnTheWay {
    /// The folder the run is in, as the system gives it.
    run_in: Option<PathBuf>,
    /// Each directory looked at, and whether it is a link.
    seen: std::collections::HashMap<PathBuf, bool>,
}

impl LinksOnTheWay {
    fn new() -> LinksOnTheWay {
        LinksOnTheWay {
            run_in: std::env::current_dir().ok(),
            seen: std::collections::HashMap::new(),
        }
    }

    /// Whether `dir`, a directory on the way to a path, lies below the
    /// folder the run is in.
    fn below_the_run(&self, dir: &Path) -> bool {
        if dir.as_os_str().is_empty() {
            return false;
        }
        if dir.is_relative() {
            return !dir
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir));
        }
        self.run_in
            .as_deref()
            .is_some_and(|run_in| dir != run_in && dir.starts_with(run_in))
    }

    /// The topmost directory link on the way to `path` below the run, if
    /// any: the directories above `path`, not `path` itself.
    fn topmost(&mut self, path: &Path) -> Option<PathBuf> {
        let above: Vec<&Path> = path.parent()?.ancestors().collect();
        for dir in above.into_iter().rev() {
            if !self.below_the_run(dir) {
                continue;
            }
            let link = *self
                .seen
                .entry(dir.to_path_buf())
                .or_insert_with(|| is_link(dir));
            if link {
                return Some(dir.to_path_buf());
            }
        }
        None
    }
}

/// `-dw`: overwrite a file's bytes before unlinking it, so that what was
/// archived is not left readable on the disk.
///
/// The zeros are SYNCED before the unlink. Without that they sit in the
/// page cache of a file that is then removed, the system is free to
/// drop them, and the bytes that were to be wiped stay on the medium.
/// rar 7.23 syncs each wiped file too (measured 4 Oct 2026 by an
/// interposed libSystem: an fsync of the file, then its rename to a
/// temporary name, then the unlink). The cost is `-dw`'s alone.
fn wipe(path: &Path) -> std::io::Result<()> {
    // The path ITSELF, following nothing: a link is removed as a link and
    // nothing is written through it (SPEC-CLI 8.2, K1 and K2). The caller
    // has looked already; this look is the wipe's own, so that no caller
    // can send zeros through a link.
    let named = std::fs::symlink_metadata(path)?;
    if named.file_type().is_symlink() {
        return std::fs::remove_file(path);
    }
    let length = named.len();
    {
        let open = || {
            let file = std::fs::OpenOptions::new().write(true).open(path)?;
            same_file(&named, &file)?;
            Ok::<_, std::io::Error>(file)
        };
        let mut file = match open() {
            // A read-only source is wiped all the same, as the reference
            // wipes it (measured 8 Oct 2026, a file of mode 0444): it is
            // made writable first. Until then it was left where it was,
            // unwiped. A file that cannot be made writable keeps the
            // first refusal.
            Err(refused) if refused.kind() == std::io::ErrorKind::PermissionDenied => {
                if make_writable(path, &named).is_err() {
                    return Err(refused);
                }
                open()?
            }
            opened => opened?,
        };
        let zeros = vec![0_u8; 1 << 16];
        let mut left = length;
        while left > 0 {
            let want = left.min(zeros.len() as u64) as usize;
            file.write_all(&zeros[..want])?;
            left -= want as u64;
        }
        file.sync_all()?;
    }
    std::fs::remove_file(path)
}

/// Refuses an opened file that is not the one `named` was read from: the
/// name was given to something else, a link among them, between the look
/// and the open, and nothing is written to that. On Unix the two are
/// compared by device and inode; elsewhere the look alone stands.
fn same_file(named: &std::fs::Metadata, opened: &std::fs::File) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let now = opened.metadata()?;
        if now.dev() != named.dev() || now.ino() != named.ino() {
            return Err(std::io::Error::other(
                "the file to wipe was replaced while it was being opened",
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = (named, opened);
    Ok(())
}

/// Lets the owner write a file that is about to be wiped: the file
/// `named` was read from, never one a link at the path leads to. On Unix
/// the bit goes on through a handle that is checked to be that file.
fn make_writable(path: &Path, named: &std::fs::Metadata) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let held = std::fs::File::open(path)?;
        same_file(named, &held)?;
        let mode = named.permissions().mode() | 0o200;
        held.set_permissions(std::fs::Permissions::from_mode(mode))
    }
    // Off a unix host the one bit there is, is the read-only attribute,
    // and clearing it is the whole of what is meant: the lint's warning
    // is about a unix mode, which the arm above sets bit by bit.
    #[cfg(not(unix))]
    {
        let mut permissions = named.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
        std::fs::set_permissions(path, permissions)
    }
}

#[cfg(test)]
mod sync_before_delete_tests;

#[cfg(test)]
mod workers_tests;

/// Since 21 Sep 2026 `-mm<size>` sets BOTH
/// `MemoryPolicy::max_dictionary` and `MemoryPolicy::working_limit`, so
/// the shipped tool can reach SPEC-G 3.5 case (b)'s budgeted create mode
/// - before this change no `rarkit-cli` invocation ever set a
/// `working_limit` other than the default, and that door was unreachable
/// from the command line whatever `-mm` was given.
#[cfg(test)]
mod mm_working_limit_tests;

#[cfg(test)]
mod direct_output_tests;

#[cfg(test)]
mod report_percent_tests;

#[cfg(test)]
mod cold_window_tests;
