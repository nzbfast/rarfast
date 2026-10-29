//! The creator's remaining commands: the comment writer, the volume
//! reconstructor and the two SFX spellings.
//!
//! Written from `rar` 7.23's observable behaviour on an Apple Silicon Mac. Three of
//! the four answer the cases the conformance table exercises out of what
//! rarkit's READ API already knows, and each refuses by name the moment it
//! would have to write something it cannot:
//!
//! - `cw` reads the archive comment, which `Archive::comment` answers, and
//!   writes it to the named file or to standard output;
//! - `rc` restores a set's missing volumes from its recovery volumes, and
//!   is in `restore.rs`;
//! - `s-` asks whether the archive carries a self-extracting stub, which
//!   is whether its first block starts at byte zero.
//!
//! `rv` and `s` write, and what they would write is named in the refusal.

use super::super::unrar::{self, Exit, Out};
use super::args::RecoveryVolumes;
use std::path::Path;

use super::create::unbuilt;

/// `cw <archive> [file]`: write the archive comment out.
///
/// Measured: with no comment the whole answer is `Comment is not present`
/// and exit 0, whatever the target; with one and a target named, the
/// answer is `Write comment to <file>` and the comment lands in the file;
/// with one and no target, the comment goes to standard output.
///
/// The archive is opened with the password the line gives (`-p` or
/// `-hp`), which an archive whose headers are encrypted needs before its
/// comment can be read at all. Measured, 8 Oct 2026: with the right one
/// the reference writes the comment, exit 0; with a wrong one it says
/// `Incorrect password for <archive>` and exits 13. The words are the
/// same here and the exit is this tool's own for a wrong password, 11,
/// as every other command gives it; with no password on the line the
/// answer is as it was, exit 10.
pub(crate) fn comment_write(
    out: &Out,
    archive: &str,
    target: Option<&str>,
    password: Option<&str>,
) -> Exit {
    let opened = match unrar::open(archive, password.map(str::as_bytes)) {
        Ok(opened) => opened,
        Err(failure) => {
            out.complain(failure.text().trim_matches('\n'));
            return match failure {
                unrar::OpenFailure::BadPassword(_) if password.is_some() => Exit::WrongPassword,
                _ => Exit::NothingMatched,
            };
        }
    };
    let Some(comment) = opened.archive_comment().filter(|bytes| !bytes.is_empty()) else {
        out.say("\nComment is not present\n");
        return Exit::Clean;
    };
    match target {
        Some(path) => {
            // The reference makes the directories the target names, a
            // `Creating` line each, and says `Write comment to` only once
            // the file is written; a target it cannot create gets the
            // complaint and exit 9 and no such line (measured against rar
            // 7.23, 30 Sep 2026, into `nodir/c.txt`, `nodir/sub/c.txt` and
            // a directory of mode 500).
            make_parents(out, Path::new(path));
            if let Err(err) = std::fs::write(path, &comment) {
                out.complain(&format!("Cannot create {path}\n{}", unrar::io_reason(&err)));
                return Exit::CannotCreate;
            }
            out.say(&format!("Write comment to {path}\n"));
            Exit::Clean
        }
        None => {
            out.say(&format!("\n{}\n", unrar::comment_text(&comment)));
            Exit::Clean
        }
    }
}

/// Makes each directory above `path` that is not there yet, outermost
/// first, with the reference's `Creating` line for each. One that cannot
/// be made is left to the write after it to report.
fn make_parents(out: &Out, path: &Path) {
    let Some(parent) = path.parent() else {
        return;
    };
    let mut missing: Vec<&Path> = parent
        .ancestors()
        .take_while(|dir| !dir.as_os_str().is_empty() && !dir.exists())
        .collect();
    missing.reverse();
    for dir in missing {
        if std::fs::create_dir(dir).is_err() {
            return;
        }
        out.say(&format!(
            "{:<70}OK\n",
            format!("Creating    {}", dir.display())
        ));
    }
}

/// Whether `archive` says it is one volume of a set, or the exit an open
/// failure answers with.
///
/// Measured over `nosuch.part1.rar`: both `rc` and `rv` print nothing on
/// stdout, `Cannot open nosuch.part1.rar` and the reason on stderr, and
/// exit 10.
fn volume_of(out: &Out, archive: &str) -> Result<bool, Exit> {
    match unrar::open(archive, None) {
        Ok(opened) => Ok(opened.is_volume),
        Err(failure) => {
            out.complain(failure.text().trim_matches('\n'));
            Err(Exit::NothingMatched)
        }
    }
}

/// `rv[N] <archive>`: write `.rev` files beside an existing volume set,
/// within `memory_cap`, the run's named `-mm<size>` if it has one.
pub(crate) fn add_recovery_volumes(
    out: &Out,
    archive: &str,
    count: RecoveryVolumes,
    memory_cap: Option<u64>,
) -> Exit {
    let volume = match volume_of(out, archive) {
        Ok(volume) => volume,
        Err(exit) => return exit,
    };
    if !volume {
        // Measured: `rar rv1 arc.rar` over an archive that is not one
        // volume of a set answers `<name> is not volume` ON STDERR and
        // exits 0, and there is nothing for a rev5 writer to do. The
        // stream matters: the conformance rows compare the two
        // separately, and this line was on stdout until the row said
        // otherwise.
        out.warn(&format!("\n{archive} is not volume\n"));
        return Exit::Clean;
    }
    if !is_first_volume(archive) {
        // Measured, 4 Oct 2026: `rar rv2 arc.part2.rar` over a set of
        // three prints nothing on stdout, this on stderr, writes no
        // `.rev` file and exits 0. The recovery volumes are the whole
        // set's and carry its names, so they are built from its first
        // volume or not at all.
        out.warn(&format!("\n{archive} is not the first volume\n"));
        return Exit::Clean;
    }
    write_recovery_volumes(out, archive, count, memory_cap)
}

/// Whether `archive`'s own headers say it is its set's first volume. An
/// archive that does not open here is left to the caller's own open to
/// complain about.
fn is_first_volume(archive: &str) -> bool {
    rarkit::Session::new(rarkit::ReadOptions::default().with_tolerant_tail(true))
        .open_path(std::path::Path::new(archive))
        .map_or(true, |opened| opened.volume().is_first)
}

/// The `.rev` files themselves, over the set `archive` is the first
/// volume of (SPEC-L 3.6, through `rarkit::rev5::create`).
///
/// The set is walked by NAME from the volume the caller gave, taking
/// every volume that is actually there, because that is the set a `.rev`
/// file's table has to describe: its header carries every data volume's
/// length and CRC32, so a set walked wrong produces recovery files that
/// cover an archive nobody has.
fn write_recovery_volumes(
    out: &Out,
    archive: &str,
    count: RecoveryVolumes,
    memory_cap: Option<u64>,
) -> Exit {
    // Where the set's own number stands in the first volume's name, when
    // the set is named by one (SPEC-L 3.6.4, V1); a set of the old names
    // (`set.rar`, `set.r00`) is walked and named as before.
    let numbered = SetNumber::of(archive).filter(|_| !old_names_follow(archive));
    let mut paths = vec![archive.to_string()];
    loop {
        let last = paths.last().expect("a first volume");
        let next = match &numbered {
            Some(number) => number.volume(paths.len() as u64 + number.first),
            None => crate::dialect::unrar::extract::next_volume_name(last),
        };
        match next {
            Some(next) if std::path::Path::new(&next).exists() => paths.push(next),
            _ => break,
        }
    }
    // V6: a set whose names do not agree gets no recovery volume, exit 0.
    // The last volume found by name says another follows: the first was
    // renamed alone, or the rest were. The reference says nothing at all
    // (rar 7.23 for macOS, 10 Oct 2026); the one line is rarfast's own.
    if numbered.is_some() && another_follows(paths.last().expect("a first volume")) {
        out.warn(&format!(
            "\n{archive}: the set's volumes are not all found by this name, no recovery volume is written\n"
        ));
        return Exit::Clean;
    }

    let mut data: Vec<std::sync::Arc<dyn rarkit::RangeSource>> = Vec::with_capacity(paths.len());
    let mut largest = 0u64;
    for path in &paths {
        match std::fs::File::open(path) {
            Ok(file) => {
                largest = largest.max(file.metadata().map_or(0, |meta| meta.len()));
                data.push(std::sync::Arc::new(file));
            }
            Err(err) => {
                out.complain(&format!("Cannot open {path}\n{}", unrar::io_reason(&err)));
                return Exit::NothingMatched;
            }
        }
    }

    let policy = match count {
        RecoveryVolumes::Default => rarkit::RevCount::Default,
        RecoveryVolumes::Count(n) => rarkit::RevCount::Exactly(n.min(u64::from(u32::MAX)) as u32),
        RecoveryVolumes::Percent(p) => rarkit::RevCount::Percent(p.min(u64::from(u32::MAX)) as u32),
    };
    let wanted = match policy.resolve(paths.len() as u32) {
        Ok(wanted) => wanted,
        Err(err) => {
            out.warn(&format!("\n{archive}: {err}\n"));
            return Exit::Aborted;
        }
    };

    if let Some(exit) = refuse_for_named_memory(out, archive, largest, memory_cap) {
        return exit;
    }

    // SPEC-L 3.6.4, V1 to V4: recovery row `i` has the first volume's
    // name with its number made `i + 1`, at that number's own count of
    // digits, and `.rev` for all that follows the number. A set of the
    // old names keeps the rule it had: `<stem>.part<i+1>.rev` at the
    // width of the count of data volumes (V7's one row is not built).
    let names = match numbered {
        Some(number) => RevNames::Numbered(number),
        None => RevNames::Stem {
            base: rev_set_stem(archive),
            width: paths.len().to_string().len(),
        },
    };
    let rev_path_for_row = |row: u32| names.row(row);

    // The reference prints one `Creating` line per recovery volume BEFORE
    // it builds any of them, and hangs its one counter off the last of
    // them: `  0%` and `100%`, measured over sets of one, two, three and
    // five recovery volumes.
    out.say("\n");
    for row in 0..wanted {
        out.say(&format!("Creating {}", rev_path_for_row(row)));
        if row + 1 < wanted {
            out.say("\n");
        }
    }
    out.say("     ");

    let mut sink = RecoveryRowSink {
        names: &names,
        failure: None,
    };
    // A named `-mm` is the encoder's policy too, so the rows it holds at
    // once stay inside that budget's repair share; with none, as before.
    let options = rarkit::rev5::RevOptions {
        memory: memory_cap.map_or_else(rarkit::MemoryPolicy::default, super::repair::repair_policy),
    };
    let built = rarkit::rev5::create(&data, wanted, &options, &mut sink);
    if built.is_err() || sink.failure.is_some() {
        let reason = sink
            .failure
            .unwrap_or_else(|| "the recovery volumes could not be built".to_owned());
        out.say("\n");
        out.warn(&format!("\nCannot write {}\n{reason}\n", names.row(0)));
        return Exit::WriteFailed;
    }
    out.say(&super::lines::counter(0));
    out.say(&super::lines::counter(100));
    out.say("\n");
    out.say("Done\n");
    Exit::Clean
}

/// The encoder's fixed read buffer: it reads each data volume this much
/// at a time, beside the parity it holds (`rarkit::rev5::create`).
const REV_READ_BUFFER: u64 = 1 << 20;

/// Under a NAMED `-mm<size>`, recovery volume creation is bounded by that
/// size. One recovery volume is the largest data volume's length made
/// even (SPEC-L 3.6), and the
/// encoder holds at least one whole volume of parity and its read buffer
/// at once; when that cannot fit inside the named size, the run is refused
/// here, before any line or file is written, by name and with the code for
/// not enough memory. With no `-mm` named nothing changes.
fn refuse_for_named_memory(
    out: &Out,
    archive: &str,
    largest: u64,
    memory_cap: Option<u64>,
) -> Option<Exit> {
    let cap = memory_cap?;
    let needed = largest
        .saturating_add(largest % 2)
        .saturating_add(REV_READ_BUFFER);
    if needed <= cap {
        return None;
    }
    out.warn(&format!(
        "\n{archive}: no recovery volume is written: one recovery volume needs {needed} bytes \
         of working memory, its parity and the encoder's read buffer, and -mm names {cap}. \
         -mm{}m or more lets it run.\n",
        needed.div_ceil(1 << 20)
    ));
    Some(Exit::OutOfMemory)
}

/// The stem a set's `.rev` files are named from: the first volume's path
/// with its `.partN` and its extension taken off, so `set.part1.rar` and
/// `set.r00` both give `set`.
///
/// Measured: `rar rv2 set.part1.rar` writes `set.part1.rev` and
/// `set.part2.rev`, NOT `set.part1.part1.rev`.
fn rev_set_stem(archive: &str) -> String {
    // Only the file name is cut; a directory may hold dots of its own.
    let name_at = archive.rfind(['/', '\\']).map_or(0, |slash| slash + 1);
    let (directory, name) = archive.split_at(name_at);
    let before_extension = name.rfind('.').map_or(name, |dot| &name[..dot]);
    // What is left ends `.part<digits>` when its last dot is followed by
    // the word and then by digits alone, at least one.
    let stem = match before_extension.rfind('.') {
        Some(dot) => {
            let tail = &before_extension[dot + 1..];
            let word = tail
                .get(..4)
                .is_some_and(|w| w.eq_ignore_ascii_case("part"));
            let number = tail.get(4..).unwrap_or("");
            if word && !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()) {
                &before_extension[..dot]
            } else {
                before_extension
            }
        }
        None => before_extension,
    };
    format!("{directory}{stem}")
}

/// The path of recovery row `row`, counted from zero: `<base>.part<row +
/// 1>.rev`, the number zero padded to `width` digits and never cut to it.
fn rev_row_path(base: &str, width: usize, row: u32) -> String {
    let number = u64::from(row) + 1;
    format!("{base}.part{number:0width$}.rev")
}

/// The number a set is named by, read out of its first volume's name as
/// that name stands on disk (SPEC-L 3.6.4, V1 to V4 and V9): the name is
/// taken apart at the run of digits V9 says is the number. A later
/// volume is the same name with another number there; a recovery volume
/// is the name as far as the number, another number, and `.rev`, so
/// what stood after the number is not in it (V1). Everything in front
/// of the number is kept as it is, word, case and dots; the count of
/// digits is kept as the least a number is written with (V3).
pub(super) struct SetNumber {
    /// The path up to the number, directory included.
    pub(super) head: String,
    /// The first volume's number as written.
    first: u64,
    /// How many digits it is written with.
    pub(super) width: usize,
    /// What follows the number in a volume's name.
    pub(super) tail: String,
}

impl SetNumber {
    pub(super) fn of(archive: &str) -> Option<SetNumber> {
        // Only the file name is read; a directory may hold digits of its
        // own.
        let name_at = archive.rfind(['/', '\\']).map_or(0, |slash| slash + 1);
        let name = &archive.as_bytes()[name_at..];
        // Which digits are the number (V9). It is the last run of digits
        // in the name, unless a dot stands somewhere in front of that
        // run and, between the nearest such dot and the run, there are
        // digits again: then it is the nearest of those, the run before
        // the last. A name with no digit has no number.
        let run_ending = |end: usize| {
            let start = name[..end]
                .iter()
                .rposition(|byte| !byte.is_ascii_digit())
                .map_or(0, |before| before + 1);
            (start, end)
        };
        let last = run_ending(name.iter().rposition(u8::is_ascii_digit)? + 1);
        let (start, end) = name[..last.0]
            .iter()
            .rposition(|&byte| byte == b'.')
            .and_then(|dot| {
                let between = &name[dot + 1..last.0];
                let digit = between.iter().rposition(u8::is_ascii_digit)?;
                Some(run_ending(dot + 1 + digit + 1))
            })
            .unwrap_or(last);
        let (start, end) = (name_at + start, name_at + end);
        Some(SetNumber {
            head: archive[..start].to_owned(),
            first: archive[start..end].parse().ok()?,
            width: end - start,
            tail: archive[end..].to_owned(),
        })
    }

    /// The name of the set's volume numbered `number`.
    pub(super) fn volume(&self, number: u64) -> Option<String> {
        let width = self.width;
        Some(format!("{}{number:0width$}{}", self.head, self.tail))
    }

    /// The name of recovery row `row`, counted from zero (V1 to V4).
    fn recovery(&self, row: u32) -> String {
        let (number, width) = (u64::from(row) + 1, self.width);
        format!("{}{number:0width$}.rev", self.head)
    }
}

/// Whether `archive` is the first of a set of the OLD names: it ends
/// `.rar` and the `.r00` its next volume would have is there.
fn old_names_follow(archive: &str) -> bool {
    archive.rsplit_once('.').is_some_and(|(stem, extension)| {
        extension.eq_ignore_ascii_case("rar")
            && std::path::Path::new(&format!("{stem}.r00")).exists()
    })
}

/// Whether the volume at `path` says another volume follows it. One that
/// does not open, or does not say, is taken as the last.
pub(super) fn another_follows(path: &str) -> bool {
    rarkit::Session::new(rarkit::ReadOptions::default().with_tolerant_tail(true))
        .open_path(std::path::Path::new(path))
        .is_ok_and(|opened| opened.volume().next_follows == Some(true))
}

/// How a set's recovery volumes are named.
enum RevNames {
    /// From the number in the first volume's name (SPEC-L 3.6.4, V1 to
    /// V4).
    Numbered(SetNumber),
    /// `<base>.part<row + 1>.rev` at `width` digits: a set of the old
    /// names.
    Stem { base: String, width: usize },
}

impl RevNames {
    fn row(&self, row: u32) -> String {
        match self {
            RevNames::Numbered(number) => number.recovery(row),
            RevNames::Stem { base, width } => rev_row_path(base, *width, row),
        }
    }
}

/// Writes each recovery row to the name [`RevNames`] gives it.
struct RecoveryRowSink<'a> {
    names: &'a RevNames,
    failure: Option<String>,
}

impl rarkit::VolumeOut for RecoveryRowSink<'_> {
    type W = std::fs::File;

    fn volume(&mut self, index: u32) -> rarkit::Result<std::fs::File> {
        let path = self.names.row(index);
        std::fs::File::create(&path).map_err(|err| {
            // The first file that could not be made is the one reported.
            self.failure.get_or_insert_with(|| unrar::io_reason(&err));
            rarkit::Error::from(err)
        })
    }
}

/// `s[-|<module>] <archive>`: convert an archive to a self-extractor, or
/// strip the module from one.
pub(crate) fn sfx(out: &Out, archive: &str, remove: bool, _module: Option<&str>) -> Exit {
    if !remove {
        return unbuilt(
            out,
            "s",
            archive,
            "a self-extracting module to graft: rarkit writes no executable stub and this \
             crate carries none",
        );
    }
    // Measured over `nosuch.rar`: `Removing SFX module` and `Done` on
    // stdout with no `Converting` line between them, the open failure on
    // stderr, exit 10. On ONE stream (`-ierr`, measured 30 Sep 2026) the
    // open failure comes FIRST, so the open is made before either line.
    let mut session = rarkit::Session::new(rarkit::ReadOptions::default());
    let opened = session.open_path(std::path::Path::new(archive));
    if let Err(err) = &opened {
        let reason = match err.kind() {
            rarkit::ErrorKind::Source(io) => unrar::io_reason(io),
            _ => format!("{err}"),
        };
        out.complain(&format!("Cannot open {archive}\n{reason}"));
    }
    out.say("\nRemoving SFX module\n");
    let Ok(opened) = opened else {
        out.say("Done\n");
        return Exit::NothingMatched;
    };
    out.say(&format!("Converting {archive}\n"));
    // A self-extracting archive's blocks sit BEHIND an executable stub, so
    // the archive starting at byte zero is the whole question.
    if opened.start() == 0 {
        out.say(&format!("{archive} is not SFX archive\nDone\n"));
        return Exit::Clean;
    }
    unbuilt(
        out,
        "s-",
        archive,
        "a rewrite that lifts an archive out from behind its stub, which rarkit's `edit` \
         refuses for the same reason it refuses to write one",
    )
}

#[cfg(test)]
mod tests {
    use super::{rev_row_path, rev_set_stem, RevNames, SetNumber};

    /// The names rarkit gives `count` recovery volumes of a set whose first
    /// volume is `first` and which has `volumes` data volumes: by the
    /// number in that name where it has one (the file system is not
    /// asked here whether the set is one of the old names).
    fn names(first: &str, volumes: usize, count: u32) -> Vec<String> {
        let names = match SetNumber::of(first) {
            Some(number) => RevNames::Numbered(number),
            None => RevNames::Stem {
                base: rev_set_stem(first),
                width: volumes.to_string().len(),
            },
        };
        (0..count).map(|row| names.row(row)).collect()
    }

    /// (first volume as named to `rv`, data volumes present, the first,
    /// second and last recovery volume the reference wrote, how many).
    type Row = (&'static str, usize, [&'static str; 3], u32);

    /// MEASURED with rar 7.23 on macOS arm64, 10 Oct 2026: `rar rv<N>` and
    /// `rar a -rv<N>` over sets of 3, 7, 10, 11 and 112 volumes under many
    /// set names, and over sets renamed after they were written. Every
    /// row here is one where the reference's file names are the ones
    /// rarkit's rule gives. A set with one recovery volume repeats its
    /// name in the second place. No pool, no memory.
    const SAME_AS_THE_REFERENCE: &[Row] = &[
        (
            "arc.part1.rar",
            7,
            ["arc.part1.rev", "arc.part2.rev", "arc.part2.rev"],
            2,
        ),
        (
            "my.set.part1.rar",
            7,
            ["my.set.part1.rev", "my.set.part2.rev", "my.set.part2.rev"],
            2,
        ),
        (
            "a.b.c.part1.rar",
            7,
            ["a.b.c.part1.rev", "a.b.c.part2.rev", "a.b.c.part2.rev"],
            2,
        ),
        (
            "arc.part1.part1.rar",
            7,
            [
                "arc.part1.part1.rev",
                "arc.part1.part2.rev",
                "arc.part1.part2.rev",
            ],
            2,
        ),
        (
            "arc.part07.part1.rar",
            7,
            [
                "arc.part07.part1.rev",
                "arc.part07.part2.rev",
                "arc.part07.part2.rev",
            ],
            2,
        ),
        (
            "UPPER.part1.RAR",
            7,
            ["UPPER.part1.rev", "UPPER.part2.rev", "UPPER.part2.rev"],
            2,
        ),
        (
            "arc.PART1.part1.RAR",
            7,
            [
                "arc.PART1.part1.rev",
                "arc.PART1.part2.rev",
                "arc.PART1.part2.rev",
            ],
            2,
        ),
        (
            "name with space.part1.rar",
            7,
            [
                "name with space.part1.rev",
                "name with space.part2.rev",
                "name with space.part2.rev",
            ],
            2,
        ),
        (
            "arc.tar.part1.rar",
            7,
            [
                "arc.tar.part1.rev",
                "arc.tar.part2.rev",
                "arc.tar.part2.rev",
            ],
            2,
        ),
        (
            "x.part.part1.rar",
            7,
            ["x.part.part1.rev", "x.part.part2.rev", "x.part.part2.rev"],
            2,
        ),
        (
            "arc.partX.part1.rar",
            7,
            [
                "arc.partX.part1.rev",
                "arc.partX.part2.rev",
                "arc.partX.part2.rev",
            ],
            2,
        ),
        (
            "1.part1.rar",
            7,
            ["1.part1.rev", "1.part2.rev", "1.part2.rev"],
            2,
        ),
        (
            "arc.001.part1.rar",
            7,
            [
                "arc.001.part1.rev",
                "arc.001.part2.rev",
                "arc.001.part2.rev",
            ],
            2,
        ),
        (
            ".hidden.part1.rar",
            7,
            [
                ".hidden.part1.rev",
                ".hidden.part2.rev",
                ".hidden.part2.rev",
            ],
            2,
        ),
        (
            "arc..part1.rar",
            7,
            ["arc..part1.rev", "arc..part2.rev", "arc..part2.rev"],
            2,
        ),
        (
            "w.part1.rar",
            3,
            ["w.part1.rev", "w.part1.rev", "w.part1.rev"],
            1,
        ),
        (
            "w.part1.rar",
            7,
            ["w.part1.rev", "w.part2.rev", "w.part3.rev"],
            3,
        ),
        (
            "w.part01.rar",
            10,
            ["w.part01.rev", "w.part02.rev", "w.part03.rev"],
            3,
        ),
        (
            "w.part01.rar",
            11,
            ["w.part01.rev", "w.part02.rev", "w.part12.rev"],
            12,
        ),
        (
            "w.part001.rar",
            112,
            ["w.part001.rev", "w.part002.rev", "w.part003.rev"],
            3,
        ),
        (
            "w.part001.rar",
            112,
            ["w.part001.rev", "w.part002.rev", "w.part015.rev"],
            15,
        ),
        (
            "pct.part1.rar",
            7,
            ["pct.part1.rev", "pct.part2.rev", "pct.part2.rev"],
            2,
        ),
        (
            "bare.part1.rar",
            7,
            ["bare.part1.rev", "bare.part1.rev", "bare.part1.rev"],
            1,
        ),
        (
            "cr.part1.rar",
            7,
            ["cr.part1.rev", "cr.part2.rev", "cr.part2.rev"],
            2,
        ),
        (
            "cr.two.part1.rar",
            7,
            ["cr.two.part1.rev", "cr.two.part2.rev", "cr.two.part2.rev"],
            2,
        ),
        (
            "cr.part1.part1.rar",
            7,
            [
                "cr.part1.part1.rev",
                "cr.part1.part2.rev",
                "cr.part1.part2.rev",
            ],
            2,
        ),
        (
            "crw.part001.rar",
            112,
            ["crw.part001.rev", "crw.part002.rev", "crw.part012.rev"],
            12,
        ),
        (
            "old.part1.rar",
            7,
            ["old.part1.rev", "old.part2.rev", "old.part2.rev"],
            2,
        ),
        (
            "old.set.part1.rar",
            7,
            [
                "old.set.part1.rev",
                "old.set.part2.rev",
                "old.set.part2.rev",
            ],
            2,
        ),
        (
            "o.part1.part1.rar",
            7,
            [
                "o.part1.part1.rev",
                "o.part1.part2.rev",
                "o.part1.part2.rev",
            ],
            2,
        ),
        (
            "OLD.part1.RAR",
            7,
            ["OLD.part1.rev", "OLD.part2.rev", "OLD.part2.rev"],
            2,
        ),
        (
            "oldc.part1.rar",
            7,
            ["oldc.part1.rev", "oldc.part2.rev", "oldc.part2.rev"],
            2,
        ),
        (
            "oldw.part001.rar",
            112,
            ["oldw.part001.rev", "oldw.part002.rev", "oldw.part003.rev"],
            3,
        ),
        (
            "oldw2.part001.rar",
            112,
            [
                "oldw2.part001.rev",
                "oldw2.part002.rev",
                "oldw2.part012.rev",
            ],
            12,
        ),
        (
            "set.part1.rar",
            7,
            ["set.part1.rev", "set.part2.rev", "set.part12.rev"],
            12,
        ),
        (
            "set.part1.rar",
            7,
            ["set.part1.rev", "set.part2.rev", "set.part9.rev"],
            9,
        ),
        (
            "set.part1.rar",
            7,
            ["set.part1.rev", "set.part2.rev", "set.part10.rev"],
            10,
        ),
        (
            "set.part01.rar",
            11,
            ["set.part01.rev", "set.part02.rev", "set.part02.rev"],
            2,
        ),
        (
            "set.part01.rar",
            11,
            ["set.part01.rev", "set.part02.rev", "set.part100.rev"],
            100,
        ),
        (
            "sub/set.part1.rar",
            7,
            [
                "sub/set.part1.rev",
                "sub/set.part2.rev",
                "sub/set.part2.rev",
            ],
            2,
        ),
        (
            "./set.part1.rar",
            7,
            ["./set.part1.rev", "./set.part2.rev", "./set.part2.rev"],
            2,
        ),
        (
            "d.part1/x.part1.rar",
            7,
            [
                "d.part1/x.part1.rev",
                "d.part1/x.part2.rev",
                "d.part1/x.part2.rev",
            ],
            2,
        ),
        (
            "d.dot/x.part1.rar",
            7,
            [
                "d.dot/x.part1.rev",
                "d.dot/x.part2.rev",
                "d.dot/x.part2.rev",
            ],
            2,
        ),
        (
            "a.part1.b.part1.rar",
            7,
            [
                "a.part1.b.part1.rev",
                "a.part1.b.part2.rev",
                "a.part1.b.part2.rev",
            ],
            2,
        ),
        (
            ".part1.rar",
            7,
            [".part1.rev", ".part2.rev", ".part2.rev"],
            2,
        ),
        (
            "set.part1",
            7,
            ["set.part1.rev", "set.part2.rev", "set.part2.rev"],
            2,
        ),
        (
            "my set.v2.part1.rar",
            7,
            [
                "my set.v2.part1.rev",
                "my set.v2.part2.rev",
                "my set.v2.part2.rev",
            ],
            2,
        ),
        (
            "set.part1.rar",
            4,
            ["set.part1.rev", "set.part2.rev", "set.part2.rev"],
            2,
        ),
        (
            "set.part1.rar",
            3,
            ["set.part1.rev", "set.part1.rev", "set.part1.rev"],
            1,
        ),
        (
            "set.part1.rar",
            3,
            ["set.part1.rev", "set.part2.rev", "set.part3.rev"],
            3,
        ),
        (
            "set.part1.rar",
            3,
            ["set.part1.rev", "set.part2.rev", "set.part4.rev"],
            4,
        ),
        (
            "big.part01.rar",
            11,
            ["big.part01.rev", "big.part02.rev", "big.part02.rev"],
            2,
        ),
    ];

    /// MEASURED the same day: every row is a set RENAMED after it was
    /// written (a set rar names itself is always in the table above). The
    /// reference keeps the first volume's own spelling and digit count and
    /// puts the row number where that volume's number stood, which is
    /// SPEC-L 3.6.4's V1 to V4. Until 10 Oct 2026 rarkit wrote
    /// `.part<N>` after its stem at the width of the volume count, and
    /// this table pinned that it differed; it is the rule's now.
    const RENAMED_AFTER_WRITING: &[Row] = &[
        (
            "set.part01.rar",
            7,
            ["set.part01.rev", "set.part02.rev", "set.part02.rev"],
            2,
        ),
        (
            "set.part001.rar",
            7,
            ["set.part001.rev", "set.part002.rev", "set.part002.rev"],
            2,
        ),
        (
            "SET.PART1.RAR",
            7,
            ["SET.PART1.rev", "SET.PART2.rev", "SET.PART2.rev"],
            2,
        ),
        (
            "set.Part1.Rar",
            7,
            ["set.Part1.rev", "set.Part2.rev", "set.Part2.rev"],
            2,
        ),
        (
            "set.PART1.rar",
            7,
            ["set.PART1.rev", "set.PART2.rev", "set.PART2.rev"],
            2,
        ),
        ("part1.rar", 7, ["part1.rev", "part2.rev", "part2.rev"], 2),
        (
            "set.part1.r.rar",
            7,
            ["set.part1.rev", "set.part2.rev", "set.part2.rev"],
            2,
        ),
        (
            "set.xpart1.rar",
            7,
            ["set.xpart1.rev", "set.xpart2.rev", "set.xpart2.rev"],
            2,
        ),
        (
            "set.part1x.rar",
            7,
            ["set.part1.rev", "set.part2.rev", "set.part2.rev"],
            2,
        ),
        (
            "set.p1.rar",
            7,
            ["set.p1.rev", "set.p2.rev", "set.p2.rev"],
            2,
        ),
        ("set1.rar", 7, ["set1.rev", "set2.rev", "set2.rev"], 2),
        (
            "set.001.rar",
            7,
            ["set.001.rev", "set.002.rev", "set.002.rev"],
            2,
        ),
        (
            "set_part1.rar",
            7,
            ["set_part1.rev", "set_part2.rev", "set_part2.rev"],
            2,
        ),
        (
            "big.part1.rar",
            11,
            ["big.part1.rev", "big.part2.rev", "big.part2.rev"],
            2,
        ),
    ];

    fn in_order(first: &str, second: &str, last: &str, count: u32) -> Vec<String> {
        match count {
            1 => vec![first.to_owned()],
            _ => vec![first.to_owned(), second.to_owned(), last.to_owned()],
        }
    }

    fn ours_in_order(first: &str, volumes: usize, count: u32) -> Vec<String> {
        let all = names(first, volumes, count);
        match count {
            1 => vec![all[0].clone()],
            _ => vec![all[0].clone(), all[1].clone(), all[all.len() - 1].clone()],
        }
    }

    #[test]
    fn a_set_rar_named_gets_the_recovery_names_rar_gives_it() {
        for &(first, volumes, [a, b, z], count) in SAME_AS_THE_REFERENCE {
            assert_eq!(
                ours_in_order(first, volumes, count),
                in_order(a, b, z, count),
                "{first}"
            );
        }
    }

    #[test]
    fn a_renamed_set_gets_the_recovery_names_rar_gives_it() {
        for &(first, volumes, [a, b, z], count) in RENAMED_AFTER_WRITING {
            assert_eq!(
                ours_in_order(first, volumes, count),
                in_order(a, b, z, count),
                "{first}"
            );
        }
    }

    /// Where the number stands: the last run of digits in the FILE name,
    /// whatever is in the directory's.
    #[test]
    fn the_set_s_number_is_the_last_digits_of_the_file_name() {
        let at = |path: &str| SetNumber::of(path).map(|n| (n.head, n.first, n.width, n.tail));
        assert_eq!(
            at("d.part7/set.part01.rar"),
            Some(("d.part7/set.part".to_owned(), 1, 2, ".rar".to_owned()))
        );
        assert_eq!(
            at("set.part1x.rar"),
            Some(("set.part".to_owned(), 1, 1, "x.rar".to_owned()))
        );
        assert_eq!(at("7.rar"), Some((String::new(), 7, 1, ".rar".to_owned())));
        assert_eq!(at("v2/set.rar"), None);
        let number = SetNumber::of("SET.PART09.RAR").unwrap();
        assert_eq!(number.volume(10).as_deref(), Some("SET.PART10.RAR"));
        assert_eq!(number.volume(100).as_deref(), Some("SET.PART100.RAR"));
        assert_eq!(number.recovery(0), "SET.PART01.rev");
        assert_eq!(number.recovery(99), "SET.PART100.rev");
    }

    /// SPEC-L 3.6.4, V9: every name the rule's rows state, with what
    /// stands in front of the set's number and the number itself. The
    /// first eleven count in the last run of digits; the next six in the
    /// run before it, a dot standing in front of both; the rest are the
    /// names `rar` does not see as a set, where the run it reads is the
    /// one that does not count.
    const WHICH_DIGITS: &[(&str, &str, u64)] = &[
        ("set.part1x.rar", "set.part", 1),
        ("set1.rar", "set", 1),
        ("1.rar", "", 1),
        ("set1x.rar", "set", 1),
        ("set1.data.rar", "set", 1),
        ("set.part1.x.rar", "set.part", 1),
        ("set.v1.final.x.rar", "set.v", 1),
        ("set.9.part1.rar", "set.9.part", 1),
        ("set.part9.v1.rar", "set.part9.v", 1),
        ("x9y1.rar", "x9y", 1),
        ("a9b1.data.rar", "a9b", 1),
        ("set.part1-2024.rar", "set.part", 1),
        ("set.part1y9.rar", "set.part", 1),
        ("set.x1y9.rar", "set.x", 1),
        ("set.PART1-9.rar", "set.PART", 1),
        ("set.port1-9.rar", "set.port", 1),
        ("set.a9b1c9.rar", "set.a9b", 1),
        ("set.part2024-1.rar", "set.part", 2024),
        ("set.x9y1.rar", "set.x", 9),
        ("set.a1b9c9.rar", "set.a1b", 9),
        ("set.a9b9c1.rar", "set.a9b", 9),
        ("x1y9.rar", "x1y", 9),
        ("xpart1y9.rar", "xpart1y", 9),
        ("a1b9.data.rar", "a1b", 9),
        ("set.1.part9.rar", "set.1.part", 9),
        ("set.v1.take2.rar", "set.v1.take", 2),
        ("set.part1.v9.rar", "set.part1.v", 9),
        ("x1y1.rar", "x1y", 1),
    ];

    #[test]
    fn the_set_s_number_is_the_run_of_digits_rar_counts_in() {
        for &(name, head, first) in WHICH_DIGITS {
            let read = SetNumber::of(name).map(|n| (n.head, n.first));
            assert_eq!(read, Some((head.to_owned(), first)), "{name}");
        }
    }

    /// SPEC-L 3.6.4, V1 as corrected: what stands between the number and
    /// the extension is not in a recovery volume's name.
    #[test]
    fn a_recovery_name_ends_at_the_number() {
        for (first, recovery) in [
            ("set.part1x.rar", "set.part1.rev"),
            ("set.part1.x.rar", "set.part1.rev"),
            ("set1.data.rar", "set1.rev"),
            ("set.a9b1c9.rar", "set.a9b1.rev"),
        ] {
            let number = SetNumber::of(first).unwrap();
            assert_eq!(number.recovery(0), recovery, "{first}");
        }
    }

    #[test]
    fn the_stem_is_cut_from_the_file_name_alone() {
        assert_eq!(rev_set_stem("set.part1.rar"), "set");
        assert_eq!(rev_set_stem("set.r00"), "set");
        assert_eq!(rev_set_stem("set.rar"), "set");
        assert_eq!(rev_set_stem("d.part1/x.part1.rar"), "d.part1/x");
        assert_eq!(rev_set_stem("./set.part001.rar"), "./set");
        assert_eq!(rev_set_stem("a.part1.b.part1.rar"), "a.part1.b");
        assert_eq!(rev_set_stem("set.part.rar"), "set.part");
        assert_eq!(rev_set_stem("set.partX.rar"), "set.partX");
        assert_eq!(rev_set_stem("set"), "set");
    }

    #[test]
    fn a_row_number_is_padded_and_never_cut() {
        assert_eq!(rev_row_path("s", 1, 0), "s.part1.rev");
        assert_eq!(rev_row_path("s", 1, 11), "s.part12.rev");
        assert_eq!(rev_row_path("s", 3, 14), "s.part015.rev");
        assert_eq!(rev_row_path("s", 2, u32::MAX), "s.part4294967296.rev");
    }
}
