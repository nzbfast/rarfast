//! `rc`: the missing volumes of a RAR 5 set, written again from the
//! recovery volumes beside it (SPEC-CLI section 13).
//!
//! This is a DRIVER over `rarkit::rev5` and holds no arithmetic. It finds
//! the set by name in the named file's directory (R2), asks the library
//! which volumes are the set's own and rebuilds the rest (R3), and owns
//! everything about the files: their names, their place, their mode, and
//! that a volume is whole or not there (SPEC-L 3.9).
//!
//! The library is asked ONCE. `rev5::repair` checks every data volume
//! given to it against the table, answers whether the set can be restored
//! before it reads a payload, and asks for a writer only for a volume it
//! is about to rebuild. So the call is made before any file of the set is
//! touched: every rebuilt volume goes to a new file beside its name
//! (`repair::fresh`), and only when the call has returned, and the volume
//! has passed its check, is a wrong volume moved aside and the new one
//! given its name (R4, R5). A run that fails leaves the set as it found
//! it.
//!
//! Where this differs from the reference by choice it says so at the
//! site: the exits of R8, the switches of R9, a file already at NAME.bad
//! (R4), a recovery volume of another set (R5), and no password (R11).

use super::super::unrar::{self, Exit, Out};
use super::args::Options;
use super::commands::SetNumber;
use super::repair::{
    answer, free_name, fresh, refuse_for_memory, repair_policy, seal, stdin_failed, taken,
};
use std::fs::File;
use std::sync::Arc;

/// The first bytes of a RAR 5 archive.
const RAR5: [u8; 8] = *b"Rar!\x1a\x07\x01\x00";
/// The first bytes of an archive of the RAR 4 family.
const RAR4: [u8; 7] = *b"Rar!\x1a\x07\x00";

/// What stands at a data volume's name.
enum Standing {
    /// Nothing.
    Absent,
    /// A file that begins as a RAR 5 archive does: it is listed, checked
    /// against the table, and kept as NAME.bad when it is wrong (C7).
    Volume(Arc<File>),
    /// Anything else: an empty file, a file that is no archive, a link, a
    /// directory. It is not listed, the volume counts as missing, and the
    /// question of C8 is asked about it.
    InTheWay,
}

/// One recovery volume found by name.
struct Recovery {
    path: String,
    info: rarkit::rev5::RevInfo,
    file: Arc<File>,
}

/// A rebuilt volume, in its new file beside its name.
struct Made {
    /// Its position in the set, from zero.
    position: u32,
    temporary: String,
    file: File,
}

/// A progress that draws nothing: the lines of C4 are printed around the
/// one library call.
struct Unseen;

impl rarkit::Progress for Unseen {}

/// `rc <name>`.
pub(crate) fn restore(out: &Out, named: &str, opts: &Options) -> Exit {
    // R1, C1: a name with no extension is given `.rar`, and for this
    // command a number is no extension (`set.part1` is `set.part1.rar`).
    let with_rar = format!("{named}.rar");
    let named = if !std::path::Path::new(named).exists()
        && !has_extension(named, "rar")
        && !has_extension(named, "rev")
        && std::path::Path::new(&with_rar).exists()
    {
        with_rar.as_str()
    } else {
        named
    };
    // R1, C2: the name is of a file that is there.
    let file = match File::open(named) {
        Ok(file) => file,
        Err(err) => {
            out.complain(&format!("Cannot open {named}\n{}", unrar::io_reason(&err)));
            return Exit::NothingMatched;
        }
    };
    let head = first_bytes(&file);
    let is_recovery = rarkit::rev5::inspect(&file).is_ok();
    let number = SetNumber::of(named);
    let beside = number.as_ref().map(|number| Beside::of(number, named));
    let named_rev = has_extension(named, "rev");

    // R10: a set of the older form is told by a RAR 4 archive with files
    // named as recovery volumes beside it.
    let older = if head.starts_with(&RAR4) {
        beside.as_ref().is_some_and(|b| !b.recovery.is_empty())
    } else {
        named_rev
            && !is_recovery
            && beside.as_ref().is_some_and(|b| {
                b.data.iter().any(|(_, path)| {
                    File::open(path).is_ok_and(|f| first_bytes(&f).starts_with(&RAR4))
                })
            })
    };
    if older {
        out.warn(&format!(
            "rarfast: `rc` does not restore recovery volumes of the older form (RAR 3 and 4). \
             {named} was not touched.\n"
        ));
        return Exit::Aborted;
    }

    // R8, C11: a named file that is no archive, or no volume, is never
    // exit 0 (a chosen difference: the reference exits 0 for both).
    if !is_recovery {
        if !head.starts_with(&RAR5) && !head.starts_with(&RAR4) {
            out.complain(&format!("{named} is not RAR archive"));
            return Exit::NothingMatched;
        }
        // R11: no password is asked, so a volume whose headers cannot be
        // read says nothing here and is taken as one.
        if unrar::open(named, None).is_ok_and(|opened| !opened.is_volume) {
            out.complain(&format!("{named} is not volume"));
            return Exit::NothingMatched;
        }
    }

    let (data_files, recovery_files, data_tail) = match beside {
        Some(beside) => (beside.data, beside.recovery, beside.tail),
        None => (Vec::new(), Vec::new(), String::new()),
    };
    let mut found: Vec<Recovery> = Vec::new();
    for path in recovery_files {
        // C3: a file named like a recovery volume that is none is passed
        // over without a word.
        let Ok(file) = File::open(&path) else {
            continue;
        };
        if let Ok(info) = rarkit::rev5::inspect(&file) {
            found.push(Recovery {
                path,
                info,
                file: Arc::new(file),
            });
        }
    }

    out.say(&format!("\n{} recovery volumes found\n", found.len()));
    if found.is_empty() {
        return nothing_found(out, named, number.as_ref(), &data_files);
    }
    let number = number.expect("a recovery volume was found by the set's number");
    out.say("Calculating checksums of all volumes.\n");

    // R2: recovery volumes are of one set when their counts and tables
    // are equal. Where the files found are of more than one, the set is
    // the one more of the data volumes there agree with in length, then
    // the one with more recovery volumes.
    let chosen = choose(&found, &data_files);
    let table = found[chosen].info.data_volumes.clone();
    let of_set: Vec<bool> = found
        .iter()
        .map(|r| r.info.same_set(&found[chosen].info))
        .collect();

    // Every position of the set, by the number in its name: position `j`
    // is the volume numbered `j + 1`.
    let name_of = |position: usize| -> String {
        let n = position as u64 + 1;
        data_files
            .iter()
            .find(|(there, _)| *there == n)
            .map_or_else(
                || {
                    format!(
                        "{}{n:0width$}{data_tail}",
                        number.head,
                        width = number.width
                    )
                },
                |(_, path)| path.clone(),
            )
    };
    let names: Vec<String> = (0..table.len()).map(name_of).collect();
    let standing: Vec<Standing> = names.iter().map(|name| standing_at(name)).collect();

    let policy = policy(opts);
    let set = rarkit::rev5::RepairSet {
        data: standing
            .iter()
            .map(|s| match s {
                Standing::Volume(file) => Some(Arc::clone(file) as Arc<dyn rarkit::RangeSource>),
                _ => None,
            })
            .collect(),
        recovery: found
            .iter()
            .zip(&of_set)
            .filter(|(_, own)| **own)
            .map(|(r, _)| (&r.info, Arc::clone(&r.file) as Arc<dyn rarkit::RangeSource>))
            .collect(),
    };

    // SPEC-L 3.9: a volume written takes the mode of the first volume
    // present.
    let like = standing
        .iter()
        .zip(&names)
        .find(|(s, _)| matches!(s, Standing::Volume(_)))
        .map_or_else(|| found[chosen].path.clone(), |(_, name)| name.clone());

    let mut made: Vec<Made> = Vec::new();
    let mut create_failure: Option<(String, String)> = None;
    let mut writer = |position: u32| -> rarkit::Result<Box<dyn std::io::Write + Send>> {
        let name = &names[position as usize];
        let opened = fresh(name, &like).and_then(|(temporary, file)| {
            let writing = file.try_clone().inspect_err(|_| {
                let _ = std::fs::remove_file(&temporary);
            })?;
            Ok((temporary, file, writing))
        });
        match opened {
            Ok((temporary, file, writing)) => {
                made.push(Made {
                    position,
                    temporary,
                    file,
                });
                Ok(Box::new(writing))
            }
            Err(err) => {
                create_failure = Some((name.clone(), unrar::io_reason(&err)));
                Err(rarkit::Error::caller(err))
            }
        }
    };

    // The recovery volumes' own checks, for the marks of C9, beside the
    // library's call, which makes them again for itself and says only
    // how many it could use.
    let (rebuilt, sound) = std::thread::scope(|scope| {
        let sound = scope.spawn(|| payloads_sound(&found, &of_set, policy.max_workers));
        let rebuilt = rarkit::rev5::repair(&set, &policy, &mut writer, &mut Unseen);
        (rebuilt, sound.join().unwrap_or_default())
    });
    let discard = |made: &[Made]| {
        for one in made {
            let _ = std::fs::remove_file(&one.temporary);
        }
    };

    // Which of the volumes there are wrong: the ones a writer was asked
    // for, or, when the library refused the set before it asked, its own
    // answer to the same question once more.
    let asked = |position: usize| made.iter().any(|m| m.position as usize == position);
    let report = match rebuilt {
        Ok(report) => report,
        Err(err) => {
            discard(&made);
            if let Some((name, reason)) = create_failure {
                // SPEC-L 3.9 F11: the set's directory may not be written.
                out.complain(&format!("Cannot create {name}\n{reason}"));
                return Exit::CannotCreate;
            }
            let wrong = wrong_volumes(&standing, &table, &policy);
            let missing: Vec<&str> = (0..names.len())
                .filter(|&j| !matches!(standing[j], Standing::Volume(_)) || wrong[j])
                .map(|j| names[j].as_str())
                .collect();
            say_listing(out, &names, &standing, &wrong, &found, &of_set, &sound);
            out.say(&format!("{} volumes missing\n", missing.len()));
            return match err.kind() {
                rarkit::ErrorKind::Recovery(rarkit::RecoveryFailure::TooManyMissing { .. }) => {
                    out.say("Reconstruction impossible\n");
                    not_restored(out, &missing, found.len())
                }
                rarkit::ErrorKind::LimitExceeded { needed, limit, .. } => {
                    refuse_for_memory(out, named, *needed, *limit)
                }
                _ => {
                    out.warn(&format!(
                        "rarfast: the set of {named} is not restored: {err}\n"
                    ));
                    Exit::ChecksumMismatch
                }
            };
        }
    };
    let wrong: Vec<bool> = (0..names.len())
        .map(|j| matches!(standing[j], Standing::Volume(_)) && asked(j))
        .collect();
    say_listing(out, &names, &standing, &wrong, &found, &of_set, &sound);
    out.say(&format!("{} volumes missing\n", made.len()));
    if made.is_empty() {
        out.say("Nothing to reconstruct\n");
        return Exit::Clean;
    }
    out.say("Reconstructing...\n");

    // The mode is given while every volume of the set still stands at
    // its own name: `like` may itself be one that is about to be moved
    // aside.
    for one in &made {
        if let Err(err) = seal(&one.file, &like) {
            discard(&made);
            let name = &names[one.position as usize];
            out.complain(&format!("Cannot create {name}\n{}", unrar::io_reason(&err)));
            return Exit::CannotCreate;
        }
    }

    // R3 to R5, R9: each rebuilt volume that passed its check is given
    // its name, in set order.
    let mut placing = Placing {
        out,
        opts,
        line_open: false,
        unrestored: 0,
        renamed: 0,
        asked: Asked::Each,
    };
    // A self-extracting first volume standing where the plain first
    // volume's name is free, told by its name alone. Measured on the
    // reference: it never writes a plain first volume beside one.
    let beside_first = matches!(standing.first(), Some(Standing::Absent))
        .then(|| {
            ["exe", "sfx", "EXE", "SFX"]
                .iter()
                .map(|ext| format!("{}{:0width$}.{ext}", number.head, 1, width = number.width))
                .find(|path| taken(path))
        })
        .flatten();
    let mut stopped = None;
    for (at, one) in made.iter().enumerate() {
        let position = one.position as usize;
        let name = &names[position];
        if let (0, Some(first)) = (position, &beside_first) {
            // The file is not read, checked or mended here.
            let _ = std::fs::remove_file(&one.temporary);
            placing.left(&format!(
                "rarfast: {name} is not written: the set's first volume {first} is there and \
                 was not checked\n"
            ));
            continue;
        }
        if !report.rebuilt.contains(&one.position) {
            // R5: a volume that failed its check is not kept.
            let _ = std::fs::remove_file(&one.temporary);
            placing.left(&format!(
                "rarfast: {name} is not restored: the rebuilt volume failed its check\n"
            ));
            continue;
        }
        if let Err(exit) = placing.place(one, name, wrong[position]) {
            discard(&made[at..]);
            stopped = Some(exit);
            break;
        }
    }
    if let Some(exit) = stopped {
        return exit;
    }
    placing.end()
}

/// The files beside the named one whose names agree with its name up to
/// its number (C3).
struct Beside {
    /// Data volumes by their number, in its order.
    data: Vec<(u64, String)>,
    /// Files named as recovery volumes, in name order.
    recovery: Vec<String>,
    /// What follows the number in a data volume's name.
    tail: String,
}

impl Beside {
    fn of(number: &SetNumber, named: &str) -> Beside {
        let name_at = number.head.rfind(['/', '\\']).map_or(0, |slash| slash + 1);
        let (directory, stem) = number.head.split_at(name_at);
        // What follows the number in a data volume's name: the named
        // file's own, or, when a recovery volume was named, `.rar` as the
        // directory spells it.
        let named_is_data = !has_extension(named, "rev");
        let mut data_tail = named_is_data.then(|| number.tail.clone());
        let mut data: Vec<(u64, String)> = Vec::new();
        let mut recovery: Vec<(u64, String)> = Vec::new();
        let listed = std::fs::read_dir(if directory.is_empty() { "." } else { directory });
        for entry in listed.into_iter().flatten().flatten() {
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else {
                continue;
            };
            let Some(rest) = name.strip_prefix(stem) else {
                continue;
            };
            let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
            let Ok(n) = rest[..digits].parse::<u64>() else {
                continue;
            };
            let tail = &rest[digits..];
            let path = format!("{directory}{name}");
            if tail.eq_ignore_ascii_case(".rev") {
                recovery.push((n, path));
            } else if (named_is_data && tail == number.tail)
                || (!named_is_data && tail.eq_ignore_ascii_case(".rar"))
            {
                data_tail.get_or_insert_with(|| tail.to_owned());
                data.push((n, path));
            }
        }
        data.sort();
        data.dedup_by_key(|(n, _)| *n);
        recovery.sort();
        Beside {
            data,
            recovery: recovery.into_iter().map(|(_, path)| path).collect(),
            tail: data_tail.unwrap_or_else(|| ".rar".to_owned()),
        }
    }
}

fn has_extension(path: &str, extension: &str) -> bool {
    std::path::Path::new(path)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case(extension))
}

/// The first eight bytes of `file`, or as many as it has.
fn first_bytes(file: &File) -> Vec<u8> {
    use rarkit::RangeSource as _;
    let mut head = [0u8; 8];
    let mut got = 0;
    while got < head.len() {
        match file.read_at(got as u64, &mut head[got..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => got += n,
        }
    }
    head[..got].to_vec()
}

/// What stands at a data volume's name. A link is never followed (SPEC-L
/// 3.9, never through a link): it is in the way, whatever it points at.
fn standing_at(name: &str) -> Standing {
    let Ok(meta) = std::fs::symlink_metadata(name) else {
        return Standing::Absent;
    };
    if !meta.is_file() {
        return Standing::InTheWay;
    }
    match File::open(name) {
        Ok(file) if first_bytes(&file) == RAR5 => Standing::Volume(Arc::new(file)),
        _ => Standing::InTheWay,
    }
}

/// The memory policy of the run: the `-mm` budget when one is given, and
/// no wider than `-mt`.
fn policy(opts: &Options) -> rarkit::MemoryPolicy {
    let mut policy = match opts.memory_cap {
        Some(cap) => repair_policy(cap),
        None => rarkit::MemoryPolicy::process_default(0),
    };
    if let Some(threads) = opts.shared.threads {
        let threads = usize::try_from(threads).unwrap_or(usize::MAX).max(1);
        policy.max_workers = policy.max_workers.min(threads);
    }
    policy
}

/// Which of the recovery volumes found stands for the set: the index of
/// one of its group.
fn choose(found: &[Recovery], data: &[(u64, String)]) -> usize {
    let agree = |info: &rarkit::rev5::RevInfo| {
        data.iter()
            .filter(|(n, path)| {
                n.checked_sub(1)
                    .and_then(|j| info.data_volumes.get(usize::try_from(j).ok()?))
                    .is_some_and(|row| std::fs::metadata(path).is_ok_and(|m| m.len() == row.size))
            })
            .count()
    };
    let mut best = (0, 0, 0);
    for (at, one) in found.iter().enumerate() {
        if found[..at].iter().any(|r| r.info.same_set(&one.info)) {
            continue;
        }
        let group = found.iter().filter(|r| r.info.same_set(&one.info)).count();
        let score = (agree(&one.info), group);
        if at == 0 || score > (best.1, best.2) {
            best = (at, score.0, score.1);
        }
    }
    best.0
}

/// Whether each recovery volume's payload is the one its header records:
/// one answer a volume found, `true` for one of another set, which is
/// not read. At most `width` are read at once.
fn payloads_sound(found: &[Recovery], of_set: &[bool], width: usize) -> Vec<bool> {
    let next = std::sync::atomic::AtomicUsize::new(0);
    let sound: Vec<std::sync::atomic::AtomicBool> = found
        .iter()
        .map(|_| std::sync::atomic::AtomicBool::new(true))
        .collect();
    let work = || loop {
        let at = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let Some(one) = found.get(at) else {
            break;
        };
        if of_set[at] {
            let good = one.info.verify_payload(one.file.as_ref()).unwrap_or(false);
            sound[at].store(good, std::sync::atomic::Ordering::Relaxed);
        }
    };
    std::thread::scope(|scope| {
        for _ in 1..width.clamp(1, found.len()) {
            scope.spawn(work);
        }
        work();
    });
    sound.into_iter().map(|s| s.into_inner()).collect()
}

/// Which of the volumes there are not the table's, for a set the library
/// refused before it asked for a writer.
fn wrong_volumes(
    standing: &[Standing],
    table: &[rarkit::rev5::DataVolume],
    policy: &rarkit::MemoryPolicy,
) -> Vec<bool> {
    let there: Vec<(usize, &File)> = standing
        .iter()
        .enumerate()
        .filter_map(|(j, s)| match s {
            Standing::Volume(file) => Some((j, file.as_ref())),
            _ => None,
        })
        .collect();
    let targets: Vec<(&dyn rarkit::RangeSource, &rarkit::rev5::DataVolume)> = there
        .iter()
        .map(|(j, file)| (*file as &dyn rarkit::RangeSource, &table[*j]))
        .collect();
    let mut wrong = vec![false; standing.len()];
    for ((j, _), answer) in there.iter().zip(rarkit::rev5::matches(&targets, policy)) {
        wrong[*j] = !answer.unwrap_or(false);
    }
    wrong
}

/// C4's list: each data volume there, each recovery volume found, and
/// the mark of one that is wrong (C7, C9). The line for a recovery
/// volume of another set is this tool's own (R5, R6).
fn say_listing(
    out: &Out,
    names: &[String],
    standing: &[Standing],
    wrong: &[bool],
    found: &[Recovery],
    of_set: &[bool],
    sound: &[bool],
) {
    if !out.says() {
        return;
    }
    let mut text = String::new();
    for (j, name) in names.iter().enumerate() {
        if matches!(standing[j], Standing::Volume(_)) {
            text.push_str(&format!("{name}\n"));
            if wrong[j] {
                text.push_str(&format!("{name:<20} - checksum error\n"));
            }
        }
    }
    for (at, one) in found.iter().enumerate() {
        let name = &one.path;
        text.push_str(&format!("{name}\n"));
        if !of_set[at] {
            text.push_str(&format!("{name:<20} - not of this set, not used\n"));
        } else if !sound.get(at).copied().unwrap_or(true) {
            text.push_str(&format!("{name:<20} - checksum error\n"));
        }
    }
    out.say(&text);
}

/// R8: a set that cannot be restored is exit 3, with one line saying
/// which volumes are missing and how many recovery volumes were found (a
/// chosen difference: the reference exits 0).
fn not_restored(out: &Out, missing: &[&str], found: usize) -> Exit {
    out.warn(&format!(
        "rarfast: the set is not restored: {} missing, {found} recovery volumes found\n",
        missing.join(", ")
    ));
    Exit::ChecksumMismatch
}

/// No recovery volume was found (C6). R8, a chosen difference from the
/// reference's exit 0: exit 3 when a volume is known to be missing, and
/// else exit 1, since with no table nothing says how many volumes the
/// set has or whether those there are sound.
fn nothing_found(
    out: &Out,
    named: &str,
    number: Option<&SetNumber>,
    data: &[(u64, String)],
) -> Exit {
    // A volume is KNOWN missing when the numbers there leave a gap from
    // 1, or the last one there says another follows it.
    let mut missing: Vec<String> = Vec::new();
    if let (Some(number), Some((last, last_path))) = (number, data.last()) {
        for n in 1..*last {
            if !data.iter().any(|(there, _)| *there == n) {
                missing.extend(number.volume(n));
            }
        }
        if super::commands::another_follows(last_path) {
            missing.extend(number.volume(last + 1));
        }
    }
    if missing.is_empty() {
        out.warn(&format!(
            "rarfast: no recovery volume was found beside {named}: nothing was checked\n"
        ));
        return Exit::Cautioned;
    }
    let missing: Vec<&str> = missing.iter().map(String::as_str).collect();
    not_restored(out, &missing, 0)
}

/// The giving of names to the rebuilt volumes, and what the run has to
/// say at its end.
struct Placing<'a> {
    out: &'a Out,
    opts: &'a Options,
    /// A `Creating` line stands without its end, for the counter the
    /// last of them carries.
    line_open: bool,
    /// Volumes left unrestored (R9: exit 3).
    unrestored: usize,
    /// Volumes written under a renamed name (R9: exit 1).
    renamed: usize,
    /// What the question's last standing answer was.
    asked: Asked,
}

/// The standing answer to the question about a file in the way: each is
/// asked about, until `a` (all are replaced) or `e` (none is).
#[derive(Clone, Copy)]
enum Asked {
    Each,
    All,
    Never,
}

impl Placing<'_> {
    fn close_line(&mut self) {
        if std::mem::take(&mut self.line_open) {
            self.out.say("\n");
        }
    }

    /// One volume is not restored, and the run says so in one line.
    fn left(&mut self, line: &str) {
        self.close_line();
        self.out.warn(line);
        self.unrestored += 1;
    }

    /// What the switches say of a file standing at `path`, a name this
    /// run wants: the name to write under (`path` itself to replace what
    /// stands there), `None` to leave it and write nothing, or the exit
    /// of a question nobody answered.
    fn answer(&mut self, path: &str) -> Result<Option<String>, Exit> {
        use unrar::args::Overwrite;
        match self.opts.shared.overwrite {
            Overwrite::Always => Ok(Some(path.to_owned())),
            Overwrite::Never => Ok(None),
            // SPEC-CLI 9.2 O8, as `r` has it: the least numbered name
            // that is free.
            Overwrite::Rename => {
                let at = path.rfind(['/', '\\']).map_or(0, |slash| slash + 1);
                let (directory, name) = path.split_at(at);
                Ok(
                    free_name(name, |candidate| taken(&format!("{directory}{candidate}")))
                        .map(|free| format!("{directory}{free}")),
                )
            }
            Overwrite::Ask if self.opts.shared.assume_yes => Ok(Some(path.to_owned())),
            Overwrite::Ask => self.ask(path),
        }
    }

    /// The question about what stands at `path`, and its answer: as
    /// [`Placing::answer`] has it.
    ///
    /// The answers are the ones the tool's question has where a file is
    /// extracted over another, read a line each from standard input by
    /// the line's first letter in either case: `y` this one; `n` not
    /// this one; `a` this and every later one; `e` none from here on;
    /// `r` a new name, read after `Enter new name: ` on standard output
    /// (a bare name goes beside `path`), and asked about in its turn
    /// when it is taken too; `q` ends the run, `Program aborted`, exit
    /// 255. Any other line, an empty one among them, prints the choices
    /// again. The input at its end is exit 12.
    fn ask(&mut self, path: &str) -> Result<Option<String>, Exit> {
        const CHOICES: &str = "[Y]es, [N]o, [A]ll, n[E]ver, [R]ename, [Q]uit ";
        match self.asked {
            Asked::All => return Ok(Some(path.to_owned())),
            Asked::Never => return Ok(None),
            Asked::Each => {}
        }
        self.close_line();
        self.out.warn(&format!("\n\nOverwrite {path}?\n{CHOICES}"));
        loop {
            let Some(line) = answer() else {
                return Err(stdin_failed(self.out));
            };
            match line.bytes().next().map(|b| b.to_ascii_lowercase()) {
                Some(b'y') => return Ok(Some(path.to_owned())),
                Some(b'n') => return Ok(None),
                Some(b'a') => {
                    self.asked = Asked::All;
                    return Ok(Some(path.to_owned()));
                }
                Some(b'e') => {
                    self.asked = Asked::Never;
                    return Ok(None);
                }
                Some(b'q') => {
                    self.out.say("\nProgram aborted\n");
                    return Err(Exit::Interrupted);
                }
                Some(b'r') => {
                    self.out.say("Enter new name: ");
                    let Some(typed) = answer() else {
                        return Err(stdin_failed(self.out));
                    };
                    self.out.say("\n");
                    let named = if typed.contains(['/', '\\']) {
                        typed
                    } else {
                        let at = path.rfind(['/', '\\']).map_or(0, |slash| slash + 1);
                        format!("{}{typed}", &path[..at])
                    };
                    return if taken(&named) {
                        self.ask(&named)
                    } else {
                        Ok(Some(named))
                    };
                }
                _ => self.out.warn(&format!("\n{CHOICES}")),
            }
        }
    }

    /// Gives one rebuilt volume its name. `Err` ends the run.
    fn place(&mut self, one: &Made, name: &str, wrong: bool) -> Result<(), Exit> {
        let drop_new = || {
            let _ = std::fs::remove_file(&one.temporary);
        };
        let mut target = name.to_owned();
        if wrong {
            // R4, C7: the wrong volume is kept as NAME.bad. A file
            // already there is never replaced in silence (a chosen
            // difference: the reference replaces it under every switch).
            let bad = format!("{name}.bad");
            let aside = if taken(&bad) {
                match self.answer(&bad) {
                    Ok(Some(aside)) => aside,
                    Ok(None) => {
                        drop_new();
                        self.left(&format!(
                            "rarfast: {name} is not restored: {bad} is there and is not \
                             replaced, so the wrong volume cannot be kept aside\n"
                        ));
                        return Ok(());
                    }
                    Err(exit) => {
                        drop_new();
                        return Err(exit);
                    }
                }
            } else {
                bad
            };
            self.close_line();
            self.out.say(&format!(
                "ERROR: Bad archive {name}\n\nRenaming {name} to {aside}\n"
            ));
            if let Err(err) = std::fs::rename(name, &aside) {
                drop_new();
                self.left(&format!(
                    "rarfast: {name} is not restored: it cannot be renamed to {aside}: {}\n",
                    unrar::io_reason(&err)
                ));
                return Ok(());
            }
        } else if taken(name) {
            // R9, C8: something that is no volume stands at the name.
            match self.answer(name) {
                Ok(Some(free)) => target = free,
                Ok(None) => {
                    drop_new();
                    self.left(&format!(
                        "rarfast: {name} is not restored: a file stands at its name and is \
                         not replaced\n"
                    ));
                    return Ok(());
                }
                Err(exit) => {
                    drop_new();
                    return Err(exit);
                }
            }
        }
        // R9: a name that cannot be given, a directory standing at it,
        // leaves that volume and the run goes on to the others (a chosen
        // difference: the reference ends the run there, exit 9).
        if let Err(err) = std::fs::rename(&one.temporary, &target) {
            drop_new();
            self.left(&format!(
                "rarfast: {name} is not restored: {target} cannot be created: {}\n",
                unrar::io_reason(&err)
            ));
            return Ok(());
        }
        self.close_line();
        self.out.say(&format!("Creating {target}"));
        self.line_open = true;
        if target != name {
            // R9: the restore did what was asked and the set is not
            // whole at its own names (a chosen difference: exit 1).
            self.close_line();
            self.out.warn(&format!(
                "rarfast: {name} was written as {target}: a file stands at its name\n"
            ));
            self.renamed += 1;
        }
        Ok(())
    }

    fn end(mut self) -> Exit {
        if self.unrestored > 0 {
            self.close_line();
            return Exit::ChecksumMismatch;
        }
        if std::mem::take(&mut self.line_open) {
            // The last `Creating` line carries the counter, as measured.
            self.out.say(&format!(
                "     {}{}\n",
                super::lines::counter(0),
                super::lines::counter(100)
            ));
        }
        self.out.say("Done\n");
        if self.renamed > 0 {
            Exit::Cautioned
        } else {
            Exit::Clean
        }
    }
}
