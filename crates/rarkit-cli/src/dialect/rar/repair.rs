//! `r <archive> [<dir>/]`: repair an archive from its recovery record.
//!
//! Written from `rar` 7.23's observable behaviour, measured on an Apple Silicon Mac on
//! 30 Sep 2026 over RAR 5 archives made by `rar` and by rarfast at `-rr3`
//! and `-rr10`, one volume and `-v` sets, 300 KB to 41 MB, damaged in 1,
//! 3 and more slices than the record holds, and undamaged. What the
//! reference does, and so what this does:
//!
//! - It writes `fixed.<name>` into the CURRENT directory, or into the
//!   destination directory when one is named, never beside the archive.
//!   The name is the archive's own file name, volume number and all: only
//!   the NAMED volume of a set is read and repaired.
//! - An archive the record finds nothing wrong with gets the whole report
//!   and no file at all.
//! - The fixed file is the volume with its damaged slices rebuilt, cut at
//!   its end block, and closed with a fresh end block that says it is the
//!   LAST volume. On one volume that is the original's bytes; on a volume
//!   of a set it drops the padding and clears the "more volumes" flag, so
//!   a fixed `part2` is 13 bytes shorter than the original. Where the
//!   headers after the protected bytes cannot be read (`-hp` and no
//!   password), it is the protected bytes alone.
//! - A group with more damaged slices than surviving rows is reported
//!   `cannot recover data`. The groups that can mend still do, and the
//!   fixed file is written; then the reference asks whether to rebuild
//!   the archive structure. When nothing mended, it rebuilds without
//!   asking, and it also rebuilds when there is no record at all.
//! - The rebuild writes `rebuilt.<name>`: with every header intact that is
//!   the volume up to its end block, which is what this writes. A volume
//!   whose headers do not walk is rebuilt by the reference from a scan for
//!   headers, which rarkit does not do, so that case is refused by name.
//!
//! The RAR 4 family's `r` reports in 512-byte sectors, runs two analysis
//! passes and writes `fixed.` even when nothing was wrong: a different
//! command in all but name, not measured to the depth this one is, so it
//! is refused by name too.

use std::io::{BufRead as _, Write as _};

use super::super::unrar::{self, Exit, Out};
use super::args::Options;
use super::lines::counter;

/// The fresh end block the reference closes every fixed volume with: a
/// RAR 5 end of archive whose flags say no volume follows (spec F).
const LAST_END_BLOCK: [u8; 8] = [0x1d, 0x77, 0x56, 0x51, 0x03, 0x05, 0x04, 0x00];

/// The window the reference's "Searching" counter steps by, measured: one
/// tick per MiB of volume, `2 5 7 10 12` on a 41,240,341 byte archive.
const SEARCH_WINDOW: u64 = 1 << 20;

/// The bytes the reference's analysis counter steps by, measured as whole
/// shards: `floor(4,000,000 / floor(P / k))`, which gives 20, 32, 57 and
/// 80 shards where `P / k` is 200,000, 125,000, 70,000 and 50,000.
const ANALYSIS_BATCH: u64 = 4_000_000;

/// The exit of a run that mended everything it judged damaged in an
/// archive whose MAIN HEADER failed its check: the reference's, which
/// answers for the header that was corrupt (see the site).
const MENDED_PAST_A_CORRUPT_MAIN_HEADER: Exit = Exit::ChecksumMismatch;

/// Where the label of a line that carries a counter ends: every one of
/// the reference's is followed by six spaces before the first backspace.
const COUNTER_GAP: &str = "      ";

/// `r`: see the module comment.
pub(crate) fn repair(
    out: &Out,
    archive: &str,
    masks: &[String],
    extract_path: Option<&str>,
    opts: &Options,
) -> Exit {
    let source = match std::fs::File::open(archive) {
        Ok(file) => file,
        Err(err) => {
            // Measured over `nosuch.rar`: `Cannot open` and the reason on
            // stderr, a blank line and `Done` on stdout, exit 10.
            out.complain(&format!(
                "Cannot open {archive}\n{}",
                unrar::io_reason(&err)
            ));
            out.say("\nDone\n");
            return Exit::NothingMatched;
        }
    };
    let size = source.metadata().map_or(0, |meta| meta.len());
    if is_rar4_family(&source) {
        return refuse(
            out,
            archive,
            "the RAR 4 family's repair reports in sectors and is not built",
        );
    }

    let read = read_options(opts);
    // Tolerant, so a header damaged past the main header still leaves the
    // main header's flags to read; the rebuild asks separately whether
    // the walk reached the end.
    let walked = rarkit::Session::new(read.clone().with_tolerant_tail(true))
        .open_path(std::path::Path::new(archive));
    // Spec L 3.5.5 O5, measured on the reference: only a SOUND main
    // header that says there is no record ends the search (an archive
    // written without `-rr` goes straight to `not found`, and so does one
    // whose flag was cleared although its records are all there). A main
    // header that does not read says nothing: where no main header
    // stands after a signature at byte 0 (a damaged signature, bytes
    // before it, enciphered headers) the walk answers as it did, and a
    // walk that lists no main block does not know either.
    let main_header = rarkit::recovery::main_header_record(&source);
    let searched = match main_header {
        rarkit::recovery::MainHeaderRecord::Present => true,
        rarkit::recovery::MainHeaderRecord::Absent => false,
        _ => walked.as_ref().map_or(true, |archive| {
            archive.has_recovery_record()
                || !archive
                    .blocks()
                    .any(|block| block.kind == rarkit::BlockKind::Main)
        }),
    };
    // With its check failing the reference says the main archive header
    // is corrupt, searches, and mends from the record it finds.
    let main_header_corrupt = main_header == rarkit::recovery::MainHeaderRecord::Corrupt;
    if main_header_corrupt {
        // The reference's own line, on stderr.
        out.warn("\nMain archive header is corrupt\n");
    }
    let check = if searched {
        out.say(&format!("\nSearching for recovery record{COUNTER_GAP}"));
        out.say(&search_ticks(size));
        out.say("\n");
        rarkit::recovery::check_inline(&source, &read).ok()
    } else {
        out.say("\n");
        None
    };
    out.say(if check.is_some() {
        "Data recovery record found\n"
    } else {
        "Data recovery record not found\n"
    });

    let directory = match destination(out, masks, extract_path) {
        Ok(directory) => directory,
        Err(exit) => return exit,
    };
    let name = std::path::Path::new(archive)
        .file_name()
        .map_or_else(|| archive.to_owned(), |n| n.to_string_lossy().into_owned());
    let place = |prefix: &str| {
        let output = format!("{prefix}{name}");
        let within = |output: &str| match &directory {
            Some(dir) => format!("{dir}/{output}"),
            None => output.to_owned(),
        };
        // Spec L 3.9 F7: under `-or` a name that is taken is left alone
        // and the output takes the next free numbered one.
        if opts.shared.overwrite == unrar::args::Overwrite::Rename {
            free_name(&output, |candidate| taken(&within(candidate)))
                .map_or_else(|| within(&output), |free| within(&free))
        } else {
            within(&output)
        }
    };

    let Some(check) = check else {
        return rebuild(out, archive, &place("rebuilt."), walked.ok(), size, opts);
    };

    let fixed = place("fixed.");
    match may_write(out, &fixed, opts) {
        Go::Write => {}
        Go::Skip => {
            out.say("Done\n");
            return Exit::Clean;
        }
        Go::Abort(exit) => return exit,
    }

    out.say(&format!("Analyzing file data{COUNTER_GAP}"));
    out.say(&analysis_ticks(&check));
    out.say("\n");

    out.say(&format!("Building {fixed}{COUNTER_GAP}"));
    out.say(&counter(0));
    // The mend runs BEFORE any slice is called recovered: a rebuilt slice
    // that fails its own CRC-64 is not written back, and what the run says
    // of each slice is what the mend did, not what the plan hoped
    // (measured, 4 Oct 2026: the reference answers `cannot recover data`
    // for a slice whose recovery row is sealed over wrong parity).
    let mended = check
        .groups
        .iter()
        .any(|group| group.recoverable() && !group.damaged.is_empty())
        .then(|| -> Result<(String, Vec<Vec<u16>>), Stop> {
            let (temporary, target) =
                fresh(&fixed, archive).map_err(|e| Stop::Failed(unrar::io_reason(&e)))?;
            mend(&source, &check, &read, &temporary, target)
                .map(|left| (temporary.clone(), left))
                .inspect_err(|_| {
                    let _ = std::fs::remove_file(&temporary);
                })
        });
    if let Some(Err(Stop::Memory { needed, limit })) = mended {
        // Refused before a slice was rebuilt: nothing is said of any.
        out.say("\n");
        return refuse_for_memory(out, archive, needed, limit);
    }
    let unmended = |g: usize, shard: u16| match &mended {
        Some(Ok((_, left))) => left[g].contains(&shard),
        _ => false,
    };
    let mut last = 0;
    let (mut recovered, mut failed) = (0u64, 0u64);
    for (g, group) in check.groups.iter().enumerate() {
        for &shard in &group.damaged {
            let verdict = if group.recoverable() && !unmended(g, shard) {
                recovered += 1;
                "data recovered"
            } else {
                failed += 1;
                "cannot recover data"
            };
            let at = check.slice_offset(shard, g);
            out.say(&format!(
                "\nCorrupt {} bytes at {:08x} {:08x} - {verdict}     ",
                group.len,
                at >> 32,
                at & 0xffff_ffff
            ));
        }
        let percent = (group.offset + group.len) * 100 / check.shard_len.max(1);
        if percent != last {
            out.say(&counter(percent));
            last = percent;
        }
    }
    out.say(&format!(
        "\n{recovered} blocks are recovered, 0 blocks are relocated\n"
    ));
    // A group with no recovery row left has no table, so its slices were
    // never checked: nothing is KNOWN of them. Measured, 4 Oct 2026: the
    // reference says so on stdout, goes on as it does for a group that
    // could not mend, and ends with exit 3 where that would be `Done`.
    let unjudged = check.groups.iter().any(|group| group.rows == 0);
    // A group with FEWER rows than the record was written with has lost
    // records to damage inside the record's own data area. Measured, 8 Oct
    // 2026: the reference says the same line and exits 3 for that too,
    // whether or not the rows that survive mended every damaged slice
    // (and with nothing damaged it writes no file and ends `Done`).
    let record_damaged = check.groups.iter().any(|group| group.rows < check.rows);
    let done = if record_damaged {
        out.say("Recovery record is corrupt.\n");
        Exit::ChecksumMismatch
    } else if failed > 0 {
        // A slice judged damaged and not mended. The reference ends such
        // a run with exit 0 when the record is whole (measured, 8 Oct
        // 2026); the rule here is that a repair that did not mend
        // everything it judged damaged never exits 0.
        Exit::ChecksumMismatch
    } else if main_header_corrupt {
        // Everything judged damaged is mended, the main header with it,
        // and the fixed file is whole. The reference still ends such a
        // run with exit 3, for the header that WAS corrupt (measured, 10
        // Oct 2026: every arm of spec L 3.5.5's probe that damages the
        // main header and is mended, 26 of them, and 0 in the 75 mended
        // arms that leave it alone). This follows the reference.
        MENDED_PAST_A_CORRUPT_MAIN_HEADER
    } else {
        // Nothing judged damaged is left unmended. Under enciphered
        // headers the exit then says what could not be done AFTER
        // mending, as the reference's does (spec L 3.8).
        enciphered_exit(&source, &walked, opts.shared.no_password).unwrap_or(Exit::Clean)
    };

    match mended {
        // Something mended: the fixed volume takes its place.
        Some(Ok((temporary, _))) if recovered > 0 => {
            if let Err(exit) = place_fixed(out, &check, &read, &temporary, &fixed, archive) {
                return exit;
            }
        }
        // Nothing did: no fixed file, as when nothing could.
        Some(Ok((temporary, _))) => {
            let _ = std::fs::remove_file(&temporary);
        }
        Some(Err(Stop::Memory { .. })) => unreachable!("refused above"),
        Some(Err(Stop::Failed(reason))) => {
            out.complain(&format!("Cannot create {fixed}\n{reason}"));
            return Exit::CannotCreate;
        }
        None => {}
    }
    if failed == 0 && !unjudged {
        out.say("Done\n");
        return done;
    }
    if recovered > 0 && !opts.shared.assume_yes {
        // Measured: the question goes to stderr, and with no answer on
        // standard input the run ends there with the fixed file kept.
        out.warn("\nReconstruct archive structure? [Y]es, [N]o ");
        match answer() {
            Some(reply) if reply.starts_with(['y', 'Y']) => {}
            Some(_) => {
                out.say("Done\n");
                return done;
            }
            None => return stdin_failed(out),
        }
    }
    let rebuilt = place("rebuilt.");
    match may_write(out, &rebuilt, opts) {
        Go::Write => {}
        Go::Skip => {
            out.say("Done\n");
            return done;
        }
        Go::Abort(exit) => return exit,
    }
    match rebuild_into(out, archive, &rebuilt, walked.ok(), size) {
        Exit::Clean => done,
        exit => exit,
    }
}

/// The exit of a repair that left nothing unmended, when the archive's
/// headers are enciphered (spec L 3.8, "The exit with enciphered
/// headers", measured on the reference over 165 runs); `None` for an
/// archive with clear headers.
///
/// The repair itself needs no key: the records and the bytes they
/// protect are the file's bytes as they stand. The exit answers for the
/// headers a key is needed for, by the first of these that holds:
///
/// - one or more bytes of the SIGNATURE do not read: 0, whatever the
///   password. No header is met to ask a password for.
/// - the ARCHIVE ENCRYPTION HEADER fails its check: 3.
/// - `-p-`, or a wrong password: 11, the archive mended all the same.
/// - no password switch at all: 0. Measured on the reference with
///   standard input at its end: it mends, names no password and exits 0,
///   where under `-p-` it exits 11. (What it does with no switch on a
///   terminal is its question to the user, which this tool does not ask.)
/// - the right password: 0, or 3 when a header does not read under it.
///
/// `walked` is the tolerant walk of the named file under the password
/// the line gave, if any; `no_password` is whether the line said `-p-`.
fn enciphered_exit(
    source: &std::fs::File,
    walked: &rarkit::Result<rarkit::Archive>,
    no_password: bool,
) -> Option<Exit> {
    // The signature, then the block behind it: its CRC32, a size of one
    // to three bytes, its type and what the size says follows. Spec L
    // 3.5.5 O6, point 1: the file is one with enciphered headers when
    // that block's type reads 4, its check holding or not.
    let mut front = [0u8; 8 + 4 + 3 + 1024];
    let got = read_whole(source, &mut front);
    let block = front[..got].get(8..)?;
    let (mut size, mut used) = (0usize, 0usize);
    for (index, &byte) in block.get(4..7)?.iter().enumerate() {
        size |= usize::from(byte & 0x7f) << (7 * index);
        used = index + 1;
        if byte & 0x80 == 0 {
            break;
        }
    }
    if block[4 + used - 1] & 0x80 != 0 || *block.get(4 + used)? != 4 {
        return None;
    }
    if front[..8] != SIGNATURE {
        return Some(Exit::Clean);
    }
    let sound = block
        .get(4..4 + used + size)
        .is_some_and(|body| rarkit::checksum::crc32(body).to_le_bytes() == block[..4]);
    if !sound {
        return Some(Exit::ChecksumMismatch);
    }
    Some(match walked {
        Ok(archive) if archive.tail().is_none() => Exit::Clean,
        Err(err) if matches!(err.kind(), rarkit::ErrorKind::WrongPassword) => Exit::WrongPassword,
        Err(err) if matches!(err.kind(), rarkit::ErrorKind::PasswordRequired) => {
            if no_password {
                Exit::WrongPassword
            } else {
                Exit::Clean
            }
        }
        _ => Exit::ChecksumMismatch,
    })
}

/// The read options a repair opens the archive with: the password, when
/// one was given, and under `-mm<size>` that budget's memory policy (a
/// named budget is a promise: the repair's working memory is held to its
/// share of it, and a repair that needs more is refused by name). With no
/// `-mm` it is the process default, as every other command reads under:
/// the larger of 512 MiB and a quarter of physical memory, under any cap
/// of the environment, the repair's limit being half of what that leaves
/// the engine.
fn read_options(opts: &Options) -> rarkit::ReadOptions {
    let read = rarkit::ReadOptions::default().with_password(
        opts.shared
            .password
            .as_deref()
            .map(|p| rarkit::Password::from(p.as_bytes())),
    );
    read.with_memory(match opts.memory_cap {
        Some(cap) => repair_policy(cap),
        None => rarkit::MemoryPolicy::process_default(0),
    })
}

/// The memory policy of a `-mm<size>` budget, as every other command
/// derives it (`crate::engine::read_options_capped`).
pub(super) fn repair_policy(cap: u64) -> rarkit::MemoryPolicy {
    rarkit::MemoryPolicy::for_process(cap.max(1 << 17), 0)
}

/// Whether the file carries the RAR 1.5 to 4.x signature.
fn is_rar4_family(mut file: &std::fs::File) -> bool {
    let mut head = [0u8; 7];
    std::io::Read::read_exact(&mut file, &mut head).is_ok() && head == *b"Rar!\x1a\x07\x00"
}

/// The RAR 5 signature.
const SIGNATURE: [u8; 8] = *b"Rar!\x1a\x07\x01\x00";

/// How far into a file the rebuild looks for the main header of an
/// archive whose signature does not read, when the reader found no
/// archive at all to bound the look: this tool's bound, not the format's.
const HEAD_SEARCH: u64 = 1 << 20;

/// Whether a main header that passes its CRC32 starts at `at` of `bytes`:
/// the CRC32, a size, then type 1.
fn sound_main_header_at(bytes: &[u8], at: usize) -> bool {
    let Some(head) = bytes.get(at..) else {
        return false;
    };
    if head.len() < 7 {
        return false;
    }
    let (mut size, mut used) = (0usize, 0usize);
    for (index, &byte) in head[4..7].iter().enumerate() {
        size |= usize::from(byte & 0x7f) << (7 * index);
        used = index + 1;
        if byte & 0x80 == 0 {
            break;
        }
    }
    let end = 4 + used + size;
    if size < 2 || head[4 + used - 1] & 0x80 != 0 || head.len() < end || head[4 + used] != 1 {
        return false;
    }
    rarkit::checksum::crc32(&head[4..end]).to_le_bytes() == head[..4]
}

/// A file with the RAR 5 signature read at `at` whatever stands there:
/// what lets the reader walk an archive whose signature is damaged and
/// whose main header is sound (spec L 3.8 B2).
struct SignatureRestored {
    file: std::fs::File,
    at: u64,
}

impl rarkit::RangeSource for SignatureRestored {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let got = rarkit::RangeSource::read_at(&self.file, offset, buf)?;
        for (index, byte) in buf[..got].iter_mut().enumerate() {
            let place = offset + index as u64;
            if (self.at..self.at + 8).contains(&place) {
                *byte = SIGNATURE[(place - self.at) as usize];
            }
        }
        Ok(got)
    }

    fn available(&self) -> u64 {
        rarkit::RangeSource::available(&self.file)
    }

    fn len(&self) -> Option<u64> {
        rarkit::RangeSource::len(&self.file)
    }
}

/// The archive a rebuild walks and where in the file it begins (spec L
/// 3.8, B1 to B4), or why there is none.
///
/// - The reader's own walk from byte 0 is the named archive's (B1).
/// - Otherwise the named archive's signature may be what does not read:
///   the first sound main header in the file, in front of whatever
///   archive the reader did find, begins the walk 8 bytes before itself,
///   behind byte 0 or behind a module (B2). A signature inside a member
///   of that archive is then that member's bytes (B3).
/// - Otherwise, a file that opens with a signature damaged in one or two
///   of its eight bytes is the named archive with no head left to walk:
///   nothing is rebuilt from an archive further in. (Measured on the
///   reference: with a signature bit and a main header bit changed it
///   writes nothing.)
/// - Otherwise the archive the reader found past byte 0 is rebuilt, as
///   the reference rebuilds it, and the caller says where it began (B4):
///   bytes in front of an archive are a module, and an archive stored in
///   one whose own head is destroyed cannot be told from that.
fn named_archive(
    path: &str,
    walked: Option<rarkit::Archive>,
    size: u64,
) -> Result<(rarkit::Archive, u64, bool), &'static str> {
    const NO_WALK: &str = "its headers do not walk, and rebuilding them by scanning is not built";
    let walked = match walked {
        Some(archive) if archive.start() == 0 => return Ok((archive, 0, false)),
        other => other,
    };
    let limit = walked
        .as_ref()
        .map_or(HEAD_SEARCH, rarkit::Archive::start)
        .min(size);
    let mut front = vec![0u8; (limit + (1 << 16)).min(size) as usize];
    let file = std::fs::File::open(path).map_err(|_| NO_WALK)?;
    let got = read_whole(&file, &mut front);
    front.truncate(got);
    let sound = (0..limit as usize).find(|&at| sound_main_header_at(&front, at + 8));
    if let Some(at) = sound {
        let at = at as u64;
        let view: std::sync::Arc<dyn rarkit::RangeSource> =
            std::sync::Arc::new(SignatureRestored { file, at });
        let options = rarkit::ReadOptions::default().with_tolerant_tail(true);
        return match rarkit::Archive::open(view, &options) {
            Ok(archive) if archive.start() == at => Ok((archive, at, true)),
            _ => Err(NO_WALK),
        };
    }
    let alike = front
        .iter()
        .zip(SIGNATURE)
        .filter(|(have, want)| *have == want)
        .count();
    if alike >= 6 {
        return Err(
            "its signature and its main header do not read, and rebuilding its headers by \
             scanning is not built",
        );
    }
    match walked {
        Some(archive) => {
            let at = archive.start();
            Ok((archive, at, false))
        }
        None => Err(NO_WALK),
    }
}

/// Fills `buf` from the start of `file`, as far as the file goes.
fn read_whole(file: &std::fs::File, buf: &mut [u8]) -> usize {
    let mut got = 0;
    while got < buf.len() {
        match rarkit::RangeSource::read_at(file, got as u64, &mut buf[got..]) {
            Ok(0) | Err(_) => break,
            Ok(more) => got += more,
        }
    }
    got
}

/// The destination directory, if the line names one, created if it is
/// not there yet.
///
/// Measured: a last argument ending in `/` is a directory, created with
/// the reference's own `Creating` line; one that does not end in `/` is a
/// directory only when it already is one, and is otherwise ignored.
fn destination(
    out: &Out,
    masks: &[String],
    extract_path: Option<&str>,
) -> Result<Option<String>, Exit> {
    let named = extract_path.map(str::to_owned).or_else(|| {
        masks
            .first()
            .filter(|mask| std::path::Path::new(mask).is_dir())
            .cloned()
    });
    let Some(named) = named else {
        return Ok(None);
    };
    let trimmed = named.trim_end_matches('/');
    let dir = if trimmed.is_empty() { "/" } else { trimmed }.to_owned();
    if !std::path::Path::new(&dir).is_dir() {
        if let Err(err) = std::fs::create_dir_all(&dir) {
            out.complain(&format!("Cannot create {dir}\n{}", unrar::io_reason(&err)));
            return Err(Exit::CannotCreate);
        }
        // The name padded to column 70, then `OK`, measured.
        out.say(&format!("{:<70}OK\n", format!("Creating    {dir}")));
    }
    Ok(Some(dir))
}

/// What to do about an output file.
pub(super) enum Go {
    Write,
    Skip,
    Abort(Exit),
}

/// Whether anything stands at `path`: a file, a directory, or a link,
/// whatever it points at or fails to.
pub(super) fn taken(path: &str) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// How many numbered names `-or` tries before it gives the name up as it
/// is: this tool's bound, so a directory full of them ends in the
/// overwrite question and not in a walk without end.
const NUMBERED_NAMES: u32 = 100_000;

/// The name an output takes under `-or`: `output` itself when nothing
/// stands there, else `output` with `(n)` before its LAST dot, for the
/// least `n` from 1 whose name is free; `None` when none of the bound is.
///
/// Measured on the reference, 10 Oct 2026, fourteen arms: `fixed.a.rar`
/// gives `fixed.a(1).rar`, then `(2)`; a gap is filled (`(1)` when only
/// `(2)` stands); `fixed.noext` gives `fixed(1).noext`, the only dot being
/// the prefix's own; `fixed.noext.` gives `fixed.noext(1).`; a name that
/// is numbered already is numbered again, `fixed.a(1)(1).rar`. `output`
/// is a file name with no directory in it, and always has the prefix's
/// dot.
pub(super) fn free_name(output: &str, taken: impl Fn(&str) -> bool) -> Option<String> {
    if !taken(output) {
        return Some(output.to_owned());
    }
    let dot = output.rfind('.').unwrap_or(output.len());
    (1..=NUMBERED_NAMES)
        .map(|n| format!("{}({n}){}", &output[..dot], &output[dot..]))
        .find(|candidate| !taken(candidate))
}

/// Whether `path` may be written, asking the reference's question when it
/// is already there.
///
/// Measured: `-o+` and `-y` overwrite; `-o-` skips, and the whole rest of
/// the run is `Done`; with neither, the question goes to stderr and the
/// answer is read from standard input, so `echo y |` overwrites.
pub(super) fn may_write(out: &Out, path: &str, opts: &Options) -> Go {
    if !std::path::Path::new(path).exists() {
        return Go::Write;
    }
    match opts.shared.overwrite {
        unrar::args::Overwrite::Always => return Go::Write,
        unrar::args::Overwrite::Never => return Go::Skip,
        // Under `-or` the path is a free one already (`free_name`); a
        // taken one here means every numbered name is taken too, and the
        // default rule answers.
        unrar::args::Overwrite::Ask | unrar::args::Overwrite::Rename if opts.shared.assume_yes => {
            return Go::Write
        }
        unrar::args::Overwrite::Ask | unrar::args::Overwrite::Rename => {}
    }
    out.warn(&format!(
        "\n\nOverwrite {path}?\n[Y]es, [N]o, [A]ll, n[E]ver, [R]ename, [Q]uit "
    ));
    match answer() {
        Some(reply) if reply.starts_with(['y', 'Y', 'a', 'A']) => Go::Write,
        Some(_) => Go::Skip,
        None => Go::Abort(stdin_failed(out)),
    }
}

/// One line from standard input, or `None` when there is none to read.
pub(super) fn answer() -> Option<String> {
    let mut line = String::new();
    match std::io::stdin().lock().read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim().to_owned()),
    }
}

/// The reference's answer to a question nobody can answer: measured with
/// standard input on `/dev/null`, `Read error in the file stdin` and the
/// C library's reason on stderr, `Program aborted`, exit 12.
pub(super) fn stdin_failed(out: &Out) -> Exit {
    out.warn("Read error in the file stdin\nInappropriate ioctl for device\n");
    out.say("\nProgram aborted\n");
    Exit::ReadFailed
}

/// The "Searching" counter after its opening `0%`: one tick per window,
/// printed when the whole percentage moves.
fn search_ticks(size: u64) -> String {
    let mut text = counter(0);
    let mut last = 0;
    let mut at = 0u64;
    while at < size {
        at = (at + SEARCH_WINDOW).min(size);
        let percent = at * 100 / size;
        if percent != last {
            text.push_str(&counter(percent));
            last = percent;
        }
    }
    if last != 100 {
        text.push_str(&counter(100));
    }
    text
}

/// The "Analyzing" counter: one tick per batch of shards, the last of
/// them at `(k - 1) / k` rather than at the whole, then `100%`. Measured:
/// `98%` for `k = 88`, `99%` for `k = 142` and `200`, and `10 20 .. 90 99`
/// for batches of 20 of 200.
fn analysis_ticks(check: &rarkit::recovery::InlineCheck) -> String {
    let k = u64::from(check.shards).max(1);
    let batch = (ANALYSIS_BATCH / (check.protected / k).max(1)).max(1);
    let mut text = String::new();
    let mut last = None;
    let mut done = 0u64;
    while done < k {
        done = (done + batch).min(k);
        let percent = if done < k {
            done * 100 / k
        } else {
            (k - 1) * 100 / k
        };
        if last != Some(percent) {
            text.push_str(&counter(percent));
            last = Some(percent);
        }
    }
    text.push_str(&counter(100));
    text
}

/// Why [`mend`] wrote no mended volume.
enum Stop {
    /// The repair's working memory, the rebuilt slices it has to hold
    /// included, is past the run's limit: refused before a slice is
    /// rebuilt.
    Memory { needed: u64, limit: u64 },
    /// Anything else, in words.
    Failed(String),
}

/// The refusal of a repair that does not fit the memory limit: by name,
/// on stderr, with both figures and the switch that lets it run, exit 2,
/// and nothing written. Never `recovered` and never `cannot recover`:
/// the data may well mend under a larger limit.
///
/// The size named is the smallest whole-megabyte `-mm` whose policy gives
/// the repair what it needs, found by asking the policy itself, since a
/// budget's repair share is not a fixed fraction of it.
pub(super) fn refuse_for_memory(out: &Out, archive: &str, needed: u64, limit: u64) -> Exit {
    let fits = |megabytes: u64| repair_policy(megabytes << 20).repair_limit >= needed;
    // The repair limit never goes down as the budget goes up, so the
    // smallest budget that fits is found by halving.
    let (mut low, mut high) = (1u64, 1u64 << 24);
    let advice = if fits(high) {
        while low < high {
            let middle = low + (high - low) / 2;
            if fits(middle) {
                high = middle;
            } else {
                low = middle + 1;
            }
        }
        format!("-mm{high}m or more lets it run.")
    } else {
        "No -mm this build accepts gives a repair that much.".to_owned()
    };
    out.warn(&format!(
        "\nrarfast: {archive} is not repaired: the repair needs {needed} bytes of working \
         memory and its limit is {limit}. {advice}\n"
    ));
    Exit::Aborted
}

/// Writes the volume to `target`, the new file [`fresh`] made at
/// `temporary`, with every recoverable group mended,
/// and answers which slices of each group are STILL damaged there because
/// their rebuild failed its own check.
///
/// The repair says only THAT a rebuilt slice failed, so when one did the
/// mended volume is checked against its record once more to learn which;
/// a run where every rebuild held pays nothing for this.
fn mend(
    source: &std::fs::File,
    check: &rarkit::recovery::InlineCheck,
    read: &rarkit::ReadOptions,
    temporary: &str,
    target: std::fs::File,
) -> Result<Vec<Vec<u16>>, Stop> {
    let failed = |e: &std::io::Error| Stop::Failed(unrar::io_reason(e));
    let mut buffered = std::io::BufWriter::new(&target);
    let report = rarkit::recovery::repair_checked(source, check, read, &mut buffered).map_err(
        |e| match e.kind() {
            rarkit::ErrorKind::LimitExceeded {
                resource: rarkit::Resource::RepairWork,
                needed,
                limit,
            } => Stop::Memory {
                needed: *needed,
                limit: *limit,
            },
            _ => Stop::Failed(e.to_string()),
        },
    )?;
    buffered.flush().map_err(|e| failed(&e))?;
    drop(buffered);
    if report.failed.is_empty() {
        return Ok(vec![Vec::new(); check.groups.len()]);
    }
    let again = std::fs::File::open(temporary).map_err(|e| failed(&e))?;
    Ok(match rarkit::recovery::check_inline(&again, read) {
        Ok(after) if after.groups.len() == check.groups.len() => after
            .groups
            .into_iter()
            .map(|group| group.damaged)
            .collect(),
        // The mended volume no longer answers: nothing is known to have
        // mended, so nothing is said to have.
        _ => check
            .groups
            .iter()
            .map(|group| group.damaged.clone())
            .collect(),
    })
}

/// Makes [`mend`]'s file the fixed volume at `path`: cut at its end
/// block, closed with [`LAST_END_BLOCK`].
///
/// Two shapes differ, both measured: a volume whose headers are
/// ENCRYPTED and walk with the password given is kept whole, its own
/// encrypted end block and padding included; one whose headers cannot be
/// walked at all (`-hp` and no password) is cut at the protected bytes.
fn place_fixed(
    out: &Out,
    check: &rarkit::recovery::InlineCheck,
    read: &rarkit::ReadOptions,
    temporary: &str,
    path: &str,
    like: &str,
) -> Result<(), Exit> {
    let placed = cut_fixed(check, read, temporary, like)
        .and_then(|()| std::fs::rename(temporary, path).map_err(|e| unrar::io_reason(&e)));
    if let Err(reason) = placed {
        let _ = std::fs::remove_file(temporary);
        out.complain(&format!("Cannot create {path}\n{reason}"));
        return Err(Exit::CannotCreate);
    }
    Ok(())
}

/// [`place_fixed`]'s cut, on `temporary` in place, and the mode of `like`
/// when it is whole.
fn cut_fixed(
    check: &rarkit::recovery::InlineCheck,
    read: &rarkit::ReadOptions,
    temporary: &str,
    like: &str,
) -> Result<(), String> {
    let mut target = std::fs::OpenOptions::new()
        .write(true)
        .open(temporary)
        .map_err(|e| unrar::io_reason(&e))?;
    // Where the fixed volume's own end block starts, if its headers
    // walk: the mended volume, not the damaged one, is what is walked.
    let walked = rarkit::Session::new(read.clone().with_tolerant_tail(true))
        .open_path(std::path::Path::new(temporary))
        .ok();
    let end = walked.as_ref().and_then(|archive| {
        archive
            .blocks()
            .find(|block| block.kind == rarkit::BlockKind::End)
            .map(|block| block.range.start)
    });
    match end {
        Some(_)
            if walked
                .as_ref()
                .is_some_and(rarkit::Archive::headers_encrypted) => {}
        Some(at) => {
            target.set_len(at).map_err(|e| unrar::io_reason(&e))?;
            std::io::Seek::seek(&mut target, std::io::SeekFrom::End(0))
                .map_err(|e| unrar::io_reason(&e))?;
            target
                .write_all(&LAST_END_BLOCK)
                .map_err(|e| unrar::io_reason(&e))?;
        }
        None => target
            .set_len(check.protected)
            .map_err(|e| unrar::io_reason(&e))?,
    }
    seal(&target, like).map_err(|e| unrar::io_reason(&e))
}

/// The rebuild when there is no record to repair from: overwrite check
/// first, then the rebuild itself.
fn rebuild(
    out: &Out,
    archive: &str,
    path: &str,
    walked: Option<rarkit::Archive>,
    size: u64,
    opts: &Options,
) -> Exit {
    match may_write(out, path, opts) {
        Go::Write => {}
        Go::Skip => {
            out.say("Done\n");
            return Exit::Clean;
        }
        Go::Abort(exit) => return exit,
    }
    rebuild_into(out, archive, path, walked, size)
}

/// `rebuilt.<name>`: the volume up to its end block, one `Found` line per
/// member header on the way.
///
/// Measured on intact headers, with and without a record, damaged data
/// and not, one volume and a set, with directories, a comment and a
/// quick-open record: the reference's file is exactly those bytes, and
/// its counter ticks at the end of each block when the percentage moves.
/// The end block is kept only when at least eight more bytes follow it:
/// measured, a volume `rar` padded keeps it and drops the padding, while a
/// lone archive, a last volume and an unpadded volume (rarfast writes
/// none) end where their end block starts.
fn rebuild_into(
    out: &Out,
    archive: &str,
    path: &str,
    walked: Option<rarkit::Archive>,
    size: u64,
) -> Exit {
    out.say(&format!("Reconstructing {archive}\n"));
    let (walked, start, restored) = match named_archive(archive, walked, size) {
        Ok(found) => found,
        Err(why) => return refuse(out, archive, why),
    };
    if walked.tail().is_some() {
        return refuse(
            out,
            archive,
            "its headers do not walk, and rebuilding them by scanning is not built",
        );
    }
    let end_block = walked
        .blocks()
        .find(|block| block.kind == rarkit::BlockKind::End);
    // Spec L 3.8 B6: an archive found past byte 0 with a sound block
    // right behind its end block is a stored member, and the rebuild is
    // of the archive that encloses it.
    if let (true, Some(block)) = (start != 0, &end_block) {
        if let Some(enclosing) = Enclosing::behind(archive, block.range.end) {
            return rebuild_enclosing(out, archive, path, &enclosing, start, size);
        }
    }
    let Some(end) = end_block.map(|block| {
        if block.range.end.saturating_add(8) <= size {
            block.range.end
        } else {
            block.range.start
        }
    }) else {
        return refuse(
            out,
            archive,
            "its headers stop before the end block, and rebuilding them by scanning is not built",
        );
    };

    out.say(&format!("Building {path}{COUNTER_GAP}"));
    out.say(&counter(0));
    let mut last = 0;
    let mut members = walked.members();
    for block in walked.blocks() {
        if block.kind == rarkit::BlockKind::File {
            if let Some(member) = members.next() {
                out.say(&format!(
                    "\nFound  {}     ",
                    unrar::text_from_archive(member.name)
                ));
            }
        }
        let percent = block.range.end.min(size) * 100 / size.max(1);
        if percent != last {
            out.say(&counter(percent));
            last = percent;
        }
        if block.kind == rarkit::BlockKind::End {
            break;
        }
    }
    if last != 100 {
        out.say(&counter(100));
    }
    out.say("\n");

    let copied = copy_archive(archive, start, restored, end, path);
    if let Err(err) = copied {
        out.complain(&format!("Cannot create {path}\n{}", unrar::io_reason(&err)));
        return Exit::CannotCreate;
    }
    if start != 0 {
        // Spec L 3.8 B4: one line, with the offset, whenever it is not 0.
        out.warn(&format!(
            "\nrarfast: the archive rebuilt as {path} was found at offset {start} of {archive}, \
             not at the file's first byte.\n"
        ));
    }
    // A rebuild rebuilds headers and promises nothing of the data.
    out.warn(&format!(
        "\nrarfast: {path} holds the members' data copied as it was found; none of it was \
         checked. Test it with the t command.\n"
    ));
    out.say("Done\n");
    Exit::Clean
}

/// A fresh head, then the file's bytes from `from` on: what lets the
/// reader walk the blocks that stand behind a stored archive when the
/// head of the archive they belong to is lost (spec L 3.8 B6).
struct BehindAHead {
    head: [u8; Enclosing::HEAD],
    file: std::fs::File,
    from: u64,
}

impl rarkit::RangeSource for BehindAHead {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let head = self.head.len() as u64;
        if offset >= head {
            return rarkit::RangeSource::read_at(&self.file, self.from + (offset - head), buf);
        }
        let have = &self.head[offset as usize..];
        let take = have.len().min(buf.len());
        buf[..take].copy_from_slice(&have[..take]);
        Ok(take)
    }

    fn available(&self) -> u64 {
        self.head.len() as u64
            + rarkit::RangeSource::available(&self.file).saturating_sub(self.from)
    }

    fn len(&self) -> Option<u64> {
        rarkit::RangeSource::len(&self.file)
            .map(|len| self.head.len() as u64 + len.saturating_sub(self.from))
    }
}

/// The archive that encloses a stored one whose walk ended at `from`
/// (spec L 3.8 B6): the blocks that stand from there on, walked behind a
/// fresh head.
///
/// An archive's end block is the last block of its file. So a sound
/// block header right behind a walked archive's end block, with no
/// signature in front of it, is a block of an enclosing archive, and the
/// walked archive is a stored member's data. The enclosing archive's own
/// head is what was lost, the stored member's file header with it.
struct Enclosing {
    walked: rarkit::Archive,
    from: u64,
}

impl Enclosing {
    /// A signature and the least main header there is: its CRC32, its
    /// size, type 1, no header flags and no archive flags.
    const HEAD: usize = 16;

    fn head() -> [u8; Self::HEAD] {
        const MAIN: [u8; 4] = [3, 1, 0, 0];
        let mut head = [0u8; Self::HEAD];
        head[..8].copy_from_slice(&SIGNATURE);
        head[8..12].copy_from_slice(&rarkit::checksum::crc32(&MAIN).to_le_bytes());
        head[12..].copy_from_slice(&MAIN);
        head
    }

    /// The enclosing archive whose blocks begin at `from` of `path`, or
    /// `None` when no sound block stands there: the file ends, or what
    /// follows is not a block (a volume's padding, another archive under
    /// its own signature, anything else).
    fn behind(path: &str, from: u64) -> Option<Enclosing> {
        let file = std::fs::File::open(path).ok()?;
        let view: std::sync::Arc<dyn rarkit::RangeSource> = std::sync::Arc::new(BehindAHead {
            head: Self::head(),
            file,
            from,
        });
        let options = rarkit::ReadOptions::default().with_tolerant_tail(true);
        let walked = rarkit::Archive::open(view, &options).ok()?;
        let sound_behind = walked.start() == 0
            && walked
                .blocks()
                .any(|block| block.kind != rarkit::BlockKind::Main);
        sound_behind.then_some(Enclosing { walked, from })
    }

    /// Where a byte of the walked view stands in the file.
    fn in_file(&self, at: u64) -> u64 {
        self.from + at.saturating_sub(Self::HEAD as u64)
    }
}

/// `rebuilt.<name>` for an archive whose head is lost and whose later
/// blocks stand behind a stored archive (spec L 3.8 B6): a fresh head,
/// each later member's header and data as found, and a fresh end block.
///
/// The stored archive is LEFT OUT: its own file header, with its name,
/// went with the head, and no name is made up for it; one line gives its
/// offset and its length. The enclosing archive's service blocks are
/// left out too: its quick open data and its recovery record describe
/// the file as it was, head and stored member included.
fn rebuild_enclosing(
    out: &Out,
    archive: &str,
    path: &str,
    enclosing: &Enclosing,
    stored_at: u64,
    size: u64,
) -> Exit {
    const NO_WALK: &str =
        "the headers behind the archive stored in it do not walk, and rebuilding \
                           them by scanning is not built";
    let walked = &enclosing.walked;
    let ended = walked
        .blocks()
        .any(|block| block.kind == rarkit::BlockKind::End);
    if walked.tail().is_some() || !ended {
        return refuse(out, archive, NO_WALK);
    }

    out.say(&format!("Building {path}{COUNTER_GAP}"));
    out.say(&counter(0));
    let mut last = 0;
    let mut members = walked.members();
    let mut kept = Vec::new();
    for block in walked.blocks() {
        if block.kind == rarkit::BlockKind::File {
            if let Some(member) = members.next() {
                out.say(&format!("\nFound  {}     ", member.name_lossy()));
            }
            kept.push(enclosing.in_file(block.range.start)..enclosing.in_file(block.range.end));
        }
        let percent = enclosing.in_file(block.range.end).min(size) * 100 / size.max(1);
        if percent != last {
            out.say(&counter(percent));
            last = percent;
        }
        if block.kind == rarkit::BlockKind::End {
            break;
        }
    }
    if last != 100 {
        out.say(&counter(100));
    }
    out.say("\n");

    let copied = || -> std::io::Result<()> {
        let (temporary, mut to) = fresh(path, archive)?;
        let mut copy = || -> std::io::Result<()> {
            let mut file = std::fs::File::open(archive)?;
            to.write_all(&Enclosing::head())?;
            for range in &kept {
                std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(range.start))?;
                let mut block = std::io::Read::take(&mut file, range.end - range.start);
                std::io::copy(&mut block, &mut to)?;
            }
            to.write_all(&LAST_END_BLOCK)?;
            to.flush()?;
            seal(&to, archive)?;
            std::fs::rename(&temporary, path)
        };
        let result = copy();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    };
    if let Err(err) = copied() {
        out.complain(&format!("Cannot create {path}\n{}", unrar::io_reason(&err)));
        return Exit::CannotCreate;
    }
    // Spec L 3.8 B6: one line, with the offset and the length.
    out.warn(&format!(
        "\nrarfast: the head of {archive} is lost. An archive stored in it at offset {stored_at}, \
         {} bytes long, has no header of its own left and is not in {path}; the members found \
         behind it are.\n",
        enclosing.from.saturating_sub(stored_at)
    ));
    out.warn(&format!(
        "\nrarfast: {path} holds the members' data copied as it was found; none of it was \
         checked. Test it with the t command.\n"
    ));
    out.say("Done\n");
    // A member of the named archive is known to be missing from the file
    // written: never the exit of a whole archive.
    Exit::ChecksumMismatch
}

/// A new, empty file beside `path` for an output to be written into
/// before it takes that name, and the file's own name.
///
/// The file is CREATED, never opened: a name already taken, by a file, by
/// a link somebody left there or by another run's work in progress, is
/// passed over for the next, so nothing that was there is truncated or
/// written through and two runs never share a file.
///
/// It is its owner's alone, to read and to write, for as long as it is
/// being made. The mode it ends with is given by [`seal`], on the open
/// file, when it is whole and before it takes its name: so an archive
/// its owner may not write (mode 0444) is repaired like any other, the
/// output staying writable until the last byte is in it. `_like`, the
/// archive, is not read here.
pub(super) fn fresh(path: &str, _like: &str) -> std::io::Result<(String, std::fs::File)> {
    // How many names are tried before the directory is called full of
    // them: each is one refused create, so the bound costs nothing in
    // the ordinary case, where the first name is free.
    const NAMES: u32 = 10_000;
    let mut making = std::fs::OpenOptions::new();
    making.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        making.mode(0o600);
    }
    for turn in 0..NAMES {
        let name = format!("{path}.rarfast-new.{turn}");
        let file = match making.open(&name) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        };
        return Ok((name, file));
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!(
            "every name from {path}.rarfast-new.0 to .{} is taken",
            NAMES - 1
        ),
    ))
}

/// Gives a whole output, still under its temporary name, the mode of
/// `like`, the archive it was made from, on the open file.
///
/// A REPAIRED ARCHIVE KEEPS THE NAMED ARCHIVE'S OWN MODE (decided 10 Oct
/// 2026; a chosen difference from the reference, whose output has what
/// the umask gives a new file, 0644 under 022, whatever the archive's
/// mode: spec L 3.9 F4). A repair does not make a private file readable:
/// 0600 stays 0600, and 0444 ends 0444. This is the ONE place the mode
/// is decided.
pub(super) fn seal(output: &std::fs::File, like: &str) -> std::io::Result<()> {
    output.set_permissions(std::fs::metadata(like)?.permissions())
}

/// Writes bytes `start` to `end` of `archive` to `path`, the RAR 5
/// signature in place of the first eight when `restored`, through a
/// [`fresh`] file beside it so a failure leaves nothing half written.
///
/// Measured on the reference: the rebuilt file begins with the archive,
/// whatever stood in front of it in the file, and with a whole signature.
fn copy_archive(
    archive: &str,
    start: u64,
    restored: bool,
    end: u64,
    path: &str,
) -> std::io::Result<()> {
    use std::io::{Read as _, Seek as _, Write as _};
    let (temporary, target) = fresh(path, archive)?;
    let written = (|| {
        let mut target = target;
        let length = end.saturating_sub(start);
        // The signature stands for as many of the first eight bytes as the
        // range holds, and the copy begins behind them.
        let stood_for = if restored {
            length.min(SIGNATURE.len() as u64)
        } else {
            0
        };
        target.write_all(&SIGNATURE[..stood_for as usize])?;
        let mut source = std::fs::File::open(archive)?;
        source.seek(std::io::SeekFrom::Start(start + stood_for))?;
        let owed = length - stood_for;
        let copied = std::io::copy(&mut source.take(owed), &mut target)?;
        if copied != owed {
            // The archive ends before `end`: a short file under the
            // rebuilt name would read as the whole of it.
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        target.flush()?;
        seal(&target, archive)?;
        drop(target);
        std::fs::rename(&temporary, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    written
}

/// The refusal for what the reference does and this does not: by name,
/// on stderr, with a non-zero code, and nothing written.
fn refuse(out: &Out, archive: &str, why: &str) -> Exit {
    out.warn(&format!(
        "\nrarfast: cannot repair {archive}: {why}. Use the reference `rar` for this one.\n"
    ));
    Exit::Aborted
}
