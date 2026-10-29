//! The `rar` dialect: the creator command set the reference answers to.
//!
//! `rar.exe` and `winrar.exe` share one command-line syntax (WinRAR's
//! manual documents it once for both), so this is the dialect for both
//! names. `winrar.exe` additionally answers errors with a dialog, which
//! makes it the wrong oracle for an exit code, so the reference for
//! every table here is the console `rar`, pinned at 7.23.
//!
//! What "the same" means is not a judgement call. The pinned
//! reference was captured on macOS and on Windows into two fixtures in the
//! project's conformance harness:
//!
//! - the captured `rar` 7.23 inventory, its own `-?`
//!   screen plus the 29 command and 118/130 switch spellings parsed out
//!   of it, and
//! - the captured `rar` 7.23 expectations, the output, exit
//!   code and resulting file tree for 175 rows.
//!
//! The conformance run against `rarfast` is the gate.
//!
//! **The read-only commands are the decoder's, not a second copy.**
//! Measured 3 Sep 2026 against the pinned pair: `rar l`, `rar lt`,
//! `rar t`, `rar x` and their siblings emit the same bytes as the
//! `unrar` spellings for the same archive, differing only in the banner
//! the harness normalises away. So [`Command::is_read_only`] hands the
//! parse to [`super::unrar::dispatch`] rather than growing a listing
//! implementation beside it that could drift; the column widths and the
//! percentage formula the decoder measured stay in one place.
//!
//! **What the creator half can and cannot do today is stated, never
//! implied.** A command this dialect cannot honour end to end refuses by
//! NAME and with a non-zero code rather than exiting 0 having done
//! something different, which the spec's R.2 paragraph is explicit is
//! the worse of the two failures. [`unimplemented_command`] is that
//! refusal and its doc comment carries the list.

mod ahead;
pub(crate) mod args;
mod commands;
mod create;
mod edit;
mod help;
mod lines;
mod repair;
mod restore;
mod select;

/// The version `-iver` prints.
///
/// It is the PINNED REFERENCE's version, not the fork's, and that is the
/// point: a script that reads `rar -iver` to decide what the tool can do
/// is asking about the dialect it is talking to. The conformance
/// fixtures are captured from 7.23, so this constant and the two help
/// screens move together when the pin moves.
///
/// The Windows build appends its architecture - the `sweep/iver` row of
/// the Windows table is `7.23 x64` where the macOS one is `7.23` - so
/// this is two constants, like the help screens and for the same reason.
#[cfg(windows)]
pub(crate) const REFERENCE_VERSION: &str = "7.23 x64";
/// See the Windows arm above.
#[cfg(not(windows))]
pub(crate) const REFERENCE_VERSION: &str = "7.23";

use std::ffi::OsString;

use args::{Command, Parsed};

use super::unrar::{self, Exit, Out};

/// Runs a `rar` command line, `argv[0]` already removed.
pub(crate) fn run(argv: &[OsString]) -> Exit {
    let parsed = match args::parse(argv) {
        Ok(parsed) => parsed,
        Err(refusal) => {
            println!("{}", refusal.message);
            return refusal.exit;
        }
    };
    dispatch(parsed)
}

/// Runs a command line typed against `rarfast`'s OWN name.
///
/// Under `unrar` or `rar` the dialect is settled by `argv[0]` and each
/// parser owns the line. Under our own name it is not settled, and the
/// two switch sets are not the same: `rar` has 118 spellings on macOS
/// and `unrar` 63, overlapping but not nested, and a handful of letters
/// mean different things to the two tools (`-f`, `-u`, `-t`, `-v` and
/// the `-m` family). So the rule is decoder-first with a creator
/// fallback: a line the decoder can read is read the decoder's way, and
/// a line it refuses as an unknown option is offered to the creator
/// before the refusal is printed.
///
/// That makes `rarfast` accept the UNION of the two inventories, which
/// is what both conformance legs ask of it - each probes this binary by
/// the path it was given, against its own tool's inventory, and the
/// claim each checks is that we refuse nothing the reference accepted.
/// It also keeps the decoder's reading of a shared spelling, so no
/// `unrar` row changes meaning by having been routed through here.
pub(crate) fn run_shared_command(argv: &[OsString]) -> Exit {
    match unrar::args::parse(argv) {
        Ok(parsed) => unrar::dispatch(parsed),
        Err(refusal) => match args::parse(argv) {
            Ok(parsed) => dispatch(parsed),
            // Both dialects refuse it, so the decoder's wording stands:
            // it is the one the `stop-switch-scan` rows of BOTH legs
            // compare against, and the two agree on it.
            Err(_) => {
                println!("{}", refusal.message);
                refusal.exit
            }
        },
    }
}

/// The one creator command the fork still cannot honour end to end.
///
/// Every other writing command is implemented, and for a stored archive
/// it writes the reference's own bytes (`r` landed with its repair driver
/// on 30 Sep 2026, see [`repair`]). This one is not, and it is refused BY
/// NAME with a non-zero code rather than exiting 0 having done something
/// different, which the spec's R.2 paragraph is explicit is the worse of
/// the two failures:
///
/// * `i[par]=<str>` is not merely unbuilt, it is NOT UNDERSTOOD:
///   measured on the `find-string` row, the reference reports a second
///   hit against `rand.bin`, a member of seeded pseudo-random bytes that
///   cannot contain the word, and prints beside it the second occurrence
///   from `text.txt`. Implementing that by guessing would produce a row
///   that passes for the wrong reason, so it needs the behaviour
///   measured across several shapes first.
///
/// The refusal is [`Exit::Aborted`] rather than [`Exit::BadCommandLine`]: the
/// caller spelled a real command correctly, and telling them they made a
/// usage error would send them looking for a typo they did not make.
fn unimplemented_command(word: &str) -> Exit {
    eprintln!(
        "rarfast: `{word}` is the one rar creator command rarfast does not \
         implement - `i` (find a string in archived data). Every other writing \
         command is built. Use the reference `rar` for this one."
    );
    Exit::Aborted
}

/// Picks the implementation for a parsed command line.
fn dispatch(parsed: Parsed) -> Exit {
    // The process's allocator policy, set before any worker starts: a
    // stated `-mm` budget's, else a create's;
    // any other command line changes nothing.
    let creates = matches!(
        parsed.command,
        Some(Command::Add | Command::Move { .. } | Command::Update | Command::Freshen)
    );
    crate::alloc_policy::on_command(parsed.opts.memory_cap, creates);
    // Where the process runs, also before any worker starts: with the
    // knob set, a create is kept to one NUMA node's CPUs (`one_node`).
    crate::one_node::on_command(parsed.opts.shared.threads, creates);
    // Read BEFORE the destructure, because it is a rule over three
    // fields at once; see [`args::sfx_selection`] for what it decides.
    let sfx = args::sfx_selection(&parsed);
    let Parsed {
        command,
        command_word,
        command_number,
        archive,
        masks,
        extract_path,
        opts,
        ..
    } = parsed;

    if opts.print_version {
        // `-iver` beats the command, whatever it was: the `sweep/iver`
        // row is `rar l -iver arc.rar` and its whole output is the
        // version number. It goes through `Out` like every other
        // message, because it is one: measured 19 Sep 2026, `rar -iver`
        // prints `7.23` and `rar -idq -iver` prints nothing at all.
        Out::new(&opts.shared).say(&format!("{}\n", crate::dialect::rar::REFERENCE_VERSION));
        return Exit::Clean;
    }

    let Some(command) = command else {
        // No command word at all is the reference's own "show the help"
        // path and exits 0. A word that is NOT a command shows the same
        // screen, exits 7, and - measured, because it is not what the
        // screen suggests - still tries to open the archive named beside
        // it, so a missing file is reported on stderr as well. Those are
        // the `no-arguments` and `bad-command` rows.
        let out = Out::new(&opts.shared);
        out.say(&format!("\n{}", help::help_screen()));
        let Some(archive) = archive else {
            return Exit::Clean;
        };
        if let Err(text) = unrar::missing_archive_message(&unrar::default_extension(&archive)) {
            out.warn(&format!("{text}\n"));
        }
        return Exit::BadCommandLine;
    };

    // A list file that could not be read stops every command, in the
    // reference's words and with its code: measured against rar 7.23 on
    // 4 Oct 2026 for `d`, `rn`, `lb`, `t` and `x`, the list given as an
    // argument, as `-n@` and as `-x@`, each answers `Cannot open
    // <list>` and the reason, `Program aborted`, exit 6, and changes
    // nothing. Only a create stopped on it (`create::add`); read as an
    // empty list, a mistyped `-x@` list excluded nothing from a delete.
    if let Some(text) = &opts.unread_list {
        let out = Out::for_creator(&opts.shared);
        out.complain(text);
        out.abort();
        return Exit::CannotOpen;
    }

    if command.is_read_only() {
        // `-ep` and `-f` on an extraction, which this parser keeps in
        // fields of its own (`path_mode`, `freshen`) and the decoder
        // therefore never sees: until 4 Oct 2026 `rarfast x -ep -m5
        // arc.rar`, a line only this parser reads, rebuilt the whole tree
        // and exited 0 (measured that day, rar 7.23 writes the files with
        // no folders for `-ep`, and for `-f` into an empty directory
        // writes nothing, exit 10). Refused by name before the archive is
        // opened, on `x` and `e` only, in the decoder's own words for a
        // switch it reads and does not honour, and with its code.
        if matches!(command, Command::ExtractFull | Command::ExtractFlat) {
            let named = if opts.path_mode == args::PathMode::NoPaths {
                Some("-ep")
            } else if opts.freshen {
                Some("-f")
            } else {
                None
            };
            if let Some(named) = named {
                Out::new(&opts.shared).warn(&format!(
                    "rarfast: {named} is read and not honoured yet; refused, and nothing was \
                     written\n"
                ));
                return Exit::BadCommandLine;
            }
        }
        // The two dialects agree byte for byte here, so the decoder
        // answers it with the switch state this parser already folded
        // into its shared half.
        let mut shared = opts.shared;
        shared.generate_name = opts.generate_name;
        // `-mm<size>` bounds a read as it bounds a create.
        shared.memory_cap = opts.memory_cap;
        return unrar::dispatch(unrar::args::Parsed {
            command: read_only_as_decoder(command),
            archive,
            masks,
            extract_path,
            opts: shared,
        });
    }

    // The creator's output is built the same way the decoder's is:
    // `-idq` silences the stdout stream and nothing narrower, so one
    // constructor serves both halves, with the creator's stand-in for the
    // logo the reference opens with. See `Out::new`, `Out::for_creator`.
    let out = Out::for_creator(&opts.shared);
    let Some(archive) = archive else {
        // A creator command with no archive named is a usage error at
        // the reference, which prints the help screen with it.
        out.say(&format!("\n{}", help::help_screen()));
        return Exit::BadCommandLine;
    };
    // The creator commands apply the default extension themselves, after
    // `-ag` has rewritten the name; every other command opens an archive
    // that is already there and takes it here (`rar d nosuch` answers
    // `Cannot open nosuch.rar`).
    let archive = match command {
        Command::Add | Command::Move { .. } | Command::Update | Command::Freshen => archive,
        _ => unrar::default_extension(&archive),
    };
    // `-n` and `-x` beside `d` and `rn`.
    let screens = edit::Screens::new(&opts.shared.include, &opts.shared.exclude);
    let exit = match command {
        Command::Add => create::add(&out, &archive, &masks, &opts, create::AddMode::Add),
        Command::Move { files_only } => create::add(
            &out,
            &archive,
            &masks,
            &opts,
            if files_only {
                create::AddMode::MoveFiles
            } else {
                create::AddMode::Move
            },
        ),
        Command::Delete => edit::delete(&out, &archive, &masks, &screens),
        Command::Rename => edit::rename(&out, &archive, &masks, &screens),
        Command::Lock => edit::lock(&out, &archive),
        Command::ChangeParameters => {
            edit::change_parameters(&out, &archive, opts.lock_after, opts.recovery_percent)
        }
        Command::Comment => edit::comment(&out, &archive, opts.comment_file.as_deref()),
        Command::Update | Command::Freshen => create::add(
            &out,
            &archive,
            &masks,
            &opts,
            if command == Command::Update {
                create::AddMode::Update
            } else {
                create::AddMode::Freshen
            },
        ),
        Command::CommentWrite => commands::comment_write(
            &out,
            &archive,
            masks.first().map(String::as_str),
            opts.shared.password.as_deref(),
        ),
        Command::ReconstructVolumes => restore::restore(&out, &archive, &opts),
        Command::AddRecoveryRecord => edit::add_recovery_record(
            &out,
            &archive,
            // `rr` with no number is `rr3` at the reference, measured on
            // a 200 KB archive: bare `rr` and `rr3` grow it by the same
            // 13,340 bytes where `rr5` grows it by 23,988. A `-rr[N]`
            // SWITCH spelled beside the command names the same thing, so
            // it stands in when the command word carries no number.
            command_number.or(opts.recovery_percent).unwrap_or(3),
        ),
        Command::AddRecoveryVolumes => commands::add_recovery_volumes(
            &out,
            &archive,
            // The parser folds the command word's own `[N][p|%]` into
            // this field, so the command and the switch have one home.
            opts.recovery_volumes
                .unwrap_or(args::RecoveryVolumes::Default),
            opts.memory_cap,
        ),
        Command::Sfx { .. } => {
            let (remove, module) = sfx;
            commands::sfx(&out, &archive, remove, module.as_deref())
        }
        Command::Repair => repair::repair(&out, &archive, &masks, extract_path.as_deref(), &opts),
        _ => unimplemented_command(&command_word),
    };
    out.finish_creator();
    exit
}

/// Translates a shared command into the decoder's own spelling.
///
/// The two enums are separate because the creator's has 21 variants and
/// the decoder's has 5; this is the only place they meet, and it is
/// total over exactly the set [`Command::is_read_only`] admits.
fn read_only_as_decoder(command: Command) -> Option<unrar::Command> {
    Some(match command {
        Command::ExtractFlat => unrar::Command::ExtractFlat,
        Command::ExtractFull => unrar::Command::ExtractFull,
        Command::Print => unrar::Command::Print,
        Command::Test => unrar::Command::Test,
        Command::List(style) => unrar::Command::List(style),
        // Unreachable by construction: every other variant answers
        // `false` to `is_read_only`, and this function has one caller,
        // which checks it first. Returning `None` rather than panicking
        // keeps a future variant from turning a mis-edit into a crash in
        // a caller's hands; the decoder answers `None` with its help
        // screen.
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args_of(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    #[test]
    fn the_unbuilt_command_refuses_by_name_rather_than_exiting_zero() {
        // The whole point of the refusal: a drop-in that exits 0 having
        // done something different is worse than one that is honest, so
        // this must never become `Exit::Clean`. The LIST is the claim
        // that matters and it keeps shrinking - `a`, `d`, `u`, `f`, `m`,
        // `rn`, `c`, `ch` and `k` landed with the write half, `rr` with
        // the recovery-record command and `rv` with the `.rev` writer -
        // so neither `rr5` nor `rv1` is here any more, and each is
        // pinned by a row of its own below instead, and so is `r` since
        // its repair driver landed.
        let exit = run(&args_of(&["i=needle", "arc.rar"]));
        assert_eq!(exit, Exit::Aborted, "`i` must not report success");
    }

    /// `rv` is BUILT, so it must reach the creator rather than the
    /// refusal - and over a name that does not exist it answers the way
    /// every other creator command that reads an archive does, with the
    /// C library's own text and exit 10. Measured on rar 7.23:
    /// `rar rv1 -y nosuch.part1.rar` prints `Cannot open
    /// nosuch.part1.rar` and exits 10.
    #[test]
    fn every_recovery_volume_spelling_reaches_the_command_and_not_the_parser() {
        // Back to the reference's own `Cannot open` shape, exit 10, now
        // that the command opens the archive before it decides anything:
        // `rar rv1 -y nosuch.part1.rar` answers exactly that, measured 19
        // Sep 2026. The point of the row is that it is not the parser's
        // usage error (7) and not the decoder's help screen.
        for word in ["rv", "rv1", "rv50p", "rv50%"] {
            let exit = run(&args_of(&[word, "no-such-archive-here.part1.rar"]));
            assert_eq!(
                exit,
                Exit::NothingMatched,
                "`{word}` must reach the creator's command, not the parser's refusal"
            );
        }
    }

    #[test]
    fn the_recovery_record_command_reaches_the_command_word_it_names() {
        // `rr5` parses as the recovery-record command with its number,
        // reaches `edit::add_recovery_record` and answers the
        // reference's own `Cannot open` shape (exit 10) for an archive
        // that is not there. The point of the row is that it is not the
        // parser's 7 and not the decoder's help screen.
        assert_eq!(
            run(&args_of(&["rr5", "no-such-archive-here.rar"])),
            Exit::NothingMatched
        );
    }

    #[test]
    fn a_refused_creator_command_leaves_every_file_on_the_disk_alone() {
        // At the fork this row pinned the reference's `Bad archive` answer
        // (exit 13) for `a`, `u` and `m` over a file that is not an
        // archive, because the creator was built and had to refuse before
        // writing. The writer is stubbed here, so what is checked is the
        // property the stub OWES: a creator command refuses with a
        // non-zero code and touches nothing - neither the named file nor
        // a `<name>.rar` beside it. Exiting 0 having written something
        // different is the failure spec R.2 names, and this is the row
        // that would catch it.
        let dir = std::env::temp_dir().join(format!("rarfast-badarc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("b.txt");
        std::fs::write(
            &source, b"zz
",
        )
        .unwrap();
        for name in ["plain.foo", "plain"] {
            for word in ["a", "u", "m"] {
                let target = dir.join(name);
                std::fs::write(
                    &target,
                    b"keep me
",
                )
                .unwrap();
                let exit = run(&args_of(&[
                    word,
                    "-idq",
                    &target.to_string_lossy(),
                    &source.to_string_lossy(),
                ]));
                assert_ne!(exit, Exit::Clean, "{word} {name}");
                assert_eq!(
                    std::fs::read(&target).unwrap(),
                    b"keep me
",
                    "{word} {name}"
                );
                assert!(!dir.join(format!("{name}.rar")).exists(), "{word} {name}");
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unbuilt_command_is_not_reported_as_a_usage_error() {
        // `Exit::BadCommandLine` would send a caller who spelled a real
        // command correctly looking for a typo they did not make.
        assert_ne!(
            run(&args_of(&["i=needle", "arc.rar"])),
            Exit::BadCommandLine
        );
    }

    #[test]
    fn repair_reaches_its_command_and_answers_a_missing_archive_like_k() {
        // `rar r nosuch.rar`, measured 30 Sep 2026: `Cannot open
        // nosuch.rar` on stderr, `Done` on stdout, exit 10.
        assert_eq!(
            run(&args_of(&["r", "no-such-archive-here.rar"])),
            Exit::NothingMatched
        );
    }

    #[test]
    fn every_read_only_command_translates_to_the_decoders_own() {
        for word in [
            "e", "x", "p", "t", "l", "lb", "lt", "lta", "v", "vb", "vt", "vta",
        ] {
            let (cmd, _, _) = args::command(word).expect("in the inventory");
            assert!(
                read_only_as_decoder(cmd).is_some(),
                "`{word}` is read-only and must reach the decoder"
            );
        }
    }

    #[test]
    fn our_own_name_accepts_a_creator_switch_on_a_shared_command() {
        // The conformance switch probe runs `<candidate> l -<switch>
        // arc.rar` by the path it was given, so under our own name a
        // creator-only spelling on a shared command must not come back
        // as a usage error. `-m0` is the decoder's unknown option and
        // the creator's store level.
        let exit = run_shared_command(&args_of(&["l", "-m0", "no-such-archive.rar"]));
        assert_ne!(exit, Exit::BadCommandLine);
    }

    #[test]
    fn our_own_name_keeps_the_decoders_reading_of_a_shared_spelling() {
        // `-` is an unknown option to both tools, and the message the
        // `stop-switch-scan` row of each leg compares is the decoder's.
        assert_eq!(
            run_shared_command(&args_of(&["l", "-", "arc.rar"])),
            Exit::BadCommandLine
        );
    }

    #[test]
    fn an_unknown_command_shows_the_help_screen_and_exits_seven() {
        // The `bad-command` row.
        assert_eq!(run(&args_of(&["qq", "arc.rar"])), Exit::BadCommandLine);
    }

    #[test]
    fn no_arguments_shows_the_help_screen_and_exits_zero() {
        // The `no-arguments` row.
        assert_eq!(run(&args_of(&[])), Exit::Clean);
    }
}
