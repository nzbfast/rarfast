//! `rarfast`: a drop-in for the reference RAR command-line tools.
//!
//! Invoked as `unrar` - by `argv[0]`, so a symlink or a copy of this
//! binary named `unrar` is enough - it behaves as unrar: every command
//! and every switch in the pinned reference's own help screen, spelled
//! the same, with the same listing formats, the same progress lines and
//! the same exit code for the same input. Invoked as `rar` or `winrar`,
//! or with a creator command, it behaves as rar: the whole captured
//! `rar` switch inventory parses, the help screen is the reference's,
//! and the commands the two tools share answer with the decoder's own
//! bytes. The creator's WRITE half is not built - a command that
//! modifies an archive refuses by name with a non-zero code rather than
//! exiting 0 having done something different.
//!
//! Called by its own name, the command letter decides: the two reference
//! command sets overlap only on `e l p t v x`, where both tools do the
//! same thing.
//!
//! The claim that this is a drop-in is checked rather than asserted.
//! The conformance run, with the reference `unrar` and `rar` beside
//! `rarfast`, runs 140 rows on an Apple Silicon Mac
//! against tables captured from the reference itself, and probes every
//! switch in its captured inventory. Read `dialect/unrar/mod.rs` before
//! changing any layout constant: several of them are not what the manual
//! would lead you to write.
//!
//! THE ENGINE UNDERNEATH IS `rarkit`, not the predecessor. What that costs
//! today - which rows pass, which wait on a codec or on a field rarkit's
//! `MemberInfo` does not carry yet, and which creator commands are stubs -
//! is in this crate's README, row by row, with the census that says which
//! of this code is ours from birth.

// What an archive is read from, and whether it is in memory already:
// the two facts the rotational source rule turns on.
mod device_class;
mod dialect;
mod residency;
// Everything that names a rarkit type. The dialects are written against
// their own `Member` view and reach the engine only through here.
mod engine;
// The environment's tuning words, read only under `reader-knobs` and
// `writer-knobs`: a shipped `rarfast` reads none.
mod knob;
// The path rule and the no-follow opener.
mod safepath;
// A big output past the OS cache, for `x` and `a` alike (the extract
// side's module, lifted for the create side's archive output).
mod unbuffered;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod writeback;
// How wide this process runs.
mod workers;
// A cold archive read in order, far ahead, on a thread of the command's.
mod window;
// The allocator policy: glibc's trim threshold under a stated `-mm` budget,
// its mmap threshold for a create with none.
mod alloc_policy;
// A create kept to one NUMA node's CPUs, behind a knob that is off as
// shipped (`RARFAST_ONE_NODE`); Linux only.
mod one_node;
// Acceptance test 7 of API 8.4.4: the command line reaches the read
// side's width dial. Tests only; it builds a fixture of tens of
// megabytes and reads `rarkit::probe`, neither of which a shipped
// binary carries.
#[cfg(test)]
mod width_dial;

use std::ffi::OsString;

use dialect::unrar::{is_creator_command, Exit};
use dialect::Dialect;

fn main() {
    // FIRST, while the process has one thread: the file-creation mask, read
    // by a set-and-restore pair that is sound only before any thread exists
    // (`dialect::unrar::read_umask_at_start`). Nothing goes above this.
    #[cfg(unix)]
    dialect::unrar::read_umask_at_start();
    let mut argv = std::env::args_os();
    let argv0 = argv
        .next()
        .unwrap_or_else(|| OsString::from("rarfast"))
        .to_string_lossy()
        .into_owned();
    let rest: Vec<OsString> = argv.collect();
    // `--version` as the FIRST argument, under every name this binary is
    // called by. Neither reference tool has a command or a switch of that
    // spelling (both answered `Unknown option: -version`, exit 7, here
    // until 0.9.0), so no accepted line changes meaning; `-v` and `-V`
    // stay with the dialects.
    if rest.first().is_some_and(|arg| arg == "--version") {
        println!("{}", version_line());
        std::process::exit(0);
    }
    keep_the_write_error_path();
    let code = dispatch(&argv0, &rest).code();
    #[cfg(feature = "pair-census")]
    for (name, count) in rarkit::pair_census() {
        eprintln!("pair-census {name} {count}");
    }
    #[cfg(all(feature = "lane-census", feature = "parallel"))]
    for (name, count) in rarkit::lane_census() {
        eprintln!("lane-census {name} {count}");
    }
    std::process::exit(code);
}

/// Ignore `SIGXFSZ`, so that a write past the file size limit (`ulimit
/// -f`) fails with `EFBIG` and the command's own write error path runs:
/// the member is named, what was written of it is removed, and the exit
/// says a write failed.
///
/// With the signal's default disposition the process was killed inside
/// the write or the length reservation: shell status 153, nothing said,
/// and partial files of members never verified left on disk
/// (SWEEP3-08OCT-19). Measured against unrar 7.23 on 9 Oct 2026 (`x -idq
/// -o+` under `ulimit -f 2000`, the second member past the limit): it
/// says `Write error in the file <name>`, asks its Retry or Abort
/// question, and leaves the first member alone; rarfast now says the
/// same first line with the system's reason, asks nothing, leaves the
/// first member alone and exits 5.
#[cfg(unix)]
#[allow(unsafe_code)]
fn keep_the_write_error_path() {
    // SAFETY: `signal` with `SIG_IGN` installs no handler and takes no
    // pointer of ours. It is called once, on the main thread, before the
    // command starts any worker. A refusal leaves the default
    // disposition, which is the behaviour without this call.
    let _ = unsafe { libc::signal(libc::SIGXFSZ, libc::SIG_IGN) };
}

#[cfg(not(unix))]
fn keep_the_write_error_path() {}

/// The one line `--version` prints: `rarfast 0.9.0 (a1b2c3d4e5f6, aarch64
/// macos)`. The commit is whatever `RARFAST_BUILD_COMMIT` held when this
/// crate was COMPILED (the release recipe sets it to the full sha), cut
/// to its first 12 characters, and `unknown` in a build that set nothing.
fn version_line() -> String {
    let commit = match option_env!("RARFAST_BUILD_COMMIT") {
        Some(sha) if !sha.is_empty() => sha.get(..12).unwrap_or(sha),
        _ => "unknown",
    };
    format!(
        "rarfast {} ({commit}, {} {})",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::ARCH,
        std::env::consts::OS
    )
}

/// Picks the dialect and runs it.
fn dispatch(argv0: &str, argv: &[OsString]) -> Exit {
    let dialect = dialect::from_argv0(argv0);
    let first = argv
        .first()
        .map(|arg| arg.to_string_lossy().into_owned())
        .unwrap_or_default();

    match dialect {
        Dialect::Rar => dialect::rar::run(argv),
        Dialect::Unrar => dialect::unrar::run(argv),
        Dialect::Auto => {
            // Called by its own name. A creator command goes to the
            // creator; anything else, the empty command line included,
            // goes to the decoder - but through the shared-command path,
            // which falls back to the creator's parser for a switch only
            // `rar` has. Under our own name we accept the UNION of the
            // two inventories, because both conformance legs probe this
            // binary by the path they were given.
            if !first.starts_with('-') && is_creator_command(&first) {
                dialect::rar::run(argv)
            } else {
                dialect::rar::run_shared_command(argv)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// THE MASK IS READ AT MAIN'S FIRST LINE (`dialect::unrar::read_umask_at_start`):
    /// the set-and-restore pair is sound only while the process has ONE
    /// thread, so nothing may come before it in `main`, no argument parse,
    /// no pool, no library call that could start one. This reads `main`'s
    /// own text and fails if any statement moves above the read.
    #[test]
    fn main_reads_the_mask_before_anything_else() {
        let text = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
        let body = text
            .split_once("\nfn main() {\n")
            .expect("`main` is in main.rs")
            .1;
        let first: Vec<&str> = body
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with("//"))
            .take(2)
            .collect();
        assert_eq!(
            first,
            ["#[cfg(unix)]", "dialect::unrar::read_umask_at_start();"],
            "the mask is read by the entry function's first statement, before any thread can start"
        );
    }

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    #[test]
    fn a_creator_command_under_our_own_name_reaches_the_creator() {
        // The creator's own answer for a mask that names nothing:
        // `Cannot open f` on stderr and exit 10, which is exactly what
        // the reference answers and what said the routing had put the
        // line in the right dialect. It was the fork's discriminator
        // too; the stubbed crate in between answered `Aborted` instead,
        // and now that the write half is built it is back.
        let exit = dispatch("rarfast", &args(&["a", "new.rar", "f"]));
        assert_eq!(exit, Exit::NothingMatched);
    }

    #[test]
    fn every_spelling_of_the_sfx_command_reaches_the_creator_under_our_own_name() {
        // `s` has three spellings and only the bare one was routed here
        // until 17 Sep 2026, so `rarfast s- arc.rar` and `rarfast
        // smymod.sfx arc.rar` answered the DECODER's help screen with
        // exit 7 - which is what made the module-name forms read as a
        // parse failure when the creator's parser had understood them
        // all along. Under the `rar` name they were always right.
        //
        // The claim is about ROUTING, so what is pinned is that none of
        // the four reaches the DECODER's usage error or its help screen.
        // The creator's own answers differ between them and that is
        // proper: `s-` opens the archive and reports the open failure
        // (10), while `s` refuses by name before touching anything (2),
        // because grafting a module is a thing this crate cannot do at
        // all. Pinning one code for all four would have to pick one of
        // those two and would then be wrong about the other.
        for word in ["s", "s-", "smymod.sfx", "sdir/mymod.sfx"] {
            let exit = dispatch("rarfast", &args(&[word, "-y", "no-such-archive.rar"]));
            assert_ne!(
                exit,
                Exit::BadCommandLine,
                "`rarfast {word}` answered the decoder's usage error"
            );
            assert_ne!(
                exit,
                Exit::Clean,
                "`rarfast {word}` reported a success it cannot have earned"
            );
        }
    }

    #[test]
    fn a_shared_command_letter_reaches_the_decoder_under_either_name() {
        // `l` belongs to both reference tools and means the same thing in
        // each, so the dialect choice is not observable here. What IS
        // observable is that it does not reach the creator stub.
        for name in ["rarfast", "unrar"] {
            let exit = dispatch(name, &args(&["l", "no-such-archive.rar"]));
            assert_ne!(
                exit,
                Exit::BadCommandLine,
                "{name} sent `l` to the wrong dialect"
            );
        }
    }

    #[test]
    fn the_creator_name_answers_a_shared_command_as_the_decoder_does() {
        // Under the `rar` name the creator dialect owns the line, and a
        // command the two tools share still reaches the decoder: `rar l`
        // and `unrar l` emit the same bytes for the same archive, so the
        // dialect choice is not observable here either.
        assert_eq!(
            dispatch("rar", &args(&["l", "no-such-archive.rar"])),
            dispatch("unrar", &args(&["l", "no-such-archive.rar"]))
        );
    }
}
