//! A copy of the `rarfast` binary that a test can run at once, on Linux as
//! everywhere else.
//!
//! **The fault this closes (Linux, `ETXTBSY`, "Text file busy").** A test
//! that copies the binary to a new name (`unrar`, which is how the binary
//! picks that dialect) and then runs the copy can be refused by the kernel:
//! `execve` of a file that some process still holds open for WRITING fails
//! with `ETXTBSY`. The test's own handle is closed by then, but the test
//! binary runs its tests on several threads, and any of them that forks a
//! child (every `Command` does) while the copy's write handle is open
//! duplicates that handle into the child, which keeps it until the child's
//! own `execve` closes it. On a Zen 4 rental (16 threads, Linux 6.8)
//! `tests/idq_closes_its_stderr_line.rs` failed this way in 17 of 30 runs
//! (1 Oct 2026). macOS has no `ETXTBSY`, which is why its runs never showed
//! it. The class was first named on 27 Sep 2026.
//!
//! **The two halves.** [`copy_executable`] writes the copy under a
//! temporary name in the same directory, syncs and CLOSES it, and only then
//! renames it into place, so no test ever runs a file this process is
//! still writing. That cannot stop a sibling thread's fork from holding a
//! duplicate of the write handle for the moment before its child's own
//! `execve`, so [`output_of`] and [`status_of`] also retry a spawn the
//! kernel calls busy, briefly and a bounded number of times, and report
//! any other error at once.

#![allow(dead_code)]

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output};
use std::time::Duration;

/// How many times a busy spawn is retried, and how long it waits between.
const BUSY_TRIES: u32 = 200;
const BUSY_WAIT: Duration = Duration::from_millis(5);

/// The binary under test.
pub fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// Where a copy of the binary named for `tool` (`unrar`, `rar`) goes in
/// `dir`: the tool's name with the system's executable suffix, which is
/// the name the binary reads its dialect from on every system.
pub fn tool_named(dir: &Path, tool: &str) -> PathBuf {
    dir.join(format!("{tool}{}", std::env::consts::EXE_SUFFIX))
}

/// Copies `from` (an executable) to `to`: under a temporary name in `to`'s
/// directory, with `from`'s permissions, synced and closed, then renamed.
pub fn copy_executable(from: &Path, to: &Path) {
    let name = to.file_name().expect("a file name").to_string_lossy();
    let part = to.with_file_name(format!(".{name}.{}.part", std::process::id()));
    {
        let mut source =
            std::fs::File::open(from).unwrap_or_else(|e| panic!("{}: {e}", from.display()));
        let mut copy =
            std::fs::File::create(&part).unwrap_or_else(|e| panic!("{}: {e}", part.display()));
        io::copy(&mut source, &mut copy).unwrap_or_else(|e| panic!("{}: {e}", part.display()));
        let mode = source
            .metadata()
            .expect("the binary's metadata")
            .permissions();
        copy.set_permissions(mode).expect("the copy's permissions");
        copy.sync_all().expect("the copy synced");
    }
    std::fs::rename(&part, to)
        .unwrap_or_else(|e| panic!("{} to {}: {e}", part.display(), to.display()));
}

/// `command`'s output, the spawn retried while the kernel calls the
/// executable busy.
pub fn output_of(command: &mut Command) -> io::Result<Output> {
    retry_busy(|| command.output())
}

/// `command`'s exit status, the spawn retried as [`output_of`]'s is.
pub fn status_of(command: &mut Command) -> io::Result<ExitStatus> {
    retry_busy(|| command.status())
}

fn retry_busy<T>(mut spawn: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    let mut tries = 0;
    loop {
        match spawn() {
            Err(e) if e.kind() == io::ErrorKind::ExecutableFileBusy && tries < BUSY_TRIES => {
                tries += 1;
                std::thread::sleep(BUSY_WAIT);
            }
            other => return other,
        }
    }
}
