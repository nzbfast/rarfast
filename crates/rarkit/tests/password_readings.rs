//! The two genuine readings of a password that holds a character outside
//! the basic plane, read from GENUINE archives.
//!
//! RAR 5 (spec K 3.7.1): a password longer than 127 is cut at 127
//! characters by the reference programs for Linux and macOS and at 127
//! UTF-16 units by the ones for Windows. A reader judges the member's
//! check record under one cut and, only for a password the two cut
//! differently, under the other, before any byte is deciphered.
//!
//! Every test here runs the sequential driver at its default width and the
//! pool at a width of 2, the narrowest hosted runner's, and holds one
//! archive of under 1 KiB and its members in memory: no test needs more
//! than a few MiB whatever the width.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use rarkit::{
    extract, extract_parallel, Disposition, ErrorKind, MemberInfo, MemberOutcome, ParallelSink,
    Password, RangeSource, ReadOptions, Sink,
};

/// The pool width every test here runs the parallel driver at.
const POOL: usize = 2;

fn vector(path: &str) -> Vec<u8> {
    let path = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../specs")).join(path);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// What one member's `close` was told, and the bytes its writer was given.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Closed {
    name: Vec<u8>,
    written: Vec<u8>,
    outcome: MemberOutcome,
}

#[derive(Default)]
struct Keep(Vec<Closed>);

impl Sink for Keep {
    type Out = Vec<u8>;

    fn open(&mut self, _member: &MemberInfo<'_>) -> rarkit::Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> rarkit::Result<()> {
        self.0.push(Closed {
            name: member.name.to_vec(),
            written: out.unwrap_or_default(),
            outcome: *outcome,
        });
        Ok(())
    }
}

/// A writer the pool can hand to a worker, whose bytes outlive it.
struct Shared(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Shared {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct KeepParallel {
    /// What every writer ever opened was given: a member that is refused
    /// has no `close`, and its writer's bytes must still be seen.
    opened: Mutex<Vec<Arc<Mutex<Vec<u8>>>>>,
    closed: Mutex<Vec<Closed>>,
}

impl ParallelSink for KeepParallel {
    type Out = Shared;

    fn open(&self, _member: &MemberInfo<'_>) -> rarkit::Result<Disposition<Shared>> {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        self.opened.lock().unwrap().push(bytes.clone());
        Ok(Disposition::Write(Shared(bytes)))
    }

    fn close(
        &self,
        member: &MemberInfo<'_>,
        out: Option<Shared>,
        outcome: &MemberOutcome,
    ) -> rarkit::Result<()> {
        self.closed.lock().unwrap().push(Closed {
            name: member.name.to_vec(),
            written: out.map(|w| w.0.lock().unwrap().clone()).unwrap_or_default(),
            outcome: *outcome,
        });
        Ok(())
    }
}

/// What an extraction came to: the members closed, every byte any writer
/// was given, and the operation's own error kind as text (`ErrorKind` has
/// no `PartialEq`).
#[derive(Debug, PartialEq, Eq)]
struct Told {
    closed: Vec<Closed>,
    bytes_given: usize,
    error: Option<String>,
}

fn kind(result: &rarkit::Result<rarkit::ExtractReport>) -> Option<String> {
    result.as_ref().err().map(|e| format!("{:?}", e.kind()))
}

/// The archive through BOTH drivers, which must tell the sink the same.
fn told(archive: &[u8], password: &str) -> Told {
    let opts = ReadOptions::default().with_password(Some(Password::from(password)));
    let source = || vec![Arc::new(archive.to_vec()) as Arc<dyn RangeSource>];

    let mut sink = Keep::default();
    let result = extract(source(), &opts, &mut sink, &mut ());
    let sequential = Told {
        bytes_given: sink.0.iter().map(|c| c.written.len()).sum(),
        closed: sink.0,
        error: kind(&result),
    };

    let sink = KeepParallel::default();
    let result = extract_parallel(source(), &opts, &sink, POOL);
    let mut closed = sink.closed.into_inner().unwrap();
    closed.sort_by(|a, b| a.name.cmp(&b.name));
    let pooled = Told {
        bytes_given: sink
            .opened
            .into_inner()
            .unwrap()
            .iter()
            .map(|bytes| bytes.lock().unwrap().len())
            .sum(),
        closed,
        error: kind(&result),
    };
    let mut sequential = sequential;
    sequential.closed.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(sequential, pooled, "the two drivers disagree");
    sequential
}

/// The password `Rar.exe` 7.23 was given for the capture's `t.rar`: 125
/// `x`, U+1F511, `y`, `z` (128 characters, 129 UTF-16 units).
fn long_password() -> String {
    format!("{}\u{1f511}yz", "x".repeat(125))
}

const WINDOWS_LONG: &str = "vectors-K/windows-06oct/long-password/t.rar";

/// The same command by the reference `rar` 7.23 for Linux
/// (`tests/password_readings/README.md`).
fn linux_long() -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/password_readings/linux-long-password.rar"
    );
    std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Spec K 3.7.1, the capture's own archive: genuine `Rar.exe` 7.23 for
/// Windows kept 125 `x` and the character (127 units) and dropped `y` and
/// `z`. Given the password as it was typed, a reader's first cut (127
/// characters, through `y`) does not fit the check record and its second
/// (127 units) does. The reference for Linux refuses the whole password
/// here (`long-password/linux-unrar.json`); the one for Windows opens it.
#[test]
fn rar5_windows_made_long_password_opens_under_the_unit_cut() {
    let archive = vector(WINDOWS_LONG);
    let whole = long_password();
    let cut_after_y: String = whole.chars().take(127).collect();
    let cut_after_key: String = whole.chars().take(126).collect();
    for password in [&whole, &cut_after_y, &cut_after_key] {
        let told = told(&archive, password);
        assert_eq!(told.error, None, "{} characters", password.chars().count());
        assert_eq!(told.closed.len(), 1);
        let member = &told.closed[0];
        assert_eq!(member.name, b"hello.txt");
        assert_eq!(member.outcome.checksum_ok, Some(true));
        assert!(!member.outcome.password_refused);
        assert_eq!(member.written.len() as u64, member.outcome.bytes);
        assert!(!member.written.is_empty());
    }
}

/// The Linux-made twin: genuine `rar` 7.23 for Linux kept 127 characters,
/// through `y`. The password as typed and the one cut after `y` open it
/// under the reader's first cut; the one cut after the character, which
/// is all the Windows writer would have kept, is 127 units, has one cut
/// and is refused, as the reference `unrar` for Linux refuses it.
#[test]
fn rar5_linux_made_long_password_opens_under_the_character_cut() {
    let archive = linux_long();
    let whole = long_password();
    let cut_after_y: String = whole.chars().take(127).collect();
    let cut_after_key: String = whole.chars().take(126).collect();
    for password in [&whole, &cut_after_y] {
        let told = told(&archive, password);
        assert_eq!(told.error, None, "{} characters", password.chars().count());
        assert_eq!(told.closed.len(), 1);
        assert_eq!(told.closed[0].name, b"hello.txt");
        assert_eq!(told.closed[0].written, b"hello\n");
        assert_eq!(told.closed[0].outcome.checksum_ok, Some(true));
    }
    let told = told(&archive, &cut_after_key);
    assert_eq!(
        told.error.as_deref(),
        Some(format!("{:?}", ErrorKind::WrongPassword).as_str())
    );
    assert_eq!(told.bytes_given, 0);
}

/// A password that is not it is refused exactly as before the second cut
/// existed: `WrongPassword` from the check record, the operation ended,
/// and not one byte given to any writer. That holds for a password with
/// one cut and for one with two (which costs one derivation more, counted
/// in `crypto::tests`).
#[test]
fn rar5_wrong_password_is_refused_as_before_whatever_its_cuts() {
    let archive = vector(WINDOWS_LONG);
    let whole = long_password();
    // Cut before the character: the capture's own refused arm.
    let before_key: String = whole.chars().take(125).collect();
    // Two cuts, neither the archive's.
    let other_long = format!("{}\u{1f511}yz", "w".repeat(125));
    // 126 units and then a character outside the basic plane: the unit cut
    // would fall inside the pair, which 3.7.1 leaves not established, so
    // the password keeps its one reading.
    let straddling = format!("{}\u{1f511}yz", "x".repeat(126));
    // Of ordinary length and more than 127 bytes of UTF-8.
    let two_byte = "\u{e9}".repeat(100);
    for password in ["Secret", &before_key, &other_long, &straddling, &two_byte] {
        for archive in [&archive, &linux_long()] {
            let told = told(archive, password);
            assert_eq!(
                told.error.as_deref(),
                Some(format!("{:?}", ErrorKind::WrongPassword).as_str()),
                "{} characters",
                password.chars().count()
            );
            assert_eq!(told.bytes_given, 0);
            assert!(told
                .closed
                .iter()
                .all(|member| member.outcome.checksum_ok != Some(true)));
        }
    }
}
