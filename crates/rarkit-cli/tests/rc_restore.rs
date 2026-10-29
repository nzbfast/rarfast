//! `rc`: the missing volumes of a RAR 5 set are written again from its
//! recovery volumes (SPEC-CLI section 13).
//!
//! THE RULES are 13.3's R1 to R11, each over what 13.1 measured of the
//! reference (C1 to C16). A test here is named for the rule it holds and
//! says the row in its own words. Where `rarfast` differs from the
//! reference by choice (R4's last part, R5, R8, R9, R11) the test holds
//! the chosen difference, not the reference.
//!
//! Every set is written by `rarfast` itself: 100,000 drawn bytes stored
//! in volumes of 16,384 bytes, which is seven volumes, and `rv3` beside
//! them. The reference `rar` is called, never opened, for one set only:
//! R11's, with encrypted headers, which `rarfast rv` does not take; that
//! test says it is not measured where no `rar` is on PATH. The one older
//! archive is a kept genuine RAR 4 file of this crate's
//! (`listing-names/r4-two.rar`).
//!
//! Width and memory: every `rc` here is run with `-mt2`, so two threads
//! are enough; a set is 115 KB on disk and the restore's working memory
//! is under 1 MiB.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// Deletes the directory one test works in when the test ends, passed
/// or failed.
struct DirWatch(PathBuf);

impl Drop for DirWatch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn work(tag: &str) -> (PathBuf, DirWatch) {
    let dir = std::env::temp_dir().join(format!("rarfast-rc-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    (dir.clone(), DirWatch(dir))
}

/// Bytes no stored volume can shrink, the same every run for one seed.
fn noise(seed: u64, len: usize) -> Vec<u8> {
    // A congruential walk of 64 bits from a start the seed picks; each
    // byte is taken from the walk's upper half, where it does not repeat
    // within any length used here.
    let mut walk = seed.wrapping_add(1).wrapping_mul(0x0123_4567_89AB_CDEF);
    let mut bytes = Vec::with_capacity(len);
    while bytes.len() < len {
        walk = walk.wrapping_mul(6_700_417).wrapping_add(104_729);
        bytes.push((walk >> 37) as u8);
    }
    bytes
}

const DATA: usize = 7;
const RECOVERY: usize = 3;

fn part(n: usize) -> String {
    format!("set.part{n}.rar")
}

fn rev(n: usize) -> String {
    format!("set.part{n}.rev")
}

/// A set in a directory of its own, and the bytes every file of it was
/// written with.
struct Set {
    dir: PathBuf,
    _watch: DirWatch,
    /// The data volumes as written, by number from 1.
    data: Vec<Vec<u8>>,
}

impl Set {
    fn new(tag: &str) -> Set {
        Set::drawn(tag, 1, &[])
    }

    /// Seven stored volumes and three recovery volumes over bytes drawn
    /// from `seed`, with `more` given to the writer.
    fn drawn(tag: &str, seed: u64, more: &[&str]) -> Set {
        let (dir, watch) = work(tag);
        write_set(&dir, seed, more);
        let data = (1..=DATA)
            .map(|n| std::fs::read(dir.join(part(n))).unwrap())
            .collect();
        Set {
            dir,
            _watch: watch,
            data,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn lose(&self, n: usize) {
        std::fs::remove_file(self.path(&part(n))).unwrap();
    }

    /// Changes one byte in the middle of volume `n`.
    fn spoil(&self, name: &str) {
        let mut bytes = std::fs::read(self.path(name)).unwrap();
        let at = bytes.len() / 2;
        bytes[at] ^= 0x55;
        std::fs::write(self.path(name), bytes).unwrap();
    }

    /// Whether volume `n` stands at its own name with the bytes it was
    /// written with.
    fn whole(&self, n: usize) -> bool {
        std::fs::read(self.path(&part(n))).is_ok_and(|bytes| bytes == self.data[n - 1])
    }

    fn all_whole(&self) -> bool {
        (1..=DATA).all(|n| self.whole(n))
    }

    /// Every name in the set's directory, sorted.
    fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    fn rc(&self, args: &[&str]) -> Ran {
        rc_in(&self.dir, args, None)
    }

    fn rc_answering(&self, args: &[&str], answers: &str) -> Ran {
        rc_in(&self.dir, args, Some(answers))
    }
}

fn write_set(dir: &Path, seed: u64, more: &[&str]) {
    std::fs::write(dir.join("data"), noise(seed, 100_000)).unwrap();
    let made = Command::new(rarfast())
        .current_dir(dir)
        .args(["a", "-idq", "-m0", "-ep", "-v16384b"])
        .args(more)
        .args(["set.rar", "data"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
    std::fs::remove_file(dir.join("data")).unwrap();
    let recovery = Command::new(rarfast())
        .current_dir(dir)
        .args([&format!("rv{RECOVERY}"), "set.part1.rar"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(recovery.status.success(), "{recovery:?}");
    let count = std::fs::read_dir(dir).unwrap().count();
    assert_eq!(count, DATA + RECOVERY, "the set's shape");
}

/// What one run left: its exit and its two streams as text, the
/// counter's backspaces and percents taken out.
struct Ran {
    exit: i32,
    out: String,
    err: String,
}

impl Ran {
    /// The lines of standard output that say anything.
    fn lines(&self) -> Vec<&str> {
        self.out
            .lines()
            .map(str::trim_end)
            .filter(|line| !line.is_empty())
            .collect()
    }

    fn says(&self, line: &str) -> bool {
        self.lines().contains(&line)
    }
}

fn plain(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut kept = String::new();
    for piece in text.split('\u{8}') {
        // What follows a backspace is a counter's redraw: `  0%`, `100%`.
        let piece = if kept.is_empty() {
            piece
        } else {
            piece.trim_start_matches(|c: char| c == ' ' || c == '%' || c.is_ascii_digit())
        };
        kept.push_str(piece);
    }
    kept
}

/// `rarfast rc -mt2 <args>` in `dir`. Standard input is at its end
/// unless `answers` gives it lines.
fn rc_in(dir: &Path, args: &[&str], answers: Option<&str>) -> Ran {
    let mut command = Command::new(rarfast());
    command
        .current_dir(dir)
        .args(["rc", "-mt2"])
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let done: Output = match answers {
        None => command.stdin(Stdio::null()).output().unwrap(),
        Some(text) => {
            use std::io::Write as _;
            let mut child = command.stdin(Stdio::piped()).spawn().unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(text.as_bytes())
                .unwrap();
            child.wait_with_output().unwrap()
        }
    };
    Ran {
        exit: done.status.code().unwrap_or(-1),
        out: plain(&done.stdout),
        err: plain(&done.stderr),
    }
}

// R1 (C1, C2): the name.

#[test]
fn r1_any_volume_of_the_set_that_is_there_may_be_named() {
    for (tag, named) in [
        ("first", "set.part1.rar"),
        ("middle", "set.part4.rar"),
        ("last", "set.part7.rar"),
        ("recovery", "set.part1.rev"),
        ("recovery-last", "set.part3.rev"),
        ("no-extension", "set.part1"),
    ] {
        let set = Set::new(&format!("r1-{tag}"));
        set.lose(3);
        let ran = set.rc(&[named]);
        assert_eq!(ran.exit, 0, "{tag}: {} {}", ran.out, ran.err);
        assert!(set.all_whole(), "{tag}");
        assert!(ran.says("Creating set.part3.rar"), "{tag}: {}", ran.out);
    }
}

#[test]
fn r1_the_first_volume_lost_is_restored_from_another_name() {
    for (tag, named) in [("second", "set.part2.rar"), ("recovery", "set.part2.rev")] {
        let set = Set::new(&format!("r1-first-lost-{tag}"));
        set.lose(1);
        let ran = set.rc(&[named]);
        assert_eq!(ran.exit, 0, "{tag}: {} {}", ran.out, ran.err);
        assert!(set.all_whole(), "{tag}");
    }
}

#[test]
fn r1_the_name_of_a_missing_volume_is_refused_with_exit_10() {
    let set = Set::new("r1-missing-named");
    set.lose(3);
    let before = set.names();
    let ran = set.rc(&["set.part3.rar"]);
    assert_eq!(ran.exit, 10, "{} {}", ran.out, ran.err);
    assert!(ran.err.contains("Cannot open set.part3.rar"), "{}", ran.err);
    assert_eq!(set.names(), before);
}

#[test]
fn r1_a_second_name_is_not_used() {
    let set = Set::new("r1-two-names");
    set.lose(3);
    std::fs::create_dir(set.path("elsewhere")).unwrap();
    let ran = set.rc(&["set.part1.rar", "elsewhere"]);
    assert_eq!(ran.exit, 0, "{} {}", ran.out, ran.err);
    assert!(set.all_whole());
    assert_eq!(std::fs::read_dir(set.path("elsewhere")).unwrap().count(), 0);
}

// R2 (C3): the set is found by name, in the named file's directory.

#[test]
fn r2_recovery_volumes_in_another_directory_are_not_found() {
    let set = Set::new("r2-elsewhere");
    std::fs::create_dir(set.path("away")).unwrap();
    for n in 1..=RECOVERY {
        std::fs::rename(set.path(&rev(n)), set.path("away").join(rev(n))).unwrap();
    }
    set.lose(3);
    let ran = set.rc(&["set.part1.rar"]);
    assert!(ran.says("0 recovery volumes found"), "{}", ran.out);
    assert!(!set.path(&part(3)).exists());
    // R8: a volume is known to be missing (the numbers have a gap).
    assert_eq!(ran.exit, 3, "{} {}", ran.out, ran.err);
}

#[test]
fn r2_the_number_in_a_recovery_volume_s_name_plays_no_part() {
    let set = Set::new("r2-rev-numbers");
    std::fs::rename(set.path(&rev(1)), set.path("set.part8.rev")).unwrap();
    std::fs::rename(set.path(&rev(3)), set.path("set.part9.rev")).unwrap();
    set.lose(2);
    set.lose(5);
    set.lose(7);
    let ran = set.rc(&["set.part1.rar"]);
    assert_eq!(ran.exit, 0, "{} {}", ran.out, ran.err);
    assert!(set.all_whole());
}

#[test]
fn r2_a_file_named_like_a_recovery_volume_that_is_none_is_passed_over() {
    let set = Set::new("r2-stray");
    std::fs::write(set.path("set.part4.rev"), noise(9, 3_000)).unwrap();
    set.lose(6);
    let ran = set.rc(&["set.part1.rar"]);
    assert_eq!(ran.exit, 0, "{} {}", ran.out, ran.err);
    assert!(ran.says("3 recovery volumes found"), "{}", ran.out);
    assert!(!ran.out.contains("set.part4.rev"), "{}", ran.out);
    assert!(set.all_whole());
}

#[test]
fn r2_a_set_named_with_a_path_is_printed_and_written_with_that_path() {
    let set = Set::new("r2-path");
    set.lose(3);
    let above = set.dir.parent().unwrap();
    let folder = set.dir.file_name().unwrap().to_string_lossy().into_owned();
    let ran = rc_in(above, &[&format!("{folder}/set.part1.rar")], None);
    assert_eq!(ran.exit, 0, "{} {}", ran.out, ran.err);
    assert!(
        ran.says(&format!("Creating {folder}/set.part3.rar")),
        "{}",
        ran.out
    );
    assert!(set.all_whole());
}

#[test]
fn r2_a_set_renamed_whole_to_two_digits_is_restored_under_those_names() {
    let set = Set::new("r2-two-digits");
    for n in 1..=DATA {
        std::fs::rename(set.path(&part(n)), set.path(&format!("set.part0{n}.rar"))).unwrap();
    }
    for n in 1..=RECOVERY {
        std::fs::rename(set.path(&rev(n)), set.path(&format!("set.part0{n}.rev"))).unwrap();
    }
    std::fs::remove_file(set.path("set.part03.rar")).unwrap();
    let ran = set.rc(&["set.part01.rar"]);
    assert_eq!(ran.exit, 0, "{} {}", ran.out, ran.err);
    assert!(ran.says("Creating set.part03.rar"), "{}", ran.out);
    assert_eq!(
        std::fs::read(set.path("set.part03.rar")).unwrap(),
        set.data[2]
    );
}

// R3, R6, R7 (C4): what is restored, what is printed, the exit.

#[test]
fn r6_the_lines_of_a_restore_are_the_reference_s_in_its_order() {
    let set = Set::new("r6-lines");
    set.lose(3);
    let ran = set.rc(&["set.part1.rar"]);
    assert_eq!(ran.exit, 0, "{} {}", ran.out, ran.err);
    assert_eq!(
        ran.lines(),
        [
            "3 recovery volumes found",
            "Calculating checksums of all volumes.",
            "set.part1.rar",
            "set.part2.rar",
            "set.part4.rar",
            "set.part5.rar",
            "set.part6.rar",
            "set.part7.rar",
            "set.part1.rev",
            "set.part2.rev",
            "set.part3.rev",
            "1 volumes missing",
            "Reconstructing...",
            "Creating set.part3.rar",
            "Done",
        ]
    );
    assert_eq!(ran.err, "");
}

#[test]
fn r3_as_many_missing_as_there_are_recovery_volumes_are_restored_in_set_order() {
    for (tag, lost) in [
        ("two", &[2usize, 6][..]),
        ("three", &[1, 4, 5][..]),
        ("last", &[7][..]),
        ("last-two", &[6, 7][..]),
    ] {
        let set = Set::new(&format!("r3-{tag}"));
        for &n in lost {
            set.lose(n);
        }
        let ran = set.rc(&["set.part3.rar"]);
        assert_eq!(ran.exit, 0, "{tag}: {} {}", ran.out, ran.err);
        assert!(set.all_whole(), "{tag}");
        let created: Vec<&str> = ran
            .lines()
            .into_iter()
            .filter(|line| line.starts_with("Creating "))
            .collect();
        let owed: Vec<String> = lost
            .iter()
            .map(|&n| format!("Creating {}", part(n)))
            .collect();
        assert_eq!(created, owed, "{tag}");
        assert!(
            ran.says(&format!("{} volumes missing", lost.len())),
            "{tag}"
        );
        // Whole or not there: nothing but the set stands in its directory.
        assert_eq!(set.names().len(), DATA + RECOVERY, "{tag}");
    }
}

#[test]
fn r7_nothing_missing_is_exit_0_and_nothing_is_written() {
    let set = Set::new("r7-whole");
    let before = set.names();
    let ran = set.rc(&["set.part1.rar"]);
    assert_eq!(ran.exit, 0, "{} {}", ran.out, ran.err);
    assert!(ran.says("0 volumes missing"), "{}", ran.out);
    assert_eq!(ran.lines().last(), Some(&"Nothing to reconstruct"));
    assert_eq!(set.names(), before);
}

#[test]
fn r3_a_missing_recovery_volume_is_not_written_again() {
    let set = Set::new("r3-rev-lost");
    std::fs::remove_file(set.path(&rev(2))).unwrap();
    set.lose(4);
    let ran = set.rc(&["set.part1.rar"]);
    assert_eq!(ran.exit, 0, "{} {}", ran.out, ran.err);
    assert!(ran.says("2 recovery volumes found"), "{}", ran.out);
    assert!(set.all_whole());
    assert!(!set.path(&rev(2)).exists());
}

/// SPEC-L 3.9: a volume `rc` writes takes the mode of the first volume
/// present, whatever the umask gives a new file.
#[cfg(unix)]
#[test]
fn r3_a_restored_volume_takes_the_mode_of_the_first_volume_present() {
    use std::os::unix::fs::PermissionsExt as _;
    let set = Set::new("r3-mode");
    for n in 1..=DATA {
        let private = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(set.path(&part(n)), private).unwrap();
    }
    set.lose(1);
    let ran = set.rc(&["set.part2.rar"]);
    assert_eq!(ran.exit, 0, "{} {}", ran.out, ran.err);
    let mode = std::fs::metadata(set.path(&part(1)))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

// R8 (C5, C6, C11): a set that cannot be restored is never exit 0.

#[test]
fn r8_more_missing_than_recovery_volumes_is_exit_3_with_one_line_and_nothing_written() {
    let set = Set::new("r8-four");
    for n in [2, 3, 5, 6] {
        set.lose(n);
    }
    let before = set.names();
    let ran = set.rc(&["set.part1.rar"]);
    assert_eq!(ran.exit, 3, "{} {}", ran.out, ran.err);
    assert!(ran.says("4 volumes missing"), "{}", ran.out);
    assert_eq!(ran.lines().last(), Some(&"Reconstruction impossible"));
    let own: Vec<&str> = ran.err.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(own.len(), 1, "{}", ran.err);
    for n in [2, 3, 5, 6] {
        assert!(own[0].contains(&part(n)), "{}", own[0]);
    }
    assert!(own[0].contains("3 recovery volumes"), "{}", own[0]);
    assert_eq!(set.names(), before);
}

#[test]
fn r8_no_recovery_volume_and_a_volume_missing_is_exit_3() {
    let set = Set::new("r8-none-one-lost");
    for n in 1..=RECOVERY {
        std::fs::remove_file(set.path(&rev(n))).unwrap();
    }
    set.lose(4);
    let ran = set.rc(&["set.part1.rar"]);
    assert_eq!(ran.exit, 3, "{} {}", ran.out, ran.err);
    assert_eq!(ran.lines(), ["0 recovery volumes found"]);
    let own: Vec<&str> = ran.err.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(own.len(), 1, "{}", ran.err);
    assert!(own[0].contains("set.part4.rar"), "{}", own[0]);
    assert!(own[0].contains("0 recovery volumes"), "{}", own[0]);
}

#[test]
fn r8_no_recovery_volume_and_none_known_missing_is_exit_1_nothing_checked() {
    let set = Set::new("r8-none-whole");
    for n in 1..=RECOVERY {
        std::fs::remove_file(set.path(&rev(n))).unwrap();
    }
    let ran = set.rc(&["set.part1.rar"]);
    assert_eq!(ran.exit, 1, "{} {}", ran.out, ran.err);
    assert_eq!(ran.lines(), ["0 recovery volumes found"]);
    let own: Vec<&str> = ran.err.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(own.len(), 1, "{}", ran.err);
    assert!(own[0].contains("nothing was checked"), "{}", own[0]);
}

#[test]
fn r8_a_named_file_that_is_no_volume_or_no_archive_is_never_exit_0() {
    let (dir, _watch) = work("r8-not-a-set");
    // An archive that is no volume.
    std::fs::write(dir.join("data"), noise(3, 4_000)).unwrap();
    let made = Command::new(rarfast())
        .current_dir(&dir)
        .args(["a", "-idq", "-m0", "single.rar", "data"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
    let ran = rc_in(&dir, &["single.rar"], None);
    assert_ne!(ran.exit, 0, "{} {}", ran.out, ran.err);
    assert!(ran.out.contains("single.rar") || ran.err.contains("single.rar"));
    // A file that is no archive: the tool's own line and exit for one.
    std::fs::write(dir.join("junk.part1.rar"), noise(4, 4_000)).unwrap();
    let ran = rc_in(&dir, &["junk.part1.rar"], None);
    assert_eq!(ran.exit, 10, "{} {}", ran.out, ran.err);
    let said = format!("{}{}", ran.out, ran.err);
    assert!(said.contains("junk.part1.rar is not RAR archive"), "{said}");
    let mut names: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    names.sort();
    assert_eq!(names, ["data", "junk.part1.rar", "single.rar"]);
}

// R4 (C7, C16): a wrong data volume is kept as NAME.bad.

#[test]
fn r4_a_wrong_volume_is_kept_as_bad_and_written_anew() {
    for (tag, named) in [("other-named", "set.part1.rar"), ("named", "set.part2.rar")] {
        let set = Set::new(&format!("r4-wrong-{tag}"));
        set.spoil(&part(2));
        let wrong = std::fs::read(set.path(&part(2))).unwrap();
        set.lose(5);
        let ran = set.rc(&[named]);
        assert_eq!(ran.exit, 0, "{tag}: {} {}", ran.out, ran.err);
        let lines = ran.lines();
        let at = |line: &str| {
            lines
                .iter()
                .position(|l| *l == line)
                .unwrap_or_else(|| panic!("{tag}: no line {line:?} in {}", ran.out))
        };
        // The wrong volume is listed twice, the second time with its mark.
        assert!(at("set.part2.rar") < at("set.part2.rar        - checksum error"));
        assert!(ran.says("2 volumes missing"), "{tag}");
        assert!(at("ERROR: Bad archive set.part2.rar") < at("Creating set.part2.rar"));
        assert!(at("Renaming set.part2.rar to set.part2.rar.bad") < at("Creating set.part2.rar"));
        assert!(at("Creating set.part2.rar") < at("Creating set.part5.rar"));
        assert!(set.all_whole(), "{tag}");
        assert_eq!(std::fs::read(set.path("set.part2.rar.bad")).unwrap(), wrong);
    }
}

#[test]
fn r4_a_longer_and_a_cut_volume_count_as_missing() {
    let set = Set::new("r4-length");
    let mut longer = set.data[0].clone();
    longer.extend_from_slice(b"more");
    std::fs::write(set.path(&part(1)), longer).unwrap();
    std::fs::write(set.path(&part(6)), &set.data[5][..9_000]).unwrap();
    let ran = set.rc(&["set.part2.rar"]);
    assert_eq!(ran.exit, 0, "{} {}", ran.out, ran.err);
    assert!(set.all_whole());
    assert!(set.path("set.part1.rar.bad").exists());
    assert!(set.path("set.part6.rar.bad").exists());
}

#[test]
fn r4_when_too_many_are_wrong_nothing_is_renamed_or_written() {
    let set = Set::new("r4-too-many");
    for n in [1, 3, 4, 6] {
        set.spoil(&part(n));
    }
    let before = set.names();
    let ran = set.rc(&["set.part2.rar"]);
    assert_eq!(ran.exit, 3, "{} {}", ran.out, ran.err);
    assert_eq!(ran.lines().last(), Some(&"Reconstruction impossible"));
    assert!(ran.says("set.part4.rar        - checksum error"));
    assert_eq!(set.names(), before);
}

/// R4's last part, a chosen difference: the reference replaces a file at
/// NAME.bad without a word under every switch (C16).
#[test]
fn r4_a_file_already_at_bad_is_never_replaced_in_silence() {
    let old_bad = noise(11, 700);
    let arm = |tag: &str| {
        let set = Set::new(&format!("r4-bad-{tag}"));
        set.spoil(&part(2));
        std::fs::write(set.path("set.part2.rar.bad"), &old_bad).unwrap();
        let wrong = std::fs::read(set.path(&part(2))).unwrap();
        (set, wrong)
    };

    // No switch, and nothing to read an answer from: asked, exit 12,
    // both files as they were.
    let (set, wrong) = arm("ask-end");
    let ran = set.rc(&["set.part1.rar"]);
    assert_eq!(ran.exit, 12, "{} {}", ran.out, ran.err);
    assert!(
        ran.err.contains("Overwrite set.part2.rar.bad?"),
        "{}",
        ran.err
    );
    assert_eq!(
        std::fs::read(set.path("set.part2.rar.bad")).unwrap(),
        old_bad
    );
    assert_eq!(std::fs::read(set.path(&part(2))).unwrap(), wrong);

    // Yes to the question, `-y` and `-o+`: the old NAME.bad is replaced.
    for (tag, switch, answer) in [
        ("yes", None, Some("y\n")),
        ("y", Some("-y"), None),
        ("o+", Some("-o+"), None),
    ] {
        let (set, wrong) = arm(tag);
        let mut args: Vec<&str> = switch.into_iter().collect();
        args.push("set.part1.rar");
        let ran = rc_in(&set.dir, &args, answer);
        assert_eq!(ran.exit, 0, "{tag}: {} {}", ran.out, ran.err);
        assert!(set.all_whole(), "{tag}");
        assert_eq!(
            std::fs::read(set.path("set.part2.rar.bad")).unwrap(),
            wrong,
            "{tag}"
        );
    }

    // No to the question, and `-o-`: the old NAME.bad stays, so the wrong
    // volume cannot be moved aside and is not restored; exit 3.
    for (tag, switch, answer) in [("no", None, Some("n\n")), ("o-", Some("-o-"), None)] {
        let (set, wrong) = arm(tag);
        let mut args: Vec<&str> = switch.into_iter().collect();
        args.push("set.part1.rar");
        let ran = rc_in(&set.dir, &args, answer);
        assert_eq!(ran.exit, 3, "{tag}: {} {}", ran.out, ran.err);
        assert_eq!(
            std::fs::read(set.path("set.part2.rar.bad")).unwrap(),
            old_bad,
            "{tag}"
        );
        assert_eq!(std::fs::read(set.path(&part(2))).unwrap(), wrong, "{tag}");
        assert!(ran.err.contains("set.part2.rar"), "{tag}: {}", ran.err);
        assert_eq!(set.names().len(), DATA + RECOVERY + 1, "{tag}");
    }

    // `-or`: the wrong volume is kept under a renamed name, both stay,
    // and the set is whole at its own names.
    let (set, wrong) = arm("or");
    let ran = set.rc(&["-or", "set.part1.rar"]);
    assert_eq!(ran.exit, 0, "{} {}", ran.out, ran.err);
    assert!(set.all_whole());
    assert_eq!(
        std::fs::read(set.path("set.part2.rar.bad")).unwrap(),
        old_bad
    );
    assert_eq!(
        std::fs::read(set.path("set.part2.rar(1).bad")).unwrap(),
        wrong
    );
}

// R9 (C8, C14, C15): a file in the way of a rebuilt volume.

/// A set with volume 3 lost and an EMPTY file at its name, and volume 5
/// lost with nothing at its name.
fn in_the_way(tag: &str) -> Set {
    let set = Set::new(&format!("r9-{tag}"));
    set.lose(3);
    set.lose(5);
    std::fs::write(set.path(&part(3)), b"").unwrap();
    set
}

#[test]
fn r9_with_no_switch_the_question_is_asked() {
    // Nothing to read an answer from: exit 12, the file left.
    let set = in_the_way("ask-end");
    let ran = set.rc(&["set.part1.rar"]);
    assert_eq!(ran.exit, 12, "{} {}", ran.out, ran.err);
    assert!(ran.err.contains("Overwrite set.part3.rar?"), "{}", ran.err);
    assert_eq!(std::fs::read(set.path(&part(3))).unwrap(), b"");
    // The empty file is not listed as a volume, and counts as missing.
    assert!(!ran.says("set.part3.rar"), "{}", ran.out);
    assert!(ran.says("2 volumes missing"), "{}", ran.out);

    // Yes: replaced.
    let set = in_the_way("ask-yes");
    let ran = set.rc_answering(&["set.part1.rar"], "y\n");
    assert_eq!(ran.exit, 0, "{} {}", ran.out, ran.err);
    assert!(set.all_whole());

    // No: that volume is not written, the run goes on to the other, and
    // the exit is 3 (the reference ends the run, exit 255).
    let set = in_the_way("ask-no");
    let ran = set.rc_answering(&["set.part1.rar"], "n\n");
    assert_eq!(ran.exit, 3, "{} {}", ran.out, ran.err);
    assert_eq!(std::fs::read(set.path(&part(3))).unwrap(), b"");
    assert!(set.whole(5));
}

#[test]
fn r9_a_file_that_is_no_archive_in_the_way_is_asked_about_too() {
    let set = Set::new("r9-junk");
    set.lose(3);
    let junk = noise(5, 2_000);
    std::fs::write(set.path(&part(3)), &junk).unwrap();
    let ran = set.rc(&["set.part1.rar"]);
    assert_eq!(ran.exit, 12, "{} {}", ran.out, ran.err);
    assert_eq!(std::fs::read(set.path(&part(3))).unwrap(), junk);
    assert!(!set.path("set.part3.rar.bad").exists());
}

#[test]
fn r9_o_plus_and_y_replace_the_file_without_asking() {
    for switch in ["-o+", "-y"] {
        let set = in_the_way(&format!("replace{switch}"));
        let ran = set.rc(&[switch, "set.part1.rar"]);
        assert_eq!(ran.exit, 0, "{switch}: {} {}", ran.out, ran.err);
        assert!(!ran.err.contains("Overwrite"), "{switch}: {}", ran.err);
        assert!(set.all_whole(), "{switch}");
        assert_eq!(ran.lines().last(), Some(&"Done"), "{switch}");
    }
}

#[test]
fn r9_o_minus_never_replaces_it_says_so_and_goes_on_to_the_others() {
    let set = in_the_way("never");
    let ran = set.rc(&["-o-", "set.part1.rar"]);
    assert_eq!(ran.exit, 3, "{} {}", ran.out, ran.err);
    assert!(!ran.err.contains("Overwrite"), "{}", ran.err);
    assert_eq!(std::fs::read(set.path(&part(3))).unwrap(), b"");
    assert!(set.whole(5));
    let own: Vec<&str> = ran
        .err
        .lines()
        .filter(|l| l.contains("set.part3.rar"))
        .collect();
    assert!(!own.is_empty(), "{}", ran.err);
    assert_eq!(set.names().len(), DATA + RECOVERY);
}

#[test]
fn r9_or_writes_under_the_renamed_name_and_the_exit_is_1() {
    let set = in_the_way("rename");
    let ran = set.rc(&["-or", "set.part1.rar"]);
    assert_eq!(ran.exit, 1, "{} {}", ran.out, ran.err);
    assert_eq!(std::fs::read(set.path(&part(3))).unwrap(), b"");
    assert_eq!(
        std::fs::read(set.path("set.part3(1).rar")).unwrap(),
        set.data[2]
    );
    assert!(set.whole(5));
    assert!(ran.err.contains("set.part3(1).rar"), "{}", ran.err);
}

/// A chosen difference: the reference ends the run there, exit 9 (C15).
#[test]
fn r9_a_directory_at_the_name_is_passed_over_and_the_others_are_restored() {
    let set = Set::new("r9-directory");
    set.lose(3);
    set.lose(5);
    std::fs::create_dir(set.path(&part(3))).unwrap();
    let ran = set.rc(&["-y", "set.part1.rar"]);
    assert_eq!(ran.exit, 3, "{} {}", ran.out, ran.err);
    assert!(set.path(&part(3)).is_dir());
    assert!(set.whole(5));
    assert!(!ran.out.contains("Program aborted"), "{}", ran.out);
    let own: Vec<&str> = ran
        .err
        .lines()
        .filter(|l| l.contains("set.part3.rar"))
        .collect();
    assert_eq!(own.len(), 1, "{}", ran.err);
    assert_eq!(set.names().len(), DATA + RECOVERY);
}

/// The question's other answers are the ones the tool's question has
/// where a file is extracted over another: `a` and `e` answer for every
/// later volume, `r` reads a new name, `q` ends the run, and any other
/// line prints the choices again.
#[test]
fn r9_the_question_s_other_answers() {
    const CHOICES: &str = "[Y]es, [N]o, [A]ll, n[E]ver, [R]ename, [Q]uit";
    // Two files in the way, volumes 3 and 5.
    let two = |tag: &str| {
        let set = in_the_way(tag);
        std::fs::write(set.path(&part(5)), b"").unwrap();
        set
    };

    // All: asked once, both replaced.
    let set = two("ask-all");
    let ran = set.rc_answering(&["set.part1.rar"], "a\n");
    assert_eq!(ran.exit, 0, "{} {}", ran.out, ran.err);
    assert_eq!(ran.err.matches("Overwrite ").count(), 1, "{}", ran.err);
    assert!(set.all_whole());

    // Never: asked once, neither replaced, exit 3.
    let set = two("ask-never");
    let ran = set.rc_answering(&["set.part1.rar"], "e\n");
    assert_eq!(ran.exit, 3, "{} {}", ran.out, ran.err);
    assert_eq!(ran.err.matches("Overwrite ").count(), 1, "{}", ran.err);
    assert_eq!(std::fs::read(set.path(&part(3))).unwrap(), b"");
    assert_eq!(std::fs::read(set.path(&part(5))).unwrap(), b"");

    // Quit: `Program aborted`, exit 255, nothing written and nothing
    // left behind; the later volume is not restored.
    let set = in_the_way("ask-quit");
    let ran = set.rc_answering(&["set.part1.rar"], "q\n");
    assert_eq!(ran.exit, 255, "{} {}", ran.out, ran.err);
    assert!(ran.says("Program aborted"), "{}", ran.out);
    assert_eq!(std::fs::read(set.path(&part(3))).unwrap(), b"");
    assert!(!set.path(&part(5)).exists());
    assert_eq!(set.names().len(), DATA - 1 + RECOVERY);

    // Rename: the name is read, the volume is written under it beside
    // the set, the file in the way stays, and the exit is 1 as for -or.
    let set = in_the_way("ask-rename");
    let ran = set.rc_answering(&["set.part1.rar"], "r\nelsewhere.rar\n");
    assert_eq!(ran.exit, 1, "{} {}", ran.out, ran.err);
    assert!(ran.out.contains("Enter new name: "), "{}", ran.out);
    assert_eq!(std::fs::read(set.path(&part(3))).unwrap(), b"");
    assert_eq!(
        std::fs::read(set.path("elsewhere.rar")).unwrap(),
        set.data[2]
    );
    assert!(set.whole(5));

    // Rename to a name that is taken: asked about that name.
    let set = in_the_way("ask-rename-taken");
    std::fs::write(set.path("taken.rar"), b"old").unwrap();
    let ran = set.rc_answering(&["set.part1.rar"], "r\ntaken.rar\nn\n");
    assert_eq!(ran.exit, 3, "{} {}", ran.out, ran.err);
    assert!(ran.err.contains("Overwrite taken.rar?"), "{}", ran.err);
    assert_eq!(std::fs::read(set.path("taken.rar")).unwrap(), b"old");

    // Another letter, and an empty line: the choices again, and the next
    // line is read.
    let set = in_the_way("ask-other");
    let ran = set.rc_answering(&["set.part1.rar"], "x\n\ny\n");
    assert_eq!(ran.exit, 0, "{} {}", ran.out, ran.err);
    assert_eq!(ran.err.matches(CHOICES).count(), 3, "{}", ran.err);
    assert!(set.all_whole());
}

/// Measured on the reference: it never writes a plain first volume
/// beside a self-extracting first volume that is there. The first
/// volume here is one by its NAME only (a plain volume renamed), which
/// is all the rule reads.
#[test]
fn r3_no_plain_first_volume_is_written_beside_a_self_extracting_one() {
    for extension in ["exe", "sfx"] {
        let set = Set::new(&format!("r3-sfx-{extension}"));
        let first = format!("set.part1.{extension}");
        std::fs::rename(set.path(&part(1)), set.path(&first)).unwrap();
        set.lose(3);
        let ran = set.rc(&["set.part2.rar"]);
        assert_eq!(ran.exit, 3, "{extension}: {} {}", ran.out, ran.err);
        assert!(!set.path(&part(1)).exists(), "{extension}");
        assert_eq!(std::fs::read(set.path(&first)).unwrap(), set.data[0]);
        assert!(set.whole(3), "{extension}");
        let own: Vec<&str> = ran.err.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(own.len(), 1, "{extension}: {}", ran.err);
        assert!(own[0].contains("set.part1.rar"), "{}", own[0]);
        assert!(own[0].contains(&first), "{}", own[0]);
        assert_eq!(set.names().len(), DATA + RECOVERY, "{extension}");
    }
}

// R2, R5 (C9, C10): recovery volumes that are wrong, or another set's.

#[test]
fn r2_a_wrong_recovery_volume_is_marked_and_not_used() {
    let set = Set::new("r2-rev-wrong");
    set.spoil(&rev(2));
    set.lose(3);
    set.lose(4);
    let ran = set.rc(&["set.part1.rar"]);
    assert_eq!(ran.exit, 0, "{} {}", ran.out, ran.err);
    assert!(ran.says("3 recovery volumes found"), "{}", ran.out);
    assert!(
        ran.says("set.part2.rev        - checksum error"),
        "{}",
        ran.out
    );
    assert!(set.all_whole());

    // One more missing than the two sound ones can restore.
    let set = Set::new("r2-rev-wrong-too-few");
    set.spoil(&rev(2));
    for n in [3, 4, 5] {
        set.lose(n);
    }
    let before = set.names();
    let ran = set.rc(&["set.part1.rar"]);
    assert_eq!(ran.exit, 3, "{} {}", ran.out, ran.err);
    assert_eq!(ran.lines().last(), Some(&"Reconstruction impossible"));
    assert_eq!(set.names(), before);
}

/// R5, a chosen difference: the reference uses another set's recovery
/// volume and writes a volume that is not the set's, exit 0 (C10).
#[test]
fn r5_a_recovery_volume_of_another_set_is_refused_and_never_used() {
    let set = Set::new("r5-another");
    let other = Set::drawn("r5-another-donor", 2, &[]);
    std::fs::copy(other.path(&rev(2)), set.path(&rev(2))).unwrap();
    set.lose(3);
    let ran = set.rc(&["set.part1.rar"]);
    assert_eq!(ran.exit, 0, "{} {}", ran.out, ran.err);
    assert!(set.all_whole(), "the volume written is the set's own");
    let refused: Vec<&str> = ran
        .lines()
        .into_iter()
        .filter(|line| line.starts_with("set.part2.rev") && line.len() > "set.part2.rev".len())
        .collect();
    assert_eq!(refused.len(), 1, "{}", ran.out);

    // All three of another set: nothing of this set can be vouched for.
    let set = Set::new("r5-all-another");
    for n in 1..=RECOVERY {
        std::fs::copy(other.path(&rev(n)), set.path(&rev(n))).unwrap();
    }
    set.lose(3);
    let before = set.names();
    let ran = set.rc(&["set.part1.rar"]);
    assert_eq!(ran.exit, 3, "{} {}", ran.out, ran.err);
    assert_eq!(set.names(), before);
}

// R6 (C12): the quiet switches.

#[test]
fn r6_idq_and_inul_print_nothing_and_restore() {
    for switch in ["-idq", "-inul"] {
        let set = Set::new(&format!("r6{switch}"));
        set.lose(3);
        let ran = set.rc(&[switch, "set.part1.rar"]);
        assert_eq!(ran.exit, 0, "{switch}: {} {}", ran.out, ran.err);
        assert_eq!(ran.out, "", "{switch}");
        assert_eq!(ran.err, "", "{switch}");
        assert!(set.all_whole(), "{switch}");
    }
    let set = Set::new("r6-kb-t");
    set.lose(3);
    let ran = set.rc(&["-kb", "-t", "set.part1.rar"]);
    assert_eq!(ran.exit, 0, "{} {}", ran.out, ran.err);
    assert!(set.all_whole());
}

// R10: the older form is refused by name.

#[test]
fn r10_a_set_of_the_older_form_is_refused_in_one_line() {
    let (dir, _watch) = work("r10-older");
    let kept = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/listing-names/r4-two.rar");
    std::fs::copy(kept, dir.join("old.part1.rar")).unwrap();
    // No recovery volume of the older form is kept in this crate; the
    // file stands for one by its name beside a RAR 4 archive, which is
    // how the set is told to be of the older form.
    std::fs::write(dir.join("old.part1.rev"), noise(6, 5_000)).unwrap();
    for named in ["old.part1.rar", "old.part1.rev"] {
        let ran = rc_in(&dir, &[named], None);
        assert_eq!(ran.exit, 2, "{named}: {} {}", ran.out, ran.err);
        let own: Vec<&str> = ran.err.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(own.len(), 1, "{named}: {}", ran.err);
        assert!(own[0].contains("older form"), "{named}: {}", own[0]);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 2, "{named}");
    }
}

// R11 (C13): no password is asked.

/// The reference `rar` on PATH, which alone here can write recovery
/// volumes beside a set whose headers are encrypted.
fn reference() -> Option<PathBuf> {
    let found = Command::new("which").arg("rar").output().ok()?;
    let path = String::from_utf8_lossy(&found.stdout).trim().to_owned();
    (found.status.success() && !path.is_empty()).then(|| PathBuf::from(path))
}

/// A chosen difference: the reference asks for the password before
/// anything else and refuses `-p-` with exit 11. The set is written by
/// the reference, called and never opened: seven volumes under
/// `-hpsecret` and three recovery volumes.
#[test]
fn r11_a_set_with_encrypted_headers_is_restored_and_no_password_is_asked() {
    let Some(reference) = reference() else {
        println!("r11: not measured, no `rar` on PATH");
        return;
    };
    for (tag, switch) in [
        ("none", None),
        ("given", Some("-psecret")),
        ("wrong", Some("-pother")),
        ("refused", Some("-p-")),
    ] {
        let (dir, _watch) = work(&format!("r11-{tag}"));
        std::fs::write(dir.join("data"), noise(7, 100_000)).unwrap();
        let made = Command::new(&reference)
            .current_dir(&dir)
            .args(["a", "-idq", "-m0", "-ep", "-v16384b", "-rv3", "-hpsecret"])
            .args(["set.rar", "data"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(made.status.success(), "{made:?}");
        std::fs::remove_file(dir.join("data")).unwrap();
        let lost = std::fs::read(dir.join(part(3))).unwrap();
        std::fs::remove_file(dir.join(part(3))).unwrap();
        let mut args: Vec<&str> = switch.into_iter().collect();
        args.push("set.part1.rar");
        let ran = rc_in(&dir, &args, None);
        assert_eq!(ran.exit, 0, "{tag}: {} {}", ran.out, ran.err);
        assert_eq!(ran.err, "", "{tag}");
        assert_eq!(std::fs::read(dir.join(part(3))).unwrap(), lost, "{tag}");
    }
}
