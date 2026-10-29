//! The creator, measured against the reference binary itself.
//!
//! **The reference IS the specification for this dialect**, so these tests
//! do not compare `rarfast` against a string somebody typed here: each row
//! runs `rar` 7.23 and `rarfast` over the SAME command line in two fresh
//! copies of the same input tree, and compares the raw stdout, the raw
//! stderr, the exit code and the whole resulting file tree. The capture is
//! taken in the test's own setup, so a row cannot pass against a stale
//! expectation.
//!
//! The comparison normalises exactly what the project's
//! the conformance run normalises and nothing else: the banner
//! lines the reference prints and we do not, terminal redraws (a run of
//! backspaces), a percentage counter, trailing spaces on a line, and blank
//! lines at either end of the stream. Widening it any further would be the
//! same edit as deleting the test.
//!
//! Where a reference binary is not installed there is nothing to measure
//! against: the row prints one line naming what it lacks and returns, and
//! that line is the only sign that it gave no verdict.

use std::path::{Path, PathBuf};
use std::process::Command;

// The copy of the binary run as `unrar`, and its spawns, kept clear of
// Linux's "Text file busy" (`support/exe_copy.rs`).
#[path = "support/exe_copy.rs"]
mod exe_copy;
use exe_copy::{copy_executable, output_of, status_of};

/// The reference this suite measures against.
const REFERENCE: &str = "rar";

/// The payload the conformance harness builds, reproduced here so that a
/// row runs over the same bytes the committed tables were captured over:
/// a compressible text file, an incompressible one, an empty one, a pair
/// of identical ones and a subdirectory.
fn build_payload(root: &Path) {
    std::fs::create_dir_all(root).unwrap();
    let mut text = Vec::new();
    for index in 0..400 {
        text.extend_from_slice(
            format!("conformance line {index:04} padding padding padding\n").as_bytes(),
        );
    }
    std::fs::write(root.join("text.txt"), &text).unwrap();
    std::fs::write(root.join("rand.bin"), pseudo_random(24576, 1)).unwrap();
    std::fs::write(root.join("zero.bin"), b"").unwrap();
    let dup = pseudo_random(8192, 2);
    std::fs::write(root.join("dup1.bin"), &dup).unwrap();
    std::fs::write(root.join("dup2.bin"), &dup).unwrap();
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(root.join("sub/nested.txt"), "nested payload\n".repeat(64)).unwrap();
    std::fs::write(root.join("files.txt"), b"text.txt\nrand.bin\n").unwrap();
    std::fs::write(root.join("comment.txt"), b"a conformance comment\n").unwrap();
    freeze(root);
}

/// The instant every payload file is stamped with.
///
/// A member's modification time goes INTO its header, so two trees built
/// a millisecond apart produce two different archives and a byte identity
/// row compares nothing. The conformance harness freezes its inputs for
/// exactly this reason; this is the same freeze, at the same instant it
/// uses.
const FROZEN: u64 = 1_000_000_000;

/// Stamps every file and directory under `root`, deepest first, so that a
/// directory's own time is not moved again by a file written inside it.
fn freeze(root: &Path) {
    let stamp = std::time::UNIX_EPOCH + std::time::Duration::from_secs(FROZEN);
    let times = std::fs::FileTimes::new()
        .set_accessed(stamp)
        .set_modified(stamp);
    let mut paths = Vec::new();
    walk_all(root, &mut paths);
    paths.push(root.to_path_buf());
    for path in paths {
        let handle = if path.is_dir() {
            // A directory handle: `File::open` is enough on unix, which
            // is where both reference binaries live.
            std::fs::File::open(&path)
        } else {
            std::fs::OpenOptions::new().write(true).open(&path)
        };
        if let Ok(handle) = handle {
            let _ = handle.set_times(times);
        }
    }
}

/// Every path under `root`, deepest first.
fn walk_all(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_all(&path, out);
        }
        out.push(path);
    }
}

/// Bytes that are the same on every box and do not compress: a 64 bit
/// linear congruential walk, which is enough for `-m3` to have nothing to
/// find.
fn pseudo_random(length: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(1);
    let mut out = Vec::with_capacity(length);
    for _ in 0..length {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        out.push((state >> 33) as u8);
    }
    out
}

/// What one run of a binary produced.
struct Run {
    stdout: String,
    stderr: String,
    exit: i32,
    files: Vec<(String, u64, [u8; 8])>,
}

/// Runs `binary` over `args` in a fresh copy of the payload.
fn run_in_copy(binary: &Path, args: &[&str], tag: &str) -> Run {
    let work = std::env::temp_dir().join(format!(
        "rarfast-ref-{}-{tag}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&work);
    build_payload(&work);
    let output = output_of(Command::new(binary).args(args).current_dir(&work))
        .unwrap_or_else(|err| panic!("{} could not be run: {err}", binary.display()));
    let run = Run {
        stdout: normalise(&String::from_utf8_lossy(&output.stdout), &work),
        stderr: normalise(&String::from_utf8_lossy(&output.stderr), &work),
        exit: output.status.code().unwrap_or(-1),
        files: fingerprint(&work),
    };
    let _ = std::fs::remove_dir_all(&work);
    run
}

/// Every file under `root`, by name, length and a cheap digest of its
/// bytes, sorted, which is what a row compares its file tree by.
fn fingerprint(root: &Path) -> Vec<(String, u64, [u8; 8])> {
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

fn walk(root: &Path, at: &Path, out: &mut Vec<(String, u64, [u8; 8])>) {
    let Ok(entries) = std::fs::read_dir(at) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(root, &path, out);
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let name = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        out.push((name, bytes.len() as u64, digest(&bytes)));
    }
}

/// A short digest, which is all a file comparison needs here: a 64 bit
/// FNV-1a walk over the bytes.
fn digest(bytes: &[u8]) -> [u8; 8] {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash.to_be_bytes()
}

/// `run.py`'s own normalisation, and no more of it.
fn normalise(text: &str, work: &Path) -> String {
    let text = text.replace('\0', "");
    let text = strip_backspaces(&text);
    let forms = [
        work.to_string_lossy().into_owned(),
        std::fs::canonicalize(work)
            .unwrap_or_else(|_| work.to_path_buf())
            .to_string_lossy()
            .into_owned(),
    ];
    let mut lines: Vec<String> = Vec::new();
    for raw in text.split('\n') {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        // A carriage return is a terminal redraw: only what would have
        // been left showing is compared.
        let mut line = raw.rsplit('\r').next().unwrap_or(raw).to_owned();
        if is_banner(&line) {
            continue;
        }
        // Longest first, or the shorter form eats the prefix of the
        // longer one.
        let mut ordered = forms.clone();
        ordered.sort_by_key(|form| std::cmp::Reverse(form.len()));
        for form in &ordered {
            if !form.is_empty() {
                line = line.replace(form.as_str(), "{WORK}");
            }
        }
        line = percent_token(&line);
        lines.push(line.trim_end().to_owned());
    }
    while lines.first().is_some_and(String::is_empty) {
        lines.remove(0);
    }
    while lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
    lines.join("\n")
}

/// Deletes every run of backspace, which is what a terminal redraw leaves
/// behind once it has been drawn.
fn strip_backspaces(text: &str) -> String {
    text.chars().filter(|c| *c != '\u{8}').collect()
}

/// The lines the reference prints about itself, which a drop-in does not.
fn is_banner(line: &str) -> bool {
    line.starts_with("Copyright")
        || line.starts_with("Trial version")
        || line.starts_with("Type '")
        || line.starts_with("Evaluation copy")
        || line.starts_with("Please register")
        || (line.starts_with("RAR ") && line.as_bytes().get(4).is_some_and(u8::is_ascii_digit))
}

/// Rewrites every `<digits>%` with a word boundary in front of it, which
/// is what the harness does to a progress counter.
fn percent_token(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut index = 0;
    while index < bytes.len() {
        let digits = bytes[index..]
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        let boundary = index == 0 || !bytes[index - 1].is_ascii_alphanumeric();
        if boundary && (1..=3).contains(&digits) && bytes.get(index + digits) == Some(&b'%') {
            out.push_str("<pct>");
            index += digits + 1;
            continue;
        }
        if digits > 0 {
            out.push_str(&line[index..index + digits]);
            index += digits;
            continue;
        }
        out.push(bytes[index] as char);
        index += 1;
    }
    out
}

/// Where the reference lives, or `None` when it is not on this box.
fn reference() -> Option<PathBuf> {
    let output = output_of(Command::new("which").arg(REFERENCE)).ok()?;
    if !output.status.success() {
        return None;
    }
    let path = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim().to_owned());
    path.is_file().then_some(path)
}

/// One row: the same command line to both binaries, everything compared.
fn same_as_reference(row: &str, args: &[&str]) {
    let Some(reference) = reference() else {
        // Said aloud, so that a run on a machine without the reference
        // is not read as a row that was compared and agreed.
        println!("{row}: not measured, no `{REFERENCE}` on PATH");
        return;
    };
    let ours = PathBuf::from(env!("CARGO_BIN_EXE_rarfast"));
    let theirs = run_in_copy(&reference, args, &format!("{}-ref", safe(row)));
    let mine = run_in_copy(&ours, args, &format!("{}-ours", safe(row)));
    compare(row, &mine, &theirs);
}

/// [`same_as_reference`], and the archive's BYTES too.
///
/// Only a stored archive claims this: an encoder chooses nothing there, so
/// the reference's own bytes are the standard. A compressed archive is
/// rarkit's own and is compared by what it extracts to instead.
fn byte_identical_to_reference(row: &str, args: &[&str]) {
    let Some(reference) = reference() else {
        println!("{row}: not measured, no `{REFERENCE}` on PATH");
        return;
    };
    let ours = PathBuf::from(env!("CARGO_BIN_EXE_rarfast"));
    let theirs = run_in_copy(&reference, args, &format!("{}-ref", safe(row)));
    let mine = run_in_copy(&ours, args, &format!("{}-ours", safe(row)));
    assert_eq!(mine.exit, theirs.exit, "{row}: exit code");
    assert_eq!(
        mine.stdout, theirs.stdout,
        "{row}: stdout\n--- ours ---\n{}\n--- reference ---\n{}",
        mine.stdout, theirs.stdout
    );
    assert_eq!(mine.files, theirs.files, "{row}: the files afterwards");
}

/// What every row asserts: the raw stdout, the raw stderr, the exit code
/// and the file tree afterwards, all four or the row does not pass.
fn compare(row: &str, mine: &Run, theirs: &Run) {
    assert_eq!(
        mine.stdout, theirs.stdout,
        "{row}: stdout\n--- ours ---\n{}\n--- reference ---\n{}",
        mine.stdout, theirs.stdout
    );
    assert_eq!(
        mine.stderr, theirs.stderr,
        "{row}: stderr\n--- ours ---\n{}\n--- reference ---\n{}",
        mine.stderr, theirs.stderr
    );
    assert_eq!(mine.exit, theirs.exit, "{row}: exit code");
    assert_eq!(
        names(&mine.files),
        names(&theirs.files),
        "{row}: the file tree afterwards"
    );
}

fn names(files: &[(String, u64, [u8; 8])]) -> Vec<&str> {
    files.iter().map(|(name, _, _)| name.as_str()).collect()
}

/// A row id as a file name.
fn safe(row: &str) -> String {
    row.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

// --- the creator's own rows -------------------------------------------
//
// Each name is the conformance table's row id where there is one, so a
// failure here and a failure there name the same thing.

#[test]
fn add_stored() {
    byte_identical_to_reference(
        "add-stored",
        &["a", "-y", "-m0", "arc.rar", "text.txt", "rand.bin"],
    );
}

#[test]
fn add_stored_recurse() {
    byte_identical_to_reference(
        "add-stored-recurse",
        &["a", "-y", "-m0", "-r", "arc.rar", "text.txt", "sub"],
    );
}

#[test]
fn add_level_zero() {
    byte_identical_to_reference("add-level-m0", &["a", "-y", "-m0", "arc.rar", "text.txt"]);
}

#[test]
fn add_rar5() {
    byte_identical_to_reference(
        "add-rar5",
        &["a", "-y", "-m0", "-ma5", "arc.rar", "text.txt"],
    );
}

#[test]
fn add_comment() {
    byte_identical_to_reference(
        "add-comment",
        &["a", "-y", "-m0", "-zcomment.txt", "arc.rar", "text.txt"],
    );
}

#[test]
fn add_listfile() {
    byte_identical_to_reference("add-listfile", &["a", "-y", "-m0", "arc.rar", "@files.txt"]);
}

#[test]
fn add_exclude() {
    byte_identical_to_reference(
        "add-exclude",
        &[
            "a",
            "-y",
            "-m0",
            "-xrand.bin",
            "arc.rar",
            "text.txt",
            "rand.bin",
        ],
    );
}

#[test]
fn add_hash_blake2() {
    byte_identical_to_reference(
        "add-hash-blake2",
        &["a", "-y", "-m0", "-htb", "arc.rar", "text.txt"],
    );
}

#[test]
fn add_a_missing_file_is_reported_and_the_rest_are_written() {
    same_as_reference(
        "add-partial-missing",
        &[
            "a",
            "-y",
            "-m0",
            "arc.rar",
            "text.txt",
            "nosuch.txt",
            "rand.bin",
        ],
    );
}

#[test]
fn add_nothing_writes_nothing() {
    same_as_reference("add-no-files", &["a", "-y", "-m0", "arc.rar", "nosuch.txt"]);
}

#[test]
fn add_quiet_prints_nothing() {
    byte_identical_to_reference(
        "add-idq",
        &["a", "-y", "-m0", "-idq", "arc.rar", "text.txt"],
    );
}

#[test]
fn add_without_the_counter() {
    byte_identical_to_reference(
        "add-idp",
        &["a", "-y", "-m0", "-idp", "arc.rar", "text.txt", "rand.bin"],
    );
}

#[test]
fn add_strips_paths() {
    byte_identical_to_reference("add-ep", &["a", "-y", "-m0", "-ep", "arc.rar", "sub"]);
}

#[test]
fn add_an_empty_member() {
    byte_identical_to_reference(
        "add-empty",
        &["a", "-y", "-m0", "arc.rar", "zero.bin", "text.txt"],
    );
}

#[test]
fn add_then_delete_the_sources() {
    byte_identical_to_reference(
        "add-df",
        &["a", "-y", "-m0", "-df", "arc.rar", "text.txt", "rand.bin"],
    );
}

#[test]
fn move_into_archive() {
    byte_identical_to_reference(
        "move-into-archive",
        &["m", "-y", "-m0", "arc.rar", "text.txt"],
    );
}

#[test]
fn move_files_only() {
    byte_identical_to_reference(
        "move-files-only",
        &["mf", "-y", "-m0", "arc.rar", "text.txt"],
    );
}

/// `m` over a directory: the reference deletes the directory's members,
/// then the directory itself, and counts the directory in its percentage.
#[test]
fn move_removes_the_directory() {
    same_as_reference(
        "move-directory",
        &["m", "-r", "-y", "-m0", "arc.rar", "sub"],
    );
}

/// `mf` moves files only, so the directory stays, but it still takes its
/// place in the count the percentage is taken over.
#[test]
fn move_files_leaves_the_directory() {
    same_as_reference(
        "move-files-directory",
        &["mf", "-r", "-y", "-m0", "arc.rar", "sub"],
    );
}

/// A directory with something in it that was not archived stays, and both
/// tools say so the same way.
#[test]
fn move_keeps_a_directory_that_is_not_empty() {
    same_as_reference(
        "move-directory-not-empty",
        &["m", "-r", "-y", "-m0", "-x*nested.txt", "arc.rar", "sub"],
    );
}

#[test]
fn add_then_test() {
    same_as_reference(
        "add-test-after",
        &["a", "-y", "-m0", "-t", "arc.rar", "text.txt"],
    );
}

/// `-v<size>` caps the volume FILE, as the reference's does.
///
/// The reference's `-v12k` caps each volume at 12,288 bytes, signature,
/// headers and end block included. Until 28 Sep 2026 `rarfast` passed the
/// figure as the engine's PAYLOAD budget, so the same command line gave
/// volumes of 12,347 and 12,348 bytes and two volumes where the reference
/// writes three; this row pinned that divergence. It now passes the FILE
/// cap (`WriteOptions::volume_file_size`), so every volume is at most the
/// cap and the set has the reference's volume count.
///
/// Not byte identity: the reference pads each non-final volume with zeros
/// up to the cap and rarkit does not (`WriteOptions::volume_file_size`),
/// so a non-final volume here is at most the cap rather than exactly it.
#[test]
fn add_volumes_cap_the_file_and_the_reference_reads_them() {
    let Some(reference) = reference() else {
        println!("volume cap: not measured, no `{REFERENCE}` on PATH");
        return;
    };
    let ours = PathBuf::from(env!("CARGO_BIN_EXE_rarfast"));
    let work = std::env::temp_dir().join(format!("rarfast-volumes-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    build_payload(&work);
    let volumes = |stem: &str| -> Vec<u64> {
        let mut sizes = Vec::new();
        while let Ok(meta) =
            std::fs::metadata(work.join(format!("{stem}.part{}.rar", sizes.len() + 1)))
        {
            sizes.push(meta.len());
        }
        sizes
    };
    for (tool, stem) in [(&ours, "arc"), (&reference, "ref")] {
        let run = output_of(
            Command::new(tool)
                .args([
                    "a",
                    "-y",
                    "-m0",
                    "-v12k",
                    &format!("{stem}.rar"),
                    "rand.bin",
                ])
                .current_dir(&work),
        )
        .unwrap();
        assert_eq!(
            run.status.code(),
            Some(0),
            "{stem}: the volume set was not written"
        );
    }

    let ours_sizes = volumes("arc");
    let reference_sizes = volumes("ref");
    assert!(
        ours_sizes.iter().all(|size| *size <= 12288),
        "a volume passed the 12,288 bytes the command line asked for: {ours_sizes:?}"
    );
    assert_eq!(
        ours_sizes.len(),
        reference_sizes.len(),
        "a different volume count from the reference's: ours {ours_sizes:?}, \
         the reference's {reference_sizes:?}"
    );

    // And the REFERENCE reads what we wrote, back to the file that went in.
    let extracted = work.join("out");
    let test = output_of(
        Command::new(&reference)
            .args(["x", "-y", "arc.part1.rar", "out/"])
            .current_dir(&work),
    )
    .unwrap();
    assert_eq!(
        test.status.code(),
        Some(0),
        "the reference refused our volume set:\n{}\n{}",
        String::from_utf8_lossy(&test.stdout),
        String::from_utf8_lossy(&test.stderr)
    );
    assert_eq!(
        std::fs::read(extracted.join("rand.bin")).unwrap(),
        std::fs::read(work.join("rand.bin")).unwrap(),
        "the volume set did not extract to the bytes that went in"
    );
    let _ = std::fs::remove_dir_all(&work);
}

/// The drop-in claim outside stored mode: whatever `rarfast` writes, the
/// REFERENCE reads it back to the bytes that went in.
///
/// This is what replaces byte identity where an encoder chooses, where a
/// salt is drawn, and where a parity block is built - and it is the
/// stronger of the two checks for those shapes, because an archive can
/// be byte-identical to nothing in particular and still be wrong.
fn reference_extracts_what_we_wrote(row: &str, create: &[&str], extract: &[&str]) {
    let Some(reference) = reference() else {
        println!("{row}: not measured, no `{REFERENCE}` on PATH");
        return;
    };
    let ours = PathBuf::from(env!("CARGO_BIN_EXE_rarfast"));
    let work = std::env::temp_dir().join(format!(
        "rarfast-cross-{}-{}",
        std::process::id(),
        safe(row)
    ));
    let _ = std::fs::remove_dir_all(&work);
    build_payload(&work);
    let written = output_of(Command::new(&ours).args(create).current_dir(&work)).unwrap();
    assert_eq!(
        written.status.code(),
        Some(0),
        "{row}: we did not write it\n{}\n{}",
        String::from_utf8_lossy(&written.stdout),
        String::from_utf8_lossy(&written.stderr)
    );
    let read = output_of(Command::new(&reference).args(extract).current_dir(&work)).unwrap();
    assert_eq!(
        read.status.code(),
        Some(0),
        "{row}: the reference refused what we wrote\n{}\n{}",
        String::from_utf8_lossy(&read.stdout),
        String::from_utf8_lossy(&read.stderr)
    );
    for name in ["text.txt", "rand.bin"] {
        let source = work.join(name);
        let out = work.join("out").join(name);
        if source.is_file() && out.is_file() {
            assert_eq!(
                std::fs::read(&out).unwrap(),
                std::fs::read(&source).unwrap(),
                "{row}: {name} did not come back"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn every_compression_level_round_trips_through_the_reference() {
    for level in ["-m1", "-m2", "-m3", "-m4", "-m5"] {
        reference_extracts_what_we_wrote(
            &format!("roundtrip{level}"),
            &["a", "-y", level, "arc.rar", "text.txt", "rand.bin"],
            &["x", "-y", "arc.rar", "out/"],
        );
    }
}

#[test]
fn a_solid_archive_round_trips_through_the_reference() {
    reference_extracts_what_we_wrote(
        "roundtrip-solid",
        &["a", "-y", "-m3", "-s", "arc.rar", "text.txt", "rand.bin"],
        &["x", "-y", "arc.rar", "out/"],
    );
}

#[test]
fn an_encrypted_archive_round_trips_through_the_reference() {
    reference_extracts_what_we_wrote(
        "roundtrip-encrypted",
        &[
            "a", "-y", "-m0", "-pswpass", "arc.rar", "text.txt", "rand.bin",
        ],
        &["x", "-y", "-pswpass", "arc.rar", "out/"],
    );
}

#[test]
fn a_header_encrypted_archive_round_trips_through_the_reference() {
    reference_extracts_what_we_wrote(
        "roundtrip-header-encrypted",
        &[
            "a",
            "-y",
            "-m0",
            "-hpswpass",
            "arc.rar",
            "text.txt",
            "rand.bin",
        ],
        &["x", "-y", "-hpswpass", "arc.rar", "out/"],
    );
}

#[test]
fn a_recovery_record_archive_round_trips_through_the_reference() {
    reference_extracts_what_we_wrote(
        "roundtrip-recovery",
        &["a", "-y", "-m0", "-rr5", "arc.rar", "text.txt"],
        &["x", "-y", "arc.rar", "out/"],
    );
}

#[test]
fn a_blake2_archive_round_trips_through_the_reference() {
    reference_extracts_what_we_wrote(
        "roundtrip-blake2",
        &["a", "-y", "-m3", "-htb", "arc.rar", "text.txt", "rand.bin"],
        &["x", "-y", "arc.rar", "out/"],
    );
}

#[test]
fn a_dictionary_choice_round_trips_through_the_reference() {
    reference_extracts_what_we_wrote(
        "roundtrip-dictionary",
        &["a", "-y", "-m3", "-md1m", "arc.rar", "text.txt"],
        &["x", "-y", "arc.rar", "out/"],
    );
}

#[test]
fn add_compressed_extracts_to_the_same_bytes() {
    // NOT byte identity: rarkit's encoder makes its own choices and the
    // spec's non-goals put the reference's ratio outside the claim. What
    // is compared is the OUTPUT and the exit code, and then that the
    // reference itself extracts what we wrote.
    for level in ["-m1", "-m2", "-m3", "-m4", "-m5"] {
        same_as_reference(
            &format!("add-level{level}"),
            &["a", "-y", level, "arc.rar", "text.txt"],
        );
    }
}

#[test]
fn freshen_with_nothing_to_freshen() {
    same_as_reference("freshen-absent", &["f", "-y", "arc.rar"]);
}

#[test]
fn an_unknown_rar4_switch_is_still_unknown() {
    same_as_reference(
        "add-rar4",
        &["a", "-y", "-m0", "-ma4", "arc.rar", "text.txt"],
    );
}

// --- the commands that read or rewrite an archive that exists ---------
//
// These need an archive in the tree first, so each builds one with the
// REFERENCE and then hands the same command line to both binaries.

/// [`same_as_reference`], with `setup` run by the reference first in both
/// trees so that the row starts from an archive the reference made.
fn same_after_setup(row: &str, setup: &[&str], args: &[&str]) {
    same_after_setup_with(row, setup, args, Damage::None);
}

/// [`same_after_setup`], with the archive's last member DAMAGED in between,
/// so that the row measures a run that fails.
fn same_after_damage(row: &str, setup: &[&str], args: &[&str]) {
    same_after_setup_with(row, setup, args, Damage::LastMemberData);
}

fn same_after_setup_with(row: &str, setup: &[&str], args: &[&str], damage: Damage) {
    let Some(reference) = reference() else {
        println!("{row}: not measured, no `{REFERENCE}` on PATH");
        return;
    };
    let ours = PathBuf::from(env!("CARGO_BIN_EXE_rarfast"));
    let theirs = run_after(
        &reference,
        &reference,
        setup,
        args,
        damage,
        &format!("{}-ref", safe(row)),
    );
    let mine = run_after(
        &reference,
        &ours,
        setup,
        args,
        damage,
        &format!("{}-ours", safe(row)),
    );
    compare(row, &mine, &theirs);
}

/// Whether a row damages the archive between the setup and the row.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Damage {
    /// The archive the setup wrote, untouched.
    None,
    /// The LAST member's data, flipped. A stored archive ends with it, so
    /// this leaves every header alone and the walk reaches the member
    /// before it notices: the reference answers `- checksum error` on
    /// stderr and exits 3, and so does rarfast.
    LastMemberData,
    /// The FIRST member's data, flipped, so the walk fails one member and
    /// then carries on to a good one.
    FirstMemberData,
    /// The MIDDLE volume of a multi-volume set, deleted outright rather
    /// than flipped in place - SPEC-API item 18's shape, and the only
    /// variant here whose setup must itself write a volume set (`-v10k`
    /// over `rand.bin` gives exactly three volumes for both `-m0` and
    /// `-m3`, measured 20 Sep 2026) rather than the single `arc.rar` the
    /// other variants damage.
    MissingMiddleVolume,
}

/// Damages `arc.rar` in `work` as `damage` says.
fn apply_damage(work: &Path, damage: Damage) {
    let path = work.join("arc.rar");
    match damage {
        Damage::None => {}
        Damage::MissingMiddleVolume => {
            let _ = std::fs::remove_file(work.join("arc.part2.rar"));
        }
        Damage::LastMemberData => {
            // The same damage `an_unselected_member_is_not_decoded_even_when
            // _its_bytes_are_damaged` uses, at the same offset, so the two
            // rows fail on the same shape when one of them fails.
            let mut bytes = std::fs::read(&path).unwrap();
            let at = bytes.len() - 600;
            for byte in &mut bytes[at..at + 64] {
                *byte ^= 0xff;
            }
            std::fs::write(&path, &bytes).unwrap();
        }
        Damage::FirstMemberData => {
            // A stored archive carries `text.txt` verbatim, so its first
            // line is findable, and flipping inside it leaves every header
            // alone.
            let mut bytes = std::fs::read(&path).unwrap();
            let needle = b"conformance line 0000";
            let at = bytes
                .windows(needle.len())
                .position(|w| w == needle)
                .unwrap();
            for byte in &mut bytes[at..at + 16] {
                *byte ^= 0xff;
            }
            std::fs::write(&path, &bytes).unwrap();
        }
    }
}

/// Builds the tree with `builder`, then runs `binary` over `args` in it.
fn run_after(
    builder: &Path,
    binary: &Path,
    setup: &[&str],
    args: &[&str],
    damage: Damage,
    tag: &str,
) -> Run {
    let work = std::env::temp_dir().join(format!("rarfast-after-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    build_payload(&work);
    let built = output_of(Command::new(builder).args(setup).current_dir(&work)).unwrap();
    assert!(built.status.success(), "the setup for {tag} failed");
    apply_damage(&work, damage);
    freeze(&work);
    let output = output_of(Command::new(binary).args(args).current_dir(&work)).unwrap();
    let run = Run {
        stdout: normalise(&String::from_utf8_lossy(&output.stdout), &work),
        stderr: normalise(&String::from_utf8_lossy(&output.stderr), &work),
        exit: output.status.code().unwrap_or(-1),
        files: fingerprint(&work),
    };
    let _ = std::fs::remove_dir_all(&work);
    run
}

/// The archive every row below starts from.
const STORED: &[&str] = &["a", "-y", "-idq", "-m0", "arc.rar", "text.txt", "rand.bin"];

#[test]
fn comment_write_with_no_comment() {
    same_after_setup("comment-write", STORED, &["cw", "-y", "arc.rar", "out.txt"]);
}

#[test]
fn comment_write_with_a_comment() {
    same_after_setup(
        "comment-write-present",
        &[
            "a",
            "-y",
            "-idq",
            "-m0",
            "-zcomment.txt",
            "arc.rar",
            "text.txt",
        ],
        &["cw", "-y", "arc.rar", "out.txt"],
    );
}

#[test]
fn change_parameters_leaves_the_archive_alone() {
    same_after_setup("change-parameters", STORED, &["ch", "-y", "-tk", "arc.rar"]);
}

// `rc` has no row here. Its answers where no recovery volume is found
// and where the named archive is no volume are no longer the reference's
// (SPEC-CLI 13.3 R8, a chosen difference: never exit 0), and the whole
// command is held in `tests/rc_restore.rs`.

/// `rv` over a REAL volume set WRITES the recovery volumes, and they are
/// the reference's own bytes.
///
/// This is the strongest row in the file. Both binaries are given the
/// SAME volume set - built once and copied, so the data volumes and
/// therefore their CRC32s are identical - and the `.rev` files they
/// produce are compared byte for byte. SPEC-L 3.6.1 says what those bytes
/// are and this says the specification was read right.
#[test]
fn recovery_volumes_over_a_volume_set_are_the_references_own_bytes() {
    let Some(reference) = reference() else {
        println!("recovery volumes: not measured, no `{REFERENCE}` on PATH");
        return;
    };
    let ours = PathBuf::from(env!("CARGO_BIN_EXE_rarfast"));
    for count in ["rv1", "rv2", "rv3"] {
        let source =
            std::env::temp_dir().join(format!("rarfast-rvsrc-{}-{count}", std::process::id()));
        let _ = std::fs::remove_dir_all(&source);
        build_payload(&source);
        assert!(status_of(
            Command::new(&reference)
                .args(["a", "-y", "-idq", "-m0", "-v12k", "arc.rar", "rand.bin"])
                .current_dir(&source)
        )
        .unwrap()
        .success());

        let mut trees = Vec::new();
        for (tag, binary) in [("ref", &reference), ("ours", &ours)] {
            let work = std::env::temp_dir()
                .join(format!("rarfast-rv-{}-{count}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&work);
            std::fs::create_dir_all(&work).unwrap();
            // The same volume set for both, so a difference in the `.rev`
            // files is a difference in the WRITER and nothing else.
            for entry in std::fs::read_dir(&source).unwrap().flatten() {
                let name = entry.file_name();
                if name.to_string_lossy().ends_with(".rar") {
                    std::fs::copy(entry.path(), work.join(&name)).unwrap();
                }
            }
            let first = lowest_volume(&work);
            let run = output_of(
                Command::new(binary)
                    .args([count, "-y", &first])
                    .current_dir(&work),
            )
            .unwrap();
            assert_eq!(
                run.status.code(),
                Some(0),
                "{count} ({tag}) exited {:?}\n{}",
                run.status.code(),
                String::from_utf8_lossy(&run.stderr)
            );
            trees.push((
                normalise(&String::from_utf8_lossy(&run.stdout), &work),
                fingerprint(&work),
                work,
            ));
        }
        let (their_out, their_files, their_work) = &trees[0];
        let (our_out, our_files, our_work) = &trees[1];
        assert_eq!(
            our_out, their_out,
            "{count}: stdout\n--- ours ---\n{our_out}\n--- reference ---\n{their_out}"
        );
        assert_eq!(
            our_files, their_files,
            "{count}: the `.rev` files are not the reference's bytes"
        );
        let _ = std::fs::remove_dir_all(our_work);
        let _ = std::fs::remove_dir_all(their_work);
        let _ = std::fs::remove_dir_all(&source);
    }
}

/// The `.rar` name in `work` that sorts lowest: where the set there begins.
fn lowest_volume(work: &Path) -> String {
    let mut names: Vec<String> = std::fs::read_dir(work)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".rar"))
        .collect();
    names.sort();
    names.first().cloned().expect("a volume set")
}

/// The three rows the member-level rewrite lacked
/// (`crates/rarkit-cli/README.md` section 4).
#[test]
fn delete_member() {
    same_after_setup("delete-member", STORED, &["d", "-y", "arc.rar", "text.txt"]);
}

#[test]
fn delete_member_matching_nothing() {
    same_after_setup(
        "delete-member-absent",
        STORED,
        &["d", "-y", "arc.rar", "nosuch.txt"],
    );
}

#[test]
fn rename_member() {
    same_after_setup(
        "rename-member",
        STORED,
        &["rn", "-y", "arc.rar", "text.txt", "renamed.txt"],
    );
}

#[test]
fn add_recovery_record_later() {
    same_after_setup(
        "add-recovery-record-later",
        STORED,
        &["rr5", "-y", "arc.rar"],
    );
}

/// **Byte identity where the rewrite reaches it.**
///
/// `same_after_setup` compares the file tree by NAME; this compares the
/// archive's BYTES. `k` and `d` re-emit every member in the rewrite form
/// of spec G 3.6.5 and rebuild the quick-open index, and the result is
/// the reference's own file. The rows that are NOT here are the measured
/// differences, each written down in the README rather than reshaped
/// around: `rn`, where the reference re-emits in the CREATE form and
/// contradicts its own rewrite rule, and `c` and `rr`, where the
/// reference pads a service block's size fields and rarkit writes them
/// naturally as it does when it creates one.
#[test]
fn a_rewrite_is_the_references_own_bytes() {
    let Some(reference) = reference() else {
        println!("rewrite bytes: not measured, no `{REFERENCE}` on PATH");
        return;
    };
    let ours = PathBuf::from(env!("CARGO_BIN_EXE_rarfast"));
    for (row, args) in [
        ("lock", vec!["k", "-y", "arc.rar"]),
        ("delete-member", vec!["d", "-y", "arc.rar", "text.txt"]),
    ] {
        let theirs = run_after(
            &reference,
            &reference,
            STORED,
            &args,
            Damage::None,
            &format!("{}-bytes-ref", safe(row)),
        );
        let mine = run_after(
            &reference,
            &ours,
            STORED,
            &args,
            Damage::None,
            &format!("{}-bytes-ours", safe(row)),
        );
        assert_eq!(
            mine.files, theirs.files,
            "{row}: the rewritten archive is not the reference's bytes"
        );
    }
}

#[test]
fn recovery_volumes_over_something_that_is_not_a_volume_set() {
    same_after_setup("recovery-volumes-plain", STORED, &["rv1", "-y", "arc.rar"]);
}

#[test]
fn stripping_a_module_from_an_archive_that_has_none() {
    same_after_setup("sfx-unconvert", STORED, &["s-", "-y", "arc.rar"]);
}

#[test]
fn update_over_an_archive_with_nothing_to_update() {
    same_after_setup("update", STORED, &["u", "-y", "arc.rar", "nosuch/text.txt"]);
}

#[test]
fn freshen_over_an_archive_whose_members_are_gone() {
    same_after_setup("freshen", STORED, &["f", "-y", "arc.rar", "nosuch.txt"]);
}

/// `k` locks the archive, and the LOCK is what the next command must
/// see. The archive's own bytes are not compared: rarkit's rewrite drops
/// the quick-open index the reference keeps, which the crate README
/// records as not done.
#[test]
fn a_locked_archive_refuses_the_next_command() {
    let Some(reference) = reference() else {
        println!("locked archive: not measured, no `{REFERENCE}` on PATH");
        return;
    };
    let ours = PathBuf::from(env!("CARGO_BIN_EXE_rarfast"));
    let work = std::env::temp_dir().join(format!("rarfast-lock-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    build_payload(&work);
    assert!(
        status_of(Command::new(&reference).args(STORED).current_dir(&work))
            .unwrap()
            .success()
    );

    let locked = output_of(
        Command::new(&ours)
            .args(["k", "-y", "arc.rar"])
            .current_dir(&work),
    )
    .unwrap();
    assert_eq!(locked.status.code(), Some(0), "`k` did not lock it");
    assert_eq!(
        normalise(&String::from_utf8_lossy(&locked.stdout), &work),
        "Processing archive arc.rar\nLocking archive\nDone",
        "the reference's own two lines, measured"
    );

    // The reference agrees it is locked, which is the only way to know
    // the flag went in rather than the message coming out.
    let theirs = output_of(
        Command::new(&reference)
            .args(["d", "-y", "arc.rar", "text.txt"])
            .current_dir(&work),
    )
    .unwrap();
    assert_eq!(theirs.status.code(), Some(4), "the reference read no lock");

    let mine = output_of(
        Command::new(&ours)
            .args(["d", "-y", "arc.rar", "text.txt"])
            .current_dir(&work),
    )
    .unwrap();
    assert_eq!(
        mine.status.code(),
        Some(4),
        "we did not refuse the locked archive"
    );
    assert_eq!(
        normalise(&String::from_utf8_lossy(&mine.stdout), &work),
        normalise(&String::from_utf8_lossy(&theirs.stdout), &work)
    );
    assert_eq!(
        normalise(&String::from_utf8_lossy(&mine.stderr), &work),
        normalise(&String::from_utf8_lossy(&theirs.stderr), &work)
    );
    let _ = std::fs::remove_dir_all(&work);
}

/// The comment `c` sets is the one the REFERENCE reads back, which is
/// the check that matters: the archive's bytes are rarkit's rewrite and
/// not the reference's.
#[test]
fn a_comment_set_here_is_read_back_by_the_reference() {
    let Some(reference) = reference() else {
        println!("comment read back: not measured, no `{REFERENCE}` on PATH");
        return;
    };
    let ours = PathBuf::from(env!("CARGO_BIN_EXE_rarfast"));
    let work = std::env::temp_dir().join(format!("rarfast-comment-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    build_payload(&work);
    assert!(
        status_of(Command::new(&reference).args(STORED).current_dir(&work))
            .unwrap()
            .success()
    );
    let set = output_of(
        Command::new(&ours)
            .args(["c", "-y", "-zcomment.txt", "arc.rar"])
            .current_dir(&work),
    )
    .unwrap();
    assert_eq!(set.status.code(), Some(0), "`c` failed");
    let read = output_of(
        Command::new(&reference)
            .args(["cw", "-y", "arc.rar", "back.txt"])
            .current_dir(&work),
    )
    .unwrap();
    assert_eq!(read.status.code(), Some(0));
    assert_eq!(
        std::fs::read(work.join("back.txt")).unwrap(),
        std::fs::read(work.join("comment.txt")).unwrap(),
        "the reference read a different comment back"
    );
    let _ = std::fs::remove_dir_all(&work);
}

/// Every refusal: a non-zero code, and the archive untouched.
///
/// This is the property spec R.2 is about, and it is the one thing a
/// refusal must never get wrong - an exit 0 over an archive that was
/// quietly changed is worse than any missing feature.
#[test]
fn every_refusal_leaves_the_archive_exactly_as_it_was() {
    let Some(reference) = reference() else {
        println!("refusals leave the archive: not measured, no `{REFERENCE}` on PATH");
        return;
    };
    let ours = PathBuf::from(env!("CARGO_BIN_EXE_rarfast"));
    for args in [
        // `d`, `rn` and `rr5` are no longer here: the member-level
        // rewrite landed and each has a row of its own below.
        vec!["s", "-y", "arc.rar"],
        vec!["a", "-y", "-m0", "arc.rar", "zero.bin"],
        vec!["a", "-y", "-m0", "-as", "arc2.rar", "text.txt"],
        vec!["a", "-y", "-m0", "-ep3", "arc2.rar", "text.txt"],
        vec!["a", "-y", "-m0", "-sfxmod", "arc2.rar", "text.txt"],
    ]
    .into_iter()
    // `-ep3` is honoured on a unix host (source_path_names.rs) and
    // refused only elsewhere.
    .filter(|args| cfg!(not(unix)) || !args.contains(&"-ep3"))
    {
        let work = std::env::temp_dir().join(format!(
            "rarfast-refuse-{}-{}",
            std::process::id(),
            safe(&args.join("-"))
        ));
        let _ = std::fs::remove_dir_all(&work);
        build_payload(&work);
        assert!(
            status_of(Command::new(&reference).args(STORED).current_dir(&work))
                .unwrap()
                .success()
        );
        let before = std::fs::read(work.join("arc.rar")).unwrap();
        let run = output_of(Command::new(&ours).args(&args).current_dir(&work)).unwrap();
        assert_ne!(
            run.status.code(),
            Some(0),
            "{args:?} reported success it cannot have earned"
        );
        assert_eq!(
            std::fs::read(work.join("arc.rar")).unwrap(),
            before,
            "{args:?} changed the archive it refused"
        );
        assert!(
            !work.join("arc2.rar").exists(),
            "{args:?} left an archive behind"
        );
        assert!(
            !String::from_utf8_lossy(&run.stderr).is_empty(),
            "{args:?} refused without saying so"
        );
        let _ = std::fs::remove_dir_all(&work);
    }
}

/// An UNSELECTED member of a non-solid archive is never decoded.
///
/// Timing would say so too - 96 MiB in eight members extracts in 0.19 s
/// whole and 0.02 s for one of them, measured 19 Sep 2026 - but a clock
/// is a flaky thing to assert on a shared box, so what is pinned here is
/// the behaviour that makes the speed possible: a member whose DATA is
/// corrupt raises nothing at all when it was not asked for. A run that
/// decoded it would find the damage and say so.
///
/// This is the `skip_unselected` the crate README listed as missing. It needed
/// `Disposition::Skip` to mean "do not decode a non-solid member at
/// all", which it now does; the call site was already here.
#[test]
fn an_unselected_member_is_not_decoded_even_when_its_bytes_are_damaged() {
    let Some(reference) = reference() else {
        println!("unselected damaged member: not measured, no `{REFERENCE}` on PATH");
        return;
    };
    let ours = PathBuf::from(env!("CARGO_BIN_EXE_rarfast"));
    let work = std::env::temp_dir().join(format!("rarfast-skip-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    build_payload(&work);
    assert!(status_of(
        Command::new(&reference)
            .args(["a", "-y", "-idq", "-m0", "arc.rar", "text.txt", "rand.bin"])
            .current_dir(&work)
    )
    .unwrap()
    .success());

    // The tail of a stored archive is the LAST member's data, which is
    // `rand.bin`: damage it and leave every header alone.
    let path = work.join("arc.rar");
    let mut bytes = std::fs::read(&path).unwrap();
    let at = bytes.len() - 600;
    for byte in &mut bytes[at..at + 64] {
        *byte ^= 0xff;
    }
    std::fs::write(&path, &bytes).unwrap();

    // The damage is real: asking for the damaged member finds it.
    let whole = output_of(
        Command::new(&ours)
            .args(["t", "arc.rar"])
            .current_dir(&work),
    )
    .unwrap();
    assert_ne!(
        whole.status.code(),
        Some(0),
        "the archive was not damaged, so this row proves nothing"
    );

    // And asking for the OTHER member does not, because the damaged one
    // is never decoded.
    for (who, binary) in [("reference", &reference), ("ours", &ours)] {
        let one = output_of(
            Command::new(binary)
                .args(["x", "-y", "arc.rar", "text.txt", "out/"])
                .current_dir(&work),
        )
        .unwrap();
        assert_eq!(
            one.status.code(),
            Some(0),
            "{who} decoded a member it was not asked for\n{}\n{}",
            String::from_utf8_lossy(&one.stdout),
            String::from_utf8_lossy(&one.stderr)
        );
        let _ = std::fs::remove_dir_all(work.join("out"));
    }
    let _ = std::fs::remove_dir_all(&work);
}

// --- `-idq` on the READ-ONLY commands ---------------------------------
//
// `-idq` asks for a quiet run and what it silences is the STDOUT STREAM,
// not one command's output: the whole table below was measured against
// `rar` / `unrar` 7.23 on 19 Sep 2026 and the rows are it. Two of them
// carry the shape. The DAMAGED archive keeps its stderr, so a quiet
// switch may never swallow a failure; and `p` writes the member's bytes
// to stdout, which are payload and not a message, so they survive.
//
// Before this, `Out::new` passed `quiet: false` and every read-only
// command of both dialects ignored the switch outright.

/// The `unrar` half of every row below.
///
/// The dialect is chosen by `argv[0]`, so this leg runs `rarfast` through
/// a symlink named `unrar` and measures it against the `unrar` binary,
/// which is a different reference from the `rar` one the rest of this
/// file uses. Without it the `unrar` dialect's own `-idq` would be pinned
/// only by inference from the `rar` leg.
const UNRAR: &str = "unrar";

/// Where the `unrar` reference lives, or `None` when it is not on this box.
fn unrar_reference() -> Option<PathBuf> {
    let output = output_of(Command::new("which").arg(UNRAR)).ok()?;
    if !output.status.success() {
        return None;
    }
    let path = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim().to_owned());
    path.is_file().then_some(path)
}

/// `rarfast` under the name `unrar`, which is the whole of how the binary
/// picks that dialect.
///
/// A COPY and not a symlink, for two reasons: `std::os::unix` does not
/// exist on the Windows target `make cross` type-checks, and a copy is
/// what the crate's own first paragraph offers beside a symlink. Each row
/// makes its own and removes it, the way each row makes its own tree.
fn ours_as_unrar(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-asunrar-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let named = dir.join(UNRAR);
    copy_executable(Path::new(env!("CARGO_BIN_EXE_rarfast")), &named);
    named
}

/// [`same_after_setup`], on the `unrar` leg: the archive is still built by
/// `rar`, and the row itself is handed to `unrar` and to `rarfast` under
/// that name.
fn same_after_setup_as_unrar(row: &str, setup: &[&str], args: &[&str]) {
    same_after_setup_as_unrar_with(row, setup, args, Damage::None);
}

/// [`same_after_damage`], on the `unrar` leg.
fn same_after_damage_as_unrar(row: &str, setup: &[&str], args: &[&str]) {
    same_after_setup_as_unrar_with(row, setup, args, Damage::LastMemberData);
}

fn same_after_setup_as_unrar_with(row: &str, setup: &[&str], args: &[&str], damage: Damage) {
    let (Some(builder), Some(reference)) = (reference(), unrar_reference()) else {
        println!("{row}: not measured, it needs `{REFERENCE}` and `{UNRAR}` both on PATH");
        return;
    };
    let ours = ours_as_unrar(&safe(row));
    let theirs = run_after(
        &builder,
        &reference,
        setup,
        args,
        damage,
        &format!("{}-uref", safe(row)),
    );
    let mine = run_after(
        &builder,
        &ours,
        setup,
        args,
        damage,
        &format!("{}-uours", safe(row)),
    );
    let _ = std::fs::remove_dir_all(ours.parent().unwrap());
    compare(row, &mine, &theirs);
}

/// `unrar`'s leg of [`same_as_reference`], for a row that needs no archive.
fn same_as_unrar(row: &str, args: &[&str]) {
    let Some(reference) = unrar_reference() else {
        println!("{row}: not measured, no `{UNRAR}` on PATH");
        return;
    };
    let ours = ours_as_unrar(&safe(row));
    let theirs = run_in_copy(&reference, args, &format!("{}-uref", safe(row)));
    let mine = run_in_copy(&ours, args, &format!("{}-uours", safe(row)));
    let _ = std::fs::remove_dir_all(ours.parent().unwrap());
    compare(row, &mine, &theirs);
}

#[test]
fn list_quiet_prints_nothing() {
    same_after_setup("list-idq", STORED, &["l", "-idq", "arc.rar"]);
}

#[test]
fn list_quiet_prints_nothing_as_unrar() {
    same_after_setup_as_unrar("list-idq-unrar", STORED, &["l", "-idq", "arc.rar"]);
}

#[test]
fn bare_list_quiet_prints_nothing() {
    same_after_setup("list-bare-idq", STORED, &["lb", "-idq", "arc.rar"]);
}

#[test]
fn bare_list_quiet_prints_nothing_as_unrar() {
    same_after_setup_as_unrar("list-bare-idq-unrar", STORED, &["lb", "-idq", "arc.rar"]);
}

#[test]
fn technical_list_quiet_prints_nothing() {
    same_after_setup("list-technical-idq", STORED, &["lt", "-idq", "arc.rar"]);
}

#[test]
fn test_quiet_prints_nothing() {
    same_after_setup("test-idq", STORED, &["t", "-idq", "arc.rar"]);
}

#[test]
fn test_quiet_prints_nothing_as_unrar() {
    same_after_setup_as_unrar("test-idq-unrar", STORED, &["t", "-idq", "arc.rar"]);
}

#[test]
fn extract_quiet_prints_nothing() {
    same_after_setup(
        "extract-idq",
        STORED,
        &["x", "-y", "-idq", "arc.rar", "out/"],
    );
}

/// The row the whole shape turns on: a quiet run that FAILS still says so.
///
/// `-idq` empties stdout and leaves stderr alone, which is why `Out::warn`
/// does not read the flag. A quiet switch that swallowed this line would
/// send a caller away believing the archive was sound.
#[test]
fn test_quiet_still_reports_a_damaged_member() {
    same_after_damage("test-idq-damaged", STORED, &["t", "-idq", "arc.rar"]);
}

#[test]
fn test_quiet_still_reports_a_damaged_member_as_unrar() {
    same_after_damage_as_unrar("test-idq-damaged-unrar", STORED, &["t", "-idq", "arc.rar"]);
}

/// SPEC-API item 18: `-kb` over a member whose CONTINUATION VOLUME is
/// missing, as against one whose bytes are present but wrong. The setup
/// writes a three-volume `rand.bin` (`-v10k` gives exactly three volumes
/// for both `-m0` and `-m3`, measured 20 Sep 2026) and [`Damage::
/// MissingMiddleVolume`] deletes the middle one before the row runs;
/// `compare` checks stdout, stderr, exit code and which files exist
/// afterward, which is enough to pin the message shape and the keep/drop
/// choice `-kb` makes. The stronger claim - that a KEPT file is the exact
/// byte count the reference produced before the gap - is
/// [`kept_size_past_a_missing_volume_matches_the_reference_stored`] below;
/// it needs its own scaffolding because `compare` reads file names only.
///
/// These rows extract into `out/`, where the member's name is FREE (10 Oct
/// 2026). Until then they extracted over the source `rand.bin` itself, a
/// TAKEN name, and there rarfast now differs from the reference by rule:
/// SPEC-CLI 9.4 W7 leaves the file that stood at the name as it was after
/// a failed replace, where the reference loses it (9.3 O14). That
/// difference has its own rows in `tests/output_path_section9.rs`; what
/// these rows measure, the words and what `-kb` keeps of a member that
/// stops at a missing volume, is W9's and is the reference's still.
#[test]
fn extract_keeps_a_member_past_a_missing_volume_with_kb_stored() {
    same_after_setup_with(
        "extract-kb-missing-volume-stored",
        &["a", "-y", "-idq", "-m0", "-v10k", "arc.rar", "rand.bin"],
        &["x", "-y", "-kb", "arc.part1.rar", "out/"],
        Damage::MissingMiddleVolume,
    );
}

#[test]
fn extract_drops_a_member_past_a_missing_volume_without_kb_stored() {
    same_after_setup_with(
        "extract-no-kb-missing-volume-stored",
        &["a", "-y", "-idq", "-m0", "-v10k", "arc.rar", "rand.bin"],
        &["x", "-y", "arc.part1.rar", "out/"],
        Damage::MissingMiddleVolume,
    );
}

#[test]
fn extract_keeps_a_member_past_a_missing_volume_with_kb_compressed() {
    same_after_setup_with(
        "extract-kb-missing-volume-compressed",
        &["a", "-y", "-idq", "-m3", "-v10k", "arc.rar", "rand.bin"],
        &["x", "-y", "-kb", "arc.part1.rar", "out/"],
        Damage::MissingMiddleVolume,
    );
}

#[test]
fn extract_drops_a_member_past_a_missing_volume_without_kb_compressed() {
    same_after_setup_with(
        "extract-no-kb-missing-volume-compressed",
        &["a", "-y", "-idq", "-m3", "-v10k", "arc.rar", "rand.bin"],
        &["x", "-y", "arc.part1.rar", "out/"],
        Damage::MissingMiddleVolume,
    );
}

/// Builds the tree with `builder`, deletes the set's middle volume, runs
/// `binary` over `args`, and returns the size of `rand.bin` afterward, or
/// `None` when the run kept nothing.
fn kept_member_size(
    builder: &Path,
    binary: &Path,
    setup: &[&str],
    args: &[&str],
    tag: &str,
) -> Option<u64> {
    let work = std::env::temp_dir().join(format!("rarfast-kept-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    build_payload(&work);
    let built = output_of(Command::new(builder).args(setup).current_dir(&work)).unwrap();
    assert!(built.status.success(), "the setup for {tag} failed");
    apply_damage(&work, Damage::MissingMiddleVolume);
    freeze(&work);
    let _ = output_of(Command::new(binary).args(args).current_dir(&work)).unwrap();
    let size = std::fs::metadata(work.join("out").join("rand.bin"))
        .ok()
        .map(|meta| meta.len());
    let _ = std::fs::remove_dir_all(&work);
    size
}

/// The stronger claim SPEC-API item 18's acceptance test makes for a
/// STORED member: the file `-kb` keeps past a missing volume is not just
/// present, it is exactly as long as the reference's own run left it
/// (measured 20 Sep 2026: both keep 10,035 of the 24,576-byte `rand.bin`
/// over this setup). A stored member is copied byte for byte, so there is
/// only one place a copy can stop, and rarkit's copy path already reaches
/// it: `crates/rarkit-cli/src/dialect/unrar/extract.rs`'s `-kb` site keeps
/// whatever `crates/rarkit/src/read/extract.rs`'s `emit` already wrote to
/// the sink before the fault, and a stored copy writes every byte it reads.
#[test]
fn kept_size_past_a_missing_volume_matches_the_reference_stored() {
    let Some(reference) = reference() else {
        println!("kept size, stored: not measured, no `{REFERENCE}` on PATH");
        return;
    };
    let ours = PathBuf::from(env!("CARGO_BIN_EXE_rarfast"));
    let setup: &[&str] = &["a", "-y", "-idq", "-m0", "-v10k", "arc.rar", "rand.bin"];
    let args: &[&str] = &["x", "-y", "-kb", "arc.part1.rar", "out/"];
    let reference_kept =
        kept_member_size(&reference, &reference, setup, args, "kb-size-stored-ref");
    let ours_kept = kept_member_size(&reference, &ours, setup, args, "kb-size-stored-ours");
    assert_eq!(
        ours_kept, reference_kept,
        "a stored member kept past a missing volume should be exactly as long \
         as the reference's own run left it"
    );
}

/// The same claim over a COMPRESSED member does NOT hold, and this pins
/// that rather than hiding it.
///
/// Measured 20 Sep 2026 over the same `-v10k` three-volume `rand.bin` at
/// `-m3`: the reference keeps 10,035 bytes with `-kb`; rarkit keeps NONE.
/// `crates/rarkit/src/read/rar5_lz.rs`'s decoder only reaches
/// `crates/rarkit/src/read/extract.rs`'s `emit` (and so the sink) at the
/// granularity its own window/wave flush works in, and the whole member
/// here sits inside the one flush the missing volume 2 never lets finish -
/// where the reference streams output as it decodes, at a finer grain.
/// This is NOT this item's site: the `-kb` fix keeps exactly what the
/// engine already wrote before the fault (the stored row above is proof of
/// that on the path where the two engines' grains agree), so nothing here
/// reshapes CLI code to chase the gap per the project's own rule against
/// it. **Not done yet (packages F, H2 and H3)**: stream a compressed member's
/// output at a finer grain so a truncated one keeps more than its last
/// completed flush.
#[test]
fn kept_size_past_a_missing_volume_never_exceeds_the_reference_compressed() {
    let Some(reference) = reference() else {
        println!("kept size, compressed: not measured, no `{REFERENCE}` on PATH");
        return;
    };
    let ours = PathBuf::from(env!("CARGO_BIN_EXE_rarfast"));
    let setup: &[&str] = &["a", "-y", "-idq", "-m3", "-v10k", "arc.rar", "rand.bin"];
    let args: &[&str] = &["x", "-y", "-kb", "arc.part1.rar", "out/"];
    let reference_kept = kept_member_size(
        &reference,
        &reference,
        setup,
        args,
        "kb-size-compressed-ref",
    )
    .unwrap_or(0);
    let ours_kept =
        kept_member_size(&reference, &ours, setup, args, "kb-size-compressed-ours").unwrap_or(0);
    assert!(
        ours_kept <= reference_kept,
        "rarkit kept MORE past a missing volume than the reference did: \
         {ours_kept} > {reference_kept}"
    );
}

/// The same property at the other end: an archive that is not there at all.
#[test]
fn extract_quiet_still_reports_a_missing_archive() {
    same_as_reference("extract-idq-missing", &["x", "-y", "-idq", "nosuch.rar"]);
}

#[test]
fn extract_quiet_still_reports_a_missing_archive_as_unrar() {
    same_as_unrar(
        "extract-idq-missing-unrar",
        &["x", "-y", "-idq", "nosuch.rar"],
    );
}

/// `-iver` is a MESSAGE, so it goes quiet with the rest of stdout.
///
/// Measured: `rar -iver` prints `7.23` and `rar -idq -iver` prints
/// nothing. It used to be a bare `println!` and so ignored the switch.
#[test]
fn the_version_is_a_message_and_goes_quiet_too() {
    same_as_reference("iver-idq", &["-idq", "-iver"]);
}

/// And `p`'s bytes are a PAYLOAD, so they do not.
#[test]
fn print_quiet_still_writes_the_member() {
    same_after_setup("print-idq", STORED, &["p", "-idq", "arc.rar", "text.txt"]);
}

#[test]
fn print_quiet_still_writes_the_member_as_unrar() {
    same_after_setup_as_unrar(
        "print-idq-unrar",
        STORED,
        &["p", "-idq", "arc.rar", "text.txt"],
    );
}

/// The same row again, on the RAW bytes and against the source file rather
/// than against the reference.
///
/// `same_after_setup` compares stdout after the harness's normalisation,
/// which trims a trailing blank line; this compares what came out of the
/// pipe with what went into the archive, byte for byte, so "the member
/// survives `-idq`" cannot pass on a normalisation.
#[test]
fn the_printed_member_is_the_source_bytes_under_idq() {
    let Some(reference) = reference() else {
        println!("printed member under -idq: not measured, no `{REFERENCE}` on PATH");
        return;
    };
    let ours = PathBuf::from(env!("CARGO_BIN_EXE_rarfast"));
    let work = std::env::temp_dir().join(format!("rarfast-print-idq-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    build_payload(&work);
    assert!(
        status_of(Command::new(&reference).args(STORED).current_dir(&work))
            .unwrap()
            .success()
    );
    let source = std::fs::read(work.join("text.txt")).unwrap();
    let printed = output_of(
        Command::new(&ours)
            .args(["p", "-idq", "arc.rar", "text.txt"])
            .current_dir(&work),
    )
    .unwrap();
    let _ = std::fs::remove_dir_all(&work);
    assert_eq!(printed.status.code(), Some(0), "print-idq-bytes: exit code");
    assert!(
        printed.stderr.is_empty(),
        "print-idq-bytes: stderr should be empty, got {:?}",
        String::from_utf8_lossy(&printed.stderr)
    );
    assert_eq!(
        printed.stdout.len(),
        source.len(),
        "print-idq-bytes: a message got into the payload"
    );
    assert_eq!(printed.stdout, source, "print-idq-bytes: the bytes");
}

// ---------------------------------------------------------------------
// `-idd`, `-idn`, `-idp` and `p`'s messages, on the RAW bytes.
//
// `normalise` strips backspaces, trims every line and turns each counter
// into a token, which is right for most rows and is exactly what would
// hide these: what `-idn` and `-idp` change is which of those pieces are
// there at all, and what `p` had wrong was two extra lines around a
// payload. So these rows compare the pipes byte for byte. `-idc` is on
// every one of them: the reference prints a copyright banner and rarfast
// prints none, and that is measured (section 5 of the README), not a
// difference to hide.
// ---------------------------------------------------------------------

/// What one run wrote, unprocessed.
struct RawRun {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit: i32,
}

/// [`run_after`] without the normalisation.
fn run_after_raw(
    builder: &Path,
    binary: &Path,
    setup: &[&str],
    args: &[&str],
    damage: Damage,
    tag: &str,
) -> RawRun {
    let work = std::env::temp_dir().join(format!("rarfast-raw-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    build_payload(&work);
    let built = output_of(Command::new(builder).args(setup).current_dir(&work)).unwrap();
    assert!(built.status.success(), "the setup for {tag} failed");
    apply_damage(&work, damage);
    freeze(&work);
    let output = output_of(Command::new(binary).args(args).current_dir(&work)).unwrap();
    let _ = std::fs::remove_dir_all(&work);
    RawRun {
        stdout: output.stdout,
        stderr: output.stderr,
        exit: output.status.code().unwrap_or(-1),
    }
}

/// One raw row, on the `rar` leg or the `unrar` leg.
fn raw_row(row: &str, damage: Damage, args: &[&str], as_unrar: bool) {
    let (Some(builder), Some(unrar)) = (reference(), unrar_reference()) else {
        println!("{row}: not measured, it needs `{REFERENCE}` and `{UNRAR}` both on PATH");
        return;
    };
    let (theirs_bin, ours_bin) = if as_unrar {
        (unrar, ours_as_unrar(&safe(row)))
    } else {
        (
            builder.clone(),
            PathBuf::from(env!("CARGO_BIN_EXE_rarfast")),
        )
    };
    let theirs = run_after_raw(
        &builder,
        &theirs_bin,
        STORED,
        args,
        damage,
        &format!("{}-ref", safe(row)),
    );
    let mine = run_after_raw(
        &builder,
        &ours_bin,
        STORED,
        args,
        damage,
        &format!("{}-ours", safe(row)),
    );
    if as_unrar {
        let _ = std::fs::remove_dir_all(ours_bin.parent().unwrap());
    }
    let show = |run: &RawRun| {
        format!(
            "stdout {:?} ({} bytes)\nstderr {:?}",
            String::from_utf8_lossy(&run.stdout[..run.stdout.len().min(400)]),
            run.stdout.len(),
            String::from_utf8_lossy(&run.stderr)
        )
    };
    assert!(
        mine.stdout == theirs.stdout,
        "{row}: stdout\n--- ours ---\n{}\n--- reference ---\n{}",
        show(&mine),
        show(&theirs)
    );
    assert!(
        mine.stderr == theirs.stderr,
        "{row}: stderr\n--- ours ---\n{}\n--- reference ---\n{}",
        show(&mine),
        show(&theirs)
    );
    assert_eq!(mine.exit, theirs.exit, "{row}: exit code");
}

/// Every row runs on both dialects: `rar`'s read path and `unrar`'s are
/// two front ends over one implementation, and a switch parsed by one and
/// dropped by the other is the exact shape of the defect being closed.
fn raw_both(row: &str, damage: Damage, args: &[&str]) {
    raw_row(row, damage, args, false);
    raw_row(&format!("{row}-unrar"), damage, args, true);
}

/// The listings compare NORMALISED, unlike the rows below: the reference
/// ends a `l`, `v` or `lt` on one more blank line than rarfast does, which
/// every listing row in this file trims and which is not matched yet
/// (README section 8), so a raw row would fail on that and not on `-id`.
fn listing_both(row: &str, args: &[&str]) {
    same_after_setup(row, STORED, args);
    same_after_setup_as_unrar(&format!("{row}-unrar"), STORED, args);
}

#[test]
fn hide_names_on_a_listing_keeps_the_header_and_the_totals() {
    listing_both("l-idn", &["l", "-idc", "-idn", "arc.rar"]);
    listing_both("v-idn", &["v", "-idc", "-idn", "arc.rar"]);
    listing_both("lb-idn", &["lb", "-idc", "-idn", "arc.rar"]);
}

#[test]
fn hide_names_on_a_technical_listing_keeps_only_the_header() {
    listing_both("lt-idn", &["lt", "-idc", "-idn", "arc.rar"]);
}

#[test]
fn hide_done_and_hide_percent_change_no_listing() {
    listing_both("l-idd-idp", &["l", "-idc", "-idd", "-idp", "arc.rar"]);
}

#[test]
fn hide_done_drops_the_verdict_of_extract_and_test() {
    raw_both(
        "x-idd",
        Damage::None,
        &["x", "-idc", "-idd", "-y", "arc.rar", "out/"],
    );
    raw_both("t-idd", Damage::None, &["t", "-idc", "-idd", "arc.rar"]);
    raw_both(
        "t-idd-damaged",
        Damage::LastMemberData,
        &["t", "-idc", "-idd", "arc.rar"],
    );
}

#[test]
fn hide_names_keeps_the_counter_and_drops_the_lines() {
    raw_both(
        "x-idn",
        Damage::None,
        &["x", "-idc", "-idn", "-y", "arc.rar", "out/"],
    );
    raw_both("t-idn", Damage::None, &["t", "-idc", "-idn", "arc.rar"]);
}

#[test]
fn hide_percent_keeps_the_lines_and_drops_the_counter() {
    raw_both(
        "x-idp",
        Damage::None,
        &["x", "-idc", "-idp", "-y", "arc.rar", "out/"],
    );
    raw_both("t-idp", Damage::None, &["t", "-idc", "-idp", "arc.rar"]);
}

#[test]
fn hiding_both_leaves_the_banner_and_the_verdict() {
    raw_both(
        "t-idn-idp",
        Damage::None,
        &["t", "-idc", "-idn", "-idp", "arc.rar"],
    );
    raw_both(
        "x-idd-idn-idp",
        Damage::None,
        &["x", "-idc", "-idd", "-idn", "-idp", "-y", "arc.rar", "out/"],
    );
}

/// A failing member ends its line, and where the newline goes depends on
/// whether the names are there and on whether the failure was first or
/// last. Both shapes, under each of the switches.
#[test]
fn the_hiding_switches_agree_when_a_member_fails() {
    for (damage, tag) in [
        (Damage::LastMemberData, "last"),
        (Damage::FirstMemberData, "first"),
    ] {
        raw_both(
            &format!("t-idp-{tag}-damaged"),
            damage,
            &["t", "-idc", "-idp", "arc.rar"],
        );
        raw_both(
            &format!("t-idn-{tag}-damaged"),
            damage,
            &["t", "-idc", "-idn", "arc.rar"],
        );
        raw_both(
            &format!("t-idn-idp-{tag}-damaged"),
            damage,
            &["t", "-idc", "-idn", "-idp", "arc.rar"],
        );
        raw_both(
            &format!("x-idn-{tag}-damaged"),
            damage,
            &["x", "-idc", "-idn", "-y", "arc.rar", "out/"],
        );
    }
}

/// The defect: `p` wrote its messages around the payload.
#[test]
fn print_writes_only_the_member_to_stdout() {
    raw_both(
        "print-payload",
        Damage::None,
        &["p", "-idc", "arc.rar", "text.txt"],
    );
    raw_both("print-payload-all", Damage::None, &["p", "-idc", "arc.rar"]);
}

/// The messages exist and go to stderr under `-ierr`, in `p`'s own shape.
#[test]
fn print_sends_its_messages_to_stderr_under_ierr() {
    raw_both(
        "print-ierr",
        Damage::None,
        &["p", "-idc", "-ierr", "arc.rar"],
    );
    raw_both(
        "print-ierr-idn",
        Damage::None,
        &["p", "-idc", "-ierr", "-idn", "arc.rar"],
    );
    raw_both(
        "print-ierr-idp",
        Damage::None,
        &["p", "-idc", "-ierr", "-idp", "arc.rar"],
    );
    raw_both(
        "print-ierr-idn-idp",
        Damage::None,
        &["p", "-idc", "-ierr", "-idn", "-idp", "arc.rar"],
    );
    raw_both(
        "print-ierr-idd",
        Damage::None,
        &["p", "-idc", "-ierr", "-idd", "arc.rar"],
    );
}

/// `p` does not stop at a bad member: it says so on stderr and exits 3,
/// and the payload is still written. rarfast used to exit 0 and say
/// nothing.
#[test]
fn print_reports_a_damaged_member() {
    for (damage, tag) in [
        (Damage::LastMemberData, "last"),
        (Damage::FirstMemberData, "first"),
    ] {
        raw_both(
            &format!("print-{tag}-damaged"),
            damage,
            &["p", "-idc", "arc.rar"],
        );
        raw_both(
            &format!("print-{tag}-damaged-idq"),
            damage,
            &["p", "-idc", "-idq", "arc.rar"],
        );
        raw_both(
            &format!("print-{tag}-damaged-inul"),
            damage,
            &["p", "-idc", "-inul", "arc.rar"],
        );
        raw_both(
            &format!("print-{tag}-damaged-idn"),
            damage,
            &["p", "-idc", "-idn", "arc.rar"],
        );
        raw_both(
            &format!("print-{tag}-damaged-ierr"),
            damage,
            &["p", "-idc", "-ierr", "arc.rar"],
        );
        raw_both(
            &format!("print-{tag}-damaged-ierr-idn-idp"),
            damage,
            &["p", "-idc", "-ierr", "-idn", "-idp", "arc.rar"],
        );
    }
}

/// Nothing matched: the reference says nothing on stdout, and under
/// `-ierr` says it on stderr.
#[test]
fn print_with_nothing_to_print() {
    raw_both(
        "print-nomatch",
        Damage::None,
        &["p", "-idc", "arc.rar", "nomatch.txt"],
    );
    raw_both(
        "print-nomatch-ierr",
        Damage::None,
        &["p", "-idc", "-ierr", "arc.rar", "nomatch.txt"],
    );
}

/// The banner names the archive even when nothing matched.
#[test]
fn nothing_matched_still_names_the_archive() {
    raw_both(
        "x-nomatch",
        Damage::None,
        &["x", "-idc", "-y", "arc.rar", "nomatch.txt"],
    );
    raw_both(
        "t-nomatch",
        Damage::None,
        &["t", "-idc", "arc.rar", "nomatch.txt"],
    );
    raw_both(
        "x-nomatch-idn",
        Damage::None,
        &["x", "-idc", "-idn", "-y", "arc.rar", "nomatch.txt"],
    );
}

/// A `lt` row over a FIXTURE ALREADY ON DISK rather than one this harness
/// builds, for the generations the reference alone can still write: `rar`
/// 7.23 no longer emits RAR 1.3, 1.5, 2.0 or 2.9/3.x/4.x archives, so the
/// only way to measure the technical listing over one is a committed
/// capture. Compared normalised, like [`listing_both`]: the reference
/// ends `lt` on one more blank line than rarfast does (README section 8).
///
/// This row started as the `Compression:` line alone,
/// was widened to the whole block once a directory's `CRC32:` line and a stored
/// member's `-md=` clause were fixed, except the `Host OS:` line and the
/// time label on the DOS-authored fixtures; and is widened to the WHOLE
/// block on every fixture by the change that
/// derives both lines from the host table `HostOs` holds.
fn technical_listing_of_fixture(row: &str, fixture: &str) {
    technical_listing_of(row, fixture, None);
}

/// [`technical_listing_of_fixture`] over a copy of a RAR 1.5 to 4.x
/// `fixture` whose every file header names `host` instead of the byte it
/// was written with, its header check value recomputed; nothing else in
/// the archive moves. The committed fixtures carry only DOS, Unix and the
/// RAR 1.3 container's absent host, so this is how the rows below reach
/// OS/2, Windows, Mac OS, BeOS, WinCE and an unnamed byte.
fn technical_listing_under_host(row: &str, fixture: &str, host: u8) {
    technical_listing_of(row, fixture, Some(host));
}

fn technical_listing_of(row: &str, fixture: &str, host: Option<u8>) {
    let Some(reference) = unrar_reference() else {
        println!("{row}: not measured, no `{UNRAR}` on PATH");
        return;
    };
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/legacy/archives");
    let mut bytes = std::fs::read(source.join(fixture)).unwrap();
    if let Some(host) = host {
        set_rar4_host(&mut bytes, host);
    }
    let ours = ours_as_unrar(&safe(row));
    let theirs = run_over_fixture(&reference, &bytes, fixture, &format!("{}-ref", safe(row)));
    let mine = run_over_fixture(&ours, &bytes, fixture, &format!("{}-ours", safe(row)));
    let _ = std::fs::remove_dir_all(ours.parent().unwrap());
    let mine = normalise(&mine, &PathBuf::new());
    let theirs = normalise(&theirs, &PathBuf::new());
    assert_eq!(
        mine, theirs,
        "{row}: stdout\n--- ours ---\n{mine}\n--- reference ---\n{theirs}"
    );
}

/// Rewrites the host byte of every file header in a RAR 1.5 to 4.x
/// archive and recomputes each one's 16 bit header check (the low half of
/// the CRC-32 over the header after the check field). The walk is the
/// block chain: seven marker bytes, then blocks of check (2), type (1),
/// flags (2) and header size (2), a file (0x74) or service (0x7A) block
/// followed by its packed data, whose size opens the header body, as is
/// any block's that sets flag 0x8000; the end block (0x7B) stops it.
fn set_rar4_host(bytes: &mut [u8], host: u8) {
    let mut at = 7;
    let mut patched = 0;
    while at + 7 <= bytes.len() {
        let kind = bytes[at + 2];
        let flags = u16::from_le_bytes([bytes[at + 3], bytes[at + 4]]);
        let size = usize::from(u16::from_le_bytes([bytes[at + 5], bytes[at + 6]]));
        let mut data = 0;
        if kind == 0x74 || kind == 0x7A || flags & 0x8000 != 0 {
            let word = &bytes[at + 7..at + 11];
            data = u32::from_le_bytes([word[0], word[1], word[2], word[3]]) as usize;
        }
        if kind == 0x74 {
            bytes[at + 15] = host;
            let check = rarkit::checksum::crc32(&bytes[at + 2..at + size]) as u16;
            bytes[at..at + 2].copy_from_slice(&check.to_le_bytes());
            patched += 1;
        }
        if kind == 0x7B || size == 0 {
            break;
        }
        at += size + data;
    }
    assert!(patched > 0, "no file header found to set the host of");
}

/// Runs `binary lt <fixture>` over `bytes` written as `fixture` in a
/// fresh directory, and returns its raw stdout.
fn run_over_fixture(binary: &Path, bytes: &[u8], fixture: &str, tag: &str) -> String {
    let work = std::env::temp_dir().join(format!(
        "rarfast-fixture-{}-{tag}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(work.join(fixture), bytes).unwrap();
    let output = output_of(
        Command::new(binary)
            .args(["lt", "-idc", fixture])
            .current_dir(&work),
    )
    .unwrap_or_else(|err| panic!("{} could not be run: {err}", binary.display()));
    let _ = std::fs::remove_dir_all(&work);
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// One fixture per format generation the repo has, plus a store-only
/// (`-m0`) member and a directory entry, which every fixture below
/// carries: this is the oracle comparison for the technical listing,
/// measured against `unrar` 7.23 directly rather than against a string
/// typed here (the
/// `Compression:` label, the
/// `Host OS:` line, the time label and the attributes). Between them they
/// carry the RAR 1.3 container's absent host, DOS and Unix.
#[test]
fn technical_listing_names_the_real_generation_rar13() {
    technical_listing_of_fixture("lt-fixture-rar13", "d140_m0.rar");
}

#[test]
fn technical_listing_names_the_real_generation_rar15() {
    technical_listing_of_fixture("lt-fixture-rar15", "d155_m0.rar");
}

#[test]
fn technical_listing_names_the_real_generation_rar20() {
    technical_listing_of_fixture("lt-fixture-rar20", "d250_m0.rar");
}

#[test]
fn technical_listing_names_the_real_generation_rar4family() {
    technical_listing_of_fixture("lt-fixture-rar4family", "r393_m3.rar");
}

/// One row per host byte the RAR 1.5 to 4.x family can carry, over copies
/// of `d250_m0.rar` (a DOS attribute word) and `r393_m0.rar` (a Unix mode
/// word) with only the host changed: the `Host OS:` line or its absence,
/// the `mtime` label and the attribute form, all from the one table
/// `HostOs` holds.
#[test]
fn technical_listing_follows_every_rar4_host_byte() {
    for host in 0..=7 {
        technical_listing_under_host(&format!("lt-host{host}-dos"), "d250_m0.rar", host);
        technical_listing_under_host(&format!("lt-host{host}-unix"), "r393_m0.rar", host);
    }
}
