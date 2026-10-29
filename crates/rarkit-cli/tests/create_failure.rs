//! What a FAILED create leaves on disk.
//!
//! Before 25 Sep 2026 the creator's failure arm removed the file named
//! `archive` and nothing else, a name re-derived after the fact rather
//! than one the run was known to have created. In volume mode the run
//! writes `arc.part1.rar`, `arc.part2.rar` ... (or `arc.rar`, `arc.r00`
//! ... under `-vn`, not reachable today), so a failed volume create left
//! every volume it had written behind, a partial set a user could take for a finished one:
//! the shape spec R.2 names. The cleanup now removes exactly the files
//! the run created, recorded as it created them.
//!
//! Two feared shapes are pinned here as UNREACHABLE rather than fixed:
//! a pre-existing `arc.rar` removed by a failed volume create of `arc`,
//! and an update of an existing archive that fails partway and takes the
//! original with it. Both are stopped earlier, by the creator's refusal
//! to add to an archive that already exists, which fires before any file
//! is opened for writing; these rows hold that refusal to it.
//!
//! The failure is forced without privileges: a DIRECTORY sits where a
//! later volume's file must go, so the run's own `File::create` of that
//! volume fails, deterministically, after earlier volumes are written.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// An empty directory of one test's own, made afresh under the system's
/// temporary directory; `tag` tells the tests of this file apart.
fn work(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("rarfast-create-fail-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Bytes a stored member cannot shrink, so the volume count is the payload
/// over the volume size.
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

/// Two 64 KiB sources, `one.bin` and `two.bin`.
fn sources(dir: &Path) {
    std::fs::write(dir.join("one.bin"), noise(64 << 10, 1)).unwrap();
    std::fs::write(dir.join("two.bin"), noise(64 << 10, 2)).unwrap();
}

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(rarfast())
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|err| panic!("rarfast could not be run: {err}"))
}

/// Every plain FILE in `dir`, sorted.
fn files_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_type()
                .map(|kind| kind.is_file())
                .unwrap_or(false)
        })
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// (b) A volume create that fails on its second volume removes the first,
/// which it wrote, and leaves the blocking directory, which it did not.
#[test]
fn a_failed_volume_create_removes_the_volumes_it_wrote() {
    let dir = work("numbered");
    sources(&dir);
    std::fs::create_dir(dir.join("arc.part2.rar")).unwrap();
    let out = run(
        &dir,
        &["a", "-y", "-m0", "-v20k", "arc", "one.bin", "two.bin"],
    );
    assert_ne!(
        out.status.code(),
        Some(0),
        "a failed create reported success"
    );
    assert_eq!(
        files_in(&dir),
        ["one.bin", "two.bin"],
        "the failed run left volumes behind; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        dir.join("arc.part2.rar").is_dir(),
        "the blocking directory went"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// (b) under `-vn`. Classic `.rNN` naming is refused under RAR 5 by the
/// writer before any volume is opened (measured on main 25 Sep 2026:
/// `WriteFeature("classic volume naming under RAR 5")`, exit 2), and the
/// CLI writes nothing else, `-ma4` being refused as rar 7.23 refuses it.
/// So this row pins that the refusal leaves nothing on disk; the tracked
/// cleanup covers the classic names too, should they become reachable.
#[test]
fn an_old_named_volume_create_leaves_nothing_behind() {
    let dir = work("classic");
    sources(&dir);
    std::fs::create_dir(dir.join("arc.r01")).unwrap();
    let out = run(
        &dir,
        &[
            "a", "-y", "-m0", "-v20k", "-vn", "arc", "one.bin", "two.bin",
        ],
    );
    assert_ne!(
        out.status.code(),
        Some(0),
        "a failed create reported success"
    );
    assert_eq!(
        files_in(&dir),
        ["one.bin", "two.bin"],
        "the refused run left files behind; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// (a) A pre-existing `arc.rar` survives, byte for byte, a volume create
/// of `arc` that would fail. Unreachable as a deletion: the run is refused
/// as an add to an existing archive before any volume is opened, so the
/// second volume's blocker is never reached either.
#[test]
fn a_failed_volume_create_never_touches_an_existing_arc_rar() {
    for extra in [&[][..], &["-vn"][..]] {
        let dir = work(&format!("existing{}", extra.len()));
        sources(&dir);
        let mine = noise(5000, 3);
        std::fs::write(dir.join("arc.rar"), &mine).unwrap();
        std::fs::create_dir(dir.join("arc.part2.rar")).unwrap();
        std::fs::create_dir(dir.join("arc.r00")).unwrap();
        let mut args = vec!["a", "-y", "-m0", "-v20k"];
        args.extend_from_slice(extra);
        args.extend_from_slice(&["arc", "one.bin", "two.bin"]);
        let out = run(&dir, &args);
        assert_ne!(out.status.code(), Some(0), "{args:?} reported success");
        assert_eq!(
            std::fs::read(dir.join("arc.rar")).unwrap(),
            mine,
            "{args:?} changed or removed the user's arc.rar"
        );
        assert_eq!(
            files_in(&dir),
            ["arc.rar", "one.bin", "two.bin"],
            "{args:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// (c) An update of an existing archive whose sources cannot all be read
/// leaves the original exactly as it was. Unreachable as a deletion for the
/// same reason as (a): an add to an existing archive is refused before
/// anything is written, whatever the command word.
#[test]
fn a_failing_update_leaves_the_original_archive() {
    for word in ["a", "u", "f", "m"] {
        let dir = work(&format!("update-{word}"));
        sources(&dir);
        let mine = noise(5000, 4);
        std::fs::write(dir.join("arc.rar"), &mine).unwrap();
        let out = run(
            &dir,
            &[word, "-y", "-m0", "arc.rar", "one.bin", "nosuch.bin"],
        );
        assert_ne!(out.status.code(), Some(0), "`{word}` reported success");
        assert_eq!(
            std::fs::read(dir.join("arc.rar")).unwrap(),
            mine,
            "`{word}` changed or removed the original archive"
        );
        assert!(dir.join("one.bin").is_file(), "`{word}` removed a source");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// A source of mode 000 is not a failed create any more: since 8 Oct 2026
/// it is left out and the rest is archived, as rar 7.23 does (measured
/// that day: `Cannot open two.bin`, `Permission denied`, `one.bin`
/// stored, exit 6; `tests/create_unreadable_source.rs`).
///
/// Until then this row forced a failed PLAIN create with such a file and
/// held the removal of its half-written `arc.rar`. That removal is still
/// in the creator, and is what the volume rows above exercise; what is
/// held here now is that the archive this run leaves is a whole one, not
/// a half-written one. Unix only by its nature.
#[cfg(unix)]
#[test]
fn an_unreadable_source_leaves_a_whole_archive_of_the_rest() {
    let dir = work("plain");
    sources(&dir);
    let locked = dir.join("two.bin");
    let mut perms = std::fs::metadata(&locked).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o000);
    std::fs::set_permissions(&locked, perms).unwrap();
    if std::fs::File::open(&locked).is_ok() {
        println!("SKIPPED: running with privileges that read a mode 000 file");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }
    let out = run(&dir, &["a", "-y", "-m0", "arc.rar", "one.bin", "two.bin"]);
    assert_eq!(out.status.code(), Some(6), "not the reference's exit code");
    let tested = run(&dir, &["t", "arc.rar"]);
    assert_eq!(tested.status.code(), Some(0), "arc.rar does not test");
    let listed = run(&dir, &["lb", "arc.rar"]);
    assert_eq!(String::from_utf8_lossy(&listed.stdout), "one.bin\n");
    let mut perms = std::fs::metadata(&locked).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o644);
    std::fs::set_permissions(&locked, perms).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// By design since 25 Sep 2026: a volume create is REFUSED, before
/// anything is written, when a FILE already sits at a name of this set's
/// volume pattern in the output directory. Which volumes a run will write
/// is not known until it writes them, so "the names it would write" is
/// read as every name the pattern matches, whatever its number and
/// padding: `arc.partN.rar` for any digits N, and under `-vn` also
/// `arc.rNN`. Before that date such a file was truncated by the run and,
/// if the run then failed, removed.
fn refuses_over(dir: &Path, victim: &str, extra: &[&str]) {
    let mine = noise(3000, 9);
    std::fs::write(dir.join(victim), &mine).unwrap();
    let mut args = vec!["a", "-y", "-m0", "-v20k"];
    args.extend_from_slice(extra);
    args.extend_from_slice(&["arc", "one.bin", "two.bin"]);
    let out = run(dir, &args);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_ne!(out.status.code(), Some(0), "{victim} {args:?} succeeded");
    assert!(
        stderr.contains(victim),
        "{victim} {args:?}: the refusal does not name the file: {stderr}"
    );
    assert_eq!(
        std::fs::read(dir.join(victim)).unwrap(),
        mine,
        "{victim} {args:?} changed the user's file"
    );
    let mut want = vec!["one.bin", "two.bin", victim];
    want.sort_unstable();
    assert_eq!(files_in(dir), want, "{victim} {args:?} wrote something");
}

#[test]
fn a_volume_create_refuses_an_existing_volume_name() {
    for victim in [
        "arc.part1.rar",
        "arc.part2.rar",
        "arc.part02.rar",
        "arc.part9.rar",
    ] {
        let dir = work(&format!("refuse-{victim}"));
        sources(&dir);
        refuses_over(&dir, victim, &[]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The same under `-vn`, whose set is `arc.rar`, `arc.r00`, `arc.r01`...
/// (`arc.rar` is the existing-archive refusal, unchanged.) The writer
/// refuses classic naming under RAR 5 today, so what this pins is that the
/// refusal comes first and names the user's file.
#[test]
fn an_old_named_volume_create_refuses_an_existing_volume_name() {
    for victim in ["arc.r00", "arc.r01"] {
        let dir = work(&format!("refuse-vn-{victim}"));
        sources(&dir);
        refuses_over(&dir, victim, &["-vn"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The pattern is this set's and no wider: another stem's volumes, a name
/// with more after `.rar`, and a `.rNN` name outside `-vn` do not stop the
/// run, and are left as they were.
#[test]
fn a_volume_create_ignores_names_outside_its_pattern() {
    let dir = work("unrelated");
    sources(&dir);
    let others = [
        "other.part2.rar",
        "arc.part2.rar.bak",
        "arc.partx.rar",
        "arc.r00",
    ];
    for name in others {
        std::fs::write(dir.join(name), name).unwrap();
    }
    let out = run(
        &dir,
        &["a", "-y", "-m0", "-v20k", "arc", "one.bin", "two.bin"],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(dir.join("arc.part1.rar").is_file());
    for name in others {
        assert_eq!(std::fs::read(dir.join(name)).unwrap(), name.as_bytes());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The output directory is the one the archive name points into, not the
/// working directory.
#[test]
fn a_volume_create_refuses_in_the_archive_directory() {
    let dir = work("subdir");
    sources(&dir);
    std::fs::create_dir(dir.join("out")).unwrap();
    let mine = noise(3000, 10);
    std::fs::write(dir.join("out/arc.part3.rar"), &mine).unwrap();
    let out = run(
        &dir,
        &["a", "-y", "-m0", "-v20k", "out/arc", "one.bin", "two.bin"],
    );
    assert_ne!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stderr).contains("arc.part3.rar"));
    assert_eq!(std::fs::read(dir.join("out/arc.part3.rar")).unwrap(), mine);
    assert_eq!(files_in(&dir.join("out")), ["arc.part3.rar"]);
    let _ = std::fs::remove_dir_all(&dir);
}
