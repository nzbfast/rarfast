//! A failed member's cleanup must never remove a file this run did not
//! write, at either of the two sites that settle a member outside
//! `Sink::close`'s own failure path.
//!
//! The wrong-password fix (`wrong_password.rs`) routed the checksum
//! failure's cleanup through `Run::discard_written`, which removes a
//! member's target only if this run created it. Two other sites still
//! removed a RE-DERIVED target under the extract-mode guard alone:
//!
//! - the lost-volume arm of `report_walk_error`, which settles the member
//!   the walk stopped on when a set is short of a volume. When no line is
//!   open, it falls back to the last member charged with a failure, and
//!   a member whose output file could not be CREATED is charged with one.
//!   So `x -y` over an existing file the run cannot open (the truncating
//!   open is refused, the run writes nothing there) followed by a missing
//!   volume removed the caller's file: unlinking needs write permission on
//!   the directory, not on the file. That is the row that failed at an
//!   earlier revision.
//!
//!   The file was mode `0444` until 1 Oct 2026. From that day `x -y`
//!   OVERWRITES a `0444` file in place, as unrar 7.23 and rar 7.23 do
//!   (`safepath::add_owner_write`; over this short set both references and
//!   rarfast then remove the failed member, exit 6, measured on x86-64
//!   Linux), so a `0444` file is one the run DID write and no longer makes
//!   this row. A file with no bit at all for its owner (`0000`) is still
//!   refused, and is the file this row now plants.
//! - `refuse_member`, which is reached only for a member whose line is
//!   open, and a line is opened only when the output file was created.
//!   No row found here reaches it for a file the run did not write; it
//!   goes through the same guard anyway, and the `-o-` row pins that.
//!
//! Every archive here is written by rarfast itself, so no reference
//! binary is needed.

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// An empty directory of one test's own, made afresh under the system's
/// temporary directory; `tag` tells the tests of this file apart.
fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-rmsites-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(dir: &Path, args: &[&str]) -> (Option<i32>, String) {
    let out = Command::new(rarfast())
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    (
        out.status.code(),
        format!(
            "stdout {:?} stderr {:?}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// Bytes that do not compress, so `-v10k` splits the member over three
/// volumes whatever the method.
fn noise(len: usize) -> Vec<u8> {
    let mut state: u32 = 0x9e37_79b9;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

const BYSTANDER: &[u8] = b"a file the caller owns, which no run of rarfast wrote\n";

/// Writes `rand.bin` as a three-volume set in `dir` and deletes the
/// middle volume.
fn short_set(dir: &Path, method: &str) {
    std::fs::write(dir.join("rand.bin"), noise(24576)).unwrap();
    let (code, said) = run(
        dir,
        &["a", "-y", "-idq", method, "-v10k", "arc.rar", "rand.bin"],
    );
    assert_eq!(code, Some(0), "building the set: {said}");
    std::fs::remove_file(dir.join("rand.bin")).unwrap();
    assert!(
        dir.join("arc.part3.rar").exists(),
        "the set is not three volumes"
    );
    std::fs::remove_file(dir.join("arc.part2.rar")).unwrap();
}

/// Root opens a read-only file for writing, so the create never fails.
#[cfg(unix)]
fn can_write_read_only(path: &Path) -> bool {
    std::fs::OpenOptions::new().write(true).open(path).is_ok()
}

/// THE DEFECT: `x -y` cannot open the caller's `rand.bin` (mode `0000`:
/// see the module note for why not `0444`), so the run writes nothing
/// there; the walk then runs off the end of what the short set holds, and
/// the lost-volume arm removed the file. Unix only by its nature: the
/// file is shut by a Unix mode.
#[cfg(unix)]
#[test]
fn a_missing_volume_leaves_a_read_only_file_the_run_could_not_open() {
    for method in ["-m0", "-m3"] {
        let dir = work(&format!("ro{method}"));
        short_set(&dir, method);
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let target = out.join("rand.bin");
        std::fs::write(&target, BYSTANDER).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o000)).unwrap();
        if can_write_read_only(&target) {
            eprintln!("not measured: a mode 0000 file opens for writing for this user");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        let (code, said) = run(&dir, &["x", "-y", "arc.part1.rar", "out/"]);
        assert_ne!(code, Some(0), "{method}: a short set must fail: {said}");
        // Readable again, to look at it: the run must have left it there.
        let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644));
        assert_eq!(
            std::fs::read(&target).ok().as_deref(),
            Some(BYSTANDER),
            "{method}: the run removed or changed a file it never wrote: {said}"
        );
        let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Under `-y` a `0444` file already on disk is to be replaced, and its
/// member then fails for the missing volume: exit 6, with `Cannot find
/// volume` and `checksum error` and no `cannot create`, and the file that
/// was there is AS IT WAS, bytes and bits.
///
/// That last clause is SPEC-CLI 9.4 W7, a chosen difference from the
/// reference (9.3 O14), in force since 10 Oct 2026: the member is written
/// beside the old file and takes its name only when it is whole. MEASURED
/// against unrar 7.23 and rar 7.23 on x86-64 Linux over a stored
/// three-volume set with its middle volume removed (1 Oct 2026): both
/// leave no `rand.bin`, exit 6, those two lines; and so did rarfast from
/// that day until this rule. Unix only by its nature: the file is
/// read-only by a Unix mode.
#[cfg(unix)]
#[test]
fn a_missing_volume_while_replacing_a_read_only_file_leaves_it_as_it_was() {
    for method in ["-m0", "-m3"] {
        let dir = work(&format!("over{method}"));
        short_set(&dir, method);
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        let target = out.join("rand.bin");
        std::fs::write(&target, BYSTANDER).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o444)).unwrap();
        let (code, said) = run(&dir, &["x", "-y", "arc.part1.rar", "out/"]);
        assert_eq!(code, Some(6), "{method}: {said}");
        assert!(
            said.contains("Cannot find volume arc.part2.rar") && said.contains("checksum error"),
            "{method}: {said}"
        );
        assert!(!said.contains("cannot create"), "{method}: {said}");
        assert_eq!(
            std::fs::read(&target).ok().as_deref(),
            Some(BYSTANDER),
            "{method}: the file that was there did not survive: {said}"
        );
        let bits = std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777;
        assert_eq!(bits, 0o444, "{method}: its bits");
        let left: Vec<_> = std::fs::read_dir(&out).unwrap().flatten().collect();
        assert_eq!(left.len(), 1, "{method}: a name was left beside it");
        let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// `x -o-` over an existing file skips the member; a missing volume
/// after it must not settle it by removing the caller's file.
#[test]
fn a_missing_volume_under_never_overwrite_leaves_an_existing_file() {
    for method in ["-m0", "-m3"] {
        let dir = work(&format!("no{method}"));
        short_set(&dir, method);
        let out = dir.join("out");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("rand.bin"), BYSTANDER).unwrap();
        let (_, said) = run(&dir, &["x", "-o-", "arc.part1.rar", "out/"]);
        assert_eq!(
            std::fs::read(out.join("rand.bin")).ok().as_deref(),
            Some(BYSTANDER),
            "{method}: `x -o-` removed or changed a file it never wrote: {said}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// What the guard must NOT change: a member this run DID write, cut short
/// by the missing volume, is still removed without `-kb` and kept with it.
#[test]
fn a_missing_volume_still_settles_the_file_the_run_wrote() {
    for method in ["-m0", "-m3"] {
        let dir = work(&format!("w{method}"));
        short_set(&dir, method);
        let (code, said) = run(&dir, &["x", "-y", "arc.part1.rar", "out/"]);
        assert_ne!(code, Some(0), "{method}: {said}");
        assert!(
            !dir.join("out/rand.bin").exists(),
            "{method}: without -kb the partial file must go: {said}"
        );
        let (code, said) = run(&dir, &["x", "-y", "-kb", "arc.part1.rar", "kept/"]);
        assert_ne!(code, Some(0), "{method}: {said}");
        assert!(
            dir.join("kept/rand.bin").exists(),
            "{method}: -kb must keep the partial file: {said}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
