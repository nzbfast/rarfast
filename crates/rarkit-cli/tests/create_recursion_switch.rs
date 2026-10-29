//! `-r`, `-r-`, `-r0` and no recursion switch choose what rar 7.23 chooses.
//!
//! Until 8 Oct 2026 `-r-` was read as "no switch", so `rar a -r- arc dir`
//! stored the whole tree, and a wildcard without `-r` walked every
//! directory it matched: `rar a arc 's/*'` stored `s/d` and everything
//! below it. With `m` or `-df` that archived and DELETED more than was
//! asked for.
//!
//! The reference's own answers, measured on 8 Oct 2026, are the table:
//!
//! - a mask that names a directory stores its whole tree with `-r`,
//!   `-r0` or no switch, and the directory's own entry alone with `-r-`;
//! - a wildcard without `-r` (or with `-r-`) takes the FILES of that one
//!   directory whose names match, and no directory at all;
//! - a wildcard with `-r` or `-r0` takes every file below whose name
//!   matches, at any depth, and the entry of every directory whose name
//!   matches, not what that directory holds;
//! - a name without a wildcard is searched for below only with `-r`:
//!   `-r a.txt` takes every `a.txt`, `-r0 c.txt` only one that is here.
//!
//! Each run is `-mt2` over nine files of at most 3,000 bytes: a pool two
//! threads wide and a few KiB of memory.

#![cfg(unix)]

#[path = "support/selection_rows.rs"]
mod selection_rows;

#[test]
fn what_each_recursion_switch_takes_is_the_references() {
    selection_rows::agree_with_the_reference(
        "recursion",
        include_str!("create-selection/rar723-recursion.txt"),
    );
}

/// With `-r` a name that is nowhere below is not an error beside one
/// that is: measured, `rar a -r arc s nosuch` says nothing on stderr and
/// exits 0, where without `-r` it complains `Cannot open nosuch` and
/// exits 10. Until 8 Oct 2026 rarfast complained either way. (The table
/// holds the exit codes; this holds the silence.)
#[test]
fn with_r_a_name_found_nowhere_is_not_complained_of() {
    use std::process::{Command, Stdio};
    let dir = std::env::temp_dir().join(format!("rarfast-r-nosuch-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("s")).unwrap();
    std::fs::write(dir.join("s/a.txt"), b"aaa\n").unwrap();
    let run = |switch: &str, archive: &str| {
        Command::new(env!("CARGO_BIN_EXE_rarfast"))
            .args(["a", "-idq", "-mt2", switch, archive, "s", "nosuch"])
            .current_dir(&dir)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    let deep = run("-r", "deep.rar");
    assert_eq!(deep.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&deep.stderr), "");
    let flat = run("-r0", "flat.rar");
    assert_eq!(flat.status.code(), Some(10));
    assert!(String::from_utf8_lossy(&flat.stderr).contains("Cannot open nosuch"));
    let _ = std::fs::remove_dir_all(&dir);
}
