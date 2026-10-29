//! `-x<mask>` and `-n<mask>` on a create choose what rar 7.23 chooses.
//!
//! Until 8 Oct 2026 a create tested each walked path against the masks
//! with the extraction side's matcher, and went into a directory whether
//! or not a mask had excluded it. So `rar a -r -df -xs/d arc s` left only
//! the entry `s/d` out, archived everything under it and then DELETED it
//! from disk, and a plain name (`-xa.txt`, `-nc.txt`) matched at any
//! depth where the reference matches that exact path alone.
//!
//! The table is the reference's own answers, `-df` and `m` rows first:
//! what it archived and what it left on disk. The rule they give is
//! written out at `select::Mask` in the crate.
//!
//! Each run is `-mt2` over nine files of at most 3,000 bytes: a pool two
//! threads wide and a few KiB of memory.

#![cfg(unix)]

#[path = "support/selection_rows.rs"]
mod selection_rows;

#[test]
fn excluded_and_included_paths_are_the_references() {
    selection_rows::agree_with_the_reference(
        "masks",
        include_str!("create-selection/rar723-exclude-include.txt"),
    );
}

/// A mask that is an absolute path is compared with the walked path made
/// absolute: measured, `rar a -r -x<cwd>/s/d arc s` leaves `s/d` and its
/// contents out, and the relative `-xs/d` does not reach a source named
/// by its absolute path.
#[test]
fn an_absolute_mask_is_compared_with_the_absolute_path() {
    use std::process::{Command, Stdio};
    let root = std::env::temp_dir().join(format!("rarfast-selection-abs-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("s/d")).unwrap();
    std::fs::write(root.join("s/a.txt"), b"aaa\n").unwrap();
    std::fs::write(root.join("s/d/c.txt"), b"ccc\n").unwrap();
    // The directory as the tool will see it: a temporary directory is
    // often reached through a link.
    let root = root.canonicalize().unwrap();
    let members = |archive: &str, mask: &str, source: &str| {
        let run = Command::new(env!("CARGO_BIN_EXE_rarfast"))
            .args(["a", "-idq", "-mt2", "-m0", "-r", mask, archive, source])
            .current_dir(&root)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(run.status.code(), Some(0), "{mask} {source}");
        let listed = Command::new(env!("CARGO_BIN_EXE_rarfast"))
            .args(["lb", archive])
            .current_dir(&root)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let mut names: Vec<String> = String::from_utf8_lossy(&listed.stdout)
            .lines()
            .map(str::to_owned)
            .collect();
        names.sort();
        names
    };
    let absolute = format!("-x{}/s/d", root.display());
    assert_eq!(members("one.rar", &absolute, "s"), ["s", "s/a.txt"]);
    let source = format!("{}/s", root.display());
    let stored = source.trim_start_matches('/').to_owned();
    assert_eq!(
        members("two.rar", &absolute, &source),
        [stored.clone(), format!("{stored}/a.txt")]
    );
    assert_eq!(members("three.rar", "-xs/d", &source).len(), 4);
    let _ = std::fs::remove_dir_all(&root);
}
