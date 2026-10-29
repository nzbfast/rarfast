//! The archive is forced to the disk before a source is deleted, and a
//! sync that fails keeps every source.
//!
//! No run can be made to fail its sync from outside, so the sync is
//! handed in: these call `delete_once_synced` with one that fails, and
//! with one that records what it was asked and what was still there.
//!
//! No pool and no memory to speak of: two files of a few bytes.

use std::cell::RefCell;
use std::path::{Path, PathBuf};

use super::{delete_once_synced, sync_written, AddMode, Chosen, Exit, Options, Out};

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-syncdel-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn chosen(dir: &Path, name: &str) -> Chosen {
    std::fs::write(dir.join(name), "bytes\n").unwrap();
    Chosen {
        shown: name.to_owned(),
        disk: dir.join(name),
        stored: name.to_owned(),
        is_dir: false,
        size: 6,
        mtime: None,
        attributes: 0,
    }
}

fn silent() -> (Options, Out) {
    let mut opts = Options::default();
    opts.shared.silent = true;
    let out = Out::new(&opts.shared);
    (opts, out)
}

#[test]
fn a_sync_that_fails_keeps_every_source_and_is_an_error() {
    let dir = work("fails");
    let files = [chosen(&dir, "a.txt"), chosen(&dir, "b.txt")];
    let written = [dir.join("arc.part1.rar"), dir.join("arc.part2.rar")];
    let (opts, out) = silent();
    let asked = RefCell::new(Vec::new());
    let exit = delete_once_synced(&out, &written, &files, &opts, AddMode::Move, |path| {
        asked.borrow_mut().push(path.to_path_buf());
        // The first volume syncs; the second does not.
        if path.ends_with("arc.part2.rar") {
            Err(std::io::Error::other("injected"))
        } else {
            Ok(())
        }
    });
    assert_eq!(exit, Exit::WriteFailed);
    assert_eq!(asked.into_inner(), written);
    assert!(dir.join("a.txt").exists() && dir.join("b.txt").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn every_file_written_is_synced_before_the_first_source_goes() {
    let dir = work("order");
    let files = [chosen(&dir, "a.txt"), chosen(&dir, "b.txt")];
    let written = [dir.join("arc.part1.rar"), dir.join("arc.part2.rar")];
    let (opts, out) = silent();
    let asked = RefCell::new(Vec::new());
    let exit = delete_once_synced(&out, &written, &files, &opts, AddMode::Move, |path| {
        assert!(dir.join("a.txt").exists() && dir.join("b.txt").exists());
        asked.borrow_mut().push(path.to_path_buf());
        Ok(())
    });
    assert_eq!(exit, Exit::Clean);
    assert_eq!(asked.into_inner(), written);
    assert!(!dir.join("a.txt").exists() && !dir.join("b.txt").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_sync_itself_answers_for_a_file_it_cannot_open_and_for_one_it_can() {
    let dir = work("real");
    assert!(sync_written(&dir.join("not-there.rar")).is_err());
    std::fs::write(dir.join("arc.rar"), "an archive\n").unwrap();
    sync_written(&dir.join("arc.rar")).unwrap();
    assert_eq!(std::fs::read(dir.join("arc.rar")).unwrap(), b"an archive\n");
    let _ = std::fs::remove_dir_all(&dir);
}
