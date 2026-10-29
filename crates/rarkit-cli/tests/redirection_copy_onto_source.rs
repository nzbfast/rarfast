//! A file copy whose `e` output is its own source's output (spec F
//! 3.8.5), on every host. Apart from `tests/redirection.rs`, which is
//! unix-only, so that the identity check this rests on runs on Windows
//! too, where it is the paths the file system resolves rather than the
//! device and inode. The archives are `crates/rarkit/tests/redirection/`
//! (`make.sh` section 8, reference rar 7.23 with `-oi:1`).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn fixture_bytes(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../rarkit/tests/redirection")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// A scratch directory of its own per row, holding the archive under
/// `a.rar` and the output under `o/`.
struct Work {
    dir: PathBuf,
}

impl Work {
    fn new(tag: &str, archive: &[u8]) -> Work {
        let dir = std::env::temp_dir().join(format!(
            "rarfast-copy-onto-source-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("o")).unwrap();
        std::fs::write(dir.join("a.rar"), archive).unwrap();
        Work { dir }
    }

    fn out(&self) -> PathBuf {
        self.dir.join("o")
    }

    /// `rarfast <cmd> <switches> a.rar o/` from inside the scratch.
    fn run(&self, cmd: &str, switches: &[&str], members: &[&str]) -> Output {
        Command::new(rarfast())
            .current_dir(&self.dir)
            .arg(cmd)
            .args(switches)
            .arg("a.rar")
            .args(members)
            .arg("o/")
            .output()
            .unwrap()
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

/// Every entry of `root`, kind and relative path with `/` between parts,
/// sorted.
fn tree(root: &Path) -> Vec<String> {
    fn walk(root: &Path, at: &Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(at).unwrap() {
            let path = entry.unwrap().path();
            let rel: Vec<String> = path
                .strip_prefix(root)
                .unwrap()
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect();
            let rel = rel.join("/");
            let meta = std::fs::symlink_metadata(&path).unwrap();
            if meta.file_type().is_symlink() {
                out.push(format!("l {rel}"));
            } else if meta.is_dir() {
                out.push(format!("d {rel}"));
                walk(root, &path, out);
            } else {
                out.push(format!("f {rel}"));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

fn lines(expected: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = expected.iter().map(|s| (*s).to_owned()).collect();
    v.sort();
    v
}

/// 3.8.5: a copy whose `e` output is its own source's output, `d/big1`
/// (a reference to `big1`) flattened onto `o/big1`. The bytes already there
/// ARE the target's, so they are kept whole, equal to what `x` writes, and
/// the run is OK. A copy made by reading and writing one file left it
/// empty, every member reported OK, exit 0. `-o-` keeps the earlier file.
#[test]
fn a_copy_onto_its_own_source_keeps_the_bytes() {
    one_file_copy_rows("samename5.rar", "same");
}

/// The same with `d/BIG1`: two names, one file on a case-insensitive
/// volume, so sameness is the file system's and never the path text's.
/// Skipped where the scratch volume tells the two names apart.
#[test]
fn a_copy_onto_its_own_source_by_another_case_keeps_the_bytes() {
    let probe = Work::new("case-probe", b"");
    std::fs::write(probe.out().join("case"), b"").unwrap();
    if !probe.out().join("CASE").exists() {
        eprintln!("skipped: the scratch volume is case-sensitive");
        return;
    }
    one_file_copy_rows("samecase5.rar", "case");
}

fn one_file_copy_rows(fixture: &str, tag: &str) {
    let archive = fixture_bytes(fixture);
    let big1 = {
        let work = Work::new(&format!("{tag}-ref"), &archive);
        let done = work.run("x", &["-y"], &[]);
        assert_eq!(code(&done), 0, "{done:?}");
        std::fs::read(work.out().join("big1")).unwrap()
    };
    assert_eq!(big1.len(), 300_000);
    for width in ["-mt1", "", "-mt2"] {
        for overwrite in ["-o+", "-y"] {
            let switches: Vec<&str> = [overwrite, width]
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect();
            let row = format!("e {}", switches.join(" "));
            let work = Work::new(&format!("{tag}-e{overwrite}{width}"), &archive);
            let done = work.run("e", &switches, &[]);
            let out = std::fs::read(work.out().join("big1")).unwrap();
            assert_eq!(
                out.len(),
                big1.len(),
                "{row}: o/big1 is {} bytes, exit {}: {done:?}",
                out.len(),
                code(&done)
            );
            assert!(out == big1, "{row}: o/big1 differs from x's big1");
            assert_eq!(code(&done), 0, "{row}: {done:?}");
            assert_eq!(tree(&work.out()), lines(&["f big1"]), "{row}");
        }

        // `-o-`: the copy is skipped, and the target's file stands.
        let work = Work::new(&format!("{tag}-e-o-{width}"), &archive);
        let switches: Vec<&str> = ["-o-", width]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect();
        let done = work.run("e", &switches, &[]);
        assert_eq!(code(&done), 0, "e -o- {width}: {done:?}");
        assert!(
            std::fs::read(work.out().join("big1")).unwrap() == big1,
            "e -o- {width}"
        );
    }
}
