//! `rarfast a` under a named `-mm<size>`: when the encoder's window cannot
//! fit inside the named size, the create is refused before anything is
//! written, exit 8, naming the `-mm` that would do, in the words `rv`
//! under `-mm` uses. A named size that fits writes as before; at 512 MiB
//! and above it writes the bytes no `-mm` writes. A storing create has no
//! encoder and is never refused for it.
//!
//! Until 23 Oct 2026 a create passed a named `-mm` in silence: under
//! `-mm256m`, `-md32m` held about 380 MiB of process at every level and
//! thread count, exited 0 and said nothing.
//!
//! The member is 34 MiB of text, so a `-md32m` window is not fitted down
//! below 32 MiB. Threads: the machine's default width. Memory: one process
//! at a time, at most about 420 MiB (the `-mm512m` and unbounded runs).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// Seeded words that compress, `len` bytes of them.
fn text(len: usize, seed: u64) -> Vec<u8> {
    let words = [
        "window ",
        "named ",
        "memory ",
        "ceiling ",
        "refused ",
        "written ",
        "level ",
        "five ",
        "dictionary ",
        "encoder ",
        "member ",
        "archive ",
    ];
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len + 16);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(words[(state % words.len() as u64) as usize].as_bytes());
        if state.is_multiple_of(11) {
            out.extend_from_slice(format!("{} ", state % 100_000).as_bytes());
        }
    }
    out.truncate(len);
    out
}

fn run(dir: &Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(rarfast())
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn archives(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".rar"))
        .collect();
    names.sort();
    names
}

/// The `-mm<N>m` a refusal names: the figure before the `m or more`.
fn named_mm(stderr: &str) -> String {
    let tail = stderr
        .split(". -mm")
        .nth(1)
        .unwrap_or_else(|| panic!("no -mm named: {stderr}"));
    let digits: String = tail.chars().take_while(char::is_ascii_digit).collect();
    assert!(
        !digits.is_empty() && tail[digits.len()..].starts_with("m or more lets it run."),
        "{stderr}"
    );
    format!("-mm{digits}m")
}

fn tested(dir: &Path, archive: &str) {
    let (code, stdout, stderr) = run(dir, &["t", "-idq", archive]);
    assert_eq!(code, 0, "{archive}: {stdout}{stderr}");
}

#[test]
fn a_create_whose_window_cannot_fit_a_named_mm_is_refused_before_writing() {
    let dir = std::env::temp_dir().join(format!("rarfast-create-mm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(dir.join("src/text.txt"), text(34 << 20, 7)).unwrap();

    // Too small for a 32 MiB window, at a level of the ladder's each end
    // and at one thread: refused, the code for not enough memory, the
    // `-mm` that would do named, and no archive left behind.
    let mut wanted = Vec::new();
    for switches in [
        &["-m5", "-md32m", "-mm256m"][..],
        &["-m1", "-md32m", "-mm256m"][..],
        &["-m5", "-md32m", "-mm256m", "-mt1"][..],
    ] {
        let mut args = vec!["a", "-idq", "-ep1"];
        args.extend_from_slice(switches);
        args.extend_from_slice(&["arc.rar", "src/text.txt"]);
        let (code, stdout, stderr) = run(&dir, &args);
        assert_eq!(code, 8, "{switches:?}: {stdout}{stderr}");
        assert!(
            stderr.contains("arc.rar: the archive is not written:"),
            "{switches:?}: {stderr}"
        );
        assert!(
            stderr.contains("-mm names 268435456"),
            "{switches:?}: {stderr}"
        );
        assert!(
            archives(&dir).is_empty(),
            "{switches:?}: wrote {:?}",
            archives(&dir)
        );
        wanted.push(named_mm(&stderr));
    }

    // The `-mm` a refusal names lets that create run.
    let (code, stdout, stderr) = run(
        &dir,
        &[
            "a",
            "-idq",
            "-ep1",
            "-m5",
            "-md32m",
            &wanted[0],
            "named.rar",
            "src/text.txt",
        ],
    );
    assert_eq!(code, 0, "{}: {stdout}{stderr}", wanted[0]);
    tested(&dir, "named.rar");

    // A named size that fits: written, and the bytes no `-mm` writes. Since
    // chain 40 the admission charges every term the run can hold
    // (`Run::named_most_bytes`), and for ONE member the finder its class
    // builds, read from its head before the refusal: this member takes the
    // chains (260 MiB at `-md32m`), and fits `-mm512m` as it did in 0.9.0.
    let (code, stdout, stderr) = run(
        &dir,
        &[
            "a",
            "-idq",
            "-ep1",
            "-m5",
            "-md32m",
            "-mm512m",
            "fits.rar",
            "src/text.txt",
        ],
    );
    assert_eq!(code, 0, "{stdout}{stderr}");
    let (code, stdout, stderr) = run(
        &dir,
        &[
            "a",
            "-idq",
            "-ep1",
            "-m5",
            "-md32m",
            "free.rar",
            "src/text.txt",
        ],
    );
    assert_eq!(code, 0, "{stdout}{stderr}");
    tested(&dir, "fits.rar");
    assert!(
        std::fs::read(dir.join("fits.rar")).unwrap()
            == std::fs::read(dir.join("free.rar")).unwrap(),
        "-mm512m and no -mm wrote different archives"
    );

    // A storing create has no encoder: never refused for one.
    let (code, stdout, stderr) = run(
        &dir,
        &[
            "a",
            "-idq",
            "-ep1",
            "-m0",
            "-mm1m",
            "stored.rar",
            "src/text.txt",
        ],
    );
    assert_eq!(code, 0, "{stdout}{stderr}");
    tested(&dir, "stored.rar");
    let _ = std::fs::remove_dir_all(&dir);
}
