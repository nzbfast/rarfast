//! The walk asking for small volumes ahead (`engine::volumes_ahead`),
//! through the whole command.
//!
//! When the walk of an extract, or of a test or print of stored members,
//! opens a small volume, the command line asks the operating system to
//! read the volumes after it ahead. The request is advice: what must hold
//! is that NO BYTE AND NO VERDICT moves. That is tested here on sets in
//! many small volumes (clear, under `-hp`, compressed), with the rule off
//! (`RARFAST_SMALL_VOLUMES_AHEAD=0`), as the page cache rules it (`1`) and
//! on whatever the page cache says (`always`: a set a test has just written
//! is in memory, and the rule as shipped leaves such a set alone, so only
//! `always` is sure to run the path here), at a distance of 1 MiB
//! (`RARFAST_SMALL_AHEAD_MIB`), which is sixteen of these volumes: every
//! command answers the same, writes the same bytes, and reports a missing
//! volume in the same words with the same exit code.
//!
//! Which volumes are asked for, and when, is `engine`'s own unit test
//! (`the_walk_asks_for_small_volumes_ahead_within_a_bound`).
//!
//! Since 2 Oct 2026 a volume of ANY size is asked for, the next one whole
//! (`RARFAST_LARGE_VOLUMES_AHEAD=0` restores the small volumes' bound): a
//! set in volumes over that bound is run the same way, with the large
//! volumes' knob on and off.
//!
//! A shipped `rarfast` reads no environment word; the read path's exist only
//! under the feature `reader-knobs`, which this test builds with:
//!
//! ```text
//! cargo test -p rarkit-cli --features reader-knobs --test small_volumes_ahead
//! ```
#![cfg(feature = "reader-knobs")]

use std::path::PathBuf;
use std::process::{Command, Output};

#[path = "support/exe_copy.rs"]
mod exe_copy;
use exe_copy::{copy_executable, output_of, rarfast};

const KIB: usize = 1 << 10;

/// The rule's three words.
const KNOBS: [&str; 3] = ["0", "1", "always"];

struct Bench {
    dir: PathBuf,
    unrar: PathBuf,
}

/// Noise a member is made of (a linear congruential stream).
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 56) as u8
        })
        .collect()
}

/// Text an LZ level packs: lines that repeat with a counter in them.
fn text(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 64);
    let mut line = 0u32;
    while out.len() < len {
        out.extend_from_slice(format!("line {line} of a member that packs well\n").as_bytes());
        line += 1;
    }
    out.truncate(len);
    out
}

impl Bench {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "rarfast-small-volumes-ahead-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        // A copy named `unrar` is how the binary picks that dialect.
        let unrar = dir.join("unrar");
        copy_executable(&rarfast(), &unrar);
        Self { dir, unrar }
    }

    fn write(&self, name: &str, bytes: &[u8]) {
        std::fs::write(self.dir.join("src").join(name), bytes).unwrap();
    }

    /// `rarfast a <switches> <archive> <files>` in the source directory.
    fn create(&self, switches: &[&str], archive: &str, files: &[&str]) {
        let out = output_of(
            Command::new(rarfast())
                .arg("a")
                .args(switches)
                .args(["-idq", &format!("../{archive}")])
                .args(files)
                .current_dir(self.dir.join("src")),
        )
        .expect("rarfast a runs");
        assert!(
            out.status.success(),
            "rarfast a {switches:?} {archive}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// The set's volumes, in order, by their names in the bench directory.
    fn volumes(&self, stem: &str) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(&format!("{stem}.part")) && name.ends_with(".rar"))
            .collect();
        names.sort();
        names
    }

    /// `unrar <args>` with the rule at `knob`.
    fn unrar(&self, args: &[&str], knob: &str) -> Output {
        self.unrar_large(args, knob, None)
    }

    /// `unrar <args>` with the rule at `knob` and the large volumes' knob
    /// at `large` (unset for `None`).
    fn unrar_large(&self, args: &[&str], knob: &str, large: Option<&str>) -> Output {
        let mut command = Command::new(&self.unrar);
        command
            .args(args)
            .current_dir(&self.dir)
            .env("RARFAST_SMALL_VOLUMES_AHEAD", knob)
            .env("RARFAST_SMALL_AHEAD_MIB", "1");
        match large {
            Some(word) => command.env("RARFAST_LARGE_VOLUMES_AHEAD", word),
            None => command.env_remove("RARFAST_LARGE_VOLUMES_AHEAD"),
        };
        output_of(&mut command).expect("unrar runs")
    }

    /// Extract `first` into a fresh directory `into` and return the run.
    fn extract(&self, op: &str, first: &str, into: &str, knob: &str) -> Output {
        let dest = self.dir.join(into);
        let _ = std::fs::remove_dir_all(&dest);
        std::fs::create_dir_all(&dest).unwrap();
        let target = format!("{into}/");
        self.unrar(&[op, "-idq", "-y", "-pSecret", first, &target], knob)
    }

    fn read(&self, into: &str, name: &str) -> Vec<u8> {
        std::fs::read(self.dir.join(into).join(name))
            .unwrap_or_else(|e| panic!("{into}/{name}: {e}"))
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn said(out: &Output) -> (Option<i32>, String, String) {
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The sets: a name and the switches that make it. The compressed set's
/// `t` and `p` are left out of the rule; its extract is not.
const SETS: [(&str, &[&str]); 3] = [
    ("clear", &["-m0", "-v64k"]),
    ("hp", &["-m0", "-hpSecret", "-v64k"]),
    ("packed", &["-m3", "-v64k"]),
];

fn bench(tag: &str) -> (Bench, Vec<u8>, Vec<u8>, Vec<u8>) {
    let bench = Bench::new(tag);
    let big = noise(1536 * KIB, 7);
    let small = noise(200 * KIB, 11);
    let words = text(900 * KIB);
    bench.write("big.bin", &big);
    bench.write("small.bin", &small);
    bench.write("words.txt", &words);
    for (name, switches) in SETS {
        bench.create(
            switches,
            &format!("{name}.rar"),
            &["big.bin", "small.bin", "words.txt"],
        );
        assert!(
            bench.volumes(name).len() > 20,
            "{name}: a set of many volumes, got {}",
            bench.volumes(name).len()
        );
    }
    (bench, big, small, words)
}

#[test]
fn every_command_answers_and_writes_the_same_with_volumes_asked_ahead() {
    let (bench, big, small, words) = bench("same");
    let whole: Vec<u8> = [&big[..], &small[..], &words[..]].concat();
    for (name, _) in SETS {
        let first = bench.volumes(name).remove(0);
        let mut tested = Vec::new();
        for knob in KNOBS {
            let at = format!("{name} at {knob}");
            // `t`: the verdict and every line of it.
            let t = bench.unrar(&["t", "-pSecret", &first], knob);
            assert!(t.status.success(), "{at}: t: {:?}", said(&t));
            tested.push(said(&t));
            // `p`: the members' bytes, in order, and nothing else.
            let p = bench.unrar(&["p", "-inul", "-pSecret", &first], knob);
            assert!(p.status.success(), "{at}: p: {:?}", p.status);
            assert!(p.stdout == whole, "{at}: p wrote other bytes");
            // `x`: every member, whole.
            let x = bench.extract("x", &first, "out", knob);
            assert!(x.status.success(), "{at}: x: {:?}", said(&x));
            assert!(bench.read("out", "big.bin") == big, "{at}: x big.bin");
            assert!(bench.read("out", "small.bin") == small, "{at}: x small.bin");
            assert!(bench.read("out", "words.txt") == words, "{at}: x words.txt");
            // `e` of the one member that starts far into the set: the walk
            // skips to it.
            let dest = bench.dir.join("one");
            let _ = std::fs::remove_dir_all(&dest);
            std::fs::create_dir_all(&dest).unwrap();
            let e = bench.unrar(
                &["e", "-idq", "-y", "-pSecret", &first, "small.bin", "one/"],
                knob,
            );
            assert!(e.status.success(), "{at}: e: {:?}", said(&e));
            assert!(bench.read("one", "small.bin") == small, "{at}: e small.bin");
        }
        assert!(
            tested.iter().all(|one| one == &tested[0]),
            "{name}: t answered differently across the rule's words: {tested:?}"
        );
    }
}

#[test]
fn a_missing_volume_is_reported_the_same_with_volumes_asked_ahead() {
    let (bench, ..) = bench("missing");
    for (name, _) in SETS {
        let volumes = bench.volumes(name);
        let first = volumes[0].clone();
        // Gone from the middle of the first member: asked for ahead (it
        // will not open, which is the walk's to report) and then walked to.
        std::fs::remove_file(bench.dir.join(&volumes[9])).unwrap();
        let mut tested = Vec::new();
        let mut extracted = Vec::new();
        for knob in KNOBS {
            let t = bench.unrar(&["t", "-pSecret", &first], knob);
            assert!(
                !t.status.success(),
                "{name} at {knob}: t passed a set with a volume gone"
            );
            tested.push(said(&t));
            let x = bench.extract("x", &first, "gone", knob);
            assert!(
                !x.status.success(),
                "{name} at {knob}: x passed a set with a volume gone"
            );
            extracted.push(said(&x));
        }
        assert!(
            tested.iter().all(|one| one == &tested[0]),
            "{name}: t reported a missing volume differently: {tested:?}"
        );
        assert!(
            extracted.iter().all(|one| one == &extracted[0]),
            "{name}: x reported a missing volume differently: {extracted:?}"
        );
    }
}

/// **A set in volumes over the small volumes' bound** (17 MiB volumes,
/// over the 16 MiB the rule once stopped at): asked for ahead, the next
/// volume whole, with the large volumes' knob as shipped, on and off, and
/// the rule's every word. `t`, `p` and `x` answer and write the same, and a
/// volume gone is reported the same.
#[test]
fn a_set_in_volumes_over_the_small_bound_answers_the_same_asked_ahead() {
    let bench = Bench::new("large");
    let big = noise(40 * 1024 * KIB + 123, 19);
    let note = text(3 * KIB);
    bench.write("full.bin", &big);
    bench.write("note.txt", &note);
    bench.create(&["-m0", "-v17m"], "large.rar", &["full.bin", "note.txt"]);
    let volumes = bench.volumes("large");
    assert!(volumes.len() >= 3, "a set of large volumes: {volumes:?}");
    let first = volumes[0].clone();
    let whole: Vec<u8> = [&big[..], &note[..]].concat();
    let mut tested = Vec::new();
    for knob in KNOBS {
        for large in [None, Some("1"), Some("0")] {
            let at = format!("rule {knob}, large {large:?}");
            let t = bench.unrar_large(&["t", &first], knob, large);
            assert!(t.status.success(), "{at}: t: {:?}", said(&t));
            tested.push(said(&t));
            let p = bench.unrar_large(&["p", "-inul", &first], knob, large);
            assert!(p.status.success() && p.stdout == whole, "{at}: p");
            let dest = bench.dir.join("out");
            let _ = std::fs::remove_dir_all(&dest);
            std::fs::create_dir_all(&dest).unwrap();
            let x = bench.unrar_large(&["x", "-idq", "-y", &first, "out/"], knob, large);
            assert!(x.status.success(), "{at}: x: {:?}", said(&x));
            assert!(bench.read("out", "full.bin") == big, "{at}: x full.bin");
            assert!(bench.read("out", "note.txt") == note, "{at}: x note.txt");
        }
    }
    assert!(
        tested.iter().all(|one| one == &tested[0]),
        "t answered differently across the knobs: {tested:?}"
    );
    std::fs::remove_file(bench.dir.join(&volumes[1])).unwrap();
    let mut gone = Vec::new();
    for large in [None, Some("0")] {
        let x = bench.unrar_large(&["x", "-idq", "-y", &first, "gone/"], "always", large);
        assert!(
            !x.status.success(),
            "large {large:?}: x passed a set with a volume gone"
        );
        gone.push(said(&x));
    }
    assert_eq!(
        gone[0], gone[1],
        "a missing large volume is reported the same"
    );
}
