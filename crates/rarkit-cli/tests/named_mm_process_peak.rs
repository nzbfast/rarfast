//! Under the least `-mm` a create is admitted at, the PROCESS holds no more
//! than the figure named (chain 40).
//!
//! A named `-mm` is the whole process's (`create::options::memory_policy`):
//! the CLI keeps its headroom and room and gives the engine the rest as its
//! `working_limit`, and the engine refuses, before a byte, a run it cannot
//! keep inside that (`Run::refuse_over_named_ceiling`). Until chain 40 the
//! refusal weighed one finder and the largest member's own history, and an
//! admitted run then held past it: counted 25 Oct 2026 on macOS (M5 Max,
//! 18 threads), at the least figure each named, the process passed it by
//! 114 MiB over 118 MB of text at `-m5 -md128m -s` (a solid run's history
//! is the stream's) and by 52 over 13,477 text files at `-md32m` (the
//! chain 40 cause count).
//!
//! And ONE member is charged one finder (FROM-STUDIO 840): an engine
//! builds the finder its member's class calls for and no other, so the
//! second finder is charged only where two or more members can call both.
//! Until then one member of 34 MiB at `-m5 -md32m` was charged both and
//! named `-mm894m`, as the pair of a chains member and a tree member does.
//!
//! The rows here: rarfast's own refusal names the least figure (`-mm<k>m
//! or more lets it run`, exit 8), the create runs under it, and the child's
//! own peak resident set (`wait4`'s `ru_maxrss`, which reads at least the
//! macOS footprint the promise is read in) must not pass it. Inputs are
//! made here, of English words drawn by a fixed generator and of a fixed
//! keystream, so nothing is read from outside the test.
//!
//! Width and memory: the create runs at the machine's own width, as the
//! shipped binary does, and holds up to about 1.4 GiB. Unix only:
//! Windows has no `wait4`, and its peak is counted apart (owed).

#![cfg(unix)]

use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// An empty directory of the test's own.
fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-mm-peak-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A xorshift generator, the same on every run.
struct Draw(u64);

impl Draw {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

const WORDS: [&str; 24] = [
    "the", "quick", "brown", "fox", "jumps", "over", "a", "lazy", "dog", "volume", "member",
    "archive", "listing", "every", "part", "of", "set", "and", "memory", "process", "figure",
    "named", "window", "history",
];

/// About `size` bytes of lines of words.
fn text(draw: &mut Draw, size: usize) -> Vec<u8> {
    let mut body = String::with_capacity(size + 96);
    while body.len() < size {
        for word in 0..12 {
            if word > 0 {
                body.push(' ');
            }
            body.push_str(WORDS[(draw.next() % WORDS.len() as u64) as usize]);
        }
        body.push('\n');
    }
    body.into_bytes()
}

/// The syllables [`prose`] makes its words of.
const SYLLABLES: [&str; 12] = ["b", "c", "d", "f", "g", "l", "m", "n", "p", "r", "s", "t"];
const VOWELS: [&str; 8] = ["a", "e", "i", "o", "u", "an", "er", "in"];

/// `size` bytes of prose: lines of ten words drawn from 20,000 made-up
/// words of two to four syllables, which level 5's class reading gives the
/// TREE (the lines of [`text`] it gives the chains). Counted 25 Oct 2026 on
/// macOS at `-m5 -md32m`: 34 MiB of it held the tree's 384 MiB where those
/// lines held the chains' 260.
fn prose(draw: &mut Draw, size: usize) -> Vec<u8> {
    let syllable = |draw: &mut Draw| {
        let pick = (draw.next() % (SYLLABLES.len() * VOWELS.len()) as u64) as usize;
        [SYLLABLES[pick / VOWELS.len()], VOWELS[pick % VOWELS.len()]].concat()
    };
    let vocab: Vec<String> = (0..20_000)
        .map(|_| {
            let count = 2 + draw.next() % 3;
            (0..count).map(|_| syllable(draw)).collect()
        })
        .collect();
    let mut body = String::with_capacity(size + 256);
    while body.len() < size {
        for word in 0..10 {
            if word > 0 {
                body.push(' ');
            }
            body.push_str(&vocab[(draw.next() % vocab.len() as u64) as usize]);
        }
        body.push_str(".\n");
    }
    body.truncate(size);
    body.into_bytes()
}

/// `count` text files of 2 to 20 kB under `dir/text`, in 100 directories.
fn many_files(dir: &Path, count: usize) {
    let mut draw = Draw(0x2545_f491_4f6c_dd1d);
    for index in 0..count {
        let sub = dir.join("text").join(format!("d{:03}", index % 100));
        std::fs::create_dir_all(&sub).unwrap();
        let size = 2_000 + (draw.next() % 18_000) as usize;
        std::fs::write(sub.join(format!("f{index:05}.txt")), text(&mut draw, size)).unwrap();
    }
}

/// One file of `mib` MiB under `dir/big.bin`: each MiB 960 KiB of keystream
/// and 64 KiB of text, a member the store rule does not store whole.
fn big_file(dir: &Path, mib: usize) {
    use std::io::Write;
    let mut draw = Draw(0x9e37_79b9_7f4a_7c15);
    let mut words = Draw(0x1234_5678_9abc_def1);
    let mut out = std::io::BufWriter::new(std::fs::File::create(dir.join("big.bin")).unwrap());
    let mut chunk = vec![0_u8; 960 << 10];
    for _ in 0..mib {
        for word in chunk.chunks_mut(8) {
            word.copy_from_slice(&draw.next().to_le_bytes()[..word.len()]);
        }
        out.write_all(&chunk).unwrap();
        out.write_all(&text(&mut words, 64 << 10)[..64 << 10])
            .unwrap();
    }
    out.flush().unwrap();
}

/// One create's exit code, stderr, and the child's own peak resident set,
/// in bytes. The child is reaped by `wait4`, which is how its own usage is
/// read, and not by `Child::wait`, which the lint looks for.
#[allow(unsafe_code, clippy::zombie_processes)]
fn create(dir: &Path, args: &[&str]) -> (i32, String, u64) {
    let child = Command::new(rarfast())
        .args(args)
        .current_dir(dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id() as libc::pid_t;
    let mut stderr = child.stderr.unwrap();
    let mut said = String::new();
    std::io::Read::read_to_string(&mut stderr, &mut said).unwrap();
    let mut status = 0;
    // SAFETY: an all-zero `rusage` is a valid value of a plain C struct,
    // and `wait4` writes only into the two locals it is given, for the
    // child this test spawned and has not waited for.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    let waited = unsafe { libc::wait4(pid, &mut status, 0, &mut usage) };
    assert_eq!(waited, pid, "wait4 failed");
    let code = std::process::ExitStatus::from_raw(status)
        .code()
        .unwrap_or(-1);
    // macOS counts `ru_maxrss` in bytes, the other Unixes in KiB.
    let unit = if cfg!(target_os = "macos") { 1 } else { 1024 };
    (code, said, (usage.ru_maxrss as u64).saturating_mul(unit))
}

/// The least `-mm`, in MiB, rarfast admits for `switches` over `sources`:
/// from 100 MiB up, by the figure each refusal names.
fn least_mm(dir: &Path, switches: &[&str], sources: &[&str]) -> u64 {
    let mut mib = 100_u64;
    for _ in 0..4 {
        let mm = format!("-mm{mib}m");
        let mut args = vec!["a", mm.as_str()];
        args.extend_from_slice(switches);
        args.extend_from_slice(&["-idq", "-y", "probe.rar"]);
        args.extend_from_slice(sources);
        let (code, said, _) = create(dir, &args);
        let _ = std::fs::remove_file(dir.join("probe.rar"));
        if code == 0 {
            return mib;
        }
        let named = said
            .split("-mm")
            .filter_map(|tail| tail.split_once("m or more"))
            .find_map(|(digits, _)| digits.parse::<u64>().ok());
        let dictionary = said
            .split_once("Dictionary wanted ")
            .and_then(|(_, tail)| tail.split_once(' '))
            .and_then(|(digits, _)| digits.parse::<u64>().ok())
            .map(|bytes| bytes >> 20);
        mib = named
            .or(dictionary)
            .unwrap_or_else(|| panic!("no figure named (exit {code}): {said}"));
    }
    panic!("no admitted figure after four refusals");
}

/// The create under its least figure: admitted, and the process inside it.
/// Answers the figure, in MiB.
fn holds_its_least_figure(dir: &Path, switches: &[&str], sources: &[&str]) -> u64 {
    let mib = least_mm(dir, switches, sources);
    let mm = format!("-mm{mib}m");
    let mut args = vec!["a", mm.as_str()];
    args.extend_from_slice(switches);
    args.extend_from_slice(&["-idq", "-y", "out.rar"]);
    args.extend_from_slice(sources);
    let (code, said, peak) = create(dir, &args);
    let _ = std::fs::remove_file(dir.join("out.rar"));
    assert_eq!(code, 0, "{switches:?} at {mm}: {said}");
    assert!(
        peak <= mib << 20,
        "{switches:?} at {mm}: the process peaked at {:.1} MiB, {:+.1} over the figure",
        peak as f64 / (1 << 20) as f64,
        peak as f64 / (1 << 20) as f64 - mib as f64
    );
    mib
}

/// Every input in one test, so that no other test's child runs beside the
/// measured one in this binary.
#[test]
fn the_process_holds_the_least_named_mm_on_many_files_one_big_file_and_one_member() {
    let dir = work("rows");
    // Many files, solid: 13,000 files, about 143 MB of text, more than the
    // dictionary, so the stream's history fills it.
    many_files(&dir, 13_000);
    holds_its_least_figure(&dir, &["-m5", "-md128m", "-s", "-r"], &["text"]);
    // The same files one at a time at `-md32m`, where both of level 5's
    // finders live at once and a worker team runs beside the lead: the
    // case whose process passed its figure by 52 MiB before chain 40.
    holds_its_least_figure(&dir, &["-m5", "-md32m", "-r"], &["text"]);
    // One big file, solid at the same dictionary: 384 MiB.
    big_file(&dir, 384);
    holds_its_least_figure(&dir, &["-m5", "-md128m", "-s"], &["big.bin"]);
    // ONE member is charged one finder (FROM-STUDIO 840): the chains for
    // the lines of words, the tree for prose, each held inside its least
    // figure. Beside each other the two are charged both finders, the
    // chains' 260 MiB more at `-md32m`; until 840 one member was charged
    // both too, and its least figure was the pair's.
    std::fs::write(
        dir.join("lines.txt"),
        &text(&mut Draw(0x5eed_0034_7e47_0001), 34 << 20)[..34 << 20],
    )
    .unwrap();
    std::fs::write(
        dir.join("prose.txt"),
        prose(&mut Draw(0x5eed_0034_9705_0001), 34 << 20),
    )
    .unwrap();
    let md32 = ["-m5", "-md32m", "-ep1"];
    let lines = holds_its_least_figure(&dir, &md32, &["lines.txt"]);
    let prose = holds_its_least_figure(&dir, &md32, &["prose.txt"]);
    let both = holds_its_least_figure(&dir, &md32, &["lines.txt", "prose.txt"]);
    assert!(
        lines + 200 <= both && prose + 200 <= both,
        "one member at -mm{lines}m (lines) and -mm{prose}m (prose), the two at -mm{both}m: one member is charged one finder"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
