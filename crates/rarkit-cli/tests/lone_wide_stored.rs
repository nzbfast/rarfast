//! ONE STORED MEMBER ALONE, IN MEMORY, is read wide for `x` and `e`
//! (`dialect::unrar::extract::lone_wide_stored`, release blocker 4),
//! through the whole command, in a build that reads the knobs.
//!
//! Before the rule such a member was read, checked and written on ONE
//! thread when it was under the seam's floor (32 MiB), and by one reader
//! feeding one writer above it. What must hold now is that a member of
//! the rule's shape is no longer either of those (the engine's seam is not
//! asked about it at all, so `RARKIT_SEAM_SAY=1` prints no line for it),
//! that every shape the rule leaves alone is asked as before, and that NO
//! BYTE AND NO VERDICT moves with it.
//!
//! The page cache's answer is stated (`RARFAST_RESIDENT`), so a case
//! never depends on what the box holds. The rule is shipped on macOS
//! from 16 MiB where the cache holds the archive, on Windows from 32 MiB
//! with no cache term (Windows has no sample of it), and on Linux from 32
//! MiB to under 128 MiB with no cache term (the stored route samples none
//! there).
//!
//! Width and memory: the default width of the box the test runs on (the
//! rule wants two or more; hosted runners are 2 to 4 wide), and an
//! archive of 16 MiB plus its output, about 34 MiB on disk; the read holds
//! at most the rule's 4 MiB read-ahead.
//!
//! Those knobs exist only under the feature `read-depth-knob`; the knob
//! test runner (`make test-knob-spawn`) builds it and runs this:
//!
//! ```text
//! cargo test -p rarkit-cli --features read-depth-knob --test lone_wide_stored
//! ```
#![cfg(feature = "read-depth-knob")]

use std::path::PathBuf;
use std::process::{Command, Output};

#[path = "support/exe_copy.rs"]
mod exe_copy;
use exe_copy::{copy_executable, output_of, rarfast};

const MIB: usize = 1 << 20;

/// Whether this system takes the 16 MiB member of these cases: macOS
/// alone (the Windows floor is 32 MiB, and there a 16 MiB member keeps the
/// route before the rule).
const SHIPPED: bool = cfg!(target_os = "macos");

struct Bench {
    dir: PathBuf,
    unrar: PathBuf,
    /// `RARFAST_LONE_WIDE`'s word for the runs that follow, or unset.
    knob: std::cell::RefCell<Option<&'static str>>,
}

/// Noise a stored member is made of (a linear congruential stream).
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

impl Bench {
    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("rarfast-lone-wide-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        // A copy named `unrar` is how the binary picks that dialect.
        let unrar = dir.join("unrar");
        copy_executable(&rarfast(), &unrar);
        Self {
            dir,
            unrar,
            knob: std::cell::RefCell::new(None),
        }
    }

    fn write(&self, name: &str, bytes: &[u8]) {
        std::fs::write(self.dir.join("src").join(name), bytes).unwrap();
    }

    /// `rarfast a -m0 <archive> <files>` in the source directory.
    fn create(&self, archive: &str, files: &[&str]) {
        let out = output_of(
            Command::new(rarfast())
                .args(["a", "-m0", "-idq", &format!("../{archive}")])
                .args(files)
                .current_dir(self.dir.join("src")),
        )
        .expect("rarfast a runs");
        ok(&out, &format!("rarfast a {archive}"));
    }

    /// `unrar <command> -idq -y <extra> <archive> <into>/` into a fresh
    /// directory, the cache's answer stated, the rule and the seam said.
    fn extract(
        &self,
        command: &str,
        archive: &str,
        into: &str,
        extra: &[&str],
        resident: &str,
    ) -> Output {
        self.extract_by(&self.unrar, command, archive, into, extra, resident)
    }

    /// [`Self::extract`] by `tool`: the `unrar` copy, or `rarfast` itself,
    /// whose own dialect carries a stated `-mm` to the read (the `unrar`
    /// name accepts the switch and does nothing with it).
    fn extract_by(
        &self,
        tool: &PathBuf,
        command: &str,
        archive: &str,
        into: &str,
        extra: &[&str],
        resident: &str,
    ) -> Output {
        let dest = self.dir.join(into);
        let _ = std::fs::remove_dir_all(&dest);
        std::fs::create_dir_all(&dest).unwrap();
        let target = format!("{into}/");
        let mut args = vec![command, "-idq", "-y"];
        args.extend_from_slice(extra);
        args.push(archive);
        args.push(&target);
        let mut run = Command::new(tool);
        run.args(&args)
            .current_dir(&self.dir)
            .env("RARFAST_RESIDENT", resident)
            .env("RARFAST_LONE_WIDE_SAY", "1")
            .env("RARKIT_SEAM_SAY", "1")
            .env_remove("RARFAST_LONE_WIDE")
            .env_remove("RARFAST_POOL")
            .env_remove("RARFAST_X_READ_AHEAD_MIB")
            .env_remove("RARKIT_SEAM_FROM_MIB")
            .env_remove("RARFAST_COLD_WINDOW");
        if let Some(word) = *self.knob.borrow() {
            run.env("RARFAST_LONE_WIDE", word);
            // The count arm keeps the rule's other guard, the source's cold
            // window, so its cases run with the window off: a cold archive
            // then has none, as on a system that never arms one.
            run.env("RARFAST_COLD_WINDOW", "0");
        }
        output_of(&mut run).expect("unrar runs")
    }

    fn same(&self, into: &str, names: &[&str]) {
        for name in names {
            let want = std::fs::read(self.dir.join("src").join(name)).unwrap();
            let got = std::fs::read(self.dir.join(into).join(name))
                .unwrap_or_else(|e| panic!("{into}/{name}: {e}"));
            assert!(want == got, "{into}/{name} differs from its source");
        }
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn ok(out: &Output, what: &str) {
    assert!(
        out.status.success(),
        "{what}: {:?} {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// What the engine's seam said of the stored members it was asked about,
/// in order: `seam` or `in sequence` each.
fn seam_lines(out: &Output) -> Vec<String> {
    String::from_utf8_lossy(&out.stderr)
        .lines()
        .filter_map(|line| line.split_once("bytes: ").map(|(_, rest)| rest.trim()))
        .map(str::to_string)
        .collect()
}

/// Whether the run said the rule took its member.
fn taken(out: &Output) -> bool {
    let text = String::from_utf8_lossy(&out.stderr);
    text.lines()
        .filter_map(|line| line.split_once("rarfast lone wide: ").map(|(_, rest)| rest))
        .next_back()
        .unwrap_or_else(|| panic!("no lone wide line in {text:?}"))
        .trim()
        == "taken"
}

/// The rule's shape: one clear stored member alone in its archive and in
/// memory, at 16 MiB (the engine's wide read floor) and at 33 MiB (over the
/// seam's 32 MiB floor, and over the Windows floor of the rule). Before
/// the rule the first was read, checked and written in turn on one thread
/// (the seam said `in sequence`) and the second was the seam's; now where
/// the system takes it the seam is not asked and the member is read wide,
/// for `x` and for `e` alike, with the same bytes. Where it is not taken
/// the seam says what it said before.
#[test]
fn a_lone_member_in_memory_is_read_wide() {
    let bench = Bench::new("lone");
    // (the member's MiB, whether this system's rule takes it, what the
    // seam says where it does not)
    let sizes = [
        (16, SHIPPED, "in sequence"),
        // On Windows the lone write takes this one from the rule
        // (`tests/lone_write_windows.rs`), and the walk reads it in turn.
        (
            33,
            SHIPPED || cfg!(target_os = "linux"),
            if cfg!(windows) { "in sequence" } else { "seam" },
        ),
    ];
    for (mib, takes, seam) in sizes {
        let name = format!("st{mib}m.bin");
        let archive = format!("lone{mib}.rar");
        bench.write(&name, &noise(mib * MIB, mib as u64));
        bench.create(&archive, &[&name]);
        for command in ["x", "e"] {
            let into = format!("out-{mib}-{command}");
            let out = bench.extract(command, &archive, &into, &[], "1");
            let what = format!("{command} {mib} MiB");
            ok(&out, &what);
            bench.same(&into, &[&name]);
            if takes {
                assert!(
                    seam_lines(&out).is_empty(),
                    "{what}: the seam is not asked of a member read wide: {:?}",
                    seam_lines(&out)
                );
                assert!(taken(&out), "{what}: the rule took it");
            } else {
                assert!(!taken(&out), "{what}: not taken here");
                assert_eq!(seam_lines(&out), [seam], "{what}");
            }
        }
    }
}

/// Every shape the rule leaves alone keeps its route, byte for byte: the
/// archive not in memory, a stated `-mt1`, a stated `-mm` (by `rarfast`
/// itself, which carries it), a member under the wide read's floor, and
/// two files where there was one.
#[test]
fn the_shapes_it_leaves_alone_keep_their_route() {
    let bench = Bench::new("alone");
    bench.write("st16m.bin", &noise(16 * MIB, 2));
    bench.write("small.bin", &noise(15 * MIB, 3));
    bench.write("note.nfo", b"release notes\n");
    bench.create("lone.rar", &["st16m.bin"]);
    bench.create("small.rar", &["small.bin"]);
    bench.create("two.rar", &["st16m.bin", "note.nfo"]);
    let rarfast = rarfast();
    // (the tool, the archive, its switches, the cache's answer, the files)
    type Case<'a> = (&'a PathBuf, &'a str, &'a [&'a str], &'a str, &'a [&'a str]);
    let cases: [Case; 5] = [
        (&bench.unrar, "lone.rar", &[], "0", &["st16m.bin"]),
        (&bench.unrar, "lone.rar", &["-mt1"], "1", &["st16m.bin"]),
        (&rarfast, "lone.rar", &["-mm256m"], "1", &["st16m.bin"]),
        (&bench.unrar, "small.rar", &[], "1", &["small.bin"]),
        (
            &bench.unrar,
            "two.rar",
            &[],
            "1",
            &["st16m.bin", "note.nfo"],
        ),
    ];
    for (i, (tool, archive, extra, resident, names)) in cases.iter().enumerate() {
        let into = format!("out-{i}");
        let out = bench.extract_by(tool, "x", archive, &into, extra, resident);
        let what = format!("x {extra:?} {archive} resident {resident}");
        ok(&out, &what);
        bench.same(&into, names);
        assert!(!taken(&out), "{what}: the rule leaves it alone");
    }
}

/// THE COUNT ARM (`RARFAST_LONE_WIDE=any`): the rule on ANY system and
/// without asking the page cache, for a count on a system that has no
/// sample of it (Windows answers Unknown). The archive is stated cold
/// here, with the source's cold window off (`RARFAST_COLD_WINDOW=0`, which
/// the arm still refuses beside), so the shipped rule refuses it; under
/// `any` it is taken, the seam is not asked, and the bytes are the same.
/// `0` refuses it; `1` (the shipped rule) refuses the cold archive where
/// the rule asks the cache, and on Windows and Linux, which ask nothing,
/// takes it.
/// The member is 32 MiB, at the floor of every system that ships the rule.
#[test]
fn the_count_arm_takes_it_on_any_system_unasked() {
    let bench = Bench::new("any");
    bench.write("st32m.bin", &noise(32 * MIB, 4));
    bench.create("lone.rar", &["st32m.bin"]);
    *bench.knob.borrow_mut() = Some("any");
    for command in ["x", "e"] {
        let into = format!("any-{command}");
        let out = bench.extract(command, "lone.rar", &into, &[], "0");
        ok(&out, command);
        bench.same(&into, &["st32m.bin"]);
        assert!(taken(&out), "{command}: the count arm took it");
        assert!(
            seam_lines(&out).is_empty(),
            "{command}: {:?}",
            seam_lines(&out)
        );
    }
    // (the knob's word, the cache's answer, taken)
    let unasked = cfg!(windows) || cfg!(target_os = "linux");
    for (word, resident, took) in [("0", "1", false), ("1", "0", unasked)] {
        *bench.knob.borrow_mut() = Some(word);
        let into = format!("word-{word}");
        let out = bench.extract("x", "lone.rar", &into, &[], resident);
        ok(&out, &into);
        bench.same(&into, &["st32m.bin"]);
        assert_eq!(taken(&out), took, "{into}");
    }
}

/// THE LINUX ARM at its edges, through the whole command and the shipped
/// word (the knob unset): a lone stored member is taken from 32 MiB to
/// under 128 MiB, warm or stated cold alike (Linux asks no cache), and not
/// a byte under 32 MiB nor at 128 MiB, where the seam is asked as before;
/// a stated `-mt1` still refuses it by the rule's own guard. No byte moves.
///
/// Width and memory: the box's default width; one member at a time, at
/// most 128 MiB in this process and about 256 MiB on disk with its
/// archive and output, each removed before the next.
#[cfg(target_os = "linux")]
#[test]
fn the_linux_arm_takes_32_to_under_128_mib() {
    let bench = Bench::new("linux");
    // (the member's bytes, the cache's answer, the switches, taken)
    let cases: [(usize, &str, &[&str], bool); 7] = [
        (32 * MIB - 1, "1", &[], false),
        (32 * MIB, "1", &[], true),
        (32 * MIB, "0", &[], true),
        (32 * MIB, "1", &["-mt1"], false),
        (64 * MIB, "1", &[], true),
        (128 * MIB - 1, "1", &[], true),
        (128 * MIB, "1", &[], false),
    ];
    for (i, (len, resident, extra, takes)) in cases.into_iter().enumerate() {
        let name = format!("m{i}.bin");
        let archive = format!("m{i}.rar");
        bench.write(&name, &noise(len, 40 + i as u64));
        bench.create(&archive, &[&name]);
        for command in ["x", "e"] {
            let into = format!("out-{i}-{command}");
            let out = bench.extract(command, &archive, &into, extra, resident);
            let what = format!("{command} {len} bytes {extra:?} resident {resident}");
            ok(&out, &what);
            bench.same(&into, &[&name]);
            assert_eq!(taken(&out), takes, "{what}");
            if takes {
                assert!(
                    seam_lines(&out).is_empty(),
                    "{what}: {:?}",
                    seam_lines(&out)
                );
            }
            let _ = std::fs::remove_dir_all(bench.dir.join(&into));
        }
        let _ = std::fs::remove_file(bench.dir.join("src").join(&name));
        let _ = std::fs::remove_file(bench.dir.join(&archive));
    }
}
