//! The cold stored route's read WINDOW (`src/window.rs`), through the whole
//! command, in a build that reads the knobs.
//!
//! The window is a cache of the archive file under the engine: a thread
//! reads the file in order, two slabs ahead, and the walk's reads are
//! copied out of the slabs. What must hold is that NO BYTE AND NO VERDICT
//! moves: every member extracts to the bytes it was made of, and a damaged
//! archive is reported as it is without the window. That is tested here on
//! every shape the stored route can meet, with the page cache's answer
//! STATED cold (`RARFAST_RESIDENT=0`), the window switched on
//! (`RARFAST_COLD_WINDOW=1`) and its slab made small
//! (`RARFAST_COLD_WINDOW_KIB`), so members cross many slabs and a slab
//! holds many members, and with what the window served read from the line
//! `RARFAST_COLD_WINDOW_SAY=1` prints. The window's reader also ASKS THE
//! KERNEL AHEAD of its own reads (`RARFAST_COLD_WINDOW_ASK`, on as
//! shipped): the same holds with the request on and off, and the line says
//! how many bytes were asked for.
//!
//! The stored route walks on macOS only (`extract::STORED_WRITTEN_WALKS`),
//! so the window engages there and nowhere else: on every other system
//! the same commands must write the same bytes and print no window line.
//!
//! Those knobs exist only under the feature `read-depth-knob`;
//! The knob test runner (`make test-knob-spawn`) builds it and runs this:
//!
//! ```text
//! cargo test -p rarkit-cli --features read-depth-knob --test cold_window
//! ```
#![cfg(feature = "read-depth-knob")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[path = "support/exe_copy.rs"]
mod exe_copy;
use exe_copy::{copy_executable, output_of, rarfast};

const KIB: usize = 1 << 10;

/// How the window's say line begins.
const SAID: &str = "rarfast window: ";

/// Whether this system's stored archives take the walk, and so the window.
const WALKS: bool = cfg!(target_os = "macos");

struct Bench {
    dir: PathBuf,
    unrar: PathBuf,
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
            std::env::temp_dir().join(format!("rarfast-cold-window-{}-{tag}", std::process::id()));
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

    /// `unrar <args>` with the archive stated COLD, the window `on` or
    /// off, its slab `slab_kib`, and the say line asked for.
    fn unrar(&self, args: &[&str], on: bool, slab_kib: usize) -> Output {
        self.run(&self.unrar, args, on, slab_kib)
    }

    /// The same under the binary's own name, the `rar` dialect, which is
    /// where `-mm` is a switch.
    fn rar(&self, args: &[&str], on: bool, slab_kib: usize) -> Output {
        self.run(&rarfast(), args, on, slab_kib)
    }

    fn run(&self, binary: &Path, args: &[&str], on: bool, slab_kib: usize) -> Output {
        let mut command = Command::new(binary);
        command
            .args(args)
            .current_dir(&self.dir)
            .env("RARFAST_RESIDENT", "0")
            .env("RARFAST_COLD_WINDOW", if on { "1" } else { "0" })
            .env("RARFAST_COLD_WINDOW_KIB", slab_kib.to_string())
            .env("RARFAST_COLD_WINDOW_SAY", "1")
            .env_remove("RARFAST_POOL")
            .env_remove("RARKIT_STORED_CUT");
        output_of(&mut command).expect("unrar runs")
    }

    /// Extract `archive` into a fresh directory `into` and return the run.
    fn extract(
        &self,
        archive: &str,
        into: &str,
        extra: &[&str],
        on: bool,
        slab_kib: usize,
    ) -> Output {
        let dest = self.dir.join(into);
        let _ = std::fs::remove_dir_all(&dest);
        std::fs::create_dir_all(&dest).unwrap();
        let mut args = vec!["x", "-idq", "-y"];
        args.extend_from_slice(extra);
        let target = format!("{into}/");
        args.push(archive);
        args.push(&target);
        self.unrar(&args, on, slab_kib)
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

/// The window's lines out of a run's stderr: `(served, of, passed)` a file.
/// A line may follow a complaint that ended without a newline, so it is
/// found wherever it begins.
fn window_lines(out: &Output) -> Vec<(u64, u64, u64)> {
    String::from_utf8_lossy(&out.stderr)
        .lines()
        .filter_map(|line| line.split_once(SAID).map(|(_, rest)| rest.to_string()))
        .map(|rest| {
            let numbers: Vec<u64> = rest
                .split(|c: char| !c.is_ascii_digit())
                .filter(|word| !word.is_empty())
                .map(|word| word.parse().unwrap())
                .collect();
            (numbers[0], numbers[1], numbers[2])
        })
        .collect()
}

fn archive_len(dir: &Path, name: &str) -> u64 {
    std::fs::metadata(dir.join(name)).unwrap().len()
}

/// A set of many members: several stored members, sizes on and off every
/// boundary, extracted cold through the window at slabs smaller and larger
/// than a member. Every byte is the source's, and on a system that walks
/// the window served nearly the whole archive.
#[test]
fn a_cold_stored_set_of_many_members_extracts_to_its_bytes_through_the_window() {
    let bench = Bench::new("subset");
    let sizes = [
        300 * KIB,
        64 * KIB,
        64 * KIB + 1,
        1,
        0,
        777 * KIB + 13,
        128 * KIB - 1,
        2 * 1024 * KIB,
    ];
    let names: Vec<String> = (0..sizes.len()).map(|i| format!("e{i:02}.bin")).collect();
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    for (i, (name, size)) in names.iter().zip(sizes).enumerate() {
        bench.write(name, &noise(size, 11 + i as u64));
    }
    bench.create(&["-m0"], "subset.rar", &names);
    let len = archive_len(&bench.dir, "subset.rar");

    for slab_kib in [16usize, 64, 100, 1024, 8192] {
        let into = format!("out-{slab_kib}");
        let out = bench.extract("subset.rar", &into, &[], true, slab_kib);
        assert!(
            out.status.success(),
            "slab {slab_kib}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        bench.same(&into, &names);
        let lines = window_lines(&out);
        // A file under half a slab is brought in by one read and gets no
        // window (`engine::window_of`).
        let floor = (slab_kib * KIB / 2) as u64;
        if WALKS && len >= floor {
            assert_eq!(
                lines.len(),
                1,
                "slab {slab_kib}: one archive file, one window"
            );
            let (served, of, _) = lines[0];
            assert_eq!(of, len);
            // Everything from the walk's first read on: the members' bytes
            // and the headers between them (a header's bytes are asked for
            // more than once, so the count may pass the file's length).
            assert!(
                served * 10 >= len * 9 && served <= len + len / 10,
                "slab {slab_kib}: served {served} of {len}"
            );
        } else {
            assert!(
                lines.is_empty(),
                "slab {slab_kib}: no window under the floor or off the walking systems"
            );
        }
    }
    assert!(
        len < 8192 * KIB as u64 / 2 && len >= 1024 * KIB as u64 / 2,
        "the largest slab above is the one the floor refuses: {len}"
    );

    // A set under BLAKE2sp records is the stored route's too.
    bench.create(&["-m0", "-htb"], "blake.rar", &names);
    let out = bench.extract("blake.rar", "out-blake", &[], true, 64);
    assert!(
        out.status.success(),
        "-htb: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    bench.same("out-blake", &names);
    assert_eq!(window_lines(&out).len(), usize::from(WALKS), "-htb");

    // The knob off: the same bytes, and no window.
    let out = bench.extract("subset.rar", "out-off", &[], false, 64);
    assert!(out.status.success());
    bench.same("out-off", &names);
    assert!(window_lines(&out).is_empty(), "off is off");
}

/// The fourth number of the window's line: the bytes its reader asked the
/// kernel for ahead of its own reads.
fn asked_ahead(out: &Output) -> Vec<u64> {
    String::from_utf8_lossy(&out.stderr)
        .lines()
        .filter_map(|line| line.split_once(SAID).map(|(_, rest)| rest.to_string()))
        .map(|rest| {
            rest.split(|c: char| !c.is_ascii_digit())
                .filter(|word| !word.is_empty())
                .nth(3)
                .expect("the line says what was asked ahead")
                .parse()
                .unwrap()
        })
        .collect()
}

/// **The window's reader asks the kernel ahead, and no byte or verdict
/// moves by it.** As shipped the request is on wherever there is a window:
/// the set extracts to its bytes and the line counts what was asked,
/// never more than the archive holds. `RARFAST_COLD_WINDOW_ASK=0` is the
/// window with no request: the same bytes, the same bytes served, nothing
/// asked. A damaged archive is reported alike with it on and off.
#[test]
fn the_request_ahead_moves_no_byte_and_its_knob_switches_it_off() {
    let bench = Bench::new("ask");
    let sizes = [300 * KIB, 64 * KIB + 1, 0, 777 * KIB + 13, 2 * 1024 * KIB];
    let names: Vec<String> = (0..sizes.len()).map(|i| format!("e{i:02}.bin")).collect();
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    for (i, (name, size)) in names.iter().zip(sizes).enumerate() {
        bench.write(name, &noise(size, 41 + i as u64));
    }
    bench.create(&["-m0"], "subset.rar", &names);
    let len = archive_len(&bench.dir, "subset.rar");
    let run = |into: &str, ask: Option<&str>, archive: &str| {
        let dest = bench.dir.join(into);
        let _ = std::fs::remove_dir_all(&dest);
        std::fs::create_dir_all(&dest).unwrap();
        let target = format!("{into}/");
        let mut command = Command::new(&bench.unrar);
        command
            .args(["x", "-idq", "-y", archive, &target])
            .current_dir(&bench.dir)
            .env("RARFAST_RESIDENT", "0")
            .env("RARFAST_COLD_WINDOW", "1")
            .env("RARFAST_COLD_WINDOW_KIB", "64")
            .env("RARFAST_COLD_WINDOW_SAY", "1")
            .env_remove("RARFAST_COLD_WINDOW_ADVISE_MIB")
            .env_remove("RARFAST_POOL")
            .env_remove("RARKIT_STORED_CUT");
        match ask {
            Some(word) => command.env("RARFAST_COLD_WINDOW_ASK", word),
            None => command.env_remove("RARFAST_COLD_WINDOW_ASK"),
        };
        output_of(&mut command).expect("unrar runs")
    };

    let shipped = run("out-shipped", None, "subset.rar");
    assert!(shipped.status.success());
    bench.same("out-shipped", &names);
    let off = run("out-noask", Some("0"), "subset.rar");
    assert!(off.status.success());
    bench.same("out-noask", &names);
    if WALKS {
        let asked = asked_ahead(&shipped);
        assert_eq!(asked.len(), 1, "one archive file, one window");
        assert!(
            asked[0] > 0 && asked[0] <= len,
            "as shipped the reader asks ahead, and for no more than the file: {} of {len}",
            asked[0]
        );
        assert_eq!(asked_ahead(&off), [0], "the knob off asks for nothing");
        assert_eq!(
            window_lines(&shipped)[0].1,
            window_lines(&off)[0].1,
            "the same archive either way"
        );
    } else {
        assert!(asked_ahead(&shipped).is_empty() && asked_ahead(&off).is_empty());
    }

    // One flipped byte in a member's data: the same verdict either way.
    let mut bytes = std::fs::read(bench.dir.join("subset.rar")).unwrap();
    let at = bytes.len() / 2;
    bytes[at] ^= 0x55;
    std::fs::write(bench.dir.join("bad.rar"), &bytes).unwrap();
    let on = run("bad-on", None, "bad.rar");
    let none = run("bad-off", Some("off"), "bad.rar");
    assert!(!on.status.success(), "the damage is reported");
    assert_eq!(on.status.code(), none.status.code());
    assert_eq!(on.stdout, none.stdout);
}

/// The conditions the window is not for: a stated `-mm`, `-mt1`, `t`, a
/// solid archive, a compressed one. Each extracts or tests as it does
/// without the knob, and opens no window. An ENCRYPTED stored archive is
/// the window's as a clear one is, and at `-mt1` it opens none either.
#[test]
fn the_window_is_only_the_deep_stored_routes() {
    let bench = Bench::new("only");
    let names = ["a.bin", "b.bin", "c.bin"];
    for (i, name) in names.iter().enumerate() {
        bench.write(name, &noise(400 * KIB + i, 31 + i as u64));
    }
    let text: Vec<u8> = b"the quick brown fox jumps over the lazy dog\n"
        .iter()
        .copied()
        .cycle()
        .take(900 * KIB)
        .collect();
    bench.write("text.txt", &text);
    bench.create(&["-m0"], "plain.rar", &names);
    bench.create(&["-m0", "-psecret"], "cipher.rar", &names);
    bench.create(&["-m0", "-s"], "solid.rar", &names);
    bench.create(&["-m3"], "packed.rar", &["text.txt"]);

    // One thread: the bytes, no window.
    let out = bench.extract("plain.rar", "out-mt1", &["-mt1"], true, 64);
    assert!(
        out.status.success(),
        "mt1: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    bench.same("out-mt1", &names);
    assert!(window_lines(&out).is_empty(), "-mt1 opens no window");
    // A stated memory limit (a switch of the `rar` name): the bytes, no
    // window.
    std::fs::create_dir_all(bench.dir.join("out-mm")).unwrap();
    let out = bench.rar(
        &["x", "-idq", "-y", "-mm256m", "plain.rar", "out-mm/"],
        true,
        64,
    );
    assert!(
        out.status.success(),
        "mm: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    bench.same("out-mm", &names);
    assert!(window_lines(&out).is_empty(), "-mm opens no window");
    // The same command with no limit stated does open one, where the
    // stored route walks: the two differ in the limit alone.
    std::fs::create_dir_all(bench.dir.join("out-nomm")).unwrap();
    let out = bench.rar(&["x", "-idq", "-y", "plain.rar", "out-nomm/"], true, 64);
    assert!(out.status.success());
    bench.same("out-nomm", &names);
    assert_eq!(window_lines(&out).len(), usize::from(WALKS));
    // `t` writes nothing: no window.
    let out = bench.unrar(&["t", "-idq", "plain.rar"], true, 64);
    assert!(out.status.success());
    assert!(window_lines(&out).is_empty(), "t opens no window");
    // A volume set whose members cross volumes is split jobs' ground, not
    // the stored walk's: the bytes, no window on any volume.
    bench.create(&["-m0", "-v700k"], "vol.rar", &names);
    let mut volumes: Vec<String> = std::fs::read_dir(&bench.dir)
        .unwrap()
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter(|name| name.starts_with("vol.") && name.ends_with(".rar"))
        .collect();
    volumes.sort();
    assert!(volumes.len() > 1, "a set of several volumes: {volumes:?}");
    let out = bench.extract(&volumes[0], "out-vol", &[], true, 64);
    assert!(
        out.status.success(),
        "volumes: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    bench.same("out-vol", &names);
    assert!(
        window_lines(&out).is_empty(),
        "split members open no window"
    );
    // Encrypted: the bytes, through a window where the stored route
    // walks; at one thread the bytes and no window.
    let out = bench.extract("cipher.rar", "out-cipher", &["-psecret"], true, 64);
    assert!(
        out.status.success(),
        "cipher: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    bench.same("out-cipher", &names);
    assert_eq!(
        window_lines(&out).len(),
        usize::from(WALKS),
        "an encrypted stored archive is read through the window"
    );
    let out = bench.extract(
        "cipher.rar",
        "out-cipher-mt1",
        &["-psecret", "-mt1"],
        true,
        64,
    );
    assert!(out.status.success());
    bench.same("out-cipher-mt1", &names);
    assert!(
        window_lines(&out).is_empty(),
        "an encrypted archive at -mt1 opens no window"
    );
    // Solid, compressed: the bytes, no window.
    for (tag, archive, extra, files) in [
        ("solid", "solid.rar", "-p-", &names[..]),
        ("packed", "packed.rar", "-p-", &["text.txt"][..]),
    ] {
        let into = format!("out-{tag}");
        let out = bench.extract(archive, &into, &[extra], true, 64);
        assert!(
            out.status.success(),
            "{tag}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        bench.same(&into, files);
        assert!(window_lines(&out).is_empty(), "{tag} opens no window");
    }
}

/// A selection: only some members are extracted, so the walk skips the
/// others' bytes. The members asked for are their sources, the others are
/// not written, and no window is opened (it would read on behind them).
#[test]
fn a_selection_skips_members_and_the_window_follows() {
    let bench = Bench::new("select");
    let names = ["one.bin", "two.bin", "three.bin", "four.bin", "five.bin"];
    for (i, name) in names.iter().enumerate() {
        bench.write(name, &noise(600 * KIB + 7 * i, 51 + i as u64));
    }
    bench.create(&["-m0"], "set.rar", &names);
    for slab_kib in [16usize, 64, 4096] {
        let into = format!("out-{slab_kib}");
        let dest = bench.dir.join(&into);
        let _ = std::fs::remove_dir_all(&dest);
        std::fs::create_dir_all(&dest).unwrap();
        let target = format!("{into}/");
        let out = bench.unrar(
            &["x", "-idq", "-y", "set.rar", "two.bin", "five.bin", &target],
            true,
            slab_kib,
        );
        assert!(
            out.status.success(),
            "slab {slab_kib}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        bench.same(&into, &["two.bin", "five.bin"]);
        for skipped in ["one.bin", "three.bin", "four.bin"] {
            assert!(!dest.join(skipped).exists(), "{skipped} was not asked for");
        }
        // A selection keeps the route it had: the window is for a command
        // that extracts every file.
        assert!(
            window_lines(&out).is_empty(),
            "slab {slab_kib}: a selection opens no window"
        );
    }
}

/// A damaged archive is reported through the window exactly as without
/// it: the same exit code and the same complaint, the members before the
/// damage whole.
#[test]
fn damage_is_reported_as_it_is_without_the_window() {
    let bench = Bench::new("damage");
    let names = ["a.bin", "b.bin", "c.bin"];
    for (i, name) in names.iter().enumerate() {
        bench.write(name, &noise(500 * KIB, 71 + i as u64));
    }
    bench.create(&["-m0"], "set.rar", &names);
    // One byte of the second member's data flipped, and a copy cut short
    // inside the third.
    let whole = std::fs::read(bench.dir.join("set.rar")).unwrap();
    let mut flipped = whole.clone();
    let at = 750 * KIB;
    flipped[at] ^= 0x40;
    std::fs::write(bench.dir.join("flipped.rar"), &flipped).unwrap();
    std::fs::write(bench.dir.join("cut.rar"), &whole[..1200 * KIB]).unwrap();

    for archive in ["flipped.rar", "cut.rar"] {
        let off = bench.extract(archive, "out-off", &[], false, 64);
        for slab_kib in [16usize, 64, 4096] {
            let on = bench.extract(archive, "out-on", &[], true, slab_kib);
            assert_eq!(
                on.status.code(),
                off.status.code(),
                "{archive} slab {slab_kib}: the exit code"
            );
            let strip = |out: &Output| -> String {
                String::from_utf8_lossy(&out.stderr)
                    .lines()
                    .filter(|line| !line.starts_with(SAID))
                    .map(|line| line.split_once(SAID).map_or(line, |(before, _)| before))
                    .map(|line| line.replace("out-on", "out-off"))
                    .collect::<Vec<_>>()
                    .join("\n")
                    .trim_end()
                    .to_string()
            };
            assert_eq!(
                strip(&on),
                strip(&off),
                "{archive} slab {slab_kib}: the complaint"
            );
            bench.same("out-on", &["a.bin"]);
            // What was written of the damaged members is what is written
            // without the window, byte for byte.
            for name in ["b.bin", "c.bin"] {
                let with = std::fs::read(bench.dir.join("out-on").join(name)).ok();
                let without = std::fs::read(bench.dir.join("out-off").join(name)).ok();
                assert!(with == without, "{archive} slab {slab_kib}: {name}");
            }
        }
    }
}

/// An ENCRYPTED stored archive through the window: a wrong password, one
/// flipped ciphertext byte and an archive cut short are each reported
/// exactly as they are without the window, the exit code, the complaint
/// and whatever was written, with the data alone encrypted (`-p`) and with
/// the headers encrypted too (`-hp`).
#[test]
fn an_encrypted_archives_damage_is_reported_as_it_is_without_the_window() {
    let bench = Bench::new("cipher-damage");
    let names = ["a.bin", "b.bin", "c.bin"];
    for (i, name) in names.iter().enumerate() {
        bench.write(name, &noise(500 * KIB + 7 * i, 91 + i as u64));
    }
    let strip = |out: &Output| -> String {
        String::from_utf8_lossy(&out.stderr)
            .lines()
            .filter(|line| !line.starts_with(SAID))
            .map(|line| line.split_once(SAID).map_or(line, |(before, _)| before))
            .map(|line| line.replace("out-on", "out-off"))
            .collect::<Vec<_>>()
            .join("\n")
            .trim_end()
            .to_string()
    };
    for (form, switch) in [("p", "-psecret"), ("hp", "-hpsecret")] {
        let set = format!("{form}.rar");
        bench.create(&["-m0", switch], &set, &names);
        let whole = std::fs::read(bench.dir.join(&set)).unwrap();
        let mut flipped = whole.clone();
        flipped[750 * KIB] ^= 0x40;
        let bad = format!("{form}-flipped.rar");
        let short = format!("{form}-cut.rar");
        std::fs::write(bench.dir.join(&bad), &flipped).unwrap();
        std::fs::write(bench.dir.join(&short), &whole[..1200 * KIB]).unwrap();

        // The intact archive under its password: the bytes, through a
        // window where the stored route walks.
        let good = bench.extract(&set, "out-on", &["-psecret"], true, 64);
        assert!(
            good.status.success(),
            "{form}: {}",
            String::from_utf8_lossy(&good.stderr)
        );
        bench.same("out-on", &names);
        assert_eq!(window_lines(&good).len(), usize::from(WALKS), "{form}");

        for (archive, password) in [
            (set.as_str(), "-pwrong"),
            (bad.as_str(), "-psecret"),
            (short.as_str(), "-psecret"),
        ] {
            let off = bench.extract(archive, "out-off", &[password], false, 64);
            for slab_kib in [16usize, 64, 4096] {
                let on = bench.extract(archive, "out-on", &[password], true, slab_kib);
                let what = format!("{archive} {password} slab {slab_kib}");
                assert!(!on.status.success(), "{what}: the fault is reported");
                assert_eq!(on.status.code(), off.status.code(), "{what}: the exit code");
                assert_eq!(on.stdout, off.stdout, "{what}: what was printed");
                assert_eq!(strip(&on), strip(&off), "{what}: the complaint");
                for name in names {
                    let with = std::fs::read(bench.dir.join("out-on").join(name)).ok();
                    let without = std::fs::read(bench.dir.join("out-off").join(name)).ok();
                    assert!(with == without, "{what}: {name}");
                }
            }
        }
    }
}
