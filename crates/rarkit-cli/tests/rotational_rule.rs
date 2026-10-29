//! The rotational rule's wiring, in a build that reads the knobs: spec F
//! 3.7.8's acceptance tests 4 and 5.
//!
//! The rule (`dialect::unrar::extract`, `ROTATIONAL_READERS`): `t` or `p`
//! of a plain stored set (RAR 5 or, since its own rows, RAR 4; solid or not, since its own row; every member stored,
//! unencrypted, under a CRC32, one of at least 16 MiB), with no `-mt` stated, read cold off a
//! rotational device, runs on ONE thread with the sequential advice. Its
//! decision is unit tested where it lives (`rotational_set`,
//! `rotational_verdict`, `walk_threads`); what is tested HERE is the whole
//! command, the device's class and the page cache's answer STATED by the
//! measuring knobs (`RARFAST_ROTATIONAL`, `RARFAST_RESIDENT`), so the test
//! runs on any box, and what the walk ran at read from the line
//! `RARFAST_ROTATIONAL_SAY=1` prints.
//!
//! Those knobs exist only under the feature `read-depth-knob`, which no
//! gate builds, so this file is empty in `make ci`. It is run by hand:
//!
//! ```text
//! cargo test -p rarkit-cli --features read-depth-knob --test rotational_rule
//! ```
#![cfg(feature = "read-depth-knob")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[path = "support/exe_copy.rs"]
mod exe_copy;
use exe_copy::{copy_executable, output_of, rarfast};

/// The line the walk prints: the default width and no advice.
const WIDE: &str = "rarfast walk: threads None; in order false";
/// The rule fired: one reader, in order.
const ONE: &str = "rarfast walk: threads Some(1); in order true";

const MIB: usize = 1 << 20;

/// The shapes beyond the plain set that the SHIPPED rule takes
/// (`extract::ROTATIONAL_SHAPES`), by the knob's names: kept in step with
/// that constant by hand, and the test below fails where they differ.
const SHIPPED: &[&str] = &["rar4", "mixed", "solid"];

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
        let dir = std::env::temp_dir().join(format!(
            "rarfast-rotational-rule-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // A copy named `unrar` is how the binary picks that dialect.
        let unrar = dir.join("unrar");
        copy_executable(&rarfast(), &unrar);
        Self { dir, unrar }
    }

    /// `rarfast a <switches> <archive> <files>`, the creator of the `rar`
    /// dialect (the binary's own name), run in the bench's directory.
    fn create(&self, switches: &[&str], archive: &str, files: &[&str]) {
        let out = output_of(
            Command::new(rarfast())
                .arg("a")
                .args(switches)
                .args(["-ep", "-idq", archive])
                .args(files)
                .current_dir(&self.dir),
        )
        .expect("rarfast a runs");
        assert!(
            out.status.success(),
            "rarfast a {switches:?} {archive}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// `unrar <args>` with the class and the residency stated and `extra`
    /// on top (a later pair wins), and the say line asked for.
    fn unrar(&self, args: &[&str], extra: &[(&str, &str)]) -> Output {
        let mut command = Command::new(&self.unrar);
        command
            .args(args)
            .current_dir(&self.dir)
            .env("RARFAST_ROTATIONAL", "1")
            .env("RARFAST_RESIDENT", "0")
            .env("RARFAST_ROTATIONAL_SAY", "1")
            .env_remove("RARFAST_ROTATIONAL_READERS")
            .env_remove("RARFAST_ROTATIONAL_ADVICE");
        for (name, value) in extra {
            command.env(name, value);
        }
        output_of(&mut command).expect("unrar runs")
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The walk's line out of a run's stderr.
fn walk_line(out: &Output) -> String {
    let stderr = String::from_utf8_lossy(&out.stderr);
    stderr
        .lines()
        .find(|line| line.starts_with("rarfast walk:"))
        .unwrap_or_else(|| panic!("no walk line in {stderr:?}"))
        .to_string()
}

fn write(dir: &Path, name: &str, bytes: &[u8]) {
    std::fs::write(dir.join(name), bytes).unwrap();
}

/// Acceptance test 4, the rule on: a plain stored set with a 16 MiB member,
/// rotational and cold, `t` and `p`, runs on one reader in order.
#[test]
fn a_plain_stored_set_cold_off_a_rotational_device_runs_on_one_reader() {
    let bench = Bench::new("fires");
    write(&bench.dir, "full.bin", &noise(20 * MIB, 1));
    write(
        &bench.dir,
        "note.txt",
        b"a small member beside the big one\n",
    );
    bench.create(&["-m0"], "set.rar", &["full.bin", "note.txt"]);
    for command in ["t", "p"] {
        let out = bench.unrar(&[command, "-idq", "set.rar"], &[]);
        assert!(out.status.success(), "{command}");
        assert_eq!(walk_line(&out), ONE, "{command}");
    }
    // The measuring knobs: a count of 0 is the rule off, another count
    // narrows with no advice, and the advice can be withheld at one.
    let off = bench.unrar(
        &["t", "-idq", "set.rar"],
        &[("RARFAST_ROTATIONAL_READERS", "0")],
    );
    assert_eq!(walk_line(&off), WIDE);
    let four = bench.unrar(
        &["t", "-idq", "set.rar"],
        &[("RARFAST_ROTATIONAL_READERS", "4")],
    );
    assert_eq!(
        walk_line(&four),
        "rarfast walk: threads Some(4); in order false"
    );
    let bare = bench.unrar(
        &["t", "-idq", "set.rar"],
        &[("RARFAST_ROTATIONAL_ADVICE", "0")],
    );
    assert_eq!(
        walk_line(&bare),
        "rarfast walk: threads Some(1); in order false"
    );
}

/// Acceptance test 4, each condition failing alone: the default width.
#[test]
fn any_one_condition_failing_keeps_the_default_width() {
    let bench = Bench::new("silent");
    write(&bench.dir, "full.bin", &noise(20 * MIB, 2));
    write(&bench.dir, "one.bin", &noise(MIB, 3));
    write(&bench.dir, "two.bin", &noise(MIB, 4));
    // Text a compressor takes, so `-m3` leaves the member compressed:
    // 70 MiB of it, past the 64 MiB a mixed set may hold and still be
    // narrowed (`extract::MIXED_COMPRESSED_CAP`).
    let text: Vec<u8> = b"the quick brown fox jumps over the lazy dog\n"
        .iter()
        .copied()
        .cycle()
        .take(70 * MIB)
        .collect();
    write(&bench.dir, "text.txt", &text);
    bench.create(&["-m0"], "set.rar", &["full.bin"]);
    bench.create(&["-m0"], "small.rar", &["one.bin", "two.bin"]);
    bench.create(&["-m3"], "packed.rar", &["text.txt"]);
    bench.create(&["-m3"], "mixed.rar", &["full.bin", "text.txt"]);
    bench.create(&["-m0", "-s"], "solid.rar", &["full.bin", "one.bin"]);
    bench.create(&["-m0", "-htb"], "blake.rar", &["full.bin"]);
    bench.create(&["-m0", "-psecret"], "cipher.rar", &["full.bin"]);

    let t = ["t", "-idq", "set.rar"];
    // The device is solid state, or the archive is in the page cache.
    let solid = bench.unrar(&t, &[("RARFAST_ROTATIONAL", "0")]);
    assert_eq!(walk_line(&solid), WIDE, "solid state");
    let warm = bench.unrar(&t, &[("RARFAST_RESIDENT", "1")]);
    assert_eq!(walk_line(&warm), WIDE, "resident");
    // A stated width is the user's, at any count.
    let stated = bench.unrar(&["t", "-idq", "-mt3", "set.rar"], &[]);
    assert_eq!(
        walk_line(&stated),
        "rarfast walk: threads Some(3); in order false"
    );
    // `x` is not the rule's.
    std::fs::create_dir_all(bench.dir.join("out")).unwrap();
    let x = bench.unrar(&["x", "-idq", "-y", "set.rar", "out/"], &[]);
    assert!(x.status.success());
    assert_eq!(walk_line(&x), WIDE, "x");
    // The set: no member of 16 MiB, a compressed member (alone, and 70
    // MiB of it in one `-m3` set beside noise, which is past the cap), a
    // BLAKE2sp hash, a cipher.
    // A solid stored archive is not among them any more: since its own
    // row the shipped rule narrows it.
    let solid = bench.unrar(&["t", "-idq", "solid.rar"], &[]);
    assert!(solid.status.success());
    assert_eq!(walk_line(&solid), ONE, "solid.rar");
    for (archive, switches) in [
        ("small.rar", &[][..]),
        ("packed.rar", &[][..]),
        ("mixed.rar", &[][..]),
        ("blake.rar", &[][..]),
        ("cipher.rar", &["-psecret"][..]),
    ] {
        let mut args = vec!["t", "-idq"];
        args.extend_from_slice(switches);
        args.push(archive);
        let out = bench.unrar(&args, &[]);
        assert!(out.status.success(), "{archive}");
        assert_eq!(walk_line(&out), WIDE, "{archive}");
    }
}

/// Acceptance test 5: the bytes and the verdicts are the same at either
/// width, on a sound archive and on a damaged one.
#[test]
fn the_bytes_and_the_verdicts_are_the_same_at_either_width() {
    let bench = Bench::new("same");
    let big = noise(20 * MIB, 5);
    write(&bench.dir, "full.bin", &big);
    write(&bench.dir, "second.bin", &noise(17 * MIB, 6));
    bench.create(&["-m0"], "set.rar", &["full.bin", "second.bin"]);
    let off = [("RARFAST_ROTATIONAL_READERS", "0")];

    let narrow = bench.unrar(&["p", "-inul", "set.rar", "full.bin"], &[]);
    let wide = bench.unrar(&["p", "-inul", "set.rar", "full.bin"], &off);
    assert_eq!(walk_line(&narrow), ONE);
    assert_eq!(walk_line(&wide), WIDE);
    assert!(narrow.status.success() && wide.status.success());
    assert!(narrow.stdout == big, "p at one reader prints the member");
    assert!(wide.stdout == big, "p at the width prints the member");

    let narrow = bench.unrar(&["t", "set.rar"], &[]);
    let wide = bench.unrar(&["t", "set.rar"], &off);
    assert_eq!(walk_line(&narrow), ONE);
    assert!(narrow.status.success() && wide.status.success());
    assert_eq!(narrow.stdout, wide.stdout, "t's listing of a sound set");

    // One byte of the LAST member's data flipped: a checksum error at
    // either width, the same exit code and the same lines.
    let path = bench.dir.join("set.rar");
    let mut bytes = std::fs::read(&path).unwrap();
    let at = bytes.len() - 4 * MIB;
    bytes[at] ^= 0x55;
    std::fs::write(&path, bytes).unwrap();
    let narrow = bench.unrar(&["t", "set.rar"], &[]);
    let wide = bench.unrar(&["t", "set.rar"], &off);
    assert_eq!(walk_line(&narrow), ONE);
    assert_eq!(walk_line(&wide), WIDE);
    assert!(!narrow.status.success());
    assert_eq!(narrow.status.code(), wide.status.code());
    assert_eq!(narrow.stdout, wide.stdout, "t's listing of a damaged set");
    let errors = |out: &Output| -> Vec<String> {
        String::from_utf8_lossy(&out.stderr)
            .lines()
            .filter(|line| !line.starts_with("rarfast "))
            .map(str::to_string)
            .collect()
    };
    assert_eq!(errors(&narrow), errors(&wide));
}

/// A RAR 4 stored archive of `members`, written by rarkit's own writer
/// (reference `rar` 7 writes RAR 5 only): one file, or with `volume` a
/// classic volume set (`<stem>.rar`, `<stem>.r00` and on) of that many
/// payload bytes a volume. Returns the first volume's name.
fn write_rar4(dir: &Path, stem: &str, members: &[(&str, &[u8])], volume: Option<u64>) -> String {
    let mut writer = rarkit::Writer::new(rarkit::WriteOptions {
        format: rarkit::WriteFormat::Rar4(rarkit::Rar4Version::V40),
        method: rarkit::WriteMethod::Stored,
        volume_size: volume,
        volume_naming: rarkit::VolumeNaming::Classic,
        filters: rarkit::FilterPolicy::Off,
        host_os: rarkit::HostOs::Unix,
        ..rarkit::WriteOptions::default()
    })
    .unwrap();
    for (name, bytes) in members {
        writer
            .add(rarkit::MemberSpec {
                name: name.as_bytes(),
                payload: rarkit::Payload::Bytes(bytes),
                mtime: None,
                attributes: 0o100644,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .unwrap();
    }
    if volume.is_some() {
        let mut volumes: Vec<Vec<u8>> = Vec::new();
        writer.finish_volumes(&mut volumes).unwrap();
        let total = volumes.len() as u32;
        for (index, bytes) in volumes.iter().enumerate() {
            let name =
                rarkit::volume_file_name(stem, index as u32, total, rarkit::VolumeNaming::Classic);
            write(dir, &name, bytes);
        }
    } else {
        let mut bytes = Vec::new();
        writer.finish_into(&mut bytes).unwrap();
        write(dir, &format!("{stem}.rar"), &bytes);
    }
    format!("{stem}.rar")
}

/// The shapes beyond the plain set (`extract::Shapes`): each is narrowed
/// only where the measuring knob names it, `t` and `p`; with the knob
/// unset (the shipped rule) and with another shape named it keeps the
/// default width; and the bytes and the verdict are the same either way.
#[test]
fn each_shape_beyond_the_plain_set_fires_only_where_the_knob_names_it() {
    let bench = Bench::new("shapes");
    let big = noise(20 * MIB, 7);
    write(&bench.dir, "full.bin", &big);
    write(&bench.dir, "one.bin", &noise(MIB, 8));
    let text: Vec<u8> = b"the quick brown fox jumps over the lazy dog\n"
        .iter()
        .copied()
        .cycle()
        .take(MIB)
        .collect();
    write(&bench.dir, "note.txt", &text);
    let one = noise(MIB, 8);
    write_rar4(
        &bench.dir,
        "old",
        &[("full.bin", &big), ("one.bin", &one)],
        None,
    );
    write_rar4(&bench.dir, "oldset", &[("full.bin", &big)], Some(6 << 20));
    bench.create(&["-m0", "-s"], "solid.rar", &["full.bin", "one.bin"]);
    bench.create(&["-m0", "-psecret"], "cipher.rar", &["full.bin"]);
    bench.create(&["-m0", "-hpsecret"], "hidden.rar", &["full.bin"]);
    bench.create(&["-m0", "-htb"], "blake.rar", &["full.bin"]);
    // The big member stored and the text compressed, member by member, in
    // one archive: at `-m3` the creator stores what will not compress, the
    // noise, and compresses the text (were the big member compressed, no knob
    // would narrow this set, and the assertions below would say so).
    bench.create(&["-m3"], "mixed.rar", &["full.bin", "note.txt"]);

    // What `p` of the whole set prints: its members, in order.
    let both = [&big[..], &one[..]].concat();
    let noted = [&big[..], &text[..]].concat();
    let shapes = ["rar4", "solid", "cipher", "blake2sp", "mixed"];
    for (archive, shape, switches, printed) in [
        ("old.rar", "rar4", &[][..], &both),
        ("oldset.rar", "rar4", &[][..], &big),
        ("solid.rar", "solid", &[][..], &both),
        ("cipher.rar", "cipher", &["-psecret"][..], &big),
        ("hidden.rar", "cipher", &["-psecret"][..], &big),
        ("blake.rar", "blake2sp", &[][..], &big),
        ("mixed.rar", "mixed", &[][..], &noted),
    ] {
        let run = |command: &str, quiet: &str, knob: Option<&str>| {
            let mut args = vec![command, quiet];
            args.extend_from_slice(switches);
            args.push(archive);
            match knob {
                Some(list) => bench.unrar(&args, &[("RARFAST_ROTATIONAL_SHAPES", list)]),
                None => bench.unrar(&args, &[]),
            }
        };
        // The shipped rule takes the shapes of `SHIPPED` and no other;
        // every other shape's knob, and `none`, keep the width.
        let shipped = run("t", "-idq", None);
        assert!(shipped.status.success(), "{archive}");
        let expected = if SHIPPED.contains(&shape) { ONE } else { WIDE };
        assert_eq!(walk_line(&shipped), expected, "{archive}, the shipped rule");
        let none = run("t", "-idq", Some("none"));
        assert_eq!(walk_line(&none), WIDE, "{archive} with none on");
        for other in shapes.iter().filter(|other| **other != shape) {
            let out = run("t", "-idq", Some(other));
            assert_eq!(walk_line(&out), WIDE, "{archive} with {other} on");
        }
        // Its own knob, and every shape at once: one reader in order.
        for list in [shape, "all"] {
            for command in ["t", "p"] {
                let out = run(command, "-inul", Some(list));
                assert!(out.status.success(), "{command} {archive} with {list}");
                assert_eq!(walk_line(&out), ONE, "{command} {archive} with {list}");
            }
        }
        // The same bytes and the same verdict at either width. (A member
        // named on the command line is judged alone, as the plain set is:
        // `t mixed.rar full.bin` reads one stored member and is narrowed by
        // the shipped rule.)
        if shape == "mixed" {
            let named = bench.unrar(&["t", "-idq", archive, "full.bin"], &[]);
            assert_eq!(walk_line(&named), ONE, "{archive}: the big member named");
        }
        let narrow = run("p", "-inul", Some(shape));
        let wide = run("p", "-inul", Some("none"));
        assert!(narrow.stdout == *printed, "{archive}: p at one reader");
        assert!(wide.stdout == *printed, "{archive}: p at the width");
        let mut args = vec!["t"];
        args.extend_from_slice(switches);
        args.push(archive);
        let narrow = bench.unrar(&args, &[("RARFAST_ROTATIONAL_SHAPES", shape)]);
        let wide = bench.unrar(&args, &[("RARFAST_ROTATIONAL_SHAPES", "none")]);
        assert_eq!(walk_line(&narrow), ONE, "{archive}: t of the whole set");
        assert_eq!(walk_line(&wide), WIDE, "{archive}: t of the whole set");
        assert!(
            narrow.status.success() && wide.status.success(),
            "{archive}"
        );
        assert_eq!(narrow.stdout, wide.stdout, "{archive}: t's listing");
    }
}

/// What no knob switches on: a set of two shapes at once, a mixed set with
/// more compressed bytes than the cap (64 MiB unpacked), and (as for the plain set) `x`, a
/// warm archive, a solid state device and a stated `-mt`.
#[test]
fn no_knob_narrows_a_combination_or_a_set_with_much_to_decode() {
    let bench = Bench::new("never");
    write(&bench.dir, "full.bin", &noise(20 * MIB, 9));
    // 70 MiB of text: past the 64 MiB cap of a mixed set.
    let text: Vec<u8> = b"the quick brown fox jumps over the lazy dog\n"
        .iter()
        .copied()
        .cycle()
        .take(70 * MIB)
        .collect();
    write(&bench.dir, "text.txt", &text);
    bench.create(&["-m0", "-s", "-psecret"], "both.rar", &["full.bin"]);
    bench.create(&["-m0", "-htb", "-psecret"], "pair.rar", &["full.bin"]);
    // The noise stored and 70 MiB of text compressed (the creator's own
    // choice at `-m3`, as `mixed.rar` of the test above proves it).
    bench.create(&["-m3"], "heavy.rar", &["full.bin", "text.txt"]);
    bench.create(&["-m0", "-s"], "solid.rar", &["full.bin"]);
    let all = [("RARFAST_ROTATIONAL_SHAPES", "all")];
    for archive in ["both.rar", "pair.rar", "heavy.rar"] {
        let out = bench.unrar(&["t", "-idq", "-psecret", archive], &all);
        assert!(out.status.success(), "{archive}");
        assert_eq!(walk_line(&out), WIDE, "{archive}");
    }
    // A shape that is on still needs every other condition of the rule.
    let t = ["t", "-idq", "solid.rar"];
    assert_eq!(walk_line(&bench.unrar(&t, &all)), ONE);
    let on = |extra: (&'static str, &'static str)| [all[0], extra];
    let out = bench.unrar(&t, &on(("RARFAST_ROTATIONAL", "0")));
    assert_eq!(walk_line(&out), WIDE, "solid state");
    let out = bench.unrar(&t, &on(("RARFAST_RESIDENT", "1")));
    assert_eq!(walk_line(&out), WIDE, "resident");
    let out = bench.unrar(&["t", "-idq", "-mt3", "solid.rar"], &all);
    assert_eq!(
        walk_line(&out),
        "rarfast walk: threads Some(3); in order false"
    );
    std::fs::create_dir_all(bench.dir.join("out")).unwrap();
    let out = bench.unrar(&["x", "-idq", "-y", "solid.rar", "out/"], &all);
    assert!(out.status.success());
    assert_eq!(walk_line(&out), WIDE, "x");
}

/// A volume set is judged by its FIRST volume alone (spec F 3.7.8): the
/// device's class and the page cache are asked of that file and of no
/// other, so a set whose later volumes sit on another device, or are
/// cached where the first is not, goes as the first says.
#[test]
fn a_volume_set_is_judged_by_its_first_volume() {
    let bench = Bench::new("first");
    write(&bench.dir, "full.bin", &noise(20 * MIB, 10));
    bench.create(&["-m0", "-v6m"], "set.rar", &["full.bin"]);
    let first = "set.part1.rar";
    assert!(bench.dir.join(first).exists() && bench.dir.join("set.part4.rar").exists());
    let asked = |out: &Output| -> Vec<String> {
        String::from_utf8_lossy(&out.stderr)
            .lines()
            .filter(|line| line.starts_with("rarfast device class of "))
            .map(str::to_string)
            .collect()
    };
    for command in ["t", "p"] {
        let out = bench.unrar(&[command, "-inul", first], &[]);
        assert!(out.status.success(), "{command}");
        assert_eq!(walk_line(&out), ONE, "{command}");
        let lines = asked(&out);
        assert_eq!(lines.len(), 1, "{command}: asked once, {lines:?}");
        assert!(
            lines[0].starts_with(&format!("rarfast device class of {first}:")),
            "{command}: {lines:?}"
        );
    }
}
