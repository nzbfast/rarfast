//! A SHIPPED `rarfast` reads no environment word that can move a byte it
//! writes: the archive is the command line's and the input's, never the
//! machine's or the shell's.
//!
//! Every write option the rar dialect has no switch for was once read
//! from the environment by every build. Here each of those words is set
//! to the value that reaches its option, on an input and a level where
//! the option moves the archive, and the archive must be the one written
//! with the word unset. Run in a build of the shipped feature set (the
//! default one), where the words are not read:
//!
//! ```text
//! cargo test -p rarkit-cli --test shipped_build_reads_no_knob
//! ```
//!
//! The same words keep their meaning in a build with the feature
//! `writer-knobs`, where the tests named for each option run.
//!
//! Width and memory: every create is `-mt4`. The largest row holds one
//! 128 MiB input in this process and writes two archives of it; every
//! other input is under 7 MiB.
//!
//! Under `writer-knobs` the words are read by design, and every test here
//! passes without a create (`knob_build`).

use std::path::{Path, PathBuf};
use std::process::Command;

/// Whether this is a build that reads the words, where nothing here holds.
fn knob_build() -> bool {
    cfg!(feature = "writer-knobs")
}

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// Every word a row here sets, so no row inherits another's from the
/// shell that runs the test.
const WORDS: [&str; 20] = [
    "RARKIT_SMALL_LAZY",
    "RARKIT_SOLID_STORE",
    "RARKIT_L3_FLOOR_LAZY",
    "RARKIT_L3_OPTIMAL",
    "RARKIT_L3_DEEP",
    "RARKIT_L12_EXTEND",
    "RARKIT_L4_OPTIMAL",
    "RARKIT_L4_TREE",
    "RARKIT_L5_TREE",
    "RARKIT_L5_FAR_ONLY",
    "RARKIT_L5_OPTIMAL",
    "RARKIT_L1_PRICED",
    "RARKIT_L1_DICT_2M",
    "RARKIT_L3_DICT_2M",
    "RARKIT_SOLID_DICT_2M",
    "RARKIT_FAR_LINKS",
    "RARKIT_STORE_ONE_MISS",
    "RARKIT_STORE_PACKED_SAMPLES",
    "RARKIT_ENCRYPTED_READ_AHEAD",
    "RARFAST_ONE_NODE",
];

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "rarfast-shipped-no-knob-{}-{tag}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `rarfast a -mt4 -idq <switches> <name>.rar <files>` in `dir` with
/// `word` set to `value`, or with none of the words set, and the
/// archive's bytes.
fn create(
    dir: &Path,
    name: &str,
    switches: &[&str],
    files: &[&str],
    word: Option<(&str, &str)>,
) -> Vec<u8> {
    let archive = format!("{name}.rar");
    let _ = std::fs::remove_file(dir.join(&archive));
    let mut command = Command::new(rarfast());
    command
        .current_dir(dir)
        .args(["a", "-mt4", "-idq"])
        .args(switches)
        .arg(&archive)
        .args(files);
    for word in WORDS {
        command.env_remove(word);
    }
    if let Some((word, value)) = word {
        command.env(word, value);
    }
    let out = command.output().unwrap();
    assert!(out.status.success(), "rarfast a {name}: {out:?}");
    std::fs::read(dir.join(archive)).unwrap()
}

/// One word, the value that reaches its option, and a create it moves.
struct Row {
    word: &'static str,
    value: &'static str,
    switches: &'static [&'static str],
    files: &'static [&'static str],
}

/// The words of `rows` whose value moved a byte of the archive.
fn moved(dir: &Path, rows: &[Row]) -> Vec<&'static str> {
    let mut moved = Vec::new();
    for row in rows {
        let unset = create(dir, "unset", row.switches, row.files, None);
        let set = create(
            dir,
            "set",
            row.switches,
            row.files,
            Some((row.word, row.value)),
        );
        if set != unset {
            moved.push(row.word);
        }
    }
    moved
}

/// Noise from a xorshift, the same bytes for the same seed.
fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        out.extend_from_slice(&state.wrapping_mul(0x2545_f491_4f6c_dd1d).to_le_bytes());
    }
    out.truncate(len);
    out
}

/// The parse options: each on a member of a few hundred kilobytes at the
/// level its option reaches.
#[test]
fn no_parse_word_moves_a_byte_of_the_archive() {
    if knob_build() {
        return;
    }
    let dir = work("parse");
    std::fs::write(
        dir.join("text.txt"),
        rarkit_testdata::chatter(0x3435, 600_000),
    )
    .unwrap();
    std::fs::write(
        dir.join("small.txt"),
        rarkit_testdata::chatter(0x736d, 200_000),
    )
    .unwrap();
    // Noise holding a 96 KiB copy of its own earlier bytes: its parse
    // blocks go to level 3's floor.
    let mut floored = noise(0x0930_2026, 524_288);
    let copy = floored[16 << 10..(16 << 10) + (96 << 10)].to_vec();
    let at = (300 << 10) + 7;
    floored[at..at + copy.len()].copy_from_slice(&copy);
    std::fs::write(dir.join("floored.bin"), floored).unwrap();
    // Text whose head reads far and holds long matches: level 5's class
    // gives it the chains unless it goes by far links alone.
    let mut far = rarkit_testdata::chatter_of(0x6661, 1 << 15, 2 << 20);
    let mut at = 4_096;
    while at + 32 <= far.len() {
        far.copy_within(at - 3_000..at - 2_968, at);
        at += 400;
    }
    std::fs::write(dir.join("far.txt"), far).unwrap();
    // A solid set with a clip of noise between two texts.
    std::fs::write(dir.join("a.txt"), rarkit_testdata::chatter(1, 300_000)).unwrap();
    std::fs::write(dir.join("m.bin"), noise(0x1001, (1 << 20) + 300_000)).unwrap();
    std::fs::write(dir.join("z.txt"), rarkit_testdata::chatter(2, 300_000)).unwrap();

    let text: &[&str] = &["text.txt"];
    let rows = [
        Row {
            word: "RARKIT_SMALL_LAZY",
            value: "0",
            switches: &["-m5"],
            files: &["small.txt"],
        },
        Row {
            word: "RARKIT_SOLID_STORE",
            value: "0",
            switches: &["-m3", "-s"],
            files: &["a.txt", "m.bin", "z.txt"],
        },
        Row {
            word: "RARKIT_L3_FLOOR_LAZY",
            value: "1",
            switches: &["-m3"],
            files: &["floored.bin"],
        },
        Row {
            word: "RARKIT_L3_OPTIMAL",
            value: "1",
            switches: &["-m3"],
            files: text,
        },
        Row {
            word: "RARKIT_L3_DEEP",
            value: "1",
            switches: &["-m3"],
            files: text,
        },
        Row {
            word: "RARKIT_L12_EXTEND",
            value: "1",
            switches: &["-m2"],
            files: text,
        },
        Row {
            word: "RARKIT_L4_OPTIMAL",
            value: "1",
            switches: &["-m4"],
            files: text,
        },
        Row {
            word: "RARKIT_L4_TREE",
            value: "1",
            switches: &["-m4"],
            files: text,
        },
        Row {
            word: "RARKIT_L5_TREE",
            value: "1",
            switches: &["-m5"],
            files: text,
        },
        Row {
            word: "RARKIT_L5_FAR_ONLY",
            value: "1",
            switches: &["-m5"],
            files: &["far.txt"],
        },
        Row {
            word: "RARKIT_L5_OPTIMAL",
            value: "1",
            switches: &["-m5"],
            files: text,
        },
        Row {
            word: "RARKIT_L1_PRICED",
            value: "1",
            switches: &["-m1"],
            files: text,
        },
    ];
    let moved = moved(&dir, &rows);
    assert!(
        moved.is_empty(),
        "a shipped rarfast wrote another archive under: {moved:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The dictionary options: a member whose one long repeat lies 3 MiB
/// back, past the 2 MiB each word once kept and inside every default.
#[test]
fn no_dictionary_word_moves_a_byte_of_the_archive() {
    if knob_build() {
        return;
    }
    let dir = work("dictionary");
    let repeat = rarkit_testdata::scramble(11, 512 << 10);
    let mut big = repeat.clone();
    big.extend_from_slice(&rarkit_testdata::chatter(12, 5 << 19));
    big.extend_from_slice(&repeat);
    big.extend_from_slice(&rarkit_testdata::chatter(13, 5 << 19));
    std::fs::write(dir.join("big.bin"), big).unwrap();
    std::fs::write(dir.join("small.txt"), rarkit_testdata::chatter(14, 40_000)).unwrap();
    let files: &[&str] = &["big.bin", "small.txt"];
    let rows = [
        Row {
            word: "RARKIT_L1_DICT_2M",
            value: "1",
            switches: &["-m1"],
            files,
        },
        Row {
            word: "RARKIT_L3_DICT_2M",
            value: "1",
            switches: &["-m3"],
            files,
        },
        Row {
            word: "RARKIT_SOLID_DICT_2M",
            value: "1",
            switches: &["-m3", "-s"],
            files,
        },
        Row {
            word: "RARKIT_FAR_LINKS",
            value: "1",
            switches: &["-m3", "-md4m"],
            files,
        },
    ];
    let moved = moved(&dir, &rows);
    assert!(
        moved.is_empty(),
        "a shipped rarfast wrote another archive under: {moved:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The store rule's options, on a member at the rule's 128 MiB floor: 13
/// of its 16 samples will not compress, which the rule stores and
/// `RARKIT_STORE_ONE_MISS` once compressed. `RARKIT_STORE_PACKED_SAMPLES`
/// is the same verdict reached the slower way, by its own account no
/// other archive: the pair says so of this member.
#[test]
fn no_store_rule_word_moves_a_byte_of_the_archive() {
    if knob_build() {
        return;
    }
    let dir = work("store");
    let len = 128 << 20;
    let mut member = noise(0x1001_2026, len);
    let segment = (32 << 20) / 16;
    for k in 0..3 {
        let sample = k * segment + (segment - (64 << 10)) / 2;
        member[sample..sample + (64 << 10)].fill(0);
    }
    std::fs::write(dir.join("member.bin"), member).unwrap();
    let rows = [
        Row {
            word: "RARKIT_STORE_ONE_MISS",
            value: "1",
            switches: &["-m3"],
            files: &["member.bin"],
        },
        Row {
            word: "RARKIT_STORE_PACKED_SAMPLES",
            value: "1",
            switches: &["-m3"],
            files: &["member.bin"],
        },
    ];
    let moved = moved(&dir, &rows);
    assert!(
        moved.is_empty(),
        "a shipped rarfast wrote another archive under: {moved:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `RARFAST_ONE_NODE=1` once kept a create to one node's CPUs (on Linux,
/// on a machine whose node holds 64 cores and more; nowhere else did it
/// do anything). The archive is the same one.
#[test]
fn the_one_node_word_moves_no_byte_of_the_archive() {
    if knob_build() {
        return;
    }
    let dir = work("node");
    std::fs::write(
        dir.join("text.txt"),
        rarkit_testdata::chatter(0x3435, 600_000),
    )
    .unwrap();
    let rows = [Row {
        word: "RARFAST_ONE_NODE",
        value: "1",
        switches: &["-m3"],
        files: &["text.txt"],
    }];
    let moved = moved(&dir, &rows);
    assert!(
        moved.is_empty(),
        "a shipped rarfast wrote another archive under: {moved:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `RARKIT_ENCRYPTED_READ_AHEAD=0` once took the encrypted stored walk
/// without its read-ahead. An encrypted archive's bytes are its salt's,
/// drawn fresh by every create, so no two are equal and the pair is held
/// to what does not depend on the salt: the same length, and the same
/// members back.
#[test]
fn the_encrypted_read_ahead_word_moves_no_length_and_no_member() {
    if knob_build() {
        return;
    }
    let dir = work("cipher");
    let first = noise(0x0e01, 6 << 20);
    let second = noise(0x0e02, 5 << 20);
    std::fs::write(dir.join("first.bin"), &first).unwrap();
    std::fs::write(dir.join("second.bin"), &second).unwrap();
    let switches: &[&str] = &["-m0", "-ppass"];
    let files: &[&str] = &["first.bin", "second.bin"];
    let unset = create(&dir, "unset", switches, files, None);
    let set = create(
        &dir,
        "set",
        switches,
        files,
        Some(("RARKIT_ENCRYPTED_READ_AHEAD", "0")),
    );
    assert_eq!(
        set.len(),
        unset.len(),
        "RARKIT_ENCRYPTED_READ_AHEAD=0 moved the archive's length"
    );
    for name in ["unset", "set"] {
        let out = dir.join(format!("out-{name}"));
        std::fs::create_dir_all(&out).unwrap();
        let mut extract = Command::new(rarfast());
        extract
            .current_dir(&out)
            .args(["x", "-mt4", "-idq", "-ppass"])
            .arg(format!("../{name}.rar"));
        for word in WORDS {
            extract.env_remove(word);
        }
        let ran = extract.output().unwrap();
        assert!(ran.status.success(), "rarfast x {name}.rar: {ran:?}");
        assert!(std::fs::read(out.join("first.bin")).unwrap() == first);
        assert!(std::fs::read(out.join("second.bin")).unwrap() == second);
    }
    let _ = std::fs::remove_dir_all(&dir);
}
