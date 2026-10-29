//! What `rarfast a` PRINTS while it writes a volume set is what it printed
//! when every member was read as the writer reached it (1 Oct 2026).
//!
//! **Why this can move at all.** A member's `Adding` line used to open on
//! the first read of its source, and a `Creating archive` header or a
//! `...` continuation was hung on whichever line was open when the writer
//! closed a volume. That is right only while the writer reads a member
//! when it reaches it. A volume set now batches its small members as one
//! archive does (a solid batch, the worker team), so a source is read
//! well before its member is written, and a boundary would land on the
//! wrong line. The writer says which member it has taken up
//! (`rarkit::Progress::member_started`) and the report opens a member's
//! line once both that and the first read have happened.
//!
//! **The pins were printed by this file built against the PARENT of that
//! change** (the two level 5 runs again from a later revision, whose level 5 by class moved their volume counts; every other run unchanged there): for each run the exit code, the number of
//! volumes written, and the length and a hash of each stream. A run that
//! stops matching prints both streams. To pin again from a new parent,
//! build this file there, run it and copy the `PIN` lines it prints.
//!
//! The tree is made here, the same on every run: small files by the
//! dozen, a subdirectory, an empty directory, an empty file, a member the
//! store rule samples and compresses, one it samples and stores, and one
//! longer than a window. A second tree is built so that a solid batch's
//! tail lands past a volume boundary: files that pack to nothing, then
//! small noise.
//!
//! **Pinned again on 11 Oct 2026, over new test data.** The members here
//! are made by the shared test data makers now, so every digest below
//! was taken again, from that day's build, whose engine was byte for byte
//! the one that passed the pins before them. They record the same
//! behaviour on new data and guard it from here on; they no longer prove
//! equality with the older build this header names.
//! The one row pinned for Windows alone (`WINDOWS_PINS`) was taken again
//! the same day from what this test itself printed for that row on
//! Windows, in a build of the same sources: five volumes and 7,230
//! bytes of standard output, where the earlier text gave six and 7,350.
//! It is the same kind of pin as the rest: it records what the writer
//! printed there on the new data and guards it from here on, and no
//! longer proves equality with the older build this header names.

use std::path::{Path, PathBuf};
use std::process::Command;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// An empty directory of one test's own, made afresh under the system's
/// temporary directory; `tag` tells the tests of this file apart.
fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-vollines-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The mixed tree, under `root/tree`.
fn mixed_tree(root: &Path) {
    let tree = root.join("tree");
    std::fs::create_dir_all(tree.join("sub/deep")).unwrap();
    std::fs::create_dir_all(tree.join("empty-dir")).unwrap();
    for i in 0..36u64 {
        let len = 2_000 + (i as usize * 7_919) % 58_000;
        let name = if i % 3 == 0 {
            format!("sub/a{i:02}.c")
        } else if i % 3 == 1 {
            format!("b{i:02}.h")
        } else {
            format!("sub/deep/c{i:02}.txt")
        };
        std::fs::write(tree.join(name), rarkit_testdata::chatter(i + 1, len)).unwrap();
    }
    std::fs::write(tree.join("empty.txt"), b"").unwrap();
    std::fs::write(tree.join("sub/empty.h"), b"").unwrap();
    std::fs::write(
        tree.join("sampled.txt"),
        rarkit_testdata::chatter(101, 1_200_000),
    )
    .unwrap();
    std::fs::write(
        tree.join("sub/stored.bin"),
        rarkit_testdata::scramble(7, 1_100_000),
    )
    .unwrap();
    std::fs::write(
        tree.join("small-noise.bin"),
        rarkit_testdata::scramble(9, 21_000),
    )
    .unwrap();
    std::fs::write(
        tree.join("sub/deep/long.txt"),
        rarkit_testdata::chatter(202, 9_500_000),
    )
    .unwrap();
}

/// The tree whose solid batches overrun their volumes, under `root/tree`.
fn ragged_tree(root: &Path) {
    let tree = root.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    for i in 0..12u8 {
        std::fs::write(
            tree.join(format!("a-flat{i:02}.dat")),
            vec![b'a' + i; 30_000],
        )
        .unwrap();
    }
    for i in 0..40u64 {
        let len = 4_000 + (i as usize * 613) % 5_000;
        std::fs::write(
            tree.join(format!("b-noise{i:02}.dat")),
            rarkit_testdata::scramble(i + 300, len),
        )
        .unwrap();
    }
    for i in 0..20u64 {
        let len = 6_000 + i as usize * 911;
        std::fs::write(
            tree.join(format!("c-text{i:02}.dat")),
            rarkit_testdata::chatter(i + 400, len),
        )
        .unwrap();
    }
}

/// FNV-1a, 64 bits: a pin's hash of one stream.
fn hash(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// One run's pin: `(label, exit code, volumes, stdout length and hash,
/// stderr length and hash)`.
type Pin = (&'static str, i32, usize, usize, u64, usize, u64);

/// The one row whose text differs on Windows, and its pin there. A
/// member's header is a few bytes different on Windows, and in this row
/// alone that moves a volume's end by one member: the fourth volume ends
/// after `b-noise39.dat` and cuts `c-text00.dat`, where on Unix it cuts
/// `b-noise39.dat`. The same six volumes, the same 7,350 bytes of text and
/// the same layout either way (a cut member's line left open, then `...`
/// and its name under the next volume's banner); read line by line against
/// the Unix text on 4 Oct 2026.
const WINDOWS_PINS: &[Pin] = &[(
    "ragged solid m1 v64k",
    0,
    5,
    7230,
    0xf6410b50dce3edc6,
    0,
    0xcbf29ce484222325,
)];

/// A row's pin on this system.
fn pin_of(label: &str) -> Option<&'static Pin> {
    let own = if cfg!(windows) { WINDOWS_PINS } else { &[] };
    own.iter().chain(PINS).find(|pin| pin.0 == label)
}

const PINS: &[Pin] = &[
    (
        "solid m3 v100k",
        0,
        31,
        7872,
        0x75b2d36ebc6b3f7c,
        0,
        0xcbf29ce484222325,
    ),
    (
        "solid m3 v40k",
        0,
        77,
        13438,
        0xea9b24b3700ab4a3,
        0,
        0xcbf29ce484222325,
    ),
    (
        "solid m1 v1m",
        0,
        4,
        4602,
        0xea58dae8d040dada,
        0,
        0xcbf29ce484222325,
    ),
    (
        "solid m5 v250k",
        0,
        12,
        5562,
        0x3a20db259491005c,
        0,
        0xcbf29ce484222325,
    ),
    (
        "solid m3 v100k in walk order",
        0,
        31,
        7872,
        0x17ddfee4f41b0f16,
        0,
        0xcbf29ce484222325,
    ),
    (
        "solid m3 v100k one thread",
        0,
        31,
        7872,
        0x75b2d36ebc6b3f7c,
        0,
        0xcbf29ce484222325,
    ),
    (
        "solid m3 v100k no counter",
        0,
        31,
        7110,
        0xe22911345cc088f0,
        0,
        0xcbf29ce484222325,
    ),
    (
        "solid m3 v100k no names",
        0,
        31,
        1212,
        0x1625456ea18632f6,
        0,
        0xcbf29ce484222325,
    ),
    (
        "solid m3 v100k blake2",
        0,
        31,
        7872,
        0x38f558303dbd4b7c,
        0,
        0xcbf29ce484222325,
    ),
    (
        "solid m3 v100k mm512m",
        0,
        31,
        7872,
        0x75b2d36ebc6b3f7c,
        0,
        0xcbf29ce484222325,
    ),
    (
        "plain m3 v100k",
        0,
        31,
        7866,
        0xd4e4d93e0db8f271,
        0,
        0xcbf29ce484222325,
    ),
    (
        "plain m3 v40k",
        0,
        77,
        13432,
        0xef3f6d743f661b3f,
        0,
        0xcbf29ce484222325,
    ),
    (
        "plain m1 v1m",
        0,
        4,
        4596,
        0x808d8f227ace28dc,
        0,
        0xcbf29ce484222325,
    ),
    (
        "plain m5 v250k",
        0,
        12,
        5556,
        0xeed4bb2ab0845f26,
        0,
        0xcbf29ce484222325,
    ),
    (
        "plain m3 v100k one thread",
        0,
        31,
        7866,
        0xd4e4d93e0db8f271,
        0,
        0xcbf29ce484222325,
    ),
    (
        "stored v200k",
        0,
        63,
        11676,
        0x976b92fd91c956e0,
        0,
        0xcbf29ce484222325,
    ),
    (
        "solid m3 one archive",
        0,
        1,
        4242,
        0xb2cc11dec252e5e1,
        0,
        0xcbf29ce484222325,
    ),
    (
        "plain m3 one archive",
        0,
        1,
        4236,
        0x1455cef70b102ca3,
        0,
        0xcbf29ce484222325,
    ),
    (
        "ragged solid m3 v40k",
        0,
        8,
        7590,
        0xfb7e4307054e01b4,
        0,
        0xcbf29ce484222325,
    ),
    (
        "ragged solid m5 v40k",
        0,
        8,
        7590,
        0xc3be3e89562cd66b,
        0,
        0xcbf29ce484222325,
    ),
    (
        "ragged solid m1 v64k",
        0,
        5,
        7148,
        0x1d8374e084c9b7e3,
        0,
        0xcbf29ce484222325,
    ),
    (
        "ragged plain m3 v40k",
        0,
        8,
        7584,
        0x615d4a4950dd10dc,
        0,
        0xcbf29ce484222325,
    ),
    (
        "solid m3 v100k, a small file unreadable",
        6,
        31,
        7808,
        0x10f4c67d78ccbb02,
        45,
        0xbc1d5888278bfaad,
    ),
    (
        "plain m3 v100k, a small file unreadable",
        6,
        31,
        7802,
        0xc664a7232db598ff,
        45,
        0xbc1d5888278bfaad,
    ),
    (
        "solid m3 v100k, the sampled file unreadable",
        6,
        29,
        7566,
        0xf5f71a14a7ce1d92,
        47,
        0x5a1bd49f9a4ebcd1,
    ),
    (
        "solid m3 one archive, a small file unreadable",
        6,
        1,
        4178,
        0xfe17f97d518d1b28,
        45,
        0xbc1d5888278bfaad,
    ),
];

/// One run: a label, which tree, and the switches after `a -r -y`.
struct Row {
    label: &'static str,
    ragged: bool,
    /// A file made unreadable before the run, relative to `tree`.
    ///
    /// Since 8 Oct 2026 such a file (mode 000) is left out by the walk
    /// and the rest is written, as rar 7.23 does: the four rows that
    /// carry one were pinned again that day from the build that made the
    /// change, each read first: every other member's line as in the row
    /// without the file, `WARNING: Cannot open 1 file` before `Done`,
    /// `Cannot open` and its reason on stderr, exit 6, and the volumes
    /// written. Before it they pinned a run that stopped at that member
    /// and wrote nothing, which a mode can no longer produce.
    locked: Option<&'static str>,
    switches: &'static [&'static str],
}

const fn row(label: &'static str, switches: &'static [&'static str]) -> Row {
    Row {
        label,
        ragged: false,
        locked: None,
        switches,
    }
}

const fn ragged(label: &'static str, switches: &'static [&'static str]) -> Row {
    Row {
        label,
        ragged: true,
        locked: None,
        switches,
    }
}

const fn locked(label: &'static str, file: &'static str, switches: &'static [&'static str]) -> Row {
    Row {
        label,
        ragged: false,
        locked: Some(file),
        switches,
    }
}

fn rows() -> Vec<Row> {
    vec![
        row("solid m3 v100k", &["-m3", "-s", "-v100k"]),
        row("solid m3 v40k", &["-m3", "-s", "-v40k"]),
        row("solid m1 v1m", &["-m1", "-s", "-v1m"]),
        row("solid m5 v250k", &["-m5", "-s", "-v250k"]),
        row(
            "solid m3 v100k in walk order",
            &["-m3", "-s", "-ds", "-v100k"],
        ),
        row(
            "solid m3 v100k one thread",
            &["-m3", "-s", "-v100k", "-mt1"],
        ),
        row(
            "solid m3 v100k no counter",
            &["-m3", "-s", "-v100k", "-idp"],
        ),
        row("solid m3 v100k no names", &["-m3", "-s", "-v100k", "-idn"]),
        row("solid m3 v100k blake2", &["-m3", "-s", "-v100k", "-htb"]),
        row("solid m3 v100k mm512m", &["-m3", "-s", "-v100k", "-mm512m"]),
        row("plain m3 v100k", &["-m3", "-v100k"]),
        row("plain m3 v40k", &["-m3", "-v40k"]),
        row("plain m1 v1m", &["-m1", "-v1m"]),
        row("plain m5 v250k", &["-m5", "-v250k"]),
        row("plain m3 v100k one thread", &["-m3", "-v100k", "-mt1"]),
        row("stored v200k", &["-m0", "-v200k"]),
        row("solid m3 one archive", &["-m3", "-s"]),
        row("plain m3 one archive", &["-m3"]),
        ragged("ragged solid m3 v40k", &["-m3", "-s", "-ds", "-v40k"]),
        ragged("ragged solid m5 v40k", &["-m5", "-s", "-ds", "-v40k"]),
        ragged("ragged solid m1 v64k", &["-m1", "-s", "-v64k"]),
        ragged("ragged plain m3 v40k", &["-m3", "-v40k"]),
        locked(
            "solid m3 v100k, a small file unreadable",
            "sub/a18.c",
            &["-m3", "-s", "-v100k"],
        ),
        locked(
            "plain m3 v100k, a small file unreadable",
            "sub/a18.c",
            &["-m3", "-v100k"],
        ),
        locked(
            "solid m3 v100k, the sampled file unreadable",
            "sampled.txt",
            &["-m3", "-s", "-v100k"],
        ),
        locked(
            "solid m3 one archive, a small file unreadable",
            "sub/a18.c",
            &["-m3", "-s"],
        ),
    ]
}

/// Whether this process reads a file whatever its mode (a root user
/// does), in which case an unreadable source cannot be made.
#[cfg(unix)]
fn reads_anything(probe: &Path) -> bool {
    std::fs::File::open(probe).is_ok()
}

/// What a run printed, with the system's separator written as `/`: a
/// progress line names a member with the system's separator, and the pins
/// are of the Unix form. The bytes are untouched on Unix.
fn pinned_form(bytes: &[u8]) -> Vec<u8> {
    if std::path::MAIN_SEPARATOR == '/' {
        return bytes.to_vec();
    }
    bytes
        .iter()
        .map(|&b| if b == b'\\' { b'/' } else { b })
        .collect()
}

/// Makes `path` unreadable, or says it cannot: only a Unix mode does it,
/// so the rows with an unreadable file are Unix only by their nature.
#[cfg(unix)]
fn lock(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000)).unwrap();
    !reads_anything(path)
}

#[cfg(not(unix))]
fn lock(_path: &Path) -> bool {
    false
}

#[cfg(unix)]
fn unlock(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644));
}

#[cfg(not(unix))]
fn unlock(_path: &Path) {}

#[test]
fn a_volume_sets_progress_lines_are_what_a_member_at_a_time_printed() {
    let mut wrong = Vec::new();
    for (at, row) in rows().into_iter().enumerate() {
        let dir = work(&format!("r{at}"));
        if row.ragged {
            ragged_tree(&dir);
        } else {
            mixed_tree(&dir);
        }
        std::fs::create_dir_all(dir.join("out")).unwrap();
        if let Some(file) = row.locked {
            let path = dir.join("tree").join(file);
            if !lock(&path) {
                eprintln!(
                    "{}: not measured, the file still reads after its mode was cleared",
                    row.label
                );
                let _ = std::fs::remove_dir_all(&dir);
                continue;
            }
        }
        let out = Command::new(rarfast())
            .args(["a", "-r", "-y"])
            .args(row.switches)
            .args(["out/set.rar", "tree"])
            .current_dir(&dir)
            .output()
            .expect("rarfast runs");
        let volumes = std::fs::read_dir(dir.join("out")).unwrap().count();
        let (stdout, stderr) = (pinned_form(&out.stdout), pinned_form(&out.stderr));
        let got: Pin = (
            row.label,
            out.status.code().unwrap_or(-1),
            volumes,
            stdout.len(),
            hash(&stdout),
            stderr.len(),
            hash(&stderr),
        );
        if pin_of(row.label) != Some(&got) {
            eprintln!(
                "PIN (\"{}\", {}, {}, {}, 0x{:016x}, {}, 0x{:016x}),",
                got.0, got.1, got.2, got.3, got.4, got.5, got.6
            );
            eprintln!(
                "--- {} stdout\n{}\n--- stderr\n{}",
                row.label,
                String::from_utf8_lossy(&out.stdout).replace('\u{8}', "<"),
                String::from_utf8_lossy(&out.stderr)
            );
            wrong.push(row.label);
        }
        if let Some(file) = row.locked {
            let path = dir.join("tree").join(file);
            unlock(&path);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    assert!(
        wrong.is_empty(),
        "{} run(s) did not print what the member-at-a-time writer printed: {wrong:?}",
        wrong.len()
    );
}
