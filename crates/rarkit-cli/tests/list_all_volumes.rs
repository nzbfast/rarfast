//! `l -v`, `v -v`, `lt -v` and `lb -v` on a volume of a set list every
//! volume from it to the set's end, as unrar does.
//!
//! The defect (bench/multivolume-list-repro-24oct, 24 Oct 2026, the
//! shipped 0.9.0 candidate): on volume 1 of a RAR 5 set `rarfast l -v`
//! and `lt -v` listed volume 1's members only and named one volume, exit
//! 0, where unrar 7.23 walks every volume. `t` and `x` were right.
//!
//! What unrar 7.23 prints, MEASURED on an M3 Mac on 24 Oct 2026 over
//! sets written by rar 7.23 (`a -ma5 -m0 -v50k` and `-m3 -v5k` over the
//! six text members [`inputs`] writes), banner aside:
//!
//! - Each volume is listed as an archive of its own, `Archive:` and
//!   `Details:` lines and all, from the volume named to the set's last.
//!   A later volume named lists from there on; the walk does not start
//!   over at the first.
//! - A volume's table carries EVERY fragment in it, the continued ones
//!   too, but its totals count a member only in the volume it starts in:
//!   the size and the count leave a continued fragment out, the packed
//!   sum keeps it.
//! - `l` and `v` close each volume on its totals with no blank line after
//!   them, and the set on one more totals row, a column further left: the
//!   size of every member, the packed size of every fragment, and the
//!   count. It ends on that row, without the blank line a one-archive
//!   listing ends on. One volume listed alone has no such row and keeps
//!   the blank line.
//! - `lt` puts its one closing blank line after the last volume only;
//!   `lta` says `Service: EOF` after each volume's blocks.
//! - `lb` names every fragment, so a member split over three volumes is
//!   named three times.
//! - A volume the set needs and the disk lacks ends the walk with
//!   `Cannot find volume <name>` on stderr and exit 6, after the
//!   volumes in hand are listed with the set's totals row.
//! - On an archive that is not a volume, `-v` changes nothing.
//!
//! Every row runs on rarkit's own sets, which need nothing on PATH. Where
//! a genuine `rar` and `unrar` 7.x are on PATH the same rows also run on
//! the reference's sets and compare with the reference's own listing.

use std::path::{Path, PathBuf};
use std::process::Command;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// An empty directory of one test's own; `tag` tells the tests apart.
fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-list-v-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// One exit code and the two streams.
struct Ran {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run(binary: &Path, dir: &Path, args: &[&str]) -> Ran {
    let out = Command::new(binary)
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|err| panic!("{} could not be run: {err}", binary.display()));
    Ran {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// The members' names under `text/`, and their sizes: one starts in a
/// later volume and several span a boundary at the volume sizes below.
const MEMBERS: [(&str, usize); 6] = [
    ("00.txt", 30_000),
    ("01.txt", 70_000),
    ("02.txt", 9_000),
    ("03.txt", 45_000),
    ("04.txt", 120_000),
    ("05.txt", 5_000),
];

/// Writes the members into `dir/text`: lines of common English words
/// drawn by a fixed generator, so the text is the same on every run and
/// compresses as text does.
fn inputs(dir: &Path) {
    const WORDS: [&str; 18] = [
        "the", "quick", "brown", "fox", "jumps", "over", "a", "lazy", "dog", "volume", "member",
        "archive", "listing", "every", "part", "of", "set", "and",
    ];
    let text = dir.join("text");
    std::fs::create_dir_all(&text).unwrap();
    let mut state = 0x2545_f491_4f6c_dd1d_u64;
    for (name, size) in MEMBERS {
        let mut body = String::with_capacity(size + 80);
        while body.len() < size {
            for word in 0..12 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                if word > 0 {
                    body.push(' ');
                }
                body.push_str(WORDS[(state % WORDS.len() as u64) as usize]);
            }
            body.push('\n');
        }
        body.truncate(size);
        std::fs::write(text.join(name), body).unwrap();
    }
}

/// The two sets of each writer: stored at 50 kB volumes, compressed at
/// 5 kB, as `(subdirectory, method, volume)`.
const SETS: [(&str, &str, &str); 2] = [("m0", "-m0", "-v50k"), ("m3", "-m3", "-v5k")];

/// Writes `dir/<sub>/set.rar` from `dir/text` through `writer` and answers
/// the volumes' paths RELATIVE to `dir`, in order.
fn write_set(writer: &Path, dir: &Path, sub: &str, method: &str, volume: &str) -> Vec<String> {
    std::fs::create_dir_all(dir.join(sub)).unwrap();
    let target = format!("{sub}/set.rar");
    let made = run(
        writer,
        dir,
        &[
            "a", "-ma5", method, volume, "-r", "-idq", "-y", &target, "text",
        ],
    );
    assert_eq!(
        made.code,
        Some(0),
        "the set was not written: {}",
        made.stderr
    );
    let mut names: Vec<String> = std::fs::read_dir(dir.join(sub))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".rar"))
        .collect();
    names.sort();
    assert!(
        names.len() >= 3,
        "{sub}: {} volumes, too few to have a member start in a later one",
        names.len()
    );
    names.iter().map(|name| format!("{sub}/{name}")).collect()
}

/// The `Archive:` lines of a listing, in order.
fn archives_named(listing: &str) -> Vec<&str> {
    listing
        .lines()
        .filter_map(|line| line.strip_prefix("Archive: "))
        .collect()
}

/// Whether `listing` names every member and the directory.
fn names_every_member(listing: &str) -> bool {
    MEMBERS.iter().all(|(name, _)| listing.contains(name))
}

/// The checks every set must pass, whoever wrote it.
fn lists_every_volume(dir: &Path, volumes: &[String]) {
    let first = volumes[0].as_str();
    for command in ["l", "v", "lt", "vt", "lta"] {
        let ran = run(&rarfast(), dir, &[command, "-v", first]);
        assert_eq!(ran.code, Some(0), "`{command} -v {first}`: {}", ran.stderr);
        assert_eq!(ran.stderr, "", "`{command} -v {first}` said on stderr");
        assert_eq!(
            archives_named(&ran.stdout),
            volumes,
            "`{command} -v {first}` named other volumes:\n{}",
            ran.stdout
        );
        assert!(
            names_every_member(&ran.stdout),
            "`{command} -v {first}` left a member out:\n{}",
            ran.stdout
        );
    }
    // The set's totals row: every member once, the directory included.
    for command in ["l", "v"] {
        let ran = run(&rarfast(), dir, &[command, "-v", first]);
        let last = ran.stdout.lines().last().unwrap_or("");
        let total: usize = MEMBERS.iter().map(|(_, size)| size).sum();
        assert!(
            last.trim_start().starts_with(&total.to_string())
                && last.trim_end().ends_with(&(MEMBERS.len() + 1).to_string()),
            "`{command} -v` did not end on the set's totals: {last:?}"
        );
    }
    // `lb -v` names each fragment, so the split members more than once.
    let bare = run(&rarfast(), dir, &["lb", "-v", first]);
    assert_eq!(bare.code, Some(0));
    assert!(
        bare.stdout.lines().count() > MEMBERS.len() + 1,
        "`lb -v` named {} lines for a set with members split over volumes",
        bare.stdout.lines().count()
    );
    // Without `-v`: volume 1 alone, as before.
    for command in ["l", "lt"] {
        let ran = run(&rarfast(), dir, &[command, first]);
        assert_eq!(archives_named(&ran.stdout), [first], "`{command}` changed");
    }
    // A later volume named: from there to the end, not from the first.
    let later = run(&rarfast(), dir, &["l", "-v", &volumes[1]]);
    assert_eq!(later.code, Some(0));
    assert_eq!(archives_named(&later.stdout), &volumes[1..]);
}

/// rarkit's own sets: no reference needed.
#[test]
fn l_v_and_lt_v_list_every_volume_of_rarkit_s_own_sets() {
    let dir = work("own");
    inputs(&dir);
    for (sub, method, volume) in SETS {
        let volumes = write_set(&rarfast(), &dir, sub, method, volume);
        lists_every_volume(&dir, &volumes);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A volume the set needs and the disk lacks: the volumes in hand are
/// listed, then `Cannot find volume` and exit 6.
#[test]
fn a_missing_volume_ends_the_listing_with_exit_6() {
    let dir = work("missing");
    inputs(&dir);
    let volumes = write_set(&rarfast(), &dir, "m0", "-m0", "-v50k");
    let gone = volumes[2].clone();
    std::fs::remove_file(dir.join(&gone)).unwrap();
    let ran = run(&rarfast(), &dir, &["l", "-v", &volumes[0]]);
    assert_eq!(ran.code, Some(6), "{}", ran.stderr);
    assert_eq!(archives_named(&ran.stdout), &volumes[..2]);
    assert!(
        ran.stderr.contains(&format!("Cannot find volume {gone}")),
        "stderr: {:?}",
        ran.stderr
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// An archive that is not a volume lists the same with `-v` and without.
#[test]
fn v_changes_nothing_on_an_archive_that_is_not_a_volume() {
    let dir = work("single");
    inputs(&dir);
    let made = run(
        &rarfast(),
        &dir,
        &["a", "-ma5", "-r", "-idq", "-y", "one.rar", "text"],
    );
    assert_eq!(made.code, Some(0), "{}", made.stderr);
    for command in ["l", "v", "lt", "lb"] {
        let with = run(&rarfast(), &dir, &[command, "-v", "one.rar"]);
        let without = run(&rarfast(), &dir, &[command, "one.rar"]);
        assert_eq!(with.code, without.code);
        assert_eq!(with.stdout, without.stdout, "`{command} -v` differs");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A genuine tool of `name` on PATH whose banner is version 7, where one is.
fn genuine(name: &str, banner: &str) -> Option<PathBuf> {
    let out = Command::new(name).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .any(|line| line.starts_with(banner))
        .then(|| PathBuf::from(name))
}

/// unrar's listing without its banner: the blank line and the banner
/// line. The blank line after the banner is the `Archive:` header's own,
/// and rarfast prints it too.
fn without_banner(listing: &str) -> String {
    match listing.strip_prefix('\n') {
        Some(rest) if rest.starts_with("UNRAR ") => rest
            .split_once('\n')
            .map_or("", |(_, tail)| tail)
            .to_owned(),
        _ => listing.to_owned(),
    }
}

/// The two columns rarfast does not yet print as unrar does for a member
/// split over volumes, `-v` or not (owed; this test is not about them):
/// the ratio's `-->`, `<--` and `<->` and the `Pack-CRC32` label.
fn without_split_marks(listing: &str) -> String {
    let mut out = String::with_capacity(listing.len());
    for line in listing.lines() {
        if line.trim_start().starts_with("Ratio: ") {
            out.push_str("       Ratio: *");
        } else if let Some(rest) = line.strip_prefix("  Pack-CRC32: ") {
            out.push_str("       CRC32: ");
            out.push_str(rest);
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

/// The reference's sets, listed by rarfast and by unrar: `l -v` and
/// `lb -v` the same byte for byte, `lt -v` the same but for the split
/// marks. Skipped, and says so, where no genuine `rar` and `unrar` are on
/// PATH.
#[test]
fn l_v_and_lt_v_match_unrar_on_the_reference_s_sets() {
    let (Some(rar), Some(unrar)) = (genuine("rar", "RAR 7."), genuine("unrar", "UNRAR 7.")) else {
        eprintln!("skipped: no genuine rar and unrar 7.x on PATH");
        return;
    };
    let dir = work("reference");
    inputs(&dir);
    for (sub, method, volume) in SETS {
        let volumes = write_set(&rar, &dir, sub, method, volume);
        lists_every_volume(&dir, &volumes);
        for named in [&volumes[0], &volumes[1]] {
            // `v` and `lta` are left out: the split marks and the quick
            // open service (`QO`, which unrar lists under `lta`) are
            // printed apart from unrar's with `-v` or without (owed).
            for command in ["l", "lb", "lt"] {
                let ours = run(&rarfast(), &dir, &[command, "-v", named]);
                let theirs = run(&unrar, &dir, &[command, "-v", named]);
                assert_eq!(ours.code, theirs.code, "`{command} -v {named}`");
                let mut want = without_banner(&theirs.stdout);
                let mut got = ours.stdout.clone();
                if command.starts_with("lt") {
                    want = without_split_marks(&want);
                    got = without_split_marks(&got);
                }
                assert_eq!(got, want, "`{command} -v {named}` differs from unrar");
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
