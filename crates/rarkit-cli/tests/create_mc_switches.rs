//! `-mc<par>` beside a creating command: honoured, harmless, or declined
//! by name, and never accepted in silence.
//!
//! Until 9 Oct 2026 every `-mc` form was accepted and read by nothing, so
//! `rarfast a -mcd- arc.rar sound.wav` wrote the archive it writes with
//! no switch and exited 0.
//!
//! **Measured against rar 7.23 on 9 Oct 2026** (an Apple silicon Mac):
//! `rar a -m3 -ma5 -mt1 -mc<par>` of one member, the archive compared
//! byte for byte with the one written with no switch, over four members:
//! text (672,360 bytes, 85,933 packed), 16 bit stereo sound (600,000 and
//! 281,408), a table of 4 byte records (600,000 and 43,621) and an
//! executable with x86-64 and arm64 code (1,961,872 and 593,327). The
//! reference exits 0 on every form, the ones it does not know included.
//!
//! | `-mc<par>` | the reference, against no switch | rarfast |
//! |---|---|---|
//! | `-mc-` | every filter off: sound 541,678, table 200,789, executable 617,131, text the same bytes | HONOURED: no filter is looked for |
//! | `-mc` `-mc+` `-mcd` `-mcd+` `-mce` | the same bytes on all four | accepted, the same bytes |
//! | `-mca` `-mca-` `-mca+` | the same bytes on all four | accepted, the same bytes |
//! | `-mcl` `-mcl-` `-mcx-` | the same bytes on all four | accepted, the same bytes |
//! | `-mct` `-mct+` `-mct-` `-mcc+` `-mcc-` `-mci+` `-mc63:128t+` `-mcz` | the same bytes on all four | accepted, the same bytes |
//! | `-mcd-` `-mcD-` `-mc1d-` | the delta filter off alone: sound 541,678, table 200,789, executable 597,618 | DECLINED by name, exit 7 |
//! | `-mce-` `-mcE-` `-mcde-` | the x86 filter off alone: executable 612,830, the rest the same bytes | DECLINED |
//! | `-mcd-e-` | both off: the sizes of `-mc-` | DECLINED |
//! | `-mce+` | the x86 filter forced on everything: every member a few bytes larger, the executable 594,275 | DECLINED |
//! | `-mc2d+` `-mc4:2d+` | a delta of that many channels forced: text 165,080 and 308,386 | DECLINED |
//! | `-mcl+` | the long range search: 78,904, 276,777, 43,627, 592,405 | DECLINED |
//! | `-mcx` `-mcx+` | the exhaustive search: 77,914, 275,436, 42,942, 585,033 | DECLINED |
//!
//! The forms are read in order there: `-mcd+ -mc-` and `-mc- -mc+` leave
//! every filter off, `-mc- -mcd+` turns the delta filter back on alone
//! (declined here).
//!
//! Why some are declined: the writer looks for a filter or does not
//! (`rarkit::FilterPolicy`), and has no switch for one filter or for the
//! match search. A declined command line is named as typed, exits 7 (the
//! code for a command line that is not run) and writes nothing. Why the
//! ARM forms are accepted: no run could be made to differ from the
//! reference's with no switch.
//!
//! Not this file's: an upper case switch NAME (`-MCD-`) is rarfast's
//! `Unknown option`, exit 7, where the reference reads it as `-mcd-`.
//!
//! Every run is `-mt2` over one member of at most 600,000 bytes: a pool
//! two threads wide and a few MiB of memory.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// 16 bit stereo sound, 600,000 bytes: two slow sawtooth waves with a
/// little noise on them, which a 2 or 4 channel delta packs far better.
fn sound() -> Vec<u8> {
    let mut source = rarkit_testdata::Seeded::new(0x6d63);
    let mut out = Vec::with_capacity(600_000);
    for i in 0..150_000_i32 {
        let noise = source.below(7) as i32 - 3;
        let left = ((i * 37) % 16_000 - 8_000 + noise) as i16;
        let right = ((i * 23) % 12_000 - 6_000 + noise) as i16;
        out.extend_from_slice(&left.to_le_bytes());
        out.extend_from_slice(&right.to_le_bytes());
    }
    out
}

/// Text, 600,000 bytes.
fn words() -> Vec<u8> {
    rarkit_testdata::chatter(0x6d63, 600_000)
}

/// A directory of one test's own, made afresh under the system's
/// temporary directory, with `sound.bin` and `words.txt` written into it.
fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-mc-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("sound.bin"), sound()).unwrap();
    std::fs::write(dir.join("words.txt"), words()).unwrap();
    dir
}

/// `rarfast a -m3 <switches> <archive> <member>`.
fn add(dir: &Path, switches: &[&str], archive: &str, member: &str) -> Output {
    Command::new(rarfast())
        .current_dir(dir)
        .args(["a", "-idq", "-mt2", "-m3"])
        .args(switches)
        .args([archive, member])
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

/// The archive `switches` write of `member`, which must be written.
fn written(dir: &Path, switches: &[&str], member: &str) -> Vec<u8> {
    let _ = std::fs::remove_file(dir.join("t.rar"));
    let out = add(dir, switches, "t.rar", member);
    assert_eq!(out.status.code(), Some(0), "{switches:?}: {out:?}");
    std::fs::read(dir.join("t.rar")).unwrap()
}

#[test]
fn the_forms_that_change_nothing_at_the_reference_change_nothing() {
    let dir = work("same");
    for member in ["sound.bin", "words.txt"] {
        let plain = written(&dir, &[], member);
        for form in [
            "-mc",
            "-mc+",
            "-mcd",
            "-mcd+",
            "-mce",
            "-mca",
            "-mca-",
            "-mca+",
            "-mcl",
            "-mcl-",
            "-mcx-",
            "-mct",
            "-mct+",
            "-mct-",
            "-mcc+",
            "-mcc-",
            "-mci+",
            "-mc63:128t+",
            "-mcz",
        ] {
            assert!(written(&dir, &[form], member) == plain, "{form} {member}");
        }
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn mc_minus_turns_every_filter_off() {
    let dir = work("off");
    let plain = written(&dir, &[], "sound.bin");
    for switches in [&["-mc-"][..], &["-mcd+", "-mc-"], &["-mc-", "-mc+"]] {
        let off = written(&dir, switches, "sound.bin");
        // The delta filter is worth more than a quarter of this member
        // (rar 7.23: 281,408 with it, 541,678 without).
        assert!(
            off.len() > plain.len() + plain.len() / 4,
            "{switches:?}: {} against {}",
            off.len(),
            plain.len()
        );
        // And the archive is sound: it tests, and unpacks to the member.
        let tested = Command::new(rarfast())
            .current_dir(&dir)
            .args(["t", "-idq", "-mt2", "t.rar"])
            .output()
            .unwrap();
        assert_eq!(tested.status.code(), Some(0), "{switches:?}: {tested:?}");
        let printed = Command::new(rarfast())
            .current_dir(&dir)
            .args(["p", "-inul", "-mt2", "t.rar"])
            .output()
            .unwrap();
        assert!(printed.stdout == sound(), "{switches:?}");
    }
    // Text has no filter to lose: the same bytes, as at the reference.
    assert!(written(&dir, &["-mc-"], "words.txt") == written(&dir, &[], "words.txt"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_form_the_writer_cannot_honour_is_declined_by_name() {
    let dir = work("declined");
    for switches in [
        &["-mcd-"][..],
        &["-mcD-"],
        &["-mc1d-"],
        &["-mce-"],
        &["-mcE-"],
        &["-mcde-"],
        &["-mcd-e-"],
        &["-mce+"],
        &["-mc2d+"],
        &["-mc4:2d+"],
        &["-mcl+"],
        &["-mcx"],
        &["-mcx+"],
        &["-mc-", "-mcd+"],
    ] {
        let named = switches.last().unwrap();
        let out = add(&dir, switches, "no.rar", "sound.bin");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(7), "{switches:?}: {stderr}");
        assert!(
            stderr.contains(&format!("`{named}`")),
            "{switches:?}: {stderr}"
        );
        assert!(
            !dir.join("no.rar").exists(),
            "{switches:?} wrote an archive"
        );
        assert!(dir.join("sound.bin").is_file());
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
