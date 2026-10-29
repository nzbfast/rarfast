//! Spec G 3.8.3's vote across the WHOLE of a file, on the command line.
//!
//! `rarfast a` hands every file to the library as a source that can seek
//! (`Payload::Seekable`). A file of
//! 4 GiB and more is judged on sixteen samples across all of it and not
//! on its first 32 MiB: one whose head will not compress and whose body
//! does is COMPRESSED. A file under 4 GiB is judged on its first 32 MiB
//! exactly as before (the look's sixteen seeks cost a hard disk 0.2 s a
//! member, which only a large member can carry): the same two shapes of
//! 38 and 40 MiB keep the verdicts their heads give. The library's rows
//! are in rarkit's `tests/store_incompressible.rs`.

use std::path::{Path, PathBuf};
use std::process::Command;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

const MIB: usize = 1 << 20;

/// The two files, in a directory of their own: 32 MiB of noise in front of
/// 6 MiB of words (`head-noise.bin`: its last three samples lie in the
/// words), and 3.25 MiB of words in front of noise, 40 MiB in all
/// (`head-text.bin`: one sample lies in the words).
fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "rarfast-store-whole-member-{}-{tag}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut head_noise = rarkit_testdata::scramble(1, 32 * MIB);
    head_noise.extend_from_slice(&rarkit_testdata::chatter(2, 6 * MIB));
    std::fs::write(dir.join("head-noise.bin"), head_noise).unwrap();
    let mut head_text = rarkit_testdata::chatter(3, 13 * MIB / 4);
    head_text.extend_from_slice(&rarkit_testdata::scramble(4, 40 * MIB - 13 * MIB / 4));
    std::fs::write(dir.join("head-text.bin"), head_text).unwrap();
    dir
}

/// `rarfast a <switches> set.rar head-noise.bin head-text.bin` in `dir`:
/// what it printed.
fn create(dir: &Path, switches: &[&str]) -> String {
    let out = Command::new(rarfast())
        .current_dir(dir)
        .arg("a")
        .args(switches)
        .arg("set.rar")
        .arg("head-noise.bin")
        .arg("head-text.bin")
        .env_remove("RARKIT_STORE_ONE_MISS")
        .env_remove("RARKIT_STORE_PACKED_SAMPLES")
        .env_remove("RARKIT_SOLID_STORE")
        .output()
        .unwrap();
    assert!(out.status.success(), "rarfast a {switches:?}: {out:?}");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The `Compression:` line `rarfast lt` prints for each member of
/// `archive`, by name.
fn methods(dir: &Path, archive: &str) -> Vec<(String, String)> {
    let out = Command::new(rarfast())
        .current_dir(dir)
        .args(["lt", archive])
        .output()
        .unwrap();
    assert!(out.status.success(), "rarfast lt {archive}: {out:?}");
    let listing = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut found = Vec::new();
    let mut name = None;
    for line in listing.lines() {
        if let Some(rest) = line.trim_start().strip_prefix("Name: ") {
            name = Some(rest.trim().to_string());
        } else if let Some(rest) = line.trim_start().strip_prefix("Compression: ") {
            if let Some(name) = name.take() {
                found.push((name, rest.trim().to_string()));
            }
        }
    }
    found
}

fn tests(dir: &Path, archive: &str) {
    let out = Command::new(rarfast())
        .current_dir(dir)
        .args(["t", "-idq", archive])
        .output()
        .unwrap();
    assert!(out.status.success(), "rarfast t {archive}: {out:?}");
    assert!(out.stderr.is_empty(), "rarfast t {archive}: {out:?}");
}

/// UNDER THE FLOOR nothing moves: one archive, a solid one and a volume
/// set, at -m1 and -m3: the file whose head is noise is STORED on its
/// head, as a reader's is, the one whose head is words is compressed,
/// each is named once as it is added, and the archive tests.
#[test]
fn a_file_under_4_gib_is_judged_on_its_head_as_before() {
    for (tag, switches, first) in [
        ("m1", &["-m1"][..], "set.rar"),
        ("m3", &["-m3"][..], "set.rar"),
        ("solid", &["-m1", "-s"][..], "set.rar"),
        ("volumes", &["-m1", "-v24m"][..], "set.part1.rar"),
    ] {
        let dir = work(tag);
        let printed = create(&dir, switches);
        for name in ["head-noise.bin", "head-text.bin"] {
            // A volume set names it again, under `...`, in each volume it
            // continues into.
            assert_eq!(
                printed.matches(&format!("Adding    {name}")).count(),
                1,
                "{tag}: {name} is not added once in {printed:?}"
            );
        }
        // A volume lists the members that begin in it.
        let mut volumes: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".rar"))
            .collect();
        volumes.sort();
        assert_eq!(volumes[0], first, "{tag}: the set's first volume");
        let methods: Vec<(String, String)> = volumes
            .iter()
            .flat_map(|volume| methods(&dir, volume))
            .collect();
        let of = |name: &str| {
            methods
                .iter()
                .find(|(member, _)| member == name)
                .unwrap_or_else(|| panic!("{tag}: {name} is not listed in {methods:?}"))
                .1
                .clone()
        };
        assert!(
            of("head-noise.bin").contains("-m0"),
            "{tag}: under 4 GiB a noise head no longer stores the file: {methods:?}"
        );
        assert!(
            !of("head-text.bin").contains("-m0"),
            "{tag}: under 4 GiB a head of words no longer compresses the file: {methods:?}"
        );
        tests(&dir, first);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// AT THE FLOOR the whole file votes. A file of exactly 4 GiB whose first
/// 64 MiB are noise and whose rest is a hole (zeros, which the filesystem
/// does not store): its head would store all 4 GiB of it; across the
/// whole file every sample lies in the zeros, so it is COMPRESSED, to
/// little more than its head.
#[test]
fn a_file_of_4_gib_is_judged_across_its_whole_length() {
    use std::io::Write;
    let dir = std::env::temp_dir().join(format!(
        "rarfast-store-whole-member-{}-floor",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    {
        let mut file = std::fs::File::create(dir.join("head-noise.bin")).unwrap();
        file.write_all(&rarkit_testdata::scramble(5, 64 * MIB))
            .unwrap();
        file.set_len(4 << 30).unwrap();
    }
    let out = Command::new(rarfast())
        .current_dir(&dir)
        .args(["a", "-m1", "-idq", "set.rar", "head-noise.bin"])
        .env_remove("RARKIT_STORE_ONE_MISS")
        .env_remove("RARKIT_STORE_PACKED_SAMPLES")
        .env_remove("RARKIT_SOLID_STORE")
        .output()
        .unwrap();
    assert!(out.status.success(), "rarfast a: {out:?}");
    let methods = methods(&dir, "set.rar");
    assert!(
        !methods[0].1.contains("-m0"),
        "a 4 GiB file was stored on its head: {methods:?}"
    );
    let packed = std::fs::metadata(dir.join("set.rar")).unwrap().len();
    assert!(
        packed < 128 << 20,
        "64 MiB of noise and a hole packed to {packed} bytes"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
