//! The store rule's option on the command line (SPEC-G 3.8.3): `rarfast`
//! reads `RARKIT_STORE_ONE_MISS` (`1` on, unset or `0` off) and passes it
//! to the library as `WriteOptions::store_one_miss`, which stores a member
//! of 128 MiB and more only when at least 15 of its 16 samples will not
//! compress, as before 1 Oct 2026, instead of at least 12; no rar dialect
//! switch sets it, it reaches every level, and it reaches no solid set and
//! no member under 128 MiB.
//!
//! A shipped `rarfast` reads no environment word; the create path's exist only
//! under the feature `writer-knobs`, which this test builds with:
//!
//! ```text
//! cargo test -p rarkit-cli --features writer-knobs --test store_one_miss
//! ```
#![cfg(feature = "writer-knobs")]

use std::path::{Path, PathBuf};
use std::process::Command;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-store-miss-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const MEMBER_BYTES: usize = 128 << 20;

/// `len` bytes of noise whose first three samples of sixteen are zero
/// bytes: 13 of 16 incompressible, which at 128 MiB the rule stores and the
/// option compresses.
fn noise_with_three_samples_that_compress(len: usize) -> Vec<u8> {
    let mut state = 0x1001_2026_u64 | 1;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        out.extend_from_slice(&state.wrapping_mul(0x2545_f491_4f6c_dd1d).to_le_bytes());
    }
    out.truncate(len);
    // `rarfast` hands a file over as a reader, which is judged on its
    // first 32 MiB: the samples are centred in sixteenths of that.
    let segment = len.min(32 << 20) / 16;
    for k in 0..3 {
        let sample = k * segment + (segment - (64 << 10)) / 2;
        out[sample..sample + (64 << 10)].fill(0);
    }
    out
}

/// `rarfast a <switches> <name>.rar member.bin` in `dir`, with
/// `RARKIT_STORE_ONE_MISS` as given, and the archive's bytes.
fn create(dir: &Path, name: &str, switches: &[&str], one_miss: Option<&str>) -> Vec<u8> {
    let archive = format!("{name}.rar");
    // `rarfast a` onto an existing archive edits it, and the loop below
    // reuses its names.
    let _ = std::fs::remove_file(dir.join(&archive));
    let mut command = Command::new(rarfast());
    command
        .current_dir(dir)
        .arg("a")
        .args(switches)
        .arg(&archive)
        .arg("member.bin")
        .env_remove("RARKIT_STORE_ONE_MISS");
    // A row named `kept-` keeps the store rule out of a solid set
    // (`RARKIT_SOLID_STORE=0`).
    command.env_remove("RARKIT_SOLID_STORE");
    if name.starts_with("kept-") {
        command.env("RARKIT_SOLID_STORE", "0");
    }
    if let Some(value) = one_miss {
        command.env("RARKIT_STORE_ONE_MISS", value);
    }
    let out = command.output().unwrap();
    assert!(out.status.success(), "rarfast a: {:?}", out);
    std::fs::read(dir.join(archive)).unwrap()
}

#[test]
fn rarkit_store_one_miss_reaches_every_level_and_no_rar_switch_does() {
    let dir = work("levels");
    std::fs::write(
        dir.join("member.bin"),
        noise_with_three_samples_that_compress(MEMBER_BYTES),
    )
    .unwrap();
    for level in ["-m1", "-m2", "-m3", "-m4", "-m5"] {
        let default = create(&dir, "default", &[level, "-idq"], None);
        assert!(default == create(&dir, "zero", &[level, "-idq"], Some("0")));
        assert!(
            default.len() > MEMBER_BYTES,
            "{level}: 13 incompressible samples of 16 did not store the member ({} bytes)",
            default.len()
        );
        // The option at levels 1 and 3 (the verdict is taken before the
        // level is looked at; the tree's levels on 128 MiB of noise are
        // minutes in a test build).
        if level != "-m1" && level != "-m3" {
            continue;
        }
        let one_miss = create(&dir, "onemiss", &[level, "-idq"], Some("1"));
        assert!(
            one_miss.len() < MEMBER_BYTES,
            "{level}: RARKIT_STORE_ONE_MISS=1 still stored the member ({} bytes)",
            one_miss.len()
        );
        // rar's own switches, however spelled, write the default.
        let spelled = create(
            &dir,
            "spelled",
            &[level, "-mt4", "-s-", "-ma5", "-idq"],
            None,
        );
        assert!(spelled == default, "{level}: no rar switch sets the option");
        // And both are sound archives.
        for archive in ["default.rar", "onemiss.rar"] {
            let test = Command::new(rarfast())
                .current_dir(&dir)
                .args(["t", "-idq", archive])
                .output()
                .unwrap();
            assert!(test.status.success(), "rarfast t {archive}: {:?}", test);
        }
    }
    // A solid member is judged by the same vote since 1 Oct 2026 (spec G
    // 3.8.3, `WriteOptions::solid_store`), so the option reaches it too;
    // with the rule kept out of solid sets (`RARKIT_SOLID_STORE=0`) a
    // solid set never samples a member, and the option is not its.
    let off = create(&dir, "solid-off", &["-m3", "-s", "-idq"], None);
    let on = create(&dir, "solid-on", &["-m3", "-s", "-idq"], Some("1"));
    assert!(off.len() > MEMBER_BYTES, "a solid member was not stored");
    assert!(
        on.len() < MEMBER_BYTES,
        "RARKIT_STORE_ONE_MISS=1 still stored a solid member"
    );
    let off = create(&dir, "kept-off", &["-m3", "-s", "-idq"], None);
    let on = create(&dir, "kept-on", &["-m3", "-s", "-idq"], Some("1"));
    assert!(
        on == off,
        "RARKIT_STORE_ONE_MISS=1 moved a byte of a solid set the rule is kept out of"
    );
    assert!(off.len() < MEMBER_BYTES, "a solid member was stored");
    // Nor is a member under 128 MiB: one miss is its rule either way.
    std::fs::write(
        dir.join("member.bin"),
        noise_with_three_samples_that_compress(MEMBER_BYTES - 1),
    )
    .unwrap();
    let off = create(&dir, "under-off", &["-m3", "-idq"], None);
    let on = create(&dir, "under-on", &["-m3", "-idq"], Some("1"));
    assert!(
        on == off,
        "RARKIT_STORE_ONE_MISS=1 moved a byte of a member under 128 MiB"
    );
    assert!(
        off.len() < MEMBER_BYTES - 1,
        "a member under 128 MiB was stored on 13 samples of 16"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
