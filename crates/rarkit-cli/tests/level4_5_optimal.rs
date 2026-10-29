//! The optimal-parse options on the command line (SPEC-G 3.8.1, SPEC-H3 8.1
//! acceptance test 3): `rarfast` reads `RARKIT_L4_OPTIMAL` and
//! `RARKIT_L5_OPTIMAL` (`1` on, unset or `0` off) and passes them to the
//! library as `WriteOptions::level4_optimal` and `level5_optimal`; each
//! reaches its own level only, and no rar dialect switch sets either, so a
//! command line written for rar writes the default however its switches
//! are spelled. `RARKIT_L4_TREE` is read the same way
//! (`WriteOptions::level4_tree`, SPEC-H3 8.1 acceptance test 10): it keeps
//! the tree at level 4, reaches no other level, no rar switch sets it, and
//! `RARKIT_L4_OPTIMAL` wins where both are on. `RARKIT_L5_TREE`
//! (`WriteOptions::level5_tree`, level 5 by class) is its twin at level 5:
//! it keeps the tree for every member, of a solid set or not, where the
//! default gives a member the chains by its class. `RARKIT_L5_FAR_ONLY`
//! (`WriteOptions::level5_far_links_only`, the class without its second
//! statistic) is read the same way: a member whose head reads far keeps
//! the tree whatever long matches the head holds, where by default one
//! that holds enough takes the chains; it reaches level 5 only, and the
//! tree knob and the optimal knob each win over it.
//!
//! A shipped `rarfast` reads no environment word; the create path's exist only
//! under the feature `writer-knobs`, which this test builds with:
//!
//! ```text
//! cargo test -p rarkit-cli --features writer-knobs --test level4_5_optimal
//! ```
#![cfg(feature = "writer-knobs")]

use std::path::{Path, PathBuf};
use std::process::Command;

const KNOBS: [&str; 5] = [
    "RARKIT_L4_OPTIMAL",
    "RARKIT_L5_OPTIMAL",
    "RARKIT_L4_TREE",
    "RARKIT_L5_TREE",
    "RARKIT_L5_FAR_ONLY",
];

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

fn work(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "rarfast-level-optimal-{}-{tag}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `rarfast a <switches> <name>.rar big.txt` in `dir`, with the knob
/// `knob` set to `value` and the other unset, and the archive's bytes.
fn create(dir: &Path, name: &str, switches: &[&str], knob: Option<(&str, &str)>) -> Vec<u8> {
    create_with(dir, name, switches, knob.as_slice())
}

/// [`create`] with any number of the knobs set.
fn create_with(dir: &Path, name: &str, switches: &[&str], knobs: &[(&str, &str)]) -> Vec<u8> {
    let archive = format!("{name}.rar");
    // `rarfast a` onto an archive that is already there edits it.
    let _ = std::fs::remove_file(dir.join(&archive));
    let mut command = Command::new(rarfast());
    command
        .current_dir(dir)
        .arg("a")
        .args(switches)
        .arg(&archive)
        .arg("big.txt");
    for knob in KNOBS {
        command.env_remove(knob);
    }
    for (knob, value) in knobs {
        command.env(knob, value);
    }
    let out = command.output().unwrap();
    assert!(out.status.success(), "rarfast a: {:?}", out);
    std::fs::read(dir.join(archive)).unwrap()
}

#[test]
fn each_knob_reaches_its_own_level_and_no_rar_switch_does() {
    let dir = work("m45");
    std::fs::write(
        dir.join("big.txt"),
        rarkit_testdata::chatter(0x3435, 600_000),
    )
    .unwrap();
    for (level, own, other) in [
        ("-m4", "RARKIT_L4_OPTIMAL", "RARKIT_L5_OPTIMAL"),
        ("-m5", "RARKIT_L5_OPTIMAL", "RARKIT_L4_OPTIMAL"),
    ] {
        let default = create(&dir, "default", &[level, "-idq"], None);
        let zero = create(&dir, "zero", &[level, "-idq"], Some((own, "0")));
        assert!(zero == default, "{own}=0 at {level}");
        let optimal = create(&dir, "optimal", &[level, "-idq"], Some((own, "1")));
        assert!(
            optimal != default,
            "{own}=1 reaches a 600 KB member at {level}"
        );
        let crossed = create(&dir, "crossed", &[level, "-idq"], Some((other, "1")));
        assert!(crossed == default, "{other}=1 does not reach {level}");
        // rar's own switches, however spelled, write the default.
        let spelled = create(
            &dir,
            "spelled",
            &[level, "-mt4", "-s-", "-ma5", "-idq"],
            None,
        );
        assert!(
            spelled == default,
            "no rar switch sets the option at {level}"
        );
        // And the optimal archive is a sound one.
        let test = Command::new(rarfast())
            .current_dir(&dir)
            .args(["t", "-idq", "optimal.rar"])
            .output()
            .unwrap();
        assert!(test.status.success(), "rarfast t optimal.rar: {:?}", test);
    }
    // Levels 1 to 3 are moved by neither knob.
    for level in ["-m1", "-m2", "-m3"] {
        let default = create(&dir, "default", &[level, "-idq"], None);
        for knob in KNOBS {
            let on = create(&dir, "on", &[level, "-idq"], Some((knob, "1")));
            assert!(on == default, "{knob}=1 moved a byte at {level}");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_tree_knob_reaches_level_4_only_and_the_optimal_knob_wins() {
    let dir = work("m4tree");
    std::fs::write(
        dir.join("big.txt"),
        rarkit_testdata::chatter(0x3435, 600_000),
    )
    .unwrap();
    let default = create(&dir, "default", &["-m4", "-idq"], None);
    let zero = create(
        &dir,
        "zero",
        &["-m4", "-idq"],
        Some(("RARKIT_L4_TREE", "0")),
    );
    assert!(zero == default, "RARKIT_L4_TREE=0 at -m4");
    let tree = create(
        &dir,
        "tree",
        &["-m4", "-idq"],
        Some(("RARKIT_L4_TREE", "1")),
    );
    assert!(
        tree != default,
        "RARKIT_L4_TREE=1 reaches a 600 KB member at -m4"
    );
    let optimal = create(
        &dir,
        "optimal",
        &["-m4", "-idq"],
        Some(("RARKIT_L4_OPTIMAL", "1")),
    );
    assert!(tree != optimal, "the tree knob is not the optimal one");
    let both = create_with(
        &dir,
        "both",
        &["-m4", "-idq"],
        &[("RARKIT_L4_TREE", "1"), ("RARKIT_L4_OPTIMAL", "1")],
    );
    assert!(
        both == optimal,
        "with both knobs on, RARKIT_L4_OPTIMAL wins"
    );
    // rar's own switches, however spelled, write the default.
    let spelled = create(
        &dir,
        "spelled",
        &["-m4", "-mt4", "-s-", "-ma5", "-idq"],
        None,
    );
    assert!(spelled == default, "no rar switch sets the tree option");
    let test = Command::new(rarfast())
        .current_dir(&dir)
        .args(["t", "-idq", "tree.rar"])
        .output()
        .unwrap();
    assert!(test.status.success(), "rarfast t tree.rar: {:?}", test);
    // A solid archive takes it too.
    let solid = create(&dir, "solid", &["-m4", "-s", "-idq"], None);
    let solid_tree = create(
        &dir,
        "solidtree",
        &["-m4", "-s", "-idq"],
        Some(("RARKIT_L4_TREE", "1")),
    );
    assert!(
        solid_tree != solid,
        "RARKIT_L4_TREE=1 reaches a solid -m4 archive"
    );
    // Every other level is as it was.
    for level in ["-m1", "-m2", "-m3", "-m5"] {
        let default = create(&dir, "default", &[level, "-idq"], None);
        let on = create(&dir, "on", &[level, "-idq"], Some(("RARKIT_L4_TREE", "1")));
        assert!(on == default, "RARKIT_L4_TREE=1 moved a byte at {level}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_level_5_tree_knob_reaches_level_5_only_and_the_optimal_knob_wins() {
    // The member is 600 KB: past the lone bound and under a megabyte, so
    // level 5 gives it the chains by default (it has no class reading).
    let dir = work("m5tree");
    std::fs::write(
        dir.join("big.txt"),
        rarkit_testdata::chatter(0x3435, 600_000),
    )
    .unwrap();
    let default = create(&dir, "default", &["-m5", "-idq"], None);
    let zero = create(
        &dir,
        "zero",
        &["-m5", "-idq"],
        Some(("RARKIT_L5_TREE", "0")),
    );
    assert!(zero == default, "RARKIT_L5_TREE=0 at -m5");
    let tree = create(
        &dir,
        "tree",
        &["-m5", "-idq"],
        Some(("RARKIT_L5_TREE", "1")),
    );
    assert!(
        tree != default,
        "RARKIT_L5_TREE=1 reaches a 600 KB member at -m5"
    );
    let optimal = create(
        &dir,
        "optimal",
        &["-m5", "-idq"],
        Some(("RARKIT_L5_OPTIMAL", "1")),
    );
    assert!(tree != optimal, "the tree knob is not the optimal one");
    let both = create_with(
        &dir,
        "both",
        &["-m5", "-idq"],
        &[("RARKIT_L5_TREE", "1"), ("RARKIT_L5_OPTIMAL", "1")],
    );
    assert!(
        both == optimal,
        "with both knobs on, RARKIT_L5_OPTIMAL wins"
    );
    // rar's own switches, however spelled, write the default.
    let spelled = create(
        &dir,
        "spelled",
        &["-m5", "-mt4", "-s-", "-ma5", "-idq"],
        None,
    );
    assert!(spelled == default, "no rar switch sets the tree option");
    let test = Command::new(rarfast())
        .current_dir(&dir)
        .args(["t", "-idq", "default.rar"])
        .output()
        .unwrap();
    assert!(test.status.success(), "rarfast t default.rar: {:?}", test);
    // A solid archive takes the chains by default and the tree by the knob.
    let solid = create(&dir, "solid", &["-m5", "-s", "-idq"], None);
    let solid_tree = create(
        &dir,
        "solidtree",
        &["-m5", "-s", "-idq"],
        Some(("RARKIT_L5_TREE", "1")),
    );
    assert!(
        solid_tree != solid,
        "RARKIT_L5_TREE=1 reaches a solid -m5 archive"
    );
    // Every other level is as it was.
    for level in ["-m1", "-m2", "-m3", "-m4"] {
        let default = create(&dir, "default", &[level, "-idq"], None);
        let on = create(&dir, "on", &[level, "-idq"], Some(("RARKIT_L5_TREE", "1")));
        assert!(on == default, "RARKIT_L5_TREE=1 moved a byte at {level}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// 2 MiB whose head reads far: the text of a vocabulary of many thousand
/// words, most of them met again only megabytes on. With `long`, a
/// phrase from a few thousand bytes back is written again every 400
/// bytes, which gives the head some 2,600 long matches where the class's
/// second statistic asks for 1,024; without, it holds next to none.
fn far_text(long: bool) -> Vec<u8> {
    let mut out = rarkit_testdata::chatter_of(0x6661, 1 << 15, 2 << 20);
    if long {
        let mut at = 4_096;
        while at + 32 <= out.len() {
            out.copy_within(at - 3_000..at - 2_968, at);
            at += 400;
        }
    }
    out
}

#[test]
fn the_level_5_far_links_only_knob_keeps_the_tree_on_a_far_member_with_long_matches_and_moves_nothing_else(
) {
    let dir = work("m5far");
    let knob = "RARKIT_L5_FAR_ONLY";
    // A far member with long matches: the chains by default, the tree by
    // the knob, which is what the tree knob writes for it.
    std::fs::write(dir.join("big.txt"), far_text(true)).unwrap();
    let default = create(&dir, "default", &["-m5", "-idq"], None);
    let tree = create(
        &dir,
        "tree",
        &["-m5", "-idq"],
        Some(("RARKIT_L5_TREE", "1")),
    );
    assert!(
        default != tree,
        "by default its long matches give it the chains"
    );
    let zero = create(&dir, "zero", &["-m5", "-idq"], Some((knob, "0")));
    assert!(zero == default, "{knob}=0 at -m5");
    let on = create(&dir, "on", &["-m5", "-idq"], Some((knob, "1")));
    assert!(on == tree, "{knob}=1: by far links alone it keeps the tree");
    let test = Command::new(rarfast())
        .current_dir(&dir)
        .args(["t", "-idq", "default.rar"])
        .output()
        .unwrap();
    assert!(test.status.success(), "rarfast t default.rar: {:?}", test);
    // Any width writes the same archive, and no rar switch sets the knob.
    for width in ["-mt1", "-mt2", "-mt8"] {
        let wide = create(&dir, "wide", &["-m5", width, "-idq"], None);
        assert!(wide == default, "the default at {width}");
    }
    let spelled = create(&dir, "spelled", &["-m5", "-s-", "-ma5", "-idq"], None);
    assert!(spelled == default, "no rar switch sets the option");
    // The tree knob and the optimal knob each win over it.
    let both = create_with(
        &dir,
        "both",
        &["-m5", "-idq"],
        &[(knob, "1"), ("RARKIT_L5_TREE", "1")],
    );
    assert!(both == tree, "with the tree knob on, the tree knob wins");
    let optimal = create(
        &dir,
        "optimal",
        &["-m5", "-idq"],
        Some(("RARKIT_L5_OPTIMAL", "1")),
    );
    let with_optimal = create_with(
        &dir,
        "withoptimal",
        &["-m5", "-idq"],
        &[(knob, "1"), ("RARKIT_L5_OPTIMAL", "1")],
    );
    assert!(with_optimal == optimal, "the optimal knob wins");
    // A solid archive of that one member goes by it too.
    let solid = create(&dir, "solid", &["-m5", "-s", "-idq"], None);
    let solid_on = create(&dir, "solidon", &["-m5", "-s", "-idq"], Some((knob, "1")));
    assert!(
        solid_on != solid,
        "{knob}=1 reaches a solid run's first member"
    );
    // Every other level is as it was.
    for level in ["-m1", "-m2", "-m3", "-m4"] {
        let default = create(&dir, "default", &[level, "-idq"], None);
        let on = create(&dir, "on", &[level, "-idq"], Some((knob, "1")));
        assert!(on == default, "{knob}=1 moved a byte at {level}");
    }
    // A far member with no long match keeps the tree either way: one
    // archive.
    std::fs::write(dir.join("big.txt"), far_text(false)).unwrap();
    let default = create(&dir, "default", &["-m5", "-idq"], None);
    let on = create(&dir, "on", &["-m5", "-idq"], Some((knob, "1")));
    assert!(
        on == default,
        "a far member with no long match is not moved"
    );
    // A member the far links give the chains, and one that is not read,
    // write one archive either way.
    for len in [1_500_000, 600_000] {
        // The shared text reads near: 2.6 far links a byte against a
        // cut-off of 7.0.
        let near = rarkit_testdata::chatter(0x3435, len);
        std::fs::write(dir.join("big.txt"), near).unwrap();
        let default = create(&dir, "default", &["-m5", "-idq"], None);
        let on = create(&dir, "on", &["-m5", "-idq"], Some((knob, "1")));
        assert!(on == default, "{knob}=1 moved a {len} byte near member");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
