//! `x` and `e` never place, write over or change a file outside the
//! destination the caller named, whatever order an archive puts its
//! links, hard links, copies and files in.
//!
//! THE RULE (spec F 3.8.2 to 3.8.5, and `safepath`'s rules 1 to 4): a
//! member lands under the destination or not at all. A link may POINT
//! outside under `-ola`, the caller's word for it; nothing is ever
//! written THROUGH one, and no file outside the destination is reached
//! by a later member of the same archive.
//!
//! Each row puts a file `outside/victim` beside the destination `out`,
//! runs rarfast and then asks only what this rule asks: is
//! `outside/victim` as it was, and is nothing new beside it. What the
//! run prints and its exit are reported, not judged, since some rows are
//! refused and some extracted, and either is within the rule.
//!
//! Unix only: the rows plant links with `symlink`.
//!
//! Width and memory: each run states `-mt1` or `-mt4`; the archives are
//! stored members of a few bytes, save the race rows' members of 2 MB (an
//! archive of at most 12 MB, held once in memory), so the test needs
//! little memory and passes on a runner two threads wide.

#![cfg(unix)]

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[path = "../../rarkit/tests/redirection/rewrite.rs"]
mod rewrite;

fn rarfast() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rarfast"))
}

/// A directory of one test's own that is removed when this value is
/// dropped, so a failed assert clears it away as a pass does.
struct DirWatch(PathBuf);

impl DirWatch {
    fn over(tag: &str, width: &str) -> (PathBuf, DirWatch) {
        let dir = std::env::temp_dir().join(format!(
            "rarfast-neverout-{}-{tag}-{}",
            std::process::id(),
            width.trim_start_matches('-')
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("out")).unwrap();
        std::fs::create_dir_all(dir.join("outside")).unwrap();
        std::fs::write(dir.join("outside/victim"), b"KEEP ME").unwrap();
        (dir.clone(), DirWatch(dir))
    }
}

impl Drop for DirWatch {
    fn drop(&mut self) {
        // A row may close a folder to writing; open every folder again so
        // the tree can go, whether or not the row's asserts held.
        fn open(p: &Path) {
            use std::os::unix::fs::PermissionsExt;
            if std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir()) {
                let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755));
                for entry in std::fs::read_dir(p).into_iter().flatten().flatten() {
                    open(&entry.path());
                }
            }
        }
        open(&self.0);
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// What a member of the archive is. A redirection carries its RAR 5
/// type (spec F 3.2.6.2: 1 a Unix link, 4 a hard link, 5 a copy).
enum Kind<'a> {
    File(&'a [u8]),
    Dir,
    Redirect(u64, &'a [u8]),
}

fn block(body: &[u8], out: &mut Vec<u8>) {
    let mut sized = rewrite::vint(body.len() as u64);
    sized.extend_from_slice(body);
    out.extend_from_slice(&rewrite::crc32(&sized).to_le_bytes());
    out.extend_from_slice(&sized);
}

/// A RAR 5 archive of stored members, in the order given, built from
/// spec F 3.2.2 and 3.2.6 (a redirection's record from 3.2.6.2).
fn archive(members: &[(&str, Kind)]) -> Vec<u8> {
    let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
    block(&[1, 0, 0], &mut out);
    for (name, kind) in members {
        let (data, file_flags, attr, extra): (&[u8], u64, u64, Vec<u8>) = match kind {
            Kind::File(data) => (data, 0x4, 0o100_644, Vec::new()),
            Kind::Dir => (b"", 0x5, 0o040_755, Vec::new()),
            Kind::Redirect(kind, target) => (
                b"",
                0x4,
                if *kind == 1 { 0o120_777 } else { 0o100_644 },
                rewrite::area(&[(5, rewrite::redirect(*kind, 0, target))]),
            ),
        };
        let mut flags = 0;
        if !extra.is_empty() {
            flags |= 0x1;
        }
        if !data.is_empty() {
            flags |= 0x2;
        }
        let mut body = rewrite::vint(2);
        body.extend(rewrite::vint(flags));
        if !extra.is_empty() {
            body.extend(rewrite::vint(extra.len() as u64));
        }
        if !data.is_empty() {
            body.extend(rewrite::vint(data.len() as u64));
        }
        body.extend(rewrite::vint(file_flags));
        body.extend(rewrite::vint(data.len() as u64));
        body.extend(rewrite::vint(attr));
        body.extend_from_slice(&rewrite::crc32(data).to_le_bytes());
        body.extend(rewrite::vint(0)); // stored
        body.extend(rewrite::vint(1)); // Unix
        body.extend(rewrite::vint(name.len() as u64));
        body.extend_from_slice(name.as_bytes());
        body.extend(extra);
        block(&body, &mut out);
        out.extend_from_slice(data);
    }
    block(&[5, 0, 0], &mut out);
    out
}

/// A RAR 5 volume set `a.part1.rar` on: one stored file split across as
/// many volumes as `names`, each volume's header carrying its own name
/// (spec F 3.2.2 to 3.2.6: the volume and volume number flags, split
/// before and after, and the end of archive's more volumes flag).
fn volumes(names: &[&str]) -> Vec<(String, Vec<u8>)> {
    let whole = &b"EVILEVIL"[..];
    let step = whole.len() / names.len();
    let mut set = Vec::new();
    for (i, name) in names.iter().enumerate() {
        let last = i + 1 == names.len();
        let piece = if last {
            &whole[i * step..]
        } else {
            &whole[i * step..(i + 1) * step]
        };
        let mut out = b"Rar!\x1a\x07\x01\x00".to_vec();
        let mut main = rewrite::vint(1);
        main.extend(rewrite::vint(0));
        main.extend(rewrite::vint(if i == 0 { 0x1 } else { 0x3 }));
        if i > 0 {
            main.extend(rewrite::vint(i as u64));
        }
        block(&main, &mut out);
        let mut flags = 0x2;
        if i > 0 {
            flags |= 0x8;
        }
        if !last {
            flags |= 0x10;
        }
        let mut body = rewrite::vint(2);
        body.extend(rewrite::vint(flags));
        body.extend(rewrite::vint(piece.len() as u64));
        body.extend(rewrite::vint(0x4));
        body.extend(rewrite::vint(whole.len() as u64));
        body.extend(rewrite::vint(0o100_644));
        let crc = rewrite::crc32(if last { whole } else { piece });
        body.extend_from_slice(&crc.to_le_bytes());
        body.extend(rewrite::vint(0)); // stored
        body.extend(rewrite::vint(1)); // Unix
        body.extend(rewrite::vint(name.len() as u64));
        body.extend_from_slice(name.as_bytes());
        block(&body, &mut out);
        out.extend_from_slice(piece);
        block(&[5, 0, if last { 0 } else { 1 }], &mut out);
        set.push((format!("a.part{}.rar", i + 1), out));
    }
    set
}

fn text(done: &Output) -> String {
    format!(
        "exit {:?}\n{}{}",
        done.status.code(),
        String::from_utf8_lossy(&done.stdout),
        String::from_utf8_lossy(&done.stderr)
    )
}

const WIDTHS: [&str; 2] = ["-mt1", "-mt4"];

/// Runs `args` (with the width and `a.rar out/` appended) over `arc` in a
/// fresh tree, after `plant` has had its say, and asserts the rule.
fn row(tag: &str, arc: &[u8], args: &[&str], plant: impl Fn(&Path)) {
    row_then(tag, arc, args, plant, |_, _| {});
}

/// [`row`], and then `after` asks what the row owes inside the
/// destination.
fn row_then(
    tag: &str,
    arc: &[u8],
    args: &[&str],
    plant: impl Fn(&Path),
    after: impl Fn(&Path, &Output),
) {
    row_built(
        tag,
        |_| vec![("a.rar".to_string(), arc.to_vec())],
        args,
        plant,
        after,
    );
}

/// [`row_then`] over the archive files `build` makes for the row's own
/// tree, so a member may name that tree by its absolute path; the first
/// file is the one named to rarfast.
fn row_built(
    tag: &str,
    build: impl Fn(&Path) -> Vec<(String, Vec<u8>)>,
    args: &[&str],
    plant: impl Fn(&Path),
    after: impl Fn(&Path, &Output),
) {
    for width in WIDTHS {
        let (dir, _watch) = DirWatch::over(tag, width);
        plant(&dir);
        let files = build(&dir);
        for (name, bytes) in &files {
            std::fs::write(dir.join(name), bytes).unwrap();
        }
        let mut all: Vec<&str> = args.to_vec();
        all.extend([width, files[0].0.as_str(), "out/"]);
        let done = Command::new(rarfast())
            .current_dir(&dir)
            .args(&all)
            .output()
            .unwrap();
        let victim = std::fs::symlink_metadata(dir.join("outside/victim"));
        assert!(
            victim.as_ref().is_ok_and(|m| m.file_type().is_file()),
            "{tag} {width}: outside/victim is no longer a plain file\n{}",
            text(&done)
        );
        assert_eq!(
            std::fs::read(dir.join("outside/victim")).unwrap(),
            b"KEEP ME",
            "{tag} {width}: the file outside the destination was written\n{}",
            text(&done)
        );
        let beside: Vec<_> = std::fs::read_dir(dir.join("outside"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            beside.len(),
            1,
            "{tag} {width}: something new outside the destination: {beside:?}\n{}",
            text(&done)
        );
        after(&dir, &done);
    }
}

/// A link to the outside file, then a FILE of the same name over it
/// (`-o+`): the file replaces the link and never writes through it, on
/// the held small-member path and on the plain one.
#[test]
fn a_file_over_an_earlier_link_writes_the_link_not_its_target() {
    for body in [&b"EVIL"[..], &[b'E'; 300_000][..]] {
        let arc = archive(&[
            ("v", Kind::Redirect(1, b"../outside/victim")),
            ("v", Kind::File(body)),
        ]);
        row("fileoverlink", &arc, &["x", "-o+", "-ola"], |_| {});
    }
}

/// A hard link whose target names an earlier member that is a link to
/// the outside file, and then a file of the hard link's name over it:
/// the hard link must not reach the outside file's bytes.
#[test]
fn a_hard_link_to_an_earlier_link_never_reaches_its_target() {
    let arc = archive(&[
        ("t", Kind::Redirect(1, b"../outside/victim")),
        ("h", Kind::Redirect(4, b"t")),
        ("h", Kind::File(b"EVIL")),
    ]);
    row("hardoverlink", &arc, &["x", "-o+", "-ola"], |_| {});
}

/// A copy whose own path is a link planted to the outside file.
#[test]
fn a_copy_onto_a_planted_link_replaces_the_link() {
    let arc = archive(&[("t", Kind::File(b"EVIL")), ("c", Kind::Redirect(5, b"t"))]);
    row("copyonlink", &arc, &["x", "-o+"], |dir| {
        symlink("../outside/victim", dir.join("out/c")).unwrap();
    });
}

/// `e` flattens every path, so a link written at the destination's top
/// may climb nowhere, however deep its stored name was.
#[test]
fn a_flattened_link_is_judged_at_the_depth_it_lands() {
    let arc = archive(&[
        ("a/b/l", Kind::Redirect(1, b"../../outside/victim")),
        ("l", Kind::File(b"EVIL")),
    ]);
    row("flatlink", &arc, &["e", "-o+"], |_| {});
}

/// A link made inside the destination by a SAFE target (no `-ola`), whose
/// parent is the name of a directory a later member wants: the chain of
/// two safe links must not add up to a way out.
#[test]
fn two_safe_links_never_add_up_to_a_way_out() {
    let arc = archive(&[
        ("d/up", Kind::Redirect(1, b"..")),
        ("d/e/up2", Kind::Redirect(1, b"../up")),
        ("d/e/up2/up/../outside/victim", Kind::File(b"EVIL")),
        ("s", Kind::Redirect(1, b"d/up")),
        ("s/s/x", Kind::File(b"EVIL")),
        ("k/l", Kind::Redirect(1, b"../s")),
        ("k/l/victim", Kind::File(b"EVIL")),
    ]);
    row("safechain", &arc, &["x", "-o+"], |_| {});
}

/// A file already in the destination that is a HARD link to the outside
/// file (another name of the same bytes), then a member of that name
/// under `-o+`: the member replaces the name in the destination, and the
/// outside file keeps its bytes, for a small member held in memory and a
/// large one written beside.
#[test]
fn a_member_over_a_hard_linked_file_leaves_the_other_name_alone() {
    for body in [&b"EVIL"[..], &[b'E'; 300_000][..]] {
        let arc = archive(&[("f", Kind::File(body))]);
        row_then(
            "overhardlink",
            &arc,
            &["x", "-o+"],
            |dir| {
                std::fs::hard_link(dir.join("outside/victim"), dir.join("out/f")).unwrap();
            },
            |dir, done| {
                assert_eq!(done.status.code(), Some(0), "{}", text(done));
                assert_eq!(std::fs::read(dir.join("out/f")).unwrap(), body);
            },
        );
    }
}

/// A file COPY member (spec F 3.8.5) whose own path holds a file that is
/// a HARD link to the outside file, under `-o+`: the copy replaces the
/// name in the destination and the outside file keeps its bytes.
#[test]
fn a_copy_over_a_hard_linked_file_leaves_the_other_name_alone() {
    let arc = archive(&[("t", Kind::File(b"EVIL")), ("c", Kind::Redirect(5, b"t"))]);
    row_then(
        "copyoverhardlink",
        &arc,
        &["x", "-o+"],
        |dir| {
            std::fs::hard_link(dir.join("outside/victim"), dir.join("out/c")).unwrap();
        },
        |dir, done| {
            assert_eq!(done.status.code(), Some(0), "{}", text(done));
            assert_eq!(std::fs::read(dir.join("out/c")).unwrap(), b"EVIL");
        },
    );
}

/// `e` of a member whose flattened name is EMPTY (a trailing slash, `.`,
/// `..`, `/` or no name at all), as a file, a link out or a directory:
/// it would be written AS the destination, so it is refused with a
/// nonzero exit and the destination stays a folder (or is never made),
/// under each overwrite mode.
#[test]
fn e_of_an_empty_flattened_name_never_writes_the_destination_itself() {
    let names = ["d/", "d/.", "d/..", ".", "..", "/", "a/b/", "./", ""];
    let modes: [&[&str]; 3] = [&["e", "-o+", "-ola"], &["e", "-o-"], &["e", "-y"]];
    for name in names {
        for kind in 0..4 {
            let member = match kind {
                0 => Kind::File(b"EVIL"),
                1 => Kind::Redirect(1, b"../outside/victim"),
                2 => Kind::Redirect(1, b"../outside"),
                _ => Kind::Dir,
            };
            let arc = archive(&[(name, member)]);
            for args in modes {
                for made in [true, false] {
                    row_then(
                        "emptyflat",
                        &arc,
                        args,
                        |dir| {
                            if !made {
                                std::fs::remove_dir(dir.join("out")).unwrap();
                            }
                        },
                        |dir, done| {
                            let what = format!("[{name}] kind {kind} {args:?} made {made}");
                            assert_ne!(done.status.code(), Some(0), "{what}\n{}", text(done));
                            match std::fs::symlink_metadata(dir.join("out")) {
                                Ok(m) => {
                                    assert!(m.is_dir(), "{what}: out is no longer a folder");
                                    let inside =
                                        std::fs::read_dir(dir.join("out")).unwrap().count();
                                    assert_eq!(inside, 0, "{what}: something landed in out");
                                }
                                Err(_) => assert!(!made, "{what}: out was removed"),
                            }
                        },
                    );
                }
            }
        }
    }
}

/// The path switches `-ap`, `-op`, `-ep1` to `-ep4` and `-or`, each over
/// a `../` name, an absolute name naming the outside file, and a link
/// (relative or absolute, to the outside folder or file) followed by a
/// member through it or over it, every form also under a prefix `x/`
/// that `-apx` and `-ep4x` would take off. Only the rule is asserted:
/// `-ap`, `-ep1` and `-ep4` are refused today (exit 7), so their rows
/// show nothing written, not that the refusal is right. `-op` names the
/// same folder as the trailing `out/`.
#[test]
fn the_path_switches_never_take_a_member_outside() {
    let switches: [&[&str]; 8] = [
        &["-o+"],
        &["-o+", "-apx"],
        &["-o+", "-ep1"],
        &["-o+", "-ep2"],
        &["-o+", "-ep3"],
        &["-o+", "-ep4x"],
        &["-or"],
        &["-o+", "-opout"],
    ];
    // Each member is a name and, for a link, its target; the rest are
    // files of four bytes.
    type Form = fn(&str) -> Vec<(String, Option<String>)>;
    fn file(name: &str) -> (String, Option<String>) {
        (name.to_string(), None)
    }
    fn link(name: &str, target: &str) -> (String, Option<String>) {
        (name.to_string(), Some(target.to_string()))
    }
    let forms: [Form; 5] = [
        |_| vec![file("../outside/victim"), file("x/../../outside/victim")],
        |abs| {
            vec![
                file(&format!("{abs}/outside/victim")),
                file(&format!("x/{abs}/outside/victim")),
            ]
        },
        |_| {
            vec![
                link("l", "../outside"),
                file("l/victim"),
                link("x/l", "../../outside"),
                file("x/l/victim"),
            ]
        },
        |_| {
            vec![
                link("l", "../outside/victim"),
                file("l"),
                link("x/l", "../../outside/victim"),
                file("x/l"),
            ]
        },
        |abs| {
            let target = format!("{abs}/outside");
            vec![
                link("l", &target),
                file("l/victim"),
                link("x/l", &target),
                file("x/l/victim"),
            ]
        },
    ];
    for switch in switches {
        for (form, members) in forms.iter().enumerate() {
            for cmd in ["x", "e"] {
                let mut args = vec![cmd, "-ola"];
                args.extend_from_slice(switch);
                row_built(
                    "pathswitch",
                    |dir| {
                        let made = members(&dir.to_string_lossy());
                        let named: Vec<(&str, Kind)> = made
                            .iter()
                            .map(|(name, target)| match target {
                                Some(t) => (name.as_str(), Kind::Redirect(1, t.as_bytes())),
                                None => (name.as_str(), Kind::File(b"EVIL")),
                            })
                            .collect();
                        vec![("a.rar".to_string(), archive(&named))]
                    },
                    &args,
                    |_| {},
                    |dir, done| {
                        let mut top: Vec<_> = std::fs::read_dir(dir)
                            .unwrap()
                            .map(|e| e.unwrap().file_name())
                            .collect();
                        top.sort();
                        assert_eq!(
                            top,
                            ["a.rar", "out", "outside"],
                            "form {form} {args:?}: something new beside the destination\n{}",
                            text(done)
                        );
                    },
                );
            }
        }
    }
}

/// A file split across volumes whose later headers carry another name (a
/// `../` name, an absolute name of the outside file, a prefixed climb or
/// just another name), or whose first header carries the climb: nothing
/// is written outside, whatever name the extraction goes by. Only the
/// rule is asserted, not how the mismatch is met. A set whose names agree
/// is extracted whole, which shows the sets are well formed.
#[test]
fn a_split_file_renamed_in_a_later_volume_never_lands_outside() {
    let sets: [&[&str]; 8] = [
        &["good", "good"],
        &["good", "../outside/victim"],
        &["../outside/victim", "good"],
        &["good", "@/outside/victim"],
        &["good", "x/../../outside/victim"],
        &["good", "other"],
        &["good", "good", "../outside/victim"],
        &["good", "../outside/victim", "good"],
    ];
    for (n, set) in sets.iter().enumerate() {
        for cmd in ["x", "e"] {
            row_built(
                "splitname",
                |dir| {
                    let abs = dir.to_string_lossy();
                    let named: Vec<String> = set.iter().map(|s| s.replace('@', &abs)).collect();
                    let named: Vec<&str> = named.iter().map(String::as_str).collect();
                    volumes(&named)
                },
                &[cmd, "-o+"],
                |_| {},
                |dir, done| {
                    if n == 0 {
                        assert_eq!(done.status.code(), Some(0), "{}", text(done));
                        assert_eq!(std::fs::read(dir.join("out/good")).unwrap(), b"EVILEVIL");
                    }
                },
            );
        }
    }
}

/// A hard link or copy member whose target `t` is already in the
/// destination as a link to the outside file, a hard link to it or a plain
/// file, which `-o-` keeps (and `-o+` and `-y` replace), alone and then
/// followed by a file or link of its own name: the outside file keeps its
/// bytes and no new name in the destination shares its inode. Only the
/// rule is asserted, not how a kept target is met.
#[test]
fn a_link_or_copy_onto_a_kept_target_never_reaches_the_outside_file() {
    use std::os::unix::fs::MetadataExt;
    let sets: [&[(&str, Kind)]; 6] = [
        &[("t", Kind::File(b"EVIL")), ("h", Kind::Redirect(4, b"t"))],
        &[("t", Kind::File(b"EVIL")), ("c", Kind::Redirect(5, b"t"))],
        &[
            ("t", Kind::File(b"EVIL")),
            ("h", Kind::Redirect(4, b"t")),
            ("h", Kind::File(b"EVIL")),
        ],
        &[
            ("t", Kind::File(b"EVIL")),
            ("c", Kind::Redirect(5, b"t")),
            ("c", Kind::File(b"EVIL")),
        ],
        &[
            ("t", Kind::File(b"EVIL")),
            ("h", Kind::Redirect(4, b"t")),
            ("h", Kind::Redirect(1, b"x")),
        ],
        &[
            ("t", Kind::File(b"EVIL")),
            ("c", Kind::Redirect(5, b"t")),
            ("c", Kind::Redirect(1, b"x")),
        ],
    ];
    for (n, set) in sets.iter().enumerate() {
        let arc = archive(set);
        for plant in ["symlink", "hardlink", "plain"] {
            for mode in ["-o-", "-o+", "-y"] {
                for cmd in ["x", "e"] {
                    row_then(
                        "keptlink",
                        &arc,
                        &[cmd, mode],
                        |dir| {
                            let t = dir.join("out/t");
                            match plant {
                                "symlink" => symlink("../outside/victim", t).unwrap(),
                                "hardlink" => {
                                    std::fs::hard_link(dir.join("outside/victim"), t).unwrap()
                                }
                                _ => std::fs::write(t, b"OLD").unwrap(),
                            }
                        },
                        |dir, done| {
                            let victim =
                                std::fs::metadata(dir.join("outside/victim")).unwrap().ino();
                            for entry in std::fs::read_dir(dir.join("out")).unwrap() {
                                let entry = entry.unwrap();
                                // The planted hard link, kept by `-o-`, is
                                // the caller's own second name for it.
                                if plant == "hardlink" && mode == "-o-" && entry.file_name() == "t"
                                {
                                    continue;
                                }
                                let ino = std::fs::symlink_metadata(entry.path()).unwrap().ino();
                                assert_ne!(
                                    ino,
                                    victim,
                                    "set {n} {plant} {mode} {cmd}: out/{:?} is the outside file\n{}",
                                    entry.file_name(),
                                    text(done)
                                );
                            }
                        },
                    );
                }
            }
        }
    }
}

/// A link member and a later file or folder whose name differs from the
/// link's only in case or in Unicode normalization (NFC and NFD), in
/// either order, at the top and one level down: on a file system that
/// folds case and normalization (APFS as macOS makes it) the two name one
/// entry, and nothing is written through the link; elsewhere they are two
/// entries. Only the rule is asserted.
#[test]
fn a_link_and_a_name_spelled_differently_never_write_through_the_link() {
    let nfc = "\u{e9}";
    let nfd = "e\u{301}";
    let sets: Vec<Vec<(String, Option<&str>)>> = vec![
        vec![("L".into(), Some("../outside")), ("l/victim".into(), None)],
        vec![("L".into(), Some("../outside/victim")), ("l".into(), None)],
        vec![
            ("a/L".into(), Some("../../outside")),
            ("a/l/victim".into(), None),
        ],
        vec![("l".into(), Some("../outside")), ("L/victim".into(), None)],
        vec![
            (nfc.into(), Some("../outside")),
            (format!("{nfd}/victim"), None),
        ],
        vec![
            (nfd.into(), Some("../outside")),
            (format!("{nfc}/victim"), None),
        ],
        vec![(nfc.into(), Some("../outside/victim")), (nfd.into(), None)],
        vec![
            (format!("{nfc}X"), Some("../outside")),
            (format!("{nfd}x/victim"), None),
        ],
    ];
    let mut arcs: Vec<Vec<u8>> = sets
        .iter()
        .map(|set| {
            let members: Vec<(&str, Kind)> = set
                .iter()
                .map(|(name, target)| match target {
                    Some(t) => (name.as_str(), Kind::Redirect(1, t.as_bytes())),
                    None => (name.as_str(), Kind::File(b"EVIL")),
                })
                .collect();
            archive(&members)
        })
        .collect();
    // The case pair again with a folder member between them.
    arcs.push(archive(&[
        ("D", Kind::Redirect(1, b"../outside")),
        ("d", Kind::Dir),
        ("d/victim", Kind::File(b"EVIL")),
    ]));
    for arc in &arcs {
        for mode in ["-o+", "-o-", "-y"] {
            for cmd in ["x", "e"] {
                row("foldlink", arc, &[cmd, mode, "-ola"], |_| {});
            }
        }
    }
}

/// A link member and a folder member of ONE name, in either order, alone
/// and with a file below the name after both, at the top and one level
/// down, the link relative or absolute: nothing lands outside and the
/// outside folder keeps its mode (0o750 here, so the folder member's
/// 0o755 would show through the link). Only the rule is asserted.
#[test]
fn a_link_and_a_folder_of_one_name_never_reach_outside() {
    use std::os::unix::fs::PermissionsExt;
    // A member is a name and what it is: "@" a link to the outside folder
    // (ABS for its absolute path), "/" a folder, else a file.
    let sets: [&[(&str, &str)]; 9] = [
        &[("l", "@"), ("l", "/"), ("l/new", "")],
        &[("l", "/"), ("l", "@"), ("l/new", "")],
        &[("l", "@"), ("l", "/")],
        &[("l", "/"), ("l", "@")],
        &[("l", "/"), ("l/a", ""), ("l", "@"), ("l/new", "")],
        &[("a/l", "@"), ("a/l", "/"), ("a/l/new", "")],
        &[("a/l", "/"), ("a/l", "@"), ("a/l/new", "")],
        &[("l", "ABS"), ("l", "/"), ("l/new", "")],
        &[("l", "/"), ("l", "ABS"), ("l/new", "")],
    ];
    for (n, set) in sets.iter().enumerate() {
        for mode in ["-o+", "-o-", "-y"] {
            for cmd in ["x", "e"] {
                row_built(
                    "linkfolder",
                    |dir| {
                        let abs = format!("{}/outside", dir.to_string_lossy());
                        let targets: Vec<String> = set
                            .iter()
                            .map(|(name, what)| match *what {
                                "@" => "../".repeat(name.matches('/').count() + 1) + "outside",
                                "ABS" => abs.clone(),
                                _ => String::new(),
                            })
                            .collect();
                        let members: Vec<(&str, Kind)> = set
                            .iter()
                            .zip(&targets)
                            .map(|((name, what), target)| match *what {
                                "/" => (*name, Kind::Dir),
                                "" => (*name, Kind::File(b"EVIL")),
                                _ => (*name, Kind::Redirect(1, target.as_bytes())),
                            })
                            .collect();
                        vec![("a.rar".to_string(), archive(&members))]
                    },
                    &[cmd, mode, "-ola"],
                    |dir| {
                        let perms = std::fs::Permissions::from_mode(0o750);
                        std::fs::set_permissions(dir.join("outside"), perms).unwrap();
                    },
                    |dir, done| {
                        let now = std::fs::metadata(dir.join("outside")).unwrap();
                        assert_eq!(
                            now.permissions().mode() & 0o7777,
                            0o750,
                            "set {n} {mode} {cmd}: the outside folder's mode changed\n{}",
                            text(done)
                        );
                    },
                );
            }
        }
    }
}

/// A RACE at width: members of 2 MB each, so several are in flight,
/// whose folder `d` the helpers may make early, and a later link member
/// `d` to the outside folder followed by more files under `d`, with the
/// big files before the link, under it, interleaved with it, one level
/// down, and after a folder member `d`. Each set runs five times at each
/// width; only the rule is asserted.
#[test]
fn early_folders_never_race_a_later_link_of_their_name() {
    let big = vec![b'E'; 2_000_000];
    let big = &big[..];
    let link = |target: &'static [u8]| Kind::Redirect(1, target);
    let sets: Vec<Vec<(&str, Kind)>> = vec![
        vec![
            ("f0", Kind::File(big)),
            ("f1", Kind::File(big)),
            ("f2", Kind::File(big)),
            ("f3", Kind::File(big)),
            ("d", link(b"../outside")),
            ("d/victim", Kind::File(big)),
            ("d/new", Kind::File(b"EVIL")),
        ],
        vec![
            ("d/a", Kind::File(big)),
            ("d/b", Kind::File(big)),
            ("d/c", Kind::File(big)),
            ("d", link(b"../outside")),
            ("d/victim", Kind::File(b"EVIL")),
            ("d/new", Kind::File(big)),
        ],
        vec![
            ("d/a", Kind::File(big)),
            ("f0", Kind::File(big)),
            ("d", link(b"../outside")),
            ("d/b", Kind::File(big)),
            ("d/victim", Kind::File(b"EVIL")),
            ("f1", Kind::File(big)),
            ("d/new", Kind::File(b"EVIL")),
        ],
        vec![
            ("a/b/x", Kind::File(big)),
            ("a/b/y", Kind::File(big)),
            ("a/b", link(b"../../outside")),
            ("a/b/victim", Kind::File(big)),
            ("a/b/new", Kind::File(b"EVIL")),
        ],
        vec![
            ("d", Kind::Dir),
            ("d/a", Kind::File(big)),
            ("d/b", Kind::File(big)),
            ("d", link(b"../outside")),
            ("d/victim", Kind::File(big)),
            ("d/new", Kind::File(big)),
        ],
    ];
    for set in &sets {
        let arc = archive(set);
        for mode in ["-o+", "-o-", "-y"] {
            for _ in 0..5 {
                row("earlyfolder", &arc, &["x", mode, "-ola"], |_| {});
            }
        }
    }
}

/// A member of a single name whose path is already a link to the outside
/// file (a symlink or a hard link), in a folder CLOSED TO WRITING (the
/// destination itself, or a folder in it), small and large: with no way
/// to replace the name, nothing is written through it. Only the rule is
/// asserted.
#[test]
fn a_link_in_a_folder_closed_to_writing_is_never_written_through() {
    use std::os::unix::fs::PermissionsExt;
    let large = vec![b'E'; 300_000];
    for (name, folder, up) in [
        ("f", "out", "../outside/victim"),
        ("sub/f", "out/sub", "../../outside/victim"),
    ] {
        for hard in [false, true] {
            for body in [&b"EVIL"[..], &large[..]] {
                let arc = archive(&[(name, Kind::File(body))]);
                for mode in ["-o+", "-y", "-o-"] {
                    for cmd in ["x", "e"] {
                        row_then(
                            "closedfolder",
                            &arc,
                            &[cmd, mode],
                            |dir| {
                                let at = dir.join(folder);
                                std::fs::create_dir_all(&at).unwrap();
                                if hard {
                                    std::fs::hard_link(dir.join("outside/victim"), at.join("f"))
                                        .unwrap();
                                } else {
                                    symlink(up, at.join("f")).unwrap();
                                }
                                std::fs::set_permissions(
                                    &at,
                                    std::fs::Permissions::from_mode(0o555),
                                )
                                .unwrap();
                            },
                            |_, _| {},
                        );
                    }
                }
            }
        }
    }
}

/// A folder the archive itself made (for an earlier file below it), then
/// a link member of the folder's name to the outside (relative, absolute,
/// to the folder or to the file, or a hard link), then members written
/// through that name: at the top, one level down and two, small and
/// 2 MB. Only the rule is asserted.
#[test]
fn a_made_folder_later_named_by_a_link_is_never_written_through() {
    let big = vec![b'E'; 2_000_000];
    let big = &big[..];
    // A member is a name and what it is: "@" a link to the outside folder,
    // "ABS" the same by absolute path, "@f" a link to the outside file,
    // "H" a hard link to it, "B" a 2 MB file, else a small file.
    let sets: [&[(&str, &str)]; 8] = [
        &[("d/a", ""), ("d", "@"), ("d/victim", ""), ("d/new", "")],
        &[("d/a", "B"), ("d", "@"), ("d/victim", "B"), ("d/new", "")],
        &[
            ("a/d/x", ""),
            ("a/d", "@"),
            ("a/d/victim", ""),
            ("a/d/new", ""),
        ],
        &[
            ("d/a", ""),
            ("d/b/c", ""),
            ("d", "@"),
            ("d/b/c", ""),
            ("d/b/new", ""),
        ],
        &[("d/e/x", ""), ("d", "@"), ("d/e/victim", "")],
        &[("d/a", ""), ("d", "ABS"), ("d/victim", ""), ("d/new", "")],
        &[("d/a", ""), ("d", "@f"), ("d", "")],
        &[("d/a", ""), ("d", "H"), ("d", "")],
    ];
    for set in sets {
        for mode in ["-o+", "-o-", "-y"] {
            for cmd in ["x", "e"] {
                row_built(
                    "madefolder",
                    |dir| {
                        let abs = format!("{}/outside", dir.to_string_lossy());
                        let targets: Vec<String> = set
                            .iter()
                            .map(|(name, what)| {
                                let up = "../".repeat(name.matches('/').count() + 1);
                                match *what {
                                    "@" => up + "outside",
                                    "@f" | "H" => up + "outside/victim",
                                    "ABS" => abs.clone(),
                                    _ => String::new(),
                                }
                            })
                            .collect();
                        let members: Vec<(&str, Kind)> = set
                            .iter()
                            .zip(&targets)
                            .map(|((name, what), target)| match *what {
                                "" => (*name, Kind::File(b"EVIL")),
                                "B" => (*name, Kind::File(big)),
                                "H" => (*name, Kind::Redirect(4, target.as_bytes())),
                                _ => (*name, Kind::Redirect(1, target.as_bytes())),
                            })
                            .collect();
                        vec![("a.rar".to_string(), archive(&members))]
                    },
                    &[cmd, mode, "-ola"],
                    |_| {},
                    |_, _| {},
                );
            }
        }
    }
}

/// A directory member whose path is a planted link to the outside
/// directory, under `-o-`: neither its mode nor anything below it lands
/// outside.
#[test]
fn a_directory_member_kept_by_o_minus_sets_nothing_through_a_link() {
    let arc = archive(&[("d", Kind::Dir), ("d/victim", Kind::File(b"EVIL"))]);
    row("dirkeep", &arc, &["x", "-o-"], |dir| {
        symlink("../outside", dir.join("out/d")).unwrap();
    });
}

/// A planted link one level down, in a folder closed to writing, to the
/// outside FOLDER, then files below the link and the two folders as
/// members (stored after their contents): no file lands through the
/// link, whether the link can be replaced or not. Only the rule is
/// asserted.
#[test]
fn a_link_below_a_folder_closed_to_writing_is_never_walked_through() {
    use std::os::unix::fs::PermissionsExt;
    let arc = archive(&[
        ("src/link/victim", Kind::File(b"EVIL")),
        ("src/link/other.txt", Kind::File(b"EVIL")),
        ("src/link", Kind::Dir),
        ("src", Kind::Dir),
    ]);
    for mode in ["-o+", "-y", "-o-"] {
        for cmd in ["x", "e"] {
            row("closedparent", &arc, &[cmd, mode], |dir| {
                let src = dir.join("out/src");
                std::fs::create_dir_all(&src).unwrap();
                symlink("../../outside", src.join("link")).unwrap();
                std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o555)).unwrap();
            });
        }
    }
}

/// The same planted link, below a folder closed to writing, with 200
/// small members under it: enough (64 or more) that `-mt4` and `-mt8`
/// under `-o+` and `-y` make files ahead of the walk. Nothing may be made
/// outside even for a moment, so beside the rule the outside folder's
/// mtime is asserted unchanged: a file made there and removed again by
/// the end of the run moves it.
#[test]
fn files_made_ahead_never_land_below_a_link_the_walk_refused() {
    use std::os::unix::fs::PermissionsExt;
    let names: Vec<String> = (0..200).map(|i| format!("src/link/f{i}")).collect();
    let members: Vec<(&str, Kind)> = names
        .iter()
        .map(|name| (name.as_str(), Kind::File(b"EVIL")))
        .collect();
    let arc = archive(&members);
    let then = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
    for width in ["-mt4", "-mt8"] {
        for mode in ["-o+", "-y"] {
            for rep in 0..3 {
                let (dir, _watch) = DirWatch::over("madeahead", width);
                let src = dir.join("out/src");
                std::fs::create_dir_all(&src).unwrap();
                symlink("../../outside", src.join("link")).unwrap();
                std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o555)).unwrap();
                std::fs::write(dir.join("a.rar"), &arc).unwrap();
                std::fs::File::open(dir.join("outside"))
                    .unwrap()
                    .set_modified(then)
                    .unwrap();
                let done = Command::new(rarfast())
                    .current_dir(&dir)
                    .args(["x", mode, width, "a.rar", "out/"])
                    .output()
                    .unwrap();
                let tag = format!("madeahead {width} {mode} rep {rep}");
                assert_eq!(
                    std::fs::read(dir.join("outside/victim")).unwrap(),
                    b"KEEP ME",
                    "{tag}: the file outside the destination was written\n{}",
                    text(&done)
                );
                let beside: Vec<_> = std::fs::read_dir(dir.join("outside"))
                    .unwrap()
                    .map(|e| e.unwrap().file_name())
                    .collect();
                assert_eq!(
                    beside.len(),
                    1,
                    "{tag}: something new outside the destination: {beside:?}\n{}",
                    text(&done)
                );
                assert_eq!(
                    std::fs::metadata(dir.join("outside"))
                        .unwrap()
                        .modified()
                        .unwrap(),
                    then,
                    "{tag}: something was made outside the destination and removed\n{}",
                    text(&done)
                );
            }
        }
    }
}
