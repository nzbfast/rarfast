//! Hostile Windows path forms and link members, extracted for real on
//! Windows: security brief 3 (alternate data streams, device names, drive,
//! UNC, device namespace and backslash forms, trailing dots and spaces)
//! and brief 2's Windows forms (symbolic links, junctions, hard links and
//! copies whose target leaves, and a file written through a link).
//!
//! THE RULE every row pins: nothing is created, written or read outside
//! the destination. Each row aims every escape at one canary directory
//! (`support/hostile_windows_rows.rs`), and after each run this checks
//! that the canary is unchanged and carries no stream, that nothing new is
//! in its directory, that nothing appears beside `out`, and that every
//! link left in `out` is one the row allows. Beyond that it pins what
//! rarfast does today, counted on a Windows 11 desktop on 27 Oct 2026:
//! the exit code of each run, and under `x` the files written.
//!
//! Every row runs as a RAR 5 archive and, where RAR 4 can carry it, as a
//! RAR 4 archive too: brief 3's names (ASCII only, since a RAR 4 name has
//! no Unicode field here) and brief 2 as Unix symbolic links, the one link
//! RAR 4 stores. Then the same forms with names that are NOT ASCII, in the
//! two-part name of spec F 3.3.7 (the `r4u-` rows): a hostile name in
//! either part, characters that only look like a separator, a dot or a
//! colon, and the encoding's edges.
//!
//! With `RARKIT_REFERENCE_UNRAR` naming a reference `UnRAR.exe`, the RAR 4
//! rows run through it too, as a whole process, and what it did is printed
//! (with `--nocapture`); that arm never fails the test.
//!
//! Where UnRAR 7.23 differs in that count, rarfast is the stricter: it
//! refuses an absolute, UNC, device namespace or climbing name
//! (`src/safepath.rs` rule 1) where the reference writes it under a mapped
//! name, maps a device name with an extension (rule 5) where Windows 11
//! no longer reads one as a device, and declines every junction (spec F
//! 3.8.6). Neither wrote outside the destination in any row.
//!
//! Windows only, and the symbolic link rows need the privilege (or
//! developer mode): without it those links are not made and the escape
//! checks still hold. One extraction at a time, each a child process on
//! the default thread pool; the archives are a few hundred bytes.
#![cfg(windows)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "../../rarkit/tests/redirection/rewrite.rs"]
mod rewrite;

#[path = "support/hostile_windows_rows.rs"]
mod rows;

/// `rarfast` as cargo built it, or, for a test binary copied to another
/// machine, the `rarfast.exe` one directory above it, as cargo lays the
/// two out.
fn rarfast() -> PathBuf {
    let built = PathBuf::from(env!("CARGO_BIN_EXE_rarfast"));
    if built.exists() {
        return built;
    }
    let exe = std::env::current_exe().unwrap();
    exe.parent().unwrap().parent().unwrap().join("rarfast.exe")
}

/// A root of this test's own, removed when dropped, so a failed assert
/// clears it away as a pass does.
struct Root(PathBuf);

impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// What a link in `out` is: whether it is one, and its target.
fn link_target(path: &Path) -> Option<PathBuf> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() {
        return std::fs::read_link(path).ok();
    }
    use std::os::windows::fs::MetadataExt;
    // FILE_ATTRIBUTE_REPARSE_POINT: a junction, which is not a symlink to
    // the standard library.
    (meta.file_attributes() & 0x400 != 0).then(|| std::fs::read_link(path).unwrap_or_default())
}

/// Every file under `root` by its path relative to `root` with `/`, and
/// every link with its target; no link is followed.
fn walk(
    root: &Path,
    dir: &Path,
    files: &mut BTreeMap<String, Vec<u8>>,
    links: &mut BTreeMap<String, PathBuf>,
) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let key = path
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if let Some(target) = link_target(&path) {
            links.insert(key, target);
        } else if path.is_dir() {
            walk(root, &path, files, links);
        } else {
            files.insert(key, std::fs::read(&path).unwrap());
        }
    }
}

/// A name as a RAR 5 Windows host's member is written on Windows: every
/// `\` and every character Win32 refuses becomes `_`.
fn flat(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '\\' | ':' | '?' | '*' | '<' | '>' | '"' | '|' => '_',
            c => c,
        })
        .collect()
}

/// What `x` writes for each row, as files under `out`, and the links it
/// leaves there.
fn expected_x(
    tag: &str,
    escaped: &str,
    drive: char,
) -> (Vec<String>, Vec<(&'static str, &'static str)>) {
    let unc = format!("\\\\localhost\\{drive}${}", &escaped[2..]);
    let names: Vec<String> = match tag {
        "b2-hard-and-copy" => vec!["c-good", "first.txt", "h-abs", "h-climb", "h-good"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        "b2-junctions" | "b2-winlink-targets" => vec!["plain-dir/kept.txt".to_owned()],
        "b2-write-through" => vec![
            "a/b/sibling.txt",
            "abs/canary.txt",
            "climb/canary.txt",
            "j/canary.txt",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        // A RAR 4 name's `\` is a separator whoever wrote it (spec F
        // question 3), so the Windows host's absolute forms are refused
        // there too, not flattened into one name.
        "b3-absolute-unix-host" | "r4-b3-absolute-unix-host" | "r4-b3-absolute-windows-host" => {
            vec!["plain.txt".to_owned()]
        }
        "r4-b2-unix-links" => vec!["lnk/canary.txt", "lnk2/canary.txt", "plain-dir/kept.txt"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        "b3-absolute-windows-host" => vec![
            "plain.txt".to_owned(),
            "_rooted.txt".to_owned(),
            flat("..\\..\\..\\escaped\\climb-backslash.txt"),
            flat(&format!("{escaped}\\abs-backslash.txt")),
            flat(&format!("{unc}\\unc.txt")),
            flat(&format!("\\\\?\\{escaped}\\verbatim.txt")),
        ],
        "b3-ads" | "r4-b3-ads" => vec![
            "ads.txt_evil".to_owned(),
            "ads2.txt__$DATA".to_owned(),
            "dir_$I30_$INDEX_ALLOCATION/inner.txt".to_owned(),
            format!("{drive}_canary.txt_evil"),
            "_lead".to_owned(),
        ],
        "b3-devices" | "r4-b3-devices" => vec![
            "CONIN$",
            "CONOUT$",
            "sub/_PRN.x.y",
            "_AUX .txt",
            "_COM1.log",
            "_COM\u{b9}",
            "_CON",
            "_con_",
            "_lpt9",
            "_LPT\u{b3}.txt",
            "_nul.txt",
            "_nul_",
        ]
        .into_iter()
        // The RAR 4 rows leave out the names that are not ASCII.
        .filter(|name| !tag.starts_with("r4-") || name.is_ascii())
        .map(str::to_owned)
        .collect(),
        "b3-trailing" | "r4-b3-trailing" => {
            vec!["t", "t_", "u _", "u._", "v.._", "w/x.txt", "w_/x.txt"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        }
        // The non-ASCII RAR 4 rows: the encoded part of a two-part name is
        // the name, whatever the fallback says, and is held to the rules an
        // ASCII name is.
        "r4u-b3-climbs" => vec!["plain-\u{fc}.txt".to_owned()],
        "r4u-b3-hostile-fallback" => vec!["\u{fc}-fb1.txt", "\u{fc}-fb2.txt", "\u{fc}-fb3.txt"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        "r4u-b3-fallback-only" => vec!["plain.txt".to_owned()],
        // A character that looks like a separator, a dot or a colon is an
        // ordinary character.
        "r4u-b3-lookalikes" => vec![
            "\u{ff0e}\u{ff0e}\u{ff3c}\u{ff0e}\u{ff0e}\u{ff3c}\u{ff0e}\u{ff0e}\u{ff3c}escaped\u{ff3c}fw.txt",
            "..\u{2215}..\u{2215}..\u{2215}escaped\u{2215}div.txt",
            "..\u{2216}..\u{2216}..\u{2216}escaped\u{2216}minus.txt",
            "..\u{a5}..\u{a5}..\u{a5}escaped\u{a5}yen.txt",
            "..\u{20a9}..\u{20a9}..\u{20a9}escaped\u{20a9}won.txt",
            "..\u{2044}..\u{2044}..\u{2044}escaped\u{2044}frac.txt",
            "\u{2024}\u{2024}/\u{2024}\u{2024}/\u{2024}\u{2024}/escaped/leader.txt",
            "ads\u{ff1a}evil.txt",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        "r4u-b3-ads" => vec![
            "\u{fc}-ads.txt_evil".to_owned(),
            "\u{fc}_evil".to_owned(),
            format!("{drive}_\u{fc}-canary.txt_evil"),
        ],
        "r4u-b3-devices" => vec![
            "_COM\u{b9}",
            "_LPT\u{b3}.txt",
            "_CON.\u{fc}",
            "_nul.\u{fc}",
            "\u{fc}/_PRN",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        "r4u-b3-trailing" => vec!["\u{fc}", "\u{fc}_", "\u{fc}-d_/x.txt", "\u{fc}-d/x.txt"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        "r4u-encoding-edges" => vec!["safe", "\u{fc}\u{fffd}.txt", "\u{1F600}.txt"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        "r4u-b2-unix-links" => vec![
            "lnk-\u{fc}/canary.txt",
            "lnk2-\u{fc}/canary.txt",
            "plain-\u{fc}/kept.txt",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        other => panic!("no expectation for row {other}"),
    };
    let links = match tag {
        "b2-winlink-targets" => vec![("inside", "plain-dir"), ("_nul", "NUL")],
        "r4-b2-unix-links" => vec![("inside", "plain-dir")],
        "r4u-b2-unix-links" => vec![("inside-\u{fc}", "plain-\u{fc}")],
        _ => vec![],
    };
    (names, links)
}

/// The exit code each run ends with: non-zero under `x` wherever a member
/// was refused or a junction declined; `e` takes each base name first, so
/// a hostile directory part is dropped rather than refused.
fn expected_exit(command: &str, tag: &str) -> i32 {
    match (command, tag) {
        (_, "b2-hard-and-copy") => 6,
        (_, "b2-winlink-targets" | "r4-b2-unix-links" | "r4u-b2-unix-links") => 1,
        ("x", "b2-junctions") => 9,
        ("x", "b2-write-through") => 1,
        (
            "x",
            "b3-absolute-unix-host"
            | "b3-absolute-windows-host"
            | "b3-ads"
            | "r4-b3-absolute-unix-host"
            | "r4-b3-absolute-windows-host"
            | "r4-b3-ads"
            | "r4u-b3-climbs"
            | "r4u-b3-fallback-only"
            | "r4u-b3-ads"
            | "r4u-encoding-edges",
        ) => 2,
        _ => 0,
    }
}

#[test]
fn no_hostile_windows_form_leaves_the_destination() {
    let root = std::env::temp_dir().join(format!("rarfast-hostile-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("bin")).unwrap();
    let _root = Root(root.clone());
    let unrar = root.join("bin").join("unrar.exe");
    std::fs::copy(rarfast(), &unrar).unwrap();
    let escaped_dir = root.join("escaped");
    let escaped = escaped_dir.to_str().unwrap().to_owned();
    let drive = escaped.chars().next().unwrap();
    assert!(escaped[1..].starts_with(':'), "{escaped} has no drive");
    let canary = escaped_dir.join(rows::CANARY);

    let rar5 = rows::rows(&escaped, drive)
        .into_iter()
        .map(|(tag, members)| (tag, rows::archive(&members)));
    let rar4 = rows::rows_rar4(&escaped, drive)
        .into_iter()
        .chain(rows::rows_rar4_unicode(&escaped, drive))
        .map(|(tag, members)| (tag, rows::archive_rar4(&members)));
    // A reference UnRAR named here runs the RAR 4 rows too, as a whole
    // process. What it does is printed, and a write of its outside the
    // destination is printed as such; neither fails this test.
    let mut arms = vec![("ours", unrar.clone())];
    if let Some(reference) = std::env::var_os("RARKIT_REFERENCE_UNRAR") {
        arms.push(("ref", PathBuf::from(reference)));
    }
    let mut failures = Vec::new();
    let mut reference_escapes = Vec::new();
    for (tag, archive) in rar5.chain(rar4) {
        for ((arm, exe), command) in arms
            .iter()
            .flat_map(|arm| ["x", "e"].map(|command| (arm, command)))
        {
            if *arm == "ref" && !tag.starts_with("r4") {
                continue;
            }
            let _ = std::fs::remove_dir_all(&escaped_dir);
            std::fs::create_dir_all(&escaped_dir).unwrap();
            std::fs::write(&canary, rows::CANARY_BODY).unwrap();
            let work = root.join(arm).join(format!("{command}-{tag}"));
            let out = work.join("out");
            std::fs::create_dir_all(&out).unwrap();
            std::fs::write(work.join("arc.rar"), &archive).unwrap();
            // The rows' climbs do reach the canary: a pass means something.
            assert_eq!(
                std::path::absolute(out.join("..\\..\\..\\escaped")).unwrap(),
                escaped_dir
            );

            let done = Command::new(exe)
                .args([command, "-o+", "-y", "arc.rar", "out\\"])
                .current_dir(&work)
                .output()
                .unwrap();
            let said = format!(
                "{}{}",
                String::from_utf8_lossy(&done.stdout),
                String::from_utf8_lossy(&done.stderr)
            );
            let row = format!("{arm} {command} {tag}");
            let mut escapes = Vec::new();

            if std::fs::read(&canary).ok().as_deref() != Some(rows::CANARY_BODY) {
                escapes.push(format!("{row}: the canary was written:\n{said}"));
            }
            if std::fs::metadata(format!("{}:evil", canary.display())).is_ok() {
                escapes.push(format!(
                    "{row}: a stream was written on the canary:\n{said}"
                ));
            }
            let mut around: BTreeSet<String> = std::fs::read_dir(&escaped_dir)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            around.remove(rows::CANARY);
            if !around.is_empty() {
                escapes.push(format!(
                    "{row}: written beside the canary: {around:?}\n{said}"
                ));
            }
            let mut beside: BTreeSet<String> = std::fs::read_dir(&work)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            beside.remove("arc.rar");
            beside.remove("out");
            if !beside.is_empty() {
                escapes.push(format!("{row}: written beside out: {beside:?}\n{said}"));
            }

            let mut files = BTreeMap::new();
            let mut links = BTreeMap::new();
            walk(&out, &out, &mut files, &mut links);
            let (want_files, want_links) = expected_x(tag, &escaped, drive);
            let allowed: BTreeMap<String, PathBuf> = want_links
                .iter()
                .map(|(name, target)| ((*name).to_owned(), PathBuf::from(target)))
                .collect();
            for (name, target) in &links {
                if allowed.get(name) != Some(target) {
                    escapes.push(format!(
                        "{row}: link {name} -> {}:\n{said}",
                        target.display()
                    ));
                }
            }
            let code = done.status.code();
            if *arm == "ref" || tag.starts_with("r4u-") {
                println!(
                    "{row}: exit {code:?}, files {:?}, links {links:?}",
                    files.keys().collect::<Vec<_>>()
                );
            }
            if *arm == "ref" {
                reference_escapes.extend(escapes);
                continue;
            }
            failures.extend(escapes);
            if command == "x" {
                let got: BTreeSet<&str> = files.keys().map(String::as_str).collect();
                let want: BTreeSet<&str> = want_files.iter().map(String::as_str).collect();
                if got != want {
                    failures.push(format!("{row}: wrote {got:?}, pinned {want:?}:\n{said}"));
                }
            }
            if code != Some(expected_exit(command, tag)) {
                failures.push(format!(
                    "{row}: exit {code:?}, pinned {}:\n{said}",
                    expected_exit(command, tag)
                ));
            }
        }
    }
    for escape in &reference_escapes {
        println!("REFERENCE OUTSIDE THE DESTINATION: {escape}");
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}
