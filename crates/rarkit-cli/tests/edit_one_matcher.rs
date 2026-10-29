//! `d` and `rn` read a mask by the read commands' matcher, and the
//! answers are rar 7.23's.
//!
//! Until 9 Oct 2026 the edit commands matched a name with a matcher of
//! their own (a greedy `*` and `?` over the whole archived name, then
//! over its last part), the last command to do so after the read commands
//! (8 Oct) and a create (9 Oct). The two tables here were measured on 9
//! Oct 2026 with `rar` 7.23 (an Apple silicon Mac) over an archive of the
//! tree [`TREE`] that `rar a -r -m0` wrote, a fresh copy of it a row:
//!
//! ```text
//! <mask> => <exit> | <members left, sorted> | <same, or what rarfast left before>
//! <old> <new> => <exit> | <members after, sorted> | <same, or what rarfast left before>
//! ```
//!
//! `edit-selection/rar723-d.txt` is every one of the 396 masks tried
//! where rarfast now answers as the reference does, 348 of them, 60 of
//! which it answered otherwise before. What a user can see, all towards
//! the reference:
//!
//! - **a name with no wildcard is that path**, and what lies beneath it:
//!   `d arc.rar a.txt` drops `a.txt` and leaves `s/a.txt` and
//!   `s/d/a.txt`, which went too; `d arc.rar dx` finds nothing (exit 10)
//!   where it dropped `s/dx`;
//! - **a wildcard does not cross into a directory's name**: `d arc.rar
//!   '*.t*'` leaves `s/dd.txt/k.bin`, `'s/d*'` leaves what lies in `s/d`,
//!   and `'?????'` leaves `s/d/e`;
//! - **a mask with a path takes the names beneath that path at any
//!   depth**: `'s/a*'` drops `s/d/a.txt` with `s/a.txt`, `'s/?'` drops
//!   `s/d/e` and `s/d/e/e` with `s/d`;
//! - **the dot rules**: `'*.*'` is every name, `'*.'` the names with no
//!   dot, `'*.*.*'` the names with one, and a dot that ends a mask
//!   matches the end of a name (`a.txt.`, `noext..`).
//!
//! `edit-selection/rar723-rn.txt` is the 37 pairs of the 794 tried that
//! rarfast answered otherwise before and answers as the reference now,
//! and the pairs it answered rightly before that rename something. `rn`
//! keeps its own rule for WHERE a wildcard looks (the member's path is
//! the mask's, so `s/d/*` does not reach `s/d/e/f.dat`); what changed is
//! the name part's dot rules, and a plain name's: `rn arc.rar a.txt. Q9`
//! renames `a.txt`.
//!
//! NOT in the tables, measured the same day and not matched:
//!
//! - **a mask that ends in a separator** (48 masks, 75 pairs: `s/d/`,
//!   `*/`). The reference reads it as a path and not as a mask, so `rar d
//!   arc.rar s/d/` is `rar d arc.rar` and DELETES EVERY MEMBER, and `rn`
//!   with one prints nothing. rarfast finds no member for it and exits 10
//!   with the archive as it was ([`a_mask_that_ends_in_a_separator`]);
//! - **the masks `.` and `..`** (measured 10 Oct 2026): the reference
//!   takes each for every member, so `rar d arc.rar .` DELETES EVERY
//!   MEMBER. rarfast finds no member for it and exits 10 with the archive
//!   as it was ([`a_mask_of_dots_alone`]); a read command lists every
//!   member for them, as the reference does;
//! - **a NEW name that ends in a separator, or is `.` or `..` or ends in
//!   one after a separator**: the reference reads it as a path too,
//!   renames nothing, says nothing and exits 0. So does rarfast where it
//!   is the last argument and ends in a separator (the command line takes
//!   it for a path, and the old name left over has no pair). Anywhere
//!   else rarfast refuses the pair by name, exit 2, the archive as it was
//!   ([`a_new_name_that_is_a_path_is_refused`]).
//!
//! **The new name** (the commit after: `edit-selection/rar723-rn-names.txt`,
//! 202 runs, 164 of which rarfast answered otherwise before). Until then
//! a wildcard `rn` cut the new mask at its last separator and gave the
//! member that path and its own last part, so `rn arc.rar 's/*' '*.zz'`
//! took `s/b.txt` OUT of its directory, to `b.zz`, and any new mask but
//! `*` and `*.<extension>` was refused. The reference reads the new mask
//! left to right beside a place in the member's WHOLE old name:
//!
//! - `*` copies the old name up to the first of the mask's next
//!   character, or all that is left where it ends the mask;
//! - `?` copies one character;
//! - `/` is written, and the place moves past the old name's next `/`;
//! - `.` is written, and the place moves past the old name's LAST `.`
//!   where it is the mask's last, its next one otherwise, and to the end
//!   where none lies ahead;
//! - any other character is written, and the place stays.
//!
//! So `'s/*' '*.zz'` gives `s/b.zz`, `'s/d/*' 'q/*'` gives `q/d/c.txt`
//! (and `'s/d/*' 's/q/*'` gives `s/q/c.txt`, as before), `a.b.txt` under
//! `*.zz` is `a.zz`, and a name with no wildcard takes a new mask the
//! same way (`rn arc.rar s/d '*x'` renames `s/d` and all beneath it to
//! `s/dx`). The rule was read off some 150 pairs made by hand and then
//! held against 3,600 more, every one of them the reference's answer; a
//! tenth of those are `edit-selection/rar723-rn-built.txt`, which a unit
//! test beside the rule reads.
//!
//! **A new name that would leave the archive's own tree** (a third
//! commit, 9 Oct 2026): a CHOSEN DIFFERENCE. rar 7.23 writes it and exits
//! 0: `rn arc.rar a.txt ../x.txt` stores a member named `../x.txt`, `rn
//! arc.rar a.txt /x.txt` one named `/x.txt`, `rn arc.rar s/d /D` stores
//! `/D` and everything beneath it there, and `rn arc.rar s/b.txt '../*'`
//! stores a member named `../` (14 pairs measured, the 12 of
//! [`a_new_name_that_leaves_the_tree_is_refused_before_any_line`] and two
//! that both tools write alike, `./x.txt` and `..x`). rarfast gives no
//! member a name that begins with a separator or holds a `..` part: the
//! pair is refused by name, exit 2, before a `Renaming` line is printed
//! or a byte written. Until then the lines were printed and the engine
//! then refused the rewrite, in words about a "malformed archive".
//!
//! Width and memory: every rarfast call states `-mt1`; the archive is
//! under 8 KiB.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

/// A name at two depths and at the top (`a.txt`), a name with two dots
/// and one with none, a directory whose name looks like a file's
/// (`dd.txt`), a file and a directory that share a first letter (`dx`,
/// `d`), and three levels of nesting.
const TREE: [&str; 11] = [
    "a.txt",
    "noext",
    "a.b.txt",
    "s/a.txt",
    "s/b.txt",
    "s/d/a.txt",
    "s/d/c.txt",
    "s/d/e/e/z.txt",
    "s/d/e/f.dat",
    "s/dd.txt/k.bin",
    "s/dx",
];

/// The members of the archive, sorted: the files and their directories.
const MEMBERS: &str = "a.b.txt a.txt noext s s/a.txt s/b.txt s/d s/d/a.txt s/d/c.txt s/d/e \
                       s/d/e/e s/d/e/e/z.txt s/d/e/f.dat s/dd.txt s/dd.txt/k.bin s/dx";

struct Work(PathBuf);

impl Work {
    /// A fresh directory holding `first.rar`, the tree stored.
    fn new(tag: &str) -> Work {
        let dir =
            std::env::temp_dir().join(format!("rarfast-edit-matcher-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let work = Work(dir);
        for (seed, name) in TREE.iter().enumerate() {
            let path = work.0.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let bytes: Vec<u8> = (0..300u32).map(|i| (i * 7 + seed as u32) as u8).collect();
            std::fs::write(path, bytes).unwrap();
        }
        let made = work.run(&[
            "a",
            "-idq",
            "-r",
            "-m0",
            "first.rar",
            "a.txt",
            "noext",
            "a.b.txt",
            "s",
        ]);
        assert!(made.status.success(), "{made:?}");
        work
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_rarfast"))
            .current_dir(&self.0)
            .arg(args[0])
            .arg("-mt1")
            .args(&args[1..])
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    /// `arc.rar` as it was first written.
    fn fresh(&self) {
        std::fs::copy(self.0.join("first.rar"), self.0.join("arc.rar")).unwrap();
    }

    /// The members of `arc.rar`, sorted, or `(erased)` when it is gone.
    fn members(&self) -> String {
        if !self.0.join("arc.rar").exists() {
            return "(erased)".to_owned();
        }
        let listed = self.run(&["lb", "arc.rar"]);
        assert!(listed.status.success(), "{listed:?}");
        let text = String::from_utf8(listed.stdout).unwrap();
        let mut names: Vec<&str> = text.lines().collect();
        names.sort_unstable();
        names.join(" ")
    }

    /// Runs every row of `table` as `<command> arc.rar <the row's
    /// arguments>` over a fresh archive, and returns the rows that did not
    /// answer as the table says.
    fn rows(&self, command: &str, table: &str) -> (usize, Vec<String>) {
        let mut wrong = Vec::new();
        let mut count = 0;
        for row in table.lines() {
            let (typed, rest) = row.split_once(" => ").expect("a row");
            let mut fields = rest.split(" | ");
            let exit: i32 = fields.next().unwrap().parse().expect("an exit");
            let members = fields.next().expect("the members");
            self.fresh();
            let mut args = vec![command, "arc.rar"];
            args.extend(typed.split(' '));
            let ran = self.run(&args);
            let got = (ran.status.code(), self.members());
            if got != (Some(exit), members.to_owned()) {
                wrong.push(format!(
                    "{command} {typed}: exit {:?}, left {}\n  the reference: exit {exit}, left \
                     {members}",
                    got.0, got.1
                ));
            }
            count += 1;
        }
        (count, wrong)
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn d_takes_what_the_reference_takes() {
    let work = Work::new("d");
    work.fresh();
    assert_eq!(work.members(), MEMBERS);
    let (count, wrong) = work.rows("d", include_str!("edit-selection/rar723-d.txt"));
    assert_eq!(count, 348);
    assert!(
        wrong.is_empty(),
        "{} rows:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[test]
fn rn_names_what_the_reference_names() {
    let work = Work::new("rn");
    let (count, wrong) = work.rows("rn", include_str!("edit-selection/rar723-rn.txt"));
    assert_eq!(count, 113);
    assert!(
        wrong.is_empty(),
        "{} rows:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[test]
fn rn_gives_the_names_the_reference_gives() {
    let work = Work::new("names");
    let (count, wrong) = work.rows("rn", include_str!("edit-selection/rar723-rn-names.txt"));
    assert_eq!(count, 202);
    assert!(
        wrong.is_empty(),
        "{} rows:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// rarfast's own answer, NOT the reference's (which renames nothing, in
/// silence, exit 0): the pair is refused by name and nothing is written.
#[test]
fn a_new_name_that_is_a_path_is_refused() {
    let work = Work::new("new-path");
    work.fresh();
    let before = std::fs::read(work.0.join("arc.rar")).unwrap();
    for args in [
        &["a.txt", "."][..],
        &["s/*", "x/.."],
        &["s/d", "x/."],
        &["s/d", "q/", "a.txt", "Q9"],
    ] {
        let (from, to) = (args[0], args[1]);
        let mut typed = vec!["rn", "arc.rar"];
        typed.extend(args);
        let ran = work.run(&typed);
        assert_eq!(ran.status.code(), Some(2), "rn {args:?}");
        assert_eq!(
            String::from_utf8_lossy(&ran.stdout),
            "\nProcessing archive arc.rar\nDone\n",
            "rn {args:?}"
        );
        let said = String::from_utf8_lossy(&ran.stderr).into_owned();
        assert!(
            said.contains(&format!("Cannot rename {from} to {to}")),
            "rn {args:?}: {said}"
        );
        assert!(std::fs::read(work.0.join("arc.rar")).unwrap() == before);
    }
    // The last argument, ending in a separator: no pair is left, nothing
    // is renamed, exit 0, which is the reference's exit too.
    let ran = work.run(&["rn", "arc.rar", "s/d", "q/"]);
    assert_eq!(ran.status.code(), Some(0));
    assert!(std::fs::read(work.0.join("arc.rar")).unwrap() == before);
}

/// rarfast's own answer, NOT the reference's (which writes each of these
/// names and exits 0): a name as BUILT that begins with a separator or
/// holds a `..` part is refused before any `Renaming` line, and nothing
/// is written.
#[test]
fn a_new_name_that_leaves_the_tree_is_refused_before_any_line() {
    let work = Work::new("leaves");
    work.fresh();
    let before = std::fs::read(work.0.join("arc.rar")).unwrap();
    // The old name, the new one, and the name the reference stores.
    for (from, to, built) in [
        ("a.txt", "/x.txt", "/x.txt"),
        ("a.txt", "../x.txt", "../x.txt"),
        ("a.txt", "../../x.txt", "../../x.txt"),
        ("a.txt", "/abs/dir/x.txt", "/abs/dir/x.txt"),
        ("a.txt", "s/../x.txt", "s/../x.txt"),
        ("a.txt", "//x.txt", "//x.txt"),
        ("a.txt", "x/../y", "x/../y"),
        ("s/b.txt", "/*", "/b.txt"),
        ("s/b.txt", "../*", "../"),
        ("s/dd.txt", "../D", "../D/k.bin"),
        ("s/dd.txt", "/D", "/D/k.bin"),
        ("s/*", "../*", "../"),
    ] {
        let ran = work.run(&["rn", "arc.rar", from, to]);
        assert_eq!(ran.status.code(), Some(2), "rn {from} {to}");
        assert_eq!(
            String::from_utf8_lossy(&ran.stdout),
            "\nProcessing archive arc.rar\nDone\n",
            "rn {from} {to}"
        );
        let said = String::from_utf8_lossy(&ran.stderr).into_owned();
        assert!(
            said.contains(" to ") && said.contains(&format!(" to {built}\n")),
            "rn {from} {to}: {said}"
        );
        assert!(said.contains("Cannot rename "), "rn {from} {to}: {said}");
        assert!(!said.contains("malformed"), "rn {from} {to}: {said}");
        assert!(std::fs::read(work.0.join("arc.rar")).unwrap() == before);
    }
    // Two the reference and rarfast both write, alike: a `.` part, and a
    // name that only begins with two dots.
    for (to, after) in [("./x.txt", "./x.txt"), ("..x", "..x")] {
        work.fresh();
        let ran = work.run(&["rn", "arc.rar", "a.txt", to]);
        assert_eq!(ran.status.code(), Some(0), "rn a.txt {to}");
        assert_eq!(
            String::from_utf8_lossy(&ran.stdout),
            format!("\nProcessing archive arc.rar\nRenaming a.txt to {after}\nDone\n")
        );
        assert!(work.members().split(' ').any(|name| name == after));
    }
}

/// The lines of three rows, whole. The reference's are these but for the
/// order of two members in its own archive.
#[test]
fn the_lines_name_the_member() {
    let work = Work::new("lines");
    for (args, lines) in [
        (
            &["d", "arc.rar", "s/a.txt."][..],
            "\nDeleting from arc.rar\nDeleting s/a.txt\nDone\n",
        ),
        (
            &["rn", "arc.rar", "a.txt.", "Q9"][..],
            "\nProcessing archive arc.rar\nRenaming a.txt to Q9\nDone\n",
        ),
        (
            &["rn", "arc.rar", "s/*.", "S/*"][..],
            "\nProcessing archive arc.rar\nRenaming s/d to S/d\nRenaming s/dx to S/dx\nDone\n",
        ),
    ] {
        work.fresh();
        let ran = work.run(args);
        assert_eq!(ran.status.code(), Some(0), "{args:?}");
        assert_eq!(String::from_utf8_lossy(&ran.stdout), lines, "{args:?}");
    }
}

/// rarfast's own answer, NOT the reference's (which reads such a mask as
/// a path, and so deletes every member): no member is found, and the
/// archive is left byte for byte.
#[test]
fn a_mask_that_ends_in_a_separator() {
    let work = Work::new("separator");
    work.fresh();
    let before = std::fs::read(work.0.join("arc.rar")).unwrap();
    for mask in ["s/d/", "s/", "*/", "s/dd.txt/"] {
        let ran = work.run(&["d", "arc.rar", mask]);
        assert_eq!(ran.status.code(), Some(10), "d {mask}");
        assert_eq!(
            String::from_utf8_lossy(&ran.stdout),
            "\nDeleting from arc.rar\nNo files to delete\n",
            "d {mask}"
        );
        assert!(std::fs::read(work.0.join("arc.rar")).unwrap() == before);
    }
}

/// rarfast's own answer, NOT the reference's: a CHOSEN DIFFERENCE from
/// the specification's rule D2 until the owner says otherwise. rar 7.23
/// takes `.` and `..` for every member and deletes them all; here no
/// member is found and the archive is left byte for byte. A listing with
/// the same masks names every member, as the reference's does.
#[test]
fn a_mask_of_dots_alone() {
    let work = Work::new("dots");
    work.fresh();
    let before = std::fs::read(work.0.join("arc.rar")).unwrap();
    let all = work.run(&["lb", "arc.rar"]).stdout;
    assert_eq!(String::from_utf8_lossy(&all).lines().count(), 16);
    for mask in [".", ".."] {
        let ran = work.run(&["d", "arc.rar", mask]);
        assert_eq!(ran.status.code(), Some(10), "d {mask}");
        assert_eq!(
            String::from_utf8_lossy(&ran.stdout),
            "\nDeleting from arc.rar\nNo files to delete\n",
            "d {mask}"
        );
        assert!(std::fs::read(work.0.join("arc.rar")).unwrap() == before);
        // Beside a mask that names a member, the dots add nothing.
        let ran = work.run(&["d", "arc.rar", mask, "noext"]);
        assert_eq!(ran.status.code(), Some(0), "d {mask} noext");
        let left = work.run(&["lb", "arc.rar"]).stdout;
        assert_eq!(String::from_utf8_lossy(&left).lines().count(), 15);
        work.fresh();
        assert_eq!(work.run(&["lb", "arc.rar", mask]).stdout, all, "lb {mask}");
    }
}
