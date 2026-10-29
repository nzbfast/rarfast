//! The read commands' mask rules: what a file argument selects, and what
//! `-x<mask>` and `-n<mask>` screen.
//!
//! Every rule here was measured off reference unrar 7.23 as a black box
//! (macOS arm64, 8 Oct 2026: `unrar lb` over 1,856 masks as an argument,
//! under `-x` and under `-n`, then 7,374 random ones) and is pinned by
//! `tests/selection_masks.rs`, whose header states the rules in words.
//! `-n` lists exactly what `-x` takes out, for every mask tried, so the
//! two share [`Screen`].
//!
//! Left unmatched, all of them masks nobody types: an `-x` mask with
//! `..` or `...` inside it, and an ARGUMENT that ends in `/.`, which the
//! reference reads as a path.
//!
//! A create screens what it walks by the same [`Screen`] and matches a
//! name by the same [`wildcard`] (`rar::select`, which says what it adds
//! for a path on disk). The edit commands read a mask here too: `d` by
//! [`selects`], `rn` a name by [`wildcard`] (`rar::edit`).

/// Whether a byte separates directories: `/`, and on Windows `\` too,
/// where an archived name is shown with it.
fn is_separator(byte: u8) -> bool {
    byte == b'/' || (cfg!(windows) && byte == b'\\')
}

// The matcher below (from `letters` to `names`) was written on 10 Oct
// 2026 from the rules of the command line's specification, sections 2 to
// 5, and its measured tables alone: each arm names the rule it is.

/// Whether a mask holds a wildcard.
pub(crate) fn has_wildcard(mask: &str) -> bool {
    mask.bytes().any(|byte| byte == b'*' || byte == b'?')
}

/// The index just past the last separator, or 0.
fn leaf_start(text: &str) -> usize {
    text.bytes()
        .rposition(is_separator)
        .map_or(0, |index| index + 1)
}

/// A mask or a name as its characters, so that a `?` is one character
/// whatever its length in bytes; on Windows a `\` is read as the `/` it
/// is shown for.
fn letters(text: &str) -> Vec<char> {
    text.chars()
        .map(|letter| {
            if cfg!(windows) && letter == '\\' {
                '/'
            } else {
                letter
            }
        })
        .collect()
}

/// Whether a stretch of a mask that holds no `*` stands for the
/// characters of `name` from `at` on: each `?` for any one character,
/// every other character for itself.
fn lies_at(stretch: &[char], name: &[char], at: usize) -> bool {
    name.get(at..at + stretch.len()).is_some_and(|there| {
        stretch
            .iter()
            .zip(there)
            .all(|(wanted, had)| *wanted == '?' || wanted == had)
    })
}

/// What a mask must stand for.
#[derive(Clone, Copy)]
enum Reach {
    /// The whole name.
    Whole,
    /// A front of the name that leaves no dot after it.
    DotFreeRest,
}

/// Rule M1 and no other: whether `mask` stands for the name, or for a
/// front of it, by `reach`.
///
/// A mask is its stretches between the stars. The first lies at the
/// front of the name; each one in the middle is put at the earliest
/// place left for it, which leaves the most room for those after it; and
/// the last must end where the reach says, at or after the room the
/// others took. Nothing is ever taken back, so a mask of many stars costs
/// one pass over the name a stretch.
fn stands_for(mask: &[char], name: &[char], reach: Reach) -> bool {
    // The earliest place the mask's part of the name may end.
    let floor = match reach {
        Reach::Whole => name.len(),
        Reach::DotFreeRest => name
            .iter()
            .rposition(|letter| *letter == '.')
            .map_or(0, |dot| dot + 1),
    };
    let mut stretches = mask.split(|letter| *letter == '*');
    let first = stretches.next().unwrap_or_default();
    if !lies_at(first, name, 0) {
        return false;
    }
    let Some(last) = stretches.next_back() else {
        // No star: the mask stands for exactly its own length.
        return first.len() >= floor;
    };
    let mut taken = first.len();
    for stretch in stretches {
        match (taken..=name.len()).find(|at| lies_at(stretch, name, *at)) {
            Some(at) => taken = at + stretch.len(),
            None => return false,
        }
    }
    (floor.max(taken + last.len())..=name.len()).any(|end| lies_at(last, name, end - last.len()))
}

/// Rule M12: the mask as written, or with some or all of the dots that
/// end it left off. A `*` directly before those dots is not this rule's,
/// and such a mask is read as written.
fn with_dots_left_off(mask: &[char], name: &[char]) -> bool {
    let dots = mask
        .iter()
        .rev()
        .take_while(|letter| **letter == '.')
        .count();
    let kept = mask.len() - dots;
    if mask[..kept].last() == Some(&'*') {
        return stands_for(mask, name, Reach::Whole);
    }
    (kept..=mask.len()).any(|length| stands_for(&mask[..length], name, Reach::Whole))
}

/// Whether a mask's characters select a name's: rules M1 and M11 to M15
/// and M17 of the command line's specification, section 2, each arm
/// naming its own.
fn chooses(mask: &[char], name: &[char]) -> bool {
    let dots = mask
        .iter()
        .rev()
        .take_while(|letter| **letter == '.')
        .count();
    let body = &mask[..mask.len() - dots];
    if let Some((_, front)) = body.split_last().filter(|(end, _)| **end == '*') {
        return match dots {
            // No dot ends the mask; the rules below are for it.
            0 => final_dot_star(mask, name),
            // M13: the star is a run with no dot, the dot a dot or
            // nothing; and `X.*.`, X with no star, is X as well.
            1 => {
                let undotted = name.strip_suffix(&['.']).unwrap_or(name);
                stands_for(front, name, Reach::DotFreeRest)
                    || stands_for(front, undotted, Reach::DotFreeRest)
                    || front
                        .split_last()
                        .filter(|(end, alone)| **end == '.' && !alone.contains(&'*'))
                        .is_some_and(|(_, alone)| chooses(alone, name))
            }
            // M15: `P*..` and longer are `P*.*.` under M1.
            _ => stands_for(&[body, &['.', '*', '.']].concat(), name, Reach::Whole),
        };
    }
    if dots == 1 {
        // M14: `P*.t.`, t plain and with no dot, is itself and `P*.*.t`.
        let star = body.iter().rposition(|letter| *letter == '*');
        if let Some((through_star, after)) = star.map(|at| body.split_at(at + 1)) {
            if let Some(('.', tail)) = after.split_first() {
                if !tail.is_empty() && !tail.iter().any(|letter| matches!(letter, '?' | '.')) {
                    let twice = [through_star, &['.', '*', '.'], tail].concat();
                    return stands_for(mask, name, Reach::Whole)
                        || stands_for(&twice, name, Reach::Whole);
                }
            }
        }
    }
    with_dots_left_off(mask, name)
}

/// A mask that ends in a `*`: rule M11 where a dot stands before that
/// star, M1 alone where none does.
fn final_dot_star(mask: &[char], name: &[char]) -> bool {
    if stands_for(mask, name, Reach::Whole) {
        return true;
    }
    let Some(shorter) = mask.strip_suffix(&['.', '*']) else {
        return false;
    };
    // M11's second clause, measured on 10 Oct 2026: `X.*.*`, X with no
    // star, is `X.*` as well (`noext.*.*` lists `noext`, `b.*.*` lists
    // `b` and `b.txt`), and a third `.*` ends it (`b.*.*.*` lists
    // neither).
    if let Some(once) = shorter.strip_suffix(&['.', '*']) {
        if !once.contains(&'*') {
            return stands_for(shorter, name, Reach::Whole) || with_dots_left_off(once, name);
        }
    }
    // M11: the final `.*` stands for nothing, and what is left is read
    // with M12 (`a..*` lists `a`); M17: of `P*..*` it is `P*.` as
    // written.
    with_dots_left_off(shorter, name)
}

/// Whether `mask` selects `name` where the two are compared whole: a
/// name part with a member's last component, or a mask with a wildcard
/// in its path part with a member's whole name, where a wildcard stands
/// for a separator as for any character.
pub(crate) fn wildcard(mask: &str, name: &str) -> bool {
    chooses(&letters(mask), &letters(name))
}

/// Whether `name` lies beneath the directory `directory` names.
fn beneath(name: &str, directory: &str) -> bool {
    let (name, directory) = (name.as_bytes(), directory.as_bytes());
    name.get(directory.len())
        .is_some_and(|byte| is_separator(*byte))
        && alike(&name[..directory.len()], directory)
}

/// Whether two stretches of names are the same, separators alike.
fn alike(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(x, y)| x == y || (is_separator(*x) && is_separator(*y)))
}

/// Whether a file argument selects `name`.
pub(crate) fn selects(mask: &str, name: &str) -> bool {
    // M16: the two masks of dots that are every member.
    mask == "." || mask == ".." || names(mask, name)
}

/// [`selects`] without rule M16, which a `-x` or `-n` mask does not have
/// (rule X2).
fn names(mask: &str, name: &str) -> bool {
    // M10 and M9: an empty mask, and one that ends in a separator, are
    // no mask.
    if mask.bytes().last().is_none_or(is_separator) {
        return false;
    }
    let (path, part) = mask.split_at(leaf_start(mask));
    if has_wildcard(path) {
        // M6: the whole mask and the whole name.
        wildcard(mask, name)
    } else if has_wildcard(part) {
        // M4 and M5: beneath the path part at any depth, by the last
        // component. M8: the path part is taken as written.
        let own = leaf_start(name);
        own >= path.len()
            && alike(&name.as_bytes()[..path.len()], path.as_bytes())
            && wildcard(part, &name[own..])
    } else {
        // M3: all beneath the directory the mask names, or the name
        // itself, which M12 lets the mask write with dots after it.
        beneath(name, mask) || wildcard(mask, name)
    }
}

/// How many bytes at the front of a `-x` or `-n` mask are dropped before
/// it is compared: every leading `./`, `../` and separator.
pub(crate) fn lead(mask: &str) -> usize {
    let bytes = mask.as_bytes();
    let mut at = 0;
    loop {
        let dots = bytes[at..].iter().take_while(|byte| **byte == b'.').count();
        match bytes.get(at + dots) {
            Some(byte) if dots <= 2 && is_separator(*byte) => at += dots + 1,
            _ => return at,
        }
    }
}

/// One `-x` or `-n` mask, read once.
pub(crate) struct Screen {
    /// The mask with its leading `./`, `../` and separators dropped; with
    /// a `*` added where it ended in a separator.
    body: String,
    /// The mask without its trailing separator, where it had one: the
    /// directory it names.
    directory: Option<String>,
    /// Nothing was left of the mask (`-x/`, `-x./`): every file, and no
    /// directory.
    every_file: bool,
}

impl Screen {
    pub(crate) fn new(mask: &str) -> Self {
        let rest = &mask[lead(mask)..];
        let ended = rest
            .as_bytes()
            .last()
            .is_some_and(|byte| is_separator(*byte));
        Self {
            body: if ended {
                format!("{rest}*")
            } else {
                rest.to_owned()
            },
            directory: ended.then(|| rest[..rest.len() - 1].to_owned()),
            every_file: rest.is_empty() && !mask.is_empty(),
        }
    }

    /// Whether the mask covers `name`: excluded under `-x`, kept under
    /// `-n`.
    pub(crate) fn covers(&self, name: &str, is_dir: bool) -> bool {
        if self.every_file {
            return !is_dir;
        }
        if let Some(directory) = &self.directory {
            if is_dir {
                // X7, and X8 (a): the directory the mask names without
                // its last separator. X8 gives a mask with a wildcard no
                // other directory: (b) is of files alone.
                return Self::one(directory, name, false)
                    || (!has_wildcard(directory) && Self::one(&self.body, name, true));
            }
        }
        Self::one(&self.body, name, is_dir)
    }

    fn one(mask: &str, name: &str, is_dir: bool) -> bool {
        let leaf = &mask[leaf_start(mask)..];
        if is_dir && has_wildcard(leaf) && leaf != "*" && leaf != "*.*" {
            return false;
        }
        let bytes = mask.as_bytes();
        let any_depth = bytes.len() > 1 && bytes[0] == b'*' && is_separator(bytes[1]);
        (any_depth && wildcard(&mask[2..], name)) || names(mask, name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_dot_rules() {
        let rows = [
            ("*.*", "noext", true),
            ("*.", "noext", true),
            ("*.", "top.txt", false),
            ("noext..", "noext", true),
            ("b.txt.", "b.txt", true),
            ("*.txt.", "top.txt", false),
            ("*.txt.", "a.b.txt", true),
            ("*.*.*", "top.txt", true),
            ("*.*.*", "noext", false),
            ("n*.*.*", "noext", false),
            ("noext.*.*", "noext", true),
            ("?*.txt.", "top.txt", false),
            ("*?.txt.", "top.txt", true),
            ("*t.", "noext", true),
            ("t*.", "top.txt", false),
            ("?????", "b.txt", true),
            ("?????", "noex", false),
        ];
        for (mask, name, expected) in rows {
            assert_eq!(wildcard(mask, name), expected, "{mask} over {name}");
        }
    }

    #[test]
    fn a_question_mark_is_one_character() {
        assert!(wildcard("a?b", "a\u{e9}b"));
        assert!(!wildcard("a??b", "a\u{e9}b"));
        assert!(wildcard("*?b", "\u{4e2d}\u{6587}b"));
    }

    /// A name's own `*` does not spend the mask's: the star is a
    /// wildcard whatever the name holds there (unrar 7.23 on macOS, 4 Oct
    /// 2026; `tests/mask_star_in_name.rs` has the table).
    #[test]
    fn a_star_in_a_name_is_matched_by_the_masks() {
        assert!(wildcard("*", "*abc"));
        assert!(wildcard("a*", "a*b"));
        assert!(wildcard("*b", "*ab"));
        assert!(wildcard("*.tmp", "*x.tmp"));
        assert!(!wildcard("*b", "*a"));
    }

    /// A mask of many stars over a long name that cannot match ends at
    /// once: no stretch of the mask is ever placed twice.
    #[test]
    fn many_stars_do_not_blow_up() {
        let mask = "*a".repeat(40) + "b";
        let name = "a".repeat(4000);
        assert!(!wildcard(&mask, &name));
        assert!(wildcard(&mask, &(name + "b")));
    }

    /// One measured table of `tests/mask-rules` (reference rar and unrar
    /// 7.23 on macOS, 10 Oct 2026; the copies of the specification's
    /// `vectors-CLI/mask-selection`): its members, and each row's mask
    /// with the names in column `column`.
    fn measured(table: &'static str, column: usize) -> (Vec<&'static str>, Vec<Row>) {
        let mut members = Vec::new();
        let mut rows = Vec::new();
        for line in table.lines() {
            if let Some(list) = line.strip_prefix("# members:") {
                members = list.split_whitespace().collect();
            } else if !line.starts_with('#') && !line.starts_with("mask\t") {
                let fields: Vec<&str> = line.split('\t').collect();
                let mask = if fields[0] == "(empty)" {
                    ""
                } else {
                    fields[0]
                };
                let names = fields[column]
                    .split(' ')
                    .filter(|name| !name.is_empty() && *name != "-")
                    .collect();
                rows.push((mask, names));
            }
        }
        assert!(!members.is_empty() && !rows.is_empty());
        (members, rows)
    }

    type Row = (&'static str, Vec<&'static str>);

    /// The rows of a table that `selects` answers otherwise, each as a
    /// line. A mask that ends in a separator is left to the command
    /// line, which reads it as a path (rule M9).
    fn unlike(table: &'static str, column: usize) -> (usize, Vec<String>) {
        let (members, rows) = measured(table, column);
        let asked: Vec<&Row> = rows.iter().filter(|row| !row.0.ends_with('/')).collect();
        let wrong = asked
            .iter()
            .filter_map(|(mask, expected)| {
                let got: Vec<&str> = members
                    .iter()
                    .copied()
                    .filter(|name| selects(mask, name))
                    .collect();
                (got != *expected).then(|| format!("{mask}: {got:?}, measured {expected:?}"))
            })
            .collect();
        (asked.len(), wrong)
    }

    /// Rules M1 and M11 to M17, exhaustively at four characters: every
    /// mask over `*`, `?`, `.`, `a` and `b` against every name over `a`,
    /// `b` and `.`.
    #[test]
    fn every_short_mask_selects_the_measured_names() {
        let (asked, wrong) = unlike(
            include_str!("../../../../tests/mask-rules/read-dots-7.23-macos-arm64.tsv"),
            1,
        );
        assert_eq!(asked, 723);
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    /// Rule M11's second clause and M17 at their own lengths: 18 masks
    /// over five members.
    #[test]
    fn a_second_final_dot_star_selects_the_measured_names() {
        let (asked, wrong) = unlike(
            include_str!("../../../../tests/mask-rules/read-five-7.23-macos-arm64.tsv"),
            1,
        );
        assert_eq!(asked, 18);
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    /// Rules M2 to M10 and M16 over a tree four levels deep.
    #[test]
    fn a_mask_over_a_tree_selects_the_measured_names() {
        let (asked, wrong) = unlike(
            include_str!("../../../../tests/mask-rules/read-tree-7.23-macos-arm64.tsv"),
            1,
        );
        assert_eq!(asked, 111);
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    /// Rule D1: `d` removes what a read command's argument selects.
    /// (The command itself holds the masks `.` and `..` back, a chosen
    /// difference; this is the matcher's answer.)
    #[test]
    fn a_delete_mask_selects_the_measured_names() {
        let (asked, wrong) = unlike(
            include_str!("../../../../tests/mask-rules/edit-7.23-macos-arm64.tsv"),
            2,
        );
        assert_eq!(asked, 95);
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    /// Rules X1 to X9: what a mask takes in `-x` and `-n`. The tree's
    /// directories are the names something lies beneath, and its two
    /// empty ones. Every row is asked, `a*/` with the rest: rule X8
    /// leaves the directories beneath `a`, which were taken until 10 Oct
    /// 2026.
    #[test]
    fn a_switch_mask_takes_the_measured_names() {
        let (members, rows) = measured(
            include_str!("../../../../tests/mask-rules/read-screen-7.23-macos-arm64.tsv"),
            1,
        );
        assert_eq!(rows.len(), 147);
        let is_dir = |name: &str| {
            name == "a/emptydir"
                || name == "e.dir"
                || members.iter().any(|other| beneath(other, name))
        };
        let wrong: Vec<String> = rows
            .iter()
            .filter_map(|(mask, expected)| {
                let screen = Screen::new(mask);
                let got: Vec<&str> = members
                    .iter()
                    .copied()
                    .filter(|name| screen.covers(name, is_dir(name)))
                    .collect();
                (got != *expected).then(|| format!("{mask}: {got:?}, measured {expected:?}"))
            })
            .collect();
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    /// Rule X8 beside the table's rows: a mask with a wildcard that ends
    /// in a separator takes the directories it names without that
    /// separator and the files that stand in a directory it stands for,
    /// and no directory beneath one. Measured on 10 Oct 2026 (`lb -n` of
    /// rar and unrar 7.23, macOS arm64, the table's own tree; 1,500 more
    /// such masks drawn at random agreed under `-x` and `-n` alike).
    #[test]
    fn a_wildcard_directory_mask_leaves_the_directories_beneath() {
        let (members, _) = measured(
            include_str!("../../../../tests/mask-rules/read-screen-7.23-macos-arm64.tsv"),
            1,
        );
        let is_dir = |name: &str| {
            name == "a/emptydir"
                || name == "e.dir"
                || members.iter().any(|other| beneath(other, name))
        };
        let rows: [(&str, &str); 5] = [
            ("x*/", "x x/Sub/s.txt x/a/b.txt x/top.txt"),
            ("a?*/", "a.d a.d/e.txt a.d/noext a/b/c.txt a/b/c/d.txt a/b/c/noext"),
            (
                "*a/",
                "a a/b.txt a/b/c.txt a/b/c/d.txt a/b/c/noext a/noext x/a x/a/b.txt",
            ),
            (
                "a*/*/",
                "a/b a/b/c a/b/c.txt a/b/c/d.txt a/b/c/noext a/emptydir",
            ),
            (
                "?/?*/",
                "a/b a/b/c a/b/c.txt a/b/c/d.txt a/b/c/noext a/emptydir x/Sub x/Sub/s.txt x/a x/a/b.txt",
            ),
        ];
        for (mask, expected) in rows {
            let screen = Screen::new(mask);
            let got: Vec<&str> = members
                .iter()
                .copied()
                .filter(|name| screen.covers(name, is_dir(name)))
                .collect();
            assert_eq!(got.join(" "), expected, "{mask}");
        }
    }

    /// Measured beside the rules on 10 Oct 2026 (rar and unrar 7.23,
    /// macOS, members `noext b b.txt a.b.txt n.x`), where no row of the
    /// tables stands: a second `.*` after a mask with no star, and what a
    /// final `.*` leaves of a mask whose star stands before two dots.
    #[test]
    fn a_plain_front_and_two_final_dot_stars() {
        let members = ["noext", "b", "b.txt", "a.b.txt", "n.x"];
        let rows: [(&str, &[&str]); 9] = [
            ("noext.*.*", &["noext"]),
            ("b.*.*", &["b", "b.txt"]),
            ("n?ext.*.*", &["noext"]),
            ("b.*.*.*", &[]),
            ("n*.*.*", &["n.x"]),
            ("noext.*.*.", &[]),
            ("noext..*", &["noext"]),
            ("b*..*", &[]),
            ("n*..*", &[]),
        ];
        for (mask, expected) in rows {
            let got: Vec<&str> = members
                .iter()
                .copied()
                .filter(|name| selects(mask, name))
                .collect();
            assert_eq!(got, expected, "{mask}");
        }
    }

    /// Rule M16 is an argument's and not a switch's (rule X2), and `rn`
    /// reads a name with no wildcard by [`wildcard`], which has no M16
    /// (rule N4).
    #[test]
    fn the_masks_of_dots_alone() {
        for mask in [".", ".."] {
            assert!(selects(mask, "a/b.txt"), "{mask}");
            assert!(!Screen::new(mask).covers("a/b.txt", false), "-x{mask}");
            assert!(!wildcard(mask, "a"), "rn {mask}");
        }
        assert!(!selects("", "a"));
        assert!(!selects("a/", "a/b.txt"));
    }
}
