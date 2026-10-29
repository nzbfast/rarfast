//! The creator's progress lines, to the column.
//!
//! Every constant here was measured against `rar` 7.23 on an Apple Silicon Mac rather
//! than read out of a manual, because the conformance normaliser compares
//! the rendered line and not its meaning. It deletes runs of backspace and
//! rewrites `\b\d{1,3}%` to a fixed token, so a percentage printed one
//! column left of the reference's, or padded to two digits where the
//! reference padded to three, gives a line of a different LENGTH and the
//! row diverges on that alone.
//!
//! What the reference emits for one added file, measured byte for byte:
//!
//! ```text
//! Adding    text.txt<pad to column 73>\b\b\b\b 42%\b\b\b\b\b  OK
//! ```
//!
//! The backspaces are a terminal redraw: the cursor walks back over the
//! padding, writes the counter in a four column field, walks back again
//! and overwrites it with the result. Three shapes differ from it and all
//! three are the reference's, not ours:
//!
//! - a DIRECTORY entry has no counter at all, so the line pads to the same
//!   column 73 and goes straight to the five backspaces;
//! - `-idp` asks for no counter, and then the padding stops one column
//!   short, at 72, because nothing is going to be walked back over;
//! - a member that runs off the end of a volume ends with four backspaces
//!   and four spaces, which ERASES the counter and leaves no result: the
//!   result lands on the last volume the member reaches.

/// The column the name field is padded out to before the counter is drawn.
///
/// Measured: `Adding    text.txt` plus padding is 73 bytes before the
/// first backspace, whatever the name.
const COUNTER_COLUMN: usize = 73;

/// The same column when no counter will be drawn (`-idp`), which is one
/// short of [`COUNTER_COLUMN`].
const PLAIN_COLUMN: usize = COUNTER_COLUMN - 1;

/// The verb field's width: `Adding` and `...` are both padded to it.
const VERB_WIDTH: usize = 10;

/// What the creator is doing to one member, in the reference's own word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verb {
    /// `Adding`: the member starts here.
    Adding,
    /// `...`: the member continues from the previous volume.
    Continuing,
}

impl Verb {
    /// The word, already padded to the verb field.
    fn word(self) -> &'static str {
        match self {
            // Both are padded to VERB_WIDTH; spelled out rather than
            // computed so the constant and the text cannot drift apart.
            Self::Adding => "Adding    ",
            Self::Continuing => "...       ",
        }
    }
}

/// How a member's progress line ENDS, which is the one thing the three
/// shapes above disagree about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ending {
    /// The member is finished here: the counter is overwritten with the
    /// result.
    Done,
    /// The member runs into the next volume: the counter is erased and
    /// nothing replaces it.
    Continues,
}

/// The line a member's progress opens with: the verb, the name and the
/// padding a counter would be drawn over.
///
/// `reserved` is whether the counter FIELD is there at all, which is not
/// the same question as whether a counter is drawn in it: a continuation
/// line and a directory line both reserve the field and draw nothing, and
/// only `-idp` gives the field up.
pub(crate) fn opening(verb: Verb, name: &str, reserved: bool) -> String {
    // Each control character is held as ONE character, so the padding
    // below is what it was (SPEC-CLI section 10, rule T8).
    let on_host = on_this_host(name);
    let name = &super::super::unrar::name_from_disk(&on_host);
    let column = if reserved {
        COUNTER_COLUMN
    } else {
        PLAIN_COLUMN
    };
    let mut line = String::from(verb.word());
    line.push_str(name);
    // A name wider than the field gets no padding at all, which is what
    // the reference does: the counter is simply drawn further right.
    let width = VERB_WIDTH + name.chars().count();
    for _ in width..column {
        line.push(' ');
    }
    line
}

/// A source's path as the reference PRINTS it on this host. The creator
/// keeps every path with forward separators, which is how it is stored;
/// on Windows the reference prints a source with backslashes, however it
/// was typed.
///
/// Measured against Rar.exe 7.x on Windows 11, 4 Oct 2026: `m m.rar
/// data/b.txt` prints `Adding    data\b.txt` and `Deleting data\b.txt`,
/// and a walked directory `Deleting directory data\sub`. rarfast printed
/// forward separators there.
fn on_this_host(name: &str) -> std::borrow::Cow<'_, str> {
    printed_with(name, cfg!(windows))
}

/// [`on_this_host`] with the host stated, so that both are tested on one.
fn printed_with(name: &str, backslashes: bool) -> std::borrow::Cow<'_, str> {
    if backslashes && name.contains('/') {
        std::borrow::Cow::Owned(name.replace('/', "\\"))
    } else {
        std::borrow::Cow::Borrowed(name)
    }
}

/// One redraw of the counter: four columns, right aligned, so that ` 42%`
/// and `100%` occupy the same field.
pub(crate) fn counter(percent: u64) -> String {
    format!("\u{8}\u{8}\u{8}\u{8}{percent:3}%")
}

/// The end of a member's line, which either carries the result or erases
/// the counter field.
///
/// `reserved` is [`opening`]'s: with the field there the cursor walks back
/// over it, and without it (`-idp`) there is nothing to walk back over.
pub(crate) fn ending(ending: Ending, reserved: bool) -> String {
    match (ending, reserved) {
        // Five back: over the four column field and one more, which is
        // where the reference puts the two spaces of the result.
        (Ending::Done, true) => "\u{8}\u{8}\u{8}\u{8}\u{8}  OK \n".to_owned(),
        (Ending::Done, false) => "  OK \n".to_owned(),
        // Four back and four spaces: the width of the counter field,
        // erased, because the result lands on the volume the member ends
        // in and not on this one.
        (Ending::Continues, true) => "\u{8}\u{8}\u{8}\u{8}    \n".to_owned(),
        (Ending::Continues, false) => "    \n".to_owned(),
    }
}

/// `-rr[N]`'s own line, which the reference prints once the members are
/// written and the parity block goes in.
///
/// Measured: the label is padded to column 36 and then redrawn once per
/// recovery BLOCK - nineteen times for a 5% record over an 18 kB archive,
/// at 5, 10, 15, 21, 26 and so on, which is `block / 19`. That count is a
/// function of the reference's own recovery geometry and nothing outside
/// the binary predicts it, so this crate draws the counter ONCE, at the
/// end, and the difference is reported in the crate README rather than
/// guessed at: a row that passed by matching a redraw count somebody
/// reverse-engineered would be passing for the wrong reason.
pub(crate) fn recovery_record() -> String {
    const RECOVERY_COLUMN: usize = 36;
    let mut line = String::from("Adding the data recovery record");
    for _ in line.len()..RECOVERY_COLUMN {
        line.push(' ');
    }
    line.push_str(&counter(100));
    line.push('\n');
    line
}

/// `-df`'s own line, which is a different layout again: the name is padded
/// to column 43 and the counter that follows counts FILES, not bytes, and
/// is never redrawn.
///
/// Measured: `Deleting rand.bin` padded, then `deleted  50%`, 55 bytes in
/// all for a two digit percentage.
pub(crate) fn deleted(name: &str, percent: u64) -> String {
    const DELETE_COLUMN: usize = 43;
    let name = &on_this_host(name);
    let mut line = String::from("Deleting ");
    line.push_str(name);
    let width = "Deleting ".len() + name.chars().count();
    for _ in width..DELETE_COLUMN {
        line.push(' ');
    }
    line.push_str(&format!("deleted {percent:3}%\n"));
    line
}

/// `Deleting directory <name>` and its verdict, which starts in the column
/// the file lines' `deleted` does not: 53.
pub(crate) fn deleted_directory(name: &str, percent: u64, gone: bool) -> String {
    const VERDICT_COLUMN: usize = 53;
    let name = &on_this_host(name);
    let mut line = String::from("Deleting directory ");
    line.push_str(name);
    let width = "Deleting directory ".len() + name.chars().count();
    for _ in width..VERDICT_COLUMN {
        line.push(' ');
    }
    let verdict = if gone { "deleted" } else { "NOT DELETED" };
    line.push_str(&format!("{verdict} {percent:3}%\n"));
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_source_is_printed_with_the_hosts_own_separator() {
        assert_eq!(printed_with("data/sub/c.txt", true), "data\\sub\\c.txt");
        assert_eq!(printed_with("data/sub/c.txt", false), "data/sub/c.txt");
        assert_eq!(printed_with("b.txt", true), "b.txt");
        let line = deleted("data/b.txt", 100);
        if cfg!(windows) {
            assert!(line.starts_with("Deleting data\\b.txt "), "{line}");
        } else {
            assert!(line.starts_with("Deleting data/b.txt "), "{line}");
        }
    }

    #[test]
    fn a_counter_line_reaches_the_column_the_reference_reaches() {
        let line = opening(Verb::Adding, "text.txt", true);
        assert_eq!(line.len(), COUNTER_COLUMN);
        assert!(line.starts_with("Adding    text.txt "));
    }

    #[test]
    fn a_counterless_line_stops_one_column_short() {
        assert_eq!(opening(Verb::Adding, "text.txt", false).len(), 72);
    }

    #[test]
    fn the_counter_field_is_four_columns_whatever_the_number() {
        assert_eq!(counter(42), "\u{8}\u{8}\u{8}\u{8} 42%");
        assert_eq!(counter(100), "\u{8}\u{8}\u{8}\u{8}100%");
        assert_eq!(counter(0), "\u{8}\u{8}\u{8}\u{8}  0%");
    }

    #[test]
    fn a_deleted_line_is_the_length_the_reference_printed() {
        // `Deleting rand.bin` ... `deleted  50%`, 55 bytes with the
        // newline off.
        let line = deleted("rand.bin", 50);
        assert_eq!(line.trim_end_matches('\n').len(), 55);
        assert!(line.ends_with("deleted  50%\n"));
    }

    #[test]
    fn a_directory_line_puts_its_verdict_in_column_53() {
        let line = deleted_directory("small", 100, false);
        assert_eq!(line.find("NOT DELETED"), Some(53));
        assert!(line.ends_with("NOT DELETED 100%\n"));
        assert!(deleted_directory("small/in", 33, true).ends_with("deleted  33%\n"));
    }

    #[test]
    fn a_name_wider_than_the_field_is_not_truncated() {
        let wide = "x".repeat(80);
        assert!(opening(Verb::Adding, &wide, true).contains(&wide));
    }
}
