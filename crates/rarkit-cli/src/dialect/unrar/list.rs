//! The four listing layouts: `l`, `v`, `lt`/`vt`, `lb`/`vb`.
//!
//! Every width here was measured off the committed conformance tables
//! rather than counted off a manual, because the tables are what the gate
//! compares against and the reference's own header line does not line up
//! with its data rows (the literal `Ratio` in the header sits a column
//! left of the numbers under it). So the header and separator lines are
//! reproduced as literals and the data rows are formatted, which is what
//! the reference itself does.

use super::args::{ListStyle, Options};
use super::extract::Selection;
use super::{
    time, AttributeForm, Exit, Member, OpenFailure, Opened, Out, Tail, CORRUPT_HEADER,
    UNEXPECTED_END,
};

/// The `l` header and its rule, verbatim.
const PLAIN_HEADER: &str = " Attributes       Size     Date    Time   Name";
const PLAIN_RULE: &str = "----------- ----------  ---------- -----  ----";

/// The `v` header and its rule, verbatim.
const WIDE_HEADER: &str =
    " Attributes       Size     Packed Ratio    Date    Time   Checksum  Name";
const WIDE_RULE: &str = "----------- ---------- ---------- ----- ---------- -----  --------  ----";

/// Label column of the technical block, in characters before the colon.
const LABEL_WIDTH: usize = 12;

/// Renders a member's attributes the way its host writes them.
///
/// Which host takes which form is [`super::HostOs::attribute_form`]. Each
/// form was MEASURED on 10 Oct 2026 against `rar` and `unrar` 7.23 (macOS
/// arm64, `l` and `lt`, which agree on every row) over archives of
/// header-only members in both container families: 159 rows under the
/// RAR 5 hosts and 200 under the RAR 1.5 to 4.x host bytes 0 to 7, every
/// bit of the word alone and several together.
///
/// - The DOS word is seven positions, `ICADSHR`. A position shows its
///   letter when its bit is set and a point when it is not: `I` 0x2000,
///   `C` 0x800, `A` 0x20, `D` 0x10, `S` 0x04, `H` 0x02, `R` 0x01. No other
///   bit of the word prints anything, and the header's own directory flag
///   prints nothing either: a directory whose word lacks 0x10 has no `D`.
/// - The Unix form is ten positions. The first is `d` where the type
///   field (bits 12 to 15) is exactly 4, `l` where it is exactly 10 and
///   `-` for every other type; again the directory flag is not asked. Then
///   owner, group and other, each `r`, `w` and an execute position. Set
///   user and set group print `s` over an execute bit and `S` without
///   one; the sticky bit prints `t` over other's execute bit and NOTHING
///   without it (`-`, not `T`).
/// - A host the reference does not interpret prints a lone `?`.
pub(crate) fn attributes(member: &Member) -> String {
    let word = member.attr;
    let set = |bits: u64| word & bits == bits;
    match member.host.attribute_form() {
        AttributeForm::Unknown => "?".to_owned(),
        AttributeForm::Dos => {
            // The letters in column order, each with the number of its bit.
            let columns = "ICADSHR".chars().zip([13_u32, 11, 5, 4, 2, 1, 0]);
            columns
                .map(|(letter, bit)| if set(1 << bit) { letter } else { '.' })
                .collect()
        }
        AttributeForm::Mode => {
            let mut text = String::with_capacity(10);
            text.push(match (word >> 12) & 0xF {
                0o04 => 'd',
                0o12 => 'l',
                _ => '-',
            });
            // Owner, group, other: where the class's three bits start, the
            // extra bit that shares its execute position, and what that
            // extra bit prints with the execute bit and without it.
            let classes = [
                (6_u32, 0o4000_u64, 's', 'S'),
                (3, 0o2000, 's', 'S'),
                (0, 0o1000, 't', '-'),
            ];
            for (shift, extra, with_execute, alone) in classes {
                text.push(if set(0o4 << shift) { 'r' } else { '-' });
                text.push(if set(0o2 << shift) { 'w' } else { '-' });
                text.push(match (set(extra), set(0o1 << shift)) {
                    (true, true) => with_execute,
                    (true, false) => alone,
                    (false, true) => 'x',
                    (false, false) => '-',
                });
            }
            text
        }
    }
}

/// unrar's integer ratio: packed over unpacked, floored, and zero where
/// there is nothing to divide.
fn ratio(member: &Member) -> u64 {
    if member.size == 0 {
        return 0;
    }
    member.packed.saturating_mul(100) / member.size
}

/// `-md=` clauses are written in the largest unit that divides evenly,
/// which is how the reference spells `128k` and `1m`.
fn dictionary_clause(bytes: u64) -> String {
    if bytes >= 1 << 30 && bytes.is_multiple_of(1 << 30) {
        format!("{}g", bytes >> 30)
    } else if bytes >= 1 << 20 && bytes.is_multiple_of(1 << 20) {
        format!("{}m", bytes >> 20)
    } else {
        format!("{}k", bytes >> 10)
    }
}

/// The family word and the printed version number for a member's
/// `Compression:` clause, from its declared unpack version.
///
/// Measured against `unrar lt` 7.23 on one fixture of each format
/// generation (`fixtures/legacy/archives/{d140,d155,d250,r393,r420,
/// r550}_m0.rar` and `specs/vectors-H/archives/h5_x86_m5.rar`), and
/// pinned again by the library's own `the_algorithm_version_is_what_
/// each_family_stores` (`crates/rarkit/tests/read_api.rs`): RAR 5 keeps a
/// compression version, 0 or 1, and the reference prints it as `v50` or
/// `v70`, BOTH under the family "RAR 5.0" (measured on an M3 Mac, 27 Sep
/// 2026: `unrar lt` 7.23 prints `RAR 5.0(v70) -m1 -md=5g` for a member
/// `rar -md5g` wrote, the first version 1 archive rarkit opens); the
/// RAR 1.5 to 4.x family keeps its own unpack version and
/// the reference prints it exactly as stored, whatever sub-version a
/// member declares (`v13`/`v14`/`v15` for RAR 1.5, `v20`/`v26` for
/// RAR 2.0, `v29` and above for RAR 2.9, 3.x and 4.x); the RAR 1.3
/// container declares the constant 2 in every archive, and the
/// reference labels that CONTAINER `RAR 5.0(v13)` rather than
/// `RAR 1.5(v13)` or anything naming the field it actually stored.
fn compression_family(member: &Member) -> (&'static str, u32) {
    match member.algorithm_version {
        0 => ("RAR 5.0", 50),
        1 => ("RAR 5.0", 70),
        2 => ("RAR 5.0", 13),
        version => ("RAR 1.5", version),
    }
}

fn compression_clause(member: &Member) -> String {
    let (family, version) = compression_family(member);
    match member.dictionary {
        Some(bytes) => format!(
            "{family}(v{version}) -m{} -md={}",
            member.method,
            dictionary_clause(bytes)
        ),
        None => format!("{family}(v{version}) -m{}", member.method),
    }
}

fn cased(name: &str, opts: &Options) -> String {
    if opts.upper_case {
        name.to_uppercase()
    } else if opts.lower_case {
        name.to_lowercase()
    } else {
        name.to_owned()
    }
}

/// The date and time column of a member that stores no time, in the `l`
/// and `v` tables. MEASURED against unrar 7.23 on macOS arm64 and
/// UnRAR.exe 7.23 on Windows 11, 4 Oct 2026, over an archive made with
/// `rar a -tsm-`: until then the column was sixteen spaces here.
const NO_TIME: &str = "????-??-?? ??:??";

fn plain_row(member: &Member, opts: &Options) -> String {
    let marker = if member.encrypted { '*' } else { ' ' };
    let date = member.mtime.map_or_else(
        || NO_TIME.to_owned(),
        |at| time::short(at, member.wall_clock),
    );
    format!(
        "{marker}{:>10} {:>10}  {date}  {}",
        attributes(member),
        member.size,
        cased(&member.name, opts)
    )
}

fn wide_row(member: &Member, opts: &Options) -> String {
    let marker = if member.encrypted { '*' } else { ' ' };
    let date = member.mtime.map_or_else(
        || NO_TIME.to_owned(),
        |at| time::short(at, member.wall_clock),
    );
    let checksum = match member.crc32 {
        Some(crc) if !member.is_dir => format!("{crc:08X}"),
        _ => " ".repeat(8),
    };
    format!(
        "{marker}{:>10} {:>10} {:>10} {:>3}%  {date}  {checksum}  {}",
        attributes(member),
        member.size,
        member.packed,
        ratio(member),
        cased(&member.name, opts)
    )
}

/// The technical listing's label for the modification time, which follows
/// the PLATFORM the listing runs on and never the member's host.
///
/// `mtime` off Windows: `unrar lta` 7.23 on macOS printed it for every
/// host byte, 0 to 7 in RAR 1.5 to 4.x headers and 0, 1, 2 and 9 in RAR 5
/// ones, the RAR 5 time record stored both as Unix time and as a Windows
/// FILETIME (an M3 Mac, 26 Sep 2026). `Modified` on Windows: UnRAR 7.23
/// x64 on a Windows desktop printed it for DOS and Unix members alike, the
/// value in the same comma-and-nine-digits form (26 Sep 2026).
fn time_label(windows: bool) -> &'static str {
    if windows {
        "Modified"
    } else {
        "mtime"
    }
}

fn technical_block(member: &Member, opts: &Options) -> String {
    let label = |name: &str| format!("{name:>LABEL_WIDTH$}: ");
    let mut out = String::new();
    // A name the reference cannot print on this host takes its whole line
    // with it (`super::listed_name_into`).
    if member.printable {
        out.push_str(&format!("{}{}\n", label("Name"), cased(&member.name, opts)));
    }
    // A redirection member names its kind and its target, as stored
    // (spec F 3.2.6.2). An unknown kind the reference lists as a plain
    // file, and so does this; a RAR 4 family link's target is its content,
    // which a listing does not read, so it has no `Target:` line here
    // where the reference prints one (not done: a listing that decodes it).
    let redirect = member
        .redirect
        .as_ref()
        .filter(|r| !matches!(r.kind, rarkit::RedirectionKind::Unknown(_)));
    let kind = if member.is_service {
        "Service".into()
    } else if member.is_dir {
        "Directory".into()
    } else if let Some(r) = redirect {
        r.kind.listing_name()
    } else {
        "File".into()
    };
    out.push_str(&format!("{}{kind}\n", label("Type")));
    // The target is shown as a RAR 5 name is (`super::listed_name_into`),
    // its `\` kept whatever the host, and a target the reference cannot
    // print takes its line with it, as a name does. MEASURED against unrar
    // 7.23 on macOS (an M3 Mac) and Linux (a small x86-64 VPS), 28 Sep
    // 2026: `a\xffb`
    // lists `a`, an overlong `/` lists `/`, a surrogate `?` on Linux and no
    // `Target:` line on macOS, and a Windows link's `..\a` lists `..\a`.
    if let Some(target) = redirect.and_then(|r| r.target.as_deref()) {
        let mut shown = String::new();
        if super::listed_name_into(target, super::HostOs::Unix, true, &mut shown) {
            out.push_str(&format!("{}{shown}\n", label("Target")));
        }
    }
    if !member.is_dir {
        out.push_str(&format!("{}{}\n", label("Size"), member.size));
        out.push_str(&format!("{}{}\n", label("Packed size"), member.packed));
        out.push_str(&format!("{}{}%\n", label("Ratio"), ratio(member)));
    }
    if let Some(mtime) = member.mtime {
        out.push_str(&format!(
            "{}{}\n",
            label(time_label(cfg!(windows))),
            time::technical(mtime, member.mtime_nanos, member.wall_clock)
        ));
    }
    // A service header renders as `.B` on both platforms and for every
    // service the reference emits (CMT, QO and RR were all checked on 3
    // Sep 2026). The derivation is not known, so this is the measurement
    // rather than a formatting rule applied to the header's attributes.
    let attrs = if member.is_service {
        ".B".to_owned()
    } else {
        attributes(member)
    };
    out.push_str(&format!("{}{attrs}\n", label("Attributes")));
    // Whether a CRC32 line prints at all is `member.crc32`'s own job, not
    // is_dir's: the RAR 1.5 to 4.x family's header always carries the
    // field, 0 for a directory included, and the reference prints it
    // there too; RAR 5 only carries one where the header set it, which an
    // ordinary directory does not, so `member.crc32` reads `None` and
    // this simply has nothing to print - no format check needed. Measured
    // against `unrar lt` on fixtures/legacy/archives/{d155,d250}_m0.rar
    // (a directory entry, "CRC32: 00000000") and specs/vectors-G/archives
    // /r5_store.rar (a directory entry, no CRC32 line at all), 26 Sep
    // 2026.
    if let Some(crc) = member.crc32 {
        if !member.is_service {
            out.push_str(&format!("{}{crc:08X}\n", label("CRC32")));
        }
    }
    if let Some(host) = member.host.name() {
        out.push_str(&format!("{}{host}\n", label("Host OS")));
    }
    out.push_str(&format!(
        "{}{}\n",
        label("Compression"),
        compression_clause(member)
    ));
    if member.solid {
        out.push_str(&format!("{}solid\n", label("Flags")));
    }
    if let Some(number) = version_number(member) {
        out.push_str(&format!("{}{number}\n", label("File version")));
    }
    out
}

/// The number an older version of a file is listed with: the header's
/// own in RAR 5, and in the older container the digits after the last `;`
/// of the stored name, where there are any.
pub(super) fn version_number(member: &Member) -> Option<u64> {
    match member.version? {
        rarkit::FileVersion::Numbered(number) => Some(u64::from(number)),
        rarkit::FileVersion::InName => member.name.rsplit_once(';')?.1.parse().ok(),
    }
}

/// Runs `l`, `v`, `lt`, `lta`, `vt`, `vta`, `lb` or `vb`.
pub(crate) fn run(
    out: &Out,
    path: &str,
    opts: &Options,
    selection: &Selection,
    style: ListStyle,
) -> Exit {
    let password = opts.password.as_deref().map(str::as_bytes);
    let opened = match super::open_listing(path, password, opts.memory_cap) {
        Ok(opened) => opened,
        Err(OpenFailure::Missing(text)) => {
            // No trailing `\n` here: the reference never puts one on a
            // `Cannot open` line either (measured 28 Sep 2026, plain
            // `unrar l nosuch.rar`). `Out::close_dangling_stderr` is what
            // adds it back under `-idq`, and only for a command that is
            // not `lb`.
            out.warn(&text);
            // A listing that opened nothing lists no members, and the
            // reference reports that as "no files" rather than as an open
            // error. The `list-absent-archive` row is this line.
            return Exit::NothingMatched;
        }
        Err(OpenFailure::NotAnArchive(text)) => {
            out.say(&format!("{text}\n"));
            return Exit::Clean;
        }
        Err(failure @ OpenFailure::Damaged(tail)) => {
            out.warn(&format!("{}\n", failure.text()));
            return tail.exit();
        }
        Err(OpenFailure::OverBudget(text)) => {
            out.warn(&format!("{text}\n"));
            return Exit::Aborted;
        }
        Err(OpenFailure::BadPassword(text)) => {
            // The header is still printed: the reference knows the
            // archive is RAR 5 with encrypted headers before it knows the
            // password is wrong, and says so.
            if !style.bare {
                out.say(&format!(
                    "\nArchive: {path}\nDetails: {}\n  0 files\n",
                    super::sniffed_details(path)
                ));
            }
            // Same shape as `OpenFailure::Missing` above: no forced `\n`.
            out.warn(&text);
            return Exit::WrongPassword;
        }
    };

    if opts.all_volumes && opened.is_volume {
        return every_volume(out, path, opts, selection, style, opened);
    }
    let (listed, _) = listing(out, path, opts, selection, style, &opened, Part::Whole);
    settle(out, style, &opened, listed)
}

/// What a listing says and returns once its table is out: the lines of a
/// header read although damaged, and the line and code of a walk that
/// stopped short.
fn settle(out: &Out, style: ListStyle, opened: &Opened, mut listed: Exit) -> Exit {
    // A header read although its checksum failed: every member is listed,
    // the one behind it included, the reference's lines for it go to
    // stderr and the listing exits 3 (`DamagedHeader`; unrar 7.23, 8 Oct
    // 2026, `l` and `lb`).
    for header in &opened.damaged {
        for line in &header.lines {
            if out.one_stream() && !style.bare {
                out.warn(&format!("{line}\n"));
            } else {
                out.warn(&format!("\n{line}"));
            }
        }
        listed = listed.worse_of(Exit::ChecksumMismatch);
    }
    // A cut or damaged archive still LISTS, at the reference and here: the
    // members in front of the damage are all there (spec F 4.6). What it
    // also does is say so once on stderr and finish with the damage's own
    // code rather than with success, even though the listing of what is
    // there is complete. Measured against unrar 7.23 on 27 Sep 2026 for
    // `l`, `lb` and `lt`: a cut exits 1 and a header the walk cannot pass
    // exits 3.
    //
    // On ONE stream (`-ierr`) the line is said where the walk stopped and
    // ends itself: `l` and `v` put it between the last member and the
    // closing rule (`listing` says it there), `lt` after its last block;
    // `lb` keeps the layout it has apart (measured 30 Sep 2026).
    let Some(tail) = opened.tail else {
        return listed;
    };
    let text = tail_text(tail);
    if !(out.one_stream() && tail_said_in_listing(style)) {
        if out.one_stream() && !style.bare {
            out.warn(&format!("{}\n", text.trim_start_matches('\n')));
        } else {
            out.warn(text);
        }
    }
    listed.worse_of(match tail {
        Tail::Truncated => Exit::Cautioned,
        Tail::CorruptHeader => Exit::ChecksumMismatch,
    })
}

/// `-v` on a volume of a set: that volume and every one after it, each
/// listed as an archive of its own, as unrar 7.23 lists them (measured
/// 24 Oct 2026, `tests/list_all_volumes.rs` has the shapes).
///
/// The set is walked as `x` and `t` walk it ([`super::extract::volume_chain`]),
/// from the volume named: a later one named lists from there on, and the
/// walk does not start over at the first. Each volume's table shows every
/// fragment it holds ([`Part::Volume`]); `l` and `v` close the set on one
/// more totals row ([`set_totals`]) when more than one volume was listed.
/// A volume the set needs and the disk lacks is said once the volumes in
/// hand are listed, and the run exits 6, as the reference's does. A volume
/// that is there and is no RAR archive at all ends the listing as the
/// reference ends it (unrar 7.23, macOS arm64, 27 Oct 2026, a four part
/// set whose second part is plain text): the volumes before it listed,
/// then `ERROR: Bad archive <name>` on stderr, `Program aborted` on
/// stdout, exit 13; until then this said nothing and exited 0. One that
/// is a RAR and does not parse is not measured: the walk ends at it, as
/// `x`'s does, and says nothing more.
fn every_volume(
    out: &Out,
    path: &str,
    opts: &Options,
    selection: &Selection,
    style: ListStyle,
    first: Opened,
) -> Exit {
    let password = opts.password.as_deref().map(str::as_bytes);
    let mut session =
        rarkit::Session::new(crate::engine::read_options_named(password, opts.memory_cap));
    let chain = super::extract::volume_chain(path, &first, &mut session);
    let volumes: Vec<Opened> = std::iter::once(first).chain(chain.later).collect();
    let alone = volumes.len() == 1;
    let mut listed = Exit::Clean;
    let mut set = Totals::default();
    for (index, (name, volume)) in chain.names.iter().zip(&volumes).enumerate() {
        let part = Part::Volume {
            closing: if style.technical {
                index + 1 == volumes.len()
            } else {
                alone
            },
        };
        let (exit, totals) = listing(out, name, opts, selection, style, volume, part);
        listed = listed.worse_of(settle(out, style, volume, exit));
        set.add(totals);
    }
    if !alone && !style.bare && !style.technical {
        out.say(&set_totals(set, style));
    }
    if let Some(name) = chain.missing {
        out.warn(&format!("\nCannot find volume {name}"));
        listed = listed.worse_of(Exit::CannotOpen);
    }
    if let Some(name) = chain.not_rar {
        out.warn(&format!("\nERROR: Bad archive {name}\n"));
        // The listing's own closing blank line stands before it.
        out.abort();
        listed = listed.worse_of(Exit::NotAnArchive);
    }
    listed
}

/// Which members a listing's table shows, and how it ends.
#[derive(Clone, Copy)]
enum Part {
    /// One archive, or one volume without `-v`: a member split across
    /// volumes is listed once, where it starts, and the listing ends on
    /// its closing blank line.
    Whole,
    /// One volume of a set under `-v`: every fragment the volume holds is
    /// a row, continued ones included, though only a member that STARTS
    /// here counts towards the size and the count; `closing` is whether
    /// the closing blank line follows (`every_volume` says when).
    Volume { closing: bool },
}

/// A table's totals: the size and count of the members that start in it,
/// and the packed size of every row.
#[derive(Clone, Copy, Default)]
struct Totals {
    size: u64,
    packed: u64,
    count: usize,
}

impl Totals {
    /// Adds one row. The sums wrap, as [`listing`] says.
    fn row(&mut self, member: &Member) {
        self.packed = self.packed.wrapping_add(member.packed);
        if !member.split_before {
            self.size = self.size.wrapping_add(member.size);
            self.count += 1;
        }
    }

    fn add(&mut self, other: Self) {
        self.size = self.size.wrapping_add(other.size);
        self.packed = self.packed.wrapping_add(other.packed);
        self.count += other.count;
    }

    /// The packed sum as a percentage of the size, floored, and 0 over
    /// nothing. What the reference prints beside a total that wrapped is
    /// not measured.
    fn ratio(self) -> u64 {
        self.packed
            .saturating_mul(100)
            .checked_div(self.size)
            .unwrap_or(0)
    }
}

/// The set's totals row under `-v`, after the last volume's own: every
/// member's size, every fragment's packed size and the count of members.
///
/// Measured against unrar 7.23, 24 Oct 2026: the row is a volume's totals
/// row a column further left (the size ends at column 21, not 22) and in
/// `v` the packed size a column nearer it again (ending at 31, not 33), so
/// the rest of the row sits two columns left of a volume's. No blank line
/// follows it. Only sizes of up to six digits and packed sizes of up to
/// six were measured; the widths given here are the narrowest that agree.
fn set_totals(set: Totals, style: ListStyle) -> String {
    let ratio = set.ratio();
    let (size, packed, count) = (set.size.cast_signed(), set.packed.cast_signed(), set.count);
    if style.verbose {
        format!(
            "{size:>21} {packed:>9} {ratio:>3}%  {:10} {:5}  {:8}  {count}\n",
            "", "", ""
        )
    } else {
        format!("{size:>21}  {:10} {:5}  {count}\n", "", "")
    }
}

/// The reference's line for where a walk stopped.
fn tail_text(tail: Tail) -> &'static str {
    match tail {
        Tail::Truncated => UNEXPECTED_END,
        Tail::CorruptHeader => CORRUPT_HEADER,
    }
}

/// Whether `listing` says a tail's line itself on one stream: `l` and `v`,
/// between the last member and the closing rule.
fn tail_said_in_listing(style: ListStyle) -> bool {
    !style.bare && !style.technical
}

/// The archive comment block a listing prints before its `Archive:`
/// header, or `None` when there is nothing to print.
///
/// Measured against rar 7.23 and unrar 7.23 on a Mac, 17 Sep 2026,
/// and the two dialects agree line for line, so this serves both. The
/// block is:
///
/// ```text
/// <blank>
/// Archive comment:
/// <the comment's bytes, verbatim>
/// <blank>
/// ```
///
/// The trailing blank is THIS block's, not the `Archive:` header's, and
/// the comment's bytes are emitted exactly as stored with a single `\n`
/// after them. That is what reproduces both shapes from one rule: a
/// comment ending in a newline lists with TWO blank lines before
/// `Archive:` (its own, then this one) and a comment without a trailing
/// newline lists with one. A builder that trimmed or normalised the end
/// would have to choose, and would be wrong for one of them.
///
/// `l`, `v`, `lt` and `lta` all print it, in both dialects; `lb` and `vb`
/// print it in neither, which needs no test here because a bare listing
/// returns before this is reached.
fn archive_comment_block(opts: &Options, comment: Option<&[u8]>) -> Option<String> {
    // `-c-` and `-idc` both mean "do not show comments", and the parser
    // folds them into the one flag.
    if opts.hide_comments {
        return None;
    }
    let comment = comment.filter(|bytes| !bytes.is_empty())?;
    Some(format!(
        "\nArchive comment:\n{}\n",
        super::comment_text(comment)
    ))
}

/// The listing itself, once the archive is open.
fn listing(
    out: &Out,
    path: &str,
    opts: &Options,
    selection: &Selection,
    style: ListStyle,
    opened: &Opened,
    part: Part,
) -> (Exit, Totals) {
    let (fragments, closing) = match part {
        Part::Whole => (false, true),
        Part::Volume { closing } => (true, closing),
    };
    let shown: Vec<&Member> = opened
        .members
        .iter()
        .filter(|member| !member.is_service || style.technical_all)
        .filter(|member| member.is_service || selection.keeps(member))
        // A member split across volumes is listed once, where it starts,
        // but under `-v` each volume shows its own fragment (`Part`).
        .filter(|member| fragments || !member.split_before)
        .collect();
    let mut totals = Totals::default();

    // `-idn` hides the per-member output of every layout. Measured against
    // `unrar` 7.23 on 19 Sep 2026: `l` and `v` keep both header lines and
    // the totals and lose the member rows and the closing rule, `lt` loses
    // its file blocks (a service block under `lta` stays), and `lb` has
    // nothing left to print. `-idd` and `-idp` change no listing.
    let names = !opts.hide_names;

    if style.bare {
        // A name the reference cannot print leaves no line, not an empty
        // one (`super::listed_name_into`).
        for member in shown.iter().filter(|m| names && m.printable) {
            out.say(&format!("{}\n", cased(&member.name, opts)));
        }
        return (Exit::Clean, totals);
    }

    if let Some(block) = archive_comment_block(opts, opened.archive_comment().as_deref()) {
        out.say(&block);
    }
    out.say(&format!("\nArchive: {path}\nDetails: {}\n", opened.details));

    if shown.is_empty() {
        out.say("  0 files\n");
        return (Exit::Clean, totals);
    }

    if style.technical {
        for member in shown.iter().filter(|member| names || member.is_service) {
            out.say(&format!("\n{}", technical_block(member, opts)));
        }
        if style.technical_all {
            // The end-of-archive record, which the reference shows as a
            // service with no fields of its own.
            out.say(&format!("\n{:>LABEL_WIDTH$}: EOF\n", "Service"));
        }
        // The reference ends `lt` on one more blank line than its last
        // block already carries: measured against `rar`/`unrar` 7.23 on
        // 20 Sep 2026 (README section 8). The `0 files` case above is
        // unmeasured and does not get one. Under `-v` only the last
        // volume does (24 Oct 2026).
        if closing {
            out.say("\n");
        }
        return (Exit::Clean, totals);
    }

    let (header, rule) = if style.verbose {
        (WIDE_HEADER, WIDE_RULE)
    } else {
        (PLAIN_HEADER, PLAIN_RULE)
    };
    out.say(&format!("\n{header}\n{rule}\n"));
    // The sizes are the archive's word, so their sums wrap, in 64 bits,
    // and are shown SIGNED, as the reference's are (measured, unrar 7.23,
    // 4 Oct 2026: two members declaring 2^63 - 1 total `-2`;
    // `tests/list_totals_wrap.rs`). Unchecked, the sum was a panic in a
    // checked build.
    for member in &shown {
        totals.row(member);
        if !names {
            continue;
        }
        let row = if style.verbose {
            wide_row(member, opts)
        } else {
            plain_row(member, opts)
        };
        out.say(&format!("{row}\n"));
    }
    if let Some(tail) = opened.tail.filter(|_| out.one_stream()) {
        out.warn(&format!("{}\n", tail_text(tail).trim_start_matches('\n')));
    }
    if names {
        out.say(&format!("{rule}\n"));
    }
    // The ratio is of the sums as counted (`Totals::ratio`).
    let total_ratio = totals.ratio();
    let (total_size, total_packed, count) = (
        totals.size.cast_signed(),
        totals.packed.cast_signed(),
        totals.count,
    );
    if style.verbose {
        out.say(&format!(
            "{:11} {total_size:>10} {total_packed:>10} {total_ratio:>3}%  {:10} {:5}  {:8}  {count}\n",
            "", "", "", ""
        ));
    } else {
        out.say(&format!(
            "{:11} {total_size:>10}  {:10} {:5}  {count}\n",
            "", "", ""
        ));
    }
    // The reference ends `l` and `v` on one more blank line than the
    // totals row already carries: measured against `rar`/`unrar` 7.23 on
    // 20 Sep 2026 (README section 8). The `0 files` case above is
    // unmeasured and does not get one. Under `-v` a set of more than one
    // volume ends on its own totals row instead (`set_totals`).
    if closing {
        out.say("\n");
    }
    (Exit::Clean, totals)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dialect::unrar::HostOs;

    fn unix_file(name: &str, size: u64, packed: u64, mode: u64) -> Member {
        let is_dir = mode & 0xF000 == 0x4000;
        Member {
            name: crate::dialect::unrar::Name::from(name),
            disk: None,
            printable: true,
            is_dir,
            is_service: false,
            size,
            packed,
            mtime: Some(1_000_000_000),
            mtime_nanos: 0,
            wall_clock: false,
            attr: mode,
            host: HostOs::Unix,
            // An ordinary RAR 5 directory's header carries no CRC32 field
            // at all (it is conditional on a file flag a directory does
            // not set), matching `member_of`'s own `None` for one; a file
            // always sets it.
            crc32: (!is_dir).then_some(0x3D50_D04A),
            encrypted: false,
            password_checked: false,
            version: None,
            split_before: false,
            split_after: false,
            algorithm_version: 0,
            method: 0,
            // A directory carries no dictionary, the way the RAR 5
            // reader builds one, and the technical block prints its
            // compression clause without a `-md=` because of it.
            dictionary: (!is_dir).then_some(128 * 1024),
            solid: false,
            unknown_version: false,
            data_end: 0,
            redirect: None,
        }
    }

    #[test]
    fn a_plain_row_is_the_width_the_rule_under_it_promises() {
        let row = plain_row(
            &unix_file("text.txt", 18400, 18400, 0o100_644),
            &Options::default(),
        );
        assert_eq!(&row[..11], " -rw-r--r--");
        assert!(row.ends_with("  text.txt"));
        // Attributes(11) + size(11) + two spaces + a 16-character stamp
        // + two spaces, before the name.
        assert_eq!(row.len(), 11 + 11 + 2 + 16 + 2 + "text.txt".len());
    }

    #[test]
    fn a_directory_row_takes_the_d_and_the_mode_bits() {
        let row = plain_row(&unix_file("sub", 0, 0, 0o040_755), &Options::default());
        assert!(row.starts_with(" drwxr-xr-x"), "got {row}");
    }

    #[test]
    fn an_encrypted_member_replaces_the_leading_space_with_a_star() {
        let mut member = unix_file("text.txt", 18400, 18400, 0o100_644);
        member.encrypted = true;
        assert!(plain_row(&member, &Options::default()).starts_with("*-rw-r--r--"));
    }

    #[test]
    fn the_windows_attribute_string_puts_a_and_d_where_the_capture_did() {
        let mut member = unix_file("text.txt", 1, 1, 0x20);
        member.host = HostOs::Windows;
        assert_eq!(attributes(&member), "..A....");
        member.attr = 0x10;
        assert_eq!(attributes(&member), "...D...");
    }

    /// Every row of the 10 Oct 2026 measurement, as the doc comment of
    /// [`attributes`] describes it. The directory flag is carried into the
    /// member because the measurement varied it; no row turns on it. No
    /// pool, no memory.
    #[test]
    fn every_measured_attribute_word_prints_as_the_reference_printed_it() {
        let column = |host: HostOs, word: u64, is_dir: bool| {
            let mut member = unix_file("m", 0, 0, word);
            member.host = host;
            member.is_dir = is_dir;
            attributes(&member)
        };
        for &(host, word, is_dir, text) in MEASURED_RAR5 {
            assert_eq!(column(host, word, is_dir), text, "{host:?} {word:#x}");
        }
        for host in [HostOs::MsDos, HostOs::Os2, HostOs::Windows, HostOs::MacOs] {
            for &(word, is_dir, text) in MEASURED_OLD_DOS {
                assert_eq!(column(host, word, is_dir), text, "{host:?} {word:#x}");
            }
        }
        for host in [HostOs::Unix, HostOs::BeOs] {
            for &(word, is_dir, text) in MEASURED_OLD_MODE {
                assert_eq!(column(host, word, is_dir), text, "{host:?} {word:#x}");
            }
        }
        for host in [HostOs::WinCe, HostOs::Other(7)] {
            for &(word, is_dir) in MEASURED_OLD_UNKNOWN {
                assert_eq!(column(host, word, is_dir), "?", "{host:?} {word:#x}");
            }
        }
    }

    /// (host, attribute word, directory flag, the column).
    const MEASURED_RAR5: &[(HostOs, u64, bool, &str)] = &[
        (HostOs::Windows, 0x0, false, "......."),
        (HostOs::Windows, 0x1, false, "......R"),
        (HostOs::Windows, 0x2, false, ".....H."),
        (HostOs::Windows, 0x4, false, "....S.."),
        (HostOs::Windows, 0x8, false, "......."),
        (HostOs::Windows, 0x10, false, "...D..."),
        (HostOs::Windows, 0x20, false, "..A...."),
        (HostOs::Windows, 0x40, false, "......."),
        (HostOs::Windows, 0x80, false, "......."),
        (HostOs::Windows, 0x100, false, "......."),
        (HostOs::Windows, 0x200, false, "......."),
        (HostOs::Windows, 0x400, false, "......."),
        (HostOs::Windows, 0x800, false, ".C....."),
        (HostOs::Windows, 0x1000, false, "......."),
        (HostOs::Windows, 0x2000, false, "I......"),
        (HostOs::Windows, 0x4000, false, "......."),
        (HostOs::Windows, 0x8000, false, "......."),
        (HostOs::Windows, 0x1_0000, false, "......."),
        (HostOs::Windows, 0x2_0000, false, "......."),
        (HostOs::Windows, 0x4_0000, false, "......."),
        (HostOs::Windows, 0x8_0000, false, "......."),
        (HostOs::Windows, 0x10_0000, false, "......."),
        (HostOs::Windows, 0x20_0000, false, "......."),
        (HostOs::Windows, 0x40_0000, false, "......."),
        (HostOs::Windows, 0x80_0000, false, "......."),
        (HostOs::Windows, 0x100_0000, false, "......."),
        (HostOs::Windows, 0x200_0000, false, "......."),
        (HostOs::Windows, 0x400_0000, false, "......."),
        (HostOs::Windows, 0x800_0000, false, "......."),
        (HostOs::Windows, 0x1000_0000, false, "......."),
        (HostOs::Windows, 0x2000_0000, false, "......."),
        (HostOs::Windows, 0x4000_0000, false, "......."),
        (HostOs::Windows, 0x8000_0000, false, "......."),
        (HostOs::Windows, 0x1_0000_0000, false, "......."),
        (HostOs::Windows, 0x2_0000_0000, false, "......."),
        (HostOs::Windows, 0x4_0000_0000, false, "......."),
        (HostOs::Windows, 0x8_0000_0000, false, "......."),
        (HostOs::Windows, 0x10_0000_0000, false, "......."),
        (HostOs::Windows, 0x20_0000_0000, false, "......."),
        (HostOs::Windows, 0x40_0000_0000, false, "......."),
        (HostOs::Windows, 0x80_0000_0000, false, "......."),
        (HostOs::Windows, 0x7F, false, "..ADSHR"),
        (HostOs::Windows, 0xFF, false, "..ADSHR"),
        (HostOs::Windows, 0xFFFF_FFFF, false, "ICADSHR"),
        (HostOs::Windows, 0xFFFF, false, "ICADSHR"),
        (HostOs::Windows, 0x21, false, "..A...R"),
        (HostOs::Windows, 0x22, false, "..A..H."),
        (HostOs::Windows, 0x24, false, "..A.S.."),
        (HostOs::Windows, 0x27, false, "..A.SHR"),
        (HostOs::Windows, 0x30, false, "..AD..."),
        (HostOs::Windows, 0x11, false, "...D..R"),
        (HostOs::Windows, 0x12, false, "...D.H."),
        (HostOs::Windows, 0x16, false, "...DSH."),
        (HostOs::Windows, 0x31, false, "..AD..R"),
        (HostOs::Windows, 0x37, false, "..ADSHR"),
        (HostOs::Windows, 0x3F, false, "..ADSHR"),
        (HostOs::Windows, 0x820, false, ".CA...."),
        (HostOs::Windows, 0x2020, false, "I.A...."),
        (HostOs::Windows, 0x4020, false, "..A...."),
        (HostOs::Windows, 0x120, false, "..A...."),
        (HostOs::Windows, 0x220, false, "..A...."),
        (HostOs::Windows, 0x420, false, "..A...."),
        (HostOs::Windows, 0x60, false, "..A...."),
        (HostOs::Windows, 0xA0, false, "..A...."),
        (HostOs::Windows, 0x28, false, "..A...."),
        (HostOs::Windows, 0x8, false, "......."),
        (HostOs::Windows, 0x18, false, "...D..."),
        (HostOs::Windows, 0x0, true, "......."),
        (HostOs::Windows, 0x20, true, "..A...."),
        (HostOs::Windows, 0x10, true, "...D..."),
        (HostOs::Windows, 0x10, false, "...D..."),
        (HostOs::Unix, 0o0, false, "----------"),
        (HostOs::Unix, 0o1, false, "---------x"),
        (HostOs::Unix, 0o2, false, "--------w-"),
        (HostOs::Unix, 0o4, false, "-------r--"),
        (HostOs::Unix, 0o10, false, "------x---"),
        (HostOs::Unix, 0o20, false, "-----w----"),
        (HostOs::Unix, 0o40, false, "----r-----"),
        (HostOs::Unix, 0o100, false, "---x------"),
        (HostOs::Unix, 0o200, false, "--w-------"),
        (HostOs::Unix, 0o400, false, "-r--------"),
        (HostOs::Unix, 0o1000, false, "----------"),
        (HostOs::Unix, 0o2000, false, "------S---"),
        (HostOs::Unix, 0o4000, false, "---S------"),
        (HostOs::Unix, 0o10000, false, "----------"),
        (HostOs::Unix, 0o20000, false, "----------"),
        (HostOs::Unix, 0o40000, false, "d---------"),
        (HostOs::Unix, 0o100000, false, "----------"),
        (HostOs::Unix, 0o644, false, "-rw-r--r--"),
        (HostOs::Unix, 0o7777, false, "-rwsrwsrwt"),
        (HostOs::Unix, 0o7666, false, "-rwSrwSrw-"),
        (HostOs::Unix, 0o10644, false, "-rw-r--r--"),
        (HostOs::Unix, 0o17777, false, "-rwsrwsrwt"),
        (HostOs::Unix, 0o17666, false, "-rwSrwSrw-"),
        (HostOs::Unix, 0o20644, false, "-rw-r--r--"),
        (HostOs::Unix, 0o27777, false, "-rwsrwsrwt"),
        (HostOs::Unix, 0o27666, false, "-rwSrwSrw-"),
        (HostOs::Unix, 0o30644, false, "-rw-r--r--"),
        (HostOs::Unix, 0o37777, false, "-rwsrwsrwt"),
        (HostOs::Unix, 0o37666, false, "-rwSrwSrw-"),
        (HostOs::Unix, 0o40644, false, "drw-r--r--"),
        (HostOs::Unix, 0o47777, false, "drwsrwsrwt"),
        (HostOs::Unix, 0o47666, false, "drwSrwSrw-"),
        (HostOs::Unix, 0o50644, false, "-rw-r--r--"),
        (HostOs::Unix, 0o57777, false, "-rwsrwsrwt"),
        (HostOs::Unix, 0o57666, false, "-rwSrwSrw-"),
        (HostOs::Unix, 0o60644, false, "-rw-r--r--"),
        (HostOs::Unix, 0o67777, false, "-rwsrwsrwt"),
        (HostOs::Unix, 0o67666, false, "-rwSrwSrw-"),
        (HostOs::Unix, 0o70644, false, "-rw-r--r--"),
        (HostOs::Unix, 0o77777, false, "-rwsrwsrwt"),
        (HostOs::Unix, 0o77666, false, "-rwSrwSrw-"),
        (HostOs::Unix, 0o100644, false, "-rw-r--r--"),
        (HostOs::Unix, 0o107777, false, "-rwsrwsrwt"),
        (HostOs::Unix, 0o107666, false, "-rwSrwSrw-"),
        (HostOs::Unix, 0o110644, false, "-rw-r--r--"),
        (HostOs::Unix, 0o117777, false, "-rwsrwsrwt"),
        (HostOs::Unix, 0o117666, false, "-rwSrwSrw-"),
        (HostOs::Unix, 0o120644, false, "lrw-r--r--"),
        (HostOs::Unix, 0o127777, false, "lrwsrwsrwt"),
        (HostOs::Unix, 0o127666, false, "lrwSrwSrw-"),
        (HostOs::Unix, 0o130644, false, "-rw-r--r--"),
        (HostOs::Unix, 0o137777, false, "-rwsrwsrwt"),
        (HostOs::Unix, 0o137666, false, "-rwSrwSrw-"),
        (HostOs::Unix, 0o140644, false, "-rw-r--r--"),
        (HostOs::Unix, 0o147777, false, "-rwsrwsrwt"),
        (HostOs::Unix, 0o147666, false, "-rwSrwSrw-"),
        (HostOs::Unix, 0o150644, false, "-rw-r--r--"),
        (HostOs::Unix, 0o157777, false, "-rwsrwsrwt"),
        (HostOs::Unix, 0o157666, false, "-rwSrwSrw-"),
        (HostOs::Unix, 0o160644, false, "-rw-r--r--"),
        (HostOs::Unix, 0o167777, false, "-rwsrwsrwt"),
        (HostOs::Unix, 0o167666, false, "-rwSrwSrw-"),
        (HostOs::Unix, 0o170644, false, "-rw-r--r--"),
        (HostOs::Unix, 0o177777, false, "-rwsrwsrwt"),
        (HostOs::Unix, 0o177666, false, "-rwSrwSrw-"),
        (HostOs::Unix, 0o104755, false, "-rwsr-xr-x"),
        (HostOs::Unix, 0o102755, false, "-rwxr-sr-x"),
        (HostOs::Unix, 0o101755, false, "-rwxr-xr-t"),
        (HostOs::Unix, 0o104644, false, "-rwSr--r--"),
        (HostOs::Unix, 0o102644, false, "-rw-r-Sr--"),
        (HostOs::Unix, 0o101644, false, "-rw-r--r--"),
        (HostOs::Unix, 0o100111, false, "---x--x--x"),
        (HostOs::Unix, 0o100222, false, "--w--w--w-"),
        (HostOs::Unix, 0o100444, false, "-r--r--r--"),
        (HostOs::Unix, 0o106755, false, "-rwsr-sr-x"),
        (HostOs::Unix, 0o107000, false, "---S--S---"),
        (HostOs::Unix, 0o100000, false, "----------"),
        (HostOs::Unix, 0o777, false, "-rwxrwxrwx"),
        (HostOs::Unix, 0o1777, false, "-rwxrwxrwt"),
        (HostOs::Unix, 0o300644, false, "-rw-r--r--"),
        (HostOs::Unix, 0o37777777777, false, "-rwsrwsrwt"),
        (HostOs::Unix, 0o120777, false, "lrwxrwxrwx"),
        (HostOs::Unix, 0o40755, false, "drwxr-xr-x"),
        (HostOs::Unix, 0o100644, true, "-rw-r--r--"),
        (HostOs::Unix, 0o0, true, "----------"),
        (HostOs::Unix, 0o40755, false, "drwxr-xr-x"),
        (HostOs::Other(2), 0x20, false, "?"),
        (HostOs::Other(9), 0x20, false, "?"),
    ];

    /// (attribute word, directory flag, the column) under hosts 0, 1, 2 and 4.
    const MEASURED_OLD_DOS: &[(u64, bool, &str)] = &[
        (0x0, false, "......."),
        (0x20, false, "..A...."),
        (0x10, false, "...D..."),
        (0x1, false, "......R"),
        (0x2, false, ".....H."),
        (0x4, false, "....S.."),
        (0x8, false, "......."),
        (0x40, false, "......."),
        (0x80, false, "......."),
        (0x100, false, "......."),
        (0x200, false, "......."),
        (0x400, false, "......."),
        (0x800, false, ".C....."),
        (0x1000, false, "......."),
        (0x2000, false, "I......"),
        (0x4000, false, "......."),
        (0x8000, false, "......."),
        (0x1_0000, false, "......."),
        (0x3F, false, "..ADSHR"),
        (0xFFFF, false, "ICADSHR"),
        (0xFFFF_FFFF, false, "ICADSHR"),
        (0x81A4, false, "..A.S.."),
        (0x41ED, false, "..A.S.R"),
        (0x0, true, "......."),
        (0x20, true, "..A...."),
    ];

    /// (attribute word, directory flag, the column) under hosts 3 and 5.
    const MEASURED_OLD_MODE: &[(u64, bool, &str)] = &[
        (0x0, false, "----------"),
        (0x20, false, "----r-----"),
        (0x10, false, "-----w----"),
        (0x1, false, "---------x"),
        (0x2, false, "--------w-"),
        (0x4, false, "-------r--"),
        (0x8, false, "------x---"),
        (0x40, false, "---x------"),
        (0x80, false, "--w-------"),
        (0x100, false, "-r--------"),
        (0x200, false, "----------"),
        (0x400, false, "------S---"),
        (0x800, false, "---S------"),
        (0x1000, false, "----------"),
        (0x2000, false, "----------"),
        (0x4000, false, "d---------"),
        (0x8000, false, "----------"),
        (0x1_0000, false, "----------"),
        (0x3F, false, "----rwxrwx"),
        (0xFFFF, false, "-rwsrwsrwt"),
        (0xFFFF_FFFF, false, "-rwsrwsrwt"),
        (0x81A4, false, "-rw-r--r--"),
        (0x41ED, false, "drwxr-xr-x"),
        (0x0, true, "----------"),
        (0x20, true, "----r-----"),
    ];

    /// (attribute word, directory flag) under hosts 6 and 7: a lone `?`.
    const MEASURED_OLD_UNKNOWN: &[(u64, bool)] = &[
        (0x0, false),
        (0x20, false),
        (0x10, false),
        (0x1, false),
        (0x2, false),
        (0x4, false),
        (0x8, false),
        (0x40, false),
        (0x80, false),
        (0x100, false),
        (0x200, false),
        (0x400, false),
        (0x800, false),
        (0x1000, false),
        (0x2000, false),
        (0x4000, false),
        (0x8000, false),
        (0x1_0000, false),
        (0x3F, false),
        (0xFFFF, false),
        (0xFFFF_FFFF, false),
        (0x81A4, false),
        (0x41ED, false),
        (0x0, true),
        (0x20, true),
    ];

    /// The technical block of an `..A....` file (DOS attribute 0x20,
    /// which is `----r-----` read as mode bits) under `host`.
    fn block_under(host: HostOs) -> String {
        let mut member = unix_file("text.txt", 1, 1, 0x20);
        member.host = host;
        member.algorithm_version = 20;
        technical_block(&member, &Options::default())
    }

    /// One row per host `unrar lta` 7.23 was run over, 26 Sep 2026: the
    /// committed DOS fixtures (`d155_m0`, `d250_m0`), the Unix ones
    /// (`r393`, `r420`, `r550`, every spec vector), and copies of
    /// `d155_m0`, `d250_m0` and `r393_m0` with the RAR 1.5 to 4.x host
    /// byte set to each of 0 to 7. The attribute column is what that
    /// DOS 0x20 word printed as under each byte.
    #[test]
    fn each_measured_host_prints_its_own_line_and_attribute_form() {
        for (host, line, attrs) in [
            (HostOs::MsDos, Some("DOS"), "..A...."),
            (HostOs::Os2, Some("OS/2"), "..A...."),
            (HostOs::Windows, Some("Windows"), "..A...."),
            (HostOs::Unix, Some("Unix"), "----r-----"),
            (HostOs::MacOs, Some("Mac OS"), "..A...."),
            (HostOs::BeOs, Some("BeOS"), "----r-----"),
            (HostOs::WinCe, Some("WinCE"), "?"),
            (HostOs::Other(7), None, "?"),
        ] {
            let block = block_under(host);
            match line {
                Some(name) => assert!(
                    block.contains(&format!("     Host OS: {name}\n")),
                    "{host:?}: got\n{block}"
                ),
                None => assert!(!block.contains("Host OS:"), "{host:?}: got\n{block}"),
            }
            assert!(
                block.contains(&format!("  Attributes: {attrs}\n")),
                "{host:?}: got\n{block}"
            );
        }
    }

    /// The RAR 1.3 container stores no host, and `unrar lta` over every
    /// `d140` fixture prints no `Host OS:` line; its attributes are the
    /// DOS word (`d140_m0`: `..A....` and `...D...`).
    #[test]
    fn the_rar13_container_prints_no_host_line_and_the_dos_word() {
        let mut member = unix_file("text.txt", 1, 1, 0x20);
        member.host = HostOs::Unrecorded;
        member.algorithm_version = 2;
        let block = technical_block(&member, &Options::default());
        assert!(!block.contains("Host OS:"), "got\n{block}");
        assert!(block.contains("  Attributes: ..A....\n"), "got\n{block}");
        member.attr = 0x10;
        assert_eq!(attributes(&member), "...D...");
    }

    /// RAR 5 names only bytes 0 and 1; `h5_x86_m5` with its host set to 2
    /// or 9 printed no `Host OS:` line and `?` attributes.
    #[test]
    fn an_unnamed_rar5_host_prints_no_line_and_a_question_mark() {
        let mut member = unix_file("x86.bin", 1, 1, 0x20);
        member.host = HostOs::Other(2);
        let block = technical_block(&member, &Options::default());
        assert!(!block.contains("Host OS:"), "got\n{block}");
        assert!(block.contains("  Attributes: ?\n"), "got\n{block}");
    }

    /// The label's two forms, pinned here because the oracle rows run
    /// only on macOS: `Modified` under Windows, `mtime` elsewhere, each
    /// fitting the twelve-character label column.
    #[test]
    fn the_time_label_follows_the_platform() {
        assert_eq!(time_label(true), "Modified");
        assert_eq!(time_label(false), "mtime");
        for windows in [true, false] {
            assert!(time_label(windows).len() <= LABEL_WIDTH);
        }
    }

    /// The timestamp's label does not depend on what wrote the member:
    /// every host byte probed above, in both formats, printed the same one.
    #[test]
    fn the_time_label_is_the_same_for_every_host() {
        for host in [
            HostOs::MsDos,
            HostOs::Os2,
            HostOs::Windows,
            HostOs::Unix,
            HostOs::MacOs,
            HostOs::BeOs,
            HostOs::WinCe,
            HostOs::Other(7),
            HostOs::Unrecorded,
        ] {
            let block = block_under(host);
            let label = format!("{:>LABEL_WIDTH$}: ", time_label(cfg!(windows)));
            assert!(block.contains(&label), "{host:?}: got\n{block}");
        }
    }

    #[test]
    fn a_wide_row_carries_the_checksum_for_a_file_and_blanks_it_for_a_directory() {
        let row = wide_row(
            &unix_file("text.txt", 18400, 18400, 0o100_644),
            &Options::default(),
        );
        assert!(row.contains("3D50D04A"), "got {row}");
        let dir = wide_row(&unix_file("sub", 0, 0, 0o040_755), &Options::default());
        assert!(!dir.contains("3D50D04A"));
        assert_eq!(dir.len(), row.len() - "text.txt".len() + "sub".len());
    }

    #[test]
    fn a_directory_block_omits_the_size_packed_ratio_and_checksum_lines() {
        let block = technical_block(&unix_file("sub", 0, 0, 0o040_755), &Options::default());
        assert!(block.contains("        Type: Directory\n"));
        assert!(!block.contains("Size:"));
        assert!(!block.contains("Ratio:"));
        assert!(!block.contains("CRC32:"));
        assert!(block.contains(" Compression: RAR 5.0(v50) -m0\n"));
    }

    /// One test per format generation, each pinned against `unrar lt` 7.23
    /// run directly over a fixture of that generation (`fixtures/legacy/
    /// archives/{d140,d155,d250,r393}_m0.rar`, 26 Sep 2026): the label a
    /// member's `Compression:` clause carries is the family word AND the
    /// printed version number [`compression_family`] derives from its
    /// declared unpack version, not a constant. A directory entry and a
    /// store-only (`-m0`) member both measure the same, which is why the
    /// fixture used for each generation and the method here are the same.
    #[test]
    fn the_rar13_container_s_own_unpack_version_prints_as_rar_5_0_v13() {
        // RAR 1.3/1.4: the container declares the constant 2 (SPEC-F
        // section on the file header table), and the reference labels
        // that CONTAINER "RAR 5.0(v13)", not "RAR 1.5(v13)".
        let mut member = unix_file("sub", 0, 0, 0o040_755);
        member.algorithm_version = 2;
        let block = technical_block(&member, &Options::default());
        assert!(
            block.contains(" Compression: RAR 5.0(v13) -m0\n"),
            "got {block}"
        );
        let mut file = unix_file("text.txt", 18400, 18400, 0o100_644);
        file.algorithm_version = 2;
        assert!(compression_clause(&file).starts_with("RAR 5.0(v13) -m0 -md="));
    }

    #[test]
    fn rar5_compression_version_one_prints_as_rar_5_0_v70() {
        // What `unrar lt` 7.23 printed for members `rar -md5g` and `-md8g`
        // wrote (an M3 Mac, 27 Sep 2026; spec F 3.2.6.3): the family stays
        // "RAR 5.0", and a size off the powers of two is spelled in the
        // largest unit dividing it.
        let mut file = unix_file("z5g.bin", 18400, 18400, 0o100_644);
        file.algorithm_version = 1;
        file.dictionary = Some(5 << 30);
        assert!(compression_clause(&file).starts_with("RAR 5.0(v70) -m"));
        assert!(compression_clause(&file).ends_with(" -md=5g"));
        file.dictionary = Some(5_248 << 20);
        assert!(compression_clause(&file).ends_with(" -md=5248m"));
    }

    #[test]
    fn rar15_prints_its_own_unpack_version() {
        let mut member = unix_file("sub", 0, 0, 0o040_755);
        member.algorithm_version = 15;
        let block = technical_block(&member, &Options::default());
        assert!(
            block.contains(" Compression: RAR 1.5(v15) -m0\n"),
            "got {block}"
        );
        let mut file = unix_file("text.txt", 18400, 18400, 0o100_644);
        file.algorithm_version = 15;
        assert!(compression_clause(&file).starts_with("RAR 1.5(v15) -m0 -md="));
    }

    #[test]
    fn rar20_prints_its_own_unpack_version() {
        let mut member = unix_file("sub", 0, 0, 0o040_755);
        member.algorithm_version = 20;
        let block = technical_block(&member, &Options::default());
        assert!(
            block.contains(" Compression: RAR 1.5(v20) -m0\n"),
            "got {block}"
        );
        let mut file = unix_file("text.txt", 18400, 18400, 0o100_644);
        file.algorithm_version = 20;
        assert!(compression_clause(&file).starts_with("RAR 1.5(v20) -m0 -md="));
    }

    #[test]
    fn rar4_family_prints_its_own_unpack_version_even_for_a_stored_member() {
        // r393/r420/r550 (RAR 2.9, 3.x, 4.x share one container): a STORED
        // member there still declares v20, and only a compressed one
        // declares v29 - measured against `unrar lt` on `r393_m0.rar`
        // (stored, v20) and `r393_m3.rar` (compressed, v29).
        let mut stored = unix_file("text.txt", 18400, 18400, 0o100_644);
        stored.algorithm_version = 20;
        stored.method = 0;
        stored.dictionary = Some(128 * 1024);
        assert_eq!(compression_clause(&stored), "RAR 1.5(v20) -m0 -md=128k");
        let mut compressed = stored.clone();
        compressed.algorithm_version = 29;
        compressed.method = 3;
        assert_eq!(compression_clause(&compressed), "RAR 1.5(v29) -m3 -md=128k");
    }

    /// The RAR 1.5 to 4.x family's header carries a CRC32 field
    /// unconditionally, 0 for a directory included, and `unrar lt` prints
    /// it - unlike RAR 5, where an ordinary directory's header has no such
    /// field at all and the reference prints nothing (the existing
    /// `a_directory_block_omits_the_size_packed_ratio_and_checksum_lines`
    /// test, still passing, is that case). Measured against `unrar lt` on
    /// `fixtures/legacy/archives/d155_m0.rar` and `d250_m0.rar`
    /// (`EMPTYDIR`, "CRC32: 00000000") and `specs/vectors-G/archives/
    /// r5_store.rar` (`sub`, no CRC32 line), 26 Sep 2026.
    #[test]
    fn a_legacy_directory_still_prints_its_stored_zero_crc32() {
        let mut member = unix_file("sub", 0, 0, 0o040_755);
        member.algorithm_version = 20;
        member.crc32 = Some(0);
        let block = technical_block(&member, &Options::default());
        assert!(block.contains(" CRC32: 00000000\n"), "got {block}");
    }

    #[test]
    fn a_file_block_carries_the_reference_s_own_label_column() {
        let block = technical_block(
            &unix_file("text.txt", 18400, 18400, 0o100_644),
            &Options::default(),
        );
        for line in [
            "        Name: text.txt",
            " Packed size: 18400",
            "       CRC32: 3D50D04A",
        ] {
            assert!(block.contains(line), "missing {line:?} in\n{block}");
        }
    }

    #[test]
    fn the_dictionary_clause_uses_the_unit_that_divides_evenly() {
        assert_eq!(dictionary_clause(128 * 1024), "128k");
        assert_eq!(dictionary_clause(1024 * 1024), "1m");
        assert_eq!(dictionary_clause(4 * 1024 * 1024), "4m");
        assert_eq!(dictionary_clause(1 << 30), "1g");
    }

    /// THE CONTROL ARM for the 17 Sep 2026 finding that no listing
    /// command displayed an archive comment in either dialect.
    ///
    /// It reads the LINE BUILDER rather than driving a listing, for the
    /// reason `edit.rs`'s and `create.rs`'s arms give: [`Out`] writes
    /// straight to the process's streams and cannot be captured, so an
    /// arm over the caller would have to shell out. The end-to-end half -
    /// that `l`, `v` and `lt` are wired to it in BOTH dialects and `lb`
    /// is not - is in `tests/cli.rs`, which runs the real binary.
    ///
    /// The discriminator is the trailing newline, which is why both
    /// shapes are here: a comment stored WITH one lists with two blank
    /// lines before `Archive:` and one stored without lists with one, and
    /// a builder that trimmed or padded the end would pass for one of
    /// them and fail the other. Measured against rar 7.23 and unrar 7.23.
    #[test]
    fn the_comment_block_emits_the_comment_s_bytes_and_exactly_one_newline_after_them() {
        let plain = Options::default();
        assert_eq!(
            archive_comment_block(&plain, Some(b"a conformance comment\n")).as_deref(),
            Some("\nArchive comment:\na conformance comment\n\n"),
        );
        assert_eq!(
            archive_comment_block(&plain, Some(b"no trailing newline")).as_deref(),
            Some("\nArchive comment:\nno trailing newline\n"),
        );
    }

    /// The three ways the block is NOT printed, each measured.
    ///
    /// `-c-` is the reference's own "Disable comments show"; an archive
    /// with no `CMT` block answers `None` rather than an empty block; and
    /// a zero-length comment is the same as none, which is what `c
    /// -zzero.bin` leaves behind (see `create::comment_block`).
    ///
    /// `-idc` is NOT one of them, and that is the negative control that
    /// matters: it is the COPYRIGHT string, measured 17 Sep 2026 - `rar l
    /// -idc` over a commented archive drops the banner and still prints
    /// the comment. The parser set `hide_comments` for it while nothing
    /// read that flag, so wiring the listing to the flag without
    /// splitting them would have hidden the comment for `-idc` too.
    #[test]
    fn the_comment_block_is_silent_for_c_minus_for_no_comment_and_for_an_empty_one() {
        let hidden = Options {
            hide_comments: true,
            ..Options::default()
        };
        assert_eq!(
            archive_comment_block(&hidden, Some(b"a conformance comment\n")),
            None
        );
        let plain = Options::default();
        assert_eq!(archive_comment_block(&plain, None), None);
        assert_eq!(archive_comment_block(&plain, Some(b"")), None);
    }

    #[test]
    fn case_folding_switches_reach_the_listed_name() {
        let member = unix_file("sub/nested.txt", 1, 1, 0o100_644);
        let upper = Options {
            upper_case: true,
            ..Options::default()
        };
        assert!(plain_row(&member, &upper).ends_with("SUB/NESTED.TXT"));
    }
}
