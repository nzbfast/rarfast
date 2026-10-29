//! The `unrar` command line, parsed the way the reference parses it.
//!
//! The switch set here is not a reading of the manual: it is the
//! captured inventory, the captured `unrar` 7.23 inventory
//! in the project's harness, which is the pinned reference's own `-?` screen
//! parsed into the spellings a drop-in must accept. Every spelling in
//! that file has an arm below, including the five that exist only on
//! Windows. The conformance harness probes each one and refuses a
//! candidate that answers a usage error where the reference did not, so
//! deleting an arm to tidy up is the same edit as failing the gate.
//!
//! Two shapes surprised the first draft and are pinned by tests at the
//! bottom of this file, because both are load-bearing rows in the matrix:
//!
//! - `-nosuchswitch` is NOT an unknown option. `n` takes a mask, so the
//!   reference reads it as `-n` with the mask `osuchswitch`, matches
//!   nothing, and lists zero files with exit 0.
//! - a bare `-` IS an unknown option, and the message the reference
//!   prints names the switch text with the leading dash already eaten,
//!   so for `-` it is empty: `ERROR: Unknown option: `.

use std::ffi::{OsStr, OsString};

use super::exit::Exit;

/// The six commands the decoder answers to, plus the creator commands we
/// recognise only to hand to the creator stub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Command {
    /// `e`: extract, discarding archived paths.
    ExtractFlat,
    /// `x`: extract with full paths.
    ExtractFull,
    /// `l`, `lb`, `lt`, `lta`, `v`, `vb`, `vt`, `vta`.
    List(ListStyle),
    /// `p`: print a member to stdout.
    Print,
    /// `t`: test.
    Test,
}

/// Which of unrar's four listing layouts a `l`/`v` spelling selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ListStyle {
    /// `v` rather than `l`: the wide table with packed size, ratio and CRC.
    pub(crate) verbose: bool,
    /// `b`: names only, no header, no totals.
    pub(crate) bare: bool,
    /// `t`: the one-field-per-line technical block.
    pub(crate) technical: bool,
    /// `ta`: technical, including service headers.
    pub(crate) technical_all: bool,
}

/// How `-o` was spelled: the rule for a file that is already there. The
/// LAST of `-o`, `-o+`, `-o-` and `-or` on the line is the rule (unrar
/// 7.23, 2 Oct 2026: `-o+ -or` renames, `-or -o+` overwrites, `-or -o-`
/// keeps), and `-y` answers only `-o`'s question.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Overwrite {
    /// `-o` or no switch: ask, on stderr, and read the answer from
    /// standard input.
    #[default]
    Ask,
    /// `-o+`: overwrite.
    Always,
    /// `-o-`: never overwrite.
    Never,
    /// `-or`: write under a new name, `name(N).ext`, the first N from 1
    /// that is free.
    Rename,
}

/// How `-ol` was spelled: what extraction does with a symbolic link
/// member (spec F 3.8.2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Links {
    /// `-ol` or no switch: create a link, skipping an unsafe one loudly.
    #[default]
    Safe,
    /// `-ola`: create every link as stored, the unsafe ones too. Nothing is
    /// ever written THROUGH one (spec F question 14 (a)).
    All,
    /// `-ol-`: skip every symbolic link silently. Hard links and file
    /// copies are made as usual.
    Skip,
}

/// Which clock a `-ta`/`-tb`/`-tn`/`-to` suffix selects.
///
/// MEASURED against rar and unrar 7.23 on macOS arm64, 4 Oct 2026, over an
/// archive with modification times alone and one made with `-tsc -tsa`:
/// `m`, `o` and no suffix read the modification time; `c` and `a` read
/// the member's OWN creation and access time, and a member that stores
/// none is never newer and always older (`-tnc7d` and `-tac<date>` select
/// nothing, `-toc7d` and `-tbc<date>` everything). Until that day every
/// suffix read the modification time here. The engine's member record
/// carries that time only, so a `c` or `a` filter is REFUSED by name at
/// the dispatch (`unhonoured_switch`) until it carries the other two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TimeField {
    /// `m`, and the default with no suffix.
    Modified,
    /// `c`.
    Created,
    /// `a`.
    Accessed,
    /// `o`.
    Other,
}

/// One `-ta`/`-tb`/`-tn`/`-to` filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TimeFilter {
    /// The clock the suffix named.
    pub(crate) field: TimeField,
    /// Unix seconds the comparison is against.
    pub(crate) at: i64,
    /// `true` for `-ta`/`-tn` (keep newer), `false` for `-tb`/`-to`.
    pub(crate) newer: bool,
}

/// A parsed unrar command line.
#[derive(Debug, Clone)]
pub(crate) struct Parsed {
    /// The command letter block, absent when no argument named one.
    pub(crate) command: Option<Command>,
    /// The archive path as spelled on the command line.
    pub(crate) archive: Option<String>,
    /// Member masks: the `<files...>` positional block.
    pub(crate) masks: Vec<String>,
    /// The trailing `<path_to_extract/>`, recognised by its separator.
    pub(crate) extract_path: Option<String>,
    /// Every switch, already folded into behaviour.
    pub(crate) opts: Options,
}

/// The switch state a decoder run needs.
#[derive(Debug, Clone, Default)]
pub(crate) struct Options {
    // --- messaging -------------------------------------------------
    /// `-inul`: no messages at all.
    pub(crate) silent: bool,
    /// `-ierr`: every message to stderr.
    pub(crate) all_to_stderr: bool,
    /// `-idq`: quiet. `-idc`, `-idd`, `-idn`, `-idp` narrow it further.
    pub(crate) quiet: bool,
    /// `-c-`: do not show comments. NOT `-idc`, which is the copyright
    /// string - see the `id` arm in [`switch`].
    pub(crate) hide_comments: bool,
    /// `-idp`: no percentage counter.
    pub(crate) hide_percent: bool,
    /// `-idn`: no per-file names while extracting.
    pub(crate) hide_names: bool,
    /// `-idd`: no "All OK" style completion messages.
    pub(crate) hide_done: bool,

    // --- names -----------------------------------------------------
    /// `-cl`: lower-case listed and extracted names.
    pub(crate) lower_case: bool,
    /// `-cu`: upper-case them.
    pub(crate) upper_case: bool,
    /// `-ep`: drop archived paths.
    pub(crate) exclude_paths: bool,
    /// `-ep3`: absolute paths, keeping a Windows drive letter.
    pub(crate) expand_paths: bool,
    /// `-ep4<path>`: strip this prefix from archived names.
    pub(crate) strip_prefix: Option<String>,
    /// `-ap<path>`: only members under this archived path.
    pub(crate) archive_path: Option<String>,

    // --- selection -------------------------------------------------
    /// `-n<mask>` and `-n@<list>`: additional include filter.
    pub(crate) include: Vec<String>,
    /// `-x<mask>` and `-x@<list>`: exclusions.
    pub(crate) exclude: Vec<String>,
    /// `-r`: recurse into archived subdirectories.
    pub(crate) recurse: bool,
    /// `-sl<size>`: only files smaller than this. Directories bypass it,
    /// as they do `-sm` (measured: `-sl0` lists the directories alone).
    pub(crate) size_less: Option<u64>,
    /// `-sm<size>`: only files LARGER than this. Both tools have it
    /// (unrar 7.23 honours it, measured 4 Oct 2026, though its help
    /// screen does not list it); it is kept here so that the
    /// selection filter stays the one place a member is judged rather
    /// than growing a second copy in the creator that could drift.
    /// Directories bypass it, which is measured: `rar l -sm1000000` over
    /// an archive whose only large member is absent still lists the
    /// zero-byte directory.
    pub(crate) size_more: Option<u64>,
    /// `-ed`: leave directory entries out. Creator-dialect only, same
    /// reasoning as `size_more`.
    pub(crate) skip_directories: bool,
    /// `-ver`: process the older versions of files an archive keeps, under
    /// `name;n`. Without it they are listed and nothing else.
    pub(crate) versions: bool,
    /// `-ver<n>`, n of 1 and up: process only the files whose version is
    /// n, under their names without the `;n`.
    pub(crate) only_version: Option<u32>,
    /// `-e<attr>` / `-e+<attr>`: the DOS attribute mask to filter on and
    /// whether it INCLUDES (the `+` form) or excludes. Creator-dialect
    /// only.
    ///
    /// The test is on the MEMBER's host, never on the running box: a
    /// DOS attribute exists only for a member a Windows rar wrote, and
    /// a unix member's `attr` holds mode bits that would collide with
    /// the masks (0o100644 has 0x20 set, so `-e+A` would match every
    /// file on macOS). Reading it per member is also what reproduces
    /// both platforms' rows from one rule: on the macOS fixtures no
    /// member has a DOS attribute, so `-e+A` selects nothing and `-eA`
    /// excludes nothing, and on the Windows fixtures the three files
    /// carry `A` and the directory does not.
    pub(crate) attribute_filter: Option<(u64, bool)>,
    /// `-ta`/`-tb`/`-tn`/`-to`, in the order given.
    pub(crate) time_filters: Vec<TimeFilter>,
    /// `-@`/`-@+`: whether `@listfile` arguments are read.
    pub(crate) file_lists: bool,

    // --- extraction ------------------------------------------------
    /// `-o`, `-o+`, `-o-`.
    pub(crate) overwrite: Overwrite,
    /// `-y`: assume yes, which makes an overwrite prompt an overwrite.
    pub(crate) assume_yes: bool,
    /// `-kb`: keep a file whose checksum failed.
    pub(crate) keep_broken: bool,
    /// `-op<path>`: write extracted files here.
    pub(crate) output_path: Option<String>,
    /// `-ad`, `-ad1`, `-ad2`: append the archive name to the destination.
    pub(crate) append_archive_dir: Option<u8>,
    /// `-ol`, `-ola`, `-ol-`.
    pub(crate) links: Links,
    /// `-f`: only members that already exist on disk.
    pub(crate) freshen: bool,
    /// `-u`: freshen, plus members that do not exist yet.
    pub(crate) update: bool,
    /// `-ai`: do not restore attributes.
    pub(crate) ignore_attributes: bool,
    /// `-ep1`: read, and refused on extraction.
    pub(crate) drop_mask_path: bool,
    /// `-ts-` and `-tsm-`: do not set the stored modification time on
    /// what is written.
    pub(crate) leave_mtime: bool,

    // --- workers ---------------------------------------------------
    /// `-mt<n>`: the worker ceiling for this run, as the reference reads
    /// it. Both dialects accept it and both mean the same thing by it,
    /// which is measured: `rar` and `unrar` 7.23 agree on every edge case
    /// `reference_threads` encodes (19 Sep 2026).
    ///
    /// It reaches the engine as
    /// [`MemoryPolicy::max_workers`](rarkit::MemoryPolicy::max_workers)
    /// (API section 8), which is the one worker control the engine has, and
    /// through it the `workers` argument of `extract_parallel` (section 4).
    /// `None` leaves the engine's own default in place.
    pub(crate) threads: Option<u64>,
    /// `-mm<size>`, rarfast's own memory ceiling, carried here from the
    /// `rar` dialect's parser when a read-only command is handed over (the
    /// `unrar` name accepts the switch and does nothing with it, as the
    /// reference does: [`m_family_as_reference`]). It is
    /// a STATED budget, so the read runs under
    /// `MemoryPolicy::from_limit(size)` and a member needing a larger
    /// window is refused (a stated budget
    /// is hard). `None` is the engine's default policy, whose window ceiling
    /// is half of physical memory.
    pub(crate) memory_cap: Option<u64>,

    // --- password --------------------------------------------------
    /// `-p<pwd>`. `-p-` clears it back to none.
    pub(crate) password: Option<String>,
    /// `-p` with no value: prompt on the terminal.
    pub(crate) prompt_password: bool,
    /// `-p-` was the last word on the password: there is none and none
    /// is to be asked for. Not the same as no password switch at all,
    /// which leaves this false.
    pub(crate) no_password: bool,
    /// The first list file (`@list`, `-n@list`, `-x@list`) that could not
    /// be read, and why: the run stops on it before the archive is opened
    /// (`dispatch_inner`), as the reference's does.
    pub(crate) unreadable_list: Option<(String, String)>,

    // --- accepted, no observable effect on a decode ----------------
    /// `-v`: list every volume rather than the first.
    pub(crate) all_volumes: bool,
    /// `-ag<format>`: the archive name is generated from the clock.
    pub(crate) generate_name: Option<String>,
    /// `-si[name]`: read the archive from standard input.
    pub(crate) from_stdin: bool,
}

/// The widest `-mt<n>` the reference accepts.
const REFERENCE_MAX_THREADS: u64 = 64;

/// `-mt<n>`'s number as the reference reads it, or `None` where it answers
/// `Unknown option` (exit 7, on every command). Measured 15 Sep 2026 on
/// `rar` 7.23 and re-measured 19 Sep 2026 on `unrar` 7.23, which agrees on
/// every case below: the leading digits fold into an unsigned 32-bit value
/// that wraps, anything after them is ignored, and only 1 to 64 is
/// accepted. So `-mt064`, `-mt4x` and `-mt4294967297` (2^32 + 1) are
/// accepted as 64, 4 and 1, while `-mt`, `-mt00`, `-mt65`, `-mt+4` and
/// `-mt4294967296` are refused.
///
/// One rule, in the shared switch state, because BOTH dialects reach the
/// same engine control with it.
pub(crate) fn reference_threads(rest: &str) -> Option<u64> {
    let value = rest
        .bytes()
        .take_while(u8::is_ascii_digit)
        .fold(0u32, |acc, digit| {
            acc.wrapping_mul(10).wrapping_add(u32::from(digit - b'0'))
        });
    Some(u64::from(value)).filter(|n| (1..=REFERENCE_MAX_THREADS).contains(n))
}

/// A refusal that carries the reference's own exit code and message.
#[derive(Debug)]
pub(crate) struct Refusal {
    /// What to print, on stdout, the way the reference prints it.
    pub(crate) message: String,
    /// The code to exit with.
    pub(crate) exit: Exit,
}

impl Options {
    pub(crate) fn new() -> Self {
        Self {
            file_lists: true,
            ..Self::default()
        }
    }
}

/// First letters whose unmatched remainder the reference SWALLOWS rather
/// than refusing. Measured against unrar 7.23 on 3 Sep 2026 by running
/// `unrar l -<c> arc.rar` for every letter and digit: `e f i k n o p r s
/// t u v w x y z` came back 0 (or, for `p`, a password prompt), and every
/// other single letter came back 7 with `ERROR: Unknown option`. It is a
/// measurement rather than a rule because no pattern in the letters
/// predicts it: neighbouring letters fall on opposite sides, and
/// guessing which side a letter falls on is how a drop-in starts
/// refusing a line the reference accepted.
const LENIENT_FIRST_LETTERS: &[u8] = b"efiknoprstuvwxyz";

fn is_lenient(rest: &str) -> bool {
    rest.as_bytes()
        .first()
        .is_some_and(|c| LENIENT_FIRST_LETTERS.contains(&c.to_ascii_lowercase()))
}

fn unknown_option(rest: &str) -> Refusal {
    Refusal {
        // The reference prints the switch text with the leading dash
        // already consumed, so a bare `-` prints an empty name. The
        // conformance row `stop-switch-scan` is exactly that line.
        message: format!("\nERROR: Unknown option: {rest}"),
        exit: Exit::BadCommandLine,
    }
}

/// The size `-sl` and `-sm` take, in bytes; `None` where the text is no
/// size and the switch filters nothing.
///
/// The rule is FITTED to rar and unrar 7.23, which agree on every row
/// (macOS arm64, 4 Oct 2026, some ninety spellings over files of chosen
/// sizes, the `g` and `t` rows over an archive whose headers were given
/// sizes each side of 10^9, 2^30, 10^12 and 2^40;
/// `tests/unrar_followup_sweep.rs` has the table):
///
/// - a text that does not begin with a digit is no size (`-sl`, `-slk`,
///   `-slx5`, `-sl-5`);
/// - the unit is the LAST character: `k m g t` are powers of 1024 and `K
///   M G T` powers of 1000; any other is bytes (`-sl1b`, `-sl1x`, and
///   `-sl1kb`, which is one byte);
/// - the digits are read together whatever stands between them (`-sl1k5`
///   is 15 bytes, `-sl1,5k` 15 KiB), and a point starts a fraction
///   (`-sl1.5k` is 1,536, `-sl0.01k` is 10, `-sl1.5` is 1; a second point
///   starts the fraction again: `-sl1.5.5k` is 15.5 KiB);
/// - a size too large to count wraps, and is judged as a signed number:
///   `-sl18446744073709551615` keeps no file and `-sm` with it every one.
///
/// Until that day `-sl` read the leading digits alone and `-sm` was not
/// read by this parser at all: `lb -sl1m` listed the empty file only.
///
/// The body was written again on 10 Oct 2026 from the rows alone, and the
/// reference was asked again first (rar and unrar 7.23, macOS arm64, 681
/// spellings, each limit found to the byte over archives of header-only
/// members; the two agree on every row, exit 0 on every row, and refuse
/// none). What those rows add to the list above:
///
/// - the unit multiplies BEFORE the fraction divides, both wrapping and
///   both signed, and the division drops the remainder toward zero
///   (`-sl1.99999999999999999k` is 18, `-sl9223372036854775807.5` is 0);
/// - the fraction's divisor is ten to the count of digits after the last
///   point, and it wraps as well (`-sl2.5` with 26 zeros and `k` is 1);
/// - from 64 digits after the point that divisor has wrapped to nothing,
///   and the size is then the undivided product (all 681 rows were read
///   the same by both tools on Linux x86-64 as well, these among them).
fn size_limit(text: &str) -> Option<i64> {
    let text = text.as_bytes();
    let (&first, &last) = (text.first()?, text.last()?);
    if !first.is_ascii_digit() {
        return None;
    }
    // One pass keeps two things: every digit of the text as one number,
    // and how many of them came after the last point (none seen: `None`).
    let mut number = 0_i64;
    let mut after_point: Option<u32> = None;
    for &byte in text {
        if byte.is_ascii_digit() {
            number = number.wrapping_mul(10).wrapping_add(i64::from(byte - b'0'));
            after_point = after_point.map(|count| count.saturating_add(1));
        } else if byte == b'.' {
            after_point = Some(0);
        }
    }
    // The last character alone names the unit: its letter picks the power
    // and its case the base.
    let base: i64 = if last.is_ascii_lowercase() {
        1024
    } else {
        1000
    };
    let unit = match last.to_ascii_lowercase() {
        b'k' => base,
        b'm' => base.pow(2),
        b'g' => base.pow(3),
        b't' => base.pow(4),
        _ => 1,
    };
    let product = number.wrapping_mul(unit);
    let divisor = 10_i64.wrapping_pow(after_point.unwrap_or(0));
    Some(product.checked_div(divisor).unwrap_or(product))
}

/// The date `-ta` and `-tb` take, as a Unix instant in local time.
///
/// Reference unrar 7.23, measured 8 Oct 2026 on macOS arm64 (sweep 2 item
/// 36; `tests/time_switches_honoured.rs` has the table): six numbers,
/// year first, each of up to its width in digits (four, then two each),
/// parted by any run of other characters or by nothing at all, so
/// `2023-11-14`, `2023/11/14,22:13` and `20231114221320` are all dates. A
/// number left out is 1 for the month and the day and 0 for the rest, and
/// one past its range carries over ([`super::time::carried_civil_to_unix`]).
///
/// A date that cannot be read, or one outside what the reference keeps
/// (before 1601, or past a point between 2100 and 3000, taken here as
/// 2^64 nanoseconds after 1601), is a time before every file:
/// [`UNREADABLE_DATE`]. Until then only the all digits form was read, and
/// anything else added no filter at all.
fn parse_stamp(text: &str) -> i64 {
    let bytes = text.as_bytes();
    let mut at = 0;
    let mut fields = [0_i64, 1, 1, 0, 0, 0];
    for (slot, width) in [4_usize, 2, 2, 2, 2, 2].into_iter().enumerate() {
        while at < bytes.len() && !bytes[at].is_ascii_digit() {
            at += 1;
        }
        let start = at;
        while at < bytes.len() && at - start < width && bytes[at].is_ascii_digit() {
            at += 1;
        }
        match text[start..at].parse() {
            Ok(number) => fields[slot] = number,
            Err(_) if slot == 0 => return UNREADABLE_DATE,
            Err(_) => break,
        }
    }
    // 1601-01-01 and 2^64 nanoseconds after it, in Unix seconds.
    const KEPT: std::ops::Range<i64> = -11_644_473_600..6_802_270_473;
    super::time::carried_civil_to_unix(fields)
        .filter(|at| KEPT.contains(at))
        .unwrap_or(UNREADABLE_DATE)
}

/// What a date the reference cannot read filters by: a time before every
/// file, so `-ta` keeps everything and `-tb` nothing.
const UNREADABLE_DATE: i64 = i64::MIN;

/// The seconds in the period `-tn` and `-to` take:
/// `[<n>d][<n>h][<n>m][<n>s]`.
///
/// MEASURED against unrar 7.23 on macOS (arm64), 4 Oct 2026, over members
/// 6 years, 3 days, 2 hours and a moment old
/// (`tests/unrar_switch_bytes_and_periods.rs` has the table):
///
/// - each unit takes the number written before it, in either case, and
///   the units ADD, in any order and repeated (`1d2h`, `2h1d`, `1h1h1h`);
/// - a character that is no digit and no unit is stepped over and drops
///   the number before it (`x7d` is seven days, `1x1h` one hour), and a
///   number with no unit after it counts for nothing (`7x`, `1d1`);
/// - so a DATE is a period of zero: `-tn20250101` selects nothing that
///   exists yet and `-to20250101` everything. Until then a period was
///   read as a date, did not parse, and added no filter at all, so
///   `x -tn7d` wrote every member; and a date WAS read as one here.
///
/// A period too long to count is as long as can be counted.
fn parse_period(text: &str) -> u64 {
    let mut total = 0_u64;
    let mut number: Option<u64> = None;
    for c in text.chars() {
        if let Some(digit) = c.to_digit(10) {
            number = Some(
                number
                    .unwrap_or(0)
                    .saturating_mul(10)
                    .saturating_add(u64::from(digit)),
            );
            continue;
        }
        let unit = match c.to_ascii_lowercase() {
            'd' => 86_400,
            'h' => 3_600,
            'm' => 60,
            's' => 1,
            _ => 0,
        };
        total = total.saturating_add(number.take().unwrap_or(0).saturating_mul(unit));
    }
    total
}

/// The Unix second a period of `seconds` back from now starts at.
fn period_start(seconds: u64) -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        });
    now.saturating_sub(i64::try_from(seconds).unwrap_or(i64::MAX))
}

fn time_field(suffix: u8) -> Option<TimeField> {
    match suffix {
        b'm' => Some(TimeField::Modified),
        b'c' => Some(TimeField::Created),
        b'a' => Some(TimeField::Accessed),
        b'o' => Some(TimeField::Other),
        _ => None,
    }
}

/// A mask no member's name matches: what a positional list that holds no
/// name selects. A name never holds a NUL.
const NO_NAME: &str = "\0";

/// Reads a list file (`@<list>`, `-n@<list>`, `-x@<list>`), or standard
/// input for the bare `@` form, into its masks.
///
/// **A list that cannot be read stops the run**, and is never an empty
/// list: the first one is kept in `unreadable` for the dispatch to
/// report. Until 4 Oct 2026 every failure read as no masks at all, which
/// as a positional selects EVERYTHING and as `-x@` excludes nothing, so a
/// list that was not there, or was not UTF-8, extracted the whole archive.
/// Reference unrar 7.23 (measured that day, macOS arm64, all three forms):
/// `Cannot open <list>` and the reason, `Program aborted`, exit 6.
fn read_mask_list(source: &str, unreadable: &mut Option<(String, String)>) -> Vec<String> {
    let read = if source.is_empty() {
        let mut bytes = Vec::new();
        use std::io::Read;
        std::io::stdin().read_to_end(&mut bytes).map(|_| bytes)
    } else {
        std::fs::read(source)
    };
    match read {
        Ok(bytes) => list_masks(&bytes),
        Err(error) => {
            let shown = if source.is_empty() { "stdin" } else { source };
            unreadable.get_or_insert_with(|| (shown.to_owned(), super::io_reason(&error)));
            Vec::new()
        }
    }
}

/// The masks a list file's bytes hold, a line each ([`list_line`]), a
/// line that holds no name dropped. A carriage return ends a line as a
/// line feed does.
///
/// The rule is FITTED to reference unrar 7.23's results on eleven lists
/// (4 Oct 2026, macOS arm64; `tests/list_file_reading.rs` has the table)
/// and is no rule a specification states:
///
/// - a UTF-16 byte order mark, of either order, and the text is UTF-16
///   (the list Notepad saves as `Unicode`);
/// - a UTF-8 byte order mark is dropped;
/// - otherwise UTF-8. Where the bytes stop being UTF-8, the lines before
///   the line that breaks are masks, and that line with everything after
///   it is ONE more, which matches no name. So such a list is never
///   empty: `a.txt` after a Latin-1 line selects nothing, as a positional
///   and under `-n@` alike, and excludes nothing under `-x@`.
fn list_masks(bytes: &[u8]) -> Vec<String> {
    let utf16 = |order: fn([u8; 2]) -> u16| {
        let units: Vec<u16> = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&pair| order(pair))
            .collect();
        String::from_utf16_lossy(&units)
    };
    let (text, broken) = match bytes {
        [0xff, 0xfe, ..] => (utf16(u16::from_le_bytes), None),
        [0xfe, 0xff, ..] => (utf16(u16::from_be_bytes), None),
        _ => {
            let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
            match std::str::from_utf8(bytes) {
                Ok(text) => (text.to_owned(), None),
                Err(error) => {
                    let whole = &bytes[..error.valid_up_to()];
                    let lines = whole
                        .iter()
                        .rposition(|&b| b == b'\n')
                        .map_or(0, |at| at + 1);
                    (
                        String::from_utf8_lossy(&bytes[..lines]).into_owned(),
                        Some(String::from_utf8_lossy(&bytes[lines..]).into_owned()),
                    )
                }
            }
        }
    };
    text.split(['\n', '\r'])
        .map(list_line)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .chain(broken)
        .collect()
}

/// The name one line of a list file holds; empty where it holds none.
///
/// FITTED to reference unrar 7.23 (macOS arm64, 4 Oct 2026, some forty
/// lists; five of the rows again with UnRAR.exe 7.23 on Windows 11;
/// `tests/unrar_followup_sweep.rs` has the table):
///
/// - two slashes and all after them are a remark and go first, inside
///   quotes too;
/// - then the spaces and tabs that TRAIL go. What stands BEFORE the name
///   is part of it: a line of a space and `a.txt` names the member whose
///   name begins with the space. Until that day both ends were trimmed;
/// - then a line that begins and ends with a double quote names what is
///   between them, as it stands (the way to a name that ends with a
///   space); a quote at one end only is part of the name.
fn list_line(line: &str) -> &str {
    let line = line.find("//").map_or(line, |at| &line[..at]);
    let line = line.trim_end_matches([' ', '\t']);
    match line.strip_prefix('"') {
        Some(rest) => rest
            .strip_suffix('"')
            .unwrap_or(if rest.is_empty() { "" } else { line }),
        None => line,
    }
}

/// Parses one switch (the text AFTER the leading dash) into `opts`.
///
/// Returns `Err` only where the reference itself refuses. Every spelling
/// in the captured inventory reaches an `Ok` arm here.
fn switch(rest: &str, opts: &mut Options) -> Result<(), Refusal> {
    // `-` with nothing after it. The reference refuses this, which is
    // what the `stop-switch-scan` row records. The help screen's `-` line
    // is not this shape: the screen lists switches without their dash, so
    // that line is `--`, which the reference reads as the end of the
    // switches (`unrar l -- -x` opens an archive named `-x.rar`, measured
    // 15 Sep 2026). `parse` honours that before this function is reached,
    // so an empty `rest` here is only ever the lone `-`.
    if rest.is_empty() {
        return Err(unknown_option(rest));
    }
    if let Some(inner) = rest.strip_prefix('@') {
        // `-@` / `-@+` toggle whether `@listfile` positionals are read.
        if inner.is_empty() || inner == "+" {
            opts.file_lists = inner == "+";
            return Ok(());
        }
        return Err(unknown_option(rest));
    }

    // The first CHARACTER, which need not be one byte: split at byte 1,
    // a dash and an accented letter was a panic where the reference says
    // `Unknown option` (measured, unrar 7.23, 4 Oct 2026). No letter below
    // is anything but ASCII, so such a switch reaches the last arm and is
    // refused there.
    let first = rest.chars().next().map_or(0, char::len_utf8);
    let (head, tail) = rest.split_at(first);
    match head {
        "a" => match tail {
            "c" => Ok(()), // Windows: `-ac`, reset the Archive flag.
            "d" | "d1" | "d2" => {
                opts.append_archive_dir = Some(match tail {
                    "d1" => 1,
                    "d2" => 2,
                    _ => 0,
                });
                Ok(())
            }
            "i" => {
                opts.ignore_attributes = true;
                Ok(())
            }
            _ if tail.starts_with('g') => {
                opts.generate_name = Some(tail[1..].to_owned());
                Ok(())
            }
            _ if tail.starts_with('p') => {
                opts.archive_path = Some(tail[1..].to_owned());
                Ok(())
            }
            _ => Err(unknown_option(rest)),
        },
        "c" => match tail {
            "-" => {
                opts.hide_comments = true;
                Ok(())
            }
            "fg-" => Ok(()), // Do not read a configuration file; we read none.
            "l" => {
                opts.lower_case = true;
                opts.upper_case = false;
                Ok(())
            }
            "u" => {
                opts.upper_case = true;
                opts.lower_case = false;
                Ok(())
            }
            _ => Err(unknown_option(rest)),
        },
        "d" => match tail {
            "h" => Ok(()), // `-dh`; ours are opened read-only anyway.
            _ => Err(unknown_option(rest)),
        },
        "e" => match tail {
            "p" => {
                opts.exclude_paths = true;
                Ok(())
            }
            // `-ep1`: drop the mask's own directory from each written
            // name. Not done here, so the dispatch refuses it on `x` and
            // `e` (sweep 2 item 32).
            "p1" => {
                opts.drop_mask_path = true;
                Ok(())
            }
            "p3" => {
                opts.expand_paths = true;
                Ok(())
            }
            _ if tail.starts_with("p4") => {
                opts.strip_prefix = Some(tail[2..].to_owned());
                Ok(())
            }
            _ => Ok(()), // A lenient first letter: swallowed, not refused.
        },
        "f" => {
            if tail.is_empty() {
                opts.freshen = true;
            }
            Ok(())
        }
        "i" => match tail {
            // `-ierr` and `-idq` share one destination, not two independent
            // flags: measured against `rar`/`unrar` 7.23 on 20 Sep 2026,
            // `unrar p -idq -ierr good.rar` puts the whole progress on
            // stderr (the LATER `-ierr` wins) and `unrar p -ierr -idq
            // good.rar` puts nothing there at all (the later `-idq` wins,
            // and it takes the destination away rather than merely
            // narrowing it). So each switch clears the other's flag as
            // well as setting its own, and whichever was given last is
            // the one left standing. `-inul` is the third member of the
            // same set (measured 30 Sep 2026, rar and unrar 7.23: `-inul
            // -ierr` prints the whole run on stderr, `-ierr -inul` nothing,
            // `-inul -idq` a failure's lines and `-idq -inul` nothing), so
            // each of the three clears the other two.
            "err" => {
                opts.all_to_stderr = true;
                opts.quiet = false;
                opts.silent = false;
                Ok(())
            }
            "nul" => {
                opts.silent = true;
                opts.all_to_stderr = false;
                opts.quiet = false;
                Ok(())
            }
            _ if tail.starts_with('d') => {
                for flag in tail[1..].bytes() {
                    match flag {
                        // `-idc` is the COPYRIGHT string, not the
                        // comment: measured 17 Sep 2026, `rar l -idc`
                        // over a commented archive drops the banner and
                        // still prints the comment, where `-c-` keeps
                        // the banner and drops the comment. It set
                        // `hide_comments` here while nothing read that
                        // flag, so the conflation cost nothing until the
                        // listing started reading it. rarfast prints no
                        // banner at all, so there is nothing left to
                        // suppress.
                        b'c' => {}
                        b'd' => opts.hide_done = true,
                        b'n' => opts.hide_names = true,
                        b'p' => opts.hide_percent = true,
                        b'q' => {
                            opts.quiet = true;
                            opts.all_to_stderr = false;
                            opts.silent = false;
                        }
                        _ => {}
                    }
                }
                Ok(())
            }
            // Windows: `-ioff[n]` powers the machine down afterwards. It
            // parses here and is declined at the act, which is also why
            // the harness declines to sweep it.
            _ if tail.starts_with("off") => Ok(()),
            _ => Ok(()),
        },
        "k" => {
            if tail == "b" {
                opts.keep_broken = true;
            }
            Ok(())
        }
        "m" => match tail {
            "lp" => Ok(()),                       // Windows: large-page memory.
            _ if tail.starts_with('e') => Ok(()), // `-me[par]`: encryption parameters.
            // `-mt<n>` is not on `unrar`'s help screen, and it is accepted
            // all the same: measured against unrar 7.23 on an Apple Silicon Mac on
            // 19 Sep 2026, `-mt1` through `-mt64` exit 0 and `-mt`,
            // `-mt0`, `-mt00`, `-mt65`, `-mt+4` and `-mt4294967296` exit 7,
            // which is `rar`'s rule to the letter.
            _ if tail.starts_with('t') => match reference_threads(&tail[1..]) {
                Some(threads) => {
                    opts.threads = Some(threads);
                    Ok(())
                }
                None => Err(unknown_option(rest)),
            },
            _ => Err(unknown_option(rest)),
        },
        "n" => {
            if let Some(list) = tail.strip_prefix('@') {
                let masks = read_mask_list(list, &mut opts.unreadable_list);
                opts.include.extend(masks);
            } else {
                opts.include.push(tail.to_owned());
            }
            Ok(())
        }
        "o" => match tail {
            "" => {
                opts.overwrite = Overwrite::Ask;
                Ok(())
            }
            "+" => {
                opts.overwrite = Overwrite::Always;
                Ok(())
            }
            "-" => {
                opts.overwrite = Overwrite::Never;
                Ok(())
            }
            "c" => Ok(()), // Windows: keep the NTFS compression flag.
            "l" => {
                opts.links = Links::Safe;
                Ok(())
            }
            "la" => {
                opts.links = Links::All;
                Ok(())
            }
            "l-" => {
                opts.links = Links::Skip;
                Ok(())
            }
            "r" => {
                opts.overwrite = Overwrite::Rename;
                Ok(())
            }
            "w" => Ok(()),                        // Who owns each file.
            _ if tail.starts_with('m') => Ok(()), // Mark of the Web.
            _ if tail.starts_with('p') => {
                opts.output_path = Some(tail[1..].to_owned());
                Ok(())
            }
            _ => Ok(()),
        },
        "p" => {
            opts.no_password = tail == "-";
            if tail == "-" {
                opts.password = None;
                opts.prompt_password = false;
            } else if tail.is_empty() {
                opts.prompt_password = true;
            } else {
                opts.password = Some(tail.to_owned());
                opts.prompt_password = false;
            }
            Ok(())
        }
        "r" => {
            match tail {
                "" => opts.recurse = true,
                // Windows: `-ri<P>[:<S>]`, priority and sleep.
                _ if tail.starts_with('i') => {}
                _ => {}
            }
            Ok(())
        }
        "s" | "S" => match tail {
            _ if tail.starts_with('c') => Ok(()), // Character set.
            _ if tail.starts_with('i') => {
                opts.from_stdin = true;
                Ok(())
            }
            // `-sl<size>` and `-sm<size>`, in either case. A text that is
            // no size leaves an earlier one standing ([`size_limit`]).
            _ if tail.starts_with(['l', 'L']) => {
                if let Some(limit) = size_limit(&tail[1..]) {
                    // Nothing is smaller than a size that wrapped below
                    // zero.
                    opts.size_less = Some(u64::try_from(limit).unwrap_or(0));
                }
                Ok(())
            }
            _ if tail.starts_with(['m', 'M']) => {
                if let Some(limit) = size_limit(&tail[1..]) {
                    // Everything is larger than one that did.
                    opts.size_more = u64::try_from(limit).ok();
                }
                Ok(())
            }
            _ => Ok(()),
        },
        "t" | "T" => {
            let Some(kind) = tail.as_bytes().first().copied() else {
                return Ok(());
            };
            // `-t` and a character that is not ASCII: refused by the
            // reference (measured), and not sliced inside here.
            if !kind.is_ascii() {
                return Err(unknown_option(rest));
            }
            let body = &tail[1..];
            // The kind and the field are read in EITHER CASE (measured,
            // unrar 7.23, 4 Oct 2026: `-tA20200101`, `-TA...`, `-tAM...`
            // and `-TN7d` filter as their lower case does). Until then an
            // upper case kind was swallowed and filtered nothing.
            let kind = kind.to_ascii_lowercase();
            match kind {
                b'a' | b'b' | b'n' | b'o' => {
                    let lower = body.as_bytes().first().map(u8::to_ascii_lowercase);
                    let (field, stamp) = match lower {
                        Some(c) if time_field(c).is_some() => {
                            (time_field(c).unwrap_or(TimeField::Modified), &body[1..])
                        }
                        _ => (TimeField::Modified, body),
                    };
                    // `-ta` and `-tb` take a date; `-tn` and `-to` take a
                    // PERIOD back from now and nothing else, so they
                    // always filter: a date given to them is a period of
                    // zero ([`parse_period`]).
                    // `-tb` is STRICTLY before its date (the reference
                    // passes over a member at the very second, measured
                    // 8 Oct 2026), where the filter itself keeps a member
                    // at its instant: so the second before.
                    let at = match kind {
                        b'n' | b'o' => period_start(parse_period(stamp)),
                        b'b' => parse_stamp(stamp).saturating_sub(1),
                        _ => parse_stamp(stamp),
                    };
                    opts.time_filters.push(TimeFilter {
                        field,
                        at,
                        newer: kind == b'a' || kind == b'n',
                    });
                    Ok(())
                }
                // `-ts-` and `-tsm-` leave a written file with the time
                // of extraction; every other `-ts` form restores the
                // stored time, which is also what no switch does
                // (reference unrar 7.23, measured 8 Oct 2026, sweep 2
                // item 35: `-ts`, `-tsm`, `-tsm1`, `-tsc-`, `-tsa-`
                // restore it). Until then all of them were read and
                // dropped.
                b's' => {
                    opts.leave_mtime = matches!(body.to_ascii_lowercase().as_str(), "-" | "m-");
                    Ok(())
                }
                // Taken by the reference and changing nothing seen: `-tc`,
                // `-tv` and `-t-`, whatever follows.
                b'c' | b'v' | b'-' => Ok(()),
                // Every other tail is refused. MEASURED against unrar 7.23
                // on macOS arm64, 4 Oct 2026, every letter and digit after
                // `-t` on `lb` and `t`: `a b c n o s v -` exit 0, the rest
                // (`-tq`, `-t1`, `-tx`, `-t+`, and `-tk` and `-tl`, which
                // are rar's) `Unknown option`, exit 7. Until then the tail
                // was swallowed here, exit 0. Under rarfast's own name a
                // refusal here is offered to the creator's parser, which
                // takes `-tk` and `-tl` as rar does.
                _ => Err(unknown_option(rest)),
            }
        }
        "u" => {
            if tail.is_empty() {
                opts.update = true;
            }
            Ok(())
        }
        "v" => {
            match tail {
                "" => opts.all_volumes = true,
                "p" => {}
                // Plain `-ver` selects the older versions of files, and
                // `-ver<n>` the one numbered n. The number is read as C
                // reads one (reference unrar 7.23, measured 8 Oct 2026,
                // sweep 2 item 34): `-ver01` and `-ver1x` are 1; `-ver0`
                // and `-verx` are plain `-ver`; `-ver-1` changes nothing.
                // Until then every numbered form was read and dropped.
                _ if tail.starts_with("er") => {
                    let number = &tail[2..];
                    let digits = number.bytes().take_while(u8::is_ascii_digit).count();
                    match number[..digits].parse::<u32>() {
                        Ok(0) => opts.versions = true,
                        Ok(wanted) => opts.only_version = Some(wanted),
                        // Digits past a `u32`: no archive holds it.
                        Err(_) if digits > 0 => opts.only_version = Some(u32::MAX),
                        Err(_) if number.starts_with('-') => {}
                        Err(_) => opts.versions = true,
                    }
                }
                _ => {}
            }
            Ok(())
        }
        "x" => {
            if let Some(list) = tail.strip_prefix('@') {
                let masks = read_mask_list(list, &mut opts.unreadable_list);
                opts.exclude.extend(masks);
            } else {
                opts.exclude.push(tail.to_owned());
            }
            Ok(())
        }
        "y" => {
            opts.assume_yes = true;
            Ok(())
        }
        _ if is_lenient(rest) => Ok(()),
        _ => Err(unknown_option(rest)),
    }
}

/// The decoder's own reading of one switch, for the `rar` dialect to
/// reuse on the spellings the two tools share.
///
/// The creator parser owns every switch whose meaning differs between
/// the two tools (`-f`, `-u`, `-t`, `-s`, `-v` and the `-m` family all
/// mean something else to `rar`), and hands the rest here rather than
/// keeping a second copy of the time-filter and `-ts` arms that would
/// drift from this one. A refusal is swallowed on purpose: the caller
/// has already decided the spelling is legal in its own dialect.
pub(crate) fn switch_for_reuse(rest: &str, opts: &mut Options) {
    let _ = switch(rest, opts);
}

/// Reads the command word. `None` means the word is not a command the
/// decoder knows, which the reference answers with the help screen and
/// exit 7.
pub(crate) fn command(word: &str) -> Option<Command> {
    let style = |verbose: bool, spec: &str| {
        Some(Command::List(ListStyle {
            verbose,
            bare: spec == "b",
            technical: spec.starts_with('t'),
            technical_all: spec == "ta",
        }))
    };
    match word {
        "e" => Some(Command::ExtractFlat),
        "x" => Some(Command::ExtractFull),
        "p" => Some(Command::Print),
        "t" => Some(Command::Test),
        "l" | "lb" | "lt" | "lta" => style(false, &word[1..]),
        "v" | "vb" | "vt" | "vta" => style(true, &word[1..]),
        _ => None,
    }
}

/// The creator commands. They belong to the `rar` dialect; recognising
/// them here is what routes a creator command line to that dialect at
/// all, rather than to the decoder's help screen.
///
/// `mf` (move files only) was missing from the bare spellings until 4 Oct
/// 2026: `rarfast mf z.rar f.txt` printed the decoder's help and exited 7,
/// where rar 7.23 (measured that day) archives the file and deletes it.
///
/// **Three of them carry an argument in the word itself**, and matching
/// only the bare spellings sent every one of those to the decoder: `rar
/// rv1 arc.part1.rar` printed unrar's help and exited 7, which is a
/// worse answer than the creator's own refusal and is not what the
/// reference does either. `rr[N]`, `rv[N][p|%]` and `i[par]=<str>` are
/// therefore matched by shape. The creator's own parser reads the
/// argument out of the word again; this only has to decide the dialect.
pub(crate) fn is_creator_command(word: &str) -> bool {
    if matches!(
        word,
        "a" | "c"
            | "ch"
            | "cw"
            | "d"
            | "f"
            | "i"
            | "k"
            | "m"
            | "mf"
            | "r"
            | "rc"
            | "rn"
            | "rr"
            | "rv"
            | "s"
            | "u"
    ) {
        return true;
    }
    // `i[par]=<str>`: the parameters sit between the letter and the `=`.
    if let Some(rest) = word.strip_prefix('i') {
        if let Some((params, _)) = rest.split_once('=') {
            return params.chars().all(|c| c.is_ascii_alphabetic());
        }
    }
    // `s`, `s-` and `s<module>` are one command with three spellings,
    // and until 17 Sep 2026 only the bare `s` was matched here - so
    // `rarfast s- arc.rar` and `rarfast smymod.sfx arc.rar` went to the
    // DECODER, which has no `s` at all, and answered unrar's help screen
    // with exit 7. That is what made the module-name forms read as a
    // parse failure when the creator's own parser had understood them
    // all along; under the `rar` name they were always routed correctly.
    // No decoder command begins with `s`, and the creator's parser takes
    // every `s`-led word for this command, so the predicates agree by
    // construction.
    if word.starts_with('s') {
        return true;
    }
    // `rr<N>` and `rv<N>`, the latter also spelled `<N>p` or `<N>%`.
    for prefix in ["rr", "rv"] {
        let Some(rest) = word.strip_prefix(prefix) else {
            continue;
        };
        let digits = rest.trim_end_matches(['p', 'P', '%']);
        if digits.len() + 1 < rest.len() {
            // More than one suffix character is not a spelling.
            continue;
        }
        if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) {
            return true;
        }
    }
    false
}

/// Whether a positional looks like the `<path_to_extract/>`.
fn looks_like_dest(arg: &str) -> bool {
    arg.ends_with('/') || (cfg!(windows) && arg.ends_with('\\'))
}

/// Puts one positional where it belongs: the command word, the archive,
/// a mask, or the destination.
///
/// Reference unrar 7.23, measured 8 Oct 2026 on macOS arm64. An argument
/// after the archive that ends in a separator is the destination wherever
/// it stands (`x arc b.txt out/ x/Sub` extracts both under `out`), and the
/// last of those and of `-op<path>` wins. On `x` and `e`, an argument with
/// no wildcard that names a directory ALREADY ON DISK (a link to one
/// included) is the destination too, if none was given before it: `x arc
/// Dir` over an earlier extraction writes the whole archive into `Dir`,
/// and does not select `Dir` from it. `t`, `p` and the listings have no
/// such rule. Until then only the LAST argument could be a destination,
/// and only by its separator.
fn place(text: String, positional: &mut Vec<String>, destination: &mut Option<Option<String>>) {
    if positional.len() >= 2 {
        if looks_like_dest(&text) {
            *destination = Some(Some(text));
            return;
        }
        let extracts = matches!(
            command(&positional[0]),
            Some(Command::ExtractFull | Command::ExtractFlat)
        );
        if extracts
            && destination.is_none()
            && !text.contains(['*', '?'])
            && std::path::Path::new(&text).is_dir()
        {
            *destination = Some(Some(format!("{text}/")));
            return;
        }
    }
    positional.push(text);
}

/// Parses a whole command line, `argv[0]` already removed.
pub(crate) fn parse(argv: &[OsString]) -> Result<Parsed, Refusal> {
    parse_with(argv, false)
}

/// [`parse`] for a binary called `unrar`: the same reading, and the `-m`
/// family as the REFERENCE `unrar` reads it ([`m_family_as_reference`]).
///
/// Under rarfast's own name the plain [`parse`] stands, so that a `-m`
/// spelling it refuses is handed to the `rar` dialect's parser, which owns
/// that family there (`rar::run_shared_command`).
pub(crate) fn parse_as_unrar(argv: &[OsString]) -> Result<Parsed, Refusal> {
    parse_with(argv, true)
}

/// The `-m` family as the reference `unrar` 7.23 reads it on a READ
/// command, for a binary called `unrar`: `None` where `rest` is not of the
/// family, else the reference's own verdict.
///
/// **What the reference does** (measured 3 Oct 2026 on macOS arm64 and
/// Linux x86-64, identical in every cell, on `l`, `t`, `x`, `p`, `v` and
/// `lb` alike). It
/// ACCEPTS, exits 0 and reads the archive as if the switch were not there:
///
/// - `-m0` to `-m5`, whatever follows the digit (`-m05`, `-m5x`, `-m3d`);
/// - `-mm` and anything after it (`-mm`, `-mm128m`, `-mm128x`, `-mm+`);
/// - `-ms` and `-mc` and anything after them (`-ms;txt`, `-mc63:128t+`);
/// - `-md<size>` (`-md64m`, `-md1g`, `-md128k`, `-md64`, `-mdx64m`);
/// - in either case of every letter (`-M3`, `-MM64M`, `-MT4`, `-ME`).
///
/// It REFUSES, exit 7: `-m` alone, `-m6` to `-m9`, `-mx`, `-mq`, `-mz`,
/// `-mta`, `-ma5`, and a `-md` with no size or a size it does not take
/// (`-md`, `-mdx`, `-mdm`, `-md0`, `-md64k`, `-md64x`, `-md64mb`,
/// `-md4096g`).
///
/// Until this was measured every one of the accepted spellings but
/// `-mt<n>` and `-me` was refused here with `Unknown option`, exit 7: a
/// line the reference runs was a usage error under the `unrar` name.
///
/// **`-mm<size>` is swallowed too**, though it is rarfast's memory
/// ceiling under its own name. Honoured here it was seen from outside: a
/// `-m3 -md32m` member under `unrar t -mm64m` exits 0 in the reference and
/// was refused for memory, exit 2. Under this name a caller relies on the
/// reference's outcome, and a failure where `unrar` succeeds is the worse
/// breach; the promise of a named `-mm` belongs to rarfast's own name.
///
/// **`-md`'s size is read by a rule FITTED to the reference's verdicts**
/// on some 150 spellings ([`dictionary_spelling`]); it is not a rule any
/// specification states, and a sentence for it is missing there. A dictionary
/// size means nothing to a read, so nothing is done with one either way.
fn m_family_as_reference(rest: &str, opts: &mut Options) -> Option<Result<(), Refusal>> {
    let lower = rest.to_ascii_lowercase();
    let tail = lower.strip_prefix('m')?;
    Some(match tail.as_bytes().first() {
        Some(b'0'..=b'5' | b's' | b'c' | b'm') => Ok(()),
        Some(b'd') if dictionary_spelling(&tail[1..]) => Ok(()),
        Some(b'd') => Err(unknown_option(rest)),
        // `-mt<n>`, `-me[par]`, `-mlp` and every refusal: the plain
        // reading, in either case, the refusal naming the text as typed.
        _ => switch(&lower, opts).map_err(|_| unknown_option(rest)),
    })
}

/// Whether the text after `-md` is a size the reference `unrar` takes, as
/// far as it was measured ([`m_family_as_reference`]): an optional `x`,
/// digits, and at most one unit letter of `k`, `m` and `g` (none counts
/// megabytes), from 128 KiB to 1,024 GiB. Up to 4 GiB the size must be a
/// power of two or less than a 32nd above one (`-md64m`, `-md65m` and
/// `-md129k` are taken; `-md66m`, `-md3`, `-md200k` and `-md4095m` are
/// refused); above 4 GiB every size is taken (`-md5g`, `-md4097m`).
fn dictionary_spelling(text: &str) -> bool {
    let text = text.strip_prefix('x').unwrap_or(text);
    let digits = text.bytes().take_while(u8::is_ascii_digit).count();
    let (number, unit) = text.split_at(digits);
    let Ok(number) = number.parse::<u64>() else {
        return false;
    };
    let unit: u64 = match unit {
        "k" => 1 << 10,
        "" | "m" => 1 << 20,
        "g" => 1 << 30,
        _ => return false,
    };
    let Some(bytes) = number.checked_mul(unit) else {
        return false;
    };
    if !(128 << 10..=1024 << 30).contains(&bytes) {
        return false;
    }
    // The power of two at or under the size, and how far past it.
    let power = 1u64 << bytes.ilog2();
    bytes > 4 << 30 || (bytes - power) < power / 32
}

fn parse_with(argv: &[OsString], as_unrar: bool) -> Result<Parsed, Refusal> {
    let mut opts = Options::new();
    let mut positional: Vec<String> = Vec::new();
    // The first `--` ends the switches wherever it stands - before the
    // command word, after it, or after the archive - and is not itself a
    // name; everything after it is positional, a second `--` and a lone
    // `-` included. Measured against unrar 7.23 on 15 Sep 2026:
    // `-- l arc.rar` and `l arc.rar --` both list, `l -- -- arc.rar`
    // opens `--.rar`, `l -- arc.rar -` lists with `-` as a mask, and
    // `-- -- l arc.rar` takes `--` for the command word.
    let mut switches_ended = false;
    // Where the files go, in the order the command line gives it: `Some`
    // of a path for an argument that is one, `Some(None)` where a later
    // `-op<path>` took over, which the dispatch reads from the options.
    let mut destination: Option<Option<String>> = None;
    for arg in argv {
        let text = os_to_string(arg);
        if switches_ended {
            place(text, &mut positional, &mut destination);
        } else if text == "--" {
            switches_ended = true;
        } else if let Some(rest) = text.strip_prefix('-') {
            let family = if as_unrar {
                m_family_as_reference(rest, &mut opts)
            } else {
                None
            };
            family.unwrap_or_else(|| switch(rest, &mut opts))?;
            if rest.strip_prefix("op").is_some_and(|path| !path.is_empty()) {
                destination = Some(None);
            }
        } else {
            place(text, &mut positional, &mut destination);
        }
    }

    let mut iter = positional.into_iter();
    let command = iter.next().as_deref().and_then(command);
    let archive = iter.next();
    let mut masks: Vec<String> = iter.collect();
    let extract_path = destination.flatten();

    // `@listfile` positionals, unless `-@` turned them off.
    if opts.file_lists {
        let mut expanded = Vec::with_capacity(masks.len());
        let mut listed = false;
        for mask in masks {
            match mask.strip_prefix('@') {
                Some(list) if !list.is_empty() => {
                    listed = true;
                    expanded.extend(read_mask_list(list, &mut opts.unreadable_list));
                }
                _ => expanded.push(mask),
            }
        }
        // A list that holds no name selects NOTHING, where no mask at all
        // selects everything: reference unrar 7.23 lists no name for
        // `lb arc.rar @empty.lst` and says `No files to extract`, exit 10,
        // for `x` and `t` (measured 4 Oct 2026).
        if listed && expanded.is_empty() {
            expanded.push(NO_NAME.to_owned());
        }
        masks = expanded;
    }

    Ok(Parsed {
        command,
        archive,
        masks,
        extract_path,
        opts,
    })
}

/// Command-line text the reference would pass through byte for byte.
/// Rust's `OsStr` cannot promise UTF-8, and a lossy conversion is the
/// only portable answer that does not lose the argument entirely.
fn os_to_string(arg: &OsStr) -> String {
    arg.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_str(args: &[&str]) -> Result<Parsed, Refusal> {
        let owned: Vec<OsString> = args.iter().map(OsString::from).collect();
        parse(&owned)
    }

    fn as_unrar(args: &[&str]) -> Result<Parsed, Refusal> {
        let owned: Vec<OsString> = args.iter().map(OsString::from).collect();
        parse_as_unrar(&owned)
    }

    /// The `-m` family under the `unrar` name, cell by cell from the table
    /// measured against reference unrar 7.23 on 3 Oct 2026 (macOS and
    /// Linux alike).
    #[test]
    fn the_m_family_is_read_as_the_reference_unrar_reads_it() {
        // Accepted, exit 0, on every command.
        for spell in [
            "m0",
            "m1",
            "m2",
            "m3",
            "m4",
            "m5",
            "m05",
            "m5x",
            "m50",
            "m3d",
            "M3",
            "mm",
            "mm0",
            "mmx",
            "mm64m",
            "mm128m",
            "mm256m",
            "mm512m",
            "mm128x",
            "mm+",
            "mm-",
            "mmm",
            "MM64m",
            "mM",
            "md1",
            "md2",
            "md64",
            "md64m",
            "md64g",
            "md1g",
            "md128k",
            "md129k",
            "md256k",
            "md1024k",
            "md4096m",
            "md65g",
            "md1024g",
            "md1024",
            "md65536",
            "md1048576",
            "md00064m",
            "md64M",
            "md64G",
            "mD64m",
            "mdx64m",
            "ms",
            "msx",
            "ms;txt",
            "mstxt;doc",
            "mc",
            "mcx",
            "mc63:128t+",
            "mc-",
            "mca",
            "me",
            "mex",
            "met",
            "mes",
            "ME",
            "mt1",
            "mt4",
            "mt64",
            "Mt4",
            "MT4",
            "mT4",
            "mlp",
            "Mlp",
        ] {
            for command in ["l", "t", "x", "p", "v", "lb"] {
                let line = [command, &format!("-{spell}"), "arc.rar"];
                assert!(as_unrar(&line).is_ok(), "{command} -{spell} was refused");
            }
        }
        // Refused, `Unknown option` naming the text as typed, exit 7.
        for spell in [
            "m",
            "m6",
            "m7",
            "m9",
            "mx",
            "mq",
            "mz",
            "mta",
            "ma5",
            "mt",
            "mt0",
            "mt65",
            "md",
            "mdx",
            "mdm",
            "mdk",
            "md0",
            "md0k",
            "md0m",
            "md0g",
            "md1k",
            "md64k",
            "md64K",
            "md100k",
            "md127k",
            "md64x",
            "md64mx",
            "md64mb",
            "md64b",
            "md64t",
            "md1t",
            "md4096g",
            "md99999999g",
            "md99999999999999999999",
            "md+64m",
            "md64.",
            "md6.4m",
            "M6",
            "MDX",
        ] {
            for command in ["l", "t", "x", "p", "v", "lb"] {
                let err = as_unrar(&[command, &format!("-{spell}"), "arc.rar"])
                    .expect_err("the reference refuses it");
                assert_eq!(err.message, format!("\nERROR: Unknown option: {spell}"));
                assert_eq!(err.exit, Exit::BadCommandLine, "-{spell}");
            }
        }
    }

    /// The reference's verdict on a `-md` size, spelling by spelling as
    /// measured (3 Oct 2026, the `-md`
    /// ladder): the rule here is fitted to these and stated nowhere else.
    #[test]
    fn a_dictionary_size_is_taken_where_the_reference_takes_it() {
        for spell in [
            "md1",
            "md2",
            "md4",
            "md64",
            "md1024",
            "md8192",
            "md65536",
            "md1048576",
            "md1047552",
            "md128k",
            "md129k",
            "md130k",
            "md256k",
            "md257k",
            "md512k",
            "md513k",
            "md1024k",
            "md1025k",
            "md2049k",
            "md4096k",
            "md4097k",
            "md4200k",
            "md1m",
            "md64m",
            "md65m",
            "md2049m",
            "md2100m",
            "md4096m",
            "md4097m",
            "md4608m",
            "md5000m",
            "md1g",
            "md2g",
            "md4g",
            "md5g",
            "md6g",
            "md7g",
            "md12g",
            "md24g",
            "md64g",
            "md1023g",
            "md1024g",
            "md4194305k",
            "md8388608k",
            "md1073741824k",
            "mdx64m",
            "mdx5g",
        ] {
            assert!(
                as_unrar(&["t", &format!("-{spell}"), "arc.rar"]).is_ok(),
                "-{spell}"
            );
        }
        for spell in [
            "md3",
            "md5",
            "md6",
            "md12",
            "md24",
            "md48",
            "md96",
            "md100",
            "md192",
            "md1048577",
            "md127k",
            "md135k",
            "md136k",
            "md144k",
            "md192k",
            "md200k",
            "md255k",
            "md264k",
            "md300k",
            "md384k",
            "md540k",
            "md768k",
            "md1100k",
            "md1536k",
            "md4095k",
            "md4400k",
            "md5000k",
            "md3m",
            "md6m",
            "md66m",
            "md68m",
            "md80m",
            "md96m",
            "md100m",
            "md2200m",
            "md3000m",
            "md4000m",
            "md4095m",
            "md3g",
            "md1025g",
            "md2048g",
            "md3072g",
            "md4095g",
            "md1073741825k",
            "mdx3",
            "mdx2048g",
        ] {
            assert!(
                as_unrar(&["t", &format!("-{spell}"), "arc.rar"]).is_err(),
                "-{spell}"
            );
        }
    }

    /// Under the `unrar` name NO `-mm` spelling sets a memory ceiling: the
    /// reference swallows the switch, so a member the named size could not
    /// hold is still read (measured: `unrar t -mm64m` on a `-md32m` member
    /// exits 0). Every other accepted `-m` switch changes nothing either;
    /// `-mt<n>` still sets the width, in either case.
    #[test]
    fn no_mm_spelling_is_a_ceiling_under_the_unrar_name() {
        for spell in [
            "-mm128m", "-MM64M", "-mm2g", "-mm512", "-mm8m", "-mm", "-mm128x", "-mm0", "-mm+",
            "-mm-", "-m5", "-md64m", "-ms", "-mc",
        ] {
            let opts = as_unrar(&["x", spell, "arc.rar"]).expect("accepted").opts;
            assert_eq!(opts.memory_cap, None, "{spell}");
        }
        let threads = |spell: &str| {
            as_unrar(&["t", spell, "arc.rar"])
                .expect("accepted")
                .opts
                .threads
        };
        assert_eq!(threads("-MT4"), Some(4));
        assert_eq!(threads("-mt4"), Some(4));
        assert_eq!(threads("-m5"), None);
    }

    /// Under rarfast's OWN name the plain parse stands: it refuses the
    /// family, so the line is handed to the `rar` dialect's parser, which
    /// owns `-m` there (`rar::run_shared_command`).
    #[test]
    fn the_plain_parse_still_refuses_the_m_family() {
        for spell in ["m5", "mm128m", "mm", "md64m", "ms", "mc", "MT4"] {
            let err = parse_str(&["t", &format!("-{spell}"), "arc.rar"]).expect_err("refused");
            assert_eq!(err.exit, Exit::BadCommandLine, "-{spell}");
        }
        assert!(parse_str(&["t", "-mt4", "arc.rar"]).is_ok());
    }

    /// The sizes `-sl` and `-sm` take, the rows no small file can show:
    /// the large units, the fraction, the wrap. No pool, no memory.
    #[test]
    fn a_size_is_read_by_its_last_character_and_its_point() {
        for (text, bytes) in [
            ("1g", 1_i64 << 30),
            ("1G", 1_000_000_000),
            ("1t", 1 << 40),
            ("1T", 1_000_000_000_000),
            ("2m", 2 << 20),
            ("2M", 2_000_000),
            ("1.5k", 1_536),
            ("1.25k", 1_280),
            ("1.999k", 2_046),
            ("1.9999999999k", 2_047),
            ("0.01k", 10),
            ("0.001k", 1),
            ("1.5.5k", 15_872),
            ("1..5k", 1_536),
            ("1x.5k", 1_536),
            ("1,5k", 15_360),
            ("1k2k", 12_288),
            ("1km", 1 << 20),
            ("1mk", 1 << 10),
            ("12x3", 123),
            ("1e3", 13),
            ("9223372036854775807", i64::MAX),
            ("9223372036854775808", i64::MIN),
            ("18446744073709551615", -1),
            ("18446744073709551616", 0),
            ("16777216t", 0),
        ] {
            assert_eq!(size_limit(text), Some(bytes), "{text}");
        }
        for text in ["", "k", "x5", "-5", "+5", " 5", ".5k"] {
            assert_eq!(size_limit(text), None, "{text:?}");
        }
    }

    /// Every row of the 10 Oct 2026 measurement (rar and unrar 7.23 on
    /// macOS arm64, which agree on all of them and exit 0 on all of them):
    /// `lb -sl<text>` and `lb -sm<text>` over archives of header-only
    /// members whose declared sizes close on the limit from both sides,
    /// so each size here is the reference's to the byte. A size below
    /// zero cannot be told from another below zero by a listing, so those
    /// rows pin the sign alone. No pool, no memory.
    #[test]
    fn every_measured_size_spelling_reads_as_the_reference_read_it() {
        for (text, bytes) in MEASURED_SIZES {
            assert_eq!(size_limit(text), Some(*bytes), "{text:?}");
        }
        for text in MEASURED_BELOW_ZERO {
            assert!(
                matches!(size_limit(text), Some(bytes) if bytes < 0),
                "{text:?}: got {:?}",
                size_limit(text)
            );
        }
        for text in MEASURED_NO_SIZE {
            assert_eq!(size_limit(text), None, "{text:?}");
        }
    }

    /// Every spelling whose size is a count of bytes, zero or more.
    const MEASURED_SIZES: &[(&str, i64)] = &[
        ("0", 0),
        ("1", 1),
        ("2", 2),
        ("4", 4),
        ("5", 5),
        ("6", 6),
        ("7", 7),
        ("8", 8),
        ("02", 2),
        ("0K", 0),
        ("0M", 0),
        ("0b", 0),
        ("0k", 0),
        ("0t", 0),
        ("1 ", 1),
        ("1.", 1),
        ("15", 15),
        ("17", 17),
        ("1B", 1),
        ("1E", 1),
        ("1G", 1_000_000_000),
        ("1K", 1000),
        ("1M", 1_000_000),
        ("1P", 1),
        ("1T", 1_000_000_000_000),
        ("1X", 1),
        ("1b", 1),
        ("1e", 1),
        ("1g", 1_073_741_824),
        ("1k", 1024),
        ("1m", 1_048_576),
        ("1p", 1),
        ("1t", 1_099_511_627_776),
        ("1x", 1),
        ("1z", 1),
        ("2K", 2000),
        ("2k", 2048),
        ("2t", 2_199_023_255_552),
        ("3M", 3_000_000),
        ("3k", 3072),
        ("3m", 3_145_728),
        ("40", 40),
        ("46", 46),
        ("4G", 4_000_000_000),
        ("4T", 4_000_000_000_000),
        ("5 ", 5),
        ("5-", 5),
        ("5.", 5),
        ("5G", 5_000_000_000),
        ("5g", 5_368_709_120),
        ("5x", 5),
        ("5\u{e9}", 5),
        ("5\u{663}", 5),
        ("64", 64),
        ("69", 69),
        ("6k", 6144),
        ("7T", 7_000_000_000_000),
        ("7t", 7_696_581_394_432),
        ("8.", 8),
        ("85", 85),
        ("8m", 8_388_608),
        ("95", 95),
        ("9T", 9_000_000_000_000),
        ("9t", 9_895_604_649_984),
        ("0.5", 0),
        ("0.9", 0),
        ("07T", 7_000_000_000_000),
        ("08k", 8192),
        ("09t", 9_895_604_649_984),
        ("1.0", 1),
        ("1.5", 1),
        ("1.9", 1),
        ("12g", 12_884_901_888),
        ("19g", 20_401_094_656),
        ("1:5", 15),
        ("1KB", 1),
        ("1Kb", 1),
        ("1Kk", 1024),
        ("1MB", 1),
        ("1e3", 13),
        ("1gb", 1),
        ("1k5", 15),
        ("1kB", 1),
        ("1kK", 1000),
        ("1kb", 1),
        ("1ki", 1),
        ("1kk", 1024),
        ("1km", 1_048_576),
        ("1m2", 12),
        ("1mb", 1),
        ("1mk", 1024),
        ("1t1", 11),
        ("1tb", 1),
        ("2.5", 2),
        ("25G", 25_000_000_000),
        ("280", 280),
        ("321", 321),
        ("34M", 34_000_000),
        ("34k", 34_816),
        ("390", 390),
        ("395", 395),
        ("44G", 44_000_000_000),
        ("5 k", 5120),
        ("5+3", 53),
        ("5-k", 5120),
        ("5.K", 5000),
        ("5.k", 5120),
        ("5gK", 5000),
        ("5k ", 5),
        ("5\u{e9}k", 5120),
        ("73k", 74_752),
        ("755", 755),
        ("756", 756),
        ("75G", 75_000_000_000),
        ("75M", 75_000_000),
        ("87K", 87_000),
        ("8xG", 8_000_000_000),
        ("999", 999),
        ("9Gb", 9),
        ("0.1K", 100),
        ("0.1T", 100_000_000_000),
        ("0.1g", 107_374_182),
        ("0.1k", 102),
        ("0.1m", 104_857),
        ("0.1t", 109_951_162_777),
        ("0.2k", 204),
        ("0.3K", 300),
        ("0.3T", 300_000_000_000),
        ("0.3g", 322_122_547),
        ("0.3k", 307),
        ("0.3m", 314_572),
        ("0.3t", 329_853_488_332),
        ("0.5K", 500),
        ("0.5e", 0),
        ("0.5k", 512),
        ("0.7K", 700),
        ("0.7T", 700_000_000_000),
        ("0.7k", 716),
        ("0.7m", 734_003),
        ("0.7t", 769_658_139_443),
        ("0.99", 0),
        ("08xb", 8),
        ("0T5.", 5),
        ("0x10", 10),
        ("1,5k", 15_360),
        ("1,6M", 16_000_000),
        ("1.0k", 1024),
        ("1.5.", 15),
        ("1.5E", 1),
        ("1.5G", 1_500_000_000),
        ("1.5K", 1500),
        ("1.5M", 1_500_000),
        ("1.5T", 1_500_000_000_000),
        ("1.5g", 1_610_612_736),
        ("1.5k", 1536),
        ("1.5m", 1_572_864),
        ("1.5t", 1_649_267_441_664),
        ("1.k5", 1),
        ("1/2k", 12_288),
        ("1000", 1000),
        ("1001", 1001),
        ("11KG", 11_000_000_000),
        ("12x3", 123),
        ("139m", 145_752_064),
        ("1413", 1413),
        ("1E3k", 13_312),
        ("1K2k", 12_288),
        ("1KiB", 1),
        ("1e3k", 13_312),
        ("1g5m", 15_728_640),
        ("1k2K", 12_000),
        ("1k2k", 12_288),
        ("1kib", 1),
        ("1x51", 151),
        ("2.9k", 2969),
        ("221.", 221),
        ("263g", 282_394_099_712),
        ("2g0m", 20_971_520),
        ("3.3T", 3_300_000_000_000),
        ("3.3t", 3_628_388_371_660),
        ("3600", 3600),
        ("375G", 375_000_000_000),
        ("445.", 445),
        ("496g", 532_575_944_704),
        ("530.", 530),
        ("58m8", 588),
        ("789b", 789),
        ("80t ", 80),
        ("94k3", 943),
        ("9M.M", 9_000_000),
        ("9t.K", 9000),
        ("9t18", 918),
        ("9xbM", 9_000_000),
        ("0.01k", 10),
        ("0.50k", 512),
        ("00.5k", 512),
        ("00015", 15),
        ("0x10k", 10_240),
        ("1 000", 1000),
        ("1,000", 1000),
        ("1..5k", 1536),
        ("1.00k", 1024),
        ("1.10k", 1126),
        ("1.25k", 1280),
        ("1.5.k", 15_360),
        ("1.5e3", 1),
        ("1.5k5", 1),
        ("1.75k", 1792),
        ("1.x5k", 1536),
        ("10.1k", 10_342),
        ("1000K", 1_000_000),
        ("1023k", 1_047_552),
        ("1024k", 1_048_576),
        ("15.5k", 15_872),
        ("1614m", 1_692_401_664),
        ("1_000", 1000),
        ("1x.5k", 1536),
        ("2971K", 2_971_000),
        ("3358m", 3_521_118_208),
        ("4542M", 4_542_000_000),
        ("4684g", 5_029_406_703_616),
        ("4MK.M", 4_000_000),
        ("5939g", 6_376_952_692_736),
        ("6M0,K", 60_000),
        ("7,TM.", 7),
        ("7.M8T", 7_800_000_000_000),
        ("8241K", 8_241_000),
        ("86t4k", 884_736),
        ("91705", 91_705),
        ("0.001k", 1),
        ("0.5.5k", 5632),
        ("0.500k", 512),
        ("0.999K", 999),
        ("000.5k", 512),
        ("1,5.5k", 15_872),
        ("1.010k", 1034),
        ("1.100k", 1126),
        ("1.5,5k", 1587),
        ("1.5.5k", 15_872),
        ("1.5k5k", 1587),
        ("1.5x5k", 1587),
        ("1.999k", 2046),
        ("100.1k", 102_502),
        ("1024.5", 1024),
        ("1024.9", 1024),
        ("26gt.3", 26),
        ("530-8T", 5_308_000_000_000_000),
        ("563 50", 56_350),
        ("5b677.", 5677),
        ("6T78m5", 6785),
        ("758K8 ", 7588),
        ("984627", 984_627),
        ("0.0001k", 0),
        ("0.9999K", 999),
        ("0948 gb", 948),
        ("1.2.3.4", 123),
        ("1.5..5k", 15_872),
        ("1.9999k", 2047),
        ("1000.1k", 1_024_102),
        ("1167K3b", 11_673),
        ("1g0G58M", 1_058_000_000),
        ("425m235", 425_235),
        ("5,9-K0k", 604_160),
        ("59653G.", 59_653),
        ("5k46.0k", 559_104),
        ("6M,7b1.", 671),
        ("735486T", 735_486_000_000_000_000),
        ("85726 g", 92_047_591_604_224),
        ("939102b", 939_102),
        ("945.5M.", 9455),
        ("96m683.", 96_683),
        ("97-k865", 97_865),
        ("0.99999K", 999),
        ("1.2.3.4k", 126_361),
        ("8388607t", 9_223_370_937_343_148_032),
        ("8388608T", 8_388_608_000_000_000_000),
        ("9223372T", 9_223_372_000_000_000_000),
        ("098g60243", 9_860_243),
        ("0k.5.2148", 5),
        ("123456789", 123_456_789),
        ("16.325416", 16),
        ("16777216t", 0),
        ("16777217t", 1_099_511_627_776),
        ("18446745T", 926_290_448_384),
        ("22554-41k", 2_309_571_584),
        ("23241255.", 23_241_255),
        ("4.k9t.2 3", 49),
        ("4174.016K", 4_174_016),
        ("5824,363.", 5_824_363),
        ("733992193", 733_992_193),
        ("77T83698b", 7_783_698),
        ("822595072", 822_595_072),
        ("0023270TMK", 23_270_000),
        ("044b2659-M", 442_659_000_000),
        ("05182m0- t", 56_976_692_551_352_320),
        ("08b056g54.", 805_654),
        ("0xTb.9g49K", 949),
        ("146G4.kk7k", 1_499_852),
        ("15G 6-x1GT", 1_561_000_000_000_000),
        ("16b728888.", 16_728_888),
        ("18,9T1755t", 2_080_006_619_403_386_880),
        ("20355b941t", 3_934_849_750_112_665_600),
        ("2G56754-3.", 2_567_543),
        ("3.x2M,615g", 3_502_008_958),
        ("30kKG5x685", 305_685),
        ("4294967295", 4_294_967_295),
        ("4294967296", 4_294_967_296),
        ("4294967297", 4_294_967_297),
        ("499583602M", 499_583_602_000_000),
        ("526247702K", 526_247_702_000),
        ("527041G22k", 53_969_020_928),
        ("67116-,81k", 6_872_761_344),
        ("7246528715", 7_246_528_715),
        ("793-3227-b", 7_933_227),
        ("867771k65G", 86_777_165_000_000_000),
        ("9bGx14753k", 936_707_072),
        ("9x5T4M650K", 954_650_000),
        ("8589934591g", 9_223_372_035_781_033_984),
        ("0.000976562k", 0),
        ("0.123456789k", 126),
        ("0.0009765624k", 0),
        ("0.0009765625k", 1),
        ("0.0009765626k", 1),
        ("0.4999999999k", 511),
        ("0.5000000001k", 512),
        ("1.0009765625k", 1025),
        ("1.9999999999k", 2047),
        ("0.00097656250k", 1),
        ("00166m3742T359", 1_663_742_359),
        ("0433M874K5k6 4", 433_874_564),
        ("09.M9 3995.x9G", 993_995_900_000_000),
        ("2 52015292g303", 252_015_292_303),
        ("2.248t1k7930MT", 34_570_011_154),
        ("23 00G1664b8k1", 2_300_166_481),
        ("29174178653..3", 29_174_178_653),
        ("318855745T424 ", 318_855_745_424),
        ("4.K9K83708g784", 4),
        ("41M533T7783253", 415_337_783_253),
        ("429.2.70860g58", 4292),
        ("564G2770-.77Gg", 6_058_878_978_993_684),
        ("6k.t6 217g6051", 6),
        ("84x2624735t1m5", 84_262_473_515),
        ("86098100G6tMK6", 8_609_810_066),
        ("2168K7T73t5x0Tk", 222_082_406_400),
        ("35m54b.5-6680K5", 3554),
        ("46534763bg3752m", 487_952_360_409_137_152),
        ("4735071866M G4b", 47_350_718_664),
        ("4G734.g9921g22k", 4_848_631),
        ("4Mg07-848 T9.9G", 4_078_489_900_000_000),
        ("512186M8,M0G83.", 5_121_868_083),
        ("5539256.0M 288b", 5_539_256),
        ("58G7608534239,t", 3_651_538_588_983_623_680),
        ("77G4M.56.gG5x3G", 77_456_530_000_000),
        ("79x5M618858651G", 2_408_863_481_489_280_512),
        ("7Gk7x991381676k", 79_863_174_836_224),
        ("8.086.M.m31  4K", 8_086_314),
        ("873b2x58080554.", 873_258_080_554),
        ("9007199254740993", 9_007_199_254_740_993),
        ("18014398509481984k", 0),
        ("4503599627370497.5", 4_503_599_627_370_497),
        ("9007199254740992.5", 9_007_199_254_740_992),
        ("9007199254740993.0", 9_007_199_254_740_993),
        ("05b.81948366m08k711", 5),
        ("1104997953.58851-M7", 1_104_997_953),
        ("11265b6025004.715-k", 115_359_769_604_828),
        ("1152921504606846977", 1_152_921_504_606_846_977),
        ("22m2tM4- 577.415x88", 2_224_577),
        ("5K237m 241k9G97474M", 5_237_241_997_474_000_000),
        ("6 -50K9632466360G0x", 65_096_324_663_600),
        ("6.809449477770b0849", 6),
        ("60TM2305-,3T58M89.9", 60_230_535_889),
        ("7515k1 b9T7643.0308", 7_515_197_643),
        ("9-3MMb9773860gb7139", 9_397_738_607_139),
        ("9007199254740993.5k", 1536),
        ("9223372036854775806", 9_223_372_036_854_775_806),
        ("9223372036854775807", 9_223_372_036_854_775_807),
        ("067-5b-4t21919578863", 675_421_919_578_863),
        ("1-848756.06x3G.86705", 1_848_756_063),
        ("1.99999999999999999k", 18),
        ("10898Kt020M33578381k", 1_115_957_282_384_262_144),
        ("1424.65809k71k41552.", 1_424_658_097_141_552),
        ("18446744073709551616", 0),
        ("18446744073709551617", 1),
        ("2.27998074802791863m", 35),
        ("23.185t6061 7646382G", 78_017),
        ("263G7924501-.T1053b1", 2_637_924_501),
        ("3052Mt16954-08.4195m", 644_852_359_272_647),
        ("36893488147419103232", 0),
        ("36893488147419103247", 15),
        ("37387.128..KT1.58.71", 37_387_128_158),
        ("3k9,1124K29x910K51m4", 39_112_429_910_514),
        ("42710073.G77t3391, 5", 42_710_073),
        ("44.86929266047572156", 44),
        ("4820mT3t2078 -.55mbT", 18_655_903_969_416_273),
        ("4T7b7745784T1385874.", 4_777_457_841_385_874),
        ("53233396.3m38G7.m715", 532_333_963_387),
        ("5329830.5M55.338.9.g", 6_819_704_358_205_128_704),
        ("539gk86854140t7T6K4g", 8_273_357_530_478_936_064),
        ("570m3M8849877,954322", 57_038_849_877_954_322),
        ("6429585412b7.377m68x", 64_295_854_127),
        ("678.266.4759071-31t5", 678_266),
        ("768705006.662.05 47k", 787_153_926_821_944),
        ("77g5t6g.06T62002565m", 754_127_242),
        ("8 .xK942. 4mM48K728.", 8_942_448_728),
        ("8,k.M9gk52.11t54.K15", 89_521_154),
        ("884g8.2294m.364935bb", 88_482_294),
        ("8t2 T.02398015T-t46K", 82_023),
        ("92233720368547758.07", 92_233_720_368_547_758),
        ("922337203685477580.7", 922_337_203_685_477_580),
        ("99999999999999999999", 7_766_279_631_452_241_919),
        ("9b892438610.8322x.11", 98_924_386_108_322),
        ("0.087916539417216931m", 8),
        ("0.2k2 G642772449010k.", 22_642_772_449_010),
        ("0.xt219G04857.411k748", 21_904_857),
        ("032x4.6K5t334m8M3211x", 324),
        ("1.4992543654223979123", 0),
        ("100000000000000000000", 7_766_279_631_452_241_920),
        ("102029g.60.0M068T3.8b", 1_020_296_000_683),
        ("134-b46319G2k8.42T884", 1_344_631_928),
        ("13997M357895 9m.3712T", 367_386_782_771_124),
        ("184467440737095516.15", 0),
        ("1844674407370955161.5", 0),
        ("1844674407370955161.6", 0),
        ("19T9184947-g919484567", 199_184_947_919_484_567),
        ("21991,882M6.30,2 5. b", 2_199_188_263_025),
        ("2608G857419870536614t", 469_401_305_106_874_368),
        ("2957m08.,,492 13 1..M", 295_708_492_131_000_000),
        ("375685m1.257M0588.735", 37_568_512_570_588),
        ("4606Gkx0b20k1619k4375", 460_602_016_194_375),
        ("5.5t2b9TK8520093g.g4g", 346_752_793_717_401_190),
        ("6-9571,7K710854399758", 695_717_710_854_399_758),
        ("65273.77g7M7411M378..", 652_737_777_411_378),
        ("6K09474b,23610340g825", 60_947_423_610_340_825),
        ("6x2.357660-3114T08081", 62),
        ("7...7661,770449581t09", 7),
        ("8-40,0gKx844449440g28", 840_084_444_944_028),
        ("89582042g6432268t88gt", 63_340_665_852_919_808),
        ("9223372036854775807.5", 0),
        ("943.89777KG8b,573b3,9", 943),
        ("976M84469Gb.78k63457b", 97_684_469),
        ("985482tK8x16505 7MG..", 9_854_828_165_057),
        ("0.1234567890123456789k", 1),
        ("110M8174,033,91m7M103K", 1_108_174_033_917_103_000),
        ("14.325391484263067608m", 4),
        ("14.4kK569674k91g34958k", 14_803),
        ("18446744073709551616.0", 0),
        ("19tt3303 483608822791m", 569_746_684_413_739_008),
        ("25.161633684698830812t", 0),
        ("2809k42.21.2G736b1458b", 28_094_221),
        ("29599.8388K085t6K8384.", 29_599_838_808_568_384),
        ("354T4T6Tx8887494319T8.", 3_544_688_874_943_198),
        ("3948227g9352Km1.MM-5g.", 3_948_227_935_215),
        ("3Gg76 1 .316K339344915", 3761),
        ("4.7272904749400823092g", 0),
        ("453716.9254b87k6313.9g", 175_149_069_018_700_185),
        ("4587.674MgT.x016 835.m", 4_810_524_869_876_776_960),
        ("5-321158442T08x073t4gT", 2_807_146_210_437_357_568),
        ("54T45010m269521K34197t", 5_854_174_839_744_495_616),
        ("6213-31.13M2T41b329tmG", 44_792_010_752),
        ("7.,5G933x10095-1m.x9kT", 768_321_289_372_683_059),
        ("72185202.917983651,04b", 72_185_202),
        ("72413060b1.5b3x0670k0k", 741_509_735_967),
        ("9.90437028797178685645", 0),
        ("92811M6T4962m2t37-..55", 9_281_164_962_237),
        ("999.k9-16.67,9g- 0M.5M", 9_999_166_790_500_000),
        ("0.00000000000000000001t", 0),
        ("0.99999999999999999999k", 0),
        ("1.00000000000000000000k", 0),
        ("1.50000000000000000000k", 0),
        ("37.6287847183811086508t", 1),
        ("4.75964251907468061815T", 0),
        ("5.98886804140821435590k", 0),
        ("60.4861718368168075247t", 0),
        ("8.49521833249979358133k", 0),
        ("88752.55596993775888009", 23),
        ("0.000000000000000000001t", 0),
        ("1.999999999999999999999k", 1),
        ("19193.177840653751104065", 8),
        ("40.43353378236548210904T", 1),
        ("47953.62491563494242196g", 16),
        ("54.84819507751019012486g", 0),
        ("65.01867495019741594806g", 0),
        ("7.012989937016441788361T", 1),
        ("0215173.51576653204-40K 3", 30_706),
        ("0763T963188.G3 902-.b8924", 7_639_631_883_902),
        ("07bbM51K5MG95,265808m2272", 7_515_952_658_082_272),
        ("099g6256588k594342.360m03", 73_919_384_908_864),
        ("0T,G.06792,-1K01909508967", 0),
        ("31.TG8816171402172t-50.44", 31_881_617_140_217_250),
        ("355.6135x7G48553Mb-GT1881", 355),
        ("4976-g9.8958-85mg54.6k660", 4_976_989_588_554),
        ("4g9M807x659t3.074224xk46.", 49_807_659_307_422_446),
        ("8.0085423355141719732270t", 2),
        ("9.7009846887061699209190T", 1),
        ("904g5,51736.4.6835640-7x1", 9_045_517_364),
        ("93.263325648456721562674T", 0),
        ("0.1098g24gG505.6345T2K545m", 51_657_800_280),
        ("24.6560416206052245910497T", 0),
        ("26261.9518317333050278856m", 0),
        ("292169.80 2K35386mt062.x95", 29_216_980_235_386_062),
        ("8-g208-5K818k158K.45K3530m", 711_013_389_800),
        ("8.66 36-5G8 M11m4-5T490M5g", 23_497),
        ("861x4,70.9b230m1k86777,6b.", 86_147_092_301_867_776),
        ("47816.0377660408178529697970", 0),
        ("99328.406330570283764554049g", 2),
        ("2.50000000000000000000000000k", 1),
        ("0.999999999999999999999999999k", 0),
        ("021m77mg3.47K3541Gx88.997m5500", 332_672_946_818),
        ("089 0Kk0066019817637G04m694968", 6_540_657_498_967_877_816),
        ("1.9T871t2,- 84K9 1050-56k5.184", 1_987_128_491_050_565),
        ("19b23G39890 6000t523K7k29103-k", 1_614_994_567_472_561_152),
        ("5915260189340379T8540420460066", 921_010_285_941_698_082),
        ("0.0000000000000000000000000001t", 0),
        ("22m460678g4964g.b8-5xm 78G33K3m", 323_864_631_438),
        ("232g-2708M.T454812K910m3,4g486K", 78_908),
        ("2M8G908144x356-975b1Gm8470TT68t", 3_490_461_235_026_067_456),
        ("34.8m-G255048b316-05335G497612m", 0),
        ("5-9 76k862T,9-T3b390M21805.675m", 4_284_337_391_641_034),
        ("59251Tb96.0,10.m036x852k-3.TT4K", 222_379_064_497_958_228),
        ("7.489.G190.80mG42..t022954163tG", 687_978_332),
        ("7xg7.25,5384b0614.T 2475b859.8g", 345_151_193_540_775_116),
        ("95Kg5.g170113b37T53mM6651k2.81k", 47_825_308_294_882_437),
        ("963463,89T.963356G1332,7002t38g", 614),
        ("1.12345678901234567890123456789k", 0),
        ("0.838325716813740038707207141108t", 0),
        ("1.000000000000000000000000000000k", 0),
        ("1.473989990103761399590378546710g", 1),
        ("9.540846160747254352565972837926T", 0),
        ("05527.395324604574952516537786751567t", 0),
        ("0000000000000000000000000000000000000007", 7),
        ("44834.8220614545791811950364688395430767247555T", 1),
        ("66940.6611196575084624052717823215025387180290T", 0),
        ("3.85231028253261774322352605924514469209089732831927t", 0),
        ("10.50686505817642572507385490962222364068014416136038m", 0),
        ("14.18396083245979323928277771832377033677122383369695T", 0),
        ("97.57556825611969532675575328063304479570720281578087T", 0),
        ("47774.76875421544300152216707064422490649290213937648557T", 0),
        ("0.866658361420662991859179657064445001519179096344494416741691t", 1),
        ("2.548812292438441286035024538089030306249328987382636347232837g", 2),
        ("7.007626872577406867585747049922817695665354921886351360750273t", 0),
        ("0.0000000000000000000000000000000000000000000000000000000000000001", 1),
        ("0.0000000000000000000000000000000000000000000000000000000000000003", 3),
        ("0.0000000000000000000000000000000000000000000000000000000000000009", 9),
        ("0.0000000000000000000000000000000000000000000000000000000000000010", 10),
        ("0.1111111111111111111111111111111111111111111111111111111111111111", 8_198_552_921_648_689_607),
        ("1.0000000000000000000000000000000000000000000000000000000000000000", 0),
        ("1.0000000000000000000000000000000000000000000000000000000000000001", 1),
        ("2.0000000000000000000000000000000000000000000000000000000000000005", 5),
        ("3.432076810985351178719583114677209831736897906281259961817445637g", 0),
        ("7.3333333333333333333333333333333333333333333333333333333333333333", 6_148_914_691_236_517_205),
        ("0.11111111111111111111111111111111111111111111111111111111111111111", 8_198_552_921_648_689_607),
        ("0.1111111111111111111111111111111111111111111111111111111111111111k", 2_049_638_230_412_172_288),
        ("04096.940821594957265522552468154580437078900409017972549900260335m", 2),
        ("06.443538341997222720303178659220825428313559750831638200446376382T", 0),
        ("4.05943627210072656247752728463234939023936237786369372466471885910", 5_114_558_306_081_692_758),
        ("97.112836846630643219198914964695596483479908905321046064361843903K", 0),
        ("5.39539119313968822346079255283757154327575592408020641722742946297g", 3_026_786_728_716_271_616),
        ("61.9850094324884364607298338975703259901680786738252813650902555274K", 8_461_778_633_666_308_880),
        ("27479.538643296473919181665054034031920264518145994232373662485276496", 0),
        ("59300.785822616488421805030469620279142906027674884058297620676055571t", 0),
        ("89525.376019016999158925269480033718083356283543484086734662521943461K", 0),
        ("96209.995230417795336485730388169969680875920503117280766288200418293t", 0),
        ("46886.5758407222580340430076357664784365043629030252398177567703289673g", 4_803_920_036_886_478_848),
        ("22.6550474697783508329452530163878935751173116249280390096572936873251518K", 2_439_352_693_167_306_288),
        ("0.00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007", 7),
    ];

    /// Every spelling whose size wrapped below zero: `-sl` with it kept
    /// no file of any size and `-sm` with it kept every one.
    const MEASURED_BELOW_ZERO: &[&str] = &[
        "0039 K693k7.,323T1458t5m9M",
        "03.60714312201570142028691701486643721125133246657715007470847558584k",
        "05895G3,7923811872630K",
        "06076.061306154777415639K",
        "06129.817653410154572878221428626348853970018531961137241715266771T",
        "075888G,16gt1092M661t",
        "09.3561513747K62548K",
        "09234.606872613782843619k",
        "0m3g776629.1912.k4224t2mM089k2M",
        "1,98288.m0x59.8791041275258 36M",
        "1.25347842687076628198743148291727382141463468680355722018447915704",
        "1.9999999999999999999999999999999999999999999999999999999999999999",
        "1024.99999999999999999999",
        "1152921504606846977.0",
        "123456789.123456789k",
        "1234567890123.4567k",
        "123456789012345678901234567890",
        "12490.7121998445392897704769665578476673833923512429505073732971682569k",
        "1470376..25.-62G909t",
        "1493499339367440482m5",
        "1591t3Gb86010403491g",
        "164G.16g312468971.915g03x5",
        "16777215t",
        "18446744073709551614",
        "18446744073709551615",
        "18446744073709551615.0",
        "18446744T",
        "2.044310848036198062K",
        "2.603489,7-3610bg90293331K8883",
        "205G90T628088T022896G5k35t",
        "2067.6504x649 T471k6G",
        "249M 917426tb17060343m",
        "25.6989935745110147004909654527824548699948988826048227737116858614487597K",
        "2854 0942Mg475643,.75234T28g06m",
        "314k810065136092mtk7901 7",
        "35348m94662767408987K",
        "3675.225270M347,61178070m16423g",
        "36879.6488696766600894104211305825262982496300945827708369028172398299T",
        "38972274859200897411K",
        "39.8780378144577739296947897894821179051072179414908992254109350687345665T",
        "39159.464979519149251672K",
        "3M3.45G6941974.234,0g",
        "3m58897-6165t63xm54G4T",
        "3tT484774t24k05m613m",
        "3x4299178M652564x35831,33t",
        "4.225316272931681678718045307724338237730839605528285615469184g",
        "4.4562783804544322036576t",
        "4.46mbTx81108k-880G6,T 85m",
        "404094T69-29305718.8699Tg84616M",
        "43066.126472242203762363548g",
        "43885.8890645899130744575252926725781495994712840069723949619677386912609021g",
        "45534Kk3b,27375.g9t",
        "5.942111242764204942597439596301981544860601851586232029720432T",
        "51-k58761.1.g K135641490,t",
        "547k2mT832.101.t474258-m0t0866",
        "5644796458m.2 4.6974K9 12b3k-7.",
        "56708.1891162248867747949118334868310404404192392213994390909009585017K",
        "57301446T.27--5t641T",
        "6.40498970667025966k",
        "62.215981564323724325893962814157724491108175890538194790855265m",
        "64016-50924293554 49k",
        "64672.45584226463401625g",
        "67.2871244378364245132090m",
        "67600114M-701.M3569TT",
        "68.6052855862739570380178820939930594968992906050512806824343923822474884",
        "70.60t.7659g7942.tG72T",
        "74.65744346060855299572634654993963086584557718770188m",
        "75.2.8666865910m9503-9215",
        "76.790823383776754660K",
        "7t416125233557205K4887m96K",
        "8-22023526.25329.T1T",
        "81.7b.01 k8M74348022tg",
        "837489M00,2133730m558k1542G04m",
        "8388607.5t",
        "8388608t",
        "84972.308.,5800654K8-t",
        "85428.5056984924412381426768T",
        "8589934592g",
        "860671246893b55984 91g8T 5",
        "8796093022208m",
        "89.47085310548273933570478276896031579416923644447832145107087473096",
        "9007199254740992k",
        "9007199254740993k",
        "9223372036854775.807k",
        "9223372036854775807.0",
        "9223372036854775807K",
        "9223372036854775807k",
        "9223372036854775808",
        "9223372036854775809",
        "9223373T",
        "92G.x54G6t4 27G9284221mt181K79t",
        "93b.m284G752M2x021144g05605901K",
        "94.-158.36683,598T3x17030t",
    ];

    /// Every spelling that is no size: both switches kept every file.
    const MEASURED_NO_SIZE: &[&str] = &[
        "", "\t5", " 5", "+", "+5", "-", "--5", "-1k", "-5", "..5k", ".5", ".5k", "K", "K1", "abc",
        "k", "k1", "k5k", "m", "x", "x5", "\u{661}", "\u{ff15}",
    ];

    #[test]
    fn bare_dash_is_an_unknown_option_with_an_empty_name() {
        // The `stop-switch-scan` conformance row: unrar 7.23 refuses `-`
        // even though the help screen lists it as "Stop switches
        // scanning", and prints the switch text with the dash eaten.
        let err = parse_str(&["l", "-", "arc.rar"]).unwrap_err();
        assert_eq!(err.message, "\nERROR: Unknown option: ");
        assert_eq!(err.exit, Exit::BadCommandLine);
    }

    fn parsed(args: &[&str]) -> Parsed {
        match parse_str(args) {
            Ok(parsed) => parsed,
            Err(err) => panic!("{args:?} refused: {:?}", err.message),
        }
    }

    #[test]
    fn double_dash_ends_the_switches_wherever_it_stands() {
        // unrar 7.23, 15 Sep 2026: all three list `arc.rar` whole, so the
        // `--` is consumed in every position rather than read as a mask.
        for args in [
            ["l", "--", "arc.rar"],
            ["--", "l", "arc.rar"],
            ["l", "arc.rar", "--"],
        ] {
            let p = parsed(&args);
            assert!(p.command.is_some(), "{args:?}");
            assert_eq!(p.archive.as_deref(), Some("arc.rar"), "{args:?}");
            assert!(p.masks.is_empty(), "{args:?}");
        }
        let p = parsed(&["l", "arc.rar", "--", "a.txt"]);
        assert_eq!(p.masks, ["a.txt"]);
    }

    #[test]
    fn after_double_dash_every_argument_is_positional() {
        // `unrar l -- -x arc.rar` answers "Cannot open -x.rar".
        let p = parsed(&["l", "--", "-x", "arc.rar"]);
        assert_eq!(p.archive.as_deref(), Some("-x"));
        assert_eq!(p.masks, ["arc.rar"]);
        // Only the first `--` is special: `l -- -- arc.rar` opens `--.rar`.
        let p = parsed(&["l", "--", "--", "arc.rar"]);
        assert_eq!(p.archive.as_deref(), Some("--"));
        assert_eq!(p.masks, ["arc.rar"]);
        // A lone `-` after `--` is a mask (`0 files`), not a refusal.
        let p = parsed(&["l", "--", "arc.rar", "-"]);
        assert_eq!(p.masks, ["-"]);
        // `-- -- l arc.rar`: the second `--` is the command word, which is
        // no command, and `l` is the archive.
        let p = parsed(&["--", "--", "l", "arc.rar"]);
        assert!(p.command.is_none());
        assert_eq!(p.archive.as_deref(), Some("l"));
    }

    #[test]
    fn a_bare_dash_before_double_dash_is_still_refused() {
        let err = parse_str(&["l", "-", "--", "arc.rar"]).unwrap_err();
        assert_eq!(err.message, "\nERROR: Unknown option: ");
        assert_eq!(err.exit, Exit::BadCommandLine);
    }

    #[test]
    fn nosuchswitch_is_read_as_an_n_mask_not_as_an_unknown_option() {
        // The `bad-switch` row. Reading this as an unknown option is the
        // obvious mistake and it changes both the exit code (7 against 0)
        // and the whole listing.
        let parsed = parse_str(&["l", "-nosuchswitch", "arc.rar"]).expect("accepted");
        assert_eq!(parsed.opts.include, vec!["osuchswitch".to_owned()]);
    }

    #[test]
    fn every_inventoried_switch_parses() {
        // One spelling per line of the captured inventory's SWITCHES
        // block, minus the two `@` forms which are tested above. A
        // spelling that starts refusing here is a spelling the harness
        // will refuse the whole candidate for.
        for spell in [
            "ad",
            "ad1",
            "ad2",
            "ag_",
            "ai",
            "apsweepdir",
            "c-",
            "cfg-",
            "cl",
            "cu",
            "dh",
            "ep",
            "ep3",
            "ep4sweepdir",
            "f",
            "idc",
            "idd",
            "idn",
            "idp",
            "idq",
            "ierr",
            "inul",
            "kb",
            "mec",
            "nsweeplist.txt",
            "o",
            "o+",
            "o-",
            "ol",
            "ol-",
            "ola",
            "om",
            "om-",
            "om1",
            "opsweepdir",
            "or",
            "ow",
            "pswpass",
            "p-",
            "r",
            "scu",
            "si",
            "sl1000000",
            "ta20200101000000",
            "taa20200101000000",
            "tac20200101000000",
            "tam20200101000000",
            "tao20200101000000",
            "tb20200101000000",
            "tn20200101000000",
            "to20200101000000",
            "ts",
            "tsa",
            "tsc",
            "tsm",
            "tsp",
            "u",
            "v",
            "ver",
            "vp",
            "xsweeplist.txt",
            "y",
            // The five that exist only on the Windows screen.
            "ac",
            "ioff1",
            "mlp",
            "oc",
            "ri0:1",
        ] {
            let mut opts = Options::new();
            assert!(
                switch(spell, &mut opts).is_ok(),
                "-{spell} was refused; it is in the captured inventory"
            );
        }
    }

    #[test]
    fn list_spellings_map_to_the_four_layouts() {
        assert_eq!(
            command("lta"),
            Some(Command::List(ListStyle {
                verbose: false,
                bare: false,
                technical: true,
                technical_all: true,
            }))
        );
        assert_eq!(
            command("vb"),
            Some(Command::List(ListStyle {
                verbose: true,
                bare: true,
                technical: false,
                technical_all: false,
            }))
        );
        assert!(command("qq").is_none());
    }

    #[test]
    fn a_trailing_separator_makes_a_positional_the_destination() {
        let parsed = parse_str(&["x", "-y", "arc.rar", "out/"]).expect("accepted");
        assert_eq!(parsed.archive.as_deref(), Some("arc.rar"));
        assert!(parsed.masks.is_empty());
        assert_eq!(parsed.extract_path.as_deref(), Some("out/"));
    }

    #[test]
    fn a_stamp_parses_as_the_wall_clock_the_switch_named() {
        // The reference reads `-tn<stamp>` in the caller's own zone, so
        // the assertion is on the wall clock rather than on an instant:
        // pinning a UTC number here would pass only in one time zone.
        let at = parse_stamp("20200101000000");
        assert_eq!(super::super::time::short(at, false), "2020-01-01 00:00");
    }
}
