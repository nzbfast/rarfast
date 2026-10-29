//! The `rar` command line, parsed the way the reference parses it.
//!
//! `rar.exe` and `winrar.exe` share ONE syntax, so this file is the
//! parser for both; the switch set is not a reading of the manual but
//! the captured inventory,
//! the captured `rar` 7.23 inventory in the project's
//! harness, which is the pinned reference's own `-?` screen parsed into the
//! spellings a drop-in must accept. 118 of them on macOS, 130 on
//! Windows, and every one has an arm below. The conformance harness
//! probes each spelling and refuses a candidate that answers a usage
//! error where the reference did not, so deleting an arm to tidy up is
//! the same edit as failing the gate.
//!
//! Four shapes surprised the first draft and are pinned by tests at the
//! bottom, because all four are load-bearing rows in the matrix:
//!
//! - `-ht` on its own IS an unknown option (exit 7) while `-htb` and
//!   `-htc` are accepted. The captured probe table says so; the help
//!   screen's `ht[b|c]` line reads as though the bare form were legal.
//! - `-ma4` is NOT a switch this reference has: it answers
//!   `ERROR: Unknown option: ma4`, exit 7, because 7.23 cannot write
//!   RAR 4 at all, so the drop-in refuses it the same way. `-ma5` IS
//!   accepted, and an earlier record took the pair together and got this half
//!   wrong: re-measured 4 Sep 2026 by the `add-rar5` conformance row,
//!   `rar a -m0 -ma5 arc.rar text.txt` exits 0 and writes the same
//!   archive as without the switch, RAR 5 already being the only format
//!   it writes. Neither spelling is in the captured inventory, which is
//!   parsed from the help screen; the inventory is authoritative for
//!   what must be ACCEPTED and silent about what else may be.
//! - `-nosuchswitch` is not an unknown option here either: `n` takes a
//!   mask, so the reference reads `-n` with the mask `osuchswitch`.
//! - a bare `-` IS an unknown option, and the message names the switch
//!   text with the leading dash already eaten, so it prints empty.
//!
//! The decoder's own switch state lives in [`Shared`], which is the
//! `unrar` dialect's `Options` verbatim: `rar l` and `unrar l` produce
//! the same bytes for the same archive (measured 3 Sep 2026: identical
//! apart from the banner the harness normalises away), so the read-only
//! commands hand that struct straight to the decoder rather than growing
//! a second listing implementation that could drift from it.

use std::ffi::{OsStr, OsString};

use super::super::unrar::args::{reference_threads, Options as Shared, Overwrite, Refusal};
use super::super::unrar::Exit;

/// Which listing layout an `l`/`v` spelling selects, in the decoder's
/// own spelling so it can be handed over unchanged.
pub(crate) use super::super::unrar::args::ListStyle;

/// Every command in the captured inventory's COMMANDS block.
///
/// Twenty-nine spellings, twenty-three command letters. They are kept as
/// one enum rather than split into "creator" and "decoder" halves
/// because the split is not observable: `rar l` and `unrar l` are the
/// same command, and a caller who types `rar x` gets the decoder either
/// way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Command {
    /// `a`: put files into an archive, which is created if absent.
    Add,
    /// `c`: add an archive comment.
    Comment,
    /// `ch`: apply switches to an archive that exists, rewriting nothing else.
    ChangeParameters,
    /// `cw`: save the archive's comment into a file.
    CommentWrite,
    /// `d`: delete members.
    Delete,
    /// `e`: extract, discarding archived paths.
    ExtractFlat,
    /// `f`: freshen - update only members already in the archive.
    Freshen,
    /// `i[par]=<str>`: find a string in the archived data.
    Find,
    /// `k`: lock the archive against further modification.
    Lock,
    /// `l`, `lb`, `lt`, `lta`, `v`, `vb`, `vt`, `vta`.
    List(ListStyle),
    /// `m`, `mf`: add, then delete the source. `mf` moves files only.
    Move { files_only: bool },
    /// `p`: print a member to stdout.
    Print,
    /// `r`: repair.
    Repair,
    /// `rc`: rebuild absent volumes of a set from its `.rev` files.
    ReconstructVolumes,
    /// `rn`: rename archived members.
    Rename,
    /// `rr[N]`: append a recovery record to an archive that already exists.
    AddRecoveryRecord,
    /// `rv[N]`: write `.rev` files beside an existing volume set.
    AddRecoveryVolumes,
    /// `s[name|-]`: make an archive self-extracting, or strip the module.
    Sfx { remove: bool },
    /// `t`: test.
    Test,
    /// `u`: update - freshen, plus members not in the archive yet.
    Update,
    /// `x`: extract with full paths.
    ExtractFull,
}

impl Command {
    /// Whether the command only reads the archive, so the decoder can
    /// answer it. These are exactly the spellings `rar` and `unrar`
    /// share, plus nothing else: a command that writes is this dialect's
    /// own even when its output looks like a listing.
    pub(crate) fn is_read_only(self) -> bool {
        matches!(
            self,
            Self::ExtractFlat | Self::ExtractFull | Self::List(_) | Self::Print | Self::Test
        )
    }
}

/// How `-m0..-m5` was spelled: the reference's six compression levels.
///
/// The spec's non-goals are explicit that matching the reference's RATIO
/// is not part of the drop-in claim; producing a VALID archive the
/// reference extracts to source-identical bytes is. Level 0 is the one
/// level where the two agree byte for byte, because a store has nothing
/// for an encoder to choose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Level {
    /// `-m0`: store.
    Store,
    /// `-m1`: fastest.
    Fastest,
    /// `-m2`: fast.
    Fast,
    /// `-m3`: the reference's default, and ours.
    #[default]
    Normal,
    /// `-m4`: good.
    Good,
    /// `-m5`: best.
    Best,
}

impl Level {
    // `is_store` and `as_u8` read the level for the WRITER, which is
    // stubbed here (work package G): kept with the parser that fills the
    // field so the switch's meaning stays in one place.
    #![allow(dead_code)]

    fn from_digit(digit: u8) -> Option<Self> {
        Some(match digit {
            b'0' => Self::Store,
            b'1' => Self::Fastest,
            b'2' => Self::Fast,
            b'3' => Self::Normal,
            b'4' => Self::Good,
            b'5' => Self::Best,
            _ => return None,
        })
    }

    /// `true` for `-m0`, the one level that stores rather than packs.
    pub(crate) fn is_store(self) -> bool {
        self == Self::Store
    }

    /// The level as the writer's 0-5 number.
    pub(crate) fn as_u8(self) -> u8 {
        match self {
            Self::Store => 0,
            Self::Fastest => 1,
            Self::Fast => 2,
            Self::Normal => 3,
            Self::Good => 4,
            Self::Best => 5,
        }
    }
}

/// Which checksum `-ht` selects for file data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum HashType {
    /// `-htc`, and the reference's default for a new archive.
    #[default]
    Crc32,
    /// `-htb`: BLAKE2sp.
    Blake2sp,
}

/// How the archived name is derived from the path on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum PathMode {
    /// No `-ep*`: the path is stored as it was spelled, relative.
    #[default]
    AsGiven,
    /// `-ep`: store the base name only, with no folder path.
    NoPaths,
    /// `-ep1`: store names relative to the folder named on the command line.
    NoBaseDir,
    /// `-ep2`: Windows only, store the absolute path.
    FullPath,
    /// `-ep3`: store the absolute path with its drive letter.
    FullPathWithDrive,
}

/// The creator's own switch state.
///
/// Only the fields a WRITE needs are here; everything a read shares with
/// the decoder lives in `shared` and is handed over untouched.
#[derive(Debug, Clone, Default)]
pub(crate) struct Options {
    /// The decoder's switch state, for the read-only commands and for
    /// the extract half of a `-t` test-after-archiving run.
    pub(crate) shared: Shared,

    // --- what to write ---------------------------------------------
    /// `-m<0..5>`.
    pub(crate) level: Level,
    /// `-md<n>[kmg]`: the match window, in bytes.
    pub(crate) dictionary: Option<u64>,
    /// `-mm+`: trade memory for speed where a writer offers the choice.
    /// NOT a reference switch - rar 7.23 has no `-mm` and refuses it - so
    /// it is rarfast's own, spelled inside the `-m` family where rar
    /// already groups its compression parameters. Today the one writer
    /// that offers the trade is the stored archive with a recovery record
    /// (`-m0 -rr`): by default it streams the input in 84 MiB, and `-mm+`
    /// takes the in-memory writer, about a fifth faster for the whole
    /// input and archive in RAM. Both write the same bytes. `-mm-` is the
    /// default, spelled out. (14 Sep 2026: 0.595 s at 1,110 MiB against
    /// 0.719 s at 84 MiB over 512 MiB, the project's
    /// research notes, the bench of 14 Sep 2026, section 6.4.)
    ///
    /// `-mm+`, `-mm-` and `-mm<size>` are three spellings of ONE switch, so
    /// the last on the command line wins: a cap asks for the lean route,
    /// and `-mm+` or `-mm-` drops any cap before it.
    pub(crate) memory_for_speed: bool,
    /// `-mm<n>[kmg]`: a ceiling on the compressing encoder's working memory,
    /// in bytes (a bare number is megabytes, as `-md` counts). rarfast's own,
    /// like `-mm+`. It is a ceiling on the WHOLE PROCESS at every size: the
    /// library's memory policy for the create is taken with the process's
    /// headroom and what this binary holds beside the engine counted
    /// first (`create::options::mm_room`). Where the default plan cannot fit
    /// it, the create takes the narrow path: at most sixteen threads (fewer
    /// where `-mt` asks) and fewer blocks encoding at once (the same bytes
    /// at any width); a figure that holds the default plan keeps the
    /// machine's width. It caps the dictionary
    /// at the named size itself: a `-md` larger than it is refused, exit 2. A
    /// create whose encoder cannot fit inside the named size at its level
    /// and dictionary is refused before anything is written, naming the size
    /// that would do, exit 8; until 23 Oct 2026 it ran past the size in
    /// silence (`-md32m` under `-mm256m` held about 380 MiB). It bounds the
    /// encoder, not the input the in-memory routes (`-s`, `-rr`, encryption)
    /// read whole. Unset, nothing moves.
    ///
    /// It also bounds recovery volume creation (`rv`, and `-rv` beside it):
    /// one recovery volume's parity, the largest data volume's length, and
    /// the encoder's 1 MiB read buffer must fit inside the named size, or
    /// the run is refused before anything is written, naming the size that
    /// would do, exit 8. Unset, recovery volumes are made as before.
    pub(crate) memory_cap: Option<u64>,
    /// `-s`, `-s-`, `-s=<par>`: solid, or explicitly not.
    pub(crate) solid: bool,
    /// `-ds`: keep the order the files were found in, where a solid
    /// compressed archive would otherwise group them by type.
    pub(crate) keep_order: bool,
    /// `-ms[ext;ext]`: extensions to leave uncompressed.
    ///
    /// Recorded and not acted on, and that is a RATIO difference rather
    /// than a behaviour one: the members it names come out compressed
    /// instead of stored, and extract to the same bytes either way. The
    /// spec's non-goals make the reference's compression ratio
    /// explicitly not part of the drop-in claim, so this is the one
    /// place where accepting a switch and not honouring it is inside the
    /// contract. Every OTHER switch that would change what lands on disk
    /// is either honoured or refused - see the refusal list at the top
    /// of `create::add`.
    pub(crate) store_types: Vec<String>,
    /// `-ht[b|c]`.
    pub(crate) hash: HashType,
    /// `-qo`, `-qo+`, `-qo-`: the quick-open index.
    pub(crate) quick_open: Option<bool>,
    /// `-v<size>[u]`: volume size in bytes.
    pub(crate) volume_size: Option<u64>,
    /// `-rr[N]`: recovery-record percentage.
    pub(crate) recovery_percent: Option<u64>,
    /// `-rv[N]` as a switch, and `rv[N]` as a command: how many external
    /// `.rev` recovery volumes to write.
    pub(crate) recovery_volumes: Option<RecoveryVolumes>,
    /// `-z[file]`: where the archive comment comes from. An empty path
    /// means standard input, as it does at the reference.
    pub(crate) comment_file: Option<String>,
    /// `-hp[password]`: encrypt the headers as well as the data.
    pub(crate) encrypt_headers: bool,
    /// `-sfx[name]`: make a self-extracting archive with this module.
    pub(crate) sfx_module: Option<String>,
    /// `-vn`: the old `.rNN` volume naming rather than `.partN.rar`.
    pub(crate) old_volume_names: bool,

    // --- which files -----------------------------------------------
    /// `-ep`, `-ep1`, `-ep2`, `-ep3`.
    pub(crate) path_mode: PathMode,
    /// `-ed`: leave out folders that hold no files.
    pub(crate) no_empty_dirs: bool,
    /// `-r`, `-r0`, `-r-`.
    pub(crate) recurse: Recurse,
    /// `-sm<size>`: only files larger than this.
    pub(crate) size_more: Option<u64>,
    /// `-as`: synchronise, deleting archived members not on disk.
    pub(crate) synchronize: bool,
    /// `-u`: update as a switch rather than as a command.
    pub(crate) update: bool,
    /// `-f`: freshen as a switch rather than as a command.
    pub(crate) freshen: bool,

    // --- what happens afterwards -----------------------------------
    /// `-t`: test the archive once it is written.
    pub(crate) test_after: bool,
    /// `-df`: delete the source files afterwards.
    pub(crate) delete_after: bool,
    /// `-dw`: wipe them afterwards.
    pub(crate) wipe_after: bool,
    /// `-k`: lock the archive once it is written.
    pub(crate) lock_after: bool,
    /// `-tk`: keep the archive's original time.
    pub(crate) keep_archive_time: bool,
    /// `-tl`: date the archive by its newest member.
    pub(crate) archive_time_latest: bool,
    /// `-ag[format]`: generate the archive name from the clock.
    pub(crate) generate_name: Option<String>,
    /// `-w<path>`: the work directory for temporary files.
    pub(crate) work_dir: Option<String>,
    /// `-ilog[name]`: append error reports to this file.
    pub(crate) error_log: Option<String>,
    /// `-log[f][=name]`: log processed names to this file.
    pub(crate) name_log: Option<String>,
    /// `-iver`: print the version and do nothing else. It beats
    /// the command, whatever the command was - the `sweep/iver` row is
    /// `rar l -iver arc.rar` and its whole output is `7.23`.
    pub(crate) print_version: bool,
    /// Every switch on this command line that a CREATE reads and does
    /// not act on, as typed (dash included), each with what it asks for.
    ///
    /// A listing, a test and an extraction honour these spellings through
    /// `shared`, so they are legal here and only the creator refuses them
    /// (`create::unsupported_switch`). They are recorded where they are
    /// parsed, not re-derived from the fields they set, because a switch
    /// whose value does not parse sets no field and is ignored just the
    /// same.
    pub(crate) create_refuses: Vec<(String, &'static str)>,
    /// Every switch on this command line that a create reads, cannot act
    /// on, and until 8 Oct 2026 dropped without a word (`-oh`, `-ow`,
    /// `-oi`, most of `-ts`, `-am`, `-log`, the `-ag` forms that are not
    /// a date), as typed and each with what it asks for.
    ///
    /// Kept apart from [`Options::create_refuses`] only for the exit
    /// code: these answer 7, the reference's code for a command line it
    /// will not run, where the older list answers 2.
    pub(crate) create_declines: Vec<(String, &'static str)>,
    /// `-mc-`: no filter is looked for (`FilterPolicy::Off`).
    pub(crate) filters_off: bool,
    /// `-ts-`, `-tsm-`: store no modification time.
    pub(crate) no_mtime: bool,
    /// `-ai` on a create: store the default modes, not the files' own.
    pub(crate) default_modes: bool,
    /// The first `-n@<list>`, `-x@<list>` or `@<list>` file that could
    /// not be read, as the complaint the reference makes of it: `Cannot
    /// open <list>` and the reason on the next line.
    ///
    /// It was read as a list with nothing in it until 4 Oct 2026, so a
    /// mistyped include list meant "include everything". The creator
    /// stops on it before anything else (`create::add`).
    pub(crate) unread_list: Option<String>,
}

/// What a `-mc<par>` switch asks of a create, by what rar 7.23 was
/// measured to do with it (9 Oct 2026, `tests/create_mc_switches.rs`: 34
/// forms over a text, 16 bit sound, a table of 4 byte records and an
/// executable, `a -m3 -ma5`, each archive compared with the one written
/// with no switch). The reference exits 0 on every form, the ones it
/// does not know included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum McForm {
    /// `-mc-`: every filter off. Honoured.
    FiltersOff,
    /// A form after which the reference writes the bytes it writes with
    /// no switch at all, on all four members: the defaults spelled out
    /// (`-mcd+`), the RAR 4 family's text, colour and Itanium modules
    /// (`-mct-`, `-mcc+`, `-mci+`), and the ARM filter either way.
    NoChange,
    /// Everything else: one filter turned off alone (`-mcd-`, `-mce-`),
    /// a filter forced (`-mce+`, `-mc4:2d+`), the long range and the
    /// exhaustive search (`-mcl+`, `-mcx`). The writer looks for filters
    /// or does not ([`rarkit::FilterPolicy`]) and has no switch for one
    /// of them, so a create declines the command line by name.
    Declined,
}

impl McForm {
    /// `par` is what follows `-mc`; a letter's case does not matter.
    fn of(par: &str) -> Self {
        const NO_CHANGE: [&str; 19] = [
            "", "+", "d", "d+", "e", "a", "a-", "a+", "l", "l-", "x-", "t", "t+", "t-", "c+", "c-",
            "i+", "63:128t+", "z",
        ];
        let par = par.to_ascii_lowercase();
        if par == "-" {
            Self::FiltersOff
        } else if NO_CHANGE.contains(&par.as_str()) {
            Self::NoChange
        } else {
            Self::Declined
        }
    }
}

impl Options {
    /// Records `-<rest>` as a switch a create must refuse.
    fn create_refuses(&mut self, rest: &str, asks: &'static str) {
        self.create_refuses.push((format!("-{rest}"), asks));
    }

    /// Records `-<rest>` as a switch a create declines, exit 7.
    fn create_declines(&mut self, rest: &str, asks: &'static str) {
        self.create_declines.push((format!("-{rest}"), asks));
    }

    /// The masks a list file holds, or none, with the file recorded in
    /// [`Options::unread_list`], when it cannot be read.
    fn mask_list(&mut self, source: &str) -> Vec<String> {
        match read_mask_list(source) {
            Ok(masks) => masks,
            Err(err) => {
                self.unread_list.get_or_insert_with(|| {
                    format!(
                        "Cannot open {source}\n{}",
                        super::super::unrar::io_reason(&err)
                    )
                });
                Vec::new()
            }
        }
    }
}

/// How `-r` was spelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Recurse {
    /// No `-r` switch at all: a directory named on the command line is
    /// still walked, and a wildcard is not taken below its directory.
    #[default]
    Off,
    /// `-r-`: nothing is walked. A directory named on the command line
    /// is stored as its own entry and no more (measured against rar
    /// 7.23, 8 Oct 2026; until then this was read as [`Recurse::Off`]).
    Never,
    /// `-r`: recurse into subdirectories.
    On,
    /// `-r0`: descend into subfolders only for wildcard masks.
    WildcardsOnly,
}

/// A parsed `rar` command line.
#[derive(Debug, Clone)]
pub(crate) struct Parsed {
    /// The command word, absent when no argument named one.
    pub(crate) command: Option<Command>,
    /// The literal command word, kept for the messages that quote it.
    pub(crate) command_word: String,
    /// The archive path as spelled.
    pub(crate) archive: Option<String>,
    /// The `<files...>` positional block.
    pub(crate) masks: Vec<String>,
    /// The trailing `<path_to_extract/>`, recognised by its separator.
    pub(crate) extract_path: Option<String>,
    /// The string `i[par]=<str>` searches for. Parsed and not yet read:
    /// `i` is one of the four commands rarfast refuses (see
    /// [`super::unimplemented_command`]), and dropping the field would
    /// make the parser silently lose an argument the reference reads.
    #[allow(dead_code)]
    pub(crate) find_text: Option<String>,
    /// `rr<N>` / `rv<N>` as a COMMAND carry their number in the word.
    /// Parsed and not yet read, for the same reason as `find_text`.
    #[allow(dead_code)]
    pub(crate) command_number: Option<u64>,
    /// `s<name>`: the SFX module the command names.
    pub(crate) sfx_name: Option<String>,
    /// Every switch, already folded into behaviour.
    pub(crate) opts: Options,
}

/// How many `.rev` recovery volumes `rv[N]` and `-rv[N]` ask for.
///
/// The reference takes three spellings and they do not mean the same
/// thing, so the count cannot be a bare number here: `rv2` is two
/// volumes, `rv2p` and `rv2%` are two percent of the set (which is ONE
/// volume for anything under fifty), and a bare `rv` is neither - it is
/// the ten percent measured in
/// the engine's own `default_recovery_volume_count`. Collapsing them into
/// a number in the parser is how `-rv50p` quietly becomes fifty files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoveryVolumes {
    /// `rvN`: N volumes exactly.
    Count(u64),
    /// `rvN%` or `rvNp`: N percent of the data volume count, rounded up.
    Percent(u64),
    /// `rv` with no number at all.
    Default,
}

/// Reads the `[N][p|%]` tail the reference allows after `rv` and `-rv`.
///
/// `None` means the tail is not one of the shapes it accepts, which for
/// a COMMAND word means the word was never `rv` at all (`rvx` is not a
/// command) and for a SWITCH is an unknown option.
pub(crate) fn recovery_volume_spec(tail: &str) -> Option<RecoveryVolumes> {
    let (number, rest) = eat_number(tail);
    match (number, rest) {
        (None, "") => Some(RecoveryVolumes::Default),
        (Some(count), "") => Some(RecoveryVolumes::Count(count)),
        (Some(percent), "p" | "P" | "%") => Some(RecoveryVolumes::Percent(percent)),
        _ => None,
    }
}

fn unknown_option(rest: &str) -> Refusal {
    Refusal {
        message: format!("\nERROR: Unknown option: {rest}"),
        exit: Exit::BadCommandLine,
    }
}

/// Splits `<digits>` off the front, returning the rest.
fn eat_number(rest: &str) -> (Option<u64>, &str) {
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    if end == 0 {
        return (None, rest);
    }
    (rest[..end].parse().ok(), &rest[end..])
}

/// `<n>[bBkKmMgGtT]`, the size form `-v`, `-md`, `-sl` and `-sm` share.
///
/// The reference's default unit differs per switch - `-sl` and `-sm`
/// count bytes, `-v` counts THOUSANDS of bytes, `-md` counts megabytes -
/// so the caller passes the multiplier to apply when no unit letter is
/// present rather than this helper guessing one.
///
/// **The letters are two alphabets**, which is what the help screen's
/// `[bBkKmMgGtT]` says: a lower case letter is a power of 1024 and an
/// upper case one a power of 1000, with `b` and `B` both bytes. Measured
/// against rar 7.23 on 4 Oct 2026: the first volume of `-v100k` is
/// 102,400 bytes and of `-v100K` 100,000, `-v2m` 2,097,152 and `-v2M`
/// 2,000,000, and `-sl`/`-sm` over sparse files put `g` at 2^30, `G` at
/// 10^9, `t` at 2^40 and `T` at 10^12. Until that day every letter was
/// read as its lower case, so `-v100M` made volumes 4.9 percent too
/// large.
fn parse_size(text: &str, default_unit: u64) -> Option<u64> {
    let (digits, rest) = eat_number(text);
    let digits = digits?;
    let unit = match rest.as_bytes().first() {
        None => default_unit,
        Some(b'b' | b'B') => 1,
        Some(b'k') => 1024,
        Some(b'm') => 1024 * 1024,
        Some(b'g') => 1024 * 1024 * 1024,
        Some(b't') => 1024_u64.pow(4),
        Some(b'K') => 1000,
        Some(b'M') => 1000 * 1000,
        Some(b'G') => 1000 * 1000 * 1000,
        Some(b'T') => 1000_u64.pow(4),
        // A trailing letter the reference does not read as a unit leaves
        // the number in bytes rather than making the switch a usage
        // error, which is what the sweep rows record.
        Some(_) => default_unit,
    };
    digits.checked_mul(unit)
}

/// `-v<size>`: [`parse_size`], and a size with a fraction.
///
/// Measured against rar 7.23 on 8 Oct 2026 by the first volume's length:
/// `-v1.5m` is 1,572,864 bytes, `-v1.5M` 1,500,000, `-v1.5` 1,500,
/// `-v1.999k` 2,046 and `-v1.123456789m` 1,178,029, so the fraction is
/// taken of the unit and cut to a whole byte; `.5m` and `1.m` are read
/// too. A size with no point in it is read as it always was.
fn volume_size(text: &str) -> Option<u64> {
    let Some((whole, rest)) = text.split_once('.') else {
        return parse_size(text, 1000);
    };
    if !whole.bytes().all(|byte| byte.is_ascii_digit()) {
        return parse_size(text, 1000);
    }
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    let (fraction, unit) = rest.split_at(digits);
    // The unit's size is what `1<unit>` reads as.
    let unit = u128::from(parse_size(&format!("1{unit}"), 1000)?);
    let whole: u128 = if whole.is_empty() {
        0
    } else {
        whole.parse().ok()?
    };
    // Eighteen places are more than a byte of any unit can show.
    let fraction = &fraction[..fraction.len().min(18)];
    let part = match fraction.parse::<u128>() {
        Ok(part) => part * unit / 10_u128.pow(fraction.len() as u32),
        Err(_) => 0,
    };
    u64::try_from(whole.checked_mul(unit)?.checked_add(part)?).ok()
}

/// `-mm<n>[kmg]`'s size, in bytes: digits and at most one unit letter, a
/// bare number counting megabytes as `-md` does.
///
/// Stricter than [`parse_size`] on purpose. That helper keeps a reference
/// switch's lax reading of a stray letter; `-mm` has no reference reading
/// to keep, and every `-mm` spelling this does not accept must stay rar
/// 7.23's own `Unknown option`. Zero and an overflow are refused too.
fn memory_cap(text: &str) -> Option<u64> {
    let digits = text.bytes().take_while(u8::is_ascii_digit).count();
    let (number, unit) = text.split_at(digits);
    let unit: u64 = match unit {
        "k" | "K" => 1 << 10,
        "" | "m" | "M" => 1 << 20,
        "g" | "G" => 1 << 30,
        _ => return None,
    };
    number
        .parse::<u64>()
        .ok()?
        .checked_mul(unit)
        .filter(|&bytes| bytes > 0)
}

/// The DOS attribute mask a `-e[+]<attr>` letter block names.
///
/// The five letters the reference documents, and the values are the DOS
/// ones every RAR family stores for a Windows member. An unrecognised
/// letter contributes nothing rather than making the switch a usage
/// error, because the reference accepts the switch either way.
fn dos_attributes(letters: &str) -> u64 {
    letters
        .bytes()
        .map(|letter| match letter.to_ascii_lowercase() {
            b'r' => 0x01, // read-only
            b'h' => 0x02, // hidden
            b's' => 0x04, // system
            b'd' => 0x10, // directory
            b'a' => 0x20, // archive
            _ => 0,
        })
        .fold(0, |mask, bit| mask | bit)
}

/// Reads a `-n@<list>` / `-x@<list>` list file, or standard input for the
/// bare `@` form.
///
/// A list FILE that cannot be read is an error and not an empty list:
/// measured against rar 7.23 on 4 Oct 2026, `rar a arc.rar a.txt b.txt`
/// with an include list `keep.lst` that is not there answers `Cannot
/// open keep.lst`, `No such file or directory`, `Program aborted`, exit
/// 6, and writes nothing; an exclude list and a list given as an
/// argument answer the same.
fn read_mask_list(source: &str) -> std::io::Result<Vec<String>> {
    let text = if source.is_empty() {
        let mut buf = String::new();
        use std::io::Read;
        let _ = std::io::stdin().read_to_string(&mut buf);
        buf
    } else {
        std::fs::read_to_string(source)?
    };
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect())
}

/// The form `-ag` alone asks for, measured against rar 7.23 on 8 Oct
/// 2026: `rar a -ag f.rar` writes `f20261008095812.rar`.
const DEFAULT_NAME_FORM: &str = "YYYYMMDDHHMMSS";

/// Whether an `-ag` form is one the name generator renders as the
/// reference does: the date letters `Y M D H S` and the separators `_`,
/// `-` and `.`, a `-` not in front.
///
/// The reference reads more (measured the same day: `N` is the archive's
/// number, `A` the day of the year, `W` and `E` a week and a weekday,
/// `{text}` literal text, and a leading `+` something else again), none
/// of which the generator knows. It wrote each of those letters into the
/// name as itself.
fn name_form_is_a_date(form: &str) -> bool {
    !form.starts_with('-')
        && form
            .bytes()
            .all(|byte| matches!(byte, b'Y' | b'M' | b'D' | b'H' | b'S' | b'_' | b'-' | b'.'))
}

/// A switch that only a Windows `rar` has (`-oc`, `-oni`, `-os`): there
/// it is read and a create declines it by name; anywhere else it is the
/// reference's own `Unknown option` (measured on macOS, 8 Oct 2026).
fn windows_only(rest: &str, opts: &mut Options, asks: &'static str) -> Result<(), Refusal> {
    if cfg!(windows) {
        opts.create_declines(rest, asks);
        Ok(())
    } else {
        Err(unknown_option(rest))
    }
}

/// Parses one switch (the text AFTER the leading dash) into `opts`.
///
/// Returns `Err` only where the reference itself refuses. Every spelling
/// in the captured inventory - both platforms' - reaches an `Ok` arm.
#[allow(clippy::too_many_lines)]
fn switch(rest: &str, opts: &mut Options) -> Result<(), Refusal> {
    // A bare `-` is refused; the `stop-switch-scan` row is exactly that
    // refusal. The help screen's `-` line is NOT this shape: the screen
    // lists switches without their dash, so that line is `--`, which the
    // reference reads as the end of the switches (`rar l -- -x` opens an
    // archive named `-x.rar`, measured 15 Sep 2026). `parse` honours
    // that before this function is reached, so an empty `rest` here is
    // only ever the lone `-`.
    if rest.is_empty() {
        return Err(unknown_option(rest));
    }
    if let Some(inner) = rest.strip_prefix('@') {
        if inner.is_empty() || inner == "+" {
            opts.shared.file_lists = inner == "+";
            return Ok(());
        }
        return Err(unknown_option(rest));
    }

    // The first CHARACTER, not the first byte: a switch that opens with a
    // character of several bytes was split inside it, which is a panic
    // and not the `Unknown option` it now reaches below.
    let (head, tail) = rest.split_at(rest.chars().next().map_or(0, char::len_utf8));
    match head {
        "a" => match tail {
            // Windows: `-ac` resets each file's Archive flag afterwards.
            "c" => Ok(()),
            // On a create the reference stores the default modes in place
            // of the files' own (`select::attributes_of`). Off a unix host
            // what it stores is unmeasured.
            "i" => {
                opts.shared.ignore_attributes = true;
                opts.default_modes = true;
                if cfg!(not(unix)) {
                    opts.create_declines(rest, "which stores default attributes off a unix host");
                }
                Ok(())
            }
            // `-am[s,r]`: store or apply the archive's own name and timestamp.
            "m" | "ms" | "mr" => {
                opts.create_declines(rest, "which records the archive's own name and time in it");
                Ok(())
            }
            // Windows: `-ao` takes only files whose Archive flag is set.
            // On a unix host there is no such flag and the reference adds
            // every file (measured against rar 7.23 on macOS, 4 Oct 2026),
            // which is what ignoring it does. Elsewhere it selects, and a
            // create that cannot select by it refuses it.
            "o" => {
                if cfg!(not(unix)) {
                    opts.create_refuses(rest, "which takes only files whose Archive flag is set");
                }
                Ok(())
            }
            "s" => {
                opts.synchronize = true;
                Ok(())
            }
            _ if tail.starts_with('d') => {
                opts.shared.append_archive_dir = Some(match tail {
                    "d1" => 1,
                    "d2" => 2,
                    _ => 0,
                });
                Ok(())
            }
            _ if tail.starts_with('g') => {
                let form = match &tail[1..] {
                    "" => DEFAULT_NAME_FORM,
                    form => form,
                };
                if !name_form_is_a_date(form) {
                    opts.create_declines(
                        rest,
                        "whose name form holds more than the date letters Y M D H S",
                    );
                }
                opts.generate_name = Some(form.to_owned());
                Ok(())
            }
            _ if tail.starts_with('p') => {
                opts.shared.archive_path = Some(tail[1..].to_owned());
                opts.create_refuses(rest, "which stores the files under a folder in the archive");
                Ok(())
            }
            _ => Err(unknown_option(rest)),
        },
        "c" => match tail {
            "-" => {
                opts.shared.hide_comments = true;
                Ok(())
            }
            "fg-" => Ok(()),
            "l" => {
                opts.shared.lower_case = true;
                opts.shared.upper_case = false;
                opts.create_refuses(rest, "which stores the names in lower case");
                Ok(())
            }
            "u" => {
                opts.shared.upper_case = true;
                opts.shared.lower_case = false;
                opts.create_refuses(rest, "which stores the names in upper case");
                Ok(())
            }
            _ => Err(unknown_option(rest)),
        },
        "d" => match tail {
            "f" => {
                opts.delete_after = true;
                Ok(())
            }
            "h" => Ok(()),
            // `-ds`: keep the given order in a solid archive.
            "s" => {
                opts.keep_order = true;
                Ok(())
            }
            "w" => {
                opts.wipe_after = true;
                Ok(())
            }
            // `-dr` asks for the sources to go to the Recycle Bin. There
            // is no such deletion here, and reading it as nothing made
            // `m -dr` delete for good and `a -dr` not delete at all, so a
            // create refuses it by name (rar 7.23 on macOS, measured 4
            // Oct 2026, does not know the switch: `Unknown option: dr`,
            // exit 7, nothing written).
            "r" => {
                opts.create_refuses(rest, "which sends the sources to the Recycle Bin");
                Ok(())
            }
            _ => Err(unknown_option(rest)),
        },
        "e" => match tail {
            "d" => {
                opts.no_empty_dirs = true;
                opts.shared.skip_directories = true;
                Ok(())
            }
            "p" => {
                opts.path_mode = PathMode::NoPaths;
                Ok(())
            }
            "p1" => {
                opts.path_mode = PathMode::NoBaseDir;
                Ok(())
            }
            "p2" => {
                opts.path_mode = PathMode::FullPath;
                Ok(())
            }
            "p3" => {
                opts.path_mode = PathMode::FullPathWithDrive;
                Ok(())
            }
            _ if tail.starts_with("p4") => {
                opts.shared.strip_prefix = Some(tail[2..].to_owned());
                opts.create_refuses(
                    rest,
                    "which leaves a leading folder out of the stored names",
                );
                Ok(())
            }
            // `-e<attr>` EXCLUDES members carrying the attribute and
            // `-e+<attr>` selects ONLY those. The distinction is the
            // whole difference between two conformance rows on each
            // platform, and it falls out of one rule because a DOS
            // attribute only exists for a member a Windows rar wrote:
            // on the macOS fixtures `-eA` lists everything and `-e+A`
            // lists `0 files`, on the Windows fixtures `-eA` leaves only
            // the directory and `-e+A` leaves only the three files.
            // Measured against rar 7.23 on both, 3 Sep 2026; reading
            // `-e[+]<attr>` as one switch gets half the rows wrong
            // whichever way it falls.
            _ => {
                let (letters, include) = match tail.strip_prefix('+') {
                    Some(letters) => (letters, true),
                    None => (tail, false),
                };
                opts.shared.attribute_filter = Some((dos_attributes(letters), include));
                opts.create_refuses(rest, "which selects files by their attributes");
                Ok(())
            }
        },
        "f" => {
            // `-f` and a tail is not a switch (measured over every
            // letter, digit, `+` and `-`, 8 Oct 2026).
            if !tail.is_empty() {
                return Err(unknown_option(rest));
            }
            opts.freshen = true;
            opts.create_refuses(
                rest,
                "which takes only files the archive already holds an older copy of",
            );
            Ok(())
        }
        "h" => match tail {
            _ if tail.starts_with('p') => {
                opts.encrypt_headers = true;
                let value = &tail[1..];
                if !value.is_empty() {
                    opts.shared.password = Some(value.to_owned());
                    opts.shared.prompt_password = false;
                } else {
                    opts.shared.prompt_password = true;
                }
                Ok(())
            }
            // `-ht[b|c]`, and the BARE `-ht` is a usage error: the
            // captured probe table has `ht` at 7 with `htb` and `htc` at
            // 0. The help screen's `ht[b|c]` reads the other way, which
            // is why this is a measurement rather than a reading.
            "tb" => {
                opts.hash = HashType::Blake2sp;
                Ok(())
            }
            "tc" => {
                opts.hash = HashType::Crc32;
                Ok(())
            }
            _ => Err(unknown_option(rest)),
        },
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
                opts.shared.all_to_stderr = true;
                opts.shared.quiet = false;
                opts.shared.silent = false;
                Ok(())
            }
            "nul" => {
                opts.shared.silent = true;
                opts.shared.all_to_stderr = false;
                opts.shared.quiet = false;
                Ok(())
            }
            "snd" | "snd-" => Ok(()),
            "ver" => {
                opts.print_version = true;
                Ok(())
            }
            "bck" => Ok(()),
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
                        b'd' => opts.shared.hide_done = true,
                        b'n' => opts.shared.hide_names = true,
                        b'p' => opts.shared.hide_percent = true,
                        b'q' => {
                            opts.shared.quiet = true;
                            opts.shared.all_to_stderr = false;
                            opts.shared.silent = false;
                        }
                        _ => {}
                    }
                }
                Ok(())
            }
            _ if tail.starts_with("log") => {
                let value = tail[3..].trim_start_matches('=');
                opts.error_log = Some(value.to_owned());
                Ok(())
            }
            // Windows: `-ieml` mails the archive, `-ioff` powers the box
            // down. Both parse and neither acts, which is also why the
            // harness declines to sweep them.
            _ if tail.starts_with("eml") || tail.starts_with("off") => Ok(()),
            _ => Ok(()),
        },
        "k" => match tail {
            "" => {
                opts.lock_after = true;
                Ok(())
            }
            "b" => {
                opts.shared.keep_broken = true;
                Ok(())
            }
            _ => Err(unknown_option(rest)),
        },
        "l" => {
            // `-log[f][=name]`. Nothing else starts with `l`.
            if let Some(spec) = tail.strip_prefix("og") {
                let value = spec.trim_start_matches('f').trim_start_matches('=');
                opts.name_log = Some(value.to_owned());
                opts.create_declines(rest, "which writes the names it processes to a file");
                return Ok(());
            }
            Err(unknown_option(rest))
        }
        "m" => {
            if let Some(level) = tail
                .as_bytes()
                .first()
                .copied()
                .filter(|_| tail.len() == 1)
                .and_then(Level::from_digit)
            {
                opts.level = level;
                return Ok(());
            }
            match tail {
                "lp" => Ok(()),
                // `-ma5` selects the RAR 5 format, which is the only
                // format 7.23 can write and therefore already the
                // default; the reference accepts it and writes exactly
                // the archive it writes without it (measured 4 Sep 2026,
                // the `add-rar5` row). `-ma4` is refused - see the arm
                // below, and the module's own note.
                "a5" => Ok(()),
                // `-mc<par>`: the filters and the match search. Until 9
                // Oct 2026 every form was accepted and read by nothing.
                _ if tail.starts_with('c') => {
                    // The forms are read in order at the reference: `-mc-
                    // -mcd+` turns the delta filter back on alone, which
                    // the writer cannot do, where `-mc- -mc+` and `-mcd+
                    // -mc-` leave every filter off (measured).
                    let form = match McForm::of(&tail[1..]) {
                        McForm::NoChange if opts.filters_off && !matches!(&tail[1..], "" | "+") => {
                            McForm::Declined
                        }
                        form => form,
                    };
                    match form {
                        McForm::FiltersOff => opts.filters_off = true,
                        McForm::NoChange => {}
                        McForm::Declined => opts.create_declines(
                            rest,
                            "which sets a filter or a match search the writer chooses for itself",
                        ),
                    }
                    Ok(())
                }
                _ if tail.starts_with('d') => {
                    // `-md[x]<n>[kmg]`. The optional `x` selects the
                    // "exact" form; both carry the same number, and the
                    // reference's bare unit here is megabytes in 7.x.
                    let body = tail[1..].trim_start_matches('x');
                    // `-md` with no size is not a switch, measured.
                    if tail == "d" {
                        return Err(unknown_option(rest));
                    }
                    // `-md`'s letters are `[kmg]` and are read in either
                    // case as powers of 1024, as they were.
                    opts.dictionary = parse_size(&body.to_ascii_lowercase(), 1024 * 1024);
                    Ok(())
                }
                _ if tail.starts_with('e') => Ok(()),
                _ if tail.starts_with('s') => {
                    opts.store_types = tail[1..]
                        .split(';')
                        .filter(|part| !part.is_empty())
                        .map(str::to_owned)
                        .collect();
                    Ok(())
                }
                _ if tail.starts_with('t') => match reference_threads(&tail[1..]) {
                    Some(threads) => {
                        opts.shared.threads = Some(threads);
                        Ok(())
                    }
                    None => Err(unknown_option(rest)),
                },
                // rarfast's own; see `Options::memory_for_speed` and
                // `Options::memory_cap`. Exact spellings and a strictly read
                // size only, so any other `-mm...` is still the reference's
                // `Unknown option`. One switch, so the last spelling wins.
                "m+" => {
                    opts.memory_for_speed = true;
                    opts.memory_cap = None;
                    Ok(())
                }
                "m-" => {
                    opts.memory_for_speed = false;
                    opts.memory_cap = None;
                    Ok(())
                }
                _ if tail.starts_with('m') => match memory_cap(&tail[1..]) {
                    Some(bytes) => {
                        opts.memory_cap = Some(bytes);
                        opts.memory_for_speed = false;
                        Ok(())
                    }
                    None => Err(unknown_option(rest)),
                },
                _ => Err(unknown_option(rest)),
            }
        }
        "n" => {
            if let Some(list) = tail.strip_prefix('@') {
                let masks = opts.mask_list(list);
                opts.shared.include.extend(masks);
            } else {
                opts.shared.include.push(tail.to_owned());
            }
            Ok(())
        }
        "o" => match tail {
            "" => {
                opts.shared.overwrite = Overwrite::Ask;
                Ok(())
            }
            "+" => {
                opts.shared.overwrite = Overwrite::Always;
                Ok(())
            }
            "-" => {
                opts.shared.overwrite = Overwrite::Never;
                Ok(())
            }
            // Windows: `-oc` keeps the NTFS compression flag, and `-oni`
            // permits names other systems may not accept.
            "c" | "ni" => windows_only(rest, opts, "which is a Windows file system switch"),
            // `-oh-` is `-oh`, measured: both store the second name of a
            // hard linked file as a link.
            "h" | "h-" => {
                opts.create_declines(rest, "which stores a hard link as a link");
                Ok(())
            }
            // `-ol` and `-ola` store a symbolic link as the link and
            // `-ol-` leaves links out. The walk here FOLLOWS a link, so
            // reading these as nothing stored what the link points at,
            // and `m -ol` then deleted it, outside the tree the command
            // named. A create refuses them by name until they are built.
            "l" | "la" | "l-" => {
                opts.create_refuses(
                    rest,
                    "which stores a symbolic link as the link, or leaves links out",
                );
                Ok(())
            }
            "r" => {
                opts.shared.overwrite = Overwrite::Rename;
                Ok(())
            }
            // Windows: `-os` stores NTFS streams.
            "s" => windows_only(rest, opts, "which stores NTFS streams"),
            // `-ow-` is `-ow`, measured: both store the owner and group.
            "w" | "w-" => {
                opts.create_declines(rest, "which stores each file's owner and group");
                Ok(())
            }
            // `-oi0` and `-oi-` ask for what a create does anyway.
            "i0" | "i-" => Ok(()),
            _ if tail.starts_with('i') => {
                opts.create_declines(rest, "which stores identical files as references");
                Ok(())
            }
            _ if tail.starts_with('p') => {
                opts.shared.output_path = Some(tail[1..].to_owned());
                Ok(())
            }
            // Every other tail is `Unknown option` at the reference,
            // measured over each letter and digit on 8 Oct 2026. Until
            // then all of them were read as nothing.
            _ => Err(unknown_option(rest)),
        },
        "p" => {
            opts.shared.no_password = tail == "-";
            if tail == "-" {
                opts.shared.password = None;
                opts.shared.prompt_password = false;
            } else if tail.is_empty() {
                opts.shared.prompt_password = true;
            } else {
                opts.shared.password = Some(tail.to_owned());
                opts.shared.prompt_password = false;
            }
            Ok(())
        }
        "q" => match tail {
            "o" | "o+" => {
                opts.quick_open = Some(true);
                Ok(())
            }
            "o-" => {
                opts.quick_open = Some(false);
                Ok(())
            }
            _ => Err(unknown_option(rest)),
        },
        "r" => match tail {
            "" => {
                opts.recurse = Recurse::On;
                opts.shared.recurse = true;
                Ok(())
            }
            "-" => {
                opts.recurse = Recurse::Never;
                opts.shared.recurse = false;
                Ok(())
            }
            "0" => {
                opts.recurse = Recurse::WildcardsOnly;
                Ok(())
            }
            _ if tail.starts_with('i') => Ok(()),
            _ if tail.starts_with('r') => {
                let (percent, _) = eat_number(&tail[1..]);
                opts.recovery_percent = Some(percent.unwrap_or(3));
                Ok(())
            }
            _ if tail.starts_with('v') => match recovery_volume_spec(&tail[1..]) {
                Some(spec) => {
                    opts.recovery_volumes = Some(spec);
                    Ok(())
                }
                None => Err(unknown_option(rest)),
            },
            _ => Err(unknown_option(rest)),
        },
        "s" => match tail {
            "" => {
                opts.solid = true;
                Ok(())
            }
            "-" => {
                opts.solid = false;
                Ok(())
            }
            "e" => {
                opts.solid = true;
                Ok(())
            }
            "v" | "v-" => Ok(()),
            _ if tail.starts_with('=') => {
                opts.solid = true;
                Ok(())
            }
            // `-sc<chr>[obj]` names a character set; with none it is not
            // a switch, measured.
            _ if tail.starts_with('c') && tail.len() > 1 => Ok(()),
            _ if tail.starts_with("fx") => {
                opts.sfx_module = Some(tail[2..].to_owned());
                Ok(())
            }
            _ if tail.starts_with('i') => {
                opts.shared.from_stdin = true;
                opts.create_refuses(rest, "which archives what arrives on standard input");
                Ok(())
            }
            _ if tail.starts_with('l') => {
                opts.shared.size_less = parse_size(&tail[1..], 1);
                opts.create_refuses(rest, "which takes only files under a size");
                Ok(())
            }
            _ if tail.starts_with('m') => {
                opts.size_more = parse_size(&tail[1..], 1);
                opts.shared.size_more = opts.size_more;
                Ok(())
            }
            // `-s<N>`, `-sd` and `-s+`, which the reference reads. Every
            // other tail is its `Unknown option`, `-st` among them
            // (measured over each letter and digit on 8 Oct 2026).
            "d" | "+" => Ok(()),
            _ if tail.bytes().all(|byte| byte.is_ascii_digit()) => Ok(()),
            _ => Err(unknown_option(rest)),
        },
        "t" => match tail {
            "" => {
                opts.test_after = true;
                Ok(())
            }
            "l" => {
                opts.archive_time_latest = true;
                Ok(())
            }
            _ if tail.starts_with('k') => {
                opts.keep_archive_time = true;
                Ok(())
            }
            // The time filters and `-ts`, whose spellings and semantics
            // the decoder already carries; `-tc` and `-tv`, which the
            // reference reads and this creator has nothing to do for.
            // Any other tail is not a switch: measured against rar 7.23
            // on 4 Oct 2026 over every letter, `a b c k l n o s v` are
            // read and the rest are `Unknown option`, exit 7. Until then
            // the decoder's answer was taken as read and all passed.
            _ if !matches!(
                tail.as_bytes().first(),
                Some(b'a' | b'b' | b'c' | b'n' | b'o' | b's' | b'v')
            ) =>
            {
                Err(unknown_option(rest))
            }
            _ => {
                super::super::unrar::args::switch_for_reuse(rest, &mut opts.shared);
                if matches!(tail.as_bytes().first(), Some(b'a' | b'b' | b'n' | b'o')) {
                    opts.create_refuses(rest, "which selects files by their time");
                }
                // `-ts`: which times a create stores. Measured against rar
                // 7.23 on 8 Oct 2026: these five write the bytes it writes
                // without them, `-ts-` and `-tsm-` store no modification
                // time, and every other form stores a creation or access
                // time, a coarser one, or keeps the sources' access time.
                match tail.strip_prefix('s') {
                    None => {}
                    Some("m" | "m+" | "m4") => opts.no_mtime = false,
                    Some("c-" | "a-") => {}
                    Some("-" | "m-") => opts.no_mtime = true,
                    Some(_) => opts.create_declines(
                        rest,
                        "which chooses the file times a create stores and how finely",
                    ),
                }
                Ok(())
            }
        },
        "u" => {
            // `-u` and a tail is not a switch, measured as `-f` was.
            if !tail.is_empty() {
                return Err(unknown_option(rest));
            }
            opts.update = true;
            opts.shared.update = true;
            Ok(())
        }
        "v" => match tail {
            "" => {
                // `-v` with no size: autodetect for a create, and list
                // every volume for a read. Both halves are recorded.
                opts.shared.all_volumes = true;
                Ok(())
            }
            "p" => Ok(()),
            // Windows: `-vd` wipes the disk before each volume.
            // It parses and never acts; the harness declines to sweep it
            // for the same reason.
            "d" => Ok(()),
            "n" => {
                opts.old_volume_names = true;
                Ok(())
            }
            _ if tail.starts_with("er") => Ok(()),
            _ => {
                // A bare `-v<n>` counts thousands of bytes: measured, the
                // first volume of `-v100` is 100,000 bytes.
                opts.volume_size = volume_size(tail);
                opts.shared.all_volumes = true;
                Ok(())
            }
        },
        "w" => {
            opts.work_dir = Some(tail.to_owned());
            Ok(())
        }
        "x" => {
            if let Some(list) = tail.strip_prefix('@') {
                let masks = opts.mask_list(list);
                opts.shared.exclude.extend(masks);
            } else {
                opts.shared.exclude.push(tail.to_owned());
            }
            Ok(())
        }
        "y" => {
            opts.shared.assume_yes = true;
            Ok(())
        }
        "z" => {
            opts.comment_file = Some(tail.to_owned());
            Ok(())
        }
        _ => Err(unknown_option(rest)),
    }
}

/// Reads the command word.
///
/// `None` means the word is not a command, which the reference answers
/// with the help screen and exit 7 - the `bad-command` row.
pub(crate) fn command(word: &str) -> Option<(Command, Option<u64>, Option<String>)> {
    let style = |verbose: bool, spec: &str| {
        Some((
            Command::List(ListStyle {
                verbose,
                bare: spec == "b",
                technical: spec.starts_with('t'),
                technical_all: spec == "ta",
            }),
            None,
            None,
        ))
    };
    match word {
        "a" => Some((Command::Add, None, None)),
        "c" => Some((Command::Comment, None, None)),
        "ch" => Some((Command::ChangeParameters, None, None)),
        "cw" => Some((Command::CommentWrite, None, None)),
        "d" => Some((Command::Delete, None, None)),
        "e" => Some((Command::ExtractFlat, None, None)),
        "f" => Some((Command::Freshen, None, None)),
        "k" => Some((Command::Lock, None, None)),
        "m" => Some((Command::Move { files_only: false }, None, None)),
        "mf" => Some((Command::Move { files_only: true }, None, None)),
        "p" => Some((Command::Print, None, None)),
        "r" => Some((Command::Repair, None, None)),
        "rc" => Some((Command::ReconstructVolumes, None, None)),
        "rn" => Some((Command::Rename, None, None)),
        "t" => Some((Command::Test, None, None)),
        "u" => Some((Command::Update, None, None)),
        "x" => Some((Command::ExtractFull, None, None)),
        "s-" => Some((Command::Sfx { remove: true }, None, None)),
        "l" | "lb" | "lt" | "lta" => style(false, &word[1..]),
        "v" | "vb" | "vt" | "vta" => style(true, &word[1..]),
        _ if word.starts_with("rr") => {
            let (number, rest) = eat_number(&word[2..]);
            rest.is_empty()
                .then_some((Command::AddRecoveryRecord, number, None))
        }
        // `rv`, `rvN`, `rvNp` and `rvN%` are all the command; the tail
        // is re-read into a spec below, where `opts` is in reach, so
        // the switch and the command share one parser.
        _ if word.starts_with("rv") => {
            let (number, _) = eat_number(&word[2..]);
            recovery_volume_spec(&word[2..]).map(|_| (Command::AddRecoveryVolumes, number, None))
        }
        // `i[par]=<str>`: the parameters, if any, sit between the letter
        // and the `=`, and the string is everything after it.
        _ if word.starts_with('i') && word.contains('=') => Some((
            Command::Find,
            None,
            word.split_once('=').map(|(_, s)| s.to_owned()),
        )),
        _ if word.starts_with('s') => Some((
            Command::Sfx { remove: false },
            None,
            Some(word[1..].to_owned()),
        )),
        _ => None,
    }
}

/// Which SFX module the `s` command will open, and whether it is the
/// REMOVING half after the switches have had their say.
///
/// The one copy of a rule with three inputs, kept out of `dispatch` so a
/// control arm can read it: `Out` writes straight to the process's
/// stderr and cannot be captured, so an arm over the command's own
/// output could not say which name it chose. Measured against rar 7.23
/// on a Mac and on a Windows laptop, 17 Sep 2026:
///
/// * `s<name>` and `-sfx<name>` are both accepted and name the same
///   thing;
/// * with both spelled, the SWITCH wins (`rar sfoo.sfx -sfxbar.sfx`
///   opens `bar.sfx`), and the last `-sfx` wins among switches - which
///   the parser already does by overwriting the field;
/// * an empty name, from a bare `s` or a bare `-sfx`, is the default
///   module;
/// * a `-sfx` spelled beside `s-` turns it back into a CONVERSION. That
///   is the cell that is not simply "the name travels", and it is the
///   reference's own answer on both platforms.
pub(crate) fn sfx_selection(parsed: &Parsed) -> (bool, Option<String>) {
    let remove = matches!(parsed.command, Some(Command::Sfx { remove: true }));
    match parsed.opts.sfx_module.clone() {
        Some(named) => (false, Some(named)),
        None => (remove, parsed.sfx_name.clone()),
    }
}

/// Whether a positional looks like the trailing `<path_to_extract/>`.
fn looks_like_dest(arg: &str) -> bool {
    arg.ends_with('/') || (cfg!(windows) && arg.ends_with('\\'))
}

/// Parses a whole command line, `argv[0]` already removed.
pub(crate) fn parse(argv: &[OsString]) -> Result<Parsed, Refusal> {
    let mut opts = Options {
        shared: Shared::new(),
        ..Options::default()
    };
    let mut positional: Vec<String> = Vec::new();
    // The first `--` ends the switches wherever it stands and is not
    // itself a name; everything after it is positional, a second `--` and
    // a lone `-` included. rar 7.23 measured 15 Sep 2026 gives the same
    // answers as unrar: `-- l arc.rar` and `l arc.rar --` both list,
    // `l -- -- arc.rar` opens `--.rar`, `l -- arc.rar -` lists with `-`
    // as a mask, and `-- -- l arc.rar` takes `--` for the command word.
    let mut switches_ended = false;
    for arg in argv {
        let text = os_to_string(arg);
        if switches_ended {
            positional.push(text);
        } else if text == "--" {
            switches_ended = true;
        } else if let Some(rest) = text.strip_prefix('-') {
            switch(rest, &mut opts)?;
        } else {
            positional.push(text);
        }
    }

    let mut iter = positional.into_iter();
    let word = iter.next().unwrap_or_default();
    let found = command(&word);
    let command_word = word;
    let archive = iter.next();
    let mut masks: Vec<String> = iter.collect();
    // A creator's trailing `dir/` is a MASK, not a destination: measured
    // against rar 7.23, `rar a arc.rar sub/` stores the contents of `sub`.
    let creates = matches!(
        found,
        Some((
            Command::Add | Command::Update | Command::Freshen | Command::Move { .. },
            _,
            _
        ))
    );
    let extract_path = masks
        .last()
        .is_some_and(|last| !creates && looks_like_dest(last))
        .then(|| masks.pop())
        .flatten();

    if opts.shared.file_lists {
        let mut expanded = Vec::with_capacity(masks.len());
        for mask in masks {
            match mask.strip_prefix('@') {
                Some(list) if !list.is_empty() => expanded.extend(opts.mask_list(list)),
                _ => expanded.push(mask),
            }
        }
        masks = expanded;
    }

    let (command, command_number, word_value) = match found {
        Some((cmd, number, value)) => (Some(cmd), number, value),
        None => (None, None, None),
    };
    // `rv[N]` as a COMMAND means what `-rv[N]` means as a switch, so it
    // lands in the same field rather than in a second one that the
    // create path would have to consult as well. A `-rv` switch spelled
    // alongside the command loses to the command word, and that is the
    // reference's own order rather than a guess: measured 4 Sep 2026 on
    // a four-volume set, `rar rv3 -rv1` writes three, `rar rv1 -rv3`
    // writes one, and `rar rv -rv3` writes the bare command's default.
    // The word reached this arm by parsing, so it parses again here.
    if matches!(command, Some(Command::AddRecoveryVolumes)) {
        let tail = command_word.get(2..).unwrap_or("");
        if let Some(spec) = recovery_volume_spec(tail) {
            opts.recovery_volumes = Some(spec);
        }
    }
    let (find_text, sfx_name) = match command {
        Some(Command::Find) => (word_value, None),
        Some(Command::Sfx { .. }) => (None, word_value),
        _ => (None, None),
    };

    Ok(Parsed {
        command,
        command_word,
        archive,
        masks,
        extract_path,
        find_text,
        command_number,
        sfx_name,
        opts,
    })
}

/// Command-line text the reference would pass through byte for byte.
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

    fn parsed(args: &[&str]) -> Parsed {
        match parse_str(args) {
            Ok(parsed) => parsed,
            Err(err) => panic!("{args:?} refused: {:?}", err.message),
        }
    }

    #[test]
    fn double_dash_ends_the_switches_wherever_it_stands() {
        // rar 7.23, 15 Sep 2026: all three list `arc.rar` whole, so the
        // `--` is consumed in every position rather than read as a mask.
        for args in [
            ["l", "--", "arc.rar"],
            ["--", "l", "arc.rar"],
            ["l", "arc.rar", "--"],
        ] {
            let p = parsed(&args);
            assert_eq!(p.command_word, "l", "{args:?}");
            assert!(p.command.is_some(), "{args:?}");
            assert_eq!(p.archive.as_deref(), Some("arc.rar"), "{args:?}");
            assert!(p.masks.is_empty(), "{args:?}");
        }
        let p = parsed(&["l", "arc.rar", "--", "a.txt"]);
        assert_eq!(p.masks, ["a.txt"]);
    }

    #[test]
    fn after_double_dash_every_argument_is_positional() {
        // `rar l -- -x arc.rar` answers "Cannot open -x.rar".
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
        assert_eq!(p.command_word, "--");
        assert!(p.command.is_none());
        assert_eq!(p.archive.as_deref(), Some("l"));
    }

    #[test]
    fn a_bare_dash_before_double_dash_is_still_refused() {
        let err = parse_str(&["l", "-", "--", "arc.rar"]).unwrap_err();
        assert_eq!(err.message, "\nERROR: Unknown option: ");
        assert_eq!(err.exit, Exit::BadCommandLine);
    }

    /// One spelling per line of the captured inventory's SWITCHES block,
    /// macOS and Windows, minus the two `@` forms tested separately. A
    /// spelling that starts refusing here is one the harness refuses the
    /// whole candidate for.
    const INVENTORY: &[&str] = &[
        "ad",
        "ad1",
        "ad2",
        "ag_",
        "ai",
        "am",
        "amr",
        "ams",
        "apsub",
        "as",
        "c-",
        "cfg-",
        "cl",
        "cu",
        "df",
        "dh",
        "ds",
        "dw",
        "er",
        "e+r",
        "ed",
        "ep",
        "ep1",
        "ep3",
        "ep4sub",
        "f",
        "hpswpass",
        "htb",
        "htc",
        "ierr",
        "ilogerr.log",
        "inul",
        "isnd",
        "isnd-",
        "iver",
        "k",
        "kb",
        "m0",
        "m1",
        "m2",
        "m3",
        "m4",
        "m5",
        "mcl",
        "mem",
        "mstxt",
        "mt1",
        "nsweeplist.txt",
        "o",
        "o+",
        "o-",
        "oh",
        "ol",
        "ol-",
        "ola",
        "opout",
        "or",
        "ow",
        "pswpass",
        "p-",
        "qo",
        "qo+",
        "qo-",
        "r",
        "r-",
        "r0",
        "rr",
        "rr5",
        "rv",
        "rv1",
        "s",
        "sc u",
        "sfx",
        "si",
        "sl100",
        "sm100",
        "t",
        "ta20200101000000",
        "taa20200101000000",
        "tac20200101000000",
        "tam20200101000000",
        "tao20200101000000",
        "tb20200101000000",
        "tba20200101000000",
        "tbc20200101000000",
        "tbm20200101000000",
        "tbo20200101000000",
        "tk",
        "tl",
        "tn20200101000000",
        "tna20200101000000",
        "tnc20200101000000",
        "tnm20200101000000",
        "tno20200101000000",
        "to20200101000000",
        "toa20200101000000",
        "toc20200101000000",
        "tom20200101000000",
        "too20200101000000",
        "ts",
        "tsa",
        "tsc",
        "tsm",
        "tsp",
        "u",
        "v",
        "v12k",
        "ver",
        "vp",
        "wwork",
        "xrand.bin",
        "y",
        "z",
        // The twelve that exist only on the Windows screen.
        "ac",
        "ao",
        "dr",
        "ep2",
        "ieml",
        "ioff",
        "mlp",
        "oc",
        "oni",
        "os",
        "ri0:1",
        "vd",
    ];

    #[test]
    fn every_inventoried_switch_parses() {
        for spell in INVENTORY {
            let mut opts = Options {
                shared: Shared::new(),
                ..Options::default()
            };
            // Three of the Windows screen's twelve are `Unknown option`
            // at a unix `rar` (measured on macOS, 8 Oct 2026), and so here.
            if cfg!(not(windows)) && matches!(*spell, "oc" | "oni" | "os") {
                let err = switch(spell, &mut opts).expect_err(spell);
                assert_eq!(err.message, format!("\nERROR: Unknown option: {spell}"));
                assert_eq!(err.exit, Exit::BadCommandLine);
                continue;
            }
            assert!(
                switch(spell, &mut opts).is_ok(),
                "-{spell} was refused; it is in the captured inventory"
            );
        }
    }

    #[test]
    fn the_bare_ht_is_a_usage_error_but_its_two_suffixes_are_not() {
        // Measured, not read: the captured probe table has `ht` at 7
        // with `htb` and `htc` at 0, which the help screen's `ht[b|c]`
        // line does not tell you.
        let mut opts = Options::default();
        assert!(switch("ht", &mut opts).is_err());
        assert!(switch("htb", &mut opts).is_ok());
        assert_eq!(opts.hash, HashType::Blake2sp);
        assert!(switch("htc", &mut opts).is_ok());
        assert_eq!(opts.hash, HashType::Crc32);
    }

    #[test]
    fn ma4_is_refused_and_ma5_is_not() {
        // The `add-rar4` and `add-rar5` conformance rows, and the pair
        // does NOT answer the same way. rar 7.23 cannot write RAR 4, so
        // `-ma4` is `ERROR: Unknown option: ma4` with exit 7; `-ma5`
        // names the only format it does write and is accepted, exit 0,
        // producing the archive it would have produced anyway. An earlier
        // record had both as refused, from one measurement of `-ma4`;
        // re-measured against the reference 4 Sep 2026.
        let mut opts = Options::default();
        let err = switch("ma4", &mut opts).expect_err("ma4 is not a 7.23 switch");
        assert_eq!(err.message, "\nERROR: Unknown option: ma4");
        assert_eq!(err.exit, Exit::BadCommandLine);
        assert!(switch("ma5", &mut opts).is_ok());
    }

    #[test]
    fn mm_plus_and_minus_are_rarfast_s_own_and_nothing_else_in_mm_is() {
        // `-mm` is not a reference switch at all: rar 7.23 answers
        // `Unknown option` for every spelling of it. rarfast accepts `-mm+`,
        // `-mm-` and `-mm<n>[kmg]`, and every other one must still be the
        // reference's refusal. (`mm1` was on the refused list until the size
        // form arrived on 15 Sep 2026; it is one megabyte now.)
        let mut opts = Options::default();
        assert!(!opts.memory_for_speed, "the default is the lean route");
        assert_eq!(opts.memory_cap, None, "the default has no cap");
        assert!(switch("mm+", &mut opts).is_ok());
        assert!(opts.memory_for_speed);
        assert!(switch("mm-", &mut opts).is_ok());
        assert!(!opts.memory_for_speed);
        for (spelling, bytes) in [
            ("mm1", 1 << 20),
            ("mm512", 512 << 20),
            ("mm512m", 512 << 20),
            ("mm64M", 64 << 20),
            ("mm2g", 2 << 30),
            ("mm2G", 2 << 30),
            ("mm300k", 300 << 10),
        ] {
            let mut opts = Options::default();
            assert!(switch(spelling, &mut opts).is_ok(), "{spelling}");
            assert_eq!(opts.memory_cap, Some(bytes), "{spelling}");
        }
        // One switch, three spellings: the last on the line wins.
        let mut opts = Options::default();
        assert!(switch("mm+", &mut opts).is_ok());
        assert!(switch("mm1g", &mut opts).is_ok());
        assert_eq!(
            (opts.memory_cap, opts.memory_for_speed),
            (Some(1 << 30), false)
        );
        assert!(switch("mm+", &mut opts).is_ok());
        assert_eq!((opts.memory_cap, opts.memory_for_speed), (None, true));
        assert!(switch("mm1g", &mut opts).is_ok());
        assert!(switch("mm-", &mut opts).is_ok());
        assert_eq!((opts.memory_cap, opts.memory_for_speed), (None, false));
        for spelling in [
            "mm",
            "mmx",
            "mm++",
            "mm0",
            "mm0g",
            "mmg",
            "mm1x",
            "mm1b",
            "mm1t",
            "mm1mb",
            "mm1.5g",
            "mm-1",
            "mm 1",
            "mm99999999999g",
            "mm99999999999999999999",
        ] {
            let err = switch(spelling, &mut opts).expect_err(spelling);
            assert_eq!(err.message, format!("\nERROR: Unknown option: {spelling}"));
            assert_eq!(err.exit, Exit::BadCommandLine);
        }
    }

    /// Measured against rar 7.23 on 8 Oct 2026 by the first volume's
    /// length: a size may carry a fraction, taken of its unit and cut to
    /// a whole byte. Until then `-v1.5m` was read as `1` and made 3,216
    /// volumes of 1,000 bytes where the reference makes two.
    #[test]
    fn a_volume_size_may_carry_a_fraction() {
        for (typed, bytes) in [
            ("1.5m", 1_572_864),
            ("1.25m", 1_310_720),
            ("0.5m", 524_288),
            (".5m", 524_288),
            ("1.m", 1_048_576),
            ("1.999k", 2_046),
            ("1.5M", 1_500_000),
            ("1.5", 1_500),
            ("100.75k", 103_168),
            ("1.0625m", 1_114_112),
            ("1.123456789m", 1_178_029),
            // No fraction: as before.
            ("100k", 102_400),
            ("100", 100_000),
            ("2M", 2_000_000),
        ] {
            let mut opts = Options::default();
            assert!(switch(&format!("v{typed}"), &mut opts).is_ok(), "{typed}");
            assert_eq!(opts.volume_size, Some(bytes), "-v{typed}");
        }
    }

    #[test]
    fn bare_dash_is_an_unknown_option_with_an_empty_name() {
        let err = parse_str(&["l", "-", "arc.rar"]).unwrap_err();
        assert_eq!(err.message, "\nERROR: Unknown option: ");
        assert_eq!(err.exit, Exit::BadCommandLine);
    }

    #[test]
    fn nosuchswitch_is_read_as_an_n_mask_not_as_an_unknown_option() {
        let parsed = parse_str(&["l", "-nosuchswitch", "arc.rar"]).expect("accepted");
        assert_eq!(parsed.opts.shared.include, vec!["osuchswitch".to_owned()]);
    }

    #[test]
    fn the_command_block_covers_every_inventoried_spelling() {
        for word in [
            "a", "c", "ch", "cw", "d", "e", "f", "k", "l", "lb", "lt", "lta", "m", "mf", "p", "r",
            "rc", "rn", "rr", "rv", "s", "s-", "t", "u", "v", "vb", "vt", "vta", "x",
        ] {
            assert!(command(word).is_some(), "`{word}` is in the inventory");
        }
        assert!(command("i=text").is_some());
        assert!(command("qq").is_none());
    }

    #[test]
    fn a_numbered_recovery_command_carries_its_number() {
        assert_eq!(
            command("rr5"),
            Some((Command::AddRecoveryRecord, Some(5), None))
        );
        assert_eq!(
            command("rv1"),
            Some((Command::AddRecoveryVolumes, Some(1), None))
        );
    }

    #[test]
    fn the_read_only_commands_are_exactly_the_two_dialects_shared_set() {
        for word in [
            "e", "x", "p", "t", "l", "lb", "lt", "lta", "v", "vb", "vt", "vta",
        ] {
            let (cmd, _, _) = command(word).expect("in the inventory");
            assert!(cmd.is_read_only(), "`{word}` is shared with unrar");
        }
        for word in [
            "a", "d", "u", "f", "m", "rn", "k", "c", "ch", "cw", "rr", "rv", "rc",
        ] {
            let (cmd, _, _) = command(word).expect("in the inventory");
            assert!(!cmd.is_read_only(), "`{word}` writes");
        }
    }

    #[test]
    fn the_four_creator_only_filters_reach_the_shared_selection() {
        // `-ed`, `-sm` and `-e<attr>` are rar-only spellings the decoder
        // merely swallows, so routing them through the shared selection
        // is what makes `rar l -ed` drop a directory row the way the
        // reference does. Measured against rar 7.23 on 3 Sep 2026.
        let parsed = parse_str(&["l", "-ed", "arc.rar"]).expect("accepted");
        assert!(parsed.opts.shared.skip_directories);
        let parsed = parse_str(&["l", "-sm1000000", "arc.rar"]).expect("accepted");
        assert_eq!(parsed.opts.shared.size_more, Some(1_000_000));
        let parsed = parse_str(&["l", "-e+A", "arc.rar"]).expect("accepted");
        assert_eq!(parsed.opts.shared.attribute_filter, Some((0x20, true)));
        // ...and the form WITHOUT the plus is the same mask, excluding.
        let parsed = parse_str(&["l", "-eA", "arc.rar"]).expect("accepted");
        assert_eq!(parsed.opts.shared.attribute_filter, Some((0x20, false)));
        let parsed = parse_str(&["l", "-iver", "arc.rar"]).expect("accepted");
        assert!(parsed.opts.print_version);
    }

    #[test]
    fn an_attribute_block_is_the_or_of_its_letters() {
        assert_eq!(dos_attributes("A"), 0x20);
        assert_eq!(dos_attributes("rhs"), 0x01 | 0x02 | 0x04);
        assert_eq!(dos_attributes("D"), 0x10);
        // A letter the reference does not document contributes nothing
        // and does not make the switch a usage error.
        assert_eq!(dos_attributes("Z"), 0);
    }

    #[test]
    fn a_volume_size_reads_its_unit_letter() {
        let parsed = parse_str(&["a", "-v12k", "arc.rar", "f"]).expect("accepted");
        assert_eq!(parsed.opts.volume_size, Some(12 * 1024));
        let parsed = parse_str(&["a", "-v1m", "arc.rar", "f"]).expect("accepted");
        assert_eq!(parsed.opts.volume_size, Some(1024 * 1024));
    }

    /// Every figure is the reference's, measured 4 Oct 2026 (see
    /// `parse_size`): lower case is a power of 1024, upper case a power
    /// of 1000, a bare `-v` counts thousands, a bare `-sm` bytes.
    #[test]
    fn a_size_letter_in_upper_case_is_a_power_of_a_thousand() {
        for (letter, size) in [
            ("b", 7),
            ("B", 7),
            ("k", 7 << 10),
            ("K", 7_000),
            ("m", 7 << 20),
            ("M", 7_000_000),
            ("g", 7 << 30),
            ("G", 7_000_000_000),
            ("t", 7 << 40),
            ("T", 7_000_000_000_000),
            ("", 7_000),
            ("x", 7_000),
        ] {
            let switch = format!("-v7{letter}");
            let parsed = parse_str(&["a", &switch, "arc.rar", "f"]).expect("accepted");
            assert_eq!(parsed.opts.volume_size, Some(size), "{switch}");
        }
        let parsed = parse_str(&["a", "-sm7G", "arc.rar", "f"]).expect("accepted");
        assert_eq!(parsed.opts.size_more, Some(7_000_000_000));
        let parsed = parse_str(&["a", "-sm7", "arc.rar", "f"]).expect("accepted");
        assert_eq!(parsed.opts.size_more, Some(7));
        // `-md` keeps its one alphabet.
        let parsed = parse_str(&["a", "-md64M", "arc.rar", "f"]).expect("accepted");
        assert_eq!(parsed.opts.dictionary, Some(64 << 20));
    }

    #[test]
    fn the_six_levels_map_to_the_writers_numbers() {
        for (spell, want) in [
            ("m0", Level::Store),
            ("m1", Level::Fastest),
            ("m3", Level::Normal),
            ("m5", Level::Best),
        ] {
            let mut opts = Options::default();
            switch(spell, &mut opts).expect("accepted");
            assert_eq!(opts.level, want);
        }
        assert!(Level::Store.is_store());
        assert!(!Level::Normal.is_store());
        assert_eq!(Level::Best.as_u8(), 5);
    }
}
