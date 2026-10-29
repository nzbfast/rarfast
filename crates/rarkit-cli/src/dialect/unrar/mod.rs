//! The `unrar` dialect: every decoder command the reference answers to,
//! spelled the same and answering with the same bytes and exit code.
//!
//! What "the same" means is not a judgement call here. The pinned
//! reference (unrar 7.23) was captured on
//! macOS and on Windows into two fixtures in the project's
//! conformance harness:
//!
//! - the captured `unrar` 7.23 inventory, the reference's
//!   own `-?` screen plus the command and switch spellings parsed out of
//!   it, and
//! - the captured `unrar` 7.23 expectations, the output,
//!   exit code and resulting file tree for 126 macOS rows and 130 Windows
//!   ones, after a normalisation that drops the banner and rewrites a
//!   percentage counter.
//!
//! The conformance run against `rarfast` is the gate.
//! Every layout constant below - a column width, a label width, the
//! twelve-character verb field - came out of that capture rather than out
//! of the manual, and several of them are not what the manual would lead
//! you to write. Three worth knowing before editing anything here:
//!
//! 1. The percentage the extract and test lines carry is the position the
//!    reference has reached in the ARCHIVE FILE, not in the member and
//!    not in the total unpacked size. It matters because the normaliser
//!    rewrites the digits but not the space in front of them, so a
//!    one-digit percentage and a three-digit one give lines of different
//!    length and the row diverges. [`percent`] is that formula.
//! 2. The reference prints timestamps in the BOX's zone, so the two
//!    committed tables disagree by five hours on the same archive. See
//!    `time.rs`.
//! 3. A directory member's progress line and a file's end in different
//!    columns (70 and 80). That is not a bug in the capture: the file
//!    line reserves the percentage field and the directory line does not.

pub(crate) mod args;
mod exit;
pub(crate) mod extract;
mod help;
mod list;
// Off Unix only the decisions compile; nothing applies them yet.
#[cfg_attr(not(unix), allow(dead_code))]
mod mode;
mod time;

#[cfg(unix)]
pub(crate) use mode::read_umask_at_start;

use std::ffi::OsString;
use std::io::Write;

// The engine seam. Everything that names a rarkit type lives there, so
// this file is the dialect and nothing else; see `crate::engine`.
pub(crate) use crate::engine::{open, open_listing, sniffed_details};

pub(crate) use args::{is_creator_command, Command};
pub(crate) use exit::Exit;

use args::{ListStyle, Options, Parsed};

/// Where a message goes. `-ierr` sends everything to stderr, `-inul` sends
/// everything nowhere and `-idq` sends everything that would have gone to
/// STDOUT nowhere, so no call site writes to a stream directly.
///
/// A MESSAGE is not a PAYLOAD. `p` writes the member's bytes to stdout and
/// those bytes are the point of the command, so they do not come through
/// here at all: `extract.rs` hands the walk a `Disposition::Write` over
/// `std::io::stdout()` directly. Measured 19 Sep 2026, `unrar p -idq
/// good.rar` and `unrar p -inul good.rar` both write the member's 20,024
/// bytes and nothing else, so neither switch may reach the payload.
pub(crate) struct Out {
    to_stderr: bool,
    /// `-inul`: nothing at all, not even a failure. Measured 19 Sep 2026:
    /// `rar a -inul /nope/arc.rar text.txt` exits 9 with both streams
    /// empty, so this one really does silence the report as well.
    silent: bool,
    /// `-idq`: the STDOUT messages go and the STDERR ones stay.
    quiet: bool,
    /// Stdout messages held back and written in blocks, set only by
    /// [`Out::held`]. `None` writes and flushes each message at once.
    hold: Option<std::sync::Mutex<Vec<u8>>>,
    /// `-idq`: whether the last byte [`Out::warn`] put on stderr was not
    /// `\n`, so [`Out::close_dangling_stderr`] can close the line the way
    /// the reference does. An `Arc` because [`Out::held`] and
    /// [`Out::beside_payload`] hand out a second `Out` for the same
    /// command line, and the state has to follow whichever of them
    /// actually writes the last complaint.
    ///
    /// Measured 28 Sep 2026 against `rar`/`unrar` 7.23, both streams read
    /// SEPARATELY (a shell's `2>&1` reorders them, since stdout is fully
    /// buffered once it is not a terminal and stderr is not): plain
    /// `unrar t` over a member whose data is corrupted writes a line
    /// ending `- checksum error` on stderr with NO trailing newline at
    /// all - the next member's `Testing` line, or the run's own `Total
    /// errors:` summary, both on stdout, is what moves the terminal
    /// down. Under `-idq` that summary never prints, and the reference
    /// closes the line itself: `unrar t -idq` over the same archive ends
    /// its `- checksum error` line with one extra byte, a `\n`. The same
    /// shape holds for `Cannot open <archive>` and its reason line, which
    /// the engine never terminates either: `unrar l -idq nosuch.rar` ends
    /// its `No such file or directory` line with a `\n` where plain
    /// `unrar l nosuch.rar` ends the same line with none. So the newline
    /// belongs to quiet mode closing out its own last line, not to any
    /// one message - see [`Out::close_dangling_stderr`] for the one
    /// command this does not reach (`lb`).
    stderr_dangling: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// The creator's stand-in for the logo the reference opens every run
    /// with, `None` for the decoder: see [`Out::for_creator`].
    logo: Option<std::sync::Arc<std::sync::atomic::AtomicU8>>,
}

/// [`Out::logo`]: nothing has been said on the message stream yet.
const LOGO_OWED: u8 = 0;
/// [`Out::logo`]: a complaint on the ONE stream (`-ierr`) came first and
/// wrote the logo's blank line itself.
const LOGO_BY_COMPLAINT: u8 = 1;
/// [`Out::logo`]: the stream has begun.
const LOGO_DONE: u8 = 2;

/// How much [`Out::held`] keeps before it writes.
const HOLD_BYTES: usize = 32 * 1024;

impl Out {
    /// The output every command writes its messages through.
    ///
    /// `-idq` asks for a quiet run, and what it silences is the STDOUT
    /// STREAM rather than one command's output. Measured 19 Sep 2026
    /// against `rar` / `unrar` 7.23, over a stored two member archive:
    ///
    /// | run | stdout | stderr | exit |
    /// | --- | --- | --- | --- |
    /// | `unrar l -idq good.rar` | empty | empty | 0 |
    /// | `unrar lb -idq good.rar` | empty | empty | 0 |
    /// | `rar l -idq good.rar` | empty | empty | 0 |
    /// | `unrar t -idq good.rar` | empty | empty | 0 |
    /// | `unrar t -idq damaged.rar` | empty | `rand.bin - checksum error` | 3 |
    /// | `unrar x -idq nosuch.rar` | empty | `Cannot open nosuch.rar` | 10 |
    /// | `unrar p -idq good.rar` | the MEMBER'S BYTES | empty | 0 |
    /// | `rar a -idq -m0 arc.rar text.txt` | empty | empty | 0 |
    /// | `rar a -idq /nope/arc.rar text.txt` | empty | `Cannot open /nope/arc.rar` | 9 |
    /// | `rar -idq -iver` | empty | empty | 0 |
    ///
    /// Two of those rows fix the shape. The failing run keeps its stderr,
    /// which is why [`Out::warn`] does not read this flag: a quiet switch
    /// that swallowed a failure would send a caller away believing the
    /// archive was sound, and a refusal is the only report a script gets
    /// of work that did not happen. And `-ierr`, which moves every message
    /// to stderr, puts the whole listing back: `unrar l -idq -ierr
    /// good.rar` prints all 388 bytes of it on stderr, and so does `rar a
    /// -idq -ierr`. So the rule is the DESTINATION's and not the
    /// command's, and one constructor serves the creator and the decoder
    /// alike.
    pub(crate) fn new(opts: &Options) -> Self {
        Self {
            to_stderr: opts.all_to_stderr,
            silent: opts.silent,
            quiet: opts.quiet,
            hold: None,
            stderr_dangling: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            logo: None,
        }
    }

    /// The creator's output: [`Out::new`], plus the blank line the
    /// reference's logo ends with, which rarfast (printing no logo) still
    /// owes the message stream.
    ///
    /// Measured against rar 7.23 on 30 Sep 2026 over every creator command
    /// with an archive or a source that is not there (`tests/parity_land3.rs`):
    ///
    /// - the run's first message on the stream opens with that blank line
    ///   (`\nDone`, `\nCreating archive`), and a run that says nothing
    ///   else still prints it (`rar rc nosuch.rar`: stdout is `\n`);
    /// - a complaint ([`Out::complain`]) is `\n` and its lines on stderr,
    ///   unended; `-idq` ends the last one when the run is over
    ///   ([`Out::finish_creator`]);
    /// - on ONE stream (`-ierr`) a complaint ends its own lines instead,
    ///   and when it comes first it is the one that writes the blank line,
    ///   so the first message after it has none (`\nCannot open
    ///   nosuch.rar\nNo such file or directory\nDone\n`).
    pub(crate) fn for_creator(opts: &Options) -> Self {
        let mut out = Self::new(opts);
        out.logo = Some(std::sync::Arc::new(std::sync::atomic::AtomicU8::new(
            LOGO_OWED,
        )));
        out
    }

    /// `text` as the message stream takes it next under the creator's
    /// logo rule; unchanged for the decoder.
    fn after_logo<'a>(&self, text: &'a str) -> std::borrow::Cow<'a, str> {
        let Some(logo) = self.logo.as_ref().filter(|_| !text.is_empty()) else {
            return text.into();
        };
        match logo.swap(LOGO_DONE, std::sync::atomic::Ordering::Relaxed) {
            LOGO_OWED if !text.starts_with('\n') => format!("\n{text}").into(),
            LOGO_BY_COMPLAINT => text.strip_prefix('\n').unwrap_or(text).into(),
            _ => text.into(),
        }
    }

    /// The creator's `Cannot open` and `Cannot create`: `text` is the
    /// message and its reason, with no newline at either end; the layout
    /// is [`Out::for_creator`]'s.
    pub(crate) fn complain(&self, text: &str) {
        if self.silent {
            return;
        }
        if self.one_stream() {
            let first = self.logo.as_ref().is_some_and(|logo| {
                logo.compare_exchange(
                    LOGO_OWED,
                    LOGO_BY_COMPLAINT,
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                )
                .is_ok()
            });
            self.warn(&format!("{}{text}\n", if first { "\n" } else { "" }));
        } else {
            self.warn(&format!("\n{text}"));
        }
    }

    /// `Program aborted`, which ends a creator run that could not start
    /// its work (measured: `rar a` into a directory that is not there,
    /// exit 9; `rar d` of an archive that is not there, exit 6). Under
    /// `-idq` the reference leaves stderr unended after it, where every
    /// other failed creator run ends it.
    pub(crate) fn abort(&self) {
        self.say("Program aborted\n");
        self.stderr_dangling
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }

    /// The end of a creator run: the logo's blank line if nothing else
    /// was said, then `-idq`'s end of the last stderr line.
    pub(crate) fn finish_creator(&self) {
        if self.says()
            && self
                .logo
                .as_ref()
                .is_some_and(|logo| logo.load(std::sync::atomic::Ordering::Relaxed) == LOGO_OWED)
        {
            self.say("\n");
        }
        self.close_dangling_stderr(false);
    }

    /// This output with its stdout messages written in blocks rather than
    /// one write each, for a walk that prints a line or two per member.
    ///
    /// Only where nobody watches the lines arrive: stdout is not a
    /// terminal, and the messages go to stdout at all. The bytes and their
    /// order are unchanged: [`Out::warn`] writes what is held before its
    /// own line, so a caller reading both streams as one (`2>&1`) sees
    /// the order a flushed run gives, and the rest goes out when the
    /// returned value is dropped.
    pub(crate) fn held(&self) -> Self {
        use std::io::IsTerminal;
        let hold =
            (!self.silent && !self.to_stderr && !self.quiet && !std::io::stdout().is_terminal())
                .then(|| std::sync::Mutex::new(Vec::with_capacity(HOLD_BYTES)));
        Self {
            to_stderr: self.to_stderr,
            silent: self.silent,
            quiet: self.quiet,
            hold,
            stderr_dangling: std::sync::Arc::clone(&self.stderr_dangling),
            logo: self.logo.clone(),
        }
    }

    /// Writes what is held, if anything.
    fn release(&self) {
        if let Some(hold) = &self.hold {
            let mut held = hold
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !held.is_empty() {
                // Held text is looked through here, once a block, not
                // once a message (see `shown`).
                write_out(Stream::Output, &held);
                held.clear();
            }
        }
    }

    /// A line the reference sends to stdout.
    ///
    /// Written with `write!` and not `print!`, because `print!` PANICS on a
    /// broken pipe: `rarfast l big.rar | head` printed a Rust panic and a
    /// backtrace note where the reference exits quietly (measured 18 Sep
    /// 2026, before this). A drop-in cannot answer `SIGPIPE` with a panic
    /// message, so every write here ignores its error, which is what the
    /// reference's own `fwrite` does.
    pub(crate) fn say(&self, text: &str) {
        if !self.says() {
            return;
        }
        let adjusted;
        let text = if self.logo.is_some() {
            adjusted = self.after_logo(text);
            &*adjusted
        } else {
            text
        };
        if self.to_stderr {
            write_out(Stream::Error, text.as_bytes());
        } else {
            if let Some(hold) = &self.hold {
                let full = {
                    let mut held = hold
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    held.extend_from_slice(text.as_bytes());
                    held.len() >= HOLD_BYTES
                };
                if full {
                    self.release();
                }
                return;
            }
            write_out(Stream::Output, text.as_bytes());
        }
    }

    /// Whether [`Out::say`] writes anything at all: not under `-inul`, and
    /// not under `-idq` unless `-ierr` has moved the messages to stderr.
    /// A caller that would only format text for `say` asks this first, so
    /// a quiet run does not build lines it throws away.
    pub(crate) fn says(&self) -> bool {
        !self.silent && (self.to_stderr || !self.quiet)
    }

    /// Whether [`Out::say`] and [`Out::warn`] write to ONE stream (`-ierr`),
    /// so a message that stands on a line of its own follows a progress
    /// line that has already ended rather than opening with its own
    /// newline.
    pub(crate) fn one_stream(&self) -> bool {
        !self.silent && self.to_stderr
    }

    /// The output for a command whose STDOUT belongs to a payload.
    ///
    /// `p` writes the member's bytes to stdout, and the reference sends no
    /// message there at all: measured 19 Sep 2026, `unrar p good.rar`
    /// gives 20,024 bytes and an empty stderr, while `unrar p -ierr
    /// good.rar` gives the same 20,024 bytes and the whole progress on
    /// stderr. `-idq` and `-inul` change neither stream's payload, and a
    /// failing member still reports on stderr. So the rule is the same
    /// one [`Out::say`] already has for `-idq` - a message is dropped when
    /// its destination is stdout - applied to a command that has no other
    /// use for that stream.
    pub(crate) fn beside_payload(&self) -> Self {
        Self {
            to_stderr: self.to_stderr,
            silent: self.silent,
            quiet: true,
            hold: None,
            stderr_dangling: std::sync::Arc::clone(&self.stderr_dangling),
            logo: self.logo.clone(),
        }
    }

    /// A line the reference sends to stderr. `-ierr` does not move these,
    /// they are already there; `-inul` still silences them, and `-idq`
    /// deliberately does NOT.
    ///
    /// A refusal is the only report a script gets of work that did not
    /// happen, and spec R.2's rule - exiting having done something
    /// different is the worse failure - is worth nothing if a switch can
    /// take the report away. The reference agrees: every `-idq` row in
    /// [`Out::new`]'s table keeps its stderr line.
    pub(crate) fn warn(&self, text: &str) {
        if self.silent {
            return;
        }
        self.release();
        write_out(Stream::Error, text.as_bytes());
        if !text.is_empty() {
            self.stderr_dangling
                .store(!text.ends_with('\n'), std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// `-idq` closing its own last stderr line: see
    /// [`Out::stderr_dangling`]. `dispatch` calls this once, after the
    /// command has run and every `warn` it made has already landed, and
    /// `bare` is whether the command was `lb` - the one spelling measured
    /// to keep its line open even under `-idq` (`unrar lb -idq nosuch.rar`
    /// answers `No such file or directory` with no trailing `\n`, where
    /// `l` in the same spot gets one).
    ///
    /// A no-op under `-inul` (nothing was written to close) and under a
    /// plain run (`quiet` is what asks for the close at all): a plain
    /// `unrar l nosuch.rar` leaves its line exactly as open as the
    /// reference does, and closing it here would be a difference this
    /// crate invented.
    pub(crate) fn close_dangling_stderr(&self, bare: bool) {
        if self.silent || !self.quiet || bare {
            return;
        }
        if self
            .stderr_dangling
            .swap(false, std::sync::atomic::Ordering::Relaxed)
        {
            let mut stream = std::io::stderr();
            let _ = stream.write_all(b"\n");
            let _ = stream.flush();
        }
    }

    /// A run refused before any member: `text` on stderr (opening with its
    /// newline and not ending with one), then `closing`, the verdict line
    /// that stands in the reference's place for it, or none under `-idd`.
    ///
    /// Measured against unrar 7.23 on 30 Sep 2026 over RAR 5 `-hp`
    /// archives and volume sets given a wrong password (`Incorrect password
    /// for <archive>`, closing `Total errors: 1`), rar 4.20 `-hp` archives
    /// whose first enciphered header fails (closing `No files to extract`,
    /// which `-idd` keeps), and an archive that is not there; `t`, `x` and
    /// `p`, plain, `-idq`, `-ierr`, `-idd` and `-inul`:
    ///
    /// - apart, the closing goes to stdout after one blank line and stderr
    ///   is left unended; `-idd` leaves the blank line alone;
    /// - on one stream (`-ierr`) the text ends itself and the closing
    ///   follows it directly;
    /// - where the stdout messages are dropped (`-idq`, and `p`, whose
    ///   stdout is the payload) there is no closing, and stderr ends with
    ///   one newline.
    pub(crate) fn refused(&self, text: &str, closing: Option<&str>) {
        if self.one_stream() {
            self.warn(&format!("{text}\n"));
            if let Some(closing) = closing {
                self.say(closing);
            }
        } else if self.says() {
            self.warn(text);
            self.say(&format!("\n{}", closing.unwrap_or("")));
        } else {
            self.warn(text);
            self.warn("\n");
        }
    }
}

/// One of the two streams a message is written to.
#[derive(Clone, Copy)]
enum Stream {
    Output,
    Error,
}

/// Whether `stream` is a terminal: asked of each stream once a run, and
/// each judged by what IT is (SPEC-CLI section 10, rule T2), so one may
/// be a terminal while the other is a pipe or a file.
fn is_terminal(stream: Stream) -> bool {
    use std::io::IsTerminal;
    static KINDS: std::sync::OnceLock<[bool; 2]> = std::sync::OnceLock::new();
    let kinds = KINDS.get_or_init(|| {
        [
            std::io::stdout().is_terminal(),
            std::io::stderr().is_terminal(),
        ]
    });
    kinds[stream as usize]
}

/// Writes one message, or one block of held messages, to `stream` as
/// that stream is sent it ([`shown`]), and flushes. Every byte of a
/// message that [`Out`] writes goes through here. Kept out of line: a
/// walk that holds its lines calls [`Out::say`] for each member and
/// this once a block.
#[inline(never)]
fn write_out(stream: Stream, text: &[u8]) {
    let text = shown(text, is_terminal(stream));
    match stream {
        Stream::Output => {
            let mut stream = std::io::stdout();
            let _ = stream.write_all(&text);
            let _ = stream.flush();
        }
        Stream::Error => {
            let mut stream = std::io::stderr();
            let _ = stream.write_all(&text);
            let _ = stream.flush();
        }
    }
}

/// Where a control character that came out of an archive is HELD while
/// its line is laid out: one private-use character for each, U+F0000
/// plus the control character's own code point. What is printed for it
/// depends on the stream the line ends up on (rules T3 and T5), which
/// is not known where the text is rendered: a name is rendered once and
/// may be printed on both streams. So the renderers of archive text put
/// the held character in ([`hold_controls`]) and [`shown`], the one
/// function every message leaves through, puts out the stand-in or the
/// character itself. One character stands for one, so a line that pads
/// a name pads it as it did (rule T8).
const HELD_FIRST: u32 = 0xF_0000;
/// A `<` of archive text that begins text of a stand-in's shape (P3).
const HELD_LESS_THAN: u32 = HELD_FIRST + 0xA0;
/// Says the character after it is the archive's own and is printed as
/// it is: one of these very characters, which a name may hold too.
const HELD_AS_IS: u32 = HELD_FIRST + 0xA1;
/// The first byte of every held character's UTF-8.
const HELD_LEAD: u8 = 0xF3;

/// The held character `bytes` begins with, if it begins with one.
fn held_at(bytes: &[u8]) -> Option<u32> {
    match *bytes {
        [HELD_LEAD, 0xB0, high @ 0x80..=0x82, low @ 0x80..=0xBF, ..] => {
            let held = HELD_FIRST + (u32::from(high - 0x80) << 6) + u32::from(low - 0x80);
            (held <= HELD_AS_IS).then_some(held)
        }
        _ => None,
    }
}

/// Archive text with each control character HELD (see [`HELD_FIRST`]),
/// for macOS and Linux. An escape is left as it is: it is six
/// characters on every stream (rule T4), which [`shown`] writes. In a
/// `comment` a line feed, a carriage return that a line feed follows,
/// and a tab are left too (rule T6). A `<` that begins text of a
/// stand-in's shape is held, since only a terminal is shown
/// `<U+003C>` for it (P3, T5).
fn hold_controls(text: &str, comment: bool) -> std::borrow::Cow<'_, str> {
    // Text with nothing to hold, which is nearly all of it: no control
    // character (the C1 ones begin with the byte C2), no `<`, and none
    // of the held characters themselves.
    let plain = |b: u8| match b {
        b'<' | 0x7F | 0xC2 | HELD_LEAD => false,
        _ => b >= 0x20,
    };
    if text.bytes().all(plain) {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 8);
    for (at, c) in text.char_indices() {
        let rest = &text[at..];
        let code = u32::from(c);
        let kept = c == '\u{1b}'
            || (comment
                && (matches!(c, '\n' | '\t') || (c == '\r' && rest[1..].starts_with('\n'))));
        let held = if kept {
            None
        } else if c.is_control() {
            Some(HELD_FIRST + code)
        } else if c == '<' && begins_like_a_stand_in(rest) {
            Some(HELD_LESS_THAN)
        } else {
            None
        };
        match held {
            Some(held) => out.extend(char::from_u32(held)),
            None => {
                if (HELD_FIRST..=HELD_AS_IS).contains(&code) {
                    out.extend(char::from_u32(HELD_AS_IS));
                }
                out.push(c);
            }
        }
    }
    std::borrow::Cow::Owned(out)
}

/// Rendered archive text as the archive holds it: every held character
/// as the one it stands for. For a caller that COMPARES a rendered name
/// (with a mask, with a stored name) and prints nothing.
fn as_stored(text: &str) -> std::borrow::Cow<'_, str> {
    if cfg!(windows) || !text.as_bytes().contains(&HELD_LEAD) {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match u32::from(c) {
            HELD_AS_IS => out.extend(chars.next()),
            HELD_LESS_THAN => out.push('<'),
            held @ HELD_FIRST..HELD_LESS_THAN => out.extend(char::from_u32(held - HELD_FIRST)),
            _ => out.push(c),
        }
    }
    std::borrow::Cow::Owned(out)
}

/// Whether `text` holds an ESC or the first byte of a held character:
/// the two things [`shown`] rewrites. This looks at every byte of a
/// listing, so it reads eight bytes at a time and stops at none: a
/// word with either byte in it, exclusive-ored with eight of that
/// byte, has a zero byte, which `(w - 0x01..) & !w & 0x80..` finds
/// without a branch.
///
/// Counted on a 20,000-member archive (instructions, an Apple silicon
/// Mac, 10 Oct 2026, against one search for ESC alone, which is what
/// stood here before): a pass that tests each byte for the two and
/// stops at the first cost `t -mt1` 4.7 percent; a second search for
/// one byte beside the first, 1.5 percent.
fn holds_what_is_rewritten(text: &[u8]) -> bool {
    const ONES: u64 = 0x0101_0101_0101_0101;
    const HIGH: u64 = 0x8080_8080_8080_8080;
    const ESCAPES: u64 = ONES * 0x1b;
    const LEADS: u64 = ONES * HELD_LEAD as u64;
    let zero_byte = |word: u64| word.wrapping_sub(ONES) & !word & HIGH;
    let (words, rest) = text.as_chunks::<8>();
    let mut found = 0;
    for word in words {
        let word = u64::from_ne_bytes(*word);
        found |= zero_byte(word ^ ESCAPES) | zero_byte(word ^ LEADS);
    }
    found != 0 || rest.iter().any(|&b| b == 0x1b || b == HELD_LEAD)
}

/// A message as it is written to a stream that is a `terminal` or is
/// not: the one function every message leaves through.
///
/// On macOS and Linux (SPEC-CLI section 10):
///
/// - every ESC is the six characters `'\033'`, on a terminal and
///   through a pipe alike (rule T4), in archive text and in any other
///   (the archive's own path, say). It is what the reference writes:
///   measured with rar and unrar 7.23 on Linux and macOS, 27 Sep 2026,
///   in a member name under `l`, `v`, `lt`, `lb`, `t` and `x`, in an
///   archive comment, in the `Archive:` and `Testing archive` lines of
///   an archive whose file name holds an ESC, and in the stderr `Cannot
///   open` line for one that does not exist;
/// - a control character HELD in archive text ([`hold_controls`]) is
///   its stand-in `<U+XXXX>` on a terminal (rule T3) and the character
///   itself on any other stream (rule T5); a held `<` is `<U+003C>` on
///   a terminal and `<` elsewhere;
/// - nothing else is changed (rule T8). The expansion comes after the
///   line is laid out: a progress line pads a name holding one control
///   character as one character wider than without it.
///
/// A Windows target writes what it is given: its renderers have put
/// the stand-ins in already, for every stream (rule T7).
///
/// Held stdout is scanned a block at a time when it is written, not a
/// message at a time: counted with `perf stat -e instructions:u` on
/// a small x86-64 VPS, a scan per message cost `t -mt1` 0.13 percent of its
/// instructions on a 20,000-member archive (about 290 a member, a short
/// search per line piece), where one scan of the block costs a few.
fn shown(text: &[u8], terminal: bool) -> std::borrow::Cow<'_, [u8]> {
    if cfg!(windows) || !holds_what_is_rewritten(text) {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut out = Vec::with_capacity(text.len() + 16);
    let mut at = 0;
    while at < text.len() {
        if text[at] == 0x1b {
            out.extend_from_slice(b"'\\033'");
            at += 1;
            continue;
        }
        let Some(held) = held_at(&text[at..]) else {
            out.push(text[at]);
            at += 1;
            continue;
        };
        at += 4;
        match held {
            HELD_AS_IS => {
                // The archive's own character, whole and as it is.
                let end = (at + 1..text.len())
                    .find(|&next| text[next] & 0xC0 != 0x80)
                    .unwrap_or(text.len());
                out.extend_from_slice(&text[at..end]);
                at = end;
            }
            HELD_LESS_THAN if terminal => out.extend_from_slice(b"<U+003C>"),
            HELD_LESS_THAN => out.push(b'<'),
            _ if terminal => {
                let _ = write!(out, "<U+{:04X}>", held - HELD_FIRST);
            }
            _ => {
                let mut bytes = [0; 4];
                let own = char::from_u32(held - HELD_FIRST).unwrap_or(char::REPLACEMENT_CHARACTER);
                out.extend_from_slice(own.encode_utf8(&mut bytes).as_bytes());
            }
        }
    }
    std::borrow::Cow::Owned(out)
}

impl Drop for Out {
    fn drop(&mut self) {
        self.release();
    }
}

/// Which host wrote a member, which decides how its attributes render and
/// what the technical listing's `Host OS:` line says, if anything.
///
/// The set is `rarkit::HostOs`'s, with the two cases the reference tells
/// apart by format rather than by byte: the RAR 1.3 container, which
/// stores no host at all, and the RAR 1.5 to 4.x family's byte 6, which
/// only that family names. Every row of [`HostOs::name`] and
/// [`HostOs::attribute_form`] was measured against `unrar lta` 7.23 on
/// an M3 Mac, 26 Sep 2026, over the committed legacy fixtures and over
/// copies of `d155_m0`, `d250_m0`, `r393_m0` and `h5_x86_m5` with only the
/// host byte (and the header check value) changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostOs {
    /// RAR 1.5 to 4.x host 0.
    MsDos,
    /// RAR 1.5 to 4.x host 1.
    Os2,
    /// RAR 1.5 to 4.x host 2, RAR 5 host 0.
    Windows,
    /// RAR 1.5 to 4.x host 3, RAR 5 host 1.
    Unix,
    /// RAR 1.5 to 4.x host 4.
    MacOs,
    /// RAR 1.5 to 4.x host 5.
    BeOs,
    /// RAR 1.5 to 4.x host 6.
    WinCe,
    /// Any other byte, in either family: RAR 1.5 to 4.x above 6, RAR 5
    /// above 1.
    Other(u8),
    /// The RAR 1.3 container, whose file header has no host field.
    Unrecorded,
}

/// How a host's attribute word is written in a listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttributeForm {
    /// The seven-position DOS word, `..A....`.
    Dos,
    /// Unix mode bits, `-rw-r--r--`.
    Mode,
    /// A host the reference does not interpret: a lone `?`.
    Unknown,
}

impl HostOs {
    /// The `Host OS:` line's value, or `None` where the reference prints
    /// no such line (the RAR 1.3 container and an unnamed byte).
    pub(crate) fn name(self) -> Option<&'static str> {
        match self {
            Self::MsDos => Some("DOS"),
            Self::Os2 => Some("OS/2"),
            Self::Windows => Some("Windows"),
            Self::Unix => Some("Unix"),
            Self::MacOs => Some("Mac OS"),
            Self::BeOs => Some("BeOS"),
            Self::WinCe => Some("WinCE"),
            Self::Other(_) | Self::Unrecorded => None,
        }
    }

    /// Which form the attribute word takes. Mac OS reads as DOS and BeOS
    /// as Unix, which is the reference's grouping, not a guess from the
    /// systems' names.
    pub(crate) fn attribute_form(self) -> AttributeForm {
        match self {
            Self::MsDos | Self::Os2 | Self::Windows | Self::MacOs | Self::Unrecorded => {
                AttributeForm::Dos
            }
            Self::Unix | Self::BeOs => AttributeForm::Mode,
            Self::WinCe | Self::Other(_) => AttributeForm::Unknown,
        }
    }
}

/// A member's display name: a range of ONE rendered string shared by
/// every member of its volume, so a volume of twenty thousand names is one
/// allocation rather than twenty thousand, and a copy of a name is a count
/// bumped rather than text copied.
///
/// Reads as the `str` it holds, compares by that text (never by which pool
/// or where in it: a member split over two volumes has its name in two
/// pools), and is the same 24 bytes a `String` is. A name that outlives
/// its volume's member list keeps that volume's whole string alive.
#[derive(Clone)]
pub(crate) struct Name {
    pool: std::sync::Arc<String>,
    start: usize,
    end: usize,
}

impl Name {
    /// The name at `start..end` of `pool`, which must be on character
    /// boundaries (a range recorded while the pool was written).
    pub(crate) fn new(pool: &std::sync::Arc<String>, start: usize, end: usize) -> Self {
        Self {
            pool: std::sync::Arc::clone(pool),
            start,
            end,
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.pool[self.start..self.end]
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.as_str().as_bytes()
    }
}

impl std::ops::Deref for Name {
    type Target = str;

    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for Name {}

impl PartialEq<str> for Name {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for Name {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl std::fmt::Debug for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.as_str(), f)
    }
}

impl std::fmt::Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A name alone in a pool of its own, for a member built one at a time.
impl From<&str> for Name {
    fn from(text: &str) -> Self {
        let pool = std::sync::Arc::new(text.to_owned());
        Self::new(&pool, 0, text.len())
    }
}

/// One archive member, in the fields the four listing layouts and the
/// progress lines need.
#[derive(Debug, Clone)]
pub(crate) struct Member {
    /// Display name, separators already native. For the TERMINAL only:
    /// what reaches the file system is [`Member::disk_name`].
    pub(crate) name: Name,
    /// The name the file system gets, where it differs from `name`'s
    /// text: see [`disk_name`]. `None` for the common name, which reads
    /// the same both ways and is not stored twice.
    pub(crate) disk: Option<std::sync::Arc<[u8]>>,
    /// Whether the reference can print the name on this host at all, as
    /// [`listed_name_into`] says; `name` is empty where it cannot.
    pub(crate) printable: bool,
    /// Whether it is a directory entry.
    pub(crate) is_dir: bool,
    /// Whether it is a service header (`QO`, `CMT`, `RR`), which only the
    /// `lta`/`vta` spellings show.
    pub(crate) is_service: bool,
    /// Unpacked size.
    pub(crate) size: u64,
    /// Packed size in this volume.
    pub(crate) packed: u64,
    /// Modification time as Unix seconds, when the archive carried one.
    pub(crate) mtime: Option<i64>,
    /// The fraction of `mtime`'s second, in nanoseconds, as the archive
    /// stored it: a RAR 5 TIME record to the nanosecond or to the 100 ns
    /// FILETIME tick, a RAR 4 extended time to the 100 ns tick, zero for a
    /// bare DOS time. Only extraction reads it, to restore the time as
    /// stored; the listings print whole seconds from `mtime` alone.
    pub(crate) mtime_nanos: u32,
    /// Whether `mtime` came from a stored WALL CLOCK (a DOS date-and-time
    /// word, which every format before RAR 5 uses) rather than from a real
    /// instant. It decides which zone the listing renders it in; see
    /// [`time::wall`].
    pub(crate) wall_clock: bool,
    /// Raw attributes, interpreted per `host`.
    pub(crate) attr: u64,
    /// The host that wrote it.
    pub(crate) host: HostOs,
    /// Stored CRC-32, absent for directories and some service headers.
    pub(crate) crc32: Option<u32>,
    /// Whether the payload is encrypted, which the listing marks with `*`.
    pub(crate) encrypted: bool,
    /// Whether a password check record was judged before the member's
    /// bytes (`rarkit::MemberInfo::password_checked`), which decides how
    /// a failed checksum of an encrypted member is reported.
    pub(crate) password_checked: bool,
    /// `Some` when the member is an older version of a file
    /// (`rarkit::MemberInfo::file_version`): listed under `name;n`, and
    /// processed only under `-ver`.
    pub(crate) version: Option<rarkit::FileVersion>,
    /// Whether this fragment continues one from the previous volume.
    pub(crate) split_before: bool,
    /// Whether it continues into the next volume.
    pub(crate) split_after: bool,
    /// The unpack version the header declares, as `rarkit::MemberInfo`
    /// carries it: RAR 5's compression version (0 for RAR 5.0, 1 for
    /// RAR 7), or the RAR 1.5 to 4.x family's own unpack version (13 to
    /// 15 for RAR 1.5, 20 or 26 for RAR 2.0, 29 and above for RAR 2.9 and
    /// later), or 2 for the RAR 1.3 container, which stores that constant
    /// in every archive. The technical listing's `Compression:` line reads
    /// this to pick both the family word and the printed version number;
    /// see `list::compression_clause`.
    pub(crate) algorithm_version: u32,
    /// Compression method, 0 through 5.
    pub(crate) method: u8,
    /// Dictionary size in bytes, `None` where the entry has no dictionary
    /// (a directory), which is the case the reference prints without a
    /// `-md=` clause.
    pub(crate) dictionary: Option<u64>,
    /// Whether the entry is part of a solid stream.
    pub(crate) solid: bool,
    /// Whether the engine refuses this member for its version alone: a
    /// COMPRESSED file (not a directory) whose RAR 5 compression version
    /// names no dictionary (spec F 3.2.6.3), or whose RAR 1.5 to 4.x
    /// unpack version spec F 3.3.5's table does not name. Its close is a
    /// refusal, never a checksum failure (`extract::Walk::on_close`).
    pub(crate) unknown_version: bool,
    /// Offset just past this member's data in its own archive file, which
    /// is what the percentage counter is a fraction of.
    pub(crate) data_end: u64,
    /// `Some` for a symbolic link, junction, hard link or file copy (spec
    /// F 3.2.6.2, 3.3.12), as the listing reports it.
    pub(crate) redirect: Option<Redirect>,
}

/// A redirection member's record, as a listing reports it.
#[derive(Clone, Debug)]
pub(crate) struct Redirect {
    pub(crate) kind: rarkit::RedirectionKind,
    /// The target as stored; `None` for the RAR 4 family, whose target is
    /// the member's content and is read only at extraction.
    pub(crate) target: Option<Vec<u8>>,
}

/// One archive file, parsed, with the facts a listing header needs.
///
/// It holds no engine handle. `crate::engine` builds it from rarkit's
/// `Archive`, and the extraction walk re-opens the volumes by NAME through
/// `rarkit::extract`, because rarkit's extract entry points take sources
/// rather than a parsed archive.
pub(crate) struct Opened {
    /// The archive comment, when the archive carries one.
    pub(crate) comment: Option<Vec<u8>>,
    /// Its members, in stored order.
    pub(crate) members: Vec<Member>,
    /// The `Details:` line's text, without the label.
    pub(crate) details: String,
    /// The file's length, the denominator of the percentage counter.
    pub(crate) size: u64,
    /// The main header block's own byte span (its CRC, size, flags and
    /// any extra area - everything from just past the format signature
    /// to the first member), which `percent`'s denominator
    /// leaves out.
    ///
    /// Measured 28 Sep 2026 against unrar 7.23 over RAR 5 archives of 3,
    /// 5 and 7 tiny stored members (`rand.bin`-free fixtures built here,
    /// a main header of 15 bytes past the 8 byte signature in every
    /// case): `unrar x -ierr` on the 5 member archive (276 bytes, its
    /// last member's data ending at file offset 268) reads `28%, 47%,
    /// 67%, 86%, 100%` where dividing each member's raw `data_end` by
    /// 268 (this crate's prior denominator) gives `26%, 45%, 63%, 81%,
    /// 100%` - a member's `data_end` is unaffected (it is an absolute
    /// file offset the reference and this crate agree on), so only the
    /// DENOMINATOR was wrong, and by exactly the main header's own size:
    /// `268 - 15 = 253` reproduces every one of the reference's five
    /// figures exactly, and the same subtraction reproduces the 3 and 7
    /// member archives' figures too (7, 9, and 6 checkpoints respectively
    /// across the three archives, all exact). `p`'s own counter is the
    /// same machinery under `Mode::Print` and read the same one low.
    pub(crate) main_header_size: u64,
    /// What the progress counter counts of this file when it is the LAST
    /// volume the walk reads: up to the end of its end record, less the
    /// service blocks after its last member; the whole file when no end
    /// record was read. Every EARLIER volume counts its whole file.
    ///
    /// Measured against unrar 7.23 on 30 Sep 2026 over the committed
    /// four-part sets and fourteen sets written by rar 7.23 at `-v4k` to
    /// `-v20k`, with and without a quick-open index in every volume: a
    /// volume before the last counts its whole file, padding and index
    /// included (`two.part1.rar`'s 4,096 bytes, not the 4,017 its data
    /// ends at, which read one high from the second volume on); the last
    /// counts to its end record (`two.part4.rar`'s 220 bytes, not 212)
    /// but not the index or recovery record behind its last member, which
    /// the 18 Sep 2026 measurement of single archives had found; and an
    /// archive whose walk stopped at a damaged header counts the whole
    /// file (`r420_dmg`'s ` 30%`, where the walked part read `100%`).
    pub(crate) counted_end: u64,
    /// Whether the main header says this is one volume of a set.
    pub(crate) is_volume: bool,
    /// Whether this volume's end record says another volume follows
    /// (SPEC-F 3.2.7 and 3.3.10), or `None` where the archive has no end
    /// record to say (API `VolumeInfo::next_follows`).
    pub(crate) next_follows: Option<bool>,
    /// Whether the main header says the members form a solid chain.
    ///
    /// Read for the `Details:` line, and read again by
    /// `extract::Run::drive` to pick the engine entry point: a solid
    /// chain's members are decoded one after another by the format's own
    /// rule (spec F 3.6), so the concurrent driver can add nothing to it
    /// but the cost of its own write pipe, which is measured.
    ///
    /// Read only where there is a concurrent path to choose, which is why
    /// a build without `parallel` is told the field is meant to be unread
    /// rather than told to drop it: the `Details:` line is built in
    /// `crate::engine` from the same fact.
    #[cfg_attr(not(feature = "parallel"), allow(dead_code))]
    pub(crate) solid: bool,
    /// Whether the password on the command line failed the archive's own
    /// check. The headers were still read, without one, because that is
    /// what the reference goes on to list.
    pub(crate) password_wrong: bool,
    /// Whether the archive's headers are enciphered, so that opening it
    /// derived a key the extraction walk can reuse. Read by
    /// `extract::run` to keep the open's session for the walk only then:
    /// an archive with readable headers derives nothing at open, and
    /// keeping the session across the walk measured as a small cost there.
    pub(crate) header_encrypted: bool,
    /// Whether the headers are enciphered in the RAR 1.5 to 4.x family,
    /// which carries no password check: a header that fails there cannot
    /// tell a wrong password from damage, and the reference says so in
    /// place of `Corrupt header is found` (`Run::report_corrupt_header` in
    /// `extract.rs`).
    pub(crate) headers_unchecked: bool,
    /// Why the header walk stopped short of the volume's end, when it did:
    /// a source cut inside a header or a data area, or a header the walk
    /// cannot step over. The members parsed before it are all here and all
    /// valid (spec F 4.6), and the reference lists and extracts them too.
    pub(crate) tail: Option<Tail>,
    /// One entry for each header of this volume that was READ although its
    /// own checksum failed, in archive order. Measured against unrar 7.23
    /// on 8 Oct 2026: it reads such a header, tests, extracts and lists
    /// its member and every later one, and exits 3.
    pub(crate) damaged: Vec<DamagedHeader>,
}

/// What is said and counted for a header that was read although its own
/// checksum failed (spec F 4.6 rule 1: reported, NAMED, and the run is
/// never a success; exit 3). The words and counts are the reference's
/// where it has them (unrar 7.23, 8 Oct 2026, `t`, `x`, `l` and `lb`,
/// over rarfast's own RAR 5 archives and the genuine rar 4.2.0 vectors,
/// each with one header's checksum field changed):
///
/// | Header | RAR 5 | RAR 1.5 to 4.x |
/// |---|---|---|
/// | main | `Corrupt header is found`, `Main archive header is corrupt`, 2 errors | `Main archive header is corrupt`, 1 error |
/// | a member's | `Corrupt header is found`, `<name> - the file header is corrupt`, 2 | `<name> - the file header is corrupt`, 2 |
/// | a service's | `Corrupt header is found`, `QO - the file header is corrupt`, 2 | |
/// | an end record | `Corrupt header is found`, 2 | nothing said, 1 |
///
/// Three differences, each chosen. An end record, and a block of no
/// known kind, is named here by a line of this program's own (`End of
/// archive header is corrupt`, `Header at offset <n> is corrupt`), where
/// the reference names nothing. A member header read from a sound quick
/// open copy is said and counted as any other, exit 3, where the
/// reference says nothing and exits 0 (3.2.9.1 rule 4). And the reference
/// says a FIRST member's header twice and counts four.
#[derive(Clone, Debug)]
pub(crate) struct DamagedHeader {
    /// The lines, each without a newline.
    pub(crate) lines: Vec<String>,
    /// What it adds to `Total errors`.
    pub(crate) errors: usize,
}

/// What stopped a volume's header walk before its end (spec F 3.5.5, 4.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tail {
    /// The source ended inside a header or a data area: a partial
    /// download, a half-copied file. The reference's word is
    /// [`UNEXPECTED_END`].
    Truncated,
    /// A header failed its own checksum or broke the format's framing, so
    /// the walk cannot know where the next one starts. The reference's
    /// word is [`CORRUPT_HEADER`].
    CorruptHeader,
}

impl Member {
    /// Cuts the `;n` of an older version off the name, in both forms:
    /// what `-ver<n>` processes a version as.
    pub(crate) fn drop_version_suffix(&mut self) {
        if let Some(at) = self.name.as_str().rfind(';') {
            self.name.end = self.name.start + at;
        }
        if let Some(disk) = &self.disk {
            if let Some(at) = disk.iter().rposition(|byte| *byte == b';') {
                self.disk = Some(disk[..at].into());
            }
        }
    }

    /// The name as the file system gets it, separated by `/`, before the
    /// traversal checks of `crate::safepath` judge it. Never the display
    /// form: see [`disk_name`].
    pub(crate) fn disk_name(&self) -> &[u8] {
        match &self.disk {
            Some(bytes) => bytes,
            None => self.name.as_bytes(),
        }
    }

    /// The name for a COMPARISON (with a mask, with a stored name): the
    /// listing's text as the archive holds it, with no control character
    /// held for a terminal ([`as_stored`]). A name that holds one never
    /// equals its on-disk bytes, so a member that keeps no on-disk name
    /// apart has nothing held, and its name is looked at no further:
    /// counted, a search of every name cost a 20,000-member `lb` about
    /// half a percent of its instructions.
    pub(crate) fn compared_name(&self) -> std::borrow::Cow<'_, str> {
        if self.disk.is_none() {
            return std::borrow::Cow::Borrowed(self.name.as_str());
        }
        as_stored(&self.name)
    }
}

impl Opened {
    /// The archive comment, when the archive carries one.
    pub(crate) fn archive_comment(&self) -> Option<Vec<u8>> {
        self.comment.clone()
    }
}

/// The reference's word for an archive that stops before its END record.
///
/// Said ONCE, after the members in front of the cut, and counted once.
/// Measured against unrar 7.23 on 27 Sep 2026 over RAR 5 archives written
/// `-qo-` and the genuine rar 4.2.0 vectors, cut inside a later header and
/// inside a member's data, for `t`, `x`, `l`, `lb` and `lt`: one line each
/// time. The reference says it a SECOND time, first, before any member,
/// only on a RAR 5 archive whose main header carries a quick open LOCATOR
/// pointing past the cut; that second line is the locator being read, and
/// spec F 4.1 says a locator that lands outside the volume is ignored. So
/// it is not said here: `tests/cut_and_damaged.rs` pins the difference.
pub(crate) const UNEXPECTED_END: &str = "\nUnexpected end of archive";

/// The reference's word for a header the walk cannot step over, measured
/// against unrar 7.23 on 27 Sep 2026 on a RAR 5 archive whose third
/// member's header size was damaged: the members before it are tested or
/// listed, then this, and the run exits 3.
pub(crate) const CORRUPT_HEADER: &str = "\nCorrupt header is found";

/// `unrar`'s own percentage: how far into the ARCHIVE FILE the reference
/// has read, floored - as a fraction of the end of the LAST PAYLOAD, not
/// of the file length. What the two denominators differ by is the END
/// record and any service block behind the last member, and it is worth
/// a whole point on every intermediate line: see the measurement at
/// `volume_last_data`'s own site in `extract.rs`.
///
/// Getting this wrong is not cosmetic. The conformance normaliser
/// rewrites `\b\d{1,3}%` to a fixed token but leaves the space in front
/// of it, so ` 4%` and `100%` produce lines one character apart and the
/// row diverges on length alone. Measured against the reference on the
/// `compressed` shape, where `text.txt` packs to 642 bytes of a 25 kB
/// archive and the line is one character longer than every other line in
/// the same row for exactly this reason.
pub(crate) fn percent(data_end: u64, archive_size: u64) -> u64 {
    if archive_size == 0 {
        return 0;
    }
    (data_end.saturating_mul(100) / archive_size).min(100)
}

/// Renders an archive member name for display: separators are the
/// platform's, because that is what the reference prints. The Windows
/// table lists `sub\nested.txt` where the macOS one lists
/// `sub/nested.txt`, for the same logical member.
#[cfg(test)]
pub(crate) fn display_name(raw: &[u8]) -> String {
    let mut out = String::new();
    append_listed_name(raw, &mut out);
    out
}

/// `display_name` appended to `out`, so many names can be rendered
/// end to end into one string. The same text, byte for byte.
pub(crate) fn append_listed_name(raw: &[u8], out: &mut String) {
    // The separator a name may carry from the other family of systems,
    // and this platform's own, which it is shown as.
    const FOREIGN: char = if cfg!(windows) { '/' } else { '\\' };
    const NATIVE: char = if cfg!(windows) { '\\' } else { '/' };
    out.reserve(raw.len());
    for piece in raw.utf8_chunks() {
        // Text goes across in runs: a run ends at a character that is
        // shown as something else: a separator, a control character, or
        // a `<` that would read as a control character's stand-in.
        let text = piece.valid();
        let mut run = 0;
        for (at, c) in text.char_indices() {
            let separator = c == FOREIGN;
            if separator || stands_in(c, &text[at..]) {
                out.push_str(&text[run..at]);
                if separator {
                    out.push(NATIVE);
                } else {
                    push_escaped_control(c, out);
                }
                run = at + c.len_utf8();
            }
        }
        out.push_str(&text[run..]);
        // Bytes that are no UTF-8 show as one replacement character for
        // each broken sequence.
        if !piece.invalid().is_empty() {
            out.push(char::REPLACEMENT_CHARACTER);
        }
    }
}

/// The printed form of a control character wherever a name is shown
/// escaped and not raw: the one place that form is chosen. It is
/// rarfast's own (SPEC-CLI section 7, rule P2): the eight printable
/// characters `<U+XXXX>`, four upper case hexadecimal digits, so a TAB
/// is `<U+0009>` and nothing a stored name holds can drive a terminal.
/// A `<` that must not be taken for one goes through here too (P3).
fn push_escaped_control(c: char, out: &mut String) {
    use std::fmt::Write as _;
    let _ = write!(out, "<U+{:04X}>", u32::from(c));
}

/// Whether `c`, the first character of `from_it`, is shown as a stand-in
/// and not as itself: every control character (P1: C0, DEL and C1, the
/// 65 of them), and a `<` that begins text shaped like a stand-in (P3).
fn stands_in(c: char, from_it: &str) -> bool {
    c.is_control() || (c == '<' && begins_like_a_stand_in(from_it))
}

/// Whether `text` begins with text of a stand-in's exact shape: `<U+`,
/// four hexadecimal digits of either case, `>` (SPEC-CLI section 7, rule
/// P3). A name's own `<` that begins such text is shown as `<U+003C>`,
/// so that every `<U+XXXX>` on a line is a stand-in and the name can be
/// read back from it.
fn begins_like_a_stand_in(text: &str) -> bool {
    matches!(
        text.as_bytes(),
        [b'<', b'U', b'+', a, b, c, d, b'>', ..]
            if [a, b, c, d].iter().all(|digit| digit.is_ascii_hexdigit())
    )
}

/// Whether this host's file system stores any byte string as a name
/// component, so a stored name need not be valid UTF-8 to be written.
/// Linux and the other Unix systems do; macOS refuses one that is not
/// (APFS answers `Illegal byte sequence`) and Windows names are UTF-16.
const HOST_TAKES_ANY_BYTES: bool =
    cfg!(all(unix, not(any(target_os = "macos", target_os = "ios"))));

/// A member's name as it is WRITTEN to the file system: the stored name
/// after the format's own decoding (`rarkit::MemberInfo::name`, `/`
/// between components), never the display form, which escapes control
/// characters for the terminal and maps separators for the listing.
///
/// `rar5` says whether the name came from a RAR 5 header. Measured
/// against unrar 7.23 on Linux (a small x86-64 VPS) and macOS (an M3 Mac),
/// 27 Sep 2026, over archives holding one member each, written from spec F
/// 3.2 with every byte 0x00 to 0x1F, 0x7F, `\`, `:`, `*`, `?` and several
/// invalid UTF-8 sequences, under host bytes 0, 1, 2, 3 and 5:
///
/// - Every control character is written byte for byte, under every host
///   (`a\tb`, `a\x1bb`, a name that is only `\t`).
/// - A RAR 5 name's `\` is an ordinary character, written as it is, under
///   every host byte but 0 (Windows), where it is written `_`: RAR 5
///   stores `/` between components, so a `\` from Windows is one no
///   Windows name can hold. RAR 1.3 to 4 names reach here with their
///   separators already `/` (spec F question 3), which is also what the
///   reference makes of a Unix name's `\` in that family: rar 4.2.0 on
///   Linux stored `bs\x` as `bs\x` and unrar 7.23 wrote a directory `bs`
///   holding `x`.
/// - A NUL ends the name, in every format and on every host: `a\0b`
///   writes `a`.
/// - A RAR 5 name ends at its first byte that does not continue valid
///   UTF-8 (`a\xffb` writes `a` on both hosts). A RAR 1.3 to 4 8-bit name
///   is written byte for byte where the host takes any bytes (Linux wrote
///   `caf\xe9`) and ends there where it does not (macOS wrote `caf`).
///
/// A name that ends up empty is skipped by the caller, as the reference
/// skips it. What is returned is then judged by `crate::safepath`, so a
/// cut cannot make a refused name acceptable: `..\0/x` becomes `..`,
/// which is refused.
pub(crate) fn disk_name(raw: &[u8], host: HostOs, rar5: bool) -> std::borrow::Cow<'_, [u8]> {
    let mut name = match raw.iter().position(|&b| b == 0) {
        Some(end) => &raw[..end],
        None => raw,
    };
    if rar5 || !HOST_TAKES_ANY_BYTES {
        if let Err(err) = std::str::from_utf8(name) {
            name = &name[..err.valid_up_to()];
        }
    }
    if rar5 && host == HostOs::Windows && name.contains(&b'\\') {
        return std::borrow::Cow::Owned(
            name.iter()
                .map(|&b| if b == b'\\' { b'_' } else { b })
                .collect(),
        );
    }
    std::borrow::Cow::Borrowed(name)
}

/// Whether this host's C library gives up on a whole message it cannot
/// convert, as macOS does, rather than replacing what it cannot convert,
/// as glibc does. Measured with unrar 7.23 in a UTF-8 locale on macOS
/// (an M3 Mac) and Linux (a small x86-64 VPS), 27 Sep 2026: a RAR 5 name
/// holding a UTF-16 surrogate lists as `a?b` on Linux and not at all on macOS,
/// and a RAR 1.3 to 4 name holding a byte that is not UTF-8 lists as far
/// as that byte on macOS and in full on Linux (see [`host_text_into`]).
const APPLE_TEXT: bool = cfg!(any(target_os = "macos", target_os = "ios"));

/// A member's name as the unrar 7.23 LISTING shows it (`l`, `v`, `lt`,
/// `lb`, and the `t` progress line), appended to `out`. Returns `false`
/// where the reference cannot print the name at all on this host, which
/// only a surrogate on macOS does: `lt` then drops the `Name:` line, `lb`
/// the whole line, and `l` and `v` show the row with no name.
///
/// Measured against unrar 7.23 in a UTF-8 locale on Linux (a small x86-64 VPS)
/// and macOS (an M3 Mac), 27 Sep 2026, over one-member archives written
/// from spec F 3.2 for every byte 0x01 to 0x1F and 0x7F, `\`, NUL, C1
/// controls, and valid, overlong, out-of-range and broken UTF-8, under
/// host bytes 0, 1 and 3; and RAR 4 archives from rar 4.2.0:
///
/// - Every control character is printed as the byte it is: a TAB, a
///   newline, BEL, DEL, a C1 control. ESC is the one exception, and it is
///   not the name's: the reference writes ESC as `'\033'` wherever it
///   prints one, so [`Out`] does that, after any padding is measured.
/// - A RAR 5 name is decoded as the reference decodes UTF-8, which is
///   more lenient than the standard: an overlong form is taken for the
///   character it spells (`C0 AF` lists as `/`, `C1 81` as `A`), a code
///   point above U+10FFFF is dropped and the name goes on, and the name
///   ends at a NUL (`C0 80` included) or at the first byte that starts no
///   sequence it takes (a stray continuation byte, `F8` and above, a
///   sequence cut short). A surrogate lists as `?` on Linux.
/// - A RAR 5 name's `\` lists as `\` under every host byte but 0
///   (Windows), where it lists as `_`, the same as it is written.
/// - A RAR 1.3 to 4 name has its separators as `/` already, and ends at
///   a NUL; its bytes then read as [`host_text_into`] reads them.
///
/// A Windows target is unmeasured and keeps the rendering it had.
pub(crate) fn listed_name_into(raw: &[u8], host: HostOs, rar5: bool, out: &mut String) -> bool {
    if cfg!(windows) {
        append_listed_name(raw, out);
        return true;
    }
    // The common name: printable ASCII with no `\` and no `<`, which
    // lists byte for byte whatever its host and format and holds nothing
    // a terminal is shown otherwise ([`hold_controls`]). One pass, as the
    // renderer before this one made: counted, three passes cost the `t`
    // walk about 0.2 percent of its instructions on a 20,000-member
    // archive.
    if raw
        .iter()
        .all(|&b| (0x20..0x7F).contains(&b) && b != b'\\' && b != b'<')
    {
        if let Ok(text) = std::str::from_utf8(raw) {
            out.push_str(text);
            return true;
        }
    }
    let start = out.len();
    let printable = listed_name_unheld(raw, host, rar5, out);
    if let std::borrow::Cow::Owned(held) = hold_controls(&out[start..], false) {
        out.truncate(start);
        out.push_str(&held);
    }
    printable
}

/// [`listed_name_into`] for a name the common path did not take, before
/// its control characters are held.
fn listed_name_unheld(raw: &[u8], host: HostOs, rar5: bool, out: &mut String) -> bool {
    let raw = match raw.iter().position(|&b| b == 0) {
        Some(end) => &raw[..end],
        None => raw,
    };
    if !rar5 {
        host_text_into(raw, out);
        return true;
    }
    let start = out.len();
    let windows = host == HostOs::Windows;
    let mut at = 0;
    while at < raw.len() {
        let lead = raw[at];
        let (len, bits) = match lead {
            0x01..=0x7F => (1, u32::from(lead)),
            0xC0..=0xDF => (2, u32::from(lead & 0x1F)),
            0xE0..=0xEF => (3, u32::from(lead & 0x0F)),
            0xF0..=0xF7 => (4, u32::from(lead & 0x07)),
            _ => break,
        };
        let Some(tail) = raw.get(at + 1..at + len) else {
            break;
        };
        if tail.iter().any(|&b| b & 0xC0 != 0x80) {
            break;
        }
        let point = tail
            .iter()
            .fold(bits, |acc, &b| (acc << 6) | u32::from(b & 0x3F));
        at += len;
        match point {
            0 => break,
            0xD800..=0xDFFF if APPLE_TEXT => {
                out.truncate(start);
                return false;
            }
            0xD800..=0xDFFF => out.push('?'),
            0x5C if windows => out.push('_'),
            _ => {
                if let Some(c) = char::from_u32(point) {
                    out.push(c);
                }
            }
        }
    }
    true
}

/// Bytes read as text the way the reference reads a name through the C
/// library: valid UTF-8 as it is, and a byte that is not UTF-8 either
/// ending the text (macOS) or, on Linux, kept as the private-use
/// character U+E000 plus the byte, with one U+FFFE before the first such
/// character. Measured with unrar 7.23 over rar 4.2.0 archives whose
/// 8-bit names hold `\xe9`, `\xe8`, `\x80`, `\xff` and a lone `\xc3`,
/// alone, twice, split by ASCII and beside a valid `\xc3\xa9`: Linux
/// listed `a\xe9b\xe8c` as `a`, U+FFFE, U+E0E9, `b`, U+E0E8, `c`, and
/// macOS listed it `a`. The `x` and `t` progress lines read the same.
fn host_text_into(bytes: &[u8], out: &mut String) {
    let mut marked = false;
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid());
        if chunk.invalid().is_empty() {
            continue;
        }
        if APPLE_TEXT {
            return;
        }
        if !marked {
            out.push('\u{FFFE}');
            marked = true;
        }
        for &b in chunk.invalid() {
            // U+E000 to U+E0FF are all scalar values.
            out.extend(char::from_u32(0xE000 + u32::from(b)));
        }
    }
}

/// An on-disk name, or a path built from one, as the reference shows it
/// on a progress or `Creating` line: [`host_text_into`] over the bytes,
/// every control character as it is (ESC is [`Out`]'s), a `\` as the `\`
/// it is. A Windows target is unmeasured: it shows a control
/// character as its stand-in (SPEC-CLI section 7) and a byte that is not
/// UTF-8 as U+FFFD.
pub(crate) fn progress_line_name(name: &[u8]) -> String {
    if !cfg!(windows) {
        let mut out = String::with_capacity(name.len());
        host_text_into(name, &mut out);
        return match hold_controls(&out, false) {
            std::borrow::Cow::Owned(held) => held,
            std::borrow::Cow::Borrowed(_) => out,
        };
    }
    escaped_text(name)
}

/// `bytes` as text with nothing in it that a terminal acts on: a control
/// character as its stand-in ([`push_escaped_control`], [`stands_in`]), a run of
/// bytes that is not UTF-8 as one U+FFFD, and every other character as
/// it is, a separator included. What a Windows target shows on a
/// progress line.
fn escaped_text(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for piece in bytes.utf8_chunks() {
        let text = piece.valid();
        for (at, c) in text.char_indices() {
            if stands_in(c, &text[at..]) {
                push_escaped_control(c, &mut out);
            } else {
                out.push(c);
            }
        }
        if !piece.invalid().is_empty() {
            out.push(char::REPLACEMENT_CHARACTER);
        }
    }
    out
}

/// A COMMENT's bytes as [`escaped_text`] shows a name's, except that a
/// comment is lines of text and keeps what makes it so: a line feed, a
/// carriage return that a line feed follows, and a tab are left as they
/// are. Every other control character is its stand-in, so a comment
/// can break its own lines and can do nothing else to a console.
/// SPEC-CLI section 7 speaks of names; which characters a comment
/// keeps is chosen here and is owed a rule.
fn escaped_comment(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for piece in bytes.utf8_chunks() {
        let text = piece.valid();
        for (at, c) in text.char_indices() {
            let rest = &text[at..];
            let kept = matches!(c, '\n' | '\t') || (c == '\r' && rest[1..].starts_with('\n'));
            if !kept && stands_in(c, rest) {
                push_escaped_control(c, &mut out);
            } else {
                out.push(c);
            }
        }
        if !piece.invalid().is_empty() {
            out.push(char::REPLACEMENT_CHARACTER);
        }
    }
    out
}

/// A name or a link target from an archive, for a line that lays out
/// no listing and no progress: the `Deleting`, `Renaming` and `Found`
/// lines, and the lines that refuse a member or a link by name. Every
/// such line takes its name through here (SPEC-CLI section 10, T1).
///
/// On Windows nothing rewrites a message once it is laid out, so the
/// name is shown as [`progress_line_name`] shows one there: each
/// control character as its stand-in, on every stream (rule T7). On
/// macOS and Linux the bytes are read as UTF-8 and their control
/// characters held for [`shown`], which knows the stream.
pub(crate) fn text_from_archive(bytes: &[u8]) -> std::borrow::Cow<'_, str> {
    if cfg!(windows) {
        return std::borrow::Cow::Owned(escaped_text(bytes));
    }
    held_text(bytes, false)
}

/// An archive comment as a listing prints it, and `cw` with no file
/// named: [`text_from_archive`]'s rule, with a comment's line ends and
/// tabs kept on every system (rule T6; [`escaped_comment`] on Windows).
pub(crate) fn comment_text(bytes: &[u8]) -> std::borrow::Cow<'_, str> {
    if cfg!(windows) {
        return std::borrow::Cow::Owned(escaped_comment(bytes));
    }
    held_text(bytes, true)
}

/// A name from the user's own disk, as the creator's `Adding` lines
/// print it: on macOS and Linux its control characters held for
/// [`shown`], as a name from an archive's are, so a terminal is sent
/// their stand-ins (rule T3) and a pipe the characters themselves (T5).
/// Windows prints it as it is.
pub(crate) fn name_from_disk(name: &str) -> std::borrow::Cow<'_, str> {
    if cfg!(windows) {
        return std::borrow::Cow::Borrowed(name);
    }
    hold_controls(name, false)
}

/// `bytes` read as UTF-8, a byte that is not as U+FFFD, with its
/// control characters held ([`hold_controls`]).
fn held_text(bytes: &[u8], comment: bool) -> std::borrow::Cow<'_, str> {
    match String::from_utf8_lossy(bytes) {
        std::borrow::Cow::Borrowed(text) => hold_controls(text, comment),
        std::borrow::Cow::Owned(text) => {
            std::borrow::Cow::Owned(hold_controls(&text, comment).into_owned())
        }
    }
}

/// Why an archive could not be opened, in the reference's own words.
pub(crate) enum OpenFailure {
    /// The file is not there, or could not be read at all.
    Missing(String),
    /// The file is there and is not a RAR archive.
    NotAnArchive(String),
    /// The headers are encrypted and the password was wrong or absent.
    BadPassword(String),
    /// The signature is whole and the first header is cut or damaged:
    /// the reference's [`UNEXPECTED_END`] or [`CORRUPT_HEADER`], on
    /// standard error, exit 1 or 3 by [`Tail`].
    Damaged(Tail),
    /// The member table and its names do not fit the read's budget (spec
    /// F 4.2): the engine's own words on standard error, exit 2, under the
    /// default budget and under a named `-mm` alike.
    OverBudget(String),
}

impl OpenFailure {
    /// The message the reference prints, whichever way the open failed.
    ///
    /// Unused while the creator's commands are stubbed: `cw`, `rc` and `s-`
    /// are its callers, and each of them reads it to answer 10 for all
    /// three open failures alike. It is kept rather than deleted so that
    /// those commands land as a wiring change and not as a decision.
    #[allow(dead_code)]
    ///
    /// The three variants differ in the EXIT a caller picks, not in how
    /// the text is built, so a command that treats them alike - `cw`,
    /// `rc` and `s-` all come back 10 - reads the text from here rather
    /// than matching three arms to reach the same string.
    pub(crate) fn text(&self) -> &str {
        match self {
            Self::Missing(text)
            | Self::NotAnArchive(text)
            | Self::BadPassword(text)
            | Self::OverBudget(text) => text,
            Self::Damaged(Tail::Truncated) => UNEXPECTED_END,
            Self::Damaged(Tail::CorruptHeader) => CORRUPT_HEADER,
        }
    }
}

impl Tail {
    /// The exit of a run that met this tail and nothing worse.
    pub(crate) fn exit(self) -> Exit {
        match self {
            Self::Truncated => Exit::Cautioned,
            Self::CorruptHeader => Exit::ChecksumMismatch,
        }
    }
}

/// The archive name a command opens, with the reference's default
/// extension applied.
///
/// Measured against rar and unrar 7.23 on 15 Sep 2026: a name whose FILE
/// NAME carries no dot and that is not an existing regular file gets
/// `.rar` appended. `unrar l nosuch` answers `Cannot open nosuch.rar`,
/// `l arc` lists `arc.rar`, `l d` over a DIRECTORY `d` answers `Cannot
/// open d.rar`, and `lb mv` beside `mv.part1.rar` answers `Cannot open
/// mv.rar` - no volume name is guessed. A regular file by the bare name
/// wins even when `<name>.rar` exists as well (`lb arc` beside both lists
/// `arc` itself), and a trailing dot is an extension (`l nosuch.` opens
/// `nosuch.`). The creator applies the same rule before anything prints:
/// `rar a noext text.txt` writes `noext.rar`, `rar a plain.foo` writes
/// `plain.foo`, and `rar a plain b.txt` over a text file `plain` answers
/// `Bad archive plain` rather than writing `plain.rar`.
pub(crate) fn default_extension(archive: &str) -> String {
    let path = std::path::Path::new(archive);
    let file = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if file.is_empty() || file.contains('.') || path.is_file() {
        archive.to_owned()
    } else {
        format!("{archive}.rar")
    }
}

/// The reference's own one-line reason for an OS failure, as a script
/// grepping its stderr sees it.
///
/// PLATFORM-NEUTRAL BY LETTING THE OS SPEAK. `std::io::Error`'s Display is
/// `strerror` on Unix and `FormatMessage` on Windows, which is exactly what
/// the reference prints on each - `No such file or directory` there, `The
/// system cannot find the file specified.` here. The one difference is the
/// ` (os error N)` suffix Rust appends and the reference never prints, so
/// that suffix is cut and nothing else is interpreted. Do not replace this
/// with a message table of our own: it would have to be written once per
/// platform and would drift from the OS the first time either re-words an
/// error.
pub(crate) fn io_reason(err: &std::io::Error) -> String {
    err.to_string()
        .split(" (os error")
        .next()
        .unwrap_or("Unknown error")
        .to_owned()
}

/// Runs one `unrar` command line. `argv` excludes the program name.
pub(crate) fn run(argv: &[OsString]) -> Exit {
    let parsed = match args::parse_as_unrar(argv) {
        Ok(parsed) => parsed,
        Err(refusal) => {
            println!("{}", refusal.message);
            return refusal.exit;
        }
    };
    dispatch(parsed)
}

pub(crate) fn dispatch(parsed: Parsed) -> Exit {
    // `-idq` closes its own last stderr line (see `Out::stderr_dangling`),
    // for every command this function answers - the six read-only ones -
    // and NOT for `lb`, which the reference leaves exactly as unclosed as
    // a plain run would (measured 28 Sep 2026: `unrar lb -idq nosuch.rar`
    // ends `No such file or directory` with no `\n`, where the same run as
    // `l` gets one). The creator's own `-idq` messages (`rar a -idq
    // /nope/arc.rar`) are NOT touched here: that path never reaches this
    // function, and the reference does not close those either.
    let bare = matches!(
        parsed.command,
        Some(Command::List(ListStyle { bare: true, .. }))
    );
    let out = Out::new(&parsed.opts);
    let exit = dispatch_inner(parsed, &out);
    out.close_dangling_stderr(bare);
    exit
}

/// The first switch on the line that this dialect parses and nothing
/// reads, by the name it is refused under; `None` where every switch
/// given is honoured or is one the reference itself ignores here.
///
/// Until 4 Oct 2026 each of these was accepted and dropped: `x -ep`
/// rebuilt the whole tree, `x -ap<path>` and `x -ad` extracted somewhere
/// else than asked, `x -f -o+` and `x -u -o+` replaced every file instead
/// of the older ones, and each run ended `All OK`, exit 0. Exiting 0
/// having done something different is the worse failure, so each is a
/// usage error (exit 7) until it is built.
///
/// **On `x` and `e` only**, for the switches about where and whether a
/// file is written: reference unrar 7.23 ignores `-ep4`, `-ap`, `-ad`,
/// `-f`, `-u` and `-op` on `t`, `l` and `p` (measured that day on macOS
/// arm64: the same output and exit with each as without), and so does
/// this. Its `t -ep` drops a directory's own line, and so does this
/// (`dispatch_inner`).
///
/// **A bare `-p` on every command**: the reference asks for the password
/// before it opens the archive, encrypted or not (with standard input
/// closed it ends `Program aborted`), and this dialect asks nothing, so
/// the run the caller expects cannot be given.
///
/// **A filter on the creation or the access time on every command**
/// (`-tac`, `-tna` and the like): the reference judges it on the member's
/// own creation or access time, which the engine's member record does not
/// carry, and until 4 Oct 2026 it was judged on the modification time.
///
/// rarfast's own name reads a line with the decoder's parser first, so it
/// gets every refusal here. A line that parser refuses and the creator's
/// accepts (`x -ep -m5 arc.rar`) arrives with the creator's parse, which
/// keeps `-ep` and `-f` in fields of its own: on such a line those two are
/// not refused until that parser hands them on.
fn unhonoured_switch(opts: &Options, extracts: bool) -> Option<&'static str> {
    if opts.prompt_password {
        return Some("-p");
    }
    // A time filter on the creation or the access time, on every command:
    // see [`args::TimeField`].
    for filter in &opts.time_filters {
        match filter.field {
            args::TimeField::Created => return Some("-t[abno]c (a filter on the creation time)"),
            args::TimeField::Accessed => return Some("-t[abno]a (a filter on the access time)"),
            args::TimeField::Modified | args::TimeField::Other => {}
        }
    }
    if !extracts {
        return None;
    }
    [
        (opts.exclude_paths, "-ep"),
        (opts.drop_mask_path, "-ep1"),
        // A listing honours these two; extraction would write the names
        // unchanged (sweep 2 item 31).
        (opts.lower_case, "-cl"),
        (opts.upper_case, "-cu"),
        (opts.strip_prefix.is_some(), "-ep4"),
        (opts.archive_path.is_some(), "-ap"),
        (opts.append_archive_dir.is_some(), "-ad"),
        (opts.freshen, "-f"),
        (opts.update, "-u"),
    ]
    .into_iter()
    .find_map(|(given, named)| given.then_some(named))
}

/// `-op<path>` as the destination of `x` and `e`, in the form a
/// destination given as a positional has (it ends with a separator).
///
/// Reference unrar 7.23, measured 4 Oct 2026 on macOS arm64: `x -opout`
/// and `x -opout/` both extract under `out`, made if it is not there
/// (`-opdeep/er/dir` makes all three); `x -opA arc.rar B/` extracts under
/// `B` and makes no `A`, which is why the caller asks this only where no
/// positional gave one; an empty `-op` is the current directory; `t -opT`
/// makes nothing. Until then the path was parsed and dropped, and
/// `x -o+ -op<dir>` overwrote in the current directory.
fn output_path_as_destination(opts: &Options) -> Option<String> {
    let path = opts
        .output_path
        .as_deref()
        .filter(|path| !path.is_empty())?;
    let ended = path.ends_with('/') || (cfg!(windows) && path.ends_with('\\'));
    Some(if ended {
        path.to_owned()
    } else {
        format!("{path}/")
    })
}

fn dispatch_inner(parsed: Parsed, out: &Out) -> Exit {
    let Parsed {
        command,
        archive,
        masks,
        extract_path,
        opts,
    } = parsed;

    let Some(command) = command else {
        // No command word at all is the reference's own "show the help"
        // path and exits 0. A word that is NOT a command shows the same
        // screen, exits 7, and - measured, because it is not what the
        // screen suggests - still tries to open the archive named beside
        // it, so a missing file is reported on stderr as well.
        out.say(&format!("\n{}", help::help_screen()));
        let Some(archive) = archive else {
            return Exit::Clean;
        };
        // `-- -- l arc.rar` lands here with `l` as the archive, and the
        // reference answers `Cannot open l.rar` before the usage screen.
        // No trailing `\n`: see the matching comment in `list.rs`.
        if let Err(OpenFailure::Missing(text)) = open(&default_extension(&archive), None) {
            out.warn(&text);
        }
        return Exit::BadCommandLine;
    };
    let Some(archive) = archive else {
        out.say(&format!("\n{}", help::help_screen()));
        return Exit::BadCommandLine;
    };
    // `-ag<format>` rewrites the archive name from the clock before
    // anything opens it, so a format that expands to a name with no file
    // behind it is an open failure and not a usage error. The default
    // extension goes on after it, as the creator's does.
    let archive = match &opts.generate_name {
        Some(format) => generated_name(&archive, format),
        None => archive,
    };
    let archive = default_extension(&archive);

    // A list file that could not be read: the reference stops here, with
    // the archive unopened (unrar 7.23, measured 4 Oct 2026: `Cannot open
    // <list>` and the reason on stderr, `Program aborted` on stdout, exit
    // 6, for `@list`, `-n@list` and `-x@list` alike). It is never an
    // empty list, which would select everything.
    if let Some((list, reason)) = &opts.unreadable_list {
        out.warn(&format!("\nCannot open {list}\n{reason}"));
        out.say("\nProgram aborted\n");
        return Exit::CannotOpen;
    }
    // A switch this dialect reads and does not honour is refused by name
    // before the archive is opened or anything is written.
    let extracts = matches!(command, Command::ExtractFull | Command::ExtractFlat);
    if let Some(named) = unhonoured_switch(&opts, extracts) {
        out.warn(&format!(
            "rarfast: {named} is read and not honoured yet; refused, and nothing was written\n"
        ));
        return Exit::BadCommandLine;
    }
    let extract_path = extract_path.or_else(|| output_path_as_destination(&opts));

    let selection = extract::Selection::new(&masks, &opts);
    // `t -ep` tests no directory: the reference prints no line for one,
    // and over an archive of directories alone says `No files to extract`,
    // exit 10 (rar and unrar 7.23 on macOS arm64, UnRAR.exe on Windows 11,
    // measured 4 Oct 2026; `-ep1` to `-ep4` keep the lines, and a listing
    // is the same with `-ep` as without). Until then every line was kept.
    //
    // `e` and `p` take no directory at all, whatever the mask: over an
    // archive of directories alone, or a mask that takes one alone, `e`
    // says `No files to extract`, exit 10, and makes no destination; `p`
    // prints nothing and exits 10 (SPEC-CLI 2.1 M18; rar and unrar 7.23,
    // macOS arm64, 11 Oct 2026, both containers). Until then both closed
    // as if something had been done, exit 0.
    let no_directories = match command {
        Command::Test => opts.exclude_paths,
        Command::ExtractFlat | Command::Print => true,
        _ => false,
    };
    let selection = if no_directories {
        selection.without_directories()
    } else {
        selection
    };
    match command {
        Command::List(style) => list::run(out, &archive, &opts, &selection.with_versions(), style),
        Command::Test => extract::run(out, &archive, &opts, &selection, extract::Mode::Test, None),
        Command::ExtractFull => extract::run(
            out,
            &archive,
            &opts,
            &selection,
            extract::Mode::Extract { flat: false },
            extract_path.as_deref(),
        ),
        Command::ExtractFlat => extract::run(
            out,
            &archive,
            &opts,
            &selection,
            extract::Mode::Extract { flat: true },
            extract_path.as_deref(),
        ),
        Command::Print => {
            extract::run(out, &archive, &opts, &selection, extract::Mode::Print, None)
        }
    }
}

/// The message the reference prints when the archive named beside an
/// unknown command is not there, or `Ok(())` when it is.
///
/// The `bad-command` row is why this exists: `rar qq arc.rar` prints the
/// help screen AND reports the missing file on stderr, which is not what
/// the screen suggests it would do. The creator dialect reaches the same
/// shape and reads the answer from here rather than keeping a second
/// copy of the wording.
pub(crate) fn missing_archive_message(path: &str) -> Result<(), String> {
    match open(path, None) {
        Err(OpenFailure::Missing(text)) => Err(text),
        _ => Ok(()),
    }
}

/// `-ag<format>`: the reference builds the archive name from the current
/// date and inserts it before the extension.
///
/// The format's letters are the reference's own: `Y` year, `M` month
/// before an `H` and minutes after one, `D` day, `H` hour, `S` second,
/// and a run's LENGTH decides the field width, so `YYYY` is four digits
/// and `YY` two. Anything else is a literal, which is the case the
/// conformance sweep exercises: `-ag_` on `arc.rar` asks for `arc_.rar`.
pub(crate) fn generated_name(path: &str, format: &str) -> String {
    let now = time::local(now_unix()).unwrap_or(time::Local {
        year: 1970,
        month: 1,
        day: 1,
        hour: 0,
        minute: 0,
        second: 0,
        nanosecond: 0,
    });
    let mut stamp = String::new();
    let letters: Vec<char> = format.chars().collect();
    let mut index = 0;
    let mut seen_hour = false;
    while index < letters.len() {
        let letter = letters[index];
        let mut run = 1;
        while index + run < letters.len() && letters[index + run] == letter {
            run += 1;
        }
        let value = match letter {
            'Y' => Some(i64::from(now.year)),
            'M' if seen_hour => Some(i64::from(now.minute)),
            'M' => Some(i64::from(now.month)),
            'D' => Some(i64::from(now.day)),
            'H' => {
                seen_hour = true;
                Some(i64::from(now.hour))
            }
            'S' => Some(i64::from(now.second)),
            _ => None,
        };
        match value {
            Some(value) => {
                let text = format!("{:0run$}", value, run = run);
                let cut = text.len().saturating_sub(run);
                stamp.push_str(&text[cut..]);
            }
            None => stamp.extend(std::iter::repeat_n(letter, run)),
        }
        index += run;
    }
    match path.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => format!("{stem}{stamp}.{ext}"),
        _ => format!("{path}{stamp}"),
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

#[cfg(test)]
mod tests {

    /// A name as SPEC-CLI section 7 says it is shown, written a second
    /// way: the whole name decoded first, then one character at a time,
    /// looking at the eight characters from each `<`. The differential
    /// below holds the renderer to it.
    fn display_name_by_section_7(raw: &[u8]) -> String {
        let text: Vec<char> = String::from_utf8_lossy(raw).chars().collect();
        let mut shown = String::new();
        for (at, &c) in text.iter().enumerate() {
            let shaped = c == '<'
                && text.len() >= at + 8
                && text[at + 1] == 'U'
                && text[at + 2] == '+'
                && text[at + 3..at + 7].iter().all(char::is_ascii_hexdigit)
                && text[at + 7] == '>';
            let code = u32::from(c);
            let control = code < 0x20 || (0x7F..=0x9F).contains(&code);
            if control || shaped {
                shown.push_str(&format!("<U+{code:04X}>"));
            } else if c == '\\' && !cfg!(windows) {
                shown.push('/');
            } else if c == '/' && cfg!(windows) {
                shown.push('\\');
            } else {
                shown.push(c);
            }
        }
        shown
    }

    /// SPEC-CLI section 7's own table, and the rows beside it. The same
    /// on every system but for the separator. No pool, no memory.
    #[test]
    fn a_control_character_in_a_name_is_shown_as_its_stand_in() {
        for (name, shown) in [
            ("a\tb", "a<U+0009>b"),
            ("\t", "<U+0009>"),
            ("\r", "<U+000D>"),
            ("\n", "<U+000A>"),
            ("\u{7}", "<U+0007>"),
            ("\u{1b}", "<U+001B>"),
            ("\u{7f}", "<U+007F>"),
            ("\u{85}", "<U+0085>"),
            ("\u{0}", "<U+0000>"),
            ("\u{1f}", "<U+001F>"),
            ("\u{80}", "<U+0080>"),
            ("\u{9f}", "<U+009F>"),
            ("esc\u{1b}[31mred", "esc<U+001B>[31mred"),
            ("nl\nhere\r", "nl<U+000A>here<U+000D>"),
            // P3: a name's own text of a stand-in's shape.
            ("<U+001B>", "<U+003C>U+001B>"),
            ("<U+001b>", "<U+003C>U+001b>"),
            ("<U+abCD>x", "<U+003C>U+abCD>x"),
            ("a<U+0009>b<U+0009>", "a<U+003C>U+0009>b<U+003C>U+0009>"),
            ("<<U+0041>", "<<U+003C>U+0041>"),
            ("<U+003C>U+001B>", "<U+003C>U+003C>U+001B>"),
            // Not that shape: shown as they stand.
            ("<", "<"),
            ("a<b>c", "a<b>c"),
            ("<U+001B", "<U+001B"),
            ("<U+01B>", "<U+01B>"),
            ("<U+0001B>", "<U+0001B>"),
            ("<U+00G1>", "<U+00G1>"),
            ("<u+001B>", "<u+001B>"),
            ("<U-001B>", "<U-001B>"),
            ("< U+001B>", "< U+001B>"),
            // The characters either side of the control ranges.
            (" ", " "),
            ("~", "~"),
            ("\u{a0}", "\u{a0}"),
            ("caf\u{e9}", "caf\u{e9}"),
        ] {
            assert_eq!(display_name(name.as_bytes()), shown, "{name:?}");
            assert_eq!(escaped_text(name.as_bytes()), shown, "{name:?}");
        }
        // A stand-in's own `<` is never shown as `<U+003C>`: a control
        // character followed by text that would finish the shape.
        assert_eq!(display_name(b"\tU+0009>"), "<U+0009>U+0009>");
        // Every one of the 65, and no other character below U+0100.
        for code in 0..0x100_u32 {
            let c = char::from_u32(code).unwrap();
            let shown = display_name(c.to_string().as_bytes());
            let control = code < 0x20 || (0x7F..=0x9F).contains(&code);
            if control {
                assert_eq!(shown, format!("<U+{code:04X}>"));
            } else if c != '\\' && c != '/' {
                assert_eq!(shown, c.to_string());
            }
        }
    }

    #[test]
    fn a_name_renders_by_section_7_for_every_short_and_random_input() {
        let check = |raw: &[u8]| {
            assert_eq!(
                super::display_name(raw),
                display_name_by_section_7(raw),
                "{raw:?}"
            );
        };
        check(b"");
        for a in 0..=255_u8 {
            check(&[a]);
            for b in 0..=255_u8 {
                check(&[a, b]);
            }
        }
        for text in [
            "dir/sub/file.txt",
            "dir\\sub\\file.txt",
            "caf\u{e9}/\u{65e5}\u{672c}.txt",
            "tab\there",
            "nl\nhere\r",
            "esc\u{1b}[31m",
            "del\u{7f}x",
            "c1\u{85}\u{9b}",
            "<U+001B>",
            "a<U+0009><U+00ff>b<U+12",
            "<<U+0041>>",
            "trailing.",
            "a b ~ ! # $ % & ' ( ) + , ; = @ [ ] ^ _ ` { }",
        ] {
            check(text.as_bytes());
        }
        check(&[0xff, b'a', 0xc3]);
        check(&[b'a', 0xe2, 0x82]);
        // A fixed generator, so a failure names a reproducible input.
        let mut source = rarkit_testdata::Seeded::new(0x756e_7261);
        for _ in 0..1024 {
            let len = source.index(48);
            let mut raw = Vec::with_capacity(len);
            for _ in 0..len {
                let state = source.next_u64();
                // Mostly printable ASCII, so the fast path and its edges
                // are hit as well as the general one.
                let byte = (state >> 24) as u8;
                raw.push(if state.is_multiple_of(4) {
                    byte
                } else {
                    0x20 + byte % 0x5f
                });
            }
            check(&raw);
        }
    }

    use super::*;

    #[test]
    fn a_name_with_no_extension_opens_name_dot_rar_unless_that_file_exists() {
        // rar and unrar 7.23, 15 Sep 2026; see `default_extension`.
        let dir = std::env::temp_dir().join(format!("rarfast-noext-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("sub.x")).unwrap();
        std::fs::create_dir_all(dir.join("adir")).unwrap();
        std::fs::write(dir.join("plain"), b"not an archive").unwrap();
        let at = |name: &str| dir.join(name).to_string_lossy().into_owned();

        assert_eq!(default_extension(&at("nosuch")), at("nosuch.rar"));
        // A dot in a PARENT is not an extension of the file.
        assert_eq!(
            default_extension(&at("sub.x/nosuch")),
            at("sub.x/nosuch.rar")
        );
        // A directory by the bare name is not the archive.
        assert_eq!(default_extension(&at("adir")), at("adir.rar"));
        // A regular file by the bare name is, whatever it holds.
        assert_eq!(default_extension(&at("plain")), at("plain"));
        // Any dot is an extension, a trailing one included, and volume
        // names are never guessed.
        assert_eq!(default_extension(&at("nosuch.")), at("nosuch."));
        assert_eq!(default_extension(&at("arc.part1")), at("arc.part1"));
        assert_eq!(default_extension("nosuch"), "nosuch.rar");
        assert_eq!(default_extension(""), "");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_open_failures_reason_is_the_os_s_own_wording_and_never_a_constant() {
        // The CONTROL ARM for the 16 Sep 2026 Windows `-z` finding: rarfast
        // printed the C library's `No such file or directory` on Windows,
        // where rar 7.23 prints the Win32 message. Anything that hardcodes
        // one platform's ENOENT wording again has to fail here, on BOTH
        // platforms, so the second probe below is an error that is NOT
        // ENOENT: reading a path THROUGH a regular file gives ENOTDIR on
        // Unix (`Not a directory`) and ERROR_PATH_NOT_FOUND on Windows
        // (`The system cannot find the path specified.`), and neither is
        // the constant that was there.
        let dir = std::env::temp_dir().join(format!("rarfast-ioreason-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("plain"), b"not a directory").unwrap();

        let missing = std::fs::read(dir.join("nosuch.txt")).unwrap_err();
        let through_a_file = std::fs::read(dir.join("plain").join("comment.txt")).unwrap_err();

        for err in [&missing, &through_a_file] {
            let reason = io_reason(err);
            // The reference prints no `(os error N)` tail, and the macOS
            // leg's committed table has none either.
            assert!(
                !reason.contains("(os error"),
                "the os error suffix reached stderr: {reason:?}"
            );
            assert!(!reason.is_empty());
            // Derived from THIS error, not from a table of our own.
            assert!(err.to_string().starts_with(&reason), "{reason:?}");
        }

        // The discriminator: two different failures do not get one wording.
        assert_ne!(io_reason(&missing), io_reason(&through_a_file));
        // And the one every conformance row on macOS reaches is unmoved by
        // the change, which is why both macOS legs hold their baselines.
        #[cfg(unix)]
        assert_eq!(io_reason(&missing), "No such file or directory");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_percentage_is_a_fraction_of_the_archive_not_of_the_member() {
        // The `compressed` shape: text.txt unpacks to 18400 bytes but
        // packs to 642 of a 25250-byte archive, and the reference prints
        // a ONE-digit percentage there. Reading the member's own progress
        // instead would print 100% and make the line a character shorter
        // than the table.
        assert_eq!(percent(700, 25_250), 2);
        assert_eq!(percent(18_500, 43_936), 42);
        assert_eq!(percent(43_936, 43_936), 100);
        assert_eq!(percent(1, 0), 0);
    }

    #[test]
    fn the_percentage_floors_and_the_boundary_is_where_the_one_low_defect_lived() {
        // Four equal 10,000-byte members in a 40,434-byte archive whose
        // last payload ends at 40,196. Against the FILE LENGTH the first
        // three lines read 24/49/74; against the last payload end they
        // read the reference's 25/50/75. Both sides of each boundary are
        // pinned, so a denominator that drifts back to the file length
        // fails here and not only in the CLI test.
        assert_eq!(percent(10_067, 40_434), 24);
        assert_eq!(percent(10_067, 40_196), 25);
        assert_eq!(percent(20_110, 40_196), 50);
        assert_eq!(percent(30_153, 40_196), 75);
        assert_eq!(percent(40_196, 40_196), 100);
        // Exactly on the boundary rounds UP by being exact, one below it
        // floors down: 2_500/10_000 is 25%, 2_499 is 24%.
        assert_eq!(percent(2_500, 10_000), 25);
        assert_eq!(percent(2_499, 10_000), 24);
        // A numerator past the denominator - a member whose header
        // declares more data than the file holds - is capped, not
        // wrapped.
        assert_eq!(percent(50_000, 40_196), 100);
    }

    /// Names rendered end to end into one pool, then read back by
    /// range, are each exactly what the one-name renderer makes, whatever
    /// came before them in the pool (ASCII, escapes, invalid bytes,
    /// multi-byte text, the empty name); and a name is still the 24 bytes
    /// a `String` is, so `Member` does not grow.
    #[test]
    fn a_pooled_name_reads_as_its_own_rendering() {
        let raws: Vec<Vec<u8>> = vec![
            b"plain.txt".to_vec(),
            b"".to_vec(),
            b"sub\\nested.txt".to_vec(),
            b"tab\there".to_vec(),
            vec![0xff, b'a', 0xc3],
            "caf\u{e9}/\u{1f600}.bin".as_bytes().to_vec(),
            b"\x1b[31mred".to_vec(),
            b"a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z.txt".to_vec(),
        ];
        let mut pool = String::with_capacity(4);
        let mut ranges = Vec::new();
        for raw in &raws {
            let start = pool.len();
            append_listed_name(raw, &mut pool);
            ranges.push((start, pool.len()));
        }
        let pool = std::sync::Arc::new(pool);
        for (raw, (start, end)) in raws.iter().zip(ranges) {
            let name = Name::new(&pool, start, end);
            assert_eq!(name.as_str(), display_name(raw), "{raw:?}");
            assert_eq!(name.clone(), Name::from(display_name(raw).as_str()));
            assert_eq!(format!("{name}"), display_name(raw));
        }
        assert_eq!(std::mem::size_of::<Name>(), std::mem::size_of::<String>());
    }

    /// The on-disk name rule, as measured against unrar 7.23 (see
    /// [`disk_name`]): the display form never feeds it.
    #[test]
    fn the_disk_name_is_the_stored_name_cut_and_mapped_only_as_measured() {
        let disk = |raw: &[u8], host, rar5| disk_name(raw, host, rar5).into_owned();
        for b in (0x01..0x20_u8).chain([0x7f]) {
            let raw = [b'a', b, b'b'];
            assert_eq!(disk(&raw, HostOs::Unix, true), raw);
            assert_eq!(disk(&raw, HostOs::Windows, true), raw);
        }
        assert_eq!(disk(b"bs\\x", HostOs::Unix, true), b"bs\\x");
        assert_eq!(disk(b"bs\\x", HostOs::Other(5), true), b"bs\\x");
        assert_eq!(disk(b"..\\x", HostOs::Windows, true), b".._x");
        assert_eq!(disk(b"a\0b", HostOs::Unix, true), b"a");
        assert_eq!(disk(b"a\0b", HostOs::Unix, false), b"a");
        assert_eq!(disk(b"a\xffb", HostOs::Unix, true), b"a");
        assert_eq!(disk(b"\xc3", HostOs::Windows, true), b"");
        let eight_bit: &[u8] = if HOST_TAKES_ANY_BYTES {
            b"caf\xe9"
        } else {
            b"caf"
        };
        assert_eq!(disk(b"caf\xe9", HostOs::Unix, false), eight_bit);
        // An ordinary name is borrowed, not copied.
        assert!(matches!(
            disk_name(b"sub/plain.txt", HostOs::Windows, true),
            std::borrow::Cow::Borrowed(_)
        ));
    }

    /// What a progress or `Creating` line shows for bytes the file system
    /// got: control characters as they are (ESC is `Out`'s to write out),
    /// a `\\` as itself, and a byte that is not UTF-8 as the reference's
    /// C library reads it. A Windows target shows the stand-ins.
    /// The Windows arm of [`progress_line_name`], which every system can
    /// run: the two rows the test below pins on Windows, and what stands
    /// around them. A separator of either kind is left as it is; the
    /// callers have mapped it already where it wants mapping.
    #[test]
    fn the_escaped_text_leaves_nothing_for_a_terminal_to_act_on() {
        assert_eq!(escaped_text(b"tab\tthere"), "tab<U+0009>there");
        assert_eq!(escaped_text(b"caf\xe9"), "caf\u{fffd}");
        assert_eq!(escaped_text(b""), "");
        assert_eq!(escaped_text(b"plain name.txt"), "plain name.txt");
        assert_eq!(escaped_text("caf\u{e9}".as_bytes()), "caf\u{e9}");
        assert_eq!(escaped_text(b"a/b\\c"), "a/b\\c");
        assert_eq!(escaped_text(b"\xff\xfe"), "\u{fffd}\u{fffd}");
        assert_eq!(escaped_text(b"cut\xc3"), "cut\u{fffd}");
        for byte in (0_u8..0x20).chain([0x7f]) {
            let shown = escaped_text(&[b'a', byte, b'b']);
            assert_eq!(shown, format!("a<U+{byte:04X}>b"));
            assert!(!shown.chars().any(char::is_control), "{byte:#x}");
        }
        assert!(!escaped_text("c1\u{85}x".as_bytes())
            .chars()
            .any(char::is_control));
        if cfg!(windows) {
            assert_eq!(progress_line_name(b"a\x07b"), escaped_text(b"a\x07b"));
        }
    }

    /// The Windows arm of [`comment_text`], which every system can run:
    /// a comment keeps its line ends and its tabs, and everything else
    /// that a console acts on is a stand-in, as in a name.
    #[test]
    fn the_escaped_comment_keeps_its_lines_and_tabs_and_nothing_else_that_acts() {
        for (comment, shown) in [
            ("one\ntwo\n", "one\ntwo\n"),
            ("one\r\ntwo\r\n", "one\r\ntwo\r\n"),
            ("a\tb", "a\tb"),
            // A carriage return that no line feed follows would write
            // over the line it is on.
            ("over\rwritten", "over<U+000D>written"),
            ("ends\r", "ends<U+000D>"),
            ("two\r\r\n", "two<U+000D>\r\n"),
            (
                "cmt\u{1b}[31mred\u{1}\tx\n",
                "cmt<U+001B>[31mred<U+0001>\tx\n",
            ),
            (
                "bell\u{7} back\u{8} del\u{7f}",
                "bell<U+0007> back<U+0008> del<U+007F>",
            ),
            ("c1 \u{9b}31m", "c1 <U+009B>31m"),
            ("nul\u{0}", "nul<U+0000>"),
            // P3 holds in a comment too, so a stand-in is always one.
            ("says <U+001B> itself", "says <U+003C>U+001B> itself"),
            ("a < b > c", "a < b > c"),
            ("caf\u{e9}", "caf\u{e9}"),
            ("", ""),
        ] {
            assert_eq!(escaped_comment(comment.as_bytes()), shown, "{comment:?}");
        }
        assert_eq!(escaped_comment(b"lat\xe9in\n"), "lat\u{fffd}in\n");
        // A carriage return and its line feed either side of bytes that
        // are no text are not a line end.
        assert_eq!(escaped_comment(b"a\r\xff\nb"), "a<U+000D>\u{fffd}\nb");
        // Nothing but a line feed, a tab and a line end's carriage
        // return is left for a console, whatever the comment holds.
        for code in (0..0x20_u32).chain(0x7f..0xa0) {
            let c = char::from_u32(code).unwrap();
            let shown = escaped_comment(format!("a{c}b").as_bytes());
            if c == '\n' || c == '\t' {
                assert_eq!(shown, format!("a{c}b"));
            } else {
                assert_eq!(shown, format!("a<U+{code:04X}>b"));
            }
        }
    }

    /// What a line outside the listings and the progress shows for a
    /// name, and a comment, on this system: stand-ins on Windows, and
    /// everywhere else the bytes as they were (ESC is `Out`'s there).
    #[test]
    fn a_name_or_a_comment_off_the_listing_drives_no_windows_console() {
        if cfg!(windows) {
            assert_eq!(
                text_from_archive(b"a\x1bb\tc\n"),
                "a<U+001B>b<U+0009>c<U+000A>"
            );
            assert_eq!(text_from_archive(b"caf\xe9"), "caf\u{fffd}");
            assert_eq!(comment_text(b"a\x1bb\tc\n"), "a<U+001B>b\tc\n");
            assert_eq!(text_from_archive(b"a\x1bb"), escaped_text(b"a\x1bb"));
            return;
        }
        // Held for the writer, which knows the stream: an escape is
        // its own, a comment's tab and line feed are kept.
        let sent = |text: &str, terminal| {
            String::from_utf8(shown(text.as_bytes(), terminal).into_owned()).unwrap()
        };
        let name = text_from_archive(b"a\x1bb\tc\n");
        assert_eq!(sent(&name, true), "a'\\033'b<U+0009>c<U+000A>");
        assert_eq!(sent(&name, false), "a'\\033'b\tc\n");
        assert_eq!(text_from_archive(b"caf\xe9"), "caf\u{fffd}");
        let comment = comment_text(b"a\x1bb\tc\x07\n");
        assert_eq!(sent(&comment, true), "a'\\033'b\tc<U+0007>\n");
        assert_eq!(sent(&comment, false), "a'\\033'b\tc\x07\n");
        assert!(matches!(
            text_from_archive(b"plain"),
            std::borrow::Cow::Borrowed(_)
        ));
    }

    /// A progress line's name: on Windows with its stand-ins, and on
    /// the other systems as the reference reads the bytes, which is
    /// what a stream that is no terminal is sent ([`as_stored`]: the
    /// control characters are held until the stream is known).
    #[test]
    fn a_progress_line_reads_the_bytes_as_the_reference_reads_them() {
        if cfg!(windows) {
            assert_eq!(progress_line_name(b"tab\tthere"), "tab<U+0009>there");
            assert_eq!(progress_line_name(b"caf\xe9"), "caf\u{fffd}");
            return;
        }
        let progress_line_name = |name: &[u8]| as_stored(&progress_line_name(name)).into_owned();
        assert_eq!(progress_line_name(b"tab\tthere"), "tab\tthere");
        assert_eq!(progress_line_name(b"e\x1b[2J"), "e\x1b[2J");
        assert_eq!(progress_line_name(b"bs\\x"), "bs\\x");
        let eight_bit = if APPLE_TEXT {
            "caf"
        } else {
            "caf\u{fffe}\u{e0e9}"
        };
        assert_eq!(progress_line_name(b"caf\xe9"), eight_bit);
    }

    /// `listed_name_into` for one name as a stream that is no terminal
    /// is sent it ([`as_stored`]), and whether it printed.
    #[cfg(not(windows))]
    fn listed(raw: &[u8], host: HostOs, rar5: bool) -> (String, bool) {
        let mut out = String::from("before|");
        let printable = listed_name_into(raw, host, rar5, &mut out);
        let name = out.strip_prefix("before|").expect("appended");
        (as_stored(name).into_owned(), printable)
    }

    /// The listing's name rule, as measured against unrar 7.23 on Linux
    /// and macOS (see [`listed_name_into`]); `tests/listing_names.rs`
    /// runs the same rows through every layout.
    #[test]
    #[cfg(not(windows))]
    fn a_listed_name_is_the_name_the_reference_lists() {
        for c in (0x01..0x20_u8).chain([0x7f]) {
            let raw = [b'a', c, b'b'];
            for host in [HostOs::Unix, HostOs::Windows, HostOs::Other(3)] {
                let want = String::from_utf8(raw.to_vec()).unwrap();
                assert_eq!(listed(&raw, host, true), (want.clone(), true));
                assert_eq!(listed(&raw, host, false), (want, true));
            }
        }
        for (raw, want) in [
            (&b"sub/plain.txt"[..], "sub/plain.txt"),
            (b"a\\b", "a\\b"),
            (b"a\0b", "a"),
            (b"\0x", ""),
            (b"a\xffb", "a"),
            (b"\xc3", ""),
            (b"a\xc3bc", "a"),
            (b"a\xe2\x82b", "a"),
            (b"a\xf8\x88\x80\x80\x80b", "a"),
            (b"a\xc0\xafb", "a/b"),
            (b"a\xc1\x81b", "aAb"),
            (b"a\xc0\x80b", "a"),
            (b"a\xf0\x80\x80\xafb", "a/b"),
            (b"a\xf4\x90\x80\x80b", "ab"),
            (b"a\xf4\x8f\xbf\xbfb", "a\u{10ffff}b"),
            (b"a\xef\xbf\xbeb", "a\u{fffe}b"),
            (b"caf\xc3\xa9", "caf\u{e9}"),
        ] {
            assert_eq!(
                listed(raw, HostOs::Unix, true),
                (want.to_owned(), true),
                "{raw:?}"
            );
        }
        assert_eq!(listed(b"a\\b/c\\", HostOs::Windows, true).0, "a_b/c_");
        assert_eq!(listed(b"a\\b", HostOs::Other(3), true).0, "a\\b");
        let surrogate = listed(b"a\xed\xa0\x80b", HostOs::Unix, true);
        if APPLE_TEXT {
            assert_eq!(surrogate, (String::new(), false));
        } else {
            assert_eq!(surrogate, ("a?b".to_owned(), true));
        }
        // RAR 1.3 to 4: a NUL still ends the name, the bytes are read as
        // the host's C library reads them.
        assert_eq!(listed(b"a\0b", HostOs::Unix, false).0, "a");
        let (split, _) = listed(b"a\xe9b\xe8c", HostOs::Unix, false);
        if APPLE_TEXT {
            assert_eq!(split, "a");
        } else {
            assert_eq!(split, "a\u{fffe}\u{e0e9}b\u{e0e8}c");
        }
        assert_eq!(
            listed(b"s/caf\xc3\xa9", HostOs::Unix, false).0,
            "s/caf\u{e9}"
        );
    }

    /// Archive text as a stream that is a `terminal` or is not is sent
    /// it: held, then shown, as a line's text is.
    #[cfg(not(windows))]
    fn sent(text: &str, comment: bool, terminal: bool) -> String {
        let held = hold_controls(text, comment);
        String::from_utf8(shown(held.as_bytes(), terminal).into_owned()).unwrap()
    }

    /// SPEC-CLI section 10's first table, for macOS and Linux: the name
    /// `a`, the character, `b`, to a terminal and to a stream that is
    /// not one; and every one of the 65 control characters.
    #[cfg(not(windows))]
    #[test]
    fn a_control_character_is_a_stand_in_to_a_terminal_and_itself_to_a_pipe() {
        for (c, on_terminal) in [
            ('\t', "a<U+0009>b"),
            ('\n', "a<U+000A>b"),
            ('\r', "a<U+000D>b"),
            ('\u{7}', "a<U+0007>b"),
            ('\u{8}', "a<U+0008>b"),
            ('\u{7f}', "a<U+007F>b"),
            ('\u{9b}', "a<U+009B>b"),
        ] {
            let name = format!("a{c}b");
            assert_eq!(sent(&name, false, true), on_terminal, "{name:?}");
            assert_eq!(sent(&name, false, false), name, "{name:?}");
        }
        // T4: an escape is six characters on both, and is never held.
        assert_eq!(sent("a\u{1b}b", false, true), "a'\\033'b");
        assert_eq!(sent("a\u{1b}b", false, false), "a'\\033'b");
        assert_eq!(hold_controls("a\u{1b}b", false), "a\u{1b}b");
        // P3 on a terminal only (T5).
        assert_eq!(sent("<U+0007>", false, true), "<U+003C>U+0007>");
        assert_eq!(sent("<U+0007>", false, false), "<U+0007>");
        assert_eq!(sent("a<b <U+12>", false, true), "a<b <U+12>");
        for code in (0..0x20_u32).chain(0x7f..0xa0) {
            let name = format!("a{}b", char::from_u32(code).unwrap());
            if code == 0x1b {
                continue;
            }
            assert_eq!(sent(&name, false, true), format!("a<U+{code:04X}>b"));
            assert_eq!(sent(&name, false, false), name);
            // One character stands for one while the line is laid out.
            assert_eq!(hold_controls(&name, false).chars().count(), 3);
            assert_eq!(as_stored(&hold_controls(&name, false)), name);
        }
        // Nothing to hold, nothing copied: by the renderer or the writer.
        assert!(matches!(
            hold_controls("plain name.txt", false),
            std::borrow::Cow::Borrowed(_)
        ));
        assert!(matches!(
            shown(b"plain\tline\n", true),
            std::borrow::Cow::Borrowed(_)
        ));
        assert_eq!(
            sent("caf\u{e9} \u{a0}\u{4e2d}", false, true),
            "caf\u{e9} \u{a0}\u{4e2d}"
        );
    }

    /// The scan that decides whether a message is rewritten at all
    /// finds either byte at every place in a word and past the last
    /// whole word, and nothing in text that holds neither.
    #[test]
    fn the_scan_finds_an_escape_or_a_held_character_wherever_it_stands() {
        let plain: Vec<u8> = (0..=255_u8)
            .filter(|&b| b != 0x1b && b != HELD_LEAD)
            .collect();
        assert!(!holds_what_is_rewritten(&plain));
        assert!(!holds_what_is_rewritten(b""));
        for len in 0..40 {
            let text = vec![b'a'; len];
            assert!(!holds_what_is_rewritten(&text), "{len}");
            for at in 0..len {
                for byte in [0x1b, HELD_LEAD] {
                    let mut text = text.clone();
                    text[at] = byte;
                    assert!(holds_what_is_rewritten(&text), "{len} {at} {byte:#x}");
                }
                // The bytes either side of each are not taken for it.
                for byte in [0x1a, 0x1c, HELD_LEAD - 1, HELD_LEAD + 1, 0x9b, 0x73] {
                    let mut text = text.clone();
                    text[at] = byte;
                    assert!(!holds_what_is_rewritten(&text), "{len} {at} {byte:#x}");
                }
            }
        }
    }

    /// Section 10's second table: what a comment keeps (T6).
    #[cfg(not(windows))]
    #[test]
    fn a_comment_keeps_its_line_ends_and_tabs_on_a_terminal_too() {
        let comment = "one\ttab\r\ntwo\rover\u{7}bell\u{1b}esc\nend\r";
        assert_eq!(
            sent(comment, true, true),
            "one\ttab\r\ntwo<U+000D>over<U+0007>bell'\\033'esc\nend<U+000D>"
        );
        assert_eq!(
            sent(comment, true, false),
            "one\ttab\r\ntwo\rover\u{7}bell'\\033'esc\nend\r"
        );
        // A name keeps none of the three.
        assert_eq!(
            sent("a\tb\r\nc", false, true),
            "a<U+0009>b<U+000D><U+000A>c"
        );
    }

    /// A name may hold the very characters control characters are held
    /// as. They are the archive's own and come out as they went in, on
    /// either kind of stream, and a comparison sees them too.
    #[cfg(not(windows))]
    #[test]
    fn a_name_holding_a_held_character_of_its_own_is_printed_as_it_is() {
        for code in [HELD_FIRST, HELD_FIRST + 7, HELD_LESS_THAN, HELD_AS_IS] {
            let own = char::from_u32(code).unwrap();
            let name = format!("a{own}\t{own}{own}b");
            let on_terminal = format!("a{own}<U+0009>{own}{own}b");
            assert_eq!(sent(&name, false, true), on_terminal, "{code:#x}");
            assert_eq!(sent(&name, false, false), name, "{code:#x}");
            assert_eq!(as_stored(&hold_controls(&name, false)), name, "{code:#x}");
        }
        // The character after the last held one is not one of them.
        let next = char::from_u32(HELD_AS_IS + 1).unwrap();
        let name = format!("a{next}b");
        assert_eq!(hold_controls(&name, false), name);
        assert_eq!(sent(&name, false, true), name);
    }

    /// The writer on a Windows target changes nothing: its renderers
    /// have put the stand-ins in already (T7).
    #[cfg(windows)]
    #[test]
    fn a_message_is_written_as_it_is_given_on_windows() {
        assert_eq!(&*shown(b"a\x1bb", true), b"a\x1bb");
        assert_eq!(&*shown(b"a\x1bb", false), b"a\x1bb");
    }

    #[test]
    fn names_take_the_platform_s_own_separator() {
        let rendered = display_name(b"sub/nested.txt");
        if cfg!(windows) {
            assert_eq!(rendered, "sub\\nested.txt");
        } else {
            assert_eq!(rendered, "sub/nested.txt");
        }
    }
}
