//! A stored member's range HANDED to the thread that delivers it, which
//! reads, hashes and writes it itself (feature `parallel`).
//!
//! **What it is for.** `extract` over a SOLID archive whose caller's writer
//! is a file runs the walk on a worker and leaves the caller's thread the
//! writes (`read::sequential`, the solid path). Every member's bytes cross
//! between the two in queued buffers, which is right for a member with a
//! decoder, whose bytes exist nowhere until the walk makes them. A STORED
//! member's bytes already exist, in the volume, and the walk only carried
//! them: counted on a Zen 4 (1 Oct 2026), `x` of
//! 8.76 GB of stored video inside a solid set was ONE thread making 66,847
//! serial reads of 128 KiB, hashing them and copying them into the queue,
//! and the caller's thread copying every byte a second time into its
//! writer's staging block, because a queued buffer starts on no page.
//!
//! So the walk hands the RANGE over instead ([`Range`]): where the bytes
//! are, not the bytes. The delivering thread has them read on threads of
//! its own into page-aligned pieces, each hashed where it was read, and
//! writes each piece from its own buffer in order.
//! Nothing is queued and nothing is copied, and the walk, which waits for
//! the range to pass, accounts for every piece exactly as its own read
//! would have ([`Passed`]): the member's CRC32, the fragment's packed
//! CRC32, the drop-behind report and the tally, in order.
//!
//! **Whole pieces at whole offsets.** A writer past the OS cache takes a
//! piece straight from its buffer only when the buffer is on a page and
//! nothing is staged in front of it, so the [`Cutter`] keeps every write of
//! a member it cuts at a multiple of the piece: a member's first bytes (the
//! part of it the walk had already read with its header), a fragment's
//! tail and the head of the next are gathered in ONE slab of a piece, the
//! range's first read tops that slab up, and every piece after it is whole
//! and written from where it was read. Only the member's last write is
//! short. The copies left are that slab, at most twice a range. A member
//! whose first bytes were written before its first range (a fragment too
//! short to hand over) is brought back to a multiple of the piece by one
//! short write, and whole from there.
//!
//! **One reader in order, or several at once: [`Dial::in_order`].** Wide
//! (`read::wide`), the window's pieces are read by as many threads at once
//! and joined in order. In order, ONE thread reads the range front to
//! back into two buffers while this one writes: the kernel then sees a
//! single sequential reader and runs its own read-ahead under it, which on
//! macOS is worth more than a second reader (cold `x` of 8.76 GB stored on
//! an M3 Ultra: two readers of 4 MiB 4.7 to 5.1 s, eight of 1 MiB 4.7 to
//! 4.8, the queue's one serial reader 2.9 to 3.3;
//! 1 Oct 2026). The default is per system ([`IN_ORDER`]).
//!
//! **The bound is the wide reader's own.** A piece is read only while it
//! lies within the plan's window of the lowest piece not yet written, and
//! the window is the read-ahead budget (`read::wide`, spec F 3.7.2); the
//! walk reads nothing while it waits. What is held is the window's pieces
//! and the slab.

use std::io::Write;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};

use crate::checksum::blake2sp::Blake2sp;
use crate::error::{Error, Result};
use crate::memory::Held;
use crate::read::cursor::read_upto_at;
use crate::read::wide::{self, Aligned, Cipher, Plan, Stop};
use crate::source::RangeSource;

/// The unread rest of a stored member's fragment, for the thread that
/// delivers the member: `len` bytes at `at` of `source`.
pub(crate) struct Range {
    pub(crate) source: Arc<dyn RangeSource>,
    pub(crate) at: u64,
    pub(crate) len: u64,
    /// The wide read's plan for a member that is only checked; a written
    /// one is read in the slabs cut from it ([`wide::slabs_of`]).
    pub(crate) plan: Plan,
    /// The member's own window (its read-ahead budget), which `plan` is
    /// narrower than where the pool's lanes granted fewer readers than
    /// the member asked for: a written range is cut to this window
    /// whatever the readers, so its writes keep their size.
    pub(crate) window: u64,
    /// How many bytes of the member its writer had been given when the
    /// range was handed over: where the range's first byte lies in the
    /// member, for a writer that keeps no count of its own ([`cut_here`]).
    pub(crate) before: u64,
}

/// The next `len` bytes of the range have been read, hashed and delivered,
/// in order, and `crc` is their CRC32: what the walk accounts for.
#[derive(Clone, Copy)]
pub(crate) struct Passed {
    pub(crate) crc: u32,
    /// The CRC32 of the same bytes as they lie in the volume: `crc` for a
    /// clear member, the ciphertext's for a deciphered one where the
    /// fragment's own check was asked for ([`Cipher::packed_crc`]).
    pub(crate) packed_crc: u32,
    pub(crate) len: u64,
}

/// How a member's writer takes a range instead of its bytes, where it can
/// (`extract::Driver::hand_over`): it answers once the whole range has
/// passed or stopped, having called back for each piece, in order, on the
/// calling thread. A callback's error ends the range and comes back as
/// [`Stop::Accepted`].
pub(crate) type HandOver<W> =
    fn(&mut W, Range, &mut dyn FnMut(Passed) -> Result<()>) -> std::result::Result<(), Stop>;

/// [`HandOver`] for a range of whole blocks of an AES-CBC member:
/// the writer's own thread deciphers the pieces it writes, and
/// answers their last ciphertext block, which the member's chain goes on
/// from. Only a writer on the thread that holds the member's key takes
/// one ([`cut_cipher_here`]).
pub(crate) type HandCipher<W> = fn(
    &mut W,
    Range,
    Cipher,
    &mut dyn FnMut(Passed) -> Result<()>,
) -> std::result::Result<[u8; 16], Stop>;

/// [`HandOver`] for a range of a CLEAR member whose one check is a
/// BLAKE2sp record ([`cut_hashed_here`]): the range is read by one reader
/// in order and the member's hasher is fed each piece, in stream order, off
/// the thread that writes it. The callback's [`Passed::crc`] is the
/// fragment's packed CRC32 where [`Hashed::packed_crc`] asked for it and
/// zero otherwise: such a member has no CRC32 of its own to account for.
pub(crate) type HandHashed<W> = for<'h> fn(
    &mut W,
    Range,
    Hashed<'h>,
    &mut dyn FnMut(Passed) -> Result<()>,
) -> std::result::Result<(), Stop>;

/// What a hashed range brings with it: the member's hasher, where it runs,
/// and whether the fragment's own check wants the pieces' CRC32.
pub(crate) struct Hashed<'h> {
    pub(crate) hasher: &'h mut Blake2sp,
    pub(crate) dial: HashDial,
    /// Whether the fragment's PACKED CRC32 is wanted (spec F 3.5.6): a
    /// split member's fragment, judged by its stream.
    pub(crate) packed_crc: bool,
}

/// How a hashed range is read: where the hasher runs and in what pieces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HashDial {
    /// The hasher on ONE lane behind the reader (`true`), so the read, the
    /// hash and the write are three threads; or on the reader itself
    /// (`false`), the seam's arrangement, two threads.
    pub(crate) lane: bool,
    /// The piece; where `None`, the window over its buffers rounded up to
    /// a power of two (half the window on the reader, a quarter with the
    /// lane), so every buffer in flight lies inside the window.
    pub(crate) piece: Option<u64>,
}

/// How a written range is read: what a measurement names, or the
/// defaults.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Dial {
    /// The piece a range is cut into; half the plan's window when `None`
    /// (a deciphered range: [`CIPHER_PIECES`] of them to the window, and
    /// [`CIPHER_RING`] of them in order).
    pub(crate) piece: Option<u64>,
    /// One reader in order (`true`) or the window's pieces at once
    /// (`false`); [`IN_ORDER`] when `None`.
    pub(crate) in_order: Option<bool>,
}

/// Whether a written range is read by ONE thread in order when nothing
/// names the arrangement: on macOS, where a file's reads wait on each
/// other in the kernel and its read-ahead follows one sequential reader
/// (the module doc has the count). Elsewhere the window's pieces are read
/// at once.
pub(crate) const IN_ORDER: bool = cfg!(target_os = "macos");

/// The buffers the in-order reader fills for a clear range: one being
/// read, one being written.
const RING: usize = 2;

/// The pieces a DECIPHERED range's window is cut into where nothing names
/// the piece and the window's pieces are read at once: each reader
/// deciphers the piece it read, so the pieces at once are the cipher's
/// lanes, and two of half the window are fewer than a fast drive's write
/// keeps busy.
const CIPHER_PIECES: u64 = 4;

/// The most pieces the in-order reader of a deciphered range runs ahead
/// of the write: one being read, one being written, the rest on the
/// cipher's lanes.
///
/// **Eight on macOS, two everywhere else.** On Apple silicon the cipher is
/// the slow stage (an encrypted stored member's serial read took twice its
/// clear twin's wall there), so the window is cut in eight and six lanes
/// decipher behind the reader. Off macOS the pieces are the largest the
/// window holds, half of it each, and the reader deciphers the piece it
/// read: counted on a 48 core x86-64 server writing to memory, `x` of an
/// 8 GiB stored member under a password took 1.94 s that way against 1.92
/// s for its clear twin, in 2,057 reads and 2,214 context switches, where
/// quarter pieces took 2.02 s and eighth pieces with six lanes 2.76 s:
/// there a request and a write of 4 MiB are worth more than lanes.
const CIPHER_RING: usize = if cfg!(target_os = "macos") { 8 } else { RING };

/// What `text` asks of a knob that turns a hand-over on and names how its
/// ranges are read: `None` for off (`0`, `off`), the dial otherwise,
/// `default` where it says nothing this knows, and `shipped` (the dial
/// the knob runs at when it is on) for `1` or `on`. The measuring arms, alone
/// or joined by a colon: `seq` (one reader in order), `wide` (the window's
/// pieces at once), and a number of 64 or more (the piece, in KiB), as in
/// `seq:1024`.
pub(crate) fn dial_of(text: Option<&str>, default: Option<Dial>, shipped: Dial) -> Option<Dial> {
    let Some(text) = text else {
        return default;
    };
    let text = text.trim().to_ascii_lowercase();
    if matches!(text.as_str(), "0" | "off") {
        return None;
    }
    let mut dial = Dial::default();
    let mut named = false;
    let mut on = false;
    for word in text.split(':') {
        match word {
            "seq" => dial.in_order = Some(true),
            "wide" => dial.in_order = Some(false),
            // On, as shipped: the default dial even where the default is
            // off, and never a dial of its own.
            "1" | "on" => {
                on = true;
                continue;
            }
            _ => match word.parse::<u64>() {
                Ok(kib) if kib >= 64 => dial.piece = Some(kib.saturating_mul(1024)),
                _ => continue,
            },
        }
        named = true;
    }
    if named {
        Some(dial)
    } else if on {
        Some(default.unwrap_or(shipped))
    } else {
        default
    }
}

/// `RARKIT_STORED_CUT`: whether a stored member WRITTEN TO A FILE by the
/// thread that reads it (a pool worker's member, and the walk's own
/// encrypted one) is cut into aligned pieces by that thread ([`cut_here`],
/// [`cut_cipher_here`]), and how its ranges are read ([`dial_of`]'s
/// words). `0` or `off` is the arrangement before 1 Oct 2026. A RUNTIME
/// knob, so one binary measures every arm.
pub(crate) const STORED_CUT_ENV: &str = "RARKIT_STORED_CUT";

/// The dial an AES-CBC member is cut at when nothing names one: ONE reader
/// in order on every system, in pieces of the window over [`CIPHER_RING`].
///
/// Off macOS a clear member's readers work at once ([`STORED_CUT_DIAL`]),
/// and a deciphered range read that way is deciphered by each reader on
/// its own piece, so the pieces at once are the cipher's width and the
/// source sees as many requests of a mebibyte or less. In order, the
/// source sees one reader making the largest requests the window holds,
/// as it does under a clear member written through the seam.
const STORED_CUT_CIPHER_DIAL: Dial = Dial {
    piece: None,
    in_order: Some(true),
};

/// The dial an AES-CBC member is cut at: what [`STORED_CUT_ENV`] names,
/// and [`STORED_CUT_CIPHER_DIAL`] where it names nothing.
pub(crate) fn stored_cut_for_cipher() -> Dial {
    #[cfg(feature = "test-support")]
    if let Some(Some(forced)) = crate::probe::stored_cut() {
        return forced;
    }
    static CUT: std::sync::OnceLock<Dial> = std::sync::OnceLock::new();
    *CUT.get_or_init(|| {
        dial_of(
            crate::knob::reader_var(STORED_CUT_ENV).ok().as_deref(),
            Some(STORED_CUT_CIPHER_DIAL),
            STORED_CUT_CIPHER_DIAL,
        )
        .unwrap_or(STORED_CUT_CIPHER_DIAL)
    })
}

/// Whether such a member is cut when [`STORED_CUT_ENV`] says nothing: not
/// on Windows, which has no row of the cut yet (its written members keep
/// `concurrent::Written` and `WIDE_WRITE`, each on rows of its own).
const STORED_CUT_DEFAULT: bool = !cfg!(windows);

/// The dial such a member is cut at when nothing names one.
///
/// **Off macOS the piece is 1 MiB**, so the window's readers are eight
/// under `rarfast x`'s 8 MiB read-ahead, clear or deciphered: on a Zen 4
/// rental's NVMe (a quiet box, cold, 1 Oct
/// 2026) a clear big member beside its sample extracted in 8.1 s by eight
/// readers of 1 MiB against 11.0 s by two of 4 MiB and 12.4 s on its
/// worker's own loop, and the `-hp` big member in 9.0 s against 13.5 s: a cold
/// drive there answers more requests at once faster than fewer large ones.
/// On macOS the reader is one, in order, and the pieces are [`Dial`]'s own
/// defaults.
#[cfg(not(target_os = "macos"))]
const STORED_CUT_DIAL: Dial = Dial {
    piece: Some(1 << 20),
    in_order: None,
};
#[cfg(target_os = "macos")]
const STORED_CUT_DIAL: Dial = Dial {
    piece: None,
    in_order: None,
};

/// The dial such a member is cut at, or `None` where it is not cut.
pub(crate) fn stored_cut() -> Option<Dial> {
    #[cfg(feature = "test-support")]
    if let Some(forced) = crate::probe::stored_cut() {
        return forced;
    }
    static CUT: std::sync::OnceLock<Option<Dial>> = std::sync::OnceLock::new();
    *CUT.get_or_init(|| {
        dial_of(
            crate::knob::reader_var(STORED_CUT_ENV).ok().as_deref(),
            STORED_CUT_DEFAULT.then_some(STORED_CUT_DIAL),
            STORED_CUT_DIAL,
        )
    })
}

/// `RARKIT_STORED_CUT_CIPHER`: `1` or `0`, whether an AES-CBC member is
/// cut too where the cut is on ([`cut_cipher_here`]); anything else, or
/// nothing, is [`STORED_CUT_CIPHER`]. A RUNTIME knob.
pub(crate) const STORED_CUT_CIPHER_ENV: &str = "RARKIT_STORED_CUT_CIPHER";

/// **An encrypted member is cut on macOS and on x86-64 Linux.** On macOS
/// the cut is one reader in order with the cipher on lanes behind it,
/// which is what the joined wide read lost every cold row for want of (a
/// 36 core Apple desktop: the single `-hp` big member cold 4.95 s to 2.38 s).
///
/// On Linux the joined read splits the read-ahead across the whole width,
/// so on a wide machine its pieces are the smallest there are and every
/// one is a wake of a reader and of the joining thread: counted on a 48
/// core, 96 thread server writing to memory, `x` of an 8 GiB stored member
/// under a password made 65,545 reads of 128 KiB and 118,810 context
/// switches in 2.65 s, where its clear twin made 2,056 reads and 2,243
/// switches in 1.92 s. Cut by one reader in order in pieces of half the
/// window ([`STORED_CUT_CIPHER_DIAL`]) the same member took 1.94 s in
/// 2,057 reads, and a set of eight such members 0.35 s against 0.445 s.
/// (The cut first counted there, eight readers of 1 MiB at once, was level
/// with the joined read or behind it on an 8 core machine's drive, which
/// is why Linux kept the joined read until the cut had this dial.)
///
/// Every other system keeps the joined read until it has rows of its own.
const STORED_CUT_CIPHER: bool = cfg!(any(
    target_os = "macos",
    all(target_os = "linux", target_arch = "x86_64")
));

/// Whether an AES-CBC member is cut where the cut is on.
pub(crate) fn stored_cut_cipher() -> bool {
    #[cfg(feature = "test-support")]
    if let Some(forced) = crate::probe::stored_cut_cipher() {
        return forced;
    }
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        match crate::knob::reader_var(STORED_CUT_CIPHER_ENV)
            .ok()
            .as_deref()
            .map(str::trim)
        {
            Some("1") => true,
            Some("0") => false,
            _ => STORED_CUT_CIPHER,
        }
    })
}

/// `RARKIT_B2SP_CUT`: whether a CLEAR stored member whose one check is a
/// BLAKE2sp record, WRITTEN TO A FILE by the pool worker that reads it, is
/// cut as a CRC32 member is ([`cut_hashed_here`]), and how
/// ([`hash_dial_of`]'s words). `0` or `off` is the arrangement before 2 Oct
/// 2026: the worker reads, hashes and writes each buffer in sequence. A
/// RUNTIME knob, so one binary measures every arm. It moves which threads
/// read and hash, never a digest and never an output byte.
pub(crate) const B2SP_CUT_ENV: &str = "RARKIT_B2SP_CUT";

/// Whether such a member is cut where [`B2SP_CUT_ENV`] says nothing: on
/// Linux and on macOS, each system on its own rows
/// (2 Oct 2026).
///
/// **Linux** (a Zen 4 rental, 8 cores, and its NVMe, a quiet box, `x`
/// on disk, K=5): a big member beside its sample and nfo extracted in 6.83 s on
/// its worker's own loop, the worker reading and hashing for 3.2 s and
/// then blocked in its writes for 3.5 s, and in 3.82 s cut (the fastest
/// rival 5.17 s); cold 9.81 s against 5.00 s (the fastest rival 8.31 s).
/// The lone big member, which the walk reads, a member only tested and a
/// set of eight in flight read level. **macOS** (an M1 Ultra, INDICATIVE at a
/// load of 3 to 9, warm, where such an archive takes the pool): 5.59 s
/// against 3.16 s, and level in the one repetition of five where the
/// hasher was given its two-lane kernel. On **Windows** a pool worker's
/// member is not reached (the stored cut is off, [`STORED_CUT_DEFAULT`]);
/// the walk's own lone member is, and this is its dial
/// ([`walk_hashed_cut`]).
const B2SP_CUT_DEFAULT: bool = cfg!(any(target_os = "linux", target_os = "macos", windows));

/// The dial such a member is cut at where the knob says only `1` or `on`.
const B2SP_CUT_DIAL: HashDial = HashDial {
    lane: true,
    piece: None,
};

/// What `text` asks of [`B2SP_CUT_ENV`]: `None` for off (`0`, `off`),
/// `shipped` for `1` or `on`, `default` where it says nothing this knows.
/// The measuring arms, alone or joined by a colon: `reader` (the hasher on
/// the reader), `lane` (on one lane behind it), and a number of 64 or more
/// (the piece, in KiB), as in `lane:1024`.
pub(crate) fn hash_dial_of(
    text: Option<&str>,
    default: Option<HashDial>,
    shipped: HashDial,
) -> Option<HashDial> {
    let Some(text) = text else {
        return default;
    };
    let text = text.trim().to_ascii_lowercase();
    if matches!(text.as_str(), "0" | "off") {
        return None;
    }
    let mut dial = shipped;
    let mut known = false;
    for word in text.split(':') {
        match word {
            "reader" => dial.lane = false,
            "lane" => dial.lane = true,
            "1" | "on" => {}
            _ => match word.parse::<u64>() {
                Ok(kib) if kib >= 64 => dial.piece = Some(kib.saturating_mul(1024)),
                _ => continue,
            },
        }
        known = true;
    }
    if known {
        Some(dial)
    } else {
        default
    }
}

/// The dial a BLAKE2sp member is cut at, or `None` where it is not cut.
pub(crate) fn b2sp_cut() -> Option<HashDial> {
    #[cfg(feature = "test-support")]
    if let Some(forced) = crate::probe::b2sp_cut() {
        return forced;
    }
    static CUT: std::sync::OnceLock<Option<HashDial>> = std::sync::OnceLock::new();
    *CUT.get_or_init(|| {
        hash_dial_of(
            crate::knob::reader_var(B2SP_CUT_ENV).ok().as_deref(),
            B2SP_CUT_DEFAULT.then_some(B2SP_CUT_DIAL),
            B2SP_CUT_DIAL,
        )
    })
}

/// `RARKIT_B2SP_CUT_WALK`: `1` (or `on`) has THE WALK cut its own clear
/// stored BLAKE2sp member that it writes to a file, as a pool worker cuts
/// one ([`cut_hashed_here`]), in place of the seam, whose source unit
/// reads and hashes on one thread; `0` (or `off`) leaves it to the seam;
/// anything else, or nothing, is [`B2SP_CUT_WALK`]. Nothing is cut where
/// [`b2sp_cut`] is off. A RUNTIME knob, so one binary carries both arms.
pub(crate) const B2SP_CUT_WALK_ENV: &str = "RARKIT_B2SP_CUT_WALK";

/// Whether the walk cuts such a member where [`B2SP_CUT_WALK_ENV`] says
/// nothing: on Linux, macOS and Windows ([`walk_hashed_cut`]) (the pool's cut ships
/// on the same two, [`B2SP_CUT_DEFAULT`]). Counted and screened on 2 Oct
/// 2026: the seam's one source thread
/// reads and hashes; the cut gives the reader, the hasher and the writer a
/// thread each. A 12 GiB lone member, cold: 5.49 s to 5.04 s on a Zen 4,
/// 5.77 s to 4.44 s on an M1 Ultra, and warm there 4.26 s to 3.13 s; under
/// a named 64 MiB budget on the Zen 4, where the seam stands down, 6.67 s
/// to 3.99 s.
const B2SP_CUT_WALK: bool = cfg!(any(target_os = "linux", target_os = "macos", windows));

/// [`B2SP_CUT_WALK_ENV`]'s value as an answer.
fn cut_walk_of(value: Option<&str>) -> bool {
    match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        Some("1" | "on") => true,
        Some("0" | "off") => false,
        _ => B2SP_CUT_WALK,
    }
}

/// Whether the walk cuts its own clear stored BLAKE2sp member: a test's
/// answer, then the environment's, read once.
pub(crate) fn b2sp_cut_walk() -> bool {
    #[cfg(feature = "test-support")]
    if let Some(forced) = crate::probe::b2sp_cut_walk() {
        return forced;
    }
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| cut_walk_of(crate::knob::reader_var(B2SP_CUT_WALK_ENV).ok().as_deref()))
}

/// [`HandHashed`] for a writer on the thread that reads the member, a pool
/// worker's or the walk's own: the range is cut on a slab of this call's own, as
/// [`cut_here`] cuts one, read by ONE reader in order, and the member's
/// hasher is fed every byte of it in order before this answers.
pub(crate) fn cut_hashed_here<W: Write>(
    out: &mut W,
    range: Range,
    hashed: Hashed<'_>,
    passed: &mut dyn FnMut(Passed) -> Result<()>,
) -> std::result::Result<(), Stop> {
    #[cfg(feature = "test-support")]
    crate::probe::note_b2sp_cut();
    let mut cutter = Cutter::for_range(stored_cut().unwrap_or(STORED_CUT_DIAL));
    let outcome = cutter.deliver_hashed(&range, out, range.before, hashed, passed);
    // As `cut`: the bytes the range accounted for are the member's and are
    // written; what stopped it is the answer.
    let tail = cutter.finish(Some(out));
    crate::read::team::keep(cutter);
    outcome?;
    tail.map_err(|e| Stop::Accepted(Error::from(e)))
}

/// One piece of a hashed range on its way from the reader to the thread
/// that writes it: its buffer, where it lies, what the source answered,
/// and its CRC32 where one was asked for.
struct Hashing {
    buf: Aligned,
    start: u64,
    want: usize,
    read: Result<usize>,
    crc: u32,
}

/// Feed `hasher` the bytes the source gave for `piece`, and take their
/// CRC32 where it is wanted.
fn absorb(hasher: &mut Blake2sp, want_crc: bool, piece: &mut Hashing) {
    if let Ok(gave) = piece.read {
        let bytes = &piece.buf.bytes()[..gave];
        hasher.update(bytes);
        if want_crc {
            piece.crc = crate::checksum::crc32(bytes);
        }
    }
}

/// Read `len` bytes at `at` of `source` on ONE scoped thread, front to
/// back, in pieces of `piece` bytes into page-aligned buffers of `ring`,
/// feed every piece to `hasher` in order, and hand each to `accept` in
/// order on the calling thread, which is free to write one while the next
/// is read and hashed.
///
/// **Where the hasher runs.** With `lane`, on a second scoped thread
/// between the reader and the calling thread, so the three stages each
/// have a thread and there are three buffers: one being read, one being
/// hashed, one being written. Without it, on the reader, and there are
/// two. Either way the digest is one ordered stream BY CONSTRUCTION: one
/// reader reads the pieces in order and sends them down one channel, and
/// one thread takes them off it.
///
/// The bound is those buffers ahead of the byte being delivered. A source
/// that ends inside the range hands over what it gave, hashed, and stops
/// there; `accept`'s own error stops the reader at its next piece, the
/// hasher having absorbed at most the buffers in flight, of a member that
/// has failed. Where the host starts no lane the reader hashes; where it
/// starts no reader the pieces are read on this thread, between the
/// writes (`crate::threads`).
#[allow(clippy::too_many_arguments)]
fn read_hashed(
    source: &dyn RangeSource,
    at: u64,
    len: u64,
    piece: usize,
    ring: &mut Vec<Aligned>,
    hasher: &mut Blake2sp,
    lane: bool,
    want_crc: bool,
    accept: &mut dyn FnMut(&[u8], u32) -> Result<()>,
) -> std::result::Result<(), Stop> {
    let depth = RING + usize::from(lane);
    ring.retain(|b| b.bytes().len() == piece);
    ring.truncate(depth);
    while ring.len() < depth {
        ring.push(Aligned::new(piece));
    }
    let pieces = len.div_ceil(piece as u64);
    let read_one = move |index: u64, mut buf: Aligned| -> Hashing {
        let start = at + index * piece as u64;
        let want = (len - index * piece as u64).min(piece as u64) as usize;
        let read = read_upto_at(source, start, &mut buf.bytes_mut()[..want]);
        Hashing {
            buf,
            start,
            want,
            read,
            crc: 0,
        }
    };
    // What the calling thread does with a piece once it is hashed: the
    // buffer comes back whatever the piece came to.
    let mut join = |piece: Hashing| -> (Aligned, std::result::Result<(), Stop>) {
        let Hashing {
            buf,
            start,
            want,
            read,
            crc,
        } = piece;
        let outcome = match read {
            Err(error) => Err(Stop::Source(error)),
            Ok(gave) => {
                let accepted = if gave > 0 {
                    accept(&buf.bytes()[..gave], crc).map_err(Stop::Accepted)
                } else {
                    Ok(())
                };
                match accepted {
                    Ok(()) if gave < want => Err(Stop::Short(start + gave as u64)),
                    other => other,
                }
            }
        };
        (buf, outcome)
    };
    // Each channel holds every buffer there is, so no send on one waits.
    let (empty_tx, empty_rx) = sync_channel::<Aligned>(depth);
    let (read_tx, read_rx) = sync_channel::<Hashing>(depth);
    let (full_tx, full_rx) = sync_channel::<Hashing>(depth);
    for buf in ring.drain(..) {
        let _ = empty_tx.send(buf);
    }
    let full = &full_rx;
    let (outcome, mut home) = std::thread::scope(move |scope| {
        // The operation's meter follows its threads (API 8.4.1, `memory::Meter`).
        let op = crate::memory::op_slot();
        // The hasher, while no lane holds it; and where the reader sends
        // a piece: to the lane, or straight to the calling thread.
        let (here, next_tx) = if lane {
            let started = crate::threads::scoped_with(
                scope,
                (hasher, read_rx, full_tx.clone()),
                move |(hasher, read_rx, full_tx): (
                    &mut Blake2sp,
                    Receiver<Hashing>,
                    SyncSender<Hashing>,
                )| {
                    let _op = crate::memory::enter(op);
                    // In stream order by construction: one receiver, one
                    // channel, one piece at a time.
                    while let Ok(mut piece) = read_rx.recv() {
                        absorb(hasher, want_crc, &mut piece);
                        if full_tx.send(piece).is_err() {
                            break;
                        }
                    }
                },
            );
            match started {
                Ok(_) => (None, read_tx),
                // No thread for the lane: the reader hashes.
                Err((hasher, _, _)) => (Some(hasher), full_tx.clone()),
            }
        } else {
            (Some(hasher), full_tx.clone())
        };
        drop(full_tx);
        let reading = move |(mut hasher, empty_rx, next_tx): (
            Option<&mut Blake2sp>,
            Receiver<Aligned>,
            SyncSender<Hashing>,
        )| {
            let _op = crate::memory::enter(op);
            for index in 0..pieces {
                // The calling thread has stopped: nothing more is wanted.
                let Ok(buf) = empty_rx.recv() else {
                    break;
                };
                let mut piece = read_one(index, buf);
                if let Some(hasher) = hasher.as_deref_mut() {
                    absorb(hasher, want_crc, &mut piece);
                }
                let whole = matches!(piece.read, Ok(got) if got == piece.want);
                if next_tx.send(piece).is_err() || !whole {
                    break;
                }
            }
            empty_rx
        };
        match crate::threads::scoped_with(scope, (here, empty_rx, next_tx), reading) {
            Ok(reader) => {
                let mut next = 0u64;
                let outcome = (|| {
                    while next < pieces {
                        let Ok(piece) = full.recv() else {
                            // The reader and the lane have gone with pieces
                            // unread, which only a panic of theirs does;
                            // the scope re-raises it.
                            break;
                        };
                        let (buf, joined) = join(piece);
                        next += 1;
                        // Back for a piece further on.
                        let _ = empty_tx.send(buf);
                        joined?;
                    }
                    Ok(())
                })();
                // Dropping the empties' sender is what releases a reader
                // waiting for one; the reader's end releases the lane.
                drop(empty_tx);
                let mut home: Vec<Aligned> = Vec::new();
                if let Ok(left) = reader.join() {
                    home.extend(left.try_iter());
                }
                (outcome, home)
            }
            Err((mut hasher, empty_rx, next_tx)) => {
                // No thread for the reader: the same pieces, read here
                // between the writes, and hashed here or on the lane.
                let mut outcome = Ok(());
                for index in 0..pieces {
                    let Ok(buf) = empty_rx.try_recv() else {
                        break;
                    };
                    let mut piece = read_one(index, buf);
                    if let Some(hasher) = hasher.as_deref_mut() {
                        absorb(hasher, want_crc, &mut piece);
                    }
                    if next_tx.send(piece).is_err() {
                        break;
                    }
                    let Ok(piece) = full.recv() else {
                        break;
                    };
                    let (buf, joined) = join(piece);
                    let _ = empty_tx.send(buf);
                    if joined.is_err() {
                        outcome = joined;
                        break;
                    }
                }
                // The lane, where there is one, ends with its sender.
                drop(next_tx);
                (outcome, empty_rx.try_iter().collect())
            }
        }
    });
    // The scope has joined every thread: what the channels still hold.
    ring.append(&mut home);
    ring.extend(full_rx.try_iter().map(|piece| piece.buf));
    ring.truncate(depth);
    outcome
}

/// [`HandOver`] for a writer on the thread that reads the member: the
/// range is cut on a slab of this call's own, from where the member's
/// writer stands ([`Range::before`]), and the slab's last, short write
/// goes out before this answers, so nothing is kept between ranges and
/// the next range of the member is brought back to a multiple of the
/// piece by one short write of its own.
pub(crate) fn cut_here<W: Write>(
    out: &mut W,
    range: Range,
    passed: &mut dyn FnMut(Passed) -> Result<()>,
) -> std::result::Result<(), Stop> {
    cut(out, &range, None, passed).map(|_| ())
}

/// [`cut_here`] for a range of whole blocks under AES-CBC: [`HandCipher`].
pub(crate) fn cut_cipher_here<W: Write>(
    out: &mut W,
    range: Range,
    cipher: Cipher,
    passed: &mut dyn FnMut(Passed) -> Result<()>,
) -> std::result::Result<[u8; 16], Stop> {
    cut(out, &range, Some(cipher), passed)
}

fn cut<W: Write>(
    out: &mut W,
    range: &Range,
    cipher: Option<Cipher>,
    passed: &mut dyn FnMut(Passed) -> Result<()>,
) -> std::result::Result<[u8; 16], Stop> {
    #[cfg(feature = "test-support")]
    crate::probe::note_stored_cut();
    let dial = match &cipher {
        Some(_) => stored_cut_for_cipher(),
        None => stored_cut().unwrap_or(STORED_CUT_DIAL),
    };
    let mut cutter = Cutter::for_range(dial);
    let outcome = cutter.deliver(range, &[], Some(out), range.before, cipher, passed);
    // Whatever the range came to, the bytes it accounted for are the
    // member's and are written: what stopped it is the answer.
    let tail = cutter.finish(Some(out));
    crate::read::team::keep(cutter);
    let chain = outcome?;
    tail.map_err(|e| Stop::Accepted(Error::from(e)))?;
    Ok(chain)
}

/// One piece the in-order reader has read: its buffer, what the source
/// answered, and the chaining value in front of it.
struct Job {
    index: u64,
    buf: Aligned,
    read: Result<usize>,
    iv: [u8; 16],
}

/// A piece ready for the calling thread: how many bytes the source gave,
/// how many of them are joined (whole blocks, under a cipher), their
/// CRC32s and their last ciphertext block.
struct Got {
    gave: usize,
    got: usize,
    crc: u32,
    packed_crc: u32,
    chain: [u8; 16],
}

type Ready = (u64, Aligned, Result<Got>);

/// What the calling thread hears of a piece beside its bytes.
#[derive(Clone, Copy)]
struct Joined {
    crc: u32,
    packed_crc: u32,
    chain: [u8; 16],
}

/// Read `len` bytes at `at` of `source` on ONE thread of the extraction's
/// team (`read::team`), front to
/// back, in pieces of `piece` bytes into `depth` page-aligned buffers of
/// `ring`, and hand each piece and its CRC32 to `accept` in order on the
/// calling thread, which is free to write one while the next is read.
///
/// **With a `cipher`** the range is whole blocks of an AES-CBC member and
/// each piece is deciphered where it lies: the reader notes the last
/// ciphertext block of each piece as it reads it, which is the chaining
/// value of the next (SPEC-K 2.1), and `lanes` more threads of the team
/// decipher and hash the pieces behind it, so the source still sees one reader in order
/// and the cipher runs as wide as the ring leaves it room. With no lanes
/// the reader deciphers each piece itself.
///
/// The bound is `depth` pieces ahead of the byte being delivered. A source
/// that ends inside the range hands over what it gave and stops there;
/// `accept`'s own error stops the reader at its next piece. Where the host
/// starts no thread the pieces are read on this one, between the writes.
#[allow(clippy::too_many_arguments)]
fn read_in_order(
    source: &Arc<dyn RangeSource>,
    at: u64,
    len: u64,
    piece: usize,
    ring: &mut Vec<Aligned>,
    depth: usize,
    cipher: Option<(Cipher, usize)>,
    accept: &mut dyn FnMut(&[u8], Joined) -> Result<()>,
) -> std::result::Result<(), Stop> {
    let depth = depth.max(RING);
    ring.retain(|b| b.bytes().len() == piece);
    ring.truncate(depth);
    while ring.len() < depth {
        ring.push(Aligned::new(piece));
    }
    let pieces = len.div_ceil(piece as u64);
    let span = move |index: u64| {
        let start = at + index * piece as u64;
        (
            start,
            (len - index * piece as u64).min(piece as u64) as usize,
        )
    };
    let (cipher, lanes) = match cipher {
        Some((cipher, lanes)) => (Some(cipher), lanes.min(depth.saturating_sub(RING))),
        None => (None, 0),
    };
    // What is done to a piece once it is read: deciphered, where there is
    // a cipher, and hashed. On the reader where there are no lanes.
    let cipher = Arc::new(cipher);
    let finish = {
        let cipher = Arc::clone(&cipher);
        move |job: Job| -> Ready {
            let Job {
                index,
                mut buf,
                read,
                iv,
            } = job;
            let got = read.map(|gave| match &*cipher {
                None => {
                    let crc = crate::checksum::crc32(&buf.bytes()[..gave]);
                    Got {
                        gave,
                        got: gave,
                        crc,
                        packed_crc: crc,
                        chain: [0; 16],
                    }
                }
                Some(cipher) => {
                    // Whole blocks only: a source that ended inside one is
                    // short at the byte it ended, and the partial block is
                    // never deciphered.
                    let got = gave & !15;
                    let body = &mut buf.bytes_mut()[..got];
                    let packed_crc = if cipher.packed_crc {
                        crate::checksum::crc32(body)
                    } else {
                        0
                    };
                    let chain = cipher.pieces.run_from(iv, body);
                    Got {
                        gave,
                        got,
                        crc: crate::checksum::crc32(body),
                        packed_crc,
                        chain,
                    }
                }
            });
            (index, buf, got)
        }
    };
    // What the calling thread does with piece `index` once it is ready.
    let mut join = |index: u64, buf: &Aligned, got: Result<Got>| {
        let (start, want) = span(index);
        let got = got.map_err(Stop::Source)?;
        if got.got > 0 {
            let joined = Joined {
                crc: got.crc,
                packed_crc: got.packed_crc,
                chain: got.chain,
            };
            accept(&buf.bytes()[..got.got], joined).map_err(Stop::Accepted)?;
        }
        if got.gave < want {
            return Err(Stop::Short(start + got.gave as u64));
        }
        Ok(())
    };
    // Each channel holds every buffer there is, so no send on one waits.
    let (work_tx, work_rx) = sync_channel::<Job>(depth);
    let work_rx = Arc::new(Mutex::new(work_rx));
    let (full_tx, full_rx) = sync_channel::<Ready>(depth);
    let (empty_tx, empty_rx) = sync_channel::<Aligned>(depth);
    for buf in ring.drain(..) {
        let _ = empty_tx.send(buf);
    }
    let first = cipher.as_ref().as_ref().map_or([0; 16], |c| c.chain);
    let ciphered = cipher.is_some();
    // The reader's seat and the lanes', on the extraction's team
    // (`read::team`): no thread is started or ended for the range unless
    // the team has none free. A host that will start none leaves the range
    // the seats it could have.
    let seats = crate::read::team::seats(1 + lanes);
    if seats.count() == 0 {
        // No thread: the same pieces, read here between the writes.
        let mut chain = first;
        let mut buf = Aligned::new(piece);
        let mut outcome = Ok(());
        for index in 0..pieces {
            let (start, want) = span(index);
            let read = read_upto_at(&**source, start, &mut buf.bytes_mut()[..want]);
            let iv = chain;
            if let Ok(got) = read {
                let blocks = got & !15;
                if ciphered && blocks >= 16 {
                    chain.copy_from_slice(&buf.bytes()[blocks - 16..blocks]);
                }
            }
            let (_, back, got) = finish(Job {
                index,
                buf,
                read,
                iv,
            });
            buf = back;
            outcome = join(index, &buf, got);
            if outcome.is_err() {
                break;
            }
        }
        ring.push(buf);
        ring.extend(empty_rx.try_iter());
        ring.truncate(depth);
        return outcome;
    }
    // The lanes: each a job that deciphers and hashes the pieces the
    // reader sends until the reader has gone, on a thread of the team for
    // as long as the range lasts.
    let started = seats.count() - 1;
    for _ in 0..started {
        let (work, full_tx, finish) = (Arc::clone(&work_rx), full_tx.clone(), finish.clone());
        seats.hand(Box::new(move |_| loop {
            let job = work.lock().unwrap_or_else(|e| e.into_inner()).recv();
            let Ok(job) = job else {
                break;
            };
            if full_tx.send(finish(job)).is_err() {
                break;
            }
        }));
    }
    // The reader: one job for the whole range, which answers the empties'
    // receiver when it ends, or `None` where it fell.
    let (home_tx, home_rx) = std::sync::mpsc::channel::<Option<Receiver<Aligned>>>();
    {
        let source = Arc::clone(source);
        let fell = crate::read::team::Fell::watch(home_tx, None);
        seats.hand(Box::new(move |_| {
            let mut chain = first;
            for index in 0..pieces {
                // The calling thread has stopped: nothing more is wanted.
                let Ok(mut buf) = empty_rx.recv() else {
                    break;
                };
                let (start, want) = span(index);
                let read = read_upto_at(&*source, start, &mut buf.bytes_mut()[..want]);
                let whole = matches!(read, Ok(got) if got == want);
                let iv = chain;
                if let Ok(got) = read {
                    let blocks = got & !15;
                    if ciphered && blocks >= 16 {
                        chain.copy_from_slice(&buf.bytes()[blocks - 16..blocks]);
                    }
                }
                let job = Job {
                    index,
                    buf,
                    read,
                    iv,
                };
                let sent = if started == 0 {
                    full_tx.send(finish(job)).is_ok()
                } else {
                    work_tx.send(job).is_ok()
                };
                if !sent || !whole {
                    break;
                }
            }
            // The reader's end is what lets the lanes go: its senders drop
            // here, before it answers, and the source's handle with them.
            drop((work_tx, full_tx, source));
            fell.answered(Some(empty_rx));
        }));
    }
    // `waiting[k]` is piece `next + k`, `None` until it is ready: the
    // lanes answer in any order and the pieces are joined in theirs.
    let mut waiting: std::collections::VecDeque<Option<(Aligned, Result<Got>)>> =
        std::collections::VecDeque::with_capacity(depth);
    let mut next = 0u64;
    let mut fallen = false;
    let outcome = (|| {
        while next < pieces {
            if waiting.front().is_some_and(Option::is_some) {
                let (buf, got) = waiting.pop_front().flatten().expect("checked");
                let joined = join(next, &buf, got);
                next += 1;
                // Back for a piece further on.
                let _ = empty_tx.send(buf);
                joined?;
                continue;
            }
            let Ok((index, buf, got)) = full_rx.recv() else {
                // The reader and the lanes have gone with pieces unread,
                // which only a panic of theirs does.
                fallen = true;
                break;
            };
            let slot = (index - next) as usize;
            while waiting.len() <= slot {
                waiting.push_back(None);
            }
            waiting[slot] = Some((buf, got));
        }
        Ok(())
    })();
    // Dropping the empties' sender is what releases a reader waiting for
    // one; the reader's end releases the lanes.
    drop(empty_tx);
    ring.extend(waiting.into_iter().flatten().map(|(buf, _)| buf));
    // The reader is waited for, as its thread's join was: it holds the
    // buffers not yet read into. The lanes go back to the team behind it
    // and are not waited for; a piece one of them still holds when a range
    // stopped early is made again by the next range.
    match home_rx.recv() {
        Ok(Some(left)) => ring.extend(left.try_iter()),
        _ => fallen = true,
    }
    if fallen {
        // A helper panicked on its thread, which has said why; this thread
        // ends as a scope whose thread panicked did.
        panic!("a helper of a cut range panicked");
    }
    ring.extend(full_rx.try_iter().map(|(_, buf, _)| buf));
    ring.extend(
        work_rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .try_iter()
            .map(|job| job.buf),
    );
    ring.truncate(depth);
    outcome
}

/// The delivering thread's end: one slab, kept for the operation, in which
/// the bytes that do not come as whole pieces are gathered.
pub(crate) struct Cutter {
    slab: Option<Aligned>,
    /// Where the gathered bytes start and end in the slab. They start at
    /// zero, except in the first slab of a member that had written
    /// `start` bytes past a multiple of the piece before its first range:
    /// that slab is gathered from `start`, so it ends on the multiple.
    start: usize,
    fill: usize,
    /// Whether the member being delivered has had a range, after which
    /// every byte of it goes through the slab.
    cutting: bool,
    dial: Dial,
    /// The in-order reader's buffers, kept between ranges.
    ring: Vec<Aligned>,
    charge: Held,
}

/// Append `bytes` to the slab, writing it out each time it fills.
fn feed<W: Write>(
    slab: &mut Aligned,
    start: &mut usize,
    fill: &mut usize,
    out: &mut W,
    mut bytes: &[u8],
) -> std::io::Result<()> {
    let size = slab.bytes().len();
    while !bytes.is_empty() {
        let n = (size - *fill).min(bytes.len());
        slab.bytes_mut()[*fill..*fill + n].copy_from_slice(&bytes[..n]);
        *fill += n;
        bytes = &bytes[n..];
        if *fill == size {
            out.write_all(&slab.bytes()[*start..])?;
            *start = 0;
            *fill = 0;
        }
    }
    Ok(())
}

impl Cutter {
    pub(crate) fn new(dial: Dial) -> Cutter {
        Cutter {
            slab: None,
            start: 0,
            fill: 0,
            cutting: false,
            dial,
            ring: Vec::new(),
            charge: Held::default(),
        }
    }

    /// A cutter for ONE range of an extraction, under `dial`: the one an
    /// earlier range of the extraction left with its team
    /// (`read::team::keep`), its slab and its reader's ring with it, or a
    /// new one. A range's cutter is finished before it is left, so it
    /// carries no byte and no member's state, only the buffers: which
    /// would otherwise be made, faulted in and given back a range.
    fn for_range(dial: Dial) -> Cutter {
        crate::read::team::kept(|kept: &Cutter| kept.dial == dial && !kept.cutting)
            .unwrap_or_else(|| Cutter::new(dial))
    }

    /// Whether this member's bytes go through the slab from here on.
    pub(crate) fn cutting(&self) -> bool {
        self.cutting
    }

    /// Bytes of the member that came the ordinary way, after a range of
    /// it: gathered, so the next range's pieces still land whole.
    pub(crate) fn put<W: Write>(&mut self, out: &mut W, bytes: &[u8]) -> std::io::Result<()> {
        match self.slab.as_mut() {
            Some(slab) => feed(slab, &mut self.start, &mut self.fill, out, bytes),
            None => out.write_all(bytes),
        }
    }

    /// The member has ended: its last, short write, and nothing kept for
    /// the member after it.
    pub(crate) fn finish<W: Write>(&mut self, out: Option<&mut W>) -> std::io::Result<()> {
        let (start, fill) = (
            std::mem::take(&mut self.start),
            std::mem::take(&mut self.fill),
        );
        self.cutting = false;
        match (out, self.slab.as_ref()) {
            (Some(out), Some(slab)) if fill > start => out.write_all(&slab.bytes()[start..fill]),
            _ => Ok(()),
        }
    }

    /// Read `range` and deliver it: into `out` in order where there
    /// is a writer, `lead` (the member's bytes the walk held unwritten)
    /// first; hashed and no more where there is none. `passed` hears of
    /// each piece once it is delivered. `before` is how many bytes of the
    /// member `out` was given before this member's first range.
    ///
    /// With a `cipher` the range is whole blocks of an AES-CBC member,
    /// deciphered piece by piece where each was read, and the answer is
    /// their last ciphertext block.
    pub(crate) fn deliver<W: Write>(
        &mut self,
        range: &Range,
        lead: &[u8],
        out: Option<&mut W>,
        before: u64,
        cipher: Option<Cipher>,
        passed: &mut dyn FnMut(Passed) -> Result<()>,
    ) -> std::result::Result<[u8; 16], Stop> {
        let source = &range.source;
        // A written piece goes whole to the writer: its plaintext on the
        // page. One that is only checked keeps the joined read's buffers.
        let mut cipher = cipher.map(|c| Cipher {
            page_plain: out.is_some(),
            ..c
        });
        let mut last = cipher.as_ref().map_or([0; 16], |c| c.chain);
        let Some(out) = out else {
            wide::verify_range(
                source,
                range.at,
                range.len,
                range.plan,
                false,
                cipher,
                &mut |piece| {
                    last = piece.chain;
                    passed(Passed {
                        crc: piece.crc,
                        packed_crc: piece.packed_crc,
                        len: piece.len,
                    })
                },
            )?;
            return Ok(last);
        };
        let in_order = self.dial.in_order.unwrap_or(IN_ORDER);
        let readers = range.plan.workers.max(1);
        let window = range.window.max((readers * range.plan.piece) as u64);
        // The plan the slabs are cut from: the readers granted, over the
        // member's whole window.
        let whole = Plan {
            workers: readers,
            piece: (window / readers as u64) as usize,
        };
        // The pieces: half the window for a clear range, whose readers
        // outrun any write; a deciphered one's are the cipher's lanes.
        let target = match (cipher.is_some(), in_order) {
            (false, _) => self.dial.piece,
            (true, false) => Some(self.dial.piece.unwrap_or(window / CIPHER_PIECES)),
            // By the window alone, so a member's pieces keep their size
            // whatever readers each of its ranges is granted.
            (true, true) => Some(self.dial.piece.unwrap_or(window / CIPHER_RING as u64)),
        };
        let plan = wide::slabs_of(whole, target);
        let size = plan.piece;
        // In order: one piece being read, one being written, and the rest
        // of the window on the cipher's lanes, which are never more than
        // the readers the plan had.
        let depth = match &cipher {
            Some(_) => ((window / size as u64) as usize).clamp(RING, CIPHER_RING),
            None => RING,
        };
        let lanes = (depth - RING).min(readers.saturating_sub(1));
        if self.slab.as_ref().is_some_and(|s| s.bytes().len() != size) {
            // A plan that changed inside an operation (a deciphered range
            // behind a clear one): what is gathered goes out before the
            // slab is replaced.
            if let Some(slab) = self.slab.take() {
                let (start, fill) = (
                    std::mem::take(&mut self.start),
                    std::mem::take(&mut self.fill),
                );
                out.write_all(&slab.bytes()[start..fill])
                    .map_err(|e| Stop::Accepted(Error::from(e)))?;
                self.cutting = false;
            }
        }
        let slab = self.slab.get_or_insert_with(|| Aligned::new(size));
        // The slab, and the in-order reader's buffers where it runs
        // (the wide reader charges its own).
        let ring = if in_order { depth as u64 } else { 0 };
        self.charge.set(slab.held_bytes() * (1 + ring));
        if !self.cutting {
            // The member's first range: what it wrote before it leaves
            // the first slab that much shorter.
            self.start = (before % size as u64) as usize;
            self.fill = self.start;
            self.cutting = true;
        }
        let (start, fill) = (&mut self.start, &mut self.fill);
        feed(slab, start, fill, out, lead).map_err(|e| Stop::Accepted(Error::from(e)))?;
        if cipher.is_some() && !fill.is_multiple_of(16) {
            // A deciphered range starts on a block, and a piece is whole
            // blocks: bytes gathered to no block (which no member's own
            // reads leave) go out as they are, and the pieces are cut
            // from here.
            out.write_all(&slab.bytes()[*start..*fill])
                .map_err(|e| Stop::Accepted(Error::from(e)))?;
            *start = 0;
            *fill = 0;
        }

        // The slab's remainder, read here: after it every piece of the
        // range begins at a multiple of the piece in the member.
        let (mut at, mut len) = (range.at, range.len);
        if *fill > 0 && len > 0 {
            let want = ((size - *fill) as u64).min(len) as usize;
            let gave = read_upto_at(&**source, at, &mut slab.bytes_mut()[*fill..*fill + want])
                .map_err(Stop::Source)?;
            let (got, crc, packed_crc) = match cipher.as_mut() {
                None => {
                    let crc = crate::checksum::crc32(&slab.bytes()[*fill..*fill + gave]);
                    (gave, crc, crc)
                }
                Some(cipher) => {
                    let got = gave & !15;
                    let body = &mut slab.bytes_mut()[*fill..*fill + got];
                    let packed_crc = if cipher.packed_crc {
                        crate::checksum::crc32(body)
                    } else {
                        0
                    };
                    if got > 0 {
                        cipher.chain = cipher.pieces.run_from(cipher.chain, body);
                        last = cipher.chain;
                    }
                    (got, crate::checksum::crc32(body), packed_crc)
                }
            };
            *fill += got;
            if *fill == size {
                out.write_all(&slab.bytes()[*start..])
                    .map_err(|e| Stop::Accepted(Error::from(e)))?;
                *start = 0;
                *fill = 0;
            }
            if got > 0 {
                passed(Passed {
                    crc,
                    packed_crc,
                    len: got as u64,
                })
                .map_err(Stop::Accepted)?;
            }
            if gave < want {
                return Err(Stop::Short(at + gave as u64));
            }
            at += want as u64;
            len -= want as u64;
        }
        if len == 0 {
            return Ok(last);
        }
        // A whole piece with nothing gathered in front of it goes from the
        // buffer it was read into; the range's last, short one is gathered
        // for whatever of the member follows it.
        let mut take = |bytes: &[u8], crc: u32, packed_crc: u32| -> Result<()> {
            if *fill == 0 && bytes.len() == size {
                out.write_all(bytes)?;
            } else {
                feed(slab, start, fill, out, bytes)?;
            }
            passed(Passed {
                crc,
                packed_crc,
                len: bytes.len() as u64,
            })
        };
        if in_order {
            read_in_order(
                source,
                at,
                len,
                size,
                &mut self.ring,
                depth,
                cipher.map(|c| (c, lanes)),
                &mut |bytes, joined| {
                    last = joined.chain;
                    take(bytes, joined.crc, joined.packed_crc)
                },
            )?;
            return Ok(last);
        }
        wide::verify_range(source, at, len, plan, true, cipher, &mut |piece| {
            let Some(bytes) = piece.bytes else {
                unreachable!("a lent read brings its bytes home")
            };
            last = piece.chain;
            take(bytes, piece.crc, piece.packed_crc)
        })?;
        Ok(last)
    }

    /// [`Cutter::deliver`] for a range of a CLEAR member under BLAKE2sp
    /// ([`Hashed`]): the same slab and the same whole pieces at whole
    /// offsets into `out`, read by ONE reader in order ([`read_hashed`])
    /// whatever [`Dial::in_order`] says, because the digest is one ordered
    /// stream; every byte of the range reaches the hasher in order,
    /// the slab's remainder from this thread and the pieces from the
    /// reader or its lane.
    pub(crate) fn deliver_hashed<W: Write>(
        &mut self,
        range: &Range,
        out: &mut W,
        before: u64,
        hashed: Hashed<'_>,
        passed: &mut dyn FnMut(Passed) -> Result<()>,
    ) -> std::result::Result<(), Stop> {
        let source: &dyn RangeSource = &*range.source;
        let Hashed {
            hasher,
            dial,
            packed_crc,
        } = hashed;
        let readers = range.plan.workers.max(1);
        let window = range.window.max((readers * range.plan.piece) as u64);
        let whole = Plan {
            workers: readers,
            piece: (window / readers as u64) as usize,
        };
        // The lane only where three of the smallest piece fit the window;
        // then the piece, never more than the window's share of a buffer.
        let lane = dial.lane && window >= 3 * (128 << 10);
        let depth = RING + usize::from(lane);
        let target = dial
            .piece
            .unwrap_or(window / depth.next_power_of_two() as u64)
            .min(window / depth as u64);
        let size = wide::slabs_of(whole, Some(target)).piece;
        if self.slab.as_ref().is_some_and(|s| s.bytes().len() != size) {
            if let Some(slab) = self.slab.take() {
                let (start, fill) = (
                    std::mem::take(&mut self.start),
                    std::mem::take(&mut self.fill),
                );
                out.write_all(&slab.bytes()[start..fill])
                    .map_err(|e| Stop::Accepted(Error::from(e)))?;
                self.cutting = false;
            }
        }
        let slab = self.slab.get_or_insert_with(|| Aligned::new(size));
        self.charge.set(slab.held_bytes() * (1 + depth as u64));
        if !self.cutting {
            // The member's first range: what it wrote before it leaves
            // the first slab that much shorter.
            self.start = (before % size as u64) as usize;
            self.fill = self.start;
            self.cutting = true;
        }
        let (start, fill) = (&mut self.start, &mut self.fill);

        // The slab's remainder, read and hashed here: after it every piece
        // of the range begins at a multiple of the piece in the member.
        let (mut at, mut len) = (range.at, range.len);
        if *fill > 0 && len > 0 {
            let want = ((size - *fill) as u64).min(len) as usize;
            let gave = read_upto_at(source, at, &mut slab.bytes_mut()[*fill..*fill + want])
                .map_err(Stop::Source)?;
            let bytes = &slab.bytes()[*fill..*fill + gave];
            hasher.update(bytes);
            let crc = if packed_crc {
                crate::checksum::crc32(bytes)
            } else {
                0
            };
            *fill += gave;
            if *fill == size {
                out.write_all(&slab.bytes()[*start..])
                    .map_err(|e| Stop::Accepted(Error::from(e)))?;
                *start = 0;
                *fill = 0;
            }
            if gave > 0 {
                passed(Passed {
                    crc,
                    packed_crc: crc,
                    len: gave as u64,
                })
                .map_err(Stop::Accepted)?;
            }
            if gave < want {
                return Err(Stop::Short(at + gave as u64));
            }
            at += want as u64;
            len -= want as u64;
        }
        if len == 0 {
            return Ok(());
        }
        read_hashed(
            source,
            at,
            len,
            size,
            &mut self.ring,
            hasher,
            lane,
            packed_crc,
            &mut |bytes, crc| {
                if *fill == 0 && bytes.len() == size {
                    out.write_all(bytes)?;
                } else {
                    feed(slab, start, fill, out, bytes)?;
                }
                passed(Passed {
                    crc,
                    packed_crc: crc,
                    len: bytes.len() as u64,
                })
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A source of `len` deterministic bytes.
    struct Bytes(Vec<u8>);

    impl RangeSource for Bytes {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            let from = (offset as usize).min(self.0.len());
            let n = buf.len().min(self.0.len() - from);
            buf[..n].copy_from_slice(&self.0[from..from + n]);
            Ok(n)
        }
        fn available(&self) -> u64 {
            self.0.len() as u64
        }
        fn len(&self) -> Option<u64> {
            Some(self.0.len() as u64)
        }
    }

    fn noise(n: usize) -> Vec<u8> {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    /// Every write a member's writer was given: its length, and whether
    /// its buffer began on a page.
    #[derive(Default)]
    struct Writes {
        bytes: Vec<u8>,
        calls: Vec<(usize, bool)>,
    }

    impl Write for Writes {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.calls
                .push((data.len(), (data.as_ptr() as usize).is_multiple_of(4096)));
            self.bytes.extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    const PLAN: Plan = Plan {
        workers: 4,
        piece: 256 * 1024,
    };

    /// Every case runs with the window's pieces read at once and with one
    /// reader in order: the two say and write the same.
    fn both_orders() -> [Dial; 2] {
        [false, true].map(|in_order| Dial {
            piece: None,
            in_order: Some(in_order),
        })
    }

    /// Both placements of a hashed range's hasher, at the default piece
    /// and at a named one.
    fn hash_dials() -> [HashDial; 4] {
        [
            HashDial {
                lane: true,
                piece: None,
            },
            HashDial {
                lane: false,
                piece: None,
            },
            HashDial {
                lane: true,
                piece: Some(128 * 1024),
            },
            HashDial {
                lane: false,
                piece: Some(128 * 1024),
            },
        ]
    }

    /// One hashed range of `data[at..]` into `out`, the member's writer
    /// having been given `data[..at]` the ordinary way first (hashed by
    /// the caller, as `emit` would have): what the range came to, the
    /// bytes it accounted for, and the pieces' CRC32s joined.
    fn hashed(
        data: &[u8],
        at: usize,
        dial: HashDial,
        out: &mut impl Write,
        hasher: &mut Blake2sp,
        want_crc: bool,
    ) -> (std::result::Result<(), Stop>, u64, crate::checksum::Crc32) {
        let source: Arc<dyn RangeSource> = Arc::new(Bytes(data.to_vec()));
        let range = Range {
            source,
            at: at as u64,
            len: (data.len() - at) as u64,
            plan: PLAN,
            window: (PLAN.workers * PLAN.piece) as u64,
            before: at as u64,
        };
        let mut accounted = 0u64;
        let mut crc = crate::checksum::Crc32::new();
        let outcome = cut_hashed_here(
            out,
            range,
            Hashed {
                hasher,
                dial,
                packed_crc: want_crc,
            },
            &mut |piece| {
                assert_eq!(piece.crc, piece.packed_crc);
                crc.append(piece.packed_crc, piece.len);
                accounted += piece.len;
                Ok(())
            },
        );
        (outcome, accounted, crc)
    }

    /// A hashed range: the digest is the member's, every write but the
    /// first (which brings the member back to a multiple of the piece)
    /// and the last is one whole piece from a page-aligned buffer, the
    /// bytes are the member's, and the pieces' CRC32s join to the range's
    /// where they were asked for. With the hasher on a lane and on the
    /// reader, at the default piece and a named one.
    #[test]
    fn a_hashed_range_keeps_the_digest_and_whole_aligned_pieces() {
        let data = noise(5 * 512 * 1024 + 12_345);
        let want = crate::checksum::blake2sp::blake2sp(&data);
        for dial in hash_dials() {
            for lead in [0usize, 4096, 70_001] {
                let mut out = Writes::default();
                out.write_all(&data[..lead]).unwrap();
                out.calls.clear();
                let mut hasher = Blake2sp::new();
                hasher.update(&data[..lead]);
                let (outcome, accounted, crc) =
                    hashed(&data, lead, dial, &mut out, &mut hasher, true);
                assert!(outcome.is_ok(), "{dial:?} lead {lead}");
                assert_eq!(
                    accounted as usize,
                    data.len() - lead,
                    "{dial:?} lead {lead}"
                );
                assert_eq!(out.bytes, data, "{dial:?} lead {lead}: the bytes");
                assert_eq!(hasher.finalize(), want, "{dial:?} lead {lead}: the digest");
                assert_eq!(
                    crc.finish(),
                    crate::checksum::crc32(&data[lead..]),
                    "{dial:?} lead {lead}: the pieces' CRC32"
                );
                // The window is 1 MiB: a quarter of it with the lane, half
                // on the reader, or the named piece.
                let size = dial
                    .piece
                    .unwrap_or(if dial.lane { 256 * 1024 } else { 512 * 1024 })
                    as usize;
                let last = out.calls.len() - 1;
                for (at, (len, aligned)) in out.calls.iter().enumerate() {
                    if at == 0 && !lead.is_multiple_of(size) {
                        assert_eq!(*len, size - lead % size, "{dial:?} lead {lead}: the first");
                    } else if at < last {
                        assert_eq!(*len, size, "{dial:?} lead {lead}: write {at}");
                        assert!(*aligned, "{dial:?} lead {lead}: write {at} on a page");
                    } else {
                        assert!(*len <= size, "{dial:?} lead {lead}: the last");
                    }
                }
            }
        }
    }

    /// No CRC32 is taken where none is wanted: the pieces say zero.
    #[test]
    fn a_hashed_range_takes_no_crc_unasked() {
        let data = noise(3 * 512 * 1024 + 77);
        for dial in hash_dials() {
            let mut out = Writes::default();
            let mut hasher = Blake2sp::new();
            let source: Arc<dyn RangeSource> = Arc::new(Bytes(data.clone()));
            let range = Range {
                source,
                at: 0,
                len: data.len() as u64,
                plan: PLAN,
                window: (PLAN.workers * PLAN.piece) as u64,
                before: 0,
            };
            let outcome = cut_hashed_here(
                &mut out,
                range,
                Hashed {
                    hasher: &mut hasher,
                    dial,
                    packed_crc: false,
                },
                &mut |piece| {
                    assert_eq!((piece.crc, piece.packed_crc), (0, 0));
                    Ok(())
                },
            );
            assert!(outcome.is_ok());
            assert_eq!(
                hasher.finalize(),
                crate::checksum::blake2sp::blake2sp(&data)
            );
        }
    }

    /// A source that ends inside the range is `Short` at the byte it
    /// ended, with every byte before it written; a writer that refuses
    /// ends the range with its own error and a prefix of the member.
    #[test]
    fn a_short_source_and_a_refusing_writer_stop_a_hashed_range() {
        let data = noise(4 * 512 * 1024 + 999);
        for dial in hash_dials() {
            // The range claims 100,000 bytes more than the source holds.
            let source: Arc<dyn RangeSource> = Arc::new(Bytes(data.clone()));
            let range = Range {
                source,
                at: 0,
                len: data.len() as u64 + 100_000,
                plan: PLAN,
                window: (PLAN.workers * PLAN.piece) as u64,
                before: 0,
            };
            let mut out = Writes::default();
            let mut hasher = Blake2sp::new();
            let outcome = cut_hashed_here(
                &mut out,
                range,
                Hashed {
                    hasher: &mut hasher,
                    dial,
                    packed_crc: false,
                },
                &mut |_| Ok(()),
            );
            assert!(
                matches!(outcome, Err(Stop::Short(end)) if end == data.len() as u64),
                "{dial:?}: short at the source's end"
            );
            assert_eq!(out.bytes, data, "{dial:?}: every byte the source gave");

            struct Full(Vec<u8>, usize);
            impl Write for Full {
                fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                    if self.0.len() + data.len() > self.1 {
                        return Err(std::io::Error::other("full"));
                    }
                    self.0.extend_from_slice(data);
                    Ok(data.len())
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            let mut full = Full(Vec::new(), 700_000);
            let mut hasher = Blake2sp::new();
            let (outcome, _, _) = hashed(&data, 0, dial, &mut full, &mut hasher, false);
            assert!(
                matches!(outcome, Err(Stop::Accepted(_))),
                "{dial:?}: refused"
            );
            assert!(full.0.len() <= 700_000 && full.0[..] == data[..full.0.len()]);
        }
    }

    /// `RARKIT_B2SP_CUT_WALK`'s words, and that it ships on Linux, macOS
    /// and Windows (`walk_hashed_cut`).
    #[test]
    fn the_walks_cut_reads_its_words_and_ships_on_linux_macos_and_windows() {
        assert_eq!(
            B2SP_CUT_WALK,
            cfg!(any(target_os = "linux", target_os = "macos", windows))
        );
        assert_eq!(cut_walk_of(None), B2SP_CUT_WALK);
        assert!(cut_walk_of(Some("1")));
        assert!(cut_walk_of(Some(" ON ")));
        assert!(!cut_walk_of(Some("0")));
        assert!(!cut_walk_of(Some("off")));
        assert_eq!(cut_walk_of(Some("what")), B2SP_CUT_WALK);
    }

    /// `RARKIT_B2SP_CUT`'s words, and that it ships on Linux, macOS and
    /// Windows (where only the walk's own member reaches it), with the
    /// hasher on a lane.
    #[test]
    fn the_hash_dial_reads_its_words_and_ships_on_linux_macos_and_windows() {
        let shipped = B2SP_CUT_DIAL;
        assert_eq!(
            B2SP_CUT_DEFAULT,
            cfg!(any(target_os = "linux", target_os = "macos", windows))
        );
        assert!(shipped.lane && shipped.piece.is_none());
        assert_eq!(hash_dial_of(None, None, shipped), None);
        assert_eq!(hash_dial_of(Some("0"), Some(shipped), shipped), None);
        assert_eq!(hash_dial_of(Some(" OFF "), Some(shipped), shipped), None);
        assert_eq!(hash_dial_of(Some("1"), None, shipped), Some(shipped));
        assert_eq!(hash_dial_of(Some("on"), None, shipped), Some(shipped));
        assert_eq!(hash_dial_of(Some("what"), None, shipped), None);
        assert_eq!(
            hash_dial_of(Some("reader"), None, shipped),
            Some(HashDial {
                lane: false,
                piece: None
            })
        );
        assert_eq!(
            hash_dial_of(Some("lane:1024"), None, shipped),
            Some(HashDial {
                lane: true,
                piece: Some(1 << 20)
            })
        );
        assert_eq!(
            hash_dial_of(Some("reader:2048"), None, shipped),
            Some(HashDial {
                lane: false,
                piece: Some(2 << 20)
            })
        );
        // A number under 64 KiB is no piece.
        assert_eq!(hash_dial_of(Some("8"), None, shipped), None);
    }

    /// A named piece larger than the window's share of a buffer is brought
    /// inside it: three buffers with the lane, two on the reader.
    #[test]
    fn a_hashed_ranges_buffers_stay_inside_the_window() {
        let data = noise(3 << 20);
        for lane in [true, false] {
            let dial = HashDial {
                lane,
                piece: Some(4 << 20),
            };
            let mut out = Writes::default();
            let mut hasher = Blake2sp::new();
            let (outcome, _, _) = hashed(&data, 0, dial, &mut out, &mut hasher, false);
            assert!(outcome.is_ok());
            let window = PLAN.workers * PLAN.piece;
            let depth = if lane { 3 } else { 2 };
            let largest = out.calls.iter().map(|c| c.0).max().unwrap();
            assert!(largest * depth <= window, "lane {lane}: {largest} a buffer");
            assert_eq!(out.bytes, data);
        }
    }

    /// A member made of a lead the walk held, a range, an ordinary tail,
    /// a second fragment's head and range, and its end: every write but
    /// the last is one whole piece from a page-aligned buffer, at a
    /// multiple of the piece in the member, and the bytes and the CRC32
    /// are the member's.
    #[test]
    fn every_write_but_the_last_is_a_whole_aligned_piece() {
        for dial in both_orders() {
            every_write_but_the_last_is_a_whole_aligned_piece_at(dial);
        }
    }

    fn every_write_but_the_last_is_a_whole_aligned_piece_at(dial: Dial) {
        let data = noise(5 * 512 * 1024 + 12_345);
        let source: Arc<dyn RangeSource> = Arc::new(Bytes(data.clone()));
        let size = wide::slabs_of(PLAN, None).piece;
        assert_eq!(size, 512 * 1024, "half the window");
        // lead, range one, a tail by hand, a head by hand, range two.
        let cuts = [0usize, 777, 1_300_000, 1_300_010, 1_300_099, data.len()];
        let mut cutter = Cutter::new(dial);
        let mut out = Writes::default();
        let mut crc = crate::checksum::Crc32::new();
        crc.update(&data[cuts[0]..cuts[1]]);
        let mut seen = cuts[1] as u64;
        let range = |cutter: &mut Cutter,
                     out: &mut Writes,
                     lead: &[u8],
                     from: usize,
                     to: usize,
                     crc: &mut crate::checksum::Crc32,
                     seen: &mut u64| {
            let r = Range {
                source: Arc::clone(&source),
                at: from as u64,
                len: (to - from) as u64,
                plan: PLAN,
                window: 0,
                before: 0,
            };
            let outcome = cutter.deliver(&r, lead, Some(out), 0, None, &mut |p| {
                crc.append(p.crc, p.len);
                *seen += p.len;
                Ok(())
            });
            assert!(outcome.is_ok());
        };
        range(
            &mut cutter,
            &mut out,
            &data[cuts[0]..cuts[1]],
            cuts[1],
            cuts[2],
            &mut crc,
            &mut seen,
        );
        assert!(cutter.cutting());
        cutter.put(&mut out, &data[cuts[2]..cuts[3]]).expect("tail");
        crc.update(&data[cuts[2]..cuts[4]]);
        seen += (cuts[4] - cuts[2]) as u64;
        range(
            &mut cutter,
            &mut out,
            &data[cuts[3]..cuts[4]],
            cuts[4],
            cuts[5],
            &mut crc,
            &mut seen,
        );
        cutter.finish(Some(&mut out)).expect("finish");
        assert!(!cutter.cutting());

        assert_eq!(out.bytes, data);
        assert_eq!(seen, data.len() as u64);
        assert_eq!(crc.finish(), crate::checksum::crc32(&data));
        let (last, whole) = out.calls.split_last().expect("writes");
        assert_eq!(whole.len(), data.len() / size);
        for (at, call) in whole.iter().enumerate() {
            assert_eq!(*call, (size, true), "write {at}");
        }
        assert_eq!(last.0, data.len() % size);
    }

    /// A member that wrote bytes before its first range (a fragment too
    /// short to hand over) is brought to a multiple of the piece by ONE
    /// short write, and written whole from there.
    #[test]
    fn bytes_written_before_the_first_range_cost_one_short_write() {
        for dial in both_orders() {
            bytes_written_before_the_first_range_cost_one_short_write_at(dial);
        }
    }

    fn bytes_written_before_the_first_range_cost_one_short_write_at(dial: Dial) {
        let data = noise(4 * 512 * 1024 + 99);
        let source: Arc<dyn RangeSource> = Arc::new(Bytes(data.clone()));
        let size = wide::slabs_of(PLAN, None).piece;
        let before = 300_001usize;
        let mut out = Writes::default();
        out.write_all(&data[..before]).expect("the early bytes");
        let mut cutter = Cutter::new(dial);
        let r = Range {
            source,
            at: before as u64,
            len: (data.len() - before) as u64,
            plan: PLAN,
            window: 0,
            before: 0,
        };
        let outcome = cutter.deliver(
            &r,
            &[],
            Some(&mut out),
            before as u64,
            None,
            &mut |_| Ok(()),
        );
        assert!(outcome.is_ok());
        cutter.finish(Some(&mut out)).expect("finish");
        assert_eq!(out.bytes, data);
        assert_eq!(out.calls[0].0, before);
        assert_eq!(out.calls[1].0, size - before);
        let (last, whole) = out.calls[2..].split_last().expect("writes");
        assert!(whole.iter().all(|c| *c == (size, true)));
        assert_eq!(whole.len(), data.len() / size - 1);
        assert_eq!(last.0, data.len() % size);
    }

    /// A member that is only checked is read at the walk's own plan, with
    /// no writer and no slab, and its pieces join to the range's CRC32.
    #[test]
    fn a_range_with_no_writer_is_hashed_and_held_nowhere() {
        for dial in both_orders() {
            a_range_with_no_writer_is_hashed_and_held_nowhere_at(dial);
        }
    }

    fn a_range_with_no_writer_is_hashed_and_held_nowhere_at(dial: Dial) {
        let data = noise(3 * 1024 * 1024 + 5);
        let source: Arc<dyn RangeSource> = Arc::new(Bytes(data.clone()));
        let mut cutter = Cutter::new(dial);
        let mut crc = crate::checksum::Crc32::new();
        let r = Range {
            source,
            at: 9,
            len: (data.len() - 9) as u64,
            plan: PLAN,
            window: 0,
            before: 0,
        };
        let outcome = cutter.deliver::<Writes>(&r, &[1, 2, 3], None, 0, None, &mut |p| {
            crc.append(p.crc, p.len);
            Ok(())
        });
        assert!(outcome.is_ok());
        assert!(!cutter.cutting());
        assert_eq!(crc.finish(), crate::checksum::crc32(&data[9..]));
    }

    /// A source that ends inside the range stops it where it ended, after
    /// the bytes it did give were delivered; a writer that refuses stops
    /// it with the writer's own error.
    #[test]
    fn a_short_source_and_a_refusing_writer_stop_the_range() {
        for dial in both_orders() {
            a_short_source_and_a_refusing_writer_stop_the_range_at(dial);
        }
    }

    fn a_short_source_and_a_refusing_writer_stop_the_range_at(dial: Dial) {
        let data = noise(2 * 1024 * 1024);
        let source: Arc<dyn RangeSource> = Arc::new(Bytes(data.clone()));
        let mut cutter = Cutter::new(dial);
        let mut out = Writes::default();
        let r = Range {
            source: Arc::clone(&source),
            at: 100,
            len: 4 * 1024 * 1024,
            plan: PLAN,
            window: 0,
            before: 0,
        };
        let mut seen = 0u64;
        let outcome = cutter.deliver(&r, &[], Some(&mut out), 0, None, &mut |p| {
            seen += p.len;
            Ok(())
        });
        assert!(matches!(outcome, Err(Stop::Short(end)) if end == data.len() as u64));
        cutter.finish(Some(&mut out)).expect("finish");
        assert_eq!(seen, (data.len() - 100) as u64);
        assert_eq!(out.bytes, &data[100..]);

        struct Full;
        impl Write for Full {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("full"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let r = Range {
            source,
            at: 0,
            len: data.len() as u64,
            plan: PLAN,
            window: 0,
            before: 0,
        };
        let mut cutter = Cutter::new(dial);
        let outcome = cutter.deliver(&r, &[], Some(&mut Full), 0, None, &mut |_| Ok(()));
        assert!(matches!(outcome, Err(Stop::Accepted(_))));
    }

    fn decryptor(key: u8, iv: u8) -> crate::crypto::MemberDecryptor {
        use aes::cipher::KeyInit;
        let key = [key; 32];
        crate::crypto::MemberDecryptor::new(crate::crypto::MemberCipher::Aes256Cbc(
            crate::crypto::cbc::CbcDec::new_with_key(
                aes::Aes256Dec::new(&key.into()),
                &key,
                [iv; 16],
            ),
        ))
    }

    /// The cipher hand-over, cut: a range of whole blocks is deciphered piece by
    /// piece where it was read, in both orders and at every depth of the
    /// in-order ring, and what is written is the serial decryptor's
    /// plaintext, in whole pieces from page-aligned buffers; the CRC32s
    /// are the plaintext's and the ciphertext's, and the chain handed back
    /// is the serial one. `before` is what the member wrote ahead of the
    /// range, which one short write brings back to a multiple of the piece.
    #[test]
    fn a_deciphered_range_is_cut_into_whole_aligned_pieces() {
        let data = noise(6 * 1024 * 1024 + 4096);
        let source: Arc<dyn RangeSource> = Arc::new(Bytes(data.clone()));
        for (at, len, before, workers) in [
            (0usize, 6 * 1024 * 1024usize, 0u64, 4usize),
            (48, 5 * 1024 * 1024 + 16 * 77, 0, 8),
            (4096, 3 * 1024 * 1024, 160, 2),
            (160, 2 * 1024 * 1024 + 16, 300_000 & !15, 3),
        ] {
            // Both orders at their own pieces, and the dial a deciphered
            // range ships at.
            for dial in both_orders().into_iter().chain([STORED_CUT_CIPHER_DIAL]) {
                let range = &data[at..at + len];
                let mut serial = decryptor(7, 9);
                let mut front = data[..at].to_vec();
                let _ = serial.update(&mut front);
                let mut plain = range.to_vec();
                assert_eq!(serial.update(&mut plain).body, plain.len());

                let mut cut = decryptor(7, 9);
                let mut front = data[..at].to_vec();
                let _ = cut.update(&mut front);
                let (pieces, chain) = cut.pieces(256 * 1024).expect("AES-CBC, nothing carried");
                let cipher = Cipher {
                    pieces,
                    chain,
                    packed_crc: true,
                    page_plain: false,
                };
                let plan = Plan {
                    workers,
                    piece: (1024 * 1024 / workers) & !4095,
                };
                let r = Range {
                    source: Arc::clone(&source),
                    at: at as u64,
                    len: len as u64,
                    plan,
                    window: 1024 * 1024,
                    before,
                };
                let mut out = Writes::default();
                let (mut crc, mut packed, mut seen) = (
                    crate::checksum::Crc32::new(),
                    crate::checksum::Crc32::new(),
                    0u64,
                );
                let mut cutter = Cutter::new(dial);
                let last = cutter
                    .deliver(&r, &[], Some(&mut out), before, Some(cipher), &mut |p| {
                        crc.append(p.crc, p.len);
                        packed.append(p.packed_crc, p.len);
                        seen += p.len;
                        Ok(())
                    })
                    .unwrap_or_else(|_| panic!("at {at} len {len} {dial:?}"));
                cutter.finish(Some(&mut out)).expect("finish");
                let case = format!("at {at} len {len} before {before} workers {workers} {dial:?}");
                assert_eq!(out.bytes, plain, "{case}");
                assert_eq!(seen, len as u64, "{case}");
                assert_eq!(crc.finish(), crate::checksum::crc32(&plain), "{case}");
                assert_eq!(
                    packed.finish(),
                    crate::checksum::crc32(range),
                    "{case}: the packed CRC is the ciphertext's"
                );
                // Every write but the first and the last is a whole piece
                // on a page.
                let size = out.calls.iter().map(|c| c.0).max().expect("writes");
                assert!(size.is_multiple_of(4096), "{case}: a piece of {size}");
                if dial == STORED_CUT_CIPHER_DIAL && len >= 1024 * 1024 {
                    // As shipped: the window over the ring, which is half
                    // of it off macOS and an eighth on it.
                    assert_eq!(size, 1024 * 1024 / CIPHER_RING, "{case}");
                }
                let inner = &out.calls[1..out.calls.len() - 1];
                assert!(
                    inner.iter().all(|c| *c == (size, true)),
                    "{case}: {:?}",
                    out.calls
                );
                assert!(
                    out.calls.len() <= len / size + 2,
                    "{case}: {} writes of {size}",
                    out.calls.len()
                );
                if before > 0 {
                    assert_eq!(
                        (before as usize + out.calls[0].0) % size,
                        0,
                        "{case}: the first write ends on a multiple of the piece"
                    );
                }
                cut.resume(last);
                let next = &data[at + len..at + len + 32];
                let (mut a, mut b) = (next.to_vec(), next.to_vec());
                let _ = serial.update(&mut a);
                let _ = cut.update(&mut b);
                assert_eq!(a, b, "{case}: the chain handed back is the serial one");
            }
        }
    }

    /// A source that ends inside a deciphered range delivers its whole
    /// blocks, in both orders, and names the byte it ended at; the partial
    /// block is never deciphered or written.
    #[test]
    fn a_short_source_under_a_cipher_delivers_whole_blocks_only() {
        let data = noise(3_000_000 + 9);
        let source: Arc<dyn RangeSource> = Arc::new(Bytes(data.clone()));
        for dial in both_orders() {
            let mut serial = decryptor(1, 2);
            let whole = data.len() & !15;
            let mut plain = data[..whole].to_vec();
            let _ = serial.update(&mut plain);
            let mut dec = decryptor(1, 2);
            let (pieces, chain) = dec.pieces(256 * 1024).expect("AES-CBC");
            let cipher = Cipher {
                pieces,
                chain,
                packed_crc: false,
                page_plain: false,
            };
            let r = Range {
                source: Arc::clone(&source),
                at: 0,
                len: 5_000_000 & !15,
                plan: PLAN,
                window: 0,
                before: 0,
            };
            let mut out = Writes::default();
            let mut seen = 0u64;
            let mut cutter = Cutter::new(dial);
            let outcome = cutter.deliver(&r, &[], Some(&mut out), 0, Some(cipher), &mut |p| {
                seen += p.len;
                Ok(())
            });
            assert!(
                matches!(outcome, Err(Stop::Short(end)) if end == data.len() as u64),
                "{dial:?}"
            );
            cutter.finish(Some(&mut out)).expect("finish");
            assert_eq!(seen, whole as u64, "{dial:?}");
            assert_eq!(out.bytes, plain, "{dial:?}");
        }
    }

    /// The stateless cut a writer's own thread makes: the range from where
    /// the writer stands, its tail written before it answers, so a second
    /// range of the member begins with one short write and is whole again.
    #[test]
    fn a_cut_here_leaves_nothing_behind_it() {
        let data = noise(5 * 512 * 1024 + 4321);
        let source: Arc<dyn RangeSource> = Arc::new(Bytes(data.clone()));
        let mut out = Writes::default();
        let mid = 1_300_003usize;
        let mut seen = 0u64;
        for (from, to) in [(0, mid), (mid, data.len())] {
            let r = Range {
                source: Arc::clone(&source),
                at: from as u64,
                len: (to - from) as u64,
                plan: PLAN,
                window: 0,
                before: from as u64,
            };
            assert!(cut_here(&mut out, r, &mut |p| {
                seen += p.len;
                Ok(())
            })
            .is_ok());
            assert_eq!(out.bytes.len(), to, "the range's tail is written");
        }
        assert_eq!(out.bytes, data);
        assert_eq!(seen, data.len() as u64);
        // The piece the cut ships at on THIS system: half the window on
        // macOS, 1 MiB elsewhere ([`STORED_CUT_DIAL`]), which is the whole
        // of this plan's window.
        let dial = stored_cut().unwrap_or(STORED_CUT_DIAL);
        let size = wide::slabs_of(PLAN, dial.piece).piece;
        let short = out.calls.iter().filter(|c| c.0 != size).count();
        assert!(short <= 3, "{:?}", out.calls);
        assert!(out.calls.iter().all(|c| c.0 != size || c.1));
    }

    /// The knob's words, for every hand-over that reads them.
    #[test]
    fn the_dial_reads_its_words() {
        let on = Some(Dial::default());
        let shipped = Dial {
            piece: Some(1 << 20),
            in_order: None,
        };
        assert_eq!(dial_of(None, on, shipped), on);
        assert_eq!(dial_of(None, None, shipped), None);
        assert_eq!(dial_of(Some("nonsense"), None, shipped), None);
        assert_eq!(dial_of(Some(" Off "), on, shipped), None);
        // On is the shipped dial where the default is off, and the
        // default where there is one: never a dial of its own.
        assert_eq!(dial_of(Some("1"), None, shipped), Some(shipped));
        assert_eq!(dial_of(Some("on"), on, shipped), on);
        assert_eq!(
            dial_of(Some("seq:2048"), None, shipped),
            Some(Dial {
                piece: Some(2048 * 1024),
                in_order: Some(true)
            })
        );
        assert_eq!(
            dial_of(Some("wide"), on, shipped),
            Some(Dial {
                piece: None,
                in_order: Some(false)
            })
        );
    }

    /// A named piece is the piece, inside the window and never under a page.
    #[test]
    fn a_named_piece_stays_inside_the_window() {
        let plan = Plan {
            workers: 16,
            piece: 512 * 1024,
        };
        assert_eq!(
            wide::slabs_of(plan, None),
            Plan {
                workers: 2,
                piece: 4 << 20
            }
        );
        assert_eq!(
            wide::slabs_of(plan, Some(1 << 20)),
            Plan {
                workers: 8,
                piece: 1 << 20
            }
        );
        assert_eq!(
            wide::slabs_of(plan, Some(64 << 20)),
            Plan {
                workers: 2,
                piece: 4 << 20
            }
        );
        let narrow = Plan {
            workers: 2,
            piece: 128 * 1024,
        };
        let cut = wide::slabs_of(narrow, None);
        assert!(cut.workers * cut.piece <= 2 * 128 * 1024);
        assert!(cut.piece.is_multiple_of(4096));
    }
}

/// THE WALK's own cut of a lone clear stored BLAKE2sp member, on Windows
/// (`read::extract`'s `hashed_cut`, 18 Oct 2026): the dial that cut is
/// taken at, or `None` where the walk leaves the member to the seam.
///
/// **What it is for.** On x86-64 the BLAKE2sp kernel is one thread, and a
/// stored member's stream lends nothing to a helper (`checksum::blake2sp`,
/// `beside`), so under the seam ONE source thread reads a 64 KiB piece,
/// hashes it and reads the next. Counted on a Windows desktop (a quiet box,
/// K=15, 18 Oct 2026): one stored member of 4 GiB under BLAKE2sp read 0.853
/// of the old engine, that one thread busy about 69 percent of the wall at
/// about 4.6 GB/s while the writer was busy 377 to 445 ms of 1,377. The
/// walk's cut ([`cut_hashed_here`]) gives the reader, the hasher and the
/// writer a thread each, as Linux and macOS ship it ([`B2SP_CUT_WALK`]):
/// the hash still runs on one core, but beside the read and the write
/// rather than between reads. Same bytes, same digest, same writes in the
/// same order, and the member is reported only once the hash has seen
/// every byte.
///
/// **Why the stored cut's own default does not decide it here.** That cut
/// is off on Windows ([`STORED_CUT_DEFAULT`]) for want of rows of a POOL
/// WORKER's member, whose writes the pool keeps on its own path there;
/// the walk's own member is another case. So on Windows the walk takes
/// [`STORED_CUT_DIAL`] where the stored cut has none BY DEFAULT, and a word
/// that names it (`RARKIT_STORED_CUT=0`) is the arrangement before, as on
/// every system. The pool is not moved: its hooks are set only where
/// [`stored_cut`] is on (`read::concurrent`).
#[cfg(windows)]
pub(crate) fn walk_hashed_cut() -> Option<Dial> {
    let cut = stored_cut();
    if cut.is_some() {
        return cut;
    }
    #[cfg(feature = "test-support")]
    if crate::probe::stored_cut().is_some() {
        return cut;
    }
    static NAMED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let named = *NAMED.get_or_init(|| crate::knob::reader_var(STORED_CUT_ENV).is_ok());
    walk_hashed_cut_of(cut, WALK_HASHED_CUT_ALONE, named)
}

/// [`walk_hashed_cut`] where the walk never cuts alone
/// ([`WALK_HASHED_CUT_ALONE`] is false): the stored cut's own dial, as the
/// walk asked it before Windows had this rule.
#[cfg(not(windows))]
#[inline(always)]
pub(crate) fn walk_hashed_cut() -> Option<Dial> {
    stored_cut()
}

/// [`walk_hashed_cut`]'s answer from the stored cut's own (`cut`), whether
/// the system's walk cuts alone (`alone`, [`WALK_HASHED_CUT_ALONE`]) and
/// whether a word names the stored cut (`named`).
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn walk_hashed_cut_of(cut: Option<Dial>, alone: bool, named: bool) -> Option<Dial> {
    if cut.is_some() || !alone || named {
        cut
    } else {
        Some(STORED_CUT_DIAL)
    }
}

/// Whether the walk cuts its own clear BLAKE2sp member where the stored
/// cut is off by default ([`walk_hashed_cut`]): on Windows alone, the one
/// system whose stored cut is off.
#[cfg_attr(not(windows), allow(dead_code))]
const WALK_HASHED_CUT_ALONE: bool = cfg!(windows);

#[cfg(test)]
mod walk_hashed_tests {
    use super::*;

    /// The dial THE WALK cuts its own clear stored BLAKE2sp member at
    /// (`walk_hashed_cut`): the stored cut's own where it has one; where it
    /// has none by default, the stored cut's shipped dial on a system whose
    /// walk cuts alone (Windows); and none where a word names the stored
    /// cut (`RARKIT_STORED_CUT=0` stays the arrangement before it). Pure:
    /// no thread, no memory.
    #[test]
    fn the_walk_cuts_its_hashed_member_alone_on_windows() {
        let named_dial = Dial {
            piece: Some(2 << 20),
            in_order: Some(true),
        };
        // The stored cut's own answer stands wherever it has one.
        for alone in [false, true] {
            for named in [false, true] {
                assert_eq!(
                    walk_hashed_cut_of(Some(named_dial), alone, named),
                    Some(named_dial)
                );
            }
        }
        // Off by default: the walk cuts alone where the system says so,
        // and never where a word named the stored cut off.
        assert_eq!(walk_hashed_cut_of(None, true, false), Some(STORED_CUT_DIAL));
        assert_eq!(walk_hashed_cut_of(None, true, true), None);
        assert_eq!(walk_hashed_cut_of(None, false, false), None);
        // Windows alone, where the stored cut has no rows of its own.
        assert_eq!(WALK_HASHED_CUT_ALONE, cfg!(windows));
        assert_eq!(STORED_CUT_DEFAULT, !cfg!(windows));
    }
}
