//! Everything on the way IN: finding an archive, the options a read
//! takes, the session that shares work between volumes, listing what an
//! archive holds, and getting the bytes out (API spec section 4).
//!
//! Section 4's shape is worth knowing before reading the rest. Where the
//! old surface had a type per family and seven ways to extract, there is
//! one [`Archive`], one [`Sink`], one [`Progress`] and one [`extract`];
//! a single file is a one-element set, and which family it is gets
//! detected rather than chosen.

use std::borrow::Cow;
use std::ops::Range;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

#[cfg(feature = "parallel")]
pub(crate) mod across;
#[cfg(feature = "parallel")]
pub(crate) mod ahead;
pub(crate) mod archive;
pub(crate) mod block;
#[cfg(feature = "parallel")]
pub(crate) mod concurrent;
pub(crate) mod cursor;
pub(crate) mod detect;
pub(crate) mod dostime;
pub(crate) mod extract;
// A stored member's range handed to the delivering thread; see its module doc.
#[cfg(feature = "parallel")]
pub(crate) mod handed;
pub(crate) mod htime;
// The bound on volumes opened ahead of the pool's workers; see its module
// doc. Only the pool forwards fragments.
#[cfg(feature = "parallel")]
pub(crate) mod forwarded;
// Every use of the budget is behind `parallel`, and without it a build
// has one member decoding at a time and no ceiling to divide.
#[cfg(feature = "parallel")]
pub(crate) mod lanes;
pub(crate) mod name4;
pub(crate) mod rar13;
pub(crate) mod rar4;
pub(crate) mod rar5;
pub(crate) mod reader;
#[cfg(feature = "parallel")]
pub(crate) mod seam;
#[cfg(feature = "parallel")]
pub(crate) mod sequential;
#[cfg(feature = "parallel")]
pub(crate) mod spin;
#[cfg(feature = "parallel")]
pub(crate) mod team;
pub(crate) mod vint;
pub(crate) mod walk;
// The wide verify of one stored member; see its module doc.
#[cfg(feature = "parallel")]
pub(crate) mod wide;

use crate::memory::MemoryPolicy;
use crate::source::{RangeSource, Volumes};
use crate::types::{Checksum, HostOs, Method, Password, Timestamp};
use crate::{Error, ErrorKind, Result};

/// Which RAR format an archive is, as its signature and headers say.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Format {
    /// RAR 1.3 and 1.4, which are a different container rather than an
    /// older dialect of the rest.
    Rar13,
    /// RAR 1.5, the first of the container that runs through to
    /// RAR 4.x.
    Rar15,
    /// RAR 2.0, which has its own LZ codec.
    Rar20,
    /// RAR 2.9, 3.x and 4.x, which share one container and are treated
    /// as one family throughout.
    Rar4Family,
    /// RAR 5, the current format.
    Rar5,
}

/// An archive signature [`detect`] found, and where it was.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Found {
    /// Which format that signature belongs to.
    pub format: Format,
    /// How far into the source it sits. Non-zero means something comes
    /// first, most often a self-extracting stub.
    pub start: u64,
}

/// The default for [`ReadOptions::sfx_scan`]: 4,194,282, the last offset
/// at which the reference programs find a `Rar!` signature (spec F 3.1.2
/// and question 2, found by probing; a signature that starts one byte
/// later they do not find).
///
/// So the default search finds every archive the reference finds behind a
/// self-extracting stub or any other prefix. A caller whose source blocks
/// at a download frontier may ask for less, and `0` means "the archive
/// starts at byte 0". On a file that holds no signature the search reads
/// this many bytes once, in 4 KiB reads, into one fixed buffer.
pub const DEFAULT_SFX_SCAN: u64 = 4_194_282;

/// Find the first archive signature in `src`, looking no further than
/// `sfx_scan` bytes in.
///
/// Nothing is allocated, and no more than `sfx_scan` bytes plus the
/// length of one signature is read, so this is cheap enough to run
/// against a source that blocks. Finding nothing within range is
/// `Ok(None)` and not an error: "this file is not a RAR" is an answer,
/// not a failure.
pub fn detect(src: &dyn RangeSource, sfx_scan: u64) -> Result<Option<Found>> {
    detect::detect_in(src, sfx_scan)
}

/// Which check a split member has to pass.
///
/// The format offers exactly two checks on a split member: every fragment
/// header but the last carries the CRC32 of that fragment's PACKED bytes,
/// and the last carries the CRC32 of the WHOLE unpacked member. Neither
/// variant ever re-reads an earlier volume.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SplitCheck {
    /// Everything [`SplitCheck::Streaming`] does, and additionally refuses
    /// a set in which a leading fragment header carries no checksum field
    /// at all.
    Strict,
    /// Check each fragment's packed CRC32 as that fragment is consumed and
    /// the whole-member checksum when the last fragment is reached,
    /// holding nothing and re-reading nothing. A bad volume is named at
    /// the end of THAT volume rather than at the end of the set.
    #[default]
    Streaming,
}

/// What every way in takes: one options type for detection, listing and
/// extraction alike.
///
/// **`non_exhaustive`, since 21 Sep 2026.** Three API changes in
/// one week each added a field here - the read width (8.4.2), the sink
/// hint (8.5) and the seam width - and a caller that built this by
/// struct literal broke on every one of them, whether or not it wrote
/// `..Default::default()`. So this struct cannot be built by literal
/// from outside the crate at all. A caller starts from
/// [`ReadOptions::default()`](Default::default) and names only what it
/// wants, either through the `with_` setters below, which chain:
///
/// ```
/// use rarkit::ReadOptions;
/// let opts = ReadOptions::default().with_sfx_scan(0).with_tolerant_tail(true);
/// ```
///
/// or by assigning the public fields, which stay public and stay
/// writable. Prefer the chain for a value you are building here:
/// assigning a field straight onto a fresh `default()` is what clippy's
/// `field_reassign_with_default` is about, and this crate's own gate
/// runs clippy with `-D warnings`. Assignment earns its keep on options
/// a caller already holds:
///
/// ```
/// use rarkit::ReadOptions;
/// fn scan_from_the_first_byte(opts: &mut ReadOptions) {
///     opts.sfx_scan = 0;
/// }
/// ```
///
/// Adding a field is then a compatible change for every caller that did
/// not want it. What no longer compiles downstream is the literal, in
/// either of its forms:
///
/// ```compile_fail
/// use rarkit::ReadOptions;
/// // error[E0639]: cannot create non-exhaustive struct using functional
/// // update syntax
/// let opts = ReadOptions { sfx_scan: 0, ..ReadOptions::default() };
/// ```
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ReadOptions {
    /// The password, for an archive whose members or headers need one.
    pub password: Option<Password>,
    /// What a read is allowed to hold at once (section 8).
    pub memory: MemoryPolicy,
    /// How far in to look for the signature. Set it to 0 to say the
    /// archive begins at the first byte and skip the search entirely.
    pub sfx_scan: u64,
    /// Which of the two checks on a split member to insist on.
    pub split_check: SplitCheck,
    /// Whether [`Archive::open`] keeps the members it parsed when the walk
    /// cannot reach the end of the volume.
    ///
    /// Off by default, which is spec F 4.6 and 3.5.5 as written: a source
    /// that ends inside a header or a data area is
    /// [`ErrorKind::Truncated`](crate::ErrorKind::Truncated) and a header
    /// whose own checksum fails is
    /// [`ErrorKind::HeaderChecksum`](crate::ErrorKind::HeaderChecksum), and
    /// either ends the open.
    ///
    /// On, the walk stops at the same place and for the same reason, but
    /// the members already parsed are kept and the reason is reported
    /// through [`Archive::tail`] instead of being returned. Nothing is
    /// parsed more permissively and no damaged header is used: 4.6 requires
    /// that members ahead of the damage stay valid, and this is the option
    /// that hands them to a caller. It is what a listing wants - reference
    /// `unrar l` on an archive whose last member runs past the end of the
    /// file lists the member, prints `Unexpected end of archive` and exits
    /// 1 - and it changes nothing about extraction, where the member still
    /// fails on its own bytes.
    pub tolerant_tail: bool,
    /// Whether a read goes on THROUGH a header whose checksum failed, as
    /// spec F 4.6 has it, and looks for the loss a locator shows.
    ///
    /// Off by default: a header whose own checksum fails then ends the
    /// walk with [`ErrorKind::HeaderChecksum`](crate::ErrorKind::HeaderChecksum).
    /// On, measured against unrar 7.23 on 8 Oct 2026:
    ///
    /// - A clear RAR 5 or RAR 1.5 to 4.x header whose checksum fails is
    ///   REPORTED and still READ, every field under the bounds a sound
    ///   header's fields are held to, and the walk goes on by its sizes
    ///   (4.6 rules 1 to 3). [`Archive::damaged_headers`] names each one,
    ///   and a run that met one is never a success. A header that is
    ///   ENCIPHERED is never read so: there a failed checksum is a wrong
    ///   key.
    /// - A member under such a header is good only by its own data
    ///   checksum. With one that matches it is delivered and good; with
    ///   one that does not it fails; with NONE it fails
    ///   ([`MemberOutcome::checksum_ok`] is `Some(false)`): nothing
    ///   vouches for it (4.6 rule 4).
    /// - Where a RAR 5 FILE header's checksum fails and the volume's quick
    ///   open record holds a copy of the header at that very offset whose
    ///   entry checksum and whose own header checksum both hold, the
    ///   copy's fields are read in its place. The header is reported all
    ///   the same ([`DamagedHeader::from_copy`]). The record is read for
    ///   nothing else: a header that is sound is never answered from a
    ///   copy (3.2.9.1, section 8 item 7).
    /// - A RAR 5 volume whose sound main header's locator names a quick
    ///   open record, and which holds no sound `QO` header at that offset
    ///   (it ends before it, or something else stands there), has lost
    ///   its tail: the walk is made, and the volume is then
    ///   [`ErrorKind::Truncated`](crate::ErrorKind::Truncated) (3.2.8
    ///   rule 2). The locator of a main header whose own checksum failed
    ///   is not used.
    /// - Damage behind the data of a volume's LAST member that stops the
    ///   walk there (a source cut inside the trailing records), where
    ///   that member's own header says it continues in the next volume,
    ///   is not an error: the volume has said everything the walk needs.
    ///
    /// Each costs a sound archive nothing: they are reached only from a
    /// failed checksum, from an error, or at the end of a volume.
    pub read_damaged: bool,
    /// A flag another thread may raise to stop the operation.
    ///
    /// It is read at every block boundary and at least once per 1 MiB
    /// produced, so the response is prompt without costing a check per
    /// byte. A raised flag ends the run as
    /// [`Cancelled`](crate::ErrorKind::Cancelled).
    pub cancel: Option<Arc<AtomicBool>>,
    /// The read side's THREAD width (section 8.4.2), mirroring
    /// [`WriteOptions::workers`](crate::WriteOptions::workers).
    ///
    /// A plain CPU figure, derived from no memory budget. It bounds the
    /// engine's own decode threads: the lanes of a RAR 5 tape decode
    /// inside one member, and the members of a non-solid set decoded at
    /// once, which together are section 8.3's breadth times width product.
    ///
    /// It is a CEILING and never a demand: a stage that runs narrower, or
    /// never threads at all, is in contract (8.2). It is not a memory
    /// figure either, and it cannot buy memory:
    /// [`MemoryPolicy::working_limit`](crate::MemoryPolicy::working_limit)
    /// is a hard ceiling at any width and lowers the width wherever the
    /// bytes force it (8.4.1, 8.4.2).
    ///
    /// `None` is the engine's own default, which is [`Self::read_width`],
    /// and does NOT mean unbounded. `Some(0)` is
    /// [`LimitExceeded`](crate::ErrorKind::LimitExceeded) with
    /// [`Resource::Workers`](crate::Resource::Workers), the same refusal
    /// [`extract_parallel`] gives a breadth of zero, rather than a silent
    /// one.
    pub workers: Option<usize>,
    /// A cost class for the one-member seam (section 8.5), and nothing
    /// else.
    ///
    /// The seam overlaps one member's read, its decrypt, its decode and
    /// its checksum with the write to the caller's writer. Whether that
    /// pays depends on what the WRITER costs, and the engine cannot see
    /// past the `Write` trait object to find out. The ladder that priced
    /// it found the SIGN of the seam's cost turning with the sink rather
    /// than with the member's size: to a real file the seam was ahead at
    /// every rung from 64 MiB to 2 GiB, and to an in-memory `Vec` it was
    /// behind by 8 to 12 percent at every rung up to 512 MiB. This is how
    /// a caller that knows which it has says so.
    ///
    /// - `None` is the default, and is the behaviour of every build
    ///   before this field existed: the engine's measured size floor
    ///   decides on its own.
    /// - `Some(true)` says the writer is backed by a real file, and the
    ///   seam engages whatever the member's size.
    /// - `Some(false)` says the writer is in memory, and keeps the seam
    ///   OFF below the size floor. Above the floor it falls back to the
    ///   floor's own answer rather than forcing the seam off, so the
    ///   field can only ever move the threshold the ladder measured and
    ///   never contradict a later measurement above it.
    ///
    /// **It is a COST CLASS and not a promise about what the sink is.**
    /// The engine never verifies it, and a caller that sets it wrongly
    /// gets a correct member and a worse wall, never an error: the bytes,
    /// the verdict, the order of the [`Sink`](crate::Sink) calls and the
    /// memory accounting are all what they would have been without it.
    /// It buys no thread and no byte either - the seam's thread comes out
    /// of [`Self::workers`] and its ring out of
    /// [`MemoryPolicy::read_ahead`](crate::MemoryPolicy::read_ahead) - so
    /// a policy with no room for a ring runs the member in sequence with
    /// `Some(true)` set, and that is not an error. Without the `parallel`
    /// feature there is no seam and the field does nothing at all.
    pub sink_is_file: Option<bool>,
    /// Whether every volume the provider will be asked for is ALREADY
    /// PRESENT, so that being asked for volume `k + 1` early costs the
    /// caller nothing: a set of files on disk, or of buffers in memory.
    ///
    /// `false` is the default, and is the one-pass promise of API section
    /// 5.3 kept to the letter: the engine asks for volume `k + 1` only
    /// after the last member byte it needs from volume `k` has been
    /// delivered, so a provider that BLOCKS until a volume arrives (a
    /// downloader) never has `k`'s last bytes wait on `k + 1`.
    ///
    /// `true` lets the engine ask for volume `k + 1` while the last
    /// `read_ahead` bytes of volume `k` are still being read and joined
    /// (spec F 3.7.2), which is what keeps the readers of a stored member
    /// posted in small volumes busy across each volume's end
    /// (`read::across`). Nothing else moves: the bytes, the verdicts, the
    /// order of the [`Sink`](crate::Sink) calls, the read-ahead bound and
    /// the drop-behind reports are what they are without it. Like
    /// [`Self::sink_is_file`] it is never verified: set wrongly, the
    /// member is still correct, and its last bytes in each volume wait for
    /// the next volume to arrive. Without the `parallel` feature it does
    /// nothing.
    pub volumes_present: bool,

    /// How many FURTHER writers [`extract_parallel`] may hold open whose
    /// member has finished decoding and only waits its turn to `close`
    /// (SPEC-API section 4, "Outputs open at once"). `None`, the default,
    /// is the standard bound exactly: a sink holds at most twice the
    /// breadth of writers open at once. `Some(n)` is the caller saying its
    /// finished writers are cheap to hold: the writers still being
    /// written stay within twice the breadth, and up to `n` more may be
    /// open that are only waiting, in archive order, to be closed. Read by
    /// [`extract_parallel`] only, and only where the pool queues the
    /// walk's own members (`RARKIT_QUEUE_OWN`).
    pub waiting_outputs: Option<usize>,
    /// Whether [`extract`]'s caller writes each member to a FILE, in
    /// order, as it is handed over. Members are then taken AHEAD of the
    /// one being written only while the sizes they declare fit a ceiling
    /// of 1,024 MiB, or
    /// [`MemoryPolicy::working_limit`](crate::MemoryPolicy) itself where
    /// that is smaller (a named budget, a cap of the environment or a
    /// small machine); a member larger than the ceiling is decoded in its
    /// turn. A member the engine's own window already holds (one that
    /// barely packs, at a read width under 18) is left to that window and
    /// is not counted against the ceiling. `false`, the default, leaves the
    /// members ahead bounded by the working limit alone, as they were.
    ///
    /// Counted 11 Oct 2026, six members of 320 MiB written to a drive, on
    /// an Apple M1 Ultra (20 threads) and an AMD EPYC 4345P (16 threads):
    /// 1,277 to 1,847 MB held without it and 157 to 906 MB with it, the
    /// wall 0.99 to 1.17 of what it was on every row. Never verified: set
    /// wrongly, every byte and verdict is what it was. Read by [`extract`]
    /// only.
    ///
    /// NOT YET PART OF THE STATED API (hidden from the documentation):
    /// its SPEC-API entry is not written yet.
    #[doc(hidden)]
    pub files_in_order: bool,
    /// Whether [`extract`] and [`extract_parallel`] select the OLDER
    /// VERSIONS of files an archive keeps
    /// ([`MemberInfo::file_version`]). `false`, the default, is what the
    /// reference does without its `-ver` switch: such a member is passed
    /// over, the sink is never shown it, and only the current file of each
    /// name is extracted. `true` hands every member to the sink, which
    /// names a version by [`MemberInfo::versioned_name`]. Listing is not
    /// affected: [`Archive::members`] holds every member either way.
    pub versions: bool,
}

impl ReadOptions {
    /// Set [`Self::versions`] and return the options.
    pub fn with_versions(mut self, versions: bool) -> Self {
        self.versions = versions;
        self
    }

    /// Set [`Self::password`] and return the options, for chaining from
    /// [`ReadOptions::default()`](Default::default).
    pub fn with_password(mut self, password: Option<Password>) -> Self {
        self.password = password;
        self
    }

    /// Set [`Self::memory`] and return the options.
    pub fn with_memory(mut self, memory: MemoryPolicy) -> Self {
        self.memory = memory;
        self
    }

    /// Set [`Self::sfx_scan`] and return the options.
    pub fn with_sfx_scan(mut self, sfx_scan: u64) -> Self {
        self.sfx_scan = sfx_scan;
        self
    }

    /// Set [`Self::split_check`] and return the options.
    pub fn with_split_check(mut self, split_check: SplitCheck) -> Self {
        self.split_check = split_check;
        self
    }

    /// Set [`Self::tolerant_tail`] and return the options.
    pub fn with_tolerant_tail(mut self, tolerant_tail: bool) -> Self {
        self.tolerant_tail = tolerant_tail;
        self
    }

    /// Set [`Self::read_damaged`] and return the options.
    pub fn with_read_damaged(mut self, read_damaged: bool) -> Self {
        self.read_damaged = read_damaged;
        self
    }

    /// Set [`Self::cancel`] and return the options.
    pub fn with_cancel(mut self, cancel: Option<Arc<AtomicBool>>) -> Self {
        self.cancel = cancel;
        self
    }

    /// Set [`Self::workers`] and return the options.
    ///
    /// A `Some(0)` is not refused here: the entry points refuse it by
    /// name when the read starts (8.4.4 test 6), which is where the
    /// error belongs.
    pub fn with_workers(mut self, workers: Option<usize>) -> Self {
        self.workers = workers;
        self
    }

    /// Set [`Self::volumes_present`] and return the options.
    pub fn with_volumes_present(mut self, volumes_present: bool) -> Self {
        self.volumes_present = volumes_present;
        self
    }

    /// Set [`Self::waiting_outputs`] and return the options.
    pub fn with_waiting_outputs(mut self, waiting_outputs: Option<usize>) -> Self {
        self.waiting_outputs = waiting_outputs;
        self
    }

    /// Set [`Self::files_in_order`] and return the options.
    #[doc(hidden)]
    pub fn with_files_in_order(mut self, files_in_order: bool) -> Self {
        self.files_in_order = files_in_order;
        self
    }

    /// Set [`Self::sink_is_file`] and return the options.
    pub fn with_sink_is_file(mut self, sink_is_file: Option<bool>) -> Self {
        self.sink_is_file = sink_is_file;
        self
    }

    /// The width this read will actually run at (section 8.4.3).
    ///
    /// `Some(n)` is taken exactly, which is what lets a caller ask for
    /// more threads than any memory-derived figure would have allowed.
    /// `None` resolves to `min(the engine's own read ceiling, the width of
    /// the pool the caller owns)`.
    ///
    /// **and the engine's own read ceiling is PROVISIONAL**: 8.4.3 says it
    /// is a MEASURED constant, whichever width measures the lowest wall
    /// inside the caller's memory ceiling, and names the measurement that must
    /// fill it in. Until that measurement runs, the figure that ships is the
    /// one the measurement in hand supports and no more - no engine
    /// ceiling below the width of the pool the caller owns - so this
    /// resolves to the pool's width. The pool is the caller's (8.3) and is
    /// never resized or read from the environment here; where the engine
    /// decodes on its own scoped lanes instead, the pool's width is read
    /// as the caller's declared budget of threads and nothing more.
    ///
    /// A zero is lifted to one rather than refused here, because the
    /// entry points refuse it by name before anything reaches this.
    ///
    /// **One side effect a caller building its own pool should know.**
    /// Reading the pool's width asks `rayon`, which BUILDS the process's
    /// global pool at the default width if the caller has not built one,
    /// and a pool that exists cannot then be built again. A caller that
    /// wants a pool of its own size builds it before its first read, which
    /// is what `rarkit-cli` does; a caller that never builds one gets
    /// rayon's own default and nothing here resizes it. The encoder's
    /// width already reads the pool the same way (API 7.2). Setting
    /// `workers` explicitly asks rayon nothing at all.
    pub fn read_width(&self) -> usize {
        match self.workers {
            Some(n) => n.max(1),
            None => pool_width(),
        }
    }

    /// `Some(0)` refused by name, for the entry points to call before they
    /// spend anything (8.4.4 test 6).
    pub(crate) fn refuse_no_workers(&self) -> Result<()> {
        if self.workers == Some(0) {
            return Err(Error::new(ErrorKind::LimitExceeded {
                resource: crate::Resource::Workers,
                needed: 1,
                limit: 0,
            }));
        }
        Ok(())
    }
}

/// The width of the pool the caller owns.
///
/// Without the `parallel` feature there is no pool and no thread: one.
#[cfg(feature = "parallel")]
pub(crate) fn pool_width() -> usize {
    rayon::current_num_threads().max(1)
}
#[cfg(not(feature = "parallel"))]
pub(crate) fn pool_width() -> usize {
    1
}

impl Default for ReadOptions {
    fn default() -> Self {
        ReadOptions {
            password: None,
            memory: MemoryPolicy::default(),
            sfx_scan: DEFAULT_SFX_SCAN,
            split_check: SplitCheck::default(),
            tolerant_tail: false,
            read_damaged: false,
            cancel: None,
            workers: None,
            sink_is_file: None,
            volumes_present: false,
            waiting_outputs: None,
            files_in_order: false,
            versions: false,
        }
    }
}

pub use archive::Archive;

impl Archive {
    /// Read one volume's headers, using a [`Session`] made for this call
    /// and dropped after it. Opening several volumes is better done
    /// through a session the caller keeps.
    pub fn open(src: Arc<dyn RangeSource>, opts: &ReadOptions) -> Result<Archive> {
        archive::open_archive(src, opts)
    }

    /// As [`Archive::open`], but from a path this crate opens itself.
    ///
    /// One of only two places in the crate that touches the filesystem
    /// (section 1), and it only opens and reads.
    pub fn open_path(path: &Path, opts: &ReadOptions) -> Result<Archive> {
        let mut ctx = reader::ReadCtx::new(opts.clone());
        archive::open_archive_path(path, &mut ctx)
    }
}

/// A read's options together with the work its volumes have in common,
/// so that the work happens once instead of per volume.
///
/// What is shared is worth being concrete about, because it is where the
/// time goes: the derived keys, at one key derivation per distinct salt
/// and password rather than one per volume, and the pattern the set's
/// volume names follow. Key derivation is deliberately expensive, so on
/// an encrypted set this is the difference between one cost and N.
///
/// It holds mutable caches, so it is `Send` and not `Sync`: keep one per
/// thread rather than sharing one.
pub struct Session {
    ctx: reader::ReadCtx,
}

impl Session {
    /// Start a session that will read with `options`.
    pub fn new(options: ReadOptions) -> Session {
        Session {
            ctx: reader::ReadCtx::new(options),
        }
    }

    /// The options the session reads with.
    pub fn options(&self) -> &ReadOptions {
        &self.ctx.options
    }

    /// Read one volume's headers from `src`, waiting on the source for as
    /// long as it needs to.
    pub fn open(&mut self, src: Arc<dyn RangeSource>) -> Result<Archive> {
        Archive::open_with(src, &mut self.ctx)
    }

    /// As [`Session::open`], from a path this crate opens itself.
    pub fn open_path(&mut self, path: &Path) -> Result<Archive> {
        archive::open_archive_path(path, &mut self.ctx)
    }

    /// Extract, reusing the session's derived keys. Takes a single
    /// archive, a complete set, or a set whose volumes are still turning
    /// up; see [`extract`] for the whole of it.
    pub fn extract<V: Volumes, K: Sink, P: Progress>(
        &mut self,
        volumes: V,
        sink: &mut K,
        progress: &mut P,
    ) -> Result<ExtractReport> {
        let mut sink = CurrentFilesMut::over(sink, self.ctx.options.versions);
        metered(|| extract::extract_with(volumes, &mut self.ctx, &mut sink, progress))
    }

    /// As [`extract_parallel`], reusing the session's derived keys, so
    /// that a set the session has already opened is not keyed a second
    /// time. Reads with the session's options; everything else, the
    /// breadth, cancellation, error order and the per-member output, is
    /// [`extract_parallel`]'s.
    #[cfg(feature = "parallel")]
    pub fn extract_parallel<V: Volumes, S: ParallelSink>(
        &mut self,
        volumes: V,
        sink: &S,
        workers: usize,
    ) -> Result<ExtractReport> {
        let sink = CurrentFiles::over(sink, self.ctx.options.versions);
        metered(|| concurrent::extract_parallel_in(volumes, &mut self.ctx, &sink, workers))
    }
}

/// What this archive is within its volume set, answered the same way for
/// both families.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VolumeInfo {
    /// Whether this is part of a set at all, rather than a lone archive.
    pub is_volume: bool,
    /// Which volume it is, where the format troubles to record that.
    pub number: Option<u32>,
    /// Whether this is the set's first volume.
    pub is_first: bool,
    /// Whether another volume follows. `None` where the format has no
    /// way to say, which is not the same as `Some(false)`.
    pub next_follows: Option<bool>,
}

/// One member, as listing reports it.
///
/// The name borrows the archive's own arena rather than copying, which
/// is how promise 4 of section 2 holds: listing N members allocates O(1)
/// times, not N.
#[derive(Clone, Debug)]
pub struct MemberInfo<'a> {
    /// The name, in bytes, after undoing whatever encoding the format
    /// stored it in. Not decoded to text: see [`MemberInfo::name_lossy`]
    /// for that, and section 1 on why path policy is the caller's.
    ///
    /// The path separator is a forward slash whatever the format is. RAR
    /// 1.3 through RAR 4 store a backslash between components whatever the
    /// host OS is, and the reader converts it, so one caller rule works for
    /// every format; RAR 5 names are already forward-slashed and are left
    /// alone. The untouched bytes stay reachable through
    /// [`Archive::blocks`] and the source (spec F question 3).
    ///
    /// Nothing here rejects a name, normalises `..`, or decides where a
    /// file goes: that is the caller's policy.
    pub name: &'a [u8],
    /// Whether the entry is a directory rather than a file.
    pub is_directory: bool,
    /// How large the member is when decoded, where the format records
    /// it at all.
    pub unpacked_size: Option<u64>,
    /// How many stored bytes of this member are in THIS volume, which
    /// for a split member is not the whole of it.
    pub packed_size: u64,
    /// Whether this is the continuation of a member begun earlier in
    /// the set.
    pub split_before: bool,
    /// Whether the member runs on into the volume after this one.
    pub split_after: bool,
    /// Whether the stored bytes are enciphered.
    pub encrypted: bool,
    /// Whether the member carries a password CHECK RECORD, which the reader
    /// judges before the member's first byte (spec K 3.7.3): a wrong
    /// password is then `WrongPassword`, and a checksum that fails after
    /// it passed is damage. Only a RAR 5 member can carry one; for an
    /// encrypted member without one (the RAR 1.3 to 4.x family, or a RAR
    /// 5 record whose flag 0x0001 is clear) a failed checksum cannot tell
    /// a wrong password from damage. `false` for an unencrypted member.
    pub password_checked: bool,
    /// When the member was last modified, where the header records it.
    pub mtime: Option<Timestamp>,
    /// The attribute word as stored, to be read according to
    /// `host_os`.
    pub attributes: u32,
    /// The system the header claims wrote this.
    pub host_os: HostOs,
    /// The check value the header carries over the content, where it
    /// carries one.
    pub checksum: Option<Checksum>,
    /// How the bytes were stored, with the window a decoder will need.
    pub method: Method,
    /// The dictionary size the header declares, whatever the method.
    ///
    /// A STORED member declares one too: RAR 5 packs the dictionary bits
    /// into the same compression-information vint as the method (spec F
    /// 3.2.6), the RAR 1.5 to 4.x family keeps them in the file flags
    /// (3.3.6), and the RAR 1.3 container's is a fixed 64 KiB (3.4.2). It
    /// is the same value [`Method::Compressed`] carries for a compressed
    /// member, read from the same field, so the two cannot disagree.
    ///
    /// `None` for a DIRECTORY entry in every generation. In the RAR 1.5 to
    /// 4.x family that is the format: the dictionary bits hold the value 7,
    /// which marks a directory and names no size (3.3.6). Measured against
    /// reference `unrar lt`, which prints no `-md=` clause for
    /// a directory of any generation and prints one for every other
    /// member, stored or compressed.
    pub dictionary: Option<u64>,
    /// The member continues the solid chain, as the header says.
    ///
    /// This is the stored per-member bit and nothing more: RAR 5's
    /// compression-information bit 6, the RAR 1.5 to 4.x family's file flag
    /// 0x0010 (spec F 3.6). Reference `unrar lt` prints its `Flags: solid`
    /// line from the same bit, and prints none on a genuine solid DOS RAR
    /// 1.55 archive, whose writer never sets it (measured on
    /// `fixtures/legacy/archives/d155_sol.rar`, 12 members, no line, and on
    /// `d250_sol.rar`, 8 of 12 with one).
    ///
    /// **It is not the whole chain rule.** For a member of unpack version
    /// 15 and below the bit is never written and the ARCHIVE's solid flag
    /// governs, so [`Archive::is_solid`] and archive order decide what
    /// continues a chain there (spec F 3.6's erratum). Extraction applies
    /// that rule itself; a caller reporting what a header holds wants this
    /// field.
    pub solid: bool,
    /// The algorithm version the header declares.
    ///
    /// The two families count it differently and the field carries each
    /// one exactly as stored: RAR 5's compression version, of which 0 is
    /// the only value this crate accepts (spec F question 9), and the RAR
    /// 1.5 to 4.x family's unpack version, which selects the decoder - 13,
    /// 14 and 15 for RAR 1.5, 20 and 26 for RAR 2.0, 29 and above for RAR
    /// 2.9 and later (3.3.5). The RAR 1.3 container declares 2 (3.4.2).
    pub algorithm_version: u32,
    /// Where this volume's stored bytes for the member sit in the
    /// source the caller supplied.
    pub data: Range<u64>,
    /// `Some` for a symbolic link, junction, hard link or file copy (spec
    /// F 3.2.6.2 and 3.3.12), `None` for every other member (SPEC-API
    /// question 21).
    ///
    /// For such a member the other fields mean what the header says and no
    /// more: `is_directory` is false even for a link to a directory (that
    /// is [`Redirection::target_is_directory`]); `unpacked_size` is the
    /// declared size, which for a hard link or a file copy is the TARGET's
    /// although no byte is decoded for it; `checksum` is the checksum of
    /// the empty string for RAR 5 and of the target bytes for the RAR 4
    /// family. [`extract`] never delivers such a member as bytes: see
    /// [`Sink`].
    pub redirection: Option<Redirection<'a>>,
    /// `Some` when the member is an OLDER VERSION of a file and not the
    /// file itself (spec F 3.2.6.4, 3.3.6): what `rar a -ver` keeps of a
    /// file each time it is added again. Several such members and the
    /// current file share one stored name. [`extract`] passes such a
    /// member over unless [`ReadOptions::versions`] is set, and a caller
    /// that writes one names it by [`MemberInfo::versioned_name`].
    pub file_version: Option<FileVersion>,
}

/// Which older version of a file a member is ([`MemberInfo::file_version`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileVersion {
    /// RAR 5: the number in the header's version record, 1 or more, the
    /// oldest version being 1. The stored name does not hold it.
    Numbered(u32),
    /// The RAR 1.5 to 4.x container: the header only flags the member as
    /// a version, and whatever number it has is part of the stored name
    /// (`b.txt;3`).
    InName,
}

impl MemberInfo<'_> {
    /// The name a listing shows and an extractor writes: the stored name,
    /// and for an older version of a file whose number the header holds
    /// apart from the name, the name followed by `;` and the number, as
    /// the reference does (`v.txt;1`).
    pub fn versioned_name(&self) -> Cow<'_, [u8]> {
        match self.file_version {
            Some(FileVersion::Numbered(number)) => {
                let mut name = self.name.to_vec();
                name.push(b';');
                name.extend_from_slice(number.to_string().as_bytes());
                Cow::Owned(name)
            }
            Some(FileVersion::InName) | None => Cow::Borrowed(self.name),
        }
    }

    /// The name as text, with anything that is not valid UTF-8 replaced
    /// rather than refused. For display; `name` is what was stored.
    pub fn name_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(self.name)
    }
}

/// What a redirection member points at (spec F 3.2.6.2, 3.3.12).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Redirection<'a> {
    /// Which kind of redirection it is.
    pub kind: RedirectionKind,
    /// The target exactly as stored, with no interpretation: the link's
    /// content for the three link kinds, an archive member name for
    /// [`RedirectionKind::HardLink`] and [`RedirectionKind::FileCopy`].
    ///
    /// `None` only in a LISTING of the RAR 4 family, whose link target is
    /// the member's content (3.3.12). At [`Sink::open`] it is always
    /// `Some`: the engine has decoded that content and checked it first.
    pub target: Option<&'a [u8]>,
    /// RAR 5's directory flag (record flag 0x0001): the link points at a
    /// directory. It does not make the member a directory. Always false
    /// for the RAR 4 family, which has no such flag.
    pub target_is_directory: bool,
}

/// The kinds of redirection a member can be (spec F 3.2.6.2).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum RedirectionKind {
    /// RAR 5 type 1, and the RAR 4 family's only kind.
    PosixSymlink,
    /// RAR 5 type 2.
    NtSymlink,
    /// RAR 5 type 3, an NTFS directory mount point.
    NtJunction,
    /// RAR 5 type 4; the target is an earlier member's name.
    HardLink,
    /// RAR 5 type 5; the target is an earlier member's name, whose bytes
    /// are this member's.
    FileCopy,
    /// Any other type, 0 included: carried rather than refused, so a
    /// listing can show it and a caller can name it when it declines the
    /// member (spec F 3.8.6).
    Unknown(u64),
}

impl RedirectionKind {
    /// The kind for a RAR 5 record's type field.
    pub(crate) fn from_rar5(code: u64) -> RedirectionKind {
        match code {
            1 => RedirectionKind::PosixSymlink,
            2 => RedirectionKind::NtSymlink,
            3 => RedirectionKind::NtJunction,
            4 => RedirectionKind::HardLink,
            5 => RedirectionKind::FileCopy,
            other => RedirectionKind::Unknown(other),
        }
    }

    /// The words reference `unrar lt` prints on a redirection member's
    /// `Type:` line, and `unknown redirection n` for a type it does not
    /// name (SPEC-API 4.3).
    pub fn listing_name(&self) -> Cow<'static, str> {
        match self {
            RedirectionKind::PosixSymlink => Cow::Borrowed("Unix symbolic link"),
            RedirectionKind::NtSymlink => Cow::Borrowed("Windows symbolic link"),
            RedirectionKind::NtJunction => Cow::Borrowed("NTFS junction point"),
            RedirectionKind::HardLink => Cow::Borrowed("Hard link"),
            RedirectionKind::FileCopy => Cow::Borrowed("File reference"),
            RedirectionKind::Unknown(n) => Cow::Owned(format!("unknown redirection {n}")),
        }
    }
}

/// One service record of an archive: a `CMT`, `QO`, `RR` or other service
/// header, which is NOT a member.
///
/// A service block never appears in [`Archive::members`] and `extract`
/// never hands one to a [`Sink`] (spec F 3.2.9). It is listed here and in
/// [`Archive::blocks`], because a technical listing names it: reference
/// `unrar lta` prints a `QO` and an `RR` entry with a size, a packed size
/// and a compression clause of their own, and for the recovery record a
/// percentage.
///
/// A service header has the SAME field layout as a file header, which is
/// why its fields arrive as a [`MemberInfo`]: `header.name` is the service
/// name (`CMT`, `QO`, `RR`), and the sizes, host OS, checksum, method and
/// dictionary are that header's own.
#[derive(Clone, Debug)]
pub struct ServiceInfo<'a> {
    /// Which service this is.
    pub kind: ServiceKind,
    /// The header's fields, in the shape a file header's take.
    pub header: MemberInfo<'a>,
    /// How many members of [`Archive::members`] come before this record,
    /// so a caller can list members and services in archive order.
    pub before_member: u32,
    /// The recovery percentage the archive was written with, from the `RR`
    /// record's own extra record of type 7, which holds it as a vint (spec
    /// L 3.5.1; the reference stores 1 to 1,000 as given); `None` on every
    /// other service and on a record that carries none.
    pub recovery_percent: Option<u32>,
}

/// One block of the archive, as [`Archive::blocks`] walks them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockInfo {
    /// Which kind of block it is.
    pub kind: BlockKind,
    /// The extent it occupies in the source.
    pub range: Range<u64>,
}

/// How many entries [`Archive::damaged_headers`] keeps for one volume:
/// the first ones. The table is a report, and a volume made of nothing
/// but such headers must not be able to grow it without bound.
pub const DAMAGED_HEADERS_KEPT: usize = 256;

/// A header that was read although its own checksum failed
/// ([`ReadOptions::read_damaged`], [`Archive::damaged_headers`]).
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct DamagedHeader {
    /// Which kind of block the header says it is.
    pub kind: BlockKind,
    /// The extent the header occupies in the source.
    pub range: Range<u64>,
    /// For a member's header, that member's index in
    /// [`Archive::members`]. `None` for every other block, and for a
    /// member header the open went on to refuse.
    pub member: Option<usize>,
    /// The quick open record held a sound copy of this header and the
    /// copy's fields were read in its place (spec F 3.2.9.1). The header
    /// is reported all the same.
    pub from_copy: bool,
}

/// What a block is, in terms both families share.
///
/// Section 4.3 is deliberate about this: the families' header layouts
/// differ, and this enum is the only thing about that difference a
/// caller sees.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockKind {
    /// The archive's own header, which carries its flags.
    Main,
    /// A member's header.
    File,
    /// A service block, which carries something about the archive rather
    /// than a member.
    Service(ServiceKind),
    /// The record that closes the archive.
    End,
    /// A type none of the above names, carried through as the byte it
    /// was.
    Other(u64),
}

/// Which service a service block performs, in terms both families
/// share.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceKind {
    /// Repair data for this volume.
    RecoveryRecord,
    /// The archive's comment.
    Comment,
    /// A service this crate does not distinguish.
    Other,
}

/// The caller's side of an extraction: where each member's bytes go,
/// and what to do about each member at all.
///
/// Both methods run on the thread that called [`extract`], so an
/// implementation need not be thread-safe. The parallel form asks for
/// [`ParallelSink`] instead, which does.
///
/// **A redirection member is never delivered as bytes** (spec F 3.8.1).
/// Its [`MemberInfo::redirection`] carries the target at `open`. Answer
/// [`Disposition::Verify`] to have it checked, as zero bytes against its
/// stored checksum for RAR 5 and as the target's CRC32 for the RAR 4
/// family, and make the link, hard link or copy at `close`, where archive
/// order means every member it can name has already closed; or answer
/// [`Disposition::Skip`]. [`Disposition::Write`] is refused: nothing is
/// written to the writer, and the operation fails with
/// [`Unsupported::Redirection`](crate::Unsupported::Redirection) naming the
/// member. That refusal is a backstop. A caller that does not make a kind
/// should decline it itself, by name, so the rest of the archive still
/// extracts.
pub trait Sink {
    /// What a member's bytes are written to.
    type Out: std::io::Write;

    /// Called once per member, in archive order, before any byte of it.
    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Self::Out>>;

    /// Called once per member opened with Write or Verify, after its last
    /// byte, with the integrity verdict. The default drops `out`.
    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Self::Out>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        Ok(())
    }

    /// A leading fragment of this member, in `volume` (0 based, an index
    /// into the caller's [`Volumes`]), holds packed bytes its CRC32 field
    /// disagrees with (spec F 3.5.6, 29 Sep 2026). Called once per such
    /// fragment, before the member's `close`, for a member opened with
    /// Write or Verify. A DIAGNOSTIC, not a verdict: the member is judged
    /// by its whole checksum alone, in [`MemberOutcome::checksum_ok`],
    /// and [`MemberOutcome::fragment_mismatches`] counts these calls. The
    /// default ignores it.
    fn fragment_mismatch(&mut self, member: &MemberInfo<'_>, volume: u32) -> Result<()> {
        let _ = (member, volume);
        Ok(())
    }
}

/// A sink's answer to "here is a member, what now?".
#[derive(Debug)]
pub enum Disposition<W> {
    /// Decode it and put the bytes in this writer.
    Write(W),
    /// Decode it and check it, but write it nowhere. This is what the
    /// `t` command is.
    Verify,
    /// Leave it alone. In a non-solid archive that means its packed
    /// bytes are never even read; in a solid one the member still has to
    /// be decoded, because the members after it depend on the history it
    /// leaves, and the output is thrown away instead. Spec F states what
    /// that costs.
    Skip,
}

/// A member's description with its two borrowed fields taken out, so it
/// can be kept past the header it was read from (the concurrent pool's
/// queue of members waiting to close); the redirection target comes back
/// beside it. [`attached`] puts both back.
#[cfg(feature = "parallel")]
pub(crate) fn detached(member: &MemberInfo<'_>) -> (MemberInfo<'static>, Option<Vec<u8>>) {
    let target = member
        .redirection
        .as_ref()
        .and_then(|r| r.target.map(<[u8]>::to_vec));
    let info = MemberInfo {
        name: &[],
        is_directory: member.is_directory,
        unpacked_size: member.unpacked_size,
        packed_size: member.packed_size,
        split_before: member.split_before,
        split_after: member.split_after,
        encrypted: member.encrypted,
        password_checked: member.password_checked,
        mtime: member.mtime,
        attributes: member.attributes,
        host_os: member.host_os,
        checksum: member.checksum,
        method: member.method,
        dictionary: member.dictionary,
        solid: member.solid,
        algorithm_version: member.algorithm_version,
        data: member.data.clone(),
        redirection: member.redirection.as_ref().map(|r| Redirection {
            kind: r.kind,
            target: None,
            target_is_directory: r.target_is_directory,
        }),
        file_version: member.file_version,
    };
    (info, target)
}

/// [`detached`] undone: the member as it was described, over `name` and
/// its redirection's `target`.
#[cfg(feature = "parallel")]
pub(crate) fn attached<'a>(
    info: &MemberInfo<'static>,
    name: &'a [u8],
    target: Option<&'a [u8]>,
) -> MemberInfo<'a> {
    MemberInfo {
        name,
        is_directory: info.is_directory,
        unpacked_size: info.unpacked_size,
        packed_size: info.packed_size,
        split_before: info.split_before,
        split_after: info.split_after,
        encrypted: info.encrypted,
        password_checked: info.password_checked,
        mtime: info.mtime,
        attributes: info.attributes,
        host_os: info.host_os,
        checksum: info.checksum,
        method: info.method,
        dictionary: info.dictionary,
        solid: info.solid,
        algorithm_version: info.algorithm_version,
        data: info.data.clone(),
        redirection: info.redirection.as_ref().map(|r| Redirection {
            kind: r.kind,
            target,
            target_is_directory: r.target_is_directory,
        }),
        file_version: info.file_version,
    }
}

/// How one member came out, handed to [`Sink::close`].
///
/// Not exhaustive: a caller reads its fields and never builds one, so a
/// field added later breaks no caller (API 4.4, 29 Sep 2026).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct MemberOutcome {
    /// Whether the content matched its recorded check value. `None`
    /// where the header carries none, which is not a failure.
    ///
    /// A mismatch arrives HERE and not as an error: extraction carries
    /// on, the report counts it, and a caller wanting to stop at the
    /// first one returns an error from `close`.
    pub checksum_ok: Option<bool>,
    /// How many bytes the member decoded to.
    pub bytes: u64,
    /// The member was closed WITHOUT being decoded because its password
    /// was refused: none was given (`ErrorKind::PasswordRequired`), or
    /// its check record said it was wrong (`ErrorKind::WrongPassword`,
    /// spec K 3.7.3). `checksum_ok` is then `Some(false)` and `bytes` 0,
    /// and the operation returns that error once the member is closed.
    /// A caller reporting per member can say "wrong password" here and
    /// not "damaged", which `checksum_ok` alone cannot tell apart.
    pub password_refused: bool,
    /// How many of the member's leading fragments held packed bytes their
    /// CRC32 field disagreed with, each already reported through
    /// [`Sink::fragment_mismatch`] (spec F 3.5.6). Not a failure: a
    /// member whose fields disagree but whose bytes are right has
    /// `checksum_ok == Some(true)`.
    pub fragment_mismatches: u32,
}

/// Whether an error a member is closed with is its PASSWORD's refusal
/// ([`MemberOutcome::password_refused`]).
pub(crate) fn password_refused(err: Option<&Error>) -> bool {
    err.is_some_and(|e| {
        matches!(
            e.kind(),
            ErrorKind::PasswordRequired | ErrorKind::WrongPassword
        )
    })
}

/// Optional reports, in both directions: how far along the engine is,
/// and which bytes it will never ask for again.
///
/// Every method has a default that does nothing, so an implementation
/// takes only the ones it wants; `()` implements the lot. Returning an
/// error from any of them ends the operation as
/// [`ErrorKind::Caller`](crate::ErrorKind::Caller), with the value
/// preserved.
///
/// The drop-behind half is a contract and not a hint: once `released(v,
/// x)` has been called, bytes of volume `v` below `x` may be discarded
/// and the engine will not ask for them again, on the error paths
/// included. One `Progress` serves the write side too, which calls
/// `output` and `volume_done` and never `released`.
pub trait Progress {
    /// The engine will never again read `volume` below `offset`
    /// (source coordinates). Monotone per volume.
    fn released(&mut self, volume: u32, offset: u64) -> Result<()> {
        Ok(())
    }

    /// The engine has finished with `volume` and will not read it again.
    fn volume_done(&mut self, volume: u32) -> Result<()> {
        Ok(())
    }

    /// Decoded bytes delivered so far, over all members.
    fn output(&mut self, total: u64) -> Result<()> {
        Ok(())
    }

    /// A WRITER has taken up member `index`, counted in the order the
    /// members are written: `add` order, or the sorted order of a solid
    /// archive under `MemberOrder::ByType`. Called once for each member
    /// that has a payload to pull, so never for a directory or an empty
    /// member, before any of the member's bytes are written; every report
    /// until the next call belongs to this member or to an entry with no
    /// payload after it. A member's payload may be PULLED earlier than
    /// this, since a batch or the worker team pulls readers ahead of the
    /// writer, so a caller that reports per member reads the member from
    /// this call and not from its reader's first read. Never called by a
    /// reader.
    fn member_started(&mut self, index: usize) -> Result<()> {
        Ok(())
    }
}

impl Progress for () {}

/// Extract, with a [`Session`] made for this call and dropped after it.
///
/// One entry point covers all three cases section 4.4 lists: a single
/// archive, which is a one-element [`Volumes`]; a complete set; and a
/// set whose later volumes have not arrived, where the provider simply
/// blocks until each is there. Nothing has to be told which family it
/// is: volume 0 settles that.
pub fn extract<V: Volumes, K: Sink, P: Progress>(
    volumes: V,
    opts: &ReadOptions,
    sink: &mut K,
    progress: &mut P,
) -> Result<ExtractReport> {
    let mut sink = CurrentFilesMut::over(sink, opts.versions);
    metered(|| extract::extract_free(volumes, opts, &mut sink, progress))
}

/// An account of a finished extraction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExtractReport {
    /// How many members were opened.
    pub members: u64,
    /// How many decoded bytes reached the sink.
    pub bytes: u64,
    /// How many members failed their check value. Extraction does not
    /// stop for these; this is where they are counted.
    pub checksum_failures: u64,
    /// How many headers, of any kind and in any volume, were read
    /// although their own checksum failed
    /// ([`ReadOptions::read_damaged`]; always zero without it, where such
    /// a header ends the walk). A run with one is never a success,
    /// whatever its members' own checksums say (spec F 4.6 rule 1), and
    /// this is where a caller of [`extract`] that holds no [`Archive`]
    /// learns of it. A member under such a header that carries no data
    /// checksum is counted in `checksum_failures` as well.
    pub damaged_headers: u64,
    /// The high-water mark for THIS call, which is not what
    /// [`crate::memory::peak`] reports: that one counts the process.
    pub peak_working_memory: u64,
}

/// What [`extract_parallel`] wants in place of a [`Sink`]: the same two
/// methods, but on `&self`, so that several workers may be inside the
/// sink at once.
///
/// Two things do NOT change by going parallel, and they are the point of
/// the trait: each member's bytes are identical to what the sequential
/// form produces, and `close` is still called in archive order.
#[cfg(feature = "parallel")]
pub trait ParallelSink: Sync {
    /// What a member's bytes are written to. `Send`, because a worker
    /// thread holds it.
    type Out: std::io::Write + Send;

    /// Called once per member, before any of its bytes, and possibly on
    /// several threads at once.
    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Self::Out>>;

    /// Called once for each member `open` accepted, after its last byte.
    /// Unlike `open`, these arrive in archive order.
    fn close(
        &self,
        member: &MemberInfo<'_>,
        out: Option<Self::Out>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        Ok(())
    }

    /// [`Sink::fragment_mismatch`], for a member this sink opened: once per
    /// leading fragment whose CRC32 field disagreed, before that member's
    /// `close`. The default ignores it.
    fn fragment_mismatch(&self, member: &MemberInfo<'_>, volume: u32) -> Result<()> {
        let _ = (member, volume);
        Ok(())
    }
}

/// Extract with the caller's sink driven on up to `workers` worker
/// threads: several members are open for writing at once.
///
/// Output per member is identical to [`extract`], and `close` is called in
/// archive order, with every member that was opened closed exactly once
/// with its own outcome.
///
/// `workers` is the caller's BREADTH request. The effective breadth is
/// the lesser of it and
/// [`ReadOptions::workers`](ReadOptions::workers), the read side's width
/// dial (section 8.4.2), which also bounds the tape lanes inside each
/// member: the two together are section 8.3's breadth times width
/// product. A zero for either is
/// [`LimitExceeded`](crate::ErrorKind::LimitExceeded) with
/// [`Resource::Workers`](crate::Resource::Workers).
///
/// [`MemoryPolicy::working_limit`](crate::MemoryPolicy::working_limit) is
/// unmoved by any of it and stays a HARD ceiling: the engine lowers the
/// members in flight, and then the width inside them, until the buffers
/// fit (8.4.1). Running narrower than the width asked for is in contract
/// and is never an error.
///
/// **What runs on the workers is the DECODE.** A member of a non-solid set
/// that is not split, not skipped and not refused is handed to a worker as
/// its byte RANGE: the worker reads that range from the volume itself -
/// [`RangeSource`](crate::RangeSource) has no cursor and takes `&self`, so
/// several of the engine's threads may be inside one source at once - and
/// decodes and writes it while the walking thread parses the next header.
/// A member that must stay on the walking thread (a solid chain, a member
/// split across volumes, one no decoder claims) is decoded there, with its
/// WRITES handed to a worker.
///
/// Four differences from [`extract`] a caller can see:
///
/// - `close` for a member arrives after the walk has passed it, so a
///   caller that wants the two in lockstep wants [`extract`];
/// - an error the caller's `close` returns, and an error its own writer
///   returns, end the run one member later than they would sequentially;
/// - an error that ends the whole OPERATION - a failed source, a cancel, a
///   limit - stops the walk when it is noticed rather than at the member
///   that met it, so members after that one may already have been opened
///   AND closed, and an aborted run can close more members than the
///   sequential form would. A damaged member is not one of these: it is
///   reported through its own `close` and the members after it are
///   extracted, which is spec F section 8 and the reason this path exists
///   in this shape;
/// - a [`LimitExceeded`](crate::ErrorKind::LimitExceeded) raised by spec
///   I's text model carries a `needed` figure that depends on which
///   members the decoder before it decoded, and the two forms spread the
///   same members over a different number of decoders. The `resource` and
///   the `limit` are the archive's and the policy's and do not change.
///
/// **The volumes must stay readable until the call returns.** A worker
/// holds its volume's source by `Arc` and may read it after the walk has
/// crossed into the next one, so a caller whose `Volumes` hands out sources
/// that discard bytes behind the engine wants [`extract`], whose
/// [`Progress::released`] says exactly when a byte is finished with.
#[cfg(feature = "parallel")]
pub fn extract_parallel<V: Volumes, S: ParallelSink>(
    volumes: V,
    opts: &ReadOptions,
    sink: &S,
    workers: usize,
) -> Result<ExtractReport> {
    let sink = CurrentFiles::over(sink, opts.versions);
    metered(|| concurrent::extract_parallel_with(volumes, opts, &sink, workers))
}

/// The caller's sink as extraction drives it: an older version of a file
/// is passed over unless the caller asked for versions (spec F 3.2.6.4
/// V2). The engine sees a member its sink skipped, so a solid chain still
/// decodes through it; the caller's sink is never shown it.
struct CurrentFilesMut<'s, K: ?Sized> {
    sink: &'s mut K,
    versions: bool,
}

/// [`CurrentFilesMut`] over a sink that several workers share.
#[cfg(feature = "parallel")]
struct CurrentFiles<'s, K: ?Sized> {
    sink: &'s K,
    versions: bool,
}

#[cfg(feature = "parallel")]
impl<'s, K: ?Sized> CurrentFiles<'s, K> {
    fn over(sink: &'s K, versions: bool) -> Self {
        CurrentFiles { sink, versions }
    }
}

impl<'s, K: ?Sized> CurrentFilesMut<'s, K> {
    fn over(sink: &'s mut K, versions: bool) -> Self {
        CurrentFilesMut { sink, versions }
    }
}

/// Whether a sink is shown `member` when versions were `asked` for or not.
fn selected(member: &MemberInfo<'_>, asked: bool) -> bool {
    asked || member.file_version.is_none()
}

impl<K: Sink + ?Sized> Sink for CurrentFilesMut<'_, K> {
    type Out = K::Out;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Self::Out>> {
        if selected(member, self.versions) {
            self.sink.open(member)
        } else {
            Ok(Disposition::Skip)
        }
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Self::Out>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        if selected(member, self.versions) {
            self.sink.close(member, out, outcome)
        } else {
            Ok(())
        }
    }

    fn fragment_mismatch(&mut self, member: &MemberInfo<'_>, volume: u32) -> Result<()> {
        if selected(member, self.versions) {
            self.sink.fragment_mismatch(member, volume)
        } else {
            Ok(())
        }
    }
}

#[cfg(feature = "parallel")]
impl<K: ParallelSink + ?Sized> ParallelSink for CurrentFiles<'_, K> {
    type Out = K::Out;

    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Self::Out>> {
        if selected(member, self.versions) {
            self.sink.open(member)
        } else {
            Ok(Disposition::Skip)
        }
    }

    fn close(
        &self,
        member: &MemberInfo<'_>,
        out: Option<Self::Out>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        if selected(member, self.versions) {
            self.sink.close(member, out, outcome)
        } else {
            Ok(())
        }
    }

    fn fragment_mismatch(&self, member: &MemberInfo<'_>, volume: u32) -> Result<()> {
        if selected(member, self.versions) {
            self.sink.fragment_mismatch(member, volume)
        } else {
            Ok(())
        }
    }
}

/// Run one extraction under its own [`crate::memory::Meter`], and report
/// the SIMULTANEOUS peak of what it charged (API section 5.2 and 8.4.1):
/// the most its buffers held AT ONCE, which a sum of each buffer's own
/// high-water mark overstates. Holdings a reused [`Session`] charged before
/// the call are not this operation's charges and are not in the figure.
fn metered(run: impl FnOnce() -> Result<ExtractReport>) -> Result<ExtractReport> {
    // The slot of this call's own meter: the one the thread did not carry
    // before it opened. A meter that found no slot free leaves the thread
    // in whatever slot it was in, which is not this call's to end.
    #[cfg(feature = "parallel")]
    let outer = crate::memory::op_slot();
    let meter = crate::memory::Meter::open();
    // The helper threads this extraction keeps are ended and waited for
    // before it returns, however it returns (`read::team`).
    #[cfg(feature = "parallel")]
    let _team = team::Ends::of(crate::memory::op_slot().filter(|slot| Some(*slot) != outer));
    let mut report = run()?;
    report.peak_working_memory = meter.peak();
    Ok(report)
}

#[cfg(test)]
mod dump;
#[cfg(test)]
mod tests;
