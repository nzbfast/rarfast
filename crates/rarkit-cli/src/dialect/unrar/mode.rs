//! Which permission bits an extracted member is left with.
//!
//! WRITTEN HERE from black-box measurement of reference unrar 7.23 on
//! Linux x86-64 (a small VPS, 27 Sep 2026: RAR 5 archives from rar 7.23,
//! RAR 4 and RAR 1.3 archives from `fixtures/legacy` with their host byte
//! and attribute word rewritten, extracted as root and as an unprivileged
//! user under umasks 000, 022, 027 and 077). No source was read. Until
//! this module every extracted file came out `0666 & !umask`, so a 0600 or
//! 0640 member became readable by everyone and a 0755 one lost its
//! execute bits.
//!
//! What the reference does, and so what this module decides:
//!
//! - **The host decides how the attribute word is read.** Unix and BeOS
//!   members carry a mode; MS-DOS, OS/2, Windows and Mac OS members carry
//!   DOS bits, of which only READ-ONLY (0x01) reaches the mode; WinCE and
//!   any unnamed host byte carry nothing the reference applies. The RAR
//!   1.3 container records no host and is DOS-only; it reads as DOS.
//! - **A Unix-host FILE gets its stored mode exactly**: the umask does not
//!   apply, and setuid, setgid and sticky survive, for root and for an
//!   ordinary user alike, whether the file was new or overwritten. (Here
//!   the three survive for the superuser alone, and an ordinary user's
//!   run says once that it left them off: SPEC-CLI 9.4 W3, a chosen
//!   difference. See [`FileMode::without_high_bits`].) The
//!   file-type bits are ignored, except that a symbolic link's are never
//!   applied as a mode (see [`FileMode::of`]).
//! - **A DOS-host file gets `0666`, or `0444` when read-only, less the
//!   umask**, and so does an unnamed host's file (read-only ignored), new
//!   or overwritten: an existing file of mode 0755 overwritten by a
//!   Windows member ends at 0644 under umask 022.
//! - **A Unix-host DIRECTORY that did not exist gets what `mkdir` gives
//!   its stored mode**: less the umask, the sticky bit kept, setgid left
//!   to the kernel (1777 lands as 1755 under umask 022, 2770 as 750). One
//!   that DID exist when its member was reached - already on the disk, or
//!   made as the parent of an earlier member, which is the usual case
//!   because writers store a directory after its contents - is set to its
//!   stored mode exactly, under `-o-` too.
//! - **A DOS-host or unnamed-host directory gets `0777` less the umask**,
//!   new or existing; its read-only bit is ignored.
//! - **`-ai`** leaves a new file at `0666` and a new directory at `0777`,
//!   less the umask, and an existing directory untouched. An existing FILE
//!   overwritten under `-ai` ends at 0700 whatever its host, mode or the
//!   umask: a reference quirk, measured on every cell and reproduced here
//!   so a script that relies on the drop-in sees the same bits.
//!
//! ONE deliberate difference, by design: the
//! reference sets a directory's mode at its member, so an archive that
//! stores a read-only directory BEFORE its contents fails those contents
//! with `Cannot create` for anyone but root (measured). Here every
//! directory's mode is set after the walk, with its time, deepest first,
//! and such an archive extracts whole. On the order every genuine writer
//! uses the result is the same bits.

use std::path::Path;

use super::HostOs;

/// How a host's attribute word reaches a mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reading {
    /// A Unix mode word: Unix and BeOS.
    Mode,
    /// DOS bits: MS-DOS, OS/2, Windows, Mac OS, and the RAR 1.3 container.
    Dos,
    /// Nothing the reference applies: WinCE and any unnamed host byte.
    Nothing,
}

fn reading(host: HostOs) -> Reading {
    match host {
        HostOs::Unix | HostOs::BeOs => Reading::Mode,
        HostOs::MsDos | HostOs::Os2 | HostOs::Windows | HostOs::MacOs | HostOs::Unrecorded => {
            Reading::Dos
        }
        HostOs::WinCe | HostOs::Other(_) => Reading::Nothing,
    }
}

/// The permission bits a mode word keeps: the nine access bits and
/// setuid, setgid and sticky, without the file-type field.
const PERMISSION_BITS: u32 = 0o7777;
/// Set user, set group and sticky: the three bits above the nine.
const HIGH_BITS: u32 = 0o7000;
/// The file-type field of a Unix mode word, and its symbolic-link value.
const TYPE_BITS: u64 = 0o170000;
const TYPE_SYMLINK: u64 = 0o120000;
/// DOS read-only.
const DOS_READ_ONLY: u64 = 0x01;
/// The Windows attributes a member's output can be left with: read-only,
/// hidden, system, archive and not-content-indexed. The rest of a stored
/// word says what the file WAS (a directory, compressed, a reparse point),
/// which no call sets.
const WINDOWS_SETTABLE: u64 = 0x01 | 0x02 | 0x04 | 0x20 | 0x2000;
/// Read-only, hidden and system: the three a caller sees.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
const WINDOWS_MARKS: u32 = 0x01 | 0x02 | 0x04;
/// `FILE_ATTRIBUTE_ARCHIVE`, what a file just written has, and
/// `FILE_ATTRIBUTE_NORMAL`, the word for "none at all".
const WINDOWS_ARCHIVE: u32 = 0x20;
const WINDOWS_NORMAL: u32 = 0x80;

/// What one file member's output is created with and left with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FileMode {
    /// The NARROW mode a file is created with where it cannot be created
    /// with its final one ([`FileMode::create_under`]): inside 0666 and
    /// inside the member's own bits, which the kernel then narrows by the
    /// umask. Never wider than `target` on the access bits, so a 0600
    /// member is never readable by others while it is being written.
    create: u32,
    /// A Unix member's nine bits, where it carries none of the three
    /// above them: the mode it may be CREATED with outright (SPEC-CLI 9.4
    /// W4). `None` for every other member.
    whole: Option<u32>,
    /// The mode it ends with if this run created it.
    fresh: Target,
    /// The mode it ends with if it was already there and overwritten.
    existing: Target,
    /// The attribute word it ends with ON WINDOWS, or `None` for none set
    /// (`-ai`); see [`FileMode::windows_word`]. Read on Windows alone.
    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    word: Option<u32>,
}

/// A mode a file or directory ends with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    /// Exactly these bits.
    Exact(u32),
    /// These bits less the umask.
    Masked(u32),
    /// Whatever it has; nothing is set.
    Keep,
}

impl Target {
    fn resolve(self, umask: u32) -> Option<u32> {
        match self {
            Self::Exact(mode) => Some(mode),
            Self::Masked(mode) => Some(mode & !umask),
            Self::Keep => None,
        }
    }
}

impl FileMode {
    /// The decision for a file member written from `attr` under `host`.
    ///
    /// A Unix-host member whose type field says SYMBOLIC LINK is not a
    /// file whose bits mean anything here: the reference makes a link of
    /// it, which this dialect does not yet do (it writes the member's
    /// bytes), and a link's `0777` applied to that plain file would leave
    /// it writable by everyone. It is created as an unnamed host's file
    /// is, and nothing is applied.
    pub(crate) fn of(host: HostOs, attr: u64, ignore_attributes: bool) -> Self {
        if ignore_attributes {
            return Self {
                create: 0o666,
                whole: None,
                fresh: Target::Keep,
                existing: Target::Exact(0o700),
                word: None,
            };
        }
        match reading(host) {
            Reading::Mode if attr & TYPE_BITS == TYPE_SYMLINK => Self::plain(),
            Reading::Mode => {
                // Truncation is the point: the word's type field and
                // anything above it are not permission bits.
                #[allow(clippy::cast_possible_truncation)]
                let mode = (attr as u32) & PERMISSION_BITS;
                Self {
                    // SPEC-CLI 9.4 W4: nothing outside 666 while the
                    // bytes go in; a member with more (an execute bit)
                    // gets it at the end, on the open file.
                    create: mode & 0o666,
                    whole: (mode & HIGH_BITS == 0).then_some(mode),
                    fresh: Target::Exact(mode),
                    existing: Target::Exact(mode),
                    word: Some(WINDOWS_ARCHIVE),
                }
            }
            Reading::Dos => {
                let mode = if attr & DOS_READ_ONLY != 0 {
                    0o444
                } else {
                    0o666
                };
                // Truncation is the point: the settable bits are low ones.
                #[allow(clippy::cast_possible_truncation)]
                let word = (attr & WINDOWS_SETTABLE) as u32;
                Self {
                    create: mode,
                    whole: None,
                    fresh: Target::Keep,
                    existing: Target::Masked(mode),
                    word: Some(if word == 0 { WINDOWS_NORMAL } else { word }),
                }
            }
            Reading::Nothing => Self::plain(),
        }
    }

    fn plain() -> Self {
        Self {
            create: 0o666,
            whole: None,
            fresh: Target::Keep,
            existing: Target::Masked(0o666),
            word: Some(WINDOWS_ARCHIVE),
        }
    }

    /// Whether this decision would leave the file with any of the three
    /// bits above the nine: set user, set group, sticky.
    pub(crate) fn has_high_bits(self) -> bool {
        [self.fresh, self.existing]
            .iter()
            .any(|target| matches!(target, Target::Exact(mode) if mode & HIGH_BITS != 0))
    }

    /// This decision with the three bits above the nine left off: what a
    /// run that is not the superuser's leaves (SPEC-CLI 9.4 W3). The nine
    /// permission bits are as they were.
    #[must_use]
    pub(crate) fn without_high_bits(self) -> Self {
        let nine = |target| match target {
            Target::Exact(mode) => Target::Exact(mode & !HIGH_BITS),
            other => other,
        };
        Self {
            fresh: nine(self.fresh),
            existing: nine(self.existing),
            ..self
        }
    }

    /// The attribute word to set on the file ON WINDOWS once its bytes are
    /// written, or `None` for none. `fresh` is whether this run created it.
    ///
    /// MEASURED against UnRAR 7.23 x64 on Windows (2 Oct 2026):
    /// a member written
    /// by a Windows host ends with exactly its stored attributes (`0x21`,
    /// `0x22`, `0x24`, `0x27`), and a Unix-host member with the archive
    /// attribute alone (`0444` is NOT read as read-only), whatever the file
    /// that was there carried: read-only, hidden and system all go. Until
    /// then nothing was set here, and a hidden or system file written over
    /// kept its attribute.
    ///
    /// A file that WAS THERE is always set, so that what it carried goes. A
    /// FRESH one is set only where its word carries read-only, hidden or
    /// system: a plain new file keeps what its directory gave it, and the
    /// extract of many files makes no call for it. That is ONE DIFFERENCE
    /// from the reference, kept: it sets every file's word, so a fresh file
    /// in a directory marked not-content-indexed loses that mark there and
    /// keeps it here.
    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    pub(crate) fn windows_word(self, fresh: bool) -> Option<u32> {
        self.word.filter(|word| !fresh || word & WINDOWS_MARKS != 0)
    }

    /// The mode a file is CREATED with under `umask` (SPEC-CLI 9.4 W4):
    /// its FINAL nine bits at once, where the umask takes none of them
    /// away and the member carries none of the three above them, so that
    /// no bits are set afterwards ([`FileMode::finish`] then answers
    /// `None`) and the file is whole in its mode from its first instant;
    /// otherwise the narrow mode, inside 666 and inside the member's own
    /// nine, with the stored bits put on at the end.
    pub(crate) fn create_under(self, umask: u32) -> u32 {
        match self.whole {
            Some(nine) if nine & umask == 0 => nine,
            _ => self.create,
        }
    }

    /// The mode to set on the file once its bytes are written, or `None`
    /// where it already has it. `fresh` is whether this run created it.
    pub(crate) fn finish(self, fresh: bool, umask: u32) -> Option<u32> {
        if !fresh {
            return self.existing.resolve(umask);
        }
        let made = self.create_under(umask) & !umask;
        match self.fresh.resolve(umask) {
            Some(mode) if mode != made => Some(mode),
            _ => None,
        }
    }
}

/// What one directory member is created with and left with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirMode {
    /// Leave it as it is.
    Keep,
    /// Set exactly these bits once the walk is over.
    Exact(u32),
    /// These bits less the umask, once the walk is over.
    Masked(u32),
    /// Create it the way `mkdir` with this mode would, and leave it with
    /// that; see [`DirMode::creation`] for how the owner's own bits are
    /// kept open until the walk is over.
    Made(u32),
}

impl DirMode {
    /// The decision for a directory member from `attr` under `host`;
    /// `existed` is whether the directory was there when its member was
    /// reached.
    pub(crate) fn of(host: HostOs, attr: u64, ignore_attributes: bool, existed: bool) -> Self {
        if ignore_attributes {
            return Self::Keep;
        }
        match reading(host) {
            Reading::Mode => {
                #[allow(clippy::cast_possible_truncation)]
                let mode = (attr as u32) & PERMISSION_BITS;
                if existed {
                    Self::Exact(mode)
                } else {
                    Self::Made(mode)
                }
            }
            Reading::Dos | Reading::Nothing if existed => Self::Masked(0o777),
            Reading::Dos | Reading::Nothing => Self::Keep,
        }
    }

    /// Whether this decision carries any of the three bits above the
    /// nine: set user, set group, sticky.
    pub(crate) fn has_high_bits(self) -> bool {
        self.stored() & HIGH_BITS != 0
    }

    /// This decision with the three bits above the nine left off: what a
    /// run that is not the superuser's leaves a directory member with
    /// (SPEC-CLI 9.4 W10 (c): W3 holds for a directory as for a file).
    #[must_use]
    pub(crate) fn without_high_bits(self) -> Self {
        match self {
            Self::Exact(mode) => Self::Exact(mode & !HIGH_BITS),
            Self::Made(mode) => Self::Made(mode & !HIGH_BITS),
            other => other,
        }
    }

    /// The mode to create a NEW directory with, or `None` for the
    /// default. A `Made` mode is created with the owner's read, write and
    /// search bits added, so the walk can still write the directory's
    /// contents and set its time; [`DirMode::after_creation`] takes them
    /// back off once the walk is over.
    pub(crate) fn creation(self) -> Option<u32> {
        match self {
            Self::Made(mode) => Some(mode | 0o700),
            _ => None,
        }
    }

    /// The stored bits of a `Made` or `Exact` mode, 0 otherwise.
    fn stored(self) -> u32 {
        match self {
            Self::Made(mode) | Self::Exact(mode) => mode,
            Self::Keep | Self::Masked(_) => 0,
        }
    }

    /// The mode a `Made` directory ends with, given the mode the kernel
    /// actually gave it at [`DirMode::creation`]: its group, other,
    /// setgid and sticky bits as made, and the owner's bits `mkdir` would
    /// have given - the stored ones, less what the umask took off the
    /// owner's `0o700`, which the made mode shows.
    pub(crate) fn after_creation(self, made: u32) -> Option<u32> {
        match self {
            Self::Made(mode) => {
                let made = made & PERMISSION_BITS;
                Some((made & !0o700) | (mode & made & 0o700))
            }
            _ => None,
        }
    }

    /// The mode to set once the walk is over, or `None` for none. A
    /// `Made` directory answers `None` here: its final mode comes from
    /// [`DirMode::after_creation`].
    pub(crate) fn finish(self, umask: u32) -> Option<u32> {
        match self {
            Self::Exact(mode) => Some(mode),
            Self::Masked(mode) => Some(mode & !umask),
            Self::Keep | Self::Made(_) => None,
        }
    }
}

/// The mode a file member's output is CREATED with:
/// [`FileMode::create_under`] the process's umask. Off Unix a create
/// takes no mode.
pub(crate) fn file_create(mode: FileMode) -> u32 {
    #[cfg(unix)]
    {
        mode.create_under(process_umask())
    }
    #[cfg(not(unix))]
    {
        mode.create
    }
}

/// The mode a file member's output is left with once its bytes are in,
/// or `None` for none: [`FileMode::finish`] against the process's umask.
/// On Windows it is the attribute word ([`FileMode::windows_word`]), which
/// [`set_on`] sets there; on any other system that is not Unix, nothing.
pub(crate) fn file_finish(mode: FileMode, fresh: bool) -> Option<u32> {
    #[cfg(unix)]
    {
        mode.finish(fresh, process_umask())
    }
    #[cfg(windows)]
    {
        mode.windows_word(fresh)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (mode, fresh);
        None
    }
}

/// [`DirMode::finish`] against the process's umask; `None` off Unix.
pub(crate) fn dir_finish(mode: DirMode) -> Option<u32> {
    #[cfg(unix)]
    {
        mode.finish(process_umask())
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        None
    }
}

/// Creates the directory `path` and any missing parents. The parents get
/// the default mode; `path` itself gets `mode.creation()` where it names
/// one, and then the answer is the mode it is to be left with (see
/// [`DirMode::after_creation`]), read back from what the kernel made.
pub(crate) fn create_directory(path: &Path, mode: DirMode) -> std::io::Result<Option<u32>> {
    #[cfg(unix)]
    if let Some(creation) = mode.creation() {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        match std::fs::DirBuilder::new().mode(creation).create(path) {
            Ok(()) => {}
            // Made in between: it existed after all, and takes its stored
            // mode exactly, as an existing directory does.
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists && path.is_dir() => {
                return Ok(Some(creation & !0o700 | mode.stored() & 0o700));
            }
            Err(err) => return Err(err),
        }
        let made = std::fs::symlink_metadata(path)?.permissions().mode();
        return Ok(mode.after_creation(made));
    }
    let _ = mode;
    std::fs::create_dir_all(path).map(|()| None)
}

/// The permission bits of `meta`, as [`DirMode::finish`] states them;
/// 0 off Unix, where no mode is ever set.
pub(crate) fn permission_bits(meta: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & PERMISSION_BITS
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        0
    }
}

/// Sets `mode` on an open file or directory. Best effort, as the
/// reference's is: a file system that refuses it keeps the bytes.
pub(crate) fn set_on(file: &std::fs::File, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(mode));
    }
    #[cfg(windows)]
    {
        let _ = crate::safepath::set_attribute_word(file, mode);
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (file, mode);
    }
}

/// Sets `mode` on the directory at `path` by name, for one this user can
/// not open (a pre-existing `0o000` directory, say). Only a real
/// directory, never through a link.
pub(crate) fn set_on_directory_path(path: &Path, mode: u32) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
            && std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).is_ok()
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        false
    }
}

/// Whether this run is the superuser's, asked once: the effective user
/// is 0. Off Unix there are no such bits to withhold and the answer is
/// yes.
#[cfg(unix)]
#[allow(unsafe_code)]
pub(crate) fn superuser() -> bool {
    static SUPERUSER: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    // SAFETY: `geteuid` takes nothing, touches no memory of ours and
    // cannot fail.
    *SUPERUSER.get_or_init(|| unsafe { libc::geteuid() } == 0)
}

/// See the Unix [`superuser`].
#[cfg(not(unix))]
pub(crate) fn superuser() -> bool {
    true
}

/// What a run says, once, when it left the three high bits off a member
/// because it is not the superuser's (SPEC-CLI 9.4 W3). The words are
/// rarfast's own.
pub(crate) const HIGH_BITS_LEFT_OFF: &str = "Set user, set group and sticky bits are restored \
     only for the superuser: left off";

/// The process's file-creation mask, as [`read_umask_at_start`] read it at
/// `main`'s first line; where that read was not made (a unit test, or a
/// count build's `RARFAST_UMASK=probe`), read where the system publishes
/// it (Linux's `/proc/self/status` since 4.7) and otherwise measured: a
/// directory made with `0777` in the temporary directory shows it, and is
/// removed. `0o022` is the fallback where neither answers, which is every
/// desktop system's default.
#[cfg(unix)]
pub(crate) fn process_umask() -> u32 {
    *UMASK.get_or_init(probed_umask)
}

/// The mask, once for the process: [`read_umask_at_start`]'s, or the
/// probe's ([`process_umask`]).
#[cfg(unix)]
static UMASK: std::sync::OnceLock<u32> = std::sync::OnceLock::new();

/// The probe's answer: published where the system publishes it, measured
/// otherwise, `0o022` where neither answers.
#[cfg(unix)]
fn probed_umask() -> u32 {
    published_umask().or_else(measured_umask).unwrap_or(0o022)
}

/// READ THE MASK AT START (release blocker 4's rest, 19 Oct 2026): called
/// at `main`'s FIRST LINE, on Unix, while the process has ONE thread.
///
/// **Why not the probe.** macOS publishes no mask, so the probe measured
/// it with a directory made and removed in the temporary directory, and
/// that was the wall in front of a lone stored member's first write:
/// counted in our own process on an M5 Ultra, `x` of a 16 MiB member made
/// its output file 0.71 ms after start, 0.37 ms of it the probe (the
/// `mkdir` alone 317 us), where the temporary directory's creates average
/// 186 to 217 us and vary widely.
///
/// **What it does.** `umask(2)` sets the mask and answers the one it
/// replaces; there is no call that only reads it. So the pair sets
/// `0o022` and at once sets back the mask it answered. Between the two
/// calls the process has a mask that may not be its own, which is sound
/// only because nothing can create a file in that instant: the process
/// has one thread, the call is `main`'s first statement (pinned by
/// `tests::main_reads_the_mask_before_anything_else`), and the pair is two
/// system calls with nothing between them. The mask after the pair is the
/// mask before it. Off Unix there is no mask and nothing is read.
///
/// A count-only knob (feature `read-depth-knob`, never shipped):
/// `RARFAST_UMASK=probe` keeps the probe, the arm `tests/umask_at_start.rs`
/// compares modes against; `RARFAST_UMASK_SAY=1` says which answered.
#[cfg(unix)]
pub(crate) fn read_umask_at_start() {
    #[cfg(feature = "read-depth-knob")]
    let probe = std::env::var("RARFAST_UMASK").is_ok_and(|v| v.trim() == "probe");
    #[cfg(not(feature = "read-depth-knob"))]
    let probe = false;
    let mask = *UMASK.get_or_init(|| {
        if probe {
            probed_umask()
        } else {
            set_and_restore()
        }
    });
    #[cfg(feature = "read-depth-knob")]
    if std::env::var("RARFAST_UMASK_SAY").is_ok_and(|v| v.trim() == "1") {
        let how = if probe { "probe" } else { "read" };
        eprintln!("rarfast umask: {mask:03o} {how}");
    }
    let _ = mask;
}

/// The set-and-restore pair of [`read_umask_at_start`]: the mask the
/// process had, which it has again when this returns.
///
/// `mode_t` is `u16` on macOS and `u32` on Linux, so the widening is a
/// conversion on one and the same type on the other.
#[cfg(unix)]
#[allow(unsafe_code)]
#[allow(clippy::useless_conversion)]
fn set_and_restore() -> u32 {
    // SAFETY: `umask` takes a mode by value, touches no memory of ours and
    // cannot fail. It is SOUND to set the mask for an instant only because
    // this runs at `main`'s first line, while the process has one thread,
    // so no file can be created under the borrowed mask; and the second
    // call puts back the mask the first answered before anything else
    // runs. See `read_umask_at_start`.
    let old = unsafe {
        let old = libc::umask(0o022);
        libc::umask(old);
        old
    };
    u32::from(old) & 0o777
}

#[cfg(unix)]
fn published_umask() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find_map(|l| l.strip_prefix("Umask:"))?;
    u32::from_str_radix(line.trim(), 8).ok()
}

#[cfg(unix)]
fn measured_umask() -> Option<u32> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let probe = std::env::temp_dir().join(format!(".rarfast-umask-{}-{nanos}", std::process::id()));
    std::fs::DirBuilder::new().mode(0o777).create(&probe).ok()?;
    let made = std::fs::symlink_metadata(&probe).map(|m| m.permissions().mode());
    let _ = std::fs::remove_dir(&probe);
    Some(0o777 & !(made.ok()? & 0o777))
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNIX_FILE: u64 = 0o100_000;
    const UNIX_DIR: u64 = 0o040_000;

    /// Every row is a cell measured off unrar 7.23 (module docs): stored
    /// mode, umask, and the mode the reference left a NEW file with.
    #[test]
    fn a_unix_file_keeps_its_stored_mode_whatever_the_umask() {
        for stored in [
            0o755_u32, 0o700, 0o644, 0o600, 0o640, 0o444, 0o000, 0o777, 0o666, 0o4755, 0o2755,
            0o1644, 0o6777, 0o4644, 0o2644,
        ] {
            for umask in [0o000, 0o022, 0o077] {
                let mode = FileMode::of(HostOs::Unix, UNIX_FILE | u64::from(stored), false);
                let got = mode
                    .finish(true, umask)
                    .unwrap_or(mode.create_under(umask) & !umask);
                assert_eq!(got, stored, "stored {stored:o} umask {umask:o}");
                assert_eq!(mode.finish(false, umask), Some(stored));
                // Never wider than the member while its bytes go in.
                assert_eq!(mode.create_under(umask) & !stored, 0);
            }
        }
    }

    /// SPEC-CLI 9.4 W4: a file is CREATED WITH ITS FINAL MODE where the
    /// umask takes none of the member's nine bits away and the member
    /// carries none of the three above them, and then no bits are set
    /// afterwards. Otherwise it is created inside 666 less the umask
    /// and inside the member's own nine, and the stored bits go on at
    /// the end. At no instant is it wider than its final bits or than
    /// the umask allows.
    #[test]
    fn a_file_is_created_with_its_final_mode_where_it_may_be() {
        for stored in [
            0o755_u32, 0o700, 0o711, 0o777, 0o775, 0o644, 0o664, 0o600, 0o640, 0o444, 0o000,
            0o4755, 0o2755, 0o1644,
        ] {
            let mode = FileMode::of(HostOs::Unix, UNIX_FILE | u64::from(stored), false);
            let nine = stored & 0o777;
            for umask in [0o000, 0o022, 0o027, 0o077] {
                let row = format!("stored {stored:o} umask {umask:o}");
                let created = mode.create_under(umask);
                // never wider than the final nine bits
                assert_eq!(created & !nine, 0, "{row}");
                let whole = nine & umask == 0 && stored == nine;
                if whole {
                    assert_eq!(created, nine, "{row}: created with its final mode");
                    assert_eq!(
                        mode.finish(true, umask),
                        None,
                        "{row}: no bits set afterwards"
                    );
                } else {
                    assert_eq!(created & !0o666, 0, "{row}: inside 666");
                    let left = mode.finish(true, umask).unwrap_or(created & !umask);
                    assert_eq!(left, stored, "{row}: the stored bits at the end");
                }
            }
        }
        // A member a DOS host wrote, an unnamed host's, and `-ai`: as before.
        for (host, attr, ignore) in [
            (HostOs::Windows, 0x20, false),
            (HostOs::Windows, 0x21, false),
            (HostOs::WinCe, 0, false),
            (HostOs::Unix, UNIX_FILE | 0o755, true),
        ] {
            let mode = FileMode::of(host, attr, ignore);
            for umask in [0o000, 0o022, 0o077] {
                assert_eq!(mode.create_under(umask) & !0o666, 0, "{host:?} {attr:#x}");
            }
        }
    }

    #[test]
    fn a_plain_unix_file_under_the_default_umask_needs_no_second_call() {
        let mode = FileMode::of(HostOs::Unix, UNIX_FILE | 0o644, false);
        assert_eq!(mode.finish(true, 0o022), None);
        let mode = FileMode::of(HostOs::Unix, UNIX_FILE | 0o664, false);
        assert_eq!(mode.finish(true, 0o022), Some(0o664));
    }

    #[test]
    fn beos_reads_as_unix_and_the_type_field_is_not_a_mode() {
        let mode = FileMode::of(HostOs::BeOs, 0x21, false);
        assert_eq!(mode.finish(false, 0o022), Some(0o041));
        // A file member whose word says directory, or all type bits: the
        // reference wrote a plain file at the access bits (s4 cells).
        for attr in [0o040_755, 0o170_755] {
            let mode = FileMode::of(HostOs::Unix, attr, false);
            assert_eq!(mode.finish(false, 0o022), Some(0o755));
        }
        // No type field at all.
        let mode = FileMode::of(HostOs::Unix, 0o600, false);
        assert_eq!(mode.finish(false, 0o022), Some(0o600));
    }

    #[test]
    fn a_symbolic_link_s_mode_is_never_applied_to_a_file() {
        let mode = FileMode::of(HostOs::Unix, 0o120_777, false);
        assert_eq!(mode.create, 0o666);
        assert_eq!(mode.finish(true, 0o022), None);
        assert_eq!(mode.finish(false, 0o022), Some(0o644));
    }

    #[test]
    fn a_dos_host_file_is_0666_or_0444_less_the_umask() {
        for host in [
            HostOs::MsDos,
            HostOs::Os2,
            HostOs::Windows,
            HostOs::MacOs,
            HostOs::Unrecorded,
        ] {
            for (attr, base) in [
                (0x20, 0o666),
                (0x21, 0o444),
                (0x01, 0o444),
                (0x22, 0o666),
                (0x27, 0o444),
                (0x00, 0o666),
                (0x80, 0o666),
                (0x2021, 0o444),
                (0o100_600, 0o666),
            ] {
                for umask in [0o022, 0o077, 0o027] {
                    let mode = FileMode::of(host, attr, false);
                    assert_eq!(mode.create, base);
                    assert_eq!(mode.finish(true, umask), None, "{host:?} {attr:#x}");
                    assert_eq!(mode.finish(false, umask), Some(base & !umask));
                }
            }
        }
    }

    #[test]
    fn an_unnamed_host_ignores_read_only() {
        for host in [HostOs::WinCe, HostOs::Other(7), HostOs::Other(2)] {
            let mode = FileMode::of(host, 0x21, false);
            assert_eq!(mode.create, 0o666);
            assert_eq!(mode.finish(false, 0o077), Some(0o600));
        }
    }

    #[test]
    fn ignore_attributes_is_the_default_when_new_and_0700_when_overwritten() {
        for (host, attr) in [
            (HostOs::Unix, UNIX_FILE | 0o4755),
            (HostOs::Windows, 0x21),
            (HostOs::WinCe, 0),
        ] {
            let mode = FileMode::of(host, attr, true);
            assert_eq!(mode.create, 0o666);
            assert_eq!(mode.finish(true, 0o027), None);
            assert_eq!(mode.finish(false, 0o027), Some(0o700));
        }
    }

    #[test]
    fn a_unix_directory_is_exact_when_it_existed_and_made_when_new() {
        let dir = DirMode::of(HostOs::Unix, UNIX_DIR | 0o1777, false, true);
        assert_eq!(dir.finish(0o077), Some(0o1777));
        assert_eq!(dir.creation(), None);
        let dir = DirMode::of(HostOs::Unix, UNIX_DIR | 0o555, false, false);
        assert_eq!(dir.creation(), Some(0o755));
        assert_eq!(dir.finish(0o022), None);
        // What the kernel made from 0o755 under umask 077 is 0o700; the
        // owner keeps r-x, as `mkdir(0555)` would have left it.
        assert_eq!(dir.after_creation(0o700), Some(0o500));
        // 1777 under 022: the kernel made 1755 from 1777; that stays.
        let dir = DirMode::of(HostOs::Unix, UNIX_DIR | 0o1777, false, false);
        assert_eq!(dir.after_creation(0o1755), Some(0o1755));
        // 2770 under 022 where the kernel dropped setgid: 750.
        let dir = DirMode::of(HostOs::Unix, UNIX_DIR | 0o2770, false, false);
        assert_eq!(dir.after_creation(0o0750), Some(0o750));
    }

    #[test]
    fn a_dos_directory_is_0777_less_the_umask_and_ai_leaves_it() {
        let dir = DirMode::of(HostOs::Windows, 0x11, false, true);
        assert_eq!(dir.finish(0o022), Some(0o755));
        assert_eq!(
            DirMode::of(HostOs::Windows, 0x11, false, false),
            DirMode::Keep
        );
        assert_eq!(
            DirMode::of(HostOs::Unix, UNIX_DIR | 0o700, true, true),
            DirMode::Keep
        );
        assert_eq!(
            DirMode::of(HostOs::Other(2), 0o40_750, false, false),
            DirMode::Keep
        );
    }

    /// The Windows word, read on every system: it is a pure decision.
    #[test]
    fn a_windows_member_ends_with_its_stored_attributes_and_a_unix_one_with_archive() {
        // Stored words as Rar.exe 7.23 writes them (2 Oct 2026).
        for (attr, word) in [
            (0x20u64, 0x20u32),
            (0x21, 0x21),
            (0x22, 0x22),
            (0x24, 0x24),
            (0x27, 0x27),
            (0x2020, 0x2020),
            // No settable bit at all: NORMAL, never 0, which sets nothing.
            (0x00, 0x80),
            (0x800, 0x80),
        ] {
            let mode = FileMode::of(HostOs::Windows, attr, false);
            // A file that was there is always set.
            assert_eq!(mode.windows_word(false), Some(word), "{attr:#x}");
            // A fresh one only where the word marks it.
            let marked = word & 0x07 != 0;
            assert_eq!(mode.windows_word(true), marked.then_some(word), "{attr:#x}");
        }
        // A Unix mode is not read for read-only: archive, on a file that
        // was there, and nothing on a fresh one.
        for attr in [0o100_444u64, 0o100_600, 0o100_755, 0o120_777] {
            let mode = FileMode::of(HostOs::Unix, attr, false);
            assert_eq!(mode.windows_word(false), Some(0x20), "{attr:o}");
            assert_eq!(mode.windows_word(true), None, "{attr:o}");
        }
        // `-ai`: nothing is set, as before (unmeasured on Windows).
        let ignored = FileMode::of(HostOs::Windows, 0x27, true);
        assert_eq!(ignored.windows_word(false), None);
        assert_eq!(ignored.windows_word(true), None);
    }

    #[cfg(unix)]
    #[test]
    fn the_umask_is_read_and_is_a_mask() {
        assert_eq!(process_umask() & !0o777, 0);
    }
}
