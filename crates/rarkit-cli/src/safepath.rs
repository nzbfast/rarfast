//! Where an extracted member is allowed to land, and how its file is
//! created.
//!
//! WRITTEN FRESH for this crate, not carried and not read across. The
//! predecessor's `safepath.rs` is the one module the dialect tree depends
//! on from outside itself, and the provenance census marks it as not to be carried: four
//! of its five production items carry donor-blamed lines
//! (`archive_relative_path` 9, the one that created a member's output
//! file 9, and the two platform
//! arms of its helper that sets the open flag against following a link, 4
//! and 2). So it is out by the project's rule and by the census both, and
//! this file was written without opening it.
//!
//! The rule below is therefore stated from what an extractor must not do,
//! not from what that file did:
//!
//! 1. An archived name is RELATIVE to the extraction directory. An
//!    absolute name, a drive letter, a UNC prefix or a leading separator
//!    is refused, not silently rebased. The name is split on its
//!    separators by this module, never by the host's `Path`, and each
//!    component is judged on its stored text and then MAPPED (rule 5)
//!    before it is joined: Windows' `Path` reads `x:` in `x:y.txt` as a
//!    drive, which is a name to map (`x_y.txt`), not a path to refuse.
//!    Only a FIRST component that is exactly a drive (`C:` in `C:\x`) is
//!    a drive-absolute name, and it is refused; every other `:` is mapped
//!    to `_`, and every joined component must read to the host as one
//!    plain component or the name is refused.
//! 2. No component may be `..`. Refused rather than resolved, because
//!    resolving depends on what exists on the disk and an attacker picks
//!    that. A `.` component is dropped.
//! 3. A component may not be empty, and the whole name may not be empty.
//! 4. The output file is created WITHOUT following a symbolic link at the
//!    final component, so a link planted by an earlier member (or already
//!    on the disk) cannot redirect a write outside the tree.
//! 5. On a WINDOWS target each component is mapped to a name Win32 can
//!    store as written (SPEC-API-rarkit.md question 20): a LAST character
//!    that is a `.` or space becomes `_` (`b..` to `b._`, as measured
//!    off the reference), every character Win32 refuses in a name
//!    (`<>:"|?*` and U+0000 to U+001F) becomes `_`, and a reserved device
//!    base name (`CON`, `PRN`, `AUX`, `NUL`, `COM1` to `COM9`, `LPT1` to
//!    `LPT9`, with or without an extension) gains a `_` prefix. Nothing
//!    else changes and nothing is mapped on any other target, where a
//!    trailing dot is an ordinary name. A name that collides after the
//!    mapping (`a.` and `a_`, or two names differing only in case) is the
//!    overwrite policy's, exactly as a file already on the disk is: no
//!    suffix is invented.
//!
//! Rule 5 exists because Win32 does not refuse such a name, it silently
//! rewrites it: a trailing dot or space is stripped at create time (`a.`
//! lands on `a`, colliding with a member really called `a`), a `:` opens
//! an alternate data stream of the file before it, and `CON` names the
//! console. The reference, on a Windows desktop (the 24 Sep
//! round), writes a trailing dot as `_`; the rest of the rule is stated in
//! that shape. The listing is untouched; the written path is mapped, and
//! so is the name on the progress line, which names the file written.
//!
//! Rule 4 is the one with a platform half: `O_NOFOLLOW` on Unix through
//! `OpenOptionsExt::custom_flags`, and on Windows the create is left to
//! the standard library, which does not follow a reparse point for a
//! `create_new` and has no stable safe spelling for the flag otherwise.
//! That difference is recorded rather than papered over.

use std::borrow::Cow;
use std::fs::{File, OpenOptions};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// What to do when the output file is already there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum IfOutputExists {
    /// Never overwrite; the member is skipped.
    #[default]
    Keep,
    /// Replace whatever is there, once the member is whole (SPEC-CLI 9.4
    /// W7): the member is written beside it.
    Replace,
    /// [`IfOutputExists::Replace`] for a name the caller has already found
    /// taken (the question was asked about it and answered yes): the file
    /// beside is made with no second create at the name.
    Beside,
}

/// Which filesystem's naming rules a written path has to satisfy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NameRules {
    /// Any component the separator split leaves is stored as written.
    Native,
    /// Win32: rule 5 of this module's documentation.
    Windows,
}

impl NameRules {
    /// The rules of the host this binary extracts on.
    pub(crate) const HOST: NameRules = if cfg!(windows) {
        NameRules::Windows
    } else {
        NameRules::Native
    };
}

/// Resolves an archived name against `root` under the host's naming
/// rules, or refuses it.
///
/// `Err` carries the reason in the words a caller prints beside the name.
///
/// The walk resolves through [`archive_relative_path_into`], one buffer
/// for every member; this owned form, and the one below it, are the same
/// validation for the tests that name a single path.
#[cfg(test)]
pub(crate) fn archive_relative_path(root: &Path, name: &str) -> Result<PathBuf, &'static str> {
    archive_relative_path_under(root, name, NameRules::HOST)
}

/// [`archive_relative_path`] under explicit `rules`, so both rule sets are
/// testable on every host.
#[cfg(test)]
pub(crate) fn archive_relative_path_under(
    root: &Path,
    name: &str,
    rules: NameRules,
) -> Result<PathBuf, &'static str> {
    let mut out = PathBuf::new();
    archive_relative_path_into(&mut out, root, name, rules)?;
    Ok(out)
}

/// `archive_relative_path_under` written into `out`, whose earlier
/// contents are replaced, so a caller resolving many names reuses one
/// buffer. The validation is the same code; on `Err` what `out` holds is
/// meaningless and is not a path to use.
pub(crate) fn archive_relative_path_into(
    out: &mut PathBuf,
    root: &Path,
    name: &str,
    rules: NameRules,
) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("empty name");
    }
    // The name is split HERE, on the separators the rules name, and never
    // handed to `Path::components`: on a Windows host that reads `x:` in
    // `x:y.txt` as a drive prefix before any mapping could run, which
    // refused a name the reference writes as `x_y.txt`, and it reads `a:b`
    // pushed onto the root as a drive and discards the root.
    let mut parts = name.split(|c| rules.is_separator(c));
    let first = parts.next().unwrap_or("");
    if first.is_empty() {
        // A leading separator: `/etc`, `\\server\share`, `\\?\C:`.
        return Err("absolute path");
    }
    if rules == NameRules::Windows && is_drive(first) {
        // `C:\x` or `C:/x`: a drive-absolute name, refused, not rebased.
        return Err("absolute path");
    }
    out.as_mut_os_string().clear();
    out.as_mut_os_string().push(root.as_os_str());
    let mut components = 0;
    for part in std::iter::once(first).chain(parts) {
        match part {
            // A doubled or trailing separator carries nothing, and `.`
            // carries nothing either; both are dropped.
            "" | "." => {}
            // Judged on the STORED text, before any mapping, so the
            // mapping can never turn a refused component into a kept one.
            ".." => return Err("path escapes the extraction directory"),
            _ => {
                // The mapped text holds no separator and no `:` and does not
                // end in a dot, so pushing it can neither restart the path
                // at a drive or root nor name a parent.
                let written = match rules {
                    NameRules::Windows => windows_component(part),
                    NameRules::Native => Cow::Borrowed(part),
                };
                // And the host's own reading agrees, whatever the rules:
                // one plain component, or the name is refused. This is what
                // refuses `a:b` under native rules on a Windows host.
                let mut read = Path::new(written.as_ref()).components();
                if !matches!(
                    (read.next(), read.next()),
                    (Some(Component::Normal(_)), None)
                ) {
                    return Err("absolute path");
                }
                out.push(written.as_ref());
                components += 1;
            }
        }
    }
    if components == 0 {
        return Err("empty name");
    }
    Ok(())
}

/// [`archive_relative_path_into`] for a name as the file system gets it
/// (`crate::dialect::unrar::disk_name`), which is UTF-8 everywhere but
/// on a host that stores any bytes (Linux), where a RAR 1.3 to 4 8-bit
/// name is written as stored. A UTF-8 name takes the one validation
/// above; any other is split on `/` and judged by the same rules 1 to 3,
/// component by component on its bytes, and never mapped, since only a
/// Windows target maps and a Windows target is never handed one.
pub(crate) fn disk_relative_path_into(
    out: &mut PathBuf,
    root: &Path,
    name: &[u8],
    rules: NameRules,
) -> Result<(), &'static str> {
    match std::str::from_utf8(name) {
        Ok(text) => archive_relative_path_into(out, root, text, rules),
        Err(_) => raw_relative_path_into(out, root, name, rules),
    }
}

#[cfg(unix)]
fn raw_relative_path_into(
    out: &mut PathBuf,
    root: &Path,
    name: &[u8],
    rules: NameRules,
) -> Result<(), &'static str> {
    use std::os::unix::ffi::OsStrExt;
    if rules == NameRules::Windows {
        return Err("name is not UTF-8");
    }
    let mut parts = name.split(|&b| b == b'/');
    if parts.next().is_some_and(<[u8]>::is_empty) {
        return Err("absolute path");
    }
    out.as_mut_os_string().clear();
    out.as_mut_os_string().push(root.as_os_str());
    let mut components = 0;
    for part in name.split(|&b| b == b'/') {
        match part {
            b"" | b"." => {}
            b".." => return Err("path escapes the extraction directory"),
            _ => {
                // Holds no `/` and is neither `.` nor `..`: one plain
                // component to a Unix host, whatever else its bytes are.
                out.push(std::ffi::OsStr::from_bytes(part));
                components += 1;
            }
        }
    }
    if components == 0 {
        return Err("empty name");
    }
    Ok(())
}

#[cfg(not(unix))]
fn raw_relative_path_into(
    _out: &mut PathBuf,
    _root: &Path,
    _name: &[u8],
    _rules: NameRules,
) -> Result<(), &'static str> {
    Err("name is not UTF-8")
}

impl NameRules {
    /// Whether `c` separates components of an archived name under these
    /// rules: `/` everywhere, and `\` too where Win32 reads it so.
    fn is_separator(self, c: char) -> bool {
        c == '/' || (self == NameRules::Windows && c == '\\')
    }
}

/// Whether `part` is exactly a drive designator, `C:`.
fn is_drive(part: &str) -> bool {
    let bytes = part.as_bytes();
    bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

/// A stored name as the progress line shows it: each component mapped
/// under `rules` exactly as `archive_relative_path_under` writes it and
/// the separators kept as stored, so the line names the file on the disk.
pub(crate) fn display_name_under(name: &str, rules: NameRules) -> Cow<'_, str> {
    if rules == NameRules::Native {
        return Cow::Borrowed(name);
    }
    let mut out = String::with_capacity(name.len() + 1);
    let mut changed = false;
    let mut rest = name;
    loop {
        let end = rest.find(|c| rules.is_separator(c)).unwrap_or(rest.len());
        let part = &rest[..end];
        let mapped = if matches!(part, "" | "." | "..") {
            Cow::Borrowed(part)
        } else {
            windows_component(part)
        };
        changed |= matches!(mapped, Cow::Owned(_));
        out.push_str(&mapped);
        match rest[end..].chars().next() {
            Some(sep) => {
                out.push(sep);
                rest = &rest[end + sep.len_utf8()..];
            }
            None => break,
        }
    }
    if changed {
        Cow::Owned(out)
    } else {
        Cow::Borrowed(name)
    }
}

/// [`display_name_under`] under the host's rules.
pub(crate) fn display_name(name: &str) -> Cow<'_, str> {
    display_name_under(name, NameRules::HOST)
}

/// One path component as Win32 will store it unchanged (rule 5).
///
/// Borrowed when nothing needs mapping, which is every ordinary name.
pub(crate) fn windows_component(part: &str) -> Cow<'_, str> {
    let refused = |c: char| {
        matches!(
            c,
            '<' | '>' | ':' | '"' | '|' | '?' | '*' | '\u{0}'..='\u{1f}'
        )
    };
    // Only the LAST character is mapped when it is a dot or a space: the
    // reference writes `b..` as `b._` (SPEC-API-rarkit.md question 20,
    // erratum of 25 Sep 2026), and one `_` is all Win32 needs to keep the
    // rest, since it strips only a trailing dot or space.
    let (kept, trailing) = match part.strip_suffix(['.', ' ']) {
        Some(kept) => (kept, true),
        None => (part, false),
    };
    let reserved = is_reserved_device(part.trim_end_matches(['.', ' ']));
    if !trailing && !reserved && !kept.contains(refused) {
        return Cow::Borrowed(part);
    }
    let mut out = String::with_capacity(part.len() + 1);
    if reserved {
        out.push('_');
    }
    out.extend(kept.chars().map(|c| if refused(c) { '_' } else { c }));
    if trailing {
        out.push('_');
    }
    Cow::Owned(out)
}

/// Whether Win32 reads `name` as a device: its base (up to the first `.`,
/// trailing spaces ignored) is a reserved device name, in any case.
fn is_reserved_device(name: &str) -> bool {
    let base = name.split('.').next().unwrap_or(name).trim_end_matches(' ');
    if ["CON", "PRN", "AUX", "NUL"]
        .iter()
        .any(|device| base.eq_ignore_ascii_case(device))
    {
        return true;
    }
    let Some(head) = base.get(..3) else {
        return false;
    };
    let mut rest = base[3..].chars();
    (head.eq_ignore_ascii_case("COM") || head.eq_ignore_ascii_case("LPT"))
        && matches!(
            (rest.next(), rest.next()),
            (Some('1'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}'), None)
        )
}

/// A member's output file as [`make_member_file`] made it.
pub(crate) struct Created {
    /// The open file the member's bytes, bits and times go through.
    pub(crate) file: File,
    /// `None` where the file stands at the member's own name, which was
    /// free. Where the name was taken, the path the file was made at
    /// instead, in the same directory: it takes the member's name
    /// ([`take_name`]) once the member is whole, and is removed otherwise.
    pub(crate) beside: Option<PathBuf>,
    /// The file that stood at the name was opened and emptied IN PLACE,
    /// because its directory let no file be made beside it
    /// ([`write_in_place`]): the one case where what stood at the name
    /// does not survive a member that fails.
    pub(crate) in_place: bool,
}

/// Creates a member's output file under `policy` (SPEC-CLI 9.4).
///
/// W1: ONE exclusive create at the member's own name, and that create is
/// what answers whether the name is free; nothing asks first. A free name
/// comes back as the open file at that name. Nothing is ever opened that
/// was there already, so no link at the name is written through (W8): an
/// exclusive create is refused by whatever stands at the name, a link to
/// nothing included.
///
/// A taken name is `Ok(None)` under [`IfOutputExists::Keep`], the caller's
/// skip or question. Under [`IfOutputExists::Replace`] it is W7's file
/// BESIDE the name ([`create_beside`]): what stands at the name is not
/// touched here at all, but for the one case [`write_in_place`] states.
///
/// The file is made with `mode` less the umask (ignored off Unix), which
/// the caller keeps inside W4's 666; the bits it ends with are the
/// member's close's.
pub(crate) fn make_member_file(
    path: &Path,
    policy: IfOutputExists,
    mode: u32,
) -> std::io::Result<Option<Created>> {
    make_member_file_with(path, policy, mode, 0)
}

/// [`make_member_file`] with the platform's own open flags (Windows'
/// `dwFlagsAndAttributes`, Unix's `O_*` bits, through std's
/// `OpenOptionsExt::custom_flags`) on its create: the unbuffered
/// writer's `FILE_FLAG_NO_BUFFERING` or `O_DIRECT` for a big member
/// (`dialect::unrar::extract::unbuffered`), so its file is opened once. 0
/// is [`make_member_file`] itself.
pub(crate) fn make_member_file_with(
    path: &Path,
    policy: IfOutputExists,
    mode: u32,
    open_flags: u32,
) -> std::io::Result<Option<Created>> {
    if policy == IfOutputExists::Beside {
        return create_beside(path, mode, open_flags).map(Some);
    }
    match create_exclusive(path, mode, open_flags) {
        Ok(file) => Ok(Some(Created {
            file,
            beside: None,
            in_place: false,
        })),
        Err(taken) if taken.kind() == std::io::ErrorKind::AlreadyExists => match policy {
            IfOutputExists::Keep => Ok(None),
            IfOutputExists::Replace | IfOutputExists::Beside => {
                create_beside(path, mode, open_flags).map(Some)
            }
        },
        Err(refused) => Err(refused),
    }
}

/// One exclusive create of `path` for writing. A create the system refused
/// leaves no file of its own behind ([`forget_refused_create`]).
fn create_exclusive(path: &Path, mode: u32, open_flags: u32) -> std::io::Result<File> {
    create_exclusive_as(path, mode, open_flags, false)
}

/// [`create_exclusive`], and with `renamable` the open file may be given
/// another name THROUGH ITSELF ([`NameAtClose`]): on Windows the create
/// asks for the right to (`DELETE`, beside the rights a file opened to
/// write has); nowhere else is there anything to ask.
fn create_exclusive_as(
    path: &Path,
    mode: u32,
    open_flags: u32,
    renamable: bool,
) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(windows)]
    if renamable {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_GENERIC_WRITE, which is what opening to write asks, and
        // DELETE, which a rename through the handle needs.
        options.access_mode(0x0012_0116 | 0x0001_0000);
    }
    #[cfg(not(windows))]
    let _ = renamable;
    set_create_mode(&mut options, mode);
    leaf_open_flags(&mut options, open_flags);
    options.open(path).inspect_err(|refused| {
        if refused.kind() != std::io::ErrorKind::AlreadyExists {
            forget_refused_create(path, open_flags);
        }
    })
}

/// W7's file BESIDE a taken name (SPEC-CLI 9.4): a new, empty file in the
/// directory of `path`, under a name of this program's own that nothing
/// holds, open for writing with `mode` and `open_flags` exactly as a file
/// at a free name is. What stands at `path` is neither opened nor changed.
///
/// The name is a dot, the program's name, this process's number and a
/// count drawn from one counter of the whole process, so no two creates
/// of a run ask for the same name, on whatever threads. It carries
/// nothing of the member's own name: a long one would then pass the
/// file system's bound on a name.
///
/// Each try is one exclusive create, which follows no link and replaces
/// nothing (W8). A name found taken, another program's file or a link put
/// there, costs that try and the next count is drawn; after
/// [`BESIDE_TRIES`] of them the last refusal is the answer.
///
/// Where the directory lets no file be made in it at all (the create is
/// refused for want of permission), 9.4 has the member written IN PLACE:
/// the file at `path` is opened and emptied by [`write_in_place`] and
/// comes back marked so, for the caller to say once a run. If that open
/// is refused too, the directory's refusal is the answer, being why no
/// file could be made. Any other refusal comes back as it is.
fn create_beside(path: &Path, mode: u32, open_flags: u32) -> std::io::Result<Created> {
    static DRAWN: AtomicU64 = AtomicU64::new(0);
    let folder = path.parent().unwrap_or(Path::new(""));
    let process = std::process::id();
    let mut last_taken = None;
    for _ in 0..BESIDE_TRIES {
        let count = DRAWN.fetch_add(1, Ordering::Relaxed);
        let beside = folder.join(format!(".rarfast-{process}-{count}.new"));
        match create_exclusive_as(&beside, mode, open_flags, true) {
            Ok(file) => {
                return Ok(Created {
                    file,
                    beside: Some(beside),
                    in_place: false,
                })
            }
            Err(taken) if taken.kind() == std::io::ErrorKind::AlreadyExists => {
                last_taken = Some(taken);
            }
            Err(closed) if closed.kind() == std::io::ErrorKind::PermissionDenied => {
                return match write_in_place(path, open_flags) {
                    Ok(file) => Ok(Created {
                        file,
                        beside: None,
                        in_place: true,
                    }),
                    Err(_) => Err(closed),
                };
            }
            Err(refused) => return Err(refused),
        }
    }
    Err(last_taken.unwrap_or_else(|| std::io::ErrorKind::AlreadyExists.into()))
}

/// Opens the regular file that stands at `path` and EMPTIES it, to be
/// written in place: for a taken name in a directory that lets no file be
/// made beside it (settled 10 Oct 2026: an extraction the reference makes,
/// SPEC-CLI 9.2 O9 `taken-in-no-write-directory`, must not start failing
/// here). W7's promise does not hold for such a file, and the caller says
/// so once a run.
///
/// Never through a link (W8): `O_NOFOLLOW` on Unix, and on Windows the
/// name is looked at and held while it is opened ([`hold_no_link`]). Never
/// over a file with another name either ([`only_name`]): that is refused
/// before it is emptied, and the caller writes beside it instead. A
/// file its owner may not write is given the owner's write bit first,
/// through a handle ([`add_owner_write`]), as the reference overwrites a
/// 0444 file; the bits it ends with are the member's close's. On Windows a
/// plain regular file is overwritten in one open
/// (`open_regular_in_place`, Windows only), and everything else as above.
pub(crate) fn write_in_place(path: &Path, open_flags: u32) -> std::io::Result<File> {
    in_place(path, open_flags, None).map(|(file, _)| file)
}

/// [`write_in_place`] for a caller that knows the file's whole new length,
/// `len`, before it opens anything: a member held in memory
/// (`extract::Run::write_held`). On Windows a plain regular file standing at
/// the name is then NOT emptied (FROM-STUDIO 552 A, 553, the x-audio2 form):
/// the caller writes its bytes from offset 0 over what is there, and where
/// the second value is `true`, the old file being longer than `len`, cuts it
/// to `len` after the write. Equal or shorter, no end-of-file call is made:
/// the write itself sets the end.
///
/// **Why (counted on a Windows PC, 17 Oct 2026).** `x` of 8,192 members of
/// one name, 16,000 bytes each, spent 941 us a member in `set_len(0)` on
/// the file the member before had written and closed a few tens of
/// microseconds earlier, 7.7 s of 8.9 s, where the same call over a
/// different file already present took 40 us.
///
/// Every other path is [`write_in_place`]'s, unchanged, the second value
/// `false`: the Unix open, which empties the file, and on Windows anything that is
/// not a plain regular file, which falls to the truncating open.
pub(crate) fn write_in_place_sized(
    path: &Path,
    open_flags: u32,
    len: u64,
) -> std::io::Result<(File, bool)> {
    in_place(path, open_flags, Some(len))
}

/// [`write_in_place`] and [`write_in_place_sized`]: `len` is the new length
/// where the caller knows it.
fn in_place(path: &Path, open_flags: u32, len: Option<u64>) -> std::io::Result<(File, bool)> {
    #[cfg(windows)]
    if let Some(opened) = open_regular_in_place(path, open_flags, len) {
        return Ok(opened);
    }
    #[cfg(not(windows))]
    let _ = len;
    let open = || -> std::io::Result<File> {
        let _held = hold_no_link(path)?;
        let mut options = OpenOptions::new();
        // Not emptied by the open: a file with another name is refused
        // before a byte of it changes ([`only_name`]), then emptied
        // through the handle.
        options.write(true);
        leaf_open_flags(&mut options, open_flags);
        let file = options.open(path)?;
        only_name(&file)?;
        file.set_len(0)?;
        Ok(file)
    };
    let opened = match open() {
        Err(refused)
            if refused.kind() == std::io::ErrorKind::PermissionDenied && add_owner_write(path) =>
        {
            open()
        }
        other => other,
    };
    opened.map(|file| (file, false))
}

/// Windows: [`write_in_place`] in ONE open, for the case it nearly always
/// meets, a plain regular file standing at the name. The name is opened
/// for writing AS ITSELF (`FILE_FLAG_OPEN_REPARSE_POINT`, so a link is
/// opened as the link and never followed) and without emptying it; the
/// SAME handle is asked what it is; and only a regular file that is no
/// reparse point of any kind is emptied, through that handle
/// (`set_len(0)`), and written. Anything else, a link, a reparse point that
/// is no link (a cloud placeholder, opened as it was), a file the open
/// refused (read-only, shared away, a directory), a query or an emptying
/// that failed, drops that handle having changed nothing and is `None`:
/// the caller then takes the path it took before, [`hold_no_link`]'s hold
/// across the truncating open, unchanged.
///
/// **What it keeps.** No link is followed (the only open is as itself), no
/// file of another name is opened or touched, and the file is judged on
/// the very handle written through, so nothing put at the name between the
/// look and the write can be the one written (the hold kept that true
/// across two opens; one open keeps it by construction).
///
/// **Why (FROM-STUDIO 464 A, counted on a Windows PC on 15 Oct 2026).**
/// `x` of 8,192 members all of one name read 818 us a member off CPU, with
/// 19 file system operations a member besides its reads and writes, where
/// 8,192 distinct names read 79 us and 6: the hold's open, query and close
/// and a second, truncating open of a file closed a moment before, per
/// member, were the waiting. This takes out one open and one close a
/// member.
///
/// **Sized** (`len` given, [`write_in_place_sized`]): the same open, query
/// and refusals, and the file is NOT emptied; the second value says the old
/// file is longer than `len` (its length is in the metadata just asked of
/// the handle), for the caller to cut after its write. Not sized, the file
/// is emptied as above and the second value is `false`.
#[cfg(windows)]
fn open_regular_in_place(path: &Path, open_flags: u32, len: Option<u64>) -> Option<(File, bool)> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const REPARSE_POINT: u32 = 0x0400;
    let mut options = OpenOptions::new();
    options
        .write(true)
        .custom_flags(OPEN_REPARSE_POINT | open_flags);
    let file = options.open(path).ok()?;
    let what = file.metadata().ok()?;
    if !what.is_file() || what.file_attributes() & REPARSE_POINT != 0 || only_name(&file).is_err() {
        return None;
    }
    if let Some(len) = len {
        let longer = what.len() > len;
        return Some((file, longer));
    }
    #[cfg(feature = "h2-probes")]
    say_in_place("emptied");
    file.set_len(0).ok()?;
    Some((file, false))
}

/// Refuses an open regular file that has another name besides the one it
/// was opened by (a hard link): written in place, its bytes and its mode
/// would change under that other name too, which may be outside the
/// destination. Until 27 Oct 2026 `x -o+` of a small member over `out/f`,
/// where `out/f` and `elsewhere/f` were one file, wrote the member into
/// `elsewhere/f` and said `All OK`. The caller writes beside and renames
/// instead, which gives the name in the destination a file of its own and
/// leaves the other name as it was.
fn only_name(file: &File) -> std::io::Result<()> {
    if link_count(file)? > 1 {
        return Err(std::io::Error::other(
            "the file at the path has another name",
        ));
    }
    Ok(())
}

/// How many names the open `file` has.
#[cfg(unix)]
fn link_count(file: &File) -> std::io::Result<u64> {
    use std::os::unix::fs::MetadataExt;
    Ok(file.metadata()?.nlink())
}

/// How many names the open `file` has: `GetFileInformationByHandle`'s
/// `nNumberOfLinks`, which the standard library does not give on stable.
#[cfg(windows)]
#[allow(unsafe_code)]
fn link_count(file: &File) -> std::io::Result<u64> {
    use std::os::windows::io::AsRawHandle;
    // `BY_HANDLE_FILE_INFORMATION`: thirteen 32-bit words, the attributes,
    // three times of two words each, the volume, the size's two halves,
    // then the number of links (word 10) and the file index.
    let mut info = [0u32; 13];
    // SAFETY: a plain system call on a handle this process holds open for
    // the length of the call (the `&File` borrow); `info` is a whole
    // `BY_HANDLE_FILE_INFORMATION`, alive across the call, which writes
    // only into it.
    let done = unsafe {
        GetFileInformationByHandle(file.as_raw_handle().cast(), info.as_mut_ptr().cast())
    };
    if done == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(u64::from(info[10]))
}

/// No hard links to count off Unix and Windows.
#[cfg(not(any(unix, windows)))]
fn link_count(_file: &File) -> std::io::Result<u64> {
    Ok(1)
}

/// `h2-probes` builds only (no shipped build reads it):
/// `RARFAST_IN_PLACE_SAY=1` says on stderr each step of a write in place
/// that `tests/held_in_place.rs` counts, one line a step:
/// `rarfast in place: <what>`.
#[cfg(feature = "h2-probes")]
pub(crate) fn say_in_place(what: &str) {
    if std::env::var("RARFAST_IN_PLACE_SAY").is_ok_and(|v| v.trim() == "1") {
        eprintln!("rarfast in place: {what}");
    }
}

/// How many names [`create_beside`] tries before it gives the create up:
/// each is this process's number and a count no other member of the run
/// has used, so a taken one is another program's file.
const BESIDE_TRIES: usize = 64;

/// W7's last step: the whole, verified file at `beside` takes the member's
/// name, `name`, in one rename. What stood at the name is replaced by it
/// at that moment and not before; a link there goes as the link it is,
/// never what it leads to (W8).
///
/// Windows refuses the rename over two things Unix does not: a file that
/// carries the read-only attribute, and a link to a directory. The
/// attribute is taken off through a handle ([`add_owner_write`]) and the
/// directory link removed as itself, and the rename made once more.
pub(crate) fn take_name(beside: &Path, name: &Path) -> std::io::Result<()> {
    match std::fs::rename(beside, name) {
        Ok(()) => Ok(()),
        Err(first) => {
            if cleared_for_rename(name) {
                std::fs::rename(beside, name)
            } else {
                Err(first)
            }
        }
    }
}

/// W7's rename made THROUGH THE MEMBER'S OWN OPEN FILE, where the system
/// has such a call, so that it costs no second open and close of the
/// file: on Windows a rename by name is an open, the set of the name and
/// a close, and over 20,000 replaced files those were most of what a
/// replace cost beyond writing in place (counted on a Windows PC, 11 Oct
/// 2026).
///
/// One of these is made when a member is created beside a taken name, and
/// shared by the member's open file and the run. The run ARMS it when the
/// member is known whole and verified, which is before its file is
/// closed; the file, as it closes, then gives itself the name; and
/// [`NameAtClose::given`] tells the run whether [`take_name`] is still
/// owed (it is wherever the system has no such call, or refused it).
#[derive(Clone)]
pub(crate) struct NameAtClose {
    name: PathBuf,
    state: std::sync::Arc<std::sync::atomic::AtomicU8>,
}

impl NameAtClose {
    const WAITING: u8 = 0;
    const ARMED: u8 = 1;
    const GIVEN: u8 = 2;

    /// For a member whose name, once whole, is `name`.
    pub(crate) fn new(name: &Path) -> Self {
        Self {
            name: name.to_path_buf(),
            state: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(Self::WAITING)),
        }
    }

    /// The member is whole and verified: its file may take the name as
    /// it closes.
    pub(crate) fn arm(&self) {
        self.state
            .store(Self::ARMED, std::sync::atomic::Ordering::Release);
    }

    /// Called by the member's open file as it closes, after its bits and
    /// times are set: gives the file the name if the run armed this.
    pub(crate) fn close_of(&self, file: &File) {
        use std::sync::atomic::Ordering;
        if self.state.load(Ordering::Acquire) == Self::ARMED
            && rename_open_file(file, &self.name).is_ok()
        {
            self.state.store(Self::GIVEN, Ordering::Release);
        }
    }

    /// Whether the file took the name as it closed.
    pub(crate) fn given(&self) -> bool {
        self.state.load(std::sync::atomic::Ordering::Acquire) == Self::GIVEN
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
#[link(name = "kernel32")]
extern "system" {
    /// The system call of this module that the standard library does not
    /// wrap, declared ONCE: for the attribute word
    /// ([`set_attribute_word`]), for the rename through an open file
    /// ([`rename_open_file`]) and for the room kept for a file
    /// ([`set_allocation_size`]).
    fn SetFileInformationByHandle(
        file: *mut core::ffi::c_void,
        class: i32,
        info: *const core::ffi::c_void,
        size: u32,
    ) -> i32;
    /// Its reading twin, for the number of a file's names
    /// ([`link_count`]).
    fn GetFileInformationByHandle(
        file: *mut core::ffi::c_void,
        info: *mut core::ffi::c_void,
    ) -> i32;
}

/// Windows: sets how much room the system keeps for the open `file` to
/// `bytes`, WITHOUT moving its end: the allocation-size class of
/// `SetFileInformationByHandle`. `false` where the file system refuses.
/// For the extract's reservation (`extract::output::reserve_room`); room
/// kept past the file's end is given back by the system at its close.
#[cfg(windows)]
#[allow(unsafe_code)]
pub(crate) fn set_allocation_size(file: &File, bytes: u64) -> bool {
    use std::os::windows::io::AsRawHandle;
    /// `FileAllocationInfo`.
    const ALLOCATION: i32 = 5;
    let Ok(size) = i64::try_from(bytes) else {
        return false;
    };
    // SAFETY: a plain system call on a handle this process holds open for
    // the length of the call (the `&File` borrow); `size` is a whole
    // `FILE_ALLOCATION_INFO` (one 64-bit integer) that lives across the
    // call, which only reads it.
    unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle().cast(),
            ALLOCATION,
            (&raw const size).cast(),
            8,
        ) != 0
    }
}

/// Windows: gives the open `file` the name `name`, replacing what stands
/// there, through its own handle (which must have been opened with the
/// right to: [`create_exclusive_as`]).
///
/// `FILE_RENAME_INFO` is a flags word, a root handle (none: the name is a
/// whole path) and the name's length in bytes, then the name in UTF-16.
/// The class is `FileRenameInfoEx` with replace-if-exists, POSIX
/// semantics (the name is replaced though another process has the old
/// file open) and ignore-read-only. A system that does not know the
/// class, or refuses the rename, is an error here and the caller's
/// rename by name is then made instead.
#[cfg(windows)]
#[allow(unsafe_code)]
fn rename_open_file(file: &File, name: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    /// `FileRenameInfoEx`.
    const RENAME_EX: i32 = 22;
    /// `FILE_RENAME_FLAG_REPLACE_IF_EXISTS`, `..._POSIX_SEMANTICS` and
    /// `..._IGNORE_READONLY_ATTRIBUTE`.
    const FLAGS: u16 = 0x1 | 0x2 | 0x40;
    /// The 16-bit units before the name: flags (2), padding (2), the
    /// root handle (4), the length (2).
    const HEAD: usize = 10;
    let whole = std::path::absolute(name)?;
    let wide: Vec<u16> = whole.as_os_str().encode_wide().collect();
    let name_bytes = u32::try_from(wide.len() * 2)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let mut units = vec![0u16; HEAD + wide.len() + 1];
    units[0] = FLAGS;
    // The length's two halves, low first.
    #[allow(clippy::cast_possible_truncation)]
    {
        units[8] = name_bytes as u16;
        units[9] = (name_bytes >> 16) as u16;
    }
    units[HEAD..HEAD + wide.len()].copy_from_slice(&wide);
    // Packed into 64-bit words so the structure is aligned as its handle
    // field wants; little-endian, as every Windows target is.
    let words: Vec<u64> = units
        .chunks(4)
        .map(|four| {
            four.iter().enumerate().fold(0u64, |word, (at, unit)| {
                word | u64::from(*unit) << (16 * at)
            })
        })
        .collect();
    let size = u32::try_from(units.len() * 2)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: a plain system call on a handle this process holds open for
    // the length of the call (the `&File` borrow); `words` is a whole
    // `FILE_RENAME_INFO` of at least `size` bytes, alive across the call,
    // which the call only reads.
    let done = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle().cast(),
            RENAME_EX,
            words.as_ptr().cast(),
            size,
        )
    };
    if done != 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Off Windows a rename by name is one call already, and it is the one
/// made ([`take_name`]).
#[cfg(not(windows))]
fn rename_open_file(_file: &File, _name: &Path) -> std::io::Result<()> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

/// Windows: whether something that refused [`take_name`]'s rename was
/// taken out of its way.
#[cfg(windows)]
fn cleared_for_rename(name: &Path) -> bool {
    if std::fs::symlink_metadata(name).is_ok_and(|there| there.file_type().is_symlink()) {
        // Only a link to a directory is removed as a directory.
        return std::fs::remove_dir(name).is_ok();
    }
    add_owner_write(name)
}

/// Off Windows a refused rename is the answer.
#[cfg(not(windows))]
fn cleared_for_rename(_name: &Path) -> bool {
    false
}

/// Removes the EMPTY file a refused exclusive create left at `path`, where
/// the create carried open flags of its own.
///
/// Linux can make the file and then refuse the open: a direct open
/// (`O_DIRECT`) of a file on a filesystem with no direct I/O is refused
/// with `EINVAL` AFTER the create has made the inode (tmpfs before Linux
/// 6.6, ramfs still). The caller's answer to a refused direct open is to
/// create the member cached, and that second exclusive create then found
/// the file THIS call had just made and took it for one already on disk:
/// kept and skipped under `-o-` (a 0 byte file, exit 0), asked about
/// under the default rule, renamed around for ever under `-or`.
///
/// The create was exclusive, so a file at the path before it would have
/// been `AlreadyExists`, which never comes here: an empty regular file
/// there now is the one this call made. Only that is removed, by name
/// (a link at the name is not a regular file and is left). One `lstat`
/// and one `unlink`, on a REFUSED create with flags only: nothing on any
/// create that is taken, and nothing on a cached one.
#[cfg(unix)]
fn forget_refused_create(path: &Path, open_flags: u32) {
    if open_flags == 0 {
        return;
    }
    if std::fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file() && meta.len() == 0) {
        let _ = std::fs::remove_file(path);
    }
}

/// Windows' refused create makes no file.
#[cfg(not(unix))]
fn forget_refused_create(_path: &Path, _open_flags: u32) {}

/// Windows: refuses a symbolic link (or a junction) standing at `path`,
/// and returns a handle that keeps the name from being given to one until
/// it is dropped. For the overwriting open (and the second open of a
/// member, [`reopen_output_file`]), which on Windows has no flag
/// of its own for it: opened with create and truncate it goes THROUGH a
/// link at the final component, and the member's bytes truncated and
/// replaced the link's target, a file outside the destination
/// (`x -o+` over a `report.txt` that is a link to `important.doc`
/// elsewhere). On Unix the same open carries `O_NOFOLLOW` and is refused.
///
/// The path is opened AS ITSELF (the reparse point, not what it leads
/// to), for no access, sharing read and write but NOT delete: while the
/// handle is held the name cannot be removed or renamed over, so what was
/// looked at is what the overwriting open then opens. A link is an error,
/// which the caller answers as it answers Unix's refusal: the link is
/// removed and the member created in its place. A name that is gone is
/// left to the open, whose create makes it.
///
/// THE COST, on Windows, per file that is there and overwritten (`-o+`,
/// `-y`, or a yes at the question), and nowhere else: three calls, an
/// open, a query and a close. A reparse point that is no link (a cloud
/// placeholder, say) is opened as it was.
#[cfg(windows)]
fn hold_no_link(path: &Path) -> std::io::Result<Option<File>> {
    use std::os::windows::fs::OpenOptionsExt;
    const SHARE_READ_WRITE: u32 = 0x1 | 0x2;
    // FILE_FLAG_OPEN_REPARSE_POINT, and FILE_FLAG_BACKUP_SEMANTICS so a
    // directory link opens too.
    const AS_ITSELF: u32 = 0x0020_0000 | 0x0200_0000;
    let mut options = OpenOptions::new();
    options
        .access_mode(0)
        .share_mode(SHARE_READ_WRITE)
        .custom_flags(AS_ITSELF);
    let held = match options.open(path) {
        Ok(held) => held,
        Err(gone) if gone.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(refused) => return Err(refused),
    };
    if held.metadata()?.file_type().is_symlink() {
        return Err(std::io::Error::other(
            "a link stands at the path of a file to overwrite",
        ));
    }
    Ok(Some(held))
}

/// Unix: the overwriting open carries `O_NOFOLLOW` itself.
#[cfg(not(windows))]
fn hold_no_link(_path: &Path) -> std::io::Result<Option<File>> {
    Ok(None)
}

/// Gives the owner of the existing regular FILE at `path` its write bit, so
/// an overwrite the mode refused can be made; `false` where nothing was
/// changed.
///
/// For [`write_in_place`] alone: a file in a directory that may be written
/// to is never opened, it is replaced by a rename. MEASURED against unrar
/// 7.23 and rar 7.23 (x86-64 Linux, 1 Oct 2026, an ordinary user, umask
/// 022): `x -o+` over a file that is there with mode `0444` in a directory
/// of mode `0555` overwrites it in place and leaves it with the member's
/// stored mode.
///
/// The bit goes on THROUGH A HANDLE opened without following a link, never
/// by name, so a link at the path cannot send the change elsewhere. A file
/// its owner may not READ either (`0000`) cannot be opened for it and is
/// refused: the only other way is a change of mode by name.
#[cfg(unix)]
fn add_owner_write(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    // A regular file by name first: opening a FIFO to read would wait for
    // its writer.
    if !std::fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file()) {
        return false;
    }
    let mut options = OpenOptions::new();
    options.read(true);
    refuse_link_leaf(&mut options);
    let Ok(held) = options.open(path) else {
        return false;
    };
    let Ok(meta) = held.metadata() else {
        return false;
    };
    let had = meta.permissions().mode() & 0o7777;
    // A file with another name keeps its mode: the bit would show under
    // that name too ([`only_name`]).
    meta.is_file()
        && only_name(&held).is_ok()
        && had & 0o200 == 0
        && held
            .set_permissions(std::fs::Permissions::from_mode(had | 0o200))
            .is_ok()
}

/// Windows: takes the READ-ONLY attribute off the existing regular file at
/// `path`, so that the rename which replaces it can be made
/// ([`take_name`]) or, in a directory that lets no file be made beside it,
/// the file be written in place ([`write_in_place`]); `false` where
/// nothing was changed.
///
/// The attribute goes THROUGH A HANDLE that follows no link
/// (`FILE_FLAG_OPEN_REPARSE_POINT`), opened for the attributes alone: a
/// handle opened to read cannot take it off (os error 5, counted on a
/// Windows desktop, 2 Oct 2026), and one opened for
/// `FILE_WRITE_ATTRIBUTES` opens whatever the file carries. The standard
/// library's `set_permissions` is not used for it: see
/// [`set_attribute_word`].
#[cfg(windows)]
fn add_owner_write(path: &Path) -> bool {
    use std::os::windows::fs::OpenOptionsExt;
    // FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES.
    const ATTRIBUTES: u32 = 0x0080 | 0x0100;
    const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let mut options = OpenOptions::new();
    options
        .access_mode(ATTRIBUTES)
        .custom_flags(OPEN_REPARSE_POINT);
    let Ok(held) = options.open(path) else {
        return false;
    };
    let Ok(meta) = held.metadata() else {
        return false;
    };
    use std::os::windows::fs::MetadataExt;
    const READ_ONLY: u32 = 0x01;
    const NORMAL: u32 = 0x80;
    let word = meta.file_attributes();
    // A file with another name keeps its attributes: they would show under
    // that name too ([`only_name`]).
    if !meta.is_file() || word & READ_ONLY == 0 || only_name(&held).is_err() {
        return false;
    }
    // Every other attribute stays; a file left with none is NORMAL,
    // since a word of 0 changes nothing ([`set_attribute_word`]).
    let rest = word & !READ_ONLY;
    set_attribute_word(&held, if rest == 0 { NORMAL } else { rest })
}

/// Windows: sets the open file's attribute word to exactly `attributes`,
/// through its handle (never by name, so a link put at the path meanwhile
/// cannot send the change elsewhere); its times are left as they are.
///
/// The standard library can only take read-only on or off (its
/// `set_permissions`), and that cannot even leave a file with no attribute
/// at all: it would pass a word of 0, which the system reads as "change
/// nothing" (counted on a Windows desktop, 2 Oct 2026: a file whose word was
/// read-only alone stayed read-only). A hidden or system attribute has to
/// go too. So this is the one system call that is not wrapped:
/// `SetFileInformationByHandle` with a `FILE_BASIC_INFO`, declared here as
/// `unbuffered`'s `fcntl` is. A word of 0 is never passed: the caller says
/// `FILE_ATTRIBUTE_NORMAL` for "none".
#[cfg(windows)]
#[allow(unsafe_code)]
pub(crate) fn set_attribute_word(file: &File, attributes: u32) -> bool {
    use std::os::windows::io::AsRawHandle;
    /// `FILE_BASIC_INFO`: four times in 100 ns ticks, where 0 leaves the
    /// time unchanged, then the attributes.
    #[repr(C)]
    struct BasicInfo {
        creation: i64,
        access: i64,
        write: i64,
        change: i64,
        attributes: u32,
    }
    /// `FileBasicInfo`.
    const BASIC: i32 = 0;
    let info = BasicInfo {
        creation: 0,
        access: 0,
        write: 0,
        change: 0,
        attributes,
    };
    // The size of a 40-byte structure fits.
    #[allow(clippy::cast_possible_truncation)]
    let size = std::mem::size_of::<BasicInfo>() as u32;
    // SAFETY: a plain system call on a handle this process holds open for
    // the length of the call (the `&File` borrow); `info` points at a
    // whole `FILE_BASIC_INFO` of the size passed, which the call only
    // reads, and nothing of ours is written.
    unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle().cast(),
            BASIC,
            (&raw const info).cast(),
            size,
        ) != 0
    }
}

/// See the Unix [`add_owner_write`].
#[cfg(not(any(unix, windows)))]
fn add_owner_write(_path: &Path) -> bool {
    false
}

/// Opens the member file at `path` AGAIN for writing, through the cache,
/// refusing a symbolic link at the final component as
/// [`make_member_file`] did when it made the file: the unbuffered
/// writer's fall back (`unbuffered::Staged`) opens a member a second time
/// by name, and between the two opens the name can be swapped for a link.
/// Nothing is created or truncated; a name that is gone is an error.
///
/// On Windows the open has no flag that refuses a link, and until 4 Oct
/// 2026 this set nothing there: it went through a link at the name. It now
/// looks first and holds the name while it opens, as the overwriting open
/// does ([`hold_no_link`]): three calls more, on the fall back alone.
pub(crate) fn reopen_output_file(path: &Path) -> std::io::Result<File> {
    let _held = hold_no_link(path)?;
    let mut options = OpenOptions::new();
    options.write(true);
    refuse_link_leaf(&mut options);
    options.open(path)
}

/// Windows: `extra` onto `options` when there are any. Windows' no-follow
/// is not set through the same field (it sets nothing, below), so these
/// flags replace nothing.
#[cfg(windows)]
fn leaf_open_flags(options: &mut OpenOptions, extra: u32) {
    if extra != 0 {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(extra);
    }
}

#[cfg(not(any(unix, windows)))]
fn leaf_open_flags(_options: &mut OpenOptions, _extra: u32) {}

/// Unix: the mode a new file is created with, before the umask.
#[cfg(unix)]
fn set_create_mode(options: &mut OpenOptions, mode: u32) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(mode);
}

#[cfg(not(unix))]
fn set_create_mode(_options: &mut OpenOptions, _mode: u32) {}

/// Opens an existing directory to set its mode and time, refusing a
/// symbolic link at the final component as [`make_member_file`] does:
/// a link planted where a directory member was cannot redirect the change
/// outside the tree.
pub(crate) fn open_directory(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_BACKUP_SEMANTICS, without which Windows will not open
        // a directory; FILE_WRITE_ATTRIBUTES to set its time.
        options.access_mode(0x0100).custom_flags(0x0200_0000);
    }
    refuse_link_leaf(&mut options);
    options.open(path)
}

/// Unix: refuse to open through a symbolic link at the final component.
#[cfg(unix)]
fn refuse_link_leaf(options: &mut OpenOptions) {
    leaf_open_flags(options, 0);
}

/// Unix: [`refuse_link_leaf`] with `extra` open flags beside it, in the one
/// `custom_flags` call.
#[cfg(unix)]
fn leaf_open_flags(options: &mut OpenOptions, extra: u32) {
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc_o_nofollow() | extra as i32);
}

/// `O_NOFOLLOW`'s value, which is not the same number on every Unix.
///
/// It is spelled out rather than taken from `libc` so that this crate does
/// not grow a dependency for one constant. Linux's value is per
/// architecture, not one number: the generic one, and arm's and arm64's
/// own. Anything not named gets 0, which
/// costs the flag rather than opening the wrong file - and `create_new`
/// still refuses an existing link under the default policy.
#[cfg(unix)]
fn libc_o_nofollow() -> i32 {
    if cfg!(any(target_os = "macos", target_os = "ios")) {
        0x0100
    } else if cfg!(all(
        target_os = "linux",
        any(target_arch = "aarch64", target_arch = "arm")
    )) {
        // arm64 and arm override the generic value; 0o400000 there is
        // O_LARGEFILE, which is what this used to pass on aarch64 Linux,
        // so a link at the final component was followed (27 Sep 2026).
        0o100000
    } else if cfg!(all(
        target_os = "linux",
        any(
            target_arch = "x86_64",
            target_arch = "x86",
            target_arch = "riscv64",
            target_arch = "loongarch64"
        )
    )) {
        0o400000
    } else {
        0
    }
}

/// Windows: the standard library's `create_new` does not follow a reparse
/// point, and the overwrite arm and the second open of a member
/// ([`reopen_output_file`]), which have no flag for it, look first
/// ([`hold_no_link`]). [`open_directory`] sets nothing here.
#[cfg(not(unix))]
fn refuse_link_leaf(_options: &mut OpenOptions) {}

#[cfg(test)]
mod pooled_tests {
    use super::*;

    /// One reused buffer resolves every name exactly as a fresh one does,
    /// and refuses exactly the names a fresh one refuses, whatever the
    /// buffer held before: under both rule sets and over both roots.
    #[test]
    fn a_reused_buffer_resolves_as_a_fresh_one() {
        let names = [
            "a.txt",
            "sub/nested.txt",
            "sub//x",
            "./a",
            "a/./b",
            "..",
            "../x",
            "a/../b",
            "/abs",
            "",
            ".",
            "a.",
            "a ",
            "con",
            "x:y.txt",
            "C:/x",
            "a\\b",
            "\\\\srv\\s",
            "d/e/f/g.bin",
            "\u{e9}t\u{e9}/\u{1f600}",
            "a/",
            "a:b",
            "trailing./x",
        ];
        let mut buf = PathBuf::from("/left/over/from/before");
        for root in [Path::new(""), Path::new("out"), Path::new("/tmp/o u t")] {
            for rules in [NameRules::Native, NameRules::Windows] {
                for name in names {
                    let fresh = archive_relative_path_under(root, name, rules);
                    let reused = archive_relative_path_into(&mut buf, root, name, rules);
                    match (fresh, reused) {
                        (Ok(path), Ok(())) => assert_eq!(path, buf, "{root:?} {name:?} {rules:?}"),
                        (Err(a), Err(b)) => assert_eq!(a, b, "{root:?} {name:?} {rules:?}"),
                        (a, b) => panic!("{root:?} {name:?} {rules:?}: {a:?} against {b:?}"),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_parent_component_is_refused_wherever_it_sits() {
        let root = Path::new("/tmp/out");
        assert!(archive_relative_path(root, "../escape.txt").is_err());
        assert!(archive_relative_path(root, "sub/../../escape.txt").is_err());
        assert!(archive_relative_path(root, "sub/..").is_err());
    }

    #[test]
    fn an_absolute_name_is_refused_rather_than_rebased() {
        let root = Path::new("/tmp/out");
        assert!(archive_relative_path(root, "/etc/passwd").is_err());
    }

    #[test]
    fn an_ordinary_name_lands_under_the_root() {
        let root = Path::new("/tmp/out");
        assert_eq!(
            archive_relative_path(root, "sub/./nested.txt").unwrap(),
            Path::new("/tmp/out/sub/nested.txt")
        );
    }

    // --- rule 5: names a Windows target cannot store as written ---

    fn windows(name: &str) -> PathBuf {
        archive_relative_path_under(Path::new("/tmp/out"), name, NameRules::Windows).unwrap()
    }

    fn native(name: &str) -> PathBuf {
        archive_relative_path_under(Path::new("/tmp/out"), name, NameRules::Native).unwrap()
    }

    /// The case that found it: a member of a `Pack.resources` directory
    /// whose name ends in a dot. Win32 would strip it; the reference
    /// writes it as `_`.
    #[test]
    fn a_trailing_dot_is_written_as_an_underscore_on_windows_only() {
        let name = "Pack.resources/Zq7hTn2LxWm4RvB9sKdP.";
        assert_eq!(
            windows(name),
            Path::new("/tmp/out/Pack.resources/Zq7hTn2LxWm4RvB9sKdP_")
        );
        assert_eq!(native(name), Path::new("/tmp/out").join(name));
        // A directory component as well as a file, and only the LAST dot
        // of a run: the reference writes `b..` as `b._` (question 20,
        // erratum of 25 Sep 2026), where this rule once wrote `b__`.
        assert_eq!(windows("dir./a.."), Path::new("/tmp/out/dir_/a._"));
        assert_eq!(windows("b.."), Path::new("/tmp/out/b._"));
        // A component of three dots is a name, not a parent, either way.
        assert_eq!(windows("..."), Path::new("/tmp/out/.._"));
        assert_eq!(native("..."), Path::new("/tmp/out/..."));
    }

    #[test]
    fn a_trailing_space_is_written_as_an_underscore_on_windows() {
        assert_eq!(windows("a "), Path::new("/tmp/out/a_"));
        assert_eq!(windows("a. "), Path::new("/tmp/out/a._"));
        assert_eq!(windows("a ."), Path::new("/tmp/out/a _"));
        assert_eq!(windows(" lead"), Path::new("/tmp/out/ lead"));
        assert_eq!(native("a "), Path::new("/tmp/out/a "));
    }

    #[test]
    fn a_reserved_device_name_gains_an_underscore_prefix_on_windows() {
        assert_eq!(windows("CON"), Path::new("/tmp/out/_CON"));
        assert_eq!(windows("sub/nul.txt"), Path::new("/tmp/out/sub/_nul.txt"));
        assert_eq!(windows("Com1 .log"), Path::new("/tmp/out/_Com1 .log"));
        assert_eq!(windows("lpt9"), Path::new("/tmp/out/_lpt9"));
        assert_eq!(windows("COM\u{b9}"), Path::new("/tmp/out/_COM\u{b9}"));
        // Only the exact device names: a longer base is an ordinary name.
        for ordinary in ["CONSOLE", "COM0", "COM10", "auxiliary.txt", "NULL"] {
            assert_eq!(windows(ordinary), Path::new("/tmp/out").join(ordinary));
        }
        assert_eq!(native("CON"), Path::new("/tmp/out/CON"));
    }

    /// A `:` would otherwise write an NTFS alternate data stream of the
    /// file before it rather than a file of this name.
    #[test]
    fn a_character_win32_refuses_is_written_as_an_underscore_on_windows() {
        assert_eq!(windows("x/a:b"), Path::new("/tmp/out/x/a_b"));
        assert_eq!(windows("q?<>\"|*.txt"), Path::new("/tmp/out/q______.txt"));
        assert_eq!(windows("tab\there"), Path::new("/tmp/out/tab_here"));
        // Native rules on a Windows host are a test-only pairing; there
        // the host reads `a:b` as a drive, so the name is refused rather
        // than rebased (the defect this test once hit on a Windows desktop).
        if cfg!(windows) {
            let root = Path::new("/tmp/out");
            assert!(archive_relative_path_under(root, "x/a:b", NameRules::Native).is_err());
        } else {
            assert_eq!(native("x/a:b"), Path::new("/tmp/out/x/a:b"));
        }
    }

    /// `x:y.txt` is a name with a colon in it, mapped as the reference
    /// maps it, not a drive-relative path to refuse (found on Windows,
    /// 25 Sep 2026: the check read `x:` as a drive before the mapping).
    #[test]
    fn a_colon_inside_a_first_component_is_mapped_not_read_as_a_drive() {
        assert_eq!(windows("x:y.txt"), Path::new("/tmp/out/x_y.txt"));
        assert_eq!(windows("C:x"), Path::new("/tmp/out/C_x"));
        assert_eq!(windows("dir/C:"), Path::new("/tmp/out/dir/C_"));
        assert_eq!(windows("ab:/c"), Path::new("/tmp/out/ab_/c"));
    }

    /// Mapping first is not loosening: every genuinely absolute or
    /// escaping name is still refused under the Windows rules, on any
    /// host, whichever separator it uses.
    #[test]
    fn a_drive_absolute_unc_or_escaping_name_is_still_refused_on_windows() {
        let root = Path::new("/tmp/out");
        for hostile in [
            "C:/Windows/x.dll",
            "C:\\Windows\\x.dll",
            "c:",
            "Z:\\",
            "\\x.txt",
            "/x.txt",
            "\\\\server\\share\\x.txt",
            "\\\\?\\C:\\x.txt",
            "//server/share/x.txt",
            "..\\x.txt",
            "a\\..\\..\\x.txt",
            "a/../x.txt",
            "..",
            "",
            ".",
            "./\\.",
        ] {
            assert!(
                archive_relative_path_under(root, hostile, NameRules::Windows).is_err(),
                "{hostile:?} was accepted"
            );
        }
        // A backslash separates on Windows, so `sub\.\f` is `sub/f`.
        assert_eq!(windows("sub\\.\\f"), Path::new("/tmp/out/sub/f"));
    }

    /// What a Windows run joins is always under the root: the written path
    /// starts with it and adds exactly the stored component count.
    #[test]
    fn every_mapped_name_stays_under_the_root() {
        let root = Path::new("/tmp/out");
        for name in ["x:y.txt", "a:b/c:d", "CON/aux.", "q?/r*", "b..", "C:x/y"] {
            let path = archive_relative_path_under(root, name, NameRules::Windows).unwrap();
            let rest = path.strip_prefix(root).unwrap();
            assert_eq!(rest.components().count(), name.split('/').count(), "{name}");
            assert!(rest.components().all(|c| matches!(c, Component::Normal(_))));
        }
    }

    /// A DIFFERENCE FROM THE REFERENCE, kept on purpose (SPEC-API-rarkit.md
    /// question 20, second erratum; read so on 25 Sep 2026):
    /// UnRAR 7.23 on Windows 11 writes `nul.txt` unchanged and
    /// prefixes only a bare device name (`CON`, `COM1`). rarkit-cli
    /// prefixes a device base with an extension too, because on Windows 10
    /// and earlier `nul.txt` opens the device and the member's data is
    /// silently lost.
    #[test]
    fn a_device_name_with_an_extension_keeps_its_prefix_unlike_unrar_on_windows_11() {
        assert_eq!(windows("nul.txt"), Path::new("/tmp/out/_nul.txt"));
        assert_eq!(windows("COM1"), Path::new("/tmp/out/_COM1"));
        assert_eq!(
            display_name_under("nul.txt", NameRules::Windows),
            "_nul.txt"
        );
    }

    #[test]
    fn the_progress_name_is_the_written_name_on_windows_only() {
        let shown = |name| display_name_under(name, NameRules::Windows).into_owned();
        assert_eq!(shown("a."), "a_");
        assert_eq!(shown("b.."), "b._");
        assert_eq!(shown("CON"), "_CON");
        assert_eq!(shown("x:y.txt"), "x_y.txt");
        assert_eq!(shown("dir./inner.txt"), "dir_/inner.txt");
        assert_eq!(shown("dir.\\inner."), "dir_\\inner_");
        assert_eq!(shown("trail "), "trail_");
        assert!(matches!(
            display_name_under("sub\\ordinary.txt", NameRules::Windows),
            Cow::Borrowed(_)
        ));
        assert_eq!(display_name_under("a.", NameRules::Native), "a.");
    }

    #[test]
    fn a_name_that_needs_nothing_is_borrowed_and_unchanged() {
        for name in ["ordinary.txt", "a", "a.b.c", ".hidden", "caf\u{e9}"] {
            assert!(
                matches!(windows_component(name), Cow::Borrowed(_)),
                "{name}"
            );
        }
        assert_eq!(windows("sub/ordinary.txt"), native("sub/ordinary.txt"));
        // The traversal rules hold under both rule sets.
        let root = Path::new("/tmp/out");
        for rules in [NameRules::Native, NameRules::Windows] {
            assert!(archive_relative_path_under(root, "../x.", rules).is_err());
            assert!(archive_relative_path_under(root, "/x.", rules).is_err());
        }
    }

    /// A name that is not UTF-8 (a RAR 1.3 to 4 8-bit name on Linux) is
    /// judged by the same rules on its bytes: kept whole where it is one
    /// plain component, refused where any component is `..` or it starts
    /// at the root, and never handed to the Windows mapping.
    #[cfg(unix)]
    #[test]
    fn a_name_that_is_not_utf8_is_judged_on_its_bytes() {
        use std::os::unix::ffi::OsStrExt;
        let root = Path::new("/tmp/out");
        let mut buf = PathBuf::new();
        disk_relative_path_into(&mut buf, root, b"s/./caf\xe9\\x", NameRules::Native).unwrap();
        assert_eq!(buf.as_os_str().as_bytes(), b"/tmp/out/s/caf\xe9\\x");
        for hostile in [
            &b"../caf\xe9"[..],
            b"a/../../\xff",
            b"\xff/..",
            b"/\xff",
            b"\xff/../x",
        ] {
            assert!(
                disk_relative_path_into(&mut buf, root, hostile, NameRules::Native).is_err(),
                "{hostile:?} was accepted"
            );
        }
        assert!(disk_relative_path_into(&mut buf, root, b"a\xff", NameRules::Windows).is_err());
        // A UTF-8 name takes the one validation `archive_relative_path`
        // runs, so the two entries agree on it.
        disk_relative_path_into(&mut buf, root, b"a\\b/c", NameRules::Native).unwrap();
        assert_eq!(
            buf,
            archive_relative_path_under(root, "a\\b/c", NameRules::Native).unwrap()
        );
    }

    #[test]
    fn the_host_rules_are_windows_exactly_on_windows() {
        assert_eq!(NameRules::HOST == NameRules::Windows, cfg!(windows));
    }

    /// `a.` and `a` no longer collide on Windows; `a.` and `a_` do, and
    /// that collision is the overwrite policy's, as for a file already on
    /// the disk: under `Never` the first member's file is kept.
    #[test]
    fn a_collision_after_the_mapping_is_the_overwrite_policys() {
        assert_ne!(windows("a."), windows("a"));
        assert_eq!(windows("a."), windows("a_"));
        let dir = std::env::temp_dir().join(format!(
            "rarkit-cli-safepath-collide-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let first = archive_relative_path_under(&dir, "a_", NameRules::Windows).unwrap();
        let second = archive_relative_path_under(&dir, "a.", NameRules::Windows).unwrap();
        std::fs::write(&first, b"first").unwrap();
        assert!(make_member_file(&second, IfOutputExists::Keep, 0o666)
            .unwrap()
            .is_none());
        assert_eq!(std::fs::read(&first).unwrap(), b"first");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The second open of a member refuses a symbolic link standing at its
    /// name, on every system: the bytes written after it must never reach
    /// the link's target. No pool and no memory to speak of. Where this user
    /// may not create a symbolic link (Windows without the privilege or
    /// developer mode) the test SAYS so and passes, having tested nothing.
    #[test]
    fn a_reopen_refuses_a_link_at_the_final_component() {
        use std::io::Write;
        let dir =
            std::env::temp_dir().join(format!("rarkit-cli-safepath-reopen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("o")).unwrap();
        let victim = dir.join("important.doc");
        std::fs::write(&victim, b"precious").unwrap();

        // An ordinary file is opened again and written.
        let plain = dir.join("o").join("plain.bin");
        std::fs::write(&plain, b"first").unwrap();
        reopen_output_file(&plain)
            .expect("an ordinary file opens again")
            .write_all(b"again")
            .unwrap();
        assert_eq!(std::fs::read(&plain).unwrap(), b"again");

        let link = dir.join("o").join("member.bin");
        #[cfg(unix)]
        let made = std::os::unix::fs::symlink(&victim, &link);
        #[cfg(windows)]
        let made = std::os::windows::fs::symlink_file(&victim, &link);
        #[cfg(not(any(unix, windows)))]
        let made: std::io::Result<()> = Err(std::io::Error::other("no links here"));
        if let Err(err) = made {
            eprintln!("this user may not create a symbolic link ({err}): skipped");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        match reopen_output_file(&link) {
            Err(_) => {}
            Ok(mut through) => {
                let _ = through.write_all(b"REPLACED");
                drop(through);
                panic!(
                    "a link at the final component was opened; its target now reads {:?}",
                    String::from_utf8_lossy(&std::fs::read(&victim).unwrap())
                );
            }
        }
        assert_eq!(std::fs::read(&victim).unwrap(), b"precious");
        // A name that is gone is an error, and nothing is created.
        let gone = dir.join("o").join("gone.bin");
        assert!(reopen_output_file(&gone).is_err());
        assert!(!gone.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Windows: an overwrite in place of a plain file is one open of the
    /// name as itself, and writes THAT file; a file with a second name (a
    /// hard link) is never written in place, and both names keep their
    /// bytes ([`only_name`], the owner's rule of 27 Oct 2026); a read-only
    /// file is still overwritten, by the path that gives the owner its
    /// write bit; and a symbolic link at the name is refused with its
    /// target untouched. Where this user may not create a symbolic link
    /// the last SAYS so and is skipped.
    #[cfg(windows)]
    #[test]
    fn an_overwrite_in_place_opens_a_plain_file_once_and_never_a_link() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!(
            "rarkit-cli-safepath-in-place-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let plain = dir.join("plain.bin");
        std::fs::write(&plain, b"old bytes, longer than the new").unwrap();
        assert!(open_regular_in_place(&plain, 0, None).is_some());
        write_in_place(&plain, 0)
            .unwrap()
            .write_all(b"new")
            .unwrap();
        assert_eq!(std::fs::read(&plain).unwrap(), b"new");
        // Sized: the same file, NOT emptied, and longer only past `len`.
        let (_, longer) = open_regular_in_place(&plain, 0, Some(2)).unwrap();
        assert!(longer);
        let (_, longer) = open_regular_in_place(&plain, 0, Some(3)).unwrap();
        assert!(!longer);
        assert_eq!(std::fs::read(&plain).unwrap(), b"new");

        // A second name: refused in place, sized or not, and nothing of
        // either name changes; the caller writes beside and renames.
        let other = dir.join("other-name");
        std::fs::hard_link(&plain, &other).unwrap();
        assert!(open_regular_in_place(&plain, 0, None).is_none());
        assert!(open_regular_in_place(&plain, 0, Some(3)).is_none());
        assert!(write_in_place(&plain, 0).is_err());
        assert!(write_in_place_sized(&plain, 0, 3).is_err());
        assert_eq!(std::fs::read(&plain).unwrap(), b"new");
        assert_eq!(std::fs::read(&other).unwrap(), b"new");

        let locked = dir.join("locked.bin");
        std::fs::write(&locked, b"old").unwrap();
        let mut bits = std::fs::metadata(&locked).unwrap().permissions();
        bits.set_readonly(true);
        std::fs::set_permissions(&locked, bits).unwrap();
        assert!(open_regular_in_place(&locked, 0, None).is_none());
        assert!(open_regular_in_place(&locked, 0, Some(3)).is_none());
        write_in_place(&locked, 0)
            .unwrap()
            .write_all(b"new")
            .unwrap();
        assert_eq!(std::fs::read(&locked).unwrap(), b"new");

        let victim = dir.join("important.doc");
        std::fs::write(&victim, b"precious").unwrap();
        let link = dir.join("member.bin");
        if let Err(err) = std::os::windows::fs::symlink_file(&victim, &link) {
            eprintln!("this user may not create a symbolic link ({err}): skipped");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        assert!(open_regular_in_place(&link, 0, None).is_none());
        assert!(open_regular_in_place(&link, 0, Some(3)).is_none());
        assert!(write_in_place(&link, 0).is_err());
        assert!(write_in_place_sized(&link, 0, 3).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"precious");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Windows: a file made beside a taken name takes the name THROUGH
    /// ITS OWN HANDLE as it closes, once armed, over a plain file and over
    /// one that carries the read-only attribute; unarmed, it does not.
    #[cfg(windows)]
    #[test]
    fn a_file_beside_takes_the_name_through_its_own_handle() {
        use std::io::Write;
        let dir =
            std::env::temp_dir().join(format!("rarkit-cli-safepath-handle-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for read_only in [false, true] {
            let path = dir.join(format!("member-{read_only}.txt"));
            std::fs::write(&path, b"original").unwrap();
            if read_only {
                let mut bits = std::fs::metadata(&path).unwrap().permissions();
                bits.set_readonly(true);
                std::fs::set_permissions(&path, bits).unwrap();
            }
            let Created {
                mut file, beside, ..
            } = make_member_file(&path, IfOutputExists::Replace, 0o666)
                .unwrap()
                .unwrap();
            let beside = beside.expect("a taken name is written beside");
            file.write_all(b"new").unwrap();
            let named = NameAtClose::new(&path);
            named.close_of(&file);
            assert!(!named.given(), "unarmed, the file keeps its own name");
            assert_eq!(std::fs::read(&path).unwrap(), b"original");
            named.arm();
            named.close_of(&file);
            assert!(named.given(), "read-only {read_only}");
            drop(file);
            assert!(!beside.exists(), "read-only {read_only}");
            assert_eq!(
                std::fs::read(&path).unwrap(),
                b"new",
                "read-only {read_only}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_never_policy_keeps_the_file_that_is_already_there() {
        let dir = std::env::temp_dir().join(format!("rarkit-cli-safepath-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("member.txt");
        std::fs::write(&path, b"original").unwrap();
        assert!(make_member_file(&path, IfOutputExists::Keep, 0o666)
            .unwrap()
            .is_none());
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
        // SPEC-CLI 9.4 W7: a taken name is not opened; the file is made
        // beside it, in the same directory, and the old bytes stand until
        // it takes the name.
        for policy in [IfOutputExists::Replace, IfOutputExists::Beside] {
            let Created { file, beside, .. } =
                make_member_file(&path, policy, 0o666).unwrap().unwrap();
            let beside = beside.expect("a taken name is written beside");
            assert_eq!(beside.parent(), path.parent());
            assert_eq!(std::fs::read(&path).unwrap(), b"original");
            drop(file);
            std::fs::write(&beside, b"new").unwrap();
            take_name(&beside, &path).unwrap();
            assert!(!beside.exists());
            assert_eq!(std::fs::read(&path).unwrap(), b"new");
            std::fs::write(&path, b"original").unwrap();
        }
        // W1: a free name is made at its own name.
        let other = dir.join("other.txt");
        let made = make_member_file(&other, IfOutputExists::Replace, 0o666)
            .unwrap()
            .unwrap();
        assert!(made.beside.is_none());
        assert!(other.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
