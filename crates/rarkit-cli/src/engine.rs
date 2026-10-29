//! The seam between the carried dialects and the rarkit engine.
//!
//! WRITTEN HERE, not carried. Every carried dialect file is ours from
//! birth by the census, but the places where those files touched the
//! PREDECESSOR's reader API (`ArchiveReader`, `ArchiveMemberDetail`,
//! the earlier engine's `FileHeader`, `extract_volumes_to_concurrent`) have no
//! equivalent to be re-pointed at: rarkit's read API is a different shape
//! (`Archive::open_path`, `Session`, `Sink`, `Progress`). So the dialect
//! keeps its own `Member` view, which is what all four listing layouts and
//! the progress lines are written against, and THIS module is the only
//! thing in the crate that names a rarkit type.
//!
//! That boundary is deliberate: when a codec or a container feature lands
//! in rarkit, the only file here that changes is this one.

use std::path::Path;
use std::sync::Arc;

use rarkit::{
    Archive, Checksum, ErrorKind, HostOs as RarkitHostOs, MemberInfo, Method, ReadOptions, Session,
};

use crate::dialect::unrar::{
    disk_name, io_reason, listed_name_into, text_from_archive, DamagedHeader, HostOs, Member, Name,
    OpenFailure, Opened, Tail,
};

/// The read options every command in these dialects opens an archive with.
///
/// A password goes in as [`rarkit::Password`], and the open keeps the
/// members it parsed when the header walk stops short of the volume's end
/// ([`ReadOptions::tolerant_tail`]), because the reference lists, tests and
/// extracts the members in front of a cut or a damaged header rather than
/// refusing the file, and spec F 4.6 says those members stay valid. The
/// reason is carried in [`Opened::tail`]; everything else is the engine's
/// default. The extraction walk reads the volumes afresh and meets the
/// same damage at the same place, so the option changes nothing it
/// decodes.
fn read_options(password: Option<&[u8]>) -> ReadOptions {
    read_options_with(password, None)
}

/// [`read_options`], with the run's `-mt<n>` folded in.
///
/// **`-mt<n>` SETS `ReadOptions::workers`, exactly** (API 8.4.6), and
/// touches `MemoryPolicy::max_workers` no longer. Until 20 Sep 2026 it
/// only ever LOWERED that field, which `from_limit` derives from the
/// memory budget as `working_limit / 64 MiB` and holds at 8 on the
/// default: so `-mt32` could not carry a read past 8 engine decode
/// threads on any box, no switch in either dialect could raise it, and
/// 8.4's opening measures that ceiling costing between 1.5x and 3.2x of
/// wall. `src/width_dial.rs` is that finding as a test.
///
/// Three things it still does not do. It may not raise the MEMORY budget
/// and nothing here lets it: `working_limit` stays the default's and
/// stays HARD, and the engine runs narrower rather than over it (8.4.1).
/// It is bounded by the box's own core count, which
/// [`crate::workers::width`] already applies when it sizes the pool:
/// threads a box cannot run at once only contend. And the read side
/// gains no memory switch of its OWN, by design: the one memory
/// switch the CLI has, `-mm<size>`, reaches a read through
/// [`read_options_capped`].
pub(crate) fn read_options_with(password: Option<&[u8]>, threads: Option<u64>) -> ReadOptions {
    ReadOptions::default()
        .with_password(password.map(rarkit::Password::from))
        .with_workers(read_width(threads))
        .with_tolerant_tail(true)
        // And reads on through the damage the reference reads through: a
        // header whose checksum alone fails, a volume short in its
        // trailing records (`ReadOptions::read_damaged`).
        .with_read_damaged(true)
        // A set this program reads is files on disk, each opened by name
        // when the walk asks for it: every volume is present already.
        .with_volumes_present(true)
        // The dialect's own selection decides whether an older version of
        // a file is processed (`-ver`), so the engine shows it every
        // member and its opens stay in step with the dialect's plan.
        .with_versions(true)
}

/// What stopped a volume's header walk short, in the dialect's two classes.
///
/// A source that ended is a cut; a header whose checksum failed, or whose
/// fields break the format's framing, is one the walk cannot step over
/// (spec F 4.1, 4.6). Nothing else reaches [`Archive::tail`].
fn tail_of(archive: &Archive) -> Option<Tail> {
    archive.tail().map(|err| match err.kind() {
        ErrorKind::Truncated => Tail::Truncated,
        _ => Tail::CorruptHeader,
    })
}

/// [`read_options_with`], under the run's `-mm<size>` when it has one.
///
/// With no `-mm` a read takes the engine's default policy,
/// whose window ceiling is half of physical memory, so rarfast opens what
/// unrar opens. With one, the size is a STATED budget and the read runs
/// under `MemoryPolicy::from_limit(size)`, the same figure an API caller
/// gets by stating it: a member whose one window does not fit it beside
/// the fixed part is refused by name (`LimitExceeded`), before any
/// allocation, and one that fits is read at the widest arrangement the
/// limit holds (SPEC-API 8.4.1).
/// The floor is the create path's, 128 KiB.
///
/// The budget is the WHOLE PROCESS's: `-mm<size>` reaches the
/// read as `MemoryPolicy::for_process(size, caller_resident)` and no `-mm`
/// as `MemoryPolicy::process_default(caller_resident)` (512
/// MiB), `caller_resident` being what this binary itself holds beside the
/// engine (its per-member plan), so the process peak is at or under the
/// budget either way.
pub(crate) fn read_options_capped(
    password: Option<&[u8]>,
    threads: Option<u64>,
    memory_cap: Option<u64>,
    caller_resident: u64,
) -> ReadOptions {
    let options = read_options_with(password, threads);
    options.with_memory(match memory_cap {
        Some(cap) => rarkit::MemoryPolicy::for_process(cap.max(1 << 17), caller_resident),
        None => read_ahead_dial(rarkit::MemoryPolicy::process_default(caller_resident)),
    })
}

/// THE READ-AHEAD DIAL, for the big-media extract count: with no `-mm`, a
/// `reserve-knob` build takes `RARFAST_READ_AHEAD_MIB` as the default
/// policy's `read_ahead` (the seam's ring is half of it, in two slabs).
/// A feature of its own that no shipped build enables.
#[cfg(feature = "reserve-knob")]
fn read_ahead_dial(policy: rarkit::MemoryPolicy) -> rarkit::MemoryPolicy {
    match std::env::var("RARFAST_READ_AHEAD_MIB")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        Some(mib) if (1..=256).contains(&mib) => {
            eprintln!("rarfast read_ahead: {mib} MiB");
            rarkit::MemoryPolicy {
                read_ahead: mib << 20,
                ..policy
            }
        }
        _ => policy,
    }
}

#[cfg(not(feature = "reserve-knob"))]
fn read_ahead_dial(policy: rarkit::MemoryPolicy) -> rarkit::MemoryPolicy {
    policy
}

/// `-mt<n>` as the read side's width, or `None` for the engine's own
/// default (API 8.4.3), which is what a run with no `-mt` gets.
///
/// The parser has already bounded `threads` to 1..=64, the reference's own
/// range; the clamp is the box's and, under a finite `RLIMIT_AS`, what the
/// address space maps (`crate::workers::width`, the figure the pool gets).
fn read_width(threads: Option<u64>) -> Option<usize> {
    threads.map(|_| crate::workers::width(threads, crate::workers::Work::Read))
}

/// Whether an engine error is about the password rather than the bytes.
fn is_password_error(err: &rarkit::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::PasswordRequired | ErrorKind::WrongPassword
    )
}

/// The reference's own words for an open that failed.
fn classify_open(path: &str, err: &rarkit::Error) -> OpenFailure {
    match err.kind() {
        ErrorKind::PasswordRequired | ErrorKind::WrongPassword => {
            OpenFailure::BadPassword(format!("\nIncorrect password for {path}"))
        }
        ErrorKind::Source(io) => {
            OpenFailure::Missing(format!("\nCannot open {path}\n{}", io_reason(io)))
        }
        // The signature whole and the first header cut, out of its
        // bounds or failing its checksum: a damaged archive, as the
        // reference calls it, never no archive (security brief 4).
        ErrorKind::Truncated if signature_at_start(path) => OpenFailure::Damaged(Tail::Truncated),
        ErrorKind::Corrupt(_)
        | ErrorKind::HeaderChecksum
        | ErrorKind::LimitExceeded {
            resource: rarkit::Resource::HeaderSize,
            ..
        } if signature_at_start(path) => OpenFailure::Damaged(Tail::CorruptHeader),
        // The member table and its names over the read's budget: refused
        // by name, never no archive (D3, spec F 4.2), in the words the walk
        // gave the same refusal before the open met it first.
        ErrorKind::LimitExceeded {
            resource: rarkit::Resource::MemberTable,
            ..
        } => OpenFailure::OverBudget(format!("\n{err} (volume 0)")),
        _ => OpenFailure::NotAnArchive(format!("\n{path} is not RAR archive")),
    }
}

/// Whether the file at `path` opens with a whole RAR 5 or RAR 1.5 to 4.x
/// signature (an archive with a stub in front of it is not asked here).
fn signature_at_start(path: &str) -> bool {
    read_prefix(path, 8).is_ok_and(|head| {
        head.starts_with(b"Rar!\x1a\x07\x01\x00") || head.starts_with(b"Rar!\x1a\x07\x00")
    })
}

/// The dialect's host for one member.
///
/// rarkit reports the stored byte; two cases need the format as well,
/// which the declared unpack version gives: the RAR 1.3 container (which
/// declares 2) stores no host, so rarkit's `MsDos` there is a default the
/// reference does not print, and byte 6 is named WinCE only in the RAR 1.5
/// to 4.x family (13 and above), never in RAR 5 (0 and 1).
///
/// `format` and not `info.algorithm_version == 2` alone decides the RAR
/// 1.3 case: 2 is ALSO a RAR 5 compression version the engine (and the
/// reference) do not know, so a RAR 5 member refused for it was falling
/// in here too and listing `Unrecorded`'s DOS-shaped attributes where the
/// reference still prints the stored Unix mode. Measured 28 Sep 2026:
/// `unrar l`/`v` over a RAR 5 archive with one member's compression
/// version rewritten to 2 (the same rewrite `tests/every_refused_
/// member.rs` uses to make it a refusal) lists that member's attributes
/// and ratio exactly like every other member - the header's own fields
/// are intact, only the codec is unknown - where this crate showed
/// `..A.S..` (the `Unrecorded` form) and rarfast still matched at a
/// GENUINELY unknown version that is not 2 (5, checked the same way).
fn host_of(info: &MemberInfo<'_>, format: rarkit::Format) -> HostOs {
    if format == rarkit::Format::Rar13 {
        return HostOs::Unrecorded;
    }
    match info.host_os {
        RarkitHostOs::MsDos => HostOs::MsDos,
        RarkitHostOs::Os2 => HostOs::Os2,
        RarkitHostOs::Windows => HostOs::Windows,
        RarkitHostOs::Unix => HostOs::Unix,
        RarkitHostOs::MacOs => HostOs::MacOs,
        RarkitHostOs::BeOs => HostOs::BeOs,
        RarkitHostOs::Other(6) if info.algorithm_version >= 13 => HostOs::WinCe,
        RarkitHostOs::Other(byte) => HostOs::Other(byte),
        // The library's enum is open; a system it names later lists as an
        // unnamed one here until this table learns it.
        _ => HostOs::Other(u8::MAX),
    }
}

/// The dialect's `Member` view of one rarkit member.
///
/// `data_end` is the offset just past this member's data in its own
/// archive file, which is what the reference's percentage counter is a
/// fraction of: rarkit reports it directly as `MemberInfo::data.end`,
/// where the predecessor's RAR 1.3-4 path had to keep a running total.
fn member_of(
    info: &MemberInfo<'_>,
    wall_clock: bool,
    format: rarkit::Format,
    name: Name,
    printable: bool,
) -> Member {
    let rar5 = format == rarkit::Format::Rar5;
    let host = host_of(info, format);
    // The file system's name, kept apart only where it differs from the
    // display text, which for an ordinary name it does not.
    let stored = info.versioned_name();
    let disk = disk_name(&stored, host, rar5);
    let disk = (*disk != *name.as_bytes()).then(|| Arc::<[u8]>::from(disk.as_ref()));
    let method = match info.method {
        Method::Stored => 0,
        Method::Compressed { level, .. } => level,
    };
    Member {
        name,
        disk,
        printable,
        is_dir: info.is_directory,
        is_service: false,
        size: info.unpacked_size.unwrap_or(0),
        packed: info.packed_size,
        mtime: info.mtime.map(|t| t.unix_seconds),
        mtime_nanos: info.mtime.map_or(0, |t| t.nanos),
        wall_clock,
        attr: u64::from(info.attributes),
        host,
        crc32: match info.checksum {
            Some(Checksum::Crc32(value)) => Some(value),
            _ => None,
        },
        encrypted: info.encrypted,
        password_checked: info.password_checked,
        version: info.file_version,
        split_before: info.split_before,
        split_after: info.split_after,
        // The per-member solid flag is not on rarkit's `MemberInfo`; the
        // technical listing prints the archive's own solid flag instead.
        // Not done: it needs a `MemberInfo` that carries it (crate README).
        algorithm_version: info.algorithm_version,
        method,
        // `MemberInfo::dictionary` already carries the header's own
        // declared size regardless of method - `None` for a directory,
        // `Some` for a STORED member too - and reading it straight
        // through, rather than deriving it from `Method::Compressed`
        // alone, is what was missing: a STORED member's own `-md=`
        // clause was dropped on every format (measured against `unrar
        // lt` on fixtures/legacy/archives/{d140,d155,d250}_m0.rar, 26
        // Sep 2026).
        dictionary: info.dictionary,
        solid: false,
        // What the engine refuses the member for (spec F 3.2.6 and
        // 3.3.5): RAR 5 names no dictionary for a version it does not
        // know; the RAR 1.5 to 4.x family's table is 13 to 15, 20, 26 and
        // 29; the RAR 1.3 container declares 2 and is always decoded. A 2
        // in the LATER family is unknown there, and unrar 7.23 agrees
        // (`r393_m3.rar`, one member at 0, 2 or 12: `Unknown method`,
        // exit 2, 28 Sep 2026); until then this reading took it for
        // known, opened a line for it and said `checksum error` beside
        // the engine's refusal.
        unknown_version: !info.is_directory
            && method != 0
            && match format {
                rarkit::Format::Rar5 => info.dictionary.is_none(),
                rarkit::Format::Rar13 => false,
                _ => !matches!(info.algorithm_version, 13..=15 | 20 | 26 | 29),
            },
        data_end: info.data.end,
        redirect: info.redirection.map(|r| crate::dialect::unrar::Redirect {
            kind: r.kind,
            target: r.target.map(<[u8]>::to_vec),
        }),
    }
}

/// The `Details:` text: the family, then each property the reference
/// appends, in the reference's own order.
fn details(archive: &Archive, header_encrypted: bool) -> String {
    // The reference's own wording per family, measured against unrar 7.23
    // on an Apple Silicon Mac over `fixtures/legacy/archives/` (18 Sep 2026): the
    // 1.40-written archive lists as `RAR 1.4`, and the 1.55, 2.50, 3.93,
    // 4.20 and 5.50-written RAR4-family archives ALL list as `RAR 1.5` -
    // it is the header format's own version, not the writer's. A genuine
    // RAR 1.3 archive shares `Rar13`'s signature and is unmeasured (no
    // fixture); it lists as `RAR 1.4` here, which is not measured yet.
    let mut text = match archive.format() {
        rarkit::Format::Rar5 => "RAR 5".to_owned(),
        rarkit::Format::Rar13 => "RAR 1.4".to_owned(),
        _ => "RAR 1.5".to_owned(),
    };
    let volume = archive.volume();
    if volume.is_volume {
        text.push_str(&format!(", volume {}", volume.number.map_or(1, |n| n + 1)));
    }
    if archive.is_solid() {
        text.push_str(", solid");
    }
    if archive.has_recovery_record() {
        text.push_str(", recovery record");
    }
    if archive.is_locked() {
        text.push_str(", lock");
    }
    if header_encrypted {
        text.push_str(", encrypted headers");
    }
    text
}

/// [`open`] for a command that only LISTS.
///
/// A listing of an archive whose HEADERS are plain reads nothing a key
/// unlocks, so such an archive is parsed without the password and the
/// PBKDF2 ladder is not run. The listing is the same.
pub(crate) fn open_listing(
    path: &str,
    password: Option<&[u8]>,
    memory_cap: Option<u64>,
) -> Result<Opened, OpenFailure> {
    if password.is_some()
        && sniff_rar50_first_block(path).is_some_and(|kind| kind != BLOCK_TYPE_ENCRYPTION)
    {
        if let Ok(opened) = open_named(path, None, memory_cap) {
            return Ok(opened);
        }
    }
    open_named(path, password, memory_cap)
}

/// Opens one archive file the way the command asked for it.
pub(crate) fn open(path: &str, password: Option<&[u8]>) -> Result<Opened, OpenFailure> {
    open_named(path, password, None)
}

/// [`open`], under the run's `-mm<size>` when it names one
/// ([`read_options_named`]).
fn open_named(
    path: &str,
    password: Option<&[u8]>,
    memory_cap: Option<u64>,
) -> Result<Opened, OpenFailure> {
    open_in(
        path,
        &mut Session::new(read_options_named(password, memory_cap)),
    )
}

/// [`read_options`], under a NAMED `-mm<size>` as [`read_options_capped`]
/// takes it, so that a listing holds its member table to the budget `t`
/// and `x` already hold theirs to (D3). With no `-mm` the read keeps the
/// engine's default policy, as before.
pub(crate) fn read_options_named(password: Option<&[u8]>, memory_cap: Option<u64>) -> ReadOptions {
    match memory_cap {
        Some(_) => read_options_capped(password, None, memory_cap, 0),
        None => read_options(password),
    }
}

/// As [`open`], reading through the caller's `session`, so that the keys
/// this open derives are still there for the command's extraction walk
/// (`Session::extract_parallel`). The session carries the command's
/// password; the listing fallback below still reads without one.
pub(crate) fn open_in(path: &str, session: &mut Session) -> Result<Opened, OpenFailure> {
    let size = std::fs::metadata(path).map(|m| m.len()).map_err(|err| {
        OpenFailure::Missing(format!("\nCannot open {path}\n{}", io_reason(&err)))
    })?;
    let mut password_wrong = false;
    let archive = match open_session(session, path) {
        Ok(archive) => archive,
        Err(err) if is_password_error(&err) && !sniff_header_encrypted(path) => {
            // A wrong password on an archive whose HEADERS are readable is
            // not an open failure at the reference: it lists the members
            // and complains once per encrypted member. Read the headers
            // again without one, which is all the listing needs.
            password_wrong = true;
            let mut plain = Session::new(read_options(None));
            open_session(&mut plain, path).map_err(|err| classify_open(path, &err))?
        }
        Err(err) => return Err(classify_open(path, &err)),
    };
    // The signature and nothing behind it: the walk read no main header
    // and met no fault (the RAR 4 family's signature is a block of its
    // own), and the reference calls it `Unexpected end of archive`, exit 1.
    let main_read = archive
        .blocks()
        .any(|block| block.kind == rarkit::BlockKind::Main);
    if archive.tail().is_none() && !main_read && signature_at_start(path) {
        return Err(OpenFailure::Damaged(Tail::Truncated));
    }
    let tail = tail_of(&archive);
    let header_encrypted = sniff_header_encrypted(path);
    // Every format before RAR 5 stores a DOS date-and-time word, which is a
    // wall clock with no zone. See `crate::dialect::unrar::time::wall`.
    let wall_clock = archive.format() != rarkit::Format::Rar5;
    let rar5 = archive.format() == rarkit::Format::Rar5;
    // Every name rendered end to end into ONE string for the volume, sized
    // from the stored names first (an estimate: an escape or a lossy byte
    // can lengthen a name, and the string then grows as any string does;
    // a sum that would overflow sizes nothing), then shared by range.
    let capacity = archive
        .members()
        .try_fold(0_usize, |sum, m| sum.checked_add(m.versioned_name().len()))
        .unwrap_or(0);
    let mut pool = String::with_capacity(capacity);
    let ranges: Vec<(usize, usize, bool)> = archive
        .members()
        .map(|m| {
            let start = pool.len();
            let printable = listed_name_into(
                &m.versioned_name(),
                host_of(&m, archive.format()),
                rar5,
                &mut pool,
            );
            (start, pool.len(), printable)
        })
        .collect();
    let pool = Arc::new(pool);
    let members: Vec<Member> = archive
        .members()
        .zip(ranges)
        .map(|(m, (start, end, printable))| {
            member_of(
                &m,
                wall_clock,
                archive.format(),
                Name::new(&pool, start, end),
                printable,
            )
        })
        .collect();
    // The headers read although their checksum failed, in the reference's
    // words and count for each (`DamagedHeader`).
    let damaged = archive
        .damaged_headers()
        .iter()
        .map(|header| {
            // Every one is NAMED (spec F 4.6 rule 1): the reference's own
            // line where it has one, and for an end record or a block of
            // no known kind, which it leaves unnamed, a line of ours.
            let member = header
                .member
                .and_then(|index| members.get(index))
                .map(|member| member.name.to_string());
            let service = || {
                archive
                    .services()
                    .find(|service| service.header.data.start == header.range.end)
                    .map(|service| text_from_archive(service.header.name).into_owned())
            };
            let named = match (header.kind, member) {
                (rarkit::BlockKind::Main, _) => "Main archive header is corrupt".to_owned(),
                (_, Some(name)) => format!("{name} - the file header is corrupt"),
                (rarkit::BlockKind::End, _) => "End of archive header is corrupt".to_owned(),
                (_, None) => match service() {
                    Some(name) => format!("{name} - the file header is corrupt"),
                    None => format!("Header at offset {} is corrupt", header.range.start),
                },
            };
            DamagedHeader {
                errors: if rar5 || header.member.is_some() {
                    2
                } else {
                    1
                },
                lines: rar5
                    .then(|| {
                        crate::dialect::unrar::CORRUPT_HEADER
                            .trim_start()
                            .to_owned()
                    })
                    .into_iter()
                    .chain(Some(named))
                    .collect(),
            }
        })
        .collect();
    let details = details(&archive, header_encrypted);
    let volume = archive.volume();
    let is_volume = volume.is_volume;
    let next_follows = volume.next_follows;
    let solid = archive.is_solid();
    let comment = archive.comment().map(<[u8]>::to_vec);
    // Up to where the main header ENDS, the signature in front of it
    // included: the RAR 1.5 to 4.x family reads its 7-byte signature as a
    // block of its own, so the Main block's own span left it out and a
    // RAR 4 set's last member read 99% where the reference reads 100%
    // (`r4_vol`, measured 30 Sep 2026; see `Opened::counted_end`). Both
    // come from ONE pass over the blocks.
    let (main_header_size, counted_end) = counter_extents(&archive, size);
    Ok(Opened {
        members,
        details,
        size,
        main_header_size,
        counted_end,
        is_volume,
        next_follows,
        solid,
        password_wrong,
        // Either answer suffices: the archive's own flag answers RAR 4 and
        // RAR 5, and the sniff reads the RAR 5 encryption header as well.
        header_encrypted: header_encrypted || archive.headers_encrypted(),
        headers_unchecked: archive.headers_encrypted() && !rar5,
        tail,
        damaged,
        comment,
    })
}

/// Where the main header ends (`Opened::main_header_size`), and how much
/// of this file the progress counter counts when it is the LAST volume a
/// walk reads (`Opened::counted_end`): up to the end of the end record,
/// less the service blocks (a quick-open index, a recovery record) that
/// follow the last member; the whole file when no end record was read, a
/// cut or damaged archive. One pass, since the second needs every block.
fn counter_extents(archive: &rarkit::Archive, size: u64) -> (u64, u64) {
    let mut main_end = 0_u64;
    let mut end = None;
    let mut services_after = 0_u64;
    for block in archive.blocks() {
        match block.kind {
            rarkit::BlockKind::Main => main_end = block.range.end,
            rarkit::BlockKind::File => services_after = 0,
            rarkit::BlockKind::Service(_) => {
                services_after += block.range.end.saturating_sub(block.range.start);
            }
            rarkit::BlockKind::End => end = Some(block.range.end),
            _ => {}
        }
    }
    let counted = end.map_or(size, |end| end.saturating_sub(services_after).min(size));
    (main_end, counted)
}

/// The extraction walk's volumes, each opened only when the walk asks for
/// it.
///
/// **Why not a list of open files.** The walk used to be handed every
/// volume already open, so a set of more volumes than the process had
/// descriptors could not be read at all: a valid 430-volume set failed
/// under macOS's default soft limit of 256 with `Unexpected end of
/// archive`, the opens past the limit having quietly ended the list. The
/// engine asks for volumes in set order and lets each one go when its walk
/// is done with it (spec F 3.5, `Volumes`), so a file is opened here at the
/// moment it is asked for and held only by whatever the engine keeps, which
/// is the volume being walked and the ones its workers are still reading.
///
/// A volume that is no longer there answers `None`, which is where the
/// engine takes the set to end: the same as a list that stopped short,
/// and `Cannot find volume` has already been said for a volume the chain
/// named and the disk did not have. Any other failure to open is the
/// source failing, and is reported as that rather than as a short set.
pub(crate) struct OnDemand {
    names: Vec<String>,
    /// The first volume not yet asked for ahead ([`volumes_ahead`]).
    asked: usize,
    /// The last volume handed to the engine ([`OnDemand::entered`]).
    entered: Arc<std::sync::atomic::AtomicUsize>,
}

impl OnDemand {
    pub(crate) fn new(names: Vec<String>) -> Self {
        Self {
            names,
            asked: 0,
            entered: Arc::default(),
        }
    }

    /// The index of the last volume handed to the engine, kept current
    /// while the walk runs: the engine asks for a volume only as its walk
    /// enters it, so no header it has yet described is in a later one.
    pub(crate) fn entered(&self) -> Arc<std::sync::atomic::AtomicUsize> {
        Arc::clone(&self.entered)
    }

    /// The walk has just opened volume `at`, `len` bytes long: ask the
    /// kernel for the volumes after it that the rule gives
    /// ([`volumes_ahead`]) and that were not asked for already.
    fn ask_ahead(&mut self, at: usize, len: u64) {
        let ahead = volumes_ahead(true, len, small_ahead_bytes(), volumes_ahead_most());
        let ask = asked_ahead(self.asked, at, ahead, self.names.len());
        self.asked = self.asked.max(ask.end);
        for name in self.names.get(ask).unwrap_or(&[]) {
            read_ahead_named(name);
        }
    }
}

impl rarkit::Volumes for OnDemand {
    fn volume(&mut self, index: u32) -> rarkit::Result<Option<Arc<dyn rarkit::RangeSource>>> {
        let Some(name) = usize::try_from(index).ok().and_then(|i| self.names.get(i)) else {
            return Ok(None);
        };
        match std::fs::File::open(name) {
            Ok(file) => {
                let small = small_volumes_ahead()
                    .then(|| file.metadata().ok())
                    .flatten()
                    .filter(std::fs::Metadata::is_file)
                    .map(|meta| meta.len());
                let source = completed_input(file, Path::new(name));
                if let Ok(at) = usize::try_from(index) {
                    self.entered
                        .fetch_max(at, std::sync::atomic::Ordering::Relaxed);
                }
                if let (Some(len), Ok(at)) = (small, usize::try_from(index)) {
                    self.ask_ahead(at, len);
                }
                Ok(Some(source))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(rarkit::Error::new(ErrorKind::Source(err))),
        }
    }
}

/// A source for one archive file, as the walk's volumes are opened.
#[cfg(test)]
pub(crate) fn source_of(path: &str) -> Result<Arc<dyn rarkit::RangeSource>, OpenFailure> {
    let file = std::fs::File::open(path).map_err(|err| {
        OpenFailure::Missing(format!("\nCannot open {path}\n{}", io_reason(&err)))
    })?;
    Ok(completed_input(file, Path::new(path)))
}

/// Opens `path` through `session` the way `Session::open_path` does, but
/// reading through [`completed_input`]. A path that will not open goes to
/// `open_path` itself, so its error, and the text built from it, is the
/// library's own.
fn open_session(session: &mut Session, path: &str) -> rarkit::Result<Archive> {
    match std::fs::File::open(path) {
        Ok(file) => session.open(completed_input(file, Path::new(path))),
        Err(_) => session.open_path(Path::new(path)),
    }
}

/// THE CLI'S INPUT POLICY: a command line names an archive that is already
/// on disk, so a REGULAR FILE is read as the completed file it was when
/// this descriptor opened it.
///
/// `std::fs::File`'s own `RangeSource` asks the descriptor for its length
/// on every `available` and `len`, which is the library's contract for a
/// source that may still be growing (API section 3), and which costs one
/// `fstat` per question: 47,345 of them in one `t` of a 20,000-member
/// archive, where two answer it. The library's contract is untouched;
/// this is a decision of the command line's, for the command line's
/// inputs, and the rest of it is:
///
/// - **The length is the descriptor's**, taken once at open, never the
///   pathname's, so a path replaced after the open changes nothing: the
///   descriptor still reads the file it opened.
/// - **Reads stop at that length.** Bytes appended after the open (a
///   download still arriving) are not read; the archive is read as it
///   stood, and an archive cut short there is reported truncated, as it
///   would have been had the command run a moment earlier. The command
///   line never waited for bytes: a plain `File` at its end answers
///   `Ok(0)` at once.
/// - **A file cut short after the open** answers `Ok(0)` before the
///   length, which the engine reports as truncated, as before.
/// - **Anything that is not a regular file** (a FIFO, a device, a
///   descriptor whose metadata cannot be read) is handed over as the
///   plain `File`, exactly as before this policy: its length is not a
///   fact to be kept.
/// - **Every volume** of a set, and the password-less fallback open, goes
///   through here separately, so each is its own completed file.
fn completed_input(file: std::fs::File, path: &Path) -> Arc<dyn rarkit::RangeSource> {
    match file.metadata() {
        Ok(meta) if meta.is_file() => Arc::new(CompletedFile {
            window: window_of(&file, meta.len()),
            file: advise_in_order(advise_sequential(file), meta.len()),
            #[cfg(windows)]
            more: more_handles::More::new(path, &meta),
            len: meta.len(),
        }),
        _ => {
            let _ = path;
            Arc::new(file)
        }
    }
}

/// On Linux, while extracting to disk (`x` and `e`) or reading at one
/// thread (`-mt1`), a regular archive file is advised
/// `POSIX_FADV_SEQUENTIAL` for its whole length before the first
/// read (the second lever of the cold big-media study, 30 Sep 2026), once
/// [`advise_sequential_reads`] has been called for the process.
///
/// **Why.** The kernel then doubles the file's read-ahead window for every
/// read of it (the `posix_fadvise(2)` manual page), and the reads that
/// take no depth of their own gain it: the seam's slabs of a big stored
/// member written to disk, the LZ decoder's packed fills. Timed on
/// a Zen 4 rental (PM9A3-class NVMe, read-ahead 256 KiB), cold, in one knob
/// binary against no advice (30 Sep 2026): big member `x` on
/// disk 1.12x, the big member over 1 GiB volumes 1.17x, a many-member set
/// at `-m3` 1.21x, S8 `x` 1.12x on its own; warm level; no CPU.
///
/// **Why not `t` and `p`.** There a big stored member is read by the wide
/// read's sixteen readers at scattered offsets, and a doubled window per
/// reader drags in bytes nobody asked for yet: the same run read the
/// cold big member's `t` 0.92x, the many-member set 0.93x and S8's `t`
/// 0.97x with the advice, so they keep the system's own read-ahead. At `-mt1` there is
/// no wide read, one reader goes in order, and the advice wins there too:
/// the cold big member's `t` 1.39x, the many-member set 1.40x, S8's 1.08x.
///
/// **Advice, not a contract.** It changes no byte read and no offset
/// asked for, only how far the kernel reads ahead; a call that fails
/// (a file system that refuses advice) is ignored and the file is read
/// as before. Not on macOS, whose one reader in order already gets 0.99
/// of the drive, and not elsewhere, where nothing was measured.
///
/// A count-only knob (feature `read-depth-knob`, never shipped):
/// `RARFAST_FADV_SEQ=0` gives no advice, today's path before this lever.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[allow(unsafe_code)]
fn advise_sequential(file: std::fs::File) -> std::fs::File {
    if !ADVISE_SEQUENTIAL.load(std::sync::atomic::Ordering::Relaxed) {
        return file;
    }
    #[cfg(feature = "read-depth-knob")]
    if std::env::var("RARFAST_FADV_SEQ").is_ok_and(|v| v.trim() == "0") {
        return file;
    }
    advise_file_sequential(&file);
    file
}

/// Advises the kernel that `file` is read in order, for its whole length
/// (`POSIX_FADV_SEQUENTIAL`): the one place the call is made, for an
/// archive read ([`advise_sequential`]) and for a create's input
/// (`dialect::rar::create`, lever (a) of the create cold-input work). A
/// call that fails is ignored and the file is read as before.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[allow(unsafe_code)]
pub(crate) fn advise_file_sequential(file: &std::fs::File) {
    use std::os::fd::AsRawFd;
    // SAFETY: an advisory call on a descriptor the caller holds open for
    // the length of the call; it reads and writes no memory of ours, and
    // its result (advice taken or not) changes no byte the file answers.
    let _ = unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL) };
}

/// Everywhere else there is no such advice to give.
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
#[inline(always)]
pub(crate) fn advise_file_sequential(_file: &std::fs::File) {}

/// The length up to which an archive file is read in order whatever the
/// width: the engine's wide read takes a range of a stored member only from
/// 16 MiB (`read::wide::FLOOR` in rarkit), and a file of that length or less
/// holds no such range (its headers take some of it), so its member bytes
/// are read front to back by the thread that walks it. The engine's floor
/// is not public; `the_in_order_advice_takes_only_a_file_under_the_wide_floor`
/// reads it through the engine's test probe and fails if this differs.
const IN_ORDER_AT_MOST: u64 = 16 << 20;

/// Whether an archive file of [`IN_ORDER_AT_MOST`] or less is advised as read in
/// order when `RARFAST_IN_ORDER_ADVICE` says nothing: on Linux, where the
/// advice exists and its rows are (1 Oct 2026: a Zen 4 rental, cold,
/// a big member and a split set in volumes of 15 MB and of 16
/// MiB 1.36x to 1.37x, `-hp` 1.33x, `-htb` 1.19x, two thousand small stored
/// members 1.24x; one archive, 17 MiB and 100 MiB volumes, LZ members, `x`,
/// `-mt1` and every warm row level). Elsewhere the call is a no-op.
const IN_ORDER_ADVICE: bool = cfg!(all(target_os = "linux", target_env = "gnu"));

/// `RARFAST_IN_ORDER_ADVICE`: `1` (or `on`) advises every archive file
/// of [`IN_ORDER_AT_MOST`] bytes or fewer as read in order ([`advise_in_order`]);
/// `0` (or `off`) gives none; anything else, or nothing, is
/// [`IN_ORDER_ADVICE`]. A RUNTIME knob, so one binary carries both arms.
const IN_ORDER_ENV: &str = "RARFAST_IN_ORDER_ADVICE";

/// `RARFAST_IN_ORDER_ADVICE`'s value as an answer.
fn in_order_advice_of(value: Option<&str>) -> bool {
    match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        Some("1" | "on") => true,
        Some("0" | "off") => false,
        _ => IN_ORDER_ADVICE,
    }
}

fn in_order_advice() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| in_order_advice_of(crate::knob::reader_var(IN_ORDER_ENV).ok().as_deref()))
}

/// Whether a file of `len` bytes takes the in-order advice: the rule is
/// on, the file is no longer than [`IN_ORDER_AT_MOST`], and the command has not
/// advised every file already (`whole`: `advise_sequential`).
fn in_order_file(on: bool, whole: bool, len: u64) -> bool {
    on && !whole && len <= IN_ORDER_AT_MOST
}

/// On Linux, a regular archive file NO LONGER than the wide read's floor is
/// advised `POSIX_FADV_SEQUENTIAL` whatever the command and the width
/// ([`IN_ORDER_AT_MOST`]): a volume of a set made in small volumes.
///
/// **Why.** [`advise_sequential`] leaves `t` and `p` at a wider width with
/// no advice, because their big stored members are read wide, by readers
/// at scattered offsets, and the advice lost there. A stored member in
/// volumes of 16 MiB or less is not read wide at any width: each fragment is
/// under the wide read's floor and is read in order by the walking thread,
/// with the system's plain read-ahead. Counted on a Zen 4 rental's NVMe
/// (a Zen 4 rental, held for the run, cold, K=3, 1 Oct 2026):
/// `t` of a 12.9 GB stored member in 859 volumes of 15 MB read 3.873 s at
/// the default width and 2.809 s at `-mt1`, and 3.859 s at `-mt1` with the
/// advice withheld: the whole of the difference is the advice.
///
/// **Per file, by its length.** The length is the one fact the open has,
/// and it is enough: no range of a file that short is one the wide read
/// takes. A larger volume keeps [`advise_sequential`]'s answer; the short
/// last volume of a set of larger ones is advised, being short.
///
/// Off Linux the call is [`advise_file_sequential`]'s own no-op: macOS has
/// no such advice, and nothing was measured anywhere else.
fn advise_in_order(file: std::fs::File, len: u64) -> std::fs::File {
    if in_order_file(in_order_advice(), advises_every_file(), len) {
        advise_file_sequential(&file);
    }
    file
}

/// Whether the walk asks for the small volumes after the one it opens
/// ([`volumes_ahead`]) when `RARFAST_SMALL_VOLUMES_AHEAD` says nothing: on
/// macOS, each system on its own rows. Linux keeps what it had: the form of
/// this first built (a request at each file's open) lost there, and the
/// walk's own form has no Linux row yet.
const SMALL_VOLUMES_AHEAD: Ahead = if cfg!(target_os = "macos") {
    Ahead::Cold
} else {
    Ahead::Off
};

/// Whether, and of which sets, the walk asks for small volumes ahead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ahead {
    /// Never.
    Off,
    /// Of a set the page cache says is not in memory: the rule as shipped.
    Cold,
    /// Of every set, in memory or not, without asking the page cache: for a
    /// test or a measurement that must run the path on a file just written.
    Always,
}

/// `RARFAST_SMALL_VOLUMES_AHEAD`: `1` (or `on`) has the walk ask for the
/// small volumes after the one it opens when the set is not in memory,
/// `always` whether it is or not, `0` (or `off`) never; anything else, or
/// nothing, is [`SMALL_VOLUMES_AHEAD`]. A RUNTIME knob, so one binary
/// carries every arm.
const SMALL_VOLUMES_AHEAD_ENV: &str = "RARFAST_SMALL_VOLUMES_AHEAD";

/// [`SMALL_VOLUMES_AHEAD_ENV`]'s value as an answer.
fn small_volumes_ahead_of(value: Option<&str>) -> Ahead {
    match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        Some("1" | "on") => Ahead::Cold,
        Some("always") => Ahead::Always,
        Some("0" | "off") => Ahead::Off,
        _ => SMALL_VOLUMES_AHEAD,
    }
}

/// The rule for this process, by its system and the knob.
pub(crate) fn small_volumes_ahead_ruled() -> Ahead {
    static ON: std::sync::OnceLock<Ahead> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        small_volumes_ahead_of(
            crate::knob::reader_var(SMALL_VOLUMES_AHEAD_ENV)
                .ok()
                .as_deref(),
        )
    })
}

/// Whether this walk asks ahead: the command has said so
/// ([`ask_small_volumes_ahead`]).
fn small_volumes_ahead() -> bool {
    ASKS_AHEAD.load(std::sync::atomic::Ordering::Relaxed)
}

/// Set by a command the rule takes, before its walk opens a volume.
static ASKS_AHEAD: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The walks of this command ask for small volumes ahead: the caller has
/// found the rule on ([`small_volumes_ahead_ruled`]), the command one it
/// takes ([`ahead_command`]) and the set not in memory.
pub(crate) fn ask_small_volumes_ahead() {
    ASKS_AHEAD.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Whether a command is one whose walk asks ahead, by what it does
/// (`extract`: `x` or `e`) and its selected members' facts, `(is a
/// directory, method)`: every extract, and a `t` or `p` whose members are
/// all STORED.
///
/// **Why not every command.** A compressed set that is only read (`t`) was
/// the one row that lost, 0.85x (four members at `-m3` in 66 volumes of
/// 15 MB, 0.338 s to 0.398 s, cold); extracted, the same set gained
/// (1.19x). A `t` of stored and compressed members together has no row and
/// keeps what it had.
pub(crate) fn ahead_command(extract: bool, members: impl Iterator<Item = (bool, u8)>) -> bool {
    if extract {
        return true;
    }
    let mut files = 0usize;
    for (is_dir, method) in members {
        if is_dir {
            continue;
        }
        if method != 0 {
            return false;
        }
        files += 1;
    }
    files > 0
}

/// Which volumes the walk asks for when it opens volume `at` of `total`:
/// the `ahead` after it, less those asked for already (`asked` is the first
/// volume never asked for), and none past the set's end. Every volume is
/// asked for once at most, and none before the walk is `ahead` volumes
/// short of it.
fn asked_ahead(asked: usize, at: usize, ahead: usize, total: usize) -> std::ops::Range<usize> {
    let end = at.saturating_add(ahead).saturating_add(1).min(total);
    let start = asked.max(at.saturating_add(1)).min(end);
    if ahead == 0 {
        return start..start;
    }
    start..end
}

/// How many bytes of the volumes after the one the walk has just opened
/// are asked for ahead when `RARFAST_SMALL_AHEAD_MIB` says nothing: 64 MiB,
/// four volumes of 15 MB. 256 MiB was no faster on any row and wider in
/// its ranges.
const SMALL_AHEAD: u64 = 64 << 20;

/// `RARFAST_SMALL_AHEAD_MIB`: [`SMALL_AHEAD`] in MiB, 1 to 4096; anything
/// else, or nothing, is [`SMALL_AHEAD`]. A screen knob.
const SMALL_AHEAD_ENV: &str = "RARFAST_SMALL_AHEAD_MIB";

fn small_ahead_bytes_of(value: Option<&str>) -> u64 {
    match value.and_then(|v| v.trim().parse::<u64>().ok()) {
        Some(mib @ 1..=4096) => mib << 20,
        _ => SMALL_AHEAD,
    }
}

fn small_ahead_bytes() -> u64 {
    static BYTES: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *BYTES.get_or_init(|| {
        small_ahead_bytes_of(crate::knob::reader_var(SMALL_AHEAD_ENV).ok().as_deref())
    })
}

/// The largest volume the walk asks for ahead, as shipped: ANY size
/// (the cold stored extract work of 2 Oct 2026, counted on two newer
/// Apple machines).
///
/// Until 2 Oct 2026 only a volume of [`IN_ORDER_AT_MOST`] or less was asked
/// for, the rule having been built for sets of 15 MB volumes. A big member in
/// volumes of 100 MiB, the commonest larger size, then started cold at
/// every volume as the small ones had, and on an M5 MacBook Air its cold
/// extract sat at 0.75 of the drive, level with rarpar (1.02x). Counted
/// there (K=7, a twin of the count build beside it, 2 Oct 2026):
/// the next volume asked for
/// WHOLE when the walk opens one took that row from 2.088 s to 1.483 s
/// (1.44x over rarpar), volumes of 200 MiB 1.40x, of 1 GiB 1.23x, the same
/// set under `-hp` 1.48x and under `-htb` 1.18x, a compressed set in
/// 100 MiB volumes 1.42x, and its cold `t` 1.03x; asking only the first
/// 32 or 8 MiB of the next volume gave back most of it. A set in memory is
/// asked nothing, as before (the page cache is asked first), and the 15 MB
/// sets read as they did.
///
/// `RARFAST_LARGE_VOLUMES_AHEAD=0` (or `off`) restores the bound of
/// [`IN_ORDER_AT_MOST`]: a RUNTIME knob, so one binary carries both arms.
fn volumes_ahead_most() -> u64 {
    static MOST: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *MOST.get_or_init(|| {
        volumes_ahead_most_of(
            crate::knob::reader_var(LARGE_VOLUMES_AHEAD_ENV)
                .ok()
                .as_deref(),
        )
    })
}

/// `RARFAST_LARGE_VOLUMES_AHEAD`: `0` (or `off`) asks for small volumes
/// only, as before; anything else, or nothing, for volumes of every size.
const LARGE_VOLUMES_AHEAD_ENV: &str = "RARFAST_LARGE_VOLUMES_AHEAD";

/// [`volumes_ahead_most`]'s reading of the variable's value.
fn volumes_ahead_most_of(value: Option<&str>) -> u64 {
    match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
        Some("0" | "off") => IN_ORDER_AT_MOST,
        _ => u64::MAX,
    }
}

/// The most of one volume asked for ahead: a gibibyte. A larger volume is
/// asked for by its first gibibyte, so one request never names more of the
/// cache than the largest volume this was counted on (1 GiB volumes:
/// 1.23x), and the call's own count of bytes, a C `int`, holds it.
const VOLUME_ASKED_AT_MOST: u64 = 1 << 30;

/// How many volumes after one of `len` bytes, just opened by the walk, are
/// asked for ahead: none unless the rule is on and the volume is no larger
/// than `most` ([`volumes_ahead_most`]); then as many of its size as fit in
/// `bytes`, and one at least.
///
/// **Why.** The kernel reads ahead inside one file and starts again, small,
/// at the next: a big member stored over 859 volumes of 15 MB is 859 cold starts,
/// and whatever reads it (the walk's own thread, a worker handed a
/// fragment, the cipher's reader) waits at each. Asked for when the walk
/// opens the volume before, a volume is in memory, or on its way, when its
/// first read comes. On a Mac Studio's own drive (an M3, held for the run,
/// cold, a 12.9 GB member in 859 volumes of 15 MB, against the same binary
/// with the rule off, 1 Oct 2026): `x` under `-hp`
/// 10.95 s to 5.52 s, where unrar took 11.10 s; `t` clear 1.68x, `-hp`
/// 1.54x, `-htb` 1.58x; 2,000 stored members of 1 MiB 1.43x; warm level.
///
/// **Why the volumes AFTER it, and why a bound.** A command opens every
/// volume once to list it before it reads any member, so a request made at
/// each file's own open, the form first built, asked for the WHOLE SET in
/// the first milliseconds (counted: 82 opens for 41 volumes, the first 41
/// inside 1.4 ms), which no machine with less memory than the set could
/// honour. Asked for here, the request is the walk's own, runs a fixed
/// distance in front of it and holds no more of the cache than `bytes`
/// beyond the volumes the walk has open. (An extract's walk hands
/// fragments to workers and runs ahead of them by the volumes it may hold
/// open, half the descriptor limit: 128 on a Mac as it ships, so under
/// 2 GiB of 15 MB volumes.) It is the cache's memory, not the process's:
/// the peak is unmoved.
fn volumes_ahead(on: bool, len: u64, bytes: u64, most: u64) -> usize {
    if !on || len == 0 || len > most {
        return 0;
    }
    usize::try_from(bytes / len).unwrap_or(usize::MAX).max(1)
}

/// Ask the kernel to read the first `len` bytes of `file` into its cache
/// now, without waiting for them ([`read_ahead_range`]).
fn read_ahead_whole(file: &std::fs::File, len: u64) {
    read_ahead_range(file, 0, len);
}

/// Ask the kernel to read the `len` bytes of `file` at `offset` into its
/// cache now, without waiting for them: `fcntl(F_RDADVISE)` on macOS,
/// `posix_fadvise(WILLNEED)` on Linux. A call that fails, or a range the
/// call's own types cannot state, is ignored and the file is read as
/// before; no byte a read answers depends on it.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[allow(unsafe_code)]
pub(crate) fn read_ahead_range(file: &std::fs::File, offset: u64, len: u64) {
    use std::os::fd::AsRawFd;
    let (Ok(offset), Ok(len)) = (libc::off_t::try_from(offset), libc::off_t::try_from(len)) else {
        return;
    };
    // SAFETY: an advisory call on a descriptor the caller holds open for
    // the length of the call; it reads and writes no memory of ours, and
    // its result changes no byte the file answers.
    let _ =
        unsafe { libc::posix_fadvise(file.as_raw_fd(), offset, len, libc::POSIX_FADV_WILLNEED) };
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
pub(crate) fn read_ahead_range(file: &std::fs::File, offset: u64, len: u64) {
    use std::os::fd::AsRawFd;
    let (Ok(offset), Ok(count)) = (libc::off_t::try_from(offset), libc::c_int::try_from(len))
    else {
        return;
    };
    let advice = libc::radvisory {
        ra_offset: offset,
        ra_count: count,
    };
    // SAFETY: `fcntl(F_RDADVISE)` reads the `radvisory` it is given, which
    // is live for the call, and nothing else of ours; the descriptor is the
    // caller's and open; its result changes no byte the file answers.
    let _ = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_RDADVISE, &advice) };
}

/// Everywhere else there is no such call.
#[cfg(not(any(all(target_os = "linux", target_env = "gnu"), target_os = "macos")))]
#[inline(always)]
pub(crate) fn read_ahead_range(_file: &std::fs::File, _offset: u64, _len: u64) {}

/// Ask for the whole of the file called `name`, if it is there, a regular
/// file and a small one: a volume the walk has not reached
/// ([`OnDemand::ask_ahead`]).
///
/// **From a thread of its own.** The call starts the file's reads before it
/// returns, so the walk hands over the name and goes on to its own reads;
/// the thread opens the file, asks, and lets it go. One thread for the
/// process, started at the first request and never joined: it ends with
/// the process, and a request it has not reached by then is one nobody
/// waits for. A name that will not open is the walk's to report when it
/// gets there, and if the thread cannot be started the volumes are read as
/// before.
fn read_ahead_named(name: &str) {
    static ASIDE: std::sync::OnceLock<Option<std::sync::mpsc::Sender<String>>> =
        std::sync::OnceLock::new();
    let to = ASIDE.get_or_init(|| {
        let (to, from) = std::sync::mpsc::channel::<String>();
        std::thread::Builder::new()
            .name("read-ahead".into())
            .spawn(move || {
                for name in from {
                    let Ok(file) = std::fs::File::open(&name) else {
                        continue;
                    };
                    match file.metadata() {
                        Ok(meta) if meta.is_file() && meta.len() <= volumes_ahead_most() => {
                            read_ahead_whole(&file, meta.len().min(VOLUME_ASKED_AT_MOST));
                        }
                        _ => {}
                    }
                }
            })
            .ok()
            .map(|_| to)
    });
    if let Some(to) = to {
        let _ = to.send(name.to_owned());
    }
}

/// Whether the command advises every archive file it opens already
/// ([`advise_sequential_reads`]).
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn advises_every_file() -> bool {
    ADVISE_SEQUENTIAL.load(std::sync::atomic::Ordering::Relaxed)
}

/// Everywhere else no file is advised.
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
#[inline(always)]
fn advises_every_file() -> bool {
    false
}

/// Whether [`advise_sequential`] advises: set once, by the command that
/// extracts to disk, before it opens its first volume. A command line runs
/// one command per process, so a process-wide switch is the whole of it.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
static ADVISE_SEQUENTIAL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Advise every archive file opened from here on as read in order
/// ([`advise_sequential`]); a no-op off Linux.
pub(crate) fn advise_sequential_reads() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    ADVISE_SEQUENTIAL.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Everywhere else the archive is read with the system's own read-ahead.
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
#[inline(always)]
fn advise_sequential(file: std::fs::File) -> std::fs::File {
    file
}

/// The read window of an archive file of `len` bytes opened while the
/// walk's switch is on (`crate::window::arm`): none for a file under half
/// a slab, which one read brings in whole.
fn window_of(file: &std::fs::File, len: u64) -> Option<crate::window::Window> {
    let slab = crate::window::armed()?;
    if len < slab / 2 {
        return None;
    }
    crate::window::Window::new(file, len, slab)
}

/// COUNT ONLY (feature `read-depth-knob`, never shipped):
/// `RARFAST_COLD_WINDOW_SAY=1` says on stderr what a file's window served
/// when the file is closed, which is what `tests/cold_window.rs` reads.
#[cfg(feature = "read-depth-knob")]
impl Drop for CompletedFile {
    fn drop(&mut self) {
        if let Some(window) = &self.window {
            if std::env::var("RARFAST_COLD_WINDOW_SAY").is_ok_and(|v| v.trim() == "1") {
                let (served, passed, asked) = window.counts();
                eprintln!(
                    "rarfast window: {served} of {} bytes served, {passed} reads passed to the file, {asked} bytes asked ahead",
                    self.len
                );
            }
        }
    }
}

/// A regular archive file with its length taken once; see
/// [`completed_input`]. On Windows it is also read through up to
/// `more_handles::HANDLES` handles in all (`more_handles`, a Windows-only
/// module, so these are code spans and not doc links: `make doc` runs
/// with `-D warnings` on every host).
struct CompletedFile {
    file: std::fs::File,
    len: u64,
    /// The read window, where the walk asked for one before this file was
    /// opened ([`window_of`]).
    window: Option<crate::window::Window>,
    #[cfg(windows)]
    more: Option<more_handles::More>,
}

impl rarkit::RangeSource for CompletedFile {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.len.saturating_sub(offset);
        let take = usize::try_from(left).map_or(buf.len(), |left| left.min(buf.len()));
        if take == 0 {
            return Ok(0);
        }
        #[cfg(windows)]
        let file = self
            .more
            .as_ref()
            .and_then(more_handles::More::for_this_thread)
            .unwrap_or(&self.file);
        #[cfg(not(windows))]
        let file = &self.file;
        // No window: the one read, as before the window existed.
        let Some(window) = &self.window else {
            return rarkit::RangeSource::read_at(file, offset, &mut buf[..take]);
        };
        self.read_through(window, file, offset, &mut buf[..take])
    }
    fn available(&self) -> u64 {
        self.len
    }
    fn len(&self) -> Option<u64> {
        Some(self.len)
    }
}

impl CompletedFile {
    /// A read through the window: it fills what it holds or is about to
    /// hold of these bytes, and the file answers the rest, which is every
    /// read behind the window's run and every read once its reader has
    /// stopped (`crate::window`). Out of line, so that the read of a file
    /// with no window is the code it was.
    #[inline(never)]
    fn read_through(
        &self,
        window: &crate::window::Window,
        file: &std::fs::File,
        offset: u64,
        buf: &mut [u8],
    ) -> std::io::Result<usize> {
        let served = window.read(offset, buf);
        if served == buf.len() {
            return Ok(served);
        }
        match rarkit::RangeSource::read_at(file, offset + served as u64, &mut buf[served..]) {
            Ok(n) => Ok(served + n),
            // The bytes the window served are the file's; the next read
            // begins where this error is and reports it.
            Err(_) if served > 0 => Ok(served),
            Err(e) => Err(e),
        }
    }
}

/// A REGULAR ARCHIVE FILE READ THROUGH SEVERAL HANDLES, on Windows (the
/// Windows stored read path).
///
/// The wide reader (`rarkit::read::wide`) reads a big stored member's
/// pieces by offset on several workers at once, all from this one source.
/// On Unix those `pread`s run in parallel. On Windows a handle opened for
/// synchronous I/O, std's default, queues its requests, so the workers
/// read in turn: on a Windows desktop (Ryzen 7 9800X3D, WD SN8100) one shared
/// handle read a 12.9 GB archive at 10.7 GB/s from 4 to 8 workers, and a
/// handle per worker at 17.0. `t` of it took 1.32 s against UnRAR.exe
/// 7.23's 2.61 (1.97x), and 0.557 s (4.68x) through 8 handles; `p` went
/// from 1.25x to 2.91x.
///
/// So the file keeps the handle it was opened with, and a thread other
/// than the one that opened it reads through one of up to `HANDLES - 1`
/// more, chosen by a per-thread index and opened by path the first time a
/// thread lands on it. A single-threaded read never opens a second.
///
/// A handle opened by path may not be the SAME file: the archive may have
/// been replaced between the two opens. One whose length, creation time or
/// last-write time differs from the first handle's is not used, and nor is
/// one that will not open; the read then goes through the first handle,
/// silently. (NTFS "tunnels" a vanished name's creation time to a file
/// made under it within seconds, so the write time is the stamp that tells
/// such a replacement apart; the file index stable std does not reach.)
/// Safe std only (`MetadataExt`).
#[cfg(windows)]
mod more_handles {
    use std::fs::File;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::OnceLock;
    use std::thread::ThreadId;

    /// Handles in all, the first included, as shipped.
    pub(super) const HANDLES: usize = 8;

    /// What a handle must match to be the same file.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct Stamp {
        len: u64,
        created: u64,
        written: u64,
    }

    fn stamp(meta: &std::fs::Metadata) -> Stamp {
        use std::os::windows::fs::MetadataExt;
        Stamp {
            len: meta.file_size(),
            created: meta.creation_time(),
            written: meta.last_write_time(),
        }
    }

    pub(super) struct More {
        path: PathBuf,
        stamp: Stamp,
        opener: ThreadId,
        slots: Vec<OnceLock<Option<File>>>,
    }

    impl More {
        /// The extra handles for the file at `path`, or `None` where there
        /// are to be none.
        pub(super) fn new(path: &Path, meta: &std::fs::Metadata) -> Option<More> {
            let extra = handles().saturating_sub(1);
            (extra > 0).then(|| More {
                path: path.to_path_buf(),
                stamp: stamp(meta),
                opener: std::thread::current().id(),
                slots: (0..extra).map(|_| OnceLock::new()).collect(),
            })
        }

        /// The handle this thread reads through, where it is not the first.
        pub(super) fn for_this_thread(&self) -> Option<&File> {
            if std::thread::current().id() == self.opener {
                return None;
            }
            let slot = &self.slots[thread_index() % self.slots.len()];
            slot.get_or_init(|| self.reopen()).as_ref()
        }

        fn reopen(&self) -> Option<File> {
            let file = File::open(&self.path).ok()?;
            let meta = file.metadata().ok()?;
            (meta.is_file() && stamp(&meta) == self.stamp).then_some(file)
        }
    }

    /// This thread's index among the threads that have read through any
    /// such file, fixed for its life.
    fn thread_index() -> usize {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        thread_local! {
            static INDEX: usize = NEXT.fetch_add(1, Ordering::Relaxed);
        }
        INDEX.with(|index| *index)
    }

    /// [`HANDLES`], or with the `read-knob` measuring feature
    /// `RARFAST_HANDLES` (1 to 64), which no shipped build reads.
    fn handles() -> usize {
        #[cfg(feature = "read-knob")]
        {
            static N: OnceLock<usize> = OnceLock::new();
            *N.get_or_init(|| {
                let n = std::env::var("RARFAST_HANDLES")
                    .ok()
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(HANDLES)
                    .clamp(1, 64);
                eprintln!("rarfast handles: {n}");
                n
            })
        }
        #[cfg(not(feature = "read-knob"))]
        {
            HANDLES
        }
    }
}

/// Reads a RAR 5 archive's FIRST block type without decrypting anything.
///
/// The reference names an archive's headers as encrypted before it knows
/// whether the password opens them, so the signature and one block header
/// are read here, which is all the question needs.
fn sniff_header_encrypted(path: &str) -> bool {
    sniff_rar50_first_block(path) == Some(BLOCK_TYPE_ENCRYPTION)
}

/// RAR 5 block type 4, the archive encryption header.
const BLOCK_TYPE_ENCRYPTION: u64 = 4;

/// The type of a RAR 5 archive's first block, or `None` when the question
/// has no answer (spec F 3.2.12): the file cannot be read, no RAR 5
/// signature is found where the engine would find one, the first
/// signature in it is the older container's, or the file ends before its
/// first block does. The block's checksum and its other fields have no
/// part in the answer, and no password is asked for.
fn sniff_rar50_first_block(path: &str) -> Option<u64> {
    /// The RAR 5 signature, and the six bytes it shares with the older
    /// container's (spec F 3.1.1): the seventh byte tells the two apart.
    const RAR5: [u8; 8] = *b"Rar!\x1a\x07\x01\x00";
    const SHARED: usize = 6;
    /// The last offset a signature is looked for at (spec F 3.1.2).
    const REACH: usize = 4_194_282;
    /// Behind the signature: four bytes of checksum, then the size and
    /// the type, each an integer of ten bytes at most.
    const CHECKSUM: usize = 4;
    const FRONT: usize = RAR5.len() + CHECKSUM + 10 + 10;

    // What stands at `at`: the RAR 5 signature, the older container's
    // (the shared bytes and a zero), or neither of the two.
    let stands = |bytes: &[u8], at: usize| -> Option<bool> {
        let here = bytes.get(at..)?;
        if here.starts_with(&RAR5) {
            Some(true)
        } else if here.starts_with(&RAR5[..SHARED]) && here.get(SHARED) == Some(&0) {
            Some(false)
        } else {
            None
        }
    };
    // Every archive a genuine writer made begins with its signature, so
    // the first read is the front of the file alone; the reach is read
    // only for a file that begins with neither container's signature.
    // The FIRST signature decides: where that is the older container's,
    // a RAR 5 signature further in answers nothing.
    let mut bytes = read_prefix(path, FRONT).ok()?;
    let at = match stands(&bytes, 0) {
        Some(true) => 0,
        Some(false) => return None,
        None => {
            bytes = read_prefix(path, REACH + FRONT).ok()?;
            // Both signatures open with one letter, so the search goes
            // from one of that letter to the next and asks what stands
            // there; nothing else in the reach is looked at twice.
            let reach = &bytes[..bytes.len().min(REACH + 1)];
            let mut from = 0;
            let (at, rar5) = loop {
                let at = from + reach[from..].iter().position(|&byte| byte == RAR5[0])?;
                if let Some(rar5) = stands(&bytes, at) {
                    break (at, rar5);
                }
                from = at + 1;
            };
            if !rar5 {
                return None;
            }
            at
        }
    };
    let block = at + RAR5.len();
    let sized = bytes.get(block + CHECKSUM..)?;
    let (size, size_bytes) = read_vint(sized)?;
    let (kind, kind_bytes) = read_vint(&sized[size_bytes..])?;
    // A block too short to hold its own type has no type to read.
    if size < kind_bytes as u64 {
        return None;
    }
    // The block must be whole in the file by its own size field: one
    // byte short and there is no answer, as there is none for a size past
    // any file.
    let end = ((block + CHECKSUM + size_bytes) as u64).checked_add(size)?;
    let length = std::fs::metadata(path).ok()?.len();
    (length >= end).then_some(kind)
}

/// The `Details:` text for an archive the engine could not open, which is
/// as much as the reference itself prints in that case.
pub(crate) fn sniffed_details(path: &str) -> String {
    if sniff_header_encrypted(path) {
        "RAR 5, encrypted headers".to_owned()
    } else {
        "RAR 5".to_owned()
    }
}

/// The leading bytes of the file at `path`, `len` of them at most. A file
/// shorter than `len` gives what it has and is not an error: the caller
/// judges whether that is enough. One open and no read past `len`, so a
/// file still growing is asked for no more than its head (API 3.3).
fn read_prefix(path: &str, len: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let most = u64::try_from(len).unwrap_or(u64::MAX);
    let mut head = Vec::with_capacity(len);
    std::fs::File::open(path)?
        .take(most)
        .read_to_end(&mut head)?;
    Ok(head)
}

/// A RAR 5 variable-length integer: seven bits per byte, low first, with
/// the high bit marking a continuation.
fn read_vint(input: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0_u64;
    for (index, byte) in input.iter().take(10).enumerate() {
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    /// Reading a small file ahead whole: only with the rule on, only for a
    /// command that reads members, only a file with bytes in it and no
    /// longer than the wide read's floor; the knob's words.
    #[test]
    fn the_walk_asks_for_small_volumes_ahead_within_a_bound() {
        use super::{
            ahead_command, asked_ahead, small_ahead_bytes_of, small_volumes_ahead_of,
            volumes_ahead, volumes_ahead_most_of, Ahead, IN_ORDER_AT_MOST, SMALL_AHEAD,
            SMALL_VOLUMES_AHEAD, VOLUME_ASKED_AT_MOST,
        };
        let any = u64::MAX;
        // Volumes of the opened one's size that fit in the bound, one at
        // least; as shipped a volume of any size is asked for, the next
        // one whole.
        assert_eq!(volumes_ahead(true, 15_000_000, 64 << 20, any), 4);
        assert_eq!(volumes_ahead(true, IN_ORDER_AT_MOST, 1 << 20, any), 1);
        assert_eq!(volumes_ahead(true, 100 << 20, 64 << 20, any), 1);
        assert_eq!(volumes_ahead(true, 4 << 30, 64 << 20, any), 1);
        assert_eq!(volumes_ahead(true, 0, 64 << 20, any), 0);
        assert_eq!(volumes_ahead(false, 15_000_000, 64 << 20, any), 0);
        // The knob off: nothing after a volume the wide read takes.
        let small = IN_ORDER_AT_MOST;
        assert_eq!(volumes_ahead(true, IN_ORDER_AT_MOST, 1 << 20, small), 1);
        assert_eq!(
            volumes_ahead(true, IN_ORDER_AT_MOST + 1, 64 << 20, small),
            0
        );
        assert_eq!(volumes_ahead(true, 100 << 20, 64 << 20, small), 0);
        for (value, most) in [
            (None, any),
            (Some("1"), any),
            (Some("on"), any),
            (Some(""), any),
            (Some("0"), small),
            (Some(" OFF "), small),
        ] {
            assert_eq!(volumes_ahead_most_of(value), most, "{value:?}");
        }
        // One request never names more than a gibibyte, which the call's
        // own count (a C int) holds.
        assert!(i32::try_from(VOLUME_ASKED_AT_MOST).is_ok());
        // Every extract; a test or print of stored members only.
        assert!(ahead_command(true, [(false, 3)].into_iter()));
        assert!(ahead_command(true, std::iter::empty()));
        assert!(ahead_command(false, [(true, 0), (false, 0)].into_iter()));
        assert!(!ahead_command(false, [(false, 0), (false, 3)].into_iter()));
        assert!(!ahead_command(false, [(true, 0)].into_iter()));
        assert!(!ahead_command(false, std::iter::empty()));
        // The knobs' words.
        assert_eq!(small_volumes_ahead_of(Some("1")), Ahead::Cold);
        assert_eq!(small_volumes_ahead_of(Some(" On ")), Ahead::Cold);
        assert_eq!(small_volumes_ahead_of(Some("always")), Ahead::Always);
        assert_eq!(small_volumes_ahead_of(Some("0")), Ahead::Off);
        assert_eq!(small_volumes_ahead_of(Some("off")), Ahead::Off);
        assert_eq!(small_volumes_ahead_of(None), SMALL_VOLUMES_AHEAD);
        assert_eq!(small_volumes_ahead_of(Some("2")), SMALL_VOLUMES_AHEAD);
        let shipped = if cfg!(target_os = "macos") {
            Ahead::Cold
        } else {
            Ahead::Off
        };
        assert_eq!(SMALL_VOLUMES_AHEAD, shipped);
        // A walk over ten volumes, four ahead: the first open asks for the
        // next four, each later open for one more, the last four for none;
        // every volume but the first is asked for exactly once.
        let (mut asked, mut all) = (0usize, Vec::new());
        for at in 0..10 {
            let ask = asked_ahead(asked, at, 4, 10);
            assert!(ask.end <= 10 && ask.start > at || ask.is_empty());
            asked = asked.max(ask.end);
            all.extend(ask);
        }
        assert_eq!(all, (1..10).collect::<Vec<_>>());
        assert_eq!(asked_ahead(0, 0, 4, 10), 1..5);
        assert_eq!(asked_ahead(5, 1, 4, 10), 5..6);
        // A walk that skips forward (a member further on) asks from there.
        assert_eq!(asked_ahead(5, 7, 4, 10), 8..10);
        // A big volume (none ahead) asks for nothing and moves nothing.
        assert!(asked_ahead(3, 2, 0, 10).is_empty());
        assert!(asked_ahead(0, 9, 4, 10).is_empty());
        assert_eq!(small_ahead_bytes_of(Some("256")), 256 << 20);
        assert_eq!(small_ahead_bytes_of(Some("0")), SMALL_AHEAD);
        assert_eq!(small_ahead_bytes_of(None), SMALL_AHEAD);
    }

    /// The in-order advice: only with the rule on, only a file no longer
    /// than the wide read's floor, and never a second time where the command has
    /// advised every file already; the knob's words.
    #[test]
    fn the_in_order_advice_takes_only_a_file_under_the_wide_floor() {
        use super::{in_order_advice_of, in_order_file, IN_ORDER_ADVICE, IN_ORDER_AT_MOST};
        // The engine's own floor, read and not copied: if it moves, this
        // fails until the rule moves with it.
        #[cfg(feature = "parallel")]
        assert_eq!(IN_ORDER_AT_MOST, rarkit::probe::wide_floor());
        assert!(in_order_file(true, false, 15_000_000));
        assert!(in_order_file(true, false, 0));
        assert!(in_order_file(true, false, IN_ORDER_AT_MOST));
        assert!(!in_order_file(true, false, IN_ORDER_AT_MOST + 1));
        assert!(!in_order_file(true, false, 100 << 20));
        assert!(!in_order_file(true, true, 15_000_000));
        assert!(!in_order_file(false, false, 15_000_000));
        assert!(in_order_advice_of(Some("1")));
        assert!(in_order_advice_of(Some(" ON ")));
        assert!(!in_order_advice_of(Some("0")));
        assert!(!in_order_advice_of(Some("off")));
        assert_eq!(in_order_advice_of(None), IN_ORDER_ADVICE);
        assert_eq!(in_order_advice_of(Some("2")), IN_ORDER_ADVICE);
    }

    use super::*;

    #[test]
    fn a_vint_is_seven_bits_a_byte_low_first() {
        assert_eq!(read_vint(&[0x00]), Some((0, 1)));
        assert_eq!(read_vint(&[0x7f]), Some((127, 1)));
        assert_eq!(read_vint(&[0x80, 0x01]), Some((128, 2)));
        assert_eq!(read_vint(&[0x80]), None);
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("rarkit-cli-{tag}-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    #[test]
    fn a_completed_input_keeps_the_length_it_opened_with() {
        use rarkit::RangeSource;
        use std::io::Write;
        let dir = scratch("completed");
        let path = dir.join("a.rar");
        std::fs::write(&path, b"0123456789").unwrap();
        let source =
            source_of(path.to_str().unwrap()).unwrap_or_else(|_| panic!("the source opens"));
        assert_eq!((source.len(), source.available()), (Some(10), 10));
        // Bytes arriving after the open are not read, and the length
        // does not move.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"abcdef")
            .unwrap();
        let mut buf = [0_u8; 32];
        assert_eq!(source.read_at(4, &mut buf).unwrap(), 6);
        assert_eq!(&buf[..6], b"456789");
        assert_eq!(source.read_at(10, &mut buf).unwrap(), 0);
        assert_eq!(source.read_at(u64::MAX, &mut buf).unwrap(), 0);
        assert_eq!(source.len(), Some(10));
        // A path replaced after the open: the descriptor still reads the
        // file it opened.
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"ZZ").unwrap();
        assert_eq!(source.read_at(0, &mut buf[..3]).unwrap(), 3);
        assert_eq!(&buf[..3], b"012");
        // Cut short after the open: an early end, which the engine reads
        // as truncation.
        let cut = dir.join("b.rar");
        std::fs::write(&cut, b"0123456789").unwrap();
        let source =
            source_of(cut.to_str().unwrap()).unwrap_or_else(|_| panic!("the source opens"));
        std::fs::OpenOptions::new()
            .write(true)
            .open(&cut)
            .unwrap()
            .set_len(4)
            .unwrap();
        assert_eq!(source.read_at(4, &mut buf).unwrap(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// THE WINDOWS HANDLE POOL gives back the file's bytes: eight threads
    /// reading ranges of one file at once, each through the handle its
    /// thread lands on, and the opening thread through the first.
    #[cfg(windows)]
    #[test]
    fn concurrent_reads_through_the_handle_pool_give_the_files_bytes() {
        use rarkit::RangeSource;
        let dir = scratch("pool");
        let path = dir.join("pool.bin");
        let data: Vec<u8> = (0..24u32 << 20)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8)
            .collect();
        std::fs::write(&path, &data).unwrap();
        let source = completed_input(std::fs::File::open(&path).unwrap(), &path);
        std::thread::scope(|scope| {
            for t in 0..8u64 {
                let (source, data) = (&source, &data);
                scope.spawn(move || {
                    let mut buf = vec![0u8; 1 << 20];
                    for k in 0..64u64 {
                        let at = ((t * 7_919 + k * 104_729) * 4_099) % (data.len() as u64 - 1);
                        let want = (data.len() as u64 - at).min(buf.len() as u64) as usize;
                        let got = source.read_at(at, &mut buf[..want]).unwrap();
                        assert!(got > 0 && buf[..got] == data[at as usize..at as usize + got]);
                    }
                });
            }
        });
        let mut head = [0u8; 64];
        assert_eq!(source.read_at(0, &mut head).unwrap(), 64);
        assert!(head[..] == data[..64]);
        drop(source);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A handle opened by path to what is no longer the SAME file is not
    /// read through: the archive renamed away and another file of the same
    /// length written in its place, a read from another thread still gives
    /// the file first opened.
    #[cfg(windows)]
    #[test]
    fn a_replaced_file_is_never_read_through_a_second_handle() {
        use rarkit::RangeSource;
        let dir = scratch("replaced");
        let path = dir.join("a.rar");
        let old = dir.join("a.old");
        let _ = std::fs::remove_file(&old);
        std::fs::write(&path, vec![0xAAu8; 1 << 20]).unwrap();
        let source = completed_input(std::fs::File::open(&path).unwrap(), &path);
        std::fs::rename(&path, &old).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&path, vec![0xBBu8; 1 << 20]).unwrap();
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let source = &source;
                scope.spawn(move || {
                    let mut buf = vec![0u8; 4096];
                    assert_eq!(source.read_at(0, &mut buf).unwrap(), 4096);
                    assert!(buf.iter().all(|&b| b == 0xAA), "read the replacement");
                });
            }
        });
        drop(source);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_device_is_not_a_completed_input() {
        use rarkit::RangeSource;
        // `/dev/zero` reports length 0; the plain File behind it still
        // reads, where a kept length of 0 would read nothing.
        let source = source_of("/dev/zero").unwrap_or_else(|_| panic!("the source opens"));
        let mut buf = [1_u8; 8];
        assert_eq!(source.read_at(0, &mut buf).unwrap(), 8);
        assert_eq!(buf, [0_u8; 8]);
    }

    #[test]
    fn a_missing_archive_fails_to_open_as_before() {
        let dir = scratch("missing");
        let path = dir.join("absent.rar");
        let mut session = Session::new(read_options(None));
        let ours = open_session(&mut session, path.to_str().unwrap()).unwrap_err();
        let lib = Session::new(read_options(None))
            .open_path(&path)
            .unwrap_err();
        assert_eq!(format!("{ours:?}"), format!("{lib:?}"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_that_is_not_rar5_has_no_first_block_type() {
        let dir = std::env::temp_dir().join(format!("rarkit-cli-sniff-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("plain.txt");
        std::fs::write(&path, b"not an archive").unwrap();
        assert_eq!(sniff_rar50_first_block(path.to_str().unwrap()), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// One thread, a 14 byte file, no pool: the head is cut at `len`, a
    /// shorter file gives all it has, and a missing file is the error.
    #[test]
    fn a_prefix_is_the_head_cut_at_len_and_a_short_file_is_whole() {
        let dir = std::env::temp_dir().join(format!("rarkit-cli-prefix-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("plain.txt");
        std::fs::write(&path, b"not an archive").unwrap();
        let name = path.to_str().unwrap();
        assert_eq!(read_prefix(name, 0).unwrap(), b"");
        assert_eq!(read_prefix(name, 3).unwrap(), b"not");
        assert_eq!(read_prefix(name, 14).unwrap(), b"not an archive");
        assert_eq!(read_prefix(name, 4096).unwrap(), b"not an archive");
        let absent = dir.join("absent.bin");
        assert!(read_prefix(absent.to_str().unwrap(), 8).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
    /// Spec F 3.2.12, the sniff alone, on files built here by the layout
    /// of 3.2.2: a signature, four bytes of checksum (never read), the
    /// size, then a header of that size that opens with the type. One
    /// thread, no pool, two files of 4 MiB and the rest under 20 KiB.
    #[test]
    fn the_first_block_is_answered_as_the_reference_answers_it() {
        const RAR5: &[u8] = b"Rar!\x1a\x07\x01\x00";
        const OLDER: &[u8] = b"Rar!\x1a\x07\x00";
        // A first block: `size` spelt as given, a header of `filled`
        // bytes that opens with `kind`.
        fn block(size: &[u8], kind: &[u8], filled: usize) -> Vec<u8> {
            let mut bytes = vec![0xAA, 0xBB, 0xCC, 0xDD];
            bytes.extend_from_slice(size);
            bytes.extend_from_slice(kind);
            bytes.resize(4 + size.len() + filled, 0x5A);
            bytes
        }
        let file = |lead: usize, signature: &[u8], rest: &[u8]| {
            let mut bytes = vec![0x20; lead];
            bytes.extend_from_slice(signature);
            bytes.extend_from_slice(rest);
            bytes
        };
        let dir = std::env::temp_dir().join(format!("rarkit-cli-first-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ask = |name: &str, bytes: &[u8]| {
            let path = dir.join(name);
            std::fs::write(&path, bytes).unwrap();
            let answer = sniff_rar50_first_block(path.to_str().unwrap());
            std::fs::remove_file(&path).unwrap();
            answer
        };
        let whole = block(&[0x21], &[4], 0x21);
        let rows: Vec<(&str, Vec<u8>, Option<u64>)> = vec![
            // FB1: an encryption header, whole, whatever follows it.
            ("hp", file(0, RAR5, &whole), Some(4)),
            (
                "hp-then-more",
                file(0, RAR5, &[&whole[..], &[0; 16]].concat()),
                Some(4),
            ),
            ("hp-lead-1001", file(1001, RAR5, &whole), Some(4)),
            ("hp-lead-reach-last", file(4_194_282, RAR5, &whole), Some(4)),
            (
                "hp-type-two-bytes",
                file(0, RAR5, &block(&[0x22], &[0x84, 0x00], 0x22)),
                Some(4),
            ),
            (
                "hp-size-two-bytes",
                file(0, RAR5, &block(&[0xA1, 0x00], &[4], 0x21)),
                Some(4),
            ),
            (
                "hp-long",
                file(0, RAR5, &block(&[0xF5, 0x80, 0x01], &[4], 16_501)),
                Some(4),
            ),
            // FB2: another first block, whole.
            ("plain", file(0, RAR5, &block(&[0x0C], &[1], 0x0C)), Some(1)),
            (
                "type-0",
                file(0, RAR5, &block(&[0x21], &[0], 0x21)),
                Some(0),
            ),
            (
                "type-128",
                file(0, RAR5, &block(&[0x22], &[0x80, 0x01], 0x22)),
                Some(128),
            ),
            // No answer: the file ends inside its first block.
            ("cut-sig-only", file(0, RAR5, &[]), None),
            ("cut-sig-plus-4", file(0, RAR5, &whole[..4]), None),
            ("cut-sig-plus-5", file(0, RAR5, &whole[..5]), None),
            ("cut-sig-plus-6", file(0, RAR5, &whole[..6]), None),
            ("cut-less-1", file(0, RAR5, &whole[..whole.len() - 1]), None),
            (
                "size-zero",
                file(0, RAR5, &block(&[0x00], &[4], 0x21)),
                None,
            ),
            // No answer: no RAR 5 signature where one is looked for, or
            // the older container's stands first.
            ("hp-lead-reach-miss", file(4_194_283, RAR5, &whole), None),
            ("byte8-01", file(0, b"Rar!\x1a\x07\x01\x01", &whole), None),
            ("older", file(0, OLDER, &whole), None),
            (
                "older-then-rar5",
                file(0, OLDER, &file(40, RAR5, &whole)),
                None,
            ),
            ("empty", Vec::new(), None),
            ("text", b"Rar! is a word, not an archive\n".to_vec(), None),
        ];
        for (name, bytes, answer) in rows {
            assert_eq!(ask(name, &bytes), answer, "{name}");
        }
        // Neither signature is skipped over: bytes that only begin like
        // one do not stop the search.
        let near = file(0, b"Rar!\x1a\x07\x05\x00", &file(40, RAR5, &whole));
        assert_eq!(ask("near-then-rar5", &near), Some(4));
        // A path that names nothing, and a directory.
        assert_eq!(
            sniff_rar50_first_block(dir.join("absent").to_str().unwrap()),
            None
        );
        assert_eq!(sniff_rar50_first_block(dir.to_str().unwrap()), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
