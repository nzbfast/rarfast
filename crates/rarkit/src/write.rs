//! Making archives: RAR 5, and the RAR 4 family at 2.9, 3.0 and 4.0 (API
//! spec section 7).
//!
//! Section 7 collapsed a product of types - compressed or not, encrypted
//! or not, whole-slice or streamed, each a type of its own - onto one
//! [`Writer`], one [`MemberSpec`] and one [`Payload`]. The three choices
//! are now an option, an option and a payload variant, which is why
//! there is so little surface here for so many combinations.

use std::io::{Read, Seek, Write};

use crate::error::{Corruption, Error, ErrorKind, Resource};
use crate::memory::MemoryPolicy;
use crate::read::Progress;
use crate::types::{HostOs, Password, Timestamp};
use crate::Result;

pub(crate) mod consts;
pub(crate) mod crypt;
pub(crate) mod engine;
pub(crate) mod filters;
pub(crate) mod options;
pub(crate) mod out;
pub(crate) mod rar4;
pub(crate) mod rar5;
pub mod revset;
pub(crate) mod store;
#[cfg(test)]
mod tests;
mod width;

/// A member's checksum as a writer carries it: the CRC32 in the header's
/// own field, or the BLAKE2sp of a hash record, never both (spec G 3.3.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Digest {
    /// CRC32, in the header's own 4 byte field.
    Crc32(u32),
    /// BLAKE2sp, in an extra record, with the CRC32 flag clear.
    Blake2sp([u8; 32]),
}

/// Builds one archive, or one set of volumes, in either family.
///
/// Members go in with [`add`](Writer::add), which records the member and
/// reads nothing. The bytes are pulled during whichever `finish_` call
/// ends the write, in the order they were added, so a
/// [`Payload::Reader`] is read through exactly once and never rewound -
/// which is what lets a caller stream a member it does not hold in
/// memory.
pub struct Writer<'a> {
    options: options::Resolved,
    members: Vec<engine::Planned<'a>>,
    /// What the member table and its names cost so far, against
    /// [`MemoryPolicy::max_member_table`].
    table_bytes: u64,
}

impl<'a> Writer<'a> {
    /// Check `options` through, and refuse now anything the chosen
    /// format cannot express.
    ///
    /// Every such combination is caught HERE, with
    /// [`Unsupported::WriteFeature`](crate::Unsupported::WriteFeature)
    /// naming it, before a byte of output exists - so a caller never
    /// discovers half way through a set that its options were
    /// impossible. Note one consequence:
    /// [`FilterPolicy::Detect`] is RAR 5 only, so
    /// `WriteOptions::default()` with a RAR 4 format is refused here
    /// rather than quietly resolved to `Off`, which would tell a caller
    /// who asked for filters nothing.
    pub fn new(options: WriteOptions) -> Result<Writer<'a>> {
        // The one seam package J owns: a RAR 4 filter request is refused
        // rather than resolved to `Off` behind the caller's
        // back (spec G section 3.14.7, SPEC-J section 3.9).
        crate::rar3_filters::refuse_written_filters(options.format, options.filters)?;
        Ok(Writer {
            options: options::resolve(options)?,
            members: Vec::new(),
            table_bytes: 0,
        })
    }

    /// Record one member. No payload byte is read here, and no header is
    /// built. The order of these calls is the order of the archive,
    /// except in a SOLID COMPRESSED archive under the default
    /// [`MemberOrder::ByType`], which the writer reorders the way
    /// [`MemberSortKey`] says before the first byte is drawn.
    ///
    /// In the RAR 4 family a member that is not a directory and whose
    /// `attributes` say SYMBOLIC LINK under a Unix host is refused here by
    /// name ([`Unsupported::WriteFeature`](crate::Unsupported::WriteFeature)).
    /// There that mode alone makes the member a link whose target is its
    /// content (spec F 3.3.12), to this crate's own reader as to any
    /// other, and a [`MemberSpec`] carries no link target: the archive
    /// would be written `Ok` and then not extract as the file it was
    /// given as. RAR 5 marks a link with a record of its own, which this
    /// writer never writes, so there the same mode word is only a mode
    /// word on a plain member, and is kept. An archive this writer
    /// returns `Ok` for reads back.
    pub fn add(&mut self, member: MemberSpec<'a>) -> Result<()> {
        check_name(member.name, self.options.is_rar4())?;
        // The reader's own rule (`read::rar4`), turned round.
        if self.options.is_rar4()
            && !member.is_directory
            && member.host_os == HostOs::Unix
            && member.attributes & consts::UNIX_TYPE_BITS == consts::UNIX_TYPE_SYMLINK
        {
            return Err(options::refuse(
                "a RAR 4 family member whose Unix attributes say symbolic link (this writer \
                 records no link target)",
            ));
        }

        let size = match (&member.payload, member.is_directory) {
            (_, true) => 0,
            (Payload::Bytes(data), false) => data.len() as u64,
            (Payload::Reader { size, .. } | Payload::Seekable { size, .. }, false) => *size,
        };
        if self.options.is_rar4() && size >= consts::R4_SIZE_FIELD_LIMIT {
            // The high size fields carry it; a target that cannot is
            // refused before any output.
            if matches!(self.options.format, WriteFormat::Rar4(Rar4Version::V29)) {
                return Err(options::refuse(
                    "a member over 4 GiB under a RAR 2.9 target",
                ));
            }
        }

        // Charged only once the member is taken: a refused member is not
        // recorded, so it costs a later one nothing.
        let cost = (member.name.len() + std::mem::size_of::<engine::Planned<'_>>()) as u64;
        let table_bytes = self.table_bytes + cost;
        if table_bytes > self.options.memory.max_member_table {
            return Err(Error::new(ErrorKind::LimitExceeded {
                resource: Resource::MemberTable,
                needed: table_bytes,
                limit: self.options.memory.max_member_table,
            }));
        }
        self.table_bytes = table_bytes;

        // A source that can seek is held aside until the run's first
        // act, which reads the store rule's samples through it and then
        // makes it the reader it is from there on.
        let (payload, seekable) = match member.payload {
            Payload::Bytes(data) => (engine::Stream::Bytes(data), None),
            Payload::Reader { reader, crc32, .. } => {
                (engine::Stream::Reader { reader, crc32 }, None)
            }
            Payload::Seekable { reader, crc32, .. } => {
                (engine::Stream::Bytes(&[]), Some((reader, crc32)))
            }
        };
        self.members.push(engine::Planned {
            name: member.name,
            payload,
            mtime: member.mtime,
            attributes: member.attributes,
            host_os: member.host_os,
            is_directory: member.is_directory,
            size,
            seekable,
        });
        Ok(())
    }

    /// Draw every member's bytes and write the whole archive to `out`,
    /// as one file.
    pub fn finish_into<W: Write>(self, out: W) -> Result<WriteReport> {
        self.finish_into_with(out, &mut ())
    }

    /// [`Writer::finish_into`], reporting through `progress`.
    ///
    /// The write side uses the READER's [`Progress`](crate::Progress)
    /// rather than a trait of its own (SPEC-API 4.4 and 7.1, and spec G
    /// 3.13's erratum of 19 Sep 2026, which decided it). A writer calls
    /// [`output`](crate::Progress::output) with the payload bytes written
    /// so far over all members and
    /// [`volume_done`](crate::Progress::volume_done) when a volume is
    /// closed and complete; it never calls
    /// [`released`](crate::Progress::released), whose default body
    /// already allows that. Reports are bounded: at most one per chunk
    /// copied and one per member, never one per byte, and never a report
    /// that allocates.
    ///
    /// **Stopping.** A callback's error ends the run and IS the error
    /// this call returns, so a callback that raises its own returns
    /// [`Error::caller`](crate::Error::caller) and the run ends as
    /// [`ErrorKind::Caller`](crate::ErrorKind::Caller), and one that asks
    /// to STOP returns `Error::new(ErrorKind::Cancelled)` and the run
    /// ends as [`ErrorKind::Cancelled`](crate::ErrorKind::Cancelled).
    /// Either ends it promptly, without finishing the member, and the
    /// output is left as far as it got: partial output is the caller's to
    /// discard.
    pub fn finish_into_with<W: Write, P: Progress>(
        mut self,
        out: W,
        progress: &mut P,
    ) -> Result<WriteReport> {
        if self.options.volume_set() {
            return Err(options::refuse(
                "a volume set through finish_into, which writes one archive",
            ));
        }
        let members = self.take_members();
        engine::run(self.options, members, out::OneVolume(Some(out)), progress)
    }

    /// Write one archive to an output that can SEEK.
    ///
    /// The same archive as [`Writer::finish_into`], reached in one pass.
    /// A field the writer cannot fill until the member's bytes have
    /// passed is written as a placeholder and corrected where it lies, so
    /// two things that `finish_into` cannot avoid go away:
    ///
    /// - **nothing is held.** `finish_into` holds the bytes from an
    ///   uncorrected placeholder onwards and reports them in
    ///   [`WriteReport::held_volume_bytes`]; here that figure is always
    ///   zero.
    /// - **no payload is read twice.** `finish_into` has to know a
    ///   [`Payload::Bytes`] member's checksum before it writes the
    ///   header, which is one pass over the member for the checksum and
    ///   one for the copy. Here the checksum is taken as the bytes pass
    ///   and the header is corrected afterwards.
    ///
    /// The archive starts wherever `out` is positioned, so one may be
    /// appended to something else; nothing before that point is read or
    /// written. A volume set is [`Writer::finish_volumes`]: this call
    /// refuses one, as `finish_into` does.
    pub fn finish_seek<W: Write + Seek>(self, out: W) -> Result<WriteReport> {
        self.finish_seek_with(out, &mut ())
    }

    /// [`Writer::finish_seek`], reporting through `progress`, which
    /// [`Writer::finish_into_with`] describes.
    pub fn finish_seek_with<W: Write + Seek, P: Progress>(
        mut self,
        out: W,
        progress: &mut P,
    ) -> Result<WriteReport> {
        if self.options.volume_set() {
            return Err(options::refuse(
                "a volume set through finish_seek, which writes one archive",
            ));
        }
        let members = self.take_members();
        engine::run(self.options, members, out::OneSeekable::new(out)?, progress)
    }

    /// Write one archive to an output that can SEEK and be READ BACK.
    ///
    /// The same archive as [`Writer::finish_seek`], byte for byte, and
    /// the same one pass. What reading back buys is an inline recovery
    /// record ([`WriteOptions::recovery_percent`]) computed from the
    /// archive where it lies: `finish_into` and `finish_seek` have to keep
    /// a COPY of every byte of the archive to compute it from, which is
    /// the archive's whole length in memory, where this reads the archive
    /// back once its protected part is final, a stripe at a time, and
    /// holds a bounded few megabytes whatever the archive's length. A
    /// `std::fs::File` opened for reading and writing is such an output.
    ///
    /// The archive starts wherever `out` is positioned, as for
    /// `finish_seek`, and only bytes this call wrote are read back.
    pub fn finish_seek_read<W: Read + Write + Seek>(self, out: W) -> Result<WriteReport> {
        self.finish_seek_read_with(out, &mut ())
    }

    /// [`Writer::finish_seek_read`], reporting through `progress`, which
    /// [`Writer::finish_into_with`] describes.
    pub fn finish_seek_read_with<W: Read + Write + Seek, P: Progress>(
        mut self,
        out: W,
        progress: &mut P,
    ) -> Result<WriteReport> {
        if self.options.volume_set() {
            return Err(options::refuse(
                "a volume set through finish_seek_read, which writes one archive",
            ));
        }
        let members = self.take_members();
        let source = out::OneReadable(out::OneSeekable::new(out)?);
        engine::run(self.options, members, source, progress)
    }

    /// Write the members as a volume set, asking `out` for each
    /// volume's writer as that volume is reached, so no volume is held
    /// whole unless a size field forces it.
    pub fn finish_volumes<O: VolumeOut>(self, out: &mut O) -> Result<WriteReport> {
        self.finish_volumes_with(out, &mut ())
    }

    /// [`Writer::finish_volumes`], reporting through `progress`, which
    /// [`Writer::finish_into_with`] describes.
    pub fn finish_volumes_with<O: VolumeOut, P: Progress>(
        mut self,
        out: &mut O,
        progress: &mut P,
    ) -> Result<WriteReport> {
        if !self.options.volume_set() {
            return Err(options::refuse(
                "a volume set with no volume size, which is one archive",
            ));
        }
        let members = self.take_members();
        engine::run(self.options, members, out::ManyVolumes(out), progress)
    }

    /// The members in the order the archive will hold them: as added,
    /// or, in a solid compressed archive under [`MemberOrder::ByType`],
    /// in [`MemberSortKey`]'s order. A stored archive is left
    /// alone even when solid, because nothing in it shares history: the
    /// reference does the same, measured (`rar a -s -m0` keeps the order
    /// it scanned in).
    fn take_members(&mut self) -> Vec<engine::Planned<'a>> {
        let mut members = std::mem::take(&mut self.members);
        if self.options.solid && !self.options.stored() && self.options.order == MemberOrder::ByType
        {
            members.sort_by(|left, right| {
                MemberSortKey::of(left.name, left.size, left.is_directory).cmp(&MemberSortKey::of(
                    right.name,
                    right.size,
                    right.is_directory,
                ))
            });
        }
        members
    }
}

/// The order a solid archive's members are written in.
///
/// A solid archive compresses each member against the history of those
/// before it, so what sits next to what decides how much there is to
/// find: members of one type placed together share their history, and
/// the same members interleaved with others do not. Measured on 9,681
/// small members, the order they were given in (name order, which walks
/// a tree directory by directory) wrote a solid archive 30 per cent
/// larger than the same members grouped by extension.
///
/// It reaches a SOLID COMPRESSED archive only. A non-solid archive and a
/// stored one are always written in the order members were added.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MemberOrder {
    /// Grouped by type, the way reference `rar` 7.23 orders a solid
    /// archive unless it is given `-ds`: see [`MemberSortKey`] for the
    /// whole rule.
    #[default]
    ByType,
    /// Exactly the order of the [`Writer::add`] calls, which is what
    /// `rar -ds` asks for.
    AsAdded,
}

/// Where one member sorts under [`MemberOrder::ByType`].
///
/// The rule is reference `rar` 7.23's own, observed from outside on a
/// solid create (`rar a -s`) with the probes that
/// showed it:
///
/// 1. every file comes before every directory;
/// 2. files are ordered by their EXTENSION, the bytes after the last `.`
///    of the last path component. A component with no `.` at all sorts
///    before every component that has one; one ending in `.` has an empty
///    extension, which sorts after that and before every other (so `a`,
///    `c`, `b.`, `d.`, `e..`, `0.x`); `.hidden` has the extension
///    `hidden`. Then by that last component whole; then by size, smallest
///    first; then by the whole stored name;
/// 3. directories are ordered deepest first, and within one depth by the
///    same keys as files.
///
/// Every comparison is on the stored bytes, case and all, so `TXT`, `Txt`
/// and `txt` are three extensions and `B.txt` sorts before `a.txt`. The
/// sort is stable, so members equal on every key keep the order they were
/// added in.
///
/// It is public so that a caller building its own member list (the
/// `rarkit` command line does, to print its progress lines in archive
/// order) can put the list in the writer's order first and pass
/// [`MemberOrder::AsAdded`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemberSortKey<'a> {
    directory: bool,
    /// Directories only: `u32::MAX` less the depth, so deeper sorts first.
    height: u32,
    /// `None` for a last component with no `.`, which sorts before every
    /// component that has one, even one that ends in `.`.
    extension: Option<&'a [u8]>,
    last: &'a [u8],
    size: u64,
    name: &'a [u8],
}

impl<'a> MemberSortKey<'a> {
    /// The key of a member stored as `name` (the API's names, `/`
    /// between components), `size` bytes long, a directory or not.
    pub fn of(name: &'a [u8], size: u64, is_directory: bool) -> MemberSortKey<'a> {
        let trimmed = name.strip_suffix(b"/").unwrap_or(name);
        let last = match trimmed.iter().rposition(|byte| *byte == b'/') {
            Some(at) => &trimmed[at + 1..],
            None => trimmed,
        };
        let extension = last
            .iter()
            .rposition(|byte| *byte == b'.')
            .map(|at| &last[at + 1..]);
        let depth = trimmed.iter().filter(|byte| **byte == b'/').count();
        MemberSortKey {
            directory: is_directory,
            height: if is_directory {
                u32::MAX - u32::try_from(depth).unwrap_or(u32::MAX)
            } else {
                0
            },
            extension,
            last,
            size,
            name,
        }
    }
}

impl Ord for MemberSortKey<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (
            self.directory,
            self.height,
            self.extension,
            self.last,
            self.size,
            self.name,
        )
            .cmp(&(
                other.directory,
                other.height,
                other.extension,
                other.last,
                other.size,
                other.name,
            ))
    }
}

impl PartialOrd for MemberSortKey<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// A name a writer can store (spec G 3.4.4 and section 4): non-empty,
/// UTF-8, no NUL, no `..` component behind either separator, no drive (a
/// letter, a colon and a separator), never
/// absolute (rooted at `/` or at a backslash), and under RAR 4 no longer than a header whose own length is
/// a 16 bit field can carry (`rar4::MAX_NAME`) and holding no backslash.
///
/// A name is never rewritten to make it legal, because a caller that
/// meant a different name should say so.
///
/// **The backslash rule is a RAR 4 one and it is a real refusal.** That
/// family stores a backslash between path components and this crate's
/// reader converts it back to the API's `/` (spec G 3.14.5), so a name
/// that already HOLDS a backslash comes back as a different name: `a\b`
/// goes in and `a/b` comes out. The format cannot tell the two apart, so
/// the name is refused rather than silently changed. Found by the
/// `write_members` fuzz target of section 6.4.
pub(crate) fn check_name(name: &[u8], rar4: bool) -> Result<()> {
    let bad = name.is_empty()
        || name.contains(&0)
        // Rooted: a backslash roots a name on the systems the `..` rule
        // below already takes it as a separator for.
        || matches!(name.first(), Some(b'/' | b'\\'))
        || std::str::from_utf8(name).is_err()
        // An empty or `.` component is still taken, though 3.4.4 lists
        // it: reference `rar` stores `sub/./b.txt` and renames to
        // `s/d/a.txt/`, and the CLI that matches it writes through here.
        // 3.4.4 and SPEC-CLI disagree on those two; the disagreement is
        // open.
        // A backslash is a separator to the systems that would be
        // walked out of, whichever family stores the name, so a parent
        // step behind one is a parent step.
        || name
            .split(|byte| *byte == b'/' || *byte == b'\\')
            .any(|part| part == b"..")
        // A drive: a letter, a colon and a separator. A colon alone is
        // an ordinary byte of a Unix name (`a:b`), which the reference
        // archives as it is, so it is not taken for one.
        || (name.len() >= 3
            && name[0].is_ascii_alphabetic()
            && name[1] == b':'
            && matches!(name[2], b'/' | b'\\'))
        || (rar4 && name.len() > rar4::MAX_NAME)
        || (rar4 && name.contains(&b'\\'));
    if bad {
        return Err(Error::new(ErrorKind::Corrupt(Corruption::MemberName)).with_member(name));
    }
    Ok(())
}

/// The file name volume `index` of a set of `total` volumes takes
/// (spec G 3.10.4).
///
/// The number in the numbered form is zero padded to the width of the
/// LAST volume's number, minimum one digit, so a four volume set is
/// `part1` to `part4` and an eleven volume set is `part01` to `part11`. A
/// writer that does not know the count in advance cannot choose the
/// width, which is why [`Writer::finish_volumes`] hands the index to
/// [`VolumeOut`] and the caller names the file; this function is the rule
/// the caller applies.
pub fn volume_file_name(stem: &str, index: u32, total: u32, naming: VolumeNaming) -> String {
    match naming {
        VolumeNaming::Classic if index == 0 => format!("{stem}.rar"),
        VolumeNaming::Classic => format!("{stem}.r{:02}", index - 1),
        VolumeNaming::Numbered => {
            let width = total.max(1).to_string().len();
            format!("{stem}.part{:0width$}.rar", index + 1, width = width)
        }
    }
}

/// One member, as the caller describes it to [`Writer::add`].
pub struct MemberSpec<'a> {
    /// The name to record, in the bytes the caller wants stored.
    pub name: &'a [u8],
    /// Where the content is to be read from.
    pub payload: Payload<'a>,
    /// The modification time to record, if any.
    pub mtime: Option<Timestamp>,
    /// The attribute word, read according to `host_os`.
    pub attributes: u32,
    /// The system to claim wrote this, which decides how a reader takes
    /// `attributes`.
    pub host_os: HostOs,
    /// Whether this entry is a directory rather than a file.
    pub is_directory: bool,
}

/// Where one member's content comes from.
pub enum Payload<'a> {
    /// Already in memory, all of it.
    Bytes(&'a [u8]),
    /// Streamed, and read exactly once during the `finish_` call.
    ///
    /// Whether the caller knows the CRC32 in advance decides how much
    /// the writer has to hold. Given it, a stored member's header can be
    /// written ahead of its data and the whole member streams through in
    /// one pass with nothing to go back and fix. Without it, the writer
    /// works the CRC32 out as the bytes pass and then patches the
    /// header, or, where the output cannot be seeked, holds that one
    /// member's HEADER until the figure is known. Its data is never
    /// held.
    ///
    /// The one exception is a COMPRESSED member of at most 256 KiB (one
    /// parse block) in a non-solid archive that is not a volume set: the
    /// writer may pull it whole ahead of the member it is writing, so
    /// that the worker team can encode it beside others (see
    /// [`WriteOptions::workers`]). It is still read exactly once, from
    /// the writing thread, and in `add` order; what is held at once is
    /// bounded, at most 4 MiB of such members' input. A compressed member
    /// of at most one window (the dictionary, at most 8 MiB) in a SOLID
    /// archive that is not a volume set may be pulled whole ahead the
    /// same way, so that a run of such members is encoded as one batch:
    /// its bytes join the run's history as it is pulled, and a batch
    /// stages at most 8 MiB of input. The next batch's members may be
    /// pulled while one batch is encoded, still by the writing thread and
    /// in `add` order, which holds at most that much again.
    Reader {
        /// The stream to read the content from.
        reader: &'a mut (dyn Read + Send),
        /// How many bytes `reader` will produce. Not an estimate: the
        /// header records it.
        size: u64,
        /// The CRC32 over those bytes, when the caller already has it.
        crc32: Option<u32>,
    },
    /// Streamed like [`Payload::Reader`], from a source that can also
    /// SEEK: a file.
    ///
    /// The member is the `size` bytes from the stream's position when the
    /// writer first touches it, which need not be the stream's start, to
    /// its end: as a reader does, the source ends where the member does.
    /// Everything [`Payload::Reader`] says holds here too, with one
    /// difference, for a member of 4 GiB and more, and it is why this
    /// variant exists. The writer decides from SAMPLES whether a member
    /// that will not compress is written stored (spec G 3.8.3), and a
    /// stream it may read only once can be sampled only at its head: its
    /// first 32 MiB, held until the decision. A member whose head has
    /// nothing in it to compress and whose body does (a disk image, a tar
    /// behind a big member) was then stored whole, and one whose head compresses
    /// in front of a body that does not went through the compressor for
    /// nothing. A LARGE member from a source that can seek is sampled
    /// across the WHOLE member instead: the writer notes where the stream
    /// stands, reads the
    /// samples where they lie (64 KiB each at a seek, in rising order,
    /// and no further than the vote needs: 2 or 5 of them for a member
    /// that compresses, 16 for one that is stored), returns to the start
    /// and from there reads the member exactly once, in order. No head
    /// is held for it.
    ///
    /// A member voted on this way is compressed only
    /// where its samples say there is something to gain: once more than
    /// four of them compress, AND the samples read so far pack together to
    /// under 99 percent of their bytes. A big member has stretches that pack to
    /// 98 or 99 percent, and five such samples of sixteen would otherwise
    /// send it through the compressor to save a fraction of a percent.
    ///
    /// That path is taken for a member of AT LEAST 4 GiB (4,294,967,296
    /// bytes) that the rule samples. The sixteen samples are sixteen
    /// seeks, which on a cold hard disk cost about a fifth of a second a
    /// member whatever its size: nothing beside a member that large, and
    /// more than the read itself for one of tens of mebibytes. A smaller
    /// member is read exactly as a [`Payload::Reader`] is, judged on its
    /// first 32 MiB, and never sought. Where the first seek
    /// fails (the source cannot seek after all) nothing has been read,
    /// and the member is treated as a [`Payload::Reader`]. A source that
    /// changes between the samples and the read is read as any reader is:
    /// the bytes that are read are the ones written and checksummed, a
    /// shorter one is `Truncated`, and the verdict taken stands.
    Seekable {
        /// The source to read the content from, standing at the
        /// member's first byte.
        reader: &'a mut (dyn ReadSeek + Send),
        /// How many bytes the member has. Not an estimate: the header
        /// records it.
        size: u64,
        /// The CRC32 over those bytes, when the caller already has it.
        crc32: Option<u32>,
    },
}

/// A source that can be read and sought: what [`Payload::Seekable`]
/// borrows. Every `Read + Seek` type is one.
pub trait ReadSeek: Read + Seek {}

impl<T: Read + Seek + ?Sized> ReadSeek for T {}

/// Where the volumes of a set are to be written.
///
/// The writer asks for one volume at a time, in order, as it reaches it,
/// so an implementation may create each file at the moment it is wanted.
///
/// `volume` hands back the writer for the volume about to be filled, and
/// `finished` takes it back once its last byte is written, in order, so
/// that a provider that collects volumes rather than writing them to
/// files can keep them.
pub trait VolumeOut {
    /// What one volume is written to.
    type W: Write;

    /// Somewhere to put volume `index`, counting from zero.
    fn volume(&mut self, index: u32) -> Result<Self::W>;

    /// The finished volume `index`. The default drops it, which is what a
    /// provider writing straight to files wants.
    fn finished(&mut self, index: u32, volume: Self::W) -> Result<()> {
        let _ = (index, volume);
        Ok(())
    }

    /// Whether a volume this provider hands out can be written back
    /// over: a field laid down as a placeholder corrected where it
    /// already lies, rather than the bytes after it being held until the
    /// figure is known.
    ///
    /// The default is `false`, which is the behaviour every provider had
    /// before this pair existed, so nothing that does not override it
    /// changes. A provider whose volume is a file it opened for reading
    /// and writing, or a buffer in memory, can answer `true` and
    /// implement [`VolumeOut::patch`], and then two things follow: a
    /// member whose checksum is not known until its bytes have passed
    /// holds nothing ([`WriteReport::held_volume_bytes`] stays zero), and
    /// a COMPRESSED member larger than one window is written as its
    /// encoder produces it rather than being held whole (spec G 3.5 and
    /// 3.7.3).
    ///
    /// **Whether the archive's bytes are the same either way.** They are,
    /// everywhere but one case, which spec G 3.5 grants and bounds:
    ///
    /// - A SOLID volume set, a stored archive, the reference layout and
    ///   every member of one window or smaller are byte for byte the same
    ///   over either kind of output, an encrypted one included (the
    ///   streamed walk cuts an encrypted member where the held walk does). So is any
    ///   member whose held-whole write, its packed bytes counted twice,
    ///   fits the policy's
    ///   [`MemoryPolicy::working_limit`](crate::MemoryPolicy::working_limit)
    ///   where the caller named no ceiling
    ///   (`MemoryPolicy::limit_named` false; spec G 3.5's held-member rule).
    /// - The exception is a member larger than one window, of a NON-SOLID
    ///   volume set or of one archive, that the writer STREAMS: where the
    ///   caller named a ceiling that holding it whole would pass (decided
    ///   20 Sep 2026), or, with no ceiling named, where that same
    ///   held-whole write, its packed bytes counted twice, would not fit
    ///   the policy's own `working_limit` (decided 28 Sep 2026 and
    ///   restated 30 Sep 2026; a member of one archive
    ///   in a solid set included).
    ///   A provider that can patch streams it, laying each fragment's
    ///   packed size field down at a reserved width; a fragment that
    ///   fills its volume is written as the held walk writes it, and only
    ///   a LAST fragment's field can be a digit wider (under a named
    ///   ceiling the packed stream can differ too, since the walks' waves
    ///   then differ). A provider that cannot patch has nowhere to
    ///   correct the field, so it holds the member whole instead, writes
    ///   the bytes the default mode writes, completes the archive rather
    ///   than failing it, and, where the caller named a
    ///   ceiling, reports the excess in
    ///   [`WriteReport::ceiling_exceeded_by`]. Both archives are valid
    ///   and reference `rar t` and `unrar t` accept both.
    fn can_patch(&self) -> bool {
        false
    }

    /// Writes `bytes` over `volume`'s own bytes at `at`, counted from
    /// the volume's first, and leaves it positioned at the end again.
    ///
    /// Called only when [`VolumeOut::can_patch`] answers `true`, and
    /// only over bytes this writer has already written to that same
    /// volume; `bytes` never runs past what is there. The default
    /// panics, because the writer never calls it otherwise.
    fn patch(&mut self, volume: &mut Self::W, at: u64, bytes: &[u8]) -> Result<()> {
        let _ = (volume, at, bytes);
        unreachable!("a patch on a volume provider that did not say it could")
    }

    /// Whether a volume this provider hands out can be READ BACK while it
    /// is being written, which a provider that can also
    /// [`patch`](VolumeOut::patch) may answer `true` to.
    ///
    /// It matters only to an inline recovery record
    /// ([`WriteOptions::recovery_percent`]). Without it the writer keeps a
    /// copy of each volume as it is written, to compute the volume's record
    /// from, which is a whole volume in memory. With it (and with
    /// [`VolumeOut::can_patch`]) the record is laid down and filled in
    /// where it lies from the volume read back a stripe at a time, and the
    /// writer holds a bounded few megabytes whatever the volume's size.
    /// The volumes' bytes are the same either way. The default is `false`.
    fn can_read_back(&self) -> bool {
        false
    }

    /// Fills `buf` with `volume`'s own bytes at `at`, counted from the
    /// volume's first, and leaves it positioned at the end again.
    ///
    /// Called only when [`VolumeOut::can_read_back`] answers `true`, only
    /// over bytes this writer has already written to that same volume,
    /// and after `volume` has been flushed. The default panics, because
    /// the writer never calls it otherwise.
    fn read_back(&mut self, volume: &mut Self::W, at: u64, buf: &mut [u8]) -> Result<()> {
        let _ = (volume, at, buf);
        unreachable!("a read back from a volume provider that did not say it could")
    }
}

/// Collects each volume in memory, in order.
///
/// A volume in memory can be written back over, so this provider patches
/// (see [`VolumeOut::can_patch`]): it is the in-memory path for
/// everything a seekable output buys, and it is what this crate's own
/// tests measure that path with.
impl VolumeOut for Vec<Vec<u8>> {
    type W = Vec<u8>;

    fn volume(&mut self, _index: u32) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }

    fn finished(&mut self, index: u32, volume: Vec<u8>) -> Result<()> {
        debug_assert_eq!(index as usize, self.len(), "volumes arrived out of order");
        self.push(volume);
        Ok(())
    }

    fn can_patch(&self) -> bool {
        true
    }

    fn patch(&mut self, volume: &mut Vec<u8>, at: u64, bytes: &[u8]) -> Result<()> {
        let at = at as usize;
        volume[at..at + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    fn can_read_back(&self) -> bool {
        true
    }

    fn read_back(&mut self, volume: &mut Vec<u8>, at: u64, buf: &mut [u8]) -> Result<()> {
        let at = at as usize;
        buf.copy_from_slice(&volume[at..at + buf.len()]);
        Ok(())
    }
}

/// Every decision a write needs, settled before it starts.
///
/// [`Writer::new`] validates the whole of this against the chosen
/// format, so an option that cannot be honoured is an error at
/// construction rather than a surprise at the end.
#[derive(Debug)]
pub struct WriteOptions {
    /// Which family, and for RAR 4 which target within it.
    pub format: WriteFormat,
    /// Whether to compress, and how hard.
    pub method: WriteMethod,
    /// The password for the whole archive; one for all members, or
    /// none at all.
    pub password: Option<Password>,
    /// Whether to encipher the headers too, so that even listing needs
    /// the password.
    pub encrypt_headers: bool,
    /// Whether members share one compression history, which compresses
    /// many small files far better and makes each depend on those
    /// before it.
    pub solid: bool,
    /// The order a SOLID COMPRESSED archive's members are written in:
    /// grouped by type (the default, as reference `rar` does
    /// unless given `-ds`), or as added. Ignored by any other archive,
    /// which is always written in the order members were added.
    pub order: MemberOrder,
    /// How many payload bytes go in each volume. `None` writes a single
    /// archive instead of a set.
    ///
    /// This counts a volume's PAYLOAD only: the signature, the headers
    /// and the end block sit on top of it, so the volume FILE is larger
    /// than this figure by whatever its own blocks cost. A caller
    /// splitting for a medium, an upload or a Usenet posting wants
    /// [`WriteOptions::volume_file_size`] instead, which caps the file.
    pub volume_size: Option<u64>,
    /// The whole volume FILE's cap in bytes; `None` = use
    /// [`WriteOptions::volume_size`].
    ///
    /// This is the budget the reference `rar`'s `-v<size>` means: the
    /// signature, every header, the end block and any inline recovery
    /// record are all counted against it, so no volume the run writes is
    /// ever longer than this. Only the LAST volume may be shorter than
    /// the rest, and it is shorter by whatever the archive had left.
    ///
    /// **rarkit does not pad a volume up to the cap.** The reference
    /// leaves every non-final volume at exactly `-v<size>` by writing
    /// zero bytes after the end block (spec G 3.10.6 and question 5, and
    /// the measurement in this crate's `volume_budget` tests); rarkit
    /// writes the content and stops, so a volume is at most the cap
    /// rather than exactly it. The trailing zeros are not a block, every
    /// reader skips them, and a poster pays for them.
    ///
    /// Setting this beside [`WriteOptions::volume_size`] is refused by
    /// [`Writer::new`]: they are two ways to say one thing.
    pub volume_file_size: Option<u64>,
    /// Which naming scheme a RAR 4 family set uses.
    pub volume_naming: VolumeNaming,
    /// How much of each volume to spend on an inline recovery record,
    /// as a percentage. `None` writes none.
    pub recovery_percent: Option<u32>,
    /// Which check value to record per member. BLAKE2sp needs RAR 5.
    pub checksum: ChecksumKind,
    /// Whether to look for content the standard filters improve.
    pub filters: FilterPolicy,
    /// Whether to spend the optimal parse's time for its ratio.
    pub optimal_parse: bool,
    /// A rarkit-only option, ON by default
    /// (spec G 3.8.1, spec H3 8.1): at levels 4 and 5, a non-solid member
    /// of at most 262,144 bytes takes the lone LAZY parse, level 3's own
    /// lone effort; `false` gives it level 3's optimal chain parse
    /// instead, the earlier default, for a few bytes (0.12% on small20k,
    /// 0.24% on tree5k at level 5) at about 1.6x to 2.4x the CPU. A no-op
    /// at level 3, whose small members take the lazy parse either way,
    /// and it reaches no level 1 or 2 member, no larger member and no
    /// solid one. `rarfast` sets it from `RARKIT_SMALL_LAZY` (`0` off);
    /// no rar dialect switch does.
    pub small_member_lazy: bool,
    /// The store rule inside a SOLID set (spec G 3.8.3 and 3.9), ON by
    /// default: a solid member of 1 MiB and more whose samples have
    /// nothing in them to compress is written STORED where it stands, and
    /// the run's history carries past it to the member after. A solid set
    /// of video is then written in the wall of a copy (timed on eight
    /// videos of 8.76 GB, 2.4 to 3.9 times faster at levels 1 and 3 and 17
    /// times at level 5, for 0.24 percent more archive). `false` keeps
    /// every solid member in the compressor, byte for byte as before 1 Oct
    /// 2026. It reaches solid sets only, at every level and in both
    /// families. What it gives away is two copies of one incompressible
    /// file less than a dictionary apart, which the chain would have
    /// matched. `rarfast` sets it from `RARKIT_SOLID_STORE` (`0` off); no
    /// rar dialect switch does.
    pub solid_store: bool,
    /// A rarkit-only option (spec G 3.8.3): at level 3, a parse
    /// block the incompressible sample sends to the floor takes the floor's
    /// own LAZY parse, exactly as level 3 wrote it before the scan,
    /// instead of the floor scan. Off by default. It reaches level 3 only:
    /// levels 1 and 2 always take the scan, levels 4 and 5 never do.
    /// `rarfast` sets it from `RARKIT_L3_FLOOR_LAZY`; no rar dialect
    /// switch does.
    pub level3_floor_lazy: bool,
    /// A rarkit-only option: level 3 parses with the optimal
    /// parse over its hash chains, 8 links deep, as it first did,
    /// instead of the lazy parse that is level 3's default since
    /// (32 links deep with the backward extension, 64 at first and
    /// with `level3_deep`). Off by default. It reaches level 3 only (and the
    /// RAR 2.9 method's level 3, which shares the ladder); a level 3 member
    /// short enough to be lone keeps the lazy parse either way.
    /// `rarfast` sets it from `RARKIT_L3_OPTIMAL` (`1` on); no rar
    /// dialect switch does.
    pub level3_optimal: bool,
    /// The backward extension's rarkit-only option: level 3's lazy
    /// parse follows its hash chains 64 links deep instead of 32. Off by default. It is a few
    /// tenths of a percent smaller on text and on the solid trees and
    /// takes 6 to 40 percent more create wall (timed on a Zen 4 rental). It
    /// reaches level 3 only, and `level3_optimal` overrides it. `rarfast`
    /// sets it from `RARKIT_L3_DEEP` (`1` on); no rar dialect switch does.
    pub level3_deep: bool,
    /// The backward extension's rarkit-only option at levels 1 and 2: their
    /// lazy parse begins a match the hash chains offered up to 32 bytes
    /// earlier, where the bytes before it agree at its distance. Off by
    /// default: timed 30 Sep 2026 it was 2.3 to 5.0 percent smaller for
    /// level wall on x86-64 and 1 to 3 percent more create wall on
    /// aarch64. Level 3 has the extension always. It reaches levels 1 and 2
    /// only, and level 1 only in its priced form (`level1_priced`).
    /// `rarfast` sets it from `RARKIT_L12_EXTEND` (`1` on); no rar
    /// dialect switch does.
    pub low_levels_extend: bool,
    /// A rarkit-only option (spec G 3.8.1, spec H3 8.1): at
    /// level 4, a member that is not lone keeps the OPTIMAL parse over the
    /// tree (cut 8, four hint slots), exactly as level 4 first wrote
    /// it, instead of the default lazy parse over the tree (cut
    /// 12, one hint slot). Off by default. It reaches level 4 only, and no
    /// lone member (`small_member_lazy` governs those). `rarfast` sets it
    /// from `RARKIT_L4_OPTIMAL`; no rar dialect switch does. It overrides
    /// `level4_tree` where both are on.
    pub level4_optimal: bool,
    /// A rarkit-only option (spec G 3.8.1, spec H3 8.1, 1 Oct 2026): at
    /// level 4, a member that is not lone keeps the lazy parse over the
    /// TREE (cut 12, one hint slot, two in a solid run, with the backward
    /// extension) instead of the default, level 3's lazy parse over the
    /// hash chains at 64 links. The tree writes 0.3 to 0.7 percent less on
    /// prose and takes about twice the wall on text at one thread. Off by
    /// default. It reaches level 4 only, and no lone member. `rarfast`
    /// sets it from `RARKIT_L4_TREE` (`1` on); no rar dialect switch does.
    pub level4_tree: bool,
    /// A rarkit-only option (spec G 3.8.1, spec H3 8.1, 1 Oct 2026): at
    /// level 5, every member that is not lone keeps the lazy parse over
    /// the TREE (cut 16, one hint slot, with the backward extension), of a
    /// solid set or not, as level 5 wrote it before it went by class. By
    /// default level 5 takes level 3's lazy parse over the hash chains
    /// where that is the faster wall: at 80 links on a member whose first
    /// megabyte reads under 7 far links a byte (code, logs, tables, most
    /// binaries), on a member under a megabyte, and on a member reading 7
    /// or more whose first megabyte holds 1,024 long matches or more
    /// (`level5_far_links_only`); a member reading 7 or more with fewer
    /// (a word list, a dictionary, generated text) keeps the tree. A solid set goes by
    /// its FIRST member, the same way: the chains at 72 links for every
    /// member of it, or the tree for every member of it. The tree writes
    /// up to 7 percent less on generated code and shuffled words and
    /// within half a percent either way on real members, for 1.2 to 4.2
    /// times the wall on the members the default gives the chains. Off by default. It reaches level 5 only, and no
    /// lone member; `level5_optimal` overrides it where both are on.
    /// `rarfast` sets it from `RARKIT_L5_TREE` (`1` on); no rar dialect
    /// switch does.
    pub level5_tree: bool,
    /// A rarkit-only option (spec H3 8.1, 2 Oct 2026): level 5's class
    /// goes by far links ALONE, as it did before it read a second
    /// statistic. By default a member whose first megabyte reads 7 far
    /// links a byte or more takes the chains all the same where a greedy
    /// parse of that megabyte takes 1,024 long matches (16 bytes or more)
    /// or more: a library, a font, a shader archive, prose; and keeps the
    /// tree where it takes fewer: a word list, a dictionary, a model's
    /// table. Timed on both architectures the members that moves were 1.5
    /// to 2.9 times faster in sum for 0.2 to 0.8 percent more bytes. On,
    /// every member reading 7 or more keeps the tree, and a solid set
    /// whose first member does. Off by default. It reaches level 5 only,
    /// and no lone member; `level5_tree` and `level5_optimal` override it.
    /// `rarfast` sets it from `RARKIT_L5_FAR_ONLY` (`1` on); no rar
    /// dialect switch does.
    pub level5_far_links_only: bool,
    /// A rarkit-only option (spec G 3.8.1, spec H3 8.1): at
    /// level 5, a member that is not lone keeps the OPTIMAL parse over the
    /// tree (cut 32, four hint slots), exactly as level 5 first wrote
    /// it, instead of the default lazy parse over the tree (cut
    /// 16, one hint slot). Off by default. It reaches level 5 only, and no
    /// lone member. `rarfast` sets it from `RARKIT_L5_OPTIMAL`; no rar
    /// dialect switch does.
    pub level5_optimal: bool,
    /// A rarkit-only option: level 1 parses as it did until 1 Oct
    /// 2026, with the lazy parse over four byte hash chains three links
    /// deep and the priced cut of its entropy blocks, instead of the fast
    /// parse that is level 1's default since (chains keyed on six bytes,
    /// one link, the four held distances first, a static price, entropy
    /// blocks cut every 64 KiB). Off by default. On, level 1 writes the
    /// bytes it wrote before then: 0.2 percent smaller on text, 2.7
    /// to 5.6 percent on code, source trees and binaries, for about twice
    /// the create wall at one thread (timed 30 Sep and 1 Oct 2026 on a Zen
    /// 4 and on an M5 Ultra). It reaches level 1 only (and the RAR 2.9
    /// method's level 1, which shares the ladder). `low_levels_extend`
    /// reaches level 1 only with this set: the fast parse has no backward
    /// extension. `rarfast` sets it from `RARKIT_L1_PRICED` (`1` on); no
    /// rar dialect switch does.
    pub level1_priced: bool,
    /// The level 1 default dictionary's rarkit-only option (spec G 3.8.1):
    /// level 1 in a non-solid RAR 5 archive, with no dictionary named,
    /// takes the 2 MiB default the other non-solid levels but 3 and
    /// the RAR 4 family take,
    /// instead of the 4 MiB that is its own default since 1 Oct 2026. Off
    /// by default. On, such a create writes the bytes it wrote before
    /// that date: about 4 percent more archive on large binaries, and a
    /// slower create at width there. It reaches nothing else: a named
    /// dictionary always wins, and levels 2 to 5, a stored archive, every
    /// solid form and the RAR 4 family never took the 4 MiB. The default is one figure on
    /// every machine, whatever its memory; a `MemoryPolicy` whose
    /// `max_dictionary` is under it reduces it, as it reduces any default.
    /// `rarfast` sets it from `RARKIT_L1_DICT_2M` (`1` on); no rar dialect
    /// switch does (`-md2m` says the same thing for one create).
    pub level1_dictionary_2mib: bool,
    /// The level 3 default dictionary's rarkit-only option (spec G 3.8.1):
    /// level 3 in a non-solid RAR 5 archive, with no dictionary named,
    /// takes the 2 MiB default non-solid levels 2, 4 and 5 and
    /// the RAR 4 family take, searched with no far-link budget, instead
    /// of the 16 MiB under a budget of 1 that is its own default since
    /// 9 Oct 2026. Off by default. On, such a create writes the bytes it
    /// wrote before that date: about 12 percent more archive on 4 GiB of
    /// binaries at the same wall. It reaches nothing else: a named
    /// dictionary always wins and is searched with no budget unless
    /// [`WriteOptions::far_link_budget`] names one. A memory ceiling the
    /// caller NAMED ([`MemoryPolicy::limit_named`], `rarfast`'s `-mm`)
    /// does what this option does, since a named budget is a promise
    /// the 16 MiB window's working memory is not yet charged to in
    /// full; an allowance nobody named never does. The default is one
    /// figure on every machine, whatever its memory; a `MemoryPolicy`
    /// whose `max_dictionary` is under it reduces it, as it reduces any
    /// default. `rarfast` sets it from `RARKIT_L3_DICT_2M` (`1` on); no
    /// rar dialect switch does (`-md2m` says the same thing for one
    /// create).
    pub level3_dictionary_2mib: bool,
    /// The solid default dictionary's rarkit-only option (spec G 3.8.1): a
    /// solid RAR 5 archive at levels 2 to 5, with no dictionary named,
    /// takes the 2 MiB default searched with no far-link budget, instead
    /// of the 32 MiB under a budget of 1 that is its own default since
    /// 10 Oct 2026 (level 1 keeps 2 MiB either way). Off by default. On, such a create
    /// writes the bytes it wrote before that date: more archive wherever
    /// a member repeats bytes that lie more than 2 MiB back in the set.
    /// It reaches nothing else: a named dictionary always wins and is
    /// searched with no budget unless [`WriteOptions::far_link_budget`]
    /// names one, and no non-solid archive and nothing of the RAR 4
    /// family ever took the 32 MiB. A memory ceiling the caller NAMED
    /// ([`MemoryPolicy::limit_named`], `rarfast`'s `-mm`) does what this
    /// option does, as it does for level 3's default; an allowance nobody
    /// named never does. The default is one figure on every machine,
    /// whatever its memory; a `MemoryPolicy` whose `max_dictionary` is
    /// under it reduces it, as it reduces any default. `rarfast` sets it
    /// from `RARKIT_SOLID_DICT_2M` (`1` on); no rar dialect switch does
    /// (`-md2m` says the same thing for one create).
    pub solid_dictionary_2mib: bool,
    /// The FAR-LINK BUDGET, a rarkit-only option of the hash chain levels:
    /// with `Some(n)`, one chain search follows at most `n` candidates
    /// that lie farther than 2 MiB back, where with `None`, the default,
    /// it follows every link to the dictionary's end alike. It is what
    /// lets a dictionary longer than 2 MiB be searched at about the cost
    /// of 2 MiB: a chain runs nearest first, so the search walks it as it
    /// does at a 2 MiB dictionary and then looks `n` links past that. It
    /// reaches every search over the chains at levels 2 to 5 (levels 2,
    /// 3 and 4, and at level 5 the members that take the chains by their
    /// class and a lone member's effort), solid or not, in both families;
    /// it does not reach level 1, whose searches follow one link or
    /// three, nor the tree where a level walks it (level 5's tree class
    /// and `level5_tree`, and level 4 under `level4_tree`). It
    /// names no dictionary: a caller pairs it with one longer than 2 MiB
    /// (`WriteMethod::Compressed { dictionary }`, the CLI's `-md`), and at
    /// 2 MiB or less it moves no byte, since no candidate is far. `Some(0)`
    /// searches no farther than 2 MiB back whatever is declared. The 2 MiB
    /// is a constant, so the bytes written never depend on the machine.
    /// `rarfast` sets it from `RARKIT_FAR_LINKS` (a count; unset, empty or
    /// not a number is `None`); no rar dialect switch does.
    ///
    /// TWO defaults are budgeted with `None` here: level 3 in a non-solid
    /// RAR 5 archive with no dictionary named searches its 16 MiB default
    /// under a budget of 1 (9 Oct 2026), and a solid RAR 5 archive at
    /// levels 2 to 5 its 32 MiB default under a budget of 1 (10 Oct
    /// 2026). `Some(n)` here replaces either figure, and
    /// [`WriteOptions::level3_dictionary_2mib`] and
    /// [`WriteOptions::solid_dictionary_2mib`] each take their default
    /// and its budget away together.
    pub far_link_budget: Option<u32>,
    /// The store rule's rarkit-only option (spec G 3.8.3): a non-solid
    /// member of 128 MiB and more is written STORED only when at least 15 of
    /// its 16 samples have nothing in them to compress, the rule as it was
    /// until 1 Oct 2026 and still is for a smaller member, instead of at
    /// least 12. Off by default: with four samples allowed to compress a
    /// big member whose opening packs is stored in the wall of a copy (timed on a
    /// 12.9 GB one at level 5, 3.9 s against 103.6 s for 0.12 percent more
    /// archive), where under this option it is compressed whole. It
    /// reaches every level, 1 to 5, and both families; a member under 128
    /// MiB is judged the same way either way, and a solid member and the
    /// reference layout are never sampled. `rarfast` sets it from
    /// `RARKIT_STORE_ONE_MISS` (`1` on); no rar dialect switch does.
    pub store_one_miss: bool,
    /// Stored encrypted members read AHEAD of the writer (SPEC-API 7.1),
    /// off by default. On, while one stored encrypted member is written
    /// the next ones' readers are read on helper threads, each member's
    /// one cipher chain running ahead into ciphertext held inside the
    /// working limit, so several members' chains run at once where one
    /// chain is otherwise the whole wall of such a set (a set of many
    /// stored members under a password: 17.8 s to 9.3 s for 24 of them
    /// on a rented Zen 4). The archive is byte for byte the same under
    /// the same entropy, and the first error reported is the same.
    ///
    /// **What the caller promises by setting it**: that its readers do not
    /// share an underlying source, and that nothing depends on a later
    /// member's reader being untouched until the earlier member is done.
    /// It reaches RAR 5 stored members of 4 MiB and more in one archive
    /// (`password`, with or without `encrypt_headers`) and in a volume set
    /// without `encrypt_headers`, on an output that can be patched; a
    /// recovery record, a solid archive, the RAR 4 family and one worker
    /// keep the walk without it. `rarfast` sets it
    /// (`RARKIT_ENCRYPTED_READ_AHEAD=0` there is the walk without it).
    pub encrypted_read_ahead: bool,
    /// The store rule's samples packed in full (spec G 3.8.3), a
    /// rarkit-only option that moves NO BYTE and no verdict. The rule
    /// reads one thing of a sample, how long it packs, and since 1 Oct
    /// 2026 that length is counted from the sample's parse without the
    /// sample being packed: the same length to the byte, for 2.6 to 2.8
    /// times fewer instructions a sample on real binaries and 6 to 10
    /// times fewer on video. Off by default. On, every sample is packed
    /// by the encoder and its output measured, as before that date: the
    /// same archive, slower, kept so that the two can be compared on any
    /// input. `rarfast` sets it from `RARKIT_STORE_PACKED_SAMPLES` (`1`
    /// on); no rar dialect switch does.
    pub store_packed_samples: bool,
    /// A comment to store in the archive, if any.
    pub comment: Option<Vec<u8>>,
    /// Whether to mark the archive against modification.
    pub lock: bool,
    /// This engine's own layout, or the reference producer's byte for
    /// byte.
    pub layout: Layout,
    /// Where salts and IVs come from (cipher padding is zero bytes).
    pub entropy: Entropy,
    /// What the write is allowed to hold at once.
    pub memory: MemoryPolicy,
    /// Refuse, before a byte of output, a write that cannot keep a
    /// ceiling the caller NAMED ([`MemoryPolicy::limit_named`]). Off by
    /// default, and off it changes nothing.
    ///
    /// Without it a named ceiling the write cannot keep is reported and
    /// never refused: the archive is finished and
    /// [`WriteReport::ceiling_exceeded_by`] carries the excess. With it,
    /// where what the run's encoder CERTAINLY holds for its largest
    /// member, at the narrowest plan the ceiling leaves it, is more than
    /// the ceiling, `finish` answers `LimitExceeded { resource:
    /// WorkingMemory }` with that figure as `needed` and the ceiling as
    /// `limit`, and writes nothing. The figure is the one the write
    /// already weighs before refusing under an environment's memory cap.
    /// It is not the run's peak and errs high: counted 23 Oct 2026 on
    /// macOS at `-m5` over 82 MiB of text, it was 406 MiB at `-md32m`
    /// where the run itself stated 363, and 244 at `-md16m` where it stated
    /// 236, so a ceiling between the two is refused though the run would
    /// have kept it. A run it admits that passes the ceiling all the same
    /// is still reported. A storing level has no encoder and is never
    /// refused here.
    ///
    /// It moves no byte of any archive it lets through.
    pub refuse_over_ceiling: bool,
    /// How wide the ENCODER may run, and nothing else (API 7.2 and
    /// 8.2).
    ///
    /// `None`, the default, means the width of the pool the caller owns.
    /// `Some(n)` asks for at most `n` tree walkers, and for at most `n`
    /// crews in the worker team that encodes a NON-SOLID compressed
    /// run's small members (those of one parse block, 256 KiB, or less)
    /// several at once and writes them in `add` order. For the walk it is
    /// a plain CPU figure: the parallel walk costs one small scratch per
    /// active walker and nothing that scales with the data. A crew is an
    /// encoder of its own, so the team is ALSO bounded by the memory
    /// policy below: at most [`MemoryPolicy::max_workers`] crews, and no
    /// more than a quarter of [`MemoryPolicy::working_limit`] at an
    /// allowance of 16 MiB a crew.
    ///
    /// It is a CEILING and never a demand, and it never RAISES anything.
    /// The width that runs is
    /// `min(workers or the pool's width, the engine's own ceiling, the
    /// pool's width)`, so asking for more walkers than the engine or the
    /// box can use buys none.
    ///
    /// **The memory ceiling is not this field.** That stays
    /// [`MemoryPolicy::max_workers`], which bounds the stages API 8.2's
    /// table assigns to it, the BLAKE2sp leaf team on this path among
    /// them. The two were one field at first and the one field was
    /// carrying two unrelated jobs: a memory derived figure (8 at the
    /// default budget) was capping an encoder that would have used every
    /// core it was given, which cost 56 percent of the create wall on 32
    /// cores and made every caller overwrite it by hand.
    ///
    /// **It cannot change a byte of output at any value** (promise 2.6).
    /// The tree's walk answers the serial walk's answers at any walker
    /// count, so the width is invisible in the archive. This crate's
    /// write tests hold that over every format, solid and not, over a
    /// volume set, and at every level of the ladder.
    pub workers: Option<usize>,
    /// The host this archive is being written ON, which is what a SERVICE
    /// block's host byte carries (spec G 3.3.4). It is the opposite of the
    /// rule for a member, whose own [`MemberSpec::host_os`] is kept
    /// unchanged: a member copied out of a Unix archive on a Windows box
    /// keeps its Unix mode. Both are fields so that a test can vary them,
    /// because no test on one platform can see the two being the same way
    /// round.
    pub host_os: HostOs,
}

impl Default for WriteOptions {
    /// RAR 5, stored, unencrypted, one archive. Note that this default
    /// is NOT usable with a RAR 4 format as it stands:
    /// `FilterPolicy::Detect` is RAR 5 only, so a RAR 4 target must set
    /// `filters` to `Off`.
    fn default() -> Self {
        WriteOptions {
            format: WriteFormat::Rar5,
            method: WriteMethod::Stored,
            password: None,
            encrypt_headers: false,
            solid: false,
            order: MemberOrder::default(),
            volume_size: None,
            volume_file_size: None,
            volume_naming: VolumeNaming::default(),
            recovery_percent: None,
            checksum: ChecksumKind::default(),
            filters: FilterPolicy::default(),
            optimal_parse: false,
            small_member_lazy: true,
            solid_store: true,
            level3_floor_lazy: false,
            level3_optimal: false,
            level3_deep: false,
            low_levels_extend: false,
            level4_optimal: false,
            level4_tree: false,
            level5_tree: false,
            level5_far_links_only: false,
            level5_optimal: false,
            level1_priced: false,
            level1_dictionary_2mib: false,
            level3_dictionary_2mib: false,
            solid_dictionary_2mib: false,
            far_link_budget: None,
            store_one_miss: false,
            encrypted_read_ahead: false,
            store_packed_samples: false,
            comment: None,
            lock: false,
            layout: Layout::default(),
            entropy: Entropy::default(),
            memory: MemoryPolicy::default(),
            refuse_over_ceiling: false,
            workers: None,
            host_os: if cfg!(windows) {
                HostOs::Windows
            } else {
                HostOs::Unix
            },
        }
    }
}

/// Which format to produce.
///
/// The older formats are absent by design and not by oversight: section 1
/// makes them read-only, so there is deliberately nothing here a caller
/// could name to ask for RAR 1.3, 1.4, 1.5 or 2.0.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum WriteFormat {
    /// RAR 5, the current format.
    #[default]
    Rar5,
    /// The RAR 4 family, at the target given.
    Rar4(Rar4Version),
}

/// Which RAR 4 family version to write.
///
/// These are the three a posting layout may ask for by name; they differ
/// in what a reader of that vintage will accept.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rar4Version {
    /// RAR 2.9, the oldest this crate writes.
    V29,
    /// RAR 3.0, which is what most RAR 4 family archives in the wild
    /// are.
    V30,
    /// RAR 4.0, the newest before RAR 5.
    V40,
}

/// Whether a member's bytes are compressed on the way in.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum WriteMethod {
    /// Written through as they are.
    #[default]
    Stored,
    /// Put through the compressor.
    Compressed {
        /// How much effort to spend, on the formats' own scale: 1 to 5.
        ///
        /// **What each level is for.** Every rung is a measured point on
        /// the speed against size curve, and none of them is there for
        /// symmetry: a level that another level beat on both axes was
        /// taken off the ladder when it was last retuned (19 Sep 2026).
        ///
        /// | level | what it is for | CPU | wall | size | peak RSS |
        /// |---|---|---|---|---|---|
        /// | 1 | as fast as compressing gets: posting at line rate | 0.12x level 3 | 0.22x | +13.9% | 107 MiB |
        /// | 2 | when the wall matters more than the last few per cent | 0.20x | 0.28x | +5.8% | 107 MiB |
        /// | 3 | the balance, and what to pick when unsure | 1.00x | 1.00x | - | 116 MiB |
        /// | 4 | for archives downloaded more often than written | 1.54x | 1.96x | -4.8% | 153 MiB |
        /// | 5 | the smallest this engine writes | 2.40x | 2.81x | -8.9% | 151 MiB |
        ///
        /// **The numbers, and where they come from.** CPU, wall and size
        /// are against level 3 on this crate's `source16` corpus - 16 MiB
        /// of a real source tree - at a 4 MiB dictionary and eighteen
        /// threads, on an 18 core aarch64 Mac (Darwin 27) under a shared
        /// load, measured by a bench script. They are
        /// a GUIDE and not a contract: the same ladder on 16 MiB of
        /// Mach-O executables puts level 5 at 2.45x level 3's CPU for
        /// 2.2% rather than 8.9%, and on already-compressed media all
        /// five levels land within 0.17% of each other, because there is
        /// nothing in those bytes to find.
        ///
        /// **Against reference `rar` 7.23 at the same level**, on the
        /// same corpora: level 1 is 0.1% to 18.8% smaller at about two
        /// thirds of its CPU, level 5 is 1.4% to 4.5% smaller on text and
        /// source and 2.9% larger on executables (the reference applies
        /// an executable filter there and this engine does not yet).
        /// Levels 2 and 3 are the ones to read carefully: they are up to
        /// 8.6% and 7.7% LARGER than the reference's own levels 2 and 3,
        /// and cheaper in the same proportion, because the reference's
        /// ladder is top heavy where this one is spread evenly over a
        /// wider range. A caller who wants the reference's level 2 size
        /// should ask for level 4 here.
        ///
        /// **Threads and memory are the caller's, separately, and the
        /// level sets neither.** Threads come from the rayon pool the
        /// call runs in, and the tree levels' walk is capped again by
        /// [`WriteOptions::workers`], the encoder's own width dial; the
        /// `rarkit` command line spells both `-mt`. The bytes do not move with either (API
        /// promise 6), only the wall. What each level does with more of them, measured on a
        /// 32 MiB member: levels 1 to 3 reach about 5.5x to 7.9x on
        /// eighteen cores, levels 4 and 5 about 6x, and a many small
        /// files SOLID set barely scales at all below level 4, because
        /// there a member is one parse block and the wave has nothing to
        /// widen over. Memory is `dictionary`, below.
        ///
        /// Level 0 is not spelled here: it is [`WriteMethod::Stored`].
        level: u8,
        /// The window to compress with. `None` takes the default: 2 MiB,
        /// or 4 MiB at level 1 in a non-solid RAR 5 archive (unless
        /// [`WriteOptions::level1_dictionary_2mib`] keeps 2 MiB there),
        /// or 16 MiB under a far-link budget of 1 at level 3 in a non-solid
        /// RAR 5 archive (unless [`WriteOptions::level3_dictionary_2mib`]
        /// or a memory ceiling the caller named,
        /// [`MemoryPolicy::limit_named`], keeps 2 MiB there),
        /// or 32 MiB under a far-link budget of 1 in a solid RAR 5 archive
        /// at levels 2 to 5 (unless
        /// [`WriteOptions::solid_dictionary_2mib`] or a named memory
        /// ceiling keeps 2 MiB there),
        /// reduced to [`MemoryPolicy::max_dictionary`] rather than
        /// refused when the policy is smaller. The default never depends
        /// on the machine's memory.
        ///
        /// **Either way it is FITTED to the input before anything is
        /// written**: halved while it is above 128 KiB and above twice
        /// the largest member (the whole set's size in a solid archive),
        /// which gives the smallest power of two above what the members
        /// can reach, so a small archive declares, allocates and asks its
        /// extractor for a small window. A 32 MiB default searched as
        /// the 2 MiB one is, every link alike, was measured on 27 Sep
        /// 2026 and not taken (smaller solid archives at a slower create);
        /// the solid default of 10 Oct 2026 is that window under the
        /// budget. Elsewhere, ask for a longer one by name where the
        /// bytes matter more.
        ///
        /// It is the dial that costs MEMORY rather than time. Peak RSS is
        /// roughly the dictionary's own bytes plus ten times it for the
        /// level 5 finder (four times it at levels 1 to 4), plus the
        /// blocks in flight; measured on 16 MiB of source at 18 threads,
        /// 128 KiB to 4 MiB moves peak RSS from 93 to 116 MiB at level 3
        /// and from 99 to 150 MiB at level 5. What it buys depends
        /// entirely on whether the content repeats at that range.
        dictionary: Option<u64>,
    },
}

/// How the files of a RAR 4 family set are named.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum VolumeNaming {
    /// The original scheme: `.rar`, then `.r00`, `.r01` and on.
    Classic,
    /// The numbered scheme: `.part1.rar`, `.part2.rar` and on.
    #[default]
    Numbered,
}

/// Which check value to record over each member's content.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ChecksumKind {
    /// CRC32, which every family can store.
    #[default]
    Crc32,
    /// BLAKE2sp, which only RAR 5 can store.
    Blake2sp,
}

/// Whether the compressor looks for content a standard filter improves.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FilterPolicy {
    /// Never apply one.
    Off,
    /// Sample the content and apply one where it pays. RAR 5 only:
    /// a RAR 4 target asking for this is refused by
    /// [`Writer::new`].
    #[default]
    Detect,
}

/// How closely the output follows the reference producer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Layout {
    /// This engine's own arrangement, which is free to differ.
    #[default]
    Default,
    /// Byte for byte what the reference `rar` 7.x writes, given a RAR 5
    /// stored archive with the same members, times, options and salt.
    /// Spec G says which options this layout can carry; the rest are
    /// refused by [`Writer::new`].
    Reference {
        /// Whether to include the quick-open record, which the reference
        /// writes by default.
        quick_open: bool,
    },
}

/// Where salts and initialisation vectors come from.
///
/// Only these. Cipher padding is not drawn from here because it is not
/// random at all: every format pads with zero bytes, as the reference
/// writer does. Whichever variant is chosen, a writer draws the same
/// NUMBER of bytes in the same ORDER for the same options and members,
/// which is what makes [`Entropy::Seeded`] reproducible rather than
/// merely repeatable.
#[derive(Default)]
pub enum Entropy {
    /// Whatever the operating system provides, which is what real use
    /// wants.
    #[default]
    Os,
    /// A fixed seed, which makes the whole write reproducible: identical
    /// inputs give identical bytes.
    Seeded([u8; 32]),
    /// The caller's own generator.
    Source(Box<dyn EntropySource>),
}

impl std::fmt::Debug for Entropy {
    /// Prints which variant this is and nothing more. A seed is key
    /// material and never reaches a formatter.
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(match self {
            Entropy::Os => "Entropy::Os",
            // The seed itself is key material: named, never shown.
            Entropy::Seeded(_) => "Entropy::Seeded(..)",
            Entropy::Source(_) => "Entropy::Source(..)",
        })
    }
}

/// A source of random bytes the caller supplies in place of the
/// operating system's.
pub trait EntropySource: Send {
    /// Fill the whole of `buf`. A partial fill is not an option; a
    /// generator that cannot manage it returns an error.
    fn fill(&mut self, buf: &mut [u8]) -> Result<()>;
}

/// An account of a finished write.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WriteReport {
    /// How many files were produced; 1 for a single archive.
    pub volumes: u32,
    /// How many bytes were written, over all of them.
    pub bytes: u64,
    /// The high-water mark for bytes of a volume held in memory because
    /// a size field needed patching and the output could not be seeked.
    /// Zero whenever the output could be patched in place.
    pub held_volume_bytes: u64,
    /// The high-water mark for THIS call's working memory, which is not
    /// what [`crate::memory::peak`] reports: that one counts the process.
    ///
    /// **A high-water mark of bytes IN USE, carried across the run**
    /// (decided 21 Sep 2026). Two things follow from that
    /// wording and both are observable:
    ///
    /// - It is the largest simultaneous total the run's buffers ever
    ///   reached, not what they hold when the run ends. Several of them
    ///   are emptied before then, so a figure read off at the end would
    ///   report a run that peaked at hundreds of megabytes as holding
    ///   nearly nothing.
    /// - It counts bytes TOUCHED and never a buffer's capacity. A
    ///   reserve the run never writes into costs address space and not
    ///   memory - a page that is never written is never resident - so a
    ///   writer that reserves a bound rather than growing into it
    ///   reports the same figure as one that grew, while retaining far
    ///   less. That is the trade taken, and
    ///   `Run::reserve_packed` is what takes it.
    pub peak_working_memory: u64,
    /// By how many bytes [`WriteReport::peak_working_memory`] passed the
    /// memory ceiling the caller set, or `None` where it did not or where
    /// the caller set none.
    ///
    /// **A ceiling that could not be kept is reported and never
    /// refused** (spec G 3.5, "Ceiling would be exceeded, output cannot
    /// patch", decided 20 Sep 2026). The writer holds a member whole
    /// where it must - the output cannot be written back over, so the
    /// member's packed size field cannot be laid down before its value is
    /// known - finishes a valid archive, answers `Ok`, and says here by
    /// how much it went over. Nothing about it is an error, and a caller
    /// that wants one tests this field and raises its own.
    ///
    /// A `working_limit` the caller did not name
    /// ([`MemoryPolicy::limit_named`](crate::MemoryPolicy::limit_named)
    /// false, as [`MemoryPolicy::default`](crate::MemoryPolicy::default)
    /// leaves it) is not a ceiling the caller chose, so this is `None` for
    /// such a caller whatever the write held.
    pub ceiling_exceeded_by: Option<u64>,
}
