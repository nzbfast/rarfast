//! What a command selects: its mode, its masks and the members they keep,
//! and what a member's failure is recorded as.

use super::mask::{selects, Screen};
use super::*;

/// What the command does with each member's bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// `t`: decode and check, write nothing.
    Test,
    /// `x` (`flat` false) and `e` (`flat` true).
    Extract {
        /// Whether archived paths are discarded.
        flat: bool,
    },
    /// `p`: write member bytes to standard output.
    Print,
}

impl Mode {
    pub(super) fn verb(self) -> &'static str {
        match self {
            Self::Test => "Testing",
            _ => "Extracting",
        }
    }

    pub(super) fn banner(self) -> &'static str {
        match self {
            Self::Test => "Testing archive",
            _ => "Extracting from",
        }
    }
}

/// Which members a command line selected: the positional masks, `-n`,
/// `-x`, the four time switches and `-sl`.
pub(crate) struct Selection {
    pub(super) masks: Vec<String>,
    pub(super) include: Vec<Screen>,
    pub(super) exclude: Vec<Screen>,
    pub(super) time_filters: Vec<TimeFilter>,
    pub(super) size_less: Option<u64>,
    pub(super) size_more: Option<u64>,
    pub(super) skip_directories: bool,
    pub(super) attribute_filter: Option<(u64, bool)>,
    /// Whether an older version of a file is kept: under `-ver`, and in
    /// every listing.
    pub(super) versions: bool,
    /// `-ver<n>`: the one version number processed, and no file without
    /// one.
    pub(super) only_version: Option<u32>,
}

impl Selection {
    /// Builds the selection from the parsed command line.
    pub(crate) fn new(masks: &[String], opts: &Options) -> Self {
        Self {
            masks: masks.to_vec(),
            include: opts.include.iter().map(|mask| Screen::new(mask)).collect(),
            exclude: opts.exclude.iter().map(|mask| Screen::new(mask)).collect(),
            time_filters: opts.time_filters.clone(),
            size_less: opts.size_less,
            size_more: opts.size_more,
            skip_directories: opts.skip_directories,
            attribute_filter: opts.attribute_filter,
            versions: opts.versions,
            only_version: opts.only_version,
        }
    }

    /// The same selection with the older versions of files kept: a
    /// listing shows them whether or not `-ver` was given.
    pub(crate) fn with_versions(mut self) -> Self {
        self.versions = true;
        self.only_version = None;
        self
    }

    /// Whether an argument is exactly this member's `name;n`: the
    /// reference then processes that version whatever `-ver` says, and
    /// under that name.
    fn names_version(&self, member: &Member) -> bool {
        member.version.is_some() && {
            let name = member.compared_name();
            self.masks.iter().any(|mask| *mask == *name)
        }
    }

    /// Whether `-ver<n>` picked this member by its number: it is then
    /// processed under its name without the `;n`.
    pub(super) fn picks_by_number(&self, member: &Member) -> bool {
        self.only_version.is_some_and(|wanted| {
            super::super::list::version_number(member) == Some(u64::from(wanted))
        }) && !self.names_version(member)
    }

    /// The same selection with every directory left out.
    pub(crate) fn without_directories(mut self) -> Self {
        self.skip_directories = true;
        self
    }

    /// Whether a member survives every filter on the command line.
    pub(crate) fn keeps(&self, member: &Member) -> bool {
        // The versions of files (sweep 2 item 34; reference unrar 7.23,
        // `tests/file_version_numbers.rs`). An argument that is exactly
        // `name;n` takes that version; else `-ver<n>` takes the files
        // numbered n and no file without a number, a directory still; else
        // a version is passed over unless plain `-ver` was given.
        if !self.names_version(member) {
            match (self.only_version, member.version) {
                (Some(_), _) if member.is_dir => {}
                (Some(_), _) if !self.picks_by_number(member) => return false,
                (None, Some(_)) if !self.versions => return false,
                _ => {}
            }
        }
        // The reference's three rules ([`super::mask`]): an argument is
        // the exact path or a directory and all beneath it, and `-n` and
        // `-x` read a mask alike.
        // A mask is matched with the name the archive holds, not with
        // the rendering a line prints.
        let name = member.compared_name();
        let name: &str = &name;
        if !self.masks.is_empty() && !self.masks.iter().any(|m| selects(m, name)) {
            return false;
        }
        let covers = |screen: &Screen| screen.covers(name, member.is_dir);
        if !self.include.is_empty() && !self.include.iter().any(covers) {
            return false;
        }
        if self.exclude.iter().any(covers) {
            return false;
        }
        if let Some(limit) = self.size_less {
            // A directory is not size filtered, as under `-sm` below:
            // `-sl0` lists the directories alone (rar and unrar 7.23,
            // measured 4 Oct 2026).
            if !member.is_dir && member.size >= limit {
                return false;
            }
        }
        if let Some((mask, include)) = self.attribute_filter {
            // Only a member whose host keeps the DOS word (DOS, OS/2,
            // Windows, Mac OS, the RAR 1.3 container) is tested against
            // these masks; a Unix or BeOS member's `attr` is mode bits,
            // and a host the listing prints as `?` has no reading at all.
            let carries = member.host.attribute_form() == super::AttributeForm::Dos
                && member.attr & mask != 0;
            if carries != include {
                return false;
            }
        }
        if self.skip_directories && member.is_dir {
            return false;
        }
        if let Some(limit) = self.size_more {
            // Measured against the reference: a directory is not size
            // filtered, so `-sm` over an archive of small files leaves
            // the directory rows standing and nothing else.
            if !member.is_dir && member.size <= limit {
                return false;
            }
        }
        for filter in &self.time_filters {
            // The modification time: the `m` and `o` suffixes and none.
            // A `c` or `a` filter never reaches here; the dispatch refuses
            // it by name ([`TimeField`]).
            let Some(mtime) = member.mtime else { continue };
            // A stored wall clock is compared as local time, as it is
            // set on disk (sweep 2 item 38).
            let mtime = if member.wall_clock {
                super::time::wall_to_instant(mtime).unwrap_or(mtime)
            } else {
                mtime
            };
            let keep = if filter.newer {
                mtime >= filter.at
            } else {
                mtime <= filter.at
            };
            if !keep {
                return false;
            }
        }
        true
    }
}

/// One logical member and the volumes its data lives in.
pub(super) struct Planned {
    /// Index of the member in its first volume's member list.
    pub(super) member: Member,
    /// `(volume index, offset past this fragment's data in that volume)`.
    pub(super) fragments: Fragments,
    /// Whether the LAST fragment we have still says the data continues.
    /// True means the volume that would carry the rest is not in hand.
    pub(super) split_after_last: bool,
}

/// A member's fragments: the one every member has, held inline, and a
/// vector only once a continuation joins it. Reads as a slice.
#[derive(Clone)]
pub(super) enum Fragments {
    One([(usize, u64); 1]),
    Many(Vec<(usize, u64)>),
}

impl Fragments {
    pub(super) fn push(&mut self, fragment: (usize, u64)) {
        match self {
            Self::One([first]) => *self = Self::Many(vec![*first, fragment]),
            Self::Many(all) => all.push(fragment),
        }
    }
}

impl std::ops::Deref for Fragments {
    type Target = [(usize, u64)];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::One(one) => one,
            Self::Many(all) => all,
        }
    }
}

/// Why one member did not come out right.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Failure {
    /// The data decoded but did not match its stored checksum.
    Checksum,
    /// An encrypted member with no password check record (the RAR 1.3 to
    /// 4.x family, or a RAR 5 record without one) whose bytes did not
    /// come out right, by checksum or in its decoder: nothing tells a
    /// wrong password from damage, and the reference says so.
    EncryptedChecksum,
    /// The member is encrypted and the password did not open it.
    Password,
    /// A volume this member continues into was not there.
    LostVolume,
    /// The archive itself stops before its END record. Not a member's
    /// failure at all, which is why it carries no member index.
    Truncated,
    /// A header the walk cannot step over (spec F 4.6): the reference's
    /// `Corrupt header is found`, exit 3. Like a cut, a property of the
    /// archive and not of a member.
    CorruptHeader,
    /// The entry's name could not be joined onto the destination without
    /// leaving it, so nothing was written. See `member_target`.
    LeavesDestination,
    /// The output file could not be created, for instance because an
    /// earlier entry left a FILE where its parent directory belongs.
    Create,
    /// An engine error with no member to charge it to.
    Unattributed,
    /// The source could not be read.
    ReadFailed,
    /// The member's output could not be WRITTEN: the caller's own writer
    /// failed partway (a full disk, a file size limit). The reference's
    /// `Write error in the file` and its exit class 5.
    WriteFailed,
    /// The engine REFUSED the member rather than failing on its bytes: a
    /// codec, a filter or a container feature it does not implement. Not a
    /// checksum failure, and complaining about a checksum would send a
    /// caller looking for a damaged file that is not damaged. The walk's
    /// own error line carries the reason.
    Refused,
    /// A symbolic link skipped as unsafe (spec F 3.8.2): the reference's
    /// warning, exit 1.
    UnsafeLink,
    /// A file copy whose source this run did not write (spec F 3.8.5): the
    /// reference's `Cannot open`, exit 6.
    CopySource,
    /// The walk reached a volume of the set that is there and is no RAR
    /// archive at all: the reference's `Bad archive`, `Program aborted`,
    /// exit 13. A property of the set, not of a member.
    BadVolume,
}

/// The members one command line selected, in archive order, with a set
/// beside them for membership tests.
///
/// The order is the point of the vector and cannot be given up: the walk
/// visits members in it, and the passes that settle a member before the
/// walk starts (a wrong password, a missing continuation volume) emit
/// their complaints in archive order because they iterate it. But
/// [`Run::begin_member`] asks only "is this index in there", once per
/// member, and on a vector that is a linear scan: at 20,000 members it is
/// about 200 million comparisons on the walking thread, and it is
/// invisible on a corpus of a few large members, which is why it stood.
///
/// So both, and the set is DERIVED from the vector in [`Selected::new`],
/// which is the only way either is built. They cannot disagree because
/// there is nowhere for them to disagree.
pub(super) struct Selected {
    /// Archive order. Iterate this.
    pub(super) order: Vec<usize>,
    /// The same indices. Probe this.
    pub(super) lookup: IndexSet,
}

/// A set of member indices, as one bit per plan position.
///
/// Every member of a walk is probed against the selection and against
/// the finished members, and a finished member is inserted: three hash
/// operations a member through a `HashSet<usize>`, 71,004 of them in one
/// `t` of a 20,000-member archive, where a bit answers each. The bits are
/// bounded by the plan the indices come from ([`IndexSet::with_bound`]);
/// an index past the bound, which nothing here produces, still goes in
/// and comes back out, through a hash set beside the bits, so the set
/// answers exactly as a `HashSet` did for every index.
#[derive(Default)]
pub(super) struct IndexSet {
    pub(super) bits: Vec<u64>,
    pub(super) beyond: Indices,
}

impl IndexSet {
    /// Room for the indices `0..bound` as bits: `bound / 8` bytes.
    pub(super) fn with_bound(bound: usize) -> Self {
        Self {
            bits: vec![0; bound.div_ceil(64)],
            beyond: Indices::default(),
        }
    }

    pub(super) fn insert(&mut self, index: usize) {
        match self.bits.get_mut(index / 64) {
            Some(word) => *word |= 1 << (index % 64),
            None => {
                self.beyond.insert(index);
            }
        }
    }

    pub(super) fn contains(&self, index: usize) -> bool {
        match self.bits.get(index / 64) {
            Some(word) => word & (1 << (index % 64)) != 0,
            None => self.beyond.contains(&index),
        }
    }
}

impl Selected {
    /// The only constructor, so that `lookup` is always `order`'s
    /// contents and never a second opinion about them.
    pub(super) fn new(order: Vec<usize>) -> Self {
        let mut lookup = IndexSet::with_bound(order.iter().max().map_or(0, |last| last + 1));
        for &index in &order {
            lookup.insert(index);
        }
        Self { order, lookup }
    }

    /// Whether this member was selected. O(1), and the reason the set
    /// exists.
    pub(super) fn contains(&self, index: usize) -> bool {
        self.lookup.contains(index)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    pub(super) fn iter(&self) -> std::slice::Iter<'_, usize> {
        self.order.iter()
    }

    /// The count of selected members, for a loop that must index the
    /// vector rather than borrow it; see the three call sites.
    pub(super) fn len(&self) -> usize {
        self.order.len()
    }

    /// The member at one position in archive order.
    pub(super) fn at(&self, position: usize) -> usize {
        self.order[position]
    }
}

/// Whether a member has no name as this command will use it: the
/// reference's `t`, `x`, `e` and `p` then pass it over whole, with no
/// line, no count, none of its bytes printed and nothing created, as if
/// no argument had selected it, and a run left with nothing says `No
/// files to extract`, exit 10 (SPEC-CLI 2.1 M18; rar and unrar 7.23,
/// aarch64 macOS, 10 Oct 2026; `tests/empty_named_member.rs`).
///
/// No name is: nothing to show AND nothing to write. That is a name of
/// zero bytes, one that starts with a NUL, and one whose first byte this
/// host cannot read (the genuine `listing-names/r4-two.rar` on macOS).
/// A name that shows as something and writes as nothing is not measured
/// and is left to the walk, which creates nothing for it.
///
/// `e` uses a FILE's name without its path, so a file `d/` has no name
/// there either, and is passed over the same way when the command names
/// no destination. With one (`dest` not empty) it is kept: the walk then
/// says the reference's complaint ([`Run::refuse_destination_itself`]).
pub(super) fn nameless(member: &Member, mode: Mode, dest: &str) -> bool {
    let whole = |name: &[u8]| name.is_empty();
    if whole(member.disk_name()) && whole(member.name.as_bytes()) {
        return true;
    }
    let last = |name: &[u8]| {
        name.rsplit(|&b| b == b'/' || (cfg!(windows) && b == b'\\'))
            .next()
            .is_none_or(<[u8]>::is_empty)
    };
    mode == Mode::Extract { flat: true }
        && !member.is_dir
        && dest.is_empty()
        && last(member.disk_name())
        && last(member.name.as_bytes())
}
