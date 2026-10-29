//! The rotational source rule: which shapes of set are read by few readers
//! from a disk with one head.

use super::*;

/// The threads `t` and `p` of a plain STORED set run at when the archive is
/// COLD on a rotational device and no `-mt` is stated: ONE, with the
/// sequential advice (`Run::walk`), which is a stated `-mt1`: one reader,
/// in order, as far ahead as the kernel will go.
///
/// **Why one.** A hard disk reads fastest in order, and the default width
/// does not read in order: a big stored member's `t` is the engine's wide
/// read, a reader a thread, and several stored members in ONE archive are
/// read at once, streams a gigabyte apart on the same spindles. On an
/// array of twelve hard disks (a Synology, RAID 6, btrfs over LVM over md,
/// a 12-core Xeon D), cold `t`, this rule in one knob binary with a pair
/// of the same arm, K=7, INDICATIVE: a stored set of many members in one
/// archive 6.04 and 5.94 s against 9.78 s at the default width (1.62x to
/// 1.65x, every rep ahead); the many-member set over 1 GiB volumes 9.73 and
/// 9.44 s against 11.03 s; a 12.9 GB member 7.14 and 7.60 s against 8.03 s; 3.4 to 5.3 CPU s against
/// 3.8 to 8.1; 1.12x to 1.26x over unrar 7.23 on all three, level with a
/// stated `-mt1` (1 Oct 2026).
///
/// **Why not four.** Four shipped first and was withdrawn
/// within the hour: it won the many-member set over volumes, where a split
/// member stays in one window, and LOST that set in one archive, 0.85x to
/// 0.88x, where four threads are four far-apart streams.
///
/// **Cold only.** Once the big member is in the page cache the width wins, 0.60
/// s at twelve readers against 2.87 s at one, so the rule asks the page
/// cache first (`residency`: sixty-four pages sampled across the first
/// volume) and a file at least half in memory, or one the kernel will not
/// answer for, keeps the default width.
///
/// **Where it applies, and only there.** The source device is rotational by
/// sysfs's own word (`device_class`: Linux; an unknown device, a cache
/// drive in front of hard disks, a network share and every other system
/// keep the default width). The archive is RAR 5, or of the RAR 1.5 to
/// 4.x family ([`Shapes::RAR4`], on since its own rows: below), solid or
/// not ([`Shapes::SOLID`], on since its own row). EVERY
/// member to be read is stored, unencrypted and under a CRC32: the one thread then carries the read
/// and that hash and nothing else, where a cipher or a BLAKE2sp hash on it
/// is unmeasured, and a compressed member wants the width for its decode,
/// unless the set's compressed members are small beside the stored ones
/// ([`Shapes::MIXED`], on within [`MIXED_COMPRESSED_CAP`]).
/// Some member is large enough for the wide read at all (16 MiB). `x` is
/// not touched. A stated `-mt` is the user's.
///
/// A count-only knob (feature `read-depth-knob`, never shipped):
/// `RARFAST_ROTATIONAL_READERS=N` sets the threads (0 switches the rule
/// off) and `RARFAST_ROTATIONAL_ADVICE=0` withholds the advice at one;
/// `RARFAST_ROTATIONAL` states the device class (`device_class::of`) and
/// `RARFAST_RESIDENT` the page cache's answer (`residency::of`);
/// `RARFAST_ROTATIONAL_SHAPES` names the shapes beyond the plain set that
/// are on ([`Shapes`]; [`ROTATIONAL_SHAPES`] is what a shipped build takes).
pub(super) const ROTATIONAL_READERS: Option<u64> = Some(1);

/// The smallest member the engine's wide read takes (`read::wide::FLOOR`):
/// below it a stored member is read in order whatever the width.
pub(super) const WIDE_READ_FLOOR: u64 = 16 << 20;

/// The shapes of a stored set beyond the plain one that the rotational
/// rule may take, each switched on by its own timed row on hard disks and
/// by nothing else (a shape without a row keeps the default width).
///
/// The plain set needs none of them: RAR 5, not solid, every member
/// stored, unencrypted and under a CRC32. A set that shows exactly ONE of
/// these is narrowed where that one is switched on; a set that shows two
/// (a solid RAR 4 set, an encrypted one hashed with BLAKE2sp) is never
/// narrowed, because no row was sat on a combination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Shapes(pub(super) u8);

impl Shapes {
    /// The plain set, and with it no shape switched on.
    pub(super) const NONE: Shapes = Shapes(0);
    /// Members of the RAR 1.5 to 4.x family (a RAR 4 volume set is the
    /// commonest old release shape). The engine reads them as it reads
    /// RAR 5's: the wide read inside a big member, several members at once.
    pub(super) const RAR4: Shapes = Shapes(1);
    /// A solid archive. Its members are read one after another already;
    /// what one reader changes is the wide read inside each big member.
    pub(super) const SOLID: Shapes = Shapes(1 << 1);
    /// An encrypted member (`-p` or `-hp`): the one thread then carries
    /// the cipher as well as the read and the CRC32.
    pub(super) const CIPHER: Shapes = Shapes(1 << 2);
    /// A member with no CRC32, which in RAR 5 is a BLAKE2sp member: the
    /// one thread then carries that hash as well as the read.
    pub(super) const BLAKE2SP: Shapes = Shapes(1 << 3);
    /// Compressed members beside the stored ones, [`MIXED_COMPRESSED_CAP`]
    /// bytes of them at most: a big member stored beside a compressed text file.
    /// The whole run is narrowed, their decode included, which is why the
    /// cap is there.
    pub(super) const MIXED: Shapes = Shapes(1 << 4);

    pub(super) const fn with(self, other: Shapes) -> Shapes {
        Shapes(self.0 | other.0)
    }

    pub(super) const fn holds(self, other: Shapes) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether a set that shows `self` is one the rule takes with `on`
    /// switched on: the plain set always, and a set of exactly one shape
    /// where that shape is on.
    pub(super) const fn taken(self, on: Shapes) -> bool {
        self.0 == 0 || (self.0.count_ones() == 1 && on.holds(self))
    }
}

/// The shapes the shipped rule takes beyond the plain set. Each is
/// switched on here by its own row on hard disks
/// (1 Oct 2026), and until then only a count
/// build's knob (`RARFAST_ROTATIONAL_SHAPES`) reaches it.
///
/// **`RAR4` is on.** The same array as the rule's own rows (a Synology,
/// RAID 6 of twelve hard disks), cold `t`, K=5, INDICATIVE, a stated
/// `-mt1` against the default width: a big member over 65 volumes of 200 MB,
/// the old release shape, 8.34 s against 22.55 s (2.6x to 2.9x, every
/// rep far outside; the width was 0.43x of unrar 7.23 there and one
/// reader is 1.16x over it); a set of eight over 1 GiB volumes 11.61 s
/// against 13.94 s; the big member over 4 GiB volumes 14.26 s against 17.54 s;
/// a many-member set in one archive 5.91 s against 7.90 s, every rep outside;
/// the big member in one archive 7.24 s against 8.36 s. No row is slower.
///
/// **`MIXED` is on**, within [`MIXED_COMPRESSED_CAP`]. The same array,
/// cold `t`, K=3, a stored 12.9 GB member beside compressed text in one
/// archive, the release an `-m3` of a directory makes: beside 200 KiB of
/// text 7.38 s against 10.21 s, beside 8 MiB 8.75 s against 11.14 s,
/// beside 64 MiB 9.55 s against 12.63 s (1.15x to 1.38x). The default
/// width LOST to unrar 7.23 on the first two (0.77x to 0.96x); one reader
/// is 1.07x to 1.17x over it. Beside a 4 GiB compressed member one reader
/// does not win (level on the big member, behind on a many-member set), and
/// such a set is never taken.
///
/// **`SOLID` is on.** The same array, cold `t`, K=5, a solid stored set
/// of eight members (8.76 GB; `rarfast a -m0 -s` writes one, reference
/// rar 7.23 sets no solid flag on a stored set): 9.54 s on one reader
/// against 12.38 to 13.06 s at the width (1.30x to 1.37x, every rep
/// ahead). The width read the eight members apart although the set is
/// solid, and LOST to unrar 7.23 (11.81 s, 0.90x to 0.95x); one reader is
/// 1.24x over it.
pub(super) const ROTATIONAL_SHAPES: Shapes = Shapes::RAR4.with(Shapes::MIXED).with(Shapes::SOLID);

/// The most unpacked bytes of COMPRESSED members a set may hold and still
/// be narrowed as [`Shapes::MIXED`]: 64 MiB, summed over every selected
/// member that is not stored, from the archive's own headers and nothing
/// of the box. Narrowing the run takes the width from their decode too, so
/// the shape is the one where that decode is small beside the stored read:
/// a release whose big member is stored and whose text files are compressed. A
/// set with more compressed bytes than this keeps the default width
/// whatever is on.
///
/// **Why 64 MiB.** It is the largest point with a winning row on hard
/// disks (64 MiB of text beside the big member, every one-reader rep ahead of
/// every rep at the width), and the next point sat, a 4 GiB compressed
/// member, does not win. Nothing between the two has a row, so nothing
/// above 64 MiB is taken.
pub(super) const MIXED_COMPRESSED_CAP: u64 = 64 << 20;

/// What a `Shapes` knob value names: the shapes in a list split by commas,
/// `all`, or `none`; `None` where a word is not one of them.
#[cfg(any(test, feature = "read-depth-knob"))]
pub(super) fn shapes_of(text: &str) -> Option<Shapes> {
    let mut shapes = Shapes::NONE;
    for word in text.split(',').map(str::trim).filter(|w| !w.is_empty()) {
        shapes = shapes.with(match word {
            "none" => Shapes::NONE,
            "all" => Shapes(0b1_1111),
            "rar4" => Shapes::RAR4,
            "solid" => Shapes::SOLID,
            "cipher" => Shapes::CIPHER,
            "blake2sp" => Shapes::BLAKE2SP,
            "mixed" => Shapes::MIXED,
            _ => return None,
        });
    }
    Some(shapes)
}

/// [`ROTATIONAL_SHAPES`], or the knob's list (count only, feature
/// `read-depth-knob`): `RARFAST_ROTATIONAL_SHAPES` names the shapes that
/// are on, replacing the shipped ones, as `shapes_of` reads it; a value
/// it cannot read is the shipped rule.
pub(super) fn rotational_shapes() -> Shapes {
    #[cfg(feature = "read-depth-knob")]
    if let Some(shapes) = std::env::var("RARFAST_ROTATIONAL_SHAPES")
        .ok()
        .and_then(|v| shapes_of(&v))
    {
        return shapes;
    }
    ROTATIONAL_SHAPES
}

/// The shapes the members a command will read show, or `None` where no
/// form of the rotational rule takes them: a command other than `t` or
/// `p`; a member of the RAR 1.3 container (its checksum is a serial byte
/// loop that was never read wide); more than [`MIXED_COMPRESSED_CAP`]
/// bytes of compressed members; or no STORED member large enough for the
/// wide read ([`WIDE_READ_FLOOR`]). Directories are skipped.
pub(super) fn rotational_shapes_of<'a>(
    mode: Mode,
    solid: bool,
    members: impl Iterator<Item = &'a Member>,
) -> Option<Shapes> {
    if !matches!(mode, Mode::Test | Mode::Print) {
        return None;
    }
    let mut shapes = if solid { Shapes::SOLID } else { Shapes::NONE };
    let mut large = false;
    let mut compressed = 0u64;
    for member in members {
        if member.is_dir {
            continue;
        }
        // RAR 5 keeps a compression version of 0 or 1; the RAR 1.3
        // container stores the constant 2; the RAR 1.5 to 4.x family
        // declares 13 or more (`Member::algorithm_version`).
        match member.algorithm_version {
            0 | 1 => {}
            2 => return None,
            _ => shapes = shapes.with(Shapes::RAR4),
        }
        if member.encrypted {
            shapes = shapes.with(Shapes::CIPHER);
        }
        if member.method != 0 {
            compressed = compressed.saturating_add(member.size);
            if compressed > MIXED_COMPRESSED_CAP {
                return None;
            }
            shapes = shapes.with(Shapes::MIXED);
            continue;
        }
        if member.crc32.is_none() {
            shapes = shapes.with(Shapes::BLAKE2SP);
        }
        large |= member.size >= WIDE_READ_FLOOR;
    }
    large.then_some(shapes)
}

/// Whether the members a command will read are a set the rotational rule
/// may narrow with the shapes `on` switched on: `t` or `p`, some stored
/// member large enough for the wide read ([`WIDE_READ_FLOOR`]), and either
/// the plain set (not a solid archive; every member that is not a
/// directory a RAR 5 member, stored, unencrypted and under a CRC32, so
/// that one thread carries nothing but the read and that hash) or a set
/// that differs from it by exactly one shape that is on ([`Shapes`]).
pub(super) fn rotational_set_with<'a>(
    mode: Mode,
    solid: bool,
    members: impl Iterator<Item = &'a Member>,
    on: Shapes,
) -> bool {
    rotational_shapes_of(mode, solid, members).is_some_and(|shows| shows.taken(on))
}

/// [`rotational_set_with`] at the shapes this build takes
/// ([`rotational_shapes`]).
pub(super) fn rotational_set<'a>(
    mode: Mode,
    solid: bool,
    members: impl Iterator<Item = &'a Member>,
) -> bool {
    rotational_set_with(mode, solid, members, rotational_shapes())
}

/// The rule's verdict from its four facts: the count it runs at (`None`,
/// the rule off), whether the set qualifies ([`rotational_set`]), the
/// device's class and the archive's residency. Only a rotational device
/// AND a cold archive narrow the run; an unknown class or an unknown
/// residency keeps the width.
pub(super) fn rotational_verdict(
    count: Option<u64>,
    set: bool,
    class: crate::device_class::Class,
    residency: crate::residency::Residency,
) -> Option<u64> {
    let narrow = set
        && class == crate::device_class::Class::Rotational
        && residency == crate::residency::Residency::Cold;
    count.filter(|_| narrow)
}

/// The threads a walk runs at (`None` is the default width) and whether
/// the rotational rule has made it ONE reader in order, which is when its
/// opens take the sequential advice.
///
/// `rule` is [`Run::rotational_readers`], and the order here is the
/// rule's first two conditions: a run already serial (the lone small
/// member) and a run with a stated `-mt` never ask it, so neither
/// resolves a device or samples the page cache.
pub(super) fn walk_threads(
    serial: bool,
    stated: Option<u64>,
    rule: impl FnOnce() -> Option<u64>,
) -> (Option<u64>, bool) {
    if serial {
        return (Some(1), false);
    }
    if stated.is_some() {
        return (stated, false);
    }
    let few = rule();
    (few, few == Some(1))
}

/// Whether the rule at one thread also gives the sequential advice; a
/// count-only knob (`RARFAST_ROTATIONAL_ADVICE=0`) withholds it.
pub(super) fn rotational_advice() -> bool {
    #[cfg(feature = "read-depth-knob")]
    if std::env::var("RARFAST_ROTATIONAL_ADVICE").is_ok_and(|v| v.trim() == "0") {
        return false;
    }
    true
}

/// [`ROTATIONAL_READERS`], or the knob's count; `None` is the rule off.
pub(super) fn rotational_reader_count() -> Option<u64> {
    #[cfg(feature = "read-depth-knob")]
    if let Some(n) = std::env::var("RARFAST_ROTATIONAL_READERS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        return (1..=64).contains(&n).then_some(n);
    }
    ROTATIONAL_READERS
}

impl Run<'_> {
    /// The few threads a stored set's `t` or `p` runs at off a rotational
    /// source ([`ROTATIONAL_READERS`]), or `None` where the rule does not
    /// apply: another command, a member that is not stored, nothing large
    /// enough for the wide read, a device that is not known to be
    /// rotational, or an archive already in the page cache. The device and
    /// the cache are asked last, and only of the first volume: a set's
    /// volumes sit together and are written together.
    pub(super) fn rotational_readers(&self) -> Option<u64> {
        let count = rotational_reader_count()?;
        let members = self.selected.iter().map(|&index| &self.plan[index].member);
        let solid = self.volumes.iter().any(|volume| volume.solid);
        if !rotational_set(self.mode, solid, members) {
            return None;
        }
        let first = Path::new(self.volume_names.first()?);
        let class = crate::device_class::of(first);
        // The page cache is asked only of a rotational source, and last.
        let (fraction, residency) = if class == crate::device_class::Class::Rotational {
            crate::residency::of(first)
        } else {
            (None, crate::residency::Residency::Unknown)
        };
        // COUNT ONLY (feature `read-depth-knob`): `RARFAST_ROTATIONAL_SAY=1`
        // says on stderr what sysfs and the page cache answered, so a
        // run can prove both on its own box without forcing either.
        #[cfg(feature = "read-depth-knob")]
        if std::env::var("RARFAST_ROTATIONAL_SAY").is_ok_and(|v| v.trim() == "1") {
            eprintln!(
                "rarfast device class of {}: {class:?}; residency {residency:?} ({fraction:?}); rotational readers {count}",
                first.display()
            );
        }
        let _ = fraction;
        rotational_verdict(Some(count), true, class, residency)
    }
}
