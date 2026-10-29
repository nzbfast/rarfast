//! A RAR 3.x `RR` record as it is read (spec L 3.7, "An `RR` record as
//! rarkit reads it", and the rows of section 4 that name it): what the
//! genuine program repairs, this repairs.
//!
//! The reference's repair was measured over 56 arms, one thing of the
//! record altered an arm (the probe and its tables are named in 3.7).
//! Each test below is a row of that table, on an archive this file
//! builds the same way: rarkit's own RAR 4 writer makes the archive,
//! whose record's header is found by its mark; the test then writes the
//! record again, a header with the fields the arm names and a data area
//! made here for the `n` and `r` the arm wants, and changes 100 bytes of
//! one protected sector (bytes 10 to 109 of sector 10, of class 0, unless
//! the arm names another). "Mended" is that the repair's output holds
//! the protected bytes as they were.
//!
//! The rule: `r` and `n` are the header's FIELDS, not what the lengths
//! would give; the four bytes after `n` are zero; the record is the 0x7A
//! block named `RR` or carrying the mark `Protect+`; nothing else of the
//! header is read; the data area is taken as it lies, bytes past `2n +
//! 512r` unread and a parity sector cut short still rebuilding what it
//! covers; `r = 0` and the other fields out of bounds refuse the record
//! cleanly; a huge `r` sizes no memory and no loop.
//!
//! Threads and memory: the archive is written by one worker; every
//! repair runs under a policy of at most 4 workers and a 16 MiB repair
//! limit; the archive is about 21 KiB.

use rarkit::memory::MemoryPolicy;
use rarkit::{
    ErrorKind, MemberSpec, Payload, ReadOptions, RecoveryFailure, WriteFormat, WriteOptions, Writer,
};

const SECTOR: usize = 512;
/// The `RR` subblock's header as every genuine writer and this one make
/// it: 32 bytes of fixed fields, the name `RR`, the mark, `r`, `n` and
/// four zero bytes.
const HEADER: usize = 54;
const NAME_AT: usize = 32;
const MARK_AT: usize = 34;
const R_AT: usize = 42;
const N_AT: usize = 46;
const LAST_FOUR_AT: usize = 50;

fn options() -> ReadOptions {
    ReadOptions::default().with_memory(MemoryPolicy {
        repair_limit: 16 << 20,
        max_workers: 4,
        ..MemoryPolicy::from_limit(64 << 20)
    })
}

fn noise(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (crc & 1).wrapping_neg());
        }
    }
    !crc
}

/// The archive in three parts: the protected bytes, a whole number of
/// sectors; the record's header as the writer made it; and what stands
/// behind the record's data area.
struct Base {
    protected: Vec<u8>,
    header: Vec<u8>,
    behind: Vec<u8>,
}

impl Base {
    /// A RAR 4 archive of one member whose record's header begins on a
    /// sector's edge, as the probe's does (its gap arms count from
    /// there). The member's length is walked until it does.
    fn new() -> Base {
        for extra in 0..2 * SECTOR {
            let payload = noise(20_000 + extra, 0x2545_f491);
            let mut writer = Writer::new(WriteOptions {
                format: WriteFormat::Rar4(rarkit::Rar4Version::V40),
                filters: rarkit::FilterPolicy::Off,
                host_os: rarkit::HostOs::Unix,
                recovery_percent: Some(5),
                workers: Some(1),
                ..WriteOptions::default()
            })
            .unwrap();
            writer
                .add(MemberSpec {
                    name: b"payload.bin",
                    payload: Payload::Bytes(&payload),
                    mtime: None,
                    attributes: 0o100644,
                    host_os: rarkit::HostOs::Unix,
                    is_directory: false,
                })
                .unwrap();
            let mut archive = Vec::new();
            writer.finish_into(&mut archive).unwrap();
            let mark = archive
                .windows(8)
                .rposition(|w| w == b"Protect+")
                .expect("the record's mark");
            let at = mark - MARK_AT;
            if !at.is_multiple_of(SECTOR) {
                continue;
            }
            let header = archive[at..at + HEADER].to_vec();
            assert_eq!(header[2], 0x7a, "a subblock");
            assert_eq!(u16::from_le_bytes([header[5], header[6]]), HEADER as u16);
            assert_eq!(&header[NAME_AT..MARK_AT], b"RR");
            let area = u32::from_le_bytes(header[7..11].try_into().unwrap()) as usize;
            return Base {
                protected: archive[..at].to_vec(),
                behind: archive[at + HEADER + area..].to_vec(),
                header,
            };
        }
        panic!("no member length puts the record on a sector's edge");
    }

    /// The protected sectors.
    fn n(&self) -> u32 {
        (self.protected.len() / SECTOR) as u32
    }

    /// The data area a writer makes for these protected bytes with `r`
    /// parity sectors: the tags, then parity sector `c`, the XOR of every
    /// sector `s` with `s mod r = c` (3.7).
    fn area(&self, r: usize) -> Vec<u8> {
        let mut tags = Vec::new();
        let mut parity = vec![0u8; SECTOR * r];
        for (s, sector) in self.protected.chunks(SECTOR).enumerate() {
            tags.extend_from_slice(&(!crc32(sector) as u16).to_le_bytes());
            let class = (s % r) * SECTOR;
            for (to, from) in parity[class..class + SECTOR].iter_mut().zip(sector) {
                *to ^= from;
            }
        }
        tags.extend(parity);
        tags
    }
}

/// A change to the record's header.
type Edit<'a> = Box<dyn Fn(&mut Vec<u8>) + 'a>;

/// One arm: the record written again over the base.
struct Arm<'a> {
    base: &'a Base,
    r: u32,
    n: u32,
    last_four: u32,
    area: Vec<u8>,
    /// Applied to the header after its fields are set and before its
    /// checksum is made.
    edit: Edit<'a>,
    /// Whether the header's own checksum is made right.
    sealed: bool,
    /// Bytes of a 0x77 block put between the protected bytes and the
    /// record, 0 for none.
    gap: usize,
    /// The damaged sector and the first of its 100 changed bytes.
    damage: (usize, usize),
}

impl<'a> Arm<'a> {
    /// The control: the fields true, `r = 2`, the area the writer's.
    fn stated(base: &'a Base) -> Arm<'a> {
        Arm {
            base,
            r: 2,
            n: base.n(),
            last_four: 0,
            area: base.area(2),
            edit: Box::new(|_| {}),
            sealed: true,
            gap: 0,
            damage: (10, 10),
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let mut header = self.base.header.clone();
        header[7..11].copy_from_slice(&(self.area.len() as u32).to_le_bytes());
        header[R_AT..N_AT].copy_from_slice(&self.r.to_le_bytes());
        header[N_AT..LAST_FOUR_AT].copy_from_slice(&self.n.to_le_bytes());
        header[LAST_FOUR_AT..HEADER].copy_from_slice(&self.last_four.to_le_bytes());
        (self.edit)(&mut header);
        if self.sealed {
            let sum = crc32(&header[2..]) as u16;
            header[..2].copy_from_slice(&sum.to_le_bytes());
        }
        let mut bytes = self.base.protected.clone();
        let (sector, from) = self.damage;
        for byte in &mut bytes[sector * SECTOR + from..sector * SECTOR + from + 100] {
            *byte ^= 0x5a;
        }
        if self.gap != 0 {
            // A block of type 0x77 with no data area, `gap` bytes long.
            let mut block = vec![0u8; self.gap];
            block[2] = 0x77;
            block[5..7].copy_from_slice(&(self.gap as u16).to_le_bytes());
            let sum = crc32(&block[2..]) as u16;
            block[..2].copy_from_slice(&sum.to_le_bytes());
            bytes.extend(block);
        }
        bytes.extend(header);
        bytes.extend(&self.area);
        bytes.extend(&self.base.behind);
        bytes
    }

    fn run(&self) -> rarkit::Result<Vec<u8>> {
        let mut out = Vec::new();
        rarkit::recovery::repair_inline(&self.bytes(), &options(), &mut out)?;
        Ok(out)
    }

    /// The damaged sector is rebuilt: the output's protected bytes are
    /// the base's.
    fn assert_mended(&self, what: &str) {
        let out = self.run().unwrap_or_else(|e| panic!("{what}: {e}"));
        let protected = &self.base.protected;
        assert!(
            out.len() >= protected.len() && out[..protected.len()] == protected[..],
            "{what}: the protected bytes are not as they were"
        );
    }

    /// The damaged sector is NOT rebuilt, and nothing faults: an error,
    /// or an output whose protected bytes are still the damaged ones.
    fn assert_not_mended(&self, what: &str) {
        if let Ok(out) = self.run() {
            let protected = &self.base.protected;
            assert!(
                out.len() < protected.len() || out[..protected.len()] != protected[..],
                "{what}: rebuilt, where the reference does not rebuild"
            );
        }
    }

    /// The record is refused cleanly: `RecoveryDamaged`.
    fn assert_refused(&self, what: &str) {
        let error = self.run().expect_err(what);
        assert!(
            matches!(
                error.kind(),
                ErrorKind::Recovery(RecoveryFailure::RecoveryDamaged)
            ),
            "{what}: {error}"
        );
    }
}

/// `stated`, `stated-other-class`, `stated-damage-at-end`.
#[test]
fn control_a_true_record_rebuilds_a_damaged_sector() {
    let base = Base::new();
    assert!(base.n() >= 40, "{} sectors", base.n());
    Arm::stated(&base).assert_mended("stated");
    Arm {
        damage: (11, 10),
        ..Arm::stated(&base)
    }
    .assert_mended("stated-other-class");
    Arm {
        damage: (11, 412),
        ..Arm::stated(&base)
    }
    .assert_mended("stated-damage-at-end");
}

/// `r-field-1`, `r-field-3`, `r-field-100`, `three-parity-r-field-2`
/// and `-3`: `r` is the header's field. A field that is not the `r` the
/// area was made for rebuilds nothing; an area of three parity sectors
/// under a field of 3 is a true record.
#[test]
fn r_is_the_headers_field() {
    let base = Base::new();
    for r in [1, 3, 100] {
        Arm {
            r,
            ..Arm::stated(&base)
        }
        .assert_not_mended(&format!("r-field-{r}"));
    }
    Arm {
        area: base.area(3),
        ..Arm::stated(&base)
    }
    .assert_not_mended("three-parity-r-field-2");
    Arm {
        r: 3,
        area: base.area(3),
        ..Arm::stated(&base)
    }
    .assert_mended("three-parity-r-field-3");
}

/// `r-field-0`: refused before anything is divided by it (the reference
/// ends on a signal).
#[test]
fn an_r_of_zero_refuses_the_record() {
    let base = Base::new();
    Arm {
        r: 0,
        ..Arm::stated(&base)
    }
    .assert_refused("r-field-0");
}

/// `r-field-2-to-the-31`, `r-field-max`: no fault and no refusal by the
/// size of `r`: it sizes no memory (512 r is far past the 16 MiB limit
/// these calls run under) and no loop; the sector is not rebuilt. (The
/// reference ends on a signal or runs until stopped.)
#[test]
fn a_huge_r_sizes_no_memory_and_no_loop() {
    let base = Base::new();
    for r in [0x8000_0000u32, 0xffff_ffff] {
        let arm = Arm {
            r,
            ..Arm::stated(&base)
        };
        if let Err(error) = arm.run() {
            assert!(
                !matches!(error.kind(), ErrorKind::LimitExceeded { .. }),
                "r = {r:#x}: {error}"
            );
        }
        arm.assert_not_mended(&format!("r = {r:#x}"));
    }
}

/// The `n-field` arms and `last-four-1`, `last-four-max`: `n` is the
/// header's field and the four bytes after it are zero. `n = 0`, one
/// more (the header then begins before `512(n - 1)` is passed), a `2n`
/// past the area, and four bytes that are not zero refuse the record;
/// one less reads the tags and the parity from the wrong places and
/// rebuilds nothing.
#[test]
fn n_is_the_headers_field_and_the_four_bytes_after_it_are_zero() {
    let base = Base::new();
    let n = base.n();
    for (what, field) in [
        ("n-field-0", 0),
        ("n-field-more-1", n + 1),
        ("n-field-max", u32::MAX),
    ] {
        Arm {
            n: field,
            ..Arm::stated(&base)
        }
        .assert_refused(what);
    }
    Arm {
        n: n - 1,
        ..Arm::stated(&base)
    }
    .assert_not_mended("n-field-less-1");
    for (what, last_four) in [("last-four-1", 1), ("last-four-max", u32::MAX)] {
        Arm {
            last_four,
            ..Arm::stated(&base)
        }
        .assert_refused(what);
    }
}

/// `area-tags-only`: the tags and no parity: nothing rebuilt, no fault.
#[test]
fn an_area_of_tags_alone_rebuilds_nothing() {
    let base = Base::new();
    let mut area = base.area(2);
    area.truncate(2 * base.n() as usize);
    Arm {
        area,
        ..Arm::stated(&base)
    }
    .assert_not_mended("area-tags-only");
}

/// The `area-*-more` arms: bytes of the data area past `2n + 512r` are
/// not read; the sector is rebuilt in either class.
#[test]
fn a_data_area_longer_than_needed_is_rebuilt_from() {
    let base = Base::new();
    for more in [1usize, 256, 512, 4096] {
        for sector in [10, 11] {
            let mut area = base.area(2);
            area.extend(noise(more, 0x0bad_5eed));
            Arm {
                area,
                damage: (sector, 10),
                ..Arm::stated(&base)
            }
            .assert_mended(&format!("{more} more, sector {sector}"));
        }
    }
}

/// The `area-*-less` arms: a parity sector the data area holds only in
/// part rebuilds the bytes it covers, and the rebuilt sector is kept
/// when its tag is the stored one. The last parity sector, of class 1,
/// is the one cut.
#[test]
fn a_data_area_cut_short_rebuilds_what_its_parity_covers() {
    let base = Base::new();
    let cut = |less: usize| {
        let mut area = base.area(2);
        area.truncate(area.len() - less);
        area
    };
    // Class 0, whose parity sector is whole or cut only past byte 109.
    for less in [1usize, 256, 511, 513, 512] {
        Arm {
            area: cut(less),
            ..Arm::stated(&base)
        }
        .assert_mended(&format!("{less} less, class 0"));
    }
    // Class 1, its parity sector cut, the damage in the part still there.
    for less in [1usize, 256] {
        Arm {
            area: cut(less),
            damage: (11, 10),
            ..Arm::stated(&base)
        }
        .assert_mended(&format!("{less} less, class 1, damage covered"));
    }
    // The damage inside the part cut off.
    for (less, damage) in [(1usize, (11, 412)), (256, (11, 300)), (513, (10, 412))] {
        Arm {
            area: cut(less),
            damage,
            ..Arm::stated(&base)
        }
        .assert_not_mended(&format!("{less} less, damage in the cut"));
    }
    // The whole of class 1's parity sector gone.
    Arm {
        area: cut(512),
        damage: (11, 10),
        ..Arm::stated(&base)
    }
    .assert_not_mended("512 less, class 1");
}

/// The mark arms and the name arms: the record is the 0x7A block named
/// `RR`, whatever its mark, or carrying the mark `Protect+`, whatever its
/// name. A block with neither is not taken: there is no record.
#[test]
fn the_record_is_found_by_its_name_or_by_its_mark() {
    let base = Base::new();
    for mark in [*b"Protect!", *b"protect+", [0u8; 8]] {
        Arm {
            edit: Box::new(move |header| header[MARK_AT..R_AT].copy_from_slice(&mark)),
            ..Arm::stated(&base)
        }
        .assert_mended(&format!("mark {mark:?}"));
    }
    for name in [*b"rr", *b"RX"] {
        Arm {
            edit: Box::new(move |header| header[NAME_AT..MARK_AT].copy_from_slice(&name)),
            ..Arm::stated(&base)
        }
        .assert_mended(&format!("name {name:?}"));
    }
    let neither = Arm {
        edit: Box::new(|header| {
            header[NAME_AT..MARK_AT].copy_from_slice(b"RX");
            header[MARK_AT..R_AT].copy_from_slice(b"protect+");
        }),
        ..Arm::stated(&base)
    };
    let error = neither.run().expect_err("neither the name nor the mark");
    assert!(
        matches!(error.kind(), ErrorKind::Recovery(RecoveryFailure::NoRecord)),
        "{error}"
    );
}

/// `method-0x33`, `version-20`, `version-36`, `data-crc-wrong`,
/// `unpacked-more`, `flags-no-skip`: nothing of the header is read but
/// its type, its flags' data bit, its two lengths, the name, the mark
/// and the three fields. Every byte from the unpacked size to the method
/// (11 to 25) is changed in turn, and the flag 0x4000 cleared; the data
/// area is taken as it lies and never decoded.
#[test]
fn nothing_else_of_the_header_is_read() {
    let base = Base::new();
    for at in 11..26usize {
        Arm {
            edit: Box::new(move |header| header[at] ^= 0x33),
            ..Arm::stated(&base)
        }
        .assert_mended(&format!("header byte {at} changed"));
    }
    Arm {
        edit: Box::new(|header| header[4] &= !0x40),
        ..Arm::stated(&base)
    }
    .assert_mended("flags-no-skip");
}

/// `header-crc-wrong`: the subblock header's own checksum must be
/// right, as for any block: there is no record.
#[test]
fn a_header_failing_its_own_check_is_no_record() {
    let base = Base::new();
    let arm = Arm {
        edit: Box::new(|header| header[0] ^= 1),
        sealed: false,
        ..Arm::stated(&base)
    };
    let error = arm.run().expect_err("header-crc-wrong");
    assert!(
        matches!(error.kind(), ErrorKind::Recovery(RecoveryFailure::NoRecord)),
        "{error}"
    );
}

/// The gap arms: the record's header may begin up to 512 bytes past
/// `512n` (a block of 111, 311, 511 or 512 bytes in between) and no
/// further (513, 611): the record is then refused. With the `n` field
/// one more over 611 bytes nothing is rebuilt.
#[test]
fn the_records_header_may_begin_up_to_one_sector_past_the_protected_bytes() {
    let base = Base::new();
    for gap in [111usize, 311, 511, 512] {
        Arm {
            gap,
            ..Arm::stated(&base)
        }
        .assert_mended(&format!("a block of {gap} before the record"));
    }
    for gap in [513usize, 611] {
        Arm {
            gap,
            ..Arm::stated(&base)
        }
        .assert_refused(&format!("a block of {gap} before the record"));
    }
    Arm {
        gap: 611,
        n: base.n() + 1,
        ..Arm::stated(&base)
    }
    .assert_not_mended("gap-600-n-field-more-1");
}

/// `block-after`: a block behind the record changes nothing.
#[test]
fn a_block_behind_the_record_changes_nothing() {
    let base = Base::new();
    let mut behind = vec![0u8; 111];
    behind[2] = 0x77;
    behind[5..7].copy_from_slice(&111u16.to_le_bytes());
    let sum = crc32(&behind[2..]) as u16;
    behind[..2].copy_from_slice(&sum.to_le_bytes());
    behind.extend(&base.behind);
    let longer = Base {
        protected: base.protected.clone(),
        header: base.header.clone(),
        behind,
    };
    Arm::stated(&longer).assert_mended("block-after");
}
