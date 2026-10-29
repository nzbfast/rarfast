//! The extract's own rules, each against its table: the routes, the
//! rotational shapes, the cold window, the reserved output.

use super::*;

/// A file member as the rotational rule reads one: its size, its
/// method, whether it is enciphered and whether its checksum is a
/// CRC32.
fn rule_member(size: u64, method: u8, encrypted: bool, crc32: bool, is_dir: bool) -> Member {
    Member {
        name: crate::dialect::unrar::Name::from("element.mkv"),
        disk: None,
        printable: true,
        is_dir,
        is_service: false,
        size,
        packed: size,
        mtime: Some(1_000_000_000),
        mtime_nanos: 0,
        wall_clock: false,
        attr: 0o100_644,
        host: crate::dialect::unrar::HostOs::Unix,
        crc32: crc32.then_some(0x3D50_D04A),
        encrypted,
        password_checked: false,
        version: None,
        split_before: false,
        split_after: false,
        algorithm_version: 0,
        method,
        dictionary: None,
        solid: false,
        unknown_version: false,
        data_end: 0,
        redirect: None,
    }
}

/// The set the rotational rule may narrow: `t` or `p`, every file
/// stored, unencrypted and CRC32, one of them at least 16 MiB.
#[test]
fn the_rotational_rule_takes_only_a_plain_stored_set_with_a_big_member() {
    const GIB: u64 = 1 << 30;
    let big = rule_member(12 * GIB, 0, false, true, false);
    let small = rule_member(8 << 20, 0, false, true, false);
    let dir = rule_member(0, 0, false, false, true);
    let set = |mode, members: &[&Member]| rotational_set(mode, false, members.iter().copied());
    // One big stored member; several in one archive; a directory among them.
    assert!(set(Mode::Test, &[&big]));
    assert!(set(Mode::Print, &[&big, &big, &small]));
    assert!(set(Mode::Test, &[&dir, &big]));
    // `x` and `e` are never narrowed.
    assert!(!set(Mode::Extract { flat: false }, &[&big]));
    assert!(!set(Mode::Extract { flat: true }, &[&big]));
    // Nothing at the wide read's floor; exactly at it; nothing at all.
    assert!(!set(Mode::Test, &[&small, &small]));
    assert!(set(
        Mode::Test,
        &[&rule_member(WIDE_READ_FLOOR, 0, false, true, false)]
    ));
    assert!(!set(
        Mode::Test,
        &[&rule_member(WIDE_READ_FLOOR - 1, 0, false, true, false)]
    ));
    assert!(!set(Mode::Test, &[]));
    assert!(!set(Mode::Test, &[&dir]));
    // A solid archive of plain stored members qualifies
    // (`Shapes::SOLID`, on since its own row); with that shape off, as
    // the rule first landed, a solid archive was never narrowed.
    assert!(rotational_set(Mode::Test, true, [&big].into_iter()));
    assert!(rotational_set(Mode::Print, true, [&big, &big].into_iter()));
    assert!(!rotational_set_with(
        Mode::Test,
        true,
        [&big, &big].into_iter(),
        Shapes::RAR4.with(Shapes::MIXED)
    ));
    // `x` of a solid set is not the rule's either.
    assert!(!rotational_set(
        Mode::Extract { flat: false },
        true,
        [&big].into_iter()
    ));
    // RAR 5's two compression versions qualify, and so does the RAR
    // 1.5 to 4.x family (`Shapes::RAR4`, on since its own rows); a
    // member of the RAR 1.3 container (its constant 2) anywhere
    // switches the set off. With that shape off, as the rule first
    // landed, an older member anywhere switched it off.
    let versioned = |version: u32| {
        let mut member = rule_member(GIB, 0, false, true, false);
        member.algorithm_version = version;
        member
    };
    assert!(set(Mode::Test, &[&versioned(0), &versioned(1)]));
    assert!(set(Mode::Test, &[&versioned(29)]));
    assert!(set(Mode::Test, &[&versioned(20), &versioned(20)]));
    assert!(set(Mode::Print, &[&big, &versioned(36)]));
    assert!(!set(Mode::Test, &[&versioned(2)]));
    assert!(!set(Mode::Test, &[&versioned(29), &versioned(2)]));
    for old in [versioned(29), versioned(36)] {
        assert!(!rotational_set_with(
            Mode::Test,
            false,
            [&big, &old].into_iter(),
            Shapes::NONE
        ));
    }
    // A RAR 4 set that is also solid, or enciphered, is two shapes at
    // once and keeps the width.
    assert!(!rotational_set(
        Mode::Test,
        true,
        [&versioned(29)].into_iter()
    ));
    let mut hidden = versioned(29);
    hidden.encrypted = true;
    assert!(!set(Mode::Test, &[&hidden]));
    // One compressed, enciphered or BLAKE2sp member anywhere switches it off.
    assert!(!set(
        Mode::Test,
        &[&big, &rule_member(GIB, 3, false, true, false)]
    ));
    assert!(!set(
        Mode::Test,
        &[&rule_member(GIB, 0, true, true, false), &big]
    ));
    assert!(!set(
        Mode::Test,
        &[&big, &rule_member(GIB, 0, false, false, false)]
    ));
}

/// The shipped rule takes the plain set and, beyond it, exactly the
/// shapes with a winning row on hard disks: the RAR 4 family's,
/// compressed members beside the stored ones up to the cap (the
/// largest point with such a row), and a solid archive. A cipher and a
/// BLAKE2sp hash lost their rows and are not among them.
#[test]
fn the_shipped_rotational_rule_takes_the_shapes_with_a_row_and_no_other() {
    assert_eq!(
        ROTATIONAL_SHAPES,
        Shapes::RAR4.with(Shapes::MIXED).with(Shapes::SOLID)
    );
    assert_eq!(MIXED_COMPRESSED_CAP, 64 << 20);
    for off in [Shapes::CIPHER, Shapes::BLAKE2SP] {
        assert!(!ROTATIONAL_SHAPES.holds(off), "{off:?}");
    }
    // The shipped line between a small mixed set and a heavy one, by
    // the members' own unpacked sizes: at the cap taken, a byte over
    // not, and the big member must be a STORED one.
    const GIB: u64 = 1 << 30;
    let big = rule_member(12 * GIB, 0, false, true, false);
    let text = |size| rule_member(size, 3, false, true, false);
    let set = |members: &[&Member]| rotational_set(Mode::Test, false, members.iter().copied());
    assert!(set(&[&big, &text(4096)]));
    assert!(set(&[&text(MIXED_COMPRESSED_CAP), &big]));
    assert!(set(&[
        &text(MIXED_COMPRESSED_CAP / 2),
        &big,
        &text(MIXED_COMPRESSED_CAP / 2)
    ]));
    assert!(!set(&[&big, &text(MIXED_COMPRESSED_CAP + 1)]));
    assert!(!set(&[&big, &text(4 * GIB)]));
    assert!(!set(&[
        &text(4096),
        &rule_member(8 << 20, 0, false, true, false)
    ]));
    // Two shapes at once keep the width: a mixed set of the RAR 4
    // family, a solid one, an enciphered one.
    let mut old = rule_member(GIB, 0, false, true, false);
    old.algorithm_version = 29;
    assert!(!set(&[&old, &text(4096)]));
    assert!(!rotational_set(
        Mode::Test,
        true,
        [&big, &text(4096)].into_iter()
    ));
    assert!(!set(&[
        &rule_member(GIB, 0, true, true, false),
        &text(4096)
    ]));
}

/// What a set shows, shape by shape, and what no form of the rule
/// takes: `x`, the RAR 1.3 container, more compressed bytes than the
/// cap, no big STORED member.
#[test]
fn a_set_shows_the_shapes_it_differs_from_the_plain_one_by() {
    const GIB: u64 = 1 << 30;
    let big = rule_member(12 * GIB, 0, false, true, false);
    let dir = rule_member(0, 0, false, false, true);
    let versioned = |version: u32| {
        let mut member = rule_member(GIB, 0, false, true, false);
        member.algorithm_version = version;
        member
    };
    let shows = |solid, members: &[&Member]| {
        rotational_shapes_of(Mode::Test, solid, members.iter().copied())
    };
    assert_eq!(shows(false, &[&big, &dir]), Some(Shapes::NONE));
    // The RAR 1.5 to 4.x family by its unpack versions; RAR 5's two
    // are plain; the RAR 1.3 container's constant is never taken.
    for version in [13, 15, 20, 26, 29, 36] {
        assert_eq!(shows(false, &[&versioned(version)]), Some(Shapes::RAR4));
    }
    assert_eq!(
        shows(false, &[&versioned(0), &versioned(1)]),
        Some(Shapes::NONE)
    );
    assert_eq!(shows(false, &[&versioned(2)]), None);
    assert_eq!(shows(false, &[&big, &versioned(2)]), None);
    // The archive's solid flag; a cipher; no CRC32.
    assert_eq!(shows(true, &[&big]), Some(Shapes::SOLID));
    let cipher = rule_member(GIB, 0, true, true, false);
    assert_eq!(shows(false, &[&big, &cipher]), Some(Shapes::CIPHER));
    let blake = rule_member(GIB, 0, false, false, false);
    assert_eq!(shows(false, &[&blake, &big]), Some(Shapes::BLAKE2SP));
    // Compressed members beside the big member: mixed up to the cap, summed
    // over all of them, and never taken past it.
    let text = |size| rule_member(size, 3, false, true, false);
    assert_eq!(shows(false, &[&big, &text(4096)]), Some(Shapes::MIXED));
    let half = MIXED_COMPRESSED_CAP / 2;
    assert_eq!(
        shows(false, &[&text(half), &big, &text(half)]),
        Some(Shapes::MIXED)
    );
    assert_eq!(shows(false, &[&text(half), &big, &text(half + 1)]), None);
    assert_eq!(shows(false, &[&big, &text(GIB)]), None);
    // The big member must be a STORED one: a compressed member is
    // never what the wide read takes.
    assert_eq!(
        shows(
            false,
            &[
                &text(MIXED_COMPRESSED_CAP),
                &rule_member(8 << 20, 0, false, true, false)
            ]
        ),
        None
    );
    // Two shapes at once are both shown.
    assert_eq!(
        shows(true, &[&versioned(29)]),
        Some(Shapes::SOLID.with(Shapes::RAR4))
    );
    let hidden = rule_member(GIB, 0, true, false, false);
    assert_eq!(
        shows(false, &[&hidden]),
        Some(Shapes::CIPHER.with(Shapes::BLAKE2SP))
    );
    // `x`, `e` and a set with nothing large show nothing to take.
    assert_eq!(
        rotational_shapes_of(Mode::Extract { flat: false }, false, [&big].into_iter()),
        None
    );
    assert_eq!(shows(true, &[&dir]), None);
}

/// A shape is taken only where it is switched on, alone: each of the
/// five on its own set, off for every other shape's set, and a set of
/// two shapes is never taken, whatever is on.
#[test]
fn a_shape_is_taken_only_where_it_is_on_and_only_alone() {
    const GIB: u64 = 1 << 30;
    let big = rule_member(12 * GIB, 0, false, true, false);
    let mut old = rule_member(GIB, 0, false, true, false);
    old.algorithm_version = 29;
    let cipher = rule_member(GIB, 0, true, true, false);
    let blake = rule_member(GIB, 0, false, false, false);
    let text = rule_member(4096, 3, false, true, false);
    let all = [
        Shapes::RAR4,
        Shapes::SOLID,
        Shapes::CIPHER,
        Shapes::BLAKE2SP,
        Shapes::MIXED,
    ];
    let sets: [(Shapes, bool, Vec<&Member>); 5] = [
        (Shapes::RAR4, false, vec![&old, &old]),
        (Shapes::SOLID, true, vec![&big, &big]),
        (Shapes::CIPHER, false, vec![&cipher]),
        (Shapes::BLAKE2SP, false, vec![&blake, &big]),
        (Shapes::MIXED, false, vec![&big, &text]),
    ];
    let everything = all.iter().fold(Shapes::NONE, |sum, &s| sum.with(s));
    for (shape, solid, members) in &sets {
        for mode in [Mode::Test, Mode::Print] {
            let taken = |on| rotational_set_with(mode, *solid, members.iter().copied(), on);
            assert!(!taken(Shapes::NONE), "{shape:?} with nothing on");
            assert!(taken(everything), "{shape:?} with everything on");
            for on in all {
                assert_eq!(taken(on), on == *shape, "{shape:?} with {on:?} on");
            }
        }
        // `x` is not the rule's, whatever is on.
        assert!(!rotational_set_with(
            Mode::Extract { flat: false },
            *solid,
            members.iter().copied(),
            everything
        ));
    }
    // The plain set is taken whatever is on.
    for on in [Shapes::NONE, everything] {
        assert!(rotational_set_with(
            Mode::Test,
            false,
            [&big].into_iter(),
            on
        ));
    }
    // Two shapes at once: no row was sat on a combination.
    assert!(!rotational_set_with(
        Mode::Test,
        true,
        [&old].into_iter(),
        everything
    ));
    assert!(!rotational_set_with(
        Mode::Test,
        false,
        [&old, &cipher].into_iter(),
        everything
    ));
    assert!(!rotational_set_with(
        Mode::Test,
        true,
        [&big, &text].into_iter(),
        everything
    ));
}

/// The knob's list: the five names, `all`, `none`, and a word that is
/// none of them is not a list.
#[test]
fn the_shapes_knob_reads_a_list_of_names() {
    assert_eq!(shapes_of(""), Some(Shapes::NONE));
    assert_eq!(shapes_of("none"), Some(Shapes::NONE));
    assert_eq!(shapes_of("rar4"), Some(Shapes::RAR4));
    assert_eq!(
        shapes_of(" solid , cipher "),
        Some(Shapes::SOLID.with(Shapes::CIPHER))
    );
    assert_eq!(
        shapes_of("blake2sp,mixed"),
        Some(Shapes::BLAKE2SP.with(Shapes::MIXED))
    );
    let all = shapes_of("all").unwrap();
    for shape in ["rar4", "solid", "cipher", "blake2sp", "mixed"] {
        assert!(all.holds(shapes_of(shape).unwrap()), "{shape}");
    }
    assert_eq!(shapes_of("rar4,rar5"), None);
    assert_eq!(shapes_of("1"), None);
}

/// The walk asks the rule only where the run is not serial already and
/// no `-mt` is stated, and one reader is the only count in order.
#[test]
fn the_walk_asks_the_rotational_rule_only_with_no_width_stated() {
    let never = || -> Option<u64> { panic!("the rule was asked") };
    // A lone small member is serial already, and a stated -mt is the
    // user's: neither asks, so neither touches sysfs or the page cache.
    assert_eq!(walk_threads(true, None, never), (Some(1), false));
    assert_eq!(walk_threads(false, Some(1), never), (Some(1), false));
    assert_eq!(walk_threads(false, Some(12), never), (Some(12), false));
    // Asked: silent is the default width, one is one reader in order,
    // and another count (the measuring knob's) narrows with no advice.
    assert_eq!(walk_threads(false, None, || None), (None, false));
    assert_eq!(walk_threads(false, None, || Some(1)), (Some(1), true));
    assert_eq!(walk_threads(false, None, || Some(4)), (Some(4), false));
}

/// The archive's window: only with the knob on, on the deep stored
/// route, with no cap stated and a second thread to spend; its two
/// slabs inside half the working limit.
#[cfg(feature = "parallel")]
#[test]
fn the_cold_window_is_the_deep_routes_and_inside_half_the_working_limit() {
    // The count-only slab dial would answer for every case below.
    if std::env::var_os("RARFAST_COLD_WINDOW_KIB").is_some() {
        return;
    }
    const MIB: u64 = 1 << 20;
    let slab = crate::window::SLAB;
    let slabs = crate::window::SLABS as u64;
    // On, deep, uncapped, the default width or a stated one over one.
    assert_eq!(
        cold_window_of(true, true, true, false, None, 512 * MIB),
        Some(slab)
    );
    assert_eq!(
        cold_window_of(true, true, true, false, Some(4), 512 * MIB),
        Some(slab)
    );
    assert_eq!(
        cold_window_of(true, true, true, false, None, 64 << 30),
        Some(slab)
    );
    // Each condition failing alone: no window.
    assert_eq!(
        cold_window_of(false, true, true, false, None, 512 * MIB),
        None
    );
    assert_eq!(
        cold_window_of(true, false, true, false, None, 512 * MIB),
        None
    );
    assert_eq!(
        cold_window_of(true, true, true, true, None, 512 * MIB),
        None
    );
    assert_eq!(
        cold_window_of(true, true, true, false, Some(1), 512 * MIB),
        None
    );
    // A selection (not every file of the set): no window.
    assert_eq!(
        cold_window_of(true, true, false, false, None, 512 * MIB),
        None
    );
    // A smaller working limit: the slabs together are half of it, and
    // under a mebibyte a slab there is none.
    assert_eq!(
        cold_window_of(true, true, true, false, None, 128 * MIB),
        Some(128 * MIB / 2 / slabs)
    );
    assert_eq!(
        cold_window_of(true, true, true, false, None, 4 * MIB),
        Some(MIB)
    );
    assert_eq!(
        cold_window_of(true, true, true, false, None, 4 * MIB - 1),
        None
    );
    // What the deep route's ring held, and no more.
    assert!(slab * slabs <= STORED_COLD_READ_AHEAD);
    // The knob: on unless switched off by `0` or `off`.
    for (value, on) in [
        (None, true),
        (Some(""), true),
        (Some("1"), true),
        (Some("on"), true),
        (Some("yes"), true),
        (Some("0"), false),
        (Some("off"), false),
        (Some(" OFF "), false),
        (Some("00"), true),
    ] {
        assert_eq!(cold_window_on(value), on, "{value:?}");
    }
    assert_eq!(cold_window_ahead(false), 0);
}

/// Only a rotational device AND a cold archive narrow the run, and
/// only where a count is set at all: the shipped count decides whether
/// the rule exists (SPEC-F 3.7.8).
#[test]
fn the_rotational_rule_narrows_only_a_cold_archive_on_a_rotational_device() {
    use crate::device_class::Class;
    use crate::residency::Residency;
    for count in [Some(1), Some(4)] {
        assert_eq!(
            rotational_verdict(count, true, Class::Rotational, Residency::Cold),
            count
        );
        for (class, residency) in [
            (Class::Rotational, Residency::Resident),
            (Class::Rotational, Residency::Unknown),
            (Class::SolidState, Residency::Cold),
            (Class::Unknown, Residency::Cold),
            (Class::Unknown, Residency::Unknown),
        ] {
            assert_eq!(rotational_verdict(count, true, class, residency), None);
        }
        // A set that does not qualify is never narrowed.
        assert_eq!(
            rotational_verdict(count, false, Class::Rotational, Residency::Cold),
            None
        );
    }
    // With no count the rule is off whatever the device and the cache say.
    assert_eq!(
        rotational_verdict(None, true, Class::Rotational, Residency::Cold),
        None
    );
}

/// A file whose first `resident` pages of every sampled window are in
/// memory: the page cache's answer either side of the half.
#[cfg(feature = "parallel")]
struct Sampled {
    resident: u64,
    answers: bool,
    spent: std::cell::Cell<u64>,
}

#[cfg(feature = "parallel")]
impl crate::residency::Pages for Sampled {
    fn shape(&self) -> (u64, u64) {
        (1 << 30, 16384)
    }
    fn resident(&self, _offset: u64, pages: u64) -> Option<u64> {
        // Asked a window at a time; the windows before `resident`
        // pages are spent are whole, the rest empty.
        let spent = self.spent.get();
        let got = pages.min(self.resident.saturating_sub(spent));
        self.spent.set(spent + pages);
        self.answers.then_some(got)
    }
}

/// The stored route on macOS follows the sample of the page cache: an
/// archive whose whole sample is in memory takes the pool; one partly
/// in memory the walk at the shipped depth; one under half the walk,
/// deep only where it is plain; one the kernel will not answer for the
/// walk at the shipped depth, as before the cache was asked.
#[cfg(feature = "parallel")]
#[test]
fn the_stored_route_takes_the_pool_only_for_a_whole_sample() {
    use crate::residency::{judge, Residency, WINDOWS, WINDOW_PAGES};
    let sample = WINDOWS * WINDOW_PAGES;
    let said = |resident: u64, answers: bool| {
        judge(&Sampled {
            resident,
            answers,
            spent: std::cell::Cell::new(0),
        })
    };
    // The whole sample in memory: the pool.
    let whole = said(sample, true);
    assert_eq!(whole, (Some(1.0), Residency::Resident));
    assert_eq!(stored_route_of(whole, true), (false, false));
    // One sampled page out of memory (0.984): the walk, at the
    // shipped depth, though the sampler still calls it resident.
    let nearly = said(sample - 1, true);
    assert_eq!(nearly.1, Residency::Resident);
    assert_eq!(stored_route_of(nearly, true), (true, false));
    // 0.50 of the sample, the sampler's own turn: still the walk.
    let half = said(sample / 2, true);
    assert_eq!(half, (Some(0.5), Residency::Resident));
    assert_eq!(stored_route_of(half, true), (true, false));
    // One page under it (0.484): cold, the walk, deep where plain.
    let under = said(sample / 2 - 1, true);
    assert!(under.0.is_some_and(|f| f < 0.5 && f > 0.48));
    assert_eq!(under.1, Residency::Cold);
    assert_eq!(stored_route_of(under, true), (true, true));
    assert_eq!(stored_route_of(under, false), (true, false));
    // Wholly cold.
    assert_eq!(stored_route_of(said(0, true), true), (true, true));
    // No answer: the walk, never deep.
    let unknown = said(sample, false);
    assert_eq!(unknown, (None, Residency::Unknown));
    assert_eq!(stored_route_of(unknown, true), (true, false));
    // A verdict stated with no fraction (a count build's knob).
    assert_eq!(
        stored_route_of((None, Residency::Resident), true),
        (false, false)
    );
    assert_eq!(stored_route_of((None, Residency::Cold), true), (true, true));
}

/// A SPLIT SET BY THE PART (22 Oct 2026): on macOS it keeps the
/// pool where the top performance level (`hw.perflevel0.physicalcpu`) has
/// 8 cores or more, and takes the stored route below that. MEASURED parts
/// only: the base M5 MacBook Air (Super 4, the walk), the M5 Max (Super
/// 6, the walk) and the M1 Ultra (Performance 16, the pool). Every other
/// part (the Pro, Max and Ultra of M2 to M4, the M5 Pro) is UNMEASURED:
/// its side of 8 is a reading of the rule, not a count. A part whose
/// level cannot be read keeps the stored route, as before the rule. Pure:
/// no width, no memory.
#[cfg(feature = "parallel")]
#[test]
fn a_split_set_keeps_the_pool_only_on_a_part_of_eight_top_cores() {
    assert_eq!(SPLIT_SET_POOL_FROM_TOP_CORES, 8);
    // (the top level's cores, keeps the pool): the three measured parts,
    // the edges, and an unknown part.
    for (top, pool) in [
        (Some(4), false),
        (Some(6), false),
        (Some(16), true),
        (Some(7), false),
        (Some(8), true),
        (None, false),
    ] {
        assert_eq!(split_set_takes_pool_on(top), pool, "{top:?}");
    }
}

/// The stored route's CONDITIONS, end to end (spec F 3.7.9): which
/// runs ask the page cache at all, where each answer sends them, what
/// the route knob overrides, and which runs read deep.
#[cfg(feature = "parallel")]
#[test]
fn the_stored_route_asks_only_where_its_conditions_hold() {
    use crate::residency::Residency::{Cold, Resident, Unknown};
    use std::cell::Cell;
    // Members: (is a directory, method, split).
    let stored = [(true, 0u8, false), (false, 0, false), (false, 0, false)];
    assert!(all_stored_written(true, true, stored.into_iter()));
    // `t` and `p`, a compressed member, ONE split member (a big member in
    // volumes, alone or beside its note), and a set of directories alone
    // are not this rule's.
    assert!(!all_stored_written(false, true, stored.into_iter()));
    assert!(!all_stored_written(
        true,
        true,
        [(false, 0, false), (false, 3, false)].into_iter()
    ));
    assert!(!all_stored_written(
        true,
        true,
        [(false, 0, false), (false, 0, true)].into_iter()
    ));
    assert!(!all_stored_written(
        true,
        true,
        [(false, 0, true)].into_iter()
    ));
    assert!(!all_stored_written(
        true,
        true,
        [(true, 0, false)].into_iter()
    ));
    // A SPLIT SET is: two or more split members, beside whole ones
    // or not, directories aside; but never with a compressed member.
    let split_set = [(true, 0u8, false), (false, 0, true), (false, 0, true)];
    assert!(all_stored_written(true, true, split_set.into_iter()));
    assert!(all_stored_written(
        true,
        true,
        [(false, 0, true), (false, 0, false), (false, 0, true)].into_iter()
    ));
    assert!(!all_stored_written(false, true, split_set.into_iter()));
    // On a part that keeps the pool for a split set (`split_set` false), a
    // split set is not this rule's; a set with no split member
    // and one split member answer as before.
    assert!(!all_stored_written(true, false, split_set.into_iter()));
    assert!(all_stored_written(true, false, stored.into_iter()));
    assert!(!all_stored_written(
        true,
        false,
        [(false, 0, false), (false, 0, true)].into_iter()
    ));
    assert!(!all_stored_written(
        true,
        true,
        [(false, 0, true), (false, 0, true), (false, 3, false)].into_iter()
    ));

    let ask = |stored, clear, solid, cut_off, knob| StoredAsk {
        stored,
        clear,
        solid,
        cut_off,
        knob,
    };
    // (walks, deep) and whether the cache was asked.
    let route = |ask: &StoredAsk, answer: Option<crate::residency::Residency>| {
        let asked = Cell::new(false);
        let (walks, deep, _) = stored_route_for(ask, || {
            asked.set(true);
            // Wholly in memory, wholly out of it, or no answer.
            answer.map(|verdict| match verdict {
                Resident => (Some(1.0), verdict),
                Cold => (Some(0.0), verdict),
                Unknown => (None, verdict),
            })
        });
        ((walks, deep), asked.get())
    };
    let plain = ask(true, true, false, false, PoolKnob::Rule);
    // Not this rule's: the cache is not asked, the route is the pool's.
    let other = ask(false, true, false, false, PoolKnob::Rule);
    assert_eq!(route(&other, Some(Cold)), ((false, false), false));
    // Resident: the pool. Cold: the walk, deep. Unknown: the walk at
    // the shipped depth. No volume name: the walk, not deep.
    assert_eq!(route(&plain, Some(Resident)), ((false, false), true));
    assert_eq!(route(&plain, Some(Cold)), ((true, true), true));
    assert_eq!(route(&plain, Some(Unknown)), ((true, false), true));
    assert_eq!(route(&plain, None), ((true, false), true));
    // An encrypted set walks cold and is never deep; so a solid one.
    let hp = ask(true, false, false, false, PoolKnob::Rule);
    assert_eq!(route(&hp, Some(Cold)), ((true, false), true));
    assert_eq!(route(&hp, Some(Resident)), ((false, false), true));
    let solid = ask(true, true, true, false, PoolKnob::Rule);
    assert_eq!(route(&solid, Some(Cold)), ((true, false), true));
    // One cold stream, which the source's window reads: a cold set that is
    // not solid, clear or encrypted. Never a resident one, one the cache
    // cannot say of, a solid one, the pool forced, or the cut switched off.
    let stream = |ask: &StoredAsk, answer| {
        stored_route_for(ask, || {
            Some(match answer {
                Resident => (Some(1.0), answer),
                Cold => (Some(0.0), answer),
                Unknown => (None, answer),
            })
        })
        .2
    };
    assert!(stream(&plain, Cold));
    assert!(stream(&hp, Cold), "an encrypted set is a stream, not deep");
    assert!(!stream(&hp, Resident) && !stream(&plain, Resident));
    assert!(!stream(&hp, Unknown) && !stream(&plain, Unknown));
    assert!(!stream(&solid, Cold));
    assert!(!stream(
        &ask(true, false, false, false, PoolKnob::Always),
        Cold
    ));
    assert!(stream(
        &ask(true, false, false, false, PoolKnob::Never),
        Cold
    ));
    assert!(!stream(
        &ask(true, false, false, true, PoolKnob::Rule),
        Cold
    ));
    assert!(!stream(&other, Cold));
    assert_eq!(stored_route_for(&plain, || None), (true, false, false));
    // The cut switched off: the cache unasked, the route before (a
    // clear set walks, an encrypted one takes the pool), never deep.
    let off = ask(true, true, false, true, PoolKnob::Rule);
    assert_eq!(route(&off, Some(Resident)), ((true, false), false));
    let off_hp = ask(true, false, false, true, PoolKnob::Rule);
    assert_eq!(route(&off_hp, Some(Cold)), ((false, false), false));
    // The pool forced is never deep; the walk forced still is.
    let forced = ask(true, true, false, false, PoolKnob::Always);
    assert_eq!(route(&forced, Some(Cold)).0, (true, false));
    let walked = ask(true, true, false, false, PoolKnob::Never);
    assert_eq!(route(&walked, Some(Cold)).0, (true, true));

    // RARFAST_POOL wins over the rule, either way.
    assert!(takes_pool_of(PoolKnob::Always, true));
    assert!(!takes_pool_of(PoolKnob::Never, false));
    assert!(takes_pool_of(PoolKnob::Rule, false));
    assert!(!takes_pool_of(PoolKnob::Rule, true));
    // One large stored member beside small ones, in small volumes,
    // walks: the big member beside a sample, an .nfo and an .srt. A member is
    // (is a directory, method, encrypted, has a CRC32, size).
    const G: u64 = 1 << 30;
    const M: u64 = 1 << 20;
    let ask = |extract: bool, small_volumes: bool, blake2sp: bool| LoneAsk {
        extract,
        small_volumes,
        blake2sp,
        floor: LONE_LARGE_SMALL_FLOOR,
    };
    type Fact = (bool, u8, bool, bool, u64);
    let beside = |large: Fact, extra: &[Fact]| {
        let mut members = vec![large];
        members.extend_from_slice(extra);
        members
    };
    let big: Fact = (false, 0, false, true, 12 * G);
    let small: [Fact; 3] = [
        (false, 0, false, true, 64 * M),
        (false, 3, false, true, 6360),
        (true, 0, false, false, 0),
    ];
    let is = |ask: LoneAsk, members: Vec<Fact>| lone_large_stored(ask, members.into_iter());
    // In small volumes, and nowhere else.
    assert_eq!(
        is(ask(true, true, false), beside(big, &small)),
        Some(12 * G)
    );
    assert_eq!(is(ask(true, false, false), beside(big, &small)), None);
    assert_eq!(is(ask(true, false, true), beside(big, &small)), None);
    // `t` and `p` are not asked; a member alone walks without the rule.
    assert_eq!(is(ask(false, true, true), beside(big, &small)), None);
    assert_eq!(is(ask(true, true, true), beside(big, &[])), None);
    assert_eq!(is(ask(true, true, true), beside(big, &small[2..])), None);
    // The rest at a quarter of the large member is taken, a byte over
    // it is not; a second large member is never small.
    let rest = |size: u64| [(false, 0u8, false, true, size)];
    assert!(is(ask(true, true, false), beside(big, &rest(3 * G))).is_some());
    assert!(is(ask(true, true, false), beside(big, &rest(3 * G + 1))).is_none());
    assert!(is(ask(true, true, true), beside(big, &rest(12 * G))).is_none());
    // A compressed set in volumes is written abreast only where the
    // files beside the largest hold more than half of it: a set of many
    // members is, a big member beside its sample is not, nor is a file alone.
    let abreast = |sizes: &[u64]| written_abreast(sizes.iter().copied());
    assert_eq!(WRITTEN_ABREAST_SHARE, 2);
    assert!(abreast(&[G; 8]));
    assert!(abreast(&[G, G]));
    assert!(!abreast(&[8 * G, 64 * M, 6360, 6360]));
    assert!(!abreast(&[8 * G, 4 * G]));
    assert!(abreast(&[8 * G, 4 * G + 1]));
    assert!(abreast(&[8 * G, 2 * G, 2 * G, 1]));
    assert!(!abreast(&[8 * G]));
    assert!(!abreast(&[]));
    // One large COMPRESSED member beside small ones walks as one archive
    // too, by the same share: (is a directory, method, size).
    let lone = |extract: bool, members: &[(bool, u8, u64)]| {
        lone_large_packed(extract, members.iter().copied())
    };
    let extras = [(false, 3u8, 64 * M), (false, 3, 6360), (true, 0, 0)];
    let with = |large: (bool, u8, u64), extra: &[(bool, u8, u64)]| {
        let mut members = vec![large];
        members.extend_from_slice(extra);
        members
    };
    assert!(lone(true, &with((false, 3, 8 * G), &extras)));
    // `t` and `p` are not asked; a member alone walks without the rule;
    // a stored large member is the other rule's.
    assert!(!lone(false, &with((false, 3, 8 * G), &extras)));
    assert!(!lone(true, &with((false, 3, 8 * G), &extras[2..])));
    assert!(!lone(true, &with((false, 0, 8 * G), &extras)));
    // Small files stored beside a compressed large one change nothing.
    assert!(lone(true, &with((false, 5, 8 * G), &[(false, 0, M)])));
    // The rest at half of the large member walks, a byte over it does
    // not; a set of many members and nothing at all do not.
    assert!(lone(true, &with((false, 3, 8 * G), &[(false, 3, 4 * G)])));
    assert!(!lone(
        true,
        &with((false, 3, 8 * G), &[(false, 3, 4 * G + 1)])
    ));
    assert!(!lone(true, &[(false, 3, G); 8]));
    assert!(!lone(true, &[]));
    assert!(!lone(true, &[(false, 3, u64::MAX), (false, 3, u64::MAX)]));
    // The large member compressed or encrypted keeps the route it had.
    let packed: Fact = (false, 3, false, true, 12 * G);
    let locked: Fact = (false, 0, true, true, 12 * G);
    assert!(is(ask(true, true, true), beside(packed, &small)).is_none());
    assert!(is(ask(true, true, true), beside(locked, &small)).is_none());
    // The floor: a member at it is taken, a byte under is not. A
    // gibibyte on Windows, 96 MiB elsewhere.
    let floor = LONE_LARGE_SMALL_FLOOR;
    assert_eq!(floor, if cfg!(windows) { G } else { 96 * M });
    let member = |size: u64| beside((false, 0, false, true, size), &rest(M));
    assert_eq!(is(ask(true, true, false), member(floor)), Some(floor));
    assert_eq!(is(ask(true, true, false), member(floor - 1)), None);
    // A BLAKE2sp member (no CRC32): only where the system takes it.
    let blake = beside((false, 0, false, false, 12 * G), &small);
    assert!(is(ask(true, true, false), blake.clone()).is_none());
    assert!(is(ask(true, true, true), blake).is_some());
    assert_eq!(LONE_LARGE_BLAKE2SP, cfg!(target_os = "linux"));
    // A small member that is encrypted or compressed changes nothing.
    let odd: [Fact; 1] = [(false, 5, true, false, M)];
    assert!(is(ask(true, true, false), beside(big, &odd)).is_some());
    // Nothing selected, and sizes that would overflow a sum.
    assert!(is(ask(true, true, true), vec![]).is_none());
    let huge: Fact = (false, 0, false, true, u64::MAX);
    assert!(is(ask(true, true, true), vec![huge, huge]).is_none());

    // A lone member (a breadth of one) walks whatever the route says;
    // so `p`, a solid set and an undispatched split member.
    assert!(pool_drives(false, false, false, 2, true));
    assert!(!pool_drives(false, false, false, 1, true));
    assert!(!pool_drives(true, false, false, 8, true));
    assert!(!pool_drives(false, true, false, 8, true));
    assert!(!pool_drives(false, false, true, 8, true));
    assert!(!pool_drives(false, false, false, 8, false));
    // Whatever else is true of it: a lone member never reaches the branch
    // that arms create ahead's spawned helpers (`Run::drive`), so a serial
    // pool cannot strand one (FROM-STUDIO 518 C's precondition).
    for print in [false, true] {
        for solid in [false, true] {
            for split in [false, true] {
                for takes in [false, true] {
                    assert!(!pool_drives(print, solid, split, 1, takes));
                }
            }
        }
    }

    // The read-ahead: deep is 256 MiB in place of the 8; a stated
    // `-mm` keeps what it had, and so does a run that is not deep (a
    // solid volume, an encrypted member, a warm archive); and it never
    // passes half the working limit.
    let (shipped, limit) = (EXTRACT_READ_AHEAD, 512u64 << 20);
    assert_eq!(stored_read_ahead(shipped, true, false, limit), 256 << 20);
    assert_eq!(stored_read_ahead(shipped, true, true, limit), shipped);
    assert_eq!(stored_read_ahead(shipped, false, false, limit), shipped);
    assert_eq!(stored_read_ahead(shipped, true, false, 128 << 20), 64 << 20);
    assert_eq!(stored_read_ahead(shipped, true, false, 8 << 20), shipped);
}

/// THE SESSION A HEADER ENCRYPTED SET IS READ THROUGH TAKES THE WALK'S
/// READ-AHEAD for the command. The session is opened before any volume is
/// read and kept for a set whose headers are encrypted (`run`), so `t` or
/// `p` of a stored member under `-hp` reads at what is stated at the open:
/// it must be what the walk states for the same command of the same
/// member under `-p` (`Run::walk`: [`test_read_ahead`], 32 MiB on macOS),
/// or the header encrypted set gets a fraction of the wide read's readers
/// (counted on an M5 Ultra, 12 Oct 2026: `t` of a stored gibibyte in 50 MB
/// volumes, four readers and 0.047 s under `-hp` against 0.027 s under
/// `-p`). An extract keeps its own depth, and a stated memory cap keeps
/// the engine's derivation for every command.
#[test]
fn the_kept_session_reads_at_the_walks_depth() {
    let default = 4 << 20;
    for flat in [false, true] {
        let mode = Mode::Extract { flat };
        assert_eq!(
            session_read_ahead(mode, false, default),
            extract_read_ahead()
        );
        assert_eq!(session_read_ahead(mode, true, default), default, "capped");
    }
    for mode in [Mode::Test, Mode::Print] {
        assert_eq!(
            session_read_ahead(mode, false, default),
            test_read_ahead(default),
            "the walk's depth for this command"
        );
        assert_eq!(session_read_ahead(mode, true, default), default, "capped");
    }
    #[cfg(target_os = "macos")]
    assert_eq!(session_read_ahead(Mode::Test, false, default), 32 << 20);
}

/// A read no wider than sixteen lanes keeps the shipped read-ahead; a
/// wider one takes 256 KiB a lane; and a working limit whose
/// sixty-fourth is under that holds it, never below the shipped.
#[test]
fn the_wide_test_read_ahead_is_a_piece_a_lane_inside_the_limit() {
    let shipped = 4 << 20;
    let roomy = 48 << 30;
    for width in [1, 2, 8, 16] {
        assert_eq!(wide_test_read_ahead(shipped, width, roomy), shipped);
    }
    assert_eq!(wide_test_read_ahead(shipped, 32, roomy), 8 << 20);
    assert_eq!(wide_test_read_ahead(shipped, 96, roomy), 24 << 20);
    // The floor of the default budget, 512 MiB: 8 MiB at the most.
    assert_eq!(wide_test_read_ahead(shipped, 96, 512 << 20), 8 << 20);
    // A capped environment: the shipped read-ahead and no less.
    assert_eq!(wide_test_read_ahead(shipped, 96, 128 << 20), shipped);
    assert_eq!(wide_test_read_ahead(shipped, 96, 0), shipped);
    // A deeper shipped read-ahead (macOS) is never made shallower.
    assert_eq!(wide_test_read_ahead(32 << 20, 20, roomy), 32 << 20);
    assert_eq!(wide_test_read_ahead(shipped, usize::MAX, roomy), roomy / 64);
}

/// The deeper read-ahead is for large stored CRC32 members: one member
/// of the wide read's own that is smaller, or hashed with BLAKE2sp,
/// keeps the whole command at the shipped read-ahead; members under
/// the wide read's floor, directories and compressed members do not
/// count either way.
#[test]
fn the_tp_window_is_for_large_stored_crc32_members() {
    const GIB: u64 = 1 << 30;
    let big = rule_member(12 * GIB, 0, false, true, false);
    let four = rule_member(WIDE_TEST_MEMBER, 0, false, true, false);
    let under = rule_member(WIDE_TEST_MEMBER - 1, 0, false, true, false);
    let member = rule_member(64 << 20, 0, false, true, false);
    let note = rule_member(WIDE_READ_FLOOR - 1, 0, false, true, false);
    let dir = rule_member(0, 0, false, false, true);
    let packed = rule_member(12 * GIB, 3, false, true, false);
    let blake = rule_member(12 * GIB, 0, false, false, false);
    let ciphered = rule_member(12 * GIB, 0, true, true, false);
    let of = |members: &[&Member]| tp_window_members(members.iter().copied());
    assert!(of(&[&big]));
    assert!(of(&[&four]));
    assert!(of(&[&big, &four, &note, &dir, &packed]));
    assert!(of(&[&ciphered]));
    assert!(!of(&[&under]));
    assert!(!of(&[&big, &member]));
    assert!(!of(&[&member, &member]));
    assert!(!of(&[&blake]));
    assert!(!of(&[&big, &blake]));
    assert!(!of(&[&packed]));
    assert!(!of(&[&note, &dir]));
    assert!(!of(&[]));
}

/// The knob's names set the rule, and anything else leaves what ships.
#[test]
fn the_tp_window_knob_takes_its_names_and_nothing_else_moves_the_default() {
    for shipped in [TpWindow::Off, TpWindow::Rule] {
        for unsaid in [None, Some(""), Some("yes"), Some("2"), Some("fast")] {
            assert_eq!(tp_window_of(unsaid, shipped), shipped, "{unsaid:?}");
        }
        for off in ["0", "off", " OFF "] {
            assert_eq!(tp_window_of(Some(off), shipped), TpWindow::Off);
        }
        for on in ["1", "on", "ON", " width ", "Width"] {
            assert_eq!(tp_window_of(Some(on), shipped), TpWindow::Rule);
        }
        assert_eq!(tp_window_of(Some("Always"), shipped), TpWindow::Always);
    }
}

/// Room is reserved for a member's output file ahead of the write
/// position WITHOUT moving the file's length, and what is written is
/// all that is ever there.
///
/// Both halves matter. Without the reservation the file system extends
/// the file once per 64 KiB piece, which is about a third of an
/// extraction's write cost. And the LENGTH stays the bytes written at
/// every instant: until 11 Oct 2026 the reservation moved the length
/// ahead (8 MiB at a time) and `drop` put it back, so a run that was
/// killed mid member (an interrupt, a loss of power) left a file
/// longer than its bytes, zeros to the next step, and `-kb` kept it.
#[test]
fn room_is_reserved_ahead_and_the_length_is_only_what_arrived() {
    let path = std::env::temp_dir().join(format!(
        "rarfast-reserve-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = fs::remove_file(&path);
    // A member on the ROOM KEPT side of the bound, stated by the bound's
    // own name: room is kept only where the seam does not write the
    // member ([`output::RESERVE_UNDER`], which is where the seam takes a
    // stored member on Apple systems), so a size written here as a number
    // stops meaning "a member that keeps room" the day that floor moves
    // (it did: 32 MiB was this test's size and became the floor itself).
    let declared = output::RESERVE_UNDER.map_or(32 << 20, |from| (from / 2).min(32 << 20));
    assert!(
        declared >= 2 * RESERVE_STEP,
        "the member must outlast a step"
    );
    let piece = vec![7u8; 64 << 10];
    let mut file = TimedFile {
        file: fs::File::create(&path).unwrap(),
        mtime: None,
        mode: None,
        declared,
        written: 0,
        reserved: 0,
        staged: None,
        shut: false,
        named: None,
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        behind: None,
    };
    for _ in 0..3 {
        file.write_all(&piece).unwrap();
    }
    assert_eq!(file.written, 3 * piece.len() as u64);
    assert!(
        file.reserved >= RESERVE_STEP,
        "nothing was reserved ahead: {}",
        file.reserved
    );
    assert!(
        file.reserved <= declared,
        "reserved {} past the declared {declared}",
        file.reserved
    );
    // The length is the bytes written, with the reservation standing.
    assert_eq!(
        fs::metadata(&path).unwrap().len(),
        3 * piece.len() as u64,
        "the reservation moved the file's length"
    );
    drop(file);
    assert_eq!(
        fs::metadata(&path).unwrap().len(),
        3 * piece.len() as u64,
        "the reservation outlived the bytes"
    );
    assert_eq!(fs::read(&path).unwrap(), piece.repeat(3));
    let _ = fs::remove_file(&path);
}

/// THE UNBUFFERED WRITER ([`unbuffered`]): its file opened ONCE with
/// the target's past-the-cache flag, as the extract opens a big
/// member's. Three shapes, in one test because what is forced is one
/// static: as shipped, the direct write of a block failing, and the
/// padded tail's failing, each of which must fall back to a cached
/// handle and still leave exactly the member. Each under two piece
/// shapes: 64 KiB pieces from an ordinary allocation (staged), and 4 MiB
/// pieces on a 4 KiB boundary (the seam's stored slabs, written straight
/// from the buffer).
///
/// COHERENCY: a cached reader opened before the first byte reads inside
/// the reservation ahead of the writes after every piece, so its cache
/// holds zeroes where the unbuffered handle then writes; after close it
/// and a fresh reader must read the member back exactly. The member is
/// 3 blocks, 2 sectors and 1,234 bytes, so its tail and its last whole
/// block meet mid-sector.
///
/// Skipped, saying so, on a target with no such flag, and where neither
/// the temp dir nor the crate's own dir takes a direct open (a tmpfs).
#[test]
fn the_unbuffered_writer_leaves_exactly_the_member_and_falls_back_cleanly() {
    use std::io::{Read, Seek, SeekFrom};
    use unbuffered::Forced;
    // One test at a time may force a failure (`unbuffered::TEST_SERIAL`).
    let _serial = unbuffered::TEST_SERIAL
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if !unbuffered::ABLE {
        eprintln!("no past-the-cache open on this target: skipped");
        return;
    }
    let len = 3 * (4 << 20) + 2 * 4096 + 1234;
    let data: Vec<u8> = (0..len as u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    // The same bytes on a 4 KiB boundary, for the straight-from-buffer
    // shape.
    let mut aligned_store = vec![0u8; len + 4096];
    let skip = aligned_store.as_ptr().align_offset(4096);
    aligned_store[skip..skip + len].copy_from_slice(&data);
    let aligned = &aligned_store[skip..skip + len];
    let dirs = [std::env::temp_dir(), std::env::current_dir().unwrap()];
    for (depth, shape, piece_len, bytes) in [0, 2].into_iter().flat_map(|depth| {
        [
            (depth, "staged", 64 << 10, &data[..]),
            (depth, "straight", 4 << 20, aligned),
        ]
    }) {
        *unbuffered::TEST_DEPTH.lock().unwrap() = Some(depth);
        for forced in [Forced::None, Forced::Write, Forced::Tail] {
            *unbuffered::TEST_FORCED.lock().unwrap() = forced;
            let name = format!(
                "rarfast-unbuffered-{depth}-{shape}-{forced:?}-{}",
                std::process::id()
            );
            let mut opened = None;
            for dir in &dirs {
                let path = dir.join(&name);
                let _ = fs::remove_file(&path);
                if let Ok(Some(crate::safepath::Created { file, .. })) =
                    crate::safepath::make_member_file_with(
                        &path,
                        crate::safepath::IfOutputExists::Keep,
                        0o666,
                        unbuffered::FLAG,
                    )
                {
                    if unbuffered::take_direct(&file) {
                        opened = Some((path, file));
                        break;
                    }
                }
            }
            let Some((path, own)) = opened else {
                eprintln!("no directory here takes a direct open: skipped");
                *unbuffered::TEST_FORCED.lock().unwrap() = Forced::None;
                return;
            };
            let mut early = fs::File::open(&path).unwrap();
            let staged = unbuffered::Staged::new(&path, &own, unbuffered::Member::Stored);
            let mut file = TimedFile {
                file: own,
                mtime: None,
                mode: None,
                declared: len as u64,
                written: 0,
                reserved: 0,
                staged: Some(staged),
                shut: false,
                named: None,
                #[cfg(all(target_os = "linux", target_env = "gnu"))]
                behind: None,
            };
            for piece in bytes.chunks(piece_len) {
                file.write_all(piece).unwrap();
                let ahead = file.written.min(file.reserved.saturating_sub(4096));
                if ahead > 0 {
                    let mut probe = [0u8; 16];
                    early.seek(SeekFrom::Start(ahead)).unwrap();
                    let _ = early.read(&mut probe).unwrap();
                }
            }
            if forced == Forced::Write {
                assert!(
                    file.staged.is_none(),
                    "{shape}: the forced write did not fall back"
                );
            }
            drop(file);
            let read_all = |f: &mut fs::File| {
                let mut got = Vec::new();
                f.seek(SeekFrom::Start(0)).unwrap();
                f.read_to_end(&mut got).unwrap();
                got
            };
            assert!(
                read_all(&mut early) == data,
                "{shape} {forced:?}: the early reader read stale bytes"
            );
            let mut fresh = fs::File::open(&path).unwrap();
            assert!(
                read_all(&mut fresh) == data,
                "{shape} {forced:?}: a fresh reader read other bytes"
            );
            assert_eq!(
                fs::metadata(&path).unwrap().len(),
                len as u64,
                "{shape} {forced:?}: length"
            );
            drop((early, fresh));
            let _ = fs::remove_file(&path);
        }
    }
    *unbuffered::TEST_FORCED.lock().unwrap() = Forced::None;
    *unbuffered::TEST_DEPTH.lock().unwrap() = None;
}

/// A member no bigger than the piece it arrives in asks the file
/// system for nothing at all.
#[test]
fn a_small_member_reserves_nothing() {
    let path = std::env::temp_dir().join(format!(
        "rarfast-reserve-small-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = fs::remove_file(&path);
    let mut file = TimedFile {
        file: fs::File::create(&path).unwrap(),
        mtime: None,
        mode: None,
        declared: 40,
        written: 0,
        reserved: 0,
        staged: None,
        shut: false,
        named: None,
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        behind: None,
    };
    file.write_all(&[1u8; 40]).unwrap();
    assert_eq!(file.reserved, 0);
    drop(file);
    assert_eq!(fs::metadata(&path).unwrap().len(), 40);
    let _ = fs::remove_file(&path);
}

/// `.part` is looked for in the name AS IT IS, not in a lowercased copy
/// whose byte offsets need not be the name's: U+212A KELVIN SIGN is three
/// bytes and lowercases to a one-byte `k`, U+0130 grows from two bytes to
/// three. Five Kelvin signs before `.part1` put the copy's offset inside
/// the fifth, and slicing the name there panicked; the reference tests
/// such a set to "All OK" (unrar 7.23, macOS, 4 Oct 2026).
#[test]
fn a_volume_name_whose_lowercase_has_another_length_is_stepped() {
    let kelvin = "\u{212a}\u{212a}\u{212a}\u{212a}\u{212a}\u{65e5}";
    assert_eq!(
        next_volume_name(&format!("{kelvin}.part1.rar")),
        Some(format!("{kelvin}.part2.rar"))
    );
    assert_eq!(
        first_volume_name(&format!("{kelvin}.part3.rar")),
        Some(format!("{kelvin}.part1.rar"))
    );
    // The copy is LONGER here, so its offset fell past the real one and
    // the digits were not found: a wrong next name on a complete set.
    let dotted = "\u{130}\u{130}\u{130}";
    assert_eq!(
        next_volume_name(&format!("{dotted}.PART09.rar")),
        Some(format!("{dotted}.PART10.rar"))
    );
    assert_eq!(
        first_volume_name(&format!("{dotted}.Part09.rar")),
        Some(format!("{dotted}.Part01.rar"))
    );
}

/// A part number with no successor in 64 bits names no next volume: it
/// overflowed, a panic in a checked build and `part0` in a release one.
#[test]
fn a_part_number_at_the_top_of_its_range_has_no_next_volume() {
    assert_eq!(next_volume_name("arc.part18446744073709551615.rar"), None);
    assert_eq!(next_volume_name("arc.r18446744073709551615"), None);
    assert_eq!(
        next_volume_name("arc.part18446744073709551614.rar").as_deref(),
        Some("arc.part18446744073709551615.rar")
    );
}

#[test]
fn the_next_volume_follows_both_naming_schemes() {
    assert_eq!(
        next_volume_name("arc.part1.rar").as_deref(),
        Some("arc.part2.rar")
    );
    assert_eq!(
        next_volume_name("arc.part09.rar").as_deref(),
        Some("arc.part10.rar")
    );
    assert_eq!(next_volume_name("arc.rar").as_deref(), Some("arc.r00"));
    assert_eq!(next_volume_name("arc.r00").as_deref(), Some("arc.r01"));
}

#[test]
fn a_file_line_and_a_directory_line_end_in_the_columns_the_capture_recorded() {
    // The reference's own two shapes: `Creating    out` runs to
    // column 70 before `OK`, and a file name runs to 73 before the
    // percentage field. Reading one width off the other is the
    // mistake this pins.
    assert_eq!(pad_to("Creating    out", DIR_NAME_COLUMN).len(), 70);
    assert_eq!(
        pad_to("Extracting  out/text.txt", FILE_NAME_COLUMN).len(),
        73
    );
}

#[test]
fn a_complaint_pads_the_name_to_the_reference_s_column() {
    assert_eq!(pad_to("text.txt", COMPLAINT_COLUMN).len(), 21);
}

#[test]
fn the_selection_s_set_and_its_vector_cannot_disagree() {
    // The whole reason `Selected` exists: `begin_member` probes the
    // set once per member, and the passes before the walk iterate
    // the vector for archive order. If the two ever answered
    // differently, a selected member would be silently skipped, or
    // an unselected one extracted. They are one construction, and
    // this pins that they agree on every index in range and on
    // every index out of it.
    for order in [
        vec![],
        vec![0],
        vec![0, 1, 2, 3],
        // Selections are sparse far more often than they are dense:
        // a mask, an `-x`, a time filter.
        vec![1, 4, 9, 16, 25],
        vec![7],
        (0..64).filter(|index| index % 3 == 0).collect::<Vec<_>>(),
    ] {
        let selected = Selected::new(order.clone());
        assert_eq!(selected.len(), order.len());
        assert_eq!(selected.is_empty(), order.is_empty());
        assert_eq!(selected.iter().copied().collect::<Vec<_>>(), order);
        for (position, index) in order.iter().enumerate() {
            assert_eq!(selected.at(position), *index);
        }
        for index in 0..80 {
            assert_eq!(
                selected.contains(index),
                order.contains(&index),
                "index {index} of {order:?}"
            );
        }
    }
}

#[test]
fn an_index_set_answers_as_a_hash_set_would() {
    for bound in [0, 1, 63, 64, 65, 200] {
        let mut set = IndexSet::with_bound(bound);
        let mut model = HashSet::new();
        // Inside the bound, on the word edges, and past it.
        for index in [0, 1, 62, 63, 64, 65, 127, 128, 199, 200, 5_000, usize::MAX] {
            set.insert(index);
            model.insert(index);
            for probe in [
                0,
                2,
                63,
                64,
                66,
                128,
                199,
                201,
                5_000,
                5_001,
                usize::MAX - 1,
                usize::MAX,
            ] {
                assert_eq!(
                    set.contains(probe),
                    model.contains(&probe),
                    "bound {bound} probe {probe}"
                );
            }
        }
    }
}

#[test]
fn a_name_wider_than_the_column_is_not_truncated() {
    let long = "a".repeat(90);
    assert_eq!(pad_to(&long, FILE_NAME_COLUMN).len(), 90);
}

#[test]
fn the_minimum_gap_wins_even_short_of_the_column() {
    // Measured off the reference (a small x86-64 VPS, unrar 7.23,
    // 27 Sep 2026): a file line's five-space gap already shows at
    // real widths (verb included) of 69, 70, 71 and 72 against the
    // 73-column field, four short of the column and closer, not
    // only at or past it; 62 and 66 still pad out to the column, as
    // does 68, the last width the five-space gap still fits inside.
    for width in [62, 66, 68] {
        let text = "a".repeat(width);
        assert_eq!(
            separated(&text, FILE_NAME_COLUMN, 5).len(),
            FILE_NAME_COLUMN,
            "width {width} should still pad to the column"
        );
    }
    for width in [69, 70, 71, 72, FILE_NAME_COLUMN, FILE_NAME_COLUMN + 20] {
        let text = "a".repeat(width);
        assert_eq!(
            separated(&text, FILE_NAME_COLUMN, 5).len(),
            width + 5,
            "width {width} should fall back to the five-space gap"
        );
    }
    // The same shape holds for a directory line's two-space gap
    // against its 70-column field: 68 still pads to the column, 69
    // and past it fall back to the fixed gap.
    assert_eq!(
        separated(&"a".repeat(68), DIR_NAME_COLUMN, 2).len(),
        DIR_NAME_COLUMN
    );
    for width in [69, DIR_NAME_COLUMN, DIR_NAME_COLUMN + 20] {
        assert_eq!(
            separated(&"a".repeat(width), DIR_NAME_COLUMN, 2).len(),
            width + 2
        );
    }
}

/// What all held members may declare at once: 64 MiB, or an eighth of a
/// named `-mm` where that is less, so the hold is a fixed small part of
/// the working limit however many members are open.
#[test]
fn the_hold_is_bounded_in_all_and_follows_a_named_limit() {
    assert_eq!(output::hold_total(None), 64 << 20);
    assert_eq!(output::hold_total(Some(8 << 20)), 1 << 20);
    assert_eq!(output::hold_total(Some(128 << 20)), 16 << 20);
    assert_eq!(output::hold_total(Some(u64::MAX)), 64 << 20);
    // One member's bound is under the default total.
    assert!(output::HOLD_BOUND <= output::hold_total(None));
}

/// Which step the reservation takes on each system in a shipped build:
/// DOUBLING (a step of 0) on Windows and on Apple systems, where the
/// call that keeps room costs enough that one every 8 MiB shows (about
/// 4 percent of a 512 MiB extract on APFS, counted 11 Oct 2026; 1,536
/// calls for a 12 GiB member on NTFS); 8 MiB steps elsewhere, where the
/// large rows are level with them.
#[cfg(not(feature = "reserve-knob"))]
#[test]
fn the_reservation_doubles_where_its_call_is_dear() {
    let doubling = cfg!(any(windows, target_vendor = "apple"));
    assert_eq!(output::SHIPPED_STEP == 0, doubling);
    if !doubling {
        assert_eq!(output::SHIPPED_STEP, RESERVE_STEP);
    }
}

/// ROOM IS KEPT FOR EVERY MEMBER UNDER A GIBIBYTE, however many are
/// written at once: on Apple systems a member has no room kept only from
/// the size at which the seam takes a member of every kind on its size
/// alone ([`route::SEAM_TAKES_ANY_FROM`]), never from the lower size at
/// which it takes a clear stored member under a CRC32
/// ([`route::SEAM_TAKES_FROM`]).
///
/// The bound was tied to that lower name, and when the seam's floor for
/// such a member went from a gibibyte to 32 MiB every member DECLARING 32
/// MiB or more lost its room, whichever way it was written: sixteen
/// stored members of 128 MiB extracted at once read 1.18 times slower at
/// eight threads, 1.51 at sixteen and 1.63 at the default width of an M5
/// Ultra than with room kept, on three times the system CPU (K=7, 13 Oct
/// 2026), where one such member alone read level either way. This row
/// passed while that happened, because it asked only that the two names
/// were equal. It asks now for the property: a member of 128 MiB keeps
/// its room at any width, and the bound is no lower than a gibibyte.
/// Everywhere else, and in a build with no seam, there is no bound; and
/// at a read width of one the kill row below pins that room is kept at
/// every size.
#[cfg(not(feature = "reserve-knob"))]
#[test]
fn the_reserve_stops_exactly_where_the_seam_takes_the_member() {
    #[cfg(all(target_vendor = "apple", feature = "parallel"))]
    {
        let from = output::RESERVE_UNDER.expect("a bound on Apple systems");
        assert!(
            from > 128 << 20,
            "a member of 128 MiB has no room kept: the bound is {from}"
        );
        assert_eq!(from, route::SEAM_TAKES_ANY_FROM);
        assert!(route::SEAM_TAKES_FROM <= from);
    }
    #[cfg(not(all(target_vendor = "apple", feature = "parallel")))]
    assert_eq!(output::RESERVE_UNDER, None);
}

/// WHAT A KILL OUTRIGHT LEAVES, on both sides of [`output::RESERVE_UNDER`]
/// and for a member of no declared size: a file of exactly the bytes that
/// were written, whether room was being kept for it or not.
///
/// The writer is this test binary run again as a child, which writes
/// three pieces to a member declaring the size it is told, says what it
/// had reserved, and kills itself with `SIGKILL` with the file open: no
/// `drop`, no close of its own. The size is only a number here (nothing
/// is ever reserved further ahead than what has been written and a
/// step), so a 4 GiB declaration costs what a small one does.
///
/// It also pins WHICH side reserved: under the size, to its last byte,
/// room was kept; from it, and with no declared size, none was asked for.
/// At a stated read width of one room was kept at every declared size.
#[cfg(all(unix, not(feature = "reserve-knob")))]
#[test]
fn a_kill_outright_leaves_the_bytes_written_on_both_sides_of_the_size() {
    use std::os::unix::process::ExitStatusExt;
    const CHILD: &str = "RARFAST_TEST_KILLED_WRITER";
    let piece = vec![7u8; 64 << 10];
    if let Ok(job) = std::env::var(CHILD) {
        let mut job = job.splitn(3, ':');
        let (declared, width, path) = (
            job.next().unwrap(),
            job.next().unwrap(),
            job.next().unwrap(),
        );
        output::state_read_width(width.parse().unwrap());
        let mut file = TimedFile {
            file: fs::File::create(path).unwrap(),
            mtime: None,
            mode: None,
            declared: declared.parse().unwrap(),
            written: 0,
            reserved: 0,
            staged: None,
            shut: false,
            named: None,
            #[cfg(all(target_os = "linux", target_env = "gnu"))]
            behind: None,
        };
        for _ in 0..3 {
            file.write_all(&piece).unwrap();
        }
        fs::write(format!("{path}.reserved"), file.reserved.to_string()).unwrap();
        // SAFETY: a plain system call that takes no pointer; it ends this
        // process, which is the point.
        #[allow(unsafe_code)]
        unsafe {
            libc::kill(libc::getpid(), libc::SIGKILL);
        }
        unreachable!("the writer outlived its own kill");
    }
    // Both sides of the bound where a system has one, and of the same
    // size where it has none. Which systems have one is the row above's
    // to pin.
    let at = output::RESERVE_UNDER.unwrap_or(1 << 30);
    let everywhere = output::RESERVE_UNDER.is_none();
    // The width is the read width the run states: at two or more the
    // seam can take a member of the size, at one it cannot, and a member
    // the sequential walk writes keeps room at every size.
    let rows = [
        ("under", at / 2, 2, true),
        ("last under", at - 1, 2, true),
        ("at", at, 2, everywhere),
        ("far", 4 << 30, 2, everywhere),
        ("unknown", 0, 2, false),
        ("under at one thread", at / 2, 1, true),
        ("at at one thread", at, 1, true),
        ("far at one thread", 4 << 30, 1, true),
        ("unknown at one thread", 0, 1, false),
    ];
    for (name, declared, width, keeps) in rows {
        let path = std::env::temp_dir().join(format!(
            "rarfast-killed-writer-{}-{name}",
            std::process::id()
        ));
        let note = format!("{}.reserved", path.display());
        let _ = fs::remove_file(&path);
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "dialect::unrar::extract::tests::a_kill_outright_leaves_the_bytes_written_on_both_sides_of_the_size",
                "--nocapture",
            ])
            .env(CHILD, format!("{declared}:{width}:{}", path.display()))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "{name}: the writer was not killed: {status:?}"
        );
        let reserved: u64 = fs::read_to_string(&note).unwrap().parse().unwrap();
        assert_eq!(
            reserved > 0,
            keeps,
            "{name}: a member declaring {declared} at a width of {width} had {reserved} reserved"
        );
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            3 * piece.len() as u64,
            "{name}: a kill left a file that is not its bytes"
        );
        assert_eq!(fs::read(&path).unwrap(), piece.repeat(3), "{name}");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&note);
    }
}

/// ONE STORED MEMBER ALONE, IN MEMORY, is read wide (`lone_wide_stored`,
/// release blocker 4): exactly one file, stored, clear, under a CRC32,
/// whole, from the system's floor (`LONE_WIDE_FROM`: the wide read's 16
/// MiB, and 32 MiB on Windows and Linux) to under its ceiling
/// (`LONE_WIDE_UNDER`: a gibibyte, and 128 MiB on Linux), in one volume
/// that is not solid and is in memory (Windows and Linux ask no cache, so
/// their walk states this term from the window guard alone), for `x` and
/// `e` with no `-mt1` and
/// no `-mm`. A member is (is a directory, method, encrypted, has a CRC32,
/// split, size), at the system's floor unless a case names its size.
/// Pure: no width, no memory.
#[cfg(feature = "parallel")]
#[test]
fn a_lone_stored_member_in_memory_is_read_wide() {
    const M: u64 = 1 << 20;
    type Fact = (bool, u8, bool, bool, bool, u64);
    let ask = LoneWideAsk {
        extract: true,
        on: true,
        one_plain_volume: true,
        in_memory: true,
        stated: false,
    };
    let is = |ask: LoneWideAsk, members: &[Fact]| lone_wide_stored(ask, members.iter().copied());
    let lone: Fact = (false, 0, false, true, false, LONE_WIDE_FROM);
    let dir: Fact = (true, 0, false, false, false, 0);
    assert!(is(ask, &[lone]));
    assert!(is(ask, &[dir, lone, dir]));
    // Each condition of the command and the set, alone, refuses it.
    for refused in [
        LoneWideAsk {
            extract: false,
            ..ask
        },
        LoneWideAsk { on: false, ..ask },
        LoneWideAsk {
            one_plain_volume: false,
            ..ask
        },
        LoneWideAsk {
            in_memory: false,
            ..ask
        },
        LoneWideAsk {
            stated: true,
            ..ask
        },
    ] {
        assert!(!is(refused, &[lone]));
    }
    // Each fact of the member, alone, refuses it.
    for member in [
        (false, 3, false, true, false, LONE_WIDE_FROM),
        (false, 0, true, true, false, LONE_WIDE_FROM),
        (false, 0, false, false, false, LONE_WIDE_FROM),
        (false, 0, false, true, true, LONE_WIDE_FROM),
    ] {
        assert!(!is(ask, &[member]));
    }
    // The floor is the system's (the wide read's 16 MiB, 32 MiB on
    // Windows and Linux), the ceiling too (a gibibyte, 128 MiB on Linux),
    // both by the member's declared size: a byte under the floor is not
    // taken, nor is the ceiling itself; a member at the wide read's floor
    // is taken only where that is the system's floor.
    let linux = cfg!(target_os = "linux");
    assert_eq!(WIDE_READ_FLOOR, 16 * M);
    assert_eq!(
        LONE_WIDE_FROM,
        if cfg!(windows) || linux {
            32 * M
        } else {
            16 * M
        }
    );
    assert_eq!(LONE_WIDE_UNDER, if linux { 128 * M } else { 1 << 30 });
    let sized = |size: u64| [(false, 0u8, false, true, false, size)];
    assert!(!is(ask, &sized(LONE_WIDE_FROM - 1)));
    assert!(is(ask, &sized(LONE_WIDE_FROM)));
    assert_eq!(is(ask, &sized(WIDE_READ_FLOOR)), !cfg!(windows) && !linux);
    assert!(is(ask, &sized(64 * M)));
    assert!(is(ask, &sized(LONE_WIDE_UNDER - 1)));
    assert!(!is(ask, &sized(LONE_WIDE_UNDER)));
    // Two files, or none, are not a member alone.
    let note: Fact = (false, 0, false, true, false, 14);
    assert!(!is(ask, &[lone, note]));
    assert!(!is(ask, &[lone, lone]));
    assert!(!is(ask, &[]));
    assert!(!is(ask, &[dir]));
    // Shipped on macOS, Windows and Linux, at four readers of 1 MiB; the
    // knob's words.
    assert_eq!(
        LONE_WIDE,
        cfg!(any(target_os = "macos", windows, target_os = "linux"))
    );
    let shipped = if LONE_WIDE {
        LoneWide::Rule
    } else {
        LoneWide::Off
    };
    assert_eq!(lone_wide_of(None), shipped);
    assert_eq!(lone_wide_of(Some(" ON ")), LoneWide::Rule);
    assert_eq!(lone_wide_of(Some("1")), LoneWide::Rule);
    assert_eq!(lone_wide_of(Some("off")), LoneWide::Off);
    assert_eq!(lone_wide_of(Some("0")), LoneWide::Off);
    assert_eq!(lone_wide_of(Some("Any")), LoneWide::Any);
    assert_eq!(lone_wide_of(Some("wide")), shipped);
    assert_eq!(LONE_WIDE_READ_AHEAD, 4 << 20);
}

/// THE WINDOWS AND LINUX ARMS of `lone_wide_stored`: shipped on macOS,
/// Windows and Linux and nowhere else; on Windows from 32 MiB to a
/// gibibyte and on Linux from 32 MiB to under 128 MiB, each with no page
/// cache term (neither samples it on the stored route) and the cold window
/// guard as it is; on macOS from the wide read's floor to a gibibyte and
/// only where the cache holds the archive, as before. Every system's
/// answers are read here whatever the build's own. Pure: no width, no
/// memory.
#[cfg(feature = "parallel")]
#[test]
fn the_lone_wide_rule_per_system() {
    const M: u64 = 1 << 20;
    // (macOS, Windows, Linux) for each system: macOS, Windows, Linux and
    // any other.
    let systems = [
        ("macOS", true, false, false),
        ("Windows", false, true, false),
        ("Linux", false, false, true),
        ("other", false, false, false),
    ];
    // (ships, floor, ceiling, asks the cache), in that order of systems.
    let want = [
        (true, WIDE_READ_FLOOR, 1 << 30, true),
        (true, 32 * M, 1 << 30, false),
        (true, 32 * M, 128 * M, false),
        (false, WIDE_READ_FLOOR, 1 << 30, true),
    ];
    for ((name, macos, windows, linux), want) in systems.into_iter().zip(want) {
        let got = (
            lone_wide_ships_on(macos, windows, linux),
            lone_wide_from_on(windows, linux),
            lone_wide_under_on(linux),
            lone_wide_asks_cache_on(windows, linux),
        );
        assert_eq!(got, want, "{name}");
    }
    // THE LINUX EDGES, by the member's declared size against the Linux
    // floor and ceiling (the rule's own range, `lone_wide_stored`): just
    // under 32 MiB is not taken, 32 MiB is, 64 MiB is, a byte under 128
    // MiB is, and 128 MiB is not; 16 MiB, the wide read's floor, is not.
    let linux = lone_wide_from_on(false, true)..lone_wide_under_on(true);
    for (size, taken) in [
        (16 * M, false),
        (32 * M - 1, false),
        (32 * M, true),
        (64 * M, true),
        (128 * M - 1, true),
        (128 * M, false),
    ] {
        assert_eq!(linux.contains(&size), taken, "Linux, {size} bytes");
    }
    // What this build ships is its own system's answer.
    let (macos, windows, linux) = (
        cfg!(target_os = "macos"),
        cfg!(windows),
        cfg!(target_os = "linux"),
    );
    assert_eq!(LONE_WIDE, lone_wide_ships_on(macos, windows, linux));
    assert_eq!(LONE_WIDE_FROM, lone_wide_from_on(windows, linux));
    assert_eq!(LONE_WIDE_UNDER, lone_wide_under_on(linux));
    assert_eq!(
        LONE_WIDE_ASKS_CACHE,
        lone_wide_asks_cache_on(windows, linux)
    );
}

/// THE WINDOWS LONE WRITE (`lone_written_stored`): shipped on Windows and
/// nowhere else, for `x` and `e` of exactly one file, stored, clear, under
/// a CRC32 and whole, from 16 MiB to under 64 MiB, in one volume that
/// is not solid and has no window, with no `-mt1` and no `-mm`. Its word
/// takes it anywhere or nowhere, and a stated word of the wide rule keeps
/// the member to that rule unless the lone write's own word is stated too.
/// Pure: no width, no memory.
#[cfg(feature = "parallel")]
#[test]
fn the_windows_lone_write_rule() {
    const M: u64 = 1 << 20;
    type Fact = (bool, u8, bool, bool, bool, u64);
    // Shipped on Windows alone.
    assert!(lone_write_ships_on(true));
    assert!(!lone_write_ships_on(false));
    assert_eq!(LONE_WRITE, cfg!(windows));
    // The word.
    assert!(lone_write_of(Some("1"), false));
    assert!(lone_write_of(Some(" ON "), true));
    assert!(!lone_write_of(Some("0"), false));
    assert!(!lone_write_of(Some("off"), false));
    assert_eq!(lone_write_of(None, false), LONE_WRITE);
    assert_eq!(lone_write_of(Some("wide"), false), LONE_WRITE);
    assert!(!lone_write_of(None, true));
    // The shape.
    let ask = LoneWideAsk {
        extract: true,
        on: true,
        one_plain_volume: true,
        in_memory: true,
        stated: false,
    };
    let is = |ask: LoneWideAsk, members: &[Fact]| lone_written_stored(ask, members.iter().copied());
    let lone: Fact = (false, 0, false, true, false, 16 * M);
    let dir: Fact = (true, 0, false, false, false, 0);
    assert!(is(ask, &[lone]));
    assert!(is(ask, &[dir, lone, dir]));
    for refused in [
        LoneWideAsk {
            extract: false,
            ..ask
        },
        LoneWideAsk { on: false, ..ask },
        LoneWideAsk {
            one_plain_volume: false,
            ..ask
        },
        LoneWideAsk {
            in_memory: false,
            ..ask
        },
        LoneWideAsk {
            stated: true,
            ..ask
        },
    ] {
        assert!(!is(refused, &[lone]));
    }
    for member in [
        (false, 3, false, true, false, 16 * M),
        (false, 0, true, true, false, 16 * M),
        (false, 0, false, false, false, 16 * M),
        (false, 0, false, true, true, 16 * M),
    ] {
        assert!(!is(ask, &[member]));
    }
    assert_eq!(LONE_WRITE_FROM, 16 * M);
    assert_eq!(LONE_WRITE_UNDER, 64 * M);
    let sized = |size: u64| [(false, 0u8, false, true, false, size)];
    assert!(!is(ask, &sized(LONE_WRITE_FROM - 1)));
    assert!(is(ask, &sized(LONE_WRITE_FROM)));
    assert!(is(ask, &sized(32 * M)));
    assert!(is(ask, &sized(LONE_WRITE_UNDER - 1)));
    assert!(!is(ask, &sized(LONE_WRITE_UNDER)));
    let note: Fact = (false, 0, false, true, false, 14);
    assert!(!is(ask, &[lone, note]));
    assert!(!is(ask, &[lone, lone]));
    assert!(!is(ask, &[]));
    assert!(!is(ask, &[dir]));
}

/// THE LONE WRITE'S END (`lone_write_end`, its promise): set a step
/// past a write that would pass it, and NEVER the member's declared length,
/// which only the member's own last bytes reach; unmoved while a write fits.
/// So a run killed mid member never leaves a file of the member's length.
/// Pure: no width, no memory.
#[cfg(feature = "parallel")]
#[test]
fn the_lone_write_end_never_reaches_the_declared_length() {
    const M: u64 = 1 << 20;
    const K: u64 = 128 << 10;
    let step = LONE_WRITE_STEP;
    assert_eq!(step, 8 * M);
    // The first write moves the end a step past itself.
    assert_eq!(lone_write_end(0, 0, K, 16 * M), K + step);
    // A write that fits moves nothing.
    assert_eq!(lone_write_end(K + step, K, K, 16 * M), K + step);
    // Short of the declared length by one byte at most, wherever the write.
    assert_eq!(lone_write_end(12 * M, 12 * M, K, 16 * M), 16 * M - 1);
    assert_eq!(lone_write_end(0, 0, 16 * M, 16 * M), 16 * M - 1);
    // Walked over a whole member in the engine's pieces: the end before
    // each write is never the declared length, never more than a step
    // past the bytes, and always takes the write but for the last bytes.
    for declared in [16 * M, 16 * M + 7, 33 * M, 64 * M - 1] {
        let (mut end, mut written) = (0, 0);
        while written < declared {
            let len = K.min(declared - written);
            end = lone_write_end(end, written, len, declared);
            assert!(end < declared, "{declared}: {end} at {written}");
            assert!(
                end <= written + len + step,
                "{declared}: {end} at {written}"
            );
            if written + len < declared {
                assert!(end >= written + len, "{declared}: {end} at {written}");
            }
            written += len;
        }
    }
}
