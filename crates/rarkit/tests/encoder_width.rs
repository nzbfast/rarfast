//! `WriteOptions::workers`: the encoder's width dial, and the one thing it
//! may never do.
//!
//! API 7.2 and 8.2 give the encoder a width
//! dial of its own, apart from `MemoryPolicy::max_workers`, which stays
//! the MEMORY ceiling. This file holds the promise that makes such a dial
//! safe to expose at all: **promise 2.6, that it cannot change a byte of
//! output at any value**, over every shape the writer can be asked for.
//!
//! `thread_width.rs` holds the narrow form of this over one shape at level
//! 3. The broad form is here: every `WriteFormat`, solid and not, a volume
//! set, and every level of the ladder.
//!
//! **Why this test says what width the encoder actually ran at.** A test
//! that only compares archives passes just as happily when the dial
//! reaches nothing at all, and that is not a hypothetical: between 19 and
//! 20 Sep 2026 `thread_width.rs`'s write leg moved the width through
//! `MemoryPolicy::max_workers`, and when the encoder was taken off
//! that field the test kept passing while varying nothing. So every
//! comparison here also reads `probe::last_walkers`, and the test FAILS if
//! the tree levels did not genuinely run at different widths.

#![cfg(all(feature = "parallel", feature = "test-support"))]

use std::sync::{Mutex, MutexGuard, OnceLock};

use rarkit::{
    probe, FilterPolicy, MemberSpec, Payload, Rar4Version, VolumeNaming, WriteFormat, WriteMethod,
    WriteOptions, Writer,
};

/// `probe::last_walkers` is PROCESS-wide, as its own comment says it has
/// to be, so every test in this file takes this.
///
/// cargo runs a binary's tests on several threads at once, and the first
/// run of this file proved the point: the matrix test's
/// `probe::forget_walkers` landed between the ceiling test's write and its
/// read, which read the width of a walk it did not start as 0. That is the
/// same lesson `thread_width.rs` records at its own `COUNTER`, and the
/// engine was right both times.
static COUNTER: Mutex<()> = Mutex::new(());

fn counter() -> MutexGuard<'static, ()> {
    COUNTER.lock().unwrap_or_else(|e| e.into_inner())
}

/// Two parse blocks' worth (they are 256 KiB), with something in them to
/// find, so the encoder does real work at every level.
///
/// Deliberately modest, and built ONCE: the suite runs unoptimised and
/// this file writes 320 archives, so the member's size is most of its
/// wall. What the file asserts does not need a big corpus. The width the
/// walk settles on is recorded when the walk is ENTERED, so a small member
/// reads it as faithfully as a large one; only the wall would differ.
fn body() -> &'static [u8] {
    static BODY: OnceLock<Vec<u8>> = OnceLock::new();
    BODY.get_or_init(|| build(320 << 10))
}

fn build(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut seed = 0x2026_0920_u64;
    while out.len() < len {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        out.extend_from_slice(format!("{:016x} ", seed >> 24).as_bytes());
        // Three repeats to one novelty, so there are matches to find at
        // every depth the ladder looks to.
        for _ in 0..3 {
            out.extend_from_slice(b"the quick brown fox jumps over the lazy dog ");
        }
    }
    out.truncate(len);
    out
}

/// One shape of archive: what is being written, and how it is laid out.
#[derive(Clone, Copy, Debug)]
struct Shape {
    what: &'static str,
    format: WriteFormat,
    solid: bool,
    /// `Some` writes a volume SET, at this many payload bytes a volume.
    volume_size: Option<u64>,
}

/// Every shape the matrix runs, which is every `WriteFormat`, solid and
/// not, and a volume set.
///
/// RAR 4 carries `FilterPolicy::Off` throughout: the erratum to
/// API 7.2 makes `Detect` RAR 5 only and `Writer::new` refuses the pair,
/// so a RAR 4 row asking for the default would be testing the refusal
/// rather than the width.
fn shapes() -> Vec<Shape> {
    let mut out = Vec::new();
    for (what, format) in [
        ("rar5", WriteFormat::Rar5),
        ("rar4-v29", WriteFormat::Rar4(Rar4Version::V29)),
        ("rar4-v30", WriteFormat::Rar4(Rar4Version::V30)),
        ("rar4-v40", WriteFormat::Rar4(Rar4Version::V40)),
    ] {
        for solid in [false, true] {
            for volume_size in [None, Some(192 << 10)] {
                out.push(Shape {
                    what,
                    format,
                    solid,
                    volume_size,
                });
            }
        }
    }
    out
}

/// Writes `shape` at `level` and `workers`, and reports the archive's
/// bytes beside the width its tree walk settled on.
///
/// The volumes are compared as a LIST and not concatenated: a width that
/// moved a member across a volume boundary without moving a byte of any
/// member would be a difference this test exists to catch, and
/// concatenating would hide it.
/// With level 5's tree option on or off (`WriteOptions::level5_tree`):
/// level 5 goes by class since 1 Oct 2026
/// (SPEC-H3 8.1), and these members, under a megabyte, take the chains by
/// default and enter no walk; with the option on they take the tree, which
/// is the walk the dial reaches.
fn write_with(
    shape: Shape,
    level: u8,
    workers: Option<usize>,
    tree: bool,
) -> (Vec<Vec<u8>>, usize) {
    let data = body();
    let options = WriteOptions {
        format: shape.format,
        method: WriteMethod::Compressed {
            level,
            dictionary: None,
        },
        solid: shape.solid,
        volume_size: shape.volume_size,
        volume_naming: VolumeNaming::Numbered,
        filters: match shape.format {
            WriteFormat::Rar5 => FilterPolicy::Detect,
            WriteFormat::Rar4(_) => FilterPolicy::Off,
        },
        workers,
        level5_tree: tree,
        ..WriteOptions::default()
    };
    let mut writer = Writer::new(options).expect("these options are all representable");
    // Two members, so `solid` has something to be solid ACROSS: a single
    // member archive is the same bytes solid or not, and would make half
    // the matrix a copy of the other half.
    for name in [b"one.dat".as_slice(), b"two.dat".as_slice()] {
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(data),
                mtime: None,
                attributes: 0,
                host_os: rarkit::HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }

    probe::forget_walkers();
    let out = if shape.volume_size.is_some() {
        let mut volumes: Vec<Vec<u8>> = Vec::new();
        writer.finish_volumes(&mut volumes).expect("finish volumes");
        volumes
    } else {
        let mut one = Vec::new();
        writer.finish_into(&mut one).expect("finish");
        vec![one]
    };
    (out, probe::last_walkers())
}

/// **Promise 2.6 over the whole matrix**: the archive is byte-identical at
/// every width, for every format, solid and not, over a volume set, at
/// every level of the ladder.
///
/// `None` is in the width list beside the numbers because it is the
/// DEFAULT and means something different from all of them - the width of
/// the caller's own pool - so a leak that only showed when the engine
/// chose the width itself would pass a test of 1, 2 and 6 alone.
#[test]
fn the_encoder_width_never_reaches_the_bytes() {
    let _guard = counter();
    let widths = [Some(1usize), Some(2), Some(6), None];
    // The TREE is the only finder whose walk the dial can reach at all;
    // the chain finder enters no walk. The tree is level 5's on a member
    // whose class keeps it, and for every member under level 5's tree
    // option, which is the arm `(5, true)` below: these members take the
    // chains by default. Every level is in the matrix anyway, because "the
    // bytes do not move" is a promise about every level and not only the
    // ones with a walk in them.
    let mut tree_widths: Vec<usize> = Vec::new();

    for shape in shapes() {
        for (level, tree) in [
            (1u8, false),
            (2, false),
            (3, false),
            (4, false),
            (5, false),
            (5, true),
        ] {
            let (first, first_walkers) = write_with(shape, level, widths[0], tree);
            for width in &widths[1..] {
                let (again, walkers) = write_with(shape, level, *width, tree);
                assert!(
                    again == first,
                    "{} level {level} tree={tree} solid={} volumes={:?}: the archive written at \
                     workers={:?} differs from the one written at workers={:?} \
                     (walk widths {walkers} against {first_walkers})",
                    shape.what,
                    shape.solid,
                    shape.volume_size,
                    width,
                    widths[0],
                );
                if tree {
                    tree_widths.push(walkers);
                }
            }
            if tree {
                tree_widths.push(first_walkers);
            }
        }
    }

    // And the assertion that stops the one above being vacuous. A walk
    // width of 0 would mean the tree levels never entered a walk, and two
    // equal widths would mean the dial moved nothing; either way the
    // comparisons above compared a thing against itself.
    assert!(
        tree_widths.iter().any(|&w| w > 0),
        "no tree level entered the walk at all, so nothing above varied the \
         encoder's width: {tree_widths:?}"
    );
    let narrowest = tree_widths.iter().copied().min().unwrap_or(0);
    let widest = tree_widths.iter().copied().max().unwrap_or(0);
    assert!(
        widest > narrowest,
        "every tree walk ran at the same width {widest}, so `WriteOptions::workers` \
         reached the encoder no differently at 1, 2, 6 and None: the comparisons \
         above cannot have caught a leak"
    );
}

/// What the dial resolves to, stated as the arithmetic API 7.2 promises:
/// `min(workers or the pool's width, the engine's own ceiling, the pool's
/// width)`.
///
/// It is a CEILING and never a demand, so this asserts that asking for
/// more never gets more, and that asking for one gets exactly one.
#[test]
fn the_dial_is_a_ceiling_and_never_a_demand() {
    let _guard = counter();
    let shape = Shape {
        what: "rar5",
        format: WriteFormat::Rar5,
        solid: false,
        volume_size: None,
    };
    // Level 5 under its tree option walks the tree on these members, so
    // the walk is entered and the width is recorded.
    let write_at = |shape, level, workers| write_with(shape, level, workers, true);
    let (_, one) = write_at(shape, 5, Some(1));
    assert_eq!(one, 1, "workers=Some(1) walked at {one}");

    let (_, default) = write_at(shape, 5, None);
    assert!(default >= 1, "workers=None walked at {default}");

    // Past anything the engine or the box can use. It saturates at what
    // `None` already gives, and never above it: the caller's figure does
    // not raise the engine's own ceiling.
    let (_, huge) = write_at(shape, 5, Some(1_000));
    assert_eq!(
        huge, default,
        "workers=Some(1000) walked at {huge} where the pool and the engine's \
         own ceiling allow {default}: a caller's figure must never RAISE the width"
    );

    // And a zero is lifted to one rather than refused or taken as none.
    let (_, zero) = write_at(shape, 5, Some(0));
    assert_eq!(zero, 1, "workers=Some(0) walked at {zero}");
}
