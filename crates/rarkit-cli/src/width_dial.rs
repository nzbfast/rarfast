//! Acceptance test 7 of API section 8.4.4: the command line reaches the
//! read side's width dial, in BOTH directions.
//!
//! 8.4.6's finding is that no switch in either dialect could raise the
//! read side's thread ceiling: `-mt<n>` only ever lowered
//! `MemoryPolicy::max_workers`, which `from_limit` derives from the memory
//! budget as `working_limit / 64 MiB` and holds at 8 on the default
//! budget. So `-mt32` on this 18 core box ran no wider than `-mt8`, and
//! the 1.5x to 3.2x of wall 8.4 opens with was unreachable from the
//! command line. A change that fixed the library and left the tool where
//! it was would leave every `rarfast x` and `rarfast t` user exactly
//! there, which is why this test is in the tool and not in the engine.
//!
//! It asserts through `probe::peak_lanes`, the counter 8.4.4 names, for
//! the reason `tests/encoder_width.rs` exists: a width dial that reaches
//! nothing keeps a byte-identical-output test passing.
//!
//! **Why the fixture is large and this file is slow.** The tape decode has
//! a size floor of 16 MiB of output below which a member takes no lane at
//! all, so a member this test can see the width of is a member of tens of
//! megabytes. `crates/rarkit/tests/breadth_width.rs` says the same at its
//! own fixture.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use rarkit::{probe, HostOs, MemberSpec, Payload, WriteMethod, WriteOptions, Writer};

/// One member's worth of material an `-m1` archive can hold: about half of
/// it compresses and half does not, so the block chain keeps growing and
/// there are blocks enough to spread over lanes. A single repeated byte
/// would give a chain of one block, which takes no lane.
fn body(bytes: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes + 128);
    let mut seed = 0x2026_0920_u64;
    while out.len() < bytes {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        out.extend_from_slice(format!("{:016x} ", seed >> 24).as_bytes());
        out.extend_from_slice(b"the quick brown fox jumps over the lazy dog ");
        for _ in 0..8 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            out.extend_from_slice(&seed.to_le_bytes());
        }
    }
    out.truncate(bytes);
    out
}

/// A non-solid archive of `members` members of `each` bytes, on disk,
/// which is the shape the tool takes: whole members, none split, so every
/// one of them can be dispatched.
fn archive_at(path: &Path, members: usize, each: usize) {
    let body = body(each);
    let mut writer = Writer::new(WriteOptions {
        method: WriteMethod::Compressed {
            level: 1,
            dictionary: None,
        },
        ..WriteOptions::default()
    })
    .expect("options");
    let names: Vec<Vec<u8>> = (0..members)
        .map(|index| format!("m{index}.dat").into_bytes())
        .collect();
    for name in &names {
        writer
            .add(MemberSpec {
                name,
                payload: Payload::Bytes(&body),
                mtime: None,
                attributes: 0,
                host_os: HostOs::Unix,
                is_directory: false,
            })
            .expect("add");
    }
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("finish");
    std::fs::write(path, &out).expect("write the archive");
}

/// The lanes one `rarfast t -mt<n>` spread itself over.
fn lanes_at(path: &Path, threads: usize) -> usize {
    lanes_with(
        path,
        &[OsString::from(format!("-mt{threads}"))],
        &format!("-mt{threads}"),
    )
}

/// The lanes one `rarfast t` with NO width switch spread itself over,
/// which is the arm 8.4.3 resolves from the pool and the arm every table
/// anyone quotes is taken on.
fn lanes_default(path: &Path) -> usize {
    lanes_with(path, &[], "no switch")
}

/// How many readings in a row must fail to lower the least one before it
/// is taken as the read's own figure, and the most readings taken.
const SETTLED_AFTER: usize = 4;
const MOST_READINGS: usize = 40;

/// The lanes one `rarfast t` spread itself over: the LEAST of several
/// readings.
///
/// **Why several.** `probe::peak_lanes` counts every tape lane alive in the
/// PROCESS, and this binary's other tests run beside this one: any of them
/// reading or creating an archive while a reading is taken adds its lanes
/// to it. On a loaded 32-core Mac that failed this test in 15 of 20 runs
/// of the whole binary and in none of 20 runs of the test alone (an M3 Mac,
/// 2 Oct 2026: "`-mt2` asked for two and the read ran 8 lanes"), which failed
/// three unrelated gate runs in one hour.
///
/// **Why the least is the read's own.** Another test's lanes can only ADD
/// to a reading, never take from it: every reading is at least what this
/// read spread over, and equal to it whenever nothing else ran. So the
/// least reading is never under the true figure, and a switch that does
/// not narrow the read still fails `narrow <= 2` however many readings are
/// taken. Readings go on until [`SETTLED_AFTER`] in a row have not lowered
/// the least.
fn lanes_with(path: &Path, extra: &[OsString], what: &str) -> usize {
    let mut least = usize::MAX;
    let mut unmoved = 0;
    for _ in 0..MOST_READINGS {
        let reading = one_reading(path, extra, what);
        if reading < least {
            least = reading;
            unmoved = 0;
        } else {
            unmoved += 1;
            if unmoved >= SETTLED_AFTER {
                break;
            }
        }
    }
    least
}

/// One reading of `probe::peak_lanes` across one `rarfast t`.
fn one_reading(path: &Path, extra: &[OsString], what: &str) -> usize {
    probe::reset_peak_lanes();
    let mut argv: Vec<OsString> = vec![OsString::from("t")];
    argv.extend_from_slice(extra);
    argv.push(OsString::from(path));
    let exit = crate::dispatch("unrar", &argv);
    assert_eq!(exit.code(), 0, "`t {what}` did not answer 0");
    probe::peak_lanes()
}

/// The pool cap a READ carried from 19 Sep to 20 Sep 2026, kept here as a
/// number to measure against rather than as a constant to restore. See
/// `crate::workers`.
const THE_OLD_READ_CAP: usize = 6;

/// The fixture's members. A box needs MORE cores than this before a wide
/// read gives any one of them a second thread, which is where a lane
/// begins; see the first assertion.
const MEMBERS: usize = 4;

fn cores() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
}

fn scratch() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rarfast-width-dial-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch");
    dir
}

/// `-mt<n>` moves the read's width in both directions, and upward past
/// the figure the memory budget used to hold it at.
///
/// ONE test rather than two, because `probe::peak_lanes` is process-wide
/// and the fixture costs tens of megabytes of encoding: both readings are
/// taken here, in sequence, off the one archive.
/// Process-wide also means the binary's OTHER tests are in every reading,
/// so each figure is the least of several ([`lanes_with`]).
#[test]
#[cfg_attr(not(feature = "h2-probes"), ignore = "needs h2-probes")]
fn the_command_line_moves_the_read_width_both_ways() {
    // The figure `MemoryPolicy::from_limit` derives at the default budget,
    // read from the engine rather than written down, and the ceiling every
    // read was held at before 8.4.2.
    let derived = rarkit::MemoryPolicy::default().max_workers;
    let dir = scratch();
    let path = dir.join("wide.rar");
    // Four members, each comfortably past the tape path's 16 MiB floor.
    archive_at(&path, MEMBERS, 20 << 20);

    let narrow = lanes_at(&path, 2);
    let wide = lanes_at(&path, 32);
    // The arm no switch selects, taken off the same archive in the same
    // process for the same reason the other two are.
    let capped = lanes_at(&path, THE_OLD_READ_CAP);
    let plain = lanes_default(&path);
    println!(
        "cores={} derived max_workers={derived} lanes at -mt2={narrow} \
         lanes at -mt32={wide} lanes at -mt{THE_OLD_READ_CAP}={capped} \
         lanes with no switch={plain}",
        cores()
    );

    // The tool holds `-mt<n>` to the box's cores (`crate::workers`), and a
    // member given one thread opens no lane. So on a box with no more
    // cores than the fixture has members there is no width the switch
    // could show: every reading is 0 whatever the switch does, and the
    // assertion would be about the box rather than about the switch.
    // Counted on Linux held to a CPU set (3 Oct 2026, x86-64, this test
    // alone): 1, 2 and 4 cores read 0 lanes at every width, as the 2 core
    // Windows hosted runner did; 5, 6, 7, 8, 16 and 96 cores read `-mt32`
    // wider than `-mt2`.
    if cores() > MEMBERS {
        assert!(
            narrow < wide,
            "`-mt2` and `-mt32` spread the same read over the same {narrow} lanes, \
             so the switch reaches nothing"
        );
    }
    assert!(
        narrow <= 2,
        "`-mt2` asked for two and the read ran {narrow} lanes"
    );
    // The direction 8.4.6 found unreachable. On a box with no more cores
    // than the derived figure there is nothing to widen INTO, and the
    // assertion would be about the box rather than about the switch.
    if cores() > derived {
        assert!(
            wide > derived,
            "`-mt32` ran {wide} lanes, no more than the memory-derived {derived}: \
             the command line still cannot raise the read's width (8.4.6)"
        );
    }

    // AND THE DEFAULT ARM, which is this crate's own half of 8.4.3 and
    // the one the 20 Sep class round was taken on. `workers: None`
    // resolves to the width of the pool the caller owns, and this binary
    // owns its pool: `crate::workers` capped a READ's at six until the
    // dial made that cap the engine's breadth, which cost up to 55
    // percent of wall on a 32-core box.
    //
    // Asserted against `-mt6` rather than against a written-down number,
    // so the test says the thing it means - a default run is not pinned
    // to what the old cap pinned it to - and keeps saying it if the
    // engine's own resolution of `None` changes underneath.
    if cores() > THE_OLD_READ_CAP {
        assert!(
            plain > capped,
            "a default read spread over {plain} lanes and `-mt{THE_OLD_READ_CAP}` over \
             {capped} on a {}-core box: the default arm is still pinned at the pool cap \
             `crate::workers` removed",
            cores()
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}
