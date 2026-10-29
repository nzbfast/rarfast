//! SPEC-H2 section 5: the archives, the hand vectors and the window and
//! parallel property tests.

use sha2::{Digest, Sha256};

use super::container::{archive, check_table, members, Member, ARCHIVES};
use super::output::{NullSink, RING_FLOOR, SPILL, WINDOW_FLOOR};
use super::{Rar5Lz, SliceSource};
// The sibling modules a test names by path: a child module's `super::tape`
// is this module's `tape`, so each is named here once.
use super::{
    ahead, block, fault, filters, ladders, output, symbols, tables, tape, vectors, PackedSource,
};
use crate::memory::MemoryPolicy;
use crate::{Corruption, ErrorKind, Rar5Fault};

/// A policy with no window ceiling in the way, so a vector archive's
/// declared dictionary is never the thing under test here.
pub(crate) fn policy() -> MemoryPolicy {
    MemoryPolicy {
        working_limit: u64::MAX,
        max_window: 1 << 33,
        ..MemoryPolicy::default()
    }
}

/// Decode every LZ member of one archive, keeping the solid chain.
pub(crate) fn decode_archive(data: &[u8], parallel: bool) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut decoder: Option<Rar5Lz> = None;
    for member in members(data) {
        if member.directory || member.method == 0 {
            continue;
        }
        let fresh = !member.solid || decoder.is_none();
        if fresh {
            let mut new = Rar5Lz::new(member.window, &policy()).expect("window");
            new.set_parallel(parallel);
            decoder = Some(new);
        }
        let lz = decoder.as_mut().unwrap();
        let mut sink: Vec<u8> = Vec::with_capacity(member.unpacked as usize);
        let mut source = SliceSource::new(&member.packed);
        lz.member(&mut source, member.unpacked, member.algorithm, &mut sink)
            .unwrap_or_else(|e| panic!("{}: {e}", member.name));
        assert_eq!(sink.len() as u64, member.unpacked, "{}", member.name);
        out.push((member.name.clone(), sink));
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    digest
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn fault_of(err: crate::Error) -> Rar5Fault {
    match err.kind() {
        ErrorKind::Corrupt(Corruption::Rar5(f)) => *f,
        other => panic!("wanted a RAR 5 fault, got {other:?}"),
    }
}

pub(crate) fn assert_fault<T>(outcome: crate::Result<T>, want: Rar5Fault) {
    match outcome {
        Err(e) => assert_eq!(fault_of(e), want),
        Ok(_) => panic!("wanted {want:?}, got success"),
    }
}

// ---------------------------------------------------------------------------
// Section 5.4: the hand vectors.
// ---------------------------------------------------------------------------

use super::vectors::BlockBuilder;
use super::{MatchState, Rar5Lz as Lz};

// The tests, one module a section.
// The directory is `unit_tests` and not `tests` because a vendored mirror of
// this crate leaves out every directory of that name (`make mirror-check`).
#[path = "unit_tests/archives.rs"]
mod archives;
#[path = "unit_tests/carried_tables.rs"]
mod carried_tables;
#[path = "unit_tests/decode_ahead.rs"]
mod decode_ahead;
#[path = "unit_tests/failing_symbol_past_end.rs"]
mod failing_symbol_past_end;
#[path = "unit_tests/far_distance.rs"]
mod far_distance;
#[path = "unit_tests/hand_vectors.rs"]
mod hand_vectors;
#[path = "unit_tests/literal_batch.rs"]
mod literal_batch;
#[path = "unit_tests/member_end.rs"]
mod member_end;
#[path = "unit_tests/short_member_kinds.rs"]
mod short_member_kinds;
#[path = "unit_tests/short_source.rs"]
mod short_source;
#[path = "unit_tests/span_past_declared.rs"]
mod span_past_declared;
#[path = "unit_tests/symbol_pass.rs"]
mod symbol_pass;
#[path = "unit_tests/unknown_filter_type.rs"]
mod unknown_filter_type;
#[path = "unit_tests/width.rs"]
mod width;
#[path = "unit_tests/window_parallel.rs"]
mod window_parallel;
#[path = "unit_tests/wrapped_source.rs"]
mod wrapped_source;

/// The distance slot and extra bits that name `distance`, walking section
/// 3.5's ladder in the encoding direction.
pub(crate) fn distance_slot(distance: usize) -> (usize, u32) {
    assert!(distance >= 1);
    if distance <= 4 {
        return (distance - 1, 0);
    }
    let value = (distance - 1) as u64;
    let bits = (63 - value.leading_zeros()) as usize - 1;
    let top = (value >> bits) as usize;
    let slot = 2 * bits + 2 + (top - 2);
    let extra = (value & ((1 << bits) - 1)) as u32;
    (slot, extra)
}

/// Decode a chain of hand built blocks into one non solid member.
fn run(blocks: &[Vec<u8>], unpacked: u64, window: u64) -> crate::Result<Vec<u8>> {
    let mut packed = Vec::new();
    for block in blocks {
        packed.extend_from_slice(block);
    }
    let mut lz = Lz::new(window, &policy())?;
    let mut sink: Vec<u8> = Vec::new();
    let mut source = SliceSource::new(&packed);
    lz.member(&mut source, unpacked, 0, &mut sink)?;
    Ok(sink)
}

// ---------------------------------------------------------------------------
// Section 5.5: the window and parallel property tests.
// ---------------------------------------------------------------------------

use super::output::{NoFilters, Window, MIN_RING, STRIDE, STRIDE_MAX};

/// A byte at a time reference for one match: the semantics section 3.7
/// states, written the slowest way there is.
fn reference_copy(out: &mut Vec<u8>, distance: usize, length: usize) {
    for _ in 0..length {
        let byte = out[out.len() - distance];
        out.push(byte);
    }
}

/// The apply stage's two LITERAL arms agree on every archive of 5.2, and
/// on a damaged member they agree on the error too.
///
/// `probe::set_literal_ladder` is a speed dial and not a behaviour
/// switch: the fixed-width store that ships and the carried inline ladder
/// it replaced write the same bytes and stop at the same operation, the
/// store's spill landing only on slots no admissible distance can name.
/// That claim is what makes the dial legitimate at all, so it is a test
/// and not a comment. `the_fixed_width_literal_store_spills_only_inside_the_margin`
/// holds the margin itself; this holds the OUTPUT, which is what a caller
/// sees.
// Both settings run the shipped walk without `h2-apply-arms`, so the
// test would pass without testing anything; `make ci` runs it with it.
#[cfg(feature = "h2-apply-arms")]
#[cfg(all(feature = "repo-tests", feature = "test-support"))]
#[test]
fn the_two_literal_arms_agree_on_every_archive() {
    for stem in ARCHIVES {
        let data = archive(stem);
        let mut both = Vec::new();
        for ladder in [true, false] {
            crate::probe::set_literal_ladder(Some(ladder));
            both.push(decode_archive(&data, true));
        }
        crate::probe::set_literal_ladder(None);
        assert_eq!(both[0].len(), both[1].len(), "{stem}");
        for (a, b) in both[0].iter().zip(&both[1]) {
            assert_eq!(a.0, b.0, "{stem}: member order");
            assert!(a.1 == b.1, "{stem}/{}: bytes", a.0);
        }
    }

    // And a DAMAGED member: the store must not turn a stop into a
    // different stop, which is the failure a spill past the margin would
    // show as long before it showed as a wrong byte.
    let data = archive("h5_text_m5");
    let member = members(&data)
        .into_iter()
        .find(|m| m.method != 0)
        .expect("a compressed member");
    for byte in (0..member.packed.len().min(4096)).step_by(11) {
        let mut packed = member.packed.clone();
        packed[byte] ^= 1 << 3;
        let mut both = Vec::new();
        for ladder in [true, false] {
            crate::probe::set_literal_ladder(Some(ladder));
            let mut lz = Rar5Lz::new(member.window, &policy()).unwrap();
            lz.set_parallel(true);
            let mut sink: Vec<u8> = Vec::new();
            let mut source = SliceSource::new(&packed);
            let outcome = lz.member(&mut source, member.unpacked, member.algorithm, &mut sink);
            both.push((outcome.map_err(|e| format!("{:?}", e.kind())), sink));
        }
        crate::probe::set_literal_ladder(None);
        assert_eq!(both[0].0, both[1].0, "byte {byte}: error kind");
        assert!(both[0].1 == both[1].1, "byte {byte}: output");
    }
}

/// THE FAR-COPY PREFETCH IS A HINT AND NOTHING ELSE: every
/// archive of 5.2 decodes to the same bytes at every depth, and a damaged
/// member stops with the same error and the same bytes before it.
///
/// Depth 1 hints the very next operation, 64 reaches past most short
/// blocks' ends, and the odd depths put the running length sum through
/// every alignment. Nothing a hint does can reach the output, so any
/// difference here is the walk's bookkeeping around it, the `ahead` sum
/// or the loop shape, broken.
// Both settings run the shipped walk without `h2-apply-arms`, so the
// test would pass without testing anything; `make ci` runs it with it.
#[cfg(feature = "h2-apply-arms")]
#[cfg(all(feature = "repo-tests", feature = "test-support"))]
#[test]
fn the_far_prefetch_changes_no_byte_and_no_error_at_any_depth() {
    const DEPTHS: [usize; 5] = [1, 3, 8, 17, 64];
    // UNGATED, so these small archives, whose matches seldom reach the
    // gate's distance, still run the pass on every tape.
    crate::probe::set_far_prefetch_mode(crate::probe::far_prefetch_modes::UNGATED);
    for stem in ARCHIVES {
        let data = archive(stem);
        crate::probe::set_far_prefetch(Some(0));
        let off = decode_archive(&data, true);
        for depth in DEPTHS {
            crate::probe::set_far_prefetch(Some(depth));
            let on = decode_archive(&data, true);
            assert_eq!(off.len(), on.len(), "{stem} depth {depth}");
            for (a, b) in off.iter().zip(&on) {
                assert_eq!(a.0, b.0, "{stem} depth {depth}: member order");
                assert!(a.1 == b.1, "{stem}/{} depth {depth}: bytes", a.0);
            }
        }
        crate::probe::set_far_prefetch(None);
    }

    let data = archive("h5_text_m5");
    let member = members(&data)
        .into_iter()
        .find(|m| m.method != 0)
        .expect("a compressed member");
    for byte in (0..member.packed.len().min(4096)).step_by(13) {
        let mut packed = member.packed.clone();
        packed[byte] ^= 1 << 5;
        let mut runs = Vec::new();
        for depth in [0, 1, 8, 64] {
            crate::probe::set_far_prefetch(Some(depth));
            let mut lz = Rar5Lz::new(member.window, &policy()).unwrap();
            lz.set_parallel(true);
            let mut sink: Vec<u8> = Vec::new();
            let mut source = SliceSource::new(&packed);
            let outcome = lz.member(&mut source, member.unpacked, member.algorithm, &mut sink);
            runs.push((outcome.map_err(|e| format!("{:?}", e.kind())), sink));
        }
        crate::probe::set_far_prefetch(None);
        for run in &runs[1..] {
            assert_eq!(runs[0].0, run.0, "byte {byte}: error kind");
            assert!(runs[0].1 == run.1, "byte {byte}: output");
        }
    }
    crate::probe::set_far_prefetch_mode(crate::probe::far_prefetch_modes::ALL);
}

/// The apply walk's ABLATION arms, held to the two things the
/// attribution table needs of them.
///
/// `probe::apply_arms` exists to bound a lever before it is written, and
/// most of its arms produce wrong bytes on purpose. Two claims are made
/// about them in the measurements and neither may rest on a
/// comment:
///
/// - `NO_RANGE` is BYTE EXACT on a valid archive. It removes the match
///   copy's distance validation, which on a valid stream never fires, so
///   it is a bound on a hoist that could really ship rather than on a
///   fantasy. If that were untrue its figure would be measuring a
///   different decode, not a cheaper one;
/// - every arm PRESERVES THE BYTE COUNT, so the member stops at the
///   operation it always stopped at and the extraction still succeeds.
///   An arm that ended a member early would read as a saving worth
///   however much of the member it skipped.
#[cfg(all(feature = "repo-tests", feature = "h2-apply-arms"))]
#[test]
fn the_apply_walk_arms_are_bounds_and_not_a_different_decode() {
    use crate::probe::apply_arms as arms;

    for stem in ARCHIVES {
        let data = archive(stem);
        let shipped = decode_archive(&data, true);

        // Byte exact, which is the claim that makes this arm's figure a
        // bound on something shippable.
        crate::probe::set_apply_arm(arms::NO_RANGE);
        let exact = decode_archive(&data, true);
        crate::probe::set_apply_arm(arms::SHIPPED);
        assert_eq!(shipped.len(), exact.len(), "{stem}: member count");
        for (a, b) in shipped.iter().zip(&exact) {
            assert_eq!(a.0, b.0, "{stem}: member order");
            assert!(a.1 == b.1, "{stem}/{}: NO_RANGE is not byte exact", a.0);
        }

        // Every arm completes, and every member is the length it was.
        // The bytes are not compared: these arms are wrong on purpose.
        for arm in [
            arms::NO_FRESH,
            arms::NO_MATCH_COPY,
            arms::NO_LIT_STORE,
            arms::NO_STORES,
        ] {
            crate::probe::set_apply_arm(arm);
            let ablated = decode_archive(&data, true);
            crate::probe::set_apply_arm(arms::SHIPPED);
            assert_eq!(
                shipped.len(),
                ablated.len(),
                "{stem}: arm {arm} member count"
            );
            for (a, b) in shipped.iter().zip(&ablated) {
                assert_eq!(
                    a.1.len(),
                    b.1.len(),
                    "{stem}/{}: arm {arm} changed the byte count",
                    a.0
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The width a leg NAMES is the width that runs (section 3.8, API 8.4.2).
// ---------------------------------------------------------------------------

/// `probe::peak_lanes` is PROCESS wide and has to be, so this takes a
/// lock: the lib tests run on several threads and another test's lanes
/// would otherwise land in this one's reading.
#[cfg(all(feature = "parallel", feature = "repo-tests"))]
static LANE_COUNTER: std::sync::Mutex<()> = std::sync::Mutex::new(());

// ---------------------------------------------------------------------
// The SOLID CHAIN's decode-ahead (section 3.8, `rar5_lz::ahead`).
// ---------------------------------------------------------------------

/// The claim counter is PROCESS-wide, as every counter in `probe` is, so
/// the two cases that read it take this and never run beside each other.
/// That alone is not enough: OTHER tests in this same binary decode a
/// solid chain ahead of its apply stage too, on their own threads, with
/// no interest in this counter and no reason to hold it, and at a wide
/// enough thread count they land inside the narrow window between a
/// holder's reset and its read. `counting()` also opens a claim scope
/// (`probe::begin_ahead_claim_scope`) on its own thread, so a foreign
/// thread's claims pass through uncounted for as long as the scope is
/// open, and closes it when the guard drops.
#[cfg(all(feature = "repo-tests", feature = "parallel"))]
static AHEAD_COUNTER: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A held [`AHEAD_COUNTER`], with the claim scope it opened, closed when
/// this drops alongside the lock.
#[cfg(all(feature = "repo-tests", feature = "parallel"))]
struct Counting {
    // Held for its drop, which is what keeps the lock through the scope;
    // never read.
    _held: std::sync::MutexGuard<'static, ()>,
}

#[cfg(all(feature = "repo-tests", feature = "parallel"))]
impl Drop for Counting {
    fn drop(&mut self) {
        crate::probe::end_ahead_claim_scope();
    }
}

/// Take the claim counter, start it from zero, and scope it to this
/// thread until the guard drops.
#[cfg(all(feature = "repo-tests", feature = "parallel"))]
fn counting() -> Counting {
    let held = AHEAD_COUNTER.lock().unwrap_or_else(|e| e.into_inner());
    // Scope first, then reset: the other order leaves a window in which a
    // foreign thread's claim lands after the reset and before the scope.
    crate::probe::begin_ahead_claim_scope();
    crate::probe::reset_ahead_claims();
    Counting { _held: held }
}
/// The shapes every x86 pass form is held to.
///
/// Extracted from `the_walking_and_the_split_x86_passes_agree` so that
/// `the_split_candidates_agree_with_the_shipped_pass` is held to the
/// SAME set and not an easier one. Anything added here reaches both,
/// which is the point: the window-boundary cases the filter-drain work
/// added for its own body are cases the candidates must pass too.
#[cfg(test)]
fn x86_pass_equivalence_cases() -> Vec<Vec<u8>> {
    let mut cases: Vec<Vec<u8>> = Vec::new();
    // SPARSE cases, which exist for `x86_pass_adaptive`: it chooses its
    // body on the density its own first scan measures, so a case set of
    // dense blocks alone would exercise ONE side of that choice and pass
    // whatever the other side did. These cross the choice in both
    // directions and cross `X86_PROBE_BYTES` too, which is where the
    // vector search takes over from the word probe.
    for gap in [8usize, 24, 40, 200, 4_000] {
        let mut block = vec![0x90u8; 24_000];
        let mut at = 0usize;
        while at + 5 < block.len() {
            block[at] = if at.is_multiple_of(2 * gap) {
                0xE8
            } else {
                0xE9
            };
            at += gap;
        }
        cases.push(block);
    }
    // No trigger at all, the sparsest block there is: the adaptive must
    // choose walking on a first scan that found nothing, and walking's
    // own vector search must cross the whole block.
    cases.push(vec![0x90u8; 24_000]);
    // DENSE at the start and EMPTY after, so the choice is made on a
    // first scan that is not representative of the block. The two bodies
    // must still agree, which is the property the choice rests on.
    let mut front = vec![0x90u8; 24_000];
    for at in (0..4_000).step_by(6) {
        front[at] = 0xE8;
    }
    cases.push(front);
    // SPARSE at the start and dense after, the same trap the other way.
    let mut back = vec![0x90u8; 24_000];
    for at in (12_000..24_000).step_by(6) {
        if at + 5 < back.len() {
            back[at] = 0xE9;
        }
    }
    cases.push(back);
    // Packed triggers: every byte a trigger, so the five byte skip is the
    // only thing deciding which are converted.
    cases.push(vec![0xE8; 64]);
    cases.push(vec![0xE9; 64]);
    // LONG packed runs, so the scan fills its 256 entry window many times
    // over and every window boundary falls INSIDE a five byte skip: 4,096
    // packed triggers accept about 819, which is three windows. A cursor
    // that is carried wrongly ACROSS a window shows up only here, and a
    // case of a few dozen bytes cannot see it however many of them there
    // are. Raised by the x86-collect work, 21 Sep 2026, whose own mutation
    // passed at the shipped window and failed at a window of 8.
    cases.push(vec![0xE8; 4_096]);
    cases.push(vec![0xE9; 4_096]);
    // The same length with the triggers four apart, so an accepted
    // trigger's operand always holds the next candidate and the window
    // boundary lands between them.
    cases.push(
        (0..4_096u32)
            .map(|i| if i % 4 == 0 { 0xE8 } else { 0x90 })
            .collect(),
    );
    // Alternating, which puts a trigger inside the last one's operand.
    cases.push(
        (0..96u32)
            .map(|i| if i % 2 == 0 { 0xE8 } else { 0xE9 })
            .collect(),
    );
    // A trigger at every position from 0 to 12 of a short block, so the
    // block's last five bytes are walked in every alignment.
    for start in 0..13usize {
        let mut case = vec![0x90u8; 13];
        case[start] = 0xE8;
        cases.push(case);
    }
    // Shorter than one operand, and empty.
    cases.push(vec![0xE8, 0x01, 0x02]);
    cases.push(Vec::new());
    // A long barren run either side of a trigger, which is the vector
    // search's own path, at every alignment of the stride.
    let probe = crate::carry::h_ours::codec::address_filters::X86_PROBE_BYTES;
    for pad in [probe, probe + 3, 2 * probe + 7] {
        for skew in 0..8usize {
            let mut case = vec![0x90u8; pad + skew];
            case.push(0xE8);
            case.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
            case.extend(std::iter::repeat_n(0x90u8, pad));
            case.push(0xE9);
            case.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            cases.push(case);
        }
    }
    // Code shaped bytes, with operands that land on both sides of every
    // branch the mapping takes.
    let mut seed = 0x1701_2026u32;
    let mut shaped = Vec::with_capacity(20_000);
    while shaped.len() < 20_000 {
        seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        shaped.push(match seed >> 27 {
            0 | 1 => 0xE8,
            2 => 0xE9,
            _ => (seed >> 11) as u8,
        });
    }
    cases.push(shaped);
    cases
}

// ---------------------------------------------------------------------
// THE SYMBOL PASS (`super::symbols`): a block its lane walked into
// 32-bit symbols must apply exactly as the shipped walk applies its tape.
// ---------------------------------------------------------------------

/// A sink that keeps every piece it is handed, so a test compares WHERE
/// the drains cut as well as what they carried.
#[cfg(feature = "parallel")]
#[derive(Default, PartialEq, Eq, Debug)]
struct Pieces(Vec<Vec<u8>>);

#[cfg(feature = "parallel")]
impl super::output::LzSink for Pieces {
    fn put(&mut self, bytes: &[u8]) -> crate::Result<()> {
        self.0.push(bytes.to_vec());
        Ok(())
    }
}

/// One case: a window with a history (sometimes lapping the ring, sometimes
/// a solid predecessor member), a live repeat state (sometimes with unset
/// slots), a declared member end (sometimes inside the block), and a random
/// tape of every operation kind: literal runs short and long, fresh matches
/// near, far, overlapping, past the window and past what the stream holds,
/// repeats of every slot, the last length, and now and then a filter.
#[cfg(feature = "parallel")]
struct SymbolCase {
    declared: u64,
    ceiling: u64,
    history: Vec<u8>,
    solid: bool,
    state: super::MatchState,
    tape: super::tape::BlockTape,
    unpacked_slack: i64,
}

/// Push `op` onto a random tape, carrying the `LITS` just before it as its
/// prefix where `fold` says so and that run fits one (the sequence op,
/// `tape::PREFIX_MAX`), so the walks meet both forms of the same stream.
#[cfg(feature = "parallel")]
fn push_folded(tape: &mut super::tape::BlockTape, op: super::tape::TapeOp, fold: bool) {
    use super::tape::tape_kind;
    if let Some(&last) = tape.steps.last() {
        if fold && last.kind() == tape_kind::LITS {
            tape.steps.pop();
            tape.steps.push(op.after(last.prefix()));
            return;
        }
    }
    tape.steps.push(op);
}

#[cfg(feature = "parallel")]
fn symbol_case(seed: u64) -> SymbolCase {
    use super::filters::{FilterKind, RawRecord};
    use super::tape::{tape_kind, BlockTape, TapeOp};
    let mut rng = rarkit_testdata::Seeded::new(seed);
    let declared: u64 = [128 << 10, 256 << 10, 512 << 10, 128 << 10][rng.below(4) as usize];
    // One case in eight has a ring of exactly the dictionary plus the
    // margin (a caller's stated budget), where the pass must refuse.
    let ceiling = if rng.chance(125) { declared } else { u64::MAX };
    let history_len = match rng.below(6) {
        0 => rng.below(64) as usize,
        1 => rng.below(8 << 10) as usize,
        2 => rng.below(300 << 10) as usize,
        3 => (1 << 20) + rng.below(2 << 20) as usize,
        _ => (declared as usize) + rng.below(200 << 10) as usize,
    };
    // Text-like history, so repeats of it are meaningful bytes.
    let history: Vec<u8> = (0..history_len)
        .map(|_| b"abcdefghij klmno\n"[rng.below(17) as usize])
        .collect();
    let solid = rng.chance(300);
    let reach = (history_len as u64).min(declared).max(1);
    let mut state = super::MatchState::default();
    for slot in state.repeats.iter_mut() {
        *slot = if rng.chance(100) {
            0
        } else {
            1 + rng.below(reach) as usize
        };
    }
    state.last_length = if rng.chance(100) {
        0
    } else {
        2 + rng.below(200) as usize
    };

    let mut tape = BlockTape::default();
    // One case in twelve carries an operation the walk refuses (a zero
    // distance, one past the window, one past the stream); the rest are
    // clean, so the pass is seen taken as well as refused.
    let poison = rng.chance(80);
    // Filter records only in a short tape in a full ring. A longer
    // filtered member in a ring of two drain batches meets a pre-existing
    // lap in the drain's own cadence, which the WALK trips on its own
    // (noted as open); it is not this pass's.
    let filtered = ceiling == u64::MAX && rng.chance(250);
    // One case in twenty holds a literal run past any drain batch.
    let huge = !filtered && rng.chance(50);
    // One case in four is REPEAT HEAVY: few fresh matches, so slots the
    // block never sets survive to its end and the state after it is the
    // live state's, moved by the rotations; that is what the split's
    // bookkeeping of carried slots has to get right.
    let repeat_heavy = rng.chance(250);
    let (lits_below, matches_below, repeats_below) = if repeat_heavy {
        (500, 530, 950)
    } else {
        (300, 800, 950)
    };
    let most = if rng.chance(200) { 20 } else { 4000 };
    let ops = 1 + rng.below(most) as usize;
    let mut produced_in_block = 0u64;
    let mut span_end = 0u64;
    for _ in 0..ops {
        let roll = rng.below(1000);
        if roll < lits_below {
            let length = if huge && rng.chance(3) {
                // Past any drain batch this ring has, now and then.
                (600 << 10) + rng.below(100) as usize
            } else if !filtered && rng.chance(20) {
                1000 + rng.below(70_000) as usize
            } else {
                1 + rng.below(24) as usize
            };
            for _ in 0..length {
                tape.verbatim.push(rng.below(256) as u8);
            }
            super::tape::flush_run(&mut tape.steps, length);
            produced_in_block += length as u64;
        } else if roll < matches_below {
            let behind = history_len as u64 + produced_in_block;
            let distance = if poison && rng.chance(2) {
                0
            } else if poison && rng.chance(3) {
                declared + 1 + rng.below(64)
            } else if poison && rng.chance(5) {
                behind + 1 + rng.below(100)
            } else if rng.chance(300) {
                1 + rng.below(16)
            } else if rng.chance(300) {
                1 + rng.below(declared)
            } else {
                1 + rng.below(4096)
            };
            let length = if !filtered && rng.chance(20) {
                100 + rng.below(4000) as usize
            } else {
                2 + rng.below(40) as usize
            };
            push_folded(
                &mut tape,
                TapeOp::new(tape_kind::MATCH, length, distance as u32),
                rng.chance(2),
            );
            produced_in_block += length as u64;
        } else if roll < repeats_below {
            let length = 2 + rng.below(40) as usize;
            push_folded(
                &mut tape,
                TapeOp::new(tape_kind::REP, length, rng.below(4) as u32),
                rng.chance(2),
            );
            produced_in_block += length as u64;
        } else if roll < 995 || !filtered {
            push_folded(
                &mut tape,
                TapeOp::new(tape_kind::REP_LAST, 0, 0),
                rng.chance(2),
            );
        } else {
            // Spans in start order and apart, as a genuine writer emits
            // them: overlapping spans are a hostile stream's, whose drain
            // behaviour is the walk's own question and not this pass's.
            let offset = span_end.saturating_sub(produced_in_block) + rng.below(2000);
            let length = 1 + rng.below(3000);
            span_end = produced_in_block + offset + length;
            tape.records.push(RawRecord {
                offset: offset as u32,
                length: length as u32,
                kind: FilterKind::Delta(1 + rng.below(4) as u8),
            });
            push_folded(
                &mut tape,
                TapeOp::new(tape_kind::FILTER, 0, 0),
                rng.chance(2),
            );
        }
    }
    tape.verbatim
        .resize(tape.verbatim.len() + super::output::STRIDE_MAX, 0);
    // Negative: the member's declared end falls this far inside the block
    // (modulo its length); otherwise it is far past it.
    let unpacked_slack = match rng.below(6) {
        0 => -1 - rng.below(produced_in_block.max(1)) as i64,
        _ => 1,
    };
    SymbolCase {
        declared,
        ceiling,
        history,
        solid,
        state,
        tape,
        unpacked_slack,
    }
}

/// Everything a case's apply leaves behind that a later block or the sink
/// could see.
#[cfg(feature = "parallel")]
#[derive(Debug, PartialEq, Eq)]
struct SymbolOutcome {
    result: std::result::Result<bool, String>,
    produced: u64,
    state: super::MatchState,
    pieces: Pieces,
}

/// Run one case through the walk (`gather` false) or through the symbol
/// pass with the walk as its refusal (`gather` true). Answers the outcome
/// and whether the pass took the block.
#[cfg(feature = "parallel")]
fn run_symbol_case(case: &SymbolCase, gather: bool, end: Option<u64>) -> (SymbolOutcome, bool) {
    use super::filters::Filters;
    use super::output::{NoFilters, Window};
    use super::{symbols, tape};
    use crate::carry::c_lz::codec::rar50::TapeApplied;

    let mut window = Window::new(case.declared, case.ceiling).unwrap();
    window.reset();
    let mut sink = Pieces::default();
    window.literals_chunked(&case.history, &mut sink, &mut NoFilters);
    if case.solid {
        window.drain(&mut sink, &mut NoFilters, true).unwrap();
        window.begin_member();
    }
    let mut state = case.state;
    let mut filters = Filters::default();
    // `end` is the block's own output as the walk measured it, when the
    // case wants the member's declared end to fall INSIDE the block.
    let unpacked = match end {
        Some(block) if case.unpacked_slack < 0 => {
            let cut = (case.unpacked_slack.unsigned_abs()) % block.max(1);
            window.produced() + block - cut
        }
        _ => window.produced() + (1 << 40),
    };
    let mut taken = false;
    let result = if gather {
        let mut built = symbols::Symbols::default();
        built.build(&case.tape, case.declared as usize);
        match symbols::apply(
            &built,
            &mut state,
            &mut window,
            &mut filters,
            unpacked,
            &mut sink,
        ) {
            Ok(Some(applied)) => {
                taken = true;
                Ok(applied)
            }
            Ok(None) => tape::apply(
                &case.tape,
                &mut state,
                &mut window,
                &mut filters,
                unpacked,
                &mut sink,
            ),
            Err(err) => Err(err),
        }
    } else {
        tape::apply(
            &case.tape,
            &mut state,
            &mut window,
            &mut filters,
            unpacked,
            &mut sink,
        )
    };
    let result = result
        .map(|a| matches!(a, TapeApplied::BlockDone))
        .map_err(|e| format!("{:?}", e.kind()));
    // What is still in the ring leaves too, so a byte the gather got wrong
    // cannot hide behind the drain cadence.
    if result.is_ok() {
        let _ = window.drain(&mut sink, &mut filters, true);
    }
    (
        SymbolOutcome {
            result,
            produced: window.produced(),
            state,
            pieces: sink,
        },
        taken,
    )
}

/// THE DIFFERENTIAL: every random case, walked and gathered on twin
/// windows, leaves the same bytes in the same drain pieces, the same
/// repeat state and last length, the same stop and the same error. It
/// also requires the pass to have been TAKEN on a large share of the cases
/// and REFUSED on some, so it cannot pass by never running.
#[cfg(feature = "parallel")]
#[test]
fn a_symbol_pass_block_is_the_walk_byte_for_byte_piece_for_piece() {
    let cases = 1_500u64;
    let mut taken = 0u64;
    for seed in 0..cases {
        let case = symbol_case(seed);
        // The block's output, measured by the walk with no end in the way,
        // so a case can put the member's end inside it.
        let (whole, _) = run_symbol_case(&case, false, None);
        let before = case.history.len() as u64 * u64::from(!case.solid);
        let block = whole.produced.saturating_sub(before);
        let (walk, _) = run_symbol_case(&case, false, Some(block));
        let (pass, took) = run_symbol_case(&case, true, Some(block));
        taken += u64::from(took);
        assert_eq!(walk.result, pass.result, "case {seed}: result");
        assert_eq!(walk.produced, pass.produced, "case {seed}: produced");
        assert_eq!(walk.state, pass.state, "case {seed}: repeat state");
        assert_eq!(
            walk.pieces.0.len(),
            pass.pieces.0.len(),
            "case {seed}: drain piece count"
        );
        for (i, (a, b)) in walk.pieces.0.iter().zip(&pass.pieces.0).enumerate() {
            assert!(a == b, "case {seed}: drain piece {i} differs");
        }
    }
    eprintln!("symbol pass taken on {taken} of {cases} cases");
    assert!(
        taken >= cases / 6 && taken < cases,
        "the pass was taken on {taken} of {cases} cases: the test must see it both taken and refused"
    );
}

/// THE LANE FORM DIFFERENTIAL:
/// the lean build and the first
/// build make the same symbols, ends, reach, longest literal, state after
/// the block, prefix tape and readiness, field for field, on every random
/// tape the walk differential uses and on a second draw of them cut to
/// their first few operations (splits, restarts and tiny blocks). The lean
/// form's `Symbols` is REUSED across cases, a lane's steady state, so a
/// stale end or symbol left by a longer earlier block would show; the first
/// form's is fresh. It also requires both readinesses to be seen.
#[cfg(feature = "parallel")]
#[test]
fn the_lean_lane_build_makes_the_first_builds_symbols_field_for_field() {
    use super::symbols::Symbols;
    let mut lean = Symbols::default();
    let (mut ready, mut not_ready) = (0u64, 0u64);
    for seed in 0..3_000u64 {
        let mut case = symbol_case(seed);
        if seed >= 1_500 {
            // Short tapes: a split near the end, a refusal, nothing to gather.
            let keep = 1 + (seed as usize % 40);
            case.tape.steps.truncate(keep);
        }
        let declared = case.declared as usize;
        let mut first = Symbols::default();
        first.build(&case.tape, declared);
        lean.build_lean(&case.tape, declared);
        let (a, b) = (first.fields(), lean.fields());
        if a.is_some() {
            ready += 1;
        } else {
            not_ready += 1;
        }
        assert!(a == b, "case {seed}: the lean build differs from the first");
    }
    eprintln!("lane forms agree: {ready} ready, {not_ready} not");
    assert!(
        ready > 300 && not_ready > 300,
        "{ready} ready, {not_ready} not"
    );

    // A ZERO-LENGTH copy and a repeat of that zero last length, by hand:
    // no decoded tape carries one (a match is at least two long), so the
    // random tapes never reach the branch that writes such an operation's
    // end; the two forms must still agree on it (a mutation that dropped
    // that end went uncaught without this case).
    use super::tape::{tape_kind, BlockTape, TapeOp};
    let mut tape = BlockTape {
        verbatim: (0..3000u32).map(|i| (i % 251) as u8).collect(),
        ..BlockTape::default()
    };
    tape.steps.push(TapeOp::lits(2000));
    tape.steps.push(TapeOp::new(tape_kind::MATCH, 0, 5));
    tape.steps.push(TapeOp::new(tape_kind::REP_LAST, 0, 0));
    tape.steps.push(TapeOp::lits(10));
    tape.steps.push(TapeOp::new(tape_kind::MATCH, 0, 40));
    tape.steps.push(TapeOp::new(tape_kind::REP_LAST, 0, 0));
    tape.steps.push(TapeOp::new(tape_kind::MATCH, 3, 7));
    tape.steps.push(TapeOp::new(tape_kind::REP_LAST, 0, 0));
    tape.verbatim.resize(3000 + super::output::STRIDE_MAX, 0);
    let mut first = Symbols::default();
    first.build(&tape, 128 << 10);
    lean.build_lean(&tape, 128 << 10);
    assert!(
        first.fields().is_some(),
        "the zero-length case is gatherable"
    );
    assert!(
        first.fields() == lean.fields(),
        "the lean build differs from the first on a zero-length copy"
    );
}

/// THE LEAN LANE BUILD ON THE WALK DIFFERENTIAL'S OWN TERMS: every random
/// case applied through the pass with its symbols built in the lean form
/// leaves exactly what the walk leaves.
#[cfg(feature = "parallel")]
#[test]
fn a_lean_symbol_block_is_the_walk_byte_for_byte_piece_for_piece() {
    use super::filters::Filters;
    use super::output::{NoFilters, Window};
    use super::{symbols, tape};
    let mut taken = 0u64;
    for seed in 0..1_500u64 {
        let case = symbol_case(seed);
        let (walk, _) = run_symbol_case(&case, false, None);
        let mut window = Window::new(case.declared, case.ceiling).unwrap();
        window.reset();
        let mut sink = Pieces::default();
        window.literals_chunked(&case.history, &mut sink, &mut NoFilters);
        if case.solid {
            window.drain(&mut sink, &mut NoFilters, true).unwrap();
            window.begin_member();
        }
        let mut state = case.state;
        let mut filters = Filters::default();
        let unpacked = window.produced() + (1 << 40);
        let mut built = symbols::Symbols::default();
        built.build_lean(&case.tape, case.declared as usize);
        let result = match symbols::apply(
            &built,
            &mut state,
            &mut window,
            &mut filters,
            unpacked,
            &mut sink,
        ) {
            Ok(Some(applied)) => {
                taken += 1;
                Ok(applied)
            }
            Ok(None) => tape::apply(
                &case.tape,
                &mut state,
                &mut window,
                &mut filters,
                unpacked,
                &mut sink,
            ),
            Err(err) => Err(err),
        }
        .map(|a| matches!(a, crate::carry::c_lz::codec::rar50::TapeApplied::BlockDone))
        .map_err(|e| format!("{:?}", e.kind()));
        if result.is_ok() {
            let _ = window.drain(&mut sink, &mut filters, true);
        }
        assert_eq!(walk.result, result, "case {seed}: result");
        assert_eq!(walk.produced, window.produced(), "case {seed}: produced");
        assert_eq!(walk.state, state, "case {seed}: repeat state");
        assert!(walk.pieces == sink, "case {seed}: drain pieces");
    }
    assert!(
        taken >= 250,
        "the lean pass was taken on only {taken} cases"
    );
}

/// A RAR 5 archive of one text member at a 128 KiB dictionary, written by
/// this crate's own writer: large enough to be several blocks, so the tape
/// path runs its lanes and the symbol pass is reachable at all, which no
/// vector archive is (each is one or two blocks).
/// An archive of one member, `len` bytes of text, compressed at level 3
/// in a dictionary of `dictionary` bytes by this crate's own writer.
#[cfg(feature = "parallel")]
fn written_text(len: usize, dictionary: u64) -> Vec<u8> {
    let text = rarkit_testdata::chatter(0x7772_6974, len);
    let mut writer = crate::Writer::new(crate::WriteOptions {
        method: crate::WriteMethod::Compressed {
            level: 3,
            dictionary: Some(dictionary),
        },
        ..crate::WriteOptions::default()
    })
    .expect("options");
    writer
        .add(crate::MemberSpec {
            name: b"text.txt",
            payload: crate::Payload::Bytes(&text),
            mtime: None,
            attributes: 0o100644,
            host_os: crate::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let mut out = Vec::new();
    writer.finish_into(&mut out).expect("write");
    out
}

#[cfg(all(feature = "parallel", feature = "test-support", feature = "repo-tests"))]
fn written_md128k(len: usize) -> Vec<u8> {
    written_text(len, 128 << 10)
}

/// THE SYMBOL PASS REACHED, on a real multi-block member at 128 KiB: the
/// pass forced on gathers blocks (counted, so the test cannot pass by never
/// running) and gives exactly the bytes the walk gives; a damaged copy
/// stops with the same error and the same bytes either way.
#[cfg(all(feature = "parallel", feature = "test-support", feature = "repo-tests"))]
#[test]
fn the_symbol_pass_takes_a_written_md128k_member_and_changes_no_byte() {
    let _counter = LANE_COUNTER.lock().unwrap_or_else(|e| e.into_inner());
    use super::symbols::{set_dial, GATHERED};
    let data = written_md128k(3 << 20);
    let member = members(&data)
        .into_iter()
        .find(|m| m.method != 0)
        .expect("a compressed member");
    assert!(
        member.window <= 128 << 10,
        "the member declares {}",
        member.window
    );
    let decode = |packed: &[u8], on: bool| {
        set_dial(Some(on));
        let mut lz = Rar5Lz::new(member.window, &policy()).unwrap();
        lz.set_parallel(true);
        let mut sink: Vec<u8> = Vec::new();
        let mut source = SliceSource::new(packed);
        let outcome = lz.member(&mut source, member.unpacked, member.algorithm, &mut sink);
        set_dial(None);
        (outcome.map_err(|e| format!("{:?}", e.kind())), sink)
    };
    let off = decode(&member.packed, false);
    let before = GATHERED.with(|g| g.get());
    let on = decode(&member.packed, true);
    let gathered = GATHERED.with(|g| g.get()) - before;
    assert!(off.0.is_ok(), "the member decodes: {:?}", off.0);
    assert_eq!(off.0, on.0);
    assert!(off.1 == on.1, "the bytes differ with the pass on");
    assert!(
        gathered > 0,
        "the pass gathered no block of a multi-block member"
    );
    eprintln!("written md128k member: {gathered} blocks gathered");
    for byte in (0..member.packed.len()).step_by(member.packed.len() / 23 + 1) {
        let mut packed = member.packed.clone();
        packed[byte] ^= 1 << 3;
        let off = decode(&packed, false);
        let on = decode(&packed, true);
        assert_eq!(off.0, on.0, "byte {byte}: error kind");
        assert!(off.1 == on.1, "byte {byte}: output");
    }
}

/// THE LEAN LANE BUILD ON A REAL MEMBER: the written md128k member decoded
/// with the pass on and the lane build in the lean form gives exactly the
/// walk's bytes and gathers blocks; a damaged copy stops with the same error
/// and the same bytes as the walk; and the first form agrees too.
#[cfg(all(feature = "parallel", feature = "test-support", feature = "repo-tests"))]
#[test]
fn the_lean_lane_build_takes_a_written_md128k_member_and_changes_no_byte() {
    let _counter = LANE_COUNTER.lock().unwrap_or_else(|e| e.into_inner());
    use super::symbols::{set_dial, set_form_dial, GATHERED};
    let data = written_md128k(3 << 20);
    let member = members(&data)
        .into_iter()
        .find(|m| m.method != 0)
        .expect("a compressed member");
    let decode = |packed: &[u8], on: bool, lean: bool| {
        set_dial(Some(on));
        set_form_dial(Some(lean));
        let mut lz = Rar5Lz::new(member.window, &policy()).unwrap();
        lz.set_parallel(true);
        let mut sink: Vec<u8> = Vec::new();
        let mut source = SliceSource::new(packed);
        let outcome = lz.member(&mut source, member.unpacked, member.algorithm, &mut sink);
        set_dial(None);
        set_form_dial(None);
        (outcome.map_err(|e| format!("{:?}", e.kind())), sink)
    };
    let off = decode(&member.packed, false, false);
    let before = GATHERED.with(|g| g.get());
    let lean = decode(&member.packed, true, true);
    let gathered = GATHERED.with(|g| g.get()) - before;
    let first = decode(&member.packed, true, false);
    assert!(off.0.is_ok(), "the member decodes: {:?}", off.0);
    assert_eq!(off.0, lean.0);
    assert!(off.1 == lean.1, "the bytes differ with the lean build");
    assert!(off.1 == first.1, "the bytes differ with the first build");
    assert!(gathered > 0, "the lean pass gathered no block");
    for byte in (0..member.packed.len()).step_by(member.packed.len() / 23 + 1) {
        let mut packed = member.packed.clone();
        packed[byte] ^= 1 << 3;
        let off = decode(&packed, false, false);
        let lean = decode(&packed, true, true);
        assert_eq!(off.0, lean.0, "byte {byte}: error kind");
        assert!(off.1 == lean.1, "byte {byte}: output");
    }
}
