//! The apply walk's arms and the far list's knob.

#[allow(unused_imports)]
use super::*;

/// WHICH ARM OF THE APPLY LOOP'S PER-OPERATION WALK RUNS, for the
/// attribution the 22 Sep per-operation work asks for.
///
/// Every structural direction off the apply stage is measured closed:
/// in-lane match resolution by its own
/// ceiling, the deeper hand-off, the ring floor, the in-place write, the
/// literal-run fold, the stride ladder. What is left is the cost of ONE
/// operation inside `tape::apply`, and a lever there is worth writing
/// only if the thing it removes is worth more than the instrument's own
/// floor. So the cost is SUBTRACTED before anything is built, the way
/// the near-match path was priced and then not written.
///
/// Most of these arms produce WRONG BYTES on purpose. They are upper
/// BOUNDS: an arm that removes a check or a store entirely costs what
/// the best possible lever against it could cost, and a bound at the
/// noise floor closes that direction without a lever being written. They
/// are reachable only through this dial, only with `test-support`, and
/// the loop is monomorphised per arm so no arm pays for another's
/// existence: the shipped walk is the same instructions whether the dial
/// is compiled in or not.
#[cfg(feature = "h2-apply-arms")]
pub mod apply_arms {
    /// The walk that ships. Every check and every store in place.
    pub const SHIPPED: u8 = 0;
    /// `MatchState::fresh`'s FOUR element write cut to ONE: the new
    /// distance is stored and the three that shift back are not. WRONG
    /// BYTES wherever a later repeat names a slot this would have
    /// moved, and the walk seeds the four slots once per tape so a
    /// repeat naming an unset slot cannot turn the arm into an early
    /// ERROR, which would read as a saving worth the rest of the
    /// member.
    ///
    /// This is the bound on the named candidate and it is deliberately
    /// the candidate's own SHAPE rather than a fantasy: a four slot
    /// ring with a head index writes one slot per fresh match too, and
    /// pays an index add on top. 6.74 million fresh matches on
    /// `rar5_incompressible_64m`.
    pub const NO_FRESH: u8 = 1;
    /// The match copy's distance validation removed. BYTE EXACT on a
    /// valid archive, where the check never fires, so this bounds the
    /// hoist that is still to do rather than a fantasy.
    pub const NO_RANGE: u8 = 2;
    /// The match copy's bytes not written, the write point advanced as
    /// though they were. WRONG BYTES. The bound on the whole match arm,
    /// which is what says whether the walk or the copy is the cost.
    pub const NO_MATCH_COPY: u8 = 3;
    /// The literal run's bytes not written, the write point advanced as
    /// though they were. WRONG BYTES. The bound on the whole literal
    /// arm, for the same reason.
    pub const NO_LIT_STORE: u8 = 4;
    /// Neither arm's bytes written: what the walk alone costs, which is
    /// the floor every other figure in the table is read against.
    pub const NO_STORES: u8 = 5;
    /// Every copy reads its source from at most [`NEAR_SOURCE_REACH`]
    /// back, where it hits the cache, and writes the same count of bytes
    /// through the same path. WRONG BYTES. The CEILING on any prefetch of
    /// the match copy's source: a perfect hint
    /// could hide the far miss and nothing more, and this arm has none.
    pub const NEAR_SOURCE: u8 = 6;
    /// How far back [`NEAR_SOURCE`] reads: inside an L1 data cache on
    /// every box this project measures on, and at least a stride, so the
    /// fast copy's conditions are the shipped copy's.
    pub const NEAR_SOURCE_REACH: usize = 1024;
    /// A WRAPPED match (its source behind the ring's start) whose
    /// source's whole stride reach ends inside the ring takes the stride
    /// copy instead of the slow path. BYTE EXACT. The BOUND on any lever
    /// that makes the wrapped copy fast: what the slow path
    /// costs, by subtraction, with the rest of the walk the shipped one.
    /// Since that lever landed (the edge form in `Window::copy_match`) the
    /// shipped copy takes these sources itself, so on this tree the arm is
    /// the shipped walk in a separate instance: a PLACEMENT control, and
    /// the subtraction it was written for is repeated on a pre-lever tree.
    pub const WRAP_STRIDE: u8 = 7;
    /// The highest arm this dial knows, so a lab can walk them.
    pub const LAST: u8 = WRAP_STRIDE;
}

#[cfg(feature = "h2-apply-arms")]
thread_local! {
    /// The apply walk arm this thread's next RAR 5 extraction runs on.
    pub(super) static APPLY_ARM: Cell<u8> = const { Cell::new(apply_arms::SHIPPED) };
}

/// Run this thread's next RAR 5 extractions with one arm of the apply
/// walk ablated. See [`apply_arm`]: most arms produce WRONG BYTES and
/// exist to bound a lever before it is written.
#[cfg(feature = "h2-apply-arms")]
pub fn set_apply_arm(arm: u8) {
    let _ = APPLY_ARM.try_with(|c| c.set(arm));
}

/// The arm this thread asked for.
#[cfg(all(feature = "parallel", feature = "h2-apply-arms"))]
pub(crate) fn apply_arm() -> u8 {
    APPLY_ARM.try_with(Cell::get).unwrap_or(apply_arms::SHIPPED)
}

#[cfg(any(feature = "h2-apply-arms", feature = "h2-far-list-knob"))]
thread_local! {
    /// Whether this thread's next RAR 5 extractions walk a tape that
    /// carries a far list with `tape::apply_listed`. `None` defers to
    /// `RARKIT_FAR_LIST`, then to the shipped `tape::FAR_LIST`. A
    /// MEASURING ARM behind `h2-far-list-knob` or `h2-apply-arms`, so the
    /// gate binary, which turns `test-support` on, compiles none of it.
    pub(super) static FAR_LIST: Cell<Option<bool>> = const { Cell::new(None) };
}

/// Run this thread's next RAR 5 extractions with the far list's walk on
/// (`Some(true)`), off (`Some(false)`: every tape walked as main walks it),
/// or as the environment and then the shipped default say (`None`). Every
/// setting writes the same bytes: a hint changes no state.
#[cfg(any(feature = "h2-apply-arms", feature = "h2-far-list-knob"))]
pub fn set_far_list(on: Option<bool>) {
    let _ = FAR_LIST.try_with(|c| c.set(on));
}

/// This thread's far list dial.
#[cfg(all(
    feature = "parallel",
    any(feature = "h2-apply-arms", feature = "h2-far-list-knob")
))]
pub(crate) fn far_list() -> Option<bool> {
    FAR_LIST.try_with(Cell::get).unwrap_or(None)
}
