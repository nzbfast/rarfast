//! The encoder's worker count against the command line's `-mt`.

use super::*;

fn cores() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
}

fn opts_with(threads: Option<u64>) -> Options {
    let mut opts = Options::default();
    opts.shared.threads = threads;
    opts
}

/// `-mt<n>` on the create path lands on the ENCODER'S width dial
/// (API 7.2), bounded by what the box can actually run.
#[test]
fn the_switch_sets_the_encoder_width() {
    assert_eq!(encoder_workers(&opts_with(Some(1))), Some(1));
    assert_eq!(encoder_workers(&opts_with(Some(4))), Some(4.min(cores())));
    // Past the box's own count it saturates there, the same way the
    // pool does: `workers::width` is the one place that rule lives.
    // The parser has already bounded `-mt<n>` to the reference's
    // 1..=64, so 64 only exercises the saturating branch on a box
    // with fewer than 64 cores; deriving the expectation the way the
    // code does keeps the assertion true on a wider one too.
    assert_eq!(encoder_workers(&opts_with(Some(64))), Some(64.min(cores())));
}

/// With no `-mt` the field is left at `None`, which asks the engine
/// for the width of the pool the caller owns.
///
/// This is not the same as writing the box's core count into the
/// field, even though `memory_policy` has just sized the pool at
/// exactly that: `None` is what API 7.2 defines as "the caller's
/// pool", and a create path that spelled the number itself would go
/// on claiming a width after a caller resized the pool under it.
#[test]
fn no_switch_leaves_the_engine_to_the_pool() {
    assert_eq!(encoder_workers(&opts_with(None)), None);
}

/// And the MEMORY ceiling is no longer moved by the create path.
///
/// Until the dials were split this function set
/// `max_workers` to the encoder's width, because that was the only
/// way to reach the encoder; API 8.2 leaves the field to the stages
/// it names, the BLAKE2sp leaf team among them, and a figure derived
/// from the memory budget is the right one for those.
#[test]
fn the_create_path_leaves_the_memory_ceiling_on_its_derivation() {
    let derived = rarkit::MemoryPolicy::default().max_workers;
    for threads in [None, Some(1), Some(32)] {
        let policy = memory_policy(&opts_with(threads), &[]);
        assert_eq!(
            policy.max_workers, derived,
            "-mt{threads:?} moved the memory ceiling to {} from {derived}",
            policy.max_workers
        );
    }
}
