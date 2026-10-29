//! The small member batches' DEFAULT, per architecture: what
//! ships when `RARKIT_SMALL_BATCH` is not set.
//!
//! - aarch64: pairs of at most 64 KiB declared, for `x` and for `t`;
//! - x86-64: the same pairs for `t` on every operating
//!   system, and for `x` on Linux only (elsewhere a written member stays
//!   on the walking thread unless the knob is set by name); its member
//!   team's default width differs, and `small_team.rs` pins that;
//! - every other target: none.
//!
//! AND ONLY ON TWO PHYSICAL CORES OR MORE: on one core (its SMT pair
//! included) the default is off on every architecture, because a batch
//! would put a worker on the walk's own core
//! (`read::concurrent::dials::small_batch_env`). Each test asks the
//! engine how many cores it counts (`rarkit::probe::physical_cores`),
//! says so, and on one core pins THAT arm: no batch is sent. A hosted
//! Windows runner of two hardware threads was such a machine on 6 Oct
//! 2026, where the x86-64 test read "t: no default batch was sent".
//!
//! The machine it states: a read four wide by name (`with_workers(4)`
//! and four workers, so the pool's own width is not asked), the default
//! memory policy, and a fixture of a few hundred bytes a member.
//!
//! In a test binary of its own, with ONE test compiled per architecture,
//! because the counters it reads (`rarkit::probe::peak_batch`) are
//! process-wide. Meaningful only where the process carries no
//! RARKIT_SMALL_BATCH of its own, so it says so and passes otherwise.

#![cfg(all(feature = "parallel", feature = "test-support"))]

use std::path::PathBuf;
use std::sync::Arc;

use rarkit::{
    extract_parallel, Disposition, MemberInfo, MemberOutcome, ParallelSink, RangeSource,
    ReadOptions, Result,
};

struct Sink {
    verify: bool,
}

impl ParallelSink for Sink {
    type Out = Vec<u8>;
    fn open(&self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        if member.is_directory {
            return Ok(Disposition::Skip);
        }
        Ok(if self.verify {
            Disposition::Verify
        } else {
            Disposition::Write(Vec::new())
        })
    }
    fn close(&self, _: &MemberInfo<'_>, _: Option<Vec<u8>>, _: &MemberOutcome) -> Result<()> {
        Ok(())
    }
}

/// `(most members, most declared bytes, batches sent)` for one run at the
/// default, writing (`x`) or verifying (`t`).
fn default_run(verify: bool) -> Option<(usize, u64, usize)> {
    if std::env::var_os("RARKIT_SMALL_BATCH").is_some() {
        eprintln!("RARKIT_SMALL_BATCH is set in this process: the default is not in force");
        return None;
    }
    let path = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/legacy/archives"
    ))
    .join("r550_m3.rar");
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    rarkit::probe::set_offload_floor(None);
    rarkit::probe::set_small_batch(None);
    rarkit::probe::set_small_team(None);
    rarkit::probe::reset_peak_batch();
    // The read's width stated: the DEFAULT pinned here is the batch's, and
    // without a workers figure the width is the pool's own, on which a
    // read two wide sends no pair.
    extract_parallel(
        vec![Arc::new(bytes) as Arc<dyn RangeSource>],
        &ReadOptions::default().with_workers(Some(4)),
        &Sink { verify },
        4,
    )
    .expect("parallel");
    Some(rarkit::probe::peak_batch())
}

/// Whether this machine is one the default is off on, said aloud: one
/// physical core as the engine counts them. The test then pins that no
/// batch is sent at all, writing or verifying.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn on_one_core_no_batch_is_sent() -> bool {
    let cores = rarkit::probe::physical_cores();
    if cores >= 2 {
        return false;
    }
    eprintln!(
        "this machine is {cores} physical core as the engine counts them: \
         the default batch is off here, and that is what is pinned"
    );
    for verify in [false, true] {
        let Some((_, _, sent)) = default_run(verify) else {
            return true;
        };
        assert_eq!(
            sent, 0,
            "verify {verify}: a batch was sent by default on one physical core"
        );
    }
    true
}

#[cfg(target_arch = "aarch64")]
#[test]
fn the_aarch64_default_batches_x_and_t_in_pairs() {
    if on_one_core_no_batch_is_sent() {
        return;
    }
    for verify in [false, true] {
        let Some((most, most_bytes, sent)) = default_run(verify) else {
            return;
        };
        assert!(sent >= 1, "verify {verify}: no default batch was sent");
        assert_eq!(most, 2, "verify {verify}: the default batch is a pair");
        assert!(
            most_bytes <= 64 << 10,
            "verify {verify}: {most_bytes} bytes"
        );
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn the_x86_64_default_batches_t_everywhere_and_x_on_linux_only() {
    if on_one_core_no_batch_is_sent() {
        return;
    }
    let Some((most, most_bytes, sent)) = default_run(true) else {
        return;
    };
    assert!(sent >= 1, "t: no default batch was sent");
    assert_eq!(most, 2, "t: the default batch is a pair");
    assert!(most_bytes <= 64 << 10, "t: {most_bytes} bytes");
    let Some((most, most_bytes, sent)) = default_run(false) else {
        return;
    };
    if cfg!(target_os = "linux") {
        assert!(sent >= 1, "x on Linux: no default batch was sent");
        assert_eq!(most, 2, "x on Linux: the default batch is a pair");
        assert!(most_bytes <= 64 << 10, "x on Linux: {most_bytes} bytes");
    } else {
        assert_eq!(
            sent, 0,
            "x off Linux: a written member was batched by default"
        );
    }
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
#[test]
fn elsewhere_the_default_sends_no_batch() {
    for verify in [false, true] {
        let Some((_, _, sent)) = default_run(verify) else {
            return;
        };
        assert_eq!(sent, 0, "verify {verify}: a batch was sent by default");
    }
}
