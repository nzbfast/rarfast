//! SPEC-G section 6.4: the same member list with a volume size, so that
//! the set has to read back as one member list.
#![no_main]

use libfuzzer_sys::fuzz_target;

mod plan;

/// The most volumes one execution may ask for.
///
/// THE FIVE SLOW UNITS of the 20 Sep 2026 campaign were all one shape:
/// ten bytes or fewer, `bulk` set - which repeats the first member's
/// data to about 400 KiB (`plan.rs`) - and a PAYLOAD BUDGET OF ONE
/// BYTE, which is what `data[0] * 64 + 1` is whenever `data[0]` is
/// zero, and zero is `WriteFormat::Rar5` stored non solid, the commonest
/// shape in the corpus. That is 409,600 volume files from a ten byte
/// input.
///
/// Measured on a laptop, the cargo-fuzz default build with
/// AddressSanitizer, one input per process:
///
/// | payload budget | volumes | wall |
/// |---|---:|---:|
/// | 1 B | 409,600 | 3.571 s |
/// | 17 B | 24,094 | 0.247 s |
/// | 113 B | 3,624 | 0.094 s |
/// | 4,081 B | 100 | 0.069 s |
///
/// So it is LINEAR in the volume count at about 8.6 microseconds a
/// volume, not a superlinear cost and not an engine fault: every one of
/// those volumes is a legal volume file the writer has to frame, and
/// spec G section 4 admits a budget that fits one payload byte. What it
/// is instead is this target spending its whole budget framing volumes:
/// 29 executions a second over the 600 s sweep, against 9,810 for
/// `edit_roundtrip` in the same run.
///
/// The budget is therefore floored so that the members the plan holds
/// cannot ask for more than this many volumes. A plan whose members are
/// small keeps its one byte budget, which is the edge spec G section 4
/// names; only the bulk repeat is held back.
const MOST_VOLUMES: u64 = 4096;

/// The smallest budget that keeps this plan under [`MOST_VOLUMES`].
fn budget_floor(plan: &plan::Plan) -> u64 {
    let bytes: u64 = plan.members.iter().map(|m| m.data.len() as u64).sum();
    (bytes / MOST_VOLUMES).max(1)
}

fuzz_target!(|data: &[u8]| {
    let Some(mut plan) = plan::Plan::decode(data) else {
        return;
    };
    // This target is the volume one: a plan that asked for one archive
    // gets a budget anyway, in whichever form its own bit chose, so that
    // both the PAYLOAD budget and the whole-FILE one are driven here.
    if plan.volume_size.is_none() && plan.volume_file_size.is_none() {
        let size = Some(u64::from(data[0]) * 64 + 1);
        if data[0] % 2 == 0 {
            plan.volume_size = size;
        } else {
            plan.volume_file_size = size;
        }
    }
    // Whichever budget the plan ended up with, its own or this target's,
    // held to [`MOST_VOLUMES`] volumes.
    let floor = budget_floor(&plan);
    plan.volume_size = plan.volume_size.map(|size| size.max(floor));
    plan.volume_file_size = plan.volume_file_size.map(|size| size.max(floor));
    // **The pipelining depth is not an input to the archive.** A solid
    // run in a volume set is encoded in BATCHES: several members staged
    // and parsed as one wave, with whatever batch straddles a volume
    // boundary discarded there and encoded again from the reset run
    // (spec G 3.9). The depth is a width and nothing else, so the same
    // plan written at any depth is the same bytes, and the cheapest place
    // to disbelieve that is here, over whatever member list, level, cap
    // and comment the fuzzer has just invented.
    //
    // Depth 1 stages one member per batch, which is the member-at-a-time
    // walk a volume set had before 19 Sep 2026, so the control arm is the
    // previous behaviour rather than this one's own answer.
    if plan.solid && plan.level > 0 {
        let depth = 2 + usize::from(data[data.len() - 1] % 31);
        let control = rarkit::internals::writers::with_batch_depth(1, || {
            plan.archive().map(|(volumes, _)| volumes)
        });
        let theirs = rarkit::internals::writers::with_batch_depth(depth, || {
            plan.archive().map(|(volumes, _)| volumes)
        });
        assert_eq!(
            control, theirs,
            "a solid set written at depth {depth} is not the archive depth 1 writes"
        );
    }
    plan.run();
});
