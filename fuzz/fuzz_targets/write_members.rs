//! SPEC-G section 6.4: a structured member list, written and read back.
//!
//! The assertion is spec G section 4's whole-package promise: no panic on
//! any caller input, and either an error or an archive rarkit's own
//! reader opens with the same members.
#![no_main]

use libfuzzer_sys::fuzz_target;

mod plan;

fuzz_target!(|data: &[u8]| {
    let Some(plan) = plan::Plan::decode(data) else {
        return;
    };
    // The pipelining DEPTH is a width and never a byte: a solid run is
    // staged and parsed in batches, and the same plan written at any
    // depth is the same archive. `write_volumes` drives this over a
    // volume set, which is where a boundary can cut a batch in half;
    // this drives it over whatever shape the plan chose, single archive
    // included, where the scope rule says the bytes must not move at all.
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
            "a solid archive written at depth {depth} is not the one depth 1 writes"
        );
    }
    plan.run();
});
