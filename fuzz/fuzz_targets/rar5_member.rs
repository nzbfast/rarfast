//! SPEC-H2 section 6.3: bytes in, a fixed declared size and a fixed 1 MiB
//! window, one non solid member, filters applied.
//!
//! The target also holds section 3.8's property: the member stops at the
//! same OPERATION in both arms, so the serial and the parallel decode must
//! answer byte identical output and the same error kind at the same output
//! position.
//!
//! The parallel arm is run THREE ways, because how the tape path is
//! scheduled is not allowed to change any of that either: under the
//! carried policy, under the overlap with a wave of one block (so the
//! chain crosses a wave boundary at every block and wave N+1 decodes
//! while wave N is applied), and under the bulk synchronous driver the
//! overlap replaced. The wave of one block is what puts a whole wave of
//! DEFERRED failures ahead of the member's own stop, which is section
//! 3.8's consequence 1 and the thing an overlap can break quietly.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rarkit::internals::rar5;

const UNPACKED: u64 = 1 << 18;
const WINDOW: u64 = 1 << 20;

fuzz_target!(|data: &[u8]| {
    let serial = rar5::decode_member_probe(data, UNPACKED, WINDOW, 0, false);
    assert!(serial.0.len() as u64 <= UNPACKED);
    let parallel = rar5::decode_member_probe(data, UNPACKED, WINDOW, 0, true);
    assert_eq!(serial.1, parallel.1, "the two arms disagree on the outcome");
    assert!(
        serial.0 == parallel.0,
        "the two arms disagree at {} against {} bytes",
        serial.0.len(),
        parallel.0.len()
    );
    for (workers, wave, overlap) in [(2, Some(1), true), (2, Some(1), false)] {
        let got =
            rar5::decode_member_probe_scheduled(data, UNPACKED, WINDOW, 0, workers, wave, overlap);
        assert_eq!(
            serial.1, got.1,
            "{workers} workers, wave {wave:?}, overlap {overlap}: the outcome moved"
        );
        assert!(
            serial.0 == got.0,
            "{workers} workers, wave {wave:?}, overlap {overlap}: {} against {} bytes",
            got.0.len(),
            serial.0.len()
        );
    }
});
