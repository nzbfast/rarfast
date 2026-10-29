//! Spec J 6.3: arbitrary bytes as a record stream against a synthetic
//! member of arbitrary length. No panic, the queue and slot bounds of
//! section 4 hold (`rar3_record_stream` asserts them as it goes), and any
//! success delivers exactly the member's length.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rarkit::internals::rar3::rar3_record_stream;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    // A member length from the first two bytes, so one input shape covers
    // members far shorter and far longer than a span bound.
    let member_len = u64::from(u16::from_le_bytes([data[0], *data.get(1).unwrap_or(&0)])) * 97;
    if let Ok((delivered, most)) = rar3_record_stream(&data[2.min(data.len())..], member_len) {
        assert_eq!(delivered, member_len, "a member is delivered whole");
        assert!(most <= rarkit::internals::rar3::MAX_QUEUED);
    }
});
