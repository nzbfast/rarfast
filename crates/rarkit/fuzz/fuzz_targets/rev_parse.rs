//! SPEC-L section 6: arbitrary bytes as a RAR 5 `.rev` header. No panic
//! and no allocation sized by the declared volume count before the header
//! size that bounds it; a header that parses describes a payload inside
//! the file.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let volume = data.to_vec();
    if let Ok(info) = rarkit::rev5::inspect(&volume) {
        assert!(info.data_count >= 1);
        assert!(info.recovery_count >= 1);
        assert!(info.row < info.recovery_count);
        assert_eq!(info.data_volumes.len(), info.data_count as usize);
        assert!(info.payload.end <= volume.len() as u64);
        // Verifying the payload reads only what the header declared.
        let _ = info.verify_payload(&volume);
        // A header always agrees with itself.
        assert!(info.same_set(&info));
    }
});
