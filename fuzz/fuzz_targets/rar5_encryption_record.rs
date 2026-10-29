//! Spec K 6: parse and judge a RAR 5 encryption record from arbitrary
//! bytes with a fixed password: the exponent bound and every length check.
//! First byte: bit 0 selects the file record (with IV) over the archive one.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rarkit::internals::crypto::{Rar5Keys, Rar5Record};

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    if let Ok(rec) = Rar5Record::parse(rest, mode & 1 != 0) {
        assert!(rec.log2 <= 24);
        // Fuzz builds clamp the exponent to 4 (spec K 6).
        let keys = Rar5Keys::derive(b"Secret", &rec.salt, rec.log2, None).unwrap();
        if let Some(check) = &rec.check {
            let _ = keys.judge_record(check);
        }
        let _ = keys.stored_word_under_key(0x1234_5678);
    }
});
