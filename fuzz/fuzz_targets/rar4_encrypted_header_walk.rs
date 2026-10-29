//! Spec K 6: the RAR 4 family encrypted-header walk (3.6.3) over arbitrary
//! bytes: `salt | AES-128-CBC(header)` blocks, each followed by its data
//! area, until a block fails or the bytes end.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rarkit::internals::crypto::{HeaderReader, KeyCache};
use rarkit::{Password, RangeSource};

fuzz_target!(|data: &[u8]| {
    let src: &dyn RangeSource = &data;
    let password = Password::from("Secret");
    let mut cache = KeyCache::new(None);
    let mut reader = HeaderReader::new();
    let mut pos = 0u64;
    for _ in 0..64 {
        let Ok(span) = reader.rar4(src, pos, &password, &mut cache) else {
            return;
        };
        let h = reader.plain();
        assert_eq!(h.len(), usize::from(span.size));
        let flags = u16::from_le_bytes([h[3], h[4]]);
        let add = if flags & 0x8000 != 0 && h.len() >= 11 {
            u64::from(u32::from_le_bytes([h[7], h[8], h[9], h[10]]))
        } else {
            0
        };
        pos = span.end + add;
    }
});
