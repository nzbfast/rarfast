//! Spec K 6: the RAR 5 encrypted-header walk (3.7.5) over arbitrary bytes:
//! `IV | AES-256-CBC(header)` headers, each followed by its data area, with
//! keys derived once from a fixed password and salt.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use rarkit::internals::crypto::{HeaderReader, Rar5Keys};
use rarkit::RangeSource;

fn vint(b: &[u8], at: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    for shift in (0..63).step_by(7) {
        let x = *b.get(*at)?;
        *at += 1;
        v |= u64::from(x & 0x7F) << shift;
        if x & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

fuzz_target!(|data: &[u8]| {
    static KEYS: OnceLock<Rar5Keys> = OnceLock::new();
    let keys = KEYS.get_or_init(|| Rar5Keys::derive(b"Secret", &[0x28; 16], 15, None).unwrap());
    let src: &dyn RangeSource = &data;
    let mut reader = HeaderReader::new();
    let mut pos = 0u64;
    for _ in 0..64 {
        let Ok(span) = reader.rar5(src, pos, keys) else {
            return;
        };
        let h = reader.plain();
        assert_eq!(h.len(), span.len);
        let mut at = 4;
        let (Some(_size), Some(_ty), Some(flags)) = (vint(h, &mut at), vint(h, &mut at), vint(h, &mut at)) else {
            return;
        };
        if flags & 1 != 0 && vint(h, &mut at).is_none() {
            return;
        }
        let add = if flags & 2 != 0 { vint(h, &mut at).unwrap_or(0) } else { 0 };
        let Some(next) = span.end.checked_add(add) else {
            return;
        };
        pos = next;
    }
});
