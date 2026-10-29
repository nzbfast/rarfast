//! SPEC-J section 6.3: `(selector, parameters, bytes)`. Every transform is
//! run in both directions for every parameter, including those outside the
//! domain (no panic); inside the domain each direction inverts the other.
#![no_main]
use libfuzzer_sys::fuzz_target;
use rarkit::internals::rar3::{rar3_transform, Rar3Transform as T};

fuzz_target!(|data: &[u8]| {
    let Some((head, bytes)) = data.split_first_chunk::<9>() else {
        return;
    };
    let t = [T::X86Call, T::X86CallJump, T::Itanium, T::Delta, T::Rgb, T::Audio][head[0] as usize % 6];
    let a = u32::from_le_bytes([head[1], head[2], head[3], head[4]]);
    let b = u32::from_le_bytes([head[5], head[6], head[7], head[8]]);
    let mut once = vec![0u8; bytes.len()];
    let mut twice = vec![0u8; bytes.len()];
    let in_domain = match t {
        T::Delta | T::Audio => a >= 1,
        T::Rgb => a >= 3 && a % 3 == 0,
        // SPEC-C Part 7 item 1: the address transforms invert each other
        // only while the span stays below 2 GiB into its member.
        _ => a as u64 + bytes.len() as u64 <= 1 << 31,
    };
    for decode in [true, false] {
        rar3_transform(t, decode, bytes, &mut once, a, b);
        rar3_transform(t, !decode, &once, &mut twice, a, b);
        if in_domain {
            assert_eq!(twice, bytes, "{t:?} decode={decode} a={a} b={b}");
        }
    }
});
