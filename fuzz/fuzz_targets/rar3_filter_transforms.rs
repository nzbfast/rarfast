//! Spec J 6.3: `(selector, parameters, bytes)` through every transform,
//! including parameters outside section 3.5's domain. No panic, and each
//! direction inverts the other wherever the transform is defined.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rarkit::internals::rar3::{rar3_transform, Rar3Transform};

fuzz_target!(|data: &[u8]| {
    if data.len() < 9 {
        return;
    }
    let t = Rar3Transform::ALL[usize::from(data[0]) % Rar3Transform::ALL.len()];
    let a = u32::from_le_bytes(data[1..5].try_into().unwrap());
    let b = u32::from_le_bytes(data[5..9].try_into().unwrap());
    let input = &data[9..];
    let mut once = vec![0u8; input.len()];
    rar3_transform(t, true, input, &mut once, a, b);
    let mut back = vec![0u8; input.len()];
    rar3_transform(t, false, &once, &mut back, a, b);
    // Section 6.2 item 1 states the inverse property for delta, RGB and
    // audio. It does NOT hold for the two address filters, and must not be
    // asserted of them: SPEC-C's x86 mapping rewrites a 4-byte field only
    // where the field's own bytes say so, so encoding can make a field the
    // decode pass then rewrites, or unmake one it would have. Those two
    // are fuzzed for "no panic, the length is kept" alone.
    //
    // Zero channels and a zero RGB width are refused by the record parser
    // (U7), and the transforms leave their output unspecified there.
    let defined = match t {
        Rar3Transform::Delta | Rar3Transform::Audio => a >= 1,
        Rar3Transform::Rgb => a >= 3 && a % 3 == 0,
        Rar3Transform::X86Call | Rar3Transform::X86CallJump | Rar3Transform::Itanium => false,
    };
    assert_eq!(once.len(), input.len(), "a transform kept the span's length");
    if defined {
        assert_eq!(back, input, "{t:?} a={a} b={b} does not invert");
    }
    // The other order, over the same bytes.
    let mut enc = vec![0u8; input.len()];
    rar3_transform(t, false, input, &mut enc, a, b);
    let mut dec = vec![0u8; input.len()];
    rar3_transform(t, true, &enc, &mut dec, a, b);
    if defined {
        assert_eq!(dec, input, "{t:?} a={a} b={b} does not invert the other way");
    }
});
