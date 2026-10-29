//! Item FUZZ-08OCT-1, found by `fuzz:rar5_member` on 8 Oct 2026 at main
//! 46a1d5bd5: one short RAR 5 member, and the serial decode and the tape
//! path name different error kinds for it.
//!
//! The input is the fuzzer's own, minimised, and is also pinned as the
//! seed `fuzz/seeds/rar5_member/arms-disagree-truncated-against-incomplete-member`.
//! The property is the one the target states (SPEC-H2 section 3.8): both
//! arms stop with the same error kind and the same bytes before it. This
//! test does not say which of the two kinds is the right one.
//!
//! The probe decodes into a 1 MiB window with a declared size of 256 KiB,
//! so the test needs a few megabytes and whatever width the probe's own
//! policy takes; the member is 14 bytes and ends at once at any width.
//! Without the `parallel` feature there is no tape path and nothing to
//! compare.

/// `8b db 0a 00` and ten bytes of `7b`: sha256 06a0c537a9f6a9de, 14 bytes.
#[cfg(feature = "parallel")]
const MEMBER: [u8; 14] = [
    0x8b, 0xdb, 0x0a, 0x00, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b, 0x7b,
];

#[cfg(feature = "parallel")]
#[test]
#[ignore = "FUZZ-08OCT-1: fails at 46a1d5bd5 (Truncated against IncompleteMember); un-ignore with the fix"]
fn a_short_member_stops_with_one_error_kind_in_both_arms() {
    use rarkit::internals::rar5;
    const UNPACKED: u64 = 1 << 18;
    const WINDOW: u64 = 1 << 20;
    let serial = rar5::decode_member_probe(&MEMBER, UNPACKED, WINDOW, 0, false);
    let tape = rar5::decode_member_probe(&MEMBER, UNPACKED, WINDOW, 0, true);
    assert!(serial.1.is_some(), "a 14 byte member cannot give 256 KiB");
    assert_eq!(serial.1, tape.1, "the two arms disagree on the error kind");
    assert_eq!(
        serial.0, tape.0,
        "the two arms disagree on the bytes before it"
    );
}
