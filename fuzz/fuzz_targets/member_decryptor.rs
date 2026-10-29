//! Spec K 6: the member decryptor with an arbitrary cipher, arbitrary
//! chunking and `finish` on arbitrary totals. Whatever the chunking, the
//! plaintext must equal one whole-buffer pass, and `update` never returns
//! more than it was given.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rarkit::internals::crypto::*;

fn cipher(kind: u8, password: &[u8]) -> MemberCipher {
    match kind % 6 {
        0 => MemberCipher::None,
        1 => MemberCipher::V13(Rar13Stream::new(password)),
        2 => MemberCipher::V15(Rar15Stream::new(password)),
        3 => MemberCipher::V20(Box::new(Rar20Block::new(password))),
        4 => MemberCipher::aes128(&Rar4Key::derive(b"Secret", Some([1; 8])).unwrap()),
        _ => MemberCipher::aes256(&Rar5Keys::derive(password, &[2; 16], 0, None).unwrap(), &[3; 16]),
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let (kind, pw_len) = (data[0], usize::from(data[1] % 16));
    let rest = &data[2..];
    let (password, rest) = rest.split_at(pw_len.min(rest.len()));
    let (sizes, payload) = rest.split_at(rest.len().min(16));
    let mut whole = payload.to_vec();
    let mut one = MemberDecryptor::new(cipher(kind, password));
    let got = one.update(&mut whole);
    assert!(got.head.is_empty() && got.body <= whole.len());
    let n = got.body;
    whole.truncate(n);
    let one_end = one.finish();

    let mut dec = MemberDecryptor::new(cipher(kind, password));
    let mut got = Vec::new();
    let mut at = 0;
    let mut i = 0;
    while at < payload.len() {
        let pick = sizes.get(i % sizes.len().max(1)).copied().unwrap_or(0);
        let n = (1 + usize::from(pick % 40)).min(payload.len() - at);
        let mut buf = payload[at..at + n].to_vec();
        let pending = dec.pending();
        let out = dec.update(&mut buf);
        assert!(out.body <= n);
        assert!(out.head.is_empty() || out.head.len() == pending);
        got.extend_from_slice(out.head);
        got.extend_from_slice(&buf[..out.body]);
        at += n;
        i += 1;
    }
    let end = dec.finish();
    assert_eq!(end.is_ok(), one_end.is_ok());
    if end.is_ok() {
        assert_eq!(got, whole);
    }
});
