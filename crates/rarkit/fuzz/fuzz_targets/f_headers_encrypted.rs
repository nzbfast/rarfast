//! Spec F 6.3 target 4: the two header-encrypted vectors with random
//! passwords, which drives spec F 4.4 - decrypted garbage through the
//! whole walk. A wrong password produces plausible random bytes: sizes
//! near 2^16, name lengths past the header, types nobody knows. Every
//! bound holds unchanged and the first failure is a named error.

#![no_main]

#[path = "f_support.rs"]
mod support;

use libfuzzer_sys::fuzz_target;
use rarkit::{Archive, ErrorKind, Password, ReadOptions};
use support::{Choppy, ENCRYPTED};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let which = usize::from(data[0]) % ENCRYPTED.len();
    let chunk = data[1];
    let password = &data[2..];
    let opts = ReadOptions::default().with_password((!password.is_empty()).then(|| Password::new(password)));
    let src = Choppy::new(ENCRYPTED[which].to_vec(), chunk);
    match Archive::open(src, &opts) {
        Ok(archive) => {
            for member in archive.members() {
                let _ = member.name_lossy();
            }
        }
        Err(e) => match e.kind() {
            ErrorKind::NotAnArchive
            | ErrorKind::Truncated
            | ErrorKind::Corrupt(_)
            | ErrorKind::HeaderChecksum
            | ErrorKind::PasswordRequired
            | ErrorKind::WrongPassword
            | ErrorKind::Unsupported(_)
            | ErrorKind::LimitExceeded { .. }
            | ErrorKind::Source(_)
            | ErrorKind::Caller
            | ErrorKind::Cancelled => {}
            other => panic!("unexpected kind from an encrypted header: {other:?}"),
        },
    }
});
