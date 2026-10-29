//! Spec F 6.3 target 2: `extract` over the same corpus with a sink that
//! returns errors at member boundaries the fuzzer picks.
//!
//! Asserted: every path ends in a returned `Error`, never a panic;
//! `released` is monotone on every run; and a member that had its `open`
//! accepted always gets its `close`.

#![no_main]

#[path = "f_support.rs"]
mod support;

use std::sync::Arc;

use libfuzzer_sys::fuzz_target;
use rarkit::{extract, ErrorKind, MemoryPolicy, RangeSource, ReadOptions};
use support::{pick, Choppy, Fickle, Monotone, VECTORS};

fuzz_target!(|data: &[u8]| {
    if data.len() < 12 {
        return;
    }
    let chunk = data[0];
    let seed = data[1];
    let budget = data[2];
    let refuse = u64::from_le_bytes(data[3..11].try_into().expect("eight bytes"));
    let body = &data[11..];

    let base = pick(VECTORS, seed).1;
    let mut bytes = base.to_vec();
    if !body.is_empty() && seed & 1 == 0 {
        let at = usize::from(seed) * 13 % bytes.len();
        for (i, b) in body.iter().enumerate().take(bytes.len() - at) {
            bytes[at + i] ^= b;
        }
    }
    let src: Arc<dyn RangeSource> = Choppy::new(bytes, chunk);
    let opts = ReadOptions::default()
        .with_memory(MemoryPolicy::from_limit(
            1u64 << (20 + u32::from(budget % 10)),
        ))
        .with_password(Some(rarkit::Password::from("Secret")))
        // The budget byte's bit 6: the walk reads on THROUGH damage
        // (`ReadOptions::read_damaged`), as a command line does. Every
        // property below holds there too: a returned error and never a
        // panic, monotone releases, a close for every accepted open, and
        // the decode-ahead path's answer the sequential path's.
        .with_read_damaged(budget & 0x40 != 0)
        // Every member is SHOWN, older versions of a file included. With
        // them hidden (the default) the engine passes such a member over
        // without an `open` and still counts it, by design, so the
        // "counted members were opened" property below would not hold on
        // an archive that has one. No vector has one, and a mutation that
        // sets the older container's version flag (0x0800) used to die on
        // the header's checksum; read through damage, it does not (found
        // by this target in its first four minutes with the bit above).
        .with_versions(true);
    // The budget byte's HIGH bit (its low part only picks the budget):
    // the sequential entry point with DECODE-AHEAD (`read::sequential`),
    // every member offered to a worker, held to the sequential path's own
    // answer on the same input. The two must agree on every close, on how
    // many members were opened and on the outcome (SPEC-API 4.4).
    let ahead = budget & 0x80 != 0;
    let opts = if ahead {
        rarkit::probe::set_offload_floor(Some(0));
        opts.with_workers(Some(4))
    } else {
        opts
    };
    let control = ahead.then(|| {
        rarkit::probe::set_seq_ahead(Some(false));
        let mut sink = Fickle::new(refuse);
        let mut progress = Monotone::default();
        let outcome = extract(vec![Arc::clone(&src)], &opts, &mut sink, &mut progress)
            .map(|r| (r.members, r.bytes, r.checksum_failures))
            .map_err(|e| format!("{:?}", e.kind()));
        rarkit::probe::set_seq_ahead(Some(true));
        (outcome, sink.opened, sink.closed)
    });
    let mut sink = Fickle::new(refuse);
    let mut progress = Monotone::default();
    let outcome = extract(vec![src], &opts, &mut sink, &mut progress);
    if let Some((want, opened, closed)) = control {
        rarkit::probe::set_seq_ahead(None);
        rarkit::probe::set_offload_floor(None);
        let have = outcome
            .as_ref()
            .map(|r| (r.members, r.bytes, r.checksum_failures))
            .map_err(|e| format!("{:?}", e.kind()));
        assert_eq!(want, have, "decode-ahead changed the outcome");
        assert_eq!(opened, sink.opened, "decode-ahead changed the opens");
        assert_eq!(closed, sink.closed, "decode-ahead changed the closes");
    }
    match outcome {
        Ok(report) => {
            assert!(report.checksum_failures <= report.members);
            // An extraction that did not happen is never reported as
            // success: every member the report counted was offered to the
            // sink and closed with its own outcome.
            assert!(
                report.members <= u64::from(sink.opened),
                "the report counted {} members from {} opens",
                report.members,
                sink.opened
            );
            assert_eq!(
                sink.closed.len() as u64,
                report.members,
                "every counted member is closed"
            );
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
            other => panic!("unexpected kind from extract: {other:?}"),
        },
    }
});
