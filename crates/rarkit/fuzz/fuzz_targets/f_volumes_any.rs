//! Spec F 6.3 target 3: a set built from the vector volumes with fragments
//! shuffled, truncated, duplicated and swapped between sets.
//!
//! The property asserted is the one spec F 3.5.4 exists for: **no run
//! produces output bytes for a member whose fragments came from two
//! different sets.** Every run ends in a clean extraction or a named
//! `Corrupt` / `Truncated`.

#![no_main]

#[path = "f_support.rs"]
mod support;

use std::sync::{Arc, OnceLock};

use libfuzzer_sys::fuzz_target;
use rarkit::{extract, ErrorKind, RangeSource, ReadOptions};
use support::{Choppy, Monotone, CVOL, SVOL};

/// The one correct payload of `rand.bin`, extracted from the intact set.
fn reference() -> &'static Vec<u8> {
    static ONCE: OnceLock<Vec<u8>> = OnceLock::new();
    ONCE.get_or_init(|| {
        let volumes: Vec<Arc<dyn RangeSource>> = SVOL
            .iter()
            .map(|v| Arc::new(v.to_vec()) as Arc<dyn RangeSource>)
            .collect();
        let mut progress = Monotone::default();
        let mut out = Vec::new();
        struct Keep<'a>(&'a mut Vec<u8>);
        impl rarkit::Sink for Keep<'_> {
            type Out = Vec<u8>;
            fn open(
                &mut self,
                _m: &rarkit::MemberInfo<'_>,
            ) -> rarkit::Result<rarkit::Disposition<Vec<u8>>> {
                Ok(rarkit::Disposition::Write(Vec::new()))
            }
            fn close(
                &mut self,
                _m: &rarkit::MemberInfo<'_>,
                o: Option<Vec<u8>>,
                _outcome: &rarkit::MemberOutcome,
            ) -> rarkit::Result<()> {
                if let Some(o) = o {
                    *self.0 = o;
                }
                Ok(())
            }
        }
        let mut keep = Keep(&mut out);
        extract(volumes, &ReadOptions::default(), &mut keep, &mut progress)
            .expect("the intact set extracts");
        out
    })
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let want = reference();
    let chunk = data[0];
    let count = usize::from(data[1] % 6) + 1;
    let mut volumes: Vec<Arc<dyn RangeSource>> = Vec::with_capacity(count);
    for step in 0..count {
        let pick = *data.get(2 + step).unwrap_or(&0);
        // Draw each volume from either set, so fragments of two different
        // sets meet whenever the fuzzer wants them to.
        let pool: &[&[u8]] = if pick & 0x08 == 0 { SVOL } else { CVOL };
        let mut bytes = pool[usize::from(pick >> 4) % pool.len()].to_vec();
        // Truncate some of them.
        if pick & 0x04 != 0 && !bytes.is_empty() {
            let keep = bytes.len() * usize::from(pick & 0x03 | 1) / 4;
            bytes.truncate(keep);
        }
        volumes.push(Choppy::new(bytes, chunk));
    }

    struct Check<'a> {
        want: &'a [u8],
    }
    impl rarkit::Sink for Check<'_> {
        type Out = Vec<u8>;
        fn open(
            &mut self,
            _m: &rarkit::MemberInfo<'_>,
        ) -> rarkit::Result<rarkit::Disposition<Vec<u8>>> {
            Ok(rarkit::Disposition::Write(Vec::new()))
        }
        fn close(
            &mut self,
            member: &rarkit::MemberInfo<'_>,
            out: Option<Vec<u8>>,
            outcome: &rarkit::MemberOutcome,
        ) -> rarkit::Result<()> {
            // A member delivered with a PASSING verdict must be the real
            // one: a set spliced from two archives can never reach here.
            if outcome.checksum_ok == Some(true) && member.name == b"rand.bin" {
                let bytes = out.unwrap_or_default();
                assert_eq!(
                    bytes.as_slice(),
                    self.want,
                    "a passing rand.bin was spliced from two sets"
                );
            }
            Ok(())
        }
    }

    // An ODD-length input runs the sequential entry point with
    // DECODE-AHEAD on (`read::sequential`) and every member offered to a
    // worker: a split member never goes ahead, so this holds the driver's
    // volume boundaries and its drop-behind to the same properties.
    let ahead = data.len() % 2 == 1;
    let opts = if ahead {
        rarkit::probe::set_seq_ahead(Some(true));
        rarkit::probe::set_offload_floor(Some(0));
        ReadOptions::default().with_workers(Some(4))
    } else {
        ReadOptions::default()
    };
    // The count byte's high bit: the walk reads on THROUGH damage
    // (`ReadOptions::read_damaged`), where a volume cut in its trailing
    // records behind a member that continues is not an error and a volume
    // whose end record was not read declares no number. The property in
    // `Check` is the one that matters most there: a set spliced from two
    // archives still never delivers a passing `rand.bin`.
    let opts = opts.with_read_damaged(data[1] & 0x80 != 0);
    let mut sink = Check { want };
    let mut progress = Monotone::default();
    let outcome = extract(volumes, &opts, &mut sink, &mut progress);
    if ahead {
        rarkit::probe::set_seq_ahead(None);
        rarkit::probe::set_offload_floor(None);
    }
    match outcome {
        Ok(_) => {}
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
            other => panic!("unexpected kind from a shuffled set: {other:?}"),
        },
    }
});
