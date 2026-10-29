//! Spec F 6.3 target 1: `Archive::open` over the vectors, mutated, with a
//! `RangeSource` that answers short reads of random length.
//!
//! Asserted: no panic, no allocation above the policy (an over-budget
//! archive is `LimitExceeded`, not an allocation failure), and no call
//! that does not return.

#![no_main]

#[path = "f_support.rs"]
mod support;

use libfuzzer_sys::fuzz_target;
use rarkit::{Archive, ErrorKind, MemoryPolicy, ReadOptions};
use support::{pick, Choppy, VECTORS};

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let (chunk, seed, budget) = (data[0], data[1], data[2]);
    let body = &data[3..];
    // Half the runs start from a vector and splice the fuzzer's bytes in,
    // so the walk reaches real header shapes; half are raw input.
    let bytes = if seed & 1 == 0 {
        let base = pick(VECTORS, seed >> 1).1;
        let mut out = base.to_vec();
        if !body.is_empty() {
            let at = usize::from(seed) * 7 % out.len();
            for (i, b) in body.iter().enumerate().take(out.len() - at) {
                out[at + i] ^= b;
            }
        }
        out
    } else {
        body.to_vec()
    };
    let src = Choppy::new(bytes, chunk);
    // A small budget exercises the LimitExceeded paths of spec F 4.2.
    let limit = 1u64 << (20 + u32::from(budget % 10));
    let opts = ReadOptions::default()
        .with_memory(MemoryPolicy::from_limit(limit))
        // Half the runs keep what the walk parsed before the damage
        // instead of refusing the archive, which is the path that hands a
        // caller members from a source the fuzzer has just cut short.
        .with_tolerant_tail(budget & 1 == 0)
        // A quarter of the runs read on THROUGH damage
        // (`ReadOptions::read_damaged`): a header whose checksum failed is
        // used, the quick open record is consulted for a copy of it, and
        // damage behind a member that continues is not looked at. Those
        // are the paths a command line reads untrusted archives by.
        .with_read_damaged(budget & 0x60 == 0x60);
    match Archive::open(src, &opts) {
        Ok(archive) => {
            let mut names = 0usize;
            for member in archive.members() {
                names += member.name.len();
                let _ = member.name_lossy();
                assert!(member.data.end >= member.data.start);
            }
            assert!(names as u64 <= opts.memory.max_member_table);
            for block in archive.blocks() {
                assert!(block.range.end >= block.range.start);
            }
            let members = archive.members().len() as u32;
            for service in archive.services() {
                // A service record is never a member, and its position
                // among them is one a caller can merge on.
                assert!(service.before_member <= members);
                assert!(service.header.data.end >= service.header.data.start);
                let _ = service.header.name_lossy();
                let _ = service.recovery_percent;
            }
            // A tail is reported only when it was asked for, and never on
            // an archive the walk reached the end of.
            assert!(archive.tail().is_none() || opts.tolerant_tail);
            // A header read through its failed checksum is reported only
            // when that was asked for, the report is bounded, and a
            // member it names is one the archive lists.
            let damaged = archive.damaged_headers();
            assert!(damaged.is_empty() || opts.read_damaged);
            assert!(damaged.len() <= rarkit::DAMAGED_HEADERS_KEPT);
            for header in damaged {
                assert!(header.range.end >= header.range.start);
                assert!(header.member.is_none_or(|index| index < archive.members().len()));
            }
            let _ = archive.comment();
        }
        Err(e) => {
            // Every refusal is a named kind, never a panic or an
            // allocation failure.
            match e.kind() {
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
                other => panic!("unexpected kind from open: {other:?}"),
            }
        }
    }
});
