//! SPEC-G section 6.4: an archive from the corpus put through every
//! `edit` entry point.
//!
//! The assertion is spec G 3.15's promise: no panic, and every member
//! that SURVIVES is byte identical - checked as the listing, because a
//! member is copied rather than decoded and its packed bytes and checksum
//! are what the rewrite must preserve. Each operation says exactly which
//! listing it expects afterwards, so a rewrite that quietly dropped or
//! reordered a member fails here rather than passing as "no panic".
#![no_main]

use std::sync::Arc;

use libfuzzer_sys::fuzz_target;
use rarkit::{Archive, Checksum, RangeSource, ReadOptions};

/// One member as it is listed: the things a rewrite must not change.
type Listed = (Vec<u8>, Option<u64>, u64, Option<Checksum>);

fn listing(archive: &Archive) -> Vec<Listed> {
    archive
        .members()
        .map(|m| (m.name.to_vec(), m.unpacked_size, m.packed_size, m.checksum))
        .collect()
}

/// Reopens what a rewrite produced, which it must always be able to do.
fn reopen(bytes: Vec<u8>) -> Archive {
    let source = Arc::new(bytes) as Arc<dyn RangeSource>;
    Archive::open(source, &ReadOptions::default())
        .expect("a rewrite this crate returned Ok for did not reopen")
}

fuzz_target!(|data: &[u8]| {
    // Three bytes of script, then the archive, so that a corpus of real
    // archives is reached by a three-byte prefix.
    let Some((&operation, rest)) = data.split_first() else {
        return;
    };
    let Some((&argument, rest)) = rest.split_first() else {
        return;
    };
    let Some((&length, archive)) = rest.split_first() else {
        return;
    };

    let source = Arc::new(archive.to_vec()) as Arc<dyn RangeSource>;
    let Ok(opened) = Archive::open(source, &ReadOptions::default()) else {
        return;
    };
    let before = listing(&opened);
    let mut out = Vec::new();

    match operation % 5 {
        // The comment, which is what this target used to be on its own.
        0 => {
            let split = usize::from(length).min(archive.len());
            let comment = &archive[..split];
            let comment = (!comment.is_empty()).then_some(comment);
            if rarkit::edit::set_comment(&opened, comment, &mut out).is_err() {
                return;
            }
            let after = reopen(out);
            assert_eq!(
                before,
                listing(&after),
                "a member changed under a rewrite that only touched the comment"
            );
        }
        // The lock flag, which must not move a member either, and which
        // the reopened archive must actually report.
        1 => {
            if rarkit::edit::lock(&opened, &mut out).is_err() {
                return;
            }
            let after = reopen(out);
            assert!(after.is_locked(), "a locked rewrite did not come back locked");
            assert_eq!(
                before,
                listing(&after),
                "a member changed under a rewrite that only set the lock flag"
            );
        }
        // A removal: the listing loses exactly the members named and
        // keeps the rest, in order.
        2 => {
            if before.is_empty() {
                return;
            }
            let index = usize::from(argument) % before.len();
            let name = before[index].0.clone();
            let Ok(report) = rarkit::edit::remove(&opened, &[&name], &mut out) else {
                return;
            };
            let after = reopen(out);
            // EVERY member with that name, not the one at `index` alone
            // and not the first alone: `remove` is given a NAME, and an
            // archive may store one name twice
            // (`seeds/edit_roundtrip/rename-picks-the-first-of-two-same-names`).
            // Until 4 Oct 2026 the call took the first of them and this
            // asserted that; the reference's `d` takes them all, and so
            // does the call now (`crates/rarkit/tests/edit_members.rs`
            // pins it).
            let expected: Vec<Listed> = before
                .iter()
                .filter(|member| member.0 != name)
                .cloned()
                .collect();
            assert_eq!(
                expected,
                listing(&after),
                "a removal did not leave exactly the members it kept"
            );
            assert_eq!(
                report.members as usize,
                expected.len(),
                "the report disagrees with the archive it wrote"
            );
        }
        // A rename: one name changes, in place, wherever it is stored,
        // and nothing else does.
        3 => {
            if before.is_empty() {
                return;
            }
            let index = usize::from(argument) % before.len();
            let from = before[index].0.clone();
            // A name built from the input, kept to what a writer accepts
            // so that the interesting failures are in the rewrite rather
            // than in the name check.
            let to: Vec<u8> = (0..=length)
                .map(|step| b'a' + (step.wrapping_add(argument) % 26))
                .collect();
            let Ok(_) = rarkit::edit::rename(&opened, &from, &to, &mut out) else {
                return;
            };
            let after = reopen(out);
            // Every member with that name, as in the removal arm above:
            // `rename` too is given a name and not a position.
            let expected: Vec<Listed> = before
                .iter()
                .map(|member| {
                    let mut member = member.clone();
                    if member.0 == from {
                        member.0 = to.clone();
                    }
                    member
                })
                .collect();
            assert_eq!(
                expected,
                listing(&after),
                "a rename changed more than the one name it was given"
            );
        }
        // A recovery record, which is a service block and not a member.
        _ => {
            let percent = u32::from(argument % 100) + 1;
            if rarkit::edit::set_recovery(&opened, Some(percent), &mut out).is_err() {
                return;
            }
            let after = reopen(out);
            assert_eq!(
                before,
                listing(&after),
                "a member changed under a rewrite that only added a recovery record"
            );
        }
    }
});
