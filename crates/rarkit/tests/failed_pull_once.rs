//! A reader whose pull has FAILED is never pulled again (spec G 3.7.2: a
//! payload is read through exactly once).
//!
//! **The defect this pins, found 1 Oct 2026 in the solid-volume-batch work
//! on
//! main, in ONE archive.** A solid batch pulls its members' readers whole,
//! ahead of the writer. A member the store rule samples (spec G 3.8.3, at
//! least 1 MiB) whose pull failed as a LATER member of a batch was left
//! for the writer to report when it reached that member; but the writer
//! takes the member's vote first, and the vote pulled the reader again. A
//! reader that has failed reads as ended (the command line's source does),
//! so the write ended `Truncated`, "the bytes ran out early", and the
//! reader's own error, the one a member at a time reports, was lost.
//!
//! The vote now leaves such a member to its own encode, which returns the
//! error the pull failed with.

use std::io::Read;

use rarkit::{ErrorKind, MemberSpec, Payload, WriteFormat, WriteMethod, WriteOptions, Writer};

/// Serves `good` bytes, fails ONCE with an error of its own, and after
/// that reads as ended.
struct Failing<'a> {
    bytes: &'a [u8],
    good: usize,
    failed: bool,
    /// How many times a read was asked of it after it had failed.
    read_after: usize,
}

impl Read for Failing<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.failed {
            self.read_after += 1;
            return Ok(0);
        }
        if self.good == 0 {
            self.failed = true;
            return Err(std::io::Error::other("the reader's own failure"));
        }
        let count = buffer.len().min(self.bytes.len()).min(self.good);
        buffer[..count].copy_from_slice(&self.bytes[..count]);
        self.bytes = &self.bytes[count..];
        self.good -= count;
        Ok(count)
    }
}

#[test]
fn a_sampled_member_whose_pull_failed_in_a_batch_is_not_pulled_again() {
    // Small members, then one the store rule samples, then small ones: the
    // sampled member is a later member of the run's first batch, so the
    // batch itself pulls it.
    let mut members: Vec<(String, Vec<u8>)> = (0..4u64)
        .map(|i| {
            (
                format!("a{i}.c"),
                rarkit_testdata::chatter(i + 1, 20_000 + i as usize * 311),
            )
        })
        .collect();
    members.push((
        "sampled.txt".into(),
        rarkit_testdata::chatter(50, 1_200_000),
    ));
    members
        .extend((0..3u64).map(|i| (format!("b{i}.c"), rarkit_testdata::chatter(i + 60, 15_000))));
    let failing = 4;

    for (family, format) in [
        ("rar5", WriteFormat::Rar5),
        ("rar4", WriteFormat::Rar4(rarkit::Rar4Version::V29)),
    ] {
        // Batched, and a member at a time (pipelining depth 1).
        for depth in [usize::MAX, 1] {
            let mut readers: Vec<Failing<'_>> = members
                .iter()
                .enumerate()
                .map(|(index, (_, data))| Failing {
                    bytes: data,
                    good: if index == failing {
                        data.len() / 2
                    } else {
                        usize::MAX
                    },
                    failed: false,
                    read_after: 0,
                })
                .collect();
            let mut write = || {
                let mut writer = Writer::new(WriteOptions {
                    format,
                    method: WriteMethod::Compressed {
                        level: 3,
                        dictionary: Some(2 << 20),
                    },
                    solid: true,
                    order: rarkit::MemberOrder::AsAdded,
                    filters: if matches!(format, WriteFormat::Rar4(_)) {
                        rarkit::FilterPolicy::Off
                    } else {
                        rarkit::FilterPolicy::default()
                    },
                    ..WriteOptions::default()
                })
                .expect("options");
                for ((name, data), reader) in members.iter().zip(readers.iter_mut()) {
                    writer
                        .add(MemberSpec {
                            name: name.as_bytes(),
                            payload: Payload::Reader {
                                reader,
                                size: data.len() as u64,
                                crc32: None,
                            },
                            mtime: None,
                            attributes: 0,
                            host_os: rarkit::HostOs::Unix,
                            is_directory: false,
                        })
                        .expect("add");
                }
                writer.finish_into(Vec::new()).map(|_| ())
            };
            let outcome = if depth == 1 {
                rarkit::internals::writers::with_batch_depth(1, write)
            } else {
                write()
            };
            let error = outcome.expect_err("a failing reader is an error");
            assert!(
                matches!(error.kind(), ErrorKind::Caller),
                "{family} at depth {depth}: the write ended in \"{error}\" and not in the reader's own error"
            );
            assert_eq!(
                readers[failing].read_after, 0,
                "{family} at depth {depth}: the reader was read again after it had failed"
            );
        }
    }
}
