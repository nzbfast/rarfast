//! Sweep L-13 (4 Oct 2026): a dictionary of 2 GiB or more over a run
//! longer than 2 GiB is REFUSED by name before a byte is written, and
//! everything short of that line still writes.
//!
//! The encoder's history is capped at a span of 2 GiB and a slide keeps
//! the dictionary, so at a FITTED dictionary of 2 GiB or more a run (the
//! largest member, or the whole set where it is solid) longer than the
//! span outgrew what the chains were sized for: a build with overflow
//! checks panicked in the chains' wave with part of the archive written.
//! The fit is to the input, so the line is drawn where the sizes are
//! known (`Run::new`), not on the named figure.
//!
//! **Width and memory.** Every write here names `workers: Some(2)`, so it
//! is two threads wide on any machine of two or more. The refusals and the
//! fitted cases read no member byte and hold a few MiB. The two writes of
//! whole GiB are `#[ignore]`d: each says what it holds.
use rarkit::{
    extract, Disposition, Entropy, Error, ErrorKind, FilterPolicy, MemberInfo, MemberOutcome,
    MemberSpec, MemoryPolicy, Payload, RangeSource, ReadOptions, Result, Sink, Unsupported,
    WriteFormat, WriteMethod, WriteOptions, Writer,
};
use std::io::Read;
use std::sync::Arc;

const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;

/// `len` bytes of words, a block of a little over 1 MiB again and again:
/// text every level compresses, so no member is stored.
struct Words {
    block: Vec<u8>,
    at: u64,
    len: u64,
    /// How many bytes were asked of it.
    pulled: u64,
}

impl Words {
    fn new(len: u64) -> Self {
        Words {
            block: rarkit_testdata::chatter(0x7370_616e, (1 << 20) + 4_099),
            at: 0,
            len,
            pulled: 0,
        }
    }
}

impl Read for Words {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = (self.len - self.at).min(buf.len() as u64) as usize;
        let mut done = 0;
        while done < left {
            let from = ((self.at + done as u64) % self.block.len() as u64) as usize;
            let n = (self.block.len() - from).min(left - done);
            buf[done..done + n].copy_from_slice(&self.block[from..from + n]);
            done += n;
        }
        self.at += left as u64;
        self.pulled += left as u64;
        Ok(left)
    }
}

/// A policy that budgets the format's largest dictionary: the default's
/// ceiling is 1 GiB, and the line this file is about lies above it.
fn roomy() -> MemoryPolicy {
    MemoryPolicy {
        working_limit: 1 << 40,
        max_dictionary: 4 * GIB,
        max_window: 4 * GIB,
        ..MemoryPolicy::default()
    }
}

fn options(level: u8, dictionary: u64, solid: bool) -> WriteOptions {
    WriteOptions {
        format: WriteFormat::Rar5,
        method: if level == 0 {
            WriteMethod::Stored
        } else {
            WriteMethod::Compressed {
                level,
                dictionary: Some(dictionary),
            }
        },
        solid,
        filters: FilterPolicy::Off,
        entropy: Entropy::Seeded([5; 32]),
        workers: Some(2),
        memory: roomy(),
        ..WriteOptions::default()
    }
}

/// Write readers of `lens` bytes as one archive, answering the archive (or
/// the refusal), what was written before a refusal, and the bytes pulled.
fn write(options: WriteOptions, lens: &[u64]) -> (std::result::Result<(), Error>, Vec<u8>, u64) {
    let mut readers: Vec<Words> = lens.iter().map(|&len| Words::new(len)).collect();
    let names: Vec<Vec<u8>> = (0..lens.len())
        .map(|i| format!("m{i}.txt").into_bytes())
        .collect();
    let mut out = Vec::new();
    let result = {
        let mut writer = Writer::new(options).expect("options");
        for ((reader, name), &size) in readers.iter_mut().zip(&names).zip(lens) {
            writer
                .add(MemberSpec {
                    name,
                    payload: Payload::Reader {
                        reader,
                        size,
                        crc32: None,
                    },
                    mtime: None,
                    attributes: 0o100644,
                    host_os: rarkit::HostOs::Unix,
                    is_directory: false,
                })
                .expect("add");
        }
        writer.finish_into(&mut out).map(|_| ())
    };
    let pulled = readers.iter().map(|reader| reader.pulled).sum();
    (result, out, pulled)
}

fn refused_by_name(what: &str, options: WriteOptions, lens: &[u64]) {
    let (result, out, pulled) = write(options, lens);
    let error = result.expect_err(what);
    match error.kind() {
        ErrorKind::Unsupported(Unsupported::WriteFeature(reason)) => {
            assert!(
                reason.contains("dictionary of 2 GiB or more") && reason.contains("1 GiB writes"),
                "{what}: the refusal names the dictionary and the one that writes: {reason}"
            );
        }
        other => panic!("{what}: refused as {other:?}"),
    }
    assert!(out.is_empty(), "{what}: {} bytes were written", out.len());
    assert_eq!(pulled, 0, "{what}: member bytes were read");
}

#[test]
fn a_dictionary_of_2_gib_or_more_over_a_longer_run_is_refused_with_nothing_written() {
    // The two shapes that panicked at a04189031, by their sizes alone: a
    // refusal reads no member byte.
    let long = 2 * GIB + 300 * MIB;
    refused_by_name("4 GiB, one member", options(1, 4 * GIB, false), &[long]);
    refused_by_name("2 GiB, solid", options(1, 2 * GIB, true), &[460 * MIB; 5]);
    // And the line itself, at every level: one byte over the span.
    for level in 1u8..=5 {
        refused_by_name(
            "2 GiB, a byte over",
            options(level, 2 * GIB, false),
            &[2 * GIB + 1],
        );
    }
}

/// Reads an archive back, every member verified and none kept.
#[derive(Default)]
struct Verified(usize);

impl Sink for Verified {
    type Out = Vec<u8>;
    fn open(&mut self, _member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        Ok(Disposition::Verify)
    }
    fn close(
        &mut self,
        _member: &MemberInfo<'_>,
        _out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        assert_eq!(outcome.checksum_ok, Some(true), "a member's checksum");
        self.0 += 1;
        Ok(())
    }
}

fn writes_and_verifies(what: &str, options: WriteOptions, lens: &[u64]) {
    let (result, out, pulled) = write(options, lens);
    result.unwrap_or_else(|error| panic!("{what}: {error}"));
    assert_eq!(pulled, lens.iter().sum::<u64>(), "{what}: every byte read");
    let sources: Vec<Arc<dyn RangeSource>> = vec![Arc::new(out)];
    let mut sink = Verified::default();
    let read = ReadOptions::default()
        .with_memory(roomy())
        .with_workers(Some(2));
    extract(sources, &read, &mut sink, &mut ()).unwrap_or_else(|error| panic!("{what}: {error}"));
    assert_eq!(sink.0, lens.len(), "{what}: every member verified");
}

#[test]
fn a_large_named_dictionary_fitted_under_the_line_still_writes() {
    // The dictionary is fitted to the input before the line is read, so a
    // named 2 or 4 GiB over small members is neither refused nor 2 GiB.
    // A few MiB held.
    writes_and_verifies("4 GiB named, 3 MiB", options(1, 4 * GIB, false), &[3 * MIB]);
    writes_and_verifies(
        "2 GiB named, solid 3 MiB",
        options(3, 2 * GIB, true),
        &[MIB; 3],
    );
}

#[test]
fn a_stored_set_longer_than_the_span_is_not_refused_for_its_dictionary() {
    // A stored write has no encoder history. By its sizes alone: the
    // refusal would come before any byte, so a write that gets as far as
    // reading its member was not refused. The reader ends early, which
    // is the error this expects instead.
    struct Short;
    impl Read for Short {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
    }
    let mut reader = Short;
    let mut writer = Writer::new(options(0, 0, false)).expect("options");
    writer
        .add(MemberSpec {
            name: b"m.bin",
            payload: Payload::Reader {
                reader: &mut reader,
                size: 2 * GIB + 1,
                crc32: None,
            },
            mtime: None,
            attributes: 0o100644,
            host_os: rarkit::HostOs::Unix,
            is_directory: false,
        })
        .expect("add");
    let error = writer
        .finish_into(std::io::sink())
        .expect_err("a reader that ends early");
    assert!(
        !matches!(
            error.kind(),
            ErrorKind::Unsupported(Unsupported::WriteFeature(_))
        ),
        "a stored write was refused: {error}"
    );
}

#[test]
#[ignore = "2.46 GiB through a 1 GiB dictionary: 9.8 GiB peak resident, 108 s optimised on an M5 Max; run in release with --ignored"]
fn the_largest_dictionary_under_the_line_writes_a_run_longer_than_the_span() {
    writes_and_verifies(
        "1 GiB, 2.46 GiB",
        options(1, GIB, false),
        &[2 * GIB + 300 * MIB],
    );
}

#[test]
#[ignore = "2 GiB through a 2 GiB dictionary: 10.8 GiB peak resident, 73 s optimised on an M5 Max; run in release with --ignored"]
fn a_2_gib_dictionary_writes_a_run_of_exactly_the_span() {
    writes_and_verifies("2 GiB, 2 GiB", options(1, 2 * GIB, false), &[2 * GIB]);
}
