//! Under a ceiling the caller NAMED, ONE member is charged the finder its
//! own class builds, read from its head before the refusal (FROM-STUDIO
//! 841), and not the larger of level 5's two: an engine builds the finder
//! its member's class calls for and no other. Counted 25 Oct 2026 on macOS
//! at `-m5 -md32m`: 34 MiB of lines of words held the chains' 260 MiB and
//! 34 MiB of prose the tree's 384, and with the tree charged to both the
//! lines were refused under the `-mm512m` that 0.9.0 wrote them at.
//!
//! What each test pins:
//!
//! - THE SAME BYTES: the head read before the refusal is the buffer the
//!   store rule's samples and the encode then read; a reader is read once,
//!   every byte in order, and never past its end;
//! - NO BYTE MOVES: the archive is the one no ceiling writes, from a
//!   reader and from bytes in memory;
//! - the tree member is still charged the tree, and is refused where its
//!   working memory cannot be held;
//! - A SINGLE MEMBER ONLY: two members are charged both finders, and are
//!   refused where each alone is admitted;
//! - a head that cannot be read is charged the tree, and the reader's own
//!   error is what the write reports, where it would have been.
//!
//! The ceiling is the one the CLI's `-mm512m` gives the engine: a working
//! limit of 432 MiB and 80 MiB kept for the process. Threads: the
//! machine's default width. Memory: up to about 450 MiB a write.

use rarkit::{
    ErrorKind, HostOs, MemberSpec, MemoryPolicy, Payload, WriteMethod, WriteOptions, Writer,
};
use std::io::Read;

const MIB: usize = 1 << 20;

/// A xorshift generator, the same on every run.
struct Draw(u64);

impl Draw {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

const WORDS: [&str; 24] = [
    "the", "quick", "brown", "fox", "jumps", "over", "a", "lazy", "dog", "volume", "member",
    "archive", "listing", "every", "part", "of", "set", "and", "memory", "process", "figure",
    "named", "window", "history",
];

/// `size` bytes of lines of twelve words of 24: the CHAINS' class.
fn lines(seed: u64, size: usize) -> Vec<u8> {
    let mut draw = Draw(seed);
    let mut body = String::with_capacity(size + 96);
    while body.len() < size {
        for word in 0..12 {
            if word > 0 {
                body.push(' ');
            }
            body.push_str(WORDS[(draw.next() % WORDS.len() as u64) as usize]);
        }
        body.push('\n');
    }
    body.truncate(size);
    body.into_bytes()
}

const CONSONANTS: [&str; 12] = ["b", "c", "d", "f", "g", "l", "m", "n", "p", "r", "s", "t"];
const VOWELS: [&str; 8] = ["a", "e", "i", "o", "u", "an", "er", "in"];

/// `size` bytes of lines of ten words drawn from 20,000 made-up words of
/// two to four syllables: the TREE's class.
fn prose(seed: u64, size: usize) -> Vec<u8> {
    let mut draw = Draw(seed);
    let syllable = |draw: &mut Draw| {
        let pick = (draw.next() % (CONSONANTS.len() * VOWELS.len()) as u64) as usize;
        [CONSONANTS[pick / VOWELS.len()], VOWELS[pick % VOWELS.len()]].concat()
    };
    let vocab: Vec<String> = (0..20_000)
        .map(|_| {
            let count = 2 + draw.next() % 3;
            (0..count).map(|_| syllable(&mut draw)).collect()
        })
        .collect();
    let mut body = String::with_capacity(size + 256);
    while body.len() < size {
        for word in 0..10 {
            if word > 0 {
                body.push(' ');
            }
            body.push_str(&vocab[(draw.next() % vocab.len() as u64) as usize]);
        }
        body.push_str(".\n");
    }
    body.truncate(size);
    body.into_bytes()
}

/// A reader over `data` that counts what it serves, and that fails with
/// an error of its own once `fails_at` bytes are served, where given.
struct Counted<'a> {
    data: &'a [u8],
    served: usize,
    fails_at: Option<usize>,
}

impl Read for Counted<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.fails_at.is_some_and(|at| self.served >= at) {
            return Err(std::io::Error::other("the source went away"));
        }
        let end = self.data.len().min(self.served + buf.len());
        let end = self.fails_at.map_or(end, |at| end.min(at.max(self.served)));
        let n = end - self.served;
        buf[..n].copy_from_slice(&self.data[self.served..end]);
        self.served = end;
        Ok(n)
    }
}

/// The CLI's `-mm512m` as the engine sees it.
fn named_512() -> MemoryPolicy {
    let mut policy = MemoryPolicy::from_limit(432 * MIB as u64);
    policy.process_overhead = 80 * MIB as u64;
    policy
}

fn options(memory: Option<MemoryPolicy>) -> WriteOptions {
    let mut options = WriteOptions {
        method: WriteMethod::Compressed {
            level: 5,
            dictionary: Some(32 * MIB as u64),
        },
        refuse_over_ceiling: memory.is_some(),
        ..WriteOptions::default()
    };
    if let Some(memory) = memory {
        options.memory = memory;
    }
    options
}

fn spec<'a>(name: &'a [u8], payload: Payload<'a>) -> MemberSpec<'a> {
    MemberSpec {
        name,
        payload,
        mtime: None,
        attributes: 0,
        host_os: HostOs::Unix,
        is_directory: false,
    }
}

/// Members from readers over `bodies`, under `memory`: the archive or the
/// error, and what each reader served.
fn from_readers(
    bodies: &[&[u8]],
    memory: Option<MemoryPolicy>,
    fails_at: Option<usize>,
) -> (rarkit::Result<Vec<u8>>, Vec<usize>) {
    let mut readers: Vec<Counted<'_>> = bodies
        .iter()
        .map(|data| Counted {
            data,
            served: 0,
            fails_at,
        })
        .collect();
    let names: Vec<Vec<u8>> = (0..bodies.len())
        .map(|i| format!("m{i}.txt").into_bytes())
        .collect();
    let result = (|| {
        let mut writer = Writer::new(options(memory))?;
        for ((reader, name), data) in readers.iter_mut().zip(&names).zip(bodies) {
            writer.add(spec(
                name,
                Payload::Reader {
                    reader,
                    size: data.len() as u64,
                    crc32: None,
                },
            ))?;
        }
        let mut out = Vec::new();
        writer.finish_into(&mut out)?;
        Ok(out)
    })();
    (result, readers.iter().map(|reader| reader.served).collect())
}

fn from_bytes(data: &[u8], memory: Option<MemoryPolicy>) -> rarkit::Result<Vec<u8>> {
    let mut writer = Writer::new(options(memory))?;
    writer.add(spec(b"m0.txt", Payload::Bytes(data)))?;
    let mut out = Vec::new();
    writer.finish_into(&mut out)?;
    Ok(out)
}

fn refused(result: &rarkit::Result<Vec<u8>>) -> bool {
    matches!(result, Err(error) if matches!(error.kind(), ErrorKind::LimitExceeded { .. }))
}

#[test]
fn one_chains_member_is_admitted_under_a_named_512_and_written_as_with_no_ceiling() {
    let data = lines(0x5eed_0034_7e47_0001, 34 * MIB);
    let (free, _) = from_readers(&[&data], None, None);
    let free = free.expect("no ceiling");
    let (named, served) = from_readers(&[&data], Some(named_512()), None);
    let named = named.expect("one chains member is charged the chains, and fits");
    assert_eq!(served, [data.len()], "the reader is read once, every byte");
    assert!(named == free, "a named ceiling moved a byte");
    // Bytes in memory take their own path (a region from the slice, where a
    // reader is fed a window at a time), so they are held to their own
    // archive with no ceiling.
    let from_memory = from_bytes(&data, Some(named_512())).expect("from bytes too");
    let memory_free = from_bytes(&data, None).expect("no ceiling");
    assert!(
        from_memory == memory_free,
        "a named ceiling moved a byte of a member in memory"
    );
}

#[test]
fn one_tree_member_is_charged_the_tree() {
    let data = prose(0x5eed_0034_9705_0001, 34 * MIB);
    let (named, _) = from_readers(&[&data], Some(named_512()), None);
    assert!(
        refused(&named),
        "the tree's 384 MiB and its history pass 432 MiB"
    );
}

#[test]
fn two_members_are_charged_both_finders() {
    let first = lines(0x5eed_0034_7e47_0001, 34 * MIB);
    let second = lines(0x5eed_0034_7e47_0002, 34 * MIB);
    let (named, _) = from_readers(&[&first, &second], Some(named_512()), None);
    assert!(refused(&named), "two members can call both classes");
}

#[test]
fn a_head_that_cannot_be_read_reports_the_readers_error() {
    let data = lines(0x5eed_0034_7e47_0001, 34 * MIB);
    let mut wide = MemoryPolicy::from_limit(2048 * MIB as u64);
    wide.process_overhead = 80 * MIB as u64;
    let (named, _) = from_readers(&[&data], Some(wide), Some(100 << 10));
    let error = named.expect_err("the source went away");
    assert!(
        !matches!(error.kind(), ErrorKind::LimitExceeded { .. }),
        "the reader's error, not a refusal: {error}"
    );
}
