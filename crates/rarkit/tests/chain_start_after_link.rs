//! A RAR 5 redirection member does not spend the start of a solid chain
//! (spec F 3.6.1 F6: a redirection member "takes nothing from the stream";
//! 3.6.2 D9: a first member that carries the bit is decoded as though it
//! did not, there being nothing before it).
//!
//! `chain_start_after_link/lead-link-solid.rar` is GENUINE: rar 7.23 for
//! macOS, `rar a -s -ol -ds -m3`, a symbolic link `a_link`, then `b.txt`
//! (2,430 bytes, bit clear) and `c.txt` (2,475 bytes, bit set). The
//! genuine writer leaves the bit clear on the first file behind leading
//! links, so the genuine archive never asked the question. The crafted
//! arms set a member's bit in its compression information and redo that
//! header's CRC32, nothing else:
//!
//! - `b.txt`'s bit set: the first member that has a stream now carries
//!   the bit, with only a link in front of it. unrar 7.23 and rar 7.23
//!   (10 Oct 2026, aarch64 macOS) test it All OK, exit 0. The reader
//!   refused `b.txt` as `Corrupt(Stream)` and failed `c.txt` behind it,
//!   because the link had counted as the set's first member.
//! - the link's bit set as well: the same answer from both programs.
//!
//! Every read runs through `extract` at one worker and at four; the
//! archive is 361 bytes and the reads hold the decoder's ordinary working
//! memory for a 1 MiB dictionary, nothing sized by the test.

use std::sync::Arc;

use rarkit::{
    extract, Disposition, MemberInfo, MemberOutcome, RangeSource, ReadOptions, Result, Sink,
};

const GENUINE: &[u8] = include_bytes!("chain_start_after_link/lead-link-solid.rar");

/// Where each file header starts, and where its compression information
/// byte sits (one byte in all three).
const LINK: (usize, usize) = (24, 42);
const B_TXT: (usize, usize) = (73, 93);
const C_TXT: (usize, usize) = (252, 272);

const B_CRC: u32 = 0xa523_64be;
const C_CRC: u32 = 0xc94a_d915;

#[derive(Default)]
struct Keep {
    members: Vec<(String, Option<bool>, Vec<u8>)>,
}

impl Sink for Keep {
    type Out = Vec<u8>;

    fn open(&mut self, member: &MemberInfo<'_>) -> Result<Disposition<Vec<u8>>> {
        if member.redirection.is_some() {
            return Ok(Disposition::Verify);
        }
        Ok(Disposition::Write(Vec::new()))
    }

    fn close(
        &mut self,
        member: &MemberInfo<'_>,
        out: Option<Vec<u8>>,
        outcome: &MemberOutcome,
    ) -> Result<()> {
        self.members.push((
            String::from_utf8_lossy(member.name).into_owned(),
            outcome.checksum_ok,
            out.unwrap_or_default(),
        ));
        Ok(())
    }
}

/// The genuine archive with the solid bit set on each member of `set`.
fn with_bits(set: &[(usize, usize)]) -> Vec<u8> {
    let mut archive = GENUINE.to_vec();
    for &(start, comp) in set {
        assert_eq!(archive[comp] & 0x40, 0, "the bit is clear as written");
        archive[comp] |= 0x40;
        // CRC32, then the header size in one byte, then that many bytes.
        let end = start + 5 + usize::from(archive[start + 4]);
        let crc = crc32fast::hash(&archive[start + 4..end]);
        archive[start..start + 4].copy_from_slice(&crc.to_le_bytes());
    }
    archive
}

fn read(archive: Vec<u8>, workers: usize) -> (Keep, Option<String>) {
    let source: Arc<dyn RangeSource> = Arc::new(archive);
    let mut sink = Keep::default();
    let options = ReadOptions::default().with_workers(Some(workers));
    let ended = extract(vec![source], &options, &mut sink, &mut ());
    (sink, ended.err().map(|e| format!("{:?}", e.kind())))
}

fn all_good(archive: &[u8], arm: &str) {
    for workers in [1, 4] {
        let (kept, ended) = read(archive.to_vec(), workers);
        let at = format!("{arm}, {workers} workers");
        assert_eq!(ended, None, "{at}");
        let seen: Vec<(&str, Option<bool>)> = kept
            .members
            .iter()
            .map(|(name, ok, _)| (name.as_str(), *ok))
            .collect();
        assert_eq!(
            seen,
            [
                ("a_link", Some(true)),
                ("b.txt", Some(true)),
                ("c.txt", Some(true)),
            ],
            "{at}"
        );
        assert_eq!(kept.members[1].2.len(), 2430, "{at}");
        assert_eq!(crc32fast::hash(&kept.members[1].2), B_CRC, "{at}");
        assert_eq!(kept.members[2].2.len(), 2475, "{at}");
        assert_eq!(crc32fast::hash(&kept.members[2].2), C_CRC, "{at}");
    }
}

#[test]
fn the_genuine_archive_reads_whole() {
    assert_eq!(GENUINE[C_TXT.1] & 0x40, 0x40, "c.txt continues as written");
    all_good(GENUINE, "genuine");
}

/// The first member with a stream carries the bit and only a link stands
/// before it: it starts the chain, as the reference reads it.
#[test]
fn a_solid_member_behind_a_leading_link_starts_the_chain() {
    all_good(&with_bits(&[B_TXT]), "b.txt's bit set");
}

/// The link's own bit changes nothing: it has no stream to continue.
#[test]
fn a_leading_link_with_its_own_bit_set_changes_nothing() {
    all_good(&with_bits(&[LINK]), "the link's bit set");
    all_good(
        &with_bits(&[LINK, B_TXT]),
        "the link's and b.txt's bits set",
    );
}
