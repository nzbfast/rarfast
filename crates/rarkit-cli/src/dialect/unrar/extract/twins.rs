//! Two members written to ONE file: found before the walk is chosen.
//!
//! The pool opens a member's output while the members before it are still
//! being written, each through a handle of its own. Where two members
//! resolve to the same file (two of one name under `x`; two of one base
//! name under `e`, which drops the directories) the later open empties the
//! file under the earlier writer, and what is left is neither member:
//! found 10 Oct 2026, `e -o+` over 8 MiB of `A` then 1,024 bytes of `B`
//! left 8,388,608 bytes at every width above one, both called `OK`.
//!
//! THE RULE: colliding destinations settle in archive order whatever the
//! width, so the file left is the one a one-thread run leaves. A sink
//! cannot hold a later member's open until an earlier one has closed
//! (the engine calls both from the walking thread), so a run that holds
//! ANY such pair takes the IN-ORDER walk whole, the one `-mt1` takes:
//! there each member is closed, and a failed one removed, before the next
//! is opened, and the default rule's question about the later member
//! follows the earlier one's line. A run of members that each have a file
//! of their own, which is nearly every run, keeps the pool and pays one
//! pass over its resolved paths for it ([`Run::destinations_collide`]).
//!
//! IN ORDER, NOT ONE THREAD: at a width above one the engine still
//! decodes ahead of that walk on its own threads and holds what it has
//! decoded until the member's turn; only the outputs are one at a time.
//! Counted 10 Oct 2026, an 18 core aarch64 laptop, `e` of six 320 MiB
//! members each beside a small file of one name, the pool against this
//! walk: stored, 0.154 s to 0.213 s and a peak of 15 MB to 1,444 MB;
//! coded, 0.166 s to 0.296 s and 145 MB to 1,673 MB (`-mt1`: 1.364 s,
//! 25 MB).
//!
//! A NAMED LIMIT: one such pair costs the whole run its pool. Holding
//! only the members of a pair for each other needs the engine to settle
//! what is in flight before one member's open, which it does not offer.
//! So the run SAYS it has left the pool ([`ONE_THREAD_NOTICE`]): a caller
//! who finds an `e` slow sees why, and `x` keeps the directories apart.
//!
//! NO READ OF THE ARCHIVE is added: the pass runs over the plan and the
//! selection the run already holds, and over the paths
//! [`Run::pool_targets`] has already resolved from them, before the walk
//! reads a byte of any member.

use super::*;

/// What a resolved path is called for this comparison: a hash of it with
/// its letters folded.
///
/// FOLDED ON EVERY SYSTEM, not only where the volume folds: whether the
/// destination's volume tells `A` from `a` costs a system call to ask and
/// differs by directory, and the answer is only ever used to choose the
/// in-order walk, which is right on either kind of volume. So two names
/// that differ only in case count as one file everywhere; on a volume
/// that keeps them apart the run is merely not pooled.
///
/// A letter is folded through its upper case and back (so the long s and
/// `s` meet, as a folding volume has them). NOT folded: two spellings of
/// one accented letter, composed and decomposed, which APFS and HFS+
/// also hold as one file; the short `8.3` alias of a long name on
/// Windows; two names of one file made by a hard link before the run.
/// Those are not seen here.
///
/// A hash and not the text, so nothing is kept per member but eight
/// bytes; two different paths of one hash only cost the run its pool.
pub(super) fn destination_key(path: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let step = |hash: u64, byte: u8| (hash ^ u64::from(byte)).wrapping_mul(PRIME);
    if path.is_ascii() {
        return path
            .iter()
            .fold(OFFSET, |hash, byte| step(hash, byte.to_ascii_lowercase()));
    }
    let mut hash = OFFSET;
    let mut utf8 = [0_u8; 4];
    for chunk in path.utf8_chunks() {
        for letter in chunk.valid().chars() {
            for upper in letter.to_uppercase() {
                for lower in upper.to_lowercase() {
                    for &byte in lower.encode_utf8(&mut utf8).as_bytes() {
                        hash = step(hash, byte);
                    }
                }
            }
        }
        // Bytes that are no text are themselves.
        for &byte in chunk.invalid() {
            hash = step(hash, byte);
        }
    }
    hash
}

/// Whether two of `members` share a destination: each is its
/// [`destination_key`] and whether it is a directory. Two directories of
/// one path are one directory, made once, and are no collision; a file or
/// a link against anything of its path is.
pub(super) fn any_two_alike(mut members: Vec<(u64, bool)>) -> bool {
    // A file sorts before a directory of its key, so a key held by a file
    // and anything else has the file in the pair's first place.
    members.sort_unstable();
    members
        .windows(2)
        .any(|pair| pair[0].0 == pair[1].0 && !pair[0].1)
}

/// What a run says, once, when it leaves the pool for members that share
/// a destination. rarfast's own words: the reference has no pool and no
/// such line.
pub(super) const ONE_THREAD_NOTICE: &str =
    "Several members share one output file: extracting one member at a time";

impl Run<'_> {
    /// [`Run::destinations_collide`], asked where the pool would otherwise
    /// drive, and the notice said when it does: a line of its own before
    /// the banner, on the stream the progress lines take, so `-idq` and
    /// `-inul` drop it with them and `-ierr` sends it with them. It is no
    /// error: nothing is counted and the exit code does not move. A run
    /// that was never going to the pool (`-mt1`, a solid archive, a run
    /// that may ask about a file already there) says nothing: it left
    /// nothing.
    pub(super) fn falls_back_to_one_at_a_time(&mut self) -> bool {
        let collide = self.destinations_collide();
        if collide {
            self.say(&format!("\n{ONE_THREAD_NOTICE}\n"));
        }
        collide
    }

    /// Whether two selected members of this `x` or `e` are written to one
    /// file, by their resolved paths ([`Run::pool_targets`]: after `e` has
    /// dropped the directories and after the host's name mapping).
    ///
    /// Asked once, where the pool would otherwise drive. Directory members
    /// under `e` are not made and are not counted.
    pub(super) fn destinations_collide(&self) -> bool {
        let Mode::Extract { flat } = self.mode else {
            return false;
        };
        if self.selected.len() < 2 {
            return false;
        }
        let mut members = Vec::with_capacity(self.selected.len());
        for &index in self.selected.iter() {
            let is_dir = self.plan[index].member.is_dir;
            if is_dir && flat {
                continue;
            }
            let path = match self.target_at.get(index) {
                Some(Target::Pooled(start, end)) => &self.targets.as_bytes()[*start..*end],
                Some(Target::Owned(path)) => path.as_os_str().as_encoded_bytes(),
                Some(
                    Target::Unresolved
                    | Target::Refused
                    | Target::Nameless
                    | Target::DestinationItself,
                )
                | None => continue,
            };
            members.push((destination_key(path), is_dir));
        }
        any_two_alike(members)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(path: &str) -> u64 {
        destination_key(path.as_bytes())
    }

    #[test]
    fn one_path_is_one_key_and_case_does_not_tell_two_apart() {
        assert_eq!(key("out/same"), key("out/same"));
        assert_eq!(key("out/Same.BIN"), key("out/same.bin"));
        assert_ne!(key("out/same"), key("out/sane"));
        assert_ne!(key("out/a/b"), key("out/ab"));
        // Beyond ASCII: an accented capital and its small letter, and the
        // long s beside `s`.
        assert_eq!(key("out/\u{c9}t\u{e9}"), key("out/\u{e9}T\u{c9}"));
        assert_eq!(key("out/me\u{17f}s"), key("out/MESS"));
        assert_ne!(key("out/\u{e9}"), key("out/e"));
    }

    #[test]
    fn bytes_that_are_no_text_are_compared_as_they_are() {
        assert_eq!(
            destination_key(b"out/caf\xe9"),
            destination_key(b"out/CAF\xe9")
        );
        assert_ne!(
            destination_key(b"out/caf\xe9"),
            destination_key(b"out/caf\xe8")
        );
    }

    #[test]
    fn a_file_against_anything_of_its_path_collides_and_two_directories_do_not() {
        assert!(!any_two_alike(Vec::new()));
        assert!(!any_two_alike(vec![(1, false), (2, false), (3, true)]));
        assert!(any_two_alike(vec![(1, false), (2, false), (1, false)]));
        assert!(any_two_alike(vec![(7, true), (2, false), (7, false)]));
        assert!(any_two_alike(vec![(7, false), (2, false), (7, true)]));
        assert!(!any_two_alike(vec![(7, true), (2, false), (7, true)]));
        assert!(any_two_alike(vec![(7, true), (7, true), (7, false)]));
    }
}
