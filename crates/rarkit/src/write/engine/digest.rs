//! A member's digest: the running checksum of its kind, the threads it
//! may take, and what a header stores of it.

use super::*;

impl<'a, 'p, V: VolumeSource, P: Progress> Run<'a, 'p, V, P> {
    /// The threads a BLAKE2sp digest this thread takes now may use, its
    /// own included (`Blake2sp::with_workers`): the helper budget counts a team's
    /// pool threads as helpers (a thread counts while it runs this write's
    /// work), so a team is given what the helper budget leaves and no
    /// more, and never above `MemoryPolicy::max_workers`, the ceiling it
    /// had before.
    ///
    /// - While the calling thread has lent the pool (`width::lent`: the
    ///   worker team's round, or a solid batch encoding beside the pulls),
    ///   the pool may be full, so the thread that hashes, hashes alone.
    /// - Otherwise nothing else of the write runs while this thread
    ///   hashes (the encoder's calls return before the digest is fed, and
    ///   the stored copy takes its own through `Run::copy_digest`), so the
    ///   team may have every helper: `1 + N`, the carried team's leaves
    ///   being `N` threads beside this one. But only from N of 2: where
    ///   the package's own lane kernel takes a batch instead, its
    ///   `rayon::join` runs both halves on pool threads while this one
    ///   waits, which is TWO helpers whatever the allowance, so at N of 1
    ///   the digest hashes alone. (Moving the digest onto the write's pool
    ///   was tried and withdrawn: it makes the hashing thread a helper
    ///   too, and counted 30 Sep 2026 a one-shot digest at `-mt1` ran two.)
    ///
    /// A crew's digest is one thread always (`PackRule`): the crew is a
    /// helper already, and its pool is full of its fellows.
    pub(super) fn digest_threads(&self) -> usize {
        let ceiling = self.options.memory.max_workers.max(1);
        let helpers = self.helpers();
        if width::lent() || helpers < 2 {
            return 1;
        }
        ceiling.min(1 + helpers)
    }

    /// A digest for the copy of member `index`, allowed the threads the
    /// helper budget leaves once the copy's own stages have theirs.
    ///
    /// **A BLAKE2sp team's pool threads count against the helper budget too**
    /// (SPEC-API's sentence for it: a pool thread counts while it runs a
    /// task the write put in the pool). So each of the copy's BLAKE2sp
    /// streams (the member's, and a volume fragment's own) is allowed
    /// `1 + spare / streams` threads, its own included, where `spare` is
    /// the helpers the widest stage plan for this member leaves over
    /// (`Stages::plan`), and never more than `MemoryPolicy::max_workers`,
    /// the ceiling it had before. At `-mt1` that is one: the thread that
    /// hashes, hashes alone. At the default policy on a wide box it is the
    /// memory ceiling, as it was.
    pub(super) fn copy_digest(&self) -> Running {
        let ceiling = self.options.memory.max_workers;
        if self.options.checksum != ChecksumKind::Blake2sp {
            return new_running(self.options.checksum, ceiling);
        }
        let helpers = self.helpers();
        let streams = if self.options.volume_set() { 2 } else { 1 };
        let stages = if helpers == 0 {
            0
        } else {
            Stages::plan(helpers, streams, true, self.options.password.is_some()).threads()
        };
        let spare = helpers.saturating_sub(stages);
        new_running(self.options.checksum, ceiling.min(1 + spare / streams))
    }

    /// The checksum a header STORES, which under RAR 5 encryption is the
    /// member's own converted under the MAC key (spec K 3.7.6).
    pub(super) fn stored(&self, digest: Option<Digest>) -> Option<Digest> {
        match (&self.crypt, digest) {
            (Some(crypt), Some(value)) => Some(crypt.stored_digest(value)),
            (_, value) => value,
        }
    }

    /// The checksum a FRAGMENT's header stores. Only the last fragment
    /// carries a checksum the MAC key converts: one that is not the last
    /// carries its own plain checksum (spec K 3.7.6). For the RAR 4 family
    /// the two are the same, since it converts nothing.
    pub(super) fn stored_as(&self, last: bool, digest: Option<Digest>) -> Option<Digest> {
        if last {
            self.stored(digest)
        } else {
            digest
        }
    }

    // ---- checksums -------------------------------------------------------

    pub(super) fn new_digest(&self) -> Running {
        // A streamed member that rolls has its engines running while this
        // thread hashes, between its pulls too, where the pool does not
        // read as lent: the thread that hashes, hashes alone.
        if self.stream.in_flight && (self.stream.rolls || self.stream.reads_ahead) {
            return new_running(self.options.checksum, 1);
        }
        new_running(self.options.checksum, self.digest_threads())
    }

    /// A directory or an empty member: the reference writes a zero CRC32
    /// for an empty member and no checksum at all for a directory.
    pub(super) fn member_digest_empty(&self, index: usize) -> Option<Digest> {
        if self.members[index].is_directory {
            None
        } else {
            let mut digest = self.new_digest();
            digest.update(&[]);
            Some(digest.finish())
        }
    }

    /// The whole member's digest, when it can be known before the bytes
    /// are read: a slice payload, or a caller who stated its CRC32.
    ///
    /// **A slice payload is deliberately NOT read ahead when the output
    /// can seek.** Taking its digest here is a whole extra pass over the
    /// member, and the only reason to pay for it is that a `Write` cannot
    /// go back over a placeholder. When it can, the header carries a
    /// placeholder, the digest is taken as the bytes pass, and the header
    /// is corrected where it lies: one pass instead of two.
    pub(super) fn whole_digest(&self, index: usize) -> Option<Digest> {
        if let Some(digest) = self.unpacked_digest {
            return Some(digest);
        }
        // A COMPRESSED member is not this case: what its header carries
        // is the UNPACKED digest, and the bytes that pass the copy are
        // the packed ones, so there is nothing for a correction to take
        // the digest from. It is taken here, as it always was.
        if self.packed.is_empty()
            && self.out.can_patch()
            && matches!(self.members[index].payload, Payload::Bytes(_))
        {
            return None;
        }
        match (&self.members[index].payload, self.options.checksum) {
            // The one-shot pre-pass a non-seekable output asks for, at
            // what the helper budget leaves.
            (Payload::Bytes(data), checksum) => {
                Some(slice_digest(data, checksum, self.digest_threads()))
            }
            (Payload::Reader { crc32: Some(v), .. }, ChecksumKind::Crc32) => {
                Some(Digest::Crc32(*v))
            }
            _ => None,
        }
    }

    /// One fragment's own digest, when the bytes are already in hand.
    ///
    /// A slice payload over a seekable output is the same one-pass case
    /// as [`Run::whole_digest`]: the placeholder costs nothing and the
    /// extra pass over the fragment does.
    pub(super) fn fragment_digest(&self, index: usize, at: u64, len: u64) -> Option<Digest> {
        if self.packed.is_empty()
            && self.out.can_patch()
            && matches!(self.members[index].payload, Payload::Bytes(_))
        {
            return None;
        }
        // At what the helper budget leaves: during the
        // worker team's round that is this thread alone.
        let threads = self.digest_threads();
        if !self.packed.is_empty() {
            let span = &self.packed[at as usize..(at + len) as usize];
            return Some(slice_digest(span, self.options.checksum, threads));
        }
        match &self.members[index].payload {
            Payload::Bytes(data) => {
                let span = &data[at as usize..(at + len) as usize];
                Some(slice_digest(span, self.options.checksum, threads))
            }
            Payload::Reader { .. } => None,
        }
    }

    /// The CRC32 the caller stated for a reader payload, which the writer
    /// checks against the bytes that passed.
    pub(super) fn declared_crc32(&self, index: usize) -> Option<Digest> {
        match &self.members[index].payload {
            Payload::Reader { crc32: Some(v), .. }
                if self.options.checksum == ChecksumKind::Crc32 =>
            {
                Some(Digest::Crc32(*v))
            }
            _ => None,
        }
    }

    /// A digest of the right KIND and no value: a header built with it is
    /// exactly as long as one built with the real digest.
    pub(super) fn placeholder_digest(&self, index: usize) -> Option<Digest> {
        if self.members[index].is_directory {
            return None;
        }
        Some(match self.options.checksum {
            ChecksumKind::Crc32 => Digest::Crc32(0),
            ChecksumKind::Blake2sp => Digest::Blake2sp([0; 32]),
        })
    }
}

/// A digest to be computed as bytes pass.
pub(super) fn new_running(checksum: ChecksumKind, max_workers: usize) -> Running {
    match checksum {
        ChecksumKind::Crc32 => Running::Crc32(Crc32::new()),
        // Built with the threads the helper budget leaves it
        // (`Run::digest_threads`), never above the write's worker ceiling,
        // per API 8.2's table. A team engages only on a batch worth one,
        // so a member too small to want threads never meets them.
        ChecksumKind::Blake2sp => Running::Blake2sp(
            Box::new(Blake2sp::with_workers(max_workers)),
            #[cfg(test)]
            (HELPERS.with(std::sync::Arc::clone), max_workers),
        ),
    }
}

/// The digest of a whole member whose bytes are all in hand, which is
/// what `Run::whole_digest` takes for a slice payload.
pub(super) fn slice_digest(data: &[u8], checksum: ChecksumKind, max_workers: usize) -> Digest {
    // The census counts the team's threads beside this one (`hold`).
    #[cfg(test)]
    let _team = (checksum == ChecksumKind::Blake2sp).then(|| hold(team_beside(max_workers)));
    match checksum {
        ChecksumKind::Crc32 => Digest::Crc32(crate::checksum::crc32(data)),
        ChecksumKind::Blake2sp => Digest::Blake2sp(
            crate::checksum::blake2sp::blake2sp_with_workers(data, max_workers),
        ),
    }
}

/// The threads a BLAKE2sp digest allowed `threads` (its own included)
/// adds beside the thread that feeds it, as the census counts them:
/// `threads - 1`. For the carried team that is its leaf threads. Where the
/// package's own lane kernel takes the batch instead, its `rayon::join`
/// runs both halves on two pool threads while the feeding thread WAITS,
/// which is one more than the feeder alone, and `threads - 1` covers it
/// from an allowance of two. A digest the CALLER feeds is the case where
/// the waiting feeder was not counted to begin with, so there the lane
/// kernel is two helpers: `Run::digest_threads` gives such a digest a team
/// only from N of 2, where `threads - 1` is at least two.
#[cfg(test)]
pub(super) fn team_beside(threads: usize) -> usize {
    threads.saturating_sub(1)
}

/// A digest being computed as bytes pass.
pub(super) enum Running {
    Crc32(Crc32),
    /// The hasher, and under `cfg(test)` the census of the thread that
    /// built it with the threads it was allowed, its own included, on
    /// which [`Running::update`] counts the team beside the hashing thread
    /// while it hashes (`team_beside`).
    Blake2sp(
        Box<Blake2sp>,
        #[cfg(test)] (std::sync::Arc<HelperCensus>, usize),
    ),
}

impl Running {
    /// Whether this digest costs more than reading the bytes it covers,
    /// which decides where a lone helper goes (`Stages::plan`).
    pub(super) fn is_costly(&self) -> bool {
        matches!(self, Running::Blake2sp(..))
    }

    pub(super) fn update(&mut self, bytes: &[u8]) {
        match self {
            Running::Crc32(state) => state.update(bytes),
            #[cfg(test)]
            Running::Blake2sp(state, (census, threads)) => {
                let _team = hold_on(census, team_beside(*threads));
                state.update(bytes);
            }
            #[cfg(not(test))]
            Running::Blake2sp(state, ..) => state.update(bytes),
        }
    }

    pub(super) fn finish(&mut self) -> Digest {
        match self {
            Running::Crc32(state) => Digest::Crc32(state.finish()),
            // `finalize_reset` rather than a replacement: a hasher owns a
            // heap stage, so building a fresh one to swap in is an
            // allocation per member (API promise 2.4), and it would throw
            // away the worker allowance `new_digest` gave this one.
            Running::Blake2sp(state, ..) => Digest::Blake2sp(state.finalize_reset()),
        }
    }
}

/// The shortest span whose digest is taken on a second thread beside the
/// copy rather than inside it ([`Run::copy_payload`]).
///
/// A scoped spawn and join costs tens of microseconds on aarch64 macOS,
/// and the CRC32 fold runs at about 58 GB/s, about 17 us a MiB, so at
/// 4 MiB the thread takes about 70 us off the copying thread for about
/// half that in its own cost. It is an ARITHMETIC floor: every stored
/// gate row is 64 or 128 MiB and nothing measured sits near it.
pub(super) const DIGEST_BESIDE_FLOOR: u64 = 4 << 20;

/// Whether a span's digest runs BESIDE its copy, on one scoped thread
/// joined before the copy returns, rather than inside the copy loop.
///
/// Only when a digest is wanted at all, when the span is at least
/// [`DIGEST_BESIDE_FLOOR`], and when there is a helper thread to spend
/// ([`Run::helpers`]): a caller that allows none keeps a
/// writer that never starts a thread for this. The bound SPEC-API 8.3
/// asks to be stated is ONE thread per member being written, alive only
/// for one span's copy.
pub(super) fn digest_beside(len: u64, helpers: usize, wanted: bool) -> bool {
    wanted && helpers >= 1 && len >= DIGEST_BESIDE_FLOOR
}

/// Whether a computed digest is the one the caller promised.
pub(super) fn digest_matches(computed: Digest, promised: Digest) -> bool {
    computed == promised
}
