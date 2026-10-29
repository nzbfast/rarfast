//! Storing a member that will not compress (spec G 3.8.3).
//!
//! "Before compressing, the writer samples the member; when the samples say
//! the data is incompressible it writes the member STORED instead, with
//! method 0 ... it must be taken from samples rather than by compressing
//! and comparing, which doubles the work on exactly the data that pays
//! least." The rule this module carries was counted and decided on 28 Sep
//! 2026:
//!
//! - a compressed member of at least [`LEAST_MEMBER_BYTES`], in a solid
//!   set too since 1 Oct 2026 (`WriteOptions::solid_store`, on by default:
//!   a member the rule stores neither starts nor ends the solid run, spec
//!   G 3.9), where its verdict is taken by judges the run keeps
//!   ([`Judges`]);
//! - [`SAMPLES`] samples of [`SAMPLE_BYTES`], each CENTRED in one of that
//!   many equal segments of the sampled span;
//! - each packed separately, from no history, at the encoder's FLOOR
//!   effort (`encode::drive::Plan::floor`);
//! - STORED when at most [`most_misses`] of them pack to less than
//!   [`LEAST_PER_MILLE`] of their own bytes: [`MOST_MISSES`], four of the
//!   sixteen, for a member of at least [`FOUR_MISSES_FROM`] since 1 Oct
//!   2026, and [`ONE_MISS`], the rule as it was decided on 28 Sep, for a
//!   smaller one and under `WriteOptions::store_one_miss`.
//!
//! The span is the whole member for bytes in memory, and for a READER,
//! which is read exactly once and cannot seek (SPEC-API 7), the first
//! [`PREFIX_BYTES`] of it, pulled only as far as the vote needs, held until
//! the decision ([`Prefix`]) and then handed to whichever path was chosen.
//!
//! **Why centred, and why a count rather than a total.** A media container
//! is incompressible in its body and not at its ends: a 4K MKV's first 64
//! KiB packed to 64 percent at the floor and its trailing cue index to 36,
//! while every sample of its body read 99.88 to 100.08 percent and the
//! whole member at level 3 came out 0.005 percent LARGER than stored. A total
//! over samples placed at the ends read 93.8 to 97.8 percent and would have
//! compressed the member. Samples centred in their segments never sit on
//! offset 0 or the last byte, and one sample that does compress is
//! outvoted by the rest.
//!
//! **Why four may compress.** One miss stored that MKV and did not store a
//! member of 12,881,000,069 bytes, whose opening packs: its first 32 MiB
//! read 86.0, 87.8, 99.6, 98.5, 98.8, 99.9 ... percent, four samples of
//! the sixteen under the bar and nothing under it after them. Compressed
//! whole at level 5 it came out 0.12 percent under its own size for 26
//! times the wall of storing it (measured 1 Oct 2026). So a
//! member is stored when at least twelve of its sixteen samples have
//! nothing in them. What that gives away is a member a quarter of whose
//! samples compress by any amount; the ladder's mixed media corpus holds
//! at least five that do and is not reached.
//!
//! **Why only from 128 MiB.** Counted with four misses at every size on
//! the rivals round's bin4g (9,516 real files, 413 of them 1 MiB and
//! more): eight members under 5 MiB were newly stored, 24.3 MB that the
//! one-miss rule packed to 19.3, among them an asset catalogue that packs
//! to 49 percent whole. Counted again with four misses from 32 MiB on 26
//! real asset catalogues of 32 to 96 MiB: six of 37 to 60 MiB newly
//! stored, 276 MB that one miss packed to 189 (+8.1 percent of the
//! corpus). Each of their samples packs to 96 to 100 percent alone: what
//! they hold is repeated at long range, which a 64 KiB sample packed from
//! no history cannot see, and two shallow misses were all that kept them
//! in the compressor. No count or bar tells them from the big member, whose
//! samples are worse. Their size does: four misses are allowed from
//! [`FOUR_MISSES_FROM`], above every catalogue measured and under the
//! members of a many-member set (150 MB and up), and a smaller member keeps one,
//! which also keeps its vote settled at the second sample that compresses
//! (the fifth cost bin4g at level 1 two seconds of fifteen, the samples
//! being packed on the writing thread).
//!
//! **What a prefix cannot see.** A reader member whose first
//! [`PREFIX_BYTES`] are incompressible and whose rest compresses is
//! stored: measured, 32 MiB of keystream in front of 32 MiB of source code
//! is stored where level 3 would have written 59 percent of it. The
//! reverse, a compressible head in front of incompressible bytes, is
//! compressed, which is what the writer did before this rule. A reader
//! cannot be sampled further: it is read once. A source that can SEEK
//! (`write::Payload::Seekable`, a file) is sampled across its whole length
//! instead, by [`seek_says_store`], where the member is at least
//! [`WHOLE_VOTE_FROM`], 4 GiB: the sixteen samples [`sample_starts`]
//! places over the whole member, each read at a seek before the run plans
//! anything, so that such a member holds no head. A smaller member from
//! such a source is a reader: sixteen seeks cost a hard disk more than
//! reading it.

use std::collections::VecDeque;
use std::io::{Read, SeekFrom};

use crate::encode::drive::Plan;
use crate::encode::rar5::{EncodeOptions, Rar5Encoder, SampleLength};
use crate::error::{Error, ErrorKind};
use crate::memory::MemoryPolicy;
use crate::write::ReadSeek;
use crate::Result;

/// The least member the rule samples. Smaller members are compressed as
/// before: the worker team encodes them together, and there is no wall or
/// memory in one worth a decision.
pub(crate) const LEAST_MEMBER_BYTES: u64 = 1 << 20;
/// How many samples a member's span is judged on.
pub(crate) const SAMPLES: usize = 16;
/// The bytes of one sample.
pub(crate) const SAMPLE_BYTES: usize = 64 << 10;
/// How many of the samples may compress and the member still be stored.
pub(crate) const MOST_MISSES: usize = 4;
/// The same for a member under [`FOUR_MISSES_FROM`], and at every size
/// under `WriteOptions::store_one_miss`: the rule as it stood until 1 Oct
/// 2026, which that option gives back byte for byte.
pub(crate) const ONE_MISS: usize = 1;
/// The least DECLARED size of a member that is allowed [`MOST_MISSES`]:
/// 128 MiB (134,217,728 bytes).
pub(crate) const FOUR_MISSES_FROM: u64 = 128 << 20;

/// How many samples of a member of `size` declared bytes may compress and
/// the member still be stored.
pub(crate) fn most_misses(size: u64, one_miss: bool) -> usize {
    if one_miss || size < FOUR_MISSES_FROM {
        ONE_MISS
    } else {
        MOST_MISSES
    }
}
/// A sample that packs to at least this many thousandths of its own bytes
/// has nothing in it to compress: 99.5 percent.
pub(crate) const LEAST_PER_MILLE: u64 = 995;
/// The least member whose source can SEEK that is voted on across its
/// WHOLE length ([`seek_says_store`]): 4 GiB (4,294,967,296 bytes), that
/// size included. A smaller one is a reader in every respect, judged on
/// its first [`PREFIX_BYTES`] as before.
///
/// Why a size and why this one (decided 2 Oct 2026 on
/// rows measured 1 Oct). The whole-member
/// vote reads sixteen samples at sixteen places before the member is read
/// once, and on a cold hard disk each is a seek: measured on a twelve disk
/// array, 0.225 s a member whatever its size. On a 12.9 GB member that is
/// not seen (21.39 s against 21.18, the null 20.78); on 64 members of 48
/// MiB it made a create of 8.79 s take 23.24. The verdict may not depend
/// on the device, so the rule is the member's size alone, and at 4 GiB
/// the look is 2 to 3 percent of a whole cold create on that array (less
/// as the member grows) and under 1 on a single disk at 150 MB/s, inside
/// the rows' own spread, while the members it was made for (a big member whose
/// opening packs, a tar behind a video, a 4 GiB binary whose head is
/// poor) are all at or over it.
pub(crate) const WHOLE_VOTE_FROM: u64 = 4 << 30;
/// The FLOOR of the whole-member vote ([`seek_says_store`]), in
/// thousandths: a member allowed [`MOST_MISSES`] whose misses have passed
/// that count is still STORED while the samples taken pack TOGETHER to at
/// least this much of their bytes, 99 percent.
///
/// Why (decided 1 Oct 2026, wall
/// first). A miss at
/// 98 percent counted as a miss at 35. A reader's head is one stretch of
/// a file and reads alike throughout, so that seldom mattered; across the
/// whole of a big member a few stretches that pack to 98 or 99 percent are
/// ordinary (of fifteen big members, nine have one to three such samples
/// of sixteen and one has five), and five of them sent a 928 MB member through
/// the compressor to save 0.6 percent. The floor asks that the samples
/// say there is something to gain before a level's work is spent.
///
/// It is not asked of a member under [`FOUR_MISSES_FROM`], nor under
/// `WriteOptions::store_one_miss`: there the samples already cannot see
/// what such members hold at long range (an asset catalogue of 60 MB
/// whose sixteen samples pack to 99.7 percent together packs to 59
/// percent whole), which is why one miss decides them, and a floor on
/// the same samples would store them.
pub(crate) const WHOLE_LEAST_PER_MILLE: u64 = 990;
/// The most of a READER member held until the decision is taken.
pub(crate) const PREFIX_BYTES: usize = 32 << 20;

/// Where each sample of a span of `len` bytes starts, as spec G 3.8.3
/// spells it: the span is cut into [`SAMPLES`] equal segments, segment `k`
/// starting at `floor(k * len / 16)`, and sample `k` is the
/// [`SAMPLE_BYTES`] centred in segment `k`, starting at
/// `seg_start + floor((seg_len - 65,536) / 2)`. At a span of 1 MiB or more
/// every segment holds a whole sample; a shorter one, which the rule never
/// samples, starts each sample at its segment and never past the end.
pub(crate) fn sample_starts(len: usize) -> impl Iterator<Item = usize> {
    let sample = SAMPLE_BYTES.min(len);
    (0..SAMPLES).map(move |segment| {
        let start = segment * len / SAMPLES;
        let end = (segment + 1) * len / SAMPLES;
        let centred = start + (end - start).saturating_sub(sample) / 2;
        centred.min(len - sample)
    })
}

/// [`sample_starts`]' sample `segment` of a span of `len` bytes, where
/// the span is a whole member and may pass what a `usize` holds: a span
/// at least a sample long, as a member the rule samples is.
pub(crate) fn sample_start_in(len: u64, segment: usize) -> u64 {
    let (segment, samples, sample) = (segment as u64, SAMPLES as u64, SAMPLE_BYTES as u64);
    // The products are taken in 128 bits: sixteen times a member's size
    // passes 64 where the size is an exbibyte.
    let start = (u128::from(segment) * u128::from(len) / u128::from(samples)) as u64;
    let end = (u128::from(segment + 1) * u128::from(len) / u128::from(samples)) as u64;
    let centred = start + (end - start).saturating_sub(sample) / 2;
    centred.min(len - sample)
}

/// Spec G 3.8.3's vote over the WHOLE of a member whose source can SEEK
/// (`Payload::Seekable`), read where each sample lies: the member is the
/// `size` bytes from where `reader` stands, at least a sample of them.
/// `judge` has no vote in it and the misses it allows set.
///
/// The samples are the ones [`sample_starts`] places over a span of the
/// member's whole length, taken in rising order, each by one seek and one
/// read of [`SAMPLE_BYTES`], no further than the sample that settles a
/// member the rule compresses; a member it stores reads all of them, as
/// [`samples_say_store`] does. The source is then returned to the
/// member's start. Nothing is held but the one sample.
///
/// **What settles it.** Under [`FOUR_MISSES_FROM`], and under
/// `WriteOptions::store_one_miss`: the miss that passes the count, as in
/// every other vote. From there, where four misses are allowed: the first
/// sample at which the misses have passed the count AND the samples taken
/// so far pack together to under [`WHOLE_LEAST_PER_MILLE`]; a member no
/// sample of which is that is stored. So a member whose misses pass four
/// on samples that hardly compress is read on, to its last sample if
/// they never fall under the floor together.
///
/// `None` where the source would not say where it stands or would not
/// take the first seek: nothing has been read, and the caller judges the
/// member as it judges a reader that cannot seek. A sample that ends
/// early is `Truncated`, as a short reader is on any pull.
pub(crate) fn seek_says_store(
    reader: &mut (dyn ReadSeek + Send),
    size: u64,
    judge: &mut Judge,
) -> Result<Option<bool>> {
    debug_assert!(size >= SAMPLE_BYTES as u64);
    let Ok(start) = reader.stream_position() else {
        return Ok(None);
    };
    let mut sample = vec![0u8; SAMPLE_BYTES];
    let mut stores = true;
    // Asked only where four misses are allowed.
    let floor = (judge.most_misses == MOST_MISSES).then_some(WHOLE_LEAST_PER_MILLE);
    let (mut packed, mut taken) = (0u64, 0u64);
    for segment in 0..SAMPLES {
        let at = start + sample_start_in(size, segment);
        match reader.seek(SeekFrom::Start(at)) {
            Ok(_) => {}
            Err(_) if segment == 0 => return Ok(None),
            Err(error) => return Err(Error::from(error)),
        }
        let mut filled = 0;
        while filled < sample.len() {
            let read = reader.read(&mut sample[filled..]).map_err(Error::from)?;
            if read == 0 {
                return Err(Error::new(ErrorKind::Truncated));
            }
            filled += read;
        }
        let (within, length) = judge.measure(&sample);
        packed += length as u64;
        taken += sample.len() as u64;
        let gains = floor.is_none_or(|floor| packed * 1000 < taken * floor);
        if !within && gains {
            stores = false;
            break;
        }
    }
    reader.seek(SeekFrom::Start(start)).map_err(Error::from)?;
    Ok(Some(stores))
}

/// Whether a member whose sampled span is `span` is written STORED, where
/// at most `most_misses` of its samples may compress ([`most_misses`] of
/// the member's declared size).
///
/// A pure function of `span`'s bytes and that count: a sample's length is
/// taken from its own bytes alone, on whichever thread, at the floor
/// effort, so the verdict cannot move with the box, the load or
/// `WriteOptions::workers` (API promise 2.6). `packed` is
/// `WriteOptions::store_packed_samples`: how the length is come by, never
/// what it is ([`Judge`]).
pub(crate) fn samples_say_store(span: &[u8], most_misses: usize, packed: bool) -> bool {
    if span.is_empty() {
        return false;
    }
    let mut judge = Judge::new(most_misses, packed);
    for start in sample_starts(span.len()) {
        if !judge.sample(&span[start..start + SAMPLE_BYTES.min(span.len())]) {
            return false;
        }
    }
    true
}

/// The vote, one sample at a time, so that a reader can stop pulling at
/// the sample that settles it.
///
/// **How a sample's length is come by.** The rule reads one thing of a
/// packed sample, its length, and since 1 Oct 2026 the length is COUNTED
/// and the sample not packed (`encode::rar5::SampleLength`: the floor's
/// parse with its symbols counted as it goes, and the one block's length
/// from the counts): 2.6 to 2.8 times fewer instructions a sample on real
/// binaries and 6 to 10 times fewer on video, on both architectures, and
/// nothing built per vote. It
/// is the same length to the byte, so every verdict and every archive is
/// what it was. A sample that form hands back, and every sample under
/// `WriteOptions::store_packed_samples`, is packed in full by the encoder
/// as before ([`Packer`]).
///
/// **What a judge holds** is its counter, 2 MiB once its samples' words
/// have reached every part of its table, built by its first sample; and
/// the packer's encoder only where a sample needed it.
pub(crate) struct Judge {
    /// The counted length's parse and tables, built by the first sample.
    counter: Option<Box<SampleLength>>,
    /// The encoder that packs a sample in full, built by the first sample
    /// that needs it: none of a default vote's do.
    packer: Option<Packer>,
    /// `WriteOptions::store_packed_samples`: pack every sample in full.
    packed: bool,
    misses: usize,
    /// How many samples may compress and the member still be stored.
    most_misses: usize,
}

/// A sample packed in full, for its length: the rule's sampler until 1 Oct
/// 2026, kept for the samples the counted length does not cover and for
/// `WriteOptions::store_packed_samples`.
struct Packer {
    encoder: Rar5Encoder,
    out: Vec<u8>,
}

impl Packer {
    /// The encoder a sample is packed by: RAR 5 at level 1's finder,
    /// dropped to the floor effort, over the smallest dictionary a writer
    /// of ours chooses, which is already twice a sample. One sample is
    /// always parsed alone and from nothing, so `lone` has nothing to add
    /// and is cleared.
    fn new() -> Packer {
        let mut plan = Plan::for_level(1).floor();
        plan.lone = None;
        Packer {
            encoder: Rar5Encoder::new(EncodeOptions {
                dictionary: MemoryPolicy::MIN_DICTIONARY as u32,
                version: 0,
                plan,
                workers: 1,
            }),
            out: Vec::with_capacity(SAMPLE_BYTES + (SAMPLE_BYTES >> 4)),
        }
    }

    fn packed_len(&mut self, sample: &[u8]) -> usize {
        self.out.clear();
        self.encoder.encode_region(sample, 0, true, &mut self.out);
        self.out.len()
    }
}

impl Judge {
    /// What a judge holds once its samples have reached all of its
    /// counter's table: `encode::floor_count::FloorCount`'s 2^20 heads of two bytes
    /// and the few KiB of prices, counts and code lengths beside them.
    pub(crate) const MOST_BYTES: u64 = (2 << 20) + (16 << 10);
    /// The same for a judge that packs in full
    /// (`WriteOptions::store_packed_samples`): the chains' 2^20 heads of
    /// four bytes, their 64 Ki links, the tokens and the packed sample.
    pub(crate) const MOST_PACKED_BYTES: u64 = (4 << 20) + (256 << 10) + (640 << 10);

    pub(crate) fn new(most_misses: usize, packed: bool) -> Judge {
        Judge {
            counter: None,
            packer: None,
            packed,
            misses: 0,
            most_misses,
        }
    }

    /// How many bytes `sample` packs to, alone and from nothing, at the
    /// floor effort.
    fn packed_len(&mut self, sample: &[u8]) -> usize {
        if !self.packed {
            let counter = self
                .counter
                .get_or_insert_with(|| Box::new(SampleLength::new()));
            if let Some(len) = counter.packed_len(sample) {
                return len;
            }
        }
        self.packer
            .get_or_insert_with(Packer::new)
            .packed_len(sample)
    }

    /// Take one sample's length and count it; answers whether the member
    /// may still be stored, which is false from the vote that decides it
    /// on.
    fn sample(&mut self, sample: &[u8]) -> bool {
        self.measure(sample).0
    }

    /// [`Judge::sample`], and the length the sample packs to, for a vote
    /// that also reads what its samples pack to together
    /// ([`seek_says_store`]).
    fn measure(&mut self, sample: &[u8]) -> (bool, usize) {
        let packed = self.packed_len(sample);
        if (packed as u64) * 1000 < sample.len() as u64 * LEAST_PER_MILLE {
            self.misses += 1;
        }
        (self.misses <= self.most_misses, packed)
    }
}

/// The rule's length of every sample of `samples`, summed, for the count's
/// probe (`examples/g_store_sample_probe.rs`): by one judge kept between
/// them, or by a judge built for each as a vote's first sample is;
/// counted, or packed in full (`packed`).
#[cfg(feature = "bench-internals")]
pub(crate) fn probe_whole(samples: &[&[u8]], fresh: bool, packed: bool) -> u64 {
    let mut judge = Judge::new(SAMPLES, packed);
    let mut sum = 0u64;
    for sample in samples {
        if fresh {
            judge = Judge::new(SAMPLES, packed);
        }
        sum += judge.packed_len(sample) as u64;
    }
    sum
}

/// The first bytes of a READER member, pulled to be sampled and then
/// served back, in order, to whichever path writes the member.
///
/// **It pulls only as far as the vote needs.** The samples lie in order
/// along the span, so the pull stops at the end of the sample that
/// settles it: at the first sample that compresses past the misses the
/// rule allows, for a member that is then compressed (on text and code
/// of 128 MiB and more that is the fifth sample, 9/32 of the span and a
/// half sample; for a smaller member, and under
/// `WriteOptions::store_one_miss`, the second, 3/32 and a half sample),
/// and at the last sample for a member that is then stored. What is held is
/// what was pulled, and it is served back to the member's own path before
/// the reader is read again.
///
/// **It is held in pieces, and a piece served back is given up.** With
/// four misses allowed a member that compresses is settled 9 MiB into a
/// 32 MiB span where one miss settled it at 3, and a head held whole until
/// its last byte was served stood beside the walk's first batch: measured,
/// a streamed 48 MiB text member's peak rose from 55.3 to 65.1 MB. In
/// pieces of [`PIECE_BYTES`] what stands beside the walk is what it has
/// not read yet.
#[derive(Default)]
pub(crate) struct Prefix {
    /// The member these bytes are the head of, or none.
    member: Option<usize>,
    /// What is held, in order. While a reader is being sampled every piece
    /// but the last is [`PIECE_BYTES`] long, so piece `i` begins at byte
    /// `i * PIECE_BYTES` of the member; a member pulled whole
    /// ([`Prefix::hold`]) is one piece.
    pieces: VecDeque<Vec<u8>>,
    /// How many bytes of the first piece have been served back.
    served: usize,
    /// How many bytes the pieces hold, served or not.
    pulled: usize,
    /// One sample's bytes, copied out of the pieces it may lie across.
    sample: Vec<u8>,
    /// Whether what is held is a head the writer read before its refusal
    /// and KEPT ([`Prefix::keep`]), which the member's samples read back
    /// rather than clear.
    kept: bool,
}

/// The bytes of one piece of a [`Prefix`].
const PIECE_BYTES: usize = 1 << 20;

impl Prefix {
    /// Forget what is held, unless it is held for a member AFTER `index`,
    /// which was sampled or pulled ahead of the writer (the worker team
    /// samples a member as it plans a batch; a solid batch pulls one
    /// whole, [`Prefix::hold`]) and which the writer has not reached yet.
    pub(crate) fn clear_up_to(&mut self, index: usize) {
        if !self.keeps(index) && self.member.is_none_or(|member| member <= index) {
            self.clear();
        }
    }

    /// Keep the head just pulled by [`Prefix::head`]: a head the writer
    /// read before its refusal to know the member's class
    /// (`Run::read_lone_head`), which the member's samples then read back
    /// before the reader, and do not clear ([`Prefix::keeps`]).
    pub(crate) fn keep(&mut self) {
        self.kept = true;
    }

    /// Whether what is held is member `index`'s KEPT head ([`Prefix::keep`])
    /// in the pieces [`Prefix::head`] pulls, none of it served yet, so that
    /// every later pull of the member reads it back, the store rule's
    /// samples first, and the reader is read once.
    fn keeps(&self, index: usize) -> bool {
        self.kept
            && self.member == Some(index)
            && self.served == 0
            && self
                .pieces
                .iter()
                .rev()
                .skip(1)
                .all(|piece| piece.len() == PIECE_BYTES)
            && self
                .pieces
                .back()
                .is_none_or(|piece| piece.len() <= PIECE_BYTES)
    }

    /// The first `bytes` of member `index`'s head where they are held and
    /// none of it is served ([`Prefix::keeps`]).
    pub(crate) fn held_head(&self, index: usize, bytes: usize) -> Option<&[u8]> {
        let first = self.pieces.front()?;
        (self.keeps(index) && first.len() >= bytes).then(|| &first[..bytes])
    }

    /// Forget any member's head, and give its bytes up.
    pub(crate) fn clear(&mut self) {
        self.kept = false;
        self.member = None;
        self.pieces.clear();
        self.served = 0;
        self.pulled = 0;
    }

    /// Hold `bytes`, the WHOLE of member `index` already pulled from its
    /// reader (a solid batch pulls a member whole to judge it,
    /// `Run::batch_solid`), to be served back to the member's own path in
    /// place of the reader, which has nothing left to give.
    pub(crate) fn hold(&mut self, index: usize, bytes: Vec<u8>) {
        self.clear();
        self.pulled = bytes.len();
        self.pieces.push_back(bytes);
        self.member = Some(index);
    }

    /// Sample member `index` over the first `span` bytes of `reader`,
    /// which must produce at least that many (a short one is `Truncated`,
    /// as it is on every other pull of a member), and answer whether it is
    /// written stored, where at most `most_misses` samples may compress
    /// (`packed`: [`samples_say_store`]'s).
    pub(crate) fn sample(
        &mut self,
        index: usize,
        reader: &mut (dyn Read + Send),
        span: usize,
        most_misses: usize,
        packed: bool,
    ) -> Result<bool> {
        self.sample_with(index, reader, span, &mut Judge::new(most_misses, packed))
    }

    /// [`Prefix::sample`] by a judge the caller keeps, with no vote in it
    /// and the misses it allows set ([`Judges::with_one`]).
    pub(crate) fn sample_with(
        &mut self,
        index: usize,
        reader: &mut (dyn Read + Send),
        span: usize,
        judge: &mut Judge,
    ) -> Result<bool> {
        if !self.keeps(index) {
            self.clear();
        }
        // A kept head is read back once, by this vote.
        self.kept = false;
        self.member = Some(index);
        if span == 0 {
            return Ok(false);
        }
        for start in sample_starts(span) {
            let end = start + SAMPLE_BYTES.min(span);
            if let Err(error) = self.pull_to(reader, end, span) {
                self.clear();
                return Err(error);
            }
            self.copy_sample(start, end);
            if !judge.sample(&self.sample) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Extend the held bytes to `end` of the `span` from `reader`.
    fn pull_to(&mut self, reader: &mut (dyn Read + Send), end: usize, span: usize) -> Result<()> {
        while self.pulled < end {
            let at = self.pulled % PIECE_BYTES;
            if at == 0 {
                let room = PIECE_BYTES.min(span - self.pulled);
                self.pieces.push_back(Vec::with_capacity(room));
            }
            let piece = self.pieces.back_mut().expect("a piece being filled");
            let to = at + (end - self.pulled).min(PIECE_BYTES - at);
            piece.resize(to, 0);
            let mut filled = at;
            while filled < to {
                let read = reader.read(&mut piece[filled..to]).map_err(Error::from)?;
                if read == 0 {
                    return Err(Error::new(ErrorKind::Truncated));
                }
                filled += read;
            }
            self.pulled += to - at;
        }
        Ok(())
    }

    /// Copy bytes `start..end` of what is held, none of it served yet,
    /// into the sample's own buffer.
    fn copy_sample(&mut self, start: usize, end: usize) {
        self.sample.clear();
        let mut at = start;
        while at < end {
            let piece = &self.pieces[at / PIECE_BYTES];
            let from = at % PIECE_BYTES;
            let n = (end - at).min(piece.len() - from);
            self.sample.extend_from_slice(&piece[from..from + n]);
            at += n;
        }
    }

    /// The first `bytes` of member `index`, pulled from `reader` as far as
    /// they are not held already, and held with the rest of its head to be
    /// served back to the member's own path: what a member's class is read
    /// from (`encode::class`) where the store rule's samples settled the
    /// vote before they reached that far, or took no vote at all.
    ///
    /// `span` is the most this prefix holds of the member, at least
    /// `bytes`, which is at most one piece. Nothing of the head has been
    /// served back yet: this is asked before the member's first window is
    /// read.
    pub(crate) fn head(
        &mut self,
        index: usize,
        reader: &mut (dyn Read + Send),
        bytes: usize,
        span: usize,
    ) -> Result<&[u8]> {
        debug_assert!(bytes <= PIECE_BYTES && bytes <= span);
        debug_assert!(
            self.member.is_none_or(|held| held <= index),
            "no later member's head is held while this one is read"
        );
        if self.member != Some(index) {
            self.clear();
            self.member = Some(index);
        }
        debug_assert_eq!(self.served, 0, "nothing of the head is served yet");
        if let Err(error) = self.pull_to(reader, bytes, span) {
            self.clear();
            return Err(error);
        }
        Ok(&self.pieces[0][..bytes])
    }

    /// The bytes held and not yet served back, which is what they cost.
    pub(crate) fn held(&self) -> usize {
        self.pulled
    }

    /// Member `index`'s payload as ONE reader: what is held of its head,
    /// then `reader`. For a consumer that takes a reader of its own, such
    /// as the stored path's read-ahead thread (`write::engine`'s
    /// `read_ahead`), which would otherwise read past the held head.
    pub(crate) fn then<'r>(
        &'r mut self,
        index: usize,
        reader: &'r mut (dyn Read + Send),
    ) -> Then<'r> {
        Then {
            prefix: self,
            index,
            reader,
        }
    }

    /// A read of member `index`: from the held head while any of it is
    /// left, then from `reader`. Never both in one call, which a caller
    /// filling a buffer in a loop already allows for.
    pub(crate) fn read(
        &mut self,
        index: usize,
        reader: &mut (dyn Read + Send),
        buf: &mut [u8],
    ) -> std::io::Result<usize> {
        if self.member == Some(index) {
            while let Some(piece) = self.pieces.front() {
                let n = buf.len().min(piece.len() - self.served);
                buf[..n].copy_from_slice(&piece[self.served..self.served + n]);
                self.served += n;
                if self.served < piece.len() {
                    return Ok(n);
                }
                // Served whole: given back rather than kept, so that a
                // head of up to 32 MiB does not stay resident beside the
                // path that is reading it, nor for the rest of the run.
                self.pulled -= piece.len();
                self.served = 0;
                self.pieces.pop_front();
                if self.pieces.is_empty() {
                    self.clear();
                    self.sample = Vec::new();
                }
                if n > 0 {
                    return Ok(n);
                }
            }
        }
        reader.read(buf)
    }
}

/// A member's held head and then its reader, read as one ([`Prefix::then`]).
pub(crate) struct Then<'r> {
    prefix: &'r mut Prefix,
    index: usize,
    reader: &'r mut (dyn Read + Send),
}

impl Read for Then<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.prefix.read(self.index, self.reader, buf)
    }
}

/// The judges a run keeps between verdicts, and the vote taken ACROSS
/// THE WRITE'S POOL rather than one sample after another on the calling
/// thread ([`Judges::say_store_wide`]).
///
/// **Why they are kept.** A judge allocates its tables when its first
/// sample arrives (2 MiB counted; about 4.5 MiB where it packs in full),
/// and a judge built for every vote faulted that in and gave it back each
/// time: counted on bin4g at `-m1 -s` with the packing judge
/// (a Zen 4 rental, 16 threads, 413 members of 1 MiB and more), 3.1 s of
/// system time and 2.8 s of wall in 22, with every thread of the pool
/// behind the same address-space lock. A kept judge takes a sample from
/// nothing as a new one does, which is how one judge already serves the
/// sixteen samples of a member, so the verdict is the same.
///
/// At most [`JUDGES_KEPT`] are kept, which is what they hold: a run that
/// meets no incompressible member touches two. A vote that finds none
/// kept builds one, and gives it up where enough are kept already.
/// [`Judges::held_bytes`] states them, for the run's working memory.
pub(crate) struct Judges {
    kept: std::sync::Mutex<Vec<Judge>>,
    /// `WriteOptions::store_packed_samples`, which every judge is built
    /// with.
    packed: bool,
    /// How many judges there are now, kept or at a vote, and the most
    /// there have been at once.
    alive: std::sync::atomic::AtomicUsize,
    most: std::sync::atomic::AtomicUsize,
}

/// The most judges a run keeps, and with [`ROUND_LEAST`] about the most
/// that pack at once.
const JUDGES_KEPT: usize = 8;

/// The most kept judges one vote holds at once: its [`SAMPLES`] packed
/// across the pool at least [`ROUND_LEAST`] to a task
/// ([`Judges::say_store_wide`]), which is [`JUDGES_KEPT`]. What a write
/// under a caller's named ceiling charges for them (`Run::judges_most`).
pub(crate) const JUDGES_AT_ONCE: usize = SAMPLES.div_ceil(ROUND_LEAST);
/// The fewest samples one pool task takes of the round that follows the
/// leading one, so that its fourteen samples want seven judges, not
/// fourteen.
const ROUND_LEAST: usize = 2;

impl Judges {
    /// No judge yet; each is built with `packed`
    /// (`WriteOptions::store_packed_samples`).
    pub(crate) fn new(packed: bool) -> Judges {
        Judges {
            kept: std::sync::Mutex::new(Vec::new()),
            packed,
            alive: std::sync::atomic::AtomicUsize::new(0),
            most: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// A judge with no vote in it, which allows `most_misses`: a kept
    /// one, or a new one.
    fn take(&self, most_misses: usize) -> Judge {
        use std::sync::atomic::Ordering::Relaxed;
        let kept = self.kept.lock().unwrap_or_else(|e| e.into_inner()).pop();
        let mut judge = kept.unwrap_or_else(|| {
            let alive = self.alive.fetch_add(1, Relaxed) + 1;
            self.most.fetch_max(alive, Relaxed);
            Judge::new(most_misses, self.packed)
        });
        judge.misses = 0;
        judge.most_misses = most_misses;
        judge
    }

    /// Keep `judge` for the next vote, unless enough are kept already.
    fn give(&self, judge: Judge) {
        let mut kept = self.kept.lock().unwrap_or_else(|e| e.into_inner());
        if kept.len() < JUDGES_KEPT {
            kept.push(judge);
        } else {
            self.alive
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// What the run's judges have held at their most, in bytes: the most
    /// there have been at once, each at a judge's whole tables
    /// ([`Judge::MOST_BYTES`]). A figure for the run's stated working
    /// memory (`Run::working_now`), which it never understates: at most
    /// [`JUDGES_KEPT`] outlive a vote, 16 MiB of counted judges.
    pub(crate) fn held_bytes(&self) -> u64 {
        let most = self.most.load(std::sync::atomic::Ordering::Relaxed) as u64;
        most * if self.packed {
            Judge::MOST_PACKED_BYTES
        } else {
            Judge::MOST_BYTES
        }
    }

    /// The most a run's judges can hold at once when at most `votes` votes
    /// are taken together: each judge at its whole tables, as
    /// [`Judges::held_bytes`] states them.
    pub(crate) fn most_bytes(&self, votes: usize) -> u64 {
        votes as u64
            * if self.packed {
                Judge::MOST_PACKED_BYTES
            } else {
                Judge::MOST_BYTES
            }
    }

    /// Run `vote` with one kept judge, for a vote taken a sample at a time
    /// ([`Prefix::sample_with`]).
    pub(crate) fn with_one<R>(&self, most_misses: usize, vote: impl FnOnce(&mut Judge) -> R) -> R {
        let mut judge = self.take(most_misses);
        let result = vote(&mut judge);
        self.give(judge);
        result
    }

    /// [`samples_say_store`]'s verdict on `span` by one kept judge, a
    /// sample at a time and no further than the vote needs: for a verdict
    /// taken on the writing thread while the pool is busy with a flush.
    pub(crate) fn say_store(&self, span: &[u8], most_misses: usize) -> bool {
        if span.is_empty() {
            return false;
        }
        self.with_one(most_misses, |judge| {
            sample_starts(span.len())
                .all(|start| judge.sample(&span[start..start + SAMPLE_BYTES.min(span.len())]))
        })
    }

    /// How many of `samples`, samples of `sample` bytes laid end to end
    /// ([`Prefix::pull_leading`]), compress: packed one after another by
    /// one kept judge, for whichever thread takes them beside a flush.
    pub(crate) fn misses_in(&self, samples: &[u8], sample: usize) -> usize {
        self.with_one(SAMPLES, |judge| {
            for bytes in samples.chunks(sample.max(1)) {
                judge.sample(bytes);
            }
            judge.misses
        })
    }

    /// How many of the samples of `bytes` that begin at `starts`, each
    /// `sample` long, compress: packed across the write's pool, at least
    /// `least` of them to a task, each by a kept judge. Without the
    /// `parallel` feature they are packed here, in order.
    fn round(&self, bytes: &[u8], starts: &[usize], sample: usize, least: usize) -> usize {
        let misses_of = |start: usize| -> usize {
            // Only the count is read: the round's caller holds the line.
            let mut judge = self.take(SAMPLES);
            judge.sample(&bytes[start..start + sample]);
            let misses = judge.misses;
            self.give(judge);
            misses
        };
        #[cfg(feature = "parallel")]
        {
            use rayon::prelude::*;
            super::width::on_pool(|| {
                starts
                    .par_iter()
                    .with_min_len(least)
                    .map(|&start| misses_of(start))
                    .sum()
            })
        }
        #[cfg(not(feature = "parallel"))]
        {
            let _ = least;
            starts.iter().map(|&start| misses_of(start)).sum()
        }
    }

    /// [`samples_say_store`]'s verdict on `span`, a member's whole bytes,
    /// with the samples packed across the write's pool: the same sixteen
    /// samples, each still packed alone, from nothing, by an encoder one
    /// thread wide, and the same count against the same bar, so the
    /// verdict is the same function of `span`'s bytes and cannot move with
    /// the width. `most_misses` is how many samples may compress and the
    /// member still be stored.
    ///
    /// For a member of a SOLID run whose verdict is wanted while the pool
    /// stands idle behind the writing thread. The vote is taken in TWO
    /// rounds: the leading samples, as many as can settle it for a member
    /// that compresses (one more than the misses allowed), and the rest
    /// only if they did not, so a member that compresses packs no more
    /// samples than the serial vote would have.
    pub(crate) fn say_store_wide(&self, span: &[u8], most_misses: usize) -> bool {
        if span.is_empty() {
            return false;
        }
        let sample = SAMPLE_BYTES.min(span.len());
        let mut starts = [0usize; SAMPLES];
        for (slot, start) in starts.iter_mut().zip(sample_starts(span.len())) {
            *slot = start;
        }
        let (leading, rest) = starts.split_at((most_misses + 1).min(SAMPLES));
        let misses = self.round(span, leading, sample, 1);
        misses <= most_misses && misses + self.round(span, rest, sample, ROUND_LEAST) <= most_misses
    }
}

impl Prefix {
    /// [`Prefix::sample`] with the samples packed across the write's pool
    /// by kept judges, for a reader member of a SOLID run reached while
    /// the pool stands idle: the two rounds of [`Judges::say_store_wide`].
    /// The head is pulled to the end of the leading round's last sample,
    /// which is where the serial vote stops for a member that compresses,
    /// and, only where those samples do not settle it, to the end of the
    /// span's last sample, which is where the serial vote stops for a
    /// member that is stored; a member the second round compresses holds
    /// more of its head than the serial vote would have, inside spec G
    /// 3.5's bound, the span.
    pub(crate) fn sample_wide(
        &mut self,
        index: usize,
        reader: &mut (dyn Read + Send),
        span: usize,
        most_misses: usize,
        judges: &Judges,
    ) -> Result<bool> {
        let samples = self.pull_leading(index, reader, span, most_misses)?;
        let sample = SAMPLE_BYTES.min(span);
        let within: Vec<usize> = (0..samples.len() / sample.max(1))
            .map(|k| k * sample)
            .collect();
        let misses = judges.round(&samples, &within, sample, 1);
        self.finish_wide(reader, span, most_misses, judges, misses)
    }

    /// The first half of [`Prefix::sample_wide`]: pull member `index`'s
    /// head as far as the leading round's last sample and answer those
    /// samples, end to end, each `SAMPLE_BYTES.min(span)` long, to be
    /// packed wherever there is a thread for them
    /// ([`Judges::misses_in`]). Empty for a span of nothing.
    pub(crate) fn pull_leading(
        &mut self,
        index: usize,
        reader: &mut (dyn Read + Send),
        span: usize,
        most_misses: usize,
    ) -> Result<Vec<u8>> {
        if !self.keeps(index) {
            self.clear();
        }
        // A kept head is read back once, by this vote.
        self.kept = false;
        self.member = Some(index);
        let mut samples = Vec::new();
        if span == 0 {
            return Ok(samples);
        }
        let sample = SAMPLE_BYTES.min(span);
        for start in sample_starts(span).take((most_misses + 1).min(SAMPLES)) {
            if let Err(error) = self.pull_to(reader, start + sample, span) {
                self.clear();
                return Err(error);
            }
            self.copy_sample(start, start + sample);
            samples.extend_from_slice(&self.sample);
        }
        Ok(samples)
    }

    /// The second half of [`Prefix::sample_wide`], given how many of the
    /// leading samples compress: the verdict, pulling the rest of the
    /// span's samples and packing them across the pool only where the
    /// leading ones did not settle it.
    pub(crate) fn finish_wide(
        &mut self,
        reader: &mut (dyn Read + Send),
        span: usize,
        most_misses: usize,
        judges: &Judges,
        misses: usize,
    ) -> Result<bool> {
        if span == 0 || misses > most_misses {
            return Ok(false);
        }
        let sample = SAMPLE_BYTES.min(span);
        let mut samples = Vec::new();
        let mut within = Vec::new();
        for start in sample_starts(span).skip((most_misses + 1).min(SAMPLES)) {
            if let Err(error) = self.pull_to(reader, start + sample, span) {
                self.clear();
                return Err(error);
            }
            self.copy_sample(start, start + sample);
            within.push(samples.len());
            samples.extend_from_slice(&self.sample);
        }
        Ok(misses + judges.round(&samples, &within, sample, ROUND_LEAST) <= most_misses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`samples_say_store`], the samples' lengths counted, which is the
    /// same verdict with every sample packed in full
    /// (`WriteOptions::store_packed_samples`) and with every sample handed
    /// back by the counted form and so packed in full by the fallback.
    fn says_store(span: &[u8], most_misses: usize) -> bool {
        let counted = samples_say_store(span, most_misses, false);
        assert_eq!(samples_say_store(span, most_misses, true), counted);
        let handed_back = crate::encode::rar5::with_samples_uncovered(|| {
            samples_say_store(span, most_misses, false)
        });
        assert_eq!(handed_back, counted);
        counted
    }

    fn keystream(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 32) as u8
            })
            .collect()
    }

    /// Spec G 3.8.3's placement, to the byte, on spans that are and are
    /// not multiples of 16: each sample centred in its own segment, never
    /// on offset 0 and never reaching the end.
    #[test]
    fn samples_are_centred_in_their_segments_as_the_spec_places_them() {
        for len in [1usize << 20, 16 << 20, (5 << 20) + 12_345, (32 << 20) - 7] {
            let starts: Vec<usize> = sample_starts(len).collect();
            assert_eq!(starts.len(), SAMPLES);
            for (k, start) in starts.iter().enumerate() {
                let seg_start = k * len / 16;
                let seg_len = (k + 1) * len / 16 - seg_start;
                assert_eq!(
                    *start,
                    seg_start + (seg_len - SAMPLE_BYTES) / 2,
                    "len {len} k {k}"
                );
                assert!(
                    *start + SAMPLE_BYTES <= seg_start + seg_len,
                    "len {len} k {k}"
                );
            }
            assert!(starts[0] > 0 || len == 1 << 20);
            assert!(starts[SAMPLES - 1] + SAMPLE_BYTES <= len);
        }
        // A span shorter than one sample is one sample of the whole span.
        assert!(sample_starts(1000).all(|start| start == 0));
    }

    /// Four misses from 128 MiB up, one below it, and one at every size
    /// under the option.
    #[test]
    fn four_misses_are_allowed_from_128_mib_and_one_below() {
        assert_eq!(FOUR_MISSES_FROM, 134_217_728);
        assert_eq!(most_misses(LEAST_MEMBER_BYTES, false), 1);
        assert_eq!(most_misses(32 << 20, false), 1);
        assert_eq!(most_misses((128 << 20) - 1, false), 1);
        assert_eq!(most_misses(128 << 20, false), 4);
        assert_eq!(most_misses(u64::MAX, false), 4);
        for size in [1 << 20, (128 << 20) - 1, 128 << 20, u64::MAX] {
            assert_eq!(most_misses(size, true), 1);
        }
    }

    #[test]
    fn incompressible_bytes_are_stored_and_text_is_not() {
        for most_misses in [MOST_MISSES, ONE_MISS] {
            assert!(says_store(&keystream(2 << 20, 1), most_misses));
            assert!(!says_store(
                &rarkit_testdata::chatter(0x7374_6f72, 2 << 20),
                most_misses
            ));
        }
    }

    /// Noise of two samples a segment, with the samples of the first
    /// `misses` segments zeroed.
    fn with_misses(misses: usize) -> Vec<u8> {
        let len = 16 * SAMPLE_BYTES * 2;
        let segment = len / SAMPLES;
        let mut member = keystream(len, 2);
        for k in 0..misses {
            member[k * segment + segment / 2 - SAMPLE_BYTES / 2..][..SAMPLE_BYTES].fill(0);
        }
        member
    }

    /// The big member's opening is outvoted: four samples that compress are
    /// allowed and five are not, so twelve of sixteen with nothing in them
    /// store the member and eleven do not.
    #[test]
    fn four_compressible_samples_are_outvoted_and_five_are_not() {
        assert_eq!((MOST_MISSES, SAMPLES), (4, 16));
        for misses in 0..=4 {
            assert!(says_store(&with_misses(misses), MOST_MISSES), "{misses}");
        }
        for misses in 5..=7 {
            assert!(!says_store(&with_misses(misses), MOST_MISSES), "{misses}");
        }
    }

    /// The rule of 28 Sep 2026, which `WriteOptions::store_one_miss` gives
    /// back: one sample that compresses is allowed, which is what stores a
    /// member whose first and last bytes are an index (the 4K MKV measured in
    /// the module documentation), and two are not.
    #[test]
    fn under_the_option_one_compressible_sample_is_outvoted_and_two_are_not() {
        assert_eq!(ONE_MISS, 1);
        assert!(says_store(&with_misses(0), ONE_MISS));
        assert!(says_store(&with_misses(1), ONE_MISS));
        for misses in 2..=5 {
            assert!(!says_store(&with_misses(misses), ONE_MISS), "{misses}");
        }
    }

    /// The failure a prefix cannot see, pinned so that it is a known
    /// property and not a surprise: an incompressible head as long as the
    /// prefix, in front of text, samples as incompressible.
    #[test]
    fn an_incompressible_head_as_long_as_the_prefix_is_stored() {
        let mut member = keystream(PREFIX_BYTES, 3);
        member.extend_from_slice(&rarkit_testdata::chatter(0x7374_6f72, 4 << 20));
        assert!(says_store(&member[..PREFIX_BYTES], MOST_MISSES));
        // The whole member has 36 MiB in 16 segments, of which the last
        // two samples are text: under the option that is two misses and it
        // compresses; the default's four allow them.
        assert!(!says_store(&member, ONE_MISS));
        assert!(says_store(&member, MOST_MISSES));
    }

    #[test]
    fn a_prefix_serves_its_bytes_back_then_the_reader() {
        let data = keystream(3 << 20, 4);
        let mut reader: &[u8] = &data;
        let mut prefix = Prefix::default();
        // Incompressible, so the vote runs to its last sample and the pull
        // stops at that sample's end, short of the span's.
        assert!(prefix
            .sample(7, &mut reader, 2 << 20, MOST_MISSES, false)
            .unwrap());
        let last = sample_starts(2 << 20).last().unwrap() + SAMPLE_BYTES;
        assert_eq!(prefix.held(), last);
        assert!(last < 2 << 20);
        let mut back = Vec::new();
        let mut buf = vec![0u8; 300_000];
        loop {
            let n = prefix.read(7, &mut reader, &mut buf).unwrap();
            if n == 0 {
                break;
            }
            back.extend_from_slice(&buf[..n]);
        }
        assert_eq!(back, data);
        assert_eq!(prefix.held(), 0);
    }

    /// A member that compresses is settled by its first five samples, and
    /// the pull stops at the fifth one's end: 9/32 of the span and half a
    /// sample, not the span. Under the option it is the first two, 3/32
    /// of the span and half a sample.
    #[test]
    fn a_compressible_reader_is_settled_early_and_held_short() {
        let data = rarkit_testdata::chatter(0x7374_6f72, 16 << 20);
        let mut reader: &[u8] = &data;
        let mut prefix = Prefix::default();
        assert!(!prefix
            .sample(3, &mut reader, 16 << 20, ONE_MISS, false)
            .unwrap());
        let second = sample_starts(16 << 20).nth(1).unwrap() + SAMPLE_BYTES;
        assert_eq!(prefix.held(), second);
        assert_eq!(second, 3 * (16 << 20) / 32 + SAMPLE_BYTES / 2);
        let mut reader: &[u8] = &data;
        assert!(!prefix
            .sample(3, &mut reader, 16 << 20, MOST_MISSES, true)
            .unwrap());
        let fifth = sample_starts(16 << 20).nth(4).unwrap() + SAMPLE_BYTES;
        assert_eq!(prefix.held(), fifth);
        assert_eq!(fifth, 9 * (16 << 20) / 32 + SAMPLE_BYTES / 2);
        // And what was pulled comes back first, then the reader's rest.
        let mut back = vec![0u8; data.len()];
        let mut filled = 0;
        while filled < back.len() {
            filled += prefix.read(3, &mut reader, &mut back[filled..]).unwrap();
        }
        assert_eq!(back, data);
    }

    /// The kept judges give the serial vote's verdict, across the pool and
    /// one at a time, on every count of compressing samples around the
    /// line, and again when the same judges are used a second time;
    /// counting each sample's length, and packing each in full
    /// (`WriteOptions::store_packed_samples`).
    #[test]
    fn kept_judges_vote_as_the_serial_judge_does() {
        let len = 16 * SAMPLE_BYTES * 2;
        let segment = len / SAMPLES;
        for packed in [false, true] {
            let judges = Judges::new(packed);
            assert_eq!(judges.held_bytes(), 0);
            for _ in 0..2 {
                for misses in 0..=6 {
                    let mut member = keystream(len, 9);
                    // The compressing samples placed LAST, so that the
                    // leading round does not settle the vote.
                    for k in SAMPLES - misses..SAMPLES {
                        member[k * segment + segment / 2 - SAMPLE_BYTES / 2..][..SAMPLE_BYTES]
                            .fill(0);
                    }
                    for most in [ONE_MISS, MOST_MISSES] {
                        let serial = says_store(&member, most);
                        assert_eq!(serial, misses <= most);
                        assert_eq!(judges.say_store_wide(&member, most), serial, "{misses}");
                        assert_eq!(judges.say_store(&member, most), serial, "{misses}");
                        let mut reader: &[u8] = &member;
                        let mut prefix = Prefix::default();
                        assert_eq!(
                            prefix
                                .sample_wide(0, &mut reader, len, most, &judges)
                                .unwrap(),
                            serial,
                            "{misses}"
                        );
                        // The head comes back first, then the reader's rest.
                        let mut back = vec![0u8; len];
                        let mut filled = 0;
                        while filled < len {
                            filled += prefix.read(0, &mut reader, &mut back[filled..]).unwrap();
                        }
                        assert!(back == member);
                    }
                }
                assert!(!judges
                    .say_store_wide(&rarkit_testdata::chatter(0x7374_6f72, 2 << 20), MOST_MISSES));
                assert!(
                    !judges.say_store(&rarkit_testdata::chatter(0x7374_6f72, 2 << 20), ONE_MISS)
                );
            }
            // What is kept is what was built and not given up, and the
            // judges are stated at the most there were at once.
            let kept = judges.kept.lock().unwrap().len();
            assert!((1..=JUDGES_KEPT).contains(&kept));
            assert_eq!(
                judges.alive.load(std::sync::atomic::Ordering::Relaxed),
                kept
            );
            let each = if packed {
                Judge::MOST_PACKED_BYTES
            } else {
                Judge::MOST_BYTES
            };
            let most = judges.most.load(std::sync::atomic::Ordering::Relaxed);
            assert!(most >= kept);
            assert_eq!(judges.held_bytes(), most as u64 * each);
            // Each kept judge holds the sampler its option names, and
            // only that one.
            for judge in judges.kept.lock().unwrap().iter() {
                assert_eq!(judge.packer.is_some(), packed);
                assert_eq!(judge.counter.is_some(), !packed);
            }
        }
    }

    /// A reader that compresses is settled by the leading round, and its
    /// head is held no further than the serial vote holds it.
    #[test]
    fn a_wide_vote_holds_a_compressible_head_as_short_as_the_serial_one() {
        let data = rarkit_testdata::chatter(0x7374_6f72, 16 << 20);
        let judges = Judges::new(false);
        for most in [ONE_MISS, MOST_MISSES] {
            let mut reader: &[u8] = &data;
            let mut prefix = Prefix::default();
            assert!(!prefix
                .sample_wide(3, &mut reader, 16 << 20, most, &judges)
                .unwrap());
            let settles = sample_starts(16 << 20).nth(most).unwrap() + SAMPLE_BYTES;
            assert_eq!(prefix.held(), settles);
        }
        let error = Prefix::default()
            .sample_wide(0, &mut &data[..100], 2 << 20, MOST_MISSES, &judges)
            .unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::Truncated));
    }

    /// The head is held in pieces and each is given up as it is served
    /// (spec G 3.5): what is held falls a piece at a time as the member's
    /// path reads it back, and never rises.
    #[test]
    fn a_prefix_gives_up_each_piece_as_it_is_served() {
        let data = rarkit_testdata::chatter(0x7374_6f72, 32 << 20);
        let mut reader: &[u8] = &data;
        let mut prefix = Prefix::default();
        assert!(!prefix
            .sample(0, &mut reader, 32 << 20, MOST_MISSES, false)
            .unwrap());
        let pulled = 9 * (32 << 20) / 32 + SAMPLE_BYTES / 2;
        assert_eq!(prefix.held(), pulled);
        let mut buf = vec![0u8; 300_000];
        let mut served = 0;
        while prefix.held() > 0 {
            let n = prefix.read(0, &mut reader, &mut buf).unwrap();
            assert_eq!(&buf[..n], &data[served..served + n]);
            served += n;
            // Whole pieces served are gone; the one being read is held.
            let left = if served == pulled {
                0
            } else {
                pulled - served / PIECE_BYTES * PIECE_BYTES
            };
            assert_eq!(prefix.held(), left);
        }
        assert_eq!(served, pulled);
    }

    #[test]
    fn a_short_reader_is_truncated() {
        let data = vec![1u8; 100];
        let mut reader: &[u8] = &data;
        let mut prefix = Prefix::default();
        let error = prefix
            .sample(0, &mut reader, 200, MOST_MISSES, false)
            .unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::Truncated));
        assert_eq!(prefix.held(), 0);
    }

    /// A sample's length is the same counted, packed in full under the
    /// option, and packed in full because the counted form handed it back
    /// (forced here; no sample the rule takes is one): the three ways a
    /// judge comes by it.
    #[test]
    fn a_judge_reads_one_length_however_it_comes_by_it() {
        let mut samples = vec![
            keystream(SAMPLE_BYTES, 9),
            rarkit_testdata::chatter(0x7374_6f72, SAMPLE_BYTES),
            vec![0u8; SAMPLE_BYTES],
            keystream(1000, 10),
            rarkit_testdata::chatter(0x7374_6f72, 3),
        ];
        let mut mixed = keystream(SAMPLE_BYTES, 11);
        mixed[20_000..40_000].copy_from_slice(&rarkit_testdata::chatter(0x7374_6f72, 20_000));
        samples.push(mixed);
        let mut counted = Judge::new(SAMPLES, false);
        let mut packed = Judge::new(SAMPLES, true);
        let mut handed_back = Judge::new(SAMPLES, false);
        for sample in &samples {
            let len = packed.packed_len(sample);
            assert_eq!(counted.packed_len(sample), len);
            let fallback =
                crate::encode::rar5::with_samples_uncovered(|| handed_back.packed_len(sample));
            assert_eq!(fallback, len);
        }
        // The counted judge built no encoder; the other two did, and the
        // judge under the option built no counter.
        assert!(counted.packer.is_none() && counted.counter.is_some());
        assert!(packed.packer.is_some() && packed.counter.is_none());
        assert!(handed_back.packer.is_some());
    }
}
