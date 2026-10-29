//! A stored member's copy: the sizes it reads and asks by, the straight
//! copy, the overlapped one, and the emit of a whole member held in
//! memory.

use super::*;

/// The copy buffer one member's packed bytes are carried through: one fixed
/// buffer, and for a stored member no decode state at all (spec F 7.3.6).
pub(crate) const COPY: usize = 64 * 1024;

/// The copy buffer a STORED member with a BLAKE2sp record is carried
/// through, which is the one case where the copy buffer IS the digest's
/// feed.
///
/// Every OTHER stored member takes [`STORED_REQUEST`] instead, which is
/// far smaller and is chosen for a different reason entirely. This
/// constant is the hasher's figure and only the hasher's.
///
/// A stored member builds no decoder (spec F 7.3.6), so nothing stands
/// between its packed bytes and the hasher: whatever this buffer is, that
/// is the size of every `Blake2sp::update` the member makes. The streaming
/// hasher absorbs a feed WHERE IT LIES only once the feed is worth its
/// kernel on its own, and at [`COPY`] it never is - so every byte of every
/// BLAKE2sp stored member was gathered into the hasher's own stage first,
/// a second pass over the whole member that the one-shot entry point never
/// makes. That is what `f/test-one-stored-blake` and
/// `f/extract-one-stored-blake` were paying for.
///
/// **Clearing the hasher's threshold is not enough, and a buffer sized TO
/// it is the worst value available.** At the threshold the gather stops,
/// but the number of batches handed to the leaf team does not fall, and
/// each call adds one more for the scrap it still has staged. Counted over
/// 16 MiB at eight workers: 64 KiB gave 32 batches and gathered every
/// byte, the threshold itself gave 62 and gathered none, and a megabyte
/// gave 31. The threshold was measured both ways for that reason -
/// a gain on a 2 GiB command-line leg, where the gather dominates, and a
/// loss on the short gate legs, where the added batches do - and the
/// change was backed out. The scrap is carried into the batch it precedes now
/// (`checksum::blake2sp::Blake2sp::dispatch_pieces`), so what is left for
/// this constant to buy is the gather and the batch count, and both want a
/// figure well above the threshold rather than at it.
///
/// **MEASURED**, and the figure is 4 MiB. An Apple M3 Mac, 32 cores, quiet box
/// (load 2.1 to 5.1), 15 pairs a leg, all three arms in ONE run with
/// the box held so the old arm is identical across them
/// (20 Sep 2026). Paired median of `old/rarkit`,
/// so higher is better and 0.97x is the gate:
///
/// | leg | before | 1 MiB | 4 MiB |
/// |---|---:|---:|---:|
/// | `f/test-one-stored-blake` | 0.766x | 0.924x | **1.016x** |
/// | `f/extract-one-stored-blake` | 0.781x | 0.939x | **1.022x** |
/// | `f/test-one-stored-encrypted` | 0.657x | 0.736x | 0.755x |
/// | `f/extract-one-stored-encrypted` | 0.665x | 0.755x | 0.774x |
///
/// Monotone, so no value between was worth timing. 4 MiB takes both
/// BLAKE2sp legs from FAIL to PASS and past the old engine, and takes
/// 9 percent off rarkit's CPU on them as well. It costs exactly its own
/// size in peak RSS - 134 to 138 MiB on the test leg - against the old
/// engine's 205 MiB on the same leg, so spec L 7's target (RSS no higher
/// than the old engine's) is kept with room to spare.
///
/// **The user's own budget binds ahead of this, and at 4 MiB the two
/// agree everywhere.** The buffer taken is the least of this constant,
/// the member's size, and [`MemoryPolicy::read_ahead`] - the policy's own
/// name for how much of a stream to hold at once, and a field the read
/// path had never spent. `read_ahead` is
/// `clamp(working_limit / 64, 64 KiB, 4 MiB)`, so its CEILING is 4 MiB
/// too: at the default 512 MiB budget both give 4 MiB, at 64 MiB the
/// budget gives 1 MiB and IT binds, and at 4 MiB it gives 64 KiB and the
/// buffer is what it always was. A caller with a small `working_limit`
/// therefore gets a small buffer without knowing this constant exists,
/// and it is never below [`COPY`], so no budget makes a stored member
/// slower than it was before this existed.
///
/// The constant is kept rather than folded into that clamp, even though
/// they coincide today, so that raising `read_ahead`'s ceiling later
/// cannot silently carry the buffer past the figure that was measured.
///
/// The worst case a caller must plan for is BREADTH times this, since
/// spec API 4.4 lets a non-solid set decode several members at once and
/// each in flight holds its own: at the default budget that is
/// `max_workers` of 8 times 4 MiB, or 32 MiB against a 512 MiB limit,
/// 6.25 percent. It falls with the budget faster than linearly, because
/// both terms are derived from it. `Scratch::held_bytes` already counts
/// this buffer, so it reaches the caller in
/// `ExtractReport::peak_working_memory` rather than being hidden.
///
/// Bounded by the member below, so an archive of short stored members does
/// not take four megabytes to carry a kilobyte.
///
/// [`MemoryPolicy::read_ahead`]: crate::MemoryPolicy::read_ahead
pub(super) const STORED_COPY: usize = 4 << 20;

/// The request a stored member with any OTHER checksum record makes of its
/// packed source.
///
/// **This is not a checksum figure and not a hasher's feed. It is a
/// REQUEST SIZE, and what it has to clear is the concurrent driver's own
/// staging window** (`read::concurrent::READ_BUF`, 64 KiB). A worker
/// serves a request that fits in that window out of a staging buffer, so
/// every byte of the member is copied twice and the member is walked in
/// 64 KiB steps whatever it asked for; a request LARGER than the window
/// is handed over directly. At [`COPY`], which is that window exactly,
/// every dispatched stored member paid the second copy.
///
/// **MEASURED, and the figure is deliberately small.** A ladder over this
/// constant on one 256 MiB stored member, four 64 MiB ones and nine 16
/// MiB ones, `rarfast` against the same tree with the bypass out, wall as
/// a fraction of that base and peak RSS beside it. A laptop, 18 cores,
/// one-minute load 17 to 27, so INDICATIVE and not a gate figure:
///
/// | leg | 128 KiB | 256 KiB | 1 MiB | 4 MiB |
/// |---|---:|---:|---:|---:|
/// | one 256 MiB, `t` | **0.734x** | 0.812x | 0.842x | 0.830x |
/// | one 256 MiB, `x` | 0.859x | 0.819x | **0.810x** | 0.838x |
/// | 4 x 64 MiB, `t` | 0.742x | 0.735x | **0.580x** | 0.789x |
/// | 4 x 64 MiB, `x` | 0.967x | **0.804x** | 0.837x | 0.855x |
/// | 9 x 16 MiB, `t` | **0.772x** | 0.778x | 0.824x | 1.005x |
/// | peak RSS, 9 x 16 MiB | **5 MiB** | 6 MiB | 13 MiB | 40 MiB |
///
/// **A LARGE buffer takes the win back on breadth and buys the RSS.**
/// Nine members in flight at 4 MiB each is 40 MiB of buffer that no
/// member reads twice, and the `t` row above walks from 0.772x to 1.005x
/// across the ladder for that reason: the checksum then reads its bytes
/// back out of memory instead of out of cache. What the bypass is worth
/// is the copy it removes, and removing it needs only a request the
/// window cannot swallow. So this is set just past the window rather than
/// as large as the budget allows, and the worst case a caller plans for -
/// BREADTH times this - is 8 times 128 KiB against a 512 MiB budget.
///
/// **And a SECOND reason for a small figure, which is not about speed at
/// all.** This buffer is also the slice a refusing writer is offered: the
/// sequential path hands the sink one chunk at a time, and spec F 3.7.6
/// bounds what a writer that refuses is made to look at. The 4 MiB draft
/// took `one_member_seam`'s
/// `the_coalescing_deliver_unit_is_reachable_and_is_not_the_default` from
/// pass to FAIL, because the sequential path then offered a refusing
/// writer MORE than the seam's whole ring did and the knob that prices
/// the ring had nothing left to price. At 128 KiB that test reads 135,129
/// bytes offered in two writes against the coalescing ring's 1,048,576,
/// which is the margin the seam's own measurement needs. A figure chosen
/// for the read alone would have loosened a promise the read cannot see.
///
/// **CONFIRMED against its nearest neighbour, 21 Sep 2026.** The ladder
/// above is a laptop's and INDICATIVE. A timed hold on an Apple M1 Mac (20
/// cores, the box held, both constants in ONE run each against its own
/// base arm) measured 128 KiB against 256 KiB: 256 KiB
/// is better on four of the six stored tool legs and on two of the three
/// gate legs, and loses `f/extract-par-8x16-stored-vsconc` by 6 percent
/// with intervals that do not overlap (7.020x against 6.624x). That leg is
/// EIGHT members in flight, so it is the 4 MiB draft's own mechanism one
/// notch down: each member holds its own buffer, and eight times 256 KiB
/// has the checksum reading out of memory rather than cache. **So the
/// figure is a TRADE and not a free win** - about 6 percent given up on the
/// narrow `t` legs to keep 6 percent on the breadth leg - and an archive
/// set known to be narrow would prefer 256 KiB, which is an argument for a
/// caller-side knob rather than for a different default.
///
/// The caller's `read_ahead` still binds ahead of it, so a small budget
/// gives a small request: at a 4 MiB `working_limit`, `read_ahead` is 64
/// KiB, this clamps to [`COPY`] and a dispatched member reads exactly as
/// it did before any of this existed.
pub(super) const STORED_REQUEST: usize = 128 * 1024;

/// The request has to EXCEED the worker's staging window or the bypass it
/// exists for never fires, and a window that grew past it would turn this
/// constant off silently rather than loudly. Held at COMPILE time because
/// there is no run in which it may be false.
const _: () = assert!(STORED_REQUEST > COPY);

/// How much of a stored member to carry at once: the least of the measured
/// ceiling [`STORED_COPY`], the caller's budget and the member itself, and
/// never below [`COPY`].
///
/// A BLAKE2sp record takes [`STORED_COPY`], where this buffer is the
/// digest's own feed. Every other stored member takes [`STORED_REQUEST`],
/// which is not about the checksum at all.
///
/// A free function so the rule is pinned by
/// `tests::the_stored_copy_buffer_stays_inside_the_callers_budget` rather
/// than stated in a comment.
pub(super) fn stored_copy_len(blake: bool, unpacked_size: Option<u64>, read_ahead: u64) -> usize {
    let want = if blake { STORED_COPY } else { STORED_REQUEST };
    let ceiling = (want as u64).min(read_ahead).max(COPY as u64);
    let member_bytes = unpacked_size.unwrap_or(0).max(COPY as u64);
    member_bytes.min(ceiling).min(usize::MAX as u64) as usize
}

/// Members below this never overlap their cipher with their hasher: a
/// thread and a hand-over cost more than the stage they would hide.
///
/// Two chunks is the smallest member with anything to overlap AT ALL -
/// one chunk has no successor to decrypt under its hash - so the floor
/// is expressed as a multiple of the chunk rather than as a size, and
/// `overlap_plan` applies it that way. This absolute figure is the
/// second condition: at a megabyte the cipher's share of the member is
/// about 200 microseconds, against a thread spawn and a join measured in
/// tens, and below it the hand-over is the larger term.
#[cfg(feature = "parallel")]
pub(super) const OVERLAP_FLOOR: u64 = 1 << 20;

/// The chunk each of the overlap's TWO buffers holds, or `None` when this
/// member runs the serial loop.
///
/// **The chunk is the serial path's OWN, and the second buffer is not
/// read-ahead.** Spec F 3.7.2's read-ahead bound is how far the engine
/// may run ahead of the byte it is DELIVERING, and in `copy_overlapped`
/// a buffer is written to the caller's writer BEFORE it is handed to
/// the hasher: by the time the hasher holds it, every byte of it has
/// already been delivered. So only the buffer the calling thread is
/// filling is ahead of the delivery point, exactly as on the serial
/// path, and the read-ahead bound is unchanged in words and in value
/// with no halving at all.
///
/// This is where `read::seam::ring_plan` differs and why the arithmetic
/// is not copied from it: the seam's ring buffers are filled by the
/// SOURCE unit and not yet written by the DELIVER unit, so they are
/// genuinely ahead and the seam halves the budget to pay for them.
/// Getting this wrong the other way costs real wall - halving would
/// feed the hasher 2 MiB where the serial path feeds it 4 MiB, and
/// the dispatch census says half the feed is about
/// twice the dispatches and twice the width-one staged remainder.
///
/// **What the second buffer IS is working memory**, one chunk of it per
/// member in flight, and that counts against
/// `MemoryPolicy::working_limit`, which is a hard
/// ceiling. `Scratch::held_bytes` counts it and
/// `the_overlaps_two_buffers_stay_inside_the_callers_budget` holds the
/// breadth-times-buffer product inside the quarter of the budget the
/// serial path's own test uses. Read as a DELTA the extra chunk is
/// outside the tolerance; read as the CEILING the target names,
/// it is far inside, which is the same reading recorded when
/// the stored copy buffer went to 4 MiB. Flagged rather than hidden.
///
/// The four conditions, none of them a promise to a caller (SPEC-API
/// 8.5, which says only that a member MAY be overlapped):
///
/// - the member is ENCRYPTED and carries a BLAKE2sp record. That pair is
///   the whole of what this is for: the cipher is the serial stage
///   (CPU/wall 1.2 on `k/aes256/cbc-decrypt-64MiB`) and BLAKE2sp is the
///   wide one (6.6 on `l/blake2sp/chunk1m-8w-vs8w`), so their sum is the
///   member and their maximum is what an overlap costs. A CRC32 record
///   leaves a word-at-a-time checksum with nothing to hide behind, and an
///   unencrypted member has no serial stage to hide;
/// - there is a WIDTH unit to spend, which a width of one does not have;
/// - the member is at least [`OVERLAP_FLOOR`];
/// - the member is at least TWO chunks, one chunk having no successor to
///   decipher under its hash and therefore nothing to overlap.
#[cfg(feature = "parallel")]
pub(super) fn overlap_plan(
    blake: bool,
    encrypted: bool,
    unpacked_size: Option<u64>,
    read_ahead: u64,
    width: usize,
) -> Option<usize> {
    if !blake || !encrypted || width < 2 {
        return None;
    }
    // The serial path's own chunk, for the reason in the doc above: the
    // second buffer is behind the delivery point and is not read-ahead.
    let chunk = stored_copy_len(true, unpacked_size, read_ahead);
    let size = unpacked_size?;
    if size < OVERLAP_FLOOR || size < 2 * chunk as u64 {
        return None;
    }
    Some(chunk)
}

/// Whether the overlap runs, with the measurement knob's answer taking
/// precedence over the engine's own.
///
/// The knob is what prices `f/extract-one-stored-encrypted-overlap` ON
/// against OFF in one binary (`probe::set_cipher_overlap`); it moves the
/// ARRANGEMENT and never the bytes.
/// The bench's chunk dial, which overrides the SIZE `overlap_plan`
/// chose and never the decision it made. A function with two bodies
/// rather than a `cfg`-selected binding, so the shipping build's `None`
/// is not a literal clippy can see through in the caller.
#[cfg(all(feature = "parallel", feature = "cipher-overlap-knob"))]
pub(super) fn overlap_dial() -> Option<usize> {
    crate::probe::cipher_overlap_chunk()
}

#[cfg(all(feature = "parallel", not(feature = "cipher-overlap-knob")))]
pub(super) fn overlap_dial() -> Option<usize> {
    None
}

#[cfg(feature = "parallel")]
pub(super) fn overlap_chunk(
    blake: bool,
    encrypted: bool,
    unpacked_size: Option<u64>,
    read_ahead: u64,
    width: usize,
) -> Option<usize> {
    let dial = overlap_dial();
    #[cfg(feature = "cipher-overlap-knob")]
    match crate::probe::cipher_overlap() {
        Some(false) => return None,
        Some(true) => {
            // Forced on: the floor and the two-chunk rule give way, and
            // nothing else does. A member with no room for a ring still
            // runs in sequence, because there is no arrangement to force.
            if !blake || !encrypted {
                return None;
            }
            return Some(dial.unwrap_or_else(|| stored_copy_len(true, unpacked_size, read_ahead)));
        }
        None => {}
    }
    overlap_plan(blake, encrypted, unpacked_size, read_ahead, width).map(|own| dial.unwrap_or(own))
}

/// A stored member: the packed bytes ARE the member, carried through one
/// fixed buffer with no decode state built at all (spec F 7.3.6).
#[allow(clippy::too_many_arguments)]
pub(super) fn copy<R: PackedRead, W: std::io::Write, T: Tally>(
    mut packed: Packed<R>,
    member: &mut Member<W>,
    blake: &mut Option<Box<Blake2sp>>,
    tally: &mut T,
    copy_buf: &mut Vec<u8>,
    pair_buf: &mut Vec<u8>,
    read_ahead: u64,
    width: usize,
    width_stated: bool,
    budget: Lanes<'_>,
) -> Result<()> {
    // SPEC-F 3.7.7: an encrypted member's cipher output feeds
    // the hasher AS IT IS PRODUCED, so the member's wall is the LARGER of
    // the two stages and not their sum. Measured on an Apple M3 Mac, 64 MiB:
    // 12.41 ms of cipher at one thread and 17.81 ms of BLAKE2sp at eight,
    // where the serial loop below pays 30.2 ms for both.
    #[cfg(feature = "parallel")]
    if let Some(chunk) = overlap_chunk(
        blake.is_some() && member.blake,
        packed.encrypted(),
        member.unpacked_size,
        read_ahead,
        width,
    ) {
        if let Some(hasher) = blake.as_deref_mut() {
            // Counted so an acceptance test cannot pass vacuously: see
            // `probe::CIPHER_OVERLAPS`.
            #[cfg(feature = "cipher-overlap-knob")]
            crate::probe::note_cipher_overlap();
            return copy_overlapped(packed, member, hasher, tally, copy_buf, pair_buf, chunk);
        }
    }
    #[cfg(not(feature = "parallel"))]
    let _ = (pair_buf, width, width_stated, budget);
    // A stored member with a CRC32 and nothing else to run over it is read
    // and hashed on `width` threads (`read::wide`), and written, where it
    // is written at all, in order from this thread: which is where the
    // wall of `t`, `p` and `x` on a large stored member goes. Every other
    // stored member takes the loop below.
    #[cfg(feature = "parallel")]
    let mut wide = wide_plan(&packed, member, blake, read_ahead, width);
    // The breadth rule's hold on this member's pieces, where its knob is on
    // and the width was not stated (`read::wide::hold`); kept across the
    // member's ranges.
    #[cfg(feature = "parallel")]
    let mut hold = crate::read::wide::hold(width, width_stated);
    // This buffer is the size of the request made of the packed source,
    // and with a BLAKE2sp record it is the hasher's feed as well: see
    // [`STORED_COPY`] and [`stored_copy_len`]. The member's own size caps
    // it, and the buffer only ever grows, so a run of short members never
    // walks it back up.
    let want = stored_copy_len(blake.is_some(), member.unpacked_size, read_ahead);
    let mut buf = std::mem::take(copy_buf);
    if buf.len() < want {
        buf.resize(want, 0);
    }
    let outcome = (|| -> Result<()> {
        loop {
            #[cfg(feature = "parallel")]
            if let (Some(plan), true) = (wide, packed.encrypted()) {
                // An ENCRYPTED stored member: its whole
                // blocks go wide, deciphered piece by piece; what is not a
                // run of whole blocks from a clean chain takes one short
                // read below and the range is asked for again.
                match packed.stream.span()? {
                    Span::End => return Ok(()),
                    Span::Range { source, at, len } => {
                        let pending = packed.decryptor.as_ref().map_or(0, |d| d.pending());
                        // Clamped to the member's declared size, so the
                        // padded last block (spec F 4.2) and anything past
                        // it take `emit`'s clamp on the serial loop.
                        let whole = member
                            .unpacked_size
                            .map_or(len, |n| n.saturating_sub(member.written))
                            .min(len)
                            & !15;
                        if pending == 0 && whole >= crate::read::wide::FLOOR {
                            let first = member.written == 0;
                            let granted = granted(&packed.stream, budget, plan, whole, first);
                            if let Some((whole, granted, _grant, hand)) = granted {
                                decipher_wide(
                                    &mut packed,
                                    member,
                                    tally,
                                    &source,
                                    at,
                                    whole,
                                    granted,
                                    plan,
                                    hand,
                                    hold.as_mut(),
                                )?;
                                continue;
                            }
                        }
                        // A block the last fragment left part way (SPEC-K
                        // 3.7.4: fragments need not be whole blocks), or
                        // a fragment's tail shorter than one: finish that
                        // block alone, so the next range starts clean,
                        // rather than read a whole buffer serially.
                        if pending != 0 || len < 16 {
                            #[cfg(feature = "test-support")]
                            crate::probe::note_wide_block_join();
                            let got = packed.read(&mut buf[..32])?;
                            if got == 0 {
                                return Ok(());
                            }
                            emit_whole(member, blake, tally, &buf[..got], None)?;
                            continue;
                        }
                    }
                    Span::Narrow => {}
                }
            } else if let Some(plan) = wide {
                match packed.stream.span()? {
                    Span::End => return Ok(()),
                    Span::Range { source, at, len } if len >= crate::read::wide::FLOOR => {
                        if member
                            .unpacked_size
                            .is_some_and(|n| member.written + len > n)
                        {
                            // More packed bytes than the member declares:
                            // `emit` drops the excess, so the rest takes
                            // the loop that does.
                            wide = None;
                        } else if let Some((len, granted, _grant, hand)) =
                            granted(&packed.stream, budget, plan, len, member.written == 0)
                        {
                            // A BLAKE2sp member's hasher goes with the
                            // range: the joining thread feeds it.
                            let hasher = blake.as_deref_mut().filter(|_| member.blake);
                            verify_wide(
                                &mut packed.stream,
                                member,
                                tally,
                                &source,
                                at,
                                len,
                                granted,
                                plan,
                                hand,
                                hasher,
                                hold.as_mut(),
                            )?;
                            continue;
                        }
                    }
                    // A fragment UNDER the floor, as every fragment of a
                    // set posted in small volumes is: this one and those
                    // after it are read by one team kept across their
                    // volumes (`read::across`), until the member ends or a
                    // fragment at the floor stands next.
                    Span::Range { len, .. } if across_takes(&packed.stream, member, len, plan) => {
                        match copy_across(&mut packed.stream, member, tally, plan)? {
                            Some(crate::read::across::Ended::Member) => return Ok(()),
                            Some(crate::read::across::Ended::Over) => continue,
                            // Nothing was taken: one ordinary read below.
                            None => {}
                        }
                    }
                    // A fragment's head already in the walk's buffer, or a
                    // short one: one ordinary read below, then ask again.
                    Span::Range { .. } | Span::Narrow => {}
                }
            }
            // Asked for only where the member's CRC32 will be read: a
            // stream that hashes a fragment for its own check hands that
            // CRC on, and `emit` appends it rather than hashing again.
            let (got, whole) = if member.crc_wanted {
                packed.read_crc(&mut buf)?
            } else {
                (packed.read(&mut buf)?, None)
            };
            if got == 0 {
                return Ok(());
            }
            emit_whole(member, blake, tally, &buf[..got], whole)?;
        }
    })();
    *copy_buf = buf;
    outcome
}

/// Whether an encrypted stored member WRITTEN TO A FILE (`x`) takes the
/// wide read. A clear one does not (the seam hides its read behind the
/// write, and the wide read bought `x` nothing on Zen 4); an encrypted
/// one's serial read is its cipher, which on aarch64 is the wall of `x`
/// itself (2.12 s against 1.13 s for the clear twin, an Apple M1 Mac).
#[cfg(feature = "parallel")]
pub(super) fn cipher_to_file() -> bool {
    true
}

/// The same member with its CIPHER and its HASHER overlapped: SPEC-F
/// 3.7.7, where these two legs actually run.
///
/// **Which stage moves, and why it is this one.** The hasher goes to a
/// scoped thread and everything else stays on the calling thread: the
/// read, the decrypt, the CRC, the write to the caller's writer and the
/// tally. That assignment is what makes this change free of any
/// signature: `Member<W>`'s writer and the `Tally` never leave the
/// thread that called `extract`, so neither gains a `Send` bound and
/// `PackedRead` gains none either, where moving the READ instead would
/// have needed `R: Send` on `decode` and on both its drivers. Only
/// [`Blake2sp`] crosses, and it is `Send` already.
///
/// **SPEC-F 3.7.7's sentence, and the two halves of it this keeps.** The
/// cipher's output feeds the hasher as it is produced, so chunk N is
/// hashed while chunk N+1 is being read and deciphered, and the member's
/// wall is the LARGER of the two stages plus one chunk of ramp rather
/// than their sum. Within any ONE chunk the decrypt still finishes
/// before that chunk is hashed - the buffer is not handed over until
/// `emit` has returned - so the hasher never sees a ciphertext byte. And
/// the cipher is not spread across workers: it stays on the one calling
/// thread, which is the pool question answered NO, as the spec
/// answers it.
///
/// **The bytes and the verdict are identical with the overlap on or
/// off.** The hasher is fed in stream order because one thread receives
/// the chunks over one channel, and it is fed exactly the bytes `emit`
/// counted as accepted - spec F 4.2's dropped padding included, which is
/// why `emit` returns that count rather than this function recomputing
/// it.
///
/// **Two buffers and no more.** They come out of `read_ahead` rather
/// than beside it (`overlap_plan`), so the total held is what the serial
/// path holds. Two is the whole of the overlap: a third buys no stage's
/// worth of hiding and costs its own size in read-ahead, which is
/// `read::seam::RING`'s arithmetic and the same answer.
///
/// **Cancellation.** A failed write, a failed tally or a read error ends
/// the loop, drops the full channel, and the scope joins before this
/// returns: the hasher does at most the one chunk it already holds. The
/// caller's error is the one reported, the hasher having none to raise.
#[cfg(feature = "parallel")]
pub(super) fn copy_overlapped<R: PackedRead, W: std::io::Write, T: Tally>(
    mut packed: Packed<R>,
    member: &mut Member<W>,
    hasher: &mut Blake2sp,
    tally: &mut T,
    copy_buf: &mut Vec<u8>,
    pair_buf: &mut Vec<u8>,
    chunk: usize,
) -> Result<()> {
    use std::sync::mpsc::sync_channel;

    // SPEC-K 2.1, and the second half of that question: the CBC
    // DECRYPT of this member's bulk runs on TWO LANES rather than one.
    //
    // **The width this spends is the plan's, not a new one.** This
    // function runs only where `overlap_plan` said yes, which requires a
    // width of at least two, and the threads it then has alive at once
    // are the hasher's and the cipher's second lane: two scoped threads
    // per member in flight, which is inside SPEC-API 8.3's "at most
    // `max_workers` per member". The calling thread is the caller's own
    // and is not one of them. No pool is created, resized or read from
    // the environment, which 8.3 forbids outright.
    //
    // **Why it is worth a lane at all, and why only one.**
    // The 22 Sep decomposition: after the overlap
    // below, the member's wall is the LARGER of the cipher and the
    // hasher, and the cipher-bearing calling thread sticks out above the
    // hasher by 0.969 ms against a cipher of 11.646. Halving the cipher
    // takes about 5.8 ms off that thread, far more than its excess, so
    // the leg becomes hasher bound and a THIRD lane would buy nothing
    // while costing the breadth a unit it could spend on another member.
    //
    // The decrypt is parallel by construction, block `i`'s plaintext
    // needing only `C[i]` and `C[i-1]`, so this is the same bytes in a
    // different order of work: `crypto::cbc::CbcDec::decrypt_blocks_two_lane`
    // carries the argument and `crypto::tests` pins the two forms equal.
    #[cfg(feature = "k-two-lane-probe")]
    let two_lane = crate::probe::two_lane_cipher().unwrap_or(true);
    #[cfg(not(feature = "k-two-lane-probe"))]
    let two_lane = true;
    if let Some(decryptor) = packed.decryptor.as_mut() {
        decryptor.set_two_lane(two_lane);
    }

    // The two buffers come from the operation's scratch, so a run of
    // members allocates them once rather than once each. They travel by
    // value through the channels and come home at the join.
    let mut first = std::mem::take(copy_buf);
    let mut second = std::mem::take(pair_buf);
    first.resize(chunk, 0);
    second.resize(chunk, 0);

    // `full` holds one: the calling thread can only ever be a chunk
    // ahead, there being two buffers and one of them in its hand.
    // `empty` holds both, so the hasher never blocks giving one back.
    let (full_tx, full_rx) = sync_channel::<Vec<u8>>(1);
    let (empty_tx, empty_rx) = sync_channel::<Vec<u8>>(2);
    let _ = empty_tx.send(first);
    let _ = empty_tx.send(second);

    let mut recovered: Vec<Vec<u8>> = Vec::with_capacity(2);
    let outcome = std::thread::scope(|scope| {
        // The operation's meter follows its threads (API 8.4.1, `memory::Meter`).
        let op = crate::memory::op_slot();
        let started = crate::threads::scoped_with(
            scope,
            (hasher, full_rx, empty_tx),
            move |(hasher, full_rx, empty_tx)| {
                let _op = crate::memory::enter(op);
                // In stream order by construction: one receiver, one
                // channel, one chunk at a time.
                while let Ok(buf) = full_rx.recv() {
                    hasher.update(&buf);
                    if empty_tx.send(buf).is_err() {
                        break;
                    }
                }
            },
        );
        // No thread for the hasher (`crate::threads`): it runs here, on
        // each chunk as it is handed over, which is the serial arrangement
        // and hashes the same bytes in the same order.
        let (hashing, mut here) = match started {
            Ok(hashing) => (Some(hashing), None),
            Err((hasher, _, empty_tx)) => (None, Some((hasher, empty_tx))),
        };
        // A chunk the member refused every byte of is kept HERE rather
        // than handed on, because the hasher must be fed exactly what
        // `emit` accepted and it accepted none of it. Keeping it also
        // keeps the buffer count at two: handing it to a channel the
        // hasher owns the other end of would lose it.
        let mut held: Option<Vec<u8>> = None;
        let outcome = (|| -> Result<()> {
            loop {
                let mut buf = match held.take() {
                    Some(buf) => buf,
                    // The hasher only drops its sender once this loop has
                    // dropped the full side, so this is the end and not a
                    // failure.
                    None => match empty_rx.recv() {
                        Ok(buf) => buf,
                        Err(_) => return Ok(()),
                    },
                };
                // Grown, never cleared: `resize` zeroes only the tail a
                // previous `truncate` cut, which is nothing at all until
                // the member's last short chunk.
                buf.resize(chunk, 0);
                let got = packed.read(&mut buf)?;
                if got == 0 {
                    held = Some(buf);
                    return Ok(());
                }
                // The write, the CRC and the tally happen HERE, before
                // the hand-over, so the caller's writer sees exactly the
                // calls it sees on the serial path and a refusal is
                // raised at the same byte (spec F 3.7.6).
                let took = emit(member, &mut None, tally, &buf[..got])?;
                if took == 0 {
                    held = Some(buf);
                    continue;
                }
                buf.truncate(took);
                if let Some((hasher, empty_tx)) = &mut here {
                    hasher.update(&buf);
                    // Room for both buffers, so this never blocks.
                    let _ = empty_tx.send(buf);
                    continue;
                }
                if full_tx.send(buf).is_err() {
                    // Unreachable while this loop holds the sender; a
                    // stop rather than an error if it ever is not.
                    return Ok(());
                }
            }
        })();
        drop(full_tx);
        drop(here);
        if let Some(hashing) = hashing {
            let _ = hashing.join();
        }
        if let Some(buf) = held {
            recovered.push(buf);
        }
        while let Ok(buf) = empty_rx.try_recv() {
            recovered.push(buf);
        }
        outcome
    });

    // The buffers come home whatever happened, largest first, so the
    // next member reuses them and `Scratch::held_bytes` keeps counting
    // what is really held.
    recovered.sort_by_key(|buf| std::cmp::Reverse(buf.capacity()));
    let mut home = recovered.into_iter();
    *copy_buf = home.next().unwrap_or_default();
    *pair_buf = home.next().unwrap_or_default();
    outcome
}

/// Push decoded bytes into the member's output and running checksums,
/// and answer how many of them the member ACCEPTED.
///
/// The count is what the overlap needs and is why it is returned rather
/// than dropped: `copy_overlapped` hashes on another thread and must
/// hash exactly the bytes this function counted, so the clamp below
/// stays the ONE place a member's declared size is applied. A second
/// copy of that arithmetic beside it is a second chance to disagree with
/// it, and spec F 4.2's padding rule is subtle enough that the two would
/// eventually differ over the last block of an encrypted member.
pub(super) fn emit<W: std::io::Write, T: Tally>(
    member: &mut Member<W>,
    blake: &mut Option<Box<Blake2sp>>,
    tally: &mut T,
    plain: &[u8],
) -> Result<usize> {
    emit_whole(member, blake, tally, plain, None)
}

/// [`emit`], given the CRC32 of the WHOLE of `plain` where a reader
/// already computed it. The member's register appends that CRC only when
/// the member accepts every byte of `plain`; a read the declared size
/// clips is hashed over its accepted prefix exactly as without one.
pub(super) fn emit_whole<W: std::io::Write, T: Tally>(
    member: &mut Member<W>,
    blake: &mut Option<Box<Blake2sp>>,
    tally: &mut T,
    plain: &[u8],
    whole: Option<u32>,
) -> Result<usize> {
    // The declared unpacked size is never used to size a buffer; it is a
    // limit on output, checked as output is produced (spec F 4.2).
    //
    // Output past it is DROPPED rather than refused, because that is what
    // an encrypted stored member needs: its packed size is its plaintext
    // rounded up to the cipher's block, so the last block carries padding
    // the member does not own. Spec F 4.2's stronger rule - a member that
    // produces more than it declared is `Corrupt` at that byte - belongs to
    // the decoders, which know the difference between padding and an
    // over-producing stream.
    //
    // The room left is computed in `u64` and SATURATED into a `usize`, not
    // truncated: a member above 4 GiB has more room left than a 32-bit
    // `usize` holds, and truncating there would cut a chunk short in the
    // middle of a member with no error at all. Saturating is exact,
    // because `plain.len()` can never exceed `usize::MAX` either.
    let take = match member.unpacked_size {
        Some(n) => {
            let room = usize::try_from(n - member.written.min(n)).unwrap_or(usize::MAX);
            plain.len().min(room)
        }
        None => plain.len(),
    };
    let whole = whole.filter(|_| take == plain.len());
    let plain = &plain[..take];
    if plain.is_empty() {
        return Ok(0);
    }
    if member.crc_wanted {
        if let Some(crc) = whole {
            member.crc.append(crc, take as u64);
            #[cfg(feature = "test-support")]
            crate::probe::note_crc_shared(false, take);
        } else {
            member.crc.update(plain);
        }
    }
    if let Some(s) = &mut member.sum16 {
        s.update(plain);
    }
    if member.blake {
        if let Some(b) = blake {
            b.update(plain);
        }
    }
    if let Some(Out::Write(w)) = &mut member.out {
        std::io::Write::write_all(w, plain)?;
    }
    member.written += plain.len() as u64;
    tally.output(plain.len())?;
    Ok(take)
}
