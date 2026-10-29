//! A clear stored member under the seam READS INTO THE RING.
//!
//! Under the seam of spec F 3.7.7 a stored member's source unit read its
//! packed bytes into the copy buffer, ran the member's checksums over
//! them in `emit` and wrote them into a ring slab, which is a memcpy of
//! every extracted byte (counted: 4,294,967,296 bytes for a
//! 4 GiB member). Here the ring LENDS the tail of the slab it is filling,
//! the packed read lands in it, the checksums run over it in place, and
//! the read is COMMITTED as one mark. The caller's writer sees the same
//! calls in the same order; the copy between is gone.
//!
//! **Why a module of its own, behind one `#[inline(never)]` entry.** The
//! first form split `emit` and put this beside it, and the decoders'
//! per-write path paid for it: the compressed text rows read 0.35 to 1.1
//! percent slower on both timed boxes at equal instructions, placement
//! and not work. A decoder
//! never reaches this code, so it is kept where the decoders' functions
//! compile exactly as they do without it; `emit`, the ring's `write` and
//! the ring's slab handling are the control's own text.

use crate::checksum::blake2sp::Blake2sp;
use crate::crypto::MemberDecryptor;
use crate::error::Result;

use super::{stored_copy_len, Decoders, Member, Out, Packed, PackedRead, Tally};

/// A writer that can LEND the region its next bytes will occupy.
pub(crate) trait Lend {
    /// Up to `want` bytes of room, never empty.
    fn lend(&mut self, want: usize) -> std::io::Result<&mut [u8]>;
    /// The first `n` bytes of the region last lent are the member's.
    fn commit(&mut self, n: usize) -> std::io::Result<()>;
    /// The member is finished: hand over what is held, and leave nothing
    /// a later `flush` could mistake for bytes.
    fn finish(&mut self) -> std::io::Result<()>;
}

/// Whether a stored member under the seam is lent: a CLEAR member with no
/// BLAKE2sp record, the narrowest of the screened forms. A BLAKE2sp
/// member's hasher feed would shrink from `STORED_COPY` to a ring chunk,
/// and an encrypted member's cipher carries its own buffer shape; neither
/// is lent until a screen prices it.
pub(crate) fn lends<W>(member: &Member<W>, encrypted: bool) -> bool {
    !member.blake && !encrypted
}

/// How many of `len` more bytes the member accepts. The SAME arithmetic
/// as `emit`'s clamp (spec F 4.2), written out rather than shared: sharing
/// it reshaped `emit`, which every decoder writes through. A clear member
/// has no cipher padding, so here it only ever cuts a stream that runs
/// past its declared size.
fn room<W>(member: &Member<W>, len: usize) -> usize {
    match member.unpacked_size {
        Some(n) => {
            let room = usize::try_from(n - member.written.min(n)).unwrap_or(usize::MAX);
            len.min(room)
        }
        None => len,
    }
}

/// A stored member at or above this asks the ring for the WHOLE of the
/// slab it is lent at each read, so the source unit makes one read and the
/// deliver unit one write per slab (1 MiB at the default budget) instead of
/// one per [`super::STORED_REQUEST`] (128 KiB): eight times fewer reads,
/// marks and writes for the same bytes in the same ring, no extra memory.
///
/// **Why a floor, and why this one.** The request size is what a refusing
/// writer is offered (`one_member_seam`'s
/// `the_coalescing_deliver_unit_is_reachable_and_is_not_the_default` pins
/// the seam at or under the sequential path's offer, which is
/// [`super::STORED_REQUEST`]), so the larger request is taken only where
/// the seam takes a member on SIZE (`seam::SEAM_FLOOR`, 1 GiB), where a
/// megabyte offered to a writer that refuses is nothing against the member
/// and the hand-overs are the measurable cost: on a Ryzen 7 9800X3D writing
/// a 12 GiB member to a WD SN8100 past the cache, 98,000 reads and writes of
/// 128 KiB held `rarfast x` at 2.34 s where the disk takes 4 MiB blocks at
/// 1.2 s (29 Sep 2026). A measured constant and not
/// an API fact.
///
/// **This is the floor of a member with a DECODER** (`seam::overlapped`
/// cuts its drain into slabs from the same size). A stored member on the
/// lent path asks for whole slabs from the size the seam takes it on,
/// `seam::LENT_FLOOR`, that one name and no figure of its own here: the
/// two were counted together and the seam without the larger request is
/// the weaker arm at every size (11 Oct 2026).
const WHOLE_SLAB_FLOOR: u64 = 1 << 30;

/// Whether a member of `unpacked_size` bytes asks for whole slabs: the
/// measurement knob's answer where a count set one, else the floor of its
/// kind (`lent`: a stored member reading into the ring).
fn whole_slab(unpacked_size: Option<u64>, lent: bool) -> bool {
    #[cfg(feature = "seam-knob")]
    if let Some(on) = crate::probe::lent_whole_slab() {
        return on;
    }
    #[cfg(feature = "read-depth-knob")]
    if let Some(floor) = whole_slab_floor_knob() {
        return unpacked_size.is_some_and(|n| n >= floor);
    }
    let floor = if lent {
        crate::read::seam::LENT_FLOOR
    } else {
        WHOLE_SLAB_FLOOR
    };
    unpacked_size.is_some_and(|n| n >= floor)
}

/// COUNT ONLY (feature `read-depth-knob`, never shipped):
/// `RARKIT_WHOLE_SLAB_FROM_MIB`, read once, states [`WHOLE_SLAB_FLOOR`] in
/// MiB (0 is every size, 1024 the shipped figure), beside the seam's own
/// `RARKIT_SEAM_FROM_MIB`, so a count moves the two floors together or
/// apart from one binary.
#[cfg(feature = "read-depth-knob")]
fn whole_slab_floor_knob() -> Option<u64> {
    static MIB: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    *MIB.get_or_init(|| {
        std::env::var("RARKIT_WHOLE_SLAB_FROM_MIB")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|mib| *mib <= 1 << 20)
            .map(|mib| mib << 20)
    })
}

/// The request a lent stored member of `unpacked_size` bytes makes of the
/// ring at each read: the whole slab from its floor ([`whole_slab`]), else the
/// sequential path's own ([`super::stored_copy_len`], from the OPERATION's
/// `read_ahead`, not the source unit's remainder, which is nothing once
/// the ring has taken the whole budget). Decided on the walking thread,
/// where a test's dial is set, and handed to [`decode_lent`].
pub(crate) fn request(
    unpacked_size: Option<u64>,
    blake: bool,
    read_ahead: u64,
    lent: bool,
) -> usize {
    if whole_slab(unpacked_size, lent) {
        usize::MAX
    } else {
        stored_copy_len(blake, unpacked_size, read_ahead)
    }
}

/// `decode` for a stored member whose writer lends. Per read, `emit`'s
/// order: the clamp, the checksums, the write (here the commit), the
/// count, the tally.
#[inline(never)]
pub(crate) fn decode_lent<R: PackedRead, L: std::io::Write + Lend, T: Tally>(
    stream: R,
    member: &mut Member<L>,
    blake: &mut Option<Box<Blake2sp>>,
    tally: &mut T,
    decryptor: Option<MemberDecryptor>,
    decoders: &mut Decoders,
    want: usize,
) -> Result<()> {
    #[cfg(feature = "test-support")]
    crate::probe::note_decoded();
    let _slot = decoders.budget.clone();
    let _slot = _slot.as_ref().map(|b| b.member_in());
    let mut packed = Packed::new(stream, decryptor);
    let Some(Out::Write(mut out)) = member.out.take() else {
        unreachable!("the seam's member always writes into its ring")
    };
    let outcome = (|| -> Result<()> {
        loop {
            let region = out.lend(want)?;
            // The read's CRC where the stream computed one for a
            // fragment check, asked for only where the member's CRC32
            // will be read: `emit_whole`'s share, on the lent path.
            let (got, whole) = if member.crc_wanted {
                packed.read_crc(region)?
            } else {
                (packed.read(region)?, None)
            };
            if got == 0 {
                return Ok(out.finish()?);
            }
            let take = room(member, got);
            if take == 0 {
                continue;
            }
            let plain = &region[..take];
            if member.crc_wanted {
                match whole.filter(|_| take == got) {
                    Some(crc) => {
                        member.crc.append(crc, take as u64);
                        #[cfg(feature = "test-support")]
                        crate::probe::note_crc_shared(true, take);
                    }
                    None => member.crc.update(plain),
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
            out.commit(take)?;
            member.written += take as u64;
            tally.output(take)?;
        }
    })();
    member.out = Some(Out::Write(out));
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole-slab request starts at each kind's own floor: the size
    /// the seam takes a lent stored member on, and a gibibyte for a member
    /// with a decoder; a member with no declared size never asks for it.
    #[test]
    fn whole_slabs_are_asked_for_from_each_kinds_floor() {
        crate::probe::set_lent_whole_slab(None);
        let lent = crate::read::seam::LENT_FLOOR;
        assert!(lent <= WHOLE_SLAB_FLOOR);
        for (floor, kind) in [(lent, true), (WHOLE_SLAB_FLOOR, false)] {
            assert!(whole_slab(Some(floor), kind));
            assert!(whole_slab(Some(floor * 12), kind));
            assert!(!whole_slab(Some(floor - 1), kind));
            assert!(!whole_slab(Some(0), kind));
            assert!(!whole_slab(None, kind));
        }
    }
}
