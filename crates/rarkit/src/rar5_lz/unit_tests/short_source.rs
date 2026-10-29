//! A source that holds less than it was asked for.

use super::*;

// ---------------------------------------------------------------------
// A source that holds less than it was asked for
// ---------------------------------------------------------------------

/// A compressed member of a few MiB and many blocks, written by this crate's
/// own writer, with its declared window.
#[cfg(feature = "parallel")]
fn a_member_of_many_blocks() -> Member {
    members(&written_text(4 << 20, 1 << 20))
        .into_iter()
        .find(|member| member.method != 0)
        .expect("a compressed member")
}

/// Hands over at most `cap` bytes past what it holds, however much is asked,
/// and says it is exhausted only once a `fill` has found nothing more: the
/// shape of spec F's buffered source, whose `ended` flag is set by a read
/// that comes back empty.
#[cfg(feature = "parallel")]
struct Capped<'a> {
    data: &'a [u8],
    at: usize,
    end: usize,
    cap: usize,
    ended: bool,
    fills: usize,
}

#[cfg(feature = "parallel")]
impl super::PackedSource for Capped<'_> {
    fn fill(&mut self, want: usize) -> crate::Result<()> {
        self.fills += 1;
        let want = want.min(self.cap);
        if self.end - self.at >= want {
            return Ok(());
        }
        let to = (self.at + want).min(self.data.len());
        if to == self.end {
            self.ended = true;
        }
        self.end = to;
        Ok(())
    }
    fn available(&self) -> &[u8] {
        &self.data[self.at..self.end]
    }
    fn advance(&mut self, n: usize) {
        self.at = (self.at + n).min(self.end);
    }
    fn exhausted(&self) -> bool {
        self.ended
    }
}

/// The streamed tape walk over `source`, against the one-slice decode.
#[cfg(feature = "parallel")]
fn streamed_matches_the_slice(member: &Member, source: &mut Capped<'_>) -> Vec<u8> {
    let mut reference = Rar5Lz::new(member.window, &policy()).expect("window");
    reference.set_parallel(false);
    let mut want = Vec::new();
    reference
        .member(
            &mut SliceSource::new(&member.packed),
            member.unpacked,
            member.algorithm,
            &mut want,
        )
        .expect("the one-slice decode");
    let mut lz = Rar5Lz::new(member.window, &policy()).expect("window");
    lz.set_parallel(true);
    let mut got = Vec::new();
    let outcome = lz.member(source, member.unpacked, member.algorithm, &mut got);
    assert!(
        outcome.is_ok(),
        "cap {}: {:?} after {} of {} bytes",
        source.cap,
        outcome.err().map(|e| format!("{:?}", e.kind())),
        got.len(),
        want.len()
    );
    assert!(
        got == want,
        "cap {}: {} bytes against {}",
        source.cap,
        got.len(),
        want.len()
    );
    got
}

/// A source that holds LESS than the walk asks for is not at the member's
/// end. Until 29 Sep 2026 the streamed walk read a short chunk as the last
/// one, so a request past the source's cap (a `STREAM_CHUNK` above the
/// buffered source's `MAX_PACKED`) ended the member early and the member
/// failed its checksum at every width, pipe on or off.
#[cfg(feature = "parallel")]
#[test]
fn a_source_holding_less_than_asked_decodes_the_whole_member() {
    let member = a_member_of_many_blocks();
    // Several chunks at each cap, and every cap above the largest block the
    // writer cuts (near 64 KiB), which a source must hold whole.
    assert!(
        member.packed.len() > 512 << 10,
        "{} packed bytes",
        member.packed.len()
    );
    for cap in [160 << 10, 300 << 10] {
        let mut source = Capped {
            data: &member.packed,
            at: 0,
            end: 0,
            cap,
            ended: false,
            fills: 0,
        };
        streamed_matches_the_slice(&member, &mut source);
    }
}

/// The member's packed bytes end EXACTLY on a chunk: the source has handed
/// over every byte and not yet found out that there are no more, which only
/// the next `fill` does. The walk must neither stop short, nor hang, nor go
/// on asking.
#[cfg(feature = "parallel")]
#[test]
fn a_member_ending_exactly_on_a_chunk_neither_hangs_nor_asks_again() {
    let member = a_member_of_many_blocks();
    let len = member.packed.len();
    for cap in [len, len / 2 + 1, len.div_ceil(3)] {
        let mut source = Capped {
            data: &member.packed,
            at: 0,
            end: 0,
            cap,
            ended: false,
            fills: 0,
        };
        streamed_matches_the_slice(&member, &mut source);
        assert!(
            source.fills <= len.div_ceil(cap) * 2 + 4,
            "cap {cap}: {} fills for {len} bytes",
            source.fills
        );
    }
}

/// A block header that is CORRUPT before the member's declared end is
/// named for what it is on the streamed walk, as on the serial one:
/// `BlockHeaderChecksum`, or `BlockSizeWidth`. The streamed walk answered
/// `Truncated` whenever the source still held, or could still give, more
/// than the largest block's worth of packed bytes after the bad header:
/// a chunk that planned no block was taken for one that held no WHOLE
/// block, and the walk asked for more until no block that large exists.
/// More bytes cannot cure a check byte, and the caller was told the
/// archive was cut short where it is damaged.
///
/// Two sources: every byte in hand with 17 MiB after the bad header, and
/// one that hands over 300 KiB at a time. Stated tape widths of one and
/// four (the decoder's own scoped lanes; no rayon pool is used). About
/// 45 MiB of memory.
#[cfg(feature = "parallel")]
#[test]
fn a_corrupt_header_before_the_end_is_named_on_the_streamed_walk() {
    use crate::{Corruption, ErrorKind, Rar5Fault};

    let member = a_member_of_many_blocks();
    // The fourth block's header.
    let mut at = 0usize;
    for _ in 0..3 {
        at += crate::rar5_lz::block_in_hand(&member.packed[at..])
            .expect("a block")
            .past();
    }
    for (damage, want) in [
        ("check byte", Rar5Fault::BlockHeaderChecksum),
        ("size width", Rar5Fault::BlockSizeWidth),
    ] {
        let mut packed = member.packed.clone();
        match damage {
            "check byte" => packed[at + 1] ^= 0xff,
            _ => packed[at] |= 0x18,
        }
        let mut long = packed.clone();
        long.resize(at + (17 << 20), 0);
        let decode = |source: &mut dyn FnMut(&mut Rar5Lz, &mut Vec<u8>) -> crate::Result<()>,
                      parallel: bool,
                      width: usize| {
            let mut lz = Rar5Lz::new(member.window, &policy()).expect("window");
            lz.set_tape_width(width);
            lz.set_width_stated(true);
            lz.set_parallel(parallel);
            let mut got = Vec::new();
            let outcome = source(&mut lz, &mut got);
            match outcome {
                Err(err) => match err.kind() {
                    ErrorKind::Corrupt(Corruption::Rar5(fault)) => format!("{fault:?}"),
                    other => format!("{other:?}"),
                },
                Ok(()) => "Ok".to_string(),
            }
        };
        for (parallel, width) in [(false, 1), (true, 1), (true, 4)] {
            let whole = decode(
                &mut |lz, got| {
                    lz.member(
                        &mut SliceSource::new(&long),
                        member.unpacked,
                        member.algorithm,
                        got,
                    )
                },
                parallel,
                width,
            );
            assert_eq!(
                whole,
                format!("{want:?}"),
                "{damage}, every byte in hand, parallel {parallel}, width {width}"
            );
            let pieces = decode(
                &mut |lz, got| {
                    let mut source = Capped {
                        data: &packed,
                        at: 0,
                        end: 0,
                        cap: 300 << 10,
                        ended: false,
                        fills: 0,
                    };
                    lz.member(&mut source, member.unpacked, member.algorithm, got)
                },
                parallel,
                width,
            );
            assert_eq!(
                pieces,
                format!("{want:?}"),
                "{damage}, 300 KiB at a time, parallel {parallel}, width {width}"
            );
        }
    }
}
