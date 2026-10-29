//! Spec A's RAR 1.x decoder entry for this repository's fuzz targets,
//! behind the `bench-internals` feature. Not part of the API; no shipped
//! build enables it.
//!
//! The doc comments here on the layout of the fuzz input are adapted from
//! this file's earlier text, which served the decoder before this one.

use crate::rar1x::Rar1x;
use crate::rar5_lz::SliceSource;

/// The largest size a fuzz case may declare (spec A 7.4).
const MAX_TARGET: usize = 1 << 20;

/// The fuzz target of SPEC-A 7.4: arbitrary packed bytes, declared sizes
/// and solid sequences.
///
/// The input is a three byte little endian size reduced into 0 to 1 MiB,
/// one byte whose low four bits say which of the chunks is solid and
/// whose next two bits are the chunk count less one, and then the packed
/// bytes cut into that many equal chunks, each decoded as a member. The
/// chain stops at the first failure, because the state after a failed
/// member is unspecified (spec A 6).
///
/// What is asserted is section 6's limit: a member never delivers more
/// than its declared size. A member that delivers fewer is one whose
/// packed bytes ran out (4.11), which is not a failure of the decode.
pub fn fuzz_decode(data: &[u8]) {
    let Some((head, rest)) = data.split_first_chunk::<4>() else {
        return;
    };
    let target = (usize::from(head[0]) | usize::from(head[1]) << 8 | usize::from(head[2]) << 16)
        % (MAX_TARGET + 1);
    let flags = head[3];
    let count = 1 + usize::from((flags >> 4) & 3);
    let chunk = rest.len() / count;
    let mut decoder = Rar1x::new();
    for index in 0..count {
        let start = index * chunk;
        let end = if index + 1 == count {
            rest.len()
        } else {
            start + chunk
        };
        let mut source = SliceSource::new(&rest[start..end]);
        let mut out: Vec<u8> = Vec::new();
        let solid = flags >> index & 1 == 1;
        if decoder
            .member(&mut source, target as u64, solid, &mut out)
            .is_err()
        {
            return;
        }
        assert!(
            out.len() <= target,
            "a member never delivers more than its declared size: {} against {target}",
            out.len()
        );
    }
}

/// How much packed data the lapping target builds from its seed.
///
/// A fuzzer's seed is a few bytes to a few kilobytes, and a member
/// decoded from that stops far short of one lap of the decoder's 128 KiB
/// history ring. The seed is tiled so that the member goes round several
/// times and a copy can name a place on the far side of the ring's end.
/// Tiling does not make the decode periodic: the state is adaptive, so
/// the same packed bits decode differently on every pass.
const PACKED: usize = 512 * 1024;

/// What the lapping target asks one member for: three laps of the ring.
const TARGET: u64 = 3 * 131_072;

fn tiled(data: &[u8]) -> Vec<u8> {
    let mut packed = Vec::with_capacity(PACKED);
    while packed.len() < PACKED && !data.is_empty() {
        let take = (PACKED - packed.len()).min(data.len());
        packed.extend_from_slice(&data[..take]);
    }
    packed
}

/// The lapping fuzz body: a member long enough to go round the history
/// ring, so that copies whose source or destination meets the ring's end
/// are reached. The decoder indexes its ring by checked or wrapping
/// arithmetic only, so what this can find is a panic or a member that
/// delivers more than it declared.
pub fn fuzz_window_edge(data: &[u8]) {
    let packed = tiled(data);
    let mut source = SliceSource::new(&packed);
    let mut lz = Rar1x::new();
    let mut out: Vec<u8> = Vec::new();
    let _ = lz.member(&mut source, TARGET, false, &mut out);
    assert!(out.len() as u64 <= TARGET);
}

/// How far a seed's member got against the ring's size, for the test
/// that holds the target above to its purpose: it must be known to lap.
pub fn window_edge_reach(data: &[u8]) -> (usize, usize) {
    let packed = tiled(data);
    let mut source = SliceSource::new(&packed);
    let mut lz = Rar1x::new();
    let mut out: Vec<u8> = Vec::new();
    let _ = lz.member(&mut source, TARGET, false, &mut out);
    (out.len(), lz.window_bytes())
}
