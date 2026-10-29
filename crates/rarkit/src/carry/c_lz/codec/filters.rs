//! Carried from the predecessor's `codec/filters.rs` at an earlier revision: items ours from birth
//! per the provenance census (and clean-room outputs, clean by provenance).

use crate::carry::h_ours::codec::address_filters;
use crate::carry::h_ours::codec::address_filters::Direction;
// local change, 5 Sep 2026 - reconstruct common channel counts
// a row at a time. Independent channel accumulators shorten the dependency
// chain while contiguous output stores avoid revisiting each cache line.
// Keep the generic channel-major path for other counts; see VENDORING.md.
pub(crate) fn delta_rows<const N: usize>(data: &[u8], out: &mut [u8]) {
    // The first len % N planes contain one extra byte. Splitting by these
    // exact counts keeps both full rows and a partial final row in bounds.
    let mut encoded = data;
    let mut planes = [&[][..]; N];
    for (channel, plane) in planes.iter_mut().enumerate() {
        let count = data.len() / N + usize::from(channel < data.len() % N);
        (*plane, encoded) = encoded.split_at(count);
    }
    let mut prev = [0u8; N];
    let mut rows = out.chunks_exact_mut(N);
    for (row, dest) in rows.by_ref().enumerate() {
        for channel in 0..N {
            prev[channel] = prev[channel].wrapping_sub(planes[channel][row]);
            dest[channel] = prev[channel];
        }
    }
    for (channel, dest) in rows.into_remainder().iter_mut().enumerate() {
        *dest = prev[channel].wrapping_sub(planes[channel][data.len() / N]);
    }
}
