//! The delta, RGB and audio transforms (SPEC-J section 3.7), both
//! directions.
//!
//! Each works on one block, the span, in isolation. Decode reads the
//! FILTERED block `src` and writes the original into `out`; encode the
//! reverse. The filtered block is always planar: the bytes of channel 0,
//! then channel 1, and so on, where original byte `i` belongs to channel
//! `i mod N`. Only `min(src.len(), out.len())` bytes are touched. No
//! allocation, no panic and O(n) for every parameter value; outside the
//! domain of section 3.5 the output bytes are unspecified.

use super::delta16;

/// Bytes in plane `c` of an `n`-byte block split over `stride` channels.
#[inline(always)]
fn plane_len(n: usize, stride: usize, c: usize) -> usize {
    if c >= n {
        0
    } else {
        (n - c).div_ceil(stride)
    }
}

// ---------------------------------------------------------------------------
// Delta, section 3.7.1
// ---------------------------------------------------------------------------

/// Delta decode over `channels` interleaved byte channels.
pub(crate) fn delta_decode(src: &[u8], out: &mut [u8], channels: u32) {
    let n = src.len().min(out.len());
    let (src, out) = (&src[..n], &mut out[..n]);
    let stride = channels as usize;
    match stride {
        0 => {}
        1 => {
            let mut acc = 0u8;
            for (o, &e) in out.iter_mut().zip(src) {
                acc = acc.wrapping_sub(e);
                *o = acc;
            }
        }
        // Section 7: read the planar filtered bytes and write the
        // interleaved original in ONE pass. The channels are independent,
        // so their accumulators ride in registers while `out` is written
        // in order and each plane is read in order.
        // Section 7: one pass for every count a row of accumulators can
        // hold in registers. The arm list was 2, 3, 4, 6 and 8, and the
        // counts it MISSED took `delta_by_channel`, which is a different
        // algorithm and not a slower spelling of this one: the RAR 3
        // corpus's own `rar3_vm_1m` member is 32 spans of SIXTEEN
        // channels and took the plane at a time path every time. The
        // width has to be a constant for the row loop to unroll and the
        // accumulators to stay in registers - a run time width was
        // measured here and is SLOWER than the fallback it replaced - so
        // the arms are generated rather than chosen.
        // Sixteen is the vector width in bytes, where the running sums
        // and the transpose are each one instruction a step; see
        // `super::delta16`. Every other width takes the scalar row form,
        // and so does this one where there is no kernel.
        s if s == delta16::N && delta16::AVAILABLE => delta_rows16(src, out),
        s if (2..=DELTA_MAX_ROWS).contains(&s) => delta_rows_upto(src, out, s),
        _ => delta_by_channel(src, out, stride),
    }
}

/// The widest channel count answered in one pass. Above it the row of
/// accumulators no longer lives in registers, so the plane at a time form
/// of [`delta_by_channel`] is no worse and carries any count at all,
/// including one above the block's own length.
const DELTA_MAX_ROWS: usize = 32;

/// Where each plane of an `n` byte block begins in the filtered bytes.
fn plane_starts<const N: usize>(n: usize) -> [usize; N] {
    let mut starts = [0usize; N];
    let mut at = 0;
    for (c, s) in starts.iter_mut().enumerate() {
        *s = at;
        at += plane_len(n, N, c);
    }
    starts
}

/// Sixteen channels: the vector kernel for the whole blocks it reaches,
/// then the scalar row form for the rows it could not and for the last
/// partial row. The kernel hands its accumulators back so the two halves
/// are one running sum and not two.
fn delta_rows16(src: &[u8], out: &mut [u8]) {
    const N: usize = delta16::N;
    let n = out.len();
    let starts = plane_starts::<N>(n);
    let (mut acc, done) = delta16::rows16(src, out, &starts);
    let rows = n / N;
    for j in done..rows {
        for c in 0..N {
            acc[c] = acc[c].wrapping_sub(src[starts[c] + j]);
            out[j * N + c] = acc[c];
        }
    }
    for (c, o) in out[rows * N..].iter_mut().enumerate() {
        *o = acc[c].wrapping_sub(src[starts[c] + rows]);
    }
}

/// Dispatch `stride` to [`delta_rows`] with `N` equal to it.
///
/// One arm per width, written out by the macro rather than by hand, so
/// that no count between 2 and [`DELTA_MAX_ROWS`] can be missing the way
/// 16 was.
fn delta_rows_upto(src: &[u8], out: &mut [u8], stride: usize) {
    macro_rules! arms {
        ($($n:literal),* $(,)?) => {
            match stride {
                $($n => delta_rows::<$n>(src, out),)*
                _ => delta_by_channel(src, out, stride),
            }
        };
    }
    arms!(
        2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
        27, 28, 29, 30, 31, 32,
    );
}

/// `N` channels, one pass: row `j` takes one byte from each plane.
fn delta_rows<const N: usize>(src: &[u8], out: &mut [u8]) {
    let n = out.len();
    let starts = plane_starts::<N>(n);
    let rows = n / N;
    let mut acc = [0u8; N];
    let (rows_out, tail) = out.as_chunks_mut::<N>();
    for (j, row) in rows_out.iter_mut().enumerate() {
        for c in 0..N {
            acc[c] = acc[c].wrapping_sub(src[starts[c] + j]);
            row[c] = acc[c];
        }
    }
    // The last, partial row: channels below `n mod N`.
    for (c, o) in tail.iter_mut().enumerate() {
        *o = acc[c].wrapping_sub(src[starts[c] + rows]);
    }
}

/// Any channel count, including counts above the block's length: one
/// channel after another, which is all a channel of a few bytes needs.
fn delta_by_channel(src: &[u8], out: &mut [u8], stride: usize) {
    let n = out.len();
    let mut rest = src;
    for c in 0..stride.min(n) {
        let (plane, tail) = rest.split_at(plane_len(n, stride, c).min(rest.len()));
        rest = tail;
        let mut acc = 0u8;
        for (o, &e) in out[c..].iter_mut().step_by(stride).zip(plane) {
            acc = acc.wrapping_sub(e);
            *o = acc;
        }
    }
}

/// The scalar row form alone, whatever [`delta_decode`] would dispatch
/// to, so a test can hold the vector kernel against it.
#[cfg(test)]
pub(super) fn delta_rows_for_tests(src: &[u8], out: &mut [u8], channels: u32) {
    let n = src.len().min(out.len());
    let (src, out) = (&src[..n], &mut out[..n]);
    delta_rows_upto(src, out, channels as usize);
}

/// The plane at a time form alone, which is what every width outside the
/// arm list took before this package carried one for it.
#[cfg(test)]
pub(super) fn delta_planes_for_tests(src: &[u8], out: &mut [u8], channels: u32) {
    let n = src.len().min(out.len());
    let (src, out) = (&src[..n], &mut out[..n]);
    delta_by_channel(src, out, channels as usize);
}

/// Delta encode, the inverse of [`delta_decode`].
// Reached only through the `internals_*` seam, behind the
// `bench-internals` feature; no shipped build enables it.
#[allow(dead_code)]
pub(crate) fn delta_encode(src: &[u8], out: &mut [u8], channels: u32) {
    let n = src.len().min(out.len());
    let (src, out) = (&src[..n], &mut out[..n]);
    let stride = channels as usize;
    if stride == 0 {
        return;
    }
    let mut rest = &mut out[..];
    for c in 0..stride.min(n) {
        let (plane, tail) = rest.split_at_mut(plane_len(n, stride, c).min(rest.len()));
        rest = tail;
        let mut prev = 0u8;
        for (o, &x) in plane.iter_mut().zip(src[c..].iter().step_by(stride)) {
            *o = prev.wrapping_sub(x);
            prev = x;
        }
    }
}

// ---------------------------------------------------------------------------
// RGB, section 3.7.2
// ---------------------------------------------------------------------------

/// The Paeth predictor (PNG, second edition, section 9.4).
#[inline(always)]
fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let (ai, bi, ci) = (a as i32, b as i32, c as i32);
    let pa = (bi - ci).abs();
    let pb = (ai - ci).abs();
    let pc = (ai + bi - 2 * ci).abs();
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

/// The prediction for position `i` of `y`, whose bytes below `i` in the
/// same channel are final. `w` is the row width in bytes.
#[inline(always)]
fn rgb_predict(y: &[u8], i: usize, w: usize) -> u8 {
    let a = if i >= 3 { y[i - 3] } else { 0 };
    if i < w.saturating_add(3) {
        a
    } else {
        paeth(a, y[i - w], y[i - w - 3])
    }
}

/// RGB decode with row width `width` bytes and red position `red_at`.
pub(crate) fn rgb_decode(src: &[u8], out: &mut [u8], width: u32, red_at: u32) {
    let n = src.len().min(out.len());
    let (src, out) = (&src[..n], &mut out[..n]);
    let w = width as usize;
    let (p0, rest) = src.split_at(plane_len(n, 3, 0));
    let (p1, p2) = rest.split_at(plane_len(n, 3, 1));
    let planes = [p0, p1, p2];
    // Step 1. Within the domain (`w` a positive multiple of 3) every
    // predictor input lies in the channel being decoded, so the three
    // channels are independent chains and run interleaved, one pixel at a
    // time, writing `out` in order. Positions before `w + 3` predict from
    // the left neighbour alone.
    let head = w.saturating_add(3).min(n);
    let mut left = [0u8; 3];
    for (i, o) in out[..head].iter_mut().enumerate() {
        let y = left[i % 3].wrapping_sub(planes[i % 3][i / 3]);
        *o = y;
        left[i % 3] = y;
    }
    // Byte by byte up to the first whole pixel after the head.
    let aligned = head.next_multiple_of(3).min(n);
    for i in head..aligned {
        out[i] = rgb_predict(out, i, w).wrapping_sub(planes[i % 3][i / 3]);
    }
    // Whole pixels.
    let whole = n / 3;
    if w >= 3 && aligned / 3 < whole {
        // The left and upper-left neighbours are the previous pixel's own
        // value and its "above", so they ride in registers from one pixel
        // to the next; only the row above is loaded.
        let first = aligned;
        let mut left = [out[first - 3], out[first - 2], out[first - 1]];
        let up0 = first - w;
        let mut upleft = [out[up0 - 3], out[up0 - 2], out[up0 - 1]];
        for j in aligned / 3..whole {
            let i = 3 * j;
            let up = i - w;
            let above = [out[up], out[up + 1], out[up + 2]];
            let y = [
                paeth(left[0], above[0], upleft[0]).wrapping_sub(p0[j]),
                paeth(left[1], above[1], upleft[1]).wrapping_sub(p1[j]),
                paeth(left[2], above[2], upleft[2]).wrapping_sub(p2[j]),
            ];
            out[i..i + 3].copy_from_slice(&y);
            left = y;
            upleft = above;
        }
    } else {
        for i in aligned..3 * whole {
            out[i] = rgb_predict(out, i, w).wrapping_sub(planes[i % 3][i / 3]);
        }
    }
    for i in (3 * whole).max(aligned)..n {
        out[i] = rgb_predict(out, i, w).wrapping_sub(planes[i % 3][i / 3]);
    }
    // Step 2: add green back to its two neighbours.
    if let Some(tail) = out.get_mut(red_at as usize..) {
        let (pixels, _) = tail.as_chunks_mut::<3>();
        for p in pixels {
            p[0] = p[0].wrapping_add(p[1]);
            p[2] = p[2].wrapping_add(p[1]);
        }
    }
}

/// Which form section 3.7.2's intermediate `y` takes at a position. It
/// depends on the position's CHANNEL, not on the position, so the test
/// leaves the per-byte path: `W` is a multiple of 3, so every predictor
/// input of a channel is in that channel and takes the same form.
#[derive(Clone, Copy)]
// Reached only through the `internals_*` seam, behind the
// `bench-internals` feature; no shipped build enables it.
#[allow(dead_code)]
enum YForm {
    /// `y[i] = x[i]`: the green channel, and every position before the
    /// colour-difference pass reaches it.
    Plain,
    /// `y[i] = x[i] - x[i + 1]`, for `i >= r` with a whole pixel left.
    Red,
    /// `y[i] = x[i] - x[i - 1]`, for `i >= r + 2`.
    Blue,
}

impl YForm {
    /// The three forms as const-generic tags, so a channel's loop can be
    /// specialised on its own.
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    const PLAIN: u8 = 0;
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    const RED: u8 = 1;
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    const BLUE: u8 = 2;

    /// `y[i]`, for an `i` in the channel this form belongs to, with the
    /// form fixed at compile time.
    #[inline(always)]
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    fn at_form<const FORM: u8>(x: &[u8], n: usize, r: usize, i: usize) -> u8 {
        match FORM {
            YForm::RED if i >= r && i + 2 < n => x[i].wrapping_sub(x[i + 1]),
            YForm::BLUE if i >= r + 2 => x[i].wrapping_sub(x[i - 1]),
            _ => x[i],
        }
    }

    /// The form of channel `c` when the red position is `r`.
    #[inline(always)]
    // Reached only through the `internals_*` seam, behind the
    // `bench-internals` feature; no shipped build enables it.
    #[allow(dead_code)]
    fn of(c: usize, r: usize) -> YForm {
        if c == r % 3 {
            YForm::Red
        } else if c == (r + 2) % 3 {
            YForm::Blue
        } else {
            YForm::Plain
        }
    }
}

/// RGB encode, the inverse of [`rgb_decode`].
// Reached only through the `internals_*` seam, behind the
// `bench-internals` feature; no shipped build enables it.
#[allow(dead_code)]
pub(crate) fn rgb_encode(src: &[u8], out: &mut [u8], width: u32, red_at: u32) {
    let n = src.len().min(out.len());
    let (x, out) = (&src[..n], &mut out[..n]);
    let w = width as usize;
    // A red position at or past the block's end subtracts nowhere (no
    // `i < n` has `i >= r`), so every channel is plain whatever `r` is,
    // and `n` stands for all of them. Without it `r + 2` below overflows
    // a 32-bit `usize` at `red_at = u32::MAX` (run on armv7, 4 Oct 2026).
    let r = (red_at as usize).min(n);
    let l0 = plane_len(n, 3, 0);
    let starts = [0, l0, l0 + plane_len(n, 3, 1)];
    // When the row is a whole number of pixels - which is the domain the
    // decoder's own pixel loop assumes, and what every genuine parameter
    // seen in section 3.5 gives - a channel's three predictor inputs are
    // its own `y` at lags 1, `W/3` and `W/3 + 1`. Materialising the
    // channel's `y` once turns the per-byte path from a strided gather
    // with a form test into three CONTIGUOUS reads and a write, which is
    // a shape the vectoriser can take. x86-64 read this leg at 0.94x
    // before it, against aarch64's 1.24x.
    if w >= 3 && w.is_multiple_of(3) {
        let mut plain = vec![0u8; l0];
        for c in 0..3.min(n) {
            let count = plane_len(n, 3, c);
            let y = &mut plain[..count];
            match YForm::of(c, r) {
                YForm::Plain => gather_channel::<{ YForm::PLAIN }>(x, y, n, r, c),
                YForm::Red => gather_channel::<{ YForm::RED }>(x, y, n, r, c),
                YForm::Blue => gather_channel::<{ YForm::BLUE }>(x, y, n, r, c),
            }
            predict_channel(y, &mut out[starts[c]..starts[c] + count], w / 3);
        }
        return;
    }
    // One channel at a time, each specialised on its own form of `y`, so
    // the per-byte path holds no test of which form this position takes.
    for c in 0..3.min(n) {
        let plane = &mut out[starts[c]..];
        match YForm::of(c, r) {
            YForm::Plain => rgb_encode_channel::<{ YForm::PLAIN }>(x, plane, n, w, r, c),
            YForm::Red => rgb_encode_channel::<{ YForm::RED }>(x, plane, n, w, r, c),
            YForm::Blue => rgb_encode_channel::<{ YForm::BLUE }>(x, plane, n, w, r, c),
        }
    }
}

/// [`rgb_encode`]'s generic path alone, for the test that pins the two
/// against each other at a whole-pixel row width.
#[cfg(test)]
pub(super) fn rgb_encode_generic_for_tests(src: &[u8], out: &mut [u8], width: u32, red_at: u32) {
    let n = src.len().min(out.len());
    let (x, out) = (&src[..n], &mut out[..n]);
    // As in `rgb_encode`: a red position past the end is the end.
    let (w, r) = (width as usize, (red_at as usize).min(n));
    let l0 = plane_len(n, 3, 0);
    let starts = [0, l0, l0 + plane_len(n, 3, 1)];
    for c in 0..3.min(n) {
        let plane = &mut out[starts[c]..];
        match YForm::of(c, r) {
            YForm::Plain => rgb_encode_channel::<{ YForm::PLAIN }>(x, plane, n, w, r, c),
            YForm::Red => rgb_encode_channel::<{ YForm::RED }>(x, plane, n, w, r, c),
            YForm::Blue => rgb_encode_channel::<{ YForm::BLUE }>(x, plane, n, w, r, c),
        }
    }
}

/// `y[k] = at_form(x, 3k + c)` for the whole channel, written in order.
///
/// The form's test is on `i` alone and both of its conditions are
/// monotone, so the range where the subtraction applies is computed once
/// and the loop inside it carries no test at all.
// Reached only through the `internals_*` seam, behind the
// `bench-internals` feature; no shipped build enables it.
#[allow(dead_code)]
fn gather_channel<const FORM: u8>(x: &[u8], y: &mut [u8], n: usize, r: usize, c: usize) {
    // The `k` with `3k + c` in the form's subtracting range.
    let (from, upto) = match FORM {
        // `i >= r` and `i + 2 < n`.
        YForm::RED => (
            r.saturating_sub(c).div_ceil(3),
            (n.saturating_sub(2)).saturating_sub(c).div_ceil(3),
        ),
        // `i >= r + 2`.
        YForm::BLUE => ((r + 2).saturating_sub(c).div_ceil(3), y.len()),
        _ => (y.len(), y.len()),
    };
    let (from, upto) = (from.min(y.len()), upto.min(y.len()));
    for (k, o) in y.iter_mut().enumerate() {
        let i = 3 * k + c;
        *o = if k >= from && k < upto {
            match FORM {
                YForm::RED => x[i].wrapping_sub(x[i + 1]),
                YForm::BLUE => x[i].wrapping_sub(x[i - 1]),
                _ => x[i],
            }
        } else {
            x[i]
        };
    }
}

/// One channel's residuals from its `y`, with `s = W / 3` the row's pixel
/// count: `plane[k] = paeth(y[k-1], y[k-s], y[k-s-1]) - y[k]`, and the
/// first `s + 1` positions predicting from the left neighbour alone.
///
/// The four reads are contiguous slices at fixed offsets and the write
/// does not alias them, so the body has no loop-carried value and no
/// bounds check.
// Reached only through the `internals_*` seam, behind the
// `bench-internals` feature; no shipped build enables it.
#[allow(dead_code)]
fn predict_channel(y: &[u8], plane: &mut [u8], s: usize) {
    let count = y.len();
    let head = count.min(s + 1);
    let mut left = 0u8;
    for (o, &here) in plane[..head].iter_mut().zip(&y[..head]) {
        *o = left.wrapping_sub(here);
        left = here;
    }
    let Some(m) = count.checked_sub(s + 1) else {
        return;
    };
    let dst = &mut plane[s + 1..count];
    let lefts = &y[s..s + m];
    let heres = &y[s + 1..s + 1 + m];
    let aboves = &y[1..1 + m];
    let uplefts = &y[..m];
    for (((o, &a), &b), (&cc, &here)) in dst
        .iter_mut()
        .zip(lefts)
        .zip(aboves)
        .zip(uplefts.iter().zip(heres))
    {
        *o = paeth(a, b, cc).wrapping_sub(here);
    }
}

/// One channel of [`rgb_encode`], its form fixed: `x` is read with a
/// stride of three from `c`, and `plane` is written in order. The path for
/// a row width that is not a whole number of pixels, where a channel's
/// predictor inputs can fall in another channel.
// Reached only through the `internals_*` seam, behind the
// `bench-internals` feature; no shipped build enables it.
#[allow(dead_code)]
fn rgb_encode_channel<const FORM: u8>(
    x: &[u8],
    plane: &mut [u8],
    n: usize,
    w: usize,
    r: usize,
    c: usize,
) {
    let head = w.saturating_add(3);
    // Rolling: this step's `y(i - 3)` and `y(i - w - 3)` are the last
    // step's `y(i)` and `y(i - w)`.
    let (mut left, mut upleft) = (0u8, 0u8);
    let mut i = c;
    let mut k = 0;
    while i < n.min(head) {
        let here = YForm::at_form::<FORM>(x, n, r, i);
        plane[k] = left.wrapping_sub(here);
        left = here;
        k += 1;
        i += 3;
    }
    if i < n {
        upleft = YForm::at_form::<FORM>(x, n, r, i - w - 3);
    }
    while i < n {
        let here = YForm::at_form::<FORM>(x, n, r, i);
        let above = YForm::at_form::<FORM>(x, n, r, i - w);
        plane[k] = paeth(left, above, upleft).wrapping_sub(here);
        upleft = above;
        left = here;
        k += 1;
        i += 3;
    }
}

// ---------------------------------------------------------------------------
// Audio, section 3.7.3
// ---------------------------------------------------------------------------

/// One channel between two of its bytes (section 3.7.3). All of it starts
/// at zero.
///
/// The section states the recurrence with three LAGGED differences. With
/// `D[0]`, `D[1]` and `D[2]` the channel's last three differences, newest
/// first, step 1 makes the lagged ones `D[0]`, `D[0] - D[1]` and
/// `D[1] - D[2]`, so step 2's weighted sum of the lagged differences is
/// also a weighted sum of the last three themselves, under the weights
/// [`Channel::spread`] gives. That is the form kept here: of its three
/// products only the first waits on the byte just produced.
///
/// The differences and the weights are indexed where steps 5 and 6 are
/// written, in [`Channel::revise`], and are ten plain fields here. Held as
/// arrays of three in this struct, and nothing else changed, the four
/// channel decode loop retires 6 percent more instructions on x86-64
/// (counted on a genuine RAR 4 audio archive, 8 Oct 2026): the byte step
/// is the hot path and wants each of them in a register of its own.
#[derive(Clone, Copy, Default)]
struct Channel {
    /// The channel's last original byte.
    last_byte: i32,
    /// Its last three differences, each a signed byte, newest first.
    difference_0: i32,
    difference_1: i32,
    difference_2: i32,
    /// Its three weights, one for each lagged difference.
    weight_0: i32,
    weight_1: i32,
    weight_2: i32,
    /// The weights as they fall on the last three differences.
    spread_0: i32,
    spread_1: i32,
    spread_2: i32,
}

/// What step 5's seven sums are made of, for the bytes since a channel's
/// weights were last revised: per byte, 8 times its filtered byte as a
/// signed byte, and the channel's differences from two before the first
/// of those bytes onwards (entry `f + 2` is the last difference as byte
/// `f` begins). Nothing reads the sums between two revisions, so they are
/// formed at the revision, in one pass over this.
struct Round {
    scaled: [i32; REVISED_EVERY],
    differences: [i32; REVISED_EVERY + 2],
}

impl Default for Round {
    fn default() -> Self {
        Round {
            scaled: [0; REVISED_EVERY],
            differences: [0; REVISED_EVERY + 2],
        }
    }
}

/// Step 6: a channel's weights are revised after its byte `t` whenever
/// `t mod 32 = 0`, so after its first byte and then after every 32nd.
const REVISED_EVERY: usize = 32;

impl Channel {
    /// The weights of the three lagged differences as weights of the last
    /// three differences: collect `w[0] D[0] + w[1] (D[0] - D[1]) +
    /// w[2] (D[1] - D[2])` by `D`.
    #[inline(always)]
    fn spread(weights: [i32; 3]) -> [i32; 3] {
        [
            weights[0] + weights[1],
            weights[2] - weights[1],
            -weights[2],
        ]
    }

    /// Before the first byte of a round: the two differences step 5 needs
    /// from before it.
    #[inline(always)]
    fn open(&self, round: &mut Round) {
        round.differences[0] = self.difference_2;
        round.differences[1] = self.difference_1;
    }

    /// Steps 1 to 4 for one byte, the `nth` of its round: `given` is the
    /// filtered byte when decoding and the original byte when encoding,
    /// and the other of the two is returned.
    #[inline(always)]
    fn byte<const ENCODE: bool>(&mut self, given: u8, round: &mut Round, nth: usize) -> u8 {
        let [newest, middle, oldest] = [self.difference_0, self.difference_1, self.difference_2];
        let [on_newest, on_middle, on_oldest] = [self.spread_0, self.spread_1, self.spread_2];
        // Step 2's floor: an arithmetic shift rounds toward minus infinity.
        let numerator =
            8 * self.last_byte + on_newest * newest + on_middle * middle + on_oldest * oldest;
        let predicted = (numerator >> 3) as u8;
        // Step 3, solved for whichever byte was not given.
        let other = predicted.wrapping_sub(given);
        let (original, filtered) = if ENCODE {
            (given, other)
        } else {
            (other, given)
        };
        let nth = nth % REVISED_EVERY;
        round.scaled[nth] = 8 * i32::from(filtered as i8);
        round.differences[nth + 2] = newest;
        // Step 4, the difference as a signed byte.
        let difference = i32::from(original.wrapping_sub(self.last_byte as u8) as i8);
        self.difference_2 = middle;
        self.difference_1 = newest;
        self.difference_0 = difference;
        self.last_byte = i32::from(original);
        other
    }

    /// Steps 5 and 6 at the end of a round of `bytes` bytes: the seven
    /// sums over the round, then the weight the smallest of them names
    /// moves by one.
    #[inline(never)]
    fn revise(&mut self, round: &Round, bytes: usize) {
        let mut sums = [0u32; 7];
        for nth in 0..bytes.min(REVISED_EVERY) {
            let scaled = round.scaled[nth];
            let lagged = [
                round.differences[nth + 2],
                round.differences[nth + 2] - round.differences[nth + 1],
                round.differences[nth + 1] - round.differences[nth],
            ];
            sums[0] += scaled.unsigned_abs();
            // Step 5 once, over the index `i`, and applied at each of its
            // three values by name: a loop over `i` here is left a loop
            // when the routine is compiled for size, as a build under a
            // profile that never ran it compiles it, and then costs a
            // tenth more instructions a byte (counted on x86-64).
            let mut pair = |i: usize| {
                sums[2 * i - 1] += (scaled - lagged[i - 1]).unsigned_abs();
                sums[2 * i] += (scaled + lagged[i - 1]).unsigned_abs();
            };
            pair(1);
            pair(2);
            pair(3);
        }
        // The smallest sum, the lowest index on a tie.
        let (mut smallest, mut least) = (0, sums[0]);
        for (j, &sum) in sums.iter().enumerate().skip(1) {
            if sum < least {
                (smallest, least) = (j, sum);
            }
        }
        if smallest == 0 {
            return;
        }
        // Sums `2i - 1` and `2i` are weight `i`'s: the odd one lowers it,
        // the even one raises it, each while the weight is inside its bound.
        let mut weights = [self.weight_0, self.weight_1, self.weight_2];
        let weight = &mut weights[(smallest - 1) / 2];
        if smallest % 2 == 1 {
            *weight -= i32::from(*weight >= -16);
        } else {
            *weight += i32::from(*weight < 16);
        }
        [self.weight_0, self.weight_1, self.weight_2] = weights;
        [self.spread_0, self.spread_1, self.spread_2] = Channel::spread(weights);
    }
}

/// Audio decode over `channels` channels.
pub(crate) fn audio_decode(src: &[u8], out: &mut [u8], channels: u32) {
    audio::<false>(src, out, channels);
}

/// Audio encode, the inverse of [`audio_decode`].
// Reached only through the `internals_*` seam, behind the
// `bench-internals` feature; no shipped build enables it.
#[allow(dead_code)]
pub(crate) fn audio_encode(src: &[u8], out: &mut [u8], channels: u32) {
    audio::<true>(src, out, channels);
}

fn audio<const ENCODE: bool>(src: &[u8], out: &mut [u8], channels: u32) {
    let n = src.len().min(out.len());
    let (src, out) = (&src[..n], &mut out[..n]);
    match channels {
        0 => {}
        1 => audio_lockstep::<ENCODE, 1>(src, out),
        2 if !ENCODE => audio_pair_decode(src, out),
        2 => audio_lockstep::<ENCODE, 2>(src, out),
        3 => audio_lockstep::<ENCODE, 3>(src, out),
        4 => audio_lockstep::<ENCODE, 4>(src, out),
        _ => audio_by_channel::<ENCODE>(src, out, channels as usize),
    }
}

/// Any channel count: one channel after another.
fn audio_by_channel<const ENCODE: bool>(src: &[u8], out: &mut [u8], stride: usize) {
    let n = src.len();
    let mut at = 0;
    let mut round = Round::default();
    for c in 0..stride.min(n) {
        let m = plane_len(n, stride, c);
        let mut channel = Channel::default();
        let (mut t, mut round_end) = (0, 1);
        while t < m {
            let (base, end) = (t, round_end.min(m));
            channel.open(&mut round);
            while t < end {
                let (k, i) = (at + t, c + t * stride);
                if ENCODE {
                    out[k] = channel.byte::<true>(src[i], &mut round, t - base);
                } else {
                    out[i] = channel.byte::<false>(src[k], &mut round, t - base);
                }
                t += 1;
            }
            channel.revise(&round, end - base);
            round_end = end + REVISED_EVERY;
        }
        at += m;
    }
}

/// Every plane's first `REVISED_EVERY` bytes as an array of that many,
/// when every plane holds them.
#[inline(always)]
fn whole_round<'a, const N: usize>(planes: &[&'a [u8]; N]) -> Option<[&'a [u8; REVISED_EVERY]; N]> {
    let mut whole = [&[0u8; REVISED_EVERY]; N];
    for c in 0..N {
        whole[c] = planes[c].first_chunk::<REVISED_EVERY>()?;
    }
    Some(whole)
}

/// Two channels decoded in lockstep: [`audio_lockstep`]'s decode arm for
/// two, in a routine of its own with its rows COUNTED.
///
/// The round's whole rows are counted, and both planes and the rows they
/// fill are cut to that one count, so the row loop is a plain count up. A
/// WHOLE round, which is every round but a block's first and its last, is
/// `REVISED_EVERY` rows by its type: the planes and the rows are arrays
/// of that many, the count is a constant of the loop and no index in it
/// can be out of range.
///
/// Only two, and of its own, and both are measured. Stepped as
/// [`audio_lockstep`] steps its rows, a build under a profile kept a
/// select and a bounds test in the two channel loop on arm64 (50
/// instructions a row against the plain build's 44). Given this form
/// inside `audio_lockstep`, the four channel loop, which is short of
/// registers on x86-64, cost 2 percent more cycles there at one thread
/// for 1 percent fewer instructions; so that routine is left exactly as
/// it was and this one is never inlined beside it.
#[inline(never)]
fn audio_pair_decode(src: &[u8], out: &mut [u8]) {
    const N: usize = 2;
    let n = src.len();
    let rows = n / N;
    let extra = n % N;
    let longest = rows + usize::from(extra > 0);
    let starts = [0, plane_len(n, N, 0)];
    let mut held = [Channel::default(); N];
    let mut rounds: [Round; N] = std::array::from_fn(|_| Round::default());
    let (mut t, mut round_end) = (0, 1);
    while t < longest {
        let (base, end) = (t, round_end.min(longest));
        let mut live = held;
        for c in 0..N {
            live[c].open(&mut rounds[c]);
        }
        let full = end.min(rows);
        let first = base.min(full);
        let count = full - first;
        let planes: [&[u8]; N] =
            std::array::from_fn(|c| &src[starts[c] + first..starts[c] + full][..count]);
        let (out_rows, _) = out[first * N..full * N].as_chunks_mut::<N>();
        let out_rows = &mut out_rows[..count];
        match (
            whole_round(&planes),
            out_rows.first_chunk_mut::<REVISED_EVERY>(),
        ) {
            (Some(planes), Some(out_rows)) if count == REVISED_EVERY => {
                for f in 0..REVISED_EVERY {
                    for c in 0..N {
                        out_rows[f][c] = live[c].byte::<false>(planes[c][f], &mut rounds[c], f);
                    }
                }
            }
            _ => {
                for f in 0..count {
                    for c in 0..N {
                        out_rows[f][c] = live[c].byte::<false>(planes[c][f], &mut rounds[c], f);
                    }
                }
            }
        }
        // The partial row, when this round reaches it.
        if end > rows {
            let f = rows - base;
            for c in 0..extra {
                let (i, k) = (rows * N + c, starts[c] + rows);
                out[i] = live[c].byte::<false>(src[k], &mut rounds[c], f);
            }
        }
        t = end;
        for c in 0..N {
            let mine = end.min(rows + usize::from(c < extra)).saturating_sub(base);
            live[c].revise(&rounds[c], mine);
        }
        held = live;
        round_end = end + REVISED_EVERY;
    }
}

/// `N` channels in lockstep: channels are independent, so their chains
/// interleave, and each original row of `N` bytes is read or written in
/// one place.
///
/// Rounds run over the LONGEST channel, so a channel's adaptation (3.7.3
/// step 6) always follows its own 32nd byte and never a block boundary:
/// channels below `n mod N` have one byte more than the others, and that
/// byte must be stepped before the round it falls in adapts.
fn audio_lockstep<const ENCODE: bool, const N: usize>(src: &[u8], out: &mut [u8]) {
    let n = src.len();
    let rows = n / N;
    // Channels `0..extra` hold one byte more than the rest: the block's
    // last, partial row.
    let extra = n % N;
    let longest = rows + usize::from(extra > 0);
    let mut starts = [0usize; N];
    let mut at = 0;
    for (c, s) in starts.iter_mut().enumerate() {
        *s = at;
        at += plane_len(n, N, c);
    }
    let mut held = [Channel::default(); N];
    let mut rounds: [Round; N] = std::array::from_fn(|_| Round::default());
    let (mut t, mut round_end) = (0, 1);
    while t < longest {
        let (base, end) = (t, round_end.min(longest));
        let mut live = held;
        for c in 0..N {
            live[c].open(&mut rounds[c]);
        }
        // Whole rows of this round: every channel has these bytes, and the
        // bounds are settled here, once per round, not per byte.
        let full = end.min(rows);
        if ENCODE {
            let (src_rows, _) = src[base.min(full) * N..full * N].as_chunks::<N>();
            for (f, row) in src_rows.iter().enumerate() {
                for c in 0..N {
                    let k = starts[c] + base + f;
                    out[k] = live[c].byte::<true>(row[c], &mut rounds[c], f);
                }
            }
        } else {
            let planes: [&[u8]; N] =
                std::array::from_fn(|c| &src[starts[c] + base.min(full)..starts[c] + full]);
            let (out_rows, _) = out[base.min(full) * N..full * N].as_chunks_mut::<N>();
            for (f, row) in out_rows.iter_mut().enumerate() {
                for c in 0..N {
                    row[c] = live[c].byte::<false>(planes[c][f], &mut rounds[c], f);
                }
            }
        }
        // The partial row, when this round reaches it.
        if end > rows {
            let f = rows - base;
            for c in 0..extra {
                let (i, k) = (rows * N + c, starts[c] + rows);
                if ENCODE {
                    out[k] = live[c].byte::<true>(src[i], &mut rounds[c], f);
                } else {
                    out[i] = live[c].byte::<false>(src[k], &mut rounds[c], f);
                }
            }
        }
        t = end;
        for c in 0..N {
            // This channel's own bytes in this round; a channel that has
            // ended contributes none and its weights do not move.
            let mine = end.min(rows + usize::from(c < extra)).saturating_sub(base);
            live[c].revise(&rounds[c], mine);
        }
        held = live;
        round_end = end + REVISED_EVERY;
    }
}
