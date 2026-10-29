//! Spec J entry points for this repository's fuzz targets and
//! benches, behind the `bench-internals` feature. Not part of the API; no
//! shipped build enables it.

use crate::memory::MemoryPolicy;
use crate::rar3_filters::{self as j, FilterState, MemberBounds, RecordBytes, SpanBytes};
use crate::Result;

/// Section 4's bounds, for the fuzz targets that assert them: the span
/// length, the slot table and the queue.
pub const MAX_SPAN: u32 = j::STAGE_SPAN;
/// See [`MAX_SPAN`].
pub const MAX_SLOTS: usize = j::SLOTS_AT_MOST;
/// See [`MAX_SPAN`].
pub const MAX_QUEUED: usize = j::WAITING_AT_MOST;

/// Which RAR 3 transform [`rar3_transform`] runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rar3Transform {
    /// x86 calls (`E8`), parameter: the member offset.
    X86Call,
    /// x86 calls and jumps (`E8`, `E9`), parameter: the member offset.
    X86CallJump,
    /// Itanium, parameter: the member offset.
    Itanium,
    /// Delta, parameter: channels.
    Delta,
    /// RGB, parameters: row width, red position.
    Rgb,
    /// Audio, parameter: channels.
    Audio,
}

impl Rar3Transform {
    /// This transform's row of the fingerprint table (section 3.4): the
    /// standard program's length in bytes and the CRC32 of those bytes.
    ///
    /// A differential oracle names a filter by its program BYTES, and this
    /// crate holds none of them. A caller that needs them reads
    /// them from `specs/vectors-J/programs.tsv`, where they were
    /// recorded from genuine archives, and finds the row by this
    /// fingerprint.
    pub fn fingerprint(self) -> (u32, u32) {
        use crate::rar3_filters::StandardProgram as P;
        match self {
            Rar3Transform::X86Call => P::X86Call,
            Rar3Transform::X86CallJump => P::X86CallJump,
            Rar3Transform::Itanium => P::Itanium,
            Rar3Transform::Delta => P::Delta,
            Rar3Transform::Rgb => P::Rgb,
            Rar3Transform::Audio => P::Audio,
        }
        .fingerprint()
    }

    /// Every transform, in fingerprint-table order.
    pub const ALL: [Rar3Transform; 6] = [
        Rar3Transform::X86Call,
        Rar3Transform::X86CallJump,
        Rar3Transform::Itanium,
        Rar3Transform::Delta,
        Rar3Transform::Rgb,
        Rar3Transform::Audio,
    ];
}

/// Run one RAR 3 transform over `src` into `out`, decode or encode.
pub fn rar3_transform(t: Rar3Transform, decode: bool, src: &[u8], out: &mut [u8], a: u32, b: u32) {
    use crate::carry::h_ours::codec::address_filters::{self as af, Direction};
    let dir = if decode {
        Direction::Decode
    } else {
        Direction::Encode
    };
    match (t, decode) {
        (Rar3Transform::Delta, true) => j::delta_decode(src, out, a),
        (Rar3Transform::Delta, false) => j::delta_encode(src, out, a),
        (Rar3Transform::Rgb, true) => j::rgb_decode(src, out, a, b),
        (Rar3Transform::Rgb, false) => j::rgb_encode(src, out, a, b),
        (Rar3Transform::Audio, true) => j::audio_decode(src, out, a),
        (Rar3Transform::Audio, false) => j::audio_encode(src, out, a),
        (addr, _) => {
            let n = src.len().min(out.len());
            out[..n].copy_from_slice(&src[..n]);
            let buf = &mut out[..n];
            match (addr, decode) {
                // The seam runs what SHIPS, so it moved with
                // `rar3_filters::record`'s apply to the walking body.
                (Rar3Transform::X86Call, true) => {
                    af::x86_pass_walking::<false, false, false>(buf, a)
                }
                (Rar3Transform::X86Call, false) => {
                    af::x86_pass_walking::<true, false, false>(buf, a)
                }
                (Rar3Transform::X86CallJump, true) => {
                    af::x86_pass_walking::<false, true, false>(buf, a)
                }
                (Rar3Transform::X86CallJump, false) => {
                    af::x86_pass_walking::<true, true, false>(buf, a)
                }
                _ => af::ia64(buf, a, dir),
            }
        }
    }
}

struct Slice<'a>(&'a [u8]);

impl RecordBytes for Slice<'_> {
    fn next_byte(&mut self) -> Result<u8> {
        let (&b, rest) = self
            .0
            .split_first()
            .ok_or_else(|| crate::Error::new(crate::ErrorKind::Truncated))?;
        self.0 = rest;
        Ok(b)
    }
}

/// Drive a synthetic member of `member_len` zero bytes through a filter
/// stream whose records come from `input`: each step reads one byte that
/// advances the decoder's position, then one record. Returns the number of
/// bytes delivered, which on success is `member_len`; also returns the
/// most filters that were queued at once.
pub fn rar3_record_stream(input: &[u8], member_len: u64) -> Result<(u64, usize)> {
    let policy = MemoryPolicy {
        max_window: 1 << 22,
        max_dictionary: 1 << 22,
        max_workers: 1,
        ..MemoryPolicy::from_limit(1 << 30)
    };
    let mut state = FilterState::new(&policy)?;
    let zeros = vec![0u8; j::STAGE_SPAN as usize];
    let member = MemberBounds {
        start: 0,
        end: member_len,
    };
    let (mut pos, mut delivered, mut most) = (0u64, 0u64, 0usize);
    let mut src = Slice(input);
    let advance = |state: &mut FilterState, delivered: &mut u64, target: u64| -> Result<()> {
        loop {
            let limit = state.hold_from().map_or(target, |h| h.min(target));
            *delivered = (*delivered).max(limit);
            match state.due_at() {
                Some(end) if end <= target => {
                    let len = (end - state.hold_from().unwrap_or(end)) as usize;
                    let span = state
                        .run_due(end, SpanBytes::Window(&zeros[..len], &[]))?
                        .expect("a due span runs");
                    assert_eq!(span.start, *delivered, "spans are delivered in order");
                    assert_eq!(span.bytes.len(), len);
                    *delivered += len as u64;
                }
                _ => return Ok(()),
            }
        }
    };
    while let Some((&step, rest)) = src.0.split_first() {
        src.0 = rest;
        pos = (pos + step as u64 * 97).min(member_len);
        advance(&mut state, &mut delivered, pos)?;
        if src.0.is_empty() {
            break;
        }
        state.read_record(&mut src, pos, member)?;
        most = most.max(state.queued());
        assert!(state.queued() <= j::WAITING_AT_MOST);
    }
    advance(&mut state, &mut delivered, member_len)?;
    state.end_member(member_len)?;
    Ok((delivered, most))
}
