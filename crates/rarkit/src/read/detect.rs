//! Detection: which generation a source holds, and where the archive starts
//! behind a self-extracting stub (spec F 3.1).

use crate::error::Result;
use crate::read::cursor::{read_upto_at, MIN_READ};
use crate::read::{Format, Found};
use crate::source::RangeSource;

/// RAR 1.3 and 1.4.
pub(crate) const SIG_RAR13: &[u8] = b"RE~^";
/// RAR 1.5, 2.0 and the RAR 4 family.
pub(crate) const SIG_RAR4: &[u8] = b"Rar!\x1a\x07\x00";
/// RAR 5.
pub(crate) const SIG_RAR5: &[u8] = b"Rar!\x1a\x07\x01\x00";

/// The longest signature, and so how far past the scan window a match may
/// still begin.
pub(crate) const MAX_SIG: usize = 8;

/// The last offset at which the RAR 1.3 signature is a mark (spec F
/// 3.1.2): the reference reads such an archive at offset 0 and at offset
/// 1 and nowhere else, and four bytes of text are too weak to search for.
const RAR13_LAST_START: u64 = 1;

/// The generation a signature at `bytes`, `offset` into the source,
/// announces. Longest form first: the RAR 4 signature is a PREFIX of the
/// RAR 5 one, so a reader that tests the shorter form first reads every
/// RAR 5 archive as a corrupt RAR 4 archive.
fn signature_at(bytes: &[u8], offset: u64) -> Option<Format> {
    if bytes.starts_with(SIG_RAR5) {
        Some(Format::Rar5)
    } else if bytes.starts_with(SIG_RAR4) {
        Some(Format::Rar4Family)
    } else if offset <= RAR13_LAST_START && bytes.starts_with(SIG_RAR13) {
        Some(Format::Rar13)
    } else {
        None
    }
}

/// How many bytes of the signature at `start` were matched.
pub(crate) fn signature_len(format: Format) -> u64 {
    match format {
        Format::Rar5 => SIG_RAR5.len() as u64,
        Format::Rar13 => SIG_RAR13.len() as u64,
        _ => SIG_RAR4.len() as u64,
    }
}

/// The first `Rar!` signature at or after offset 0, or the RAR 1.3
/// signature at offset 0 or 1, reading at most `sfx_scan` bytes plus one
/// signature. Allocates nothing beyond one stack
/// buffer. `Ok(None)` means no signature in range; it is not an error.
///
/// `sfx_scan == 0` means the archive starts at byte 0 and no search is made.
/// The FIRST signature wins even when the archive behind it does not parse
/// (spec F 3.1.3): a reader that rescans on a parse failure finds a
/// different archive from the reference in exactly the cases where a
/// producer is trying to make two readers disagree.
pub(crate) fn detect_in(src: &dyn RangeSource, sfx_scan: u64) -> Result<Option<Found>> {
    let mut buf = [0u8; MIN_READ + MAX_SIG];
    // The furthest byte the search may read: a signature starting at
    // `sfx_scan` ends here (API 5.1, spec F 3.1.2).
    let limit = sfx_scan.saturating_add(MAX_SIG as u64);
    // Source offset of `buf[0]`, and how many bytes of `buf` are valid.
    let mut base = 0u64;
    let mut have = 0usize;
    loop {
        let from = base + have as u64;
        let room = (buf.len() - have).min(usize::try_from(limit - from).unwrap_or(usize::MAX));
        let got = read_upto_at(src, from, &mut buf[have..have + room])?;
        // Either the source ended or the bound was reached; neither has a
        // next window.
        let at_end = got < room || from + got as u64 == limit;
        have += got;
        // A start within the last seven bytes may still match once more
        // bytes arrive, so it is left for the next window unless there is
        // no next window.
        let last_start = if at_end {
            have
        } else {
            have.saturating_sub(MAX_SIG - 1)
        };
        for at in 0..last_start {
            if base + at as u64 > sfx_scan {
                return Ok(None);
            }
            if let Some(format) = signature_at(&buf[at..have], base + at as u64) {
                return Ok(Some(Found {
                    format,
                    start: base + at as u64,
                }));
            }
        }
        if at_end {
            return Ok(None);
        }
        buf.copy_within(last_start..have, 0);
        base += last_start as u64;
        have -= last_start;
        if base > sfx_scan {
            return Ok(None);
        }
    }
}
