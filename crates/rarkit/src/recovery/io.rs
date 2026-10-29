//! Positional reads, in the shapes the recovery paths want.

use crate::source::RangeSource;
use crate::{Error, ErrorKind, Result};

/// Fill `buf` from `offset`, looping over short reads. A source that ends
/// first is [`ErrorKind::Truncated`].
pub(crate) fn read_exact_at(src: &dyn RangeSource, offset: u64, buf: &mut [u8]) -> Result<()> {
    let got = read_at_most(src, offset, buf)?;
    if got < buf.len() {
        return Err(Error::new(ErrorKind::Truncated).with_offset(offset + got as u64));
    }
    Ok(())
}

/// Fill as much of `buf` from `offset` as the source holds; the count.
pub(crate) fn read_at_most(src: &dyn RangeSource, offset: u64, buf: &mut [u8]) -> Result<usize> {
    let mut at = 0usize;
    while at < buf.len() {
        let n = src
            .read_at(offset + at as u64, &mut buf[at..])
            .map_err(|e| Error::new(ErrorKind::Source(e)).with_offset(offset + at as u64))?;
        if n == 0 {
            break;
        }
        at += n;
    }
    Ok(at)
}

/// The source's length, from its declaration or from what has arrived.
pub(crate) fn length(src: &dyn RangeSource) -> u64 {
    src.len().unwrap_or_else(|| src.available())
}
