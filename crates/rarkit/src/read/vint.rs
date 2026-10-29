//! The RAR 5 variable length integer (spec F 3.2.1).
//!
//! Seven bits per byte, least significant group first, the top bit set on
//! every byte but the last. At most ten bytes; a value above `2^63 - 1` is
//! refused, because nothing in the format needs the top bit and accepting
//! it makes every later addition a trap.

/// The longest vint the format allows.
pub(crate) const MAX_VINT_BYTES: usize = 10;

/// Read a vint from `bytes` at `*at`, advancing `*at` past it. `None` when
/// it does not terminate inside `bytes`, runs past ten bytes, or names a
/// value above `2^63 - 1`.
#[inline]
pub(crate) fn read(bytes: &[u8], at: &mut usize) -> Option<u64> {
    // THE ONE-BYTE CASE, TAKEN FIRST, because it is most of them and it
    // needs none of the loop below.
    //
    // A RAR 5 file header is read through about eight of these, and a
    // sampled profile of the sequential driver over 20,000 small
    // members books 4.1 percent of a whole member to this function -
    // more than `parse_file` itself (measured). Most of
    // those reads are one byte: the header flags, the file flags, the
    // block type, a short name length, a host code, a size under 128.
    // For those the loop's shift bookkeeping, its two overflow tests
    // and its `i64::MAX` bound are all dead work, because a byte with
    // its top bit clear is at most 127.
    //
    // The slow path below is unchanged and still decides every other
    // case, so the two agree by construction rather than by a second
    // implementation of the same rule.
    let first = *bytes.get(*at)?;
    if first & 0x80 == 0 {
        *at += 1;
        return Some(u64::from(first));
    }
    read_long(bytes, at)
}

/// Every vint that is not one byte (spec F 3.2.1).
fn read_long(bytes: &[u8], at: &mut usize) -> Option<u64> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    for step in 0..MAX_VINT_BYTES {
        let byte = *bytes.get(*at + step)?;
        let group = u64::from(byte & 0x7F);
        // The tenth group carries one bit; anything above `2^63 - 1` is
        // refused whatever group it came from.
        if shift >= 64 || (group << shift) >> shift != group {
            return None;
        }
        value |= group << shift;
        if byte & 0x80 == 0 {
            if value > i64::MAX as u64 {
                return None;
            }
            *at += step + 1;
            return Some(value);
        }
        shift += 7;
    }
    None
}

/// A vint read as a `usize`, refusing a value this machine cannot index.
pub(crate) fn read_usize(bytes: &[u8], at: &mut usize) -> Option<usize> {
    usize::try_from(read(bytes, at)?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec F 5.3's unit vectors.
    #[test]
    fn spec_f_5_3_vectors() {
        let mut at = 0;
        assert_eq!(read(&[0x90, 0x00], &mut at), Some(16));
        assert_eq!(at, 2, "0x90 continues, 0x00 terminates");

        at = 0;
        assert_eq!(read(&[0xa4, 0x83, 0x02], &mut at), Some(0x81A4));
        assert_eq!(at, 3);

        at = 0;
        assert_eq!(read(&[0x80, 0x00, 0x01], &mut at), Some(0));
        assert_eq!(at, 2, "the third byte is not consumed");

        assert_eq!(read(&[0x80; 11], &mut 0), None);
    }

    /// **The one-byte fast path and the loop agree on every value the
    /// fast path takes, and on the boundary either side of it.**
    ///
    /// The fast path exists because a sampled profile booked 4.1
    /// percent of a 20,000 small member extraction to this function.
    /// It must not become a second reading of the format: this holds
    /// it against the loop for all 128 values it claims, and shows the
    /// first value it does NOT claim still goes the long way.
    #[test]
    fn the_one_byte_path_agrees_with_the_loop() {
        for byte in 0u8..=0x7F {
            let mut fast = 0;
            let mut slow = 0;
            assert_eq!(
                read(&[byte], &mut fast),
                read_long(&[byte], &mut slow),
                "value 0x{byte:02x} must read the same either way"
            );
            assert_eq!(fast, slow, "and must consume the same bytes");
            assert_eq!(fast, 1, "a byte with the top bit clear is one byte");
        }
        // 0x80 is the first byte the fast path must NOT claim: it
        // continues, so the value is 0 and TWO bytes are consumed.
        let mut at = 0;
        assert_eq!(read(&[0x80, 0x00], &mut at), Some(0));
        assert_eq!(at, 2, "a continuing byte goes the long way");
        // And a lone continuing byte does not terminate.
        assert_eq!(read(&[0x80], &mut 0), None);
    }

    #[test]
    fn a_vint_that_runs_past_the_header_is_refused() {
        assert_eq!(read(&[0x80, 0x80], &mut 0), None);
        assert_eq!(read(&[], &mut 0), None);
    }

    #[test]
    fn the_top_bit_is_refused() {
        // 0x8000_0000_0000_0000 exactly.
        let bytes = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01];
        assert_eq!(read(&bytes, &mut 0), None);
        // One below it is the largest value the format may name.
        let max = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];
        assert_eq!(read(&max, &mut 0), Some(i64::MAX as u64));
    }

    #[test]
    fn every_value_round_trips() {
        for bits in 0..63 {
            let value = 1u64 << bits;
            let mut bytes = Vec::new();
            let mut rest = value;
            loop {
                let group = (rest & 0x7F) as u8;
                rest >>= 7;
                bytes.push(if rest == 0 { group } else { group | 0x80 });
                if rest == 0 {
                    break;
                }
            }
            let mut at = 0;
            assert_eq!(read(&bytes, &mut at), Some(value));
            assert_eq!(at, bytes.len());
        }
    }
}
