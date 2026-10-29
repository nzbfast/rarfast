//! The RAR 4 family's two-part Unicode name encoding (spec F 3.3.7).
//!
//! With file flag 0x0200 the name field holds a fallback name in ASCII, one
//! zero byte, then an encoded UTF-16 form. It is decoded as the reference
//! decodes it (the section's erratum of 4 Oct 2026, measured on unrar
//! 7.23): a run copies from the whole name FIELD and stops at the
//! field's end, a code unit of zero ends the name, and a selector that
//! needs a byte which is not there keeps the units decoded so far.
//!
//! **What bounds the work on a hostile field: the field's own length.**
//! There is no ceiling on the name. Every pass of the selector loop spends
//! at least one encoded byte, a run's unit `n` is byte `n` of the field so
//! no run takes the name past the field's length, and every other selector
//! spends a byte a unit: a name has fewer units than twice its field has
//! bytes, and the field is inside a header of at most 64 KiB. (Before
//! this a run read past the fallback's end as `?`, one byte gave 129
//! units, and a ceiling of 2,048 units was what bounded it.)

/// Decode `field` (the stored name bytes) into `out`, appending. With no
/// zero byte the field is the name and its bytes are appended unchanged.
pub(crate) fn decode_into(field: &[u8], unicode: bool, out: &mut Vec<u8>) {
    if !unicode {
        out.extend_from_slice(field);
        return;
    }
    let Some(zero) = field.iter().position(|b| *b == 0) else {
        out.extend_from_slice(field);
        return;
    };
    let units = decode_units(field, zero);
    if units.is_empty() {
        // No unit at all is no name: the fallback stands.
        out.extend_from_slice(&field[..zero]);
    } else {
        push_utf8(&units, out);
    }
}

/// The UTF-16 code units the encoded part of `field` names, the part
/// after the separating zero at `zero`. Empty when there is no encoded
/// part, or none of it makes a unit.
fn decode_units(field: &[u8], zero: usize) -> Vec<u16> {
    let mut out: Vec<u16> = Vec::new();
    let Some(&shared) = field.get(zero + 1) else {
        return out;
    };
    let high = u16::from(shared) << 8;
    let body = field.get(zero + 2..).unwrap_or(&[]);
    let mut at = 0usize;
    let mut selectors = 0u8;
    let mut left = 0u8;
    let take = |at: &mut usize| -> Option<u8> {
        let b = *body.get(*at)?;
        *at += 1;
        Some(b)
    };
    // The decode is over when the encoded bytes are, whatever the last
    // selector byte still holds: its trailing selectors describe nothing,
    // and both genuine two part names of the corpus end that way. A
    // selector that needs a byte which is not there ends it too, with the
    // units already decoded kept; and so does a unit of ZERO, whichever
    // selector made it, which is how the reference lists such a name.
    'decode: while at < body.len() {
        if left == 0 {
            let Some(next) = take(&mut at) else { break };
            selectors = next;
            left = 4;
        }
        let selector = selectors >> 6;
        selectors <<= 2;
        left -= 1;
        let unit = match selector {
            0 => take(&mut at).map(u16::from),
            1 => take(&mut at).map(|low| u16::from(low) | high),
            2 => {
                let low = take(&mut at);
                let hi = take(&mut at);
                // Half a unit is no unit (the reference reads the missing
                // half from past the name's bytes; pinned by a test).
                low.zip(hi)
                    .map(|(low, hi)| u16::from(low) | (u16::from(hi) << 8))
            }
            _ => {
                let Some(length) = take(&mut at) else { break };
                let (run, correction) = if length & 0x80 != 0 {
                    let Some(correction) = take(&mut at) else {
                        break;
                    };
                    (usize::from(length & 0x7F) + 2, Some(correction))
                } else {
                    (usize::from(length) + 2, None)
                };
                for _ in 0..run {
                    // Unit `n` of the name is byte `n` of the whole name
                    // field, and the run stops where the field does.
                    let Some(&base) = field.get(out.len()) else {
                        break;
                    };
                    let unit = match correction {
                        None => u16::from(base),
                        Some(c) => u16::from(base.wrapping_add(c)) | high,
                    };
                    if unit == 0 {
                        break 'decode;
                    }
                    out.push(unit);
                }
                continue;
            }
        };
        match unit {
            Some(unit) if unit != 0 => out.push(unit),
            _ => break,
        }
    }
    out
}

/// UTF-16 code units as UTF-8, with an unpaired surrogate replaced.
fn push_utf8(units: &[u16], out: &mut Vec<u8>) {
    let mut buf = [0u8; 4];
    for unit in char::decode_utf16(units.iter().copied()) {
        let ch = unit.unwrap_or(char::REPLACEMENT_CHARACTER);
        out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec F 5.3: `hello.txt\0` with no encoded part is `hello.txt`.
    #[test]
    fn spec_f_5_3_no_encoded_part() {
        let mut out = Vec::new();
        decode_into(b"hello.txt\0", true, &mut out);
        assert_eq!(out, b"hello.txt");
    }

    #[test]
    fn a_plain_field_is_its_own_name() {
        let mut out = Vec::new();
        decode_into(b"SUB\\NESTED", false, &mut out);
        assert_eq!(out, b"SUB\\NESTED");
    }

    #[test]
    fn selector_zero_and_two_carry_units_straight() {
        // Fallback "x", shared high byte 0x04, selectors 00 10 00 10.
        let mut field = vec![b'x', 0, 0x04, 0x22];
        field.extend_from_slice(&[b'a', 0x10, 0x04, b'b', 0x11, 0x04]);
        let mut out = Vec::new();
        decode_into(&field, true, &mut out);
        assert_eq!(String::from_utf8(out).unwrap(), "a\u{410}b\u{411}");
    }

    #[test]
    fn selector_one_puts_the_shared_high_byte_on_top() {
        // Selectors 01 01 01 01 = 0x55, four low halves.
        let field = [b'x', 0, 0x04, 0x55, 0x10, 0x11, 0x12, 0x13];
        let mut out = Vec::new();
        decode_into(&field, true, &mut out);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "\u{410}\u{411}\u{412}\u{413}"
        );
    }

    // ---- SPEC-F 3.3.7 as the reference does it (the erratum of 4 Oct
    // 2026, which this decoder follows). Each vector below is one the
    // erratum reports from reference unrar 7.23. One thread, no pool, no
    // memory to speak of.

    fn decoded(field: &[u8]) -> String {
        let mut out = Vec::new();
        decode_into(field, true, &mut out);
        String::from_utf8(out).expect("UTF-8")
    }

    /// Fallback `ABCDEFGHIJ`, a shared high byte, then the encoded bytes.
    fn field_of(high: u8, encoded: &[u8]) -> Vec<u8> {
        let mut field = b"ABCDEFGHIJ".to_vec();
        field.push(0);
        field.push(high);
        field.extend_from_slice(encoded);
        field
    }

    /// Item 2: a run copies from the whole NAME FIELD, the fallback name,
    /// the separating zero, the shared high byte and the encoded bytes
    /// themselves, unit `n` from byte `n`. It read past the fallback's end
    /// as `?`.
    #[test]
    fn a_run_copies_from_the_whole_name_field() {
        // Eight literal `q`, a corrected run of 10 with correction 1, `Z`.
        let encoded = [
            0x00, b'q', b'q', b'q', b'q', 0x00, b'q', b'q', b'q', b'q', 0xC0, 0x88, 0x01, b'Z',
        ];
        assert_eq!(
            decoded(&field_of(0, &encoded)),
            "qqqqqqqqJK\u{1}\u{1}\u{1}rrrr\u{1}Z"
        );
        // The same field with the shared high byte 4.
        assert_eq!(
            decoded(&field_of(4, &encoded)),
            "qqqqqqqq\u{44a}\u{44b}\u{401}\u{405}\u{401}\u{472}\u{472}\u{472}\u{472}\u{401}Z"
        );
    }

    /// Item 2: a run STOPS where the name field ends, whatever length it
    /// declared: a corrected run of 128 over a field of 7 bytes is 7 units.
    #[test]
    fn a_run_stops_at_the_end_of_the_name_field() {
        let field = [b'A', b'B', 0, 0, 0xC0, 0xFE, 0x01];
        assert_eq!(decoded(&field), "BC\u{1}\u{1}\u{c1}\u{ff}\u{2}");
    }

    /// Item 1: no ceiling on the name's length. A name of 3,000 literal
    /// units is listed whole; it was cut at 2,048.
    #[test]
    fn a_name_of_three_thousand_units_is_whole() {
        let mut encoded = Vec::new();
        for _ in 0..750 {
            encoded.extend_from_slice(&[0x00, b'n', b'a', b'm', b'e']);
        }
        let name = decoded(&field_of(0, &encoded));
        assert_eq!(name.len(), 3000);
        assert!(name.ends_with("namename"));
    }

    /// Item 3: so a hostile field cannot amplify. 400 corrected runs of
    /// 129 over a one byte fallback are 903 units from a 903 byte field:
    /// the name's units are bounded by the field's own bytes.
    #[test]
    fn four_hundred_long_runs_give_no_more_units_than_the_field_has_bytes() {
        let mut field = vec![b'A', 0, 0x04];
        for _ in 0..100 {
            field.extend_from_slice(&[0xFF, 0xFF, 1, 0xFF, 1, 0xFF, 1, 0xFF, 1]);
        }
        assert_eq!(field.len(), 903);
        assert_eq!(decoded(&field).chars().count(), 903);
    }

    /// Spec F 3.3.7, "The longest name": the format bounds a name by the
    /// field that carries it, and a decoded name has fewer units than
    /// twice its field has bytes, so the longest field costs bounded
    /// memory: under 131,070 units, and with a growing vector's slack
    /// under 524,280 bytes held. Three fields
    /// at the longest a 16 bit header size could carry, 65,535 bytes:
    /// all literal units, the densest (one byte a unit after the selector
    /// bytes); all selector 2 units; and corrected runs of 129, which
    /// declare 43 times the units the field has bytes and give no more
    /// than the field's length. And the longest name the reference was
    /// shown listing, 59,985 units, is whole. Single threaded; under
    /// 1 MiB.
    #[test]
    fn the_longest_field_costs_bounded_memory() {
        const FIELD: usize = 65_535;
        let field_with = |selector_byte: u8, operand: &[u8]| {
            let mut field = vec![b'A', 0, 0x04];
            while field.len() + 1 + 4 * operand.len() <= FIELD {
                field.push(selector_byte);
                for _ in 0..4 {
                    field.extend_from_slice(operand);
                }
            }
            field
        };
        let literals = field_with(0b0000_0000, b"q");
        let pairs = field_with(0b1010_1010, &[0x2d, 0x4e]);
        let runs = field_with(0b1111_1111, &[0xff, 1]);
        for (name, field, units) in [
            ("literals", &literals, (literals.len() - 3) / 5 * 4),
            ("two byte units", &pairs, (pairs.len() - 3) / 9 * 4),
            ("runs", &runs, runs.len()),
        ] {
            assert!(field.len() > FIELD - 9, "{name}: a field at the limit");
            let decoded = decode_units(field, 1);
            assert_eq!(decoded.len(), units, "{name}");
            assert!(decoded.len() < 2 * field.len(), "{name}");
            assert!(decoded.capacity() * 2 < 8 * FIELD, "{name}: bytes held");
        }
        // 59,985 literal units, the longest the reference listed whole.
        let mut longest = vec![b'A', 0, 0];
        for chunk in vec![b'n'; 59_985].chunks(4) {
            longest.push(0);
            longest.extend_from_slice(chunk);
        }
        assert_eq!(decode_units(&longest, 1), vec![u16::from(b'n'); 59_985]);
    }

    /// Item 4: a code unit of ZERO ends the name, whichever selector made
    /// it. An uncorrected run that passes the fallback's end reads the
    /// separating zero and the name ends there; it added `?` units.
    #[test]
    fn a_zero_unit_ends_the_name() {
        // `x`, a zero unit, `Z`, by selectors 0, 1 and 2 in turn.
        assert_eq!(decoded(&field_of(0, &[0x00, b'x', 0, b'Z'])), "x");
        assert_eq!(decoded(&field_of(0, &[0x10, b'x', 0, b'Z'])), "x");
        assert_eq!(decoded(&field_of(0, &[0x20, b'x', 0, 0, b'Z'])), "x");
        // A run of 50 from position 0, then `Z`, `Y`.
        assert_eq!(decoded(&field_of(0, &[0xC0, 48, b'Z', b'Y'])), "ABCDEFGHIJ");
        // Eight literal `q` and a run of 10.
        assert_eq!(
            decoded(&field_of(
                0,
                &[0x00, b'q', b'q', b'q', b'q', 0x00, b'q', b'q', b'q', b'q', 0xC0, 8]
            )),
            "qqqqqqqqIJ"
        );
        // Literal units past the fallback's end are just units.
        let mut field = vec![b'A', b'B', b'C', 0, 0];
        field.extend_from_slice(&[0x00, b'0', b'1', b'2', b'3']);
        field.extend_from_slice(&[0x00, b'4', b'5', b'6', b'7', 0x00, b'8', b'9']);
        assert_eq!(decoded(&field), "0123456789");
    }

    /// Item 5: a selector that needs a byte which is not there does not
    /// bring the fallback name back: the units decoded so far are the
    /// name. It answered `ABCDEFGHIJ`.
    #[test]
    fn a_selector_short_of_a_byte_keeps_the_decoded_units() {
        // `x`, `y`, then a corrected run whose correction byte is missing.
        assert_eq!(decoded(&field_of(0, &[0x0C, b'x', b'y', 0x88])), "xy");
    }

    /// PINNED DIFFERENCE, item 5's second vector: `x`, `y`, then selector
    /// 2 with one byte `L` left. The reference lists `xyL`, having read
    /// the missing half past the name's bytes, "not something to copy";
    /// rarkit makes no unit of half a unit and lists `xy`.
    #[test]
    fn pinned_half_a_two_byte_unit_is_no_unit() {
        assert_eq!(decoded(&field_of(0, &[0x08, b'x', b'y', b'L'])), "xy");
    }

    /// With NO unit decoded the fallback name stands: a name of no units
    /// is no name, and the erratum's "the units decoded so far are the
    /// name" was measured with units in hand.
    #[test]
    fn with_no_unit_decoded_the_fallback_stands() {
        // A selector byte asking for two data bytes with none behind it.
        assert_eq!(decoded(&[b'a', b'b', 0, 0x00, 0x80]), "ab");
        // A shared high byte and nothing after it.
        assert_eq!(decoded(&[b'a', b'b', 0, 0x04]), "ab");
    }
}

#[cfg(test)]
mod corpus_tests {
    use super::*;

    /// The corpus's `rar4_sharpcompress_files_only.rar` carries
    /// `????.txt` with the encoded form of `тест.txt` behind it: four
    /// selector-1 units and a selector-3 run of four, which leaves two of
    /// that selector byte's four selectors unused (spec F 3.3.7).
    #[test]
    fn a_genuine_two_part_name_decodes() {
        let field = [
            0x3f, 0x3f, 0x3f, 0x3f, 0x2e, 0x74, 0x78, 0x74, 0x00, 0x04, 0x55, 0x42, 0x35, 0x41,
            0x42, 0xc0, 0x02,
        ];
        let mut out = Vec::new();
        decode_into(&field, true, &mut out);
        assert_eq!(String::from_utf8(out).unwrap(), "тест.txt");
    }
}
