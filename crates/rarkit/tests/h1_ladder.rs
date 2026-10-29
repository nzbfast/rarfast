//! The subtractive ladder's own falsification (the subtractive ladder bench).
//!
//! A ladder whose rows are not the same measurement is worse than no
//! ladder, so two things are checked here and both can fail: that the
//! full stage decodes the stream it was built from byte for byte, and
//! that every other stage walks the same symbol count over the same
//! bytes. Neither is a performance assertion; both are what the figures
//! are worth nothing without.

use rarkit::internals::rar3_lz::{ladder_stages, literal_ladder};

/// Enough symbols that the window wraps several times and the pair loop
/// is entered on both sides of a wrap.
const SYMBOLS: usize = 200_000;

/// Every shape the ladder has.
///
/// `incomp` and `code` are the alphabets the pair-loop-gate work
/// MEASURED off the real corpora, widths 7 to 9 and 5 to 9. The other
/// three are constructions: `random` is one width, which no block that
/// can END is able to carry, `nearflat` is two, and `text` is four to
/// twelve, which is a wider spread than any real rar3 leg shows.
const SHAPES: [&str; 5] = ["incomp", "code", "random", "nearflat", "text"];

#[test]
fn v_ladder_the_full_stage_decodes_its_own_stream_in_both_shapes() {
    for shape in SHAPES {
        let ladder = literal_ladder(shape, SYMBOLS).expect("shape");
        let (got, want) = ladder.full_against_expected(1 << 16);
        assert!(!want.is_empty(), "{shape}: nothing expected");
        assert_eq!(
            got.len(),
            want.len(),
            "{shape}: the full stage produced a different length"
        );
        assert_eq!(
            got.iter().zip(&want).position(|(a, b)| a != b),
            None,
            "{shape}: the full stage does not decode its own literals"
        );
    }
}

#[test]
fn v_ladder_every_stage_walks_the_same_symbol_count() {
    for shape in SHAPES {
        let ladder = literal_ladder(shape, SYMBOLS).expect("shape");
        let (full, _) = ladder.run("full").expect("stage");
        assert!(full > SYMBOLS / 2, "{shape}: the full stage walked {full}");
        for stage in ladder_stages() {
            let (walked, _) = ladder.run(stage).expect("stage");
            assert_eq!(
                walked, full,
                "{shape}: stage {stage} walked {walked} symbols against the full stage's {full}, \
                 so the rows are not comparable"
            );
        }
    }
}

#[test]
fn v_ladder_names_no_shape_and_no_stage_it_does_not_have() {
    assert!(literal_ladder("ppmd", 1024).is_none());
    let ladder = literal_ladder("random", 4096).expect("shape");
    assert!(ladder.run("no-such-stage").is_none());
    assert_eq!(ladder_stages().len(), 13);
    assert!(literal_ladder("random", 4096)
        .expect("shape")
        .stage_against_expected("no-such-stage", 16)
        .is_none());
}

/// Every candidate LOOP decodes the stream it was built from, byte for
/// byte, in every shape.
///
/// This is the check the timing is worth nothing without, and it is a
/// different check from the full stage's: the four stages added here
/// are CANDIDATE loops and not subtractions, so each of them has to
/// produce the same literals as the loop it is a candidate against. A
/// speculative second lookup in particular is only sound because its
/// guess is tested before it is used, and this is where that is shown
/// rather than asserted.
#[test]
fn v_ladder_every_decoding_stage_decodes_its_own_stream() {
    for shape in SHAPES {
        let ladder = literal_ladder(shape, SYMBOLS).expect("shape");
        let stages = ladder.decoding_stages();
        assert!(
            stages.len() >= 7,
            "{shape}: {} decoding stages, so a candidate loop is going unchecked",
            stages.len()
        );
        for stage in stages {
            let (got, want) = ladder
                .stage_against_expected(stage, 1 << 16)
                .expect("a decoding stage");
            assert!(!want.is_empty(), "{shape}/{stage}: nothing expected");
            assert_eq!(got.len(), want.len(), "{shape}/{stage}: a different length");
            assert_eq!(
                got.iter().zip(&want).position(|(a, b)| a != b),
                None,
                "{shape}/{stage}: does not decode its own literals"
            );
        }
    }
}

/// A subtractive stage is REFUSED the byte comparison rather than failed
/// by it.
///
/// `no-lookup` writes shifted input bytes on purpose, so asking it to
/// decode would be asking the wrong question; the seam answers `None`
/// and this is what says so.
#[test]
fn v_ladder_a_subtractive_stage_is_not_asked_to_decode() {
    let ladder = literal_ladder("random", 4096).expect("shape");
    for stage in ["no-lookup", "refill-only", "lookup-only", "write-only"] {
        assert!(
            ladder.stage_against_expected(stage, 16).is_none(),
            "{stage} was asked to decode, and it does not"
        );
        assert!(
            !ladder.decoding_stages().contains(&stage),
            "{stage} is listed as a decoding stage"
        );
    }
}

/// The alphabet properties the candidate loops turn on, stated as
/// numbers rather than left to the reader.
///
/// A fourteen bit pair table cannot answer a pair of eight bit codes,
/// and both flat shapes are eight bit codes, so its cover on them is
/// ZERO and its row measures the cost of asking. The sixteen bit table
/// answers them and is outside SPEC-H1 4.2's ceiling. This test is what
/// keeps that arithmetic honest if either width is ever changed.
#[test]
fn v_ladder_the_pair_tables_cover_what_the_widths_allow() {
    let flat = literal_ladder("random", 4096).expect("shape");
    let (narrow, wide) = flat.pair_cover();
    assert_eq!(
        narrow, 0.0,
        "a 14 bit index answered a pair of eight bit codes, which is 16 bits"
    );
    assert!(
        wide > 0.99,
        "a 16 bit index answered only {wide} of its entries"
    );
    let (mode, one, two) = flat.mode_cover();
    assert_eq!(mode, 8, "the flat shape's literals are eight bits");
    assert_eq!(
        one, 1.0,
        "every literal of the flat shape has the modal width"
    );

    // The two MEASURED shapes, against the gate measurement's own counts.
    let incomp = literal_ladder("incomp", 200_000).expect("shape");
    let (narrow, _) = incomp.pair_cover();
    // The gate measurement found 2.14 percent of that leg's pairs at
    // `w1 + w2 <= 14`. This shape draws its widths independently, which
    // its own comment shows is faithful on THIS leg, so its cover is the
    // 7+7 corner of an independent draw and is the same order.
    assert!(
        narrow > 0.0 && narrow < 0.2,
        "the 7 to 9 alphabet resolved {narrow} of its pairs at 14 bits"
    );
    let (mode, one, _) = incomp.mode_cover();
    assert_eq!(mode, 8, "the incompressible leg's modal literal width");
    // Measured at 84.95 percent by the gate measurement, 21 Sep 2026.
    assert!(
        (0.83..0.87).contains(&one),
        "the modal width covered {one} of the incompressible draw, and the corpus says 0.8495"
    );
    let (best, _) = incomp.best_mode();
    assert_eq!(
        best, mode,
        "on this leg the code's Kraft mass and the realized draw agree, so the statistic is right"
    );

    // THE STATISTIC IS RIGHT ON BOTH MEASURED LEGS, and this is what
    // says so rather than a comment claiming it.
    //
    // `literal_mode` infers the guessed width from the code LENGTHS,
    // because lengths are all a decoder has, and it is only as good as
    // the assumption that the encoder built a code matched to its
    // frequencies. An earlier cut of this shape INVENTED counts over the
    // measured width RANGE, and those tied at widths 8 and 9 and made
    // the statistic pick 8 where the draw is half at 9; this test
    // asserted the disagreement. On the alphabet the probe actually read
    // off the member there is no tie: width 9 carries 0.4180 of the mass
    // against 0.1719 for the runner up, the statistic picks 9, and 9 is
    // the modal realized width at about 50 percent. The tie was the
    // construction's and not the corpus's.
    let code = literal_ladder("code", 200_000).expect("shape");
    let (mode, one, _) = code.mode_cover();
    let (best, best_hit) = code.best_mode();
    assert_eq!(mode, 9, "the code leg's modal literal width");
    assert_eq!(
        best, mode,
        "the statistic picks the width the draw actually favours on this leg too"
    );
    // Measured at 50.37 percent by the gate measurement, 21 Sep 2026.
    assert!(
        (0.48..0.53).contains(&one) && (best_hit - one).abs() < 1.0e-9,
        "the modal width covered {one} of the code draw against the best {best_hit}, and the \
         corpus says 0.5037"
    );

    let near = literal_ladder("nearflat", 200_000).expect("shape");
    let (mode, one, two_near) = near.mode_cover();
    assert_eq!(mode, 8);
    // 240 of the 256 literals are eight bits wide and the emitter is
    // uniform over them, so the one width guess is right about 93.75
    // percent of the time and the two width guess always.
    assert!(
        (0.92..0.96).contains(&one),
        "the one width guess hit {one} of the near flat shape's literals"
    );
    assert!(
        two_near > 0.999,
        "the two width guess hit only {two_near}, and the shape has exactly two widths"
    );
    assert_eq!(two, 1.0, "the flat shape has one width, so two cover it");
}
