//! `two_arm`'s leg filter, both forms, pinned against the real create leg
//! names in `support/creategate.rs`'s `SHAPES`, the list the bench builds
//! its `g/create/*` legs from.
//!
//! The substring form stays the default and must still select a prefix
//! leg's siblings, so no existing bench script changes meaning. The
//! exact form must select the named leg and only that leg.

#[path = "support/creategate.rs"]
mod creategate;
#[path = "support/legselect.rs"]
mod legselect;

use creategate::SHAPES;
use legselect::{selects, LegMatch};

/// Every create leg name `filter` selects in the form `how`.
fn selected(filter: &str, how: LegMatch) -> Vec<&'static str> {
    SHAPES
        .iter()
        .map(|s| s.name)
        .filter(|name| selects(Some(filter), how, name))
        .collect()
}

#[test]
fn the_default_form_is_substring_and_still_selects_the_siblings() {
    assert_eq!(
        LegMatch::from_args(&["g/create/rar5/m0"]),
        LegMatch::Substring
    );
    assert_eq!(
        LegMatch::from_args(&["--only=old", "--rounds=3", "g/create/rar5/m0"]),
        LegMatch::Substring
    );
    let got = selected("g/create/rar5/m0", LegMatch::Substring);
    for sibling in [
        "g/create/rar5/m0",
        "g/create/rar5/m0/streamed",
        "g/create/rar5/m0/20k",
        "g/create/rar5/m0/rr",
        "g/create/rar5/m0/vol+rr",
        "g/create/rar5/m0/pw",
        "g/create/rar5/m0/hp",
    ] {
        assert!(
            got.contains(&sibling),
            "substring form lost {sibling}: {got:?}"
        );
    }
    assert_eq!(got.len(), 7, "{got:?}");
}

#[test]
fn the_exact_form_selects_the_named_leg_and_only_it() {
    assert_eq!(
        LegMatch::from_args(&["--only=rarkit", "--exact", "g/create/rar5/m0"]),
        LegMatch::Exact
    );
    assert_eq!(
        selected("g/create/rar5/m0", LegMatch::Exact),
        ["g/create/rar5/m0"]
    );
    // Every create leg, each selected alone by its own name.
    for shape in &SHAPES {
        assert_eq!(selected(shape.name, LegMatch::Exact), [shape.name]);
    }
    // A leg that is not a prefix of anything reads the same in both forms.
    assert_eq!(
        selected("g/create/rar5/m0/pw", LegMatch::Substring),
        selected("g/create/rar5/m0/pw", LegMatch::Exact)
    );
}

#[test]
fn the_exact_form_takes_no_part_of_a_name() {
    assert!(selected("g/create/rar5/m", LegMatch::Exact).is_empty());
    assert!(selected("rar5/m0", LegMatch::Exact).is_empty());
    assert!(!selects(
        Some("g/create/rar5/m0"),
        LegMatch::Exact,
        "g/create/rar5/m0 "
    ));
}

#[test]
fn no_filter_selects_every_leg_in_either_form() {
    for shape in &SHAPES {
        assert!(selects(None, LegMatch::Substring, shape.name));
        assert!(selects(None, LegMatch::Exact, shape.name));
    }
}

/// The `code` legs sit under their level's text leg, so the
/// substring form of `g/create/rar5/m3` now runs `m3/code` in the same
/// process too, and a run that wants the text leg alone passes
/// `--exact`. Their same-binary partners are `g/detect/*`, named apart so
/// no `g/create` filter reaches them.
#[test]
fn the_code_legs_are_siblings_of_their_level_and_the_detect_legs_are_not() {
    for level in ["m1", "m3", "m5"] {
        let text = format!("g/create/rar5/{level}");
        let code = format!("g/create/rar5/{level}/code");
        let got = selected(&text, LegMatch::Substring);
        assert!(got.contains(&code.as_str()), "{text}: {got:?}");
        assert_eq!(selected(&code, LegMatch::Exact), [code.as_str()]);
        assert_eq!(
            selected(&code, LegMatch::Substring),
            [code.as_str()],
            "{code} is a prefix of nothing"
        );
        assert!(!selects(
            Some("g/create"),
            LegMatch::Substring,
            &format!("g/detect/rar5/{level}/code")
        ));
    }
}
