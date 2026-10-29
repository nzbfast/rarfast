//! Which legs a `two_arm` positional filter selects, and how.
//!
//! The filter has always been a SUBSTRING of the leg's name, and that
//! stays the default so no bench script that already names a leg
//! changes meaning. But a leg whose name is a prefix of other legs'
//! names cannot be selected alone that way: `g/create/rar5/m0` is inside
//! all six `g/create/rar5/m0/*` names, so every one of its processes also
//! ran those six legs at its own calibrated rounds, and the process's
//! peak RSS was theirs rather than its own (found
//! 23 Sep 2026). `--exact` asks for the name and nothing
//! longer.
//!
//! It lives here, beside the other sources `two_arm` compiles in by
//! `#[path]`, so `tests/leg_select.rs` can pin both forms against the real
//! create leg names: a bench target is not run by `cargo test`.

#![allow(dead_code)]

/// The flag that asks for the exact form.
pub const EXACT_FLAG: &str = "--exact";

/// How a positional filter is matched against a leg's name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegMatch {
    /// The filter appears anywhere in the name. The default.
    Substring,
    /// The filter IS the name.
    Exact,
}

impl LegMatch {
    /// `Exact` when the arguments carry `--exact`, `Substring` otherwise.
    pub fn from_args<S: AsRef<str>>(args: &[S]) -> Self {
        if args.iter().any(|a| a.as_ref() == EXACT_FLAG) {
            LegMatch::Exact
        } else {
            LegMatch::Substring
        }
    }

    /// The word a run prints for this form.
    pub fn label(self) -> &'static str {
        match self {
            LegMatch::Substring => "substring",
            LegMatch::Exact => "exact",
        }
    }
}

/// Whether the leg called `name` runs under `filter`. No filter selects
/// every leg in either form.
pub fn selects(filter: Option<&str>, how: LegMatch, name: &str) -> bool {
    match (filter, how) {
        (None, _) => true,
        (Some(f), LegMatch::Substring) => name.contains(f),
        (Some(f), LegMatch::Exact) => name == f,
    }
}
