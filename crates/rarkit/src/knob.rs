//! The environment's tuning words, read only by a build that asks for
//! them.
//!
//! A shipped build reads no environment word of its own: what it writes
//! and the route it takes are the caller's options and the input's, never
//! the shell's. Every dial that was once a word any build read goes
//! through this module. Under the feature `reader-knobs` (the reading
//! side's routes, widths and memory) or `writer-knobs` (the writing
//! side's) the word is read as it always was; without the feature the
//! answer is "not set", so each dial takes exactly the default it took
//! with the word unset, and nothing of the environment reaches it.

use std::env::VarError;
use std::ffi::OsString;

/// A reading side word, as `std::env::var` gives it.
#[cfg(feature = "reader-knobs")]
pub(crate) fn reader_var(name: &str) -> Result<String, VarError> {
    std::env::var(name)
}

/// A reading side word: not set, in a build without `reader-knobs`.
#[cfg(not(feature = "reader-knobs"))]
#[inline(always)]
pub(crate) fn reader_var(_name: &str) -> Result<String, VarError> {
    Err(VarError::NotPresent)
}

/// A reading side word, as `std::env::var_os` gives it.
#[cfg(feature = "reader-knobs")]
pub(crate) fn reader_var_os(name: &str) -> Option<OsString> {
    std::env::var_os(name)
}

/// A reading side word: not set, in a build without `reader-knobs`.
#[cfg(not(feature = "reader-knobs"))]
#[inline(always)]
pub(crate) fn reader_var_os(_name: &str) -> Option<OsString> {
    None
}

/// A writing side word, as `std::env::var` gives it.
#[cfg(feature = "writer-knobs")]
pub(crate) fn writer_var(name: &str) -> Result<String, VarError> {
    std::env::var(name)
}

/// A writing side word: not set, in a build without `writer-knobs`.
#[cfg(not(feature = "writer-knobs"))]
#[inline(always)]
pub(crate) fn writer_var(_name: &str) -> Result<String, VarError> {
    Err(VarError::NotPresent)
}
