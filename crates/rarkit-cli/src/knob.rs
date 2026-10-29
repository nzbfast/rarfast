//! The environment's tuning words, read only by a build that asks for
//! them.
//!
//! A shipped `rarfast` reads no environment word of its own: the archive
//! it writes and the route it takes are the command line's and the
//! input's, never the shell's. Every option the dialects have no switch
//! for goes through this module. Under the feature `writer-knobs` (the
//! create path's options) or `reader-knobs` (the read path's routes,
//! widths and memory) the word is read as it always was; without the
//! feature the answer is "not set", so each option takes exactly the
//! default it took with the word unset, and nothing of the environment
//! reaches it. The engine's own words go the same way (`rarkit::knob`,
//! under its features of the same names, which these turn on).

use std::env::VarError;
use std::ffi::OsString;

/// A read path word, as `std::env::var` gives it.
#[cfg(feature = "reader-knobs")]
pub(crate) fn reader_var(name: &str) -> Result<String, VarError> {
    std::env::var(name)
}

/// A read path word: not set, in a build without `reader-knobs`.
#[cfg(not(feature = "reader-knobs"))]
#[inline(always)]
pub(crate) fn reader_var(_name: &str) -> Result<String, VarError> {
    Err(VarError::NotPresent)
}

/// A create path word, as `std::env::var` gives it.
#[cfg(feature = "writer-knobs")]
pub(crate) fn writer_var(name: &str) -> Result<String, VarError> {
    std::env::var(name)
}

/// A create path word: not set, in a build without `writer-knobs`.
#[cfg(not(feature = "writer-knobs"))]
#[inline(always)]
pub(crate) fn writer_var(_name: &str) -> Result<String, VarError> {
    Err(VarError::NotPresent)
}

/// A create path word, as `std::env::var_os` gives it.
#[cfg(feature = "writer-knobs")]
pub(crate) fn writer_var_os(name: &str) -> Option<OsString> {
    std::env::var_os(name)
}

/// A create path word: not set, in a build without `writer-knobs`.
#[cfg(not(feature = "writer-knobs"))]
#[inline(always)]
pub(crate) fn writer_var_os(_name: &str) -> Option<OsString> {
    None
}
