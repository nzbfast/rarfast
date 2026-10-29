//! Module path only.

/// `many` is the predecessor's NEON four-lane leaf kernel and is aarch64
/// only by its own terms; the carry left every item of it out, so what
/// remains is that file's import list and nothing else. Ungated, those 21
/// `std::arch::aarch64` imports were 21 of the 22 errors that stopped
/// `rarkit` compiling for x86-64 at every commit on `main`
/// (18 Sep 2026). Gating the declaration is the
/// whole fix and leaves the module exactly where a later carry wants it.
#[cfg(target_arch = "aarch64")]
pub(crate) mod many;
pub(crate) mod simd;
