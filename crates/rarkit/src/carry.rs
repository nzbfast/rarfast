//! Stage B port: the predecessor's items that are ours from birth (the provenance
//! census, CARRY) and the four clean-room outputs, one module per work
//! package of the originality plan's table 1.1. Not wired to the public
//! API yet; each package decides what to keep as it is built.
//!
//! Port-period allowances, each for a reason that ends when the package is
//! wired to the API: imports and macros whose only users are feature-gated
//! or not yet carried; carried `pub` items bounded by crate-private traits;
//! and `chunks_exact` with a constant size, which the predecessor's older
//! declared `rust-version` kept silent - moving those hot loops to
//! `as_chunks` is a measured change for the package's own work, not a
//! lint fix.
#![allow(unused_imports, unused_macros, private_bounds, private_interfaces)]
#![allow(clippy::chunks_exact_to_as_chunks)]
pub(crate) mod b_writers;
pub(crate) mod c_lz;
pub(crate) mod g_recovery;
pub(crate) mod h_ours;
pub(crate) mod wiring;
