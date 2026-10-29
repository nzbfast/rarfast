//! Carried from the predecessor's `rar50/write/mod.rs` at an earlier revision: items ours from birth
//! per the provenance census (and clean-room outputs, clean by provenance).

/// The RAR 5.0 dictionary's floor and quantum: a v0 dictionary is a
/// power-of-two multiple of this.
pub(crate) const RAR50_DICTIONARY_QUANTUM: u64 = 128 * 1024;
/// What `fitted_dictionary_size` fits to: the largest member of a
/// non-solid set, the whole set of a solid one (its window spans them).
pub(crate) fn largest_payload(sizes: impl Iterator<Item = u64>, solid: bool) -> u64 {
    if solid {
        sizes.fold(0u64, u64::saturating_add)
    } else {
        sizes.max().unwrap_or(0)
    }
}

pub(crate) mod reference;
