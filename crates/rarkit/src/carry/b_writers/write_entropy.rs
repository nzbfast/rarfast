//! Carried from the predecessor's `write_entropy.rs` at an earlier revision: items ours from birth
//! per the provenance census (and clean-room outputs, clean by provenance).

use std::cell::RefCell;
/// The seeded state, which unlike [`Entropy`] has to advance.
///
/// Each draw takes the next 32-byte block of `BLAKE2s(key = seed,
/// message = counter)`, so successive draws inside one archive differ -
/// the RAR 5 header IVs in particular must not repeat under one key -
/// while the sequence itself is fixed by the seed.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Seeded {
    pub(crate) seed: [u8; 32],
    pub(crate) counter: u64,
}
impl Seeded {
    pub(crate) fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(32) {
            let block = blake2s_simd::Params::new()
                .hash_length(32)
                .key(&self.seed)
                .hash(&self.counter.to_le_bytes());
            self.counter = self.counter.wrapping_add(1);
            chunk.copy_from_slice(&block.as_bytes()[..chunk.len()]);
        }
    }
}
thread_local! {
    /// The seeded source installed for the write running on this thread,
    /// if any. `None` - the state every thread starts in - means the
    /// draw sites call `getrandom::fill`, which is what they did before
    /// this module existed.
    static INSTALLED: RefCell<Option<Seeded>> = const { RefCell::new(None) };
}
