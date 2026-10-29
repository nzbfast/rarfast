//! Seeded bytes for the input builders behind `bench-internals`.
//!
//! The fuzz and bench input builders in this crate (`internals_h`'s
//! window edge input, `rar3_lz`'s literal burst and its ladder) need a
//! run of bytes that depends on a seed and on nothing else, and that a
//! compressor can do nothing with. The tests' shared makers live in a
//! crate of their own that this one never links outside its tests, so
//! these builders keep this one small source to themselves.

/// A seeded run of bytes that do not compress.
///
/// A 64 bit linear congruential generator (the multiplier and increment
/// are Knuth's for MMIX, TAOCP volume 2, 3.3.4) of which only the top
/// byte of each state is given out: the top bits of such a generator are
/// its best ones, and at a byte a step the period of 2^64 is far past
/// any input built here. Every seed is a good seed.
pub(crate) struct ByteRun {
    state: u64,
}

impl ByteRun {
    /// A run that depends on nothing but `seed`.
    pub(crate) fn new(seed: u32) -> Self {
        let mut run = Self {
            state: u64::from(seed),
        };
        // One step, so two seeds that differ in a low bit part at once.
        run.byte();
        run
    }

    /// The next byte of the run.
    pub(crate) fn byte(&mut self) -> u8 {
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.state >> 56) as u8
    }
}
