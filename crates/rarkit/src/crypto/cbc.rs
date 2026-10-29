//! CBC mode over the `aes` block cipher, with the chaining loop on THIS
//! side of the crate boundary (spec K 2.1, and 7's cipher targets).
//!
//! The mode is the standard one and is unchanged by where it is written:
//! decryption is `P[i] = D(C[i]) ^ C[i-1]`, encryption is
//! `C[i] = E(P[i] ^ C[i-1])`, and `C[-1]` is the IV in both. The vectors
//! of `crypto::tests` and the oracle differentials hold it.
//!
//! WHY IT IS HERE AND NOT THE `cbc` CRATE. `cbc::Decryptor` drives the
//! block cipher one block at a time, and the leaves `aes`'s aarch64
//! backend reaches for a block's bytes are non-generic and carry no
//! `#[inline]`, so with the default link they are CALLS: without
//! link-time optimisation the mode crate pays one of them per 16-byte
//! block, with the block round-tripped through the stack. Handing the
//! block cipher a whole TILE of blocks in one call and doing the XOR
//! here leaves the rest of the loop where the optimiser can see it.
//! The tile was chosen on measured figures.

use std::sync::Arc;

use aes::cipher::consts::U16;
use aes::cipher::{Array, BlockCipherDecrypt, BlockCipherEncrypt};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Blocks handed to the block cipher in one call, and so the size of the
/// plaintext scratch beside the caller's buffer: 512 bytes, L1-resident
/// next to the tile it came from. Measured against 8, 16, 64, 128 and
/// 256 blocks on aarch64; the curve is flat from 32 up. On x86-64, 128 was
/// measured and DECLINED: it fed the `aes` crate's VAES backends where the
/// wide chain is off, but with `super::x86_dec` taking every VAES CPU's
/// runs from 4 KiB, and level on a Coffee Lake with AES-NI alone, it buys
/// nothing measured (the CBC tile rows).
pub(super) const TILE: usize = 32;

/// One CBC block.
type Block = Array<u8, U16>;

/// The fewest whole blocks worth splitting across two lanes.
///
/// Below it the scoped thread costs more than the half it takes away.
/// A spawn and a join on aarch64 macOS is tens of microseconds; one
/// block is a handful of nanoseconds, so the floor is set where the
/// half-run is worth a small multiple of the spawn rather than at the
/// point the two merely break even. 16384 blocks is 256 KiB of
/// ciphertext, and the read path's own chunk is 4 MiB, so every chunk of
/// a member large enough for [`super::super::read::extract`] to overlap
/// at all is far above it and only the member's short last chunk falls
/// back.
///
/// **It is an ARITHMETIC floor, not a measured one, and that is stated
/// rather than glossed.** A ladder over it would only move legs whose
/// buffers sit near 256 KiB, and the overlapped read path has none: its
/// chunk is `read::extract::STORED_COPY`, 4 MiB on the default policy,
/// sixteen times the floor. The ladder is
/// not done, and it waits on the first change that gives the split a caller whose
/// buffers are small enough for the floor to decide anything.
const TWO_LANE_FLOOR: usize = 16384;

/// The fewest bytes in one run for which the wide chain is worth
/// building. The x86-64 figures: its key schedule (FIPS 197 5.2 and the
/// AESIMC inversion) costs about 6,700 instructions, which is what
/// `k/rar5-hp/list20000` paid per HEADER when the chain was built eagerly
/// (+117 percent on that row, 28 Sep 2026); the crate's path is about 17
/// cycles a block and the wide one about 2, so a run of 256 blocks pays
/// the schedule back. A member whose runs never reach this stays on the
/// crate's path and pays nothing but 32 kept bytes. aarch64 takes the
/// same floor (10 Oct 2026): its wide chain saves about half the crate
/// path's cost a block, and the floor was not laddered there.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const WIDE_MIN_BYTES: usize = 4096;

/// ONE KEY'S DECRYPTION SCHEDULES: the block cipher's, and the wide form's
/// (`super::x86_dec`, or `super::armv8_dec` on aarch64) where there is one.
/// They hold no chaining state, so one of these serves every chain under
/// its key at once, by shared reference.
///
/// WHO OWNS IT AND WHEN IT IS WIPED. It is made once for a key and held
/// behind a shared handle. The key cache's slot holds the handle for as
/// long as the key is cached, and a member's chain made with
/// [`CbcDec::new_on`] holds another for as long as the member lasts: the
/// member BORROWS the schedules and has no copy of them to wipe. When the
/// last handle goes (the cache's slot on eviction or at the session's end,
/// or a member that outlived the slot), this is dropped, once, and both
/// schedules are wiped by their own drops: the `aes` crate's (its
/// `zeroize` feature, which the bound on [`Schedule::new`] holds it to)
/// and the wide chain's.
pub(crate) struct Schedule<C> {
    cipher: C,
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    wide: Option<super::wide_dec::Chain>,
}

impl<C: BlockCipherDecrypt<BlockSize = U16> + ZeroizeOnDrop> Schedule<C> {
    /// The schedules of `key` (16 or 32 bytes), whose block cipher is
    /// `cipher`, with the wide form made now where the machine has one:
    /// what the key cache holds for a key.
    pub(crate) fn new(cipher: C, key: &[u8]) -> Arc<Self> {
        debug_assert!(key.len() == 16 || key.len() == 32);
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let _ = key;
        #[cfg(feature = "test-support")]
        wiped::made();
        Arc::new(Schedule {
            cipher,
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            wide: super::wide_dec::Chain::new(key),
        })
    }
}

impl<C: BlockCipherDecrypt<BlockSize = U16>> Schedule<C> {
    /// Decrypt one run of whole blocks in place from `chain`, on the wide
    /// form where there is one and the crate's tile path otherwise, and
    /// answer the run's last ciphertext block ([`decrypt_run`]).
    #[inline]
    pub(crate) fn run(&self, chain: [u8; 16], buf: &mut [u8]) -> [u8; 16] {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        if let Some(wide) = self.wide.as_ref() {
            return wide.decrypt_run(chain, buf);
        }
        decrypt_run(&self.cipher, chain, buf)
    }
}

/// The count of the schedules' wipe: once for each [`Schedule`], when its
/// last handle goes. The wipe itself is the fields' own drops, which run
/// after this.
#[cfg(feature = "test-support")]
impl<C> Drop for Schedule<C> {
    fn drop(&mut self) {
        #[allow(unused_mut)]
        let mut bytes = std::mem::size_of::<C>();
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        if self.wide.is_some() {
            bytes += std::mem::size_of::<super::wide_dec::Chain>();
        }
        wiped::schedule(bytes);
    }
}

/// AES-CBC decryption, in place, many blocks per call.
///
/// A chain OWNS its chaining value, and the key [`CbcDec::new_with_key`]
/// gave it until that is taken; both are wiped when the chain ends. The
/// schedules it deciphers on are a [`Schedule`]'s, which it holds by a
/// shared handle and does not copy.
pub struct CbcDec<C> {
    /// The key's schedules: the key cache's for a chain made with
    /// [`CbcDec::new_on`], this chain's alone otherwise.
    sched: Arc<Schedule<C>>,
    /// The chaining value: the ciphertext block before the next one.
    chain: [u8; 16],
    /// The key [`CbcDec::new_with_key`] was given, kept until the first run
    /// long enough to build the wide chain from it, then taken; `None`
    /// from every other constructor and once taken.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    key: Option<(zeroize::Zeroizing<[u8; 32]>, usize)>,
}

/// A chain's end: its chaining value (the IV, then ciphertext) is wiped
/// here, and the kept key, where it was never taken, by its own drop. The
/// schedules are not this chain's to wipe unless it holds their last
/// handle ([`Schedule`]).
impl<C> Drop for CbcDec<C> {
    fn drop(&mut self) {
        self.chain.zeroize();
        #[cfg(feature = "test-support")]
        {
            #[allow(unused_mut)]
            let mut bytes = self.chain.len();
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            if self.key.is_some() {
                bytes += 32;
            }
            wiped::member(bytes);
        }
    }
}

/// What the chains here wipe when they end, COUNTED: the tests of the wipe
/// rule (spec K 7, zeroisation on drop) read these and never read memory
/// that has been freed. Each count is its thread's own, so a test reads
/// only the drops it made itself.
#[cfg(feature = "test-support")]
pub(crate) mod wiped {
    use std::cell::Cell;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Schedules made and schedules wiped by the whole process, on any
    /// thread: what a test that reads on several threads compares once
    /// the read has returned. A test binary with other chains alive
    /// beside its own reads its thread's counts instead.
    static MADE: AtomicU64 = AtomicU64::new(0);
    static WIPED: AtomicU64 = AtomicU64::new(0);

    /// A key's schedules were made.
    pub(crate) fn made() {
        MADE.fetch_add(1, Ordering::SeqCst);
    }

    /// Schedules the process has made, and schedules it has wiped.
    #[cfg_attr(not(feature = "bench-internals"), allow(dead_code))]
    pub(crate) fn totals() -> (u64, u64) {
        (MADE.load(Ordering::SeqCst), WIPED.load(Ordering::SeqCst))
    }

    thread_local! {
        static MEMBER_BYTES: Cell<u64> = const { Cell::new(0) };
        static SCHEDULES: Cell<u64> = const { Cell::new(0) };
        static SCHEDULE_BYTES: Cell<u64> = const { Cell::new(0) };
    }

    /// A key's schedules lost their last handle and wiped `bytes`.
    pub(crate) fn schedule(bytes: usize) {
        WIPED.fetch_add(1, Ordering::SeqCst);
        SCHEDULES.with(|c| c.set(c.get() + 1));
        SCHEDULE_BYTES.with(|c| c.set(c.get() + bytes as u64));
    }

    /// How many keys' schedules this thread has wiped, and their bytes.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn schedules() -> (u64, u64) {
        (SCHEDULES.with(Cell::get), SCHEDULE_BYTES.with(Cell::get))
    }

    /// A member's chain ended and wiped `bytes` of secret state of its own.
    pub(crate) fn member(bytes: usize) {
        MEMBER_BYTES.with(|c| c.set(c.get() + bytes as u64));
    }

    /// Bytes the member chains dropped on this thread have wiped.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn member_bytes() -> u64 {
        MEMBER_BYTES.with(Cell::get)
    }
}

/// Decrypt one run of whole blocks in place from `chain`, and answer the
/// run's LAST CIPHERTEXT BLOCK, which chains into whatever follows it.
///
/// Free of the `CbcDec` so that two runs of one buffer can be in flight
/// at once ([`CbcDec::decrypt_blocks_two_lane`]): the block cipher is
/// shared by reference and holds no chaining state, and each run's
/// plaintext scratch is its own.
///
/// A trailing partial block is left untouched, and a run with no whole
/// block at all answers the chain it was given, so a caller can hand on
/// the result without asking how many blocks there were.
pub(super) fn decrypt_run<C: BlockCipherDecrypt<BlockSize = U16>>(
    cipher: &C,
    chain: [u8; 16],
    buf: &mut [u8],
) -> [u8; 16] {
    let mut chain = chain;
    let mut scratch = [0u8; TILE * 16];
    for tile in buf.chunks_mut(TILE * 16) {
        let n = tile.len() / 16;
        if n == 0 {
            break;
        }
        {
            let src = Block::slice_as_chunks(&tile[..n * 16]).0;
            let dst = Block::slice_as_chunks_mut(&mut scratch[..n * 16]).0;
            cipher
                .decrypt_blocks_b2b(src, dst)
                .expect("one output block per input block");
        }
        let plain = scratch.as_chunks::<16>().0;
        let blocks = tile.as_chunks_mut::<16>().0;
        // The last ciphertext block of the tile chains into the next
        // one, and is read before the XOR below overwrites it.
        let next = blocks[n - 1];
        // Descending, so each block reads its predecessor's
        // ciphertext before that predecessor becomes plaintext.
        for i in (1..n).rev() {
            let p = u128::from_ne_bytes(plain[i]) ^ u128::from_ne_bytes(blocks[i - 1]);
            blocks[i] = p.to_ne_bytes();
        }
        let p = u128::from_ne_bytes(plain[0]) ^ u128::from_ne_bytes(chain);
        blocks[0] = p.to_ne_bytes();
        chain = next;
    }
    // Scratch held one tile of plaintext.
    scratch.fill(0);
    chain
}

impl<C: BlockCipherDecrypt<BlockSize = U16>> CbcDec<C> {
    /// A chain from `iv` under `cipher`, through the crate's block
    /// decryption alone: the reference form `super::tests` holds the wide
    /// one to, and what every shipped caller took before `new_with_key`.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn new(cipher: C, iv: [u8; 16]) -> Self {
        #[cfg(feature = "test-support")]
        wiped::made();
        CbcDec {
            sched: Arc::new(Schedule {
                cipher,
                #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
                wide: None,
            }),
            chain: iv,
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            key: None,
        }
    }

    /// A chain from `iv` on `sched`, a key's schedules made once
    /// ([`Schedule::new`], the key cache's): the member's own chain, which
    /// borrows them for as long as it lasts. Nothing is expanded, inverted
    /// or copied here but the IV.
    pub(crate) fn new_on(sched: &Arc<Schedule<C>>, iv: [u8; 16]) -> Self {
        CbcDec {
            sched: Arc::clone(sched),
            chain: iv,
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            key: None,
        }
    }

    /// A chain from `iv` under `cipher`, whose key is `key` (16 or 32
    /// bytes): on an x86-64 CPU with VAES the runs go through
    /// `super::x86_dec` from the first one of [`WIDE_MIN_BYTES`] on, on an
    /// aarch64 machine with the AES extension through `super::armv8_dec`
    /// likewise, and everywhere else this is [`CbcDec::new`].
    pub fn new_with_key(cipher: C, key: &[u8], iv: [u8; 16]) -> Self {
        debug_assert!(key.len() == 16 || key.len() == 32);
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        let key = {
            let mut kept = zeroize::Zeroizing::new([0u8; 32]);
            kept[..key.len()].copy_from_slice(key);
            Some((kept, key.len()))
        };
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let _ = key;
        #[cfg(feature = "test-support")]
        wiped::made();
        CbcDec {
            sched: Arc::new(Schedule {
                cipher,
                #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
                wide: None,
            }),
            chain: iv,
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            key,
        }
    }

    /// A chain from `iv` under `cipher`, with the wide form given: every
    /// run takes it from the first. `None` is [`CbcDec::new`], the crate's
    /// path alone, which is how the tests force the fallback of a machine
    /// without the instructions on one that has them.
    #[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
    pub(crate) fn new_with_wide(
        cipher: C,
        wide: Option<super::wide_dec::Chain>,
        iv: [u8; 16],
    ) -> Self {
        #[cfg(feature = "test-support")]
        wiped::made();
        CbcDec {
            sched: Arc::new(Schedule { cipher, wide }),
            chain: iv,
            key: None,
        }
    }

    /// Whether the chain's schedules have a wide form.
    #[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
    fn has_wide(&self) -> bool {
        self.sched.wide.is_some()
    }

    /// Build the wide chain on the first run of `len` bytes long enough
    /// to pay for its key schedule. The key is taken on that first attempt
    /// whether or not the CPU has a form, so a CPU without one asks once.
    ///
    /// Only a chain that kept a key has anything to build, and its
    /// schedules are its own alone ([`CbcDec::new_with_key`]) unless a
    /// copy made by [`CbcDec::share`] is still out, in which case the key
    /// stays kept and the next run asks again.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn build_wide(&mut self, len: usize) {
        if self.key.is_none() || len < WIDE_MIN_BYTES {
            return;
        }
        if let Some(sched) = Arc::get_mut(&mut self.sched) {
            if let Some((key, key_len)) = self.key.take() {
                if sched.wide.is_none() {
                    sched.wide = super::wide_dec::Chain::new(&key[..key_len]);
                }
            }
        }
    }

    /// Decrypt the whole blocks at the front of `buf`, in place. A
    /// trailing partial block is left untouched; callers either refuse
    /// one or carry it (see [`super::MemberDecryptor`]).
    pub fn decrypt_blocks(&mut self, buf: &mut [u8]) {
        // The wide form takes the whole run, the same blocks from
        // the same chain to the same last ciphertext block, which
        // `super::tests` holds block for block against the crates.
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        self.build_wide(buf.len());
        self.chain = self.sched.run(self.chain, buf);
    }

    /// The chaining value: the ciphertext block the next run chains from.
    #[cfg(feature = "parallel")]
    pub(crate) fn chain(&self) -> [u8; 16] {
        self.chain
    }

    /// Carry on from `chain`, the last ciphertext block of bytes deciphered
    /// elsewhere ([`CbcDec::run_from`]), as if this chain had deciphered
    /// them itself.
    #[cfg(feature = "parallel")]
    pub(crate) fn set_chain(&mut self, chain: [u8; 16]) {
        self.chain = chain;
    }

    /// Build whatever the runs of [`CbcDec::run_from`] will use, before
    /// they are shared: on x86-64 the wide chain for a run of `len` bytes,
    /// which [`CbcDec::decrypt_blocks`] would otherwise build on its first
    /// long run. It changes no byte of any output.
    #[cfg(feature = "parallel")]
    pub(crate) fn prepare(&mut self, len: usize) {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        self.build_wide(len);
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let _ = len;
    }

    /// A second chain on this chain's schedules as they stand, whatever
    /// [`CbcDec::prepare`] built included, for the threads that run pieces
    /// of it ([`CbcDec::run_from`]) and cannot borrow this one. It holds a
    /// handle on the same schedules and no copy of them, and no key: it
    /// builds nothing. Its chaining value is wiped when it ends, as this
    /// chain's is.
    #[cfg(feature = "parallel")]
    pub(crate) fn share(&self) -> Self {
        CbcDec {
            sched: Arc::clone(&self.sched),
            chain: self.chain,
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            key: None,
        }
    }

    /// Decrypt one run of whole blocks in place from `chain`, on a SHARED
    /// reference, and answer its last ciphertext block; this chain's own
    /// state is not read or moved.
    ///
    /// This is what lets a member be deciphered in pieces on several
    /// threads at once (`read::wide`): a piece of whole blocks needs its
    /// own ciphertext and the one block in front of it and nothing else,
    /// by the arithmetic [`CbcDec::decrypt_blocks_two_lane`] argues. Each
    /// run is exactly the tile loop [`CbcDec::decrypt_blocks`] runs, from
    /// the chaining value it would have reached there, so the bytes are
    /// the same. A trailing partial block is left untouched.
    #[cfg(feature = "parallel")]
    pub(crate) fn run_from(&self, chain: [u8; 16], buf: &mut [u8]) -> [u8; 16] {
        self.sched.run(chain, buf)
    }

    /// The same bytes, with the buffer's whole blocks split across TWO
    /// lanes: the calling thread and one scoped thread.
    ///
    /// **Why the mode allows it at all.** CBC DECRYPTION is parallel by
    /// construction, where CBC encryption is not: the plaintext of block
    /// `i` is `D(C[i]) ^ C[i-1]`, so a run of blocks needs only its own
    /// ciphertext and the ONE ciphertext block in front of it. The
    /// second lane's chaining value is therefore knowable before the
    /// first lane has done anything, and it is taken out of the buffer
    /// here, BEFORE the first lane overwrites that block with its
    /// plaintext. Nothing is speculated and nothing is recomputed.
    ///
    /// **The bytes are identical to [`decrypt_blocks`](Self::decrypt_blocks),**
    /// which is not a claim about the schedule but about the arithmetic:
    /// each lane runs exactly the tile loop the serial form runs, from
    /// exactly the chaining value the serial form would have reached at
    /// that block, so the two differ in no byte and in no final chain.
    /// `super::tests` pins that against the serial form at every length,
    /// and the lane boundary is walked across a tile boundary on purpose.
    ///
    /// **No pool, and a bounded thread.** One scoped thread, joined
    /// before this returns, taken for the length of one buffer. The
    /// engine creates no pool and reads no thread count from the
    /// environment (SPEC-API 8.3); the caller that turns this on is
    /// `read::extract::copy_overlapped`, which runs only where
    /// `overlap_plan` already found a width unit to spend.
    ///
    /// A buffer under [`TWO_LANE_FLOOR`] whole blocks runs serially
    /// instead, the spawn being worth more than the half it saves.
    pub fn decrypt_blocks_two_lane(&mut self, buf: &mut [u8])
    where
        C: Sync,
    {
        let blocks = buf.len() / 16;
        if blocks < TWO_LANE_FLOOR {
            self.decrypt_blocks(buf);
            return;
        }
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        self.build_wide(buf.len());
        // Block aligned, and both lanes are non-empty because the floor
        // is far above two.
        let split = (blocks / 2) * 16;
        let (first, second) = buf.split_at_mut(split);
        // The second lane chains from the first lane's LAST CIPHERTEXT
        // BLOCK, read here while it is still ciphertext.
        let mut carry = [0u8; 16];
        carry.copy_from_slice(&first[split - 16..]);

        // Both lanes run on the one schedule, by shared reference.
        let sched = &*self.sched;
        let chain = self.chain;
        // The second lane's own end chain is the whole buffer's, the
        // second lane holding the buffer's last whole block.
        // A second lane the host will not start (`crate::threads`) runs on
        // this thread after the first: `carry` was read before either half
        // was deciphered, so the chaining is the same either way.
        let tail = std::thread::scope(|scope| {
            let lane =
                crate::threads::scoped_with(scope, second, move |second| sched.run(carry, second));
            sched.run(chain, first);
            match lane {
                Ok(lane) => lane.join(),
                Err(second) => Ok(sched.run(carry, second)),
            }
        });
        match tail {
            Ok(chain) => self.chain = chain,
            // A lane that panicked decrypted an unknown prefix of its
            // half, so there is no state to carry on from: re-raise
            // rather than return bytes of two arrangements.
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }
}

/// Encrypt one run of whole blocks in place from `chain` under a SHARED
/// block cipher, and answer the run's last ciphertext block: the loop
/// [`CbcEnc::encrypt_blocks`] runs, free of the `CbcEnc` so that a key
/// schedule expanded once can serve many short chains (every encrypted
/// header of an archive, spec K 3.6.3 and 3.7.5) without a copy. A
/// trailing partial block is left untouched.
pub(super) fn encrypt_run<C: BlockCipherEncrypt<BlockSize = U16>>(
    cipher: &C,
    chain: [u8; 16],
    buf: &mut [u8],
) -> [u8; 16] {
    let mut chain = chain;
    for block in Block::slice_as_chunks_mut(buf).0 {
        let x = u128::from_ne_bytes(*block.as_ref()) ^ u128::from_ne_bytes(chain);
        *block = Block::from(x.to_ne_bytes());
        cipher.encrypt_block(block);
        chain = *block.as_ref();
    }
    chain
}

/// AES-CBC encryption, in place.
///
/// The chain is serial by definition, so there is no batch to hand the
/// block cipher; what this saves against `cbc::Encryptor` is the mode
/// crate's own per-block machinery around the same call.
pub struct CbcEnc<C> {
    cipher: C,
    chain: [u8; 16],
}

impl<C: BlockCipherEncrypt<BlockSize = U16>> CbcEnc<C> {
    /// A chain from `iv` under `cipher`.
    pub fn new(cipher: C, iv: [u8; 16]) -> Self {
        CbcEnc { cipher, chain: iv }
    }

    /// Start a fresh chain from `iv` under the same cipher.
    pub fn restart(&mut self, iv: [u8; 16]) {
        self.chain = iv;
    }

    /// Encrypt the whole blocks at the front of `buf`, in place. A
    /// trailing partial block is left untouched; every caller here
    /// refuses a length that is not a multiple of 16 first.
    pub fn encrypt_blocks(&mut self, buf: &mut [u8]) {
        self.chain = encrypt_run(&self.cipher, self.chain, buf);
    }

    /// The same chain as [`encrypt_blocks`](Self::encrypt_blocks), reading
    /// the plaintext from `src` and writing the ciphertext to `dst`, so a
    /// caller whose plaintext is not its own to overwrite does not first
    /// copy it into the buffer it encrypts.
    ///
    /// **Why this costs the chain nothing.** CBC encryption is bound by the
    /// LATENCY of one block after another, and the plaintext load sits off
    /// that dependency: block `i`'s bytes can be read while block `i - 1`
    /// is still in the cipher. So the copy the caller no longer makes is
    /// taken out of the wall, not moved inside the loop. The bytes are
    /// [`encrypt_blocks`](Self::encrypt_blocks)'s on the same input, which
    /// `super::tests` holds against the `cbc` crate at every tile edge.
    ///
    /// Whole blocks only: `src` and `dst` are the same length, a multiple
    /// of 16, which the callers in `crypto` check before reaching here.
    pub fn encrypt_blocks_from(&mut self, src: &[u8], dst: &mut [u8]) {
        debug_assert_eq!(src.len(), dst.len());
        let mut chain = self.chain;
        let plain = src.as_chunks::<16>().0;
        for (plain, block) in plain.iter().zip(Block::slice_as_chunks_mut(dst).0) {
            let x = u128::from_ne_bytes(*plain) ^ u128::from_ne_bytes(chain);
            *block = Block::from(x.to_ne_bytes());
            self.cipher.encrypt_block(block);
            chain = *block.as_ref();
        }
        self.chain = chain;
    }
}

/// Which decryption path a member takes on x86-64 is decided by the CPU's
/// features and the run's length alone, and every path gives the same
/// bytes: the 512-bit VAES form with AES-NI, AVX-512F and VAES; the 256-bit
/// form with AES-NI, AVX2 and VAES; the crate's chain in [`TILE`]-block
/// calls otherwise, and for any run below [`WIDE_MIN_BYTES`] before the
/// wide chain is built.
///
/// On aarch64 (since 10 Oct 2026) the same holds with one wide form,
/// `super::armv8_dec`, where the machine has the AES extension, and the
/// module runs there too under the name it was given on x86-64.
#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
mod x86_dispatch_tests {
    #[cfg(target_arch = "x86_64")]
    use super::super::x86_dec::{self, Form};
    use super::*;
    use aes::cipher::{BlockModeDecrypt, KeyInit, KeyIvInit};

    fn noise(n: usize, seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    /// The `cbc` crate over the `aes` crate: the reference.
    fn reference(key: &[u8], iv: [u8; 16], buf: &mut [u8]) {
        let whole = buf.len() / 16 * 16;
        let buf = &mut buf[..whole];
        if key.len() == 32 {
            ::cbc::Decryptor::<aes::Aes256>::new_from_slices(key, &iv)
                .expect("a 32-byte key")
                .decrypt_blocks(Array::slice_as_chunks_mut(buf).0);
        } else {
            ::cbc::Decryptor::<aes::Aes128>::new_from_slices(key, &iv)
                .expect("a 16-byte key")
                .decrypt_blocks(Array::slice_as_chunks_mut(buf).0);
        }
    }

    /// The form detection must choose, from the features alone.
    #[cfg(target_arch = "x86_64")]
    fn expected_form() -> Option<Form> {
        let aes = is_x86_feature_detected!("aes");
        let vaes = is_x86_feature_detected!("vaes");
        if aes && vaes && is_x86_feature_detected!("avx512f") {
            Some(Form::Zmm8)
        } else if aes && vaes && is_x86_feature_detected!("avx2") {
            Some(Form::Ymm4)
        } else {
            None
        }
    }

    /// Detection picks the widest form the features allow and none without
    /// VAES, and a chain built with its key takes that form once a run
    /// reaches [`WIDE_MIN_BYTES`] and not before.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_path_is_chosen_by_the_cpus_features() {
        let want = expected_form();
        eprintln!("this CPU's decrypt path: {want:?} (None is the {TILE}-block crate tile)");
        // The knob can name another form in a count; detection is what ships.
        #[cfg(not(feature = "x86-wide-knob"))]
        assert_eq!(x86_dec::form(), want);
        let key = noise(32, 1);
        let mut dec =
            CbcDec::new_with_key(aes::Aes256Dec::new_from_slice(&key).unwrap(), &key, [0; 16]);
        let mut short = vec![0u8; WIDE_MIN_BYTES - 16];
        dec.decrypt_blocks(&mut short);
        assert!(
            !dec.has_wide(),
            "no wide chain before a run of WIDE_MIN_BYTES"
        );
        let mut long = vec![0u8; WIDE_MIN_BYTES];
        dec.decrypt_blocks(&mut long);
        assert_eq!(dec.has_wide(), x86_dec::form().is_some());
        let mut plain = CbcDec::new(aes::Aes256Dec::new_from_slice(&key).unwrap(), [0; 16]);
        plain.decrypt_blocks(&mut long);
        assert!(!plain.has_wide(), "CbcDec::new never takes a wide form");
    }

    /// On aarch64 the wide chain is taken where the machine has the AES
    /// extension and nowhere else, by a chain built with its key once a
    /// run reaches [`WIDE_MIN_BYTES`] and not before.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn the_path_is_chosen_by_the_cpus_features() {
        let want = std::arch::is_aarch64_feature_detected!("aes");
        eprintln!("this CPU's decrypt path: wide {want} (false is the {TILE}-block crate tile)");
        let key = noise(32, 1);
        let mut dec =
            CbcDec::new_with_key(aes::Aes256Dec::new_from_slice(&key).unwrap(), &key, [0; 16]);
        let mut short = vec![0u8; WIDE_MIN_BYTES - 16];
        dec.decrypt_blocks(&mut short);
        assert!(
            !dec.has_wide(),
            "no wide chain before a run of WIDE_MIN_BYTES"
        );
        let mut long = vec![0u8; WIDE_MIN_BYTES];
        dec.decrypt_blocks(&mut long);
        assert_eq!(dec.has_wide(), want);
        let mut plain = CbcDec::new(aes::Aes256Dec::new_from_slice(&key).unwrap(), [0; 16]);
        plain.decrypt_blocks(&mut long);
        assert!(!plain.has_wide(), "CbcDec::new never takes a wide form");
    }

    /// THE FALLBACK, FORCED. A machine without the instructions gives the
    /// key cache no wide chain (`Chain::new` answers `None`), and a member
    /// then starts from `CbcDec::new_with_wide(cipher, None, iv)`: built
    /// here by hand on a machine that HAS them, it must take the crate's
    /// tile path for runs of any length, never build a wide chain, and
    /// give the reference bytes, whole, split and two-lane.
    #[test]
    fn the_forced_fallback_is_the_crates_path_and_gives_the_reference_bytes() {
        let wide_blocks = WIDE_MIN_BYTES / 16;
        let data = noise(16 * (TWO_LANE_FLOOR + 4 * TILE), 41);
        for key_len in [32usize, 16] {
            let key = noise(key_len, 100 + key_len as u64);
            let iv: [u8; 16] = noise(16, 9).try_into().unwrap();
            for blocks in [
                0,
                1,
                TILE,
                TILE + 1,
                wide_blocks - 1,
                wide_blocks,
                3 * wide_blocks + 5,
                TWO_LANE_FLOOR + 3 * TILE + 7,
            ] {
                let n = 16 * blocks;
                let mut want = data[..n].to_vec();
                reference(&key, iv, &mut want);
                let cut = (n / 2) & !15;
                if key_len == 32 {
                    let c = aes::Aes256Dec::new_from_slice(&key).unwrap();
                    let mut d = CbcDec::new_with_wide(c.clone(), None, iv);
                    let mut got = data[..n].to_vec();
                    d.decrypt_blocks(&mut got[..cut]);
                    d.decrypt_blocks(&mut got[cut..]);
                    assert!(!d.has_wide(), "the forced fallback built a wide chain");
                    assert_eq!(got, want, "fallback, key 32, {blocks} blocks");
                    let mut d = CbcDec::new_with_wide(c, None, iv);
                    let mut got = data[..n].to_vec();
                    d.decrypt_blocks_two_lane(&mut got);
                    assert!(!d.has_wide());
                    assert_eq!(got, want, "fallback two lane, key 32, {blocks} blocks");
                } else {
                    let c = aes::Aes128Dec::new_from_slice(&key).unwrap();
                    let mut d = CbcDec::new_with_wide(c.clone(), None, iv);
                    let mut got = data[..n].to_vec();
                    d.decrypt_blocks(&mut got[..cut]);
                    d.decrypt_blocks(&mut got[cut..]);
                    assert!(!d.has_wide(), "the forced fallback built a wide chain");
                    assert_eq!(got, want, "fallback, key 16, {blocks} blocks");
                    let mut d = CbcDec::new_with_wide(c, None, iv);
                    let mut got = data[..n].to_vec();
                    d.decrypt_blocks_two_lane(&mut got);
                    assert!(!d.has_wide());
                    assert_eq!(got, want, "fallback two lane, key 16, {blocks} blocks");
                }
            }
        }
    }

    /// Every path against the reference, both key sizes, at every length
    /// that puts a [`TILE`] edge or the [`WIDE_MIN_BYTES`] edge inside a
    /// run, whole and split across that edge, with a partial trailing
    /// block, and two-lane: the crate tile path (`CbcDec::new`), the path
    /// this CPU dispatches to (`CbcDec::new_with_key`), and each wide form
    /// the CPU has, built by hand.
    #[test]
    fn every_path_gives_the_reference_bytes() {
        let wide_blocks = WIDE_MIN_BYTES / 16;
        let mut lengths = vec![1, 2, TILE - 1, TILE, TILE + 1, 2 * TILE, 2 * TILE + 1];
        lengths.extend([
            wide_blocks - 1,
            wide_blocks,
            wide_blocks + 1,
            3 * wide_blocks + 5,
        ]);
        lengths.extend([TWO_LANE_FLOOR + 3 * TILE + 7]);
        let data = noise(16 * (TWO_LANE_FLOOR + 4 * TILE) + 5, 99);
        for key_len in [32usize, 16] {
            let key = noise(key_len, key_len as u64);
            let iv: [u8; 16] = noise(16, 7).try_into().unwrap();
            for &blocks in &lengths {
                for extra in [0usize, 5] {
                    let n = 16 * blocks + extra;
                    let src = &data[..n];
                    let mut want = src.to_vec();
                    reference(&key, iv, &mut want);
                    // The crate tile path, whole.
                    let mut got = src.to_vec();
                    decrypt_with(&key, iv, false, &mut got, &[n]);
                    assert_eq!(
                        got, want,
                        "tile path, key {key_len}, {blocks} blocks + {extra}"
                    );
                    // The dispatched path, whole, and split across the wide edge.
                    for cuts in [
                        vec![n],
                        vec![(16 * blocks / 2) & !15, n],
                        vec![WIDE_MIN_BYTES - 16, n],
                    ] {
                        let mut got = src.to_vec();
                        decrypt_with(&key, iv, true, &mut got, &cuts);
                        assert_eq!(
                            got, want,
                            "dispatched, key {key_len}, {blocks} blocks + {extra}, cuts {cuts:?}"
                        );
                    }
                    // Two lanes, both constructors.
                    for keyed in [false, true] {
                        let mut got = src.to_vec();
                        let whole = n / 16 * 16;
                        if key_len == 32 {
                            let c = aes::Aes256Dec::new_from_slice(&key).unwrap();
                            let mut d = if keyed {
                                CbcDec::new_with_key(c, &key, iv)
                            } else {
                                CbcDec::new(c, iv)
                            };
                            d.decrypt_blocks_two_lane(&mut got[..whole]);
                        } else {
                            let c = aes::Aes128Dec::new_from_slice(&key).unwrap();
                            let mut d = if keyed {
                                CbcDec::new_with_key(c, &key, iv)
                            } else {
                                CbcDec::new(c, iv)
                            };
                            d.decrypt_blocks_two_lane(&mut got[..whole]);
                        }
                        assert_eq!(
                            got, want,
                            "two lane keyed {keyed}, key {key_len}, {blocks} blocks + {extra}"
                        );
                    }
                }
            }
        }
    }

    /// Decrypt `buf` in place in pieces ending at each of `cuts` (ascending,
    /// the last `buf.len()`, whole blocks until the last), through
    /// `CbcDec::new_with_key` where `keyed`, `CbcDec::new` otherwise.
    fn decrypt_with(key: &[u8], iv: [u8; 16], keyed: bool, buf: &mut [u8], cuts: &[usize]) {
        fn go<C: BlockCipherDecrypt<BlockSize = U16>>(
            mut d: CbcDec<C>,
            buf: &mut [u8],
            cuts: &[usize],
        ) {
            let mut at = 0;
            for &cut in cuts {
                let cut = cut.max(at).min(buf.len());
                d.decrypt_blocks(&mut buf[at..cut]);
                at = cut;
            }
        }
        if key.len() == 32 {
            let c = aes::Aes256Dec::new_from_slice(key).unwrap();
            go(
                if keyed {
                    CbcDec::new_with_key(c, key, iv)
                } else {
                    CbcDec::new(c, iv)
                },
                buf,
                cuts,
            );
        } else {
            let c = aes::Aes128Dec::new_from_slice(key).unwrap();
            go(
                if keyed {
                    CbcDec::new_with_key(c, key, iv)
                } else {
                    CbcDec::new(c, iv)
                },
                buf,
                cuts,
            );
        }
    }
}
