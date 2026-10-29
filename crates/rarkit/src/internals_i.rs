//! Spec I entry points for this repository's tests, benches and fuzz
//! targets, behind the `bench-internals` feature. Not part of the API; no
//! shipped build enables it.
//!
//! Spec H's RAR 3 LZ decoder does not exist yet, so the window and the
//! stream driving below stand in for it on members that are PPM from their
//! first block. They are test scaffolding, not spec H's answer.

use crate::ppmd::{MemoryBudget, PpmDecoder, PpmStep, StreamBytes, StreamWindow};
use crate::{Corruption, Error, ErrorKind, Result, Unsupported};

pub use crate::error::PpmFault;

/// A byte source over one member's packed data, counting what it reads.
pub struct Packed<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Packed<'a> {
    /// Read `bytes` from the start.
    pub fn new(bytes: &'a [u8]) -> Packed<'a> {
        Packed { bytes, at: 0 }
    }

    /// How many bytes the decoder has taken.
    pub fn read(&self) -> usize {
        self.at
    }
}

impl StreamBytes for Packed<'_> {
    fn next_byte(&mut self) -> Result<u8> {
        match self.bytes.get(self.at) {
            Some(&b) => {
                self.at += 1;
                Ok(b)
            }
            None => Err(Error::new(ErrorKind::Truncated)),
        }
    }
}

/// The output side spec H will own: one buffer per solid stream, with the
/// whole stream kept so a match can reach back into an earlier member.
#[derive(Default)]
pub struct Window {
    out: Vec<u8>,
}

impl Window {
    /// An empty window.
    pub fn new() -> Window {
        Window::default()
    }

    /// Everything the stream has produced.
    pub fn bytes(&self) -> &[u8] {
        &self.out
    }

    /// How many bytes the stream has produced.
    pub fn len(&self) -> usize {
        self.out.len()
    }

    /// Whether nothing has been produced yet.
    pub fn is_empty(&self) -> bool {
        self.out.is_empty()
    }

    /// Start a new stream, keeping the buffer.
    pub fn clear(&mut self) {
        self.out.clear();
    }
}

impl StreamWindow for Window {
    fn put(&mut self, byte: u8) -> Result<()> {
        self.out.push(byte);
        Ok(())
    }

    fn copy(&mut self, distance: u32, length: u32) -> Result<()> {
        let distance = distance as usize;
        if distance == 0 || distance > self.out.len() {
            return Err(Error::new(ErrorKind::Corrupt(Corruption::Stream)));
        }
        for _ in 0..length {
            let byte = self.out[self.out.len() - distance];
            self.out.push(byte);
        }
        Ok(())
    }
}

/// One member of a run: its packed bytes and its declared unpacked size.
#[derive(Clone, Copy)]
pub struct MemberIn<'a> {
    /// The member's packed data, starting at its own block header.
    pub packed: &'a [u8],
    /// The size the member's header declares.
    pub unpacked: u64,
}

/// What one member decoded to.
pub struct MemberOut {
    /// The member's bytes.
    pub data: Vec<u8>,
    /// Packed bytes the decoder read, counting the block header. This is
    /// the vectors' `packed_read` column.
    pub packed_read: usize,
}

/// What a whole run decoded to.
pub struct RunOut {
    /// One entry per member, in order.
    pub members: Vec<MemberOut>,
    /// How many times the model started over the run.
    pub model_starts: u64,
    /// The largest `held_bytes` the decoder reported.
    pub peak_held: u64,
}

/// Decode a run of RAR 3 members whose data is PPM from its first block.
///
/// `solid` keeps one model, one escape byte and one window across the run,
/// which is what a solid archive means. A member that starts in LZ mode, or
/// a block that hands back to the LZ side, is spec H's and is refused here.
pub fn decode_ppm_run(members: &[MemberIn<'_>], solid: bool, working_limit: u64) -> Result<RunOut> {
    PpmRunner::new().run(members, solid, working_limit)
}

/// One decoder and one window, kept across runs. This is the shape a real
/// driver has: the arena is sized once and re-used (spec I 7.3 items 1 and
/// 2), never allocated per member or per archive.
#[derive(Default)]
pub struct PpmRunner {
    decoder: PpmDecoder,
    window: Window,
}

impl PpmRunner {
    /// A runner holding nothing yet.
    pub fn new() -> PpmRunner {
        PpmRunner::default()
    }

    /// Working memory the runner holds.
    pub fn held_bytes(&self) -> u64 {
        self.decoder.held_bytes()
    }

    /// Decode a run of RAR 3 members whose data is PPM from its first block.
    ///
    /// `solid` keeps one model, one escape byte and one window across the run,
    /// which is what a solid archive means. A member that starts in LZ mode, or
    /// a block that hands back to the LZ side, is spec H's and is refused here.
    pub fn run(
        &mut self,
        members: &[MemberIn<'_>],
        solid: bool,
        working_limit: u64,
    ) -> Result<RunOut> {
        let budget = MemoryBudget {
            working_limit,
            held_elsewhere: 0,
        };
        let owed = || Error::new(ErrorKind::Unsupported(Unsupported::WriteFeature("spec H")));
        let decoder = &mut self.decoder;
        let window = &mut self.window;
        decoder.reset_stream();
        window.clear();
        let starts_before = decoder.model_starts();
        let mut out = RunOut {
            members: Vec::new(),
            model_starts: 0,
            peak_held: 0,
        };
        for member in members {
            if !solid {
                // A non-solid member keeps the arena but starts its model
                // afresh from its own header (API 5.2).
                decoder.reset_stream();
                window.clear();
            }
            let base = window.len();
            let mut src = Packed::new(member.packed);
            let first = src.next_byte()?;
            if first & 0x80 == 0 {
                return Err(owed());
            }
            decoder.begin_block(first, &mut src, &budget)?;
            let mut room = member.unpacked;
            while room > 0 {
                match decoder.step(&mut src, window, room)? {
                    PpmStep::Produced(n) => room = room.saturating_sub(u64::from(n)),
                    PpmStep::EndOfBlock => {
                        let head = src.next_byte()?;
                        if head & 0x80 == 0 {
                            return Err(owed());
                        }
                        decoder.begin_block(head, &mut src, &budget)?;
                    }
                    PpmStep::EndOfMemberData => break,
                    PpmStep::FilterRecord { .. } => return Err(owed()),
                }
            }
            past_the_size(decoder, window, &budget, &mut src)?;
            out.peak_held = out.peak_held.max(decoder.held_bytes());
            // The member's output is its first declared bytes; what its
            // packed data produced after them stays in the window (spec I
            // 3.3, "Member end").
            let produced = &window.bytes()[base..];
            let declared = usize::try_from(member.unpacked).unwrap_or(usize::MAX);
            out.members.push(MemberOut {
                data: produced[..produced.len().min(declared)].to_vec(),
                packed_read: src.read(),
            });
        }
        out.model_starts = decoder.model_starts() - starts_before;
        Ok(out)
    }
}

/// Drive one START block from arbitrary bytes, for the `ppm_block` fuzz
/// target (spec I section 6). Returns the bytes produced and the largest
/// working memory the decoder reported.
pub fn fuzz_ppm_block(data: &[u8], cap: u64) -> FuzzRun {
    let none = FuzzRun {
        produced: 0,
        held: 0,
        model_size: 0,
    };
    let Some((&order, rest)) = data.split_first() else {
        return none;
    };
    let Some((&memory, rest)) = rest.split_first() else {
        return none;
    };
    // A START header: order code from the input, memory clamped to 1 to
    // 4 MiB so a run stays fast, and an escape byte of 2.
    let head = 0x80 | 0x20 | (order & 0x1f);
    let mut packed = Vec::with_capacity(rest.len() + 2);
    packed.push(memory & 3);
    packed.extend_from_slice(rest);
    let mut src = Packed::new(&packed);
    let mut window = Window::new();
    let mut decoder = PpmDecoder::new();
    let budget = MemoryBudget {
        working_limit: u64::MAX,
        held_elsewhere: 0,
    };
    let model_size = (u64::from(memory & 3) + 1) << 20;
    if decoder.begin_block(head, &mut src, &budget).is_err() {
        return FuzzRun {
            produced: 0,
            held: decoder.held_bytes(),
            model_size,
        };
    }
    let mut made = 0u64;
    while made < cap {
        match decoder.step(&mut src, &mut window, cap - made) {
            Ok(PpmStep::Produced(n)) => made += u64::from(n),
            Ok(PpmStep::EndOfBlock) | Ok(PpmStep::EndOfMemberData) => break,
            Ok(PpmStep::FilterRecord { .. }) => {}
            Err(_) => break,
        }
        // The window is the fuzzer's only unbounded cost; drop it when it
        // grows past what a match can reach back over.
        if window.len() > (1 << 22) + (1 << 16) {
            break;
        }
    }
    FuzzRun {
        produced: made,
        held: decoder.held_bytes(),
        model_size,
    }
}

/// What one fuzz run did.
pub struct FuzzRun {
    /// Bytes the decoder wrote to the window.
    pub produced: u64,
    /// Working memory the decoder held at the end.
    pub held: u64,
    /// The model size the synthetic header signalled.
    pub model_size: u64,
}

/// Drive a solid run of members end to end from fuzzed bytes, for the
/// `ppm_member` fuzz target: a START header, a declared unpacked size taken
/// from the input, the member-end check (spec I 3.3), and then the NEXT
/// member on the same decoder whether or not this one faulted.
///
/// Carrying on past a member's fault is the point, and is what spec F's
/// `extract` does: a solid archive whose third member fails reports it and
/// opens the fourth with the model, the escape byte and the range decoder
/// exactly as the fault left them. A decoder that answers untrusted bytes
/// with an error but leaves itself half-narrowed will panic there and not
/// where the damage was. That is what the divide-by-zero of 20 Sep 2026
/// did, and why one member alone never found it.
///
/// Spec F's whole container is still to do here: this is the member path
/// with the same hand-over, not `extract` itself.
///
/// Returns the bytes the run produced.
pub fn fuzz_ppm_member(data: &[u8]) -> Result<u64> {
    let Some((&declared, rest)) = data.split_first() else {
        return Ok(0);
    };
    let Some((&memory, rest)) = rest.split_first() else {
        return Ok(0);
    };
    let Some((&split, rest)) = rest.split_first() else {
        return Ok(0);
    };
    let mut packed = Vec::with_capacity(rest.len() + 3);
    // order 8, a new model, an escape byte: the defaults rar writes.
    packed.push(0xE7);
    packed.push(memory & 3);
    packed.push(0xFF);
    packed.extend_from_slice(rest);
    let unpacked = u64::from(declared) * 37;

    // Members two and three continue the same model: a CONTINUE header
    // (bit 7 set, bit 5 clear) over the tail of the same bytes, cut where
    // the input says. They are driven even when member one failed.
    let cut = 3 + (usize::from(split) * 29) % (packed.len().max(4) - 3);
    let mut again = Vec::with_capacity(packed.len() - cut + 1);
    again.push(0x80u8);
    again.extend_from_slice(&packed[cut..]);
    let mut once_more = Vec::with_capacity(packed.len() + 1);
    once_more.push(0x80u8);
    once_more.extend_from_slice(&packed[3..]);
    let mut decoder = PpmDecoder::new();
    let mut window = Window::new();
    let budget = MemoryBudget {
        working_limit: u64::MAX,
        held_elsewhere: 0,
    };
    decoder.reset_stream();
    let mut produced = 0u64;
    let mut first_error = None;
    for member in [&packed[..], &again[..], &once_more[..]] {
        let before = window.len() as u64;
        if let Err(e) = drive_one(&mut decoder, &mut window, &budget, member, unpacked) {
            first_error.get_or_insert(e);
        }
        produced += window.len() as u64 - before;
        if window.len() > (1 << 22) + (1 << 16) {
            break;
        }
    }
    match first_error {
        Some(e) => Err(e),
        None => Ok(produced),
    }
}

/// One member of a solid run: the block header, the token loop and the
/// member end, on a decoder that keeps whatever the last member left.
fn drive_one(
    decoder: &mut PpmDecoder,
    window: &mut Window,
    budget: &MemoryBudget,
    packed: &[u8],
    unpacked: u64,
) -> Result<()> {
    let owed = || Error::new(ErrorKind::Unsupported(Unsupported::WriteFeature("spec H")));
    let mut src = Packed::new(packed);
    let first = src.next_byte()?;
    if first & 0x80 == 0 {
        return Err(owed());
    }
    decoder.begin_block(first, &mut src, budget)?;
    let mut room = unpacked;
    while room > 0 {
        match decoder.step(&mut src, window, room)? {
            PpmStep::Produced(n) => room = room.saturating_sub(u64::from(n)),
            PpmStep::EndOfBlock => {
                let head = src.next_byte()?;
                if head & 0x80 == 0 {
                    return Err(owed());
                }
                decoder.begin_block(head, &mut src, budget)?;
            }
            PpmStep::EndOfMemberData => break,
            PpmStep::FilterRecord { .. } => return Err(owed()),
        }
    }
    past_the_size(decoder, window, budget, &mut src)
}

/// A member's packed data from the point where its declared size has been
/// produced (spec I 3.3, "Member end"): token after token to escape code
/// 2, or to escape code 0 with nothing after it. A block that hands back
/// to the LZ side is spec H's and is refused here, as in [`Model::run`].
fn past_the_size(
    decoder: &mut PpmDecoder,
    window: &mut Window,
    budget: &MemoryBudget,
    src: &mut Packed<'_>,
) -> Result<()> {
    loop {
        match decoder.step_past_end(src, window)? {
            PpmStep::Produced(_) => {}
            PpmStep::EndOfMemberData => return Ok(()),
            PpmStep::EndOfBlock => {
                if src.at == src.bytes.len() {
                    return Ok(());
                }
                let head = src.next_byte()?;
                if head & 0x80 == 0 {
                    return Err(Error::new(ErrorKind::Unsupported(
                        Unsupported::WriteFeature("spec H"),
                    )));
                }
                decoder.begin_block_past_end(head, src, budget)?;
            }
            PpmStep::FilterRecord { .. } => {
                return Err(Error::new(ErrorKind::Unsupported(
                    Unsupported::WriteFeature("spec H"),
                )))
            }
        }
    }
}

/// Read one block header and stop (spec I 3.2), for the tests that
/// exercise the header's own refusals and its memory budget. `packed`
/// starts at the header byte. Returns the working memory the decoder then
/// holds.
pub fn begin_block_only(packed: &[u8], working_limit: u64, held_elsewhere: u64) -> Result<u64> {
    let budget = MemoryBudget {
        working_limit,
        held_elsewhere,
    };
    let mut src = Packed::new(packed);
    let mut decoder = PpmDecoder::new();
    let first = src.next_byte()?;
    decoder.begin_block(first, &mut src, &budget)?;
    Ok(decoder.held_bytes())
}

/// Time-probe helper: build a decoder and start a model, nothing more.
pub fn start_only(memory_byte: u8) -> u64 {
    let packed = [0xE7u8, memory_byte, 0xFF, 1, 2, 3, 4];
    begin_block_only(&packed, u64::MAX, 0).unwrap()
}
