//! The RAR 2.0 LZ codec: unpack versions 20 and 26 (spec H3 part A).
//!
//! A RAR 2.0 stream is a chain of blocks, each either an LZ block or a
//! multimedia block, with no byte alignment anywhere and no end of block
//! field: the LZ alphabet's symbol 269 and the multimedia alphabet's symbol
//! 256 end a block, and a header follows at once.
//!
//! Three rules in here are the ones that are silent when they are wrong,
//! and each has a hand vector that pins it:
//!
//! - the code length alphabet has 19 symbols, not RAR 2.9's 20, and its
//!   repeat symbol reads 2 bits where RAR 2.9's reads 3 (section 3.2);
//! - the length bonus is ASYMMETRIC, with two distance thresholds on the
//!   fresh arm and three on the repeated arm, which is the opposite way
//!   round from RAR 5 (section 3.3);
//! - main symbol 256 pushes its distance onto the repeated distances,
//!   which RAR 2.9's symbol 258 does not;
//! - and the repeated distance arm pushes too, where RAR 2.9 rotates.
//!   That last one is an ERRATUM to the specification, measured against
//!   the fixtures and reference `unrar`: see `Rar20Lz::push_distance`.

pub(crate) mod audio;
pub(crate) mod bits;
#[cfg(feature = "audio-lane-ref")]
pub(crate) mod lane_ref;
pub(crate) mod table;
#[cfg(test)]
mod tests;
pub(crate) mod window;

use crate::carry::c_lz::codec::rar20::{HUFF20_LUT_BITS, LENGTH_SLOTS};
use crate::error::Rar20Fault;
use crate::{Corruption, Error, ErrorKind, Result};
use audio::{Model, MAX_CHANNELS};
use bits::BitSource;
use table::Table;
use window::Window;

/// Symbols in the code length alphabet. Nineteen, not RAR 2.9's twenty.
const LEVEL_SYMBOLS: usize = 19;
/// Symbols in the LZ main alphabet.
const MAIN_SYMBOLS: usize = 298;
/// Slots in the distance ladder: H1's first 48, so the largest distance is
/// the 1 MiB maximum RAR 2.0 dictionary.
const DISTANCE_SLOTS: usize = 48;
/// Slots in the short distance ladder.
const SHORT_SLOTS: usize = 8;
/// Symbols in one multimedia channel's alphabet: 256 residuals and the
/// block terminator.
const AUDIO_SYMBOLS: usize = 257;
/// Code lengths an LZ block reads: main, then distance, then length.
const LZ_LENGTHS: usize = MAIN_SYMBOLS + DISTANCE_SLOTS + LENGTH_SLOTS;
/// The stored code length array, wide enough for four multimedia
/// alphabets; an LZ block's lengths occupy its front.
const STORED_LENGTHS: usize = AUDIO_SYMBOLS * MAX_CHANNELS;
/// Repeated distances the stream remembers.
const REPEATS: usize = 4;

/// The length ladder, H1's, all 28 slots: the fresh arm adds 3 to the base
/// and the repeated arm 2.
const LENGTH_BASE: [u32; LENGTH_SLOTS] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128,
    160, 192, 224,
];
const LENGTH_EXTRA: [u8; LENGTH_SLOTS] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5,
];

/// The distance ladder, H1's first 48 slots. Every slot's extra bits are
/// read as plain bits: RAR 2.0 has no low distance alphabet.
const DISTANCE_BASE: [u32; DISTANCE_SLOTS] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
    2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608,
    262144, 327680, 393216, 458752, 524288, 589824, 655360, 720896, 786432, 851968, 917504, 983040,
];
const DISTANCE_EXTRA: [u8; DISTANCE_SLOTS] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
];

/// The short distance ladder, H1's: eight slots tiling 1 to 256.
const SHORT_BASE: [u32; SHORT_SLOTS] = [0, 4, 8, 16, 32, 64, 128, 192];
const SHORT_EXTRA: [u8; SHORT_SLOTS] = [2, 2, 3, 4, 5, 6, 6, 6];

/// What one call to [`Rar20Lz::run`] stopped for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lz20Step {
    /// The room the caller gave is used up. Bytes are in the window.
    Filled,
    /// The block ended and a header follows at once.
    BlockEnded,
    /// A step was about to BEGIN with the member's packed input already
    /// exhausted, so the member ends here, short of its declared size
    /// (SPEC-H3 3.5 and SPEC-D part 2, both as of 20 Sep
    /// 2026; SPEC-A 6.1 states the rule in full).
    ///
    /// RAR 2.0 has no end of stream marker, so before that rule the
    /// declared size was what ended a member and the zero bits past the
    /// packed input carried the decode to it. The outcome of ending here
    /// is a member CHECKSUM failure and not an error: the caller is short
    /// of what the header declared, which is exactly what the checksum
    /// reports. No error variant moves.
    Exhausted,
}

/// Which alphabet family the current block decodes through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Lz,
    Multimedia,
}

/// One RAR 2.0 decoder per stream: fresh for a non solid member, shared by
/// a whole solid chain.
pub(crate) struct Rar20Lz {
    level: Table,
    main: Table,
    distance: Table,
    length: Table,
    audio_table: [Table; MAX_CHANNELS],
    /// The stored code lengths, carried between blocks by the keep bit.
    stored: [u8; STORED_LENGTHS],
    /// Scratch the table reads write through, so no block allocates.
    lengths: [u8; STORED_LENGTHS],
    repeats: [u32; REPEATS],
    last_length: u32,
    /// Bytes of a match that did not fit in the room one call was given:
    /// written first by the next call for the same member, and by
    /// [`Rar20Lz::match_past_the_size`] where the member's declared size
    /// was the bound.
    owed_copy: OwedCopy,
    mode: Mode,
    /// Whether a block is in force, so `run` may decode symbols.
    codes_stand: bool,
    channels: usize,
    channel: usize,
    model: Model,
    /// Set when a member's tail began a table read that did not complete
    /// (SPEC-D 2.2 rule 3): no later member of this stream is decoded.
    /// Holds what the read met, `None` for packed data that ran out.
    tail_read_failed: Option<Option<Rar20Fault>>,
}

/// The part of a match that ran past the room a call was given.
#[derive(Clone, Copy, Default)]
struct OwedCopy {
    distance: u32,
    length: u32,
}

impl Rar20Lz {
    /// A decoder with nothing decoded yet.
    pub(crate) fn new() -> Rar20Lz {
        Rar20Lz {
            level: Table::new(LEVEL_SYMBOLS),
            main: Table::new(MAIN_SYMBOLS),
            distance: Table::new(DISTANCE_SLOTS),
            length: Table::new(LENGTH_SLOTS),
            audio_table: [
                Table::new(AUDIO_SYMBOLS),
                Table::new(AUDIO_SYMBOLS),
                Table::new(AUDIO_SYMBOLS),
                Table::new(AUDIO_SYMBOLS),
            ],
            stored: [0; STORED_LENGTHS],
            lengths: [0; STORED_LENGTHS],
            repeats: [0; REPEATS],
            last_length: 0,
            owed_copy: OwedCopy::default(),
            mode: Mode::Lz,
            codes_stand: false,
            channels: 1,
            channel: 0,
            model: Model::fresh(),
            tail_read_failed: None,
        }
    }

    /// Whether a block is in force.
    pub(crate) fn codes_stand(&self) -> bool {
        self.codes_stand
    }

    /// Read a block header and the code lengths that follow it
    /// (sections 3.1 and 3.2), and put them in force. A read past the end
    /// of the input is refused: this is the read a member's TAIL is given
    /// (SPEC-D 2.2), and the one a header far from the end takes.
    pub(crate) fn begin_block(&mut self, input: &mut impl BitSource) -> Result<()> {
        self.refuse_after_a_failed_tail_read()?;
        // The header is not byte aligned and has no mode bit in the RAR 3
        // sense: a 16 bit lookahead, then the fields are consumed from it.
        if input.available() < 2 {
            return Err(Error::new(ErrorKind::Truncated));
        }
        self.read_header(input)?;
        self.build_tables()?;
        self.codes_stand = true;
        Ok(())
    }

    /// [`Self::begin_block`] for a header a member's own decode meets
    /// with its declared size not yet produced, on input that is not
    /// exhausted (spec H3 3.5, "A block header that the end of the packed
    /// data cuts"). The header's bits past the end of the packed data are
    /// read as zeros. It is TAKEN, `true`, when that read ends fewer than
    /// [`HEADER_TAKEN_WITHIN`] bits past the end: its tables are then in
    /// force. Otherwise it is NOT taken, `false`: that is no fault,
    /// nothing of it is in force, the member ends where its terminator
    /// stood, and the next member of a solid chain starts in the old
    /// block under the old tables.
    ///
    /// A fault in a header the end does not cut is the fault it always
    /// was. One met once the read is in bits past the end, a list the
    /// zeros oversubscribe among them, makes the header not taken and is
    /// no fault of the member (rule 6).
    pub(crate) fn begin_block_in_member(&mut self, input: &mut impl BitSource) -> Result<bool> {
        if input.available() >= HEADER_BITS_MOST {
            return self.begin_block(input).map(|()| true);
        }
        self.refuse_after_a_failed_tail_read()?;
        // What a header's read writes before its tables are built: the
        // stored lengths, the mode and the channels. The tables in force
        // are untouched until `build_tables`.
        let kept = (self.stored, self.mode, self.channels, self.channel);
        let read = self.read_header(&mut self::bits::PastEndAsZeros(input));
        let past = input.bits_past_end();
        // A list the zeros oversubscribe is a fault of that read as well:
        // asked BEFORE anything is built, so that the tables in force
        // stay whole (rule 6; the reference takes such a header where
        // the read ends fewer than 8 bits past the end, and rarkit, which
        // builds no oversubscribed table, does not).
        let unbuildable = read.is_err() || self.a_list_is_oversubscribed();
        if past >= HEADER_TAKEN_WITHIN || (past > 0 && unbuildable) {
            (self.stored, self.mode, self.channels, self.channel) = kept;
            self.codes_stand = true;
            return Ok(false);
        }
        read?;
        self.build_tables()?;
        self.codes_stand = true;
        Ok(true)
    }

    /// A member's decode came to a header point with its packed input
    /// exhausted and its declared size not produced: the whole header is
    /// past the end, so none is taken, and the next member of a solid
    /// chain starts in the old block under the old tables (spec H3 3.5,
    /// the same part, rule 4).
    pub(crate) fn no_header_left(&mut self) {
        // A stream that has had no block yet has none to stay in.
        self.codes_stand = match self.mode {
            Mode::Lz => self.main.is_used(),
            Mode::Multimedia => self.audio_table[self.channel & (MAX_CHANNELS - 1)].is_used(),
        };
    }

    /// The header's own bits and its code lengths, read onto the stored
    /// array. Nothing is built.
    fn read_header(&mut self, input: &mut impl BitSource) -> Result<()> {
        let multimedia = input.read(1)? == 1;
        let keep = input.read(1)? == 1;
        if multimedia {
            let channels = input.read(2)? as usize + 1;
            self.channels = channels;
            // A channel index at or above the new count restarts at zero;
            // otherwise it is kept, which is observable when a later
            // multimedia block resumes on it.
            if self.channel >= channels {
                self.channel = 0;
            }
            self.mode = Mode::Multimedia;
        } else {
            // An LZ header leaves the current channel index alone.
            self.mode = Mode::Lz;
        }

        if !keep {
            self.stored.fill(0);
        }
        let wanted = match self.mode {
            Mode::Lz => LZ_LENGTHS,
            Mode::Multimedia => AUDIO_SYMBOLS * self.channels,
        };
        self.read_lengths(input, wanted)
    }

    /// Read `wanted` code lengths through the 19 symbol code length
    /// alphabet, additively on the stored array (section 3.2).
    fn read_lengths(&mut self, input: &mut impl BitSource, wanted: usize) -> Result<()> {
        // The code length alphabet's own lengths are 19 plain 4 bit
        // fields, with no escape at all.
        let mut level = [0u8; LEVEL_SYMBOLS];
        for slot in level.iter_mut() {
            *slot = input.read(4)? as u8;
        }
        self.level.build(&level)?;

        let mut at = 0;
        while at < wanted {
            // T2 is not established on this table (3.2), so a value no
            // level codeword owns stays a refusal.
            let symbol = self.level.decode_owned(input)?;
            match symbol {
                0..=15 => {
                    // Additive on the stored array, as in H1.
                    let new = (self.stored[at] + symbol as u8) % 16;
                    self.lengths[at] = new;
                    self.stored[at] = new;
                    at += 1;
                }
                16 => {
                    if at == 0 {
                        return Err(fault(Rar20Fault::RepeatAtStart));
                    }
                    // Two bits here, not RAR 2.9's three.
                    let count = 3 + input.read(2)? as usize;
                    let repeated = self.lengths[at - 1];
                    for _ in 0..count.min(wanted - at) {
                        self.lengths[at] = repeated;
                        self.stored[at] = repeated;
                        at += 1;
                    }
                }
                17 => {
                    let count = 3 + input.read(3)? as usize;
                    at = self.write_zeros(at, count, wanted);
                }
                18 => {
                    let count = 11 + input.read(7)? as usize;
                    at = self.write_zeros(at, count, wanted);
                }
                _ => return Err(fault(Rar20Fault::LevelSymbol)),
            }
        }
        Ok(())
    }

    /// A run of zero lengths, which is what RAR 2.0 puts where RAR 2.9 has
    /// a repeat of the previous length.
    fn write_zeros(&mut self, mut at: usize, count: usize, wanted: usize) -> usize {
        for _ in 0..count.min(wanted - at) {
            self.lengths[at] = 0;
            self.stored[at] = 0;
            at += 1;
        }
        at
    }

    /// Whether [`Self::build_tables`] would refuse the lengths just read.
    fn a_list_is_oversubscribed(&self) -> bool {
        match self.mode {
            Mode::Lz => {
                let (main, rest) = self.lengths.split_at(MAIN_SYMBOLS);
                let (distance, rest) = rest.split_at(DISTANCE_SLOTS);
                Table::oversubscribed(main)
                    || Table::oversubscribed(distance)
                    || Table::oversubscribed(&rest[..LENGTH_SLOTS])
            }
            Mode::Multimedia => (0..self.channels).any(|channel| {
                let at = channel * AUDIO_SYMBOLS;
                Table::oversubscribed(&self.lengths[at..at + AUDIO_SYMBOLS])
            }),
        }
    }

    /// Build the block's tables from the lengths just read.
    fn build_tables(&mut self) -> Result<()> {
        match self.mode {
            Mode::Lz => {
                let (main, rest) = self.lengths.split_at(MAIN_SYMBOLS);
                let (distance, rest) = rest.split_at(DISTANCE_SLOTS);
                self.main.build(main)?;
                self.distance.build(distance)?;
                self.length.build(&rest[..LENGTH_SLOTS])?;
            }
            Mode::Multimedia => {
                for channel in 0..self.channels {
                    let at = channel * AUDIO_SYMBOLS;
                    let lengths = &self.lengths[at..at + AUDIO_SYMBOLS];
                    self.audio_table[channel].build(lengths)?;
                }
            }
        }
        Ok(())
    }

    /// HOT PATH. Decode until `room` bytes have been produced or the block
    /// ends.
    pub(crate) fn run(
        &mut self,
        input: &mut impl BitSource,
        out: &mut Window,
        room: u64,
    ) -> Result<Lz20Step> {
        // Once a call, never a symbol.
        self.refuse_after_a_failed_tail_read()?;
        let mut room = room;
        // What the last call's room cut off a match is written first. A
        // member's driver clears it at the member's declared end
        // (`match_past_the_size`), so it is never another member's.
        if self.owed_copy.length > 0 {
            let take = u64::from(self.owed_copy.length).min(room);
            out.copy(self.owed_copy.distance, take as u32)?;
            self.owed_copy.length -= take as u32;
            room -= take;
            if room == 0 {
                return Ok(Lz20Step::Filled);
            }
        }
        match self.mode {
            Mode::Lz => self.run_lz(input, out, room),
            Mode::Multimedia => self.run_multimedia(input, out, room),
        }
    }

    /// The LZ alphabet's loop (section 3.3).
    ///
    /// A FUNCTION OF ITS OWN, never inlined, as the multimedia loop is:
    /// each loop is then compiled alone, with everything a symbol runs
    /// always inlined into it, so neither loop's code moves with the other
    /// or with what a build's inliner (or a profile) makes of their caller
    /// (measured 2 Oct 2026). The call is one a
    /// block, or one a stretch of a member's room.
    #[inline(never)]
    fn run_lz(
        &mut self,
        input: &mut impl BitSource,
        out: &mut Window,
        mut room: u64,
    ) -> Result<Lz20Step> {
        while room > 0 {
            if input.available() == 0 {
                return Ok(Lz20Step::Exhausted);
            }
            let symbol = self.main.decode(input)?;
            match symbol {
                0..=255 => {
                    out.put(symbol as u8);
                    room -= 1;
                }
                256 => {
                    // Repeat the last match, at the last distance, with the
                    // last length. This arm PUSHES the distance, which
                    // RAR 2.9's symbol 258 does not. With no match yet,
                    // nothing happens at all.
                    if self.last_length > 0 {
                        let distance = self.repeats[0];
                        self.push_distance(distance);
                        room = self.emit_match(out, room, distance, self.last_length)?;
                    }
                }
                257..=260 => {
                    let slot = (symbol - 257) as usize;
                    let distance = self.repeats[slot];
                    let length = self.read_length(input, 2)?;
                    // A repeated distance match counts all three steps,
                    // the one at 0x101 among them.
                    let length = length + steps_reached(distance, &REPEATED_STEPS);
                    // RAR 2.0 PUSHES here, where RAR 2.9 rotates. See the
                    // erratum on `push_distance` below.
                    self.push_distance(distance);
                    self.last_length = length;
                    room = self.emit_match(out, room, distance, length)?;
                }
                261..=268 => {
                    let slot = (symbol - 261) as usize;
                    let distance = SHORT_BASE[slot] + 1 + input.read_field(SHORT_EXTRA[slot]);
                    self.push_distance(distance);
                    self.last_length = 2;
                    room = self.emit_match(out, room, distance, 2)?;
                }
                269 => {
                    // A terminator that only the zeros past the end of
                    // the packed data complete ends the member's decode
                    // and NOT the block: the member behind it in a solid
                    // chain begins at the first bit of its own packed
                    // data in the block and under the tables in force
                    // (spec H3 3.5, what the reference does, items 5 and
                    // 7).
                    if input.past_end() {
                        return Ok(Lz20Step::Exhausted);
                    }
                    self.codes_stand = false;
                    return Ok(Lz20Step::BlockEnded);
                }
                270..=297 => {
                    let slot = (symbol - 270) as usize;
                    let length = self.length_from_slot(input, slot, 3)?;
                    let distance = self.read_distance(input)?;
                    let length = length + steps_reached(distance, &FRESH_STEPS);
                    self.push_distance(distance);
                    self.last_length = length;
                    room = self.emit_match(out, room, distance, length)?;
                }
                _ => return Err(fault(Rar20Fault::MainSymbol)),
            }
        }
        Ok(Lz20Step::Filled)
    }

    /// The multimedia loop (section 3.4): every byte comes through the
    /// predictor, and there are no matches, distances or literals.
    ///
    /// The bytes go into a contiguous run of the window rather than
    /// through [`Window::put`] one at a time, so the ring's bounds check
    /// and wrap test are paid once for the run instead of once for each
    /// byte. What the run costs instead is that the block terminator and
    /// a fault cannot simply return: the bytes already written have to be
    /// committed first, which is what `ended` and `fault` carry out of the
    /// inner loop.
    ///
    /// Never inlined, for the reason given at [`Rar20Lz::run_lz`].
    #[inline(never)]
    fn run_multimedia(
        &mut self,
        input: &mut impl BitSource,
        out: &mut Window,
        mut room: u64,
    ) -> Result<Lz20Step> {
        while room > 0 {
            let want = usize::try_from(room).unwrap_or(usize::MAX);
            let mut filled = 0usize;
            let mut ended = false;
            let mut spent = false;
            let mut fault_seen = None;
            {
                let slot = out.run(want);
                debug_assert!(!slot.is_empty());
                while filled < slot.len() {
                    if input.available() == 0 {
                        spent = true;
                        break;
                    }
                    #[allow(clippy::indexing_slicing)] // masked to the array
                    let decoded = self.audio_table[self.channel & (MAX_CHANNELS - 1)].decode(input);
                    let symbol = match decoded {
                        Ok(symbol) => symbol,
                        Err(error) => {
                            fault_seen = Some(error);
                            break;
                        }
                    };
                    match symbol {
                        0..=255 => {
                            #[cfg(feature = "audio-lane-ref")]
                            lane_ref::count_sample();
                            let byte = self.model.residual_to_byte(self.channel, symbol as u8);
                            // The window is still written, so a later LZ
                            // block can match into bytes a multimedia
                            // block produced.
                            #[allow(clippy::indexing_slicing)] // loop bound
                            {
                                slot[filled] = byte;
                            }
                            filled += 1;
                            self.channel += 1;
                            if self.channel == self.channels {
                                self.channel = 0;
                            }
                        }
                        256 => {
                            ended = true;
                            break;
                        }
                        _ => {
                            fault_seen = Some(fault(Rar20Fault::AudioSymbol));
                            break;
                        }
                    }
                }
            }
            out.commit(filled);
            room -= filled as u64;
            if let Some(error) = fault_seen {
                return Err(error);
            }
            if ended {
                self.codes_stand = false;
                return Ok(Lz20Step::BlockEnded);
            }
            if spent {
                // The bytes decoded before the input ran out are committed
                // above; the member ends here.
                return Ok(Lz20Step::Exhausted);
            }
        }
        Ok(Lz20Step::Filled)
    }

    /// Produce a match's bytes, as many of them as `room` has place for,
    /// and give back the room that is left. The bytes that had no place
    /// are owed: they are noted with the match's distance, and the next
    /// call for the member, or the member's end, produces them.
    #[inline(always)]
    fn emit_match(
        &mut self,
        out: &mut Window,
        room: u64,
        distance: u32,
        length: u32,
    ) -> Result<u64> {
        let placed = u64::from(length).min(room);
        // No more than `length`, so nothing is lost in the narrowing.
        let now = placed as u32;
        out.copy(distance, now)?;
        if now < length {
            self.owed_copy = OwedCopy {
                distance,
                length: length - now,
            };
        }
        Ok(room - placed)
    }

    /// The member's declared size has been produced: put what is left of a
    /// match that passed it into the stream, and say whether there was
    /// any (SPEC-H3 3.5, "A match that passes the declared size").
    ///
    /// The match enters the stream WHOLE, so the next member of a solid
    /// chain starts after it and later matches copy what the reference's
    /// copy. The bytes written here are NO member's output: the caller
    /// drops them from the window undelivered, and fails the member,
    /// whose checksum in the reference is over bytes it does not deliver.
    /// Until 9 Oct 2026 they were kept and became the first bytes of the
    /// next member.
    pub(crate) fn match_past_the_size(&mut self, out: &mut Window) -> Result<bool> {
        let rest = std::mem::take(&mut self.owed_copy);
        if rest.length == 0 {
            return Ok(false);
        }
        out.copy(rest.distance, rest.length)?;
        Ok(true)
    }

    /// A length slot and its extra bits, with `base` added: 3 on the fresh
    /// arm, 2 on the repeated one.
    #[inline(always)]
    fn read_length(&mut self, input: &mut impl BitSource, base: u32) -> Result<u32> {
        let slot = self.length.decode(input)? as usize;
        if slot >= LENGTH_SLOTS {
            return Err(fault(Rar20Fault::LengthSlot));
        }
        self.length_from_slot(input, slot, base)
    }

    #[inline(always)]
    fn length_from_slot(
        &mut self,
        input: &mut impl BitSource,
        slot: usize,
        base: u32,
    ) -> Result<u32> {
        let extra = input.read_field(LENGTH_EXTRA[slot]);
        Ok(LENGTH_BASE[slot] + base + extra)
    }

    /// A fresh match's distance. Every slot's extra bits are plain bits.
    #[inline(always)]
    fn read_distance(&mut self, input: &mut impl BitSource) -> Result<u32> {
        let slot = self.distance.decode(input)? as usize;
        if slot >= DISTANCE_SLOTS {
            return Err(fault(Rar20Fault::DistanceSlot));
        }
        let extra = input.read_field(DISTANCE_EXTRA[slot]);
        Ok(DISTANCE_BASE[slot] + 1 + extra)
    }

    /// Push a distance, discarding the oldest.
    ///
    /// ERRATUM to spec H3 section 3.3, not yet corrected there. The
    /// specification lists symbols 257 to 260 as "a repeated distance
    /// match" and states no history update for them, so the obvious
    /// reading is H1 section 3.5's ROTATION. It is not what RAR 2.0 does:
    /// the repeated distance arm PUSHES, exactly as the fresh and short
    /// arms do, so a match at repeated distance `k` leaves a second copy
    /// of that distance at the front and discards the oldest.
    ///
    /// Measured, not inferred. Rotation decodes `D250_M5.RAR` and six of
    /// the ten RAR 2.0 corpus members, because none of them names a
    /// repeated distance deeper than `k = 1` before the two readings
    /// diverge. It fails `unpack20_keep_tables.rar`'s `unrar` member at
    /// byte 72 and `unpack20_audio_text.rar`'s at byte 698. Pushing
    /// decodes all ten byte for byte, and reference `unrar` 7.23 agrees
    /// with the pushing reading on both. `repeated_distances_are_pushed`
    /// pins it.
    #[inline(always)]
    fn push_distance(&mut self, distance: u32) {
        self.repeats = [distance, self.repeats[0], self.repeats[1], self.repeats[2]];
    }

    /// The refusal every member meets after a tail read that did not
    /// complete: the fault that read met, again.
    #[inline]
    fn refuse_after_a_failed_tail_read(&self) -> Result<()> {
        match self.tail_read_failed {
            None => Ok(()),
            Some(None) => Err(Error::new(ErrorKind::Truncated)),
            Some(Some(met)) => Err(fault(met)),
        }
    }

    /// At a member's declared end: the table switch its tail may hold for
    /// the member after it (SPEC-D 2.2).
    ///
    /// Nothing is taken unless a block is in force, [`TAIL_FROM_BYTES`]
    /// bytes or more of the member's packed input are unread, the active
    /// table has a symbol, and the next symbol under it is the block's
    /// terminator: any other symbol, and bits that are no codeword at
    /// all, leave every table and the block as they were (rule 2). Then a
    /// table read is made, and a read that completes is what the next
    /// member starts under (rule 1). The member is complete before any of
    /// this and does not fail by anything in its tail.
    ///
    /// A read that does NOT complete, because the packed data ran out or
    /// the lengths were not a code, is remembered: no later member of
    /// the stream is decoded, each being refused with what the read met
    /// (rule 3). That is stricter than the reference, which goes on under
    /// a state of its own; that state is not reproduced here.
    ///
    /// The error this returns is never the archive's: only a failure of
    /// the source to deliver bytes it has comes back to the caller.
    pub(crate) fn finish_member(&mut self, input: &mut impl BitSource) -> Result<()> {
        if !self.codes_stand || input.whole_bytes_left() < TAIL_FROM_BYTES {
            return Ok(());
        }
        let (active, terminator) = match self.mode {
            Mode::Lz => (&self.main, 269),
            Mode::Multimedia => (&self.audio_table[self.channel], 256),
        };
        if !active.is_used() || !matches!(active.decode(input), Ok(next) if next == terminator) {
            return Ok(());
        }
        self.codes_stand = false;
        let Err(met) = self.begin_block(input) else {
            return Ok(());
        };
        self.tail_read_failed = Some(match met.kind() {
            ErrorKind::Truncated => None,
            ErrorKind::Corrupt(Corruption::Rar20(met)) => Some(*met),
            _ => return Err(met),
        });
        Ok(())
    }
}

/// A cut block header is taken when its read ends fewer than this many
/// bits past the end of the packed data (spec H3 3.5: 8 is the one value
/// that gives what the reference wrote in every measured arm).
const HEADER_TAKEN_WITHIN: u64 = 8;

/// More bits than any block header and its lengths can take: 4 of
/// header, 19 level lengths of 4, and at most 1,028 code lengths (four
/// channels of 257) of a 15 bit code and 7 extra bits each. A header
/// with this much input left is not cut by its end.
const HEADER_BITS_MOST: u64 = 1 << 15;

/// Unread bytes of a member's packed input below which nothing is taken
/// from its tail, a partly read byte counted whole. Observed, not chosen:
/// the reference takes nothing at four and begins a table read at five
/// (SPEC-D 2.2, O3 against O4).
const TAIL_FROM_BYTES: usize = 5;

/// The distances at which a FRESH match (main symbols 270 to 297) is one
/// byte longer, each step it has reached adding its own byte (section 3.3).
const FRESH_STEPS: [u32; 2] = [0x2000, 0x4_0000];

/// The same for a REPEATED DISTANCE match (257 to 260), which has a third
/// step below the other two. A short match and symbol 256 have none.
const REPEATED_STEPS: [u32; 3] = [0x101, 0x2000, 0x4_0000];

/// The bytes a match at `distance` gains: one for each of `steps` that the
/// distance is at or beyond. A distance never set is 0 and gains nothing;
/// the copy refuses it.
#[inline(always)]
fn steps_reached(distance: u32, steps: &[u32]) -> u32 {
    steps.iter().map(|&step| u32::from(distance >= step)).sum()
}

/// The failure of a member whose last match passed its declared size
/// (SPEC-H3 3.5): its declared bytes were delivered, and it has the
/// verdict of a member whose checksum does not match.
pub(crate) fn match_past_the_size() -> Error {
    Error::new(ErrorKind::Corrupt(Corruption::Stream))
}

fn fault(fault: Rar20Fault) -> Error {
    Error::new(ErrorKind::Corrupt(Corruption::Rar20(fault)))
}

/// The most one member's output buffer reserves UP FRONT, whatever the
/// member header declares.
///
/// Spec F section 4.2: a declared unpacked size is "never used to size a
/// buffer; it is a limit on output, checked as output is produced", and
/// the field arrives from an untrusted RAR 2.0 member header. Sizing the
/// buffer by it let a header of a few bytes ask for the whole declared
/// size at once on a 64-bit target, and on a 32-bit one a declared size at
/// or over 4 GiB truncated in the narrowing cast and reserved some small
/// unrelated figure instead.
const OUTPUT_RESERVE_MAX: u64 = 1 << 20;

/// What to reserve for a member declaring `unpacked` bytes: the declared
/// size only while it is small, and the vector grows as output arrives.
fn reserve_for(unpacked: u64) -> usize {
    // The `min` is what makes the narrowing exact on a 32-bit target.
    unpacked.min(OUTPUT_RESERVE_MAX) as usize
}

/// A RAR 2.0 stream held whole by its caller: the decoder and the bytes
/// it has produced, which outlive a member so that a solid chain's
/// members can be given one after another. An archive comment is read
/// through it as well, being a stream of one member.
pub(crate) struct Rar20Chain {
    codec: Rar20Lz,
    history: Window,
}

/// How a member's decode came to its end.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MemberEnd {
    /// Every byte the header declared was produced.
    AtDeclaredSize,
    /// The packed data gave out first, or the header that should have
    /// followed a block was not taken. The member is short, and its
    /// checksum is what says so.
    Short,
}

impl Rar20Chain {
    /// A stream that has produced nothing, over `capacity` bytes of
    /// history.
    pub(crate) fn new(capacity: u32) -> Rar20Chain {
        Rar20Chain {
            codec: Rar20Lz::new(),
            history: Window::new(capacity),
        }
    }

    /// The next member of the stream: `packed` is all of its packed data
    /// and `unpacked` the size its header declares. The bytes come back
    /// whole, and are fewer than declared where the member ended short.
    pub(crate) fn decode_next(&mut self, packed: &[u8], unpacked: u64) -> Result<Vec<u8>> {
        let mut input = bits::SliceBits::new(packed);
        let mut bytes = Vec::with_capacity(reserve_for(unpacked));
        if self.decode_up_to(&mut input, unpacked, &mut bytes)? == MemberEnd::Short {
            return Ok(bytes);
        }
        // A match that ran past the declared size goes into the stream
        // whole (SPEC-H3 3.5), for the members behind this one to copy
        // from, but its bytes past the size are nobody's output.
        let ran_past = self.codec.match_past_the_size(&mut self.history)?;
        self.history.take(self.history.held_bytes());
        // Only a member that reached its declared size has a tail that may
        // hold the next member's code lengths (SPEC-D part 2).
        self.codec.finish_member(&mut input)?;
        if ran_past {
            return Err(match_past_the_size());
        }
        Ok(bytes)
    }

    /// Decode into `bytes` until they number `unpacked`, block after
    /// block, or until the member can give no more.
    fn decode_up_to(
        &mut self,
        input: &mut bits::SliceBits<'_>,
        unpacked: u64,
        bytes: &mut Vec<u8>,
    ) -> Result<MemberEnd> {
        loop {
            let owed = unpacked - bytes.len() as u64;
            if owed == 0 {
                return Ok(MemberEnd::AtDeclaredSize);
            }
            if !self.codec.codes_stand() {
                // A block header is due here. With no packed data left
                // there is none to take; one that the end of the packed
                // data cuts may not be taken either. Both end the member.
                if input.available() == 0 {
                    self.codec.no_header_left();
                    return Ok(MemberEnd::Short);
                }
                if !self.codec.begin_block_in_member(input)? {
                    return Ok(MemberEnd::Short);
                }
            }
            // Never more at once than the history can hold undelivered.
            let room = owed.min(self.history.room() as u64);
            let step = self.codec.run(input, &mut self.history, room)?;
            self.deliver(bytes);
            if step == Lz20Step::Exhausted {
                return Ok(MemberEnd::Short);
            }
        }
    }

    /// Hand everything produced and not yet delivered to the member.
    fn deliver(&mut self, bytes: &mut Vec<u8>) {
        let (older, newer) = self.history.pending();
        bytes.extend_from_slice(older);
        bytes.extend_from_slice(newer);
        self.history.take(self.history.held_bytes());
    }
}
