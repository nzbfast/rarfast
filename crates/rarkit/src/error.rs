//! One error type for the whole crate (API spec section 6).
//!
//! Section 6 wants a caller to be able to match on WHAT went wrong
//! without first working out which part of the engine produced it, so
//! there is a single [`Error`], a single [`ErrorKind`], and the detail
//! that used to live in per-family error types sits in the payload of a
//! kind instead.

use std::error::Error as StdError;
use std::fmt;

use crate::read::Format;

/// The crate's `Result`: anything can fail with [`Error`] and nothing
/// fails with anything else.
pub type Result<T> = std::result::Result<T, Error>;

/// Anything that went wrong, with enough around it to say WHERE.
///
/// The kind is the answer to "what happened"; beside it the error carries
/// as much of the member, the volume index and the source offset as was
/// known at the point of failure, because a caller reading a
/// multi-volume set needs those to say anything useful to a user. When
/// the caller's own code raised the failure, its value travels here too
/// and comes back out through [`Error::into_caller_error`].
///
/// `Display` prints whichever of the three are known. No message this
/// crate produces contains password bytes, at any kind.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    member: Option<Vec<u8>>,
    volume: Option<u32>,
    offset: Option<u64>,
    caller: Option<Box<dyn StdError + Send + Sync>>,
}

impl Error {
    /// An error of `kind`, with nothing known about where yet. The
    /// `with_` methods below add that as the stack unwinds past what
    /// knows it.
    pub fn new(kind: ErrorKind) -> Self {
        Error {
            kind,
            member: None,
            volume: None,
            offset: None,
            caller: None,
        }
    }

    /// Wrap a value the CALLER's code failed with, so it can be taken
    /// back out unchanged later.
    pub fn caller(err: impl Into<Box<dyn StdError + Send + Sync>>) -> Self {
        Error {
            caller: Some(err.into()),
            ..Error::new(ErrorKind::Caller)
        }
    }

    /// Record which member was being worked on.
    pub fn with_member(mut self, name: &[u8]) -> Self {
        self.member = Some(name.to_vec());
        self
    }

    /// Record which volume of the set was being read.
    pub fn with_volume(mut self, volume: u32) -> Self {
        self.volume = Some(volume);
        self
    }

    /// Record where in the source this happened. The offset is the
    /// caller's own coordinate system, not one relative to a header.
    pub fn with_offset(mut self, offset: u64) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Which kind of failure this is.
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    /// The member being worked on, in the bytes the archive stored,
    /// when that was known.
    pub fn member(&self) -> Option<&[u8]> {
        self.member.as_deref()
    }

    /// The volume being read, counting from zero in set order, when
    /// that was known.
    pub fn volume(&self) -> Option<u32> {
        self.volume
    }

    /// Where in the source this happened, when that was known.
    pub fn offset(&self) -> Option<u64> {
        self.offset
    }

    /// Take back the value the caller's own code failed with.
    ///
    /// `Ok` with that value when this error came from a `Sink`,
    /// `Progress`, `Volumes` or `EntropySource`; otherwise `Err` with
    /// this error handed back untouched, so nothing is lost by asking.
    /// Section 2 promise 8 is what this exists for: a caller can tell its
    /// own abort from a broken archive.
    pub fn into_caller_error(self) -> std::result::Result<Box<dyn StdError + Send + Sync>, Error> {
        match (self.kind, self.caller) {
            (ErrorKind::Caller, Some(held)) => Ok(held),
            // Not a caller's error, or a caller's error with nothing
            // kept: put it back exactly as it came in.
            (kind, held) => Err(Error {
                kind,
                caller: held,
                ..self
            }),
        }
    }
}

impl From<std::io::Error> for Error {
    /// An `io::Error` reaching this crate came out of the caller's own
    /// code, so it becomes [`ErrorKind::Caller`] and keeps its value. A
    /// failure inside a `RangeSource` is [`ErrorKind::Source`] and is
    /// built there, not here.
    fn from(err: std::io::Error) -> Self {
        Error::caller(err)
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Error::new(kind)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;
        if let Some(held) = &self.caller {
            write!(f, ": {held}")?;
        }
        // Where it happened, in one parenthesis, and only when something
        // about the where is actually known: the old form printed a bare
        // "()" after an error that carried no context at all.
        let mut opened = false;
        if let Some(name) = &self.member {
            write!(f, " (member {:?}", String::from_utf8_lossy(name))?;
            opened = true;
        }
        for (label, value) in [
            ("volume", self.volume.map(u64::from)),
            ("offset", self.offset),
        ] {
            let Some(value) = value else { continue };
            f.write_str(if opened { ", " } else { " (" })?;
            write!(f, "{label} {value}")?;
            opened = true;
        }
        if opened {
            f.write_str(")")?;
        }
        Ok(())
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        // A source's own failure first: when both are present it is the
        // one nearer the cause.
        if let ErrorKind::Source(failed) = &self.kind {
            return Some(failed);
        }
        self.caller.as_deref().map(|held| held as &dyn StdError)
    }
}

/// What went wrong, as a caller matches on it.
///
/// `non_exhaustive`, so a later package naming a new kind is not a
/// breaking change; a caller wants a catch-all arm anyway.
#[derive(Debug)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Nothing that looks like an archive where one had to be.
    NotAnArchive,
    /// The bytes ran out early: a source that stopped before its
    /// declared length, or a volume set that has no next volume.
    Truncated,
    /// The bytes are there and the format forbids what they say. The
    /// payload says which rule.
    Corrupt(Corruption),
    /// A header's own checksum disagreed with the header, so nothing
    /// read out of it can be trusted.
    HeaderChecksum,
    /// The headers themselves are enciphered, so even listing needs a
    /// password and none was supplied.
    PasswordRequired,
    /// The password was supplied and is wrong. RAR 5 only: it carries a
    /// check value that can say so at `open`, where a RAR 4 family
    /// archive has none and fails later, on the data.
    WrongPassword,
    /// The archive is well formed and asks for something outside this
    /// crate's scope. The payload says what.
    Unsupported(Unsupported),
    /// Something the archive declared, or something an operation planned,
    /// is larger than [`MemoryPolicy`](crate::MemoryPolicy) allows.
    ///
    /// Promise 3 of section 2: this arrives BEFORE the allocation, never
    /// as one that failed, and it names all three figures so a caller can
    /// decide whether to raise the limit and retry.
    LimitExceeded {
        /// What was being sized.
        resource: Resource,
        /// How many bytes it wanted.
        needed: u64,
        /// How many the policy allows.
        limit: u64,
    },
    /// A repair could not be carried out. The payload says why.
    Recovery(RecoveryFailure),
    /// The caller's source failed a read. The `io::Error` is the
    /// caller's own, unchanged; this is also how a blocking source
    /// cancels an operation.
    Source(std::io::Error),
    /// Something the CALLER implemented failed - a `Sink`, a `Progress`,
    /// a `Volumes` or an `EntropySource`. The value it failed with is
    /// still here; [`Error::into_caller_error`] gives it back.
    Caller,
    /// A cancel flag the caller set was noticed, and the operation
    /// stopped on purpose.
    Cancelled,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Nothing printed here may carry password bytes, at any kind.
        match self {
            ErrorKind::NotAnArchive => f.write_str("no RAR archive here"),
            ErrorKind::Truncated => f.write_str("the bytes ran out early"),
            ErrorKind::Corrupt(rule) => write!(f, "malformed archive: {rule:?}"),
            ErrorKind::HeaderChecksum => f.write_str("a header disagrees with its own checksum"),
            ErrorKind::PasswordRequired => f.write_str("this archive needs a password"),
            ErrorKind::WrongPassword => f.write_str("that password is not it"),
            ErrorKind::Unsupported(what) => {
                write!(f, "outside this engine's scope: {what:?}")
            }
            ErrorKind::LimitExceeded {
                resource,
                needed,
                limit,
            } => match resource {
                // SPEC-API 8.1 term 4: the host refused what the policy
                // allowed, so the words are the host's and not the policy's.
                Resource::AddressSpace => write!(
                    f,
                    "the system refused {needed} bytes the policy allowed (address space {limit})"
                ),
                _ => write!(
                    f,
                    "{resource:?} wanted {needed} bytes and the policy allows {limit}"
                ),
            },
            ErrorKind::Recovery(why) => write!(f, "cannot repair: {why:?}"),
            ErrorKind::Source(failed) => write!(f, "the source failed: {failed}"),
            ErrorKind::Caller => f.write_str("the caller's own code failed"),
            ErrorKind::Cancelled => f.write_str("cancelled on request"),
        }
    }
}

/// Which of the formats' rules the bytes broke.
///
/// The variant list was open for a long time and each package grew it;
/// section 6's erratum of 19 Sep 2026 closed it and fixed the list as the
/// packages left it, naming the section behind each. `non_exhaustive`,
/// and so is every per-family fault enum below it: a caller may tell the
/// FAMILIES apart here, but the detail inside one is diagnostics to
/// print, never a key to branch on.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Corruption {
    /// A header whose fields disagree with each other, or with what the
    /// format permits.
    Header,
    /// A compressed stream that stopped making sense to its decoder.
    Stream,
    /// A volume that is not part of the set it was offered to.
    VolumeSet,
    /// A RAR 3 filter record that breaks the format's framing or bounds
    /// (spec J section 4).
    FilterRecord,
    /// A RAR 3 standard filter's parameters outside their domain (spec J
    /// section 3.5).
    FilterParameters,
    /// A RAR 3 PPM block the text model cannot continue (spec I section 2).
    Ppmd(PpmFault),
    /// A RAR 2.9 / 3.x / 4.x LZ stream a decoder cannot continue (spec H1
    /// section 2); which field failed.
    Rar3(Rar3Fault),
    /// A RAR 5 compressed stream broke one of spec H2's rules; which one.
    Rar5(Rar5Fault),
    /// A RAR 2.0 LZ or multimedia stream the decoder cannot continue
    /// (spec H3 section 2).
    Rar20(Rar20Fault),
    /// A member name a writer cannot store: empty, absolute, holding a NUL
    /// byte or a `..` component, or longer than the format's name field
    /// can say (spec G section 4).
    MemberName,
    /// A payload that yielded more bytes than the caller declared (spec G
    /// 3.7.2). Too FEW is [`ErrorKind::Truncated`] instead: the declared
    /// size is already in a header that may be in another volume.
    PayloadLength,
    /// A payload whose checksum disagrees with the one the caller stated
    /// (spec G 3.7.2).
    Checksum,
    /// A redirection record the engine cannot use (spec F 3.2.6.2, 3.3.12,
    /// 3.8.1): a malformed RAR 5 record, an empty or NUL-bearing target, a
    /// RAR 4 family link whose target is above 64 KiB, or a file copy
    /// naming itself.
    Redirection,
    /// An old comment block (type 0x75) standing between the blocks of the
    /// older container, where no genuine writer puts one: theirs are
    /// embedded in a main or a file header (spec F 3.3.3 B2).
    CommentOutsideHeader,
}

/// What the RAR 2.0 codec refused (spec H3 section 2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Rar20Fault {
    /// A code length alphabet symbol above 18. The alphabet has 19
    /// symbols, not RAR 2.9's 20.
    LevelSymbol,
    /// A repeat of the previous code length arrived at position zero,
    /// where there is nothing to repeat.
    RepeatAtStart,
    /// A main alphabet symbol above 297.
    MainSymbol,
    /// A length alphabet symbol above 27.
    LengthSlot,
    /// A distance alphabet symbol above 47.
    DistanceSlot,
    /// A multimedia alphabet symbol above 256.
    AudioSymbol,
    /// A match reaching before the start of the stream, past the window,
    /// or naming a distance of zero.
    DistanceOutOfRange,
    /// A code length list whose Kraft sum exceeds the code space. A RAR 2.0
    /// table is strict and refuses it when the table is built.
    Oversubscribed,
    /// A lookahead in an incomplete table's unused space, or any read from
    /// an all zero table.
    InvalidCode,
}

/// What the RAR 3 text model refused (spec I section 2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PpmFault {
    /// A starting block header signalled order 1, which the model cannot
    /// hold.
    BadOrder,
    /// A continuing block header arrived with no model to continue.
    NoModel,
    /// A count the range decoder produced is at or beyond its total, or a
    /// division would be by zero.
    RangeOutOfBounds,
    /// An escape was decoded in the root context, which nothing in RAR 3
    /// gives a meaning.
    RootEscape,
    /// Not raised since 9 Oct 2026: a member's packed data is decoded on
    /// after its declared size to its end pair (spec I 3.3, "Member
    /// end"), so no symbol there is out of place. Kept so that a caller's
    /// match on it still builds.
    BadMemberEnd,
    /// Not raised since 9 Oct 2026: a copy that passes the declared size
    /// enters the window whole (spec I 3.3). Kept so that a caller's match
    /// on it still builds.
    CopyPastEnd,
    /// The escape code that ends a member's data arrived before the
    /// member's declared size had been produced (spec I 3.3).
    EndedShort,
    /// A model invariant of spec I section 3.10 would be violated. No
    /// stream can reach it; it exists so that no code path can panic.
    Inconsistent,
}

/// Which field of a RAR 3 LZ stream was impossible (SPEC-H1 section 2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Rar3Fault {
    /// A code length alphabet symbol above 19.
    LevelSymbol,
    /// A repeat of the previous code length arrived first.
    RepeatAtStart,
    /// A main alphabet symbol above 298.
    MainSymbol,
    /// A length alphabet symbol above 27.
    LengthSlot,
    /// A distance alphabet symbol above 59.
    DistanceSlot,
    /// A low distance alphabet symbol above 16.
    LowDistanceSymbol,
    /// A match reaching before the start of the stream, or past the
    /// declared dictionary.
    DistanceOutOfRange,
    /// A repeated distance slot naming a distance of zero, which no match
    /// has ever set.
    UninitialisedRepeat,
    /// Not raised since 6 Oct 2026: a member's packed data is decoded on
    /// after its declared size (SPEC-H1 3.8, B1), so no symbol there is
    /// out of place. Kept so that a caller's match on it still builds.
    TrailingData,
}

/// Which rule of the RAR 5 LZ codec a stream broke (SPEC-H2 section 2).
///
/// Every variant names the FIELD that failed, so a caller can tell a bad
/// block header from a bad distance slot without matching on prose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Rar5Fault {
    /// The block header's byte wise check did not hold (section 3.2).
    BlockHeaderChecksum,
    /// The block header's size width field is 3, which would mean a four
    /// byte payload length (section 3.2).
    BlockSizeWidth,
    /// A code length alphabet symbol is above 19 (section 3.3).
    LevelSymbol,
    /// A repeat of the previous code length arrived first (section 3.3).
    RepeatAtStart,
    /// A table's code lengths claim more code space than exists (3.4).
    Oversubscribed,
    /// A lookahead fell in an incomplete table's unused space (3.4).
    InvalidCode,
    /// A symbol was asked of a table with no symbols at all (3.4).
    EmptyTable,
    /// A length slot's extra bit count would exceed 24 (section 3.5).
    LengthSlot,
    /// A distance slot's extra bit count would exceed 31 (section 3.5).
    DistanceSlot,
    /// A repeated distance slot named a distance of zero (section 3.5).
    UninitialisedRepeat,
    /// A match reaches before the start of the stream, or past the declared
    /// window (section 3.7).
    DistanceOutOfRange,
    /// A filter record's type field is 4 or above (section 3.6).
    FilterType,
    /// A filter's span is not inside the bytes the member produced, or is
    /// longer than the format's filter block bound (section 3.6).
    FilterRange,
    /// The last block of the chain ended with the member short (3.2).
    IncompleteMember,
}

/// Something the archive legitimately asks for that this crate will not
/// do.
///
/// Every variant carries enough to NAME the thing in a report, which is
/// the point of the type: section 1 draws the scope, and a caller outside
/// it should be able to say exactly what it hit rather than "unsupported".
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Unsupported {
    /// A RAR 3 member carrying a filter program that is not one of the
    /// six standard ones. There is no interpreter here (section 1), so
    /// the program is reported by its length and hash instead.
    FilterProgram {
        /// How many bytes of program there were.
        len: u32,
        /// The CRC32 over those bytes, which identifies the program.
        crc32: u32,
    },
    /// A member compressed by a method no decoder here implements.
    Method {
        /// Which family the archive is, since the codes differ.
        format: Format,
        /// The method code exactly as the header stored it.
        code: u32,
    },
    /// A writing option the target format has no way to express - a
    /// recovery record on a split RAR 4 set, for one. The string names
    /// which.
    WriteFeature(&'static str),
    /// A format version this crate does not read.
    Version(u32),
    /// A sink answered [`Disposition::Write`](crate::Disposition::Write)
    /// for a redirection member, which is never delivered as bytes
    /// (SPEC-API 4.4, spec F 3.8.1). Nothing was written to the writer.
    Redirection(crate::read::RedirectionKind),
    /// An encryption parameter this crate cannot use: a RAR 5 KDF exponent
    /// above 24, a RAR 5 encryption version other than 0, or the unpack
    /// version of an encrypted RAR 4 family member that selects no cipher.
    Encryption {
        /// Which family the archive is.
        format: Format,
        /// Whichever of the three numbers above was out of range.
        code: u32,
    },
}

/// What a [`LimitExceeded`](ErrorKind::LimitExceeded) was sizing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Resource {
    /// A window a member asked a decoder for.
    Window,
    /// The RAR 3 text model's arena (spec I section 4.2), counted against
    /// the working limit together with the window.
    TextModel,
    /// A window a writer wanted to compress with.
    Dictionary,
    /// The length a header declared for itself.
    HeaderSize,
    /// The table of members for one volume, with the arena holding
    /// their names.
    MemberTable,
    /// Working memory for a repair. One resource for every family:
    /// section 6 collapsed the per-family variants onto this.
    RepairWork,
    /// Threads an operation wanted to run on.
    Workers,
    /// The working memory reading ONE member needs at breadth one, against
    /// a stated budget below it: refused before any member is
    /// read, `needed` and `limit` in the terms of the policy's constructor.
    WorkingMemory,
    /// The packed bytes of ONE RAR 5 block, against what a stated budget
    /// leaves beside the member's window: refused at that block, before
    /// its payload is read, the one refusal that can come inside a member
    /// (SPEC-API 8.4.1). `needed` is what the operation would hold with
    /// the block, `limit` the budget's engine limit.
    BlockBuffer,
    /// An allocation the policy ADMITTED that the host then refused, its
    /// address space or its memory spent (under `ulimit -v 1g`, say):
    /// `needed` the bytes asked for, `limit` the finite `RLIMIT_AS` where
    /// one is set, else the policy's own figure for that allocation (SPEC-API
    /// 8.1 term 4). What the policy itself refuses is never this.
    AddressSpace,
}

/// Why a repair could not be carried out.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RecoveryFailure {
    /// There is nothing to repair from: this volume carries no recovery
    /// record at all.
    NoRecord,
    /// Too much is gone. The code can rebuild only as many pieces as
    /// there is recovery data for, and more than that are absent.
    TooManyMissing {
        /// How many pieces are absent.
        missing: u32,
        /// How many the recovery data could have rebuilt.
        available: u32,
    },
    /// The recovery data is sound but describes some other set.
    SetMismatch,
    /// The recovery data did not survive either.
    RecoveryDamaged,
}
