//! The small types both sides of the engine speak in.
//!
//! Nothing here carries behaviour worth the name: these are the shapes a
//! member's facts arrive in and leave in, so that a reader and a writer
//! agree without either owning the other's vocabulary. What each one MEANS
//! in a given container is spec F's to say.

use std::fmt;

use zeroize::Zeroizing;

/// A password, kept as bytes and wiped from memory when it is dropped.
///
/// Bytes, not text: the RAR formats hash what they are given, so the
/// question of which encoding a passphrase was typed in belongs to the
/// caller and is not decided here. Printing one is not possible by
/// accident either - the `Debug` written below shows that a password is
/// present and never what it is.
#[derive(Clone, Eq, PartialEq)]
pub struct Password {
    /// Wiped when this goes out of scope, which is the whole reason the
    /// type exists rather than a bare `Vec<u8>`.
    bytes: Zeroizing<Vec<u8>>,
}

impl Password {
    /// Take ownership of `bytes` as a password.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Password {
            bytes: Zeroizing::new(bytes.into()),
        }
    }

    /// The bytes back, for the key derivation that needs them.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<&str> for Password {
    fn from(text: &str) -> Self {
        Password::new(text.as_bytes())
    }
}

impl From<&[u8]> for Password {
    fn from(bytes: &[u8]) -> Self {
        Password::new(bytes)
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Password").finish_non_exhaustive()
    }
}

/// When a member was last modified.
///
/// One shape for both families, split so that it loses nothing either of
/// them records: the seconds field reaches times before 1970 because it is
/// signed, and the nanoseconds field is fine enough for the more precise
/// of the two formats. Reading a coarse stored time simply leaves the
/// second field at zero. Spec F is what maps each format's stored form
/// onto this.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Timestamp {
    /// Seconds from 1970-01-01T00:00:00Z, negative before it.
    pub unix_seconds: i64,
    /// The fraction of that second, in nanoseconds, always under one
    /// thousand million.
    pub nanos: u32,
}

/// Which system wrote the member, as its header claims.
///
/// This is a REPORT of a stored byte and not a judgement about it: an
/// archive may name a system it was not written on, and the value matters
/// mainly because it settles how `MemberInfo::attributes` should be read.
/// The list is open - a byte outside it arrives as `Other`, unchanged -
/// and the type is `non_exhaustive` so that naming a further one later is
/// not a breaking change.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum HostOs {
    /// MS-DOS, which is what the oldest archives in the wild claim.
    MsDos,
    /// OS/2, which shares MS-DOS's reading of the attribute word.
    Os2,
    /// Windows, which is also what an unset value is taken to mean.
    #[default]
    Windows,
    /// Unix, including Linux and the BSDs. Spec F 3.2 records this as
    /// the only value RAR 5 writes besides Windows.
    Unix,
    /// Mac OS, meaning the classic system rather than macOS.
    MacOs,
    /// BeOS, which spec F 3.3 lists and this project has never seen
    /// written.
    BeOs,
    /// A byte none of the above names, carried through as it was stored.
    Other(u8),
}

/// The check value a member's header carries over its CONTENT.
///
/// Which of the two is present is the archive's choice, not the caller's,
/// so this is an enum rather than a pair of options; a member with no
/// check value at all is `None` at the field that holds this.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Checksum {
    /// A CRC32, which every family can carry.
    Crc32(u32),
    /// A BLAKE2sp digest, which only RAR 5 can.
    Blake2sp([u8; 32]),
}

/// What was done to a member's bytes before they were written.
///
/// The compressed arm carries the two figures that decide what decoding
/// will COST, which is why they sit here rather than behind an accessor:
/// a caller sizing its memory needs the dictionary before it commits to
/// the member.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Method {
    /// Written through unchanged.
    Stored,
    /// Compressed, at the effort and window the header records.
    Compressed {
        /// The effort setting, as the header stores it.
        level: u8,
        /// The window the decoder will need, in bytes.
        dictionary: u64,
    },
}
