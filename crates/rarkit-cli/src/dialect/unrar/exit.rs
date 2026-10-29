//! unrar's exit table.
//!
//! The numbers are the manual's. Which one a given input shape produces
//! is NOT the manual's: it was captured from the pinned reference into
//! the captured `unrar` 7.23 expectations, because the code
//! depends on where unrar notices the problem rather than on what the
//! problem is. Two rows in that table make the point:
//!
//! - a missing volume comes back 6 (open error) when unrar reaches the
//!   end of the volume it has and cannot open the next, even though the
//!   member it was writing then also fails its checksum, which on its own
//!   would be 3;
//! - a listing of an archive that is not there comes back 10 (no files),
//!   not 6, because `l` counts members rather than opening a payload.
//!
//! So a caller here picks the arm the CAPTURE showed, and a change to one
//! is a change to a conformance row.

/// One code from unrar's table.
///
/// Every code the reference can return has a variant, including the ones
/// no input shape in today's matrix produces. That is the point: the
/// table is a fixture of the reference's contract, and a caller reading
/// this enum should see the whole of it rather than the subset our
/// current call sites happen to reach. Deleting an unreached variant to
/// quieten the lint would make the next shape that needs it look like a
/// new decision instead of a lookup.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Exit {
    /// 0: everything asked for happened.
    Clean,
    /// 1: finished, with a warning.
    Cautioned,
    /// 2: a fatal error.
    Aborted,
    /// 3: a checksum mismatch in extracted or tested data.
    ChecksumMismatch,
    /// 4: the archive is locked.
    SealedArchive,
    /// 5: a write failed.
    WriteFailed,
    /// 6: a file could not be opened, a missing volume included.
    CannotOpen,
    /// 7: the command line was wrong.
    BadCommandLine,
    /// 8: out of memory.
    OutOfMemory,
    /// 9: a file could not be created.
    CannotCreate,
    /// 10: nothing matched, so nothing was done.
    NothingMatched,
    /// 11: the password was wrong.
    WrongPassword,
    /// 12: a read failed.
    ReadFailed,
    /// 13: the archive named for writing exists and is not an archive.
    /// Not in the manual's table; measured on rar 7.23, 15 Sep 2026:
    /// `rar a plain.foo b.txt` over a text file answers `ERROR: Bad
    /// archive plain.foo` and exits 13, leaving the file untouched.
    NotAnArchive,
    /// 255: the user interrupted the run.
    Interrupted,
}

impl Exit {
    /// The process exit status.
    pub(crate) fn code(self) -> i32 {
        match self {
            Self::Clean => 0,
            Self::Cautioned => 1,
            Self::Aborted => 2,
            Self::ChecksumMismatch => 3,
            Self::SealedArchive => 4,
            Self::WriteFailed => 5,
            Self::CannotOpen => 6,
            Self::BadCommandLine => 7,
            Self::OutOfMemory => 8,
            Self::CannotCreate => 9,
            Self::NothingMatched => 10,
            Self::WrongPassword => 11,
            Self::ReadFailed => 12,
            Self::NotAnArchive => 13,
            Self::Interrupted => 255,
        }
    }

    /// How unrar ranks two outcomes when a run hits more than one. The
    /// reference reports the LAST error class it set rather than the
    /// worst, with one exception that the capture pins: a run that both
    /// lost a volume and then failed a checksum reports the open error.
    /// Ranking by this order reproduces that without special-casing the
    /// shape.
    fn severity(self) -> u8 {
        match self {
            Self::Clean => 0,
            Self::Cautioned => 1,
            Self::NothingMatched => 2,
            Self::ChecksumMismatch => 3,
            Self::WrongPassword => 4,
            Self::CannotCreate | Self::WriteFailed | Self::ReadFailed => 5,
            Self::CannotOpen => 6,
            Self::SealedArchive | Self::OutOfMemory | Self::Aborted | Self::NotAnArchive => 7,
            Self::BadCommandLine => 8,
            Self::Interrupted => 9,
        }
    }

    /// Folds another outcome into this one, keeping the more severe.
    pub(crate) fn worse_of(self, other: Self) -> Self {
        if other.severity() > self.severity() {
            other
        } else {
            self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Exit;

    #[test]
    fn the_codes_are_the_manuals() {
        assert_eq!(Exit::Clean.code(), 0);
        assert_eq!(Exit::ChecksumMismatch.code(), 3);
        assert_eq!(Exit::CannotOpen.code(), 6);
        assert_eq!(Exit::BadCommandLine.code(), 7);
        assert_eq!(Exit::NothingMatched.code(), 10);
        assert_eq!(Exit::WrongPassword.code(), 11);
        assert_eq!(Exit::Interrupted.code(), 255);
    }

    #[test]
    fn a_missing_volume_outranks_the_checksum_failure_it_causes() {
        // The `extract-missing-volume` row comes back 6, not 3, even
        // though the member that was mid-write also fails its checksum.
        assert_eq!(
            Exit::ChecksumMismatch.worse_of(Exit::CannotOpen),
            Exit::CannotOpen,
            "a lost volume is reported over the checksum failure it caused"
        );
        assert_eq!(
            Exit::CannotOpen.worse_of(Exit::ChecksumMismatch),
            Exit::CannotOpen
        );
    }

    #[test]
    fn a_wrong_password_outranks_a_checksum_failure() {
        assert_eq!(
            Exit::ChecksumMismatch.worse_of(Exit::WrongPassword),
            Exit::WrongPassword
        );
    }
}
