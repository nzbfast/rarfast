//! Archive editing (API spec section 7.5, spec G 3.15): a rewrite from an
//! opened archive to a new output. Members are never decoded and never
//! recompressed, and the caller replaces the file, so a failed edit leaves
//! the original untouched.
//!
//! Five things a rewrite can change, in any combination:
//!
//! | Entry point | The reference's command |
//! |---|---|
//! | [`set_comment`] | `c` |
//! | [`lock`] | `k` |
//! | [`remove`] | `d` |
//! | [`rename`] | `rn` |
//! | [`set_recovery`] | `rr[N]` on an archive that already exists |
//!
//! **What survives a rewrite.** Every member that is kept travels with its
//! data byte for byte, which is the strongest form of "never recompressed"
//! available: the bytes are not rebuilt, they are moved. A member that is
//! renamed keeps its data and every header field but the name, because the
//! name is SPLICED into the header it already had rather than the header
//! rebuilt, so a record this crate does not model survives instead of
//! being dropped.
//!
//! **The quick-open index is rebuilt, not dropped.** It caches each large
//! member's header together with the offset that header sits at, so a
//! rewrite that moves the blocks invalidates it. Earlier versions of this
//! module dropped it and the locator record with it, which left a valid
//! archive that was not the reference's bytes; it is now rebuilt over the
//! members the output actually holds, which is what the reference does for
//! every one of the five commands above (measured on `rar` 7.23,
//! 19 Sep 2026: `d`, `rn`, `k` and `c` all leave a RESIZED index behind).
//!
//! **The inline recovery record is rebuilt or dropped, never carried.** It
//! is parity over the bytes of the archive as they stood, so after a
//! rewrite it would protect a file that no longer exists. When the source
//! had one it is recomputed over the rewritten archive at the same
//! percentage; [`set_recovery`] adds, replaces or removes one.
//!
//! **A member header is re-emitted in the REWRITE form of spec G 3.6.5**:
//! both size fields take their natural width instead of the reserve the
//! writer makes for a member it is about to stream. That is what the
//! reference does to a member it re-emits, and with it `lock` and `remove`
//! produce the reference's own bytes.
//!
//! **What is refused, by name.** A rewrite never decodes, so it cannot do
//! what the reference does by recompressing: [`remove`] on a SOLID archive
//! is refused, because the members after the removed one are decoded
//! against its history. Header-encrypted archives and self-extracting
//! archives are refused, and so is a member-level change to one volume of
//! a set. Each refusal says which it is.

use std::io::Write;

use crate::{Archive, HostOs, Result};

pub(crate) mod header;
mod rewrite;

pub use rewrite::EditReport;

use rewrite::Edit;

/// What an edit is told beside the change itself.
///
/// One thing today: the system the rewrite is made ON. A service header
/// the rewrite builds (the comment, the quick-open index, the recovery
/// record) names that system in its host field, as
/// [`WriteOptions::host_os`](crate::WriteOptions::host_os) has a create
/// name it (spec G 3.3.4). A member's own host field is never touched: it
/// says where the member came from. The default is the system this build
/// runs on, which is what the functions of this module use; a caller that
/// wants the same bytes from every machine names one.
///
/// Each method is the function of the same name, under these options.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EditOptions {
    /// The system the rewrite is made on.
    pub host_os: HostOs,
}

impl Default for EditOptions {
    fn default() -> EditOptions {
        EditOptions {
            host_os: rewrite::BUILD_HOST,
        }
    }
}

impl EditOptions {
    fn run(&self, src: &Archive, edit: Edit<'_>, out: impl Write) -> Result<EditReport> {
        rewrite::rewrite(
            src,
            &Edit {
                host: Some(self.host_os),
                ..edit
            },
            out,
        )
    }

    /// [`set_comment`] under these options.
    pub fn set_comment(
        &self,
        src: &Archive,
        comment: Option<&[u8]>,
        out: impl Write,
    ) -> Result<()> {
        let edit = Edit {
            comment: Some(comment),
            ..Edit::default()
        };
        self.run(src, edit, out).map(|_| ())
    }

    /// [`lock`] under these options.
    pub fn lock(&self, src: &Archive, out: impl Write) -> Result<()> {
        let edit = Edit {
            lock: Some(true),
            ..Edit::default()
        };
        self.run(src, edit, out).map(|_| ())
    }

    /// [`remove`] under these options.
    pub fn remove(&self, src: &Archive, names: &[&[u8]], out: impl Write) -> Result<EditReport> {
        let edit = Edit {
            remove: names,
            ..Edit::default()
        };
        self.run(src, edit, out)
    }

    /// [`rename`] under these options.
    pub fn rename(
        &self,
        src: &Archive,
        from: &[u8],
        to: &[u8],
        out: impl Write,
    ) -> Result<EditReport> {
        self.rename_many(src, &[(from, to)], out)
    }

    /// [`rename_many`] under these options.
    pub fn rename_many(
        &self,
        src: &Archive,
        pairs: &[(&[u8], &[u8])],
        out: impl Write,
    ) -> Result<EditReport> {
        let edit = Edit {
            rename: pairs,
            ..Edit::default()
        };
        self.run(src, edit, out)
    }

    /// [`set_recovery`] under these options.
    pub fn set_recovery(
        &self,
        src: &Archive,
        percent: Option<u32>,
        out: impl Write,
    ) -> Result<EditReport> {
        let edit = Edit {
            recovery: Some(percent),
            ..Edit::default()
        };
        self.run(src, edit, out)
    }
}

/// Write `src` out again carrying `comment` as its archive comment, or
/// carrying none when that is `None`.
///
/// Nothing else about the archive is disturbed: whether it was locked stays
/// what it was, and every member travels undecoded. `out` is a fresh
/// destination, never the file `src` was opened on, and putting the result
/// in the original's place afterwards belongs to the caller.
pub fn set_comment(src: &Archive, comment: Option<&[u8]>, out: impl Write) -> Result<()> {
    EditOptions::default().set_comment(src, comment, out)
}

/// Write `src` out again with its lock flag raised, keeping the comment it
/// already carries.
///
/// The flag lives in the main header, which is the one block a rewrite
/// rebuilds, so this is [`set_comment`]'s rewrite with the comment left
/// alone. As there, the caller replaces the file.
pub fn lock(src: &Archive, out: impl Write) -> Result<()> {
    EditOptions::default().lock(src, out)
}

/// Write `src` out again without the members `names` name, which is the
/// reference's `d` command.
///
/// Names are matched against the name the archive STORES, exactly, and a
/// name the archive stores more than once names every member that stores
/// it, as it does to the reference. A name
/// the archive does not hold is reported in [`EditReport::unmatched`]
/// rather than refused, so one call can be given a list and the caller
/// decides what to say about the misses.
///
/// Refused on a SOLID archive: the members after the removed one are
/// decoded against its history, and a rewrite never recompresses.
pub fn remove(src: &Archive, names: &[&[u8]], out: impl Write) -> Result<EditReport> {
    EditOptions::default().remove(src, names, out)
}

/// Write `src` out again with the member named `from` stored as `to`,
/// which is the reference's `rn` command.
///
/// The member keeps its place in the archive, its data bytes and every
/// header field but the name. Where the archive stores `from` more than
/// once, every member of that name is renamed, as the reference does. `to` is checked exactly as
/// [`Writer::add`](crate::Writer::add) checks a name.
///
/// **This works on a solid archive**, where [`remove`] does not: nothing
/// in a solid chain depends on a member's name, so the data is untouched
/// and the chain still decodes. The reference recompresses the archive for
/// a rename; it does not have to.
pub fn rename(src: &Archive, from: &[u8], to: &[u8], out: impl Write) -> Result<EditReport> {
    EditOptions::default().rename(src, from, to, out)
}

/// [`rename`] over several members in one rewrite, old name to new.
///
/// A pair whose old name the archive does not hold is reported in
/// [`EditReport::unmatched`], as [`remove`] reports one.
pub fn rename_many(src: &Archive, pairs: &[(&[u8], &[u8])], out: impl Write) -> Result<EditReport> {
    EditOptions::default().rename_many(src, pairs, out)
}

/// Write `src` out again with an inline recovery record of `percent`,
/// which is the reference's `rr[N]` command; `None` removes the record.
///
/// The record is computed over the rewritten archive, which is the only
/// thing it could usefully cover (SPEC-L 3.5.1: it is parity over the
/// bytes before it).
pub fn set_recovery(src: &Archive, percent: Option<u32>, out: impl Write) -> Result<EditReport> {
    EditOptions::default().set_recovery(src, percent, out)
}
