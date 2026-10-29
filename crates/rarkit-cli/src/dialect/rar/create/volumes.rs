//! The volumes of a set: their names and the files they open.

use super::*;

/// The archive name with its extension off, which is what a volume set's
/// file names are built from.
pub(super) fn volume_stem(archive: &str) -> String {
    let path = Path::new(archive);
    match path.extension() {
        Some(_) => path.with_extension("").to_string_lossy().into_owned(),
        None => archive.to_owned(),
    }
}

/// The first FILE in the archive's directory that a volume set of this
/// stem could be written over, if any.
///
/// How many volumes a run writes, and so how wide their numbers are
/// padded, is known only once it has written them, so every name of the
/// set's PATTERN counts: `stem.partN.rar` for any run of digits N, and
/// under `-vn` also `stem.rN`. (`stem.rar` is the plain existing-archive
/// refusal.) ASCII case is folded, because on a case-insensitive disk
/// `ARC.PART2.RAR` is the file `arc.part2.rar` would open. A directory
/// there is not refused: creating a volume over it fails without harming
/// it, and the failed-create cleanup removes what the run did write.
pub(super) fn existing_volume(archive: &str, classic: bool) -> Option<String> {
    let stem = volume_stem(archive);
    let stem = Path::new(&stem);
    let base = stem.file_name()?.to_string_lossy().to_ascii_lowercase();
    let dir = match stem.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let digits = |text: &str| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
    let mut found: Vec<String> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| !kind.is_dir()))
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| {
            let lower = name.to_ascii_lowercase();
            let Some(rest) = lower
                .strip_prefix(base.as_str())
                .and_then(|rest| rest.strip_prefix('.'))
            else {
                return false;
            };
            let numbered = rest
                .strip_prefix("part")
                .and_then(|rest| rest.strip_suffix(".rar"))
                .is_some_and(digits);
            let old = classic && rest.strip_prefix('r').is_some_and(digits);
            numbered || old
        })
        .collect();
    found.sort();
    let name = found.into_iter().next()?;
    Some(match stem.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => {
            parent.join(name).to_string_lossy().into_owned()
        }
        _ => name,
    })
}

/// How many volumes the set is expected to need, which is what decides the
/// WIDTH the numbers are padded to.
///
/// The reference chooses that width before it writes the second volume, so
/// it cannot be counting them: measured, `-v12k` over 24 kB names three
/// volumes `part1` to `part3` while `-v1k` over the same file names
/// twenty-eight `part01` to `part28`. An estimate from the payload and the
/// volume size gives both.
pub(super) fn estimated_volumes(files: &[Chosen], opts: &Options) -> u32 {
    let Some(size) = opts.volume_size.filter(|size| *size > 0) else {
        return 1;
    };
    let total: u64 = files.iter().map(|file| file.size).sum();
    let estimate = total.div_ceil(size).max(1);
    u32::try_from(estimate).unwrap_or(u32::MAX)
}

/// Where a volume set's volumes go: one file per volume, named by
/// [`rarkit::volume_file_name`].
pub(super) struct Volumes<'a> {
    pub(super) stem: String,
    pub(super) naming: VolumeNaming,
    pub(super) estimate: u32,
    /// What one volume is expected to reach, which decides whether it is
    /// written past the OS cache (`crate::unbuffered::Output`).
    pub(super) expected: u64,
    /// Every volume file created so far, in order, for the failure arm.
    pub(super) created: &'a mut Vec<PathBuf>,
}

impl Volumes<'_> {
    /// The file name volume `index` takes.
    pub(super) fn name(&self, index: u32) -> String {
        rarkit::volume_file_name(&self.stem, index, self.estimate.max(index + 1), self.naming)
    }
}

impl VolumeOut for Volumes<'_> {
    type W = crate::unbuffered::Output;

    fn volume(&mut self, index: u32) -> rarkit::Result<crate::unbuffered::Output> {
        let name = self.name(index);
        // The name is taken first by a create the SYSTEM refuses when a
        // file is already there, under any spelling it holds to be the
        // same name. The look before the run ([`existing_volume`]) folds
        // ASCII case only and is taken once: until 8 Oct 2026 a file
        // whose name differed in the case of a letter outside ASCII, or
        // that appeared after the look, was opened here and written
        // over, exit 0. Only a file this call made is recorded as the
        // run's own, so a failed run never removes the one it refused.
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&name)
            .map_err(|err| {
                rarkit::Error::caller(if err.kind() == std::io::ErrorKind::AlreadyExists {
                    format!("{name} already exists and would be overwritten")
                } else {
                    format!("{name}: {err}")
                })
            })?;
        self.created.push(PathBuf::from(&name));
        crate::unbuffered::Output::create(Path::new(&name), self.expected)
            .map_err(|err| rarkit::Error::caller(format!("{name}: {err}")))
    }

    /// A volume past the OS cache writes its staged tail and is cut back to
    /// its bytes HERE, where a failure is the run's (`Output::close`).
    fn finished(
        &mut self,
        _index: u32,
        mut volume: crate::unbuffered::Output,
    ) -> rarkit::Result<()> {
        volume.close().map_err(rarkit::Error::from)
    }

    /// A volume is a file this provider created itself and writes from
    /// its first byte, so a field laid down as a placeholder can be
    /// corrected where it lies.
    ///
    /// **Without this every stored member's bytes were HELD.** A
    /// `Payload::Reader` states no CRC32, so its fragment header goes down
    /// with a placeholder, and over an output that cannot patch the
    /// writer holds everything after that placeholder until the checksum
    /// is known: one whole volume. Measured on an Apple M3 Mac, 28 Sep 2026,
    /// `a -m0` over one 4 GiB file: 1,030 MiB peak RSS at `-v1g` and
    /// 4,102 MiB at `-v4g`, against rar 7.23's 21 MiB at both. Patching,
    /// the stored bytes are the same and nothing is held.
    ///
    /// It also opens SPEC-G 3.5's budgeted mode to the shipped tool: under
    /// `-mm` a compressed member of a non-solid set larger than one window
    /// streams instead of being held whole past the ceiling.
    fn can_patch(&self) -> bool {
        true
    }

    fn patch(
        &mut self,
        volume: &mut crate::unbuffered::Output,
        at: u64,
        bytes: &[u8],
    ) -> rarkit::Result<()> {
        use std::io::{Seek as _, SeekFrom};
        let failed = rarkit::Error::from;
        let end = volume.stream_position().map_err(failed)?;
        volume.seek(SeekFrom::Start(at)).map_err(failed)?;
        volume.write_all(bytes).map_err(failed)?;
        volume.seek(SeekFrom::Start(end)).map_err(failed)?;
        Ok(())
    }

    /// A volume is opened for reading too (`crate::unbuffered::Output`), so a
    /// recovery record (`-rr`) is computed from the volume read back
    /// rather than from a copy of it the writer would otherwise keep: a
    /// whole volume in memory, 1 GiB at `-v1g`.
    fn can_read_back(&self) -> bool {
        true
    }

    fn read_back(
        &mut self,
        volume: &mut crate::unbuffered::Output,
        at: u64,
        buf: &mut [u8],
    ) -> rarkit::Result<()> {
        use std::io::{Read as _, Seek as _, SeekFrom};
        let failed = rarkit::Error::from;
        let end = volume.stream_position().map_err(failed)?;
        volume.seek(SeekFrom::Start(at)).map_err(failed)?;
        volume.read_exact(buf).map_err(failed)?;
        volume.seek(SeekFrom::Start(end)).map_err(failed)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file that is at a volume's name when the volume is opened, which
    /// the look before the run did not see, is not written over: on any
    /// system, whatever its rule for names.
    #[test]
    fn a_volume_is_not_opened_over_a_file_that_is_there() {
        let dir = std::env::temp_dir().join(format!("rarfast-volopen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut created = Vec::new();
        let mut volumes = Volumes {
            stem: dir.join("set").to_string_lossy().into_owned(),
            naming: VolumeNaming::Numbered,
            estimate: 3,
            expected: 0,
            created: &mut created,
        };
        let planted = volumes.name(1);
        std::fs::write(&planted, b"0123456789").unwrap();
        assert!(volumes.volume(0).is_ok());
        let refused = volumes.volume(1).err().map(|err| err.to_string());
        assert!(refused.is_some_and(|text| text.contains("already exists")));
        assert_eq!(std::fs::read(&planted).unwrap(), b"0123456789");
        // Only the volume this run made is its own to remove.
        assert_eq!(created, [PathBuf::from(volumes_name(&dir, 0))]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn volumes_name(dir: &Path, index: u32) -> String {
        rarkit::volume_file_name(
            &dir.join("set").to_string_lossy(),
            index,
            3,
            VolumeNaming::Numbered,
        )
    }
}
