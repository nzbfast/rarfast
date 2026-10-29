//! Where a member is written: its path under the destination, and the
//! directories above it.

use super::*;

/// The longest output path, in characters, written on Windows (see
/// [`Run::too_long`]): Linux's PATH_MAX.
#[cfg(windows)]
const LONGEST_PATH: usize = 4_096;

/// The destination as the directory members are joined onto: the path
/// the caller gave, less THIS system's own separators at its end, and
/// never less than a root.
///
/// On Unix a `\` is a character of a name, so `out\/` is the directory
/// `out\` (unrar 7.23 extracts into it, measured 10 Oct 2026); until then
/// both `/` and `\` were cut on every system and the members went into
/// `out`. A destination that IS a root keeps one separator: `/` cut to
/// nothing joined every member onto the current directory instead, and a
/// Windows `C:\` cut to `C:` names the drive's current directory, not its
/// root. The progress lines print the caller's own spelling, not this.
pub(super) fn dest_base(dest: &str) -> &str {
    let cut = dest.trim_end_matches(std::path::is_separator);
    let was_root = cut.is_empty() || (cfg!(windows) && cut.ends_with(':'));
    if was_root && cut.len() < dest.len() {
        // A separator is one byte, so this is the root and no more.
        &dest[..=cut.len()]
    } else {
        cut
    }
}

/// The directories the walk takes as there, and nothing else may say so.
///
/// `before` is every path that existed before this run touched anything:
/// the destination, every directory a target sits under, and every
/// directory member's own path. With workers creating parents ahead of
/// the walk, "does this directory exist" asked of the FILESYSTEM answers
/// yes for a directory nobody has announced yet, so the `Creating` lines
/// are decided against that snapshot plus `made`, the directories this
/// run made or announced: exactly what the filesystem said when the walk
/// was the only writer. `before` is empty outside `x` and `e`.
///
/// The two sets and the memo in front of them ([`ParentMemo`]) live
/// behind this one type so that a path can leave a set, or a set be
/// replaced, ONLY through [`KnownDirs::unmake`] and
/// [`KnownDirs::set_before`], and both empty the memo: a yes the memo
/// kept after its set took it back would be a wrong answer.
#[derive(Default)]
pub(super) struct KnownDirs {
    before: HashSet<PathBuf>,
    made: HashSet<PathBuf>,
    memo: ParentMemo,
}

impl KnownDirs {
    /// Whether `path` stood before the run.
    pub(super) fn was_there(&self, path: &Path) -> bool {
        self.before.contains(path)
    }

    /// Whether this run made (or announced) `path`.
    pub(super) fn made(&self, path: &Path) -> bool {
        self.made.contains(path)
    }

    /// Whether `path` is there as far as the walk is concerned.
    pub(super) fn exists(&self, path: &Path) -> bool {
        self.before.contains(path) || self.made.contains(path)
    }

    /// This run made `path`; `false` where it already had. A path added
    /// takes no yes back, so the memo stands.
    pub(super) fn make(&mut self, path: PathBuf) -> bool {
        self.made.insert(path)
    }

    /// This run removed a directory it had made: the memo is emptied.
    pub(super) fn unmake(&mut self, path: &Path) {
        self.made.remove(path);
        self.memo.forget();
    }

    /// The snapshot of what stood before the run: the memo is emptied.
    pub(super) fn set_before(&mut self, there: HashSet<PathBuf>) {
        self.before = there;
        self.memo.forget();
    }

    /// [`KnownDirs::exists`] for a file's parent, the question every file
    /// asks: answered by the memo where it holds these very bytes, and by
    /// the sets otherwise, whose yes the memo then keeps. Nothing but a
    /// yes of the sets ever goes into the memo.
    pub(super) fn parent_exists(&mut self, parent: &Path) -> bool {
        let bytes = parent.as_os_str().as_encoded_bytes();
        let bucket = ParentMemo::bucket(bytes);
        if self.memo.holds(bucket, bytes) {
            return true;
        }
        let there = self.exists(parent);
        if there {
            self.memo.keep(bucket, bytes);
        }
        there
    }

    /// Whether the memo alone would answer for `parent` (the unit rows).
    #[cfg(test)]
    fn parent_known(&self, parent: &Path) -> bool {
        self.memo.knows(parent)
    }
}

/// The parents of files that [`Run::ensure_parents`] has already found to
/// exist, by the bytes of their paths: 512 buckets of two paths each, the
/// two asked last kept.
///
/// Every file asks whether its parent directory is there, and the answer
/// lives in two sets keyed by the path, each hashed part by part with the
/// standard hasher: about 2,000 user instructions a file in an archive of
/// small files, for an answer that was the same for the last file of the
/// same directory. A hit here is a path whose very bytes the sets have
/// already said yes to, so it answers what they would. The bucket's
/// number is no promise: a miss, or more paths in one bucket than it
/// holds, asks the sets as before and is never a wrong answer.
///
/// WHAT A MISS COSTS, counted (a Zen 4 box, plain builds, 12 Oct 2026):
/// on an archive of 20,000 files in 4,000 folders visited in turn, which
/// no memo of this size can hold, about 300 user instructions a file
/// more than the sets alone, under one percent of that extract; on 200
/// folders visited in turn every file hits and saves about 2,100. So an
/// archive made to crowd it pays that one percent and no more. Two paths
/// a bucket, because folders visited in turn brought two of them to one
/// bucket often enough, each putting the other out at every file, to
/// lose four tenths of what the memo saves (counted, 200 folders in 256
/// single places). It is emptied whenever either set loses a path or is
/// replaced ([`KnownDirs`] sees to it).
struct ParentMemo {
    /// Two paths a bucket, the one asked last first; an empty one is no
    /// path (a parent's path is never empty). Each keeps its room when
    /// another path takes its place, so a miss allocates nothing once
    /// the memo is warm.
    buckets: Vec<[Vec<u8>; 2]>,
}

impl Default for ParentMemo {
    fn default() -> Self {
        Self {
            buckets: (0..Self::BUCKETS)
                .map(|_| [Vec::new(), Vec::new()])
                .collect(),
        }
    }
}

impl ParentMemo {
    /// A power of two: the bucket is the top bits of a 64-bit mix.
    const BUCKETS: usize = 512;

    /// The bucket a path's bytes fall in: eight bytes a step, one multiply.
    fn bucket(bytes: &[u8]) -> usize {
        const BY: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut mix = bytes.len() as u64;
        let (words, rest) = bytes.as_chunks::<8>();
        for word in words {
            mix = (mix.rotate_left(5) ^ u64::from_le_bytes(*word)).wrapping_mul(BY);
        }
        let mut last = 0u64;
        for byte in rest {
            last = (last << 8) | u64::from(*byte);
        }
        mix = (mix.rotate_left(5) ^ last).wrapping_mul(BY);
        (mix >> (64 - Self::BUCKETS.trailing_zeros())) as usize
    }

    /// Whether `bucket` holds these very bytes.
    fn holds(&self, bucket: usize, bytes: &[u8]) -> bool {
        let pair = &self.buckets[bucket];
        !bytes.is_empty() && (pair[0] == bytes || pair[1] == bytes)
    }

    /// These bytes take `bucket`'s first place, what was there the second,
    /// and what was second is put out. For bytes the sets said yes to.
    fn keep(&mut self, bucket: usize, bytes: &[u8]) {
        let pair = &mut self.buckets[bucket];
        if pair[0] != bytes {
            pair.swap(0, 1);
            pair[0].clear();
            pair[0].extend_from_slice(bytes);
        }
    }

    /// Whether these very bytes were learned and not since put out.
    #[cfg(test)]
    fn knows(&self, dir: &Path) -> bool {
        let bytes = dir.as_os_str().as_encoded_bytes();
        self.holds(Self::bucket(bytes), bytes)
    }

    /// [`ParentMemo::keep`] by the path (the unit rows).
    #[cfg(test)]
    fn learn(&mut self, dir: &Path) {
        let bytes = dir.as_os_str().as_encoded_bytes();
        self.keep(Self::bucket(bytes), bytes);
    }

    /// Nothing is known: a set lost a path, or was replaced.
    fn forget(&mut self) {
        for pair in &mut self.buckets {
            pair[0].clear();
            pair[1].clear();
        }
    }
}

impl Run<'_> {
    /// The filesystem path this member extracts to, or `None` when the
    /// archived name may not be joined onto the destination.
    ///
    /// **This is the only thing in this file that may reach the filesystem.**
    /// `member_display_name` is progress TEXT: it concatenates the
    /// destination as the caller typed it with the name as the archive
    /// spells it, which is right for a progress line and catastrophic for
    /// `File::create` - an entry named `../escape.bin` extracted to `out/`
    /// resolved to `out/../escape.bin`, wrote outside the destination, and
    /// still reported `All OK` (fixed 9 Sep 2026; the earlier engine's front had
    /// refused the same archive all along).
    ///
    /// The name judged is the member's ON-DISK name (`disk_name`: cut at a
    /// NUL, and at invalid UTF-8 where the host or the format needs it, a
    /// RAR 5 Windows `\` written `_`), never its display text, and
    /// `safepath::disk_relative_path_into` refuses a leading separator, a
    /// drive or UNC prefix under Windows rules, and any `..` component of
    /// that name, so no cut or escape can carry one past it. Flattening for
    /// `e` takes the base name BEFORE validating, so a hostile directory
    /// part is discarded rather than trusted. On a Windows target a name
    /// Win32 cannot store as written (a trailing dot or space, a refused
    /// character, a device name) is mapped there too: `safepath` rule 5,
    /// SPEC-API-rarkit.md question 20. The progress line shows the same
    /// mapped name (`member_display_name`); the listing shows the stored
    /// one.
    pub(super) fn member_target(&self, index: usize) -> Option<&Path> {
        match self.target_at.get(index)? {
            Target::Pooled(start, end) => Some(Path::new(&self.targets[*start..*end])),
            Target::Owned(path) => Some(path),
            Target::Unresolved | Target::Refused | Target::Nameless | Target::DestinationItself => {
                None
            }
        }
    }

    /// The name [`Run::member_target`] resolves for a member, and the root
    /// it is resolved under.
    ///
    /// The name is the member's ON-DISK name ([`Member::disk_name`]),
    /// never its display text, and `e` takes its base on the separators
    /// the host's rules name: on Unix a `\` is a character of the name.
    pub(super) fn target_parts(&self, index: usize) -> (&Path, &[u8]) {
        let member = &self.plan[index].member;
        let stored = member.disk_name();
        let name = match self.mode {
            Mode::Extract { flat: true } => stored
                .rsplit(|&b| b == b'/' || (cfg!(windows) && b == b'\\'))
                .next()
                .unwrap_or(stored),
            _ => stored,
        };
        let base = dest_base(&self.dest);
        let root = if base.is_empty() {
            Path::new("")
        } else {
            Path::new(base)
        };
        (root, name)
    }

    /// Resolves every selected member's output path once, through one
    /// reused buffer, into [`Run::targets`]: the same validation
    /// (`safepath::archive_relative_path_into`, the code
    /// `archive_relative_path` runs), with no path allocated per member
    /// and none resolved twice. The string is sized once from the names;
    /// an estimate, since a Windows mapping can lengthen a name, and a
    /// sum that would overflow sizes nothing. Held for the run: about the
    /// selected names' total length plus the destination per member.
    pub(super) fn pool_targets(&mut self) {
        let mut target_at = vec![Target::Unresolved; self.plan.len()];
        let per = self.dest.len() + 1;
        let estimate = self.selected.iter().try_fold(0_usize, |sum, &index| {
            sum.checked_add(per)?
                .checked_add(self.plan[index].member.name.len())
        });
        let mut targets = String::with_capacity(estimate.unwrap_or(0));
        let mut buf = PathBuf::new();
        for &index in self.selected.iter() {
            let (root, name) = self.target_parts(index);
            if name.is_empty() {
                let member = &self.plan[index].member;
                let all_path = self.mode == (Mode::Extract { flat: true })
                    && !member.is_dir
                    && !member.disk_name().is_empty()
                    && !self.dest.is_empty();
                target_at[index] = if all_path {
                    Target::DestinationItself
                } else {
                    Target::Nameless
                };
                continue;
            }
            // A FILE whose on-disk name ends in a separator names no file
            // (`a/` once a cut took `a/\xffb`'s tail): the reference
            // fails its create. Refused here, before `safepath` drops
            // the empty last component and writes a file `a`.
            if !self.plan[index].member.is_dir && name.ends_with(b"/") {
                target_at[index] = Target::Refused;
                continue;
            }
            let resolved = crate::safepath::disk_relative_path_into(
                &mut buf,
                root,
                name,
                crate::safepath::NameRules::HOST,
            );
            target_at[index] = match (resolved, buf.to_str()) {
                (Err(_), _) => Target::Refused,
                (Ok(()), Some(text)) => {
                    let start = targets.len();
                    targets.push_str(text);
                    Target::Pooled(start, targets.len())
                }
                (Ok(()), None) => Target::Owned(buf.clone()),
            };
        }
        self.targets = targets;
        self.target_at = target_at;
    }

    /// Says that an entry was refused, and makes the run fail.
    ///
    /// Counted as an error so the exit code is non-zero: silently skipping
    /// a hostile entry would leave `All OK` on a run that did not extract
    /// what the archive claimed.
    pub(super) fn refuse_unsafe_name(&mut self, index: usize) {
        let name = self.plan[index].member.name.clone();
        self.complain(&name, "- would be written outside the destination");
        self.say("\n");
        self.errors += 1;
        // The exit code is built from `failures`, NOT from `errors`:
        // bumping the counter alone prints "Total errors: 1" and still
        // exits 0, which is the shape of the original defect.
        self.failures.push((index, Failure::LeavesDestination));
        self.done.insert(index);
    }

    /// Refuses a member a level of whose path is still a LINK
    /// ([`Run::ensure_parents`]'s `false`). Making ahead ends first: a
    /// helper takes a directory as ready once the walk has passed its
    /// first member, refused or not, and would make the next file there
    /// by its full path, through the link. Called before the walk marks
    /// this member passed, so no helper ever finds that directory ready.
    pub(super) fn refuse_through_link(&mut self, index: usize) {
        #[cfg(any(
            all(target_os = "linux", feature = "parallel"),
            all(target_os = "macos", feature = "parallel")
        ))]
        self.halt_ahead();
        self.refuse_unsafe_name(index);
    }

    /// Creates every missing parent directory of `path`, announcing each.
    ///
    /// Announced the way a member's own line is: the destination as the
    /// caller typed it, then the archived part in the platform's own
    /// separator. The reference on Windows prints `Creating out/sub` over
    /// `x arc.rar out/` beside `Extracting out/sub\nested.txt`; showing
    /// the joined path printed `out\sub` there.
    /// Whether `path` exists as far as the walk's own output is concerned:
    /// it did before the run, or this run has announced (or silently made)
    /// it. See [`KnownDirs`] for why the filesystem is not asked.
    pub(super) fn logically_exists(&self, path: &Path) -> bool {
        self.dirs.exists(path)
    }

    /// Windows: why a member's output `path` past 4,096 characters
    /// (`LONGEST_PATH`) is not written, or `None` for any shorter one; `None`
    /// everywhere else, whose system's own limit ends the path (Linux's
    /// PATH_MAX, 4,096 bytes). Windows accepts some 32,767, and a deep
    /// name's cost grows with the square of its depth there: 8,000 levels
    /// took 49 s on a hosted runner (run 40655614997), FOR EACH such
    /// member. Refused before anything is made for it, with the system's
    /// own reason for a name too long (FROM-STUDIO 1001, 1007).
    /// Handle-relative creation lifts it (0.9.1).
    pub(super) fn too_long(path: &Path) -> Option<std::io::Error> {
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt as _;
            // ERROR_FILENAME_EXCED_RANGE.
            const TOO_LONG: i32 = 206;
            if path.as_os_str().encode_wide().nth(LONGEST_PATH).is_some() {
                return Some(std::io::Error::from_raw_os_error(TOO_LONG));
            }
        }
        #[cfg(not(windows))]
        let _ = path;
        None
    }

    /// Makes every missing parent of `path`, as said above [`Run::logically_exists`].
    /// `false` where a level is still a LINK once the walk has tried to
    /// replace it (a folder closed to writing keeps it): a create by the
    /// full path would go through it, so the caller refuses the member
    /// (spec F 3.8.3). Any other level that could not be made is left to
    /// the member's own create to fail, as it was.
    #[must_use]
    pub(super) fn ensure_parents(&mut self, path: &Path) -> bool {
        let Some(parent) = path.parent() else {
            return true;
        };
        if parent.as_os_str().is_empty() || self.dirs.parent_exists(parent) {
            return true;
        }
        // The parent itself is not there (just asked): the walk up starts
        // at the level above it.
        let mut stack = vec![parent.to_path_buf()];
        let mut cursor = parent.parent();
        while let Some(dir) = cursor {
            if dir.as_os_str().is_empty() || self.logically_exists(dir) {
                break;
            }
            stack.push(dir.to_path_buf());
            cursor = dir.parent();
        }
        let base = PathBuf::from(dest_base(&self.dest));
        for dir in stack.into_iter().rev() {
            // A worker may have made it already; either way it is this
            // run's, and announced here, in archive order, exactly once. A
            // LINK standing in its place is replaced by a real directory,
            // so nothing is ever created through one (spec F 3.8.3).
            links::real_dir(&dir);
            // The one stat this always made, now kept: the mode the
            // directory was made with, so its own member need not set
            // the same bits again (see `made_modes`). An lstat, so a link
            // that could not be replaced never passes for the directory.
            let Some(made) = fs::symlink_metadata(&dir).ok().filter(fs::Metadata::is_dir) else {
                if links::is_link(&dir) {
                    return false;
                }
                continue;
            };
            if self.dirs.make(dir.clone()) {
                if let Some(capture) = self.capture.as_mut() {
                    capture.dirs.push(dir.clone());
                }
                self.made_modes
                    .insert(dir.clone(), mode::permission_bits(&made));
                let shown = match dir.strip_prefix(&base) {
                    Ok(relative) if !base.as_os_str().is_empty() => {
                        format!(
                            "{}{}",
                            self.dest,
                            super::progress_line_name(relative.as_os_str().as_encoded_bytes())
                        )
                    }
                    _ => super::progress_line_name(dir.as_os_str().as_encoded_bytes()),
                };
                self.creating(&shown);
            }
        }
        true
    }
}

impl Run<'_> {
    /// The destination directory itself, announced once.
    pub(super) fn ensure_dest(&mut self) {
        if self.dest.is_empty() {
            return;
        }
        // Once this run has made it every later call would change nothing,
        // so it returns before building the owned path it would insert.
        let trimmed = dest_base(&self.dest);
        if trimmed.is_empty() || self.dirs.made(Path::new(trimmed)) {
            return;
        }
        let trimmed = trimmed.to_owned();
        let path = PathBuf::from(&trimmed);
        if self.logically_exists(&path) {
            self.dirs.make(path);
            return;
        }
        // The levels about to be made, outermost first, for a member whose
        // `open` is being captured (see `Run::held`).
        let missing: Vec<PathBuf> = if self.capture.is_some() {
            let mut levels: Vec<PathBuf> = path
                .ancestors()
                .take_while(|level| !level.as_os_str().is_empty() && !level.exists())
                .map(Path::to_path_buf)
                .collect();
            levels.reverse();
            levels
        } else {
            Vec::new()
        };
        if fs::create_dir_all(&path).is_ok() && self.dirs.make(path) {
            if let Some(capture) = self.capture.as_mut() {
                capture.dirs.extend(missing);
            }
            self.creating(&trimmed);
        }
    }

    /// The directories above a path the caller TYPED at `Enter new name:`,
    /// made where they are missing and announced as the reference
    /// announces them (`Creating    sub2`, unrar 7.23, 2 Oct 2026). The
    /// path is the caller's own, read as the reference reads it: from the
    /// current directory, not the destination, and wherever it points.
    /// Nothing that is already there is touched, a link least of all, which
    /// is why this is not [`Run::ensure_parents`].
    pub(super) fn make_typed_parents(&mut self, path: &Path) {
        let Some(parent) = path.parent().filter(|dir| !dir.as_os_str().is_empty()) else {
            return;
        };
        let mut missing: Vec<PathBuf> = parent
            .ancestors()
            .take_while(|level| !level.as_os_str().is_empty() && !level.exists())
            .map(Path::to_path_buf)
            .collect();
        missing.reverse();
        for dir in missing {
            if fs::create_dir(&dir).is_ok() {
                let shown = super::progress_line_name(dir.as_os_str().as_encoded_bytes());
                self.dirs.make(dir);
                self.creating(&shown);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::dest_base;
    use super::{KnownDirs, ParentMemo};
    use std::collections::HashSet;
    use std::path::{Path, PathBuf};

    /// A YES NEVER OUTLIVES ITS SET. The two ways a path stops being there
    /// (this run removes a directory it made; the snapshot of what stood
    /// before is replaced) are the only two [`KnownDirs`] has, and after
    /// either the memo knows nothing: a parent that is no longer there is
    /// asked of the sets again and answered no.
    #[test]
    fn a_path_that_leaves_a_set_takes_its_yes_out_of_the_memo() {
        let (made, other) = (Path::new("out/made"), Path::new("out/other"));
        let mut dirs = KnownDirs::default();
        // Not there: no, and nothing is learned of it.
        assert!(!dirs.parent_exists(made));
        assert!(!dirs.parent_known(made));
        assert!(dirs.make(made.to_path_buf()));
        assert!(dirs.make(other.to_path_buf()));
        assert!(dirs.parent_exists(made) && dirs.parent_exists(other));
        assert!(dirs.parent_known(made) && dirs.parent_known(other));
        // The run removes one directory it made: no yes is kept, not the
        // other's either, and the sets answer for both.
        dirs.unmake(made);
        assert!(!dirs.parent_known(made) && !dirs.parent_known(other));
        assert!(
            !dirs.parent_exists(made),
            "a path that is gone was answered yes"
        );
        assert!(!dirs.parent_known(made), "a path that is gone was learned");
        assert!(dirs.parent_exists(other));

        let before = Path::new("out/before");
        dirs.set_before(HashSet::from([before.to_path_buf()]));
        assert!(dirs.was_there(before) && !dirs.made(before));
        assert!(dirs.parent_exists(before) && dirs.parent_exists(other));
        assert!(dirs.parent_known(before) && dirs.parent_known(other));
        // The snapshot is replaced: again nothing is known.
        dirs.set_before(HashSet::new());
        assert!(!dirs.parent_known(before) && !dirs.parent_known(other));
        assert!(!dirs.parent_exists(before) && dirs.parent_exists(other));
    }

    /// AN ARCHIVE MADE TO CROWD THE MEMO GETS THE OLD SPEED AND NEVER A
    /// WRONG ANSWER. Forty paths that all fall in ONE bucket (found by
    /// trying names, as a hostile archive's author would): the memo holds
    /// the last two of them alone, so the rest are asked of the sets as
    /// they always were, and the answer is right for every one, asked in
    /// any order; a path of the same bucket that was never made is known
    /// to neither.
    #[test]
    fn a_crowded_bucket_costs_a_question_and_never_a_wrong_answer() {
        let bucket_of = |dir: &Path| ParentMemo::bucket(dir.as_os_str().as_encoded_bytes());
        let mut crowd: Vec<PathBuf> = (0..)
            .map(|n| PathBuf::from(format!("out/crowd{n}/sub")))
            .filter(|dir| bucket_of(dir) == 7)
            .take(41)
            .collect();
        let never = crowd.pop().unwrap();
        let mut dirs = KnownDirs::default();
        for dir in &crowd {
            assert!(dirs.make(dir.clone()));
            assert!(dirs.parent_exists(dir));
            assert!(dirs.parent_known(dir));
        }
        let (kept, put_out) = crowd.split_at(crowd.len() - 2);
        let (kept, put_out) = (put_out, kept);
        assert!(kept.iter().all(|dir| dirs.parent_known(dir)));
        for dir in put_out {
            assert!(
                !dirs.parent_known(dir),
                "{dir:?}: three paths in one bucket"
            );
        }
        // Every path of the crowd, round and round: yes each time.
        for _ in 0..3 {
            for dir in &crowd {
                assert!(dirs.parent_exists(dir), "{dir:?}: the sets lost a path");
            }
        }
        assert!(!dirs.parent_known(&never) && !dirs.parent_exists(&never));
    }

    /// The memo answers yes only for the very bytes it was told, keeps two
    /// paths a bucket (two folders visited in turn do not put each other
    /// out), and knows nothing once it is told to forget.
    #[test]
    fn the_parent_memo_says_yes_only_to_what_it_was_told() {
        let mut memo = ParentMemo::default();
        let dirs: Vec<PathBuf> = (0..3 * ParentMemo::BUCKETS)
            .map(|n| PathBuf::from(format!("out/d{n:04}/sub")))
            .collect();
        assert!(dirs.iter().all(|dir| !memo.knows(dir)));
        memo.learn(&dirs[0]);
        assert!(memo.knows(&dirs[0]));
        assert!(!memo.knows(Path::new("out/d0000")));
        assert!(!memo.knows(Path::new("out/d0000/sub/")));
        // Two paths of one bucket, learned in turn again and again: both
        // stay.
        let bucket_of = |dir: &Path| ParentMemo::bucket(dir.as_os_str().as_encoded_bytes());
        let twin = dirs[1..]
            .iter()
            .find(|dir| bucket_of(dir) == bucket_of(&dirs[0]))
            .expect("more paths than buckets");
        for _ in 0..3 {
            memo.learn(twin);
            memo.learn(&dirs[0]);
            assert!(memo.knows(twin) && memo.knows(&dirs[0]));
        }
        for dir in &dirs {
            memo.learn(dir);
            assert!(memo.knows(dir), "{dir:?} was just learned");
        }
        // Two paths a bucket at most, and none known that was not learned.
        let known = dirs.iter().filter(|dir| memo.knows(dir)).count();
        assert!(known <= 2 * ParentMemo::BUCKETS, "{known} known");
        assert!(
            known > ParentMemo::BUCKETS,
            "{known}: the buckets are not spread"
        );
        assert!(memo.knows(dirs.last().unwrap()));
        assert!(!memo.knows(Path::new("out/never/sub")));
        memo.forget();
        assert!(dirs.iter().all(|dir| !memo.knows(dir)));
    }

    /// The directory a destination names, by computation alone: nothing
    /// here touches the filesystem, the root least of all.
    #[test]
    fn a_destination_keeps_its_root_and_its_own_characters() {
        assert_eq!(dest_base(""), "");
        assert_eq!(dest_base("out/"), "out");
        assert_eq!(dest_base("out//"), "out");
        assert_eq!(dest_base("a/b/"), "a/b");
        assert_eq!(dest_base("out"), "out");
        // A root stays a root, however many separators spell it.
        assert_eq!(dest_base("/"), "/");
        assert_eq!(dest_base("//"), "/");
        assert_eq!(
            std::path::Path::new(dest_base("/")).join("m"),
            std::path::Path::new("/m")
        );
        if cfg!(windows) {
            assert_eq!(dest_base("out\\"), "out");
            assert_eq!(dest_base("out\\/"), "out");
            assert_eq!(dest_base("\\"), "\\");
            assert_eq!(dest_base("C:\\"), "C:\\");
            assert_eq!(dest_base("C:/"), "C:/");
            assert_eq!(dest_base("C:\\out\\"), "C:\\out");
            // Drive-relative as typed: no separator was there to keep.
            assert_eq!(dest_base("C:"), "C:");
        } else {
            // A backslash is a character of the name.
            assert_eq!(dest_base("out\\/"), "out\\");
            assert_eq!(dest_base("out\\"), "out\\");
            assert_eq!(dest_base("\\/"), "\\");
        }
    }
}
