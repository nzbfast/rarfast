//! Whether the device an archive is read from is ROTATIONAL (hard disks,
//! or an array of them), on Linux, from sysfs.
//!
//! **Why the command line asks.** A big stored member's `t` and `p` are
//! read by the engine's wide read, as many readers as the width, and the
//! stored members of one archive are read several at once. A solid-state
//! drive wants that depth; hard disks read fastest in order. On a Synology
//! (RAID 6 of twelve hard disks, btrfs over LVM over md, a 12-core Xeon D),
//! cold, one reader in order beat the default width on every stored shape
//! timed: a stored set of many members in one archive `t` 9.78 s against
//! 6.04 and 5.94 s, the many-member set over 1 GiB volumes 11.03 s against
//! 9.73 and 9.44 s, a 12.9 GB member 8.03 s against 7.14 and 7.60 s (the NAS runs of 1 Oct
//! 2026, K=7, INDICATIVE). So where the source is rotational, and the
//! archive is not in the page cache already (`residency`), the unrar
//! dialect runs such a read on one thread, in order
//! (`dialect::unrar::extract`, `ROTATIONAL_READERS`).
//!
//! **The fact, and only the fact.** A block device says what it is in
//! `queue/rotational`: `1` for a hard disk, `0` otherwise. That file is the
//! evidence; a mount option is NOT (that array's btrfs was mounted `ssd`).
//! A stacked device (device mapper, md) reports for itself, and names what
//! it sits on in `slaves/`; this walks down them, and calls the device
//! rotational only when EVERY layer says `1`, solid state only when every
//! layer says `0`. Anything else (a cache drive in front of hard disks, a
//! file that cannot be read, a file system with no block device at all, a
//! network share) is [`Class::Unknown`], which changes nothing.
//!
//! **Finding the device.** Two routes, the first where it works:
//!
//! 1. the file's `st_dev` as `major:minor`, looked up in
//!    `/sys/dev/block/` (ext4, xfs: the file system sits on the device);
//! 2. where `st_dev` is an anonymous device with no entry there (btrfs
//!    gives every subvolume one), the SOURCE of the mount the path is
//!    under: the line of `/proc/self/mountinfo` with the longest mount
//!    point over the path, whose source is a device node; a device-mapper
//!    node is matched by the name in `/sys/class/block/dm-*/dm/name`.
//!
//! Every read here is of a few small files, once a command; nothing is
//! cached across commands and nothing is written.

use std::path::{Path, PathBuf};

/// What the source's device is, as far as sysfs says.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Class {
    /// Every layer of the device reads `queue/rotational` = 1.
    Rotational,
    /// Every layer reads 0.
    SolidState,
    /// Mixed layers, or the device could not be found or read.
    Unknown,
}

/// How deep a stack of devices is followed before giving up: a partition
/// on md on LVM on dm-crypt is four.
const DEPTH: usize = 8;

/// Where the kernel's two views live; a test points them at a tree of its
/// own.
pub(crate) struct Roots {
    /// `/sys`.
    pub(crate) sys: PathBuf,
    /// `/proc/self/mountinfo`.
    pub(crate) mountinfo: PathBuf,
}

impl Roots {
    #[cfg_attr(not(all(target_os = "linux", target_env = "gnu")), allow(dead_code))]
    fn system() -> Roots {
        Roots {
            sys: PathBuf::from("/sys"),
            mountinfo: PathBuf::from("/proc/self/mountinfo"),
        }
    }
}

/// The class of the device `path` (an archive file) is read from.
///
/// A count-only knob (feature `read-depth-knob`, never shipped):
/// `RARFAST_ROTATIONAL=1` or `=0` states the class and reads nothing, on
/// any system.
pub(crate) fn of(path: &Path) -> Class {
    #[cfg(feature = "read-depth-knob")]
    match std::env::var("RARFAST_ROTATIONAL")
        .as_deref()
        .map(str::trim)
    {
        Ok("1") => return Class::Rotational,
        Ok("0") => return Class::SolidState,
        _ => {}
    }
    from_sysfs(path)
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn from_sysfs(path: &Path) -> Class {
    use std::os::unix::fs::MetadataExt;
    let Ok(real) = std::fs::canonicalize(path) else {
        return Class::Unknown;
    };
    let Ok(meta) = std::fs::metadata(&real) else {
        return Class::Unknown;
    };
    let dev = meta.dev();
    // glibc's encoding of a device number (`gnu_dev_major`, `gnu_dev_minor`).
    let major = ((dev >> 32) & 0xffff_f000) | ((dev >> 8) & 0x0000_0fff);
    let minor = ((dev >> 12) & 0xffff_ff00) | (dev & 0x0000_00ff);
    class_of(&Roots::system(), &real, major, minor)
}

/// Everywhere else nothing is known, so nothing changes.
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn from_sysfs(_path: &Path) -> Class {
    Class::Unknown
}

/// [`of`] with the kernel's views and the file's device number stated:
/// `real` is the file's canonical path.
#[cfg_attr(not(all(target_os = "linux", target_env = "gnu")), allow(dead_code))]
pub(crate) fn class_of(roots: &Roots, real: &Path, major: u64, minor: u64) -> Class {
    match device_dir(roots, real, major, minor) {
        Some(dir) => layers(roots, &dir, DEPTH).unwrap_or(Class::Unknown),
        None => Class::Unknown,
    }
}

/// The sysfs directory of the device the file `real` (a canonical path,
/// `st_dev` `major:minor`) lives on, by the two routes of the module's
/// head.
fn device_dir(roots: &Roots, real: &Path, major: u64, minor: u64) -> Option<PathBuf> {
    let by_number = roots.sys.join("dev/block").join(format!("{major}:{minor}"));
    if by_number.exists() {
        Some(by_number)
    } else {
        mount_source(&roots.mountinfo, real).and_then(|source| block_dir(roots, &source))
    }
}

/// Whether the device `path` (an OUTPUT's file or directory) is on is, or
/// sits on, a PARITY ARRAY: an md device whose `md/level` reads `raid4`,
/// `raid5` or `raid6`, at any layer of its stack.
///
/// **Why the command line asks** (the write rule on facts, `unbuffered`, a
/// knob). A parity array takes a direct write as a read-modify-write of a
/// stripe unless the write covers whole stripes, and the page cache is what
/// gathers whole stripes: on a RAID 6 of twelve hard disks an extract's
/// direct writes landed 0.24x to 0.75x as soon as cached ones (the NAS
/// rows, 1 Oct 2026). So a slow device that is such an array is
/// written cached, whatever else the rule on facts would say.
///
/// **What this does not see**: an array behind a hardware controller (one
/// disk to the kernel), a network share (no block device here), ZFS raidz
/// and btrfs's own raid5/6 (no md device), and anything off Linux. Those
/// answer `false`, and the rule's other facts decide.
// A test of the rule states the answer itself, so a test build has no caller.
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn parity(path: &Path) -> bool {
    parity_from_sysfs(path)
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[cfg_attr(test, allow(dead_code))]
fn parity_from_sysfs(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(real) = std::fs::canonicalize(path) else {
        return false;
    };
    let Ok(meta) = std::fs::metadata(&real) else {
        return false;
    };
    let dev = meta.dev();
    let major = ((dev >> 32) & 0xffff_f000) | ((dev >> 8) & 0x0000_0fff);
    let minor = ((dev >> 12) & 0xffff_ff00) | (dev & 0x0000_00ff);
    parity_of(&Roots::system(), &real, major, minor)
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
#[cfg_attr(test, allow(dead_code))]
fn parity_from_sysfs(_path: &Path) -> bool {
    false
}

/// [`parity`] with the kernel's views and the file's device number stated:
/// `real` is the path's canonical form.
#[cfg_attr(not(all(target_os = "linux", target_env = "gnu")), allow(dead_code))]
pub(crate) fn parity_of(roots: &Roots, real: &Path, major: u64, minor: u64) -> bool {
    device_dir(roots, real, major, minor).is_some_and(|dir| parity_layers(roots, &dir, DEPTH))
}

/// Whether `dir` (a device's sysfs directory) or anything under it by
/// `slaves/` is an md parity array. A partition of an array has no `md`
/// directory of its own; its array's is one up.
fn parity_layers(roots: &Roots, dir: &Path, depth: usize) -> bool {
    if depth == 0 {
        return false;
    }
    let read = |d: &Path| std::fs::read_to_string(d.join("md/level")).ok();
    let level = read(dir).or_else(|| {
        let real = std::fs::canonicalize(dir).ok()?;
        read(real.parent()?)
    });
    if level.is_some_and(|l| matches!(l.trim(), "raid4" | "raid5" | "raid6")) {
        return true;
    }
    let Ok(slaves) = std::fs::read_dir(dir.join("slaves")) else {
        return false;
    };
    slaves.flatten().any(|slave| {
        parity_layers(
            roots,
            &roots.sys.join("class/block").join(slave.file_name()),
            depth - 1,
        )
    })
}

/// The source field of the mount `real` is under: the mountinfo line whose
/// mount point is the longest one over the path.
fn mount_source(mountinfo: &Path, real: &Path) -> Option<String> {
    let text = std::fs::read_to_string(mountinfo).ok()?;
    let mut best: Option<(usize, String)> = None;
    for line in text.lines() {
        // "id parent major:minor root mount-point options [tags] - type
        // source super-options"; the tags vary in number, the dash does not.
        let Some((before, after)) = line.split_once(" - ") else {
            continue;
        };
        let (Some(point), Some(source)) = (before.split(' ').nth(4), after.split(' ').nth(1))
        else {
            continue;
        };
        let (point, source) = (unescape(point), unescape(source));
        if !real.starts_with(&point) {
            continue;
        }
        // `starts_with` compares whole components, so "/vol" is not over
        // "/volume1"; a later line at the same point shadows an earlier one.
        let depth = Path::new(&point).components().count();
        if best.as_ref().is_none_or(|(d, _)| depth >= *d) {
            best = Some((depth, source));
        }
    }
    best.map(|(_, source)| source)
}

/// mountinfo writes a space, a tab, a newline and a backslash as `\040`,
/// `\011`, `\012` and `\134`.
fn unescape(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    let mut rest = field;
    while let Some(at) = rest.find('\\') {
        out.push_str(&rest[..at]);
        let code = rest.get(at + 1..at + 4);
        match code.and_then(|c| u8::from_str_radix(c, 8).ok()) {
            Some(byte) => {
                out.push(char::from(byte));
                rest = &rest[at + 4..];
            }
            None => {
                out.push('\\');
                rest = &rest[at + 1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// The sysfs directory of the block device a mount's source names, where
/// it names one: `/dev/sda3`, `/dev/md2`, `/dev/mapper/<name>`.
fn block_dir(roots: &Roots, source: &str) -> Option<PathBuf> {
    let node = Path::new(source);
    if !node.starts_with("/dev") {
        // "tmpfs", "//server/share", "server:/export", "overlay": no device.
        return None;
    }
    let class = roots.sys.join("class/block");
    // The node's own name, and the name it resolves to where it is a link
    // (`/dev/mapper/vg-lv` is one on most systems, to `../dm-3`).
    let own = node.file_name()?.to_str()?.to_owned();
    let resolved = std::fs::canonicalize(node)
        .ok()
        .and_then(|p| p.file_name().and_then(|n| n.to_str()).map(str::to_owned));
    for name in resolved.iter().chain(std::iter::once(&own)) {
        let dir = class.join(name);
        if dir.exists() {
            return Some(dir);
        }
    }
    // A device-mapper node that is a device file of its own: find the dm
    // device that carries its name.
    if node.starts_with("/dev/mapper") {
        for entry in std::fs::read_dir(&class).ok()?.flatten() {
            let dir = entry.path();
            let named = std::fs::read_to_string(dir.join("dm/name")).ok();
            if named.is_some_and(|n| n.trim() == own) {
                return Some(dir);
            }
        }
    }
    None
}

/// What `queue/rotational` says for a device directory: its own, or its
/// parent's where the directory is a partition's (a partition has no queue
/// of its own; its disk's directory is one up).
fn rotational(dir: &Path) -> Option<bool> {
    let read = |d: &Path| std::fs::read_to_string(d.join("queue/rotational")).ok();
    let text = read(dir).or_else(|| {
        let real = std::fs::canonicalize(dir).ok()?;
        read(real.parent()?)
    })?;
    match text.trim() {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

/// The class of a device and of everything under it by `slaves/`: `None`
/// where any layer cannot be read or the stack is deeper than `depth`.
fn layers(roots: &Roots, dir: &Path, depth: usize) -> Option<Class> {
    if depth == 0 {
        return None;
    }
    let mut class = if rotational(dir)? {
        Class::Rotational
    } else {
        Class::SolidState
    };
    // A partition's slaves, if any, are its disk's; a plain disk has none.
    let Ok(slaves) = std::fs::read_dir(dir.join("slaves")) else {
        return Some(class);
    };
    for slave in slaves.flatten() {
        let name = slave.file_name();
        let under = roots.sys.join("class/block").join(&name);
        if layers(roots, &under, depth - 1)? != class {
            class = Class::Unknown;
        }
    }
    Some(class)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// A fake `/sys` and mountinfo under a fresh directory.
    struct Tree {
        top: PathBuf,
    }

    impl Tree {
        fn new(tag: &str) -> Tree {
            let top =
                std::env::temp_dir().join(format!("rarfast-devclass-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&top);
            std::fs::create_dir_all(top.join("sys/class/block")).unwrap();
            std::fs::create_dir_all(top.join("sys/dev/block")).unwrap();
            std::fs::create_dir_all(top.join("sys/devices")).unwrap();
            Tree { top }
        }

        fn roots(&self) -> Roots {
            Roots {
                sys: self.top.join("sys"),
                mountinfo: self.top.join("mountinfo"),
            }
        }

        /// A whole device `name` whose queue says `rot`, sitting on `slaves`,
        /// with a device-mapper name where it has one.
        fn device(&self, name: &str, rot: Option<&str>, slaves: &[&str], dm: Option<&str>) {
            let dir = self.top.join("sys/devices").join(name);
            std::fs::create_dir_all(dir.join("queue")).unwrap();
            if let Some(rot) = rot {
                std::fs::write(dir.join("queue/rotational"), format!("{rot}\n")).unwrap();
            }
            if !slaves.is_empty() {
                std::fs::create_dir_all(dir.join("slaves")).unwrap();
                for slave in slaves {
                    std::fs::write(dir.join("slaves").join(slave), b"").unwrap();
                }
            }
            if let Some(dm) = dm {
                std::fs::create_dir_all(dir.join("dm")).unwrap();
                std::fs::write(dir.join("dm/name"), format!("{dm}\n")).unwrap();
            }
            self.link(name, &dir);
        }

        /// A partition `part` of the disk `disk`: a directory inside the
        /// disk's, with no queue of its own.
        fn partition(&self, disk: &str, part: &str) {
            let dir = self.top.join("sys/devices").join(disk).join(part);
            std::fs::create_dir_all(&dir).unwrap();
            self.link(part, &dir);
        }

        /// The md device `name` is an array of `level`.
        fn md(&self, name: &str, level: &str) {
            let dir = self.top.join("sys/devices").join(name).join("md");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("level"), format!("{level}\n")).unwrap();
        }

        fn link(&self, name: &str, dir: &Path) {
            std::os::unix::fs::symlink(dir, self.top.join("sys/class/block").join(name)).unwrap();
        }

        /// `major:minor` is the device `name`.
        fn number(&self, major: u64, minor: u64, name: &str) {
            let to = self.top.join("sys/class/block").join(name);
            let at = self
                .top
                .join("sys/dev/block")
                .join(format!("{major}:{minor}"));
            std::os::unix::fs::symlink(std::fs::canonicalize(to).unwrap(), at).unwrap();
        }

        fn mounts(&self, lines: &[&str]) {
            std::fs::write(self.top.join("mountinfo"), lines.join("\n") + "\n").unwrap();
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.top);
        }
    }

    /// The Synology the rule was found on: btrfs over a device-mapper node
    /// over LVM over a RAID 6 of hard-disk partitions, an anonymous
    /// `st_dev`, and an `ssd` mount option that is not evidence.
    fn synology(tree: &Tree, disk_rot: &str) {
        for disk in ["sda", "sdb", "sdc"] {
            tree.device(disk, Some(disk_rot), &[], None);
            tree.partition(disk, &format!("{disk}3"));
        }
        tree.device("md2", Some(disk_rot), &["sda3", "sdb3", "sdc3"], None);
        tree.device("dm-1", Some(disk_rot), &["md2"], Some("vg1-volume_1"));
        tree.device("dm-3", Some(disk_rot), &["dm-1"], Some("cachedev_0"));
        tree.mounts(&[
            "21 1 9:0 / / rw,relatime shared:1 - ext4 /dev/md0 rw,data=ordered",
            "60 21 0:45 /@syno /volume1 rw,relatime shared:30 - btrfs /dev/mapper/cachedev_0 rw,ssd,space_cache=v2",
            "61 21 0:46 /@syno/@share /volume1/share\\040one rw shared:31 - btrfs /dev/mapper/cachedev_0 rw,ssd",
        ]);
    }

    #[test]
    fn an_array_of_hard_disks_under_btrfs_is_rotational() {
        let tree = Tree::new("syno");
        synology(&tree, "1");
        // 0:45 has no entry under /sys/dev/block: the mount's source is the
        // route, the dm node found by its name.
        let class = class_of(&tree.roots(), Path::new("/volume1/full/full.rar"), 0, 45);
        assert_eq!(class, Class::Rotational);
        // A share whose mount point has a space in it.
        let class = class_of(&tree.roots(), Path::new("/volume1/share one/a.rar"), 0, 46);
        assert_eq!(class, Class::Rotational);
    }

    #[test]
    fn the_same_stack_on_solid_state_is_solid_state() {
        let tree = Tree::new("ssd");
        synology(&tree, "0");
        let class = class_of(&tree.roots(), Path::new("/volume1/full/full.rar"), 0, 45);
        assert_eq!(class, Class::SolidState);
    }

    #[test]
    fn a_cache_drive_in_front_of_hard_disks_is_unknown() {
        let tree = Tree::new("mixed");
        synology(&tree, "1");
        // The top device says 0 (a flash cache); the layers under it say 1.
        std::fs::write(tree.top.join("sys/devices/dm-3/queue/rotational"), b"0\n").unwrap();
        let class = class_of(&tree.roots(), Path::new("/volume1/full/full.rar"), 0, 45);
        assert_eq!(class, Class::Unknown);
    }

    #[test]
    fn a_partition_by_its_device_number_reads_its_disks_queue() {
        let tree = Tree::new("part");
        tree.device("sda", Some("1"), &[], None);
        tree.partition("sda", "sda3");
        tree.number(8, 3, "sda3");
        tree.device("nvme0n1", Some("0"), &[], None);
        tree.partition("nvme0n1", "nvme0n1p2");
        tree.number(259, 2, "nvme0n1p2");
        tree.mounts(&[]);
        let hdd = class_of(&tree.roots(), Path::new("/data/a.rar"), 8, 3);
        assert_eq!(hdd, Class::Rotational);
        let ssd = class_of(&tree.roots(), Path::new("/data/a.rar"), 259, 2);
        assert_eq!(ssd, Class::SolidState);
    }

    #[test]
    fn whatever_cannot_be_read_is_unknown() {
        let tree = Tree::new("unknown");
        // No queue file at all.
        tree.device("sdz", None, &[], None);
        tree.number(8, 400, "sdz");
        // A network share and a memory file system: no block device.
        tree.mounts(&[
            "70 21 0:50 / /mnt/nas rw - cifs //server/share rw",
            "71 21 0:51 / /dev/shm rw - tmpfs tmpfs rw",
            "72 21 0:52 / /mnt/gone rw - ext4 /dev/sdq1 rw",
        ]);
        let roots = tree.roots();
        assert_eq!(
            class_of(&roots, Path::new("/x/a.rar"), 8, 400),
            Class::Unknown
        );
        assert_eq!(
            class_of(&roots, Path::new("/mnt/nas/a.rar"), 0, 50),
            Class::Unknown
        );
        assert_eq!(
            class_of(&roots, Path::new("/dev/shm/a.rar"), 0, 51),
            Class::Unknown
        );
        // A source device sysfs does not know.
        assert_eq!(
            class_of(&roots, Path::new("/mnt/gone/a.rar"), 0, 52),
            Class::Unknown
        );
        // No mount over the path, and no mountinfo at all.
        assert_eq!(
            class_of(&roots, Path::new("/elsewhere/a.rar"), 0, 53),
            Class::Unknown
        );
        std::fs::remove_file(tree.top.join("mountinfo")).unwrap();
        assert_eq!(
            class_of(&roots, Path::new("/mnt/nas/a.rar"), 0, 50),
            Class::Unknown
        );
    }

    #[test]
    fn the_longest_mount_point_over_the_path_wins_by_whole_components() {
        let tree = Tree::new("mounts");
        tree.device("sda", Some("1"), &[], None);
        tree.device("nvme0n1", Some("0"), &[], None);
        tree.mounts(&[
            "1 0 0:60 / / rw - btrfs /dev/nvme0n1 rw",
            "2 1 0:61 / /vol rw - btrfs /dev/nvme0n1 rw",
            "3 1 0:62 / /volume1 rw - btrfs /dev/sda rw",
        ]);
        let roots = tree.roots();
        // "/vol" is not over "/volume1": the root's would win, were it not
        // for the mount at "/volume1" itself.
        assert_eq!(
            class_of(&roots, Path::new("/volume1/a.rar"), 0, 62),
            Class::Rotational
        );
        assert_eq!(
            class_of(&roots, Path::new("/vol/a.rar"), 0, 61),
            Class::SolidState
        );
        assert_eq!(
            class_of(&roots, Path::new("/srv/a.rar"), 0, 60),
            Class::SolidState
        );
    }

    /// **A parity array is found at any layer of an output's stack, and
    /// nothing else is called one**: the Synology's btrfs over two
    /// device-mapper layers over md, by the mount's source; an ext4 straight
    /// on an md array, and on a partition of one, by the device number; a
    /// mirror, a stripe, a plain disk, a share and a device sysfs does not
    /// know are not parity.
    #[test]
    fn a_parity_array_is_found_under_the_output_and_nothing_else_is() {
        for (level, parity) in [
            ("raid6", true),
            ("raid5", true),
            ("raid4", true),
            ("raid1", false),
            ("raid0", false),
            ("raid10", false),
            ("linear", false),
        ] {
            let tree = Tree::new(&format!("parity-{level}"));
            synology(&tree, "1");
            tree.md("md2", level);
            let roots = tree.roots();
            assert_eq!(
                parity_of(&roots, Path::new("/volume1/out/full.mkv"), 0, 45),
                parity,
                "{level}: under two device-mapper layers"
            );
            // The array itself carrying the file system, and a partition of it.
            tree.number(9, 2, "md2");
            tree.partition("md2", "md2p1");
            tree.number(259, 7, "md2p1");
            assert_eq!(
                parity_of(&roots, Path::new("/data/out"), 9, 2),
                parity,
                "{level}: md"
            );
            assert_eq!(
                parity_of(&roots, Path::new("/data/out"), 259, 7),
                parity,
                "{level}: a partition of md"
            );
        }
        let tree = Tree::new("parity-none");
        synology(&tree, "0");
        // No `md/level` anywhere: hard disks under LVM alone.
        let roots = tree.roots();
        assert!(!parity_of(&roots, Path::new("/volume1/out"), 0, 45));
        tree.device("nvme0n1", Some("0"), &[], None);
        tree.number(259, 0, "nvme0n1");
        assert!(!parity_of(&roots, Path::new("/data/out"), 259, 0));
        // A share, and a device sysfs does not know: not seen, so not parity.
        tree.mounts(&["70 21 0:50 / /mnt/nas rw - cifs //server/share rw"]);
        assert!(!parity_of(&roots, Path::new("/mnt/nas/out"), 0, 50));
        assert!(!parity_of(&roots, Path::new("/elsewhere/out"), 8, 999));
    }

    #[test]
    fn mountinfo_escapes_are_undone() {
        assert_eq!(unescape("/a\\040b"), "/a b");
        assert_eq!(unescape("/tab\\011x\\134y"), "/tab\tx\\y");
        assert_eq!(unescape("/plain"), "/plain");
        assert_eq!(unescape("/odd\\9"), "/odd\\9");
    }
}
