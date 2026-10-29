//! THE MASK READ AT START (`dialect::unrar::read_umask_at_start`): the
//! file-creation mask is read at `main`'s first line by a set-and-restore
//! pair, in place of the probe that measured it with a directory made and
//! removed in the temporary directory. What must hold is that every file
//! extracted under every mask has EXACTLY the mode the probe gave it, and
//! that the mask read is the mask the process was started with.
//!
//! Each case extracts the same archive of files of several stored modes
//! under a mask the shell sets (`umask`, then `exec`), once as shipped and
//! once with the probe kept (`RARFAST_UMASK=probe`), and compares the
//! modes, and the bytes, of every file. `RARFAST_UMASK_SAY=1` says which
//! answered and what it read.
//!
//! Those knobs exist only under the feature `read-depth-knob`; the knob
//! test runner (`make test-knob-spawn`) builds it and runs this:
//!
//! ```text
//! cargo test -p rarkit-cli --features read-depth-knob --test umask_at_start
//! ```
//!
//! Unix only: off Unix there is no mask. Width and memory: one thread is
//! enough (`-mt1` is not stated; the files are a few bytes each), and the
//! archive and its outputs are under a megabyte.
#![cfg(all(unix, feature = "read-depth-knob"))]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};

#[path = "support/exe_copy.rs"]
mod exe_copy;
use exe_copy::{copy_executable, output_of, rarfast};

/// The stored modes, one file each.
const MODES: [u32; 6] = [0o755, 0o644, 0o640, 0o600, 0o777, 0o444];

/// The masks each case is started under.
const MASKS: [u32; 4] = [0o000, 0o022, 0o027, 0o077];

struct Bench {
    dir: PathBuf,
    unrar: PathBuf,
}

impl Bench {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("rarfast-umask-start-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        let unrar = dir.join("unrar");
        copy_executable(&rarfast(), &unrar);
        for mode in MODES {
            let path = dir.join("src").join(format!("m{mode:o}"));
            std::fs::write(&path, format!("mode {mode:o}\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let names: Vec<String> = MODES.iter().map(|m| format!("m{m:o}")).collect();
        let made = output_of(
            Command::new(rarfast())
                .args(["a", "-m0", "-idq", "../modes.rar"])
                .args(&names)
                .current_dir(dir.join("src")),
        )
        .expect("rarfast a runs");
        assert!(made.status.success(), "rarfast a: {made:?}");
        Self { dir, unrar }
    }

    /// `unrar x` of the archive into a fresh `into`, started under `mask`,
    /// with the probe kept or not: what it said, and each file's mode.
    fn extract(&self, mask: u32, probe: bool, into: &str) -> (Output, Vec<(String, u32)>) {
        let dest = self.dir.join(into);
        let _ = std::fs::remove_dir_all(&dest);
        std::fs::create_dir_all(&dest).unwrap();
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg(format!("umask {mask:03o}; exec \"$0\" \"$@\""))
            .arg(&self.unrar)
            .args(["x", "-idq", "-y", "modes.rar", &format!("{into}/")])
            .current_dir(&self.dir)
            .env("RARFAST_UMASK_SAY", "1")
            .env_remove("RARFAST_UMASK");
        if probe {
            command.env("RARFAST_UMASK", "probe");
        }
        let out = output_of(&mut command).expect("unrar runs");
        assert!(out.status.success(), "{into}: {out:?}");
        let modes = MODES
            .iter()
            .map(|mode| {
                let name = format!("m{mode:o}");
                let path = dest.join(&name);
                assert_eq!(
                    std::fs::read(&path).unwrap(),
                    format!("mode {mode:o}\n").into_bytes(),
                    "{into}/{name}: its bytes"
                );
                let got = std::fs::symlink_metadata(&path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777;
                (name, got)
            })
            .collect();
        (out, modes)
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        // A 0o444 or 0o000 file inside a directory we own removes as ever.
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// What the run said of its mask: (the mask in octal, `read` or `probe`).
fn said(out: &Output) -> (String, String) {
    let text = String::from_utf8_lossy(&out.stderr);
    let line = text
        .lines()
        .filter_map(|line| line.split_once("rarfast umask: ").map(|(_, rest)| rest))
        .next_back()
        .unwrap_or_else(|| panic!("no umask line in {text:?}"));
    let (mask, how) = line.trim().split_once(' ').expect("the mask and how");
    (mask.to_string(), how.to_string())
}

/// Under every mask, the mask read at start is the shell's, the probe's is
/// the same, and every file has exactly the mode the probe gave it.
#[test]
fn the_mask_read_at_start_gives_every_file_the_probes_mode() {
    let bench = Bench::new();
    for mask in MASKS {
        let (read, read_modes) = bench.extract(mask, false, &format!("read-{mask:03o}"));
        let (probe, probe_modes) = bench.extract(mask, true, &format!("probe-{mask:03o}"));
        assert_eq!(said(&read), (format!("{mask:03o}"), "read".to_string()));
        assert_eq!(said(&probe), (format!("{mask:03o}"), "probe".to_string()));
        assert_eq!(read_modes, probe_modes, "under umask {mask:03o}");
    }
}
