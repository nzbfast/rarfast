# Test files that still run nothing on Windows, and what each needs

Counted on 4 Oct 2026 on a hosted Windows runner: 62 of the 85 test
binaries of this package run tests there (566 pass). Of the 23 that run
none, 14 are Unix by their nature and say why above their gate, 4 are
behind a feature, and the 5 below are portable in subject but hold
expectations MEASURED from the reference tools on Linux and macOS only.
Each needs its Windows column measured from the reference's Windows
builds (`Rar.exe` and `UnRAR.exe` 7.23) before its gate can go. None of
them can be ported by converting separators: the expected bytes are the
reference's own, and on Windows they are not known until read.

What the Windows builds of the reference were seen to do, 4 Oct 2026,
which every capture below can lean on:

- a LISTED name and a progress line's member name carry the system's
  separator (`sub\b.txt`);
- an extraction DESTINATION is shown as it was typed, before the
  member's name: `UnRAR x tree.rar n/` prints `Creating    n/d1` and
  `Extracting  n/d1\a.bin`, and the same with an absolute destination
  ending in a forward slash; `Rar x` prints the same lines. rarfast
  prints these lines the same way;
- an OS error's words are the system's, not `No such file or directory`;
- an archive written on Windows differs from one written on Unix by a
  few bytes of each member's header, so a volume's end can fall one
  member later (`volume_progress_lines.rs` pins one such row);
- NTFS keeps a time to 100 ns, cut and not rounded
  (`subsecond_times.rs`).

## The five

| file | tests | what its expectations are | what a Windows column needs |
|---|---|---|---|
| `listing_names.rs` | 7 | how `l`, `v`, `lt`, `lb` and the `t` line show a name holding a backslash, a NUL, each control character or bytes that are not UTF-8, for three host bytes; Linux and macOS already differ | the same archives (built in the file, and `tests/listing-names/`) listed by `UnRAR.exe` with its output read as BYTES from a pipe, in a stated console code page; a third column beside the two there. The file builds names from raw bytes with the Unix `OsStr` extension, which wants a Windows form too |
| `source_path_names.rs` | 5 | the name `rar a` stores for each path switch (`-ep`, `-ep1`, `-ep2`, `-ep3`), mask and climbing source, about 190 cells read from `rar lb` on macOS | the same tree and command lines run by `Rar.exe`, typed with both separators, and `lb` read back; a drive letter and a current directory on another drive are new cells. The tree is made with one symbolic link, which wants a privilege on Windows |
| `unrar_parity_leftovers.rs` | 3 | 173 recorded cells of exit code, stdout, stderr and files left (`tests/parity-leftovers/capture.py` wrote `cells.rs`), one of them an archive that is not there, whose stderr is the OS's words | `capture.py` run against `UnRAR.exe` to a second cells file chosen by system. Its other two tests need no capture and could run today once the first is split out |
| `parity_land3.rs` | 1 | the same kind of recorded cells for both tools (`tests/parity-land3/capture.py`); the test runs the binary through a symbolic link named for the tool, and plants files of a given Unix mode | the capture run against `Rar.exe` and `UnRAR.exe`; the binary copied to the tool's name with the executable suffix (`support/exe_copy.rs`, `tool_named`) in place of the link; the mode cells stay Unix only |
| `redirection.rs` | 18 | the trees reference unrar leaves from archives of symbolic links, hard links, junctions and file copies, and its words for each one it skips; measured on Linux | the same archives extracted by `UnRAR.exe` as an ordinary user and as one who may create links, and each tree read back. About seven tests (`t`, `lt`, file copies, the refusals that create nothing) ask nothing of the file system's links and are the first to move |

## How the others were moved

Thirty-two files lost their gate on 4 Oct 2026 by these rules, and a
port of the five should keep them: the expected side is put in the
system's form, never the tool's output normalised, unless the pin is a
hash; a test types a destination with the system's separator unless the
destination's own display is its subject; a test that is Unix by its
nature keeps a gate of its own with the reason beside it; no assertion
is weakened on Unix to pass on Windows.
