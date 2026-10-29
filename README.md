# rarkit

A Rust engine for the RAR archive format, and `rarfast`, a command line
tool built on it that takes the commands and switches of `rar` and
`unrar`. It creates, lists, tests, extracts and repairs RAR archives and
is built to be fast on many cores.

## Where this code came from

rarkit is a clean-room implementation of the RAR format. It is not a
product of RARLAB. It contains no code from RAR, UnRAR, rars or any
other RAR implementation, and it is not a fork of any of them. That is
why it is published under MIT OR Apache-2.0 and not under the UnRAR
licence.

The work was split into two roles, and the two were kept apart.

**Specification writers** described the format and the behaviour of the
reference tools in writing: what genuine `rar` and `unrar` programs
write for a given input, what they accept and what they refuse. They
found it by running those programs as black boxes and reading the bytes
of archives they wrote, and from RARLAB's public description of the RAR
5.0 format. Some specification writers had also read this project's
earlier engine, described below. No specification writer wrote engine
code from a specification.

**Engine writers** wrote `crates/rarkit` from those specifications. An
engine writer did not read, reference or consult the source of UnRAR, of
any other program's RAR code, of rars, or of this project's earlier
engine, while doing the work: the project's rules forbade opening any of
them, and a writer who was shown such material by accident had to stop
and report it.

Two checks run on every change to keep this true. One fails the build if
any line of original code in the engine outside
`crates/rarkit/src/carry/` was typed by anyone other than an engine
writer. It reads the development history, which is not part of this
repository, so it has no tool here and a reader cannot run it. The other
is a similarity scan of the engine and of the command line tool against
the source of rars. That one a reader can run: `tools/simscan.py` is
here, `python3 tools/simscan.py --selftest` checks the scanner itself,
and `tools/SIMSCAN.md` says how to run it against any tree you choose.

**The earlier engine.** Before rarkit, this project kept an earlier
engine of its own, which began as a fork of the public project `rars`
(<https://github.com/bitplane/rars>). rarkit is not that engine and is
not a fork of rars. Two parts of this repository hold code that this
project wrote itself while it worked in that fork, and then moved
across: `crates/rarkit/src/carry/`, kept apart so that its history is
plain, with each module's header saying where it came from; and the
first version of the `rar` and `unrar` command dialects in
`crates/rarkit-cli`. Only items this project had written from their
first line were moved; no line written by the rars project came with
them, and the similarity scan covers both.

## Status

0.9.0 is a beta. Do not trust it with your only copy of anything:
after creating an archive, test it (`rarfast t archive.rar`, and with
`unrar t archive.rar` if you have unrar) before deleting the originals.
`docs/release-0.9.0/` has the release notes and the known issues.

Source, issues and releases: <https://github.com/nzbfast/rarfast>.

## Layout

| Path | What |
|---|---|
| `crates/rarkit` | The library. `unsafe` is denied across the workspace and allowed by name only in the modules that need it: SIMD checksum, CRC, AES and recovery kernels, huge page advice, and counting allocators in tests. Feature `parallel` is on by default. |
| `docs/release-0.9.0` | Release notes, known issues, checksums and third-party notices. |
| `tools/` | The similarity scanner (`tools/SIMSCAN.md`). |
| `crates/rarkit-cli` | `rarfast`: one binary, the `rar` and `unrar` dialects. |
| `fixtures/`, `specs/vectors-*` | Archives the tests read. |
| `fuzz/`, `crates/rarkit/fuzz/` | Fuzz targets, pinned seeds and past findings. |

## Building and testing

The toolchain is pinned in `rust-toolchain.toml`.

    cargo build --release -p rarkit-cli     # target/release/rarfast

The build leaves the program at `target/release/rarfast` and does not
put it on your path: run it by that name, or copy it to a directory
that is on your path.

    target/release/rarfast a -m5 backup.rar my-folder     # create an archive
    target/release/rarfast t backup.rar                   # test it
    target/release/rarfast x backup.rar                   # extract it

`crates/rarkit-cli/README.md` says how the one binary takes the `rar`
and the `unrar` dialects.

The first build needs the network once, for the pinned toolchain and
the dependencies. `cargo fetch --locked` fetches the dependencies ahead
of time; after it, building and testing need no network
(`CARGO_NET_OFFLINE=true` holds cargo to that).

To run the tests:

    CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --workspace --locked

Read these four points before you start it.

**Time.** Without `CARGO_PROFILE_TEST_OPT_LEVEL=1` cargo builds the
tests unoptimised, and the suite then takes about two hours: 115
minutes on a Linux machine with 96 hardware threads and 89 minutes on a
Mac with 36, with a hundred or so tests running for more than a minute
each. This project's own gate sets the variable. On one machine it
brought the run of the test binaries from 2,747 seconds down to 308.

**Disk.** A full `cargo test` builds well over a hundred test binaries.
After the release build and the unoptimised test run the `target`
directory held 34 GB on Linux and 10 GB on macOS: allow that much free
disk. `CARGO_PROFILE_TEST_DEBUG=0` makes it smaller.

**No timeout.** `cargo test` waits for ever on a test that hangs. A
test that cargo reports as running for over 60 seconds is, as a rule,
only slow, above all in an unoptimised build; no test is known to hang.

**Features.** The line above leaves about sixty of the engine's unit
tests unbuilt and about thirty more ignored: they sit behind features
that are off by default, and among them are the tests that read the
shipped vectors against their check tables. This line runs them too:

    CARGO_PROFILE_TEST_OPT_LEVEL=1 cargo test --workspace --locked \
        --features rarkit/repo-tests,rarkit/audio-lane-ref,rarkit/h2-probes,rarkit-cli/h2-probes

The test suite is written for a machine with at least eight hardware
threads and several GB of free memory. On a smaller machine set
`RAYON_NUM_THREADS=8`; some tests may still fail there. This repository
carries no hosted CI yet; one follows.

On Windows the suite is narrower, and a green run there covers less than
it seems to. Of the 85 `rarkit-cli` test binaries, 30 run tests on
Windows (472 tests) and 55 run none: 45 of the 84 test files are for
Unix only, and the rest need a feature that is off by default. The
engine's own integration tests have not been run on Windows. The Windows
build was also checked by a smoke test of 36 steps and by hand on two
Windows 11 PCs.

Some tests compare rarkit's output with the reference `rar` and `unrar`
tools and pass without them. One does not: without `unrar` installed, add
`-- --skip every_vector_lists_the_names_the_reference_prints`.

`--all-features` is not supported: the feature `oracle-compare` turns on
tests and examples that need a comparison engine that is not part of
this repository.

`rarfast --version` prints a commit: it is the development commit this
tree was exported from (also in `EXPORTED-FROM`), which is what the
released binaries print. It names the release the source was cut from,
not the state of your working copy.

## Fixtures

The archives under `fixtures/` and `specs/vectors-*` were made for this
project from generated inputs, by genuine RARLAB writers of several
periods, so that the readers are tested against what real writers emit. No RARLAB
program is included in this repository, and the inputs contain no
third-party content. Each directory's README or manifest names the writer
and switches behind every archive.

## Licence

MIT OR Apache-2.0, at your option.
