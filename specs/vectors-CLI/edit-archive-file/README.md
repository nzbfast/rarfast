# What an edit does to the archive and to its file (10 Oct 2026)

The two probes and the two tables here are behind SPEC-CLI 11.2 and
11.3. Neither probe keeps an archive: each has the genuine rar write
its archives under TMPDIR and removes them. Each docstring says what
an arm is and what a row's columns hold.

- `edit-archive-holds-probe.py` makes
  `edit-archive-holds-7.23-macos-arm64.tsv`: 196 rows, 14 kinds of
  archive by 7 `d` and 7 `rn` (11.2). Run it as
  `edit-archive-holds-probe.py --rar /path/rar --label L --out DIR
  --rar4 fixtures/legacy/archives/r420_m3.rar`.
  The same run makes `edit-then-recovery-7.23-macos-arm64.tsv`: 48
  rows, what a recovery command or switch gives after an edit (11.2,
  H13).
- `edit-keeps-recovery-probe.py` makes
  `edit-keeps-recovery-7.23-macos-arm64.tsv`: 24 rows, four edits put
  to archives written with three recovery switches, by rar and by a
  second program given with `--tool NAME=PATH` (here a build of
  rarkit's own tool at main `47fd69e1f`, run as a black box): whether
  the recovery record is still there afterwards (11.4).
- `edit-archive-file-probe.py` makes
  `edit-archive-file-7.23-macos-arm64.tsv`: 87 arms, 10 runs each, on
  an archive of 256 MB (11.3). It makes two small disk images of its
  own for the arms on another volume (hdiutil on macOS; a tmpfs on
  Linux, where it must be root) and detaches them. Run it the same
  way, with `--megabytes 256 --runs 10`.

The answers kept are rar 7.23 for macOS on arm64 (SHA-256
`fd6c7db73c659a28`, first 16), run as an ordinary user. The second
probe watches by listing directories while rar runs: a name that
lives very briefly can be missed, and the table's column "seen in
runs" says in how many of the 10 runs each name was seen. rar is
called and nothing else: it is not traced. Of what it printed only the
`Details:` words and the keys of the probes' marker phrases are kept.

The three `*-7.23-linux-x86-64.tsv` tables are the two probes on 11 Oct
2026 with rar 7.23 for x86-64 Linux (SHA-256 `56c3c4fd46faa7a9`, first
16; an AMD EPYC 4345P), run AS ROOT, which no permission stops: the
arms of a directory or an archive that cannot be written succeed
there and say nothing of an ordinary user on Linux. The other arms
answer as on macOS. `edit-keeps-recovery` was not run there.

Owed: Windows, the older genuine programs, Linux as an ordinary user.
