# The first block of a RAR 5 archive, and the password (10 Oct 2026)

`../first-block-probe.py` and the files here are the probe, the inputs
and the answers behind SPEC-F 3.2.12. Its docstring says what an arm
is, how the programs are called and what a row's columns hold.

- `first-block-7.23-macos-arm64.tsv`: 660 rows, 55 arms put to `rar`
  7.23 and to `unrar` 7.23 for macOS on arm64 (SHA-256
  `fd6c7db73c659a28` and `99720d63484b8db7`, first 16), each with `l`
  and with `t`, each with the right password, a wrong one and none.
  The two programs agree in every row.
- `first-block-arms-7.23-macos-arm64.tsv`: the 55 arms, each with its
  length, its SHA-256 and what it is.
- `<arm>.rar`, 48 files: the inputs of 65,536 bytes or fewer, the very
  ones the table was measured on (rar draws a new salt for every
  encrypted archive, so a second run of the probe writes other bytes
  and measures those). The password of every one is `RIGHT`. NOT kept:
  `hp-lead-reach-last` and `hp-lead-reach-miss` (4,194,282 and
  4,194,283 bytes that are zero, then `hp.rar`), `hp-second-volume`
  (made again by the probe), the two RAR 4 arms (they are
  `fixtures/legacy/archives/r420_hp.rar`, password `Secret`, and
  `r420_m3.rar`), and the two arms that are no file (`missing`,
  `directory`).

Of what a program printed, only the words after `Details: ` and the
keys of the probe's marker phrases are kept.

- `first-block-7.23-linux-x86-64.tsv` and
  `first-block-arms-7.23-linux-x86-64.tsv`: the same probe on 11 Oct
  2026 with rar and unrar 7.23 for x86-64 Linux (SHA-256
  `56c3c4fd46faa7a9` and `926d3a00775ed96a`, first 16; an AMD EPYC
  4345P, as root), and under `linux-x86-64/` the 48 inputs THAT run
  was measured on (rar draws new salts each run, so they are not the
  macOS inputs). Exits, `Details` words and counts are the same as on
  macOS in all 660 rows.

Owed: Windows, the older genuine programs.
