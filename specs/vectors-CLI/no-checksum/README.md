# The mark of a member that no checksum vouches for (10 Oct 2026)

The archives and table behind SPEC-CLI section 12.
`no-checksum-probe.py` says in its first comment how the bases were
written, how an arm rewrites them, and what a row holds.

    no-checksum-probe.py --build DIR
    no-checksum-probe.py --judge DIR --label LABEL --rar RAR --unrar UNRAR

- The bytes given to rar are not kept (one is a symbolic link, one an
  empty directory): `--build` writes them, and the probe holds them.
- `sets/kinds.rar`, `comp.rar`, `solid.rar`, `blake.rar`,
  `set.part1.rar` to `set.part3.rar`: written by genuine rar 7.23 for
  macOS, all with `-qo-`.
- `sets/no-checksum-7.23-macos-arm64.tsv`: 1,984 rows: 31 arms, 32
  commands, rar and unrar 7.23 on macOS (arm64).

The arms are not kept: `--judge` makes each from its base in memory.
- `sets/no-checksum-7.23-linux-x86-64.tsv`: the same 1,984 rows on
  x86-64 Linux (11 Oct 2026), every row the same as macOS.

- `sets/no-checksum-7.23-windows-x64.tsv`: the same 1,984 rows with
  Rar.exe and UnRAR.exe 7.23 for Windows x64 on a Windows 11 PC (11
  Oct 2026), every row the same as macOS but for the banner under
  `-ierr`.

The programs are called; neither is opened or traced. The older
genuine programs are owed.
