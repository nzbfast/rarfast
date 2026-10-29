# An unsplit member with the unknown size flag (10 Oct 2026)

The archives and table behind SPEC-F 3.2.6's sentence on file flag
0x0008. `../unsplit-unknown-size-probe.py` says in its first comment
how each archive was made and what a row holds.

- `in/a.bin`: 60,000 bytes, the input of `../stdin-split/` too.
- `si-m0.rar`, `si-m3.rar`: written by genuine rar 7.23 for macOS from
  standard input, no volumes, `-qo-`. rar writes file flags 0x0006
  and the true size: it does not set the flag.
- `*.flag.rar`, `*.flag-zero.rar`, `*.flag-less.rar`: the flag set by
  hand, the size field as written, 0, and 59,999; the header's own
  checksum made right.
- `outcomes-7.23-macos-arm64.tsv`: 16 arms, each archive as it is and
  with one data bit changed.

- `outcomes-7.23-linux-x86-64.tsv`: the same 16 arms judged on
  x86-64 Linux (11 Oct 2026): every row the same as macOS.

The programs are called; neither is opened or traced.
