# A clear stored member: its checksum and the order of its bytes (13 Oct 2026)

The rows behind SPEC-F 3.7.7 S14. `../clear-stored-order-probe.py
--build DIR` has genuine rar 7.23 store one member of 8 MiB and one of
256 MiB (`-m0`), each clear (`rar5-clear`) and again encrypted
(`rar5-twin`), and makes the damaged and the cut copies; `--judge` runs
one genuine program over them, one arm a row. The probe's first comment
names the arms, the columns and the marks. The inputs are fixed bytes
the probe makes and are NOT kept here: about 1.7 GB, and made again by
`--build` in a few seconds.

The programs are called, and sent signals (STOP and CONT for the looks
at a growing file, INT for the interrupt arms); they are never opened
or traced.

- `clear-stored-order-7.23-macos-arm64.tsv`: 138 rows, 69 for unrar
  7.23 and the same 69 arms for rar 7.23 (SHA-256 `99720d63484b8db7`
  and `fd6c7db73c659a28`, first 16), on macOS 27.0.1 (arm64), an
  ordinary user, the destination an APFS volume. The two
  programs agree in every column but the last.
- `clear-stored-order-7.23-linux-x86-64.tsv`: the same 138 rows for
  unrar 7.23 and rar 7.23 for x86-64 Linux (SHA-256 `926d3a00775ed96a`
  and `56c3c4fd46faa7a9`, first 16), on Linux 6.8, the superuser, the
  destination the root volume. It agrees with the macOS table in
  every column but the last, in all 138 rows.

The last column, `seen`, holds what differs from run to run (how many
looks, how far the file had got, how long the part left by an interrupt
was) and is not part of what a row pins: run again, every other column
came out the same in a second run of each program on macOS.

NOT measured: Windows, a member of the older container
(rar 7.23 does not write one: `rar a -ma4` ends with exit 7), and
`rarfast`.
