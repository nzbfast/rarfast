# rar3-rr-accept: which RAR 3.x `RR` records the reference's repair uses

For SPEC-L 3.7, "What the reference's repair needs of an `RR` record".

| File | What |
|---|---|
| `rar-7.23-macos-arm64.tsv` | the output of `../rar3-rr-accept-probe.py` with rar and unrar 7.23 for macOS arm64, 11 Oct 2026 |
| `rar-7.23-linux-x86-64.tsv` | the same with rar and unrar 7.23 for x86-64 Linux, 11 Oct 2026 |

The first two lines of a table are the two programs' banners. Then one
row an arm: what is altered in the record, `unrar t`, `rar r -y` on the
archive undamaged, and `rar r -y` with one protected sector damaged. An
exit code below zero is a signal's number, but for -9, which the probe
writes when it stopped a run still going after 45 seconds.

    python3 ../rar3-rr-accept-probe.py --rar RAR --unrar UNRAR --work DIR > rar-<version>-<system>.tsv

The archives are constructed and nothing is random: a run builds the
same 56 again. The two systems' tables differ in one cell: the arm
`r-field-max`, a signal on Linux and a run stopped at 45 seconds on
macOS.
