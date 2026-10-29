# rar3-rr-origin: where a RAR 3.x `RR` record's sectors are counted from

For SPEC-L 3.7, "The origin".

| File | What |
|---|---|
| `rar-7.23-macos-arm64.tsv` | the output of `../rar3-rr-origin-probe.py` with rar 7.23 for macOS arm64, 11 Oct 2026 |
| `rar-7.23-linux-x86-64.tsv` | the same with rar 7.23 for x86-64 Linux, 11 Oct 2026 |

The first line of a table is the program's banner. A row is one damaged
archive: how many made bytes stand before the signature, which origin the
record was made for, the sector damaged, and what `rar r -y` did (the
probe's first comment says the rest).

    python3 ../rar3-rr-origin-probe.py --rar RAR --work DIR > rar-<version>-<system>.tsv

The archives are constructed and nothing is random: a run builds the same
33 again. The bytes before the signature are made bytes and no self
extracting module.
