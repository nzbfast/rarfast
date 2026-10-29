# The test cases of specification B, with values nobody chose (11 Oct 2026)

`../spec-b-cases-probe.py` and the table here are behind SPEC-B 1.6,
2.3 and 3.4. Each case is a need in one sentence; its values are drawn
by the probe from the system's random source within the range the need
fixes, or are forced by the definition and marked so; the order of the
cases is drawn too. The probe holds no key derivation, no cipher and
no field arithmetic. Its docstring says what a row holds.

`spec-b-cases-7.23-macos-arm64.tsv`: 21 cases, ONE draw. The 10 of
Part 3 carry what unrar 7.23 and rar 7.23 for macOS on arm64 (SHA-256
`99720d63484b8db7` and `fd6c7db73c659a28`, first 16) both print for
the drawn bytes; the 11 of Parts 1 and 2 are marked NOT MEASURED, with
what pins each end to end. Run the probe with `--check` on the table
to put the Part 3 rows to the programs again, here or on another
system: it stops unless every row comes out the same.

The `*-7.23-linux-x86-64.tsv` table beside it is that `--check` run on
11 Oct 2026 with rar and unrar 7.23 for x86-64 Linux (SHA-256
`56c3c4fd46faa7a9` and `926d3a00775ed96a`, first 16; an AMD EPYC
4345P, as root): every row the same bytes as on macOS.

THE TWO FIELD CHECKS (the cases "the field of bytes" and "the
overflow") were given a case list of ours later on 11 Oct 2026:
products by 2, operands rising, two of them drawn and two at the edge
of the overflow (the probe's first comment states the rule).
`--field-rows` drew those two rows once and wrote them into both
tables here; every other row is the first draw's and was not made
again. The Linux table was then checked once more on x86-64 Linux (an
Intel Xeon Platinum 8488C): `--check` on the macOS table gave this
Linux table byte for byte.

Owed: Windows; the older genuine programs.
