# The locator's quick open offset (9 Oct 2026)

The files and answers behind SPEC-F 3.2.8 rule 2 as settled on 9 Oct 2026.

`../locator-offset-probe.py --build DIR` has a genuine rar write four
bases (clear headers and `-hpSecret`, one file and a set of five volumes,
every one with a quick open record) and writes 82 arms beside them, one
directory an arm, each holding every file of its base with ONE of them
changed: the locator's quick open offset set to another value of the same
width, or the file cut short. Its docstring says what each column of an
answers file means. `cases.tsv` has the SHA-256 of every base file and of
every changed file and what its arm is. rar stamps the time into what it
writes and draws a fresh salt for `-hp`, so a second build gives other
bytes: the files kept here are the ones the answers are about.

| File | What |
|---|---|
| `layout.txt` | `--layout`: each block's place counted from the start of the main header as stored, and what each locator holds. In all 12 base files the offset lands exactly on the `QO` header; behind `-hp` both are counted to the first byte of a header's IV |
| `outcomes-unrar-7.23-macos-arm64.tsv` | unrar 7.23 for macOS, SHA-256 `99720d63484b8db7` (first 16) |
| `outcomes-rar-7.23-macos-arm64.tsv` | rar 7.23 for macOS, `fd6c7db73c659a28` |

The two agree in every column of every arm. Behind `-hp` what the genuine
programs make of an offset on no block changes from build to build with
the salt: of two builds on 9 Oct, `hp.arm.offset-plus-1` wrote all four
members in one and none in the other, exit 3 both times. The arms with
clear headers gave the same answers in both builds.

Nothing a program printed is kept: the marks are derived.

9 Oct 2026: the `*-7.23-linux-x86-64*` files here are rar 7.23 and unrar
7.23 for x86-64 Linux (SHA-256 `56c3c4fd46faa7a9` and `926d3a00775ed96a`,
first 16) on the same vectors, made by `probes-again.sh` of `specs/`;
`EVIDENCE-PASS-STATE.md` there says, rule by rule, whether they agree with
the macOS answers. The older genuine readers are still owed.
