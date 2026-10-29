# Group K on Windows: genuine UnRAR and Rar 7.23, 6 Oct 2026

The key derivation and password probes of `specs/vectors-K`, run against
the genuine Windows programs. 68 commands.

| Path | What it is |
|---|---|
| `probes/b3-astral.json` | `b3-rar3-kdf-probe.py astral`, run unchanged: the probe's own output, and each `UnRAR t` call it made (arguments, exit, both streams, the sha256 of the archive it had built) |
| `probes/b3-length.json` | `b3-rar3-kdf-probe.py length`, the same way |
| `probes/k5-rar5.json` | `k-evidence-probe.py rar5 --unrar`, the same way |
| `long-password/linux-unrar.py`, `long-password/linux-unrar.json` | `t.rar` tested with the reference unrar 7.23 for x86-64 Linux, the password whole and cut after y, after U+1F511 and before U+1F511, under two UTF-8 locales |
| `long-password/record.json`, `long-password/t.rar` | `Rar.exe a -ma5 -m0 -p<125 x, U+1F511, y, z> t.rar hello.txt`, then `UnRAR t` with the whole password and with it cut after y, after U+1F511 and before U+1F511. `t.rar` is the archive, kept so it can be tested on another system |

The archives the probes build and hand to UnRAR are not kept: each call
records the archive's size and sha256, and the probe rebuilds it.

## How the run was made

A GitHub hosted `windows-latest` runner, by the manual workflow
`windows-genuine-capture` at scope `full`, with this repository's wincap
capture tools (their README says what each file is and how a record is
laid out). The programs are the genuine RARLAB `Rar.exe` and
`UnRAR.exe` 7.23 for Windows x64, fetched on the runner from RARLAB's own
site: `PROGRAMS.json` holds the URL, the package's size and sha256, and
each program's size, sha256 and banner. They are shareware, used inside
their trial terms for interoperability testing; they were never committed,
never copied off the runner and are not in the run's artifact.
`SYSTEM.json` is the runner's system in its own words.

Nothing here is interpreted. Each record holds the command as given, its
exit code and both output streams as raw bytes (`..._base64`; `..._shown`
is the same bytes written as a Python bytes literal). `INDEX.tsv` has one
line per command and `COUNTS.txt` the totals. No command failed to run and
no arm was lost to a fault of the driver.

## How to run it again

    gh workflow run windows-genuine-capture.yml --ref <branch with the capture tools> -f scope=full -f groups=K
    gh run download <run id> -n windows-genuine-capture-full -D <dir>

and copy `<dir>/vectors-K/windows-06oct` here. Salts, the times of files
made on the runner and the runner's image differ from run to run, so
archives and listings are not byte for byte repeatable; the probes' own
constructed archives are.
