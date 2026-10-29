# Spec L test vectors

Inputs and archives for `specs/SPEC-L-rarkit-crc-recovery.md`
section 5. Every `.rar` and `.rev` here was written by reference RARLAB
`rar` 7.23 (macOS, Homebrew) on 18 Sep 2026; none by any other program. No
RARLAB binary is committed. `SHA256SUMS` pins every file.

## Inputs (`in/`)

- `hello.txt`, `data.bin`: the same inputs as `../vectors-K/in/` (see that
  README for how `data.bin` is generated).
- `b<n>.bin` for n in 0, 1, 64, 511, 512, 513, 4096, 4097: byte `i` is
  `(7 i + 3) mod 256`. Regenerate:

      python3 -c "
      for n in (0,1,64,511,512,513,4096,4097):
          open(f'b{n}.bin','wb').write(bytes((i*7+3)&255 for i in range(n)))"

## Archives, and the commands that wrote them (run inside `in/`)

    rar a -ma5 -m0 -rr5 -idq ../rr5_small.rar hello.txt data.bin
    rar a -ma5 -m0 -rr100 -idq ../rr100_small.rar hello.txt
    rar a -ma5 -m0 -v16k -rv2 -idq ../rv.rar data.bin
    rar a -ma5 -m0 -v12289b -rv1 -idq ../rvodd.rar hello.txt data.bin
    rar a -ma5 -m0 -htb -idq ../blake_sizes.rar b0.bin b1.bin b64.bin b511.bin b512.bin b513.bin b4096.bin b4097.bin data.bin

`rar` stamps times and a clock-derived tag into these files, so re-running
the commands gives different bytes with the same geometry; the spec's
vectors are for THESE files.

## Probe of the reference (4 Oct 2026)

`lost-group-records-probe.py` makes a 14,000,000 byte `-rr3` archive in a
scratch directory, breaks every recovery record of one group, and prints
what reference `rar r` says, exits with and writes (spec L 3.8's paragraph
on a group that cannot be judged). It needs `rar` and `unrar`, commits no
archive and is not pinned in `SHA256SUMS`.

## CRC-64 check values (6 Oct 2026)

`crc64-check-values.py` computes the CRC-64 values spec L quotes in 3.2 and
5.1, for both conventions, by two independent methods that must agree, and
reproduces the public catalogue's check value for CRC-64/XZ. It reads no
archive and needs no reference program. `crc64-check-values.txt` is its
output. Neither is pinned in `SHA256SUMS`.

## Recovery volume header (6 Oct 2026)

`l4-rev-header-probe.py` is the observation behind spec L sections 3.6.2,
3.6.3 and the `.rev` rows of section 4. It copies `rv.part1.rar`,
`rv.part3.rar` and `rv.part1.rev` to a scratch directory (so the second
data volume is missing), alters one field of the recovery volume's header
per arm, and prints whether `rar rc` and `unrar x` rebuilt the missing
volume byte for byte. It needs `rar` and `unrar`. `l4-rev-header/` holds
the answers of rar and unrar 7.23 for x86-64 Linux; the altered files are
not committed, the probe rebuilds each from `rv.part1.rev`
(`--keep DIR` leaves them).

## Evidence probe for the whole specification (6 Oct 2026)

`l-evidence-probe.py` is the observation behind spec L sections 3.1, 3.3,
3.4, 3.5, 3.6.1, 3.6.4 and 3.7. It is written from the specification's text
and public definitions only, and the reference programs are its judge. It
has seven arms, each run as

    python3 l-evidence-probe.py <arm> --rar <path to rar> --work <scratch dir>

- `census`: makes 49 archives with an inline recovery record at chosen
  protected lengths and percentages, plus a three volume set, parses every
  record, and checks each statement of 3.5.1, 3.5.2 and 3.4 against the
  bytes; it counts the archives on which each other reading of the
  geometry, of the table and of the code gives a different answer. It also
  reads `rr5_small.rar` and `rr100_small.rar` from this directory. Pure
  Python; allow ten minutes.
- `reader`: damages one genuine archive, alters one field of its records
  per arm, and prints what `rar r` did (3.5.3, 3.5.5). A run of the
  reference that is still going after 45 seconds is stopped and recorded.
- `rev`: writes 46 sets with recovery volumes, counts and parses them
  (3.6.1, 3.6.4), and reads the two sets committed here.
- `legacy`: needs `--fixtures <the repository's fixtures directory>`. Parses
  the RAR 2.x and RAR 3.x recovery records of 15 genuine files under
  `fixtures/legacy/archives` and puts damaged copies of five to `rar r`
  (3.7).
- `blake`: writes one `-htb` archive of 18 members and compares the stored
  digests with BLAKE2sp from Python's `hashlib` and with seven other
  readings (3.3.1).
- `equal` (7 Oct 2026): constructs RAR 4 archives with an `RR` subblock
  from the text of 3.7, the member's sectors all different, partly
  equal, all equal or repeating with a period, damages one or two sectors and prints what `rar r`
  wrote (3.7, "Where the reference's repair goes wrong"); output
  `l-evidence/equal-sectors.txt`, 26 archives and 207 runs, one process
  at a time. These archives hold fixed bytes, so a second run gives the
  same file.
- `sfx`: puts 3,001 bytes before a genuine archive, asks `rar rr5` to add a
  record, and reads what the record protects (3.5.1).

`l-evidence/` holds each arm's output under rar 7.23 for x86-64 Linux
(sha256 of the binary `56c3c4fd46faa7a9f52264d30cb96813e19ec7c4587d9f18424d7e909cf78555`).
The archives the arms make are not committed: they hold random bytes and a
tag that changes per run, so a second run gives other bytes and the same
answers. Neither the probe nor its outputs are pinned in `SHA256SUMS`.

## The code of RAR 3 recovery volumes, for spec B part 1 (6 Oct 2026)

`b1-rar3-rev-code-probe.py` is the observation behind spec B part 1. Its
`census` arm (`--fixtures <the repository's fixtures directory>`) compares
the two genuine RAR 3 recovery volumes under `fixtures/legacy/archives`
with the stated code and five other readings, byte by byte. Its `rebuild`
arm (`--rar`, `--work` as well) writes recovery volumes for the genuine set
`r393_rv` with 2, 3 and 5 parity symbols under the stated code and under
other readings, removes data volumes and asks `rar rc` to rebuild them; it
first finds, by trying, which arrangement of three counts in a recovery
volume's last bytes the reference accepts. `b1-rar3-rev-code/` holds both
arms' output under rar 7.23 for x86-64 Linux. Nothing the probe writes is
committed.

## Three measurements of 11 Oct 2026

- `rar5-tag-clock-probe.py`, `rar5-tag-clock/`: what a genuine writer
  stores as the tag of its RAR 5 recovery records (SPEC-L 3.5.2): 40 runs
  on each of two systems with the clock read around each. The tag is of
  the clock and not of the content.
- `rar3-rr-accept-probe.py`, `rar3-rr-accept/`: which RAR 3.x `RR`
  records the reference's repair uses (SPEC-L 3.7): one constructed
  archive, its record altered in one thing an arm, 56 arms, on two
  systems.

- `rar3-rr-origin-probe.py`, `rar3-rr-origin/`: where the sectors of
  such a record are counted from when bytes stand before the signature
  (SPEC-L 3.7): the same archive behind 100 to 5,000 made bytes, the
  record made for each origin, 33 arms, on two systems.

`rc-restore-probe.py` is the measurement behind SPEC-CLI section 13
(12 Oct 2026): what the genuine `rar rc` takes, looks at, prints,
exits with and leaves, over a RAR 5 set it has `rar` write (with and
without encrypted headers) and over the kept sets of the older form.
`rc-restore/` holds its table, 143 rows on macOS (arm64).

`rc-sfx-first-probe.py` is the measurement behind SPEC-CLI 13.1 C17
(13 Oct 2026): what `rar rc` does with a set whose first volume
extracts itself (`set.part1.sfx`, and the same file renamed `.exe`
and `.EXE`). It needs the `default.sfx` module that comes with the
program, passed by its path with `--sfx` and never opened.
`rc-sfx-first/` holds its table, 78 rows on macOS (arm64).

`rc-old-names-probe.py` is the measurement behind SPEC-CLI 13.1 C18
(13 Oct 2026): whether `rar` writes a RAR 5 set under the old volume
names (`set.rar`, `set.r00`), and what `rc`, `rv` and `t` do with one
made by renaming, under three namings of its recovery volumes.
`rc-old-names/` holds its table, 62 rows on macOS (arm64).

None of these is listed in `SHA256SUMS`, which pins the archives of section 5.
