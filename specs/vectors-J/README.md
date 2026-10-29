# vectors-J: test vectors for SPEC-J (RAR 3 standard filters)

Read `specs/SPEC-J-rarkit-rar3-filters.md` section 5 first;
this file only lists what is here.

| File | What |
|---|---|
| `archives/*.rar` | 15 archives written by genuine RARLAB rar 4.20 (Linux x64) and 3.93 (Linux i386) from the seeded inputs. No RARLAB binary is in this directory. |
| `MANIFEST.tsv` | per archive: size, SHA-256, writer, switches, programs defined (length:CRC32:records) |
| `inputs.py`, `inputs.sha256` | the seeded input generator and the hashes every extracted file must match |
| `mk.sh` | the command lines each rar build ran (inside the container) |
| `records-derived.tsv` | four records built by hand from section 3.9's rules |
| `programs.tsv` | the six standard programs' bytes as cut from genuine archives, with length and CRC32. No statement of SPEC-J rests on it (section 0, item 3) |
| `hand.tsv` | hand vectors for section 3.7's transforms; `j-hand-check.py` shows each to be what `jmodel.py` gives |

## The RAR 3 filter limits

`j4-filter-limits-probe.py` is the observation behind spec J section 4.
`--unrar <path>` builds 83 members, each an LZ block of literals with
delta or x86 call filter records placed among them, and prints how many of
each member's spans the reference transformed: ladders of the number of
records waiting at once, of the number of program slots one stream
defines, and of one span's length. It reads the two programs' bytes from
`programs.tsv` and borrows the table writer of
`../vectors-H/d3-prefix-table-shapes-probe.py`. `j4-filter-limits/` holds
unrar 7.23's answers on x86-64 Linux and the four archives either side of
the two count limits; the probe rebuilds the rest.

## The constructed probes and the genuine census

Everything in this part was made without any reader's or writer's
source: genuine `unrar` is the judge of every constructed member, and
genuine archives are read with a decoder written from SPEC-H1's text and a
record parser written from SPEC-J's.

| File | What |
|---|---|
| `jlib.py` | shared by the probes: a writer of RAR 3 members that carry filter records, a parser of records, a CRC32 forger, the runner. It never holds a program's bytes: a probe defines a program with a MADE string of the standard length and CRC32 and a zero XOR, which the reference runs as the standard program (SPEC-J 3.4) |
| `jmodel.py` | section 3.7's transforms restated one byte at a time, each with the other readings the probes put beside it |
| `j-census.py`, `genuine-census.txt`, `genuine-records.tsv` | the census of the filter records in every genuine RAR 4 family archive this repository keeps: 126 records in 57 archives, each rebuilt byte for byte by section 3.9's rules |
| `j34-identify-probe.py`, `j34-identify/` | section 3.4: how a program is identified (40 arms) |
| `j37-transforms-probe.py`, `j37-transforms/` | section 3.7: the delta, RGB and audio transforms against 37 other readings (255 arms) |
| `j35-parameters-probe.py`, `j35-parameters/` | sections 3.3 item 4, 3.5 and 4: registers, parameter edges, the offset, span lengths and the two count limits (178 arms with `--big`) |
| `j33-record-probe.py`, `j33-record/` | sections 3.1 to 3.3: framing and fields (63 arms) |
| `j-hand-check.py` | shows `hand.tsv` and `records-derived.tsv` to be what `jmodel.py` and `jlib.py` give |
| `j36-queue-probe.py`, `j36-queue/` | sections 3.6 and 3.8: order, the history, the member's end, solid streams (27 arms) |
| `j35-genuine-tails-census.py`, `j35-genuine-tails/` | sections 3.5 and 3.9: what genuine rar 3.93, 4.20 and 5.50 (`-ma4`) write in a member's last record, over 35 file sizes and 8 switches (1,269 records in 707 archives), and what genuine unrar 4.20, 5.50 and 7.23 and rar 3.93 print for each. `census.txt` is its output; the 10 archives kept are the ones with an RGB row wider than its span |
| `j35-rgb-short-span-probe.py`, `j35-rgb-short-span/` | section 3.5: constructed RGB spans shorter than their row (59 arms), with the answers of genuine unrar 4.20 (runs them), 5.50 and 7.23 (leave them unchanged) |

Each directory holds `unrar-7.23-linux-x86-64.txt`, the probe's output
under reference unrar 7.23 for x86-64 Linux (sha256 of the binary
`926d3a00775ed96afccfdef69c3781334b71ccdb733931edf30f4866e4f08410`), and,
except `j35-parameters/`, every archive put to the reference (`*.rar`) with
the bytes the stated reading gives beside it (`*.want`). unrar 7.23 for
macOS on arm64 gave the same output line for line on the five probes `j33`
to `j37`.

The five directories `j33-record/` to `j37-transforms/` also hold
`unrar-4.20-linux-x86-64.txt` and `unrar-5.50-linux-x86-64.txt`: the same
probes (`j35` with `--big`) under genuine unrar 4.20 and 5.50, out of
RARLAB's packages `rarlinux-x64-4.2.0.tar.gz` and
`rarlinux-x64-5.5.0.tar.gz` (`fixtures/legacy/packages.sha256` has their
hashes; sha256 of the two `unrar` binaries
`b58f87ff10af64ed774b215fb86e4b3c9d871d809f692a34a98b5276a0e317af` and
`ed76b80d171bbe5e375496e42607a232efd4014c6c942c6e23a3b1abde7b68c3`). A
line marked `NOT THE STATED READING` in those files is that reader
differing from unrar 7.23, not a fault of the probe. On every arm of
`j37` and of the `made` and `genuine` arms of `j34` the three readers
agree; SPEC-J 3.5 says where they differ on `j35`. The writers of the
tails census: `rar_static` of `rarlinux-3.9.3.tar.gz` (sha256
`67c8af41230afcbaa26bf006c4792b8854d2fb52b0c6f394160874a2d76395d5`, run
with `LC_ALL=C`), `rar` of the 4.2.0 package
(`c54e61f5e67af29aedb73815958401f297942fc2818afbf60211a1a25d09027c`) and
`rar` of the 5.5.0 package
(`78da105b3652ca61d0ac89c0d7fa180fe5d6819eb1fc3de5e17266aad0ecbffe`).
No RARLAB program is kept here.

To run one again:

    python3 j34-identify-probe.py --unrar /path/to/unrar
    python3 j35-parameters-probe.py --unrar /path/to/unrar --big
    python3 j-census.py --tsv genuine-records.tsv > genuine-census.txt
    python3 j35-rgb-short-span-probe.py --unrar /path/to/unrar-4.20
    python3 j35-genuine-tails-census.py --bin DIR --work DIR > j35-genuine-tails/census.txt

or, without the probes, for any kept arm:

    unrar p -inul j34-identify/j34_057_made.rar | cmp - j34-identify/j34_057_made.want

The probes need Python 3 and nothing else, but `j-census.py` and
`jlib.programs()`, which load a RAR 3 reader written from SPEC-H1's text
that is not kept at the tip.

`genuine-records.tsv`, `genuine-census.txt`, `j35-genuine-tails/census.txt` and the tables of `j34-identify/` were made at the private commit be5c09422 by a tool not kept at the tip (that RAR 3 reader). No such tool is written again: from now a table is checked by rarkit's shipped reader against the genuine archives.
