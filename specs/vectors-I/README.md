# Vectors and probe records for specification I

Two generations of material live here.

- **18 Sep 2026: genuine archives.** `archives/` holds 23 archives written
  by the genuine rar 4.2.0 build; `MANIFEST.tsv`, `INPUTS.sha256`,
  `inputs.py`, `mk-inside.sh`, `generate.sh`, `ppmhead.py`, `verify.py`
  and `VERIFY.txt` describe and regenerate them. SPEC-I section 5.1 is
  the census taken over them.
- **6 Oct 2026: the probe records.** Everything below.

## The public sources SPEC-I is tagged to

Fetched on 6 Oct 2026 into a scratch directory outside every repository,
and not committed. SPEC-I cites them as **S** and **Z** with line numbers;
the numbers are those of the files as fetched (S with its line ends as
they are in the package).

**S: PPMd variant H, the 2001 package** ("PPMd var.H", dated 21 Apr 2001
in its `read_me.txt`, which says of the package "Now, PPMd is pure public
domain program" and of the coder "claimed to be a public domain").

- `ppmdh.rar`, from
  `https://web.archive.org/web/20100927185349id_/http://compression.ru/ds/ppmdh.rar`
  (the author's own address `http://www.compression.ru/ds/ppmdh.rar`
  answered 406 to a plain fetch on the day), 58,082 bytes, SHA-256
  `c07b244f3a5d59f45417b4684f2877678ebd8c66376e24e41444e813d865d174`.
- Files read, with SHA-256:
  - `read_me.txt` `45d9a99bd143deda28e295d8dd6cdb1131e3291407982b066df62d763da27fad`
  - `PPMd.h` `10ad8458e2d5aa3da6abdd4d70aeafa0c05f10183060fd652d07a8151223d159`
  - `PPMdType.h` `d79ab83c7edb77b7015e041069df4ef91c0c1ea85a8dc6ae61a8d516ea073649`
  - `Model.cpp` `7f92b5a05b1a1bc7c1d89e5407026521a2fc5ad49206de6afdcdf1783f2175eb`
  - `SubAlloc.hpp` `e2012977b0f7fafc12aca5f072fada039d2fb996fe30032a9c7698305b6ac7d5`
  - `Coder.hpp` `4fc7249193575f97086b603e2ff0583dcdf37bdf2199880e9717df7cc3596613`
- Not read: `PPMd.cpp` (the command line program), the two `.exe` files
  and the makefiles.

**Z: LZMA SDK 9.20** (2010; each file's own header says "Public domain").
This SDK holds no RAR code of any kind.

- `lzma920.tar.bz2`, from `https://www.7-zip.org/a/lzma920.tar.bz2`,
  534,077 bytes, SHA-256
  `8ac221acdca8b6f6dd110120763af42b3707363752fc04e63c7bbff76774a445`.
- Files read, with SHA-256:
  - `C/Ppmd.h` `57b3bdc65d0794abf75efd8fea28f7535f4ccbd51b16377ea570ef6cf7c3047c`
  - `C/Ppmd7.h` `731e5e6bda5aaf125cb7364351cee81e5ed76d5d38734f6da19fa1c576edf866`
  - `C/Ppmd7.c` `ebac49deb2082c9c827ea810e9d32fd2978484c9b81679c5dace9f2ac5d0c83c`
  - `C/Ppmd7Dec.c` `95cdf1272d63a912c9c4f43b4b15251f193ae57ee5a099824666fd9468b82819`
- Nothing else in the SDK was opened. Z's range coder is 7z's own and is
  NOT the one RAR 3 uses (`Ppmd7.h` lines 5 to 7 say so); SPEC-I 3.6 is
  tagged to S alone.

**Fetched again, 7 Oct 2026.** Both archives were fetched a second time
from the two addresses above, into another directory outside every
repository: the same sizes, the same two archive hashes, and the same ten
file hashes. The author's own address for S answered 406 again. In the
SDK's archive the names holding "Ppmd" are `C/Ppmd.h`, `C/Ppmd7.c`,
`C/Ppmd7.h`, `C/Ppmd7Dec.c`, `C/Ppmd7Enc.c` and, under
`CPP/7zip/Compress/`, `PpmdDecoder.h`, `PpmdEncoder.cpp` and
`PpmdRegister.cpp`; only the four listed above were opened.
`names-check-07oct.tsv` is the check of the 32 names SPEC-I prints
(SPEC-I 9.4): 52 checks, 51 found, 1 not found.

Neither source says anything about the RAR format. Everything SPEC-I
states about how RAR 3 starts a block, frames the range decoder, uses an
escape byte, ends a member or bounds memory comes from the probe below or
from the census of the genuine archives.

## The probe

The probe's tool was a PPMd variant H model with a range encoder and
decoder, written from SPEC-I sections 3.2 to 3.11 and checked against S
and Z. Run on genuine archives it decoded their PPM members and compared
each with the CRC32 in its header. It is not kept at the tip (it stands
in the private history at commit be5c09422).

`i-evidence-probe.py` is the observation behind SPEC-I sections 3.1 to
3.11 and 4:

    python3 i-evidence-probe.py --build evidence-06oct
    python3 i-evidence-probe.py --variants evidence-06oct
    python3 i-evidence-probe.py --judge evidence-06oct --unrar /path/to/unrar

`--build` is seeded and rebuilds the same archives byte for byte (about a
minute). `--variants` takes about five minutes. `--arena-search NAME...`
is how the three `m3*` plaintexts were found; it is not needed to re-run
the evidence.

`evidence-06oct/` holds:

| File | What it is |
|---|---|
| `m*.rar` | part M: 21 plaintexts written as PPM blocks by the stated model |
| `m-streams.tsv` | per stream: order code, memory byte, escape byte, size, CRC32 and SHA-256 of the plaintext, and what the stated model did while writing it (model starts, merges, rescales and so on) |
| `m-variants.tsv` | per variant reading of one statement: the section, the other reading in words, and the streams on which that reading decodes to other bytes |
| `r*.rar` | part R: one archive per question put to the reference |
| `r-cases.tsv` | per case: the question, the reading the archive was coded under, and the length and SHA-256 of the bytes that reading prints |
| `short-own-checksum-probe.py`, `short-own-checksum.txt` | `r26_code2_early_then_block_full_size.rar` with its stored CRC32 rewritten to that of the 600 bytes the reference prints, and the reference's answer to it (OK, exit 0) beside its answer to the archive as kept |
| `answers-unrar-7.23-linux-x86_64.txt` | what the reference did with every archive |
| `answers-unrar-7.23-macos-arm64.txt` | the same under the macOS build |
| `outcomes-unrar-7.23-linux-x86_64.txt`, `outcomes-unrar-7.23-macos-arm64.txt` | the same outcomes, derived from the two recorded files above by `../derive-outcomes.py`: line 1 is written new (plain program name and version, the system, the recorded file's name and SHA-256, the rule) and every later line is the recorded file's own, byte for byte. The recorded files are never edited. `python3 derive-outcomes.py --check` in `vectors-I/` fails unless both are current (SPEC-I 5.2) |
| `genuine-census.txt` | that model over the genuine archives of `archives/` |

A part R case is read like this: the archive was coded so that, IF the
reference follows the named reading, it prints exactly the recorded
bytes. "PRINTS THE BYTES OF THIS READING" with `rc=0` says it does.
Cases come in families that code the same intent under rival readings,
and the family's answers pick the reading.

The filter record cases (`r60` to `r64`) lay a record out by SPEC-J
sections 3.2 and 3.3 and use the delta program's 29 bytes as
`vectors-J/programs.tsv` records them from genuine archives. The LZ
blocks of `r50` to `r52` are bytes of the genuine archives
`archives/i18_solid_mixed_auto.rar` and `archives/i13_empty_and_one.rar`.

No reader of the RAR format was opened to write any file here.

The tables of `evidence-06oct/` (and the columns of `MANIFEST.tsv` that the model printed) were made at the private commit be5c09422 by a tool not kept at the tip (the PPMd model). No such tool is written again: from now a table is checked by rarkit's shipped reader against the genuine archives.
