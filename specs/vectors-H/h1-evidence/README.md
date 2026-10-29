# Evidence for SPEC-H1 (the RAR 2.9 / 3.x LZ data)

Read the specification first. This directory holds the observations its
sections cite, and what is needed to make them again.

| Path | What |
|---|---|
| `h1probe.py` | a decoder written from SPEC-H1's text in which each statement can be replaced by another plausible reading, a bit by bit writer of blocks, and the build, judge and census commands |
| `cases_*.py` | the cases, one file per section of the specification; each names the readings it tells apart |
| `streams/<group>/*.rar` | the archives the cases build, one or more members each; the file headers carry the CRC32 of the bytes of the reading named in `want.tsv` |
| `streams/<group>/streams.tsv` | per case: what it holds and which readings give other bytes on it |
| `streams/<group>/want.tsv` | per case: the size and SHA-256 of each member under the reading in the headers |
| `streams/<group>/readings.tsv` | per case and other reading: what that reading gives on the same archive |
| `streams/<group>/variants.tsv` | what each named reading is |
| `streams/<group>/unrar-7.23-linux-x86-64.txt` | what reference unrar 7.23 for x86-64 Linux answered: `unrar t` and `unrar p` on every archive |
| `census.txt` | counts over the genuine RAR 4 family archives of this repository |

## Making the observations again

    python3 h1probe.py --build /some/dir            # rebuilds every archive, byte for byte
    python3 h1probe.py --judge /some/dir --unrar /path/to/unrar
    python3 h1probe.py --census ../../../fixtures/legacy/archives/*.rar \
        ../legacy/*.rar ../../vectors-I/archives/*.rar ../../vectors-J/archives/*.rar

`--build` refuses a case on which a reading it names gives the same bytes
as the reading in the headers, so every row of `streams.tsv` is a stream
that tells its readings apart. `--judge` prints, per case, whether the
reference tested the member OK and printed the bytes of the reading in the
headers, and which of the other readings' bytes it printed instead, if any.
A case marked `observe` asks an open question: its headers carry one
candidate reading and the answer is read from what the reference printed.

Groups, by the section of the specification they serve: `s32` 3.1 and 3.2;
`s33` 3.3; `s34-lengths`, `s34-symbols` 3.4; `s34-short`, `s35-ladder`,
`s35-bonus`, `s35-low`, `s35-repeat` 3.5; `s36` 3.6; `s37` 3.7; `s38` 3.8;
`s39` 3.9; `s310` 3.10; `s43` 4.3. 250 archives in all.

Three cases splice bytes of genuine archives into a constructed member,
because the probe has no PPM model and no filter: one PPM member of
`../../vectors-I/archives/i12_one.rar` (`cases_s32.py`) and two filter
records of `../../vectors-J/archives/` (`cases_s39.py`). The bytes are
written out in those files.

In `streams.tsv`, a case whose headers carry a reading other than `stated`
is one where the reference does something the specification's own rule
does not (section 0 of the specification lists them); `readings.tsv` then
has a `stated` row saying what the specification requires instead.

Group and case names are the ones the specification's evidence paragraphs
use. Nothing here is a model for an implementation.
