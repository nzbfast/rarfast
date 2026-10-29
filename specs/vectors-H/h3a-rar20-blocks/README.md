# The RAR 2.0 blocks: probe records for SPEC-H3 part A (6 Oct 2026)

`../h3a-rar20-blocks-probe.py` is the observation behind sections 3.1 to
3.5 of SPEC-H3. It holds a RAR 2.0 decoder written from the text of those
sections (and of SPEC-D parts 1 and 2 for the multimedia predictor and the
end of a member), and for each statement that could be read another way
one or more VARIANTS of that decoder. The reference `unrar` is the judge.

## Re-running it

    python3 ../h3a-rar20-blocks-probe.py --build DIR
    python3 ../h3a-rar20-blocks-probe.py --judge DIR --unrar /path/to/unrar
    python3 ../h3a-rar20-blocks-probe.py --census --unrar /path/to/unrar \
        fixtures/legacy/archives/d250_*.rar specs/vectors-H/legacy/D250_M5.RAR \
        fixtures/rar20-dictionary/archives/genuine-rar250-m3.rar

`--build` is seeded and rebuilds the archives of this directory byte for
byte. It refuses to write a case on which a variant the case names gives
the same bytes as the stated reading. `--judge` exits 0 only when the
reference's bytes are the stated reading's on every case that names
variants.

## What is here

- `*.rar`: 70 archives, one per case, each of one or two members of unpack
  version 20 (version 13 to 30 in the `x35-unpack-version-*` cases). The
  file headers carry the CRC32 of the stated reading's bytes, so the
  reference reports a member OK exactly when it reads it as stated.
- `*.m1.want`, `*.m2.want`: the stated reading's bytes for each member,
  where they are 4,096 bytes or fewer. `cases.tsv` has the length and the
  first 64 bits of the SHA-256 of every member's bytes, these included.
- `cases.tsv`: one row per member: the case, the sections it serves, its
  kind (`variants` or `explore`), the declared size, the stated reading's
  verdict and bytes, and the variants whose bytes differ on it.
- `variants.tsv`: every variant, what it reads in place of the stated
  text, and the cases on which its bytes differ from the stated reading's.
- `judge-unrar-7.23-linux-x86-64.txt`: what reference unrar 7.23 for
  x86-64 Linux did with every archive. `judge-unrar-7.23-macos-arm64.txt`
  is the same run under unrar 7.23 for macOS; the two differ in their
  first line only.
- `census-unrar-7.23-linux-x86-64.txt`: the census of genuine DOS RAR 2.50
  output: 89 members of 15 archives, each decoded with the stated reading
  and checked against its header's CRC32, then counts of every header
  field, table shape, level symbol, main symbol, ladder slot and length
  threshold met, and a list of things looked for and never found.

## The two kinds of case

A `variants` case (names beginning `h3`) is built so that the stated
reading and each variant it names give different bytes. The reference
extracting the stated bytes shows it follows none of those variants there.
40 cases, 241 variants; 168 of the variants each raise one entry of one
ladder of section 3.3 by one.

An `explore` case (names beginning `x3`) asks an open question: what the
reference does with a stream the stated text refuses or no genuine archive
contains. It lists two or more readings and the judge prints the
reference's bytes and which reading, if any, they equal. Its header CRC32
is of the first reading's bytes unless the case says otherwise, so "OK"
and "checksum error" in the reference's answer are to be read against
that.

No reader's source was opened to write the probe. It is not a model for an
implementation.

## The stated reading and rarkit's rules

The probe's stated reading is what the reference does wherever that could
be established, so that the reference's "OK" is the test. In four places
SPEC-H3 part A keeps a stricter rule of rarkit's own and says so: a block
whose first level symbol is 16, an oversubscribed table, a repeated
distance match on a distance never set, and a distance beyond what the
stream has produced. The three `h32-oversubscribed-*` cases therefore
record what the reference does with a table rarkit refuses, and the
variant named `over-refused` on them is rarkit's rule: the reference does
not follow it and rarkit does. SPEC-H3 section 9.1 says what a
rarkit decoder does with every case here.
