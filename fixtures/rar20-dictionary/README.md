# The RAR 2.0 declared-dictionary divergence

Two archives of **the same 80,000-byte input**, in the same format, at the
same compression level, both accepted by reference `unrar` 7.23. rarkit
decodes one of them and refuses the other. They exist so that whichever way
the tolerance question is decided, the rule has a fixture under it.

| file | writer | declared dictionary | `unrar` 7.23 | rarkit when recorded |
|---|---|---|---|---|
| `archives/genuine-rar250-m3.rar` | RAR 2.50, RARLAB, 24 March 1999 | 64 KiB | OK | **All OK** |
| `archives/nonconformant-64k.rar` | the encoder of this project's EARLIER ENGINE, the one it kept before rarkit; not RARLAB's RAR and not rarkit. `--format rar20 --level 3` | 64 KiB | OK | **`Rar20(DistanceOutOfRange)`** |

**Which program wrote which.** `genuine-rar250-m3.rar` was written by
RARLAB's RAR 2.50. `nonconformant-64k.rar` was written by the RAR 2.0
encoder of the engine this project used before rarkit (the top-level
README's section on where this code came from describes that engine). It
is kept as a file of bytes that a reader meets; no source of that engine
is in this directory or needed to use it.

`input-DICT.TXT` is the input both hold; `make-input.py` rewrites it and
`ARCHIVES.sha256` covers all three files.

## What the pair proves

The earlier engine's RAR 2.0 encoder writes the dictionary field correctly
and then **does not bound its match finder by it**. Its stream names a
distance of more than 65,536 at output offset 67,018 of 80,000, which is
1,482 bytes past the first lap of the declared window. rarkit sizes the
window at the declared dictionary, as spec H3 section 3.5 requires, so the
match reaches outside it and the member is refused. Handed the identical
packed bytes with a 128 KiB window instead, rarkit delivers all 80,000
bytes correctly, so nothing but the window size is in question: the LZ
decoder, the Huffman tables and the block structure are all right.

Reference `unrar` never enforces the field for this format, which is why
it reads both.

**The genuine archive is the control that settles which side is wrong.**
RAR 2.50 is a RAR 2.0 writer from the era the format is named for; given
the same input and the same switch it declares the same 64 KiB and stays
inside it. So the construct is not something a conformant RAR 2.0 writer
emits, and rarkit is right about the format. What is open is whether a
reader that promises to read what the reference reads should tolerate it
anyway. See the ERRATUM at spec H3 section 3.5 and the project's
research note of 19 Sep 2026 on the RAR 2.0 decode divergence.

## Why this is not in `fixtures/legacy/`

That corpus has one rule: every archive in it comes from a genuine
RARLAB writer, and it must stay that way, because its job is to say what
the formats ARE. Half of this pair is deliberately from our own
non-conformant writer, which is the opposite job. The genuine half was
produced by the same generator and the same cached RAR 2.50 build that
`fixtures/legacy/` uses, under dosbox in a container with no network.

## How the archives were made

    # the non-conformant one, from a build of the earlier engine
    <the earlier engine's command line tool> add --format rar20 --level 3 \
        nonconformant-64k.rar DICT.TXT

    # the genuine one, RAR 2.50 under dosbox, from the cached package
    # (sha256 3862e775d7b503463608962a96fe7b21b78b643c94f6b98341a2cbc5abad24d3)
    RAR a -y -m3 GEN250.RAR DICT.TXT

`--dict-size` reproduces the whole shape: at `64k` and `128k` the
earlier engine's writer exceeds what it declared, and at `256k` and above the
same input fits inside it and rarkit reads the result. The threshold in
member size, at the default dictionary, is 66,712 bytes: one byte less and
the encoder finds no match past 64 KiB.
