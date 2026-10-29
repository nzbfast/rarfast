# Spec K test vectors

Inputs and archives for `specs/SPEC-K-rarkit-crypto.md`
section 5.4. Every `.rar` here was written by reference RARLAB `rar` 7.23
(macOS, Homebrew) on 18 Sep 2026. No RARLAB binary
is committed. `SHA256SUMS` pins every file.

## Inputs (`in/`)

- `hello.txt`: the 27 bytes `rarkit spec K vector input\n`.
- `data.bin`: 40,000 bytes, the concatenation of SHA-256(`i` as 4 LE bytes)
  for `i = 0, 1, 2, ...`, cut to 40,000. Regenerate:

      python3 -c "import hashlib;o=bytearray();i=0
      while len(o)<40000: o+=hashlib.sha256(i.to_bytes(4,'little')).digest();i+=1
      open('data.bin','wb').write(o[:40000])"

## Archives, and the commands that wrote them (run inside `in/`)

    rar a -ma5 -m0 -pSecret -idq ../r5_p_m0_crc.rar hello.txt data.bin
    rar a -ma5 -m0 -htb -pSecret -idq ../r5_p_m0_blake.rar hello.txt
    rar a -ma5 -m0 -hpSecret -idq ../r5_hp_m0.rar hello.txt
    rar a -ma5 -m0 -pSecret -v16k -idq ../r5_p_vol.rar data.bin
    rar a -ma5 -m3 -pSecret -idq ../r5_p_m3.rar data.bin

Salts and IVs are random, so re-running the commands gives different
archives; the spec's vectors are for THESE files. Every one passes
`unrar t -pSecret` (7.23, exit 0).

## The exponent rewrite (spec K 3.7.1)

In `r5_p_m0_blake.rar` the file header of `hello.txt` starts at byte 23 and
is 124 bytes long; the KDF exponent byte of its encryption record is at byte
56 (value 15). Write 24, 25, 31 or 255 there, then re-stamp the header CRC32
(the 4 LE bytes at 23..27 are the CRC32 of bytes 27..147). Reference `unrar`
7.23 `t -pSecret`: 24 gives "Incorrect password" after 5.30 s (exit 11);
25, 31 and 255 give "You may need a newer version of RAR" at once (exit 2).

## Legacy archives

Not committed: see spec K section 5 and
`fixtures/legacy/README.md` for the recipe
that regenerates them. Their vectors are in the spec, as text.

## Probes of the reference (4 Oct 2026)

Two scripts that build their archives in a scratch directory, put them to
reference `unrar` 7.23 and print one line per arm; neither commits an
archive, and neither is pinned in `SHA256SUMS`.

- `ragged-packed-total-probe.py`: an encrypted RAR 5 member whose packed
  bytes do not total a multiple of 16 (spec K 2.3). Needs
  `rar` and `unrar`.
- `rar13-volume-keystream-probe.py`: two hand-built two-volume RAR 1.3
  encrypted sets, each with one keystream across the crossing and with key
  setup run again there (spec K 3.3). Needs `unrar` only. The
  sets are hand-built; no genuine DOS RAR 1.40 set is among the fixtures.

## RAR 3 key derivation, for spec B part 3 (6 Oct 2026)

`b3-rar3-kdf-probe.py` is the observation behind spec B part 3. It needs
the `openssl` command for AES and `--fixtures <the repository's fixtures
directory>`. `census` decrypts the first header block of three genuine
archives with encrypted headers under the stated derivation and nine other
readings. `reference` (`--unrar`, `--work` as well) encrypts the members of
the genuine archive `r393_pw.rar` again under other passwords, with the
stated derivation or another reading, and asks `unrar t` whether the
archive is good; allow ten minutes, the long passwords are slow in Python.
`astral` does the same for one password with a character outside the basic
plane, under seven readings. `astral-length` (7 Oct 2026) does it for four
passwords of 127 and 128 characters with one such character at place 126
or 127, under 15 seeds: whether the 127 are counted in characters or in
16-bit units. `b3-rar3-kdf/` holds each arm's output under unrar 7.23 for
x86-64 Linux, and `astral-length-macos.txt` that arm's under unrar 7.23
for macOS, which is the same. Each arm is one thread. Nothing the probe writes is committed.

## DOS writer directory entries, for SPEC-NOTES (6 Oct 2026)

`notes-dos-directory-census.py --fixtures <fixtures directory> [--unrar
<path>]` reads every file block of the 25 archives DOS RAR 1.55 and 2.50
wrote under `fixtures/legacy/archives` and counts how directory entries are
marked; with `--unrar` it adds what `unrar lt` calls each entry.
`notes-dos-directory-census.txt` is its output with unrar 7.23 for x86-64
Linux.

## Evidence probe for the whole of spec K (6 Oct 2026)

`k-evidence-probe.py` is the observation behind spec K sections 3.2 to 3.7.
It needs the `openssl` command for AES.

- `rar5 [--unrar <path> --work <scratch dir>]`: a census of the five RAR 5
  archives in this directory under the stated key derivation, check record,
  checksum conversion, header encryption and fragment chain, and under 19
  other readings; with `--unrar`, arms that rewrite `r5_p_m0_crc.rar`
  (exponent, check record, other passwords and exponents, password length
  and its unit, the checksum flag) and ask `unrar t`. The archive's quick
  open record holds a copy of the second member's file header, which the
  reference reads in place of the header itself; the arms rewrite the copy
  as well, and one arm leaves it to show that.
- `legacy --fixtures <fixtures directory> --unrar <path> --work <dir>`: for
  the RAR 1.3, RAR 1.5 and RAR 2.0 ciphers, encrypts the members of a
  genuine DOS archive again under other passwords with the stated cipher
  and with other readings of it, and asks `unrar t`.

(11 Oct 2026: the `rar5` arm DRAWS two of its passwords at each run,
where it used to carry two a person chose; `k-evidence/rar5.txt` is
that arm run again on that day under unrar 7.23 for macOS on arm64,
its 108 other lines the same as the x86-64 Linux record it replaces.)
`k-evidence/` holds both arms' output under unrar 7.23 for x86-64 Linux
(sha256 of the binary `926d3a00775ed96afccfdef69c3781334b71ccdb733931edf30f4866e4f08410`).
(11 Oct 2026: `b3-rar3-kdf-probe.py reference` DRAWS its four passwords
with characters beyond ASCII at each run, where it carried four a
person chose; `b3-rar3-kdf/reference.txt` is that arm run again on
that day under unrar 7.23 for macOS on arm64: good, good, refused
(the character outside the basic plane) and good, as before, and its
40 other lines the same as the x86-64 Linux record it replaces.)
`b3-rar3-kdf-probe.py length` and `b3-rar3-kdf/length.txt` are the same
question of password length for the RAR 3 derivation. Nothing the probes
write is committed.
