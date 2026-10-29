# The record behind SPEC-H2 sections 3.3 to 3.7 (6 Oct 2026)

`../h2-symbols-probe.py` built everything here; its head says how.

| Path | What |
|---|---|
| `manifest.tsv`, `manifest-big.tsv` | one row per archive: the arm, its kind (`discover` or `observe`), the archive, the size and SHA-256 of the bytes the row's reading gives, what the member holds, and (discover) the variant readings that give other bytes on it or (observe) the candidate reading the archive's checksum is of |
| `h2sym_*.rar` | the archives. A discover arm has one. An observe arm has one per candidate, `__c0`, `__c1`, `__c2`, the same packed data under each candidate's size and CRC32 |
| `unrar-7.23-x86-64-linux.txt` | what reference unrar 7.23 for x86-64 Linux (sha256 `926d3a00775ed96a...`) did with each archive: the exit code of `unrar t`, its message, and whether `unrar p` printed the row's bytes |
| `unrar-7.23-macos.txt` | the same under unrar 7.23 for macOS (aarch64) |
| `version-1/` | the one arm that needs `-md16g`: a member of 8 GiB under algorithm version 1, its manifest and both answers |
| `census-rar-7.23.txt` | `--census` over 101 compressed members written by reference rar 7.23: the 18 of `../archives/h5_*.rar`, and 83 written on x86-64 Linux on 6 Oct 2026 (not committed: rar stamps times into its output) |

## Re-running

    python3 ../h2-symbols-probe.py --build /tmp/x                  # small arms
    python3 ../h2-symbols-probe.py --build /tmp/x --big            # needs 30 GiB
    python3 ../h2-symbols-probe.py --judge /tmp/x --unrar /path/to/unrar
    python3 ../h2-symbols-probe.py --judge . --unrar /path/to/unrar

The build is seeded: it writes the same archives. The two members of
`--big` that need a dictionary of 256 MiB and of 4 GiB are in the second
manifest; the reference needs that much memory to read them.

The census archives were written by

    python3 ../h2-block-header-probe.py --make GEN
    python3 ../h2-pending-filters-probe.py --make FLT
    for md in 128k 256k 1m; do for m in 1 3 5; do
      rar a -ep1 -ma5 -m$m -md$md GEN/md${md}_m$m.rar \
          GEN/in/text.txt GEN/in/mix.bin GEN/in/table.bin; done; done
    python3 ../h2-symbols-probe.py --census ../archives/h5_*.rar GEN/*.rar FLT/*.rar

`FLT` packs the executables of the system it runs on, so its counts move
a little with the host.

## Reading an answer

A `discover` row is established when `unrar t` exits 0 and `unrar p`
printed the stated reading's bytes: the reference then agrees with the
stated reading on a member where every variant in the row's last column
disagrees. An `observe` row says which candidate, if any, the reference's
bytes are.

The tables here were made at the private commit be5c09422 by a tool not kept at the tip (a RAR 5 reader written from SPEC-H2's text). No such tool is written again: from now a table is checked by rarkit's shipped reader against the genuine archives.
