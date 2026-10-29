# large-rar15: two large genuine RAR 1.5 archives for the spec A bench legs

Written 20 Sep 2026. Nothing under `crates/` was touched.

## Why

The largest spec A input any bench leg had was `rar15_40/rar154/doc_154_best.rar`
(502,961 unpacked bytes). An earlier look, "a large RAR 1.5
leg is wanted and cannot be built in this repository", closed off every route
that goes through a modern `rar` or through code in this crate. This directory
takes the route it did not list: the period writer itself.

| id | files | unpacked | archived | shape |
|---|---|---|---|---|
| `l15_txt` | `archives/l15_txt.rar` | 4,194,304 | 1,557,182 (37%) | one member of ordinary text, method 0x35 (`-m5`), unpack version 15: the step path of spec A 4.4 to 4.7 |
| `l15_rnd` | `archives/l15_rnd.rar`, `.r00`, `.r01` | 4,194,304 | 4,198,541 over three volumes | one member of random bytes split across three volumes, method 0x35 on every volume: literals only, run mode (rule D5) |

Why the random one is split: single-volume, RAR 1.55 STORES random input
(method 0x30, packed size equal to unpacked, so no decoder work at all). With
`-v` it emits a packed stream (0x35) whose size is a little over the input's.
That is also how the corpus's `rar154/random.*` (the `vol3-2MiB` leg) is
shaped, so the pair reads as the same leg at twice the size. The volume
boundaries are at 1,536,000 bytes, so the split is not a multiple of anything
the decoder is likely to align to.

## Provenance

- **Writer**: RAR 1.55 for DOS, 16 Aug 1995, `RAR155.EXE`
  (sha256 `ec48bfd97a609379a91069f6a2093fe4016875bb451499c53bd244e65d4102cc`,
  from the cache the legacy generator uses, `packages.sha256` names its source).
  Only `RAR.EXE` inside it ran, under dosbox inside a container started with
  `--network none` whose one mount is the work directory, exactly as
  `fixtures/legacy/README.md` section 3 requires. The package was unpacked by
  reference `unrar`, never executed as a program, never disassembled or
  looked inside. It is not committed, and neither is any RARLAB binary.
- **Commands** (`MANIFEST.tsv` `command` column): `RAR a -y -m5 ..\out\L15_TXT.RAR TEXT.TXT`
  and `RAR a -y -m5 -v1500k ..\out\L15_RND.RAR RANDOM.BIN`.
- **Inputs**: `make-input.py` in this directory, seeded (`INPUTS.sha256` is the
  digest list). They are generated pseudo-English and seeded random, and
  contain nobody's text. The archives are container artefacts of those inputs:
  the bytes are the writer's, the payload is ours, and no other RAR
  implementation's source or corpus is involved.
- **Check by the reference**: `unrar t` passes on both and `unrar x` returns
  members byte-identical to the inputs (checked, `cmp`, 20 Sep 2026). Header
  reading: host OS DOS, unpack version 15, `-md=64k`.
- **Reproducibility**: not promised. DOS RAR stamps the file time (rounded to
  2 s), so a re-run may differ in those bytes. The committed archives are the
  fixtures; `ARCHIVES.sha256` and `MANIFEST.tsv` are held by
  the project's fixtures check.

Re-run: as `fixtures/legacy/README.md` section 1, with `python3 make-input.py
<work>` for the inputs, `-m5` on `<work>/INT` and `-m5 -v1500k` on `<work>/INR`.

## Wiring the legs (the gate bench)

Four-line `Case`s beside the existing `f/extract-rar15*` ones, `rarkit: f_extract`,
`old: Some(f_extract_old)`, plus a `-vsnull` partner per that file's convention:

- `f/extract-rar15-txt4MiB` from `fixtures/large-rar15/archives/l15_txt.rar`
- `f/extract-rar15-rnd4MiB-vol3` from `fixtures/large-rar15/archives/l15_rnd.rar`
  (the volume set is opened from the first volume as `vol3-2MiB` is)

Prediction to test: text gains like `doc17` (about +28%), random like
`vol3-2MiB` (about +2%). Nothing was measured here.
