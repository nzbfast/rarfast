#!/usr/bin/env python3
"""Rewrite `input-DICT.TXT`, the 80,000-byte input both archives hold.

Deterministic pseudo-English: a 4,096-word vocabulary drawn from a fixed
seed, then words drawn from it with the same generator, so every run on
every box produces the same bytes. It is compressible enough that a match
finder that is not bounded by a 64 KiB dictionary reaches past one, which
is the whole point of the fixture, and short enough that the archives are
under 40 KB each. Check with ARCHIVES.sha256.
"""
import pathlib, random
r = random.Random(20)
vocab = ["".join(r.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(r.randint(3, 9)))
         for _ in range(4096)]
out, n = [], 0
while n < 80000:
    w = vocab[r.randrange(4096)]
    out.append(w)
    n += len(w) + 1
here = pathlib.Path(__file__).resolve().parent
here.joinpath("input-DICT.TXT").write_bytes((" ".join(out))[:80000].encode())
