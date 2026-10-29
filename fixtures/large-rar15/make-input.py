#!/usr/bin/env python3
"""Write the two large inputs the large-rar15 archives hold.

    make-input.py <dir>      # writes <dir>/INT/TEXT.TXT and <dir>/INR/RANDOM.BIN

Both are seeded and only use getrandbits/random/choice/randrange, so every
run on every box produces the same bytes (INPUTS.sha256 checks it).

  TEXT.TXT   4 MiB of pseudo-English prose: a 6,000-word vocabulary with a
             Zipf-like frequency, sentences of varying length, commas,
             full stops and paragraph breaks, CRLF line ends wrapped at
             about 72 columns as a DOS text file would be. Ordinary text
             for the step path of spec A, with matches of every distance
             up to the 64 KiB window, not a fixed-stride corpus.
  RANDOM.BIN 4 MiB of seeded random bytes: incompressible, so the writer
             has nothing to model.
"""
import os
import random
import sys

TEXT_BYTES = 4 * 1024 * 1024
RAND_BYTES = 4 * 1024 * 1024


def text(n):
    r = random.Random(1500)
    vocab = ["".join(r.choice("etaoinshrdlucmfwypvbgkjqxz") for _ in range(r.randint(2, 10)))
             for _ in range(6000)]
    weights = [1.0 / (i + 1) for i in range(len(vocab))]
    total = sum(weights)
    cum, acc = [], 0.0
    for w in weights:
        acc += w / total
        cum.append(acc)

    def word():
        x = r.random()
        lo, hi = 0, len(cum) - 1
        while lo < hi:
            mid = (lo + hi) // 2
            if cum[mid] < x:
                lo = mid + 1
            else:
                hi = mid
        return vocab[lo]

    out, size, line = [], 0, ""
    while size < n:
        words = [word() for _ in range(r.randint(5, 18))]
        words[0] = words[0].capitalize()
        for i in range(1, len(words) - 1):
            if r.random() < 0.08:
                words[i] += ","
        sentence = " ".join(words) + ". "
        if r.random() < 0.1:
            sentence += "\r\n\r\n"
            out.append(line.rstrip() + "\r\n\r\n")
            size += len(out[-1])
            line = ""
            continue
        for tok in sentence.split(" "):
            if len(line) + len(tok) + 1 > 72:
                out.append(line.rstrip() + "\r\n")
                size += len(out[-1])
                line = ""
            line += tok + " "
    return "".join(out).encode("ascii")[:n]


def main(d):
    for sub in ("INT", "INR"):
        os.makedirs(os.path.join(d, sub), exist_ok=True)
    open(os.path.join(d, "INT", "TEXT.TXT"), "wb").write(text(TEXT_BYTES))
    r = random.Random(15)
    open(os.path.join(d, "INR", "RANDOM.BIN"), "wb").write(
        b"".join(r.getrandbits(64).to_bytes(8, "little") for _ in range(RAND_BYTES // 8)))


if __name__ == "__main__":
    main(sys.argv[1])
