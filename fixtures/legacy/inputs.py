#!/usr/bin/env python3
"""Seeded input trees for the rarkit legacy fixture generator.

    inputs.py <workdir>

Writes two sibling trees under <workdir> and prints `sha256  size  path`
for every file, sorted, which is the INPUTS.sha256 the generator diffs
against its committed copy.

  IN/   8.3 upper-case names, no long names, no non-ASCII: the tree the
        16-bit DOS builds archive. Also archived by the Linux builds, so
        one tree serves every writer and the per-archive digests compare.
  CMT.TXT  an archive comment, at the work root so no writer archives it.
  INX/  extras only the Linux builds can take: the content that makes a
        genuine RAR 3.x/4.x encoder choose each standard filter, a long
        name and a non-ASCII name.

Determinism: `random.Random` with an integer seed and only
getrandbits/randint/random/choice calls, so the same bytes come out on
every box and every Python from 3.6 on. Every file's mtime is set to a
fixed instant, because the archive headers embed it (DOS builds round it
to 2 s, which is why byte-identical regeneration is not promised - see
README section 5).

NOT a fixed-stride corpus for the general payload: the text lines vary in
length and the binary blob mixes seeded random with runs of varying
length. A fixed stride reads as signal in a measurement that is really an
alignment artifact (the lesson recorded against spec C). The three filter
inputs below ARE fixed stride, because the stride is what the filter
keys on; they are payload for a reader test, never for a timing one.
"""
import hashlib
import math
import os
import random
import struct
import sys

MTIME = 1_600_000_000  # 2020-09-13T12:26:40Z, a fixed instant

WORDS = (
    "the of and to in is that for it as with was on be by at this from or "
    "an are not have which one had but were all their there archive volume "
    "member header block symbol order escape range coder memory restart "
    "window filter decode encode frequency statistics successor suffix "
    "binary table index unit stored solid recovery protect sector comment "
    "password dictionary directory attribute nested empty legacy reader"
).split()


def text(rng, n):
    """n bytes of word text in lines of varying length."""
    parts, size = [], 0
    while size < n:
        line = " ".join(rng.choice(WORDS) for _ in range(rng.randint(3, 15)))
        line = line[0].upper() + line[1:] + ".\n"
        parts.append(line)
        size += len(line)
    return "".join(parts).encode()[:n]


def blob(rng, n):
    """n bytes mixing seeded random with runs and repeats of varying length.
    No fixed stride anywhere in it."""
    out = bytearray()
    while len(out) < n:
        r = rng.random()
        if r < 0.25:
            out += bytes([rng.getrandbits(8)]) * rng.randint(3, 90)
        elif r < 0.45:
            seg = bytes(rng.getrandbits(8) for _ in range(rng.randint(5, 40)))
            out += seg * rng.randint(2, 6)
        else:
            out += bytes(rng.getrandbits(8) for _ in range(rng.randint(10, 300)))
    return bytes(out[:n])


def x86_code(rng, n):
    """x86-like code: E8/E9 calls with clustered relative displacements
    between runs of common opcode bytes, which is what makes the absolute
    form compress better and the encoder choose the x86 filter."""
    code = bytearray()
    while len(code) < n:
        r = rng.random()
        if r < 0.06:
            code += b"\xe8" + struct.pack("<i", rng.randint(-3000, 3000) - len(code) % 64)
        elif r < 0.08:
            code += b"\xe9" + struct.pack("<i", rng.randint(-400, 400))
        else:
            code += bytes([rng.choice([0x8B, 0x89, 0x48, 0x0F, 0x00, 0x00, 0xFF, 0x55, 0xC3, 0x83])])
    return bytes(code[:n])


def ia64_bundles(rng, count):
    """16-byte Itanium bundles: a template byte, a branch-slot major opcode
    nibble of 5, and a bundle-relative target in the 20-bit field, so the
    absolute form repeats."""
    out = bytearray()
    for k in range(count):
        b = bytearray(rng.getrandbits(8) for _ in range(16))
        b[0] = rng.choice([0x10, 0x11, 0x16, 0x17])
        w = struct.unpack_from("<I", b, 12)[0]
        w = (w & ~(0xFFFFF << 4)) | ((((k + rng.randint(-8, 8)) - k) & 0xFFFFF) << 4)
        w = (w & 0x0FFFFFFF) | (5 << 28)
        struct.pack_into("<I", b, 12, w)
        out += b
    return bytes(out)


def rgb_pixels(rng, w, h):
    """24-bit pixels, smooth gradients plus mild noise."""
    out = bytearray()
    for y in range(h):
        for x in range(w):
            n = rng.randint(-2, 2)
            out += bytes([(x * 2 + n) & 255, (y * 3 + x + n) & 255, (128 + y - x + n) & 255])
    return bytes(out)


def bmp24(pixels, w, h):
    """The same pixels as a bottom-up 24-bit BMP, for the encoder's
    automatic choice rather than a forced one."""
    row = bytearray()
    for y in range(h - 1, -1, -1):
        for x in range(w):
            r, g, b = pixels[(y * w + x) * 3:(y * w + x) * 3 + 3]
            row += bytes([b, g, r])
    head = b"BM" + struct.pack("<IHHI", 54 + len(row), 0, 0, 54)
    head += struct.pack("<IiiHHIIiiII", 40, w, h, 1, 24, 0, len(row), 2835, 2835, 0, 0)
    return head + bytes(row)


def pcm16(rng, frames):
    """16-bit little-endian stereo, two sines with a little noise."""
    out = bytearray()
    for i in range(frames):
        left = int(9000 * math.sin(i * 0.031)) + rng.randint(-40, 40)
        right = int(7000 * math.sin(i * 0.047 + 1.0)) + rng.randint(-40, 40)
        out += struct.pack("<hh", left, right)
    return bytes(out)


def wav(pcm):
    head = b"RIFF" + struct.pack("<I", 36 + len(pcm)) + b"WAVE"
    head += b"fmt " + struct.pack("<IHHIIHH", 16, 1, 2, 44100, 44100 * 4, 4, 16)
    return head + b"data" + struct.pack("<I", len(pcm)) + pcm


def records3(rng, n):
    """3-byte records whose fields each drift slowly: the delta filter's case."""
    out = bytearray()
    a = b = c = 0
    for _ in range(n):
        a = (a + rng.randint(0, 2)) & 255
        b = (b + rng.randint(-1, 1)) & 255
        c = (c + 7) & 255
        out += bytes([a, b, c])
    return bytes(out)


def build(work):
    rng = random.Random(20260918)
    files = {}

    # --- IN: the tree every writer archives, 8.3 upper-case, DOS-safe ---
    files["IN/HELLO.TXT"] = text(rng, 16800)
    files["IN/DATA.BIN"] = blob(rng, 20192)
    files["IN/EMPTY.DAT"] = b""              # zero-length member
    files["IN/ONE.DAT"] = b"A"               # one-byte member
    files["IN/BIG.TXT"] = text(rng, 90000)   # exceeds the 64 KB window, splits volumes
    files["IN/AUDIO.RAW"] = pcm16(rng, 9000)  # RAR 2.0 -mm, RAR 3 audio filter
    files["IN/TABLE.BIN"] = records3(rng, 5000)
    files["IN/SUB/NESTED/DEEP.TXT"] = text(rng, 700)
    files["IN/SUB/SIB.TXT"] = text(rng, 300)
    files["CMT.TXT"] = (b"rarkit legacy fixture set.\r\n"
                        b"This comment is stored by the -z switch.\r\n")

    # --- INX: what only the Linux builds can take ---
    files["INX/X86.BIN"] = x86_code(rng, 12000)
    files["INX/IA64.BIN"] = ia64_bundles(rng, 512)
    pix = rgb_pixels(rng, 96, 64)
    files["INX/RGB.RAW"] = pix
    files["INX/IMAGE.BMP"] = bmp24(pix, 96, 64)
    files["INX/PCM.RAW"] = pcm16(rng, 4000)
    files["INX/SOUND.WAV"] = wav(files["INX/PCM.RAW"])
    files["INX/DELTA.BIN"] = records3(rng, 4000)
    files["INX/a-long-file-name-that-no-8.3-writer-could-store.txt"] = text(rng, 900)
    files["INX/naam-met-accenten-éèü-ñ.txt"] = text(rng, 400)

    out = []
    for name in sorted(files):
        path = os.path.join(work, name)
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(path, "wb") as f:
            f.write(files[name])
        os.utime(path, (MTIME, MTIME))
        out.append("%s  %7d  %s" % (hashlib.sha256(files[name]).hexdigest(), len(files[name]), name))
    # An empty directory, which has no file to create it.
    os.makedirs(os.path.join(work, "IN/EMPTYDIR"), exist_ok=True)
    # Directory mtimes too, so a DOS writer's directory entries are fixed.
    for d in ("IN", "IN/SUB", "IN/SUB/NESTED", "IN/EMPTYDIR", "INX"):
        os.utime(os.path.join(work, d), (MTIME, MTIME))
    return out


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: inputs.py <workdir>")
    print("\n".join(build(sys.argv[1])))
