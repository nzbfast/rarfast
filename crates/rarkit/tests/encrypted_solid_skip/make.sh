#!/bin/sh
# How the archives beside this file were made, on 7 Oct 2026, with the
# reference rar 7.23 for macOS (arm64). A salt and the file times make
# each run's bytes its own, so SHA256SUMS names the ones kept here.
#
# Four members that share most of their text, so that every member after
# the first is packed as matches into the members before it and cannot be
# decoded without them.
set -eu
work=$(mktemp -d)
here=$(cd "$(dirname "$0")" && pwd)
python3 - "$work" <<'PY'
import sys, os
root = sys.argv[1]
def text(seed, lines):
    out = []
    state = seed
    for n in range(lines):
        state = (state * 6364136223846793005 + 1442695040888963407) % (1 << 64)
        out.append("line %04d of the shared body, word %05d and word %05d\n"
                   % (n, (state >> 40) % 100000, (state >> 20) % 100000))
    return "".join(out).encode()
body = text(7, 400)
open(os.path.join(root, "a-head.txt"), "wb").write(body)
open(os.path.join(root, "b-second.txt"), "wb").write(body[:9000] + text(11, 60) + body[9000:])
open(os.path.join(root, "c-third.txt"), "wb").write(text(13, 40) + body[2000:] + body[:2000])
open(os.path.join(root, "d-last.txt"), "wb").write(body[5000:15000] + text(17, 80) + body)
PY
cd "$work"
rar a -ma5 -s -m3 -ep -idq -p'skip the head' "$here/rar5_solid_p.rar" a-head.txt b-second.txt c-third.txt d-last.txt
rar a -ma5 -s -m3 -ep -idq -hp'skip the head' "$here/rar5_solid_hp.rar" a-head.txt b-second.txt c-third.txt d-last.txt
shasum -a 256 a-head.txt b-second.txt c-third.txt d-last.txt > "$here/MEMBERS.sha256"
cd "$here"
shasum -a 256 rar5_solid_p.rar rar5_solid_hp.rar > SHA256SUMS
rm -r "$work"
