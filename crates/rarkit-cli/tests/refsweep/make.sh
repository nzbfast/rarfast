#!/bin/sh
# Regenerates this directory's archives with REFERENCE rar 7.23. Each is the
# minimised form of a divergence the reference-writer sweep found.
# rar is not deterministic
# across runs (it stamps nothing random, but a different rar or a
# different file order moves bytes), so the committed archives are the
# ones the tests hold, and their digests are in SHA256SUMS.
#
#   RARBIN=/path/to/rar sh make.sh OUTDIR
set -eu
RARBIN=${RARBIN:-rar}
OUT=$(cd "${1:?OUTDIR}" && pwd)
unset RAR
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
cd "$W"
stamp() { find src -exec touch -h -d "2020-01-02 03:04:05" {} +; }

# 1. Unix modes: 0755, 0600, 0640.
mkdir src
printf '#!/bin/sh\necho hi\n' > src/x.sh
printf 'secret\n' > src/r.txt
printf 'group\n' > src/g.txt
stamp
chmod 755 src/x.sh; chmod 600 src/r.txt; chmod 640 src/g.txt
"$RARBIN" a -idq -y -ma5 -m3 "$OUT/modes.rar" src/
rm -rf src

# 2. A file copy (-oi): b.txt is stored as a reference to a.txt.
mkdir src
i=0; while [ $i -lt 3000 ]; do echo "line $i of the copied file"; i=$((i+1)); done > src/a.txt
cp src/a.txt src/b.txt
stamp
"$RARBIN" a -idq -y -ma5 -m3 -oi "$OUT/filecopy.rar" src/
rm -rf src

# 3. Links (-ol -oh): three symbolic links and a hard link.
mkdir src
echo target-data > src/t.txt
ln -s t.txt src/rel; ln -s ../src src/dirl; ln -s nowhere src/dang
ln src/t.txt src/hard.txt
stamp
"$RARBIN" a -idq -y -ma5 -m3 -ol -oh "$OUT/links.rar" src/
rm -rf src

# 4. The 16th member of a solid stream empty, at -m1 (the -m3 form is held by
# the fix's own tests): 20 small text files, f015.txt zero bytes.
mkdir src
i=0
while [ $i -lt 20 ]; do
    f=$(printf 'src/f%03d.txt' $i)
    if [ $i -eq 15 ]; then : > "$f"; else
        j=0; while [ $j -lt $((60 + i * 7)) ]; do
            printf 'alpha beta %d gamma %d delta\n' $j $((i * j % 97)); j=$((j+1))
        done > "$f"
    fi
    i=$((i+1))
done
stamp
"$RARBIN" a -idq -y -ma5 -m1 -s "$OUT/solid-empty16-m1.rar" src/
rm -rf src

# 5. A 512 MiB dictionary: 300,000,000 zero bytes at -md1g, which rar
# 7.23 records as -md=512m (it rounds the dictionary down to the input).
mkdir src
head -c 300000000 /dev/zero > src/zeros
stamp
"$RARBIN" a -idq -y -ma5 -m1 -md1g "$OUT/dict512m.rar" src/
rm -rf src

# 6. Names wider than the listing column: a 70-character directory with
# one small file in it.
mkdir -p src/dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
echo x > src/dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd/f
stamp
"$RARBIN" a -r -idq -y -ma5 -m3 "$OUT/longname.rar" src/
rm -rf src

# 7. Names with control characters and a backslash, legal in a Unix name.
mkdir src
for n in "tab$(printf '\t')there" "nl
x" "cr$(printf '\r')x" "esc$(printf '\033')x" "bs\\x" "del$(printf '\177')x" "bel$(printf '\007')x"; do
    printf '%s' "$n" > "src/$n"
done
stamp
"$RARBIN" a -idq -y -ma5 -m3 "$OUT/ctlnames.rar" src/
rm -rf src

# 8. RAR 4, written by a genuine rar 4.20 (RAR4BIN, run under LC_ALL=C),
# the true-colour filter forced over 65,537 bytes of a ten-letter pattern.
# Skipped, and left as committed, when RAR4BIN is not set.
if [ -n "${RAR4BIN:-}" ]; then
    mkdir src
    printf 'abcdefghij%.0s' $(seq 6554) | head -c 65537 > src/p65537
    stamp
    LC_ALL=C "$RAR4BIN" a -idq -y -m3 -mcC+ "$OUT/r4-rgb.rar" src/
    rm -rf src
fi

set -- modes.rar filecopy.rar links.rar solid-empty16-m1.rar dict512m.rar longname.rar ctlnames.rar r4-rgb.rar
cd "$OUT" && { sha256sum "$@" 2>/dev/null || shasum -a 256 "$@"; }
