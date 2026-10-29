#!/bin/sh
# Regenerates this directory's 1 GiB dictionary archives with REFERENCE
# rar 7.23, and checks that reference unrar 7.23 tests and extracts every
# archive here to the bytes it was made from. The committed
# archives are the ones the tests hold; their digests are in SHA256SUMS.
#
# dict512m.rar is NOT made here: it is the reference-writer sweep's
# fixture (tests/refsweep/make.sh, item 5), copied byte for byte: 300,000,000 zero bytes at -md1g,
# which rar 7.23 records as -md=512m.
#
# rar sizes the dictionary to the input: -md1g over more than 512 MiB
# stays 1 GiB. The inputs are zero bytes so each archive is a few KiB.
#
#   RARBIN=/path/to/rar UNRARBIN=/path/to/unrar sh make.sh OUTDIR
set -eu
RARBIN=${RARBIN:-rar}
UNRARBIN=${UNRARBIN:-unrar}
OUT=$(cd "${1:?OUTDIR}" && pwd)
unset RAR
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
cd "$W"
stamp() { find src -exec touch -h -t 202001020304.05 {} +; }

# 1. One NON-SOLID member of 600,000,000 zero bytes at -md1g: a 1 GiB
# dictionary that the member itself needs only 600,000,000 bytes of.
mkdir src
head -c 600000000 /dev/zero > src/big
stamp
"$RARBIN" a -idq -y -ma5 -m1 -md1g "$OUT/dict1g.rar" src/
rm -rf src

# 2. A SOLID stream of two members of 300,000,000 zero bytes each at
# -md1g: the stream needs its whole declared 1 GiB window.
mkdir src
head -c 300000000 /dev/zero > src/a
head -c 300000000 /dev/zero > src/b
stamp
"$RARBIN" a -idq -y -ma5 -m1 -md1g -s "$OUT/dict1g-solid.rar" src/
rm -rf src

# unrar reads each archive back to zero bytes of the stated lengths.
check() {
    arc=$1; shift
    "$UNRARBIN" t -idq "$OUT/$arc"
    mkdir x
    "$UNRARBIN" x -idq -y "$OUT/$arc" x/
    for pair in "$@"; do
        name=${pair%%=*}; size=${pair#*=}
        head -c "$size" /dev/zero | cmp - "x/src/$name"
        [ "$(wc -c < "x/src/$name" | tr -d ' ')" = "$size" ]
    done
    rm -rf x
    echo "unrar: $arc OK"
}
check dict512m.rar zeros=300000000
check dict1g.rar big=600000000
check dict1g-solid.rar a=300000000 b=300000000
"$UNRARBIN" lt "$OUT/dict1g.rar" | grep -i 'dict\|compression'
"$UNRARBIN" lt "$OUT/dict1g-solid.rar" | grep -i 'dict\|compression\|flags'

set -- dict512m.rar dict1g.rar dict1g-solid.rar
cd "$OUT" && { sha256sum "$@" 2>/dev/null || shasum -a 256 "$@"; }
