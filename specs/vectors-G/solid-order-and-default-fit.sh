#!/bin/sh
# The probes behind SPEC-G 3.9.1 (the solid order) and 3.8.1
# (rar 7.23's default dictionary and its fit to the input).
#
#     ./solid-order-and-default-fit.sh [WORKDIR]
#
# Needs `rar` and `unrar` 7.23 on PATH and specs/vectors-F/rar7-dictionary-
# field.py beside this directory. Run 27 Sep 2026 on an Apple M5 Max Mac (aarch64
# macOS, APFS), homebrew's copies, sha256 fd6c7db7... (rar) and 99720d63...
# (unrar). Written from black-box runs only;
# no implementation's source was read. Prints the orders and dictionaries
# the section quotes; the walk order it prints first depends on the file
# system and is the one thing expected to differ between boxes.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
field="$here/../vectors-F/rar7-dictionary-field.py"
w=${1:-$(mktemp -d)}
mkdir -p "$w" && cd "$w"
lb() { unrar lb "$1" | tr '\n' ' '; echo; }
dict() { python3 "$field" "$1" | grep '^type 2' | sed 's/.*dictionary=//' | awk '{printf "%dK ", $1/1024}'; echo; }

echo "== extension groups"
rm -rf g && mkdir -p g/in/sub/deep g/in/alpha && cd g/in
for f in z.txt a.c m.txt b.C B.txt noext README Makefile x.tar.gz y.gz q.h k.TXT \
         sub/c.txt sub/a.c sub/deep/b.txt alpha/z.c .hidden c.; do printf 'data %s\n' "$f" > "$f"; done
cd ..
rar a -idq ns.rar in; rar a -s -idq s.rar in; rar a -s -ds -idq sds.rar in
printf 'walk:   '; lb ns.rar; printf 'solid:  '; lb s.rar; printf 'with -ds: '; lb sds.rar
cd ..

echo "== base name and path"
rm -rf n && mkdir -p n/in/zz/yy n/in/aa n/in/mm && cd n/in
for f in a.txt a-.txt ab.txt zz/a.txt aa/a.txt mm/a.txt zz/yy/a.txt a.tar.gz a.gz a0.gz \
         "$(printf '\303\251').txt" e.txt Z.txt ..x x.. 'a b.txt'; do printf 'd\n' > "$f"; done
head -c 100000 /dev/urandom > zbig.txt; head -c 50000 /dev/urandom > zz/y.txt
cd ..
rar a -idq ns.rar in; rar a -s -idq s.rar in
printf 'walk:  '; lb ns.rar; printf 'solid: '; lb s.rar
cd ..

echo "== directories"
rm -rf d && mkdir -p d/in/b/c/d d/in/a/e d/in/c.x d/in/a.y/q d/in/B2 d/in/zz/b && cd d/in
for f in b/c/d/f.txt a/e/f.txt c.x/f.txt a.y/f.txt zz/b/f.txt top.txt; do printf 'd\n' > "$f"; done
cd ..
rar a -idq ns.rar in; rar a -s -idq s.rar in
printf 'walk:  '; lb ns.rar; printf 'solid: '; lb s.rar
cd in; rar a -s -idq ../args.rar zz/b/f.txt top.txt a.y/f.txt b/c/d/f.txt; cd ..
printf 'command line names: '; lb args.rar
cd ..

echo "== groups and volumes (the solid bits: 0 opens a group)"
rm -rf v && mkdir -p v/in && cd v/in
for f in z.txt a.c m.txt b.c y.h q.txt c.h e.c; do head -c 30000 /dev/urandom | base64 > "$f"; done
cd ..
for sw in "-s" "-s3" "-se" "-se -ds" "-s3 -ds" "-s -m0"; do
    n=$(echo "$sw" | tr -d ' -'); rar a $sw -idq "x_$n.rar" in
    printf '%-8s ' "($sw)"; lb "x_$n.rar"
    printf '         '; python3 "$field" "x_$n.rar" | grep '^type 2' | awk '{printf "%s %s  ", $3, $6}'; echo
done
rar a -s -v40k -idq vol.rar in
for p in vol.part*.rar; do printf '%s: ' "$p"; python3 "$field" "$p" | grep '^type 2' | awk '{printf "%s %s  ", $3, $6}'; echo; done
cd ..

echo "== default dictionary and fit (-m3, no -md)"
rm -rf f && mkdir f && cd f
for n in 0 100 131071 131072 1048575 1048576 16777215 16777216 33554433 104857600; do
    truncate -s "$n" "f$n"; rm -f t.rar; rar a -m3 -ep -idq t.rar "f$n"; printf '%10d: ' "$n"; dict t.rar
done
truncate -s 3m a3m b3m
rm -f t.rar; rar a -m3 -ep -idq t.rar a3m b3m; printf 'two 3 MiB, non-solid: '; dict t.rar
rm -f t.rar; rar a -s -m3 -ep -idq t.rar a3m b3m; printf 'two 3 MiB, solid:     '; dict t.rar
truncate -s 100000 k100; truncate -s 115000 k115; truncate -s 200000 k200; truncate -s 600000 k600 l600
rm -f t.rar; rar a -m3 -ep -idq t.rar k100 k115; printf '100,000 + 115,000, non-solid: '; dict t.rar
rm -f t.rar; rar a -m3 -ep -idq t.rar k200 k115; printf '200,000 + 115,000, non-solid: '; dict t.rar
for fs in "f100" "k100 k115" "k200 k115" "f1048575" "k600 l600" "f1048576"; do
    rm -f t.rar; rar a -s -m3 -ep -idq t.rar $fs; printf 'solid %s: ' "$fs"; dict t.rar
done
rm -f t.rar; rar a -s -m3 -md256k -ep -idq t.rar k200 k115; printf 'solid 200,000 + 115,000, -md256k: '; dict t.rar
rm -f t.rar; rar a -m3 -md8m -ep -idq t.rar f104857600; printf '100 MiB, -md8m:       '; dict t.rar
rm -f t.rar; rar a -m0 -ep -idq t.rar a3m; printf '3 MiB, -m0:            '; dict t.rar
rm -f t.rar; seq 1 20000 | rar a -m3 -idq -sistdin.bin t.rar; printf 'stdin, 108,894 bytes: '; dict t.rar
rm -f t.rar; seq 1 20000 | rar a -s -m3 -idq -sistdin.bin t.rar; printf 'stdin, solid: '; dict t.rar
for m in 1 5; do rm -f t.rar; rar a -m$m -ep -idq t.rar f104857600; printf '100 MiB, -m%s:         ' $m; dict t.rar; done
head -c 131072 /dev/urandom > r131072; rm -f t.rar; rar a -m3 -ep -idq t.rar r131072
printf '131,072 random bytes, -m3 (stored): '; python3 "$field" t.rar | grep '^type 2' | awk '{print $7, $NF}'
