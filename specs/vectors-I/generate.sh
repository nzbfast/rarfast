#!/bin/zsh
# Regenerate spec I's PPMd vectors with the GENUINE rar 4.2.0 build.
#
#   generate.sh <dir holding rarlinux-x64-4.2.0.tar.gz> <work dir under $HOME>
#
# The package is supplied by whoever runs this (never fetched, never committed:
# fixtures/legacy/README.md). Its
# SHA-256 must be db4a35d1092eade42fd4233e200c8a24b942c7d67a4b7d0f92914781924b3985.
# rar runs as a black box in an x86-64 alpine container with no network; the
# work dir must be under $HOME (colima mounts only that) and is mounted at its
# real absolute path. Needs a running colima profile ($COLIMA_PROFILE).
set -eu
PKG=$1; W=$2; P=${COLIMA_PROFILE:-rarkitppmd}
HERE=${0:A:h}
echo "db4a35d1092eade42fd4233e200c8a24b942c7d67a4b7d0f92914781924b3985  $PKG/rarlinux-x64-4.2.0.tar.gz" | shasum -a 256 -c -
mkdir -p $W/bin $W/out $W/IN
tar -xzf $PKG/rarlinux-x64-4.2.0.tar.gz -C $W rar/rar_static
mv $W/rar/rar_static $W/bin/rar420
python3 $HERE/inputs.py $W/IN > $W/INPUTS.sha256
diff $W/INPUTS.sha256 $HERE/INPUTS.sha256
cp $HERE/mk-inside.sh $W/
colima -p $P nerdctl -- run --rm --platform linux/amd64 --network none \
  -v $W:$W -w $W/IN alpine:3.20 sh $W/mk-inside.sh $W/bin/rar420 $W/out
# Every archive must round-trip under reference unrar before it is used.
python3 $HERE/verify.py $W/out $W/IN $W unrar=unrar
python3 $HERE/ppmhead.py $W/out/*.rar
