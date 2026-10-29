#!/bin/zsh
# The only entry point of the rarkit legacy fixture generator.
#
#   generate.sh <package dir> <work dir under $HOME> [extra build.py args]
#
# <package dir> holds the six legacy RARLAB packages listed in
# packages.sha256. They are SUPPLIED by whoever runs this: never fetched by
# this script, never committed to any repository, and a new download needs
# the owner's explicit yes first. If one is absent the run refuses and prints the
# filename, source URL and size to ask for (README section 3).
#
# <work dir> must be under $HOME and is mounted into the containers at its
# real absolute path: colima mounts only $HOME, and a mount at any other
# path sends every fixture-relative lookup somewhere else.
#
# Needs: a running colima profile ($COLIMA_PROFILE, default rarkitfx),
# reference `unrar` 7.23 on PATH, python3. Set OLD_ENGINE to an old-engine
# binary (rarfast) to fill the manifest's old_engine column.
set -eu
HERE=${0:A:h}
if (( $# < 2 )); then
  print -u2 "usage: generate.sh <package dir> <work dir under \$HOME> [build.py args...]"
  exit 64
fi
PKG=$1; WORK=$2; shift 2
: ${COLIMA_PROFILE:=rarkitfx}
if ! colima list 2>/dev/null | grep -qE "^${COLIMA_PROFILE}[[:space:]]+Running"; then
  print -u2 "colima profile '$COLIMA_PROFILE' is not running. Start one of your own"
  print -u2 "(do NOT borrow a bench profile):"
  print -u2 "  colima start -p $COLIMA_PROFILE --cpu 4 --memory 8 --disk 30 --runtime containerd"
  exit 3
fi
command -v unrar >/dev/null || { print -u2 "reference unrar is not on PATH"; exit 3; }
OLD=""
if [[ -n ${OLD_ENGINE:-} ]]; then OLD="--old=$OLD_ENGINE"; fi
exec python3 $HERE/build.py --pkg $PKG --work $WORK --profile $COLIMA_PROFILE ${OLD:+$OLD} "$@"
