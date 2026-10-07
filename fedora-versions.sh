#!/bin/sh
# Print KEY from fedora-versions.yml: stable or rechunker as a number,
# supported as a JSON array. It reads each key's one-line form and refuses
# anything else, so a reshaped file fails the caller instead of being misread.
#
#   sh fedora-versions.sh supported    # [44,43]
set -eu
file=$(dirname "$0")/fedora-versions.yml
key=${1:?usage: fedora-versions.sh stable|supported|rechunker}
case $key in
  stable|rechunker) value='[0-9]+' ;;
  supported) value='\[ *[0-9]+( *, *[0-9]+)* *\]' ;;
  *) echo "fedora-versions.sh: no key $key" >&2; exit 2 ;;
esac
found=$(sed -En "s/^$key:[[:space:]]*($value)[[:space:]]*(#.*)?\$/\1/p" "$file")
if [ -z "$found" ] || [ "$(printf '%s\n' "$found" | wc -l)" -ne 1 ]; then
  echo "fedora-versions.sh: $file has no one-line $key" >&2
  exit 1
fi
printf '%s\n' "$found" | tr -d ' '
