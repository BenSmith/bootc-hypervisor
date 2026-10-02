#!/bin/bash
# Print REPO@DIGEST for IMAGE (REPO:TAG) once root's store holds it under a
# policy that accepts only a sigstore signature by cosign.pub. Build from what
# this prints, not from the tag: `podman build` re-resolves a tag on its own,
# unverified, so a checked tag proves nothing about what gets built.
#
#   bash .forgejo/scripts/verified-ref.sh registry.local/negativo-rpms:44
set -euo pipefail
image=$1
repo=${image%:*}
key=$(realpath "$(dirname "$0")/../../cosign.pub")
policy=$(mktemp)
trap 'rm -f "$policy"' EXIT
printf '{"default":[{"type":"reject"}],"transports":{"docker":{"%s":[{"type":"sigstoreSigned","keyPath":"%s","signedIdentity":{"type":"matchRepository"}}]}}}' \
  "$repo" "$key" > "$policy"
if ! sudo podman pull -q --signature-policy="$policy" "$image" >/dev/null; then
  echo "::error::${image} is missing or not signed by cosign.pub" >&2
  exit 1
fi
digest=$(sudo podman image inspect --format '{{.Digest}}' "$image")
echo "verified: ${image} (${digest})" >&2
echo "${repo}@${digest}"
