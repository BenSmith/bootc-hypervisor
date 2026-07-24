#!/bin/sh
# ComfyUI entrypoint.
#
# Two jobs:
#   1. Seed the bind-mounted directories from the pristine copy taken at build
#      time, so an empty host mount does not mask content the ComfyUI repo
#      ships (models/configs/*.yaml, custom_nodes/websocket_image_save.py).
#   2. Launch main.py with $COMFYUI_ARGS word-split, so the workload TOML's
#      [container.environment] COMFYUI_ARGS is actually honoured.
set -eu

DEFAULTS=/opt/comfyui-defaults
APP=/comfyui

# cp -a preserves the tree, -n never overwrites an existing file. Together they
# restore only what is missing, so user-supplied models and nodes are untouched
# and a mount that has already been seeded is a no-op.
#
# A failure here is NOT fatal — ComfyUI still starts, just without the stock
# models/configs and example nodes — but it must be loud. The usual cause is an
# SELinux label: the volume needs container_file_t, which workload-ensure-user
# applies to /var/lib/workloads via semanage fcontext + restorecon. A mount from
# anywhere else (a hand-rolled test, an absolute path outside the workload tree)
# will be denied unless the volume carries a :z suffix.
for d in models custom_nodes input user; do
    [ -d "$DEFAULTS/$d" ] || continue
    mkdir -p "$APP/$d" || true
    if ! err=$(cp -a -n "$DEFAULTS/$d/." "$APP/$d/" 2>&1); then
        echo "WARNING: could not seed $APP/$d — continuing without stock content." >&2
        echo "WARNING:   $(echo "$err" | head -1)" >&2
        echo "WARNING:   if this is a bind mount, check its SELinux label is container_file_t." >&2
    fi
done

cd "$APP"

# Unquoted on purpose — COMFYUI_ARGS is a flag string that must word-split.
# shellcheck disable=SC2086
exec python3 main.py ${COMFYUI_ARGS:-}
