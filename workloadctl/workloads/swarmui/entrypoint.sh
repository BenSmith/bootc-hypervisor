#!/usr/bin/env bash
# SwarmUI entrypoint.
#
# Mirrors upstream's launchtools/docker-standard-inner.sh, minus its `fixch`
# UID-remapping path — that exists to repair host bind mounts owned by the wrong
# user, which workloadctl already handles: workload-ensure-user creates the
# volume dirs owned by _wl-swarmui and labels them container_file_t, and the
# container runs as root inside its own userns, mapping straight back to that
# user. There is nothing left to chown.
#
# bash, not sh: launch-linux.sh and the build-logic it sources are bash scripts
# (arrays, `source`, backticks under `set -o pipefail`), and Debian's /bin/sh is
# dash.
set -eu

APP=/SwarmUI

# Docker/podman leave HOME as "/" for a root process, which is read-only under
# this image's layout and is NOT persisted. SwarmUI and the ComfyUI backend it
# installs both write there — pip caches, HuggingFace downloads, the dotnet
# first-run sentinel. Parking HOME inside dlbackend puts all of it on the one
# volume already sized for the backend install, so a container replace does not
# re-download ~10 GB of torch. Upstream's own docker script does exactly this.
export HOME="$APP/dlbackend/linuxhome"
mkdir -p "$HOME"

cd "$APP"

# We exec the server binary DIRECTLY rather than going through launch-linux.sh,
# because that script breaks signal delivery: it runs
#
#     ./src/bin/live_release/SwarmUI $@        # a CHILD, not exec
#
# so PID 1 is bash, and bash does not forward SIGTERM to a foreground child it
# is waiting on. Verified on a built image: `podman stop` waits the full grace
# period and then SIGKILLs. Under the generated unit that means every
# `systemctl stop workload-swarmui` kills SwarmUI mid-write instead of letting
# it flush settings and sessions.
#
# Skipping the script costs nothing here. Its only runtime contribution is the
# two ASPNETCORE_* exports set below (verified: they are the sole `export`s in
# launchtools/linux-build-logic.sh); everything else it does is build and
# git-update logic that is already done at image build time and is meaningless
# for an immutable image. Dropping it also removes the dotnet-10 auto-install
# branch entirely rather than merely defusing it.
#
# This also replaces launch-linux.sh's --forward_restart: SwarmUI's in-UI
# "Restart" button exits 42, which now propagates straight to systemd, and the
# generated unit's Restart=on-failure brings it back. Same outcome, one less
# process, and systemd's view of the service stays accurate.
export ASPNETCORE_ENVIRONMENT="Production"
export ASPNETCORE_URLS="http://*:7801"

# --launch_mode none suppresses the "open a browser" behaviour (there is no
# browser in the container). --host 0.0.0.0 is required to reach the published
# port; SwarmUI binds loopback otherwise.
#
# SWARMUI_ARGS is unquoted on purpose — it is a flag string that must word-split.
# shellcheck disable=SC2086
exec ./src/bin/live_release/SwarmUI --launch_mode none --host 0.0.0.0 ${SWARMUI_ARGS:-}
