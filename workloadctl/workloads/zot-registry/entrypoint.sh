#!/bin/sh
set -eu

# /var/lib/registry is a volume mount — already owned by workload user via
# workload-ensure-user chown. Config is mounted read-only at /etc/zot/config.json.

exec /usr/local/bin/zot serve /etc/zot/config.json
