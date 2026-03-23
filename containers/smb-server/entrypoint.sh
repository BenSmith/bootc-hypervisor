#!/bin/bash
set -euo pipefail

mkdir -p /var/lib/samba/private /var/lib/samba/lock

exec smbd --foreground --no-process-group
