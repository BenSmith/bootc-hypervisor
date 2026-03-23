#!/bin/sh
set -eu

# /var/spool/squid is a volume mount — already owned by workload user via
# workload-ensure-user chown. No other writable dirs needed: squid.conf
# sends logs to stdio and puts the PID file in /var/spool/squid.

# Initialize cache directories if needed
squid -z 2>/dev/null || true

# Remove stale PID file
rm -f /var/spool/squid/squid.pid

# Run squid in foreground
exec squid -N
