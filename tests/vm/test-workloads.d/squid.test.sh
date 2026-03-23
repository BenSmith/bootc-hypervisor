# Tests for squid workload
pre_start_squid() {
    # Write a minimal squid.conf — required_files means it must exist before start
    local home
    home=$(getent passwd _wl-squid 2>/dev/null | cut -d: -f6) || return
    [ -d "$home" ] || return
    [ -d "$home/squid.conf" ] && rm -rf "$home/squid.conf"
    if [ ! -f "$home/squid.conf" ]; then
        cat > "$home/squid.conf" <<'SQUIDCONF'
acl localnet src 127.0.0.0/8
http_access allow localhost
http_access allow localnet
http_access deny all
http_port 3128
cache_dir ufs /var/spool/squid 100 16 256
coredump_dir /var/spool/squid
access_log stdio:/dev/stdout
cache_log stdio:/dev/stderr
cache_store_log none
pid_filename /var/spool/squid/squid.pid
logfile_rotate 0
SQUIDCONF
        chown _wl-squid: "$home/squid.conf"
    fi
}

test_squid() {
    if ! systemctl is-active --quiet workload-squid.service; then
        fail "squid: service not active, skipping tests"
        echo "  --- journal ---"
        journalctl -u workload-squid.service --no-pager -n 20 2>/dev/null || true
        echo "  --- container logs ---"
        local _squid_uid
        _squid_uid=$(id -u _wl-squid 2>/dev/null || echo "")
        if [ -n "$_squid_uid" ]; then
            machinectl -q shell "_wl-squid@.host" /usr/bin/podman logs workload-squid 2>&1 | tail -20 || true
        fi
        return
    fi

    # HTTP proxy check — squid should accept CONNECT on 3128
    local proxy_ok=false response
    for i in 1 2 3 4 5 6; do
        response=$(curl -s -o /dev/null -w '%{http_code}' -x http://localhost:3128 http://localhost:3128/ 2>/dev/null || echo "000")
        # Squid returns 400 or 403 for direct requests to itself — that's fine, it means it's listening
        if [ "$response" != "000" ]; then
            proxy_ok=true
            break
        fi
        sleep 3
    done
    if [ "$proxy_ok" = true ]; then
        pass "squid: listening on port 3128 (HTTP $response)"
    else
        fail "squid: not responding on port 3128"
    fi

    # Verify squid identifies itself in error pages
    local body
    body=$(curl -s -x http://localhost:3128 http://localhost:3128/ 2>/dev/null || echo "")
    if echo "$body" | grep -qi 'squid'; then
        pass "squid: response identifies as squid"
    else
        fail "squid: response does not identify as squid"
    fi
}
