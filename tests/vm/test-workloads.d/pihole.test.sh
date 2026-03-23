# Fully disable systemd-resolved so pihole-FTL can bind port 53
_stop_resolved() {
    systemctl stop systemd-resolved-varlink.socket systemd-resolved-monitor.socket 2>/dev/null || true
    systemctl stop systemd-resolved.service 2>/dev/null || true
    # Wait for port 53 to be fully released
    local tries=0
    while ss -ulnp | grep -q 'systemd-resolve' && [ $tries -lt 10 ]; do
        sleep 1
        tries=$((tries + 1))
    done
}

pre_start_pihole() {
    echo "  Disabling systemd-resolved (conflicts with pihole on port 53)"
    systemctl mask systemd-resolved.service systemd-resolved-varlink.socket systemd-resolved-monitor.socket 2>/dev/null || true
    _stop_resolved
}

# Tests for pihole workload
test_pihole() {
    if ! systemctl is-active --quiet workload-pihole.service; then
        fail "pihole: service not active, skipping tests"
        return
    fi

    # Service file checks: userns=host code path
    local svc
    svc=$(cat /run/systemd/system/workload-pihole.service 2>/dev/null || echo "")
    if [ -n "$svc" ]; then
        if echo "$svc" | grep -q -- '--userns=.*host'; then
            pass "pihole: service uses --userns=host"
        else
            fail "pihole: expected --userns=host in service file"
        fi
        if echo "$svc" | grep -q -- '--network=.*host'; then
            pass "pihole: service uses --network=host"
        else
            fail "pihole: expected --network=host in service file"
        fi
    fi

    # Initialize gravity database — FTL DNS does not work until gravity is populated
    # on first start. See: https://github.com/pi-hole/docker-pi-hole/issues/1743
    echo "  Initializing gravity (DNS unavailable until this completes)..."
    wl_exec pihole pihole -g 2>&1 | tail -5 || true

    # Restart the workload service to give FTL a clean start with gravity populated
    echo "  Restarting pihole service after gravity init..."
    systemctl stop workload-pihole.service
    _stop_resolved
    systemctl start workload-pihole.service
    sleep 10

    # Web UI check (after restart so FTL is fully initialized)
    local http_ok=false response
    for i in 1 2 3 4 5 6; do
        response=$(curl -s -o /dev/null -w '%{http_code}' http://localhost/admin/ 2>/dev/null || echo "000")
        if [ "$response" = "200" ] || [ "$response" = "302" ]; then
            http_ok=true
            break
        fi
        sleep 3
    done
    if [ "$http_ok" = true ]; then
        pass "pihole: /admin/ returns $response"
    else
        fail "pihole: /admin/ returned $response (expected 200 or 302)"
    fi

    # DNS check — query pi.hole which FTL handles locally (no upstream needed)
    if command -v dig >/dev/null 2>&1; then
        local dns_ok=false dig_output
        for i in 1 2 3 4 5 6; do
            dig_output=$(dig +time=5 +tries=1 @127.0.0.1 pi.hole A 2>&1 || echo "")
            if echo "$dig_output" | grep -q 'Query time:'; then
                dns_ok=true
                break
            fi
            sleep 5
        done
        if [ "$dns_ok" = true ]; then
            pass "pihole: FTL responding to DNS queries"
        else
            fail "pihole: FTL not responding to DNS queries"
            echo "  Port 53 bound: $(ss -ulnp | grep ':53 ' || echo 'no')"
            echo "  --- FTL log ---"
            wl_exec pihole cat /var/log/pihole/FTL.log 2>&1 | tail -30 || true
            wl_exec pihole cat /etc/pihole/pihole-FTL.log 2>&1 | tail -30 || true
            echo "  --- dig output ---"
            echo "  $dig_output"
        fi
    else
        echo "  SKIP: dig not available, skipping DNS test"
    fi
}
