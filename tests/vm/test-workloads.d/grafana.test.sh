# Tests for grafana workload
pre_start_grafana() {
    # Write a minimal grafana.ini — required_files means it must exist before start
    local home
    home=$(getent passwd _wl-grafana 2>/dev/null | cut -d: -f6) || return
    [ -d "$home" ] || return
    # Podman may have created grafana.ini as a directory (volume mount with missing source)
    [ -d "$home/grafana.ini" ] && rm -rf "$home/grafana.ini"
    if [ ! -f "$home/grafana.ini" ]; then
        cat > "$home/grafana.ini" <<'EOF'
[server]
http_port = 3000

[analytics]
reporting_enabled = false
check_for_updates = false
EOF
        chown _wl-grafana: "$home/grafana.ini"
    fi
}

test_grafana() {
    if ! systemctl is-active --quiet workload-grafana.service; then
        fail "grafana: service not active, skipping tests"
        return
    fi

    # Web UI check
    local http_ok=false response
    for i in 1 2 3 4 5 6; do
        response=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:3000/login 2>/dev/null || echo "000")
        if [ "$response" = "200" ]; then
            http_ok=true
            break
        fi
        sleep 3
    done
    if [ "$http_ok" = true ]; then
        pass "grafana: /login returns 200"
    else
        fail "grafana: /login returned $response (expected 200)"
    fi

    # Health API check
    local health
    health=$(curl -s http://localhost:3000/api/health 2>/dev/null || echo "")
    if echo "$health" | grep -q '"database": "ok"'; then
        pass "grafana: /api/health reports database ok"
    else
        fail "grafana: /api/health unexpected response: $health"
    fi

    # Auto-provisioned Prometheus datasource
    local datasources
    datasources=$(curl -s -u admin:admin http://localhost:3000/api/datasources 2>/dev/null || echo "")
    if echo "$datasources" | grep -q '"type":"prometheus"'; then
        pass "grafana: Prometheus datasource auto-provisioned"
    else
        echo "  INFO: Prometheus datasource not found (may not be provisioned in test image)"
    fi

    # Auto-provisioned workload dashboard
    local search
    search=$(curl -s -u admin:admin 'http://localhost:3000/api/search?query=workload' 2>/dev/null || echo "")
    if echo "$search" | grep -qi 'workload'; then
        pass "grafana: workload dashboard auto-provisioned"
    else
        echo "  INFO: workload dashboard not found (may not be in test image)"
    fi
}
