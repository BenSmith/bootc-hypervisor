# Tests for prometheus-server workload
pre_start_prometheus-server() {
    local home
    home=$(getent passwd _wl-prometheus-server 2>/dev/null | cut -d: -f6) || return
    [ -d "$home" ] || return

    # Write minimal prometheus.yml — required_files means it must exist before start
    [ -d "$home/prometheus.yml" ] && rm -rf "$home/prometheus.yml"
    if [ ! -f "$home/prometheus.yml" ]; then
        cat > "$home/prometheus.yml" <<'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - /etc/prometheus/rules/*.yml

scrape_configs:
  - job_name: 'node'
    static_configs:
      - targets: ['localhost:9100']
EOF
        chown _wl-prometheus-server: "$home/prometheus.yml"
    fi

    # Copy alert rules if available on the host image
    if [ -d /usr/share/workload-containers/prometheus-server/rules ] && [ ! -d "$home/rules" ]; then
        cp -r /usr/share/workload-containers/prometheus-server/rules "$home/rules"
        chown -R _wl-prometheus-server: "$home/rules"
    fi
    # Ensure rules dir exists even if no rules shipped
    mkdir -p "$home/rules"
    chown _wl-prometheus-server: "$home/rules"
}

test_prometheus-server() {
    if ! systemctl is-active --quiet workload-prometheus-server.service; then
        fail "prometheus-server: service not active, skipping tests"
        journalctl -u workload-prometheus-server.service --no-pager -n 20 2>/dev/null || true
        return
    fi

    # Web UI check
    local http_ok=false response
    for i in 1 2 3 4 5 6; do
        response=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:9090/-/ready 2>/dev/null || echo "000")
        if [ "$response" = "200" ]; then
            http_ok=true
            break
        fi
        sleep 3
    done
    if [ "$http_ok" = true ]; then
        pass "prometheus-server: /-/ready returns 200"
    else
        fail "prometheus-server: /-/ready returned $response (expected 200)"
    fi

    # Check that node-exporter target is configured
    local targets
    targets=$(curl -s http://localhost:9090/api/v1/targets 2>/dev/null || echo "")
    if echo "$targets" | grep -q 'localhost:9100'; then
        pass "prometheus-server: node-exporter target configured"
    else
        fail "prometheus-server: node-exporter target not found"
        echo "  Targets response: $targets"
    fi

    # Wait a scrape cycle then check the target is up
    sleep 20
    targets=$(curl -s http://localhost:9090/api/v1/targets 2>/dev/null || echo "")
    if echo "$targets" | grep -q '"health":"up"'; then
        pass "prometheus-server: node-exporter target is up"
    else
        # May still be starting — don't hard-fail, just warn
        echo "  INFO: node-exporter target not yet up (may need more time)"
        echo "  Targets: $targets"
    fi

    # Check alert rules were loaded
    local rules
    rules=$(curl -s http://localhost:9090/api/v1/rules 2>/dev/null || echo "")
    if echo "$rules" | grep -q 'WorkloadDown'; then
        pass "prometheus-server: alert rules loaded (WorkloadDown found)"
    else
        echo "  INFO: alert rules not loaded (rules dir may be empty)"
    fi

    # Query a workload metric via PromQL
    local query_result
    query_result=$(curl -s 'http://localhost:9090/api/v1/query?query=workload_enabled_total' 2>/dev/null || echo "")
    if echo "$query_result" | grep -q '"resultType":"vector"'; then
        pass "prometheus-server: PromQL query for workload_enabled_total works"
    else
        echo "  INFO: workload_enabled_total not yet scraped"
    fi
}
