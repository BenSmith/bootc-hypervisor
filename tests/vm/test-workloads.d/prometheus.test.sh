# Tests for prometheus node-exporter workload
test_prometheus() {
    if ! systemctl is-active --quiet workload-prometheus.service; then
        fail "prometheus: service not active, skipping HTTP tests"
        return
    fi

    local prom_ok=false response
    for i in 1 2 3 4 5; do
        response=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:9100/metrics 2>/dev/null || echo "000")
        if [ "$response" = "200" ]; then
            prom_ok=true
            break
        fi
        sleep 2
    done
    if [ "$prom_ok" = true ]; then
        pass "prometheus: /metrics returns 200"
    else
        fail "prometheus: /metrics returned $response (expected 200)"
    fi

    # Fetch once to a file — metrics output can be several MB, too large for shell vars
    local metrics_file
    metrics_file=$(mktemp)
    curl -s http://localhost:9100/metrics >"$metrics_file" 2>/dev/null || true

    if grep -q 'node_cpu_seconds_total' "$metrics_file"; then
        pass "prometheus: metrics contain node_cpu_seconds_total"
    else
        fail "prometheus: node_cpu_seconds_total not found in metrics output"
    fi
    if grep -qi 'node_memory_' "$metrics_file"; then
        pass "prometheus: metrics contain node_memory_* entries"
    else
        fail "prometheus: no node_memory_* metrics found in output"
    fi

    # Textfile collector: workload metrics from workload-metrics timer
    if grep -q 'workload_active' "$metrics_file"; then
        pass "prometheus: textfile collector has workload_active metric"
    else
        fail "prometheus: workload_active not found (textfile collector not working?)"
        echo "  Check: ls -la /var/lib/prometheus/node-exporter/"
        ls -la /var/lib/prometheus/node-exporter/ 2>/dev/null || echo "  (dir missing)"
    fi
    if grep -q 'workload_enabled_total' "$metrics_file"; then
        pass "prometheus: textfile collector has workload_enabled_total"
    else
        fail "prometheus: workload_enabled_total not found in metrics"
    fi

    rm -f "$metrics_file"
}
