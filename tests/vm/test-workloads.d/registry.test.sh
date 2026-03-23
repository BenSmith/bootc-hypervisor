# Tests for registry workload
test_registry() {
    if ! systemctl is-active --quiet workload-registry.service; then
        fail "registry: service not active, skipping HTTP tests"
        return
    fi

    local registry_ok=false response
    for i in 1 2 3 4 5; do
        response=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:5000/v2/ 2>/dev/null || echo "000")
        if [ "$response" = "200" ]; then
            registry_ok=true
            break
        fi
        sleep 2
    done
    if [ "$registry_ok" = true ]; then
        pass "registry: /v2/ returns 200"
    else
        fail "registry: /v2/ returned $response (expected 200)"
    fi

    local catalog
    catalog=$(curl -s http://localhost:5000/v2/_catalog 2>/dev/null || echo "")
    if echo "$catalog" | grep -q '"repositories"'; then
        pass "registry: /v2/_catalog returns valid JSON"
    else
        fail "registry: /v2/_catalog response invalid: $catalog"
    fi
}
