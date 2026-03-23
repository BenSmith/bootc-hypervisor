# Tests for echo-plain workload
test_echo-plain() {
    # Service file checks
    local svc
    svc=$(cat /run/systemd/system/workload-echo-plain.service 2>/dev/null || echo "")
    if [ -n "$svc" ]; then
        if echo "$svc" | grep -q -- '--env GREETING='; then
            pass "echo-plain: GREETING passed as --env"
        else
            fail "echo-plain: GREETING not found as --env arg"
        fi
        if echo "$svc" | grep -q -- '--env-file'; then
            fail "echo-plain: should not have --env-file (no secrets)"
        else
            pass "echo-plain: no --env-file (correct)"
        fi
        if echo "$svc" | grep -q 'workload-write-env'; then
            fail "echo-plain: should not call workload-write-env"
        else
            pass "echo-plain: no workload-write-env (correct)"
        fi
    fi

    # Runtime env check
    local env_out
    env_out=$(wl_exec echo-plain env || echo "")
    if echo "$env_out" | grep -q 'GREETING=hello-from-plain'; then
        pass "echo-plain: GREETING=hello-from-plain"
    else
        fail "echo-plain: GREETING not found or wrong value"
        echo "  Got: $(echo "$env_out" | grep GREETING || echo '(not found)')"
    fi

    # No secrets file
    if [ ! -f "/run/workload-env/workload-echo-plain.secrets" ]; then
        pass "echo-plain: no secrets file (correct)"
    else
        fail "echo-plain: should not have a secrets file"
    fi
}
