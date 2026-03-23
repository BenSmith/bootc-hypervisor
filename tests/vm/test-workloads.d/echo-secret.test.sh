# Tests for echo-secret workload
test_echo-secret() {
    # Service file checks
    local svc
    svc=$(cat /run/systemd/system/workload-echo-secret.service 2>/dev/null || echo "")
    if [ -n "$svc" ]; then
        if echo "$svc" | grep -q -- '--env-file'; then
            pass "echo-secret: has --env-file"
        else
            fail "echo-secret: missing --env-file"
        fi
        if echo "$svc" | grep -q 'workload-write-env'; then
            pass "echo-secret: has workload-write-env in ExecStartPre"
        else
            fail "echo-secret: missing workload-write-env"
        fi
        if echo "$svc" | grep -q -- '--env TOKEN='; then
            fail "echo-secret: TOKEN should NOT be in --env args (it's a secret)"
        else
            pass "echo-secret: TOKEN not leaked in --env args"
        fi
        if echo "$svc" | grep -q -- '--env MODE='; then
            pass "echo-secret: plain var MODE passed as --env"
        else
            fail "echo-secret: MODE not found as --env arg"
        fi
        if echo "$svc" | grep -q 'LoadCredentialEncrypted=test-token:'; then
            pass "echo-secret: LoadCredentialEncrypted for test-token"
        else
            fail "echo-secret: missing LoadCredentialEncrypted for test-token"
        fi
    fi

    # Runtime env check
    local env_out
    env_out=$(wl_exec echo-secret env || echo "")
    if echo "$env_out" | grep -q 'TOKEN=sk-test-99999'; then
        pass "echo-secret: TOKEN=sk-test-99999 (decrypted correctly)"
    else
        fail "echo-secret: TOKEN not found or wrong value"
        echo "  Got: $(echo "$env_out" | grep TOKEN || echo '(not found)')"
    fi
    if echo "$env_out" | grep -q 'MODE=testing'; then
        pass "echo-secret: MODE=testing (plain var)"
    else
        fail "echo-secret: MODE not found or wrong value"
    fi

    # Secrets file permissions
    local secrets_file="/run/workload-env/workload-echo-secret.secrets"
    if [ -f "$secrets_file" ]; then
        local perms owner
        perms=$(stat -c '%a' "$secrets_file")
        if [ "$perms" = "600" ]; then
            pass "echo-secret: secrets file mode 600"
        else
            fail "echo-secret: secrets file mode $perms (expected 600)"
        fi
        owner=$(stat -c '%U' "$secrets_file")
        if [ "$owner" = "_wl-echo-secret" ]; then
            pass "echo-secret: secrets file owned by _wl-echo-secret"
        else
            fail "echo-secret: secrets file owned by $owner (expected _wl-echo-secret)"
        fi
    else
        fail "echo-secret: secrets file not found at $secrets_file"
    fi
}
