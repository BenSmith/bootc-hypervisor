# Tests for echo-mixed workload
test_echo-mixed() {
    # Runtime env check
    local env_out
    env_out=$(wl_exec echo-mixed env || echo "")
    if echo "$env_out" | grep -q 'DSN=host=db password=hunter2 port=5432'; then
        pass "echo-mixed: DSN with embedded secret resolved correctly"
    else
        fail "echo-mixed: DSN not found or wrong value"
        echo "  Got: $(echo "$env_out" | grep DSN || echo '(not found)')"
    fi

    # Secrets file permissions
    local secrets_file="/run/workload-env/workload-echo-mixed.secrets"
    if [ -f "$secrets_file" ]; then
        local perms owner
        perms=$(stat -c '%a' "$secrets_file")
        if [ "$perms" = "600" ]; then
            pass "echo-mixed: secrets file mode 600"
        else
            fail "echo-mixed: secrets file mode $perms (expected 600)"
        fi
        owner=$(stat -c '%U' "$secrets_file")
        if [ "$owner" = "_wl-echo-mixed" ]; then
            pass "echo-mixed: secrets file owned by _wl-echo-mixed"
        else
            fail "echo-mixed: secrets file owned by $owner (expected _wl-echo-mixed)"
        fi
    else
        fail "echo-mixed: secrets file not found at $secrets_file"
    fi
}
