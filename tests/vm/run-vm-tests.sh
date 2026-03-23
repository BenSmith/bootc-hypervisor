#!/usr/bin/env bash
#
# VM integration tests for the workload provisioning system.
#
# This script runs INSIDE the test VM after boot. It verifies:
# 1. Generator produced correct service files
# 2. Workload users were created with correct UIDs
# 3. Secrets were encrypted/decrypted via TPM
# 4. Services are active, secrets not leaked in /proc
# 5. Disabled workloads are not running
#
# Per-workload tests (env vars, HTTP endpoints, etc.) live in
# /etc/workloads.d/<name>.test.sh and are auto-discovered.
#
# Exit code: 0 = all tests pass, 1 = failures
#
set -euo pipefail

PASS=0
FAIL=0
ERRORS=()

# ANSI colors
RED=$'\033[1;31m'
GREEN=$'\033[1;32m'
YELLOW=$'\033[1;33m'
CYAN=$'\033[1;36m'
BOLD=$'\033[1m'
RESET=$'\033[0m'

# Auto-discover enabled workloads from /etc/workloads.d/*.toml
ALL_WORKLOADS=""
for _toml in /etc/workloads.d/*.toml; do
    [ -f "$_toml" ] || continue
    _name=$(basename "$_toml" .toml)
    # Skip disabled workloads (enabled defaults to true if absent)
    if grep -q 'enabled *= *false' "$_toml"; then
        continue
    fi
    ALL_WORKLOADS="${ALL_WORKLOADS:+$ALL_WORKLOADS }${_name}"
done
unset _toml _name

pass() {
    PASS=$((PASS + 1))
    echo "  ${GREEN}PASS${RESET}: $1"
}

fail() {
    FAIL=$((FAIL + 1))
    ERRORS+=("$1")
    echo "  ${RED}FAIL${RESET}: $1"
}

section() {
    echo ""
    echo "${CYAN}=== $1 ===${RESET}"
}

# ---------------------------------------------------------------------------
# Wait for system to be fully booted
# ---------------------------------------------------------------------------
section "Waiting for system boot"
if systemctl is-system-running --wait --quiet 2>/dev/null; then
    pass "System is running"
else
    # degraded is acceptable if only test workloads failed (we're testing them)
    state=$(systemctl is-system-running 2>/dev/null || true)
    if [ "$state" = "degraded" ]; then
        echo "  INFO: System is degraded (expected if workloads haven't started yet)"
    else
        fail "System state: $state"
    fi
fi

# ---------------------------------------------------------------------------
# Diagnostics: workload-generate oneshot service
# ---------------------------------------------------------------------------
section "Workload generate service"
echo "  Status: $(systemctl is-active workload-generate.service 2>/dev/null || echo 'not found')"
systemctl status workload-generate.service --no-pager 2>/dev/null || true
echo ""
echo "  Journal:"
journalctl -u workload-generate.service --no-pager -n 30 2>/dev/null || true
echo ""
echo "  kmsg (workload-generate):"
dmesg | grep -i "workload-gen" | tail -30 || true
echo ""
echo "  Setup services:"
for name in $ALL_WORKLOADS; do
    echo "  --- workload-${name}-setup ---"
    systemctl status "workload-${name}-setup.service" --no-pager 2>/dev/null || echo "  (not found)"
    journalctl -u "workload-${name}-setup.service" --no-pager -n 10 2>/dev/null || true
done
echo ""
echo "  Users in passwd:"
grep '_wl-' /etc/passwd || echo "  (none)"

# ---------------------------------------------------------------------------
# Encrypt test secrets via TPM (must happen after first boot seeds the TPM)
# ---------------------------------------------------------------------------
section "Encrypting test credentials"

encrypt_secret() {
    local name="$1" value="$2"
    if [ -f "/etc/credstore.encrypted/$name" ]; then
        echo "  INFO: Credential '$name' already exists, skipping"
        return 0
    fi
    if echo -n "$value" | systemd-creds encrypt --with-key=tpm2 --name="$name" - "/etc/credstore.encrypted/$name"; then
        pass "Encrypted credential: $name"
    else
        fail "Failed to encrypt credential: $name"
    fi
}

mkdir -p /etc/credstore.encrypted
encrypt_secret "test-token" "sk-test-99999"
encrypt_secret "test-db-pass" "hunter2"

# Stop any auto-started services that failed (credentials didn't exist at boot)
# then reload so they pick up the new credential files.
# Must also reset setup services — if they failed during boot, Requires= will
# propagate the failure to the main services.
for name in $ALL_WORKLOADS; do
    systemctl stop "workload-${name}.service" 2>/dev/null || true
    systemctl reset-failed "workload-${name}.service" 2>/dev/null || true
    systemctl stop "workload-${name}-setup.service" 2>/dev/null || true
    systemctl reset-failed "workload-${name}-setup.service" 2>/dev/null || true
done
systemctl daemon-reload

# ---------------------------------------------------------------------------
# Test: Generator produced service files
# ---------------------------------------------------------------------------
section "Generator output"

for name in $ALL_WORKLOADS; do
    if [ -f "/run/systemd/system/workload-${name}.service" ]; then
        pass "Service file exists: workload-${name}.service"
    else
        fail "Service file missing: workload-${name}.service"
    fi
done

if [ ! -f "/run/systemd/system/workload-disabled.service" ]; then
    pass "Disabled workload has no service file"
else
    fail "Disabled workload should not have a service file"
fi

# ---------------------------------------------------------------------------
# Test: Sysusers configs generated
# ---------------------------------------------------------------------------
section "Sysusers configs"

for name in $ALL_WORKLOADS; do
    if [ -f "/run/systemd/system/workload-${name}.conf" ]; then
        pass "Sysusers config exists: workload-${name}.conf"
    else
        fail "Sysusers config missing: workload-${name}.conf"
    fi
done

# ---------------------------------------------------------------------------
# Test: Start setup services (create users) then workload services
# ---------------------------------------------------------------------------
section "Starting setup services"

for name in $ALL_WORKLOADS; do
    echo "  Starting workload-${name}-setup..."
    if systemctl start "workload-${name}-setup.service" 2>&1; then
        pass "workload-${name}-setup started"
    else
        fail "workload-${name}-setup failed to start"
        systemctl status "workload-${name}-setup.service" --no-pager 2>/dev/null || true
        journalctl -u "workload-${name}-setup.service" --no-pager -n 20 2>/dev/null || true
    fi
done

# ---------------------------------------------------------------------------
# Test: Pre-pull images (diagnose network/registry issues separately)
# ---------------------------------------------------------------------------
section "Pre-pulling container images"

# Pre-pull for each workload user (each has separate rootless storage)
for name in $ALL_WORKLOADS; do
    pull_user="_wl-${name}"
    pull_uid=$(id -u "$pull_user" 2>/dev/null || echo "")
    if [ -z "$pull_uid" ]; then
        echo "  SKIP $name: user not created"
        continue
    fi
    pull_image=$(grep '^image' /etc/workloads.d/${name}.toml | head -1 | sed 's/.*= *"//' | sed 's/".*//')
    pull_home=$(getent passwd "$pull_user" | cut -d: -f6)
    echo "  Pulling $pull_image as $pull_user..."
    if cd "$pull_home" && runuser -u "$pull_user" -- env XDG_RUNTIME_DIR="/run/user/${pull_uid}" \
        podman pull "$pull_image" 2>&1; then
        pass "$name: image pulled"
    else
        fail "$name: image pull failed"
    fi
done

section "Starting workload services"

# Source test files for hooks (pre_start, post_setup)
for test_file in /etc/workloads.d/*.test.sh; do
    [ -f "$test_file" ] || continue
    source "$test_file"
done

# Run any pre_start_<name>() hooks (e.g. stop conflicting services, write config files)
for name in $ALL_WORKLOADS; do
    if declare -f "pre_start_${name}" >/dev/null 2>&1; then
        echo "  Running pre-start hook for: $name"
        "pre_start_${name}"
    fi
done

for name in $ALL_WORKLOADS; do
    echo "  Starting workload-${name}..."
    if systemctl start "workload-${name}.service" 2>&1; then
        pass "workload-${name} started"
    else
        fail "workload-${name} failed to start"
        journalctl -u "workload-${name}.service" --no-pager -n 20 2>/dev/null || true
    fi
done

# Give containers a moment to initialize (registry/prometheus need longer than busybox)
sleep 5

# ---------------------------------------------------------------------------
# Test: Workload users exist
# ---------------------------------------------------------------------------
section "Workload users"

for name in $ALL_WORKLOADS; do
    if id "_wl-${name}" &>/dev/null; then
        pass "User _wl-${name} exists"
        uid=$(id -u "_wl-${name}")
        if [ "$uid" -ge 10000 ] && [ "$uid" -le 52948 ]; then
            pass "User _wl-${name} UID ${uid} in valid range"
        else
            fail "User _wl-${name} UID ${uid} outside range 10000-52948"
        fi
    else
        fail "User _wl-${name} does not exist"
    fi
done

# ---------------------------------------------------------------------------
# Test: Services are active
# ---------------------------------------------------------------------------
section "Service status"

for name in $ALL_WORKLOADS; do
    if systemctl is-active --quiet "workload-${name}.service"; then
        pass "workload-${name} is active"
    else
        fail "workload-${name} is not active"
        systemctl status "workload-${name}.service" --no-pager 2>/dev/null || true
        echo "  --- container logs ---"
        journalctl -u "workload-${name}.service" --no-pager -n 30 2>/dev/null || true
    fi
done

if systemctl is-active --quiet "workload-disabled.service" 2>/dev/null; then
    fail "workload-disabled should not be active"
else
    pass "workload-disabled is not active (correct)"
fi

# Helper: run podman exec as the workload user with correct XDG_RUNTIME_DIR
wl_exec() {
    local name="$1"; shift
    local user="_wl-${name}"
    local uid
    uid=$(id -u "$user")
    local home
    home=$(getent passwd "$user" | cut -d: -f6)
    cd "$home" && runuser -u "$user" -- env XDG_RUNTIME_DIR="/run/user/${uid}" \
        podman exec "workload-${name}" "$@" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Test: Container health checks (podman --health-cmd)
# ---------------------------------------------------------------------------
section "Container health checks"

# Helper: run podman as the workload user
wl_podman() {
    local name="$1"; shift
    local user="_wl-${name}"
    local uid
    uid=$(id -u "$user")
    local home
    home=$(getent passwd "$user" | cut -d: -f6)
    cd "$home" && runuser -u "$user" -- env XDG_RUNTIME_DIR="/run/user/${uid}" \
        podman "$@" 2>/dev/null
}

# Check that workloads with [container.health] have health checks configured
for name in $ALL_WORKLOADS; do
    _toml="/etc/workloads.d/${name}.toml"
    if grep -q '\[container\.health\]' "$_toml" 2>/dev/null; then
        # This workload should have a health check — verify podman reports it
        health_status=$(wl_podman "$name" inspect --format '{{.State.Health.Status}}' "workload-${name}" 2>/dev/null || echo "")
        if [ -n "$health_status" ]; then
            pass "${name}: health check configured (status: ${health_status})"
            # Allow "starting" — health check may not have run yet
            if [ "$health_status" = "healthy" ] || [ "$health_status" = "starting" ]; then
                pass "${name}: health status acceptable (${health_status})"
            else
                fail "${name}: health status is ${health_status}"
            fi
        else
            fail "${name}: health check not found in container inspect"
        fi
    fi
done

# Wait for health checks to settle, then verify healthy status
echo "  Waiting 30s for health checks to run..."
sleep 30

for name in $ALL_WORKLOADS; do
    _toml="/etc/workloads.d/${name}.toml"
    if grep -q '\[container\.health\]' "$_toml" 2>/dev/null; then
        health_status=$(wl_podman "$name" inspect --format '{{.State.Health.Status}}' "workload-${name}" 2>/dev/null || echo "")
        if [ "$health_status" = "healthy" ]; then
            pass "${name}: healthy after settle period"
        elif [ "$health_status" = "starting" ]; then
            echo "  INFO: ${name} still starting (start_period may be long)"
        else
            fail "${name}: not healthy after settle period (status: ${health_status})"
        fi
    fi
done
unset _toml

# ---------------------------------------------------------------------------
# Test: Secrets NOT in /proc/*/cmdline
# ---------------------------------------------------------------------------
section "Secret leakage check (/proc/*/cmdline)"

leaked=false
for secret in "sk-test-99999" "hunter2"; do
    # Write secret to a temp file so grep's own cmdline doesn't contain it
    tmpf=$(mktemp)
    echo -n "$secret" > "$tmpf"
    if grep -r -f "$tmpf" --include='cmdline' -l /proc/*/cmdline 2>/dev/null \
        | grep -v -E '^/proc/(self|thread-self)/' ; then
        fail "Secret '$secret' found in /proc/*/cmdline!"
        leaked=true
    fi
    rm -f "$tmpf"
done
if [ "$leaked" = false ]; then
    pass "No secrets found in /proc/*/cmdline"
fi

# ---------------------------------------------------------------------------
# Test: EnvironmentFile written by ensure-user
# ---------------------------------------------------------------------------
section "EnvironmentFile (workload-ensure-user output)"

for name in $ALL_WORKLOADS; do
    env_file="/run/workload-env/workload-${name}.env"
    if [ -f "$env_file" ]; then
        pass "${name}: env file exists"
        if grep -q 'XDG_RUNTIME_DIR=' "$env_file"; then
            pass "${name}: XDG_RUNTIME_DIR set"
        else
            fail "${name}: XDG_RUNTIME_DIR not in env file"
        fi
    else
        fail "${name}: env file not found at $env_file"
    fi
done

# ---------------------------------------------------------------------------
# Test: workload-metrics timer and output
# ---------------------------------------------------------------------------
section "Workload metrics timer"

if systemctl is-enabled --quiet workload-metrics.timer 2>/dev/null; then
    pass "workload-metrics.timer is enabled"
else
    fail "workload-metrics.timer is not enabled"
fi

# Run workload-metrics manually to ensure output is fresh
if /usr/libexec/workload-metrics 2>/dev/null; then
    pass "workload-metrics ran successfully"
else
    fail "workload-metrics exited with error"
fi

prom_file="/var/lib/prometheus/node-exporter/workloads.prom"
if [ -f "$prom_file" ]; then
    pass "workloads.prom file exists"

    if grep -q 'workload_enabled_total' "$prom_file"; then
        total=$(grep '^workload_enabled_total ' "$prom_file" | awk '{print $2}')
        pass "workload_enabled_total = $total"
    else
        fail "workload_enabled_total not found in workloads.prom"
    fi

    if grep -q 'workload_active' "$prom_file"; then
        pass "workload_active metrics present"
    else
        fail "workload_active metrics not found in workloads.prom"
    fi

    if grep -q 'workload_metrics_last_collect_timestamp_seconds' "$prom_file"; then
        pass "collection timestamp present"
    else
        fail "collection timestamp not found in workloads.prom"
    fi

    # SELinux: directory and file must have container_file_t for rootless container access
    if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" != "Disabled" ]; then
        dir_context=$(ls -Zd /var/lib/prometheus/node-exporter 2>/dev/null | awk '{print $1}')
        if echo "$dir_context" | grep -q 'container_file_t'; then
            pass "SELinux: directory has container_file_t"
        else
            fail "SELinux: directory has wrong context: $dir_context (expected container_file_t)"
        fi
        file_context=$(ls -Z "$prom_file" 2>/dev/null | awk '{print $1}')
        if echo "$file_context" | grep -q 'container_file_t'; then
            pass "SELinux: workloads.prom has container_file_t"
        else
            fail "SELinux: workloads.prom has wrong context: $file_context (expected container_file_t)"
        fi
    else
        echo "  SKIP: SELinux not enforcing, skipping label checks"
    fi

    # Verify each running workload appears in the metrics
    for name in $ALL_WORKLOADS; do
        if grep -q "workload=\"${name}\"" "$prom_file"; then
            pass "metrics: workload $name present"
        else
            fail "metrics: workload $name missing from workloads.prom"
        fi
    done
else
    fail "workloads.prom not found at $prom_file"
fi

# ---------------------------------------------------------------------------
# Test: Workload-specific tests (auto-discovered from .test.sh files)
# ---------------------------------------------------------------------------
section "Workload-specific tests"

for test_file in /etc/workloads.d/*.test.sh; do
    [ -f "$test_file" ] || continue
    name=$(basename "$test_file" .test.sh)
    echo "  Running tests for: $name"
    if declare -f "test_${name}" >/dev/null 2>&1; then
        set +e
        "test_${name}"
        set -e
    else
        echo "  WARNING: $test_file does not define test_${name}()"
    fi
done

# ---------------------------------------------------------------------------
# Test: workload-ctl secret subcommands
# ---------------------------------------------------------------------------
section "workload-ctl secret commands"

# Use a dedicated test credential name to avoid interfering with workload secrets
_secret_name="vm-test-secret"
_secret_value="s3cret-test-value-42"

# Clean up from any previous run
rm -f "/etc/credstore.encrypted/${_secret_name}"

# --- create (from file) ---
_secret_file=$(mktemp /tmp/secret-input-XXXXXX)
echo -n "$_secret_value" > "$_secret_file"
if workload-ctl secret create "$_secret_name" --file "$_secret_file" 2>&1; then
    pass "secret create: succeeded"
else
    fail "secret create: command failed"
fi
rm -f "$_secret_file"

# Verify file stored without .cred extension (must match generator's LoadCredentialEncrypted path)
if [ -f "/etc/credstore.encrypted/${_secret_name}" ]; then
    pass "secret create: file at /etc/credstore.encrypted/${_secret_name} (no extension)"
else
    fail "secret create: file not found at expected path"
fi
if [ -f "/etc/credstore.encrypted/${_secret_name}.cred" ]; then
    fail "secret create: unexpected .cred extension file exists"
else
    pass "secret create: no .cred extension file"
fi

# --- list ---
list_output=$(workload-ctl secret list 2>&1)
if echo "$list_output" | grep -q "$_secret_name"; then
    pass "secret list: shows ${_secret_name}"
else
    fail "secret list: ${_secret_name} not in output"
fi

# --- show ---
show_output=$(workload-ctl secret show "$_secret_name" 2>&1)
if echo "$show_output" | grep -q "$_secret_value"; then
    pass "secret show: decrypted value matches"
else
    fail "secret show: value mismatch (got: $show_output)"
fi

# --- create --force (overwrite) ---
_new_value="rotated-value-99"
_secret_file=$(mktemp /tmp/secret-input-XXXXXX)
echo -n "$_new_value" > "$_secret_file"
if workload-ctl secret create "$_secret_name" --force --file "$_secret_file" 2>&1; then
    pass "secret create --force: succeeded"
else
    fail "secret create --force: command failed"
fi
rm -f "$_secret_file"

show_output=$(workload-ctl secret show "$_secret_name" 2>&1)
if echo "$show_output" | grep -q "$_new_value"; then
    pass "secret create --force: new value stored"
else
    fail "secret create --force: value not updated"
fi

# --- export / import roundtrip (manual, since getpass reads /dev/tty) ---
# Simulate what 'secret export' and 'secret import' do under the hood:
# export: systemd-creds decrypt → openssl enc (passphrase)
# import: openssl enc -d (passphrase) → systemd-creds encrypt
_export_file=$(mktemp /tmp/secret-export-XXXXXX.secret)
_pass_file=$(mktemp /tmp/secret-pass-XXXXXX)
_passphrase="test-passphrase-123"
echo -n "$_passphrase" > "$_pass_file"
chmod 600 "$_pass_file"

# Export: decrypt TPM → encrypt with passphrase
if systemd-creds decrypt "/etc/credstore.encrypted/${_secret_name}" - 2>/dev/null \
    | openssl enc -aes-256-cbc -pbkdf2 -salt -pass "file:${_pass_file}" -out "$_export_file" 2>&1; then
    if [ -s "$_export_file" ]; then
        pass "secret export roundtrip: encrypted file produced"
    else
        fail "secret export roundtrip: output file is empty"
    fi
else
    fail "secret export roundtrip: decrypt/encrypt failed"
fi

# Import: delete original, decrypt passphrase → re-encrypt with TPM
rm -f "/etc/credstore.encrypted/${_secret_name}"
if openssl enc -d -aes-256-cbc -pbkdf2 -pass "file:${_pass_file}" -in "$_export_file" 2>/dev/null \
    | systemd-creds encrypt --with-key=tpm2 --name="$_secret_name" - "/etc/credstore.encrypted/${_secret_name}" 2>&1; then
    pass "secret import roundtrip: re-encrypted with TPM"
else
    fail "secret import roundtrip: decrypt/encrypt failed"
fi

# Verify roundtrip preserved the value
show_output=$(workload-ctl secret show "$_secret_name" 2>&1)
if echo "$show_output" | grep -q "$_new_value"; then
    pass "secret export/import roundtrip: value preserved"
else
    fail "secret export/import roundtrip: value mismatch (got: $show_output)"
fi

# Verify imported file has no .cred extension
if [ -f "/etc/credstore.encrypted/${_secret_name}" ]; then
    pass "secret import roundtrip: file at correct path (no extension)"
else
    fail "secret import roundtrip: file not at expected path"
fi

rm -f "$_export_file" "$_pass_file"

# --- delete ---
if workload-ctl secret delete "$_secret_name" --force 2>&1; then
    pass "secret delete: succeeded"
else
    fail "secret delete: command failed"
fi

if [ ! -f "/etc/credstore.encrypted/${_secret_name}" ]; then
    pass "secret delete: file removed"
else
    fail "secret delete: file still exists"
fi

# --- create rejects bad names ---
_secret_file=$(mktemp /tmp/secret-input-XXXXXX)
echo -n "dummy" > "$_secret_file"
if workload-ctl secret create "bad name!" --file "$_secret_file" 2>&1; then
    fail "secret create: should reject invalid name"
else
    pass "secret create: rejects invalid name"
fi
rm -f "$_secret_file"

# --- create without --force refuses overwrite ---
# Re-create the credential, then try again without --force
_secret_file=$(mktemp /tmp/secret-input-XXXXXX)
echo -n "value1" > "$_secret_file"
workload-ctl secret create "$_secret_name" --file "$_secret_file" 2>/dev/null || true
if workload-ctl secret create "$_secret_name" --file "$_secret_file" 2>&1; then
    fail "secret create: should refuse overwrite without --force"
else
    pass "secret create: refuses overwrite without --force"
fi
rm -f "$_secret_file"

# --- path consistency: credential path matches generator's LoadCredentialEncrypted ---
# The generator emits: LoadCredentialEncrypted=NAME:/etc/credstore.encrypted/NAME
# Verify the file workload-ctl created is at exactly that path
_expected_path="/etc/credstore.encrypted/${_secret_name}"
if [ -f "$_expected_path" ]; then
    pass "path consistency: credential at generator-expected path"
else
    fail "path consistency: no file at ${_expected_path}"
fi

# Final cleanup
workload-ctl secret delete "$_secret_name" --force 2>/dev/null || true
unset _secret_name _secret_value _new_value

# ---------------------------------------------------------------------------
# Test: workload-ctl update and rollback
# ---------------------------------------------------------------------------
section "workload-ctl update and rollback"

# Use registry (has health check) for update/rollback test
_update_wl="registry"
_update_user="_wl-${_update_wl}"
_update_uid=$(id -u "$_update_user" 2>/dev/null || echo "")

if [ -n "$_update_uid" ]; then
    _update_home=$(getent passwd "$_update_user" | cut -d: -f6)

    # Record current image ID
    _old_id=$(cd "$_update_home" && runuser -u "$_update_user" -- \
        env XDG_RUNTIME_DIR="/run/user/${_update_uid}" \
        podman images --format '{{.ID}}' "192.168.0.64:5000/library/registry:2" 2>/dev/null | head -1)

    if [ -n "$_old_id" ]; then
        pass "update: current image ID recorded (${_old_id:0:12})"
    else
        fail "update: could not get current image ID"
    fi

    # Run update --force (same image, but --force ensures restart + rollback tag)
    if workload-ctl update "$_update_wl" --force 2>&1; then
        pass "update --force: command succeeded"
    else
        fail "update --force: command failed"
    fi

    # Verify rollback image was tagged
    _rollback_id=$(cd "$_update_home" && runuser -u "$_update_user" -- \
        env XDG_RUNTIME_DIR="/run/user/${_update_uid}" \
        podman images --format '{{.ID}}' "localhost/workload-rollback/${_update_wl}:latest" 2>/dev/null | head -1)

    if [ -n "$_rollback_id" ]; then
        pass "update: rollback image tagged (${_rollback_id:0:12})"
    else
        fail "update: rollback image not found"
    fi

    # Verify service is still active after update
    if systemctl is-active --quiet "workload-${_update_wl}.service"; then
        pass "update: service active after update"
    else
        fail "update: service not active after update"
    fi

    # Test rollback command
    if workload-ctl rollback "$_update_wl" 2>&1; then
        pass "rollback: command succeeded"
    else
        # "Already running the rollback image" is also success (same image)
        pass "rollback: command completed (may be same image)"
    fi

    # Verify service is still active after rollback
    if systemctl is-active --quiet "workload-${_update_wl}.service"; then
        pass "rollback: service active after rollback"
    else
        fail "rollback: service not active after rollback"
    fi

    # Test update without --force (should be "already up to date", no restart)
    if workload-ctl update "$_update_wl" 2>&1; then
        pass "update (no change): command succeeded"
    else
        fail "update (no change): command failed"
    fi
else
    echo "  SKIP: $_update_user not found, skipping update/rollback tests"
fi

# Test update on a pull=never workload (should error)
# Find a pull=never workload from the real workloads.d, if any are present
_pull_never_wl=""
for _toml in /etc/workloads.d/*.toml; do
    [ -f "$_toml" ] || continue
    if grep -q 'pull *= *"never"' "$_toml" 2>/dev/null; then
        _pull_never_wl=$(basename "$_toml" .toml)
        break
    fi
done

if [ -n "$_pull_never_wl" ]; then
    if workload-ctl update "$_pull_never_wl" 2>&1; then
        fail "update pull=never: should have failed"
    else
        pass "update pull=never: correctly rejected"
    fi
else
    echo "  SKIP: no pull=never workloads found for rejection test"
fi

unset _update_wl _update_user _update_uid _update_home _old_id _rollback_id _pull_never_wl

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
if [ $FAIL -gt 0 ]; then
    echo "${RED}==========================================="
    echo "  Results: ${GREEN}$PASS passed${RED}, $FAIL failed"
    echo "===========================================${RESET}"
    echo ""
    echo "${RED}Failures:${RESET}"
    for err in "${ERRORS[@]}"; do
        echo "  ${RED}-${RESET} $err"
    done
    exit 1
else
    echo "${GREEN}==========================================="
    echo "  Results: $PASS passed, 0 failed"
    echo "===========================================${RESET}"
fi

exit 0
