#!/bin/bash
# Smoke test for workload-ctl
# Tests basic functionality and JSON output for all commands
#
# Can be run in two modes:
# 1. Against installed system: sudo ./test-workload-ctl.sh
# 2. Against repo: ./test-workload-ctl.sh (from repo root)

# Don't exit on error - we want to run all tests
set +e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

# Test result tracking
test_pass() {
    echo -e "${GREEN}✓${NC} $1"
    ((PASS_COUNT++))
}

test_fail() {
    echo -e "${RED}✗${NC} $1"
    ((FAIL_COUNT++))
}

test_skip() {
    echo -e "${YELLOW}⊘${NC} $1"
    ((SKIP_COUNT++))
}

test_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# Check if running as root for commands that need it
check_root() {
    if [[ $EUID -ne 0 ]]; then
        return 1
    fi
    return 0
}

# Validate JSON output
validate_json() {
    local output="$1"
    if echo "$output" | python3 -m json.tool > /dev/null 2>&1; then
        return 0
    fi
    return 1
}

# Detect context: repo vs installed system
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKLOAD_CTL=""
WORKLOAD_DIR="/etc/workloads.d"
CONTEXT="unknown"

# Check if we're in the repo (workload-ctl exists in same directory as this script)
if [[ -f "$SCRIPT_DIR/workload-ctl" ]]; then
    WORKLOAD_CTL="$SCRIPT_DIR/workload-ctl"
    CONTEXT="repo"
    # In repo, workloads.d is in parent directory
    if [[ -d "$SCRIPT_DIR/../workloads.d" ]]; then
        WORKLOAD_DIR="$SCRIPT_DIR/../workloads.d"
    fi
elif command -v workload-ctl &> /dev/null; then
    WORKLOAD_CTL="workload-ctl"
    CONTEXT="installed"
else
    echo -e "${RED}Error: workload-ctl not found${NC}"
    echo "Not found in repo (./bin/workload-ctl) or in PATH"
    exit 1
fi

echo "========================================"
echo "workload-ctl Smoke Test"
echo "========================================"
echo ""
test_info "Context: $CONTEXT"
test_info "workload-ctl: $WORKLOAD_CTL"
test_info "Config directory: $WORKLOAD_DIR"

# Export config directory for workload-ctl to use (in repo mode)
if [[ "$CONTEXT" == "repo" ]]; then
    export WORKLOAD_CONFIG_DIR="$WORKLOAD_DIR"
    test_info "Exported: WORKLOAD_CONFIG_DIR=$WORKLOAD_CONFIG_DIR"
fi

echo ""

# Get first available workload for testing
WORKLOAD=""
if [[ -d "$WORKLOAD_DIR" ]]; then
    WORKLOAD=$(ls "$WORKLOAD_DIR"/*.toml 2>/dev/null | head -1 | xargs -r basename -s .toml)
fi

if [[ -z "$WORKLOAD" ]]; then
    test_info "No workloads found in $WORKLOAD_DIR - some tests will be skipped"
else
    test_info "Using workload: $WORKLOAD"
fi

echo ""
echo "========================================"
echo "Testing: list command"
echo "========================================"

# Test: list (no args)
if output=$("$WORKLOAD_CTL" list 2>&1); then
    test_pass "list command works"
else
    test_fail "list command failed"
fi

# Test: list --json
if output=$("$WORKLOAD_CTL" list --json 2>&1); then
    if validate_json "$output"; then
        test_pass "list --json produces valid JSON"
        # Check structure
        if echo "$output" | grep -q '"workloads"'; then
            test_pass "list --json has 'workloads' key"
        else
            test_fail "list --json missing 'workloads' key"
        fi
    else
        test_fail "list --json produces invalid JSON"
    fi
else
    test_fail "list --json failed"
fi

echo ""
echo "========================================"
echo "Testing: ps command"
echo "========================================"

# Test: ps (no args)
if output=$("$WORKLOAD_CTL" ps 2>&1); then
    test_pass "ps command works"
else
    test_fail "ps command failed"
fi

# Test: ps --json
if output=$("$WORKLOAD_CTL" ps --json 2>&1); then
    if validate_json "$output"; then
        test_pass "ps --json produces valid JSON"
        if echo "$output" | grep -q '"containers"'; then
            test_pass "ps --json has 'containers' key"
        else
            test_fail "ps --json missing 'containers' key"
        fi
    else
        test_fail "ps --json produces invalid JSON"
    fi
else
    test_fail "ps --json failed"
fi

echo ""
echo "========================================"
echo "Testing: images command"
echo "========================================"

# Test: images list
if output=$("$WORKLOAD_CTL" images list 2>&1); then
    test_pass "images list command works"
else
    test_fail "images list command failed"
fi

# Test: images list --json
if output=$("$WORKLOAD_CTL" images list --json 2>&1); then
    if validate_json "$output"; then
        test_pass "images list --json produces valid JSON"
        if echo "$output" | grep -q '"images"' && echo "$output" | grep -q '"total"'; then
            test_pass "images list --json has required keys"
        else
            test_fail "images list --json missing required keys"
        fi
    else
        test_fail "images list --json produces invalid JSON"
    fi
else
    test_fail "images list --json failed"
fi

# Workload-specific tests
if [[ -n "$WORKLOAD" ]]; then
    echo ""
    echo "========================================"
    echo "Testing: info command (workload: $WORKLOAD)"
    echo "========================================"

    # Test: info
    if output=$("$WORKLOAD_CTL" info "$WORKLOAD" 2>&1); then
        test_pass "info command works"
    else
        test_fail "info command failed"
    fi

    # Test: info --json
    if output=$("$WORKLOAD_CTL" info "$WORKLOAD" --json 2>&1); then
        if validate_json "$output"; then
            test_pass "info --json produces valid JSON"
            # Check for expected keys
            keys_found=0
            for key in "workload" "container" "user" "network" "storage" "service"; do
                if echo "$output" | grep -q "\"$key\""; then
                    ((keys_found++))
                fi
            done
            if [[ $keys_found -eq 6 ]]; then
                test_pass "info --json has all required sections"
            else
                test_fail "info --json missing some sections (found $keys_found/6)"
            fi
        else
            test_fail "info --json produces invalid JSON"
        fi
    else
        test_fail "info --json failed"
    fi

    echo ""
    echo "========================================"
    echo "Testing: validate command (workload: $WORKLOAD)"
    echo "========================================"

    # Test: validate
    if output=$("$WORKLOAD_CTL" validate "$WORKLOAD" 2>&1); then
        test_pass "validate command works"
    else
        # Validation failures are expected for some workloads
        test_info "validate command ran (may have found issues)"
    fi

    # Test: validate --json
    if output=$("$WORKLOAD_CTL" validate "$WORKLOAD" --json 2>&1); then
        if validate_json "$output"; then
            test_pass "validate --json produces valid JSON"
            # Check structure
            keys_found=0
            for key in "workload" "passed" "errors" "warnings" "checks"; do
                if echo "$output" | grep -q "\"$key\""; then
                    ((keys_found++))
                fi
            done
            if [[ $keys_found -eq 5 ]]; then
                test_pass "validate --json has all required keys"
            else
                test_fail "validate --json missing some keys (found $keys_found/5)"
            fi
        else
            test_fail "validate --json produces invalid JSON"
        fi
    else
        test_fail "validate --json command failed"
    fi

    echo ""
    echo "========================================"
    echo "Testing: ports command (workload: $WORKLOAD)"
    echo "========================================"

    # Test: ports
    if output=$("$WORKLOAD_CTL" ports "$WORKLOAD" 2>&1); then
        test_pass "ports command works"
    else
        test_fail "ports command failed"
    fi

    # Test: ports --json
    if output=$("$WORKLOAD_CTL" ports "$WORKLOAD" --json 2>&1); then
        if validate_json "$output"; then
            test_pass "ports --json produces valid JSON"
            if echo "$output" | grep -q '"workload"' && echo "$output" | grep -q '"network_mode"'; then
                test_pass "ports --json has required keys"
            else
                test_fail "ports --json missing required keys"
            fi
        else
            test_fail "ports --json produces invalid JSON"
        fi
    else
        test_fail "ports --json failed"
    fi

    echo ""
    echo "========================================"
    echo "Testing: health command (workload: $WORKLOAD)"
    echo "========================================"

    # Test: health
    if output=$("$WORKLOAD_CTL" health "$WORKLOAD" 2>&1); then
        test_pass "health command works"
    else
        # Health check failures are expected if workload isn't running
        test_info "health command ran (workload may be unhealthy)"
    fi

    # Test: health --json (exit code may be non-zero if unhealthy, which is expected)
    output=$("$WORKLOAD_CTL" health "$WORKLOAD" --json 2>&1) || true
    if validate_json "$output"; then
        test_pass "health --json produces valid JSON"
        # Check structure
        if echo "$output" | grep -q '"workload"' && echo "$output" | grep -q '"overall"' && echo "$output" | grep -q '"checks"'; then
            test_pass "health --json has all required keys"
        else
            test_fail "health --json missing required keys"
        fi
    else
        test_fail "health --json produces invalid JSON"
        echo "Output was: $output"
    fi

    echo ""
    echo "========================================"
    echo "Testing: status command (workload: $WORKLOAD)"
    echo "========================================"

    # Test: status (systemctl wrapper - just check it runs)
    if "$WORKLOAD_CTL" status "$WORKLOAD" > /dev/null 2>&1; then
        test_pass "status command works"
    else
        test_info "status command ran (service may not be active)"
    fi

else
    test_skip "Skipping workload-specific tests (no workloads found)"
fi

echo ""
echo "========================================"
echo "Testing: validate --all command"
echo "========================================"

# Test: validate --all
if output=$("$WORKLOAD_CTL" validate --all 2>&1); then
    test_pass "validate --all command works"
else
    test_info "validate --all ran (may have found issues)"
fi

# Test: validate --all --json (exit code may be non-zero if validation fails, which is expected)
output=$("$WORKLOAD_CTL" validate --all --json 2>&1) || true
if validate_json "$output"; then
    test_pass "validate --all --json produces valid JSON"
    if echo "$output" | grep -q '"validation_results"' && echo "$output" | grep -q '"all_passed"'; then
        test_pass "validate --all --json has required keys"
    else
        test_fail "validate --all --json missing required keys"
    fi
else
    test_fail "validate --all --json produces invalid JSON"
    echo "Output was: $output"
fi

echo ""
echo "========================================"
echo "Testing: Help and error handling"
echo "========================================"

# Test: Invalid command
if "$WORKLOAD_CTL" invalid-command > /dev/null 2>&1; then
    test_fail "Invalid command should fail"
else
    test_pass "Invalid command properly rejected"
fi

# Test: Missing workload argument
if "$WORKLOAD_CTL" info > /dev/null 2>&1; then
    test_fail "Missing argument should fail"
else
    test_pass "Missing argument properly rejected"
fi

# Test: Non-existent workload
if "$WORKLOAD_CTL" info non-existent-workload-xyz > /dev/null 2>&1; then
    test_fail "Non-existent workload should fail"
else
    test_pass "Non-existent workload properly rejected"
fi

echo ""
echo "========================================"
echo "Test Summary"
echo "========================================"
echo -e "${GREEN}Passed:${NC} $PASS_COUNT"
echo -e "${RED}Failed:${NC} $FAIL_COUNT"
echo -e "${YELLOW}Skipped:${NC} $SKIP_COUNT"
echo ""

if [[ $FAIL_COUNT -eq 0 ]]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    exit 1
fi
