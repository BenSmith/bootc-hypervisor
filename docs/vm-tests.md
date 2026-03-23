# VM Integration Tests

VM integration tests verify that the workload provisioning system works end-to-end:
generator, user creation, service files, container startup, and workload-specific behavior.

Tests run inside a disposable QEMU VM built from the hypervisor bootc image with test
workload configs layered on top.

## Running tests

```bash
# Build the test VM image (builds base image if needed)
just test-vm-build

# Run tests (boots VM, runs tests via SSH, tears down)
just test-vm

# Boot a debug VM (interactive, not auto-destroyed)
just test-vm-debug
```

## Project structure

```
tests/vm/
  run-vm-tests.sh              # Main test orchestrator (runs inside the VM)
  test-vm.Containerfile         # Builds test VM image from hypervisor-bootc
  test-workloads.d/
    <name>.toml                 # Workload config (copied to /etc/workloads.d/)
    <name>.test.sh              # Test functions for that workload (optional)
    disabled.toml               # Negative test: disabled workload
```

## Adding a new test

### 1. Create the workload config

Add `tests/vm/test-workloads.d/<name>.toml`. This is a standard workload config
that will be copied to `/etc/workloads.d/` in the test VM.

```toml
[workload]
name = "my-app"
enabled = true

[container]
image = "192.168.0.64:5000/my-app:latest"
pull = "missing"

[network]
mode = "pasta"
ports = ["8080:8080"]
```

Use the local registry (`192.168.0.64:5000`) for images — don't pull from Docker Hub
during tests. If the image needs a local build, build and push it before running tests:

```bash
cd containers/my-app
sudo ./build.sh
sudo podman tag localhost/my-app:latest 192.168.0.64:5000/my-app:latest
sudo podman push 192.168.0.64:5000/my-app:latest
```

### 2. Create the test file

Add `tests/vm/test-workloads.d/<name>.test.sh`. This file is sourced by the main
test script and should define one or both of:

- **`pre_start_<name>()`** — runs after user/home creation but before the service starts.
  Use this to write config files, stop conflicting services, etc.
- **`test_<name>()`** — runs after all services are started. Contains your test assertions.

```bash
# Tests for my-app workload

pre_start_my-app() {
    # Write config files needed by the container
    local home
    home=$(getent passwd _wl-my-app 2>/dev/null | cut -d: -f6) || return
    [ -d "$home" ] || return

    # Remove ghost directories (podman creates dirs for missing volume sources)
    [ -d "$home/config.yaml" ] && rm -rf "$home/config.yaml"

    if [ ! -f "$home/config.yaml" ]; then
        cat > "$home/config.yaml" <<'EOF'
port: 8080
EOF
        chown _wl-my-app: "$home/config.yaml"
    fi
}

test_my-app() {
    if ! systemctl is-active --quiet workload-my-app.service; then
        fail "my-app: service not active, skipping tests"
        return
    fi

    # HTTP check with retry loop
    local http_ok=false response
    for i in 1 2 3 4 5 6; do
        response=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/ 2>/dev/null || echo "000")
        if [ "$response" = "200" ]; then
            http_ok=true
            break
        fi
        sleep 3
    done
    if [ "$http_ok" = true ]; then
        pass "my-app: HTTP returns 200"
    else
        fail "my-app: HTTP returned $response (expected 200)"
    fi
}
```

### 3. Build and run

```bash
just test-vm-build    # Rebuilds the VM image with your new test files
just test-vm          # Runs the tests
```

## Available helpers

The main test script provides these functions for use in test files:

| Function | Description |
|---|---|
| `pass "message"` | Record a passing test |
| `fail "message"` | Record a failing test |
| `wl_exec <name> <cmd...>` | Run a command inside the workload's container (`podman exec`) |

## Common patterns

### Ghost directory removal

When a volume mount points to a file that doesn't exist yet, podman creates it as a
directory. Pre-start hooks should check for and remove these before writing config files:

```bash
[ -d "$home/my.conf" ] && rm -rf "$home/my.conf"
```

### Service file inspection

Check that the generator produced correct flags in the systemd service file:

```bash
local svc
svc=$(cat /run/systemd/system/workload-my-app.service 2>/dev/null || echo "")
if echo "$svc" | grep -q -- '--network=.*host'; then
    pass "my-app: service uses --network=host"
fi
```

Note: the generator's `_dq()` quoting function wraps values in double quotes,
so `--network=host` appears as `--network="host"` in service files. Use `.*` in
grep patterns to match both.

### HTTP checks with retries

Containers may take a few seconds to start. Always retry:

```bash
local ok=false response
for i in 1 2 3 4 5 6; do
    response=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:PORT/ 2>/dev/null || echo "000")
    if [ "$response" = "200" ]; then
        ok=true
        break
    fi
    sleep 3
done
```

### Stopping conflicting host services

Some workloads need a host service stopped first (e.g., pihole needs systemd-resolved
stopped to bind port 53). Do this in the pre-start hook:

```bash
pre_start_my-dns() {
    systemctl stop some-conflicting.service 2>/dev/null || true
}
```

### Large command output

Don't capture large outputs (like Prometheus metrics) in shell variables. Write to
a temp file and grep from it instead:

```bash
local tmpfile
tmpfile=$(mktemp)
curl -s http://localhost:9100/metrics > "$tmpfile" 2>/dev/null || true
if grep -q 'node_cpu_seconds_total' "$tmpfile"; then
    pass "metrics contain node_cpu"
fi
rm -f "$tmpfile"
```

## What the main script tests automatically

For every enabled workload (without needing a `.test.sh` file), `run-vm-tests.sh`
automatically verifies:

- Generator produced a service file in `/run/systemd/system/`
- Sysusers config was generated
- Setup service ran successfully
- Container image was pulled
- Workload user exists with a UID in the valid range (10000-52948)
- Service is active after start
- No secrets leaked in `/proc/*/cmdline`
- EnvironmentFile written by workload-ensure-user
- Disabled workloads are not running

The `.test.sh` files add workload-specific checks on top of these.
