#!/usr/bin/env just --justfile

version := "0.1.0"

# Run CLI-surface acceptance harness (all verbs, both substrates)
test-cli target:
  pytest tests/cli_surface/ --target={{target}} -v

# CLI surface — container substrate only (no VM boot; much faster)
test-cli-containers target:
  pytest tests/cli_surface/ --target={{target}} -m "not vm and not slow" -v

# CLI surface — VM substrate only (requires /dev/kvm on target)
test-cli-vm target:
  pytest tests/cli_surface/ --target={{target}} -m vm -v

# CLI surface — deploy current tree to target first, then run all tests
test-cli-deploy target:
  pytest tests/cli_surface/ --target={{target}} --deploy -v

# Run all unit tests
test:
  PYTHONPATH=lib python3 -m unittest discover -s tests -p 'test_*.py' -v

# Run unit tests only (no integration)
test-unit:
  PYTHONPATH=lib python3 -m unittest tests.test_workload_lib tests.test_generator tests.test_write_env tests.test_metrics -v

# Run integration tests
test-integration:
  PYTHONPATH=lib python3 -m unittest tests.test_integration -v

# Lint: check Python syntax
lint:
  python3 -m py_compile lib/workload_lib.py
  python3 -m py_compile lib/podman.py
  python3 -m py_compile generators/workload-generate
  python3 -m py_compile bin/workloadctl
  python3 -m py_compile libexec/workload-ensure-user
  python3 -m py_compile libexec/workload-write-env
  python3 -m py_compile libexec/workload-exporter

# Build RPM from local checkout (no tarball)
rpm-build:
  #!/usr/bin/env bash
  set -euo pipefail
  serial="$(date +%Y%m%d%H%M%S)"
  mkdir -p rpmbuild/{BUILD,RPMS,SRPMS,SPECS}
  rpmbuild -bb \
    --define "_topdir $(pwd)/rpmbuild" \
    --define "_sourcedir $(pwd)" \
    --define "_builddir $(pwd)/rpmbuild/BUILD" \
    --define "buildserial ${serial}" \
    rpm/workloadctl.spec
  echo "RPM built:"
  find rpmbuild/RPMS -name "workloadctl-*${serial}*.rpm"

# Build and install RPM (upgrade if already installed)
rpm-install: rpm-build
  #!/usr/bin/env bash
  set -euo pipefail
  rpm=$(find rpmbuild/RPMS -name 'workloadctl-*.rpm' -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2)
  echo "Installing ${rpm}"
  sudo dnf install -y --allowerasing "$rpm"

# Remove old build artifacts
rpm-clean:
  rm -rf rpmbuild

# --- Manual test VM (throwaway Fedora VM for multi-container validation) ---

# Boot the test VM (downloads the Fedora cloud image on first run)
vm-up:
  tests/vm/vm.sh up

# Build the RPM and install it + test workloads into the running VM
vm-deploy:
  tests/vm/vm.sh deploy

# SSH into the test VM (optionally run a command: just vm-ssh 'workloadctl list')
vm-ssh *cmd:
  tests/vm/vm.sh ssh {{cmd}}

# Power off the test VM and drop the per-boot overlay
vm-down:
  tests/vm/vm.sh down

# Show whether the test VM is running
vm-status:
  tests/vm/vm.sh status
