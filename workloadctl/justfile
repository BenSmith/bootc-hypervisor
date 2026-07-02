#!/usr/bin/env just --justfile

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

# Run the unit suite under coverage.py (dev-only), print a per-file report
coverage:
  PYTHONPATH=lib python3 -m coverage run --source=lib,bin,generators,libexec -m unittest discover -s tests
  python3 -m coverage report --sort=cover

# As `coverage`, plus write the HTML report to htmlcov/
coverage-html: coverage
  python3 -m coverage html
  @echo "HTML report: file://$(pwd)/htmlcov/index.html"

# Lint: byte-compile every Python source (syntax check)
lint:
  python3 -m py_compile lib/*.py bin/workloadctl generators/workload-generate libexec/workload-*

# Lint with ruff (dev-only); scripts named explicitly since they lack .py.
# tests/ and libexec/ scripts insert lib/ onto sys.path before importing
# from it (no venv/package manager here), which ruff flags as E402
# (import not at top of file) — that pattern is intentional.
lint-ruff:
  ruff check --per-file-ignores "tests/*.py:E402,libexec/*:E402" lib/ tests/ bin/workloadctl generators/workload-generate libexec/workload-*

# Type-check with mypy (dev-only, advisory). lib/ + tests/ run together
# (--explicit-package-bases avoids a false "duplicate module" clash between
# tests/test_lifecycle.py and tests/cli_surface/test_lifecycle.py); the
# extension-less scripts have no unique module name of their own, so mypy
# treats each as "__main__" and they must be checked one at a time or they
# collide with each other.
typecheck:
  #!/usr/bin/env bash
  set -uo pipefail
  export MYPYPATH=lib
  status=0
  mypy lib/ tests/ --ignore-missing-imports --explicit-package-bases --check-untyped-defs || status=1
  for f in bin/workloadctl generators/workload-generate libexec/workload-*; do
    mypy "$f" --ignore-missing-imports --check-untyped-defs || status=1
  done
  exit "$status"

# Lint all bundle Containerfiles with hadolint.
# Intentionally suppressed:
#   DL3006/DL3007: image version/tag pinning — we track by image, not tag
#   DL3018/DL3041: apk/dnf package version pinning — intentional; we want
#                  the latest stable package from the distro repo
#   DL3059: consecutive RUN — intentional for readability and layer isolation
# Excluded: vncdesktop-labwc — XML inside a heredoc makes hadolint choke on
# the leading '<' of XML tags, treating them as Dockerfile instructions.
lint-containerfiles:
  find workloads -name Containerfile \
    ! -path 'workloads/vncdesktop-labwc/*' \
    | sort \
    | xargs hadolint \
        --ignore DL3006 \
        --ignore DL3007 \
        --ignore DL3018 \
        --ignore DL3041 \
        --ignore DL3059

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
