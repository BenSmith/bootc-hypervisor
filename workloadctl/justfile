#!/usr/bin/env just --justfile

version := "0.1.0"

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
  python3 -m py_compile generators/workload-generate
  python3 -m py_compile bin/workloadctl
  python3 -m py_compile libexec/workload-ensure-user
  python3 -m py_compile libexec/workload-write-env
  python3 -m py_compile libexec/workload-metrics

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
  find rpmbuild/RPMS -name '*.rpm' -newer rpmbuild/SPECS -o -name '*.rpm' -newer rpm/workloadctl.spec | head -1

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
