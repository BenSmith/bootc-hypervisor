#!/usr/bin/env just --justfile

version := "1.0.0"

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
  mkdir -p rpmbuild/{BUILD,RPMS,SRPMS,SPECS}
  # Use this directory as the SOURCES so the spec can reference files directly
  rpmbuild -bb \
    --define "_topdir $(pwd)/rpmbuild" \
    --define "_sourcedir $(pwd)" \
    --define "_builddir $(pwd)/rpmbuild/BUILD" \
    rpm/workloadctl.spec
  echo "RPM built:"
  find rpmbuild/RPMS -name '*.rpm'
