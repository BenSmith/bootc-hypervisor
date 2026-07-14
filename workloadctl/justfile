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

# Runtime rung — boot a harness-owned VM and run the `runtime`-marked checks.
# WLRT_MODE=dev (default): cached Fedora Cloud image + local RPM. WLRT_MODE=gate:
# the real bootc image + swtpm (B1b). Skips cleanly without /dev/kvm + QEMU.
test-runtime:
  pytest tests/cli_surface/ -m runtime --target=vm:${WLRT_MODE:-dev} -v

# Full KVM-host verification sweep: CLI surface (container+VM) + runtime rung in
# both dev and gate fidelity. Run this ON a KVM host — the runtime rung boots
# QEMU locally, so it can't be driven over SSH. {{target}} is the CLI-surface
# substrate (default `local` = this host); pair with `just test` for rungs 1-2.
# Each step skips cleanly if its prerequisite (KVM/OVMF/swtpm) is absent.
test-all-runtime target="local":
  just test-cli-deploy {{target}}
  just test-runtime
  WLRT_MODE=gate just test-runtime

# Where this tree gets rsynced on the remote KVM host, relative to its $HOME.
# Whatever layout you keep checkouts in is yours, not the project's: set
# WLRT_REMOTE_PATH to it.
wlrt_remote_path := env_var_or_default('WLRT_REMOTE_PATH', 'workloadctl')

# Drive the full sweep on a REMOTE prepared host from your laptop: rsync this
# tree over, then run `test-all-runtime` there and stream the output back. The
# host must already be set up for the runtime rung — a checkout at
# {{wlrt_remote_path}} and the wlrt image cache (~/wlrt-cache, preserved via the
# tests/runtime/.cache exclude below).
test-all-runtime-remote host target="local":
  rsync -a --delete \
    --exclude='.git/' --exclude='__pycache__/' --exclude='*.pyc' \
    --exclude='rpmbuild/' --exclude='.pytest_cache/' \
    --exclude='tests/runtime/.cache' \
    ./ {{host}}:{{wlrt_remote_path}}/
  ssh {{host}} 'cd {{wlrt_remote_path}} && just test-all-runtime {{target}}'

# Run all unit tests.
# -t . makes the repo root the top-level dir, so modules import as `tests.<name>`
# and tests/__init__.py runs first -- that is what puts lib/ on sys.path.
test:
  python3 -m unittest discover -t . -s tests -p 'test_*.py' -v

# Run unit tests only (no integration)
test-unit:
  python3 -m unittest tests.test_workload_lib tests.test_generator tests.test_write_env tests.test_metrics -v

# Run integration tests
test-integration:
  python3 -m unittest tests.test_integration -v

# Regenerate snapshot test fixtures after intentional generator changes.
# Re-runs the generator over every TOML in workloads.d/ and writes the
# normalized output to tests/snapshots/. Review with `git diff tests/snapshots/`.
test-snapshot-update:
  UPDATE_SNAPSHOTS=1 python3 -m unittest tests.test_snapshots -v

# Run the unit suite under coverage.py (dev-only), print a per-file report.
# COVERAGE_PROCESS_START makes tests that shell out to our scripts route the
# subprocess through `coverage run` too (see tests/covhelper.py); combine then
# merges those per-process data files into the parent's.
coverage:
  rm -f .coverage .coverage.*
  COVERAGE_PROCESS_START={{justfile_directory()}}/.coveragerc \
    python3 -m coverage run --rcfile=.coveragerc -m unittest discover -t . -s tests
  python3 -m coverage combine --rcfile=.coveragerc
  python3 -m coverage report --rcfile=.coveragerc --sort=cover

# As `coverage`, plus write the HTML report to htmlcov/
coverage-html: coverage
  python3 -m coverage html --rcfile=.coveragerc
  @echo "HTML report: file://$(pwd)/htmlcov/index.html"

# Lint: byte-compile every Python source (syntax check)
lint:
  python3 -m py_compile lib/*.py bin/workloadctl generators/workload-generate libexec/workload-*

# Lint with ruff (dev-only); scripts named explicitly since they lack .py.
# tests/ and libexec/ scripts insert lib/ onto sys.path before importing
# from it (no venv/package manager here), which ruff flags as E402
# (import not at top of file) — that pattern is intentional.
lint-ruff *args:
  ruff check {{args}} --per-file-ignores "tests/*.py:E402,libexec/*:E402" lib/ tests/ bin/workloadctl generators/workload-generate libexec/workload-*

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
