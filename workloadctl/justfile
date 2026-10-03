#!/usr/bin/env just --justfile

# No .pyc, ever, for this project's own runs. Test recipes pass `python3 -B`;
# this export exists for the SUBPROCESSES, which -B does not reach --
# sys.dont_write_bytecode is per-interpreter and is not inherited, while
# tests/__init__.py's script_env() builds a child environment with
# os.environ.copy(), so an exported var propagates to every entrypoint the
# suite launches. Those children are the ones that import lib/, which is the
# cache that actually caused trouble.
#
# WHY AT ALL: CPython compares source and bytecode mtimes at ONE-SECOND
# granularity, so a file rewritten twice inside the same second keeps executing
# the first version's bytecode. That is not a corner case here -- it is the
# exact shape of mutation-testing a gate (perturb, run, restore, run), which
# this project does deliberately and often. The half that lies is the RESTORE:
# a perturbation has new content and gets fresh bytecode, while the revert can
# silently not take, so the reassuring reading is the unreliable one and the
# breakage surfaces later as a fresh failure in a test that just passed.
# Cost: nothing measurable. lib/ is stdlib-only and import time is noise beside
# the subprocess work the suite actually does.
export PYTHONDONTWRITEBYTECODE := "1"

# Run CLI-surface acceptance harness (all verbs, both substrates)
test-cli target:
  python3 -B -m pytest tests/cli_surface/ --target={{target}} -v

# CLI surface — container substrate only (no VM boot; much faster)
test-cli-containers target:
  python3 -B -m pytest tests/cli_surface/ --target={{target}} -m "not vm and not slow" -v

# CLI surface — VM substrate only (requires /dev/kvm on target)
test-cli-vm target:
  python3 -B -m pytest tests/cli_surface/ --target={{target}} -m vm -v

# CLI surface — deploy current tree to target first, then run all tests
test-cli-deploy target:
  python3 -B -m pytest tests/cli_surface/ --target={{target}} --deploy -v

# Runtime rung — boot a harness-owned VM and run the `runtime`-marked checks.
# WLRT_MODE=dev (default): cached Fedora Cloud image + local RPM. WLRT_MODE=gate:
# the real bootc image + swtpm (B1b). Skips cleanly without /dev/kvm + QEMU.
test-runtime:
  python3 -B -m pytest tests/cli_surface/ -m runtime --target=vm:${WLRT_MODE:-dev} -v

# Kill any harness VM left behind by a cancelled run and drop its scratch dir.
# A killed run never reaches its own cleanup, so its QEMU keeps running and keeps
# holding disk; CI sweeps before each runtime rung. Safe when nothing is stale.
reap-stale-runs:
  python3 tests/runtime/vmlaunch.py reap

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
# -v only when stdout is a terminal: piped (CI, redirects) this suite prints
# ~5,000 lines for 4,947 tests and the failure line drowns in them. The check
# lives in the recipe body because fd 1 must be the real terminal -- a backtick
# variable would capture stdout into a pipe and always read as non-TTY.
test:
  #!/usr/bin/env bash
  set -euo pipefail
  args=()
  [ -t 1 ] && args+=(-v)
  python3 -B -m unittest discover -t . -s tests -p 'test_*.py' "${args[@]}"

# Run unit tests only (no integration)
test-unit:
  #!/usr/bin/env bash
  set -euo pipefail
  args=()
  [ -t 1 ] && args+=(-v)
  python3 -B -m unittest tests.test_workload_lib tests.test_generator tests.test_write_env tests.test_metrics tests.test_stdlib_only "${args[@]}"

# Run integration tests
test-integration:
  #!/usr/bin/env bash
  set -euo pipefail
  args=()
  [ -t 1 ] && args+=(-v)
  python3 -B -m unittest tests.test_integration "${args[@]}"

# Render every shipped bundle's units into DIR, for diffing across a refactor.
# Nothing is committed: take a baseline before the change, another after, and
# `diff -ru` them. Every behavioral difference across all bundles shows up in one
# place, which is what a large generator refactor needs.
#
#   just snapshot-baseline /tmp/before     # on the pre-refactor commit
#   ...refactor...
#   just snapshot-baseline /tmp/after
#   diff -ru /tmp/before /tmp/after
snapshot-baseline dir:
  #!/usr/bin/env python3
  import sys, pathlib
  sys.path[:0] = [".", "lib"]
  from tests.test_shipped_bundles import generate_all, normalize_baseline
  dest = pathlib.Path("{{dir}}").resolve()
  units = dest / "units"
  units.mkdir(parents=True, exist_ok=True)
  tomls, sys_d, cfg = generate_all(units)
  masked = normalize_baseline(units, sys_d, cfg)
  print(f"{len(tomls)} bundles -> {units} (sysusers: {sys_d}); "
        f"normalized {masked} files")

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

# Lint: byte-compile every Python source (syntax check).
lint:
  python3 -m py_compile lib/*.py bin/workloadctl generators/workload-generate libexec/workload-*

# Lint with ruff (dev-only); scripts named explicitly since they lack .py.
# The rule set is pinned to ruff's classic default (pycodestyle errors and
# pyflakes), so a ruff release that widens its defaults does not turn this
# into a style report. libexec/ scripts and some tests set
# sys.dont_write_bytecode before their imports, which ruff flags as E402
# (import not at top of file) — that pattern is intentional.
lint-ruff *args:
  ruff check --select E4,E7,E9,F {{args}} --per-file-ignores "tests/*.py:E402,libexec/*:E402" lib/ tests/ bin/workloadctl generators/workload-generate libexec/workload-*

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
# hadolint's heredoc parser is picky in two ways that are invisible in shell:
# the delimiter must follow '<<' with no space ("<<'EOF'", not "<< 'EOF'"), and
# a terminator line must be followed by a blank line before the next
# instruction. Violating either makes it parse heredoc *content* as Dockerfile
# instructions, which is why the errors point at innocent lines.
lint-containerfiles:
  find workloads -name Containerfile \
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

# The image hypervisor.Containerfile pins for moatery's RPM, its signature
# verified against the repo's cosign.pub, printed as repo@digest. Every
# consumer takes this ref rather than the tag, so what it installs is what
# was signed, not whatever the tag names by the time it pulls. Signatures
# are registry attachments, so the host needs use-sigstore-attachments for
# the registry (registries.d/registry-local.yaml; the hypervisor image and
# the runners carry it).
moatery-rpm-ref:
  #!/usr/bin/env bash
  set -euo pipefail
  image=$(sed -n 's/^ARG MOATERY_RPM=//p' ../hypervisor.Containerfile)
  [ -n "$image" ] || { echo "no ARG MOATERY_RPM in hypervisor.Containerfile" >&2; exit 1; }
  repo="${image%:*}"
  policy=$(mktemp)
  trap 'rm -f "$policy"' EXIT
  printf '{"default":[{"type":"reject"}],"transports":{"docker":{"%s":[{"type":"sigstoreSigned","keyPath":"%s","signedIdentity":{"type":"matchRepository"}}]}}}' \
    "$repo" "$(realpath ../cosign.pub)" > "$policy"
  podman pull -q --signature-policy="$policy" "$image" >/dev/null
  digest=$(podman image inspect "$image" \
    | python3 -c 'import json, sys; print(json.load(sys.stdin)[0]["Digest"])')
  echo "verified: $image ($digest)" >&2
  echo "$repo@$digest"

# moatery's RPM, which workloadctl's requires, out of the verified image
# (FROM scratch, /moatery.rpm), to DEST.
moatery-rpm dest="moatery.rpm":
  #!/usr/bin/env bash
  set -euo pipefail
  ref=$({{just_executable()}} -f {{justfile()}} moatery-rpm-ref)
  ctr=$(podman create "$ref" none)
  trap 'podman rm -f "$ctr" >/dev/null' EXIT
  podman cp "$ctr:/moatery.rpm" "{{dest}}"
  rpm -qp "{{dest}}"

# Remove old build artifacts
rpm-clean:
  rm -rf rpmbuild
