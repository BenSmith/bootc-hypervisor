"""
test_runtime_secret.py — B5 runtime check: the secret round-trip, proven on a
real kernel.

The secret machinery only actually works on a live system: `systemd-creds`
decrypts the encrypted blob into a tmpfs-backed EnvironmentFile at unit start,
and the `${SECRET:name}` reference is resolved into the container's environment.
None of that is observable from unit-file text — it needs a running workload on
a real kernel. This test enables a container that references a secret and
asserts both halves of the contract:

  * **Round-trip**: the plaintext the operator fed to `secret create` shows up
    inside the container (`workloadctl exec <wl> -- printenv`).

  * **No plaintext on any command line**: the secret is delivered to podman via
    `--env-file` (a tmpfs path), never `--env KEY=VALUE`, so the value must not
    appear in any process's `/proc/<pid>/cmdline` where `ps`/argv snooping could
    read it. A regression that switched to inline `--env` would leak it here.

    (Note: we deliberately do NOT assert "plaintext absent under
    `/var/lib/workloads/<name>/`". That dir is the workload's rootless-podman
    graphroot — `$HOME` — and podman bakes a container's resolved env into its
    on-disk config store by design. That is inherent to podman, not a
    workloadctl leak; the meaningful, controllable invariant is the argv one
    above. The genuinely sensitive decrypted form lives only in tmpfs
    `/run/workload-env/`.)

The value is fed via the `clitest_secret` fixture with `--key-type host` (the
default resolution on a TPM-less dev VM); under gate mode (swtpm present) the
same path runs with `--key-type auto` → tpm2.

Guardrail: never print the secret value to the log on success — assertions
check membership without echoing the plaintext.

Marked `runtime`: only runs under `--target=vm:<mode>` (i.e. `just test-runtime`).
"""

import pytest

from fixtures import dump_journal

pytestmark = pytest.mark.runtime

# Must match the clitest_secret fixture + clitest-secret.toml.
SECRET_VALUE = "clitest-secret-value-12345"
ENV_VAR = "CLITEST_TOKEN"          # [container.environment] CLITEST_TOKEN = "${SECRET:clitest_token}"


def test_secret_reaches_container_env(target, clitest_secret):
    """The `${SECRET:...}` reference resolves to the operator's plaintext inside
    the running container's environment."""
    name = clitest_secret
    r = target.wl_exec(name, ["printenv", ENV_VAR], sudo=True, check=False)
    if r.rc != 0:
        dump_journal(target, name)
    assert r.rc == 0, f"`printenv {ENV_VAR}` failed in {name}: {r.stderr!r}"
    # Compare without echoing: assert equality, don't print the value on failure.
    got = r.stdout.strip()
    assert got == SECRET_VALUE, (
        f"{ENV_VAR} inside {name} did not match the created secret "
        f"(len got={len(got)}, expected={len(SECRET_VALUE)})"
    )


def test_secret_not_on_any_process_cmdline(target, clitest_secret):
    """The secret is passed via --env-file, not inline --env, so its plaintext
    must never appear in any process's argv (/proc/<pid>/cmdline)."""
    name = clitest_secret
    # /proc/*/cmdline is NUL-separated; -a treats it as text, -F fixed-string,
    # -l lists matching files. The pattern is fed on STDIN (`-f -`), never as a
    # grep argv — otherwise grep would match its own /proc/self/cmdline (and the
    # sh wrapper) and self-report a false leak. rc!=0 / empty stdout is the pass.
    r = target.run(
        ["sh", "-c", "grep -alF -f - /proc/[0-9]*/cmdline 2>/dev/null"],
        input=SECRET_VALUE, sudo=True, check=False,
    )
    matches = [ln for ln in r.stdout.splitlines() if ln.strip()]
    if matches:
        # Redacted diagnosis: for each offending pid, print comm + argv with the
        # secret masked, so we can see WHAT carries it without echoing the value.
        for cmdline_path in matches:
            pid = cmdline_path.split("/")[2]
            comm = target.run(["cat", f"/proc/{pid}/comm"], sudo=True, check=False).stdout.strip()
            raw = target.run(["sh", "-c", f"tr '\\0' ' ' < /proc/{pid}/cmdline"],
                             sudo=True, check=False).stdout
            print(f"----- pid {pid} ({comm}) -----\n{raw.replace(SECRET_VALUE, '<REDACTED>')}")
    assert not matches, (
        f"secret plaintext found on {len(matches)} process command line(s) for "
        f"{name} — it must be delivered via --env-file, never inline --env "
        f"(see redacted diagnosis above)"
    )
