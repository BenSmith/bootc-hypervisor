"""
test_runtime_secret_tmpfs.py — C1 GAP check: the decrypted secret at rest lives
only in a RAM-backed, workload-owned, 0400 credential store on a real kernel.

`LoadCredentialEncrypted` decrypts each `${SECRET:...}` blob into
`/run/credentials/workload-<name>.service/<cred>` at unit start
(generators/workload-generate). The security claim is about the *at-rest* form of
that plaintext: it must sit on a memory-backed filesystem (never swapped to disk),
be readable only by the workload user, and mode 0400. None of that is observable
from unit text — it needs the running unit's credential mount on a real kernel.

test_runtime_secret.py already proves the *round-trip* (plaintext reaches the
container env) and the *no-argv-leak* invariant; this test is the complementary
*at-rest* half: mount type, mode, and owner of the credential itself.

The workload runs `User=_wl-<name>` in a sandbox (ProtectSystem/PrivateTmp), so the
credential mount may live in the unit's private mount namespace. We inspect it
through the main process's own view — `/proc/<mainpid>/mountinfo` for the mount
type and `/proc/<mainpid>/root/...` for the file — which resolves correctly whether
the mount is host-global or namespaced.

Guardrail: never echo the plaintext on success — the content corroboration
compares without printing the value.

Marked `runtime`: only runs under `--target=vm:<mode>` (i.e. `just test-runtime`).
"""

import pytest

pytestmark = pytest.mark.runtime

# Must match the clitest_secret fixture + clitest-secret.toml.
SECRET_VALUE = "clitest-secret-value-12345"
CRED_NAME = "clitest_token"          # LoadCredentialEncrypted id
SERVICE = "workload-clitest-secret.service"
USER = "_wl-clitest-secret"
# systemd credential store for the unit; the decrypted cred is <dir>/<CRED_NAME>.
CRED_DIR = f"/run/credentials/{SERVICE}"


def _dump_journal(target, name):
    r = target.run(
        ["journalctl", "--no-pager", "-n", "80", "-u", f"workload-{name}.service"],
        sudo=True, check=False,
    )
    print(f"\n----- journalctl -u workload-{name}.service (tail) -----\n"
          f"{r.stdout}\n{r.stderr}\n--------------------------------------------------------")


def _mount_fstype(mountinfo_text, mountpoint):
    """Return (fstype, options) of `mountpoint` from a /proc/<pid>/mountinfo dump.

    mountinfo splits into pre-separator fields then ` - ` then `fstype source
    superopts`. Per-mount options are field [5]; fstype is the token right after
    the ` - ` separator.
    """
    for line in mountinfo_text.splitlines():
        parts = line.split(" ")
        if len(parts) < 6 or parts[4] != mountpoint:
            continue
        opts = parts[5]
        if " - " in line:
            fstype = line.split(" - ", 1)[1].split(" ")[0]
        else:
            fstype = ""
        return fstype, opts
    return None, None


def test_secret_credential_ram_backed_and_locked_down(target, clitest_secret):
    """The decrypted credential is on a RAM-backed fs, mode 0400, owned by the
    workload user."""
    name = clitest_secret

    main_pid = target.run(
        ["systemctl", "show", SERVICE, "-p", "MainPID", "--value"],
        sudo=True, check=True,
    ).stdout.strip()
    if not (main_pid.isdigit() and int(main_pid) > 0):
        _dump_journal(target, name)
        pytest.fail(f"no MainPID for {SERVICE} (got {main_pid!r})")

    # --- mount type: the credential store is memory-backed (RAM-only) ---
    # Read from the main process's own mount view so this holds whether the
    # credential mount is host-global or in the unit's private namespace.
    mountinfo = target.run(["cat", f"/proc/{main_pid}/mountinfo"],
                           sudo=True, check=True).stdout
    fstype, opts = _mount_fstype(mountinfo, CRED_DIR)
    print(f"\n----- credential mount {CRED_DIR} (MainPID {main_pid} view) -----\n"
          f"fstype={fstype} opts={opts}\n"
          f"---------------------------------------------------------------")
    assert fstype is not None, (
        f"{CRED_DIR} is not a mount in MainPID {main_pid}'s namespace — the "
        f"credential is not on its own memory-backed store:\n{mountinfo}"
    )
    # systemd uses ramfs (never swappable) for credentials; accept tmpfs too so
    # the check is not brittle across systemd versions — both are memory-backed.
    assert fstype in ("ramfs", "tmpfs"), (
        f"credential store {CRED_DIR} is {fstype!r}, not a RAM-backed filesystem"
    )
    assert "ro" in (opts or "").split(","), (
        f"credential store {CRED_DIR} is not read-only (opts {opts!r})"
    )

    # --- file mode + owner, read through the main process's root view ---
    cred_path = f"/proc/{main_pid}/root{CRED_DIR}/{CRED_NAME}"
    st = target.run(["stat", "-c", "%a %U", cred_path], sudo=True, check=False)
    if st.rc != 0:
        _dump_journal(target, name)
    assert st.rc == 0, f"decrypted credential {CRED_DIR}/{CRED_NAME} missing: {st.stderr!r}"
    mode, owner = st.stdout.split()
    print(f"----- credential {CRED_NAME}: mode={mode} owner={owner} -----")
    assert mode == "400", f"credential {CRED_NAME} mode is {mode}, expected 400"
    assert owner == USER, f"credential {CRED_NAME} owned by {owner}, expected {USER}"

    # --- corroborate it IS the decrypted secret, without echoing the value ---
    got = target.run(["cat", cred_path], sudo=True, check=True).stdout.rstrip("\n")
    assert got == SECRET_VALUE, (
        f"credential content does not match the created secret "
        f"(len got={len(got)}, expected={len(SECRET_VALUE)})"
    )
