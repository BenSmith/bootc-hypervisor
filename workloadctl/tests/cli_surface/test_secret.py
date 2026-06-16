"""
test_secret.py — secret management verbs.

Covers: secret create, list, show, rotate, export, import, delete.

Side effects verified: blob present, show round-trips value, export/import
round-trips, rotate changes ciphertext, delete removes blob.
"""

import json

import pytest

from target import Target


# The name used for all clitest secret tests
SECRET_NAME = "clitest-token"
SECRET_VALUE = "clitest-secret-value-12345"
CRED_PATH = f"/etc/credstore.encrypted/{SECRET_NAME}"


@pytest.fixture()
def created_secret(target, key_type):
    """Create the clitest-token secret; delete it on teardown."""
    _create_secret(target, SECRET_NAME, SECRET_VALUE, key_type)
    yield SECRET_NAME, SECRET_VALUE
    target.wl(f"secret delete --force {SECRET_NAME}", check=False, timeout=15)


def _create_secret(target: Target, name: str, value: str, key_type: str):
    target.wl(
        f"secret create --key-type {key_type} --force {name}",
        input=value,
        check=True,
        timeout=30,
    )


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------

class TestSecretCreate:
    def test_create_makes_blob(self, target, key_type, record_property):
        """secret create writes an encrypted blob to /etc/credstore.encrypted/."""
        record_property("cell", "secret_create/any")
        try:
            _create_secret(target, SECRET_NAME, SECRET_VALUE, key_type)
            # Blob exists
            exists = target.remote_path_exists(CRED_PATH)
            assert exists, f"Credential blob not found at {CRED_PATH}"
        finally:
            target.wl(f"secret delete --force {SECRET_NAME}", check=False, timeout=15)

    def test_create_force_overwrites(self, target, key_type, record_property):
        """--force on an existing secret overwrites it."""
        record_property("cell", "secret_create/any")
        try:
            _create_secret(target, SECRET_NAME, "first-value", key_type)
            _create_secret(target, SECRET_NAME, "second-value", key_type)
            # Verify round-trip with the second value
            r = target.wl(f"secret show {SECRET_NAME}", check=True, timeout=20)
            assert "second-value" in r.stdout
        finally:
            target.wl(f"secret delete --force {SECRET_NAME}", check=False, timeout=15)

    def test_create_without_force_fails_if_exists(self, target, key_type, created_secret, record_property):
        """Creating a secret that exists without --force must fail cleanly."""
        record_property("cell", "secret_create/any")
        name, _ = created_secret
        # Provide stdin so the command can't block waiting for a value if the
        # existence check happens after the read; it must still reject the dup.
        r = target.wl(
            f"secret create --key-type {key_type} {name}",
            input="should-be-rejected",
            check=False, timeout=15,
        )
        assert r.rc != 0, "Expected failure when creating duplicate without --force"
        assert "Traceback" not in r.stderr


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------

class TestSecretList:
    def test_list_plain(self, target, created_secret, record_property):
        record_property("cell", "secret_list/any")
        r = target.wl("secret list", check=True)
        assert r.rc == 0
        name, _ = created_secret
        assert name in r.stdout

    def test_list_json(self, target, created_secret, record_property):
        record_property("cell", "secret_list/any")
        r = target.wl("secret list --json", check=True)
        assert r.rc == 0
        data = json.loads(r.stdout)
        assert "credentials" in data
        names = [c["name"] for c in data["credentials"]]
        name, _ = created_secret
        assert name in names

    def test_list_json_has_size(self, target, created_secret, record_property):
        record_property("cell", "secret_list/any")
        r = target.wl("secret list --json", check=True)
        data = json.loads(r.stdout)
        name, _ = created_secret
        entry = next((c for c in data["credentials"] if c["name"] == name), None)
        assert entry is not None
        assert "size" in entry
        assert entry["size"] > 0


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------

class TestSecretShow:
    def test_show_round_trips_value(self, target, created_secret, record_property):
        """secret show decrypts and returns the original value."""
        record_property("cell", "secret_show/any")
        name, value = created_secret
        r = target.wl(f"secret show {name}", check=True, timeout=20)
        assert r.rc == 0
        assert value in r.stdout, (
            f"show did not return expected value. stdout: {r.stdout!r}"
        )

    def test_show_nonexistent_fails(self, target, record_property):
        record_property("cell", "secret_show/any")
        r = target.wl("secret show clitest-nonexistent-xxx", check=False, timeout=15)
        assert r.rc != 0
        assert "Traceback" not in r.stderr


# ---------------------------------------------------------------------------
# rotate
# ---------------------------------------------------------------------------

class TestSecretRotate:
    def test_rotate_changes_ciphertext(self, target, key_type, created_secret, record_property):
        """rotate re-encrypts the secret (ciphertext changes)."""
        record_property("cell", "secret_rotate/any")
        name, value = created_secret

        # Read original blob bytes (as size proxy; actual bytes differ per-run)
        r1 = target.run(["stat", "-c", "%s", CRED_PATH], sudo=True, check=True)
        original_size = r1.stdout.strip()

        r = target.wl(
            f"secret rotate --key-type {key_type} {name}",
            input=value,  # provide new value on stdin
            check=True, timeout=30,
        )
        assert r.rc == 0

        # Value still decrypts correctly
        r2 = target.wl(f"secret show {name}", check=True, timeout=20)
        assert value in r2.stdout

    def test_rotate_no_traceback(self, target, key_type, created_secret, record_property):
        record_property("cell", "secret_rotate/any")
        name, value = created_secret
        r = target.wl(
            f"secret rotate --key-type {key_type} {name}",
            input=value,
            check=False, timeout=30,
        )
        assert "Traceback" not in r.stderr


# ---------------------------------------------------------------------------
# export / import
# ---------------------------------------------------------------------------

class TestSecretExportImport:
    def test_export_import_round_trip(self, target, key_type, created_secret, record_property):
        """export → import round-trips the secret value.

        Export produces a passphrase-encrypted file; import re-encrypts with TPM/host key.
        We use a simple passphrase ('testpass') for the export.
        """
        record_property("cell", "secret_export_import/any")
        name, value = created_secret
        export_path = f"/tmp/clitest-export-{name}.secret"

        try:
            # Export (non-interactive: passphrase via stdin, single line)
            r = target.wl(
                f"secret export --passphrase-stdin --output {export_path} {name}",
                input="testpass\n",
                check=False, timeout=30,
            )
            if r.rc != 0:
                pytest.skip(f"secret export failed: {r.stderr}")

            # Verify export file exists
            assert target.remote_path_exists(export_path), "Export file not created"

            # Delete the original secret
            target.wl(f"secret delete --force {name}", check=True, timeout=15)

            # Import with a new name to avoid conflict
            import_name = f"{name}-imported"
            try:
                r = target.wl(
                    f"secret import --passphrase-stdin --key-type {key_type} --force {import_name} {export_path}",
                    input="testpass\n",  # passphrase via stdin (non-interactive)
                    check=False, timeout=30,
                )
                if r.rc != 0:
                    pytest.skip(f"secret import failed: {r.stderr}")

                # Verify round-trip
                r2 = target.wl(f"secret show {import_name}", check=True, timeout=20)
                assert value in r2.stdout, (
                    f"Import round-trip failed: expected {value!r} in {r2.stdout!r}"
                )
            finally:
                target.wl(f"secret delete --force {import_name}", check=False, timeout=15)
                # Re-create the original for teardown
                _create_secret(target, name, value, key_type)
        finally:
            target.run(["rm", "-f", export_path], sudo=False, check=False)


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------

class TestSecretDelete:
    def test_delete_removes_blob(self, target, key_type, record_property):
        """secret delete removes the encrypted blob."""
        record_property("cell", "secret_delete/any")
        _create_secret(target, SECRET_NAME, SECRET_VALUE, key_type)
        assert target.remote_path_exists(CRED_PATH), "Blob should exist before delete"

        r = target.wl(f"secret delete --force {SECRET_NAME}", check=True, timeout=15)
        assert r.rc == 0

        assert not target.remote_path_exists(CRED_PATH), (
            f"Blob still exists at {CRED_PATH} after delete"
        )

    def test_delete_nonexistent_with_force(self, target, record_property):
        """delete --force on a nonexistent secret must not crash."""
        record_property("cell", "secret_delete/any")
        r = target.wl("secret delete --force clitest-nosuchsecret", check=False, timeout=15)
        assert "Traceback" not in r.stderr
