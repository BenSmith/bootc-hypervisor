#!/usr/bin/env python3
"""Integration tests for the workload generator.

Runs the generator with temp directories and validates the output files.
No root required — all paths are overridden via env vars and argv.
"""

import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

GENERATOR = os.path.join(os.path.dirname(__file__), '..', 'generators', 'workload-generate')
LIB_DIR = os.path.join(os.path.dirname(__file__), '..', 'lib')


def run_generator(config_dir, services_dir, sysusers_dir):
    """Run the generator and return the CompletedProcess."""
    env = os.environ.copy()
    env["WORKLOAD_CONFIG_DIR"] = str(config_dir)
    env["SYSUSERS_DIR"] = str(sysusers_dir)
    env["PYTHONPATH"] = LIB_DIR
    return subprocess.run(
        [sys.executable, GENERATOR, str(services_dir)],
        capture_output=True, text=True, env=env,
    )


def write_config(config_dir, name, toml_content):
    """Write a TOML config file to the config directory."""
    path = Path(config_dir) / f"{name}.toml"
    path.write_text(textwrap.dedent(toml_content))
    return path


class TestGeneratorBasic(unittest.TestCase):
    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.services_dir, self.sysusers_dir):
            shutil.rmtree(d)

    def run_gen(self):
        return run_generator(self.config_dir, self.services_dir, self.sysusers_dir)

    def read_service(self, name):
        return (Path(self.services_dir) / f"workload-{name}.service").read_text()

    def read_sysusers(self, name):
        return (Path(self.sysusers_dir) / f"workload-{name}.conf").read_text()

    def test_basic_workload(self):
        write_config(self.config_dir, "web", """\
            [workload]
            name = "web"
            enabled = true

            [container]
            image = "docker.io/nginx:latest"

            [network]
            ports = ["8080:80"]
        """)

        result = self.run_gen()
        self.assertEqual(result.returncode, 0)

        service = self.read_service("web")
        self.assertIn("ExecStart=/usr/bin/podman run", service)
        self.assertIn('"docker.io/nginx:latest"', service)
        self.assertIn("--publish 8080:80", service)
        self.assertIn("User=_wl-web", service)
        self.assertIn("--network=", service)

        sysusers = self.read_sysusers("web")
        self.assertIn("u _wl-web", sysusers)

    def test_disabled_workload_skipped(self):
        write_config(self.config_dir, "off", """\
            [workload]
            name = "off"
            enabled = false

            [container]
            image = "nginx"
        """)

        self.run_gen()
        self.assertFalse(
            (Path(self.services_dir) / "workload-off.service").exists()
        )

    def test_missing_name_skipped(self):
        write_config(self.config_dir, "broken", """\
            [workload]
            enabled = true

            [container]
            image = "nginx"
        """)

        result = self.run_gen()
        self.assertEqual(result.returncode, 0)  # generator always exits 0
        self.assertFalse(
            (Path(self.services_dir) / "workload-broken.service").exists()
        )

    def test_symlink_for_autostart(self):
        write_config(self.config_dir, "svc", """\
            [workload]
            name = "svc"
            enabled = true

            [container]
            image = "alpine"
        """)

        self.run_gen()
        wants = Path(self.services_dir) / "multi-user.target.wants" / "workload-svc.service"
        self.assertTrue(wants.is_symlink())
        self.assertEqual(os.readlink(wants), "../workload-svc.service")


class TestGeneratorPlainEnvVars(unittest.TestCase):
    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.services_dir, self.sysusers_dir):
            shutil.rmtree(d)

    def test_plain_env_vars_as_args(self):
        write_config(self.config_dir, "app", """\
            [workload]
            name = "app"
            enabled = true

            [container]
            image = "myapp"

            [container.environment]
            FOO = "bar"
            PORT = "8080"
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-app.service").read_text()

        self.assertIn("--env FOO=", service)
        self.assertIn("--env PORT=", service)
        # No shell wrapper
        self.assertNotIn("/bin/sh -c", service)
        # No env-file (no secrets)
        self.assertNotIn("--env-file", service)
        self.assertNotIn("workload-write-env", service)


class TestGeneratorSecrets(unittest.TestCase):
    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.services_dir, self.sysusers_dir):
            shutil.rmtree(d)

    def test_secret_env_vars_use_env_file(self):
        write_config(self.config_dir, "secret-app", """\
            [workload]
            name = "secret-app"
            enabled = true

            [container]
            image = "myapp"

            [container.environment]
            API_KEY = "${SECRET:api-key}"
            PLAIN = "visible"
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-secret-app.service").read_text()

        # Secret env var NOT passed as --env
        self.assertNotIn("--env API_KEY=", service)
        # Plain env var still passed as --env
        self.assertIn("--env PLAIN=", service)
        # env-file for secrets
        self.assertIn("--env-file", service)
        self.assertIn("workload-secret-app.secrets", service)
        # write-env helper in ExecStartPre
        self.assertIn("ExecStartPre=+/usr/libexec/workload-write-env secret-app", service)
        # No shell wrapper
        self.assertNotIn("/bin/sh -c", service)

    def test_load_credential_encrypted_directives(self):
        write_config(self.config_dir, "creds", """\
            [workload]
            name = "creds"
            enabled = true

            [container]
            image = "myapp"

            [container.environment]
            KEY = "${SECRET:my-key}"

            [secrets]
            files = [
                { credential = "tls-cert", path = "/etc/ssl/cert.pem" }
            ]
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-creds.service").read_text()

        self.assertIn("LoadCredentialEncrypted=my-key:", service)
        self.assertIn("LoadCredentialEncrypted=tls-cert:", service)

    def test_secret_file_volume_mount(self):
        write_config(self.config_dir, "filemount", """\
            [workload]
            name = "filemount"
            enabled = true

            [container]
            image = "myapp"

            [secrets]
            files = [
                { credential = "tls-cert", path = "/etc/ssl/cert.pem", mode = "ro" }
            ]
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-filemount.service").read_text()

        self.assertIn("--volume", service)
        self.assertIn("tls-cert", service)
        self.assertIn("/etc/ssl/cert.pem", service)
        # No env-file needed (no secret env vars)
        self.assertNotIn("--env-file", service)
        self.assertNotIn("workload-write-env", service)


class TestGeneratorVolumeExpansion(unittest.TestCase):
    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.services_dir, self.sysusers_dir):
            shutil.rmtree(d)

    def test_relative_volume_expanded(self):
        write_config(self.config_dir, "vols", """\
            [workload]
            name = "vols"
            enabled = true

            [container]
            image = "myapp"

            [storage]
            volumes = ["./data:/app/data:rw"]
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-vols.service").read_text()

        self.assertIn("/var/lib/workloads/vols/data", service)
        self.assertNotIn("./data", service)


class TestGeneratorDevices(unittest.TestCase):
    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.services_dir, self.sysusers_dir):
            shutil.rmtree(d)

    def test_gpu_amd(self):
        write_config(self.config_dir, "gpu", """\
            [workload]
            name = "gpu"
            enabled = true

            [container]
            image = "rocm-app"

            [devices]
            gpu = "amd"
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-gpu.service").read_text()

        self.assertIn("--device /dev/kfd", service)
        self.assertIn("--device /dev/dri", service)

    def test_generic_device(self):
        write_config(self.config_dir, "usb", """\
            [workload]
            name = "usb"
            enabled = true

            [container]
            image = "myapp"

            [devices]
            devices = ["/dev/ttyUSB0"]
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-usb.service").read_text()

        self.assertIn("--device /dev/ttyUSB0", service)


class TestGeneratorResources(unittest.TestCase):
    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.services_dir, self.sysusers_dir):
            shutil.rmtree(d)

    def test_cpu_and_memory_limits(self):
        write_config(self.config_dir, "limited", """\
            [workload]
            name = "limited"
            enabled = true

            [container]
            image = "myapp"

            [resources]
            cpu_quota = "200%"
            memory_max = "4G"
            tasks_max = 100
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-limited.service").read_text()

        self.assertIn("CPUQuota=200%", service)
        self.assertIn("MemoryMax=4G", service)
        self.assertIn("TasksMax=100", service)


class TestGeneratorUserns(unittest.TestCase):
    def setUp(self):
        self.config_dir = tempfile.mkdtemp()
        self.services_dir = tempfile.mkdtemp()
        self.sysusers_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        for d in (self.config_dir, self.services_dir, self.sysusers_dir):
            shutil.rmtree(d)

    def test_default_keep_id(self):
        write_config(self.config_dir, "keepid", """\
            [workload]
            name = "keepid"
            enabled = true

            [container]
            image = "myapp"
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-keepid.service").read_text()
        self.assertIn("--userns=keep-id", service)

    def test_host_userns(self):
        write_config(self.config_dir, "hostns", """\
            [workload]
            name = "hostns"
            enabled = true

            [container]
            image = "myapp"

            [security]
            userns = "host"
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-hostns.service").read_text()
        self.assertIn("--userns=host", service)

    def test_keep_id_with_uid_gid(self):
        write_config(self.config_dir, "uidgid", """\
            [workload]
            name = "uidgid"
            enabled = true

            [container]
            image = "myapp"

            [security]
            userns = "keep-id:uid=65534,gid=65534"
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-uidgid.service").read_text()
        self.assertIn("--userns=keep-id:uid=65534,gid=65534", service)

    def test_keep_id_with_uid_only(self):
        write_config(self.config_dir, "uidonly", """\
            [workload]
            name = "uidonly"
            enabled = true

            [container]
            image = "myapp"

            [security]
            userns = "keep-id:uid=1000"
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-uidonly.service").read_text()
        self.assertIn("--userns=keep-id:uid=1000", service)

    def test_keep_id_with_gid_only(self):
        write_config(self.config_dir, "gidonly", """\
            [workload]
            name = "gidonly"
            enabled = true

            [container]
            image = "myapp"

            [security]
            userns = "keep-id:gid=1000"
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-gidonly.service").read_text()
        self.assertIn("--userns=keep-id:gid=1000", service)

    def test_invalid_userns_defaults_to_keep_id(self):
        write_config(self.config_dir, "badns", """\
            [workload]
            name = "badns"
            enabled = true

            [container]
            image = "myapp"

            [security]
            userns = "bogus"
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-badns.service").read_text()
        self.assertIn("--userns=keep-id", service)

    def test_keep_id_nonnumeric_uid_defaults_to_keep_id(self):
        write_config(self.config_dir, "baduid", """\
            [workload]
            name = "baduid"
            enabled = true

            [container]
            image = "myapp"

            [security]
            userns = "keep-id:uid=abc"
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-baduid.service").read_text()
        self.assertIn("--userns=keep-id", service)

    def test_keep_id_unknown_param_defaults_to_keep_id(self):
        write_config(self.config_dir, "badparam", """\
            [workload]
            name = "badparam"
            enabled = true

            [container]
            image = "myapp"

            [security]
            userns = "keep-id:foo=1"
        """)

        run_generator(self.config_dir, self.services_dir, self.sysusers_dir)
        service = (Path(self.services_dir) / "workload-badparam.service").read_text()
        self.assertIn("--userns=keep-id", service)


class TestGeneratorAlwaysExitsZero(unittest.TestCase):
    def test_empty_config_dir(self):
        with tempfile.TemporaryDirectory() as config_dir, \
             tempfile.TemporaryDirectory() as services_dir, \
             tempfile.TemporaryDirectory() as sysusers_dir:
            result = run_generator(config_dir, services_dir, sysusers_dir)
            self.assertEqual(result.returncode, 0)

    def test_missing_config_dir(self):
        with tempfile.TemporaryDirectory() as services_dir, \
             tempfile.TemporaryDirectory() as sysusers_dir:
            result = run_generator("/nonexistent/path", services_dir, sysusers_dir)
            self.assertEqual(result.returncode, 0)

    def test_invalid_toml(self):
        with tempfile.TemporaryDirectory() as config_dir, \
             tempfile.TemporaryDirectory() as services_dir, \
             tempfile.TemporaryDirectory() as sysusers_dir:
            (Path(config_dir) / "bad.toml").write_text("this is not valid toml {{{")
            result = run_generator(config_dir, services_dir, sysusers_dir)
            self.assertEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
