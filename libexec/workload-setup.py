#!/usr/bin/python3
"""
Configure rootless workload users after sysusers creates them.
Runs as a systemd service after boot to set up subuid/subgid and home directories.
"""

import os
import pwd
import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ImportError:
    import tomli as tomllib


WORKLOAD_CONFIG_DIR = Path("/etc/workloads.d")


def log(msg):
    """Print to stdout (captured by systemd journal)."""
    print(msg, flush=True)


def get_enabled_workload_configs():
    """Parse workload configs and return list of (username, config) tuples for enabled workloads."""
    enabled_configs = []

    if not WORKLOAD_CONFIG_DIR.exists():
        return enabled_configs

    for config_file in WORKLOAD_CONFIG_DIR.glob("*.toml"):
        try:
            with open(config_file, "rb") as f:
                config = tomllib.load(f)

            # Skip disabled workloads
            if not config.get("workload", {}).get("enabled", False):
                continue

            # Extract name and id
            name = config.get("workload", {}).get("name")
            workload_id = config.get("container", {}).get("id")

            if name and workload_id:
                username = f"_wl-{name}-{workload_id}"
                enabled_configs.append((username, config))

        except Exception as e:
            log(f"WARNING: Failed to parse {config_file}: {e}")
            continue

    return enabled_configs


def user_exists(username):
    """Check if user exists."""
    try:
        pwd.getpwnam(username)
        return True
    except KeyError:
        return False


def configure_subuid_subgid(username, config):
    """Configure subordinate UID/GID ranges for rootless containers."""
    try:
        user_info = pwd.getpwnam(username)
        uid = user_info.pw_uid
        home_dir = user_info.pw_dir
        gid = user_info.pw_gid

        # Allocate 65536 subordinate UIDs/GIDs
        # Start at 100000 + (uid offset * 100000) to avoid conflicts
        # For UID 10001: 100000 + (1 * 100000) = 200000
        # For UID 10002: 100000 + (2 * 100000) = 300000
        base_uid = 10000
        uid_offset = uid - base_uid
        subuid_start = 100000 + (uid_offset * 100000)
        subgid_start = 100000 + (uid_offset * 100000)
        count = 65536

        subuid_entry = f"{username}:{subuid_start}:{count}\n"
        subgid_entry = f"{username}:{subgid_start}:{count}\n"

        # Check if entries already exist
        subuid_exists = False
        subgid_exists = False

        try:
            with open("/etc/subuid", "r") as f:
                if any(line.startswith(f"{username}:") for line in f):
                    subuid_exists = True
        except FileNotFoundError:
            pass

        try:
            with open("/etc/subgid", "r") as f:
                if any(line.startswith(f"{username}:") for line in f):
                    subgid_exists = True
        except FileNotFoundError:
            pass

        # Add entries if they don't exist
        # Use subprocess with shell redirection to work around early-boot filesystem restrictions
        if not subuid_exists:
            result = subprocess.run(
                ["bash", "-c", f"echo '{subuid_entry.strip()}' >> /etc/subuid"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                log(f"  Configured subuid range for {username}: {subuid_start}:{count}")
            else:
                raise Exception(f"Failed to write subuid: {result.stderr}")

        if not subgid_exists:
            result = subprocess.run(
                ["bash", "-c", f"echo '{subgid_entry.strip()}' >> /etc/subgid"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                log(f"  Configured subgid range for {username}: {subgid_start}:{count}")
            else:
                raise Exception(f"Failed to write subgid: {result.stderr}")

        # Create home directory if it doesn't exist
        home_path = Path(home_dir)
        if not home_path.exists():
            log(f"  Creating home directory {home_dir}")
            home_path.mkdir(parents=True, exist_ok=True)
            os.chown(home_dir, uid, gid)
            os.chmod(home_dir, 0o700)
        else:
            # Ensure correct ownership even if dir exists
            os.chown(home_dir, uid, gid)
            os.chmod(home_dir, 0o700)

        # Create volume mount directories from config
        volumes = config.get("storage", {}).get("volumes", [])
        for volume_spec in volumes:
            # Parse volume spec: "/host/path:/container/path:options"
            parts = volume_spec.split(":")
            if not parts:
                continue

            host_path = Path(parts[0])

            # Only create directories that are within the home directory
            # This is for safety - don't create arbitrary system directories
            try:
                # Check if host_path is relative to home_dir
                host_path.relative_to(home_path)

                # It's inside the home directory, safe to create
                if not host_path.exists():
                    log(f"  Creating volume directory {host_path}")
                    host_path.mkdir(parents=True, exist_ok=True)
                    os.chown(host_path, uid, gid)
                    os.chmod(host_path, 0o755)
            except ValueError:
                # Path is not relative to home directory, skip
                # These should be created manually by the admin
                pass

        # Set SELinux label for container access
        log(f"  Setting SELinux context for {home_dir}")
        subprocess.run(
            ["restorecon", "-R", home_dir],
            capture_output=True
        )

        return True
    except Exception as e:
        log(f"  WARNING: Failed to configure {username}: {e}")
        return False


def setup_selinux_policy():
    """Set up SELinux policy for workload directories.

    This creates a persistent policy that survives system relabels.
    """
    try:
        # Check if policy already exists
        result = subprocess.run(
            ["semanage", "fcontext", "-l"],
            capture_output=True,
            text=True
        )

        if "/var/lib/workloads" in result.stdout:
            log("  SELinux policy for /var/lib/workloads already exists")
            return True

        # Add policy for workload directories
        log("  Creating SELinux policy for /var/lib/workloads")
        result = subprocess.run(
            ["semanage", "fcontext", "-a", "-t", "container_file_t",
             "/var/lib/workloads(/.*)?"],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            log("  SELinux policy created successfully")
            return True
        else:
            log(f"  WARNING: Failed to create SELinux policy: {result.stderr}")
            return False

    except Exception as e:
        log(f"  WARNING: Failed to set up SELinux policy: {e}")
        return False


def enable_linger(username):
    """Enable lingering for workload user.

    Creates persistent systemd user manager (user@UID.service) that:
    - Maintains /run/user/<uid> directory
    - Provides D-Bus session for podman
    - Allows podman to use systemd cgroup manager
    """
    try:
        user_info = pwd.getpwnam(username)
        uid = user_info.pw_uid

        # Check if linger is already enabled
        linger_file = Path(f"/var/lib/systemd/linger/{username}")
        if linger_file.exists():
            log(f"  Linger already enabled for {username}")
            return True

        # Enable linger using loginctl
        result = subprocess.run(
            ["loginctl", "enable-linger", str(uid)],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            log(f"  Enabled linger for {username} (UID {uid})")
            return True
        else:
            log(f"  WARNING: Failed to enable linger for {username}: {result.stderr}")
            return False

    except Exception as e:
        log(f"  WARNING: Failed to enable linger for {username}: {e}")
        return False


def main():
    log("Starting workload setup")

    # Get enabled workload configs
    enabled_configs = get_enabled_workload_configs()
    log(f"Found {len(enabled_configs)} enabled workload(s)")

    if not enabled_configs:
        log("No enabled workloads, nothing to do")
        return 0

    # Set up SELinux policy for workload directories (runs once, persistent)
    setup_selinux_policy()

    # Configure subuid/subgid, create home dirs, and enable linger for each enabled workload
    # Note: Group memberships are handled by systemd-sysusers 'm' directives in the generator
    for username, config in enabled_configs:
        if not user_exists(username):
            log(f"  WARNING: User {username} does not exist (should have been created by sysusers)")
            continue

        log(f"  Configuring {username}")
        configure_subuid_subgid(username, config)
        enable_linger(username)

    log("Workload setup complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
