"""
cmd_interact — interactive/exec commands: shell, exec, logs, cp, attach.
Also contains VM SSH/console helpers used by other modules.
"""

import os
from pathlib import Path
import re
import subprocess
import sys

from workload_lib import (
    VM_BRIDGE_NAME,
    VM_DHCP_LEASE_FILE,
    VM_SOCKET_DIR,
    vm_mac_address,
)
from workloadctl_core import (
    WorkloadConfig,
    WorkloadManager,
    parse_workload_ref,
    resolve_container_target,
)


# ---------------------------------------------------------------------------
# VM console/SSH helpers (also imported by cmd_lifecycle, cmd_update, cmd_inspect)
# ---------------------------------------------------------------------------

def _vm_console_sock(name: str) -> Path:
    return VM_SOCKET_DIR / name / "console.sock"


def _vm_ssh_key(config: "WorkloadConfig") -> Path:
    return config.home_dir / ".ssh" / "id_ed25519"


def _vm_guest_user(config: "WorkloadConfig") -> str:
    return config.config.get("vm", {}).get("user", "workload")


def _vm_ssh_command(
    config: "WorkloadConfig",
    guest_ip: str,
    exec_args: list[str] | None = None,
    connect_timeout: int | None = None,
) -> list[str]:
    """Build the ssh argv used to reach a VM workload's guest user."""
    key_path = _vm_ssh_key(config)
    guest_user = _vm_guest_user(config)
    cmd = [
        "ssh",
        *(["-t"] if sys.stdout.isatty() else []),
        "-i", str(key_path),
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
    ]
    if connect_timeout is not None:
        cmd += ["-o", f"ConnectTimeout={connect_timeout}"]
    cmd.append(f"{guest_user}@{guest_ip}")
    if exec_args:
        cmd += ["--", *exec_args]
    return cmd


def _vm_guest_ip(name: str, bridge: str = VM_BRIDGE_NAME) -> str | None:
    """Look up the VM's IP by hostname in dnsmasq leases, MAC via ARP, or mDNS.

    The dnsmasq lease file is only authoritative when workload-bridge.service
    actually manages a bridge it created (signalled by /run/workload-vm/
    bridge-managed). On a pre-existing LAN bridge (e.g. br0) no dnsmasq runs
    and any old lease entries are stale, so we go straight to ARP.

    Falls back to mDNS ({name}.local) when avahi/nss-mdns are available.
    """
    if Path("/run/workload-vm/bridge-managed").exists():
        lease_file = VM_DHCP_LEASE_FILE
        if lease_file.exists():
            try:
                for line in lease_file.read_text().splitlines():
                    parts = line.split()
                    # dnsmasq lease format: <timestamp> <mac> <ip> <hostname> <client-id>
                    if len(parts) >= 4 and parts[3] == name:
                        return parts[2]
            except OSError:
                pass

    # Pre-existing LAN bridge: no lease file.  Look up by the VM's stable MAC.
    mac = vm_mac_address(name)
    try:
        result = subprocess.run(
            ["ip", "neigh", "show", "dev", bridge],
            capture_output=True, text=True,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            # `ip neigh show dev <iface>` omits the `dev <iface>` tokens it
            # prints in the unfiltered form, so the MAC's column isn't fixed
            # (`<ip> lladdr <mac> <state>` here vs `<ip> dev <iface> lladdr
            # <mac> <state>` unfiltered). Find it by the `lladdr` marker, which
            # is stable either way; parts[0] is always the IP.
            if "lladdr" in parts:
                mac_idx = parts.index("lladdr") + 1
                if mac_idx < len(parts) and parts[mac_idx].lower() == mac.lower():
                    return parts[0]
    except OSError:
        pass

    # mDNS fallback: works when avahi + nss-mdns are installed on the host.
    try:
        result = subprocess.run(
            ["getent", "hosts", f"{name}.local"],
            capture_output=True, text=True, timeout=3,
        )
        if result.returncode == 0:
            parts = result.stdout.split()
            if parts:
                return parts[0]
    except (OSError, subprocess.TimeoutExpired):
        pass

    return None


# ---------------------------------------------------------------------------
# Exec helpers
# ---------------------------------------------------------------------------

def _interactive_exec_flags():
    """Interactivity flags for `podman exec`: always keep stdin open (-i), but
    only allocate a pseudo-TTY (-t) when stdin is a real terminal.

    Passing -t without a TTY hangs on piped input. Without -t, scripted /
    non-interactive callers use a plain no-pty exec path, which is robust.
    """
    return ["-i", "-t"] if sys.stdin.isatty() else ["-i"]


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_shell(args, manager: WorkloadManager):
    """Open interactive shell in workload container or VM console"""
    workload, container = parse_workload_ref(args.workload)
    config = WorkloadConfig(workload)

    if not manager.user_exists(config):
        print(f"Error: Workload user '{config.username}' does not exist", file=sys.stderr)
        print("Is the workload enabled and running?", file=sys.stderr)
        sys.exit(1)

    if config.is_vm:
        # Prefer SSH so the guest tty inherits the host's window size and
        # signal handling. The serial console (socat below) is reserved as
        # an explicit recovery path when --console is passed or SSH can't
        # reach the VM (no lease, no network, sshd down).
        if not args.console:
            guest_ip = _vm_guest_ip(config.name, config.vm_bridge)
            if guest_ip:
                ssh_cmd = _vm_ssh_command(config, guest_ip, connect_timeout=5)
                result = subprocess.run(ssh_cmd)
                # 255 = ssh transport failure (host unreachable, auth, etc.);
                # anything else came from the remote shell and should propagate.
                if result.returncode != 255:
                    sys.exit(result.returncode)
                print(f"SSH to '{workload}' failed; falling back to serial console.",
                      file=sys.stderr)
            else:
                print(f"No IP found for VM '{workload}'; falling back to serial console.",
                      file=sys.stderr)

        # Connect to the VM serial console via the socat multiplexer.
        # The console socket is created by QEMU; multiple clients share it
        # through a socat relay (each session gets its own input/output view).
        console_sock = _vm_console_sock(config.name)
        if not console_sock.exists():
            print(f"Error: console socket not found: {console_sock}", file=sys.stderr)
            print(f"Is workload '{workload}' running?", file=sys.stderr)
            sys.exit(1)
        print(f"Connecting to {workload} console (Ctrl-] to disconnect)...")
        print()
        os.execvp("socat", ["socat", "STDIO,raw,echo=0,escape=0x1d", f"UNIX-CONNECT:{console_sock}"])
        # execvp replaces the process; unreachable
        return

    target = resolve_container_target(config, container, workload)

    # Determine container user from environment, fall back to root
    env = config.config.get("container", {}).get("environment", {})
    container_user = env.get("CONTAINER_USER")
    container_uid = env.get("CONTAINER_UID")

    exec_opts = _interactive_exec_flags()
    if container_user:
        uid = container_uid or "1000"
        home = f"/home/{container_user}"
        exec_opts.extend(["--user", container_user, "--workdir", home,
                          "--env", f"HOME={home}",
                          "--env", f"XDG_RUNTIME_DIR=/run/user/{uid}",
                          "--env", f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus"])
    elif container_uid:
        exec_opts.extend(["--user", container_uid,
                          "--env", f"XDG_RUNTIME_DIR=/run/user/{container_uid}",
                          "--env", f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{container_uid}/bus"])

    print(f"Opening shell in {target}...")
    print()

    # Try bash first, fall back to sh only if bash isn't available in the image.
    # 127 = command not found; any other non-zero is propagated from the user's
    # last command (e.g. 130 after ^C), not a reason to relaunch.
    result = manager.run_podman_exec(config, [*exec_opts, target, "/bin/bash"])
    if result.returncode == 127:
        manager.run_podman_exec(config, [*exec_opts, target, "/bin/sh"], check=True)


def cmd_exec(args, manager: WorkloadManager):
    """Execute command in workload container or VM (via SSH)"""
    workload, container = parse_workload_ref(args.workload)
    config = WorkloadConfig(workload)

    if not manager.user_exists(config):
        print(f"Error: Workload user '{config.username}' does not exist", file=sys.stderr)
        print("Is the workload enabled and running?", file=sys.stderr)
        sys.exit(1)

    # argparse.REMAINDER keeps a literal `--` separator if the user passed one
    # (`workloadctl exec web -- cmd`); drop it so it isn't run as the command.
    exec_args = args.exec_args
    if exec_args and exec_args[0] == "--":
        exec_args = exec_args[1:]
    if not exec_args:
        print("Error: no command given to exec", file=sys.stderr)
        sys.exit(2)

    if config.is_vm:
        guest_ip = _vm_guest_ip(config.name, config.vm_bridge)
        if not guest_ip:
            print(f"Error: could not determine IP for VM '{workload}'", file=sys.stderr)
            print(f"  Check {VM_DHCP_LEASE_FILE} or use 'workloadctl shell {workload}' (console).",
                  file=sys.stderr)
            sys.exit(1)
        ssh_cmd = _vm_ssh_command(config, guest_ip, exec_args=exec_args)
        result = subprocess.run(ssh_cmd)
        sys.exit(result.returncode)

    target = resolve_container_target(config, container, workload)
    # Propagate the command's exit code (like the VM path above) rather than
    # raising on nonzero: `exec ... -- sh -c 'exit 42'` should exit 42, not
    # surface a raw CalledProcessError as exit 1.
    result = manager.run_podman_exec(config, [*_interactive_exec_flags(), target, *exec_args])
    sys.exit(result.returncode)


def cmd_logs(args, manager: WorkloadManager):
    """View workload logs"""
    workload, container = parse_workload_ref(args.workload)
    config = WorkloadConfig(workload)

    if container is not None:
        if container not in config.container_names():
            print(f"Error: container '{container}' not in workload '{workload}'. "
                  f"Available: {', '.join(config.container_names())}", file=sys.stderr)
            sys.exit(2)
        unit = f"workload-{workload}-{container}.service"
        cmd = ["journalctl", "-u", unit]
    elif config.is_multi:
        # journalctl's `-u 'glob*'` is unreliable (fails with "No data
        # available" when a matching unit has no journal entries yet), so
        # pass every unit explicitly: setup, umbrella, the pod/net helper,
        # and each container service.
        helper = "pod" if config.mode == "pod" else "net"
        units = [
            f"workload-{workload}-setup.service",
            config.service_name,
            f"workload-{workload}-{helper}.service",
            *config.sub_service_names(),
        ]
        cmd = ["journalctl"]
        for u in units:
            cmd += ["-u", u]
    else:
        cmd = ["journalctl", "-u", config.service_name]

    # Add options
    if args.follow:
        cmd.append("-f")
    if args.lines:
        cmd.extend(["-n", str(args.lines)])
    elif not args.follow and not args.since and not args.extra_args:
        cmd.extend(["-n", "50"])
    if args.since:
        cmd.extend(["--since", args.since])

    if args.extra_args:
        cmd.extend(args.extra_args)

    subprocess.run(cmd)


def cmd_cp(args, manager: WorkloadManager):
    """Copy files to/from container"""
    src = args.source
    dest = args.destination

    # Parse workload[/container]:path syntax
    workload_pattern = re.compile(r'^([^:]+):(.+)$')

    src_match = workload_pattern.match(src)
    dest_match = workload_pattern.match(dest)

    if src_match and not dest_match:
        # Copy from container
        workload_ref = src_match.group(1)
        container_path = src_match.group(2)
        host_path = dest
        direction = "from"
    elif dest_match and not src_match:
        # Copy to container
        workload_ref = dest_match.group(1)
        container_path = dest_match.group(2)
        host_path = src
        direction = "to"
    else:
        print("Error: One argument must be in workload:path format", file=sys.stderr)
        print("Examples:", file=sys.stderr)
        print("  workloadctl cp webserver:/etc/config ./config", file=sys.stderr)
        print("  workloadctl cp ./file.txt webserver:/data/file.txt", file=sys.stderr)
        print("  workloadctl cp proxy/web:/etc/config ./config", file=sys.stderr)
        sys.exit(1)

    workload, container = parse_workload_ref(workload_ref)
    config = WorkloadConfig(workload)

    if not manager.user_exists(config):
        print(f"Error: Workload user '{config.username}' does not exist", file=sys.stderr)
        print("Is the workload enabled and running?", file=sys.stderr)
        sys.exit(1)

    target = resolve_container_target(config, container, workload)

    if direction == "from":
        manager.podman(config).run("cp", f"{target}:{container_path}", host_path, check=True)
    else:
        manager.podman(config).run("cp", host_path, f"{target}:{container_path}", check=True)

    print("✓ Copied successfully")


def cmd_attach(args, manager: WorkloadManager):
    """Attach to container process"""
    workload, container = parse_workload_ref(args.workload)
    config = WorkloadConfig(workload)

    if not manager.user_exists(config):
        print(f"Error: Workload user '{config.username}' does not exist", file=sys.stderr)
        print("Is the workload enabled and running?", file=sys.stderr)
        sys.exit(1)

    target = resolve_container_target(config, container, workload)
    print(f"Attaching to {target}...")
    print("(Press Ctrl+C to detach)")
    print()

    manager.podman(config).run("attach", target, check=True)
