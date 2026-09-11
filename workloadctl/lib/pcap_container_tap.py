"""The guest vantage of a container capture: tcpdump in the workload's netns.

A container has no QEMU to ask, so the tap is tcpdump entered into the
network namespace of the workload's infra process. The pid comes from the
podman wrapper and the interface is read from inside the namespace, never
assumed.
"""
import subprocess

from helper_main import log, run
from pcap import VANTAGE_GUEST
from podman import Podman
from workload_lib import workload_home_dir


def container_netns_pid(name: str, plan: dict) -> int | None:
    """The pid whose network namespace a container's guest-side capture enters.

    Through lib/podman.py, not a hand-rolled `runuser`: talking to a workload
    user's rootless podman needs XDG_RUNTIME_DIR, HOME and that user's session
    bus, and `runuser` alone supplies none of them — it does not even leave a
    cwd the workload user can enter, so the first attempt failed with "cannot
    chdir to /home/ben" before podman ran at all.

    The container name comes from the plan, because the podman name is
    `workload-<name>` for a single-container workload and
    `workload-<name>-<container>` for one member of a pod. Guessing the bare
    workload name finds nothing; guessing the wrong member captures a sibling's
    traffic and says nothing about it.
    """
    container = plan.get("podman_container")
    if not container:
        return None
    podman = Podman.for_user(f"_wl-{name}", plan["uid"],
                             workload_home_dir(name))
    info = podman.container_inspect(container)
    if info is None:
        return None
    pid = (info.get("State") or {}).get("Pid")
    return int(pid) if pid else None


def container_interface(pid: int) -> str:
    """The interface to capture on, discovered rather than assumed.

    pasta names its tun after the host interface it templated from, falling
    back to tap0 only when there is no template, and podman may pass its own —
    measured on podman 5.8.4, a pasta container's is `enp1s0` (copying the
    host's) while a custom-network container gets a veth called `eth0`. No
    single name is right for both, so read the default route inside the
    namespace.
    """
    result = run(["nsenter", "-t", str(pid), "-n", "ip", "-o", "route",
                  "show", "default"])
    parts = result.stdout.split()
    if "dev" in parts:
        return parts[parts.index("dev") + 1]
    # No default route inside the namespace. `any` still captures, and saying
    # so beats guessing tap0 — which is right for neither pasta nor a veth.
    log("  WARNING: no default route in the namespace; capturing on 'any'")
    return "any"


def container_reader(name: str, plan: dict, path: str | None) -> subprocess.Popen:
    pid = container_netns_pid(name, plan)
    if pid is None:
        raise RuntimeError(
            f"could not find a running container for "
            f"{plan.get('podman_container') or name}; is the workload up?")
    interface = container_interface(pid)
    argv = ["nsenter", "-t", str(pid), "-n", "tcpdump", "-i", interface,
            "-s", str(plan["snaplen"][VANTAGE_GUEST]), "-U"]
    if path:
        argv += ["-w", path]
    if plan.get("bpf"):
        argv += list(plan["bpf"])
    log(f"  {' '.join(argv)}")
    return subprocess.Popen(argv)
