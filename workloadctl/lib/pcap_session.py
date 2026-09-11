"""One capture session: what the run installs, and the cleanup that removes
it whether or not the run reached its own finally.

run() is the body of the transient workload-pcap-<name>.service; cleanup()
is its ExecStopPost, and needs no plan because everything it removes is
findable from the workload name alone.
"""
import os
import pwd
import signal
import subprocess
import time

from helper_main import log
from pcap import VANTAGE_GUEST, VANTAGE_HOST, filter_dump_id, guest_staging_path, vantage_path
from pcap_container_tap import container_reader
from pcap_host_tap import host_down, host_reader, host_up, report_completeness
from pcap_vm_tap import (
    emit_probe, finalize_guest, guest_vm_down, guest_vm_up, qmp_command,
)


def cleanup(name: str) -> int:
    """Remove everything a capture could have left behind. Idempotent.

    Runs as the unit's ExecStopPost, so it fires on a clean exit, a failed
    start, a RuntimeMaxSec timeout and a `kill -9` alike — the cases a
    `finally` in the capture process cannot reach. Doing the work twice is
    normal and costs a few nft calls.
    """
    try:
        uid = pwd.getpwnam(f"_wl-{name}").pw_uid
    except KeyError:
        return 0
    host_down(uid)
    # The filter-dump object outlives its file, so drop it even when this run
    # never installed one — QEMU answers "object not found" and we move on.
    try:
        qmp_command(name, "object-del", {"id": filter_dump_id(0)})
        log(f"  Removed {filter_dump_id(0)} from {name}")
    except Exception:  # noqa: BLE001
        pass
    # A staged file still here means the capture process died without
    # finalizing — a kill -9, or an OOM kill. Say where it is rather than
    # delete it: the packets are real, the operator asked for them, and only
    # their timestamps are uncorrected. It lives in a tmpfs, there is at most
    # one per workload, and the next capture overwrites it.
    staging = guest_staging_path(name)
    if os.path.exists(staging):
        log(f"  A staged capture remains at {staging} — the capture process "
            f"did not finalize, so its timestamps are offset by the VM's "
            f"uptime plus this host's UTC offset. Relative deltas are correct.")
    return 0


def run(name: str, plan: dict) -> int:
    """One capture, from the plan the CLI rendered. Everything installed on
    the way in is removed in the finally, whatever happened between."""
    vantages = plan["vantages"]

    readers: list[subprocess.Popen] = []
    object_id = None
    started = None

    try:
        if VANTAGE_HOST in vantages:
            host_up(plan)
        if VANTAGE_GUEST in vantages:
            guest_path = vantage_path(plan["write"], VANTAGE_GUEST, len(vantages))
            if plan["substrate"].startswith("VM"):
                object_id = guest_vm_up(name, plan)
                if object_id is None:
                    return 1
                # After the tap, not before: a probe emitted before the object
                # exists is not in the file, and the correction would then be
                # measured against whatever unrelated packet happened to be
                # first.
                started = emit_probe(plan["uid"])
            else:
                readers.append(container_reader(name, plan, guest_path))

        if VANTAGE_HOST in vantages:
            readers.append(host_reader(plan))

        _wait(readers, plan)
        return 0
    finally:
        if object_id:
            guest_vm_down(name, object_id)
            finalize_guest(name, guest_path, started)
        for reader in readers:
            _terminate(reader)
        if VANTAGE_HOST in vantages:
            # Order matters: the counter lives on the rule host_down deletes,
            # and the file is only complete once tcpdump above has exited.
            report_completeness(plan)
            host_down(plan["uid"])


def _wait(readers: list[subprocess.Popen], plan: dict) -> None:
    """Follow the capture until a bound trips or a reader exits.

    The duration bound is RuntimeMaxSec on the unit, so it is not implemented
    here. Size is: at link rate, time is not a size bound, and the filter-dump
    path has no `-C` of its own — so poll st_size on whatever files exist.
    """
    max_size = plan.get("max_size_bytes") or 0
    paths = [p for p in (vantage_path(plan["write"], v, len(plan["vantages"])) for v in plan["vantages"])
             if p and p != "-"]
    while True:
        for reader in readers:
            if reader.poll() is not None:
                return
        if max_size:
            total = sum(os.path.getsize(p) for p in paths if os.path.exists(p))
            if total >= max_size:
                log(f"  Size bound reached ({total} bytes); stopping.")
                return
        if not readers and not paths:
            # A VM guest-side capture with no file to watch: nothing to poll,
            # so wait for RuntimeMaxSec or an explicit stop.
            signal.pause()
        time.sleep(1)


def _terminate(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
