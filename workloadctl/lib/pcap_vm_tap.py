"""The guest vantage of a VM capture: a filter-dump object over QMP.

QEMU stamps filter-dump packets with QEMU_CLOCK_VIRTUAL + start_ts, which is
wrong twice over -- the clock counts from VM start rather than capture start,
and start_ts reinterprets the guest's UTC RTC as host local time. Rather than
guess either term, emit_probe causes one packet at a wall-clock instant this
side knows, and finalize_guest shifts every record by the difference between
that instant and the timestamp the probe carries in the finished file. Nothing
is asked of the guest.
"""
import os
import shutil
import time

from config_parser import SOCKET_DIR
from helper_main import log
from pcap import VANTAGE_GUEST, filter_dump_object, guest_staging_path
from pcap_file import (
    PcapFormatError, pcap_first_timestamp, pcap_shift_timestamps,
)
from qmp import QMPClient
from workload_addr import MGMT_SSH_PORT, management_address


def qmp_socket(name: str) -> str:
    """The control monitor, not the metrics one.

    A QMP socket serves one client at a time. Our use is two brief
    control-flavoured calls, so it belongs on the same monitor as
    system_powerdown rather than on the channel the exporter polls on a timer —
    colliding with a timer is likelier than colliding with a shutdown.
    """
    return f"{SOCKET_DIR}/{name}/qmp.sock"


def guest_vm_up(name: str, plan: dict) -> str | None:
    """Add the filter-dump object. Returns its id, or None if it did not take.

    Writes into the workload's runtime dir, never straight to the operator's
    `-w` path: QEMU runs as _wl-<name> and confined as svirt_t, so an ordinary
    path fails on DAC before SELinux has an opinion.

    And it fails SILENTLY. QEMU accepts `object-add`, the object exists, and no
    file is ever created — measured. So the file's existence is checked here
    rather than trusted, because the alternative is a capture that reports
    success and produces nothing.
    """
    staging = guest_staging_path(name)
    obj = filter_dump_object(0, staging, plan["snaplen"][VANTAGE_GUEST])
    try:
        qmp_command(name, "object-add", obj)
    except Exception as e:  # noqa: BLE001
        log(f"  ERROR: QEMU refused the capture object: {e}")
        return None
    for _ in range(20):
        if os.path.exists(staging):
            break
        time.sleep(0.1)
    else:
        log(f"  ERROR: QEMU accepted the capture object but never created "
            f"{staging}. Is the VM running, and is that directory writable by "
            f"_wl-{name}?")
        guest_vm_down(name, obj["id"])
        return None
    log(f"  Tapping netdev {obj['netdev']} into {staging} "
        f"(maxlen {obj['maxlen']})")
    return obj["id"]


def qmp_command(name: str, command: str, arguments: dict):
    """One QMP round trip on the control monitor.

    connect/negotiate/close by hand rather than as a context manager: QMPClient
    is constructed empty and connected separately, and a monitor serves one
    client at a time, so holding it open across the capture would block
    ExecStop's system_powerdown for the whole run.
    """
    client = QMPClient()
    try:
        client.connect(qmp_socket(name), timeout=5.0, recv_timeout=5.0)
        client.negotiate()
        return client.execute(command, arguments)
    finally:
        client.close()


def guest_vm_down(name: str, object_id: str) -> None:
    try:
        qmp_command(name, "object-del", {"id": object_id})
    except Exception as e:  # noqa: BLE001
        log(f"  WARNING: could not remove {object_id}: {e}")


def emit_probe(uid: int) -> float:
    """Cause one guest-visible packet at a wall-clock instant we know.

    A TCP connect to the workload's management address makes passt hand the
    guest a SYN, which the tap sees. Nothing is sent, nothing needs to answer,
    and the guest needs no cooperation — which is the point. Deriving the
    offset from guest uptime instead (an earlier design's proposal) would have
    left a full timezone offset in place, silently, on every non-UTC host.

    Returns the wall-clock time of the probe. Even if the connection is
    refused, the SYN is emitted and stamped, so a guest with no sshd still
    yields a usable reference.
    """
    import socket
    address = management_address(uid)
    stamp = time.time()
    try:
        with socket.create_connection((address, MGMT_SSH_PORT), timeout=2):
            pass
    except OSError:
        pass
    return stamp


def correct_timestamps(path: str, offset: float) -> bool:
    """Shift a guest-side file by a measured offset.

    What `editcap -t` did, minus the dependency — which mattered because this
    sits in the finalize path that also moves the file to the operator's -w
    destination, so a missing binary aborted the move and the capture never
    appeared. Still write-then-rename: a failure partway must not leave a
    half-shifted file where the whole one was.
    """
    tmp = f"{path}.shifted"
    try:
        shifted = pcap_shift_timestamps(path, tmp, -offset)
    except (OSError, PcapFormatError) as e:
        log(f"  WARNING: could not correct guest-side timestamps: {e}. They "
            f"are offset by the VM's uptime plus this host's UTC offset; "
            f"relative deltas within the file are still correct.")
        if os.path.exists(tmp):
            os.unlink(tmp)
        return False
    os.replace(tmp, path)
    log(f"  Corrected guest-side timestamps by {-offset:.3f}s "
        f"({shifted} packets)")
    return True


def finalize_guest(name: str, dest: str | None, started: float | None) -> None:
    """Correct the staged file's timestamps, then put it where -w asked.

    Two steps in one place because they are the same step: the move exists
    because a confined QEMU cannot write the operator's path, and the
    correction exists because filter-dump's clock is wrong twice — and the
    correction already forced a finalize, so the move rides along free.
    """
    staging = guest_staging_path(name)
    if not os.path.exists(staging):
        return
    if started is not None:
        first = _first_packet_time(staging)
        if first is not None:
            correct_timestamps(staging, first - started)
    if not dest or dest == "-":
        os.unlink(staging)
        return
    shutil.move(staging, dest)
    os.chmod(dest, 0o640)
    log(f"  Wrote {dest}")


def _first_packet_time(path: str) -> float | None:
    """Epoch seconds of the first packet, read from the record header.

    Parsing capinfos meant matching a label that was renamed between wireshark
    releases, and matching one spelling silently skipped the correction. None
    means the file holds no packets — nothing to correct, so no warning.
    """
    try:
        return pcap_first_timestamp(path)
    except (OSError, PcapFormatError) as e:
        log(f"  WARNING: could not read a first-packet time from {path} ({e}); "
            f"leaving guest-side timestamps uncorrected")
        return None
