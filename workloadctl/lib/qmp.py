"""
QMP client for QEMU's newline-delimited JSON monitor.

Single source of truth for the QMP wire protocol, shared by the VM helpers
(workload-vm-notify, workload-vm-qmp, workload-vm-shutdown), the exporter, and
workloadctl. Kept in its own module so the connect/retry, capabilities
handshake, and async-event draining live in one place.

Installed to /usr/libexec/workloadctl/qmp.py.
"""

import contextlib
import json
import socket
import time
from typing import Any


class QMPClient:
    """Minimal QMP client over QEMU's newline-delimited JSON monitor.

    Single source of truth for the QMP wire protocol — workload-vm-notify,
    workload-vm-qmp, workload-exporter, and workloadctl all build on this so
    the connect/retry, capabilities handshake, and async-event draining can't
    drift between them. Usable as a context manager.

    Note on monitor contention: a `-qmp unix:...,server=on,wait=off` socket
    serves only one client at a time. The always-on metrics exporter therefore
    connects to a *separate* QMP monitor (qmp-metrics.sock) so its polling can
    never block the control monitor (qmp.sock) used for system_powerdown etc.
    """

    def __init__(self):
        self._sock = None
        self._buf = b""

    def connect(self, path, timeout: float = 10.0, recv_timeout: float = 5.0):
        """Connect to the QMP unix socket, retrying until `timeout` elapses.

        Raises TimeoutError if the socket never becomes available.
        """
        deadline = time.monotonic() + timeout
        while True:
            # The socket is closed on the way out of this block unless the
            # connect succeeds, in which case pop_all() detaches it so it
            # survives as self._sock. This releases the fd on *any* failure in
            # the attempt — not just the OSError below — so a retry loop against
            # a not-yet-ready monitor can't leak descriptors.
            with contextlib.ExitStack() as stack:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                stack.callback(s.close)
                s.settimeout(recv_timeout)
                try:
                    s.connect(str(path))
                except (OSError, ConnectionRefusedError):
                    if time.monotonic() >= deadline:
                        raise TimeoutError(
                            f"QMP socket not ready after {timeout:.0f}s: {path}"
                        )
                    time.sleep(0.2)
                    continue
                self._sock = s
                stack.pop_all()  # success: keep the socket open
                return

    def _readline(self) -> dict:
        """Read one newline-delimited JSON object from the socket."""
        while True:
            if b"\n" in self._buf:
                line, self._buf = self._buf.split(b"\n", 1)
                return json.loads(line.decode())
            assert self._sock is not None
            chunk = self._sock.recv(4096)
            if not chunk:
                raise ConnectionError("QMP socket closed")
            self._buf += chunk

    def _send(self, obj: dict):
        assert self._sock is not None
        self._sock.sendall((json.dumps(obj) + "\n").encode())

    def negotiate(self):
        """Read the QMP greeting and switch the monitor into command mode."""
        self._readline()  # {"QMP": {"version": ..., "capabilities": [...]}}
        self._send({"execute": "qmp_capabilities"})
        self._readline()  # {"return": {}}

    def execute(self, command: str, arguments: dict | None = None,
                max_events: int = 20) -> dict:
        """Run one QMP command, draining async events until its reply arrives.

        Returns the full reply dict ({"return": ...} or {"error": ...}).
        Raises ConnectionError if no reply arrives within max_events messages.
        """
        cmd: dict[str, Any] = {"execute": command}
        if arguments:
            cmd["arguments"] = arguments
        self._send(cmd)
        for _ in range(max_events):
            msg = self._readline()
            if "return" in msg or "error" in msg:
                return msg
        raise ConnectionError(
            f"no QMP reply for {command!r} after {max_events} messages"
        )

    def next_message(self) -> dict | None:
        """Read one QMP message (async event or reply), or None on a read
        timeout while the monitor is still open. Raises ConnectionError when the
        monitor closes (e.g. QEMU exited). Lets a caller watch for async events
        like SHUTDOWN without conflating a quiet monitor with a closed one.
        """
        try:
            return self._readline()
        except socket.timeout:
            return None

    def close(self):
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
