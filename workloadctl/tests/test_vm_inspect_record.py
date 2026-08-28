"""The per-request record's join key — rung 5 T1a.

Rungs 2–4 log a decision per connection and per request, and none of those
lines say WHICH connection. `peer=` is on every one of them and cannot serve:
a source port repeats across the requests on one keep-alive connection and is
reused by the kernel after close, so grouping by it merges unrelated
connections and splits one connection's own requests apart.

T1a puts a connection id at the front of `where` — which every decision path
in the listener interpolates — and a request ordinal in the two request loops.
These tests hold three properties: the key is on every line, one connection's
lines share it, and two connections do not.
"""

import io
import json
import os
import re
import socket
import stat
import tempfile
import threading
import time
import unittest
import unittest.mock
from pathlib import Path

from tests import load_script
from vm import (
    VM_INSPECT_LOG_ID_FIELD, VM_INSPECT_LOG_REQ_FIELD,
    VM_INSPECT_RECORD_FILE, VM_INSPECT_RECORD_ROOT,
    VM_INSPECT_RECORD_SELINUX_TYPE,
    vm_inspect_logs_directory, vm_inspect_record_dir, vm_inspect_record_path,
)

ROOT = Path(__file__).resolve().parent.parent

_MOD = None


def _mod():
    """The listener module, loaded once — see test_vm_inspect_listener._mod."""
    global _MOD
    if _MOD is None:
        _MOD = load_script("libexec/workload-vm-inspect-listener")
    return _MOD


ID = re.compile(r"\bid=([0-9a-f]{12})\b")
REQ = re.compile(r"\breq=(\d+)\b")

CLEARTEXT = ("198.18.1.1", 8080)
TLS = ("198.18.1.1", 8443)


def _listener_with(local):
    m = unittest.mock.Mock()
    m.getsockname.return_value = local
    return m


class _Harness(unittest.TestCase):

    def _pair(self):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        a.settimeout(3.0)
        b.settimeout(3.0)
        return a, b

    def _serve(self, feed, *, local=CLEARTEXT, hosts=(), peer=("192.0.2.1", 1024)):
        """One connection, driven through _serve — the function _handle's
        thread calls, so the lines are the real ones and the assertion is not
        a race against a daemon thread."""
        mod = _mod()
        out = io.StringIO()
        listener = mod.Listener(
            [_listener_with(local)], out,
            policy=mod.Policy(tls="splice", hosts=tuple(hosts)))
        ours, guest = self._pair()
        guest.sendall(feed)
        guest.shutdown(socket.SHUT_WR)
        listener._serve(ours, peer, local, mod.plane_for_port(local[1]),
                        mod.secrets.token_hex(6))
        return out.getvalue()

    def _lines(self, log):
        return [ln for ln in log.splitlines() if ln.strip()]


class TestTheFieldNamesAreShared(unittest.TestCase):
    """lib/ restates what this entrypoint emits, because lib/ cannot import an
    extension-less script. The restatement is only safe while a rename over
    there fails a test here — otherwise the reader keeps looking for a field
    nobody emits any more and reports every join as a miss."""

    def test_the_id_field_name_matches(self):
        self.assertEqual(_mod().LOG_ID_FIELD, VM_INSPECT_LOG_ID_FIELD)

    def test_the_request_field_name_matches(self):
        self.assertEqual(_mod().LOG_REQ_FIELD, VM_INSPECT_LOG_REQ_FIELD)


class TestEveryLineCarriesTheId(_Harness):
    """`where` leads with the id, so every path that interpolates it gets one
    — which is the whole reason the field went there rather than onto the
    handful of lines someone remembered to edit."""

    def test_a_refused_request_carries_one(self):
        log = self._serve(b"GET / HTTP/1.1\r\nHost: nobody.example\r\n\r\n")
        self.assertRegex(log, ID)

    def test_a_forwarded_request_carries_one(self):
        mod = _mod()
        origin = []

        def dial(addr, timeout=None):
            near, far = self._pair()
            far.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            origin.append(far)
            return near

        with unittest.mock.patch.object(
                socket, "create_connection", side_effect=dial):
            log = self._serve(
                b"GET / HTTP/1.1\r\nHost: ok.example\r\nConnection: close\r\n\r\n",
                hosts=("ok.example",))
        self.assertIn("forward ", log)
        self.assertRegex(log, ID)

    def test_a_tls_connection_with_no_readable_name_carries_one(self):
        log = self._serve(b"\x16\x03\x01\x00\x05rubbish", local=TLS)
        self.assertIn("drop ", log)
        self.assertRegex(log, ID)

    def test_the_id_leads_the_line_after_the_verb(self):
        """Anchored, not merely present. A reader grepping one connection out
        of a file wants a fixed position to cut on, and a field that drifted
        to the end of the line would still pass a bare `assertIn`."""
        log = self._serve(b"GET / HTTP/1.1\r\nHost: nobody.example\r\n\r\n")
        for line in self._lines(log):
            self.assertRegex(line, r"^\w+ id=[0-9a-f]{12} plane=")

    def test_a_connection_the_ceiling_rejects_carries_one(self):
        """The rejection path never reaches _serve, which is exactly why the
        id is minted in _handle: a guest reporting a stall it got no answer to
        is correlated through these two lines or through nothing."""
        mod = _mod()
        out = io.StringIO()
        listener = mod.Listener([_listener_with(CLEARTEXT)], out, limit=0)
        conn = unittest.mock.MagicMock()
        conn.recv.return_value = b""
        listener._handle(conn, ("192.0.2.1", 1024), _listener_with(CLEARTEXT))
        self.assertIn("rejected ", out.getvalue())
        self.assertRegex(out.getvalue(), ID)

    def test_a_connection_no_thread_could_be_started_for_carries_one(self):
        mod = _mod()
        out = io.StringIO()
        listener = mod.Listener([_listener_with(CLEARTEXT)], out)
        conn = unittest.mock.MagicMock()
        conn.recv.return_value = b""
        with unittest.mock.patch.object(
                threading.Thread, "start",
                side_effect=RuntimeError("can't start new thread")):
            listener._handle(conn, ("192.0.2.1", 1024),
                             _listener_with(CLEARTEXT))
        self.assertIn("cannot start thread", out.getvalue())
        self.assertRegex(out.getvalue(), ID)


class TestTheIdGroupsOneConnection(_Harness):

    def test_every_line_of_one_connection_shares_it(self):
        """Three requests, two of them refused, on one connection. If the id
        were minted per request rather than per connection this passes each
        line individually and groups nothing."""
        log = self._serve(
            b"GET /a HTTP/1.1\r\nHost: nobody.example\r\n\r\n"
            b"GET /b HTTP/1.1\r\nHost: other.example\r\n\r\n"
            b"GET /c HTTP/1.1\r\nHost: third.example\r\n\r\n")
        found = set(ID.findall(log))
        self.assertEqual(len(self._lines(log)), 3)
        self.assertEqual(len(found), 1, f"one connection, one id: {log!r}")

    def test_two_connections_do_not_share_it(self):
        feed = b"GET / HTTP/1.1\r\nHost: nobody.example\r\n\r\n"
        first = set(ID.findall(self._serve(feed)))
        second = set(ID.findall(self._serve(feed)))
        self.assertEqual(len(first), 1)
        self.assertEqual(len(second), 1)
        self.assertNotEqual(first, second)

    def test_the_id_is_not_a_counter(self):
        """Restarts are the case. The listener is socket-activated, so a
        counter begins again at zero every time the socket re-triggers it,
        while the record file it keys outlives that restart — two unrelated
        connections would collide on the one key a reader joins on."""
        mod = _mod()
        out = io.StringIO()
        listener = mod.Listener([_listener_with(CLEARTEXT)], out, limit=0)
        for _ in range(4):
            conn = unittest.mock.MagicMock()
            conn.recv.return_value = b""
            listener._handle(conn, ("192.0.2.1", 1024),
                             _listener_with(CLEARTEXT))
        found = ID.findall(out.getvalue())
        self.assertEqual(len(found), 4)
        self.assertEqual(len(set(found)), 4)
        self.assertNotIn("000000000000", found)


class TestTheRequestOrdinal(_Harness):

    def test_it_counts_the_requests_on_one_connection(self):
        log = self._serve(
            b"GET /a HTTP/1.1\r\nHost: nobody.example\r\n\r\n"
            b"GET /b HTTP/1.1\r\nHost: other.example\r\n\r\n"
            b"GET /c HTTP/1.1\r\nHost: third.example\r\n\r\n")
        self.assertEqual(REQ.findall(log), ["1", "2", "3"])

    def test_a_connection_level_line_has_none(self):
        """The TLS front takes its decision before any request exists, so a
        `req=` there would be inventing an ordinal for something that is not a
        request — and a reader joining on it would attribute a connection's
        refusal to whichever request happened to be numbered 1."""
        log = self._serve(b"\x16\x03\x01\x00\x05rubbish", local=TLS)
        self.assertNotRegex(log, REQ)


if __name__ == "__main__":
    unittest.main()


class TestWhereTheRecordGoes(unittest.TestCase):
    """Not the journal, and not the workload tree. Both alternatives were
    argued and both are wrong for reasons the paths themselves cannot state,
    so the paths are pinned here."""

    def test_the_record_is_not_under_the_workload_tree(self):
        """state/ is svirt_image_t, the label the PKI rules exist to move
        material out of, and data/ is where `./` volume anchors resolve — a
        guest with a volume at the data root would read its own audit log."""
        path = str(vm_inspect_record_path("demo"))
        self.assertNotIn("/var/lib/workloads", path)
        self.assertNotIn("/run/workload-vm", path)

    def test_the_path_is_per_workload(self):
        self.assertNotEqual(vm_inspect_record_path("a"),
                            vm_inspect_record_path("b"))
        self.assertEqual(vm_inspect_record_path("a").name,
                         VM_INSPECT_RECORD_FILE)
        self.assertEqual(vm_inspect_record_dir("a").parent,
                         VM_INSPECT_RECORD_ROOT)

    def test_the_logs_directory_names_the_same_place(self):
        """A LogsDirectory= naming a different path than the listener writes to
        gives the unit a writable directory nobody uses and a write that fails
        EROFS under ProtectSystem=strict — swallowed by the per-connection
        OSError handler, and shaped like a network fault."""
        self.assertEqual(
            Path("/var/log") / vm_inspect_logs_directory("demo"),
            vm_inspect_record_dir("demo"))

    def test_the_root_is_created_0700_by_tmpfiles(self):
        """systemd applies LogsDirectoryMode= to the LEAF only and creates the
        parents 0755, so the per-workload directories would sit 0700 under a
        root anyone could list."""
        conf = (ROOT / "systemd" / "workloads-dirs.conf").read_text()
        line = [ln for ln in conf.splitlines()
                if ln.split()[1:2] == [str(VM_INSPECT_RECORD_ROOT)]]
        self.assertEqual(len(line), 1, conf)
        self.assertEqual(line[0].split()[2], "0700")


class TestTheUnitCarriesTheDirectory(unittest.TestCase):
    """LogsDirectory= is doing three things at once — creating the directory as
    User=, recreating it when an operator deletes it, and adding it to the
    unit's writable set under ProtectSystem=strict. The third has no other
    statement in the unit, so losing this line loses the write silently."""

    def _unit(self):
        gen = load_script("generators/workload-generate")
        config = {
            "workload": {"name": "recdemo", "mode": "vm"},
            "vm": {"image": "/tmp/x.qcow2", "memory": "1G", "cpus": 1,
                   "network": {"egress": "filtered",
                               "hosts": ["example.com"]}},
        }
        return gen.generate_vm_inspect_service(config, "_wl-recdemo")

    def test_it_names_the_workloads_own_directory(self):
        self.assertIn(f"LogsDirectory={vm_inspect_logs_directory('recdemo')}",
                      self._unit())

    def test_the_mode_is_0700(self):
        self.assertIn("LogsDirectoryMode=0700", self._unit())


class TestTheSubtreeIsLabelled(unittest.TestCase):
    """A record left as var_log_t is readable by every domain shipped policy
    lets read the system's logs — which is the ACL the decision to keep it out
    of the journal exists to avoid."""

    def _cil(self):
        return (ROOT / "security" / "workload-inspect.cil").read_text()

    def test_the_type_is_declared(self):
        self.assertIn(f"(type {VM_INSPECT_RECORD_SELINUX_TYPE})", self._cil())

    def test_it_is_a_logfile_so_logrotate_needs_no_rule_of_ours(self):
        self.assertIn(
            f"(typeattributeset logfile ({VM_INSPECT_RECORD_SELINUX_TYPE}))",
            self._cil())

    def test_the_filecon_covers_every_workload(self):
        self.assertIn(f'(filecon "{VM_INSPECT_RECORD_ROOT}(/.*)?"', self._cil())

    def test_init_may_mount_it(self):
        """ReadWritePaths=/LogsDirectory= under ProtectSystem=strict is a bind
        mount init_t performs, so the label is checked against INIT_T. Without
        it the unit does not start and the message names the ExecStartPre."""
        self.assertRegex(
            self._cil(),
            rf"\(allow init_t {VM_INSPECT_RECORD_SELINUX_TYPE} "
            rf"\(dir \([^)]*mounton")

    def test_the_filecon_is_not_shadowed(self):
        """A module filecon is silently ignored under a prefix workloadctl
        registers in file_contexts.local. /var/log is not one of those, which
        is the only reason this rule may live in the module at all."""
        from provisioning import LOCAL_FCONTEXT_ROOTS
        for root in LOCAL_FCONTEXT_ROOTS:
            self.assertFalse(str(VM_INSPECT_RECORD_ROOT).startswith(root))


class TestRotationIsLogrotates(unittest.TestCase):
    """Writing our own was rejected: the failure mode of getting it wrong is a
    full /var on a hypervisor."""

    def _conf(self):
        return (ROOT / "logrotate" / "workloadctl-inspect").read_text()

    def _directives(self):
        """The file with its comments removed. A substring pin over the whole
        text counts the comment that ARGUES against a directive as the
        directive being present — the exact defect a rung-3 review found and
        the reason these assertions read the stanza rather than the file."""
        return "\n".join(
            ln for ln in self._conf().splitlines()
            if not ln.lstrip().startswith("#"))

    def test_it_covers_the_record_path(self):
        self.assertIn(f"{VM_INSPECT_RECORD_ROOT}/*/{VM_INSPECT_RECORD_FILE} {{",
                      self._directives())

    def test_it_does_not_create_the_file(self):
        """`create` takes ONE literal owner and this path is a glob, so it
        cannot produce <name>/requests.log owned by _wl-<name> per match. The
        listener recreates it on the HUP instead."""
        self.assertIn("nocreate", self._directives())
        self.assertNotRegex(self._directives(), r"(?m)^\s*create\b")

    def test_it_hups_rather_than_truncating(self):
        """copytruncate races an in-flight write and would tear a record."""
        self.assertNotIn("copytruncate", self._directives())
        self.assertIn("postrotate", self._directives())
        self.assertIn("-s HUP", self._directives())

    def test_a_failing_postrotate_does_not_abort_the_rotation(self):
        """The glob matches nothing on a host whose inspected workloads are all
        stopped, and a postrotate that fails aborts the rotate."""
        self.assertIn("|| true", self._directives())

    def test_compression_is_delayed(self):
        """The listener holds the current fd until its next write, so an idle
        workload has not acted on the HUP when the compress would run."""
        self.assertIn("delaycompress", self._directives())

    def test_there_is_a_hard_size_bound(self):
        """A chatty agent filling /var takes the hypervisor down, where a
        truncated history only loses evidence — so the cap matters more than
        the count, and `maxsize` rather than `size` keeps the daily run too."""
        self.assertRegex(self._directives(),
                         r"(?m)^\s*maxsize\s+\d+[KMG]\s*$")

    def test_it_ships(self):
        spec = (ROOT / "rpm" / "workloadctl.spec").read_text()
        self.assertIn("logrotate.d/workloadctl-inspect", spec)

    def test_the_numbers_survive_an_upgrade(self):
        """They are defaults to revisit; an operator who has revisited them
        must not lose that to an upgrade."""
        spec = (ROOT / "rpm" / "workloadctl.spec").read_text()
        self.assertIn(
            "%config(noreplace) %{_sysconfdir}/logrotate.d/workloadctl-inspect",
            spec)


class TestTheRecordFile(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(
            self.dir, ignore_errors=True))
        self.path = os.path.join(self.dir, VM_INSPECT_RECORD_FILE)

    def _log(self, path=None, out=None, on_failure=None):
        log = _mod().RequestLog(self.path if path is None else path,
                                out=out, on_failure=on_failure)
        self.addCleanup(log.close)
        return log

    def _lines(self):
        with open(self.path) as f:
            return [json.loads(ln) for ln in f if ln.strip()]

    def test_it_writes_one_json_object_per_line(self):
        log = self._log()
        log.write({"id": "a", "host": "one.example"})
        log.write({"id": "b", "host": "two.example"})
        self.assertEqual([r["host"] for r in self._lines()],
                         ["one.example", "two.example"])

    def test_a_new_file_is_0600(self):
        """The mode IS the access decision here: root and the workload uid,
        nobody else, which is the whole reason the record is not in a
        journal."""
        old = os.umask(0o000)
        self.addCleanup(os.umask, old)
        self._log().write({"id": "a"})
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_a_file_that_already_exists_is_tightened(self):
        """What the fchmod is actually for, and the case that makes it not
        redundant with the open mode: O_CREAT's mode applies to a file being
        CREATED and is ignored for one already there. A record left behind at
        0644 by an operator, by an older build, or by a logrotate `create` line
        someone adds back would otherwise stay world-readable for the life of
        the file while every test of a fresh one passes."""
        with open(self.path, "w"):
            pass
        os.chmod(self.path, 0o644)
        self._log().write({"id": "a"})
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_it_appends_to_an_existing_file(self):
        """A restart must not discard the record the previous instance wrote —
        the socket unit re-triggers the listener freely."""
        with open(self.path, "w") as f:
            f.write('{"id": "old"}\n')
        self._log().write({"id": "new"})
        self.assertEqual([r["id"] for r in self._lines()], ["old", "new"])

    def test_a_reopen_after_a_rotation_writes_to_a_new_file(self):
        log = self._log()
        log.write({"id": "before"})
        rotated = self.path + ".1"
        os.rename(self.path, rotated)
        log.reopen()
        log.write({"id": "after"})
        self.assertEqual([r["id"] for r in self._lines()], ["after"])
        with open(rotated) as f:
            self.assertIn("before", f.read())

    def test_without_a_reopen_the_writes_follow_the_renamed_file(self):
        """The half that makes the HUP necessary rather than decorative: a
        rename does not move an open fd, so a rotation with no signal leaves
        every later record in a file logrotate is about to compress away."""
        log = self._log()
        log.write({"id": "before"})
        rotated = self.path + ".1"
        os.rename(self.path, rotated)
        log.write({"id": "after"})
        self.assertFalse(os.path.exists(self.path))
        with open(rotated) as f:
            self.assertIn("after", f.read())

    def test_reopening_does_no_io(self):
        """reopen() runs in a SIGNAL HANDLER, on whichever thread the kernel
        picks. Doing the close-and-open there deadlocks against a thread
        already inside write(), which is why it only sets a flag."""
        log = self._log()
        log.write({"id": "a"})
        os.rename(self.path, self.path + ".1")
        log.reopen()
        self.assertFalse(os.path.exists(self.path),
                         "reopen() opened the file itself")

    def test_a_sink_that_cannot_be_written_never_raises(self):
        """The standing rule for every diagnostic here, and it binds harder on
        this one: these run on the CONNECTION threads, so an escape takes a
        guest request down per failure."""
        log = self._log(path=os.path.join(self.dir, "nope", "requests.log"))
        log.write({"id": "a"})          # must not raise

    def test_a_failure_is_counted(self):
        """The permanent reading. The warning is emitted once per process, so a
        sink broken since boot is invisible to anyone not tailing at the moment
        it failed — and a reader must know the record is incomplete before
        concluding a guest made no requests."""
        seen = []
        log = self._log(path=os.path.join(self.dir, "nope", "requests.log"),
                        on_failure=lambda: seen.append(1))
        log.write({"id": "a"})
        log.write({"id": "b"})
        self.assertEqual(len(seen), 2)

    def test_only_the_first_failure_is_logged(self):
        """A line per failed record would put exactly the volume the private
        sink exists to keep out of the journal back into it."""
        out = io.StringIO()
        log = self._log(path=os.path.join(self.dir, "nope", "requests.log"),
                        out=out)
        for _ in range(5):
            log.write({"id": "a"})
        self.assertEqual(out.getvalue().count("WARNING"), 1)

    def test_an_unserialisable_field_degrades_to_a_missing_record(self):
        """A later rung adding a field json cannot take must lose the record,
        never the request."""
        seen = []
        log = self._log(on_failure=lambda: seen.append(1))
        log.write({"id": object()})
        log.write({"id": "b"})
        self.assertEqual([r["id"] for r in self._lines()], ["b"])
        self.assertEqual(len(seen), 1)

    def test_no_path_writes_nothing(self):
        """The convention _status_path already uses: the shape tests construct
        a Listener with no workload name and no directory to write into, and a
        diagnostic that made those impossible would decide which tests exist."""
        _mod().RequestLog(None).write({"id": "a"})

    def test_concurrent_writers_produce_whole_lines(self):
        """O_APPEND fixes the offset but does not make a partial write atomic;
        the lock is what keeps one record on one line.

        The write is instrumented to yield MID-RECORD, which is what the
        scheduler is free to do and what a bare `os.write` per fragment would
        expose. Without the instrumentation a single os.write of a small line
        never interleaves in practice and the test passes with no lock at
        all."""
        mod = _mod()
        log = self._log()
        real = os.write

        def torn(fd, data):
            if fd == log._fd and data.endswith(b"\n"):
                real(fd, data[:8])
                time.sleep(0.001)
                return real(fd, data[8:])
            return real(fd, data)

        with unittest.mock.patch.object(mod.os, "write", torn):
            record = {"id": "x", "pad": "y" * 400}
            threads = [threading.Thread(target=log.write, args=(record,))
                       for _ in range(16)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=5)
        self.assertEqual(len(self._lines()), 16)


class TestTheListenerHoldsOne(unittest.TestCase):

    def test_a_failure_shows_up_in_the_status_document(self):
        mod = _mod()
        listener = mod.Listener([], io.StringIO(),
                                record_path="/nonexistent/dir/requests.log")
        self.addCleanup(listener.record.close)
        self.assertEqual(
            listener.counters.snapshot(open_now=0, refused=0)["record_failures"],
            0)
        listener.record.write({"id": "a"})
        self.assertEqual(
            listener.counters.snapshot(open_now=0, refused=0)["record_failures"],
            1)

    def test_the_counter_exists_even_when_nothing_is_written(self):
        """A figure that only accumulates when someone is watching is a figure
        nobody can trust — the reason the listener's other counters are
        unconditional."""
        mod = _mod()
        listener = mod.Listener([], io.StringIO())
        self.assertIn("record_failures",
                      listener.counters.snapshot(open_now=0, refused=0))
