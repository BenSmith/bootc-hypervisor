#!/usr/bin/env python3
"""inspect_rig.py — does a guest told nothing about egress actually land in the
transparent inspector, and does an allowlisted host actually come back?

Run this ON a KVM host with the workloadctl RPM installed. It boots two
throwaway VM workloads and probes them from inside.

WHY TWO GUESTS

The rung's claim has two halves that fail independently, and a single guest
proves neither on its own:

  plain  filtered, no `hosts`   nothing is allowlisted, so every dial to 80/443
                                is DNAT'd onto the listener and DROPPED there.
                                This is the redirect's own claim, isolated from
                                any question about what policy then says.
  hosts  filtered, with `hosts` the allowed path. Its dial to an allowlisted
                                name is forwarded (cleartext) or spliced (TLS)
                                and comes back 200. Nothing else in this rig
                                walks the inspector's upstream leg, so without
                                this arm the forward and splice code paths have
                                never executed under SELinux at all.

The two differ in exactly one config line, which is what makes a failure
attributable.

WHAT THIS RIG LOOKED LIKE BEFORE RUNG 2, AND WHY THAT MATTERS TO A READER

Its second arm was called `proxy` and carried a real tinyproxy. Its job was the
wl_inspect_cg exemption: the proxy's upstream CONNECT leg was tcp dport 443 from
the workload's own uid, so without that element it was redirected into the
listener it was dialling past. Rung 2 deleted the proxy, so that member of the
set is gone and the arm's purpose changed underneath its name. Every "last
green" figure recorded against the older shape describes a different rig; see
tests/manual/README.md.

WHAT ONLY A REAL BOOT CAN SHOW

The inspect socket is ordered after workload-<name>-setup.service, which is
what creates _wl-<name>. The generator computes the listener address from that
user's uid, so a socket that starts before setup fails to resolve the user and
takes the VM down with it. Every unit test passes with that ordering missing.

WHAT THE STATUS-FILE CHECKS ARE FOR

The counters both producers keep are written to a file in the VM's
RuntimeDirectory, and the write is guaranteed never to raise -- a failure is a
journal warning, nothing more. That guarantee is deliberate (a diagnostic must
not take down the thing it is observing) and it means a confined domain with no
grant on that directory produces exactly what a working one produces: a green
suite, a green rig, and no file. The only way to tell those apart is to look for
the file, which is what status_files() does.

The stale-file check is the other half. The run directory is declared
RuntimeDirectoryPreserve=yes so a restart does not yank the qmp and console
sockets out from under the sidecars, and both producers are socket-activated --
so after a restart the file on disk belongs to the PREVIOUS boot and no process
is running to correct it. `written_at` cannot disambiguate: a file from a
previous boot and a live process idle since that moment are the same file. The
arming helpers clear it, and restart_clears_status() is the only check that can
see that wiring, because it needs a real preserved directory surviving a real
restart.

WHAT THE DOMAIN CHECKS ARE FOR

workload-vm-inspect-listener carries a filecon and a type_transition, so it
should be wlinspect_t. workload-vm-resolve carries neither, so it entrypoints
bin_t from init_t with nothing to retype it and runs in PID 1's own domain --
a process terminating guest-supplied DNS packets, unconfined by the boundary
wlinspect_t exists to draw. domains() states the expectation and lets the host
answer; until a wlresolve_t module ships, that check failing IS the finding.
"""

import argparse
import json
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

BASE_IMAGE = Path("/var/lib/broker-rig/base.qcow2")
DNS_ALLOW = "1.1.1.1:53"
ALLOWED_HOST = "example.com"

# The endpoint the retired proxy advertised. Dialled from inside a guest to
# prove nothing answers there any more -- the negative this rung owes, and the
# one that catches a host still carrying a stale nft element or an older
# workloadctl beside this one.
RETIRED_PROXY_ADDR = "192.0.2.1"
RETIRED_PROXY_PORT = 3128

# Spelled out rather than imported from lib/vm.py: a rig that computes both
# sides from one constant cannot notice them drifting apart.
PORT_CLEARTEXT = 8080
PORT_TLS = 8443
ORIG_CLEARTEXT = 80
ORIG_TLS = 443

# A v4 literal that is routable-looking but never dialled for real: the whole
# point is that the packet is translated before it leaves the host, so what is
# on the far side is irrelevant. Using a literal keeps DNS out of the probe.
PROBE_V4 = "93.184.216.34"
PROBE_V6 = "2606:2800:220:1:248:1893:25c8:1946"
# The /48 the v6 probe lives in. A host with no IPv6 uplink has no route to it,
# and a connect() with no route fails at the routing lookup -- BEFORE the nat
# output hook runs, so the redirect never gets the chance to act and the probe
# reports a v6 failure that says nothing about the redirect. The rig installs
# this route on the dummy link for the duration of the v6 probes so that the
# question under test is the redirect and not the host's uplink. It is removed
# again; a host that already routes the prefix is left alone.
PROBE_V6_NET = "2606:2800:220::/48"
INSPECT_LINK = "workload-proxy"

# Spelled out rather than imported from lib/vm.py, for the reason above the
# port constants: a rig that computes both sides from one constant cannot
# notice them drifting apart.
VM_RUN_DIR = "/run/workload-vm"
INSPECT_STATUS = "inspect-status.json"
RESOLVE_STATUS = "resolve-status.json"

# A name the responder will be asked for. It need not resolve to anything real
# -- what is under test is that the query reaches the responder and moves its
# counters, not what the answer says.
RESOLVE_PROBE = "rig-probe.example.net"

AUDIT_LOG = "/var/log/audit/audit.log"

# The listener's STATUS_INTERVAL, spelled out for the usual reason. The file is
# written once before the accept loop and then on this cadence, so a check that
# dials and reads a few seconds later reads the PRE-LOOP write: zeros, freshly
# stamped, indistinguishable from a producer whose counting is broken. The
# first run of these checks failed exactly that way and the defect was the
# rig's.
STATUS_INTERVAL = 30.0
STATUS_SETTLE = STATUS_INTERVAL + 6

# Denials the inspect module documents as deliberately NOT granted: Python
# probing whether stdout is a tty, and two `search` denials that are the domain
# boundary working (it must not read the workload's certs or state tree).
# Excluded by tcontext so that a NEW denial still fails the check -- filtering
# on "any denial" would make this assertion permanently red and therefore
# ignored.
EXPECTED_DENIAL_TCONTEXTS = ("init_t", "cert_t", "container_file_t")

# The domain each producer is expected to run in. wlresolve_t does not exist
# yet; naming it here is the assertion, not a description of the host.
EXPECTED_DOMAINS = {
    "inspect": "wlinspect_t",
    "resolve": "wlresolve_t",
}


@dataclass(frozen=True)
class Arm:
    name: str
    hosts: bool


ARMS = (Arm("wlri-plain", False), Arm("wlri-hosts", True))

results = []


def say(msg):
    print(msg, flush=True)


def record(label, ok, detail):
    results.append((label, ok, detail))
    say(f"  {'PASS' if ok else 'FAIL'}  {label}: {detail}")


def run(argv, check=True, timeout=120):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(f"{argv!r} rc={p.returncode}\n{p.stdout}\n{p.stderr}")
    return p


def guest(name, script, timeout=90):
    """A bash login shell, so profile.d applies as well as PAM's
    /etc/environment -- the two places the guest env is written."""
    return subprocess.run(
        ["workloadctl", "exec", name, "--", "bash", "-lc", script],
        capture_output=True, text=True, timeout=timeout)


def preflight():
    if Path("/proc/self/uid_map").read_text().split()[1] != "0":
        sys.exit("run as root")
    for p in (BASE_IMAGE, Path("/usr/libexec/workloadctl/workload-vm-inspect"),
              Path("/usr/libexec/workloadctl/workload-vm-inspect-listener")):
        if not p.exists():
            sys.exit(f"missing {p}")
    if not Path("/dev/kvm").exists():
        sys.exit("no /dev/kvm")


def toml_for(arm):
    lines = [
        f"# {arm.name} — generated by inspect_rig.py. Throwaway; safe to purge.",
        "[workload]",
        f'name = "{arm.name}"',
        "enabled = false",
        "",
        "[vm]",
        f'local_image = "{BASE_IMAGE}"',
        "vcpus = 1",
        'memory = "768M"',
        'user = "workload"',
        "rollback_keep = 1",
        "",
        "[vm.network]",
        'egress = "filtered"',
    ]
    # Every [vm.network] scalar first: the [[vm.network.allow]] table below
    # closes that section, and TOML will not let it be reopened.
    #
    # Only the second arm gets `hosts`, and it is not a naming accident: it is
    # the single line the two arms differ by, so a difference in what they can
    # reach has one available explanation.
    #
    # Under rung 1 this line did more than that. `hosts` was what vm_uses_proxy()
    # keyed on, so setting it on the plain arm did not give that arm an
    # allowlist -- it gave it a tinyproxy and six proxy variables, and stopped it
    # being the plain arm at all. Measured, by doing it: the forwards returned
    # 200 through the proxy and the inspector never activated. That trap is gone
    # with the predicate, and both arms are inspected either way now.
    if arm.hosts:
        lines.append(f'hosts = ["{ALLOWED_HOST}"]')
    # The table form, not the bare string rung 2 retired. A rig carrying a
    # retired spelling fails at enable with no VM ever booted, which looks
    # nothing like the thing under test.
    lines += [
        "",
        "[[vm.network.allow]]",
        f'address = "{DNS_ALLOW}"',
        'reason  = "the rig\'s guests need a resolver to reach at all"',
    ]
    return "\n".join(lines) + "\n"


def deploy():
    say("== deploying two guests ==")
    for arm in ARMS:
        d = Path("/etc/workloads.d") / arm.name
        d.mkdir(parents=True, exist_ok=True)
        (d / "workload.toml").write_text(toml_for(arm))
    for arm in ARMS:
        say(f"  enabling {arm.name} ...")
        p = run(["workloadctl", "enable", arm.name], check=False, timeout=900)
        if p.returncode != 0:
            say(p.stdout[-3000:])
            say(p.stderr[-3000:])
            sys.exit(f"enable {arm.name} failed")
    say("  waiting for guests to answer ssh (first boot: cloud-init) ...")
    deadline = time.time() + 600
    pending = {a.name for a in ARMS}
    while pending and time.time() < deadline:
        for name in sorted(pending):
            r = guest(name, "echo UP", timeout=60)
            if r.returncode == 0 and "UP" in r.stdout:
                say(f"  {name} up")
                pending.discard(name)
        if pending:
            time.sleep(10)
    if pending:
        for name in sorted(pending):
            subprocess.run(["journalctl", "-u", f"workload-{name}.service",
                            "-n", "40", "--no-pager"])
        sys.exit(f"never became reachable: {sorted(pending)}")


def uid_of(name):
    return int(run(["id", "-u", f"_wl-{name}"]).stdout.strip())


def unit_prop(unit, prop):
    return run(["systemctl", "show", "-p", prop, "--value", unit]).stdout.strip()


def ruleset():
    return json.loads(run(["nft", "-j", "list", "ruleset"]).stdout)["nftables"]


def set_elements(table, name):
    """Every element of one named set/map, as printed strings."""
    for obj in ruleset():
        for kind in ("set", "map"):
            s = obj.get(kind)
            if s and s.get("name") == name and s.get("table") == table:
                return s.get("elem", [])
    return None


def guards():
    """Is the posture under test actually in force?"""
    say("== guards ==")
    for arm in ARMS:
        uid = uid_of(arm.name)
        sock = f"workload-{arm.name}-inspect.socket"

        state = unit_prop(sock, "ActiveState")
        sub = unit_prop(sock, "SubState")
        # SubState is `listening` until the first connection and `running`
        # once the socket's service is up -- both mean the socket is bound.
        # Accepting only `listening` makes the guard depend on whether a
        # probe has already run, which is not what it is asking.
        record(f"{arm.name}: inspect socket bound",
               state == "active" and sub in ("listening", "running"),
               f"{state}/{sub}")

        after = unit_prop(sock, "After")
        record(f"{arm.name}: socket ordered after setup",
               f"workload-{arm.name}-setup.service" in after,
               "present" if f"workload-{arm.name}-setup.service" in after
               else f"After={after}")

        for mapname in ("wl_inspect4", "wl_inspect6"):
            elems = set_elements("workload_proxy", mapname)
            hit = elems is not None and any(
                str(uid) in json.dumps(e) for e in elems)
            record(f"{arm.name}: {mapname} carries uid {uid}",
                   hit, "present" if hit else f"elems={elems}")

    # The redirect exemption. One element per re-originating unit whose service
    # has started -- each arms its own on ExecStartPre -- so the members here are
    # inspectors and responders and nothing else.
    #
    # Under rung 1 there was a third kind of member, the workload's tinyproxy,
    # and it was the one this check existed for: without it the proxy's upstream
    # CONNECT leg was redirected into the listener it was dialling past. That
    # member is gone with the service. The check stays because the exemption it
    # covers did not: an inspector missing from this set dials into itself, and
    # no unit test can see that fail -- it is a cgroup id resolved at add time.
    cg = set_elements("workload_proxy", "wl_inspect_cg")
    n = len(cg or [])
    record("wl_inspect_cg carries at least one re-originator cgroup",
           n >= 1, f"{n} element(s)")


def host_can_route_v6():
    return run(["ip", "-6", "route", "get", PROBE_V6],
               check=False).returncode == 0


def temporary_v6_route():
    """Install the probe route if the host lacks one. Returns a cleanup fn."""
    if host_can_route_v6():
        return lambda: None
    run(["ip", "-6", "route", "add", PROBE_V6_NET, "dev", INSPECT_LINK])
    say(f"  (installed {PROBE_V6_NET} via {INSPECT_LINK} for the v6 probes; "
        f"this host has no IPv6 uplink)")
    return lambda: run(["ip", "-6", "route", "del", PROBE_V6_NET,
                        "dev", INSPECT_LINK], check=False)


def parse_probe(r):
    return (r.stdout or "").strip() + (("  err=" + r.stderr.strip())
                                       if r.stderr.strip() else "")


def journal_since(name, since):
    return run(["journalctl", "-u", f"workload-{name}-inspect.service",
                "--since", since, "--no-pager", "-o", "cat"],
               check=False).stdout


def probes():
    say("== probes ==")
    plain = "wlri-plain"

    r = guest(plain, "env | grep -i -E '^(https?|no)_proxy=' | wc -l")
    record(f"{plain}: guest has no proxy variables",
           r.stdout.strip() == "0", parse_probe(r))

    drop_route = temporary_v6_route()
    for label, host, port, plane in (
            ("v4 cleartext", PROBE_V4, ORIG_CLEARTEXT, "cleartext"),
            ("v4 tls", PROBE_V4, ORIG_TLS, "tls"),
            ("v6 cleartext", f"[{PROBE_V6}]", ORIG_CLEARTEXT, "cleartext"),
            ("v6 tls", f"[{PROBE_V6}]", ORIG_TLS, "tls")):
        mark = time.strftime("%Y-%m-%d %H:%M:%S")
        time.sleep(1.2)
        r = guest(plain, f"curl -sS -m 10 -o /dev/null -w '%{{http_code}}' "
                         f"http://{host}:{port}/ ; echo rc=$?", timeout=40)
        time.sleep(2)
        log = journal_since(plain, mark)
        hit = f"plane={plane}" in log and f":{PORT_CLEARTEXT if plane == 'cleartext' else PORT_TLS}" in log
        record(f"{plain}: {label} dial reaches the listener", hit,
               (log.strip().splitlines() or ["<no journal line>"])[-1]
               + f"  | curl: {parse_probe(r)}")

    drop_route()

    # The listener is socket-activated: the service should be running only
    # because a connection arrived, not because anything started it.
    st = unit_prop(f"workload-{plain}-inspect.service", "ActiveState")
    record(f"{plain}: inspect service activated by the connection",
           st == "active", st)

    # THE NEGATIVE THIS RUNG OWES, and the only place it can be asked honestly:
    # inside a booted guest, on a host running the real thing.
    #
    # An operator upgrading a workload whose image bakes in the old export, or
    # whose custom seed was written against the old docs, gets a client dialling
    # 192.0.2.1:3128. That has to FAIL rather than quietly work, or the two
    # designs run side by side and the transparent one is not the only path out.
    # It is asked of the guest that has no allowlist at all, so a success here
    # could not be confused with policy permitting something.
    r = guest(plain,
              f"timeout 8 bash -c "
              f"'echo > /dev/tcp/{RETIRED_PROXY_ADDR}/{RETIRED_PROXY_PORT}' "
              f"&& echo OPEN || echo CLOSED", timeout=40)
    record(f"{plain}: the retired proxy endpoint answers nothing",
           "CLOSED" in r.stdout, parse_probe(r))

    # A guest that SETS the retired variable reaches nothing through it. Not the
    # same assertion as the one above: that one says the endpoint is dead, this
    # one says a real client configured against it fails rather than falling
    # back to a direct dial that would have worked.
    r = guest(plain,
              f"https_proxy=http://{RETIRED_PROXY_ADDR}:{RETIRED_PROXY_PORT} "
              f"curl -sS -m 15 -o /dev/null -w '%{{http_code}}' "
              f"https://{ALLOWED_HOST}/ ; echo ' rc='$?", timeout=60)
    record(f"{plain}: a guest setting the old https_proxy fails",
           r.returncode != 0 or " rc=0" not in r.stdout, parse_probe(r))

    # THE ALLOWED PATH, and until it was written nothing had ever walked it.
    # Every event this rig produced was a drop -- {"dropped": 5, "forwarded": 0,
    # "spliced": 0} on a 31/31 run under the rung-1 shape -- because the plain
    # arm's allowlist is empty by construction and the old proxy arm's traffic
    # was exempted by wl_inspect_cg before the inspector ever saw it. So the
    # inspector's forward and splice legs had never executed under SELinux, and
    # the module grants those sockets neither `create` nor `connect` nor
    # name_connect on any port.
    #
    # This arm is now the ordinary case rather than an adversarial one: a guest
    # with an allowlist, dialling an allowlisted host, with nothing to bypass
    # because nothing was ever offered to it. That is the change rung 2 made, and
    # these two probes are what say the change is real rather than only intended.
    p = "wlri-hosts"
    r = guest(p, "env | grep -i -E '^(https?|no)_proxy=' | wc -l")
    record(f"{p}: guest has no proxy variables either",
           r.stdout.strip() == "0", parse_probe(r))
    for label, scheme, plane in (("cleartext forward", "http", "cleartext"),
                                 ("tls splice", "https", "tls")):
        mark = time.strftime("%Y-%m-%d %H:%M:%S")
        time.sleep(1.2)
        r = guest(p, f"curl -sS -m 25 -o /dev/null -w '%{{http_code}}' "
                     f"{scheme}://{ALLOWED_HOST}/ ; echo ' rc='$?", timeout=60)
        ok = r.returncode == 0 and r.stdout.strip()[:3] in ("200", "301", "302")
        time.sleep(2)
        log = journal_since(p, mark)
        record(f"{p}: {label} of an allowlisted host", ok,
               parse_probe(r) + "  | "
               + (log.strip().splitlines() or ["<no journal line>"])[-1])


def status_path(name, filename):
    return Path(VM_RUN_DIR) / name / filename


def read_status(name, filename):
    """The parsed status document, or a string saying why there isn't one.

    Returns (doc_or_None, detail). A missing file is the interesting failure
    and gets its own detail string, because on an enforcing host with no
    qemu_var_run_t grant for the producer's domain that is EXACTLY what a
    denied write looks like from here -- the code catches OSError and logs.
    """
    p = status_path(name, filename)
    if not p.exists():
        return None, f"{p} does not exist"
    try:
        return json.loads(p.read_text()), str(p)
    except (OSError, ValueError) as exc:
        return None, f"{p} unreadable/unparseable: {exc}"


def audit_mark():
    """A byte offset into the audit log, or None if it cannot be read.

    An offset rather than a timestamp on purpose: `ausearch -ts boot` is known
    to report zero records on a host whose audit.log plainly contains hundreds,
    so this rig reads the file directly and remembers where it started.
    """
    try:
        return Path(AUDIT_LOG).stat().st_size
    except OSError:
        return None


def audit_denials(mark, needles):
    """Denials logged since `mark` mentioning any of `needles`.

    NOT proof of absence when it comes back empty. systemd's own policy
    dontaudits rules these domains genuinely need -- the inspect module's
    header records one that was found only by running `semodule -DB` and
    retrying, having survived four enforcing iterations invisibly. Treat an
    empty list as "nothing in the audited set", and do the -DB pass by hand
    before concluding a domain is complete.
    """
    if mark is None:
        return []
    try:
        with open(AUDIT_LOG, "rb") as f:
            f.seek(mark)
            blob = f.read().decode("utf-8", "replace")
    except OSError:
        return []
    out = []
    for ln in blob.splitlines():
        if "denied" not in ln or not any(n in ln for n in needles):
            continue
        tctx = ""
        for tok in ln.split():
            if tok.startswith("tcontext="):
                tctx = tok
        if any(f":{t}:" in tctx for t in EXPECTED_DENIAL_TCONTEXTS):
            continue
        out.append(ln)
    return out


def selinux_mode():
    r = run(["getenforce"], check=False)
    return (r.stdout or "").strip() or "unknown"


def unit_label(unit):
    """The SELinux label of a unit's main process, or a reason there isn't one.

    Asked of systemd rather than found by scanning `ps`, because both producers
    are socket-activated: a scan races their lifetime and reports "no such
    process" for a unit that is merely between states, which reads as a policy
    finding and is not. MainPID=0 is reported as the unit's own state, so a
    restart-looping service says so instead of masquerading as a mislabelled
    one.
    """
    pid = unit_prop(unit, "MainPID")
    if not pid or pid == "0":
        return None, (f"no main process (ActiveState="
                      f"{unit_prop(unit, 'ActiveState')}/"
                      f"{unit_prop(unit, 'SubState')})")
    try:
        return Path(f"/proc/{pid}/attr/current").read_text().strip("\x00\n"), None
    except OSError as exc:
        return None, f"pid {pid}: {exc}"


def domains():
    """Which domain does each producer actually run in?

    Only meaningful with both producers running, so this is called after the
    probes have activated them.
    """
    say("== domains ==")
    mode = selinux_mode()
    record("SELinux is enforcing", mode == "Enforcing", mode)
    if mode != "Enforcing":
        # Said plainly rather than skipped silently: every domain check below
        # passes trivially on a permissive host, and a green run there proves
        # nothing about the policy.
        say("  (permissive/disabled: the domain and denial checks below cannot"
            " fail, and a green result here is not evidence)")

    plain = "wlri-plain"
    for kind, expected in sorted(EXPECTED_DOMAINS.items()):
        unit = f"workload-{plain}-{kind}.service"
        label, why = unit_label(unit)
        if label is None:
            record(f"{unit}: has a running main process", False, why)
            continue
        # The label is user:role:type:level; the type is what the module names.
        parts = label.split(":")
        dom = parts[2] if len(parts) > 2 else label
        record(f"{unit}: runs as {expected}", dom == expected,
               f"{label} (type={dom})")


def status_files(mark):
    """Do the counters reach disk, do they carry real figures, and do they move?

    Returns the inspector's pre-restart dispositions, which restart_clears_status
    needs in order to recognise the previous instance's numbers.
    """
    say("== status files ==")
    plain = "wlri-plain"

    # A DNS query, to give the responder something to count. The name need not
    # resolve; reaching the responder is the whole of the requirement.
    guest(plain, f"getent hosts {RESOLVE_PROBE} >/dev/null 2>&1 || true",
          timeout=40)
    # And a dial the inspector must refuse, so `dropped` has something in it.
    guest(plain, f"curl -sS -m 10 -o /dev/null http://{PROBE_V4}:{ORIG_CLEARTEXT}/"
                 " || true", timeout=40)

    # The wait is the point, not politeness: anything shorter reads the
    # pre-loop write and reports zeros as a counting failure.
    say(f"  waiting {STATUS_SETTLE:.0f}s for a status tick ...")
    time.sleep(STATUS_SETTLE)

    dispositions = None
    for filename, producer in ((INSPECT_STATUS, "inspector"),
                               (RESOLVE_STATUS, "responder")):
        doc, detail = read_status(plain, filename)
        record(f"{plain}: {producer} wrote its status file",
               doc is not None, detail)
        if doc is None:
            continue
        stamp = doc.get("written_at")
        # Plausible, not merely present: `0` or a string would be a
        # serialisation bug that a presence check waves through.
        fresh = (isinstance(stamp, (int, float))
                 and abs(time.time() - stamp) < 3600)
        record(f"{plain}: {producer} status is stamped and fresh", fresh,
               f"written_at={stamp!r}")

    doc, detail = read_status(plain, INSPECT_STATUS)
    if doc is not None:
        dispositions = doc.get("dispositions") or {}
        # The refused dial above must appear. A file full of zeros after real
        # traffic is a producer writing its startup snapshot and nothing more,
        # which is what a broken counter and a broken flush both look like.
        record(f"{plain}: inspector counted the refused dial",
               dispositions.get("dropped", 0) > 0, json.dumps(dispositions))
        reasons = doc.get("drop_reasons") or {}
        # And the reason map has to reconcile with it -- the two are written
        # from one snapshot under one lock, so a disagreement is a real defect
        # and not a sampling artifact.
        record(f"{plain}: drop reasons reconcile with the drop total",
               sum(reasons.values()) == dispositions.get("dropped", 0),
               f"sum={sum(reasons.values())} dropped="
               f"{dispositions.get('dropped')} {reasons}")

    denials = audit_denials(mark, ("wlinspect_t", "wlresolve_t"))
    # Named separately from the file checks: a missing file WITH denials is a
    # policy gap, a missing file without them is something else, and the two
    # want different next steps.
    record("no unexpected denials for the producer domains", not denials,
           "none beyond the documented residuals" if not denials
           else f"{len(denials)}: {denials[0][:200]}")
    return dispositions


def restart_clears_status(before):
    """Can the previous instance's figures survive into a new instance?

    NOT "is the file absent after a restart". The inspect service is
    PartOf=workload-<name>.service, so a VM restart restarts it too -- it comes
    straight back up and writes its pre-loop snapshot, with no dial needed and
    no ordering guarantee against the arming helper that clears the file. A
    file is therefore expected to be there, and demanding absence fails a
    correct system. What must NOT survive is the previous instance's COUNTS,
    which is the whole of what clear_status is for and is unambiguous: a fresh
    instance reads zero, and the pre-restart snapshot did not.
    """
    say("== stale status across a restart ==")
    plain = "wlri-plain"

    if not before or not before.get("dropped"):
        record(f"{plain}: pre-restart counters are non-zero", False,
               f"nothing to distinguish a stale file from a fresh one: {before}")
        return
    record(f"{plain}: pre-restart counters are non-zero", True, json.dumps(before))

    run(["workloadctl", "restart", plain], timeout=300)
    # No dial, no query, no exec: an exec would give a fresh instance real
    # traffic to count and blur the distinction being drawn.
    time.sleep(5)

    for filename, producer in ((INSPECT_STATUS, "inspector"),
                               (RESOLVE_STATUS, "responder")):
        p = status_path(plain, filename)
        if not p.exists():
            record(f"{plain}: {producer} shows no previous-instance counters",
                   True, "file absent")
            continue
        try:
            doc = json.loads(p.read_text())
        except (OSError, ValueError) as exc:
            record(f"{plain}: {producer} shows no previous-instance counters",
                   False, f"unreadable: {exc}")
            continue
        counts = doc.get("dispositions") or doc.get("queries") or {}
        carried = [k for k, v in counts.items() if isinstance(v, int) and v]
        record(f"{plain}: {producer} shows no previous-instance counters",
               not carried,
               "all zero" if not carried
               else f"CARRIED {carried} from before the restart: {counts}")

    # And the directory is genuinely preserved -- otherwise "all zero" could be
    # systemd having wiped the tree, which would prove nothing about the
    # arming helpers.
    d = Path(VM_RUN_DIR) / plain
    others = sorted(x.name for x in d.iterdir()) if d.is_dir() else []
    record(f"{plain}: the run directory survived the restart",
           bool(others), f"contains {others}")


def teardown():
    say("== teardown ==")
    for arm in ARMS:
        subprocess.run(["workloadctl", "disable", arm.name, "--purge"],
                       capture_output=True, text=True, timeout=300)
        shutil.rmtree(Path("/etc/workloads.d") / arm.name, ignore_errors=True)
        say(f"  purged {arm.name}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true",
                    help="leave the guests running for inspection")
    ap.add_argument("--no-deploy", action="store_true",
                    help="reuse guests left by an earlier --keep run")
    args = ap.parse_args()

    preflight()
    try:
        if not args.no_deploy:
            deploy()
        guards()
        mark = audit_mark()
        probes()
        # After the probes, so both producers have been socket-activated and
        # have something to report. Before the restart, which clears them.
        domains()
        before = status_files(mark)
        restart_clears_status(before)
    finally:
        if not args.keep:
            teardown()

    bad = [r for r in results if not r[1]]
    say(f"\n{len(results) - len(bad)}/{len(results)} passed")
    for label, _, detail in bad:
        say(f"  FAIL  {label}: {detail}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
