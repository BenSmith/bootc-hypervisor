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
import hashlib
import json
import shutil
import stat
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

# The record's home, its filename, its join field and the one reason the plain
# arm must produce. Spelled out rather than imported from lib/vm.py for the
# reason the run dir and the ports are: a rig that computes both sides from one
# constant cannot notice them drifting apart.
RECORD_ROOT = "/var/log/workloadctl/egress"
RECORD_FILE = "requests.log"
LOG_ID_FIELD = "id"
NOT_ALLOWLISTED = "not allowlisted"

# A uid that is emphatically not root and not any workload's. `nobody` is 65534
# on every Fedora host, and the assertion it serves is that the record's 0600
# under a 0700 under a 0700 is real rather than argued.
NOBODY_UID = 65534
INSPECT_POLICY = "inspect.json"
DIGEST_KEY = "policy_digest"
# /var/lib/workloads, NOT /etc/workloads.d: the bundle directory holds the
# TOML, the state subtree holds the PKI. A rig pointed at the config root
# finds no certificate and reports the fingerprint check as unarmed.
WORKLOADS_STATE = "/var/lib/workloads"
CA_REL = "state/ca/egress-ca.crt"

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

# --quiet: what a run prints when nothing is wrong.
#
# A green run is 57 PASS lines, several carrying a whole JSON document, and the
# reason to want that smaller is not tidiness -- this output is read back
# through an ssh pipe by a reader that pays for every byte, and the passes tell
# that reader nothing the tally does not.
#
# TWO THINGS ARE DELIBERATELY NOT SUPPRESSED, because a quiet flag that hides a
# failure is worse than no flag at all:
#
#   * every FAIL line verbatim, detail and all. That detail is the entire
#     product of a hardware run. Three separate times in this tree a rig bug
#     read as a product bug, and each was told apart by reading the failure's
#     own printed evidence -- the uid the assertion said was missing was
#     sitting in the detail it printed.
#   * the section header the failure sits under, emitted lazily just before the
#     first FAIL inside it, and again if an exception escapes. Without it a
#     quiet run's traceback arrives with no indication of which phase produced
#     it, which is the one thing the chatter was buying.
QUIET = False
_section = None
_section_shown = False


def say(msg):
    """Progress and section chatter -- silent under --quiet.

    Section headers are still TRACKED when silent: `_show_section` prints the
    latest one if a failure or an exception makes locality matter.
    """
    global _section, _section_shown
    if msg.startswith("=="):
        _section, _section_shown = msg, False
    if not QUIET:
        print(msg, flush=True)


def _show_section():
    """Print the current section header once, on the first FAIL beneath it."""
    global _section_shown
    if QUIET and _section and not _section_shown:
        print(_section, flush=True)
        _section_shown = True


def record(label, ok, detail):
    results.append((label, ok, detail))
    if not ok:
        _show_section()
    if ok and QUIET:
        return
    print(f"  {'PASS' if ok else 'FAIL'}  {label}: {detail}", flush=True)


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

def exemptions():
    """Both cgroup exemptions, named per arm, AFTER the probes.

    WHY THIS IS NOT IN guards()

    It was, through rung 1, and it passed there -- because the member it was
    really watching was the workload's tinyproxy, an ordinary long-running
    service that came up with the VM. By the time guards() ran, its element was
    installed.

    The inspector is not that. It is socket-activated, and the elements are
    armed by the SERVICE's ExecStartPre, not the socket's -- a cgroup element
    resolves to an id at add time, and at the moment the socket is bound the
    service has no cgroup for one to resolve to. So before the first guest dial
    the set is legitimately empty, and a guard that reads it there reports a
    missing exemption on a host where nothing is missing. That is the shape of
    failure this rig exists to avoid, arriving from the rig's own side.

    WHY BOTH SETS, AND WHY BY PATH

    The invariant is both-or-neither. wl_inspect_cg (nat) keeps the inspector's
    upstream dial from being redirected into the listener it IS; wl_egress_cg
    (filter) keeps that same dial from hitting the default-deny drop. One
    without the other is an inspector that loops into itself or reaches
    nothing, and each failure looks like the other from the guest.

    Matched on the exact cgroup path rather than counted, because a non-empty
    set proves nothing about WHICH unit is in it: with two arms running, one
    arm's element satisfies a count of >= 1 while the other dials into itself.
    """
    say("== cgroup exemptions ==")
    nat = set_elements("workload_proxy", "wl_inspect_cg")
    flt = set_elements("workload_filter", "wl_egress_cg")
    for arm in ARMS:
        path = f"workloads.slice/workload-{arm.name}-inspect.service"
        for label, elems in (("wl_inspect_cg (redirect)", nat),
                             ("wl_egress_cg (default-deny)", flt)):
            hit = elems is not None and any(
                path in json.dumps(e) for e in elems)
            record(f"{arm.name}: inspector exempted in {label}",
                   hit, "present" if hit else f"elems={elems}")


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


def egress(name, *flags, as_uid=None, timeout=60):
    """`workloadctl egress`, optionally as somebody who should not be able to."""
    argv = ["workloadctl", "egress", name, *flags]
    if as_uid is not None:
        argv = ["setpriv", "--reuid", str(as_uid), "--regid", str(as_uid),
                "--clear-groups"] + argv
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)


def records():
    """THE SEAM T1 AND T2 ONLY HAVE TOGETHER — rung 5.

    A live guest makes a request, and an operator reads it back. Nothing in the
    unit suite reaches this: the record's writer is exercised against a fake
    listener and its reader against a fixture directory, and both are green on
    a host where the file is never created because the unit's LogsDirectory=
    is wrong, or its label is, or the listener's write is denied and swallowed
    by the OSError handler that must never let a diagnostic kill a request.

    THE REQUEST UNDER TEST IS AN ALLOWED ONE, deliberately. Refusals already
    log to the journal today, so a record containing only refusals would be a
    green reading that means nothing about whether the allowed path records at
    all — and the allowed path is the one the private sink exists for, since a
    denied request never reached anything.

    The plain arm supplies the other half: `reason` is now the ONLY place a
    not-allowlisted denial is distinguishable from a not-permitted one, because
    the guest-facing refusal body was made generic and names neither.
    """
    say("== the record ==")
    allowed, plain = "wlri-hosts", "wlri-plain"
    marker = f"/rig-{int(time.time())}"

    d = Path(RECORD_ROOT) / allowed
    f = d / RECORD_FILE

    mark = time.strftime("%Y-%m-%d %H:%M:%S")
    time.sleep(1.2)
    r = guest(allowed, f"curl -sS -m 25 -o /dev/null -w '%{{http_code}}' "
                       f"http://{ALLOWED_HOST}{marker} ; echo ' rc='$?",
              timeout=60)
    time.sleep(2)

    # THE ACL, on hardware. The mode argument in the plan is only an argument
    # until a real listener has created the file as its own uid under a
    # LogsDirectory= systemd made.
    try:
        dst, fst = d.stat(), f.stat()
    except OSError as exc:
        record(f"{allowed}: the record file exists", False, str(exc))
        record(f"{allowed}: the record's modes are 0700/0600", False, "no file")
        record(f"{allowed}: an allowed request is recorded", False, "no file")
        record(f"{allowed}: the record's id joins to a journal line", False,
               "no file")
        record(f"{allowed}: --id selects that connection alone", False, "no file")
        record(f"{plain}: a denial's reason names which denial it was", False,
               "no file")
        record(f"{allowed}: a non-root read is refused with a sentence", False,
               "no file")
        record("egress: an unknown --reason is an error, not an empty report",
               False, "no file")
        return

    uid = uid_of(allowed)
    record(f"{allowed}: the record file exists", True, str(f))
    record(f"{allowed}: the record's modes are 0700/0600",
           stat.S_IMODE(dst.st_mode) == 0o700
           and stat.S_IMODE(fst.st_mode) == 0o600
           and dst.st_uid == uid and fst.st_uid == uid,
           f"dir {oct(stat.S_IMODE(dst.st_mode))} uid {dst.st_uid}, "
           f"file {oct(stat.S_IMODE(fst.st_mode))} uid {fst.st_uid}, "
           f"workload uid {uid}")

    # Read it back the way an operator would, through the shipped CLI.
    got = egress(allowed, "--json", "--lines", "0")
    try:
        doc = json.loads(got.stdout)
    except ValueError:
        doc = None
    hit = None
    for rec in (doc or {}).get("records", []):
        if rec.get("path") == marker and rec.get("decision") == "forward":
            hit = rec
            break
    record(f"{allowed}: an allowed request is recorded", hit is not None,
           (f"{hit}" if hit else
            f"curl: {parse_probe(r)} | egress rc={got.returncode} "
            f"{(got.stderr or got.stdout).strip()[:300]}"))

    if hit:
        # THE JOIN, in the direction an operator walks it: the id in the record
        # is the id on the journal line for the same connection. Asserted
        # against real output on both sides rather than against the constant,
        # because the constant agreeing with itself is what the unit pin
        # already covers.
        cid = hit.get(LOG_ID_FIELD)
        log = journal_since(allowed, mark)
        record(f"{allowed}: the record's id joins to a journal line",
               bool(cid) and f"{LOG_ID_FIELD}={cid}" in log,
               f"{LOG_ID_FIELD}={cid} | "
               + (log.strip().splitlines() or ["<no journal line>"])[-1])

        sel = egress(allowed, "--json", "--lines", "0",
                     "--id", f"{LOG_ID_FIELD}={cid}")
        try:
            picked = json.loads(sel.stdout).get("records", [])
        except ValueError:
            picked = []
        record(f"{allowed}: --id selects that connection alone",
               bool(picked) and all(p.get(LOG_ID_FIELD) == cid for p in picked),
               f"{len(picked)} record(s), ids "
               f"{sorted({p.get(LOG_ID_FIELD) for p in picked})}")
    else:
        record(f"{allowed}: the record's id joins to a journal line", False,
               "no allowed record to join from")
        record(f"{allowed}: --id selects that connection alone", False,
               "no allowed record to select")

    # The plain arm dialled hosts nothing allowlists, so its record must say
    # WHICH refusal that was. The guest was told nothing.
    denied = egress(plain, "--json", "--lines", "0", "--decision", "drop")
    try:
        reasons = {x.get("reason")
                   for x in json.loads(denied.stdout).get("records", [])}
    except ValueError:
        reasons = set()
    record(f"{plain}: a denial's reason names which denial it was",
           NOT_ALLOWLISTED in reasons,
           f"egress rc={denied.returncode}, reasons seen: "
           f"{sorted(x for x in reasons if x)}")

    # THE ACL AGAIN, from the other side: the mode bits above are a claim about
    # what a non-root reader gets, and this is that reader.
    nobody = egress(allowed, as_uid=NOBODY_UID)
    record(f"{allowed}: a non-root read is refused with a sentence",
           nobody.returncode != 0
           and "root" in (nobody.stderr or "") and "Traceback" not in
           (nobody.stderr or ""),
           f"rc={nobody.returncode} {(nobody.stderr or '').strip()[:200]}")

    # A filter value that matches nothing renders identically to a guest that
    # never hit that refusal. Asserted against the shipped CLI, not the module.
    bad = egress(allowed, "--reason", "not allowed")
    record("egress: an unknown --reason is an error, not an empty report",
           bad.returncode != 0 and NOT_ALLOWLISTED in (bad.stderr or ""),
           f"rc={bad.returncode} {(bad.stderr or '').strip()[:200]}")


def diagnose(name, timeout=120):
    """`workloadctl diagnose <name>` as an operator runs it."""
    return subprocess.run(["workloadctl", "diagnose", name],
                          capture_output=True, text=True, timeout=timeout)


def _concat_of(elem):
    """The concat tuple of one nft set element, whatever shape it arrived in.

    TWO SHAPES, and the difference is not cosmetic. A set declared with a
    per-element `counter` renders each element WRAPPED --
    {"elem": {"val": {"concat": [...]}, "counter": {...}}} -- while a plain set
    renders the bare {"concat": [...]}. wl_inspect_self/self6 carry counters
    (deliberately: see workload-filter.nft) and wl_inspect_dst/dst6 do not, so
    a reader that knows only the bare shape passes on the maps and fails on the
    sets, reporting a set that is armed as unarmed. Measured that way on a KVM
    host 2026-08-31: the elements printed in the failure detail plainly
    contained the uid the assertion said was missing.

    Returns None for anything that is neither shape, so an nft output this does
    not understand reads as "no match" rather than raising inside the loop.
    """
    if not isinstance(elem, dict):
        return None
    if isinstance(elem.get("elem"), dict):
        val = elem["elem"].get("val")
        elem = val if isinstance(val, dict) else {}
    concat = elem.get("concat")
    return concat if isinstance(concat, list) and concat else None


def staleness():
    """THE SEAMS T4, T5 AND T7 ONLY HAVE ON A LIVE HOST — rung 5.

    All three are cross-process comparisons between a value a RUNNING process
    holds and a value on disk, and every one of them is green in the unit suite
    against injected observations. What the unit suite cannot reach:

      T4  the digest has to survive the trip. The listener computes it at its
          own start and writes it into a status file in a RuntimeDirectory a
          confined domain may not be able to write -- and that write is
          guaranteed never to raise, so a denial produces a missing key, which
          the reader is REQUIRED to treat as silence. Absent this check, a
          policy comparison that never runs and a policy comparison that always
          agrees are the same green line.

      T5  the four filter-table sets have to be readable by name from the CLI's
          own domain. A drifted name, a set that moved tables, or an `nft`
          the CLI may not exec all produce "unreadable", which is also silence.

      T7  the fingerprint the minter reports has to equal the one computed off
          the file. Both come from vm_mint.pem_fingerprint, but only here do
          they come from two different PROCESSES reading two different copies
          -- the listener's remembered value against a fresh read.

    Each destructive step is undone before the next assertion, and the undo is
    asserted rather than assumed: a rig that breaks the product and dies leaves
    the next run measuring the break. See tests/manual/README.md.
    """
    say("== staleness (T4/T5/T7) ==")
    name = "wlri-hosts"
    uid = uid_of(name)
    policy = str(Path(VM_RUN_DIR) / name / INSPECT_POLICY)

    # --- T4: the digest reaches the status file, and it is the RIGHT one ---
    doc, detail = read_status(name, INSPECT_STATUS)
    running = (doc or {}).get(DIGEST_KEY)
    record("the listener reports a policy digest",
           bool(running), f"{DIGEST_KEY}={running!r} ({detail})")

    try:
        on_disk = hashlib.sha256(Path(policy).read_bytes()).hexdigest()
    except OSError as exc:
        on_disk = None
        say(f"  could not read {policy}: {exc}")
    record("the reported digest is of the document on disk",
           bool(running) and running == on_disk,
           f"running={running} disk={on_disk}")

    # A healthy workload must not be reported stale. Asserted before the
    # break, because a check that fires on everything would "pass" the break
    # below for the wrong reason.
    clean = diagnose(name)
    record("a current listener is not reported stale",
           "DIFFERENT policy" not in clean.stdout,
           clean.stdout[-400:] if "DIFFERENT policy" in clean.stdout else "quiet")

    # --- T4: make the disk copy differ, and require diagnose to say so ---
    saved = None
    try:
        saved = Path(policy).read_bytes()
        doc_on_disk = json.loads(saved)
        doc_on_disk["hosts"] = list(doc_on_disk.get("hosts") or []) + [
            "rig-added.invalid"]
        Path(policy).write_text(json.dumps(doc_on_disk, indent=2,
                                          sort_keys=True) + "\n")
        stale = diagnose(name)
        record("an edited document is reported as a stale listener",
               "DIFFERENT policy" in stale.stdout, stale.stdout[-400:])
        record("the stale remedy names the VM, not the socket",
               "DIFFERENT policy" in stale.stdout
               and f"restart workload-{name}.service" in stale.stdout,
               stale.stdout[-400:])
    except (OSError, ValueError) as exc:
        record("an edited document is reported as a stale listener",
               False, f"could not rewrite {policy}: {exc}")
    finally:
        if saved is not None:
            # NOT a best-effort restore: leaving the document edited would make
            # the next run of this rig measure the edit, and the arm would look
            # broken in a way that reads exactly like the product being broken.
            Path(policy).write_bytes(saved)
    after = diagnose(name)
    record("the document was restored",
           "DIFFERENT policy" not in after.stdout, after.stdout[-400:])

    # --- T5: the four filter-table sets, read by the names diagnose uses ---
    for set_name in ("wl_inspect_dst", "wl_inspect_dst6",
                     "wl_inspect_self", "wl_inspect_self6"):
        # "workload_filter", not "inet workload_filter": set_elements matches
        # nft's own `table` field, which carries the name alone. The family is
        # a sibling key. Getting this wrong reads as an unarmed set, which is
        # indistinguishable from the failure under test.
        elems = set_elements("workload_filter", set_name)
        # On the FIRST component, not a substring of the rendered element: uid
        # 10001 is a substring of 100010 and of the port list, so the loose
        # test guards() uses for the maps would pass here on a set belonging to
        # a different workload entirely.
        armed = elems is not None and any(
            str(c[0]) == str(uid) for c in map(_concat_of, elems) if c)
        record(f"{set_name} carries uid {uid}", armed,
               f"elements={elems!r}"[:200])

    # --- T7: the minter's CA fingerprint equals a fresh read of the file ---
    ca = ((doc or {}).get("mint") or {}).get("ca") or {}
    reported = ca.get("sha256") if isinstance(ca, dict) else None
    cert = Path(WORKLOADS_STATE) / name / CA_REL
    fresh = None
    if cert.exists():
        out = subprocess.run(
            ["openssl", "x509", "-in", str(cert), "-noout",
             "-fingerprint", "-sha256"],
            capture_output=True, text=True, timeout=30)
        if out.returncode == 0:
            fresh = out.stdout.strip().partition("=")[2].strip()
    record("the minter's CA fingerprint matches the file on disk",
           bool(reported) and reported == fresh,
           f"reported={reported} openssl={fresh} cert={cert}")
    record("the CA report carries an expiry",
           isinstance(ca, dict) and isinstance(
               ca.get("not_after"), (int, float)),
           f"ca={ca!r}")


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

    That pass has now been done for wlinspect_t and wlresolve_t, on a KVM host
    2026-09-01: `semodule -DB`, a full green rig run (57/57), harvest, then
    `semodule -B`. It raised the run's denial count from 43 to 60 and added
    NOTHING in either producer domain -- the whole delta was svirt_t and
    init_t, and all of it the exec-transition triple (siginh, rlimitinh,
    noatsecure) plus inherited-fd read/write, which upstream policy dontaudits
    because a domain transition legitimately produces them. So the two domains
    this rig covers are complete as of that date. It does not generalise: a
    later grant, or a new domain, re-owes the pass.
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
    ap.add_argument("--quiet", action="store_true",
                    help="print only failures and the tally")
    args = ap.parse_args()
    global QUIET
    QUIET = args.quiet

    preflight()
    try:
        if not args.no_deploy:
            deploy()
        guards()
        mark = audit_mark()
        probes()
        # After the probes, so there is traffic to have recorded, and before
        # the restart, which is where the counters (and only the counters) are
        # cleared -- the record file deliberately outlives a restart, which is
        # why its ids are minted rather than counted.
        records()
        # After the probes, so both producers have been socket-activated and
        # have something to report. Before the restart, which clears them.
        exemptions()
        # After exemptions, so the minter has certainly run and the CA report
        # exists; before domains(), because the deliberate policy edit below is
        # undone in a finally and must not be left standing by a later failure.
        staleness()
        domains()
        before = status_files(mark)
        restart_clears_status(before)
    except BaseException:
        # Under --quiet the headers were never printed, so name the phase the
        # traceback below belongs to. BaseException, not Exception: a
        # KeyboardInterrupt on a run this long is a normal way to stop it, and
        # knowing where it was interrupted is worth the same one line.
        _show_section()
        raise
    finally:
        if not args.keep:
            teardown()

    bad = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(bad)}/{len(results)} passed", flush=True)
    # The replay is for a full run, where 57 PASS lines separate the failures
    # from each other and from the tally. Under --quiet nothing was printed
    # between them but other FAIL lines, so it would be a verbatim second copy
    # of what is already on the screen.
    if not QUIET:
        for label, _, detail in bad:
            print(f"  FAIL  {label}: {detail}", flush=True)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
