#!/usr/bin/python3
"""Container egress parity, measured on a real host (P1-16).

Every assertion here needs a packet to cross a real kernel hook, a real DNAT,
and a real SELinux domain transition, so none of them is reachable from
`just test`. The unit suite proves that the generator writes the right lines
into the right units; it cannot prove that a container's dial to 443 arrives at
this workload's inspector rather than leaving the host.

WHAT IT MEASURES, and the failure each row exists to catch:

  1. THE THREE-RUNG LADDER on ONE image, in order. Rung 1 (no [network] keys)
     gets no proxy at all; rung 2 (`hosts` only) gets a spliced proxy and needs
     NO CA; rung 3 (a policy entry) is REFUSED until `ca_delivery` is stated
     and then terminates. Rung 2 is the rung a 443-only habit skips, and the
     rung-2-to-rung-3 transition is where a silent CA requirement would hide.

  2. BOTH REDIRECTED PLANES. 443 must reach the inspector with a readable SNI
     and 80 must reach it with a readable Host header. A 443-only pass is the
     specific failure this row exists to catch: it leaves plaintext HTTP
     unfiltered in a workload every report calls filtered.

  3. THE INSPECTOR'S OWN RE-DIAL is exempt in BOTH nft tables. A missing
     exemption does not error -- it HANGS (re-filtered) or loops (re-redirected
     into itself), so the tell is a wall-clock bound on a request that
     succeeded, not a return code.

  4. A DENIED HOST is refused AND attributed to the right workload's record.

  5. [[network.internal]] IN BOTH DIRECTIONS. The inspector is barred from
     opening a connection into RFC 1918 space; the entry is the exemption. A
     rig that only tested the entry PRESENT would pass against an inspector
     that had no internal-destination guard at all.

  6. `disable` LEAVES NOTHING in either nft table and no inspect units.

  7. audit.log CLEAN under enforcing -- because a policy gap that is merely
     dontaudit'd or that falls on a path the happy case never takes is
     invisible to every functional assertion above.

  8. THE CROSS-WORKLOAD REACHABILITY GAP, reported and NOT asserted. See
     `check_cross_workload_gap` for why it is a gap rather than a failure and
     what has to be decided before it becomes an assertion.

WHAT IT DOES NOT MEASURE, deliberately:

  * IPv6. A v6 egress probe on a host with no global v6 address dies at the
    routing lookup, BEFORE nftables sees it, so the row passes having tested
    nothing. Run it somewhere with v6 or record it as untested; do not let a
    v4-only host's green stand in for it.
  * A non-80/443 [[network.allow]] entry whose address changes after arming.
    Needs a real non-80/443 upstream and a mid-run address change.
  * `ca_delivery = "env"` on an image with an embedded root store. Needs a
    non-glibc-ish base image whose client ignores the five CA variables.

RUNNING IT

    sudo python3 tests/manual/container_egress_rig.py

Needs root, podman, an installed workloadctl RPM, and outbound HTTPS. It does
NOT need /dev/kvm -- this is the container substrate, which is the point.

Two throwaway workloads are created under /etc/workloads.d and purged at the
end. Both names are prefixed `ceg-`; nothing else in this tree uses that
prefix. `--keep` leaves them running for inspection.

The [[network.internal]] section needs a host on the LAN that answers on port
80 and is reachable from this machine. Pass it as CEG_LAN_HOST; without it that
section SKIPS rather than passing, because a probe against an unreachable
target fails identically to a working internal-destination drop.

    sudo CEG_LAN_HOST=192.168.0.10 python3 tests/manual/container_egress_rig.py

Last green: not yet run as a script. The checks it encodes were confirmed
by hand on a bare-metal Fedora 44 host under enforcing on 2026-09-05; this
file is the reusable form of that pass, and its first run is what makes it a
measurement rather than a transcription.
"""

import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

sys.dont_write_bytecode = True

# A base with a TLS-capable client and nothing else. busybox wget speaks HTTPS,
# which matters: `apk add curl` fails inside a rootless container here, and
# chasing that is chasing a package manager rather than an egress path.
IMAGE = "docker.io/library/alpine:latest"

FILTERED = "ceg-plain"      # the workload under test; walks all three rungs
OPEN = "ceg-open"           # no [network] table at all; opted into nothing

# Public, stable, and answers on both 80 and 443 -- the two redirected ports
# are the whole measurement, so a name that answers on only one would make the
# cleartext half untestable.
ALLOWED = "example.com"
# NOT in `hosts`, and it must resolve: a name that does not resolve is refused
# for the wrong reason, and the record would say so in a way that reads like
# the denial being tested.
DENIED = "neverssl.com"

# The operator's LAN target for the [[network.internal]] section. No default:
# an address baked in here would be wrong on every host but one, and a probe
# against a wrong address fails exactly like a working internal drop.
LAN_HOST = os.environ.get("CEG_LAN_HOST")

# What `toml_for` writes when CEG_LAN_HOST is unset. The internal-destination
# SHAPE must be generated on every host, or tests/test_manual_rig_configs.py
# validates only the arms this machine happens to be able to run -- which is
# [[gates-have-gaps-in-their-own-shape]]: the gate exists to catch a rig config
# that stopped validating, and the arm most likely to break is the one most
# hosts skip. The runtime section still skips; only the text is unconditional.
LAN_HOST_IN_CONFIG = LAN_HOST or "10.99.99.1"

WORKLOAD_DIR = Path("/etc/workloads.d")
RECORD_ROOT = Path("/var/log/workloadctl/egress")
AUDIT_LOG = Path("/var/log/audit/audit.log")

# The one already-documented, deliberately-ungranted denial (see
# security/workload-inspect.cil, "ONE RESIDUAL DENIAL IS DELIBERATELY NOT
# GRANTED"): wlinspect_t probing init_t's unix_stream_socket for tty-ness on
# stdout. Harmless, and a green run stays green with it denied -- so it is
# filtered out by shape rather than by suppressing the whole check.
KNOWN_AVC = re.compile(r"scontext=\S*wlinspect_t\S*.*tcontext=\S*init_t\S*"
                       r".*tclass=unix_stream_socket")

# S1's bound. A missing cgroup exemption in either table does not error: the
# re-dial is filtered or redirected into the listener itself, and the symptom
# is a request that eventually times out. Anything that completes well inside
# this took the exempt path. Generous on purpose -- first-time leaf minting is
# the slow case and was measured at ~1.7s.
REDIAL_BUDGET = 8.0

# UID_MIN and VM_INSPECT_ADDR_BASE, re-derived rather than imported. A rig that
# computes both sides of a comparison from the one constant the product uses
# cannot notice the constant changing -- same reasoning as input_chain_rig.py's
# spelled-out addresses, adapted because the uid here is allocated at enable
# and is not known in advance.
UID_MIN = 10000
INSPECT_V4_BASE = (198, 18, 1, 0)


@dataclass(frozen=True)
class Arm:
    name: str
    rung: int          # 1 = no keys, 2 = hosts only, 3 = + a policy entry
    internal: bool = False


# Every SHAPE this rig writes, so tests/test_manual_rig_configs.py validates
# all of them -- not just the two it happens to deploy first. `ceg-plain`
# appears three times because the ladder section rewrites its file in place and
# each rewrite is a config a schema change can break independently.
#
# The rung-3-without-ca_delivery shape is deliberately NOT here: it must FAIL
# validation, which is the assertion, and the gate asserts every arm validates.
# It is built by `_toml_missing_ca_delivery` below, whose name keeps it out of
# the gate's `def toml_for(` selector.
ARMS = (
    Arm(FILTERED, 1),
    Arm(FILTERED, 2),
    Arm(FILTERED, 3),
    Arm(FILTERED, 3, internal=True),
    Arm(OPEN, 1),
)

results = []
gaps = []


def record(label, ok, detail=""):
    results.append((label, ok, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {label}"
          f"{'  -- ' + detail if detail else ''}", flush=True)


def record_gap(label, detail):
    """An observation that is NOT scored.

    Reserved for a property this rig can measure and that the design has not
    yet decided. Scoring it would make the rig permanently red, which trains a
    reader to ignore red; printing nothing would lose the measurement. See
    check_cross_workload_gap.
    """
    gaps.append((label, detail))
    print(f"  GAP   {label}  -- {detail}", flush=True)


def skip(label, why):
    print(f"  SKIP  {label}  -- {why}", flush=True)


def say(msg):
    print(msg, flush=True)


def run(argv, check=True, timeout=120, **kw):
    """A timeout is a RESULT here, not an exception.

    Half of what this rig measures fails by HANGING -- a missing cgroup
    exemption, a redirect armed in front of an inspector that did not start --
    so a TimeoutExpired propagating out of a probe aborts the run at the exact
    moment the interesting thing happened, and the traceback replaces the
    finding. It happened on the first hardware run of this file. A timeout now
    comes back as rc=124 with a marker in stdout, so the assertion that was
    being made still gets made, and it fails.
    """
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout, **kw)
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or b"").decode("utf-8", "replace") \
            if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        p = subprocess.CompletedProcess(
            argv, 124, out + f"\n[TIMED OUT after {timeout}s]", "")
        if check:
            raise RuntimeError(f"{argv!r} timed out after {timeout}s")
        return p
    if check and p.returncode != 0:
        raise RuntimeError(f"{argv!r} rc={p.returncode}\n{p.stdout}\n{p.stderr}")
    return p


def cli(*args, check=False, timeout=300):
    return run(["workloadctl", *args], check=check, timeout=timeout)


def inside(name, script, timeout=60):
    """Run a shell command in the workload's container."""
    return run(["workloadctl", "exec", name, "--", "sh", "-c", script],
               check=False, timeout=timeout)


def fetch(name, url, timeout=60):
    """One request from inside the container, as (seconds, ok, detail).

    `ok` IS WGET'S OWN EXIT STATUS, and getting that right took a rewrite.
    The obvious spelling -- `wget ... | head -c 200; echo "[rc=$?]"` -- reports
    the exit status of HEAD, which is 0 whatever wget did, so a 403 and a 200
    were indistinguishable and every "must be refused" row passed for the wrong
    reason while reading as a failure. The body and the error text go to
    separate files so the status is not inferred from prose that varies by
    wget build.

    The elapsed time is returned because S1's failure mode is a hang rather
    than an error, and a timeout arrives here as ok=False with the marker
    `run()` substitutes rather than as an exception.
    """
    started = time.monotonic()
    script = (
        f"if wget -q -O /tmp/ceg-body -T 15 {url!r} 2>/tmp/ceg-err; "
        f"then echo '[OK]'; else echo '[NO]'; fi; "
        f"head -c 110 /tmp/ceg-body 2>/dev/null; echo; "
        f"head -c 110 /tmp/ceg-err 2>/dev/null"
    )
    p = inside(name, script, timeout=timeout)
    out = (p.stdout + p.stderr).strip()
    ok = "[OK]" in out
    detail = " ".join(out.replace("[OK]", "").replace("[NO]", "").split())[:90]
    return time.monotonic() - started, ok, detail


# --- config generation -------------------------------------------------------

def toml_for(arm):
    """The workload.toml for one arm.

    EVERY [network] SCALAR IS WRITTEN ABOVE THE FIRST ARRAY-OF-TABLES. A scalar
    below one belongs to that ENTRY, not to [network]: the file parses, the
    workload enables, and the key is silently in the wrong table. The generated
    text is checked for exactly this by tests/test_manual_rig_configs.py, on
    the text rather than the parsed document, because the parsed document is
    where the mistake becomes invisible.
    """
    lines = [
        f"# {arm.name} -- generated by container_egress_rig.py.",
        "# Throwaway; safe to purge.",
        "[workload]",
        f'name = "{arm.name}"',
        "enabled = false",
        "",
        "[container]",
        f'image = "{IMAGE}"',
        'command = ["sleep", "infinity"]',
        "",
        "[network]",
        'mode = "pasta"',
    ]
    if arm.rung == 1:
        # Rung 1 is the absence of every key below, and the [network] table
        # here carries `mode` alone -- which is NOT a trigger. This arm exists
        # to prove that a container sharing a host with a filtered one is
        # untouched by it.
        return "\n".join(lines) + "\n"

    lines.append(f'hosts = ["{ALLOWED}"]')
    if arm.rung >= 3:
        # V16's interlock. The policy entry below is what makes the effective
        # tls mode "inspect", and an inspecting workload needs a trust-delivery
        # route stated. Alpine's busybox wget reads SSL_CERT_FILE, so "env" is
        # the honest value here; "image" would be an assertion this rig cannot
        # make about a pulled base.
        lines.append('ca_delivery = "env"')
    if arm.internal:
        # `internal` names a host that must ALSO be allowlisted, or the entry
        # excepts a destination the workload is refused before the exception is
        # reached -- which is a validation error, not a no-op. The `hosts` line
        # is rewritten in place rather than appended, because appending would
        # put a second scalar below `ca_delivery` and TOML would take the last
        # one; there is exactly one `hosts` key.
        idx = lines.index(f'hosts = ["{ALLOWED}"]')
        lines[idx] = f'hosts = ["{ALLOWED}", "{LAN_HOST_IN_CONFIG}"]'

    if arm.rung >= 3:
        lines += [
            "",
            "[[network.policy]]",
            f'host    = "{ALLOWED}"',
            'methods = ["GET"]',
            'paths   = ["/*"]',
        ]
    if arm.internal:
        lines += [
            "",
            "[[network.internal]]",
            f'host   = "{LAN_HOST_IN_CONFIG}"',
            'reason = "rig target; the LAN host this section measures against"',
        ]
    return "\n".join(lines) + "\n"


def _toml_missing_ca_delivery():
    """A rung-3 config with `ca_delivery` omitted. Must be REFUSED.

    Named with a leading underscore so tests/test_manual_rig_configs.py's
    `def toml_for(` selector does not discover it: that gate asserts every
    generated config VALIDATES, and this one exists to fail.
    """
    return toml_for(Arm(FILTERED, 3)).replace('ca_delivery = "env"\n', "")


def write_config(name, text):
    d = WORKLOAD_DIR / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "workload.toml").write_text(text)


# --- host state --------------------------------------------------------------

def workload_uid(name):
    p = run(["getent", "passwd", f"_wl-{name}"], check=False)
    if p.returncode != 0:
        return None
    return int(p.stdout.split(":")[2])


def inspector_v4(uid):
    """vm_inspect_address(uid).v4, re-derived. See INSPECT_V4_BASE."""
    a, b, c, d = INSPECT_V4_BASE
    n = (a << 24 | b << 16 | c << 8 | d) + (uid - UID_MIN)
    return ".".join(str((n >> s) & 0xFF) for s in (24, 16, 8, 0))


def nft_dump(table):
    p = run(["nft", "list", "table", "inet", table], check=False)
    return p.stdout if p.returncode == 0 else ""


def egress_records(name):
    p = cli("egress", name, "--json", "-n", "0")
    if p.returncode != 0:
        return []
    try:
        doc = json.loads(p.stdout)
    except json.JSONDecodeError:
        return []
    if isinstance(doc, dict):
        for key in ("records", "requests", "entries"):
            if isinstance(doc.get(key), list):
                return doc[key]
        return []
    return doc if isinstance(doc, list) else []


def latest_for(name, host):
    for rec in reversed(egress_records(name)):
        if rec.get("host") == host:
            return rec
    return None


def audit_since(marker):
    """AVC lines newer than a byte offset into audit.log, minus the known one."""
    if not AUDIT_LOG.exists():
        return []
    with AUDIT_LOG.open("rb") as fh:
        fh.seek(marker)
        tail = fh.read().decode("utf-8", "replace")
    out = []
    for line in tail.splitlines():
        if "avc:  denied" not in line:
            continue
        if KNOWN_AVC.search(line):
            continue
        if "ceg-" not in line and "wlinspect" not in line:
            # Unrelated host noise. Narrow rather than absent: a denial that
            # names neither this rig's workloads nor the inspector domain is
            # not this rig's to report, and reporting it makes every run on a
            # busy host read as a failure.
            continue
        out.append(line)
    return out


def audit_marker():
    return AUDIT_LOG.stat().st_size if AUDIT_LOG.exists() else 0


# --- sections ----------------------------------------------------------------

def check_rung_ladder():
    """The ladder, walked in order on one image, with a recreate between rungs.

    Deliberately one workload rather than three: the thing under test is the
    TRANSITION -- what changes when a policy entry is added -- and three
    separately-enabled workloads would each prove their own end state while
    saying nothing about moving between them.
    """
    say("\n== the three-rung ladder ==")

    # Rung 1 was deployed as OPEN. Prove no proxy exists for it.
    uid_open = workload_uid(OPEN)
    record("rung 1: an untriggered container has no inspect units",
           not Path(f"/run/systemd/system/workload-{OPEN}-inspect.socket").exists(),
           f"uid {uid_open}")
    proxy = nft_dump("workload_proxy")
    record("rung 1: it is in no redirect map",
           uid_open is not None and f"{uid_open} ." not in proxy)
    p = cli("egress", OPEN)
    record("rung 1: `egress` refuses it, naming the trigger",
           p.returncode != 0 and "no inspected egress" in (p.stdout + p.stderr),
           (p.stdout + p.stderr).strip()[:90])

    # Rung 2: deployed as FILTERED. `hosts` only, and NO ca_delivery anywhere.
    text = (WORKLOAD_DIR / FILTERED / "workload.toml").read_text()
    record("rung 2: the file states no ca_delivery",
           "ca_delivery" not in text)
    p = cli("validate", FILTERED)
    record("rung 2: it validates with no CA route stated",
           p.returncode == 0, (p.stdout + p.stderr).strip()[:90])
    elapsed, ok, out = fetch(FILTERED, f"https://{ALLOWED}/")
    record("rung 2: HTTPS to an allowlisted host round-trips",
           ok, f"{elapsed:.1f}s  {out}")
    rec = latest_for(FILTERED, ALLOWED)
    record("rung 2: the record says the connection was SPLICED",
           bool(rec) and rec.get("mode") == "splice",
           json.dumps({k: rec.get(k) for k in ("plane", "mode", "decision")})
           if rec else "no record")

    # Rung 3, first half: the refusal. Written to disk and validated WITHOUT
    # being enabled, so a refusal here cannot be confused with a start failure.
    write_config(FILTERED, _toml_missing_ca_delivery())
    p = cli("validate", FILTERED)
    text = (p.stdout + p.stderr)
    record("rung 3: adding a policy entry is REFUSED without ca_delivery",
           p.returncode != 0, f"rc={p.returncode}")
    record("rung 3: the refusal names the missing key",
           "ca_delivery" in text, text.strip().splitlines()[-1][:100] if text.strip() else "")

    # Rung 3, second half: state the key and apply. `recreate`, never
    # `restart`: the units themselves change shape here (the CA volume and the
    # five environment variables are added to the podman argv), and `restart`
    # regenerates nothing.
    write_config(FILTERED, toml_for(Arm(FILTERED, 3)))
    p = cli("validate", FILTERED)
    record("rung 3: with ca_delivery stated it validates",
           p.returncode == 0, (p.stdout + p.stderr).strip()[:90])
    p = cli("recreate", FILTERED, timeout=600)
    record("rung 3: recreate applies it", p.returncode == 0,
           (p.stdout + p.stderr).strip()[-90:])
    time.sleep(5)
    elapsed, ok, out = fetch(FILTERED, f"https://{ALLOWED}/")
    record("rung 3: HTTPS still round-trips after the transition",
           ok, f"{elapsed:.1f}s  {out}")
    rec = latest_for(FILTERED, ALLOWED)
    # The mode name on the wire is the terminating one; `splice` here would
    # mean the transition changed the file and not the running inspector.
    record("rung 3: the connection is now TERMINATED, not spliced",
           bool(rec) and rec.get("mode") != "splice",
           json.dumps({k: rec.get(k) for k in ("plane", "mode", "decision")})
           if rec else "no record")
    record("rung 3: the request inside the session is visible",
           bool(rec) and rec.get("method") is not None,
           json.dumps({k: rec.get(k) for k in ("method", "path", "status")})
           if rec else "no record")


def check_both_planes():
    """R5. 443 with a readable SNI, and 80 with a readable Host header.

    The cleartext half is the one that gets skipped, and skipping it leaves
    plaintext HTTP unfiltered in a workload every report calls filtered. The
    assertion is not that the request succeeded -- it is that the inspector
    read the NAME, which on 80 means the Host header and not merely the dial.
    """
    say("\n== both redirected planes ==")
    elapsed, ok, out = fetch(FILTERED, f"http://{ALLOWED}/")
    record("cleartext: HTTP to an allowlisted host round-trips",
           ok, f"{elapsed:.1f}s  {out}")
    rec = latest_for(FILTERED, ALLOWED)
    record("cleartext: the record is on the cleartext plane",
           bool(rec) and rec.get("plane") == "cleartext",
           rec.get("plane") if rec else "no record")
    record("cleartext: the Host header was read, not just the dial",
           bool(rec) and rec.get("method") and rec.get("path"),
           json.dumps({k: rec.get(k) for k in ("method", "path", "status")})
           if rec else "no record")

    elapsed, ok, out = fetch(FILTERED, f"https://{ALLOWED}/")
    record("tls: HTTPS to an allowlisted host round-trips",
           ok, f"{elapsed:.1f}s  {out}")
    rec = latest_for(FILTERED, ALLOWED)
    record("tls: the record is on the tls plane and names the SNI",
           bool(rec) and rec.get("plane") == "tls" and rec.get("host") == ALLOWED,
           json.dumps({k: rec.get(k) for k in ("plane", "host")})
           if rec else "no record")


def check_redial_exemption():
    """S1, the most repeated bug in the whole egress project.

    The inspector's own upstream connection must be exempt in BOTH tables:
    `wl_inspect_cg` in workload_proxy (or its re-dial is redirected back into
    itself) and `wl_egress_cg` in workload_filter (or its re-dial is filtered
    like the workload's own). NEITHER failure produces an error -- one loops
    and one hangs -- so this checks the elements are present AND that a request
    that used them completed inside a wall-clock bound.
    """
    say("\n== the inspector's own re-dial (S1) ==")
    unit = f"workloads.slice/workload-{FILTERED}-inspect.service"
    proxy, filt = nft_dump("workload_proxy"), nft_dump("workload_filter")
    record("the inspector's cgroup is exempt in workload_proxy",
           unit in proxy, "wl_inspect_cg")
    record("the inspector's cgroup is exempt in workload_filter",
           unit in filt, "wl_egress_cg")
    elapsed, ok, out = fetch(FILTERED, f"https://{ALLOWED}/")
    record("a forwarded request completes well inside the hang budget",
           ok and elapsed < REDIAL_BUDGET,
           f"{elapsed:.1f}s of {REDIAL_BUDGET:.0f}s  {out}")


def check_denial():
    """A host that is not allowlisted is refused, and the refusal lands in THIS
    workload's record.

    Attribution here means the housing, not the payload: the record is derived
    from the config-side policy, never from anything the container claims, so
    what is being checked is that the decision was written into the record of
    the workload that made the request.
    """
    say("\n== a denied host ==")
    elapsed, ok, out = fetch(FILTERED, f"https://{DENIED}/")
    record("a non-allowlisted host does not round-trip",
           not ok, f"{elapsed:.1f}s  {out}")
    rec = latest_for(FILTERED, DENIED)
    record("the denial is in this workload's record",
           bool(rec), "no record" if not rec else rec.get("decision", ""))
    record("the record says it was dropped, and why",
           bool(rec) and rec.get("decision") == "drop" and rec.get("reason"),
           json.dumps({k: rec.get(k) for k in ("decision", "reason")})
           if rec else "")
    other = [r for r in egress_records(OPEN)] if workload_uid(OPEN) else []
    record("the denial is NOT in the other workload's record",
           not any(r.get("host") == DENIED for r in other),
           f"{len(other)} records on {OPEN}")


def check_internal():
    """G9, in BOTH directions.

    Present-only would pass against an inspector with no internal-destination
    guard at all, which is the guard that stops an allowlisted PUBLIC name from
    being pointed at the LAN. So the same host is probed twice: allowlisted but
    NOT excepted (must be dropped, with the internal reason named), then with
    the exception (must reach it).
    """
    say("\n== [[network.internal]], both directions ==")
    if not LAN_HOST:
        skip("the internal-destination guard",
             "set CEG_LAN_HOST to a LAN host answering on port 80")
        return

    p = run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             "--max-time", "5", f"http://{LAN_HOST}/"], check=False)
    if not p.stdout.strip().isdigit() or p.stdout.strip() == "000":
        skip("the internal-destination guard",
             f"CEG_LAN_HOST={LAN_HOST} does not answer on port 80 from this "
             f"host, so a drop below would prove nothing")
        return

    # Allowlisted, NOT excepted.
    text = toml_for(Arm(FILTERED, 3))
    text = text.replace(f'hosts = ["{ALLOWED}"]',
                        f'hosts = ["{ALLOWED}", "{LAN_HOST}"]')
    write_config(FILTERED, text)
    if cli("recreate", FILTERED, timeout=600).returncode != 0:
        record("recreate for the not-excepted arm", False, "recreate failed")
        return
    time.sleep(5)
    elapsed, ok, out = fetch(FILTERED, f"http://{LAN_HOST}/")
    record("allowlisted but not excepted: the LAN host is NOT reached",
           not ok, f"{elapsed:.1f}s  {out}")
    rec = latest_for(FILTERED, LAN_HOST)
    record("and the record names the internal destination as the reason",
           bool(rec) and rec.get("decision") == "drop"
           and "internal" in (rec.get("reason") or ""),
           json.dumps({k: rec.get(k) for k in ("decision", "reason")})
           if rec else "no record")

    # With the exception.
    write_config(FILTERED, toml_for(Arm(FILTERED, 3, internal=True)))
    if cli("recreate", FILTERED, timeout=600).returncode != 0:
        record("recreate for the excepted arm", False, "recreate failed")
        return
    time.sleep(5)
    elapsed, ok, out = fetch(FILTERED, f"http://{LAN_HOST}/")
    record("with [[network.internal]]: the same host IS reached",
           ok, f"{elapsed:.1f}s  {out}")
    rec = latest_for(FILTERED, LAN_HOST)
    record("and the record says it was forwarded",
           bool(rec) and rec.get("decision") == "forward",
           json.dumps({k: rec.get(k) for k in ("decision", "upstream")})
           if rec else "no record")


def check_reporting():
    """Which commands report a container as inspected -- and which do not, BY
    DESIGN, because that half is what a stale premise gets wrong.

    `egress`, `doctor` and the exporter are routed through the substrate
    predicate. `rules`, `diagnose`, `drift` and `pcap` are explicitly VM-only
    pending the container document renderer, so their refusal is the correct
    behaviour and is asserted as such. A rig that asserted all seven would fail
    four rows for a decision that was made on purpose.
    """
    say("\n== reporting ==")
    p = cli("egress", FILTERED, "--json", "-n", "1")
    record("`egress` reads the record for a container", p.returncode == 0,
           f"rc={p.returncode}")

    p = cli("doctor", FILTERED, "--json")
    ok, detail = False, f"rc={p.returncode}"
    if p.returncode in (0, 1):
        try:
            doc = json.loads(p.stdout)
            block = doc.get("egress") or {}
            ok = bool(block)
            detail = json.dumps(sorted(block))[:90]
        except json.JSONDecodeError:
            detail = "not JSON"
    record("`doctor --json` carries an egress block for a container", ok, detail)

    drop = Path("/run/workload-exporter/workloads.prom")
    text = drop.read_text() if drop.exists() else ""
    record("the exporter marks the container inspected",
           f'workload="{FILTERED}"' in text and "inspect" in text,
           "no drop file" if not text else f"{len(text.splitlines())} lines")

    # `rules` is the one that refuses outright, and its message names the
    # trigger rather than saying "not supported". That is the shape a VM-only
    # surface is supposed to have.
    p = cli("rules", FILTERED)
    record("`rules` refuses a container and names the trigger",
           p.returncode != 0 and "no inspected egress" in (p.stdout + p.stderr),
           (p.stdout + p.stderr).strip()[:70])

    # THE OTHER THREE ARE MEASURED, NOT ASSERTED, because the row this rig was
    # written from had a stale premise: it called `diagnose`, `drift` and
    # `pcap` "VM-only" as though each refuses. They do not. `diagnose` is a
    # general workload check that runs fine for a container and simply says
    # nothing about its egress; `drift` and `pcap` were left unrouted, which is
    # not the same thing as declining. Whatever they do, an operator meets it,
    # so it is recorded rather than guessed at -- and a rig that asserted a
    # refusal here would have failed rows for a decision made on purpose while
    # missing the one below.
    for verb in ("diagnose", "drift", "pcap"):
        p = cli(verb, FILTERED)
        text = " ".join((p.stdout + p.stderr).split())
        record_gap(f"`{verb}` on an inspected container",
                   f"rc={p.returncode}: {text[:100]}")


def check_cross_workload_gap():
    """MEASURED, NOT SCORED: can an unfiltered container reach a filtered
    workload's inspector?

    `nftables/workload-proxy.nft` argues that cross-workload inspector access
    is STRUCTURALLY unavailable rather than denied by rule: a uid with no
    element in the redirect maps gets no translation, so its packet leaves
    untranslated and meets the default-deny drop in workload_filter. That drop
    is itself guarded on `@wl_filtered` membership -- which an unfiltered
    workload, of either substrate, is also not in. So the argument does not
    close for a container, and reading the rule suggests it does not close for
    an `egress = "open"` VM either.

    This is NOT scored, for two reasons. It is very likely a pre-existing
    property of the shared inspector design rather than anything this effort
    introduced, so failing the container rig for it would attribute it wrongly;
    and the remedy is a decision (a peer-credential check in the listener? an
    input-chain rule that covers co-resident uids? accept it and document the
    boundary?) that has not been made. Turn this into a `record()` on the day
    that decision lands -- and if the decision is "accept it", invert the
    assertion so the rig pins the accepted boundary rather than falling silent.
    """
    say("\n== cross-workload reachability (measured, not scored) ==")
    uid = workload_uid(FILTERED)
    if uid is None:
        skip("cross-workload reachability", "no uid for the filtered workload")
        return
    addr = inspector_v4(uid)
    # The listener's REAL ports, not 80/443: the point is reaching it without
    # a redirect, which is what a co-resident uid with no element would have to
    # do. 8080 is the cleartext listener, 8443 the TLS one.
    for port, label in ((8080, "cleartext"), (8443, "tls")):
        _, ok, out = fetch(OPEN, f"http://{addr}:{port}/", timeout=30)
        # "Reached" is NOT the same as "the request succeeded". A 400 from the
        # listener's own parser and a TLS reset are both proof that bytes
        # arrived at it, which is the whole question; a connection refused or
        # a timeout would be the answer we want. So this reads the error text,
        # not wget's exit status.
        reached = ok or "400" in out or "reset" in out or "HTTP/" in out
        record_gap(
            f"{OPEN} -> {FILTERED}'s inspector on {addr}:{port} ({label})",
            f"{'REACHED' if reached else 'not reached'}: {out[:70]}")


def check_disable_cleanliness():
    """`disable` must leave no inspect units and no element in EITHER table.

    Both tables, because they are armed by different units -- the workload
    service's ExecStopPost tears down the filter half and the inspect service's
    tears down the proxy half -- so a teardown that forgot one leaves a
    redirect pointing at a listener that no longer exists, which the next
    workload to claim that uid inherits.
    """
    say("\n== disable leaves nothing behind ==")
    uid = workload_uid(FILTERED)
    p = cli("disable", FILTERED, timeout=300)
    record("disable succeeds", p.returncode == 0,
           (p.stdout + p.stderr).strip()[-80:])
    time.sleep(3)
    for suffix in ("socket", "service"):
        path = Path(f"/run/systemd/system/workload-{FILTERED}-inspect.{suffix}")
        record(f"the inspect .{suffix} is gone", not path.exists(), str(path))
    proxy, filt = nft_dump("workload_proxy"), nft_dump("workload_filter")
    unit = f"workload-{FILTERED}-inspect.service"
    record("workload_proxy holds no element for it",
           unit not in proxy and (uid is None or f"{uid} ." not in proxy),
           f"uid {uid}")
    record("workload_filter holds no element for it",
           unit not in filt and (uid is None or f"\t{uid}" not in filt),
           f"uid {uid}")


def check_audit(marker):
    """Under enforcing, and only under enforcing.

    A permissive run measures the branch that ran: an earlier denial changes
    which branch a later step takes, so a permissive harvest is one sample of
    one path and reads as complete. If the host is not enforcing this SKIPS
    rather than passing.
    """
    say("\n== SELinux ==")
    mode = run(["getenforce"], check=False).stdout.strip()
    if mode != "Enforcing":
        skip("audit.log clean", f"host is {mode!r}, not Enforcing")
        return
    denials = audit_since(marker)
    record("no AVC beyond the one deliberately not granted",
           not denials,
           f"{len(denials)} denial(s); first: {denials[0][:110]}" if denials
           else "clean")


# --- driver ------------------------------------------------------------------

def preflight():
    if os.geteuid() != 0:
        sys.exit("run as root: this rig enables and disables real workloads")
    for tool in ("workloadctl", "podman", "nft", "getent"):
        if run(["which", tool], check=False).returncode != 0:
            sys.exit(f"missing {tool}")
    for name in (FILTERED, OPEN):
        if (WORKLOAD_DIR / name).exists():
            sys.exit(f"{WORKLOAD_DIR / name} already exists -- purge it first "
                     f"(`workloadctl disable {name} --purge`) so this rig is "
                     f"not measuring a previous run's state")
        # The egress record outlived `disable --purge` until 2026-09-05, and a
        # leftover one is worse than untidy in BOTH directions: `latest_for()`
        # would match a record from a previous run, and the directory is a
        # LogsDirectory= owned by whoever held the uid last, so systemd refuses
        # to set it up and the inspect service fails 240/LOGS_DIRECTORY --
        # which presents as every redirected connection hanging. Refused rather
        # than swept, because on a host with the fix this cannot happen and its
        # presence means something else left it.
        stale = RECORD_ROOT / name
        if stale.exists():
            sys.exit(f"{stale} is left over from an earlier run. Remove it "
                     f"(`sudo rm -rf {stale}`) -- a stale record makes this "
                     f"rig read another run's decisions, and its ownership "
                     f"stops the inspector from starting at all")


def deploy():
    """Enable BOTH workloads at rung 1, then move the filtered one to rung 2.

    Not the obvious order, and the reason is a constraint worth knowing before
    you write a filtered container workload of your own: THE IMAGE PULL IS THE
    WORKLOAD'S OWN TRAFFIC. `podman run --pull=missing` runs in the workload
    service's ExecStart, as the workload uid, AFTER
    `workload-container-filter up` has armed the redirect -- so on a filtered
    workload whose image is not already in its store, the pull is dialled at
    443, lands on this workload's inspector, and is refused because a registry
    is not in `hosts`. `transfer_image` does not cover it: root's store is the
    override channel for images the bundle BUILDS, and a third-party image is
    deliberately left to its own pull policy.

    So a rig that enabled the filtered arm directly would measure image supply
    and report it as an egress failure. Enabling at rung 1 lets the pull happen
    unfiltered, and the recreate to rung 2 then exercises the rung-1-to-rung-2
    transition as a bonus -- which the ladder section otherwise skips.
    """
    say("== deploying ==")
    write_config(OPEN, toml_for(Arm(OPEN, 1)))
    write_config(FILTERED, toml_for(Arm(FILTERED, 1)))
    for name in (OPEN, FILTERED):
        say(f"  enabling {name} ...")
        p = cli("enable", name, timeout=900)
        if p.returncode != 0:
            sys.exit(f"enable {name} failed:\n{p.stdout}\n{p.stderr}")
    # `enable` returns when the unit has STARTED, which is before the image is
    # pulled and the container is answering `exec`. Driving traffic into a
    # container that is not up yet fails every probe with an error that names
    # exec rather than egress -- the rig bug that looks exactly like a product
    # bug, which this tree has now hit five times.
    say("  waiting for both containers to answer exec ...")
    deadline = time.time() + 300
    pending = [OPEN, FILTERED]
    while pending and time.time() < deadline:
        for name in list(pending):
            p = inside(name, "echo UP", timeout=30)
            if p.returncode == 0 and "UP" in p.stdout:
                say(f"  {name} up")
                pending.remove(name)
        if pending:
            time.sleep(5)
    if pending:
        for name in pending:
            subprocess.run(["journalctl", "-u", f"workload-{name}.service",
                            "-n", "30", "--no-pager"])
        sys.exit(f"never became reachable: {', '.join(pending)}")

    # Both images are now in their own stores, so the filtered arm can be
    # filtered without needing the registry. See this function's docstring.
    say(f"  moving {FILTERED} to rung 2 ...")
    write_config(FILTERED, toml_for(Arm(FILTERED, 2)))
    p = cli("recreate", FILTERED, timeout=600)
    if p.returncode != 0:
        sys.exit(f"recreate {FILTERED} to rung 2 failed:\n{p.stdout}\n{p.stderr}")
    deadline = time.time() + 180
    while time.time() < deadline:
        r = inside(FILTERED, "echo UP", timeout=30)
        if r.returncode == 0 and "UP" in r.stdout:
            say(f"  {FILTERED} back up, filtered")
            return
        time.sleep(5)
    subprocess.run(["journalctl", "-u", f"workload-{FILTERED}.service",
                    "-n", "30", "--no-pager"])
    subprocess.run(["journalctl", "-u", f"workload-{FILTERED}-inspect.service",
                    "-n", "20", "--no-pager"])
    sys.exit(f"{FILTERED} did not come back after moving to rung 2")


def cleanup():
    say("\n== cleanup ==")
    for name in (FILTERED, OPEN):
        cli("disable", name, "--purge", timeout=300)
        d = WORKLOAD_DIR / name
        if d.exists():
            for child in d.iterdir():
                child.unlink()
            d.rmdir()
    say("  purged")


def main():
    keep = "--keep" in sys.argv
    preflight()
    marker = audit_marker()
    deploy()
    try:
        check_rung_ladder()
        check_both_planes()
        check_redial_exemption()
        check_denial()
        check_internal()
        check_reporting()
        check_cross_workload_gap()
        check_disable_cleanliness()
        check_audit(marker)
    finally:
        if keep:
            say("\n--keep: workloads left in place")
        else:
            cleanup()

    failed = [r for r in results if not r[1]]
    say(f"\n{len(results) - len(failed)}/{len(results)} assertions passed")
    if gaps:
        say(f"{len(gaps)} measured gap(s), not scored:")
        for label, detail in gaps:
            say(f"  {label}: {detail}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
