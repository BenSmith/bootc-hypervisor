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

  9. THE THREE ROWS THAT WERE DEFERRED FOR WANTING ANOTHER HOST, and two of
     them never did. Each is built from a fixture this rig now stands up and
     tears down itself:

       * IPv6 (check_ipv6). The old note said a v6 probe needs an uplink or it
         dies at the routing lookup having tested nothing. True of a probe at
         a public v6 address, and beside the point: what the row needs is a v6
         destination the kernel will ROUTE, and a ULA on a dummy link is one.
         An uplink would have added an ISP to the measurement, not removed a
         doubt from it. Runs anywhere now.
       * The [[network.allow]] address rotation (check_allow_rotation). Needed
         "a real non-80/443 upstream and a mid-run address change" -- which is
         two stub origins with different bodies and one line in /etc/hosts.
       * `ca_delivery = "env"` against an embedded root store
         (check_embedded_root_store). The one that genuinely needed something
         absent, and what was absent was an IMAGE, so it is a pull. A JDK: the
         five CA variables workloadctl delivers include NODE_EXTRA_CA_CERTS,
         so the obvious Node example proves the opposite of the row, and Go
         reads SSL_CERT_FILE. A JVM reads none of them.

WHAT IT STILL DOES NOT MEASURE:

  * A GLOBAL-SCOPE v6 destination. The redirect map keys on `tcp dport` alone,
    so translation is scope-blind and the ULA result carries -- but that is a
    reading of workload-proxy.nft, not a measurement, and it is the one claim
    here that would still be worth a v6-capable host.

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

Last green 2026-09-06, 78/78 on a bare-metal Fedora 44 host under enforcing.
Getting there took seven product fixes and eight rig fixes, and the split is
worth knowing before reading a failure here.

The five product defects of the first pass were all on the `recreate` path --
the one the schema reference tells operators to use -- and every one of them
presented as a HANG or as a misreport rather than as an error. The two the
three rows in (9) added are a different kind: both are LEGIBILITY defects, and
every functional assertion around each of them was green. A stale
`[[network.allow]]` address was refused correctly and named by nothing; a
client that refused the minted leaf was refused correctly and told to apply a
remedy it does not have. Neither is visible to a test that asks whether the
right thing happened -- only to one that asks what an operator would be told.

The rig defects were all in how a probe's result was READ: wget's exit status
taken from the wrong end of a pipe, a timeout raised instead of recorded, a
capture verb invoked in its blocking form, an origin on a dummy link that every
`oif lo` accept admitted regardless of policy, a probe that measured a DNS
cache and reported it as an arm-time pin, and an address with a `g` in it that
`ip` rejected and this rig reported as "nothing could bind". Both classes look
identical in the output. When a row here fails, check what the probe measured
before believing what it says.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
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
BRIDGE = "ceg-bridge"       # bridge topology: each container in its OWN netns
# Pod topology, and the ONLY multi-member workload here with more than one
# container. Two members, because the defect this workload exists to catch
# (S9) is an ordering one: with a single member there is less window between
# the head unit and the last member, and the point of the row is that the
# arming precedes ALL of them. Pod mode had never run on a host at all --
# `check_bridge_mode` covered the other multi-container topology, and the two
# differ in which head unit exists and what the members share.
POD = "ceg-pod"

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

# --- The three rows that need host fixtures rather than an uplink -----------
#
# Each of these was deferred on the grounds that it "needs a host this one is
# not". Two of the three did not: what the IPv6 row needs is a v6 destination
# the kernel will ROUTE, which a ULA on a dummy link supplies without any
# uplink at all, and what the rotation row needs is a name whose answer changes
# under it, which /etc/hosts supplies. Only the embedded-root-store row needed
# something genuinely absent, and that was an IMAGE, which is a pull.
#
# The fixture is a veth pair with the origins in a NETWORK NAMESPACE, and the
# namespace is the load-bearing part rather than a tidiness measure. The first
# version of this put the addresses on a dummy link, which made every one of
# them LOCAL -- and `workload-filter.nft`'s output chain accepts a filtered
# uid's traffic unconditionally when `oif lo`, because loopback is the
# workload's own control plane (exec, the DNS forward) and not egress. A
# local origin is therefore reached whether or not any element authorises it,
# so the rotation row would have passed its dial and proved nothing about the
# pin. Behind a veth the origins are off-box as far as the routing table is
# concerned, and the allow element is the only thing that can admit them.
#
# Created rather than borrowed: an address on a real interface would make these
# rows depend on the operator's LAN, which is the coupling CEG_LAN_HOST already
# has to apologise for.
NETNS = "ceg-rig"
VETH_HOST, VETH_NS = "ceg-rig0", "ceg-rig1"
HOST_V4, HOST_V6 = "10.99.98.1", "fd00:cec::1"

# The v6 origin. fc00::/7 is in `wl_internal6`, so a ULA destination is an
# INTERNAL one and this row needs a [[network.internal]] entry to reach it --
# not incidental, and worth knowing before reading a failure here: it makes the
# v6 twin of the internal-exemption set load-bearing, which no other row
# exercises. What it does NOT prove is a global-scope v6 destination; the
# redirect map keys on `tcp dport` alone (workload-proxy.nft), so translation
# is scope-blind, but that is a reading of the rule and not a measurement.
# `fd00:cec::`, not `fd00:ceg::`: `g` is not a hexadecimal digit, and `ip`
# rejects the address with "inet6 prefix is expected" -- which this rig then
# reported as "nothing could bind", three layers from the cause. The first
# hardware run of the v6 row skipped for exactly this and nothing in the output
# pointed at a typo.
V6_ADDR = "fd00:cec::10"
V6_HOST = "ceg6.test"
V6_DENIED = "ceg6-denied.test"   # same address, NOT allowlisted; see check_ipv6

# The rotation origins. TWO addresses with DIFFERENT bodies, because the whole
# question is WHICH one answered: a dial that succeeds against the address the
# element was armed with and a dial that succeeds against the address the name
# resolves to now are indistinguishable by success alone.
ROT_A, ROT_B = "10.99.98.10", "10.99.98.11"
ROT_BODY_A, ROT_BODY_B = "ORIGIN-A", "ORIGIN-B"
ROT_HOST = "ceg-rotate.test"
# NOT 80 or 443. An `[[network.allow]]` entry on a redirected port would be
# tested through the inspector, and the arm-time pinning this row exists to
# measure is a property of the nft element, which only carries the un-redirected
# ports. Choosing 80 here would make the row pass while measuring nothing.
ROT_PORT = 8888

HOSTS_FILE = Path("/etc/hosts")
# Every line this rig adds to /etc/hosts carries this, and cleanup removes by
# it rather than by restoring a saved copy: a saved copy loses whatever else
# edited the file while the rig ran, on a host that is not ours to be careless
# with.
HOSTS_TAG = "# ceg-rig"

# The embedded-root-store workload (R9). A JDK, because the five CA variables
# workloadctl delivers (VM_CA_ENV_VARS, lib/vm.py) are read by OpenSSL, Node,
# python-requests, git and pip -- and NODE_EXTRA_CA_CERTS is one of them, so the
# obvious "Node ignores SSL_CERT_FILE" example is exactly wrong here. A JVM
# reads none of the five: its trust store is `cacerts` inside the image, and
# there is no environment variable that adds to it. That is the shape this row
# exists to catch, and it is the shape an operator hits without warning.
NODE_WL = "ceg-jvm"
NODE_IMAGE = "docker.io/library/eclipse-temurin:21-jdk-alpine"
# A second allowlisted name so the workload can KEEP a policy entry -- and
# therefore stay rung 3, with `ca_delivery` still required -- while the host
# under test is exempted from inspection. Splicing the only policy host would
# drop the workload to rung 2 and prove the remedy by removing the feature.
NODE_OTHER = "example.org"

# --- the credential broker arm (P2) ------------------------------------------
#
# One workload, deliberately POD topology. The broker's ordering defect (P2-3)
# is invisible in single mode: `container_broker_before` returns the umbrella
# there and the umbrella is the right answer, so a single-mode row would pass
# whichever way the code went. In pod mode the umbrella is `After=` its
# members, so a broker ordered before it starts after every container -- the
# same shape as S9, one unit over.
CRED_WL = "ceg-cred"
CRED_NAME = "ceg-key"
CRED_PLACEHOLDER = "PLACEHOLDER-CEG"
# What the provider must see. Never written into the workload's config, never
# in its environment: the placeholder is what the container gets, and the two
# being different is what makes "the broker substituted it" a measurement
# rather than a restatement.
CRED_SECRET = "SECRET-CEG-BROKER"
CRED_ENV = "CEG_API_KEY"

# `.test` is reserved (RFC 6761), so this can never collide with a real record.
PROVIDER = "ceg-provider.test"
# In the rig namespace, NOT on loopback. The container has its own loopback and
# a stub on the host's is simply unreachable from it -- and worse, a dial to
# 127.0.0.1 from inside never leaves the container's netns, so it never meets
# the host nftables that every row here is about.
PROVIDER_ADDR = "10.99.98.20"
PROVIDER_PORT = 443     # not configurable: `upstream` is https://<host>

# The broker's address family and port, spelled out rather than imported, for
# INSPECT_V4_BASE's reason.
BROKER_V4_BASE = (127, 129, 0, 0)   # VM_BROKER_ADDR_BASE
BROKER_PORT = 8081                  # VM_BROKER_INSTANCE_PORT

# The header a generated instance uses when the workload names no convention.
# Restated because a rig asserting `Authorization` against a default of
# `x-api-key` reads a header nothing writes and calls a working substitution a
# failure -- which is how it read on broker_rig's first run.
AUTH_HEADER_DEFAULT = "x-api-key"

# Both refusals are 403, so the STATUS cannot say whether a request was refused
# for its Host or for its CALLER. Those are different claims with different
# controls, and the caller one is the whole invariant here.
DENY_UNKNOWN_CALLER = "caller not registered with the broker"

# The rig's own trust drop-ins, so teardown removes what it created.
TRUST_DROPIN = "10-ceg-trust.conf"
_dropins = []

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
    # "single" = one [container]; "bridge" = workload.mode = "bridge" with
    # [[containers]], which puts each container in its OWN netns reached
    # through an auto-created workload-<name>-net rather than pasta (P1-9);
    # "pod" = workload.mode = "pod", members sharing one netns behind a
    # workload-<name>-pod.service head unit (S9).
    topology: str = "single"
    # The three host-fixture rows, each of which needs a [network] shape the
    # rung/topology axes cannot express. Dispatched in toml_for, so every one
    # of them stays on the path tests/test_manual_rig_configs.py validates --
    # these are the shapes MOST likely to rot, because they are the ones a
    # normal run on a normal host never writes.
    variant: str = ""


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
    Arm(BRIDGE, 1, topology="bridge"),
    Arm(BRIDGE, 3, topology="bridge"),
    Arm(POD, 1, topology="pod"),
    Arm(POD, 3, topology="pod"),
    Arm(FILTERED, 2, variant="v6"),
    Arm(FILTERED, 2, variant="rotate"),
    Arm(NODE_WL, 1, variant="node-rung1"),
    Arm(NODE_WL, 3, variant="node"),
    Arm(NODE_WL, 3, variant="node-spliced"),
    Arm(CRED_WL, 1, topology="pod", variant="cred-rung1"),
    Arm(CRED_WL, 3, topology="pod", variant="cred"),
)

results = []
gaps = []

# Scratch for the throwaway TLS material the v6 origin serves. Made in
# preflight so a failure to create it is a startup error rather than a row.
FIXTURE_DIR = Path(tempfile.mkdtemp(prefix="ceg-fixtures-"))


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


def dial_as_root(host, port, timeout=20):
    """One dial from the HOST as root, returning whatever came back as text.

    Root is the only caller nftables lets through to a listener (rules 9/10
    exempt uid 0 so a host-wide drop cannot catch `diagnose`/`doctor`), which
    makes this the only probe that can measure the listener's OWN check rather
    than the packet filter in front of it.

    Reads the error text, not the exit status, for the reason `fetch` does: a
    refusal and an answer must be told apart by what the far end said, and
    "400" from the listener's own parser IS an answer.
    """
    p = subprocess.run(
        ["curl", "-sS", "-m", str(timeout), "-o", "-",
         f"http://{host}:{port}/"],
        capture_output=True, text=True)
    return (p.stdout + p.stderr).strip().replace("\n", " ")


def fetch(name, url, timeout=60, extra=""):
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
        # Truncate both first. wget leaves the PREVIOUS request's body in place
        # when it fails, so a refusal was printing the last success's HTML as
        # its detail -- the assertion was right and the evidence beside it was
        # from a different request, which is worse than no detail.
        f": > /tmp/ceg-body; : > /tmp/ceg-err; "
        f"if wget -q {extra} -O /tmp/ceg-body -T 15 {url!r} 2>/tmp/ceg-err; "
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
    if arm.variant.startswith("cred"):
        return _cred_toml(arm)
    if arm.variant:
        return _variant_toml(arm)
    if arm.topology == "bridge":
        return _bridge_toml(arm)
    if arm.topology == "pod":
        return _pod_toml(arm)

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


def _bridge_toml(arm):
    """A bridge-topology workload with an inspected [network] (P1-9).

    REACHED THROUGH toml_for, not called directly, and that is deliberate.
    tests/test_manual_rig_configs.py selects this FILE on the text
    `def toml_for(` but then calls `toml_for(arm)` once per ARMS entry -- so a
    second top-level generator would never be called by it, and this config
    would be the one shape in the file no gate validates. That is precisely
    the decay the gate exists to catch, one level up. Dispatching on
    `arm.topology` keeps it on the gated path.

    Note there is no `[network] mode` key: the topology owns the podman network
    (an auto-created workload-<name>-net), and naming pasta here would be a
    contradiction the generator resolves in favour of one of them silently.
    """
    lines = [
        f"# {BRIDGE} -- generated by container_egress_rig.py.",
        "# Throwaway; safe to purge.",
        "[workload]",
        f'name = "{BRIDGE}"',
        'mode = "bridge"',
        "enabled = false",
        "",
        "[[containers]]",
        'name = "app"',
        "",
        # Multi-container form NESTS the container block; `image` directly
        # under [[containers]] is not the same key and validation says so.
        # The gate caught exactly that here before this reached a host.
        "[containers.container]",
        f'image = "{IMAGE}"',
        'command = ["sleep", "infinity"]',
    ]
    if arm.rung == 1:
        # No [network] table at all: this arm exists so the image pull happens
        # UNFILTERED. See deploy() -- the pull is the workload's own traffic.
        return "\n".join(lines) + "\n"

    # Scalars above the first array-of-tables, per toml_for's docstring.
    lines += [
        "",
        "[network]",
        f'hosts = ["{ALLOWED}"]',
        'ca_delivery = "env"',
        "",
        "[[network.policy]]",
        f'host    = "{ALLOWED}"',
        'methods = ["GET"]',
        'paths   = ["/*"]',
    ]
    return "\n".join(lines) + "\n"


def _pod_toml(arm):
    """A pod-topology workload with an inspected [network] (S9).

    Reached through toml_for for _bridge_toml's reason -- a second top-level
    generator would be the one shape in this file no gate validates.

    TWO members sharing one netns, which is what pod mode is. They talk on
    localhost, so neither needs a port, and `sleep infinity` is enough for
    both: nothing here is about what the containers do, only about what was
    true of the host's nftables before either of them started.

    `[network] mode` is omitted. Pod mode DOES honour it (it becomes
    `podman pod create --network=`), unlike bridge mode where it is ignored
    outright -- but naming pasta here would add an axis to a row that is about
    ordering, and pasta is the default anyway.
    """
    lines = [
        f"# {POD} -- generated by container_egress_rig.py.",
        "# Throwaway; safe to purge.",
        "[workload]",
        f'name = "{POD}"',
        'mode = "pod"',
        "enabled = false",
        "",
        "[[containers]]",
        'name = "app"',
        "",
        # Nested, per _bridge_toml: `image` directly under [[containers]] is a
        # different key and validation says so.
        "[containers.container]",
        f'image = "{IMAGE}"',
        'command = ["sleep", "infinity"]',
        "",
        "[[containers]]",
        'name = "side"',
        "",
        # Again `[containers.container]`: the sub-table is relative to the LAST
        # array element, so this one nests under `side`, not under `app`.
        "[containers.container]",
        f'image = "{IMAGE}"',
        'command = ["sleep", "infinity"]',
    ]
    if arm.rung == 1:
        # No [network] table: the image pull happens UNFILTERED, per deploy().
        return "\n".join(lines) + "\n"

    # Scalars above the first array-of-tables, per toml_for's docstring.
    lines += [
        "",
        "[network]",
        f'hosts = ["{ALLOWED}"]',
        'ca_delivery = "env"',
        "",
        "[[network.policy]]",
        f'host    = "{ALLOWED}"',
        'methods = ["GET"]',
        'paths   = ["/*"]',
    ]
    return "\n".join(lines) + "\n"


def _cred_toml(arm):
    """The credential-broker workload (P2), in POD topology.

    Reached through toml_for, like every other generator in this file, so
    tests/test_manual_rig_configs.py validates it -- see _bridge_toml. That
    matters more here than anywhere else in the file: this is the only shape
    the rig writes that a broker instance is generated from, so a schema change
    that broke it would take the entire broker arm down while looking exactly
    like a broker defect.

    NO `hosts` KEY, and that is deliberate. A host with a matching
    [[network.policy]] entry is governed by that entry alone, so listing the
    provider as well would leave a second explanation for a request that got
    through -- the same reasoning broker_rig states for the VM twin.

    TWO POLICY ENTRIES FOR ONE HOST, sharing one credential, which is the
    ordinary way to vary methods by path. On the VM side that shape rendered
    the host's broker table TWICE; TOML refuses a table declared twice, so the
    broker exited at start and every brokered request 502'd on a config
    `validate` had just called clean. P2-1 renders both substrates through one
    function, and this is the config that says so on a host.
    """
    lines = [
        f"# {CRED_WL} -- generated by container_egress_rig.py (P2 broker arm).",
        "# Throwaway; safe to purge.",
        "[workload]",
        f'name = "{CRED_WL}"',
        'mode = "pod"',
        "enabled = false",
        "",
        "[[containers]]",
        'name = "app"',
        "",
        # Nested, per _pod_toml: `image` directly under [[containers]] is a
        # different key and validation says so.
        "[containers.container]",
        f'image = "{IMAGE}"',
        'command = ["sleep", "infinity"]',
        "",
        "[[containers]]",
        'name = "side"',
        "",
        "[containers.container]",
        f'image = "{IMAGE}"',
        'command = ["sleep", "infinity"]',
    ]
    if arm.variant == "cred-rung1":
        # No [network] table: the image pull is the WORKLOAD'S OWN TRAFFIC
        # (see deploy()), and this workload's store is its own -- the other
        # arms' pulls do not fill it.
        return "\n".join(lines) + "\n"

    # Every [network] scalar above the first array-of-tables, per toml_for.
    lines += [
        "",
        "[network]",
        # The policy entry makes the effective tls mode "inspect", and an
        # inspecting workload owes a trust-delivery route. busybox wget reads
        # SSL_CERT_FILE, so "env" is the honest value for this image.
        'ca_delivery = "env"',
        "",
        "[[network.credential]]",
        f'name        = "{CRED_NAME}"',
        f'placeholder = "{CRED_PLACEHOLDER}"',
        f'env         = "{CRED_ENV}"',
        "",
        "[[network.policy]]",
        f'host       = "{PROVIDER}"',
        f'credential = "{CRED_NAME}"',
        'methods    = ["GET"]',
        'paths      = ["/v1/*"]',
        "",
        "[[network.policy]]",
        f'host       = "{PROVIDER}"',
        f'credential = "{CRED_NAME}"',
        'methods    = ["POST"]',
        'paths      = ["/v2/*"]',
        # NO [[network.internal]] ENTRY, AND THAT IS AN ASSERTION. The provider
        # is a 10/8 address, which is in wl_internal4 -- so if the inspector
        # ever dials the ORIGIN of a brokered host again (it did, and the dial
        # was removed), this arm fails on the first probe with `internal
        # destination`, naming a host the request was never going to. An
        # exemption here would quietly cover for that.
    ]
    return "\n".join(lines) + "\n"


def _variant_toml(arm):
    """The [network] shapes for the three host-fixture rows.

    REACHED THROUGH toml_for for _bridge_toml's reason: the gate in
    tests/test_manual_rig_configs.py selects this file on the text
    `def toml_for(` and then calls `toml_for(arm)` once per ARMS entry, so a
    generator it cannot reach is the one shape in the file nothing validates.
    These three are the shapes that most need it -- an ordinary run on an
    ordinary host writes none of them, so a schema change would break them
    silently and the breakage would surface weeks later, on hardware, looking
    exactly like the product defect the row was written to find.
    """
    head = [
        f"# {arm.name} -- generated by container_egress_rig.py ({arm.variant}).",
        "# Throwaway; safe to purge.",
        "[workload]",
        f'name = "{arm.name}"',
        "enabled = false",
        "",
        "[container]",
        f'image = "{NODE_IMAGE if arm.name == NODE_WL else IMAGE}"',
        'command = ["sleep", "infinity"]',
    ]

    if arm.variant == "v6":
        # Rung 2 deliberately: `hosts` alone splices, so this row needs no CA
        # and no trust store in the container, and what it measures -- whether
        # a v6 dial to 80/443 is TRANSLATED -- is unaffected by which of the two
        # tls postures the inspector then takes. Adding a policy entry would
        # put an image's trust store in the path of an IPv6 measurement.
        #
        # V6_DENIED is deliberately NOT in `hosts`. It resolves to the same
        # address, which is the whole trick: a refusal for it can only have
        # come from the inspector reading the name, so it is the one probe that
        # tells "the v6 packet reached the inspector" apart from "the v6 packet
        # went somewhere and something answered".
        return "\n".join(head + [
            "",
            "[network]",
            'mode = "pasta"',
            f'hosts = ["{V6_HOST}"]',
            "",
            "[[network.internal]]",
            f'host   = "{V6_HOST}"',
            'reason = "the rig v6 origin is a ULA, and fc00::/7 is in '
            'wl_internal6 -- without this the inspector is barred from the '
            'address the row measures"',
        ]) + "\n"

    if arm.variant == "rotate":
        # `hosts` AND an allow entry. The allow entry alone would be a trigger,
        # but the workload also needs a redirected path so a failure here can
        # be told apart from a workload that armed nothing at all.
        return "\n".join(head + [
            "",
            "[network]",
            'mode = "pasta"',
            f'hosts = ["{ALLOWED}"]',
            "",
            "[[network.allow]]",
            f'host   = "{ROT_HOST}"',
            f"port   = {ROT_PORT}",
            'reason = "rig target for the D7 arm-time-pinning row: this '
            'address is resolved ONCE, when the element is armed"',
        ]) + "\n"

    if arm.variant == "node-rung1":
        # No [network] table at all. The JDK image is ~180MB and the pull is
        # the WORKLOAD'S OWN TRAFFIC (see deploy()), so it has to happen before
        # anything is armed or it is dialled at 443, lands on this workload's
        # own inspector, and is refused because a registry is not in `hosts`.
        return "\n".join(head) + "\n"

    if arm.variant in ("node", "node-spliced"):
        policy_host = NODE_OTHER if arm.variant == "node-spliced" else ALLOWED
        lines = head + [
            "",
            "[network]",
            'mode = "pasta"',
            f'hosts = ["{ALLOWED}", "{NODE_OTHER}"]',
            'ca_delivery = "env"',
            "",
            "[[network.policy]]",
            # The policy entry moves to the OTHER host in the spliced arm, so
            # the workload stays rung 3 -- still inspecting, still owing
            # `ca_delivery` -- while the host under test is exempted. Splicing
            # the only policy host would drop it to rung 2 and "prove" the
            # remedy by deleting the feature.
            f'host    = "{policy_host}"',
            'methods = ["GET"]',
            'paths   = ["/*"]',
        ]
        if arm.variant == "node-spliced":
            lines += [
                "",
                "[[network.splice]]",
                f'host   = "{ALLOWED}"',
                'reason = "this image carries its own trust store and reads '
                'none of the five CA variables, so inspection cannot be made '
                'to work for it -- splice, or change the image"',
            ]
        return "\n".join(lines) + "\n"

    raise ValueError(f"unknown arm variant {arm.variant!r}")


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


def broker_v4(uid):
    """vm_broker_listen_address(uid), re-derived. See INSPECT_V4_BASE."""
    a, b, c, d = BROKER_V4_BASE
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


# --- host fixtures -----------------------------------------------------------
#
# Everything below builds state on the HOST rather than in a workload, and all
# of it is torn down in cleanup(). It is the half of these three rows that was
# mistaken for "needs a different host".

_servers = []          # Popen handles for the stub origins
_fixtures_up = False   # so cleanup() can be tolerant without being silent


def fixtures_up():
    """A veth into a namespace holding every origin address, v4 and v6.

    See NETNS above for why the origins may not be host-local. The v6 half also
    settles the question that kept the IPv6 row unrun: it needs no uplink,
    because what it needs is a v6 destination the kernel will ROUTE, and the
    far side of a veth is one.

    `nodad` on both v6 addresses: duplicate address detection costs a second of
    silence during which a bind fails with EADDRNOTAVAIL, which presents as the
    stub origin dying at startup -- one layer away from anything this rig is
    about, and indistinguishable from it in the output.
    """
    global _fixtures_up
    run(["ip", "netns", "add", NETNS], check=False)
    run(["ip", "link", "add", VETH_HOST, "type", "veth",
         "peer", "name", VETH_NS], check=False)
    if run(["ip", "link", "set", VETH_NS, "netns", NETNS],
           check=False).returncode != 0:
        return False
    run(["ip", "addr", "add", f"{HOST_V4}/24", "dev", VETH_HOST], check=False)
    run(["ip", "-6", "addr", "add", f"{HOST_V6}/64", "dev", VETH_HOST,
         "nodad"], check=False)
    if run(["ip", "link", "set", VETH_HOST, "up"], check=False).returncode != 0:
        return False
    for argv in (
            ["-n", NETNS, "link", "set", "lo", "up"],
            ["-n", NETNS, "addr", "add", f"{ROT_A}/24", "dev", VETH_NS],
            ["-n", NETNS, "addr", "add", f"{ROT_B}/24", "dev", VETH_NS],
            # The stub provider the broker arm dials. In the namespace with
            # the others, for NETNS's reason: an origin the host considers
            # local is admitted by `oif lo` whatever any element says.
            ["-n", NETNS, "addr", "add", f"{PROVIDER_ADDR}/24", "dev", VETH_NS],
            ["-n", NETNS, "-6", "addr", "add", f"{V6_ADDR}/64", "dev", VETH_NS,
             "nodad"],
            ["-n", NETNS, "link", "set", VETH_NS, "up"]):
        run(["ip", *argv], check=False)
    _fixtures_up = True
    return True


def fixtures_down():
    # Deleting the namespace takes VETH_NS with it; the host side has to go
    # separately, and does not vanish on its own if the pair was created but
    # never moved.
    run(["ip", "netns", "del", NETNS], check=False)
    run(["ip", "link", "del", VETH_HOST], check=False)


def hosts_write(pairs):
    """Rewrite this rig's OWN lines in /etc/hosts, leaving everything else.

    Removes by tag rather than restoring a saved copy: a saved copy silently
    reverts whatever else edited the file while the rig ran, and this runs on a
    host that is not the rig's to be careless with.
    """
    kept = [ln for ln in HOSTS_FILE.read_text().splitlines()
            if HOSTS_TAG not in ln]
    kept += [f"{addr}\t{name}\t{HOSTS_TAG}" for addr, name in pairs]
    HOSTS_FILE.write_text("\n".join(kept) + "\n")
    # resolved answers /etc/hosts from a cache it does not invalidate quickly
    # enough for a rotation measured in seconds. Without this the row measures
    # the cache and reports it as the pinning under test.
    run(["resolvectl", "flush-caches"], check=False)


def hosts_clear():
    hosts_write([])


def serve_origin(bind, port, body, tls_pair=None):
    """Start one stub origin and wait until it actually accepts a connection.

    Returning as soon as Popen returns races the bind: a probe fired at a
    socket that is not listening yet fails with connection-refused, which is
    also what a working drop looks like. Every row here would then be measuring
    the rig's own startup.
    """
    argv = ["ip", "netns", "exec", NETNS,
            sys.executable, "-B", str(Path(__file__).parent / "stub_origin.py"),
            bind, str(port), body]
    if tls_pair:
        argv += list(tls_pair)
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    _servers.append(proc)
    import socket as _socket
    family = _socket.AF_INET6 if ":" in bind else _socket.AF_INET
    deadline = time.time() + 15
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with _socket.socket(family, _socket.SOCK_STREAM) as sk:
                sk.settimeout(1)
                sk.connect((bind, port))
            return True
        except OSError:
            time.sleep(0.3)
    return False


def stop_origins():
    for proc in _servers:
        proc.terminate()
    for proc in _servers:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    _servers.clear()


def self_signed(directory):
    """A throwaway certificate for the v6 TLS origin.

    Self-signed on purpose and it is enough: the row measures whether a v6 dial
    to 443 is TRANSLATED, and rung 2 SPLICES -- the origin's own certificate
    reaches the client untouched, so the client is run with verification off
    and the evidence is the inspector's record rather than the chain.
    """
    cert, key = directory / "origin.crt", directory / "origin.key"
    p = run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(key), "-out", str(cert), "-days", "1",
             "-subj", f"/CN={V6_HOST}",
             "-addext", f"subjectAltName=DNS:{V6_HOST},DNS:{V6_DENIED}"],
            check=False, timeout=60)
    return (str(cert), str(key)) if p.returncode == 0 else None


def wait_up(ref, why, seconds=180):
    deadline = time.time() + seconds
    while time.time() < deadline:
        q = inside(ref, "echo UP", timeout=30)
        if q.returncode == 0 and "UP" in q.stdout:
            return True
        time.sleep(5)
    record(why, False, f"{ref} never answered exec")
    return False


def host_resolves(name, expect, tries=10):
    """Wait until THE HOST resolves `name` to `expect`.

    The host is the right vantage and the only one that matters, because the
    host is where the resolution that gets PINNED happens: the filter helper
    runs as root on the host and calls getaddrinfo there. What the container
    resolves is a separate question the rotation row deliberately no longer
    depends on -- see check_allow_rotation on why its dials are literals.
    """
    for _ in range(tries):
        p = run(["getent", "ahosts", name], check=False)
        if expect in p.stdout:
            return True
        time.sleep(1)
    return False


def allow_elements(uid):
    """The addresses currently armed in wl_allow4 for one uid, as text.

    Read from nft rather than recomputed, because the whole question this
    serves is whether the ARMED value still matches what the name resolves to
    -- and a rig that derived both sides from one resolution could not tell.
    """
    dump = run(["nft", "list", "set", "inet", "workload_filter", "wl_allow4"],
               check=False).stdout
    return [ln.strip() for ln in dump.splitlines() if f"{uid} ." in ln]


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
    # REACHED, not "answered 200". The operator's LAN host is whatever they
    # pointed CEG_LAN_HOST at, and a 404 from it is a complete round trip
    # through the exemption -- the thing under test -- while a 502 from the
    # inspector is the drop. Keying this on wget's exit status made a target
    # that serves nothing at `/` read as a failed exemption.
    record("with [[network.internal]]: the same host IS reached",
           ok or "HTTP/" in out, f"{elapsed:.1f}s  {out}")
    rec = latest_for(FILTERED, LAN_HOST)
    record("and the record says it was forwarded",
           bool(rec) and rec.get("decision") == "forward",
           json.dumps({k: rec.get(k) for k in ("decision", "upstream")})
           if rec else "no record")


def check_reporting():
    """Which commands report a container as inspected -- and which do not, BY
    DESIGN, because that half is what a stale premise gets wrong.

    `egress`, `doctor`, the exporter and -- since G7 -- `diagnose` are routed
    through the substrate predicate. `rules` is explicitly VM-only pending the
    container document renderer, so its refusal is the correct behaviour and is
    asserted as such; `drift` and `pcap` are simply unrouted, which is not the
    same thing as declining, and are measured rather than asserted. See the
    comment on that loop below: the row this rig was written from called all
    four "VM-only as though each refuses", and three of them never did.
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

    # TRIGGER IT, do not read whatever the timer last left. The drop file is
    # written by workload-exporter.service on a timer, so reading it directly
    # measures whenever that last fired -- which on this rig is typically
    # before the workload under test was even enabled. It failed exactly that
    # way (59 stale lines, no ceg-plain row) while the predicate was correct
    # for every arm, i.e. the rig reported a product defect that did not exist.
    run(["systemctl", "start", "workload-exporter.service"], check=False)
    drop = Path("/run/workload-exporter/workloads.prom")
    text = drop.read_text() if drop.exists() else ""
    record("the exporter marks the container inspected",
           f'workload="{FILTERED}"' in text and "inspect" in text,
           "no drop file" if not text else f"{len(text.splitlines())} lines")

    # `rules` is the one that refuses outright, and its message names the
    # trigger rather than saying "not supported". That is the shape a VM-only
    # surface is supposed to have.
    #
    # THIS ROW ASSERTED THE WRONG MESSAGE AND PASSED ON IT until 2026-09-06.
    # It pinned "no inspected egress" -- which is the sentence an UNINSPECTED
    # workload gets, and `ceg-plain` at this point in the run is inspected. The
    # CLI reached it because the refusal branched on the VM predicate alone, so
    # an inspected container was told it had no inspected egress (false), and
    # offered as the remedy the `[network]` trigger it had already written.
    # e07f279 split the branch; this row now pins the half that applies here.
    # Both halves are asserted, because "refuses" alone is satisfied by the
    # sentence that was wrong: the message must NOT deny the trigger, and it
    # must name the document that does exist on disk, which is the only thing
    # in it an operator can act on.
    p = cli("rules", FILTERED)
    out = (p.stdout + p.stderr)
    record("`rules` refuses a container without denying its trigger",
           p.returncode != 0 and "no inspected egress" not in out
           and "IS inspected" in out,
           out.strip()[:90])
    # And the path it names must be the one that is actually there. A refusal
    # naming a plausible-but-wrong path is worse than one naming none: the
    # operator goes and looks, finds nothing, and concludes the feature is
    # broken rather than unrendered. So this checks the file too.
    doc = f"/run/workload-vm/{FILTERED}/inspect.json"
    record("`rules`' refusal names the live policy document, and it exists",
           doc in out and Path(doc).exists(),
           f"named={doc in out} present={Path(doc).exists()}")

    # THE OTHER THREE ARE MEASURED, NOT ASSERTED, because the row this rig was
    # written from had a stale premise: it called `diagnose`, `drift` and
    # `pcap` "VM-only" as though each refuses. They do not. `diagnose` is a
    # general workload check that runs fine for a container and simply says
    # nothing about its egress; `drift` and `pcap` were left unrouted, which is
    # not the same thing as declining. Whatever they do, an operator meets it,
    # so it is recorded rather than guessed at -- and a rig that asserted a
    # refusal here would have failed rows for a decision made on purpose while
    # missing the one below.
    # `pcap` is asked what vantages it offers (-D), NOT started. A bare
    # `pcap <name>` STARTS a capture and runs until it is stopped, on both
    # substrates -- that is the verb working, not hanging. Invoking it the
    # obvious way cost this rig 300 seconds per run and recorded the timeout as
    # if it meant something about containers.
    for verb, extra in (("diagnose", ()), ("drift", ()),
                        ("pcap", ("-D",))):
        p = cli(verb, FILTERED, *extra, timeout=90)
        text = " ".join((p.stdout + p.stderr).split())
        record_gap(f"`{verb}` on an inspected container",
                   f"rc={p.returncode}: {text[:100]}")


def check_bridge_mode():
    """P1-9: does the redirect still fire when the netns is a podman bridge?

    THE OPEN HALF OF P1-9. The uid half is answered -- uid_attribution_rig.py
    measured `exact-uid` on all three of its in-container-uid arms under
    bridge mode, so `meta skuid` selects this traffic exactly as it does under
    pasta. What that does NOT answer is the redirect: bridge mode gives each
    container its own netns reached through an auto-created
    workload-<name>-net rather than pasta, which is a different path to the
    host socket, and every hardware pass before this one used pasta only.

    The DNAT is expected to hold because it happens host-side, after
    re-origination -- but "expected to hold" is what this whole rig exists to
    stop me writing.

    THE ASSERTION THAT MATTERS IS THE RECORD, not the fetch. A successful
    request proves the container reached the origin; it does not prove it went
    THROUGH the inspector, and a redirect that silently failed would let the
    request succeed by going straight out. Only the inspector's own record of
    it distinguishes those two, and they are otherwise identical from inside
    the container.
    """
    say("\n== bridge topology (P1-9) ==")
    # RUNG 1 FIRST, for deploy()'s reason: the image pull is the workload's own
    # traffic, and a filtered workload whose image is not already in its store
    # dials the registry at 443, lands on its own inspector and is refused.
    # Enabling straight at rung 3 would measure image supply and report it as
    # an egress failure -- the rig bug that looks exactly like a product bug.
    write_config(BRIDGE, toml_for(Arm(BRIDGE, 1, topology="bridge")))
    p = cli("enable", BRIDGE, timeout=900)
    if p.returncode != 0:
        record("bridge: enable succeeds", False,
               (p.stdout + p.stderr).strip()[-100:])
        return
    record("bridge: enable succeeds", True)

    ref = f"{BRIDGE}/app"
    deadline = time.time() + 300
    while time.time() < deadline:
        q = inside(ref, "echo UP", timeout=30)
        if q.returncode == 0 and "UP" in q.stdout:
            break
        time.sleep(5)
    else:
        record("bridge: the container answers exec", False, "never came up")
        cli("disable", BRIDGE, "--purge", timeout=300)
        return
    record("bridge: the container answers exec", True)

    # Now move it to rung 3, with the image already local.
    write_config(BRIDGE, toml_for(Arm(BRIDGE, 3, topology="bridge")))
    if cli("recreate", BRIDGE, timeout=600).returncode != 0:
        record("bridge: recreate onto an inspected config", False)
        cli("disable", BRIDGE, "--purge", timeout=300)
        return
    record("bridge: recreate onto an inspected config", True)
    time.sleep(5)

    uid = workload_uid(BRIDGE)
    record("bridge: it is in the redirect map",
           uid is not None and f"{uid} ." in nft_dump("workload_proxy"),
           f"uid {uid}")

    # `ref` is `<workload>/<container>`: bridge mode has no default container.
    elapsed, ok, out = fetch(ref, f"https://{ALLOWED}/")
    record("bridge: HTTPS to an allowlisted host round-trips",
           ok, f"{elapsed:.1f}s  {out}")

    rec = latest_for(BRIDGE, ALLOWED)
    record("bridge: the inspector RECORDED it, so the redirect fired",
           bool(rec),
           json.dumps({k: rec.get(k) for k in ("plane", "mode", "decision")})
           if rec else "NO RECORD -- the request went around the inspector")

    # The denial half. A redirect that fires only for allowlisted traffic
    # would pass every check above and enforce nothing.
    _, ok_denied, out_denied = fetch(ref, f"https://{DENIED}/")
    record("bridge: a non-allowlisted host is refused",
           not ok_denied, out_denied[:80])

    # S9's other half. Bridge mode HAD run here, but only ever in steady state
    # -- enable, recreate, sleep 5, probe -- which is blind to an arming that
    # lands after the members are already up. The ordering is what 91c8fd4
    # changed, and this is the topology it changed it for.
    check_head_unit_ordering(BRIDGE, f"workload-{BRIDGE}-net.service",
                             [f"workload-{BRIDGE}-app.service"])

    cli("disable", BRIDGE, "--purge", timeout=300)
    d = WORKLOAD_DIR / BRIDGE
    if d.exists():
        for c in d.iterdir():
            c.unlink()
        d.rmdir()


def _show(unit, prop):
    """One systemd property of one unit, as the manager currently has it."""
    p = run(["systemctl", "show", unit, "-p", prop, "--value"],
            check=False, timeout=30)
    return (p.stdout or "").strip()


def check_head_unit_ordering(name, head, members):
    """S9: is the egress arming ordered AHEAD of the member containers?

    THE DEFECT THIS MEASURES SHIPPED, AND NOTHING SAW IT. The arming lived on
    the umbrella (`workload-<name>.service`) because `[network]` is
    workload-level and the umbrella is the unit that represents the workload.
    But the umbrella is `After=` its members, so systemd started every
    container first and ran the arming afterwards: for the whole of member
    startup the workload had no `wl_filtered` element, no DNAT and no
    listener, then became filtered mid-flight. 91c8fd4 moved it to the head
    unit. Single mode was never affected, which is why every hardware pass
    before this one was green -- every workload the rig deployed was single.

    ASSERTED ON THE RUNNING MANAGER, NOT ON THE GENERATED FILE. A unit test
    can read what the generator wrote; only a host can say what systemd
    parsed, and the two differ whenever a stale unit is still loaded -- which
    is exactly the state an operator lands in after an RPM upgrade without a
    regenerate, and the state the %post scriptlet warns about.

    THE UMBRELLA'S `After=` IS ASSERTED TOO, and it is the load-bearing row.
    Without it the other assertions are a preference: "the arming is on the
    head unit" only matters because the umbrella runs LATE, and if a future
    change made the umbrella start first, moving the arming would have been
    pointless rather than a fix. This pins the premise, not just the remedy.
    """
    say(f"\n== {name}: the arming is ordered before the members (S9) ==")
    arm = f"workload-container-filter up {name}"

    head_pre = _show(head, "ExecStartPre")
    record(f"{name}: the head unit carries the egress arming",
           arm in head_pre, head if arm in head_pre else f"absent from {head}")

    umbrella = f"workload-{name}.service"
    umb_pre = _show(umbrella, "ExecStartPre")
    record(f"{name}: the umbrella does NOT carry it any more",
           arm not in umb_pre,
           "still on the umbrella -- 91c8fd4 regressed" if arm in umb_pre
           else "clean")

    # The premise. If this ever reads false, the fix above stops being one.
    umb_after = _show(umbrella, "After")
    late = [m for m in members if m in umb_after]
    record(f"{name}: the umbrella really is ordered AFTER its members",
           len(late) == len(members),
           f"After= names {len(late)}/{len(members)}: {' '.join(late)}")

    # And the head unit is ordered ahead of them, in the other direction.
    ahead = [m for m in members if head in _show(m, "After")]
    record(f"{name}: every member is ordered after the head unit",
           len(ahead) == len(members),
           f"{len(ahead)}/{len(members)} members are After={head}")

    # The socket the DNAT points at must be up before the head unit, or a
    # redirected connection from the first member hangs with nothing bound.
    sock = f"workload-{name}-inspect.socket"
    head_after, head_req = _show(head, "After"), _show(head, "Requires")
    record(f"{name}: the head unit Requires= and After= the inspect socket",
           sock in head_after and sock in head_req,
           f"After={sock in head_after} Requires={sock in head_req}")

    # Finally the observation rather than the configuration: what the clock
    # says. Monotonic microseconds, so these are comparable across units.
    def started(unit):
        v = _show(unit, "ExecMainStartTimestampMonotonic")
        if not v or not v.isdigit() or v == "0":
            v = _show(unit, "InactiveExitTimestampMonotonic")
        return int(v) if v.isdigit() and v != "0" else None

    t_head = started(head)
    t_members = {m: started(m) for m in members}
    if t_head is None or any(v is None for v in t_members.values()):
        record_gap(f"{name}: head-vs-member start timestamps",
                   f"head={t_head} members={t_members}")
    else:
        latest_head_first = all(v > t_head for v in t_members.values())
        record(f"{name}: the head unit started before every member, measured",
               latest_head_first,
               "  ".join(f"{m.split('-')[-1]}:+{(v - t_head) / 1e6:.2f}s"
                         for m, v in t_members.items()))


def check_pod_mode():
    """S9's other topology: does pod mode filter, and did it ever run?

    IT HAD NOT. `check_bridge_mode` covered one multi-container topology and
    this rig deployed nothing in the other, so pod mode reached a release
    having been exercised by unit tests alone -- on the substrate where the
    ordering hole above lived.

    Same ladder shape as bridge, and for the same reason: rung 1 first so the
    image pull is the workload's own UNFILTERED traffic. A filtered workload
    whose image is not already in its store dials the registry on 443, lands
    on its own inspector, is refused, and the row reports an egress failure
    when what it measured was image supply.
    """
    say("\n== pod topology (S9) ==")
    write_config(POD, toml_for(Arm(POD, 1, topology="pod")))
    p = cli("enable", POD, timeout=900)
    if p.returncode != 0:
        record("pod: enable succeeds", False, (p.stdout + p.stderr).strip()[-120:])
        return
    record("pod: enable succeeds", True)

    ref = f"{POD}/app"
    deadline = time.time() + 300
    while time.time() < deadline:
        q = inside(ref, "echo UP", timeout=30)
        if q.returncode == 0 and "UP" in q.stdout:
            break
        time.sleep(5)
    else:
        record("pod: the container answers exec", False, "never came up")
        cli("disable", POD, "--purge", timeout=300)
        return
    record("pod: the container answers exec", True)

    # Both members, because a pod that started one of them is not a pod.
    q = inside(f"{POD}/side", "echo UP", timeout=30)
    record("pod: the SECOND member answers exec too",
           q.returncode == 0 and "UP" in q.stdout, q.stdout.strip()[:60])

    write_config(POD, toml_for(Arm(POD, 3, topology="pod")))
    if cli("recreate", POD, timeout=600).returncode != 0:
        record("pod: recreate onto an inspected config", False)
        cli("disable", POD, "--purge", timeout=300)
        return
    record("pod: recreate onto an inspected config", True)
    time.sleep(5)

    uid = workload_uid(POD)
    record("pod: it is in the redirect map",
           uid is not None and f"{uid} ." in nft_dump("workload_proxy"),
           f"uid {uid}")

    elapsed, ok, out = fetch(ref, f"https://{ALLOWED}/")
    record("pod: HTTPS to an allowlisted host round-trips",
           ok, f"{elapsed:.1f}s  {out}")

    rec = latest_for(POD, ALLOWED)
    record("pod: the inspector RECORDED it, so the redirect fired",
           bool(rec),
           json.dumps({k: rec.get(k) for k in ("plane", "mode", "decision")})
           if rec else "NO RECORD -- the request went around the inspector")

    # The second member shares the netns, so it shares the redirect. If only
    # the first were filtered, every assertion above would still pass and half
    # the pod would be unfiltered.
    _, ok2, out2 = fetch(f"{POD}/side", f"https://{DENIED}/")
    record("pod: the second member is filtered too",
           not ok2, out2[:80])

    _, ok_denied, out_denied = fetch(ref, f"https://{DENIED}/")
    record("pod: a non-allowlisted host is refused", not ok_denied,
           out_denied[:80])

    check_head_unit_ordering(
        POD, f"workload-{POD}-pod.service",
        [f"workload-{POD}-app.service", f"workload-{POD}-side.service"])

    cli("disable", POD, "--purge", timeout=300)
    d = WORKLOAD_DIR / POD
    if d.exists():
        for c in d.iterdir():
            c.unlink()
        d.rmdir()


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
    introduced, so failing the container rig for it would attribute it wrongly.

    THE DECISION LANDED AND IT WAS "CLOSE IT", so this is scored now, as the
    docstring it replaces asked for. Two layers, both required to hold:

      - `workload_filter` drops a non-root packet whose destination is a live
        inspector address that is not the sender's own (@wl_inspect_live). The
        rule existed before, qualified `meta skuid @wl_filtered` -- "workloads
        already under policy" -- which an `egress = "open"` VM, a container
        with no [network] table and an ordinary shell all fail to be, so all
        three went straight through.
      - the listener refuses a caller whose uid is not the workload's own,
        root included, via lib/peer_identity.py.

    Not reaching it is therefore the assertion. A REACHED here is a real
    regression in one of those two layers, and reaching it was never only a
    reachability problem: the dials landed in the victim's egress records.
    """
    say("\n== cross-workload reachability ==")
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
        record(
            f"{OPEN} cannot reach {FILTERED}'s inspector on {addr}:{port} "
            f"({label})",
            not reached,
            f"{'REACHED' if reached else 'not reached'}: {out[:70]}")

    # THE ROOT PROBE IS THE ONLY ONE THAT REACHES THE LISTENER AT ALL, and
    # therefore the only one that measures the listener's own check.
    #
    # The rules above drop every non-root caller, so the probes above time out
    # at nftables and the listener never sees a packet -- they measure the nft
    # layer and say nothing about the second one. Root is exempted from that
    # drop on purpose (so a host-wide rule cannot catch `diagnose`/`doctor`),
    # which makes root the only caller whose bytes arrive.
    #
    # Before the listener checked, root got `400` here -- the listener's own
    # parser answering, i.e. proof of reach, with the dial landing in THIS
    # workload's egress records. It must now get nothing at all.
    for port, label in ((8080, "cleartext"), (8443, "tls")):
        out = dial_as_root(addr, port)
        answered = "400" in out or "HTTP/" in out
        record(
            f"root reaches {FILTERED}'s listener on {addr}:{port} ({label}) "
            f"and is refused without an answer",
            not answered,
            f"{'ANSWERED' if answered else 'no answer'}: {out[:70]}")


def check_ipv6():
    """R5's v6 half: a dial to 80/443 over IPv6 must be TRANSLATED.

    The failure this row exists to catch is not a wrong decision, it is the
    absence of one: `proxy_dnat` has a v6 rule of its own (`dnat ip6 to ...
    map @wl_inspect6`) because `dnat` and `dnat ip6` are different translations
    in the inet family, and a v4-only redirect sends dual-stack traffic out
    over v6 untranslated. That leaves a workload every report calls filtered
    reaching v6 destinations with no inspector in the path -- and because the
    packet then meets the default deny, the operator-visible symptom is a
    TIMEOUT, which is what everyone attributes to the network.

    WHY THIS CAN RUN ON A HOST WITH NO IPv6 UPLINK, which is the reason it sat
    unrun for a fortnight. It never needed one. What it needs is a v6
    destination the kernel will route, and a ULA on a dummy link is exactly
    that -- the packet is built, the routing lookup succeeds, and it arrives at
    the nftables hook under test. An uplink would add an ISP to the
    measurement, not remove a doubt from it.

    THE DISCRIMINATING PROBE IS THE DENIED ONE. A successful v6 fetch proves
    something answered; it does not prove the inspector was in the path,
    because an untranslated packet to a reachable origin also succeeds if the
    workload is not filtered. V6_DENIED resolves to the SAME address and is not
    in `hosts`, so a refusal for it can only have come from the inspector
    reading the name -- which is the whole claim.
    """
    say("\n== IPv6 (R5), on a ULA behind a veth ==")
    if not _fixtures_up:
        skip("the IPv6 redirect", "the fixture namespace could not be built")
        return
    certs = self_signed(FIXTURE_DIR)
    if not certs:
        skip("the IPv6 redirect", "openssl could not make a throwaway cert")
        return
    if not serve_origin(V6_ADDR, 80, "V6-CLEARTEXT"):
        skip("the IPv6 redirect", f"nothing could bind [{V6_ADDR}]:80")
        return
    if not serve_origin(V6_ADDR, 443, "V6-TLS", certs):
        skip("the IPv6 redirect", f"nothing could bind [{V6_ADDR}]:443")
        return
    hosts_write([(V6_ADDR, V6_HOST), (V6_ADDR, V6_DENIED)])

    # THE CONTAINER HAS NO IPv6 UNLESS THE HOST LOOKS LIKE IT HAS IPv6.
    # Measured 2026-09-06: with the origin routable from the host and the
    # redirect map correctly armed for this uid, every v6 probe still came back
    # `Network unreachable` -- from the CONTAINER'S own stack, before pasta,
    # before nftables, before anything this row is about. pasta configures the
    # guest from the host's own template interface, and a host with no v6
    # DEFAULT ROUTE gets a guest with no v6 at all.
    #
    # So the row adds one, via the fixture veth, at a metric nothing competes
    # with. On a host with no v6 uplink this displaces nothing; on a host that
    # HAS one the existing default is more specific by metric and keeps
    # winning. It is removed in the `finally` below rather than in cleanup(),
    # because a host that believes it has v6 connectivity makes every other
    # section's happy-eyeballs client wait for a timeout first.
    run(["ip", "-6", "route", "add", "default", "via", V6_ADDR,
         "dev", VETH_HOST, "metric", "4096"], check=False)
    try:
        _check_ipv6_body()
    finally:
        run(["ip", "-6", "route", "del", "default", "via", V6_ADDR,
             "dev", VETH_HOST, "metric", "4096"], check=False)


def _check_ipv6_body():
    """The v6 row proper. Split out only so check_ipv6 can guarantee the
    temporary v6 default route is removed however this returns -- and it
    returns early in three places."""
    write_config(FILTERED, toml_for(Arm(FILTERED, 2, variant="v6")))
    if cli("recreate", FILTERED, timeout=600).returncode != 0:
        record("recreate onto the v6 arm", False, "recreate failed")
        return
    if not wait_up(FILTERED, "the container is back up on the v6 arm"):
        return

    # Reported before anything is probed, because a container with no v6
    # address fails every row below with `Network unreachable` -- which is not
    # a verdict about the redirect and must not be read as one.
    q = inside(FILTERED, "ip -6 route 2>/dev/null | grep -v '^fe80\\|^unreachable' "
                         "| head -4")
    has_v6 = bool(q.stdout.strip())
    record("the container has an IPv6 route at all, so a v6 probe reaches "
           "the host's stack", has_v6,
           " ".join(q.stdout.split())[:90] or
           "no v6 route inside the container: pasta gives the guest v6 only "
           "when the host has a v6 default route, so every probe below would "
           "die in the container's own stack")

    uid = workload_uid(FILTERED)
    v6map = run(["nft", "list", "map", "inet", "workload_proxy", "wl_inspect6"],
                check=False).stdout
    # Read the map, not the rule. The rule is in the shipped skeleton and is
    # always there; what a v4-only arming bug leaves out is the ELEMENT, and
    # that is the difference between "the product ships a v6 rule" and "this
    # workload is redirected on v6".
    record("the v6 redirect map holds an element for this uid",
           uid is not None and f"{uid} ." in v6map,
           f"uid {uid}")

    elapsed, ok, out = fetch(FILTERED, f"http://{V6_HOST}/")
    record("v6 cleartext (80) round-trips to the v6 origin",
           ok and "V6-CLEARTEXT" in out, f"{elapsed:.1f}s  {out}")
    rec = latest_for(FILTERED, V6_HOST)
    record("and the inspector RECORDED it, so the v6 packet was translated",
           bool(rec) and rec.get("plane") == "cleartext",
           json.dumps({k: rec.get(k) for k in ("plane", "mode", "decision")})
           if rec else "NO RECORD -- the v6 dial went around the inspector")

    # Verification off, deliberately: rung 2 splices, so the certificate that
    # reaches the client is the throwaway origin's own. The chain is not what
    # this row measures and checking it would fail the row for the rig's cert.
    elapsed, ok, out = fetch(FILTERED, f"https://{V6_HOST}/",
                             extra="--no-check-certificate")
    record("v6 TLS (443) round-trips to the v6 origin",
           ok and "V6-TLS" in out, f"{elapsed:.1f}s  {out}")
    rec = latest_for(FILTERED, V6_HOST)
    record("and the record shows the SNI was read on the v6 plane",
           bool(rec) and rec.get("plane") == "tls",
           json.dumps({k: rec.get(k) for k in ("plane", "mode", "decision")})
           if rec else "no record")

    # THE ROW'S ACTUAL ASSERTION. Same address, name not allowlisted.
    elapsed, ok, out = fetch(FILTERED, f"http://{V6_DENIED}/")
    record("a NON-allowlisted v6 name at the same address is refused",
           not ok or "V6-CLEARTEXT" not in out, f"{elapsed:.1f}s  {out}")
    rec = latest_for(FILTERED, V6_DENIED)
    record("and the refusal came from the inspector, not from the network",
           bool(rec) and rec.get("decision") == "drop",
           json.dumps({k: rec.get(k) for k in ("decision", "reason")})
           if rec else "NO RECORD -- an untranslated v6 packet leaves no trace, "
                       "which is exactly the failure this row exists to catch")


def check_allow_rotation():
    """D7: an `[[network.allow]]` address is pinned at ARM TIME.

    `container_allow_resolve` runs once, in `workload-container-filter up`, and
    what it produces is an nft element naming a literal address. Nothing
    re-resolves it afterwards -- there is no per-workload DNS responder for
    containers (D7), so unlike a VM there is nothing keeping the address the
    container DIALS and the address that got ARMED in agreement. When they
    diverge the packet is not accepted by the allow rule, falls through to the
    default deny, and is dropped on a counter shared with every other filtered
    workload on the host.

    So the row has two halves and only the second is in doubt. That the pinning
    is real is a property to CONFIRM. That the divergence is legible is the
    property under test -- "fails visibly, not as a silent intermittent drop"
    is the whole reason this row was written, and an intermittent drop with no
    surface naming it is indistinguishable from a flaky upstream.

    Measured with TWO origins carrying DIFFERENT bodies rather than one origin
    moved. Which address answered is the entire question, and a single origin
    would make "the pin held" and "the rotation never took" the same reading.
    """
    say("\n== [[network.allow]] address rotation (D7) ==")
    if not _fixtures_up:
        skip("the allow-rotation row", "the fixture namespace could not be built")
        return
    if not serve_origin(ROT_A, ROT_PORT, ROT_BODY_A):
        skip("the allow-rotation row", f"nothing could bind {ROT_A}:{ROT_PORT}")
        return
    if not serve_origin(ROT_B, ROT_PORT, ROT_BODY_B):
        skip("the allow-rotation row", f"nothing could bind {ROT_B}:{ROT_PORT}")
        return

    hosts_write([(ROT_A, ROT_HOST)])
    if not host_resolves(ROT_HOST, ROT_A):
        skip("the allow-rotation row",
             f"the host does not resolve {ROT_HOST} to {ROT_A}, so the "
             f"element would be armed with something this row cannot predict")
        return
    write_config(FILTERED, toml_for(Arm(FILTERED, 2, variant="rotate")))
    if cli("recreate", FILTERED, timeout=600).returncode != 0:
        record("recreate onto the rotation arm", False, "recreate failed")
        return
    if not wait_up(FILTERED, "the container is back up on the rotation arm"):
        return

    uid = workload_uid(FILTERED)
    armed = allow_elements(uid)
    record("the allow element is armed with the address the name had THEN",
           any(ROT_A in e for e in armed), "; ".join(armed) or "no element")
    # THE DIALS ARE LITERAL ADDRESSES, NOT THE NAME, and that is the fix for a
    # confound the first two hardware runs had. What the pin governs is which
    # ADDRESS is authorised; involving the container's resolver in the probe
    # adds a second variable that can disagree with the host's, and on
    # 2026-09-06 it did -- the host resolved the rotated name and the container
    # was still answered with the old address, so the "does not reach origin B"
    # row reached origin A and read as a pass while measuring a DNS cache.
    # Dialling the literal removes DNS from the probe path entirely. The
    # arm-time resolution is still exercised, on the host, where it happens:
    # the element assertion above IS that measurement.
    elapsed, ok, out = fetch(FILTERED, f"http://{ROT_A}:{ROT_PORT}/")
    record("the armed address is reachable on its non-80/443 port",
           ok and ROT_BODY_A in out, f"{elapsed:.1f}s  {out}")

    # Rotate. Nothing about the workload changes; only the answer does.
    hosts_write([(ROT_B, ROT_HOST)])
    followed = host_resolves(ROT_HOST, ROT_B)
    record("the name now answers with origin B's address on the host, which "
           "is the vantage arming uses",
           followed, f"expected {ROT_B}")
    if not followed:
        return
    elapsed, ok, out = fetch(FILTERED, f"http://{ROT_B}:{ROT_PORT}/")
    record("the address the name has NOW is not authorised: the dial does "
           "not reach origin B",
           not (ok and ROT_BODY_B in out), f"{elapsed:.1f}s  {out}")
    record("the element still names the OLD address, unchanged by the rotation",
           any(ROT_A in e for e in allow_elements(uid)),
           "; ".join(allow_elements(uid)) or "no element")

    # The half that is actually in question. The drop is in nftables, so the
    # inspector never sees the connection and `egress` cannot know about it --
    # checked explicitly rather than assumed, because "there is no record" is
    # itself the reason the operator has nowhere to look.
    record("the drop leaves NO egress record, so `egress` cannot surface it",
           latest_for(FILTERED, ROT_HOST) is None,
           "confirmed: the inspector is not in this path")

    surfaces = {}
    for verb in (("diagnose", FILTERED), ("doctor",), ("validate", FILTERED)):
        q = cli(*verb, timeout=180)
        surfaces[verb[0]] = q.stdout + q.stderr
    named = [verb for verb, text in surfaces.items() if ROT_A in text]
    record("some workloadctl surface names the STALE address, so the "
           "divergence is findable",
           bool(named),
           f"named by: {', '.join(named)}" if named else
           f"none of {', '.join(surfaces)} mentions {ROT_A}; the dial is a "
           f"silent drop on a shared counter and nothing points at the "
           f"[[network.allow]] entry that caused it")

    # D7's stated remedy, confirmed rather than assumed: a re-arm is the
    # refresh, and there is no other one.
    if cli("recreate", FILTERED, timeout=600).returncode != 0:
        record("a re-arm refreshes the pinned address", False, "recreate failed")
        return
    if not wait_up(FILTERED, "the container is back up after the re-arm"):
        return
    record("a re-arm re-resolves: the element now names the NEW address",
           any(ROT_B in e for e in allow_elements(uid)),
           "; ".join(allow_elements(uid)) or "no element")
    elapsed, ok, out = fetch(FILTERED, f"http://{ROT_B}:{ROT_PORT}/")
    record("and origin B is now reachable", ok and ROT_BODY_B in out,
           f"{elapsed:.1f}s  {out}")
    # The other half of a re-arm, which is the half an operator does not
    # expect: the OLD grant is gone. An element is replaced, not added to, so a
    # destination that was reachable before the rotation stops being reachable
    # after it -- and if the name was rotated by mistake, this is the row that
    # says so.
    elapsed, ok, out = fetch(FILTERED, f"http://{ROT_A}:{ROT_PORT}/")
    record("and the address it USED to name is no longer authorised",
           not (ok and ROT_BODY_A in out), f"{elapsed:.1f}s  {out}")


def java_fetch(url, timeout=90):
    """One HTTPS request from inside the JVM workload, as (ok, text).

    A JDK single-file source launch rather than curl, and that IS the row: the
    point is a client whose trust store is inside the image and that reads none
    of the five CA variables workloadctl delivers. Running curl here would
    measure OpenSSL, which reads SSL_CERT_FILE and therefore works -- the row
    would pass and prove the opposite of what it claims.
    """
    script = (
        "cat > /tmp/F.java <<'JEOF'\n"
        "public class F { public static void main(String[] a) throws Exception {\n"
        "  var c = (java.net.HttpURLConnection)"
        " java.net.URI.create(a[0]).toURL().openConnection();\n"
        "  c.setConnectTimeout(15000); c.setReadTimeout(15000);\n"
        "  System.out.println(\"[OK] \" + c.getResponseCode());\n"
        "}}\n"
        "JEOF\n"
        f"java /tmp/F.java {url!r} 2>&1 | tr '\\n' ' ' | head -c 400"
    )
    q = inside(NODE_WL, script, timeout=timeout)
    text = " ".join((q.stdout + q.stderr).split())
    return "[OK]" in text, text[:220]


def check_embedded_root_store():
    """R9: `ca_delivery = "env"` against an image that carries its own store.

    R9 says workloadctl may not claim `ca_delivery` verifies anything -- it is
    an operator ASSERTION, and it catches an unstated CA route, never a wrong
    one. This is the row where that abstraction meets an image: the operator
    states `env`, workloadctl delivers all five variables, every check on the
    host is green, and the workload cannot make a single HTTPS request, because
    a JVM's anchors live in `cacerts` inside the image and no environment
    variable adds to them.

    THE OBVIOUS EXAMPLE IS THE WRONG ONE. Node looks like the canonical
    "ignores SSL_CERT_FILE" client and is not usable here: NODE_EXTRA_CA_CERTS
    is one of the five workloadctl sets (VM_CA_ENV_VARS, lib/vm.py), so Node
    trusts the CA and the row would pass having measured nothing. Go reads
    SSL_CERT_FILE too. A JVM reads none of them.

    THREE PROBES, and the middle one is the row:
      1. UNFILTERED baseline. Without it a failure below is equally well
         explained by the image, the network, or the probe.
      2. Rung 3, inspecting. Must fail, and must fail as a TRUST failure --
         a timeout here would mean the redirect broke, which is a different
         defect wearing this one's clothes.
      3. The remedy. `[[network.splice]]` for that host, with the policy entry
         moved to a second allowlisted name so the workload STAYS rung 3.
         Splicing the only policy host would demonstrate the remedy by
         deleting the feature.
    """
    say("\n== an image with its own trust store (R9) ==")
    write_config(NODE_WL, toml_for(Arm(NODE_WL, 1, variant="node-rung1")))
    p = cli("enable", NODE_WL, timeout=1800)
    if p.returncode != 0:
        record("the JVM workload enables (pull is ~180MB, unfiltered)", False,
               (p.stdout + p.stderr).strip()[-120:])
        return
    record("the JVM workload enables (pull is ~180MB, unfiltered)", True)
    if not wait_up(NODE_WL, "the JVM container answers exec", seconds=600):
        cli("disable", NODE_WL, "--purge", timeout=300)
        return

    try:
        ok, text = java_fetch(f"https://{ALLOWED}/")
        record("baseline: unfiltered, the JVM completes an HTTPS request",
               ok, text)
        if not ok:
            record("the R9 row is measurable on this image", False,
                   "the baseline failed, so a failure under inspection below "
                   "would not be attributable to trust")
            return

        write_config(NODE_WL, toml_for(Arm(NODE_WL, 3, variant="node")))
        if cli("recreate", NODE_WL, timeout=900).returncode != 0:
            record("recreate onto the inspecting arm", False, "recreate failed")
            return
        if not wait_up(NODE_WL, "the JVM container is back up, inspected",
                       seconds=300):
            return

        # Delivery happened. Asserted, because the row's claim is "the image
        # ignores a mechanism that WORKED", and a broken delivery produces the
        # same failed request while meaning something entirely different.
        q = inside(NODE_WL,
                   "for v in SSL_CERT_FILE NODE_EXTRA_CA_CERTS REQUESTS_CA_BUNDLE "
                   "GIT_SSL_CAINFO PIP_CERT; do eval \"p=\\$$v\"; "
                   "[ -n \"$p\" ] && [ -r \"$p\" ] && echo \"$v=ok\"; done")
        delivered = q.stdout.count("=ok")
        record("all five CA variables are delivered and point at a readable "
               "bundle", delivered == 5, f"{delivered}/5: "
               f"{' '.join(q.stdout.split())[:90]}")

        ok, text = java_fetch(f"https://{ALLOWED}/")
        record("inspected: the JVM CANNOT complete the request, "
               "CA delivery notwithstanding", not ok, text)
        trust = any(m in text for m in
                    ("PKIX", "unable to find valid certification path",
                     "SSLHandshakeException", "trustAnchors"))
        record("and it fails as a TRUST failure, not as a timeout",
               trust, text)

        # Legibility. The operator has the client's error and whatever the
        # inspector said; the question is whether either names a remedy that
        # applies to a CONTAINER with a baked-in store.
        rec = latest_for(NODE_WL, ALLOWED)
        logs = cli("logs", NODE_WL, "-n", "200", timeout=120)
        journal = run(["journalctl", "-u",
                       f"workload-{NODE_WL}-inspect.service", "-n", "80",
                       "--no-pager"], check=False).stdout
        blob = (logs.stdout + logs.stderr + journal)
        record("the inspector recorded the refused handshake",
               bool(rec) and rec.get("decision") == "drop",
               json.dumps({k: rec.get(k) for k in ("decision", "reason")})
               if rec else "no record")
        # NOT "it must not mention re-seeding". A VM instance seeded before
        # the workload had a CA really does need re-seeding, and that sentence
        # is right for it. The defect measured on 2026-09-06 was that
        # re-seeding was the ONLY remedy named -- so an operator whose client
        # has an embedded trust store was sent to repair a CA route that
        # cannot be made to work, for a guest that does not exist.
        names_remedy = "splice" in blob.lower()
        record("the explanation names the remedy an embedded trust store "
               "actually has",
               names_remedy,
               "names [[network.splice]]" if names_remedy else
               "nothing in the record or the inspector's journal mentions "
               "splice; the only remedy offered is one a container with a "
               "baked-in store does not have")

        write_config(NODE_WL, toml_for(Arm(NODE_WL, 3, variant="node-spliced")))
        if cli("recreate", NODE_WL, timeout=900).returncode != 0:
            record("recreate onto the spliced arm", False, "recreate failed")
            return
        if not wait_up(NODE_WL, "the JVM container is back up, spliced",
                       seconds=300):
            return
        # Still rung 3: the policy entry moved to the second allowlisted name
        # rather than being deleted, so `ca_delivery` is still required and the
        # workload is still inspecting -- for every host but this one.
        q = cli("validate", NODE_WL)
        record("the spliced config still validates as an inspecting workload",
               q.returncode == 0, (q.stdout + q.stderr).strip()[:90])
        ok, text = java_fetch(f"https://{ALLOWED}/")
        record("[[network.splice]] is the remedy: the JVM completes the "
               "request again", ok, text)
    finally:
        cli("disable", NODE_WL, "--purge", timeout=300)
        d = WORKLOAD_DIR / NODE_WL
        if d.exists():
            for c in d.iterdir():
                c.unlink()
            d.rmdir()


DNS_ADDR = "10.99.98.20"     # a routable resolver, in the fixture namespace
DNS_PORT = 53


def _probe_53(uid, proto, timeout=6):
    """One port-53 dial to DNS_ADDR as `uid`, returning (reached, detail).

    BOTH PROTOCOLS, because the rule under test is protocol-agnostic and the
    two fail differently. The drop is `meta skuid @wl_filtered counter drop`
    with no protocol qualifier, and the accept above it matches on `th dport`,
    which is TCP and UDP alike -- but real DNS is UDP first, and a TCP-only
    probe would leave the protocol the resolver actually uses unmeasured.

    A DROP IS A TIMEOUT, NOT A REFUSAL, and that distinction is the whole
    reading. Connection-refused means the packet ARRIVED and nothing was
    listening -- which is a broken fixture reporting itself as a working
    filter. So a refusal is reported as `reached`, and the fixture's own
    control row below is what stops a silently-dead responder passing every
    assertion here.
    """
    script = (
        "import socket,sys\n"
        f"s=socket.socket(socket.AF_INET, socket.SOCK_"
        f"{'STREAM' if proto == 'tcp' else 'DGRAM'})\n"
        f"s.settimeout({timeout})\n"
        "try:\n"
        f"    s.connect(({DNS_ADDR!r}, {DNS_PORT}))\n"
        + ("    s.send(b'\\x00\\x00'); s.recv(64)\n" if proto == "udp" else "")
        + "    print('REACHED')\n"
        "except socket.timeout:\n"
        "    print('TIMEOUT')\n"
        "except OSError as e:\n"
        # EPERM is the informative one and it is NOT a timeout: an nft `drop`
        # in the output chain rejects a LOCAL sender synchronously, so a
        # blocked UDP query fails at send() with errno 1 rather than waiting.
        # That is the filter's own signature -- an absence of a reply could be
        # a dead responder, EPERM could not be -- so it is named rather than
        # folded into a numeric fallback nobody can read at a glance.
        "    print('DROPPED-EPERM' if e.errno == 1 else"
        "          'REFUSED' if e.errno in (111, 113) else f'ERR {e.errno}')\n")
    p = run(["setpriv", f"--reuid={uid}", f"--regid={uid}", "--clear-groups",
             "python3", "-c", script],
            check=False, timeout=timeout + 20)
    out = (p.stdout or "").strip() + (p.stderr or "").strip()
    # REFUSED counts as reached: see the docstring.
    return ("REACHED" in out or "REFUSED" in out), out[:60]


def check_container_resolver():
    """S10: does the default deny take a filtered container's DNS?

    NEVER MEASURED ANYWHERE, on any host, until this row. The claim was read
    straight off `nftables/workload-filter.nft` and it is a claim about the
    HOST, not about the workload: a triggered container's uid enters
    `wl_filtered` and meets the last rule in the output chain, and the only
    accept its DNS can use is `oif lo`. The port-53 accept in that file is
    scoped to `wl_egress_cg` -- the INSPECTOR's cgroup -- which a container is
    never in.

    So a loopback stub in resolv.conf (127.0.0.53) resolves fine and a LAN
    resolver resolves nothing, including the very hostnames the workload's own
    `hosts` allowlist names. Every host this rig has ever run on, this one
    included, uses the resolved stub -- which is why 78/78 passed through the
    `oif lo` accept without anyone choosing it. The green measured the branch
    that ran.

    THE FIXTURE IS A ROUTABLE RESOLVER, NOT ANOTHER HOST. What the row needs
    is a port-53 destination the kernel will route off loopback, and the far
    side of the existing veth is one. The namespace matters for the reason it
    matters everywhere else here: an address on a dummy link is LOCAL, `oif
    lo` accepts a filtered uid's traffic to it unconditionally, and the row
    would pass having measured the exemption instead of the drop.
    """
    say("\n== a filtered container's DNS (S10) ==")
    uid, open_uid = workload_uid(FILTERED), workload_uid(OPEN)
    if uid is None or open_uid is None:
        record("resolver: both workloads have uids", False,
               f"{FILTERED}={uid} {OPEN}={open_uid}")
        return

    # A responder on both protocols. It answers nothing DNS-shaped -- the
    # question is whether the packet ARRIVES, and a real resolver would add a
    # dependency without adding an assertion.
    run(["ip", "-n", NETNS, "addr", "add", f"{DNS_ADDR}/24", "dev", VETH_NS],
        check=False)
    responder = subprocess.Popen(
        ["ip", "netns", "exec", NETNS, "python3", "-c",
         "import socket,threading\n"
         f"t=socket.socket(); t.setsockopt(socket.SOL_SOCKET,"
         f"socket.SO_REUSEADDR,1); t.bind(({DNS_ADDR!r},{DNS_PORT}))\n"
         "t.listen(8)\n"
         f"u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
         f"u.bind(({DNS_ADDR!r},{DNS_PORT}))\n"
         "threading.Thread(target=lambda:[u.sendto(b'ok',a) for _,a in "
         "iter(lambda:u.recvfrom(512),None)],daemon=True).start()\n"
         "while True: t.accept()[0].close()\n"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)

    try:
        # THE CONTROL FIRST. Without it every assertion below is satisfied by
        # a responder that never came up: a dead fixture and a working drop
        # are the same timeout.
        reached, detail = _probe_53(open_uid, "tcp")
        record("resolver: an UNFILTERED uid reaches the resolver (control)",
               reached, detail)
        if not reached:
            record_gap("resolver: the fixture never answered",
                       "every row below would read as a working filter")
            return

        for proto in ("tcp", "udp"):
            reached, detail = _probe_53(uid, proto)
            record(f"resolver: the filtered uid is DROPPED on {proto}/53",
                   not reached, detail)

        # The documented remedy, which is the half an operator acts on. It
        # needs port 53 SPECIFICALLY -- the element is (uid, address, port) --
        # and an allow entry written without the port arms nothing that
        # matches, which is why the diagnose message spells the TOML out.
        base = toml_for(Arm(FILTERED, 2))
        write_config(FILTERED, base + (
            "\n[[network.allow]]\n"
            f'address = "{DNS_ADDR}"\n'
            f"port    = {DNS_PORT}\n"
            'reason  = "rig: the resolver S10 says a filtered container loses"\n'
        ))
        if cli("recreate", FILTERED, timeout=600).returncode != 0:
            record("resolver: recreate with an allow entry on 53", False)
            return
        record("resolver: recreate with an allow entry on 53", True)
        time.sleep(4)

        elements = allow_elements(uid)
        record("resolver: the allow element is armed with the port",
               any(DNS_ADDR in e and str(DNS_PORT) in e for e in elements),
               " | ".join(elements)[:100] or "no elements")

        for proto in ("tcp", "udp"):
            reached, detail = _probe_53(uid, proto)
            record(f"resolver: the allow entry lifts the drop on {proto}/53",
                   reached, detail)

        # And what `diagnose` says on THIS host, which is a stub host. The
        # passing disposition is the one every previous run relied on without
        # ever naming it, so it is worth pinning that the new check does not
        # cry wolf where the whole hardware history has been green.
        p = cli("diagnose", FILTERED)
        out = p.stdout + p.stderr
        record("resolver: `diagnose` raises no resolver alarm on a stub host",
               "resolves NOTHING" not in out, "clean"
               if "resolves NOTHING" not in out else out[-120:])
    finally:
        responder.terminate()
        try:
            responder.wait(timeout=10)
        except subprocess.TimeoutExpired:
            responder.kill()
        run(["ip", "-n", NETNS, "addr", "del", f"{DNS_ADDR}/24",
             "dev", VETH_NS], check=False)


# --- the credential broker arm (P2) ------------------------------------------

def provider_cert():
    """A throwaway CA-and-leaf-in-one for the stub provider.

    The broker has no option to skip upstream verification and should not have
    one, so the stub needs a certificate the broker will actually VERIFY.
    basicConstraints and keyUsage are explicit because Python verifies with
    VERIFY_X509_STRICT and rejects a trust anchor lacking keyCertSign -- a
    self-signed leaf without them fails on the upstream leg, which reads as a
    broker fault rather than as the rig's own certificate.
    """
    cert, key = FIXTURE_DIR / "provider.crt", FIXTURE_DIR / "provider.key"
    p = run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(key), "-out", str(cert), "-days", "1",
             "-subj", f"/CN={PROVIDER}",
             "-addext", f"subjectAltName=DNS:{PROVIDER}",
             "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,digitalSignature"],
            check=False, timeout=60)
    if p.returncode != 0:
        return None
    # World-readable on purpose: the broker instance reads it as its own
    # DynamicUser, which exists only while that unit does and can be granted
    # nothing ahead of time. It is a public certificate; the key beside it is
    # not, and is not shared.
    cert.chmod(0o644)
    # cert_t, not the tmp type it inherits. Both readers are confined --
    # wlinspect_t is granted certificates and not this directory -- so without
    # the relabel the rig's own scaffolding produces an AVC that reads as a
    # trust failure in the thing under test.
    run(["chcon", "-t", "cert_t", str(cert)], check=False, timeout=60)
    return str(cert), str(key)


def start_provider(cert, key):
    """The stub provider, in the rig namespace, on a routable address.

    stub_upstream.py rather than stub_origin.py: this one reports in its BODY
    which credential arrived. Asserting on "the container got a 200" would pass
    even if the broker attached the wrong key, or none.
    """
    argv = ["ip", "netns", "exec", NETNS,
            sys.executable, "-B",
            str(Path(__file__).parent / "stub_upstream.py"),
            str(PROVIDER_PORT), cert, key]
    env = dict(os.environ, STUB_BIND=PROVIDER_ADDR)
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, env=env)
    _servers.append(proc)
    import socket as _socket
    deadline = time.time() + 15
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as sk:
                sk.settimeout(1)
                sk.connect((PROVIDER_ADDR, PROVIDER_PORT))
            return True
        except OSError:
            time.sleep(0.3)
    return False


def write_trust_dropins(cert):
    """Hand the broker and the inspector the stub's certificate, and nothing
    else.

    A drop-in under /etc applies to a unit whose fragment the generator wrote
    into /run, which is what makes this possible without touching the generated
    file -- and touching it would be pointless, since it is rewritten at every
    boot.

    SSL_CERT_FILE REPLACES the trust store for the process it is set on, which
    is why it is set per unit in a drop-in this rig removes rather than
    anywhere a real workload could inherit it.

    THE INSPECTOR IS IN THE LIST AND SHOULD NOT NEED TO BE. A brokered host is
    no longer dialled at its origin, so the inspector never verifies the
    provider's chain. It is here because its absence would turn a regression of
    that fix into a TLS error rather than into the `internal destination`
    failure the missing [[network.internal]] entry is there to produce, and one
    of those is legible.
    """
    for kind in ("broker", "inspect"):
        d = Path(f"/etc/systemd/system/workload-{CRED_WL}-{kind}.service.d")
        d.mkdir(parents=True, exist_ok=True)
        (d / TRUST_DROPIN).write_text(
            "# container_egress_rig.py -- removed at teardown. The stub\n"
            "# provider's certificate, so this unit verifies it the way it\n"
            "# verifies a real one. NOT installed into the host trust store:\n"
            "# this rig must not leave a trust anchor on a borrowed machine.\n"
            "[Service]\n"
            f"Environment=SSL_CERT_FILE={cert}\n")
        _dropins.append(d)
    run(["systemctl", "daemon-reload"], check=False, timeout=60)


def remove_trust_dropins():
    for d in _dropins:
        shutil.rmtree(d, ignore_errors=True)
    _dropins.clear()
    run(["systemctl", "daemon-reload"], check=False, timeout=60)


def seal_credential():
    """Seal the secret into the credstore the generated unit loads from.

    --key-type host, not tpm2: the property under test is which credential
    reaches which caller, not how the blob was sealed, and this must run on a
    host without a TPM.
    """
    blob = FIXTURE_DIR / "cred.txt"
    blob.write_text(CRED_SECRET + "\n")
    blob.chmod(0o600)
    p = run(["workloadctl", "secret", "create",
             f"broker/{CRED_WL}/{CRED_NAME}", "--file", str(blob),
             "--key-type", "host", "--force"], check=False, timeout=120)
    blob.unlink(missing_ok=True)
    return p.returncode == 0, (p.stdout + p.stderr)[-200:]


def unseal_credential():
    run(["workloadctl", "secret", "delete", f"broker/{CRED_WL}/{CRED_NAME}",
         "--force"], check=False, timeout=120)


def dial_broker(addr, host, as_uid=None, as_gid=None, path="/v1/models"):
    """One dial at a broker instance from the host, optionally as another uid.

    Returns (http_code, body). Reads the body rather than the exit status,
    because the two refusals this measures are both 403 and differ only in what
    they say.
    """
    argv = []
    if as_uid is not None:
        argv = ["setpriv", f"--reuid={as_uid}", f"--regid={as_gid}",
                "--clear-groups"]
    argv += ["curl", "-sS", "-m", "20", "-w", "\nHTTP:%{http_code}",
             "-H", f"Host: {host}", f"http://{addr}:{BROKER_PORT}{path}"]
    p = run(argv, check=False, timeout=60)
    out = (p.stdout or "") + (p.stderr or "")
    code = ""
    for line in out.splitlines():
        if line.startswith("HTTP:"):
            code = line[5:].strip()
    body = out.replace(f"HTTP:{code}", "").strip()
    return code, body


def check_broker_invariants():
    """P2: the container credential broker, on a host, with real packets.

    THE INVARIANT, in the plan's words: the container must not be able to name
    the broker, choose to use it, or be pointed at another workload's. For a VM
    that is nearly free -- a guest has no route to host loopback at all. For a
    container it is a different argument entirely, because the workload's
    traffic is re-originated by a HOST process owned by the workload uid, and
    the broker's own check is a peer-uid check against that same uid. So the
    container's uid is exactly the uid the broker serves, and what keeps the
    container out is that the container is not the one holding the socket.

    The control row is first and it is not a formality. Every refusal below is
    equally satisfied by a broker that is DOWN, and a broker whose unit failed
    to start is precisely what the two VM-side defects produced -- an inert
    brokered path under a green unit suite.

    WHY POD TOPOLOGY. See CRED_WL. `container_broker_before` returns the
    umbrella in single mode and the umbrella is the correct answer there, so a
    single-mode workload cannot distinguish the fix from the defect.
    """
    say("\n== the credential broker (P2) ==")

    if not _fixtures_up:
        skip("credential broker", "the rig namespace is not up")
        return

    pair = provider_cert()
    if not pair:
        skip("credential broker", "could not generate the provider certificate")
        return
    cert, key = pair
    if not start_provider(cert, key):
        skip("credential broker", f"the stub provider never listened on "
                                  f"{PROVIDER_ADDR}:{PROVIDER_PORT}")
        return
    hosts_write([(PROVIDER_ADDR, PROVIDER)])
    if not host_resolves(PROVIDER, PROVIDER_ADDR):
        skip("credential broker", f"the host never resolved {PROVIDER}")
        return

    sealed, detail = seal_credential()
    if not sealed:
        skip("credential broker", f"could not seal the credential: {detail}")
        return

    # Rung 1 first, unfiltered, so the image pull is not this workload's own
    # filtered traffic. See deploy(): the pull runs as the workload uid AFTER
    # the redirect is armed, and this workload's podman store is its own -- the
    # other arms' pulls do not fill it.
    say(f"  enabling {CRED_WL} unfiltered so the pull can happen ...")
    write_config(CRED_WL, toml_for(Arm(CRED_WL, 1, topology="pod",
                                       variant="cred-rung1")))
    p = cli("enable", CRED_WL, timeout=900)
    if p.returncode != 0:
        record("the credential workload enables", False,
               (p.stdout + p.stderr)[-200:])
        return
    if not wait_up(f"{CRED_WL}/app", "the credential workload comes up"):
        return

    say("  recreating with the credential and its policy ...")
    write_config(CRED_WL, toml_for(Arm(CRED_WL, 3, topology="pod",
                                       variant="cred")))
    # Before the recreate, so the broker's FIRST start already trusts the stub.
    write_trust_dropins(cert)
    p = cli("recreate", CRED_WL, timeout=600)
    if p.returncode != 0:
        record("the credential workload recreates with a broker", False,
               (p.stdout + p.stderr)[-200:])
        return
    if not wait_up(f"{CRED_WL}/app", "the credential workload comes back"):
        return

    uid = workload_uid(CRED_WL)
    if uid is None:
        record("the credential workload has a uid", False, "getent found none")
        return
    addr = broker_v4(uid)
    unit = f"workload-{CRED_WL}-broker.service"

    # --- the unit exists and is running -------------------------------------
    active = _show(unit, "ActiveState")
    record("the broker instance is running",
           active == "active",
           f"{unit} is {active or 'absent'} "
           f"-- an inert broker satisfies every refusal below")

    # --- ROW 4 (the control): its own inspector IS served --------------------
    #
    # From the host as the WORKLOAD's uid, which is the identity the inspector
    # dials with. A 200 carrying the sealed secret is the only thing that makes
    # the three refusals attributable.
    gid = uid
    code, body = dial_broker(addr, PROVIDER, uid, gid)
    record("the workload's own uid is served, and the secret is attached",
           code == "200" and CRED_SECRET in body,
           f"http={code} body={body[:140]!r}")

    # --- ROW 2: another workload's uid is refused, NAMING THE CALLER ---------
    other_uid = workload_uid(OPEN)
    if other_uid is None:
        skip("another workload's uid is refused", f"no uid for {OPEN}")
    else:
        code, body = dial_broker(addr, PROVIDER, other_uid, other_uid)
        record("another workload's uid gets nothing, and is refused for being "
               "the wrong CALLER",
               (code == "403" and DENY_UNKNOWN_CALLER in body
                and CRED_SECRET not in body),
               f"http={code} body={body[:140]!r} -- the sentence is matched "
               f"because an unknown HOST is also a 403, and that is a "
               f"different claim")

    # --- ROW 3: root is refused too -----------------------------------------
    #
    # Root is the caller nftables lets through everywhere else, so if the uid
    # check has stopped running this is the probe that says so. A 403 for root
    # is also the only evidence that the refusals above came from the broker's
    # own check rather than from a packet filter in front of it.
    code, body = dial_broker(addr, PROVIDER, None, None)
    record("root is refused at the same address and Host",
           (code == "403" and DENY_UNKNOWN_CALLER in body
            and CRED_SECRET not in body),
           f"http={code} body={body[:140]!r}")

    # --- ROW 1: the container cannot NAME it --------------------------------
    seen = inside(f"{CRED_WL}/app",
                  "env; echo ---; cat /etc/hosts 2>/dev/null; echo ---; "
                  "cat /etc/resolv.conf 2>/dev/null", timeout=60)
    text = seen.stdout + seen.stderr
    record("nothing inside the container names the broker's address",
           "127.129." not in text,
           f"found it: {[l for l in text.splitlines() if '127.129.' in l][:2]}"
           if "127.129." in text else "no 127.129.x.y anywhere in env, "
                                      "/etc/hosts or resolv.conf")
    record("the container holds the PLACEHOLDER, never the key",
           f"{CRED_ENV}={CRED_PLACEHOLDER}" in text
           and CRED_SECRET not in text,
           f"{CRED_ENV} present={f'{CRED_ENV}=' in text} "
           f"secret leaked={CRED_SECRET in text}")

    # --- the end-to-end request, which is the only thing that has sent a
    # --- packet through the whole chain ------------------------------------
    #
    # container -> DNAT -> its inspector -> its broker -> the provider. Two of
    # the five defects the VM side shipped were invisible to everything except
    # this: a pooled ORIGIN connection handed to a brokered request so the
    # broker was never dialled at all, and the broker's own address falling
    # inside wl_internal4 so the dial was dropped once it was made.
    _, ok, detail = fetch(f"{CRED_WL}/app",
                          f"https://{PROVIDER}/v1/models", timeout=90)
    record("a container request to the provider is brokered end to end",
           ok and CRED_SECRET in detail,
           f"ok={ok} body={detail[:140]!r}")
    record("the provider saw the key in the default header",
           f'"{AUTH_HEADER_DEFAULT}": "{CRED_SECRET}"' in detail,
           f"body={detail[:140]!r} -- asserting on the 200 alone would pass "
           f"with the wrong key attached, or none")

    # A path the policy does not cover, so the request is refused by the
    # INSPECTOR before the broker is reached. Without this the row above is
    # also consistent with a workload whose every request is brokered.
    _, ok2, detail2 = fetch(f"{CRED_WL}/app",
                            f"https://{PROVIDER}/v9/nope", timeout=90)
    record("a path outside the policy is refused, carrying no key",
           not ok2 and CRED_SECRET not in detail2,
           f"ok={ok2} body={detail2[:110]!r}")

    # --- P2-5: the internal carve-out ---------------------------------------
    #
    # 127.129.x.y is inside wl_internal4 and the cgroup-keyed drop sits ABOVE
    # the `oif lo` accept, so without an element here the inspector's dial to
    # its own broker is dropped -- and presents as a broker that is down, which
    # is why the control row above cannot substitute for reading the set.
    ok_dump = run(["nft", "list", "set", "inet", "workload_filter",
                   "wl_internal_ok4"], check=False).stdout
    record("the broker's address is exempted from the internal drop (P2-5)",
           addr in ok_dump,
           f"wl_internal_ok4 {'names' if addr in ok_dump else 'does NOT name'} "
           f"{addr}")

    # --- P2-3: the ordering, measured on the clock --------------------------
    head = f"workload-{CRED_WL}-pod.service"
    before = _show(unit, "Before")
    record("the broker is ordered before the POD unit, not the umbrella (P2-3)",
           head in before,
           f"Before={before!r} -- the umbrella is After= its members, so "
           f"ordering the broker ahead of IT puts it after every container")

    def started(u):
        v = _show(u, "ExecMainStartTimestampMonotonic")
        if not v or not v.isdigit() or v == "0":
            v = _show(u, "InactiveExitTimestampMonotonic")
        return int(v) if v.isdigit() and v != "0" else None

    members = [f"workload-{CRED_WL}-app.service",
               f"workload-{CRED_WL}-side.service"]
    t_broker = started(unit)
    t_members = {m: started(m) for m in members}
    if t_broker is None or any(v is None for v in t_members.values()):
        record_gap("broker-vs-member start timestamps",
                   f"broker={t_broker} members={t_members}")
    else:
        record("the broker started before every member, measured",
               all(v > t_broker for v in t_members.values()),
               "  ".join(f"{m.split('-')[-1]}:+{(v - t_broker) / 1e6:.2f}s"
                         for m, v in t_members.items()))

    # --- P2-6: the cgroup depth, and the bound that is actually load-bearing -
    #
    # The inspector's own exemptions match `socket cgroupv2 level 2` EXACTLY,
    # and S1's tail is that a wrong depth fails open with no error. The broker
    # is believed to need no cgroup-matched rule at all -- its DynamicUser sits
    # at 61184+, disjoint from the workload range, so it is not in wl_filtered
    # and the default-deny never applies to it. That belief is what the two
    # rows below check; the depth itself is recorded either way, per P2-6.
    cg = _show(unit, "ControlGroup")
    depth = len([c for c in cg.split("/") if c])
    record_gap("the broker unit's cgroup depth (P2-6)",
               f"{cg!r} -> level {depth} "
               f"(the inspector's exemptions match level 2 exactly)")

    main_pid = _show(unit, "MainPID")
    dyn_uid = None
    if main_pid.isdigit() and main_pid != "0":
        st = Path(f"/proc/{main_pid}/status")
        if st.exists():
            for line in st.read_text().splitlines():
                if line.startswith("Uid:"):
                    dyn_uid = int(line.split()[1])
    if dyn_uid is None:
        record_gap("the broker's dynamic uid", f"MainPID={main_pid!r}")
    else:
        filtered = run(["nft", "list", "set", "inet", "workload_filter",
                        "wl_filtered"], check=False).stdout
        record("the broker's dynamic uid is disjoint from the workload range",
               dyn_uid >= 61184 and dyn_uid != uid,
               f"uid={dyn_uid} workload uid={uid}")
        in_filtered = re.search(rf"\b{dyn_uid}\b", filtered) is not None
        record("the broker is NOT in wl_filtered, so IPAddressAllow is its "
               "only egress bound",
               not in_filtered,
               f"uid={dyn_uid} {'IS' if in_filtered else 'is not'} in "
               f"wl_filtered -- if it ever is, the default-deny applies and "
               f"S1's cgroup depth stops being moot")

    allow = _show(unit, "IPAddressAllow")
    record("that bound names the provider and nothing wider",
           PROVIDER_ADDR in allow and "0.0.0.0/0" not in allow,
           f"IPAddressAllow={allow[:120]!r}")

    # --- the record ---------------------------------------------------------
    rec = latest_for(CRED_WL, PROVIDER)
    if rec is None:
        record(f"{CRED_WL} recorded the brokered request", False,
               "no record for the provider")
    else:
        record("the record names the credential that rode along",
               rec.get("credential") == CRED_NAME,
               f"credential={rec.get('credential')!r}")
        record("the record's upstream is the workload's OWN broker",
               str(rec.get("upstream", "")).startswith(addr),
               f"upstream={rec.get('upstream')!r} (want {addr}:{BROKER_PORT}) "
               f"-- a loopback upstream is only legible beside the credential "
               f"name, which is why both are asserted")
        record("the record carries no credential MATERIAL",
               CRED_SECRET not in json.dumps(rec),
               "the record names WHICH credential, never which key")


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
    for name in (FILTERED, OPEN, BRIDGE, NODE_WL, CRED_WL):
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


    # The three host fixtures. Not fatal if they fail: their rows SKIP, which
    # is the honest reading -- a rig that refused to start over a dummy
    # interface would take the other forty assertions down with it.
    if not fixtures_up():
        say(f"  WARNING: could not build the {NETNS} namespace; the IPv6 and "
            f"rotation rows will skip")


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
    stop_origins()
    hosts_clear()
    fixtures_down()
    shutil.rmtree(FIXTURE_DIR, ignore_errors=True)
    remove_trust_dropins()
    unseal_credential()
    for name in (FILTERED, OPEN, POD, BRIDGE, CRED_WL):
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
        check_bridge_mode()
        check_pod_mode()
        check_cross_workload_gap()
        # The three rows that needed host fixtures rather than another host.
        # After the sections above, because both of the first two REWRITE the
        # filtered workload's config, and before disable-cleanliness, which
        # ends its life.
        check_ipv6()
        check_allow_rotation()
        # After the rotation, which also rewrites the filtered workload's
        # config, and before the JDK row, which is a different workload.
        check_container_resolver()
        check_embedded_root_store()
        # Last of the workload sections: it deploys a workload of its own, and
        # it rewrites /etc/hosts, so anything after it would be measuring this
        # section's fixtures rather than its own.
        check_broker_invariants()
        check_disable_cleanliness()
        check_audit(marker)
    finally:
        if keep:
            # The WORKLOADS are what --keep is for. The host fixtures are not:
            # leaving `ceg-rotate.test` in /etc/hosts and two python processes
            # bound to a dummy link is not inspectable state, it is litter on
            # somebody's machine.
            stop_origins()
            hosts_clear()
            fixtures_down()
            # The trust drop-ins and the sealed credential are HOST state too,
            # and a trust anchor left on a borrowed machine is exactly what
            # write_trust_dropins refuses to do the other way round. The
            # workload keeps running without them; its broker stops trusting a
            # stub that is no longer there, which is the honest end state.
            remove_trust_dropins()
            unseal_credential()
            shutil.rmtree(FIXTURE_DIR, ignore_errors=True)
            say("\n--keep: workloads left in place; host fixtures torn down")
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
