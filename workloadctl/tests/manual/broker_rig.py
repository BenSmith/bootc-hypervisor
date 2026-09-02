#!/usr/bin/env python3
"""broker_rig.py — does a guest actually get a key it never holds, and can two
workloads' brokers tell each other's callers apart?

Run this ON a KVM host with the workloadctl RPM installed. It boots two
throwaway VM workloads, runs a stub provider on the host, and probes from
inside each guest and from the host as each workload's own uid.

WHAT REPLACED WHAT

The rig that lived here until rung 6 probed a HOST-WIDE broker at an advertised
endpoint (192.0.2.1:8081) that every guest was told about, reached through a
uid-keyed nft redirect. ADR 007 deleted that whole shape. Every one of its 18
assertions was about the deleted mechanism, so it was deleted with it rather
than patched -- see tests/manual/README.md for why patching would have been
worse than nothing.

What is under test now is the opposite arrangement: one broker instance per
workload, bound to an address derived from that workload's uid, dialled by that
workload's inspector, and named to the guest NOT AT ALL. The guest dials the
provider's real name; the inspector recognises the host as credential-backed
and sends that request to this workload's broker instead of to the origin.

WHY TWO GUESTS AND NOT FOUR

The old rig needed four because `broker = true`, `hosts` and the credential name
were three independent config axes and their COMBINATIONS were where both of its
defects lived. Three of those axes are gone. What is left needs two:

  wlbrk-a   credential key-a, placeholder PLACEHOLDER-A
  wlbrk-b   credential key-b, placeholder PLACEHOLDER-B

identical in every other line, including the provider hostname. Only the last of
the four claims needs the second workload, and it is the claim the design turns
on -- so the arms differ ONLY in which credential they name, and a difference in
what comes back has exactly one available explanation.

THE FOUR CLAIMS

1. A guest reaches a credential-backed host holding a placeholder and never the
   key. Asserted from BOTH ends: the stub reports which Authorization header
   arrived, and the guest is asked what its own environment holds. Either half
   alone is satisfied by a broker that attached nothing (the guest's fiction is
   present, the stub sees it, and a 200 comes back looking identical).
2. A Host the broker does not know is refused. Sent from the host as the
   workload's own uid, NOT from the guest, and that is not a shortcut: a guest
   cannot construct this request. The inspector dials the broker only for hosts
   the policy names with a credential, and validation refuses a wildcard on such
   an entry, so every Host that can reach the broker through the guest is one the
   generated config named. The refusal is real all the same -- it is what stands
   between a compromised inspector and a key attached to a destination of its
   choosing -- so it is probed at the only place it can be reached from.
3. A guest dialling 127.129.x.y directly reaches its OWN loopback and finds
   nothing. This is the whole of "the guest is never told where the broker is":
   the address is derivable by anyone who reads the source, and it has to be
   useless from inside the guest anyway.
4. Two workloads get different credentials from two instances. Same provider
   name, same request, two guests, two secrets.

THE CONTROLS, AND WHY EACH IS LOAD-BEARING

  * The uid probe in claim 2 is run TWICE more: once with the Host the config
    does name (which must succeed, or the 403 proves only that the rig never
    reached a broker), and once as root against the same address (which must be
    refused, or the 403 for an unknown Host is consistent with a broker that
    has stopped checking WHO is calling and is refusing on the Host alone).
  * And once as the OTHER workload's uid, which is the cross-workload claim
    stated positively: both instances are on the same host's loopback, so
    nothing but the uid check keeps b's caller out of a's credential.

WHAT THE HOST-SIDE SCAFFOLDING COSTS, AND WHY IT IS HONEST

The broker's upstream is `https://<the Host>` with no override -- deliberately,
so a policy-matched path cannot be prefixed on the way out -- so the provider
has to answer at that name on 443. The rig therefore writes ONE /etc/hosts entry
and binds 127.0.0.1:443, and removes both at teardown. The stub's certificate is
handed to each broker instance through SSL_CERT_FILE in a drop-in rather than
installed into the host's trust store, on policy_rig.py's reasoning: the trust
decision stays the broker's, made the way it always is, and this rig does not
leave a trust anchor behind on a machine it borrowed.

Nothing here weakens the path under test. The drop-in adds one environment
variable and changes no directive; the broker still verifies, still refuses a
plaintext upstream, and is still the RPM's copy started by the generated unit.
"""

import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

sys.dont_write_bytecode = True

RIG = Path("/var/lib/broker-rig")
BASE_IMAGE = RIG / "base.qcow2"

CLOUD_URL = ("https://download.fedoraproject.org/pub/fedora/linux/releases/44/"
             "Cloud/x86_64/images/Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2")
CLOUD_SHA = "28680fe5b371a5a82ebf43a31926e086a168e59949d03969c5093e7071f90b7f"

# Spelled out rather than imported, on every other rig's reasoning: a rig that
# computes both sides from one constant cannot notice them drifting apart, and
# these five are exactly the values a guest-invisible mechanism is described by.
UID_MIN = 10000                             # lib/vm.py
BROKER_ADDR_BASE = "127.129.0.0"            # VM_BROKER_ADDR_BASE
BROKER_PORT = 8081                          # VM_BROKER_INSTANCE_PORT
BROKER_RUNDIR = "/run/workloadctl/broker"   # VM_BROKER_RUNTIME_SUBDIR
BROKER_CONFIG = "broker.toml"               # VM_BROKER_CONFIG_NAME

# The installed broker and the installed everything else. `just rpm-install`
# refreshes them; a green run then means the PACKAGE is right, which is the
# claim worth making.
BROKER_BIN = Path("/usr/libexec/workloadctl/agent-broker")

# The name the guests dial and the broker resolves. `.test` is reserved
# (RFC 6761) so it can never collide with a real record, and the host's own
# resolver is not consulted for it -- the /etc/hosts line this rig writes is.
PROVIDER = "provider.wlbrk.test"
PROVIDER_PORT = 443       # not configurable: `upstream` is https://<host>
# Never written into any config. It exists to be a Host no broker instance has
# a row for, which is the whole of claim 2.
UNKNOWN_HOST = "elsewhere.wlbrk.test"

# The broker's two refusal bodies, restated. Both are 403, so the STATUS alone
# cannot say whether a request was refused for its Host or for its caller --
# and those are different claims with different controls. Matching the sentence
# is what makes each assertion attributable.
# The header a generated instance attaches the credential in when the workload
# says nothing. Restated here because a rig asserting `Authorization` against a
# default of `x-api-key` reads a header nothing writes and calls a working
# substitution a failure -- it did, on the first run of this rewrite. An arm
# that DOES name a convention asserts its own; see Arm.header.
AUTH_HEADER_DEFAULT = "x-api-key"

DENY_UNKNOWN_CALLER = "caller not registered with the broker"
DENY_UNKNOWN_HOST = "no credential is configured for that host"

HOSTS_FILE = Path("/etc/hosts")
HOSTS_MARK = "# added by broker_rig.py -- removed at teardown"

DNS_ALLOW = "1.1.1.1:53"

# The guest variable both arms seed their placeholder into. The same name in
# both is safe and is the point: the guests are separate, and an identical
# variable holding a different value is what claim 4 reads.
GUEST_ENV = "RIG_PROVIDER_KEY"

# The inspector's record, for the T5 seam: `upstream` is the broker's address
# on a brokered request and `credential` names the material that rode along.
# Restated rather than imported, for the reason the addresses above are.
RECORD_ROOT = Path("/var/log/workloadctl/egress")
RECORD_FILE = "requests.log"

AUDIT_LOG = Path("/var/log/audit/audit.log")
# The domain the inspector runs in. T5 added its grant to connect to the
# broker's port; a denial here is silent by construction -- the dial fails, the
# listener counts a dead broker, and the guest gets a 502 that names the broker.
INSPECT_DOMAIN = "wlinspect_t"

# The ONE denial security/workload-inspect.cil deliberately does not grant, and
# the reason it is excluded here by SHAPE rather than the domain being dropped
# from the check: it is Python asking whether its stdout -- the journal socket
# inherited from init -- is a tty, the answer is "no" either way, and the module
# says in as many words that the run is green with it denied so granting it
# would widen the domain for nothing. It fires six times at every listener
# start. Anything else in this domain still fails the assertion, which is the
# point: a denial on the broker dial is SILENT, and a check that had been
# widened to "wlinspect_t is noisy, ignore it" could not see it.
UNGRANTED_TARGET = "tcontext=system_u:system_r:init_t:s0"
UNGRANTED_CLASS = "tclass=unix_stream_socket"
UNGRANTED_PERMS = ("{ getattr }", "{ ioctl }")


def is_known_ungranted(line):
    return (UNGRANTED_TARGET in line and UNGRANTED_CLASS in line
            and any(p in line for p in UNGRANTED_PERMS))


@dataclass(frozen=True)
class Arm:
    name: str
    credential: str
    placeholder: str
    secret: str
    # None means "say nothing and get the broker's default", which is what
    # every workload got before these keys existed. The two arms differ here
    # so one run covers both the default and an overridden convention.
    auth_header: str | None = None
    auth_format: str | None = None

    @property
    def header(self):
        return self.auth_header or AUTH_HEADER_DEFAULT

    @property
    def sent_value(self):
        """What the provider should see in that header."""
        fmt = self.auth_format or "{secret}"
        return fmt.format(secret=self.secret)


ARMS = [
    Arm("wlbrk-a", credential="key-a", placeholder="PLACEHOLDER-A",
        secret="SECRET-WLBRK-A"),
    # The provider convention the generated config could not express until the
    # keys existed: every instance ran `x-api-key: {secret}`, so an
    # OpenAI-shaped provider answered 401 on a request the inspector had
    # recorded as fully authorised and brokered.
    Arm("wlbrk-b", credential="key-b", placeholder="PLACEHOLDER-B",
        secret="SECRET-WLBRK-B",
        auth_header="Authorization", auth_format="Bearer {secret}"),
]
BY_NAME = {a.name: a for a in ARMS}

results: list[tuple[str, bool, str]] = []

# Every child we start, appended as it is started rather than returned at the
# end -- an exit between two starts otherwise leaks the first, and a leaked stub
# satisfies the NEXT run's readiness check while answering for a certificate
# that run never generated.
children: list[subprocess.Popen] = []

# Everything this rig wrote outside its own directory, so teardown removes what
# it created and nothing else.
hosts_line_written = False
dropins_written: list[Path] = []


def say(msg):
    print(msg, flush=True)


def record(label, ok, detail):
    results.append((label, ok, detail))
    say(f"  {'PASS' if ok else 'FAIL'}  {label}: {detail}")


def run(argv, check=True, timeout=120, **kw):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                       **kw)
    if check and p.returncode != 0:
        raise RuntimeError(f"{argv!r} rc={p.returncode}\n{p.stdout}\n{p.stderr}")
    return p


def guest(name, script, timeout=90):
    """Run a bash LOGIN shell in the guest.

    Login shell so profile.d applies as well as PAM's /etc/environment -- the
    two places the guest env is written, and a probe using only one would not
    notice the other going missing.
    """
    return subprocess.run(
        ["workloadctl", "exec", name, "--", "bash", "-lc", script],
        capture_output=True, text=True, timeout=timeout)


def uid_of(name):
    return int(run(["id", "-u", f"_wl-{name}"]).stdout.strip())


def gid_of(name):
    return int(run(["id", "-g", f"_wl-{name}"]).stdout.strip())


def broker_address(uid):
    """vm_broker_listen_address, restated. See the constants block."""
    return str(ipaddress.ip_address(
        int(ipaddress.ip_address(BROKER_ADDR_BASE)) + uid - UID_MIN))


CURL = 'curl -sS -m 20 -w "\\nHTTP:%{http_code}" '


def parse(r):
    """(body, status, rc). The status is appended by -w, so a transport failure
    leaves it empty rather than reporting somebody else's code."""
    body = r.stdout
    code = ""
    if "HTTP:" in body:
        body, _, code = body.rpartition("HTTP:")
    return body.strip(), code.strip(), r.returncode


# --- preflight -------------------------------------------------------------

def preflight():
    say("== preflight ==")
    if os.geteuid() != 0:
        sys.exit("run as root: it enables workloads, seals credentials and "
                 "binds 443")
    for tool in ("workloadctl", "qemu-system-x86_64", "qemu-img", "openssl",
                 "setpriv", "ss", "passt"):
        if run(["sh", "-c", f"command -v {tool}"], check=False).returncode != 0:
            sys.exit(f"missing {tool}")
    if not Path("/dev/kvm").exists():
        sys.exit("no /dev/kvm")
    if not os.access(BROKER_BIN, os.X_OK):
        sys.exit(f"missing {BROKER_BIN} — it ships in the workloadctl RPM; "
                 f"run `just rpm-install` from the checkout")
    # A stale listener takes traffic that should have gone to a process this run
    # started, and the result reads as a fault in whatever is downstream of it.
    busy = run(["ss", "-lntH", f"sport = :{PROVIDER_PORT}"], check=False)
    if busy.stdout.strip():
        sys.exit(f"something already listens on :{PROVIDER_PORT} — the stub "
                 f"provider must answer there, because `upstream` is "
                 f"https://{PROVIDER} with no port to override:\n{busy.stdout}")
    for arm in ARMS:
        if (Path("/etc/workloads.d") / arm.name).exists():
            sys.exit(f"/etc/workloads.d/{arm.name} already exists — a previous "
                     f"run did not tear down; remove it or run with --keep off")
    if HOSTS_MARK in HOSTS_FILE.read_text():
        sys.exit(f"{HOSTS_FILE} still carries this rig's line from an earlier "
                 f"run; remove the line marked {HOSTS_MARK!r}")
    say(f"  ok: toolchain, /dev/kvm, :{PROVIDER_PORT} free, no leftovers")


def fetch_base_image():
    RIG.mkdir(parents=True, exist_ok=True)
    if BASE_IMAGE.exists():
        say(f"  base image present: {BASE_IMAGE}")
        return
    say(f"  downloading {CLOUD_URL}")
    run(["curl", "-fSL", "--retry", "3", "-o", str(BASE_IMAGE), CLOUD_URL],
        timeout=1800)
    got = run(["sha256sum", str(BASE_IMAGE)]).stdout.split()[0]
    if got != CLOUD_SHA:
        BASE_IMAGE.unlink()
        sys.exit(f"checksum mismatch: {got} != {CLOUD_SHA}")
    say("  checksum ok")


# --- the stub provider ------------------------------------------------------

def make_stub_cert():
    """A throwaway CA-and-leaf-in-one for the stub, issued for PROVIDER.

    The broker has no option to skip upstream verification and should not have
    one, so the stub needs a certificate the broker will actually verify.
    basicConstraints and keyUsage are explicit because Python 3.13+ verifies
    with VERIFY_X509_STRICT and rejects a trust anchor lacking keyCertSign --
    emitting a well-formed certificate keeps this rig testing the broker rather
    than that.

    An existing pair is reused only while it is still VALID. Existence alone is
    not enough: the certificate lives two days and this rig is run by hand, so
    the common case is a rerun after it lapsed -- and a stale one fails on the
    upstream leg, which reads as a broker fault rather than as the rig's own
    leftover.
    """
    cert, key = RIG / "stub-cert.pem", RIG / "stub-key.pem"
    if cert.exists() and key.exists():
        # -checkend is seconds AHEAD, not now: one expiring mid-run is the same
        # failure arriving later and harder to read.
        fresh = run(["openssl", "x509", "-checkend", "3600", "-noout",
                     "-in", str(cert)], check=False, timeout=60)
        if fresh.returncode == 0:
            subject = run(["openssl", "x509", "-noout", "-subject",
                           "-in", str(cert)], check=False, timeout=60).stdout
            if PROVIDER in subject:
                return cert, key
            say(f"  stub certificate is for {subject.strip()!r}, not "
                f"{PROVIDER} — regenerating")
        else:
            say(f"  stub certificate {cert} has expired — regenerating")
        cert.unlink()
        key.unlink(missing_ok=True)
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "2",
         "-subj", f"/CN={PROVIDER}",
         "-addext", f"subjectAltName=DNS:{PROVIDER}",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,digitalSignature"],
        timeout=60)
    # World-readable on purpose: each broker instance reads it as its own
    # DynamicUser, which exists only while that unit does and can be granted
    # nothing ahead of time. It is a public certificate; the key beside it is
    # not, and is not shared.
    cert.chmod(0o644)
    # cert_t, not the var_lib_t it inherits from /var/lib. Both readers are
    # confined -- the inspector runs in wlinspect_t, whose module grants it
    # certificates and not this directory -- so without the relabel the rig's
    # own scaffolding produces an AVC that reads as a trust failure in the
    # thing under test. `restorecon` would undo it; nothing here runs one.
    run(["chcon", "-t", "cert_t", str(cert)], check=False, timeout=60)
    say(f"  generated stub certificate {cert} for {PROVIDER}")
    return cert, key


def start_stub(rigdir, cert, key):
    log = open(RIG / "stub.log", "w")
    stub = subprocess.Popen(
        [sys.executable, str(rigdir / "stub_upstream.py"),
         str(PROVIDER_PORT), str(cert), str(key)],
        stdout=log, stderr=log)
    children.append(stub)
    await_listener("stub provider", PROVIDER_PORT, stub, RIG / "stub.log")


def await_listener(label, port, proc, logfile):
    """Wait for `proc` -- specifically, not merely for the port.

    Matching the pid is the whole point. A check that only asks whether
    SOMETHING is listening is satisfied by a leftover from an earlier run, and
    every downstream result then describes that stranger instead.
    """
    for _ in range(100):
        if proc.poll() is not None:
            say(f"--- {label} died (rc={proc.returncode}) ---")
            say(logfile.read_text()[-2000:])
            sys.exit(f"{label} exited before it listened")
        held = run(["ss", "-lntpH", f"sport = :{port}"], check=False).stdout
        if f"pid={proc.pid}," in held:
            say(f"  {label} listening on :{port} (pid {proc.pid})")
            return
        if held.strip():
            sys.exit(f":{port} is held by something that is not our {label} "
                     f"(pid {proc.pid}):\n{held}")
        time.sleep(0.2)
    sys.exit(f"{label} never listened on :{port}")


# --- host scaffolding: the name, the trust, the material --------------------

def write_hosts_entry():
    """Point PROVIDER at the stub, for the BROKER's lookup only.

    The guests never consult this file and do not need to: their only
    nameserver synthesises every name to their own inspector address. This entry
    exists because the broker resolves its upstream itself, and because
    `vm_broker_upstream_addresses` resolves it a second time at generation to
    build the instance's IPAddressAllow= -- the sole egress bound on that unit,
    since its dynamic uid is not in wl_filtered.
    """
    global hosts_line_written
    with HOSTS_FILE.open("a") as fh:
        fh.write(f"127.0.0.1 {PROVIDER}  {HOSTS_MARK}\n")
    hosts_line_written = True
    say(f"  {HOSTS_FILE}: 127.0.0.1 {PROVIDER}")


def remove_hosts_entry():
    if not hosts_line_written:
        return
    kept = [ln for ln in HOSTS_FILE.read_text().splitlines(True)
            if HOSTS_MARK not in ln]
    HOSTS_FILE.write_text("".join(kept))
    say(f"  {HOSTS_FILE}: rig line removed")


# The two units that dial the stub, and BOTH need to trust it. The broker is
# the obvious one. The inspector is not, and the reason is the prerequisite
# above: it dials the origin over VERIFIED TLS before it reads the request, so
# on a brokered host it must trust the provider's chain even though it will
# send the request somewhere else entirely.
TRUSTING_UNITS = ("broker", "inspect")


def write_trust_dropin(arm, cert):
    """Hand these units the stub's certificate, and nothing else.

    A drop-in under /etc applies to a unit whose fragment the generator wrote
    into /run, which is what makes this possible without touching the generated
    file -- and touching it would be pointless, since it is rewritten at every
    boot.

    SSL_CERT_FILE REPLACES the trust store for the process it is set on. That
    is acceptable here because neither unit dials anything but the stub in this
    rig, and it is the reason the variable is set per unit in a drop-in this
    rig removes rather than anywhere a real workload would inherit it.
    """
    for kind in TRUSTING_UNITS:
        d = Path(f"/etc/systemd/system/workload-{arm.name}-{kind}.service.d")
        d.mkdir(parents=True, exist_ok=True)
        f = d / "10-rig-trust.conf"
        f.write_text(
            "# broker_rig.py — removed at teardown. The stub provider's\n"
            "# certificate, so this unit verifies it the way it verifies a\n"
            "# real one. NOT installed into the host trust store: this rig\n"
            "# must not leave a trust anchor behind on a machine it borrowed.\n"
            "[Service]\n"
            f"Environment=SSL_CERT_FILE={cert}\n")
        dropins_written.append(d)
        say(f"  {f}")


def seal_material():
    """Seal each arm's secret into the credstore the generated unit loads from.

    --key-type host, not tpm2: this must run on a host without a TPM, and the
    property under test is which credential reaches which caller, not how the
    blob was sealed.
    """
    for arm in ARMS:
        blob = RIG / f"{arm.credential}.txt"
        blob.write_text(arm.secret + "\n")
        blob.chmod(0o600)
        run(["workloadctl", "secret", "create",
             f"broker/{arm.name}/{arm.credential}",
             "--file", str(blob), "--key-type", "host", "--force"],
            timeout=120)
        blob.unlink()
        say(f"  sealed broker/{arm.name}/{arm.credential}")


def unseal_material():
    for arm in ARMS:
        subprocess.run(["workloadctl", "secret", "delete",
                        f"broker/{arm.name}/{arm.credential}", "--force"],
                       capture_output=True, text=True, timeout=120)


# --- workloads -------------------------------------------------------------

def toml_for(arm):
    lines = [
        f"# {arm.name} — generated by broker_rig.py. Throwaway; safe to purge.",
        "[workload]",
        f'name = "{arm.name}"',
        "enabled = false",
        "",
        "[vm]",
        # local_image reflinks on btrfs, so two guests cost one copy of the base
        # image rather than two downloads into two per-workload caches.
        f'local_image = "{BASE_IMAGE}"',
        "vcpus = 1",
        'memory = "768M"',
        'user = "workload"',
        "rollback_keep = 1",
        "",
        "[vm.network]",
        # Filtered, and therefore inspected. Both halves are required for a
        # broker instance to exist at all: the inspector is the only thing that
        # dials it, so an instance for an unfiltered VM would hold decrypted
        # material for a path that does not exist, and validation refuses it.
        'egress = "filtered"',
        # No `hosts`. PROVIDER is governed by its [[vm.network.policy]] entry
        # ALONE -- a host with any matching policy entry is not consulted
        # against `hosts` -- so listing it as well would prove nothing and
        # would leave a second explanation for a request that got through.
        "",
        # Every [vm.network] scalar is above this line: the tables below end
        # that section and TOML will not let it be reopened, so a scalar written
        # here is read as a key of the table above it instead.
        "[[vm.network.credential]]",
        f'name        = "{arm.credential}"',
        f'placeholder = "{arm.placeholder}"',
        f'env         = "{GUEST_ENV}"',
    ]
    # Only when the arm names one, so the other arm keeps proving that saying
    # nothing still gets the broker's own default.
    if arm.auth_header:
        lines.append(f'auth_header = "{arm.auth_header}"')
    if arm.auth_format:
        lines.append(f'auth_format = "{arm.auth_format}"')
    lines += [
        "",
        # TWO ENTRIES FOR ONE HOST, sharing one credential, which is the
        # ordinary way to vary methods by path -- and which rendered the host's
        # broker table TWICE until the render collapsed on the host. TOML
        # refuses a table declared twice, so the broker exited at start and
        # every brokered request 502'd, on a config `validate` had just called
        # clean. Written here on purpose: the shape is only covered on hardware
        # if a rig actually deploys it.
        "[[vm.network.policy]]",
        f'host       = "{PROVIDER}"',
        f'credential = "{arm.credential}"',
        'methods    = ["GET"]',
        'paths      = ["/v1/*"]',
        "",
        "[[vm.network.policy]]",
        f'host       = "{PROVIDER}"',
        f'credential = "{arm.credential}"',
        'methods    = ["POST"]',
        'paths      = ["/v2/*"]',
        "",
        # NO [[vm.network.internal]] ENTRY, AND THAT IS AN ASSERTION.
        #
        # This rig needed one until the origin dial was fixed.
        # `_serve_tls_inspect` used to dial the ORIGIN over verified TLS before
        # reading the request -- always, including on a host the request would
        # then be brokered to -- so a credential-backed host had to be reachable
        # AND verifiable from the workload uid even though nothing was ever sent
        # there. The stub answers on the host's own loopback, so without an
        # exemption the guest got a 502 reading `internal destination`, naming
        # an origin the request would never have gone to.
        #
        # A brokered host is no longer dialled at the origin at all, so the
        # exemption is unnecessary -- and its absence here is the only check
        # that says so on hardware. If the origin dial ever comes back, this rig
        # fails on the first probe with that same `internal destination`, which
        # is a far better signal than an exemption quietly covering for it.
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
    # Before enable, and not as a formality. This rig's TOML is generated by no
    # gate that can see a schema change, and a config refused at enable produces
    # no VM, no listener and no broker -- the same surface a missing SELinux
    # grant produces. `validate` also reads the credstore, so a credential that
    # was never sealed is named HERE rather than presenting as a broker that
    # will not start.
    for arm in ARMS:
        p = run(["workloadctl", "validate", arm.name], check=False, timeout=120)
        if p.returncode != 0:
            say(p.stdout[-3000:])
            say(p.stderr[-3000:])
            sys.exit(f"validate {arm.name} failed — the rig's own config is "
                     f"stale against the schema, which looks exactly like the "
                     f"thing under test")
        say(f"  {arm.name} validates")
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


# --- guards: is the posture under test actually in force? -------------------

def guards():
    say("== guards (before any probe) ==")
    addresses = {}
    for arm in ARMS:
        uid = uid_of(arm.name)
        addresses[arm.name] = broker_address(uid)

        unit = f"workload-{arm.name}-broker.service"
        state = run(["systemctl", "is-active", unit], check=False).stdout.strip()
        record(f"{arm.name} has a broker instance of its own",
               state == "active", f"{unit} is {state!r}")

        want = f"{addresses[arm.name]}:{BROKER_PORT}"
        held = run(["ss", "-lntH", f"sport = :{BROKER_PORT}"],
                   check=False).stdout
        record(f"{arm.name} listens on its uid-derived address",
               want in held.replace("\t", " ").replace("  ", " ") or
               any(want in line for line in held.split()),
               f"want {want} among {held.split() or ['<nothing>']}")

    # The two negatives the design turns on, asserted rather than inferred from
    # the positive above: 127.0.0.1 and 0.0.0.0 both put one workload's broker
    # where every other workload's inspector is dialling.
    record("the two instances are on different addresses",
           addresses["wlbrk-a"] != addresses["wlbrk-b"],
           f"{addresses}")
    record("neither instance is on a shared address",
           not ({"127.0.0.1", "0.0.0.0"} & set(addresses.values())),
           f"{addresses}")

    for arm in ARMS:
        # The generated config holds every credential NAME this instance loads
        # and must not be readable by the uid a guest escape obtains.
        cfg = f"{BROKER_RUNDIR}/{arm.name}/{BROKER_CONFIG}"
        p = run(["setpriv", f"--reuid={uid_of(arm.name)}",
                 f"--regid={gid_of(arm.name)}", "--clear-groups",
                 "cat", cfg], check=False, timeout=60)
        record(f"{arm.name} broker config is unreadable by the workload uid",
               p.returncode != 0 and arm.credential not in p.stdout,
               f"rc={p.returncode} stdout={p.stdout[:80]!r}")

    for arm in ARMS:
        r = guest(arm.name, f'echo "[${GUEST_ENV}]"')
        val = r.stdout.strip()
        record(f"{arm.name} guest holds the placeholder",
               val == f"[{arm.placeholder}]",
               f"{val} (want [{arm.placeholder}])")

    for arm in ARMS:
        # The negative that matters more than the positive above, and asked of
        # the WHOLE environment rather than of the one variable: a key that
        # leaked into the guest under any other name is the failure this design
        # exists to prevent.
        r = guest(arm.name, "env")
        record(f"{arm.name} guest environment holds no secret at all",
               not any(a.secret in r.stdout for a in ARMS),
               f"env has {len(r.stdout.splitlines())} lines, none matching "
               f"{[a.secret for a in ARMS]}")
    return addresses


# --- probes ----------------------------------------------------------------

def stub_body(text):
    """The stub's JSON, or None. It reports which credential arrived, which is
    the only reading that tells a working substitution from a 200."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None


def claim_1_and_4():
    """A guest reaches the provider; the key it never held arrives there."""
    say("== claims 1 and 4: the guest, the placeholder, and the key ==")
    seen = {}
    for arm in ARMS:
        # THE GUEST SENDS ITS PLACEHOLDER, in the header a real client would
        # put it in. Without this the guest sends no credential header at all,
        # the "no placeholder reached the provider" assertion below is
        # vacuously true, and a broker that was bypassed entirely looks
        # identical to one that substituted correctly -- which is exactly how
        # this rig's first green-ish run read before the pool-key defect was
        # found. The fiction has to be on the wire for its replacement to be
        # observable.
        r = guest(arm.name,
                  CURL + f'-H "{arm.header}: ${GUEST_ENV}" '
                  f'https://{PROVIDER}/v1/models')
        body, code, rc = parse(r)
        doc = stub_body(body)
        # `x-api-key`, not `Authorization`, and that is the BROKER's default
        # rather than a choice this rig made: render_vm_broker_config emits
        # neither `auth_header` nor `auth_format`, so every generated instance
        # runs the broker's own defaults (`x-api-key: {secret}`). A workload
        # cannot currently name a provider that wants `Authorization: Bearer`.
        auth = (doc or {}).get(arm.header.lower(), "")
        seen[arm.name] = auth
        record(f"{arm.name} reaches {PROVIDER} and the BROKER's key arrives "
               f"in {arm.header}",
               code == "200" and auth == arm.sent_value,
               f"rc={rc} http={code} {arm.header}={auth!r} "
               f"(want {arm.sent_value!r})")
        record(f"{arm.name} never sent its own placeholder upstream",
               arm.placeholder not in body,
               f"body={body[:160]!r} — the guest DID send the placeholder, so "
               f"its arrival at the provider means the request never went "
               f"through the broker at all")

    # Claim 4. Same name, same request, two guests. Asserted on the pair as
    # well as on each, because two instances both serving key-a would satisfy
    # one of the two assertions above and this is what sees it.
    record("the two workloads are told apart",
           (seen["wlbrk-a"] == BY_NAME["wlbrk-a"].sent_value
            and seen["wlbrk-b"] == BY_NAME["wlbrk-b"].sent_value
            and seen["wlbrk-a"] != seen["wlbrk-b"]),
           f"a={seen['wlbrk-a']!r} b={seen['wlbrk-b']!r}")


def claim_2(addresses):
    """A Host the broker does not know is refused -- and the controls that make
    that refusal mean what it says."""
    say("== claim 2: an unknown Host, and the three controls ==")
    arm = BY_NAME["wlbrk-a"]
    addr = addresses[arm.name]
    uid, gid = uid_of(arm.name), gid_of(arm.name)

    def dial(as_uid, as_gid, host, label):
        argv = []
        if as_uid is not None:
            argv = ["setpriv", f"--reuid={as_uid}", f"--regid={as_gid}",
                    "--clear-groups"]
        argv += ["curl", "-sS", "-m", "15", "-w", "\nHTTP:%{http_code}",
                 "-H", f"Host: {host}",
                 f"http://{addr}:{BROKER_PORT}/v1/models"]
        p = run(argv, check=False, timeout=60)
        body, code, rc = parse(p)
        say(f"    {label}: rc={rc} http={code} body={body[:120]!r}")
        return body, code, rc

    # The control FIRST, so a refusal below cannot be a rig that never reached
    # a broker at all.
    body, code, _ = dial(uid, gid, PROVIDER, "control: the Host it does know")
    record("the workload uid reaches its own broker for a known Host",
           code == "200" and arm.secret in body,
           f"http={code} — without this, every refusal below is also "
           f"consistent with nothing listening")

    body, code, _ = dial(uid, gid, UNKNOWN_HOST, "the unknown Host")
    record("an unknown Host is refused, carrying no credential",
           (code == "403" and DENY_UNKNOWN_HOST in body
            and not any(a.secret in body for a in ARMS)),
           f"http={code} body={body[:160]!r} — 200 would mean a credential "
           f"was attached to a destination no config named, and the CALLER "
           f"refusal is also a 403, which is why the sentence is matched")

    # Root, against the same address and the same known Host. Without this, the
    # 403 above is equally consistent with a broker that has stopped checking
    # WHO is calling and refuses on the Host alone.
    body, code, _ = dial(None, None, PROVIDER, "control: root")
    record("root is not served, at the same address and Host",
           (code == "403" and DENY_UNKNOWN_CALLER in body
            and not any(a.secret in body for a in ARMS)),
           f"http={code} body={body[:160]!r} — refused for its CALLER, which "
           f"is the half the unknown-Host probe cannot show")

    # The cross-workload claim, stated positively. Both instances are on the
    # same host's loopback: nothing but the uid check keeps b's caller out of
    # a's credential.
    other = BY_NAME["wlbrk-b"]
    body, code, _ = dial(uid_of(other.name), gid_of(other.name), PROVIDER,
                         "control: the other workload's uid")
    record("the other workload's uid gets nothing from this instance",
           (code == "403" and DENY_UNKNOWN_CALLER in body
            and not any(a.secret in body for a in ARMS)),
           f"http={code} body={body[:160]!r} — a's key reaching b's uid is "
           f"the hole ADR 007 decision 6 closes")


def claim_3(addresses):
    """A guest dialling the broker's address reaches its own loopback."""
    say("== claim 3: the guest cannot dial the broker ==")
    for arm in ARMS:
        for target_name, addr in sorted(addresses.items()):
            which = "its own" if target_name == arm.name else "the other's"
            r = guest(arm.name,
                      CURL + f'http://{addr}:{BROKER_PORT}/v1/models')
            body, code, rc = parse(r)
            record(f"{arm.name} dialling {which} broker address reaches "
                   f"nothing",
                   rc != 0 and code != "200"
                   and not any(a.secret in body for a in ARMS),
                   f"{addr}:{BROKER_PORT} rc={rc} http={code} "
                   f"body={body[:120]!r} — inside the guest this is the "
                   f"guest's OWN loopback, and nothing listens there")


def the_record():
    """The T5 seam: does the inspector say the request went to the broker?

    `upstream` is honestly the broker's address on a brokered request, and
    `credential` is the name of the material that rode along -- which is what
    makes a loopback `upstream` legible rather than alarming. Neither field can
    be checked by a unit test against a real dial.
    """
    say("== the record ==")
    for arm in ARMS:
        f = RECORD_ROOT / arm.name / RECORD_FILE
        if not f.exists():
            record(f"{arm.name} wrote an egress record", False, f"no {f}")
            continue
        rows = []
        for line in f.read_text().splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        brokered = [r for r in rows if r.get("host") == PROVIDER]
        record(f"{arm.name} recorded the request to {PROVIDER}",
               bool(brokered), f"{len(rows)} rows, {len(brokered)} for the host")
        if not brokered:
            continue
        row = brokered[-1]
        record(f"{arm.name} record names the credential that rode along",
               row.get("credential") == arm.credential,
               f"credential={row.get('credential')!r} "
               f"(want {arm.credential!r})")
        record(f"{arm.name} record's upstream is its own broker",
               str(row.get("upstream", "")).startswith(
                   broker_address(uid_of(arm.name))),
               f"upstream={row.get('upstream')!r} "
               f"(want {broker_address(uid_of(arm.name))}:{BROKER_PORT})")
        record(f"{arm.name} record carries no credential MATERIAL",
               not any(a.secret in json.dumps(row) for a in ARMS),
               f"row={json.dumps(row)[:200]!r} — the record names which "
               f"credential, never which key")


def selinux(since):
    """T5's new grant, asserted on the audit log rather than on the outcome.

    The dial to the broker is a new access for wlinspect_t. A denial on it is
    SILENT by construction: the connect fails, the listener counts a dead
    broker, and the guest gets a 502 naming the broker -- which is exactly what
    a broker that is genuinely down produces. So a green run of the claims above
    does NOT establish that the grant is present, only that nothing needed it
    yet. Reading the log is what tells those apart.

    ausearch is not used: it reports zero events for -ts boot on at least one
    host in this fleet while the log itself holds hundreds, so the log is read
    directly.
    """
    say("== SELinux ==")
    if run(["sh", "-c", "command -v getenforce"], check=False).returncode == 0:
        mode = run(["getenforce"], check=False).stdout.strip()
    else:
        mode = "unknown"
    record("the host is enforcing",
           mode == "Enforcing",
           f"getenforce says {mode!r} — a permissive run measures the branch "
           f"that ran, not the one policy would have allowed")
    if not AUDIT_LOG.exists():
        record("audit log is readable", False, f"no {AUDIT_LOG}")
        return
    denials = []
    for line in AUDIT_LOG.read_text(errors="replace").splitlines():
        if "avc:" not in line or "denied" not in line:
            continue
        m = re.search(r"\bmsg=audit\((\d+)", line)
        if m and float(m.group(1)) < since:
            continue
        if INSPECT_DOMAIN not in line and "agent-broker" not in line:
            continue
        if is_known_ungranted(line):
            continue
        denials.append(line[-300:])
    record(f"no {INSPECT_DOMAIN} or broker denial during this run",
           not denials,
           "\n      ".join(denials) if denials
           else f"0 unexplained AVCs since the run started (the documented "
                f"stdout probe is excluded by shape, not by domain)")


# --- teardown ---------------------------------------------------------------

def teardown():
    say("== teardown ==")
    for p in children:
        p.terminate()
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()
    for arm in ARMS:
        subprocess.run(["workloadctl", "disable", arm.name, "--purge"],
                       capture_output=True, text=True, timeout=300)
        # --purge owns the workload's state, not a config directory somebody
        # else created, so the rig removes what the rig wrote. Left behind,
        # these show up in `workloadctl list` on a borrowed machine.
        shutil.rmtree(Path("/etc/workloads.d") / arm.name, ignore_errors=True)
        say(f"  purged {arm.name}")
    unseal_material()
    for d in dropins_written:
        shutil.rmtree(d, ignore_errors=True)
        say(f"  removed {d}")
    if dropins_written:
        subprocess.run(["systemctl", "daemon-reload"],
                       capture_output=True, text=True, timeout=120)
    remove_hosts_entry()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true",
                    help="leave the guests, the stub and the scaffolding up")
    args = ap.parse_args()
    rigdir = Path(__file__).resolve().parent

    preflight()
    fetch_base_image()
    since = time.time()
    try:
        # Host scaffolding first, and in this order. The name has to resolve
        # before `enable`, because generation resolves it to build the broker
        # unit's IPAddressAllow= -- the sole egress bound on that unit -- and a
        # unit generated before the entry exists reaches nothing, which presents
        # as the provider being down.
        write_hosts_entry()
        cert, key = make_stub_cert()
        for arm in ARMS:
            write_trust_dropin(arm, cert)
        run(["systemctl", "daemon-reload"], timeout=120)
        start_stub(rigdir, cert, key)
        seal_material()
        deploy()
        addresses = guards()
        claim_1_and_4()
        claim_2(addresses)
        claim_3(addresses)
        the_record()
        selinux(since)
    finally:
        if args.keep:
            say("== --keep: leaving everything up ==")
        else:
            teardown()

    say("\n== summary ==")
    failed = [r for r in results if not r[1]]
    for label, ok, _detail in results:
        say(f"  {'PASS' if ok else 'FAIL'}  {label}")
    say(f"\n{len(results) - len(failed)}/{len(results)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
