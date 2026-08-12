#!/usr/bin/env python3
"""broker_rig.py — does a VM actually reach the credential broker, and can the
broker tell two guests apart?

Run this ON a KVM host with the workloadctl RPM installed. It boots four
throwaway VM workloads, runs a broker and a stub upstream on the host, and
probes the broker from inside each guest.

WHY FOUR GUESTS

Every unit test on both sides of this passes today. What none of them can reach
is whether the kernel, the guest, and two separate repos' constants agree in a
live system -- and the two defects found while building this both lived in
*combinations*, invisible to the simplest possible test:

  * the client records the address it DIALLED, not the one the broker is bound
    to, so a match on getsockname() alone finds nothing -- while every loopback
    test passes, loopback being the one path with nothing to translate;
  * a guest with both a proxy and a broker sends its broker request THROUGH the
    proxy, which answers 403 -- indistinguishable from the broker refusing an
    unauthorised caller.

So the arms here are the combinations. Each differs from `a` in exactly one
line, which is what makes a failure attributable:

  a  proxy + broker, key-a   the realistic configuration
  b  proxy + broker, key-b   differs from a only in NAME -> identity
  c  broker, no proxy        differs from a only in `hosts` -> the direct path
  d  proxy, no broker        differs from a only in `broker` -> entitlement

a vs b is the identity claim: same advertised literal dialled, different uid,
different credential comes back. a vs d is the reachability claim, which is
separate and fails independently -- d has no map element, so nothing translates
its packet and nothing is listening where it lands. A test with only one guest
proves neither.

The probe on `a` through an explicitly forced proxy is the regression test for
the NO_PROXY fix: it must 403 while the default probe on the same guest returns
200. Without it a green run is also consistent with a proxy configured wide
open, which would make the default probe succeed for the wrong reason.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

RIG = Path("/var/lib/broker-rig")
BASE_IMAGE = RIG / "base.qcow2"
CREDS = RIG / "creds"

CLOUD_URL = ("https://download.fedoraproject.org/pub/fedora/linux/releases/44/"
             "Cloud/x86_64/images/Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2")
CLOUD_SHA = "28680fe5b371a5a82ebf43a31926e086a168e59949d03969c5093e7071f90b7f"

# These four must match lib/vm.py. They are spelled out rather than imported
# because a rig that computes both sides from one constant cannot notice them
# drifting apart -- which is the exact failure this rig exists to catch.
ADVERTISED = "192.0.2.1"
BROKER_PORT = 8081
PROXY_PORT = 3128
BROKER_LISTEN = ("127.0.0.1", 8081)

STUB_PORT = 19999
DNS_ALLOW = "1.1.1.1:53"
PROXY_HOST = "example.com"


@dataclass(frozen=True)
class Arm:
    name: str
    proxy: bool
    broker: bool
    credential: str | None


ARMS = [
    Arm("rt-broker-a", proxy=True, broker=True, credential="key-a"),
    Arm("rt-broker-b", proxy=True, broker=True, credential="key-b"),
    Arm("rt-broker-c", proxy=False, broker=True, credential="key-c"),
    Arm("rt-broker-d", proxy=True, broker=False, credential=None),
]
BY_NAME = {a.name: a for a in ARMS}

results: list[tuple[str, bool, str]] = []

# Every child we start, appended as it is started rather than returned at the
# end. An earlier version returned the pair, so an exit *between* the two
# starts leaked the first one -- and the leaked plaintext stub then satisfied
# the next run's readiness check and made the broker look like it had a TLS
# fault. Teardown reads this list, so a child is reachable from the moment it
# exists.
children: list[subprocess.Popen] = []


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
    """Run a bash login shell in the guest. Login shell so profile.d applies as
    well as PAM's /etc/environment -- the two places the guest env is written,
    and a probe that used only one would not notice the other going missing."""
    return subprocess.run(
        ["workloadctl", "exec", name, "--", "bash", "-lc", script],
        capture_output=True, text=True, timeout=timeout)


# --- preflight -------------------------------------------------------------

def preflight():
    say("== preflight ==")
    if os.geteuid() != 0:
        sys.exit("run as root: it enables workloads and reads the ruleset")
    for tool in ("workloadctl", "qemu-system-x86_64", "qemu-img", "socat",
                 "nft", "tinyproxy", "passt"):
        if run(["sh", "-c", f"command -v {tool}"], check=False).returncode != 0:
            sys.exit(f"missing {tool}")
    if not Path("/dev/kvm").exists():
        sys.exit("no /dev/kvm")
    # A stale listener on EITHER port silently takes traffic that should have
    # gone to a process this run started, and the result reads as a fault in
    # whatever is downstream of it.
    for port in (BROKER_LISTEN[1], STUB_PORT):
        busy = run(["ss", "-lntH", f"sport = :{port}"], check=False)
        if busy.stdout.strip():
            sys.exit(f"something already listens on :{port} — a leftover from "
                     f"an earlier run will make this one lie:\n{busy.stdout}")
    say(f"  ok: toolchain, /dev/kvm, ports {BROKER_LISTEN[1]} and {STUB_PORT} free")


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


# --- the broker and its stub upstream --------------------------------------

def make_stub_cert():
    """A throwaway CA-and-leaf-in-one for the stub, trusted by the broker only.

    The broker has no option to skip upstream verification and should not have
    one, so the stub needs a certificate the broker will actually verify. It is
    handed over through SSL_CERT_FILE on the broker process rather than
    installed into the host's trust store: this rig must not leave a trust
    anchor behind on a machine it borrowed.

    basicConstraints and keyUsage are set explicitly because Python 3.13+
    verifies with VERIFY_X509_STRICT, which rejects a trust anchor lacking
    keyCertSign -- the same defect the design doc's relax_x509_strict exists
    for. Emitting a well-formed cert here keeps the rig testing the broker
    rather than that.
    """
    cert, key = RIG / "stub-cert.pem", RIG / "stub-key.pem"
    if cert.exists() and key.exists():
        return cert, key
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "2",
         "-subj", "/CN=localhost",
         "-addext", "subjectAltName=DNS:localhost",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,digitalSignature"],
        timeout=60)
    say(f"  generated stub certificate {cert}")
    return cert, key


def broker_config():
    lines = [
        # localhost, not 127.0.0.1: the broker requires a hostname, and the
        # certificate is issued for one.
        f'upstream = "https://localhost:{STUB_PORT}"',
        'credential = "key-default"',
        'auth_header = "Authorization"',
        'auth_format = "Bearer {secret}"',
        f'listen_address = "{BROKER_LISTEN[0]}"',
        f'listen_port = {BROKER_LISTEN[1]}',
        # False on purpose: an unregistered caller must 403. With this true the
        # d arm could not tell "refused" from "served as a stranger".
        'allow_unknown_callers = false',
        'connect_timeout = 5.0',
        'read_timeout = 30.0',
        '',
    ]
    for arm in ARMS:
        if arm.credential:
            lines += [f'[sandboxes.{arm.name}]',
                      f'credential = "{arm.credential}"', '']
    return "\n".join(lines)


def start_services(rigdir):
    say("== host services ==")
    CREDS.mkdir(parents=True, exist_ok=True)
    CREDS.chmod(0o700)
    (CREDS / "key-default").write_text("SECRET-DEFAULT\n")
    for arm in ARMS:
        if arm.credential:
            (CREDS / arm.credential).write_text(f"SECRET-{arm.name}\n")

    cfg = RIG / "broker.toml"
    cfg.write_text(broker_config())

    cert, key = make_stub_cert()
    stub_log = open(RIG / "stub.log", "w")
    broker_log = open(RIG / "broker.log", "w")
    stub = subprocess.Popen([sys.executable, str(rigdir / "stub_upstream.py"),
                             str(STUB_PORT), str(cert), str(key)],
                            stdout=stub_log, stderr=stub_log)
    children.append(stub)
    env = {**os.environ, "CREDENTIALS_DIRECTORY": str(CREDS),
           "SSL_CERT_FILE": str(cert)}
    broker = subprocess.Popen([sys.executable, str(rigdir / "broker.py"), str(cfg)],
                              stdout=broker_log, stderr=broker_log, env=env)
    children.append(broker)

    for label, port, proc, logfile in (
            ("stub upstream", STUB_PORT, stub, RIG / "stub.log"),
            ("broker", BROKER_LISTEN[1], broker, RIG / "broker.log")):
        await_listener(label, port, proc, logfile)


def await_listener(label, port, proc, logfile):
    """Wait for `proc` -- specifically, not merely for the port.

    Matching the pid is the whole point. A check that only asks whether
    something is listening is satisfied by a leftover from an earlier run, and
    then every downstream result describes that stranger instead: a plaintext
    stub answering where a TLS one should be reads as a TLS fault in the
    broker, which is a long way from the truth.
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


# --- workloads -------------------------------------------------------------

def toml_for(arm):
    lines = [
        f"# {arm.name} — generated by broker_rig.py. Throwaway; safe to purge.",
        "[workload]",
        f'name = "{arm.name}"',
        "enabled = false",
        "",
        "[vm]",
        # local_image reflinks on btrfs, so four guests cost one copy of the
        # base image rather than four downloads into four per-workload caches.
        f'local_image = "{BASE_IMAGE}"',
        "vcpus = 1",
        'memory = "768M"',
        'user = "workload"',
        "rollback_keep = 1",
        "",
        "[vm.network]",
        # Filtered on every arm, including the ones without a proxy: the broker
        # path crosses the filter chain, and an `open` arm would not show that
        # the loopback exemption is what lets it through.
        'egress = "filtered"',
        f'allow = ["{DNS_ALLOW}"]',
    ]
    if arm.proxy:
        lines.append(f'hosts = ["{PROXY_HOST}"]')
    if arm.broker:
        lines.append("broker = true")
    return "\n".join(lines) + "\n"


def deploy():
    say("== deploying four guests ==")
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


# --- guards: is the posture under test actually in force? -------------------

def uid_of(name):
    return int(run(["id", "-u", f"_wl-{name}"]).stdout.strip())


def broker_map():
    """uid -> "addr:port" from the live ruleset, parsed rather than grepped: a
    regex would also match handles and table ids, and an empty result has to
    mean "nothing is armed" rather than "the pattern missed"."""
    p = run(["nft", "-j", "list", "map", "inet", "workload_broker",
             "wl_broker_dest"], check=False)
    if p.returncode != 0:
        return {}
    out = {}
    for item in json.loads(p.stdout).get("nftables", []):
        if "map" not in item:
            continue
        for elem in item["map"].get("elem", []) or []:
            if not (isinstance(elem, list) and len(elem) == 2):
                continue
            key, val = elem
            if isinstance(key, dict) and "elem" in key:
                key = key["elem"].get("val", key)
            try:
                uid = int(key)
            except (TypeError, ValueError):
                continue
            parts = val.get("concat", []) if isinstance(val, dict) else []
            if len(parts) == 2:
                out[uid] = f"{parts[0]}:{parts[1]}"
    return out


def guards():
    say("== guards (before any probe) ==")
    armed = broker_map()
    want = f"{BROKER_LISTEN[0]}:{BROKER_LISTEN[1]}"
    for arm in ARMS:
        uid = uid_of(arm.name)
        got = armed.get(uid)
        if arm.broker:
            record(f"{arm.name} has a map element",
                   got == want,
                   f"uid {uid} -> {got!r} (want {want!r}); armed={armed}")
        else:
            record(f"{arm.name} has NO map element",
                   got is None,
                   f"uid {uid} -> {got!r}; armed={armed}")

    for arm in ARMS:
        r = guest(arm.name, 'echo "[${WORKLOAD_BROKER_URL}]"')
        val = r.stdout.strip()
        want_url = f"[http://{ADVERTISED}:{BROKER_PORT}]"
        if arm.broker:
            record(f"{arm.name} guest env carries the endpoint",
                   val == want_url, f"{val} (want {want_url})")
        else:
            record(f"{arm.name} guest env has no endpoint", val == "[]", val)

    for arm in ARMS:
        r = guest(arm.name, 'echo "[${NO_PROXY}]"')
        if arm.proxy:
            record(f"{arm.name} NO_PROXY covers the advertised address",
                   ADVERTISED in r.stdout, r.stdout.strip())
        else:
            record(f"{arm.name} has no proxy variables",
                   r.stdout.strip() == "[]", r.stdout.strip())


# --- probes ----------------------------------------------------------------

CURL = 'curl -sS -m 20 -w "\\nHTTP:%{http_code}" '


def parse(r):
    body = r.stdout
    code = ""
    if "HTTP:" in body:
        body, _, code = body.rpartition("HTTP:")
    return body.strip(), code.strip(), r.returncode


def probes():
    say("== probes ==")
    for arm in ARMS:
        if not arm.broker:
            continue
        r = guest(arm.name, CURL + '"$WORKLOAD_BROKER_URL/v1/models"')
        body, code, rc = parse(r)
        want = f"SECRET-{arm.name}"
        ok = code == "200" and want in body
        record(f"{arm.name} reaches the broker and gets its OWN credential",
               ok, f"rc={rc} http={code} body={body[:160]!r} want {want!r}")

    # Two guests, two credentials, one advertised literal. This is the claim.
    bodies = {}
    for name in ("rt-broker-a", "rt-broker-b"):
        r = guest(name, CURL + '"$WORKLOAD_BROKER_URL/v1/models"')
        bodies[name] = parse(r)[0]
    record("a and b are told apart",
           ("SECRET-rt-broker-a" in bodies["rt-broker-a"]
            and "SECRET-rt-broker-b" in bodies["rt-broker-b"]
            and bodies["rt-broker-a"] != bodies["rt-broker-b"]),
           f"a={bodies['rt-broker-a'][:90]!r} b={bodies['rt-broker-b'][:90]!r}")

    # The regression test for the NO_PROXY fix: this is what the guest did
    # before it, and it must not work. `env -u` rather than curl's --noproxy
    # because it reproduces the pre-fix condition exactly -- the variables
    # simply not naming the advertised address -- instead of depending on how
    # a given curl parses an empty bypass list.
    #
    # The assertion is on the CREDENTIAL, not the status. A status check calls
    # 502 a pass, and 502 is what the broker returns when it has already
    # identified the caller and is talking upstream -- i.e. the request got
    # through, which is the opposite of what this claims to show.
    r = guest("rt-broker-a",
              "env -u NO_PROXY -u no_proxy " + CURL
              + f'--proxy http://{ADVERTISED}:{PROXY_PORT} '
                f'http://{ADVERTISED}:{BROKER_PORT}/v1/models')
    body, code, rc = parse(r)
    leaked = "SECRET-rt-broker-a" in body
    record("a forced through the proxy never reaches the broker",
           code == "403" and not leaked,
           f"rc={rc} http={code} body={body[:160]!r} — want 403 from the proxy; "
           f"502 would mean it reached the broker anyway, 200 would mean the "
           f"proxy is carrying broker traffic")

    # No map element -> no translation -> nothing listening where it lands.
    r = guest("rt-broker-d",
              CURL + f'http://{ADVERTISED}:{BROKER_PORT}/v1/models')
    body, code, rc = parse(r)
    refused = rc != 0 and code != "200"
    record("d cannot reach the broker at all",
           refused,
           f"rc={rc} http={code} body={body[:160]!r} "
           f"(a 403 here would mean it CONNECTED and was identified as a "
           f"stranger -- reachability, not identity, is what d tests)")


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
        # --purge owns the workload's state, not a config directory someone
        # else created, so this rig has to remove what this rig wrote. Left
        # behind, they show up in `workloadctl list` on a borrowed machine.
        shutil.rmtree(Path("/etc/workloads.d") / arm.name, ignore_errors=True)
        say(f"  purged {arm.name}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true",
                    help="leave the guests and services running for debugging")
    args = ap.parse_args()
    rigdir = Path(__file__).resolve().parent

    preflight()
    fetch_base_image()
    try:
        # Services first. They are cheap and their config is the likeliest
        # thing to be wrong, and finding that out after a four-guest boot
        # costs minutes per attempt. Starting the broker before the workload
        # users exist is harmless: profiles are keyed by name and the uid is
        # resolved per request, not at startup.
        start_services(rigdir)
        deploy()
        guards()
        probes()
    finally:
        if args.keep:
            say("== --keep: leaving everything up ==")
        else:
            teardown()

    say("\n== summary ==")
    failed = [r for r in results if not r[1]]
    for label, ok, detail in results:
        say(f"  {'PASS' if ok else 'FAIL'}  {label}")
    say(f"\n{len(results) - len(failed)}/{len(results)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
