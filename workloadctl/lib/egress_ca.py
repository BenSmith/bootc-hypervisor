#!/usr/bin/env python3
"""The per-workload egress CA, the leaves it signs, and where all of it lives.

One CA per workload rather than one per host, and the directory names, the
validity windows and the two openssl invocations are all here together
because they are one decision each spelled in several places: the minter
creates the directories, the SELinux patterns label them
(workload_selinux.pki_fcontext_patterns composes the names here with the
workload's root and its own types), and `diagnose` reads the certificate
back. A drift between any two of those is a mislabelled directory or an
untrusted anchor, and both present as a network fault rather than as a
naming mistake. Where the anchor goes inside the guest is guest_ca's.

Both substrates, despite the `vm_`/`VM_` prefixes -- the container half mints
against the same CA through the same minter.

On the listener's side of the line: this module takes a STATE DIRECTORY and
knows nothing about which workload it belongs to or how workloadctl found it.
It imports inspect_document and nothing above it, so the inspector's closure
stays free of the config grammar. Nothing here runs openssl or touches the
filesystem; it builds paths and argv, and lib/egress_mint.py is what executes
them.

Installed to /usr/libexec/workloadctl/egress_ca.py.
"""

import ipaddress
import time
from pathlib import Path

from inspect_document import normalise_hostname


# --- The per-workload egress CA ---
#
# One CA per workload, generated like the SSH host keypair: idempotent, made
# once, NEVER churned, and created before the seed ISO that carries it.
#
# Per-workload scoping is what makes the key affordable. It lives in the
# workload's state directory owned by _wl-<name> -- the same uid QEMU runs as --
# and the only party trusting it is the guest that uid already owns, so a guest
# escape stealing it gains the ability to impersonate sites TO ITSELF. A single
# host-wide CA shared by every workload would be a genuine crown jewel.
#
# `backup` never captures state/, so the key is in no archive and needs no
# exclusion rule.

CA_DIR_NAME = "ca"
CA_KEY_NAME = "egress-ca.key"
CA_CERT_NAME = "egress-ca.crt"


# The two leaf caches live beside the CA, under the same state directory, and
# their names are here rather than in egress_mint because the SELinux patterns
# in workload_selinux have to name the same three directories the minter
# creates. A drift between the two spellings is a mislabelled directory, which
# presents as the inspector failing to mint and not as a naming mistake.
LEAF_DIR_NAME = "leaves"
DENIAL_DIR_NAME = "leaves-denied"


# Ten years. The number follows from never rotating rather than from any threat
# estimate: a CA that expires is a CA that must be replaced, replacing it means
# re-provisioning the guest (cloud-init runs once per instance-id), so the
# validity is the real upper bound on a VM's life. Ten years puts that boundary
# beyond the hardware's, which is the point -- anything shorter schedules a
# total outage, every HTTPS request failing validation on a VM `diagnose` calls
# healthy, for a date nobody wrote down.
#
# Distance is not the same as invisibility: the CA report carries notAfter and
# `diagnose` warns inside the last year, so a workload that lives long enough
# to reach it gets a re-provision SCHEDULED rather than discovered.
CA_VALIDITY_DAYS = 3650


# notBefore is backdated an hour for clock skew. Guest drift is ~10 ppm
# (about five minutes a year), so this covers roughly 1,200
# years of it -- and exactly ONE HOUR of a vCPU pause, which a guest loses
# permanently. The backdate is not what makes pauses survivable; the clock
# keeper (lib/vm_clock.py, once a minute per VM) is. What the backdate buys
# is that a pause SHORTER than an hour, and the keeper's own one-minute
# window after a longer one, cost the guest nothing at all.
CA_BACKDATE_SECONDS = 3600


def ca_dir(state_dir) -> Path:
    """Where this workload's egress CA lives, given its state directory."""
    return Path(state_dir) / CA_DIR_NAME


def ca_key_path(state_dir) -> Path:
    return ca_dir(state_dir) / CA_KEY_NAME


def ca_cert_path(state_dir) -> Path:
    return ca_dir(state_dir) / CA_CERT_NAME


def leaf_dir(state_dir) -> Path:
    """Where the working set of minted leaves lives."""
    return Path(state_dir) / LEAF_DIR_NAME


def denial_dir(state_dir) -> Path:
    """Where leaves minted under a refusal live -- a sibling of the working
    set, not a subdirectory, so a `rm -rf` of one cannot take the other."""
    return Path(state_dir) / DENIAL_DIR_NAME


def ca_subject(name: str) -> str:
    """The CA's subject. Names the workload, because an operator reading a
    certificate error inside a guest needs to know which CA it came from."""
    return f"/CN=workloadctl egress CA ({name})"


def ca_openssl_argv(name: str, key_path, cert_path, *, now: float) -> list[str]:
    """One `openssl req -x509` invocation that mints the CA.

    THE THREE EXTENSIONS ARE NOT DECORATION. Python 3.14's ssl (OpenSSL 3.5)
    rejects a chain whose CA lacks a Subject Key Identifier
    with `certificate verify failed: Missing Authority Key Identifier`, and
    then -- once that is added -- with `CA cert does not include key usage
    extension`. curl, Go and Node accept the same CA without any of them, so a
    CA missing them works everywhere until a Python client tries, and presents
    as a trust failure indistinguishable from "the guest never installed our
    CA". They are asserted by parsing the certificate, not by matching this
    argv: what matters is what OpenSSL emitted, not what we asked for.

    `-not_before` is used rather than letting notBefore default to now, so the
    hour of skew tolerance is a property of the certificate rather than of when
    the process happened to run. Requires OpenSSL 3.5, which is what Fedora 43
    and 44 ship.

    ECDSA P-256 to match the leaves: RSA-2048 minting is slow enough to be
    noticeable on a cold cache.
    """
    not_before = time.strftime(
        "%Y%m%d%H%M%SZ", time.gmtime(now - CA_BACKDATE_SECONDS))
    return [
        "openssl", "req", "-x509",
        "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-noenc",
        "-keyout", str(key_path),
        "-out", str(cert_path),
        "-days", str(CA_VALIDITY_DAYS),
        "-not_before", not_before,
        "-subj", ca_subject(name),
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-addext", "subjectKeyIdentifier=hash",
    ]


# --- Leaves ---
#
# What the CA above signs, one per exact name the guest asks for.

# Thirty days. Short because nothing renews these -- the working-set cache
# re-mints inside 24 h of expiry and that is the whole rotation story -- and
# because a leaf that leaked is a leaf valid for one host, for a month, signed
# by a CA one guest trusts. Long enough that a VM which runs for a fortnight
# never re-mints its working set.
LEAF_VALIDITY_DAYS = 30


# Re-mint once a leaf is inside this of notAfter. A day, so a long-running
# connection opened just under the wire still outlives its certificate by an
# order of magnitude.
LEAF_RENEW_WITHIN_SECONDS = 86400


class LeafRefused(ValueError):
    """A name that will not be minted for, with the reason in the message.

    Raised BEFORE openssl is reached, which is the point: every character of
    the name below travels into an `-addext` argument, and `subjectAltName`
    takes a comma-separated list. A name carrying a comma would add extensions
    of the guest's choosing to a certificate the host signs. Nothing downstream
    of here re-checks, so this function is the boundary.
    """


# The longest a DNS name may be, and the longest one label may be (RFC 1035).
LEAF_NAME_MAX = 253
LEAF_LABEL_MAX = 63


_LEAF_LABEL_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyz0123456789-_")


def leaf_san(name: str) -> str:
    """The subjectAltName value for one name, or raise LeafRefused.

    ALLOWLIST, NOT DENYLIST. The obvious spelling of this check is to reject
    the characters that hurt -- comma, newline, `=` -- and it is the wrong
    shape: the set of characters that mean something to openssl's extension
    parser is openssl's to change, and a name is guest-chosen input reaching a
    subprocess argument. So the check names what is permitted and refuses the
    rest, which is a rule that cannot rot.

    An IP literal becomes an `IP:` SAN rather than a `DNS:` one. A `DNS:`
    entry holding an address does not match when a client connects to that
    address -- so minting one would produce a certificate that verifies
    nowhere, and the failure would present as an unexplained handshake error
    rather than as a refusal.

    `_` is permitted in a label though RFC 1035 forbids it: it is common in
    real service names, and every client this design faces resolves and
    validates such names. Refusing them would break traffic the allowlist
    authorised, which is the failure this whole rung exists to avoid.
    """
    name = normalise_hostname(name)
    if not name:
        raise LeafRefused("empty name")

    try:
        address = ipaddress.ip_address(name)
    except ValueError:
        address = None
    if address is not None:
        # A SCOPED ADDRESS IS REFUSED, and not for tidiness. `ip_address`
        # takes anything after a `%` as an IPv6 scope id and keeps it in
        # the string, commas included, so `fe80::1%a,DNS:victim.example`
        # parses as an address and would reach -addext whole. No SAN can
        # name a scope, so nothing is lost by refusing one.
        if getattr(address, "scope_id", None):
            raise LeafRefused(f"a scoped address in {name!r}")
        return f"IP:{address}"

    if len(name) > LEAF_NAME_MAX:
        raise LeafRefused(f"name longer than {LEAF_NAME_MAX} characters")
    labels = name.split(".")
    for label in labels:
        if not label:
            raise LeafRefused(f"empty label in {name!r}")
        if len(label) > LEAF_LABEL_MAX:
            raise LeafRefused(f"label longer than {LEAF_LABEL_MAX} "
                              f"characters in {name!r}")
        bad = set(label) - _LEAF_LABEL_CHARS
        if bad:
            raise LeafRefused(
                f"character {sorted(bad)[0]!r} not permitted in a name")
    return f"DNS:{name}"


def leaf_openssl_argv(name: str, ca_key, ca_cert,
                         key_path, cert_path, *, now: float) -> list[str]:
    """One `openssl req -x509 -CA` invocation that mints a leaf for `name`.

    A single process, not a CSR and a sign: `req -x509` takes `-CA`/`-CAkey`
    since OpenSSL 3.0 and does both, which halves the cost of the thing the
    token bucket exists to ration.

    THE SAN IS CRITICAL, AND THAT IS LOAD-BEARING. The subject is empty (there
    is no meaningful CN for a name the host does not own), and RFC 5280 says a
    certificate with an empty subject MUST mark subjectAltName critical.
    Without the flag, Python's ssl rejects the chain with
    `Subject empty and Subject Alt Name extension not critical` -- a verify
    failure whose message names neither the SAN value nor the CA, so it reads
    like a trust problem and sends a reader to the anchor.

    THE SAN CARRIES THE EXACT NAME, NEVER THE ALLOWLIST PATTERN THAT MATCHED.
    A `*.example.com` entry authorises the guest to reach names under it; a
    leaf minted for `*.example.com` would be a certificate the guest could use
    against any of them, including ones a later narrowing of the list removes.
    One name asked for, one name signed.

    notBefore is backdated by the same hour the CA is, for the same reason and
    with the same caveat -- see CA_BACKDATE_SECONDS, and the clock keeper
    (lib/vm_clock.py) that is the actual remedy for a paused guest.
    """
    not_before = time.strftime(
        "%Y%m%d%H%M%SZ", time.gmtime(now - CA_BACKDATE_SECONDS))
    return [
        "openssl", "req", "-x509",
        "-CA", str(ca_cert),
        "-CAkey", str(ca_key),
        "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-noenc",
        "-keyout", str(key_path),
        "-out", str(cert_path),
        "-days", str(LEAF_VALIDITY_DAYS),
        "-not_before", not_before,
        "-subj", "/",
        "-addext", f"subjectAltName=critical,{leaf_san(name)}",
        "-addext", "basicConstraints=critical,CA:FALSE",
        "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
        "-addext", "extendedKeyUsage=serverAuth",
        "-addext", "subjectKeyIdentifier=hash",
        "-addext", "authorityKeyIdentifier=keyid",
    ]
