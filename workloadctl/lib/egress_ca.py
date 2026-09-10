#!/usr/bin/env python3
"""The per-workload egress CA, the leaves it signs, and where all of it lives.

One CA per workload rather than one per host, and the directory names, the
validity windows, the SELinux types of the subtree and the two openssl
invocations are all here together because they are one decision each spelled
in several places: the minter creates the directories, the SELinux patterns
label them, `diagnose` reads the certificate back, and the seed writes the
anchor into the guest. A drift between any two of those is a mislabelled
directory or an untrusted anchor, and both present as a network fault rather
than as a naming mistake.

Both substrates, despite the `vm_`/`VM_` prefixes -- the container half mints
against the same CA through the same minter.

Below workload_lib and below the substrate facade: this module imports
config_parser and egress_policy and nothing above them. Nothing here runs
openssl or touches the filesystem; it builds paths and argv, and lib/egress_mint.py
is what executes them.

Installed to /usr/libexec/workloadctl/egress_ca.py.
"""

import ipaddress
import time
from pathlib import Path

from config_parser import normalise_hostname, workload_root_dir
from egress_policy import vm_uses_inspect


# Where the guest finds the CA whose certificates the inspector's spliced
# connections are presented under. A guest path, not a host path: the file
# arrives inside the seed and is written by cloud-init.
#
# /usr/local/share/ca-certificates is the directory `update-ca-certificates`
# consumes on Debian-family guests; Fedora's anchors live elsewhere. The five
# variables below name the FILE directly rather than relying on either, because
# the whole point of the block is to work in a guest whose distribution we do
# not choose.
CA_BUNDLE_PATH = "/usr/local/share/ca-certificates/workloadctl-egress.crt"


# The environment variables that point a guest's HTTP clients at that bundle.
# Five, because there is no single one: OpenSSL reads SSL_CERT_FILE, Node reads
# NODE_EXTRA_CA_CERTS, python-requests reads REQUESTS_CA_BUNDLE, git reads
# GIT_SSL_CAINFO and pip reads PIP_CERT. A guest missing any one of them fails
# only in that ecosystem, which is the hardest kind of failure to attribute.
CA_ENV_VARS = (
    "SSL_CERT_FILE",
    "NODE_EXTRA_CA_CERTS",
    "REQUESTS_CA_BUNDLE",
    "GIT_SSL_CAINFO",
    "PIP_CERT",
)


# The guest variables workloadctl seeds itself, and therefore the ones a
# credential's `env` may not be. Derived from the producers rather than listed,
# so a sixth CA variable cannot leave this behind: the failure a stale copy
# produces is a silent overwrite in the seed, not an error anywhere.
#
# No broker variable is reserved, because nothing seeds one -- the guest is
# never told a broker address (ADR 007 decision 6).
RESERVED_GUEST_ENV = frozenset(CA_ENV_VARS)


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
# below have to name the same three directories the minter creates. A drift
# between the two spellings is a mislabelled directory, which presents as the
# inspector failing to mint and not as a naming mistake.
LEAF_DIR_NAME = "leaves"
DENIAL_DIR_NAME = "leaves-denied"


# THE PKI SUBTREE HAS ITS OWN LABELS, AND THAT IS THE WHOLE POINT
#
# `wlinspect_t` is a separate domain from `svirt_t` so that the component
# terminating guest input cannot reach the workload's disks, volumes or state
# directory. The inspector reads a private key and writes a leaf cache, and
# both live in that state directory beside the disk images.
# Granting the domain `svirt_image_t` would be one rule shorter, would work,
# and would hand the inspector the guest's disks — so the material moves
# instead: three directories with labels of their own, and the domain is
# granted those.
#
# Two types, not one, because the permissions genuinely differ. The CA is
# READ-ONLY to the inspector: an inspector that could rewrite it could replace
# the anchor the guest was seeded with, which is unrecoverable without a
# re-provision. The leaves are read-write because minting them is the job.
CA_SELINUX_TYPE = "wlinspect_ca_t"
LEAF_SELINUX_TYPE = "wlinspect_leaf_t"


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
# permanently. The backdate is not what makes pauses survivable; the mint-time
# clock check is.
CA_BACKDATE_SECONDS = 3600


# The window CA_VALIDITY_DAYS' comment already promised: `diagnose` warns
# inside the last year. A year rather than a month because the remedy is a
# RE-PROVISION -- cloud-init runs once per instance-id, so the guest is rebuilt,
# not restarted -- and a month's notice for that is notice of an outage rather
# than of a decision.
CA_EXPIRY_WARN_DAYS = 365


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


def pki_fcontext_patterns(name: str) -> list[tuple[str, str]]:
    """(pattern, type) for every directory in one workload's PKI subtree.

    Registered in `file_contexts.local` beside the per-workload svirt_image_t
    rule, and more specific than it, which is the only reason these win: within
    ONE source most-specific-wins applies, and `.local` outranks the base file
    wholesale. A CIL `filecon` in the policy module lands in the base file and
    would be silently shadowed -- see shadowed_filecon_paths().
    """
    root = workload_root_dir(name)
    return [
        (f"{root}/state/{CA_DIR_NAME}(/.*)?", CA_SELINUX_TYPE),
        (f"{root}/state/{LEAF_DIR_NAME}(/.*)?", LEAF_SELINUX_TYPE),
        (f"{root}/state/{DENIAL_DIR_NAME}(/.*)?", LEAF_SELINUX_TYPE),
    ]


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


# Whether there is a bundle at CA_BUNDLE_PATH for those variables to name.
#
# THIS IS NOT CAUTION, IT IS THE DIFFERENCE BETWEEN WORKING AND BROKEN. Every
# one of those five variables REPLACES the runtime's default trust store rather
# than adding to it, and every one of them fails closed when the file it names
# does not exist: OpenSSL's SSL_CERT_FILE pointing at a missing path makes
# loading the default verify paths fail outright, and requests, git and pip
# raise on the open. So the block must never be written for a certificate
# nothing is presenting yet: that is a total outage inside every filtered
# guest, not a degraded mode.
#
# THREE THINGS MOVE TOGETHER OR NONE OF THEM DO: this flag, the write_files
# entry in _render_default_user_data that puts the PEM at CA_BUNDLE_PATH,
# and the seed contract in build_cloud_init_iso. Flipping this alone points
# five variables at a file nothing writes, which is the total outage described
# above -- so it is not a "safe" partial step, it is the worst of the three.
VM_CA_BUNDLE_AVAILABLE = True


def vm_ca_env(config: dict) -> dict[str, str]:
    """The CA environment a filtered guest is given, or {} if it has none.

    NO PROXY VARIABLES. The redirect is transparent, so nothing a guest sets
    can turn the filtering off or on, and http_proxy/https_proxy/no_proxy are
    not written: a guest that still sets https_proxy to some literal of its own
    reaches a host address where nothing listens.

    This workload's own CA is minted into
    its state directory, written into the seed at CA_BUNDLE_PATH, and named
    by these five variables -- and under the default `tls = "inspect"` the guest
    NEEDS it, because the leaf the inspector presents is signed by nothing else.

    ONCE PER INSTANCE ID, the same caveat the proxy block carried. cloud-init
    replays a seed only when the instance id changes, so editing this block on a
    running guest changes nothing until the VM is re-seeded — and an operator
    who switches egress mode on a live workload gets a guest whose environment
    still describes the previous mode.
    """
    # VM-only by construction: this is a cloud-init guest-env block. The
    # container equivalent would be env injection directly into the unit, and
    # it must not ship before a container CA exists -- these five variables
    # REPLACE the trust store (RESERVED_GUEST_ENV), so an empty shape is
    # not inert, it is every TLS verification in the workload failing.
    if not vm_uses_inspect(config) or not VM_CA_BUNDLE_AVAILABLE:
        return {}
    return {var: CA_BUNDLE_PATH for var in CA_ENV_VARS}


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
        return f"IP:{ipaddress.ip_address(name)}"
    except ValueError:
        pass

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
    with the same caveat -- see CA_BACKDATE_SECONDS, and the mint-time clock
    check that is the actual remedy for a paused guest.
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
