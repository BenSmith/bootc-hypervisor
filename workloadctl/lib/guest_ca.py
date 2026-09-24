#!/usr/bin/env python3
"""What a guest is given so that it trusts its workload's egress CA.

The anchor's path inside the guest and the variables that name it, which
the seed, the container's run arguments and validation all spell from
here. The CA itself -- where it lives on the host, how it is minted -- is
egress_ca's; this module decides only where a guest finds it.

Installed to /usr/libexec/workloadctl/guest_ca.py.
"""


# Where the guest finds the CA whose certificates the inspector's spliced
# connections are presented under. A guest path, not a host path: the file
# arrives inside the seed and is written by cloud-init.
#
# /usr/local/share/ca-certificates is the directory `update-ca-certificates`
# consumes on Debian-family guests; Fedora's anchors live elsewhere. The five
# variables below name the FILE directly rather than relying on either, because
# the whole point of the block is to work in a guest whose distribution we do
# not choose.
CA_BUNDLE_PATH = "/usr/local/share/ca-certificates/egress-ca.crt"


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
