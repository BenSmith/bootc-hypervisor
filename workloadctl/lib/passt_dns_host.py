"""What the host can offer a passt guest as DNS: gateways and resolvers.

Two readers, each per address family, each silent about a family it finds
nothing for. `default_gateways` is the address a guest will be told is its
nameserver and which passt intercepts; `host_resolvers` is where passt
actually sends the query, never disclosed to the guest. Both are read late,
from the VM unit's own ExecStartPre, because the default route does not exist
when the generator runs.
"""
import ipaddress
import re
import subprocess
from pathlib import Path

from helper_main import log

RESOLV_CONF = Path("/etc/resolv.conf")


def default_gateways() -> dict[int, str]:
    """The host's default-route gateway per family, as {4: addr, 6: addr}.

    This is the address the guest is told is its resolver and which passt
    intercepts. It is not required to be the gateway — fwd_nat_from_tap()
    (fwd.c:906-913) matches DNS flows on dns_match alone — but the gateway is
    the natural choice: passt answers for it, so the guest reaches it whatever
    its routing table looks like.

    Families with no default route are simply absent from the result.
    """
    gateways: dict[int, str] = {}
    for family, flag in ((4, "-4"), (6, "-6")):
        try:
            result = subprocess.run(
                ["ip", flag, "route", "show", "default"],
                capture_output=True, text=True, timeout=5,
            )
        except (OSError, subprocess.SubprocessError) as e:
            log(f"  WARNING: could not read the IPv{family} default route: {e}")
            continue
        if result.returncode != 0:
            continue
        for line in result.stdout.splitlines():
            fields = line.split()
            if "via" not in fields:
                continue
            candidate = fields[fields.index("via") + 1]
            try:
                addr = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            # A link-local IPv6 gateway (fe80::/10) is scoped to an interface,
            # so it is not a usable dns-forward value — passt would hand the
            # guest an address it cannot disambiguate.
            if addr.is_link_local:
                continue
            gateways[family] = str(addr)
            break
    return gateways


def host_resolvers() -> dict[int, str]:
    """The first nameserver per family from /etc/resolv.conf, as {4:.., 6:..}.

    Loopback included, deliberately: passt resolves host-side, where a stub
    resolver like 127.0.0.53 is reachable. This value is where passt actually
    sends the query and is never disclosed to the guest.
    """
    resolvers: dict[int, str] = {}
    try:
        text = RESOLV_CONF.read_text()
    except OSError as e:
        log(f"  WARNING: could not read {RESOLV_CONF}: {e}")
        return resolvers
    for line in text.splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        match = re.match(r"^nameserver\s+(\S+)$", line)
        if not match:
            continue
        # Strip any zone id: a scoped address is not usable as a dns-host.
        candidate = match.group(1).split("%", 1)[0]
        try:
            addr = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        resolvers.setdefault(4 if addr.version == 4 else 6, str(addr))
    return resolvers
