"""One VM's passt DNS fragment, decided and written.

`passt_dns` is the dispatch: which of the three answers a workload gets --
no resolver at all, its own synthesising responder, or the host's
nameservers -- from its config and, only on the last path, from
/etc/resolv.conf. `write_passt_env` drops the result where the VM unit's
ExecStart reads it back as `${WL_PASST_DNS}`.
"""
import os
import pwd
from pathlib import Path

from egress_policy import uses_resolve
from helper_main import log
from passt_dns_fragment import (
    NO_RESOLVER,
    build_dns_fragment,
    build_synthesis_fragment,
)
from passt_dns_host import default_gateways, host_resolvers
from workload_addr import resolve_address
from workload_lib import load_workload_config
from run_files import workload_env_dir


def workload_config(name: str) -> dict:
    """This workload's parsed TOML, or {} if it cannot be read.

    An empty dict is a workload that is not a VM as far as uses_resolve is
    concerned, which lands on the no-responder path.
    """
    try:
        return load_workload_config(name)
    except (OSError, ValueError) as e:
        log(f"  WARNING: could not read config for {name}: {e}; assuming "
            f"resolver = \"host\" and no responder")
        return {}


def resolver_mode(config: dict) -> str:
    """[vm.network].resolver for this workload: "host" (default) or "none"."""
    mode = (config.get("vm", {}) or {}).get("network", {}) \
        .get("resolver", "host")
    return mode if mode in ("host", "none") else "host"


def responder_address(name: str) -> str:
    """This workload's synthesising responder address, 127.130.x.y.

    Derived from the uid, which exists by the time this runs: the netdev
    prestart is on the VM unit, and the VM unit Requires= the setup service
    that creates the user.
    """
    return resolve_address(pwd.getpwnam(f"_wl-{name}").pw_uid)


def passt_dns(name: str) -> tuple[str, list[str]]:
    """The fragment for this workload, and the notes to log about it."""
    config = workload_config(name)

    if resolver_mode(config) == "none":
        # The guest gets no resolver at all. Under synthesis this no longer
        # means "no DNS tunnelling" -- nothing is forwarded either way -- it
        # means a guest that can only dial literals.
        return (NO_RESOLVER,
                ['[vm.network].resolver = "none": the guest is given no '
                 'resolver'])
    if uses_resolve(config):
        try:
            responder = responder_address(name)
        except (KeyError, ValueError) as e:
            # Fail closed, and specifically NOT back to build_dns_fragment.
            # This workload's guest is filtered; handing it the host's real
            # nameservers because we could not derive a uid would be a leak of
            # exactly the kind synthesis exists to remove.
            log(f"  WARNING: no responder address for {name} ({e}); "
                f"the guest gets no resolver rather than the host's")
            return (NO_RESOLVER, [])
        return build_synthesis_fragment(default_gateways(), responder)
    # No responder: an unfiltered or bridged VM, whose guest really is being
    # handed the host's own nameservers. /etc/resolv.conf is read here and
    # nowhere else.
    return build_dns_fragment(default_gateways(), host_resolvers())


def write_passt_env(name: str, fragment: str) -> Path:
    """Write the EnvironmentFile the VM unit splices into its netdev."""
    env_dir = workload_env_dir()
    env_dir.mkdir(parents=True, exist_ok=True)
    env_file = env_dir / f"workload-{name}.passt"
    tmp = env_file.with_suffix(".passt.tmp")
    # Write-then-rename: ExecStart reads this file microseconds later, and a
    # torn read would produce a netdev argument QEMU rejects.
    tmp.write_text(f"WL_PASST_DNS={fragment}\n")
    os.replace(tmp, env_file)
    return env_file
