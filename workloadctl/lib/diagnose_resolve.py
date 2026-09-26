"""The resolver half of diagnose: is the synthesising responder the workload's DNS.

A filtered VM's guest is told one nameserver, the per-workload responder on
the host, and a filtered container's pasta sends its queries there, so a
responder that is not listening is the whole of DNS for that workload while
every other line in `diagnose` still passes. vm_resolve_check() and
container_resolve_check() are the verdicts: the socket unit, the static map
it reads, and for a VM the passt netdev line that tells the guest where to
look, each named when it is the thing that is wrong.
"""

import os

from diagnose_probe import PROBE
from egress_policy import container_uses_resolve, vm_uses_resolve
from run_files import workload_env_dir
from substrate import service_active
from egress_policy import resolve_static_path
from workload_addr import RESOLVE_PORT, resolve_address


def _netdev_dns_fragment(name: str) -> str | None:
    """What passt was told about DNS at this VM's last start, or None.

    One line, at a path the VM's own ExecStartPre replaces on every start:

        /run/workload-env/workload-<name>.passt
        WL_PASST_DNS=dns-forward=<gw>,dns=<gw>,dns-host=127.130.x.y,...

    None when the file is unreadable or carries no such assignment, which the
    caller treats as "nothing to say" rather than as a fault -- an absent file
    is the normal state of a VM that has never started, and a diagnostic must
    not invent a failure out of a missing diagnostic.

    Cheap on purpose: one read of one short file, no systemctl, no subprocess.
    It is the decision that actually reached QEMU, which is why this is worth
    reading rather than recomputing -- recomputing would answer what the
    fragment WOULD be now, and the guest is running on what it WAS then.
    """
    try:
        text = (workload_env_dir() / f"workload-{name}.passt").read_text()
    except OSError:
        return None
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() == "WL_PASST_DNS":
            return value.strip()
    return None


def vm_resolve_check(config, *, socket_active=PROBE, static_present=PROBE,
                     vm_active=PROBE, netdev_dns=PROBE
                     ) -> tuple[str, bool, str] | None:
    """Report whether a VM's synthesising responder can actually answer it.

    Returns None for workloads with no responder (not a VM, bridged,
    unfiltered, or `resolver = "none"`), so no line is emitted.

    The same argument inspect_check makes for checking its socket
    separately, one step worse. The guest's resolver list has EXACTLY ONE
    entry, so a responder that is not there is not a degraded lookup path --
    it is the whole of DNS for that guest. Nothing else in `diagnose` would
    say so: `vm_egress` reports the VM correctly filtered, `vm_inspect`
    reports its traffic correctly redirected, `status` is green, and inside
    the guest every name fails to resolve. That reads as a broken guest.

    Two ways it happens on a VM that booted fine, which is why this is not
    covered by the VM unit's Requires= on the socket:

      - The socket is Accept=no, so systemd's trigger limit applies and
        hitting it fails the socket unit PERMANENTLY until something restarts
        it. The service's own Restart=on-failure does not rebind it -- only
        the socket can, and it is the thing that failed.
      - The static map is written by the VM's own ExecStartPre
        (workload-vm-filter up) and read by the responder at start. The
        responder is socket-activated, so a missing map is not noticed
        until the guest's first query, and then it fails the START -- on a
        query the guest has already made.

    And a third, one layer out, which the first two cannot see: a responder
    that is bound, loaded and correct, on a guest that was never told to ask
    it. `workload-vm-netdev` decides what passt advertises, and it fails CLOSED
    -- no IPv4 default route, or a uid it could not derive, and the guest is
    given `dhcp-dns=off` rather than the host's real nameservers. That is the
    right call (handing a filtered guest the host's resolvers is the leak
    synthesis exists to remove) and it is silent: the explanation goes to the
    journal at VM start and nothing reads it back. So the last arm compares
    what the guest was actually told against this workload's own responder,
    which also catches a `dns-host=` naming some OTHER address -- a fragment
    left by an instance started under different config.

    Observations are injectable (PROBE sentinel) so the verdict logic is
    testable without a live host.
    """
    if not vm_uses_resolve(config.config):
        return None
    try:
        uid = config.uid
    except Exception:
        # No user yet, so no units either: generation precedes user creation,
        # and a first `enable` reaches this before _wl-<name> exists. user_exists
        # already reports that. inspect_check guards the same way, and
        # without it the address in the healthy line below raises straight out
        # of collect_diagnose_checks, which catches nothing -- one unresolvable
        # uid would take the whole command down rather than skip one line.
        return None

    name = config.name
    unit = f"workload-{name}-resolve.socket"
    restart = f"systemctl restart {unit}"

    if socket_active is PROBE:
        # Unpacked. See inspect_check: the bare tuple is always truthy.
        socket_active, _ = service_active(unit)
    if not socket_active:
        return ("vm_resolve", False,
                f"{unit} is not listening, and it is this guest's ONLY "
                f"nameserver — every name in the guest fails to resolve while "
                f"the VM runs, its egress stays filtered and every other line "
                f"here passes. Inside the guest that reads as a broken guest. "
                f"Start it: {restart}")

    path = resolve_static_path(name)
    if static_present is PROBE:
        static_present = os.path.exists(path)
    if not static_present:
        return ("vm_resolve", False,
                f"{unit} is listening but {path} is missing, so the responder "
                f"will fail its start on the guest's first query rather than "
                f"answer it — and it is socket-activated, so nothing has "
                f"noticed yet. The map is written by this VM's own "
                f"prestart: systemctl restart workload-{name}.service")

    address = resolve_address(uid)
    told = f"synthesising responder on {address}:{RESOLVE_PORT}, " \
           f"{unit} listening, static map {path}"

    # Gated on the VM being up, like the other VM-runtime observations here:
    # the fragment describes the LAST start, so on a stopped VM it is a
    # decision that may not be the next one, and reporting it would be a
    # verdict on history. Skipped, not failed -- the two arms above are about
    # the host and stay meaningful either way.
    if vm_active is PROBE:
        vm_active, _ = service_active(config.service_name)
    if not vm_active:
        return ("vm_resolve", True, told)

    if netdev_dns is PROBE:
        netdev_dns = _netdev_dns_fragment(name)
    if netdev_dns is None:
        # Nothing written, or nothing to read. Not a fault of its own; see
        # _netdev_dns_fragment.
        return ("vm_resolve", True, told)

    if f"dns-host={address}" not in netdev_dns:
        return ("vm_resolve", False,
                f"the responder is listening and loaded, but this guest was "
                f"never told to ask it: passt was started with "
                f"{netdev_dns!r}, which does not point at {address}. The "
                f"guest resolves NOTHING while every other line here passes — "
                f"and it fails closed on purpose, so there is no fallback to "
                f"the host's nameservers to mask it. Usually the host had no "
                f"IPv4 default route when the VM started (there is no address "
                f"to advertise and intercept); "
                f"`journalctl -u workload-{name}.service` carries the reason "
                f"workload-vm-netdev gave. Fix the host's routing, then: "
                f"systemctl restart workload-{name}.service")

    return ("vm_resolve", True, f"{told}, advertised to the guest by passt")


def container_resolve_check(config, *, socket_active=PROBE,
                            static_present=PROBE
                            ) -> tuple[str, bool, str] | None:
    """Report whether a container's synthesising responder can answer it.

    Returns None for workloads with no responder (a VM, an unfiltered
    container, bridge mode, or a network pasta is not on), so no line is
    emitted.

    vm_resolve_check's first two arms, for the same two failures: a socket
    that hit its trigger limit and stays failed, and a static map the
    container's own prestart did not write. The third arm has no container
    twin to read back: `--dns-host` is on the unit's own `--network=`, which
    `drift` compares against a fresh render.
    """
    if config.is_vm or not container_uses_resolve(config.config):
        return None
    try:
        uid = config.uid
    except Exception:
        return None                      # no user yet; user_exists says so

    name = config.name
    unit = f"workload-{name}-resolve.socket"

    if socket_active is PROBE:
        socket_active, _ = service_active(unit)
    if not socket_active:
        return ("container_resolve", False,
                f"{unit} is not listening, and it is the only nameserver "
                f"that answers this container — every name inside it fails "
                f"to resolve while its egress stays filtered and every other "
                f"line here passes. Start it: systemctl restart {unit}")

    path = resolve_static_path(name)
    if static_present is PROBE:
        static_present = os.path.exists(path)
    if not static_present:
        return ("container_resolve", False,
                f"{unit} is listening but {path} is missing, so the responder "
                f"will fail its start on the container's first query rather "
                f"than answer it. The map is written by this workload's own "
                f"prestart: systemctl restart workload-{name}.service")

    address = resolve_address(uid)
    return ("container_resolve", True,
            f"synthesising responder on {address}:{RESOLVE_PORT}, {unit} "
            f"listening, static map {path}, reached through pasta's "
            f"--dns-host")
