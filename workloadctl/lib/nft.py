"""Shared nftables plumbing for the libexec arming helpers.

The four arming helpers (`workload-{vm,container}-{filter,inspect}`) each had
their own copy of the functions below, and two of those copies said so in
their own docstrings -- "Verbatim copy of workload-vm-filter's purge()",
"Verbatim logic from workload-vm-inspect's twin". A comment is not an import:
the two must stay identical and nothing enforced it, so a fix to one was a
silent divergence from the other. There is nothing substrate-specific in any
of them, because the key they all work on is the WORKLOAD UID, which is the
one thing a VM and a container hold in common.

`workloadctl diagnose` reads the same nft state read-only, and shares
nft_json() from here for the same reason.

Every function is tolerant of a missing table, set or element. A missing one
means there is nothing of ours to remove, which is the desired end state
either way, and these run on stop paths where the absence is expected.
"""
import json
import subprocess

from helper_main import log, run
from nft_constants import (NFT_BIN, NFT_SET_INTERNAL_OK4,
                           NFT_SET_INTERNAL_OK6, NFT_SETS, NFT_TABLE)
from vm import (vm_filter_delete_command,
                vm_inspect_link_address_commands,
                vm_inspect_link_delete_commands,
                vm_internal_ok_delete_commands, vm_internal_ok_list_commands,
                vm_internal_ok_uid_elements, vm_owned_elements)


def nft_json(*args, timeout: int = 10):
    """Run `nft -j <args>` and return the parsed document, or None.

    None for every way of not having an answer -- nft absent, nft refusing,
    output that is not JSON -- because every caller does the same thing with
    all three: treat the object as not present.
    """
    try:
        result = subprocess.run([NFT_BIN, "-j", *args],
                                capture_output=True, text=True,
                                timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout)
    except ValueError:
        return None


def nft_chain(chain: str, table: str = None):
    """Parsed `nft -j -a list chain <table> <chain>`, or None.

    `-a` is not optional here: every caller works on rule HANDLES, and nft
    omits them without it. Defaults to the filter table, which is the one all
    the per-workload chains live in.
    """
    return nft_json("-a", "list", "chain", *(table or NFT_TABLE).split(),
                    chain)


def set_elements(payload) -> list:
    """The `elem` list out of a parsed `nft -j list set` document.

    Empty for a set that exists and holds nothing, and for a document that
    holds no set at all -- the caller has nothing to delete in either case.
    """
    for item in (payload or {}).get("nftables", []):
        if "set" in item:
            return item["set"].get("elem", [])
    return []


def purge_uid_elements(uid: int) -> int:
    """Remove every element owned by `uid` from every filter set. Returns the
    count.

    Called at the top of `up`, not only on the stop path, and that is what
    makes the armed state a function of the config ALONE rather than of the
    config plus every config it ever had. `ExecStopPost` deletes the entries
    named in the unit file as it exists at stop time, so when an operator
    removes an entry from `allow` and re-enables, the regenerated unit deletes
    only the entries that are still configured and the dropped one stays in
    the set -- permitting traffic the config no longer permits, silently,
    until the host reboots. Verified on nftables 1.1.6: arming {A, B} and then
    deleting {B} leaves A behind.

    nft has no "delete every element whose first field is this uid", which is
    why this enumerates and deletes by exact value rather than being three
    Exec lines in a unit.
    """
    removed = 0
    for set_name in NFT_SETS:
        listed = run([NFT_BIN, "-j", "list", "set", *NFT_TABLE.split(),
                      set_name])
        if listed.returncode != 0:
            continue
        try:
            payload = json.loads(listed.stdout)
        except ValueError:
            continue
        owned = vm_owned_elements(uid, set_elements(payload))
        if not owned:
            continue
        result = run(vm_filter_delete_command(set_name, owned))
        if result.returncode == 0:
            removed += len(owned)
        else:
            log(f"  WARNING: could not clear {set_name}: "
                f"{result.stderr.strip()}")
    return removed


def purge_internal_exemptions(uid: int, name: str) -> None:
    """Remove every `internal` exemption element belonging to this workload.

    By UID, read back out of the kernel, rather than by re-resolving the names
    the elements were armed from. The config is not a handle on what is armed:
    a record that rotated between start and stop resolves to an address that is
    not the one in the set, so a name-driven delete removes nothing and leaves
    the old (uid, address) element behind -- armed, unnamed by any config line,
    and alive until reboot. See vm_internal_ok_uid_elements.
    """
    for argv, set_name in zip(vm_internal_ok_list_commands(),
                              (NFT_SET_INTERNAL_OK4, NFT_SET_INTERNAL_OK6)):
        result = run(argv)
        if result.returncode != 0:
            continue
        try:
            payload = json.loads(result.stdout)
        except ValueError:
            continue
        entries = vm_internal_ok_uid_elements(uid, payload, f"_wl-{name}")
        for delete in vm_internal_ok_delete_commands(set_name, entries):
            run(delete)


def add_listener_addresses(uid: int) -> None:
    """Add this workload's v4 and v6 inspector listener addresses to the link.

    Raises on a real failure -- an inspector with no address to listen on
    cannot be reached, and the redirect would send the workload's traffic to
    nothing. An address that is already there is not a failure: the unit is
    restartable and a previous instance's address legitimately survives.
    """
    for argv in vm_inspect_link_address_commands(uid):
        result = run(argv)
        if result.returncode != 0 and "xist" not in result.stderr \
                and "assigned" not in result.stderr:
            raise RuntimeError(f"could not add listener address: "
                               f"{result.stderr.strip()}")


def remove_listener_addresses(uid: int) -> None:
    """Remove this workload's listener addresses. Warns rather than raising.

    The per-workload addresses only -- the link and the advertised address are
    shared and stay. Tolerates the address being absent: a start that died
    before adding it left nothing to remove, and a stop must not fail over it.
    """
    for argv in vm_inspect_link_delete_commands(uid):
        result = run(argv)
        if result.returncode != 0 \
                and "Cannot assign requested address" not in result.stderr:
            log(f"  WARNING: could not remove listener address: "
                f"{result.stderr.strip()}")
