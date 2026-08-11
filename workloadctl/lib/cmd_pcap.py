"""
cmd_pcap — capture a workload's traffic, from one or both vantages.

The surface is tcpdump's, because the people who reach for this already know
tcpdump: `-i` selects a vantage, `-w` writes a file (and without it nothing
touches disk), `-s` truncates, `-c`/`-C`/`-W`/`-G` bound and rotate. The one
new idea is that a vantage is an interface, which tcpdump users already accept
from `any`, `lo` and `nflog:3`.

Teardown belongs to systemd, not to this command: the capture runs in a
transient unit whose ExecStopPost removes the nftables rule and the QEMU
object, so a dropped session or a `kill -9` cannot leave either behind. See
lib/pcap.py.
"""
import json
import os
import subprocess
import sys

import cli_log
from pcap import (
    DIRECTION_DEFAULT, DURATION_DEFAULT, MAX_SIZE_DEFAULT, PCAP_UNIT_PREFIX,
    VANTAGE_GUEST, VANTAGE_HOST, available_vantages, build_plan, parse_duration,
    parse_size, parse_snaplen, pcap_unit_name, pcap_vantages, render_plan,
    systemd_run_argv, validate_request,
)
from workloadctl_core import require_root
from cmd_validate import load_config_or_exit


def _stdout_is_claimed(args) -> bool:
    """Whatever binds stdout pushes prose to stderr.

    cli_log already draws the line — prose is what workloadctl says about what
    it is doing, output is what the command was asked to produce — and `--json`
    reserves stdout for the result object. `pcap` adds no new rule; it only
    supplies a second thing that binds stdout, and `-w -` binds it exactly as
    `--json` does.
    """
    return bool(getattr(args, "json", False)) or getattr(args, "write", None) == "-"


def _say(args, message: str = "") -> None:
    if getattr(args, "quiet", False):
        return
    print(message, file=sys.stderr if _stdout_is_claimed(args) else sys.stdout)


def cmd_pcap(args, manager):
    """Capture packets from a workload's host- and/or guest-side vantage."""
    if getattr(args, "list", False):
        return _list_captures(args)

    if not getattr(args, "workload", None):
        cli_log.error("a workload is required (except with --list)")
        return 2

    config = load_config_or_exit(args.workload.split("/")[0],
                                 json_mode=bool(getattr(args, "json", False)))

    if getattr(args, "list_interfaces", False):
        return _report_vantages(args, config)

    if getattr(args, "stop", False):
        return _stop_capture(args, config)

    return _start_capture(args, config)


# --- reporting ---

def _report_vantages(args, config) -> int:
    """`-D`: what this workload offers, and why anything missing is missing."""
    vantages = pcap_vantages(config)
    if getattr(args, "json", False):
        print(json.dumps({
            "workload": config.name,
            "vantages": [{"name": v.name, "available": v.available,
                          "detail": v.detail,
                          "supports_filter": v.supports_filter,
                          "supports_direction": v.supports_direction,
                          "supports_rotation": v.supports_rotation}
                         for v in vantages],
        }, indent=2))
        return 0
    print(f"Vantages for {config.name!r}:")
    for vantage in vantages:
        mark = "✓" if vantage.available else "✗"
        print(f"  {mark} {vantage.name:<6} {vantage.detail}")
        if vantage.available and not vantage.supports_filter:
            print("           cannot be narrowed by a BPF filter, cannot "
                  "honor -Q, and does not rotate")
    return 0


def _list_captures(args) -> int:
    """`--list`: read systemd rather than a registry of our own.

    Which is also why a reboot ending every capture is self-correcting: there
    is no state of ours to go stale.
    """
    result = subprocess.run(
        ["systemctl", "list-units", "--type=service", "--all",
         "--no-legend", "--plain", f"{PCAP_UNIT_PREFIX}*"],
        capture_output=True, text=True)
    units = [line.split()[0] for line in result.stdout.splitlines()
             if line.strip()]
    if getattr(args, "json", False):
        print(json.dumps({"captures": units}, indent=2))
        return 0
    if not units:
        print("No captures running.")
        return 0
    print("Running captures:")
    for unit in units:
        workload = unit[len(PCAP_UNIT_PREFIX):].removesuffix(".service")
        print(f"  {workload:<24} {unit}")
    return 0


# --- lifecycle ---

def _stop_capture(args, config) -> int:
    require_root()
    unit = pcap_unit_name(config.name)
    result = subprocess.run(["systemctl", "stop", unit],
                            capture_output=True, text=True)
    if result.returncode != 0:
        cli_log.error(f"could not stop {unit}: {result.stderr.strip()}")
        return 1
    _say(args, f"Stopped {unit}. The nftables rule and any QEMU object were "
               f"removed by its ExecStopPost.")
    return 0


def _start_capture(args, config) -> int:
    requested = list(getattr(args, "interface", None) or [VANTAGE_HOST])
    # Deduplicate while preserving the order the operator asked for.
    vantages = list(dict.fromkeys(requested))

    try:
        duration = parse_duration(getattr(args, "duration", None)
                                  or DURATION_DEFAULT)
        max_size = parse_size(getattr(args, "max_size", None) or MAX_SIZE_DEFAULT)
        snaplen = parse_snaplen(getattr(args, "snapshot_length", None), vantages)
    except ValueError as e:
        cli_log.error(str(e))
        return 2

    direction = getattr(args, "direction", None) or DIRECTION_DEFAULT
    bpf = list(getattr(args, "filter", None) or [])
    write = getattr(args, "write", None)
    rotation = any(getattr(args, key, None) for key in
                   ("rotate_size", "file_count", "rotate_seconds"))

    errors = validate_request(
        config, vantages=vantages, direction=direction, bpf=bpf, write=write,
        detach=getattr(args, "detach", False),
        json_output=getattr(args, "json", False), rotation=rotation)
    if errors:
        for error in errors:
            cli_log.error(error)
        available = available_vantages(config)
        if available:
            cli_log.error(f"available vantages: {', '.join(available)} "
                          f"(workloadctl pcap -D {config.name})")
        return 2

    plan = build_plan(config, vantages=vantages, snaplen=snaplen,
                      direction=direction, write=write, duration=duration,
                      max_size=max_size, bpf=bpf)

    # One renderer for both, following the rule substrate.py already states for
    # `disable --dry-run`: whatever one does, the other must describe.
    if getattr(args, "dry_run", False):
        if getattr(args, "json", False):
            print(json.dumps({"result": "dry-run", "plan": plan.to_json()},
                             indent=2))
            return 0
        print("Dry run — would:")
        print()
        print(render_plan(plan))
        print()
        print("Nothing was changed. Re-run without --dry-run to apply.")
        return 0

    require_root()

    # Refuse before narrating. The unit name is per-workload, so a second
    # invocation collides — and it is almost always a forgotten first one, so
    # naming the running capture beats suffixing a second. Printing the plan
    # first would describe something that is not going to happen.
    unit = pcap_unit_name(config.name)
    if _unit_active(unit):
        cli_log.error(
            f"{config.name} is already being captured by {unit}. Stop it "
            f"first: workloadctl pcap --stop {config.name}")
        return 1

    _say(args, render_plan(plan))
    _say(args)

    helper_args = _helper_args(config, plan, args, bpf)
    result = subprocess.run(systemd_run_argv(config.name, helper_args,
                                             duration=duration),
                            capture_output=True, text=True)
    if result.returncode != 0:
        cli_log.error(f"could not start {unit}: {result.stderr.strip()}")
        return 1

    # Detached, a rejected object-add or a tcpdump that dies on startup would
    # happen after this command exits 0 — so settle and confirm before
    # returning, rather than reporting success for something already dead.
    if not _settled(unit):
        cli_log.error(
            f"{unit} did not stay running. Its output: "
            f"journalctl -u {unit}")
        return 1

    if getattr(args, "detach", False):
        if getattr(args, "json", False):
            print(json.dumps({"result": "started", "unit": unit,
                              "plan": plan.to_json()}, indent=2))
        else:
            _say(args, f"Capturing in the background as {unit}.")
            _say(args, f"  Stop it:  workloadctl pcap --stop {config.name}")
            if write:
                _say(args, f"  Writing:  {write}")
        return 0

    # Foreground is this command *following* the unit, not running the capture.
    _say(args, f"Following {unit}. Ctrl-C stops it.")
    try:
        subprocess.run(["journalctl", "-u", unit, "-f", "-o", "cat",
                        "--since", "now"])
    except KeyboardInterrupt:
        pass
    finally:
        subprocess.run(["systemctl", "stop", unit],
                       capture_output=True, text=True)
    return 0


def _helper_args(config, plan, args, bpf: list[str]) -> list[str]:
    """Argv for libexec/workload-pcap. The plan travels as JSON.

    The helper re-deriving the plan from the config would let the two disagree
    — and the whole contract of §6.6 is that what was printed is what runs.
    """
    payload = plan.to_json()
    payload["bpf"] = bpf
    payload["numeric"] = bool(getattr(args, "numeric", False))
    payload["packet_count"] = getattr(args, "packet_count", None)
    payload["rotate_size"] = getattr(args, "rotate_size", None)
    payload["file_count"] = getattr(args, "file_count", None)
    payload["rotate_seconds"] = getattr(args, "rotate_seconds", None)
    return ["run", config.name, json.dumps(payload)]


def _unit_active(unit: str) -> bool:
    result = subprocess.run(["systemctl", "is-active", unit],
                            capture_output=True, text=True)
    return result.stdout.strip() == "active"


# How long a capture is given to prove it is running rather than merely
# started. Type=exec marks a unit active the moment the exec succeeds, so a
# helper that dies a moment later — a QMP object QEMU refuses, a tcpdump that
# exits on a bad option — is observably "active" first. Returning on that first
# reading reports success for something already dead, which is exactly the
# failure --detach exists to prevent. Found on the bench, where a refused
# object-add was reported as "Capturing in the background".
_SETTLE_SECONDS = 2.0


def _settled(unit: str, settle: float = _SETTLE_SECONDS) -> bool:
    """Whether the unit is still running after it has had time to fail.

    Deliberately a *dwell*, not a poll-until-active: the interesting states are
    reached quickly and the wrong answer is the early one.
    """
    import time
    deadline = time.monotonic() + settle
    while time.monotonic() < deadline:
        result = subprocess.run(["systemctl", "is-active", unit],
                                capture_output=True, text=True)
        if result.stdout.strip() in ("failed", "inactive"):
            return False
        time.sleep(0.25)
    return _unit_active(unit)
