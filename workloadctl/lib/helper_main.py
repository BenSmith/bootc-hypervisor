"""Shared entrypoint plumbing for the libexec arming helpers.

`workload-{vm,container}-{filter,inspect}` are four scripts with one shape:
systemd runs them as `<script> up <name>` from an ExecStartPre and
`<script> down <name>` from the matching ExecStopPost, and each half has a
different failure contract. Every one of them had its own copy of `log`,
`run`, the argv dispatch and the top-level exception handler, and the copies
had already drifted in signature (`run(argv, check)` in one pair,
`run(argv, check=False)` in the other) without drifting in behaviour.

Nothing here is nftables-specific -- that lives in lib/nft.py, which builds on
this module.
"""
import subprocess
import sys


def log(msg):
    """One line to stdout, unbuffered, for the journal.

    Flushed on every call: these run as short-lived ExecStartPre/ExecStopPost
    processes whose stdout is a pipe, and a helper that fails after logging
    would otherwise lose the lines that say why.
    """
    print(msg, flush=True)


def run(argv, check=False):
    """Run one nft/ip invocation. Returns the CompletedProcess.

    `check=False` by default because the tolerant call is the common one on
    these paths -- a missing element or an already-assigned address is the
    expected state on a stop, or on a start that follows a failed one. The
    timeout is a bound, not a tuning knob: nft and ip either answer at once or
    are wedged, and a wedged one must not hold a unit's start open forever.
    """
    return subprocess.run(argv, capture_output=True, text=True, check=check,
                          timeout=30)


def up_down_main(argv, up, down):
    """Dispatch `<script> <up|down> <name>` to one of two callables.

    Exit 2 on a usage error rather than 1, so a systemd unit generated with the
    wrong argv is distinguishable in the journal from an arming failure.
    """
    if len(argv) != 3 or argv[1] not in ("up", "down"):
        print(f"usage: {argv[0]} <up|down> <name>", file=sys.stderr)
        return 2
    action, name = argv[1], argv[2]
    return up(name) if action == "up" else down(name)


def run_helper(main, argv):
    """Call `main(argv)` and turn an escaping exception into an exit code.

    THE ASYMMETRY IS THE POINT, and it is the same on all four helpers. `up`
    fails loudly: a workload whose config claims confinement and whose filter
    or redirect did not arm would run wide open while claiming otherwise, which
    is the exact misreport this layer exists to prevent -- better to fail the
    start. `down` is tolerant: its elements are legitimately absent whenever the
    start failed before arming, or an operator used the break-glass
    `nft delete table`, and a stop that fails over a missing element is a
    workload that cannot be stopped.
    """
    try:
        return main(argv)
    except Exception as e:  # noqa: BLE001
        print(f"  ERROR: {e}", file=sys.stderr)
        return 1 if len(argv) > 1 and argv[1] == "up" else 0
