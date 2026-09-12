"""One workloadctl invocation: parse, configure the narration, dispatch, exit.

main(argv) turns a command line into a call of the handler its verb names and
the status that call produced. run(argv) wraps it in the ladder that maps
every typed error a handler may raise to the exit status a script sees, and
that emits the JSON failure document a --json caller is owed however the
command died.
"""
import sys
import traceback

import cli_log
from cli_parser import build_parser
from provisioning import ImageTransferError
from substrate import LifecycleError, ProvisionFailed
from workloadctl_core import (
    NotRoot,
    UsageError,
    WorkloadManager,
    WorkloadMasked,
    WorkloadUserNotFound,
)


def main(argv) -> int:
    """Dispatch argv to its verb's handler; the status that handler produced."""
    args = build_parser().parse_args(argv[1:])

    # One configure() for the whole process, before any handler can speak.
    #
    # Two different flags spell themselves --json. On a read verb it means "my
    # stdout is a report I print myself"; on a mutating verb it means "cli_log
    # writes the result object to stdout". Both need prose off stdout, so both
    # set quiet — but only the second may set json_mode, because json_mode is
    # what licenses cli_log to *write* a document there. Granting it to a read
    # verb puts a second JSON object on a stream that already holds a report
    # (emit_failure fires from the exit ladder on any non-zero exit), and no
    # parser downstream survives that.
    json_flag = getattr(args, "json", False)
    cli_log.configure(
        quiet=getattr(args, "quiet", False) or json_flag,
        json_mode=json_flag and getattr(args, "emits_result", False),
        command=args.command,
    )

    # Create manager
    manager = WorkloadManager()

    # Each subparser sets its own `func` default (set_defaults(func=...)), so
    # dispatch is calling whichever handler argparse resolved -- and returning
    # what it returns. Most handlers report failure by raising one of the typed
    # errors run() maps, or by calling sys.exit directly; `egress` and `pcap`
    # report theirs by RETURNING a code, and a script checking `$?` must see
    # it.
    #
    # A nonzero INT, rather than any truthy value: a handler that returns None
    # -- nearly all of them -- is a 0, and a test that stands a handler up as
    # a Mock gets a truthy Mock back, which must not become the exit status.
    handler = getattr(args, "func", None)
    if handler:
        code = handler(args, manager)
        if isinstance(code, int) and code:
            return code
        return 0
    print(f"Command '{args.command}' not yet implemented", file=sys.stderr)
    return 1


def run(argv) -> int:
    """Run main() and map library exceptions to the process exit code.

    Returns the code the process should exit with. A handler that calls
    sys.exit directly raises SystemExit through here; its code is returned as
    the process would have used it -- None as 0, an int as itself, and a
    message printed to stderr as 1, which is what the interpreter does with
    `sys.exit("message")`.

    Every failing path also calls cli_log.emit_failure(), which is a no-op
    unless --json: a scripted caller must get a result document on stdout even
    when the command died before it could report its own, and this ladder is
    the one place that sees every way that can happen. A command that already
    emitted its own result (a partly-failed `update --all`, whose per-workload
    rows say far more than this backstop could) keeps it.
    """
    try:
        code = main(argv)
    except SystemExit as e:
        code = e.code
        if code is None:
            code = 0
        elif not isinstance(code, int):
            print(code, file=sys.stderr)
            code = 1
        if code:
            cli_log.emit_failure(f"command failed (exit {code}); see stderr")
        return code
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        cli_log.emit_failure("interrupted")
        return 130
    except UsageError as e:
        # Message already printed by the raiser; usage errors exit 2.
        cli_log.emit_failure(str(e))
        return 2
    except LifecycleError as e:
        # Diagnostic (if any) already printed by the raiser; reproduce the
        # exact returncode of the systemctl/podman invocation that failed.
        cli_log.emit_failure(f"lifecycle command failed (exit {e.returncode})")
        return e.returncode
    except ImageTransferError as e:
        # Backstop for `recreate`, which has no per-workload result to emit.
        # `enable` catches this itself so it can emit one.
        print(f"Error: {e}", file=sys.stderr)
        cli_log.emit_failure(str(e))
        return 1
    except ProvisionFailed as e:
        # Raiser prints the "✗ ..." diagnostic. Commands that need to keep going
        # (update --all tallies per-workload failures) catch it themselves; this
        # is the backstop for the ones that just need a clean nonzero exit.
        cli_log.emit_failure(str(e))
        return 1
    except NotRoot as e:
        print(f"Error: {e}", file=sys.stderr)
        cli_log.emit_failure(str(e))
        return 1
    except WorkloadMasked as e:
        print(str(e), file=sys.stderr)
        cli_log.emit_failure(str(e))
        return 1
    except WorkloadUserNotFound as e:
        print(f"Error: {e}", file=sys.stderr)
        cli_log.emit_failure(str(e))
        return 1
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        cli_log.emit_failure(str(e))
        return 1
    except Exception as e:
        # Unexpected: not one of the typed errors above, so it's likely a bug
        # in workloadctl rather than an operator/environment condition. Print
        # the full traceback (not just the message) so a bug report has
        # something to act on.
        traceback.print_exc(file=sys.stderr)
        print(
            "This looks like a workloadctl bug, not a usage error. "
            "Please re-run the command and include the traceback above in a bug report.",
            file=sys.stderr,
        )
        cli_log.emit_failure(f"internal error: {e!r}")
        return 1
    return code
