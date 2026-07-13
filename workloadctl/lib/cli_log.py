"""
cli_log — the CLI's prose channel, and the JSON result object for mutating verbs.

Two kinds of text come out of a command and they are not the same thing:

- **Prose** — what workloadctl says *about* what it is doing: progress, status,
  diagnostics. It goes through this module.
- **Output** — what the command was *asked* to produce: reports (`list`,
  `status`, `drift`), dry-run plans, JSON documents, passthrough payloads
  (`incant`, `logs`, `stats`). It stays on plain `print()`.

That split is what makes `--quiet` safe to add: it silences the narration and
can never eat the answer. Anything an operator would be angry to lose when they
asked for it is output, not prose.

Severity is real. `info()` lands on stdout, `warn()` / `error()` on stderr, so
the two survive a redirect (`workloadctl update --all >log 2>errors`). `--quiet`
raises the threshold to WARNING: failures and warnings still speak, the running
commentary doesn't.

`--json` does the same *and* reserves stdout for the result object, which the
mutating verbs emit through `emit_result()` — so a caller can pipe stdout
straight into `jq` while the prose-free diagnostics still go to stderr.

Handlers resolve `sys.stdout` / `sys.stderr` at emit time instead of binding the
stream when the handler is built: a caller that replaces either afterwards (the
test suite, via `redirect_stdout`) must still capture what we write.
"""

import json
import logging
import sys


LOGGER_NAME = "workloadctl"

_logger = logging.getLogger(LOGGER_NAME)

_state = {
    "quiet": False,
    "json": False,
    "command": None,
    "emitted": False,
}


class _StdStreamHandler(logging.Handler):
    """Emit to sys.stdout / sys.stderr, looked up per record."""

    def __init__(self, stream_name: str):
        super().__init__()
        self._stream_name = stream_name

    def emit(self, record: logging.LogRecord) -> None:
        try:
            stream = getattr(sys, self._stream_name)
            stream.write(self.format(record) + "\n")
            stream.flush()
        except Exception:  # pragma: no cover - logging's own error path
            self.handleError(record)


def _below_warning(record: logging.LogRecord) -> bool:
    return record.levelno < logging.WARNING


def _install_handlers() -> None:
    """Wire the two handlers onto the workloadctl logger (idempotent).

    Import-time setup, so a command module that logs before (or without) a
    configure() call — every unit test that calls a cmd_ function directly —
    still gets the default verbose behaviour.
    """
    if _logger.handlers:
        return
    out = _StdStreamHandler("stdout")
    out.addFilter(_below_warning)
    err = _StdStreamHandler("stderr")
    err.setLevel(logging.WARNING)
    _logger.addHandler(out)
    _logger.addHandler(err)
    _logger.setLevel(logging.INFO)
    # The root logger is nobody's business here: workloadctl is not a library
    # whose logs someone else configures, and propagating would double-print
    # under any caller that did touch the root.
    _logger.propagate = False


_install_handlers()


def configure(*, quiet: bool = False, json_mode: bool = False,
              command: str | None = None) -> None:
    """Set the output mode for this process. Called once, from the entrypoint."""
    _state["quiet"] = quiet
    _state["json"] = json_mode
    _state["command"] = command
    _state["emitted"] = False
    # JSON mode implies quiet prose: stdout belongs to the result object.
    _logger.setLevel(logging.WARNING if (quiet or json_mode) else logging.INFO)


def reset() -> None:
    """Restore the default (verbose, non-JSON) mode. For tests."""
    configure()


def is_quiet() -> bool:
    """True when prose is suppressed (either --quiet or --json)."""
    return _state["quiet"] or _state["json"]


def json_enabled() -> bool:
    return _state["json"]


def info(message: str = "") -> None:
    """Progress / status prose → stdout. Suppressed by --quiet and --json."""
    _logger.info(message)


def warn(message: str) -> None:
    """A condition the operator should see but that isn't fatal → stderr."""
    _logger.warning(message)


def error(message: str) -> None:
    """A failure → stderr. Survives --quiet."""
    _logger.error(message)


def partial(message: str) -> None:
    """Write prose to stdout with no trailing newline (a progress tick).

    Bypasses `logging`, which always terminates a record — the "waiting… done"
    idiom needs a line to stay open. Honors the same suppression as info().
    """
    if is_quiet():
        return
    sys.stdout.write(message)
    sys.stdout.flush()


def emit_result(workloads: list[dict], *, ok: bool = True, **extra) -> None:
    """Emit a mutating verb's JSON result object. No-op unless --json.

    The shape is fixed so a script can treat every mutating verb the same:
    the command that ran, whether it succeeded overall, and one row per
    workload it touched (`{"workload": …, "result": …}`, plus whatever the
    verb can say about it — old/new image, failure reason). Verb-specific
    top-level keys (a `summary`, a dry-run `plan`) ride in **extra.
    """
    if not _state["json"]:
        return
    payload = {
        "command": _state["command"],
        "ok": ok,
        "workloads": list(workloads),
    }
    payload.update(extra)
    _state["emitted"] = True
    # default=str: rows carry domain values (a VM rollback target names its
    # generation file as a Path), and a serialization crash must never be how
    # an operator finds out their update succeeded.
    print(json.dumps(payload, indent=2, default=str))


def emit_failure(message: str) -> None:
    """Emit a JSON failure object for a command that died before it could
    report its own result. No-op unless --json, and never overwrites a result
    the command already emitted (a partly-failed `update --all` reports its own
    per-workload detail, which is strictly better than this backstop).
    """
    if not _state["json"] or _state["emitted"]:
        return
    _state["emitted"] = True
    print(json.dumps({
        "command": _state["command"],
        "ok": False,
        "workloads": [],
        "error": message,
    }, indent=2))
