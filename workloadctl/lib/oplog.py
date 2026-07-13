"""
oplog — the per-workload operations log.

One JSON object per line in `/var/lib/workloads/<name>/operations.log`: what
changed a workload, when, at whose hand, and what the outcome was. It answers
"when was this rolled back, and from what image?" without reading the journal.

**It is a record, not an audit trail.** Only root can run the verbs that write
here, and root can equally edit or delete the file — so it is worthless as a
tamper-evident control and is not offered as one. What it is good for is the
thing the journal is bad at: `sudo` already logs *that* someone ran
`workloadctl update web`; nothing recorded that the update moved nginx from
1f2e3d4c to 9a8b7c6d, or that two workloads failed their health check and got
rolled back. That outcome is what lands here.

Placement, and what each choice buys:

- **Beside the workload, not host-global.** The record lives next to the thing
  it describes, so there is nothing central to keep tidy and no correlation
  step. Every line leads with a UTC timestamp, so
  `cat /var/lib/workloads/*/operations.log | sort` still reconstructs a
  host-wide timeline.
- **At the workload root, not under `state/` or `data/`.** Only `data/` is
  captured by backup, so a restore doesn't import some other host's history
  into a fresh workload — which is right, because this describes what *this
  host* did, not what the workload owns. And `state/` is owned by the rootless
  `_wl-<name>` user; the root dir is not, so the workload can't touch its own
  record.
- **Purge takes it with them.** `disable --purge` rmtree's the workload root,
  and the log goes too. That is coherent — the workload is gone — and the
  alternative (a host-global tombstone) reintroduces exactly the central file
  this design avoids.

Writing here is best-effort in the strict sense: a failure to record must never
be the reason an operation reports failure. Every error path below warns and
returns.
"""

import datetime
import json
import logging
import os
import pwd
from pathlib import Path

from workload_lib import workload_root_dir


# The same channel cli_log warns on, reached by logger name rather than by
# importing cli_log — which imports *this* module to fan emit_result() out to
# both sinks. Depending on the stdlib logger keeps that graph acyclic and the
# direction natural (cli_log → oplog → workload_lib).
_logger = logging.getLogger("workloadctl")


OPLOG_NAME = "operations.log"

# Results that record nothing, and why:
#   dry-run / listed — the verb reported a plan or a report; nothing changed.
#   purged           — the directory the log lives in was just deleted. Warning
#                      about the absent dir here would fire on every purge.
NON_MUTATING_RESULTS = frozenset({"dry-run", "listed", "purged"})

# One warning per process. A batch (`update --all`) would otherwise repeat the
# same "can't write" line once per workload.
_warned = False


LOGINUID_PATH = Path("/proc/self/loginuid")

# The kernel's "no login session" sentinel: (uid_t)-1. A process with this
# loginuid was not started by any human login — it is a daemon, a systemd unit,
# a timer. Distinguishing that from a person at a root console is the whole
# reason we consult loginuid at all.
LOGINUID_NONE = 0xFFFFFFFF


def _uid_name(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def _login_uid() -> int | None:
    """The audit login uid, or None if there is no login session behind us.

    PAM sets /proc/self/loginuid at login and the kernel makes it immutable
    thereafter (changing it needs CAP_AUDIT_CONTROL), so it survives `su`,
    `sudo`, and any number of nested root shells: it names *which human logged
    in*, however many privilege hops later the command actually ran. Absent on
    a kernel without CONFIG_AUDIT, which is the same as "we don't know".
    """
    try:
        raw = LOGINUID_PATH.read_text().strip()
    except OSError:
        return None
    try:
        uid = int(raw)
    except ValueError:
        return None
    return None if uid == LOGINUID_NONE else uid


def _invoker() -> tuple[str, str]:
    """Who ran this, and how much to trust the answer: (user, source).

    Three sources, most trustworthy first:

    - `login` — from the audit loginuid. The only one of the three that is not
      forgeable from userspace, and the only one that survives `su -` (where
      SUDO_USER is never set and the real uid is just 0). Says "ben" even three
      shells deep in root.
    - `sudo` — SUDO_USER. A plain environment variable, so trivially spoofable;
      that costs nothing here, since root can rewrite this whole file anyway and
      the log claims no tamper-evidence. Kept as the fallback for a kernel with
      no audit support.
    - `system` — no login session at all: a systemd unit, a timer, cron. This is
      the case the old SUDO_USER-only derivation got wrong, reporting a bare
      "root" that a human at a root console would produce too.
    """
    uid = _login_uid()
    if uid is not None:
        return _uid_name(uid), "login"
    who = os.environ.get("SUDO_USER")
    if who:
        return who, "sudo"
    return _uid_name(os.getuid()), "system"


def _warn_once(message: str) -> None:
    global _warned
    if _warned:
        return
    _warned = True
    _logger.warning(f"  ⚠ operations log: {message}")


def record(command: str | None, rows: list[dict], *, ok: bool = True) -> None:
    """Append one line per mutated workload. Never raises.

    `rows` are the result rows the verb reported (see cli_log.emit_result), so
    the log and `--json` can't drift: they are the same dict, and anything a
    verb learns to report is recorded without a second call site to remember.
    """
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    user, source = _invoker()

    for row in rows:
        name = row.get("workload")
        if not name or row.get("result") in NON_MUTATING_RESULTS:
            continue

        root = workload_root_dir(name)
        if not root.is_dir():
            # Nothing to hang the log off. The workload root is created early in
            # enable and torn down only by purge, so this means the workload was
            # never provisioned — worth saying out loud, never worth failing for.
            _warn_once(f"{root} does not exist; not recording {command} of '{name}'")
            continue

        entry = {"ts": ts, "command": command, "ok": ok,
                 "user": user, "user_source": source}
        entry.update(row)

        try:
            # O_APPEND so concurrent invocations interleave whole lines rather
            # than overwrite each other; explicit 0644 so the mode doesn't ride
            # on whatever umask the operator's shell happened to have.
            fd = os.open(root / OPLOG_NAME,
                         os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
            try:
                os.write(fd, (json.dumps(entry, default=str) + "\n").encode())
            finally:
                os.close(fd)
        except OSError as e:
            _warn_once(f"could not write {root / OPLOG_NAME}: {e}")


def read(name: str, limit: int | None = None) -> list[dict]:
    """The workload's recorded operations, oldest first (the last `limit` if given).

    Tolerates a corrupt line rather than failing the read: a half-written entry
    (a machine that lost power mid-append) must not make the rest unreadable.
    """
    path = workload_root_dir(name) / OPLOG_NAME
    if not path.is_file():
        return []
    entries = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except ValueError:
            continue
    return entries[-limit:] if limit else entries
