"""Recovering the listeners a .socket unit passed in.

Shared by the two programs that are socket-activated and never bind:
`libexec/workload-vm-inspect-listener` and `libexec/workload-vm-resolve`.
Both take their sockets from systemd and refuse to open one of their own --
but for different reasons, which is why `refusal` is a parameter rather than
a sentence written here. The listener's bind must stay in the inherited fd to
keep it out of the workload SELinux domain; the resolver's port 53 is
privileged and the process is not. An operator who hits this needs the reason
that applies to the program they are looking at, so each supplies its own.

Only the *reason* differs. Reading LISTEN_PID/LISTEN_FDS, refusing an
activation environment that belongs to another process, and turning the fd
range into sockets are identical in both, and are here.
"""
import os
import socket


class NotSocketActivated(Exception):
    """The process was not handed its listeners by the socket unit."""


def inherited_listening_sockets(*, refusal: str) -> list[socket.socket]:
    """Recover the sockets systemd passed in, or fail loudly.

    Reads LISTEN_PID and LISTEN_FDS; the fds are 3 .. 3+LISTEN_FDS.
    socket.socket(fileno=fd) recovers each one's family and type from the fd on
    Linux, so this does not have to be told which of them is which.

    `refusal` completes the sentence explaining why no fallback bind happens;
    it is appended to "It refuses to open a socket of its own".
    """
    listen_pid = os.environ.get("LISTEN_PID")
    listen_fds = os.environ.get("LISTEN_FDS")
    missing = [name for name, value in (("LISTEN_PID", listen_pid),
                                        ("LISTEN_FDS", listen_fds))
               if value is None]
    if missing:
        raise NotSocketActivated(
            "this program is socket-activated and never binds: it takes its "
            f"sockets from the .socket unit, but {', '.join(missing)} is not "
            f"set. It refuses to open a socket of its own{refusal}")
    if listen_pid != str(os.getpid()):
        raise NotSocketActivated(
            f"LISTEN_PID={listen_pid} is not this process ({os.getpid()}); "
            "the activation environment belongs to another process, so the "
            "inherited fds would not be ours to use")
    try:
        count = int(listen_fds)
    except ValueError:
        raise NotSocketActivated(
            f"LISTEN_FDS={listen_fds!r} is not an integer") from None
    return [socket.socket(fileno=fd) for fd in range(3, 3 + count)]
