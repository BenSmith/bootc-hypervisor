"""
diagnose_vm_clock — is the guest's clock right, and can the keeper see it?

The clock keeper (workload-<name>-clock.timer, lib/vm_clock.py) repairs a
paused guest once a minute and is SILENT about a guest it cannot reach: a
guest whose image lacks qemu-guest-agent is a supported configuration, and a
timer that said so once a minute forever would be a journal nobody reads.
That leaves exactly one place for the fact to surface, and it is here, when
an operator asks. The verdict function is pure; the battery does the one
round trip and hands the number in.

Two failures, deliberately distinguished, because their fixes are different
people's: no answer is the GUEST's problem (install the agent), while an
answer that is far out is the HOST's (the keeper is not doing its job, or
has not yet -- a guest resumed inside the last minute is skewed and about to
be repaired, and a red line for that minute is the truth).
"""
from vm_clock import CLOCK_SKEW_THRESHOLD_SECONDS


def vm_guest_clock_check(
        offset: float | None, name: str, *,
        threshold: float = CLOCK_SKEW_THRESHOLD_SECONDS,
) -> tuple[bool, str, str | None]:
    """(passed, message, fix) for one guest's measured clock offset.

    `offset` is guest minus host in seconds, or None when the agent did not
    answer -- the same reading the keeper takes (vm_clock.guest_clock_offset).
    The threshold is the keeper's, so the line goes red exactly where the
    keeper would act.
    """
    if offset is None:
        return (False,
                "guest agent does not answer: the clock keeper cannot see or "
                "set this guest's clock",
                f"install and enable qemu-guest-agent in the guest (the "
                f"built-in seed does). Until then a paused or suspended "
                f"{name} keeps a rewound clock, and fails TLS on every name "
                f"it has not already visited")
    if abs(offset) <= threshold:
        return (True, f"guest clock within {abs(offset):.1f}s of the host's",
                None)
    return (False,
            f"guest clock is {offset:+.1f}s from the host's, past the "
            f"{threshold:.0f}s the keeper repairs at",
            f"the keeper puts it back within a minute of a resume; if this "
            f"persists: sudo systemctl status workload-{name}-clock.timer && "
            f"sudo journalctl -u workload-{name}-clock -n 20")
