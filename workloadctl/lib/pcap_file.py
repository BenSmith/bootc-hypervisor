"""Classic pcap files, read and rewritten with `struct` alone.

Packet count, first timestamp, and the guest-side timestamp shift. Classic
pcap is a 24-byte header, then 16 bytes and payload per packet, and both
capture writers emit it (tcpdump is told to; QEMU hard-codes PCAP_MAGIC,
net/dump.c:43). Done here rather than through capinfos and editcap because
those ship in wireshark-cli, a `Suggests:` dnf does not install, while
tcpdump is a `Recommends:` that it does -- so a default host had the capture
tool and neither finisher, and a missing finisher in a `finally` aborted the
helper's teardown. Parsing capinfos' output was its own silent failure: its
"First packet time" label changed between releases, and matching one skipped
the correction without saying so. Reading the field cannot.

Microseconds for the a1b2c3d4 pair, nanoseconds for a1b23c4d, each byte-
swapped when writer and reader disagree on endianness. The magic
distinguishes them, so a 1000x error is unrepresentable.

Installed to /usr/libexec/workloadctl/pcap_file.py.
"""

import os
import struct

_PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4": ("<", 1_000_000),
    b"\xd4\xc3\xb2\xa1": (">", 1_000_000),
    b"\xa1\xb2\x3c\x4d": ("<", 1_000_000_000),
    b"\x4d\x3c\xb2\xa1": (">", 1_000_000_000),
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

PCAP_GLOBAL_HEADER_LEN = 24
PCAP_RECORD_HEADER_LEN = 16


class PcapFormatError(ValueError):
    """A file that is not a classic pcap we can read."""


def _read_pcap_header(handle) -> tuple[str, int]:
    """Consume the 24-byte global header. Returns (endianness, ticks/second).

    pcapng is named rather than lumped into "not a pcap file": it is what an
    operator is most likely to point this at by mistake.
    """
    magic = handle.read(4)
    if magic == _PCAPNG_MAGIC:
        raise PcapFormatError(
            "this is a pcapng file; workloadctl writes and reads classic pcap")
    try:
        endian, ticks = _PCAP_MAGICS[magic]
    except KeyError:
        raise PcapFormatError(
            f"not a classic pcap file (magic {magic.hex() or 'empty'})"
        ) from None
    handle.read(PCAP_GLOBAL_HEADER_LEN - 4)
    return endian, ticks


def pcap_first_timestamp(path: str) -> float | None:
    """Epoch seconds of the first packet, or None if the file holds none.

    Reads 40 bytes. "No packets" is a None and "unreadable" is a raise — a
    distinction capinfos could only make through a return code.
    """
    with open(path, "rb") as handle:
        endian, ticks = _read_pcap_header(handle)
        header = handle.read(PCAP_RECORD_HEADER_LEN)
        if len(header) < PCAP_RECORD_HEADER_LEN:
            return None
        seconds, fraction = struct.unpack(endian + "II", header[:8])
        return seconds + fraction / ticks


def pcap_packet_count(path: str) -> int:
    """Packets in a finished capture, by walking the record headers.

    Whole records only: a capture killed mid-write leaves a torn one, and this
    number is compared against what the kernel handed to nflog to notice a
    shortfall. Payloads are seeked over, not read — 0.9 s for 1M packets.
    """
    size = os.path.getsize(path)
    with open(path, "rb") as handle:
        endian, _ticks = _read_pcap_header(handle)
        unpack = struct.Struct(endian + "IIII").unpack
        count = 0
        while True:
            header = handle.read(PCAP_RECORD_HEADER_LEN)
            if len(header) < PCAP_RECORD_HEADER_LEN:
                return count
            _seconds, _fraction, captured, _original = unpack(header)
            # Bounds the seek against the file rather than against a length
            # from the file, so a corrupt record header cannot walk past EOF.
            if handle.tell() + captured > size:
                return count
            handle.seek(captured, 1)
            count += 1


def pcap_shift_timestamps(src: str, dst: str, delta: float) -> int:
    """Copy `src` to `dst` with every timestamp moved by `delta` seconds.

    What `editcap -t` did. The global header is copied verbatim; magic, snaplen
    and link type are the writer's business.

    Integer ticks, not float seconds: a 2026 epoch needs 16 significant digits
    to hold microseconds, past what float64 carries, so float arithmetic would
    jitter the low digit of every packet. `delta` is the only rounding.
    """
    delta_ticks: int | None = None
    written = 0
    size = os.path.getsize(src)
    with open(src, "rb") as source, open(dst, "wb") as out:
        endian, ticks = _read_pcap_header(source)
        source.seek(0)
        out.write(source.read(PCAP_GLOBAL_HEADER_LEN))
        delta_ticks = round(delta * ticks)
        record = struct.Struct(endian + "IIII")
        while True:
            header = source.read(PCAP_RECORD_HEADER_LEN)
            if len(header) < PCAP_RECORD_HEADER_LEN:
                break
            seconds, fraction, captured, original = record.unpack(header)
            if source.tell() + captured > size:
                break            # torn final record, same rule as the count
            # Clamped at the epoch: a shift large enough to go negative would
            # wrap the unsigned field into 2106 rather than fail.
            shifted = max(0, seconds * ticks + fraction + delta_ticks)
            new_seconds, new_fraction = divmod(shifted, ticks)
            out.write(record.pack(new_seconds, new_fraction, captured, original))
            out.write(source.read(captured))
            written += 1
    return written
