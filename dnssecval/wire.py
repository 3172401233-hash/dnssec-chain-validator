"""Wire-format parsing and the core RR / RRset data model.

The validator works on *offline* captures, so every input is a fully captured
wire message (the standard answer/authority/additional sections) or a single
wire resource record.  Parsing is strict about truncation: a record whose
fixed header or advertised RDATA runs past the buffer raises
:class:`TruncatedWire` rather than being silently accepted.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .name import WireFormatError, decode_name


class TruncatedWire(WireFormatError):
    """A wire record or message ended before its advertised length."""


@dataclass(frozen=True)
class RR:
    """A single resource record.

    ``rdata`` is the raw, uncompressed RDATA exactly as carried on the wire.
    Parsed name fields inside RDATA are kept separately only by the
    specialised record modules; the generic RR retains the octets, which is
    what canonical ordering and signature verification operate on.
    """

    name: tuple[bytes, ...]
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes

    def key(self) -> tuple:
        return (self.name, self.rtype, self.rclass)


@dataclass
class Message:
    answers: list[RR] = field(default_factory=list)
    authority: list[RR] = field(default_factory=list)
    additional: list[RR] = field(default_factory=list)

    def all_rrs(self) -> list[RR]:
        return self.answers + self.authority + self.additional


def _u16(buf: bytes, offset: int) -> int:
    return (buf[offset] << 8) | buf[offset + 1]


def _u32(buf: bytes, offset: int) -> int:
    return (
        (buf[offset] << 24)
        | (buf[offset + 1] << 16)
        | (buf[offset + 2] << 8)
        | buf[offset + 3]
    )


def parse_rr(buf: bytes, offset: int) -> tuple[RR, int]:
    """Parse one resource record starting at ``offset``."""
    try:
        owner, offset = decode_name(buf, offset)
        if offset + 10 > len(buf):
            raise TruncatedWire("truncated RR fixed header")
        rtype = _u16(buf, offset)
        rclass = _u16(buf, offset + 2)
        ttl = _u32(buf, offset + 4)
        rdlen = _u16(buf, offset + 8)
        offset += 10
        end = offset + rdlen
        if end > len(buf):
            raise TruncatedWire(
                f"truncated RDATA for {rtype}: need {rdlen} octets, "
                f"have {len(buf) - offset}"
            )
        rdata = bytes(buf[offset:end])
        return RR(owner, rtype, rclass, ttl, rdata), end
    except IndexError as exc:  # defensive: _u16/_u32 bounds
        raise TruncatedWire("truncated RR") from exc


def parse_message(buf: bytes) -> Message:
    """Parse a full DNS message, returning records grouped by section."""
    if len(buf) < 12:
        raise TruncatedWire("message shorter than 12-octet header")
    qdcount = _u16(buf, 4)
    ancount = _u16(buf, 6)
    nscount = _u16(buf, 8)
    arcount = _u16(buf, 10)
    offset = 12
    for _ in range(qdcount):
        _, offset = decode_name(buf, offset)
        if offset + 4 > len(buf):
            raise TruncatedWire("truncated question section")
        offset += 4
    msg = Message()
    sections = [
        (ancount, msg.answers),
        (nscount, msg.authority),
        (arcount, msg.additional),
    ]
    for count, target in sections:
        for _ in range(count):
            rr, offset = parse_rr(buf, offset)
            target.append(rr)
    return msg


def parse_single_rr(buf: bytes) -> RR:
    """Parse a buffer that holds exactly one wire resource record."""
    rr, end = parse_rr(buf, 0)
    if end != len(buf):
        raise WireFormatError("trailing octets after single RR")
    return rr


def group_rrsets(records: list[RR]) -> dict[tuple, list[RR]]:
    """Group records into RRsets keyed by (name, type, class).

    Duplicate records (identical name/type/class/rdata/ttl) collapse to a
    single entry, mirroring the set semantics of an RRset.
    """
    groups: dict[tuple, list[RR]] = {}
    seen: dict[tuple, set[bytes]] = {}
    for rr in records:
        key = rr.key()
        groups.setdefault(key, [])
        dedup = seen.setdefault(key, set())
        if rr.rdata in dedup:
            continue
        dedup.add(rr.rdata)
        groups[key].append(rr)
    return groups
