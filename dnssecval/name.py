"""Domain name handling.

Names are represented as a tuple of *raw* labels (``bytes``), preserving the
original case as seen on the wire.  Case is only folded when canonical forms
or digests are computed, never when records are parsed or compared for
identity at the wire level.
"""

from __future__ import annotations


class WireFormatError(Exception):
    """Raised when a wire message or record is malformed or truncated."""


ROOT = ()


def decode_name(buf: bytes, offset: int = 0) -> tuple[tuple[bytes, ...], int]:
    """Decode a (possibly compressed) wire name.

    Returns the labels and the offset immediately following the name in the
    *uncompressed* case.  A name that consists entirely of compression
    pointers returns the offset just past the first pointer.
    """
    labels: list[bytes] = []
    seen: set[int] = set()
    cursor = offset
    followed_pointer = False
    end_after_pointer = 0
    while True:
        if cursor >= len(buf):
            raise WireFormatError("truncated name: ran past end of message")
        length = buf[cursor]
        if length == 0:
            cursor += 1
            if followed_pointer and end_after_pointer == 0:
                end_after_pointer = cursor
            break
        kind = length & 0xC0
        if kind == 0xC0:
            if cursor + 1 >= len(buf):
                raise WireFormatError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | buf[cursor + 1]
            if not followed_pointer:
                end_after_pointer = cursor + 2
            if pointer in seen or pointer == cursor or pointer >= len(buf):
                raise WireFormatError("invalid or looping compression pointer")
            seen.add(pointer)
            cursor = pointer
            followed_pointer = True
            continue
        if kind != 0:
            raise WireFormatError("reserved label type in name")
        start = cursor + 1
        end = start + length
        if end > len(buf):
            raise WireFormatError("truncated label in name")
        labels.append(buf[start:end])
        cursor = end
    final_offset = end_after_pointer if followed_pointer else cursor
    return tuple(labels), final_offset


def from_text(text: str) -> tuple[bytes, ...]:
    if text in (".", ""):
        return ROOT
    labels = []
    for label in text.rstrip(".").split("."):
        if not label:
            raise WireFormatError("empty label in name")
        encoded = label.encode("ascii")
        if len(encoded) > 63:
            raise WireFormatError("label longer than 63 octets")
        labels.append(encoded)
    return tuple(labels)


def to_text(name: tuple[bytes, ...]) -> str:
    if name == ROOT:
        return "."
    return ".".join(label.decode("ascii", "replace") for label in name) + "."


def to_wire(name: tuple[bytes, ...]) -> bytes:
    out = bytearray()
    for label in name:
        out.append(len(label))
        out.extend(label)
    out.append(0)
    return bytes(out)


def canonical_wire(name: tuple[bytes, ...]) -> bytes:
    out = bytearray()
    for label in name:
        lowered = label.lower()
        out.append(len(lowered))
        out.extend(lowered)
    out.append(0)
    return bytes(out)


def canonical_compare(a: tuple[bytes, ...], b: tuple[bytes, ...]) -> int:
    """RFC 4034 section 6.1 canonical name ordering.

    Names are compared from the most significant (rightmost) label toward the
    left, label-by-label on lower-cased octets; a shorter name sorts before a
    longer one when all shared labels are equal.  Returns -1/0/1.
    """
    rev_a = list(reversed(a))
    rev_b = list(reversed(b))
    for label_a, label_b in zip(rev_a, rev_b):
        low_a, low_b = label_a.lower(), label_b.lower()
        if low_a < low_b:
            return -1
        if low_a > low_b:
            return 1
    if len(a) < len(b):
        return -1
    if len(a) > len(b):
        return 1
    return 0


def canonical_text(name: tuple[bytes, ...]) -> str:
    return to_text(tuple(label.lower() for label in name))


def equal_ci(a: tuple[bytes, ...], b: tuple[bytes, ...]) -> bool:
    if len(a) != len(b):
        return False
    return all(x.lower() == y.lower() for x, y in zip(a, b))


def is_subdomain(child: tuple[bytes, ...], parent: tuple[bytes, ...]) -> bool:
    if len(parent) > len(child):
        return False
    return equal_ci(child[len(child) - len(parent):], parent)


def parent_of(name: tuple[bytes, ...]) -> tuple[bytes, ...]:
    if name == ROOT:
        return ROOT
    return name[1:]


def split_labels(name: tuple[bytes, ...]) -> list[tuple[bytes, ...]]:
    """Return the name and every ancestor, from the name itself up to root."""
    chain = []
    current: tuple[bytes, ...] = name
    while True:
        chain.append(current)
        if current == ROOT:
            break
        current = current[1:]
    return chain
