"""NSEC / NSEC3 hashing and authenticated-denial logic.

The functions here decide whether a captured proof *covers* a queried name
and type.  Cryptographic validity of the proof records is established
elsewhere (the chain validator signs them); this module only reasons about
name ordering and type-bitmap semantics per RFC 4034 / RFC 5155 / RFC 7129.
"""

from __future__ import annotations

import base64
import hashlib

from . import constants as C
from . import name as name_mod
from .name import canonical_wire
from .rdata import NSEC3


class NsecError(Exception):
    pass


def _wire_unsigned(name: tuple[bytes, ...]) -> bytes:
    """Length-prefixed label wire form without the trailing root octet."""
    out = bytearray()
    for label in name:
        out.append(len(label))
        out.extend(label)
    return bytes(out)


def nsec3_hash(name: tuple[bytes, ...], hash_algorithm: int,
               iterations: int, salt: bytes) -> bytes:
    """RFC 5155 section 5 hashed-owner-name computation."""
    hash_name = C.NSEC3_DIGESTS.get(hash_algorithm)
    if hash_name is None:
        raise NsecError(f"NSEC3 hash algorithm {hash_algorithm} unsupported")
    digest = hashlib.new(hash_name)
    digest.update(_wire_unsigned(name))
    digest.update(salt)
    value = digest.digest()
    for _ in range(iterations):
        digest = hashlib.new(hash_name)
        digest.update(value)
        digest.update(salt)
        value = digest.digest()
    return value


def hashed_owner_label(hash_value: bytes) -> bytes:
    """The base32hex (no padding) label that carries an NSEC3 hash."""
    return base64.b32encode(hash_value).rstrip(b"=").lower()


def nsec3_owner_name(zone: tuple[bytes, ...], hash_value: bytes) -> tuple[bytes, ...]:
    return (hashed_owner_label(hash_value),) + zone


def _name_in_range(name: tuple[bytes, ...],
                   interval_start: tuple[bytes, ...],
                   interval_end: tuple[bytes, ...]) -> bool:
    """NSEC range test: start < name <= end on the canonical name order.

    A wrapped record (end <= start on the linear order) covers the region
    from start to the end of the name space and from root to end.
    """
    start_cmp = name_mod.canonical_compare(interval_start, interval_end)
    target_vs_start = name_mod.canonical_compare(interval_start, name)
    target_vs_end = name_mod.canonical_compare(name, interval_end)
    if start_cmp < 0:
        # Non-wrapping interval (start, end]: start < name <= end.
        return target_vs_start < 0 and target_vs_end <= 0
    # Last record in the zone wraps around the canonical name space.
    return target_vs_start < 0 or target_vs_end <= 0


def _hash_in_range(hash_value: bytes, start: bytes, end: bytes) -> bool:
    if start < end:
        return start < hash_value <= end
    return hash_value > start or hash_value <= end


def nsec_covers_name(nsec_rr, qname: tuple[bytes, ...]) -> bool:
    """``nsec_rr`` is a wire RR of type NSEC; parse then range-test."""
    from .rdata import parse_nsec

    parsed = parse_nsec(nsec_rr.rdata)
    return _name_in_range(qname, nsec_rr.name, parsed.next_name)


def nsec3_covers_name(nsec3_rr, zone: tuple[bytes, ...],
                      qname: tuple[bytes, ...]) -> bool:
    from .rdata import parse_nsec3

    parsed: NSEC3 = parse_nsec3(nsec3_rr.rdata)
    target = nsec3_hash(qname, parsed.hash_algorithm, parsed.iterations, parsed.salt)
    # Owner name is <base32 hash>.zone; the leading label is the start hash.
    if not name_mod.is_subdomain(nsec3_rr.name, zone):
        return False
    start_label = nsec3_rr.name[0]
    try:
        start_hash = base64.b32decode(
            start_label.upper() + b"=" * ((8 - len(start_label) % 8) % 8)
        )
    except Exception as exc:  # malformed base32 label
        raise NsecError("undecodable NSEC3 owner label") from exc
    return _hash_in_range(target, start_hash, parsed.next_hashed_owner)


def closest_encloser_proof(zone: tuple[bytes, ...], qname: tuple[bytes, ...],
                           nsec3_records, params: NSEC3) -> bool:
    """RFC 7129 NXDOMAIN proof: closest encloser exists, next-closer does not.

    Walking the qname labels from the apex upward, the *closest encloser* is
    the longest ancestor whose hashed name is itself an NSEC3 owner (so it is
    proven to exist).  The *next closer* name is that encloser plus one more
    qname label; an NSEC3 interval must cover its hash, proving that name (and
    therefore everything beneath it, including qname) does not exist.
    """
    if not name_mod.is_subdomain(qname, zone):
        return False
    owner_hashes = set()
    for rr in nsec3_records:
        try:
            owner_hashes.add(_owner_hash(rr))
        except NsecError:
            continue

    # Enumerate enclosers starting at qname itself and stripping labels.
    for strip in range(0, len(qname) - len(zone) + 1):
        encloser = qname[strip:]
        encloser_hash = nsec3_hash(
            encloser, params.hash_algorithm, params.iterations, params.salt
        )
        if encloser_hash not in owner_hashes:
            continue
        # This encloser exists; the next-closer is one label deeper toward qname.
        if strip == 0:
            next_closer = qname
        else:
            next_closer = qname[strip - 1:]
        for rr in nsec3_records:
            try:
                if nsec3_covers_name(rr, zone, next_closer):
                    return True
            except NsecError:
                continue
        # Closest encloser found but no covering record: proof is incomplete.
        return False
    return False


def _owner_hash(nsec3_rr) -> bytes:
    label = nsec3_rr.name[0]
    return base64.b32decode(
        label.upper() + b"=" * ((8 - len(label) % 8) % 8)
    )


def wildcard_nsec_covers(nsec_rr, qname: tuple[bytes, ...]) -> bool:
    """NSEC record whose owner is the matching wildcard (RFC 7129)."""
    if not nsec_rr.name or nsec_rr.name[0] != b"*":
        return False
    # The wildcard *.parent matches qname when qname is one label deeper.
    wildcard_parent = nsec_rr.name[1:]
    return name_mod.is_subdomain(qname, wildcard_parent) and len(qname) == len(wildcard_parent) + 1


def wildcard_nsec3_covers(zone: tuple[bytes, ...], qname: tuple[bytes, ...],
                          nsec3_records, params: NSEC3) -> bool:
    """NSEC3 wildcard-existence proof for NODATA under a wildcard."""
    # Closest encloser = qname minus its leading label; wildcard = *.encloser.
    if len(qname) <= len(zone):
        return False
    encloser = qname[1:]
    wildcard = (b"*",) + encloser
    wildcard_hash = nsec3_hash(
        wildcard, params.hash_algorithm, params.iterations, params.salt
    )
    for rr in nsec3_records:
        if _owner_hash(rr) == wildcard_hash:
            return True
    return False
