"""Structured parsers for the DNSSEC record types.

Each parser returns a dataclass plus the raw wire RDATA, so callers can both
inspect fields and retain the original octets for canonical processing.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import constants as C
from .name import WireFormatError, decode_name


def _u16(buf: bytes, off: int) -> int:
    return (buf[off] << 8) | buf[off + 1]


def _u32(buf: bytes, off: int) -> int:
    return int.from_bytes(buf[off:off + 4], "big")


@dataclass(frozen=True)
class DNSKEY:
    flags: int
    protocol: int
    algorithm: int
    public_key: bytes
    rdata: bytes

    @property
    def zone_key(self) -> bool:
        return bool(self.flags & 0x0100)

    @property
    def sep(self) -> bool:
        return bool(self.flags & 0x0001)

    @property
    def key_tag(self) -> int:
        return key_tag(self.rdata)


@dataclass(frozen=True)
class DS:
    key_tag: int
    algorithm: int
    digest_type: int
    digest: bytes
    rdata: bytes


@dataclass(frozen=True)
class RRSIG:
    type_covered: int
    algorithm: int
    labels: int
    original_ttl: int
    signature_expiration: int
    signature_inception: int
    key_tag: int
    signer_name: tuple[bytes, ...]
    signature: bytes
    rdata: bytes
    signer_end: int


@dataclass(frozen=True)
class NSEC:
    next_name: tuple[bytes, ...]
    types: frozenset[int]
    rdata: bytes


@dataclass(frozen=True)
class NSEC3:
    hash_algorithm: int
    flags: int
    iterations: int
    salt: bytes
    next_hashed_owner: bytes
    types: frozenset[int]
    rdata: bytes

    @property
    def opt_out(self) -> bool:
        return bool(self.flags & 0x01)


def parse_dnskey(rdata: bytes) -> DNSKEY:
    if len(rdata) < 4:
        raise WireFormatError("DNSKEY RDATA too short")
    flags = _u16(rdata, 0)
    protocol = rdata[2]
    algorithm = rdata[3]
    public_key = rdata[4:]
    if not public_key:
        raise WireFormatError("DNSKEY with empty public key")
    return DNSKEY(flags, protocol, algorithm, public_key, rdata)


def parse_ds(rdata: bytes) -> DS:
    if len(rdata) < 4:
        raise WireFormatError("DS RDATA too short")
    tag = _u16(rdata, 0)
    algorithm = rdata[2]
    digest_type = rdata[3]
    digest = rdata[4:]
    if not digest:
        raise WireFormatError("DS with empty digest")
    return DS(tag, algorithm, digest_type, digest, rdata)


def parse_rrsig(rdata: bytes) -> RRSIG:
    if len(rdata) < 18:
        raise WireFormatError("RRSIG RDATA too short")
    type_covered = _u16(rdata, 0)
    algorithm = rdata[2]
    labels = rdata[3]
    original_ttl = _u32(rdata, 4)
    expiration = _u32(rdata, 8)
    inception = _u32(rdata, 12)
    tag = _u16(rdata, 16)
    signer, signer_end = decode_name(rdata, 18)
    signature = rdata[signer_end:]
    if not signature:
        raise WireFormatError("RRSIG with empty signature")
    return RRSIG(
        type_covered, algorithm, labels, original_ttl,
        expiration, inception, tag, signer, signature, rdata, signer_end,
    )


def parse_type_bitmap(buf: bytes, offset: int) -> tuple[frozenset[int], int]:
    types: set[int] = set()
    while offset < len(buf):
        if offset + 2 > len(buf):
            raise WireFormatError("truncated type bitmap window header")
        window = buf[offset]
        bitmap_len = buf[offset + 1]
        offset += 2
        if bitmap_len == 0 or offset + bitmap_len > len(buf):
            raise WireFormatError("invalid type bitmap length")
        bitmap = buf[offset:offset + bitmap_len]
        offset += bitmap_len
        for bit_index, octet in enumerate(bitmap):
            if octet == 0:
                continue
            for bit in range(8):
                if octet & (0x80 >> bit):
                    types.add(window * 256 + bit_index * 8 + bit)
    return frozenset(types), offset


def parse_nsec(rdata: bytes) -> NSEC:
    next_name, end = decode_name(rdata, 0)
    types, _ = parse_type_bitmap(rdata, end)
    return NSEC(next_name, types, rdata)


def parse_nsec3(rdata: bytes) -> NSEC3:
    if len(rdata) < 5:
        raise WireFormatError("NSEC3 RDATA too short")
    hash_algorithm = rdata[0]
    flags = rdata[1]
    iterations = _u16(rdata, 2)
    salt_len = rdata[4]
    off = 5
    if off + salt_len > len(rdata):
        raise WireFormatError("truncated NSEC3 salt")
    salt = rdata[off:off + salt_len]
    off += salt_len
    if off >= len(rdata):
        raise WireFormatError("NSEC3 missing hash length")
    hash_len = rdata[off]
    off += 1
    if off + hash_len > len(rdata):
        raise WireFormatError("truncated NSEC3 next hashed owner")
    next_hash = rdata[off:off + hash_len]
    off += hash_len
    types, _ = parse_type_bitmap(rdata, off)
    return NSEC3(hash_algorithm, flags, iterations, salt, next_hash, types, rdata)


def key_tag(dnskey_rdata: bytes) -> int:
    """RFC 4034 Appendix B key tag."""
    acc = 0
    for index, octet in enumerate(dnskey_rdata):
        acc += octet if index % 2 == 0 else octet << 8
    acc += (acc >> 16) & 0xFFFF
    return acc & 0xFFFF


def parse_by_type(rtype: int, rdata: bytes):
    if rtype == C.DNSKEY:
        return parse_dnskey(rdata)
    if rtype == C.DS:
        return parse_ds(rdata)
    if rtype == C.RRSIG:
        return parse_rrsig(rdata)
    if rtype == C.NSEC:
        return parse_nsec(rdata)
    if rtype == C.NSEC3:
        return parse_nsec3(rdata)
    raise WireFormatError(f"no structured parser for type {rtype}")
