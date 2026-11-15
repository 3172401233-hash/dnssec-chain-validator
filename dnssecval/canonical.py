"""Canonical DNS name / RRset forms and the RRSIG signed-data assembly.

Implements RFC 4034 sections 6 (canonical RDATA and RR ordering) and
3.1.8 (the RRSIG RDATA portion that is actually signed).
"""

from __future__ import annotations

from . import constants as C
from . import name as name_mod
from .name import decode_name
from .rdata import RRSIG
from .wire import RR


# RR types whose RDATA embeds one or more domain names that must be
# down-cased in canonical form.  Each entry maps type -> ordered list of the
# byte offsets at which a name begins within RDATA.
def _embedded_name_offsets(rtype: int, rdata: bytes) -> list[int]:
    if rtype in (C.NS, C.CNAME, C.DNAME):
        return [0]
    if rtype == C.SOA:
        _, after_mname = decode_name(rdata, 0)
        return [0, after_mname]
    if rtype == C.NSEC:
        return [0]
    # DNSKEY, DS, RRSIG, A, NSEC3 carry no down-casable name in the RDATA
    # that participates in the generic canonical ordering (the RRSIG signer
    # is handled separately when building signature input).
    return []


def canonical_rdata(rr: RR) -> bytes:
    """Return canonical (name-folded) RDATA for ordering/digest use."""
    offsets = _embedded_name_offsets(rr.rtype, rr.rdata)
    if not offsets:
        return rr.rdata
    buf = bytearray(rr.rdata)
    for start in offsets:
        labels, end = decode_name(bytes(buf), start)
        folded = name_mod.canonical_wire(labels)
        buf[start:end] = folded
    return bytes(buf)


def canonical_rr_wire(rr: RR, ttl: int | None = None) -> bytes:
    """Full canonical wire form of an RR, with the RRset TTL substituted."""
    effective_ttl = rr.ttl if ttl is None else ttl
    out = bytearray()
    out += name_mod.canonical_wire(rr.name)
    out += rr.rtype.to_bytes(2, "big")
    out += rr.rclass.to_bytes(2, "big")
    out += effective_ttl.to_bytes(4, "big")
    crdata = canonical_rdata(rr)
    out += len(crdata).to_bytes(2, "big")
    out += crdata
    return bytes(out)


def sorted_rrset(records: list[RR]) -> list[RR]:
    """Canonical order: ascending canonical RDATA octets (RFC 4034 6.3)."""
    return sorted(records, key=lambda rr: canonical_rdata(rr))


def rrset_ttl(records: list[RR], sig: RRSIG) -> int:
    """The TTL used in the signed form is min(RRset TTLs, original TTL)."""
    minimum = min(rr.ttl for rr in records)
    return min(minimum, sig.original_ttl)


def build_signed_data(records: list[RR], sig: RRSIG) -> bytes:
    """Assemble the data that an RRSIG signature is computed over."""
    # RRSIG RDATA up to but excluding the signature field, with the signer
    # name in canonical (lower-cased) form.
    head = bytearray(sig.rdata[:sig.signer_end])
    signer_canonical = name_mod.canonical_wire(sig.signer_name)
    # The signer name occupies the tail of the head region; rebuild head as
    # prefix + canonical signer to fold its case.
    prefix = bytes(sig.rdata[:18])
    rrsig_part = prefix + signer_canonical

    ttl = rrset_ttl(records, sig)
    out = bytearray(rrsig_part)
    for rr in sorted_rrset(records):
        out += canonical_rr_wire(rr, ttl)
    return bytes(out)
