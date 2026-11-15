"""Shared fixtures: build a signed root -> child zone chain on demand."""

from __future__ import annotations

from dnssecval import builder
from dnssecval import constants as C
from dnssecval import name as name_mod
from dnssecval.validator import TrustAnchor, ZoneData
from dnssecval.wire import RR


class SignedZone:
    def __init__(self, apex: str, algorithm: int, ttl: int = 3600):
        self.apex = apex
        self.algorithm = algorithm
        self.ttl = ttl
        self.private = builder.generate_key(algorithm)
        dnskey_rd = builder.dnskey_rdata(algorithm, self.private.public_key())
        self.dnskey = builder.make_rr(apex, C.DNSKEY, dnskey_rd, ttl)
        self.records: list[RR] = [self.dnskey]

    @property
    def key_tag(self) -> int:
        from dnssecval import rdata
        return rdata.key_tag(self.dnskey.rdata)

    def add(self, rr: RR) -> RR:
        self.records.append(rr)
        return rr

    def sign_dnskey(self, inception: int, expiration: int) -> RR:
        sig = builder.sign_rrset(
            [self.dnskey], self.apex, self.algorithm, self.private,
            self.key_tag, inception=inception, expiration=expiration,
        )
        self.records.append(sig)
        return sig


def build_two_zone_chain(now: int, root_alg=C.Algo.RSASHA256,
                         child_alg=C.Algo.ECDSA_P256_SHA256,
                         root_apex=".", child_apex="example."):
    root = SignedZone(root_apex, root_alg)
    child = SignedZone(child_apex, child_alg)

    # Root DS for the child key, signed by the root key.
    ds_rd = builder.ds_rdata(child.dnskey, child_apex)
    ds = builder.make_rr(child_apex, C.DS, ds_rd, root.ttl)
    root.add(ds)
    root_ds_sig = builder.sign_rrset(
        [ds], root_apex, root_alg, root.private, root.key_tag,
        inception=now - 3600, expiration=now + 3600,
    )
    root.add(root_ds_sig)

    # Self-sign each apex DNSKEY RRset.
    root.sign_dnskey(now - 3600, now + 3600)
    child.sign_dnskey(now - 3600, now + 3600)

    # Root SOA so negative responses carry authority.
    root_soa = builder.make_rr(
        root_apex, C.SOA, builder.soa_rdata(root_apex, "hostmaster." + root_apex),
    )
    root.add(root_soa)
    child_soa = builder.make_rr(
        child_apex, C.SOA,
        builder.soa_rdata(child_apex, "hostmaster." + child_apex),
    )
    child.add(child_soa)

    root_anchor = TrustAnchor(name_mod.from_text(root_apex), root.dnskey)
    zones = {
        name_mod.from_text(root_apex): ZoneData(root.records),
        name_mod.from_text(child_apex): ZoneData(child.records),
    }
    return root, child, root_anchor, zones
