import unittest

from tests._fixtures import SignedZone
from dnssecval import builder, name, rdata
from dnssecval import constants as C
from dnssecval.status import Reason, State
from dnssecval.validator import TrustAnchor, Validator, ZoneData

NOW = 2_000_000_000


def _ds_for(parent: SignedZone, child_apex: str, child: SignedZone) -> tuple:
    ds_rd = builder.ds_rdata(child.dnskey, child_apex)
    ds = builder.make_rr(child_apex, C.DS, ds_rd)
    sig = builder.sign_rrset(
        [ds], parent.apex, parent.algorithm, parent.private, parent.key_tag,
        inception=NOW - 3600, expiration=NOW + 3600,
    )
    return ds, sig


class ThreeLevelChainTests(unittest.TestCase):
    def test_root_to_grandchild_secure(self):
        root = SignedZone(".", C.Algo.RSASHA256)
        mid = SignedZone("example.", C.Algo.ECDSA_P256_SHA256)
        leaf = SignedZone("sub.example.", C.Algo.ED25519)

        for zone in (root, mid, leaf):
            zone.sign_dnskey(NOW - 3600, NOW + 3600)

        ds1, sig1 = _ds_for(root, "example.", mid)
        root.add(ds1)
        root.add(sig1)
        ds2, sig2 = _ds_for(mid, "sub.example.", leaf)
        mid.add(ds2)
        mid.add(sig2)

        # Signed A record in the leaf zone.
        a_rr = builder.make_rr(
            "host.sub.example.", C.A, builder.a_rdata("198.51.100.23")
        )
        a_sig = builder.sign_rrset(
            [a_rr], "sub.example.", leaf.algorithm, leaf.private,
            leaf.key_tag, inception=NOW - 3600, expiration=NOW + 3600,
        )
        leaf.add(a_rr)
        leaf.add(a_sig)

        zones = {
            name.ROOT: ZoneData(root.records),
            name.from_text("example."): ZoneData(mid.records),
            name.from_text("sub.example."): ZoneData(leaf.records),
        }
        anchor = TrustAnchor(name.ROOT, root.dnskey)
        result = Validator([anchor], now=NOW).validate(
            "host.sub.example.", C.A, zones
        )
        self.assertEqual(result.state, State.SECURE)
        self.assertEqual(
            result.proven_chain, [".", "example.", "sub.example."]
        )

    def test_broken_middle_link_makes_leaf_bogus(self):
        root = SignedZone(".", C.Algo.RSASHA256)
        mid = SignedZone("example.", C.Algo.ECDSA_P256_SHA256)
        leaf = SignedZone("sub.example.", C.Algo.ED25519)
        for zone in (root, mid, leaf):
            zone.sign_dnskey(NOW - 3600, NOW + 3600)
        ds1, sig1 = _ds_for(root, "example.", mid)
        root.add(ds1)
        root.add(sig1)
        # Leaf DS present but its digest corrupted, then re-signed by mid so
        # the DS RRset signature stays valid while digest linkage fails.
        ds2, _ = _ds_for(mid, "sub.example.", leaf)
        corrupted = bytearray(ds2.rdata)
        corrupted[-1] ^= 0x01
        bad_ds = builder.make_rr("sub.example.", C.DS, bytes(corrupted))
        bad_sig = builder.sign_rrset(
            [bad_ds], "example.", mid.algorithm, mid.private, mid.key_tag,
            inception=NOW - 3600, expiration=NOW + 3600,
        )
        mid.add(bad_ds)
        mid.add(bad_sig)

        zones = {
            name.ROOT: ZoneData(root.records),
            name.from_text("example."): ZoneData(mid.records),
            name.from_text("sub.example."): ZoneData(leaf.records),
        }
        anchor = TrustAnchor(name.ROOT, root.dnskey)
        result = Validator([anchor], now=NOW).validate(
            "host.sub.example.", C.A, zones
        )
        self.assertEqual(result.state, State.BOGUS)
        self.assertEqual(result.reason, Reason.DS_DIGEST_MISMATCH)


if __name__ == "__main__":
    unittest.main()
