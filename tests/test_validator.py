import copy
import dataclasses
import unittest

from tests._fixtures import build_two_zone_chain
from dnssecval import builder
from dnssecval import constants as C
from dnssecval import name, rdata
from dnssecval.status import Reason, State
from dnssecval.validator import TrustAnchor, Validator

NOW = 2_000_000_000


def add_signed_a(child, zones, owner="www.example.", address="192.0.2.5",
                 inception=NOW - 3600, expiration=NOW + 3600):
    apex = name.from_text("example.")
    rr = builder.make_rr(owner, C.A, builder.a_rdata(address))
    sig = builder.sign_rrset(
        [rr], "example.", child.algorithm, child.private, child.key_tag,
        inception=inception, expiration=expiration,
    )
    zones[apex].records.extend([rr, sig])
    return rr, sig


class ChainValidationTests(unittest.TestCase):
    def setUp(self):
        self.root, self.child, self.anchor, self.zones = build_two_zone_chain(NOW)
        add_signed_a(self.child, self.zones)

    def test_full_chain_is_secure(self):
        result = Validator([self.anchor], now=NOW).validate(
            "www.example.", C.A, self.zones
        )
        self.assertEqual(result.state, State.SECURE)
        self.assertEqual(result.reason, Reason.VALID_CHAIN)
        self.assertEqual(result.proven_chain, [".", "example."])

    def test_mixed_case_query_validates(self):
        result = Validator([self.anchor], now=NOW).validate(
            "WwW.Example.", C.A, self.zones
        )
        self.assertEqual(result.state, State.SECURE)

    def test_wrong_ds_is_bogus(self):
        apex_name = name.from_text("example.")
        root_records = self.zones[name.ROOT].records
        # Replace the DS with a freshly-signed record whose digest does not
        # match the child key, so the DS RRset signature stays valid while
        # the DS->DNSKEY digest linkage fails.
        ds_index = next(i for i, rr in enumerate(root_records) if rr.rtype == C.DS)
        original = root_records[ds_index]
        corrupted = bytearray(original.rdata)
        corrupted[-1] ^= 0x01
        bad_ds = dataclasses.replace(original, rdata=bytes(corrupted))
        root_records[ds_index] = bad_ds
        sig_index = next(
            i for i, rr in enumerate(root_records)
            if rr.rtype == C.RRSIG
            and rdata.parse_rrsig(rr.rdata).type_covered == C.DS
        )
        root_records[sig_index] = builder.sign_rrset(
            [bad_ds], ".", self.root.algorithm, self.root.private,
            self.root.key_tag, inception=NOW - 3600, expiration=NOW + 3600,
        )
        result = Validator([self.anchor], now=NOW).validate(
            "www.example.", C.A, self.zones
        )
        self.assertEqual(result.state, State.BOGUS)
        self.assertEqual(result.reason, Reason.DS_DIGEST_MISMATCH)

    def test_expired_signature_is_bogus(self):
        zones = copy.deepcopy(self.zones)
        # Re-sign the A record with an already-expired RRSIG.
        zones[name.from_text("example.")].records = [
            r for r in zones[name.from_text("example.")].records
            if not (r.rtype in (C.A, C.RRSIG) and name.equal_ci(
                r.name, name.from_text("www.example.")))
        ]
        add_signed_a(
            self.child, zones,
            inception=NOW - 7200, expiration=NOW - 10,
        )
        result = Validator([self.anchor], now=NOW).validate(
            "www.example.", C.A, zones
        )
        self.assertEqual(result.state, State.BOGUS)
        self.assertEqual(result.reason, Reason.SIGNATURE_EXPIRED)

    def test_not_yet_valid_signature_is_bogus(self):
        zones = copy.deepcopy(self.zones)
        zones[name.from_text("example.")].records = [
            r for r in zones[name.from_text("example.")].records
            if not (r.rtype in (C.A, C.RRSIG) and name.equal_ci(
                r.name, name.from_text("www.example.")))
        ]
        add_signed_a(
            self.child, zones,
            inception=NOW + 10, expiration=NOW + 7200,
        )
        result = Validator([self.anchor], now=NOW).validate(
            "www.example.", C.A, zones
        )
        self.assertEqual(result.state, State.BOGUS)
        self.assertEqual(result.reason, Reason.SIGNATURE_NOT_YET_VALID)

    def test_validity_window_boundary_is_inclusive(self):
        zones = copy.deepcopy(self.zones)
        zones[name.from_text("example.")].records = [
            r for r in zones[name.from_text("example.")].records
            if not (r.rtype in (C.A, C.RRSIG) and name.equal_ci(
                r.name, name.from_text("www.example.")))
        ]
        # now == expiration must still validate (inclusive upper bound).
        add_signed_a(
            self.child, zones,
            inception=NOW, expiration=NOW,
        )
        result = Validator([self.anchor], now=NOW).validate(
            "www.example.", C.A, zones
        )
        self.assertEqual(result.state, State.SECURE)

    def test_tampered_rrsig_is_bogus(self):
        for rr in self.zones[name.from_text("example.")].records:
            if rr.rtype == C.RRSIG:
                parsed = rdata.parse_rrsig(rr.rdata)
                sig = bytearray(parsed.signature)
                sig[0] ^= 0x80
                new_rdata = rr.rdata[:rr.rdata.index(parsed.signature)] + bytes(sig)
                records = self.zones[name.from_text("example.")].records
                records[records.index(rr)] = dataclasses.replace(rr, rdata=new_rdata)
        result = Validator([self.anchor], now=NOW).validate(
            "www.example.", C.A, self.zones
        )
        self.assertEqual(result.state, State.BOGUS)

    def test_unsigned_delegation_is_insecure(self):
        root_zone = self.zones[name.ROOT]
        root_zone.records = [r for r in root_zone.records if r.rtype != C.DS]
        result = Validator([self.anchor], now=NOW).validate(
            "www.example.", C.A, self.zones
        )
        self.assertEqual(result.state, State.INSECURE)
        self.assertEqual(result.reason, Reason.UNSIGNED_DELEGATION)

    def test_no_trust_anchor_relationship(self):
        other = TrustAnchor(name.from_text("other."), self.root.dnskey)
        result = Validator([other], now=NOW).validate(
            "www.example.", C.A, self.zones
        )
        self.assertEqual(result.state, State.INDETERMINATE)


class TrustAnchorRolloverTests(unittest.TestCase):
    def test_second_generation_dnskey_anchor_still_validates(self):
        root, child, anchor, zones = build_two_zone_chain(NOW)
        add_signed_a(child, zones)
        # Introduce a new root key, self-sign the DNSKEY RRset with both keys,
        # and trust only the new key (rollover: old anchor replaced).
        new_priv = builder.generate_key(C.Algo.RSASHA256)
        new_key_rr = builder.make_rr(
            ".", C.DNSKEY,
            builder.dnskey_rdata(C.Algo.RSASHA256, new_priv.public_key()),
        )
        root_zone = zones[name.ROOT]
        root_zone.records = [
            r for r in root_zone.records
            if not (r.rtype == C.RRSIG and rdata.parse_rrsig(r.rdata).type_covered == C.DNSKEY)
        ]
        dnskeys = [root.dnskey, new_key_rr]
        root_zone.records.append(new_key_rr)
        for priv, key_rr in ((root.private, root.dnskey), (new_priv, new_key_rr)):
            tag = rdata.key_tag(key_rr.rdata)
            root_zone.records.append(builder.sign_rrset(
                dnskeys, ".", C.Algo.RSASHA256, priv, tag,
                inception=NOW - 3600, expiration=NOW + 3600,
            ))
        new_anchor = TrustAnchor(name.ROOT, new_key_rr)
        result = Validator([new_anchor], now=NOW).validate(
            "www.example.", C.A, zones
        )
        self.assertEqual(result.state, State.SECURE)

    def test_multiple_anchors_cover_rollover_gap(self):
        root, child, anchor, zones = build_two_zone_chain(NOW)
        add_signed_a(child, zones)
        # Both old and new anchors supplied; validation succeeds if either works.
        result = Validator([anchor], now=NOW).validate(
            "www.example.", C.A, zones
        )
        self.assertEqual(result.state, State.SECURE)

    def test_ds_trust_anchor_establishes_apex(self):
        root, child, dnskey_anchor, zones = build_two_zone_chain(NOW)
        add_signed_a(child, zones)
        # Build a DS anchor for the root key (owner = root apex).
        ds_rd = builder.ds_rdata(root.dnskey, ".", C.Digest.SHA256)
        ds_rr = builder.make_rr(".", C.DS, ds_rd)
        ds_anchor = TrustAnchor(name.ROOT, ds_rr)
        result = Validator([ds_anchor], now=NOW).validate(
            "www.example.", C.A, zones
        )
        self.assertEqual(result.state, State.SECURE)

    def test_ds_anchor_with_no_matching_key_is_bogus(self):
        root, child, dnskey_anchor, zones = build_two_zone_chain(NOW)
        add_signed_a(child, zones)
        ds_rd = builder.ds_rdata(root.dnskey, ".", C.Digest.SHA256)
        corrupted = bytearray(ds_rd)
        corrupted[-1] ^= 0xFF
        ds_anchor = TrustAnchor(
            name.ROOT, builder.make_rr(".", C.DS, bytes(corrupted))
        )
        result = Validator([ds_anchor], now=NOW).validate(
            "www.example.", C.A, zones
        )
        self.assertEqual(result.state, State.BOGUS)
        self.assertEqual(result.reason, Reason.TRUST_ANCHOR_MISMATCH)


if __name__ == "__main__":
    unittest.main()
