import unittest

from tests._fixtures import build_two_zone_chain
from dnssecval import builder, nsec
from dnssecval import constants as C
from dnssecval import name
from dnssecval.status import Reason, State
from dnssecval.validator import Validator

NOW = 2_000_000_000


def sign_and_add(zone_obj, zones, apex, rrset):
    sig = builder.sign_rrset(
        rrset, apex, zone_obj.algorithm, zone_obj.private, zone_obj.key_tag,
        inception=NOW - 3600, expiration=NOW + 3600,
    )
    zones[name.from_text(apex)].records.extend(rrset + [sig])
    return sig


class NsecDenialTests(unittest.TestCase):
    def setUp(self):
        self.root, self.child, self.anchor, self.zones = build_two_zone_chain(NOW)

    def test_proven_nxdomain_nsec(self):
        # NSEC interval: example. -> zzz.example. covers the missing name
        # missing.example.
        nsec_rr = builder.make_rr(
            "example.", C.NSEC,
            builder.nsec_rdata("zzz.example.", [C.SOA, C.NS, C.DNSKEY, C.NSEC]),
        )
        sign_and_add(self.child, self.zones, "example.", [nsec_rr])
        result = Validator([self.anchor], now=NOW).validate(
            "missing.example.", C.A, self.zones
        )
        self.assertEqual(result.state, State.SECURE)
        self.assertEqual(result.reason, Reason.PROVEN_NXDOMAIN)

    def test_proven_nodata_nsec(self):
        host = "host.example."
        a_rr = builder.make_rr(host, C.A, builder.a_rdata("192.0.2.10"))
        sign_and_add(self.child, self.zones, "example.", [a_rr])
        # NSEC owned by the existing host lists A but not AAAA.
        nsec_rr = builder.make_rr(
            host, C.NSEC, builder.nsec_rdata("next.example.", [C.A, C.RRSIG]),
        )
        sign_and_add(self.child, self.zones, "example.", [nsec_rr])
        result = Validator([self.anchor], now=NOW).validate(
            host, 28, self.zones  # AAAA = 28
        )
        self.assertEqual(result.state, State.SECURE)
        self.assertEqual(result.reason, Reason.PROVEN_NODATA)

    def test_forged_denial_when_type_bitmap_lists_type(self):
        host = "host.example."
        nsec_rr = builder.make_rr(
            host, C.NSEC, builder.nsec_rdata("next.example.", [C.A, C.RRSIG]),
        )
        sign_and_add(self.child, self.zones, "example.", [nsec_rr])
        # Querying A while the owner NSEC claims A exists => forged NODATA.
        result = Validator([self.anchor], now=NOW).validate(
            host, C.A, self.zones
        )
        self.assertEqual(result.state, State.BOGUS)
        self.assertEqual(result.reason, Reason.FORGED_DENIAL)

    def test_forged_nxdomain_without_covering_record(self):
        # NSEC interval that does not cover the queried name.
        nsec_rr = builder.make_rr(
            "aaa.example.", C.NSEC,
            builder.nsec_rdata("bbb.example.", [C.NSEC]),
        )
        sign_and_add(self.child, self.zones, "example.", [nsec_rr])
        result = Validator([self.anchor], now=NOW).validate(
            "zzz.example.", C.A, self.zones
        )
        self.assertEqual(result.state, State.BOGUS)
        self.assertEqual(result.reason, Reason.FORGED_DENIAL)

    def test_unsigned_zone_cannot_prove_denial(self):
        root_zone = self.zones[name.ROOT]
        root_zone.records = [r for r in root_zone.records if r.rtype != C.DS]
        nsec_rr = builder.make_rr(
            "example.", C.NSEC,
            builder.nsec_rdata("zzz.example.", [C.NSEC]),
        )
        sign_and_add(self.child, self.zones, "example.", [nsec_rr])
        result = Validator([self.anchor], now=NOW).validate(
            "missing.example.", C.A, self.zones
        )
        self.assertEqual(result.state, State.INSECURE)
        self.assertEqual(result.reason, Reason.UNSIGNED_DELEGATION)


class Nsec3HashTests(unittest.TestCase):
    def test_hash_is_stable_and_owner_label_roundtrip(self):
        qname = name.from_text("host.example.")
        digest = nsec.nsec3_hash(qname, C.Digest.SHA1, 0, b"")
        label = nsec.hashed_owner_label(digest)
        self.assertEqual(len(label), 32)  # base32hex of 20-octet SHA-1
        rebuilt = nsec.nsec3_owner_name(name.from_text("example."), digest)
        self.assertEqual(rebuilt[0], label)

    def test_salt_and_iterations_change_hash(self):
        qname = name.from_text("host.example.")
        base = nsec.nsec3_hash(qname, C.Digest.SHA1, 0, b"")
        salted = nsec.nsec3_hash(qname, C.Digest.SHA1, 0, b"\xaa\xbb")
        iterated = nsec.nsec3_hash(qname, C.Digest.SHA1, 5, b"")
        self.assertNotEqual(base, salted)
        self.assertNotEqual(base, iterated)


class Nsec3DenialTests(unittest.TestCase):
    def setUp(self):
        self.root, self.child, self.anchor, self.zones = build_two_zone_chain(NOW)

    def _nsec3(self, owner_name, next_hash, types, salt=b"", iterations=0):
        rd = builder.nsec3_rdata(
            C.Digest.SHA1, 0, iterations, salt, next_hash, types
        )
        rr = builder.make_rr(owner_name, C.NSEC3, rd)
        sign_and_add(self.child, self.zones, "example.", [rr])
        return rr

    def test_proven_nodata_nsec3(self):
        host = name.from_text("host.example.")
        target = nsec.nsec3_hash(host, C.Digest.SHA1, 0, b"")
        owner = name.to_text(nsec.nsec3_owner_name(name.from_text("example."), target))
        # Next hash is a different value; bitmap omits AAAA.
        next_hash = nsec.nsec3_hash(name.from_text("next.example."), C.Digest.SHA1, 0, b"")
        self._nsec3(owner, next_hash, [C.A, C.RRSIG])
        result = Validator([self.anchor], now=NOW).validate(
            "host.example.", 28, self.zones
        )
        self.assertEqual(result.state, State.SECURE)
        self.assertEqual(result.reason, Reason.PROVEN_NODATA)

    def test_forged_nsec3_nodata_when_bitmap_includes_type(self):
        host = name.from_text("host.example.")
        target = nsec.nsec3_hash(host, C.Digest.SHA1, 0, b"")
        owner = name.to_text(nsec.nsec3_owner_name(name.from_text("example."), target))
        next_hash = nsec.nsec3_hash(name.from_text("next.example."), C.Digest.SHA1, 0, b"")
        self._nsec3(owner, next_hash, [C.A])
        result = Validator([self.anchor], now=NOW).validate(
            "host.example.", C.A, self.zones
        )
        self.assertEqual(result.state, State.BOGUS)
        self.assertEqual(result.reason, Reason.FORGED_DENIAL)

    def test_proven_nxdomain_nsec3_closest_encloser(self):
        zone = name.from_text("example.")
        qname = name.from_text("a.missing.example.")
        # Closest encloser = example. (its hash must be an NSEC3 owner).
        encloser_hash = nsec.nsec3_hash(zone, C.Digest.SHA1, 0, b"")
        # Next-closer = missing.example. must fall inside an interval.
        next_closer = name.from_text("missing.example.")
        nc_hash = nsec.nsec3_hash(next_closer, C.Digest.SHA1, 0, b"")
        encloser_owner = name.to_text(
            nsec.nsec3_owner_name(zone, encloser_hash))
        self._nsec3(encloser_owner, nc_hash, [C.SOA, C.NS, C.DNSKEY])
        # Interval record whose range contains the next-closer hash.
        start = nsec.nsec3_hash(name.from_text("m.example."), C.Digest.SHA1, 0, b"")
        start_owner = name.to_text(nsec.nsec3_owner_name(zone, start))
        self._nsec3(start_owner, nc_hash, [])
        result = Validator([self.anchor], now=NOW).validate(
            "a.missing.example.", C.A, self.zones
        )
        self.assertEqual(result.state, State.SECURE)
        self.assertEqual(result.reason, Reason.PROVEN_NXDOMAIN)

    def test_forged_nsec3_nxdomain_without_covering_interval(self):
        zone = name.from_text("example.")
        # Only prove the encloser (example.) exists, with an interval that
        # does NOT cover the next-closer name; NXDOMAIN must not be granted.
        encloser_hash = nsec.nsec3_hash(zone, C.Digest.SHA1, 0, b"")
        encloser_owner = name.to_text(nsec.nsec3_owner_name(zone, encloser_hash))
        far_hash = nsec.nsec3_hash(
            name.from_text("zzzzz.example."), C.Digest.SHA1, 0, b""
        )
        self._nsec3(encloser_owner, far_hash, [C.SOA, C.NS])
        result = Validator([self.anchor], now=NOW).validate(
            "a.missing.example.", C.A, self.zones
        )
        self.assertEqual(result.state, State.BOGUS)
        self.assertEqual(result.reason, Reason.FORGED_DENIAL)


if __name__ == "__main__":
    unittest.main()
