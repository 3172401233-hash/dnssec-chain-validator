import unittest

from dnssecval import builder, canonical
from dnssecval import constants as C
from dnssecval import name


class CanonicalFormTests(unittest.TestCase):
    def test_name_case_folding(self):
        upper = name.from_text("WWW.Example.")
        wire = name.canonical_wire(upper)
        self.assertEqual(wire, name.canonical_wire(name.from_text("www.example.")))
        self.assertNotEqual(name.to_wire(upper), name.to_wire(
            name.from_text("www.example.")))

    def test_rrset_ordering_is_canonical_rdata(self):
        rr1 = builder.make_rr("a.example.", C.A, builder.a_rdata("192.0.2.9"))
        rr2 = builder.make_rr("a.example.", C.A, builder.a_rdata("192.0.2.1"))
        rr3 = builder.make_rr("a.example.", C.A, builder.a_rdata("192.0.2.20"))
        ordered = canonical.sorted_rrset([rr1, rr2, rr3])
        self.assertEqual(
            [r.rdata for r in ordered],
            [builder.a_rdata("192.0.2.1"),
             builder.a_rdata("192.0.2.9"),
             builder.a_rdata("192.0.2.20")],
        )

    def test_soa_rdata_names_are_folded(self):
        rr = builder.make_rr(
            "Example.", C.SOA,
            builder.soa_rdata("NS1.Example.", "Hostmaster.Example."),
        )
        crdata = canonical.canonical_rdata(rr)
        self.assertNotIn(b"NS1", crdata)
        self.assertIn(b"ns1", crdata)

    def test_owner_name_case_folded_in_canonical_wire(self):
        rr = builder.make_rr("Mix.Example.", C.A, builder.a_rdata("192.0.2.5"))
        wire = canonical.canonical_rr_wire(rr)
        self.assertIn(b"mix", wire)
        self.assertIn(b"example", wire)

    def test_canonical_name_ordering_rfc4034(self):
        root = name.ROOT
        apex = name.from_text("example.")
        host = name.from_text("host.example.")
        zzz = name.from_text("zzz.example.")
        # Root sorts first, then the apex, then labels compared right-to-left.
        self.assertEqual(name.canonical_compare(root, apex), -1)
        self.assertEqual(name.canonical_compare(apex, host), -1)
        self.assertEqual(name.canonical_compare(host, zzz), -1)
        # Case-insensitive and reflexive.
        self.assertEqual(
            name.canonical_compare(
                name.from_text("HOST.example."),
                name.from_text("host.Example."),
            ),
            0,
        )

    def test_nsec_interval_uses_canonical_order(self):
        from dnssecval import nsec
        nsec_rr = builder.make_rr(
            "example.", C.NSEC,
            builder.nsec_rdata("zzz.example.", [C.NSEC]),
        )
        inside = name.from_text("gone.example.")
        outside = name.from_text("zzzzzz.example.")
        self.assertTrue(nsec.nsec_covers_name(nsec_rr, inside))
        self.assertFalse(nsec.nsec_covers_name(nsec_rr, outside))


if __name__ == "__main__":
    unittest.main()
