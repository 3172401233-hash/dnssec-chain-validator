import unittest

from tests._fixtures import build_two_zone_chain
from dnssecval import builder, rdata
from dnssecval import constants as C
from dnssecval import name
from dnssecval.status import Reason, State
from dnssecval.validator import Validator

NOW = 2_000_000_000


class AlgorithmPolicyTests(unittest.TestCase):
    def test_unsupported_signature_algorithm_is_bogus(self):
        root, child, anchor, zones = build_two_zone_chain(
            NOW, child_alg=C.Algo.ECDSA_P256_SHA256
        )
        apex = name.from_text("example.")
        # Craft an RRSIG advertising DSA (algorithm 3) over a real A RRset.
        a_rr = builder.make_rr("host.example.", C.A, builder.a_rdata("192.0.2.1"))
        fake_sig = builder.sign_rrset(
            [a_rr], "example.", C.Algo.ECDSA_P256_SHA256, child.private,
            child.key_tag, inception=NOW - 3600, expiration=NOW + 3600,
        )
        parsed = rdata.parse_rrsig(fake_sig.rdata)
        # Rewrite the algorithm byte (offset 2) to DSA.
        rewritten = bytearray(fake_sig.rdata)
        rewritten[2] = C.Algo.DSA
        dsa_sig = builder.make_rr("host.example.", C.RRSIG, bytes(rewritten))
        zones[apex].records.extend([a_rr, dsa_sig])
        result = Validator([anchor], now=NOW).validate(
            "host.example.", C.A, zones
        )
        self.assertEqual(result.state, State.BOGUS)
        self.assertEqual(result.reason, Reason.UNSUPPORTED_ALGORITHM)

    def test_unknown_algorithm_number_is_bogus(self):
        root, child, anchor, zones = build_two_zone_chain(NOW)
        apex = name.from_text("example.")
        a_rr = builder.make_rr("host.example.", C.A, builder.a_rdata("192.0.2.1"))
        sig = builder.sign_rrset(
            [a_rr], "example.", child.algorithm, child.private,
            child.key_tag, inception=NOW - 3600, expiration=NOW + 3600,
        )
        rewritten = bytearray(sig.rdata)
        rewritten[2] = 99  # unassigned algorithm number
        zones[apex].records.extend(
            [a_rr, builder.make_rr("host.example.", C.RRSIG, bytes(rewritten))]
        )
        result = Validator([anchor], now=NOW).validate(
            "host.example.", C.A, zones
        )
        self.assertEqual(result.state, State.BOGUS)
        self.assertEqual(result.reason, Reason.UNKNOWN_ALGORITHM)


class Nsec3ParsingTests(unittest.TestCase):
    def test_iterations_salt_and_opt_out_roundtrip(self):
        salt = b"\x01\x02\x03"
        next_hash = b"\xaa" * 20
        rd = builder.nsec3_rdata(
            C.Digest.SHA1, flags=0x01, iterations=12, salt=salt,
            next_hash=next_hash, types=[C.A, C.RRSIG],
        )
        parsed = rdata.parse_nsec3(rd)
        self.assertTrue(parsed.opt_out)
        self.assertEqual(parsed.iterations, 12)
        self.assertEqual(parsed.salt, salt)
        self.assertEqual(parsed.next_hashed_owner, next_hash)
        self.assertIn(C.A, parsed.types)
        self.assertIn(C.RRSIG, parsed.types)
        self.assertNotIn(28, parsed.types)  # AAAA absent


if __name__ == "__main__":
    unittest.main()
