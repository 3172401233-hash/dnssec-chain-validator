import unittest

from dnssecval import builder, crypto
from dnssecval import constants as C
from dnssecval import name, rdata


ALL_ALGOS = [
    C.Algo.RSASHA1,
    C.Algo.RSASHA1_NSEC3_SHA1,
    C.Algo.RSASHA256,
    C.Algo.RSASHA512,
    C.Algo.ECDSA_P256_SHA256,
    C.Algo.ECDSA_P384_SHA384,
    C.Algo.ED25519,
    C.Algo.ED448,
]


class CryptoTests(unittest.TestCase):
    def test_sign_verify_round_trip_every_algorithm(self):
        for alg in ALL_ALGOS:
            with self.subTest(alg=alg):
                priv = builder.generate_key(alg)
                pub = priv.public_key()
                blob = builder.public_key_blob(alg, pub)
                data = b"dnssec canonical test data " + bytes([alg])
                signature = builder._sign(alg, priv, data)
                self.assertTrue(
                    crypto.verify_signature(alg, blob, data, signature)
                )
                self.assertFalse(
                    crypto.verify_signature(alg, blob, data + b"x", signature)
                )

    def test_ds_digest_sha256_matches(self):
        priv = builder.generate_key(C.Algo.RSASHA256)
        dnskey = builder.make_rr(
            "example.", C.DNSKEY,
            builder.dnskey_rdata(C.Algo.RSASHA256, priv.public_key()),
        )
        ds_rd = builder.ds_rdata(dnskey, "example.", C.Digest.SHA256)
        ds = rdata.parse_ds(ds_rd)
        self.assertTrue(
            crypto.ds_matches(ds, name.from_text("example."), dnskey.rdata)
        )

    def test_ds_digest_owner_case_insensitive(self):
        priv = builder.generate_key(C.Algo.ECDSA_P256_SHA256)
        dnskey = builder.make_rr(
            "Example.", C.DNSKEY,
            builder.dnskey_rdata(C.Algo.ECDSA_P256_SHA256, priv.public_key()),
        )
        ds_rd = builder.ds_rdata(dnskey, "example.", C.Digest.SHA256)
        ds = rdata.parse_ds(ds_rd)
        self.assertTrue(
            crypto.ds_matches(ds, name.from_text("EXAMPLE."), dnskey.rdata)
        )

    def test_wrong_ds_digest_rejected(self):
        priv = builder.generate_key(C.Algo.RSASHA256)
        dnskey = builder.make_rr(
            "example.", C.DNSKEY,
            builder.dnskey_rdata(C.Algo.RSASHA256, priv.public_key()),
        )
        ds_rd = bytearray(builder.ds_rdata(dnskey, "example."))
        ds_rd[-1] ^= 0xFF  # corrupt the digest
        ds = rdata.parse_ds(bytes(ds_rd))
        self.assertFalse(
            crypto.ds_matches(ds, name.from_text("example."), dnskey.rdata)
        )

    def test_unknown_algorithm_number(self):
        self.assertNotIn(99, C.ALGORITHMS)
        self.assertFalse(C.is_supported(99))
        with self.assertRaises(crypto.UnsupportedAlgorithm):
            crypto.parse_public_key(99, b"\x03\x01\x00\x01")

    def test_known_but_unsupported_algorithm(self):
        self.assertIn(C.Algo.DSA, C.ALGORITHMS)
        self.assertFalse(C.is_supported(C.Algo.DSA))
        with self.assertRaises(crypto.UnsupportedAlgorithm):
            crypto.parse_public_key(C.Algo.DSA, b"\x02\x04\x00\x00\x00\x01")

    def test_malformed_rsa_key_rejected(self):
        with self.assertRaises(crypto.CryptoError):
            crypto.parse_rsa_key(b"\x03\x01\x00")


if __name__ == "__main__":
    unittest.main()
