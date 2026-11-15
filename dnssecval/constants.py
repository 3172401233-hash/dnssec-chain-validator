"""DNS record types, DNSSEC algorithms and digest identifiers."""

from __future__ import annotations

# Resource record types
A = 1
NS = 2
SOA = 6
CNAME = 5
DNAME = 39
DNSKEY = 48
DS = 43
RRSIG = 46
NSEC = 47
NSEC3 = 50
NSEC3PARAM = 51

TYPE_NAMES = {
    A: "A",
    NS: "NS",
    SOA: "SOA",
    CNAME: "CNAME",
    DNAME: "DNAME",
    DNSKEY: "DNSKEY",
    DS: "DS",
    RRSIG: "RRSIG",
    NSEC: "NSEC",
    NSEC3: "NSEC3",
    NSEC3PARAM: "NSEC3PARAM",
}


class Algo:
    """DNS security algorithm numbers (RFC 4034, RFC 5702, RFC 6605, RFC 8080)."""

    RSAMD5 = 1
    DH = 2
    DSA = 3
    RSASHA1 = 5
    DSA_NSEC3_SHA1 = 6
    RSASHA1_NSEC3_SHA1 = 7
    RSASHA256 = 8
    RSASHA512 = 10
    ECC_GOST = 12
    ECDSA_P256_SHA256 = 13
    ECDSA_P384_SHA384 = 14
    ED25519 = 15
    ED448 = 16
    INDIRECT = 252
    PRIVATEDNS = 253
    PRIVATEOID = 254


# Algorithm metadata: family and the digest used for signing.
# Only the families this library can actually verify are marked supported.
ALGORITHMS: dict[int, dict[str, object]] = {
    Algo.RSASHA1: {"family": "RSA", "hash": "sha1", "supported": True},
    Algo.RSASHA1_NSEC3_SHA1: {"family": "RSA", "hash": "sha1", "supported": True},
    Algo.RSASHA256: {"family": "RSA", "hash": "sha256", "supported": True},
    Algo.RSASHA512: {"family": "RSA", "hash": "sha512", "supported": True},
    Algo.ECDSA_P256_SHA256: {"family": "ECDSA", "hash": "sha256", "supported": True, "curve": "P256"},
    Algo.ECDSA_P384_SHA384: {"family": "ECDSA", "hash": "sha384", "supported": True, "curve": "P384"},
    Algo.ED25519: {"family": "EdDSA", "hash": None, "supported": True, "curve": "Ed25519"},
    Algo.ED448: {"family": "EdDSA", "hash": None, "supported": True, "curve": "Ed448"},
    # Deliberately unsupported legacy / private families.
    Algo.RSAMD5: {"family": "RSA", "hash": "md5", "supported": False},
    Algo.DSA: {"family": "DSA", "hash": "sha1", "supported": False},
    Algo.DSA_NSEC3_SHA1: {"family": "DSA", "hash": "sha1", "supported": False},
    Algo.ECC_GOST: {"family": "GOST", "hash": "gost", "supported": False},
    Algo.INDIRECT: {"family": "INDIRECT", "hash": None, "supported": False},
    Algo.PRIVATEDNS: {"family": "PRIVATE", "hash": None, "supported": False},
    Algo.PRIVATEOID: {"family": "PRIVATE", "hash": None, "supported": False},
}


class Digest:
    """DS / NSEC3 digest algorithm numbers."""

    SHA1 = 1
    SHA256 = 2
    GOST = 3
    SHA384 = 4


DS_DIGESTS = {
    Digest.SHA1: "sha1",
    Digest.SHA256: "sha256",
    Digest.SHA384: "sha384",
}

# NSEC3 currently only defines SHA-1.
NSEC3_DIGESTS = {
    Digest.SHA1: "sha1",
}


def is_supported(algorithm: int) -> bool:
    meta = ALGORITHMS.get(algorithm)
    return bool(meta and meta["supported"])
