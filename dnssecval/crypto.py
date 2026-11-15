"""Cryptographic primitives: key parsing, DS digests and RRSIG verification."""

from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa

from . import constants as C
from . import name as name_mod


class CryptoError(Exception):
    """A key or signature could not be parsed or verified."""


class UnsupportedAlgorithm(CryptoError):
    """The algorithm number is recognised but not implemented."""


def _hashlib_name(algorithm: int) -> str:
    meta = C.ALGORITHMS.get(algorithm)
    if not meta or not meta["supported"]:
        raise UnsupportedAlgorithm(f"algorithm {algorithm} is not supported")
    return meta["hash"]  # type: ignore[return-value]


def _rsa_der(modulus: int, exponent: int) -> bytes:
    key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
    return key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def parse_rsa_key(blob: bytes) -> rsa.RSAPublicKey:
    if len(blob) < 2:
        raise CryptoError("RSA public key too short")
    # RFC 3110: if the first octet is a sub-prefix length the exponent is
    # longer than 255 octets.
    exp_len = blob[0]
    offset = 1
    if exp_len == 0:
        if len(blob) < 3:
            raise CryptoError("truncated extended RSA exponent length")
        exp_len = int.from_bytes(blob[1:3], "big")
        offset = 3
    if exp_len == 0 or offset + exp_len >= len(blob):
        raise CryptoError("invalid RSA exponent length")
    exponent = int.from_bytes(blob[offset:offset + exp_len], "big")
    modulus_start = offset + exp_len
    modulus_bytes = blob[modulus_start:]
    if not modulus_bytes:
        raise CryptoError("RSA key missing modulus")
    modulus = int.from_bytes(modulus_bytes, "big")
    if modulus == 0 or exponent == 0:
        raise CryptoError("RSA key with zero modulus or exponent")
    try:
        return rsa.RSAPublicNumbers(exponent, modulus).public_key()
    except ValueError as exc:
        raise CryptoError(f"invalid RSA public key: {exc}") from exc


def parse_ecdsa_key(blob: bytes, curve_name: str) -> ec.EllipticCurvePublicKey:
    if curve_name == "P256":
        coord_len, curve = 32, ec.SECP256R1()
    else:
        coord_len, curve = 48, ec.SECP384R1()
    if len(blob) != coord_len * 2:
        raise CryptoError(
            f"ECDSA {curve_name} key must be {coord_len * 2} octets, got {len(blob)}"
        )
    x = int.from_bytes(blob[:coord_len], "big")
    y = int.from_bytes(blob[coord_len:], "big")
    try:
        return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
    except ValueError as exc:
        raise CryptoError(f"invalid ECDSA public key: {exc}") from exc


def parse_public_key(algorithm: int, blob: bytes):
    meta = C.ALGORITHMS.get(algorithm)
    if not meta:
        raise UnsupportedAlgorithm(f"unknown algorithm number {algorithm}")
    if not meta["supported"]:
        raise UnsupportedAlgorithm(f"algorithm {algorithm} ({meta['family']}) unsupported")
    family = meta["family"]
    if family == "RSA":
        return parse_rsa_key(blob)
    if family == "ECDSA":
        return parse_ecdsa_key(blob, meta["curve"])  # type: ignore[arg-type]
    if family == "EdDSA":
        if meta["curve"] == "Ed25519":
            if len(blob) != 32:
                raise CryptoError("Ed25519 key must be 32 octets")
            return ed25519.Ed25519PublicKey.from_public_bytes(blob)
        if len(blob) != 57:
            raise CryptoError("Ed448 key must be 57 octets")
        return ed448.Ed448PublicKey.from_public_bytes(blob)
    raise UnsupportedAlgorithm(f"unsupported key family {family}")


def _new_hash(name: str) -> hashes.HashAlgorithm:
    mapping = {
        "sha1": hashes.SHA1(),
        "sha256": hashes.SHA256(),
        "sha384": hashes.SHA384(),
        "sha512": hashes.SHA512(),
    }
    if name not in mapping:
        raise UnsupportedAlgorithm(f"hash {name} not available")
    return mapping[name]


def verify_signature(algorithm: int, public_key_blob: bytes,
                     signed_data: bytes, signature: bytes) -> bool:
    """Return True when ``signature`` validates over ``signed_data``."""
    key = parse_public_key(algorithm, public_key_blob)
    meta = C.ALGORITHMS[algorithm]
    family = meta["family"]
    try:
        if family == "RSA":
            key.verify(  # type: ignore[union-attr]
                signature, signed_data, padding.PKCS1v15(),
                _new_hash(meta["hash"]),  # type: ignore[arg-type]
            )
            return True
        if family == "ECDSA":
            der_sig = _ecdsa_to_der(signature, meta["curve"])  # type: ignore[arg-type]
            key.verify(  # type: ignore[union-attr]
                der_sig, signed_data, ec.ECDSA(_new_hash(meta["hash"])),  # type: ignore[arg-type]
            )
            return True
        if family == "EdDSA":
            key.verify(signature, signed_data)  # type: ignore[union-attr]
            return True
    except (InvalidSignature, ValueError):
        return False
    raise UnsupportedAlgorithm(f"cannot verify with family {family}")


def _ecdsa_to_der(raw: bytes, curve_name: str) -> bytes:
    """Convert the raw R||S ECDSA signature (RFC 6605) to DER."""
    coord_len = 32 if curve_name == "P256" else 48
    if len(raw) != coord_len * 2:
        raise CryptoError("ECDSA signature has wrong length for curve")
    r = int.from_bytes(raw[:coord_len], "big")
    s = int.from_bytes(raw[coord_len:], "big")
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    return encode_dss_signature(r, s)


def ds_digest(digest_type: int, owner_name: tuple[bytes, ...],
              dnskey_rdata: bytes) -> bytes:
    """Compute the DS digest (RFC 4034 5.1.4)."""
    hash_name = C.DS_DIGESTS.get(digest_type)
    if hash_name is None:
        raise UnsupportedAlgorithm(f"DS digest type {digest_type} unsupported")
    hasher = hashlib.new(hash_name)
    hasher.update(name_mod.canonical_wire(owner_name))
    hasher.update(dnskey_rdata)
    return hasher.digest()


def ds_matches(ds, owner_name: tuple[bytes, ...], dnskey_rdata: bytes) -> bool:
    try:
        expected = ds_digest(ds.digest_type, owner_name, dnskey_rdata)
    except UnsupportedAlgorithm:
        return False
    return expected == ds.digest
