"""Helpers to build wire records and real signatures for tests / fixtures.

This is the inverse of the offline parser: it generates keypairs, encodes
DNSKEY RDATA, builds RRSIG records over canonical RRsets, and emits plain
records (A/SOA/DS/NSEC/NSEC3).  Everything uses the same canonical rules as
the validator so a chain built here validates cryptographically.
"""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa

from . import canonical
from . import constants as C
from . import name as name_mod
from . import rdata as rdata_mod
from .wire import RR


def generate_key(algorithm: int):
    if algorithm in (C.Algo.RSASHA1, C.Algo.RSASHA1_NSEC3_SHA1,
                     C.Algo.RSASHA256, C.Algo.RSASHA512):
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if algorithm == C.Algo.ECDSA_P256_SHA256:
        return ec.generate_private_key(ec.SECP256R1())
    if algorithm == C.Algo.ECDSA_P384_SHA384:
        return ec.generate_private_key(ec.SECP384R1())
    if algorithm == C.Algo.ED25519:
        return ed25519.Ed25519PrivateKey.generate()
    if algorithm == C.Algo.ED448:
        return ed448.Ed448PrivateKey.generate()
    raise ValueError(f"cannot generate key for algorithm {algorithm}")


def _rsa_public_blob(public_key) -> bytes:
    nums = public_key.public_numbers()
    exp = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
    modulus = nums.n.to_bytes(public_key.key_size // 8, "big")
    if len(exp) > 255:
        prefix = b"\x00" + len(exp).to_bytes(2, "big")
    else:
        prefix = bytes([len(exp)])
    return prefix + exp + modulus


def _ec_public_blob(public_key, coord_len: int) -> bytes:
    nums = public_key.public_numbers()
    return nums.x.to_bytes(coord_len, "big") + nums.y.to_bytes(coord_len, "big")


def public_key_blob(algorithm: int, public_key) -> bytes:
    meta = C.ALGORITHMS[algorithm]
    family = meta["family"]
    if family == "RSA":
        return _rsa_public_blob(public_key)
    if family == "ECDSA":
        coord_len = 32 if meta["curve"] == "P256" else 48
        return _ec_public_blob(public_key, coord_len)
    if family == "EdDSA":
        return public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
    raise ValueError(f"unsupported family {family}")


def dnskey_rdata(algorithm: int, public_key, flags: int = 257) -> bytes:
    blob = public_key_blob(algorithm, public_key)
    return flags.to_bytes(2, "big") + bytes([3, algorithm]) + blob


def make_rr(owner_text: str, rtype: int, rdata: bytes,
            ttl: int = 3600, rclass: int = 1) -> RR:
    return RR(name_mod.from_text(owner_text), rtype, rclass, ttl, rdata)


def a_rdata(address: str) -> bytes:
    return bytes(int(part) for part in address.split("."))


def soa_rdata(mname: str, rname: str, serial: int = 1,
              ttl: int = 3600) -> bytes:
    out = bytearray()
    out += name_mod.to_wire(name_mod.from_text(mname))
    out += name_mod.to_wire(name_mod.from_text(rname))
    out += serial.to_bytes(4, "big")
    out += ttl.to_bytes(4, "big")
    out += (ttl // 2).to_bytes(4, "big")
    out += (ttl * 2).to_bytes(4, "big")
    out += ttl.to_bytes(4, "big")
    return bytes(out)


def ds_rdata(dnskey_rr: RR, owner_text: str, digest_type: int = C.Digest.SHA256,
             algorithm: int | None = None) -> bytes:
    key = rdata_mod.parse_dnskey(dnskey_rr.rdata)
    algo = algorithm if algorithm is not None else key.algorithm
    tag = rdata_mod.key_tag(dnskey_rr.rdata)
    digest = hashlib.new(C.DS_DIGESTS[digest_type])
    digest.update(name_mod.canonical_wire(name_mod.from_text(owner_text)))
    digest.update(dnskey_rr.rdata)
    head = tag.to_bytes(2, "big") + bytes([algo, digest_type])
    return head + digest.digest()


def type_bitmap(types: list[int]) -> bytes:
    windows: dict[int, bytearray] = {}
    for t in sorted(types):
        window, offset = divmod(t, 256)
        byte_index, bit = divmod(offset, 8)
        bitmap = windows.setdefault(window, bytearray(32))
        bitmap[byte_index] |= 0x80 >> bit
    out = bytearray()
    for window in sorted(windows):
        bitmap = windows[window].rstrip(b"\x00")
        out.append(window)
        out.append(len(bitmap))
        out += bitmap
    return bytes(out)


def nsec_rdata(next_name_text: str, types: list[int]) -> bytes:
    out = bytearray(name_mod.to_wire(name_mod.from_text(next_name_text)))
    out += type_bitmap(types)
    return bytes(out)


def nsec3_rdata(hash_algorithm: int, flags: int, iterations: int,
                salt: bytes, next_hash: bytes, types: list[int]) -> bytes:
    out = bytearray()
    out += bytes([hash_algorithm, flags])
    out += iterations.to_bytes(2, "big")
    out.append(len(salt))
    out += salt
    out.append(len(next_hash))
    out += next_hash
    out += type_bitmap(types)
    return bytes(out)


def _sign(algorithm: int, private_key, data: bytes) -> bytes:
    meta = C.ALGORITHMS[algorithm]
    family = meta["family"]
    if family == "RSA":
        hash_obj = {"sha1": hashes.SHA1, "sha256": hashes.SHA256,
                    "sha512": hashes.SHA512}[meta["hash"]]()
        return private_key.sign(data, __import__(
            "cryptography.hazmat.primitives.asymmetric.padding",
            fromlist=["PKCS1v15"]).PKCS1v15(), hash_obj)
    if family == "ECDSA":
        hash_obj = {"sha256": hashes.SHA256, "sha384": hashes.SHA384}[
            meta["hash"]]()
        der = private_key.sign(data, ec.ECDSA(hash_obj))
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        r, s = decode_dss_signature(der)
        coord_len = 32 if meta["curve"] == "P256" else 48
        return r.to_bytes(coord_len, "big") + s.to_bytes(coord_len, "big")
    if family == "EdDSA":
        return private_key.sign(data)
    raise ValueError(f"cannot sign with family {family}")


def sign_rrset(rrset: list[RR], signer_text: str, algorithm: int,
               private_key, key_tag: int, *,
               inception: int, expiration: int,
               original_ttl: int | None = None) -> RR:
    """Produce an RRSIG RR covering ``rrset``."""
    covered = rrset[0].rtype
    labels = len(rrset[0].name)
    ttl = original_ttl if original_ttl is not None else rrset[0].ttl
    rrsig_head = (
        covered.to_bytes(2, "big")
        + bytes([algorithm, labels])
        + ttl.to_bytes(4, "big")
        + expiration.to_bytes(4, "big")
        + inception.to_bytes(4, "big")
        + key_tag.to_bytes(2, "big")
        + name_mod.canonical_wire(name_mod.from_text(signer_text))
    )
    # Reconstruct a minimal RRSIG object for canonical assembly.
    sig_placeholder = rdata_mod.RRSIG(
        covered, algorithm, labels, ttl, expiration, inception, key_tag,
        name_mod.from_text(signer_text), b"", rrsig_head, len(rrsig_head),
    )
    signed_data = canonical.build_signed_data(rrset, sig_placeholder)
    signature = _sign(algorithm, private_key, signed_data)
    return RR(rrset[0].name, C.RRSIG, rrset[0].rclass, rrset[0].ttl,
              rrsig_head + signature)
