"""Offline DNSSEC chain validator and authenticated-denial classifier.

All inputs are pre-captured records; nothing here performs network I/O.
The validator walks the delegation chain from a configured trust anchor,
verifies DNSKEY/DS linkage and every RRSIG, then classifies a response as a
proven positive answer, proven NXDOMAIN, proven NODATA, an unsigned zone, or
a verification failure.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import canonical
from . import constants as C
from . import crypto
from . import name as name_mod
from . import nsec as nsec_mod
from . import rdata as rdata_mod
from .rdata import NSEC3 as NSEC3Parsed
from .status import Reason, State, ValidationResult
from .wire import RR, group_rrsets


class ValidatorError(Exception):
    pass


@dataclass
class TrustAnchor:
    """A trust anchor expressed as either a DS or a DNSKEY RR.

    A DS anchor must name the zone it is published for (its owner).  A
    DNSKEY anchor is a trusted zone key whose owner is the zone apex.
    Multiple anchors may be supplied to support rollover: every anchor is
    tried and a single valid match is sufficient.
    """

    zone: tuple[bytes, ...]
    rr: RR


@dataclass
class ZoneData:
    """All captured records belonging to one zone, keyed by owner/type."""

    records: list[RR] = field(default_factory=list)

    def rrsets(self) -> dict[tuple, list[RR]]:
        return group_rrsets(self.records)


class Validator:
    def __init__(self, anchors: list[TrustAnchor], *, now: int | None = None):
        if not anchors:
            raise ValidatorError("at least one trust anchor is required")
        self.anchors = anchors
        self._now = now

    @property
    def now(self) -> int:
        if self._now is not None:
            return self._now
        import time

        return int(time.time())

    # ------------------------------------------------------------------
    # RRset signature verification
    # ------------------------------------------------------------------
    def verify_rrset(self, rrset: list[RR], rrsig_rrs: list[RR],
                     dnskeys: list[RR]) -> tuple[State, Reason, str]:
        if not rrsig_rrs:
            return State.INSECURE, Reason.NO_SIGNATURE, "RRset has no RRSIG"
        parsed_keys = []
        for key_rr in dnskeys:
            try:
                parsed_keys.append((key_rr, rdata_mod.parse_dnskey(key_rr.rdata)))
            except rdata_mod.WireFormatError:
                continue

        applicable: list = []
        time_failures: list[Reason] = []
        unsupported: tuple[State, Reason, str] | None = None
        for sig_rr in rrsig_rrs:
            try:
                sig = rdata_mod.parse_rrsig(sig_rr.rdata)
            except rdata_mod.WireFormatError as exc:
                return State.BOGUS, Reason.MALFORMED, str(exc)
            if sig.type_covered != rrset[0].rtype:
                continue
            # An unrecognised / unimplemented algorithm can never validate,
            # even if no matching key is present; remember the first one.
            if not C.is_supported(sig.algorithm):
                if unsupported is None:
                    known = sig.algorithm in C.ALGORITHMS
                    unsupported = (
                        State.BOGUS,
                        Reason.UNSUPPORTED_ALGORITHM if known
                        else Reason.UNKNOWN_ALGORITHM,
                        f"algorithm {sig.algorithm} cannot be verified",
                    )
                continue
            state, reason, detail = self._check_time(sig)
            if state == State.BOGUS:
                time_failures.append(reason)
                continue
            applicable.append(sig)

        key_owner = parsed_keys[0][0].name if parsed_keys else rrset[0].name
        for sig in applicable:
            matching = [
                (kr, key) for kr, key in parsed_keys
                if key.key_tag == sig.key_tag
                and key.algorithm == sig.algorithm
                and key.zone_key
                and name_mod.equal_ci(sig.signer_name, key_owner)
            ]
            if not matching:
                continue
            signed_data = canonical.build_signed_data(rrset, sig)
            for _, key in matching:
                try:
                    ok = crypto.verify_signature(
                        sig.algorithm, key.public_key, signed_data, sig.signature
                    )
                except crypto.UnsupportedAlgorithm:
                    if unsupported is None:
                        unsupported = (
                            State.BOGUS, Reason.UNSUPPORTED_ALGORITHM,
                            f"algorithm {sig.algorithm} cannot be verified",
                        )
                    continue
                except crypto.CryptoError as exc:
                    continue
                if ok:
                    return State.SECURE, Reason.VALID_CHAIN, "signature valid"
        # No supported signature validated; report why in priority order.
        if unsupported is not None:
            return unsupported
        if time_failures:
            return State.BOGUS, time_failures[0], "no currently-valid signature"
        return State.BOGUS, Reason.SIGNATURE_INVALID, "no RRSIG validated"

    def _check_time(self, sig) -> tuple[State, Reason, str]:
        # RFC 4034: inception <= now <= expiration (inclusive boundaries).
        if self.now < sig.signature_inception:
            return (
                State.BOGUS, Reason.SIGNATURE_NOT_YET_VALID,
                f"inception {sig.signature_inception} > now {self.now}",
            )
        if self.now > sig.signature_expiration:
            return (
                State.BOGUS, Reason.SIGNATURE_EXPIRED,
                f"expiration {sig.signature_expiration} < now {self.now}",
            )
        return State.SECURE, Reason.VALID_CHAIN, "within validity window"

    # ------------------------------------------------------------------
    # DNSKEY / DS linkage
    # ------------------------------------------------------------------
    def find_matching_dnskeys(self, ds, dnskey_rrs: list[RR],
                               zone: tuple[bytes, ...]) -> list[RR]:
        out = []
        for key_rr in dnskey_rrs:
            try:
                key = rdata_mod.parse_dnskey(key_rr.rdata)
            except rdata_mod.WireFormatError:
                continue
            if key.algorithm != ds.algorithm:
                continue
            if key.key_tag != ds.key_tag:
                continue
            if crypto.ds_matches(ds, zone, key_rr.rdata):
                out.append(key_rr)
        return out

    def dnskey_signed_by(self, dnskey_rrs: list[RR],
                         signer_keys: list[RR],
                         sig_records: list[RR] | None = None
                         ) -> tuple[State, Reason, str]:
        """Verify a DNSKEY RRset.

        ``signer_keys`` are the candidate DNSKEY RRs that may validate the
        RRset; the matching RRSIG records are taken from ``sig_records`` (or
        from the RRset's own records for a self-signed apex).
        """
        rrsets = group_rrsets(dnskey_rrs)
        if len(rrsets) != 1:
            return State.BOGUS, Reason.MALFORMED, "DNSKEY records span multiple RRsets"
        dnskey_rrset = next(iter(rrsets.values()))
        sig_source = sig_records if sig_records is not None else dnskey_rrset
        sig_rrs = [r for r in sig_source if r.rtype == C.RRSIG]
        candidate_keys = signer_keys or dnskey_rrset
        rrsigs = self._rrsigs_for(dnskey_rrset, sig_rrs)
        return self.verify_rrset(dnskey_rrset, rrsigs, candidate_keys)

    def _rrsigs_for(self, rrset: list[RR], sig_rrs: list[RR]) -> list[RR]:
        owner = rrset[0].name
        rtype = rrset[0].rtype
        out = []
        for sig_rr in sig_rrs:
            if not name_mod.equal_ci(sig_rr.name, owner):
                continue
            try:
                sig = rdata_mod.parse_rrsig(sig_rr.rdata)
            except rdata_mod.WireFormatError:
                continue
            if sig.type_covered == rtype:
                out.append(sig_rr)
        return out

    # ------------------------------------------------------------------
    # Chain walking
    # ------------------------------------------------------------------
    def build_chain(self, qname: tuple[bytes, ...],
                    zones: dict[tuple[bytes, ...], ZoneData]):
        """Return the ordered list of zone apexes from an anchor to qname.

        Apex comparison is case-insensitive.  The first anchor whose zone is
        an ancestor of qname anchors the walk; subsequent anchors serve as
        rollover alternatives during key matching.
        """
        normalized = {name_mod.canonical_text(z): z for z in zones}
        anchor_zones = [
            a.zone for a in self.anchors
            if name_mod.is_subdomain(qname, a.zone)
        ]
        if not anchor_zones:
            return None
        start = min(anchor_zones, key=len)
        chain = []
        current = start
        while True:
            chain.append(current)
            if current == qname or len(current) >= len(qname):
                break
            child = self._next_zone(current, qname, zones, normalized)
            if child is None:
                break
            current = child
        return chain

    def _next_zone(self, parent, qname, zones, normalized):
        # Return the shallowest known zone apex immediately below parent (one
        # delegation hop), so intermediate zones are never skipped.
        for depth in range(len(parent) + 1, len(qname) + 1):
            apex = qname[len(qname) - depth:]
            key = name_mod.canonical_text(apex)
            if key in normalized:
                return normalized[key]
        return None

    def validate_zone_link(self, parent_zone, child_zone,
                           parent_data: ZoneData, child_data: ZoneData,
                           extra_keys: list[RR] | None = None
                           ) -> tuple[State, Reason, str, list[RR]]:
        """Verify that child_zone is authentically delegated by parent.

        Returns the validated child DNSKEY RRset so callers can continue the
        walk.  An unsigned delegation (DS absent) yields INSECURE.
        """
        parent_sets = parent_data.rrsets()
        child_sets = child_data.rrsets()
        ds_rrset = self._rrset(parent_sets, child_zone, C.DS)
        child_keys = self._rrset(child_sets, child_zone, C.DNSKEY)
        if ds_rrset is None:
            # No DS at the parent => the parent asserts an unsigned cut.
            return (
                State.INSECURE, Reason.UNSIGNED_DELEGATION,
                f"no DS for {name_mod.to_text(child_zone)}", [],
            )
        if not child_keys:
            return (
                State.BOGUS, Reason.NO_DNSKEY,
                f"child zone {name_mod.to_text(child_zone)} has no DNSKEY", [],
            )
        # The DS RRset must itself be signed by the parent DNSKEY.
        ds_sigs = self._rrsigs_for(ds_rrset, parent_data.records)
        parent_keys = extra_keys if extra_keys is not None else self._rrset(
            parent_sets, parent_zone, C.DNSKEY
        ) or []
        state, reason, detail = self.verify_rrset(ds_rrset, ds_sigs, parent_keys)
        if state != State.SECURE:
            return state, reason, f"DS RRset: {detail}", []
        # At least one DS must digest-match a child DNSKEY.
        validated = []
        for ds_rr in ds_rrset:
            ds = rdata_mod.parse_ds(ds_rr.rdata)
            validated.extend(self.find_matching_dnskeys(ds, child_keys, child_zone))
        if not validated:
            return (
                State.BOGUS, Reason.DS_DIGEST_MISMATCH,
                "no child DNSKEY matches a parent DS digest", [],
            )
        # The child DNSKEY RRset must validate under one of the matched keys.
        state, reason, detail = self.dnskey_signed_by(
            child_keys, validated, child_data.records
        )
        if state != State.SECURE:
            return state, reason, f"child DNSKEY RRset: {detail}", []
        return State.SECURE, Reason.VALID_CHAIN, "delegation verified", child_keys

    def _rrset(self, sets, owner, rtype):
        for (name, t, rclass), rrset in sets.items():
            if t == rtype and name_mod.equal_ci(name, owner):
                return rrset
        return None

    # ------------------------------------------------------------------
    # Trust anchors
    # ------------------------------------------------------------------
    def anchor_keys(self, zone) -> list[RR]:
        """Collect trusted DNSKEY RRs from every anchor for ``zone``.

        Both DNSKEY anchors and DS anchors are accepted.  For a DS anchor the
        matching child DNSKEY must be supplied in the captured zone data; for
        a DNSKEY anchor the key is trusted directly.  Multiple anchors make
        rollover transparent: the union of trusted keys is returned.
        """
        trusted: list[RR] = []
        for anchor in self.anchors:
            if not name_mod.equal_ci(anchor.zone, zone):
                continue
            if anchor.rr.rtype == C.DNSKEY:
                trusted.append(anchor.rr)
        return trusted

    def anchor_ds(self, zone) -> list[RR]:
        return [a.rr for a in self.anchors
                if a.rr.rtype == C.DS and name_mod.equal_ci(a.zone, zone)]

    def establish_apex(self, zone, data: ZoneData
                       ) -> tuple[State, Reason, str, list[RR]]:
        """Establish the DNSKEY RRset at an anchor apex (handles rollover)."""
        sets = data.rrsets()
        apex_keys = self._rrset(sets, zone, C.DNSKEY)
        if not apex_keys:
            return State.BOGUS, Reason.NO_DNSKEY, "anchor zone has no DNSKEY", []
        direct = self.anchor_keys(zone)
        if direct:
            state, reason, detail = self.dnskey_signed_by(
                apex_keys, direct, data.records
            )
            if state == State.SECURE:
                return state, reason, detail, apex_keys
            # Fall through to DS-based anchors before declaring failure.
        ds_anchors = self.anchor_ds(zone)
        if ds_anchors:
            matched: list[RR] = []
            for ds_rr in ds_anchors:
                ds = rdata_mod.parse_ds(ds_rr.rdata)
                matched.extend(self.find_matching_dnskeys(ds, apex_keys, zone))
            if not matched:
                return (
                    State.BOGUS, Reason.TRUST_ANCHOR_MISMATCH,
                    "no apex DNSKEY matches a DS trust anchor", [],
                )
            state, reason, detail = self.dnskey_signed_by(
                apex_keys, matched, data.records
            )
            if state == State.SECURE:
                return state, reason, detail, apex_keys
            return state, reason, detail, []
        if direct:
            return state, reason, detail, []
        return (
            State.INDETERMINATE, Reason.TRUST_ANCHOR_MISMATCH,
            "no applicable trust anchor for apex", [],
        )

    # ------------------------------------------------------------------
    # Top-level entry point
    # ------------------------------------------------------------------
    def validate(self, qname_text: str, qtype: int,
                 zones: dict[tuple[bytes, ...], ZoneData]) -> ValidationResult:
        qname = name_mod.from_text(qname_text)
        chain = self.build_chain(qname, zones)
        if chain is None:
            return ValidationResult(
                State.INDETERMINATE, Reason.TRUST_ANCHOR_MISMATCH,
                qname_text, qtype, "no trust anchor is an ancestor of qname",
            )
        proven: list[str] = []
        apex = chain[0]
        state, reason, detail, active_keys = self.establish_apex(
            apex, zones[apex]
        )
        if state != State.SECURE:
            return ValidationResult(state, reason, qname_text, qtype, detail)
        proven.append(name_mod.to_text(apex))
        previous_zone, previous_data, previous_keys = apex, zones[apex], active_keys

        for child in chain[1:]:
            state, reason, detail, child_keys = self.validate_zone_link(
                previous_zone, child, previous_data, zones[child],
                extra_keys=previous_keys,
            )
            if state == State.INSECURE:
                # Provably unsigned delegation: anything below cannot be
                # cryptographically proven, including a negative answer.
                return ValidationResult(
                    State.INSECURE, Reason.UNSIGNED_DELEGATION,
                    qname_text, qtype, detail, proven,
                )
            if state != State.SECURE:
                return ValidationResult(
                    State.BOGUS, reason, qname_text, qtype, detail, proven,
                )
            proven.append(name_mod.to_text(child))
            previous_zone, previous_data, previous_keys = (
                child, zones[child], child_keys,
            )

        # The chain is secure up to the zone that should contain qname.
        return self._validate_answer(
            qname, qtype, previous_zone, previous_data, previous_keys, proven,
            qname_text,
        )

    def _validate_answer(self, qname, qtype, zone, data: ZoneData,
                         zone_keys, proven, qname_text) -> ValidationResult:
        sets = data.rrsets()
        answer = self._rrset(sets, qname, qtype)
        cname = self._rrset(sets, qname, C.CNAME)
        if answer is not None:
            sigs = self._rrsigs_for(answer, data.records)
            state, reason, detail = self.verify_rrset(answer, sigs, zone_keys)
            return ValidationResult(
                state, reason, qname_text, qtype, detail, proven,
            )
        if cname is not None:
            sigs = self._rrsigs_for(cname, data.records)
            state, reason, detail = self.verify_rrset(cname, sigs, zone_keys)
            return ValidationResult(
                state, reason, qname_text, qtype, f"CNAME: {detail}", proven,
            )
        return self._classify_denial(
            qname, qtype, zone, data, zone_keys, proven, qname_text,
        )

    # ------------------------------------------------------------------
    # Authenticated denial
    # ------------------------------------------------------------------
    def _signed_nsec_records(self, data: ZoneData, zone_keys) -> list[RR]:
        sets = data.rrsets()
        valid = []
        for (owner, rtype, _rclass), rrset in sets.items():
            if rtype not in (C.NSEC, C.NSEC3):
                continue
            sigs = self._rrsigs_for(rrset, data.records)
            state, _, _ = self.verify_rrset(rrset, sigs, zone_keys)
            if state == State.SECURE:
                valid.extend(rrset)
        return valid

    def _classify_denial(self, qname, qtype, zone, data: ZoneData,
                         zone_keys, proven, qname_text) -> ValidationResult:
        # The SOA in authority distinguishes NXDOMAIN (name absent) from
        # NODATA (name present, type absent) in a normal negative response.
        has_soa = self._rrset(data.rrsets(), zone, C.SOA) is not None
        signed_proofs = self._signed_nsec_records(data, zone_keys)
        nsec = [r for r in signed_proofs if r.rtype == C.NSEC]
        nsec3 = [r for r in signed_proofs if r.rtype == C.NSEC3]

        if not signed_proofs:
            # No usable signed denial records.  If the zone is signed but the
            # proof is missing/failed this is bogus; an unsigned zone would
            # already have been caught at the delegation boundary.
            return ValidationResult(
                State.BOGUS, Reason.INSUFFICIENT_DENIAL,
                qname_text, qtype,
                "no validly signed NSEC/NSEC3 records prove the denial", proven,
            )

        if nsec:
            return self._classify_nsec(
                qname, qtype, zone, nsec, has_soa, proven, qname_text,
            )
        return self._classify_nsec3(
            qname, qtype, zone, data, nsec3, has_soa, proven, qname_text,
        )

    def _classify_nsec(self, qname, qtype, zone, nsec_records, has_soa,
                       proven, qname_text) -> ValidationResult:
        parsed = []
        for rr in nsec_records:
            record = rdata_mod.parse_nsec(rr.rdata)
            parsed.append((rr, record))

        # NXDOMAIN: an NSEC interval covers qname and qname is not an owner.
        covering = [
            (rr, rec) for rr, rec in parsed
            if nsec_mod.nsec_covers_name(rr, qname)
        ]
        name_exists = any(
            name_mod.equal_ci(rr.name, qname) for rr, _ in parsed
        )
        if covering and not name_exists:
            return ValidationResult(
                State.SECURE, Reason.PROVEN_NXDOMAIN,
                qname_text, qtype,
                "NSEC interval proves the name does not exist", proven,
            )

        # NODATA: an NSEC owned by qname lists its types but not qtype.
        for rr, rec in parsed:
            if name_mod.equal_ci(rr.name, qname):
                if qtype in rec.types:
                    return ValidationResult(
                        State.BOGUS, Reason.FORGED_DENIAL,
                        qname_text, qtype,
                        "NSEC type bitmap contains the denied type", proven,
                    )
                return ValidationResult(
                    State.SECURE, Reason.PROVEN_NODATA,
                    qname_text, qtype,
                    "owner NSEC proves the type does not exist", proven,
                )

        # Wildcard NODATA: a wildcard NSEC exists and qname matches it.
        for rr, rec in parsed:
            if nsec_mod.wildcard_nsec_covers(rr, qname):
                if qtype in rec.types:
                    return ValidationResult(
                        State.BOGUS, Reason.FORGED_DENIAL,
                        qname_text, qtype, "wildcard NSEC lists the type", proven,
                    )
                return ValidationResult(
                    State.SECURE, Reason.PROVEN_WILDCARD_NODATA,
                    qname_text, qtype, "wildcard NSEC proves NODATA", proven,
                )

        return ValidationResult(
            State.BOGUS, Reason.FORGED_DENIAL, qname_text, qtype,
            "NSEC records do not form a valid proof for this query", proven,
        )

    def _nsec3_params(self, data: ZoneData) -> NSEC3Parsed | None:
        for rr in data.records:
            if rr.rtype == C.NSEC3:
                return rdata_mod.parse_nsec3(rr.rdata)
        return None

    def _classify_nsec3(self, qname, qtype, zone, data: ZoneData,
                        nsec3_records, has_soa, proven,
                        qname_text) -> ValidationResult:
        params = self._nsec3_params(data)
        if params is None:
            return ValidationResult(
                State.BOGUS, Reason.MALFORMED, qname_text, qtype,
                "NSEC3 records present but parameters unavailable", proven,
            )
        wrapped = []
        for rr in nsec3_records:
            try:
                wrapped.append((rr, rdata_mod.parse_nsec3(rr.rdata)))
            except rdata_mod.WireFormatError:
                continue

        target_hash = nsec_mod.nsec3_hash(
            qname, params.hash_algorithm, params.iterations, params.salt
        )
        # NODATA: an NSEC3 owner equals the hash of qname and omits qtype.
        for rr, rec in wrapped:
            if nsec_mod._owner_hash(rr) == target_hash:
                if qtype in rec.types:
                    return ValidationResult(
                        State.BOGUS, Reason.FORGED_DENIAL, qname_text, qtype,
                        "NSEC3 bitmap contains the denied type", proven,
                    )
                return ValidationResult(
                    State.SECURE, Reason.PROVEN_NODATA, qname_text, qtype,
                    "NSEC3 owner proves the name exists without the type",
                    proven,
                )

        # NXDOMAIN: closest-encloser + next-closer coverage (RFC 7129).
        if nsec_mod.closest_encloser_proof(zone, qname, nsec3_records, params):
            return ValidationResult(
                State.SECURE, Reason.PROVEN_NXDOMAIN, qname_text, qtype,
                "NSEC3 closest-encloser proof establishes NXDOMAIN", proven,
            )

        # Wildcard NODATA fallback.
        if nsec_mod.wildcard_nsec3_covers(zone, qname, nsec3_records, params):
            return ValidationResult(
                State.SECURE, Reason.PROVEN_WILDCARD_NODATA, qname_text, qtype,
                "NSEC3 wildcard proof establishes NODATA", proven,
            )

        return ValidationResult(
            State.BOGUS, Reason.FORGED_DENIAL, qname_text, qtype,
            "NSEC3 records do not prove this denial", proven,
        )
