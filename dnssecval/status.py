"""Validation outcome vocabulary.

The top-level state mirrors the DNSSEC resolver model:

* ``SECURE``   - a complete, cryptographically valid chain was established.
* ``INSECURE`` - the zone provably does not use DNSSEC (signed proof of an
                 unsigned delegation), so absence/presence is trusted but
                 unsigned.  This is the "resolver cannot prove the negative"
                 case at the trust boundary.
* ``BOGUS``    - DNSSEC is expected but verification failed (broken chain,
                 bad signature, expired signature, forged denial, ...).
* ``INDETERMINATE`` - no trust anchor could be related to the query.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class State(str, Enum):
    SECURE = "SECURE"
    INSECURE = "INSECURE"
    BOGUS = "BOGUS"
    INDETERMINATE = "INDETERMINATE"


class Reason(str, Enum):
    # Positive / generic
    VALID_CHAIN = "valid_chain"
    NO_SIGNATURE = "no_signature"                 # RRset not signed
    UNSUPPORTED_ALGORITHM = "unsupported_algorithm"
    UNKNOWN_ALGORITHM = "unknown_algorithm"
    SIGNATURE_NOT_YET_VALID = "signature_not_yet_valid"
    SIGNATURE_EXPIRED = "signature_expired"
    SIGNATURE_INVALID = "signature_invalid"
    NO_MATCHING_DNSKEY = "no_matching_dnskey"
    DS_DIGEST_MISMATCH = "ds_digest_mismatch"
    BROKEN_CHAIN = "broken_chain"
    TRUST_ANCHOR_MISMATCH = "trust_anchor_mismatch"
    # Denial
    PROVEN_NXDOMAIN = "proven_nxdomain"
    PROVEN_NODATA = "proven_nodata"
    PROVEN_WILDCARD_NODATA = "proven_wildcard_nodata"
    FORGED_DENIAL = "forged_denial"
    INSUFFICIENT_DENIAL = "insufficient_denial"
    # Zone boundary
    UNSIGNED_DELEGATION = "unsigned_delegation"
    NO_DNSKEY = "no_dnskey"
    # Structural
    MALFORMED = "malformed"


@dataclass
class ValidationResult:
    state: State
    reason: Reason
    qname: str
    qtype: int
    detail: str = ""
    proven_chain: list[str] = field(default_factory=list)

    @property
    def secure(self) -> bool:
        return self.state == State.SECURE

    @property
    def bogus(self) -> bool:
        return self.state == State.BOGUS

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        base = f"{self.state.value}: {self.reason.value} for {self.qname} {self.qtype}"
        return f"{base} ({self.detail})" if self.detail else base
