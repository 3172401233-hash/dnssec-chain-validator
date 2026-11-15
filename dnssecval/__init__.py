"""Offline DNSSEC chain validation library.

Public entry points:

* :class:`~dnssecval.validator.Validator` - chain + denial validation.
* :class:`~dnssecval.validator.TrustAnchor`, :class:`~dnssecval.validator.ZoneData`.
* :class:`~dnssecval.status.State`, :class:`~dnssecval.status.Reason`,
  :class:`~dnssecval.status.ValidationResult`.
* :mod:`dnssecval.wire` - strict wire parsing (truncation aware).
* :mod:`dnssecval.builder` - keypair / signed-record construction.
"""

from .status import Reason, State, ValidationResult
from .validator import TrustAnchor, Validator, ValidatorError, ZoneData
from .wire import Message, RR, TruncatedWire, WireFormatError, parse_message, parse_single_rr

__all__ = [
    "Reason",
    "State",
    "ValidationResult",
    "TrustAnchor",
    "Validator",
    "ValidatorError",
    "ZoneData",
    "Message",
    "RR",
    "TruncatedWire",
    "WireFormatError",
    "parse_message",
    "parse_single_rr",
]
