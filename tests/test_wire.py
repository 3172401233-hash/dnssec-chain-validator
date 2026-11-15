import struct
import unittest

from dnssecval import builder
from dnssecval import constants as C
from dnssecval import name
from dnssecval.wire import (
    TruncatedWire,
    WireFormatError,
    group_rrsets,
    parse_message,
    parse_single_rr,
)


def wire_rr(owner: str, rtype: int, rdata: bytes, ttl: int = 300) -> bytes:
    out = bytearray(name.to_wire(name.from_text(owner)))
    out += struct.pack("!HHIH", rtype, 1, ttl, len(rdata))
    out += rdata
    return bytes(out)


class WireParseTests(unittest.TestCase):
    def test_round_trip_single_rr(self):
        raw = wire_rr("www.example.", C.A, builder.a_rdata("198.51.100.7"))
        rr = parse_single_rr(raw)
        self.assertEqual(name.to_text(rr.name), "www.example.")
        self.assertEqual(rr.rtype, C.A)
        self.assertEqual(rr.rdata, builder.a_rdata("198.51.100.7"))

    def test_truncated_rdata_raises(self):
        raw = wire_rr("www.example.", C.A, builder.a_rdata("198.51.100.7"))
        with self.assertRaises(TruncatedWire):
            parse_single_rr(raw[:-2])

    def test_truncated_header_raises(self):
        raw = wire_rr("x.example.", C.A, b"\x01\x02\x03\x04")
        with self.assertRaises(WireFormatError):
            parse_single_rr(raw[:6])

    def test_trailing_octets_rejected(self):
        raw = wire_rr("x.example.", C.A, builder.a_rdata("198.51.100.7"))
        with self.assertRaises(WireFormatError):
            parse_single_rr(raw + b"\x00")

    def test_compression_pointer_in_message(self):
        # Header with one question and one answer; answer name is a pointer
        # back to the question name.
        qname = name.to_wire(name.from_text("host.example."))
        header = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
        question = qname + struct.pack("!HH", C.A, 1)
        answer = b"\xc0\x0c"
        answer += struct.pack("!HHIH", C.A, 1, 60, 4) + builder.a_rdata("203.0.113.9")
        msg = parse_message(header + question + answer)
        self.assertEqual(len(msg.answers), 1)
        self.assertEqual(name.to_text(msg.answers[0].name), "host.example.")

    def test_bad_compression_pointer(self):
        header = struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0)
        # Pointer loops to itself at offset 12.
        bad = header + b"\xc0\x0c"
        with self.assertRaises(WireFormatError):
            parse_message(bad)

    def test_duplicate_records_collapse(self):
        rr = builder.make_rr("a.example.", C.A, builder.a_rdata("192.0.2.5"))
        groups = group_rrsets([rr, rr, rr])
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(next(iter(groups.values()))), 1)

    def test_distinct_rdata_kept(self):
        rr1 = builder.make_rr("a.example.", C.A, builder.a_rdata("192.0.2.5"))
        rr2 = builder.make_rr("a.example.", C.A, builder.a_rdata("192.0.2.6"))
        groups = group_rrsets([rr1, rr2])
        self.assertEqual(len(next(iter(groups.values()))), 2)


if __name__ == "__main__":
    unittest.main()
