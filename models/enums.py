from __future__ import annotations

from enum import IntEnum


class ByteEnum(IntEnum):
    def __bytes__(self):
        return self.value.to_bytes(2, byteorder='big')

    @classmethod
    def from_bytes(cls, byte: bytes) -> ByteEnum:
        return cls(int.from_bytes(byte, byteorder='big'))


class TYPE(ByteEnum):
    """DNS record types."""
    OTHER = 0
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    HINFO = 13
    MX = 15
    TXT = 16
    AAAA = 28
    DNAME = 39
    CAA = 257


class QTYPEAddition(ByteEnum):
    """DNS query record types."""
    AXFR = 252
    MAILB = 253
    MAILA = 254
    ANY = 255


QTYPE = ByteEnum('QTYPE', TYPE.__members__ | QTYPEAddition.__members__)


class CLASS(ByteEnum):
    """DNS record classes."""
    IN = 1
    CH = 3
    HS = 4


class QCLASSAddition(ByteEnum):
    """DNS query record classes."""
    ANY = 255


QCLASS = ByteEnum('QCLASS', CLASS.__members__ | QCLASSAddition.__members__)


class QR(IntEnum):
    """DNS message types."""
    QUERY = 0
    RESPONSE = 1


class OPCODE(IntEnum):
    """DNS operation codes."""
    QUERY = 0
    IQUERY = 1


class RCODE(IntEnum):
    """DNS response codes."""
    NO_ERROR = 0
    FORMAT_ERROR = 1
    SERVER_FAILURE = 2
    NAME_ERROR = 3
    NOT_IMPLEMENTED = 4
    REFUSED = 5
    YX_DOMAIN = 6
    YX_RR_SET = 7
    NX_RR_SET = 8
    NOT_AUTH = 9
    NOT_ZONE = 10

