from __future__ import annotations

from models import Header, QR, OPCODE, RCODE
from models.constants import HEADER_ID_SECTION, HEADER_FLAGS_SECTION, HEADER_QDCOUNT_SECTION, HEADER_ANCOUNT_SECTION, \
    HEADER_NSCOUNT_SECTION, HEADER_ARCOUNT_SECTION, HEADER_QR_MASK, HEADER_QR_SHIFT, HEADER_OPCODE_MASK, \
    HEADER_OPCODE_SHIFT, HEADER_AA_SHIFT, HEADER_TC_SHIFT, HEADER_RD_SHIFT, HEADER_RA_SHIFT, HEADER_Z_SHIFT, \
    HEADER_Z_MASK, HEADER_RA_MASK, HEADER_RD_MASK, HEADER_TC_MASK, HEADER_AA_MASK, HEADER_RCODE_MASK, \
    HEADER_RCODE_SHIFT, HEADER_LENGTH
from models.exceptions import DNSError, MalformedDNSResponseException


class ResponseHeader(Header):
    _valid: bool

    def __init__(self, payload: bytes):
        if len(payload) < HEADER_LENGTH:
            raise MalformedDNSResponseException("Invalid header")
        self._id = int.from_bytes(payload[HEADER_ID_SECTION], byteorder='big')
        self._flags = int.from_bytes(payload[HEADER_FLAGS_SECTION], byteorder='big')
        self._qdcount = int.from_bytes(payload[HEADER_QDCOUNT_SECTION], byteorder='big')
        self._ancount = int.from_bytes(payload[HEADER_ANCOUNT_SECTION], byteorder='big')
        self._nscount = int.from_bytes(payload[HEADER_NSCOUNT_SECTION], byteorder='big')
        self._arcount = int.from_bytes(payload[HEADER_ARCOUNT_SECTION], byteorder='big')
        self.parse_flags()

    def parse_flags(self) -> None:
        try:
            self._qr = QR((self._flags & HEADER_QR_MASK) >> HEADER_QR_SHIFT)
        except ValueError:
            self._qr = None
        try:
            self._opcode = OPCODE((self._flags & HEADER_OPCODE_MASK) >> HEADER_OPCODE_SHIFT)
        except ValueError:
            self._opcode = None
        self._aa = bool((self._flags & HEADER_AA_MASK) >> HEADER_AA_SHIFT)
        self._tc = bool((self._flags & HEADER_TC_MASK) >> HEADER_TC_SHIFT)
        self._rd = bool((self._flags & HEADER_RD_MASK) >> HEADER_RD_SHIFT)
        self._ra = bool((self._flags & HEADER_RA_MASK) >> HEADER_RA_SHIFT)
        self._z = (self._flags & HEADER_Z_MASK) >> HEADER_Z_SHIFT
        try:
            self._rcode = RCODE(self._flags & HEADER_RCODE_MASK >> HEADER_RCODE_SHIFT)
        except ValueError:
            self._rcode = None

    def validate(self) -> None:
        if self._rcode is not None and self._rcode != RCODE.NO_ERROR:
            raise DNSError("Server responded with error code: {} '{}'".format(self._rcode, self._rcode.name),
                           self._rcode, self._aa)
        if self._qr is None or self._opcode is None or self._rcode is None or self._z != 0:
            raise MalformedDNSResponseException("Invalid header")
        self._valid = True

    def extend(self, other: ResponseHeader):
        self._ancount += other.ancount
        self._nscount += other.nscount
        self._arcount += other.arcount
        self._tc = other.tc
        self._rcode = other.rcode
        self._ra = other.ra
        self._flags = other.flags

    @property
    def successful(self) -> bool:
        return self._valid and self._rcode is RCODE.NO_ERROR

    @property
    def valid(self) -> bool:
        return self._valid


