from __future__ import annotations

from models import Header, QR, OPCODE, RCODE
from models.constants import HEADER_QR_SHIFT, HEADER_OPCODE_SHIFT, HEADER_AA_SHIFT, HEADER_TC_SHIFT, HEADER_RD_SHIFT, \
    HEADER_RA_SHIFT, HEADER_Z_SHIFT, HEADER_RCODE_SHIFT, HEADER_LENGTH
from models.exceptions import AlreadySentException


class RequestHeader(Header):
    _sent: bool = False

    class Builder:
        def __init__(self):
            self.val_id = 0
            self.val_qdcount = 0
            self.val_ancount = 0
            self.val_rd = True
            self.val_opcode = OPCODE.QUERY

        def id(self, id_: int) -> RequestHeader.Builder:
            self.val_id = id_
            return self

        def qdcount(self, qdcount: int) -> RequestHeader.Builder:
            if qdcount < 0 or qdcount > 65535:
                raise ValueError('qdcount must be between 0 and 65535')
            self.val_qdcount = qdcount
            return self

        def ancount(self, ancount: int) -> RequestHeader.Builder:
            if ancount < 0 or ancount > 65535:
                raise ValueError('ancount must be between 0 and 65535')
            self.val_ancount = ancount
            return self

        def rd(self, rd: bool) -> RequestHeader.Builder:
            self.val_rd = rd
            return self

        def opcode(self, opcode: OPCODE) -> RequestHeader.Builder:
            self.val_opcode = opcode
            return self

        def build(self) -> RequestHeader:
            return RequestHeader(self)

    def __init__(self, builder: Builder):
        self._id = builder.val_id
        self._qdcount = builder.val_qdcount
        self._ancount = builder.val_ancount
        self._nscount = 0
        self._arcount = 0
        self._qr = QR.QUERY
        self._opcode = builder.val_opcode
        self._aa = False
        self._tc = False
        self._rd = builder.val_rd
        self._ra = False
        self._z = 0
        self._rcode = RCODE.NO_ERROR

    def calculate_flags(self):
        self._flags = 0
        self._flags |= self._qr.value << HEADER_QR_SHIFT
        self._flags |= self._opcode.value << HEADER_OPCODE_SHIFT
        self._flags |= self._aa << HEADER_AA_SHIFT
        self._flags |= self._tc << HEADER_TC_SHIFT
        self._flags |= self._rd << HEADER_RD_SHIFT
        self._flags |= self._ra << HEADER_RA_SHIFT
        self._flags |= self._z << HEADER_Z_SHIFT
        self._flags |= self._rcode.value << HEADER_RCODE_SHIFT

    @Header.id.setter
    def id(self, id_: int):
        if self._sent:
            raise AlreadySentException()
        self._id = id_

    @Header.qdcount.setter
    def qdcount(self, qdcount: int):
        if self._sent:
            raise AlreadySentException()
        if qdcount < 0 or qdcount > 65535:
            raise ValueError('qdcount must be between 0 and 65535')
        self._qdcount = qdcount

    @Header.ancount.setter
    def ancount(self, ancount: int):
        if self._sent:
            raise AlreadySentException()
        if ancount < 0 or ancount > 65535:
            raise ValueError('ancount must be between 0 and 65535')
        self._ancount = ancount

    @Header.rd.setter
    def rd(self, rd: bool):
        if self._sent:
            raise AlreadySentException()
        self._rd = rd

    @Header.opcode.setter
    def opcode(self, opcode: OPCODE):
        if self._sent:
            raise AlreadySentException()
        self._opcode = opcode

    @property
    def sent(self):
        return self._sent

    def mark_sent(self):
        self._sent = True

    def __bytes__(self) -> bytes:
        self.calculate_flags()
        arr = bytearray()
        arr.extend(self._id.to_bytes(2, byteorder='big'))
        arr.extend(self._flags.to_bytes(2, byteorder='big'))
        arr.extend(self._qdcount.to_bytes(2, byteorder='big'))
        arr.extend(self._ancount.to_bytes(2, byteorder='big'))
        arr.extend(self._nscount.to_bytes(2, byteorder='big'))
        arr.extend(self._arcount.to_bytes(2, byteorder='big'))
        return bytes(arr)

    def __len__(self):
        return HEADER_LENGTH
