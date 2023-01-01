from __future__ import annotations

from typing import Optional

from models import QR, OPCODE, RCODE


class Header:
    _id: int
    _flags: int
    _qdcount: int
    _ancount: int
    _nscount: int
    _arcount: int
    _qr: Optional[QR]
    _opcode: Optional[OPCODE]
    _aa: bool
    _tc: bool
    _rd: bool
    _ra: bool
    _z: int
    _rcode: Optional[RCODE]

    @property
    def id(self) -> int:
        return self._id

    @property
    def flags(self) -> int:
        return self._flags

    @property
    def qdcount(self) -> int:
        return self._qdcount

    @property
    def ancount(self) -> int:
        return self._ancount

    @property
    def nscount(self) -> int:
        return self._nscount

    @property
    def arcount(self) -> int:
        return self._arcount

    @property
    def qr(self) -> Optional[QR]:
        return self._qr

    @property
    def opcode(self) -> Optional[OPCODE]:
        return self._opcode

    @property
    def aa(self) -> bool:
        return self._aa

    @property
    def tc(self) -> bool:
        return self._tc

    @property
    def rd(self) -> bool:
        return self._rd

    @property
    def ra(self) -> bool:
        return self._ra

    @property
    def z(self) -> int:
        return self._z

    @property
    def rcode(self) -> Optional[RCODE]:
        return self._rcode
