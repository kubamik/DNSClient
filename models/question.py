from __future__ import annotations

from typing import Optional, Union

from models import QTYPE, QCLASS, DomainName


class Question:
    _qname: DomainName
    _qtype: QTYPE
    _qclass: QCLASS

    def __init__(self, qname: Union[str, DomainName], qtype: QTYPE, qclass: QCLASS):
        if isinstance(qname, str):
            self._qname = DomainName(qname)
        else:
            self._qname = qname
        self._qtype = qtype
        self._qclass = qclass

    @property
    def qname(self) -> DomainName:
        return self._qname

    @property
    def qtype(self) -> QTYPE:
        return self._qtype

    @property
    def qclass(self) -> QCLASS:
        return self._qclass

    def modified_copy(self, qname: Optional[str] = None, qtype: Optional[QTYPE] = None,
                      qclass: Optional[QCLASS] = None) -> Question:
        if qname is None:
            qname = self._qname
        if qtype is None:
            qtype = self._qtype
        if qclass is None:
            qclass = self._qclass

        return Question(qname, qtype, qclass)

    def __bytes__(self):
        arr = bytearray()
        arr.extend(bytes(self._qname))
        arr.extend(bytes(self._qtype))
        arr.extend(bytes(self._qclass))

        return bytes(arr)

    @classmethod
    def from_bytes(cls, payload: bytes) -> Question:
        qname, n = DomainName.from_bytes(payload)
        n = len(qname)
        qtype = QTYPE.from_bytes(payload[n: n+2])
        qclass = QCLASS.from_bytes(payload[n+2: n+4])

        return cls(qname, qtype, qclass)

    def __len__(self):
        return len(self._qname) + 4

    def __repr__(self):
        return f'{self._qname} {self._qtype.name} {self._qclass.name}'

    def __eq__(self, other: Question):
        if not isinstance(other, Question):
            return False
        return self._qname == other._qname and self._qtype == other._qtype and self._qclass == other._qclass
