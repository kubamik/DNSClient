from __future__ import annotations

from datetime import timedelta
import socket
from typing import Type, Union, Optional

from models import TYPE, CLASS, DomainName
from models.constants.rr_constants import RR_TYPE_SECTION, RR_CLASS_SECTION, RR_TTL_SECTION, RR_RDLENGTH_SECTION, \
    RR_RDATA_SECTION, RR_FIXED_LENGTH, MX_PREFERENCE_SECTION


class RR:
    _name: DomainName
    _type: TYPE
    _class: CLASS
    _ttl: int
    _rdlength: int
    _rdata: Optional[bytes]

    def __init__(self, name: DomainName, type_: Union[TYPE, int], class_: CLASS, ttl: int, rdlength: int,
                 rdata: Optional[bytes] = None):
        self._name = name
        self._type = type_
        self._class = class_
        self._ttl = ttl
        self._rdlength = rdlength
        self._rdata = rdata

    def __bytes__(self):
        ...

    @classmethod
    def from_bytes(cls, name: DomainName, payload: bytes, original: bytes) -> RR:
        try:
            type_ = TYPE.from_bytes(payload[RR_TYPE_SECTION])
        except ValueError:
            type_ = int.from_bytes(payload[RR_TYPE_SECTION], 'big')
        class_ = CLASS.from_bytes(payload[RR_CLASS_SECTION])
        ttl = int.from_bytes(payload[RR_TTL_SECTION], 'big')
        rdlength = int.from_bytes(payload[RR_RDLENGTH_SECTION], 'big')
        rdata = payload[RR_RDATA_SECTION.start: RR_RDATA_SECTION.start + rdlength]
        return cls(name, type_, class_, ttl, len(rdata), rdata)

    def __len__(self):
        return len(self._name) + RR_FIXED_LENGTH + self._rdlength

    def __repr__(self):
        type_name = self._type if not isinstance(self._type, TYPE) else self._type.name
        return f'{self._name} {type_name} {self._class.name} {timedelta(seconds=self._ttl)}'

    @property
    def name(self):
        return self._name

    @property
    def type_(self) -> Union[TYPE, int]:
        return self._type

    @property
    def class_(self) -> CLASS:
        return self._class

    @property
    def ttl(self) -> int:
        return self._ttl

    @property
    def rdlength(self) -> int:
        return self._rdlength

    @property
    def rdata(self) -> Optional[bytes]:
        return self.rdata


class A(RR):
    _type = TYPE.A
    _class = CLASS.IN
    _address: str

    def __init__(self, name: DomainName, ttl: int, address: str, rdlength: int = -1):
        if rdlength == -1:
            rdlength = 4
        super().__init__(name, self.type_, self.class_, ttl, rdlength)
        self._address = address

    @classmethod
    def from_bytes(cls, name: DomainName, payload: bytes, original: bytes) -> RR:
        ttl = int.from_bytes(payload[RR_TTL_SECTION], 'big')
        rdlength = int.from_bytes(payload[RR_RDLENGTH_SECTION], 'big')
        rdata = payload[RR_RDATA_SECTION.start: RR_RDATA_SECTION.start + rdlength]
        address = socket.inet_ntop(socket.AF_INET, rdata)
        return cls(name, ttl, address, rdlength)

    def __repr__(self):
        return f'{self._name} {self.type_.name} {self.class_.name} {timedelta(seconds=self._ttl)} {self._address}'

    @property
    def address(self) -> str:
        return self._address


class NS(RR):
    _type = TYPE.NS
    _nsdname: DomainName

    def __init__(self, name: DomainName, class_: CLASS, ttl: int, rdlength: int, nsdname: DomainName):
        super().__init__(name, self.type_, class_, ttl, rdlength)
        self._nsdname = nsdname

    @classmethod
    def from_bytes(cls, name: DomainName, payload: bytes, original: bytes) -> RR:
        class_ = CLASS.from_bytes(payload[RR_CLASS_SECTION])
        ttl = int.from_bytes(payload[RR_TTL_SECTION], 'big')
        rdlength = int.from_bytes(payload[RR_RDLENGTH_SECTION], 'big')
        rdata = payload[RR_RDATA_SECTION.start: RR_RDATA_SECTION.start + rdlength]
        nsdname, _ = DomainName.from_bytes(rdata, original)
        return cls(name, class_, ttl, rdlength, nsdname)

    def __repr__(self):
        return f'{self._name} {self.type_.name} {self._class.name} {timedelta(seconds=self._ttl)} {self._nsdname}'

    @property
    def nsdname(self) -> DomainName:
        return self._nsdname


class CNAME(RR):
    _type = TYPE.CNAME
    _cname: DomainName

    def __init__(self, name: DomainName, class_: CLASS, ttl: int, rdlength: int, cname: DomainName):
        super().__init__(name, self.type_, class_, ttl, rdlength)
        self._cname = cname

    @classmethod
    def from_bytes(cls, name: DomainName, payload: bytes, original: bytes) -> RR:
        class_ = CLASS.from_bytes(payload[RR_CLASS_SECTION])
        ttl = int.from_bytes(payload[RR_TTL_SECTION], 'big')
        rdlength = int.from_bytes(payload[RR_RDLENGTH_SECTION], 'big')
        rdata = payload[RR_RDATA_SECTION.start: RR_RDATA_SECTION.start + rdlength]
        cname, _ = DomainName.from_bytes(rdata, original)
        return cls(name, class_, ttl, rdlength, cname)

    def __repr__(self):
        return f'{self._name} {self.type_.name} {self._class.name} {timedelta(self._ttl)} {self._cname}'

    @property
    def cname(self) -> DomainName:
        return self._cname


class MX(RR):
    _type = TYPE.MX
    _preference: int
    _exchange: DomainName

    def __init__(self, name: DomainName, class_: CLASS, ttl: int, rdlength: int, preference: int, exchange: DomainName):
        super().__init__(name, self.type_, class_, ttl, rdlength)
        self._preference = preference
        self._exchange = exchange

    @classmethod
    def from_bytes(cls, name: DomainName, payload: bytes, original: bytes) -> RR:
        class_ = CLASS.from_bytes(payload[RR_CLASS_SECTION])
        ttl = int.from_bytes(payload[RR_TTL_SECTION], 'big')
        rdlength = int.from_bytes(payload[RR_RDLENGTH_SECTION], 'big')
        rdata = payload[RR_RDATA_SECTION.start: RR_RDATA_SECTION.start + rdlength]
        preference = int.from_bytes(rdata[MX_PREFERENCE_SECTION], 'big')
        exchange, _ = DomainName.from_bytes(rdata[2:], original)
        return cls(name, class_, ttl, rdlength, preference, exchange)

    def __repr__(self):
        return f'{self._name} {self.type_.name} {self._class.name} {timedelta(seconds=self._ttl)} {self._preference} ' \
               f'{self._exchange}'

    @property
    def preference(self) -> int:
        return self._preference

    @property
    def exchange(self) -> DomainName:
        return self._exchange


class TXT(RR):
    _type = TYPE.TXT
    _txt: str

    def __init__(self, name: DomainName, class_: CLASS, ttl: int, rdlength: int, txt: str):
        super().__init__(name, self.type_, class_, ttl, rdlength)
        self._txt = txt

    @classmethod
    def from_bytes(cls, name: DomainName, payload: bytes, original: bytes) -> RR:
        class_ = CLASS.from_bytes(payload[RR_CLASS_SECTION])
        ttl = int.from_bytes(payload[RR_TTL_SECTION], 'big')
        rdlength = int.from_bytes(payload[RR_RDLENGTH_SECTION], 'big')
        rdata = payload[RR_RDATA_SECTION.start: RR_RDATA_SECTION.start + rdlength]
        txt = ''
        while rdata:
            length = int.from_bytes(rdata[:1], 'big')
            txt += rdata[1:1 + length].decode('utf-8')
            rdata = rdata[1 + length:]
        return cls(name, class_, ttl, rdlength, txt)

    def __repr__(self):
        return f'{self._name} {self.type_.name} {self._class.name} {timedelta(seconds=self._ttl)} {self._txt}'

    @property
    def txt(self) -> str:
        return self._txt


class AAAA(RR):
    _type = TYPE.AAAA
    _address: str

    def __init__(self, name: DomainName, class_: CLASS, ttl: int, rdlength: int, address: str):
        super().__init__(name, self.type_, class_, ttl, rdlength)
        self._address = address

    @classmethod
    def from_bytes(cls, name: DomainName, payload: bytes, original: bytes) -> RR:
        class_ = CLASS.from_bytes(payload[RR_CLASS_SECTION])
        ttl = int.from_bytes(payload[RR_TTL_SECTION], 'big')
        rdlength = int.from_bytes(payload[RR_RDLENGTH_SECTION], 'big')
        rdata = payload[RR_RDATA_SECTION.start: RR_RDATA_SECTION.start + rdlength]
        address = socket.inet_ntop(socket.AF_INET6, rdata)
        return cls(name, class_, ttl, rdlength, address)

    def __repr__(self):
        return f'{self._name} {self.type_.name} {self._class.name} {timedelta(seconds=self._ttl)} {self._address}'

    @property
    def address(self) -> str:
        return self._address


type_to_RR = {
    TYPE.A: A,
    TYPE.NS: NS,
    TYPE.CNAME: CNAME,
    TYPE.MX: MX,
    TYPE.TXT: TXT,
    TYPE.AAAA: AAAA
}


def get_rr_type(payload: bytes) -> Type[RR]:
    try:
        type_ = TYPE.from_bytes(payload[RR_TYPE_SECTION])
    except ValueError:
        return RR
    return type_to_RR.get(type_, RR)
