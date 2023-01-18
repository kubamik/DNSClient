from __future__ import annotations

from datetime import timedelta
import socket
from typing import Type, Union, Optional

from models import TYPE, CLASS, DomainName
from models.constants.rr_constants import RR_TYPE_SECTION, RR_CLASS_SECTION, RR_TTL_SECTION, RR_RDLENGTH_SECTION, \
    RR_RDATA_SECTION, RR_FIXED_LENGTH, MX_PREFERENCE_SECTION, SOA_SERIAL_SECTION_LENGTH, SOA_REFRESH_SECTION_LENGTH, \
    SOA_RETRY_SECTION_LENGTH, SOA_EXPIRE_SECTION_LENGTH, SOA_MINIMUM_SECTION_LENGTH, CAA_FLAGS_SECTION, \
    CAA_TAG_LENGTH_SECTION, CAA_TAG_SECTION


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
        return f'{self._name} {type_name} {self._class.name} {timedelta(seconds=self._ttl)} {self._rdata}'

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


class DNAME(RR):
    _type = TYPE.CNAME
    _dname: DomainName

    def __init__(self, name: DomainName, class_: CLASS, ttl: int, rdlength: int, cname: DomainName):
        super().__init__(name, self.type_, class_, ttl, rdlength)
        self._dname = cname

    @classmethod
    def from_bytes(cls, name: DomainName, payload: bytes, original: bytes) -> RR:
        class_ = CLASS.from_bytes(payload[RR_CLASS_SECTION])
        ttl = int.from_bytes(payload[RR_TTL_SECTION], 'big')
        rdlength = int.from_bytes(payload[RR_RDLENGTH_SECTION], 'big')
        rdata = payload[RR_RDATA_SECTION.start: RR_RDATA_SECTION.start + rdlength]
        cname, _ = DomainName.from_bytes(rdata, original)
        return cls(name, class_, ttl, rdlength, cname)

    def __repr__(self):
        return f'{self._name} {self.type_.name} {self._class.name} {timedelta(self._ttl)} {self._dname}'

    @property
    def dname(self) -> DomainName:
        return self._dname


class SOA(RR):
    _type = TYPE.SOA
    _mname: DomainName
    _rname: DomainName
    _serial: int
    _refresh: int
    _retry: int
    _expire: int
    _minimum: int

    def __init__(self, name: DomainName, class_: CLASS, ttl: int, rdlength: int, mname: DomainName, rname: DomainName,
                 serial: int, refresh: int, retry: int, expire: int, minimum: int):
        super().__init__(name, self.type_, class_, ttl, rdlength)
        self._mname = mname
        self._rname = rname
        self._serial = serial
        self._refresh = refresh
        self._retry = retry
        self._expire = expire
        self._minimum = minimum

    @classmethod
    def from_bytes(cls, name: DomainName, payload: bytes, original: bytes) -> RR:
        class_ = CLASS.from_bytes(payload[RR_CLASS_SECTION])
        ttl = int.from_bytes(payload[RR_TTL_SECTION], 'big')
        rdlength = int.from_bytes(payload[RR_RDLENGTH_SECTION], 'big')
        rdata = payload[RR_RDATA_SECTION.start: RR_RDATA_SECTION.start + rdlength]
        mname, length = DomainName.from_bytes(rdata, original)
        rname, rname_length = DomainName.from_bytes(rdata[length:], original)
        length += rname_length
        serial = int.from_bytes(rdata[length: length + SOA_SERIAL_SECTION_LENGTH], 'big')
        length += SOA_SERIAL_SECTION_LENGTH
        refresh = int.from_bytes(rdata[length: length + SOA_REFRESH_SECTION_LENGTH], 'big')
        length += SOA_REFRESH_SECTION_LENGTH
        retry = int.from_bytes(rdata[length: length + SOA_RETRY_SECTION_LENGTH], 'big')
        length += SOA_RETRY_SECTION_LENGTH
        expire = int.from_bytes(rdata[length: length + SOA_EXPIRE_SECTION_LENGTH], 'big')
        length += SOA_EXPIRE_SECTION_LENGTH
        minimum = int.from_bytes(rdata[length: length + SOA_MINIMUM_SECTION_LENGTH], 'big')
        return cls(name, class_, ttl, rdlength, mname, rname, serial, refresh, retry, expire, minimum)

    def __repr__(self):
        rname = self._rname.labels[0].replace('\\', '') + '@' + '.'.join(self._rname.labels[1:])
        return f'{self._name} {self.type_.name} {self._class.name} {timedelta(seconds=self._ttl)} {self._mname} ' \
               f'{rname} {self._serial} {timedelta(seconds=self._refresh)} {timedelta(seconds=self._retry)}' \
               f' {timedelta(seconds=self._expire)} {timedelta(seconds=self._minimum)}'

    @property
    def mname(self) -> DomainName:
        return self._mname

    @property
    def rname(self) -> DomainName:
        return self._rname

    @property
    def serial(self) -> int:
        return self._serial

    @property
    def refresh(self) -> int:
        return self._refresh

    @property
    def retry(self) -> int:
        return self._retry

    @property
    def expire(self) -> int:
        return self._expire

    @property
    def minimum(self) -> int:
        return self._minimum


class CAA(RR):
    _type = TYPE.CAA
    flags: int
    tag: str
    value: str

    def __init__(self, name: DomainName, class_: CLASS, ttl: int, rdlength: int, flags: int, tag: str, value: str):
        super().__init__(name, self.type_, class_, ttl, rdlength)
        self.flags = flags
        self.tag = tag
        self.value = value

    @classmethod
    def from_bytes(cls, name: DomainName, payload: bytes, original: bytes) -> RR:
        class_ = CLASS.from_bytes(payload[RR_CLASS_SECTION])
        ttl = int.from_bytes(payload[RR_TTL_SECTION], 'big')
        rdlength = int.from_bytes(payload[RR_RDLENGTH_SECTION], 'big')
        rdata = payload[RR_RDATA_SECTION.start: RR_RDATA_SECTION.start + rdlength]
        flags = int.from_bytes(rdata[CAA_FLAGS_SECTION], 'big')
        tag_length = int.from_bytes(rdata[CAA_TAG_LENGTH_SECTION], 'big')
        tag = rdata[CAA_TAG_SECTION.start: CAA_TAG_SECTION.start + tag_length].decode('utf-8')
        value = rdata[CAA_TAG_SECTION.start + tag_length:].decode('utf-8')
        return cls(name, class_, ttl, rdlength, flags, tag, value)

    def __repr__(self):
        return f'{self._name} {self.type_.name} {self._class.name} {timedelta(seconds=self._ttl)} ' \
               f'{str(bin(self.flags))[2:]} {self.tag} {self.value}'


class PTR(RR):
    _type = TYPE.PTR
    _ptrdname: DomainName

    def __init__(self, name: DomainName, class_: CLASS, ttl: int, rdlength: int, ptrdname: DomainName):
        super().__init__(name, self.type_, class_, ttl, rdlength)
        self._ptrdname = ptrdname

    @classmethod
    def from_bytes(cls, name: DomainName, payload: bytes, original: bytes) -> RR:
        class_ = CLASS.from_bytes(payload[RR_CLASS_SECTION])
        ttl = int.from_bytes(payload[RR_TTL_SECTION], 'big')
        rdlength = int.from_bytes(payload[RR_RDLENGTH_SECTION], 'big')
        rdata = payload[RR_RDATA_SECTION.start: RR_RDATA_SECTION.start + rdlength]
        ptrdname, length = DomainName.from_bytes(rdata, original)
        return cls(name, class_, ttl, rdlength, ptrdname)

    def __repr__(self):
        return f'{self._name} {self.type_.name} {self._class.name} {timedelta(seconds=self._ttl)} {self._ptrdname}'

    @property
    def ptrdname(self) -> DomainName:
        return self._ptrdname


type_to_RR = {
    TYPE.A: A,
    TYPE.NS: NS,
    TYPE.CNAME: CNAME,
    TYPE.MX: MX,
    TYPE.TXT: TXT,
    TYPE.AAAA: AAAA,
    TYPE.DNAME: DNAME,
    TYPE.SOA: SOA,
    TYPE.CAA: CAA,
    TYPE.PTR: PTR
}


def get_rr_type(payload: bytes) -> Type[RR]:
    try:
        type_ = TYPE.from_bytes(payload[RR_TYPE_SECTION])
    except ValueError:
        return RR
    return type_to_RR.get(type_, RR)
