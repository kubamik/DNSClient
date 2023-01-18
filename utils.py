from datetime import datetime, timedelta
from typing import Optional

from config import MAX_RETRIES, MAX_RETRIES_PER_HOST
from models import DomainName
from models.exceptions import RetrievalException, HostRetrievalException
from models.rrs import NS, SOA
from request import Request
from response import Response


def check_response(req: Request, resp: Response) -> bool:
    if resp.header.id != req.header.id:
        return False
    if resp.question != req.question:
        return False
    return True


def check_tries(tries: int, host_tries: int, exc: Exception) -> bool:
    if tries > MAX_RETRIES:
        raise RetrievalException(f"Max retries exceeded") from exc
    if host_tries > MAX_RETRIES_PER_HOST:
        raise HostRetrievalException(f"Max retries per host exceeded") from exc
    return True


class Authority:
    name: DomainName
    expiration: datetime
    nsdname: DomainName
    address: Optional[str]

    def __init__(self, name: DomainName, nsdname: DomainName, address: Optional[str] = None, ttl: Optional[int] = None):
        self.name = name
        if ttl is not None:
            self.expiration = datetime.now() + timedelta(seconds=ttl)
        else:
            self.expiration = datetime.max
        self.nsdname = nsdname
        self.address = address

    @classmethod
    def from_ns(cls, authority: NS, address: Optional[str] = None):
        return cls(authority.name, authority.nsdname, address, authority.ttl)

    @classmethod
    def from_soa(cls, soa: SOA, address: Optional[str] = None):
        return cls(soa.name, soa.mname, address, soa.ttl)

    def __repr__(self):
        return f"Authority({self.nsdname}, {self.address})"

    def __hash__(self):
        return hash(self.nsdname)

    def __eq__(self, other):
        if isinstance(other, str):
            return self.nsdname.name == other
        if isinstance(other, DomainName):
            return self.nsdname == other
        if isinstance(other, Authority):
            return self.nsdname == other.nsdname
        return False
