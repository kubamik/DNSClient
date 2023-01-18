import contextlib
import itertools
import select
import socket
from typing import Dict, List, Optional, Tuple, Iterator

from config import MAX_SENDING_WAIT_TIME_SECONDS, MAX_RECEIVING_WAIT_TIME_SECONDS, ROOT_SERVERS, \
    PREFERRED_ROOT_SERVER, ROOT_SERVER_NAME_SUFFIX
from models import QTYPE, QCLASS, DomainName, RCODE
from models.constants import PROTOCOL, ADDRESS_FAMILY, PORT, HEADER_ID_SECTION_LENGTH_BITS, TCP_PROTOCOL, \
    TCP_LENGTH_FIELD_SIZE, MAX_UDP_PAYLOAD_SIZE
from models.exceptions import MalformedDNSResponseException, NoRespondingServersException, \
    HostRetrievalException, DNSError, DNSNameError
from models.question import Question
from models.rrs import RR, NS, A, CNAME, DNAME, SOA
from request.request import Request, Query
from response.response import Response
from utils import check_tries, check_response, Authority


class DNSClient:
    sock: socket.socket
    rd: bool
    required_aa: bool
    seq: int = 0
    authorities: Dict[DomainName, Tuple[Dict[DomainName, Authority], Dict[DomainName, Authority]]]

    def __init__(self, rd: bool = True, required_aa: bool = False):
        self.rd = rd
        self.sock = socket.socket(ADDRESS_FAMILY, PROTOCOL)
        self.sock.settimeout(0.1)
        self.sock.setblocking(False)
        self.tries = {}
        self.authorities = {}
        self.required_aa = required_aa
        roots = {
            DomainName(PREFERRED_ROOT_SERVER + ROOT_SERVER_NAME_SUFFIX): Authority(
                DomainName(''), DomainName(PREFERRED_ROOT_SERVER + ROOT_SERVER_NAME_SUFFIX),
                ROOT_SERVERS[PREFERRED_ROOT_SERVER])
        }
        roots |= {
            DomainName(i + ROOT_SERVER_NAME_SUFFIX): Authority(
                DomainName(''), DomainName(i + ROOT_SERVER_NAME_SUFFIX), addr) for i, addr in ROOT_SERVERS.items()
            if i != PREFERRED_ROOT_SERVER
        }
        self.authorities[DomainName('')] = (roots, {})

    def __del__(self):
        self.sock.close()

    def retrieve(self, name: str, qtype: QTYPE = QTYPE.A, qclass: QCLASS = QCLASS.IN) -> Response:
        res = Resolver(self, name, qtype, qclass)
        return res.resolve()

    def update_authorities(self, authority: List[RR], additional: List[RR]):
        if not authority:
            return {}

        new_authorities = {}
        for rr in authority:
            if isinstance(rr, NS):
                authority = Authority.from_ns(rr)
                new_authorities[authority.nsdname] = authority
            elif isinstance(rr, SOA):
                authority = Authority.from_soa(rr)
                new_authorities[authority.nsdname] = authority
        for rr in additional:
            if isinstance(rr, A) and rr.name in new_authorities:
                new_authorities[rr.name].address = rr.address

        for name, auth in new_authorities.items():
            known, unknown = self.authorities.setdefault(auth.name, ({}, {}))
            if name in unknown and auth.address is not None:
                unknown.pop(name)
                known[name] = auth
            elif name not in known and name not in unknown:
                if auth.address is not None:
                    known[name] = auth
                else:
                    unknown[name] = auth
        return new_authorities


class Resolver:
    client: DNSClient
    tries: int
    sock: socket.socket
    hostname: str
    qtype: QTYPE
    qclass: QCLASS
    address_stack: List[Authority]

    def __init__(self, client: DNSClient, hostname: str, qtype: QTYPE = QTYPE.A, qclass: QCLASS = QCLASS.IN):
        self.client = client
        self.tries = 0
        self.hostname = hostname
        self.qtype = qtype
        self.qclass = qclass
        self.sock = socket.socket(ADDRESS_FAMILY, PROTOCOL)
        self.sock.settimeout(0.1)
        self.sock.setblocking(False)
        self.address_stack = []

    def __del__(self):
        self.sock.close()

    def resolve(self) -> Response:
        self.tries = 0
        return self.retrieve(self.hostname, self.qtype, self.qclass)

    def retrieve(self, hostname: str, qtype: QTYPE, qclass: QCLASS, previous_answers: List[RR] = None) -> Response:
        if not previous_answers:
            previous_answers = []
        question = Question(hostname, qtype, qclass)
        known_authorities_name = self.get_greatest_authority_name(DomainName(hostname))
        authorities = self.get_authorities(known_authorities_name)

        while True:
            address, authorities = self.get_next_authority(authorities, known_authorities_name)
            if not address:
                continue
            try:
                response = self.retrieve_from(address, question)
            except HostRetrievalException:
                continue
            except DNSError as e:
                if e.code is RCODE.NAME_ERROR:
                    raise DNSNameError(hostname)
                continue

            new_authorities = self.client.update_authorities(response.authority, response.additional).values()
            new_authorities = sorted(new_authorities, key=lambda x: x.address is not None)
            if response.answer and (response.header.aa or not self.client.required_aa):
                if qtype == QTYPE.ANY:
                    return response
                if self.check_for_answer(response, hostname, qtype, qclass):
                    response.add_previous_answer(previous_answers)
                    return response
                resp = self.check_for_name_alias(response, hostname, qtype, qclass, previous_answers)
                if resp:
                    return resp
            if response.header.aa:
                response.add_previous_answer(previous_answers)
                return response
            if response.authority:
                authorities = itertools.chain(new_authorities, authorities)

    def retrieve_from(self, address: str, question: Question) -> Optional[Response]:
        request = Query(self.client.seq, self.client.rd, [question])
        self.client.seq += 1
        self.client.seq %= 2 << HEADER_ID_SECTION_LENGTH_BITS
        host_tries = 0

        resp = None
        last_exc = None
        if len(request) <= MAX_UDP_PAYLOAD_SIZE:
            while resp is None and check_tries(self.tries, host_tries, last_exc):
                try:
                    self.send(address, request)
                    resp = self._receive(request)
                except (ConnectionError, TimeoutError, MalformedDNSResponseException) as e:
                    self.tries += 1
                    host_tries += 1
                    last_exc = e

        if resp and resp.header.tc or len(request) > MAX_UDP_PAYLOAD_SIZE:
            resp, _ = self.retrieve_via_tcp(request, address, host_tries)
        resp.validate()
        return resp

    def _receive(self, request: Request) -> Response:
        if select.select([self.sock], [], [], MAX_RECEIVING_WAIT_TIME_SECONDS)[0]:
            response, _ = self.sock.recvfrom(2048)
            if response:
                resp = Response(response)
                if check_response(request, resp):
                    return resp
                else:
                    raise MalformedDNSResponseException('Wrong response')
            else:
                raise ConnectionError('No response')
        else:
            raise TimeoutError()

    def retrieve_via_tcp(self, request: Request, address: str, host_tries: int) -> Tuple[Optional[Response], int]:
        last_exc = None
        while check_tries(self.tries, host_tries, last_exc):
            sock = socket.socket(ADDRESS_FAMILY, TCP_PROTOCOL)
            try:
                sock.connect((address, PORT))
                if select.select([], [sock], [], MAX_SENDING_WAIT_TIME_SECONDS)[1]:
                    req = bytes(request)
                    sock.sendall(len(req).to_bytes(TCP_LENGTH_FIELD_SIZE, 'big') + req)
                    sock.shutdown(socket.SHUT_WR)
                    request.mark_sent()
                    buf = b'initial'
                    resp = b''
                    while buf and (len(resp) < 2 or len(resp) != int.from_bytes(resp[:2], 'big') + 2) \
                            and select.select([sock], [], [], MAX_RECEIVING_WAIT_TIME_SECONDS)[0]:
                        buf = sock.recv(2048)
                        resp += buf
                    if resp:
                        resp = Response(resp[TCP_LENGTH_FIELD_SIZE:])
                        return resp, host_tries
                    else:
                        raise ConnectionError('No response')
                else:
                    raise TimeoutError()
            except (socket.error, MalformedDNSResponseException, ConnectionError, TimeoutError) as e:
                last_exc = e
            finally:
                with contextlib.suppress(Exception):
                    sock.shutdown(socket.SHUT_RDWR)
                sock.close()
            self.tries += 1
            host_tries += 1

    def send(self, address: str, request: Request):
        if select.select([], [self.sock], [], MAX_SENDING_WAIT_TIME_SECONDS)[1]:
            size = self.sock.sendto(bytes(request), (address, PORT))
            request.mark_sent()
            if not size:
                raise ConnectionError('Cannot send request')
        else:
            raise TimeoutError()

    def get_authorities(self, name: DomainName) -> Iterator[Authority]:
        return itertools.chain(*(d.values() for d in self.client.authorities[name]))

    def get_next_authority(self, authorities: Iterator[Authority], known_name) \
            -> Tuple[Optional[str], Iterator[Authority]]:
        try:
            authority = next(authorities)
        except StopIteration:
            if known_name == DomainName(''):
                return None, authorities
            known_authorities_name = self.get_greatest_authority_name(known_name.parent())
            authorities = self.get_authorities(known_authorities_name)
            return None, authorities

        if authority.address is None:
            try:
                authority_response = self.retrieve(authority.nsdname.name, QTYPE.A, QCLASS.IN)
                for rr in authority_response.answer:
                    if isinstance(rr, A):
                        authority.address = rr.address
                        break
                else:
                    self.client.authorities[authority.name][1].pop(authority.nsdname)
            except DNSNameError:
                self.client.authorities[authority.name][1].pop(authority.nsdname)
        return authority.address, authorities

    def get_greatest_authority_name(self, name: DomainName) -> DomainName:
        while name not in self.client.authorities or not self.client.authorities[name][0]:
            name = name.parent()
        return name

    @staticmethod
    def check_for_answer(response: Response, hostname: str, qtype: QTYPE, qclass: QCLASS) -> bool:
        for rr in response.answer:
            if rr.name.name == hostname and rr.type_ == qtype and rr.class_ == qclass:
                return True
        return False

    def check_for_name_alias(self, response: Response, hostname: str, qtype: QTYPE, qclass: QCLASS,
                             previous_answers: List[RR]) -> Optional[Response]:
        for rr in response.answer:
            if rr.name.name == hostname and isinstance(rr, CNAME):
                if self.check_for_answer(response, rr.cname.name, qtype, qclass):
                    response.add_previous_answer(previous_answers)
                    return response
                return self.retrieve(rr.cname.name, qtype, qclass, previous_answers + response.answer)
            elif rr.name.name == hostname and isinstance(rr, DNAME):
                new_hostname = hostname.replace(rr.name.name, rr.dname.name)
                if self.check_for_answer(response, new_hostname, qtype, qclass):
                    response.add_previous_answer(previous_answers)
                    return response
                return self.retrieve(new_hostname, qtype, qclass, previous_answers + response.answer)
        return None
