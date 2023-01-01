import contextlib
import socket

import select
from typing import Dict, Tuple, List

from config import MAX_SENDING_WAIT_TIME_SECONDS, MAX_RECEIVING_WAIT_TIME_SECONDS, DNS_ADDRESS, MAX_RETRIES_PER_HOST, \
    MAX_RETRIES
from models import QTYPE, QCLASS
from models.constants import PROTOCOL, ADDRESS_FAMILY, PORT, HEADER_ID_SECTION_LENGTH_BITS, TCP_PROTOCOL, \
    TCP_LENGTH_FIELD_SIZE, MAX_UDP_PAYLOAD_SIZE
from models.exceptions import RetrievalException, HostRetrievalException, MalformedDNSResponseException
from models.question import Question
from request.request import Request, Query
from response.response import Response
from utils import check_tries, check_response


class DNSClient:
    sock: socket.socket
    rd: bool
    _seq = 0
    tries: Dict[int, List[int]] = {}

    def __init__(self, rd: bool = True):
        self.rd = rd
        self.sock = socket.socket(ADDRESS_FAMILY, PROTOCOL)
        self.sock.settimeout(0.1)
        self.sock.setblocking(False)

    def __del__(self):
        self.sock.close()

    def _receive(self, request: Request):
        recv, _, _ = select.select([self.sock], [], [], MAX_RECEIVING_WAIT_TIME_SECONDS)
        if recv:
            response, _ = self.sock.recvfrom(2048)
            if response:
                resp = Response(response)
                if check_response(request, resp):
                    return resp
        return None

    @staticmethod
    def _retrieve_via_tcp(request: Request, address: str, tries: int, host_tries: int):
        while check_tries(tries, host_tries):
            sock = socket.socket(ADDRESS_FAMILY, TCP_PROTOCOL)
            try:
                sock.connect((address, PORT))
                if select.select([], [sock], [], MAX_SENDING_WAIT_TIME_SECONDS)[1]:
                    req = bytes(request)
                    sock.sendall(len(req).to_bytes(TCP_LENGTH_FIELD_SIZE, 'big') + req)
                    request.mark_sent()
                    buf = b'initial'
                    resp = b''
                    while buf and select.select([sock], [], [], MAX_RECEIVING_WAIT_TIME_SECONDS)[0]:
                        buf = sock.recv(2048)
                        resp += buf
                    if resp:
                        resp = Response(resp[TCP_LENGTH_FIELD_SIZE:])
                        return resp, tries, host_tries

            except (socket.error, MalformedDNSResponseException):
                pass
            finally:
                with contextlib.suppress(Exception):
                    sock.shutdown(2)
                sock.close()
            tries += 1
            host_tries += 1

    def retrieve(self, hostnames: list, qtype: QTYPE = QTYPE.A, qclass: QCLASS = QCLASS.IN):
        questions = []
        for hostname in hostnames:
            questions.append(Question(hostname, qtype, qclass))

        request = Query(self._seq, self.rd, questions)
        self._seq += 1
        self._seq %= 2 << HEADER_ID_SECTION_LENGTH_BITS
        tries, host_tries = 0, 0

        resp = None
        if len(request) <= MAX_UDP_PAYLOAD_SIZE:
            while resp is None and check_tries(tries, host_tries):
                if self.send(DNS_ADDRESS, request):
                    resp = self._receive(request)
                if resp is None:
                    tries += 1
                    host_tries += 1

        if resp and resp.header.tc or len(request) > MAX_UDP_PAYLOAD_SIZE:
            resp, tries, host_tries = self._retrieve_via_tcp(request, DNS_ADDRESS, tries, host_tries)

        return resp

    def send(self, address: str, request: Request):
        _, wrt, _ = select.select([], [self.sock], [], MAX_SENDING_WAIT_TIME_SECONDS)
        if wrt:
            size = self.sock.sendto(bytes(request), (address, PORT))
            request.mark_sent()
            return bool(size)

        return False

    def recv(self):
        recv, _, _ = select.select([self.sock], [], [], MAX_RECEIVING_WAIT_TIME_SECONDS)
        if recv:
            return self.sock.recvfrom(2048)
        return None


if __name__ == '__main__':
    client = DNSClient()
    print(client.retrieve(['pwr.edu.pl'], QTYPE.TXT))
    # print(client.retrieve(['a.root-servers.net']))
    # print(client.retrieve(['b.root-servers.net']))
