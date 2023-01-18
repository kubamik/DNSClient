from __future__ import annotations

from typing import List, Optional

from models import DomainName, QR
from models.constants import HEADER_LENGTH
from models.constants.rr_constants import RR_FIXED_LENGTH
from models.exceptions import MalformedDNSResponseException
from models.question import Question
from models.rrs import RR, get_rr_type
from response.header import ResponseHeader


class Response:
    _header: ResponseHeader
    _question: List[Question]
    _answer: List[RR]
    _authority: List[RR]
    _additional: List[RR]

    def __init__(self, payload: bytes):
        try:
            self._header = ResponseHeader(payload[:HEADER_LENGTH])
            self._question = []
            self._answer = []
            self._authority = []
            self._additional = []

            rest_payload = self._parse_question(payload[HEADER_LENGTH:])
            rest_payload = self._parse_answer(rest_payload, payload)
            rest_payload = self._parse_authority(rest_payload, payload)
            self._parse_additional(rest_payload, payload)
        except ValueError as e:
            raise MalformedDNSResponseException(f"Malformed DNS response") from e

    def _parse_question(self, payload: bytes) -> bytes:
        for _ in range(self._header.qdcount):
            question = Question.from_bytes(payload)
            self._question.append(question)
            payload = payload[len(question):]
        return payload

    @staticmethod
    def parse_rrs(payload: bytes, original: bytes, count: int, container: List[RR]) -> bytes:
        for _ in range(count):
            name, length = DomainName.from_bytes(payload, original)
            new_payload = payload[length:]
            type_ = get_rr_type(new_payload)
            rr = type_.from_bytes(name, new_payload, original)
            container.append(rr)
            payload = payload[length + RR_FIXED_LENGTH + rr.rdlength: ]

        return payload

    def _parse_answer(self, payload: bytes, original: bytes, ancount: Optional[int] = None) -> bytes:
        return self.parse_rrs(payload, original, ancount if ancount is not None else self._header.ancount, self._answer)

    def _parse_authority(self, payload: bytes, original: bytes, nscount: Optional[int] = None) -> bytes:
        return self.parse_rrs(payload, original, nscount if nscount is not None else self._header.nscount,
                              self._authority)

    def _parse_additional(self, payload: bytes, original: bytes, arcount: Optional[int] = None) -> bytes:
        return self.parse_rrs(payload, original, arcount if arcount is not None else self._header.arcount,
                              self._additional)

    def __repr__(self):
        return f"Response:\n\tQuestion:\n\t\t" + "\n\t\t".join(repr(q) for q in self._question) + \
               "\n\tAnswer:\n\t\t" + "\n\t\t".join(repr(a) for a in self._answer) + \
               "\n\tAuthority:\n\t\t" + "\n\t\t".join(repr(a) for a in self._authority) + \
               "\n\tAdditional:\n\t\t" + "\n\t\t".join(repr(a) for a in self._additional)

    def extend(self, other: Response):
        self._answer.extend(other.answer)
        self._authority.extend(other.authority)
        self._additional.extend(other.additional)
        self._header.extend(other.header)

    def add_previous_answer(self, answers: List[RR]):
        self._answer = answers + self._answer

    @property
    def header(self):
        return self._header

    @property
    def question(self):
        return self._question

    @property
    def answer(self):
        return self._answer

    @property
    def authority(self):
        return self._authority

    @property
    def additional(self):
        return self._additional

    def validate(self):
        self._header.validate()
        if self._header.qr != QR.RESPONSE:
            raise MalformedDNSResponseException("Response is not a response")

