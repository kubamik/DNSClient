from abc import ABC
from typing import List

from models import OPCODE
from models.constants import HEADER_LENGTH
from models.exceptions import AlreadySentException
from models.rrs import RR
from .header import RequestHeader
from models.question import Question


class Request(ABC):
    _type: OPCODE = NotImplemented
    _header: RequestHeader
    _question: List[Question]
    _answer: List[RR]
    _sent = False

    def __init__(self, id_, rd, questions: List[Question], answers: List[RR]):
        self._header = RequestHeader.Builder().rd(rd).id(id_).opcode(self._type).\
            qdcount(len(questions)).ancount(len(answers)).build()
        self._question = questions
        self._answer = answers

    @property
    def header(self) -> RequestHeader:
        return self._header

    @property
    def id(self) -> int:
        return self._header.id

    @id.setter
    def id(self, id_: int):
        self._header.id = id_

    @property
    def rd(self) -> bool:
        return self._header.rd

    @rd.setter
    def rd(self, rd: bool):
        self._header.rd = rd

    @property
    def question(self) -> List[Question]:
        return self._question

    @property
    def answers(self) -> List[RR]:
        return self._answer

    @property
    def sent(self) -> bool:
        return self._sent

    def mark_sent(self):
        self._sent = True

    def __bytes__(self):
        arr = bytearray()
        arr.extend(bytes(self._header))

        for question in self._question:
            arr.extend(bytes(question))

        for answer in self._answer:
            arr.extend(bytes(answer))

        return bytes(arr)

    def __len__(self):
        return HEADER_LENGTH + sum(len(q) for q in self._question) + sum(len(a) for a in self._answer)


class Query(Request):
    _type: OPCODE = OPCODE.QUERY

    def __init__(self, id_: int, rd: bool, question: List[Question]):
        super().__init__(id_, rd, question, [])

    @Request.question.setter
    def question(self, question: List[Question]):
        if self._sent:
            raise AlreadySentException()
        self._question = question
        self._header.qdcount = len(question)
