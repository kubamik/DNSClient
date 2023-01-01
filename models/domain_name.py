from __future__ import annotations

from typing import List, Optional, Tuple

from models.constants.response_constants import POINTER_MASK, POINTER_OFFSET_MASK


class DomainName:
    _name: str
    _labels: List[str]

    def __init__(self, name: str):
        self._name = name
        self._labels = [label for label in name.split('.') if label != '']

        for label in self._labels:
            if len(label) > 63:
                raise ValueError("Label length must be less than 63")

    @property
    def name(self) -> str:
        return self._name

    @property
    def labels(self) -> List[str]:
        return self._labels

    def __bytes__(self):
        arr = bytearray()
        for label in self._labels:
            arr.extend(int.to_bytes(len(label), 1, 'big'))
            arr.extend(label.encode("ascii"))
        arr.extend(b'\x00')

        return bytes(arr)

    @classmethod
    def from_bytes(cls, payload: bytes, original: Optional[bytes] = None) -> Tuple[DomainName, int]:
        labels = []
        length = 0
        it = iter(payload)
        for n in it:
            if n == 0:
                length += 1
                break
            elif n & POINTER_MASK:
                offset = n * (1 << 8) + next(it)
                offset &= POINTER_OFFSET_MASK
                if original is None:
                    raise ValueError("Original payload not provided")
                dn, _ = DomainName.from_bytes(original[offset:], original)
                labels.extend(dn.labels)
                length += 2
                break
            else:
                label = ''.join(chr(next(it)) for _ in range(n))
                labels.append(label)
                length += n + 1
        return cls('.'.join(labels)), length

    def __len__(self):
        return (len(self._name) or -1) + 2

    def __str__(self):
        return self._name

    def __eq__(self, other: DomainName):
        if not isinstance(other, DomainName):
            return False
        return self._name == other._name
