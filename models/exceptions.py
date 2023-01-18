from models import RCODE


class AlreadySentException(Exception):
    def __init__(self):
        super().__init__('cannot edit properties of sent request')


class MalformedDNSResponseException(Exception):
    def __init__(self, message: str):
        super().__init__(message)


class RetrievalException(Exception):
    def __init__(self, message: str):
        super().__init__(message)


class HostRetrievalException(Exception):
    def __init__(self, message: str):
        super().__init__(message)


class DNSError(Exception):
    code: RCODE
    aa: bool

    def __init__(self, message: str, code: RCODE, aa: bool):
        super().__init__(message)
        self.code = code
        self.aa = aa


class NoRespondingServersException(Exception):
    def __init__(self):
        super().__init__('none of the servers responded')


class DNSNameError(Exception):
    def __init__(self, hostname: str):
        super().__init__('no such name ' + hostname)
