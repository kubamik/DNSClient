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
    def __init__(self, message: str, tries: int):
        super().__init__(message)
        self.tries = tries


class DNSError(Exception):
    def __init__(self, message: str):
        super().__init__(message)