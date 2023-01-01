from config import MAX_RETRIES, MAX_RETRIES_PER_HOST
from models.exceptions import RetrievalException, HostRetrievalException
from request import Request
from response import Response


def check_response(req: Request, resp: Response) -> bool:
    if resp.header.id != req.header.id:
        return False
    if resp.question != req.question:
        return False
    return True


def check_tries(tries: int, host_tries: int) -> bool:
    if tries > MAX_RETRIES:
        raise RetrievalException(f"Max retries exceeded")
    if host_tries > MAX_RETRIES_PER_HOST:
        raise HostRetrievalException(f"Max retries per host exceeded", tries)
    return True
