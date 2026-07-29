from hmtp.core.entities import crypto
from hmtp.core.entities.responses import success


def issue_stamp_use_case(repo) -> dict:
    """A stamp is a single-use bearer token, distributed out of band."""
    token = crypto.url_token(18)
    repo.add_stamp(token)
    return success(stamp=token)
