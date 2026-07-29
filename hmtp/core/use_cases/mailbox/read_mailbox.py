from hmtp.core.entities.responses import ResponseTypes, failure, success


def read_mailbox_use_case(repo, config: dict, user: str, presented_token: str) -> dict:
    """Authenticated read access for the mailbox owner's devices. Content
    stays sealed: each device decrypts its own copy locally."""
    if user != config["address"].split("@")[0]:
        return failure(ResponseTypes.UNKNOWN_MAILBOX, "user", "unknown mailbox")
    token = config.get("read_token")
    if not token or presented_token != token:
        return failure(ResponseTypes.VERIFICATION_ERROR, "token", "invalid read token")
    boxes = {
        box: [row["payload"] for row in repo.messages_in(box)]
        for box in ("inbox", "requests")
    }
    return success(**boxes)
