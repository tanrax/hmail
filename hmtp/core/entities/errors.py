class PermanentRejection(Exception):
    """A 4xx from the receiver: retrying the same message cannot succeed."""


class PeerUnreachable(Exception):
    """The peer cannot be reached right now: retrying later may succeed."""
