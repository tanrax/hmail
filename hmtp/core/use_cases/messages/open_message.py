import json

from hmtp.core.entities import crypto
from hmtp.core.entities.message import message_id, plaintext_core


def open_message(msg: dict, config: dict) -> dict:
    """Return the plaintext content of a stored message, checking that the
    id really is the hash of that plaintext. Raises ValueError on mismatch;
    callers translate, this helper never crosses a layer boundary."""
    if "sealed" in msg:
        content = json.loads(crypto.unseal(msg["sealed"], config))
    else:
        content = msg["content"]
    if message_id(plaintext_core(msg, content)) != msg["id"]:
        raise ValueError("id does not match content")
    return content
