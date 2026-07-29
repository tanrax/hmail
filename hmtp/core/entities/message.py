"""Pure message logic: canonicalization, content addressing, envelopes.

Everything here is deterministic and free of I/O; SPEC.md sections 3-5.
"""

import hashlib
import json
import re


def canonical(payload: dict) -> bytes:
    """RFC 8785 (JCS) canonical form for HMTP's field names: sorted keys,
    no insignificant whitespace, minimal escaping, UTF-8 bytes."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def message_id(payload: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical(payload)).hexdigest()


def plaintext_core(msg: dict, content: dict) -> dict:
    """The message id hashes this: the visible envelope plus the plaintext
    content, before any sealing. Every copy of a message shares it, so
    thread references match across nodes and retries stay idempotent."""
    envelope = {k: msg[k] for k in ("from", "to", "date", "in_reply_to") if k in msg}
    return envelope | content


def blob_digest(ref: dict) -> str:
    """Validate and return the hex digest of an attachment reference
    (also guards the blob store against path traversal)."""
    digest = ref["hash"].removeprefix("sha256:")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("malformed attachment hash")
    return digest


def safe_filename(name: str) -> str:
    """An attachment name is untrusted input: strip any path components."""
    return name.replace("\\", "/").rsplit("/", 1)[-1] or "attachment"
