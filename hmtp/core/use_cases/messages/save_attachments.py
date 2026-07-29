from cryptography.exceptions import InvalidTag

from hmtp.core.entities import crypto
from hmtp.core.entities.errors import PeerUnreachable, PermanentRejection
from hmtp.core.entities.message import blob_digest, safe_filename
from hmtp.core.entities.responses import ResponseTypes, failure, success
from hmtp.core.use_cases.messages.open_message import open_message
from hmtp.core.use_cases.messages.reply_message import find_single_message


def save_attachments_use_case(
    repo, config: dict, network, blob_store, target: str
) -> dict:
    """Decrypt the attachments of a stored message. Returns the plaintext
    files; writing them to disk is the caller's job."""
    row, error = find_single_message(repo, target)
    if error:
        return error
    msg = row["payload"]
    try:
        content = open_message(msg, config)
    except (InvalidTag, ValueError, KeyError) as err:
        return failure(ResponseTypes.VERIFICATION_ERROR, "message", str(err))
    refs = content.get("attachments", [])
    if not refs:
        return failure(ResponseTypes.RESOURCE_ERROR, "attachments", "no attachments")
    # The sealed references must match what the envelope announced, or the
    # sender told the server and the recipient two different stories.
    sealed_view = {(ref["hash"], ref["size"]) for ref in refs}
    visible_view = {(ref["hash"], ref["size"]) for ref in msg.get("attachments", [])}
    if sealed_view != visible_view:
        return failure(
            ResponseTypes.VERIFICATION_ERROR,
            "attachments",
            "attachment lists do not match",
        )
    files = []
    for ref in refs:
        try:
            digest = blob_digest(ref)
            blob = blob_store.read(digest)
            if blob is None:
                blob = network.fetch_blob(ref["url"])
            if not crypto.blob_matches(blob, ref, digest):
                return failure(
                    ResponseTypes.VERIFICATION_ERROR,
                    "attachments",
                    f"blob {ref['hash']} failed verification",
                )
            files.append(
                {
                    "name": safe_filename(ref["name"]),
                    "data": crypto.decrypt_blob(blob, ref["key"]),
                }
            )
        except (PeerUnreachable, PermanentRejection, InvalidTag, KeyError) as err:
            return failure(ResponseTypes.RESOURCE_ERROR, "attachments", str(err))
    return success(files=files)
