import os
from datetime import UTC, datetime

from hmtp.core.entities import crypto
from hmtp.core.entities.constants import MAX_ATTACHMENT, MAX_ATTACHMENTS, VERSION
from hmtp.core.entities.errors import PeerUnreachable, PermanentRejection
from hmtp.core.entities.message import canonical, message_id, plaintext_core
from hmtp.core.entities.responses import ResponseTypes, failure, success


def send_message_use_case(
    repo,
    config: dict,
    network,
    blob_store,
    recipient: str,
    text: str,
    subject: str | None = None,
    in_reply_to: str | None = None,
    attachments: list[dict] | None = None,
    stamp: str | None = None,
) -> dict:
    """Sign, seal and deliver a message; queue it if the recipient's node is
    unreachable. Attachments arrive as [{"name": str, "data": bytes}]."""
    if attachments and len(attachments) > MAX_ATTACHMENTS:
        return failure(
            ResponseTypes.PARAMETERS_ERROR,
            "attachments",
            f"at most {MAX_ATTACHMENTS} attachments per message",
        )
    if attachments and any(len(a["data"]) > MAX_ATTACHMENT for a in attachments):
        return failure(
            ResponseTypes.PARAMETERS_ERROR,
            "attachments",
            f"attachments are capped at {MAX_ATTACHMENT} bytes",
        )
    try:
        doc = network.fetch_discovery(recipient)
    except (PeerUnreachable, PermanentRejection, ValueError, KeyError):
        doc = None
    # Subject and body travel together inside the sealed payload; the salt
    # keeps the visible id from confirming a guessed short plaintext.
    content = {
        "subject": subject or "",
        "body": text,
        "salt": crypto.b64(os.urandom(16)),
    }
    visible_refs = []
    if attachments:
        sealed_refs = []
        for attachment in attachments:
            blob, digest, key = crypto.encrypt_blob(attachment["data"])
            blob_store.write(digest, blob)
            sealed_refs.append(
                {
                    "name": attachment["name"],
                    "hash": f"sha256:{digest}",
                    "url": f"{config['base_url']}/hmtp/blob/{digest}",
                    "size": len(blob),
                    "key": key,
                }
            )
        content["attachments"] = sealed_refs
        # The envelope announces hash, url and size only: the recipient's
        # server can mirror blobs it cannot decrypt, and learns no names.
        visible_refs = [
            {k: ref[k] for k in ("hash", "url", "size")} for ref in sealed_refs
        ]
    payload = {
        "v": VERSION,
        "from": config["address"],
        "to": [recipient],
        "date": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    if in_reply_to:
        payload["in_reply_to"] = in_reply_to
    # The id hashes the plaintext, computed before sealing.
    payload["id"] = message_id(plaintext_core(payload, content))
    if visible_refs:
        payload["attachments"] = visible_refs
    if doc and doc.get("encryption_key"):
        payload["sealed"] = crypto.seal(
            canonical(content).decode(), doc["encryption_key"]
        )
        if doc.get("devices"):
            payload["sealed_devices"] = {
                name: crypto.seal(canonical(content).decode(), device_key)
                for name, device_key in doc["devices"].items()
            }
    else:
        payload["content"] = content
    wire = payload | {
        "signature": crypto.sign_bytes(canonical(payload), config["private_key"])
    }
    # Writing to someone means their replies are welcome in your inbox.
    repo.add_contact(recipient)
    try:
        if doc is None:
            raise PeerUnreachable("recipient node unreachable")
        receipt = network.post_message(doc["inbox"], wire, stamp)
        return success(delivered=wire["id"], mirrored=receipt.get("mirrored", []))
    except PermanentRejection as error:
        return failure(ResponseTypes.REJECTED, "delivery", str(error), id=wire["id"])
    except (PeerUnreachable, ValueError, KeyError) as error:
        repo.queue_message(wire, recipient, stamp)
        return success(queued=wire["id"], reason=str(error))
