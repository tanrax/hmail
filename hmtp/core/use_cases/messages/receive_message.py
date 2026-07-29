from cryptography.exceptions import InvalidSignature

from hmtp.core.entities import crypto
from hmtp.core.entities.constants import MAX_ATTACHMENTS, VERSION
from hmtp.core.entities.errors import PeerUnreachable, PermanentRejection
from hmtp.core.entities.message import message_id, plaintext_core
from hmtp.core.entities.responses import ResponseTypes, failure, success
from hmtp.core.use_cases.identity.key_continuity import check_key_continuity
from hmtp.core.use_cases.messages.mirror_attachments import mirror_attachments


def receive_message_use_case(
    repo,
    config: dict,
    network,
    blob_store,
    user: str,
    msg: dict,
    stamp: str | None = None,
) -> dict:
    """The receiving server's pipeline, in SPEC.md section 9 order."""
    if user != config["address"].split("@")[0]:
        return failure(ResponseTypes.UNKNOWN_MAILBOX, "user", "unknown mailbox")
    if not isinstance(msg, dict) or msg.get("v") != VERSION:
        return failure(
            ResponseTypes.UNSUPPORTED_VERSION, "v", "unsupported protocol version"
        )
    malformed = any(k not in msg for k in ("id", "from", "to", "date", "signature"))
    if malformed or ("sealed" in msg) == ("content" in msg):  # exactly one
        return failure(ResponseTypes.PARAMETERS_ERROR, "message", "malformed message")
    if len(msg.get("attachments", [])) > MAX_ATTACHMENTS:
        return failure(
            ResponseTypes.PARAMETERS_ERROR, "attachments", "too many attachments"
        )
    # The id hashes the plaintext: with sealed content only the recipient
    # can check it (and does, on read); plaintext content is checked here.
    if (
        "content" in msg
        and message_id(plaintext_core(msg, msg["content"])) != msg["id"]
    ):
        return failure(
            ResponseTypes.VERIFICATION_ERROR, "id", "id does not match content"
        )
    try:
        doc = network.fetch_discovery(msg["from"])
        crypto.verify_signature(msg, doc["signing_key"])
    except (PeerUnreachable, PermanentRejection):
        # The sender's keys are unreachable right now: ask them to retry.
        return failure(
            ResponseTypes.KEYS_UNREACHABLE, "from", "sender keys unreachable"
        )
    except (InvalidSignature, ValueError, KeyError):
        return failure(
            ResponseTypes.VERIFICATION_ERROR,
            "signature",
            "signature verification failed",
        )
    known = repo.is_contact(msg["from"])
    needs_stamp = config.get("postage_required") and not known
    if needs_stamp and not (stamp and repo.consume_stamp(stamp)):
        return failure(
            ResponseTypes.PAYMENT_REQUIRED,
            "stamp",
            "payment required",
            hint="resend with a stamp",
            realm=config["address"],
        )
    # Continuity: a sender whose key changed without a signed chain is
    # re-anchored by domain, so it must earn consent again.
    trusted = check_key_continuity(repo, msg["from"], doc)
    box = "inbox" if known and trusted else "requests"
    inserted = repo.store_message(msg, user, box)
    if not inserted:
        return {
            "type": ResponseTypes.DUPLICATE,
            "errors": [],
            "data": {"delivered": msg["id"], "mirrored": []},
        }
    # Mirror blobs only after consent: strangers cannot fill our disk.
    mirrored = mirror_attachments(msg, network, blob_store) if box == "inbox" else []
    return success(delivered=msg["id"], mirrored=mirrored, box=box)
