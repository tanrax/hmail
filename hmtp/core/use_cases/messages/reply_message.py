from cryptography.exceptions import InvalidTag

from hmtp.core.entities.responses import ResponseTypes, failure
from hmtp.core.use_cases.messages.open_message import open_message
from hmtp.core.use_cases.messages.send_message import send_message_use_case


def find_single_message(repo, target: str) -> tuple[dict | None, dict | None]:
    """Locate one stored message by (a prefix of) its id. Returns
    (row, error_response); exactly one of the two is set."""
    prefix = target.removeprefix("sha256:")
    rows = repo.find_messages(f"sha256:{prefix}")
    if not rows:
        return None, failure(
            ResponseTypes.RESOURCE_ERROR, "id", f"no message matches {target}"
        )
    if len(rows) > 1:
        return None, failure(
            ResponseTypes.PARAMETERS_ERROR,
            "id",
            "ambiguous id",
            matches=[row["id"] for row in rows],
        )
    return rows[0], None


def reply_message_use_case(
    repo, config: dict, network, blob_store, target: str, text: str
) -> dict:
    row, error = find_single_message(repo, target)
    if error:
        return error
    try:
        subject = open_message(row["payload"], config)["subject"]
    except (InvalidTag, ValueError, KeyError):
        subject = ""
    if subject and not subject.startswith("Re: "):
        subject = f"Re: {subject}"
    return send_message_use_case(
        repo,
        config,
        network,
        blob_store,
        row["sender"],
        text,
        subject=subject or None,
        in_reply_to=row["id"],
    )
