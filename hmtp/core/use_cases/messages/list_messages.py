from cryptography.exceptions import InvalidTag

from hmtp.core.entities.responses import success
from hmtp.core.use_cases.messages.open_message import open_message


def list_messages_use_case(repo, config: dict) -> dict:
    """Both boxes with decrypted content, ready for any UI to render."""
    boxes = {}
    for box in ("inbox", "requests"):
        entries = []
        for row in repo.messages_in(box):
            entry = {
                "id": row["id"],
                "date": row["date"],
                "sender": row["sender"],
                "in_reply_to": row["in_reply_to"],
            }
            try:
                content = open_message(row["payload"], config)
                entry["subject"] = content["subject"]
                entry["body"] = content["body"]
                entry["attachments"] = [
                    ref["name"] for ref in content.get("attachments", [])
                ]
            except (InvalidTag, ValueError, KeyError):
                entry["subject"] = ""
                entry["body"] = "[cannot decrypt or id does not match]"
                entry["attachments"] = []
            entries.append(entry)
        boxes[box] = entries
    return success(**boxes)
