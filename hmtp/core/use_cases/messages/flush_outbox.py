import time

from hmtp.core.entities.constants import MAX_BACKOFF, RETRY_BASE
from hmtp.core.entities.errors import PeerUnreachable, PermanentRejection
from hmtp.core.entities.responses import success


def flush_outbox_use_case(repo, network) -> dict:
    """Retry queued deliveries with exponential backoff. Permanent
    rejections (4xx) are dropped: retrying them cannot succeed."""
    now = time.time()
    delivered, dropped, still_queued = [], [], []
    for entry in repo.due_outbox(now):
        try:
            doc = network.fetch_discovery(entry["recipient"])
            network.post_message(doc["inbox"], entry["payload"], entry["stamp"])
            repo.delete_outbox(entry["id"])
            delivered.append(entry["id"])
        except PermanentRejection as error:
            repo.delete_outbox(entry["id"])
            dropped.append({"id": entry["id"], "reason": str(error)})
        except (PeerUnreachable, ValueError, KeyError):
            delay = min(RETRY_BASE * 2 ** entry["attempts"], MAX_BACKOFF)
            repo.bump_outbox(entry["id"], now + delay)
            still_queued.append(
                {"id": entry["id"], "attempt": entry["attempts"] + 1, "next_in": delay}
            )
    return success(delivered=delivered, dropped=dropped, still_queued=still_queued)
