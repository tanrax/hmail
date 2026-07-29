from hmtp.core.entities import crypto
from hmtp.core.entities.constants import MAX_ATTACHMENT
from hmtp.core.entities.errors import PeerUnreachable, PermanentRejection
from hmtp.core.entities.message import blob_digest


def mirror_attachments(msg: dict, network, blob_store) -> list[str]:
    """Download and store the blobs listed in the visible envelope so the
    recipient never reads from the sender's server. Returns mirrored hashes."""
    mirrored = []
    for ref in msg.get("attachments", []):
        try:
            if ref["size"] > MAX_ATTACHMENT:
                continue
            digest = blob_digest(ref)
            if not blob_store.has(digest):
                blob = network.fetch_blob(ref["url"])
                if not crypto.blob_matches(blob, ref, digest):
                    continue
                blob_store.write(digest, blob)
            mirrored.append(ref["hash"])
        except (PeerUnreachable, PermanentRejection, ValueError, KeyError, TypeError):
            continue
    return mirrored
