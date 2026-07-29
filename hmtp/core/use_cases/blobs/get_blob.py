import re

from hmtp.core.entities.responses import ResponseTypes, failure, success


def get_blob_use_case(blob_store, digest: str) -> dict:
    """Serve an opaque encrypted blob by its content address."""
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        return failure(ResponseTypes.PARAMETERS_ERROR, "digest", "malformed blob id")
    blob = blob_store.read(digest)
    if blob is None:
        return failure(ResponseTypes.RESOURCE_ERROR, "digest", "unknown blob")
    return success(blob=blob)
