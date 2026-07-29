from cryptography.exceptions import InvalidSignature

from hmtp.core.entities import crypto


def check_key_continuity(repo, address: str, doc: dict) -> bool:
    """TOFU pin of each sender's signing key. When the key changes, the
    published rotation chain must connect the pinned key to the current one
    (each hop signed by the previous key); a break means the identity was
    re-anchored by the domain, not by a signature."""
    current = doc["signing_key"]
    pinned = repo.pinned_key(address)
    if pinned is None:
        repo.pin_key(address, current)
        return True
    if pinned == current:
        return True
    chain = doc.get("rotations", [])
    keys = [entry.get("key") for entry in chain]
    if pinned not in keys or not chain or chain[-1].get("key") != current:
        return False
    try:
        start = keys.index(pinned)
        for prev, entry in zip(chain[start:], chain[start + 1 :]):
            crypto.verify_bytes(crypto.unb64(entry["key"]), entry["sig"], prev["key"])
    except (InvalidSignature, KeyError, ValueError):
        return False
    repo.pin_key(address, current)
    return True
