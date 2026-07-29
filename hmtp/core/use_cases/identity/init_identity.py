from hmtp.core.entities import crypto
from hmtp.core.entities.responses import success


def init_identity_use_case(config_store, address: str, base_url: str) -> dict:
    signing_private, signing_public = crypto.new_signing_keypair()
    encryption_private, encryption_public = crypto.new_encryption_keypair()
    cfg = {
        "address": address,
        "base_url": base_url.rstrip("/"),
        "private_key": signing_private,
        "public_key": signing_public,
        "rotations": [{"key": signing_public}],
        "encryption_private_key": encryption_private,
        "encryption_public_key": encryption_public,
        "read_token": crypto.url_token(24),
    }
    config_store.save(cfg)
    return success(address=address)
