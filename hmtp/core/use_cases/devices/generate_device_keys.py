from hmtp.core.entities import crypto
from hmtp.core.entities.responses import success


def generate_device_keys_use_case() -> dict:
    """Generate a keypair ON the new device; only the public key travels."""
    private, public = crypto.new_encryption_keypair()
    return success(private_key=private, public_key=public)
