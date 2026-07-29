from hmtp.core.entities.responses import ResponseTypes, failure, success


def get_discovery_use_case(config: dict, user: str) -> dict:
    """The discovery document for a mailbox (SPEC.md section 2)."""
    if user != config["address"].split("@")[0]:
        return failure(ResponseTypes.UNKNOWN_MAILBOX, "user", "unknown mailbox")
    doc = {
        "address": config["address"],
        "inbox": f"{config['base_url']}/hmtp/inbox/{user}",
        "signing_key": config["public_key"],
        "rotations": config.get("rotations") or [{"key": config["public_key"]}],
    }
    if "encryption_public_key" in config:
        doc["encryption_key"] = config["encryption_public_key"]
    if config.get("devices"):
        doc["devices"] = config["devices"]
    return success(document=doc)
