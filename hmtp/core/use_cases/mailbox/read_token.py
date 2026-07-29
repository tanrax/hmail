from hmtp.core.entities import crypto
from hmtp.core.entities.responses import success


def read_token_use_case(config_store) -> dict:
    """The mailbox read token, created on demand for pre-token configs."""
    cfg = config_store.load()
    if "read_token" not in cfg:
        cfg["read_token"] = crypto.url_token(24)
        config_store.save(cfg)
    return success(token=cfg["read_token"])
