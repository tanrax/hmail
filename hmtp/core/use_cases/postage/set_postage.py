from hmtp.core.entities.responses import success


def set_postage_use_case(config_store, enabled: bool) -> dict:
    cfg = config_store.load()
    cfg["postage_required"] = enabled
    config_store.save(cfg)
    return success(postage_required=enabled)
