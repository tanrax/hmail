from hmtp.core.entities.responses import success


def register_device_use_case(config_store, name: str, public_key: str) -> dict:
    cfg = config_store.load()
    cfg.setdefault("devices", {})[name] = public_key
    config_store.save(cfg)
    return success(device=name)
