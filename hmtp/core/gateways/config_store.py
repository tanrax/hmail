"""Contract for the node's identity and settings (keys, address, devices)."""

from typing import Protocol


class ConfigStore(Protocol):
    def load(self) -> dict: ...

    def save(self, cfg: dict) -> None: ...
