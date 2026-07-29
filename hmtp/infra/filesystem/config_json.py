import json
from pathlib import Path


class JSONConfigStore:
    """The node's identity and settings, as config.json in its home."""

    def __init__(self, home: Path):
        self.path = home / "config.json"

    def load(self) -> dict:
        return json.loads(self.path.read_text())

    def save(self, cfg: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(cfg, indent=2))
