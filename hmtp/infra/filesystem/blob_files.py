from pathlib import Path


class FileBlobStore:
    """Encrypted attachment blobs as files named by their hex digest."""

    def __init__(self, home: Path):
        self.directory = home / "blobs"

    def _path(self, digest: str) -> Path:
        return self.directory / digest

    def has(self, digest: str) -> bool:
        return self._path(digest).exists()

    def read(self, digest: str) -> bytes | None:
        path = self._path(digest)
        return path.read_bytes() if path.exists() else None

    def write(self, digest: str, blob: bytes) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        self._path(digest).write_bytes(blob)
