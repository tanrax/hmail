"""Local storage contract for encrypted attachment blobs."""

from typing import Protocol


class BlobStore(Protocol):
    def has(self, digest: str) -> bool: ...

    def read(self, digest: str) -> bytes | None: ...

    def write(self, digest: str, blob: bytes) -> None: ...
