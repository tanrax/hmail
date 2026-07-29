"""Peer network contract. Implementations translate transport errors into
the domain exceptions of core.entities.errors: PermanentRejection for
definitive refusals, PeerUnreachable for anything worth retrying."""

from typing import Protocol


class Network(Protocol):
    def fetch_discovery(self, address: str) -> dict:
        """GET the discovery document for an address (SPEC.md section 2)."""
        ...

    def post_message(
        self, inbox_url: str, wire: dict, stamp: str | None = None
    ) -> dict:
        """Deliver a message (SPEC.md section 8) and return the receipt."""
        ...

    def fetch_blob(self, url: str) -> bytes:
        """Download an attachment blob (SPEC.md section 7)."""
        ...
