import ipaddress
import json
import socket

import httpx

from hmtp.core.entities.errors import PeerUnreachable, PermanentRejection


class HttpxNetwork:
    """httpx implementation of the Network gateway, with the SSRF guard.
    Transport failures become PeerUnreachable (retryable); any 4xx becomes
    PermanentRejection (SPEC.md section 8)."""

    def __init__(self, insecure: bool = False):
        # insecure = plain HTTP and no SSRF guard, for local tests only
        self.insecure = insecure

    def _guard_host(self, host: str) -> None:
        """Refuse to talk to private networks (SSRF guard)."""
        if self.insecure:
            return
        for info in socket.getaddrinfo(host, None):
            if not ipaddress.ip_address(info[4][0]).is_global:
                raise PeerUnreachable(f"{host} resolves to a private address")

    def _guard_url(self, url: str) -> None:
        self._guard_host(url.split("://", 1)[1].split("/", 1)[0].split(":")[0])

    def fetch_discovery(self, address: str) -> dict:
        user, host = address.split("@", 1)
        self._guard_host(host.split(":")[0])
        scheme = "http" if self.insecure else "https"
        url = f"{scheme}://{host}/.well-known/hmtp/{user}"
        try:
            response = httpx.get(url, timeout=10)
            return response.json()
        except (httpx.HTTPError, OSError, ValueError) as error:
            raise PeerUnreachable(str(error)) from error

    def post_message(
        self, inbox_url: str, wire: dict, stamp: str | None = None
    ) -> dict:
        self._guard_url(inbox_url)
        headers = {"Content-Type": "application/hmtp+json"}
        if stamp:
            headers["Authorization"] = f"HMTP-Stamp {stamp}"
        try:
            response = httpx.post(
                inbox_url, content=json.dumps(wire), headers=headers, timeout=10
            )
        except (httpx.HTTPError, OSError) as error:
            raise PeerUnreachable(str(error)) from error
        if 400 <= response.status_code < 500:
            raise PermanentRejection(f"{response.status_code} {response.text[:100]}")
        if response.status_code >= 500:
            raise PeerUnreachable(f"status {response.status_code}")
        try:
            return response.json()
        except ValueError:
            return {}

    def fetch_blob(self, url: str) -> bytes:
        self._guard_url(url)
        try:
            response = httpx.get(url, timeout=30)
        except (httpx.HTTPError, OSError) as error:
            raise PeerUnreachable(str(error)) from error
        if response.status_code != 200:
            raise PermanentRejection(f"status {response.status_code}")
        return response.content
