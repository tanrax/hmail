"""Tests for the HMTP node.

No real network: httpx is patched so every request is routed straight to
the Flask test client of the node that owns the target host. Each node
gets its own home directory (keys and database) under tmp_path.
"""

import base64
import json
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

import hmtp


class FakeResponse:
    def __init__(self, response):
        self._response = response
        self.status_code = response.status_code

    def json(self):
        return self._response.get_json()

    def raise_for_status(self):
        if self.status_code >= 400:
            raise hmtp.httpx.HTTPError(f"status {self.status_code}")


class Node:
    """One HMTP identity with its own home directory."""

    def __init__(self, home, address):
        self.home = home
        self.address = address
        self.user, self.host = address.split("@", 1)
        self.run(hmtp.init, address, f"http://{self.host}")

    def run(self, fn, *args, **kwargs):
        hmtp.HOME = self.home
        return fn(*args, **kwargs)

    def rows(self, query, *params):
        hmtp.HOME = self.home
        return hmtp.db().execute(query, params).fetchall()

    def stored_messages(self):
        return [
            (mid, box, json.loads(payload))
            for mid, box, payload in self.rows(
                "SELECT id, box, payload FROM messages ORDER BY date"
            )
        ]

    def open(self, msg):
        return self.run(lambda: hmtp.open_message(msg, hmtp.config()))


@pytest.fixture()
def network(tmp_path, monkeypatch):
    """Two-node network with httpx routed through Flask test clients."""
    monkeypatch.setattr(hmtp, "INSECURE", True)
    nodes = {}
    client = hmtp.app.test_client()
    wires = []

    def dispatch(url, method, payload=None):
        host, _, path = url.split("://", 1)[1].partition("/")
        target = nodes[host]  # KeyError = host down, a PEER_ERRORS member
        caller_home = hmtp.HOME
        hmtp.HOME = target.home
        try:
            if method == "get":
                return FakeResponse(client.get(f"/{path}"))
            return FakeResponse(client.post(f"/{path}", json=payload))
        finally:
            hmtp.HOME = caller_home

    monkeypatch.setattr(
        hmtp.httpx, "get", lambda url, timeout=None: dispatch(url, "get")
    )

    def fake_post(url, json=None, timeout=None):
        wires.append(json)
        return dispatch(url, "post", json)

    monkeypatch.setattr(hmtp.httpx, "post", fake_post)

    def make(name):
        node = Node(tmp_path / name, f"{name}@{name}.example")
        nodes[node.host] = node
        return node

    return SimpleNamespace(make=make, nodes=nodes, wires=wires, client=client)


@pytest.fixture()
def ana(network):
    return network.make("ana")


@pytest.fixture()
def bob(network):
    return network.make("bob")


def post_to(network, node, wire):
    hmtp.HOME = node.home
    return network.client.post(f"/hmtp/inbox/{node.user}", json=wire)


def test_subject_and_body_travel_sealed(network, ana, bob):
    ana.run(hmtp.send, bob.address, "the secret plan", subject="operation midnight")

    wire = network.wires[-1]
    assert "sealed" in wire
    assert "subject" not in wire
    assert "operation midnight" not in json.dumps(wire)
    assert "the secret plan" not in json.dumps(wire)


def test_recipient_reads_subject_and_body_after_unsealing(network, ana, bob):
    ana.run(hmtp.send, bob.address, "the secret plan", subject="operation midnight")

    _, _, msg = bob.stored_messages()[0]
    content = bob.open(msg)
    assert content["subject"] == "operation midnight"
    assert content["body"] == "the secret plan"


def test_id_hashes_the_plaintext_not_the_ciphertext(network, ana, bob):
    ana.run(hmtp.send, bob.address, "hello")

    mid, _, msg = bob.stored_messages()[0]
    content = bob.open(msg)
    assert hmtp.message_id(hmtp.plaintext_core(msg, content)) == mid
    envelope_with_ciphertext = {k: v for k, v in msg.items() if k != "signature"}
    assert hmtp.message_id(envelope_with_ciphertext) != mid


def test_retries_are_idempotent(network, ana, bob):
    ana.run(hmtp.send, bob.address, "hello")
    wire = network.wires[-1]

    retry = post_to(network, bob, wire)

    assert retry.status_code == 200  # delivered before, not inserted again
    assert len(bob.stored_messages()) == 1


def test_unknown_sender_lands_in_requests_until_accepted(network, ana, bob):
    ana.run(hmtp.send, bob.address, "hi, you don't know me")
    assert bob.stored_messages()[0][1] == "requests"

    bob.run(hmtp.accept, ana.address)

    assert bob.stored_messages()[0][1] == "inbox"


def test_writing_to_someone_welcomes_their_replies(network, ana, bob):
    ana.run(hmtp.send, bob.address, "first contact")

    bob.run(hmtp.send, ana.address, "answering back")

    assert ana.stored_messages()[0][1] == "inbox"


def test_reply_threads_by_id_and_prefixes_subject(network, ana, bob):
    ana.run(hmtp.send, bob.address, "the secret plan", subject="operation midnight")
    parent_id = bob.stored_messages()[0][0]

    bob.run(hmtp.reply, parent_id, "count me in")

    wire = network.wires[-1]
    assert wire["in_reply_to"] == parent_id
    _, _, msg = ana.stored_messages()[0]
    assert ana.open(msg)["subject"] == "Re: operation midnight"


def test_tampered_envelope_is_rejected(network, ana, bob):
    ana.run(hmtp.send, bob.address, "hello")
    wire = dict(network.wires[-1])

    wire["date"] = "1999-12-31T23:59:59+00:00"

    assert post_to(network, bob, wire).status_code == 401


def test_lying_id_is_detected_by_the_recipient(network, ana, bob):
    # A malicious sender signs a well-formed message whose id is NOT the
    # hash of the sealed plaintext. The server cannot tell (it cannot read
    # the content), but the recipient must catch it when opening.
    bob_doc = ana.run(
        lambda: hmtp.httpx.get(hmtp.wellknown_url(bob.address), timeout=10).json()
    )
    cfg = ana.run(hmtp.config)
    key = ed25519.Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(cfg["private_key"])
    )
    content = {"subject": "", "body": "real text", "salt": hmtp.b64(b"x" * 16)}
    payload = {
        "from": ana.address,
        "to": [bob.address],
        "date": "2026-07-29T10:00:00+00:00",
        "id": hmtp.message_id({"body": "something else entirely"}),
        "sealed": hmtp.seal(json.dumps(content), bob_doc["encryption_key"]),
    }
    wire = payload | {"signature": hmtp.b64(key.sign(hmtp.canonical(payload)))}

    accepted = post_to(network, bob, wire)
    assert accepted.status_code == 201  # the server has no way to know

    _, _, msg = bob.stored_messages()[0]
    with pytest.raises(ValueError, match="id does not match"):
        bob.open(msg)


def test_message_too_large_is_rejected(network, bob):
    hmtp.HOME = bob.home
    response = network.client.post(
        f"/hmtp/inbox/{bob.user}",
        data=b"x" * (hmtp.MAX_SIZE + 1),
        content_type="application/json",
    )

    assert response.status_code == 413


def test_rotation_keeps_old_mail_readable(network, ana):
    ana.run(hmtp.send, ana.address, "note to self", subject="before rotation")

    ana.run(hmtp.rotate)

    _, _, msg = ana.stored_messages()[0]
    assert ana.open(msg)["subject"] == "before rotation"


def test_queued_mail_is_delivered_on_flush(network, ana, bob):
    down = network.nodes.pop(bob.host)  # bob's node goes offline
    ana.run(hmtp.send, bob.address, "are you there?")
    assert bob.stored_messages() == []
    assert len(ana.rows("SELECT id FROM outbox")) == 1

    network.nodes[bob.host] = down  # bob comes back
    ana.run(hmtp.flush)

    assert bob.open(bob.stored_messages()[0][2])["body"] == "are you there?"
    assert ana.rows("SELECT id FROM outbox") == []
