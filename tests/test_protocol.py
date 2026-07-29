"""Protocol tests for the HMTP node.

No real network: httpx is patched inside the network gateway so every
request is routed straight to the Flask test client of the node that owns
the target host. Each node gets its own home directory, repository, blob
store and config under tmp_path; there are no globals to switch.
"""

import json
import os
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import x25519

from hmtp.core.entities import crypto
from hmtp.core.entities.constants import MAX_SIZE, VERSION
from hmtp.core.entities.message import canonical, message_id, plaintext_core
from hmtp.core.entities.responses import ResponseTypes
from hmtp.core.use_cases.devices.register_device import register_device_use_case
from hmtp.core.use_cases.identity.init_identity import init_identity_use_case
from hmtp.core.use_cases.identity.rotate_keys import rotate_keys_use_case
from hmtp.core.use_cases.mailbox.accept_contact import accept_contact_use_case
from hmtp.core.use_cases.messages.flush_outbox import flush_outbox_use_case
from hmtp.core.use_cases.messages.open_message import open_message
from hmtp.core.use_cases.messages.reply_message import reply_message_use_case
from hmtp.core.use_cases.messages.save_attachments import save_attachments_use_case
from hmtp.core.use_cases.messages.send_message import send_message_use_case
from hmtp.core.use_cases.postage.issue_stamp import issue_stamp_use_case
from hmtp.core.use_cases.postage.set_postage import set_postage_use_case
from hmtp.infra.api.flask.src.app import create_app
from hmtp.infra.database.sqlite_repo import SQLiteRepo
from hmtp.infra.filesystem.blob_files import FileBlobStore
from hmtp.infra.filesystem.config_json import JSONConfigStore
from hmtp.infra.gateways import httpx_network
from hmtp.infra.gateways.httpx_network import HttpxNetwork


class FakeResponse:
    def __init__(self, response):
        self.status_code = response.status_code
        self.content = response.get_data()
        self.text = self.content.decode("utf-8", errors="replace")
        self._json = response.get_json(silent=True)

    def json(self):
        if self._json is None:
            raise ValueError("not json")
        return self._json


class Node:
    """One HMTP identity with its own home directory and wiring."""

    def __init__(self, home, address):
        self.home = home
        self.address = address
        self.user, self.host = address.split("@", 1)
        self.repo = SQLiteRepo(home)
        self.config_store = JSONConfigStore(home)
        self.blobs = FileBlobStore(home)
        self.network = HttpxNetwork(insecure=True)
        init_identity_use_case(self.config_store, address, f"http://{self.host}")
        self.client = create_app(home, insecure=True).test_client()

    @property
    def config(self):
        return self.config_store.load()

    def send(self, recipient, text, **kwargs):
        return send_message_use_case(
            self.repo, self.config, self.network, self.blobs, recipient, text, **kwargs
        )

    def reply(self, target, text):
        return reply_message_use_case(
            self.repo, self.config, self.network, self.blobs, target, text
        )

    def accept(self, address):
        return accept_contact_use_case(self.repo, self.network, self.blobs, address)

    def stored_messages(self):
        return [
            (row["id"], row["box"], row["payload"])
            for row in self.repo.find_messages("sha256:")
        ]

    def open(self, msg):
        return open_message(msg, self.config)


@pytest.fixture()
def network(tmp_path, monkeypatch):
    """Two-node network with httpx routed through Flask test clients."""
    nodes = {}
    wires = []
    content_types = []

    def dispatch(url, method, body=None, headers=None):
        host, _, path = url.split("://", 1)[1].partition("/")
        target = nodes[host]  # KeyError = host down: a retryable failure
        if method == "get":
            return FakeResponse(target.client.get(f"/{path}"))
        headers = dict(headers or {})
        content_type = headers.pop("Content-Type", "application/json")
        return FakeResponse(
            target.client.post(
                f"/{path}", data=body, content_type=content_type, headers=headers
            )
        )

    monkeypatch.setattr(
        httpx_network.httpx, "get", lambda url, timeout=None: dispatch(url, "get")
    )

    def fake_post(url, content=None, headers=None, timeout=None):
        wires.append(json.loads(content))
        content_types.append(headers["Content-Type"])
        return dispatch(url, "post", content, headers)

    monkeypatch.setattr(httpx_network.httpx, "post", fake_post)

    def make(name):
        node = Node(tmp_path / name, f"{name}@{name}.example")
        nodes[node.host] = node
        return node

    return SimpleNamespace(
        make=make, nodes=nodes, wires=wires, content_types=content_types
    )


@pytest.fixture()
def ana(network):
    return network.make("ana")


@pytest.fixture()
def bob(network):
    return network.make("bob")


def post_to(node, wire, **kwargs):
    return node.client.post(f"/hmtp/inbox/{node.user}", json=wire, **kwargs)


def boxes_by_body(node):
    return {node.open(msg)["body"]: box for _, box, msg in node.stored_messages()}


def test_subject_and_body_travel_sealed(network, ana, bob):
    ana.send(bob.address, "the secret plan", subject="operation midnight")

    wire = network.wires[-1]
    assert "sealed" in wire
    assert "subject" not in wire
    assert "operation midnight" not in json.dumps(wire)
    assert "the secret plan" not in json.dumps(wire)


def test_recipient_reads_subject_and_body_after_unsealing(network, ana, bob):
    ana.send(bob.address, "the secret plan", subject="operation midnight")

    _, _, msg = bob.stored_messages()[0]
    content = bob.open(msg)
    assert content["subject"] == "operation midnight"
    assert content["body"] == "the secret plan"


def test_id_hashes_the_plaintext_not_the_ciphertext(network, ana, bob):
    ana.send(bob.address, "hello")

    mid, _, msg = bob.stored_messages()[0]
    content = bob.open(msg)
    assert message_id(plaintext_core(msg, content)) == mid
    envelope_with_ciphertext = {k: v for k, v in msg.items() if k != "signature"}
    assert message_id(envelope_with_ciphertext) != mid


def test_retries_are_idempotent(network, ana, bob):
    ana.send(bob.address, "hello")
    wire = network.wires[-1]

    retry = post_to(bob, wire)

    assert retry.status_code == 200  # delivered before, not inserted again
    assert len(bob.stored_messages()) == 1


def test_unknown_sender_lands_in_requests_until_accepted(network, ana, bob):
    ana.send(bob.address, "hi, you don't know me")
    assert bob.stored_messages()[0][1] == "requests"

    bob.accept(ana.address)

    assert bob.stored_messages()[0][1] == "inbox"


def test_writing_to_someone_welcomes_their_replies(network, ana, bob):
    ana.send(bob.address, "first contact")

    bob.send(ana.address, "answering back")

    assert ana.stored_messages()[0][1] == "inbox"


def test_reply_threads_by_id_and_prefixes_subject(network, ana, bob):
    ana.send(bob.address, "the secret plan", subject="operation midnight")
    parent_id = bob.stored_messages()[0][0]

    bob.reply(parent_id, "count me in")

    wire = network.wires[-1]
    assert wire["in_reply_to"] == parent_id
    _, _, msg = ana.stored_messages()[0]
    assert ana.open(msg)["subject"] == "Re: operation midnight"


def test_wire_declares_version_and_media_type(network, ana, bob):
    ana.send(bob.address, "hello")

    assert network.wires[-1]["v"] == VERSION
    assert network.content_types[-1] == "application/hmtp+json"


def test_unsupported_version_is_rejected(network, ana, bob):
    ana.send(bob.address, "hello")
    wire = dict(network.wires[-1])

    wire["v"] = 99

    assert post_to(bob, wire).status_code == 400


def test_canonical_form_is_sorted_compact_utf8():
    assert canonical({"b": 1, "a": "café"}) == '{"a":"café","b":1}'.encode()


def test_message_with_both_sealed_and_content_is_rejected(network, ana, bob):
    ana.send(bob.address, "hello")
    wire = dict(network.wires[-1])

    wire["content"] = {"subject": "", "body": "decoy", "salt": crypto.b64(b"y" * 16)}

    assert post_to(bob, wire).status_code == 400


def test_tampered_envelope_is_rejected(network, ana, bob):
    ana.send(bob.address, "hello")
    wire = dict(network.wires[-1])

    wire["date"] = "1999-12-31T23:59:59+00:00"

    assert post_to(bob, wire).status_code == 401


def test_lying_id_is_detected_by_the_recipient(network, ana, bob):
    # A malicious sender signs a well-formed message whose id is NOT the
    # hash of the sealed plaintext. The server cannot tell (it cannot read
    # the content), but the recipient must catch it when opening.
    bob_doc = ana.network.fetch_discovery(bob.address)
    content = {"subject": "", "body": "real text", "salt": crypto.b64(b"x" * 16)}
    payload = {
        "v": VERSION,
        "from": ana.address,
        "to": [bob.address],
        "date": "2026-07-29T10:00:00+00:00",
        "id": message_id({"body": "something else entirely"}),
        "sealed": crypto.seal(json.dumps(content), bob_doc["encryption_key"]),
    }
    wire = payload | {
        "signature": crypto.sign_bytes(canonical(payload), ana.config["private_key"])
    }

    accepted = post_to(bob, wire)
    assert accepted.status_code == 201  # the server has no way to know

    _, _, msg = bob.stored_messages()[0]
    with pytest.raises(ValueError, match="id does not match"):
        bob.open(msg)


def test_message_too_large_is_rejected(network, bob):
    response = bob.client.post(
        f"/hmtp/inbox/{bob.user}",
        data=b"x" * (MAX_SIZE + 1),
        content_type="application/json",
    )

    assert response.status_code == 413


def test_rotation_keeps_old_mail_readable(network, ana):
    ana.send(ana.address, "note to self", subject="before rotation")

    rotate_keys_use_case(ana.config_store, ana.repo)

    _, _, msg = ana.stored_messages()[0]
    assert ana.open(msg)["subject"] == "before rotation"


def test_rotation_chain_preserves_trust(network, ana, bob):
    bob.accept(ana.address)
    ana.send(bob.address, "before rotation")  # pins ana's key on bob

    rotate_keys_use_case(ana.config_store, ana.repo)
    ana.send(bob.address, "after rotation")

    assert boxes_by_body(bob) == {
        "before rotation": "inbox",
        "after rotation": "inbox",
    }


def test_reanchored_identity_is_demoted_to_requests(network, ana, bob):
    bob.accept(ana.address)
    ana.send(bob.address, "legit")

    # The domain re-anchors: brand-new keys, no signed chain to the old one.
    init_identity_use_case(ana.config_store, ana.address, f"http://{ana.host}")
    ana.send(bob.address, "who am I now?")

    assert boxes_by_body(bob)["who am I now?"] == "requests"

    bob.accept(ana.address)  # re-trust pins the new key
    ana.send(bob.address, "trusted again")
    assert boxes_by_body(bob)["trusted again"] == "inbox"


def test_stranger_needs_a_stamp_when_postage_is_on(network, ana, bob):
    set_postage_use_case(bob.config_store, True)

    rejected = ana.send(bob.address, "cold call")

    assert rejected["type"] == ResponseTypes.REJECTED
    assert bob.stored_messages() == []  # 402: dropped, not stored
    assert ana.repo.all_outbox() == []  # and not queued either

    token = issue_stamp_use_case(bob.repo)["data"]["stamp"]
    stamped = ana.send(bob.address, "cold call, stamped", stamp=token)
    assert stamped["type"] == ResponseTypes.SUCCESS
    assert len(bob.stored_messages()) == 1

    reused = ana.send(bob.address, "reusing the stamp", stamp=token)
    assert reused["type"] == ResponseTypes.REJECTED  # stamps are single-use
    assert len(bob.stored_messages()) == 1


def test_attachments_are_sealed_mirrored_and_recoverable(network, ana, bob):
    secret = os.urandom(1000)
    bob.accept(ana.address)  # known contact: mirror at delivery

    ana.send(
        bob.address,
        "see attachment",
        attachments=[{"name": "plan.pdf", "data": secret}],
    )

    wire = network.wires[-1]
    visible = wire["attachments"][0]
    assert "key" not in visible and "name" not in visible  # envelope leaks neither
    digest = visible["hash"].removeprefix("sha256:")
    assert bob.blobs.has(digest)  # mirrored at delivery

    saved = save_attachments_use_case(
        bob.repo, bob.config, bob.network, bob.blobs, wire["id"]
    )
    assert saved["data"]["files"] == [{"name": "plan.pdf", "data": secret}]


def test_stranger_attachments_mirror_only_after_accept(network, ana, bob):
    ana.send(
        bob.address,
        "hi stranger",
        attachments=[{"name": "cat.jpg", "data": b"x" * 100}],
    )

    digest = network.wires[-1]["attachments"][0]["hash"].removeprefix("sha256:")
    assert not bob.blobs.has(digest)  # deferred: no consent yet

    bob.accept(ana.address)

    assert bob.blobs.has(digest)


def test_attachment_ids_cover_the_attachment_references(network, ana, bob):
    ana.send(
        bob.address, "with file", attachments=[{"name": "doc.txt", "data": b"data"}]
    )

    _, _, msg = bob.stored_messages()[0]
    content = bob.open(msg)  # would raise if the id did not cover the refs
    assert content["attachments"][0]["name"] == "doc.txt"
    assert message_id(plaintext_core(msg, content)) == msg["id"]


def test_mailbox_endpoint_requires_the_read_token(network, ana, bob):
    ana.send(bob.address, "hello")
    token = bob.config["read_token"]

    denied = bob.client.get(
        f"/hmtp/mailbox/{bob.user}", headers={"Authorization": "Bearer wrong"}
    )
    assert denied.status_code == 401

    granted = bob.client.get(
        f"/hmtp/mailbox/{bob.user}", headers={"Authorization": f"Bearer {token}"}
    )
    assert granted.status_code == 200
    assert len(granted.get_json()["requests"]) == 1  # still sealed, box intact


def test_devices_get_their_own_sealed_copy(network, ana, bob):
    device = x25519.X25519PrivateKey.generate()
    register_device_use_case(
        bob.config_store, "laptop", crypto.b64(device.public_key().public_bytes_raw())
    )

    ana.send(bob.address, "for all my devices")

    wire = network.wires[-1]
    device_cfg = {
        "encryption_private_key": crypto.b64(device.private_bytes_raw()),
        "encryption_public_key": crypto.b64(device.public_key().public_bytes_raw()),
    }
    content = json.loads(crypto.unseal(wire["sealed_devices"]["laptop"], device_cfg))
    assert content["body"] == "for all my devices"
    _, _, msg = bob.stored_messages()[0]
    assert bob.open(msg)["body"] == "for all my devices"  # primary copy intact


def test_rejected_mail_is_dropped_not_retried(network, ana, bob):
    down = network.nodes.pop(bob.host)  # bob offline: the message gets queued
    ana.send(bob.address, "queued while down")
    entry = ana.repo.all_outbox()[0]
    wire = dict(entry["payload"])
    wire["date"] = "1999-12-31T23:59:59+00:00"  # breaks the signature: 401
    ana.repo.replace_outbox_payload(entry["id"], wire)

    network.nodes[bob.host] = down  # bob comes back and rejects permanently
    flush_outbox_use_case(ana.repo, ana.network)

    assert ana.repo.all_outbox() == []  # dropped, not requeued
    assert bob.stored_messages() == []


def test_queued_mail_is_delivered_on_flush(network, ana, bob):
    down = network.nodes.pop(bob.host)  # bob's node goes offline
    ana.send(bob.address, "are you there?")
    assert bob.stored_messages() == []
    assert len(ana.repo.all_outbox()) == 1

    network.nodes[bob.host] = down  # bob comes back
    flush_outbox_use_case(ana.repo, ana.network)

    assert bob.open(bob.stored_messages()[0][2])["body"] == "are you there?"
    assert ana.repo.all_outbox() == []
