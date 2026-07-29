# /// script
# requires-python = ">=3.11"
# dependencies = ["flask", "httpx", "cryptography", "waitress"]
# ///
"""HMTP (HTTP Mail Transfer Protocol): a minimal self-hosted mail node over HTTP.

One file, no SMTP.

Usage:
    hmtp.py init <address> <public-base-url>       create identity and database
    hmtp.py serve [port]                           run the node (default 8025)
    hmtp.py send <address> [-s <subject>] <text>   sign, encrypt and deliver
    hmtp.py reply <message-id> <text>              reply to a message (threaded)
    hmtp.py flush                                  retry queued deliveries
    hmtp.py list                                   show inbox and contact requests
    hmtp.py accept <address>                       accept a contact request
    hmtp.py rotate                                 replace signing and encryption keys
"""

import base64
import hashlib
import ipaddress
import json
import os
import socket
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from flask import Flask, jsonify, request
from waitress import serve as waitress_serve

HOME = Path(os.environ.get("HMTP_HOME", Path.home() / ".hmtp"))
INSECURE = os.environ.get("HMTP_INSECURE") == "1"  # plain HTTP, local tests only
HOST = os.environ.get("HMTP_HOST", "127.0.0.1")  # 0.0.0.0 inside containers
VERSION = 1  # wire protocol version, see SPEC.md
MAX_SIZE = 64_000
MAX_BACKOFF = 86_400  # retry at most once a day
# Anything that can go wrong while resolving, fetching or checking a peer.
PEER_ERRORS = (httpx.HTTPError, OSError, ValueError, KeyError, InvalidSignature)

app = Flask(__name__)


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(HOME / "hmtp.db")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS messages ("
        "id TEXT PRIMARY KEY, sender TEXT, recipient TEXT, date TEXT,"
        "payload TEXT, box TEXT,"  # box: 'inbox' or 'requests'
        "in_reply_to TEXT)"
    )
    conn.execute("CREATE TABLE IF NOT EXISTS contacts (address TEXT PRIMARY KEY)")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS outbox ("
        "id TEXT PRIMARY KEY, recipient TEXT, payload TEXT,"
        "attempts INTEGER, next_try REAL)"
    )
    return conn


def config() -> dict:
    return json.loads((HOME / "config.json").read_text())


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def canonical(payload: dict) -> bytes:
    """RFC 8785 (JCS) canonical form for HMTP's field names: sorted keys,
    no insignificant whitespace, minimal escaping, UTF-8 bytes."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def message_id(payload: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical(payload)).hexdigest()


def plaintext_core(msg: dict, content: dict) -> dict:
    """The message id hashes this: the visible envelope plus the plaintext
    content, before any sealing. Every copy of a message shares it, so
    thread references match across nodes and retries stay idempotent."""
    envelope = {k: msg[k] for k in ("from", "to", "date", "in_reply_to") if k in msg}
    return envelope | content


def guard_host(host: str) -> None:
    """Refuse to talk to private networks (SSRF guard)."""
    if INSECURE:
        return
    for info in socket.getaddrinfo(host, None):
        if not ipaddress.ip_address(info[4][0]).is_global:
            raise ValueError(f"{host} resolves to a private address")


def wellknown_url(address: str) -> str:
    user, host = address.split("@", 1)
    guard_host(host.split(":")[0])
    scheme = "http" if INSECURE else "https"
    return f"{scheme}://{host}/.well-known/hmtp/{user}"


def verify(msg: dict) -> None:
    """Check the signature against the signing key published on the sender's
    domain. The id hashes the plaintext, so when the content is sealed only
    the recipient can check it (and does, on read); for plaintext content
    the server checks it right here."""
    payload = {k: v for k, v in msg.items() if k != "signature"}
    if (
        "content" in msg
        and message_id(plaintext_core(msg, msg["content"])) != msg["id"]
    ):
        raise ValueError("id does not match content")
    doc = httpx.get(wellknown_url(msg["from"]), timeout=10).json()
    key = ed25519.Ed25519PublicKey.from_public_bytes(
        base64.b64decode(doc["signing_key"])
    )
    key.verify(base64.b64decode(msg["signature"]), canonical(payload))


def _sealing_key(shared: bytes, ephemeral_pub: bytes, recipient_pub: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=ephemeral_pub + recipient_pub,
    ).derive(shared)


def seal(text: str, recipient_key_b64: str) -> dict:
    """Encrypt the content (subject and body) to the recipient's X25519 key
    (sealed box): only the holder of the private key can read it, servers
    included."""
    recipient_pub = base64.b64decode(recipient_key_b64)
    recipient_key = x25519.X25519PublicKey.from_public_bytes(recipient_pub)
    ephemeral = x25519.X25519PrivateKey.generate()
    ephemeral_pub = ephemeral.public_key().public_bytes_raw()
    key = _sealing_key(ephemeral.exchange(recipient_key), ephemeral_pub, recipient_pub)
    nonce = os.urandom(12)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, text.encode(), None)
    return {
        "cipher": "x25519-chacha20poly1305",
        "ephemeral_key": b64(ephemeral_pub),
        "nonce": b64(nonce),
        "data": b64(ciphertext),
    }


def unseal(sealed: dict, cfg: dict) -> str:
    """Decrypt with the current encryption key, falling back to rotated-out
    ones so old mail stays readable after a key rotation."""
    keypairs = [
        (cfg["encryption_private_key"], cfg["encryption_public_key"]),
        *cfg.get("previous_encryption_keys", []),
    ]
    ephemeral_pub = base64.b64decode(sealed["ephemeral_key"])
    for private_b64, public_b64 in keypairs:
        private = x25519.X25519PrivateKey.from_private_bytes(
            base64.b64decode(private_b64)
        )
        shared = private.exchange(
            x25519.X25519PublicKey.from_public_bytes(ephemeral_pub)
        )
        key = _sealing_key(shared, ephemeral_pub, base64.b64decode(public_b64))
        try:
            return (
                ChaCha20Poly1305(key)
                .decrypt(
                    base64.b64decode(sealed["nonce"]),
                    base64.b64decode(sealed["data"]),
                    None,
                )
                .decode()
            )
        except InvalidTag:
            continue
    raise ValueError("no encryption key can decrypt this message")


def open_message(msg: dict, cfg: dict) -> dict:
    """Return the plaintext content of a stored message, checking that the
    id really is the hash of that plaintext."""
    if "sealed" in msg:
        content = json.loads(unseal(msg["sealed"], cfg))
    else:
        content = msg["content"]
    if message_id(plaintext_core(msg, content)) != msg["id"]:
        raise ValueError("id does not match content")
    return content


@app.get("/.well-known/hmtp/<user>")
def wellknown(user: str):
    cfg = config()
    if user != cfg["address"].split("@")[0]:
        return jsonify(error="unknown mailbox"), 404
    doc = {
        "address": cfg["address"],
        "inbox": f"{cfg['base_url']}/hmtp/inbox/{user}",
        "signing_key": cfg["public_key"],
    }
    if "encryption_public_key" in cfg:
        doc["encryption_key"] = cfg["encryption_public_key"]
    return jsonify(doc)


@app.post("/hmtp/inbox/<user>")
def inbox(user: str):
    cfg = config()
    if user != cfg["address"].split("@")[0]:
        return jsonify(error="unknown mailbox"), 404
    if request.content_length and request.content_length > MAX_SIZE:
        return jsonify(error="message too large"), 413
    msg = request.get_json(silent=True) or {}
    if msg.get("v") != VERSION:
        return jsonify(error="unsupported protocol version"), 400
    malformed = any(k not in msg for k in ("id", "from", "to", "date", "signature"))
    if malformed or ("sealed" in msg) == ("content" in msg):  # exactly one
        return jsonify(error="malformed message"), 400
    try:
        verify(msg)
    except (httpx.HTTPError, OSError):
        # The sender's keys are unreachable right now: ask them to retry.
        return jsonify(error="sender keys unreachable"), 503
    except (ValueError, KeyError, InvalidSignature):
        return jsonify(error="signature verification failed"), 401
    conn = db()
    known = conn.execute(
        "SELECT 1 FROM contacts WHERE address = ?", (msg["from"],)
    ).fetchone()
    box = "inbox" if known else "requests"
    inserted = conn.execute(
        "INSERT OR IGNORE INTO messages VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            msg["id"],
            msg["from"],
            user,
            msg["date"],
            json.dumps(msg),
            box,
            msg.get("in_reply_to"),
        ),
    ).rowcount
    conn.commit()
    return jsonify(delivered=msg["id"]), 201 if inserted else 200


def post_message(inbox_url: str, wire: dict) -> None:
    httpx.post(
        inbox_url,
        content=json.dumps(wire),
        headers={"Content-Type": "application/hmtp+json"},
        timeout=10,
    ).raise_for_status()


def deliver(recipient: str, wire: dict) -> None:
    doc = httpx.get(wellknown_url(recipient), timeout=10).json()
    post_message(doc["inbox"], wire)


def send(
    recipient: str,
    text: str,
    subject: str | None = None,
    in_reply_to: str | None = None,
) -> None:
    cfg = config()
    key = ed25519.Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(cfg["private_key"])
    )
    try:
        doc = httpx.get(wellknown_url(recipient), timeout=10).json()
    except PEER_ERRORS:
        doc = None
    # Subject and body travel together inside the sealed payload; the salt
    # keeps the visible id from confirming a guessed short plaintext.
    content = {"subject": subject or "", "body": text, "salt": b64(os.urandom(16))}
    payload = {
        "v": VERSION,
        "from": cfg["address"],
        "to": [recipient],
        "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    if in_reply_to:
        payload["in_reply_to"] = in_reply_to
    # The id hashes the plaintext, computed before sealing.
    payload["id"] = message_id(plaintext_core(payload, content))
    if doc and doc.get("encryption_key"):
        payload["sealed"] = seal(json.dumps(content), doc["encryption_key"])
    else:
        payload["content"] = content
    wire = payload | {"signature": b64(key.sign(canonical(payload)))}
    conn = db()
    # Writing to someone means their replies are welcome in your inbox.
    conn.execute("INSERT OR IGNORE INTO contacts VALUES (?)", (recipient,))
    # Release the write lock before network I/O: the recipient node may
    # share this database (e.g. when you write to your own address).
    conn.commit()
    try:
        if doc is None:
            raise ValueError("recipient node unreachable")
        post_message(doc["inbox"], wire)
        print(f"delivered {wire['id']}")
    except PEER_ERRORS as exc:
        conn.execute(
            "INSERT OR IGNORE INTO outbox VALUES (?, ?, ?, 0, 0)",
            (wire["id"], recipient, json.dumps(wire)),
        )
        conn.commit()
        print(f"queued ({exc})")


def flush() -> None:
    conn = db()
    now = time.time()
    rows = conn.execute(
        "SELECT id, recipient, payload, attempts FROM outbox WHERE next_try <= ?",
        (now,),
    ).fetchall()
    if not rows:
        print("nothing due")
        return
    for mid, recipient, payload, attempts in rows:
        try:
            deliver(recipient, json.loads(payload))
            conn.execute("DELETE FROM outbox WHERE id = ?", (mid,))
            print(f"delivered {mid}")
        except PEER_ERRORS:
            delay = min(300 * 2**attempts, MAX_BACKOFF)
            conn.execute(
                "UPDATE outbox SET attempts = attempts + 1, next_try = ? WHERE id = ?",
                (now + delay, mid),
            )
            print(f"still queued {mid} (attempt {attempts + 1}, next in {delay}s)")
    conn.commit()


def init(address: str, base_url: str) -> None:
    HOME.mkdir(parents=True, exist_ok=True)
    signing = ed25519.Ed25519PrivateKey.generate()
    encryption = x25519.X25519PrivateKey.generate()
    (HOME / "config.json").write_text(
        json.dumps(
            {
                "address": address,
                "base_url": base_url.rstrip("/"),
                "private_key": b64(signing.private_bytes_raw()),
                "public_key": b64(signing.public_key().public_bytes_raw()),
                "encryption_private_key": b64(encryption.private_bytes_raw()),
                "encryption_public_key": b64(
                    encryption.public_key().public_bytes_raw()
                ),
            },
            indent=2,
        )
    )
    db().close()
    print(f"identity created for {address} in {HOME}")


def list_messages() -> None:
    cfg = config()
    conn = db()
    for box in ("inbox", "requests"):
        print(f"== {box} ==")
        rows = conn.execute(
            "SELECT id, date, sender, payload, in_reply_to FROM messages"
            " WHERE box = ? ORDER BY date",
            (box,),
        ).fetchall()
        for mid, date, sender, payload, in_reply_to in rows:
            try:
                content = open_message(json.loads(payload), cfg)
                subject, body = content["subject"], content["body"]
            except (InvalidTag, ValueError, KeyError):
                subject, body = "", "[cannot decrypt or id does not match]"
            thread = f" reply-to {in_reply_to[:19]}" if in_reply_to else ""
            print(f"[{date}] {sender} {subject} ({mid[:19]}){thread}")
            print(f"  {body}")


def reply(target: str, text: str) -> None:
    prefix = target.removeprefix("sha256:")
    conn = db()
    rows = conn.execute(
        "SELECT id, sender, payload FROM messages WHERE id LIKE ?",
        (f"sha256:{prefix}%",),
    ).fetchall()
    if not rows:
        print(f"no message matches {target}")
        return
    if len(rows) > 1:
        print("ambiguous id, matches:")
        for row in rows:
            print(f"  {row[0]}")
        return
    mid, sender, payload = rows[0]
    try:
        subject = open_message(json.loads(payload), config())["subject"]
    except (InvalidTag, ValueError, KeyError):
        subject = ""
    if subject and not subject.startswith("Re: "):
        subject = f"Re: {subject}"
    send(sender, text, subject=subject or None, in_reply_to=mid)


def rotate() -> None:
    """Replace both keypairs. Receivers always fetch the current signing key,
    so the new one is trusted immediately and the old one is useless to a
    thief the moment this returns. Old encryption keys are kept so `list`
    can still decrypt mail sealed to them, and queued outgoing mail is
    re-signed (its id hashes the plaintext, so it is unaffected)."""
    cfg = config()
    signing = ed25519.Ed25519PrivateKey.generate()
    encryption = x25519.X25519PrivateKey.generate()
    cfg.setdefault("previous_encryption_keys", []).insert(
        0, [cfg["encryption_private_key"], cfg["encryption_public_key"]]
    )
    cfg["private_key"] = b64(signing.private_bytes_raw())
    cfg["public_key"] = b64(signing.public_key().public_bytes_raw())
    cfg["encryption_private_key"] = b64(encryption.private_bytes_raw())
    cfg["encryption_public_key"] = b64(encryption.public_key().public_bytes_raw())
    (HOME / "config.json").write_text(json.dumps(cfg, indent=2))
    conn = db()
    rows = conn.execute("SELECT id, payload FROM outbox").fetchall()
    for mid, payload in rows:
        wire = json.loads(payload)
        core = {k: v for k, v in wire.items() if k != "signature"}
        wire = core | {"signature": b64(signing.sign(canonical(core)))}
        conn.execute(
            "UPDATE outbox SET payload = ? WHERE id = ?", (json.dumps(wire), mid)
        )
    conn.commit()
    print(f"keys rotated, {len(rows)} queued message(s) re-signed")


def accept(address: str) -> None:
    conn = db()
    conn.execute("INSERT OR IGNORE INTO contacts VALUES (?)", (address,))
    conn.execute("UPDATE messages SET box = 'inbox' WHERE sender = ?", (address,))
    conn.commit()
    print(f"{address} accepted")


def main() -> None:
    match sys.argv[1:]:
        case ["init", address, base_url]:
            init(address, base_url)
        case ["serve", *rest]:
            waitress_serve(app, host=HOST, port=int(rest[0]) if rest else 8025)
        case ["send", recipient, "-s", subject, *words]:
            send(recipient, " ".join(words), subject=subject)
        case ["send", recipient, *words]:
            send(recipient, " ".join(words))
        case ["reply", target, *words]:
            reply(target, " ".join(words))
        case ["flush"]:
            flush()
        case ["list"]:
            list_messages()
        case ["accept", address]:
            accept(address)
        case ["rotate"]:
            rotate()
        case _:
            print(__doc__)


if __name__ == "__main__":
    main()
