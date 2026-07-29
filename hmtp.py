# /// script
# requires-python = ">=3.11"
# dependencies = ["flask", "httpx", "cryptography", "waitress"]
# ///
"""HMTP (HTTP Mail Transfer Protocol): a minimal self-hosted mail node over HTTP.

One file, no SMTP.

Usage:
    hmtp.py init <address> <public-base-url>       create identity and database
    hmtp.py serve [port]                           run the node (default 8025)
    hmtp.py send <address> [-s <subject>] [-a <file>]... [--stamp <token>] <text>
    hmtp.py reply <message-id> <text>              reply to a message (threaded)
    hmtp.py attachments <message-id> [dir]         save and decrypt attachments
    hmtp.py flush                                  retry queued deliveries
    hmtp.py list                                   show inbox and contact requests
    hmtp.py accept <address>                       accept a contact request
    hmtp.py rotate                                 replace signing and encryption keys
    hmtp.py postage on|off                         require stamps from strangers
    hmtp.py stamp                                  issue a single-use postage stamp
    hmtp.py token                                  print the mailbox read token
    hmtp.py device keygen                          generate a key pair for a device
    hmtp.py device add <name> <public-key>         publish a device encryption key
"""

import base64
import hashlib
import ipaddress
import json
import os
import re
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
MAX_ATTACHMENT = 10_000_000  # per encrypted blob, in bytes
MAX_ATTACHMENTS = 4  # per message
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
        "attempts INTEGER, next_try REAL, stamp TEXT)"
    )
    # Last signing key seen per sender (TOFU pin for rotation continuity).
    conn.execute(
        "CREATE TABLE IF NOT EXISTS peers (address TEXT PRIMARY KEY, signing_key TEXT)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS stamps (token TEXT PRIMARY KEY, used INTEGER)"
    )
    try:  # pre-postage databases lack the stamp column
        conn.execute("ALTER TABLE outbox ADD COLUMN stamp TEXT")
    except sqlite3.OperationalError:
        pass
    return conn


def config() -> dict:
    return json.loads((HOME / "config.json").read_text())


def save_config(cfg: dict) -> None:
    (HOME / "config.json").write_text(json.dumps(cfg, indent=2))


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


def guard_url(url: str) -> None:
    guard_host(url.split("://", 1)[1].split("/", 1)[0].split(":")[0])


def wellknown_url(address: str) -> str:
    user, host = address.split("@", 1)
    guard_host(host.split(":")[0])
    scheme = "http" if INSECURE else "https"
    return f"{scheme}://{host}/.well-known/hmtp/{user}"


def verify(msg: dict) -> dict:
    """Check the signature against the signing key published on the sender's
    domain and return the fetched discovery document. The id hashes the
    plaintext, so when the content is sealed only the recipient can check it
    (and does, on read); for plaintext content the server checks it here."""
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
    return doc


def key_continuity(conn: sqlite3.Connection, address: str, doc: dict) -> bool:
    """TOFU pin of each sender's signing key. When the key changes, the
    published rotation chain must connect the pinned key to the current one
    (each hop signed by the previous key); a break means the identity was
    re-anchored by the domain, not by a signature."""
    current = doc["signing_key"]
    row = conn.execute(
        "SELECT signing_key FROM peers WHERE address = ?", (address,)
    ).fetchone()
    if row is None:
        conn.execute("INSERT INTO peers VALUES (?, ?)", (address, current))
        return True
    pinned = row[0]
    if pinned == current:
        return True
    chain = doc.get("rotations", [])
    keys = [entry.get("key") for entry in chain]
    if pinned not in keys or not chain or chain[-1].get("key") != current:
        return False
    try:
        start = keys.index(pinned)
        for prev, entry in zip(chain[start:], chain[start + 1 :]):
            ed25519.Ed25519PublicKey.from_public_bytes(
                base64.b64decode(prev["key"])
            ).verify(base64.b64decode(entry["sig"]), base64.b64decode(entry["key"]))
    except (InvalidSignature, KeyError, ValueError):
        return False
    conn.execute(
        "UPDATE peers SET signing_key = ? WHERE address = ?", (current, address)
    )
    return True


def _sealing_key(shared: bytes, ephemeral_pub: bytes, recipient_pub: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=ephemeral_pub + recipient_pub,
    ).derive(shared)


def seal(text: str, recipient_key_b64: str) -> dict:
    """Encrypt the content (subject, body, attachment keys) to an X25519 key
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


def blob_digest(ref: dict) -> str:
    """Validate and return the hex digest of an attachment reference
    (also guards the blob store against path traversal)."""
    digest = ref["hash"].removeprefix("sha256:")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("malformed attachment hash")
    return digest


def seal_attachment(path_str: str, base_url: str) -> tuple[dict, dict]:
    """Encrypt a file with a fresh single-use key, store the opaque blob for
    serving, and return (sealed reference, visible reference)."""
    path = Path(path_str)
    data = path.read_bytes()
    if len(data) > MAX_ATTACHMENT:
        raise ValueError(f"{path.name} exceeds {MAX_ATTACHMENT} bytes")
    key = os.urandom(32)
    nonce = os.urandom(12)
    blob = nonce + ChaCha20Poly1305(key).encrypt(nonce, data, None)
    digest = hashlib.sha256(blob).hexdigest()
    (HOME / "blobs").mkdir(parents=True, exist_ok=True)
    (HOME / "blobs" / digest).write_bytes(blob)
    sealed_ref = {
        "name": path.name,
        "hash": f"sha256:{digest}",
        "url": f"{base_url}/hmtp/blob/{digest}",
        "size": len(blob),
        "key": b64(key),
    }
    visible_ref = {k: sealed_ref[k] for k in ("hash", "url", "size")}
    return sealed_ref, visible_ref


def fetch_blob(ref: dict) -> bytes:
    """Return an attachment blob, from the local mirror or the origin,
    verifying size and hash either way."""
    digest = blob_digest(ref)
    local = HOME / "blobs" / digest
    if local.exists():
        blob = local.read_bytes()
    else:
        guard_url(ref["url"])
        blob = httpx.get(ref["url"], timeout=30).content
    if len(blob) != ref["size"] or hashlib.sha256(blob).hexdigest() != digest:
        raise ValueError(f"blob {ref['hash']} failed verification")
    return blob


def mirror_attachments(msg: dict) -> list[str]:
    """Download and store the blobs listed in the visible envelope so the
    recipient never reads from the sender's server. Returns mirrored hashes."""
    mirrored = []
    for ref in msg.get("attachments", []):
        try:
            if ref["size"] > MAX_ATTACHMENT:
                continue
            digest = blob_digest(ref)
            target = HOME / "blobs" / digest
            if not target.exists():
                (HOME / "blobs").mkdir(parents=True, exist_ok=True)
                target.write_bytes(fetch_blob(ref))
            mirrored.append(ref["hash"])
        except PEER_ERRORS:
            continue
    return mirrored


@app.get("/.well-known/hmtp/<user>")
def wellknown(user: str):
    cfg = config()
    if user != cfg["address"].split("@")[0]:
        return jsonify(error="unknown mailbox"), 404
    doc = {
        "address": cfg["address"],
        "inbox": f"{cfg['base_url']}/hmtp/inbox/{user}",
        "signing_key": cfg["public_key"],
        "rotations": cfg.get("rotations") or [{"key": cfg["public_key"]}],
    }
    if "encryption_public_key" in cfg:
        doc["encryption_key"] = cfg["encryption_public_key"]
    if cfg.get("devices"):
        doc["devices"] = cfg["devices"]
    return jsonify(doc)


@app.get("/hmtp/blob/<digest>")
def blob(digest: str):
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        return jsonify(error="malformed blob id"), 400
    path = HOME / "blobs" / digest
    if not path.exists():
        return jsonify(error="unknown blob"), 404
    return path.read_bytes(), 200, {"Content-Type": "application/octet-stream"}


@app.get("/hmtp/mailbox/<user>")
def mailbox(user: str):
    """Authenticated read access for the mailbox owner's devices. Content
    stays sealed: each device decrypts its own copy locally."""
    cfg = config()
    if user != cfg["address"].split("@")[0]:
        return jsonify(error="unknown mailbox"), 404
    presented = request.headers.get("Authorization", "")
    if not cfg.get("read_token") or presented != f"Bearer {cfg['read_token']}":
        return jsonify(error="invalid read token"), 401
    conn = db()
    boxes = {}
    for box in ("inbox", "requests"):
        boxes[box] = [
            json.loads(payload)
            for (payload,) in conn.execute(
                "SELECT payload FROM messages WHERE box = ? ORDER BY date", (box,)
            )
        ]
    return jsonify(boxes)


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
    if len(msg.get("attachments", [])) > MAX_ATTACHMENTS:
        return jsonify(error="too many attachments"), 400
    try:
        doc = verify(msg)
    except (httpx.HTTPError, OSError):
        # The sender's keys are unreachable right now: ask them to retry.
        return jsonify(error="sender keys unreachable"), 503
    except (ValueError, KeyError, InvalidSignature):
        return jsonify(error="signature verification failed"), 401
    conn = db()
    known = conn.execute(
        "SELECT 1 FROM contacts WHERE address = ?", (msg["from"],)
    ).fetchone()
    if cfg.get("postage_required") and not known:
        auth = request.headers.get("Authorization", "")
        token = (
            auth.removeprefix("HMTP-Stamp ").strip()
            if auth.startswith("HMTP-Stamp ")
            else ""
        )
        fresh = conn.execute(
            "SELECT 1 FROM stamps WHERE token = ? AND used = 0", (token,)
        ).fetchone()
        if not fresh:
            return (
                jsonify(error="payment required", hint="resend with a stamp"),
                402,
                {"WWW-Authenticate": f'HMTP-Stamp realm="{cfg["address"]}"'},
            )
        conn.execute("UPDATE stamps SET used = 1 WHERE token = ?", (token,))
    # Continuity: a sender whose key changed without a signed chain is
    # re-anchored by domain, so it must earn consent again.
    trusted = key_continuity(conn, msg["from"], doc)
    box = "inbox" if known and trusted else "requests"
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
    # Mirror blobs only after consent: strangers cannot fill our disk.
    mirrored = mirror_attachments(msg) if inserted and box == "inbox" else []
    return jsonify(delivered=msg["id"], mirrored=mirrored), 201 if inserted else 200


class PermanentRejection(Exception):
    """A 4xx from the receiver: retrying the same message cannot succeed."""


def post_message(inbox_url: str, wire: dict, stamp: str | None = None) -> dict:
    headers = {"Content-Type": "application/hmtp+json"}
    if stamp:
        headers["Authorization"] = f"HMTP-Stamp {stamp}"
    response = httpx.post(
        inbox_url, content=json.dumps(wire), headers=headers, timeout=10
    )
    if 400 <= response.status_code < 500:
        raise PermanentRejection(f"{response.status_code} {response.text[:100]}")
    response.raise_for_status()
    return response.json()


def deliver(recipient: str, wire: dict, stamp: str | None = None) -> dict:
    doc = httpx.get(wellknown_url(recipient), timeout=10).json()
    return post_message(doc["inbox"], wire, stamp)


def send(
    recipient: str,
    text: str,
    subject: str | None = None,
    in_reply_to: str | None = None,
    attachments: list[str] | None = None,
    stamp: str | None = None,
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
    visible_refs = []
    if attachments:
        if len(attachments) > MAX_ATTACHMENTS:
            print(f"at most {MAX_ATTACHMENTS} attachments per message")
            return
        refs = [seal_attachment(path, cfg["base_url"]) for path in attachments]
        content["attachments"] = [sealed_ref for sealed_ref, _ in refs]
        visible_refs = [visible_ref for _, visible_ref in refs]
    payload = {
        "v": VERSION,
        "from": cfg["address"],
        "to": [recipient],
        "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    if in_reply_to:
        payload["in_reply_to"] = in_reply_to
    # The id hashes the plaintext, computed before sealing. The visible
    # attachment list (no names, no keys) rides outside the core so the
    # recipient's server can mirror blobs it cannot decrypt.
    payload["id"] = message_id(plaintext_core(payload, content))
    if visible_refs:
        payload["attachments"] = visible_refs
    if doc and doc.get("encryption_key"):
        payload["sealed"] = seal(json.dumps(content), doc["encryption_key"])
        if doc.get("devices"):
            payload["sealed_devices"] = {
                name: seal(json.dumps(content), device_key)
                for name, device_key in doc["devices"].items()
            }
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
        receipt = post_message(doc["inbox"], wire, stamp)
        print(f"delivered {wire['id']}")
        if receipt.get("mirrored"):
            print(f"attachments mirrored by recipient: {len(receipt['mirrored'])}")
    except PermanentRejection as exc:
        print(f"rejected, not retrying ({exc})")
    except PEER_ERRORS as exc:
        conn.execute(
            "INSERT OR IGNORE INTO outbox VALUES (?, ?, ?, 0, 0, ?)",
            (wire["id"], recipient, json.dumps(wire), stamp),
        )
        conn.commit()
        print(f"queued ({exc})")


def flush() -> None:
    conn = db()
    now = time.time()
    rows = conn.execute(
        "SELECT id, recipient, payload, attempts, stamp FROM outbox"
        " WHERE next_try <= ?",
        (now,),
    ).fetchall()
    if not rows:
        print("nothing due")
        return
    for mid, recipient, payload, attempts, stamp in rows:
        try:
            deliver(recipient, json.loads(payload), stamp)
            conn.execute("DELETE FROM outbox WHERE id = ?", (mid,))
            print(f"delivered {mid}")
        except PermanentRejection as exc:
            conn.execute("DELETE FROM outbox WHERE id = ?", (mid,))
            print(f"dropped {mid}, rejected ({exc})")
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
    public = b64(signing.public_key().public_bytes_raw())
    save_config(
        {
            "address": address,
            "base_url": base_url.rstrip("/"),
            "private_key": b64(signing.private_bytes_raw()),
            "public_key": public,
            "rotations": [{"key": public}],
            "encryption_private_key": b64(encryption.private_bytes_raw()),
            "encryption_public_key": b64(encryption.public_key().public_bytes_raw()),
            "read_token": base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip("="),
        }
    )
    db().close()
    print(f"identity created for {address} in {HOME}")


def message_row(target: str, columns: str):
    """Find one stored message by (a prefix of) its id, or explain why not."""
    prefix = target.removeprefix("sha256:")
    conn = db()
    rows = conn.execute(
        f"SELECT {columns} FROM messages WHERE id LIKE ?", (f"sha256:{prefix}%",)
    ).fetchall()
    if not rows:
        print(f"no message matches {target}")
        return None
    if len(rows) > 1:
        print("ambiguous id, matches:")
        for row in rows:
            print(f"  {row[0]}")
        return None
    return rows[0]


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
                names = [ref["name"] for ref in content.get("attachments", [])]
                if names:
                    body += f" [{len(names)} attachment(s): {', '.join(names)}]"
            except (InvalidTag, ValueError, KeyError):
                subject, body = "", "[cannot decrypt or id does not match]"
            thread = f" reply-to {in_reply_to[:19]}" if in_reply_to else ""
            print(f"[{date}] {sender} {subject} ({mid[:19]}){thread}")
            print(f"  {body}")


def reply(target: str, text: str) -> None:
    row = message_row(target, "id, sender, payload")
    if row is None:
        return
    mid, sender, payload = row
    try:
        subject = open_message(json.loads(payload), config())["subject"]
    except (InvalidTag, ValueError, KeyError):
        subject = ""
    if subject and not subject.startswith("Re: "):
        subject = f"Re: {subject}"
    send(sender, text, subject=subject or None, in_reply_to=mid)


def save_attachments(target: str, directory: str = ".") -> None:
    row = message_row(target, "id, payload")
    if row is None:
        return
    msg = json.loads(row[1])
    content = open_message(msg, config())
    refs = content.get("attachments", [])
    if not refs:
        print("no attachments")
        return
    # The sealed references must match what the envelope announced, or the
    # sender is telling the server and the recipient two different stories.
    sealed_view = {(ref["hash"], ref["size"]) for ref in refs}
    visible_view = {(ref["hash"], ref["size"]) for ref in msg.get("attachments", [])}
    if sealed_view != visible_view:
        print("attachment lists do not match, refusing")
        return
    for ref in refs:
        blob = fetch_blob(ref)
        data = ChaCha20Poly1305(base64.b64decode(ref["key"])).decrypt(
            blob[:12], blob[12:], None
        )
        name = Path(ref["name"]).name or "attachment"
        destination = Path(directory) / name
        counter = 1
        while destination.exists():
            destination = Path(directory) / f"{counter}-{name}"
            counter += 1
        destination.write_bytes(data)
        print(f"saved {destination} ({len(data)} bytes)")


def rotate() -> None:
    """Replace both keypairs and extend the rotation chain: the outgoing
    signing key signs the new one, so anyone who pinned the old key can
    verify the handover. Old encryption keys are kept so `list` can still
    decrypt mail sealed to them, and queued outgoing mail is re-signed
    (its id hashes the plaintext, so it is unaffected)."""
    cfg = config()
    old_signing = ed25519.Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(cfg["private_key"])
    )
    signing = ed25519.Ed25519PrivateKey.generate()
    encryption = x25519.X25519PrivateKey.generate()
    new_public_bytes = signing.public_key().public_bytes_raw()
    cfg.setdefault("rotations", [{"key": cfg["public_key"]}]).append(
        {"key": b64(new_public_bytes), "sig": b64(old_signing.sign(new_public_bytes))}
    )
    cfg.setdefault("previous_encryption_keys", []).insert(
        0, [cfg["encryption_private_key"], cfg["encryption_public_key"]]
    )
    cfg["private_key"] = b64(signing.private_bytes_raw())
    cfg["public_key"] = b64(new_public_bytes)
    cfg["encryption_private_key"] = b64(encryption.private_bytes_raw())
    cfg["encryption_public_key"] = b64(encryption.public_key().public_bytes_raw())
    save_config(cfg)
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
    # Accepting also re-trusts the sender's key: forget the pin so the next
    # delivery pins whatever the domain publishes now.
    conn.execute("DELETE FROM peers WHERE address = ?", (address,))
    conn.commit()
    # Consent granted: mirror the attachments that delivery deferred.
    for (payload,) in conn.execute(
        "SELECT payload FROM messages WHERE sender = ?", (address,)
    ).fetchall():
        mirror_attachments(json.loads(payload))
    print(f"{address} accepted")


def postage(setting: str) -> None:
    cfg = config()
    cfg["postage_required"] = setting == "on"
    save_config(cfg)
    print(f"postage for strangers: {setting}")


def issue_stamp() -> None:
    token = base64.urlsafe_b64encode(os.urandom(18)).decode().rstrip("=")
    conn = db()
    conn.execute("INSERT INTO stamps VALUES (?, 0)", (token,))
    conn.commit()
    print(token)


def read_token() -> None:
    cfg = config()
    if "read_token" not in cfg:
        cfg["read_token"] = (
            base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip("=")
        )
        save_config(cfg)
    print(cfg["read_token"])


def device_keygen() -> None:
    """Generate a keypair ON the new device; only the public key travels."""
    private = x25519.X25519PrivateKey.generate()
    print(f"private (keep on the device): {b64(private.private_bytes_raw())}")
    print(
        f"public  (register with 'device add'): "
        f"{b64(private.public_key().public_bytes_raw())}"
    )


def device_add(name: str, public_key: str) -> None:
    cfg = config()
    cfg.setdefault("devices", {})[name] = public_key
    save_config(cfg)
    print(f"device {name} published")


def parse_send(rest: list[str]) -> dict:
    options = {"subject": None, "stamp": None, "attachments": []}
    words = []
    args = iter(rest)
    for arg in args:
        if arg == "-s":
            options["subject"] = next(args, "")
        elif arg == "-a":
            options["attachments"].append(next(args, ""))
        elif arg == "--stamp":
            options["stamp"] = next(args, "")
        else:
            words.append(arg)
    options["text"] = " ".join(words)
    options["attachments"] = options["attachments"] or None
    return options


def main() -> None:
    match sys.argv[1:]:
        case ["init", address, base_url]:
            init(address, base_url)
        case ["serve", *rest]:
            waitress_serve(app, host=HOST, port=int(rest[0]) if rest else 8025)
        case ["send", recipient, *rest]:
            options = parse_send(rest)
            send(
                recipient,
                options["text"],
                subject=options["subject"],
                attachments=options["attachments"],
                stamp=options["stamp"],
            )
        case ["reply", target, *words]:
            reply(target, " ".join(words))
        case ["attachments", target, *rest]:
            save_attachments(target, rest[0] if rest else ".")
        case ["flush"]:
            flush()
        case ["list"]:
            list_messages()
        case ["accept", address]:
            accept(address)
        case ["rotate"]:
            rotate()
        case ["postage", ("on" | "off") as setting]:
            postage(setting)
        case ["stamp"]:
            issue_stamp()
        case ["token"]:
            read_token()
        case ["device", "keygen"]:
            device_keygen()
        case ["device", "add", name, public_key]:
            device_add(name, public_key)
        case _:
            print(__doc__)


if __name__ == "__main__":
    main()
