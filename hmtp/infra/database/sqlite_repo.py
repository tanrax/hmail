import json
import sqlite3
from pathlib import Path


class SQLiteRepo:
    """SQLite implementation of the Repository gateway. One file per node;
    every write commits immediately so concurrent processes (the server,
    the CLI, the flush sidecar) never hold the write lock across I/O."""

    def __init__(self, home: Path):
        home.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(home / "hmtp.db")
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS messages ("
            "id TEXT PRIMARY KEY, sender TEXT, recipient TEXT, date TEXT,"
            "payload TEXT, box TEXT,"  # box: 'inbox' or 'requests'
            "in_reply_to TEXT)"
        )
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS contacts (address TEXT PRIMARY KEY)"
        )
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS outbox ("
            "id TEXT PRIMARY KEY, recipient TEXT, payload TEXT,"
            "attempts INTEGER, next_try REAL, stamp TEXT)"
        )
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS peers ("
            "address TEXT PRIMARY KEY, signing_key TEXT)"
        )
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS stamps (token TEXT PRIMARY KEY, used INTEGER)"
        )
        try:  # pre-postage databases lack the stamp column
            self.connection.execute("ALTER TABLE outbox ADD COLUMN stamp TEXT")
        except sqlite3.OperationalError:
            pass
        self.connection.commit()

    def _message_row(self, row) -> dict:
        return {
            "id": row["id"],
            "date": row["date"],
            "sender": row["sender"],
            "payload": json.loads(row["payload"]),
            "in_reply_to": row["in_reply_to"],
            "box": row["box"],
        }

    # Messages
    def store_message(self, msg: dict, recipient: str, box: str) -> bool:
        inserted = self.connection.execute(
            "INSERT OR IGNORE INTO messages VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                msg["id"],
                msg["from"],
                recipient,
                msg["date"],
                json.dumps(msg),
                box,
                msg.get("in_reply_to"),
            ),
        ).rowcount
        self.connection.commit()
        return bool(inserted)

    def messages_in(self, box: str) -> list[dict]:
        rows = self.connection.execute(
            "SELECT * FROM messages WHERE box = ? ORDER BY date", (box,)
        ).fetchall()
        return [self._message_row(row) for row in rows]

    def find_messages(self, id_prefix: str) -> list[dict]:
        rows = self.connection.execute(
            "SELECT * FROM messages WHERE id LIKE ?", (f"{id_prefix}%",)
        ).fetchall()
        return [self._message_row(row) for row in rows]

    def move_sender_to_inbox(self, sender: str) -> None:
        self.connection.execute(
            "UPDATE messages SET box = 'inbox' WHERE sender = ?", (sender,)
        )
        self.connection.commit()

    def messages_from(self, sender: str) -> list[dict]:
        rows = self.connection.execute(
            "SELECT * FROM messages WHERE sender = ?", (sender,)
        ).fetchall()
        return [self._message_row(row) for row in rows]

    # Contacts
    def is_contact(self, address: str) -> bool:
        row = self.connection.execute(
            "SELECT 1 FROM contacts WHERE address = ?", (address,)
        ).fetchone()
        return row is not None

    def add_contact(self, address: str) -> None:
        self.connection.execute("INSERT OR IGNORE INTO contacts VALUES (?)", (address,))
        self.connection.commit()

    # Outbox
    def queue_message(self, wire: dict, recipient: str, stamp: str | None) -> None:
        self.connection.execute(
            "INSERT OR IGNORE INTO outbox VALUES (?, ?, ?, 0, 0, ?)",
            (wire["id"], recipient, json.dumps(wire), stamp),
        )
        self.connection.commit()

    def _outbox_row(self, row) -> dict:
        return {
            "id": row["id"],
            "recipient": row["recipient"],
            "payload": json.loads(row["payload"]),
            "attempts": row["attempts"],
            "stamp": row["stamp"],
        }

    def due_outbox(self, now: float) -> list[dict]:
        rows = self.connection.execute(
            "SELECT * FROM outbox WHERE next_try <= ?", (now,)
        ).fetchall()
        return [self._outbox_row(row) for row in rows]

    def all_outbox(self) -> list[dict]:
        rows = self.connection.execute("SELECT * FROM outbox").fetchall()
        return [self._outbox_row(row) for row in rows]

    def delete_outbox(self, message_id: str) -> None:
        self.connection.execute("DELETE FROM outbox WHERE id = ?", (message_id,))
        self.connection.commit()

    def bump_outbox(self, message_id: str, next_try: float) -> None:
        self.connection.execute(
            "UPDATE outbox SET attempts = attempts + 1, next_try = ? WHERE id = ?",
            (next_try, message_id),
        )
        self.connection.commit()

    def replace_outbox_payload(self, message_id: str, wire: dict) -> None:
        self.connection.execute(
            "UPDATE outbox SET payload = ? WHERE id = ?",
            (json.dumps(wire), message_id),
        )
        self.connection.commit()

    # Peers
    def pinned_key(self, address: str) -> str | None:
        row = self.connection.execute(
            "SELECT signing_key FROM peers WHERE address = ?", (address,)
        ).fetchone()
        return row["signing_key"] if row else None

    def pin_key(self, address: str, signing_key: str) -> None:
        self.connection.execute(
            "INSERT INTO peers VALUES (?, ?)"
            " ON CONFLICT(address) DO UPDATE SET signing_key = excluded.signing_key",
            (address, signing_key),
        )
        self.connection.commit()

    def unpin_key(self, address: str) -> None:
        self.connection.execute("DELETE FROM peers WHERE address = ?", (address,))
        self.connection.commit()

    # Stamps
    def add_stamp(self, token: str) -> None:
        self.connection.execute("INSERT INTO stamps VALUES (?, 0)", (token,))
        self.connection.commit()

    def consume_stamp(self, token: str) -> bool:
        used = self.connection.execute(
            "UPDATE stamps SET used = 1 WHERE token = ? AND used = 0", (token,)
        ).rowcount
        self.connection.commit()
        return bool(used)
