from pathlib import Path

from flask import Flask, jsonify, request

from hmtp.core.entities.constants import MAX_SIZE
from hmtp.core.entities.responses import ResponseTypes
from hmtp.core.use_cases.blobs.get_blob import get_blob_use_case
from hmtp.core.use_cases.discovery.get_discovery import get_discovery_use_case
from hmtp.core.use_cases.mailbox.read_mailbox import read_mailbox_use_case
from hmtp.core.use_cases.messages.receive_message import receive_message_use_case
from hmtp.infra import settings
from hmtp.infra.database.sqlite_repo import SQLiteRepo
from hmtp.infra.filesystem.blob_files import FileBlobStore
from hmtp.infra.filesystem.config_json import JSONConfigStore
from hmtp.infra.gateways.httpx_network import HttpxNetwork

# The HTTP layer's only opinions: which status code each response type
# maps to. Everything else is the use cases' business.
STATUS_BY_TYPE = {
    ResponseTypes.SUCCESS: 200,
    ResponseTypes.DUPLICATE: 200,
    ResponseTypes.PARAMETERS_ERROR: 400,
    ResponseTypes.UNSUPPORTED_VERSION: 400,
    ResponseTypes.VERIFICATION_ERROR: 401,
    ResponseTypes.PAYMENT_REQUIRED: 402,
    ResponseTypes.UNKNOWN_MAILBOX: 404,
    ResponseTypes.TOO_LARGE: 413,
    ResponseTypes.RESOURCE_ERROR: 404,
    ResponseTypes.KEYS_UNREACHABLE: 503,
    ResponseTypes.SYSTEM_ERROR: 500,
}


def create_app(home: Path | None = None, insecure: bool | None = None) -> Flask:
    home = home if home is not None else settings.HOME
    insecure = insecure if insecure is not None else settings.INSECURE
    app = Flask(__name__)

    def repo() -> SQLiteRepo:
        return SQLiteRepo(home)

    def config() -> dict:
        return JSONConfigStore(home).load()

    def problem(result: dict, status: int | None = None):
        payload = {"error": result["errors"][0]["message"]} if result["errors"] else {}
        payload.update(result["data"])
        return jsonify(payload), status or STATUS_BY_TYPE[result["type"]]

    @app.get("/.well-known/hmtp/<user>")
    def wellknown(user: str):
        result = get_discovery_use_case(config(), user)
        if result["type"] != ResponseTypes.SUCCESS:
            return problem(result)
        return jsonify(result["data"]["document"])

    @app.get("/hmtp/blob/<digest>")
    def blob(digest: str):
        result = get_blob_use_case(FileBlobStore(home), digest)
        if result["type"] != ResponseTypes.SUCCESS:
            return problem(result)
        return (
            result["data"]["blob"],
            200,
            {"Content-Type": "application/octet-stream"},
        )

    @app.get("/hmtp/mailbox/<user>")
    def mailbox(user: str):
        presented = request.headers.get("Authorization", "").removeprefix("Bearer ")
        result = read_mailbox_use_case(repo(), config(), user, presented)
        if result["type"] != ResponseTypes.SUCCESS:
            return problem(result)
        return jsonify(result["data"])

    @app.post("/hmtp/inbox/<user>")
    def inbox(user: str):
        if request.content_length and request.content_length > MAX_SIZE:
            return jsonify(error="message too large"), 413
        msg = request.get_json(silent=True) or {}
        auth = request.headers.get("Authorization", "")
        stamp = (
            auth.removeprefix("HMTP-Stamp ").strip()
            if auth.startswith("HMTP-Stamp ")
            else None
        )
        result = receive_message_use_case(
            repo(),
            config(),
            HttpxNetwork(insecure=insecure),
            FileBlobStore(home),
            user,
            msg,
            stamp,
        )
        if result["type"] == ResponseTypes.SUCCESS:
            return jsonify(result["data"]), 201
        if result["type"] == ResponseTypes.DUPLICATE:
            return jsonify(result["data"]), 200
        if result["type"] == ResponseTypes.PAYMENT_REQUIRED:
            realm = result["data"].get("realm", "")
            body = jsonify(
                error="payment required", hint=result["data"].get("hint", "")
            )
            return body, 402, {"WWW-Authenticate": f'HMTP-Stamp realm="{realm}"'}
        return problem(result)

    return app
