from pathlib import Path

import click
from waitress import serve as waitress_serve

from hmtp.core.entities.responses import ResponseTypes
from hmtp.core.use_cases.devices.generate_device_keys import (
    generate_device_keys_use_case,
)
from hmtp.core.use_cases.devices.register_device import register_device_use_case
from hmtp.core.use_cases.identity.init_identity import init_identity_use_case
from hmtp.core.use_cases.identity.rotate_keys import rotate_keys_use_case
from hmtp.core.use_cases.mailbox.accept_contact import accept_contact_use_case
from hmtp.core.use_cases.mailbox.read_token import read_token_use_case
from hmtp.core.use_cases.messages.flush_outbox import flush_outbox_use_case
from hmtp.core.use_cases.messages.list_messages import list_messages_use_case
from hmtp.core.use_cases.messages.reply_message import reply_message_use_case
from hmtp.core.use_cases.messages.save_attachments import save_attachments_use_case
from hmtp.core.use_cases.messages.send_message import send_message_use_case
from hmtp.core.use_cases.postage.issue_stamp import issue_stamp_use_case
from hmtp.core.use_cases.postage.set_postage import set_postage_use_case
from hmtp.infra import settings
from hmtp.infra.api.flask.src.app import create_app
from hmtp.infra.database.sqlite_repo import SQLiteRepo
from hmtp.infra.filesystem.blob_files import FileBlobStore
from hmtp.infra.filesystem.config_json import JSONConfigStore
from hmtp.infra.gateways.httpx_network import HttpxNetwork


def _deps():
    home = settings.HOME
    return (
        SQLiteRepo(home),
        JSONConfigStore(home),
        HttpxNetwork(insecure=settings.INSECURE),
        FileBlobStore(home),
    )


def _echo_send_result(result: dict) -> None:
    data = result["data"]
    if result["type"] == ResponseTypes.SUCCESS and "delivered" in data:
        click.echo(f"delivered {data['delivered']}")
        if data.get("mirrored"):
            click.echo(f"attachments mirrored by recipient: {len(data['mirrored'])}")
    elif result["type"] == ResponseTypes.SUCCESS and "queued" in data:
        click.echo(f"queued ({data['reason']})")
    elif result["type"] == ResponseTypes.REJECTED:
        click.echo(f"rejected, not retrying ({result['errors'][0]['message']})")
    else:
        click.echo(result["errors"][0]["message"])


@click.group()
def cli():
    """HMTP: a minimal self-hosted mail node over HTTP. No SMTP."""


@cli.command()
@click.argument("address")
@click.argument("base_url")
def init(address, base_url):
    """Create identity and database."""
    _, config_store, _, _ = _deps()
    init_identity_use_case(config_store, address, base_url)
    click.echo(f"identity created for {address} in {settings.HOME}")


@cli.command()
@click.argument("port", default=8025)
def serve(port):
    """Run the node (default port 8025)."""
    waitress_serve(create_app(), host=settings.HOST, port=port)


@cli.command()
@click.argument("recipient")
@click.argument("words", nargs=-1, required=True)
@click.option("-s", "--subject", default=None, help="Subject (travels encrypted).")
@click.option(
    "-a",
    "--attach",
    "attach_paths",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Attach a file (repeatable).",
)
@click.option("--stamp", default=None, help="Postage stamp for a first contact.")
def send(recipient, words, subject, attach_paths, stamp):
    """Sign, encrypt and deliver a message."""
    repo, config_store, network, blob_store = _deps()
    attachments = [
        {"name": path.name, "data": path.read_bytes()} for path in attach_paths
    ]
    result = send_message_use_case(
        repo,
        config_store.load(),
        network,
        blob_store,
        recipient,
        " ".join(words),
        subject=subject,
        attachments=attachments or None,
        stamp=stamp,
    )
    _echo_send_result(result)


@cli.command()
@click.argument("message_id")
@click.argument("words", nargs=-1, required=True)
def reply(message_id, words):
    """Reply to a message (threaded)."""
    repo, config_store, network, blob_store = _deps()
    result = reply_message_use_case(
        repo, config_store.load(), network, blob_store, message_id, " ".join(words)
    )
    if result["type"] == ResponseTypes.PARAMETERS_ERROR and "matches" in result["data"]:
        click.echo("ambiguous id, matches:")
        for match in result["data"]["matches"]:
            click.echo(f"  {match}")
        return
    _echo_send_result(result)


@cli.command()
@click.argument("message_id")
@click.argument(
    "directory",
    default=".",
    type=click.Path(file_okay=False, path_type=Path),
)
def attachments(message_id, directory):
    """Save and decrypt the attachments of a message."""
    repo, config_store, network, blob_store = _deps()
    result = save_attachments_use_case(
        repo, config_store.load(), network, blob_store, message_id
    )
    if result["type"] != ResponseTypes.SUCCESS:
        click.echo(result["errors"][0]["message"])
        return
    directory.mkdir(parents=True, exist_ok=True)
    for file in result["data"]["files"]:
        destination = directory / file["name"]
        counter = 1
        while destination.exists():
            destination = directory / f"{counter}-{file['name']}"
            counter += 1
        destination.write_bytes(file["data"])
        click.echo(f"saved {destination} ({len(file['data'])} bytes)")


@cli.command()
def flush():
    """Retry queued deliveries."""
    repo, _, network, _ = _deps()
    result = flush_outbox_use_case(repo, network)
    data = result["data"]
    if not any(data.values()):
        click.echo("nothing due")
        return
    for message_id in data["delivered"]:
        click.echo(f"delivered {message_id}")
    for entry in data["dropped"]:
        click.echo(f"dropped {entry['id']}, rejected ({entry['reason']})")
    for entry in data["still_queued"]:
        click.echo(
            f"still queued {entry['id']}"
            f" (attempt {entry['attempt']}, next in {entry['next_in']}s)"
        )


@cli.command("list")
def list_command():
    """Show inbox and contact requests."""
    repo, config_store, _, _ = _deps()
    result = list_messages_use_case(repo, config_store.load())
    for box in ("inbox", "requests"):
        click.echo(f"== {box} ==")
        for entry in result["data"][box]:
            body = entry["body"]
            if entry["attachments"]:
                names = ", ".join(entry["attachments"])
                body += f" [{len(entry['attachments'])} attachment(s): {names}]"
            thread = (
                f" reply-to {entry['in_reply_to'][:19]}" if entry["in_reply_to"] else ""
            )
            click.echo(
                f"[{entry['date']}] {entry['sender']} {entry['subject']}"
                f" ({entry['id'][:19]}){thread}"
            )
            click.echo(f"  {body}")


@cli.command()
@click.argument("address")
def accept(address):
    """Accept a contact request."""
    repo, _, network, blob_store = _deps()
    accept_contact_use_case(repo, network, blob_store, address)
    click.echo(f"{address} accepted")


@cli.command()
def rotate():
    """Replace signing and encryption keys (chained, see SPEC.md)."""
    repo, config_store, _, _ = _deps()
    result = rotate_keys_use_case(config_store, repo)
    if result["type"] != ResponseTypes.SUCCESS:
        click.echo(result["errors"][0]["message"])
        return
    click.echo(
        f"keys rotated, {result['data']['resigned']} queued message(s) re-signed"
    )


@cli.command()
@click.argument("setting", type=click.Choice(["on", "off"]))
def postage(setting):
    """Require stamps from strangers."""
    _, config_store, _, _ = _deps()
    set_postage_use_case(config_store, setting == "on")
    click.echo(f"postage for strangers: {setting}")


@cli.command()
def stamp():
    """Issue a single-use postage stamp."""
    repo, _, _, _ = _deps()
    result = issue_stamp_use_case(repo)
    click.echo(result["data"]["stamp"])


@cli.command()
def token():
    """Print the mailbox read token."""
    _, config_store, _, _ = _deps()
    result = read_token_use_case(config_store)
    click.echo(result["data"]["token"])


@cli.group()
def device():
    """Manage per-device encryption keys."""


@device.command()
def keygen():
    """Generate a key pair ON the new device; only the public key travels."""
    result = generate_device_keys_use_case()
    click.echo(f"private (keep on the device): {result['data']['private_key']}")
    click.echo(f"public  (register with 'device add'): {result['data']['public_key']}")


@device.command("add")
@click.argument("name")
@click.argument("public_key")
def device_add(name, public_key):
    """Publish a device encryption key in the discovery document."""
    _, config_store, _, _ = _deps()
    register_device_use_case(config_store, name, public_key)
    click.echo(f"device {name} published")


if __name__ == "__main__":
    cli()
