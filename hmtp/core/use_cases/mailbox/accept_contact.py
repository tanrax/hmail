from hmtp.core.entities.responses import success
from hmtp.core.use_cases.messages.mirror_attachments import mirror_attachments


def accept_contact_use_case(repo, network, blob_store, address: str) -> dict:
    repo.add_contact(address)
    repo.move_sender_to_inbox(address)
    # Accepting also re-trusts the sender's key: forget the pin so the next
    # delivery pins whatever the domain publishes now.
    repo.unpin_key(address)
    # Consent granted: mirror the attachments that delivery deferred.
    for row in repo.messages_from(address):
        mirror_attachments(row["payload"], network, blob_store)
    return success(accepted=address)
