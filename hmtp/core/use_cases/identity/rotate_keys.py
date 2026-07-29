from hmtp.core.entities import crypto
from hmtp.core.entities.message import canonical
from hmtp.core.entities.responses import ResponseTypes, failure, success


def rotate_keys_use_case(config_store, repo) -> dict:
    """Replace both keypairs and extend the rotation chain: the outgoing
    signing key signs the new one, so anyone who pinned the old key can
    verify the handover. Old encryption keys are kept so old sealed mail
    stays readable, and queued outgoing mail is re-signed (its id hashes
    the plaintext, so it is unaffected)."""
    try:
        cfg = config_store.load()
        old_private = cfg["private_key"]
        signing_private, signing_public = crypto.new_signing_keypair()
        encryption_private, encryption_public = crypto.new_encryption_keypair()
        cfg.setdefault("rotations", [{"key": cfg["public_key"]}]).append(
            {
                "key": signing_public,
                "sig": crypto.sign_bytes(crypto.unb64(signing_public), old_private),
            }
        )
        cfg.setdefault("previous_encryption_keys", []).insert(
            0, [cfg["encryption_private_key"], cfg["encryption_public_key"]]
        )
        cfg["private_key"] = signing_private
        cfg["public_key"] = signing_public
        cfg["encryption_private_key"] = encryption_private
        cfg["encryption_public_key"] = encryption_public
        config_store.save(cfg)
        entries = repo.all_outbox()
        for entry in entries:
            wire = entry["payload"]
            core = {k: v for k, v in wire.items() if k != "signature"}
            wire = core | {
                "signature": crypto.sign_bytes(canonical(core), signing_private)
            }
            repo.replace_outbox_payload(entry["id"], wire)
        return success(resigned=len(entries))
    except Exception as error:  # noqa: BLE001 -- exceptions never leave a use case
        return failure(ResponseTypes.SYSTEM_ERROR, "system", str(error))
