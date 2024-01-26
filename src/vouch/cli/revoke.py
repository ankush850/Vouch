"""`vouch revoke`, per 04_FRONTEND_SPEC.md's revoke transcript and
03_SECURITY_AND_ACCESS.md section 5.5.

Unlike `rotate`, revocation doesn't change `keys.root` -- it only appends
to `revoked` -- so the SAME root key set authorizes both "prev's
threshold" and "next's own threshold" in `verify_root_link`, and only one
signature (from the still-good root key) is needed, not two.
"""

from __future__ import annotations

import json
from pathlib import Path

import click

from .. import keys, originstore
from .. import root as root_mod
from ..timeutil import utc_now_iso
from ._common import decode_envelope_payload, decode_key_entries, find_sole_publisher, latest_root_version


@click.command("revoke")
@click.argument("key_id")
@click.option("--reason", required=True)
@click.option("--store", type=click.Path(path_type=Path), required=True)
@click.option("--root-key", "root_key_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--out", type=click.Path(path_type=Path), required=True)
@click.option("--passphrase-fd", type=int, default=None)
def revoke_command(key_id: str, reason: str, store: Path, root_key_path: Path, out: Path, passphrase_fd: int | None) -> None:
    """Prepare a new root version revoking KEY_ID."""
    passphrase = keys.read_passphrase(passphrase_fd)
    loaded = keys.load_encrypted_key(root_key_path, passphrase)
    if loaded.role != "root":
        raise click.ClickException(f"{root_key_path} is a {loaded.role} key, not a root key")

    fingerprint = find_sole_publisher(store)
    current_version = latest_root_version(store, fingerprint)
    current_envelope = originstore.read_root_doc(store, fingerprint, current_version)
    current_doc = decode_envelope_payload(current_envelope)

    revoked = list(current_doc.get("revoked", []))
    revoked.append({"id": key_id, "at": utc_now_iso(), "reason": reason})

    next_doc = root_mod.build_root_doc(
        publisher=current_doc["publisher"],
        root_keys=decode_key_entries(current_doc["keys"]["root"]),
        release_keys=decode_key_entries(current_doc["keys"]["release"]),
        timestamp_keys=decode_key_entries(current_doc["keys"]["timestamp"]),
        root_version=current_version + 1,
        threshold_root=current_doc.get("threshold", {}).get("root", 1),
        revoked=revoked,
    )
    envelope = root_mod.sign_root_doc(next_doc, loaded.private_key, loaded.key_id)

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n")

    release_ids = {e["id"] for e in current_doc["keys"]["release"]}
    click.echo(f"prepared root doc v{current_version + 1}: revokes {key_id}, adds nothing")
    click.echo(f"written to {out}")
    click.echo("ACTION REQUIRED: run on the publish host:")
    click.echo(f"  vouch publisher import-root {out} --store {store} --release-key rk.key")
    if key_id in release_ids:
        click.echo("after import: re-sign current manifests with a new release key:")
        click.echo("  vouch publish --resign-all --key rk-new.key --store ...")
