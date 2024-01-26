"""`vouch rotate`, per 04_FRONTEND_SPEC.md's rotate/revoke ceremony shape
and 03_SECURITY_AND_ACCESS.md section 5.4.

Meant to run wherever the CURRENT root key lives (D5: root keys are kept
offline). Reads the store's current root chain (read-only -- nothing here
is written back to `--store`) and writes a fully cross-signed new root
document to `--out` as a portable file; the operator carries that file
back to the online publish host and applies it via `publisher import-root`.
This models the "prepare, sign offline, import" ceremony from the
frontend spec without needing a third command: both the current and new
root private keys are expected to be available together at rotation time
(a real deployment can run this whole command on the air-gapped machine in
one sitting), and only the resulting file crosses the boundary.
"""

from __future__ import annotations

import json
from pathlib import Path

import click

from .. import keys, originstore
from .. import root as root_mod
from ..dsse import add_signature
from ._common import decode_envelope_payload, decode_key_entries, find_sole_publisher, latest_root_version


@click.command("rotate")
@click.option("--store", type=click.Path(path_type=Path), required=True, help="Origin store to read the current root chain from")
@click.option("--root-key", "root_key_path", type=click.Path(exists=True, path_type=Path), required=True, help="Current (soon-to-be-previous) root private key")
@click.option("--new-root-key", "new_root_key_path", type=click.Path(exists=True, path_type=Path), required=True, help="New root private key")
@click.option("--threshold", "threshold_root", type=int, default=1, help="New root's own signature threshold")
@click.option("--out", type=click.Path(path_type=Path), required=True, help="Where to write the prepared, signed root document")
@click.option("--passphrase-fd", type=int, default=None, help="Passphrase fd for --root-key")
@click.option(
    "--new-root-passphrase-fd", type=int, default=None,
    help="Passphrase fd for --new-root-key; prompted interactively if omitted",
)
def rotate_command(
    store: Path,
    root_key_path: Path,
    new_root_key_path: Path,
    threshold_root: int,
    out: Path,
    passphrase_fd: int | None,
    new_root_passphrase_fd: int | None,
) -> None:
    """Prepare a new root version rotating to a new root key, cross-signed
    by both the current and new root keys."""
    old_passphrase = keys.read_passphrase(passphrase_fd)
    old_loaded = keys.load_encrypted_key(root_key_path, old_passphrase)
    if old_loaded.role != "root":
        raise click.ClickException(f"{root_key_path} is a {old_loaded.role} key, not a root key")

    new_passphrase = keys.read_passphrase(new_root_passphrase_fd)
    new_loaded = keys.load_encrypted_key(new_root_key_path, new_passphrase)
    if new_loaded.role != "root":
        raise click.ClickException(f"{new_root_key_path} is a {new_loaded.role} key, not a root key")

    fingerprint = find_sole_publisher(store)
    current_version = latest_root_version(store, fingerprint)
    current_envelope = originstore.read_root_doc(store, fingerprint, current_version)
    current_doc = decode_envelope_payload(current_envelope)

    next_doc = root_mod.build_root_doc(
        publisher=current_doc["publisher"],
        root_keys=[(new_loaded.key_id, keys.public_bytes(new_loaded.public_key))],
        release_keys=decode_key_entries(current_doc["keys"]["release"]),
        timestamp_keys=decode_key_entries(current_doc["keys"]["timestamp"]),
        root_version=current_version + 1,
        threshold_root=threshold_root,
        revoked=current_doc.get("revoked", []),
    )
    envelope = root_mod.sign_root_doc(next_doc, new_loaded.private_key, new_loaded.key_id)
    envelope = add_signature(envelope, old_loaded.private_key, old_loaded.key_id)

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n")

    click.echo(f"prepared root doc v{current_version + 1}: rotates root key to {new_loaded.key_id}")
    click.echo(f"written to {out}")
    click.echo("ACTION REQUIRED: run on the publish host:")
    click.echo(f"  vouch publisher import-root {out} --store {store} --release-key rk.key")
