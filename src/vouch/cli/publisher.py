"""`publisher init` / `publisher delegate`, per 04_FRONTEND_SPEC.md section 4.

M1 deviates deliberately from the frontend spec's abbreviated transcript: it
takes `--root-key` (the encrypted private key) directly on both commands
rather than splitting into an export/sign/import ceremony. That ceremony
exists to support an air-gapped root across a multi-step *rotation* flow
(M3); M1 has no rotation or chain-walking and a 1-of-1 threshold, so the
ceremony would be complexity with nothing yet to justify it.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import click

from .. import keys, originstore, root
from ..canonical import canonicalize
from ..hashing import b3_hex
from ..store import ensure_layout
from ._common import decode_envelope_payload, find_sole_publisher, latest_root_version


@click.group("publisher")
def publisher_group() -> None:
    """Publisher-side commands: initialize an origin, delegate role keys."""


@publisher_group.command("init")
@click.argument("name")
@click.option("--root-key", "root_key_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--store", type=click.Path(path_type=Path), required=True, help="Origin store directory")
@click.option("--passphrase-fd", type=int, default=None)
def publisher_init(name: str, root_key_path: Path, store: Path, passphrase_fd: int | None) -> None:
    """Initialize a new publisher identity at STORE, named NAME locally."""
    passphrase = keys.read_passphrase(passphrase_fd)
    loaded = keys.load_encrypted_key(root_key_path, passphrase)
    if loaded.role != "root":
        raise click.ClickException(f"{root_key_path} is a {loaded.role} key, not a root key")

    pub = keys.public_bytes(loaded.public_key)
    doc = root.build_root_doc(publisher=loaded.key_id, root_keys=[(loaded.key_id, pub)])
    envelope = root.sign_root_doc(doc, loaded.private_key, loaded.key_id)

    ensure_layout(store)
    originstore.write_root_doc(store, loaded.key_id, 1, envelope)

    click.echo(f"initialized publisher {name} -> {loaded.key_id}")
    click.echo(f"store: {store}")


@publisher_group.command("delegate")
@click.option("--role", type=click.Choice(["release", "timestamp"]), required=True)
@click.option("--key", "pub_key_path", type=click.Path(exists=True, path_type=Path), required=True, help="Public key file (.pub) to delegate")
@click.option("--root-key", "root_key_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--store", type=click.Path(path_type=Path), required=True)
@click.option("--passphrase-fd", type=int, default=None)
def publisher_delegate(role: str, pub_key_path: Path, root_key_path: Path, store: Path, passphrase_fd: int | None) -> None:
    """Add a release or timestamp key to the root document. Works against
    whichever root version is currently latest -- including after a
    rotation (M3), when the publisher's permanent identity (the fingerprint
    everything is stored under) and the CURRENT root key's own id are no
    longer the same value. Bumps the root version; since delegation never
    touches `keys.root` itself, the same current root key's single
    signature satisfies both the previous and the new version's threshold
    (same reasoning as `revoke`), so no cross-signing ceremony is needed.
    """
    passphrase = keys.read_passphrase(passphrase_fd)
    root_loaded = keys.load_encrypted_key(root_key_path, passphrase)
    if root_loaded.role != "root":
        raise click.ClickException(f"{root_key_path} is a {root_loaded.role} key, not a root key")

    pubfile_role, delegated_kid, delegated_pub = keys.load_public_key_file(pub_key_path)
    if pubfile_role != role:
        raise click.ClickException(f"{pub_key_path} is a {pubfile_role} key, not {role!r}")

    fingerprint = find_sole_publisher(store)
    current_version = latest_root_version(store, fingerprint)
    existing_envelope = originstore.read_root_doc(store, fingerprint, current_version)
    doc = decode_envelope_payload(existing_envelope)

    if root_loaded.key_id not in {k["id"] for k in doc.get("keys", {}).get("root", [])}:
        raise click.ClickException(f"{root_key_path} is not among the current root keys for {fingerprint}")

    doc = dict(doc)
    doc["keys"] = dict(doc["keys"])
    doc["keys"][role] = [{"id": delegated_kid, "pub": base64.b64encode(delegated_pub).decode("ascii")}]
    doc["root_version"] = current_version + 1

    new_envelope = root.sign_root_doc(doc, root_loaded.private_key, root_loaded.key_id)
    originstore.write_root_doc(store, fingerprint, current_version + 1, new_envelope)

    click.echo(f"delegated {role} key {delegated_kid} (root v{current_version + 1})")


@publisher_group.command("import-root")
@click.argument("signed_root_file", type=click.Path(exists=True, path_type=Path))
@click.option("--store", type=click.Path(path_type=Path), required=True)
@click.option("--release-key", "release_key_path", type=click.Path(exists=True, path_type=Path), required=True, help="Release key, to sign the log entry for this rotation/revocation")
@click.option("--passphrase-fd", type=int, default=None)
def publisher_import_root(signed_root_file: Path, store: Path, release_key_path: Path, passphrase_fd: int | None) -> None:
    """Apply a prepared, cross-signed root document (from `rotate` or
    `revoke`) to STORE, after validating it's a legitimate extension of
    the currently stored root chain.
    """
    envelope = json.loads(signed_root_file.read_text())
    payload = decode_envelope_payload(envelope)
    fingerprint = payload.get("publisher")
    new_version = payload.get("root_version")
    if not fingerprint or not isinstance(new_version, int):
        raise click.ClickException(f"{signed_root_file}: not a recognized root document")

    ensure_layout(store)
    prev_envelope = originstore.read_root_doc(store, fingerprint, new_version - 1)
    if prev_envelope is None:
        raise click.ClickException(f"{store}: no root document at version {new_version - 1} to rotate from")
    prev_doc = decode_envelope_payload(prev_envelope)

    verified_next = root.verify_root_link(prev_doc, envelope)

    originstore.write_root_doc(store, fingerprint, new_version, envelope)

    passphrase = keys.read_passphrase(passphrase_fd)
    release_loaded = keys.load_encrypted_key(release_key_path, passphrase)
    if release_loaded.role != "release":
        raise click.ClickException(f"{release_key_path} is a {release_loaded.role} key, not a release key")

    prev_root_ids = {k["id"] for k in prev_doc["keys"]["root"]}
    next_root_ids = {k["id"] for k in verified_next["keys"]["root"]}
    event = "rotate" if prev_root_ids != next_root_ids else "revoke"
    leaf_digest = b3_hex(canonicalize(verified_next))
    log_index, _checkpoint = originstore.append_log_leaf(
        store, fingerprint, event=event, digest=leaf_digest,
        release_private_key=release_loaded.private_key, release_key_id=release_loaded.key_id,
    )

    click.echo(f"imported root v{new_version} for {fingerprint} ({event})")
    click.echo(f"log: leaf {log_index} appended")
