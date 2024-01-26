"""`publish`, per 04_FRONTEND_SPEC.md section 4.

M1 deliberately refused `--base`/`--dataset`/`--code`/`--records` (D15):
`provenance`/`record_index` were always null, and silently accepting flags
that imply lineage/record recording while doing nothing with them would
violate the "loud, specific" UX principle. M3 is where they become real.

Provenance materials are resolved ONLY from the local trust cache, never
the network (D-decision continuing D22's role-separation: a publish host
shouldn't need live network access to sign a release) -- an uncached
reference is a clean usage error telling the operator to `vouch fetch`
it first.

`--resign-all` is a distinct mode (frontend spec's exact recovery flow
after a release-key revocation): it re-signs every current manifest with
a new release key. The manifest bytes and digest are unchanged (only the
DSSE envelope's signature changes), matching the security doc's D13
remediation note that re-signing is cheap because content never moves.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import click

from .. import keys, manifest as manifest_mod, originstore
from ..errors import VouchError
from ..fetch_flow import parse_ref
from ..records import parse_granularity
from ..store import default_home, ensure_layout
from ..trust_store import load_cached_manifest
from ._common import decode_envelope_payload, find_sole_publisher


def _resolve_material(ref: str) -> dict:
    """Resolve NAME/ARTIFACT@VERSION -> {"role", "ref", "digest"} from the
    local trust cache. Never touches the network.
    """
    try:
        publisher_name, artifact, version = parse_ref(ref)
    except VouchError as e:
        raise click.ClickException(str(e))

    home = default_home()
    cached = load_cached_manifest(home, publisher_name, artifact, version)
    if cached is None:
        raise click.ClickException(f"{ref}: not found in the local cache; run `vouch fetch {ref}` first to resolve it")
    return {"ref": ref, "digest": cached["digest"]}


@click.command("publish")
@click.argument("source_dir", type=click.Path(exists=True, file_okay=False, path_type=Path), required=False)
@click.option("--name", default=None)
@click.option("--version", default=None)
@click.option("--type", "artifact_type", type=click.Choice(["model", "dataset"]), default=None)
@click.option("--release-key", "release_key_path", type=click.Path(exists=True, path_type=Path), required=True)
@click.option("--store", type=click.Path(path_type=Path), required=True, help="Origin store directory")
@click.option("--base", "base_refs", multiple=True, help="Base model REF (repeatable), resolved from the local cache")
@click.option("--dataset", "dataset_refs", multiple=True, help="Dataset REF (repeatable), resolved from the local cache")
@click.option("--code", "code_ref", default=None, help="Code reference, e.g. git+https://host/repo@REV")
@click.option("--records", "records_spec", default="none", help="Dataset record index granularity: none|line|block:N")
@click.option("--resign-all", is_flag=True, help="Re-sign every current manifest with --release-key instead of publishing new content")
@click.option("--passphrase-fd", type=int, default=None)
def publish_command(
    source_dir: Path | None,
    name: str | None,
    version: str | None,
    artifact_type: str | None,
    release_key_path: Path,
    store: Path,
    base_refs: tuple[str, ...],
    dataset_refs: tuple[str, ...],
    code_ref: str | None,
    records_spec: str,
    resign_all: bool,
    passphrase_fd: int | None,
) -> None:
    """Chunk, hash, and sign everything under SOURCE_DIR as a new release."""
    passphrase = keys.read_passphrase(passphrase_fd)
    release_loaded = keys.load_encrypted_key(release_key_path, passphrase)
    if release_loaded.role != "release":
        raise click.ClickException(f"{release_key_path} is a {release_loaded.role} key, not a release key")

    ensure_layout(store)
    fingerprint = find_sole_publisher(store)

    if resign_all:
        _resign_all(store, fingerprint, release_loaded)
        return

    if source_dir is None or name is None or version is None or artifact_type is None:
        raise click.ClickException("SOURCE_DIR, --name, --version, and --type are required unless --resign-all is given")

    if records_spec != "none" and artifact_type != "dataset":
        raise click.ClickException("--records only applies to --type dataset")
    parse_granularity(records_spec)  # validate early, before hashing anything

    provenance_digest = None
    if base_refs or dataset_refs or code_ref:
        from .. import provenance as provenance_mod

        materials = []
        for ref in base_refs:
            materials.append({"role": "base-model", **_resolve_material(ref)})
        for ref in dataset_refs:
            materials.append({"role": "dataset", **_resolve_material(ref)})
        build_info = {"kind": "finetune" if base_refs else "build"}
        if code_ref:
            build_info["code"] = code_ref

    seq = originstore.next_seq(store, fingerprint, name)

    click.echo(f"hashing files under {source_dir} ...")
    built = manifest_mod.build_manifest(
        source_dir,
        store,
        publisher=fingerprint,
        name=name,
        version=version,
        seq=seq,
        artifact_type=artifact_type,
        records=records_spec,
    )
    total_chunks = sum(len(f["chunks"]) for f in built["files"])
    click.echo(f"done: {len(built['files'])} file(s), {built['total_size']} bytes, {total_chunks} chunks")

    if base_refs or dataset_refs or code_ref:
        subject_digest = manifest_mod.content_digest(built)
        attestation = provenance_mod.build_provenance(
            name=name, version=version, manifest_digest=subject_digest, materials=materials, build=build_info
        )
        attestation_digest = provenance_mod.provenance_digest(attestation)
        attestation_envelope = provenance_mod.sign_provenance(attestation, release_loaded.private_key, release_loaded.key_id)
        originstore.write_manifest_envelope(store, attestation_digest, attestation_envelope)
        built["provenance"] = attestation_digest
        click.echo(f"provenance {attestation_digest} signed ({len(materials)} material(s))")

    digest = manifest_mod.manifest_digest(built)
    envelope = manifest_mod.sign_manifest(built, release_loaded.private_key, release_loaded.key_id)
    originstore.write_manifest_envelope(store, digest, envelope)

    log_index, _checkpoint = originstore.append_log_leaf(
        store, fingerprint, event="publish", digest=digest,
        release_private_key=release_loaded.private_key, release_key_id=release_loaded.key_id,
    )
    originstore.write_current_pointer(store, fingerprint, name, version, digest, log_index=log_index)

    click.echo(f"manifest {digest} signed (release key {release_loaded.key_id})")
    click.echo(f"log: leaf {log_index} appended")
    click.echo(f"published {name}@{version} (seq {seq})")


def _resign_all(store: Path, fingerprint: str, release_loaded) -> None:
    count = 0
    for artifact in originstore.list_artifacts(store, fingerprint):
        for version in originstore.list_versions(store, fingerprint, artifact):
            pointer = originstore.read_current_pointer(store, fingerprint, artifact, version)
            old_envelope = originstore.read_manifest_envelope(store, pointer["digest"])
            payload = decode_envelope_payload(old_envelope)
            new_envelope = manifest_mod.sign_manifest(payload, release_loaded.private_key, release_loaded.key_id)
            # The manifest's own bytes/digest are unchanged -- only the
            # signature changed -- so this overwrites the SAME digest-keyed
            # object with a freshly-signed envelope.
            originstore.write_manifest_envelope(store, pointer["digest"], new_envelope)
            count += 1

    # The transparency-log checkpoint is also release-key-signed: if it was
    # last signed by the very key being revoked, V7 would otherwise stay
    # broken for every consumer until some unrelated future log event.
    originstore.resign_checkpoint(store, fingerprint, release_private_key=release_loaded.private_key, release_key_id=release_loaded.key_id)

    click.echo(f"re-signed {count} manifest(s) and the log checkpoint with release key {release_loaded.key_id}")
