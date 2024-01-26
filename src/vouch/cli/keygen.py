from __future__ import annotations

from pathlib import Path

import click

from .. import keys


@click.command("keygen")
@click.option("--role", type=click.Choice(keys.ROLES), required=True)
@click.option("--out", "out_path", type=click.Path(path_type=Path), required=True, help="Path to write the encrypted private key")
@click.option("--passphrase-fd", type=int, default=None, help="Read the passphrase from this file descriptor instead of prompting")
def keygen_command(role: str, out_path: Path, passphrase_fd: int | None) -> None:
    """Generate a new Ed25519 key for ROLE, encrypted at rest."""
    passphrase = keys.read_passphrase(passphrase_fd, confirm=(passphrase_fd is None))
    private_key = keys.generate_keypair()
    key_id = keys.save_encrypted_key(out_path, private_key, role, passphrase)

    pub_path = Path(str(out_path) + ".pub")
    keys.save_public_key(pub_path, private_key.public_key(), role)

    click.echo(f"new {role} key: {key_id}")
    if role == "root":
        click.echo("  (fingerprint to distribute out-of-band)")
    click.echo(f"private key: {out_path}")
    click.echo(f"public key:  {pub_path}")
