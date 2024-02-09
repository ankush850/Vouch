"""The `vouch` CLI entry point, per 04_FRONTEND_SPEC.md section 3.

Verified by default, and only: no flag, environment variable, or config
key anywhere in this codebase disables a verification check or yields an
artifact that skipped one.
"""

from __future__ import annotations

import click

from .completion import completion_command
from .diff import diff_command
from .doctor import doctor_command
from .fetch import fetch_command
from .hash_util import hash_command
from .inspect import inspect_command
from .keygen import keygen_command
from .keys_export import keys_export_command
from .log import log_group
from .mirror import mirror_group
from .origin import origin_group
from .provenance import provenance_command
from .prune import prune_command
from .publish import publish_command
from .publisher import publisher_group
from .revoke import revoke_command
from .rotate import rotate_command
from .status import status_command
from .trust import trust_group
from .trust_bundle import trust_bundle_command
from .verify import verify_command
from .version import version_command


@click.group()
@click.option("--json", "json_output", is_flag=True, help="Emit a machine-readable result/v1 JSON object")
@click.option("--quiet", is_flag=True, help="Suppress progress output")
@click.pass_context
def main(ctx: click.Context, json_output: bool, quiet: bool) -> None:
    """Vouch: verified-by-default distribution for ML models and datasets."""
    ctx.ensure_object(dict)
    ctx.obj["json"] = json_output
    ctx.obj["quiet"] = quiet


main.add_command(keygen_command)
main.add_command(publisher_group)
main.add_command(publish_command)
main.add_command(origin_group)
main.add_command(mirror_group)
main.add_command(trust_group)
main.add_command(fetch_command)
main.add_command(verify_command)
main.add_command(rotate_command)
main.add_command(revoke_command)
main.add_command(log_group)
main.add_command(provenance_command)
main.add_command(diff_command)
main.add_command(status_command)
main.add_command(doctor_command)
main.add_command(inspect_command)
main.add_command(version_command)
main.add_command(hash_command)
main.add_command(keys_export_command)
main.add_command(completion_command)
main.add_command(prune_command)
main.add_command(trust_bundle_command)


if __name__ == "__main__":
    main()
