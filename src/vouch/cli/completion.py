"""`vouch completion SHELL`: generate autocompletion scripts."""

from __future__ import annotations

import click


@click.command("completion")
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish", "powershell"]))
def completion_command(shell: str) -> None:
    """Generate shell autocompletion script instructions."""
    if shell == "bash":
        click.echo('eval "$(_VOUCH_COMPLETE=bash_source vouch)"')
    elif shell == "zsh":
        click.echo('eval "$(_VOUCH_COMPLETE=zsh_source vouch)"')
    elif shell == "fish":
        click.echo('eval (env _VOUCH_COMPLETE=fish_source vouch)')
    elif shell == "powershell":
        click.echo('Register-ArgumentCompleter -Native -CommandName vouch -ScriptBlock { ... }')
