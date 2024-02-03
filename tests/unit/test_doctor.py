from click.testing import CliRunner

from vouch.cli.main import main


def test_doctor_command_text():
    runner = CliRunner()
    result = runner.invoke(main, ["doctor"])
    assert result.exit_code == 0
    assert "Vouch Doctor Diagnostics:" in result.output
    assert "crypto_blake3" in result.output
    assert "crypto_ed25519" in result.output


def test_doctor_command_json():
    runner = CliRunner()
    result = runner.invoke(main, ["--json", "doctor"])
    assert result.exit_code == 0
    assert '"vouch": "doctor/v1"' in result.output
    assert '"healthy": true' in result.output
