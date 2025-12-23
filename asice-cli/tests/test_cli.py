import subprocess
import sys
from pathlib import Path


def run_cli(*args):
    cmd = [sys.executable, "-m", "asice_cli.cli", *args]
    return subprocess.run(cmd, capture_output=True, text=True)


def test_package_requires_arguments():
    result = run_cli("package")
    assert result.returncode != 0
    assert "Usage:" in result.stderr


def test_package_missing_file(tmp_path):
    key = tmp_path / "key.pem"
    cert = tmp_path / "cert.pem"
    key.write_text("dummy")
    cert.write_text("dummy")
    result = run_cli(
        "package",
        "--key",
        str(key),
        "--cert",
        str(cert),
        "--tsa-url",
        "https://example",
        "--tsa-cert",
        str(cert),
        "missing.txt",
    )
    assert result.returncode != 0
    assert "does not exist" in result.stderr


def test_verify_requires_archive(tmp_path):
    cert = tmp_path / "cert.pem"
    cert.write_text("dummy")
    result = run_cli(
        "verify",
        "--signer-cert",
        str(cert),
        "--tsa-cert",
        str(cert),
        "--report",
        "json",
        "missing.asice",
    )
    assert result.returncode != 0
    assert "does not exist" in result.stderr


def test_retimestamp_requires_arguments():
    result = run_cli("retimestamp")
    assert result.returncode != 0
    assert "Usage:" in result.stderr
