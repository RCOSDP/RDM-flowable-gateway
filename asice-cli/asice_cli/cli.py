"""Command line interface for asice-cli."""
from __future__ import annotations

import json
import logging
from enum import Enum
from pathlib import Path
from typing import List, Optional

import typer

from .core import (
    PackagingError,
    UsageError,
    VerificationError,
    create_archive,
    retimestamp_archive,
    verify_archive,
)
from .tsa import TSAError

logger = logging.getLogger("asice_cli")
app = typer.Typer(add_completion=False)

USAGE_ERROR = 64
SOFTWARE_ERROR = 70
IO_ERROR = 74


class ReportFormat(str, Enum):
    json = "json"


def _configure_logging(verbose: bool, quiet: bool) -> None:
    if verbose and quiet:
        raise typer.BadParameter("--verbose and --quiet are mutually exclusive")
    level = logging.WARNING
    if verbose:
        level = logging.INFO
    elif quiet:
        level = logging.ERROR
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


@app.command("package")
def package_cmd(
    key: Path = typer.Option(..., "--key", "-k", exists=True, readable=True, help="PEM encoded private key"),
    cert: Path = typer.Option(..., "--cert", "-c", exists=True, readable=True, help="PEM encoded certificate"),
    tsa_url: str = typer.Option(..., "--tsa-url", help="RFC 3161 TSA endpoint"),
    tsa_cert: Optional[Path] = typer.Option(
        None,
        "--tsa-cert",
        exists=True,
        readable=True,
        help="Certificate bundle for verifying TSA responses",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Destination .asice file. Defaults to stdout when omitted.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Emit info logs"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress non-error logs"),
    files: List[Path] = typer.Argument(..., exists=True, readable=True, dir_okay=False, help="Payload files"),
) -> None:
    """Build an ASiC-E container from ``files``."""
    _configure_logging(verbose, quiet)
    if tsa_cert is None:
        raise typer.BadParameter("--tsa-cert is required")

    logger.info("Building ASiC-E bundle: files=%d output=%s", len(files), output or "stdout")

    try:
        create_archive(files, key, cert, tsa_url, tsa_cert, output)
    except UsageError as exc:
        typer.secho(f"error: {exc}", err=True, fg=typer.colors.RED)
        raise typer.Exit(USAGE_ERROR) from exc
    except PackagingError as exc:
        typer.secho(f"error: {exc}", err=True, fg=typer.colors.RED)
        raise typer.Exit(SOFTWARE_ERROR) from exc
    except TSAError as exc:
        typer.secho(f"tsa error: {exc}", err=True, fg=typer.colors.RED)
        raise typer.Exit(IO_ERROR) from exc


@app.command("verify")
def verify_cmd(
    archive: Path = typer.Argument(..., exists=True, readable=True, dir_okay=False, help=".asice file"),
    signer_cert: Path = typer.Option(
        ...,
        "--signer-cert",
        exists=True,
        readable=True,
        help="Certificate bundle for verifying PKCS#7 signatures",
    ),
    tsa_cert: Path = typer.Option(
        ...,
        "--tsa-cert",
        exists=True,
        readable=True,
        help="Certificate bundle for verifying TSA responses",
    ),
    report: Optional[ReportFormat] = typer.Option(
        None,
        "--report",
        help="Emit verification report (json)",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Emit info logs"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress non-error logs"),
) -> None:
    """Verify an ASiC-E container."""
    _configure_logging(verbose, quiet)
    logger.info("Verifying %s", archive)
    try:
        report_data = verify_archive(archive, signer_cert, tsa_cert, want_report=report is not None)
    except UsageError as exc:
        typer.secho(f"error: {exc}", err=True, fg=typer.colors.RED)
        raise typer.Exit(USAGE_ERROR) from exc
    except VerificationError as exc:
        typer.secho(f"verify error: {exc}", err=True, fg=typer.colors.RED)
        raise typer.Exit(IO_ERROR) from exc
    except TSAError as exc:
        typer.secho(f"tsa error: {exc}", err=True, fg=typer.colors.RED)
        raise typer.Exit(IO_ERROR) from exc
    else:
        if report_data and report == ReportFormat.json:
            typer.echo(json.dumps(report_data, ensure_ascii=False))


@app.command("retimestamp")
def retimestamp_cmd(
    archive: Path = typer.Argument(..., exists=True, readable=True, dir_okay=False, help=".asice file"),
    tsa_url: str = typer.Option(..., "--tsa-url", help="RFC 3161 TSA endpoint"),
    tsa_cert: Path = typer.Option(..., "--tsa-cert", exists=True, readable=True, help="TSA certificate bundle"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Updated .asice output. Defaults to stdout."),
    signer_cert: Optional[Path] = typer.Option(None, "--signer-cert", exists=True, readable=True, help="Certificate bundle for verifying the existing signature"),
    max_age: Optional[int] = typer.Option(None, "--max-age", help="Skip when latest timestamp is younger than DAYS"),
    force: bool = typer.Option(False, "--force", help="Force re-timestamp even when within max-age"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Emit info logs"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress non-error logs"),
) -> None:
    """Extend the timestamp chain for an ASiC-E container."""
    _configure_logging(verbose, quiet)
    try:
        result_path, updated = retimestamp_archive(
            archive,
            tsa_url,
            tsa_cert,
            output,
            signer_cert=signer_cert,
            max_age_days=max_age,
            force=force,
        )
    except UsageError as exc:
        typer.secho(f"error: {exc}", err=True, fg=typer.colors.RED)
        raise typer.Exit(USAGE_ERROR) from exc
    except PackagingError as exc:
        typer.secho(f"error: {exc}", err=True, fg=typer.colors.RED)
        raise typer.Exit(SOFTWARE_ERROR) from exc
    except TSAError as exc:
        typer.secho(f"tsa error: {exc}", err=True, fg=typer.colors.RED)
        raise typer.Exit(IO_ERROR) from exc
    else:
        if not updated:
            logger.info("Existing timestamp is still within policy; no new archive emitted")


def run() -> None:
    """Entry point for ``python -m asice_cli.cli`` and console_scripts."""
    app()


if __name__ == "__main__":  # pragma: no cover
    run()
class ReportFormat(str, Enum):
    json = "json"
