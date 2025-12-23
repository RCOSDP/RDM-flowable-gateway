"""Helpers for talking to RFC 3161 Time Stamp Authorities."""
from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import requests
from requests import Response
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

REQUEST_HEADERS = {"Content-Type": "application/timestamp-query"}
RETRY_STATUS = (500, 502, 503, 504)


class TSAError(RuntimeError):
    """Raised when TSA communication or validation fails."""


@dataclass(slots=True)
class TSAClient:
    """Issues timestamp requests using the local ``openssl`` binary."""

    url: str
    ca_bundle: Path
    timeout: float = 10.0
    digest: str = "sha512"

    _session: requests.Session = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=RETRY_STATUS,
            allowed_methods=("POST",),
        )
        adapter = HTTPAdapter(max_retries=retry)
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)

    def close(self) -> None:
        self._session.close()

    def request_token(self, target: Path) -> bytes:
        """Return a timestamp token for the bytes stored at ``target``."""
        if not target.exists():  # pragma: no cover - sanity guard
            raise TSAError(f"Timestamp target {target} does not exist")
        request_blob = _build_timestamp_request(target, self.digest)
        response = self._post(request_blob)
        token = response.content
        self._verify_response(token, target)
        return token

    def _post(self, payload: bytes) -> Response:
        try:
            response = self._session.post(
                self.url,
                headers=REQUEST_HEADERS,
                data=payload,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:  # pragma: no cover - network failure
            raise TSAError(f"Failed to reach TSA {self.url}: {exc}") from exc
        if response.status_code in {400, 401, 402, 403, 500, 502, 503, 504}:
            # align with RDM defaults that treat these as fatal immediately
            raise TSAError(
                f"TSA {self.url} returned HTTP {response.status_code}"
            )
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            raise TSAError(f"Unexpected TSA response: {exc}") from exc
        return response

    def _verify_response(self, token: bytes, target: Path) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            token_path = Path(tmp) / "tsa-response.tst"
            token_path.write_bytes(token)
            _verify_timestamp(token_path, target, self.ca_bundle, self.digest)


def _build_timestamp_request(target: Path, digest: str) -> bytes:
    digest_flag = _digest_flag(digest)
    cmd = [
        "openssl",
        "ts",
        "-query",
        "-data",
        str(target),
        digest_flag,
        "-cert",
    ]
    try:
        completed = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise TSAError("Failed to create timestamp request via openssl") from exc
    return completed.stdout


def verify_timestamp(token: Path, target: Path, ca_bundle: Path, digest: str = "sha512") -> None:
    _verify_timestamp(token, target, ca_bundle, digest)


def _verify_timestamp(token: Path, target: Path, ca_bundle: Path, digest: str) -> None:
    digest_flag = _digest_flag(digest)
    cmd = [
        "openssl",
        "ts",
        "-verify",
        "-in",
        str(token),
        "-data",
        str(target),
        digest_flag,
        "-CAfile",
        str(ca_bundle),
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise TSAError("TSA response failed openssl verification") from exc


def _digest_flag(digest: str) -> str:
    lowered = digest.lower()
    if lowered not in {"sha256", "sha512"}:
        raise TSAError(f"Unsupported digest algorithm: {digest}")
    return f"-{lowered}"
