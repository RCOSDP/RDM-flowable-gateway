from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

from urllib import request as urllib_request
from urllib.error import HTTPError as URLLibHTTPError, URLError


@dataclass(frozen=True)
class KeyRecord:
    kid: str
    algorithm: str
    public_key: str


class KeySet:
    def __init__(self, records: Dict[str, KeyRecord]):
        if not records:
            raise ValueError("KeySet cannot be empty")
        self._records = records

    def get(self, kid: str) -> KeyRecord:
        try:
            return self._records[kid]
        except KeyError as error:
            raise KeyError(f"Unknown key id: {kid}") from error


def _parse_keyset_payload(data: Dict[str, Any]) -> KeySet:
    try:
        entries = data["keys"]
    except KeyError as error:
        raise RuntimeError("Keyset JSON must contain 'keys' array") from error

    records: Dict[str, KeyRecord] = {}
    for entry in entries:
        try:
            kid = entry["kid"]
            algorithm = entry["alg"]
        except KeyError as error:
            raise RuntimeError("Key entry requires 'kid' and 'alg'") from error

        if kid in records:
            raise RuntimeError(f"Duplicate key id: {kid}")

        if not algorithm.startswith("RS") and not algorithm.startswith("ES"):
            raise RuntimeError(f"Unsupported algorithm for gateway key {kid}: {algorithm}")

        public_key = entry.get("public_key")
        if not public_key:
            raise RuntimeError(f"Key entry '{kid}' missing public_key")

        records[kid] = KeyRecord(kid=kid, algorithm=algorithm, public_key=public_key)

    return KeySet(records)


def load_keyset_from_path(path: Path) -> KeySet:
    if not path.exists():
        raise RuntimeError(f"Keyset file not found: {path}")

    try:
        data = json.loads(path.read_text())
    except ValueError as error:
        raise RuntimeError(f"Keyset file is not valid JSON: {path}") from error

    return _parse_keyset_payload(data)


def load_keyset_from_url(url: str, timeout: float = 5.0) -> KeySet:
    try:
        with urllib_request.urlopen(url, timeout=timeout) as response:
            content_type = response.headers.get("Content-Type", "application/json")
            payload = response.read().decode("utf-8")
    except (URLError, URLLibHTTPError) as error:
        raise RuntimeError(f"Failed to fetch keyset from {url}: {error}") from error

    if "json" not in content_type:
        raise RuntimeError(f"Unexpected content type from {url}: {content_type}")

    try:
        data = json.loads(payload)
    except ValueError as error:
        raise RuntimeError(f"Keyset response from {url} is not valid JSON") from error

    return _parse_keyset_payload(data)
