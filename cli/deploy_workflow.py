#!/usr/bin/env python3
"""Deploy BPMN + form assets to Flowable via the REST API."""

from __future__ import annotations

import argparse
import getpass
import json
import mimetypes
import os
from pathlib import Path
from typing import Iterable, List, Tuple
from urllib.parse import urljoin

from types import ModuleType


_HTTPX: ModuleType | None = None


def _require_httpx() -> ModuleType:
    global _HTTPX
    if _HTTPX is None:
        try:
            import httpx  # type: ignore
        except ImportError as exc:  # pragma: no cover - dependency guard
            raise RuntimeError(
                "The 'httpx' package is required. Install dependencies with 'pip install -r requirements.txt'."
            ) from exc
        _HTTPX = httpx
    return _HTTPX

DEFAULT_DEPLOYMENT_CATEGORY = "rdm"
DEPLOYMENT_ENDPOINT = "service/repository/deployments"


def _env_default(key: str, fallback: str | None = None) -> str | None:
    value = os.environ.get(key)
    if value:
        return value
    return fallback


def _detect_content_type(path: Path) -> str:
    content_type, _ = mimetypes.guess_type(path.name)
    if content_type:
        return content_type
    if path.suffix in {".xml", ".bpmn", ".bpmn20", ".bpmn20.xml"}:
        return "application/xml"
    if path.suffix in {".json", ".form"}:
        return "application/json"
    return "application/octet-stream"


def _open_files(paths: Iterable[Path]) -> List[Tuple[str, Tuple[str, object, str]]]:
    files: List[Tuple[str, Tuple[str, object, str]]] = []
    for path in paths:
        if not path.exists():
            raise FileNotFoundError(f"Asset not found: {path}")
        files.append(("file", (path.name, path.open("rb"), _detect_content_type(path))))
    return files


def _close_files(entries: Iterable[Tuple[str, Tuple[str, object, str]]]) -> None:
    for _, (_, handle, _) in entries:
        try:
            handle.close()
        except Exception:
            pass


def deploy(
    *,
    base_url: str,
    username: str,
    password: str,
    assets: List[Path],
    deployment_name: str,
    category: str | None,
    tenant_id: str | None,
    enable_duplicate_filtering: bool,
) -> dict:
    if not assets:
        raise ValueError("At least one asset must be supplied for deployment.")

    endpoint = urljoin(base_url.rstrip('/') + '/', DEPLOYMENT_ENDPOINT)

    data: dict[str, str] = {"deploymentName": deployment_name}
    if category:
        data["category"] = category
    if tenant_id:
        data["tenantId"] = tenant_id
    if enable_duplicate_filtering:
        data["enableDuplicateFiltering"] = "true"

    files = _open_files(assets)

    httpx = _require_httpx()

    try:
        with httpx.Client(timeout=30.0, auth=(username, password)) as client:
            response = client.post(
                endpoint,
                data=data,
                files=files,
            )
    finally:
        _close_files(files)

    try:
        payload = response.json()
    except ValueError:
        response.raise_for_status()
        raise

    if response.status_code >= 400:
        message = json.dumps(payload, indent=2, ensure_ascii=False)
        raise RuntimeError(f"Deployment failed ({response.status_code}): {message}")

    return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--flowable-url",
        dest="flowable_url",
        default=_env_default("FLOWABLE_REST_BASE_URL", "http://127.0.0.1:8090/flowable-rest"),
        help="Flowable REST base URL (default: %(default)s)",
    )
    parser.add_argument(
        "--username",
        dest="username",
        default=_env_default("FLOWABLE_REST_APP_ADMIN_USER_ID", "rest-admin"),
        help="Flowable REST username (default: %(default)s)",
    )
    parser.add_argument(
        "--password",
        dest="password",
        default=_env_default("FLOWABLE_REST_APP_ADMIN_PASSWORD"),
        help="Flowable REST password (default: env FLOWABLE_REST_APP_ADMIN_PASSWORD)",
    )
    parser.add_argument(
        "--name",
        dest="deployment_name",
        default="rdm-publication-approval",
        help="Deployment name to register in Flowable (default: %(default)s)",
    )
    parser.add_argument(
        "--category",
        dest="category",
        default=DEFAULT_DEPLOYMENT_CATEGORY,
        help="Deployment category label (default: %(default)s)",
    )
    parser.add_argument(
        "--tenant-id",
        dest="tenant_id",
        default=None,
        help="Optional tenant identifier to associate with the deployment",
    )
    parser.add_argument(
        "--skip-duplicate-filter",
        dest="disable_duplicate_filter",
        action="store_true",
        help="Disable Flowable duplicate filtering on deployment",
    )
    parser.add_argument(
        "--asset",
        dest="assets",
        action="append",
        type=Path,
        required=True,
        help="Path to a BPMN or supporting asset file. Supply multiple --asset flags as needed.",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    password = args.password
    if not password:
        password = getpass.getpass("Flowable password: ")

    assets = [path.resolve() for path in args.assets]

    try:
        payload = deploy(
            base_url=args.flowable_url,
            username=args.username,
            password=password,
            assets=assets,
            deployment_name=args.deployment_name,
            category=args.category,
            tenant_id=args.tenant_id,
            enable_duplicate_filtering=not args.disable_duplicate_filter,
        )
    except Exception as error:
        print(f"Deployment failed: {error}")
        return 1

    name = payload.get("name") or args.deployment_name
    deployment_id = payload.get("id") or payload.get("deploymentId")
    resources = payload.get("resources") or []

    print(f"Deployment '{name}' created (id={deployment_id}).")
    if resources:
        print("Registered resources:")
        for entry in resources:
            resource_name = entry.get("name") or entry.get("id")
            resource_id = entry.get("id")
            print(f"  - {resource_name} ({resource_id})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
