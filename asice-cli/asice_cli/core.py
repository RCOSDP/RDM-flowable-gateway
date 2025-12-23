"""Core ASiC-E generation logic."""
from __future__ import annotations

import base64
import hashlib
import io
import logging
import mimetypes
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple
from xml.etree import ElementTree as ET

from .tsa import TSAClient, TSAError, verify_timestamp

logger = logging.getLogger(__name__)

ASIC_NS = "http://uri.etsi.org/02918/v1.2.1#"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"
DIGEST_URI = "http://www.w3.org/2001/04/xmlenc#sha256"
META_INF = "META-INF"
SIGNATURE_FILENAME = f"{META_INF}/signatures.p7s"
SIGNATURE_MIME = "application/pkcs7-mime"
TIMESTAMP_MIME = "application/vnd.etsi.timestamp-token"
TIMESTAMP_FILENAME = f"{META_INF}/timestamp.tst"
MIMETYPE_FILE = "mimetype"
MIMETYPE_VALUE = b"application/vnd.etsi.asic-e+zip"
SIGNATURE_MANIFEST = f"{META_INF}/ASiCManifest.xml"
BASE_TIMESTAMP_MANIFEST = f"{META_INF}/ASiCManifest-timestamp.xml"


class UsageError(Exception):
    """Raised when user input fails validation."""


class PackagingError(Exception):
    """Raised when openssl or packaging steps fail."""


class VerificationError(Exception):
    """Raised when container verification fails."""


@dataclass(slots=True)
class Payload:
    source: Path
    arcname: str
    digest: bytes
    size: int


@dataclass(slots=True)
class ManifestEntry:
    name: str
    digest: bytes
    mime_type: str | None = None


@dataclass(slots=True)
class ManifestDocument:
    name: str
    content: bytes
    sig_reference: str
    sig_mime: str | None
    entries: List[ManifestEntry]


def create_archive(
    files: Sequence[Path],
    key: Path,
    cert: Path,
    tsa_url: str,
    tsa_cert: Path,
    output: Path | None,
) -> Path | None:
    payloads = _collect_payloads(files)
    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        manifest_entries = [_manifest_entry_from_payload(payload) for payload in payloads]

        sig_manifest_bytes = _build_asic_manifest(manifest_entries, SIGNATURE_FILENAME, SIGNATURE_MIME)
        sig_manifest_path = tmp_dir / "asic_manifest_signature.xml"
        sig_manifest_path.write_bytes(sig_manifest_bytes)

        timestamp_manifest_bytes = _build_asic_manifest(manifest_entries, TIMESTAMP_FILENAME, TIMESTAMP_MIME)
        timestamp_manifest_path = tmp_dir / "asic_manifest_timestamp.xml"
        timestamp_manifest_path.write_bytes(timestamp_manifest_bytes)

        signature_path = tmp_dir / "signatures.p7s"
        _sign_manifest(sig_manifest_path, key, cert, signature_path)

        tsa_client = TSAClient(tsa_url, tsa_cert)
        try:
            token_bytes = tsa_client.request_token(timestamp_manifest_path)
        finally:
            tsa_client.close()
        timestamp_path = tmp_dir / "timestamp.tst"
        timestamp_path.write_bytes(token_bytes)

        archive_path = tmp_dir / "bundle.asice"
        _write_archive(
            archive_path,
            payloads,
            [
                (SIGNATURE_MANIFEST, sig_manifest_bytes),
                (BASE_TIMESTAMP_MANIFEST, timestamp_manifest_bytes),
            ],
            signature_path,
            [(TIMESTAMP_FILENAME, timestamp_path)],
        )

        if output is None:
            data = archive_path.read_bytes()
            sys.stdout.buffer.write(data)
            sys.stdout.flush()
            return None

        output = output.expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(archive_path), str(output))
        return output


def verify_archive(
    bundle: Path,
    signer_cert: Path,
    tsa_cert: Path,
    want_report: bool = False,
) -> Dict[str, Any] | None:
    archive = bundle.expanduser().resolve()
    if not archive.exists():
        raise UsageError(f"Archive not found: {bundle}")
    if not archive.is_file():
        raise UsageError(f"Archive must be a file: {bundle}")

    with zipfile.ZipFile(archive, "r") as bundle_zip:
        manifest_docs = _load_manifest_documents(bundle_zip)
        if not manifest_docs:
            raise VerificationError("ASiCManifest files are missing")

        signature_manifests = [doc for doc in manifest_docs if _is_signature_reference(doc.sig_reference)]
        if not signature_manifests:
            raise VerificationError("No signature manifest present")

        payload_entries = signature_manifests[0].entries
        _validate_payloads(bundle_zip, payload_entries)

        signature_refs = {_normalize_member(doc.sig_reference) for doc in signature_manifests}
        signature_blobs = _read_named_members(bundle_zip, signature_refs, "signature")

        timestamp_blobs = _collect_timestamp_blobs(bundle_zip)
        timestamp_entries = sorted(timestamp_blobs.items(), key=lambda item: item[0])
        timestamp_manifests = [doc for doc in manifest_docs if _is_timestamp_reference(doc.sig_reference)]
        timestamp_targets = []
        for doc in timestamp_manifests:
            ref = _normalize_member(doc.sig_reference)
            token_bytes = timestamp_blobs.get(ref)
            if token_bytes is None:
                raise VerificationError(f"Missing timestamp file referenced by {doc.name}: {ref}")
            timestamp_targets.append((doc, token_bytes))

    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        for doc in signature_manifests:
            manifest_path = tmp_dir / Path(doc.name).name
            manifest_path.write_bytes(doc.content)
            sig_name = _normalize_member(doc.sig_reference)
            sig_bytes = signature_blobs[sig_name]
            signature_path = tmp_dir / Path(sig_name).name
            signature_path.write_bytes(sig_bytes)
            _verify_signature(signature_path, manifest_path, signer_cert)

        for doc, token_bytes in timestamp_targets:
            manifest_path = tmp_dir / Path(doc.name).name
            manifest_path.write_bytes(doc.content)
            token_name = Path(_normalize_member(doc.sig_reference)).name
            token_path = tmp_dir / token_name
            token_path.write_bytes(token_bytes)
            verify_timestamp(token_path, manifest_path, tsa_cert)

    if want_report:
        tokens_report = []
        for name, data in timestamp_entries:
            token_time = _extract_timestamp_time(data)
            tokens_report.append(
                {
                    "name": name,
                    "size": len(data),
                    "time": token_time.isoformat() if token_time else None,
                }
            )
        latest_time = _latest_timestamp_time(timestamp_entries)
        payload_report = [
            {
                "name": entry.name,
                "sha256": base64.b64encode(entry.digest).decode("ascii"),
            }
            for entry in payload_entries
        ]
        return {
            "archive": str(archive),
            "payloads": payload_report,
            "signature": {
                "certificate": str(signer_cert),
                "status": "verified",
                "manifests": [doc.name for doc in signature_manifests],
            },
            "timestamp": {
                "certificate": str(tsa_cert),
                "status": "verified",
                "latest_time": latest_time.isoformat() if latest_time else None,
                "manifests": [doc.name for doc in timestamp_manifests],
                "tokens": tokens_report,
            },
        }
    return None


def _collect_payloads(files: Sequence[Path]) -> List[Payload]:
    if not files:
        raise UsageError("Provide at least one file to package")
    payloads: List[Payload] = []
    seen: set[str] = set()
    for file_path in files:
        path = file_path.expanduser().resolve()
        if not path.exists():
            raise UsageError(f"Input file not found: {file_path}")
        if not path.is_file():
            raise UsageError(f"Input must be a regular file: {file_path}")
        arcname = path.name
        if arcname in seen:
            raise UsageError(f"Duplicate file name detected: {arcname}")
        seen.add(arcname)
        digest = _hash_file(path)
        size = path.stat().st_size
        payloads.append(Payload(path, arcname, digest, size))
    return payloads


def _hash_file(path: Path) -> bytes:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            if not chunk:
                break
            h.update(chunk)
    return h.digest()


def _manifest_entry_from_payload(payload: Payload) -> ManifestEntry:
    mime_type, _ = mimetypes.guess_type(payload.arcname)
    return ManifestEntry(payload.arcname, payload.digest, mime_type)


def _build_asic_manifest(
    entries: Iterable[ManifestEntry],
    sig_reference: str,
    sig_mime: str | None,
) -> bytes:
    ET.register_namespace("asic", ASIC_NS)
    ET.register_namespace("ds", DS_NS)

    root = ET.Element(ET.QName(ASIC_NS, "ASiCManifest"))
    sig_attrib = {"URI": sig_reference}
    if sig_mime:
        sig_attrib["MimeType"] = sig_mime
    ET.SubElement(root, ET.QName(ASIC_NS, "SigReference"), attrib=sig_attrib)

    for entry in entries:
        attrib = {"URI": entry.name}
        if entry.mime_type:
            attrib["MimeType"] = entry.mime_type
        data_ref = ET.SubElement(root, ET.QName(ASIC_NS, "DataObjectReference"), attrib=attrib)
        digest_method = ET.SubElement(
            data_ref,
            ET.QName(DS_NS, "DigestMethod"),
            attrib={"Algorithm": DIGEST_URI},
        )
        digest_method.tail = None
        digest_value = ET.SubElement(data_ref, ET.QName(DS_NS, "DigestValue"))
        digest_value.text = base64.b64encode(entry.digest).decode("ascii")

    tree = ET.ElementTree(root)
    buf = io.BytesIO()
    tree.write(buf, encoding="utf-8", xml_declaration=True)
    return buf.getvalue()


def _sign_manifest(manifest: Path, key: Path, cert: Path, output: Path) -> None:
    cmd = [
        "openssl",
        "cms",
        "-sign",
        "-binary",
        "-in",
        str(manifest),
        "-signer",
        str(cert),
        "-inkey",
        str(key),
        "-md",
        "sha256",
        "-outform",
        "DER",
        "-nodetach",
        "-nosmimecap",
        "-cades",
        "-out",
        str(output),
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise PackagingError("Failed to sign manifest via openssl") from exc


def _write_archive(
    destination: Path,
    payloads: Iterable[Payload],
    manifests: Iterable[Tuple[str, bytes]],
    signature_path: Path,
    timestamp_items: Iterable[Tuple[str, Path]],
) -> None:
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_STORED) as bundle:
        bundle.writestr(MIMETYPE_FILE, MIMETYPE_VALUE, compress_type=zipfile.ZIP_STORED)
        for payload in payloads:
            bundle.write(payload.source, arcname=payload.arcname, compress_type=zipfile.ZIP_STORED)
        for name, data in manifests:
            bundle.writestr(name, data)
        bundle.write(signature_path, arcname=SIGNATURE_FILENAME)
        for name, path in timestamp_items:
            bundle.write(path, arcname=name)


def _read_required(zip_file: zipfile.ZipFile, member: str, label: str) -> bytes:
    try:
        return zip_file.read(member)
    except KeyError as exc:
        raise VerificationError(f"Missing {label}: {member}") from exc


def _manifest_member(name: str) -> bool:
    normalized = _normalize_member(name)
    return normalized.startswith(f"{META_INF}/ASiCManifest") and normalized.endswith(".xml")


def _is_timestamp_member(name: str) -> bool:
    normalized = _normalize_member(name).lower()
    return normalized.startswith(f"{META_INF.lower()}/timestamp") and normalized.endswith(".tst")


def _normalize_member(name: str) -> str:
    return name.lstrip("./")


def _is_signature_reference(uri: str) -> bool:
    normalized = Path(_normalize_member(uri))
    return normalized.suffix.lower() == ".p7s" and "signature" in normalized.name.lower()


def _is_timestamp_reference(uri: str) -> bool:
    normalized = Path(_normalize_member(uri))
    return normalized.suffix.lower() == ".tst" and "timestamp" in normalized.name.lower()


def _load_manifest_documents(zip_file: zipfile.ZipFile) -> List[ManifestDocument]:
    manifests: List[ManifestDocument] = []
    for info in zip_file.infolist():
        if info.is_dir():
            continue
        if _manifest_member(info.filename):
            data = zip_file.read(info.filename)
            manifests.append(_parse_manifest(info.filename, data))
    return manifests


def _read_named_members(zip_file: zipfile.ZipFile, members: set[str], label: str) -> Dict[str, bytes]:
    blobs: Dict[str, bytes] = {}
    for member in sorted(members):
        if not member:
            continue
        blobs[member] = _read_required(zip_file, member, label)
    return blobs


def _collect_timestamp_blobs(zip_file: zipfile.ZipFile) -> Dict[str, bytes]:
    blobs: Dict[str, bytes] = {}
    for info in zip_file.infolist():
        if info.is_dir():
            continue
        if _is_timestamp_member(info.filename):
            blobs[info.filename] = zip_file.read(info.filename)
    return blobs


def _validate_payloads(zip_file: zipfile.ZipFile, entries: List[ManifestEntry]) -> None:
    manifest_names = {entry.name for entry in entries}
    archive_names = {
        info.filename
        for info in zip_file.infolist()
        if not info.is_dir()
        and not info.filename.startswith(f"{META_INF}/")
        and info.filename != MIMETYPE_FILE
    }
    if manifest_names != archive_names:
        raise VerificationError("Manifest entries do not match archive payloads")

    for entry in entries:
        data = zip_file.read(entry.name)
        actual_digest = hashlib.sha256(data).digest()
        if actual_digest != entry.digest:
            raise VerificationError(f"Digest mismatch for {entry.name}")


def _parse_manifest(name: str, manifest_bytes: bytes) -> ManifestDocument:
    try:
        root = ET.fromstring(manifest_bytes)
    except ET.ParseError as exc:
        raise VerificationError(f"Manifest {name} is not valid XML") from exc

    sig_el = root.find(str(ET.QName(ASIC_NS, "SigReference")))
    if sig_el is None:
        raise VerificationError(f"Manifest {name} is missing SigReference")
    sig_reference = sig_el.get("URI")
    if not sig_reference:
        raise VerificationError(f"Manifest {name} SigReference missing URI")
    sig_mime = sig_el.get("MimeType")

    entries: List[ManifestEntry] = []
    q_ref = ET.QName(ASIC_NS, "DataObjectReference")
    q_digest = ET.QName(DS_NS, "DigestValue")
    for data_ref in root.findall(str(q_ref)):
        uri = data_ref.get("URI")
        digest_el = data_ref.find(str(q_digest))
        if not uri or digest_el is None or not digest_el.text:
            raise VerificationError(f"Manifest {name} entry missing URI or digest")
        try:
            digest_bytes = base64.b64decode(digest_el.text.strip())
        except (ValueError, TypeError) as exc:
            raise VerificationError(f"Manifest {name} has invalid digest encoding") from exc
        mime_type = data_ref.get("MimeType")
        entries.append(ManifestEntry(uri, digest_bytes, mime_type))
    if not entries:
        raise VerificationError(f"Manifest {name} does not reference any payloads")
    return ManifestDocument(name, manifest_bytes, sig_reference, sig_mime, entries)


def _verify_signature(signature_path: Path, manifest_path: Path, signer_cert: Path) -> None:
    cmd = [
        "openssl",
        "cms",
        "-verify",
        "-binary",
        "-inform",
        "DER",
        "-in",
        str(signature_path),
        "-content",
        str(manifest_path),
        "-CAfile",
        str(signer_cert),
        "-out",
        os.devnull,
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise VerificationError("PKCS#7 signature verification failed") from exc


def retimestamp_archive(
    bundle: Path,
    tsa_url: str,
    tsa_cert: Path,
    output: Path | None,
    signer_cert: Path | None = None,
    max_age_days: int | None = None,
    force: bool = False,
) -> Tuple[Path | None, bool]:
    archive = bundle.expanduser().resolve()
    if not archive.exists():
        raise UsageError(f"Archive not found: {bundle}")
    if not archive.is_file():
        raise UsageError(f"Archive must be a file: {bundle}")

    with zipfile.ZipFile(archive, "r") as bundle_zip:
        manifest_docs = _load_manifest_documents(bundle_zip)
        if not manifest_docs:
            raise VerificationError("ASiCManifest files are missing")
        signature_manifests = [doc for doc in manifest_docs if _is_signature_reference(doc.sig_reference)]
        if not signature_manifests:
            raise VerificationError("No signature manifest present")
        payload_entries = signature_manifests[0].entries
        signature_refs = {_normalize_member(doc.sig_reference) for doc in signature_manifests}
        signature_blobs = _read_named_members(bundle_zip, signature_refs, "signature")

        timestamp_blobs = _collect_timestamp_blobs(bundle_zip)
        timestamp_entries = sorted(timestamp_blobs.items(), key=lambda item: item[0])
        base_timestamp_doc = next(
            (
                doc
                for doc in manifest_docs
                if _normalize_member(doc.sig_reference) == TIMESTAMP_FILENAME
            ),
            None,
        )
        base_timestamp_bytes = timestamp_blobs.get(TIMESTAMP_FILENAME)

    latest_time = _latest_timestamp_time(timestamp_entries)
    if max_age_days is not None and not force and latest_time is not None:
        if datetime.now(timezone.utc) - latest_time <= timedelta(days=max_age_days):
            return None, False

    existing_manifest_names = {doc.name for doc in manifest_docs}
    existing_timestamp_names = {name for name, _ in timestamp_entries}
    new_token_name = _next_timestamp_name(existing_timestamp_names)
    new_manifest_name = _next_timestamp_manifest_name(existing_manifest_names)
    new_manifest_bytes = _build_asic_manifest(payload_entries, new_token_name, TIMESTAMP_MIME)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        manifest_path = tmp_dir / Path(new_manifest_name).name
        manifest_path.write_bytes(new_manifest_bytes)

        tsa_client = TSAClient(tsa_url, tsa_cert)
        try:
            new_token_bytes = tsa_client.request_token(manifest_path)
        finally:
            tsa_client.close()

        if signer_cert is not None:
            sig_doc = signature_manifests[0]
            sig_manifest_path = tmp_dir / Path(sig_doc.name).name
            sig_manifest_path.write_bytes(sig_doc.content)
            sig_name = _normalize_member(sig_doc.sig_reference)
            sig_path = tmp_dir / Path(sig_name).name
            sig_path.write_bytes(signature_blobs[sig_name])
            _verify_signature(sig_path, sig_manifest_path, signer_cert)

            if base_timestamp_doc is not None and base_timestamp_bytes is not None:
                base_manifest_path = tmp_dir / Path(base_timestamp_doc.name).name
                base_manifest_path.write_bytes(base_timestamp_doc.content)
                base_token_path = tmp_dir / Path(TIMESTAMP_FILENAME).name
                base_token_path.write_bytes(base_timestamp_bytes)
                verify_timestamp(base_token_path, base_manifest_path, tsa_cert)

        new_archive_path = tmp_dir / "retimestamp.asice"
        _clone_archive_with_token(
            archive,
            new_archive_path,
            (new_manifest_name, new_manifest_bytes),
            (new_token_name, new_token_bytes),
        )

        if output is None:
            data = new_archive_path.read_bytes()
            sys.stdout.buffer.write(data)
            sys.stdout.flush()
            return None, True

        output = output.expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(new_archive_path), str(output))
        return output, True


def _next_timestamp_name(existing: set[str]) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    name = f"{META_INF}/timestamp-{stamp}.tst"
    counter = 1
    while name in existing:
        name = f"{META_INF}/timestamp-{stamp}-{counter}.tst"
        counter += 1
    return name


def _next_timestamp_manifest_name(existing: set[str]) -> str:
    base = f"{META_INF}/ASiCManifest-timestamp"
    candidate = f"{base}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}" + ".xml"
    counter = 1
    while candidate in existing:
        candidate = f"{base}-{counter}.xml"
        counter += 1
    return candidate


def _clone_archive_with_token(
    src: Path,
    dest: Path,
    manifest_entry: Tuple[str, bytes],
    token_entry: Tuple[str, bytes],
) -> None:
    with zipfile.ZipFile(src, "r") as src_zip, zipfile.ZipFile(dest, "w") as dst_zip:
        for info in src_zip.infolist():
            if info.is_dir():
                dst_zip.writestr(info, b"")
            else:
                data = src_zip.read(info.filename)
                dst_zip.writestr(info, data)
        manifest_name, manifest_bytes = manifest_entry
        dst_zip.writestr(manifest_name, manifest_bytes)
        token_name, token_bytes = token_entry
        dst_zip.writestr(token_name, token_bytes)


def _extract_timestamp_time(token: bytes) -> datetime | None:
    with tempfile.TemporaryDirectory() as tmp:
        token_path = Path(tmp) / "timestamp_info.tst"
        token_path.write_bytes(token)
        cmd = ["openssl", "ts", "-reply", "-in", str(token_path), "-text"]
        try:
            completed = subprocess.run(cmd, check=True, capture_output=True, text=True)
        except (OSError, subprocess.CalledProcessError) as exc:
            logger.warning("Failed to inspect timestamp token: %s", exc)
            return None
    for line in completed.stdout.splitlines():
        if line.strip().startswith("Time stamp:"):
            value = line.split("Time stamp:", 1)[1].strip()
            for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
                try:
                    parsed = datetime.strptime(value, fmt)
                except ValueError:
                    continue
                return parsed.replace(tzinfo=timezone.utc)
            logger.warning("Unable to parse timestamp value: %s", value)
    return None


def _latest_timestamp_time(entries: List[Tuple[str, bytes]]) -> datetime | None:
    latest: datetime | None = None
    for name, token in entries:
        token_time = _extract_timestamp_time(token)
        if token_time is None:
            continue
        if latest is None or token_time > latest:
            latest = token_time
    return latest
