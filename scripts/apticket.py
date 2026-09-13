"""Capture and validate the restore-bound Image4 manifest ticket.

Apple returns this DER object as ``ApImg4Ticket`` in the main TSS response.
Liter8 keeps the ticket as a normal work-directory artifact so SSHRD and normal
boot creation never depend on a manually copied device file.
"""

from __future__ import annotations

import hashlib
import json
import os
import plistlib
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote_to_bytes

from liter8_workflow import WorkflowError


TICKET_NAME = "apticket.im4m"
METADATA_NAME = "apticket.json"


def validate_im4m(ticket: bytes) -> None:
    """Reject truncated data and unrelated ASN.1 objects before publication."""
    if len(ticket) < 8 or ticket[0] != 0x30:
        raise WorkflowError("APTicket is not a DER SEQUENCE")

    length_byte = ticket[1]
    if length_byte < 0x80:
        header_size = 2
        payload_size = length_byte
    else:
        length_octets = length_byte & 0x7F
        if length_octets == 0 or length_octets > 4 or len(ticket) < 2 + length_octets:
            raise WorkflowError("APTicket has an invalid DER length")
        header_size = 2 + length_octets
        payload_size = int.from_bytes(ticket[2:header_size], "big")

    if header_size + payload_size != len(ticket):
        raise WorkflowError(
            f"APTicket DER length is {header_size + payload_size}, got {len(ticket)} bytes"
        )
    # An IM4M begins with a DER sequence whose first IA5 string names the
    # manifest. This prevents a different Apple ticket from being accepted.
    if b"\x16\x04IM4M" not in ticket[:16]:
        raise WorkflowError("APTicket is DER, but it is not an IM4M manifest")


def _plist_from_tss_response(response: bytes) -> dict | None:
    """Decode Apple's form-wrapped TSS plist without changing the response."""
    marker = b"REQUEST_STRING="
    candidates = [response]
    if marker in response:
        body = response.split(marker, 1)[1]
        candidates = [body, unquote_to_bytes(body)]
    for candidate in candidates:
        try:
            document = plistlib.loads(candidate)
        except Exception:
            continue
        if isinstance(document, dict):
            return document
    return None


def ticket_from_tss_response(response: bytes) -> bytes | None:
    """Return the main AP ticket, or None for baseband/Cryptex TSS replies."""
    document = _plist_from_tss_response(response)
    if document is None:
        return None
    value = document.get("ApImg4Ticket") or document.get("APTicket")
    if value is None:
        return None
    if not isinstance(value, bytes):
        raise WorkflowError("TSS returned a non-data ApImg4Ticket")
    validate_im4m(value)
    return value


def request_identity(request: bytes) -> dict[str, object]:
    """Retain only identifiers needed to prevent use with the wrong restore."""
    try:
        document = plistlib.loads(request)
    except Exception:
        return {}
    if not isinstance(document, dict):
        return {}
    metadata: dict[str, object] = {}
    ecid = document.get("ApECID")
    nonce = document.get("ApNonce")
    if isinstance(ecid, int):
        metadata["ecid"] = ecid
    if isinstance(nonce, bytes):
        metadata["apNonce"] = nonce.hex()
    return metadata


def tickets_from_debug_log(text: str) -> list[bytes]:
    """Recover tickets printed by idevicerestore's plist debug formatter."""
    matches = re.findall(
        r'"(?:APTicket|ApImg4Ticket)"\s*:\s*<([0-9a-fA-F\s]+)>',
        text,
        flags=re.MULTILINE,
    )
    unique: list[bytes] = []
    for encoded in matches:
        ticket = bytes.fromhex("".join(encoded.split()))
        validate_im4m(ticket)
        if ticket not in unique:
            unique.append(ticket)
    return unique


def identity_from_debug_log(text: str) -> dict[str, object]:
    """Bind a recovered ticket to the ECID, build, and nonce in its log."""
    metadata: dict[str, object] = {}
    ecid = re.search(r"\bECID:\s*(\d+)", text)
    build = re.search(r"\bIPSW Product Build:\s*(\S+)", text)
    nonce = re.search(
        r"Getting ApNonce[^\n]*?((?:[0-9a-fA-F]{2}[ ]+){31}[0-9a-fA-F]{2})",
        text,
    )
    if ecid:
        metadata["ecid"] = int(ecid.group(1))
    if build:
        metadata["build"] = build.group(1)
    if nonce:
        metadata["apNonce"] = "".join(nonce.group(1).split()).lower()
    return metadata


def publish_ticket(
    ticket: bytes,
    directory: Path,
    *,
    source: str,
    metadata: dict[str, object] | None = None,
) -> Path:
    """Atomically replace the ticket and its human-readable provenance."""
    validate_im4m(ticket)
    directory.mkdir(parents=True, exist_ok=True)
    ticket_path = directory / TICKET_NAME
    metadata_path = directory / METADATA_NAME
    record: dict[str, object] = {
        "schema": 1,
        "source": source,
        "capturedAt": datetime.now(timezone.utc).isoformat(),
        "size": len(ticket),
        "sha256": hashlib.sha256(ticket).hexdigest(),
    }
    record.update(metadata or {})

    temporary_paths: list[Path] = []
    try:
        with tempfile.NamedTemporaryFile(dir=directory, delete=False) as output:
            temporary_ticket = Path(output.name)
            temporary_paths.append(temporary_ticket)
            output.write(ticket)
            output.flush()
            os.fsync(output.fileno())
        with tempfile.NamedTemporaryFile("w", dir=directory, delete=False) as output:
            temporary_metadata = Path(output.name)
            temporary_paths.append(temporary_metadata)
            json.dump(record, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_ticket, ticket_path)
        os.replace(temporary_metadata, metadata_path)
    finally:
        for temporary in temporary_paths:
            temporary.unlink(missing_ok=True)
    return ticket_path


def capture_from_debug_log(log: Path, work_directory: Path, *, profile_id: str) -> Path:
    text = log.read_text(errors="strict")
    if "Status: Restore Finished" not in text:
        raise WorkflowError(f"restore log did not finish successfully: {log}")
    tickets = tickets_from_debug_log(text)
    if len(tickets) != 1:
        raise WorkflowError(
            f"expected one unique APTicket in {log.name}, found {len(tickets)}"
        )
    metadata = identity_from_debug_log(text)
    metadata["profileID"] = profile_id
    metadata["restoreLog"] = log.name
    return publish_ticket(
        tickets[0], work_directory,
        source="idevicerestore-debug-log",
        metadata=metadata,
    )


def latest_successful_restore_log(work_directory: Path) -> Path:
    logs = work_directory / "logs"
    candidates = sorted(
        logs.glob("restore-cfw-*.log"),
        key=lambda path: path.stat().st_mtime_ns,
        reverse=True,
    )
    for candidate in candidates:
        if "Status: Restore Finished" in candidate.read_text(errors="replace"):
            return candidate
    raise WorkflowError(f"no successful restore debug log was found in {logs}")
