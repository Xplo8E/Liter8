#!/usr/bin/env python3
"""Loopback TSS proxy owned by one Liter8 restore operation.

idevicerestore sends its TSS requests here. The proxy forwards them to Apple
and retries status 168 once with the same reviewed eUICC fields used by the
device-tested public beta-4 workflow. Request and response bodies are never
printed because they contain device-specific signing material.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from apticket import publish_ticket, request_identity, ticket_from_tss_response


UPSTREAM_TSS_URL = "https://gs.apple.com/TSS/controller?action=2"
TSS_PATH = "/TSS/controller?action=2"
EUICC_KEYS = (
    "\t<key>eUICC,ApProductionMode</key>\n\t<true/>\n"
    "\t<key>eUICC,ChipID</key>\n\t<integer>5</integer>\n"
    "\t<key>eUICC,EID</key>\n\t<data>\n"
    "\tiQSQMgBQCIgmAASEJAh2MQ==\n\t</data>\n"
    "\t<key>eUICC,RootKeyIdentifier</key>\n\t<data>\n"
    "\tQVhK/T5EfBDbGEdwMfU42u7Qx9M=\n\t</data>\n"
)


def tss_status(response: bytes) -> str | None:
    """Read only the leading STATUS field, before the encoded plist body."""
    head = response.decode("utf-8", errors="replace").split("&", 1)[0]
    return head.removeprefix("STATUS=").strip() if head.startswith("STATUS=") else None


def inject_euicc(request: bytes) -> bytes:
    """Insert the reviewed eUICC fields once into an XML plist request."""
    text = request.decode("utf-8", errors="strict")
    if "eUICC,ChipID" in text:
        return request
    closing_root = text.rfind("</dict>")
    if closing_root < 0:
        raise ValueError("TSS request has no root XML dictionary")
    return (text[:closing_root] + EUICC_KEYS + text[closing_root:]).encode()


class TSSProxyHandler(BaseHTTPRequestHandler):
    """Forward TSS requests while exposing only concise progress."""

    server_version = "Liter8TSS/1"

    def do_GET(self) -> None:  # noqa: N802 - inherited API spelling
        if self.path != "/health":
            self.send_error(404)
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok\n")

    def do_POST(self) -> None:  # noqa: N802 - inherited API spelling
        if self.path != TSS_PATH:
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            request = self.rfile.read(length)
            if len(request) != length:
                raise ValueError("short TSS request body")

            print(f"[tss] forwarding request ({length} bytes)", flush=True)
            response = self.forward(request)
            status = tss_status(response)
            if status == "168":
                print("[tss] status 168; retrying with reviewed eUICC fields", flush=True)
                response = self.forward(inject_euicc(request))
                status = tss_status(response)

            # Only the main restore-signing reply contains ApImg4Ticket.
            # Baseband, Rose, and Cryptex replies safely return None here.
            ticket = ticket_from_tss_response(response)
            if ticket is not None and self.server.ticket_directory is not None:
                metadata = request_identity(request)
                metadata["profileID"] = self.server.profile_id
                publish_ticket(
                    ticket,
                    self.server.ticket_directory,
                    source="apple-tss-response",
                    metadata=metadata,
                )
                print("[tss] captured and validated ApImg4Ticket", flush=True)

            print(f"[tss] upstream status: {status or 'unknown'}", flush=True)
            self.send_response(200)
            self.send_header("Content-Type", "application/x-www-form-urlencoded")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)
        except Exception as error:
            message = f"Liter8 TSS proxy failed: {error}".encode()
            self.send_response(502)
            self.send_header("Content-Length", str(len(message)))
            self.end_headers()
            self.wfile.write(message)

    @staticmethod
    def forward(request_body: bytes) -> bytes:
        request = urllib.request.Request(
            UPSTREAM_TSS_URL,
            data=request_body,
            headers={
                "Content-Type": "text/xml; charset=utf-8",
                "User-Agent": "InetURL/1.0",
                "Cache-Control": "no-cache",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read()

    def log_message(self, format: str, *arguments: object) -> None:
        # Lifecycle and upstream status are enough; suppress the noisy access log.
        return


def publish_ready(path: Path, *, pid: int, port: int) -> None:
    """Publish readiness atomically so the parent never reads partial JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as temporary:
        temporary_path = Path(temporary.name)
        json.dump({"pid": pid, "port": port}, temporary)
        temporary.write("\n")
    os.replace(temporary_path, path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--ready-file", type=Path, required=True)
    parser.add_argument("--ticket-directory", type=Path)
    parser.add_argument("--profile-id", default="unknown")
    arguments = parser.parse_args()

    # Port zero asks the kernel for an unused port, avoiding collisions with a
    # forgotten manual proxy while remaining reachable only from this Mac.
    server = HTTPServer((arguments.bind, arguments.port), TSSProxyHandler)
    server.ticket_directory = arguments.ticket_directory
    server.profile_id = arguments.profile_id
    port = server.server_address[1]
    publish_ready(arguments.ready_file, pid=os.getpid(), port=port)
    print(f"[tss] listening on http://{arguments.bind}:{port} (pid {os.getpid()})", flush=True)
    server.serve_forever(poll_interval=0.2)


if __name__ == "__main__":
    main()
