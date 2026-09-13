#!/usr/bin/env python3
"""Boot the restore iBSS and erase-restore the Liter8 CFW."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from apticket import TICKET_NAME, capture_from_debug_log, tickets_from_debug_log
from liter8_workflow import Context, WorkflowError, main_guard, run


def stage(number: int, title: str) -> None:
    """Make long restore logs readable without hiding the tool's live output."""
    separator = "+" * 72
    print(f"\n{separator}", flush=True)
    print(f"RESTORE STAGE {number}/5: {title}", flush=True)
    print(separator, flush=True)


def restore_log_path(context: Context) -> Path:
    """Allocate a new log file so a failed retry never overwrites its evidence."""
    logs = context.state / "logs"
    logs.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    candidate = logs / f"restore-cfw-{timestamp}.log"
    suffix = 1
    while candidate.exists():
        candidate = logs / f"restore-cfw-{timestamp}-{suffix}.log"
        suffix += 1
    return candidate


def executable_from_environment(variable: str, command: str) -> str:
    value = os.environ.get(variable)
    if value:
        path = Path(value).expanduser().resolve()
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
        raise WorkflowError(f"{variable} is not executable: {path}")
    found = shutil.which(command)
    if not found:
        raise WorkflowError(f"{command} is required; pass --{command} <executable>")
    return found


@contextmanager
def managed_tss_proxy(context: Context):
    """Run the bundled loopback proxy for exactly one restore."""
    proxy_script = context.resources / "scripts/tss_proxy.py"
    if not proxy_script.is_file():
        raise WorkflowError(f"bundled TSS proxy is missing: {proxy_script}")

    with tempfile.TemporaryDirectory(prefix="tss-proxy-", dir=context.state) as directory:
        ready_file = Path(directory) / "ready.json"
        pid_file = context.state / "tss-proxy.pid"
        process = subprocess.Popen([
            sys.executable, "-u", proxy_script,
            "--bind", "127.0.0.1", "--port", "0",
            "--ready-file", ready_file,
            "--ticket-directory", context.state,
            "--profile-id", context.profile_id,
        ], start_new_session=True)
        try:
            deadline = time.monotonic() + 10
            ready = None
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise WorkflowError(
                        f"managed TSS proxy exited with status {process.returncode} before readiness"
                    )
                if ready_file.is_file():
                    try:
                        ready = json.loads(ready_file.read_text())
                    except (OSError, ValueError):
                        ready = None
                    if ready is not None:
                        break
                time.sleep(0.05)

            if ready is None:
                raise WorkflowError("managed TSS proxy did not become ready within 10 seconds")
            if ready.get("pid") != process.pid:
                raise WorkflowError("managed TSS proxy published an unexpected PID")
            port = ready.get("port")
            if not isinstance(port, int) or not 0 < port < 65536:
                raise WorkflowError("managed TSS proxy published an invalid port")

            # Keep a visible PID for diagnostics during restore. The owning
            # parent removes it only after it has reaped this exact process.
            pid_file.write_text(f"{process.pid}\n")
            url = f"http://127.0.0.1:{port}"
            print(f"[+] managed TSS proxy ready: pid {process.pid}, {url}", flush=True)
            yield url
        finally:
            stage(5, "stop the managed TSS proxy and preserve diagnostics")
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            try:
                if pid_file.read_text().strip() == str(process.pid):
                    pid_file.unlink()
            except FileNotFoundError:
                pass
            print(f"[+] managed TSS proxy stopped: pid {process.pid}", flush=True)


def restore() -> None:
    context = Context.load()
    ibss = context.work / "Ramdisk/iBSS.raw"
    if not ibss.is_file():
        raise WorkflowError("restore iBSS is missing; run fw make-cfw first")
    if not context.cfw.is_dir():
        raise WorkflowError("CFW is missing; run fw make-cfw first")

    # Refuse to erase-restore from stale or modified output. This invokes the
    # same verifier used after make-cfw before the device is touched.
    stage(1, "verify every custom-firmware artifact")
    verifier = context.resources / "scripts/verify_cfw.py"
    run([Path(sys.executable), verifier])

    usbliter8ctl = shutil.which("usbliter8ctl")
    if not usbliter8ctl:
        raise WorkflowError("bundled usbliter8ctl is missing")
    idevicerestore = executable_from_environment("LITER8_IDEVICERESTORE", "idevicerestore")
    log_path = restore_log_path(context)

    stage(2, "start the restore-scoped TSS proxy")
    with managed_tss_proxy(context) as tss_url:
        stage(3, "boot the patched restore iBSS through RP2350")
        print("[*] booting restore iBSS through the RP2350 transport", flush=True)
        result = subprocess.run([usbliter8ctl, "boot", str(ibss)])
        if result.returncode:
            print("  usbliter8ctl returned after the expected USB transition", flush=True)

        stage(4, "personalize, transfer, ASR-restore, and finalize the CFW")
        print(f"[*] detailed idevicerestore log: {log_path}", flush=True)
        print(f"[*] erase-restoring CFW through managed proxy {tss_url}", flush=True)
        # Debug output stays live on the terminal and is also retained by
        # idevicerestore. The timestamped file is essential when the device
        # closes a transient service such as ASR before returning its reason.
        run([
            idevicerestore,
            "-d",
            "--logfile", log_path,
            "-s", tss_url,
            "-e", "-y",
            context.cfw,
        ])
        # The proxy normally publishes directly from Apple's response. Confirm
        # that idevicerestore later handed restored those exact bytes. Older
        # proxy builds can still recover through the debug-log fallback.
        ticket = context.work / TICKET_NAME
        logged_tickets = tickets_from_debug_log(log_path.read_text(errors="strict"))
        if ticket.is_file():
            if logged_tickets and logged_tickets != [ticket.read_bytes()]:
                raise WorkflowError("proxied and idevicerestore APTickets do not match")
        else:
            ticket = capture_from_debug_log(
                log_path, context.work, profile_id=context.profile_id
            )
        print(f"[+] verified restore APTicket: {ticket}", flush=True)
    print("[+] idevicerestore completed", flush=True)


if __name__ == "__main__":
    main_guard(restore)
