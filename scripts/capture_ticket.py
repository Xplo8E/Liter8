#!/usr/bin/env python3
"""Recover and publish the AP ticket from Liter8's latest successful restore."""

from apticket import capture_from_debug_log, latest_successful_restore_log
from liter8_workflow import Context, main_guard


def capture() -> None:
    context = Context.load()
    log = latest_successful_restore_log(context.work)
    ticket = capture_from_debug_log(log, context.work, profile_id=context.profile_id)
    print(f"[+] captured restore APTicket: {ticket}", flush=True)


if __name__ == "__main__":
    main_guard(capture)
