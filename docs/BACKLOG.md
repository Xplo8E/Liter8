# Liter8 backlog

## P1: Make `fw get-boot` and `fw get-rd` incremental

Both commands currently rebuild every artifact even when the IPSW, APTicket, patch plans and bundled payloads are unchanged. This makes normal boot and SSHRD iteration unnecessarily slow.

Before optimizing, add per-stage elapsed-time logging so the actual cost is visible. Then investigate:

- cache extracted IM4P payloads by source-file hash;
- reuse patched and signed artifacts only when the source, selected firmware profile, patch plan, boot arguments, APTicket and Liter8 version all match;
- build independent firmware IMG4 artifacts concurrently;
- avoid repeating the common iBSS/iBEC base patch work while preserving the iBSS-only n104 display patch;
- cache the expensive SSHRD DMG construction using the restore ramdisk and SSH payload hashes as inputs.

Cached output must still pass the existing payload, IMG4 and `liter8-boot.json` hash verification. A cache mismatch or incomplete entry must fall back to a clean rebuild, never a partially reused boot set.

Acceptance criteria:

- the first run remains a fully verified clean build;
- an unchanged second run clearly reports cache hits and is substantially faster;
- changing any patch input, boot argument, ticket or payload invalidates only the affected artifacts;
- `fw boot` and `fw boot-rd` continue rejecting stale or mode-mismatched sets.
