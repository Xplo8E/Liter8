# Adding firmware support

Liter8 separates firmware identity, resolver signatures, patch payloads, and
verification oracles. Keep those layers separate when adding a build.

## 1. Identify the firmware

Record the immutable build ID, product type, board, chip ID, board ID, and the
component paths selected from `BuildManifest.plist`. Add an
`IPSWWorkflowProfile` only after those values have been checked against the
actual IPSW.

Firmware selection must not depend on the archive filename.

## 2. Classify each existing resolver

Run the resolver against clean binaries from the new build and classify the
result:

- **unchanged**: the existing semantic evidence still selects exactly one site;
- **new signature variant**: the operation is unchanged but compiler output or
  surrounding control flow changed;
- **new payload variant**: the resolved function is the same but its ABI or the
  required replacement behavior changed;
- **new resolver**: the old evidence no longer identifies the operation safely.

Do not loosen uniqueness checks merely to make a new binary pass.

## 3. Keep opcodes readable

Signature words belong under `Sources/Liter8Core/Profiles/`. Patch bytes belong
under `Profiles/Payloads/` when they vary by firmware family. Every raw word or
byte sequence needs a nearby comment explaining the instruction or data it
represents and why it is part of the signature or payload.

Offsets do not belong in either registry.

## 4. Add exact-build oracles

Store manifests under:

```text
fixtures/<build>/<board>/
```

Each manifest should bind the test to the clean input SHA-256, expected original
bytes, resolved offsets, replacements, and complete patched-output SHA-256.
Large Apple binaries remain local and are skipped when absent.

Point tests at that private tree without encoding its location in source:

```sh
LITER8_FIXTURE_ROOT=/path/to/private/research make test-full
```

Known offsets verify a resolver result. They must never be consulted by runtime
resolution or used as a fallback.

## 5. Test failure behavior

Add focused tests for:

- the clean supported binary;
- a missing anchor;
- duplicate or ambiguous candidates;
- a wrong pre-image;
- profile mismatch;
- complete output parity with an independent implementation.

Run the responsive suite while developing, then the full optimized suite:

```sh
make test
make test-full
make integration
```

## 6. Validate the device workflow

Resolver parity proves bytes, not behavior. Record each stage separately:

1. CFW construction and verification.
2. Restore and APTicket capture.
3. SSHRD construction and boot.
4. Bootstrap and System/Data/Preboot provisioning.
5. Normal boot.
6. Post-boot finalization and repeated health checks.

Keep the resulting run note under `docs/runs/`. Mark partial resolver coverage
as research-only until the complete workflow has exact-device evidence.
