# Contributing to Liter8

Liter8 accepts changes that improve patch resolution, add reviewed firmware support, strengthen the workflow, or make the research easier to reproduce. Every supported byte must have a reason, and every supported build must have evidence.

## Before you start

Read these in order:

1. [README.md](../README.md)
2. [CODEBASE_GUIDE.md](../CODEBASE_GUIDE.md)
3. [FIRMWARE_SUPPORT_GUIDE.md](FIRMWARE_SUPPORT_GUIDE.md)
4. [ADDING_FIRMWARE_SUPPORT.md](ADDING_FIRMWARE_SUPPORT.md)
5. The resolver and tests closest to your change

For device workflow changes, also read the latest relevant run under `docs/runs/`. For a concrete multi-build resolver example, read the retained `24A435` research note under `docs/plans/`.

> [!WARNING]
> Do not commit IPSWs, extracted Apple binaries, SHSH blobs, APTickets, device identifiers, private keys, generated work directories, or device logs that contain personal data.

## Set up a development checkout

```sh
git clone --recurse-submodules https://github.com/Xplo8E/liter8.git
cd liter8
make setup
make
make test
```

`make setup` builds the pinned `idevicerestore` and creates an isolated Python environment. It does not install Python packages globally.

Use the debug executable during development:

```sh
.build/debug/liter8 profiles
.build/debug/liter8 fw actions
```

Use a release build for repeated kernelcache scans:

```sh
make release
.build/release/liter8 resolve kernel restore /path/to/kernelcache.raw
```

## Design rules

### Resolve from evidence

Runtime resolvers locate a patch from structure, control flow, references, and instruction semantics. They must reject missing, duplicated, or inconsistent evidence.

> [!IMPORTANT]
> Never use a known offset as a runtime fallback. Known offsets belong only in exact-build fixtures that verify the resolver's output.

If compiler output changes, add a reviewed signature variant. If the target's ABI or replacement behavior changes, add a payload variant. Do not weaken a uniqueness check to make a new build pass.

### Keep responsibilities separate

- Swift owns firmware identity, parsing, patch discovery, guarded writes, IMG4/IM4P handling, and verification.
- Python owns generic macOS and device orchestration where Swift adds no useful safety or clarity.
- Profiles select reviewed signature and payload variants.
- Fixture manifests are independent exact-build oracles.
- Workflow scripts must remain build-independent.

### Explain raw bytes

Every opcode, mask, replacement word, byte string, and magic constant needs a nearby comment that explains:

- the decoded instruction or represented data;
- why it identifies the target or implements the patch;
- which operands are fixed and which are derived from the input;
- any ABI, alignment, branch-range, or code-cave assumption.

Prefer named constants and small typed structures over anonymous arrays of hex words. Keep signatures under `Sources/Liter8Core/Profiles/`; keep firmware-varying patch bytes under `Sources/Liter8Core/Profiles/Payloads/`.

### Preserve guarded writes

A patch plan must resolve and validate every record before writing any output. Each record needs the exact expected pre-image. A mismatch must fail the whole operation without leaving a partially patched file.

## Adding a firmware build

Use [ADDING_FIRMWARE_SUPPORT.md](ADDING_FIRMWARE_SUPPORT.md) as the full checklist. At minimum, a new build needs:

1. Product version, build ID, product type, board, chip ID, board ID, and manifest-selected component paths.
2. Clean input sizes, SHA-256 hashes, Mach-O UUIDs, and embedded fingerprints.
3. A classification of every required resolver as unchanged, new signature variant, new payload variant, or new resolver.
4. Exact-build manifests under `fixtures/<build>/<board>/`.
5. Clean-input, wrong-input, missing-anchor, duplicate-candidate, pre-image, and complete-output parity tests.
6. A run note under `docs/runs/` when physical-device validation begins.

> [!NOTE]
> Resolver coverage, artifact construction, restore success, SSHRD boot, normal boot, and post-boot health are separate claims. State exactly which level has been demonstrated.

Do not add an `IPSWWorkflowProfile` until the manifest identity and component mapping have been checked against the actual IPSW. Do not mark a profile fully supported until the complete physical-device workflow has passed.

## Tests

Run the smallest relevant test while editing, then the broader suite before a pull request:

```sh
make test           # Fast unit suite; private binaries may skip
make test-fixtures  # Optimized Beta 4 and 24A435 fixture verification
make integration    # Host workflow and orchestration tests
make test-full      # All optimized resolver tests except uncached E2E
make test-e2e       # Uncached production-composition resolver test
make check          # Full resolver, E2E, and integration tiers
```

Private Apple binaries may live outside the repository. Point the full suite at them without copying them into the checkout:

```sh
LITER8_FIXTURE_ROOT=/path/to/private/research make test-fixtures
LITER8_FIXTURE_ROOT=/path/to/private/research make test-full
```

`test-fixtures` verifies exact offsets, original bytes, replacements, and complete patched-output hashes for the Beta 4 and `24A435` manifests. It also checks that `apply --records-out` publishes records from the same guarded apply operation. `test-e2e` deliberately repeats the uncached composite resolver and is kept separate because it is slower.

If a required private fixture is unavailable, say which test skipped and which claim remains unverified.

## Device evidence

A successful build is not device validation. For an end-to-end support claim, record:

- CFW construction and complete artifact verification;
- restore completion and restore-bound APTicket capture;
- SSHRD construction and boot;
- System, Data, and Preboot provisioning checks;
- normal boot and expected display behavior;
- bootstrap finalization, Dropbear access, launchd jobs, and health checks;
- any failure, retry, manual step, and device-visible symptom.

Keep observations separate from explanations. Include the exact command, build, board, input hashes, output hashes, and relevant logs. Remove ECIDs, serial numbers, tickets, keys, network credentials, and other private values.

## Pull requests

Keep a pull request focused on one resolver family, firmware build, workflow fix, or documentation change. Describe:

- what changed and why;
- the firmware build and board, when applicable;
- the semantic anchors and expected failure behavior;
- tests run and their results;
- private-fixture tests that skipped;
- physical-device evidence, or a clear statement that it was not performed;
- remaining limitations.

> [!IMPORTANT]
> Do not describe a hypothesis or resolver-only result as verified device support. The repository uses three useful states: pending research, resolver verified, and end-to-end verified.

Do not add generated build products, `.liter8` work directories, setup caches, or copied firmware artifacts to a pull request. Third-party binaries and payloads also require documented source, version, hash, license, and redistribution permission.

## Documentation style

Write for the next researcher who must reproduce the work. Use exact paths, commands, functions, offsets, hashes, and failure messages. Explain why a patch exists and what would disprove it. Avoid vague claims such as "works on iOS 27" when only one build and board were tested.

Use GitHub callouts sparingly:

- `[!NOTE]` for useful context;
- `[!IMPORTANT]` for invariants and required checks;
- `[!WARNING]` for destructive actions or private artifacts.
