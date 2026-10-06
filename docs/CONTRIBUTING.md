# Contributing to Liter8

PRs welcome on patch resolution, new firmware support, workflow fixes, and anything that makes the research easier to reproduce. The bar is the same throughout: every supported byte needs a reason, every supported build needs evidence.

> [!WARNING]
> Never commit an IPSW, an extracted Apple binary, an SHSH blob, an APTicket, a device identifier, a private key, a generated work directory, or a device log with personal data in it.

## Before you start

Read [README.md](../README.md), then [CODEBASE_GUIDE.md](../CODEBASE_GUIDE.md), then whichever of these matters for your change:

- [FIRMWARE_SUPPORT_GUIDE.md](FIRMWARE_SUPPORT_GUIDE.md) for what "supported" means
- [ADDING_FIRMWARE_SUPPORT.md](ADDING_FIRMWARE_SUPPORT.md) if you are porting a build
- the latest note under `docs/runs/` if you are touching the device workflow
- [the 24A435 note](plans/IOS_27_24A435_RC_PATCHES.md) for a worked multi-build resolver example

Then read the resolver and the tests closest to what you are changing.

## Setting up

```sh
git clone --recurse-submodules https://github.com/Xplo8E/liter8.git
cd liter8
make setup
make
make test
```

`make setup` builds the pinned `idevicerestore` and makes Liter8's own Python environment. Nothing goes in globally. Test targets are listed in [CODEBASE_GUIDE.md](../CODEBASE_GUIDE.md).

Private Apple binaries live outside the repo. Point the suite at them rather than copying them in:

```sh
LITER8_FIXTURE_ROOT=/path/to/private/research make test-fixtures
```

Tests that need a binary you do not have will skip. If one skips, say so in the PR and say which claim is therefore unverified.

## Working without a device

You do not need a phone to work on a resolver.

`survey <extracted-dir>` runs every plan over an extracted firmware at once. Start there on a new build. Add `--guards` when you are ready to write a profile and it prints one, measured off the root filesystem. That part takes minutes and about 9 GB, so it is not the default.

`resolve` reports what a plan would do and leaves the input alone. `--json` for records.

```sh
.build/release/liter8 resolve iboot ibss-normal /path/to/iBSS.raw --json
```

`apply` writes a patched copy somewhere else. `verify` checks a binary against a fixture.

```sh
.build/release/liter8 apply kernel restore /path/to/kernelcache.raw /path/to/kernelcache.patched
.build/release/liter8 verify fixtures/24A5390f/n104ap/kernel-restore-n104-24A5390f.json /path/to/kernelcache.raw
```

`inspect` gives you segments, strings, xrefs, disassembly and masked pattern search, which is what you want when a signature stops matching.

Fixture offsets are oracles for `verify` and nothing else. Resolution never falls back to them. A plan fails rather than guessing when its evidence is missing, duplicated or inconsistent.

## Design rules

### Resolve from evidence

A resolver finds its site from structure, control flow, references and instruction semantics. If the evidence is missing, duplicated or inconsistent it must reject, not pick the nearest candidate.

> [!IMPORTANT]
> A known offset is never a runtime fallback. Known offsets belong in fixtures, which check the resolver's output.

Compiler output changed? Add a signature variant. ABI or replacement behavior changed? Add a payload variant. Do not weaken a uniqueness check to make a new build pass. That is the one shortcut that will cost someone a phone.

### Keep the layers apart

Swift owns firmware identity, parsing, patch discovery, guarded writes, container handling and verification. Python owns the generic macOS and device orchestration, where Swift would add no safety and no clarity. Profiles pick which signature and payload variant applies. Fixtures are independent oracles. Workflow scripts stay build-independent.

### Explain raw bytes

Every opcode, mask, replacement word and magic constant needs a comment near it. Say what the instruction decodes to, why it identifies this target rather than a similar one, which operands are fixed and which come from the input, and what you are assuming about ABI, alignment, branch range or code caves.

Prefer a named constant or a small typed struct to an anonymous array of hex words. Signatures go under `Sources/Liter8Core/Profiles/`. Patch bytes that vary by firmware family go under `Profiles/Payloads/`.

### Keep writes guarded

A plan resolves and validates every record before anything is written. Each record carries its exact expected pre-image. One mismatch fails the whole operation, and nothing is left half-patched.

## Adding a firmware build

[ADDING_FIRMWARE_SUPPORT.md](ADDING_FIRMWARE_SUPPORT.md) is the full checklist. The minimum is:

1. Product version, build ID, product type, board, chip ID, board ID, and the component paths the manifest selects.
2. Clean input sizes, SHA-256 hashes, Mach-O UUIDs, embedded fingerprints.
3. Every required resolver classified: unchanged, new signature variant, new payload variant, or new resolver.
4. Manifests under `fixtures/<build>/<board>/`.
5. Tests for the clean input, the wrong input, a missing anchor, duplicate candidates, a bad pre-image, and complete output parity.
6. A run note under `docs/runs/` once you start on hardware.

Do not add a `DeviceWorkflowProfile` before checking the manifest identity and component mapping against a real IPSW. Do not call a profile supported before the whole device workflow has passed on a phone.

## Device evidence

A build that compiles is not a validated device. For an end-to-end claim, record each of these separately, because they fail separately:

CFW construction and artifact verification. Restore completion and APTicket capture. SSHRD construction and boot. System, Data and Preboot provisioning checks. Normal boot and what the screen actually did. Bootstrap finalization, Dropbear, launchd jobs, health checks.

Then record every failure, retry, manual step and device-visible symptom. Those are the parts someone reproducing your work will actually need.

Keep what you observed separate from what you think it means. Include the command, the build, the board, input and output hashes, and the relevant log. Strip ECIDs, serial numbers, tickets, keys and network credentials.

## Pull requests

One resolver family, one build, one workflow fix, or one documentation change per PR. Say what changed and why. Name the build and board. Name the semantic anchors and what failure you expect on wrong input. List the tests you ran, and the private-fixture tests that skipped. Give the device evidence, or state plainly that you did not run it. Say what is still broken.

> [!IMPORTANT]
> Do not describe a hypothesis or a resolver-only result as device support. There are three states and they are not interchangeable: pending research, resolver verified, end-to-end verified.

No build products, `.liter8` directories, setup caches or copied firmware in a PR. A third-party binary or payload needs a documented source, version, hash, license and redistribution permission before it goes in `tools/`.

## Writing docs

Write for whoever has to reproduce this. Exact paths, commands, functions, offsets, hashes, failure messages. Say why a patch exists and what would prove it wrong.

Avoid a claim like "works on iOS 27" when you tested one build on one board.

No em-dashes. Use callouts sparingly: `[!NOTE]` for context worth stopping at, `[!IMPORTANT]` for an invariant, `[!WARNING]` for something destructive or private. If a page has four of them, none of them is doing any work.
