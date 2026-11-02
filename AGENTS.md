# Liter8 agent instructions

These instructions apply to the entire repository. Use them for code review, debugging, and implementation tasks. Prefer a concrete, evidence-backed finding over a speculative warning. Do not modify code unless the task requests a change.

## Project contract

Liter8 is a macOS-hosted, tethered custom-firmware and jailbreak workflow for iOS 27-era A13 devices, built on usbliter8. It discovers and guards firmware patches, constructs restore and normal-boot artifacts, orchestrates an erase restore and SSH ramdisk provisioning, and sends the boot chain from pwn DFU. The primary device-validated target is iPhone 11 (`iPhone12,1`, `n104ap`). Other devices, boards, and firmware builds have different validation states.

**This is a firmware patcher, not a collection of fixed offsets.** A patch is acceptable only when its location and original bytes are derived from the supplied binary and independently verified. A compiled binary, a matching resolver, a constructed IMG4, and a successful hardware boot are four different levels of evidence.

Read `README.md`, `CODEBASE_GUIDE.md`, and `docs/CONTRIBUTING.md` before substantial work. For firmware or board support also read `docs/FIRMWARE_SUPPORT_GUIDE.md` and `docs/ADDING_FIRMWARE_SUPPORT.md`. Read the matching design note, run log, resolver, and tests before editing a subsystem. Some prose documentation can lag the implementation: verify commands, paths, profiles, and behavior against **current source and tests**, not an older example. In particular, the present CLI entry point is `Sources/Liter8CLI/Liter8Command.swift`, using Swift ArgumentParser.

## Architecture and ownership

| Location | Responsibility |
| --- | --- |
| `Sources/Liter8CLI/` | ArgumentParser command tree, `resolve`/`apply`/`verify`/`inspect`/`survey`, firmware command validation and workflow dispatch |
| `Sources/Liter8Core/Binary/` | Bounded binary reads, ARM64 analysis, Mach-O/Objective-C structure, read-only inspection |
| `Sources/Liter8Core/Resolvers/` | Semantic patch discovery for iBoot, kernel, TXM, userland, and DeviceTree |
| `Sources/Liter8Core/Profiles/` | Kernel fingerprint to signature/payload variant mapping; firmware-family patch bytes under `Payloads/` |
| `Sources/Liter8Core/Patching/` | `PatchRecord`, guarded preflight/application, exact-build fixture verification |
| `Sources/Liter8Core/Firmware/` | IPSW identity and extraction, exact device-workflow profiles, Swift-to-Python context, IMG4/IM4P, host tools and process supervision |
| `scripts/` | Build-independent Python host orchestration: CFW, boot artifacts, APTickets/TSS, disk images, SSHRD, USB boot/restore and provisioning handoff |
| `device/` | SSHRD/on-device provisioning, launchd cache and userland fixups, bootstrap resources and native helpers |
| `Tests/Liter8CoreTests/`, `Tests/*.py`, `Tests/*.sh` | Swift unit/fixture tests and workflow/CLI/integration tests |
| `fixtures/<build>/<board>/` | Version-bound JSON verification oracles; **not** runtime offsets |
| `payloads/`, `tools/`, `vendor/` | Hash-pinned inputs, host binaries and Git submodules; preserve provenance and pins |
| `docs/` | Design decisions, firmware support procedures, research evidence and device-run records |

The ownership boundary is deliberate:

- **Swift decides:** firmware identity, component mapping, binary parsing, patch discovery, signature/payload selection, guarded patching, IMG4/IM4P processing, and verification.
- **Python orchestrates:** staging, copying, disk-image operations, invoking external tools, signing and packaging, device sequence and provisioning. It must call back into the running Liter8 Swift executable (`LITER8_SELF`) for semantic binary patches.
- **Device scripts perform reviewed provisioning:** changes to System/Data/Preboot, launchd jobs, signing, pairing and other boot-time fixes need exact-build guards, reversible/idempotent behavior where supported, and device-visible verification.
- Do not introduce build-specific file names, instruction offsets, device-class decision trees, or duplicate patch logic into generic `scripts/` workflows. Component locations come from the selected `BuildManifest.plist` identity and the Swift-generated workflow context.

### Trace a firmware operation end to end

1. `Sources/Liter8CLI/Liter8Command.swift` and `FirmwareCommands.swift` define the accepted command and options. `FirmwareWorkflowRunner.swift` validates firmware/board identity. `FirmwareScriptRunner.swift` maps prepared actions to bundled Python helpers.
2. `Sources/Liter8Core/Firmware/IPSWManifest.swift` owns exact `DeviceWorkflowProfile` selection. `FirmwareWorkflowContext.swift` selects a unique, non-research erase identity and exposes validated semantic paths to Python.
3. A resolver in `Sources/Liter8Core/Resolvers/` emits `PatchRecord` values. `GuardedPatchApplier` checks every record before modifying an in-memory copy. CLI `apply --records-out` emits evidence from the **same resolution pass**.
4. `scripts/liter8_workflow.py` invokes that CLI, stages the patched target, and publishes it. `make_cfw.py`, `boot_artifacts.py`, `rootfs.py`, `sshrd.py`, `ramdisk_patch.py`, and `device_provision.py` coordinate the surrounding artifacts.
5. `verify_cfw.py` and boot-artifact manifests check generated inputs. `restore_cfw.py` and `device_boot.py` are the hardware-facing paths; `apticket.py` and the loopback `tss_proxy.py` handle restore-bound signing tickets.

For a regression, follow the exact command through **all affected layers** rather than reviewing only the changed helper.

## Change impact and regression review (all code changes)

For every new feature, patch, hook, tweak, or change to existing behavior, review what it can **break that previously worked**, not only whether its intended path works. This applies to Swift, Python, native C/C++/Objective-C code, shell scripts, profiles, resources, and tests.

- Trace the change from its entry point through direct/indirect callers, consumers, generated artifacts, installation steps, persistent state and boot-time execution. Check dependencies shared with unrelated features. Do not assume a change is isolated because its source file is.
- Compare old and new behavior for the intended case, **feature disabled**, missing inputs/payloads, wrong build/board, repeated invocation, partial failure, and reboot/reconnect where relevant. An optional feature must not silently become mandatory or default-on.
- Identify affected user-visible and recovery paths: boot and repeat boot, process/app launch, SpringBoard, rootless bootstrap/Sileo, SSH access, pairing/RemoteXPC/DeveloperDiskImage, cellular and other daemon services. Check only plausible dependencies, but explicitly state which critical paths were assessed and which lack evidence.
- Check ordering, lifetimes and shared state: mount availability at load time, launchd job dependencies, environment propagation, file ownership/modes, path visibility under sandbox rules, signing, hashes, markers, stored keys, and cleanup. New code must not weaken existing fail-closed guards to make its feature work.
- Add or update negative and regression tests at the owning layer. Run the relevant existing tests as well as new ones; tests of generated files or source strings are **not** proof that a hook executes correctly on device. Separate static, mocked, exact-firmware, and hardware observations.
- In reviews, flag concrete cross-feature regressions even if the changed feature itself works. If a critical effect cannot be tested without a real device, record it as **unverified**, identify the specific failure to watch for and the smallest discriminating test, and do not claim compatibility.

## Non-negotiable correctness and safety invariants

### Firmware identity and supported hardware

- `DeviceWorkflowRegistry` gates hardware workflows using the actual `BuildManifest.plist` product version, build, product type, device class, chip ID and board ID. A filename is not firmware identity. Multi-board IPSWs must not silently select a board; require an unambiguous match or explicit `--board`.
- `KernelResolverProfileRegistry` uses an embedded XNU fingerprint to select supported signature/payload variants. It is **not** a grant to perform a device workflow. Several Apple build IDs can share an XNU fingerprint. Unknown or ambiguous fingerprints must not be guessed into a known profile.
- `fw prepare` may extract an **unprofiled** IPSW for research, marked extraction-only. It must not thereby authorize `make-cfw`, restore, provisioning or boot. Existing experimental profiles require explicit `--experimental` opt-in; prepared device actions independently revalidate the extracted manifest.
- Do not promote an experimental profile or claim hardware support from resolver, artifact, or synthetic-test success alone. Consult the actual device-run evidence under `docs/runs/`. Maintain a clear distinction between pending research, resolver verified, artifact verified, and device tested.
- Do not relax guards, copy stock launchd/cache hashes or Setup method counts from another build, or reuse board-specific boot additions without measuring the target firmware. Treat known gaps, including SEP, cellular data and Apple services, as unresolved unless new evidence proves otherwise.

### Semantic patching

- **Never use a known offset as a runtime fallback.** Known offsets are permitted in fixture manifests, comments documenting observed evidence, and independent comparisons, not as the resolver's answer. The location must be rediscovered from the current input using semantic structure, xrefs, control flow, instruction properties and bounded patterns.
- Missing anchors, duplicated matches, incompatible ABI, unexpected instructions, unsupported variants and wrong pre-images must cause an explicit failure. Do not replace uniqueness checks with first-match selection, nearest-match heuristics, overly broad masks or silent partial patching.
- Keep signature variants separate from payload variants. Compiler/layout drift may justify a new signature; changed replacement semantics or ABI may justify a new payload. Avoid cloning a complete resolver to add one build.
- Every raw instruction word, mask, code cave and replacement byte sequence needs a nearby explanation of its decoded behavior, fixed versus variable bits, alignment, branch range, calling convention, and why the evidence identifies the intended operation. Verify file offsets versus VM addresses and raw payload offsets versus IM4P container bytes.
- Respect ARM64 instruction semantics, branch reachability, BTI/PAC landing pads, function entry versus writable stub entry, register/stack conventions, and preserved control flow. Do not infer a safe replacement solely from matching a byte pattern.
- `PatchRecord` originals and replacements must be nonempty, equal length, in bounds and nonoverlapping. `GuardedPatchApplier` accepts only exact original bytes or the exact already-applied replacement, preflights **the entire record set** before writing, and fails for every other state. Preserve that idempotency and all-or-nothing behavior **per patch plan**.
- Do not change plan composition casually. In particular, `KernelBootResolver`, `KernelBootCompatibilityResolver`, and `KernelDiagnosticResolver` intentionally select different patch sets. Review a plan change against both fixture hashes and the hardware-facing caller.

### Containers, extraction and artifact integrity

- Preserve IM4P fourcc, description and container metadata when replacing payloads. IMG4 creation embeds a device-provided IM4M/APTicket; it does not generate Apple's signature. Round-trip parse and verify produced containers.
- Preflight IPSW member paths, duplicates, symlinks, size limits and archive integrity before publishing extraction. Verify the actual extracted tree, including when reusing a completion marker. Preserve staging/rollback semantics; never treat a marker alone as proof of completeness.
- Keep the clean extracted firmware separate from mutable CFW/work outputs. Guard file/path containment and reject traversal, unsafe links, stale context, wrong profile, wrong mode and mismatched artifact hashes.
- Preserve current atomic publication boundaries: guarded patch output, records written for that same run, prepared extraction, and staged boot sets. Do not assume a multi-stage firmware workflow is globally atomic just because an individual output is.
- Before sending boot artifacts, validate `liter8-boot.json` against required filenames, selected profile, normal versus SSHRD mode, sizes and SHA-256 digests. Before provisioning, validate the exact root filesystem identity and its launchd/cache/Setup guards.
- Treat `--serial` as an explicit per-artifact boot-argument change. The `--demote-ap` path is documented as a non-booting research experiment; do not introduce it into the normal boot path or allow an inherited environment variable to silently enable it.

### Host processes, provisioning and sensitive data

- Scripts are loaded from the application's immutable resource directory, never from extracted IPSW contents or the mutable work directory. Preserve the Swift-generated context boundary, Python venv isolation and exact `LITER8_SELF` callback path.
- Review subprocess command construction, exit-status checks, timeouts, signal handling, cleanup and mount detach. `InterruptibleProcess` exists to prevent an interrupted firmware operation from leaving `idevicerestore`, USB tools or other grandchildren running. An aborted restore must not continue unattended.
- Rootfs and SSHRD operations may invoke macOS disk mounting or `sudo`. Preserve verification and cleanup for partial failures. On-device launchd-cache and binary changes must retain exact shape/count/hash guards, signing identifiers and entitlements as applicable, plus post-change verification.
- Treat TSS requests/responses, APTickets, signing material, ECIDs, nonces, serial numbers, credentials, pairing records and device logs as sensitive. Never print them in reviews, tests or new diagnostics. Do not commit IPSWs, extracted Apple binaries, SHSH blobs, tickets, private keys, generated work directories or logs containing personal information.
- Do not change vendored submodules, prebuilt tools, payload archives, their digests or redistribution assumptions without an explicit task and traceable source/version/license/hash evidence.

### Device-side hooks, tweak injection and bootstrap

Treat code in `device/` as executable boot/runtime behavior, **not** just payload-building data. A successful build, valid CodeDirectory, or intact installer hash does not prove a daemon survives the hook. Read `device/README.md` and the relevant hook, build script, provisioning step and existing tests together.

- **PID 1 and process-spawn injection:** `device/launchdhook/lhook.c` is weak-loaded by `/sbin/launchd` and interposes `posix_spawn`/`posix_spawnp`. Review the enable marker, hard denylist, configurable deny policy, missing-payload pass-through, constructor work and startup timing **before** changing injection. Check nested process propagation, `DYLD_INSERT_LIBRARIES` merging and deduplication, exact allocated-memory ownership, unexpected target processes, and the ability to disable injection without a successful normal boot. A mistake may prevent boot or cut off SSH recovery.
- **Tweak loading:** Check the interaction between `lhook`, `/var/jb/usr/lib/TweakLoader.dylib` (ElleKit), the TweakInject filters and any optional `systemhook` payloads. Verify that adding or removing a tweak does not broaden the injected process set, break unrelated spawns, force a missing library on dyld, introduce duplicate loader entries, or assume every sandboxed process can read the same files. Do not treat a single successful app injection as proof of system-wide stability.
- **Process-local shims:** For `device/pairingfix/`, `coreauthfix/`, `remotexpcfix/`, `fdrfix/`, `wififix/`, `launchdhook/systemhook_icon.c` and future hooks, verify the **exact target process**, intercepted selector/function and ABI, constructor/load order, symbol binding, recursion/reentrancy, memory ownership and original-call behavior. Where a hook has a marker or state predicate, require malformed/absent/disabled inputs and all nonmatching calls to retain stock behavior. Avoid broad keychain, LocalAuthentication, MobileKeyBag, FDR or sandbox changes to solve one measured case.
- **Load commands and signatures:** Follow `device/launchdhook/patch_launchd.py`, `resign_pagehashes.py`, `verify_diff.py`, native `build.sh` files, and `device/userland_fixups.py`. Check that Mach-O load commands fit verified padding, weak loads are intentional, the dylib exists at the correct **boot-time** filesystem path, `__interpose` is present only when intended, both required architecture slices are correct, and identifiers/entitlements/signatures and unrelated executable bytes are preserved and verified.
- **End-to-end installation:** Trace every new payload through `device/fetch_payloads.sh` → `scripts/device_provision.py` → `device/sshrd_provision.sh` → installed paths, launchd cache and `device/boot/jbboot.sh` or `device/finalize.sh` as applicable. Verify source hashes, staging, readback, permissions, first-boot defaults, `--check`, re-provision/idempotency, failure cleanup, rollback markers and reboot behavior. A built dylib with no verified deployment, activation or consumer is incomplete integration.
- **Per-boot jobs and bootstrap state:** Review daemon `ProgramArguments`, interpreter availability on the System volume, launchd supervision/KeepAlive, process lifetime, mount ordering, Data/Preboot dependencies and expected one-time versus per-boot work. Avoid background grandchildren, unbounded retries, repeated destructive setup, or changes that make Dropbear, `com.jbboot`, Sileo, persona setup, icon tokens or DDI services depend on an optional tweak.
- **Prove both paths:** Where feasible, test stock/pass-through and enabled behavior, matching and nonmatching processes, missing/corrupt payload or marker, double installation, partial provisioning, and clean restart. Build/link/signature checks and Python source-level assertions are useful **structural** evidence, not substitutes for exact-device hook and repeat-boot tests. Never enable injection or run on-device tests automatically during a code review.

## Review procedure and priorities

For code review, report actionable defects, not generic style advice. Focus in this order:

1. **Unintended hardware effects:** wrong device/board/build selection, unauthorized experimental fallback, an erase/restore/boot operation reached without its checks, or process cleanup that leaves a device tool running.
2. **Incorrect patch output:** semantic false positives, dropped/duplicated records, broadened signatures, invalid branch/ABI assumptions, patch-plan composition drift, unexpected pre-images or partial writes.
3. **Broken trust/identity boundaries:** untrusted archive paths, symlinks, stale manifests/markers, writable resource lookup, host-tool overrides, incorrect hash/signature/entitlement validation, unsafe mounted filesystem changes.
4. **Cross-feature device regressions:** a new tweak, hook, daemon fix or bootstrap step breaking launchd/spawn, SpringBoard, SSH recovery, pairing, cellular, Sileo, or repeat-boot behavior; absent or incorrect disabled/pass-through behavior.
5. **Workflow regressions:** restore versus normal-boot artifact mixups, wrong TSS ticket association, accidental loss of a successful prior output, changed boot upload ordering, idempotency/retry errors, interrupted mounting or provisioning.
6. **Coverage and documentation:** incorrect profile support claims, missing negative tests, fixture oracles that do not independently verify output, documentation that disagrees with current code.

Trace a suspected issue to a concrete input and execution path. Before calling it a bug, check adjacent validation, the caller, the relevant test and whether the purported state is actually reachable. Distinguish an implementation defect from an unverified hardware hypothesis. For assembly or firmware-specific claims, name the applicable build/board and cite the instruction or fixture evidence. If that evidence is unavailable, say so instead of inventing a symbol, constant, offset or result.

For every finding, give **severity, `path:line`, trigger/precondition, actual consequence, affected build/board if relevant, and a minimal reproducer or discriminating test**. Findings first, ordered by impact. Avoid speculative severity inflation and duplicate reports of the same root cause. If no actionable findings are supported, state that explicitly and list what could not be verified.

## Testing and validation

Requires macOS 14+, Swift 6 and the dependencies in `README.md`. `make setup` initializes pinned submodules, builds external tools and prepares the Python runtime; it can access the network and change local setup state. Use it only when needed, but note that the Python suites do need it: `scripts/restore_cfw.py` imports PyUSB at module scope, so `make integration` fails at import rather than reporting a test result until `requirements.txt` is installed.

| Command | What it verifies |
| --- | --- |
| `swift build` or `make` | Development build |
| `make test` | Fast Swift edit loop; excludes real kernel fixtures, release fixtures and uncached kernel end-to-end scan |
| `make release` | Optimized CLI for expensive firmware scans |
| `make test-fixtures` | Optimized exact-build fixture verification and apply-records checks, with private inputs |
| `make test-full` | Release-mode tests excluding the deliberately uncached kernel end-to-end check |
| `make test-e2e` | Uncached production kernel-plan composition against real fixture data |
| `make integration` | Swift/Python CLI handoff, IPSW robustness, Python workflow behavior and scoped CLI help, using synthetic/mocked inputs |
| `make check` | `test-full`, `test-e2e` and `integration` |

Private Apple binaries are **not** shipped. `LITER8_FIXTURE_ROOT` points to an operator-owned private fixture tree. A fixture test that **skips** because input binaries are missing does not prove the affected resolver or patched-output hash. Clearly report passes, failures, skips, and tests not run. Prefer release mode for full-size kernelcache scans and `resolve`/`inspect`/`survey` for non-mutating investigation.

Establish a baseline before attributing a failure. Run the same suite on the merge-base, not only on the branch under review: this tree can carry a pre-existing failure, and a test that asserts on source text rather than behavior goes stale when the code it greps for is refactored. Report a failure as pre-existing when the baseline shows it, and compare test **counts** as well as pass/fail so an added test is not mistaken for a fixed one.

Read a command's own exit status, never a pipeline's. `swift test 2>&1 | tail -25` reports `tail`'s status, so a failing suite looks like a pass. Redirect to a file and inspect it instead. This repo has shipped that exact bug before, in `device/setup_debugger.sh`, where a failed `apt` was reported as success.

When changing a resolver, test a clean exact-build input, missing/ambiguous anchors, modified pre-image, overlap/out-of-bounds where relevant, already-applied behavior, complete output hash and unrelated supported builds. When changing workflow code, exercise stale/wrong-board/wrong-mode state, path traversal, incomplete staging, rollback, subprocess failure, interruption and repeated execution. Use mocks/synthetic fixtures for host-device boundaries before proposing a hardware test.

**Agent execution boundary:** Do not automatically run `fw restore-cfw` (erase restore), `fw boot`, `fw boot-rd`, `fw bootstrap`, `fw provision`, `fw finalize`, `fw setup-*`, raw `device/` provisioning, `idevicerestore`, USB transports, or any other device-mutating step. Obtain explicit operator direction for the **exact device, build, work directory, action and expected data loss** before hardware operations. Treat disk-image mounting, `sudo`, signing, IPSW extraction and artifact generation as local side effects and use only task-approved paths. A code review does not authorize these commands.

## Changes and final response

- Make the smallest correct change at the owning layer. Do not hide regressions by bypassing guards or downgrading error handling. Update the affected tests, fixtures and focused documentation when behavior changes.
- Preserve explicit CLI option scoping in Swift ArgumentParser and the host/device boundary in the Python helpers. Do not resurrect old `main.swift` dispatch or introduce a second parser.
- Document the precise firmware/build/board and observed evidence for any new patch or support claim. Use an experimental workflow profile until an appropriate device-run record exists. Keep generated firmware, research-private paths and credentials out of commits.
- End an implementation response with changed files, verification commands and their actual results, skipped/unavailable checks, and any unverified hardware behavior. Never claim a build, fixture, restore or boot succeeded unless it was actually exercised.
