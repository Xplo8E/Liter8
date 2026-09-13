"""Shared, build-independent helpers for Liter8 firmware workflows.

The Swift launcher writes a context file from BuildManifest.plist and exports
its location as LITER8_CONTEXT.  Python only orchestrates files and host tools;
it never selects firmware offsets or embeds board-specific filenames.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path


class WorkflowError(RuntimeError):
    """A clear operator-facing workflow failure."""


@dataclass(frozen=True)
class Context:
    profile_id: str
    work: Path
    source: Path
    cfw: Path
    components: dict[str, str]
    liter8: Path
    resources: Path
    product_version: str = ""
    build: str = ""

    @classmethod
    def load(cls) -> "Context":
        context_path = required_environment_path("LITER8_CONTEXT")
        document = json.loads(context_path.read_text())
        if document.get("schema") != 1:
            raise WorkflowError(f"unsupported Liter8 context schema: {document.get('schema')}")

        work = Path.cwd().resolve()
        source = Path(document["sourceRoot"]).resolve()
        if not source.is_dir():
            raise WorkflowError(f"extracted IPSW is missing: {source}")
        return cls(
            profile_id=str(document["profileID"]),
            work=work,
            source=source,
            cfw=work / "CFW",
            components=dict(document["components"]),
            liter8=required_environment_path("LITER8_SELF"),
            resources=required_environment_path("LITER8_RESOURCE_DIR"),
            product_version=str(document.get("productVersion", "")),
            build=str(document.get("build", "")),
        )

    def component(self, name: str, *, in_cfw: bool = False) -> Path:
        """Resolve a semantic manifest component below its trusted tree."""
        try:
            relative = self.components[name]
        except KeyError as error:
            raise WorkflowError(f"BuildManifest has no {name} component") from error
        root = self.cfw if in_cfw else self.source
        result = (root / relative).resolve()
        if not result.is_relative_to(root.resolve()):
            raise WorkflowError(f"component {name} escapes its firmware tree: {relative}")
        return result

    @property
    def state(self) -> Path:
        """Return the selected work directory itself as mutable run state.

        The Swift launcher already runs this helper with cwd set to
        `--work-dir`. Appending another `.liter8` here made an operator-selected
        `.liter8` workspace become `.liter8/.liter8`.
        """
        self.work.mkdir(parents=True, exist_ok=True)
        return self.work

    def prepare_cfw(self) -> None:
        """Create a writable, copy-on-write clone of the extracted IPSW."""
        marker = self.cfw / ".copy-complete"
        if marker.is_file():
            try:
                recorded = json.loads(marker.read_text())
            except (OSError, ValueError) as error:
                raise WorkflowError(
                    "CFW has an untrusted legacy completion marker; use a clean --work-dir"
                ) from error
            expected = {"profileID": self.profile_id, "sourceRoot": str(self.source)}
            if recorded != expected:
                raise WorkflowError(
                    "CFW belongs to another firmware source; use a different --work-dir"
                )
            print("[*] CFW copy is already complete", flush=True)
            return
        if self.cfw.exists():
            raise WorkflowError(
                f"incomplete CFW directory exists: {self.cfw}; move it aside before retrying"
            )

        staging = self.work / f".CFW-clone-{uuid.uuid4()}"
        started = time.monotonic()
        print("[*] cloning extracted IPSW -> CFW (APFS copy-on-write)", flush=True)
        try:
            # macOS cp -c asks APFS to clone file extents. The new tree looks
            # like an independent copy, but unchanged multi-gigabyte images do
            # not consume another 10 GB or pass through the SSD again.
            result = subprocess.run([
                "/bin/cp", "-cR", "-p", self.source, staging,
            ])
            if result.returncode:
                raise WorkflowError(
                    "APFS copy-on-write cloning failed; place --work-dir on an APFS volume"
                )

            # The source extraction is intentionally read-only in places.
            # Patches replace files inside CFW, so grant only owner-write while
            # preserving every other permission bit copied from the IPSW.
            for directory, directories, files in os.walk(staging):
                for name in [*directories, *files]:
                    path = Path(directory) / name
                    mode = path.stat(follow_symlinks=False).st_mode
                    os.chmod(path, mode | stat.S_IWUSR, follow_symlinks=False)

            (staging / ".copy-complete").write_text(json.dumps({
                "profileID": self.profile_id,
                "sourceRoot": str(self.source),
            }, sort_keys=True) + "\n")
            os.replace(staging, self.cfw)
        finally:
            if staging.exists():
                shutil.rmtree(staging)
        print(f"[*] CFW clone ready in {time.monotonic() - started:.2f}s", flush=True)

    def backup(self, path: Path) -> Path:
        """Keep the pristine container used for repeatable extract/repack."""
        backup = path.with_name(path.name + ".bak")
        if not backup.exists():
            shutil.copy2(path, backup)
        return backup

    def reset_to_pristine(self, path: Path) -> Path:
        """Restore a component from its first-run backup before repatching."""
        backup = self.backup(path)
        shutil.copy2(backup, path)
        return backup

    def extract_im4p(self, source: Path, output: Path) -> None:
        print(f"[*] extracting IM4P payload: {source.name}", flush=True)
        output.parent.mkdir(parents=True, exist_ok=True)
        run([self.liter8, "im4p", "extract", source, output])

    def repack_im4p(self, original: Path, payload: Path, output: Path) -> None:
        print(f"[*] repacking IM4P payload: {output.name}", flush=True)
        run([self.liter8, "im4p", "repack", original, payload, output])

    def apply(
        self,
        component: str,
        plan: str,
        target: Path,
        *,
        record_name: str,
        capture_records: bool = True,
    ) -> None:
        """Resolve in Swift, save the oracle, then atomically apply in Swift."""
        print(f"[*] resolving {component}/{plan}: {target.name}", flush=True)
        if capture_records:
            records = run(
                [self.liter8, "resolve", component, plan, target, "--json"],
                capture=True,
            ).stdout
            records_dir = self.state / "patch-records"
            records_dir.mkdir(exist_ok=True)
            (records_dir / f"{record_name}.json").write_text(records)

        # Intermediates such as `.DeviceTree.im4p` are already hidden. Avoid
        # producing the confusing `..DeviceTree...` name while retaining a
        # hidden atomic output for ordinary names such as `iBSS.raw`.
        temporary_prefix = target.name if target.name.startswith(".") else f".{target.name}"
        with tempfile.NamedTemporaryFile(
            prefix=f"{temporary_prefix}.liter8-", dir=target.parent, delete=False
        ) as temporary:
            temporary_path = Path(temporary.name)
        try:
            run([self.liter8, "apply", component, plan, target, temporary_path])
            os.replace(temporary_path, target)
        finally:
            temporary_path.unlink(missing_ok=True)
        self.record_hash(target, record_name)

    def record_hash(self, target: Path, record_name: str) -> None:
        """Bind later verification to the exact artifact written by this run."""
        hashes = self.state / "artifact-hashes"
        hashes.mkdir(exist_ok=True)
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        (hashes / f"{record_name}.sha256").write_text(f"{digest}\n")


def required_environment_path(name: str) -> Path:
    value = os.environ.get(name)
    if not value:
        raise WorkflowError(f"{name} was not supplied by the Liter8 launcher")
    return Path(value).expanduser().resolve()


def run(
    arguments: list[object],
    *,
    capture: bool = False,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run without a shell and preserve live output unless data is requested."""
    command = [str(argument) for argument in arguments]
    # When stdout is machine-readable, capture only stdout. Stderr remains on
    # the terminal so Swift's early profile/progress messages are still live.
    result = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        env=environment,
    )
    if result.returncode:
        raise WorkflowError(
            f"command exited with status {result.returncode}: {' '.join(command)}"
        )
    return result


def main_guard(function) -> None:
    """Give workflow errors a short message instead of a Python traceback."""
    try:
        function()
    except (OSError, ValueError, WorkflowError) as error:
        raise SystemExit(f"[!] {error}") from error
