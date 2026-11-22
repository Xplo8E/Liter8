# Host file safety review

Scope: shared host-side file handling, using synthetic local files only.
No device operations, firmware patches or authentication changes.

## Findings and fixes

| Priority | Location | Trigger and consequence | Fix |
| --- | --- | --- | --- |
| P1 | scripts/liter8_workflow.py:254, Context.backup | First copy fails after writing some bytes. A later call trusts the partial .bak, so the original can be lost once the working copy changes. | Copy to a temporary regular file, then publish without overwriting an existing backup. |
| P2 | scripts/liter8_workflow.py:265, Context.reset_to_pristine | Copy fails after truncating the destination. The current file becomes partial even though the saved copy remains available. | Replace the destination only after a complete copy. |
| P2 | scripts/liter8_workflow.py:166, Context.component/prepare_cfw/backup | Existing file or directory links are accepted as trusted state. A linked mutable directory escapes the intended workspace, and backup links can read or overwrite unrelated files. | Refuse linked mutable roots, completion markers, sources and backups; check regular file types. |

These defects are build-independent host file operations. Minimal regression
cases are test_interrupted_backup_does_not_leave_a_pristine_marker,
test_failed_restore_preserves_current_file_and_backup, and
test_completion_marker_cannot_make_a_linked_workspace_trusted in
Tests/host-file-safety-tests.py.

## Branch coverage

| Branch | Reviewed commit | Shared helper blob | Original regression result |
| --- | --- | --- | --- |
| main | 8c8629e5497cfa0b469ee41d6085f54efc4e34c0 | 2297bf08b62743d058e5a471753336fbd0af7a67 | 14 tests, 12 failures |
| keychain-master-owner | 5dd3e55f5e09a8b300cb3b2973af70a6d05571d6 | same | 14 tests, 12 failures |
| research/e07-passcode-gate | d538f6048407928ead92cbbb0f717dc01c46c47d | same | 14 tests, 12 failures |

The shared file was loaded from each Git ref and tested independently.
This is not a review of every file or of the branches' authentication changes.

## Validation

- make test-host-files: 14/14 pass after the fixes.
- Six existing ContextTests pass both before and after the changes.
- Tests cover interrupted copies, cancellation, retries, first-writer wins,
  link rejection, a missing destination and preservation of unrelated files.
- compileall and git diff --check pass.

The same backup filename, return value and copy2 metadata behavior are retained.
A missing target can still be recreated from an existing regular backup.
The clone and component callers now fail early on a linked mutable root;
ordinary source-tree component lookup is unchanged. No boot or provisioning
operation was exercised.

Full Swift/macOS suites were not run: this environment has no Swift or macOS
tools. No claim about SEP, passcodes or hardware compatibility follows from
these host-only tests. Existing partial backups made by older code cannot be
identified or repaired by these changes; preserve an independent original.
