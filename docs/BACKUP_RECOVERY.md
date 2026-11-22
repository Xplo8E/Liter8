# Optional backup helper

These host-side scripts create a local iOS backup and optionally stage selected
files over SSH. They are **not part of `liter8 fw`**. They do not install firmware,
prevent an erase, restore apps or recover SEP/Keychain data.

## Requirements

Python 3.9+, libimobiledevice for backup creation, and OpenSSH for optional
staging. Encrypted backups also need the pinned Python dependency:

```sh
python3 -m pip install -r requirements-encrypted.txt
```

## Before an erase

Connect a normally booted, unlocked iPhone that trusts the Mac:

```sh
python3 scripts/backup_wizard.py before --mode encrypted --post-action manual
```

The backup is stored under `~/Liter8Backups/` by default. For encrypted copies,
the wizard asks for the existing backup password, decrypts the index and
checks each selected file using temporary plaintext. It removes the temporary
files and never saves the password. Failed checks block session verification.

This does **not** prove every item in the backup can be restored, nor does it
check iCloud-only content. Keep a separate, trusted backup.

## After boot

For SSH staging, choose `auto` during `before` and manually run `after`
once an SSH server is already available:

```sh
python3 scripts/backup_wizard.py after --ssh-host 127.0.0.1 --ssh-port 2222
```

Only selected photos, videos, recordings and documents are copied to a separate
staging folder. Native iOS app databases are not modified. Choosing `manual`
instead keeps the backup on the Mac and shows a local extraction command.

To scan or extract an existing local backup without the wizard:

```sh
python3 scripts/backup_recovery.py --backup /path/to/backup
python3 scripts/backup_recovery.py --backup /path/to/backup --extract
```

Exports use fresh private directories. Incomplete extraction fails instead of
reporting success. The wizard records backup manifest hashes and refuses a later
transfer if those files change.

## Tests

```sh
python3 -m unittest discover -s Tests/BackupRecoveryTests -p 'test_*.py' -v
```

Tests use synthetic data and simulated SSH. No real-device restore or native
app import has been verified. Never put backups, IDs, passwords or keys in a PR.
