# Restore ramdisk payloads

`liter8 fw get-rd` expects these build-independent resources here:

- `ssh.tar.gz`: the SSH restore environment copied into the expanded ramdisk.
- `sftp_server_ents.plist`: entitlements used when re-signing sftp-server.

They are runtime payloads, not firmware signatures or build-specific workflow
code. Keep their provenance and hashes documented when importing them.

The bundled archive was copied byte-for-byte from the current public beta-4
workflow and has
SHA-256 `ddfa230acd2789c7e61ddb0d2ec3df9a6c741f2ddcab58fc1a826d278be1d74d`.
Liter8 verifies that digest before mounting or modifying any image. The
`--sshrd-payload` option remains available for an explicitly selected copy,
but the same digest is required.
The entitlement file here has SHA-256
`b84a4d58b616b66787f17614ebcdc279ce6e498918da265a201a025d9847991a`.
