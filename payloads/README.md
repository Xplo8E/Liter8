# Restore ramdisk payloads

`liter8 fw get-rd` expects these build-independent resources here:

- `ssh.tar.gz`: the SSH restore environment copied into the expanded ramdisk.
- `sftp_server_ents.plist`: entitlements used when re-signing sftp-server.

`liter8 fw provision` expects one more:

- `oslog`: the os_log reader installed on the device as `/var/root/oslog`.

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

## oslog

`oslog` streams the unified log from a running device. A normally booted
device has no `/usr/bin/log`, so this is the only way to read the log of a
booted Liter8 device from the host:

```sh
liter8/tools/logdev --info --debug
liter8/tools/logdev -p wifid
```

It is built from the `oslog` fork at `Xplo8E/oslog`, commit `ce3e9a8`
("Fix oslog message decoding on iOS 27"), with

```sh
xcrun --sdk iphoneos clang++ -arch arm64 -miphoneos-version-min=15.0 \
  -O2 -Wall -fobjc-arc -Iheaders main.mm -framework Foundation -o build/oslog
ldid -Sents.xml build/oslog
```

The fork is of limneos's oslog, which is Apple's LLDB os_log client under the
University of Illinois/NCSA Open Source License; `LICENSE.TXT` in that
repository is the license text and applies to these bytes.

Those exact bytes have SHA-256
`b15e0091dbf9d4276a2159d1f8f912425411c0b1516e8f0df873364ce909bbeb`, and
Liter8 verifies that digest before installing it. They were validated on
iPhone12,1 / n104ap, iOS 27.2 build 24B5089g: ten controlled messages and
1,646 live messages rendered without a compose failure. The upstream
`build/oslog` of the same commit differs in its ad-hoc signature blob only;
its `__text` segment is byte-identical, so a local rebuild is functionally the
same tool.

The commit that fixed the iOS 27 layout matters. Without it, every message
renders as `<compose failure [corrupt log]>`, because the message union moved
from `+0x30` to `+0x34` when Apple packed a UID into the entry prefix. The
reader selects the layout at runtime on iOS major version 27 and keeps the
legacy layout elsewhere. Only iOS 27.2 has been validated; other builds in the
same major version are unverified.

The binary carries Apple's private logging entitlements, which `logd` checks
before it opens a stream. It must therefore be copied byte for byte, and the
signature is written by `ldid`, whose CodeDirectory does not carry the ad-hoc
flag that the host `codesign` insists on. Do not "fix" the signature with
`codesign`: that would strip the entitlement blob and the tool would stop
working.
