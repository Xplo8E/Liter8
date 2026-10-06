#!/usr/bin/env python3
"""Select one APFS volume by role from SSHRD's textual ioreg output."""

import re
import sys


def volume_for_role(text, role):
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)
    matches = []
    for block in re.split(r"(?m)^.*\+-o .*<class AppleAPFSVolume,", text)[1:]:
        roles = re.search(r'"Role"\s*=\s*\(([^)]*)\)', block)
        bsd = re.search(r'"BSD Name"\s*=\s*"(disk[0-9]+s[0-9]+)"', block)
        if roles and bsd and role in re.findall(r'"([^"]+)"', roles[1]):
            matches.append('/dev/' + bsd[1])
    if len(matches) != 1:
        raise ValueError(f"expected one APFS {role} volume, found {len(matches)}")
    return matches[0]


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit('usage: apfs_role.py ROLE < ioreg.txt')
    try:
        print(volume_for_role(sys.stdin.read(), sys.argv[1]))
    except ValueError as error:
        sys.exit(str(error))
