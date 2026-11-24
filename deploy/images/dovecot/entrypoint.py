#!/usr/bin/python3
"""Dovecot container entrypoint.

Prepares the maildir volume, materialises the operator-owned (0600) passwd
mount — and the staged config, when present — as container-side copies the
daemon can read, then runs the daemon in the foreground.

Subcommands:
    (default)  prepare and exec the daemon in the foreground
    reload     re-stage and reload the running daemon
"""

import os
import shutil
import subprocess
import sys


def prepare() -> None:
    """Make the maildir volume writable by the vmail user and stage files."""
    os.makedirs("/var/mail/vhosts", exist_ok=True)
    os.chown("/var/mail/vhosts", 5000, 5000)
    if os.path.isfile("/run/ayane/dovecot.conf"):
        shutil.copyfile("/run/ayane/dovecot.conf", "/etc/dovecot/dovecot.conf")
    shutil.copyfile("/run/ayane/passwd", "/etc/dovecot/passwd")
    import grp

    os.chown("/etc/dovecot/passwd", 0, grp.getgrnam("dovecot").gr_gid)
    os.chmod("/etc/dovecot/passwd", 0o640)


def start() -> None:
    prepare()
    os.execv("/usr/sbin/dovecot", ["dovecot", "-F"])


def reload() -> None:
    prepare()
    subprocess.run(["doveadm", "reload"], check=True)


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "reload":
        reload()
        return 0
    start()
    return 0  # unreachable: start() execs away


if __name__ == "__main__":
    raise SystemExit(main())