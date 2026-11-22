#!/usr/bin/python3
"""Postfix container entrypoint.

Materialises the staged config copies (single-file mounts under /run/ayane)
into /etc/postfix, then runs the daemon in the foreground. Staging avoids
both problems of direct config mounts: a directory mount shadows the
package's postfix-files (integrity check fails, crash loop), and a
single-file mount pins the inode so host-side edits never reach a running
container.

Subcommands:
    (default)  stage configs and exec the daemon in the foreground
    reload     re-stage configs and reload the running daemon
"""

import os
import shutil
import subprocess
import sys

STAGED = {
    "/run/ayane/main.cf": "/etc/postfix/main.cf",
    "/run/ayane/master.cf": "/etc/postfix/master.cf",
}


def stage() -> None:
    """Copy staged configs over the baked ones when present."""
    for src, dst in STAGED.items():
        if os.path.isfile(src):
            shutil.copyfile(src, dst)


def start() -> None:
    """Stage configs and replace this process with the daemon."""
    stage()
    os.execv("/usr/sbin/postfix", ["postfix", "start-fg"])


def reload() -> None:
    """Re-stage configs and ask the running daemon to reload."""
    stage()
    subprocess.run(["postfix", "reload"], check=True)


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "reload":
        reload()
        return 0
    start()
    return 0  # unreachable: start() execs away


if __name__ == "__main__":
    raise SystemExit(main())